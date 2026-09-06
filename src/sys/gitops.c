/**
 * gitops.c - Git operations wrapper implementation
 *
 * All libgit2 calls are wrapped with error handling and resource cleanup.
 */

#include "sys/gitops.h"

#include <dirent.h>
#include <errno.h>
#include <git2.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/string.h"
#include "sys/filesystem.h"
#include "sys/identity.h"
#include "sys/transfer.h"

error_t *gitops_get_signature(git_signature **out, git_repository *repo) {
    if (git_signature_default(out, repo) == 0) {
        return NULL;
    }

    const char *user = identity()->name;
    if (!user) user = "dotta";

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(hostname, "localhost", sizeof(hostname));
    }
    hostname[sizeof(hostname) - 1] = '\0';

    char email[512];
    snprintf(email, sizeof(email), "%s@%s", user, hostname);

    int err = git_signature_now(out, user, email);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

/**
 * Repository operations
 *
 * The open is also the presence test: whether a repository stands at a path is
 * not a separate question from whether it opens, and a predicate that answers
 * it by opening and throwing the failure away can only report "absent" for every
 * reason an open can fail — a config parse error in the user's own ~/.gitconfig
 * among them, which libgit2 loads on open. So the failure is classified here,
 * where the libgit2 code is in scope and the only place it ever will be, and
 * the caller reads the code rather than a boolean.
 *
 * GIT_ENOTFOUND is libgit2's answer for both an absent repository and one it
 * could not read (an unreadable .git directory reports as not found), and it
 * words them identically — "could not find repository at X" for either — so nothing
 * is lost in replacing that message, and the caller disambiguates the pair against
 * the filesystem, which is the authority on presence. Everything else keeps
 * libgit2's own message.
 */
error_t *gitops_open_repository(git_repository **out, const char *path) {
    CHECK_NULL(out);
    CHECK_NULL(path);

    int err = git_repository_open(out, path);
    if (err == GIT_ENOTFOUND) {
        return ERROR(ERR_NOT_FOUND, "No git repository at: %s", path);
    }
    if (err == GIT_EOWNER) {
        return ERROR(
            ERR_PERMISSION,
            "Repository at %s is not owned by the current user", path
        );
    }
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

error_t *gitops_init_repository(git_repository **out, const char *path) {
    CHECK_NULL(out);
    CHECK_NULL(path);

    git_repository_init_options opts;
    git_repository_init_options_init(&opts, GIT_REPOSITORY_INIT_OPTIONS_VERSION);
    opts.flags = GIT_REPOSITORY_INIT_BARE | GIT_REPOSITORY_INIT_MKPATH;

    int err = git_repository_init_ext(out, path, &opts);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

void gitops_close_repository(git_repository *repo) {
    if (repo) {
        git_repository_free(repo);
    }
}

/**
 * Branch/Reference operations
 */
error_t *gitops_reference_exists(
    git_repository *repo, const char *refname, bool *exists
) {
    CHECK_NULL(repo);
    CHECK_NULL(refname);
    CHECK_NULL(exists);
    CHECK_ARG(refname[0] != '\0', "Reference name cannot be empty");

    git_reference *ref = NULL;
    int rc = git_reference_lookup(&ref, repo, refname);
    if (rc == GIT_ENOTFOUND) {
        *exists = false;
        return NULL;
    }
    if (rc < 0) {
        return error_from_git(rc);
    }
    git_reference_free(ref);

    *exists = true;
    return NULL;
}

error_t *gitops_branch_exists(
    git_repository *repo, const char *name, bool *exists
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(exists);
    CHECK_ARG(name[0] != '\0', "Branch name cannot be empty");

    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_branch_refname(refname, sizeof(refname), name);
    if (err) {
        return err;
    }

    return gitops_reference_exists(repo, refname, exists);
}

error_t *gitops_branch_blocker(
    git_repository *repo, const char *name, char **out_blocker
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(out_blocker);
    CHECK_ARG(name[0] != '\0', "Branch name cannot be empty");

    *out_blocker = NULL;

    string_array_t *branches = NULL;
    error_t *err = gitops_list_branches(repo, &branches);
    if (err) {
        return err;
    }

    size_t len = strlen(name);
    for (size_t i = 0; i < branches->count; i++) {
        const char *other = branches->items[i];
        size_t other_len = strlen(other);

        /* Nested names: one is a folder the other lives in — the shorter matched
         * whole, with a '/' where the longer one continues past it. Equal names
         * are not nested, and the boundary test says so on its own: the shorter
         * length indexes the other name's terminator. */
        size_t shorter = other_len < len ? other_len : len;
        bool nested = strncmp(other, name, shorter) == 0
            && (other_len > len ? other[len] : name[other_len]) == '/';

        if (nested) {
            *out_blocker = strdup(other);
            if (!*out_blocker) {
                err = ERROR(ERR_MEMORY, "Failed to allocate branch name");
            }
            break;
        }
    }

    string_array_free(branches);
    return err;
}

/* What a walk of the loose store holds constant: the repository the lookups ask,
 * where in every path beneath the namespace's directory the ref's name begins,
 * how many components the namespace has, and the listing itself. */
typedef struct {
    git_repository *repo;
    size_t refname_at;        /* "<namespace>/…" begins here in every path walked */
    size_t depth;             /* the namespace's components: "refs/heads" has two */
    string_array_t *names;    /* the names beneath it, as listed so far */
} loose_walk_t;

/*
 * The loose store beneath a listing, read whole (the header). Git's own reading
 * of a refs directory: a dot-entry is not a ref and neither is a `.lock` (a write
 * in flight) — no valid name begins with the one or ends with the other; a
 * directory is a namespace to enter; a regular file or a link is a ref. Every
 * ref is looked up the way libgit2 reads one, whether or not the enumeration
 * named it — one judge for the loose store, so a file the enumeration listed
 * and one it dropped meet the same rule, and a name Git refuses (an editor's
 * `work~`) refuses either way. The refusal is the listing's, in Git's words.
 * What resolves is listed under the name libgit2 gives it — its normalized
 * spelling, the enumeration's own, so a name readdir spells otherwise (decomposed,
 * on a filesystem that stores it so) is found listed and never listed twice —
 * unless the enumeration listed it. What vanished since the directory was read
 * holds nothing, a dangling link included, and so does a link to a directory:
 * libgit2 enters one (GIT_ITERATOR_DESCEND_SYMLINKS) and the walk does not, which
 * is what keeps it finite with no depth count; what stands beneath a linked
 * directory is the enumeration's reading, proved by nothing. A device or a fifo
 * is nothing libgit2 would list. A directory that will not open, or an entry
 * that will not stat, is the walk's own refusal, naming the directory. A namespace
 * with no directory holds no loose refs.
 *
 * The cost is one open and one parse per loose ref — the read libgit2 made once
 * already — and a scan of the listing per ref: tens of branches, well under a
 * millisecond.
 */
static error_t *walk_loose_refs(const loose_walk_t *walk, const char *dir) {
    DIR *d = fs_opendir(dir);
    if (!d) {
        if (errno == ENOENT) {
            return NULL;
        }
        return error_from_errno(errno, "Cannot read the refs under '%s'", dir);
    }

    /* errno cleared before every readdir: a NULL is the end, or the error it names */
    error_t *err = NULL;
    struct dirent *entry;
    for (errno = 0; (entry = readdir(d)) != NULL; errno = 0) {
        const char *name = entry->d_name;
        if (name[0] == '.' || str_ends_with(name, ".lock")) {
            continue;
        }

        char *path = str_format("%s/%s", dir, name);
        if (!path) {
            err = ERROR(ERR_MEMORY, "Failed to allocate a ref path");
            break;
        }

        switch (fs_lstat_occupant(path, NULL)) {
            case FS_OCCUPANT_DIRECTORY:
                err = walk_loose_refs(walk, path);
                break;

            case FS_OCCUPANT_REGULAR:
            case FS_OCCUPANT_SYMLINK: {
                git_reference *ref = NULL;
                int rc = git_reference_lookup(
                    &ref, walk->repo, path + walk->refname_at
                );
                if (rc == GIT_ENOTFOUND) {
                    break;
                }
                if (rc < 0) {
                    err = error_from_git(rc);
                    break;
                }
                /* The namespace's components lead the name whatever their spelling
                 * — normalization moves no '/' — and what follows them is the
                 * name beneath it. */
                const char *listed = git_reference_name(ref);
                for (size_t depth = walk->depth; depth > 0; depth--) {
                    listed = strchr(listed, '/') + 1;
                }
                if (!string_array_contains(walk->names, listed)) {
                    err = string_array_push(walk->names, listed);
                }
                git_reference_free(ref);
                break;
            }

            case FS_OCCUPANT_NONE:
            case FS_OCCUPANT_OTHER:
                break;

            case FS_OCCUPANT_UNKNOWN:
                err = error_from_errno(
                    errno, "Cannot read the refs under '%s'", dir
                );
                break;
        }

        free(path);
        if (err) {
            break;
        }
    }

    if (!err && errno != 0) {
        err = error_from_errno(errno, "Cannot read the refs under '%s'", dir);
    }
    closedir(d);
    return err;
}

error_t *gitops_list_refs(
    git_repository *repo, const char *namespace, string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(namespace);
    CHECK_NULL(out);
    CHECK_ARG(namespace[0] != '\0', "Reference namespace cannot be empty");

    /* libgit2's enumeration under the namespace: the packed refs, loudly; the
     * loose ones as far as it could read them. The glob walks the namespace's
     * own directory and nothing beside it; a name is listed past "<namespace>/". */
    char glob[DOTTA_REFNAME_MAX];
    int written = snprintf(glob, sizeof(glob), "%s/*", namespace);
    if (written < 0 || (size_t) written >= sizeof(glob)) {
        return ERROR(
            ERR_INVALID_ARG, "Reference namespace too long: '%s'", namespace
        );
    }

    git_reference_iterator *iter = NULL;
    int rc = git_reference_iterator_glob_new(&iter, repo, glob);
    if (rc < 0) {
        return error_from_git(rc);
    }
    string_array_t *names = string_array_new(0);
    if (!names) {
        git_reference_iterator_free(iter);
        return ERROR(ERR_MEMORY, "Failed to allocate the ref listing");
    }

    error_t *err = NULL;
    for (;;) {
        /* Classified, not compared: GIT_ITEROVER is the enumeration finished,
         * and a negative code one that never did. */
        const char *refname = NULL;
        rc = git_reference_next_name(&refname, iter);
        if (rc == GIT_ITEROVER) {
            break;
        }
        if (rc < 0) {
            err = error_from_git(rc);
            break;
        }
        err = string_array_push(names, refname + strlen(namespace) + 1);
        if (err) {
            break;
        }
    }
    git_reference_iterator_free(iter);

    /* The loose store beneath it, read whole. */
    char *dir = NULL;
    if (!err) {
        err = fs_path_join(git_repository_commondir(repo), namespace, &dir);
    }
    if (!err) {
        loose_walk_t walk = {
            .repo       = repo,
            .refname_at = strlen(dir) - strlen(namespace),
            .depth      = 1,
            .names      = names,
        };
        for (const char *slash = strchr(namespace, '/'); slash;
            slash = strchr(slash + 1, '/')) {
            walk.depth++;
        }
        err = walk_loose_refs(&walk, dir);
        free(dir);
    }
    if (err) {
        string_array_free(names);
        return err;
    }

    *out = names;
    return NULL;
}

error_t *gitops_list_branches(git_repository *repo, string_array_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    return gitops_list_refs(repo, "refs/heads", out);
}

error_t *gitops_list_remote_tracking(
    git_repository *repo, const char *remote_name, string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(out);

    char namespace[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(
        namespace, sizeof(namespace), "refs/remotes/%s", remote_name
    );
    if (err) {
        return err;
    }

    string_array_t *names = NULL;
    err = gitops_list_refs(repo, namespace, &names);
    if (err) {
        return err;
    }

    /* Under the remote's namespace and not a branch of it: its symbolic HEAD. */
    string_array_remove_value(names, "HEAD");

    *out = names;
    return NULL;
}

error_t *gitops_delete_branch(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_ARG(name[0] != '\0', "Branch name cannot be empty");

    char refname[DOTTA_REFNAME_MAX];
    error_t *err_build = gitops_branch_refname(refname, sizeof(refname), name);
    if (err_build) {
        return err_build;
    }

    git_reference *ref = NULL;
    int err = git_reference_lookup(&ref, repo, refname);
    if (err < 0) {
        return error_wrap(
            error_from_git(err), "Failed to lookup branch '%s'", name
        );
    }

    /* A linked worktree's checkout is the one that must be asked (the header):
     * the store itself checks nothing out, so a bare main repository is passed
     * over by libgit2's walk of the worktrees and only a linked one can answer. */
    if (git_branch_is_checked_out(ref)) {
        git_reference_free(ref);
        return ERROR(
            ERR_CONFLICT,
            "Branch '%s' is checked out in a worktree of the repository; "
            "remove that worktree first (git worktree list)", name
        );
    }

    err = git_reference_delete(ref);
    git_reference_free(ref);
    if (err < 0) {
        return error_wrap(
            error_from_git(err), "Failed to delete branch '%s'", name
        );
    }

    return NULL;
}

/**
 * Tree operations
 */

/**
 * Resolve a Git reference to its tree, optionally capturing the peeled OID
 *
 * Shared implementation for gitops_load_tree and gitops_load_branch_tree. The
 * OID captured (when out_oid is non-NULL) is the peeled object's OID: the commit
 * OID for commit-backed branches, the tree OID for orphan-tree branches. This
 * matches the OID that the old profile_load captured via the same
 * git_reference_peel(ANY) path, ensuring staleness detection consistency.
 */
static error_t *resolve_ref_to_tree(
    git_repository *repo, const char *ref_name, git_tree **out_tree,
    git_oid *out_oid
) {
    /* Get reference */
    git_reference *ref = NULL;
    int err = git_reference_lookup(&ref, repo, ref_name);
    if (err < 0) {
        return error_wrap(
            error_from_git(err),
            "Failed to lookup reference '%s'", ref_name
        );
    }

    /* Peel reference to get the underlying object */
    git_object *obj = NULL;
    err = git_reference_peel(&obj, ref, GIT_OBJECT_ANY);
    git_reference_free(ref);
    if (err < 0) {
        return error_wrap(
            error_from_git(err), "Failed to peel reference '%s'",
            ref_name
        );
    }

    /* Capture peeled OID before consuming the object */
    if (out_oid) {
        git_oid_cpy(out_oid, git_object_id(obj));
    }

    /* Handle different object types */
    git_object_t obj_type = git_object_type(obj);

    if (obj_type == GIT_OBJECT_COMMIT) {
        /* Normal branch pointing to commit - get tree from commit
         * SAFETY: We verified obj_type == GIT_OBJECT_COMMIT, so this cast is safe
         */
        git_commit *commit = (git_commit *) obj;
        err = git_commit_tree(out_tree, commit);
        git_object_free(obj);
        if (err < 0) {
            return error_from_git(err);
        }
    } else if (obj_type == GIT_OBJECT_TREE) {
        *out_tree = (git_tree *) obj;
    } else {
        /* Unexpected object type */
        git_object_free(obj);
        return ERROR(
            ERR_GIT, "Reference '%s' points to unexpected object type: %d",
            ref_name, obj_type
        );
    }

    return NULL;
}

error_t *gitops_load_tree(
    git_repository *repo, const char *ref_name, git_tree **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ref_name);
    CHECK_NULL(out);
    CHECK_ARG(ref_name[0] != '\0', "Reference name cannot be empty");

    return resolve_ref_to_tree(repo, ref_name, out, NULL);
}

error_t *gitops_load_branch_tree(
    git_repository *repo, const char *branch_name, git_tree **out_tree,
    git_oid *out_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out_tree);

    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_branch_refname(
        refname, sizeof(refname), branch_name
    );
    if (err) {
        return err;
    }

    return resolve_ref_to_tree(repo, refname, out_tree, out_oid);
}

error_t *gitops_tree_walk(
    const git_tree *tree, git_treewalk_cb callback, void *payload
) {
    CHECK_NULL(tree);
    CHECK_NULL(callback);

    int err = git_tree_walk(tree, GIT_TREEWALK_PRE, callback, payload);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

/**
 * Commit operations
 */
error_t *gitops_get_commit(
    git_repository *repo, const char *ref_name, git_commit **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ref_name);
    CHECK_NULL(out);

    git_oid oid;
    int err = git_reference_name_to_id(&oid, repo, ref_name);
    if (err < 0) {
        return error_wrap(
            error_from_git(err),
            "Failed to resolve reference '%s'", ref_name
        );
    }

    err = git_commit_lookup(out, repo, &oid);
    if (err < 0) {
        return error_wrap(
            error_from_git(err),
            "Failed to lookup commit for reference '%s'", ref_name
        );
    }

    return NULL;
}

/**
 * Remote operations
 */
error_t *gitops_fetch_remote(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    git_fetch_options fetch_opts;
    git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &fetch_opts.callbacks, xfer, GIT_DIRECTION_FETCH
    );

    /* No refspecs given: the remote's own, as configured. */
    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    err = git_remote_fetch(remote, NULL, &fetch_opts, NULL);
    transfer_op_end(xfer, err);
    git_remote_free(remote);

    if (err < 0) {
        return error_from_git(err);
    }
    return NULL;
}

error_t *gitops_fetch_branch(
    git_repository *repo, const char *remote_name, const char *branch_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(xfer);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");
    CHECK_ARG(branch_name[0] != '\0', "Branch name cannot be empty");

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    git_fetch_options fetch_opts;
    git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &fetch_opts.callbacks, xfer, GIT_DIRECTION_FETCH
    );

    char refspec[DOTTA_REFSPEC_MAX];
    error_t *err_build = gitops_build_refname(
        refspec, sizeof(refspec), "refs/heads/%s:refs/remotes/%s/%s",
        branch_name, remote_name, branch_name
    );
    if (err_build) {
        git_remote_free(remote);
        return error_wrap(
            err_build, "Invalid branch/remote name '%s/%s'",
            remote_name, branch_name
        );
    }

    char *refspecs[] = { refspec };
    git_strarray refs = { refspecs, 1 };

    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    err = git_remote_fetch(remote, &refs, &fetch_opts, NULL);
    transfer_op_end(xfer, err);
    git_remote_free(remote);

    if (err < 0) {
        return error_from_git(err);
    }
    return NULL;
}

error_t *gitops_fetch_branches(
    git_repository *repo, const char *remote_name, const string_array_t *branches,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branches);
    CHECK_NULL(xfer);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");
    CHECK_ARG(branches->count > 0, "branches must not be empty");

    /* Look up remote once */
    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Build array of refspecs for all branches */
    char **refspecs = calloc(branches->count, sizeof(char *));
    if (!refspecs) {
        git_remote_free(remote);
        return ERROR(ERR_MEMORY, "Failed to allocate refspecs array");
    }

    /* Construct refspecs for each branch */
    error_t *err_result = NULL;
    for (size_t i = 0; i < branches->count; i++) {
        if (!branches->items[i]) {
            err_result = ERROR(
                ERR_INVALID_ARG, "branches[%zu] is NULL", i
            );
            goto cleanup;
        }
        if (branches->items[i][0] == '\0') {
            err_result = ERROR(
                ERR_INVALID_ARG, "branches[%zu] cannot be empty", i
            );
            goto cleanup;
        }

        /* Allocate buffer for this refspec */
        refspecs[i] = malloc(DOTTA_REFSPEC_MAX);
        if (!refspecs[i]) {
            err_result = ERROR(ERR_MEMORY, "Failed to allocate refspec buffer");
            goto cleanup;
        }

        /* Build refspec: refs/heads/branch:refs/remotes/origin/branch */
        error_t *err_build = gitops_build_refname(
            refspecs[i], DOTTA_REFSPEC_MAX, "refs/heads/%s:refs/remotes/%s/%s",
            branches->items[i], remote_name, branches->items[i]
        );
        if (err_build) {
            err_result = error_wrap(
                err_build, "Invalid branch/remote name '%s/%s'",
                remote_name, branches->items[i]
            );
            goto cleanup;
        }
    }

    git_fetch_options fetch_opts;
    git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &fetch_opts.callbacks, xfer, GIT_DIRECTION_FETCH
    );

    /* Build git_strarray from our refspecs */
    git_strarray refs = { refspecs, branches->count };

    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    err = git_remote_fetch(remote, &refs, &fetch_opts, NULL);
    transfer_op_end(xfer, err);

    if (err < 0) {
        err_result = error_from_git(err);
        goto cleanup;
    }

cleanup:
    /* Free refspecs array */
    if (refspecs) {
        for (size_t i = 0; i < branches->count; i++) {
            free(refspecs[i]);
        }
        free(refspecs);
    }

    git_remote_free(remote);
    return err_result;
}

error_t *gitops_push_branch(
    git_repository *repo, const char *remote_name, const char *branch_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(xfer);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");
    CHECK_ARG(branch_name[0] != '\0', "Branch name cannot be empty");

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    git_push_options push_opts;
    git_push_options_init(&push_opts, GIT_PUSH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &push_opts.callbacks, xfer, GIT_DIRECTION_PUSH
    );

    char refspec[DOTTA_REFSPEC_MAX];
    error_t *err_build = gitops_build_refname(
        refspec, sizeof(refspec), "refs/heads/%s:refs/heads/%s",
        branch_name, branch_name
    );
    if (err_build) {
        git_remote_free(remote);
        return error_wrap(
            err_build, "Invalid branch name '%s'", branch_name
        );
    }

    char *refspecs[] = { refspec };
    git_strarray refs = { refspecs, 1 };

    transfer_op_begin(xfer, GIT_DIRECTION_PUSH);
    err = git_remote_push(remote, &refs, &push_opts);
    transfer_op_end(xfer, err);
    git_remote_free(remote);

    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

error_t *gitops_force_push_branch(
    git_repository *repo, const char *remote_name, const char *branch_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(xfer);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");
    CHECK_ARG(branch_name[0] != '\0', "Branch name cannot be empty");

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    git_push_options push_opts;
    git_push_options_init(&push_opts, GIT_PUSH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &push_opts.callbacks, xfer, GIT_DIRECTION_PUSH
    );

    /* Force push refspec ('+' prefix accepts non-fast-forward update) */
    char refspec[DOTTA_REFSPEC_MAX];
    error_t *err_build = gitops_build_refname(
        refspec, sizeof(refspec), "+refs/heads/%s:refs/heads/%s",
        branch_name, branch_name
    );
    if (err_build) {
        git_remote_free(remote);
        return error_wrap(
            err_build, "Invalid branch name '%s'", branch_name
        );
    }

    char *refspecs[] = { refspec };
    git_strarray refs = { refspecs, 1 };

    transfer_op_begin(xfer, GIT_DIRECTION_PUSH);
    err = git_remote_push(remote, &refs, &push_opts);
    transfer_op_end(xfer, err);
    git_remote_free(remote);

    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

error_t *gitops_delete_remote_branch(
    git_repository *repo, const char *remote_name, const char *branch_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(xfer);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");
    CHECK_ARG(branch_name[0] != '\0', "Branch name cannot be empty");

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    git_push_options push_opts;
    git_push_options_init(&push_opts, GIT_PUSH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &push_opts.callbacks, xfer, GIT_DIRECTION_PUSH
    );

    /* Delete remote branch using empty refspec: :refs/heads/branch */
    char refspec[DOTTA_REFSPEC_MAX];
    error_t *err_build = gitops_build_refname(
        refspec, sizeof(refspec), ":refs/heads/%s", branch_name
    );
    if (err_build) {
        git_remote_free(remote);
        return error_wrap(
            err_build, "Invalid branch name '%s'", branch_name
        );
    }

    char *refspecs[] = { refspec };
    git_strarray refs = { refspecs, 1 };

    transfer_op_begin(xfer, GIT_DIRECTION_PUSH);
    err = git_remote_push(remote, &refs, &push_opts);
    transfer_op_end(xfer, err);
    git_remote_free(remote);

    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

error_t *gitops_list_remote_branches(
    git_repository *repo, const char *remote_name,
    transfer_context_t *xfer, string_array_t **out_branches
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);
    CHECK_NULL(out_branches);

    git_remote *remote = NULL;
    string_array_t *branches = string_array_new(0);
    if (!branches) {
        return ERROR(ERR_MEMORY, "Failed to allocate branch list");
    }

    int git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err < 0) {
        string_array_free(branches);
        return error_from_git(git_err);
    }

    /* git_remote_connect + git_remote_ls transfer no byte payload, so the progress
     * callback never fires; GIT_DIRECTION_FETCH keeps the credential path aligned
     * with fetch semantics. */
    git_remote_callbacks callbacks;
    git_remote_init_callbacks(&callbacks, GIT_REMOTE_CALLBACKS_VERSION);
    transfer_configure_callbacks(&callbacks, xfer, GIT_DIRECTION_FETCH);

    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    git_err = git_remote_connect(
        remote, GIT_DIRECTION_FETCH, &callbacks, NULL, NULL
    );
    transfer_op_end(xfer, git_err);
    if (git_err < 0) {
        git_remote_free(remote);
        string_array_free(branches);
        return error_from_git(git_err);
    }

    const git_remote_head **refs = NULL;
    size_t refs_len = 0;
    git_err = git_remote_ls(&refs, &refs_len, remote);
    if (git_err < 0) {
        git_remote_disconnect(remote);
        git_remote_free(remote);
        string_array_free(branches);
        return error_from_git(git_err);
    }

    static const char heads_prefix[] = "refs/heads/";
    const size_t prefix_len = sizeof(heads_prefix) - 1;

    for (size_t i = 0; i < refs_len; i++) {
        const char *refname = refs[i]->name;

        if (!str_starts_with(refname, heads_prefix)) {
            continue;
        }

        const char *branch_name = refname + prefix_len;

        if (*branch_name == '\0') {
            continue;
        }

        error_t *push_err = string_array_push(branches, branch_name);
        if (push_err) {
            git_remote_disconnect(remote);
            git_remote_free(remote);
            string_array_free(branches);
            return push_err;
        }
    }

    git_remote_disconnect(remote);
    git_remote_free(remote);

    *out_branches = branches;
    return NULL;
}

error_t *gitops_get_remote_url(
    git_repository *repo, const char *remote_name, char **out_url
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(out_url);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    const char *url = git_remote_url(remote);
    if (!url) {
        git_remote_free(remote);
        return ERROR(
            ERR_NOT_FOUND, "Remote '%s' has no URL configured",
            remote_name
        );
    }

    *out_url = strdup(url);
    git_remote_free(remote);

    if (!*out_url) {
        return ERROR(ERR_MEMORY, "Failed to duplicate remote URL");
    }

    return NULL;
}

error_t *gitops_resolve_default_remote(
    git_repository *repo, arena_t *arena, const char **out_name,
    const char **out_url
) {
    CHECK_NULL(repo);
    CHECK_NULL(arena);
    CHECK_NULL(out_name);

    *out_name = NULL;
    if (out_url) *out_url = NULL;

    git_strarray remotes = { 0 };
    int git_err = git_remote_list(&remotes, repo);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    if (remotes.count == 0) {
        git_strarray_dispose(&remotes);
        return ERROR(
            ERR_NOT_FOUND, "No remotes configured\n"
            "Hint: Add a remote with 'dotta remote add <name> <url>'"
        );
    }

    /* Select: "origin" wins; otherwise sole remote; otherwise ambiguous. */
    const char *selected = NULL;
    for (size_t i = 0; i < remotes.count; i++) {
        if (strcmp(remotes.strings[i], "origin") == 0) {
            selected = "origin";
            break;
        }
    }
    if (!selected && remotes.count == 1) {
        selected = remotes.strings[0];
    }
    if (!selected) {
        git_strarray_dispose(&remotes);
        return ERROR(
            ERR_INVALID_ARG,
            "Multiple remotes configured, but no 'origin' found\n"
            "Hint: Specify remote explicitly or rename preferred remote to 'origin'"
        );
    }

    const char *name = arena_strdup(arena, selected);
    git_strarray_dispose(&remotes);
    if (!name) {
        return ERROR(ERR_MEMORY, "Failed to allocate remote name");
    }

    /* URL is optional. A remote without URL is legal — credentialed transfer
     * tolerates a NULL URL — so leave *out_url = NULL on that branch instead of
     * erroring. */
    if (out_url) {
        git_remote *remote = NULL;
        int lookup_err = git_remote_lookup(&remote, repo, name);
        if (lookup_err < 0) {
            return error_from_git(lookup_err);
        }

        const char *url = git_remote_url(remote);
        if (url) {
            *out_url = arena_strdup(arena, url);
            git_remote_free(remote);
            if (!*out_url) {
                return ERROR(ERR_MEMORY, "Failed to allocate remote URL");
            }
        } else {
            git_remote_free(remote);
        }
    }

    *out_name = name;

    return NULL;
}

/**
 * Reference operations
 */
error_t *gitops_create_reference(
    git_repository *repo, const char *name, const git_oid *oid,
    bool force
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(oid);

    git_reference *ref = NULL;
    int err = git_reference_create(&ref, repo, name, oid, force, NULL);
    if (err < 0) {
        return error_from_git(err);
    }

    git_reference_free(ref);

    return NULL;
}

error_t *gitops_resolve_reference_oid(
    git_repository *repo, const char *ref_name, git_oid *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ref_name);
    CHECK_NULL(out);

    int err = git_reference_name_to_id(out, repo, ref_name);
    if (err < 0) {
        if (err == GIT_ENOTFOUND) {
            return ERROR(
                ERR_NOT_FOUND, "Reference '%s' not found",
                ref_name
            );
        }
        return error_wrap(
            error_from_git(err),
            "Failed to resolve reference '%s'", ref_name
        );
    }

    return NULL;
}

error_t *gitops_resolve_branch_head_oid(
    git_repository *repo, const char *branch_name, git_oid *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out);

    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_branch_refname(
        refname, sizeof(refname), branch_name
    );
    if (err) {
        return err;
    }

    return gitops_resolve_reference_oid(repo, refname, out);
}

error_t *gitops_resolve_remote_branch_oid(
    git_repository *repo,
    const char *remote_name, const char *branch_name, git_oid *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(out);

    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(
        refname, sizeof(refname), "refs/remotes/%s/%s",
        remote_name, branch_name
    );
    if (err) {
        return error_wrap(
            err, "Invalid remote/branch name '%s/%s'",
            remote_name, branch_name
        );
    }

    return gitops_resolve_reference_oid(repo, refname, out);
}

/**
 * Tree lookups
 */
error_t *gitops_find_file_in_tree(
    git_tree *tree, const char *path, git_tree_entry **out
) {
    CHECK_NULL(tree);
    CHECK_NULL(path);
    CHECK_NULL(out);
    CHECK_ARG(path[0] != '\0', "Path cannot be empty");

    /* Normalize path: strip all leading slashes. A single-slash strip would leave
     * "//foo" as "/foo", which git_tree_entry_bypath would reject as an absolute
     * path. */
    const char *normalized_path = path;
    while (*normalized_path == '/') {
        normalized_path++;
    }
    if (*normalized_path == '\0') {
        return ERROR(
            ERR_INVALID_ARG, "Path cannot be empty or just slashes"
        );
    }

    /* Lookup entry in tree */
    git_tree_entry *temp_entry = NULL;
    int ret = git_tree_entry_bypath(&temp_entry, tree, normalized_path);
    if (ret < 0) {
        if (ret == GIT_ENOTFOUND) {
            return ERROR(ERR_NOT_FOUND, "File '%s' not found", path);
        }
        return error_from_git(ret);
    }

    *out = temp_entry;
    return NULL;
}

/**
 * Open a zero-copy view onto a blob
 */
error_t *gitops_blob_view_open(
    git_repository *repo, const git_oid *oid, gitops_blob_view_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(oid);
    CHECK_NULL(out);

    *out = (gitops_blob_view_t){ 0 };

    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, repo, oid);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    out->_handle = blob;
    out->data = git_blob_rawcontent(blob);
    out->size = (size_t) git_blob_rawsize(blob);

    return NULL;
}

/**
 * Close a blob view
 */
void gitops_blob_view_close(gitops_blob_view_t *view) {
    if (!view || !view->_handle) {
        return;
    }

    git_blob_free(view->_handle);
    *view = (gitops_blob_view_t){ 0 };
}

/**
 * Read blob content by OID
 */
error_t *gitops_read_blob_content(
    git_repository *repo, const git_oid *oid, void **out_content,
    size_t *out_size
) {
    CHECK_NULL(repo);
    CHECK_NULL(oid);
    CHECK_NULL(out_content);
    CHECK_NULL(out_size);

    gitops_blob_view_t view;
    error_t *err = gitops_blob_view_open(repo, oid, &view);
    if (err) {
        return err;
    }

    void *content = malloc(view.size + 1);
    if (!content) {
        gitops_blob_view_close(&view);
        return ERROR(ERR_MEMORY, "Failed to allocate blob content buffer");
    }

    if (view.size > 0) {
        memcpy(content, view.data, view.size);
    }
    ((char *) content)[view.size] = '\0';

    *out_content = content;
    *out_size = view.size;

    gitops_blob_view_close(&view);
    return NULL;
}

/**
 * Resolve commit reference within a branch
 */
error_t *gitops_resolve_commit_in_branch(
    git_repository *repo, const char *branch_name, const char *commit_ref,
    git_oid *out_oid, git_commit **out_commit
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(commit_ref);
    CHECK_NULL(out_oid);

    /* Build the branch refname. */
    char ref_name[DOTTA_REFNAME_MAX];
    error_t *err_build = gitops_branch_refname(
        ref_name, sizeof(ref_name), branch_name
    );
    if (err_build) {
        return err_build;
    }

    /* Look up the branch and capture its tip OID by value.
     *
     * The tip is the authoritative reference for downstream reachability checks.
     * Copying the OID (20 bytes) decouples this function from the git_reference
     * handle's lifetime, so we can release branch_ref immediately and operate
     * on the OID alone. */
    git_reference *branch_ref = NULL;
    int ret = git_reference_lookup(&branch_ref, repo, ref_name);
    if (ret < 0) {
        return error_from_git(ret);
    }

    const git_oid *tip_target = git_reference_target(branch_ref);
    if (!tip_target) {
        git_reference_free(branch_ref);
        return ERROR(
            ERR_GIT, "Branch '%s' has no target", branch_name
        );
    }
    git_oid branch_tip_oid;
    git_oid_cpy(&branch_tip_oid, tip_target);
    git_reference_free(branch_ref);

    /* Fast path: "HEAD" resolves to the tip we just captured.
     *
     * Skips revparse and the reachability check below — both would be redundant
     * since the tip is, by definition, reachable from itself. */
    if (strcmp(commit_ref, "HEAD") == 0) {
        git_oid_cpy(out_oid, &branch_tip_oid);
        if (out_commit) {
            ret = git_commit_lookup(out_commit, repo, out_oid);
            if (ret < 0) {
                return error_from_git(ret);
            }
        }
        return NULL;
    }

    /* Build the input string for git_revparse_single.
     *
     * "HEAD~N" / "HEAD^N" must resolve relative to branch_name (not the
     * repository's HEAD), so we rewrite them as "<branch>~N" / "<branch>^N".
     * Anything else (raw SHA, tag, "<branch>~N") is passed through as-is — the
     * reachability check below catches inputs that resolve to commits on other
     * branches, regardless of input syntax.
     *
     * Exact "HEAD" was matched above; using str_starts_with("HEAD") alone would
     * also match strings like a hypothetical "HEADLESS" tag and misroute them
     * into the ancestry-rewrite path. */
    char *allocated_ref = NULL;
    const char *resolve_ref = commit_ref;

    if (str_starts_with(commit_ref, "HEAD~") ||
        str_starts_with(commit_ref, "HEAD^")) {
        allocated_ref = str_format("%s%s", branch_name, commit_ref + 4);
        if (!allocated_ref) {
            return ERROR(ERR_MEMORY, "Failed to allocate ref string");
        }
        resolve_ref = allocated_ref;
    }

    git_object *obj = NULL;
    ret = git_revparse_single(&obj, repo, resolve_ref);
    free(allocated_ref);  /* NULL-safe */
    if (ret < 0) {
        return ERROR(
            ERR_NOT_FOUND, "Commit '%s' not found in branch '%s'",
            commit_ref, branch_name
        );
    }

    /* Peel to a commit object.
     *
     * Annotated tags wrap commits — git_revparse_single returns the tag object
     * whose OID is the tag's, not the commit's. Peeling normalises
     * tag/commit/symbolic-ref inputs to a commit so out_oid always names a commit
     * and the reachability check below operates on commit OIDs (as
     * git_graph_descendant_of requires).
     *
     * For inputs that are already commits, peel returns a refcount-bumped reference
     * to the same object — which is why obj is freed separately.
     *
     * Inputs that cannot be peeled to a commit (trees, blobs) yield an error
     * here rather than a confusing failure later. */
    git_object *commit_obj = NULL;
    ret = git_object_peel(&commit_obj, obj, GIT_OBJECT_COMMIT);
    git_object_free(obj);
    if (ret < 0) {
        return error_wrap(
            error_from_git(ret),
            "Reference '%s' does not point to a commit", commit_ref
        );
    }

    /* Constrain the resolved commit to ones reachable from branch_name.
     *
     * git_revparse_single resolves repository-wide; without this check, a SHA
     * that exists on a different branch would resolve successfully and silently
     * misattribute the commit. The invariant we enforce: the resolved OID must
     * equal the branch tip or be one of its ancestors.
     *
     * git_graph_descendant_of returns 0 for self, so an exact tip match needs
     * an explicit oid_equal short-circuit (the same pairing sync.c uses for
     * fast-forward checks). */
    const git_oid *resolved_oid = git_object_id(commit_obj);
    if (!git_oid_equal(resolved_oid, &branch_tip_oid)) {
        int reach = git_graph_descendant_of(
            repo, &branch_tip_oid, resolved_oid
        );
        if (reach < 0) {
            git_object_free(commit_obj);
            return error_from_git(reach);
        }
        if (reach == 0) {
            git_object_free(commit_obj);
            return ERROR(
                ERR_NOT_FOUND,
                "Commit '%s' is not reachable from branch '%s'",
                commit_ref, branch_name
            );
        }
    }

    git_oid_cpy(out_oid, resolved_oid);

    if (out_commit) {
        /* SAFETY: peel(GIT_OBJECT_COMMIT) guarantees commit_obj's type. */
        *out_commit = (git_commit *) commit_obj;
    } else {
        git_object_free(commit_obj);
    }

    return NULL;
}

/**
 * Get tree from commit OID
 */
error_t *gitops_get_tree_from_commit(
    git_repository *repo, const git_oid *commit_oid,
    git_tree **out_tree
) {
    CHECK_NULL(repo);
    CHECK_NULL(commit_oid);
    CHECK_NULL(out_tree);

    /* Lookup commit */
    git_commit *commit = NULL;
    int err = git_commit_lookup(&commit, repo, commit_oid);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Get tree from commit */
    err = git_commit_tree(out_tree, commit);
    git_commit_free(commit);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

/**
 * Find merge base between two commits
 */
error_t *gitops_find_merge_base(
    git_repository *repo, const git_oid *one, const git_oid *two,
    git_oid *out_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(one);
    CHECK_NULL(two);
    CHECK_NULL(out_oid);

    int err = git_merge_base(out_oid, repo, one, two);
    if (err < 0) {
        if (err == GIT_ENOTFOUND) {
            return ERROR(
                ERR_NOT_FOUND, "No merge base found between commits"
            );
        }
        return error_from_git(err);
    }

    return NULL;
}

/**
 * Merge trees without modifying HEAD or working directory
 */
error_t *gitops_merge_trees_safe(
    git_repository *repo, const git_oid *ancestor_oid, const git_oid *our_oid,
    const git_oid *their_oid, git_index **out_index
) {
    CHECK_NULL(repo);
    CHECK_NULL(ancestor_oid);
    CHECK_NULL(our_oid);
    CHECK_NULL(their_oid);
    CHECK_NULL(out_index);

    git_tree *ancestor_tree = NULL;
    git_tree *our_tree = NULL;
    git_tree *their_tree = NULL;
    git_index *index = NULL;
    error_t *err = NULL;
    int git_err;

    /* Get tree from ancestor commit */
    err = gitops_get_tree_from_commit(repo, ancestor_oid, &ancestor_tree);
    if (err) {
        return error_wrap(err, "Failed to get ancestor tree");
    }

    /* Get tree from our commit */
    err = gitops_get_tree_from_commit(repo, our_oid, &our_tree);
    if (err) {
        git_tree_free(ancestor_tree);
        return error_wrap(err, "Failed to get our tree");
    }

    /* Get tree from their commit */
    err = gitops_get_tree_from_commit(repo, their_oid, &their_tree);
    if (err) {
        git_tree_free(our_tree);
        git_tree_free(ancestor_tree);
        return error_wrap(err, "Failed to get their tree");
    }

    /* Perform three-way merge on trees */
    git_merge_options merge_opts;
    git_merge_options_init(&merge_opts, GIT_MERGE_OPTIONS_VERSION);
    git_err = git_merge_trees(
        &index, repo, ancestor_tree, our_tree, their_tree, &merge_opts
    );

    /* Clean up trees */
    git_tree_free(their_tree);
    git_tree_free(our_tree);
    git_tree_free(ancestor_tree);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    *out_index = index;
    return NULL;
}

/**
 * Create merge commit from index
 */
error_t *gitops_create_merge_commit(
    git_repository *repo, git_index *index, git_commit *our_commit,
    git_commit *their_commit, const char *message, git_oid *out_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(index);
    CHECK_NULL(our_commit);
    CHECK_NULL(their_commit);
    CHECK_NULL(message);
    CHECK_NULL(out_oid);

    /* Check for conflicts */
    if (git_index_has_conflicts(index)) {
        return ERROR(
            ERR_CONFLICT,
            "Cannot create merge commit: index has conflicts"
        );
    }

    /* Write index to tree
     * IMPORTANT: Use git_index_write_tree_to() because the index from
     * git_merge_trees() is not backed by a repository, so we must explicitly
     * write to the repo's ODB.
     */
    git_oid tree_oid;
    int err = git_index_write_tree_to(&tree_oid, index, repo);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Lookup tree object */
    git_tree *tree = NULL;
    err = git_tree_lookup(&tree, repo, &tree_oid);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Get signature with fallback */
    git_signature *sig = NULL;
    error_t *sig_err = gitops_get_signature(&sig, repo);
    if (sig_err) {
        git_tree_free(tree);
        return sig_err;
    }

    /* Create merge commit with two parents
     * NOTE: We pass NULL as the reference name to avoid updating any reference.
     * The caller is responsible for updating branch references.
     */
    const git_commit *parents[] = { our_commit, their_commit };
    err = git_commit_create(
        out_oid, repo, NULL, sig, sig, NULL, message, tree, 2, parents
    );

    git_signature_free(sig);
    git_tree_free(tree);

    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

/**
 * Perform in-memory rebase without modifying HEAD
 */
error_t *gitops_rebase_inmemory_safe(
    git_repository *repo, const git_oid *branch_oid, const git_oid *onto_oid,
    git_oid *out_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_oid);
    CHECK_NULL(onto_oid);
    CHECK_NULL(out_oid);

    git_annotated_commit *branch_commit = NULL;
    git_annotated_commit *onto_commit = NULL;
    git_rebase *rebase = NULL;
    git_signature *sig = NULL;
    error_t *err = NULL;
    int git_err;

    /* Create annotated commits for rebase */
    git_err = git_annotated_commit_lookup(&branch_commit, repo, branch_oid);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_err = git_annotated_commit_lookup(&onto_commit, repo, onto_oid);
    if (git_err < 0) {
        git_annotated_commit_free(branch_commit);
        return error_from_git(git_err);
    }

    /* Initialize in-memory rebase
     * CRITICAL: opts.inmemory = 1 ensures HEAD is never modified
     */
    git_rebase_options opts;
    git_rebase_options_init(&opts, GIT_REBASE_OPTIONS_VERSION);
    opts.inmemory = 1;  /* This is the key - never touch HEAD or working directory */

    git_err = git_rebase_init(&rebase, repo, branch_commit, NULL, onto_commit, &opts);
    git_annotated_commit_free(onto_commit);
    git_annotated_commit_free(branch_commit);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Get signature once for all rebase operations */
    err = gitops_get_signature(&sig, repo);
    if (err) {
        git_rebase_abort(rebase);
        git_rebase_free(rebase);
        return error_wrap(err, "Failed to get signature for rebase");
    }

    /* Process each rebase operation Initialize commit_oid to onto_oid - if there
     * are no operations to rebase (branch is already up-to-date or behind), we
     * return onto_oid which is correct for both cases (no-op or fast-forward).
     */
    git_rebase_operation *op = NULL;
    git_oid commit_oid;
    git_oid_cpy(&commit_oid, onto_oid);

    while ((git_err = git_rebase_next(&op, rebase)) == 0) {
        /* Commit the rebased operation In inmemory mode, this doesn't touch HEAD
         * or working directory
         */
        git_err = git_rebase_commit(&commit_oid, rebase, NULL, sig, NULL, NULL);

        if (git_err < 0) {
            git_signature_free(sig);
            git_rebase_abort(rebase);
            git_rebase_free(rebase);

            /* Check for merge conflicts Both GIT_EMERGECONFLICT (-13) and
             * GIT_EUNMERGED (-10) indicate conflicts
             */
            if (git_err == GIT_EMERGECONFLICT || git_err == GIT_EUNMERGED) {
                return ERROR(
                    ERR_CONFLICT, "Rebase resulted in conflicts. "
                    "Resolve manually using 'git rebase' or try merge strategy instead."
                );
            }

            err = error_from_git(git_err);
            return error_wrap(err, "Failed to commit during rebase");
        }
    }

    /* Free signature now that we're done with all commits */
    git_signature_free(sig);

    /* Check if rebase completed successfully */
    if (git_err != GIT_ITEROVER) {
        err = error_from_git(git_err);
        git_rebase_abort(rebase);
        git_rebase_free(rebase);
        return error_wrap(err, "Rebase iteration failed");
    }

    /* Finish rebase */
    git_err = git_rebase_finish(rebase, NULL);
    git_rebase_free(rebase);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Return the final commit OID */
    git_oid_cpy(out_oid, &commit_oid);
    return NULL;
}

/**
 * Update branch reference to new commit
 */
error_t *gitops_update_branch_reference(
    git_repository *repo, const char *branch_name, const git_oid *new_oid,
    const char *reflog_msg
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(new_oid);
    CHECK_NULL(reflog_msg);

    /* Build reference name */
    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_branch_refname(refname, sizeof(refname), branch_name);
    if (err) {
        return err;
    }

    /* Lookup existing reference */
    git_reference *ref = NULL;
    int git_err = git_reference_lookup(&ref, repo, refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Update reference to new OID with reflog message This is an atomic operation
     * that updates the branch without touching HEAD
     */
    git_reference *new_ref = NULL;
    git_err = git_reference_set_target(&new_ref, ref, new_oid, reflog_msg);
    git_reference_free(ref);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_reference_free(new_ref);
    return NULL;
}

/**
 * Diff operations
 */
error_t *gitops_diff_trees(
    git_repository *repo, git_tree *old_tree, git_tree *new_tree,
    const git_diff_options *opts, git_diff **out_diff
) {
    CHECK_NULL(repo);
    CHECK_NULL(out_diff);

    /* Note: old_tree and new_tree can be NULL for added/deleted semantics */

    int ret = git_diff_tree_to_tree(
        out_diff, repo, old_tree, new_tree, opts
    );
    if (ret < 0) {
        return error_from_git(ret);
    }

    return NULL;
}

error_t *gitops_diff_get_stats(
    git_diff *diff, git_diff_stats **out_stats
) {
    CHECK_NULL(diff);
    CHECK_NULL(out_stats);

    int ret = git_diff_get_stats(out_stats, diff);
    if (ret < 0) {
        return error_from_git(ret);
    }

    return NULL;
}

/**
 * A branch name to its reference, or Git's refusal
 */
error_t *gitops_branch_refname(
    char *buffer, size_t buffer_size, const char *name
) {
    CHECK_NULL(buffer);
    CHECK_NULL(name);

    int valid = 0;
    int ret = git_branch_name_is_valid(&valid, name);
    if (ret < 0) {
        return error_from_git(ret);
    }
    if (!valid) {
        return ERROR(ERR_INVALID_ARG, "'%s' is not a valid branch name", name);
    }

    return gitops_build_refname(buffer, buffer_size, "refs/heads/%s", name);
}

/**
 * Validate and build a Git reference name
 */
error_t *gitops_build_refname(
    char *buffer, size_t buffer_size, const char *format,
    ...
) {
    CHECK_NULL(buffer);
    CHECK_NULL(format);

    if (buffer_size == 0) {
        return ERROR(ERR_INVALID_ARG, "Buffer size must be greater than 0");
    }

    va_list args;
    va_start(args, format);
    int written = vsnprintf(buffer, buffer_size, format, args);
    va_end(args);

    if (written < 0) {
        return ERROR(ERR_INTERNAL, "Failed to format reference name");
    }

    if ((size_t) written >= buffer_size) {
        return ERROR(
            ERR_INVALID_ARG, "Reference name too long (truncated): "
            "needs %d bytes, buffer is %zu bytes", written + 1, buffer_size
        );
    }

    /* Validate reference name against Git naming rules */
    if (!strchr(buffer, ':')) {
        int valid = 0;
        int ret = git_reference_name_is_valid(&valid, buffer);
        if (ret < 0) {
            return ERROR(ERR_INTERNAL, "Failed to validate reference name");
        }
        if (!valid) {
            return ERROR(
                ERR_INVALID_ARG, "Invalid Git reference name: '%s'",
                buffer
            );
        }
    }

    return NULL;
}
