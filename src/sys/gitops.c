/**
 * gitops.c - Git operations wrapper implementation
 *
 * All libgit2 calls are wrapped with error handling and resource cleanup.
 */

#include "sys/gitops.h"

#include <dirent.h>
#include <errno.h>
#include <git2.h>
#include <git2/sys/repository.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/refspec.h"
#include "base/string.h"
#include "sys/filesystem.h"
#include "sys/identity.h"
#include "sys/transfer.h"

error_t gitops_init(void) {
    /* The one git failure error_from_git cannot read: git_error_last answers
     * out of a thread-local the runtime sets up, and an init that failed leaves
     * the count at zero, so libgit2's own reply is the static "you must call
     * git_libgit2_init" — the call that just failed, offered to a user who cannot
     * make it. The subject is the whole message, and it has to be, main() being
     * the one caller that prints an error rather than wrapping it. */
    if (git_libgit2_init() < 0) {
        return ERROR(ERR_GIT, "Failed to initialize libgit2");
    }

    /* libgit2 caches a parsed object only below a per-type ceiling, 4096 bytes
     * for a tree by default — an entry costs its name plus 27 — so a directory
     * past ~110 entries yields a tree that is never cached, and every
     * git_tree_entry_bypath through it re-reads, inflates and SHA-1-verifies
     * each tree on the way down. Four loops ask once per item, quadratic where
     * the items scale with the directory's own width: core/workspace.c per orphaned
     * record, core/profiles.c per tracked directory item, cmds/list.c per listed
     * file under -v, cmds/export.c per sheet key.
     *
     * Trees: no ceiling. Blobs: libgit2's zero, never cached — infra/content
     * keeps the one a blob needs. Total: 64 MB, below libgit2's 256 MB default.
     *
     * Unchecked because a refused opt leaves these two defaults standing, and
     * standing they cost speed and change no answer. That is the test and not
     * the habit: a knob whose refusal would change an answer — the strict-object
     * and owner-validation family this function's header names — is checked where
     * it is set. */
    (void) git_libgit2_opts(
        GIT_OPT_SET_CACHE_OBJECT_LIMIT, GIT_OBJECT_TREE, (size_t) SIZE_MAX
    );
    (void) git_libgit2_opts(
        GIT_OPT_SET_CACHE_MAX_SIZE, (ssize_t) (64 * 1024 * 1024)
    );

    return NULL;
}

void gitops_shutdown(void) {
    git_libgit2_shutdown();
}

error_t gitops_get_signature(git_signature **out, git_repository *repo) {
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
    if (err < 0) return error_from_git(err);

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
error_t gitops_open_repository(git_repository **out, const char *path) {
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
    if (err < 0) return error_from_git(err);

    return NULL;
}

error_t gitops_init_repository(git_repository **out, const char *path) {
    CHECK_NULL(out);
    CHECK_NULL(path);

    git_repository_init_options opts;
    git_repository_init_options_init(&opts, GIT_REPOSITORY_INIT_OPTIONS_VERSION);
    opts.flags = GIT_REPOSITORY_INIT_BARE | GIT_REPOSITORY_INIT_MKPATH;

    int err = git_repository_init_ext(out, path, &opts);
    if (err < 0) return error_from_git(err);

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

/*
 * A reference database that has never read the store, installed on the handle.
 * libgit2 reads packed-refs again when the file changed and never when it did
 * not — not even one whose parse it refused: it stamps the file before parsing
 * and keeps the stamp over a failed parse, then serves the emptied cache as the
 * store until the file changes (util/sortedcache.c git_sortedcache_lockandload,
 * refdb_fs.c packed_reload). So a decision that rests on what the store does
 * not hold — an absence, a listing's completeness, a name free for a create —
 * reads through a database that has read nothing yet. The handle keeps its own
 * count of the one it is given (git_repository_set_refdb), and a reference or
 * an iterator from the old one keeps that one alive (refdb.c counts each).
 */
static error_t gitops_reopen_refdb(git_repository *repo) {
    git_refdb *fresh = NULL;
    int rc = git_refdb_open(&fresh, repo);
    if (rc < 0) {
        return error_wrap(error_from_git(rc), "Cannot read the references");
    }

    rc = git_repository_set_refdb(repo, fresh);
    git_refdb_free(fresh);
    if (rc < 0) {
        return error_wrap(error_from_git(rc), "Cannot read the references");
    }
    return NULL;
}

error_t gitops_reference_find(
    git_repository *repo, const char *refname, git_reference **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(refname);
    CHECK_NULL(out);
    CHECK_ARG(refname[0] != '\0', "Reference name cannot be empty");

    /* A loose ref answers "not there" only where no file stands, or a directory
     * does — an unreadable one is GIT_ELOCKED (fs_path.c git_fs_path_set_error)
     * — so a lookup that finds, or fails, is the answer. */
    *out = NULL;
    int rc = git_reference_lookup(out, repo, refname);
    if (rc != GIT_ENOTFOUND) {
        return rc < 0 ? error_from_git(rc) : NULL;
    }

    /* A miss read packed-refs one of two ways, and neither proves it: under the
     * sorted trait, which git and libgit2 both write, a search that one damaged
     * record steers past its own name — and every name before it, where it sits
     * at the first probe (refdb_fs.c packed_lookup); otherwise a cached parse a
     * refused one left empty. So the name is listed through a database that has
     * read nothing: the iterator parses the file whole and refuses a damaged
     * one. A refname carries no byte libgit2's glob reads specially — the reference
     * rule refuses '*', '?', '[' and '\' — so the name is its own glob. */
    RETURN_IF_ERROR(gitops_reopen_refdb(repo));

    git_reference_iterator *iter = NULL;
    rc = git_reference_iterator_glob_new(&iter, repo, refname);
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "Cannot read reference '%s'", refname
        );
    }
    const char *listed = NULL;
    rc = git_reference_next_name(&listed, iter);
    git_reference_iterator_free(iter);
    if (rc == GIT_ITEROVER) return NULL;
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "Cannot read reference '%s'", refname
        );
    }

    /* Listed: asked once more, of the database whose cache the parse just filled
     * — an unsorted file's lookup reads that cache and finds it. A sorted file's
     * search can miss a name its parse lists, records out of order or CRLF line
     * ends, and that is no absence. */
    rc = git_reference_lookup(out, repo, refname);
    if (rc == GIT_ENOTFOUND) {
        return ERROR(
            ERR_GIT, "Reference '%s' is listed but no lookup reaches it", refname
        );
    }
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "Cannot read reference '%s'", refname
        );
    }
    return NULL;
}

error_t gitops_reference_exists(
    git_repository *repo, const char *refname, bool *exists
) {
    CHECK_NULL(repo);
    CHECK_NULL(refname);
    CHECK_NULL(exists);

    git_reference *ref = NULL;
    RETURN_IF_ERROR(gitops_reference_find(repo, refname, &ref));
    *exists = ref != NULL;
    git_reference_free(ref);

    return NULL;
}

error_t gitops_branch_exists(
    git_repository *repo, const char *name, bool *exists
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(exists);

    char refname[DOTTA_REFNAME_MAX];
    RETURN_IF_ERROR(gitops_branch_refname(refname, sizeof(refname), name));

    return gitops_reference_exists(repo, refname, exists);
}

error_t gitops_branch_blocker(
    git_repository *repo, const char *name, char *blocker, size_t size
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(blocker);
    CHECK_ARG(size > 0, "blocker buffer cannot be empty");

    blocker[0] = '\0';

    /* Only a name Git accepts stands anywhere to be blocked: one it refuses is
     * refused here, in the branch rule's words, and never scanned. */
    char refname[DOTTA_REFNAME_MAX];
    RETURN_IF_ERROR(gitops_branch_refname(refname, sizeof(refname), name));

    /* The branches, in a frame of this call's own: the answer is copied out of
     * it into the caller's buffer before it goes. */
    arena_t *frame = arena_create(0);
    string_array_t branches;
    error_t err = gitops_list_branches(repo, frame, &branches);

    size_t len = strlen(name);
    for (size_t i = 0; !err && i < branches.count; i++) {
        const char *other = branches.entries[i];
        size_t other_len = strlen(other);

        /* Nested names: one is a folder the other lives in — the shorter matched
         * whole, with a '/' where the longer one continues past it. Equal names
         * are not nested, and the boundary test says so on its own: the shorter
         * length indexes the other name's terminator. */
        size_t shorter = other_len < len ? other_len : len;
        bool nested = strncmp(other, name, shorter) == 0
            && (other_len > len ? other[len] : name[other_len]) == '/';

        if (nested) {
            /* A listed branch is a ref name, which a caller's DOTTA_REFNAME_MAX
             * buffer holds whole: a shorter buffer is the caller's bug. */
            CHECK_ARG(other_len < size, "blocker buffer too small for a branch name");
            memcpy(blocker, other, other_len + 1);
            break;
        }
    }

    arena_free(frame);
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
static error_t walk_loose_refs(const loose_walk_t *walk, const char *dir) {
    DIR *d = fs_opendir(dir);
    if (!d) {
        if (errno == ENOENT) return NULL;
        return error_from_errno(errno, "Cannot read the refs under '%s'", dir);
    }

    /* errno cleared before every readdir: a NULL is the end, or the error it names */
    error_t err = NULL;
    struct dirent *entry;
    for (errno = 0; (entry = readdir(d)) != NULL; errno = 0) {
        const char *name = entry->d_name;
        if (name[0] == '.' || str_ends_with(name, ".lock")) {
            continue;
        }

        char *path = heap_str_format("%s/%s", dir, name);

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
                if (rc == GIT_ENOTFOUND) break;
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
                    string_array_push(walk->names, listed);
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
        if (err) break;
    }

    if (!err && errno != 0) {
        err = error_from_errno(errno, "Cannot read the refs under '%s'", dir);
    }
    closedir(d);
    return err;
}

error_t gitops_list_refs(
    git_repository *repo, const char *namespace, arena_t *arena, string_array_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(namespace);
    CHECK_NULL(arena);
    CHECK_NULL(out);
    CHECK_ARG(namespace[0] != '\0', "Reference namespace cannot be empty");

    /* libgit2's enumeration under the namespace: the packed refs, loudly, parsed
     * by a database that has read nothing yet — one that met a refused parse
     * would list no packed ref at all (gitops_reopen_refdb); the loose ones as
     * far as it could read them. The glob walks the namespace's own directory
     * and nothing beside it; a name is listed past "<namespace>/". */
    RETURN_IF_ERROR(gitops_reopen_refdb(repo));

    char glob[DOTTA_REFNAME_MAX];
    int written = snprintf(glob, sizeof(glob), "%s/*", namespace);
    if (written < 0 || (size_t) written >= sizeof(glob)) {
        return ERROR(
            ERR_INVALID_ARG, "Reference namespace too long: '%s'", namespace
        );
    }

    git_reference_iterator *iter = NULL;
    int rc = git_reference_iterator_glob_new(&iter, repo, glob);
    if (rc < 0) return error_from_git(rc);
    string_array_t names;
    string_array_init(&names, arena);

    error_t err = NULL;
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
        string_array_push(&names, refname + strlen(namespace) + 1);
    }
    git_reference_iterator_free(iter);
    if (err) return err;

    /* The loose store beneath it, read whole: its directory is spelled in the
     * answer's arena, beside the names. */
    const char *dir = str_path_join(arena, git_repository_commondir(repo), namespace);
    loose_walk_t walk = {
        .repo       = repo,
        .refname_at = strlen(dir) - strlen(namespace),
        .depth      = 1,
        .names      = &names,
    };
    for (const char *slash = strchr(namespace, '/'); slash;
        slash = strchr(slash + 1, '/')) {
        walk.depth++;
    }
    RETURN_IF_ERROR(walk_loose_refs(&walk, dir));

    *out = names;
    return NULL;
}

error_t gitops_list_branches(git_repository *repo, arena_t *arena, string_array_t *out) {
    CHECK_NULL(repo);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    return gitops_list_refs(repo, "refs/heads", arena, out);
}

error_t gitops_list_remote_tracking(
    git_repository *repo, const char *remote_name, arena_t *arena, string_array_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    char namespace[DOTTA_REFNAME_MAX];
    error_t err = gitops_build_refname(
        namespace, sizeof(namespace), "refs/remotes/%s", remote_name
    );
    if (err) return err;

    string_array_t names;
    err = gitops_list_refs(repo, namespace, arena, &names);
    if (err) return err;

    /* Under the remote's namespace and not a branch of it: its symbolic HEAD. */
    string_array_remove_value(&names, "HEAD");

    *out = names;
    return NULL;
}

error_t gitops_delete_branch(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    char refname[DOTTA_REFNAME_MAX];
    RETURN_IF_ERROR(gitops_branch_refname(refname, sizeof(refname), name));

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
 * Resolve a Git reference to its tree
 *
 * Shared implementation for gitops_load_tree and gitops_load_branch_tree: the
 * reference peeled to whatever it names — a commit's tree for a commit-backed
 * branch, the tree itself for an orphan-tree one.
 */
static error_t resolve_ref_to_tree(
    git_repository *repo, const char *ref_name, git_tree **out_tree
) {
    /* The reference, or its absence proven (gitops_reference_find) */
    git_reference *ref = NULL;
    RETURN_IF_ERROR(gitops_reference_find(repo, ref_name, &ref));
    if (!ref) {
        return ERROR(ERR_NOT_FOUND, "Reference '%s' not found", ref_name);
    }

    /* Peel reference to get the underlying object */
    git_object *obj = NULL;
    int err = git_reference_peel(&obj, ref, GIT_OBJECT_ANY);
    git_reference_free(ref);
    if (err < 0) {
        return error_wrap(
            error_from_git(err), "Failed to peel reference '%s'",
            ref_name
        );
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
        if (err < 0) return error_from_git(err);
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

error_t gitops_load_tree(
    git_repository *repo, const char *ref_name, git_tree **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ref_name);
    CHECK_NULL(out);
    CHECK_ARG(ref_name[0] != '\0', "Reference name cannot be empty");

    return resolve_ref_to_tree(repo, ref_name, out);
}

error_t gitops_load_branch_tree(
    git_repository *repo, const char *branch_name, git_tree **out_tree
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out_tree);

    char refname[DOTTA_REFNAME_MAX];
    error_t err = gitops_branch_refname(
        refname, sizeof(refname), branch_name
    );
    if (err) return err;

    return resolve_ref_to_tree(repo, refname, out_tree);
}

error_t gitops_tree_walk(
    const git_tree *tree, git_treewalk_cb callback, void *payload
) {
    CHECK_NULL(tree);
    CHECK_NULL(callback);

    int err = git_tree_walk(tree, GIT_TREEWALK_PRE, callback, payload);
    if (err < 0) return error_from_git(err);

    return NULL;
}

/**
 * Commit operations
 */
error_t gitops_load_commit(
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

error_t gitops_load_branch_commit(
    git_repository *repo, const char *branch, git_commit **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch);
    CHECK_NULL(out);

    char refname[DOTTA_REFNAME_MAX];
    RETURN_IF_ERROR(gitops_branch_refname(refname, sizeof(refname), branch));

    /* Through a symbolic branch to the one it names: `git symbolic-ref` makes
     * one legally, and every other reader of a branch reads through it. */
    git_oid tip;
    int rc = git_reference_name_to_id(&tip, repo, refname);
    if (rc < 0) {
        return error_wrap(error_from_git(rc), "Cannot read branch '%s'", branch);
    }

    /* The tip is read as a commit, as the stage reads the parent it commits on
     * (sys/stage.c): a branch naming a tag or a tree has no commit at its tip. */
    rc = git_commit_lookup(out, repo, &tip);
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "Cannot read the tip of branch '%s'", branch
        );
    }

    return NULL;
}

/*
 * One of HEAD's steps, read at the cursor and the cursor moved past it: the step's
 * operator, `~` or `^`, with its count — 1 where none is written — or 0 where
 * the text at the cursor is no step. The count saturates rather than wraps: no
 * history is 2^64 commits deep, so a count past that reaches beyond the root
 * like any count longer than the history, git's own reading of one that overflows
 * (lib/git/object-name.c get_nth_ancestor). The digits are ASCII's ten, whatever
 * the locale's classes hold.
 */
static char gitops_revision_step(const char **cursor, size_t *count) {
    const char *p = *cursor;
    const char op = *p++;
    if (op != '~' && op != '^') return 0;

    size_t n = *p >= '0' && *p <= '9' ? 0 : 1;
    for (; *p >= '0' && *p <= '9'; p++) {
        const size_t digit = (size_t) (*p - '0');
        n = n > (SIZE_MAX - digit) / 10 ? SIZE_MAX : n * 10 + digit;
    }

    *cursor = p;
    *count = n;
    return op;
}

error_t gitops_revision_resolve(
    git_repository *repo, const char *spelling, gitops_revision_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(spelling);
    CHECK_NULL(out);

    /* HEAD's steps are read whole now, so one the walk would not take refuses
     * before any branch is read; gitops_revision_find walks them from each tip. */
    const char *ancestry = refspec_ancestry(spelling);
    if (ancestry) {
        for (const char *step = ancestry; *step;) {
            size_t count = 0;
            if (!gitops_revision_step(&step, &count)) {
                return ERROR(
                    ERR_INVALID_ARG,
                    "Cannot resolve '%s': after HEAD, dotta reads ~N and ^N steps",
                    spelling
                );
            }
        }
        *out = (gitops_revision_t){ .spelling = spelling, .ancestry = ancestry };
        return NULL;
    }

    /* Every other spelling is git's, and names one commit whichever branch is
     * asked after, so it is resolved here, once. revparse answers a typo, a lost
     * commit and a tag whose object is gone alike (GIT_ENOTFOUND), and nothing
     * after it could tell them apart: a spelling that does not resolve is the
     * failure, and never a branch passed over. */
    git_object *named = NULL;
    int rc = git_revparse_single(&named, repo, spelling);
    if (rc < 0) {
        return error_wrap(error_from_git(rc), "Cannot resolve '%s'", spelling);
    }

    /* Peeled to a commit: an annotated tag's id is the tag's, and the commit is
     * the one it names, so the id the revision holds is always a commit's — the
     * reachability query reads commits. A tree or a blob names none, refused
     * here rather than as a failure later. A commit peels to a counted reference
     * to itself, which is why the named object is freed on its own. */
    git_object *commit = NULL;
    rc = git_object_peel(&commit, named, GIT_OBJECT_COMMIT);
    git_object_free(named);
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "'%s' does not point to a commit", spelling
        );
    }

    *out = (gitops_revision_t){ .spelling = spelling };
    git_oid_cpy(&out->commit, git_object_id(commit));
    git_object_free(commit);
    return NULL;
}

error_t gitops_revision_find(
    git_repository *repo, const gitops_revision_t *rev, const char *branch,
    git_commit *tip, git_commit **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(rev);
    CHECK_NULL(branch);
    CHECK_NULL(tip);
    CHECK_NULL(out);

    *out = NULL;

    if (!rev->ancestry) {
        /* A commit resolved repository-wide may be any branch's, and read as
         * this one's without asking it would be misattributed. It is the branch's
         * where the tip is that commit or reaches it through its parents — the
         * graph answers the tip itself as reachable, which descendant_of does
         * not (graph.c). A history it cannot read is the failure, as `git
         * merge-base --is-ancestor` fails it: an unread object below the commit
         * decides nothing. */
        int rc = git_graph_reachable_from_any(repo, &rev->commit, git_commit_id(tip), 1);
        if (rc < 0) {
            return error_wrap(
                error_from_git(rc),
                "Cannot tell whether commit '%s' is reachable from branch '%s'",
                rev->spelling, branch
            );
        }
        if (rc == 0) return NULL;

        rc = git_commit_lookup(out, repo, &rev->commit);
        if (rc < 0) {
            return error_wrap(
                error_from_git(rc), "Cannot read commit '%s'", rev->spelling
            );
        }
        return NULL;
    }

    /* HEAD's steps, walked back from the tip this branch was read at. The walk
     * holds its own reference from the start — the tip is the answer to HEAD
     * itself — and git_commit_dup's one answer is 0 (a count taken, nothing
     * made). */
    git_commit *at = NULL;
    (void) git_commit_dup(&at, tip);

    for (const char *step = rev->ancestry; *step;) {
        size_t count = 0;
        const char op = gitops_revision_step(&step, &count);
        CHECK_ARG(op != 0, "a revision's steps are the ones its resolve read");

        /* `~N` takes N first parents; `^N` takes one step, to the Nth parent,
         * and `^0` none — it is the commit itself. */
        size_t steps = count;
        size_t nth = 0;
        if (op == '^') {
            if (count == 0) continue;
            steps = 1;
            nth = count - 1;
        }

        for (; steps > 0; steps--) {
            /* The count read off the parsed commit is the evidence: a parent
             * past it is a history shorter than the steps reach — no commit, an
             * answer — while one it names is there to load, and a load that fails
             * is an object the store lost, though libgit2 answers GIT_ENOTFOUND. */
            if (nth >= git_commit_parentcount(at)) {
                git_commit_free(at);
                return NULL;
            }

            git_commit *parent = NULL;
            int rc = git_commit_parent(&parent, at, (unsigned int) nth);
            git_commit_free(at);
            if (rc < 0) {
                return error_wrap(
                    error_from_git(rc), "Cannot walk '%s' in branch '%s'",
                    rev->spelling, branch
                );
            }
            at = parent;
        }
    }

    *out = at;
    return NULL;
}

/**
 * Resolve commit reference within a branch
 */
error_t gitops_resolve_commit_in_branch(
    git_repository *repo, const char *branch_name, const char *commit_ref,
    git_commit **out_commit
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(commit_ref);
    CHECK_NULL(out_commit);

    /* The revision first: a spelling that names nothing refuses before the branch
     * is read, whichever branch is named. */
    gitops_revision_t rev;
    RETURN_IF_ERROR(gitops_revision_resolve(repo, commit_ref, &rev));

    /* The tip, read once, and the revision asked of it: HEAD's steps and the
     * membership of a commit are one tip's answers, never two reads of a ref
     * that may move between them. */
    git_commit *tip = NULL;
    RETURN_IF_ERROR(gitops_load_branch_commit(repo, branch_name, &tip));

    error_t err = gitops_revision_find(repo, &rev, branch_name, tip, out_commit);
    git_commit_free(tip);
    if (err || *out_commit) return err;

    /* The branch has no commit for it: HEAD's steps reach past its history, or
     * its history does not hold the commit. */
    if (rev.ancestry) {
        return ERROR(
            ERR_NOT_FOUND, "'%s' names no commit of branch '%s'", commit_ref,
            branch_name
        );
    }
    return ERROR(
        ERR_NOT_FOUND, "Commit '%s' is not reachable from branch '%s'",
        commit_ref, branch_name
    );
}

/**
 * Remote operations
 */
error_t gitops_fetch_remote(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) return error_from_git(err);

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

    if (err < 0) return error_from_git(err);
    return NULL;
}

error_t gitops_fetch_branch(
    git_repository *repo, const char *remote_name, const char *branch_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(xfer);

    /* The refspec's source is the branch's ref, spelled where every one is. */
    char refname[DOTTA_REFNAME_MAX];
    RETURN_IF_ERROR(gitops_branch_refname(refname, sizeof(refname), branch_name));

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) return error_from_git(err);

    git_fetch_options fetch_opts;
    git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &fetch_opts.callbacks, xfer, GIT_DIRECTION_FETCH
    );

    char refspec[DOTTA_REFSPEC_MAX];
    error_t err_build = gitops_build_refname(
        refspec, sizeof(refspec), "%s:refs/remotes/%s/%s",
        refname, remote_name, branch_name
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

    if (err < 0) return error_from_git(err);
    return NULL;
}

error_t gitops_fetch_branches(
    git_repository *repo, const char *remote_name, const string_array_t *branches,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branches);
    CHECK_NULL(xfer);
    CHECK_ARG(branches->count > 0, "branches must not be empty");

    /* Look up remote once */
    git_remote *remote = NULL;
    int rc = git_remote_lookup(&remote, repo, remote_name);
    if (rc < 0) return error_from_git(rc);

    /* The refspecs, one per branch, in a frame of this call's own — its answer
     * is no memory — and in the one shape git_strarray reads: a string array's
     * entries are an argv as they stand. */
    arena_t *frame = arena_create(0);
    string_array_t refspecs;
    string_array_init_cap(&refspecs, frame, branches->count);

    error_t err = NULL;
    for (size_t i = 0; i < branches->count; i++) {
        /* Each refspec's source is its branch's ref, spelled where every one is. */
        char refname[DOTTA_REFNAME_MAX];
        err = gitops_branch_refname(refname, sizeof(refname), branches->entries[i]);
        if (err) goto cleanup;

        /* Build refspec: refs/heads/branch:refs/remotes/origin/branch */
        char refspec[DOTTA_REFSPEC_MAX];
        err = gitops_build_refname(
            refspec, sizeof(refspec), "%s:refs/remotes/%s/%s",
            refname, remote_name, branches->entries[i]
        );
        if (err) {
            err = error_wrap(
                err, "Invalid branch/remote name '%s/%s'",
                remote_name, branches->entries[i]
            );
            goto cleanup;
        }
        string_array_push(&refspecs, refspec);
    }

    git_fetch_options fetch_opts;
    git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &fetch_opts.callbacks, xfer, GIT_DIRECTION_FETCH
    );

    git_strarray refs = { refspecs.entries, refspecs.count };

    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    rc = git_remote_fetch(remote, &refs, &fetch_opts, NULL);
    transfer_op_end(xfer, rc);

    if (rc < 0) err = error_from_git(rc);

cleanup:
    arena_free(frame);
    git_remote_free(remote);
    return err;
}

error_t gitops_push_branch(
    git_repository *repo, const char *remote_name, const char *branch_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(xfer);

    /* The refspec's halves are the branch's ref, spelled where every one is. */
    char refname[DOTTA_REFNAME_MAX];
    RETURN_IF_ERROR(gitops_branch_refname(refname, sizeof(refname), branch_name));

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) return error_from_git(err);

    git_push_options push_opts;
    git_push_options_init(&push_opts, GIT_PUSH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &push_opts.callbacks, xfer, GIT_DIRECTION_PUSH
    );

    char refspec[DOTTA_REFSPEC_MAX];
    error_t err_build = gitops_build_refname(
        refspec, sizeof(refspec), "%s:%s", refname, refname
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

    if (err < 0) return error_from_git(err);

    return NULL;
}

error_t gitops_force_push_branch(
    git_repository *repo, const char *remote_name, const char *branch_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(xfer);

    /* The refspec's halves are the branch's ref, spelled where every one is. */
    char refname[DOTTA_REFNAME_MAX];
    RETURN_IF_ERROR(gitops_branch_refname(refname, sizeof(refname), branch_name));

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) return error_from_git(err);

    git_push_options push_opts;
    git_push_options_init(&push_opts, GIT_PUSH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &push_opts.callbacks, xfer, GIT_DIRECTION_PUSH
    );

    /* Force push refspec ('+' prefix accepts non-fast-forward update) */
    char refspec[DOTTA_REFSPEC_MAX];
    error_t err_build = gitops_build_refname(
        refspec, sizeof(refspec), "+%s:%s", refname, refname
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

    if (err < 0) return error_from_git(err);

    return NULL;
}

error_t gitops_delete_remote_branch(
    git_repository *repo, const char *remote_name, const char *branch_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(xfer);

    /* The refspec's halves are the branch's ref, spelled where every one is. */
    char refname[DOTTA_REFNAME_MAX];
    RETURN_IF_ERROR(gitops_branch_refname(refname, sizeof(refname), branch_name));

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) return error_from_git(err);

    git_push_options push_opts;
    git_push_options_init(&push_opts, GIT_PUSH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &push_opts.callbacks, xfer, GIT_DIRECTION_PUSH
    );

    /* Delete remote branch using empty refspec: :refs/heads/branch */
    char refspec[DOTTA_REFSPEC_MAX];
    error_t err_build = gitops_build_refname(
        refspec, sizeof(refspec), ":%s", refname
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

    if (err < 0) return error_from_git(err);

    return NULL;
}

error_t gitops_list_remote_branches(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer,
    arena_t *arena, string_array_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err < 0) return error_from_git(git_err);

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
        return error_from_git(git_err);
    }

    const git_remote_head **refs = NULL;
    size_t refs_len = 0;
    git_err = git_remote_ls(&refs, &refs_len, remote);
    if (git_err < 0) {
        git_remote_disconnect(remote);
        git_remote_free(remote);
        return error_from_git(git_err);
    }

    static const char heads_prefix[] = "refs/heads/";
    const size_t prefix_len = sizeof(heads_prefix) - 1;

    string_array_t branches;
    string_array_init(&branches, arena);
    for (size_t i = 0; i < refs_len; i++) {
        const char *refname = refs[i]->name;

        if (!str_starts_with(refname, heads_prefix)) {
            continue;
        }

        const char *branch_name = refname + prefix_len;

        if (*branch_name == '\0') {
            continue;
        }

        string_array_push(&branches, branch_name);
    }

    git_remote_disconnect(remote);
    git_remote_free(remote);

    *out = branches;
    return NULL;
}

error_t gitops_get_remote_url(
    git_repository *repo, const char *remote_name, arena_t *arena,
    const char **out_url
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(arena);
    CHECK_NULL(out_url);

    git_remote *remote = NULL;
    int rc = git_remote_lookup(&remote, repo, remote_name);
    if (rc < 0) return error_from_git(rc);

    /* Copied before the remote goes: the URL is the remote's, and NULL where it
     * has none. */
    *out_url = arena_strdup(arena, git_remote_url(remote));
    git_remote_free(remote);

    return NULL;
}

error_t gitops_resolve_default_remote(
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
    if (git_err < 0) return error_from_git(git_err);

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

    /* URL is optional, and so is a remote's: one without a URL answers NULL. */
    if (out_url) RETURN_IF_ERROR(gitops_get_remote_url(repo, name, arena, out_url));

    *out_name = name;

    return NULL;
}

/**
 * Reference operations
 */
error_t gitops_create_reference(
    git_repository *repo, const char *name, const git_oid *oid,
    bool force
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(oid);

    /* A create that must not overwrite decides the name free, and libgit2 asks
     * its cached parse of packed-refs — one a refused parse left empty would
     * find every packed name free, and the loose ref written would stand over a
     * packed branch. So the decision reads a database that has read nothing. */
    if (!force) RETURN_IF_ERROR(gitops_reopen_refdb(repo));

    git_reference *ref = NULL;
    int err = git_reference_create(&ref, repo, name, oid, force, NULL);
    if (err < 0) return error_from_git(err);

    git_reference_free(ref);

    return NULL;
}

error_t gitops_reference_oid(
    git_repository *repo, const char *ref_name, git_oid *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ref_name);
    CHECK_NULL(out);

    /* Found, or its absence proven (gitops_reference_find): a packed-refs that
     * will not parse is its own failure, never a reference that is not there. */
    git_reference *ref = NULL;
    RETURN_IF_ERROR(gitops_reference_find(repo, ref_name, &ref));
    if (!ref) {
        memset(out, 0, sizeof(*out));
        return NULL;
    }

    /* Through a symbolic reference to the one it names: one that names nothing
     * stands, and resolves to no id. */
    git_reference *direct = NULL;
    int err = git_reference_resolve(&direct, ref);
    git_reference_free(ref);
    if (err < 0) {
        return error_wrap(
            error_from_git(err), "Failed to resolve reference '%s'", ref_name
        );
    }
    git_oid_cpy(out, git_reference_target(direct));
    git_reference_free(direct);

    return NULL;
}

error_t gitops_resolve_reference_oid(
    git_repository *repo, const char *ref_name, git_oid *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ref_name);
    CHECK_NULL(out);

    RETURN_IF_ERROR(gitops_reference_oid(repo, ref_name, out));
    if (git_oid_is_zero(out)) {
        return ERROR(ERR_NOT_FOUND, "Reference '%s' not found", ref_name);
    }

    return NULL;
}

error_t gitops_resolve_branch_head_oid(
    git_repository *repo, const char *branch_name, git_oid *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out);

    char refname[DOTTA_REFNAME_MAX];
    error_t err = gitops_branch_refname(
        refname, sizeof(refname), branch_name
    );
    if (err) return err;

    return gitops_resolve_reference_oid(repo, refname, out);
}

error_t gitops_resolve_remote_branch_oid(
    git_repository *repo,
    const char *remote_name, const char *branch_name, git_oid *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(out);

    char refname[DOTTA_REFNAME_MAX];
    error_t err = gitops_build_refname(
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
 * Open a zero-copy view onto a blob
 */
error_t gitops_blob_view_open(
    git_repository *repo, const git_oid *oid, gitops_blob_view_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(oid);
    CHECK_NULL(out);

    *out = (gitops_blob_view_t){ 0 };

    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, repo, oid);
    if (git_err < 0) return error_from_git(git_err);

    out->_handle = blob;
    out->data = git_blob_rawcontent(blob);
    out->size = (size_t) git_blob_rawsize(blob);

    return NULL;
}

/**
 * Close a blob view
 */
void gitops_blob_view_close(gitops_blob_view_t *view) {
    if (!view || !view->_handle) return;

    git_blob_free(view->_handle);
    *view = (gitops_blob_view_t){ 0 };
}

/**
 * Read blob content by OID
 */
error_t gitops_read_blob_content(
    git_repository *repo, const git_oid *oid, void **out_content,
    size_t *out_size
) {
    CHECK_NULL(repo);
    CHECK_NULL(oid);
    CHECK_NULL(out_content);
    CHECK_NULL(out_size);

    gitops_blob_view_t view;
    error_t err = gitops_blob_view_open(repo, oid, &view);
    if (err) return err;

    void *content = heap_alloc(view.size + 1);

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
 * Get tree from commit OID
 */
error_t gitops_get_tree_from_commit(
    git_repository *repo, const git_oid *commit_oid,
    git_tree **out_tree
) {
    CHECK_NULL(repo);
    CHECK_NULL(commit_oid);
    CHECK_NULL(out_tree);

    /* Lookup commit */
    git_commit *commit = NULL;
    int err = git_commit_lookup(&commit, repo, commit_oid);
    if (err < 0) return error_from_git(err);

    /* Get tree from commit */
    err = git_commit_tree(out_tree, commit);
    git_commit_free(commit);
    if (err < 0) return error_from_git(err);

    return NULL;
}

/**
 * Find merge base between two commits
 */
error_t gitops_find_merge_base(
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
error_t gitops_merge_trees_safe(
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
    error_t err = NULL;
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

    if (git_err < 0) return error_from_git(git_err);

    *out_index = index;
    return NULL;
}

/**
 * Create merge commit from index
 */
error_t gitops_create_merge_commit(
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
    if (err < 0) return error_from_git(err);

    /* Lookup tree object */
    git_tree *tree = NULL;
    err = git_tree_lookup(&tree, repo, &tree_oid);
    if (err < 0) return error_from_git(err);

    /* Get signature with fallback */
    git_signature *sig = NULL;
    error_t sig_err = gitops_get_signature(&sig, repo);
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

    if (err < 0) return error_from_git(err);

    return NULL;
}

/**
 * Perform in-memory rebase without modifying HEAD
 */
error_t gitops_rebase_inmemory_safe(
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
    error_t err = NULL;
    int git_err;

    /* Create annotated commits for rebase */
    git_err = git_annotated_commit_lookup(&branch_commit, repo, branch_oid);
    if (git_err < 0) return error_from_git(git_err);

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

    if (git_err < 0) return error_from_git(git_err);

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

    if (git_err < 0) return error_from_git(git_err);

    /* Return the final commit OID */
    git_oid_cpy(out_oid, &commit_oid);
    return NULL;
}

/**
 * Update branch reference to new commit
 */
error_t gitops_update_branch_reference(
    git_repository *repo, const char *branch_name, const git_oid *new_oid,
    const char *reflog_msg
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(new_oid);
    CHECK_NULL(reflog_msg);

    /* Build reference name */
    char refname[DOTTA_REFNAME_MAX];
    error_t err = gitops_branch_refname(refname, sizeof(refname), branch_name);
    if (err) return err;

    /* Lookup existing reference */
    git_reference *ref = NULL;
    int git_err = git_reference_lookup(&ref, repo, refname);
    if (git_err < 0) return error_from_git(git_err);

    /* Update reference to new OID with reflog message This is an atomic operation
     * that updates the branch without touching HEAD
     */
    git_reference *new_ref = NULL;
    git_err = git_reference_set_target(&new_ref, ref, new_oid, reflog_msg);
    git_reference_free(ref);

    if (git_err < 0) return error_from_git(git_err);

    git_reference_free(new_ref);
    return NULL;
}

/**
 * Diff operations
 */
error_t gitops_diff_trees(
    git_repository *repo, git_tree *old_tree, git_tree *new_tree,
    const git_diff_options *opts, git_diff **out_diff
) {
    CHECK_NULL(repo);
    CHECK_NULL(out_diff);

    /* Note: old_tree and new_tree can be NULL for added/deleted semantics */

    int ret = git_diff_tree_to_tree(
        out_diff, repo, old_tree, new_tree, opts
    );
    if (ret < 0) return error_from_git(ret);

    return NULL;
}

error_t gitops_diff_get_stats(
    git_diff *diff, git_diff_stats **out_stats
) {
    CHECK_NULL(diff);
    CHECK_NULL(out_stats);

    int ret = git_diff_get_stats(out_stats, diff);
    if (ret < 0) return error_from_git(ret);

    return NULL;
}

/**
 * A branch name to its reference, or Git's refusal
 */
error_t gitops_branch_refname(
    char *buffer, size_t buffer_size, const char *name
) {
    CHECK_NULL(buffer);
    CHECK_NULL(name);

    /* A name typed empty is refused in words of its own: Git's rule refuses it
     * too, but as a name — "'' is not a valid branch name" — that leaves the
     * reader to decode what was typed. */
    if (name[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Branch name cannot be empty");
    }

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
error_t gitops_build_refname(
    char *buffer, size_t buffer_size, const char *format,
    ...
) {
    CHECK_NULL(buffer);
    CHECK_NULL(format);
    CHECK_ARG(buffer_size > 0, "buffer_size holds at least the terminator");

    /* The format is its writer's, so one that cannot be formatted is a caller's
     * bug; a name the buffer cannot hold is the user's, and refused. */
    va_list args;
    va_start(args, format);
    int written = vsnprintf(buffer, buffer_size, format, args);
    va_end(args);
    CHECK_ARG(written >= 0, "the reference format cannot be formatted");

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
            return error_from_git(ret);
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
