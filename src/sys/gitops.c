/**
 * gitops.c - Git operations wrapper implementation
 *
 * All libgit2 calls are wrapped with error handling and resource cleanup.
 */

#include "sys/gitops.h"

#include <git2.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "base/array.h"
#include "base/error.h"
#include "base/string.h"
#include "sys/transfer.h"

error_t *gitops_get_signature(git_signature **out, git_repository *repo) {
    if (git_signature_default(out, repo) == 0) {
        return NULL;
    }

    const char *user = getenv("USER");
    if (!user || !*user) user = "dotta";

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
 */
error_t *gitops_open_repository(git_repository **out, const char *path) {
    CHECK_NULL(out);
    CHECK_NULL(path);

    int err = git_repository_open(out, path);
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

error_t *gitops_discover_repository(char **out, const char *start_path) {
    CHECK_NULL(out);
    CHECK_NULL(start_path);

    git_buf buf = GIT_BUF_INIT;
    int err = git_repository_discover(&buf, start_path, 0, NULL);
    if (err < 0) {
        git_buf_dispose(&buf);
        return error_from_git(err);
    }

    *out = strdup(buf.ptr);
    git_buf_dispose(&buf);

    if (!*out) {
        return ERROR(ERR_MEMORY, "Failed to allocate repository path");
    }

    return NULL;
}

error_t *gitops_discover_and_open(git_repository **out, const char *start_path) {
    CHECK_NULL(out);
    CHECK_NULL(start_path);

    char *repo_path = NULL;
    error_t *err = gitops_discover_repository(&repo_path, start_path);
    if (err) {
        return err;
    }

    err = gitops_open_repository(out, repo_path);
    free(repo_path);
    return err;
}

/**
 * Branch/Reference operations
 */
error_t *gitops_branch_exists(
    git_repository *repo,
    const char *name,
    bool *exists
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(exists);
    CHECK_ARG(name[0] != '\0', "Branch name cannot be empty");

    git_reference *ref = NULL;
    char refname[DOTTA_REFNAME_MAX];
    error_t *err_build = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", name
    );
    if (err_build) {
        return error_wrap(
            err_build, "Invalid branch name '%s'", name
        );
    }

    int err = git_reference_lookup(&ref, repo, refname);
    if (err == GIT_ENOTFOUND) {
        *exists = false;
        return NULL;
    }

    if (err < 0) {
        return error_from_git(err);
    }

    git_reference_free(ref);

    *exists = true;
    return NULL;
}

error_t *gitops_create_orphan_branch(
    git_repository *repo,
    const char *name
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_ARG(name[0] != '\0', "Branch name cannot be empty");

    /* Create empty tree */
    git_treebuilder *tb = NULL;
    git_oid tree_oid;
    int err;

    err = git_treebuilder_new(&tb, repo, NULL);
    if (err < 0) {
        return error_wrap(
            error_from_git(err),
            "Failed to create tree builder for orphan branch '%s'", name
        );
    }

    err = git_treebuilder_write(&tree_oid, tb);
    git_treebuilder_free(tb);
    if (err < 0) {
        return error_wrap(
            error_from_git(err),
            "Failed to write empty tree for orphan branch '%s'", name
        );
    }

    /* Get tree object */
    git_tree *tree = NULL;
    err = git_tree_lookup(&tree, repo, &tree_oid);
    if (err < 0) {
        return error_wrap(
            error_from_git(err),
            "Failed to lookup tree for orphan branch '%s'", name
        );
    }

    /* Get signature with fallback */
    git_signature *sig = NULL;
    error_t *sig_err = gitops_get_signature(&sig, repo);
    if (sig_err) {
        git_tree_free(tree);
        return error_wrap(
            sig_err, "Failed to get signature for orphan branch '%s'", name
        );
    }

    /* Create orphan commit (no parents) */
    git_oid commit_oid;
    char refname[DOTTA_REFNAME_MAX];
    error_t *err_build = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", name
    );
    if (err_build) {
        git_signature_free(sig);
        git_tree_free(tree);
        return error_wrap(err_build, "Invalid branch name '%s'", name);
    }

    err = git_commit_create(
        &commit_oid,
        repo,
        refname,  /* This creates the branch reference */
        sig,
        sig,
        NULL,     /* encoding */
        "Initialize empty branch",
        tree,
        0,        /* no parents = orphan */
        NULL      /* no parent commits */
    );

    git_signature_free(sig);
    git_tree_free(tree);

    if (err < 0) {
        return error_wrap(
            error_from_git(err),
            "Failed to create orphan commit for branch '%s'", name
        );
    }

    return NULL;
}

error_t *gitops_list_branches(
    git_repository *repo,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    git_branch_iterator *iter = NULL;
    int err = git_branch_iterator_new(&iter, repo, GIT_BRANCH_LOCAL);
    if (err < 0) {
        return error_wrap(
            error_from_git(err), "Failed to create branch iterator"
        );
    }

    string_array_t *branches = string_array_new(0);
    if (!branches) {
        git_branch_iterator_free(iter);
        return ERROR(ERR_MEMORY, "Failed to allocate branch list");
    }

    git_reference *ref = NULL;
    git_branch_t branch_type;

    while (git_branch_next(&ref, &branch_type, iter) == 0) {
        const char *name = NULL;
        err = git_branch_name(&name, ref);
        if (err < 0) {
            git_reference_free(ref);
            git_branch_iterator_free(iter);
            string_array_free(branches);
            return error_wrap(
                error_from_git(err), "Failed to get branch name"
            );
        }

        error_t *derr = string_array_push(branches, name);
        git_reference_free(ref);
        if (derr) {
            git_branch_iterator_free(iter);
            string_array_free(branches);
            return derr;
        }
    }

    git_branch_iterator_free(iter);

    *out = branches;
    return NULL;
}

error_t *gitops_list_remote_tracking(
    git_repository *repo,
    const char *remote_name,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(out);

    /* Build prefix to strip: "<remote_name>/" */
    char prefix[DOTTA_REFNAME_MAX];
    int ret = snprintf(prefix, sizeof(prefix), "%s/", remote_name);

    if (ret < 0 || (size_t) ret >= sizeof(prefix)) {
        return ERROR(ERR_INVALID_ARG, "Remote name too long");
    }
    size_t prefix_len = (size_t) ret;

    git_branch_iterator *iter = NULL;
    int err = git_branch_iterator_new(&iter, repo, GIT_BRANCH_REMOTE);
    if (err < 0) {
        return error_wrap(
            error_from_git(err),
            "Failed to create remote branch iterator"
        );
    }

    string_array_t *branches = string_array_new(0);
    if (!branches) {
        git_branch_iterator_free(iter);
        return ERROR(ERR_MEMORY, "Failed to allocate branch list");
    }

    git_reference *ref = NULL;
    git_branch_t branch_type;

    while (git_branch_next(&ref, &branch_type, iter) == 0) {
        const char *name = NULL;
        err = git_branch_name(&name, ref);
        if (err < 0) {
            git_reference_free(ref);
            continue;  /* Non-fatal: skip unreadable refs */
        }

        /* git_branch_name returns "origin/branch" for remote branches */
        if (!str_starts_with(name, prefix)) {
            git_reference_free(ref);
            continue;  /* Different remote */
        }

        const char *branch_name = name + prefix_len;

        /* Skip special refs */
        if (strcmp(branch_name, "dotta-worktree") == 0 ||
            strcmp(branch_name, "HEAD") == 0) {
            git_reference_free(ref);
            continue;
        }

        error_t *derr = string_array_push(branches, branch_name);
        git_reference_free(ref);
        if (derr) {
            git_branch_iterator_free(iter);
            string_array_free(branches);
            return derr;
        }
    }

    git_branch_iterator_free(iter);

    *out = branches;
    return NULL;
}

error_t *gitops_delete_branch(
    git_repository *repo,
    const char *name
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_ARG(name[0] != '\0', "Branch name cannot be empty");

    git_reference *ref = NULL;
    char refname[DOTTA_REFNAME_MAX];
    error_t *err_build = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", name
    );
    if (err_build) {
        return error_wrap(
            err_build, "Invalid branch name '%s'", name
        );
    }

    int err = git_reference_lookup(&ref, repo, refname);
    if (err < 0) {
        return error_wrap(
            error_from_git(err),
            "Failed to lookup branch '%s'", name
        );
    }

    err = git_branch_delete(ref);
    git_reference_free(ref);
    if (err < 0) {
        return error_wrap(
            error_from_git(err),
            "Failed to delete branch '%s'", name
        );
    }

    return NULL;
}

error_t *gitops_current_branch(
    git_repository *repo,
    char **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    git_reference *head = NULL;
    int err = git_repository_head(&head, repo);
    if (err < 0) {
        if (err == GIT_EUNBORNBRANCH) {
            return ERROR(
                ERR_NOT_FOUND, "HEAD points to an unborn branch"
            );
        }
        if (err == GIT_ENOTFOUND) {
            return ERROR(
                ERR_NOT_FOUND, "Repository has no HEAD reference"
            );
        }
        return error_from_git(err);
    }

    /* git_branch_name fails for detached HEAD (reference is not a branch) */
    const char *name = NULL;
    err = git_branch_name(&name, head);
    if (err < 0) {
        git_reference_free(head);
        return ERROR(
            ERR_NOT_FOUND, "HEAD is detached (not on any branch)"
        );
    }

    *out = strdup(name);
    git_reference_free(head);

    if (!*out) {
        return ERROR(
            ERR_MEMORY, "Failed to allocate branch name"
        );
    }

    return NULL;
}

error_t *gitops_is_current_branch(
    git_repository *repo,
    const char *branch_name,
    bool *is_current
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(is_current);

    /* Default to false */
    *is_current = false;

    /* Bare repositories have no working directory or checked-out branch */
    if (git_repository_is_bare(repo)) {
        return NULL;
    }

    /* Get HEAD reference */
    git_reference *head = NULL;
    int err = git_repository_head(&head, repo);
    if (err < 0) {
        if (err == GIT_EUNBORNBRANCH || err == GIT_ENOTFOUND) {
            /* Unborn branch or no HEAD - not an error, just not current */
            return NULL;
        }
        return error_from_git(err);
    }

    /* Get branch name from HEAD.
     * git_branch_name returns GIT_ERROR (-1) with GIT_ERROR_INVALID when the
     * reference is not a local branch (detached HEAD, direct commit ref, etc.).
     * Any failure here means HEAD is not pointing to a named branch, so the
     * branch we are checking is definitely not current. */
    const char *current_name = NULL;
    err = git_branch_name(&current_name, head);
    if (err < 0) {
        git_reference_free(head);
        return NULL;
    }

    /* Compare branch names */
    *is_current = (strcmp(current_name, branch_name) == 0);

    git_reference_free(head);

    return NULL;
}

/**
 * Tree operations
 */

/**
 * Resolve a Git reference to its tree, optionally capturing the peeled OID
 *
 * Shared implementation for gitops_load_tree and gitops_load_branch_tree.
 * The OID captured (when out_oid is non-NULL) is the peeled object's OID:
 * the commit OID for commit-backed branches, the tree OID for orphan-tree
 * branches. This matches the OID that the old profile_load captured
 * via the same git_reference_peel(ANY) path, ensuring staleness detection
 * consistency.
 */
static error_t *resolve_ref_to_tree(
    git_repository *repo,
    const char *ref_name,
    git_tree **out_tree,
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
        /* Orphan branch pointing directly to tree
         * SAFETY: We verified obj_type == GIT_OBJECT_TREE, so this cast is safe
         */
        *out_tree = (git_tree *) obj;
        /* Don't free obj - we're transferring ownership to caller */
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
    git_repository *repo,
    const char *ref_name,
    git_tree **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ref_name);
    CHECK_NULL(out);
    CHECK_ARG(ref_name[0] != '\0', "Reference name cannot be empty");

    return resolve_ref_to_tree(repo, ref_name, out, NULL);
}

error_t *gitops_load_branch_tree(
    git_repository *repo,
    const char *branch_name,
    git_tree **out_tree,
    git_oid *out_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out_tree);

    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", branch_name
    );
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    return resolve_ref_to_tree(repo, refname, out_tree, out_oid);
}

error_t *gitops_tree_walk(
    git_tree *tree,
    git_treewalk_cb callback,
    void *payload
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
error_t *gitops_create_commit(
    git_repository *repo,
    const char *branch_name,
    git_tree *tree,
    const char *message,
    git_oid *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(tree);
    CHECK_NULL(message);

    /* Get signature with fallback */
    git_signature *sig = NULL;
    error_t *sig_err = gitops_get_signature(&sig, repo);
    if (sig_err) return sig_err;

    /* Get parent commit if branch exists */
    git_oid commit_oid;
    git_commit *parent = NULL;
    char refname[DOTTA_REFNAME_MAX];
    error_t *err_build = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", branch_name
    );
    if (err_build) {
        git_signature_free(sig);
        /* NOTE: Do not free 'tree' - it is owned by the caller */
        return error_wrap(
            err_build, "Invalid branch name '%s'", branch_name
        );
    }

    int err = git_reference_name_to_id(&commit_oid, repo, refname);
    if (err == 0) {
        /* Branch exists - look up parent commit */
        err = git_commit_lookup(&parent, repo, &commit_oid);
        if (err < 0) {
            git_signature_free(sig);
            return error_from_git(err);
        }
    } else if (err != GIT_ENOTFOUND) {
        /* Unexpected error (not just "branch doesn't exist yet") */
        git_signature_free(sig);
        return error_from_git(err);
    }
    /* GIT_ENOTFOUND: new branch, parent stays NULL (orphan commit) */

    /* Create commit */
    const git_commit *parents[] = { parent };
    int parent_count = parent ? 1 : 0;

    err = git_commit_create(
        &commit_oid, repo, refname, sig, sig, NULL,
        message, tree, parent_count, parents
    );

    git_signature_free(sig);
    if (parent) {
        git_commit_free(parent);
    }

    if (err < 0) {
        return error_from_git(err);
    }

    if (out) {
        git_oid_cpy(out, &commit_oid);
    }

    return NULL;
}

error_t *gitops_get_commit(
    git_repository *repo,
    const char *ref_name,
    git_commit **out
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
 * Split file path into segments for recursive tree building
 *
 * Normalizes path and splits into components:
 * - Leading slashes skipped: "/foo/bar" -> ["foo", "bar"]
 * - Double slashes collapsed: "foo//bar" -> ["foo", "bar"]
 * - Trailing slash rejected: "foo/bar/" -> Error (not a file path)
 * - Empty path rejected: "" -> Error
 *
 * @param file_path Path to split (must not be NULL)
 * @param out_segments Output array (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *split_path_to_segments(
    const char *file_path,
    string_array_t **out_segments
) {
    if (!file_path || !out_segments) {
        return ERROR(
            ERR_INVALID_ARG,
            "file_path and out_segments cannot be NULL"
        );
    }

    /* Skip leading slashes */
    const char *p = file_path;
    while (*p == '/') {
        p++;
    }

    if (*p == '\0') {
        return ERROR(
            ERR_INVALID_ARG,
            "File path cannot be empty or just slashes"
        );
    }

    /* Reject trailing slashes (directory path, not a file path) */
    size_t normalized_len = strlen(p);
    if (p[normalized_len - 1] == '/') {
        return ERROR(
            ERR_INVALID_ARG,
            "File path '%s' ends with '/' (directory, not file)",
            file_path
        );
    }

    string_array_t *segments = string_array_new(0);
    if (!segments) {
        return ERROR(
            ERR_MEMORY,
            "Failed to allocate path segments array"
        );
    }

    /* Parse segments using strchr to find delimiters.
     * Loop invariant: p points to the start of a non-empty segment
     * (guaranteed by leading/trailing slash rejection and slash-skipping). */
    while (*p != '\0') {
        const char *end = strchr(p, '/');
        size_t seg_len = end ? (size_t) (end - p) : strlen(p);

        /* Reject . and .. components (invalid in Git trees) */
        if ((seg_len == 1 && p[0] == '.') ||
            (seg_len == 2 && p[0] == '.' && p[1] == '.')) {
            string_array_free(segments);
            return ERROR(
                ERR_INVALID_ARG,
                "File path '%s' contains invalid component '%.*s'",
                file_path, (int) seg_len, p
            );
        }

        char *segment = strndup(p, seg_len);
        if (!segment) {
            string_array_free(segments);
            return ERROR(ERR_MEMORY, "Failed to allocate path segment");
        }

        error_t *err = string_array_push_owned(segments, segment);
        if (err) {
            free(segment);
            string_array_free(segments);
            return error_wrap(err, "Failed to add path segment");
        }

        /* Advance past segment; skip consecutive slashes */
        if (!end) {
            break;
        }
        p = end + 1;
        while (*p == '/') {
            p++;
        }
    }

    /* Guard against pathologically deep paths that would cause stack
     * overflow in recursive tree construction. Real-world dotfile paths
     * rarely exceed ~10 levels; 64 is extremely generous. */
    if (segments->count > 64) {
        string_array_free(segments);
        return ERROR(
            ERR_INVALID_ARG,
            "File path '%s' has too many components (%zu, max 64)",
            file_path, segments->count
        );
    }

    *out_segments = segments;
    return NULL;
}

/**
 * Recursively build tree structure for file at arbitrary depth
 *
 * Uses inside-out construction: builds innermost tree first, then works outward.
 * Preserves existing tree entries at each level (siblings are copied).
 *
 * @param repo Repository (must not be NULL)
 * @param parent_tree Existing tree at this level (NULL for new directories)
 * @param segments Path segment array (must not be NULL, count > 0)
 * @param depth Current segment index (0 = first segment)
 * @param blob_oid File content blob OID (must not be NULL)
 * @param file_mode File permissions
 * @param out_tree_oid Output: OID of tree at this level (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *build_tree_for_path(
    git_repository *repo,
    git_tree *parent_tree,
    const string_array_t *segments,
    size_t depth,
    const git_oid *blob_oid,
    git_filemode_t file_mode,
    git_oid *out_tree_oid
) {
    const char *segment = segments->items[depth];
    bool is_final = (depth == segments->count - 1);
    int git_err;

    if (is_final) {
        /*
         * Base case: Insert blob at this level
         *
         * Create treebuilder from parent (copies existing entries),
         * insert/update the file, write tree.
         */
        git_treebuilder *builder = NULL;
        git_err = git_treebuilder_new(&builder, repo, parent_tree);
        if (git_err < 0) {
            return error_from_git(git_err);
        }

        git_err = git_treebuilder_insert(
            NULL, builder, segment, blob_oid, file_mode
        );
        if (git_err < 0) {
            git_treebuilder_free(builder);
            return error_from_git(git_err);
        }

        git_err = git_treebuilder_write(out_tree_oid, builder);
        git_treebuilder_free(builder);

        if (git_err < 0) {
            return error_from_git(git_err);
        }

        return NULL;
    }

    /*
     * Recursive case: Build child tree first, then insert tree entry
     *
     * 1. Check if segment exists in parent_tree
     * 2. If exists as tree: load it as child context
     * 3. If exists as blob: error (file/directory conflict)
     * 4. If doesn't exist: child_tree = NULL (will create new directory)
     * 5. Recurse to build child tree
     * 6. Insert child tree OID into this level
     */
    git_tree *child_tree = NULL;
    error_t *err = NULL;

    if (parent_tree) {
        const git_tree_entry *entry = git_tree_entry_byname(parent_tree, segment);
        if (entry) {
            git_object_t entry_type = git_tree_entry_type(entry);
            if (entry_type == GIT_OBJECT_TREE) {
                /* Existing directory - load it */
                const git_oid *entry_oid = git_tree_entry_id(entry);
                git_err = git_tree_lookup(&child_tree, repo, entry_oid);
                if (git_err < 0) {
                    return error_from_git(git_err);
                }
            } else {
                /* Conflict: path component exists but is not a directory */
                return ERROR(
                    ERR_CONFLICT,
                    "Cannot create path: '%s' exists as a file, not a directory",
                    segment
                );
            }
        }
        /* If entry is NULL, child_tree remains NULL (new directory) */
    }

    /* Recurse to build child tree */
    git_oid child_tree_oid;
    err = build_tree_for_path(
        repo, child_tree, segments, depth + 1, blob_oid, file_mode, &child_tree_oid
    );

    /* Free child_tree if we loaded it */
    if (child_tree) {
        git_tree_free(child_tree);
    }

    if (err) {
        return err;
    }

    /* Insert child tree into this level */
    git_treebuilder *builder = NULL;
    git_err = git_treebuilder_new(&builder, repo, parent_tree);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_err = git_treebuilder_insert(
        NULL, builder, segment, &child_tree_oid, GIT_FILEMODE_TREE
    );
    if (git_err < 0) {
        git_treebuilder_free(builder);
        return error_from_git(git_err);
    }

    git_err = git_treebuilder_write(out_tree_oid, builder);
    git_treebuilder_free(builder);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    return NULL;
}

/**
 * Helper: Check if file exists in tree with matching OID and file mode
 *
 * Uses git_tree_entry_bypath for arbitrary depth path traversal.
 * Returns true only if the file exists, is a blob, its OID matches
 * target_oid, AND its filemode matches target_mode.
 *
 * The mode check is critical: without it, a change from regular to
 * executable (same content, different mode) would be treated as a no-op.
 */
static bool file_matches_oid_and_mode(
    git_tree *tree,
    const char *file_path,
    const git_oid *target_oid,
    git_filemode_t target_mode
) {
    if (!tree || !file_path || !target_oid) {
        return false;
    }

    /* Normalize: skip leading slash */
    const char *path = file_path;
    while (*path == '/') {
        path++;
    }
    if (*path == '\0') {
        return false;
    }

    /* git_tree_entry_bypath handles arbitrary depth internally */
    git_tree_entry *entry = NULL;
    int ret = git_tree_entry_bypath(&entry, tree, path);
    if (ret < 0) {
        return false;  /* Not found or error */
    }

    bool matches = (git_tree_entry_type(entry) == GIT_OBJECT_BLOB &&
        git_oid_equal(git_tree_entry_id(entry), target_oid) &&
        git_tree_entry_filemode(entry) == target_mode);

    git_tree_entry_free(entry);

    return matches;
}

error_t *gitops_update_file(
    git_repository *repo,
    const char *branch_name,
    const char *file_path,
    const char *content,
    size_t content_size,
    const char *commit_message,
    git_filemode_t file_mode,
    bool *was_modified
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(file_path);
    CHECK_NULL(content);
    CHECK_NULL(commit_message);

    /* Initialize output parameter */
    if (was_modified) {
        *was_modified = false;
    }

    /* Validate file mode */
    if (file_mode != GIT_FILEMODE_BLOB && file_mode != GIT_FILEMODE_BLOB_EXECUTABLE) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid file mode: "
            "must be GIT_FILEMODE_BLOB or GIT_FILEMODE_BLOB_EXECUTABLE"
        );
    }

    /* Compute blob OID without writing to ODB (avoids orphan objects on no-op) */
    git_oid blob_oid;
    int git_err = git_odb_hash(&blob_oid, content, content_size, GIT_OBJECT_BLOB);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Load current tree from branch */
    char ref_name[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(
        ref_name, sizeof(ref_name), "refs/heads/%s", branch_name
    );
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    git_tree *current_tree = NULL;
    err = gitops_load_tree(repo, ref_name, &current_tree);
    if (err) {
        return error_wrap(
            err, "Failed to load tree from branch '%s'", branch_name
        );
    }

    /* Check for no-op: file exists with identical content AND mode.
     * Both must match - same content with a different mode (e.g. regular →
     * executable) is a real change that requires a commit. */
    if (file_matches_oid_and_mode(current_tree, file_path, &blob_oid, file_mode)) {
        git_tree_free(current_tree);
        return NULL;  /* Success, no modification needed */
    }

    /* Content changed — now actually write the blob to ODB */
    git_err = git_blob_create_from_buffer(&blob_oid, repo, content, content_size);
    if (git_err < 0) {
        git_tree_free(current_tree);
        return error_from_git(git_err);
    }

    /*
     * Build tree structure using recursive helper
     *
     * This handles paths at any depth:
     * - "file.txt" (root level)
     * - ".dotta/metadata.json" (one level)
     * - "a/b/c/d.txt" (arbitrary depth)
     */

    /* Split path into segments */
    string_array_t *segments = NULL;
    err = split_path_to_segments(file_path, &segments);
    if (err) {
        git_tree_free(current_tree);
        return error_wrap(err, "Invalid file path '%s'", file_path);
    }

    /* Build tree recursively */
    git_oid new_tree_oid;
    err = build_tree_for_path(
        repo, current_tree, segments, 0, &blob_oid, file_mode, &new_tree_oid
    );

    /* Cleanup: segments and current_tree no longer needed */
    string_array_free(segments);
    git_tree_free(current_tree);

    if (err) {
        return error_wrap(
            err, "Failed to build tree for path '%s'",
            file_path
        );
    }

    /* Load the new tree */
    git_tree *new_tree = NULL;
    git_err = git_tree_lookup(&new_tree, repo, &new_tree_oid);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Create commit */
    err = gitops_create_commit(
        repo,
        branch_name,
        new_tree,
        commit_message,
        NULL
    );
    if (err) {
        git_tree_free(new_tree);
        return err;
    }

    /* Commit succeeded: the ref advanced and the tree changed. Report it
     * via was_modified *before* the sync attempt so the flag stays a
     * faithful signal of "did the commit happen" even if a later step
     * fails. Errors below carry recovery context so callers can still
     * tell a commit failure from a post-commit sync failure. */
    if (was_modified) *was_modified = true;

    /*
     * Sync INDEX and workdir when we advance the current branch.
     *
     * The commit we just created advanced the branch ref, but the
     * repo's shared index (.git/index) still points at the previous
     * tree and the workdir still holds the previous content. When the
     * target is the currently-checked-out branch (typically only
     * dotta-worktree here), the next time anything inspects working
     * state — `git status`, a subsequent `git_checkout_head`, or the
     * caller's own logic — it sees phantom "local modifications"
     * pointing backwards at the file we just committed.
     *
     * `git_checkout_tree` with a single-path pathspec and FORCE is the
     * canonical libgit2 primitive for "make INDEX and workdir match
     * this tree entry, leaving other paths alone". Scoping to one path
     * ensures we don't touch unrelated workdir files the user may
     * have modified.
     *
     * Profile-branch writes (the vast majority of callers) skip this —
     * their indexes and workdirs are never observed while HEAD stays
     * on dotta-worktree, and mutating the shared index for another
     * branch would corrupt the checked-out branch's staging area. See
     * the long comment in gitops_commit_tree_updates_safe for the
     * rationale behind that invariant.
     */
    bool on_current = false;
    err = gitops_is_current_branch(repo, branch_name, &on_current);
    if (err) {
        git_tree_free(new_tree);
        return error_wrap(
            err,
            "Commit to '%s' succeeded but could not determine HEAD state "
            "to sync working directory",
            branch_name
        );
    }

    if (on_current) {
        /* Skip leading slashes to match libgit2's repo-relative pathspec form */
        const char *norm_path = file_path;
        while (*norm_path == '/') norm_path++;

        char *paths[] = { (char *) norm_path };
        git_checkout_options opts;
        git_checkout_options_init(&opts, GIT_CHECKOUT_OPTIONS_VERSION);
        opts.checkout_strategy = GIT_CHECKOUT_FORCE;
        opts.paths.strings = paths;
        opts.paths.count = 1;

        git_err = git_checkout_tree(repo, (const git_object *) new_tree, &opts);
        if (git_err < 0) {
            err = error_wrap(
                error_from_git(git_err),
                "Commit to '%s' succeeded but failed to sync working "
                "directory for '%s'. Run 'dotta git checkout -- %s' "
                "to reconcile",
                branch_name, norm_path, norm_path
            );
        }
    }

    git_tree_free(new_tree);
    return err;
}

error_t *gitops_commit_tree_updates_safe(
    git_repository *repo,
    const char *branch_name,
    const gitops_tree_update_t *updates,
    size_t update_count,
    const char *const *removals,
    size_t removal_count,
    const char *message,
    git_oid *out_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(message);

    if (update_count > 0 && !updates) {
        return ERROR(
            ERR_INVALID_ARG,
            "updates is NULL but update_count is %zu", update_count
        );
    }
    if (removal_count > 0 && !removals) {
        return ERROR(
            ERR_INVALID_ARG,
            "removals is NULL but removal_count is %zu", removal_count
        );
    }
    if (update_count == 0 && removal_count == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "gitops_commit_tree_updates_safe requires at least one update or removal"
        );
    }

    /* Validate updates: non-empty path and supported mode */
    for (size_t i = 0; i < update_count; i++) {
        if (!updates[i].path || updates[i].path[0] == '\0') {
            return ERROR(
                ERR_INVALID_ARG,
                "updates[%zu].path is NULL or empty", i
            );
        }
        git_filemode_t m = updates[i].mode;
        if (m != GIT_FILEMODE_BLOB &&
            m != GIT_FILEMODE_BLOB_EXECUTABLE &&
            m != GIT_FILEMODE_LINK) {
            return ERROR(
                ERR_INVALID_ARG,
                "updates[%zu].mode 0%o is not a supported blob mode "
                "(expected BLOB, BLOB_EXECUTABLE, or LINK)",
                i, (unsigned int) m
            );
        }
    }

    /* Validate removals: non-empty path */
    for (size_t i = 0; i < removal_count; i++) {
        if (!removals[i] || removals[i][0] == '\0') {
            return ERROR(
                ERR_INVALID_ARG,
                "removals[%zu] is NULL or empty", i
            );
        }
    }

    /* Resolve branch HEAD tree */
    char ref_name[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(
        ref_name, sizeof(ref_name), "refs/heads/%s", branch_name
    );
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    git_tree *head_tree = NULL;
    err = gitops_load_tree(repo, ref_name, &head_tree);
    if (err) {
        return error_wrap(
            err, "Failed to load tree from branch '%s'", branch_name
        );
    }

    /* Standalone in-memory index for HEAD-safe tree construction.
     *
     * CRITICAL: We must NOT call git_repository_index() here. That
     * returns the repository's shared index (backed by .git/index),
     * which is tied to whichever branch HEAD currently points at
     * (typically dotta-worktree). Mutating it would corrupt the
     * checked-out branch's staging area.
     *
     * A standalone index has no backing file, so we:
     *   - Seed it from the branch HEAD tree via git_index_read_tree()
     *   - Stage entries by blob OID with git_index_add() (no worktree
     *     I/O — the blobs already live in the ODB)
     *   - Write the resulting tree directly to the repo ODB via
     *     git_index_write_tree_to(), NOT git_index_write() which
     *     would try to persist to a non-existent backing file.
     */
    git_index *index = NULL;
    git_tree *new_tree = NULL;

    int git_err = git_index_new(&index);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    git_err = git_index_read_tree(index, head_tree);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Apply updates. git_index_add() replaces entries at the same
     * path, so explicit remove-before-add is not needed. */
    for (size_t i = 0; i < update_count; i++) {
        git_index_entry entry;
        memset(&entry, 0, sizeof(entry));
        entry.mode = updates[i].mode;
        entry.path = updates[i].path;
        git_oid_cpy(&entry.id, &updates[i].blob_oid);

        git_err = git_index_add(index, &entry);
        if (git_err < 0) {
            err = error_wrap(
                error_from_git(git_err),
                "Failed to stage '%s' in branch '%s'",
                updates[i].path, branch_name
            );
            goto cleanup;
        }
    }

    /* Apply removals. Missing entries are an error so the caller
     * notices bugs rather than silently no-op'ing. */
    for (size_t i = 0; i < removal_count; i++) {
        git_err = git_index_remove_bypath(index, removals[i]);
        if (git_err < 0) {
            err = error_wrap(
                error_from_git(git_err),
                "Failed to remove '%s' from branch '%s'",
                removals[i], branch_name
            );
            goto cleanup;
        }
    }

    /* Write tree to repo ODB (not to disk — the index has no backing file) */
    git_oid new_tree_oid;
    git_err = git_index_write_tree_to(&new_tree_oid, index, repo);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    git_err = git_tree_lookup(&new_tree, repo, &new_tree_oid);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Commit the new tree onto the branch (gitops_create_commit
     * handles signature, parent lookup, and reference update). */
    err = gitops_create_commit(repo, branch_name, new_tree, message, out_oid);

cleanup:
    if (new_tree) git_tree_free(new_tree);
    if (index) git_index_free(index);
    if (head_tree) git_tree_free(head_tree);

    return err;
}

/**
 * Remote operations
 */
error_t *gitops_clone(
    git_repository **out,
    const char *url,
    const char *local_path,
    transfer_context_t *xfer
) {
    CHECK_NULL(out);
    CHECK_NULL(url);
    CHECK_NULL(local_path);
    CHECK_NULL(xfer);

    git_clone_options opts;
    git_clone_options_init(&opts, GIT_CLONE_OPTIONS_VERSION);

    transfer_configure_callbacks(
        &opts.fetch_opts.callbacks, xfer, GIT_DIRECTION_FETCH
    );

    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    int err = git_clone(out, url, local_path, &opts);
    transfer_op_end(xfer, err);

    if (err < 0) {
        return error_from_git(err);
    }
    return NULL;
}

error_t *gitops_fetch_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
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
    git_repository *repo,
    const char *remote_name,
    const string_array_t *branches,
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
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
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
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
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
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
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
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer,
    string_array_t **out_branches
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

    /* git_remote_connect + git_remote_ls transfer no byte payload, so the
     * progress callback never fires; GIT_DIRECTION_FETCH keeps the
     * credential path aligned with fetch semantics. */
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

        if (*branch_name == '\0' ||
            strcmp(branch_name, "dotta-worktree") == 0) {
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
    git_repository *repo,
    const char *remote_name,
    char **out_url
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

/**
 * Reference operations
 */
error_t *gitops_create_reference(
    git_repository *repo,
    const char *name,
    const git_oid *oid,
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

error_t *gitops_lookup_reference(
    git_repository *repo,
    const char *name,
    git_reference **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(out);

    int err = git_reference_lookup(out, repo, name);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

error_t *gitops_resolve_reference_oid(
    git_repository *repo,
    const char *ref_name,
    git_oid *out
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
    git_repository *repo,
    const char *branch_name,
    git_oid *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out);

    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", branch_name
    );
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    return gitops_resolve_reference_oid(repo, refname, out);
}

error_t *gitops_resolve_remote_branch_oid(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    git_oid *out
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
 * Index operations
 */
error_t *gitops_get_index(git_repository *repo, git_index **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    int err = git_repository_index(out, repo);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

error_t *gitops_index_add(git_index *index, const char *path) {
    CHECK_NULL(index);
    CHECK_NULL(path);

    int err = git_index_add_bypath(index, path);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

error_t *gitops_index_write_tree(git_index *index, git_oid *out) {
    CHECK_NULL(index);
    CHECK_NULL(out);

    /* Write index to disk */
    int err = git_index_write(index);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Create tree from index */
    err = git_index_write_tree(out, index);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

/**
 * Find file by exact path in tree
 */
error_t *gitops_find_file_in_tree(
    git_tree *tree,
    const char *path,
    git_tree_entry **out
) {
    CHECK_NULL(tree);
    CHECK_NULL(path);
    CHECK_NULL(out);
    CHECK_ARG(path[0] != '\0', "Path cannot be empty");

    /* Normalize path: strip all leading slashes.
     * Consistent with split_path_to_segments which uses the same while-loop
     * approach. A single-slash strip would leave "//foo" as "/foo" which
     * git_tree_entry_bypath would reject as an absolute path. */
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
    git_repository *repo,
    const git_oid *oid,
    gitops_blob_view_t *out
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
    git_repository *repo,
    const git_oid *oid,
    void **out_content,
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
    git_repository *repo,
    const char *branch_name,
    const char *commit_ref,
    git_oid *out_oid,
    git_commit **out_commit
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(commit_ref);
    CHECK_NULL(out_oid);

    git_object *obj = NULL;

    /* Build reference name for branch */
    char ref_name[DOTTA_REFNAME_MAX];
    error_t *err_build = gitops_build_refname(
        ref_name, sizeof(ref_name), "refs/heads/%s", branch_name
    );
    if (err_build) {
        return error_wrap(
            err_build, "Invalid branch name '%s'",
            branch_name
        );
    }

    /* Get the branch reference */
    git_reference *branch_ref = NULL;
    int ret = git_reference_lookup(&branch_ref, repo, ref_name);

    if (ret < 0) {
        return error_from_git(ret);
    }

    /* Parse commit_ref relative to this branch.
     *
     * We check for "HEAD" exactly first, then for "HEAD~" / "HEAD^" prefixes.
     * Using str_starts_with("HEAD") alone would be too broad — any string
     * beginning with those four characters (e.g. a hypothetical tag named
     * "HEADLESS") would be misrouted into the ancestry resolution path. */
    char *allocated_ref = NULL;
    const char *resolve_ref = commit_ref;

    if (strcmp(commit_ref, "HEAD") == 0) {
        /* Exact HEAD: return the branch tip OID directly */
        const git_oid *branch_oid = git_reference_target(branch_ref);
        if (!branch_oid) {
            git_reference_free(branch_ref);
            return ERROR(
                ERR_GIT, "Branch '%s' has no target",
                branch_name
            );
        }
        git_oid_cpy(out_oid, branch_oid);
        git_reference_free(branch_ref);

        if (out_commit) {
            ret = git_commit_lookup(out_commit, repo, out_oid);
            if (ret < 0) {
                return error_from_git(ret);
            }
        }
        return NULL;
    } else if (str_starts_with(commit_ref, "HEAD~") ||
        str_starts_with(commit_ref, "HEAD^")) {
        /* HEAD~N or HEAD^N - resolve relative to branch name.
         * Strip "HEAD" (4 chars) and prepend the branch name, giving e.g.
         * "mybranch~2" which git_revparse_single understands natively. */
        allocated_ref = str_format("%s%s", branch_name, commit_ref + 4);
        if (!allocated_ref) {
            git_reference_free(branch_ref);
            return ERROR(ERR_MEMORY, "Failed to allocate ref string");
        }
        resolve_ref = allocated_ref;
    }
    /* else: commit SHA or other ref — use commit_ref directly */

    git_reference_free(branch_ref);

    /* Resolve the reference */
    ret = git_revparse_single(&obj, repo, resolve_ref);
    free(allocated_ref);  /* NULL-safe */

    if (ret < 0) {
        return ERROR(
            ERR_NOT_FOUND, "Commit '%s' not found in branch '%s'",
            commit_ref, branch_name
        );
    }

    /* Get the commit OID */
    const git_oid *obj_oid = git_object_id(obj);
    if (!obj_oid) {
        git_object_free(obj);
        return ERROR(ERR_GIT, "Failed to get object ID");
    }

    git_oid_cpy(out_oid, obj_oid);

    /* If caller wants the commit object, look it up */
    if (out_commit) {
        git_commit *commit = NULL;
        ret = git_commit_lookup(&commit, repo, out_oid);
        git_object_free(obj);

        if (ret < 0) {
            return error_from_git(ret);
        }
        *out_commit = commit;
    } else {
        git_object_free(obj);
    }

    return NULL;
}

/**
 * Get tree from commit OID
 */
error_t *gitops_get_tree_from_commit(
    git_repository *repo,
    const git_oid *commit_oid,
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
    git_repository *repo,
    const git_oid *one,
    const git_oid *two,
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
    git_repository *repo,
    const git_oid *ancestor_oid,
    const git_oid *our_oid,
    const git_oid *their_oid,
    git_index **out_index
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
    git_repository *repo,
    git_index *index,
    git_commit *our_commit,
    git_commit *their_commit,
    const char *message,
    git_oid *out_oid
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
     * IMPORTANT: Use git_index_write_tree_to() because the index from git_merge_trees()
     * is not backed by a repository, so we must explicitly write to the repo's ODB.
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
        out_oid,
        repo,
        NULL,  /* Don't update any reference */
        sig,
        sig,
        NULL,  /* encoding */
        message,
        tree,
        2,     /* parent count */
        parents
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
    git_repository *repo,
    const git_oid *branch_oid,
    const git_oid *onto_oid,
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

    /* Process each rebase operation
     * Initialize commit_oid to onto_oid - if there are no operations to rebase
     * (branch is already up-to-date or behind), we return onto_oid which is
     * correct for both cases (no-op or fast-forward).
     */
    git_rebase_operation *op = NULL;
    git_oid commit_oid;
    git_oid_cpy(&commit_oid, onto_oid);

    while ((git_err = git_rebase_next(&op, rebase)) == 0) {
        /* Commit the rebased operation
         * In inmemory mode, this doesn't touch HEAD or working directory
         */
        git_err = git_rebase_commit(&commit_oid, rebase, NULL, sig, NULL, NULL);

        if (git_err < 0) {
            git_signature_free(sig);
            git_rebase_abort(rebase);
            git_rebase_free(rebase);

            /* Check for merge conflicts
             * Both GIT_EMERGECONFLICT (-13) and GIT_EUNMERGED (-10) indicate conflicts
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
    git_repository *repo,
    const char *branch_name,
    const git_oid *new_oid,
    const char *reflog_msg
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(new_oid);
    CHECK_NULL(reflog_msg);

    /* Build reference name */
    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", branch_name
    );
    if (err) {
        return error_wrap(
            err, "Invalid branch name '%s'", branch_name
        );
    }

    /* Lookup existing reference */
    git_reference *ref = NULL;
    int git_err = git_reference_lookup(&ref, repo, refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Update reference to new OID with reflog message
     * This is an atomic operation that updates the branch without touching HEAD
     */
    git_reference *new_ref = NULL;
    git_err = git_reference_set_target(
        &new_ref, ref, new_oid, reflog_msg
    );
    git_reference_free(ref);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_reference_free(new_ref);
    return NULL;
}

/**
 * Worktree operations
 */
error_t *gitops_sync_worktree(
    git_repository *repo,
    git_checkout_strategy_t strategy
) {
    CHECK_NULL(repo);

    /* Bare repositories have no working directory to sync */
    if (git_repository_is_bare(repo)) {
        return NULL;
    }

    git_checkout_options opts;
    git_checkout_options_init(&opts, GIT_CHECKOUT_OPTIONS_VERSION);
    opts.checkout_strategy = strategy;

    int err = git_checkout_head(repo, &opts);
    if (err < 0) {
        if (strategy == GIT_CHECKOUT_SAFE) {
            /*
             * SAFE checkout failed - likely due to local modifications.
             * Provide a clear, actionable error message.
             */
            return ERROR(
                ERR_CONFLICT,
                "Working directory has local modifications that conflict with HEAD.\n"
                "Your changes have been preserved. To resolve:\n"
                "  git checkout .   Discard all local changes\n"
                "  git stash        Save changes temporarily\n"
                "  git diff         View what differs"
            );
        }
        return error_from_git(err);
    }

    return NULL;
}

/**
 * Diff operations
 */
error_t *gitops_diff_trees(
    git_repository *repo,
    git_tree *old_tree,
    git_tree *new_tree,
    const git_diff_options *opts,
    git_diff **out_diff
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
    git_diff *diff,
    git_diff_stats **out_stats
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
 * Check if path is a valid git repository
 */
bool gitops_is_repository(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    /* Try to open as git repository */
    git_repository *repo = NULL;
    int err = git_repository_open(&repo, path);
    if (err < 0) {
        return false;
    }

    git_repository_free(repo);
    return true;
}

/**
 * Validate and build a Git reference name
 */
error_t *gitops_build_refname(
    char *buffer,
    size_t buffer_size,
    const char *format,
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
