/**
 * gitops.c - Git operations wrapper implementation
 *
 * All libgit2 calls are wrapped with error handling and resource cleanup.
 */

#include "gitops.h"

#include <git2.h>
#include <git2/errors.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include "credentials.h"
#include "error.h"
#include "transfer.h"
#include "utils/array.h"
#include "utils/string.h"

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

error_t *gitops_branch_exists(git_repository *repo, const char *name, bool *exists) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(exists);
    CHECK_ARG(name[0] != '\0', "Branch name cannot be empty");

    git_reference *ref = NULL;
    char refname[256];
    error_t *err_build = gitops_build_refname(refname, sizeof(refname), "refs/heads/%s", name);
    if (err_build) {
        return error_wrap(err_build, "Invalid branch name '%s'", name);
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

error_t *gitops_create_orphan_branch(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_ARG(name[0] != '\0', "Branch name cannot be empty");

    /* Create empty tree */
    git_treebuilder *tb = NULL;
    git_oid tree_oid;
    int err;

    err = git_treebuilder_new(&tb, repo, NULL);
    if (err < 0) {
        return error_wrap(error_from_git(err),
                "Failed to create tree builder for orphan branch '%s'", name);
    }

    err = git_treebuilder_write(&tree_oid, tb);
    git_treebuilder_free(tb);
    if (err < 0) {
        return error_wrap(error_from_git(err),
                "Failed to write empty tree for orphan branch '%s'", name);
    }

    /* Get tree object */
    git_tree *tree = NULL;
    err = git_tree_lookup(&tree, repo, &tree_oid);
    if (err < 0) {
        return error_wrap(error_from_git(err),
                "Failed to lookup tree for orphan branch '%s'", name);
    }

    /* Get default signature */
    git_signature *sig = NULL;
    err = git_signature_default(&sig, repo);
    if (err < 0) {
        git_tree_free(tree);
        return error_wrap(error_from_git(err),
                "Failed to get signature for orphan branch '%s'", name);
    }

    /* Create orphan commit (no parents) */
    git_oid commit_oid;
    char refname[256];
    error_t *err_build = gitops_build_refname(refname, sizeof(refname), "refs/heads/%s", name);
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
        return error_wrap(error_from_git(err),
                "Failed to create orphan commit for branch '%s'", name);
    }

    return NULL;
}

error_t *gitops_list_branches(git_repository *repo, string_array_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    git_branch_iterator *iter = NULL;
    int err = git_branch_iterator_new(&iter, repo, GIT_BRANCH_LOCAL);
    if (err < 0) {
        return error_wrap(error_from_git(err), "Failed to create branch iterator");
    }

    string_array_t *branches = string_array_create();
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
            return error_wrap(error_from_git(err), "Failed to get branch name");
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

error_t *gitops_delete_branch(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_ARG(name[0] != '\0', "Branch name cannot be empty");

    git_reference *ref = NULL;
    char refname[256];
    error_t *err_build = gitops_build_refname(refname, sizeof(refname), "refs/heads/%s", name);
    if (err_build) {
        return error_wrap(err_build, "Invalid branch name '%s'", name);
    }

    int err = git_reference_lookup(&ref, repo, refname);
    if (err < 0) {
        return error_wrap(error_from_git(err), "Failed to lookup branch '%s'", name);
    }

    err = git_branch_delete(ref);
    git_reference_free(ref);
    if (err < 0) {
        return error_wrap(error_from_git(err), "Failed to delete branch '%s'", name);
    }

    return NULL;
}

error_t *gitops_current_branch(git_repository *repo, char **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    git_reference *head = NULL;
    int err = git_repository_head(&head, repo);
    if (err < 0) {
        return error_from_git(err);
    }

    const char *name = NULL;
    err = git_branch_name(&name, head);
    if (err < 0) {
        git_reference_free(head);
        return error_from_git(err);
    }

    *out = strdup(name);
    git_reference_free(head);

    if (!*out) {
        return ERROR(ERR_MEMORY, "Failed to allocate branch name");
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

    /* Get branch name from HEAD (handles detached HEAD gracefully) */
    const char *current_name = NULL;
    err = git_branch_name(&current_name, head);
    if (err < 0) {
        git_reference_free(head);
        /* Detached HEAD - not pointing to any branch */
        if (err == GIT_ENOTFOUND) {
            return NULL;
        }
        return error_from_git(err);
    }

    /* Compare branch names */
    *is_current = (strcmp(current_name, branch_name) == 0);

    git_reference_free(head);
    return NULL;
}

/**
 * Tree operations
 */

error_t *gitops_load_tree(git_repository *repo, const char *ref_name, git_tree **out) {
    CHECK_NULL(repo);
    CHECK_NULL(ref_name);
    CHECK_NULL(out);
    CHECK_ARG(ref_name[0] != '\0', "Reference name cannot be empty");

    /* Get reference */
    git_reference *ref = NULL;
    int err = git_reference_lookup(&ref, repo, ref_name);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Peel reference to get the underlying object (handles both commits and direct tree refs) */
    git_object *obj = NULL;
    err = git_reference_peel(&obj, ref, GIT_OBJECT_ANY);
    git_reference_free(ref);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Handle different object types */
    git_object_t obj_type = git_object_type(obj);

    if (obj_type == GIT_OBJECT_COMMIT) {
        /* Normal branch pointing to commit - get tree from commit
         * SAFETY: We verified obj_type == GIT_OBJECT_COMMIT, so this cast is safe
         */
        git_commit *commit = (git_commit *)obj;
        err = git_commit_tree(out, commit);
        git_object_free(obj);
        if (err < 0) {
            return error_from_git(err);
        }
    } else if (obj_type == GIT_OBJECT_TREE) {
        /* Orphan branch pointing directly to tree
         * SAFETY: We verified obj_type == GIT_OBJECT_TREE, so this cast is safe
         */
        *out = (git_tree *)obj;
        /* Don't free obj - we're transferring ownership to caller */
    } else {
        /* Unexpected object type */
        git_object_free(obj);
        return ERROR(ERR_GIT,
                    "Reference '%s' points to unexpected object type: %d",
                    ref_name, obj_type);
    }

    return NULL;
}

error_t *gitops_tree_walk(git_tree *tree, git_treewalk_cb callback, void *payload) {
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

    /* Get default signature */
    git_signature *sig = NULL;
    int err = git_signature_default(&sig, repo);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Check if branch exists to get parent */
    git_oid commit_oid;
    git_oid *parent_oid = NULL;
    git_commit *parent = NULL;
    char refname[256];
    error_t *err_build = gitops_build_refname(refname, sizeof(refname), "refs/heads/%s", branch_name);
    if (err_build) {
        git_signature_free(sig);
        /* NOTE: Do not free 'tree' - it is owned by the caller */
        return error_wrap(err_build, "Invalid branch name '%s'", branch_name);
    }

    git_reference *ref = NULL;
    if (git_reference_lookup(&ref, repo, refname) == 0) {
        err = git_reference_name_to_id(&commit_oid, repo, refname);
        git_reference_free(ref);
        if (err < 0) {
            git_signature_free(sig);
            return error_from_git(err);
        }
        parent_oid = &commit_oid;
        err = git_commit_lookup(&parent, repo, parent_oid);
        if (err < 0) {
            git_signature_free(sig);
            return error_from_git(err);
        }
    }

    /* Create commit */
    const git_commit *parents[] = { parent };
    int parent_count = parent ? 1 : 0;

    err = git_commit_create(
        &commit_oid,
        repo,
        refname,
        sig,
        sig,
        NULL,
        message,
        tree,
        parent_count,
        parents
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
        return error_from_git(err);
    }

    err = git_commit_lookup(out, repo, &oid);
    if (err < 0) {
        return error_from_git(err);
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
        return ERROR(ERR_INVALID_ARG, "file_path and out_segments cannot be NULL");
    }

    /* Skip leading slashes */
    const char *p = file_path;
    while (*p == '/') {
        p++;
    }

    if (*p == '\0') {
        return ERROR(ERR_INVALID_ARG, "File path cannot be empty or just slashes");
    }

    string_array_t *segments = string_array_create();
    if (!segments) {
        return ERROR(ERR_MEMORY, "Failed to allocate path segments array");
    }

    /* Parse segments */
    const char *segment_start = p;
    while (*p != '\0') {
        if (*p == '/') {
            /* End of segment */
            size_t segment_len = (size_t)(p - segment_start);
            if (segment_len > 0) {
                /* Non-empty segment - add it */
                char *segment = malloc(segment_len + 1);
                if (!segment) {
                    string_array_free(segments);
                    return ERROR(ERR_MEMORY, "Failed to allocate path segment");
                }
                memcpy(segment, segment_start, segment_len);
                segment[segment_len] = '\0';

                error_t *err = string_array_push_take(segments, segment);
                if (err) {
                    free(segment);
                    string_array_free(segments);
                    return error_wrap(err, "Failed to add path segment");
                }
            }
            /* Skip consecutive slashes */
            while (*p == '/') {
                p++;
            }
            segment_start = p;
        } else {
            p++;
        }
    }

    /* Handle final segment (after last slash or entire path if no slashes) */
    size_t segment_len = (size_t)(p - segment_start);
    if (segment_len > 0) {
        char *segment = malloc(segment_len + 1);
        if (!segment) {
            string_array_free(segments);
            return ERROR(ERR_MEMORY, "Failed to allocate final path segment");
        }
        memcpy(segment, segment_start, segment_len);
        segment[segment_len] = '\0';

        error_t *err = string_array_push_take(segments, segment);
        if (err) {
            free(segment);
            string_array_free(segments);
            return error_wrap(err, "Failed to add final path segment");
        }
    } else {
        /* Path ended with slash - not a valid file path */
        string_array_free(segments);
        return ERROR(ERR_INVALID_ARG,
                    "File path '%s' ends with '/' (directory, not file)", file_path);
    }

    if (string_array_size(segments) == 0) {
        string_array_free(segments);
        return ERROR(ERR_INVALID_ARG, "File path contains no valid segments");
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
    const char *segment = string_array_get(segments, depth);
    bool is_final = (depth == string_array_size(segments) - 1);
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

        git_err = git_treebuilder_insert(NULL, builder, segment, blob_oid, file_mode);
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
                return ERROR(ERR_CONFLICT,
                            "Cannot create path: '%s' exists as a file, not a directory",
                            segment);
            }
        }
        /* If entry is NULL, child_tree remains NULL (new directory) */
    }

    /* Recurse to build child tree */
    git_oid child_tree_oid;
    err = build_tree_for_path(repo, child_tree, segments, depth + 1,
                               blob_oid, file_mode, &child_tree_oid);

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

    git_err = git_treebuilder_insert(NULL, builder, segment,
                                     &child_tree_oid, GIT_FILEMODE_TREE);
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
 * Helper: Check if file exists in tree with matching OID
 *
 * Uses git_tree_entry_bypath for arbitrary depth path traversal.
 * Returns true if file exists and blob OID matches target_oid.
 */
static bool file_matches_oid(
    git_tree *tree,
    const char *file_path,
    const git_oid *target_oid
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
                    git_oid_equal(git_tree_entry_id(entry), target_oid));
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
        return ERROR(ERR_INVALID_ARG,
                    "Invalid file mode: must be GIT_FILEMODE_BLOB or GIT_FILEMODE_BLOB_EXECUTABLE");
    }

    /* Create blob from content */
    git_oid blob_oid;
    int git_err = git_blob_create_from_buffer(&blob_oid, repo, content, content_size);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Load current tree from branch */
    char ref_name[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(ref_name, sizeof(ref_name),
                                        "refs/heads/%s", branch_name);
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    git_tree *current_tree = NULL;
    err = gitops_load_tree(repo, ref_name, &current_tree);
    if (err) {
        return error_wrap(err, "Failed to load tree from branch '%s'", branch_name);
    }

    /* Check for no-op: file exists with same content */
    if (file_matches_oid(current_tree, file_path, &blob_oid)) {
        git_tree_free(current_tree);
        return NULL;  /* Success, no modification needed */
    }

    /* Set modification flag - we're proceeding with update */
    if (was_modified) {
        *was_modified = true;
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
    err = build_tree_for_path(repo, current_tree, segments, 0,
                              &blob_oid, file_mode, &new_tree_oid);

    /* Cleanup: segments and current_tree no longer needed */
    string_array_free(segments);
    git_tree_free(current_tree);

    if (err) {
        return error_wrap(err, "Failed to build tree for path '%s'", file_path);
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

    git_tree_free(new_tree);

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

    git_clone_options opts = GIT_CLONE_OPTIONS_INIT;

    /* Set up transfer callbacks if context provided */
    if (xfer) {
        opts.fetch_opts.callbacks.credentials = transfer_credentials_callback;
        opts.fetch_opts.callbacks.transfer_progress = transfer_progress_callback;
        opts.fetch_opts.callbacks.payload = xfer;
    } else {
        /* No transfer context - use basic credential callback */
        opts.fetch_opts.callbacks.credentials = credentials_callback;
    }

    /* Clone with credential and progress support */
    int err = git_clone(out, url, local_path, &opts);
    if (err < 0) {
        /* Reject credentials on failure if context provided */
        if (xfer && xfer->cred) {
            credential_context_reject(xfer->cred);
        }
        return error_from_git(err);
    }

    /* Approve credentials on success if context provided */
    if (xfer && xfer->cred) {
        credential_context_approve(xfer->cred);
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
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");
    CHECK_ARG(branch_name[0] != '\0', "Branch name cannot be empty");

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Set up transfer callbacks if context provided */
    git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
    if (xfer) {
        fetch_opts.callbacks.credentials = transfer_credentials_callback;
        fetch_opts.callbacks.transfer_progress = transfer_progress_callback;
        fetch_opts.callbacks.payload = xfer;
    } else {
        /* No transfer context - use basic credential callback */
        fetch_opts.callbacks.credentials = credentials_callback;
    }

    char refspec[256];
    error_t *err_build = gitops_build_refname(refspec, sizeof(refspec), "refs/heads/%s:refs/remotes/%s/%s",
                                       branch_name, remote_name, branch_name);
    if (err_build) {
        git_remote_free(remote);
        return error_wrap(err_build, "Invalid branch/remote name '%s/%s'", remote_name, branch_name);
    }

    const char *refspecs[] = { refspec };
    git_strarray refs = { (char **)refspecs, 1 };

    err = git_remote_fetch(remote, &refs, &fetch_opts, NULL);
    git_remote_free(remote);

    if (err < 0) {
        /* Authentication failed - reject credentials if they were provided */
        if (xfer && xfer->cred) {
            credential_context_reject(xfer->cred);
        }
        return error_from_git(err);
    }

    /* Success - approve credentials if they were provided */
    if (xfer && xfer->cred) {
        credential_context_approve(xfer->cred);
    }

    return NULL;
}

error_t *gitops_fetch_branches(
    git_repository *repo,
    const char *remote_name,
    char **branch_names,
    size_t branch_count,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_names);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");
    CHECK_ARG(branch_count > 0, "branch_count must be greater than 0");

    /* Look up remote once */
    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Build array of refspecs for all branches */
    char **refspecs = calloc(branch_count, sizeof(char *));
    if (!refspecs) {
        git_remote_free(remote);
        return ERROR(ERR_MEMORY, "Failed to allocate refspecs array");
    }

    /* Construct refspecs for each branch */
    error_t *err_result = NULL;
    for (size_t i = 0; i < branch_count; i++) {
        if (!branch_names[i]) {
            err_result = ERROR(ERR_INVALID_ARG, "branch_names[%zu] is NULL", i);
            goto cleanup;
        }
        if (branch_names[i][0] == '\0') {
            err_result = ERROR(ERR_INVALID_ARG, "branch_names[%zu] cannot be empty", i);
            goto cleanup;
        }

        /* Allocate buffer for this refspec */
        refspecs[i] = malloc(256);
        if (!refspecs[i]) {
            err_result = ERROR(ERR_MEMORY, "Failed to allocate refspec buffer");
            goto cleanup;
        }

        /* Build refspec: refs/heads/branch:refs/remotes/origin/branch */
        error_t *err_build = gitops_build_refname(
            refspecs[i], 256,
            "refs/heads/%s:refs/remotes/%s/%s",
            branch_names[i], remote_name, branch_names[i]
        );
        if (err_build) {
            err_result = error_wrap(err_build,
                "Invalid branch/remote name '%s/%s'",
                remote_name, branch_names[i]);
            goto cleanup;
        }
    }

    /* Set up transfer callbacks if context provided */
    git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
    if (xfer) {
        fetch_opts.callbacks.credentials = transfer_credentials_callback;
        fetch_opts.callbacks.transfer_progress = transfer_progress_callback;
        fetch_opts.callbacks.payload = xfer;
    } else {
        /* No transfer context - use basic credential callback */
        fetch_opts.callbacks.credentials = credentials_callback;
    }

    /* Build git_strarray from our refspecs */
    git_strarray refs = { refspecs, branch_count };

    /* Perform the batched fetch */
    err = git_remote_fetch(remote, &refs, &fetch_opts, NULL);

    if (err < 0) {
        /* Authentication failed - reject credentials if they were provided */
        if (xfer && xfer->cred) {
            credential_context_reject(xfer->cred);
        }
        err_result = error_from_git(err);
        goto cleanup;
    }

    /* Success - approve credentials if they were provided */
    if (xfer && xfer->cred) {
        credential_context_approve(xfer->cred);
    }

cleanup:
    /* Free refspecs array */
    if (refspecs) {
        for (size_t i = 0; i < branch_count; i++) {
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
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");
    CHECK_ARG(branch_name[0] != '\0', "Branch name cannot be empty");

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Set up transfer callbacks if context provided */
    git_push_options push_opts = GIT_PUSH_OPTIONS_INIT;
    if (xfer) {
        push_opts.callbacks.credentials = transfer_credentials_callback;
        push_opts.callbacks.push_transfer_progress = transfer_push_progress_callback;
        push_opts.callbacks.payload = xfer;
    } else {
        /* No transfer context - use basic credential callback */
        push_opts.callbacks.credentials = credentials_callback;
    }

    char refspec[256];
    error_t *err_build = gitops_build_refname(refspec, sizeof(refspec), "refs/heads/%s:refs/heads/%s",
                                       branch_name, branch_name);
    if (err_build) {
        git_remote_free(remote);
        return error_wrap(err_build, "Invalid branch name '%s'", branch_name);
    }

    const char *refspecs[] = { refspec };
    git_strarray refs = { (char **)refspecs, 1 };

    err = git_remote_push(remote, &refs, &push_opts);
    git_remote_free(remote);

    if (err < 0) {
        /* Authentication failed - reject credentials if they were provided */
        if (xfer && xfer->cred) {
            credential_context_reject(xfer->cred);
        }
        return error_from_git(err);
    }

    /* Success - approve credentials if they were provided */
    if (xfer && xfer->cred) {
        credential_context_approve(xfer->cred);
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

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Set up transfer callbacks if context provided */
    git_push_options push_opts = GIT_PUSH_OPTIONS_INIT;
    if (xfer) {
        push_opts.callbacks.credentials = transfer_credentials_callback;
        push_opts.callbacks.push_transfer_progress = transfer_push_progress_callback;
        push_opts.callbacks.payload = xfer;
    } else {
        /* No transfer context - use basic credential callback */
        push_opts.callbacks.credentials = credentials_callback;
    }

    /* Delete remote branch using empty refspec: :refs/heads/branch */
    char refspec[256];
    error_t *err_build = gitops_build_refname(refspec, sizeof(refspec), ":refs/heads/%s", branch_name);
    if (err_build) {
        git_remote_free(remote);
        return error_wrap(err_build, "Invalid branch name '%s'", branch_name);
    }

    const char *refspecs[] = { refspec };
    git_strarray refs = { (char **)refspecs, 1 };

    err = git_remote_push(remote, &refs, &push_opts);
    git_remote_free(remote);

    if (err < 0) {
        /* Authentication failed - reject credentials if they were provided */
        if (xfer && xfer->cred) {
            credential_context_reject(xfer->cred);
        }
        return error_from_git(err);
    }

    /* Success - approve credentials if they were provided */
    if (xfer && xfer->cred) {
        credential_context_approve(xfer->cred);
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
    git_repository *repo,
    git_tree *tree,
    const char *path,
    git_tree_entry **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(path);
    CHECK_NULL(out);
    CHECK_ARG(path[0] != '\0', "Path cannot be empty");

    /* Normalize path (remove leading slash if present) */
    const char *normalized_path = path;
    if (path[0] == '/') {
        normalized_path = path + 1;
        /* After removing slash, check if we're left with empty string */
        if (normalized_path[0] == '\0') {
            return ERROR(ERR_INVALID_ARG, "Path cannot be just '/'");
        }
    }

    /* Lookup entry in tree */
    git_tree_entry *temp_entry = NULL;
    int ret = git_tree_entry_bypath(&temp_entry, tree, normalized_path);
    if (ret < 0) {
        if (ret == GIT_ENOTFOUND) {
            return ERROR(ERR_NOT_FOUND,
                        "File '%s' not found", path);
        }
        return error_from_git(ret);
    }

    *out = temp_entry;
    return NULL;
}

/**
 * Walk tree looking for files with matching basename
 */
typedef struct {
    const char *target_basename;
    char **matching_paths;
    size_t count;
    size_t capacity;
} basename_search_t;

static int find_by_basename_callback(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    basename_search_t *search = (basename_search_t *)payload;
    const char *entry_name = git_tree_entry_name(entry);

    /* Defensive check - should never be NULL from valid tree entry */
    if (!entry_name) {
        return -1;
    }

    /* Check if basename matches */
    if (strcmp(entry_name, search->target_basename) == 0) {
        /* Build full path with overflow protection */
        size_t root_len = strlen(root);
        size_t name_len = strlen(entry_name);

        /* Check for size_t overflow before allocation */
        if (root_len > SIZE_MAX - name_len - 1) {
            return -1;  /* Path too long, would overflow */
        }

        size_t path_len = root_len + name_len + 1;
        char *full_path = malloc(path_len);
        if (!full_path) {
            return -1;  /* Memory allocation failed */
        }

        if (root_len > 0) {
            snprintf(full_path, path_len, "%s%s", root, entry_name);
        } else {
            snprintf(full_path, path_len, "%s", entry_name);
        }

        /* Add to results with capacity doubling */
        if (search->count >= search->capacity) {
            /* Check for capacity overflow before doubling */
            size_t new_capacity = search->capacity == 0 ? 4 : search->capacity * 2;
            if (new_capacity < search->capacity || new_capacity > SIZE_MAX / sizeof(char *)) {
                free(full_path);
                return -1;  /* Capacity would overflow */
            }

            char **new_paths = realloc(search->matching_paths, new_capacity * sizeof(char *));
            if (!new_paths) {
                free(full_path);
                return -1;  /* Memory allocation failed */
            }
            search->matching_paths = new_paths;
            search->capacity = new_capacity;
        }

        search->matching_paths[search->count++] = full_path;
    }

    return 0;
}

/**
 * Find files by basename in tree
 */
error_t *gitops_find_files_by_basename_in_tree(
    git_repository *repo,
    git_tree *tree,
    const char *basename,
    char ***out_paths,
    size_t *out_count
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(basename);
    CHECK_NULL(out_paths);
    CHECK_NULL(out_count);
    CHECK_ARG(basename[0] != '\0', "Basename cannot be empty");

    basename_search_t search = {
        .target_basename = basename,
        .matching_paths = NULL,
        .count = 0,
        .capacity = 0
    };

    int ret = git_tree_walk(tree, GIT_TREEWALK_PRE, find_by_basename_callback, &search);
    if (ret < 0) {
        for (size_t i = 0; i < search.count; i++) {
            free(search.matching_paths[i]);
        }
        free(search.matching_paths);
        return error_from_git(ret);
    }

    *out_paths = search.matching_paths;
    *out_count = search.count;
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
    char ref_name[256];
    error_t *err_build = gitops_build_refname(ref_name, sizeof(ref_name), "refs/heads/%s", branch_name);
    if (err_build) {
        return error_wrap(err_build, "Invalid branch name '%s'", branch_name);
    }

    /* Get the branch reference */
    git_reference *branch_ref = NULL;
    int ret = git_reference_lookup(&branch_ref, repo, ref_name);

    if (ret < 0) {
        return error_from_git(ret);
    }

    /* Parse commit_ref relative to this branch */
    char *full_ref = NULL;
    if (str_starts_with(commit_ref, "HEAD")) {
        /* HEAD~N or HEAD^N - resolve relative to branch HEAD */
        const git_oid *branch_oid = git_reference_target(branch_ref);
        if (!branch_oid) {
            git_reference_free(branch_ref);
            return ERROR(ERR_GIT, "Branch '%s' has no target", branch_name);
        }

        /* Try to parse as HEAD~N or HEAD^N */
        if (strcmp(commit_ref, "HEAD") == 0) {
            git_oid_cpy(out_oid, branch_oid);
            git_reference_free(branch_ref);

            if (out_commit) {
                ret = git_commit_lookup(out_commit, repo, out_oid);
                if (ret < 0) {
                    return error_from_git(ret);
                }
            }
            return NULL;
        } else {
            /* HEAD~N or HEAD^N */
            full_ref = str_format("%s%s", branch_name, commit_ref + 4);
            if (!full_ref) {
                git_reference_free(branch_ref);
                return ERROR(ERR_MEMORY, "Failed to allocate ref string");
            }
        }
    } else {
        /* Assume it's a commit SHA or other ref */
        full_ref = strdup(commit_ref);
    }

    git_reference_free(branch_ref);

    /* Resolve the reference */
    ret = git_revparse_single(&obj, repo, full_ref ? full_ref : commit_ref);
    free(full_ref);

    if (ret < 0) {
        return ERROR(ERR_NOT_FOUND, "Commit '%s' not found in branch '%s'",
                    commit_ref, branch_name);
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
 * Advanced merge/rebase operations (HEAD-safe)
 */

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
            return ERROR(ERR_NOT_FOUND, "No merge base found between commits");
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
    git_merge_options merge_opts = GIT_MERGE_OPTIONS_INIT;
    git_err = git_merge_trees(&index, repo, ancestor_tree, our_tree, their_tree, &merge_opts);

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
        return ERROR(ERR_CONFLICT, "Cannot create merge commit: index has conflicts");
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

    /* Get signature */
    git_signature *sig = NULL;
    err = git_signature_default(&sig, repo);
    if (err < 0) {
        git_tree_free(tree);
        return error_from_git(err);
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
    git_rebase_options opts = GIT_REBASE_OPTIONS_INIT;
    opts.inmemory = 1;  /* This is the key - never touch HEAD or working directory */

    git_err = git_rebase_init(&rebase, repo, branch_commit, NULL, onto_commit, &opts);
    git_annotated_commit_free(onto_commit);
    git_annotated_commit_free(branch_commit);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Get signature once for all rebase operations */
    git_err = git_signature_default(&sig, repo);
    if (git_err < 0) {
        err = error_from_git(git_err);
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
                return ERROR(ERR_CONFLICT,
                            "Rebase resulted in conflicts. "
                            "Please resolve manually using 'git rebase' or try merge strategy instead.");
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
    char refname[256];
    error_t *err = gitops_build_refname(refname, sizeof(refname), "refs/heads/%s", branch_name);
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
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
    git_err = git_reference_set_target(&new_ref, ref, new_oid, reflog_msg);
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

    git_checkout_options opts = GIT_CHECKOUT_OPTIONS_INIT;
    opts.checkout_strategy = strategy;

    int err = git_checkout_head(repo, &opts);
    if (err < 0) {
        const git_error *e = git_error_last();
        if (e && strategy == GIT_CHECKOUT_SAFE) {
            /*
             * SAFE checkout failed - likely due to local modifications.
             * Provide a clear, actionable error message.
             */
            return ERROR(ERR_CONFLICT,
                "Working directory has local modifications that conflict with HEAD.\n"
                "Your changes have been preserved. To resolve:\n"
                "  git checkout .   Discard all local changes\n"
                "  git stash        Save changes temporarily\n"
                "  git diff         View what differs");
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

    int ret = git_diff_tree_to_tree(out_diff, repo, old_tree, new_tree, opts);
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
error_t *gitops_build_refname(char *buffer, size_t buffer_size, const char *format, ...) {
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

    if ((size_t)written >= buffer_size) {
        return ERROR(ERR_INVALID_ARG,
                    "Reference name too long (truncated): needs %d bytes, buffer is %zu bytes",
                    written + 1, buffer_size);
    }

    return NULL;
}
