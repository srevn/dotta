/**
 * gitops.c - Git operations wrapper implementation
 *
 * All libgit2 calls are wrapped with error handling and resource cleanup.
 */

#define _POSIX_C_SOURCE 200809L  /* For strdup */

#include "gitops.h"

#include <git2.h>
#include <git2/errors.h>
#include <string.h>

#include "credentials.h"
#include "error.h"
#include "utils/array.h"
#include "utils/repo.h"

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

    git_reference *ref = NULL;
    char refname[256];
    error_t *err_build = build_refname(refname, sizeof(refname), "refs/heads/%s", name);
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

    /* Create empty tree */
    git_treebuilder *tb = NULL;
    git_oid tree_oid;
    int err;

    err = git_treebuilder_new(&tb, repo, NULL);
    if (err < 0) {
        return error_from_git(err);
    }

    err = git_treebuilder_write(&tree_oid, tb);
    git_treebuilder_free(tb);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Get tree object */
    git_tree *tree = NULL;
    err = git_tree_lookup(&tree, repo, &tree_oid);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Get default signature */
    git_signature *sig = NULL;
    err = git_signature_default(&sig, repo);
    if (err < 0) {
        git_tree_free(tree);
        return error_from_git(err);
    }

    /* Create orphan commit (no parents) */
    git_oid commit_oid;
    char refname[256];
    error_t *err_build = build_refname(refname, sizeof(refname), "refs/heads/%s", name);
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
        return error_from_git(err);
    }

    return NULL;
}

error_t *gitops_list_branches(git_repository *repo, string_array_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    git_branch_iterator *iter = NULL;
    int err = git_branch_iterator_new(&iter, repo, GIT_BRANCH_LOCAL);
    if (err < 0) {
        return error_from_git(err);
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
            return error_from_git(err);
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

    git_reference *ref = NULL;
    char refname[256];
    error_t *err_build = build_refname(refname, sizeof(refname), "refs/heads/%s", name);
    if (err_build) {
        return error_wrap(err_build, "Invalid branch name '%s'", name);
    }

    int err = git_reference_lookup(&ref, repo, refname);
    if (err < 0) {
        return error_from_git(err);
    }

    err = git_branch_delete(ref);
    git_reference_free(ref);
    if (err < 0) {
        return error_from_git(err);
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

/**
 * Tree operations
 */

error_t *gitops_load_tree(git_repository *repo, const char *ref_name, git_tree **out) {
    CHECK_NULL(repo);
    CHECK_NULL(ref_name);
    CHECK_NULL(out);

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
        /* Normal branch pointing to commit - get tree from commit */
        git_commit *commit = (git_commit *)obj;
        err = git_commit_tree(out, commit);
        git_object_free(obj);
        if (err < 0) {
            return error_from_git(err);
        }
    } else if (obj_type == GIT_OBJECT_TREE) {
        /* Orphan branch pointing directly to tree */
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
    error_t *err_build = build_refname(refname, sizeof(refname), "refs/heads/%s", branch_name);
    if (err_build) {
        git_signature_free(sig);
        /* NOTE: Do not free 'tree' - it is owned by the caller */
        return error_wrap(err_build, "Invalid branch name '%s'", branch_name);
    }

    git_reference *ref = NULL;
    if (git_reference_lookup(&ref, repo, refname) == 0) {
        git_reference_name_to_id(&commit_oid, repo, refname);
        parent_oid = &commit_oid;
        err = git_commit_lookup(&parent, repo, parent_oid);
        git_reference_free(ref);
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
 * Remote operations
 */

error_t *gitops_clone(
    git_repository **out,
    const char *url,
    const char *local_path
) {
    CHECK_NULL(out);
    CHECK_NULL(url);
    CHECK_NULL(local_path);

    git_clone_options opts = GIT_CLONE_OPTIONS_INIT;

    /* Set up credential callback */
    opts.fetch_opts.callbacks.credentials = credentials_callback;

    /* Clone with credential support */
    int err = git_clone(out, url, local_path, &opts);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

error_t *gitops_fetch_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    void *cred_ctx
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Fetch with credential support */
    git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
    fetch_opts.callbacks.credentials = credentials_callback;
    fetch_opts.callbacks.payload = cred_ctx;

    char refspec[256];
    error_t *err_build = build_refname(refspec, sizeof(refspec), "refs/heads/%s:refs/remotes/%s/%s",
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
        if (cred_ctx) {
            credential_context_reject(cred_ctx);
        }
        return error_from_git(err);
    }

    /* Success - approve credentials if they were provided */
    if (cred_ctx) {
        credential_context_approve(cred_ctx);
    }

    return NULL;
}

error_t *gitops_push_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    void *cred_ctx
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Push with credential support */
    git_push_options push_opts = GIT_PUSH_OPTIONS_INIT;
    push_opts.callbacks.credentials = credentials_callback;
    push_opts.callbacks.payload = cred_ctx;

    char refspec[256];
    error_t *err_build = build_refname(refspec, sizeof(refspec), "refs/heads/%s:refs/heads/%s",
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
        if (cred_ctx) {
            credential_context_reject(cred_ctx);
        }
        return error_from_git(err);
    }

    /* Success - approve credentials if they were provided */
    if (cred_ctx) {
        credential_context_approve(cred_ctx);
    }

    return NULL;
}

error_t *gitops_delete_remote_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    void *cred_ctx
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    git_remote *remote = NULL;
    int err = git_remote_lookup(&remote, repo, remote_name);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Delete remote branch using empty refspec: :refs/heads/branch */
    git_push_options push_opts = GIT_PUSH_OPTIONS_INIT;
    push_opts.callbacks.credentials = credentials_callback;
    push_opts.callbacks.payload = cred_ctx;

    char refspec[256];
    error_t *err_build = build_refname(refspec, sizeof(refspec), ":refs/heads/%s", branch_name);
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
        if (cred_ctx) {
            credential_context_reject(cred_ctx);
        }
        return error_from_git(err);
    }

    /* Success - approve credentials if they were provided */
    if (cred_ctx) {
        credential_context_approve(cred_ctx);
    }

    return NULL;
}

error_t *gitops_merge_ff_only(git_repository *repo, const char *branch_name) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);

    /* Get their commit */
    char refname[256];
    error_t *err_build = build_refname(refname, sizeof(refname), "refs/heads/%s", branch_name);
    if (err_build) {
        return error_wrap(err_build, "Invalid branch name '%s'", branch_name);
    }

    git_annotated_commit *their_head = NULL;
    git_reference *ref = NULL;
    int err;

    err = git_reference_lookup(&ref, repo, refname);
    if (err < 0) {
        return error_from_git(err);
    }

    err = git_annotated_commit_from_ref(&their_head, repo, ref);
    git_reference_free(ref);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Perform fast-forward merge */
    git_merge_analysis_t analysis;
    git_merge_preference_t preference;
    const git_annotated_commit *merge_heads[] = { their_head };

    err = git_merge_analysis(&analysis, &preference, repo, merge_heads, 1);
    if (err < 0) {
        git_annotated_commit_free(their_head);
        return error_from_git(err);
    }

    if ((analysis & GIT_MERGE_ANALYSIS_FASTFORWARD) == 0) {
        git_annotated_commit_free(their_head);
        return ERROR(ERR_GIT, "Fast-forward merge not possible for '%s'", branch_name);
    }

    /* Perform FF merge */
    git_reference *target_ref = NULL;
    err = git_repository_head(&target_ref, repo);
    if (err < 0) {
        git_annotated_commit_free(their_head);
        return error_from_git(err);
    }

    git_reference *new_target_ref = NULL;
    err = git_reference_set_target(&new_target_ref, target_ref,
                                   git_annotated_commit_id(their_head),
                                   "merge: Fast-forward");
    git_reference_free(target_ref);
    git_annotated_commit_free(their_head);

    if (err < 0) {
        return error_from_git(err);
    }

    git_reference_free(new_target_ref);
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

    /* Normalize path (remove leading slash if present) */
    const char *normalized_path = path;
    if (path[0] == '/') {
        normalized_path = path + 1;
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

    /* Check if basename matches */
    if (strcmp(entry_name, search->target_basename) == 0) {
        /* Build full path */
        size_t root_len = strlen(root);
        size_t path_len = root_len + strlen(entry_name) + 2;
        char *full_path = malloc(path_len);
        if (!full_path) {
            return -1;  /* Memory allocation failed */
        }

        if (root_len > 0 && root[root_len - 1] != '/') {
            snprintf(full_path, path_len, "%s/%s", root, entry_name);
        } else if (root_len > 0) {
            snprintf(full_path, path_len, "%s%s", root, entry_name);
        } else {
            snprintf(full_path, path_len, "%s", entry_name);
        }

        /* Add to results */
        if (search->count >= search->capacity) {
            search->capacity = search->capacity == 0 ? 4 : search->capacity * 2;
            char **new_paths = realloc(search->matching_paths,
                                      search->capacity * sizeof(char *));
            if (!new_paths) {
                free(full_path);
                return -1;  /* Memory allocation failed */
            }
            search->matching_paths = new_paths;
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
    error_t *err_build = build_refname(ref_name, sizeof(ref_name), "refs/heads/%s", branch_name);
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
    if (strncmp(commit_ref, "HEAD", 4) == 0) {
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
            size_t full_ref_size = strlen(branch_name) + strlen(commit_ref) + 10;
            full_ref = malloc(full_ref_size);
            if (!full_ref) {
                git_reference_free(branch_ref);
                return ERROR(ERR_MEMORY, "Failed to allocate ref string");
            }
            snprintf(full_ref, full_ref_size, "%s%s", branch_name, commit_ref + 4);
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

    /* Write index to tree */
    git_oid tree_oid;
    int err = git_index_write_tree(&tree_oid, index);
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

    /* Process each rebase operation
     * Initialize commit_oid to onto_oid - if there are no operations to rebase
     * (branch is already up-to-date or behind), we return onto_oid which is
     * correct for both cases (no-op or fast-forward).
     */
    git_rebase_operation *op = NULL;
    git_oid commit_oid;
    git_oid_cpy(&commit_oid, onto_oid);

    while ((git_err = git_rebase_next(&op, rebase)) == 0) {
        /* Get signature */
        git_signature *sig = NULL;
        git_err = git_signature_default(&sig, repo);
        if (git_err < 0) {
            err = error_from_git(git_err);
            git_rebase_abort(rebase);
            git_rebase_free(rebase);
            return error_wrap(err, "Failed to get signature during rebase");
        }

        /* Commit the rebased operation
         * In inmemory mode, this doesn't touch HEAD or working directory
         */
        git_err = git_rebase_commit(&commit_oid, rebase, NULL, sig, NULL, NULL);
        git_signature_free(sig);

        if (git_err < 0) {
            git_rebase_abort(rebase);
            git_rebase_free(rebase);

            /* Check for merge conflicts specifically */
            if (git_err == GIT_EMERGECONFLICT) {
                return ERROR(ERR_CONFLICT,
                            "Rebase resulted in conflicts. "
                            "Please resolve manually using 'git rebase' or try merge strategy instead.");
            }

            err = error_from_git(git_err);
            return error_wrap(err, "Failed to commit during rebase");
        }
    }

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
    error_t *err = build_refname(refname, sizeof(refname), "refs/heads/%s", branch_name);
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
