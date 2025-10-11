/**
 * gitops.h - Git operations wrapper
 *
 * Thin wrapper around libgit2 with error handling and resource management.
 *
 * Design principles:
 * - Validate all inputs
 * - Convert libgit2 errors to dotta errors
 * - Manage libgit2 object lifecycles
 * - No business logic (just git operations)
 */

#ifndef DOTTA_GITOPS_H
#define DOTTA_GITOPS_H

#include <git2.h>

#include "types.h"

/**
 * Repository operations
 */

/**
 * Open git repository at path
 *
 * @param out Repository handle (must not be NULL)
 * @param path Repository path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_open_repository(git_repository **out, const char *path);

/**
 * Close repository and free resources
 *
 * Safe to call with NULL.
 *
 * @param repo Repository handle (can be NULL)
 */
void gitops_close_repository(git_repository *repo);

/**
 * Discover repository starting from path
 *
 * Searches upward from start_path to find .git directory.
 *
 * @param out Repository path (must not be NULL, caller must free)
 * @param start_path Starting search path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_discover_repository(char **out, const char *start_path);

/**
 * Discover and open repository
 *
 * Convenience function combining discover + open.
 *
 * @param out Repository handle (must not be NULL)
 * @param start_path Starting search path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_discover_and_open(git_repository **out, const char *start_path);

/**
 * Branch/Reference operations
 */

/**
 * Check if branch exists
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @param exists Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_branch_exists(git_repository *repo, const char *name, bool *exists);

/**
 * Create orphan branch (no parent commits)
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_create_orphan_branch(git_repository *repo, const char *name);

/**
 * List all local branches
 *
 * @param repo Repository (must not be NULL)
 * @param out String array of branch names (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_list_branches(git_repository *repo, string_array_t **out);

/**
 * Delete branch
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_delete_branch(git_repository *repo, const char *name);

/**
 * Get current branch name
 *
 * @param repo Repository (must not be NULL)
 * @param out Branch name (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *gitops_current_branch(git_repository *repo, char **out);

/**
 * Tree operations
 */

/**
 * Load tree from reference
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Reference name (e.g., "refs/heads/main") (must not be NULL)
 * @param out Tree object (must not be NULL, caller must free with git_tree_free)
 * @return Error or NULL on success
 */
error_t *gitops_load_tree(git_repository *repo, const char *ref_name, git_tree **out);

/**
 * Walk tree with callback
 *
 * @param tree Tree to walk (must not be NULL)
 * @param callback Callback function (must not be NULL)
 * @param payload User data passed to callback
 * @return Error or NULL on success
 */
error_t *gitops_tree_walk(
    git_tree *tree,
    git_treewalk_cb callback,
    void *payload
);

/**
 * Find file by exact path in tree
 *
 * Normalizes path (removes leading slash) before lookup.
 *
 * @param repo Repository (must not be NULL)
 * @param tree Tree to search (must not be NULL)
 * @param path File path (must not be NULL)
 * @param out Tree entry (must not be NULL, caller must free with git_tree_entry_free)
 * @return Error or NULL on success
 */
error_t *gitops_find_file_in_tree(
    git_repository *repo,
    git_tree *tree,
    const char *path,
    git_tree_entry **out
);

/**
 * Find files by basename in tree
 *
 * Searches recursively for all files with matching basename.
 *
 * @param repo Repository (must not be NULL)
 * @param tree Tree to search (must not be NULL)
 * @param basename File basename to search for (must not be NULL)
 * @param out_paths Array of matching paths (must not be NULL, caller must free array and strings)
 * @param out_count Number of matching paths (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_find_files_by_basename_in_tree(
    git_repository *repo,
    git_tree *tree,
    const char *basename,
    char ***out_paths,
    size_t *out_count
);

/**
 * Commit operations
 */

/**
 * Create commit
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param tree Tree object (must not be NULL)
 * @param message Commit message (must not be NULL)
 * @param out Commit OID (can be NULL if not needed)
 * @return Error or NULL on success
 */
error_t *gitops_create_commit(
    git_repository *repo,
    const char *branch_name,
    git_tree *tree,
    const char *message,
    git_oid *out
);

/**
 * Get commit from reference
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Reference name (must not be NULL)
 * @param out Commit object (must not be NULL, caller must free with git_commit_free)
 * @return Error or NULL on success
 */
error_t *gitops_get_commit(
    git_repository *repo,
    const char *ref_name,
    git_commit **out
);

/**
 * Resolve commit reference within a branch
 *
 * Resolves commit references (HEAD, HEAD~N, SHA, etc.) relative to a branch.
 * Supports:
 * - "HEAD" (branch HEAD)
 * - "HEAD~N" or "HEAD^N" (ancestry)
 * - Full/short SHA
 * - Tags
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param commit_ref Commit reference (must not be NULL)
 * @param out_oid Resolved commit OID (must not be NULL)
 * @param out_commit Resolved commit object (can be NULL if not needed, caller must free)
 * @return Error or NULL on success
 */
error_t *gitops_resolve_commit_in_branch(
    git_repository *repo,
    const char *branch_name,
    const char *commit_ref,
    git_oid *out_oid,
    git_commit **out_commit
);

/**
 * Remote operations
 */

/**
 * Clone repository from URL
 *
 * @param out Repository handle (must not be NULL)
 * @param url Remote URL (must not be NULL)
 * @param local_path Local path for clone (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_clone(
    git_repository **out,
    const char *url,
    const char *local_path
);

/**
 * Fetch branch from remote
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin") (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param cred_ctx Credential context for approve/reject (may be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_fetch_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    void *cred_ctx
);

/**
 * Push branch to remote
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param cred_ctx Credential context for approve/reject (may be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_push_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    void *cred_ctx
);

/**
 * Delete a branch from remote repository
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param cred_ctx Credential context for approve/reject (may be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_delete_remote_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    void *cred_ctx
);

/**
 * Fast-forward merge (no conflicts possible)
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch to merge from (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_merge_ff_only(git_repository *repo, const char *branch_name);

/**
 * Reference operations
 */

/**
 * Create reference
 *
 * @param repo Repository (must not be NULL)
 * @param name Reference name (e.g., "refs/heads/mybranch") (must not be NULL)
 * @param oid Target OID (must not be NULL)
 * @param force Overwrite if exists
 * @return Error or NULL on success
 */
error_t *gitops_create_reference(
    git_repository *repo,
    const char *name,
    const git_oid *oid,
    bool force
);

/**
 * Lookup reference
 *
 * @param repo Repository (must not be NULL)
 * @param name Reference name (must not be NULL)
 * @param out Reference object (must not be NULL, caller must free with git_reference_free)
 * @return Error or NULL on success
 */
error_t *gitops_lookup_reference(
    git_repository *repo,
    const char *name,
    git_reference **out
);

/**
 * Index operations
 */

/**
 * Get repository index
 *
 * @param repo Repository (must not be NULL)
 * @param out Index object (must not be NULL, caller must free with git_index_free)
 * @return Error or NULL on success
 */
error_t *gitops_get_index(git_repository *repo, git_index **out);

/**
 * Add file to index
 *
 * @param index Index (must not be NULL)
 * @param path Path relative to repository root (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_index_add(git_index *index, const char *path);

/**
 * Write index to disk and create tree
 *
 * @param index Index (must not be NULL)
 * @param out Tree OID (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_index_write_tree(git_index *index, git_oid *out);

#endif /* DOTTA_GITOPS_H */
