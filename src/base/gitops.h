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
 * Common buffer size constants for Git operations
 *
 * These constants define standard buffer sizes used throughout dotta.
 * Git allows up to 255 chars per reference component, but we use
 * conservative limits for safety and to catch truncation early.
 */
#define DOTTA_REFNAME_MAX 256    /* For git reference names (refs/heads/...) */
#define DOTTA_REFSPEC_MAX 256    /* For git refspecs (refs/heads/foo:refs/remotes/...) */
#define DOTTA_MESSAGE_MAX 512    /* For commit messages and prompts */

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
 * Check if path is a valid git repository
 *
 * @param path Path to check (must not be NULL)
 * @return true if path exists and is a valid git repository
 */
bool gitops_is_repository(const char *path);

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

/* Forward declaration for transfer context */
typedef struct transfer_context_s transfer_context_t;

/**
 * Clone repository from URL
 *
 * @param out Repository handle (must not be NULL)
 * @param url Remote URL (must not be NULL)
 * @param local_path Local path for clone (must not be NULL)
 * @param xfer Transfer context for credentials and progress (may be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_clone(
    git_repository **out,
    const char *url,
    const char *local_path,
    transfer_context_t *xfer
);

/**
 * Fetch branch from remote
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin") (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param xfer Transfer context for credentials and progress (may be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_fetch_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    transfer_context_t *xfer
);

/**
 * Fetch multiple branches from remote in a single operation
 *
 * Performs a batched fetch of multiple branches, significantly reducing
 * network overhead compared to fetching each branch individually.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin") (must not be NULL)
 * @param branch_names Array of branch names (must not be NULL)
 * @param branch_count Number of branches to fetch (must be > 0)
 * @param xfer Transfer context for credentials and progress (may be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_fetch_branches(
    git_repository *repo,
    const char *remote_name,
    const char **branch_names,
    size_t branch_count,
    transfer_context_t *xfer
);

/**
 * Push branch to remote
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param xfer Transfer context for credentials and progress (may be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_push_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    transfer_context_t *xfer
);

/**
 * Delete a branch from remote repository
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param xfer Transfer context for credentials and progress (may be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_delete_remote_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    transfer_context_t *xfer
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
 * Validate and build a Git reference name
 *
 * Builds a reference name using printf-style formatting and validates
 * it fits in the provided buffer without truncation.
 *
 * Git allows up to 255 chars per component, but we use conservative limits
 * to prevent silent failures with libgit2 operations.
 *
 * @param buffer Output buffer for the reference name (must not be NULL)
 * @param buffer_size Size of output buffer
 * @param format Printf-style format string (must not be NULL)
 * @param ... Format arguments
 * @return Error or NULL on success
 *
 * Example:
 *   char refname[256];
 *   error_t *err = gitops_build_refname(refname, sizeof(refname), "refs/heads/%s", branch);
 */
error_t *gitops_build_refname(char *buffer, size_t buffer_size, const char *format, ...);

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

/**
 * Advanced merge/rebase operations (HEAD-safe)
 *
 * These operations never modify HEAD and are designed for dotta's architecture
 * where HEAD must always point to dotta-worktree.
 */

/**
 * Get tree from commit OID
 *
 * Convenience function to extract tree from a commit.
 *
 * @param repo Repository (must not be NULL)
 * @param commit_oid Commit OID (must not be NULL)
 * @param out_tree Tree object (must not be NULL, caller must free with git_tree_free)
 * @return Error or NULL on success
 */
error_t *gitops_get_tree_from_commit(
    git_repository *repo,
    const git_oid *commit_oid,
    git_tree **out_tree
);

/**
 * Find merge base between two commits
 *
 * Finds the best common ancestor for a three-way merge.
 *
 * @param repo Repository (must not be NULL)
 * @param one First commit OID (must not be NULL)
 * @param two Second commit OID (must not be NULL)
 * @param out_oid Merge base commit OID (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_find_merge_base(
    git_repository *repo,
    const git_oid *one,
    const git_oid *two,
    git_oid *out_oid
);

/**
 * Merge trees without modifying HEAD or working directory
 *
 * Performs a three-way merge using common ancestor. This is a pure
 * tree-level operation that never touches HEAD.
 *
 * @param repo Repository (must not be NULL)
 * @param ancestor_oid Common ancestor commit (must not be NULL)
 * @param our_oid Our commit (local) (must not be NULL)
 * @param their_oid Their commit (remote) (must not be NULL)
 * @param out_index Resulting merge index (must not be NULL, caller must free with git_index_free)
 * @return Error or NULL on success
 */
error_t *gitops_merge_trees_safe(
    git_repository *repo,
    const git_oid *ancestor_oid,
    const git_oid *our_oid,
    const git_oid *their_oid,
    git_index **out_index
);

/**
 * Create merge commit from index
 *
 * Creates a merge commit with two parents. Does not update any references.
 *
 * @param repo Repository (must not be NULL)
 * @param index Merged index (must not be NULL, must not have conflicts)
 * @param our_commit Our commit (local) (must not be NULL)
 * @param their_commit Their commit (remote) (must not be NULL)
 * @param message Commit message (must not be NULL)
 * @param out_oid Created commit OID (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_create_merge_commit(
    git_repository *repo,
    git_index *index,
    git_commit *our_commit,
    git_commit *their_commit,
    const char *message,
    git_oid *out_oid
);

/**
 * Perform in-memory rebase without modifying HEAD
 *
 * Rebases branch_oid onto onto_oid using libgit2's in-memory mode.
 * This never touches HEAD or the working directory.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_oid Branch to rebase (must not be NULL)
 * @param onto_oid Target to rebase onto (must not be NULL)
 * @param out_oid Final rebased commit OID (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_rebase_inmemory_safe(
    git_repository *repo,
    const git_oid *branch_oid,
    const git_oid *onto_oid,
    git_oid *out_oid
);

/**
 * Update branch reference to new commit
 *
 * Updates a branch reference without modifying HEAD. Thread-safe with reflog.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param new_oid New commit OID (must not be NULL)
 * @param reflog_msg Reflog message (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_update_branch_reference(
    git_repository *repo,
    const char *branch_name,
    const git_oid *new_oid,
    const char *reflog_msg
);

#endif /* DOTTA_GITOPS_H */
