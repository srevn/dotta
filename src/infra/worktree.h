/**
 * worktree.h - Temporary git worktree management
 *
 * Manages temporary worktrees for safe git operations without
 * disturbing the main working directory.
 *
 * CRITICAL: Worktrees MUST be cleaned up, even on error paths.
 *
 * Design principles:
 * - Explicit error handling (creation can fail)
 * - Safe cleanup (can be called multiple times)
 * - Close all handles before pruning
 * - Unique temporary directory names
 * - No leaked resources
 */

#ifndef DOTTA_WORKTREE_H
#define DOTTA_WORKTREE_H

#include <git2.h>

#include "types.h"

/**
 * Worktree handle (opaque)
 *
 * Contains all resources needed for worktree operations.
 * Must be cleaned up with worktree_cleanup().
 */
typedef struct worktree_handle worktree_handle_t;

/**
 * Create temporary worktree
 *
 * Creates a new temporary worktree in system temp directory.
 * The worktree is initially empty (no branch checked out).
 *
 * IMPORTANT: Must call worktree_cleanup() even if subsequent operations fail.
 *
 * @param repo Main repository (must not be NULL)
 * @param out Worktree handle (must not be NULL)
 * @return Error or NULL on success
 *
 * Example:
 *   worktree_handle_t *wt = NULL;
 *   err = worktree_create_temp(repo, &wt);
 *   if (err) return err;
 *
 *   // ... do work ...
 *
 *   worktree_cleanup(wt);  // ALWAYS call cleanup
 */
error_t *worktree_create_temp(
    git_repository *repo,
    worktree_handle_t **out
);

/**
 * Checkout existing branch in worktree
 *
 * @param wt Worktree handle (must not be NULL)
 * @param branch_name Branch name (must not be NULL, must exist)
 * @return Error or NULL on success
 */
error_t *worktree_checkout_branch(
    worktree_handle_t *wt,
    const char *branch_name
);

/**
 * Create and checkout orphan branch in worktree
 *
 * Creates a new orphan branch (no parent commits) and checks it out.
 *
 * @param wt Worktree handle (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @return Error or NULL on success
 */
error_t *worktree_create_orphan(
    worktree_handle_t *wt,
    const char *branch_name
);

/**
 * Cleanup worktree and free all resources
 *
 * Safe to call multiple times (idempotent).
 * Safe to call with NULL.
 *
 * Cleanup order (critical):
 * 1. Close worktree repository handle
 * 2. Prune libgit2 worktree object
 * 3. Delete temporary worktree branch
 * 4. Remove worktree directory
 * 5. Free name string
 * 6. Free handle memory
 *
 * @param wt Worktree handle (can be NULL)
 */
void worktree_cleanup(worktree_handle_t *wt);

/**
 * Get worktree filesystem path
 *
 * @param wt Worktree handle (must not be NULL)
 * @return Path (valid until worktree_cleanup called)
 */
const char *worktree_get_path(const worktree_handle_t *wt);

/**
 * Get worktree repository handle
 *
 * @param wt Worktree handle (must not be NULL)
 * @return Repository (do not free, owned by worktree)
 */
git_repository *worktree_get_repo(const worktree_handle_t *wt);

/**
 * Get worktree index
 *
 * @param wt Worktree handle (must not be NULL)
 * @param out Index (must not be NULL, caller must free with git_index_free)
 * @return Error or NULL on success
 */
error_t *worktree_get_index(worktree_handle_t *wt, git_index **out);

/**
 * RAII cleanup helper
 *
 * Note: This is provided for convenience, but explicit cleanup
 * is recommended for critical resources like worktrees.
 */
static inline void cleanup_worktree_handle(worktree_handle_t **wt) {
    if (wt && *wt) {
        worktree_cleanup(*wt);
        *wt = NULL;
    }
}

#define WORKTREE_CLEANUP __attribute__((cleanup(cleanup_worktree_handle)))

#endif /* DOTTA_WORKTREE_H */
