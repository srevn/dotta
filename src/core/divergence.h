/**
 * divergence.h - Branch divergence resolution strategies
 *
 * This module encapsulates all divergence resolution logic for sync operations.
 * It provides a clean abstraction over merge/rebase operations that never
 * modifies HEAD, maintaining dotta's architectural principle.
 *
 * All operations are designed to be atomic: either the entire operation succeeds
 * and the branch is updated, or it fails and the branch remains unchanged.
 */

#ifndef DOTTA_CORE_DIVERGENCE_H
#define DOTTA_CORE_DIVERGENCE_H

#include <git2.h>

#include "types.h"

/**
 * Divergence resolution strategies
 */
typedef enum {
    DIVERGENCE_STRATEGY_REBASE,   /* Rebase local onto remote */
    DIVERGENCE_STRATEGY_MERGE,    /* Merge remote into local */
    DIVERGENCE_STRATEGY_OURS,     /* Force push local (destructive) */
    DIVERGENCE_STRATEGY_THEIRS    /* Reset to remote (destructive) */
} divergence_strategy_t;

/**
 * Divergence resolution context
 *
 * Encapsulates all information needed for divergence resolution.
 * The saved_oid is used for rollback if resolution fails.
 */
typedef struct {
    git_repository *repo;              /* Repository handle (must not be NULL) */
    const char *remote_name;           /* Remote name (e.g., "origin") */
    const char *branch_name;           /* Branch name to resolve */
    divergence_strategy_t strategy;    /* Resolution strategy */
    git_oid saved_oid;                 /* Original branch OID (for rollback) */
} divergence_context_t;

/**
 * Initialize divergence context
 *
 * Prepares a context for divergence resolution by saving the current branch state.
 *
 * @param ctx Context to initialize (must not be NULL)
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param strategy Resolution strategy
 * @return Error or NULL on success
 */
error_t *divergence_context_init(
    divergence_context_t *ctx,
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    divergence_strategy_t strategy
);

/**
 * Resolve branch divergence using specified strategy
 *
 * Performs merge or rebase WITHOUT modifying HEAD. Uses in-memory operations
 * and only updates the branch reference upon successful completion.
 *
 * The context must be initialized with divergence_context_init() first.
 *
 * @param ctx Divergence context (must not be NULL, must be initialized)
 * @param out_oid Final commit OID after resolution (can be NULL if not needed)
 * @return Error or NULL on success
 */
error_t *divergence_resolve(
    divergence_context_t *ctx,
    git_oid *out_oid
);

/**
 * Rollback divergence resolution to saved state
 *
 * Resets the branch to the OID saved in the context (saved during init).
 * This is used when resolution succeeds but subsequent operations fail
 * (e.g., push fails after rebase).
 *
 * @param ctx Divergence context (must not be NULL)
 * @return Error or NULL on success
 */
error_t *divergence_rollback(divergence_context_t *ctx);

/**
 * Verify divergence was resolved
 *
 * Checks that the branch is now ahead of remote (or up-to-date) and
 * not behind or diverged anymore.
 *
 * @param ctx Divergence context (must not be NULL)
 * @param out_ahead Commits ahead of remote (can be NULL)
 * @param out_behind Commits behind remote (can be NULL)
 * @return Error or NULL on success
 */
error_t *divergence_verify(
    divergence_context_t *ctx,
    size_t *out_ahead,
    size_t *out_behind
);

#endif /* DOTTA_CORE_DIVERGENCE_H */
