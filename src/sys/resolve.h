/**
 * resolve.h - Branch divergence resolution strategies
 *
 * This module encapsulates all branch resolution logic for sync operations. It
 * provides a clean abstraction over merge/rebase operations that never modifies
 * HEAD, maintaining dotta's architectural principle.
 *
 * A resolution writes the branch only from the head it was computed from — the
 * one resolve_init read — and a rollback only from the head the resolution left,
 * each under the branch's own lock (sys/gitops.h gitops_write_reference): a commit
 * another writer lands on the branch meanwhile, or its deletion, refuses the
 * write, and the branch stays as that writer left it. Either the resolution lands
 * whole and the branch names its result, or nothing is written.
 *
 * What a resolution integrates is resolve_init's two reads, the branch's head
 * and the remote-tracking head, not the heads the caller's analysis decided from:
 * a commit landed on either between the two is in what a rebase or a merge
 * resolves, and a reset to the remote discards the branch's and lands on the
 * remote's. The remote-tracking head is read nowhere after: a push writes the
 * ref past the head a resolution integrated (lib/libgit2/src/libgit2/push.c
 * git_push_update_tips, through the remote's fetch refspec), so a reader of what
 * was integrated reads the context, never the ref.
 */

#ifndef DOTTA_RESOLVE_H
#define DOTTA_RESOLVE_H

#include <git2.h>
#include <types.h>

#include "sys/gitops.h"

/**
 * Divergence resolution strategies
 */
typedef enum {
    RESOLVE_STRATEGY_REBASE,   /* Rebase local onto remote */
    RESOLVE_STRATEGY_MERGE,    /* Merge remote into local */
    RESOLVE_STRATEGY_OURS,     /* Force push local (destructive) */
    RESOLVE_STRATEGY_THEIRS    /* Reset to remote (destructive) */
} resolve_strategy_t;

/**
 * Divergence resolution context
 *
 * Three heads: the two resolve_init read — the branch's, every resolution's
 * expectation and the rollback's target, and the remote-tracking head, what a
 * rebase, a merge and a reset to the remote integrate — and the one the resolution
 * left, the rollback's expectation, Git's null id until a resolution lands. The
 * action is the word the commit a resolution writes names: the merge's — a rebase's
 * replays carry their picks' own, and a reset writes none.
 */
typedef struct {
    git_repository *repo;             /* Repository handle (must not be NULL) */
    const char *remote_name;          /* Remote name (e.g., "origin") */
    const char *branch_name;          /* Branch name to resolve */
    resolve_strategy_t strategy;      /* Resolution strategy */
    const char *action;               /* The word the merge commit names its action by */
    char refname[DOTTA_REFNAME_MAX];  /* The branch's reference, every write's */
    git_oid local_oid;                /* The branch's head resolve_init read */
    git_oid remote_oid;               /* The remote-tracking head resolve_init read */
    git_oid resolved_oid;             /* The head the resolution left; the null id before one */
} resolve_context_t;

/**
 * Initialize divergence context
 *
 * The branch's reference, through the branch rule (sys/gitops.h
 * gitops_branch_refname), and the head it names, read through a symbolic one:
 * the head every resolution is computed from and written over; then the
 * remote-tracking head (gitops_resolve_remote_branch_oid), what a rebase, a merge
 * and a reset to the remote integrate. Either absent is refused (ERR_NOT_FOUND).
 * No resolution has landed yet.
 *
 * @param ctx Context to initialize (must not be NULL)
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param strategy Resolution strategy
 * @param action The word its caller names the action of a commit the resolution
 *               writes by (must not be NULL; borrowed for the context's life)
 * @return Error or NULL on success
 */
error_t resolve_init(
    resolve_context_t *ctx,
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    resolve_strategy_t strategy,
    const char *action
);

/**
 * Resolve branch divergence using specified strategy
 *
 * Performs merge or rebase WITHOUT modifying HEAD. Uses in-memory operations
 * and writes the branch once, upon successful completion, only from the branch's
 * head resolve_init read: one another writer moved or deleted since is refused
 * (ERR_CONFLICT for a move, Git's words for a deletion), the branch as it left
 * it. The head the resolution left is ctx->resolved_oid.
 *
 * The context must be initialized with resolve_init() first.
 *
 * @param ctx Divergence context (must not be NULL, must be initialized)
 * @return Error or NULL on success
 */
error_t resolve_execute(resolve_context_t *ctx);

/**
 * Rollback divergence resolution to the head the branch stood at
 *
 * Writes the branch back to its head as resolve_init read it, only from the head
 * the resolution left: one another writer moved since is refused (ERR_CONFLICT),
 * and so is a rollback no resolution came before. This is used when resolution
 * succeeds but subsequent operations fail (e.g., push fails after rebase).
 *
 * @param ctx Divergence context (must not be NULL)
 * @return Error or NULL on success
 */
error_t resolve_rollback(resolve_context_t *ctx);

/**
 * Verify divergence was resolved
 *
 * Checks that the branch is now ahead of remote (or up-to-date) and not behind
 * or diverged anymore.
 *
 * @param ctx Divergence context (must not be NULL)
 * @param out_ahead Commits ahead of remote (can be NULL)
 * @param out_behind Commits behind remote (can be NULL)
 * @return Error or NULL on success
 */
error_t resolve_verify(
    resolve_context_t *ctx,
    size_t *out_ahead,
    size_t *out_behind
);

#endif /* DOTTA_RESOLVE_H */
