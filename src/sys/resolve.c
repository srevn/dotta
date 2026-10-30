/**
 * resolve.c - Branch divergence resolution implementation
 */

#include "sys/resolve.h"

#include <git2.h>

#include "base/error.h"
#include "sys/gitops.h"
#include "sys/upstream.h"

/**
 * Initialize divergence context
 */
error_t resolve_init(
    resolve_context_t *ctx,
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    resolve_strategy_t strategy,
    const char *action
) {
    CHECK_NULL(ctx);
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(action);

    ctx->repo = repo;
    ctx->remote_name = remote_name;
    ctx->branch_name = branch_name;
    ctx->strategy = strategy;
    ctx->action = action;
    ctx->resolved_oid = (git_oid) GIT_OID_SHA1_ZERO;

    /* The branch's reference, every write's, and the head it names: the one every
     * resolution is computed from and written over, read through a symbolic one,
     * an absence refused */
    error_t err = gitops_branch_refname(ctx->refname, sizeof(ctx->refname), branch_name);
    if (err) return err;

    err = gitops_resolve_reference_oid(repo, ctx->refname, &ctx->local_oid);
    if (err) return err;

    /* The remote-tracking head, an absence refused: what the resolution integrates,
     * read once, here, since a push writes the ref past it (resolve.h) */
    return gitops_resolve_remote_branch_oid(repo, remote_name, branch_name, &ctx->remote_oid);
}

/**
 * Resolve with rebase strategy (in-memory)
 */
static error_t resolve_rebase_inmemory(resolve_context_t *ctx) {
    CHECK_NULL(ctx);

    /* Perform in-memory rebase (never touches HEAD) */
    git_oid rebased_oid;
    error_t err = gitops_rebase_inmemory_safe(
        ctx->repo, &ctx->local_oid, &ctx->remote_oid, &rebased_oid
    );
    if (err) {
        return error_wrap(
            err, "Rebase failed for branch '%s'",
            ctx->branch_name
        );
    }

    /* Update branch reference to point to rebased commits */
    err = gitops_write_reference(
        ctx->repo, ctx->refname, &rebased_oid, &ctx->local_oid, ctx->action,
        "rebase onto %s/%s", ctx->remote_name, ctx->branch_name
    );
    if (err) return err;

    git_oid_cpy(&ctx->resolved_oid, &rebased_oid);
    return NULL;
}

/**
 * Resolve with "ours" strategy (keep local, handled by caller)
 *
 * This strategy doesn't modify the local branch - it stays at local_oid. The
 * actual force push to remote is handled by the caller.
 */
static error_t resolve_ours(resolve_context_t *ctx) {
    CHECK_NULL(ctx);

    /* Local branch remains unchanged at its current position */
    git_oid_cpy(&ctx->resolved_oid, &ctx->local_oid);

    /* Always succeeds - this is a no-op strategy */
    return NULL;
}

/**
 * Resolve with "theirs" strategy (reset to remote)
 */
static error_t resolve_theirs(resolve_context_t *ctx) {
    CHECK_NULL(ctx);

    /* Update local branch to point to remote commit */
    error_t err = gitops_write_reference(
        ctx->repo, ctx->refname, &ctx->remote_oid, &ctx->local_oid, ctx->action,
        "reset to %s/%s (theirs strategy)", ctx->remote_name, ctx->branch_name
    );
    if (err) return err;

    git_oid_cpy(&ctx->resolved_oid, &ctx->remote_oid);
    return NULL;
}

/**
 * Resolve branch divergence using specified strategy
 */
error_t resolve_execute(resolve_context_t *ctx) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->remote_name);
    CHECK_NULL(ctx->branch_name);

    /* Dispatch to appropriate strategy implementation */
    switch (ctx->strategy) {
        case RESOLVE_STRATEGY_REBASE:
            return resolve_rebase_inmemory(ctx);

        case RESOLVE_STRATEGY_OURS:
            return resolve_ours(ctx);

        case RESOLVE_STRATEGY_THEIRS:
            return resolve_theirs(ctx);
    }

    CHECK_ARG(false, "a divergence strategy no enumerator names");
}

/**
 * Rollback divergence resolution to the head the branch stood at
 */
error_t resolve_rollback(resolve_context_t *ctx) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->branch_name);

    /* Back to the branch's head resolve_init read, only from the one the resolution
     * left: before any, Git's null id, which a branch that stands refuses */
    return gitops_write_reference(
        ctx->repo, ctx->refname, &ctx->local_oid, &ctx->resolved_oid, ctx->action,
        "rollback after failure"
    );
}

/**
 * Verify divergence was resolved
 */
error_t resolve_verify(
    resolve_context_t *ctx,
    size_t *out_ahead,
    size_t *out_behind
) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->remote_name);
    CHECK_NULL(ctx->branch_name);

    /* Analyze current branch state */
    upstream_info_t info;
    error_t err = upstream_analyze_profile(
        ctx->repo, ctx->remote_name, ctx->branch_name, &info
    );
    if (err) return err;

    if (out_ahead) *out_ahead = info.ahead;
    if (out_behind) *out_behind = info.behind;

    upstream_state_t state = info.state;
    size_t ahead = info.ahead;
    size_t behind = info.behind;

    /* After successful resolution, we should be ahead of remote (or equal) */
    if (state == UPSTREAM_NO_REMOTE) {
        return error_create(
            ERR_INTERNAL,
            "Divergence resolution completed but no remote tracking branch "
            "found for '%s'", ctx->branch_name
        );
    }

    if (state == UPSTREAM_NO_LOCAL) {
        return error_create(
            ERR_INTERNAL,
            "Divergence resolution completed but local branch '%s' no longer "
            "exists", ctx->branch_name
        );
    }

    if (state == UPSTREAM_REMOTE_AHEAD) {
        return error_create(
            ERR_INTERNAL,
            "Divergence resolution completed but branch '%s' is still "
            "behind remote (%zu commits)", ctx->branch_name, behind
        );
    }

    if (state == UPSTREAM_DIVERGED) {
        return error_create(
            ERR_INTERNAL,
            "Divergence resolution completed but branch '%s' is still diverged "
            "(ahead: %zu, behind: %zu)", ctx->branch_name, ahead, behind
        );
    }

    return NULL;
}
