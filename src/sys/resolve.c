/**
 * resolve.c - Branch divergence resolution implementation
 */

#include "sys/resolve.h"

#include <git2.h>
#include <stdio.h>
#include <string.h>

#include "base/error.h"
#include "sys/gitops.h"
#include "sys/upstream.h"

/**
 * Initialize divergence context
 */
error_t *resolve_init(
    resolve_context_t *ctx,
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    resolve_strategy_t strategy
) {
    CHECK_NULL(ctx);
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    /* Get current branch OID for rollback */
    git_oid saved_oid;
    error_t *err = gitops_resolve_branch_head_oid(repo, branch_name, &saved_oid);
    if (err) {
        return err;
    }

    /* Initialize context */
    ctx->repo = repo;
    ctx->remote_name = remote_name;
    ctx->branch_name = branch_name;
    ctx->strategy = strategy;
    git_oid_cpy(&ctx->saved_oid, &saved_oid);

    return NULL;
}

/**
 * Resolve with rebase strategy (in-memory)
 */
static error_t *resolve_rebase_inmemory(
    resolve_context_t *ctx,
    git_oid *out_oid
) {
    CHECK_NULL(ctx);

    /* Get remote commit OID (local OID already captured in ctx->saved_oid) */
    git_oid remote_oid;
    error_t *err = gitops_resolve_remote_branch_oid(
        ctx->repo, ctx->remote_name, ctx->branch_name, &remote_oid
    );
    if (err) {
        return err;
    }

    /* Perform in-memory rebase (never touches HEAD) */
    git_oid rebased_oid;
    err = gitops_rebase_inmemory_safe(
        ctx->repo, &ctx->saved_oid, &remote_oid, &rebased_oid
    );
    if (err) {
        return error_wrap(
            err, "Rebase failed for branch '%s'",
            ctx->branch_name
        );
    }

    /* Update branch reference to point to rebased commits */
    char reflog_msg[DOTTA_MESSAGE_MAX];
    snprintf(
        reflog_msg, sizeof(reflog_msg),
        "sync: Rebase onto %s/%s",
        ctx->remote_name, ctx->branch_name
    );

    err = gitops_update_branch_reference(
        ctx->repo, ctx->branch_name, &rebased_oid, reflog_msg
    );
    if (err) {
        return error_wrap(
            err, "Failed to update branch '%s' after rebase",
            ctx->branch_name
        );
    }

    if (out_oid) {
        git_oid_cpy(out_oid, &rebased_oid);
    }

    return NULL;
}

/**
 * Resolve with merge strategy (tree-based merge)
 */
static error_t *resolve_merge_trees(
    resolve_context_t *ctx,
    git_oid *out_oid
) {
    CHECK_NULL(ctx);

    /* Get remote commit OID (local OID already captured in ctx->saved_oid) */
    git_oid remote_oid;
    error_t *err = gitops_resolve_remote_branch_oid(
        ctx->repo, ctx->remote_name, ctx->branch_name, &remote_oid
    );
    if (err) {
        return err;
    }

    /* Find merge base */
    git_oid merge_base_oid;
    err = gitops_find_merge_base(
        ctx->repo, &ctx->saved_oid, &remote_oid, &merge_base_oid
    );
    if (err) {
        if (error_code(err) == ERR_NOT_FOUND) {
            error_free(err);
            return ERROR(
                ERR_NOT_FOUND,
                "No common history for branch '%s' - branches may have been "
                "created independently. Use 'ours' or 'theirs' strategy instead",
                ctx->branch_name
            );
        }
        return error_wrap(
            err, "Failed to find merge base for branch '%s'",
            ctx->branch_name
        );
    }

    /* Perform tree merge (never touches HEAD) */
    git_index *merged_index = NULL;
    err = gitops_merge_trees_safe(
        ctx->repo, &merge_base_oid, &ctx->saved_oid, &remote_oid, &merged_index
    );
    if (err) {
        return error_wrap(err, "Merge failed for branch '%s'", ctx->branch_name);
    }

    /* Check for conflicts */
    if (git_index_has_conflicts(merged_index)) {
        git_index_free(merged_index);
        return ERROR(
            ERR_CONFLICT, "Merge resulted in conflicts for branch '%s'. "
            "Please resolve manually using 'git merge'.", ctx->branch_name
        );
    }

    /* Get commit objects for merge commit creation */
    git_commit *local_commit = NULL;
    git_commit *remote_commit = NULL;
    git_oid merge_commit_oid;

    int git_err = git_commit_lookup(&local_commit, ctx->repo, &ctx->saved_oid);
    if (git_err < 0) {
        git_index_free(merged_index);
        return error_from_git(git_err);
    }

    git_err = git_commit_lookup(&remote_commit, ctx->repo, &remote_oid);
    if (git_err < 0) {
        git_commit_free(local_commit);
        git_index_free(merged_index);
        return error_from_git(git_err);
    }

    /* Create merge commit */
    char message[DOTTA_MESSAGE_MAX];
    snprintf(
        message, sizeof(message),
        "Merge remote-tracking branch '%s/%s'",
        ctx->remote_name, ctx->branch_name
    );

    err = gitops_create_merge_commit(
        ctx->repo, merged_index, local_commit, remote_commit,
        message, &merge_commit_oid
    );
    git_commit_free(remote_commit);
    git_commit_free(local_commit);
    git_index_free(merged_index);

    if (err) {
        return error_wrap(
            err, "Failed to create merge commit for branch '%s'",
            ctx->branch_name
        );
    }

    /* Update branch reference to point to merge commit */
    char reflog_msg[DOTTA_MESSAGE_MAX];
    snprintf(
        reflog_msg, sizeof(reflog_msg),
        "sync: Merge %s/%s",
        ctx->remote_name, ctx->branch_name
    );

    err = gitops_update_branch_reference(
        ctx->repo, ctx->branch_name, &merge_commit_oid, reflog_msg
    );
    if (err) {
        return error_wrap(
            err, "Failed to update branch '%s' after merge",
            ctx->branch_name
        );
    }

    if (out_oid) {
        git_oid_cpy(out_oid, &merge_commit_oid);
    }

    return NULL;
}

/**
 * Resolve with "ours" strategy (keep local, handled by caller)
 *
 * This strategy doesn't modify the local branch - it stays at saved_oid.
 * The actual force push to remote is handled by the caller.
 */
static error_t *resolve_ours(resolve_context_t *ctx, git_oid *out_oid) {
    CHECK_NULL(ctx);

    /* Local branch remains unchanged at its current position */
    if (out_oid) {
        git_oid_cpy(out_oid, &ctx->saved_oid);
    }

    /* Always succeeds - this is a no-op strategy */
    return NULL;
}

/**
 * Resolve with "theirs" strategy (reset to remote)
 */
static error_t *resolve_theirs(resolve_context_t *ctx, git_oid *out_oid) {
    CHECK_NULL(ctx);

    /* Get remote commit OID */
    git_oid remote_oid;
    error_t *err = gitops_resolve_remote_branch_oid(
        ctx->repo, ctx->remote_name, ctx->branch_name, &remote_oid
    );
    if (err) {
        return err;
    }

    /* Update local branch to point to remote commit */
    char reflog_msg[DOTTA_MESSAGE_MAX];
    snprintf(
        reflog_msg, sizeof(reflog_msg),
        "sync: Reset to %s/%s (theirs strategy)",
        ctx->remote_name, ctx->branch_name
    );

    err = gitops_update_branch_reference(
        ctx->repo, ctx->branch_name, &remote_oid, reflog_msg
    );
    if (err) {
        return error_wrap(
            err, "Failed to reset branch '%s' to remote",
            ctx->branch_name
        );
    }

    /* Return the new OID (remote) */
    if (out_oid) {
        git_oid_cpy(out_oid, &remote_oid);
    }

    return NULL;
}

/**
 * Resolve branch divergence using specified strategy
 */
error_t *resolve_execute(
    resolve_context_t *ctx,
    git_oid *out_oid
) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->remote_name);
    CHECK_NULL(ctx->branch_name);

    /* Dispatch to appropriate strategy implementation */
    switch (ctx->strategy) {
        case RESOLVE_STRATEGY_REBASE:
            return resolve_rebase_inmemory(ctx, out_oid);

        case RESOLVE_STRATEGY_MERGE:
            return resolve_merge_trees(ctx, out_oid);

        case RESOLVE_STRATEGY_OURS:
            return resolve_ours(ctx, out_oid);

        case RESOLVE_STRATEGY_THEIRS:
            return resolve_theirs(ctx, out_oid);

        default:
            return ERROR(
                ERR_INVALID_ARG, "Unknown divergence strategy: %d",
                ctx->strategy
            );
    }
}

/**
 * Rollback divergence resolution to saved state
 */
error_t *resolve_rollback(resolve_context_t *ctx) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->branch_name);

    return gitops_update_branch_reference(
        ctx->repo,
        ctx->branch_name,
        &ctx->saved_oid,
        "sync: Rollback after failure"
    );
}

/**
 * Verify divergence was resolved
 */
error_t *resolve_verify(
    resolve_context_t *ctx,
    size_t *out_ahead,
    size_t *out_behind
) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->remote_name);
    CHECK_NULL(ctx->branch_name);

    /* Analyze current branch state */
    upstream_info_t *info = NULL;
    error_t *err = upstream_analyze_profile(
        ctx->repo, ctx->remote_name, ctx->branch_name, &info
    );
    if (err) {
        return error_wrap(
            err, "Failed to analyze branch '%s' after resolution",
            ctx->branch_name
        );
    }

    /* Extract results */
    if (out_ahead) *out_ahead = info->ahead;
    if (out_behind) *out_behind = info->behind;

    upstream_state_t state = info->state;
    size_t ahead = info->ahead;
    size_t behind = info->behind;
    upstream_info_free(info);

    /* After successful resolution, we should be ahead of remote (or equal) */
    if (state == UPSTREAM_NO_REMOTE) {
        return ERROR(
            ERR_INTERNAL,
            "Divergence resolution completed but no remote tracking branch "
            "found for '%s'", ctx->branch_name
        );
    }

    if (state == UPSTREAM_UNKNOWN) {
        return ERROR(
            ERR_INTERNAL,
            "Divergence resolution completed but could not determine state "
            "of branch '%s'", ctx->branch_name
        );
    }

    if (state == UPSTREAM_REMOTE_AHEAD) {
        return ERROR(
            ERR_INTERNAL,
            "Divergence resolution completed but branch '%s' is still "
            "behind remote (%zu commits)", ctx->branch_name, behind
        );
    }

    if (state == UPSTREAM_DIVERGED) {
        return ERROR(
            ERR_INTERNAL,
            "Divergence resolution completed but branch '%s' is still diverged "
            "(ahead: %zu, behind: %zu)", ctx->branch_name, ahead, behind
        );
    }

    return NULL;
}
