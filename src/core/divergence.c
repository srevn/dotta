/**
 * divergence.c - Branch divergence resolution implementation
 */

#define _POSIX_C_SOURCE 200809L  /* For snprintf */

#include "divergence.h"

#include <git2.h>
#include <stdio.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "utils/repo.h"
#include "utils/upstream.h"

/**
 * Initialize divergence context
 */
error_t *divergence_context_init(
    divergence_context_t *ctx,
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    divergence_strategy_t strategy
) {
    CHECK_NULL(ctx);
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    /* Build branch reference name */
    char refname[DOTTA_REFNAME_MAX];
    error_t *err = build_refname(refname, sizeof(refname), "refs/heads/%s", branch_name);
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    /* Get current branch OID for rollback */
    git_reference *ref = NULL;
    int git_err = git_reference_lookup(&ref, repo, refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    const git_oid *oid = git_reference_target(ref);
    if (!oid) {
        git_reference_free(ref);
        return ERROR(ERR_GIT, "Branch '%s' has no target OID", branch_name);
    }

    /* Initialize context */
    ctx->repo = repo;
    ctx->remote_name = remote_name;
    ctx->branch_name = branch_name;
    ctx->strategy = strategy;
    git_oid_cpy(&ctx->saved_oid, oid);

    git_reference_free(ref);
    return NULL;
}

/**
 * Resolve with rebase strategy (in-memory)
 */
static error_t *resolve_rebase_inmemory(divergence_context_t *ctx, git_oid *out_oid) {
    CHECK_NULL(ctx);

    /* Get local and remote commit OIDs */
    char local_refname[DOTTA_REFNAME_MAX];
    char remote_refname[DOTTA_REFNAME_MAX];
    error_t *err;

    err = build_refname(local_refname, sizeof(local_refname), "refs/heads/%s", ctx->branch_name);
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", ctx->branch_name);
    }

    err = build_refname(remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s",
                       ctx->remote_name, ctx->branch_name);
    if (err) {
        return error_wrap(err, "Invalid remote/branch name '%s/%s'",
                         ctx->remote_name, ctx->branch_name);
    }

    /* Get local commit OID */
    git_oid local_oid;
    int git_err = git_reference_name_to_id(&local_oid, ctx->repo, local_refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Get remote commit OID */
    git_oid remote_oid;
    git_err = git_reference_name_to_id(&remote_oid, ctx->repo, remote_refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Perform in-memory rebase (never touches HEAD) */
    git_oid rebased_oid;
    err = gitops_rebase_inmemory_safe(ctx->repo, &local_oid, &remote_oid, &rebased_oid);
    if (err) {
        return error_wrap(err, "Rebase failed for branch '%s'", ctx->branch_name);
    }

    /* Update branch reference to point to rebased commits */
    char reflog_msg[DOTTA_MESSAGE_MAX];
    snprintf(reflog_msg, sizeof(reflog_msg), "sync: Rebase onto %s/%s",
             ctx->remote_name, ctx->branch_name);

    err = gitops_update_branch_reference(ctx->repo, ctx->branch_name, &rebased_oid, reflog_msg);
    if (err) {
        return error_wrap(err, "Failed to update branch '%s' after rebase", ctx->branch_name);
    }

    if (out_oid) {
        git_oid_cpy(out_oid, &rebased_oid);
    }

    return NULL;
}

/**
 * Resolve with merge strategy (tree-based merge)
 */
static error_t *resolve_merge_trees(divergence_context_t *ctx, git_oid *out_oid) {
    CHECK_NULL(ctx);

    /* Get local and remote commit OIDs */
    char local_refname[DOTTA_REFNAME_MAX];
    char remote_refname[DOTTA_REFNAME_MAX];
    error_t *err;

    err = build_refname(local_refname, sizeof(local_refname), "refs/heads/%s", ctx->branch_name);
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", ctx->branch_name);
    }

    err = build_refname(remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s",
                       ctx->remote_name, ctx->branch_name);
    if (err) {
        return error_wrap(err, "Invalid remote/branch name '%s/%s'",
                         ctx->remote_name, ctx->branch_name);
    }

    /* Get local commit OID */
    git_oid local_oid;
    int git_err = git_reference_name_to_id(&local_oid, ctx->repo, local_refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Get remote commit OID */
    git_oid remote_oid;
    git_err = git_reference_name_to_id(&remote_oid, ctx->repo, remote_refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Find merge base */
    git_oid merge_base_oid;
    err = gitops_find_merge_base(ctx->repo, &local_oid, &remote_oid, &merge_base_oid);
    if (err) {
        return error_wrap(err, "Failed to find merge base for branch '%s'", ctx->branch_name);
    }

    /* Perform tree merge (never touches HEAD) */
    git_index *merged_index = NULL;
    err = gitops_merge_trees_safe(ctx->repo, &merge_base_oid, &local_oid, &remote_oid, &merged_index);
    if (err) {
        return error_wrap(err, "Merge failed for branch '%s'", ctx->branch_name);
    }

    /* Check for conflicts */
    if (git_index_has_conflicts(merged_index)) {
        git_index_free(merged_index);
        return ERROR(ERR_CONFLICT,
                    "Merge resulted in conflicts for branch '%s'. "
                    "Please resolve manually using 'git merge'.", ctx->branch_name);
    }

    /* Get commit objects for merge commit creation */
    git_commit *local_commit = NULL;
    git_commit *remote_commit = NULL;
    git_oid merge_commit_oid;

    git_err = git_commit_lookup(&local_commit, ctx->repo, &local_oid);
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
    snprintf(message, sizeof(message), "Merge remote-tracking branch '%s/%s'",
             ctx->remote_name, ctx->branch_name);

    err = gitops_create_merge_commit(ctx->repo, merged_index, local_commit, remote_commit,
                                     message, &merge_commit_oid);
    git_commit_free(remote_commit);
    git_commit_free(local_commit);
    git_index_free(merged_index);

    if (err) {
        return error_wrap(err, "Failed to create merge commit for branch '%s'", ctx->branch_name);
    }

    /* Update branch reference to point to merge commit */
    char reflog_msg[DOTTA_MESSAGE_MAX];
    snprintf(reflog_msg, sizeof(reflog_msg), "sync: Merge %s/%s",
             ctx->remote_name, ctx->branch_name);

    err = gitops_update_branch_reference(ctx->repo, ctx->branch_name, &merge_commit_oid, reflog_msg);
    if (err) {
        return error_wrap(err, "Failed to update branch '%s' after merge", ctx->branch_name);
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
static error_t *resolve_ours(divergence_context_t *ctx, git_oid *out_oid) {
    CHECK_NULL(ctx);

    /* Local branch remains unchanged at its current position */
    if (out_oid) {
        git_oid_cpy(out_oid, &ctx->saved_oid);
    }

    return NULL;
}

/**
 * Resolve with "theirs" strategy (reset to remote)
 */
static error_t *resolve_theirs(divergence_context_t *ctx, git_oid *out_oid) {
    CHECK_NULL(ctx);

    /* Get remote reference */
    char remote_refname[DOTTA_REFNAME_MAX];
    error_t *err = build_refname(remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s",
                                  ctx->remote_name, ctx->branch_name);
    if (err) {
        return error_wrap(err, "Invalid remote/branch name '%s/%s'",
                         ctx->remote_name, ctx->branch_name);
    }

    /* Get remote commit OID */
    git_oid remote_oid;
    int git_err = git_reference_name_to_id(&remote_oid, ctx->repo, remote_refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Update local branch to point to remote commit */
    char reflog_msg[DOTTA_MESSAGE_MAX];
    snprintf(reflog_msg, sizeof(reflog_msg), "sync: Reset to %s/%s (theirs strategy)",
             ctx->remote_name, ctx->branch_name);

    err = gitops_update_branch_reference(ctx->repo, ctx->branch_name, &remote_oid, reflog_msg);
    if (err) {
        return error_wrap(err, "Failed to reset branch '%s' to remote", ctx->branch_name);
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
error_t *divergence_resolve(
    divergence_context_t *ctx,
    git_oid *out_oid
) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->remote_name);
    CHECK_NULL(ctx->branch_name);

    /* Dispatch to appropriate strategy implementation */
    switch (ctx->strategy) {
        case DIVERGENCE_STRATEGY_REBASE:
            return resolve_rebase_inmemory(ctx, out_oid);

        case DIVERGENCE_STRATEGY_MERGE:
            return resolve_merge_trees(ctx, out_oid);

        case DIVERGENCE_STRATEGY_OURS:
            return resolve_ours(ctx, out_oid);

        case DIVERGENCE_STRATEGY_THEIRS:
            return resolve_theirs(ctx, out_oid);

        default:
            return ERROR(ERR_INVALID_ARG, "Unknown divergence strategy: %d", ctx->strategy);
    }
}

/**
 * Rollback divergence resolution to saved state
 */
error_t *divergence_rollback(divergence_context_t *ctx) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->branch_name);

    /* Build branch reference name */
    char refname[DOTTA_REFNAME_MAX];
    error_t *err = build_refname(refname, sizeof(refname), "refs/heads/%s", ctx->branch_name);
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", ctx->branch_name);
    }

    /* Lookup branch reference */
    git_reference *ref = NULL;
    int git_err = git_reference_lookup(&ref, ctx->repo, refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Reset branch to saved OID */
    git_reference *new_ref = NULL;
    git_err = git_reference_set_target(&new_ref, ref, &ctx->saved_oid,
                                      "sync: Rollback after failure");
    git_reference_free(ref);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_reference_free(new_ref);
    return NULL;
}

/**
 * Verify divergence was resolved
 */
error_t *divergence_verify(
    divergence_context_t *ctx,
    size_t *out_ahead,
    size_t *out_behind
) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->remote_name);
    CHECK_NULL(ctx->branch_name);

    /* Analyze current branch state */
    upstream_info_t *info = NULL;
    error_t *err = upstream_analyze_profile(ctx->repo, ctx->remote_name, ctx->branch_name, &info);
    if (err) {
        return error_wrap(err, "Failed to analyze branch '%s' after resolution", ctx->branch_name);
    }

    /* Extract results */
    if (out_ahead) *out_ahead = info->ahead;
    if (out_behind) *out_behind = info->behind;

    upstream_state_t state = info->state;
    size_t ahead = info->ahead;
    size_t behind = info->behind;
    upstream_info_free(info);

    /* After successful resolution, we should be ahead of remote (or equal) */
    if (state == UPSTREAM_REMOTE_AHEAD) {
        return ERROR(ERR_INTERNAL,
                    "Divergence resolution completed but branch '%s' is still behind remote (%zu commits)",
                    ctx->branch_name, behind);
    }

    if (state == UPSTREAM_DIVERGED) {
        return ERROR(ERR_INTERNAL,
                    "Divergence resolution completed but branch '%s' is still diverged "
                    "(ahead: %zu, behind: %zu)",
                    ctx->branch_name, ahead, behind);
    }

    return NULL;
}
