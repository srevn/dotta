/**
 * sync.c - Intelligent synchronization command
 */

#include "cmds/sync.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "crypto/keymgr.h"
#include "infra/epoch.h"
#include "sys/gitops.h"
#include "sys/resolve.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/hooks.h"

/**
 * Per-profile sync outcome
 */
typedef enum {
    SYNC_OUTCOME_UP_TO_DATE = 0, /* Genuine no-op (or analyze never reached) */
    SYNC_OUTCOME_PUSHED,         /* Clean push: LOCAL_AHEAD / NO_REMOTE created */
    SYNC_OUTCOME_PULLED,         /* Clean FF: REMOTE_AHEAD + auto_pull */
    SYNC_OUTCOME_RESOLVED,       /* Destructive: rebase / merge / ours / theirs */
    SYNC_OUTCOME_DIVERGED,       /* Unresolved: warn / --no-push / --no-pull / cancel / unknown */
    SYNC_OUTCOME_FAILED,         /* Push/pull/resolution error */
} sync_outcome_t;

/**
 * Per-profile sync result
 */
typedef struct {
    char *profile;
    upstream_state_t state;
    size_t ahead;
    size_t behind;
    sync_outcome_t outcome;
    error_t *error;                 /* Owned; set by mark_result_failed */
} profile_sync_result_t;

/**
 * Overall sync results
 */
typedef struct {
    profile_sync_result_t *profiles;
    size_t profile_count;
} sync_results_t;

/**
 * Create sync results
 */
static sync_results_t *sync_results_create(size_t profile_count) {
    sync_results_t *results = calloc(1, sizeof(sync_results_t));
    if (!results) {
        return NULL;
    }

    results->profiles = calloc(profile_count, sizeof(profile_sync_result_t));
    if (!results->profiles) {
        free(results);
        return NULL;
    }

    results->profile_count = profile_count;
    return results;
}

/**
 * Free sync results
 */
static void sync_results_free(sync_results_t *results) {
    if (!results) {
        return;
    }

    for (size_t i = 0; i < results->profile_count; i++) {
        free(results->profiles[i].profile);
        error_free(results->profiles[i].error);
    }

    free(results->profiles);
    free(results);
}

/**
 * Single funnel for SYNC_OUTCOME_FAILED. Takes ownership of err. Caller must
 * print any output_error messages before calling.
 */
static void mark_result_failed(
    profile_sync_result_t *result,
    error_t *err
) {
    result->outcome = SYNC_OUTCOME_FAILED;
    result->error = err;
}

/**
 * The divergence strategies by the word `--diverged` and the config take — the
 * one spelling the parser, the receipts and completion share.
 */
static const struct {
    const char *name;
    sync_strategy_t strategy;
    const char *summary;
} sync_strategies[] = {
    { "warn",   DIVERGE_WARN,   "Report the divergence, resolve by hand" },
    { "rebase", DIVERGE_REBASE, "Rebase local commits onto the remote"   },
    { "merge",  DIVERGE_MERGE,  "Merge the remote into the local branch" },
    { "ours",   DIVERGE_OURS,   "Keep local, force-push over the remote" },
    { "theirs", DIVERGE_THEIRS, "Keep remote, reset the local branch"    },
};

#define SYNC_STRATEGY_COUNT (sizeof(sync_strategies) / sizeof(*sync_strategies))

/**
 * Parse divergence strategy from string
 *
 * @param str Strategy string (NULL defaults to DIVERGE_WARN)
 * @param out_strategy Parsed strategy (set only on success)
 * @return true if valid (or NULL), false if unrecognized
 */
static bool parse_divergence_strategy(
    const char *str,
    sync_strategy_t *out_strategy
) {
    if (!str) {
        *out_strategy = DIVERGE_WARN;
        return true;
    }

    for (size_t i = 0; i < SYNC_STRATEGY_COUNT; i++) {
        if (strcmp(str, sync_strategies[i].name) == 0) {
            *out_strategy = sync_strategies[i].strategy;
            return true;
        }
    }
    return false;
}

/**
 * Pull branch with fast-forward only Returns true if branch was updated
 */
static error_t *pull_branch_ff(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    bool *updated
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(updated);

    *updated = false;

    /* Get local and remote refs */
    char local_refname[DOTTA_REFNAME_MAX];
    char remote_refname[DOTTA_REFNAME_MAX];
    error_t *err;

    err = gitops_build_refname(
        local_refname, sizeof(local_refname), "refs/heads/%s",
        branch_name
    );
    if (err) {
        return error_wrap(
            err, "Invalid branch name '%s'",
            branch_name
        );
    }

    err = gitops_build_refname(
        remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s",
        remote_name, branch_name
    );
    if (err) {
        return error_wrap(
            err, "Invalid remote/branch name '%s/%s'",
            remote_name, branch_name
        );
    }

    git_reference *local_ref = NULL;
    git_reference *remote_ref = NULL;

    int git_err = git_reference_lookup(&local_ref, repo, local_refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_err = git_reference_lookup(&remote_ref, repo, remote_refname);
    if (git_err < 0) {
        git_reference_free(local_ref);
        if (git_err == GIT_ENOTFOUND) {
            /* Remote branch doesn't exist */
            return NULL;
        }
        return error_from_git(git_err);
    }

    const git_oid *remote_oid = git_reference_target(remote_ref);
    const git_oid *local_oid = git_reference_target(local_ref);

    /* Check if branches are at the same commit (up-to-date) */
    if (git_oid_equal(local_oid, remote_oid)) {
        git_reference_free(local_ref);
        git_reference_free(remote_ref);
        /* Already up-to-date, nothing to do */
        return NULL;
    }

    /* Check if fast-forward is possible by checking if local is ancestor of remote
     * This is independent of where HEAD is currently pointing, which is important
     * because we're always on dotta-worktree, not on the branch we're updating.
     */
    git_err = git_graph_descendant_of(repo, remote_oid, local_oid);
    if (git_err < 0) {
        git_reference_free(local_ref);
        git_reference_free(remote_ref);
        return error_from_git(git_err);
    }

    if (git_err == 0) {
        /* local is NOT an ancestor of remote - cannot fast-forward */
        git_reference_free(local_ref);
        git_reference_free(remote_ref);
        return ERROR(
            ERR_CONFLICT, "Cannot fast-forward '%s' - branches have diverged",
            branch_name
        );
    }

    /* git_err == 1 means local IS an ancestor of remote - can fast-forward */

    /* Perform fast-forward */
    git_reference *updated_ref = NULL;
    git_err = git_reference_set_target(
        &updated_ref, local_ref, remote_oid, "sync: Fast-forward pull"
    );
    git_reference_free(local_ref);
    git_reference_free(remote_ref);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_reference_free(updated_ref);
    *updated = true;

    return NULL;
}

/**
 * Phase 1: Fetch profiles in sync scope from remote
 *
 * Operates on the active set (scope_active): fetching is driven by what the user
 * asked for. `dotta sync -p work` fetches only `work`, not every enabled profile.
 * Precedence-adjacent work (push phase) still uses the full enabled set — different
 * role, different accessor.
 */
static error_t *sync_fetch_phase(
    git_repository *repo,
    const char *remote_name,
    const scope_t *scope,
    sync_results_t *results,
    output_t *out,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(scope);
    CHECK_NULL(results);
    CHECK_NULL(out);

    const string_array_t *profiles = scope_active(scope);

    /* Check if remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err == GIT_ENOTFOUND) {
        return ERROR(
            ERR_NOT_FOUND, "No remote '%s' configured\n"
            "Hint: Run 'dotta remote add %s <url>' to add a remote",
            remote_name, remote_name
        );
    } else if (git_err < 0) {
        return error_from_git(git_err);
    }
    git_remote_free(remote);

    /* Ephemeral fetch progress — shown while fetching, cleared after. On TTY:
     * transfer progress overwrites via \r, then line cleared entirely. On pipe:
     * falls back to persistent line with newline. */
    bool ephemeral = output_is_tty(out);
    output_print(
        out, OUTPUT_NORMAL, "Fetching from '%s'...",
        remote_name
    );
    fflush(out->stream);

    /* Build array of fetchable branch names.
     *
     * Only include profiles that have a remote tracking ref — these are known
     * to exist (or have existed) on the remote. Local-only profiles (never pushed)
     * have no tracking ref and would cause the entire batched fetch to fail with
     * a "ref not found" error from the remote. */
    char **branch_names = malloc(profiles->count * sizeof(char *));
    if (!branch_names) {
        if (ephemeral) {
            output_clear_line(out);
        } else {
            output_newline(out, OUTPUT_NORMAL);
        }
        return ERROR(ERR_MEMORY, "Failed to allocate branch names array");
    }

    size_t fetch_count = 0;
    for (size_t i = 0; i < profiles->count; i++) {
        char remote_refname[DOTTA_REFNAME_MAX];
        error_t *err_build = gitops_build_refname(
            remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s",
            remote_name, profiles->items[i]
        );
        if (err_build) {
            error_free(err_build);
            continue;
        }

        git_reference *ref = NULL;
        int rc = git_reference_lookup(&ref, repo, remote_refname);
        if (rc == 0) {
            git_reference_free(ref);
            branch_names[fetch_count++] = profiles->items[i];
        }
    }

    /* Skip fetch entirely if no profiles have remote tracking refs */
    if (fetch_count == 0) {
        free(branch_names);
        if (ephemeral) {
            output_clear_line(out);
        } else {
            output_newline(out, OUTPUT_NORMAL);
        }
        return NULL;
    }

    /* Perform batched fetch - single network operation for all branches */
    string_array_t fetch_arr = { .items = branch_names, .count = fetch_count };
    error_t *err = gitops_fetch_branches(repo, remote_name, &fetch_arr, xfer);
    free(branch_names);

    /* Resolve the ephemeral fetch/progress line. Handles all cases:
     *   - Callback completed: already cleared, harmless no-op
     *   - Mid-progress error: clears partial progress
     *   - Up-to-date: clears "Fetching..." text */
    transfer_progress_resolved(xfer);
    if (ephemeral) {
        output_clear_line(out);
    } else {
        output_newline(out, OUTPUT_NORMAL);
    }

    if (err) {
        /* Classify authoritatively from the transfer outcome rather than matching
         * libgit2's English error strings. Read immediately: the next
         * transfer_op_begin would overwrite last_outcome. */
        const char *err_msg = error_message(err);
        if (transfer_last_outcome(xfer) == TRANSFER_OUTCOME_AUTH_FAILED) {
            output_error(out, "Authentication failed: %s", err_msg);
        } else {
            output_error(out, "Fetch failed: %s", err_msg);
        }
        error_free(err);

        return ERROR(
            ERR_GIT, "Failed to fetch profiles from remote\n"
            "Hint: Check network connectivity and remote accessibility"
        );
    }

    return NULL;
}

/**
 * Phase 2: Analyze branch states for profiles in sync scope
 *
 * Operates on the active set (scope_active), matching sync_fetch_phase: analyze
 * only what the user asked for. results is sized from scope_active(scope)->count
 * by the caller; the two counts agree.
 */
static error_t *sync_analyze_phase(
    git_repository *repo,
    const char *remote_name,
    const scope_t *scope,
    sync_results_t *results,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(scope);
    CHECK_NULL(results);
    CHECK_NULL(out);

    const string_array_t *profiles = scope_active(scope);

    for (size_t i = 0; i < profiles->count; i++) {
        profile_sync_result_t *result = &results->profiles[i];

        result->profile = strdup(profiles->items[i]);
        if (!result->profile) {
            return ERROR(ERR_MEMORY, "Failed to allocate profile name");
        }

        /* Analyze state */
        upstream_info_t info;
        error_t *err = upstream_analyze_profile(
            repo, remote_name, profiles->items[i], &info
        );

        if (err) {
            mark_result_failed(result, err);
            continue;
        }

        result->state = info.state;
        result->ahead = info.ahead;
        result->behind = info.behind;
    }

    return NULL;
}

/**
 * Attempt divergence rollback after resolution failure
 *
 * Returns critical error if rollback itself fails (caller must propagate). Returns
 * NULL and prints informational message on successful rollback.
 */
static error_t *attempt_rollback(
    resolve_context_t *resolve,
    const char *profile,
    const char *failure_reason,
    output_t *out
) {
    error_t *err = resolve_rollback(resolve);
    if (err) {
        output_styled(
            out, OUTPUT_NORMAL,
            "    {red}✗{reset} Critical: Rollback failed: %s\n",
            error_message(err)
        );
        output_newline(out, OUTPUT_NORMAL);
        return error_wrap(
            err, "Failed to rollback branch '%s' after %s.\n"
            "Repository may be in an inconsistent state.\n"
            "Manual intervention required: git reset --hard origin/%s",
            profile, failure_reason, profile
        );
    }

    output_info(out, OUTPUT_NORMAL, "    ↺ Rolled back to original state");

    return NULL;
}

/**
 * Handle UPSTREAM_REMOTE_AHEAD: auto-pull (fast-forward) or warn
 */
static void handle_remote_ahead(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    output_t *out,
    bool auto_pull,
    bool no_pull
) {
    if (!auto_pull) {
        /* Just warn - don't auto-pull */
        output_colored(
            out, OUTPUT_NORMAL, upstream_state_color(result->state),
            "  %s %s: remote has %zu new commit%s\n",
            upstream_state_symbol(result->state),
            result->profile, result->behind, result->behind == 1 ? "" : "s"
        );

        if (no_pull) {
            output_hint(
                out, OUTPUT_NORMAL,
                "    Pull skipped (--no-pull)"
            );
        } else {
            output_hint(
                out, OUTPUT_NORMAL,
                "    Enable 'auto_pull' for automatic pull during sync"
            );
        }
        result->outcome = SYNC_OUTCOME_DIVERGED;
        return;
    }

    /* Auto-pull when safe (fast-forward only) */
    output_info(
        out, OUTPUT_VERBOSE, "  Pulling %s (%zu commit%s behind)...",
        result->profile, result->behind, result->behind == 1 ? "" : "s"
    );

    bool pulled = false;
    error_t *err = pull_branch_ff(repo, remote_name, result->profile, &pulled);
    if (err) {
        output_styled(
            out, OUTPUT_NORMAL,
            "  {red}✗{reset} {red}%s{reset}: pull failed - %s\n",
            result->profile, error_message(err)
        );
        mark_result_failed(result, err);
        return;
    }

    if (!pulled) {
        /* Race: analyze saw REMOTE_AHEAD but FF found nothing new (we caught up
         * between phases). Reclassify to reflect reality so downstream consumers
         * (summary, hooks) see coherent state. */
        result->state = UPSTREAM_UP_TO_DATE;
        result->outcome = SYNC_OUTCOME_UP_TO_DATE;
        output_colored(
            out, OUTPUT_VERBOSE, upstream_state_color(result->state),
            "  %s %s: already up-to-date\n",
            upstream_state_symbol(result->state), result->profile
        );
        return;
    }

    /* Pull succeeded. What the pull did to the view is reported by cmd_sync's
     * manifest block, once, after every profile's Git work. */
    result->outcome = SYNC_OUTCOME_PULLED;
    output_styled(
        out, OUTPUT_NORMAL,
        "  {green}✓{reset} {green}%s{reset}: pulled %zu commit%s\n",
        result->profile, result->behind, result->behind == 1 ? "" : "s"
    );
}

/**
 * Resolve divergence via rebase or merge, then push
 *
 * Unified handler for DIVERGE_REBASE and DIVERGE_MERGE strategies (structurally
 * identical — only the strategy enum and log strings differ).
 *
 * Returns critical error only on rollback failure (caller must propagate). All
 * other failures are recorded in result/results and return NULL.
 */
static error_t *resolve_and_push_divergence(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    output_t *out,
    resolve_strategy_t strategy,
    const char *strategy_name,
    transfer_context_t *xfer,
    bool no_push
) {
    const char *cap_name = (strategy == RESOLVE_STRATEGY_REBASE)
        ? "Rebase" : "Merge";
    const char *past_desc = (strategy == RESOLVE_STRATEGY_REBASE)
        ? "rebased onto remote" : "merged with remote";
    const char *push_desc = (strategy == RESOLVE_STRATEGY_REBASE)
        ? "rebased commits" : "merge commit";

    output_info(
        out, OUTPUT_NORMAL,
        "    Resolving with %s strategy...",
        strategy_name
    );

    /* Initialize divergence context (saves current state for rollback) */
    resolve_context_t resolve;
    error_t *err = resolve_init(
        &resolve, repo, remote_name, result->profile, strategy
    );
    if (err) {
        output_styled(
            out, OUTPUT_NORMAL,
            "    {red}✗{reset} Failed to initialize divergence context: %s\n",
            error_message(err)
        );
        mark_result_failed(result, err);
        return NULL;
    }

    /* Perform in-memory resolution (never modifies HEAD) */
    err = resolve_execute(&resolve, NULL);
    if (err) {
        output_styled(
            out, OUTPUT_NORMAL,
            "    {red}✗{reset} %s failed: %s\n",
            cap_name, error_message(err)
        );
        mark_result_failed(result, err);
        return NULL;
    }

    /* Verify resolution */
    size_t ahead = 0;
    err = resolve_verify(&resolve, &ahead, NULL);
    if (err) {
        output_styled(
            out, OUTPUT_NORMAL,
            "    {red}✗{reset} %s verification failed: %s\n",
            cap_name, error_message(err)
        );
        mark_result_failed(result, err);

        char reason[64];
        snprintf(
            reason, sizeof(reason), "%s verification failure", strategy_name
        );
        return attempt_rollback(&resolve, result->profile, reason, out);
    }

    output_styled(
        out, OUTPUT_NORMAL,
        "    {green}✓{reset} Successfully %s (%zu commit%s to push)\n",
        past_desc, ahead, ahead == 1 ? "" : "s"
    );

    if (no_push) {
        output_info(out, OUTPUT_NORMAL, "    Push skipped (--no-push)");
    } else {
        /* Push resolved commits */
        err = gitops_push_branch(repo, remote_name, result->profile, xfer);
        if (err) {
            output_styled(
                out, OUTPUT_NORMAL,
                "    {red}✗{reset} Push after %s failed: %s\n",
                strategy_name, error_message(err)
            );
            mark_result_failed(result, err);

            output_info(
                out, OUTPUT_NORMAL,
                "    ↺ Rolling back %s (push failed)...",
                strategy_name
            );
            return attempt_rollback(
                &resolve, result->profile, "push failure", out
            );
        }

        output_styled(
            out, OUTPUT_NORMAL,
            "    {green}✓{reset} Pushed %s\n",
            push_desc
        );
    }

    /* Resolved locally even if push was deferred — next sync sees LOCAL_AHEAD. */
    result->outcome = SYNC_OUTCOME_RESOLVED;

    return NULL;
}

/**
 * Handle DIVERGE_OURS: force push local branch to remote
 */
static error_t *handle_diverged_ours(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    output_t *out,
    bool confirm_destructive,
    transfer_context_t *xfer,
    bool no_push
) {
    output_info(out, OUTPUT_NORMAL, "    Resolving with 'ours' strategy (force push)...");

    if (no_push) {
        output_info(out, OUTPUT_NORMAL, "    Force push skipped (--no-push)");
        result->outcome = SYNC_OUTCOME_DIVERGED;
        return NULL;
    }

    /* Get user confirmation for destructive operation */
    if (confirm_destructive) {
        char prompt[DOTTA_MESSAGE_MAX];
        snprintf(
            prompt, sizeof(prompt),
            "Warning: This will force push local '%s' and overwrite remote.\n"
            "Remote commits will be permanently lost. Continue?",
            result->profile
        );
        if (!output_confirm_or_default(out, prompt, false, false)) {
            output_info(out, OUTPUT_NORMAL, "    Operation cancelled by user");
            result->outcome = SYNC_OUTCOME_DIVERGED;
            return NULL;
        }
    }

    /* Force push local to remote (local branch stays unchanged) */
    error_t *err = gitops_force_push_branch(repo, remote_name, result->profile, xfer);
    if (err) {
        output_styled(
            out, OUTPUT_NORMAL,
            "    {red}✗{reset} Force push failed: %s\n",
            error_message(err)
        );
        mark_result_failed(result, err);
        return NULL;
    }

    output_styled(
        out, OUTPUT_NORMAL,
        "    {green}✓{reset} Force pushed to remote (remote commits discarded)\n"
    );
    result->outcome = SYNC_OUTCOME_RESOLVED;

    return NULL;
}

/**
 * Handle DIVERGE_THEIRS: reset local branch to remote
 */
static error_t *handle_diverged_theirs(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    output_t *out,
    bool confirm_destructive
) {
    output_info(
        out, OUTPUT_NORMAL,
        "    Resolving with 'theirs' strategy (reset to remote)..."
    );

    /* Get user confirmation for destructive operation */
    if (confirm_destructive) {
        char prompt[DOTTA_MESSAGE_MAX];
        snprintf(
            prompt, sizeof(prompt),
            "Warning: This will reset '%s' to remote and discard local commits.\n"
            "Local changes will be lost. Continue?", result->profile
        );
        if (!output_confirm_or_default(out, prompt, false, false)) {
            output_info(
                out, OUTPUT_NORMAL, "    Operation cancelled by user"
            );
            result->outcome = SYNC_OUTCOME_DIVERGED;
            return NULL;
        }
    }

    /* Initialize divergence context (saves current state for rollback) */
    resolve_context_t resolve;
    error_t *err = resolve_init(
        &resolve, repo, remote_name, result->profile, RESOLVE_STRATEGY_THEIRS
    );
    if (err) {
        output_styled(
            out, OUTPUT_NORMAL,
            "    {red}✗{reset} Failed to initialize divergence context: %s\n",
            error_message(err)
        );
        mark_result_failed(result, err);
        return NULL;
    }

    /* Resolve divergence (resets local branch to remote) */
    err = resolve_execute(&resolve, NULL);
    if (err) {
        output_styled(
            out, OUTPUT_NORMAL,
            "    {red}✗{reset} Reset failed: %s\n",
            error_message(err)
        );
        mark_result_failed(result, err);
        return NULL;
    }

    /* Verify reset succeeded
     *
     * No rollback on failure — theirs strategy already reset the branch to the
     * desired state. Rolling back would undo what the user requested.
     */
    err = resolve_verify(&resolve, NULL, NULL);
    if (err) {
        output_styled(
            out, OUTPUT_NORMAL,
            "    {red}✗{reset} Reset verification failed: %s\n",
            error_message(err)
        );
        output_styled(
            out, OUTPUT_NORMAL,
            "    {yellow}⚠{reset} Local branch was reset but verification failed\n"
        );
        mark_result_failed(result, err);
        return NULL;
    }

    output_styled(
        out, OUTPUT_NORMAL,
        "    {green}✓{reset} Reset to remote (local commits discarded)\n"
    );
    result->outcome = SYNC_OUTCOME_RESOLVED;

    return NULL;
}

/**
 * Handle UPSTREAM_DIVERGED: dispatch based on configured strategy
 *
 * Returns critical error only on rollback failure (from rebase/merge).
 */
static error_t *handle_diverged(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    output_t *out,
    sync_strategy_t strategy,
    transfer_context_t *xfer,
    bool confirm_destructive,
    bool no_push
) {
    output_styled(
        out, OUTPUT_NORMAL,
        "  {yellow}⚠{reset} {red}%s{reset}: diverged (%zu local, %zu remote commits)\n",
        result->profile, result->ahead, result->behind
    );

    switch (strategy) {
        case DIVERGE_WARN: {
            output_hint(
                out, OUTPUT_NORMAL,
                "    Use --diverged=<strategy> or set diverged_strategy in config"
            );
            output_hintline(
                out, OUTPUT_NORMAL,
                "    Strategies: rebase, merge, ours (keep local), theirs (keep remote)"
            );
            result->outcome = SYNC_OUTCOME_DIVERGED;
            break;
        }

        /* Non-WARN strategies own their outcome inside the inner handler. */
        case DIVERGE_REBASE: {
            return resolve_and_push_divergence(
                repo, remote_name, result, out, RESOLVE_STRATEGY_REBASE,
                "rebase", xfer, no_push
            );
        }

        case DIVERGE_MERGE: {
            return resolve_and_push_divergence(
                repo, remote_name, result, out, RESOLVE_STRATEGY_MERGE,
                "merge", xfer, no_push
            );
        }

        case DIVERGE_OURS: {
            return handle_diverged_ours(
                repo, remote_name, result, out, confirm_destructive,
                xfer, no_push
            );
        }

        case DIVERGE_THEIRS: {
            return handle_diverged_theirs(
                repo, remote_name, result, out, confirm_destructive
            );
        }
    }

    return NULL;
}

/**
 * Phase 3: Sync branches with remote (push/pull/divergence handling)
 *
 * Git only. Every pull, rebase, merge and reset moves a branch HEAD and nothing
 * else; what that did to the view is read off once, for every enabled profile,
 * in cmd_sync's manifest block after this loop returns.
 */
static error_t *sync_push_phase(
    git_repository *repo,
    const char *remote_name,
    sync_results_t *results,
    output_t *out,
    bool ephemeral,
    bool auto_pull,
    bool no_pull,
    bool no_push,
    sync_strategy_t diverged_strategy,
    transfer_context_t *xfer,
    bool confirm_destructive
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(results);
    CHECK_NULL(out);

    if (!ephemeral) {
        output_section(out, OUTPUT_NORMAL, "Syncing with remote");
    }

    for (size_t i = 0; i < results->profile_count; i++) {
        profile_sync_result_t *result = &results->profiles[i];

        /* Skip rows that already failed in analyze phase. */
        if (result->outcome == SYNC_OUTCOME_FAILED) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {red}✗{reset} {red}%s{reset}: %s\n",
                result->profile, error_message(result->error)
            );
            continue;
        }

        /* Handle based on state */
        switch (result->state) {
            case UPSTREAM_UP_TO_DATE: {
                /* outcome remains UP_TO_DATE via calloc-default. */
                output_colored(
                    out, OUTPUT_VERBOSE, upstream_state_color(result->state),
                    "  %s %s: up-to-date\n",
                    upstream_state_symbol(result->state), result->profile
                );
                break;
            }

            case UPSTREAM_LOCAL_AHEAD: {
                /* theirs: discard local commits, reset to remote Blocked by
                 * --no-pull since resetting to remote incorporates remote state */
                if (diverged_strategy == DIVERGE_THEIRS && !no_pull) {
                    output_colored(
                        out, OUTPUT_NORMAL, upstream_state_color(result->state),
                        "  %s %s: %zu commit%s ahead of remote\n",
                        upstream_state_symbol(result->state),
                        result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                    );
                    error_t *err = handle_diverged_theirs(
                        repo, remote_name, result, out, confirm_destructive
                    );
                    if (err) return err;
                    break;
                }

                if (no_push) {
                    output_colored(
                        out, OUTPUT_NORMAL, upstream_state_color(result->state),
                        "  %s %s: %zu commit%s ahead (push skipped: --no-push)\n",
                        upstream_state_symbol(result->state),
                        result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                    );
                    result->outcome = SYNC_OUTCOME_DIVERGED;
                    break;
                }

                /* Safe to push - local has new commits */
                output_info(
                    out, OUTPUT_VERBOSE, "  Pushing %s (%zu commit%s)...",
                    result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                );

                error_t *err = gitops_push_branch(repo, remote_name, result->profile, xfer);
                if (err) {
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  {red}✗{reset} {red}%s{reset}: push failed - %s\n",
                        result->profile, error_message(err)
                    );
                    mark_result_failed(result, err);
                } else {
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  {green}✓{reset} {green}%s{reset}: pushed %zu commit%s\n",
                        result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                    );
                    result->outcome = SYNC_OUTCOME_PUSHED;
                }
                break;
            }

            case UPSTREAM_NO_REMOTE: {
                if (no_push) {
                    output_colored(
                        out, OUTPUT_NORMAL, upstream_state_color(result->state),
                        "  %s %s: local only (push skipped: --no-push)\n",
                        upstream_state_symbol(result->state), result->profile
                    );
                    result->outcome = SYNC_OUTCOME_DIVERGED;
                    break;
                }

                /* Remote branch doesn't exist - create it */
                output_info(
                    out, OUTPUT_VERBOSE,
                    "  Creating remote branch %s...",
                    result->profile
                );

                error_t *err = gitops_push_branch(repo, remote_name, result->profile, xfer);
                if (err) {
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  {red}✗{reset} {red}%s{reset}: failed to create remote branch - %s\n",
                        result->profile, error_message(err)
                    );
                    mark_result_failed(result, err);
                } else {
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  {green}✓{reset} {green}%s{reset}: created remote branch\n",
                        result->profile
                    );
                    result->outcome = SYNC_OUTCOME_PUSHED;
                }
                break;
            }

            case UPSTREAM_REMOTE_AHEAD: {
                /* ours: force push local, discard remote commits */
                if (diverged_strategy == DIVERGE_OURS) {

                    output_colored(
                        out, OUTPUT_NORMAL, upstream_state_color(result->state),
                        "  %s %s: %zu remote commit%s ahead\n",
                        upstream_state_symbol(result->state),
                        result->profile, result->behind, result->behind == 1 ? "" : "s"
                    );
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "    {yellow}⚠{reset} Local is behind — "
                        "force push will overwrite newer remote commits\n"
                    );

                    error_t *err = handle_diverged_ours(
                        repo, remote_name, result, out, confirm_destructive, xfer, no_push
                    );
                    if (err) {
                        return err;
                    }
                    break;
                }
                handle_remote_ahead(
                    repo, remote_name, result, out, auto_pull, no_pull
                );
                break;
            }

            case UPSTREAM_DIVERGED: {
                /* --no-pull blocks strategies that incorporate remote changes */
                if (no_pull && diverged_strategy != DIVERGE_WARN &&
                    diverged_strategy != DIVERGE_OURS) {

                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  {yellow}⚠{reset} {red}%s{reset}: diverged "
                        "(%zu local, %zu remote commits)\n",
                        result->profile, result->ahead, result->behind
                    );
                    const char *name = "?";
                    for (size_t s = 0; s < SYNC_STRATEGY_COUNT; s++) {
                        if (sync_strategies[s].strategy == diverged_strategy) {
                            name = sync_strategies[s].name;
                        }
                    }

                    output_hint(
                        out, OUTPUT_NORMAL,
                        "    '%s' resolution skipped (--no-pull prevents "
                        "incorporating remote changes)", name
                    );
                    result->outcome = SYNC_OUTCOME_DIVERGED;
                    break;
                }
                error_t *err = handle_diverged(
                    repo, remote_name, result, out, diverged_strategy, xfer,
                    confirm_destructive, no_push
                );
                if (err) {
                    return err;  /* Critical rollback failure */
                }
                break;
            }

            case UPSTREAM_UNKNOWN: {
                output_colored(
                    out, OUTPUT_NORMAL, upstream_state_color(result->state),
                    "  %s %s: state unknown\n",
                    upstream_state_symbol(result->state), result->profile
                );
                result->outcome = SYNC_OUTCOME_DIVERGED;
                break;
            }
        }
    }

    return NULL;
}

/**
 * Render dry-run analysis: per-profile state, then closing banner.
 *
 * Glyph and color flow from upstream_state_symbol / upstream_state_color so the
 * visual stays in lockstep with list/status as those maps evolve. Analyze-phase
 * failures use the outcome glyph (✗), not a state glyph.
 */
static void sync_render_dry_run(
    const sync_results_t *results,
    output_t *out
) {
    output_section(out, OUTPUT_NORMAL, "Dry run analysis");

    for (size_t i = 0; i < results->profile_count; i++) {
        const profile_sync_result_t *r = &results->profiles[i];

        if (r->outcome == SYNC_OUTCOME_FAILED) {
            output_styled(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s: %s\n",
                r->profile, error_message(r->error)
            );
            continue;
        }

        const char *glyph = upstream_state_symbol(r->state);
        output_color_t color = upstream_state_color(r->state);

        switch (r->state) {
            case UPSTREAM_UP_TO_DATE:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: up-to-date\n",
                    glyph, r->profile
                );
                break;
            case UPSTREAM_LOCAL_AHEAD:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: %zu commit%s to push\n",
                    glyph, r->profile, r->ahead, r->ahead == 1 ? "" : "s"
                );
                break;
            case UPSTREAM_REMOTE_AHEAD:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: %zu commit%s to pull\n",
                    glyph, r->profile, r->behind, r->behind == 1 ? "" : "s"
                );
                break;
            case UPSTREAM_DIVERGED:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: diverged (%zu local, %zu remote)\n",
                    glyph, r->profile, r->ahead, r->behind
                );
                break;
            case UPSTREAM_NO_REMOTE:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: local only (no remote branch)\n",
                    glyph, r->profile
                );
                break;
            case UPSTREAM_UNKNOWN:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: unknown state\n",
                    glyph, r->profile
                );
                break;
        }
    }

    output_newline(out, OUTPUT_NORMAL);
    output_info(out, OUTPUT_NORMAL, "Dry run: no changes made");
}

/**
 * Render the final sync summary.
 *
 * Tallies per-row outcomes (single source of truth), disambiguates the DIVERGED
 * umbrella by the captured analyze-phase state into needs_pull / needs_push /
 * diverged buckets, then emits the count lines, the session-level transfer stats,
 * and — when apply has work, whether the manifest block just staged, released
 * or reassigned it or the record already disagreed with the view — the "Run apply"
 * hint.
 *
 * The receipt, and only the receipt: every line goes to `out`, and whether sync
 * kept its promise is sync_failure's to say through the return value. The three
 * registers partition the profiles by what the run did with them — ✓ for the
 * buckets it acted on, "Warning:" for the ones it was told to leave alone
 * (--no-push, --no-pull, 'warn' on a divergence), ✗ for the ones it tried and
 * could not. A failure written to stderr from here would leave a redirected sync's
 * receipt reading as a clean success.
 *
 * The summary keeps the finer-grained user vocabulary; hook env (Tier 2) will
 * expose the cleaner outcome partition.
 */
static void sync_render_summary(
    const sync_results_t *results,
    const transfer_context_t *xfer,
    bool manifest_changed,
    bool apply_pending,
    output_t *out
) {
    output_section(out, OUTPUT_NORMAL, "Sync complete");

    size_t pushed = 0, pulled = 0, resolved = 0;
    size_t up_to_date = 0, failed = 0;
    size_t needs_pull = 0, needs_push = 0, diverged = 0;

    for (size_t i = 0; i < results->profile_count; i++) {
        const profile_sync_result_t *r = &results->profiles[i];
        switch (r->outcome) {
            case SYNC_OUTCOME_UP_TO_DATE: up_to_date++; break;
            case SYNC_OUTCOME_PUSHED:     pushed++; break;
            case SYNC_OUTCOME_PULLED:     pulled++; break;
            case SYNC_OUTCOME_RESOLVED:   resolved++; break;
            case SYNC_OUTCOME_FAILED:     failed++; break;
            case SYNC_OUTCOME_DIVERGED:
                switch (r->state) {
                    case UPSTREAM_REMOTE_AHEAD:
                        needs_pull++;
                        break;
                    case UPSTREAM_LOCAL_AHEAD:
                    case UPSTREAM_NO_REMOTE:
                        needs_push++;
                        break;
                    case UPSTREAM_DIVERGED:
                    case UPSTREAM_UNKNOWN:
                    case UPSTREAM_UP_TO_DATE:
                        diverged++;
                        break;
                }
                break;
        }
    }

    if (pushed > 0) {
        output_success(
            out, OUTPUT_NORMAL, "{cyan}%zu{reset} profile%s pushed",
            pushed, pushed == 1 ? "" : "s"
        );
    }
    if (pulled > 0) {
        output_success(
            out, OUTPUT_NORMAL, "{cyan}%zu{reset} profile%s pulled",
            pulled, pulled == 1 ? "" : "s"
        );
    }
    if (resolved > 0) {
        output_success(
            out, OUTPUT_NORMAL, "{cyan}%zu{reset} profile%s resolved",
            resolved, resolved == 1 ? "" : "s"
        );
    }
    if (up_to_date > 0) {
        output_info(
            out, OUTPUT_NORMAL, "{cyan}%zu{reset} profile%s already up-to-date",
            up_to_date, up_to_date == 1 ? "" : "s"
        );
    }
    if (needs_push > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "{cyan}%zu{reset} profile%s need push",
            needs_push, needs_push == 1 ? "" : "s"
        );
    }
    if (needs_pull > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "{cyan}%zu{reset} profile%s need pull",
            needs_pull, needs_pull == 1 ? "" : "s"
        );
    }
    if (diverged > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "{cyan}%zu{reset} profile%s diverged",
            diverged, diverged == 1 ? "" : "s"
        );
    }
    if (failed > 0) {
        output_styled(
            out, OUTPUT_NORMAL, "{red}✗{reset} {cyan}%zu{reset} profile%s failed\n",
            failed, failed == 1 ? "" : "s"
        );
    }

    /* Session-level wire stats (silent if nothing moved) */
    transfer_summarize(xfer, out, OUTPUT_NORMAL);

    /* The hint states a fact about the record, not about this sync. The manifest
     * block is the direct evidence of new work — it is empty exactly when the
     * Git phase touched nothing managed (a pull of README or .dottaignore, a
     * push, 'ours'), which no guess from the outcome tallies could tell apart —
     * and apply_pending is the work that was already there: an earlier sync
     * reviewed with status instead of apply, a scope change, local drift. The
     * block is a delta and prints once; the hint prints for as long as the work
     * stands. */
    if (manifest_changed || apply_pending) {
        output_newline(out, OUTPUT_NORMAL);
        output_hint(
            out, OUTPUT_NORMAL, "Run 'dotta apply' to deploy, or 'dotta status' to review"
        );
    }
}

/**
 * The run's failure, if it had one — the answer cmd_sync returns.
 *
 * A profile the run tried to reconcile and could not (SYNC_OUTCOME_FAILED —
 * whatever the phase: analyze, pull, resolve, push) is a broken promise, and
 * only the return value carries that to the caller. The reason was printed beside
 * the profile it belongs to and the receipt counted it, but a shell reads neither.
 *
 * A profile the run deliberately left alone is not a failure: the caller asked
 * for that (--no-push, --no-pull), the configured strategy did ('warn' on a
 * divergence), or the user declined the prompt. The DIVERGED bucket's warning
 * is that bucket's whole report, and `dotta sync && dotta apply` keeps working
 * for everyone who syncs under 'warn'.
 *
 * Pure, and deliberately so: the per-profile errors stay owned by `results` and
 * are never rethrown, since each was already rendered where it happened. The
 * message carries the one fact the receipt does not — how much of the run the
 * failures were.
 */
static error_t *sync_failure(const sync_results_t *results) {
    size_t failed = 0;
    for (size_t i = 0; i < results->profile_count; i++) {
        if (results->profiles[i].outcome == SYNC_OUTCOME_FAILED) failed++;
    }

    if (failed == 0) {
        return NULL;
    }

    /* The plural agrees with the total, which is the noun it qualifies: "1 of 2
     * profiles failed", "1 of 1 profile failed". */
    return ERROR(
        ERR_GIT, "%zu of %zu profile%s failed to sync",
        failed, results->profile_count,
        results->profile_count == 1 ? "" : "s"
    );
}

/*
 * Render the one unrecoverable cell: the local epoch differs from the remote's
 * canonical epoch and reachable ciphertext (tip or history, any branch) is keyed
 * by the local one. Warn loudly and continue — plaintext profiles still sync.
 */
static void epoch_emit_conflict(output_t *out) {
    output_warning(
        out, OUTPUT_NORMAL,
        "Repository epoch conflict: the local epoch differs from the remote's; "
        "encrypted files pulled by this sync will not decrypt"
    );
    output_hint(
        out, OUTPUT_NORMAL,
        "Re-clone if this machine's encrypted files came from the remote; "
        "otherwise reconcile the independent encryption roots manually"
    );
    output_hint(
        out, OUTPUT_NORMAL,
        "Or delete the profiles whose encrypted content (including history) "
        "you no longer need ('dotta remove <name> --delete-profile'); the "
        "next sync then adopts the remote epoch"
    );
}

/*
 * Apply the CLI gates to epoch_resolve's verdict, render the outcome, and run
 * the chosen git action (establish via epoch_push, adopt via epoch_fetch). The
 * fact-finding already happened in infra/epoch; this layer is pure policy +
 * rendering.
 *
 * Runs before the fetch phase so the decision's census is never contaminated by
 * pulled remote ciphertext. Best-effort: returns NULL on every epoch-level outcome
 * (warn-and-continue); a non-NULL return is reserved for programmer misuse surfaced
 * by the decide call.
 */
static error_t *epoch_reconcile(
    const dotta_ctx_t *ctx,
    const char *remote_name,
    transfer_context_t *xfer,
    const cmd_sync_options_t *opts
) {
    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr;
    output_t *out = ctx->out;

    epoch_reconcile_t decision;
    error_t *err = epoch_resolve(repo, remote_name, xfer, &decision);
    if (err) {
        /* decide errors only on programmer misuse (a NULL argument) — it folds
         * transport failure to UNREACHABLE. Surface the bug rather than swallow
         * it as best-effort. */
        return err;
    }

    switch (decision) {
        case EPOCH_RECONCILE_UNREACHABLE:
            /* The authoritative "remote unreachable" error comes from the fetch
             * phase that runs next. */
            output_info(out, OUTPUT_VERBOSE, "Skipped epoch sync (remote unreachable)");
            return NULL;

        case EPOCH_RECONCILE_EQUAL:
            output_info(out, OUTPUT_VERBOSE, "Repository epoch up to date");
            return NULL;

        case EPOCH_RECONCILE_NO_LOCAL_EPOCH:
            /* Nothing to publish; never claim an establish (the guard). */
            output_info(
                out, OUTPUT_VERBOSE,
                "No local repository epoch to establish (run 'dotta init')"
            );
            return NULL;

        case EPOCH_RECONCILE_ESTABLISH: {
            /* Establish is push-shaped: gate on --no-push. */
            if (opts->no_push) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Remote has no repository epoch; establish skipped"
                );
                return NULL;
            }
            if (opts->dry_run) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Would establish repository epoch on remote"
                );
                return NULL;
            }
            err = epoch_push(repo, remote_name, xfer);
            if (err) {
                output_warning(
                    out, OUTPUT_NORMAL,
                    "Failed to establish repository epoch on remote: %s",
                    error_message(err)
                );
                error_free(err);
                return NULL;  /* best-effort; retried next sync */
            }
            output_success(
                out, OUTPUT_VERBOSE,
                "Established repository epoch on remote"
            );
            return NULL;
        }

        case EPOCH_RECONCILE_CONFLICT:
            epoch_emit_conflict(out);
            return NULL;  /* warn-and-continue; no git op */

        case EPOCH_RECONCILE_ADOPT: {
            /* Adopt is pull-shaped: gate on --no-pull. */
            if (opts->no_pull) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Remote repository epoch differs; adopt skipped"
                );
                return NULL;
            }
            if (opts->dry_run) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Would adopt repository epoch from remote"
                );
                return NULL;
            }
            kdf_epoch_t adopted;
            err = epoch_fetch(repo, remote_name, xfer, &adopted);
            if (err) {
                /* A malformed remote epoch: epoch_fetch judged the bytes before
                 * installing them, so the local epoch still stands, and its message
                 * names the blob that is wrong — printed whole, as clone prints
                 * it. Anything else is the fetch's own failure under one line
                 * of context. */
                output_warning(
                    out, OUTPUT_NORMAL, err->code == ERR_CRYPTO ? "%s"
                    : "Failed to adopt repository epoch from remote: %s",
                    error_message(err)
                );
                error_free(err);
                return NULL;  /* best-effort */
            }
            output_success(
                out, OUTPUT_VERBOSE,
                "Adopted repository epoch from remote (no local ciphertext "
                "depended on the replaced one)"
            );
            /* The run's crypto handles were bound to the epoch at dispatch; the
             * adopt moved that authority mid-command, so re-bind — the same duty
             * sync discharges for Git by rebuilding the manifest after the pulls.
             * NULL-safe for encryption-disabled runs. What the old epoch's session
             * file holds is not this run's to remove: the file is named by the
             * epoch, and a checkout still on that epoch is the one entitled to
             * read it. */
            keymgr_rekey(keymgr, &adopted);
            return NULL;
        }
    }

    return NULL;  /* unreachable: decide returns one of six decisions */
}

/**
 * Sync command implementation
 */
error_t *cmd_sync(const dotta_ctx_t *ctx, const cmd_sync_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const char *repo_path = ctx->run.repo_path;
    state_t *state = ctx->run.state;
    const mount_table_t *mounts = ctx->run.mounts;
    content_cache_t *content_cache = ctx->run.content_cache;
    const manifest_t *before = ctx->run.manifest;  /* The view ahead of the Git phase: the dispatcher's */
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Declare all resources, initialized to NULL. */
    error_t *err = NULL;
    workspace_t *ws = NULL;
    manifest_t *after = NULL;                  /* The view after the Git phase (owned) */
    scope_t *scope = NULL;
    sync_results_t *results = NULL;
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    transfer_context_t *xfer = NULL;
    char *current_branch = NULL;
    char *profiles_str = NULL;
    char *remote_env = NULL;

    /* Verify main worktree is on dotta-worktree branch */
    err = gitops_current_branch(repo, &current_branch);
    if (err) {
        err = error_wrap(err, "Failed to get current branch");
        goto cleanup;
    }

    if (strcmp(current_branch, "dotta-worktree") != 0) {
        /* Create error before freeing current_branch to avoid use-after-free */
        err = ERROR(
            ERR_STATE_INVALID,
            "Main worktree must be on 'dotta-worktree' branch (currently on '%s')\n"
            "Hint: Run 'dotta git checkout dotta-worktree' to fix", current_branch
        );
        goto cleanup;
    }
    free(current_branch);
    current_branch = NULL;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Build operation scope
     *
     *   scope_enabled — the persistent enabled set, the CLI filter's bound and
     *                   the Manifest block's attribution.
     *   scope_active  — sync operation face (fetch / analyze / pull targets).
     */
    scope_inputs_t scope_inputs = {
        .profiles      = opts->profiles,
        .profile_count = opts->profile_count,
    };
    err = scope_build(
        repo, state, &scope_inputs, config, mounts, ctx->arena, &scope
    );
    if (err) goto cleanup;

    if (scope_enabled(scope)->count == 0) {
        err = ERROR(
            ERR_NOT_FOUND, "No enabled profiles to sync\n"
            "Hint: Run 'dotta profile enable <name>' to enable profiles\n"
            "      Or run 'dotta profile list --all' to see available profiles"
        );
        goto cleanup;
    }

    /* Create results tracker */
    results = sync_results_create(scope_active(scope)->count);
    if (!results) {
        err = ERROR(ERR_MEMORY, "Failed to create results");
        goto cleanup;
    }

    /* Auto-detect remote early — fail fast before expensive workspace load. URL
     * is resolved alongside the name; the credential helper consumes it when
     * transfer_context_create runs further down. */
    err = gitops_resolve_default_remote(
        repo, ctx->arena, &remote_name, &remote_url
    );
    if (err) {
        goto cleanup;
    }

    /* Validate workspace - sync requires clean workspace (no uncommitted changes)
     *
     * Skip entirely when --force is used: the clean check result is unused, and
     * workspace_load can be expensive (filesystem analysis, directory scanning).
     * Either way the view ahead of the Git phase is `before` — the dispatcher's,
     * which the workspace joins in the non-forced arm and which --force reads
     * as it is, no disk involved. The block after the Git phase diffs it against
     * the view the pulls produced.
     */
    if (!opts->force) {
        /* Both kinds are observed: one lstat per directory row, and the guard
         * below reads a tracked directory's divergence off the same route table
         * as a file's — a load that routes items must never read NULL over a
         * squatter (workspace_load_t). Orphans stay off — a Git probe per profile
         * for items only the settle (apply's cleanup) and status's Issues read;
         * the guard counts the view's rows, and the block after the Git phase
         * diffs two views. */
        workspace_load_t ws_opts = {
            .analyze_files       = true,   /* Validate file state for uncommitted changes */
            .analyze_orphans     = false,
            .analyze_untracked   = config->auto_detect_new_files, /* Respect config */
            .analyze_directories = true    /* The guard reads directory rows too */
        };
        err = workspace_load(
            repo, state, config, content_cache, before, &ws_opts, ctx->arena, &ws
        );
        if (err) {
            err = error_wrap(err, "Failed to load workspace");
            goto cleanup;
        }

        /* Persist the observations and slow-path CMP_EQUAL confirmations
         * (self-healing optimization). Seeds the fast path for subsequent
         * status/apply calls. Non-fatal on failure — sync's workspace validation
         * still works correctly. */
        error_t *flush_err = workspace_flush_updates(ws);
        if (flush_err) {
            error_free(flush_err);
        }

        /* Count what stands between this workspace and a clean sync, in the scope
         * the run names: a pull of the named profiles moves nothing of the others',
         * so their divergence is neither at risk nor this run's to send to update
         * (scope_accepts_profile — the filter status's sections apply). The
         * deployed partition is read off the one route table (workspace_item_route
         * — the same table status's sections and update's filter read, so sync
         * cannot route an item a third way), the other states by the state switch
         * beside it. One item, one count. */
        workspace_items_t all_diverged = workspace_get_all_diverged(ws);

        /* The rule the arms below follow: sync blocks on update's work and on
         * the conflicts update refuses and the user must decide; it reports,
         * and never blocks on, what no verb takes by default and what one named
         * verb resolves. A squatted tracked directory is a decision (--force,
         * add --force, remove) and blocks; a squatted rung dotta only passes
         * through has one verb and no decision — the same fact that gives it
         * its own status section — and blocks nothing; and a child observed through
         * either is not an edit a pull can conflict with, so it blocks nothing
         * either. */
        size_t uncommitted_count = 0; /* CAPTURE — update's to commit */
        size_t conflict_count = 0;    /* CONFLICT ∪ KIND — status's Conflicts: no default verb */
        size_t deleted_count = 0;     /* DELETED state — update's to commit */
        size_t untracked_count = 0;   /* UNTRACKED state — update --include-new's */
        size_t unverified_count = 0;  /* UNVERIFIABLE — dotta could not look; blocks nothing */
        size_t squatted_count = 0;    /* KIND_DERIVED — a rung dotta only passes through; blocks nothing */
        size_t displaced_count = 0;   /* DISPLACED_* — seen through a squatter; blocks nothing */

        for (size_t i = 0; i < all_diverged.count; i++) {
            const workspace_item_t *item = all_diverged.entries[i];

            if (!scope_accepts_profile(scope, item->profile)) {
                continue;
            }

            switch (item->state) {
                case WORKSPACE_STATE_DEPLOYED:
                    switch (workspace_item_route(item)) {
                        case WORKSPACE_ROUTE_DISPLACED_TRACKED:
                        case WORKSPACE_ROUTE_DISPLACED_DERIVED:
                            /* Observed through a squatter: the bits were read
                             * off the squatter's target, so there is no local
                             * edit here for a pull to conflict with — the
                             * squatter's own row is the work, and it is counted
                             * under its own arm. Counted to be reported, never
                             * to block. */
                            displaced_count++;
                            break;

                        case WORKSPACE_ROUTE_UNVERIFIABLE:
                            /* No committable work by definition — the guard is
                             * about local edits a pull would turn into conflicts,
                             * and a path dotta could not read has none to commit.
                             * Counted to be reported, never to block. */
                            unverified_count++;
                            break;

                        case WORKSPACE_ROUTE_CONFLICT:
                        case WORKSPACE_ROUTE_KIND:
                            /* Neither verb's by default (status's Conflicts):
                             * both sides moved, or a kind the copy cannot commit.
                             * update refuses these, so the hints below must not
                             * send them there. */
                            conflict_count++;
                            break;

                        case WORKSPACE_ROUTE_KIND_DERIVED:
                            /* A different kind stands at a directory dotta only
                             * passes through: never planned, so nothing beneath
                             * it is dotta's to lose to a pull, and one named
                             * verb resolves it ('dotta update <dir>'). Counted
                             * to be reported, never to block. */
                            squatted_count++;
                            break;

                        case WORKSPACE_ROUTE_CAPTURE:
                            /* update's work — every capturable divergence family,
                             * ownership and encryption included: a policy-violating
                             * blob is uncommitted work exactly here, where a
                             * push would publish it. */
                            uncommitted_count++;
                            break;

                        case WORKSPACE_ROUTE_STALE:
                        case WORKSPACE_ROUTE_REASSIGNED:
                        case WORKSPACE_ROUTE_CLEAN:
                            /* Apply's side or nothing: Git moved past the deployed
                             * blob and disk did not — a mode rider included —
                             * or a pending handover. No local work a pull puts
                             * at risk. */
                            break;
                    }
                    break;

                case WORKSPACE_STATE_DELETED:
                    deleted_count++;
                    break;

                case WORKSPACE_STATE_UNTRACKED:
                    untracked_count++;
                    break;

                case WORKSPACE_STATE_UNDEPLOYED:
                case WORKSPACE_STATE_ORPHANED:
                case WORKSPACE_STATE_RELEASED:
                    /* Not sync's concern — handled by apply command. RELEASED
                     * is never emitted here anyway: it comes only from orphan
                     * analysis, which this load switches off. */
                    break;
            }
        }

        size_t blocking_count = uncommitted_count + conflict_count +
            deleted_count + untracked_count;

        if (blocking_count > 0) {
            if (config->strict_mode) {
                /* Strict mode: Block with full diagnostic output. The lines carry
                 * status's section vocabulary — one item, one line — and the
                 * unverifiable count rides along as an advisory so the paths
                 * the analysis could not settle are never silent. */
                output_section(out, OUTPUT_NORMAL, "Workspace has uncommitted changes");
                output_newline(out, OUTPUT_NORMAL);

                if (uncommitted_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu uncommitted change%s",
                        uncommitted_count, uncommitted_count == 1 ? "" : "s"
                    );
                }
                if (conflict_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu conflict%s",
                        conflict_count, conflict_count == 1 ? "" : "s"
                    );
                }
                if (deleted_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu deleted path%s",
                        deleted_count, deleted_count == 1 ? "" : "s"
                    );
                }
                if (untracked_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu new untracked file%s",
                        untracked_count, untracked_count == 1 ? "" : "s"
                    );
                }
                if (unverified_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu unverifiable path%s",
                        unverified_count, unverified_count == 1 ? "" : "s"
                    );
                }
                if (squatted_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu squatted ancestor%s",
                        squatted_count, squatted_count == 1 ? "" : "s"
                    );
                }
                if (displaced_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu displaced path%s",
                        displaced_count, displaced_count == 1 ? "" : "s"
                    );
                }

                output_newline(out, OUTPUT_NORMAL);
                output_info(out, OUTPUT_NORMAL, "Sync requires a clean workspace.");
                output_newline(out, OUTPUT_NORMAL);
                output_hintline(out, OUTPUT_NORMAL, "Next steps:");
                if (conflict_count > 0) {
                    output_hintline(
                        out, OUTPUT_NORMAL,
                        "  Conflicts:      dotta diff, apply --force, add --force, or remove"
                    );
                }
                if (uncommitted_count + deleted_count > 0) {
                    output_hintline(out, OUTPUT_NORMAL, "  Commit changes: dotta update");
                }
                if (untracked_count > 0) {
                    output_hintline(
                        out, OUTPUT_NORMAL,
                        "  New files:      dotta update --include-new"
                    );
                }
                output_hintline(out, OUTPUT_NORMAL, "  Synchronize:    dotta sync");
                output_hintline(out, OUTPUT_NORMAL, "  Or bypass with: dotta sync --force");

                err = ERROR(
                    ERR_VALIDATION,
                    "Cannot sync with uncommitted changes (found %zu uncommitted item%s)",
                    blocking_count, blocking_count == 1 ? "" : "s"
                );
                goto cleanup;
            }

            /* Non-strict mode: Warn and require user confirmation
             *
             * The risk: syncing before committing local changes can turn them
             * into conflicts. If the pull moves a file the user edited, the edit
             * becomes [modified] [stale] — update will not commit over Git's
             * newer content, and no verb takes it by default: the user decides
             * (the cancel hint below names the two flags that do).
             *
             * Safe workflow: update → sync → resolve any divergence explicitly
             */
            output_warning(
                out, OUTPUT_NORMAL, "Workspace has %zu uncommitted change%s",
                blocking_count, blocking_count == 1 ? "" : "s"
            );

            /* Show breakdown in verbose mode */
            if (uncommitted_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu uncommitted", uncommitted_count);
            }
            if (conflict_count > 0) {
                output_info(
                    out, OUTPUT_VERBOSE, "  %zu conflict%s",
                    conflict_count, conflict_count == 1 ? "" : "s"
                );
            }
            if (deleted_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu deleted", deleted_count);
            }
            if (untracked_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu untracked", untracked_count);
            }
            if (unverified_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu unverifiable", unverified_count);
            }
            if (squatted_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu squatted", squatted_count);
            }
            if (displaced_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu displaced", displaced_count);
            }

            output_info(out, OUTPUT_NORMAL, "Syncing before 'update' may lead to conflicts.");
            output_newline(out, OUTPUT_NORMAL);

            /* Confirmation with safe defaults:
             * - Interactive: defaults to NO (user must explicitly type 'y')
             * - Non-interactive (CI/CD): refuses automatically
             */
            if (!output_confirm_or_default(out, "Continue anyway?", false, false)) {
                output_info(out, OUTPUT_NORMAL, "Sync cancelled");
                if (conflict_count > 0) {
                    output_hint(
                        out, OUTPUT_NORMAL,
                        "Resolve conflicts first: 'dotta diff' shows both sides; "
                        "'dotta apply --force' keeps Git's, 'dotta add --force' keeps "
                        "disk's, 'dotta remove' untracks; 'dotta update' commits the rest"
                    );
                } else {
                    output_hint(
                        out, OUTPUT_NORMAL,
                        "Run 'dotta update' first to commit local changes"
                    );
                }
                err = NULL;  /* User cancelled - clean exit, not an error */
                goto cleanup;
            }

            /* User confirmed - proceed with sync */
            output_info(out, OUTPUT_VERBOSE, "Proceeding with uncommitted changes");
            output_newline(out, OUTPUT_NORMAL);
        } else {
            /* Nothing blocks, but not every path is settled: say so and proceed.
             * Silence here once hid real divergence — the one route the old fold
             * never counted. A path the analysis could not read no verb resolves;
             * the user must look (status's Unverifiable section carries the way
             * out). A squatted rung dotta only passes through has its one verb,
             * and status's own section names it; a path observed through a squatter
             * waits on the squatter, and status lists both. */
            if (unverified_count > 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Note: %zu path%s could not be verified ('dotta status' lists %s)",
                    unverified_count, unverified_count == 1 ? "" : "s",
                    unverified_count == 1 ? "it" : "them"
                );
            }
            if (squatted_count > 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Note: %zu squatted ancestor%s — a different kind stands at a "
                    "directory dotta only passes through ('dotta status' lists %s)",
                    squatted_count, squatted_count == 1 ? "" : "s",
                    squatted_count == 1 ? "it" : "them"
                );
            }
            if (displaced_count > 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Note: %zu path%s observed through a squatted directory "
                    "('dotta status' lists %s)",
                    displaced_count, displaced_count == 1 ? "" : "s",
                    displaced_count == 1 ? "it" : "them"
                );
            }
        }
    }

    /* Build the hook invocation. Same struct is reused for both pre-sync (here)
     * and post-sync (after the manifest block). profiles_str / remote_env are
     * heap-allocated and freed at cleanup; sync_extras is a stack literal whose
     * lifetime is cmd_sync's frame — covers both fire sites. */
    profiles_str = string_array_join(scope_active(scope), " ");
    if (!profiles_str) {
        err = ERROR(ERR_MEMORY, "Failed to join profile names for hook env");
        goto cleanup;
    }

    remote_env = str_format("DOTTA_REMOTE=%s", remote_name);
    if (!remote_env) {
        err = ERROR(ERR_MEMORY, "Failed to build DOTTA_REMOTE for hook env");
        goto cleanup;
    }

    char *const sync_extras[] = { remote_env, NULL };
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_SYNC,
        .profile    = profiles_str,
        .files      = NULL,
        .file_count = 0,
        .extras     = sync_extras,
        .dry_run    = opts->dry_run,
    };

    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /* Create transfer context for progress reporting. URL was resolved alongside
     * the remote name above; it feeds the credential helper here */
    transfer_options_t xfer_opts = {
        .output             = out,
        .url                = remote_url,
        .ephemeral_progress = true,
    };
    err = transfer_context_create(&xfer_opts, &xfer);
    if (err) goto cleanup;

    /* Determine auto_pull setting: CLI --no-pull overrides config */
    bool auto_pull = opts->no_pull ? false : config->auto_pull;

    /* Determine divergence strategy: CLI overrides config */
    const char *strategy = opts->diverged ? opts->diverged : config->diverged_strategy;
    sync_strategy_t diverged_strategy;
    if (!parse_divergence_strategy(strategy, &diverged_strategy)) {
        err = ERROR(
            ERR_INVALID_ARG, "Invalid divergence strategy '%s' "
            "(valid: warn, rebase, merge, ours, theirs)", strategy
        );
        goto cleanup;
    }

    /* Reconcile the repository epoch with the remote. Placed before the fetch
     * phase so the in-use census cannot see pulled remote ciphertext. */
    err = epoch_reconcile(ctx, remote_name, xfer, opts);
    if (err) {
        goto cleanup;
    }

    /* Phase 1: Fetch profiles in sync scope from remote */
    err = sync_fetch_phase(
        repo, remote_name, scope, results, out, xfer
    );
    if (err) {
        goto cleanup;
    }

    /* Phase 2: Analyze branch states */
    err = sync_analyze_phase(
        repo, remote_name, scope, results, out
    );
    if (err) {
        goto cleanup;
    }

    /* Dry run: display analysis and exit without executing push/pull. The answer
     * still stands — a profile the analysis could not read is a question the
     * dry run failed to answer, not a profile it found no work for. */
    if (opts->dry_run) {
        sync_render_dry_run(results, out);
        err = sync_failure(results);
        goto cleanup;
    }

    /* Phase 3: Sync with remote (push/pull/divergence handling)
     *
     * Git only — no state is written in this phase, so the write lock is never
     * held across network IO. Nothing catches up afterwards either: the view is
     * computed, and the block that follows only reports what the phase did to it.
     *
     * When all profiles are up-to-date and not in verbose mode, the sync section
     * is ephemeral — shown as progress during execution, cleared after. This
     * avoids noise when there's nothing actionable to report. */
    bool no_push = opts->no_push;
    bool all_quiet = true;
    for (size_t i = 0; i < results->profile_count; i++) {
        const profile_sync_result_t *r = &results->profiles[i];
        if (r->outcome != SYNC_OUTCOME_UP_TO_DATE ||
            r->state != UPSTREAM_UP_TO_DATE) {
            all_quiet = false;
            break;
        }
    }
    bool sync_ephemeral = !output_is_verbose(out) && all_quiet;

    if (sync_ephemeral) {
        output_print(out, OUTPUT_NORMAL, "Syncing with remote...");
        fflush(out->stream);
    }

    err = sync_push_phase(
        repo, remote_name, results, out, sync_ephemeral, auto_pull, opts->no_pull,
        no_push, diverged_strategy, xfer, config->confirm_destructive
    );

    if (sync_ephemeral) {
        output_clear_line(out);
    }

    if (err) {
        goto cleanup;
    }

    /* Manifest block — the view after the Git phase, diffed against the view
     * before it. A true delta in both modes: a local external commit that predates
     * the sync is in `before` and `after` alike and is
     * reported by its results (status's [stale], [released]), not here;
     * what the block names is what the pulls and resolutions above did to the
     * view. Sync writes no state.
     *
     * Attribution is per enabled profile — scope_enabled, never the -p narrowed
     * scope_active: precedence runs across the whole enabled set, which is what
     * both views are built over (the state's rows, untouched since dispatch —
     * nothing in sync mutates enabled_profiles; a missing branch contributes
     * nothing to either and was warned about at scope_build time). A path p lost
     * to q is p's reassignment and q's claim; a path that moved between two pulled
     * profiles is one reassignment, never a transient release.
     *
     * Sync does not deploy. Apply's divergence analysis does that, which is what
     * the summary's hint points at.
     *
     * A failed build is not sync's failure — every Git ref already moved and
     * stands — and its message carries the repair (a tree that will not load,
     * metadata that will not parse): warn with it and carry on. A pulled custom/
     * claim this machine cannot place does not fail the build; the health notice
     * after the block is its signal. */
    const string_array_t *enabled = scope_enabled(scope);
    bool manifest_changed = false;    /* The block printed: the Git phase moved something managed */
    bool apply_pending = false;       /* The record disagrees with the view, whenever that began */

    err = manifest_build(repo, state, ctx->arena, &after);
    if (err) {
        output_warning(
            out, OUTPUT_NORMAL, "Manifest build failed: %s", error_message(err)
        );
        error_free(err);
        err = NULL;
    } else {
        anchor_t *anchors = NULL;
        size_t anchor_count = 0;
        err = state_get_all_anchors(state, ctx->arena, &anchors, &anchor_count);
        if (err) {
            err = error_wrap(err, "Failed to read anchors");
            goto cleanup;
        }

        manifest_diff_stats_t *stats = arena_calloc(
            ctx->arena, enabled->count, sizeof(*stats)
        );
        if (!stats) {
            err = ERROR(ERR_MEMORY, "Failed to allocate manifest statistics");
            goto cleanup;
        }

        err = manifest_diff(before, after, anchors, anchor_count, enabled, stats);
        if (err) {
            err = error_wrap(err, "Failed to diff manifest across sync");
            goto cleanup;
        }

        for (size_t i = 0; i < enabled->count; i++) {
            const manifest_diff_stats_t *s = &stats[i];
            size_t staged = s->added + s->updated;

            /* A departure here is a Git-side removal, so every orphan it leaves
             * is one apply releases (the record retires, the copy stays); a
             * departure with no record has no filesystem effect and asks nothing
             * of the user, so it is not counted. */
            size_t released = s->orphans.owned + s->orphans.observed;

            if (staged + released + s->reassigned == 0) continue;

            if (!manifest_changed) {
                output_section(out, OUTPUT_NORMAL, "Manifest");
                manifest_changed = true;
            }

            /* One line per profile, non-zero parts only. */
            output_print(out, OUTPUT_NORMAL, "  %s:", s->profile);
            const char *sep = " ";
            if (staged > 0) {
                output_print(out, OUTPUT_NORMAL, "%s%zu staged", sep, staged);
                sep = ", ";
            }
            if (released > 0) {
                output_print(out, OUTPUT_NORMAL, "%s%zu released", sep, released);
                sep = ", ";
            }
            if (s->reassigned > 0) {
                output_print(
                    out, OUTPUT_NORMAL, "%s%zu reassigned", sep, s->reassigned
                );
            }
            output_print(out, OUTPUT_NORMAL, "\n");
        }

        /* The import's health: claims the branches carry that this machine cannot
         * place (their profile has no deployment target here). The block above
         * cannot say it — an unbound claim is in neither view's rows — so this
         * notice is the import moment's only signal. */
        manifest_unbound_t unbound = manifest_unbound(after);
        const char *unbound_profile = NULL;
        for (size_t i = 0; i < unbound.count;) {
            const char *profile = unbound.entries[i].profile;
            size_t n = 0;
            while (i + n < unbound.count &&
                strcmp(unbound.entries[i + n].profile, profile) == 0) n++;
            output_warning(
                out, OUTPUT_NORMAL,
                "Profile '%s': %zu custom/ path%s need%s a deployment target",
                profile, n, n == 1 ? "" : "s", n == 1 ? "s" : ""
            );
            if (!unbound_profile) unbound_profile = profile;
            i += n;
        }
        if (unbound_profile) {
            output_hint(
                out, OUTPUT_NORMAL,
                "Run 'dotta profile enable %s --target /path' to set the target",
                unbound_profile
            );
        }

        /* The hint's standing half: what the record already disagreed with the
         * view about, whichever sync or scope change left it there. Read off
         * the view the Git phase produced and the two facts anchor_t's doc states,
         * no disk and no second workspace load: a record whose path the view
         * lacks is an orphan apply prunes, releases or reclaims; a record whose
         * confirmed kind and content are not the row's is stale, or was never
         * confirmed; an owned file record under another profile is a reassignment
         * apply has not acknowledged (a directory's record keeps whoever made
         * it — reassignment is a file's fact, derived in the file analyzer and
         * acknowledged over files.clean); and a row with no record is undeployed,
         * or was never observed. Mode, owner and group are claims the record
         * copies, not facts it confirms, and say nothing here: a pulled metadata
         * change is the block's to report, once.
         *
         * The record's paths are unique and so are the view's, so the records
         * that found a row count the rows that have one. */
        size_t recorded = 0;
        for (size_t i = 0; i < anchor_count; i++) {
            const anchor_t *anchor = &anchors[i];
            const manifest_row_t *row = manifest_lookup(after, anchor->filesystem_path);

            if (!row) {
                apply_pending = true;
                continue;
            }
            recorded++;

            if (anchor->type != row->type ||
                !git_oid_equal(&anchor->blob_oid, &row->blob_oid)) {
                apply_pending = true;
            } else if (row->type != PATH_TYPE_DIRECTORY && anchor->deployed_at > 0 &&
                strcmp(anchor->profile, row->profile) != 0) {
                apply_pending = true;
            }
        }
        if (recorded < manifest_rows(after).count) {
            apply_pending = true;
        }
    }

    /* Post-sync fires once the Git phase and the manifest block are done; a failed
     * build was warned above and is not a reason to skip it. Nor is a profile
     * that failed: the pushes and pulls that did land are real, and the hook's
     * subject is the world sync leaves behind, not what sync returns. */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* Final summary */
    sync_render_summary(results, xfer, manifest_changed, apply_pending, out);

    /* The receipt is printed; the return value is what the caller reads. */
    err = sync_failure(results);

cleanup:
    /* Free resources in reverse order of allocation. state is borrowed from the
     * dispatcher and sync opens no transaction of its own (the flush scopes its
     * own; nothing else writes). `before` is the dispatcher's view — not freed
     * here. */
    if (current_branch) free(current_branch);
    manifest_free(after);
    if (ws) workspace_free(ws);
    if (xfer) transfer_context_free(xfer);
    if (results) sync_results_free(results);
    if (scope) scope_free(scope);
    if (profiles_str) free(profiles_str);
    if (remote_env) free(remote_env);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * What can stand at the cursor: an enabled profile, by -p or bare; for --diverged,
 * a strategy.
 */
static args_want_t sync_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) opts_v;
    const dotta_ctx_t *ctx = ctx_v;

    if (ARGS_VALUE_IS(at, cmd_sync_options_t, diverged)) {
        for (size_t i = 0; i < SYNC_STRATEGY_COUNT; i++) {
            fprintf(
                out, "%s\t%s\n",
                sync_strategies[i].name, sync_strategies[i].summary
            );
        }
        return ARGS_WANT_NONE;
    }

    completion_profiles(ctx, out, COMPLETION_ENABLED);
    return ARGS_WANT_NONE;
}

static error_t *sync_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_sync(ctx, (const cmd_sync_options_t *) opts_v);
}

static const args_opt_t sync_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_APPEND(
        "p profile",       "<name>",
        cmd_sync_options_t,profiles,     profile_count,
        "Filter sync to profile(s) (repeatable)"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_sync_options_t,dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG(
        "no-push",
        cmd_sync_options_t,no_push,
        "Fetch and analyze only; skip push"
    ),
    ARGS_FLAG(
        "no-pull",
        cmd_sync_options_t,no_pull,
        "Push only; skip pull"
    ),
    ARGS_FLAG(
        "f force",
        cmd_sync_options_t,force,
        "Sync even with uncommitted local changes"
    ),
    ARGS_STRING(
        "diverged",        "<strategy>",
        cmd_sync_options_t,diverged,
        "Diverged-branch strategy (see notes)"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_sync_options_t,verbose,
        "Verbose output"
    ),
    /* Bare profile positionals funnel into the same APPEND field. */
    ARGS_POSITIONAL_ANY(
        cmd_sync_options_t,profiles,     profile_count
    ),
    ARGS_END,
};

const args_command_t spec_sync = {
    .name         = "sync",
    .summary      = "Synchronize profiles with remote repository",
    .usage        = "%s sync [options] [profile]...",
    .description  =
        "Fetch, analyze, and reconcile enabled profiles with their\n"
        "remote counterparts. Requires a clean workspace; run '%s\n"
        "update' to commit pending filesystem changes first.\n",
    .notes        =
        "Diverged Strategies:\n"
        "  warn          Report and stop (default).\n"
        "  rebase        Replay local commits atop remote.\n"
        "  merge         Create a merge commit.\n"
        "  ours          Keep local side; overwrite remote on push.\n"
        "  theirs        Keep remote side; drop local commits.\n",
    .examples     =
        "  %s sync                    # All enabled profiles\n"
        "  %s sync global             # Single profile\n"
        "  %s sync global darwin      # Multiple profiles\n"
        "  %s sync -n                 # Preview without writing\n"
        "  %s sync -f                 # Bypass clean-workspace check\n"
        "  %s sync --no-pull          # Push only\n"
        "  %s sync --diverged rebase  # Override divergence strategy\n",
    .epilogue     =
        "See also:\n"
        "  %s update          # Commit local changes first\n"
        "  %s status --remote # Inspect remote state before syncing\n",
    .opts_size    = sizeof(cmd_sync_options_t),
    .opts         = sync_opts,
    .complete     = sync_complete,
    .payload      = &(const dotta_needs_t){
        .repo     = DOTTA_REPO_OPEN,
        .state    = DOTTA_STATE_READ,
        .mounts   = true,
        .crypto   = DOTTA_CRYPTO_CACHED,
        .manifest = true,
    },
    .dispatch     = sync_dispatch,
};
