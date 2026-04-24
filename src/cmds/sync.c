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

#include "base/args.h"
#include "base/error.h"
#include "base/output.h"
#include "core/manifest.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "sys/gitops.h"
#include "sys/resolve.h"
#include "sys/transfer.h"
#include "sys/upstream.h"

/**
 * Per-profile sync result
 */
typedef struct {
    char *profile;
    sync_branch_state_t state;
    size_t ahead;
    size_t behind;
    bool pushed;
    bool failed;
    char *error_message;
} profile_sync_result_t;

/**
 * Overall sync results
 */
typedef struct {
    profile_sync_result_t *profiles;
    size_t count;
    size_t pushed_count;
    size_t need_pull_count;
    size_t diverged_count;
    size_t up_to_date_count;
    size_t pulled_count;             /* Profiles updated from remote (pull/resolve/reset) */
    size_t failed_count;
    size_t fetch_failed_count;       /* Track fetch failures separately */
    size_t auth_failed_count;        /* Track authentication failures */
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

    results->count = profile_count;
    return results;
}

/**
 * Free sync results
 */
static void sync_results_free(sync_results_t *results) {
    if (!results) {
        return;
    }

    for (size_t i = 0; i < results->count; i++) {
        free(results->profiles[i].profile);
        free(results->profiles[i].error_message);
    }

    free(results->profiles);
    free(results);
}

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

    if (strcmp(str, "warn") == 0) {
        *out_strategy = DIVERGE_WARN;
        return true;
    }
    if (strcmp(str, "rebase") == 0) {
        *out_strategy = DIVERGE_REBASE;
        return true;
    }
    if (strcmp(str, "merge") == 0) {
        *out_strategy = DIVERGE_MERGE;
        return true;
    }
    if (strcmp(str, "ours") == 0) {
        *out_strategy = DIVERGE_OURS;
        return true;
    }
    if (strcmp(str, "theirs") == 0) {
        *out_strategy = DIVERGE_THEIRS;
        return true;
    }

    return false;
}

/**
 * Pull branch with fast-forward only
 * Returns true if branch was updated, and optionally returns old/new OIDs
 */
static error_t *pull_branch_ff(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    bool *updated,
    git_oid *old_oid,  /* Can be NULL */
    git_oid *new_oid   /* Can be NULL */
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

    /* Capture OIDs before updating (if caller wants them) */
    if (old_oid) {
        git_oid_cpy(old_oid, local_oid);
    }
    if (new_oid) {
        git_oid_cpy(new_oid, remote_oid);
    }

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
 * Operates on the active set (scope_active): fetching is driven by what the
 * user asked for. `dotta sync -p work` fetches only `work`, not every
 * enabled profile. Precedence-adjacent work (push phase) still uses the
 * full enabled set — different role, different accessor.
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

    /* Ephemeral fetch progress — shown while fetching, cleared after.
     * On TTY: transfer progress overwrites via \r, then line cleared entirely.
     * On pipe: falls back to persistent line with newline. */
    bool ephemeral = output_is_tty(out);
    output_print(
        out, OUTPUT_NORMAL, "Fetching from '%s'...",
        remote_name
    );
    fflush(out->stream);

    /* Build array of fetchable branch names.
     *
     * Only include profiles that have a remote tracking ref — these are known
     * to exist (or have existed) on the remote. Local-only profiles (never
     * pushed) have no tracking ref and would cause the entire batched fetch
     * to fail with a "ref not found" error from the remote. */
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
        /* Classify authoritatively from the transfer outcome rather than
         * matching libgit2's English error strings. Read immediately:
         * the next transfer_op_begin would overwrite last_outcome. */
        const char *err_msg = error_message(err);
        if (transfer_last_outcome(xfer) == TRANSFER_OUTCOME_AUTH_FAILED) {
            results->auth_failed_count++;
            output_error(out, "Authentication failed: %s", err_msg);
        } else {
            results->fetch_failed_count++;
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
 * Operates on the active set (scope_active), matching sync_fetch_phase:
 * analyze only what the user asked for. results is sized from
 * scope_active(scope)->count by the caller; the two counts agree.
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
        upstream_info_t *info = NULL;
        error_t *err = upstream_analyze_profile(
            repo, remote_name, profiles->items[i], &info
        );

        if (err) {
            result->failed = true;
            result->error_message = strdup(error_message(err));
            results->failed_count++;
            error_free(err);
            continue;
        }

        result->state = info->state;
        result->ahead = info->ahead;
        result->behind = info->behind;
        upstream_info_free(info);

        /* Update counters */
        switch (result->state) {
            case UPSTREAM_UP_TO_DATE:
                results->up_to_date_count++;
                break;
            case UPSTREAM_LOCAL_AHEAD:
                /* Can push */
                break;
            case UPSTREAM_REMOTE_AHEAD:
                results->need_pull_count++;
                break;
            case UPSTREAM_DIVERGED:
                results->diverged_count++;
                break;
            case UPSTREAM_NO_REMOTE:
                break;
            case UPSTREAM_UNKNOWN:
                /* Skip unknown states */
                break;
        }
    }

    return NULL;
}

/**
 * Record profile operation failure
 *
 * Takes ownership of err (frees it). Caller must print any
 * output_error messages BEFORE calling this function.
 */
static void mark_result_failed(
    profile_sync_result_t *result,
    sync_results_t *results,
    error_t *err
) {
    result->failed = true;
    result->error_message = strdup(error_message(err));
    results->failed_count++;
    error_free(err);
}

/**
 * Sync manifest after branch update (non-fatal on failure)
 *
 * Calls manifest_sync_diff with NULL metadata_cache (cache is stale after
 * fetch/pull — fresh metadata is loaded from updated Git state).
 *
 * On failure: prints warning + recovery hint, returns false.
 * On success: writes stats to output parameters, returns true.
 * Output parameters are optional (can be NULL).
 */
static bool sync_manifest(
    git_repository *repo,
    state_t *state,
    const char *profile,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles,
    output_t *out,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks,
    size_t *out_skipped
) {
    size_t synced = 0, removed = 0, fallbacks = 0, skipped = 0;
    error_t *err = manifest_sync_diff(
        repo, state, profile, old_oid, new_oid, enabled_profiles,
        &synced, &removed, &fallbacks, &skipped
    );

    if (err) {
        output_warning(
            out, OUTPUT_NORMAL, "     Manifest sync failed: %s",
            error_message(err)
        );
        output_hint(
            out, OUTPUT_NORMAL, "     Run 'dotta status' or 'dotta apply' to resync manifest"
        );
        error_free(err);
        return false;
    }

    if (out_synced) *out_synced = synced;
    if (out_removed) *out_removed = removed;
    if (out_fallbacks) *out_fallbacks = fallbacks;
    if (out_skipped) *out_skipped = skipped;

    return true;
}

/**
 * Sync manifest and print standard result summary
 *
 * High-level wrapper for non-pull callers (rebase, merge, theirs).
 * Prints manifest stats line and skipped files warning.
 */
static void sync_manifest_and_report(
    git_repository *repo,
    state_t *state,
    const char *profile,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles,
    output_t *out
) {
    size_t synced = 0, removed = 0, fallbacks = 0, skipped = 0;
    bool ok = sync_manifest(
        repo, state, profile, old_oid, new_oid, enabled_profiles,
        out, &synced, &removed, &fallbacks, &skipped
    );

    if (ok && (synced > 0 || removed > 0 || fallbacks > 0)) {
        output_info(
            out, OUTPUT_NORMAL, "     Manifest: %zu staged, %zu removed, %zu fallback%s",
            synced, removed, fallbacks, fallbacks == 1 ? "" : "s"
        );
    }

    if (skipped > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "     %zu custom file%s skipped (no prefix configured for '%s')",
            skipped, skipped == 1 ? "" : "s", profile
        );
        output_hint(
            out, OUTPUT_NORMAL, "     Run: dotta profile enable --prefix <path> %s",
            profile
        );
    }
}

/**
 * Attempt divergence rollback after resolution failure
 *
 * Returns critical error if rollback itself fails (caller must propagate).
 * Returns NULL and prints informational message on successful rollback.
 */
static error_t *attempt_rollback(
    resolve_context_t *ctx,
    const char *profile,
    const char *failure_reason,
    output_t *out
) {
    error_t *err = resolve_rollback(ctx);
    if (err) {
        output_error(out, "     ✗ Critical: Rollback failed: %s", error_message(err));
        output_newline(out, OUTPUT_NORMAL);
        return error_wrap(
            err, "Failed to rollback branch '%s' after %s.\n"
            "Repository may be in an inconsistent state.\n"
            "Manual intervention required: git reset --hard origin/%s",
            profile, failure_reason, profile
        );
    }

    output_info(out, OUTPUT_NORMAL, "     ↺ Rolled back to original state");

    return NULL;
}

/**
 * Handle UPSTREAM_REMOTE_AHEAD: auto-pull (fast-forward) or warn
 */
static void handle_remote_ahead(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    sync_results_t *results,
    output_t *out,
    bool auto_pull,
    bool no_pull,
    state_t *state,
    const string_array_t *enabled_profiles
) {
    if (!auto_pull) {
        /* Just warn - don't auto-pull */
        output_info(
            out, OUTPUT_NORMAL, "  ↓ {yellow}%s{reset}: remote has %zu new commit%s",
            result->profile, result->behind, result->behind == 1 ? "" : "s"
        );

        if (no_pull) {
            output_hint(
                out, OUTPUT_NORMAL, "     Pull skipped (--no-pull)"
            );
        } else {
            output_hint(
                out, OUTPUT_NORMAL, "     Enable 'auto_pull' for automatic pull during sync"
            );
        }
        return;
    }

    /* Auto-pull when safe (fast-forward only) */
    output_info(
        out, OUTPUT_VERBOSE, "  Pulling %s (%zu commit%s behind)...",
        result->profile, result->behind, result->behind == 1 ? "" : "s"
    );

    bool pulled = false;
    git_oid old_oid, new_oid;
    error_t *err = pull_branch_ff(
        repo, remote_name, result->profile, &pulled, &old_oid, &new_oid
    );
    if (err) {
        output_error(
            out, "  ✗ %s: pull failed - %s",
            result->profile, error_message(err)
        );
        mark_result_failed(result, results, err);
        return;
    }

    if (!pulled) {
        /* Already up-to-date - report in verbose mode */
        output_info(
            out, OUTPUT_VERBOSE, "  = {green}%s{reset}: already up-to-date",
            result->profile
        );
        /* Decrement need_pull_count since it was already up-to-date */
        if (results->need_pull_count > 0) {
            results->need_pull_count--;
        }
        return;
    }

    /* Pull succeeded */
    if (results->need_pull_count > 0) {
        results->need_pull_count--;
    }
    results->pulled_count++;

    /* Sync manifest — stats needed for success message */
    size_t synced = 0, removed = 0, fallbacks = 0, skipped = 0;
    bool manifest_ok = sync_manifest(
        repo, state, result->profile, &old_oid, &new_oid,
        enabled_profiles, out, &synced, &removed, &fallbacks, &skipped
    );

    if (!manifest_ok) {
        output_success(
            out, OUTPUT_NORMAL, "  {green}%s{reset}: pulled %zu commit%s (manifest sync failed)",
            result->profile, result->behind, result->behind == 1 ? "" : "s"
        );
    } else {
        output_success(
            out, OUTPUT_NORMAL,
            "  {green}%s{reset}: pulled %zu commit%s (%zu staged, %zu removed, %zu fallback%s)",
            result->profile, result->behind, result->behind == 1 ? "" : "s",
            synced, removed, fallbacks, fallbacks == 1 ? "" : "s"
        );
    }
    if (skipped > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "     %zu custom file%s skipped (no prefix configured for '%s')",
            skipped, skipped == 1 ? "" : "s", result->profile
        );
        output_hint(
            out, OUTPUT_NORMAL, "     Run: dotta profile enable --prefix <path> %s",
            result->profile
        );
    }
}

/**
 * Resolve divergence via rebase or merge, then push
 *
 * Unified handler for DIVERGE_REBASE and DIVERGE_MERGE strategies
 * (structurally identical — only the strategy enum and log strings differ).
 *
 * Returns critical error only on rollback failure (caller must propagate).
 * All other failures are recorded in result/results and return NULL.
 */
static error_t *resolve_and_push_divergence(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    sync_results_t *results,
    output_t *out,
    resolve_strategy_t strategy,
    const char *strategy_name,
    transfer_context_t *xfer,
    state_t *state,
    const string_array_t *enabled_profiles,
    bool no_push
) {
    const char *cap_name = (strategy == RESOLVE_STRATEGY_REBASE)
        ? "Rebase" : "Merge";
    const char *past_desc = (strategy == RESOLVE_STRATEGY_REBASE)
        ? "rebased onto remote" : "merged with remote";
    const char *push_desc = (strategy == RESOLVE_STRATEGY_REBASE)
        ? "rebased commits" : "merge commit";

    output_info(
        out, OUTPUT_NORMAL, "     Resolving with %s strategy...",
        strategy_name
    );

    /* Initialize divergence context (saves current state for rollback) */
    resolve_context_t ctx;
    error_t *err = resolve_init(
        &ctx, repo, remote_name, result->profile, strategy
    );
    if (err) {
        output_error(
            out, "     ✗ Failed to initialize divergence context: %s",
            error_message(err)
        );
        mark_result_failed(result, results, err);
        return NULL;
    }

    /* Perform in-memory resolution (never modifies HEAD) */
    git_oid new_oid;
    err = resolve_execute(&ctx, &new_oid);
    if (err) {
        output_error(
            out, "     ✗ %s failed: %s",
            cap_name, error_message(err)
        );
        mark_result_failed(result, results, err);
        return NULL;
    }

    /* Verify resolution */
    size_t ahead = 0;
    err = resolve_verify(&ctx, &ahead, NULL);
    if (err) {
        output_error(
            out, "     ✗ %s verification failed: %s",
            cap_name, error_message(err)
        );
        mark_result_failed(result, results, err);

        char reason[64];
        snprintf(
            reason, sizeof(reason), "%s verification failure", strategy_name
        );
        return attempt_rollback(&ctx, result->profile, reason, out);
    }

    output_success(
        out, OUTPUT_NORMAL, "     Successfully %s (%zu commit%s to push)",
        past_desc, ahead, ahead == 1 ? "" : "s"
    );

    if (no_push) {
        output_info(out, OUTPUT_NORMAL, "     Push skipped (--no-push)");
    } else {
        /* Push resolved commits */
        err = gitops_push_branch(repo, remote_name, result->profile, xfer);
        if (err) {
            output_error(
                out, "     ✗ Push after %s failed: %s",
                strategy_name, error_message(err)
            );
            mark_result_failed(result, results, err);

            output_info(
                out, OUTPUT_NORMAL, "     ↺ Rolling back %s (push failed)...",
                strategy_name
            );
            return attempt_rollback(
                &ctx, result->profile, "push failure", out
            );
        }

        output_success(
            out, OUTPUT_NORMAL, "     Pushed %s",
            push_desc
        );
        result->pushed = true;
        results->pushed_count++;
    }

    if (results->diverged_count > 0) {
        results->diverged_count--;
    }
    results->pulled_count++;

    /* Sync manifest with changes from resolution */
    sync_manifest_and_report(
        repo, state, result->profile, &ctx.saved_oid,
        &new_oid, enabled_profiles, out
    );

    return NULL;
}

/**
 * Handle DIVERGE_OURS: force push local branch to remote
 */
static error_t *handle_diverged_ours(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    sync_results_t *results,
    output_t *out,
    bool confirm_destructive,
    transfer_context_t *xfer,
    bool no_push
) {
    output_info(out, OUTPUT_NORMAL, "     Resolving with 'ours' strategy (force push)...");

    if (no_push) {
        output_info(out, OUTPUT_NORMAL, "     Force push skipped (--no-push)");
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
            output_info(out, OUTPUT_NORMAL, "     Operation cancelled by user");
            return NULL;
        }
    }

    /* Force push local to remote (local branch stays unchanged) */
    error_t *err = gitops_force_push_branch(repo, remote_name, result->profile, xfer);
    if (err) {
        output_error(out, "     ✗ Force push failed: %s", error_message(err));
        mark_result_failed(result, results, err);
        return NULL;
    }

    output_success(
        out, OUTPUT_NORMAL, "     Force pushed to remote (remote commits discarded)"
    );
    result->pushed = true;
    results->pushed_count++;

    return NULL;
}

/**
 * Handle DIVERGE_THEIRS: reset local branch to remote
 */
static error_t *handle_diverged_theirs(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    sync_results_t *results,
    output_t *out,
    bool confirm_destructive,
    state_t *state,
    const string_array_t *enabled_profiles
) {
    output_info(
        out, OUTPUT_NORMAL, "     Resolving with 'theirs' strategy (reset to remote)..."
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
                out, OUTPUT_NORMAL, "     Operation cancelled by user"
            );
            return NULL;
        }
    }

    /* Initialize divergence context (saves current state for rollback) */
    resolve_context_t ctx;
    error_t *err = resolve_init(
        &ctx, repo, remote_name, result->profile, RESOLVE_STRATEGY_THEIRS
    );
    if (err) {
        output_error(
            out, "     ✗ Failed to initialize divergence context: %s",
            error_message(err)
        );
        mark_result_failed(result, results, err);
        return NULL;
    }

    /* Resolve divergence (resets local branch to remote) */
    git_oid new_oid;
    err = resolve_execute(&ctx, &new_oid);
    if (err) {
        output_error(
            out, "     ✗ Reset failed: %s",
            error_message(err)
        );
        mark_result_failed(result, results, err);
        return NULL;
    }

    /* Verify reset succeeded
     *
     * No rollback on failure — theirs strategy already reset the branch to
     * the desired state. Rolling back would undo what the user requested.
     */
    err = resolve_verify(&ctx, NULL, NULL);
    if (err) {
        output_error(out, "     ✗ Reset verification failed: %s", error_message(err));
        output_warning(out, OUTPUT_NORMAL, "     Local branch was reset but verification failed");
        mark_result_failed(result, results, err);
        return NULL;
    }

    output_success(out, OUTPUT_NORMAL, "     Reset to remote (local commits discarded)");
    results->pulled_count++;

    /* Sync manifest with changes from reset */
    sync_manifest_and_report(
        repo, state, result->profile, &ctx.saved_oid,
        &new_oid, enabled_profiles, out
    );

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
    sync_results_t *results,
    output_t *out,
    sync_strategy_t strategy,
    transfer_context_t *xfer,
    bool confirm_destructive,
    state_t *state,
    const string_array_t *enabled_profiles,
    bool no_push
) {
    output_warning(
        out, OUTPUT_NORMAL, "  ⚠ {red}%s{reset}: diverged (%zu local, %zu remote commits)",
        result->profile, result->ahead, result->behind
    );

    switch (strategy) {
        case DIVERGE_WARN: {
            output_hint(
                out, OUTPUT_NORMAL,
                "     Use --diverged=<strategy> or set diverged_strategy in config"
            );
            output_hintline(
                out, OUTPUT_NORMAL,
                "     Strategies: rebase, merge, ours (keep local), theirs (keep remote)"
            );
            break;
        }

        case DIVERGE_REBASE: {
            return resolve_and_push_divergence(
                repo, remote_name, result, results, out, RESOLVE_STRATEGY_REBASE,
                "rebase", xfer, state, enabled_profiles, no_push
            );
        }

        case DIVERGE_MERGE: {
            return resolve_and_push_divergence(
                repo, remote_name, result, results, out, RESOLVE_STRATEGY_MERGE,
                "merge", xfer, state, enabled_profiles, no_push
            );
        }

        case DIVERGE_OURS: {
            error_t *err = handle_diverged_ours(
                repo, remote_name, result, results, out, confirm_destructive,
                xfer, no_push
            );
            if (!err && result->pushed) {
                if (results->diverged_count > 0) results->diverged_count--;
            }
            return err;
        }

        case DIVERGE_THEIRS: {
            size_t before = results->pulled_count;
            error_t *err = handle_diverged_theirs(
                repo, remote_name, result, results, out, confirm_destructive,
                state, enabled_profiles
            );
            if (!err && results->pulled_count > before) {
                if (results->diverged_count > 0) results->diverged_count--;
            }
            return err;
        }
    }

    return NULL;
}

/**
 * Phase 3: Sync branches with remote (push/pull/divergence handling)
 *
 * Includes manifest synchronization when branches are updated via
 * pull/rebase/merge/reset operations. This maintains the VWD architecture
 * by keeping the manifest table in sync with Git branches.
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
    bool confirm_destructive,
    state_t *state,                           /* For manifest updates */
    const string_array_t *enabled_profiles    /* For precedence resolution */
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(results);
    CHECK_NULL(out);
    CHECK_NULL(state);
    CHECK_NULL(enabled_profiles);

    if (!ephemeral) {
        output_section(out, OUTPUT_NORMAL, "Syncing with remote");
    }

    for (size_t i = 0; i < results->count; i++) {
        profile_sync_result_t *result = &results->profiles[i];

        /* Skip failed analysis */
        if (result->failed) {
            output_error(out, "  %s: %s", result->profile, result->error_message);
            continue;
        }

        /* Handle based on state */
        switch (result->state) {
            case UPSTREAM_UP_TO_DATE: {
                output_info(
                    out, OUTPUT_VERBOSE, "  = {green}%s{reset}: up-to-date",
                    result->profile
                );
                break;
            }

            case UPSTREAM_LOCAL_AHEAD: {
                /* theirs: discard local commits, reset to remote
                 * Blocked by --no-pull since resetting to remote incorporates remote state */
                if (diverged_strategy == DIVERGE_THEIRS && !no_pull) {
                    output_info(
                        out, OUTPUT_NORMAL, "  ↑ {yellow}%s{reset}: %zu commit%s ahead of remote",
                        result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                    );
                    error_t *err = handle_diverged_theirs(
                        repo, remote_name, result, results, out, confirm_destructive,
                        state, enabled_profiles
                    );
                    if (err) return err;
                    break;
                }

                if (no_push) {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "  ↑ {yellow}%s{reset}: %zu commit%s ahead (push skipped: --no-push)",
                        result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                    );
                    break;
                }

                /* Safe to push - local has new commits */
                output_info(
                    out, OUTPUT_VERBOSE, "  Pushing %s (%zu commit%s)...",
                    result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                );

                error_t *err = gitops_push_branch(repo, remote_name, result->profile, xfer);
                if (err) {
                    output_error(
                        out, "  ✗ %s: push failed - %s",
                        result->profile, error_message(err)
                    );
                    mark_result_failed(result, results, err);
                } else {
                    result->pushed = true;
                    results->pushed_count++;

                    output_success(
                        out, OUTPUT_NORMAL, "  {green}%s{reset}: pushed %zu commit%s",
                        result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                    );
                }
                break;
            }

            case UPSTREAM_NO_REMOTE: {
                if (no_push) {
                    output_info(
                        out, OUTPUT_NORMAL, "  • %s: local only (push skipped: --no-push)",
                        result->profile
                    );
                    break;
                }

                /* Remote branch doesn't exist - create it */
                output_info(
                    out, OUTPUT_VERBOSE, "  Creating remote branch %s...",
                    result->profile
                );

                error_t *err = gitops_push_branch(repo, remote_name, result->profile, xfer);
                if (err) {
                    output_error(
                        out, "  ✗ %s: failed to create remote branch - %s",
                        result->profile, error_message(err)
                    );
                    mark_result_failed(result, results, err);
                } else {
                    result->pushed = true;
                    results->pushed_count++;
                    output_success(
                        out, OUTPUT_NORMAL, "  {green}%s{reset}: created remote branch",
                        result->profile
                    );
                }
                break;
            }

            case UPSTREAM_REMOTE_AHEAD: {
                /* ours: force push local, discard remote commits */
                if (diverged_strategy == DIVERGE_OURS) {

                    output_info(
                        out, OUTPUT_NORMAL, "  ↓ {yellow}%s{reset}: %zu remote commit%s ahead",
                        result->profile, result->behind, result->behind == 1 ? "" : "s"
                    );
                    output_warning(
                        out, OUTPUT_NORMAL,
                        "     Local is behind — force push will overwrite newer remote commits"
                    );

                    error_t *err = handle_diverged_ours(
                        repo, remote_name, result, results, out, confirm_destructive, xfer, no_push
                    );
                    if (err) {
                        return err;
                    }
                    /* Adjust: analyze phase counted this as needing pull,
                     * but only decrement if ours actually resolved (pushed).
                     * If --no-push or user cancelled, profile still needs attention. */
                    if (result->pushed && results->need_pull_count > 0) {
                        results->need_pull_count--;
                    }
                    break;
                }
                handle_remote_ahead(
                    repo, remote_name, result, results, out, auto_pull, no_pull,
                    state, enabled_profiles
                );
                break;
            }

            case UPSTREAM_DIVERGED: {
                /* --no-pull blocks strategies that incorporate remote changes */
                if (no_pull && diverged_strategy != DIVERGE_WARN &&
                    diverged_strategy != DIVERGE_OURS) {

                    output_warning(
                        out, OUTPUT_NORMAL,
                        "  ⚠ {red}%s{reset}: diverged (%zu local, %zu remote commits)",
                        result->profile, result->ahead, result->behind
                    );
                    const char *name = diverged_strategy == DIVERGE_REBASE ? "rebase" :
                        diverged_strategy == DIVERGE_MERGE ? "merge" : "theirs";

                    output_hint(
                        out, OUTPUT_NORMAL, "     '%s' resolution skipped (--no-pull prevents "
                        "incorporating remote changes)", name
                    );
                    break;
                }
                error_t *err = handle_diverged(
                    repo, remote_name, result, results, out, diverged_strategy, xfer,
                    confirm_destructive, state, enabled_profiles, no_push
                );
                if (err) {
                    return err;  /* Critical rollback failure */
                }
                break;
            }

            case UPSTREAM_UNKNOWN: {
                output_warning(out, OUTPUT_NORMAL, "  ? %s: state unknown", result->profile);
                break;
            }
        }
    }

    return NULL;
}

/**
 * Sync command implementation
 */
error_t *cmd_sync(const dotta_ctx_t *ctx, const cmd_sync_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->state);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    state_t *state = ctx->state;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Declare all resources, initialized to NULL */
    error_t *err = NULL;
    workspace_t *ws = NULL;
    scope_t *scope = NULL;
    sync_results_t *results = NULL;
    char *remote_name = NULL;
    char *remote_url = NULL;
    transfer_context_t *xfer = NULL;
    char *current_branch = NULL;

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
     *   scope_enabled — persistent VWD scope (passed to workspace_load).
     *   scope_active  — sync operation face (fetch / analyze / pull targets).
     */
    scope_inputs_t scope_inputs = {
        .profiles      = opts->profiles,
        .profile_count = opts->profile_count,
    };
    err = scope_build(repo, state, &scope_inputs, config, &scope);
    if (err) goto cleanup;

    if (scope_enabled(scope)->count == 0) {
        err = ERROR(
            ERR_NOT_FOUND, "No enabled profiles to sync\n"
            "Hint: Run 'dotta profile enable <name>' to enable profiles\n"
            "      Or run 'dotta profile list --remote' to see available profiles"
        );
        goto cleanup;
    }

    /* Create results tracker */
    results = sync_results_create(scope_active(scope)->count);
    if (!results) {
        err = ERROR(ERR_MEMORY, "Failed to create results");
        goto cleanup;
    }

    /* Auto-detect remote early — fail fast before expensive workspace load */
    err = upstream_detect_remote(repo, &remote_name);
    if (err) {
        goto cleanup;
    }

    /* Drift counters — populated by the non-force workspace scan below or,
     * when workspace_load is skipped, from the explicit reconcile in the
     * force branch further down. Declared here so the emission site sees
     * them regardless of mode. Reuses manifest_repair_stats_t so the force
     * path can write directly into this struct via manifest_reconcile.
     *
     * Non-force reads from the persistent anchor vs manifest.blob_oid
     * comparison in analyze_file_divergence, which survives the
     * status→sync sequence — reconcile's own stats would silently drop
     * to {0} on a second invocation against already-repaired state. */
    manifest_repair_stats_t drift = { 0 };

    /* Validate workspace - sync requires clean workspace (no uncommitted changes)
     *
     * Skip entirely when --force is used: the clean check result is unused, and
     * workspace_load can be expensive (filesystem analysis, directory scanning).
     */
    if (!opts->force) {
        workspace_load_t ws_opts = {
            .analyze_files       = true,   /* Validate file state for uncommitted changes */
            .analyze_orphans     = false,  /* Orphans are apply's concern, not sync's */
            .analyze_untracked   = config->auto_detect_new_files, /* Respect config */
            .analyze_directories = false,  /* Directory metadata is apply's concern */
            .analyze_encryption  = false   /* Encryption is apply's concern */
        };
        err = workspace_load(
            repo, state, scope, config, ctx->content_cache, &ws_opts, &ws
        );
        if (err) {
            err = error_wrap(err, "Failed to load workspace");
            goto cleanup;
        }

        /* Persist deployment-anchor advances from slow-path CMP_EQUAL checks
         * (self-healing optimization). Seeds the fast path for subsequent
         * status/apply calls. Non-fatal on failure — sync's workspace
         * validation still works correctly. */
        error_t *flush_err = workspace_flush_anchor_updates(ws);
        if (flush_err) {
            error_free(flush_err);
        }

        /* Count all types of divergence */
        size_t all_diverged_count = 0;
        const workspace_item_t *all_diverged = workspace_get_all_diverged(ws, &all_diverged_count);

        size_t modified_count = 0;    /* DEPLOYED with CONTENT divergence */
        size_t deleted_count = 0;     /* DELETED state */
        size_t mode_diff_count = 0;   /* DEPLOYED with MODE divergence */
        size_t type_diff_count = 0;   /* DEPLOYED with TYPE divergence */
        size_t untracked_count = 0;   /* UNTRACKED state */

        for (size_t i = 0; i < all_diverged_count; i++) {
            const workspace_item_t *item = &all_diverged[i];

            switch (item->state) {
                case WORKSPACE_STATE_DEPLOYED:
                    if (item->divergence & DIVERGENCE_CONTENT) modified_count++;
                    if (item->divergence & DIVERGENCE_MODE) mode_diff_count++;
                    if (item->divergence & DIVERGENCE_TYPE) type_diff_count++;
                    break;
                case WORKSPACE_STATE_DELETED:
                    deleted_count++;
                    break;
                case WORKSPACE_STATE_UNTRACKED:
                    untracked_count++;
                    break;
                case WORKSPACE_STATE_RELEASED:
                    /* Drift: file removed from Git externally. Sync does not
                     * prune (that's apply's job), but the count is useful as
                     * an informational nudge toward the next apply. */
                    drift.released++;
                    break;
                case WORKSPACE_STATE_UNDEPLOYED:
                case WORKSPACE_STATE_ORPHANED:
                    /* Not sync's concern — handled by apply command */
                    break;
            }
            /* Drift flags are independent of lifecycle state: STALE combines
             * with CONTENT on DEPLOYED items, profile_changed can coexist
             * with any state. Classified here alongside the switch. */
            if (item->divergence & DIVERGENCE_STALE) drift.updated++;
            if (item->profile_changed) drift.reassigned++;
        }

        size_t uncommitted_count =
            modified_count + deleted_count + mode_diff_count + type_diff_count + untracked_count;

        if (uncommitted_count > 0) {
            if (config->strict_mode) {
                /* Strict mode: Block with full diagnostic output */
                output_section(out, OUTPUT_NORMAL, "Workspace has uncommitted changes");
                output_newline(out, OUTPUT_NORMAL);

                /* Show what's uncommitted */
                if (modified_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu modified file%s",
                        modified_count, modified_count == 1 ? "" : "s"
                    );
                }
                if (deleted_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu deleted file%s",
                        deleted_count, deleted_count == 1 ? "" : "s"
                    );
                }
                if (mode_diff_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu file%s with permission changes",
                        mode_diff_count, mode_diff_count == 1 ? "" : "s"
                    );
                }
                if (type_diff_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu file%s with type changes",
                        type_diff_count, type_diff_count == 1 ? "" : "s"
                    );
                }
                if (untracked_count > 0) {
                    output_info(
                        out, OUTPUT_NORMAL, "  %zu new untracked file%s",
                        untracked_count, untracked_count == 1 ? "" : "s"
                    );
                }

                output_newline(out, OUTPUT_NORMAL);
                output_info(out, OUTPUT_NORMAL, "Sync requires a clean workspace.");
                output_newline(out, OUTPUT_NORMAL);
                output_hintline(out, OUTPUT_NORMAL, "Next steps:");
                output_hintline(out, OUTPUT_NORMAL, "  Commit changes: dotta update");
                output_hintline(out, OUTPUT_NORMAL, "  Synchronize:    dotta sync");
                output_hintline(out, OUTPUT_NORMAL, "  Or bypass with: dotta sync --force");

                err = ERROR(
                    ERR_VALIDATION,
                    "Cannot sync with uncommitted changes (found %zu uncommitted file%s)",
                    uncommitted_count, uncommitted_count == 1 ? "" : "s"
                );
                goto cleanup;
            }

            /* Non-strict mode: Warn and require user confirmation
             *
             * The risk: syncing before committing local changes can hide remote conflicts.
             * If remote has changes to the same files, pulling those changes updates the
             * manifest. Then 'update' commits local changes ON TOP of remote's version,
             * silently overwriting remote changes without merge/conflict detection.
             *
             * Safe workflow: update → sync → resolve any divergence explicitly
             */
            output_warning(
                out, OUTPUT_NORMAL, "Workspace has %zu uncommitted change%s",
                uncommitted_count, uncommitted_count == 1 ? "" : "s"
            );

            /* Show breakdown in verbose mode */
            if (modified_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu modified", modified_count);
            }
            if (deleted_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu deleted", deleted_count);
            }
            if (mode_diff_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu permission changes", mode_diff_count);
            }
            if (type_diff_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu type changes", type_diff_count);
            }
            if (untracked_count > 0) {
                output_info(out, OUTPUT_VERBOSE, "  %zu untracked", untracked_count);
            }

            output_newline(out, OUTPUT_NORMAL);
            output_info(out, OUTPUT_NORMAL, "Syncing before 'update' may hide remote conflicts.");
            output_newline(out, OUTPUT_NORMAL);

            /* Confirmation with safe defaults:
             * - Interactive: defaults to NO (user must explicitly type 'y')
             * - Non-interactive (CI/CD): refuses automatically
             */
            if (!output_confirm_or_default(out, "Continue anyway?", false, false)) {
                output_info(out, OUTPUT_NORMAL, "Sync cancelled");
                output_hint(out, OUTPUT_NORMAL, "Run 'dotta update' first to commit local changes");
                err = NULL;  /* User cancelled - clean exit, not an error */
                goto cleanup;
            }

            /* User confirmed - proceed with sync */
            output_info(out, OUTPUT_VERBOSE, "Proceeding with uncommitted changes");
            output_newline(out, OUTPUT_NORMAL);
        }
    }

    /* Get remote URL for credential handling */
    error_t *url_err = gitops_get_remote_url(repo, remote_name, &remote_url);
    error_free(url_err);

    /* Create transfer context for progress reporting. Ephemeral progress
     * is enabled so the fetch progress line is cleared on completion,
     * leaving a clean framing around sync's subsequent status output. */
    transfer_options_t xfer_opts = {
        .output = out,
        .url = remote_url,
        .ephemeral_progress = true,
    };
    err = transfer_context_create(&xfer_opts, &xfer);
    free(remote_url);
    remote_url = NULL;
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

    /* Dry run: display analysis and exit without executing push/pull */
    if (opts->dry_run) {
        output_section(out, OUTPUT_NORMAL, "Dry run analysis");
        for (size_t i = 0; i < results->count; i++) {
            profile_sync_result_t *r = &results->profiles[i];
            if (r->failed) {
                output_error(out, "  ✗ %s: %s", r->profile, r->error_message);
                continue;
            }
            switch (r->state) {
                case UPSTREAM_UP_TO_DATE:
                    output_info(
                        out, OUTPUT_NORMAL, "  = %s: up-to-date",
                        r->profile
                    );
                    break;
                case UPSTREAM_LOCAL_AHEAD:
                    output_info(
                        out, OUTPUT_NORMAL, "  ↑ %s: %zu commit%s to push",
                        r->profile, r->ahead, r->ahead == 1 ? "" : "s"
                    );
                    break;
                case UPSTREAM_REMOTE_AHEAD:
                    output_info(
                        out, OUTPUT_NORMAL, "  ↓ %s: %zu commit%s to pull",
                        r->profile, r->behind, r->behind == 1 ? "" : "s"
                    );
                    break;
                case UPSTREAM_DIVERGED:
                    output_warning(
                        out, OUTPUT_NORMAL, "  ↕ %s: diverged (%zu local, %zu remote)",
                        r->profile, r->ahead, r->behind
                    );
                    break;
                case UPSTREAM_NO_REMOTE:
                    output_info(
                        out, OUTPUT_NORMAL, "  • %s: local only (no remote branch)",
                        r->profile
                    );
                    break;
                case UPSTREAM_UNKNOWN:
                    output_warning(
                        out, OUTPUT_NORMAL, "  ? %s: unknown state",
                        r->profile
                    );
                    break;
            }
        }
        output_newline(out, OUTPUT_NORMAL);
        output_info(out, OUTPUT_NORMAL, "Dry run: no changes made");
        err = NULL;
        goto cleanup;
    }

    /* Promote the borrowed READ handle to a write transaction for the
     * mutation phase. Dry-run exits above, so the lock is only held when
     * we're actually going to push/pull — shorter lock window than
     * declaring WRITE on the whole dispatch. */
    err = state_begin(state);
    if (err) {
        err = error_wrap(err, "Failed to open state transaction");
        goto cleanup;
    }

    /* Reconcile manifest with current Git state before sync operations.
     *
     * If external Git changes moved a branch HEAD since the last dotta
     * operation, state entries have stale blob_oid values. manifest_sync_diff
     * (downstream of push) computes a diff between old_oid (local HEAD before
     * fetch) and new_oid (after merge), then advances the per-profile
     * commit_oid to match the new HEAD. That masks pre-existing staleness:
     * files changed between the stale state and the pre-fetch HEAD get their
     * commit_oid updated (now matching HEAD) while blob_oid stays at the
     * stale value — ghost entries permanently invisible to staleness detection.
     *
     * Non-force: workspace_load above already reconciled via its prelude
     *   call. Drift counters were populated from the persistent anchor vs
     *   manifest.blob_oid comparison during the same scan. A second
     *   reconcile here would be a no-op producing stats = {0} — the path
     *   that silently broke output before this change. Skip it.
     *
     * Force: workspace_load was skipped for performance. This explicit
     *   reconcile is the only drift signal in this mode; it writes into
     *   the same drift struct the non-force branch populated, so emission
     *   is uniform. manifest_reconcile detects sync's already-held
     *   transaction via state_locked() and writes directly (no nested
     *   begin/commit). */
    if (opts->force) {
        err = manifest_reconcile(repo, state, &drift);
        if (err) {
            err = error_wrap(err, "Failed to reconcile manifest before sync");
            goto cleanup;
        }
    }

    if (drift.updated > 0) {
        output_info(
            out, OUTPUT_NORMAL, "Synchronized %zu file%s from external Git changes",
            drift.updated, drift.updated == 1 ? "" : "s"
        );
    }
    if (drift.refreshed > 0) {
        output_info(
            out, OUTPUT_NORMAL, "Refreshed tracking for %zu unchanged file%s",
            drift.refreshed, drift.refreshed == 1 ? "" : "s"
        );
    }
    if (drift.released > 0) {
        output_info(
            out, OUTPUT_NORMAL, "Released %zu file%s from management (run 'dotta apply' to prune)",
            drift.released, drift.released == 1 ? "" : "s"
        );
    }
    if (drift.reassigned > 0) {
        output_info(
            out, OUTPUT_NORMAL, "Detected %zu profile reassignment%s from external changes",
            drift.reassigned, drift.reassigned == 1 ? "" : "s"
        );
    }

    /* Phase 3: Sync with remote (push/pull/divergence handling)
     *
     * When all profiles are up-to-date and not in verbose mode, the sync
     * section is ephemeral — shown as progress during execution, cleared after.
     * This avoids noise when there's nothing actionable to report. */
    bool no_push = opts->no_push;
    bool all_quiet = (results->up_to_date_count == results->count);
    bool sync_ephemeral = !output_is_verbose(out) && all_quiet;

    if (sync_ephemeral) {
        output_print(out, OUTPUT_NORMAL, "Syncing...");
        fflush(out->stream);
    }

    /* sync_push_phase's enabled_profiles parameter drives precedence
     * resolution in manifest_sync_diff. scope_enabled is exactly the right
     * set: validated by profile_resolve_enabled (missing branches already
     * filtered and warned about at scope_build time) and filter-independent
     * by construction (CLI -p narrows scope_active, never scope_enabled).
     * Nothing between scope_build and here mutates the enabled_profiles
     * table (state_set_profiles / state_enable_profile / state_disable_profile
     * are confined to add/remove/profile/clone/interactive). */
    err = sync_push_phase(
        repo, remote_name, results, out, sync_ephemeral, auto_pull, opts->no_pull,
        no_push, diverged_strategy, xfer, config->confirm_destructive,
        state, scope_enabled(scope)
    );

    if (sync_ephemeral) {
        output_clear_line(out);
    }

    if (err) {
        goto cleanup;
    }

    /* Commit manifest changes */
    err = state_commit(state);
    if (err) {
        err = error_wrap(err, "Failed to save manifest changes");
        goto cleanup;
    }

    /* Final summary */
    output_section(out, OUTPUT_NORMAL, "Sync complete");

    if (results->pushed_count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "  {cyan}%zu{reset} profile%s pushed",
            results->pushed_count, results->pushed_count == 1 ? "" : "s"
        );
    }

    if (results->pulled_count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "  {cyan}%zu{reset} profile%s updated from remote",
            results->pulled_count, results->pulled_count == 1 ? "" : "s"
        );
    }

    if (results->up_to_date_count > 0) {
        output_info(
            out, OUTPUT_NORMAL, "  {cyan}%zu{reset} profile%s already up-to-date",
            results->up_to_date_count, results->up_to_date_count == 1 ? "" : "s"
        );
    }

    if (results->need_pull_count > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "  {cyan}%zu{reset} profile%s need pull",
            results->need_pull_count, results->need_pull_count == 1 ? "" : "s"
        );
    }

    if (results->diverged_count > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "  {cyan}%zu{reset} profile%s diverged",
            results->diverged_count, results->diverged_count == 1 ? "" : "s"
        );
    }

    if (results->failed_count > 0) {
        output_error(
            out, "  {cyan}%zu{reset} profile%s failed",
            results->failed_count, results->failed_count == 1 ? "" : "s"
        );
    }

    if (results->fetch_failed_count > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "  {cyan}%zu{reset} fetch operation%s failed",
            results->fetch_failed_count, results->fetch_failed_count == 1 ? "" : "s"
        );
    }

    if (results->auth_failed_count > 0) {
        output_error(
            out, "  {cyan}%zu{reset} authentication failure%s",
            results->auth_failed_count, results->auth_failed_count == 1 ? "" : "s"
        );
    }

    /* Session-level wire stats (silent if nothing moved) */
    transfer_summarize(xfer, out, OUTPUT_NORMAL);

    /* Provide guidance on next steps if remote content was pulled/resolved */
    if (results->pulled_count > 0) {
        output_newline(out, OUTPUT_NORMAL);
        output_hint(
            out, OUTPUT_NORMAL, "Run 'dotta apply' to deploy, or 'dotta status' to review"
        );
    }

    /* Success - fall through to cleanup */
    err = NULL;

cleanup:
    /* Free resources in reverse order of allocation. state is borrowed
     * from the dispatcher; workspace borrows scope's enabled array
     * internally, so free workspace first, then scope. state_rollback
     * is a no-op if no transaction is active, closing any partially-begun
     * mutation-phase transaction on error paths. */
    state_rollback(state);

    if (current_branch) free(current_branch);
    if (ws) workspace_free(ws);
    if (xfer) transfer_context_free(xfer);
    if (remote_url) free(remote_url);
    if (remote_name) free(remote_name);
    if (results) sync_results_free(results);
    if (scope) scope_free(scope);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

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
    .name        = "sync",
    .summary     = "Synchronize profiles with remote repository",
    .usage       = "%s sync [options] [profile]...",
    .description =
        "Fetch, analyze, and reconcile enabled profiles with their\n"
        "remote counterparts. Requires a clean workspace; run '%s\n"
        "update' to commit pending filesystem changes first.\n",
    .notes       =
        "Diverged Strategies:\n"
        "  warn          Report and stop (default).\n"
        "  rebase        Replay local commits atop remote.\n"
        "  merge         Create a merge commit.\n"
        "  ours          Keep local side; overwrite remote on push.\n"
        "  theirs        Keep remote side; drop local commits.\n",
    .examples    =
        "  %s sync                    # All enabled profiles\n"
        "  %s sync global             # Single profile\n"
        "  %s sync global darwin      # Multiple profiles\n"
        "  %s sync -n                 # Preview without writing\n"
        "  %s sync -f                 # Bypass clean-workspace check\n"
        "  %s sync --no-pull          # Push only\n"
        "  %s sync --diverged rebase  # Override divergence strategy\n",
    .epilogue    =
        "See also:\n"
        "  %s update          # Commit local changes first\n"
        "  %s status --remote # Inspect remote state before syncing\n",
    .opts_size   = sizeof(cmd_sync_options_t),
    .opts        = sync_opts,
    .payload     = &dotta_ext_read_crypto,
    .dispatch    = sync_dispatch,
};
