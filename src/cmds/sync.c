/**
 * sync.c - Intelligent synchronization command
 */

#include "sync.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/credentials.h"
#include "base/error.h"
#include "base/gitops.h"
#include "base/transfer.h"
#include "core/divergence.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "core/upstream.h"
#include "core/workspace.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"

/**
 * Per-profile sync result
 */
typedef struct {
    char *profile_name;
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
    size_t no_remote_count;
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
        free(results->profiles[i].profile_name);
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
    sync_divergence_strategy_t *out_strategy
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
 * Perform force push (for OURS strategy)
 */
static error_t *force_push_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    /* Force push local to remote */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Set up transfer callbacks if context provided */
    git_push_options push_opts = GIT_PUSH_OPTIONS_INIT;
    if (xfer) {
        push_opts.callbacks.credentials = transfer_credentials_callback;
        push_opts.callbacks.push_transfer_progress = transfer_push_progress_callback;
        push_opts.callbacks.payload = xfer;
    } else {
        /* No transfer context - use basic credential callback */
        push_opts.callbacks.credentials = credentials_callback;
    }

    /* Force push refspec ('+' prefix forces the push) */
    char refspec[DOTTA_REFSPEC_MAX];
    error_t *err_build = gitops_build_refname(refspec, sizeof(refspec),
                            "+refs/heads/%s:refs/heads/%s", branch_name, branch_name);
    if (err_build) {
        git_remote_free(remote);
        return error_wrap(err_build, "Invalid branch name '%s'", branch_name);
    }

    const char *refspecs[] = { refspec };
    git_strarray refs = { (char **)refspecs, 1 };

    git_err = git_remote_push(remote, &refs, &push_opts);
    git_remote_free(remote);

    if (git_err < 0) {
        if (xfer && xfer->cred) {
            credential_context_reject(xfer->cred);
        }
        return error_from_git(git_err);
    }

    if (xfer && xfer->cred) {
        credential_context_approve(xfer->cred);
    }

    return NULL;
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

    err = gitops_build_refname(local_refname, sizeof(local_refname),
                               "refs/heads/%s", branch_name);
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    err = gitops_build_refname(remote_refname, sizeof(remote_refname),
                               "refs/remotes/%s/%s", remote_name, branch_name);
    if (err) {
        return error_wrap(err, "Invalid remote/branch name '%s/%s'",
                          remote_name, branch_name);
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
        return ERROR(ERR_CONFLICT,
                    "Cannot fast-forward '%s' - branches have diverged", branch_name);
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
    git_err = git_reference_set_target(&updated_ref, local_ref, remote_oid,
                                       "sync: Fast-forward pull");
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
 * Phase 1: Fetch enabled profiles from remote
 */
static error_t *sync_fetch_enabled_profiles(
    git_repository *repo,
    const char *remote_name,
    profile_list_t *profiles,
    sync_results_t *results,
    output_ctx_t *out,
    bool verbose,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(profiles);
    CHECK_NULL(results);
    CHECK_NULL(out);

    /* Check if remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err == GIT_ENOTFOUND) {
        return ERROR(ERR_NOT_FOUND, "No remote '%s' configured\n"
                    "Hint: Run 'dotta remote add %s <url>' to add a remote",
                    remote_name, remote_name);
    } else if (git_err < 0) {
        return error_from_git(git_err);
    }
    git_remote_free(remote);

    char section_title[DOTTA_MESSAGE_MAX];
    snprintf(section_title, sizeof(section_title), "Fetching enabled profiles from '%s'",
             remote_name);
    output_section(out, section_title);

    /* Build array of branch names for batched fetch */
    char **branch_names = malloc(profiles->count * sizeof(char *));
    if (!branch_names) {
        return ERROR(ERR_MEMORY, "Failed to allocate branch names array");
    }

    for (size_t i = 0; i < profiles->count; i++) {
        branch_names[i] = profiles->profiles[i].name;
        if (verbose) {
            output_info(out, "  Queuing %s...", branch_names[i]);
        }
    }

    /* Perform batched fetch - single network operation for all branches */
    if (verbose) {
        output_info(out, "  Fetching %zu profile%s in batch...",
                   profiles->count, profiles->count == 1 ? "" : "s");
    }

    error_t *err = gitops_fetch_branches(repo, remote_name, branch_names, profiles->count, xfer);
    free(branch_names);

    if (err) {
        /* Check if this is an authentication error */
        const char *err_msg = error_message(err);
        if (strstr(err_msg, "authentication") || strstr(err_msg, "credentials") ||
            strstr(err_msg, "permission denied") || strstr(err_msg, "unauthorized")) {
            results->auth_failed_count++;
            output_error(out, "Authentication failed: %s", err_msg);
        } else {
            results->fetch_failed_count++;
            output_error(out, "Fetch failed: %s", err_msg);
        }
        error_free(err);

        return ERROR(ERR_GIT, "Failed to fetch profiles from remote\n"
                     "Hint: Check network connectivity and remote accessibility");
    }

    if (verbose) {
        output_success(out, "Fetched %zu enabled profile%s",
                       profiles->count, profiles->count == 1 ? "" : "s");
    }

    output_newline(out);
    return NULL;
}

/**
 * Phase 2: Analyze branch states
 */
static error_t *sync_analyze_phase(
    git_repository *repo,
    const char *remote_name,
    profile_list_t *profiles,
    sync_results_t *results,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(profiles);
    CHECK_NULL(results);
    CHECK_NULL(out);

    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];
        profile_sync_result_t *result = &results->profiles[i];

        result->profile_name = strdup(profile->name);
        if (!result->profile_name) {
            return ERROR(ERR_MEMORY, "Failed to allocate profile name");
        }

        /* Analyze state */
        upstream_info_t *info = NULL;
        error_t *err = upstream_analyze_profile(
            repo, remote_name, profile->name, &info
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
                results->no_remote_count++;
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
    const char *profile_name,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles,
    output_ctx_t *out,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks,
    size_t *out_skipped
) {
    size_t synced = 0, removed = 0, fallbacks = 0, skipped = 0;
    error_t *err = manifest_sync_diff(
        repo, state, profile_name, old_oid, new_oid, enabled_profiles,
        NULL /* metadata_cache — stale after fetch */,
        &synced, &removed, &fallbacks, &skipped
    );

    if (err) {
        output_warning(out, "   Manifest sync failed: %s", error_message(err));
        output_hint(out, "   Run 'dotta status' or 'dotta apply' to resync manifest");
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
    const char *profile_name,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles,
    output_ctx_t *out
) {
    size_t synced = 0, removed = 0, fallbacks = 0, skipped = 0;
    bool ok = sync_manifest(
        repo, state, profile_name, old_oid, new_oid, enabled_profiles,
        out,&synced, &removed, &fallbacks, &skipped
    );

    if (ok && (synced > 0 || removed > 0 || fallbacks > 0)) {
        output_info(out, "   Manifest: %zu staged, %zu removed, %zu fallback%s",
                   synced, removed, fallbacks, fallbacks == 1 ? "" : "s");
    }

    if (skipped > 0) {
        output_warning(out, "   %zu custom file%s skipped (no prefix configured for '%s')",
                      skipped, skipped == 1 ? "" : "s", profile_name);
        output_hint(out, "   Run: dotta profile enable --prefix <path> %s", profile_name);
    }
}

/**
 * Attempt divergence rollback after resolution failure
 *
 * Returns critical error if rollback itself fails (caller must propagate).
 * Returns NULL and prints informational message on successful rollback.
 */
static error_t *attempt_rollback(
    divergence_context_t *ctx,
    const char *profile_name,
    const char *failure_reason,
    output_ctx_t *out
) {
    error_t *err = divergence_rollback(ctx);
    if (err) {
        output_error(out, "   ✗ CRITICAL: Rollback failed: %s", error_message(err));
        output_newline(out);
        return error_wrap(err,
            "Failed to rollback branch '%s' after %s.\n"
            "Repository may be in an inconsistent state.\n"
            "Manual intervention required: git reset --hard origin/%s",
            profile_name, failure_reason, profile_name);
    }

    output_info(out, "   ↺ Rolled back to original state");
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
    output_ctx_t *out,
    bool verbose,
    bool auto_pull,
    state_t *state,
    const string_array_t *enabled_profiles
) {
    if (!auto_pull) {
        /* Just warn - don't auto-pull */
        char *colored = output_colorize(out, OUTPUT_COLOR_YELLOW, result->profile_name);
        output_info(out, "↓ %s: remote has %zu new commit%s",
               colored ? colored : result->profile_name,
               result->behind, result->behind == 1 ? "" : "s");
        output_hint(out, "   Run 'dotta pull' or enable auto_pull in config to automatically pull");
        free(colored);
        return;
    }

    /* Auto-pull when safe (fast-forward only) */
    if (verbose) {
        output_info(out, "Pulling %s (%zu commit%s behind)...",
               result->profile_name, result->behind, result->behind == 1 ? "" : "s");
    }

    bool pulled = false;
    git_oid old_oid, new_oid;
    error_t *err = pull_branch_ff(
        repo, remote_name, result->profile_name, &pulled, &old_oid, &new_oid
    );
    if (err) {
        output_error(out, "✗ %s: pull failed - %s", result->profile_name, error_message(err));
        mark_result_failed(result, results, err);
        return;
    }

    if (!pulled) {
        /* Already up-to-date - report in verbose mode */
        if (verbose) {
            char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
            output_info(out, "= %s: already up-to-date", colored ? colored : result->profile_name);
            free(colored);
        }
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

    /* Sync manifest — stats needed for success message */
    size_t synced = 0, removed = 0, fallbacks = 0, skipped = 0;
    bool manifest_ok = sync_manifest(
        repo, state, result->profile_name, &old_oid, &new_oid,
        enabled_profiles, out, &synced, &removed, &fallbacks, &skipped
    );

    char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
    if (!manifest_ok) {
        output_success(out, "%s: pulled %zu commit%s (manifest sync failed)",
               colored ? colored : result->profile_name,
               result->behind, result->behind == 1 ? "" : "s");
    } else {
        output_success(out, "%s: pulled %zu commit%s (%zu staged, %zu removed, %zu fallback%s)",
               colored ? colored : result->profile_name,
               result->behind, result->behind == 1 ? "" : "s",
               synced, removed, fallbacks, fallbacks == 1 ? "" : "s");
    }
    if (skipped > 0) {
        output_warning(out, "   %zu custom file%s skipped (no prefix configured for '%s')",
                      skipped, skipped == 1 ? "" : "s", result->profile_name);
        output_hint(out, "   Run: dotta profile enable --prefix <path> %s", result->profile_name);
    }
    free(colored);
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
    output_ctx_t *out,
    divergence_strategy_t strategy,
    const char *strategy_name,
    transfer_context_t *xfer,
    state_t *state,
    const string_array_t *enabled_profiles
) {
    const char *cap_name = (strategy == DIVERGENCE_STRATEGY_REBASE)
        ? "Rebase" : "Merge";
    const char *past_desc = (strategy == DIVERGENCE_STRATEGY_REBASE)
        ? "rebased onto remote" : "merged with remote";
    const char *push_desc = (strategy == DIVERGENCE_STRATEGY_REBASE)
        ? "rebased commits" : "merge commit";

    output_info(out, "   Resolving with %s strategy...", strategy_name);

    /* Initialize divergence context (saves current state for rollback) */
    divergence_context_t ctx;
    error_t *err = divergence_context_init(&ctx, repo, remote_name, result->profile_name, strategy);
    if (err) {
        output_error(out, "   ✗ Failed to initialize divergence context: %s", error_message(err));
        mark_result_failed(result, results, err);
        return NULL;
    }

    /* Perform in-memory resolution (never modifies HEAD) */
    git_oid new_oid;
    err = divergence_resolve(&ctx, &new_oid);
    if (err) {
        output_error(out, "   ✗ %s failed: %s", cap_name, error_message(err));
        mark_result_failed(result, results, err);
        return NULL;
    }

    /* Verify resolution */
    size_t ahead = 0;
    err = divergence_verify(&ctx, &ahead, NULL);
    if (err) {
        output_error(out, "   ✗ %s verification failed: %s", cap_name, error_message(err));
        mark_result_failed(result, results, err);

        char reason[64];
        snprintf(reason, sizeof(reason), "%s verification failure", strategy_name);
        return attempt_rollback(&ctx, result->profile_name, reason, out);
    }

    output_success(out, "   Successfully %s (%zu commit%s to push)",
                   past_desc, ahead, ahead == 1 ? "" : "s");

    /* Push resolved commits */
    err = gitops_push_branch(repo, remote_name, result->profile_name, xfer);
    if (err) {
        output_error(out, "   ✗ Push after %s failed: %s", strategy_name, error_message(err));
        mark_result_failed(result, results, err);

        output_info(out, "   ↺ Rolling back %s (push failed)...", strategy_name);
        return attempt_rollback(&ctx, result->profile_name, "push failure", out);
    }

    output_success(out, "   Pushed %s", push_desc);
    result->pushed = true;
    results->pushed_count++;
    if (results->diverged_count > 0) {
        results->diverged_count--;
    }

    /* Sync manifest with changes from resolution */
    sync_manifest_and_report(
        repo, state, result->profile_name, &ctx.saved_oid, &new_oid, enabled_profiles, out
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
    output_ctx_t *out,
    bool confirm_destructive,
    transfer_context_t *xfer
) {
    output_info(out, "   Resolving with 'ours' strategy (force push)...");

    /* Get user confirmation for destructive operation */
    if (confirm_destructive) {
        char prompt[DOTTA_MESSAGE_MAX];
        snprintf(prompt, sizeof(prompt),
                "WARNING: This will force push and OVERWRITE remote '%s'.\n"
                "Remote commits will be LOST. Continue?", result->profile_name);
        if (!output_confirm_or_default(out, prompt, false, false)) {
            output_info(out, "   Operation cancelled by user");
            return NULL;
        }
    }

    /* Initialize divergence context (saves current state for rollback) */
    divergence_context_t ctx;
    error_t *err = divergence_context_init(
        &ctx, repo, remote_name, result->profile_name, DIVERGENCE_STRATEGY_OURS
    );
    if (err) {
        output_error(out, "   ✗ Failed to initialize divergence context: %s",
                    error_message(err));
        mark_result_failed(result, results, err);
        return NULL;
    }

    /* For OURS, resolve is a no-op (local stays unchanged) */
    err = divergence_resolve(&ctx, NULL);
    if (err) {
        output_error(out, "   ✗ Resolution failed: %s", error_message(err));
        mark_result_failed(result, results, err);
        return NULL;
    }

    /* Force push to remote */
    err = force_push_branch(repo, remote_name, result->profile_name, xfer);
    if (err) {
        output_error(out, "   ✗ Force push failed: %s", error_message(err));
        mark_result_failed(result, results, err);
        return NULL;
    }

    output_success(out, "   Force pushed to remote (remote commits discarded)");
    result->pushed = true;
    results->pushed_count++;
    if (results->diverged_count > 0) {
        results->diverged_count--;
    }

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
    output_ctx_t *out,
    bool confirm_destructive,
    state_t *state,
    const string_array_t *enabled_profiles
) {
    output_info(out, "   Resolving with 'theirs' strategy (reset to remote)...");

    /* Get user confirmation for destructive operation */
    if (confirm_destructive) {
        char prompt[DOTTA_MESSAGE_MAX];
        snprintf(prompt, sizeof(prompt),
                "WARNING: This will reset '%s' to remote and DISCARD local commits.\n"
                "Local changes will be LOST. Continue?", result->profile_name);
        if (!output_confirm_or_default(out, prompt, false, false)) {
            output_info(out, "   Operation cancelled by user");
            return NULL;
        }
    }

    /* Initialize divergence context (saves current state for rollback) */
    divergence_context_t ctx;
    error_t *err = divergence_context_init(
        &ctx, repo, remote_name, result->profile_name, DIVERGENCE_STRATEGY_THEIRS
    );
    if (err) {
        output_error(out, "   ✗ Failed to initialize divergence context: %s",
                     error_message(err));
        mark_result_failed(result, results, err);
        return NULL;
    }

    /* Resolve divergence (resets local branch to remote) */
    git_oid new_oid;
    err = divergence_resolve(&ctx, &new_oid);
    if (err) {
        output_error(out, "   ✗ Reset failed: %s", error_message(err));
        mark_result_failed(result, results, err);
        return NULL;
    }

    /* Verify reset succeeded */
    err = divergence_verify(&ctx, NULL, NULL);
    if (err) {
        output_error(out, "   ✗ Reset verification failed: %s", error_message(err));
        output_warning(out, "   Local branch was reset but verification failed");
        mark_result_failed(result, results, err);
        return NULL;
    }

    output_success(out, "   Reset to remote (local commits discarded)");
    if (results->diverged_count > 0) {
        results->diverged_count--;
    }

    /* Sync manifest with changes from reset */
    sync_manifest_and_report(
        repo, state, result->profile_name, &ctx.saved_oid, &new_oid, enabled_profiles, out
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
    output_ctx_t *out,
    sync_divergence_strategy_t strategy,
    transfer_context_t *xfer,
    bool confirm_destructive,
    state_t *state,
    const string_array_t *enabled_profiles
) {
    char *colored = output_colorize(out, OUTPUT_COLOR_RED, result->profile_name);
    output_warning(out, "⚠ %s: diverged (%zu local, %zu remote commits)",
           colored ? colored : result->profile_name, result->ahead, result->behind);
    free(colored);

    switch (strategy) {
        case DIVERGE_WARN:
            output_hint(out, "   Use --diverged=<strategy> or set sync.diverged_strategy in config");
            output_hint_line(out, "   Strategies: rebase, merge, ours (keep local), theirs (keep remote)");
            break;

        case DIVERGE_REBASE:
            return resolve_and_push_divergence(
                repo, remote_name, result, results, out,
                DIVERGENCE_STRATEGY_REBASE, "rebase", xfer, state, enabled_profiles);

        case DIVERGE_MERGE:
            return resolve_and_push_divergence(
                repo, remote_name, result, results, out,
                DIVERGENCE_STRATEGY_MERGE, "merge", xfer, state, enabled_profiles);

        case DIVERGE_OURS:
            return handle_diverged_ours(
                repo, remote_name, result, results, out,
                confirm_destructive, xfer);

        case DIVERGE_THEIRS:
            return handle_diverged_theirs(
                repo, remote_name, result, results, out,
                confirm_destructive, state, enabled_profiles);
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
    output_ctx_t *out,
    bool verbose,
    bool auto_pull,
    sync_divergence_strategy_t diverged_strategy,
    transfer_context_t *xfer,
    bool confirm_destructive,
    state_t *state,                           /* For manifest updates */
    const string_array_t *enabled_profiles,   /* For precedence resolution */
    workspace_t *ws                           /* For cached resources */
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(results);
    CHECK_NULL(out);
    CHECK_NULL(state);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(ws);

    /* metadata_cache intentionally unused during sync — stale after fetch/pull.
     * Manifest operations load fresh metadata from updated Git state. */
    (void)workspace_get_metadata_cache(ws);

    output_section(out, "Syncing with remote");

    for (size_t i = 0; i < results->count; i++) {
        profile_sync_result_t *result = &results->profiles[i];

        /* Skip failed analysis */
        if (result->failed) {
            output_error(out, "  %s: %s", result->profile_name, result->error_message);
            continue;
        }

        /* Handle based on state */
        switch (result->state) {
            case UPSTREAM_UP_TO_DATE: {
                if (verbose) {
                    char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
                    output_info(out, "= %s: up-to-date", colored ? colored : result->profile_name);
                    free(colored);
                }
                break;
            }

            case UPSTREAM_LOCAL_AHEAD: {
                /* theirs: discard local commits, reset to remote */
                if (diverged_strategy == DIVERGE_THEIRS) {
                    char *colored = output_colorize(out, OUTPUT_COLOR_YELLOW, result->profile_name);
                    output_info(out, "↑ %s: %zu commit%s ahead of remote",
                                colored ? colored : result->profile_name,
                                result->ahead, result->ahead == 1 ? "" : "s");
                    free(colored);
                    error_t *err = handle_diverged_theirs(
                        repo, remote_name, result, results, out,
                        confirm_destructive, state, enabled_profiles
                    );
                    if (err) {
                        return err;
                    }
                    break;
                }

                /* Safe to push - local has new commits */
                if (verbose) {
                    output_info(out, "Pushing %s (%zu commit%s)...",
                           result->profile_name, result->ahead, result->ahead == 1 ? "" : "s");
                }

                error_t *err = gitops_push_branch(repo, remote_name, result->profile_name, xfer);
                if (err) {
                    output_error(out, "✗ %s: push failed - %s",
                                result->profile_name, error_message(err));
                    mark_result_failed(result, results, err);
                } else {
                    result->pushed = true;
                    results->pushed_count++;
                    char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
                    output_success(out, "%s: pushed %zu commit%s",
                           colored ? colored : result->profile_name,
                           result->ahead, result->ahead == 1 ? "" : "s");
                    free(colored);
                }
                break;
            }

            case UPSTREAM_NO_REMOTE: {
                /* Remote branch doesn't exist - create it */
                if (verbose) {
                    output_info(out, "Creating remote branch %s...", result->profile_name);
                }

                error_t *err = gitops_push_branch(repo, remote_name, result->profile_name, xfer);
                if (err) {
                    output_error(out, "✗ %s: failed to create remote branch - %s",
                                 result->profile_name, error_message(err));
                    mark_result_failed(result, results, err);
                } else {
                    result->pushed = true;
                    results->pushed_count++;
                    char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
                    output_success(out, "%s: created remote branch",
                           colored ? colored : result->profile_name);
                    free(colored);
                }
                break;
            }

            case UPSTREAM_REMOTE_AHEAD: {
                /* ours: force push local, discard remote commits */
                if (diverged_strategy == DIVERGE_OURS) {
                    char *colored = output_colorize(out, OUTPUT_COLOR_YELLOW, result->profile_name);
                    output_info(out, "↓ %s: %zu remote commit%s ahead",
                                colored ? colored : result->profile_name,
                                result->behind, result->behind == 1 ? "" : "s");
                    free(colored);
                    error_t *err = handle_diverged_ours(
                        repo, remote_name, result, results, out,
                        confirm_destructive, xfer
                    );
                    if (err) {
                        return err;
                    }
                    /* Adjust: analyze phase counted this as needing pull */
                    if (results->need_pull_count > 0) {
                        results->need_pull_count--;
                    }
                    break;
                }
                handle_remote_ahead(
                    repo, remote_name, result, results, out, verbose,
                    auto_pull, state, enabled_profiles
                );
                break;
            }

            case UPSTREAM_DIVERGED: {
                error_t *err = handle_diverged(
                    repo, remote_name, result, results, out, diverged_strategy,
                    xfer, confirm_destructive, state, enabled_profiles
                );
                if (err) {
                    return err;  /* Critical rollback failure */
                }
                break;
            }

            case UPSTREAM_UNKNOWN: {
                output_warning(out, "  ? %s: state unknown", result->profile_name);
                break;
            }
        }
    }

    output_newline(out);
    return NULL;
}

/**
 * Sync command implementation
 */
error_t *cmd_sync(git_repository *repo, const cmd_sync_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Declare all resources, initialized to NULL */
    error_t *err = NULL;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;
    profile_list_t *workspace_profiles = NULL;
    profile_list_t *sync_profiles = NULL;
    sync_results_t *results = NULL;
    char *remote_name = NULL;
    char *remote_url = NULL;
    transfer_context_t *xfer = NULL;
    workspace_t *ws = NULL;
    state_t *state = NULL;
    string_array_t *enabled_profiles = NULL;
    char *current_branch = NULL;

    /* Verify main worktree is on dotta-worktree branch */
    err = gitops_current_branch(repo, &current_branch);
    if (err) {
        err = error_wrap(err, "Failed to get current branch");
        goto cleanup;
    }

    if (strcmp(current_branch, "dotta-worktree") != 0) {
        /* Create error before freeing current_branch to avoid use-after-free */
        err = ERROR(ERR_STATE_INVALID,
                    "Main worktree must be on 'dotta-worktree' branch (currently on '%s')\n"
                    "Hint: Run 'dotta git checkout dotta-worktree' to fix",
                    current_branch);
        goto cleanup;
    }
    free(current_branch);
    current_branch = NULL;

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        error_free(err);
        err = NULL;
        config = config_create_default();
        if (!config) {
            err = ERROR(ERR_MEMORY, "Failed to create default configuration");
            goto cleanup;
        }
    }

    /* Create output context from config */
    out = output_create_from_config(config);
    if (!out) {
        err = ERROR(ERR_MEMORY, "Failed to create output context");
        goto cleanup;
    }

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Load profiles
     * - workspace_profiles: ALWAYS persistent enabled profiles (for VWD scope)
     * - sync_profiles: CLI filter or shared pointer (for sync operations)
     */

    /* Phase 1: Load workspace profiles (ALWAYS persistent) */
    err = profile_resolve_for_workspace(repo, config->strict_mode, &workspace_profiles);
    if (err) {
        err = error_wrap(err, "Failed to resolve enabled profiles");
        goto cleanup;
    }

    if (workspace_profiles->count == 0) {
        err = ERROR(ERR_NOT_FOUND,
                    "No enabled profiles to sync\n"
                    "Hint: Run 'dotta profile enable <name>' to enable profiles\n"
                    "      Or run 'dotta profile list --remote' to see available profiles");
        goto cleanup;
    }

    /* Phase 2: Load sync profiles (CLI filter or shared pointer) */
    if (opts->profiles && opts->profile_count > 0) {
        /* User specified CLI filter */
        err = profile_resolve_for_operations(repo, opts->profiles, opts->profile_count,
                                             config->strict_mode, &sync_profiles);
        if (err) {
            err = error_wrap(err, "Failed to resolve sync profiles");
            goto cleanup;
        }

        /* Validate: filter profiles must be enabled in workspace */
        err = profile_validate_filter(workspace_profiles, sync_profiles);
        if (err) {
            goto cleanup;
        }
    } else {
        /* No CLI filter - share workspace profiles */
        sync_profiles = workspace_profiles;
    }

    /* Create results tracker */
    results = sync_results_create(sync_profiles->count);
    if (!results) {
        err = ERROR(ERR_MEMORY, "Failed to create results");
        goto cleanup;
    }

    /* Validate workspace - sync requires clean workspace (no uncommitted changes)
     *
     * CRITICAL: Use workspace_profiles (persistent) for VWD scope, NOT sync_profiles.
     * This ensures manifest scope matches state scope for accurate divergence detection.
     */
    workspace_load_t ws_opts = {
        .analyze_files = true,         /* Validate file state for uncommitted changes */
        .analyze_orphans = false,      /* Orphans are apply's concern, not sync's */
        .analyze_untracked = (config && config->auto_detect_new_files), /* Respect config */
        .analyze_directories = false,  /* Directory metadata is apply's concern */
        .analyze_encryption = false    /* Encryption is apply's concern */
    };
    /* Pass NULL for state - this is read-only validation, not a transactional operation.
     * State transaction opened later for manifest updates after sync completes. */
    err = workspace_load(repo, NULL, workspace_profiles, config, &ws_opts, &ws);
    if (err) {
        err = error_wrap(err, "Failed to load workspace");
        goto cleanup;
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
            case WORKSPACE_STATE_UNDEPLOYED:
            case WORKSPACE_STATE_ORPHANED:
            case WORKSPACE_STATE_RELEASED:
                /* Not sync's concern - handled by apply command */
                break;
        }
    }

    size_t uncommitted_count = modified_count + deleted_count + mode_diff_count +
                               type_diff_count + untracked_count;

    /* Check for uncommitted changes (fatal unless --force or user confirms) */
    if (uncommitted_count > 0 && !opts->force) {
        if (config->strict_mode) {
            /* Strict mode: Block with full diagnostic output */
            output_section(out, "Workspace has uncommitted changes");
            output_newline(out);

            /* Show what's uncommitted */
            if (modified_count > 0) {
                output_info(out, "  %zu modified file%s", modified_count,
                           modified_count == 1 ? "" : "s");
            }
            if (deleted_count > 0) {
                output_info(out, "  %zu deleted file%s", deleted_count,
                           deleted_count == 1 ? "" : "s");
            }
            if (mode_diff_count > 0) {
                output_info(out, "  %zu file%s with permission changes", mode_diff_count,
                           mode_diff_count == 1 ? "" : "s");
            }
            if (type_diff_count > 0) {
                output_info(out, "  %zu file%s with type changes", type_diff_count,
                           type_diff_count == 1 ? "" : "s");
            }
            if (untracked_count > 0) {
                output_info(out, "  %zu new untracked file%s", untracked_count,
                           untracked_count == 1 ? "" : "s");
            }

            output_newline(out);
            output_info(out, "Sync requires a clean workspace to prevent data loss.");
            output_newline(out);
            output_info(out, "Next steps:");
            output_info(out, "  1. Run 'dotta update' to commit these changes to profile branches");
            output_info(out, "  2. Then run 'dotta sync' to synchronize with remote");
            output_newline(out);
            output_info(out, "Or run 'dotta sync --force' to sync without committing local changes.");
            output_newline(out);

            err = ERROR(ERR_VALIDATION,
                        "Cannot sync with uncommitted changes (found %zu uncommitted file%s)",
                        uncommitted_count, uncommitted_count == 1 ? "" : "s");
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
        output_warning(out, "Workspace has %zu uncommitted change%s",
                      uncommitted_count, uncommitted_count == 1 ? "" : "s");

        /* Show breakdown in verbose mode */
        if (opts->verbose) {
            if (modified_count > 0) {
                output_info(out, "  %zu modified", modified_count);
            }
            if (deleted_count > 0) {
                output_info(out, "  %zu deleted", deleted_count);
            }
            if (mode_diff_count > 0) {
                output_info(out, "  %zu permission changes", mode_diff_count);
            }
            if (type_diff_count > 0) {
                output_info(out, "  %zu type changes", type_diff_count);
            }
            if (untracked_count > 0) {
                output_info(out, "  %zu untracked", untracked_count);
            }
        }

        output_newline(out);
        output_info(out, "Syncing before 'update' may hide remote conflicts.");
        output_hint(out, "Remote changes to the same files will be silently overwritten");
        output_hint_line(out, "when you run 'update'. Commit first to preserve conflict detection.");
        output_newline(out);

        /* Confirmation with safe defaults:
         * - Interactive: defaults to NO (user must explicitly type 'y')
         * - Non-interactive (CI/CD): refuses automatically
         */
        if (!output_confirm_or_default(out, "Continue anyway?", false, false)) {
            output_info(out, "Sync cancelled");
            output_hint(out, "Run 'dotta update' first to commit local changes");
            err = NULL;  /* User cancelled - clean exit, not an error */
            goto cleanup;
        }

        /* User confirmed - proceed with sync */
        if (opts->verbose) {
            output_info(out, "Proceeding with uncommitted changes (user confirmed)");
        }
        output_newline(out);
    }

    /* Exit early if dry run */
    if (opts->dry_run) {
        output_info(out, "Dry run: no changes made");
        err = NULL;
        goto cleanup;
    }

    /* Auto-detect remote */
    err = upstream_detect_remote(repo, &remote_name);
    if (err) {
        goto cleanup;
    }

    /* Create transfer context for progress reporting and credentials */
    git_remote *remote_obj = NULL;
    if (git_remote_lookup(&remote_obj, repo, remote_name) == 0) {
        const char *url = git_remote_url(remote_obj);
        if (url) {
            remote_url = strdup(url);
        }
        git_remote_free(remote_obj);
    }

    xfer = transfer_context_create(out, remote_url);
    free(remote_url);
    remote_url = NULL;
    if (!xfer) {
        err = ERROR(ERR_MEMORY, "Failed to create transfer context");
        goto cleanup;
    }

    /* Determine auto_pull setting: CLI --no-pull overrides config */
    bool auto_pull = opts->no_pull ? false : config->auto_pull;

    /* Determine divergence strategy: CLI overrides config */
    const char *strategy_str = opts->diverged ? opts->diverged : config->diverged_strategy;
    sync_divergence_strategy_t diverged_strategy;
    if (!parse_divergence_strategy(strategy_str, &diverged_strategy)) {
        err = ERROR(ERR_INVALID_ARG, "Invalid divergence strategy '%s' "
                    "(valid: warn, rebase, merge, ours, theirs)", strategy_str);
        goto cleanup;
    }

    /* Phase 1: Fetch enabled profiles from remote (use sync_profiles for operations) */
    err = sync_fetch_enabled_profiles(repo, remote_name, sync_profiles,
                                      results, out, opts->verbose, xfer);
    if (err) {
        goto cleanup;
    }

    /* Phase 2: Analyze branch states (use sync_profiles for operations) */
    err = sync_analyze_phase(repo, remote_name, sync_profiles, results, out);
    if (err) {
        goto cleanup;
    }

    /* Open state transaction for manifest updates during sync */
    err = state_load_for_update(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to open state transaction");
        goto cleanup;
    }

    /* Build enabled profiles array for manifest operations (use workspace_profiles) */
    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* Repair stale manifest before sync operations.
     *
     * If external Git changes moved a branch HEAD since the last dotta operation,
     * state entries have stale git_oid/blob_oid values. manifest_sync_diff() computes
     * a diff between old_oid (local HEAD before fetch) and new_oid (after merge). It
     * then calls sync_profile_git_oids() which updates ALL entries' git_oid to match
     * the new HEAD. This masks pre-existing staleness: files changed between the stale
     * state and the pre-fetch HEAD would have their git_oid updated (now matching HEAD)
     * but blob_oid unchanged (still from the stale commit). These entries become
     * permanently invisible to staleness detection — ghost entries with wrong blob_oid.
     *
     * Running repair first brings state in sync with the current local HEAD. Then
     * sync_diff operates on accurate state and only handles the remote changes. */
    if (enabled_profiles && enabled_profiles->count > 0) {
        manifest_repair_stats_t repair_stats = {0};
        err = manifest_repair_stale(repo, state, enabled_profiles, &repair_stats, NULL);
        if (err) {
            err = error_wrap(err, "Failed to repair stale manifest before sync");
            goto cleanup;
        }

        if (repair_stats.updated > 0 || repair_stats.released > 0) {
            output_info(out, "Synchronized %zu file%s, released %zu from management",
                        repair_stats.updated, repair_stats.updated == 1 ? "" : "s",
                        repair_stats.released);
        }
    }

    /* Phase 3: Sync with remote (push/pull/divergence handling) */
    err = sync_push_phase(repo, remote_name, results, out, opts->verbose,
                          auto_pull, diverged_strategy, xfer,
                          config->confirm_destructive, state, enabled_profiles, ws);
    if (err) {
        goto cleanup;
    }

    /* Commit manifest changes */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to save manifest changes");
        goto cleanup;
    }

    /* Final summary */
    output_section(out, "Sync complete");

    if (results->pushed_count > 0) {
        output_success(out, "%zu profile%s pushed",
                      results->pushed_count,
                      results->pushed_count == 1 ? "" : "s");
    }

    if (results->up_to_date_count > 0) {
        output_info(out, "%zu profile%s already up-to-date",
                   results->up_to_date_count,
                   results->up_to_date_count == 1 ? "" : "s");
    }

    if (results->need_pull_count > 0) {
        output_warning(out, "%zu profile%s need pull",
                      results->need_pull_count,
                      results->need_pull_count == 1 ? "" : "s");
    }

    if (results->diverged_count > 0) {
        output_warning(out, "%zu profile%s diverged (manual resolution needed)",
                      results->diverged_count,
                      results->diverged_count == 1 ? "" : "s");
    }

    if (results->failed_count > 0) {
        output_error(out, "%zu profile%s failed",
                    results->failed_count,
                    results->failed_count == 1 ? "" : "s");
    }

    if (results->fetch_failed_count > 0) {
        output_warning(out, "%zu fetch operation%s failed",
                      results->fetch_failed_count,
                      results->fetch_failed_count == 1 ? "" : "s");
    }

    if (results->auth_failed_count > 0) {
        output_error(out, "%zu authentication failure%s",
                    results->auth_failed_count,
                    results->auth_failed_count == 1 ? "" : "s");
    }

    /* Provide guidance on next steps if profiles were updated */
    size_t updated_count = results->pushed_count + (sync_profiles->count -
                                                    results->need_pull_count -
                                                    results->diverged_count -
                                                    results->failed_count -
                                                    results->up_to_date_count);
    if (updated_count > 0 && results->failed_count == 0) {
        output_newline(out);
        output_info(out, "Manifest updated with changes from remote");
        output_hint(out, "Run 'dotta status' to review staged changes");
        output_hint(out, "Run 'dotta apply' to deploy changes to filesystem");
    }

    /* Success - fall through to cleanup */
    err = NULL;

cleanup:
    /* Free resources in reverse order of allocation */
    if (current_branch) free(current_branch);
    if (enabled_profiles) string_array_free(enabled_profiles);
    if (state) state_free(state);
    if (ws) workspace_free(ws);
    if (xfer) transfer_context_free(xfer);
    if (remote_url) free(remote_url);
    if (remote_name) free(remote_name);
    if (results) sync_results_free(results);
    if (sync_profiles && sync_profiles != workspace_profiles) {
        profile_list_free(sync_profiles);
    }
    if (workspace_profiles) {
        profile_list_free(workspace_profiles);
    }
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}
