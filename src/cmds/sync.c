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
    size_t fetch_failed_count;      /* Track fetch failures separately */
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
 */
static sync_divergence_strategy_t parse_divergence_strategy(const char *str, output_ctx_t *out) {
    if (!str) {
        return DIVERGE_WARN;
    }

    if (strcmp(str, "rebase") == 0) {
        return DIVERGE_REBASE;
    } else if (strcmp(str, "merge") == 0) {
        return DIVERGE_MERGE;
    } else if (strcmp(str, "ours") == 0) {
        return DIVERGE_OURS;
    } else if (strcmp(str, "theirs") == 0) {
        return DIVERGE_THEIRS;
    } else if (strcmp(str, "warn") == 0) {
        return DIVERGE_WARN;
    }

    /* Invalid strategy - warn user and fall back to safe default */
    if (out) {
        output_warning(out, "Invalid divergence strategy '%s' (valid: warn, rebase, merge, ours, theirs)", str);
        output_info(out, "Falling back to 'warn' (safe default)");
    }
    return DIVERGE_WARN;  /* Default */
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
    snprintf(refspec, sizeof(refspec), "+refs/heads/%s:refs/heads/%s", branch_name, branch_name);

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

    err = gitops_build_refname(local_refname, sizeof(local_refname), "refs/heads/%s", branch_name);
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    err = gitops_build_refname(remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s", remote_name, branch_name);
    if (err) {
        return error_wrap(err, "Invalid remote/branch name '%s/%s'", remote_name, branch_name);
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
        return ERROR(ERR_NOT_FOUND,
                    "No remote '%s' configured\n"
                    "Hint: Run 'dotta remote add %s <url>' to add a remote",
                    remote_name, remote_name);
    } else if (git_err < 0) {
        return error_from_git(git_err);
    }
    git_remote_free(remote);

    char section_title[DOTTA_MESSAGE_MAX];
    snprintf(section_title, sizeof(section_title), "Fetching enabled profiles from '%s'", remote_name);
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

        return ERROR(ERR_GIT,
                    "Failed to fetch profiles from remote\n"
                    "Hint: Check network connectivity and remote accessibility");
    }

    if (verbose) {
        output_success(out, "Fetched %zu enabled profile%s",
                      profiles->count,
                      profiles->count == 1 ? "" : "s");
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
        error_t *err = upstream_analyze_profile(repo, remote_name, profile->name, &info);

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
 * Phase 3: Sync branches with remote (push/pull/divergence handling)
 *
 * Now includes manifest synchronization when branches are updated via
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

    /* Extract cached resources from workspace for manifest operations */
    keymanager_t *km = workspace_get_keymanager(ws);
    const hashmap_t *metadata_cache = workspace_get_metadata_cache(ws);
    content_cache_t *content_cache = workspace_get_content_cache(ws);

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
            case UPSTREAM_UP_TO_DATE:
                if (verbose) {
                    char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
                    output_info(out, "= %s: up-to-date", colored ? colored : result->profile_name);
                    free(colored);
                }
                break;

            case UPSTREAM_LOCAL_AHEAD: {
                /* Safe to push - local has new commits */
                if (verbose) {
                    output_info(out, "Pushing %s (%zu commit%s)...",
                           result->profile_name,
                           result->ahead, result->ahead == 1 ? "" : "s");
                }

                error_t *err = gitops_push_branch(repo, remote_name, result->profile_name, xfer);
                if (err) {
                    result->failed = true;
                    result->error_message = strdup(error_message(err));
                    results->failed_count++;
                    output_error(out, "✗ %s: push failed - %s",
                                result->profile_name, error_message(err));
                    error_free(err);
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
                    result->failed = true;
                    result->error_message = strdup(error_message(err));
                    results->failed_count++;
                    output_error(out, "✗ %s: failed to create remote branch - %s",
                                result->profile_name, error_message(err));
                    error_free(err);
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
                if (auto_pull) {
                    /* Auto-pull when safe (fast-forward only) */
                    if (verbose) {
                        output_info(out, "Pulling %s (%zu commit%s behind)...",
                               result->profile_name,
                               result->behind, result->behind == 1 ? "" : "s");
                    }

                    bool pulled = false;
                    git_oid old_oid, new_oid;
                    error_t *err = pull_branch_ff(repo, remote_name, result->profile_name, &pulled, &old_oid, &new_oid);
                    if (err) {
                        result->failed = true;
                        result->error_message = strdup(error_message(err));
                        results->failed_count++;
                        output_error(out, "✗ %s: pull failed - %s",
                                    result->profile_name, error_message(err));
                        error_free(err);
                    } else if (pulled) {
                        /* Pull succeeded - decrement need_pull_count since we resolved it */
                        if (results->need_pull_count > 0) {
                            results->need_pull_count--;
                        }

                        /* Update manifest with changes from pull */
                        size_t synced = 0, removed = 0, fallbacks = 0;
                        error_t *manifest_err = manifest_sync_diff(
                            repo, state, result->profile_name,
                            &old_oid, &new_oid, enabled_profiles,
                            km, metadata_cache, content_cache,
                            &synced, &removed, &fallbacks
                        );

                        if (manifest_err) {
                            /* Log warning but don't fail - Git succeeded, manifest can be recovered */
                            output_warning(out, "   Manifest sync failed: %s", error_message(manifest_err));
                            output_hint(out, "   Run 'dotta status' or 'dotta apply' to resync manifest");
                            error_free(manifest_err);
                        }

                        char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
                        if (manifest_err) {
                            output_success(out, "%s: pulled %zu commit%s (manifest sync failed)",
                                   colored ? colored : result->profile_name,
                                   result->behind, result->behind == 1 ? "" : "s");
                        } else {
                            output_success(out, "%s: pulled %zu commit%s (%zu staged, %zu removed, %zu fallback%s)",
                                   colored ? colored : result->profile_name,
                                   result->behind, result->behind == 1 ? "" : "s",
                                   synced, removed, fallbacks, fallbacks == 1 ? "" : "s");
                        }
                        free(colored);
                    } else {
                        /* Already up-to-date - report in verbose mode */
                        if (verbose) {
                            char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
                            output_info(out, "= %s: already up-to-date",
                                   colored ? colored : result->profile_name);
                            free(colored);
                        }
                        /* Decrement need_pull_count since it was already up-to-date */
                        if (results->need_pull_count > 0) {
                            results->need_pull_count--;
                        }
                    }
                } else {
                    /* Just warn - don't auto-pull */
                    char *colored = output_colorize(out, OUTPUT_COLOR_YELLOW, result->profile_name);
                    output_info(out, "↓ %s: remote has %zu new commit%s",
                           colored ? colored : result->profile_name,
                           result->behind, result->behind == 1 ? "" : "s");
                    output_hint(out, "   Run 'dotta pull' or enable auto_pull in config to automatically pull");
                    free(colored);
                }
                break;
            }

            case UPSTREAM_DIVERGED: {
                /* Handle divergence based on strategy */
                char *colored = output_colorize(out, OUTPUT_COLOR_RED, result->profile_name);
                output_warning(out, "⚠ %s: diverged (%zu local, %zu remote commits)",
                       colored ? colored : result->profile_name,
                       result->ahead, result->behind);
                free(colored);

                error_t *err = NULL;
                switch (diverged_strategy) {
                    case DIVERGE_WARN:
                        output_hint(out, "   Use --diverged=<strategy> or set sync.diverged_strategy in config");
                        output_hint_line(out, "   Strategies: rebase, merge, ours (keep local), theirs (keep remote)");
                        results->diverged_count++;
                        break;

                    case DIVERGE_REBASE:
                    {
                        output_info(out, "   Resolving with rebase strategy...");

                        /* Initialize divergence context */
                        divergence_context_t ctx;
                        err = divergence_context_init(&ctx, repo, remote_name, result->profile_name,
                                                      DIVERGENCE_STRATEGY_REBASE);
                        if (err) {
                            output_error(out, "   ✗ Failed to initialize divergence context: %s",
                                        error_message(err));
                            error_free(err);
                            break;
                        }

                        /* Perform in-memory rebase (never modifies HEAD) */
                        git_oid new_oid;
                        err = divergence_resolve(&ctx, &new_oid);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "   ✗ Rebase failed: %s", error_message(err));
                            error_free(err);
                        } else {
                            /* Verify rebase succeeded */
                            size_t ahead = 0;
                            err = divergence_verify(&ctx, &ahead, NULL);
                            if (err) {
                                result->failed = true;
                                result->error_message = strdup(error_message(err));
                                results->failed_count++;
                                output_error(out, "   ✗ Rebase verification failed: %s", error_message(err));
                                error_free(err);
                                /* Rollback */
                                err = divergence_rollback(&ctx);
                                if (err) {
                                    output_error(out, "   ✗ CRITICAL: Rollback failed: %s", error_message(err));
                                    output_newline(out);
                                    error_t *rollback_err = error_wrap(err,
                                        "Failed to rollback branch '%s' after rebase verification failure.\n"
                                        "Repository may be in an inconsistent state.\n"
                                        "Manual intervention required: git reset --hard origin/%s",
                                        result->profile_name, result->profile_name);
                                    return rollback_err;
                                } else {
                                    output_info(out, "   ↺ Rolled back to original state");
                                }
                            } else {
                                output_success(out, "   Successfully rebased onto remote (%zu commit%s to push)",
                                       ahead, ahead == 1 ? "" : "s");

                                /* Now push the rebased commits */
                                err = gitops_push_branch(repo, remote_name, result->profile_name, xfer);
                                if (err) {
                                    result->failed = true;
                                    result->error_message = strdup(error_message(err));
                                    results->failed_count++;
                                    output_error(out, "   ✗ Push after rebase failed: %s", error_message(err));
                                    error_free(err);
                                    /* Rollback since push failed */
                                    output_info(out, "   ↺ Rolling back rebase (push failed)...");
                                    err = divergence_rollback(&ctx);
                                    if (err) {
                                        output_error(out, "   ✗ CRITICAL: Rollback failed: %s", error_message(err));
                                        output_newline(out);
                                        error_t *rollback_err = error_wrap(err,
                                            "Failed to rollback branch '%s' after push failure.\n"
                                            "Repository may be in an inconsistent state.\n"
                                            "Manual intervention required: git reset --hard origin/%s",
                                            result->profile_name, result->profile_name);
                                        return rollback_err;
                                    } else {
                                        output_success(out, "   Rolled back to original state");
                                    }
                                } else {
                                    output_success(out, "   Pushed rebased commits");
                                    result->pushed = true;
                                    results->pushed_count++;

                                    /* Update manifest with changes from rebase */
                                    size_t synced = 0, removed = 0, fallbacks = 0;
                                    error_t *manifest_err = manifest_sync_diff(
                                        repo, state, result->profile_name,
                                        &ctx.saved_oid, &new_oid, enabled_profiles,
                                        km, metadata_cache, content_cache,
                                        &synced, &removed, &fallbacks
                                    );

                                    if (manifest_err) {
                                        output_warning(out, "   Manifest sync failed: %s", error_message(manifest_err));
                                        output_hint(out, "   Run 'dotta status' or 'dotta apply' to resync manifest");
                                        error_free(manifest_err);
                                    } else if (synced > 0 || removed > 0 || fallbacks > 0) {
                                        output_info(out, "   Manifest: %zu staged, %zu removed, %zu fallback%s",
                                                   synced, removed, fallbacks, fallbacks == 1 ? "" : "s");
                                    }
                                }
                            }
                        }
                        break;
                    }

                    case DIVERGE_MERGE:
                    {
                        output_info(out, "   Resolving with merge strategy...");

                        /* Initialize divergence context */
                        divergence_context_t ctx;
                        err = divergence_context_init(&ctx, repo, remote_name, result->profile_name,
                                                      DIVERGENCE_STRATEGY_MERGE);
                        if (err) {
                            output_error(out, "   ✗ Failed to initialize divergence context: %s",
                                        error_message(err));
                            error_free(err);
                            break;
                        }

                        /* Perform tree-based merge (never modifies HEAD) */
                        git_oid new_oid;
                        err = divergence_resolve(&ctx, &new_oid);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "   ✗ Merge failed: %s", error_message(err));
                            error_free(err);
                        } else {
                            /* Verify merge succeeded */
                            size_t ahead = 0;
                            err = divergence_verify(&ctx, &ahead, NULL);
                            if (err) {
                                result->failed = true;
                                result->error_message = strdup(error_message(err));
                                results->failed_count++;
                                output_error(out, "   ✗ Merge verification failed: %s", error_message(err));
                                error_free(err);
                                /* Rollback */
                                err = divergence_rollback(&ctx);
                                if (err) {
                                    output_error(out, "   ✗ CRITICAL: Rollback failed: %s", error_message(err));
                                    output_newline(out);
                                    error_t *rollback_err = error_wrap(err,
                                        "Failed to rollback branch '%s' after merge verification failure.\n"
                                        "Repository may be in an inconsistent state.\n"
                                        "Manual intervention required: git reset --hard origin/%s",
                                        result->profile_name, result->profile_name);
                                    return rollback_err;
                                } else {
                                    output_info(out, "   ↺ Rolled back to original state");
                                }
                            } else {
                                output_success(out, "   Successfully merged with remote (%zu commit%s to push)",
                                       ahead, ahead == 1 ? "" : "s");

                                /* Now push the merge commit */
                                err = gitops_push_branch(repo, remote_name, result->profile_name, xfer);
                                if (err) {
                                    result->failed = true;
                                    result->error_message = strdup(error_message(err));
                                    results->failed_count++;
                                    output_error(out, "   ✗ Push after merge failed: %s", error_message(err));
                                    error_free(err);
                                    /* Rollback since push failed */
                                    output_info(out, "   ↺ Rolling back merge (push failed)...");
                                    err = divergence_rollback(&ctx);
                                    if (err) {
                                        output_error(out, "   ✗ CRITICAL: Rollback failed: %s", error_message(err));
                                        output_newline(out);
                                        error_t *rollback_err = error_wrap(err,
                                            "Failed to rollback branch '%s' after push failure.\n"
                                            "Repository may be in an inconsistent state.\n"
                                            "Manual intervention required: git reset --hard origin/%s",
                                            result->profile_name, result->profile_name);
                                        return rollback_err;
                                    } else {
                                        output_success(out, "   Rolled back to original state");
                                    }
                                } else {
                                    output_success(out, "   Pushed merge commit");
                                    result->pushed = true;
                                    results->pushed_count++;

                                    /* Update manifest with changes from merge */
                                    size_t synced = 0, removed = 0, fallbacks = 0;
                                    error_t *manifest_err = manifest_sync_diff(
                                        repo, state, result->profile_name,
                                        &ctx.saved_oid, &new_oid, enabled_profiles,
                                        km, metadata_cache, content_cache,
                                        &synced, &removed, &fallbacks
                                    );

                                    if (manifest_err) {
                                        output_warning(out, "   Manifest sync failed: %s", error_message(manifest_err));
                                        output_hint(out, "   Run 'dotta status' or 'dotta apply' to resync manifest");
                                        error_free(manifest_err);
                                    } else if (synced > 0 || removed > 0 || fallbacks > 0) {
                                        output_info(out, "   Manifest: %zu staged, %zu removed, %zu fallback%s",
                                                   synced, removed, fallbacks, fallbacks == 1 ? "" : "s");
                                    }
                                }
                            }
                        }
                        break;
                    }

                    case DIVERGE_OURS:
                    {
                        output_info(out, "   Resolving with 'ours' strategy (force push)...");

                        /* Get user confirmation for destructive operation */
                        if (confirm_destructive) {
                            char prompt[DOTTA_MESSAGE_MAX];
                            snprintf(prompt, sizeof(prompt),
                                    "WARNING: This will force push and OVERWRITE remote '%s'.\n"
                                    "Remote commits will be LOST. Continue?", result->profile_name);
                            bool confirmed = output_confirm_or_default(out, prompt, false, false);
                            if (!confirmed) {
                                output_info(out, "   Operation cancelled by user");
                                break;
                            }
                        }

                        /* Initialize divergence context (saves current state for rollback) */
                        divergence_context_t ctx;
                        err = divergence_context_init(&ctx, repo, remote_name, result->profile_name,
                                                      DIVERGENCE_STRATEGY_OURS);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "   ✗ Failed to initialize divergence context: %s",
                                        error_message(err));
                            error_free(err);
                            break;
                        }

                        /* Resolve divergence (for OURS, this is a no-op - local stays unchanged) */
                        err = divergence_resolve(&ctx, NULL);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "   ✗ Resolution failed: %s", error_message(err));
                            error_free(err);
                            break;
                        }

                        /* Force push to remote */
                        err = force_push_branch(repo, remote_name, result->profile_name, xfer);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "   ✗ Force push failed: %s", error_message(err));
                            error_free(err);
                        } else {
                            output_success(out, "   Force pushed to remote (remote commits discarded)");
                            result->pushed = true;
                            results->pushed_count++;
                        }
                        break;
                    }

                    case DIVERGE_THEIRS:
                    {
                        output_info(out, "   Resolving with 'theirs' strategy (reset to remote)...");

                        /* Get user confirmation for destructive operation */
                        if (confirm_destructive) {
                            char prompt[DOTTA_MESSAGE_MAX];
                            snprintf(prompt, sizeof(prompt),
                                    "WARNING: This will reset '%s' to remote and DISCARD local commits.\n"
                                    "Local changes will be LOST. Continue?", result->profile_name);
                            bool confirmed = output_confirm_or_default(out, prompt, false, false);
                            if (!confirmed) {
                                output_info(out, "   Operation cancelled by user");
                                break;
                            }
                        }

                        /* Initialize divergence context (saves current state for rollback) */
                        divergence_context_t ctx;
                        err = divergence_context_init(&ctx, repo, remote_name, result->profile_name,
                                                      DIVERGENCE_STRATEGY_THEIRS);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "   ✗ Failed to initialize divergence context: %s",
                                        error_message(err));
                            error_free(err);
                            break;
                        }

                        /* Resolve divergence (resets local branch to remote) */
                        git_oid new_oid;
                        err = divergence_resolve(&ctx, &new_oid);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "   ✗ Reset failed: %s", error_message(err));
                            error_free(err);
                        } else {
                            /* Verify reset succeeded */
                            err = divergence_verify(&ctx, NULL, NULL);
                            if (err) {
                                result->failed = true;
                                result->error_message = strdup(error_message(err));
                                results->failed_count++;
                                output_error(out, "   ✗ Reset verification failed: %s", error_message(err));
                                output_warning(out, "   Local branch was reset but verification failed");
                                error_free(err);
                            } else {
                                output_success(out, "   Reset to remote (local commits discarded)");
                                /* No push needed - local is now at remote */

                                /* Update manifest with changes from reset */
                                size_t synced = 0, removed = 0, fallbacks = 0;
                                error_t *manifest_err = manifest_sync_diff(
                                    repo, state, result->profile_name,
                                    &ctx.saved_oid, &new_oid, enabled_profiles,
                                    km, metadata_cache, content_cache,
                                    &synced, &removed, &fallbacks
                                );

                                if (manifest_err) {
                                    output_warning(out, "   Manifest sync failed: %s", error_message(manifest_err));
                                    output_hint(out, "   Run 'dotta status' or 'dotta apply' to resync manifest");
                                    error_free(manifest_err);
                                } else if (synced > 0 || removed > 0 || fallbacks > 0) {
                                    output_info(out, "   Manifest: %zu staged, %zu removed, %zu fallback%s",
                                               synced, removed, fallbacks, fallbacks == 1 ? "" : "s");
                                }
                            }
                        }
                        break;
                    }
                }
                break;
            }

            case UPSTREAM_UNKNOWN:
                /* Skip profiles with unknown state */
                output_warning(out, "  ? %s: state unknown", result->profile_name);
                break;
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

    error_t *err = NULL;
    dotta_config_t *config = NULL;
    profile_list_t *profiles = NULL;
    sync_results_t *results = NULL;
    char *remote_name = NULL;

    /* Verify main worktree is on dotta-worktree branch */
    char *current_branch = NULL;
    err = gitops_current_branch(repo, &current_branch);
    if (err) {
        return error_wrap(err, "Failed to get current branch");
    }

    if (strcmp(current_branch, "dotta-worktree") != 0) {
        free(current_branch);
        return ERROR(ERR_STATE_INVALID,
                    "Main worktree must be on 'dotta-worktree' branch (currently on '%s')\n"
                    "Hint: Run 'git checkout dotta-worktree' to fix",
                    current_branch);
    }
    free(current_branch);

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        error_free(err);
        err = NULL;
        config = config_create_default();
    }

    /* Create output context from config */
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Load enabled profiles using standard profile resolution
     * Priority: CLI -p (temporary) > state (persistent management)
     */
    profile_source_t source;
    err = profile_resolve(repo, opts->profiles, opts->profile_count,
                         config->strict_mode, &profiles, &source);
    if (err) {
        config_free(config);
        output_free(out);
        return error_wrap(err, "Failed to resolve enabled profiles");
    }

    /* Provide helpful error when no enabled profiles */
    if (profiles->count == 0) {
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return ERROR(ERR_NOT_FOUND,
                    "No enabled profiles to sync\n"
                    "Hint: Run 'dotta profile enable <name>' to enable profiles\n"
                    "      Or run 'dotta profile list --remote' to see available profiles");
    }

    /* Create results tracker */
    results = sync_results_create(profiles->count);
    if (!results) {
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return ERROR(ERR_MEMORY, "Failed to create results");
    }

    /* Validate workspace - sync requires clean workspace (no uncommitted changes) */
    workspace_t *ws = NULL;
    workspace_load_t ws_opts = {
        .analyze_files = true,         /* Validate file state */
        .analyze_orphans = true,       /* Validate no orphans */
        .analyze_untracked = (config && config->auto_detect_new_files), /* Respect config */
        .analyze_directories = false,  /* Don't block sync on directory metadata */
        .analyze_encryption = false    /* Encryption checked during deployment, not here */
    };
    err = workspace_load(repo, profiles, config, &ws_opts, &ws);
    if (err) {
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return error_wrap(err, "Failed to load workspace");
    }

    /* Count all types of divergence */
    size_t all_diverged_count = 0;
    const workspace_item_t *all_diverged = workspace_get_all_diverged(ws, &all_diverged_count);

    size_t modified_count = 0;    /* DEPLOYED with CONTENT divergence */
    size_t deleted_count = 0;     /* DELETED state */
    size_t mode_diff_count = 0;   /* DEPLOYED with MODE divergence */
    size_t type_diff_count = 0;   /* DEPLOYED with TYPE divergence */
    size_t untracked_count = 0;   /* UNTRACKED state */
    size_t undeployed_count = 0;  /* UNDEPLOYED state */
    size_t orphaned_count = 0;    /* ORPHANED state */

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
                undeployed_count++;
                break;
            case WORKSPACE_STATE_ORPHANED:
                orphaned_count++;
                break;
        }
    }

    size_t uncommitted_count = modified_count + deleted_count + mode_diff_count +
                               type_diff_count + untracked_count;

    /* Check for uncommitted changes (fatal unless --force) */
    if (uncommitted_count > 0 && !opts->force) {
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

        workspace_free(ws);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return ERROR(ERR_VALIDATION,
                    "Cannot sync with uncommitted changes (found %zu uncommitted file%s)",
                    uncommitted_count, uncommitted_count == 1 ? "" : "s");
    }

    /* Warn about undeployed files (non-fatal) */
    if (undeployed_count > 0) {
        output_warning(out, "Workspace has %zu undeployed file%s",
                      undeployed_count, undeployed_count == 1 ? "" : "s");
        output_info(out, "These files exist in profiles but have never been deployed.");
        output_info(out, "Run 'dotta apply' after sync to deploy them.");
        output_newline(out);
    }

    /* Warn about orphaned state entries (non-fatal) */
    if (orphaned_count > 0) {
        output_warning(out, "Workspace has %zu orphaned state entr%s",
                      orphaned_count, orphaned_count == 1 ? "y" : "ies");
        output_info(out, "These are state entries for files no longer in any profile.");
        output_info(out, "Run 'dotta status' for details.");
        output_newline(out);
    }

    /* NOTE: Keep workspace alive - needed for manifest sync resources */

    /* Exit early if dry run */
    if (opts->dry_run) {
        output_info(out, "Dry run: no changes made");
        workspace_free(ws);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return NULL;
    }

    /* Auto-detect remote */
    err = upstream_detect_remote(repo, &remote_name);
    if (err) {
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return err;
    }

    /* Create transfer context for progress reporting and credentials */
    git_remote *remote_obj = NULL;
    char *remote_url = NULL;
    if (git_remote_lookup(&remote_obj, repo, remote_name) == 0) {
        const char *url = git_remote_url(remote_obj);
        if (url) {
            remote_url = strdup(url);
        }
        git_remote_free(remote_obj);
    }

    transfer_context_t *xfer = transfer_context_create(out, remote_url);
    free(remote_url);
    if (!xfer) {
        free(remote_name);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return ERROR(ERR_MEMORY, "Failed to create transfer context");
    }

    /* Determine auto_pull setting: CLI --no-pull overrides config */
    bool auto_pull = opts->no_pull ? false : config->auto_pull;

    /* Determine divergence strategy: CLI overrides config */
    sync_divergence_strategy_t diverged_strategy = parse_divergence_strategy(
        opts->diverged ? opts->diverged : config->diverged_strategy,
        out
    );

    /* Phase 1: Fetch enabled profiles from remote */
    err = sync_fetch_enabled_profiles(repo, remote_name, profiles, results, out, opts->verbose, xfer);
    if (err) {
        transfer_context_free(xfer);
        free(remote_name);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return err;
    }

    /* Phase 2: Analyze branch states */
    err = sync_analyze_phase(repo, remote_name, profiles, results, out);
    if (err) {
        transfer_context_free(xfer);
        free(remote_name);
        workspace_free(ws);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return err;
    }

    /* Open state transaction for manifest updates during sync */
    state_t *state = NULL;
    err = state_load_for_update(repo, &state);
    if (err) {
        transfer_context_free(xfer);
        free(remote_name);
        workspace_free(ws);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return error_wrap(err, "Failed to open state transaction");
    }

    /* Build enabled profiles array for manifest operations */
    string_array_t *enabled_profiles = NULL;
    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        state_free(state);
        transfer_context_free(xfer);
        free(remote_name);
        workspace_free(ws);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return error_wrap(err, "Failed to get enabled profiles");
    }

    /* Phase 3: Sync with remote (push/pull/divergence handling) */
    err = sync_push_phase(repo, remote_name, results, out, opts->verbose,
                          auto_pull, diverged_strategy, xfer,
                          config->confirm_destructive, state, enabled_profiles, ws);
    if (err) {
        string_array_free(enabled_profiles);
        state_free(state);  /* Rolls back transaction on error */
        transfer_context_free(xfer);
        free(remote_name);
        workspace_free(ws);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return err;
    }

    /* Commit manifest changes */
    err = state_save(repo, state);
    if (err) {
        string_array_free(enabled_profiles);
        state_free(state);  /* Rolls back transaction on save failure */
        transfer_context_free(xfer);
        free(remote_name);
        workspace_free(ws);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return error_wrap(err, "Failed to save manifest changes");
    }

    /* Cleanup */
    string_array_free(enabled_profiles);
    state_free(state);
    workspace_free(ws);
    transfer_context_free(xfer);
    free(remote_name);

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
    size_t updated_count = results->pushed_count + (profiles->count - results->need_pull_count - results->diverged_count - results->failed_count - results->up_to_date_count);
    if (updated_count > 0 && results->failed_count == 0) {
        output_newline(out);
        output_info(out, "Manifest updated with changes from sync.");
        output_hint(out, "   Run 'dotta status' to review staged changes");
        output_hint(out, "   Run 'dotta apply' to deploy changes to filesystem");
    }

    /* Cleanup */
    sync_results_free(results);
    profile_list_free(profiles);
    config_free(config);
        output_free(out);

    return NULL;
}
