/**
 * profile.c - Profile lifecycle management
 *
 * Explicit profile management commands for controlling which profiles
 * are enabled vs merely available on this machine.
 */

#include "profile.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "base/transfer.h"
#include "core/profiles.h"
#include "core/state.h"
#include "core/upstream.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"

/**
 * Count files in profile
 *
 * @param repo Repository (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param count Output file count (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *count_profile_files(git_repository *repo, const char *profile_name, size_t *count) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(count);

    profile_t *profile = NULL;
    error_t *err = profile_load(repo, profile_name, &profile);
    if (err) {
        return error_wrap(err, "Failed to load profile");
    }

    string_array_t *files = NULL;
    err = profile_list_files(repo, profile, &files);
    if (err) {
        profile_free(profile);
        return error_wrap(err, "Failed to list files");
    }

    *count = string_array_size(files);
    string_array_free(files);
    profile_free(profile);
    return NULL;
}

/**
 * Profile list subcommand
 *
 * Shows enabled vs available profiles with clear visual distinction.
 */
static error_t *profile_list(
    git_repository *repo,
    const cmd_profile_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup */
    state_t *state = NULL;
    string_array_t *enabled_profiles = NULL;
    string_array_t *all_branches = NULL;
    string_array_t *available = NULL;
    char *remote_name = NULL;
    char *remote_url = NULL;
    git_remote *remote_obj = NULL;
    transfer_context_t *xfer = NULL;
    string_array_t *remote_branches = NULL;
    string_array_t *remote_only = NULL;
    error_t *err = NULL;

    /* Load state to get enabled profiles */
    err = state_load(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to load state");
        goto cleanup;
    }

    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* Get all local branches */
    err = gitops_list_branches(repo, &all_branches);
    if (err) {
        err = error_wrap(err, "Failed to list branches");
        goto cleanup;
    }

    /* Separate into enabled and available */
    available = string_array_create();
    if (!available) {
        err = ERROR(ERR_MEMORY, "Failed to create array");
        goto cleanup;
    }

    for (size_t i = 0; i < string_array_size(all_branches); i++) {
        const char *name = string_array_get(all_branches, i);

        /* Skip dotta-worktree */
        if (strcmp(name, "dotta-worktree") == 0) {
            continue;
        }

        /* Check if enabled */
        bool is_enabled = false;
        for (size_t j = 0; j < string_array_size(enabled_profiles); j++) {
            if (strcmp(string_array_get(enabled_profiles, j), name) == 0) {
                is_enabled = true;
                break;
            }
        }

        if (!is_enabled) {
            err = string_array_push(available, name);
            if (err) {
                err = error_wrap(err, "Failed to add profile to available list");
                goto cleanup;
            }
        }
    }

    /* Print enabled profiles */
    if (string_array_size(enabled_profiles) > 0) {
        output_section(out, "Enabled profiles (in layering order)");
        for (size_t i = 0; i < string_array_size(enabled_profiles); i++) {
            const char *name = string_array_get(enabled_profiles, i);
            size_t file_count = 0;
            error_t *count_err = count_profile_files(repo, name, &file_count);

            /* Show file counts if available, otherwise indicate error */
            if (count_err) {
                output_printf(out, OUTPUT_NORMAL, "  %zu. %s (file count unavailable)\n", i + 1, name);
                error_free(count_err);
            } else {
                output_printf(out, OUTPUT_NORMAL, "  %zu. %s (%zu file%s)\n",
                       i + 1, name, file_count, file_count == 1 ? "" : "s");
            }
        }
        output_newline(out);
    } else {
        output_info(out, "No enabled profiles");
        output_info(out, "Hint: Run 'dotta profile enable <name>' to enable a profile\n");
    }

    /* Print available (disabled) profiles */
    if (string_array_size(available) > 0 && opts->show_available) {
        output_section(out, "Available (disabled)");
        for (size_t i = 0; i < string_array_size(available); i++) {
            const char *name = string_array_get(available, i);
            size_t file_count = 0;
            error_t *count_err = count_profile_files(repo, name, &file_count);

            /* Show file counts if available, otherwise indicate error */
            if (count_err) {
                output_printf(out, OUTPUT_NORMAL, "  • %s (file count unavailable)\n", name);
                error_free(count_err);
            } else {
                output_printf(out, OUTPUT_NORMAL, "  • %s (%zu file%s)\n",
                       name, file_count, file_count == 1 ? "" : "s");
            }
        }
        output_newline(out);
    }

    /* Show remote profiles if requested */
    if (opts->show_remote) {
        error_t *remote_err = upstream_detect_remote(repo, &remote_name);
        if (remote_err) {
            output_warning(out, "Could not detect remote: %s", error_message(remote_err));
            error_free(remote_err);
        } else {
            /* Get remote URL for credential handling */
            if (git_remote_lookup(&remote_obj, repo, remote_name) == 0) {
                const char *url = git_remote_url(remote_obj);
                if (url) {
                    remote_url = strdup(url);
                }
                git_remote_free(remote_obj);
                remote_obj = NULL;
            }

            /* Create transfer context for credentials */
            xfer = transfer_context_create(out, remote_url);
            if (!xfer) {
                output_warning(out, "Failed to create transfer context");
            } else {
                /*
                 * Query remote server for available branches (network operation)
                 * This contacts the remote server to get the current list of profiles,
                 * ensuring we see newly added profiles that haven't been fetched yet.
                 */
                remote_err = upstream_query_remote_branches(repo, remote_name, xfer->cred, &remote_branches);
                if (remote_err) {
                    output_warning(out, "Could not query remote: %s", error_message(remote_err));
                    error_free(remote_err);
                } else if (string_array_size(remote_branches) > 0) {
                    /*
                     * Filter out branches that already exist locally
                     * Uses string_array_difference() for O(n+m) set difference
                     */
                    error_t *diff_err = string_array_difference(remote_branches, all_branches, &remote_only);
                    if (diff_err) {
                        output_warning(out, "Failed to filter remote branches: %s", error_message(diff_err));
                        error_free(diff_err);
                    }

                    if (remote_only && string_array_size(remote_only) > 0) {
                        output_section(out, "Remote (not fetched)");
                        for (size_t i = 0; i < string_array_size(remote_only); i++) {
                            output_printf(out, OUTPUT_NORMAL, "  • %s\n", string_array_get(remote_only, i));
                        }
                        output_newline(out);
                    }
                }
            }
        }
    }

cleanup:
    /* Cleanup all resources */
    string_array_free(remote_only);
    string_array_free(remote_branches);
    transfer_context_free(xfer);
    free(remote_url);
    free(remote_name);
    string_array_free(available);
    string_array_free(all_branches);
    string_array_free(enabled_profiles);
    state_free(state);

    return err;
}

/**
 * Profile fetch subcommand
 *
 * Downloads profiles without enabling them.
 */
static error_t *profile_fetch(
    git_repository *repo,
    const cmd_profile_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup */
    char *remote_name = NULL;
    char *remote_url = NULL;
    git_remote *remote_obj = NULL;
    transfer_context_t *xfer = NULL;
    string_array_t *remote_branches = NULL;
    error_t *err = NULL;

    /* Counters for summary (not cleaned up) */
    size_t fetched_count = 0;
    size_t failed_count = 0;

    /* Detect remote */
    err = upstream_detect_remote(repo, &remote_name);
    if (err) {
        err = error_wrap(err, "No remote configured");
        goto cleanup;
    }

    /* Create transfer context for progress and credentials */
    if (git_remote_lookup(&remote_obj, repo, remote_name) == 0) {
        const char *url = git_remote_url(remote_obj);
        if (url) {
            remote_url = strdup(url);
        }
        git_remote_free(remote_obj);
        remote_obj = NULL;
    }

    xfer = transfer_context_create(out, remote_url);
    if (!xfer) {
        err = ERROR(ERR_MEMORY, "Failed to create transfer context");
        goto cleanup;
    }

    output_section(out, "Fetching profiles");

    if (opts->fetch_all) {
        /* Query remote server for all available branches */
        err = upstream_query_remote_branches(repo, remote_name, xfer ? xfer->cred : NULL, &remote_branches);
        if (err) {
            err = error_wrap(err, "Failed to query remote branches");
            goto cleanup;
        }

        for (size_t i = 0; i < string_array_size(remote_branches); i++) {
            const char *branch_name = string_array_get(remote_branches, i);

            if (opts->verbose) {
                output_info(out, "  Fetching %s...", branch_name);
            }

            error_t *fetch_err = gitops_fetch_branch(repo, remote_name, branch_name, xfer);
            if (fetch_err) {
                output_error(out, "Failed to fetch '%s': %s",
                            branch_name, error_message(fetch_err));
                error_free(fetch_err);
                failed_count++;
                continue;
            }

            /* Create local tracking branch if needed */
            bool already_exists = profile_exists(repo, branch_name);
            if (already_exists) {
                /* Branch already exists - fetch updated the remote ref */
                fetched_count++;
                if (opts->verbose) {
                    output_success(out, "  ✓ Updated %s", branch_name);
                }
            } else {
                fetch_err = upstream_create_tracking_branch(repo, remote_name, branch_name);
                if (fetch_err) {
                    output_error(out, "Failed to create local branch '%s': %s",
                                branch_name, error_message(fetch_err));
                    error_free(fetch_err);
                    failed_count++;
                } else {
                    fetched_count++;
                    if (opts->verbose) {
                        output_success(out, "  ✓ Fetched %s", branch_name);
                    }
                }
            }
        }
    } else {
        /* Fetch specific profiles */
        if (opts->profile_count == 0) {
            err = ERROR(ERR_INVALID_ARG,
                        "No profiles specified\n"
                        "Hint: Use 'dotta profile fetch <name>' or '--all'");
            goto cleanup;
        }

        /* Pre-flight validation: query remote for available branches */
        string_array_t *available_remote = NULL;
        err = upstream_query_remote_branches(repo, remote_name, xfer ? xfer->cred : NULL, &available_remote);
        if (err) {
            err = error_wrap(err, "Failed to query remote branches");
            goto cleanup;
        }

        /* Validate requested profiles exist on remote */
        bool has_missing = false;
        for (size_t i = 0; i < opts->profile_count; i++) {
            const char *profile_name = opts->profiles[i];
            bool found = false;

            /* Check if profile exists on remote */
            for (size_t j = 0; j < string_array_size(available_remote); j++) {
                if (strcmp(string_array_get(available_remote, j), profile_name) == 0) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                output_error(out, "Profile '%s' does not exist on remote '%s'",
                            profile_name, remote_name);
                has_missing = true;
            }
        }

        /* If any profiles are missing, show available profiles and error */
        if (has_missing) {
            if (string_array_size(available_remote) > 0) {
                output_section(out, "Available profiles on remote");
                for (size_t i = 0; i < string_array_size(available_remote); i++) {
                    output_printf(out, OUTPUT_NORMAL, "  • %s\n", string_array_get(available_remote, i));
                }
                output_newline(out);
            }
            string_array_free(available_remote);
            err = ERROR(ERR_NOT_FOUND, "One or more requested profiles not found on remote");
            goto cleanup;
        }

        string_array_free(available_remote);

        for (size_t i = 0; i < opts->profile_count; i++) {
            const char *profile_name = opts->profiles[i];

            /* Check if already exists locally */
            bool already_exists = profile_exists(repo, profile_name);
            if (already_exists && opts->verbose) {
                output_info(out, "  %s already exists locally (updating...)",
                           profile_name);
            }

            error_t *fetch_err = gitops_fetch_branch(repo, remote_name, profile_name, xfer);
            if (fetch_err) {
                output_error(out, "Failed to fetch '%s': %s",
                            profile_name, error_message(fetch_err));
                error_free(fetch_err);
                failed_count++;
                continue;
            }

            /* Create/update local tracking branch (skip if already exists) */
            if (already_exists) {
                /* Branch already exists - consider this a successful fetch/update */
                fetched_count++;
                if (opts->verbose) {
                    output_success(out, "  ✓ Updated %s", profile_name);
                }
            } else {
                fetch_err = upstream_create_tracking_branch(repo, remote_name, profile_name);
                if (fetch_err) {
                    output_warning(out, "Failed to create local branch '%s': %s",
                                  profile_name, error_message(fetch_err));
                    error_free(fetch_err);
                } else {
                    fetched_count++;
                    if (opts->verbose) {
                        output_success(out, "  ✓ Fetched %s", profile_name);
                    }
                }
            }
        }
    }

cleanup:
    /* Cleanup all resources */
    string_array_free(remote_branches);
    transfer_context_free(xfer);
    free(remote_url);
    free(remote_name);

    /* If there's an error, return it now */
    if (err) {
        return err;
    }

    /* Summary (only shown on success) */
    output_newline(out);
    if (fetched_count > 0) {
        output_success(out, "Fetched %zu profile%s",
                      fetched_count, fetched_count == 1 ? "" : "s");
    }
    if (failed_count > 0) {
        output_warning(out, "Failed to fetch %zu profile%s",
                      failed_count, failed_count == 1 ? "" : "s");
    }

    /* Only error if ALL operations failed or no profiles were available */
    if (fetched_count == 0 && failed_count > 0) {
        return ERROR(ERR_GIT, "All profile fetch operations failed");
    }

    if (fetched_count == 0) {
        return ERROR(ERR_GIT, "No profiles available to fetch");
    }

    /* Success if at least some profiles were fetched (even if some failed) */
    return NULL;
}

/**
 * Profile enable subcommand
 *
 * Adds profiles to the enabled set in state.
 */
static error_t *profile_enable(
    git_repository *repo,
    const cmd_profile_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup */
    state_t *state = NULL;
    string_array_t *enabled = NULL;
    string_array_t *to_enable = NULL;
    string_array_t *all_branches = NULL;
    char **profile_names = NULL;
    error_t *err = NULL;

    /* Counters for summary (not cleaned up) */
    size_t enabled_count = 0;
    size_t already_enabled = 0;
    size_t not_found = 0;

    /* Load state (with locking for write transaction) */
    err = state_load_for_update(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to load state");
        goto cleanup;
    }

    /* Get current enabled profiles */
    err = state_get_profiles(state, &enabled);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* Determine which profiles to enable */
    to_enable = string_array_create();
    if (!to_enable) {
        err = ERROR(ERR_MEMORY, "Failed to create array");
        goto cleanup;
    }

    if (opts->all_profiles) {
        /* Enable all local profiles */
        err = gitops_list_branches(repo, &all_branches);
        if (err) {
            err = error_wrap(err, "Failed to list branches");
            goto cleanup;
        }

        for (size_t i = 0; i < string_array_size(all_branches); i++) {
            const char *name = string_array_get(all_branches, i);
            if (strcmp(name, "dotta-worktree") != 0) {
                err = string_array_push(to_enable, name);
                if (err) {
                    err = error_wrap(err, "Failed to add profile to enable list");
                    goto cleanup;
                }
            }
        }
    } else {
        /* Enable specified profiles */
        if (opts->profile_count == 0) {
            err = ERROR(ERR_INVALID_ARG,
                       "No profiles specified\n"
                       "Hint: Use 'dotta profile enable <name>' or '--all'");
            goto cleanup;
        }

        for (size_t i = 0; i < opts->profile_count; i++) {
            err = string_array_push(to_enable, opts->profiles[i]);
            if (err) {
                err = error_wrap(err, "Failed to add profile to enable list");
                goto cleanup;
            }
        }
    }

    /* Process each profile */
    for (size_t i = 0; i < string_array_size(to_enable); i++) {
        const char *profile_name = string_array_get(to_enable, i);

        /* Check if already enabled */
        bool is_enabled = false;
        for (size_t j = 0; j < string_array_size(enabled); j++) {
            if (strcmp(string_array_get(enabled, j), profile_name) == 0) {
                is_enabled = true;
                break;
            }
        }

        if (is_enabled) {
            if (opts->verbose) {
                output_info(out, "  %s already enabled", profile_name);
            }
            already_enabled++;
            continue;
        }

        /* Check if profile exists */
        if (!profile_exists(repo, profile_name)) {
            output_warning(out, "Profile '%s' does not exist locally", profile_name);
            output_info(out, "  Hint: Run 'dotta profile fetch %s' first", profile_name);
            not_found++;
            continue;
        }

        /* Add to enabled list */
        err = string_array_push(enabled, profile_name);
        if (err) {
            err = error_wrap(err, "Failed to add profile to enabled list");
            goto cleanup;
        }
        enabled_count++;

        if (opts->verbose) {
            size_t file_count = 0;
            error_t *count_err = count_profile_files(repo, profile_name, &file_count);

            if (count_err) {
                output_success(out, "  ✓ Enabled %s", profile_name);
                error_free(count_err);
            } else {
                output_success(out, "  ✓ Enabled %s (%zu file%s)",
                              profile_name, file_count, file_count == 1 ? "" : "s");
            }
        }
    }

    /* Update state with new enabled profiles */
    if (enabled_count > 0) {
        profile_names = malloc(string_array_size(enabled) * sizeof(char *));
        if (!profile_names) {
            err = ERROR(ERR_MEMORY, "Failed to allocate profile names");
            goto cleanup;
        }

        for (size_t i = 0; i < string_array_size(enabled); i++) {
            profile_names[i] = (char *)string_array_get(enabled, i);
        }

        err = state_set_profiles(state, profile_names, string_array_size(enabled));
        if (err) {
            err = error_wrap(err, "Failed to update state");
            goto cleanup;
        }

        /* Save state */
        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to save state");
            goto cleanup;
        }
    }

cleanup:
    /* Cleanup all resources */
    free(profile_names);
    string_array_free(all_branches);
    string_array_free(to_enable);
    string_array_free(enabled);
    state_free(state);

    /* If there's an error, return it now */
    if (err) {
        return err;
    }

    /* Summary (only shown on success) */
    if (!opts->verbose) {
        output_newline(out);
    }

    if (enabled_count > 0) {
        output_success(out, "Enabled %zu profile%s",
                      enabled_count, enabled_count == 1 ? "" : "s");
        output_info(out, "Run 'dotta apply' to deploy these profiles to your filesystem");
    }
    if (already_enabled > 0 && !opts->quiet) {
        output_info(out, "%zu profile%s already enabled",
                   already_enabled, already_enabled == 1 ? "" : "s");
    }
    if (not_found > 0) {
        output_warning(out, "%zu profile%s not found",
                      not_found, not_found == 1 ? "" : "s");
    }

    if (enabled_count == 0 && not_found > 0) {
        return ERROR(ERR_NOT_FOUND, "No profiles were enabled");
    }

    return NULL;
}

/**
 * Profile disable subcommand
 *
 * Removes profiles from the enabled set.
 */
static error_t *profile_disable(
    git_repository *repo,
    const cmd_profile_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup */
    state_t *state = NULL;
    string_array_t *enabled = NULL;
    string_array_t *to_disable = NULL;
    string_array_t *new_enabled = NULL;
    char **profile_names = NULL;
    error_t *err = NULL;

    /* Counters for summary (not cleaned up) */
    size_t disabled_count = 0;
    size_t not_enabled = 0;

    /* Load state (with locking for write transaction) */
    err = state_load_for_update(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to load state");
        goto cleanup;
    }

    /* Get current enabled profiles */
    err = state_get_profiles(state, &enabled);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* Determine which profiles to disable */
    to_disable = string_array_create();
    if (!to_disable) {
        err = ERROR(ERR_MEMORY, "Failed to create array");
        goto cleanup;
    }

    if (opts->all_profiles) {
        /* Disable all */
        for (size_t i = 0; i < string_array_size(enabled); i++) {
            err = string_array_push(to_disable, string_array_get(enabled, i));
            if (err) {
                err = error_wrap(err, "Failed to add profile to disable list");
                goto cleanup;
            }
        }
    } else {
        /* Disable specified profiles */
        if (opts->profile_count == 0) {
            err = ERROR(ERR_INVALID_ARG,
                       "No profiles specified\n"
                       "Hint: Use 'dotta profile disable <name>' or '--all'");
            goto cleanup;
        }

        for (size_t i = 0; i < opts->profile_count; i++) {
            err = string_array_push(to_disable, opts->profiles[i]);
            if (err) {
                err = error_wrap(err, "Failed to add profile to disable list");
                goto cleanup;
            }
        }
    }

    /* Build new enabled list (excluding disabled) */
    new_enabled = string_array_create();
    if (!new_enabled) {
        err = ERROR(ERR_MEMORY, "Failed to create array");
        goto cleanup;
    }

    /* Build new enabled list and count profiles */
    for (size_t i = 0; i < string_array_size(enabled); i++) {
        const char *profile_name = string_array_get(enabled, i);

        /* Check if should be disabled */
        bool should_disable = false;
        for (size_t j = 0; j < string_array_size(to_disable); j++) {
            if (strcmp(string_array_get(to_disable, j), profile_name) == 0) {
                should_disable = true;
                break;
            }
        }

        if (should_disable) {
            disabled_count++;
            if (opts->verbose) {
                output_success(out, "  ✓ Disabled %s", profile_name);
            }
        } else {
            err = string_array_push(new_enabled, profile_name);
            if (err) {
                err = error_wrap(err, "Failed to add profile to new enabled list");
                goto cleanup;
            }
        }
    }

    /* Check for profiles that weren't enabled */
    for (size_t i = 0; i < string_array_size(to_disable); i++) {
        const char *profile_name = string_array_get(to_disable, i);

        bool was_enabled = false;
        for (size_t j = 0; j < string_array_size(enabled); j++) {
            if (strcmp(string_array_get(enabled, j), profile_name) == 0) {
                was_enabled = true;
                break;
            }
        }

        if (!was_enabled) {
            if (opts->verbose) {
                output_info(out, "  %s was not enabled", profile_name);
            }
            not_enabled++;
        }
    }

    /* Dry-run mode: show what would happen and exit */
    if (opts->dry_run) {
        if (disabled_count > 0) {
            output_newline(out);
            output_info(out, "Would disable %zu profile%s:",
                       disabled_count, disabled_count == 1 ? "" : "s");
            for (size_t i = 0; i < string_array_size(to_disable); i++) {
                const char *profile_name = string_array_get(to_disable, i);
                /* Check if it was actually enabled */
                bool was_enabled = false;
                for (size_t j = 0; j < string_array_size(enabled); j++) {
                    if (strcmp(string_array_get(enabled, j), profile_name) == 0) {
                        was_enabled = true;
                        break;
                    }
                }
                if (was_enabled) {
                    output_printf(out, OUTPUT_NORMAL, "  - %s\n", profile_name);
                }
            }
            output_newline(out);
            output_info(out, "Run 'dotta apply' to remove deployed files");
        }
        goto cleanup;
    }

    /* Update state with new enabled profiles */
    if (disabled_count > 0) {
        profile_names = malloc(string_array_size(new_enabled) * sizeof(char *));
        if (!profile_names) {
            err = ERROR(ERR_MEMORY, "Failed to allocate profile names");
            goto cleanup;
        }

        for (size_t i = 0; i < string_array_size(new_enabled); i++) {
            profile_names[i] = (char *)string_array_get(new_enabled, i);
        }

        err = state_set_profiles(state, profile_names, string_array_size(new_enabled));
        if (err) {
            err = error_wrap(err, "Failed to update state");
            goto cleanup;
        }

        /* Save state (profile disabling only - filesystem cleanup via 'apply') */
        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to save state");
            goto cleanup;
        }
    }

cleanup:
    /* Cleanup all resources */
    free(profile_names);
    string_array_free(new_enabled);
    string_array_free(to_disable);
    string_array_free(enabled);
    state_free(state);

    /* If there's an error, return it now */
    if (err) {
        return err;
    }

    /* Summary (only shown on success) */
    if (!opts->verbose) {
        output_newline(out);
    }

    if (disabled_count > 0) {
        output_success(out, "Disabled %zu profile%s",
                      disabled_count, disabled_count == 1 ? "" : "s");
        output_info(out, "Run 'dotta apply' to remove deployed files from filesystem");
    }
    if (not_enabled > 0 && !opts->quiet) {
        output_info(out, "%zu profile%s were not enabled",
                   not_enabled, not_enabled == 1 ? "" : "s");
    }

    /* Return success if profiles were already disabled (idempotent) */
    if (disabled_count == 0 && not_enabled > 0) {
        return NULL;
    }

    /* Only error if nothing was specified or found */
    if (disabled_count == 0) {
        return ERROR(ERR_NOT_FOUND, "No specified profiles were enabled or found");
    }

    return NULL;
}

/**
 * Profile reorder subcommand
 *
 * Changes the order of enabled profiles, which affects layering precedence.
 */
static error_t *profile_reorder(
    git_repository *repo,
    const cmd_profile_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup */
    state_t *state = NULL;
    string_array_t *current_enabled = NULL;
    error_t *err = NULL;

    /* Validation: at least one profile specified */
    if (opts->profile_count == 0) {
        err = ERROR(ERR_INVALID_ARG,
                    "No profiles specified\n"
                    "Hint: Provide profiles in desired order: dotta profile reorder <p1> <p2> ...");
        goto cleanup;
    }

    /* Load state (with locking for write transaction) */
    err = state_load_for_update(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to load state");
        goto cleanup;
    }

    /* Get current enabled profiles */
    err = state_get_profiles(state, &current_enabled);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* Edge case: no enabled profiles */
    if (string_array_size(current_enabled) == 0) {
        err = ERROR(ERR_VALIDATION,
                   "No enabled profiles to reorder\n"
                   "Hint: Run 'dotta profile enable <name>' first");
        goto cleanup;
    }

    /* Edge case: single profile */
    if (string_array_size(current_enabled) == 1) {
        if (!opts->quiet) {
            output_info(out, "Only one enabled profile, nothing to reorder");
        }
        goto cleanup;  /* Success, but no-op */
    }

    /* Validation 1: Check for duplicates in new order */
    for (size_t i = 0; i < opts->profile_count; i++) {
        for (size_t j = i + 1; j < opts->profile_count; j++) {
            if (strcmp(opts->profiles[i], opts->profiles[j]) == 0) {
                err = ERROR(ERR_VALIDATION,
                           "Profile '%s' appears multiple times in reorder list",
                           opts->profiles[i]);
                goto cleanup;
            }
        }
    }

    /* Validation 2: All provided profiles must be currently enabled */
    for (size_t i = 0; i < opts->profile_count; i++) {
        bool is_enabled = false;
        for (size_t j = 0; j < string_array_size(current_enabled); j++) {
            if (strcmp(opts->profiles[i], string_array_get(current_enabled, j)) == 0) {
                is_enabled = true;
                break;
            }
        }
        if (!is_enabled) {
            err = ERROR(ERR_VALIDATION,
                       "Profile '%s' is not enabled\n"
                       "Hint: Only enabled profiles can be reordered. Run 'dotta profile list' to see enabled profiles",
                       opts->profiles[i]);
            goto cleanup;
        }
    }

    /* Validation 3: Profile count must match */
    if (opts->profile_count != string_array_size(current_enabled)) {
        err = ERROR(ERR_VALIDATION,
                   "Profile count mismatch: %zu enabled, %zu provided\n"
                   "Hint: All enabled profiles must be included in reorder",
                   string_array_size(current_enabled),
                   opts->profile_count);
        goto cleanup;
    }

    /* Validation 4: All currently enabled profiles must be included */
    for (size_t i = 0; i < string_array_size(current_enabled); i++) {
        const char *enabled_profile = string_array_get(current_enabled, i);
        bool found = false;
        for (size_t j = 0; j < opts->profile_count; j++) {
            if (strcmp(opts->profiles[j], enabled_profile) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            err = ERROR(ERR_VALIDATION,
                       "Missing enabled profile '%s' from reorder list\n"
                       "Hint: All enabled profiles must be included",
                       enabled_profile);
            goto cleanup;
        }
    }

    /* Check if order actually changed (idempotency) */
    bool order_changed = false;
    for (size_t i = 0; i < opts->profile_count; i++) {
        if (strcmp(opts->profiles[i], string_array_get(current_enabled, i)) != 0) {
            order_changed = true;
            break;
        }
    }

    if (!order_changed) {
        if (!opts->quiet) {
            output_info(out, "No change - profiles already in requested order");
        }
        goto cleanup;  /* Success, but no-op */
    }

    /* Show before/after in verbose mode */
    if (opts->verbose) {
        output_section(out, "Profile order change");
        output_printf(out, OUTPUT_NORMAL, "  Before:");
        for (size_t i = 0; i < string_array_size(current_enabled); i++) {
            output_printf(out, OUTPUT_NORMAL, " %s", string_array_get(current_enabled, i));
        }
        output_newline(out);

        output_printf(out, OUTPUT_NORMAL, "  After: ");
        for (size_t i = 0; i < opts->profile_count; i++) {
            output_printf(out, OUTPUT_NORMAL, " %s", opts->profiles[i]);
        }
        output_newline(out);
    }

    /* Update state with new order */
    err = state_set_profiles(state, opts->profiles, opts->profile_count);
    if (err) {
        err = error_wrap(err, "Failed to update state");
        goto cleanup;
    }

    /* Save state (releases lock automatically) */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to save state");
        goto cleanup;
    }

    /* Success message */
    if (!opts->quiet) {
        output_newline(out);
        output_success(out, "Reordered %zu profile%s",
                      opts->profile_count,
                      opts->profile_count == 1 ? "" : "s");
        output_info(out, "Run 'dotta apply' to deploy with new profile order");
    }

cleanup:
    /* Cleanup all resources */
    string_array_free(current_enabled);
    state_free(state);

    return err;
}

/**
 * Profile validate subcommand
 *
 * Checks state consistency and offers to fix issues.
 */
static error_t *profile_validate(
    git_repository *repo,
    const cmd_profile_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup */
    state_t *state = NULL;
    string_array_t *enabled = NULL;
    string_array_t *missing = NULL;
    string_array_t *valid = NULL;
    char **profile_names = NULL;
    error_t *err = NULL;

    /* State for reporting (not cleaned up) */
    bool has_issues = false;
    bool fixed_enabled_profiles = false;  /* Track what we actually fixed */
    bool has_orphaned_files = false;      /* Track issues we can't fix */
    size_t orphaned_files = 0;

    /* Load state (with locking if we're going to fix issues) */
    if (opts->fix) {
        err = state_load_for_update(repo, &state);
    } else {
        err = state_load(repo, &state);
    }
    if (err) {
        err = error_wrap(err, "Failed to load state");
        goto cleanup;
    }

    /* Get enabled profiles from state */
    err = state_get_profiles(state, &enabled);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    output_section(out, "Validating profile state");

    /* Check 1: Enabled profiles exist as branches */
    missing = string_array_create();
    if (!missing) {
        err = ERROR(ERR_MEMORY, "Failed to create array");
        goto cleanup;
    }

    for (size_t i = 0; i < string_array_size(enabled); i++) {
        const char *profile_name = string_array_get(enabled, i);

        if (!profile_exists(repo, profile_name)) {
            err = string_array_push(missing, profile_name);
            if (err) {
                err = error_wrap(err, "Failed to add profile to missing list");
                goto cleanup;
            }
            has_issues = true;
        }
    }

    if (string_array_size(missing) > 0) {
        output_warning(out, "Found %zu missing profile%s in state:",
                      string_array_size(missing),
                      string_array_size(missing) == 1 ? "" : "s");

        for (size_t i = 0; i < string_array_size(missing); i++) {
            output_printf(out, OUTPUT_NORMAL, "  • %s\n", string_array_get(missing, i));
        }

        if (opts->fix) {
            /* Remove missing profiles from state */
            valid = string_array_create();
            if (!valid) {
                err = ERROR(ERR_MEMORY, "Failed to create array");
                goto cleanup;
            }

            for (size_t i = 0; i < string_array_size(enabled); i++) {
                const char *name = string_array_get(enabled, i);
                if (profile_exists(repo, name)) {
                    err = string_array_push(valid, name);
                    if (err) {
                        err = error_wrap(err, "Failed to add profile to valid list");
                        goto cleanup;
                    }
                }
            }

            profile_names = malloc(string_array_size(valid) * sizeof(char *));
            if (!profile_names) {
                err = ERROR(ERR_MEMORY, "Failed to allocate profile names");
                goto cleanup;
            }

            for (size_t i = 0; i < string_array_size(valid); i++) {
                profile_names[i] = (char *)string_array_get(valid, i);
            }

            err = state_set_profiles(state, profile_names, string_array_size(valid));
            if (err) {
                err = error_wrap(err, "Failed to update state");
                goto cleanup;
            }

            err = state_save(repo, state);
            if (err) {
                err = error_wrap(err, "Failed to save state");
                goto cleanup;
            }

            output_success(out, "✓ Removed missing profiles from state\n");
            fixed_enabled_profiles = true;
        } else {
            output_info(out, "Hint: Run 'dotta profile validate --fix' to remove them\n");
        }
    }

    /* Check 2: State file entries reference valid profiles */
    size_t state_file_count = 0;
    state_file_entry_t *state_files = NULL;
    err = state_get_all_files(state, &state_files, &state_file_count);
    if (err) {
        goto cleanup;
    }

    for (size_t i = 0; i < state_file_count; i++) {
        const char *profile_name = state_files[i].profile;
        if (!profile_exists(repo, profile_name)) {
            orphaned_files++;
            has_issues = true;
            has_orphaned_files = true;
        }
    }

    state_free_all_files(state_files, state_file_count);

    if (orphaned_files > 0) {
        output_warning(out, "Found %zu orphaned file entr%s in state",
                      orphaned_files,
                      orphaned_files == 1 ? "y" : "ies");
        output_info(out, "  These reference non-existent profiles");
        output_info(out, "  Hint: Run 'dotta apply' to clean up\n");
    }

cleanup:
    /* Cleanup all resources */
    free(profile_names);
    string_array_free(valid);
    string_array_free(missing);
    string_array_free(enabled);
    state_free(state);

    /* If there's an error, return it now */
    if (err) {
        return err;
    }

    /* Summary (only shown on success) */
    output_newline(out);
    if (!has_issues) {
        output_success(out, "Profile state is valid");
    } else {
        if (opts->fix) {
            /* Be accurate about what was actually fixed */
            if (fixed_enabled_profiles && !has_orphaned_files) {
                output_success(out, "Fixed all profile state issues");
            } else if (fixed_enabled_profiles && has_orphaned_files) {
                output_info(out, "Fixed enabled profile list");
                output_info(out, "Note: Orphaned files require 'dotta apply' to clean up");
            } else if (!fixed_enabled_profiles && has_orphaned_files) {
                output_warning(out, "Profile state has issues that require 'dotta apply'");
            } else {
                /* Shouldn't reach here, but handle gracefully */
                output_warning(out, "Profile state has issues");
            }
        } else {
            output_warning(out, "Profile state has issues");
            output_info(out, "Run 'dotta profile validate --fix' to fix automatically");
        }
    }

    return NULL;
}

/**
 * Profile command dispatcher
 */
error_t *cmd_profile(git_repository *repo, const cmd_profile_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Load config for output context */
    dotta_config_t *config = NULL;
    error_t *err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: use defaults */
        config = config_create_default();
    }

    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* Override verbosity from CLI */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }
    if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Dispatch to subcommand */
    error_t *result = NULL;
    switch (opts->subcommand) {
        case PROFILE_LIST:
            result = profile_list(repo, opts, out);
            break;

        case PROFILE_FETCH:
            result = profile_fetch(repo, opts, out);
            break;

        case PROFILE_ENABLE:
            result = profile_enable(repo, opts, out);
            break;

        case PROFILE_DISABLE:
            result = profile_disable(repo, opts, out);
            break;

        case PROFILE_REORDER:
            result = profile_reorder(repo, opts, out);
            break;

        case PROFILE_VALIDATE:
            result = profile_validate(repo, opts, out);
            break;

        default:
            result = ERROR(ERR_INVALID_ARG, "Unknown subcommand");
            break;
    }

    output_free(out);
    config_free(config);
    return result;
}
