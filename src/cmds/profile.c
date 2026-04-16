/**
 * profile.c - Profile lifecycle management
 *
 * Explicit profile management commands for controlling which profiles
 * are enabled vs merely available on this machine.
 */

#include "cmds/profile.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/transfer.h"
#include "sys/upstream.h"

/**
 * Count files in profile
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param count Output file count (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *count_profile_files(
    git_repository *repo,
    const char *profile,
    size_t *count
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(count);

    string_array_t *files = NULL;
    error_t *err = profile_list_files(repo, profile, &files);
    if (err) {
        return error_wrap(err, "Failed to list files");
    }

    *count = files->count;
    string_array_free(files);
    return NULL;
}

/**
 * Print manifest enable statistics
 *
 * Shows deployment analysis from manifest enable operation.
 * Verbose mode shows detailed breakdown, normal mode shows summary.
 */
static void print_manifest_enable_stats(
    const output_ctx_t *out,
    const char *profile,
    const manifest_enable_stats_t *stats
) {
    if (!stats || stats->total_files == 0) return;

    if (output_is_verbose(out)) {
        /* Detailed breakdown */
        output_section(out, OUTPUT_VERBOSE, "Manifest Analysis");
        output_print(
            out, OUTPUT_VERBOSE, "  Profile: %s\n",
            profile
        );
        output_print(
            out, OUTPUT_VERBOSE, "  Total files: %zu\n",
            stats->total_files
        );

        if (stats->already_deployed > 0) {
            output_styled(
                out, OUTPUT_VERBOSE,
                "    - {green}%zu{reset} already deployed and correct\n",
                stats->already_deployed
            );
        }

        if (stats->needs_deployment > 0) {
            output_styled(
                out, OUTPUT_VERBOSE,
                "    - {yellow}%zu{reset} need deployment\n",
                stats->needs_deployment
            );
        }

        if (stats->access_errors > 0) {
            output_newline(out, OUTPUT_VERBOSE);
            output_warning(
                out, OUTPUT_VERBOSE, "Could not access %zu file%s during profile enable",
                stats->access_errors, stats->access_errors == 1 ? "" : "s"
            );
            output_hint(
                out, OUTPUT_VERBOSE, "Run 'dotta status' for deployment details"
            );
        }

        output_newline(out, OUTPUT_VERBOSE);
    } else {
        /* Compact summary */
        if (stats->needs_deployment > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Staged %zu file%s for deployment\n",
                stats->needs_deployment, stats->needs_deployment == 1 ? "" : "s"
            );
        }
        if (stats->already_deployed > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Found %zu file%s already up-to-date\n",
                stats->already_deployed, stats->already_deployed == 1 ? "" : "s"
            );
        }

        if (stats->access_errors > 0) {
            output_warning(
                out, OUTPUT_NORMAL, "Could not access %zu file%s during profile enable",
                stats->access_errors, stats->access_errors == 1 ? "" : "s"
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta status' for deployment details"
            );
        }
    }
}

/**
 * Print manifest disable statistics
 *
 * Shows impact analysis from manifest disable operation.
 */
static void print_manifest_disable_stats(
    const output_ctx_t *out,
    const char *profile,
    const manifest_disable_stats_t *stats
) {
    if (!stats || stats->total_files == 0) return;

    if (output_is_verbose(out)) {
        /* Detailed breakdown */
        output_section(out, OUTPUT_VERBOSE, "Manifest Analysis");
        output_print(out, OUTPUT_VERBOSE, "  Profile: %s\n", profile);

        output_print(
            out, OUTPUT_VERBOSE,
            "  Total files affected: %zu\n", stats->total_files
        );

        if (stats->files_with_fallback > 0) {
            output_styled(
                out, OUTPUT_VERBOSE,
                "    - {green}%zu{reset} file%s with fallback (will revert)\n",
                stats->files_with_fallback,
                stats->files_with_fallback == 1 ? "" : "s"
            );
        }

        if (stats->files_removed > 0) {
            output_styled(
                out, OUTPUT_VERBOSE,
                "    - {red}%zu{reset} file%s without fallback (will be removed)\n",
                stats->files_removed,
                stats->files_removed == 1 ? "" : "s"
            );
        }
    } else {
        /* Compact summary */
        if (stats->files_removed > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Staged %zu file%s for removal\n",
                stats->files_removed, stats->files_removed == 1 ? "" : "s"
            );
        }

        if (stats->files_with_fallback > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Reverted %zu file%s to lower precedence\n",
                stats->files_with_fallback,
                stats->files_with_fallback == 1 ? "" : "s"
            );
        }
    }
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
    available = string_array_new(0);
    if (!available) {
        err = ERROR(ERR_MEMORY, "Failed to create array");
        goto cleanup;
    }

    for (size_t i = 0; i < all_branches->count; i++) {
        const char *profile = all_branches->items[i];

        /* Skip dotta-worktree */
        if (strcmp(profile, "dotta-worktree") == 0) {
            continue;
        }

        /* Check if enabled */
        bool is_enabled = false;
        for (size_t j = 0; j < enabled_profiles->count; j++) {
            if (strcmp(enabled_profiles->items[j], profile) == 0) {
                is_enabled = true;
                break;
            }
        }

        if (!is_enabled) {
            err = string_array_push(available, profile);
            if (err) {
                err = error_wrap(
                    err, "Failed to add profile to available list"
                );
                goto cleanup;
            }
        }
    }

    /* Print enabled profiles */
    if (enabled_profiles->count > 0) {
        output_section(out, OUTPUT_NORMAL, "Enabled profiles (in layering order)");
        for (size_t i = 0; i < enabled_profiles->count; i++) {
            const char *profile = enabled_profiles->items[i];
            size_t file_count = 0;
            error_t *count_err = count_profile_files(repo, profile, &file_count);

            /* Show file counts if available, otherwise indicate error */
            if (count_err) {
                output_styled(
                    out, OUTPUT_NORMAL, "  %zu. {cyan}%s{reset} (file count unavailable)\n",
                    i + 1, profile
                );
                error_free(count_err);
            } else {
                output_styled(
                    out, OUTPUT_NORMAL, "  %zu. {cyan}%s{reset} (%zu file%s)\n",
                    i + 1, profile, file_count, file_count == 1 ? "" : "s"
                );
            }
        }
    } else {
        output_info(out, OUTPUT_NORMAL, "No enabled profiles");
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta profile enable <name>'");
    }

    /* Print available (disabled) profiles */
    if (available->count > 0 && opts->show_available) {
        output_section(out, OUTPUT_NORMAL, "Available (disabled)");
        for (size_t i = 0; i < available->count; i++) {
            const char *profile = available->items[i];
            size_t file_count = 0;
            error_t *count_err = count_profile_files(repo, profile, &file_count);

            /* Show file counts if available, otherwise indicate error */
            if (count_err) {
                output_styled(
                    out, OUTPUT_NORMAL, "  • {cyan}%s{reset} (file count unavailable)\n",
                    profile
                );
                error_free(count_err);
            } else {
                output_styled(
                    out, OUTPUT_NORMAL, "  • {cyan}%s{reset} (%zu file%s)\n",
                    profile, file_count, file_count == 1 ? "" : "s"
                );
            }
        }
    }

    /* Show remote profiles if requested */
    if (opts->show_remote) {
        error_t *remote_err = upstream_detect_remote(repo, &remote_name);
        if (remote_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Could not detect remote: %s",
                error_message(remote_err)
            );
            error_free(remote_err);
        } else {
            /* Get remote URL for credential handling */
            error_t *url_err = gitops_get_remote_url(repo, remote_name, &remote_url);
            error_free(url_err);

            /* Create transfer context for credentials */
            xfer = transfer_context_create(out, remote_url);
            if (!xfer) {
                output_warning(out, OUTPUT_NORMAL, "Failed to create transfer context");
            } else {
                /*
                 * Query remote server for available branches (network operation)
                 * This contacts the remote server to get the current list of profiles,
                 * ensuring we see newly added profiles that haven't been fetched yet.
                 */
                remote_err = upstream_query_remote_branches(
                    repo, remote_name, xfer->cred, &remote_branches
                );
                if (remote_err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Could not query remote: %s",
                        error_message(remote_err)
                    );
                    error_free(remote_err);
                } else if (remote_branches->count > 0) {
                    /* Filter out branches that already exist locally */
                    remote_only = string_array_new(remote_branches->count);
                    if (remote_only) {
                        for (size_t ri = 0; ri < remote_branches->count; ri++) {
                            if (!string_array_contains(all_branches, remote_branches->items[ri])) {
                                string_array_push(remote_only, remote_branches->items[ri]);
                            }
                        }
                    }

                    if (remote_only && remote_only->count > 0) {
                        output_section(out, OUTPUT_NORMAL, "Remote (not fetched)");
                        for (size_t i = 0; i < remote_only->count; i++) {
                            output_print(
                                out, OUTPUT_NORMAL, "  • %s\n",
                                remote_only->items[i]
                            );
                        }
                        output_newline(out, OUTPUT_NORMAL);
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

    /* Get remote URL for credential handling */
    error_t *url_err = gitops_get_remote_url(repo, remote_name, &remote_url);
    error_free(url_err);

    /* Create transfer context for progress reporting and credentials */
    xfer = transfer_context_create(out, remote_url);
    if (!xfer) {
        err = ERROR(ERR_MEMORY, "Failed to create transfer context");
        goto cleanup;
    }

    output_section(out, OUTPUT_NORMAL, "Fetching profiles");

    if (opts->fetch_all) {
        /* Query remote server for all available branches */
        err = upstream_query_remote_branches(
            repo, remote_name, xfer ? xfer->cred : NULL, &remote_branches
        );
        if (err) {
            err = error_wrap(err, "Failed to query remote branches");
            goto cleanup;
        }

        for (size_t i = 0; i < remote_branches->count; i++) {
            const char *branch_name = remote_branches->items[i];

            output_info(out, OUTPUT_VERBOSE, "  Fetching %s...", branch_name);

            error_t *fetch_err = gitops_fetch_branch(repo, remote_name, branch_name, xfer);
            if (fetch_err) {
                output_error(
                    out, "Failed to fetch '%s': %s",
                    branch_name, error_message(fetch_err)
                );
                error_free(fetch_err);
                failed_count++;
                continue;
            }

            /* Create local tracking branch if needed */
            bool already_exists = profile_exists(repo, branch_name);
            if (already_exists) {
                /* Branch already exists - fetch updated the remote ref */
                fetched_count++;
                output_styled(
                    out, OUTPUT_VERBOSE, "  {green}✓{reset} Updated %s\n",
                    branch_name
                );
            } else {
                fetch_err = upstream_create_tracking_branch(repo, remote_name, branch_name);
                if (fetch_err) {
                    output_error(
                        out, "Failed to create local branch '%s': %s",
                        branch_name, error_message(fetch_err)
                    );
                    error_free(fetch_err);
                    failed_count++;
                } else {
                    fetched_count++;
                    output_styled(
                        out, OUTPUT_VERBOSE, "  {green}✓{reset} Fetched %s\n",
                        branch_name
                    );
                }
            }
        }
    } else {
        /* Fetch specific profiles */
        if (opts->profile_count == 0) {
            err = ERROR(
                ERR_INVALID_ARG, "No profiles specified\n"
                "Hint: Use 'dotta profile fetch <name>' or '--all'"
            );
            goto cleanup;
        }

        /* Pre-flight validation: query remote for available branches */
        string_array_t *available_remote = NULL;
        err = upstream_query_remote_branches(
            repo, remote_name, xfer ? xfer->cred : NULL, &available_remote
        );
        if (err) {
            err = error_wrap(err, "Failed to query remote branches");
            goto cleanup;
        }

        /* Validate requested profiles exist on remote */
        bool has_missing = false;
        for (size_t i = 0; i < opts->profile_count; i++) {
            const char *profile = opts->profiles[i];
            bool found = false;

            /* Check if profile exists on remote */
            for (size_t j = 0; j < available_remote->count; j++) {
                if (strcmp(available_remote->items[j], profile) == 0) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                output_error(
                    out, "Profile '%s' does not exist on remote '%s'",
                    profile, remote_name
                );
                has_missing = true;
            }
        }

        /* If any profiles are missing, show available profiles and error */
        if (has_missing) {
            if (available_remote->count > 0) {
                output_section(out, OUTPUT_NORMAL, "Available profiles on remote");
                for (size_t i = 0; i < available_remote->count; i++) {
                    output_print(
                        out, OUTPUT_NORMAL, "  • %s\n",
                        available_remote->items[i]
                    );
                }
                output_newline(out, OUTPUT_NORMAL);
            }
            string_array_free(available_remote);
            err = ERROR(
                ERR_NOT_FOUND, "One or more requested profiles not found on remote"
            );
            goto cleanup;
        }

        string_array_free(available_remote);

        for (size_t i = 0; i < opts->profile_count; i++) {
            const char *profile = opts->profiles[i];

            /* Check if already exists locally */
            bool already_exists = profile_exists(repo, profile);
            if (already_exists) {
                output_info(
                    out, OUTPUT_VERBOSE, "  %s already exists locally (updating...)",
                    profile
                );
            }

            error_t *fetch_err = gitops_fetch_branch(repo, remote_name, profile, xfer);
            if (fetch_err) {
                output_error(
                    out, "Failed to fetch '%s': %s",
                    profile, error_message(fetch_err)
                );
                error_free(fetch_err);
                failed_count++;
                continue;
            }

            /* Create/update local tracking branch (skip if already exists) */
            if (already_exists) {
                /* Branch already exists - consider this a successful fetch/update */
                fetched_count++;
                output_styled(
                    out, OUTPUT_VERBOSE, "  {green}✓{reset} Updated %s\n",
                    profile
                );
            } else {
                fetch_err = upstream_create_tracking_branch(repo, remote_name, profile);
                if (fetch_err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to create local branch '%s': %s",
                        profile, error_message(fetch_err)
                    );
                    error_free(fetch_err);
                } else {
                    fetched_count++;
                    output_styled(
                        out, OUTPUT_VERBOSE, "  {green}✓{reset} Fetched %s\n",
                        profile
                    );
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
    output_newline(out, OUTPUT_NORMAL);
    if (fetched_count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Fetched %zu profile%s",
            fetched_count, fetched_count == 1 ? "" : "s"
        );
    }
    if (failed_count > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "Failed to fetch %zu profile%s",
            failed_count, failed_count == 1 ? "" : "s"
        );
    }

    /* Only error if ALL operations failed or no profiles were available */
    if (fetched_count == 0 && failed_count > 0) {
        return ERROR(
            ERR_GIT, "All profile fetch operations failed"
        );
    }

    if (fetched_count == 0) {
        return ERROR(
            ERR_GIT, "No profiles available to fetch"
        );
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
    error_t *err = NULL;

    /* Counters for summary (not cleaned up) */
    size_t enabled_count = 0;
    size_t already_enabled = 0;
    size_t not_found = 0;

    /* Load state (with locking for write transaction) */
    err = state_open(repo, &state);
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
    to_enable = string_array_new(0);
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

        for (size_t i = 0; i < all_branches->count; i++) {
            const char *profile = all_branches->items[i];
            if (strcmp(profile, "dotta-worktree") != 0) {
                err = string_array_push(to_enable, profile);
                if (err) {
                    err = error_wrap(err, "Failed to add profile to enable list");
                    goto cleanup;
                }
            }
        }
    } else {
        /* Enable specified profiles */
        if (opts->profile_count == 0) {
            err = ERROR(
                ERR_INVALID_ARG, "No profiles specified\n"
                "Hint: Use 'dotta profile enable <name>' or '--all'"
            );
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

    /* Validation: --prefix requires exactly ONE profile */
    if (opts->custom_prefix && to_enable->count > 1) {
        output_error(out, "Cannot use --prefix with multiple profiles");
        output_hint(out, OUTPUT_NORMAL, "Enable each profile separately:");

        for (size_t i = 0; i < to_enable->count; i++) {
            output_hint(
                out, OUTPUT_NORMAL, "dotta profile enable %s --prefix <path>",
                to_enable->items[i]
            );
        }
        err = ERROR(ERR_INVALID_ARG, "Ambiguous --prefix usage");
        goto cleanup;
    }

    /* Process each profile */
    for (size_t i = 0; i < to_enable->count; i++) {
        const char *profile = to_enable->items[i];

        /* Check if already enabled */
        bool is_enabled = false;
        for (size_t j = 0; j < enabled->count; j++) {
            if (strcmp(enabled->items[j], profile) == 0) {
                is_enabled = true;
                break;
            }
        }

        if (is_enabled) {
            output_info(
                out, OUTPUT_VERBOSE, "  %s already enabled",
                profile
            );
            already_enabled++;
            continue;
        }

        /* Check if profile exists */
        if (!profile_exists(repo, profile)) {
            output_warning(
                out, OUTPUT_NORMAL, "Profile '%s' does not exist locally",
                profile
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile fetch %s' first",
                profile
            );
            not_found++;
            continue;
        }

        /* Check if profile contains custom/ files */
        bool has_custom = false;
        err = profile_has_custom_files(repo, profile, &has_custom);
        if (err) {
            /* Non-fatal: assume no custom files */
            error_free(err);
            err = NULL;
        }

        /* Validate custom prefix requirement */
        if (has_custom && !opts->custom_prefix) {
            output_error(
                out, "Profile '%s' contains custom/ files but --prefix not provided",
                profile
            );
            output_hint(
                out, OUTPUT_NORMAL, "dotta profile enable %s --prefix /path/to/target",
                profile
            );
            not_found++;
            continue;
        }

        /* Validate custom prefix if provided */
        if (opts->custom_prefix) {
            err = path_validate_custom_prefix(opts->custom_prefix);
            if (err) {
                output_error(
                    out, "Invalid custom prefix: %s",
                    error_message(err)
                );
                error_free(err);
                err = NULL;
                not_found++;
                continue;
            }
        }

        /* Enable profile in state with custom prefix */
        err = state_enable_profile(state, profile, opts->custom_prefix);
        if (err) {
            err = error_wrap(err, "Failed to enable profile in state");
            goto cleanup;
        }

        /* Add to enabled list (for manifest building) */
        err = string_array_push(enabled, profile);
        if (err) {
            err = error_wrap(err, "Failed to add profile to enabled list");
            goto cleanup;
        }
        enabled_count++;

        /* Sync profile to manifest and capture stats */
        manifest_enable_stats_t stats = { 0 };
        err = manifest_enable_profile(
            repo, state, profile, enabled, &stats
        );
        if (err) {
            err = error_wrap(
                err, "Failed to sync profile '%s' to manifest",
                profile
            );
            goto cleanup;
        }

        /* Show manifest analysis (verbose: detailed, normal: compact) */
        output_styled(
            out, OUTPUT_NORMAL, "  {green}✓{reset} Enabled %s\n",
            profile
        );
        print_manifest_enable_stats(out, profile, &stats);
    }

    /* Save state (profiles already updated via state_enable_profile in loop) */
    if (enabled_count > 0) {
        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to save state");
            goto cleanup;
        }
    }

cleanup:
    /* Cleanup all resources */
    string_array_free(all_branches);
    string_array_free(to_enable);
    string_array_free(enabled);
    state_free(state);

    /* If there's an error, return it now */
    if (err) {
        return err;
    }

    /* Summary (only shown on success) */
    if (!output_is_verbose(out)) {
        output_newline(out, OUTPUT_NORMAL);
    }

    if (enabled_count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Enabled %zu profile%s",
            enabled_count, enabled_count == 1 ? "" : "s"
        );
        output_info(
            out, OUTPUT_NORMAL, "Files staged for deployment in manifest"
        );
        output_info(
            out, OUTPUT_NORMAL, "Run 'dotta status' to review or 'dotta apply' to deploy"
        );
    }
    if (already_enabled > 0 && !opts->quiet) {
        output_info(
            out, OUTPUT_NORMAL, "%zu profile%s already enabled",
            already_enabled, already_enabled == 1 ? "" : "s"
        );
    }
    if (not_found > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "%zu profile%s not found",
            not_found, not_found == 1 ? "" : "s"
        );
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
    error_t *err = NULL;

    /* Counters for summary (not cleaned up) */
    size_t disabled_count = 0;
    size_t not_enabled = 0;

    /* Load state (with locking for write transaction) */
    err = state_open(repo, &state);
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
    to_disable = string_array_new(0);
    if (!to_disable) {
        err = ERROR(ERR_MEMORY, "Failed to create array");
        goto cleanup;
    }

    if (opts->all_profiles) {
        /* Disable all */
        for (size_t i = 0; i < enabled->count; i++) {
            err = string_array_push(to_disable, enabled->items[i]);
            if (err) {
                err = error_wrap(err, "Failed to add profile to disable list");
                goto cleanup;
            }
        }
    } else {
        /* Disable specified profiles */
        if (opts->profile_count == 0) {
            err = ERROR(
                ERR_INVALID_ARG, "No profiles specified\n"
                "Hint: Use 'dotta profile disable <name>' or '--all'"
            );
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

    /* Count profiles and build new_enabled for manifest operations */
    new_enabled = string_array_new(0);
    if (!new_enabled) {
        err = ERROR(ERR_MEMORY, "Failed to create array");
        goto cleanup;
    }

    /* Build new_enabled list (for manifest_disable_profile) and count */
    for (size_t i = 0; i < enabled->count; i++) {
        const char *profile = enabled->items[i];

        /* Check if this profile should be disabled */
        bool should_disable = false;
        for (size_t j = 0; j < to_disable->count; j++) {
            if (strcmp(to_disable->items[j], profile) == 0) {
                should_disable = true;
                disabled_count++;
                break;
            }
        }

        /* Add to new_enabled if NOT being disabled (needed for manifest fallback) */
        if (!should_disable) {
            err = string_array_push(new_enabled, profile);
            if (err) {
                err = error_wrap(err, "Failed to build remaining profiles list");
                goto cleanup;
            }
        }
    }

    /* Check for profiles that weren't enabled */
    for (size_t i = 0; i < to_disable->count; i++) {
        const char *profile = to_disable->items[i];

        bool was_enabled = false;
        for (size_t j = 0; j < enabled->count; j++) {
            if (strcmp(enabled->items[j], profile) == 0) {
                was_enabled = true;
                break;
            }
        }

        if (!was_enabled) {
            output_info(out, OUTPUT_VERBOSE, "  %s was not enabled", profile);
            not_enabled++;
        }
    }

    /* Dry-run mode: show what would happen and exit */
    if (opts->dry_run) {
        if (disabled_count > 0) {
            output_newline(out, OUTPUT_NORMAL);

            output_info(
                out, OUTPUT_NORMAL, "Would disable %zu profile%s:", disabled_count,
                disabled_count == 1 ? "" : "s"
            );
            for (size_t i = 0; i < to_disable->count; i++) {
                const char *profile = to_disable->items[i];
                /* Check if it was actually enabled */
                bool was_enabled = false;
                for (size_t j = 0; j < enabled->count; j++) {
                    if (strcmp(enabled->items[j], profile) == 0) {
                        was_enabled = true;
                        break;
                    }
                }
                if (was_enabled) {
                    output_print(
                        out, OUTPUT_NORMAL, "  - %s\n",
                        profile
                    );
                }
            }
            output_newline(out, OUTPUT_NORMAL);
            output_info(out, OUTPUT_NORMAL, "Run 'dotta apply' to remove deployed files");
        }
        goto cleanup;
    }

    /* Update state with disabled profiles */
    if (disabled_count > 0) {
        /* Process each disabled profile */
        for (size_t i = 0; i < to_disable->count; i++) {
            const char *profile = to_disable->items[i];

            /* Check if this profile was actually enabled */
            bool was_enabled = false;
            for (size_t j = 0; j < enabled->count; j++) {
                if (strcmp(enabled->items[j], profile) == 0) {
                    was_enabled = true;
                    break;
                }
            }

            if (was_enabled) {
                /* Unsync from manifest (updates to fallback or marks for removal) */
                manifest_disable_stats_t stats = { 0 };
                err = manifest_disable_profile(
                    repo, state, profile, new_enabled, &stats
                );
                if (err) {
                    err = error_wrap(
                        err, "Failed to unsync profile '%s' from manifest",
                        profile
                    );
                    goto cleanup;
                }

                /* Show manifest analysis (verbose: detailed, normal: compact) */
                output_styled(
                    out, OUTPUT_NORMAL, "  {green}✓{reset} Disabled %s\n",
                    profile
                );
                print_manifest_disable_stats(out, profile, &stats);

                /* Remove from state */
                err = state_disable_profile(state, profile);
                if (err) {
                    err = error_wrap(
                        err, "Failed to remove profile '%s' from state",
                        profile
                    );
                    goto cleanup;
                }
            }
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
    string_array_free(new_enabled);
    string_array_free(to_disable);
    string_array_free(enabled);
    state_free(state);

    /* If there's an error, return it now */
    if (err) return err;

    /* Summary (only shown on success) */
    if (!output_is_verbose(out)) {
        output_newline(out, OUTPUT_NORMAL);
    }

    if (disabled_count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Disabled %zu profile%s",
            disabled_count, disabled_count == 1 ? "" : "s"
        );
        output_info(
            out, OUTPUT_NORMAL, "Files updated in manifest (fallback or marked for removal)"
        );
        output_info(
            out, OUTPUT_NORMAL, "Run 'dotta status' to review or 'dotta apply' to execute changes"
        );
    }

    if (not_enabled > 0 && !opts->quiet) {
        output_info(
            out, OUTPUT_NORMAL, "%zu profile%s were not enabled",
            not_enabled, not_enabled == 1 ? "" : "s"
        );
    }

    /* Return success if profiles were already disabled (idempotent) */
    if (disabled_count == 0 && not_enabled > 0) {
        return NULL;
    }

    /* Only error if nothing was specified or found */
    if (disabled_count == 0) {
        return ERROR(
            ERR_NOT_FOUND, "No specified profiles were enabled or found"
        );
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
        err = ERROR(
            ERR_INVALID_ARG, "No profiles specified\n"
            "Hint: Provide profiles in desired order: "
            "dotta profile reorder <p1> <p2> ..."
        );
        goto cleanup;
    }

    /* Load state (with locking for write transaction) */
    err = state_open(repo, &state);
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
    if (current_enabled->count == 0) {
        err = ERROR(
            ERR_VALIDATION, "No enabled profiles to reorder\n"
            "Hint: Run 'dotta profile enable <name>' first"
        );
        goto cleanup;
    }

    /* Edge case: single profile */
    if (current_enabled->count == 1) {
        if (!opts->quiet) {
            output_info(
                out, OUTPUT_NORMAL, "Only one enabled profile, nothing to reorder"
            );
        }
        goto cleanup;  /* Success, but no-op */
    }

    /* Validation 1: Check for duplicates in new order */
    for (size_t i = 0; i < opts->profile_count; i++) {
        for (size_t j = i + 1; j < opts->profile_count; j++) {
            if (strcmp(opts->profiles[i], opts->profiles[j]) == 0) {
                err = ERROR(
                    ERR_VALIDATION,
                    "Profile '%s' appears multiple times in reorder list",
                    opts->profiles[i]
                );
                goto cleanup;
            }
        }
    }

    /* Validation 2: All provided profiles must be currently enabled */
    for (size_t i = 0; i < opts->profile_count; i++) {
        bool is_enabled = false;
        for (size_t j = 0; j < current_enabled->count; j++) {
            if (strcmp(opts->profiles[i], current_enabled->items[j]) == 0) {
                is_enabled = true;
                break;
            }
        }
        if (!is_enabled) {
            err = ERROR(
                ERR_VALIDATION, "Profile '%s' is not enabled\n"
                "Hint: Only enabled profiles can be reordered."
                " Run 'dotta profile list' to see enabled profiles",
                opts->profiles[i]
            );
            goto cleanup;
        }
    }

    /* Validation 3: Profile count must match */
    if (opts->profile_count != current_enabled->count) {
        err = ERROR(
            ERR_VALIDATION, "Profile count mismatch: %zu enabled, %zu provided\n"
            "Hint: All enabled profiles must be included in reorder",
            current_enabled->count, opts->profile_count
        );
        goto cleanup;
    }

    /* Validation 4: All currently enabled profiles must be included */
    for (size_t i = 0; i < current_enabled->count; i++) {
        const char *enabled_profile = current_enabled->items[i];
        bool found = false;
        for (size_t j = 0; j < opts->profile_count; j++) {
            if (strcmp(opts->profiles[j], enabled_profile) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            err = ERROR(
                ERR_VALIDATION, "Missing enabled profile '%s' from reorder list\n"
                "Hint: All enabled profiles must be included", enabled_profile
            );
            goto cleanup;
        }
    }

    /* Check if order actually changed (idempotency) */
    bool order_changed = false;
    for (size_t i = 0; i < opts->profile_count; i++) {
        if (strcmp(opts->profiles[i], current_enabled->items[i]) != 0) {
            order_changed = true;
            break;
        }
    }

    if (!order_changed) {
        if (!opts->quiet) {
            output_info(out, OUTPUT_NORMAL, "No change - profiles already in requested order");
        }
        goto cleanup;  /* Success, but no-op */
    }

    /* Show before/after in verbose mode */
    output_section(out, OUTPUT_VERBOSE, "Profile order change");

    output_print(out, OUTPUT_VERBOSE, "  Before:");
    for (size_t i = 0; i < current_enabled->count; i++) {
        output_print(
            out, OUTPUT_VERBOSE, " %s",
            current_enabled->items[i]
        );
    }
    output_newline(out, OUTPUT_VERBOSE);

    output_print(out, OUTPUT_VERBOSE, "  After: ");
    for (size_t i = 0; i < opts->profile_count; i++) {
        output_print(
            out, OUTPUT_VERBOSE, " %s",
            opts->profiles[i]
        );
    }
    output_newline(out, OUTPUT_VERBOSE);

    /* Update state with new order */
    string_array_t new_order = {
        .items    = opts->profiles,
        .count    = opts->profile_count,
        .capacity = opts->profile_count
    };
    err = state_set_profiles(state, &new_order);
    if (err) {
        err = error_wrap(err, "Failed to update state");
        goto cleanup;
    }

    /* Update manifest to reflect new precedence order */
    err = manifest_reorder_profiles(repo, state, &new_order);
    if (err) {
        err = error_wrap(err, "Failed to update manifest with new precedence");
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
        output_newline(out, OUTPUT_NORMAL);
        output_success(
            out, OUTPUT_NORMAL, "Reordered %zu profile%s",
            opts->profile_count, opts->profile_count == 1 ? "" : "s"
        );
        output_info(
            out, OUTPUT_NORMAL, "Manifest updated to reflect new precedence"
        );
        output_hint(
            out, OUTPUT_NORMAL, "Run 'dotta status' to review changes"
        );
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
    error_t *err = NULL;

    /* State for reporting (not cleaned up) */
    bool has_issues = false;
    bool fixed_enabled_profiles = false;  /* Track what we actually fixed */
    bool has_orphaned_files = false;      /* Track issues we can't fix */
    size_t orphaned_files = 0;

    /* Load state (with locking if we're going to fix issues) */
    if (opts->fix) {
        err = state_open(repo, &state);
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

    output_section(out, OUTPUT_NORMAL, "Validating profile state");

    /* Check 1: Enabled profiles exist as branches */
    missing = string_array_new(0);
    if (!missing) {
        err = ERROR(ERR_MEMORY, "Failed to create array");
        goto cleanup;
    }

    for (size_t i = 0; i < enabled->count; i++) {
        const char *profile = enabled->items[i];

        if (!profile_exists(repo, profile)) {
            err = string_array_push(missing, profile);
            if (err) {
                err = error_wrap(err, "Failed to add profile to missing list");
                goto cleanup;
            }
            has_issues = true;
        }
    }

    if (missing->count > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "Found %zu missing profile%s in state:",
            missing->count, missing->count == 1 ? "" : "s"
        );

        for (size_t i = 0; i < missing->count; i++) {
            output_print(out, OUTPUT_NORMAL, "  • %s\n", missing->items[i]);
        }

        if (opts->fix) {
            /* Remove missing profiles from state */
            for (size_t i = 0; i < missing->count; i++) {
                const char *profile = missing->items[i];
                err = state_disable_profile(state, profile);
                if (err) {
                    err = error_wrap(
                        err, "Failed to remove missing profile '%s' from state",
                        profile
                    );
                    goto cleanup;
                }
            }

            err = state_save(repo, state);
            if (err) {
                err = error_wrap(err, "Failed to save state");
                goto cleanup;
            }

            output_success(out, OUTPUT_NORMAL, "Removed missing profiles from state");
            fixed_enabled_profiles = true;
        } else {
            output_hint(out, OUTPUT_NORMAL, "Run 'dotta profile validate --fix' to remove them");
        }
    }

    /* Check 2: State file entries reference valid profiles */
    size_t state_file_count = 0;
    state_file_entry_t *state_files = NULL;
    err = state_get_all_files(state, NULL, &state_files, &state_file_count);
    if (err) {
        goto cleanup;
    }

    for (size_t i = 0; i < state_file_count; i++) {
        const char *profile = state_files[i].profile;
        if (!profile_exists(repo, profile)) {
            orphaned_files++;
            has_issues = true;
            has_orphaned_files = true;
        }
    }

    state_free_all_files(state_files, state_file_count);

    if (orphaned_files > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "Found %zu orphaned file entr%s in state",
            orphaned_files, orphaned_files == 1 ? "y" : "ies"
        );
        output_hint(out, OUTPUT_NORMAL, "  Run 'dotta apply' to clean up");
    }

cleanup:
    /* Cleanup all resources */
    string_array_free(missing);
    string_array_free(enabled);
    state_free(state);

    /* If there's an error, return it now */
    if (err) {
        return err;
    }

    /* Summary (only shown on success) */
    output_newline(out, OUTPUT_NORMAL);
    if (!has_issues) {
        output_success(out, OUTPUT_NORMAL, "Profile state is valid");
    } else {
        if (opts->fix) {
            /* Be accurate about what was actually fixed */
            if (fixed_enabled_profiles && !has_orphaned_files) {
                output_success(
                    out, OUTPUT_NORMAL, "Fixed all profile state issues"
                );
            } else if (fixed_enabled_profiles && has_orphaned_files) {
                output_info(
                    out, OUTPUT_NORMAL, "Fixed enabled profile list"
                );
                output_info(
                    out, OUTPUT_NORMAL, "Orphaned files require 'dotta apply' to clean up"
                );
            } else if (!fixed_enabled_profiles && has_orphaned_files) {
                output_warning(
                    out, OUTPUT_NORMAL, "Profile state has issues that require 'dotta apply'"
                );
            } else {  /* Shouldn't reach here, but handle gracefully */
                output_warning(
                    out, OUTPUT_NORMAL, "Profile state has issues"
                );
            }
        } else {
            output_warning(
                out, OUTPUT_NORMAL, "Profile state has issues"
            );
            output_info(
                out, OUTPUT_NORMAL, "Run 'dotta profile validate --fix'"
            );
        }
    }

    return NULL;
}

/**
 * Profile command dispatcher
 */
error_t *cmd_profile(const args_ctx_t *ctx, const cmd_profile_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    output_ctx_t *out = ctx->out;

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
            result = ERROR(
                ERR_INVALID_ARG, "Unknown subcommand"
            );
            break;
    }

    return result;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Single dispatch wrapper shared by every subcommand.
 *
 * Each sub's `init_defaults` already set the `subcommand` discriminator,
 * so `cmd_profile`'s switch routes the call.
 */
static error_t *profile_dispatch(const args_ctx_t *ctx, void *opts_v) {
    return cmd_profile(ctx, (const cmd_profile_options_t *) opts_v);
}

/* --- list --- */

static void profile_list_defaults(void *o) {
    cmd_profile_options_t *opts = o;
    opts->subcommand = PROFILE_LIST;
    opts->show_available = true;
}

static const args_opt_t profile_list_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "all",             cmd_profile_options_t,show_remote,
        "Show all available and remote profiles"
    ),
    ARGS_END,
};

static const args_command_t spec_profile_list = {
    .name          = "profile list",
    .summary       = "Show all profiles and their enabled status",
    .usage         = "%s profile list [--all]",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_list_opts,
    .init_defaults = profile_list_defaults,
    .repo_mode     = ARGS_REPO_REQUIRED,
    .dispatch      = profile_dispatch,
};

/* --- fetch --- */

static void profile_fetch_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_FETCH;
}

static const args_opt_t profile_fetch_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "all",                cmd_profile_options_t,  fetch_all,
        "Fetch all remote profiles"
    ),
    ARGS_FLAG(
        "v verbose",          cmd_profile_options_t,  verbose,
        "Show detailed progress"
    ),
    ARGS_POSITIONAL_ANY(
        cmd_profile_options_t,
        profiles,             profile_count
    ),
    ARGS_END,
};

static const args_command_t spec_profile_fetch = {
    .name          = "profile fetch",
    .summary       = "Download profiles from a remote without enabling them",
    .usage         = "%s profile fetch [--all] [-v] [<name>...]",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_fetch_opts,
    .init_defaults = profile_fetch_defaults,
    .repo_mode     = ARGS_REPO_REQUIRED,
    .dispatch      = profile_dispatch,
};

/* --- enable --- */

static void profile_enable_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_ENABLE;
}

static const args_opt_t profile_enable_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "all",
        cmd_profile_options_t,all_profiles,
        "Enable all local profiles"
    ),
    ARGS_STRING(
        "prefix",             "<path>",
        cmd_profile_options_t,custom_prefix,
        "Custom prefix for profiles with custom/ files"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_profile_options_t,verbose,
        "Show detailed progress"
    ),
    ARGS_FLAG(
        "q quiet",
        cmd_profile_options_t,quiet,
        "Suppress non-error output"
    ),
    ARGS_POSITIONAL_ANY(
        cmd_profile_options_t,profiles, profile_count
    ),
    ARGS_END,
};

static const args_command_t spec_profile_enable = {
    .name          = "profile enable",
    .summary       = "Enable profiles for deployment",
    .usage         = "%s profile enable [--all] [--prefix <path>] [-v|-q] [<name>...]",
    .description   =
        "Enables one or more profiles so that 'dotta apply' deploys their files.\n"
        "\n"
        "  --prefix <path> attaches a custom mount point for profiles that contain\n"
        "  custom/ files (e.g. --prefix /mnt/jails/web). Only valid for a single\n"
        "  profile per invocation.\n",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_enable_opts,
    .init_defaults = profile_enable_defaults,
    .repo_mode     = ARGS_REPO_REQUIRED,
    .dispatch      = profile_dispatch,
};

/* --- disable --- */

static void profile_disable_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_DISABLE;
}

static const args_opt_t profile_disable_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "all",
        cmd_profile_options_t,all_profiles,
        "Disable all currently enabled profiles"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_profile_options_t,dry_run,
        "Show what would change without modifying state"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_profile_options_t,verbose,
        "Show detailed progress"
    ),
    ARGS_FLAG(
        "q quiet",
        cmd_profile_options_t,quiet,
        "Suppress non-error output"
    ),
    ARGS_POSITIONAL_ANY(
        cmd_profile_options_t,profiles, profile_count
    ),
    ARGS_END,
};

static const args_command_t spec_profile_disable = {
    .name          = "profile disable",
    .summary       = "Disable profiles, mark for removal on next apply",
    .usage         = "%s profile disable [--all] [-n] [-v|-q] [<name>...]",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_disable_opts,
    .init_defaults = profile_disable_defaults,
    .repo_mode     = ARGS_REPO_REQUIRED,
    .dispatch      = profile_dispatch,
};

/* --- reorder --- */

static void profile_reorder_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_REORDER;
}

static const args_opt_t profile_reorder_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "v verbose",
        cmd_profile_options_t,verbose,
        "Show the profile order before and after the change"
    ),
    ARGS_FLAG(
        "q quiet",
        cmd_profile_options_t,quiet,
        "Suppress non-error output"
    ),
    ARGS_POSITIONAL_ANY(
        cmd_profile_options_t,profiles, profile_count
    ),
    ARGS_END,
};

static const args_command_t spec_profile_reorder = {
    .name          = "profile reorder",
    .summary       = "Change the layering order of enabled profiles",
    .usage         = "%s profile reorder [-v|-q] <name>...",
    .description   =
        "Provide every enabled profile in the desired order. Later profiles\n"
        "override earlier ones during layering.\n",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_reorder_opts,
    .init_defaults = profile_reorder_defaults,
    .repo_mode     = ARGS_REPO_REQUIRED,
    .dispatch      = profile_dispatch,
};

/* --- validate --- */

static void profile_validate_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_VALIDATE;
}

static const args_opt_t profile_validate_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "fix",
        cmd_profile_options_t,fix,
        "Automatically fix any detected inconsistencies"
    ),
    ARGS_END,
};

static const args_command_t spec_profile_validate = {
    .name          = "profile validate",
    .summary       = "Check for and fix inconsistencies in the profile state",
    .usage         = "%s profile validate [--fix]",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_validate_opts,
    .init_defaults = profile_validate_defaults,
    .repo_mode     = ARGS_REPO_REQUIRED,
    .dispatch      = profile_dispatch,
};

/* --- parent: subcommand index + spec --- */

static const args_subcommand_t profile_subs[] = {
    { "list",     &spec_profile_list,     false },
    { "fetch",    &spec_profile_fetch,    false },
    { "enable",   &spec_profile_enable,   false },
    { "disable",  &spec_profile_disable,  false },
    { "reorder",  &spec_profile_reorder,  false },
    { "validate", &spec_profile_validate, false },
    { NULL,       NULL,                   false }
};

const args_command_t spec_profile = {
    .name               = "profile",
    .summary            = "Profile management and layering",
    .usage              = "%s profile <subcommand> [options]",
    .description        =
        "Manage which profiles are used in your current workspace.\n"
        "\n"
        "Profile States:\n"
        "  • Available  - Profiles that exist locally but are not enabled\n"
        "  • Enabled    - Profiles that will be deployed by 'dotta apply'\n"
        "  • Remote     - Profiles on a remote that have not been fetched yet\n"
        "\n"
        "Enabling a profile is a persistent choice that marks it for deployment.\n"
        "Run 'dotta apply' to synchronize the workspace with the set of enabled profiles.\n"
        "\n"
        "Run '%s profile <subcommand> --help' for per-subcommand options.\n",
    .examples           =
        "  %s profile list --all              # Show local and remote profiles\n"
        "  %s profile fetch darwin            # Download a profile\n"
        "  %s profile enable darwin           # Enable a profile for deployment\n"
        "  %s profile disable --all           # Disable all enabled profiles\n"
        "  %s profile reorder global darwin   # Change layering priority\n"
        "  %s profile validate --fix          # Fix state inconsistencies\n",
    .opts_size          = sizeof(cmd_profile_options_t),
    .subcommands        = profile_subs,
    .default_subcommand = &spec_profile_list,
};
