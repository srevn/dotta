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
#include "base/hashmap.h"
#include "base/output.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"
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
 * Reports gain-side attribution for one enabled profile from a single
 * apply_scope call: files_claimed (rows the profile won precedence for)
 * partitioned by lstat observation into files_present and files_missing.
 * access_errors is a subset of files_missing: paths where lstat failed
 * for a non-ENOENT reason.
 */
static void print_manifest_enable_stats(
    const output_t *out,
    const char *profile,
    const manifest_scope_stats_t *stats
) {
    if (!stats || stats->files_claimed == 0) return;

    if (output_is_verbose(out)) {
        /* Detailed breakdown */
        output_section(out, OUTPUT_VERBOSE, "Manifest Analysis");
        output_print(
            out, OUTPUT_VERBOSE, "  Profile: %s\n",
            profile
        );
        output_print(
            out, OUTPUT_VERBOSE, "  Total files: %zu\n",
            stats->files_claimed
        );

        if (stats->files_present > 0) {
            output_styled(
                out, OUTPUT_VERBOSE,
                "    - {green}%zu{reset} already deployed\n",
                stats->files_present
            );
        }

        if (stats->files_missing > 0) {
            output_styled(
                out, OUTPUT_VERBOSE,
                "    - {yellow}%zu{reset} need deployment\n",
                stats->files_missing
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
        if (stats->files_missing > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Staged %zu file%s for deployment\n",
                stats->files_missing, stats->files_missing == 1 ? "" : "s"
            );
        }
        if (stats->files_present > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Found %zu file%s already deployed\n",
                stats->files_present, stats->files_present == 1 ? "" : "s"
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
 * Reports loss-side attribution for one disabled profile from a single
 * apply_scope call: files_reassigned (picked up by a fallback profile)
 * + files_orphaned (left scope entirely → STATE_INACTIVE).
 */
static void print_manifest_disable_stats(
    const output_t *out,
    const char *profile,
    const manifest_scope_stats_t *stats
) {
    if (!stats) return;

    size_t total = stats->files_reassigned + stats->files_orphaned;
    if (total == 0) return;

    if (output_is_verbose(out)) {
        /* Detailed breakdown */
        output_section(out, OUTPUT_VERBOSE, "Manifest Analysis");
        output_print(out, OUTPUT_VERBOSE, "  Profile: %s\n", profile);

        output_print(
            out, OUTPUT_VERBOSE,
            "  Total files affected: %zu\n", total
        );

        if (stats->files_reassigned > 0) {
            output_styled(
                out, OUTPUT_VERBOSE,
                "    - {green}%zu{reset} file%s with fallback (will reassign)\n",
                stats->files_reassigned,
                stats->files_reassigned == 1 ? "" : "s"
            );
        }

        if (stats->files_orphaned > 0) {
            output_styled(
                out, OUTPUT_VERBOSE,
                "    - {red}%zu{reset} file%s without fallback (will be removed)\n",
                stats->files_orphaned,
                stats->files_orphaned == 1 ? "" : "s"
            );
        }

        output_newline(out, OUTPUT_VERBOSE);
    } else {
        /* Compact summary */
        if (stats->files_orphaned > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Staged %zu file%s for removal\n",
                stats->files_orphaned, stats->files_orphaned == 1 ? "" : "s"
            );
        }

        if (stats->files_reassigned > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Reassigned %zu file%s to lower precedence\n",
                stats->files_reassigned,
                stats->files_reassigned == 1 ? "" : "s"
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
    state_t *state,
    arena_t *arena,
    const cmd_profile_options_t *opts,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup. remote_name/remote_url are
     * arena-borrowed when the --remote branch resolves them. */
    string_array_t *enabled_profiles = NULL;
    string_array_t *all_branches = NULL;
    string_array_t *available = NULL;
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    transfer_context_t *xfer = NULL;
    string_array_t *remote_branches = NULL;
    string_array_t *remote_only = NULL;
    error_t *err = NULL;

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
        error_t *remote_err = gitops_resolve_default_remote(
            repo, arena, &remote_name, &remote_url
        );
        if (remote_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Could not detect remote: %s",
                error_message(remote_err)
            );
            error_free(remote_err);
        } else {
            /* Create transfer context for credentials */
            transfer_options_t xfer_opts = {
                .output = out,
                .url    = remote_url,
            };
            error_t *xfer_err = transfer_context_create(&xfer_opts, &xfer);
            if (xfer_err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to create transfer context: %s",
                    error_message(xfer_err)
                );
                error_free(xfer_err);
            } else {
                /*
                 * Query remote server for available branches (network operation)
                 * This contacts the remote server to get the current list of profiles,
                 * ensuring we see newly added profiles that haven't been fetched yet.
                 */
                remote_err = gitops_list_remote_branches(
                    repo, remote_name, xfer, &remote_branches
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
    /* Cleanup all resources. remote_name/remote_url are arena-borrowed. */
    string_array_free(remote_only);
    string_array_free(remote_branches);
    transfer_context_free(xfer);
    string_array_free(available);
    string_array_free(all_branches);
    string_array_free(enabled_profiles);

    return err;
}

/**
 * Profile fetch subcommand
 *
 * Downloads profiles without enabling them.
 */
static error_t *profile_fetch(
    git_repository *repo,
    arena_t *arena,
    const cmd_profile_options_t *opts,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(arena);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup. remote_name/remote_url are
     * arena-borrowed. */
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    transfer_context_t *xfer = NULL;
    string_array_t *remote_branches = NULL;
    error_t *err = NULL;

    /* Counters for summary (not cleaned up) */
    size_t fetched_count = 0;
    size_t failed_count = 0;

    /* Detect remote (name + URL — URL feeds the credential helper). */
    err = gitops_resolve_default_remote(
        repo, arena, &remote_name, &remote_url
    );
    if (err) {
        err = error_wrap(err, "No remote configured");
        goto cleanup;
    }

    /* Create transfer context for progress reporting and credentials */
    transfer_options_t xfer_opts = {
        .output             = out,
        .url                = remote_url,
        .ephemeral_progress = true,
    };
    err = transfer_context_create(&xfer_opts, &xfer);
    if (err) {
        goto cleanup;
    }

    output_section(out, OUTPUT_NORMAL, "Fetching profiles");

    if (opts->fetch_all) {
        /* Query remote server for all available branches */
        err = gitops_list_remote_branches(
            repo, remote_name, xfer, &remote_branches
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
        err = gitops_list_remote_branches(
            repo, remote_name, xfer, &available_remote
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
    /* Session-level wire stats (silent on failed sessions or no data).
     * Emit before freeing xfer so stats are still live. */
    transfer_summarize(xfer, out, OUTPUT_NORMAL);

    /* Cleanup all resources */
    string_array_free(remote_branches);
    transfer_context_free(xfer);

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
 * Four-phase flow (see manifest_apply_scope's ORDERING RULE):
 *   1. Gather & validate — resolve --all/args to a request set, then
 *      filter out already-enabled, missing, and custom-without-prefix
 *      profiles. Emits per-profile warnings; produces to_enable_validated.
 *   2. Commit scope to state — state_enable_profile per target (writes
 *      target + zero-OID sentinel), then manifest_persist_profile_head
 *      per target to fill in the real branch HEAD. enabled_profiles
 *      is now authoritative.
 *   3. Reconcile once — a single apply_scope call builds the VWD for
 *      the post-enable set, with stats_filter pinned to the newly
 *      enabled profiles so gain-side stats (files_claimed / on-disk /
 *      absent) land in the right slot per profile. Old K·M cost
 *      (rebuilding the manifest per profile) collapses to a single M.
 *   4. Per-profile feedback — iterate the validated targets to preserve
 *      per-profile output, then state_save.
 */
static error_t *profile_enable(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const cmd_profile_options_t *opts,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup */
    string_array_t *enabled = NULL;
    string_array_t *all_branches = NULL;
    string_array_t *to_enable = NULL;
    string_array_t *to_enable_validated = NULL;
    hashmap_t *enabled_set = NULL;
    hashmap_t *seen_set = NULL;
    manifest_scope_stats_t *stats = NULL;
    error_t *err = NULL;

    /* Phase 1 observations — tallied during the validation loop. */
    size_t already_enabled = 0;
    size_t not_found = 0;

    /* Phase 1: Gather & validate */
    err = state_get_profiles(state, &enabled);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* O(1) already-enabled lookups; replaces the inner linear scan that
     * made the previous flow O(K·E) on the membership check.
     *
     * seen_set tracks profiles decided-about within this command pass, so
     * duplicate args like `enable foo foo` are silently deduped instead of
     * producing two rows in to_enable_validated (and, downstream, two
     * "Enabled foo" lines with split stats attribution). */
    size_t cap = enabled->count > 0 ? enabled->count * 2 : 16;
    enabled_set = hashmap_borrow(cap);
    seen_set = hashmap_borrow(cap);
    if (!enabled_set || !seen_set) {
        err = ERROR(ERR_MEMORY, "Failed to create membership sets");
        goto cleanup;
    }
    for (size_t i = 0; i < enabled->count; i++) {
        err = hashmap_set(enabled_set, enabled->items[i], (void *) (uintptr_t) 1);
        if (err) {
            err = error_wrap(err, "Failed to populate enabled membership set");
            goto cleanup;
        }
    }

    /* Resolve the request set (--all → list of local branches; args →
     * verbatim). Both paths deposit into to_enable; Phase 1's filter
     * loop decides which ones are actually actionable. */
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

    /* Fatal up-front: --target binds to a specific profile and cannot
     * disambiguate among many. Caught here before any state mutation. */
    if (opts->target && to_enable->count > 1) {
        output_error(out, "Cannot use --target with multiple profiles");
        output_hint(out, OUTPUT_NORMAL, "Enable each profile separately:");

        for (size_t i = 0; i < to_enable->count; i++) {
            output_hint(
                out, OUTPUT_NORMAL, "dotta profile enable %s --target <path>",
                to_enable->items[i]
            );
        }
        err = ERROR(ERR_INVALID_ARG, "Ambiguous --target usage");
        goto cleanup;
    }

    /* Fatal up-front: validate the prefix value itself. Validating inside
     * the per-profile loop used to categorize a bad prefix as not_found,
     * which mislabels a CLI input problem as a missing profile. With the
     * --target-requires-single-profile rule above, a single validation
     * here covers every path that can reach Phase 2. */
    if (opts->target) {
        err = mount_validate_target(opts->target);
        if (err) {
            err = error_wrap(err, "Invalid --target value");
            goto cleanup;
        }
    }

    /* Filter: already-enabled and missing-branch are non-fatal per-profile
     * skips. Custom-without-prefix is fatal — the profile exists but the
     * user's input is incomplete, which is categorically different from
     * "not found". Treating it as a per-profile skip previously leaked
     * into the not_found tally and produced contradictory diagnostics.
     * The surviving set lands in to_enable_validated. */
    to_enable_validated = string_array_new(0);
    if (!to_enable_validated) {
        err = ERROR(ERR_MEMORY, "Failed to create validated list");
        goto cleanup;
    }

    for (size_t i = 0; i < to_enable->count; i++) {
        const char *profile = to_enable->items[i];

        /* Silently dedupe duplicate args — we've already decided about
         * this profile earlier in this pass. */
        if (hashmap_has(seen_set, profile)) continue;
        err = hashmap_set(seen_set, profile, (void *) (uintptr_t) 1);
        if (err) {
            err = error_wrap(err, "Failed to mark profile '%s' as seen", profile);
            goto cleanup;
        }

        if (hashmap_has(enabled_set, profile)) {
            output_info(out, OUTPUT_VERBOSE, "  %s already enabled", profile);
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

        /* Fatal: the profile exists, but its custom/ files require a
         * mount point the user didn't provide. Mirrors the
         * --target-with-multiple-profiles check above — both are
         * CLI-input errors, not per-profile skips. */
        if (has_custom && !opts->target) {
            output_error(
                out, "Profile '%s' contains custom/ files but --target not provided",
                profile
            );
            output_hint(
                out, OUTPUT_NORMAL, "dotta profile enable %s --target /path/to/target",
                profile
            );
            err = ERROR(
                ERR_INVALID_ARG,
                "Profile '%s' requires --target", profile
            );
            goto cleanup;
        }

        err = string_array_push(to_enable_validated, profile);
        if (err) {
            err = error_wrap(err, "Failed to add profile to validated list");
            goto cleanup;
        }
    }

    /* Dry-run: preview what a live run would do, skip every state
     * mutation. Dry-run owns its complete UX below — the live-path
     * summary is unreachable on this branch (goto cleanup bypasses it). */
    if (opts->dry_run) {
        if (!output_is_verbose(out)) {
            output_newline(out, OUTPUT_NORMAL);
        }

        if (to_enable_validated->count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Would enable %zu profile%s:",
                to_enable_validated->count,
                to_enable_validated->count == 1 ? "" : "s"
            );
            for (size_t i = 0; i < to_enable_validated->count; i++) {
                output_print(
                    out, OUTPUT_NORMAL, "  - %s\n",
                    to_enable_validated->items[i]
                );
            }
            output_newline(out, OUTPUT_NORMAL);
            output_info(
                out, OUTPUT_NORMAL, "Run 'dotta apply' to deploy files"
            );
        }
        if (already_enabled > 0) {
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
        /* Mirror the live-path terminal: if nothing would be enabled
         * because every requested profile was missing, surface the same
         * error a live run would produce. Idempotent cases (all already
         * enabled) fall through to cleanup with err == NULL. */
        if (to_enable_validated->count == 0 && not_found > 0) {
            err = ERROR(ERR_NOT_FOUND, "No profiles were enabled");
        }
        goto cleanup;
    }

    /* Phases 2–4 share the "we have work to do" precondition. Wrapping
     * them together makes the "nothing validated → exit without touching
     * state" path explicit; the transaction opened by state_open then
     * rolls back via state_free on the no-op exit. */
    if (to_enable_validated->count > 0) {
        /* Phase 2: Commit scope to state */
        for (size_t i = 0; i < to_enable_validated->count; i++) {
            const char *profile = to_enable_validated->items[i];

            err = state_enable_profile(state, profile, opts->target);
            if (err) {
                err = error_wrap(
                    err, "Failed to enable profile '%s' in state", profile
                );
                goto cleanup;
            }

            /* Replace the zero-OID sentinel state_enable_profile writes
             * with the real branch HEAD so enabled_profiles is fully
             * authoritative before apply_scope runs. */
            err = manifest_persist_profile_head(repo, state, profile);
            if (err) {
                err = error_wrap(
                    err, "Failed to persist HEAD for profile '%s'", profile
                );
                goto cleanup;
            }
        }

        /* Phase 3: Reconcile once */
        stats = calloc(to_enable_validated->count, sizeof(*stats));
        if (!stats) {
            err = ERROR(ERR_MEMORY, "Failed to allocate enable stats");
            goto cleanup;
        }

        err = manifest_apply_scope(
            repo, state, arena, to_enable_validated, stats
        );
        if (err) {
            err = error_wrap(err, "Failed to reconcile manifest after enable");
            goto cleanup;
        }

        /* Phase 4: Per-profile feedback */
        for (size_t i = 0; i < to_enable_validated->count; i++) {
            output_styled(
                out, OUTPUT_NORMAL, "  {green}✓{reset} Enabled %s\n",
                to_enable_validated->items[i]
            );
            print_manifest_enable_stats(
                out, to_enable_validated->items[i], &stats[i]
            );
        }

        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to save state");
            goto cleanup;
        }
    }

    /* Live summary — only runs on non-dry-run, non-error completion.
     * Any Phase 2-4 failure sets err and jumps to cleanup, skipping
     * the summary; dry-run owns its own messaging above. */
    if (!output_is_verbose(out)) {
        output_newline(out, OUTPUT_NORMAL);
    }

    if (to_enable_validated->count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Enabled %zu profile%s",
            to_enable_validated->count,
            to_enable_validated->count == 1 ? "" : "s"
        );
        output_info(
            out, OUTPUT_NORMAL, "Files staged for deployment in manifest"
        );
    }
    if (already_enabled > 0) {
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

    /* Terminal: error only if the user's inputs produced zero validated
     * profiles AND at least one was genuinely missing. Pure idempotent
     * cases (all already-enabled, or --all on an empty repo) fall
     * through to cleanup with err == NULL. */
    if (to_enable_validated->count == 0 && not_found > 0) {
        err = ERROR(ERR_NOT_FOUND, "No profiles were enabled");
    }

cleanup:
    /* Cleanup all resources. Hashmaps freed before the string_arrays they
     * borrow keys from (enabled, to_enable) to respect the borrow lifetime;
     * seen_set borrows keys from to_enable, enabled_set from enabled. */
    free(stats);
    if (seen_set) hashmap_free(seen_set, NULL);
    if (enabled_set) hashmap_free(enabled_set, NULL);
    string_array_free(to_enable_validated);
    string_array_free(to_enable);
    string_array_free(all_branches);
    string_array_free(enabled);

    return err;
}

/**
 * Profile disable subcommand
 *
 * Four-phase flow (see manifest_apply_scope's ORDERING RULE):
 *   1. Gather & validate — filter requested profiles to those actually
 *      enabled; emit not-enabled diagnostics up front.
 *   2. Commit scope to state — state_disable_profile per validated
 *      target; enabled_profiles is now authoritative for the target set.
 *   3. Reconcile once — a single apply_scope call rebuilds the VWD
 *      against the post-disable enabled set and attributes loss-side
 *      stats (files_reassigned / files_orphaned) to each disabled
 *      profile via stats_filter.
 *   4. Per-profile feedback — iterate the validated targets to preserve
 *      the existing per-profile UX.
 */
static error_t *profile_disable(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const cmd_profile_options_t *opts,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup */
    string_array_t *enabled = NULL;
    string_array_t *to_disable_validated = NULL;
    hashmap_t *enabled_set = NULL;
    hashmap_t *seen_set = NULL;
    manifest_scope_stats_t *stats = NULL;
    error_t *err = NULL;

    /* Phase 1 observation — tallied during explicit-args validation. */
    size_t not_enabled = 0;

    /* Phase 1: Gather & validate */
    err = state_get_profiles(state, &enabled);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* --all on an empty enabled set is idempotent: there is nothing to
     * disable, which matches `disable <name>` where <name> is not
     * enabled (also a no-op success). The historic ERR_NOT_FOUND here
     * made the two paths inconsistent for the same user intent. */
    if (opts->all_profiles && enabled->count == 0) {
        if (!opts->quiet) {
            output_info(out, OUTPUT_NORMAL, "No enabled profiles to disable");
        }
        goto cleanup;  /* err is NULL — idempotent success */
    }

    /* O(1) membership lookups; pre-loop replaces the inner linear scans
     * that made the old flow quadratic when many profiles were passed.
     *
     * seen_set tracks profiles decided-about within this command pass,
     * so duplicate args (`disable foo foo`) are silently deduped and
     * don't produce two rows in to_disable_validated. Only the explicit-
     * args path consults it; --all iterates the unique enabled set. */
    size_t cap = enabled->count > 0 ? enabled->count * 2 : 16;
    enabled_set = hashmap_borrow(cap);
    seen_set = hashmap_borrow(cap);
    if (!enabled_set || !seen_set) {
        err = ERROR(ERR_MEMORY, "Failed to create membership sets");
        goto cleanup;
    }
    for (size_t i = 0; i < enabled->count; i++) {
        err = hashmap_set(enabled_set, enabled->items[i], (void *) (uintptr_t) 1);
        if (err) {
            err = error_wrap(err, "Failed to populate enabled membership set");
            goto cleanup;
        }
    }

    to_disable_validated = string_array_new(0);
    if (!to_disable_validated) {
        err = ERROR(ERR_MEMORY, "Failed to create array");
        goto cleanup;
    }

    if (opts->all_profiles) {
        /* --all: every currently enabled profile is, by definition, valid. */
        for (size_t i = 0; i < enabled->count; i++) {
            err = string_array_push(to_disable_validated, enabled->items[i]);
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
            const char *profile = opts->profiles[i];

            /* Silently dedupe duplicate args — we've already decided
             * about this profile earlier in this pass. */
            if (hashmap_has(seen_set, profile)) continue;
            err = hashmap_set(seen_set, profile, (void *) (uintptr_t) 1);
            if (err) {
                err = error_wrap(err, "Failed to mark profile '%s' as seen", profile);
                goto cleanup;
            }

            if (hashmap_has(enabled_set, profile)) {
                err = string_array_push(to_disable_validated, profile);
                if (err) {
                    err = error_wrap(err, "Failed to add profile to disable list");
                    goto cleanup;
                }
            } else {
                output_info(
                    out, OUTPUT_VERBOSE, "  %s was not enabled", profile
                );
                not_enabled++;
            }
        }
    }

    /* Dry-run: preview what a live run would do, skip every state
     * mutation. Dry-run owns its complete UX below — the live-path
     * summary is unreachable on this branch (goto cleanup bypasses it). */
    if (opts->dry_run) {
        if (!output_is_verbose(out)) {
            output_newline(out, OUTPUT_NORMAL);
        }

        if (to_disable_validated->count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Would disable %zu profile%s:",
                to_disable_validated->count,
                to_disable_validated->count == 1 ? "" : "s"
            );
            for (size_t i = 0; i < to_disable_validated->count; i++) {
                output_print(
                    out, OUTPUT_NORMAL, "  - %s\n",
                    to_disable_validated->items[i]
                );
            }
            output_newline(out, OUTPUT_NORMAL);
            output_info(
                out, OUTPUT_NORMAL, "Run 'dotta apply' to remove deployed files"
            );
        }
        if (not_enabled > 0) {
            output_info(
                out, OUTPUT_NORMAL, "%zu profile%s not enabled",
                not_enabled, not_enabled == 1 ? "" : "s"
            );
        }
        goto cleanup;
    }

    /* Phases 2–4 share the "we have work to do" precondition. Wrapping
     * them together makes the "nothing validated → exit without touching
     * state" path explicit; the transaction opened by state_open then
     * rolls back via state_free on the no-op exit. */
    if (to_disable_validated->count > 0) {
        /* Phase 2: Commit scope to state */
        for (size_t i = 0; i < to_disable_validated->count; i++) {
            err = state_disable_profile(state, to_disable_validated->items[i]);
            if (err) {
                err = error_wrap(
                    err, "Failed to remove profile '%s' from state",
                    to_disable_validated->items[i]
                );
                goto cleanup;
            }
        }

        /* Phase 3: Reconcile once */
        stats = calloc(to_disable_validated->count, sizeof(*stats));
        if (!stats) {
            err = ERROR(ERR_MEMORY, "Failed to allocate disable stats");
            goto cleanup;
        }

        err = manifest_apply_scope(
            repo, state, arena, to_disable_validated, stats
        );
        if (err) {
            err = error_wrap(err, "Failed to reconcile manifest after disable");
            goto cleanup;
        }

        /* Phase 4: Per-profile feedback */
        for (size_t i = 0; i < to_disable_validated->count; i++) {
            output_styled(
                out, OUTPUT_NORMAL, "  {green}✓{reset} Disabled %s\n",
                to_disable_validated->items[i]
            );
            print_manifest_disable_stats(
                out, to_disable_validated->items[i], &stats[i]
            );
        }

        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to save state");
            goto cleanup;
        }
    }

    /* Live summary — only runs on non-dry-run, non-error completion.
     * All reachable states here are successes:
     *   - count > 0: actual work performed.
     *   - count == 0 && not_enabled > 0: idempotent (user asked to
     *     disable profiles that weren't enabled).
     *   - count == 0 && not_enabled == 0 is unreachable: the explicit-
     *     args path requires opts->profile_count > 0 (caught earlier),
     *     and the --all-on-empty case is caught by the early exit. */
    if (!output_is_verbose(out)) {
        output_newline(out, OUTPUT_NORMAL);
    }

    if (to_disable_validated->count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Disabled %zu profile%s",
            to_disable_validated->count,
            to_disable_validated->count == 1 ? "" : "s"
        );
        output_info(
            out, OUTPUT_NORMAL, "Files updated in manifest (fallback or marked for removal)"
        );
    }

    if (not_enabled > 0) {
        output_info(
            out, OUTPUT_NORMAL, "%zu profile%s not enabled",
            not_enabled, not_enabled == 1 ? "" : "s"
        );
    }

cleanup:
    /* Cleanup all resources. Hashmaps freed before the string_arrays whose
     * items they borrow — seen_set borrows from opts->profiles (caller-
     * owned, outlives us) and enabled_set from enabled (owned here). */
    free(stats);
    if (seen_set) hashmap_free(seen_set, NULL);
    if (enabled_set) hashmap_free(enabled_set, NULL);
    string_array_free(to_disable_validated);
    string_array_free(enabled);

    return err;
}

/**
 * Profile reorder subcommand
 *
 * Changes the order of enabled profiles, which affects layering precedence.
 */
static error_t *profile_reorder(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const cmd_profile_options_t *opts,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup */
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
            output_info(out, OUTPUT_NORMAL, "Profiles already in requested order");
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

    /* Reconcile manifest against the new precedence order.
     *
     * state_set_profiles preserves commit_oid for profiles that remain
     * enabled, so enabled_profiles is already fully authoritative — no
     * persist_profile_head loop needed for reorder. */
    err = manifest_apply_scope(repo, state, arena, NULL, NULL);
    if (err) {
        err = error_wrap(err, "Failed to reconcile manifest with new precedence");
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

    return err;
}

/**
 * Profile validate subcommand
 *
 * Checks state consistency and offers to fix issues.
 */
static error_t *profile_validate(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const cmd_profile_options_t *opts,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Resource tracking for cleanup */
    string_array_t *enabled = NULL;
    string_array_t *missing = NULL;
    error_t *err = NULL;

    /* State for reporting (not cleaned up) */
    bool has_issues = false;
    bool fixed_enabled_profiles = false;  /* Track what we actually fixed */
    bool has_orphaned_files = false;      /* Track issues we can't fix */
    size_t orphaned_files = 0;

    /* Promote to a write transaction when we intend to mutate */
    if (opts->fix) {
        err = state_begin(state);
        if (err) {
            err = error_wrap(err, "Failed to begin state transaction");
            goto cleanup;
        }
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

            err = state_commit(state);
            if (err) {
                err = error_wrap(err, "Failed to commit state transaction");
                goto cleanup;
            }

            output_success(out, OUTPUT_NORMAL, "Removed missing profiles from state");
            fixed_enabled_profiles = true;
        } else {
            output_hint(out, OUTPUT_NORMAL, "Run 'dotta profile validate --fix' to remove them");
        }
    }

    /* Check 2: State file entries reference valid profiles
     *
     * Dedupe by profile before probing Git: F per-row probes (where F is the
     * total manifest entry count) collapses to P probes (where P is the
     * distinct-profile count, typically <10). For each missing profile we
     * then ask SQL once for its row count rather than incrementing during
     * the row scan. */
    string_array_t *file_profiles = NULL;
    err = state_get_distinct_file_profiles(state, &file_profiles);
    if (err) goto cleanup;

    for (size_t i = 0; i < file_profiles->count; i++) {
        const char *profile = file_profiles->items[i];
        if (profile_exists(repo, profile)) continue;

        size_t n = 0;
        err = state_count_files_by_profile(state, profile, &n);
        if (err) {
            string_array_free(file_profiles);
            goto cleanup;
        }
        orphaned_files += n;
        has_issues = true;
        has_orphaned_files = true;
    }
    string_array_free(file_profiles);

    if (orphaned_files > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "Found %zu orphaned file entr%s in state",
            orphaned_files, orphaned_files == 1 ? "y" : "ies"
        );
        output_hint(out, OUTPUT_NORMAL, "  Run 'dotta apply' to clean up");
    }

cleanup:
    /* Cleanup all resources. state_rollback is a no-op if no transaction
     * is active, so it's safe to call unconditionally on the borrowed handle */
    state_rollback(state);

    string_array_free(missing);
    string_array_free(enabled);

    /* If there's an error, return it now */
    if (err) return err;

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
error_t *cmd_profile(const dotta_ctx_t *ctx, const cmd_profile_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    state_t *state = ctx->state;  /* NULL for fetch (repo_only) */
    output_t *out = ctx->out;

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
            result = profile_list(repo, state, ctx->arena, opts, out);
            break;

        case PROFILE_FETCH:
            result = profile_fetch(repo, ctx->arena, opts, out);
            break;

        case PROFILE_ENABLE:
            result = profile_enable(repo, state, ctx->arena, opts, out);
            break;

        case PROFILE_DISABLE:
            result = profile_disable(repo, state, ctx->arena, opts, out);
            break;

        case PROFILE_REORDER:
            result = profile_reorder(repo, state, ctx->arena, opts, out);
            break;

        case PROFILE_VALIDATE:
            result = profile_validate(repo, state, ctx->arena, opts, out);
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
static error_t *profile_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
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
    .payload       = &dotta_ext_read,
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
    .payload       = &dotta_ext_repo_only,
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
        "target",             "<path>",
        cmd_profile_options_t,target,
        "Deployment target for profiles with custom/ files"
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

static const args_command_t spec_profile_enable = {
    .name          = "profile enable",
    .summary       = "Enable profiles for deployment",
    .usage         = "%s profile enable [options] [<name>...]",
    .description   =
        "Enables one or more profiles so that 'dotta apply' deploys their files.\n"
        "\n"
        "  --target <path> attaches a custom mount point for profiles that contain\n"
        "  custom/ files (e.g. --target /mnt/jails/web). Only valid for a single\n"
        "  profile per invocation.\n",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_enable_opts,
    .init_defaults = profile_enable_defaults,
    .payload       = &dotta_ext_write,
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
    .usage         = "%s profile disable [options] [<name>...]",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_disable_opts,
    .init_defaults = profile_disable_defaults,
    .payload       = &dotta_ext_write,
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
    .usage         = "%s profile reorder [options] [<name>...]",
    .description   =
        "Provide every enabled profile in the desired order. Later profiles\n"
        "override earlier ones during layering.\n",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_reorder_opts,
    .init_defaults = profile_reorder_defaults,
    .payload       = &dotta_ext_write,
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
    .payload       = &dotta_ext_read,
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
        "Enabling a profile is a persistent choice that marks it for deployment.\n"
        "Run 'dotta apply' to synchronize the workspace with the set of enabled profiles.\n",
    .notes              =
        "Manage which profiles are used in your current workspace.\n"
        "Profile States:\n"
        "  • Available  - Profiles that exist locally but are not enabled\n"
        "  • Enabled    - Profiles that will be deployed by 'dotta apply'\n"
        "  • Remote     - Profiles on a remote that have not been fetched yet\n",
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
