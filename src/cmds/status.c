/**
 * status.c - Show status of managed files
 */

#include "status.h"

#include <git2.h>
#include <stdio.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/profiles.h"
#include "core/state.h"
#include "core/upstream.h"
#include "core/workspace.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"
#include "utils/privilege.h"
#include "utils/timeutil.h"

/**
 * Display enabled profiles and last deployment info
 */
static void display_enabled_profiles(
    output_ctx_t *out,
    const profile_list_t *profiles,
    const manifest_t *manifest,
    const state_t *state,
    bool verbose
) {
    if (!out || !profiles) {
        return;
    }

    /* Show enabled profiles */
    output_section(out, "Enabled profiles");

    for (size_t i = 0; i < profiles->count; i++) {
        const profile_t *profile = &profiles->profiles[i];

        /* Format profile name */
        char *colored_name = output_colorize(out, OUTPUT_COLOR_CYAN, profile->name);

        if (colored_name) {
            output_printf(out, OUTPUT_NORMAL, "  %s", colored_name);
            free(colored_name);
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %s", profile->name);
        }

        /* Show per-profile last deployed timestamp */
        if (state) {
            time_t profile_deploy_time = state_get_profile_timestamp(state, profile->name);
            if (profile_deploy_time > 0) {
                char time_buf[64];
                char relative_buf[64];

                /* Format both absolute and relative time */
                struct tm *tm_info = localtime(&profile_deploy_time);
                strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
                format_relative_time(profile_deploy_time, relative_buf, sizeof(relative_buf));

                /* Display dimmed timestamp */
                char *dimmed_time = output_colorize(out, OUTPUT_COLOR_DIM,
                    time_buf);
                if (dimmed_time) {
                    output_printf(out, OUTPUT_NORMAL, "  %s(deployed %s)%s",
                                 output_color_code(out, OUTPUT_COLOR_DIM),
                                 relative_buf,
                                 output_color_code(out, OUTPUT_COLOR_RESET));
                    free(dimmed_time);
                } else {
                    output_printf(out, OUTPUT_NORMAL, "  (deployed %s)", relative_buf);
                }
            }
        }

        /* In verbose mode, show file count for this profile */
        if (verbose && manifest) {
            size_t profile_file_count = 0;
            for (size_t j = 0; j < manifest->count; j++) {
                if (manifest->entries[j].source_profile == profile) {
                    profile_file_count++;
                }
            }
            output_printf(out, OUTPUT_NORMAL, "\n    %zu file%s",
                         profile_file_count, profile_file_count == 1 ? "" : "s");
        }

        output_newline(out);
    }
}

/**
 * Format a diverged item entry for display
 *
 * Returns the label, color, and formatted info string for an item (file or directory).
 * Supports composite labels showing multiple metadata divergences (e.g., "[mode] [ownership]").
 */
static void format_diverged_item(
    output_ctx_t *out,
    const workspace_item_t *item,
    const char **out_label,
    output_color_t *out_color,
    char *info_buffer,
    size_t buffer_size
) {
    if (!out || !item || !out_label || !out_color || !info_buffer) {
        return;
    }

    /* Static buffer for composite label (reused across calls, safe for single-threaded CLI) */
    static char label_buffer[256];
    size_t offset = 0;

    /* Primary label from state */
    switch (item->state) {
        case WORKSPACE_STATE_UNDEPLOYED:
            offset += snprintf(label_buffer, sizeof(label_buffer), "[undeployed]");
            *out_color = OUTPUT_COLOR_CYAN;
            snprintf(info_buffer, buffer_size, "%s %s(from %s)%s",
                    item->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    item->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;

        case WORKSPACE_STATE_DELETED:
            offset += snprintf(label_buffer, sizeof(label_buffer), "[deleted]");
            *out_color = OUTPUT_COLOR_RED;
            snprintf(info_buffer, buffer_size, "%s %s(from %s)%s",
                    item->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    item->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;

        case WORKSPACE_STATE_DEPLOYED:
            /* For deployed items, prioritize divergence flags */
            if (item->divergence & DIVERGENCE_TYPE) {
                offset += snprintf(label_buffer, sizeof(label_buffer), "[type]");
                *out_color = OUTPUT_COLOR_RED;
            } else if (item->divergence & DIVERGENCE_CONTENT) {
                offset += snprintf(label_buffer, sizeof(label_buffer), "[modified]");
                *out_color = OUTPUT_COLOR_YELLOW;
            } else if (item->divergence & DIVERGENCE_MODE) {
                offset += snprintf(label_buffer, sizeof(label_buffer), "[mode]");
                *out_color = OUTPUT_COLOR_YELLOW;
            } else if (item->divergence & DIVERGENCE_OWNERSHIP) {
                offset += snprintf(label_buffer, sizeof(label_buffer), "[ownership]");
                *out_color = OUTPUT_COLOR_YELLOW;
            } else if (item->divergence & DIVERGENCE_ENCRYPTION) {
                offset += snprintf(label_buffer, sizeof(label_buffer), "[unencrypted]");
                *out_color = OUTPUT_COLOR_MAGENTA;
            }

            /* Show metadata provenance for mode/ownership if available */
            if ((item->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) &&
                item->metadata_profile) {
                snprintf(info_buffer, buffer_size, "%s %s(metadata from %s)%s",
                        item->filesystem_path,
                        output_color_code(out, OUTPUT_COLOR_DIM),
                        item->metadata_profile,
                        output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                snprintf(info_buffer, buffer_size, "%s %s(from %s)%s",
                        item->filesystem_path,
                        output_color_code(out, OUTPUT_COLOR_DIM),
                        item->profile,
                        output_color_code(out, OUTPUT_COLOR_RESET));
            }
            break;

        case WORKSPACE_STATE_ORPHANED:
            offset += snprintf(label_buffer, sizeof(label_buffer), "[orphaned]");
            *out_color = OUTPUT_COLOR_RED;
            snprintf(info_buffer, buffer_size, "%s %s(from %s)%s",
                    item->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    item->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;

        case WORKSPACE_STATE_UNTRACKED:
            offset += snprintf(label_buffer, sizeof(label_buffer), "[new]");
            *out_color = OUTPUT_COLOR_CYAN;
            snprintf(info_buffer, buffer_size, "%s %s(in %s)%s",
                    item->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    item->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;
    }

    /* Add secondary divergence labels if not already shown as primary */
    /* Only for DEPLOYED state with multiple divergences */
    if (item->state == WORKSPACE_STATE_DEPLOYED && offset < sizeof(label_buffer)) {
        /* Check each bit and add label if not the primary one shown */
        if ((item->divergence & DIVERGENCE_CONTENT) &&
            !strstr(label_buffer, "[modified]")) {
            offset += snprintf(label_buffer + offset,
                              sizeof(label_buffer) - offset, " [modified]");
        }

        if ((item->divergence & DIVERGENCE_MODE) &&
            !strstr(label_buffer, "[mode]")) {
            offset += snprintf(label_buffer + offset,
                              sizeof(label_buffer) - offset, " [mode]");
        }

        if ((item->divergence & DIVERGENCE_OWNERSHIP) &&
            !strstr(label_buffer, "[ownership]")) {
            offset += snprintf(label_buffer + offset,
                              sizeof(label_buffer) - offset, " [ownership]");
        }

        if ((item->divergence & DIVERGENCE_ENCRYPTION) &&
            !strstr(label_buffer, "[unencrypted]")) {
            offset += snprintf(label_buffer + offset,
                              sizeof(label_buffer) - offset, " [unencrypted]");
        }
    }

    /* Point out_label to the composite buffer */
    *out_label = label_buffer;
}

/**
 * Display workspace status
 *
 * Shows the consistency between profile state, deployment state, and filesystem.
 * Organized into actionable sections (Git-like structure).
 *
 * @param ws Workspace (must not be NULL, borrowed from caller)
 * @param out Output context (must not be NULL)
 * @param verbose Verbose output flag
 */
static void display_workspace_status(
    workspace_t *ws,
    output_ctx_t *out,
    bool verbose
) {
    if (!ws || !out) {
        return;
    }

    /* Get workspace status from provided workspace */
    workspace_status_t ws_status = workspace_get_status(ws);

    /* Only display section if there's something to report */
    if (ws_status != WORKSPACE_CLEAN || verbose) {
        output_newline(out);
        output_section(out, "Workspace status");

        /* Display overall status with color */
        const char *status_msg = NULL;
        output_color_t status_color = OUTPUT_COLOR_GREEN;

        switch (ws_status) {
            case WORKSPACE_CLEAN:
                status_msg = "Clean - all states aligned";
                status_color = OUTPUT_COLOR_GREEN;
                break;

            case WORKSPACE_DIRTY:
                status_msg = "Dirty - workspace has divergence";
                status_color = OUTPUT_COLOR_YELLOW;
                break;

            case WORKSPACE_INVALID:
                status_msg = "Invalid - workspace has orphaned state entries";
                status_color = OUTPUT_COLOR_RED;
                break;
        }

        if (status_msg) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s%s%s\n",
                             output_color_code(out, status_color),
                             status_msg,
                             output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  %s\n", status_msg);
            }
        }

        /* Show sectioned output for dirty/invalid workspace */
        if (ws_status != WORKSPACE_CLEAN) {
            /* Get all diverged items once */
            size_t all_count = 0;
            const workspace_item_t *all_items = workspace_get_all_diverged(ws, &all_count);

            /* Single allocation for all category pointers (5 categories × all_count slots)
             * Memory layout: [pending_removal...][uncommitted...][undeployed...][new_files...][orphaned...]
             * This provides cache-friendly contiguous memory with single malloc/free. */
            const workspace_item_t **categorized = malloc(all_count * 5 * sizeof(workspace_item_t *));
            if (!categorized) {
                output_error(out, "Failed to allocate memory for status display (%zu items)", all_count);
                return;
            }

            /* Category arrays (pointer arithmetic into single allocation) */
            const workspace_item_t **pending_removal = categorized;
            const workspace_item_t **uncommitted = categorized + all_count;
            const workspace_item_t **undeployed = categorized + all_count * 2;
            const workspace_item_t **new_files = categorized + all_count * 3;
            const workspace_item_t **orphaned = categorized + all_count * 4;

            size_t pending_removal_count = 0;
            size_t uncommitted_count = 0;
            size_t undeployed_count = 0;
            size_t new_count = 0;
            size_t orphaned_count = 0;

            for (size_t i = 0; i < all_count; i++) {
                const workspace_item_t *item = &all_items[i];

                /* Priority 1: Check manifest_status for staging operations
                 * Files with PENDING_REMOVAL status take precedence over workspace_state
                 * categorization since they represent explicit staging intent. */
                if (item->manifest_status == MANIFEST_STATUS_PENDING_REMOVAL) {
                    pending_removal[pending_removal_count++] = item;
                    continue;  /* Skip workspace_state categorization */
                }

                /* Priority 2: Categorize by workspace_state (existing logic) */
                switch (item->state) {
                    case WORKSPACE_STATE_DEPLOYED:
                        /* Deployed with divergence → uncommitted changes */
                        if (item->divergence != DIVERGENCE_NONE) {
                            uncommitted[uncommitted_count++] = item;
                        }
                        break;

                    case WORKSPACE_STATE_DELETED:
                        /* Deleted files → uncommitted changes */
                        uncommitted[uncommitted_count++] = item;
                        break;

                    case WORKSPACE_STATE_UNDEPLOYED:
                        undeployed[undeployed_count++] = item;
                        break;

                    case WORKSPACE_STATE_UNTRACKED:
                        new_files[new_count++] = item;
                        break;

                    case WORKSPACE_STATE_ORPHANED:
                        orphaned[orphaned_count++] = item;
                        break;
                }
            }

            /* Section 1: Changes to be removed (staging operations) */
            if (pending_removal_count > 0) {
                output_newline(out);
                char header[256];
                snprintf(header, sizeof(header), "Changes to be removed (%zu item%s)",
                         pending_removal_count, pending_removal_count == 1 ? "" : "s");
                output_printf(out, OUTPUT_NORMAL, "%s%s%s %s%s%s\n",
                             output_color_code(out, OUTPUT_COLOR_BOLD), header,
                             output_color_code(out, OUTPUT_COLOR_RESET),
                             output_color_code(out, OUTPUT_COLOR_DIM),
                             "(use \"dotta apply\" to remove these files)",
                             output_color_code(out, OUTPUT_COLOR_RESET));
                output_newline(out);

                for (size_t i = 0; i < pending_removal_count; i++) {
                    const workspace_item_t *item = pending_removal[i];
                    char info[1024];

                    /* Build info string with profile and file status */
                    if (!item->on_filesystem) {
                        /* File already deleted by user - note this edge case */
                        snprintf(info, sizeof(info), "%s %s(from %s, already removed)%s",
                                item->filesystem_path,
                                output_color_code(out, OUTPUT_COLOR_DIM),
                                item->profile,
                                output_color_code(out, OUTPUT_COLOR_RESET));
                    } else {
                        /* File still exists, will be removed on apply */
                        snprintf(info, sizeof(info), "%s %s(from %s)%s",
                                item->filesystem_path,
                                output_color_code(out, OUTPUT_COLOR_DIM),
                                item->profile,
                                output_color_code(out, OUTPUT_COLOR_RESET));
                    }

                    output_item(out, "[pending removal]", OUTPUT_COLOR_RED, info);
                }
            }

            /* Section 2: Uncommitted Changes */
            if (uncommitted_count > 0) {
                output_newline(out);
                char header[256];
                snprintf(header, sizeof(header), "Uncommitted changes (%zu item%s)",
                         uncommitted_count, uncommitted_count == 1 ? "" : "s");
                output_printf(out, OUTPUT_NORMAL, "%s%s%s %s%s%s\n",
                             output_color_code(out, OUTPUT_COLOR_BOLD), header,
                             output_color_code(out, OUTPUT_COLOR_RESET),
                             output_color_code(out, OUTPUT_COLOR_DIM),
                             "(use \"dotta update\" to commit these changes)",
                             output_color_code(out, OUTPUT_COLOR_RESET));
                output_newline(out);

                for (size_t i = 0; i < uncommitted_count; i++) {
                    char info[1024];
                    const char *label = NULL;
                    output_color_t color = OUTPUT_COLOR_YELLOW;
                    format_diverged_item(out, uncommitted[i], &label, &color, info, sizeof(info));
                    output_item(out, label, color, info);
                }
            }

            /* Section 3: Undeployed Files */
            if (undeployed_count > 0) {
                output_newline(out);
                char header[256];
                snprintf(header, sizeof(header), "Undeployed files (%zu item%s)",
                         undeployed_count, undeployed_count == 1 ? "" : "s");
                output_printf(out, OUTPUT_NORMAL, "%s%s%s %s%s%s\n",
                             output_color_code(out, OUTPUT_COLOR_BOLD), header,
                             output_color_code(out, OUTPUT_COLOR_RESET),
                             output_color_code(out, OUTPUT_COLOR_DIM),
                             "(use \"dotta apply\" to deploy these files)",
                             output_color_code(out, OUTPUT_COLOR_RESET));
                output_newline(out);

                for (size_t i = 0; i < undeployed_count; i++) {
                    char info[1024];
                    const char *label = NULL;
                    output_color_t color = OUTPUT_COLOR_CYAN;
                    format_diverged_item(out, undeployed[i], &label, &color,
                                       info, sizeof(info));
                    output_item(out, label, color, info);
                }
            }

            /* Section 4: New Files */
            if (new_count > 0) {
                output_newline(out);
                char header[256];
                snprintf(header, sizeof(header), "New files (%zu item%s)",
                         new_count, new_count == 1 ? "" : "s");
                output_printf(out, OUTPUT_NORMAL, "%s%s%s %s%s%s\n",
                             output_color_code(out, OUTPUT_COLOR_BOLD), header,
                             output_color_code(out, OUTPUT_COLOR_RESET),
                             output_color_code(out, OUTPUT_COLOR_DIM),
                             "(use \"dotta update --include-new\" to track these files)",
                             output_color_code(out, OUTPUT_COLOR_RESET));
                output_newline(out);

                for (size_t i = 0; i < new_count; i++) {
                    char info[1024];
                    const char *label = NULL;
                    output_color_t color = OUTPUT_COLOR_CYAN;
                    format_diverged_item(out, new_files[i], &label, &color,
                                       info, sizeof(info));
                    output_item(out, label, color, info);
                }
            }

            /* Section 5: Issues (orphaned) */
            if (orphaned_count > 0) {
                output_newline(out);
                char header[256];
                snprintf(header, sizeof(header), "Issues (%zu item%s)",
                         orphaned_count, orphaned_count == 1 ? "" : "s");
                output_printf(out, OUTPUT_NORMAL, "%s%s%s %s%s%s\n",
                             output_color_code(out, OUTPUT_COLOR_BOLD), header,
                             output_color_code(out, OUTPUT_COLOR_RESET),
                             output_color_code(out, OUTPUT_COLOR_DIM),
                             "(run \"dotta apply\" to remove orphaned files)",
                             output_color_code(out, OUTPUT_COLOR_RESET));
                output_newline(out);

                for (size_t i = 0; i < orphaned_count; i++) {
                    char info[1024];
                    const char *label = NULL;
                    output_color_t color = OUTPUT_COLOR_RED;
                    format_diverged_item(out, orphaned[i], &label, &color,
                                       info, sizeof(info));
                    output_item(out, label, color, info);
                }
            }

            /* Cleanup (single free for all category arrays) */
            free(categorized);

            output_newline(out);
        }
    }
}

/**
 * Display multi-profile files (files that exist in multiple profiles)
 *
 * Helps users understand which files have potential ownership ambiguity.
 */
static void display_multi_profile_files(
    git_repository *repo,
    profile_list_t *profiles,
    const manifest_t *manifest,
    output_ctx_t *out
) {
    if (!repo || !profiles || !manifest || !out) {
        return;
    }

    /* Count files that exist in multiple profiles */
    size_t multi_profile_count = 0;
    for (size_t i = 0; i < manifest->count; i++) {
        if (manifest->entries[i].all_profiles &&
            string_array_size(manifest->entries[i].all_profiles) > 0) {
            multi_profile_count++;
        }
    }

    /* Only display if there are multi-profile files */
    if (multi_profile_count == 0) {
        return;
    }

    output_newline(out);
    output_section(out, "Multi-profile files");
    output_info(out, "%zu file%s exist%s in multiple profiles:",
               multi_profile_count,
               multi_profile_count == 1 ? "" : "s",
               multi_profile_count == 1 ? "s" : "");
    output_newline(out);

    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];
        if (entry->all_profiles && string_array_size(entry->all_profiles) > 0) {
            /* Show which profile currently "owns" (deployed) the file */
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s%s%s  deployed from: %s%s%s\n",
                             output_color_code(out, OUTPUT_COLOR_RESET),
                             entry->filesystem_path,
                             output_color_code(out, OUTPUT_COLOR_RESET),
                             output_color_code(out, OUTPUT_COLOR_CYAN),
                             entry->source_profile->name,
                             output_color_code(out, OUTPUT_COLOR_RESET));

                /* Show all profiles containing this file */
                output_printf(out, OUTPUT_NORMAL, "    %salso in:%s ",
                             output_color_code(out, OUTPUT_COLOR_DIM),
                             output_color_code(out, OUTPUT_COLOR_RESET));

                for (size_t j = 0; j < string_array_size(entry->all_profiles); j++) {
                    const char *profile_name = string_array_get(entry->all_profiles, j);
                    /* Don't repeat the source profile */
                    if (strcmp(profile_name, entry->source_profile->name) != 0) {
                        output_printf(out, OUTPUT_NORMAL, "%s%s%s ",
                                     output_color_code(out, OUTPUT_COLOR_CYAN),
                                     profile_name,
                                     output_color_code(out, OUTPUT_COLOR_RESET));
                    }
                }
                output_newline(out);
            } else {
                output_printf(out, OUTPUT_NORMAL, "  %s  deployed from: %s\n",
                             entry->filesystem_path,
                             entry->source_profile->name);
                output_printf(out, OUTPUT_NORMAL, "    also in: ");
                for (size_t j = 0; j < string_array_size(entry->all_profiles); j++) {
                    const char *profile_name = string_array_get(entry->all_profiles, j);
                    if (strcmp(profile_name, entry->source_profile->name) != 0) {
                        output_printf(out, OUTPUT_NORMAL, "%s ", profile_name);
                    }
                }
                output_newline(out);
            }
        }
    }

    output_newline(out);
    output_info(out, "Note: Updates to these files will be committed to the profile that deployed them.");
}

/**
 * Display remote sync status for profiles
 *
 * By default shows only enabled profiles for consistency with workspace status.
 * Use show_all_profiles to report on every branch in the repository.
 */
static error_t *display_remote_status(
    git_repository *repo,
    const profile_list_t *enabled_profiles,
    output_ctx_t *out,
    bool show_all_profiles,
    bool verbose,
    bool no_fetch
) {
    CHECK_NULL(repo);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(out);

    /* Detect remote */
    char *remote_name = NULL;
    error_t *err = upstream_detect_remote(repo, &remote_name);
    if (err) {
        /* No remote configured - not an error, just skip this section */
        error_free(err);
        return NULL;
    }

    /* Determine which profiles to check */
    profile_list_t *profiles_to_check = NULL;
    bool should_free_profiles = false;

    if (show_all_profiles) {
        /* Explicit request: show ALL local profiles */
        err = profile_list_all_local(repo, &profiles_to_check);
        if (err) {
            free(remote_name);
            return error_wrap(err, "Failed to load all profiles");
        }
        should_free_profiles = true;
    } else {
        /* Default: show only enabled profiles (consistent with workspace status) */
        profiles_to_check = (profile_list_t*)enabled_profiles;  /* Borrowed reference */
    }

    if (profiles_to_check->count == 0) {
        if (should_free_profiles) {
            profile_list_free(profiles_to_check);
        }
        free(remote_name);
        return NULL;
    }

    /* Fetch if requested */
    if (!no_fetch) {
        if (verbose) {
            output_info(out, "Fetching from '%s'...", remote_name);
        }

        /* Build array of branch names for batched fetch */
        char **branch_names = calloc(profiles_to_check->count, sizeof(char *));
        if (!branch_names) {
            /* Memory allocation failed - non-fatal, just warn */
            if (verbose) {
                output_warning(out, "Failed to allocate memory for fetch operation");
            }
        } else {
            /* Populate array with borrowed references to profile names */
            for (size_t i = 0; i < profiles_to_check->count; i++) {
                branch_names[i] = (char *)profiles_to_check->profiles[i].name;
            }

            /* Perform batched fetch - single network operation for all branches */
            error_t *fetch_err = gitops_fetch_branches(
                repo, remote_name, branch_names, profiles_to_check->count, NULL
            );

            if (fetch_err) {
                /* Non-fatal: just warn and continue with status display */
                if (verbose) {
                    output_warning(out, "Failed to fetch branches: %s",
                                  error_message(fetch_err));
                }
                error_free(fetch_err);
            }

            /* Free the array (strings are borrowed, don't free them) */
            free(branch_names);
        }

        /* Add spacing after fetch output in verbose mode */
        if (verbose) {
            output_newline(out);
        }
    }

    /* Display remote sync status section */
    output_newline(out);
    char section_title[256];
    snprintf(section_title, sizeof(section_title), "Remote sync status (%s)", remote_name);
    output_section(out, section_title);

    /* Analyze and display each profile's sync state */
    size_t up_to_date = 0;
    size_t ahead = 0;
    size_t behind = 0;
    size_t diverged = 0;
    size_t no_remote = 0;

    for (size_t i = 0; i < profiles_to_check->count; i++) {
        const char *profile_name = profiles_to_check->profiles[i].name;

        /* Analyze upstream state */
        upstream_info_t *info = NULL;
        err = upstream_analyze_profile(repo, remote_name, profile_name, &info);
        if (err) {
            /* Show error for this profile but continue */
            output_error(out, "  %s: %s", profile_name, error_message(err));
            error_free(err);
            continue;
        }

        /* Format display based on state */
        const char *symbol = upstream_state_symbol(info->state);
        output_color_t color;
        char status_str[128];

        switch (info->state) {
            case UPSTREAM_UP_TO_DATE:
                color = OUTPUT_COLOR_GREEN;
                snprintf(status_str, sizeof(status_str), "%s up-to-date", symbol);
                up_to_date++;
                break;
            case UPSTREAM_LOCAL_AHEAD:
                color = OUTPUT_COLOR_YELLOW;
                snprintf(status_str, sizeof(status_str), "%s %zu ahead", symbol, info->ahead);
                ahead++;
                break;
            case UPSTREAM_REMOTE_AHEAD:
                color = OUTPUT_COLOR_YELLOW;
                snprintf(status_str, sizeof(status_str), "%s %zu behind", symbol, info->behind);
                behind++;
                break;
            case UPSTREAM_DIVERGED:
                color = OUTPUT_COLOR_RED;
                snprintf(status_str, sizeof(status_str), "%s diverged (%zu ahead, %zu behind)",
                        symbol, info->ahead, info->behind);
                diverged++;
                break;
            case UPSTREAM_NO_REMOTE:
                color = OUTPUT_COLOR_CYAN;
                snprintf(status_str, sizeof(status_str), "%s no remote", symbol);
                no_remote++;
                break;
            case UPSTREAM_UNKNOWN:
            default:
                color = OUTPUT_COLOR_DIM;
                snprintf(status_str, sizeof(status_str), "? unknown");
                break;
        }

        /* Display with colors */
        if (verbose && info->state != UPSTREAM_NO_REMOTE && info->state != UPSTREAM_UNKNOWN) {
            /* Verbose mode: show detailed commit info */
            output_newline(out);
            output_printf(out, OUTPUT_NORMAL, "Profile: %s\n", profile_name);

            /* Get local commit info */
            char local_ref[256];
            snprintf(local_ref, sizeof(local_ref), "refs/heads/%s", profile_name);
            git_commit *local_commit = NULL;
            error_t *commit_err = gitops_get_commit(repo, local_ref, &local_commit);

            if (!commit_err && local_commit) {
                const git_oid *local_oid = git_commit_id(local_commit);
                char local_oid_str[8];
                git_oid_tostr(local_oid_str, sizeof(local_oid_str), local_oid);

                const char *local_summary = git_commit_summary(local_commit);
                git_time_t local_time = git_commit_time(local_commit);

                char time_str[64];
                format_relative_time(local_time, time_str, sizeof(time_str));

                output_printf(out, OUTPUT_NORMAL, "  Status:         ");
                if (output_colors_enabled(out)) {
                    output_printf(out, OUTPUT_NORMAL, "%s%s%s\n",
                                 output_color_code(out, color),
                                 status_str,
                                 output_color_code(out, OUTPUT_COLOR_RESET));
                } else {
                    output_printf(out, OUTPUT_NORMAL, "%s\n", status_str);
                }
                output_printf(out, OUTPUT_NORMAL, "  Local commit:   %s %s (%s)\n",
                             local_oid_str, local_summary, time_str);

                git_commit_free(local_commit);
            }
            error_free(commit_err);

            /* Get remote commit info if it exists */
            if (info->exists_remotely) {
                char remote_ref[256];
                snprintf(remote_ref, sizeof(remote_ref), "refs/remotes/%s/%s",
                        remote_name, profile_name);
                git_commit *remote_commit = NULL;
                commit_err = gitops_get_commit(repo, remote_ref, &remote_commit);

                if (!commit_err && remote_commit) {
                    const git_oid *remote_oid = git_commit_id(remote_commit);
                    char remote_oid_str[8];
                    git_oid_tostr(remote_oid_str, sizeof(remote_oid_str), remote_oid);

                    const char *remote_summary = git_commit_summary(remote_commit);
                    git_time_t remote_time = git_commit_time(remote_commit);

                    char time_str[64];
                    format_relative_time(remote_time, time_str, sizeof(time_str));

                    output_printf(out, OUTPUT_NORMAL, "  Remote commit:  %s %s (%s)\n",
                                 remote_oid_str, remote_summary, time_str);

                    git_commit_free(remote_commit);
                }
                error_free(commit_err);
            }
        } else {
            /* Compact mode: single line matching enabled profiles format */
            char *colored_name = output_colorize(out, OUTPUT_COLOR_CYAN, profile_name);
            if (colored_name) {
                output_printf(out, OUTPUT_NORMAL, "  %s", colored_name);
                free(colored_name);
            } else {
                output_printf(out, OUTPUT_NORMAL, "  %s", profile_name);
            }

            /* Display status in dimmed parentheses */
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s(%s)%s\n",
                             output_color_code(out, OUTPUT_COLOR_DIM),
                             status_str,
                             output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  (%s)\n", status_str);
            }
        }

        upstream_info_free(info);
    }

    output_newline(out);

    /* Display summary section */
    output_section(out, "Sync summary");

    if (up_to_date > 0) {
        char *colored_count = output_colorize(out, OUTPUT_COLOR_CYAN, "%zu");
        if (colored_count) {
            char formatted[64];
            snprintf(formatted, sizeof(formatted), colored_count, up_to_date);
            output_printf(out, OUTPUT_NORMAL, "  %s up-to-date\n", formatted);
            free(colored_count);
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %zu up-to-date\n", up_to_date);
        }
    }
    if (ahead > 0) {
        char *colored_count = output_colorize(out, OUTPUT_COLOR_CYAN, "%zu");
        if (colored_count) {
            char formatted[64];
            snprintf(formatted, sizeof(formatted), colored_count, ahead);
            output_printf(out, OUTPUT_NORMAL, "  %s ahead\n", formatted);
            free(colored_count);
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %zu ahead\n", ahead);
        }
    }
    if (behind > 0) {
        char *colored_count = output_colorize(out, OUTPUT_COLOR_CYAN, "%zu");
        if (colored_count) {
            char formatted[64];
            snprintf(formatted, sizeof(formatted), colored_count, behind);
            output_printf(out, OUTPUT_NORMAL, "  %s behind\n", formatted);
            free(colored_count);
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %zu behind\n", behind);
        }
    }
    if (diverged > 0) {
        char *colored_count = output_colorize(out, OUTPUT_COLOR_CYAN, "%zu");
        if (colored_count) {
            char formatted[64];
            snprintf(formatted, sizeof(formatted), colored_count, diverged);
            output_printf(out, OUTPUT_NORMAL, "  %s diverged\n", formatted);
            free(colored_count);
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %zu diverged\n", diverged);
        }
    }
    if (no_remote > 0) {
        char *colored_count = output_colorize(out, OUTPUT_COLOR_CYAN, "%zu");
        if (colored_count) {
            char formatted[64];
            snprintf(formatted, sizeof(formatted), colored_count, no_remote);
            output_printf(out, OUTPUT_NORMAL, "  %s no remote\n", formatted);
            free(colored_count);
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %zu no remote\n", no_remote);
        }
    }

    /* Free profiles if we allocated them */
    if (should_free_profiles) {
        profile_list_free(profiles_to_check);
    }

    free(remote_name);
    return NULL;
}

/**
 * Extract storage paths from manifest for privilege checking
 *
 * Allocates array of storage path pointers. Caller must free the array
 * (but not the strings, which are borrowed from manifest).
 *
 * @param manifest Manifest (must not be NULL)
 * @param paths_out Output array of paths (must not be NULL)
 * @param count_out Output count (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *extract_storage_paths_from_manifest(
    const manifest_t *manifest,
    const char ***paths_out,
    size_t *count_out
) {
    CHECK_NULL(manifest);
    CHECK_NULL(paths_out);
    CHECK_NULL(count_out);

    if (manifest->count == 0) {
        *paths_out = NULL;
        *count_out = 0;
        return NULL;
    }

    const char **paths = calloc(manifest->count, sizeof(char *));
    if (!paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
    }

    for (size_t i = 0; i < manifest->count; i++) {
        paths[i] = manifest->entries[i].storage_path;
    }

    *paths_out = paths;
    *count_out = manifest->count;
    return NULL;
}

/**
 * Status command implementation
 */
error_t *cmd_status(
    git_repository *repo,
    const cmd_status_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Declare all resources at top and initialize to NULL */
    error_t *err = NULL;
    dotta_config_t *config = NULL;
    profile_list_t *profiles = NULL;
    const manifest_t *manifest = NULL;
    workspace_t *ws = NULL;
    output_ctx_t *out = NULL;

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        error_free(err);
        err = NULL;
        config = config_create_default();
        if (!config) {
            err = ERROR(ERR_MEMORY, "Failed to create default config");
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

    /* Load profiles */
    err = profile_resolve(repo, opts->profiles, opts->profile_count,
                         config->strict_mode, &profiles, NULL);

    if (err) {
        err = error_wrap(err, "Failed to load profiles");
        goto cleanup;
    }

    if (profiles->count == 0) {
        output_info(out, "No profiles found");
        goto cleanup;
    }

    /* Load workspace (includes manifest building and divergence analysis)
     *
     * The workspace builds the manifest internally during initialization,
     * eliminating redundant manifest building. We extract the manifest
     * immediately for use in privilege checking and display functions.
     *
     * This pattern ensures single manifest build per command invocation,
     * matching the optimization in apply.c.
     */
    workspace_load_t ws_opts = {
        .analyze_files = true,
        .analyze_orphans = true,
        .analyze_untracked = (config && config->auto_detect_new_files),
        .analyze_directories = true,
        .analyze_encryption = true
    };
    /* Pass NULL for state - status is read-only, workspace allocates its own state */
    err = workspace_load(repo, NULL, profiles, config, &ws_opts, &ws);
    if (err) {
        err = error_wrap(err, "Failed to load workspace");
        goto cleanup;
    }

    /* Extract manifest from workspace (borrowed reference, owned by workspace) */
    manifest = workspace_get_manifest(ws);
    if (!manifest) {
        err = ERROR(ERR_INTERNAL, "Workspace manifest is NULL");
        goto cleanup;
    }

    /* Extract state from workspace (borrowed reference, owned by workspace) */
    const state_t *state = workspace_get_state(ws);
    if (!state) {
        err = ERROR(ERR_INTERNAL, "Workspace state is NULL");
        goto cleanup;
    }

    /* Check privileges for complete status (may re-exec with sudo) */
    if (!opts->no_sudo && manifest && manifest->count > 0) {
        /* Extract storage paths from manifest */
        const char **storage_paths = NULL;
        size_t path_count = 0;

        error_t *extract_err = extract_storage_paths_from_manifest(
            manifest, &storage_paths, &path_count);

        if (!extract_err && path_count > 0) {
            /* Check if privileges needed (may re-exec) */
            error_t *priv_err = privilege_ensure_for_operation(
                storage_paths,
                path_count,
                "status",
                true,  /* interactive mode (prompt allowed) */
                opts->argc,
                opts->argv,
                out
            );

            free((void *)storage_paths);

            if (priv_err) {
                /* User declined elevation or non-interactive mode */
                output_newline(out);
                output_warning(out, "Status check will be INCOMPLETE:\n");
                output_printf(out, OUTPUT_NORMAL, "  ✓ Content changes will be detected\n");
                output_printf(out, OUTPUT_NORMAL, "  ✓ Permission mode changes will be detected\n");
                output_printf(out, OUTPUT_NORMAL, "  ✗ Ownership changes will NOT be detected\n");
                output_newline(out);

                error_free(priv_err);
                /* Continue with partial status */
            }
        } else {
            /* Extraction failed - non-fatal, continue without privilege check */
            error_free(extract_err);
        }
    }

    /* Display enabled profiles and last deployment info */
    display_enabled_profiles(out, profiles, manifest, state, opts->verbose);

    /* Display workspace status (workspace provides divergence analysis) */
    display_workspace_status(ws, out, opts->verbose);

    /* Display multi-profile files (if verbose mode or if there are any) */
    display_multi_profile_files(repo, profiles, manifest, out);

    /* Show remote sync status (if requested) */
    if (opts->show_remote) {
        err = display_remote_status(repo, profiles, out, opts->all_profiles,
                                    opts->verbose, opts->no_fetch);
        if (err) {
            /* Non-fatal: might not have remote configured */
            error_free(err);
            err = NULL;
        }
    }

cleanup:
    /* Free all resources (safe with NULL pointers) */
    workspace_free(ws);
    profile_list_free(profiles);
    config_free(config);
    output_free(out);

    return err;
}
