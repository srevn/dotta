/**
 * status.c - Show status of managed files
 */

#include "status.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
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
#include "utils/timeutil.h"

/**
 * Display active profiles and last deployment info
 */
static void display_active_profiles(
    output_ctx_t *out,
    const profile_list_t *profiles,
    const manifest_t *manifest,
    const state_t *state,
    bool verbose
) {
    if (!out || !profiles) {
        return;
    }

    /* Show active profiles */
    output_section(out, "Active profiles");

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
 * Format a diverged file entry for display
 *
 * Returns the label, color, and formatted info string for a file.
 */
static void format_diverged_file(
    output_ctx_t *out,
    const workspace_file_t *file,
    const char **out_label,
    output_color_t *out_color,
    char *info_buffer,
    size_t buffer_size
) {
    if (!out || !file || !out_label || !out_color || !info_buffer) {
        return;
    }

    switch (file->type) {
        case DIVERGENCE_UNDEPLOYED:
            *out_label = "[undeployed]";
            *out_color = OUTPUT_COLOR_CYAN;
            snprintf(info_buffer, buffer_size, "%s %s(from %s)%s",
                    file->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    file->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;

        case DIVERGENCE_MODIFIED:
            *out_label = "[modified]";
            *out_color = OUTPUT_COLOR_YELLOW;
            snprintf(info_buffer, buffer_size, "%s %s(from %s)%s",
                    file->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    file->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;

        case DIVERGENCE_DELETED:
            *out_label = "[deleted]";
            *out_color = OUTPUT_COLOR_RED;
            snprintf(info_buffer, buffer_size, "%s %s(from %s)%s",
                    file->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    file->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;

        case DIVERGENCE_UNTRACKED:
            *out_label = "[new]";
            *out_color = OUTPUT_COLOR_CYAN;
            snprintf(info_buffer, buffer_size, "%s %s(in %s)%s",
                    file->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    file->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;

        case DIVERGENCE_ORPHANED:
            *out_label = "[orphaned]";
            *out_color = OUTPUT_COLOR_RED;
            snprintf(info_buffer, buffer_size, "%s %s(from %s)%s",
                    file->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    file->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;

        case DIVERGENCE_MODE_DIFF:
            *out_label = "[mode]";
            *out_color = OUTPUT_COLOR_YELLOW;
            snprintf(info_buffer, buffer_size, "%s %s(from %s)%s",
                    file->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    file->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;

        case DIVERGENCE_TYPE_DIFF:
            *out_label = "[type]";
            *out_color = OUTPUT_COLOR_RED;
            snprintf(info_buffer, buffer_size, "%s %s(from %s)%s",
                    file->filesystem_path,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    file->profile,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            break;

        default:
            *out_label = "[unknown]";
            *out_color = OUTPUT_COLOR_DIM;
            snprintf(info_buffer, buffer_size, "%s", file->filesystem_path);
            break;
    }
}

/**
 * Display a divergence section with files of specific types
 *
 * Shows section header, hint, and individual files.
 * Only displays if count > 0.
 */
static void display_divergence_section(
    output_ctx_t *out,
    const workspace_t *ws,
    const char *section_title,
    const char *hint_message,
    const divergence_type_t *types,
    size_t type_count
) {
    if (!out || !ws || !section_title || !types) {
        return;
    }

    /* Count total files for these types */
    size_t total_count = 0;
    for (size_t t = 0; t < type_count; t++) {
        total_count += workspace_count_divergence(ws, types[t]);
    }

    /* Skip section if no files */
    if (total_count == 0) {
        return;
    }

    /* Display section header with count and inline hint */
    output_newline(out);
    char header[256];
    snprintf(header, sizeof(header), "%s (%zu file%s)",
             section_title, total_count, total_count == 1 ? "" : "s");

    /* Print header in bold, then hint in dim on same line */
    if (output_colors_enabled(out)) {
        const char *bold = output_color_code(out, OUTPUT_COLOR_BOLD);
        const char *dim = output_color_code(out, OUTPUT_COLOR_DIM);
        const char *reset = output_color_code(out, OUTPUT_COLOR_RESET);

        if (hint_message) {
            output_printf(out, OUTPUT_NORMAL, "%s%s%s %s%s%s\n",
                         bold, header, reset, dim, hint_message, reset);
        } else {
            output_printf(out, OUTPUT_NORMAL, "%s%s%s\n", bold, header, reset);
        }
    } else {
        if (hint_message) {
            output_printf(out, OUTPUT_NORMAL, "%s %s\n", header, hint_message);
        } else {
            output_printf(out, OUTPUT_NORMAL, "%s\n", header);
        }
    }

    /* Display individual files */
    output_newline(out);

    for (size_t t = 0; t < type_count; t++) {
        size_t count = 0;
        const workspace_file_t **files = workspace_get_diverged(ws, types[t], &count);

        if (files) {
            for (size_t i = 0; i < count; i++) {
                const workspace_file_t *file = files[i];
                char info[1024];
                const char *label = NULL;
                output_color_t color = OUTPUT_COLOR_YELLOW;

                format_diverged_file(out, file, &label, &color, info, sizeof(info));
                output_item(out, label, color, info);
            }

            /* Free the allocated pointer array */
            free(files);
        }
    }
}

/**
 * Display workspace status
 *
 * Shows the consistency between profile state, deployment state, and filesystem.
 * Organized into actionable sections (Git-like structure).
 */
static void display_workspace_status(
    git_repository *repo,
    profile_list_t *profiles,
    const dotta_config_t *config,
    output_ctx_t *out,
    bool verbose
) {
    if (!repo || !profiles || !out) {
        return;
    }

    /* Load workspace */
    workspace_t *ws = NULL;
    error_t *err = workspace_load(repo, profiles, config, &ws);
    if (err) {
        /* Non-fatal: if workspace fails to load, skip this section */
        if (verbose) {
            output_warning(out, "Failed to load workspace: %s", error_message(err));
        }
        error_free(err);
        return;
    }

    /* Get workspace status */
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
            /* Section 1: Uncommitted Changes (what 'update' would commit) */
            divergence_type_t uncommitted_types[] = {
                DIVERGENCE_MODIFIED,
                DIVERGENCE_DELETED,
                DIVERGENCE_MODE_DIFF,
                DIVERGENCE_TYPE_DIFF
            };
            display_divergence_section(
                out, ws,
                "Uncommitted changes",
                "(use \"dotta update\" to commit these changes)",
                uncommitted_types,
                sizeof(uncommitted_types) / sizeof(uncommitted_types[0])
            );

            /* Section 2: Undeployed Files (what 'apply' would deploy) */
            divergence_type_t undeployed_types[] = {
                DIVERGENCE_UNDEPLOYED
            };
            display_divergence_section(
                out, ws,
                "Undeployed files",
                "(use \"dotta apply\" to deploy these files)",
                undeployed_types,
                sizeof(undeployed_types) / sizeof(undeployed_types[0])
            );

            /* Section 3: New Files (in tracked directories) */
            divergence_type_t new_file_types[] = {
                DIVERGENCE_UNTRACKED
            };
            display_divergence_section(
                out, ws,
                "New files",
                "(use \"dotta update --include-new\" to track these files)",
                new_file_types,
                sizeof(new_file_types) / sizeof(new_file_types[0])
            );

            /* Section 4: Issues (orphaned state) */
            divergence_type_t issue_types[] = {
                DIVERGENCE_ORPHANED
            };
            display_divergence_section(
                out, ws,
                "Issues",
                "(run \"dotta apply\" to remove orphaned files)",
                issue_types,
                sizeof(issue_types) / sizeof(issue_types[0])
            );
            
            output_newline(out);
        }
    }

    workspace_free(ws);
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
 * By default shows only active profiles for consistency with workspace status.
 * Use show_all_profiles to report on every branch in the repository.
 */
static error_t *display_remote_status(
    git_repository *repo,
    const profile_list_t *active_profiles,
    output_ctx_t *out,
    bool show_all_profiles,
    bool verbose,
    bool no_fetch
) {
    CHECK_NULL(repo);
    CHECK_NULL(active_profiles);
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
        /* Default: show only active profiles (consistent with workspace status) */
        profiles_to_check = (profile_list_t*)active_profiles;  /* Borrowed reference */
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

        /* Fetch each profile branch */
        for (size_t i = 0; i < profiles_to_check->count; i++) {
            const char *branch_name = profiles_to_check->profiles[i].name;
            error_t *fetch_err = gitops_fetch_branch(repo, remote_name, branch_name, NULL);
            if (fetch_err) {
                /* Non-fatal: just warn */
                if (verbose) {
                    output_warning(out, "Failed to fetch '%s': %s",
                                  branch_name, error_message(fetch_err));
                }
                error_free(fetch_err);
            }
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
            /* Compact mode: single line matching active profiles format */
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
 * Status command implementation
 */
error_t *cmd_status(git_repository *repo, const cmd_status_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Declare all resources at top and initialize to NULL */
    error_t *err = NULL;
    dotta_config_t *config = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *manifest = NULL;
    state_t *state = NULL;
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

    /* Load state */
    err = state_load(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to load state");
        goto cleanup;
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

    /* Build manifest (needed for both profile display and filesystem status) */
    err = profile_build_manifest(repo, profiles, &manifest);
    if (err) {
        err = error_wrap(err, "Failed to build manifest");
        goto cleanup;
    }

    /* Display active profiles and last deployment info */
    display_active_profiles(out, profiles, manifest, state, opts->verbose);

    /* Display workspace status */
    display_workspace_status(repo, profiles, config, out, opts->verbose);

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
    manifest_free(manifest);
    profile_list_free(profiles);
    state_free(state);
    config_free(config);
    output_free(out);

    return err;
}
