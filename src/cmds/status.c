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

        /* Format profile name with marker */
        char *colored_name = output_colorize(out, OUTPUT_COLOR_CYAN, profile->name);
        char *auto_text = profile->auto_detected ? " (auto-detected)" : "";

        if (colored_name) {
            output_printf(out, OUTPUT_NORMAL, "  %s %s%s",
                         profile->auto_detected ? "*" : " ", colored_name, auto_text);
            free(colored_name);
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %s %s%s",
                         profile->auto_detected ? "*" : " ", profile->name, auto_text);
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
            output_printf(out, OUTPUT_NORMAL, "\n      %zu file%s",
                         profile_file_count, profile_file_count == 1 ? "" : "s");
        }

        output_newline(out);
    }
}

/**
 * Display workspace status
 *
 * Shows the consistency between profile state, deployment state, and filesystem.
 * Displays counts and details for undeployed, modified, deleted, and orphaned files.
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

    /* Count divergence types */
    size_t undeployed = workspace_count_divergence(ws, DIVERGENCE_UNDEPLOYED);
    size_t modified = workspace_count_divergence(ws, DIVERGENCE_MODIFIED);
    size_t deleted = workspace_count_divergence(ws, DIVERGENCE_DELETED);
    size_t orphaned = workspace_count_divergence(ws, DIVERGENCE_ORPHANED);
    size_t mode_diff = workspace_count_divergence(ws, DIVERGENCE_MODE_DIFF);
    size_t type_diff = workspace_count_divergence(ws, DIVERGENCE_TYPE_DIFF);
    size_t untracked = workspace_count_divergence(ws, DIVERGENCE_UNTRACKED);

    /* Only display section if there's something to report */
    if (ws_status != WORKSPACE_CLEAN || verbose) {
        output_newline(out);
        output_section(out, "Workspace status");

        /* Display overall status with color */
        switch (ws_status) {
            case WORKSPACE_CLEAN:
                output_success(out, "Clean - all states aligned");
                break;

            case WORKSPACE_DIRTY:
                output_warning(out, "Dirty - has divergence");
                if (undeployed > 0) {
                    output_info(out, "  %zu undeployed file%s (in profile, never deployed)",
                               undeployed, undeployed == 1 ? "" : "s");
                }
                if (modified > 0) {
                    output_info(out, "  %zu modified file%s (deployed, changed on disk)",
                               modified, modified == 1 ? "" : "s");
                }
                if (deleted > 0) {
                    output_info(out, "  %zu deleted file%s (deployed, removed from disk)",
                               deleted, deleted == 1 ? "" : "s");
                }
                if (untracked > 0) {
                    output_info(out, "  %zu untracked file%s (new in tracked directories)",
                               untracked, untracked == 1 ? "" : "s");
                }
                if (mode_diff > 0) {
                    output_info(out, "  %zu file%s with mode differences",
                               mode_diff, mode_diff == 1 ? "" : "s");
                }
                if (type_diff > 0) {
                    output_info(out, "  %zu file%s with type differences",
                               type_diff, type_diff == 1 ? "" : "s");
                }
                break;

            case WORKSPACE_INVALID:
                output_error(out, "Invalid - has orphaned state entries");
                if (orphaned > 0) {
                    output_info(out, "  %zu orphaned state entr%s (state without profile file)",
                               orphaned, orphaned == 1 ? "y" : "ies");
                }
                break;
        }

        /* In verbose mode, show affected files */
        if (verbose && ws_status != WORKSPACE_CLEAN) {
            output_newline(out);
            output_info(out, "Affected files:");

            size_t count = 0;
            const workspace_file_t *diverged = workspace_get_all_diverged(ws, &count);
            if (diverged) {
                for (size_t i = 0; i < count; i++) {
                    const workspace_file_t *file = &diverged[i];
                    char info[1024];
                    const char *label = NULL;
                    output_color_t color = OUTPUT_COLOR_YELLOW;

                    switch (file->type) {
                        case DIVERGENCE_UNDEPLOYED:
                            label = "[undeployed]";
                            color = OUTPUT_COLOR_CYAN;
                            snprintf(info, sizeof(info), "%s %s(from %s)%s",
                                    file->filesystem_path,
                                    output_color_code(out, OUTPUT_COLOR_DIM),
                                    file->profile,
                                    output_color_code(out, OUTPUT_COLOR_RESET));
                            break;
                        case DIVERGENCE_MODIFIED:
                            label = "[modified]";
                            color = OUTPUT_COLOR_YELLOW;
                            snprintf(info, sizeof(info), "%s %s(from %s)%s",
                                    file->filesystem_path,
                                    output_color_code(out, OUTPUT_COLOR_DIM),
                                    file->profile,
                                    output_color_code(out, OUTPUT_COLOR_RESET));
                            break;
                        case DIVERGENCE_DELETED:
                            label = "[deleted]";
                            color = OUTPUT_COLOR_RED;
                            snprintf(info, sizeof(info), "%s %s(from %s)%s",
                                    file->filesystem_path,
                                    output_color_code(out, OUTPUT_COLOR_DIM),
                                    file->profile,
                                    output_color_code(out, OUTPUT_COLOR_RESET));
                            break;
                        case DIVERGENCE_UNTRACKED:
                            label = "[new]";
                            color = OUTPUT_COLOR_CYAN;
                            snprintf(info, sizeof(info), "%s %s(in %s)%s",
                                    file->filesystem_path,
                                    output_color_code(out, OUTPUT_COLOR_DIM),
                                    file->profile,
                                    output_color_code(out, OUTPUT_COLOR_RESET));
                            break;
                        case DIVERGENCE_ORPHANED:
                            label = "[orphaned]";
                            color = OUTPUT_COLOR_RED;
                            snprintf(info, sizeof(info), "%s %s(from %s)%s",
                                    file->filesystem_path,
                                    output_color_code(out, OUTPUT_COLOR_DIM),
                                    file->profile,
                                    output_color_code(out, OUTPUT_COLOR_RESET));
                            break;
                        case DIVERGENCE_MODE_DIFF:
                            label = "[mode]";
                            color = OUTPUT_COLOR_YELLOW;
                            snprintf(info, sizeof(info), "%s %s(from %s)%s",
                                    file->filesystem_path,
                                    output_color_code(out, OUTPUT_COLOR_DIM),
                                    file->profile,
                                    output_color_code(out, OUTPUT_COLOR_RESET));
                            break;
                        case DIVERGENCE_TYPE_DIFF:
                            label = "[type]";
                            color = OUTPUT_COLOR_RED;
                            snprintf(info, sizeof(info), "%s %s(from %s)%s",
                                    file->filesystem_path,
                                    output_color_code(out, OUTPUT_COLOR_DIM),
                                    file->profile,
                                    output_color_code(out, OUTPUT_COLOR_RESET));
                            break;
                        default:
                            continue;
                    }

                    output_item(out, label, color, info);
                }
            }
        }

        /* Show hints based on what's detected */
        if (ws_status != WORKSPACE_CLEAN) {
            output_newline(out);

            if (undeployed > 0) {
                char *hint = output_colorize(out, OUTPUT_COLOR_DIM,
                        "Hint: Run 'dotta apply' to deploy undeployed files");
                if (hint) {
                    output_printf(out, OUTPUT_NORMAL, "%s\n", hint);
                    free(hint);
                } else {
                    output_info(out, "Hint: Run 'dotta apply' to deploy undeployed files");
                }
            }

            if (modified > 0 || deleted > 0) {
                char *hint = output_colorize(out, OUTPUT_COLOR_DIM,
                        "Hint: Run 'dotta update' to commit local changes");
                if (hint) {
                    output_printf(out, OUTPUT_NORMAL, "%s\n", hint);
                    free(hint);
                } else {
                    output_info(out, "Hint: Run 'dotta update' to commit local changes");
                }
            }

            if (untracked > 0) {
                char *hint = output_colorize(out, OUTPUT_COLOR_DIM,
                        "Hint: Run 'dotta update --include-new' to add new files to profile");
                if (hint) {
                    output_printf(out, OUTPUT_NORMAL, "%s\n", hint);
                    free(hint);
                } else {
                    output_info(out, "Hint: Run 'dotta update --include-new' to add new files to profile");
                }
            }

            if (orphaned > 0) {
                char *hint = output_colorize(out, OUTPUT_COLOR_DIM,
                        "Hint: Orphaned state entries indicate removed profile files");
                if (hint) {
                    output_printf(out, OUTPUT_NORMAL, "%s\n", hint);
                    free(hint);
                } else {
                    output_info(out, "Hint: Orphaned state entries indicate removed profile files");
                }
            }
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
        output_newline(out);
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
            /* Compact mode: single line */
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s%-12s%s  %s%s%s\n",
                             output_color_code(out, OUTPUT_COLOR_CYAN),
                             profile_name,
                             output_color_code(out, OUTPUT_COLOR_RESET),
                             output_color_code(out, color),
                             status_str,
                             output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  %-12s  %s\n", profile_name, status_str);
            }
        }

        upstream_info_free(info);
    }

    output_newline(out);

    /* Display summary */
    output_section(out, "Sync summary");
    if (up_to_date > 0) {
        output_info(out, "%zu up-to-date", up_to_date);
    }
    if (ahead > 0) {
        output_info(out, "%zu ahead (ready to push)", ahead);
    }
    if (behind > 0) {
        output_info(out, "%zu behind (run 'dotta sync' to pull)", behind);
    }
    if (diverged > 0) {
        output_warning(out, "%zu diverged (needs resolution)", diverged);
        output_info(out, "  Hint: Run 'dotta sync --diverged=rebase' or 'dotta sync --diverged=merge' to resolve");
    }
    if (no_remote > 0) {
        output_info(out, "%zu without remote branch", no_remote);
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
