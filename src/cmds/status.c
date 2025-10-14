/**
 * status.c - Show status of managed files
 */

#include "status.h"

#include <dirent.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/ignore.h"
#include "core/profiles.h"
#include "core/state.h"
#include "core/upstream.h"
#include "core/workspace.h"
#include "infra/compare.h"
#include "utils/config.h"
#include "utils/output.h"
#include "utils/string.h"
#include "utils/timeutil.h"

/**
 * New file entry
 */
typedef struct {
    char *filesystem_path;
    char *profile;
    char *storage_path;
} new_file_entry_t;

/**
 * New file list
 */
typedef struct {
    new_file_entry_t *entries;
    size_t count;
    size_t capacity;
} new_file_list_t;

/**
 * Create new file list
 */
static new_file_list_t *new_file_list_create(void) {
    new_file_list_t *list = calloc(1, sizeof(new_file_list_t));
    if (!list) {
        return NULL;
    }
    list->capacity = 16;
    list->entries = calloc(list->capacity, sizeof(new_file_entry_t));
    if (!list->entries) {
        free(list);
        return NULL;
    }
    return list;
}

/**
 * Add entry to new file list
 */
static error_t *new_file_list_add(
    new_file_list_t *list,
    const char *filesystem_path,
    const char *profile,
    const char *storage_path
) {
    CHECK_NULL(list);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);

    /* Grow if needed */
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity * 2;
        new_file_entry_t *new_entries = realloc(list->entries,
                                                 new_capacity * sizeof(new_file_entry_t));
        if (!new_entries) {
            return ERROR(ERR_MEMORY, "Failed to grow new file list");
        }
        list->entries = new_entries;
        list->capacity = new_capacity;
    }

    /* Add entry */
    new_file_entry_t *entry = &list->entries[list->count];
    entry->filesystem_path = strdup(filesystem_path);
    entry->profile = strdup(profile);
    entry->storage_path = strdup(storage_path);

    if (!entry->filesystem_path || !entry->profile || !entry->storage_path) {
        free(entry->filesystem_path);
        free(entry->profile);
        free(entry->storage_path);
        return ERROR(ERR_MEMORY, "Failed to allocate new file entry");
    }

    list->count++;
    return NULL;
}

/**
 * Free new file list
 */
static void new_file_list_free(new_file_list_t *list) {
    if (!list) {
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        free(list->entries[i].filesystem_path);
        free(list->entries[i].profile);
        free(list->entries[i].storage_path);
    }
    free(list->entries);
    free(list);
}

/**
 * Check if file is in manifest
 */
static bool is_file_in_manifest(const manifest_t *manifest, const char *filesystem_path) {
    if (!manifest || !filesystem_path) {
        return false;
    }

    for (size_t i = 0; i < manifest->count; i++) {
        if (strcmp(manifest->entries[i].filesystem_path, filesystem_path) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Recursively scan directory for new files
 */
static error_t *scan_directory_for_new_files(
    const char *dir_path,
    const char *storage_prefix,
    const char *profile,
    const manifest_t *manifest,
    ignore_context_t *ignore_ctx,
    new_file_list_t *new_files
) {
    CHECK_NULL(dir_path);
    CHECK_NULL(storage_prefix);
    CHECK_NULL(profile);
    CHECK_NULL(manifest);
    CHECK_NULL(new_files);

    DIR *dir = opendir(dir_path);
    if (!dir) {
        /* Non-fatal: directory might have been deleted or permissions issue */
        return NULL;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Build full path */
        char *full_path = str_format("%s/%s", dir_path, entry->d_name);
        if (!full_path) {
            closedir(dir);
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }

        /* Check if path exists (handle race conditions) */
        if (!fs_lexists(full_path)) {
            free(full_path);
            continue;
        }

        /* Check if ignored */
        bool is_dir = fs_is_directory(full_path);
        if (ignore_ctx) {
            bool ignored = false;
            error_t *err = ignore_should_ignore(ignore_ctx, full_path, is_dir, &ignored);
            if (!err && ignored) {
                free(full_path);
                continue;
            }
            error_free(err);  /* Ignore errors in ignore checking */
        }

        if (is_dir) {
            /* Recurse into subdirectory */
            char *sub_storage_prefix = str_format("%s/%s", storage_prefix, entry->d_name);
            if (!sub_storage_prefix) {
                free(full_path);
                closedir(dir);
                return ERROR(ERR_MEMORY, "Failed to allocate storage prefix");
            }

            error_t *err = scan_directory_for_new_files(
                full_path,
                sub_storage_prefix,
                profile,
                manifest,
                ignore_ctx,
                new_files
            );

            free(sub_storage_prefix);
            free(full_path);

            if (err) {
                closedir(dir);
                return err;
            }
        } else {
            /* Check if this file is already tracked */
            if (!is_file_in_manifest(manifest, full_path)) {
                /* This is a new file! */
                char *storage_path = str_format("%s/%s", storage_prefix, entry->d_name);
                if (!storage_path) {
                    free(full_path);
                    closedir(dir);
                    return ERROR(ERR_MEMORY, "Failed to allocate storage path");
                }

                error_t *err = new_file_list_add(new_files, full_path, profile, storage_path);
                free(storage_path);
                free(full_path);

                if (err) {
                    closedir(dir);
                    return err;
                }
            } else {
                free(full_path);
            }
        }
    }

    closedir(dir);
    return NULL;
}

/**
 * Display status summary with counts
 */
static void display_status_summary(
    output_ctx_t *out,
    size_t total_files,
    size_t up_to_date,
    size_t not_deployed,
    size_t modified,
    size_t new_file_count
) {
    if (!out) {
        return;
    }

    output_section(out, "Summary");

    char summary_text[256];
    snprintf(summary_text, sizeof(summary_text), "%zu file%s in profiles",
            total_files, total_files == 1 ? "" : "s");
    output_info(out, "%s", summary_text);

    if (output_colors_enabled(out)) {
        snprintf(summary_text, sizeof(summary_text), "  %s%zu%s up to date",
                output_color_code(out, OUTPUT_COLOR_GREEN), up_to_date,
                output_color_code(out, OUTPUT_COLOR_RESET));
        output_printf(out, OUTPUT_NORMAL, "%s\n", summary_text);
    } else {
        output_info(out, "  %zu up to date", up_to_date);
    }

    if (not_deployed > 0) {
        if (output_colors_enabled(out)) {
            snprintf(summary_text, sizeof(summary_text),
                    "  %s%zu%s not deployed (run '%sdotta apply%s')",
                    output_color_code(out, OUTPUT_COLOR_RED), not_deployed,
                    output_color_code(out, OUTPUT_COLOR_RESET),
                    output_color_code(out, OUTPUT_COLOR_CYAN),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "%s\n", summary_text);
        } else {
            output_info(out, "  %zu not deployed (run 'dotta apply')", not_deployed);
        }
    }

    if (modified > 0) {
        if (output_colors_enabled(out)) {
            snprintf(summary_text, sizeof(summary_text),
                    "  %s%zu%s modified locally (use %s--force%s to overwrite)",
                    output_color_code(out, OUTPUT_COLOR_YELLOW), modified,
                    output_color_code(out, OUTPUT_COLOR_RESET),
                    output_color_code(out, OUTPUT_COLOR_CYAN),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "%s\n", summary_text);
        } else {
            output_info(out, "  %zu modified locally (use --force to overwrite)", modified);
        }
    }

    if (new_file_count > 0) {
        if (output_colors_enabled(out)) {
            snprintf(summary_text, sizeof(summary_text),
                    "  %s%zu%s new file%s detected (run '%sdotta update --include-new%s' to add)",
                    output_color_code(out, OUTPUT_COLOR_CYAN), new_file_count,
                    output_color_code(out, OUTPUT_COLOR_RESET),
                    new_file_count == 1 ? "" : "s",
                    output_color_code(out, OUTPUT_COLOR_CYAN),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "%s\n", summary_text);
        } else {
            output_info(out, "  %zu new file%s detected (run 'dotta update --include-new' to add)",
                       new_file_count, new_file_count == 1 ? "" : "s");
        }
    }
}

/**
 * Scan tracked directories for new files
 */
static error_t *scan_for_new_files_in_dirs(
    git_repository *repo,
    const state_t *state,
    const manifest_t *manifest,
    const dotta_config_t *config,
    output_ctx_t *out,
    const cmd_status_options_t *opts,
    new_file_list_t **new_files_out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(manifest);
    CHECK_NULL(config);
    CHECK_NULL(out);
    CHECK_NULL(opts);
    CHECK_NULL(new_files_out);

    error_t *err = NULL;
    new_file_list_t *new_files = new_file_list_create();
    if (!new_files) {
        return ERROR(ERR_MEMORY, "Failed to create new file list");
    }

    /* Get tracked directories from state */
    size_t dir_count = 0;
    const state_directory_entry_t *directories = state_get_all_directories(state, &dir_count);

    if (directories && dir_count > 0) {
        for (size_t i = 0; i < dir_count; i++) {
            const state_directory_entry_t *dir_entry = &directories[i];

            /* Check if directory still exists */
            if (!fs_exists(dir_entry->filesystem_path)) {
                continue;
            }

            /* Create profile-specific ignore context for this directory */
            ignore_context_t *ignore_ctx = NULL;
            err = ignore_context_create(repo, config, dir_entry->profile, NULL, 0, &ignore_ctx);
            if (err) {
                /* Non-fatal: continue without ignore filtering */
                error_free(err);
                err = NULL;
            }

            /* Scan this directory for new files */
            err = scan_directory_for_new_files(
                dir_entry->filesystem_path,
                dir_entry->storage_prefix,
                dir_entry->profile,
                manifest,
                ignore_ctx,
                new_files
            );

            /* Free ignore context */
            ignore_context_free(ignore_ctx);

            if (err) {
                /* Log warning but continue with other directories */
                if (opts->verbose) {
                    fprintf(stderr, "Warning: failed to scan directory '%s': %s\n",
                           dir_entry->filesystem_path, error_message(err));
                }
                error_free(err);
                err = NULL;
            }
        }
    }

    *new_files_out = new_files;
    return NULL;
}

/**
 * Check status of files in manifest
 */
static error_t *check_files_status(
    git_repository *repo,
    const manifest_t *manifest,
    output_ctx_t *out,
    const cmd_status_options_t *opts,
    size_t *up_to_date_count,
    size_t *modified_count,
    size_t *not_deployed_count
) {
    CHECK_NULL(repo);
    CHECK_NULL(manifest);
    CHECK_NULL(out);
    CHECK_NULL(opts);
    CHECK_NULL(up_to_date_count);
    CHECK_NULL(modified_count);
    CHECK_NULL(not_deployed_count);

    *up_to_date_count = 0;
    *modified_count = 0;
    *not_deployed_count = 0;

    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];

        /* Compare with disk */
        compare_result_t cmp_result;
        error_t *err = compare_tree_entry_to_disk(
            repo,
            entry->entry,
            entry->filesystem_path,
            &cmp_result
        );

        if (err) {
            return error_wrap(err, "Failed to compare '%s'", entry->filesystem_path);
        }

        /* Categorize status and display */
        char info_text[1024];
        if (cmp_result == CMP_MISSING) {
            (*not_deployed_count)++;
            snprintf(info_text, sizeof(info_text), "%s (from %s)",
                    entry->filesystem_path, entry->source_profile->name);
            output_item(out, "[not-deployed]", OUTPUT_COLOR_RED, info_text);
        } else if (cmp_result == CMP_EQUAL) {
            (*up_to_date_count)++;
            if (opts->verbose) {
                output_item(out, "[ok]", OUTPUT_COLOR_GREEN, entry->filesystem_path);
            }
        } else if (cmp_result == CMP_DIFFERENT || cmp_result == CMP_MODE_DIFF) {
            (*modified_count)++;
            snprintf(info_text, sizeof(info_text), "%s (from %s)",
                    entry->filesystem_path, entry->source_profile->name);
            output_item(out, "[modified]", OUTPUT_COLOR_YELLOW, info_text);
        } else if (cmp_result == CMP_TYPE_DIFF) {
            (*modified_count)++;
            snprintf(info_text, sizeof(info_text), "%s (type mismatch)",
                    entry->filesystem_path);
            output_item(out, "[type]", OUTPUT_COLOR_RED, info_text);
        }
    }

    return NULL;
}

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

    /* Show last deployment time if available */
    if (state) {
        time_t last_deploy = state_get_timestamp(state);
        if (last_deploy > 0) {
            char time_buf[64];
            struct tm *tm_info = localtime(&last_deploy);
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
            output_info(out, "  Last deployed: %s", time_buf);
        }
    }
    output_newline(out);
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
    output_ctx_t *out,
    bool verbose
) {
    if (!repo || !profiles || !out) {
        return;
    }

    /* Load workspace */
    workspace_t *ws = NULL;
    error_t *err = workspace_load(repo, profiles, &ws);
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

    /* Only display section if there's something to report */
    if (ws_status != WORKSPACE_CLEAN || verbose) {
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
                            snprintf(info, sizeof(info), "%s (from %s)",
                                    file->filesystem_path, file->profile);
                            break;
                        case DIVERGENCE_MODIFIED:
                            label = "[modified]";
                            color = OUTPUT_COLOR_YELLOW;
                            snprintf(info, sizeof(info), "%s", file->filesystem_path);
                            break;
                        case DIVERGENCE_DELETED:
                            label = "[deleted]";
                            color = OUTPUT_COLOR_RED;
                            snprintf(info, sizeof(info), "%s", file->filesystem_path);
                            break;
                        case DIVERGENCE_ORPHANED:
                            label = "[orphaned]";
                            color = OUTPUT_COLOR_RED;
                            snprintf(info, sizeof(info), "%s (from %s)",
                                    file->filesystem_path, file->profile);
                            break;
                        case DIVERGENCE_MODE_DIFF:
                            label = "[mode]";
                            color = OUTPUT_COLOR_YELLOW;
                            snprintf(info, sizeof(info), "%s", file->filesystem_path);
                            break;
                        case DIVERGENCE_TYPE_DIFF:
                            label = "[type]";
                            color = OUTPUT_COLOR_RED;
                            snprintf(info, sizeof(info), "%s", file->filesystem_path);
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
                output_info(out, "Hint: Run 'dotta apply' to deploy undeployed files");
            }
            if (orphaned > 0) {
                output_info(out, "Hint: Orphaned state entries indicate removed profile files");
            }
        }

        output_newline(out);
    }

    workspace_free(ws);
}

/**
 * Display remote sync status for profiles
 *
 * Note: This function loads ALL local profiles, not just auto-detected ones,
 * to show complete remote sync state across all branches.
 */
static error_t *display_remote_status(
    git_repository *repo,
    output_ctx_t *out,
    bool verbose,
    bool no_fetch
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    /* Detect remote */
    char *remote_name = NULL;
    error_t *err = upstream_detect_remote(repo, &remote_name);
    if (err) {
        /* No remote configured - not an error, just skip this section */
        error_free(err);
        return NULL;
    }

    /* Load ALL local profiles (not just auto-detected) for remote status */
    profile_list_t *all_profiles = NULL;
    err = profile_list_all_local(repo, &all_profiles);
    if (err) {
        free(remote_name);
        return error_wrap(err, "Failed to load profiles");
    }

    if (all_profiles->count == 0) {
        profile_list_free(all_profiles);
        free(remote_name);
        return NULL;
    }

    /* Fetch if requested */
    if (!no_fetch) {
        if (verbose) {
            output_info(out, "Fetching from '%s'...", remote_name);
        }

        /* Fetch each profile branch */
        for (size_t i = 0; i < all_profiles->count; i++) {
            const char *branch_name = all_profiles->profiles[i].name;
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
    char section_title[256];
    snprintf(section_title, sizeof(section_title), "Remote sync status (%s)", remote_name);
    output_section(out, section_title);

    /* Analyze and display each profile's sync state */
    size_t up_to_date = 0;
    size_t ahead = 0;
    size_t behind = 0;
    size_t diverged = 0;
    size_t no_remote = 0;

    for (size_t i = 0; i < all_profiles->count; i++) {
        const char *profile_name = all_profiles->profiles[i].name;

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

    profile_list_free(all_profiles);
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
    new_file_list_t *new_files = NULL;
    size_t up_to_date = 0;
    size_t modified = 0;
    size_t not_deployed = 0;

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
                         config, config->strict_mode, &profiles, NULL);

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
    output_newline(out);
    display_workspace_status(repo, profiles, out, opts->verbose);

    /* Show filesystem status (if requested) */
    if (opts->show_local) {
        /* Add section header */
        output_newline(out);
        if (opts->verbose) {
            output_section(out, "Filesystem status");
        }

        /* Check status of all files in manifest */
        err = check_files_status(repo, manifest, out, opts,
                                &up_to_date, &modified, &not_deployed);
        if (err) {
            goto cleanup;
        }

        /* Scan tracked directories for new files */
        err = scan_for_new_files_in_dirs(repo, state, manifest, config, out, opts, &new_files);
        if (err) {
            goto cleanup;
        }

        /* Display new files */
        size_t new_file_count = 0;
        if (new_files && new_files->count > 0) {
            new_file_count = new_files->count;
            for (size_t i = 0; i < new_files->count; i++) {
                const new_file_entry_t *entry = &new_files->entries[i];
                char info_text[1024];
                snprintf(info_text, sizeof(info_text), "%s (in %s)",
                        entry->filesystem_path, entry->profile);
                output_item(out, "[new]", OUTPUT_COLOR_CYAN, info_text);
            }
        }

        /* Display summary */
        display_status_summary(out, manifest->count, up_to_date,
                              not_deployed, modified, new_file_count);
    }

    /* Show remote sync status (if requested) */
    if (opts->show_remote) {
        output_newline(out);
        err = display_remote_status(repo, out, opts->verbose, opts->no_fetch);
        if (err) {
            /* Non-fatal: might not have remote configured */
            error_free(err);
            err = NULL;
        }
    }

    /* Display contextual hints based on detected conditions */
    bool has_hints = false;
    if (not_deployed > 0 || modified > 0 || new_files) {
        if (!has_hints) {
            has_hints = true;
        }

        if (not_deployed > 0) {
            char *hint = output_colorize(out, OUTPUT_COLOR_DIM,
                    "Hint: Run 'dotta apply' to deploy files to filesystem");
            if (hint) {
                output_printf(out, OUTPUT_NORMAL, "%s\n", hint);
                free(hint);
            } else {
                output_info(out, "Hint: Run 'dotta apply' to deploy files to filesystem");
            }
        }

        if (modified > 0) {
            char *hint = output_colorize(out, OUTPUT_COLOR_DIM,
                    "Hint: Use 'dotta apply --force' to overwrite locally modified files");
            if (hint) {
                output_printf(out, OUTPUT_NORMAL, "%s\n", hint);
                free(hint);
            } else {
                output_info(out, "Hint: Use 'dotta apply --force' to overwrite locally modified files");
            }
        }

        if (new_files && new_files->count > 0) {
            char *hint = output_colorize(out, OUTPUT_COLOR_DIM,
                    "Hint: Run 'dotta update --include-new' to add new files to profile");
            if (hint) {
                output_printf(out, OUTPUT_NORMAL, "%s\n", hint);
                free(hint);
            } else {
                output_info(out, "Hint: Run 'dotta update --include-new' to add new files to profile");
            }
        }
    }

    /* Add trailing newline for UX consistency */
    if (out) {
        output_newline(out);
    }

cleanup:
    /* Free all resources (safe with NULL pointers) */
    new_file_list_free(new_files);
    manifest_free(manifest);
    profile_list_free(profiles);
    state_free(state);
    config_free(config);
    output_free(out);

    return err;
}
