/**
 * cleanup.c - Orphaned file and empty directory cleanup implementation
 *
 * Implements coordinated cleanup of orphaned files and empty directories
 * with safety validation and optimized metadata loading.
 */

#include "cleanup.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/safety.h"
#include "core/state.h"
#include "utils/array.h"
#include "utils/hashmap.h"
#include "utils/output.h"

/**
 * Directory pruning state
 *
 * Tracks the state of each directory during iterative pruning to avoid
 * redundant filesystem checks. This optimization significantly reduces
 * system call overhead for deep directory hierarchies.
 */
typedef enum {
    DIR_STATE_UNKNOWN = 0,    /* Not yet checked this iteration */
    DIR_STATE_REMOVED,        /* Successfully removed in a previous iteration */
    DIR_STATE_NOT_EMPTY,      /* Contains files or subdirectories, won't be removed */
    DIR_STATE_NONEXISTENT,    /* Doesn't exist on filesystem */
    DIR_STATE_FAILED          /* Removal failed (permissions, I/O error, etc.) */
} directory_state_t;

/**
 * Create cleanup result structure
 */
static error_t *create_result(cleanup_result_t **out) {
    CHECK_NULL(out);

    cleanup_result_t *result = calloc(1, sizeof(cleanup_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate cleanup result");
    }

    /* All fields initialized to 0/NULL by calloc */
    *out = result;
    return NULL;
}

/**
 * Free cleanup result
 */
void cleanup_result_free(cleanup_result_t *result) {
    if (!result) {
        return;
    }

    /* Free embedded safety violations */
    if (result->safety_violations) {
        safety_result_free(result->safety_violations);
    }

    free(result);
}

/**
 * Load metadata from deployed-but-not-active profiles
 *
 * Optimization: Only loads metadata from profiles that are deployed (have files
 * in state) but not currently active. This avoids duplicate loading when the
 * caller already has metadata from active profiles.
 *
 * Algorithm:
 * 1. Get all deployed profiles from state
 * 2. Compute set difference: deployed - active
 * 3. Load metadata only from inactive profiles
 * 4. If active_metadata provided, merge with inactive metadata
 *
 * Edge Cases:
 * - No deployed profiles → Returns empty metadata
 * - No active profiles → Loads from all deployed profiles
 * - All deployed profiles are active → Returns empty metadata (or clones active)
 *
 * @param repo Repository (must not be NULL)
 * @param state State for deployed profile lookup (must not be NULL)
 * @param active_metadata Pre-loaded metadata from active profiles (can be NULL)
 * @param active_profiles Currently active profiles (can be NULL)
 * @param out_metadata Merged metadata (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *load_complete_metadata(
    git_repository *repo,
    const state_t *state,
    const metadata_t *active_metadata,
    const profile_list_t *active_profiles,
    metadata_t **out_metadata
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(out_metadata);

    error_t *err = NULL;
    string_array_t *deployed_profiles = NULL;
    string_array_t *inactive_profiles = NULL;
    metadata_t *inactive_metadata = NULL;
    metadata_t *complete_metadata = NULL;

    /* Get all deployed profiles from state */
    err = state_get_deployed_profiles(state, &deployed_profiles);
    if (err) {
        return error_wrap(err, "Failed to get deployed profiles");
    }

    /* Handle case: no deployed profiles */
    if (!deployed_profiles || string_array_size(deployed_profiles) == 0) {
        string_array_free(deployed_profiles);
        /* Return empty metadata (not an error) */
        return metadata_create_empty(out_metadata);
    }

    /* Compute set difference: deployed - active */
    inactive_profiles = string_array_create();
    if (!inactive_profiles) {
        string_array_free(deployed_profiles);
        return ERROR(ERR_MEMORY, "Failed to allocate inactive profiles array");
    }

    for (size_t i = 0; i < string_array_size(deployed_profiles); i++) {
        const char *deployed_name = string_array_get(deployed_profiles, i);
        bool is_active = false;

        /* Check if this deployed profile is also active */
        if (active_profiles) {
            for (size_t j = 0; j < active_profiles->count; j++) {
                if (strcmp(deployed_name, active_profiles->profiles[j].name) == 0) {
                    is_active = true;
                    break;
                }
            }
        }

        /* Add to inactive list if not active */
        if (!is_active) {
            err = string_array_push(inactive_profiles, deployed_name);
            if (err) {
                string_array_free(deployed_profiles);
                string_array_free(inactive_profiles);
                return error_wrap(err, "Failed to add inactive profile");
            }
        }
    }

    /* Load metadata from inactive profiles */
    if (string_array_size(inactive_profiles) > 0) {
        err = metadata_load_from_profiles(repo, inactive_profiles, &inactive_metadata);
        if (err) {
            /* Non-fatal if metadata doesn't exist, but fatal on other errors */
            if (err->code != ERR_NOT_FOUND) {
                string_array_free(deployed_profiles);
                string_array_free(inactive_profiles);
                return error_wrap(err, "Failed to load metadata from inactive profiles");
            }
            /* Metadata not found - treat as empty */
            error_free(err);
            err = metadata_create_empty(&inactive_metadata);
            if (err) {
                string_array_free(deployed_profiles);
                string_array_free(inactive_profiles);
                return err;
            }
        }
    } else {
        /* No inactive profiles - create empty metadata */
        err = metadata_create_empty(&inactive_metadata);
        if (err) {
            string_array_free(deployed_profiles);
            string_array_free(inactive_profiles);
            return err;
        }
    }

    /* Merge active and inactive metadata */
    if (active_metadata) {
        /* Both active and inactive metadata available - merge them */
        const metadata_t *to_merge[] = {active_metadata, inactive_metadata};
        err = metadata_merge(to_merge, 2, &complete_metadata);
        if (err) {
            metadata_free(inactive_metadata);
            string_array_free(deployed_profiles);
            string_array_free(inactive_profiles);
            return error_wrap(err, "Failed to merge active and inactive metadata");
        }
        /* Transfer ownership to result, free inactive */
        metadata_free(inactive_metadata);
    } else {
        /* Only inactive metadata available - use it directly */
        complete_metadata = inactive_metadata;
        inactive_metadata = NULL;  /* Transfer ownership */
    }

    /* Clean up temporary arrays */
    string_array_free(deployed_profiles);
    string_array_free(inactive_profiles);

    *out_metadata = complete_metadata;
    return NULL;
}

/**
 * Report safety violations to user
 *
 * Displays detailed information about files that cannot be safely removed
 * with guidance on how to proceed.
 */
static void report_safety_violations(
    output_ctx_t *out,
    const safety_result_t *safety_result
) {
    if (!out || !safety_result || safety_result->count == 0) {
        return;
    }

    output_section(out, "Modified orphaned files detected");
    output_newline(out);

    output_warning(out, "The following files cannot be safely removed:");

    for (size_t i = 0; i < safety_result->count; i++) {
        const safety_violation_t *v = &safety_result->violations[i];

        /* Format reason for display */
        const char *reason_display = NULL;
        const char *icon = "•";

        if (strcmp(v->reason, SAFETY_REASON_MODIFIED) == 0) {
            reason_display = "modified";
            icon = "✗";
        } else if (strcmp(v->reason, SAFETY_REASON_MODE_CHANGED) == 0) {
            reason_display = "permissions changed";
            icon = "⚠";
        } else if (strcmp(v->reason, SAFETY_REASON_TYPE_CHANGED) == 0) {
            reason_display = "type changed";
            icon = "⚠";
        } else if (strcmp(v->reason, SAFETY_REASON_PROFILE_DELETED) == 0) {
            reason_display = "profile branch deleted";
            icon = "!";
        } else if (strcmp(v->reason, SAFETY_REASON_FILE_REMOVED) == 0) {
            reason_display = "removed from profile";
            icon = "!";
        } else if (strcmp(v->reason, SAFETY_REASON_CANNOT_VERIFY) == 0) {
            reason_display = "cannot verify";
            icon = "?";
        } else {
            reason_display = v->reason;
        }

        if (output_colors_enabled(out)) {
            const char *reason_color = v->content_modified ?
                output_color_code(out, OUTPUT_COLOR_RED) :
                output_color_code(out, OUTPUT_COLOR_YELLOW);

            output_printf(out, OUTPUT_NORMAL, "  %s%s%s %s %s(%s",
                   reason_color,
                   icon,
                   output_color_code(out, OUTPUT_COLOR_RESET),
                   v->filesystem_path,
                   reason_color,
                   reason_display);

            if (v->source_profile) {
                output_printf(out, OUTPUT_NORMAL, " from %s%s%s",
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       v->source_profile,
                       reason_color);
            }

            output_printf(out, OUTPUT_NORMAL, ")%s\n",
                   output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %s %s (%s",
                   icon, v->filesystem_path, reason_display);

            if (v->source_profile) {
                output_printf(out, OUTPUT_NORMAL, " from %s", v->source_profile);
            }

            output_printf(out, OUTPUT_NORMAL, ")\n");
        }
    }
    output_newline(out);

    output_info(out, "These files are from unselected profiles but have uncommitted changes.");
    output_info(out, "To prevent data loss, commit changes before removing:");
    output_newline(out);
    output_info(out, "Options:");
    output_info(out, "  1. Commit changes to the profile:");

    /* Get first violation's profile for example commands */
    const char *example_profile = NULL;
    if (safety_result->count > 0 && safety_result->violations[0].source_profile) {
        example_profile = safety_result->violations[0].source_profile;
    }

    if (example_profile) {
        output_info(out, "     dotta update -p %s <files>", example_profile);
        output_info(out, "     dotta apply");
    } else {
        output_info(out, "     dotta update <files>");
        output_info(out, "     dotta apply");
    }

    output_info(out, "  2. Force removal (discards changes):");
    output_info(out, "     dotta apply --force");
    output_info(out, "  3. Keep the profile selected:");

    if (example_profile) {
        output_info(out, "     dotta profile select %s", example_profile);
    }
}

/**
 * Remove orphaned files from filesystem
 *
 * Identifies files in state that are not in manifest and removes them after
 * safety validation. Integrates with safety module to prevent data loss.
 *
 * Algorithm:
 * 1. Build hashmap of manifest paths for O(1) lookup
 * 2. Identify orphaned files (in state, not in manifest)
 * 3. Run safety checks (unless force=true)
 * 4. Remove safe files, skip violated files, track failures
 *
 * @param repo Repository (must not be NULL)
 * @param state State for file tracking (must not be NULL)
 * @param manifest Current manifest (must not be NULL)
 * @param result Cleanup result to update (must not be NULL)
 * @param opts Cleanup options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *prune_orphaned_files(
    git_repository *repo,
    const state_t *state,
    const manifest_t *manifest,
    cleanup_result_t *result,
    const cleanup_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(manifest);
    CHECK_NULL(result);
    CHECK_NULL(opts);
    CHECK_NULL(opts->out);

    error_t *err = NULL;
    string_array_t *to_remove = NULL;
    hashmap_t *manifest_paths = NULL;
    hashmap_t *violations_map = NULL;
    state_file_entry_t *state_files = NULL;
    size_t state_file_count = 0;

    output_ctx_t *out = opts->out;
    bool verbose = opts->verbose;
    bool dry_run = opts->dry_run;
    bool force = opts->force;

    /* Get all files tracked in state */
    err = state_get_all_files(state, &state_files, &state_file_count);
    if (err) {
        return error_wrap(err, "Failed to get state files");
    }

    /* Handle case: no files in state */
    if (state_file_count == 0) {
        state_free_all_files(state_files, state_file_count);
        return NULL;  /* Nothing to do */
    }

    /* Build hashmap of manifest paths for O(1) lookup */
    manifest_paths = hashmap_create(manifest->count);
    if (!manifest_paths) {
        state_free_all_files(state_files, state_file_count);
        return ERROR(ERR_MEMORY, "Failed to create manifest paths hashmap");
    }

    for (size_t i = 0; i < manifest->count; i++) {
        err = hashmap_set(manifest_paths, manifest->entries[i].filesystem_path, (void *)1);
        if (err) {
            err = error_wrap(err, "Failed to populate manifest paths hashmap");
            goto cleanup;
        }
    }

    /* Identify orphaned files (in state, not in manifest) */
    to_remove = string_array_create();
    if (!to_remove) {
        err = ERROR(ERR_MEMORY, "Failed to allocate orphan list");
        goto cleanup;
    }

    for (size_t i = 0; i < state_file_count; i++) {
        const state_file_entry_t *state_entry = &state_files[i];

        if (!hashmap_has(manifest_paths, state_entry->filesystem_path)) {
            err = string_array_push(to_remove, state_entry->filesystem_path);
            if (err) {
                err = error_wrap(err, "Failed to add orphaned file to list");
                goto cleanup;
            }
        }
    }

    result->orphaned_files_found = string_array_size(to_remove);

    /* Early exit if no orphaned files */
    if (result->orphaned_files_found == 0) {
        if (verbose) {
            output_print(out, OUTPUT_VERBOSE, "No orphaned files to remove\n");
        }
        err = NULL;
        goto cleanup;
    }

    /* Safety check: detect modified orphaned files */
    if (!force) {
        err = safety_check_removal(
            repo,
            state,
            (const char **)to_remove->items,
            to_remove->count,
            force,
            &result->safety_violations
        );

        if (err) {
            /* Fatal error during safety check */
            err = error_wrap(err, "Safety check failed");
            goto cleanup;
        }

        /* Build violations map for O(1) lookup during removal */
        if (result->safety_violations && result->safety_violations->count > 0) {
            violations_map = hashmap_create(result->safety_violations->count);
            if (!violations_map) {
                err = ERROR(ERR_MEMORY, "Failed to create violations hashmap");
                goto cleanup;
            }

            for (size_t i = 0; i < result->safety_violations->count; i++) {
                const safety_violation_t *v = &result->safety_violations->violations[i];
                hashmap_set(violations_map, v->filesystem_path, (void *)1);
            }

            /* Report violations to user */
            report_safety_violations(out, result->safety_violations);
        }
    }

    /* Remove orphaned files */
    if (verbose) {
        char header[128];
        snprintf(header, sizeof(header), "Pruning %zu orphaned file%s",
                string_array_size(to_remove),
                string_array_size(to_remove) == 1 ? "" : "s");
        output_section(out, header);
    }

    for (size_t i = 0; i < string_array_size(to_remove); i++) {
        const char *path = string_array_get(to_remove, i);

        /* Skip if file has safety violation */
        if (violations_map && hashmap_has(violations_map, path)) {
            result->orphaned_files_skipped++;
            if (verbose) {
                if (output_colors_enabled(out)) {
                    output_printf(out, OUTPUT_NORMAL, "  %s[skipped]%s %s (safety violation)\n",
                           output_color_code(out, OUTPUT_COLOR_YELLOW),
                           output_color_code(out, OUTPUT_COLOR_RESET),
                           path);
                } else {
                    output_printf(out, OUTPUT_NORMAL, "  [skipped] %s (safety violation)\n", path);
                }
            }
            continue;
        }

        /* Skip if file doesn't exist (already deleted) */
        if (!fs_exists(path)) {
            /* Don't count as skipped or failed - file is already gone */
            continue;
        }

        /* Dry run: report but don't remove */
        if (dry_run) {
            if (verbose) {
                if (output_colors_enabled(out)) {
                    output_printf(out, OUTPUT_NORMAL, "  %s[would remove]%s %s\n",
                           output_color_code(out, OUTPUT_COLOR_CYAN),
                           output_color_code(out, OUTPUT_COLOR_RESET),
                           path);
                } else {
                    output_printf(out, OUTPUT_NORMAL, "  [would remove] %s\n", path);
                }
            }
            continue;
        }

        /* Remove file */
        error_t *remove_err = fs_remove_file(path);
        if (remove_err) {
            /* Non-fatal: track failure and continue */
            result->orphaned_files_failed++;
            if (verbose) {
                if (output_colors_enabled(out)) {
                    fprintf(stderr, "  %s[fail]%s %s: %s\n",
                           output_color_code(out, OUTPUT_COLOR_RED),
                           output_color_code(out, OUTPUT_COLOR_RESET),
                           path, error_message(remove_err));
                } else {
                    fprintf(stderr, "  [fail] %s: %s\n", path, error_message(remove_err));
                }
            }
            error_free(remove_err);
        } else {
            /* File removed successfully */
            result->orphaned_files_removed++;
            if (verbose) {
                if (output_colors_enabled(out)) {
                    output_printf(out, OUTPUT_NORMAL, "  %s[removed]%s %s\n",
                           output_color_code(out, OUTPUT_COLOR_GREEN),
                           output_color_code(out, OUTPUT_COLOR_RESET),
                           path);
                } else {
                    output_printf(out, OUTPUT_NORMAL, "  [removed] %s\n", path);
                }
            }
        }
    }

    /* Print summary if not verbose */
    if (!verbose && result->orphaned_files_removed > 0) {
        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "Pruned %s%zu%s orphaned file%s\n",
                   output_color_code(out, OUTPUT_COLOR_YELLOW),
                   result->orphaned_files_removed,
                   output_color_code(out, OUTPUT_COLOR_RESET),
                   result->orphaned_files_removed == 1 ? "" : "s");
        } else {
            output_printf(out, OUTPUT_NORMAL, "Pruned %zu orphaned file%s\n",
                   result->orphaned_files_removed,
                   result->orphaned_files_removed == 1 ? "" : "s");
        }
    }

    err = NULL;

cleanup:
    if (violations_map) hashmap_free(violations_map, NULL);
    if (manifest_paths) hashmap_free(manifest_paths, NULL);
    if (to_remove) string_array_free(to_remove);
    state_free_all_files(state_files, state_file_count);
    return err;
}

/**
 * Reset parent directory state to UNKNOWN
 *
 * When a child directory is removed, the parent might now be empty.
 * This function finds the parent in the directory list and resets its
 * state so it will be rechecked in the next iteration.
 *
 * Edge cases:
 * - Root directory (/) → No parent, skip
 * - No slash in path → No parent, skip
 * - Parent not in tracked list → Skip (only track explicitly added dirs)
 *
 * @param directories Array of tracked directories
 * @param dir_count Number of directories
 * @param states Array of directory states (parallel to directories)
 * @param removed_path Path of directory that was just removed
 */
static void reset_parent_directory_state(
    const metadata_directory_entry_t *directories,
    size_t dir_count,
    directory_state_t *states,
    const char *removed_path
) {
    if (!directories || !states || !removed_path || dir_count == 0) {
        return;
    }

    /* Extract parent path by finding last slash */
    const char *last_slash = strrchr(removed_path, '/');

    /* Edge case: root directory or no parent */
    if (!last_slash || last_slash == removed_path) {
        return;  /* No parent to reset */
    }

    /* Build parent path (everything before last slash) */
    size_t parent_len = last_slash - removed_path;
    char *parent_path = strndup(removed_path, parent_len);
    if (!parent_path) {
        return;  /* Memory allocation failed - non-fatal */
    }

    /* Find parent in directories list */
    for (size_t i = 0; i < dir_count; i++) {
        if (strcmp(directories[i].filesystem_path, parent_path) == 0) {
            /* Found parent - reset state if it was marked non-empty */
            if (states[i] == DIR_STATE_NOT_EMPTY) {
                states[i] = DIR_STATE_UNKNOWN;
            }
            break;
        }
    }

    free(parent_path);
}

/**
 * Prune empty tracked directories
 *
 * Iteratively removes directories that are:
 * 1. Explicitly tracked in metadata (added via `dotta add`)
 * 2. Empty (contain no files or subdirectories)
 *
 * Uses state tracking optimization to avoid redundant filesystem checks
 * for deep directory hierarchies.
 *
 * Algorithm:
 * - Iteration 1: Check all dirs, remove empty ones
 * - Iteration 2: Parent dirs might now be empty, check unknowns only
 * - Repeat until no progress made (stable state)
 *
 * State Tracking Optimization:
 * - DIR_STATE_REMOVED: Skip in all future iterations
 * - DIR_STATE_NOT_EMPTY: Skip until child removed (then reset to UNKNOWN)
 * - DIR_STATE_NONEXISTENT: Skip in all future iterations
 * - DIR_STATE_FAILED: Skip in all future iterations
 * - DIR_STATE_UNKNOWN: Check in this iteration
 *
 * @param metadata Complete metadata (must not be NULL)
 * @param result Cleanup result to update (must not be NULL)
 * @param opts Cleanup options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *prune_empty_directories(
    const metadata_t *metadata,
    cleanup_result_t *result,
    const cleanup_options_t *opts
) {
    CHECK_NULL(metadata);
    CHECK_NULL(result);
    CHECK_NULL(opts);
    CHECK_NULL(opts->out);

    output_ctx_t *out = opts->out;
    bool verbose = opts->verbose;
    bool dry_run = opts->dry_run;

    /* Get all tracked directories */
    size_t dir_count = 0;
    const metadata_directory_entry_t *directories =
        metadata_get_all_tracked_directories(metadata, &dir_count);

    if (dir_count == 0) {
        return NULL;  /* No tracked directories */
    }

    result->directories_checked = dir_count;

    /* Allocate state tracking array */
    directory_state_t *states = calloc(dir_count, sizeof(directory_state_t));
    if (!states) {
        /* Non-fatal: allocation failure skips directory pruning entirely.
         * This is safer than attempting unoptimized pruning, which could
         * be prohibitively expensive for large directory hierarchies. */
        output_warning(out, "Failed to allocate directory state tracking, skipping directory pruning");
        return NULL;
    }

    /* All states initialized to DIR_STATE_UNKNOWN by calloc */

    bool header_printed = false;
    bool made_progress = true;

    /* Iteratively remove empty directories until stable */
    while (made_progress) {
        made_progress = false;

        for (size_t i = 0; i < dir_count; i++) {
            const char *dir_path = directories[i].filesystem_path;

            /* Optimization: Skip directories with known state */
            if (states[i] == DIR_STATE_REMOVED ||
                states[i] == DIR_STATE_NONEXISTENT ||
                states[i] == DIR_STATE_FAILED) {
                continue;
            }

            /* Skip non-empty directories (until child removed) */
            if (states[i] == DIR_STATE_NOT_EMPTY) {
                continue;
            }

            /* Check if directory exists */
            if (!fs_exists(dir_path)) {
                states[i] = DIR_STATE_NONEXISTENT;
                continue;
            }

            /* Check if directory is empty */
            if (!fs_is_directory_empty(dir_path)) {
                states[i] = DIR_STATE_NOT_EMPTY;
                continue;  /* Won't re-check until child removed */
            }

            /* Print header on first removal attempt */
            if (!header_printed && verbose) {
                output_section(out, "Pruning empty tracked directories");
                header_printed = true;
            }

            /* Dry run: report but don't remove */
            if (dry_run) {
                if (verbose) {
                    if (output_colors_enabled(out)) {
                        output_printf(out, OUTPUT_NORMAL, "  %s[would remove]%s %s\n",
                               output_color_code(out, OUTPUT_COLOR_CYAN),
                               output_color_code(out, OUTPUT_COLOR_RESET),
                               dir_path);
                    } else {
                        output_printf(out, OUTPUT_NORMAL, "  [would remove] %s\n", dir_path);
                    }
                }
                continue;
            }

            /* Remove empty directory */
            error_t *err = fs_remove_dir(dir_path, false);
            if (err) {
                /* Non-fatal: track failure and continue */
                result->directories_failed++;
                states[i] = DIR_STATE_FAILED;
                if (verbose) {
                    if (output_colors_enabled(out)) {
                        fprintf(stderr, "  %s[fail]%s %s: %s\n",
                               output_color_code(out, OUTPUT_COLOR_RED),
                               output_color_code(out, OUTPUT_COLOR_RESET),
                               dir_path, error_message(err));
                    } else {
                        fprintf(stderr, "  [fail] %s: %s\n", dir_path, error_message(err));
                    }
                }
                error_free(err);
            } else {
                /* Directory removed successfully */
                result->directories_removed++;
                states[i] = DIR_STATE_REMOVED;
                made_progress = true;

                /* Reset parent directory state (might now be empty) */
                reset_parent_directory_state(directories, dir_count, states, dir_path);

                if (verbose) {
                    if (output_colors_enabled(out)) {
                        output_printf(out, OUTPUT_NORMAL, "  %s[removed]%s %s\n",
                               output_color_code(out, OUTPUT_COLOR_GREEN),
                               output_color_code(out, OUTPUT_COLOR_RESET),
                               dir_path);
                    } else {
                        output_printf(out, OUTPUT_NORMAL, "  [removed] %s\n", dir_path);
                    }
                }
            }
        }
    }

    /* Print summary if not verbose */
    if (!verbose) {
        if (result->directories_removed > 0) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "Pruned %s%zu%s empty director%s\n",
                       output_color_code(out, OUTPUT_COLOR_YELLOW),
                       result->directories_removed,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       result->directories_removed == 1 ? "y" : "ies");
            } else {
                output_printf(out, OUTPUT_NORMAL, "Pruned %zu empty director%s\n",
                       result->directories_removed,
                       result->directories_removed == 1 ? "y" : "ies");
            }
        }
        if (result->directories_failed > 0) {
            output_warning(out, "Failed to prune %zu director%s",
                   result->directories_failed,
                   result->directories_failed == 1 ? "y" : "ies");
        }
    }

    free(states);
    return NULL;
}

/**
 * Execute cleanup operations
 *
 * Main entry point for cleanup module. Coordinates orphaned file removal
 * and empty directory pruning with safety checks and optimized metadata loading.
 */
error_t *cleanup_execute(
    git_repository *repo,
    const state_t *state,
    const manifest_t *manifest,
    const cleanup_options_t *opts,
    cleanup_result_t **out_result
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(opts->out);
    CHECK_NULL(out_result);

    error_t *err = NULL;
    cleanup_result_t *result = NULL;
    metadata_t *complete_metadata = NULL;

    /* Create result structure */
    err = create_result(&result);
    if (err) {
        return err;
    }

    /* Step 1: Remove orphaned files with safety validation */
    err = prune_orphaned_files(repo, state, manifest, result, opts);
    if (err) {
        cleanup_result_free(result);
        return error_wrap(err, "Failed to remove orphaned files");
    }

    /* Step 2: Load complete metadata (optimized for deployed-but-not-active profiles) */
    err = load_complete_metadata(
        repo,
        state,
        opts->active_metadata,
        opts->active_profiles,
        &complete_metadata
    );
    if (err) {
        cleanup_result_free(result);
        return error_wrap(err, "Failed to load metadata for directory cleanup");
    }

    /* Step 3: Prune empty tracked directories */
    err = prune_empty_directories(complete_metadata, result, opts);
    if (err) {
        metadata_free(complete_metadata);
        cleanup_result_free(result);
        return error_wrap(err, "Failed to prune empty directories");
    }

    /* Clean up and return result */
    metadata_free(complete_metadata);
    *out_result = result;
    return NULL;
}
