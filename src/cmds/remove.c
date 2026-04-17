/**
 * remove.c - Remove files from profiles or delete profiles
 */

#include "cmds/remove.h"

#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "base/string.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/path.h"
#include "infra/worktree.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/upstream.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/hooks.h"

/**
 * Validate command options
 */
static error_t *validate_options(const cmd_remove_options_t *opts) {
    CHECK_NULL(opts);

    if (!opts->profile || opts->profile[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name is required");
    }

    /* If deleting profile, paths are optional */
    if (opts->delete_profile) {
        if (opts->paths && opts->path_count > 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "Cannot specify paths when using --delete-profile"
            );
        }
        return NULL;
    }

    /* If not deleting profile, paths are required */
    if (!opts->paths || opts->path_count == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "At least one path is required (or use --delete-profile)"
        );
    }

    return NULL;
}

/**
 * Resolve input paths to storage paths
 *
 * Accepts both filesystem paths and storage paths as input.
 * Uses hashmap for O(M+N) performance instead of O(N×M) nested loops.
 *
 * Complexity: O(M) to build index + O(N) to process inputs = O(M+N)
 * Old implementation: O(N×M) with nested loops
 *
 * @param state Optional state for custom prefix resolution (improves UX, can be NULL)
 */
static error_t *resolve_paths_to_remove(
    git_repository *repo,
    const char *profile,
    char **input_paths,
    size_t path_count,
    string_array_t **storage_paths_out,
    string_array_t **filesystem_paths_out,
    const cmd_remove_options_t *opts,
    output_ctx_t *out,
    state_t *state
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(input_paths);
    CHECK_NULL(storage_paths_out);
    CHECK_NULL(filesystem_paths_out);
    CHECK_NULL(opts);

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    string_array_t *storage_paths = NULL;
    string_array_t *filesystem_paths = NULL;
    string_array_t *profile_files = NULL;
    hashmap_t *profile_files_map = NULL;

    /* Look up the profile's custom prefix for custom/ path resolution
     * (optional, improves UX). Borrowed from the state row cache; stable
     * for the duration of this call (no enabled_profiles mutation below). */
    const char *custom_prefix =
        state ? state_peek_profile_prefix(state, profile) : NULL;

    /* Allocate arrays */
    storage_paths = string_array_new(0);
    filesystem_paths = string_array_new(0);
    if (!storage_paths || !filesystem_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate path arrays");
        goto cleanup;
    }

    /* Get list of files in profile */
    err = profile_list_files(repo, profile, &profile_files);
    if (err) {
        err = error_wrap(err, "Failed to list files in profile");
        goto cleanup;
    }

    /* Build hashmap index for O(1) lookups */
    profile_files_map = hashmap_borrow(profile_files->count);
    if (!profile_files_map) {
        err = ERROR(ERR_MEMORY, "Failed to create profile files index");
        goto cleanup;
    }

    for (size_t i = 0; i < profile_files->count; i++) {
        const char *file = profile_files->items[i];
        err = hashmap_set(profile_files_map, file, (void *) 1);  /* Dummy value */
        if (err) {
            err = error_wrap(err, "Failed to index profile files");
            goto cleanup;
        }
    }

    /* Process each input path */
    for (size_t i = 0; i < path_count; i++) {
        const char *input_path = input_paths[i];
        char *storage_path = NULL;
        char *canonical = NULL;

        /* Resolve input path to storage format (file need not exist) */
        err = path_resolve_input(
            input_path, custom_prefix ? &custom_prefix : NULL,
            custom_prefix ? 1 : 0, &storage_path
        );
        if (err) {
            if (!opts->force) {
                goto cleanup;
            }
            /* With --force, skip this path */
            output_warning(
                out, OUTPUT_VERBOSE, "Skipping invalid path '%s': %s",
                input_path, error_message(err)
            );
            error_free(err);
            err = NULL;
            continue;
        }

        /* Try to get filesystem path for output (non-fatal if it fails) */
        error_t *convert_err = path_from_storage(storage_path, custom_prefix, &canonical);
        if (convert_err) {
            /* Can still work with storage path only */
            error_free(convert_err);
            canonical = NULL;
        }

        /* Find all files that match this path (exact match or directory prefix) */
        size_t matches_found = 0;
        size_t storage_path_len = strlen(storage_path);

        /* Check exact match first - O(1) with hashmap */
        if (hashmap_has(profile_files_map, storage_path)) {
            /* Exact file match found */
            char *fs_path = canonical ? strdup(canonical) : NULL;

            err = string_array_push(storage_paths, storage_path);
            if (!err) {
                /* If filesystem path unavailable (custom/ without prefix context),
                 * fall back to storage path. Downstream consumers handle gracefully:
                 * state lookups return "not found", display shows storage format. */
                err = string_array_push(filesystem_paths, fs_path ? fs_path : storage_path);
            }

            free(fs_path);

            if (err) {
                free(storage_path);
                free(canonical);
                err = error_wrap(err, "Failed to track path for removal");
                goto cleanup;
            }

            matches_found++;
        }

        /* Check for directory prefix matches - requires iteration */
        for (size_t j = 0; j < profile_files->count; j++) {
            const char *profile_file = profile_files->items[j];

            /* Skip if already matched as exact */
            if (strcmp(profile_file, storage_path) == 0) {
                continue;
            }

            /* Directory prefix match */
            if (str_starts_with(profile_file, storage_path)) {
                /* Ensure it's a directory boundary */
                if (profile_file[storage_path_len] == '/') {
                    /* Reconstruct filesystem path for this file */
                    char *file_fs_path = NULL;
                    err = path_from_storage(profile_file, custom_prefix, &file_fs_path);
                    if (err) {
                        if (opts->verbose || !opts->force) {
                            output_warning(
                                out, OUTPUT_NORMAL,
                                "Failed to resolve filesystem path for '%s': %s",
                                profile_file, error_message(err)
                            );
                        }
                        error_free(err);
                        err = NULL;
                        continue;
                    }

                    err = string_array_push(storage_paths, profile_file);
                    if (!err) {
                        err = string_array_push(filesystem_paths, file_fs_path);
                    }

                    free(file_fs_path);

                    if (err) {
                        free(storage_path);
                        free(canonical);
                        err = error_wrap(err, "Failed to track path for removal");
                        goto cleanup;
                    }

                    matches_found++;
                }
            }
        }

        if (matches_found == 0) {
            if (!opts->force) {
                /* Save storage_path for error message before freeing */
                char error_storage_path[PATH_MAX];
                snprintf(error_storage_path, sizeof(error_storage_path), "%s", storage_path);

                free(storage_path);
                free(canonical);

                err = ERROR(
                    ERR_NOT_FOUND, "File '%s' not found in profile '%s'\n"
                    "Hint: Use 'dotta list --profile %s' to see tracked files",
                    error_storage_path, profile, profile
                );
                goto cleanup;
            }
            /* With --force, warn and skip */
            output_warning(
                out, OUTPUT_VERBOSE, "File '%s' not found in profile, skipping",
                storage_path
            );
        }

        free(storage_path);
        free(canonical);
    }

    /* Check if we found any files */
    if (storage_paths->count == 0) {
        err = ERROR(
            ERR_NOT_FOUND, "No files found to remove from profile '%s'",
            profile
        );
        goto cleanup;
    }

    /* Success - transfer ownership to caller */
    *storage_paths_out = storage_paths;
    *filesystem_paths_out = filesystem_paths;
    storage_paths = NULL;      /* Prevent cleanup */
    filesystem_paths = NULL;   /* Prevent cleanup */

cleanup:
    /* Free all resources */
    if (profile_files_map) hashmap_free(profile_files_map, NULL);
    if (profile_files) string_array_free(profile_files);
    if (storage_paths) string_array_free(storage_paths);
    if (filesystem_paths) string_array_free(filesystem_paths);

    return err;
}

/**
 * Remove file from worktree
 */
static error_t *remove_file_from_worktree(
    worktree_handle_t *wt,
    const char *storage_path,
    const cmd_remove_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(wt);
    CHECK_NULL(storage_path);
    CHECK_NULL(opts);

    const char *wt_path = worktree_get_path(wt);
    char *file_path = str_format("%s/%s", wt_path, storage_path);
    if (!file_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate file path");
    }

    /* Check if file exists */
    if (!fs_exists(file_path)) {
        free(file_path);
        if (!opts->force) {
            return ERROR(
                ERR_NOT_FOUND, "File '%s' not found in worktree",
                storage_path
            );
        }
        /* With --force, skip silently */
        return NULL;
    }

    /* Remove from filesystem */
    error_t *err = fs_remove_file(file_path);
    free(file_path);
    if (err) {
        return error_wrap(
            err, "Failed to remove file '%s' from worktree",
            storage_path
        );
    }

    /* Stage deletion */
    err = worktree_unstage_file(wt, storage_path);
    if (err) {
        return error_wrap(err, "Failed to unstage file");
    }

    output_info(out, OUTPUT_VERBOSE, "Removed: %s", storage_path);

    return NULL;
}

/**
 * Check if a file is currently deployed from a different profile
 *
 * Helper to determine if removing a file from one profile will affect the filesystem.
 */
static bool deployed_from_other_profile(
    state_t *state,
    const char *filesystem_path,
    const char *current_profile
) {
    if (!state || !filesystem_path || !current_profile) {
        return false;
    }

    if (!state_file_exists(state, filesystem_path)) {
        return false;
    }

    state_file_entry_t *state_entry = NULL;
    error_t *err = state_get_file(state, filesystem_path, &state_entry);

    bool is_other = false;
    if (!err && state_entry &&
        state_entry->state &&
        strcmp(state_entry->state, STATE_ACTIVE) == 0 &&
        strcmp(state_entry->profile, current_profile) != 0) {
        is_other = true;
    }

    error_free(err);
    state_free_entry(state_entry);
    return is_other;
}

/**
 * Analyze multi-profile conflicts for files to be removed
 *
 * Checks each file against all other profiles and determines:
 * - Which other profiles contain the file
 * - Whether the file is deployed from another profile
 *
 * Performance: O(M×P + N) where M=profiles, P=avg files/profile, N=files checked
 * Uses centralized profile_build_file_index() for optimal performance.
 *
 * Returns arrays of other profiles per file (caller must free).
 */
static error_t *analyze_multi_profile_conflicts(
    git_repository *repo,
    const string_array_t *storage_paths,
    const string_array_t *filesystem_paths,
    const char *current_profile,
    state_t *state,
    string_array_t ***other_profiles_out,
    size_t *multi_profile_count_out,
    bool *has_deployed_from_other_out
) {
    CHECK_NULL(repo);
    CHECK_NULL(storage_paths);
    CHECK_NULL(filesystem_paths);
    CHECK_NULL(current_profile);
    CHECK_NULL(other_profiles_out);
    CHECK_NULL(multi_profile_count_out);
    CHECK_NULL(has_deployed_from_other_out);

    error_t *err = NULL;
    size_t file_count = storage_paths->count;

    /* Allocate array to hold other_profiles for each file */
    string_array_t **other_profiles = calloc(file_count, sizeof(string_array_t *));
    if (!other_profiles) {
        return ERROR(ERR_MEMORY, "Failed to allocate multi-profile tracking");
    }

    /* Build profile file index once (O(M×P) - loads all profiles)
     * Uses centralized function from core/profiles.c */
    hashmap_t *profile_index = NULL;
    err = profile_build_file_index(repo, current_profile, &profile_index);
    if (err) {
        free(other_profiles);
        return error_wrap(err, "Failed to build profile index");
    }

    size_t multi_profile_count = 0;
    bool has_deployed_from_other = false;

    /* Check each file using O(1) index lookups */
    for (size_t i = 0; i < file_count; i++) {
        const char *storage_path = storage_paths->items[i];
        const char *filesystem_path = filesystem_paths->items[i];

        /* Lookup profiles containing this file - O(1) */
        string_array_t *indexed_profiles = hashmap_get(profile_index, storage_path);

        if (indexed_profiles && indexed_profiles->count > 0) {
            /* Create a copy for the output (index owns the original) */
            other_profiles[i] = string_array_new(0);
            if (other_profiles[i]) {
                for (size_t j = 0; j < indexed_profiles->count; j++) {
                    string_array_push(other_profiles[i], indexed_profiles->items[j]);
                }
                multi_profile_count++;

                /* Check if deployed from another profile.
                 * Only valid with actual filesystem paths (absolute), not
                 * storage path fallbacks (relative, e.g., "home/.bashrc"). */
                if (filesystem_path[0] == '/' &&
                    deployed_from_other_profile(state, filesystem_path, current_profile)) {
                    has_deployed_from_other = true;
                }
            }
        }
    }

    /* Free the index (and all its string arrays) */
    hashmap_free(profile_index, string_array_free_cb);

    *other_profiles_out = other_profiles;
    *multi_profile_count_out = multi_profile_count;
    *has_deployed_from_other_out = has_deployed_from_other;

    return NULL;
}

/**
 * Display multi-profile warnings to the user
 *
 * Shows which files exist in multiple profiles and explains the implications.
 */
static void display_multi_profile_warnings(
    output_ctx_t *out,
    const string_array_t *filesystem_paths,
    string_array_t **other_profiles,
    size_t file_count,
    size_t multi_profile_count,
    bool has_deployed_from_other,
    const char *current_profile
) {
    if (!out || multi_profile_count == 0) return;

    output_section(out, OUTPUT_NORMAL, "Multi-profile file warning");
    output_warning(
        out, OUTPUT_NORMAL, "%zu file%s exist%s in multiple profiles:",
        multi_profile_count,
        multi_profile_count == 1 ? "" : "s",
        multi_profile_count == 1 ? "s" : ""
    );

    /* Display each multi-profile file */
    for (size_t i = 0; i < file_count; i++) {
        if (!other_profiles[i] || other_profiles[i]->count == 0) {
            continue;
        }

        const char *fs_path = filesystem_paths->items[i];
        output_styled(
            out, OUTPUT_NORMAL, "  {yellow}%s{reset} also in:",
            fs_path
        );

        for (size_t j = 0; j < other_profiles[i]->count; j++) {
            output_styled(
                out, OUTPUT_NORMAL, " {cyan}%s{reset}",
                other_profiles[i]->items[j]
            );
        }
        output_newline(out, OUTPUT_NORMAL);
    }

    /* Explain implications */
    output_newline(out, OUTPUT_NORMAL);
    output_info(
        out, OUTPUT_NORMAL, "These files will be removed only from profile '%s'.",
        current_profile
    );

    if (has_deployed_from_other) {
        output_warning(
            out, OUTPUT_NORMAL, "Some files are currently deployed from other profiles."
        );
        output_info(
            out, OUTPUT_NORMAL, "Those files will remain on the filesystem."
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL, "Files deployed from '%s' will remain until 'dotta apply'.",
            current_profile
        );
    }
    output_newline(out, OUTPUT_NORMAL);
}

/**
 * Free multi-profile tracking arrays
 */
static void free_multi_profile_tracking(string_array_t **other_profiles, size_t count) {
    if (!other_profiles) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        string_array_free(other_profiles[i]);
    }
    free(other_profiles);
}

/**
 * Confirm removal operation
 */
static bool confirm_removal(
    const string_array_t *storage_paths,
    const cmd_remove_options_t *opts,
    const config_t *config,
    output_ctx_t *out
) {
    if (!storage_paths || !opts || !out) {
        return false;
    }

    /* Skip confirmation if --force */
    if (opts->force) {
        return true;
    }

    /* Skip confirmation for dry run */
    if (opts->dry_run) {
        return true;
    }

    size_t count = storage_paths->count;

    /* Check config threshold */
    size_t threshold = 5; /* Default threshold */
    if (config->confirm_destructive) {
        threshold = 1;    /* Always confirm in strict mode */
    }

    /* No confirmation needed for small operations below threshold */
    if (count < threshold) {
        return true;
    }

    /* Prompt user */
    char prompt[512];
    if (opts->delete_files) {
        snprintf(
            prompt, sizeof(prompt), "Remove %zu file%s from profile '%s'?\n"
            "(Deployed files will be removed on 'dotta apply')",
            count, count == 1 ? "" : "s", opts->profile
        );
    } else {
        snprintf(
            prompt, sizeof(prompt), "Remove %zu file%s from profile '%s'?\n"
            "(Deployed files will be released from management)",
            count, count == 1 ? "" : "s", opts->profile
        );
    }

    return output_confirm(out, prompt, false);
}

/**
 * Confirm profile deletion
 */
static bool confirm_profile_deletion(
    const char *profile,
    size_t file_count,
    const cmd_remove_options_t *opts,
    const config_t *config,
    output_ctx_t *out
) {
    if (!profile || !out) {
        return false;
    }

    /* Skip confirmation if --force */
    if (opts->force) {
        return true;
    }

    output_newline(out, OUTPUT_NORMAL);
    output_warning(
        out, OUTPUT_NORMAL, "This will delete profile '%s' (%zu file%s)",
        profile, file_count, file_count == 1 ? "" : "s"
    );
    if (opts->delete_files) {
        output_info(
            out, OUTPUT_NORMAL,
            "         Deployed files will be removed when you run 'dotta apply'."
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL,
            "         Deployed files will be released from management."
        );
    }
    output_newline(out, OUTPUT_NORMAL);

    bool confirmed = output_confirm_destructive(
        out, config ? config->confirm_destructive : true, "Continue?", opts->force
    );

    return confirmed;
}

/**
 * Create commit for removal
 */
static error_t *create_removal_commit(
    worktree_handle_t *wt,
    const cmd_remove_options_t *opts,
    const string_array_t *removed_paths,
    const config_t *config
) {
    CHECK_NULL(wt);
    CHECK_NULL(opts);
    CHECK_NULL(removed_paths);

    /* Build commit message context */
    commit_message_context_t ctx = {
        .action        = COMMIT_ACTION_REMOVE,
        .profile       = opts->profile,
        .files         = removed_paths->items,
        .file_count    = removed_paths->count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };

    char *message = build_commit_message(config, &ctx);
    if (!message) {
        return ERROR(ERR_MEMORY, "Failed to build commit message");
    }

    /* Create commit */
    error_t *err = worktree_commit(wt, opts->profile, message, NULL);
    free(message);

    if (err) {
        return error_wrap(err, "Failed to create commit");
    }

    return NULL;
}

/**
 * Remove metadata entries for removed files
 *
 * Loads existing metadata from worktree, removes entries for deleted files,
 * and saves the updated metadata back. The metadata.json file is then staged.
 */
static error_t *cleanup_metadata(
    worktree_handle_t *wt,
    const string_array_t *removed_paths,
    output_ctx_t *out
) {
    CHECK_NULL(wt);
    CHECK_NULL(removed_paths);

    const char *worktree_path = worktree_get_path(wt);
    if (!worktree_path) {
        return ERROR(ERR_INTERNAL, "Worktree path is NULL");
    }

    /* Load existing metadata from worktree (if it exists) */
    metadata_t *metadata = NULL;
    char *metadata_file_path = str_format("%s/%s", worktree_path, METADATA_FILE_PATH);
    if (!metadata_file_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata file path");
    }

    error_t *err = metadata_load_from_file(metadata_file_path, &metadata);
    free(metadata_file_path);

    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            /* No existing metadata - nothing to clean up */
            error_free(err);
            return NULL;
        } else {
            /* Real error - propagate */
            return error_wrap(err, "Failed to load existing metadata");
        }
    }

    /* Remove metadata entries for each removed file */
    size_t removed_count = 0;
    for (size_t i = 0; i < removed_paths->count; i++) {
        const char *storage_path = removed_paths->items[i];

        /* Check if metadata item exists */
        if (metadata_has_item(metadata, storage_path)) {
            err = metadata_remove_item(metadata, storage_path);
            if (err) {
                metadata_free(metadata);
                return error_wrap(
                    err, "Failed to remove metadata item: %s",
                    storage_path
                );
            }

            removed_count++;

            output_info(out, OUTPUT_VERBOSE, "Removed metadata: %s", storage_path);
        }
    }

    /* Remove orphaned directory entries
     *
     * When all files under a tracked directory are removed, the directory
     * metadata entry must also be removed. Otherwise manifest_sync_directories()
     * will re-activate the directory as STATE_ACTIVE on every subsequent operation.
     *
     * Directory metadata is always derivative of file metadata (created as a
     * side-effect of `dotta add` capturing parent directory permissions). If no
     * files remain under a directory, the entry is genuinely orphaned.
     */
    size_t dir_count = 0;
    const metadata_item_t **directories =
        metadata_get_items_by_kind(metadata, METADATA_ITEM_DIRECTORY, &dir_count);

    if (directories && dir_count > 0) {
        /* Get remaining files for prefix checking */
        size_t file_count = 0;
        const metadata_item_t **files =
            metadata_get_items_by_kind(metadata, METADATA_ITEM_FILE, &file_count);

        /* Collect orphaned keys first (can't modify metadata during iteration) */
        string_array_t *orphaned_dirs = string_array_new(0);
        if (!orphaned_dirs) {
            free(files);
            free(directories);
            metadata_free(metadata);
            return ERROR(ERR_MEMORY, "Failed to allocate orphaned dirs array");
        }

        for (size_t d = 0; d < dir_count; d++) {
            const char *dir_key = directories[d]->key;
            size_t dir_key_len = strlen(dir_key);
            bool has_files = false;

            for (size_t f = 0; f < file_count; f++) {
                if (str_starts_with(files[f]->key, dir_key) &&
                    files[f]->key[dir_key_len] == '/'){
                    has_files = true;
                    break;
                }
            }

            if (!has_files) {
                err = string_array_push(orphaned_dirs, dir_key);
                if (err) {
                    string_array_free(orphaned_dirs);
                    free(files);
                    free(directories);
                    metadata_free(metadata);
                    return error_wrap(err, "Failed to track orphaned directory");
                }
            }
        }

        /* Remove orphaned directories */
        for (size_t i = 0; i < orphaned_dirs->count; i++) {
            err = metadata_remove_item(metadata, orphaned_dirs->items[i]);
            if (err) {
                string_array_free(orphaned_dirs);
                free(files);
                free(directories);
                metadata_free(metadata);
                return error_wrap(err, "Failed to remove orphaned directory metadata");
            }

            removed_count++;

            output_info(
                out, OUTPUT_VERBOSE, "Removed orphaned directory metadata: %s",
                orphaned_dirs->items[i]
            );
        }

        string_array_free(orphaned_dirs);
        free(files);
        free(directories);
    }

    /* Skip rewrite if nothing was actually removed from metadata */
    if (removed_count == 0) {
        metadata_free(metadata);
        return NULL;
    }

    /* Save updated metadata to worktree */
    err = metadata_save_to_worktree(worktree_path, metadata);
    metadata_free(metadata);

    if (err) {
        return error_wrap(err, "Failed to save metadata");
    }

    /* Stage metadata.json file */
    err = worktree_stage_file(wt, METADATA_FILE_PATH);
    if (err) {
        return error_wrap(err, "Failed to stage metadata");
    }

    if (removed_count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "Cleaned up metadata for %zu file(s)",
            removed_count
        );
    }

    return NULL;
}

/**
 * Remove files from profile
 */
static error_t *remove_files_from_profile(
    git_repository *repo,
    const config_t *config,
    output_ctx_t *out,
    const char *repo_path,
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    string_array_t *storage_paths = NULL;
    string_array_t *filesystem_paths = NULL;
    string_array_t **other_profiles = NULL;
    size_t multi_profile_count = 0;
    worktree_handle_t *wt = NULL;
    string_array_t *removed_paths = NULL;
    state_t *state = NULL;
    bool profile_enabled = false;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    } else if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Load state for custom prefix resolution (read-only, optional for UX) */
    error_t *state_err = state_load(repo, &state);
    if (state_err) {
        /* Non-fatal: if state loading fails, path resolution degrades gracefully */
        error_free(state_err);
        state = NULL;
    }

    /* Resolve paths */
    err = resolve_paths_to_remove(
        repo, opts->profile, opts->paths, opts->path_count, &storage_paths,
        &filesystem_paths, opts, out, state
    );
    if (err) {
        goto cleanup;
    }

    /* Analyze multi-profile conflicts (critical safety check) */
    bool has_deployed_from_other = false;
    err = analyze_multi_profile_conflicts(
        repo,
        storage_paths,
        filesystem_paths,
        opts->profile,
        state,
        &other_profiles,
        &multi_profile_count,
        &has_deployed_from_other
    );

    if (err) {
        goto cleanup;
    }

    /* Capture profile-enabled status. Keep the state handle alive — the
     * manifest-update phase below upgrades it to a write transaction via
     * state_begin rather than reopening the database. */
    if (state) {
        profile_enabled = state_has_profile(state, opts->profile);
    }

    /* Display multi-profile warnings BEFORE any operation */
    display_multi_profile_warnings(
        out,
        filesystem_paths,
        other_profiles,
        storage_paths->count,
        multi_profile_count,
        has_deployed_from_other,
        opts->profile
    );

    /* Dry run - just show what would be removed */
    if (opts->dry_run) {
        output_print(
            out, OUTPUT_NORMAL, "Would remove from profile '%s':\n",
            opts->profile
        );
        for (size_t i = 0; i < storage_paths->count; i++) {
            output_print(
                out, OUTPUT_NORMAL, "  - %s\n",
                storage_paths->items[i]
            );
        }
        output_print(
            out, OUTPUT_NORMAL, "\nTotal: %zu file%s would be removed from profile\n",
            storage_paths->count,
            storage_paths->count == 1 ? "" : "s"
        );
        if (opts->delete_files) {
            output_print(
                out, OUTPUT_NORMAL, "(Deployed files would be removed on 'dotta apply')\n"
            );
        } else {
            output_print(
                out, OUTPUT_NORMAL, "(Deployed files would be released from management)\n"
            );
        }

        goto cleanup;  /* err is NULL, will return success */
    }

    /* Confirm operation */
    if (!confirm_removal(storage_paths, opts, config, out)) {
        output_print(out, OUTPUT_NORMAL, "Cancelled\n");
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Cleanup multi-profile tracking - done with it */
    free_multi_profile_tracking(other_profiles, storage_paths->count);
    other_profiles = NULL;

    /* Build hook invocation with filesystem paths (resolved by
     * resolve_paths_to_remove). Reached only on non-dry-run: the dry-run
     * branch above early-cleanups before this point, so dry_run is
     * always false here in practice — still passed for honesty. */
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .files      = filesystem_paths->items,
        .file_count = filesystem_paths->count,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-remove hook */
    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /* Create temporary worktree */
    err = worktree_create_temp(repo, &wt);
    if (err) {
        err = error_wrap(err, "Failed to create temporary worktree");
        goto cleanup;
    }

    /* Checkout profile branch */
    err = worktree_checkout_branch(wt, opts->profile);
    if (err) {
        err = error_wrap(
            err, "Failed to checkout profile '%s'",
            opts->profile
        );
        goto cleanup;
    }

    /* Interactive mode requires a terminal for user prompts */
    if (opts->interactive && !isatty(STDIN_FILENO)) {
        err = ERROR(
            ERR_INVALID_ARG,
            "Interactive mode requires a terminal (stdin is not a TTY)"
        );
        goto cleanup;
    }

    /* Remove each file from worktree, tracking which files are actually removed */
    size_t removed_count = 0;
    removed_paths = string_array_new(0);
    if (!removed_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate removed paths array");
        goto cleanup;
    }

    for (size_t i = 0; i < storage_paths->count; i++) {
        const char *storage_path = storage_paths->items[i];

        /* Interactive mode: prompt for each file */
        if (opts->interactive) {
            char prompt[PATH_MAX + 16];
            snprintf(prompt, sizeof(prompt), "Remove %s?", storage_path);
            if (!output_confirm(out, prompt, false)) {
                output_info(out, OUTPUT_VERBOSE, "Skipped: %s", storage_path);
                continue;
            }
        }

        err = remove_file_from_worktree(wt, storage_path, opts, out);
        if (err) {
            /* If interactive or force, continue on error */
            if (opts->interactive || opts->force) {
                output_warning(out, OUTPUT_NORMAL, "%s", error_message(err));
                error_free(err);
                err = NULL;
                continue;
            }
            /* Otherwise, abort */
            goto cleanup;
        }

        err = string_array_push(removed_paths, storage_path);
        if (err) {
            err = error_wrap(err, "Failed to track removed path");
            goto cleanup;
        }
        removed_count++;
    }

    /* Nothing was removed (e.g., all declined in interactive mode) */
    if (removed_count == 0) {
        output_info(out, OUTPUT_NORMAL, "No files removed");
        goto cleanup;
    }

    /* Clean up metadata for actually-removed files only */
    err = cleanup_metadata(wt, removed_paths, out);
    if (err) {
        err = error_wrap(err, "Failed to clean up metadata");
        goto cleanup;
    }

    /* Create commit */
    err = create_removal_commit(wt, opts, removed_paths, config);
    if (err) {
        goto cleanup;
    }

    /* Cleanup worktree */
    worktree_cleanup(&wt);

    /*
     * Architectural note: We do NOT delete files from the filesystem here.
     * This maintains separation of concerns:
     * - `remove` modifies the Git repository (profile branches)
     * - `apply` synchronizes the filesystem (prunes orphaned files by default)
     *
     * This ensures `apply` has global context from all enabled profiles to
     * correctly determine if a file should be removed (avoiding premature
     * deletion of files still needed by higher-priority profiles).
     */

    /* Update manifest if profile is enabled.
     *
     * profile_enabled==true implies state was successfully loaded with a live DB
     * (state_has_profile returns false for NULL/empty state), so
     * state_begin is safe without an additional guard. The handle
     * is reused — no second state_open that would re-prepare
     * statements and re-query enabled_profiles from scratch. */
    size_t manifest_removed_count = 0, manifest_fallback_count = 0;

    if (profile_enabled) {
        /* Open transaction for manifest update */
        error_t *manifest_err = state_begin(state);
        if (manifest_err) {
            /* Non-fatal */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to open transaction for manifest update: %s",
                error_message(manifest_err)
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta status' or 'dotta apply' to resync manifest"
            );
            error_free(manifest_err);
        } else {
            /* Get enabled profiles for manifest sync */
            string_array_t *enabled_profiles = NULL;
            manifest_err = state_get_profiles(state, &enabled_profiles);
            if (manifest_err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to get enabled profiles: %s",
                    error_message(manifest_err)
                );
                output_hint(
                    out, OUTPUT_NORMAL, "Run 'dotta status' or 'dotta apply' to resync"
                );
                error_free(manifest_err);
                state_rollback(state);
            } else {
                /* Update manifest with fallback logic */
                manifest_err = manifest_remove_files(
                    repo,
                    state,
                    opts->profile,
                    removed_paths,
                    enabled_profiles,
                    &manifest_removed_count,
                    &manifest_fallback_count
                );

                if (manifest_err) {
                    /* Non-fatal: Git succeeded, manifest can recover */
                    output_warning(
                        out, OUTPUT_NORMAL, "Manifest update failed: %s",
                        error_message(manifest_err)
                    );
                    output_hint(
                        out, OUTPUT_NORMAL, "Run 'dotta status' or 'dotta apply' to resync"
                    );
                    error_free(manifest_err);
                    state_rollback(state);
                } else {
                    /* manifest_remove_files() marks entries STATE_DELETED.
                     * With --delete-files: leave them for apply to clean up.
                     * Default: release immediately (no apply needed). */
                    if (!opts->delete_files && manifest_removed_count > 0) {
                        state_file_entry_t *delete_entries = NULL;
                        size_t delete_count = 0;
                        error_t *delete_err = state_get_entries_by_profile(
                            state, opts->profile, NULL, &delete_entries, &delete_count
                        );
                        if (!delete_err) {
                            for (size_t di = 0; di < delete_count; di++) {
                                if (delete_entries[di].state &&
                                    strcmp(delete_entries[di].state, STATE_DELETED) == 0) {
                                    error_t *rm_err = state_remove_file(
                                        state, delete_entries[di].filesystem_path
                                    );
                                    if (rm_err) {
                                        error_free(rm_err);
                                    }
                                }
                            }
                            state_free_all_files(delete_entries, delete_count);
                        } else {
                            error_free(delete_err);
                        }
                    }

                    /* Commit transaction */
                    error_t *commit_err = state_commit(state);
                    if (commit_err) {
                        output_warning(
                            out, OUTPUT_NORMAL, "Failed to save manifest updates: %s",
                            error_message(commit_err)
                        );
                        output_hint(
                            out, OUTPUT_NORMAL, "Run 'dotta status' or 'dotta apply' to resync"
                        );
                        error_free(commit_err);
                        state_rollback(state);
                    } else if (manifest_removed_count > 0 || manifest_fallback_count > 0) {
                        if (opts->delete_files) {
                            output_info(
                                out, OUTPUT_VERBOSE,
                                "Manifest: %zu staged for removal, %zu fallback%s",
                                manifest_removed_count, manifest_fallback_count,
                                manifest_fallback_count == 1 ? "" : "s"
                            );
                        } else {
                            output_info(
                                out, OUTPUT_VERBOSE,
                                "Manifest: %zu released, %zu fallback%s",
                                manifest_removed_count, manifest_fallback_count,
                                manifest_fallback_count == 1 ? "" : "s"
                            );
                        }
                    }
                }

                string_array_free(enabled_profiles);
            }
        }
    } else {
        output_info(out, OUTPUT_VERBOSE, "Profile not enabled, Git updated only");
    }

    /* Execute post-remove hook */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* Success */
    if (!opts->quiet) {
        output_success(
            out, OUTPUT_NORMAL, "Removed %zu file%s from profile '%s'",
            removed_count, removed_count == 1 ? "" : "s", opts->profile
        );
        if (opts->delete_files) {
            output_info(
                out, OUTPUT_NORMAL, "Run 'dotta apply' to remove files from filesystem"
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL, "Files released from management (no apply needed)"
            );
        }
        output_newline(out, OUTPUT_NORMAL);
    }

cleanup:
    /* Free all resources in reverse order of allocation */
    if (removed_paths) string_array_free(removed_paths);
    if (wt) worktree_cleanup(&wt);
    if (other_profiles) free_multi_profile_tracking(
        other_profiles, storage_paths->count
    );
    if (filesystem_paths) string_array_free(filesystem_paths);
    if (storage_paths) string_array_free(storage_paths);
    if (state) state_free(state);

    return err;
}

/**
 * Delete entire profile branch
 */
static error_t *delete_profile_branch(
    git_repository *repo,
    const config_t *config,
    output_ctx_t *out,
    const char *repo_path,
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    char *remote_name = NULL;
    upstream_info_t *upstream_info = NULL;
    state_t *state = NULL;
    string_array_t *all_profiles = NULL;
    string_array_t *files = NULL;
    string_array_t *hook_fs_paths = NULL;
    char *hook_custom_prefix = NULL;
    bool performed = false;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    } else if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Check if profile exists */
    if (!profile_exists(repo, opts->profile)) {
        if (!opts->force) {
            err = ERROR(
                ERR_NOT_FOUND, "Profile '%s' does not exist\n"
                "Hint: Use 'dotta list' to see available profiles",
                opts->profile
            );
            goto cleanup;
        }
        /* With --force, just warn and exit */
        output_warning(
            out, OUTPUT_VERBOSE, "Profile '%s' does not exist",
            opts->profile
        );
        goto cleanup;  /* err is NULL, will return success */
    }

    /* SAFETY: Prevent deletion of last remaining profile */
    err = profile_list_all_local(repo, &all_profiles);
    if (err) {
        err = error_wrap(err, "Failed to list profiles");
        goto cleanup;
    }

    if (all_profiles->count <= 1) {
        err = ERROR(
            ERR_INVALID_ARG, "Cannot delete last remaining profile '%s'\n"
            "Hint: A repository must have at least one profile", opts->profile
        );
        goto cleanup;
    }
    string_array_free(all_profiles);
    all_profiles = NULL;

    /* Load profile to count files */
    err = profile_list_files(repo, opts->profile, &files);
    if (err) {
        err = error_wrap(err, "Failed to list files in profile '%s'", opts->profile);
        goto cleanup;
    }

    size_t file_count = files->count;

    /* Dry run */
    if (opts->dry_run) {
        output_print(
            out, OUTPUT_NORMAL, "Would delete profile '%s' (%zu file%s)\n",
            opts->profile, file_count, file_count == 1 ? "" : "s"
        );
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Check for unpushed changes and detect remote
     * Keep remote_name for later use when pushing deletion
     */
    bool has_unpushed = false;
    bool is_local_only = false;

    err = upstream_detect_remote(repo, &remote_name);
    if (!err && remote_name) {
        /* Remote exists - check upstream state */
        err = upstream_analyze_profile(
            repo, remote_name, opts->profile, &upstream_info
        );
        if (!err && upstream_info) {
            /* Determine if profile has actual remote tracking */
            if (upstream_info->state == UPSTREAM_NO_REMOTE) {
                /* Profile exists locally but was never pushed to remote */
                is_local_only = true;
            } else if (upstream_info->state == UPSTREAM_LOCAL_AHEAD ||
                upstream_info->state == UPSTREAM_DIVERGED){
                /* Profile has remote tracking and has unpushed changes */
                has_unpushed = true;
            }
        } else if (err) {
            /* Non-fatal: can't determine upstream state */
            error_free(err);
            err = NULL;
        }
    } else if (err) {
        /* No remote configured - treat as local-only */
        is_local_only = true;
        error_free(err);
        err = NULL;
    }

    /* Warn about unpushed changes (only if profile has remote tracking) */
    if (has_unpushed && !opts->force) {
        output_newline(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "Profile '%s' has unpushed changes!", opts->profile);
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta sync' first to avoid data loss");
        output_newline(out, OUTPUT_NORMAL);
    } else if (is_local_only) {
        /* Inform about local-only status in verbose mode (not a warning) */
        output_info(
            out, OUTPUT_VERBOSE, "Note: Profile '%s' is local-only (not pushed to remote)",
            opts->profile
        );
    }

    /* Free upstream_info after we're done using is_local_only */
    if (upstream_info) {
        upstream_info_free(upstream_info);
        upstream_info = NULL;
    }

    /* Load state for informational queries and enabled check (single read-only load) */
    bool profile_was_enabled = false;
    size_t deployed_count = 0;

    err = state_load(repo, &state);
    if (err) {
        /* Non-fatal */
        error_free(err);
        err = NULL;
        state = NULL;
    }

    if (state) {
        /* Check if profile is enabled */
        profile_was_enabled = state_has_profile(state, opts->profile);

        /* Count deployed files for informational display */
        size_t state_file_count = 0;
        state_file_entry_t *state_files = NULL;
        error_t *state_err = state_get_all_files(
            state, NULL, &state_files, &state_file_count
        );
        if (!state_err && state_files) {
            for (size_t i = 0; i < state_file_count; i++) {
                if (strcmp(state_files[i].profile, opts->profile) == 0) {
                    deployed_count++;
                }
            }
            state_free_all_files(state_files, state_file_count);
        }
        if (state_err) {
            error_free(state_err);
        }

        /* Save custom prefix for hook filesystem path conversion (own a copy
         * because the state handle is about to be freed). */
        const char *pfx = state_peek_profile_prefix(state, opts->profile);
        if (pfx) hook_custom_prefix = strdup(pfx);

        state_free(state);
        state = NULL;
    }

    /* Inform about deployed files (informational, not a warning) */
    if (deployed_count > 0) {
        output_newline(out, OUTPUT_VERBOSE);

        output_info(
            out, OUTPUT_VERBOSE, "Note: Profile '%s' has %zu deployed file%s",
            opts->profile, deployed_count, deployed_count == 1 ? "" : "s"
        );

        if (opts->delete_files) {
            output_info(
                out, OUTPUT_VERBOSE,
                "      These will be removed when you run 'dotta apply'."
            );
        } else {
            output_info(
                out, OUTPUT_VERBOSE,
                "      These files will be released from management."
            );
        }
        output_newline(out, OUTPUT_VERBOSE);
    }

    /* Confirm deletion */
    if (!confirm_profile_deletion(
        opts->profile, file_count, opts, config, out
        )) {
        output_print(out, OUTPUT_NORMAL, "Cancelled\n");
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Convert storage paths to filesystem paths for hook consistency.
     * The file removal path passes filesystem paths to hooks; do the same here. */
    if (files) {
        hook_fs_paths = string_array_new(0);
        if (hook_fs_paths) {
            for (size_t i = 0; i < files->count; i++) {
                char *fs_path = NULL;
                error_t *conv_err = path_from_storage(
                    files->items[i], hook_custom_prefix, &fs_path
                );
                if (!conv_err && fs_path) {
                    string_array_push(hook_fs_paths, fs_path);
                    free(fs_path);
                } else {
                    /* Fall back to storage path (e.g., custom/ without prefix) */
                    string_array_push(hook_fs_paths, files->items[i]);
                    if (conv_err) error_free(conv_err);
                }
            }
        }
    }

    /* Build hook invocation. Prefer filesystem paths (consistent with the
     * file-removal subcommand); fall back to storage paths if synthesis
     * was skipped. Both arrays live until cleanup. */
    const string_array_t *hook_files = hook_fs_paths ? hook_fs_paths : files;
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .files      = hook_files ? hook_files->items : NULL,
        .file_count = hook_files ? hook_files->count : 0,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-remove hook */
    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /*
     * Architectural note: We do NOT delete files from the filesystem here.
     * This maintains separation of concerns - `apply` handles filesystem cleanup.
     * This ensures proper global context when determining file removal.
     */

    /* Update manifest if profile is enabled (BEFORE deleting branch) */

    if (profile_was_enabled) {
        output_print(
            out, OUTPUT_VERBOSE, "Disabling profile in manifest before deletion...\n"
        );

        /* Open transaction */
        state_t *manifest_state = NULL;
        err = state_open(repo, &manifest_state);
        if (err) {
            err = error_wrap(
                err, "Failed to open transaction for profile disable"
            );
            goto cleanup;
        }

        /* Get enabled profiles */
        string_array_t *enabled_profiles = NULL;
        err = state_get_profiles(manifest_state, &enabled_profiles);
        if (err) {
            state_free(manifest_state);
            err = error_wrap(err, "Failed to get enabled profiles");
            goto cleanup;
        }

        /* Build list of remaining profiles (exclude opts->profile) */
        string_array_t *remaining = string_array_new(0);
        if (!remaining) {
            err = ERROR(ERR_MEMORY, "Failed to allocate remaining profiles array");
            state_free(manifest_state);
            string_array_free(enabled_profiles);
            goto cleanup;
        }

        for (size_t i = 0; i < enabled_profiles->count; i++) {
            const char *enabled = enabled_profiles->items[i];
            if (strcmp(enabled, opts->profile) != 0) {
                err = string_array_push(remaining, enabled);
                if (err) {
                    err = error_wrap(err, "Failed to build remaining profiles list");
                    state_free(manifest_state);
                    string_array_free(enabled_profiles);
                    string_array_free(remaining);
                    goto cleanup;
                }
            }
        }

        /* Disable profile (handles fallback logic, marks for removal)
         * CRITICAL: This MUST happen BEFORE git_branch_delete() because
         * manifest_disable_profile() needs to read from Git branches to
         * detect fallbacks */
        err = manifest_disable_profile(
            repo,
            manifest_state,
            opts->profile,
            remaining,
            NULL  /* No stats needed for remove command */
        );

        if (err) {
            err = error_wrap(err, "Failed to disable profile in manifest");
            state_free(manifest_state);
            string_array_free(enabled_profiles);
            string_array_free(remaining);
            goto cleanup;
        }

        /* Remove from enabled_profiles in state */
        err = state_disable_profile(manifest_state, opts->profile);
        if (err) {
            err = error_wrap(err, "Failed to remove profile from state");
            state_free(manifest_state);
            string_array_free(enabled_profiles);
            string_array_free(remaining);
            goto cleanup;
        }

        /* Commit transaction */
        err = state_save(repo, manifest_state);
        state_free(manifest_state);
        string_array_free(enabled_profiles);
        string_array_free(remaining);

        if (err) {
            err = error_wrap(err, "Failed to save manifest updates");
            goto cleanup;
        }

        output_styled(
            out, OUTPUT_VERBOSE, "{green}✓{reset} Cleaned up manifest entries\n"
        );
    }

    /* Delete local branch (NOW safe - manifest already cleaned up) */
    err = gitops_delete_branch(repo, opts->profile);
    if (err) {
        err = error_wrap(err, "Failed to delete profile '%s'", opts->profile);
        goto cleanup;
    }

    performed = true;

    /* Post-deletion: upgrade STATE_INACTIVE entries to STATE_DELETED
     * (or release immediately without --delete-files)
     *
     * After branch deletion, STATE_INACTIVE entries from manifest_disable_profile()
     * (or from a prior profile disable) must be upgraded to STATE_DELETED.
     * Without this, the safety module would RELEASE these files (branch gone +
     * STATE_INACTIVE = irrecoverable), when the user's intent is to delete them.
     *
     * Without --delete-files: remove state entries entirely (release from management).
     *
     * This is a SEPARATE transaction from the earlier manifest_disable_profile
     * transaction — the branch must be deleted first.
     */
    state_t *delete_state = NULL;
    error_t *delete_err = state_open(repo, &delete_state);
    if (!delete_err && delete_state) {
        size_t released_count = 0;

        /* Handle file entries */
        state_file_entry_t *file_entries = NULL;
        size_t entry_count = 0;
        delete_err = state_get_entries_by_profile(
            delete_state, opts->profile, NULL, &file_entries, &entry_count
        );
        if (!delete_err) {
            for (size_t i = 0; i < entry_count; i++) {
                if (!file_entries[i].state ||
                    (strcmp(file_entries[i].state, STATE_INACTIVE) != 0 &&
                    strcmp(file_entries[i].state, STATE_DELETED) != 0)){
                    continue;
                }
                error_t *file_err = NULL;

                if (opts->delete_files) {
                    file_err = state_set_file_state(
                        delete_state, file_entries[i].filesystem_path, STATE_DELETED
                    );
                } else {
                    file_err = state_remove_file(
                        delete_state, file_entries[i].filesystem_path
                    );
                }
                if (file_err) {
                    error_free(file_err);
                } else {
                    released_count++;
                }
            }
            state_free_all_files(file_entries, entry_count);
        } else {
            error_free(delete_err);
            delete_err = NULL;
        }

        /* Handle directory entries */
        state_directory_entry_t *dir_entries = NULL;
        size_t dir_count = 0;
        delete_err = state_get_directories_by_profile(
            delete_state, opts->profile, NULL, &dir_entries, &dir_count
        );
        if (!delete_err) {
            for (size_t i = 0; i < dir_count; i++) {
                if (!dir_entries[i].state ||
                    (strcmp(dir_entries[i].state, STATE_INACTIVE) != 0 &&
                    strcmp(dir_entries[i].state, STATE_DELETED) != 0)){
                    continue;
                }
                error_t *dir_err = NULL;
                if (opts->delete_files) {
                    dir_err = state_set_directory_state(
                        delete_state, dir_entries[i].filesystem_path, STATE_DELETED
                    );
                } else {
                    dir_err = state_remove_directory(
                        delete_state, dir_entries[i].filesystem_path
                    );
                }
                if (dir_err) {
                    error_free(dir_err);
                }
            }
            state_free_all_directories(dir_entries, dir_count);
        } else {
            error_free(delete_err);
            delete_err = NULL;
        }

        /* Commit transaction */
        delete_err = state_save(repo, delete_state);
        if (delete_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to update state after branch deletion: %s",
                error_message(delete_err)
            );
            error_free(delete_err);
        } else if (released_count > 0) {
            if (opts->delete_files) {
                output_info(
                    out, OUTPUT_VERBOSE, "%zu file%s staged for removal",
                    released_count, released_count == 1 ? "" : "s"
                );
            } else {
                output_info(
                    out, OUTPUT_VERBOSE, "%zu file%s released from management",
                    released_count, released_count == 1 ? "" : "s"
                );
            }
        }

        state_free(delete_state);
    } else if (delete_err) {
        /* Non-fatal: safety module will handle this conservatively */
        output_warning(
            out, OUTPUT_NORMAL, "Failed to open state for post-deletion update: %s",
            error_message(delete_err)
        );
        error_free(delete_err);
    }

    /* Push deletion to remote if remote exists
     * This is critical for sync to work - other repos need to know the branch was deleted
     */
    if (remote_name && !is_local_only) {
        output_info(
            out, OUTPUT_NORMAL, "Pushing profile deletion to remote '%s'...",
            remote_name
        );

        /* We don't have a credential context here, but gitops_delete_remote_branch will handle NULL */
        err = gitops_delete_remote_branch(repo, remote_name, opts->profile, NULL);
        if (err) {
            /* Non-fatal: warn but don't fail the whole operation
             * The local branch is already deleted, so this is just about syncing
             */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to push deletion to remote: %s",
                error_message(err)
            );
            output_info(
                out, OUTPUT_NORMAL,
                "         The profile was deleted locally, but sync could fail."
            );
            output_info(
                out, OUTPUT_NORMAL,
                "         You can manually push the deletion with: git push %s :%s",
                remote_name, opts->profile
            );
            error_free(err);
            err = NULL;
        } else {
            output_info(out, OUTPUT_NORMAL, "Profile deletion pushed to remote");
        }

        free(remote_name);
        remote_name = NULL;
    }

    /*
     * Architectural note: State entries were upgraded to STATE_DELETED (or
     * released without --delete-files) in the post-deletion block above.
     * Final filesystem cleanup for STATE_DELETED entries happens on `apply`.
     */

    /* Execute post-remove hook */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* Success message (only on actual deletion, not dry-run/cancel/error) */
    if (performed && !opts->quiet) {
        output_success(out, OUTPUT_NORMAL, "Profile '%s' deleted", opts->profile);

        if (opts->delete_files) {
            output_info(
                out, OUTPUT_NORMAL,
                "Run 'dotta apply' to remove deployed files from filesystem"
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL,
                "Files released from management (no apply needed)"
            );
        }
        output_newline(out, OUTPUT_NORMAL);
    }

cleanup:
    /* Free all resources in reverse order of allocation */
    if (hook_fs_paths) string_array_free(hook_fs_paths);
    if (hook_custom_prefix) free(hook_custom_prefix);
    if (state) state_free(state);
    if (upstream_info) upstream_info_free(upstream_info);
    if (remote_name) free(remote_name);
    if (files) string_array_free(files);
    if (all_profiles) string_array_free(all_profiles);

    return err;
}

/**
 * Remove command implementation
 */
error_t *cmd_remove(const dotta_ctx_t *ctx, const cmd_remove_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    const config_t *config = ctx->config;
    output_ctx_t *out = ctx->out;

    /* Validate options */
    error_t *err = validate_options(opts);
    if (err) {
        return err;
    }

    /* Branch: Delete profile or remove files */
    if (opts->delete_profile) {
        return delete_profile_branch(repo, config, out, ctx->repo_path, opts);
    }

    return remove_files_from_profile(repo, config, out, ctx->repo_path, opts);
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `profile` and `paths[]`.
 *
 * Legacy-compatible rules:
 *   1. -p/--profile was given: every positional is a path.
 *   2. -p not given: first positional is the profile, rest are paths.
 *   3. --delete-profile: paths must be empty (mutually exclusive).
 *   4. Without --delete-profile: at least one path is required.
 */
static error_t *remove_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_remove_options_t *o = opts_v;

    if (o->profile != NULL) {
        o->paths = o->positional_args;
        o->path_count = o->positional_count;
    } else {
        if (o->positional_count == 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "profile name is required (as first positional or via -p)"
            );
        }
        o->profile = o->positional_args[0];
        o->paths = o->positional_args + 1;
        o->path_count = o->positional_count - 1;
    }

    if (o->delete_profile && o->path_count > 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "cannot specify paths when using --delete-profile"
        );
    }
    if (!o->delete_profile && o->path_count == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "at least one path is required (or use --delete-profile)"
        );
    }
    return NULL;
}

static error_t *remove_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_remove(ctx, (const cmd_remove_options_t *) opts_v);
}

static const args_opt_t remove_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",         "<name>",
        cmd_remove_options_t,profile,
        "Profile name (alternative to positional)"
    ),
    ARGS_STRING(
        "m message",         "<msg>",
        cmd_remove_options_t,message,
        "Commit message"
    ),
    ARGS_FLAG(
        "delete-profile",
        cmd_remove_options_t,delete_profile,
        "Delete the entire profile branch"
    ),
    ARGS_FLAG(
        "delete-files",
        cmd_remove_options_t,delete_files,
        "Stage deployed copies for removal on next apply"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_remove_options_t,dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG(
        "f force",
        cmd_remove_options_t,force,
        "Skip confirmation prompts"
    ),
    ARGS_FLAG(
        "i interactive",
        cmd_remove_options_t,interactive,
        "Prompt for each file"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_remove_options_t,verbose,
        "Verbose output"
    ),
    ARGS_FLAG(
        "q quiet",
        cmd_remove_options_t,quiet,
        "Minimal output"
    ),
    /* <profile> [<path>...]. -p promotes positionals to all-paths. */
    ARGS_POSITIONAL_RAW(
        cmd_remove_options_t,positional_args, positional_count,
        0,                   0
    ),
    ARGS_END,
};

const args_command_t spec_remove = {
    .name        = "remove",
    .summary     = "Remove files from a profile or delete profile",
    .usage       =
        "%s remove [options] <profile> <path>...\n"
        "   or: %s remove [options] <profile> --delete-profile\n"
        "   or: %s remove [options] --profile <name> <path>...",
    .description =
        "Untrack files from a profile, optionally scheduling removal of\n"
        "the deployed copies, or delete the profile branch outright.\n",
    .notes       =
        "Operation Modes:\n"
        "  (default)           Remove files from the profile branch. Deployed\n"
        "                      copies are released from management and stay\n"
        "                      on the filesystem untouched.\n"
        "  --delete-files      Same as default, plus stage the deployed\n"
        "                      copies for removal on the next '%s apply'.\n"
        "  --delete-profile    Delete the entire profile branch. No paths\n"
        "                      may be given; cannot be combined with\n"
        "                      --delete-files.\n",
    .examples    =
        "  %s remove global ~/.bashrc                  # Untrack, keep on disk\n"
        "  %s remove darwin ~/.config/nvim -n          # Preview removal\n"
        "  %s remove darwin ~/.config/nvim --delete-files  # Remove on apply\n"
        "  %s remove staging --delete-profile          # Delete whole profile\n",
    .epilogue    =
        "See also:\n"
        "  %s profile disable <name>  # Stop deploying without deleting\n"
        "  %s apply                   # Carry out staged file removals\n",
    .opts_size   = sizeof(cmd_remove_options_t),
    .opts        = remove_opts,
    .post_parse  = remove_post_parse,
    .user_data   = &dotta_ext_required,
    .dispatch    = remove_dispatch,
};
