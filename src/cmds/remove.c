/**
 * remove.c - Remove files from profiles or delete profiles
 */

#include "remove.h"

#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "core/upstream.h"
#include "infra/path.h"
#include "infra/worktree.h"
#include "utils/array.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/hooks.h"
#include "utils/output.h"
#include "utils/string.h"

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
    const char *profile_name,
    char **input_paths,
    size_t path_count,
    string_array_t **storage_paths_out,
    string_array_t **filesystem_paths_out,
    const cmd_remove_options_t *opts,
    output_ctx_t *out,
    state_t *state
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(input_paths);
    CHECK_NULL(storage_paths_out);
    CHECK_NULL(filesystem_paths_out);
    CHECK_NULL(opts);

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    string_array_t *storage_paths = NULL;
    string_array_t *filesystem_paths = NULL;
    profile_t *profile = NULL;
    string_array_t *profile_files = NULL;
    hashmap_t *profile_files_map = NULL;
    hashmap_t *prefix_map = NULL;
    const char *custom_prefix = NULL;

    /* Load prefix map for custom/ path resolution (optional, improves UX) */
    if (state) {
        error_t *map_err = state_get_prefix_map(state, &prefix_map);
        if (!map_err && prefix_map) {
            custom_prefix = (const char *) hashmap_get(prefix_map, profile_name);
        } else if (map_err) {
            /* Non-fatal: if prefix map loading fails,
             * just degrade to showing storage paths */
            error_free(map_err);
        }
    }

    /* Allocate arrays */
    storage_paths = string_array_create();
    filesystem_paths = string_array_create();
    if (!storage_paths || !filesystem_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate path arrays");
        goto cleanup;
    }

    /* Load profile to check file existence */
    err = profile_load(repo, profile_name, &profile);
    if (err) {
        err = error_wrap(
            err, "Failed to load profile '%s'",
            profile_name
        );
        goto cleanup;
    }

    /* Get list of files in profile */
    err = profile_list_files(repo, profile, &profile_files);
    if (err) {
        err = error_wrap(err, "Failed to list files in profile");
        goto cleanup;
    }

    /* Build hashmap index for O(1) lookups */
    profile_files_map = hashmap_create(string_array_size(profile_files));
    if (!profile_files_map) {
        err = ERROR(ERR_MEMORY, "Failed to create profile files index");
        goto cleanup;
    }

    for (size_t i = 0; i < string_array_size(profile_files); i++) {
        const char *file = string_array_get(profile_files, i);
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

        /* Resolve input path to storage format (flexible mode - file need not exist)
         *
         * Note: No custom prefix context available for remove command - users must use
         * storage format (custom/etc/nginx.conf) for custom/ paths */
        err = path_resolve_input(input_path, false, NULL, 0, &storage_path);
        if (err) {
            if (!opts->force) {
                goto cleanup;
            }
            /* With --force, skip this path */
            if (opts->verbose && out) {
                output_warning(
                    out, "Skipping invalid path '%s': %s",
                    input_path, error_message(err)
                );
            }
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
        for (size_t j = 0; j < string_array_size(profile_files); j++) {
            const char *profile_file = string_array_get(profile_files, j);

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
                        if ((opts->verbose || !opts->force) && out) {
                            output_warning(
                                out, "Failed to resolve filesystem path for '%s': %s",
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
                    error_storage_path, profile_name, profile_name
                );
                goto cleanup;
            }
            /* With --force, warn and skip */
            if (opts->verbose && out) {
                output_warning(
                    out, "File '%s' not found in profile, skipping",
                    storage_path
                );
            }
        }

        free(storage_path);
        free(canonical);
    }

    /* Check if we found any files */
    if (string_array_size(storage_paths) == 0) {
        err = ERROR(
            ERR_NOT_FOUND, "No files found to remove from profile '%s'",
            profile_name
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
    if (prefix_map) hashmap_free(prefix_map, free);
    if (profile_files_map) hashmap_free(profile_files_map, NULL);
    if (profile_files) string_array_free(profile_files);
    if (profile) profile_free(profile);
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
    git_index *index = NULL;
    err = worktree_get_index(wt, &index);
    if (err) {
        return error_wrap(err, "Failed to get worktree index");
    }

    int git_err = git_index_remove_bypath(index, storage_path);
    if (git_err < 0) {
        git_index_free(index);
        return error_from_git(git_err);
    }

    git_err = git_index_write(index);
    git_index_free(index);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    if (opts->verbose && out) {
        output_info(out, "Removed: %s", storage_path);
    }

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
    size_t file_count = string_array_size(storage_paths);

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
        const char *storage_path = string_array_get(storage_paths, i);
        const char *filesystem_path = string_array_get(filesystem_paths, i);

        /* Lookup profiles containing this file - O(1) */
        string_array_t *indexed_profiles = hashmap_get(profile_index, storage_path);

        if (indexed_profiles && string_array_size(indexed_profiles) > 0) {
            /* Create a copy for the output (index owns the original) */
            other_profiles[i] = string_array_create();
            if (other_profiles[i]) {
                for (size_t j = 0; j < string_array_size(indexed_profiles); j++) {
                    string_array_push(other_profiles[i], string_array_get(indexed_profiles, j));
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
    hashmap_free(profile_index, string_array_free);

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
    if (!out || multi_profile_count == 0) {
        return;
    }

    output_newline(out);
    output_section(out, "Multi-profile file warning");
    output_warning(
        out, "%zu file%s exist%s in multiple profiles:",
        multi_profile_count,
        multi_profile_count == 1 ? "" : "s",
        multi_profile_count == 1 ? "s" : ""
    );

    /* Display each multi-profile file */
    for (size_t i = 0; i < file_count; i++) {
        if (!other_profiles[i] || string_array_size(other_profiles[i]) == 0) {
            continue;
        }

        const char *fs_path = string_array_get(filesystem_paths, i);
        output_styled(
            out, OUTPUT_NORMAL, "  {yellow}%s{reset} also in:",
            fs_path
        );

        for (size_t j = 0; j < string_array_size(other_profiles[i]); j++) {
            output_styled(
                out, OUTPUT_NORMAL, " {cyan}%s{reset}",
                string_array_get(other_profiles[i], j)
            );
        }
        output_newline(out);
    }

    /* Explain implications */
    output_newline(out);
    output_info(
        out, "These files will be removed only from profile '%s'.",
        current_profile
    );

    if (has_deployed_from_other) {
        output_warning(
            out, "Some files are currently deployed from other profiles."
        );
        output_info(
            out, "Those files will remain on the filesystem."
        );
    } else {
        output_info(
            out, "Files deployed from '%s' will remain until 'dotta apply'.",
            current_profile
        );
    }
    output_newline(out);
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
    const dotta_config_t *config,
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

    size_t count = string_array_size(storage_paths);

    /* Check config threshold */
    size_t threshold = 5; /* Default threshold */
    if (config && config->confirm_destructive) {
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
    const char *profile_name,
    size_t file_count,
    bool is_auto_detected,
    const cmd_remove_options_t *opts,
    const dotta_config_t *config,
    output_ctx_t *out
) {
    if (!profile_name || !out) {
        return false;
    }

    /* Skip confirmation if --force */
    if (opts->force) {
        return true;
    }

    /* Extra warning for auto-detected profiles */
    if (is_auto_detected) {
        output_warning(
            out, "'%s' is an auto-detected profile",
            profile_name
        );
    }

    output_newline(out);
    output_warning(
        out, "This will delete profile '%s' (%zu file%s)",
        profile_name, file_count, file_count == 1 ? "" : "s"
    );
    if (opts->delete_files) {
        output_info(
            out, "         Deployed files will be removed when you run 'dotta apply'."
        );
    } else {
        output_info(
            out, "         Deployed files will be released from management."
        );
    }
    output_newline(out);

    bool confirmed = output_confirm_destructive(out, config, "Continue?", opts->force);

    return confirmed;
}

/**
 * Create commit for removal
 */
static error_t *create_removal_commit(
    git_repository *repo,
    worktree_handle_t *wt,
    const cmd_remove_options_t *opts,
    const string_array_t *removed_paths,
    const dotta_config_t *config
) {
    CHECK_NULL(repo);
    CHECK_NULL(wt);
    CHECK_NULL(opts);
    CHECK_NULL(removed_paths);

    git_repository *wt_repo = worktree_get_repo(wt);
    if (!wt_repo) {
        return ERROR(ERR_INTERNAL, "Worktree repository is NULL");
    }

    /* Get index tree */
    git_index *index = NULL;
    error_t *err = worktree_get_index(wt, &index);
    if (err) {
        return error_wrap(err, "Failed to get worktree index");
    }

    git_oid tree_oid;
    int git_err = git_index_write_tree(&tree_oid, index);
    git_index_free(index);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_tree *tree = NULL;
    git_err = git_tree_lookup(&tree, wt_repo, &tree_oid);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

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
        git_tree_free(tree);
        return ERROR(ERR_MEMORY, "Failed to build commit message");
    }

    /* Create commit */
    git_oid commit_oid;
    err = gitops_create_commit(
        wt_repo,
        opts->profile,
        tree,
        message,
        &commit_oid
    );

    free(message);
    git_tree_free(tree);

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
    const cmd_remove_options_t *opts,
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
    for (size_t i = 0; i < string_array_size(removed_paths); i++) {
        const char *storage_path = string_array_get(removed_paths, i);

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

            if (opts->verbose && out) {
                output_info(
                    out, "Removed metadata: %s",
                    storage_path
                );
            }
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
        string_array_t *orphaned_dirs = string_array_create();
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
        for (size_t i = 0; i < string_array_size(orphaned_dirs); i++) {
            err = metadata_remove_item(metadata, string_array_get(orphaned_dirs, i));
            if (err) {
                string_array_free(orphaned_dirs);
                free(files);
                free(directories);
                metadata_free(metadata);
                return error_wrap(err, "Failed to remove orphaned directory metadata");
            }

            removed_count++;

            if (opts->verbose && out) {
                output_info(
                    out, "Removed orphaned directory metadata: %s",
                    string_array_get(orphaned_dirs, i)
                );
            }
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
    git_index *index = NULL;
    err = worktree_get_index(wt, &index);
    if (err) {
        return error_wrap(err, "Failed to get worktree index");
    }

    int git_err = git_index_add_bypath(index, METADATA_FILE_PATH);
    if (git_err < 0) {
        git_index_free(index);
        return error_from_git(git_err);
    }

    git_err = git_index_write(index);
    git_index_free(index);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    if (opts->verbose && out && removed_count > 0) {
        output_info(
            out, "Cleaned up metadata for %zu file(s)",
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
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;
    string_array_t *storage_paths = NULL;
    string_array_t *filesystem_paths = NULL;
    string_array_t **other_profiles = NULL;
    size_t multi_profile_count = 0;
    char *repo_dir = NULL;
    hook_context_t *hook_ctx = NULL;
    worktree_handle_t *wt = NULL;
    string_array_t *removed_paths = NULL;
    state_t *state = NULL;
    bool profile_enabled = false;

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue without config */
        error_free(err);
        err = NULL;
        config = config_create_default();
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

    /* Capture profile-enabled status and release read-only state early.
     * State was only needed for path resolution and conflict analysis above. */
    if (state) {
        profile_enabled = state_has_profile(state, opts->profile);
        state_free(state);
        state = NULL;
    }

    /* Display multi-profile warnings BEFORE any operation */
    display_multi_profile_warnings(
        out,
        filesystem_paths,
        other_profiles,
        string_array_size(storage_paths),
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
        for (size_t i = 0; i < string_array_size(storage_paths); i++) {
            output_print(
                out, OUTPUT_NORMAL, "  - %s\n",
                string_array_get(storage_paths, i)
            );
        }
        output_print(
            out, OUTPUT_NORMAL, "\nTotal: %zu file%s would be removed from profile\n",
            string_array_size(storage_paths),
            string_array_size(storage_paths) == 1 ? "" : "s"
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
    free_multi_profile_tracking(other_profiles, string_array_size(storage_paths));
    other_profiles = NULL;

    /* Get repository directory for hooks */
    err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        goto cleanup;
    }

    /* Execute pre-remove hook */
    hook_ctx = hook_context_create(repo_dir, "remove", opts->profile);
    if (hook_ctx) {
        /* Add paths to hook context */
        err = hook_context_add_files(
            hook_ctx, filesystem_paths->items, filesystem_paths->count
        );
        if (err) goto cleanup;

        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_PRE_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - abort operation */
            if (hook_result && hook_result->output && hook_result->output[0] && out) {
                output_print(
                    out, OUTPUT_NORMAL, "Hook output:\n%s\n",
                    hook_result->output
                );
            }
            hook_result_free(hook_result);
            err = error_wrap(err, "Pre-remove hook failed");
            goto cleanup;
        }
        hook_result_free(hook_result);
    }

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
    removed_paths = string_array_create();
    if (!removed_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate removed paths array");
        goto cleanup;
    }

    for (size_t i = 0; i < string_array_size(storage_paths); i++) {
        const char *storage_path = string_array_get(storage_paths, i);

        /* Interactive mode: prompt for each file */
        if (opts->interactive) {
            char prompt[PATH_MAX + 16];
            snprintf(prompt, sizeof(prompt), "Remove %s?", storage_path);
            if (!output_confirm(out, prompt, false)) {
                if (opts->verbose) {
                    output_info(out, "Skipped: %s", storage_path);
                }
                continue;
            }
        }

        err = remove_file_from_worktree(wt, storage_path, opts, out);
        if (err) {
            /* If interactive or force, continue on error */
            if (opts->interactive || opts->force) {
                if (out) {
                    output_warning(out, "%s", error_message(err));
                }
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
        if (out) {
            output_info(out, "No files removed");
        }
        goto cleanup;
    }

    /* Clean up metadata for actually-removed files only */
    err = cleanup_metadata(wt, removed_paths, opts, out);
    if (err) {
        err = error_wrap(err, "Failed to clean up metadata");
        goto cleanup;
    }

    /* Create commit */
    err = create_removal_commit(repo, wt, opts, removed_paths, config);
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

    /* Update manifest if profile is enabled */
    size_t manifest_removed_count = 0, manifest_fallback_count = 0;

    if (profile_enabled) {
        /* Open transaction for manifest update */
        state_t *update_state = NULL;
        err = state_load_for_update(repo, &update_state);
        if (err) {
            /* Non-fatal */
            if (out) {
                output_warning(
                    out, "Failed to open transaction for manifest update: %s",
                    error_message(err)
                );
                output_hint(out, "Run 'dotta status' or 'dotta apply' to resync manifest");
            }
            error_free(err);
            err = NULL;
        } else {
            /* Get enabled profiles for manifest sync */
            string_array_t *enabled_profiles = NULL;
            err = state_get_profiles(update_state, &enabled_profiles);
            if (err) {
                if (out) {
                    output_warning(
                        out, "Failed to get enabled profiles: %s",
                        error_message(err)
                    );
                    output_hint(
                        out, "Run 'dotta status' or 'dotta apply' to resync manifest"
                    );
                }
                error_free(err);
                err = NULL;
                state_free(update_state);
            } else {
                /* Update manifest with fallback logic */
                error_t *manifest_err = manifest_remove_files(
                    repo,
                    update_state,
                    opts->profile,
                    removed_paths,
                    enabled_profiles,
                    &manifest_removed_count,
                    &manifest_fallback_count
                );

                if (manifest_err) {
                    /* Non-fatal: Git succeeded, manifest can recover */
                    if (out) {
                        output_warning(
                            out, "Manifest update failed: %s",
                            error_message(manifest_err)
                        );
                        output_hint(
                            out, "Run 'dotta status' or 'dotta apply' to resync manifest"
                        );
                    }
                    error_free(manifest_err);
                } else {
                    /* manifest_remove_files() marks entries STATE_DELETED.
                     * With --delete-files: leave them for apply to clean up.
                     * Default: release immediately (no apply needed). */
                    if (!opts->delete_files && manifest_removed_count > 0) {
                        state_file_entry_t *delete_entries = NULL;
                        size_t delete_count = 0;
                        error_t *delete_err = state_get_entries_by_profile(
                            update_state, opts->profile, &delete_entries, &delete_count
                        );
                        if (!delete_err) {
                            for (size_t di = 0; di < delete_count; di++) {
                                if (delete_entries[di].state &&
                                    strcmp(delete_entries[di].state, STATE_DELETED) == 0) {
                                    error_t *rm_err = state_remove_file(
                                        update_state, delete_entries[di].filesystem_path
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
                    err = state_save(repo, update_state);
                    if (err) {
                        if (out) {
                            output_warning(
                                out, "Failed to save manifest updates: %s",
                                error_message(err)
                            );
                            output_hint(
                                out, "Run 'dotta status' or 'dotta apply' to resync manifest"
                            );
                        }
                        error_free(err);
                        err = NULL;
                    } else {
                        /* Display manifest sync results */
                        if ((manifest_removed_count > 0 || manifest_fallback_count > 0) &&
                            out && opts->verbose){
                            if (opts->delete_files) {
                                output_info(
                                    out, "Manifest: %zu staged for removal, %zu fallback%s",
                                    manifest_removed_count, manifest_fallback_count,
                                    manifest_fallback_count == 1 ? "" : "s"
                                );
                            } else {
                                output_info(
                                    out, "Manifest: %zu released, %zu fallback%s",
                                    manifest_removed_count, manifest_fallback_count,
                                    manifest_fallback_count == 1 ? "" : "s"
                                );
                            }
                        }
                    }
                }

                state_free(update_state);
                string_array_free(enabled_profiles);
            }
        }
    } else if (opts->verbose && out) {
        output_info(out, "Profile not enabled, Git updated only");
    }

    /* Execute post-remove hook */
    if (hook_ctx && !opts->dry_run) {
        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_POST_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - warn but don't abort (files already removed) */
            if (out) {
                output_warning(
                    out, "Post-remove hook failed: %s",
                    error_message(err)
                );

                if (hook_result && hook_result->output && hook_result->output[0]) {
                    output_print(
                        out, OUTPUT_NORMAL, "Hook output:\n%s\n",
                        hook_result->output
                    );
                }
            }
            error_free(err);
            err = NULL;
        }
        hook_result_free(hook_result);
    }

    /* Success */
    if (!opts->quiet) {
        output_success(
            out, "Removed %zu file%s from profile '%s'",
            removed_count, removed_count == 1 ? "" : "s", opts->profile
        );
        if (opts->delete_files) {
            output_info(
                out, "Run 'dotta apply' to remove files from filesystem"
            );
        } else {
            output_info(
                out, "Files released from management (no apply needed)"
            );
        }
        output_newline(out);
    }

cleanup:
    /* Free all resources in reverse order of allocation */
    if (removed_paths) string_array_free(removed_paths);
    if (wt) worktree_cleanup(&wt);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (repo_dir) free(repo_dir);
    if (other_profiles) free_multi_profile_tracking(
        other_profiles, string_array_size(storage_paths)
    );
    if (filesystem_paths) string_array_free(filesystem_paths);
    if (storage_paths) string_array_free(storage_paths);
    if (state) state_free(state);
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}

/**
 * Delete entire profile branch
 */
static error_t *delete_profile_branch(
    git_repository *repo,
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;
    char *remote_name = NULL;
    upstream_info_t *upstream_info = NULL;
    state_t *state = NULL;
    char *repo_dir = NULL;
    hook_context_t *hook_ctx = NULL;
    profile_list_t *all_profiles = NULL;
    profile_t *profile = NULL;
    string_array_t *files = NULL;
    string_array_t *hook_fs_paths = NULL;
    char *hook_custom_prefix = NULL;
    bool performed = false;

    /* Load config first */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal */
        error_free(err);
        err = NULL;
        config = config_create_default();
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
        if (opts->verbose) {
            output_warning(
                out, "Profile '%s' does not exist",
                opts->profile
            );
        }
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
    profile_list_free(all_profiles);
    all_profiles = NULL;

    /* Load profile to count files */
    err = profile_load(repo, opts->profile, &profile);
    if (err) {
        err = error_wrap(err, "Failed to load profile '%s'", opts->profile);
        goto cleanup;
    }

    err = profile_list_files(repo, profile, &files);
    if (err) {
        err = error_wrap(err, "Failed to list files in profile");
        goto cleanup;
    }

    size_t file_count = string_array_size(files);
    bool is_auto_detected = profile->auto_detected;

    /* Keep files alive for hook context; freed in cleanup */
    profile_free(profile);
    profile = NULL;

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
        output_newline(out);
        output_warning(out, "Profile '%s' has unpushed changes!", opts->profile);
        output_info(out, "         Deleting now may result in data loss.");
        output_info(out, "         Consider running 'dotta sync' first.");
        output_newline(out);
    } else if (is_local_only && opts->verbose) {
        /* Inform about local-only status in verbose mode (not a warning) */
        output_info(
            out, "Note: Profile '%s' is local-only (not pushed to remote)",
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
            state, &state_files, &state_file_count
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

        /* Save custom prefix for hook filesystem path conversion */
        hashmap_t *pfx_map = NULL;
        error_t *pfx_err = state_get_prefix_map(state, &pfx_map);

        if (!pfx_err && pfx_map) {
            const char *pfx = hashmap_get(pfx_map, opts->profile);
            if (pfx) hook_custom_prefix = strdup(pfx);
            hashmap_free(pfx_map, free);
        } else if (pfx_err) {
            error_free(pfx_err);
        }

        state_free(state);
        state = NULL;
    }

    /* Inform about deployed files (informational, not a warning) */
    if (deployed_count > 0 && opts->verbose) {
        output_newline(out);

        output_info(
            out, "Note: Profile '%s' has %zu deployed file%s",
            opts->profile, deployed_count, deployed_count == 1 ? "" : "s"
        );

        if (opts->delete_files) {
            output_info(out, "      These will be removed when you run 'dotta apply'.");
        } else {
            output_info(out, "      These files will be released from management.");
        }
        output_newline(out);
    }

    /* Confirm deletion */
    if (!confirm_profile_deletion(
        opts->profile, file_count, is_auto_detected, opts, config, out
        )) {
        output_print(out, OUTPUT_NORMAL, "Cancelled\n");
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Get repository directory for hooks */
    err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        goto cleanup;
    }

    /* Convert storage paths to filesystem paths for hook consistency.
     * The file removal path passes filesystem paths to hooks; do the same here. */
    if (files) {
        hook_fs_paths = string_array_create();
        if (hook_fs_paths) {
            for (size_t i = 0; i < string_array_size(files); i++) {
                char *fs_path = NULL;
                error_t *conv_err = path_from_storage(
                    string_array_get(files, i), hook_custom_prefix, &fs_path
                );
                if (!conv_err && fs_path) {
                    string_array_push(hook_fs_paths, fs_path);
                    free(fs_path);
                } else {
                    /* Fall back to storage path (e.g., custom/ without prefix) */
                    string_array_push(hook_fs_paths, string_array_get(files, i));
                    if (conv_err) error_free(conv_err);
                }
            }
        }
    }

    /* Execute pre-remove hook */
    hook_ctx = hook_context_create(repo_dir, "remove", opts->profile);
    if (hook_ctx) {
        /* Pass filesystem paths to hook (consistent with file removal hooks) */
        string_array_t *hook_files = hook_fs_paths ? hook_fs_paths : files;
        if (hook_files) {
            err = hook_context_add_files(hook_ctx, hook_files->items, hook_files->count);
            if (err) goto cleanup;
        }

        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_PRE_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - abort operation */
            if (hook_result && hook_result->output && hook_result->output[0]) {
                output_print(
                    out, OUTPUT_NORMAL, "Hook output:\n%s\n",
                    hook_result->output
                );
            }
            hook_result_free(hook_result);
            err = error_wrap(err, "Pre-remove hook failed");
            goto cleanup;
        }
        hook_result_free(hook_result);
    }

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
        err = state_load_for_update(repo, &manifest_state);
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
        string_array_t *remaining = string_array_create();
        if (!remaining) {
            err = ERROR(ERR_MEMORY, "Failed to allocate remaining profiles array");
            state_free(manifest_state);
            string_array_free(enabled_profiles);
            goto cleanup;
        }

        for (size_t i = 0; i < string_array_size(enabled_profiles); i++) {
            const char *enabled = string_array_get(enabled_profiles, i);
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
    error_t *delete_err = state_load_for_update(repo, &delete_state);
    if (!delete_err && delete_state) {
        size_t released_count = 0;

        /* Handle file entries */
        state_file_entry_t *file_entries = NULL;
        size_t entry_count = 0;
        delete_err = state_get_entries_by_profile(
            delete_state, opts->profile, &file_entries, &entry_count
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
            delete_state, opts->profile, &dir_entries, &dir_count
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
                out, "Failed to update state after branch deletion: %s",
                error_message(delete_err)
            );
            error_free(delete_err);
        } else if (released_count > 0 && opts->verbose) {
            if (opts->delete_files) {
                output_info(
                    out, "%zu file%s staged for removal",
                    released_count, released_count == 1 ? "" : "s"
                );
            } else {
                output_info(
                    out, "%zu file%s released from management",
                    released_count, released_count == 1 ? "" : "s"
                );
            }
        }

        state_free(delete_state);
    } else if (delete_err) {
        /* Non-fatal: safety module will handle this conservatively */
        output_warning(
            out, "Failed to open state for post-deletion update: %s",
            error_message(delete_err)
        );
        error_free(delete_err);
    }

    /* Push deletion to remote if remote exists
     * This is critical for sync to work - other repos need to know the branch was deleted
     */
    if (remote_name && !is_local_only) {
        output_info(
            out, "Pushing profile deletion to remote '%s'...",
            remote_name
        );

        /* We don't have a credential context here, but gitops_delete_remote_branch will handle NULL */
        err = gitops_delete_remote_branch(repo, remote_name, opts->profile, NULL);
        if (err) {
            /* Non-fatal: warn but don't fail the whole operation
             * The local branch is already deleted, so this is just about syncing
             */
            output_warning(
                out, "Failed to push deletion to remote: %s",
                error_message(err)
            );
            output_info(
                out, "         The profile was deleted locally, but sync could fail."
            );
            output_info(
                out, "         You can manually push the deletion with: git push %s :%s",
                remote_name, opts->profile
            );
            error_free(err);
            err = NULL;
        } else {
            output_info(out, "Profile deletion pushed to remote");
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
    if (hook_ctx && !opts->dry_run) {
        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_POST_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - warn but don't abort (profile already deleted) */
            output_warning(out, "Post-remove hook failed: %s", error_message(err));
            if (hook_result && hook_result->output && hook_result->output[0]) {
                output_print(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
            }
            error_free(err);
            err = NULL;
        }
        hook_result_free(hook_result);
    }

    /* Success message (only on actual deletion, not dry-run/cancel/error) */
    if (performed && !opts->quiet) {
        output_success(
            out, "Profile '%s' deleted",
            opts->profile
        );

        if (opts->delete_files) {
            output_info(
                out, "Run 'dotta apply' to remove deployed files from filesystem"
            );
        } else {
            output_info(
                out, "Files released from management (no apply needed)"
            );
        }
        output_newline(out);
    }

cleanup:
    /* Free all resources in reverse order of allocation */
    if (hook_fs_paths) string_array_free(hook_fs_paths);
    free(hook_custom_prefix);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (repo_dir) free(repo_dir);
    if (state) state_free(state);
    if (upstream_info) upstream_info_free(upstream_info);
    if (remote_name) free(remote_name);
    if (out) output_free(out);
    if (config) config_free(config);
    if (files) string_array_free(files);
    if (profile) profile_free(profile);
    if (all_profiles) profile_list_free(all_profiles);

    return err;
}

/**
 * Remove command implementation
 */
error_t *cmd_remove(git_repository *repo, const cmd_remove_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Validate options */
    error_t *err = validate_options(opts);
    if (err) {
        return err;
    }

    /* Branch: Delete profile or remove files */
    if (opts->delete_profile) {
        return delete_profile_branch(repo, opts);
    }
    return remove_files_from_profile(repo, opts);
}
