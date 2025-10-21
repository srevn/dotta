/**
 * remove.c - Remove files from profiles or delete profiles
 */

#include "remove.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
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
            return ERROR(ERR_INVALID_ARG,
                        "Cannot specify paths when using --delete-profile");
        }
        return NULL;
    }

    /* If not deleting profile, paths are required */
    if (!opts->paths || opts->path_count == 0) {
        return ERROR(ERR_INVALID_ARG,
                    "At least one path is required (or use --delete-profile)");
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
 */
static error_t *resolve_paths_to_remove(
    git_repository *repo,
    const char *profile_name,
    const char **input_paths,
    size_t path_count,
    string_array_t **storage_paths_out,
    string_array_t **filesystem_paths_out,
    const cmd_remove_options_t *opts,
    output_ctx_t *out
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
        err = error_wrap(err, "Failed to load profile '%s'", profile_name);
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
        err = hashmap_set(profile_files_map, file, (void *)1);  /* Dummy value */
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

        /* Resolve input path to storage format (flexible mode - file need not exist) */
        err = path_resolve_input(input_path, false, &storage_path);
        if (err) {
            if (!opts->force) {
                goto cleanup;
            }
            /* With --force, skip this path */
            if (opts->verbose && out) {
                output_warning(out, "Skipping invalid path '%s': %s",
                              input_path, error_message(err));
            }
            error_free(err);
            err = NULL;
            continue;
        }

        /* Try to get filesystem path for output (non-fatal if it fails) */
        error_t *conv_err = path_from_storage(storage_path, &canonical);
        if (conv_err) {
            /* Can still work with storage path only */
            error_free(conv_err);
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
                    err = path_from_storage(profile_file, &file_fs_path);
                    if (err) {
                        if ((opts->verbose || !opts->force) && out) {
                            output_warning(out, "Failed to resolve filesystem path for '%s': %s",
                                          profile_file, error_message(err));
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
                free(storage_path);
                free(canonical);
                err = ERROR(ERR_NOT_FOUND,
                            "File '%s' not found in profile '%s'\n"
                            "Hint: Use 'dotta list --profile %s' to see tracked files",
                            storage_path, profile_name, profile_name);
                goto cleanup;
            }
            /* With --force, warn and skip */
            if (opts->verbose && out) {
                output_warning(out, "File '%s' not found in profile, skipping", storage_path);
            }
        }

        free(storage_path);
        free(canonical);
    }

    /* Check if we found any files */
    if (string_array_size(storage_paths) == 0) {
        err = ERROR(ERR_NOT_FOUND,
                    "No files found to remove from profile '%s'", profile_name);
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
            return ERROR(ERR_NOT_FOUND,
                        "File '%s' not found in worktree", storage_path);
        }
        /* With --force, skip silently */
        return NULL;
    }

    /* Remove from filesystem */
    error_t *err = fs_remove_file(file_path);
    free(file_path);
    if (err) {
        return error_wrap(err, "Failed to remove file '%s' from worktree", storage_path);
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
static bool is_deployed_from_other_profile(
    git_repository *repo,
    const char *filesystem_path,
    const char *current_profile
) {
    if (!repo || !filesystem_path || !current_profile) {
        return false;
    }

    state_t *state = NULL;
    error_t *err = state_load(repo, &state);
    if (err) {
        error_free(err);
        return false;
    }

    if (!state || !state_file_exists(state, filesystem_path)) {
        state_free(state);
        return false;
    }

    state_file_entry_t *state_entry = NULL;
    err = state_get_file(state, filesystem_path, &state_entry);

    bool is_other = false;
    if (!err && state_entry && strcmp(state_entry->profile, current_profile) != 0) {
        is_other = true;
    }

    error_free(err);
    state_free_entry(state_entry);
    state_free(state);
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

                /* Check if deployed from another profile */
                if (is_deployed_from_other_profile(repo, filesystem_path, current_profile)) {
                    has_deployed_from_other = true;
                }
            }
        }
    }

    /* Free the index (and all its string arrays) */
    hashmap_free(profile_index, (void (*)(void *))string_array_free);

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
    output_warning(out, "%zu file%s exist%s in multiple profiles:",
                  multi_profile_count,
                  multi_profile_count == 1 ? "" : "s",
                  multi_profile_count == 1 ? "s" : "");

    /* Display each multi-profile file */
    for (size_t i = 0; i < file_count; i++) {
        if (!other_profiles[i] || string_array_size(other_profiles[i]) == 0) {
            continue;
        }

        const char *fs_path = string_array_get(filesystem_paths, i);

        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "  %s%s%s also in:",
                         output_color_code(out, OUTPUT_COLOR_YELLOW),
                         fs_path,
                         output_color_code(out, OUTPUT_COLOR_RESET));

            for (size_t j = 0; j < string_array_size(other_profiles[i]); j++) {
                output_printf(out, OUTPUT_NORMAL, " %s%s%s",
                             output_color_code(out, OUTPUT_COLOR_CYAN),
                             string_array_get(other_profiles[i], j),
                             output_color_code(out, OUTPUT_COLOR_RESET));
            }
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %s also in:", fs_path);
            for (size_t j = 0; j < string_array_size(other_profiles[i]); j++) {
                output_printf(out, OUTPUT_NORMAL, " %s",
                             string_array_get(other_profiles[i], j));
            }
        }
        output_newline(out);
    }

    /* Explain implications */
    output_newline(out);
    output_info(out, "These files will be removed ONLY from profile '%s'.", current_profile);

    if (has_deployed_from_other) {
        output_warning(out, "Some files are currently deployed from other profiles.");
        output_info(out, "Those files will remain on the filesystem.");
    } else {
        output_info(out, "Files deployed from '%s' will remain until 'dotta apply'.", current_profile);
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
    const dotta_config_t *config
) {
    CHECK_NULL(storage_paths);
    CHECK_NULL(opts);

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
    size_t threshold = 5;  /* Default threshold */
    if (config && config->confirm_destructive) {
        threshold = 1;  /* Always confirm in strict mode */
    }

    /* No confirmation needed for small operations below threshold */
    if (count < threshold) {
        return true;
    }

    /* Prompt user */
    char prompt[512];
    snprintf(prompt, sizeof(prompt),
            "Remove %zu file%s from profile '%s'?\n"
            "(Filesystem files will remain until 'dotta apply')",
            count, count == 1 ? "" : "s", opts->profile);

    output_ctx_t *out = output_create_from_config(config);
    bool confirmed = output_confirm(out, prompt, false);
    output_free(out);

    return confirmed;
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
    CHECK_NULL(profile_name);
    CHECK_NULL(out);

    /* Skip confirmation if --force */
    if (opts->force) {
        return true;
    }

    /* Extra warning for auto-detected profiles */
    if (is_auto_detected) {
        output_warning(out, "'%s' is an auto-detected profile", profile_name);
    }

    output_newline(out);
    output_warning(out, "This will delete profile '%s' (%zu file%s)",
                  profile_name, file_count, file_count == 1 ? "" : "s");
    output_info(out, "         Deployed files will remain on filesystem.");
    output_info(out, "         Run 'dotta apply' to remove them.");
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
        .action = COMMIT_ACTION_REMOVE,
        .profile = opts->profile,
        .files = (const char **)removed_paths->items,
        .file_count = removed_paths->count,
        .custom_msg = opts->message,
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
    const string_array_t *removed_storage_paths,
    const cmd_remove_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(wt);
    CHECK_NULL(removed_storage_paths);

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
    for (size_t i = 0; i < string_array_size(removed_storage_paths); i++) {
        const char *storage_path = string_array_get(removed_storage_paths, i);

        /* Check if metadata entry exists */
        if (metadata_has_entry(metadata, storage_path)) {
            err = metadata_remove_entry(metadata, storage_path);
            if (err) {
                metadata_free(metadata);
                return error_wrap(err, "Failed to remove metadata entry: %s", storage_path);
            }

            removed_count++;

            if (opts->verbose && out) {
                output_info(out, "Removed metadata: %s", storage_path);
            }
        }
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
        output_info(out, "Cleaned up metadata for %zu file(s)", removed_count);
    }

    return NULL;
}

/**
 * Remove files from profile
 */
static error_t *remove_files_from_profile(
    git_repository *repo,
    const cmd_remove_options_t *opts,
    size_t *removed_count_out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(removed_count_out);

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

    *removed_count_out = 0;

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
    }

    /* Resolve paths */
    err = resolve_paths_to_remove(repo, opts->profile, opts->paths, opts->path_count,
                                   &storage_paths, &filesystem_paths, opts, out);
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
        &other_profiles,
        &multi_profile_count,
        &has_deployed_from_other
    );

    if (err) {
        goto cleanup;
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
        output_printf(out, OUTPUT_NORMAL, "Would remove from profile '%s':\n", opts->profile);
        for (size_t i = 0; i < string_array_size(storage_paths); i++) {
            output_printf(out, OUTPUT_NORMAL, "  - %s\n", string_array_get(storage_paths, i));
        }
        output_printf(out, OUTPUT_NORMAL, "\nTotal: %zu file%s would be removed from profile\n",
                     string_array_size(storage_paths),
                     string_array_size(storage_paths) == 1 ? "" : "s");
        output_printf(out, OUTPUT_NORMAL, "(Filesystem files would remain until 'dotta apply')\n");

        goto cleanup;  /* err is NULL, will return success */
    }

    /* Confirm operation */
    if (!confirm_removal(storage_paths, opts, config)) {
        output_printf(out, OUTPUT_NORMAL, "Cancelled\n");
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
        hook_ctx->dry_run = opts->dry_run;

        /* Add paths to hook context */
        hook_context_add_files(hook_ctx,
                              (const char **)filesystem_paths->items,
                              filesystem_paths->count);

        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_PRE_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - abort operation */
            if (hook_result && hook_result->output && hook_result->output[0] && out) {
                output_printf(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
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
        err = error_wrap(err, "Failed to checkout profile '%s'", opts->profile);
        goto cleanup;
    }

    /* Remove each file from worktree */
    size_t removed_count = 0;
    for (size_t i = 0; i < string_array_size(storage_paths); i++) {
        const char *storage_path = string_array_get(storage_paths, i);

        /* Interactive mode: prompt for each file */
        if (opts->interactive) {
            /* Interactive prompts go to stdout (user expects them there) */
            printf("Remove %s? [y/N] ", storage_path);
            fflush(stdout);

            char response[10];
            if (!fgets(response, sizeof(response), stdin)) {
                /* EOF or error - skip this file */
                continue;
            }

            if (response[0] != 'y' && response[0] != 'Y') {
                /* User declined - skip this file */
                if (opts->verbose && out) {
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
        removed_count++;
    }

    /* Clean up metadata for removed files */
    err = cleanup_metadata(wt, storage_paths, opts, out);
    if (err) {
        err = error_wrap(err, "Failed to clean up metadata");
        goto cleanup;
    }

    /* Create commit */
    err = create_removal_commit(repo, wt, opts, storage_paths, config);
    if (err) {
        goto cleanup;
    }

    /* Cleanup worktree */
    worktree_cleanup(wt);
    wt = NULL;

    /*
     * Architectural note: We do NOT delete files from the filesystem here.
     * This maintains separation of concerns:
     * - `remove` modifies the Git repository (profile branches)
     * - `apply` synchronizes the filesystem (prunes orphaned files by default)
     *
     * This ensures `apply` has global context from all selected profiles to
     * correctly determine if a file should be removed (avoiding premature
     * deletion of files still needed by higher-priority profiles).
     */

    /* Execute post-remove hook */
    if (hook_ctx && !opts->dry_run) {
        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_POST_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - warn but don't abort (files already removed) */
            if (out) {
                output_warning(out, "Post-remove hook failed: %s", error_message(err));
                if (hook_result && hook_result->output && hook_result->output[0]) {
                    output_printf(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
                }
            }
            error_free(err);
            err = NULL;
        }
        hook_result_free(hook_result);
    }

    /* Success - save removed count */
    *removed_count_out = removed_count;

cleanup:
    /* Free all resources in reverse order */
    if (hook_ctx) hook_context_free(hook_ctx);
    if (repo_dir) free(repo_dir);
    if (wt) worktree_cleanup(wt);
    if (other_profiles) free_multi_profile_tracking(other_profiles, multi_profile_count);
    if (filesystem_paths) string_array_free(filesystem_paths);
    if (storage_paths) string_array_free(storage_paths);
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
    }

    /* Check if profile exists */
    if (!profile_exists(repo, opts->profile)) {
        if (!opts->force) {
            err = ERROR(ERR_NOT_FOUND,
                       "Profile '%s' does not exist\n"
                       "Hint: Use 'dotta list' to see available profiles",
                       opts->profile);
            goto cleanup;
        }
        /* With --force, just warn and exit */
        if (opts->verbose) {
            output_warning(out, "Profile '%s' does not exist", opts->profile);
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
        err = ERROR(ERR_INVALID_ARG,
                    "Cannot delete last remaining profile '%s'\n"
                    "Hint: A repository must have at least one profile",
                    opts->profile);
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

    string_array_free(files);
    files = NULL;
    profile_free(profile);
    profile = NULL;

    /* Dry run */
    if (opts->dry_run) {
        output_printf(out, OUTPUT_NORMAL, "Would delete profile '%s' (%zu file%s)\n",
                     opts->profile, file_count, file_count == 1 ? "" : "s");
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
        err = upstream_analyze_profile(repo, remote_name, opts->profile, &upstream_info);
        if (!err && upstream_info) {
            /* Determine if profile has actual remote tracking */
            if (upstream_info->state == UPSTREAM_NO_REMOTE) {
                /* Profile exists locally but was never pushed to remote */
                is_local_only = true;
            } else if (upstream_info->state == UPSTREAM_LOCAL_AHEAD ||
                       upstream_info->state == UPSTREAM_DIVERGED) {
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
        output_info(out, "Note: Profile '%s' is local-only (not pushed to remote)", opts->profile);
    }

    /* Free upstream_info after we're done using is_local_only */
    if (upstream_info) {
        upstream_info_free(upstream_info);
        upstream_info = NULL;
    }

    /* Load state to check for deployed files (read-only, informational only) */
    err = state_load(repo, &state);
    if (err) {
        /* Non-fatal */
        error_free(err);
        err = NULL;
        state = NULL;
    }

    /* Check if profile has deployed files (informational message for user) */
    size_t deployed_count = 0;
    if (state) {
        size_t state_file_count = 0;
        state_file_entry_t *state_files = NULL;
        error_t *state_err = state_get_all_files(state, &state_files, &state_file_count);
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
    }

    /* Inform about deployed files (informational, not a warning) */
    if (deployed_count > 0 && opts->verbose) {
        output_newline(out);
        output_info(out, "Note: Profile '%s' has %zu deployed file%s",
                   opts->profile, deployed_count, deployed_count == 1 ? "" : "s");
        output_info(out, "      These will be removed when you run 'dotta apply'.");
        output_newline(out);
    }

    /* Free state (no longer needed - we don't modify it) */
    if (state) {
        state_free(state);
        state = NULL;
    }

    /* Confirm deletion */
    if (!confirm_profile_deletion(opts->profile, file_count, is_auto_detected, opts, config, out)) {
        output_printf(out, OUTPUT_NORMAL, "Cancelled\n");
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Get repository directory for hooks */
    err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        goto cleanup;
    }

    /* Execute pre-remove hook */
    hook_ctx = hook_context_create(repo_dir, "remove", opts->profile);
    if (hook_ctx) {
        hook_ctx->dry_run = opts->dry_run;

        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_PRE_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - abort operation */
            if (hook_result && hook_result->output && hook_result->output[0]) {
                output_printf(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
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

    /* Delete local branch */
    err = gitops_delete_branch(repo, opts->profile);
    if (err) {
        err = error_wrap(err, "Failed to delete profile '%s'", opts->profile);
        goto cleanup;
    }

    /* Push deletion to remote if remote exists
     * This is critical for sync to work - other repos need to know the branch was deleted
     */
    if (remote_name) {
        if (opts->verbose) {
            output_info(out, "Pushing profile deletion to remote '%s'...", remote_name);
        }

        /* We don't have a credential context here, but gitops_delete_remote_branch will handle NULL */
        err = gitops_delete_remote_branch(repo, remote_name, opts->profile, NULL);
        if (err) {
            /* Non-fatal: warn but don't fail the whole operation
             * The local branch is already deleted, so this is just about syncing
             */
            output_warning(out, "Failed to push deletion to remote: %s", error_message(err));
            output_info(out, "         The profile was deleted locally, but sync may not work correctly.");
            output_info(out, "         You can manually push the deletion with: git push %s :%s",
                       remote_name, opts->profile);
            error_free(err);
            err = NULL;
        } else if (opts->verbose) {
            output_info(out, "Profile deletion pushed to remote");
        }

        free(remote_name);
        remote_name = NULL;
    }

    /*
     * Architectural note: We do not modify state here.
     * State cleanup happens automatically on next `apply`:
     * - Profile resolution won't include deleted profile
     * - Orphaned files will be pruned during deployment
     * - State will be rebuilt to reflect new reality
     *
     * This ensures `apply` has full global context for cleanup decisions.
     */

    /* Execute post-remove hook */
    if (hook_ctx && !opts->dry_run) {
        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_POST_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - warn but don't abort (profile already deleted) */
            output_warning(out, "Post-remove hook failed: %s", error_message(err));
            if (hook_result && hook_result->output && hook_result->output[0]) {
                output_printf(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
            }
            error_free(err);
            err = NULL;
        }
        hook_result_free(hook_result);
    }

cleanup:
    /* Free all resources in reverse order of allocation */
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

    /* Create output context for summary messages */
    output_ctx_t *out = output_create();
    if (!out) {
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* Apply CLI flags */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    } else if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Branch: Delete profile */
    if (opts->delete_profile) {
        err = delete_profile_branch(repo, opts);
        if (err) {
            output_free(out);
            return err;
        }

        if (!opts->quiet && !opts->dry_run) {
            output_success(out, "Profile '%s' deleted", opts->profile);
            output_info(out, "Run 'dotta apply' to remove deployed files from filesystem");
            output_newline(out);
        }

        output_free(out);
        return NULL;
    }

    /* Branch: Remove files from profile */
    size_t removed_count = 0;
    err = remove_files_from_profile(repo, opts, &removed_count);
    if (err) {
        output_free(out);
        return err;
    }

    /* Display summary */
    if (!opts->quiet && !opts->dry_run) {
        output_success(out, "Removed %zu file%s from profile '%s'",
                      removed_count, removed_count == 1 ? "" : "s", opts->profile);
        output_info(out, "Run 'dotta apply' to remove files from filesystem");
        output_newline(out);
    }

    output_free(out);
    return NULL;
}
