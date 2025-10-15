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
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(input_paths);
    CHECK_NULL(storage_paths_out);
    CHECK_NULL(filesystem_paths_out);
    CHECK_NULL(opts);

    error_t *err = NULL;
    hashmap_t *profile_files_map = NULL;

    string_array_t *storage_paths = string_array_create();
    string_array_t *filesystem_paths = string_array_create();
    if (!storage_paths || !filesystem_paths) {
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        return ERROR(ERR_MEMORY, "Failed to allocate path arrays");
    }

    /* Load profile to check file existence */
    profile_t *profile = NULL;
    err = profile_load(repo, profile_name, &profile);
    if (err) {
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        return error_wrap(err, "Failed to load profile '%s'", profile_name);
    }

    /* Get list of files in profile */
    string_array_t *profile_files = NULL;
    err = profile_list_files(repo, profile, &profile_files);
    if (err) {
        profile_free(profile);
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        return error_wrap(err, "Failed to list files in profile");
    }

    /* Build hashmap index for O(1) lookups */
    profile_files_map = hashmap_create(string_array_size(profile_files));
    if (!profile_files_map) {
        string_array_free(profile_files);
        profile_free(profile);
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        return ERROR(ERR_MEMORY, "Failed to create profile files index");
    }

    for (size_t i = 0; i < string_array_size(profile_files); i++) {
        const char *file = string_array_get(profile_files, i);
        err = hashmap_set(profile_files_map, file, (void *)1);  /* Dummy value */
        if (err) {
            hashmap_free(profile_files_map, NULL);
            string_array_free(profile_files);
            profile_free(profile);
            string_array_free(storage_paths);
            string_array_free(filesystem_paths);
            return error_wrap(err, "Failed to index profile files");
        }
    }

    /* Process each input path */
    for (size_t i = 0; i < path_count; i++) {
        const char *input_path = input_paths[i];
        char *storage_path = NULL;
        char *canonical = NULL;
        bool is_storage_path_format = false;

        /* Strategy: Try filesystem path first, then storage path */

        /* Attempt 1: Treat as filesystem path */
        err = fs_canonicalize_path(input_path, &canonical);
        if (!err) {
            /* Successfully canonicalized - convert to storage path */
            path_prefix_t prefix;
            err = path_to_storage(canonical, &storage_path, &prefix);
            if (err) {
                free(canonical);
                hashmap_free(profile_files_map, NULL);
                string_array_free(profile_files);
                profile_free(profile);
                string_array_free(storage_paths);
                string_array_free(filesystem_paths);
                return error_wrap(err, "Failed to convert filesystem path '%s'", input_path);
            }
        } else {
            /* Attempt 2: Treat as storage path directly */
            error_free(err);
            err = NULL;

            /* Validate it looks like a storage path (home/... or root/...) */
            if (strncmp(input_path, "home/", 5) == 0 || strncmp(input_path, "root/", 5) == 0) {
                storage_path = strdup(input_path);
                is_storage_path_format = true;

                /* Try to reconstruct filesystem path for output */
                err = path_from_storage(storage_path, &canonical);
                if (err) {
                    /* Non-fatal: we can still work with storage path only */
                    error_free(err);
                    err = NULL;
                    canonical = NULL;
                }
            } else {
                /* Neither filesystem nor storage path */
                if (!opts->force) {
                    hashmap_free(profile_files_map, NULL);
                    string_array_free(profile_files);
                    profile_free(profile);
                    string_array_free(storage_paths);
                    string_array_free(filesystem_paths);
                    return ERROR(ERR_INVALID_ARG,
                                "Path '%s' is neither a valid filesystem path nor storage path\n"
                                "Hint: Storage paths must start with 'home/' or 'root/'",
                                input_path);
                }
                /* With --force, skip this path */
                if (opts->verbose) {
                    fprintf(stderr, "Warning: Skipping invalid path '%s'\n", input_path);
                }
                continue;
            }
        }

        /* Find all files that match this path (exact match or directory prefix) */
        size_t matches_found = 0;
        size_t storage_path_len = strlen(storage_path);

        /* Check exact match first - O(1) with hashmap */
        if (hashmap_has(profile_files_map, storage_path)) {
            /* Exact file match found */
            char *fs_path = canonical ? strdup(canonical) : NULL;
            if (!fs_path && !is_storage_path_format) {
                /* Try to reconstruct from storage path */
                err = path_from_storage(storage_path, &fs_path);
                if (err) {
                    error_free(err);
                    err = NULL;
                }
            }

            err = string_array_push(storage_paths, storage_path);
            if (!err) {
                err = string_array_push(filesystem_paths, fs_path ? fs_path : storage_path);
            }

            free(fs_path);

            if (err) {
                free(storage_path);
                free(canonical);
                hashmap_free(profile_files_map, NULL);
                string_array_free(profile_files);
                profile_free(profile);
                string_array_free(storage_paths);
                string_array_free(filesystem_paths);
                return error_wrap(err, "Failed to track path for removal");
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
            if (strncmp(profile_file, storage_path, storage_path_len) == 0) {
                /* Ensure it's a directory boundary */
                if (profile_file[storage_path_len] == '/') {
                    /* Reconstruct filesystem path for this file */
                    char *file_fs_path = NULL;
                    err = path_from_storage(profile_file, &file_fs_path);
                    if (err) {
                        if (opts->verbose || !opts->force) {
                            fprintf(stderr, "Warning: Failed to resolve filesystem path for '%s': %s\n",
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
                        hashmap_free(profile_files_map, NULL);
                        string_array_free(profile_files);
                        profile_free(profile);
                        string_array_free(storage_paths);
                        string_array_free(filesystem_paths);
                        return error_wrap(err, "Failed to track path for removal");
                    }

                    matches_found++;
                }
            }
        }

        if (matches_found == 0) {
            if (!opts->force) {
                free(storage_path);
                free(canonical);
                hashmap_free(profile_files_map, NULL);
                string_array_free(profile_files);
                profile_free(profile);
                string_array_free(storage_paths);
                string_array_free(filesystem_paths);
                return ERROR(ERR_NOT_FOUND,
                            "File '%s' not found in profile '%s'\n"
                            "Hint: Use 'dotta list --profile %s' to see tracked files",
                            storage_path, profile_name, profile_name);
            }
            /* With --force, warn and skip */
            if (opts->verbose) {
                fprintf(stderr, "Warning: File '%s' not found in profile, skipping\n",
                       storage_path);
            }
        }

        free(storage_path);
        free(canonical);
    }

    hashmap_free(profile_files_map, NULL);
    string_array_free(profile_files);
    profile_free(profile);

    /* Check if we found any files */
    if (string_array_size(storage_paths) == 0) {
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        return ERROR(ERR_NOT_FOUND,
                    "No files found to remove from profile '%s'", profile_name);
    }

    *storage_paths_out = storage_paths;
    *filesystem_paths_out = filesystem_paths;
    return NULL;
}

/**
 * Remove file from worktree
 */
static error_t *remove_file_from_worktree(
    worktree_handle_t *wt,
    const char *storage_path,
    const cmd_remove_options_t *opts
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
        return error_from_git(git_err);
    }

    git_err = git_index_write(index);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    if (opts->verbose) {
        printf("Removed: %s\n", storage_path);
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

    const state_file_entry_t *state_entry = NULL;
    err = state_get_file(state, filesystem_path, &state_entry);

    bool is_other = false;
    if (!err && state_entry && strcmp(state_entry->profile, current_profile) != 0) {
        is_other = true;
    }

    error_free(err);
    state_free(state);
    return is_other;
}

/**
 * Build inverted index: storage_path -> set of profiles containing that path
 *
 * Loads all profiles once and builds an index for O(1) lookups.
 * This is a massive optimization over loading profiles repeatedly per-file.
 *
 * Complexity: O(M×P) where M = profile count, P = avg files per profile
 * Old approach was: O(N×M×GitOps) where N = files being checked
 *
 * @param repo Repository (must not be NULL)
 * @param current_profile Profile to exclude from results (must not be NULL)
 * @param out_index Output hashmap storage_path -> string_array_t of profile names
 * @return Error or NULL on success
 */
static error_t *build_profile_file_index(
    git_repository *repo,
    const char *current_profile,
    hashmap_t **out_index
) {
    CHECK_NULL(repo);
    CHECK_NULL(current_profile);
    CHECK_NULL(out_index);

    error_t *err = NULL;

    /* Create index hashmap */
    hashmap_t *index = hashmap_create(256);  /* Reasonable initial size */
    if (!index) {
        return ERROR(ERR_MEMORY, "Failed to create profile file index");
    }

    /* Get all branches */
    string_array_t *all_branches = NULL;
    err = gitops_list_branches(repo, &all_branches);
    if (err) {
        hashmap_free(index, NULL);
        return error_wrap(err, "Failed to list branches");
    }

    /* Load each profile once and index its files */
    for (size_t i = 0; i < string_array_size(all_branches); i++) {
        const char *branch_name = string_array_get(all_branches, i);

        /* Skip current profile and dotta-worktree */
        if (strcmp(branch_name, current_profile) == 0 ||
            strcmp(branch_name, "dotta-worktree") == 0) {
            continue;
        }

        /* Try to load profile */
        profile_t *profile = NULL;
        err = profile_load(repo, branch_name, &profile);
        if (err) {
            error_free(err);
            continue;  /* Non-fatal: skip this profile */
        }

        /* Get list of all files in this profile */
        string_array_t *files = NULL;
        err = profile_list_files(repo, profile, &files);
        profile_free(profile);

        if (err) {
            error_free(err);
            continue;  /* Non-fatal: skip this profile */
        }

        /* Add this profile to the index for each of its files */
        for (size_t j = 0; j < string_array_size(files); j++) {
            const char *storage_path = string_array_get(files, j);

            /* Get or create profile list for this storage path */
            string_array_t *profile_list = hashmap_get(index, storage_path);
            if (!profile_list) {
                profile_list = string_array_create();
                if (!profile_list) {
                    string_array_free(files);
                    string_array_free(all_branches);
                    /* Free index and all its arrays */
                    hashmap_free(index, (void (*)(void *))string_array_free);
                    return ERROR(ERR_MEMORY, "Failed to create profile list for file");
                }

                err = hashmap_set(index, storage_path, profile_list);
                if (err) {
                    string_array_free(profile_list);
                    string_array_free(files);
                    string_array_free(all_branches);
                    hashmap_free(index, (void (*)(void *))string_array_free);
                    return error_wrap(err, "Failed to index file");
                }
            }

            /* Add this profile to the list */
            err = string_array_push(profile_list, branch_name);
            if (err) {
                /* Non-fatal: continue without this entry */
                error_free(err);
            }
        }

        string_array_free(files);
    }

    string_array_free(all_branches);
    *out_index = index;
    return NULL;
}

/**
 * Analyze multi-profile conflicts for files to be removed
 *
 * Checks each file against all other profiles and determines:
 * - Which other profiles contain the file
 * - Whether the file is deployed from another profile
 *
 * Performance: O(M×P + N) where M=profiles, P=avg files/profile, N=files checked
 * Old implementation: O(N×M×GitOps) - massive improvement!
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

    /* Build profile file index once (O(M×P) - loads all profiles) */
    hashmap_t *profile_index = NULL;
    err = build_profile_file_index(repo, current_profile, &profile_index);
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
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(profile_name);

    /* Skip confirmation if --force */
    if (opts->force) {
        return true;
    }

    /* Extra warning for auto-detected profiles */
    if (is_auto_detected) {
        printf("WARNING: '%s' is an auto-detected profile.\n", profile_name);
    }

    printf("WARNING: This will delete profile '%s' (%zu file%s).\n",
           profile_name, file_count, file_count == 1 ? "" : "s");
    printf("         Deployed files will remain on filesystem.\n");
    printf("         Run 'dotta apply' to remove them.\n");

    output_ctx_t *out = output_create();
    bool confirmed = output_confirm(out, "Continue?", false);
    output_free(out);

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
    bool verbose
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

            if (verbose) {
                printf("Removed metadata: %s\n", storage_path);
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
        return error_from_git(git_err);
    }

    git_err = git_index_write(index);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    if (verbose && removed_count > 0) {
        printf("Cleaned up metadata for %zu file(s)\n", removed_count);
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

    error_t *err = NULL;
    *removed_count_out = 0;

    /* Load configuration */
    dotta_config_t *config = NULL;
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue without config */
        error_free(err);
        err = NULL;
        config = config_create_default();
    }

    /* Resolve paths */
    string_array_t *storage_paths = NULL;
    string_array_t *filesystem_paths = NULL;
    err = resolve_paths_to_remove(repo, opts->profile, opts->paths, opts->path_count,
                                   &storage_paths, &filesystem_paths, opts);
    if (err) {
        config_free(config);
        return err;
    }

    /* Analyze multi-profile conflicts (critical safety check) */
    string_array_t **other_profiles = NULL;
    size_t multi_profile_count = 0;
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
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        config_free(config);
        return err;
    }

    /* Display multi-profile warnings BEFORE any operation */
    output_ctx_t *out = output_create_from_config(config);
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
        printf("Would remove from profile '%s':\n", opts->profile);
        for (size_t i = 0; i < string_array_size(storage_paths); i++) {
            printf("  - %s\n", string_array_get(storage_paths, i));
        }
        printf("\nTotal: %zu file%s would be removed from profile\n",
               string_array_size(storage_paths),
               string_array_size(storage_paths) == 1 ? "" : "s");
        printf("(Filesystem files would remain until 'dotta apply')\n");

        free_multi_profile_tracking(other_profiles, string_array_size(storage_paths));
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        config_free(config);
        output_free(out);
        return NULL;
    }

    /* Confirm operation */
    if (!confirm_removal(storage_paths, opts, config)) {
        printf("Cancelled\n");
        free_multi_profile_tracking(other_profiles, string_array_size(storage_paths));
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        config_free(config);
        output_free(out);
        return NULL;
    }

    /* Cleanup multi-profile tracking and output context */
    free_multi_profile_tracking(other_profiles, string_array_size(storage_paths));
    output_free(out);

    /* Get repository directory for hooks */
    char *repo_dir = NULL;
    err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        config_free(config);
        return err;
    }

    /* Execute pre-remove hook */
    hook_context_t *hook_ctx = hook_context_create(repo_dir, "remove", opts->profile);
    if (hook_ctx) {
        /* Add paths to hook context */
        hook_context_add_files(hook_ctx,
                              (const char **)filesystem_paths->items,
                              filesystem_paths->count);

        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_PRE_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - abort operation */
            if (hook_result && hook_result->output && hook_result->output[0]) {
                fprintf(stderr, "Hook output:\n%s\n", hook_result->output);
            }
            hook_result_free(hook_result);
            hook_context_free(hook_ctx);
            free(repo_dir);
            string_array_free(storage_paths);
            string_array_free(filesystem_paths);
            config_free(config);
            return error_wrap(err, "Pre-remove hook failed");
        }
        hook_result_free(hook_result);
    }

    /* Create temporary worktree */
    worktree_handle_t *wt = NULL;
    err = worktree_create_temp(repo, &wt);
    if (err) {
        hook_context_free(hook_ctx);
        free(repo_dir);
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        config_free(config);
        return error_wrap(err, "Failed to create temporary worktree");
    }

    /* Checkout profile branch */
    err = worktree_checkout_branch(wt, opts->profile);
    if (err) {
        worktree_cleanup(wt);
        hook_context_free(hook_ctx);
        free(repo_dir);
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        config_free(config);
        return error_wrap(err, "Failed to checkout profile '%s'", opts->profile);
    }

    /* Remove each file from worktree */
    size_t removed_count = 0;
    for (size_t i = 0; i < string_array_size(storage_paths); i++) {
        const char *storage_path = string_array_get(storage_paths, i);

        /* Interactive mode: prompt for each file */
        if (opts->interactive) {
            printf("Remove %s? [y/N] ", storage_path);
            fflush(stdout);

            char response[10];
            if (!fgets(response, sizeof(response), stdin)) {
                /* EOF or error - skip this file */
                continue;
            }

            if (response[0] != 'y' && response[0] != 'Y') {
                /* User declined - skip this file */
                if (opts->verbose) {
                    printf("Skipped: %s\n", storage_path);
                }
                continue;
            }
        }

        err = remove_file_from_worktree(wt, storage_path, opts);
        if (err) {
            /* If interactive or force, continue on error */
            if (opts->interactive || opts->force) {
                fprintf(stderr, "Warning: %s\n", error_message(err));
                error_free(err);
                err = NULL;
                continue;
            }
            /* Otherwise, abort */
            worktree_cleanup(wt);
            hook_context_free(hook_ctx);
            free(repo_dir);
            string_array_free(storage_paths);
            string_array_free(filesystem_paths);
            config_free(config);
            return err;
        }
        removed_count++;
    }

    /* Clean up metadata for removed files */
    err = cleanup_metadata(wt, storage_paths, opts->verbose);
    if (err) {
        worktree_cleanup(wt);
        hook_context_free(hook_ctx);
        free(repo_dir);
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        config_free(config);
        return error_wrap(err, "Failed to clean up metadata");
    }

    /* Create commit */
    err = create_removal_commit(repo, wt, opts, storage_paths, config);
    if (err) {
        worktree_cleanup(wt);
        hook_context_free(hook_ctx);
        free(repo_dir);
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        config_free(config);
        return err;
    }

    /* Cleanup worktree */
    worktree_cleanup(wt);

    /*
     * Architectural note: We do NOT delete files from the filesystem here.
     * This maintains separation of concerns:
     * - `remove` modifies the Git repository (profile branches)
     * - `apply` synchronizes the filesystem (prunes orphaned files by default)
     *
     * This ensures `apply` has global context from all active profiles to
     * correctly determine if a file should be removed (avoiding premature
     * deletion of files still needed by higher-priority profiles).
     */

    /* Execute post-remove hook */
    if (hook_ctx) {
        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_POST_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - warn but don't abort (files already removed) */
            fprintf(stderr, "Warning: Post-remove hook failed: %s\n", error_message(err));
            if (hook_result && hook_result->output && hook_result->output[0]) {
                fprintf(stderr, "Hook output:\n%s\n", hook_result->output);
            }
            error_free(err);
            err = NULL;
        }
        hook_result_free(hook_result);
        hook_context_free(hook_ctx);
    }

    /* Cleanup */
    free(repo_dir);
    string_array_free(storage_paths);
    string_array_free(filesystem_paths);
    config_free(config);

    *removed_count_out = removed_count;
    return NULL;
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

    error_t *err = NULL;

    /* Check if profile exists */
    if (!profile_exists(repo, opts->profile)) {
        if (!opts->force) {
            return ERROR(ERR_NOT_FOUND,
                        "Profile '%s' does not exist\n"
                        "Hint: Use 'dotta list' to see available profiles",
                        opts->profile);
        }
        /* With --force, just warn and exit */
        if (opts->verbose) {
            fprintf(stderr, "Warning: Profile '%s' does not exist\n", opts->profile);
        }
        return NULL;
    }

    /* SAFETY: Prevent deletion of last remaining profile */
    profile_list_t *all_profiles = NULL;
    err = profile_list_all_local(repo, &all_profiles);
    if (err) {
        return error_wrap(err, "Failed to list profiles");
    }

    if (all_profiles->count <= 1) {
        profile_list_free(all_profiles);
        return ERROR(ERR_INVALID_ARG,
                    "Cannot delete last remaining profile '%s'\n"
                    "Hint: A repository must have at least one profile",
                    opts->profile);
    }
    profile_list_free(all_profiles);

    /* Load profile to count files */
    profile_t *profile = NULL;
    err = profile_load(repo, opts->profile, &profile);
    if (err) {
        return error_wrap(err, "Failed to load profile '%s'", opts->profile);
    }

    string_array_t *files = NULL;
    err = profile_list_files(repo, profile, &files);
    if (err) {
        profile_free(profile);
        return error_wrap(err, "Failed to list files in profile");
    }

    size_t file_count = string_array_size(files);
    bool is_auto_detected = profile->auto_detected;

    string_array_free(files);
    profile_free(profile);

    /* Dry run */
    if (opts->dry_run) {
        printf("Would delete profile '%s' (%zu file%s)\n",
               opts->profile, file_count, file_count == 1 ? "" : "s");
        return NULL;
    }

    /* Check for unpushed changes and detect remote
     * Keep remote_name for later use when pushing deletion
     */
    bool has_unpushed = false;
    bool is_local_only = false;
    char *remote_name = NULL;
    upstream_info_t *upstream_info = NULL;

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
        printf("\nWARNING: Profile '%s' has unpushed changes!\n", opts->profile);
        printf("         Deleting now may result in data loss.\n");
        printf("         Consider running 'dotta sync' first.\n\n");
    } else if (is_local_only && opts->verbose) {
        /* Inform about local-only status in verbose mode (not a warning) */
        printf("Note: Profile '%s' is local-only (not pushed to remote)\n", opts->profile);
    }

    /* Free upstream_info after we're done using is_local_only */
    if (upstream_info) {
        upstream_info_free(upstream_info);
        upstream_info = NULL;
    }

    /* Load state to check for deployed files and active profiles (with locking for potential writes) */
    state_t *state = NULL;
    err = state_load_for_update(repo, &state);
    if (err) {
        /* Non-fatal */
        error_free(err);
        err = NULL;
    }

    /* Check if profile is active and needs to be deactivated */
    bool is_active = false;
    if (state) {
        string_array_t *active_profiles = NULL;
        err = state_get_profiles(state, &active_profiles);
        if (!err) {
            /* Check if profile is in active list */
            for (size_t i = 0; i < string_array_size(active_profiles); i++) {
                if (strcmp(string_array_get(active_profiles, i), opts->profile) == 0) {
                    is_active = true;
                    break;
                }
            }
            string_array_free(active_profiles);
        } else {
            /* Non-fatal: just proceed without checking active status */
            error_free(err);
            err = NULL;
        }
    }

    /* Check if profile has deployed files */
    size_t deployed_count = 0;
    if (state) {
        size_t state_file_count = 0;
        const state_file_entry_t *state_files = state_get_all_files(state, &state_file_count);
        for (size_t i = 0; i < state_file_count; i++) {
            if (strcmp(state_files[i].profile, opts->profile) == 0) {
                deployed_count++;
            }
        }
    }

    /* Inform about deployed files (informational, not a warning) */
    if (deployed_count > 0 && opts->verbose) {
        printf("\nNote: Profile '%s' has %zu deployed file%s\n",
               opts->profile, deployed_count, deployed_count == 1 ? "" : "s");
        printf("      Run 'dotta apply' after deletion to remove them.\n\n");
    }

    /* Confirm deletion */
    if (!confirm_profile_deletion(opts->profile, file_count, is_auto_detected, opts)) {
        printf("Cancelled\n");
        free(remote_name);
        state_free(state);
        return NULL;
    }

    /* Load config */
    dotta_config_t *config = NULL;
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal */
        error_free(err);
        err = NULL;
        config = config_create_default();
    }

    /* Get repository directory for hooks */
    char *repo_dir = NULL;
    err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        free(remote_name);
        state_free(state);
        config_free(config);
        return err;
    }

    /* Execute pre-remove hook */
    hook_context_t *hook_ctx = hook_context_create(repo_dir, "remove", opts->profile);
    if (hook_ctx) {
        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_PRE_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - abort operation */
            if (hook_result && hook_result->output && hook_result->output[0]) {
                fprintf(stderr, "Hook output:\n%s\n", hook_result->output);
            }
            hook_result_free(hook_result);
            hook_context_free(hook_ctx);
            free(repo_dir);
            free(remote_name);
            state_free(state);
            config_free(config);
            return error_wrap(err, "Pre-remove hook failed");
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
        free(remote_name);
        state_free(state);
        config_free(config);
        return error_wrap(err, "Failed to delete profile '%s'", opts->profile);
    }

    /* Push deletion to remote if remote exists
     * This is critical for sync to work - other repos need to know the branch was deleted
     */
    if (remote_name) {
        if (opts->verbose) {
            printf("Pushing profile deletion to remote '%s'...\n", remote_name);
        }

        /* We don't have a credential context here, but gitops_delete_remote_branch will handle NULL */
        err = gitops_delete_remote_branch(repo, remote_name, opts->profile, NULL);
        if (err) {
            /* Non-fatal: warn but don't fail the whole operation
             * The local branch is already deleted, so this is just about syncing
             */
            fprintf(stderr, "Warning: Failed to push deletion to remote: %s\n", error_message(err));
            fprintf(stderr, "         The profile was deleted locally, but sync may not work correctly.\n");
            fprintf(stderr, "         You can manually push the deletion with: git push %s :%s\n",
                   remote_name, opts->profile);
            error_free(err);
            err = NULL;
        } else if (opts->verbose) {
            printf("Profile deletion pushed to remote\n");
        }

        free(remote_name);
        remote_name = NULL;
    }

    /* Track whether state was modified and needs saving */
    bool state_modified = false;

    /*
     * Clean up all state entries for the deleted profile
     *
     * This removes both file and directory entries that belong to this profile.
     * Using the existing state_cleanup_profile() function ensures symmetric
     * handling: add creates entries, remove deletes them.
     *
     * This immediate cleanup is cleaner than waiting for the next `apply` and
     * prevents orphaned entries if user doesn't run `apply` after deletion.
     */
    if (state) {
        size_t cleanup_count = 0;
        err = state_cleanup_profile(state, opts->profile, &cleanup_count);
        if (err) {
            /* Non-fatal: warn but continue */
            fprintf(stderr, "Warning: Failed to clean up state entries for profile: %s\n",
                   error_message(err));
            error_free(err);
            err = NULL;
        } else if (cleanup_count > 0) {
            state_modified = true;
            if (opts->verbose) {
                printf("Cleaned up %zu state entr%s for profile '%s'\n",
                       cleanup_count, cleanup_count == 1 ? "y" : "ies", opts->profile);
            }
        }
    }

    /*
     * Deactivate profile if it was active
     *
     * This MUST happen to maintain state consistency - a deleted profile
     * cannot remain in the active list, or `apply` will fail with
     * "profile not found".
     *
     * Note: state_cleanup_profile() above handles file and directory entries.
     * This section only handles removing the profile from state.profiles[].
     */
    if (is_active && state) {
        /* Build new active profiles list without the deleted profile */
        string_array_t *active_profiles = NULL;
        err = state_get_profiles(state, &active_profiles);
        if (!err) {
            string_array_t *new_active = string_array_create();
            if (!new_active) {
                string_array_free(active_profiles);
                free(repo_dir);
                state_free(state);
                config_free(config);
                return ERROR(ERR_MEMORY, "Failed to create active profiles array");
            }

            /* Copy all profiles except the one being deleted */
            for (size_t i = 0; i < string_array_size(active_profiles); i++) {
                const char *name = string_array_get(active_profiles, i);
                if (strcmp(name, opts->profile) != 0) {
                    string_array_push(new_active, name);
                }
            }

            /* Update state with new active profiles list */
            const char **profile_names = malloc(string_array_size(new_active) * sizeof(char *));
            if (!profile_names) {
                string_array_free(new_active);
                string_array_free(active_profiles);
                free(repo_dir);
                state_free(state);
                config_free(config);
                return ERROR(ERR_MEMORY, "Failed to allocate profile names array");
            }

            for (size_t i = 0; i < string_array_size(new_active); i++) {
                profile_names[i] = string_array_get(new_active, i);
            }

            err = state_set_profiles(state, profile_names, string_array_size(new_active));
            free(profile_names);
            string_array_free(new_active);
            string_array_free(active_profiles);

            if (err) {
                fprintf(stderr, "Warning: Failed to deactivate profile in state: %s\n", error_message(err));
                error_free(err);
                err = NULL;
            } else {
                state_modified = true;
                if (opts->verbose) {
                    printf("Deactivated profile '%s' from active list\n", opts->profile);
                }
            }
        } else {
            /* Non-fatal: warn but continue */
            fprintf(stderr, "Warning: Failed to deactivate profile: %s\n", error_message(err));
            error_free(err);
            err = NULL;
        }
    }

    /* Save state if profile was deactivated */
    if (state_modified && state) {
        err = state_save(repo, state);
        if (err) {
            fprintf(stderr, "Warning: Failed to save state: %s\n", error_message(err));
            error_free(err);
            err = NULL;
        }
    }

    /* Execute post-remove hook */
    if (hook_ctx) {
        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_POST_REMOVE, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - warn but don't abort (profile already deleted) */
            fprintf(stderr, "Warning: Post-remove hook failed: %s\n", error_message(err));
            if (hook_result && hook_result->output && hook_result->output[0]) {
                fprintf(stderr, "Hook output:\n%s\n", hook_result->output);
            }
            error_free(err);
            err = NULL;
        }
        hook_result_free(hook_result);
        hook_context_free(hook_ctx);
    }

    free(repo_dir);
    state_free(state);
    config_free(config);

    return NULL;
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

    /* Branch: Delete profile */
    if (opts->delete_profile) {
        err = delete_profile_branch(repo, opts);
        if (err) {
            return err;
        }

        if (!opts->quiet && !opts->dry_run) {
            printf("Profile '%s' deleted\n", opts->profile);
            printf("Run 'dotta apply' to remove deployed files from filesystem\n");
            printf("\n");
        }

        return NULL;
    }

    /* Branch: Remove files from profile */
    size_t removed_count = 0;
    err = remove_files_from_profile(repo, opts, &removed_count);
    if (err) {
        return err;
    }

    /* Display summary */
    if (!opts->quiet && !opts->dry_run) {
        printf("Removed %zu file%s from profile '%s'\n",
               removed_count, removed_count == 1 ? "" : "s", opts->profile);
        printf("Run 'dotta apply' to remove files from filesystem\n");
        printf("\n");
    }

    return NULL;
}
