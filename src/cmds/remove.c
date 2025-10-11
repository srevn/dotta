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
#include "core/profiles.h"
#include "core/state.h"
#include "infra/path.h"
#include "infra/worktree.h"
#include "utils/array.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/hooks.h"
#include "utils/string.h"
#include "utils/upstream.h"

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
 * Converts filesystem paths to storage paths and validates they exist in profile.
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

    /* Process each input path */
    for (size_t i = 0; i < path_count; i++) {
        const char *input_path = input_paths[i];

        /* Canonicalize filesystem path */
        char *canonical = NULL;
        err = fs_canonicalize_path(input_path, &canonical);
        if (err) {
            /* If path doesn't exist on filesystem, try to interpret as storage path */
            if (!opts->force) {
                string_array_free(profile_files);
                profile_free(profile);
                string_array_free(storage_paths);
                string_array_free(filesystem_paths);
                return error_wrap(err, "Failed to resolve path '%s'", input_path);
            }
            /* With --force, continue to next path */
            error_free(err);
            err = NULL;
            continue;
        }

        /* Convert to storage path */
        char *storage_path = NULL;
        path_prefix_t prefix;
        err = path_to_storage(canonical, &storage_path, &prefix);
        if (err) {
            free(canonical);
            string_array_free(profile_files);
            profile_free(profile);
            string_array_free(storage_paths);
            string_array_free(filesystem_paths);
            return error_wrap(err, "Failed to convert path '%s'", input_path);
        }

        /* Find all files that match this path (exact match or directory prefix) */
        size_t matches_found = 0;
        size_t storage_path_len = strlen(storage_path);

        for (size_t j = 0; j < string_array_size(profile_files); j++) {
            const char *profile_file = string_array_get(profile_files, j);
            bool match = false;

            /* Exact match */
            if (strcmp(profile_file, storage_path) == 0) {
                match = true;
            }
            /* Directory prefix match (e.g., "home/.config/nvim" matches "home/.config/nvim/init.vim") */
            else if (strncmp(profile_file, storage_path, storage_path_len) == 0) {
                /* Ensure it's a directory boundary (next char is '/') */
                if (profile_file[storage_path_len] == '/' ||
                    profile_file[storage_path_len] == '\0') {
                    match = true;
                }
            }

            if (match) {
                /* Reconstruct filesystem path for this file */
                char *file_fs_path = NULL;
                err = path_from_storage(profile_file, &file_fs_path);
                if (err) {
                    error_free(err);
                    /* Fallback: use canonical path if it's an exact match, otherwise skip */
                    if (strcmp(profile_file, storage_path) == 0) {
                        file_fs_path = strdup(canonical);
                        if (!file_fs_path) {
                            /* Memory allocation failed, skip this file */
                            continue;
                        }
                    } else {
                        /* Can't determine filesystem path, skip this file */
                        continue;
                    }
                }

                /* Both paths are valid - add to both arrays together to maintain sync */
                string_array_push(storage_paths, profile_file);
                string_array_push(filesystem_paths, file_fs_path);
                free(file_fs_path);
                matches_found++;
            }
        }

        if (matches_found == 0) {
            if (!opts->force) {
                free(storage_path);
                free(canonical);
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
 * Cleanup deployed file from filesystem
 */
static error_t *cleanup_deployed_file(
    const char *filesystem_path,
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(opts);

    if (!fs_exists(filesystem_path)) {
        if (opts->verbose) {
            printf("File already removed from filesystem: %s\n", filesystem_path);
        }
        return NULL;
    }

    error_t *err = fs_remove_file(filesystem_path);
    if (err) {
        return error_wrap(err, "Failed to remove file '%s' from filesystem",
                         filesystem_path);
    }

    if (opts->verbose) {
        printf("Cleaned up: %s\n", filesystem_path);
    }

    return NULL;
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

    /* No confirmation needed for small operations */
    if (count < threshold && !opts->cleanup) {
        return true;
    }

    /* Prompt user */
    if (opts->cleanup) {
        printf("This will remove %zu file%s from profile AND filesystem.\n",
               count, count == 1 ? "" : "s");
    } else {
        printf("Remove %zu file%s from profile '%s'?\n",
               count, count == 1 ? "" : "s", opts->profile);
    }

    printf("Continue? [y/N] ");
    fflush(stdout);

    char response[10];
    if (!fgets(response, sizeof(response), stdin)) {
        return false;
    }

    return (response[0] == 'y' || response[0] == 'Y');
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

    if (opts->cleanup) {
        printf("         Deployed files will be removed from filesystem.\n");
    } else {
        printf("         Deployed files will remain on filesystem.\n");
        printf("         Hint: Use 'dotta apply --prune' to clean up.\n");
    }

    printf("\nContinue? [y/N] ");
    fflush(stdout);

    char response[10];
    if (!fgets(response, sizeof(response), stdin)) {
        return false;
    }

    return (response[0] == 'y' || response[0] == 'Y');
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
 * Update state after file removal
 */
static error_t *update_state_after_removal(
    state_t *state,
    const string_array_t *removed_filesystem_paths,
    const char *profile_name
) {
    CHECK_NULL(state);
    CHECK_NULL(removed_filesystem_paths);
    CHECK_NULL(profile_name);

    /* Remove each file from state */
    for (size_t i = 0; i < string_array_size(removed_filesystem_paths); i++) {
        const char *path = string_array_get(removed_filesystem_paths, i);

        if (state_file_exists(state, path)) {
            error_t *err = state_remove_file(state, path);
            if (err) {
                /* Non-fatal: just log warning */
                fprintf(stderr, "Warning: Failed to update state for '%s': %s\n",
                       path, error_message(err));
                error_free(err);
            }
        }
    }

    /* Check if any tracked directories are now empty and should be removed */
    size_t dir_count = 0;
    const state_directory_entry_t *dirs = state_get_all_directories(state, &dir_count);

    for (size_t i = 0; i < dir_count; i++) {
        /* Only check directories for this profile */
        if (strcmp(dirs[i].profile, profile_name) != 0) {
            continue;
        }

        /* Check if any files still exist under this directory's storage prefix */
        bool has_files = false;
        size_t file_count = 0;
        const state_file_entry_t *files = state_get_all_files(state, &file_count);

        const char *dir_prefix = dirs[i].storage_prefix;
        size_t prefix_len = strlen(dir_prefix);

        for (size_t j = 0; j < file_count; j++) {
            /* Check if file is from same profile and under this directory */
            if (strcmp(files[j].profile, profile_name) == 0) {
                const char *file_storage = files[j].storage_path;
                if (strncmp(file_storage, dir_prefix, prefix_len) == 0) {
                    /* Check directory boundary */
                    if (file_storage[prefix_len] == '/' || file_storage[prefix_len] == '\0') {
                        has_files = true;
                        break;
                    }
                }
            }
        }

        /* If directory is now empty, remove it from state */
        if (!has_files) {
            error_t *err = state_remove_directory(state, dirs[i].filesystem_path);
            if (err) {
                /* Non-fatal: just log warning */
                fprintf(stderr, "Warning: Failed to remove directory tracking for '%s': %s\n",
                       dirs[i].filesystem_path, error_message(err));
                error_free(err);
            }
        }
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

    /* Load state */
    state_t *state = NULL;
    err = state_load(repo, &state);
    if (err) {
        config_free(config);
        return error_wrap(err, "Failed to load state");
    }

    /* Resolve paths */
    string_array_t *storage_paths = NULL;
    string_array_t *filesystem_paths = NULL;
    err = resolve_paths_to_remove(repo, opts->profile, opts->paths, opts->path_count,
                                   &storage_paths, &filesystem_paths, opts);
    if (err) {
        state_free(state);
        config_free(config);
        return err;
    }

    /* Dry run - just show what would be removed */
    if (opts->dry_run) {
        printf("Would remove from profile '%s':\n", opts->profile);
        for (size_t i = 0; i < string_array_size(storage_paths); i++) {
            printf("  - %s\n", string_array_get(storage_paths, i));
        }
        printf("\nTotal: %zu file%s would be removed\n",
               string_array_size(storage_paths),
               string_array_size(storage_paths) == 1 ? "" : "s");

        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        state_free(state);
        config_free(config);
        return NULL;
    }

    /* Confirm operation */
    if (!confirm_removal(storage_paths, opts, config)) {
        printf("Cancelled\n");
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        state_free(state);
        config_free(config);
        return NULL;
    }

    /* Get repository directory for hooks */
    char *repo_dir = NULL;
    err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        state_free(state);
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
            state_free(state);
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
        state_free(state);
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
        state_free(state);
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
            state_free(state);
            config_free(config);
            return err;
        }
        removed_count++;
    }

    /* Create commit */
    err = create_removal_commit(repo, wt, opts, storage_paths, config);
    if (err) {
        worktree_cleanup(wt);
        hook_context_free(hook_ctx);
        free(repo_dir);
        string_array_free(storage_paths);
        string_array_free(filesystem_paths);
        state_free(state);
        config_free(config);
        return err;
    }

    /* Cleanup worktree */
    worktree_cleanup(wt);

    /* Cleanup filesystem if requested */
    if (opts->cleanup) {
        for (size_t i = 0; i < string_array_size(filesystem_paths); i++) {
            const char *fs_path = string_array_get(filesystem_paths, i);

            err = cleanup_deployed_file(fs_path, opts);
            if (err) {
                fprintf(stderr, "Warning: %s\n", error_message(err));
                error_free(err);
                err = NULL;
            }
        }

        /* Update state to remove files that were cleaned up from filesystem
         * Only do this when --cleanup is used. Without --cleanup, files remain on
         * the filesystem and in state, so that 'apply --prune' can remove them later.
         */
        err = update_state_after_removal(state, filesystem_paths, opts->profile);
        if (err) {
            fprintf(stderr, "Warning: Failed to update state: %s\n", error_message(err));
            error_free(err);
            err = NULL;
        }

        /* Save state */
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
    state_free(state);
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
    char *remote_name = NULL;
    err = upstream_detect_remote(repo, &remote_name);
    if (!err && remote_name) {
        /* Remote exists - check upstream state */
        upstream_info_t *upstream_info = NULL;
        err = upstream_analyze_profile(repo, remote_name, opts->profile, &upstream_info);
        if (!err && upstream_info) {
            if (upstream_info->state == UPSTREAM_LOCAL_AHEAD ||
                upstream_info->state == UPSTREAM_DIVERGED ||
                upstream_info->state == UPSTREAM_NO_REMOTE) {
                has_unpushed = true;
            }
            upstream_info_free(upstream_info);
        } else if (err) {
            /* Non-fatal: can't determine upstream state */
            error_free(err);
            err = NULL;
        }
    } else if (err) {
        /* No remote configured - this is fine */
        error_free(err);
        err = NULL;
    }

    /* Warn about unpushed changes */
    if (has_unpushed && !opts->force) {
        printf("\nWARNING: Profile '%s' has unpushed changes!\n", opts->profile);
        printf("         Deleting now may result in data loss.\n");
        printf("         Consider running 'dotta sync' first.\n\n");
    }

    /* Load state to check for deployed files */
    state_t *state = NULL;
    err = state_load(repo, &state);
    if (err) {
        /* Non-fatal */
        error_free(err);
        err = NULL;
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

    /* Warn about deployed files */
    if (deployed_count > 0 && !opts->cleanup && !opts->force) {
        printf("\nWARNING: Profile '%s' has %zu deployed file%s!\n",
               opts->profile, deployed_count, deployed_count == 1 ? "" : "s");
        printf("         These files will remain on your filesystem after deletion.\n");
        printf("         Use --cleanup to remove them, or run 'dotta apply --prune' later.\n\n");
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

    /* Cleanup deployed files if requested */
    if (opts->cleanup && state) {
        size_t state_file_count = 0;
        const state_file_entry_t *state_files = state_get_all_files(state, &state_file_count);

        for (size_t i = 0; i < state_file_count; i++) {
            if (strcmp(state_files[i].profile, opts->profile) == 0) {
                err = cleanup_deployed_file(state_files[i].filesystem_path, opts);
                if (err) {
                    fprintf(stderr, "Warning: %s\n", error_message(err));
                    error_free(err);
                    err = NULL;
                }
            }
        }
    }

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

    /* Update state - remove all files from this profile
     * Only do this when --cleanup is used. Without --cleanup, files remain on
     * the filesystem and in state, so that 'apply --prune' can remove them later.
     */
    if (opts->cleanup && state) {
        size_t state_file_count = 0;
        const state_file_entry_t *state_files = state_get_all_files(state, &state_file_count);

        /* Collect files to remove (can't modify while iterating) */
        string_array_t *files_to_remove = string_array_create();
        for (size_t i = 0; i < state_file_count; i++) {
            if (strcmp(state_files[i].profile, opts->profile) == 0) {
                string_array_push(files_to_remove, state_files[i].filesystem_path);
            }
        }

        /* Remove files */
        for (size_t i = 0; i < string_array_size(files_to_remove); i++) {
            err = state_remove_file(state, string_array_get(files_to_remove, i));
            if (err) {
                fprintf(stderr, "Warning: Failed to update state: %s\n", error_message(err));
                error_free(err);
                err = NULL;
            }
        }
        string_array_free(files_to_remove);

        /* Remove directory tracking for this profile */
        size_t dir_count = 0;
        const state_directory_entry_t *dirs = state_get_all_directories(state, &dir_count);

        string_array_t *dirs_to_remove = string_array_create();
        for (size_t i = 0; i < dir_count; i++) {
            if (strcmp(dirs[i].profile, opts->profile) == 0) {
                string_array_push(dirs_to_remove, dirs[i].filesystem_path);
            }
        }

        for (size_t i = 0; i < string_array_size(dirs_to_remove); i++) {
            err = state_remove_directory(state, string_array_get(dirs_to_remove, i));
            if (err) {
                fprintf(stderr, "Warning: Failed to remove directory tracking: %s\n", error_message(err));
                error_free(err);
                err = NULL;
            }
        }
        string_array_free(dirs_to_remove);

        /* Save state */
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
            printf("Deleted profile '%s'\n", opts->profile);

            if (!opts->cleanup) {
                printf("\nHint: Deployed files remain on filesystem.\n");
                printf("      Run 'dotta apply --prune' to clean up.\n");
            }
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

        if (!opts->cleanup) {
            printf("\nHint: Files remain on filesystem.\n");
            printf("      Use --cleanup or run 'dotta apply --prune' to remove them.\n");
        }
        printf("\n");
    }

    return NULL;
}
