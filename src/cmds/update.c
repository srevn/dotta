/**
 * update.c - Update profiles with modified files
 */

#include "update.h"

#include <dirent.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/ignore.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "core/workspace.h"
#include "infra/compare.h"
#include "infra/worktree.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/output.h"
#include "utils/string.h"

/**
 * Modified file entry
 */
typedef struct {
    char *filesystem_path;    /* Full filesystem path */
    char *storage_path;       /* Storage path (home/.bashrc) */
    profile_t *source_profile; /* Which profile owns this file */
    compare_result_t status;   /* Type of modification */
} modified_file_t;

/**
 * List of modified files
 */
typedef struct {
    modified_file_t *files;
    size_t count;
    size_t capacity;
} modified_file_list_t;

/**
 * Create modified file list
 */
static modified_file_list_t *modified_file_list_create(void) {
    modified_file_list_t *list = calloc(1, sizeof(modified_file_list_t));
    if (!list) {
        return NULL;
    }

    list->capacity = 16;
    list->files = calloc(list->capacity, sizeof(modified_file_t));
    if (!list->files) {
        free(list);
        return NULL;
    }

    return list;
}

/**
 * Add file to list
 */
static error_t *modified_file_list_add(
    modified_file_list_t *list,
    const char *filesystem_path,
    const char *storage_path,
    profile_t *profile,
    compare_result_t status
) {
    CHECK_NULL(list);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);

    /* Grow if needed */
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity * 2;
        modified_file_t *new_files = realloc(list->files,
                                             new_capacity * sizeof(modified_file_t));
        if (!new_files) {
            return ERROR(ERR_MEMORY, "Failed to grow file list");
        }
        list->files = new_files;
        list->capacity = new_capacity;
    }

    /* Add entry */
    modified_file_t *entry = &list->files[list->count];
    entry->filesystem_path = strdup(filesystem_path);
    entry->storage_path = strdup(storage_path);
    entry->source_profile = profile;
    entry->status = status;

    if (!entry->filesystem_path || !entry->storage_path) {
        free(entry->filesystem_path);
        free(entry->storage_path);
        return ERROR(ERR_MEMORY, "Failed to allocate paths");
    }

    list->count++;
    return NULL;
}

/**
 * Free modified file list
 */
static void modified_file_list_free(modified_file_list_t *list) {
    if (!list) {
        return;
    }

    for (size_t i = 0; i < list->count; i++) {
        free(list->files[i].filesystem_path);
        free(list->files[i].storage_path);
    }

    free(list->files);
    free(list);
}

/**
 * New file entry (for tracking new files in directories)
 */
typedef struct {
    char *filesystem_path;
    char *storage_path;
    profile_t *source_profile;
} new_file_t;

/**
 * List of new files
 */
typedef struct {
    new_file_t *files;
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
    list->files = calloc(list->capacity, sizeof(new_file_t));
    if (!list->files) {
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
    const char *storage_path,
    profile_t *profile
) {
    CHECK_NULL(list);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);

    /* Grow if needed */
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity * 2;
        new_file_t *new_files = realloc(list->files,
                                        new_capacity * sizeof(new_file_t));
        if (!new_files) {
            return ERROR(ERR_MEMORY, "Failed to grow new file list");
        }
        list->files = new_files;
        list->capacity = new_capacity;
    }

    /* Add entry */
    new_file_t *entry = &list->files[list->count];
    entry->filesystem_path = strdup(filesystem_path);
    entry->storage_path = strdup(storage_path);
    entry->source_profile = profile;

    if (!entry->filesystem_path || !entry->storage_path) {
        free(entry->filesystem_path);
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
        free(list->files[i].filesystem_path);
        free(list->files[i].storage_path);
    }
    free(list->files);
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
    profile_t *profile,
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

                error_t *err = new_file_list_add(new_files, full_path, storage_path, profile);
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
 * Check if file matches filter (if any)
 */
static bool file_matches_filter(
    const char *filesystem_path,
    const cmd_update_options_t *opts
) {
    /* If no file filter, include all */
    if (!opts->files || opts->file_count == 0) {
        return true;
    }

    /* Check if this file is in the filter list */
    for (size_t i = 0; i < opts->file_count; i++) {
        if (strcmp(filesystem_path, opts->files[i]) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Find all modified files using workspace divergence analysis
 *
 * This function uses the workspace module to detect divergence between
 * profile state, deployment state, and filesystem state. It correctly
 * distinguishes between:
 * - MODIFIED: Files deployed and changed on disk (include)
 * - DELETED: Files deployed and removed from disk (include)
 * - MODE_DIFF: Files with permission changes (include)
 * - TYPE_DIFF: Files with type changes (include)
 * - UNDEPLOYED: Files in profile but never deployed (exclude - not a modification)
 */
static error_t *find_modified_files(
    git_repository *repo,
    profile_list_t *profiles,
    const cmd_update_options_t *opts,
    modified_file_list_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    modified_file_list_t *modified = modified_file_list_create();
    if (!modified) {
        return ERROR(ERR_MEMORY, "Failed to create modified file list");
    }

    /* Load workspace to analyze divergence */
    workspace_t *ws = NULL;
    error_t *err = workspace_load(repo, profiles, &ws);
    if (err) {
        modified_file_list_free(modified);
        return error_wrap(err, "Failed to load workspace");
    }

    /* Get all diverged files */
    size_t count = 0;
    const workspace_file_t *diverged = workspace_get_all_diverged(ws, &count);

    /* Process each diverged file */
    for (size_t i = 0; i < count; i++) {
        const workspace_file_t *file = &diverged[i];

        /* Skip undeployed files - these are not modifications */
        if (file->type == DIVERGENCE_UNDEPLOYED) {
            continue;
        }

        /* Skip orphaned files - these are state cleanup issues, not file updates */
        if (file->type == DIVERGENCE_ORPHANED) {
            continue;
        }

        /* Apply file filter if specified */
        if (!file_matches_filter(file->filesystem_path, opts)) {
            continue;
        }

        /* Map workspace divergence type to compare result type for compatibility */
        compare_result_t cmp_result;
        switch (file->type) {
            case DIVERGENCE_MODIFIED:
                cmp_result = CMP_DIFFERENT;
                break;
            case DIVERGENCE_DELETED:
                cmp_result = CMP_MISSING;
                break;
            case DIVERGENCE_MODE_DIFF:
                cmp_result = CMP_MODE_DIFF;
                break;
            case DIVERGENCE_TYPE_DIFF:
                cmp_result = CMP_TYPE_DIFF;
                break;
            default:
                continue;  /* Skip unknown types */
        }

        /* Find the profile for this file */
        profile_t *source_profile = NULL;
        for (size_t j = 0; j < profiles->count; j++) {
            if (strcmp(profiles->profiles[j].name, file->profile) == 0) {
                source_profile = &profiles->profiles[j];
                break;
            }
        }

        if (!source_profile) {
            /* Profile not in active set - skip */
            continue;
        }

        /* Add to modified list */
        err = modified_file_list_add(
            modified,
            file->filesystem_path,
            file->storage_path,
            source_profile,
            cmp_result
        );

        if (err) {
            workspace_free(ws);
            modified_file_list_free(modified);
            return err;
        }
    }

    workspace_free(ws);
    *out = modified;
    return NULL;
}

/**
 * Copy file from filesystem to worktree
 */
static error_t *copy_file_to_worktree(
    worktree_handle_t *wt,
    const char *filesystem_path,
    const char *storage_path
) {
    CHECK_NULL(wt);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);

    const char *wt_path = worktree_get_path(wt);
    char *dest_path = str_format("%s/%s", wt_path, storage_path);
    if (!dest_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate destination path");
    }

    /* Create parent directory */
    char *parent = NULL;
    error_t *err = fs_get_parent_dir(dest_path, &parent);
    if (err) {
        free(dest_path);
        return err;
    }

    err = fs_create_dir(parent, true);
    free(parent);
    if (err) {
        free(dest_path);
        return error_wrap(err, "Failed to create parent directory");
    }

    /* Remove existing file if present */
    if (fs_lexists(dest_path)) {
        err = fs_remove_file(dest_path);
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to remove existing file");
        }
    }

    /* Copy file */
    if (fs_is_symlink(filesystem_path)) {
        /* Handle symlink */
        char *target = NULL;
        err = fs_read_symlink(filesystem_path, &target);
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to read symlink");
        }

        err = fs_create_symlink(target, dest_path);
        free(target);
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to create symlink");
        }
    } else {
        /* Handle regular file */
        err = fs_copy_file(filesystem_path, dest_path);
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to copy file");
        }
    }

    free(dest_path);
    return NULL;
}

/**
 * Capture and save metadata for updated files
 *
 * Similar to add.c, but works with modified_file_t array.
 */
static error_t *capture_and_save_metadata(
    worktree_handle_t *wt,
    modified_file_t *files,
    size_t file_count,
    bool verbose
) {
    CHECK_NULL(wt);
    CHECK_NULL(files);

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
            /* No existing metadata - create new */
            error_free(err);
            err = metadata_create_empty(&metadata);
            if (err) {
                return err;
            }
        } else {
            /* Real error - propagate */
            return error_wrap(err, "Failed to load existing metadata");
        }
    }

    /* Capture metadata for each updated file */
    size_t captured_count = 0;

    for (size_t i = 0; i < file_count; i++) {
        modified_file_t *file = &files[i];

        /* Skip deleted files */
        if (file->status == CMP_MISSING) {
            /* Remove metadata entry if it exists */
            if (metadata_has_entry(metadata, file->storage_path)) {
                err = metadata_remove_entry(metadata, file->storage_path);
                if (err && err->code != ERR_NOT_FOUND) {
                    metadata_free(metadata);
                    return error_wrap(err, "Failed to remove metadata entry");
                }
                if (err) {
                    error_free(err);
                }
                if (verbose) {
                    printf("Removed metadata: %s\n", file->filesystem_path);
                }
            }
            continue;
        }

        /* Capture metadata from filesystem */
        metadata_entry_t *entry = NULL;
        err = metadata_capture_from_file(file->filesystem_path, file->storage_path, &entry);

        if (err) {
            metadata_free(metadata);
            return error_wrap(err, "Failed to capture metadata for: %s", file->filesystem_path);
        }

        /* entry will be NULL for symlinks - skip them */
        if (entry) {
            /* Save metadata before adding (for verbose output) */
            mode_t mode = entry->mode;
            char *owner = entry->owner ? strdup(entry->owner) : NULL;
            char *group = entry->group ? strdup(entry->group) : NULL;

            /* Add to metadata collection (copies all fields including owner/group) */
            err = metadata_add_entry(metadata, entry);
            metadata_entry_free(entry);

            if (err) {
                free(owner);
                free(group);
                metadata_free(metadata);
                return error_wrap(err, "Failed to add metadata entry");
            }

            captured_count++;

            if (verbose) {
                if (owner || group) {
                    printf("Captured metadata: %s (mode: %04o, owner: %s:%s)\n",
                          file->filesystem_path, mode,
                          owner ? owner : "?",
                          group ? group : "?");
                } else {
                    printf("Captured metadata: %s (mode: %04o)\n",
                          file->filesystem_path, mode);
                }
            }
            free(owner);
            free(group);
        }
    }

    /* Save metadata to worktree */
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

    if (verbose && captured_count > 0) {
        printf("Updated metadata for %zu file(s)\n", captured_count);
    }

    return NULL;
}

/**
 * Update a single profile with its modified files
 */
static error_t *update_profile(
    git_repository *repo,
    profile_t *profile,
    modified_file_t *files,
    size_t file_count,
    const cmd_update_options_t *opts,
    output_ctx_t *out,
    const dotta_config_t *config
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(files);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    if (file_count == 0) {
        return NULL;
    }

    worktree_handle_t *wt = NULL;
    error_t *err = NULL;

    /* Create temporary worktree */
    err = worktree_create_temp(repo, &wt);
    if (err) {
        return error_wrap(err, "Failed to create temporary worktree");
    }

    /* Checkout profile branch */
    err = worktree_checkout_branch(wt, profile->name);
    if (err) {
        worktree_cleanup(wt);
        return error_wrap(err, "Failed to checkout profile '%s'", profile->name);
    }

    /* Copy each modified file to worktree and stage */
    git_index *index = NULL;
    err = worktree_get_index(wt, &index);
    if (err) {
        worktree_cleanup(wt);
        return error_wrap(err, "Failed to get worktree index");
    }

    for (size_t i = 0; i < file_count; i++) {
        modified_file_t *file = &files[i];

        if (opts->verbose) {
            output_info(out, "  %s", file->filesystem_path);
        }

        /* Handle deleted files (missing from filesystem) */
        if (file->status == CMP_MISSING) {
            /* Remove from index (stage deletion) */
            int git_err = git_index_remove_bypath(index, file->storage_path);
            if (git_err < 0) {
                worktree_cleanup(wt);
                return error_from_git(git_err);
            }
            continue;
        }

        /* Copy to worktree */
        err = copy_file_to_worktree(wt, file->filesystem_path, file->storage_path);
        if (err) {
            worktree_cleanup(wt);
            return error_wrap(err, "Failed to copy '%s'", file->filesystem_path);
        }

        /* Stage file */
        int git_err = git_index_add_bypath(index, file->storage_path);
        if (git_err < 0) {
            worktree_cleanup(wt);
            return error_from_git(git_err);
        }
    }

    /* Capture and save metadata for updated files */
    err = capture_and_save_metadata(wt, files, file_count, opts->verbose);
    if (err) {
        worktree_cleanup(wt);
        return error_wrap(err, "Failed to capture metadata");
    }

    /* Note: metadata capture function already wrote the index */

    /* Create commit */
    git_oid tree_oid;
    int git_err = git_index_write_tree(&tree_oid, index);
    if (git_err < 0) {
        worktree_cleanup(wt);
        return error_from_git(git_err);
    }

    git_repository *wt_repo = worktree_get_repo(wt);
    git_tree *tree = NULL;
    git_err = git_tree_lookup(&tree, wt_repo, &tree_oid);
    if (git_err < 0) {
        worktree_cleanup(wt);
        return error_from_git(git_err);
    }

    /* Build array of storage paths for commit message */
    const char **storage_paths = malloc(file_count * sizeof(char *));
    if (!storage_paths) {
        git_tree_free(tree);
        worktree_cleanup(wt);
        return ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
    }

    for (size_t i = 0; i < file_count; i++) {
        storage_paths[i] = files[i].storage_path;
    }

    /* Build commit message context */
    commit_message_context_t ctx = {
        .action = COMMIT_ACTION_UPDATE,
        .profile = profile->name,
        .files = storage_paths,
        .file_count = file_count,
        .custom_msg = opts->message,
        .target_commit = NULL
    };

    char *message = build_commit_message(config, &ctx);
    free(storage_paths);

    if (!message) {
        git_tree_free(tree);
        worktree_cleanup(wt);
        return ERROR(ERR_MEMORY, "Failed to build commit message");
    }

    /* Create commit */
    git_oid commit_oid;
    err = gitops_create_commit(wt_repo, profile->name, tree, message, &commit_oid);

    free(message);
    git_tree_free(tree);

    if (err) {
        worktree_cleanup(wt);
        return error_wrap(err, "Failed to create commit");
    }

    /* Cleanup */
    worktree_cleanup(wt);

    return NULL;
}

/**
 * Detect new files in tracked directories
 *
 * Scans directories tracked in state for files not yet in the manifest.
 *
 * @param repo Repository (must not be NULL)
 * @param profiles Active profiles (must not be NULL)
 * @param state State with tracked directories (must not be NULL)
 * @param config Configuration (may be NULL)
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @param new_files Output list of new files (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *update_detect_new_files(
    git_repository *repo,
    profile_list_t *profiles,
    state_t *state,
    const dotta_config_t *config,
    const cmd_update_options_t *opts,
    output_ctx_t *out,
    new_file_list_t **new_files
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(state);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(new_files);

    error_t *err = NULL;
    manifest_t *manifest = NULL;
    new_file_list_t *list = NULL;

    list = new_file_list_create();
    if (!list) {
        return ERROR(ERR_MEMORY, "Failed to create new file list");
    }

    /* Build manifest for checking */
    err = profile_build_manifest(repo, profiles, &manifest);
    if (err) {
        new_file_list_free(list);
        return error_wrap(err, "Failed to build manifest");
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

            /* Find the profile for this directory */
            profile_t *dir_profile = NULL;
            for (size_t j = 0; j < profiles->count; j++) {
                if (strcmp(profiles->profiles[j].name, dir_entry->profile) == 0) {
                    dir_profile = &profiles->profiles[j];
                    break;
                }
            }

            if (!dir_profile) {
                continue;  /* Profile not active */
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
                dir_profile,
                manifest,
                ignore_ctx,
                list
            );

            /* Free ignore context */
            ignore_context_free(ignore_ctx);

            if (err) {
                /* Log warning but continue with other directories */
                if (opts->verbose) {
                    output_warning(out, "Failed to scan directory '%s': %s",
                                  dir_entry->filesystem_path, error_message(err));
                }
                error_free(err);
                err = NULL;
            }
        }
    }

    manifest_free(manifest);
    *new_files = list;
    return NULL;
}

/**
 * Display summary of files to be updated
 */
static void update_display_summary(
    output_ctx_t *out,
    const modified_file_list_t *modified,
    const new_file_list_t *new_files
) {
    if (!out || !modified) {
        return;
    }

    /* Show modified files */
    output_section(out, "Modified files");
    for (size_t i = 0; i < modified->count; i++) {
        modified_file_t *file = &modified->files[i];
        char info[1024];
        snprintf(info, sizeof(info), "%s (in %s)",
                file->filesystem_path, file->source_profile->name);

        const char *status_label = NULL;
        output_color_t color = OUTPUT_COLOR_YELLOW;

        switch (file->status) {
            case CMP_DIFFERENT:
                status_label = "[modified]";
                break;
            case CMP_MODE_DIFF:
                status_label = "[mode]";
                break;
            case CMP_TYPE_DIFF:
                status_label = "[type]";
                color = OUTPUT_COLOR_RED;
                break;
            case CMP_MISSING:
                status_label = "[deleted]";
                color = OUTPUT_COLOR_RED;
                break;
            default:
                status_label = "[?]";
                break;
        }

        output_item(out, status_label, color, info);
    }

    /* Show new files if any */
    if (new_files && new_files->count > 0) {
        output_section(out, "New files");
        for (size_t i = 0; i < new_files->count; i++) {
            new_file_t *file = &new_files->files[i];
            char info[1024];
            snprintf(info, sizeof(info), "%s (in %s)",
                    file->filesystem_path, file->source_profile->name);
            output_item(out, "[new]", OUTPUT_COLOR_CYAN, info);
        }
    }

    output_newline(out);
}

/**
 * Confirmation result codes
 */
typedef enum {
    CONFIRM_PROCEED,        /* Proceed with operation */
    CONFIRM_CANCELLED,      /* User cancelled */
    CONFIRM_DRY_RUN,        /* Dry run mode */
    CONFIRM_SKIP_NEW_FILES  /* Skip new files but continue */
} confirm_result_t;

/**
 * Handle user confirmations for update operation
 *
 * @param result Output parameter for confirmation result
 * @return Error or NULL on success (sets result)
 */
static error_t *update_confirm_operation(
    output_ctx_t *out,
    const cmd_update_options_t *opts,
    const modified_file_list_t *modified,
    const new_file_list_t *new_files,
    const dotta_config_t *config,
    confirm_result_t *result
) {
    CHECK_NULL(out);
    CHECK_NULL(opts);
    CHECK_NULL(modified);
    CHECK_NULL(result);

    *result = CONFIRM_PROCEED;

    /* Dry run - just show and exit */
    if (opts->dry_run) {
        size_t new_count = new_files ? new_files->count : 0;
        output_info(out, "Dry run: would update %zu modified file%s and add %zu new file%s",
                   modified->count, modified->count == 1 ? "" : "s",
                   new_count, new_count == 1 ? "" : "s");
        *result = CONFIRM_DRY_RUN;
        return NULL;
    }

    /* Interactive confirmation */
    if (opts->interactive) {
        printf("Update these files? [y/N] ");
        fflush(stdout);

        char response[10];
        if (!fgets(response, sizeof(response), stdin) ||
            (response[0] != 'y' && response[0] != 'Y')) {
            output_info(out, "Cancelled");
            *result = CONFIRM_CANCELLED;
            return NULL;
        }
    }

    /* Confirmation for new files (if auto-detected via config, not explicit flag) */
    if (new_files && new_files->count > 0 &&
        config && config->confirm_new_files &&
        !opts->include_new && !opts->only_new &&
        config->auto_detect_new_files) {

        printf("\nFound %zu new file%s. Add %s to profiles? [y/N] ",
               new_files->count, new_files->count == 1 ? "" : "s",
               new_files->count == 1 ? "it" : "them");
        fflush(stdout);

        char response[10];
        if (!fgets(response, sizeof(response), stdin) ||
            (response[0] != 'y' && response[0] != 'Y')) {
            /* Skip new files but continue with modified */
            *result = CONFIRM_SKIP_NEW_FILES;
            return NULL;
        }
    }

    *result = CONFIRM_PROCEED;
    return NULL;
}

/**
 * Execute profile updates for all profiles
 */
static error_t *update_execute_for_all_profiles(
    git_repository *repo,
    profile_list_t *profiles,
    modified_file_list_t *modified,
    new_file_list_t *new_files,
    const cmd_update_options_t *opts,
    output_ctx_t *out,
    const dotta_config_t *config,
    size_t *total_updated
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(modified);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(total_updated);

    *total_updated = 0;

    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];

        /* Collect files for this profile */
        size_t profile_file_count = 0;
        modified_file_t *profile_files = NULL;

        /* Count modified files for this profile */
        for (size_t j = 0; j < modified->count; j++) {
            if (modified->files[j].source_profile == profile) {
                profile_file_count++;
            }
        }

        /* Count new files for this profile */
        size_t new_file_count_for_profile = 0;
        if (new_files) {
            for (size_t j = 0; j < new_files->count; j++) {
                if (new_files->files[j].source_profile == profile) {
                    new_file_count_for_profile++;
                }
            }
        }

        size_t total_file_count = profile_file_count + new_file_count_for_profile;

        if (total_file_count == 0) {
            continue;
        }

        /* Allocate array for this profile's files (modified + new) */
        profile_files = calloc(total_file_count, sizeof(modified_file_t));
        if (!profile_files) {
            return ERROR(ERR_MEMORY, "Failed to allocate profile files");
        }

        /* Copy modified file entries */
        size_t idx = 0;
        for (size_t j = 0; j < modified->count; j++) {
            if (modified->files[j].source_profile == profile) {
                profile_files[idx++] = modified->files[j];
            }
        }

        /* Add new files as modified entries (they'll be copied and staged) */
        if (new_files) {
            for (size_t j = 0; j < new_files->count; j++) {
                new_file_t *new_file = &new_files->files[j];
                if (new_file->source_profile == profile) {
                    /* Convert new_file to modified_file format */
                    profile_files[idx].filesystem_path = new_file->filesystem_path;
                    profile_files[idx].storage_path = new_file->storage_path;
                    profile_files[idx].source_profile = new_file->source_profile;
                    profile_files[idx].status = CMP_DIFFERENT;  /* Treat as modified/new */
                    idx++;
                }
            }
        }

        /* Update this profile */
        char *colored_name = output_colorize(out, OUTPUT_COLOR_CYAN, profile->name);
        if (colored_name) {
            output_info(out, "Updating profile '%s':", colored_name);
            free(colored_name);
        } else {
            output_info(out, "Updating profile '%s':", profile->name);
        }

        error_t *err = update_profile(repo, profile, profile_files, total_file_count, opts, out, config);
        free(profile_files);

        if (err) {
            return error_wrap(err, "Failed to update profile '%s'", profile->name);
        }

        *total_updated += total_file_count;

        if (!opts->verbose) {
            output_success(out, "  Updated %zu file%s",
                          total_file_count, total_file_count == 1 ? "" : "s");
        }
    }

    return NULL;
}

/**
 * Update command implementation
 */
error_t *cmd_update(git_repository *repo, const cmd_update_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;
    profile_list_t *profiles = NULL;
    modified_file_list_t *modified = NULL;
    new_file_list_t *new_files = NULL;
    state_t *state = NULL;
    bool should_detect_new = false;
    bool skip_new_files = false;
    size_t total_updated = 0;

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        error_free(err);
        err = NULL;
        config = config_create_default();
        if (!config) {
            err = ERROR(ERR_MEMORY, "Failed to create default configuration");
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

    /* Load profiles with config fallback */
    err = profile_resolve(repo, opts->profiles, opts->profile_count,
                         config, config->strict_mode, &profiles, NULL);

    if (err) {
        err = error_wrap(err, "Failed to load profiles");
        goto cleanup;
    }

    if (profiles->count == 0) {
        err = ERROR(ERR_NOT_FOUND, "No profiles found");
        goto cleanup;
    }

    /* Determine if we should detect new files */
    should_detect_new = opts->include_new || opts->only_new || config->auto_detect_new_files;

    /* Load state for new file detection */
    if (should_detect_new) {
        err = state_load(repo, &state);
        if (err) {
            err = error_wrap(err, "Failed to load state");
            goto cleanup;
        }
    }

    /* Find modified files (unless only_new is set) */
    if (!opts->only_new) {
        err = find_modified_files(repo, profiles, opts, &modified);
        if (err) {
            goto cleanup;
        }
    } else {
        /* Create empty list when only processing new files */
        modified = modified_file_list_create();
        if (!modified) {
            err = ERROR(ERR_MEMORY, "Failed to create modified file list");
            goto cleanup;
        }
    }

    /* Detect new files if requested (by flag or config) */
    if (should_detect_new) {
        err = update_detect_new_files(repo, profiles, state, config, opts, out, &new_files);
        if (err) {
            err = error_wrap(err, "Failed to detect new files");
            goto cleanup;
        }
    }

    /* Check if we have anything to update */
    size_t total_count = modified->count + (new_files ? new_files->count : 0);
    if (total_count == 0) {
        if (opts->only_new) {
            output_info(out, "No new files to add");
        } else if (opts->include_new) {
            output_info(out, "No modified or new files to update");
        } else {
            output_info(out, "No modified files to update");
        }
        err = NULL;  /* Not an error */
        goto cleanup;
    }

    /* Display summary of files to update */
    update_display_summary(out, modified, new_files);

    /* Handle user confirmations */
    confirm_result_t confirm_result;
    err = update_confirm_operation(out, opts, modified, new_files, config, &confirm_result);
    if (err) {
        goto cleanup;
    }

    /* Handle confirmation result */
    switch (confirm_result) {
        case CONFIRM_CANCELLED:
        case CONFIRM_DRY_RUN:
            /* User cancelled or dry run - clean exit (not an error) */
            goto cleanup;

        case CONFIRM_SKIP_NEW_FILES:
            /* User declined new files - continue with modified files only */
            output_info(out, "Skipping new files");
            skip_new_files = true;
            new_file_list_free(new_files);
            new_files = NULL;

            /* If no modified files, nothing left to do */
            if (modified->count == 0) {
                goto cleanup;
            }
            break;

        case CONFIRM_PROCEED:
            /* Continue with operation */
            break;
    }

    /* Execute profile updates */
    err = update_execute_for_all_profiles(repo, profiles, modified,
                                          skip_new_files ? NULL : new_files,
                                          opts, out, config, &total_updated);
    if (err) {
        goto cleanup;
    }

    /* Summary */
    output_newline(out);
    output_success(out, "Updated %zu file%s across %zu profile%s",
                   total_updated, total_updated == 1 ? "" : "s",
                   profiles->count, profiles->count == 1 ? "" : "s");

cleanup:
    /* Add trailing newline for UX consistency */
    if (out) {
        output_newline(out);
    }

    /* Free all resources in reverse order */
    if (state) state_free(state);
    if (new_files) new_file_list_free(new_files);
    if (modified) modified_file_list_free(modified);
    if (profiles) profile_list_free(profiles);
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}
