/**
 * update.c - Update profiles with modified files
 */

#include "update.h"

#include <dirent.h>
#include <fnmatch.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/workspace.h"
#include "crypto/keymanager.h"
#include "crypto/policy.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "infra/worktree.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/hooks.h"
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
 * Check if path should be excluded by CLI patterns
 *
 * Simple pattern matching for temporary per-operation filtering
 */
static bool is_excluded(
    const char *path,
    const cmd_update_options_t *opts
) {
    if (!path || !opts->exclude_patterns || opts->exclude_count == 0) {
        return false;
    }

    /* Extract basename for pattern matching */
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;

    /* Check each exclude pattern */
    for (size_t i = 0; i < opts->exclude_count; i++) {
        const char *pattern = opts->exclude_patterns[i];

        /* Try matching against full path */
        if (fnmatch(pattern, path, 0) == 0) {
            return true;
        }

        /* Try matching against basename */
        if (fnmatch(pattern, basename, 0) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Find all modified and new files using workspace divergence analysis
 *
 * This function uses the workspace module to detect divergence between
 * profile state, deployment state, and filesystem state. It correctly
 * distinguishes between:
 * - MODIFIED: Files deployed and changed on disk (modified files)
 * - DELETED: Files deployed and removed from disk (modified files)
 * - MODE_DIFF: Files with permission changes (modified files)
 * - TYPE_DIFF: Files with type changes (modified files)
 * - UNTRACKED: New files in tracked directories (new files)
 * - UNDEPLOYED: Files in profile but never deployed (skip - not a modification)
 * - ORPHANED: State cleanup issues (skip - not file updates)
 *
 * This single workspace load efficiently provides both modified and new files,
 * eliminating the need for separate scanning logic.
 *
 * The --exclude patterns are applied as a simple post-filter on the detected files.
 */
static error_t *find_modified_and_new_files(
    git_repository *repo,
    profile_list_t *profiles,
    const dotta_config_t *config,
    const cmd_update_options_t *opts,
    output_ctx_t *out,
    modified_file_list_t **modified_out,
    new_file_list_t **new_out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(opts);
    CHECK_NULL(modified_out);
    CHECK_NULL(new_out);

    modified_file_list_t *modified = modified_file_list_create();
    if (!modified) {
        return ERROR(ERR_MEMORY, "Failed to create modified file list");
    }

    new_file_list_t *new_files = new_file_list_create();
    if (!new_files) {
        modified_file_list_free(modified);
        return ERROR(ERR_MEMORY, "Failed to create new file list");
    }

    /* Load workspace to analyze ALL divergence (modified + new) */
    workspace_t *ws = NULL;
    error_t *err = workspace_load(repo, profiles, config, &ws);
    if (err) {
        modified_file_list_free(modified);
        new_file_list_free(new_files);
        return error_wrap(err, "Failed to load workspace");
    }

    /* Process each category of divergence separately */
    divergence_type_t modification_types[] = {
        DIVERGENCE_MODIFIED,
        DIVERGENCE_DELETED,
        DIVERGENCE_MODE_DIFF,
        DIVERGENCE_TYPE_DIFF
    };

    compare_result_t cmp_results[] = {
        CMP_DIFFERENT,
        CMP_MISSING,
        CMP_MODE_DIFF,
        CMP_TYPE_DIFF
    };

    /* Process modified/deleted/mode/type changes */
    for (size_t t = 0; t < 4; t++) {
        size_t count = 0;
        const workspace_file_t **files = workspace_get_diverged(ws, modification_types[t], &count);

        for (size_t i = 0; i < count; i++) {
            const workspace_file_t *file = files[i];

            /* Apply file filter if specified */
            if (!file_matches_filter(file->filesystem_path, opts)) {
                continue;
            }

            /* Check exclude patterns */
            if (is_excluded(file->filesystem_path, opts)) {
                if (opts->verbose && out) {
                    output_info(out, "Excluded: %s", file->filesystem_path);
                }
                continue;
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
                /* Profile not in enabled set - skip */
                continue;
            }

            /* Add to modified list */
            err = modified_file_list_add(
                modified,
                file->filesystem_path,
                file->storage_path,
                source_profile,
                cmp_results[t]
            );

            if (err) {
                free(files);
                workspace_free(ws);
                modified_file_list_free(modified);
                new_file_list_free(new_files);
                return err;
            }
        }

        free(files);  /* Free the allocated pointer array */
    }

    /* Process untracked (new) files */
    size_t untracked_count = 0;
    const workspace_file_t **untracked_files = workspace_get_diverged(ws, DIVERGENCE_UNTRACKED, &untracked_count);

    for (size_t i = 0; i < untracked_count; i++) {
        const workspace_file_t *file = untracked_files[i];

        /* Apply file filter if specified */
        if (!file_matches_filter(file->filesystem_path, opts)) {
            continue;
        }

        /* Check exclude patterns */
        if (is_excluded(file->filesystem_path, opts)) {
            if (opts->verbose && out) {
                output_info(out, "Excluded: %s", file->filesystem_path);
            }
            continue;
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
            /* Profile not in enabled set - skip */
            continue;
        }

        /* Add to new files list */
        err = new_file_list_add(new_files, file->filesystem_path,
                               file->storage_path, source_profile);
        if (err) {
            free(untracked_files);
            workspace_free(ws);
            modified_file_list_free(modified);
            new_file_list_free(new_files);
            return err;
        }
    }

    free(untracked_files);  /* Free the allocated pointer array */

    workspace_free(ws);
    *modified_out = modified;
    *new_out = new_files;
    return NULL;
}

/**
 * Copy file from filesystem to worktree (with optional encryption)
 *
 * @param out_was_encrypted Optional output - set to true if file was encrypted (can be NULL)
 */
static error_t *copy_file_to_worktree(
    worktree_handle_t *wt,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile_name,
    keymanager_t *km,
    const dotta_config_t *config,
    const metadata_t *metadata,
    bool *out_was_encrypted
) {
    CHECK_NULL(wt);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);

    /* Initialize all resources to NULL for goto cleanup */
    char *dest_path = NULL;
    char *parent = NULL;
    char *target = NULL;
    error_t *err = NULL;

    const char *wt_path = worktree_get_path(wt);
    if (!wt_path) {
        return ERROR(ERR_INTERNAL, "Worktree path is NULL");
    }

    dest_path = str_format("%s/%s", wt_path, storage_path);
    if (!dest_path) {
        err = ERROR(ERR_MEMORY, "Failed to allocate destination path");
        goto cleanup;
    }

    /* Create parent directory */
    err = fs_get_parent_dir(dest_path, &parent);
    if (err) {
        goto cleanup;
    }

    err = fs_create_dir(parent, true);
    if (err) {
        err = error_wrap(err, "Failed to create parent directory");
        goto cleanup;
    }

    /* Remove existing file if present */
    if (fs_lexists(dest_path)) {
        err = fs_remove_file(dest_path);
        if (err) {
            err = error_wrap(err, "Failed to remove existing file");
            goto cleanup;
        }
    }

    /* Copy file (with optional encryption) */
    if (fs_is_symlink(filesystem_path)) {
        /* Handle symlink - no encryption for symlinks */
        err = fs_read_symlink(filesystem_path, &target);
        if (err) {
            err = error_wrap(err, "Failed to read symlink");
            goto cleanup;
        }

        err = fs_create_symlink(target, dest_path);
        if (err) {
            err = error_wrap(err, "Failed to create symlink");
            goto cleanup;
        }

        /* Symlinks are never encrypted */
        if (out_was_encrypted) {
            *out_was_encrypted = false;
        }
    } else {
        /* Handle regular file - determine encryption policy using centralized logic
         *
         * The policy function handles the critical "maintain encryption" logic:
         * If file was previously encrypted, it stays encrypted (security-critical).
         */
        bool should_encrypt = false;
        err = encryption_policy_should_encrypt(
            config,
            storage_path,
            false,           /* No explicit --encrypt flag in update.c */
            false,           /* No explicit --no-encrypt flag in update.c */
            metadata,        /* Critical: checks previous encryption state */
            &should_encrypt
        );
        if (err) {
            err = error_wrap(err, "Failed to determine encryption policy for '%s'", storage_path);
            goto cleanup;
        }

        /* Store file to worktree with optional encryption (handles read → encrypt → write) */
        err = content_store_file_to_worktree(
            filesystem_path,
            dest_path,
            storage_path,
            profile_name,
            km,
            should_encrypt
        );
        if (err) {
            err = error_wrap(err, "Failed to store file to worktree");
            goto cleanup;
        }

        /* Propagate encryption status to caller */
        if (out_was_encrypted) {
            *out_was_encrypted = should_encrypt;
        }
    }

cleanup:
    if (target) free(target);
    if (parent) free(parent);
    if (dest_path) free(dest_path);
    return err;
}

/**
 * Capture and save metadata for updated files
 *
 * @param encryption_status Encryption status for each file (can be NULL)
 */
static error_t *capture_and_save_metadata(
    worktree_handle_t *wt,
    modified_file_t *files,
    size_t file_count,
    const bool *encryption_status,
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
            /* Use tracked encryption status from copy_file_to_worktree() */
            if (encryption_status) {
                entry->encrypted = encryption_status[i];
            } else {
                /* Fallback: assume plaintext if no tracked status */
                entry->encrypted = false;
            }

            /* Save metadata before adding (for verbose output) */
            mode_t mode = entry->mode;
            char *owner = entry->owner ? strdup(entry->owner) : NULL;
            char *group = entry->group ? strdup(entry->group) : NULL;
            bool is_encrypted = entry->encrypted;

            /* Add to metadata collection (copies all fields including owner/group and encryption) */
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
                    printf("Captured metadata: %s (mode: %04o, owner: %s:%s%s)\n",
                          file->filesystem_path, mode,
                          owner ? owner : "?",
                          group ? group : "?",
                          is_encrypted ? ", encrypted" : "");
                } else {
                    printf("Captured metadata: %s (mode: %04o%s)\n",
                          file->filesystem_path, mode,
                          is_encrypted ? ", encrypted" : "");
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
        git_index_free(index);
        return error_from_git(git_err);
    }

    git_err = git_index_write(index);
    git_index_free(index);
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

    /* Initialize all resources to NULL for goto cleanup */
    worktree_handle_t *wt = NULL;
    git_index *index = NULL;
    git_tree *tree = NULL;
    const char **storage_paths = NULL;
    char *message = NULL;
    error_t *err = NULL;
    git_repository *wt_repo = NULL;
    metadata_t *existing_metadata = NULL;
    keymanager_t *key_mgr = NULL;
    bool *encryption_status = NULL;

    /* Load existing metadata from profile branch (for encryption status) */
    err = metadata_load_from_branch(repo, profile->name, &existing_metadata);
    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            /* No existing metadata - that's OK, create empty */
            error_free(err);
            err = metadata_create_empty(&existing_metadata);
            if (err) {
                return error_wrap(err, "Failed to create empty metadata");
            }
        } else {
            /* Real error */
            return error_wrap(err, "Failed to load metadata from profile '%s'", profile->name);
        }
    }

    /* Get keymanager if encryption may be needed
     *
     * Keymanager handles profile key caching internally, so files will reuse
     * the same derived key without redundant derivations (O(1) after first derivation).
     *
     * Get keymanager if EITHER:
     *   1. Profile has encrypted files (need to maintain encryption when updating)
     *   2. Auto-encrypt patterns configured (files may match patterns)
     */
    bool needs_encryption = false;

    /* Check if any existing files are encrypted */
    if (existing_metadata && config && config->encryption_enabled) {
        for (size_t i = 0; i < existing_metadata->count; i++) {
            if (existing_metadata->entries[i].encrypted) {
                needs_encryption = true;
                break;
            }
        }
    }

    /* Check if auto-encrypt patterns are configured */
    if (!needs_encryption && config && config->encryption_enabled &&
        config->auto_encrypt_patterns && config->auto_encrypt_pattern_count > 0) {
        needs_encryption = true;
    }

    if (needs_encryption && config && config->encryption_enabled) {
        key_mgr = keymanager_get_global(config);
        if (!key_mgr) {
            if (existing_metadata) metadata_free(existing_metadata);
            return ERROR(ERR_INTERNAL, "Failed to get encryption key manager");
        }
    }

    /* Create temporary worktree */
    err = worktree_create_temp(repo, &wt);
    if (err) {
        err = error_wrap(err, "Failed to create temporary worktree");
        goto cleanup;
    }

    /* Checkout profile branch */
    err = worktree_checkout_branch(wt, profile->name);
    if (err) {
        err = error_wrap(err, "Failed to checkout profile '%s'", profile->name);
        goto cleanup;
    }

    /* Allocate encryption status tracking array */
    encryption_status = calloc(file_count, sizeof(bool));
    if (!encryption_status) {
        err = ERROR(ERR_MEMORY, "Failed to allocate encryption status array");
        goto cleanup;
    }

    /* Copy each modified file to worktree and stage */
    err = worktree_get_index(wt, &index);
    if (err) {
        err = error_wrap(err, "Failed to get worktree index");
        goto cleanup;
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
                err = error_from_git(git_err);
                goto cleanup;
            }
            continue;
        }

        /* Copy to worktree (encryption handled transparently by content layer) */
        err = copy_file_to_worktree(
            wt,
            file->filesystem_path,
            file->storage_path,
            profile->name,
            key_mgr,
            config,
            existing_metadata,
            &encryption_status[i]
        );
        if (err) {
            err = error_wrap(err, "Failed to copy '%s'", file->filesystem_path);
            goto cleanup;
        }

        /* Stage file */
        int git_err = git_index_add_bypath(index, file->storage_path);
        if (git_err < 0) {
            err = error_from_git(git_err);
            goto cleanup;
        }
    }

    /* Capture and save metadata for updated files */
    err = capture_and_save_metadata(wt, files, file_count, encryption_status, opts->verbose);
    if (err) {
        err = error_wrap(err, "Failed to capture metadata");
        goto cleanup;
    }

    /* Note: metadata capture function already wrote the index */

    /* Create commit */
    git_oid tree_oid;
    int git_err = git_index_write_tree(&tree_oid, index);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    wt_repo = worktree_get_repo(wt);
    git_err = git_tree_lookup(&tree, wt_repo, &tree_oid);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Build array of storage paths for commit message */
    storage_paths = malloc(file_count * sizeof(char *));
    if (!storage_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
        goto cleanup;
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

    message = build_commit_message(config, &ctx);
    if (!message) {
        err = ERROR(ERR_MEMORY, "Failed to build commit message");
        goto cleanup;
    }

    /* Create commit */
    git_oid commit_oid;
    err = gitops_create_commit(wt_repo, profile->name, tree, message, &commit_oid);
    if (err) {
        err = error_wrap(err, "Failed to create commit");
        goto cleanup;
    }

cleanup:
    /* Free resources in reverse order */
    if (message) free(message);
    if (storage_paths) free(storage_paths);
    if (tree) git_tree_free(tree);
    if (index) git_index_free(index);
    if (wt) worktree_cleanup(wt);
    if (existing_metadata) metadata_free(existing_metadata);
    if (encryption_status) free(encryption_status);

    return err;
}

/**
 * Display summary of files to be updated
 */
static void update_display_summary(
    output_ctx_t *out,
    const modified_file_list_t *modified,
    const new_file_list_t *new_files,
    git_repository *repo
) {
    if (!out || !modified) {
        return;
    }

    /* Track multi-profile files for warning */
    size_t multi_profile_count = 0;

    /* Build profile file index once for O(M×P) instead of O(N×M×GitOps)
     * This is a massive performance improvement for repos with many profiles */
    hashmap_t *profile_index = NULL;

    /* Show modified files */
    output_section(out, "Modified files");
    for (size_t i = 0; i < modified->count; i++) {
        modified_file_t *file = &modified->files[i];

        /* Lazy-build index on first file needing multi-profile check */
        if (!profile_index && i == 0) {
            error_t *err = profile_build_file_index(repo, NULL, &profile_index);
            if (err) {
                /* Non-fatal: continue without multi-profile detection */
                error_free(err);
                profile_index = NULL;
            }
        }

        /* Check if file exists in other profiles using O(1) index lookup */
        string_array_t *other_profiles = NULL;
        if (profile_index) {
            string_array_t *indexed_profiles = hashmap_get(profile_index, file->storage_path);
            if (indexed_profiles && string_array_size(indexed_profiles) > 0) {
                /* Create filtered copy excluding the source profile */
                other_profiles = string_array_create();
                if (other_profiles) {
                    for (size_t j = 0; j < string_array_size(indexed_profiles); j++) {
                        const char *profile_name = string_array_get(indexed_profiles, j);
                        /* Skip the source profile */
                        if (strcmp(profile_name, file->source_profile->name) != 0) {
                            string_array_push(other_profiles, profile_name);
                        }
                    }
                }
            }
        }

        /* Build info string using dynamic buffer to avoid overflow */
        buffer_t *info_buf = buffer_create();
        if (!info_buf) {
            string_array_free(other_profiles);
            continue;  /* Skip this file on memory error */
        }

        if (other_profiles && string_array_size(other_profiles) > 0) {
            /* File exists in multiple profiles - add warning indicator */
            buffer_append_string(info_buf, file->filesystem_path);
            buffer_append_string(info_buf, " (in ");
            buffer_append_string(info_buf, file->source_profile->name);
            buffer_append_string(info_buf, ") ");
            buffer_append_string(info_buf, output_color_code(out, OUTPUT_COLOR_DIM));
            buffer_append_string(info_buf, "[also in:");

            for (size_t j = 0; j < string_array_size(other_profiles); j++) {
                buffer_append_string(info_buf, " ");
                buffer_append_string(info_buf, string_array_get(other_profiles, j));
            }

            buffer_append_string(info_buf, "]");
            buffer_append_string(info_buf, output_color_code(out, OUTPUT_COLOR_RESET));

            multi_profile_count++;
        } else {
            buffer_append_string(info_buf, file->filesystem_path);
            buffer_append_string(info_buf, " (in ");
            buffer_append_string(info_buf, file->source_profile->name);
            buffer_append_string(info_buf, ")");
        }

        /* Release buffer as null-terminated string */
        char *info = NULL;
        error_t *release_err = buffer_release_data(info_buf, &info);
        if (release_err) {
            error_free(release_err);
            string_array_free(other_profiles);
            continue;  /* Skip this file on error */
        }

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

        free(info);
        string_array_free(other_profiles);
    }

    /* Free the profile index */
    if (profile_index) {
        hashmap_free(profile_index, (void (*)(void *))string_array_free);
    }

    /* Show multi-profile warning if needed */
    if (multi_profile_count > 0) {
        output_newline(out);
        output_warning(out, "%zu file%s exist%s in multiple profiles",
                      multi_profile_count,
                      multi_profile_count == 1 ? "" : "s",
                      multi_profile_count == 1 ? "s" : "");
        output_info(out, "  Updates will be committed to the profile that deployed them (shown above).");
        output_info(out, "  To update a different profile, remove the file from the current profile first.");
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

        printf("Found %zu new file%s. Add %s to profiles? [y/N] ",
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
    hook_context_t *hook_ctx = NULL;
    char *repo_dir = NULL;
    char *profiles_str = NULL;
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

    /* Load profiles */
    err = profile_resolve(repo, opts->profiles, opts->profile_count,
                         config->strict_mode, &profiles, NULL);

    if (err) {
        err = error_wrap(err, "Failed to load profiles");
        goto cleanup;
    }

    if (profiles->count == 0) {
        err = ERROR(ERR_NOT_FOUND, "No profiles found");
        goto cleanup;
    }

    /* Get repository directory for hooks */
    err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        goto cleanup;
    }

    /* Execute pre-update hook */
    if (config && repo_dir) {
        /* Build array of profile names and join with spaces */
        const char **profile_names_array = malloc(profiles->count * sizeof(char *));
        if (profile_names_array) {
            for (size_t i = 0; i < profiles->count; i++) {
                profile_names_array[i] = profiles->profiles[i].name;
            }
            profiles_str = str_join(profile_names_array, profiles->count, " ");
            free(profile_names_array);
        }

        if (profiles_str) {
            /* Create hook context with all profiles */
            hook_ctx = hook_context_create(repo_dir, "update", profiles_str);
            if (hook_ctx) {
                hook_ctx->dry_run = opts->dry_run;
                hook_context_add_files(hook_ctx, opts->files, opts->file_count);

                hook_result_t *hook_result = NULL;
                err = hook_execute(config, HOOK_PRE_UPDATE, hook_ctx, &hook_result);

                if (err) {
                    /* Hook failed - abort operation */
                    if (hook_result && hook_result->output && hook_result->output[0]) {
                        output_printf(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
                    }
                    hook_result_free(hook_result);
                    err = error_wrap(err, "Pre-update hook failed");
                    goto cleanup;
                }
                hook_result_free(hook_result);
            }
        }
    }

    /* Determine if we should detect new files */
    should_detect_new = opts->include_new || opts->only_new || config->auto_detect_new_files;

    /* Find diverged files (modified + new) using unified workspace analysis */
    err = find_modified_and_new_files(repo, profiles, config, opts, out, &modified, &new_files);
    if (err) {
        err = error_wrap(err, "Failed to analyze divergence");
        goto cleanup;
    }

    /* Filter new files based on detection settings */
    if (!should_detect_new && new_files) {
        /* User didn't request new file detection - discard them */
        new_file_list_free(new_files);
        new_files = NULL;
    }

    /* Handle only_new flag - discard modified files if set */
    if (opts->only_new && modified) {
        modified_file_list_free(modified);
        modified = modified_file_list_create();
        if (!modified) {
            err = ERROR(ERR_MEMORY, "Failed to create modified file list");
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
    update_display_summary(out, modified, new_files, repo);

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

    /* Execute post-update hook */
    if (hook_ctx && !opts->dry_run) {
        hook_result_t *hook_result = NULL;
        error_t *hook_err = hook_execute(config, HOOK_POST_UPDATE, hook_ctx, &hook_result);

        if (hook_err) {
            /* Hook failed - warn but don't abort (files already updated) */
            output_warning(out, "Post-update hook failed: %s", error_message(hook_err));
            if (hook_result && hook_result->output && hook_result->output[0]) {
                output_printf(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
            }
            error_free(hook_err);
        }
        hook_result_free(hook_result);
    }

    /* Summary */
    output_newline(out);
    output_success(out, "Updated %zu file%s across %zu profile%s",
                   total_updated, total_updated == 1 ? "" : "s",
                   profiles->count, profiles->count == 1 ? "" : "s");

cleanup:
    /* Free all resources in reverse order */
    if (profiles_str) free(profiles_str);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (repo_dir) free(repo_dir);
    if (new_files) new_file_list_free(new_files);
    if (modified) modified_file_list_free(modified);
    if (profiles) profile_list_free(profiles);
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}
