/**
 * update.c - Update profiles with modified files
 */

#include "update.h"

#include <dirent.h>
#include <errno.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "core/workspace.h"
#include "crypto/keymanager.h"
#include "crypto/policy.h"
#include "infra/content.h"
#include "infra/path.h"
#include "infra/worktree.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/hooks.h"
#include "utils/match.h"
#include "utils/output.h"
#include "utils/privilege.h"
#include "utils/string.h"

/**
 * Copy file from filesystem to worktree (with optional encryption)
 *
 * @param out_was_encrypted Optional output - set to true if file was encrypted (can be NULL)
 * @param out_stat Optional output - filled with stat data from source file (can be NULL)
 */
static error_t *copy_file_to_worktree(
    worktree_handle_t *wt,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile_name,
    keymanager_t *km,
    const dotta_config_t *config,
    const metadata_t *metadata,
    bool *out_was_encrypted,
    struct stat *out_stat
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

        /* Store file to worktree and capture stat atomically
         * ARCHITECTURE: Single lstat() inside content_store_file_to_worktree() is captured
         * and propagated to caller for metadata operations, eliminating race condition. */
        struct stat file_stat;
        err = content_store_file_to_worktree(
            filesystem_path,
            dest_path,
            storage_path,
            profile_name,
            km,
            should_encrypt,
            &file_stat  /* Capture stat for metadata - eliminates race condition */
        );
        if (err) {
            err = error_wrap(err, "Failed to store file to worktree");
            goto cleanup;
        }

        /* Propagate stat to caller if requested */
        if (out_stat) {
            memcpy(out_stat, &file_stat, sizeof(struct stat));
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
 * Confirmation result codes
 */
typedef enum {
    CONFIRM_PROCEED,        /* Proceed with operation */
    CONFIRM_CANCELLED,      /* User cancelled */
    CONFIRM_DRY_RUN,        /* Dry run mode */
    CONFIRM_SKIP_NEW_FILES  /* Skip new files but continue */
} confirm_result_t;

/**
 * Item array for profile grouping
 *
 * Lightweight container for grouping workspace items by profile.
 * Contains only borrowed pointers to workspace-owned items - no duplication.
 *
 * Memory ownership:
 * - items: owned array of pointers (must free)
 * - items[i]: borrowed pointers from workspace (do not free)
 */
typedef struct {
    const workspace_item_t **items;  /* Borrowed pointers from workspace */
    size_t count;
    size_t capacity;
} item_array_t;

/**
 * Free item array
 *
 * Frees the array structure and pointer array, but NOT the pointed-to items
 * (which are owned by the workspace).
 *
 * Generic callback signature for use with containers (e.g., hashmap_free).
 * Accepts void* to match standard C cleanup callback pattern.
 *
 * @param ptr Array to free (can be NULL)
 */
static void item_array_free(void *ptr) {
    item_array_t *array = ptr;
    if (!array) {
        return;
    }
    free(array->items);  /* Free pointer array only */
    free(array);
}

/**
 * Check if file matches CLI filter (if any)
 *
 * Helper function for filter_items_for_update().
 */
static bool matches_file_filter(
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
 * Helper function for filter_items_for_update().
 */
static bool matches_exclude_pattern(
    const char *path,
    const cmd_update_options_t *opts
) {
    if (!path || !opts->exclude_patterns || opts->exclude_count == 0) {
        return false;
    }

    /* Use match module for gitignore-style pattern matching */
    return match_any(
        opts->exclude_patterns,
        opts->exclude_count,
        path,
        MATCH_DOUBLESTAR  /* Enable ** support */
    );
}

/**
 * Filter workspace items relevant for update command
 *
 * Returns items that should be updated based on command options, workspace state, and divergence.
 *
 * INCLUDED ITEMS (STATE + DIVERGENCE):
 * - DEPLOYED + any divergence (content/mode/ownership/encryption/type changed)
 * - DELETED state (removed from filesystem)
 * - UNTRACKED state (new files, if flags OR config->auto_detect_new_files)
 *
 * EXCLUDED ITEMS:
 * - UNDEPLOYED state (not modified, just not deployed yet - handled by apply)
 * - ORPHANED state (handled by remove command)
 * - DEPLOYED + NONE divergence (clean, nothing to update)
 *
 * CLI FILTERS APPLIED:
 * - opts->files: Only specific files (if provided)
 * - opts->exclude_patterns: Gitignore-style exclusions
 * - opts->only_new: Only untracked files (excludes modified)
 *
 * CRITICAL CORRECTNESS REQUIREMENTS:
 * 1. UNTRACKED state: Include when flags OR auto_detect is enabled
 *    Flags (--include-new, --only-new) bypass confirmation
 *    Auto-detect includes them for later confirmation prompt
 *
 * 2. MODE/OWNERSHIP divergence: Apply to BOTH files AND directories
 *    Files can have metadata-only changes (e.g., chmod without content change)
 *
 * @param ws Workspace (must not be NULL)
 * @param opts Update options (must not be NULL)
 * @param config Configuration (can be NULL, used for auto_detect_new_files)
 * @param out Output context (for verbose logging, can be NULL)
 * @param out_items Output array of pointers to workspace_item_t (must not be NULL, caller must free array)
 * @param count_out Output count (must not be NULL)
 * @return Error or NULL on success (out_items will be NULL if no matches)
 */
static error_t *filter_items_for_update(
    const workspace_t *ws,
    const cmd_update_options_t *opts,
    const dotta_config_t *config,
    output_ctx_t *out,
    const workspace_item_t ***out_items,
    size_t *count_out
) {
    CHECK_NULL(ws);
    CHECK_NULL(opts);
    CHECK_NULL(out_items);
    CHECK_NULL(count_out);

    *out_items = NULL;
    *count_out = 0;

    /* Get all diverged items from workspace */
    size_t all_count = 0;
    const workspace_item_t *all = workspace_get_all_diverged(ws, &all_count);

    if (!all || all_count == 0) {
        return NULL;  /* No items - not an error */
    }

    /* First pass: count items that match filter criteria */
    size_t match_count = 0;

    for (size_t i = 0; i < all_count; i++) {
        const workspace_item_t *item = &all[i];
        bool should_include = false;

        /* Determine if item should be included based on state + divergence */
        switch (item->state) {
            case WORKSPACE_STATE_DEPLOYED:
                /* Deployed files/dirs with divergence - check what kind */
                if (item->divergence != DIVERGENCE_NONE) {
                    /* Has some divergence (content/mode/ownership/encryption/type) */
                    should_include = !opts->only_new;
                }
                /* DEPLOYED + NONE = clean, exclude */
                break;

            case WORKSPACE_STATE_DELETED:
                /* File removed from filesystem - include unless --only-new */
                should_include = !opts->only_new;
                break;

            case WORKSPACE_STATE_UNTRACKED:
                /* New files - include if:
                 * - Explicit flags set (--include-new or --only-new), OR
                 * - Config auto_detect_new_files is enabled (for confirmation prompt) */
                should_include = (opts->include_new || opts->only_new ||
                                 (config && config->auto_detect_new_files));
                break;

            case WORKSPACE_STATE_UNDEPLOYED:
            case WORKSPACE_STATE_ORPHANED:
                /* Not relevant for update command:
                 * - UNDEPLOYED: handled by apply command
                 * - ORPHANED: handled by remove command */
                should_include = false;
                break;
        }

        if (!should_include) {
            continue;
        }

        /* Apply CLI file filter */
        if (!matches_file_filter(item->filesystem_path, opts)) {
            continue;
        }

        /* Apply exclusion patterns */
        if (matches_exclude_pattern(item->filesystem_path, opts)) {
            if (opts->verbose && out) {
                output_info(out, "Excluded: %s", item->filesystem_path);
            }
            continue;
        }

        match_count++;
    }

    if (match_count == 0) {
        return NULL;  /* No matches - not an error */
    }

    /* Second pass: allocate and populate result array */
    const workspace_item_t **results = calloc(match_count, sizeof(workspace_item_t *));
    if (!results) {
        return ERROR(ERR_MEMORY, "Failed to allocate filter results array");
    }

    size_t result_idx = 0;

    for (size_t i = 0; i < all_count; i++) {
        const workspace_item_t *item = &all[i];
        bool should_include = false;

        /* Same filtering logic as first pass */
        switch (item->state) {
            case WORKSPACE_STATE_DEPLOYED:
                if (item->divergence != DIVERGENCE_NONE) {
                    should_include = !opts->only_new;
                }
                break;

            case WORKSPACE_STATE_DELETED:
                should_include = !opts->only_new;
                break;

            case WORKSPACE_STATE_UNTRACKED:
                should_include = (opts->include_new || opts->only_new ||
                                 (config && config->auto_detect_new_files));
                break;

            case WORKSPACE_STATE_UNDEPLOYED:
            case WORKSPACE_STATE_ORPHANED:
                should_include = false;
                break;
        }

        if (!should_include) {
            continue;
        }

        if (!matches_file_filter(item->filesystem_path, opts)) {
            continue;
        }

        if (matches_exclude_pattern(item->filesystem_path, opts)) {
            continue;
        }

        results[result_idx++] = item;
    }

    *out_items = results;
    *count_out = match_count;
    return NULL;
}

/**
 * Group workspace items by profile
 *
 * Creates a hashmap: profile_name -> item_array_t*
 * Each profile gets an array of items that belong to it.
 *
 * Uses item->profile string for grouping (not source_profile pointer,
 * as that may be NULL for items from disabled profiles).
 *
 * @param items Array of workspace item pointers (must not be NULL)
 * @param count Number of items
 * @param out_groups Output hashmap (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *group_items_by_profile(
    const workspace_item_t **items,
    size_t count,
    hashmap_t **out_groups
) {
    CHECK_NULL(items);
    CHECK_NULL(out_groups);

    hashmap_t *groups = hashmap_create(32);
    if (!groups) {
        return ERROR(ERR_MEMORY, "Failed to create profile groups hashmap");
    }

    for (size_t i = 0; i < count; i++) {
        const workspace_item_t *item = items[i];
        const char *profile_name = item->profile;

        if (!profile_name) {
            /* Defensive: skip items with no profile name */
            continue;
        }

        /* Get or create array for this profile */
        item_array_t *array = hashmap_get(groups, profile_name);

        if (!array) {
            /* Create new array for this profile */
            array = calloc(1, sizeof(item_array_t));
            if (!array) {
                hashmap_free(groups, item_array_free);
                return ERROR(ERR_MEMORY, "Failed to allocate item array");
            }

            array->capacity = 16;
            array->items = calloc(array->capacity, sizeof(workspace_item_t *));
            if (!array->items) {
                free(array);
                hashmap_free(groups, item_array_free);
                return ERROR(ERR_MEMORY, "Failed to allocate items array");
            }

            error_t *err = hashmap_set(groups, profile_name, array);
            if (err) {
                free(array->items);
                free(array);
                hashmap_free(groups, item_array_free);
                return error_wrap(err, "Failed to add profile group to hashmap");
            }
        }

        /* Grow array if needed */
        if (array->count >= array->capacity) {
            size_t new_capacity = array->capacity * 2;
            const workspace_item_t **new_items = realloc(
                array->items,
                new_capacity * sizeof(workspace_item_t *)
            );
            if (!new_items) {
                hashmap_free(groups, item_array_free);
                return ERROR(ERR_MEMORY, "Failed to grow item array");
            }
            array->items = new_items;
            array->capacity = new_capacity;
        }

        /* Add item pointer to array */
        array->items[array->count++] = item;
    }

    *out_groups = groups;
    return NULL;
}

/**
 * Update metadata for items (unified for files and directories)
 *
 * CRITICAL: encryption_status and file_stats are indexed by FILE position only
 * (not by all items). We track a separate file_idx that advances only for files.
 *
 * @param wt Worktree handle (must not be NULL)
 * @param items Array of workspace items to update (must not be NULL)
 * @param item_count Number of items
 * @param encryption_status Encryption status for FILES only (indexed by file position, can be NULL)
 * @param file_stats Stat data for FILES only (indexed by file position, can be NULL)
 * @param opts Update options (must not be NULL)
 * @param out Output context (can be NULL)
 * @return Error or NULL on success
 */
static error_t *update_metadata_for_profile(
    worktree_handle_t *wt,
    const workspace_item_t **items,
    size_t item_count,
    const bool *encryption_status,
    const struct stat *file_stats,
    const cmd_update_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(wt);
    CHECK_NULL(items);
    CHECK_NULL(opts);

    /* Early exit if nothing to update */
    if (item_count == 0) {
        return NULL;
    }

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

    size_t captured_file_count = 0;
    size_t updated_dir_count = 0;
    size_t file_idx = 0;  /* Track position in file_stats/encryption_status arrays */

    /* Process all items (files and directories) in a unified loop */
    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        /* Dispatch by item kind */
        switch (item->item_kind) {
            case WORKSPACE_ITEM_FILE: {
                /* Handle file metadata */

                /* Handle deleted files */
                if (item->state == WORKSPACE_STATE_DELETED) {
                    /* Remove metadata entry if it exists */
                    if (metadata_has_item(metadata, item->storage_path)) {
                        err = metadata_remove_item(metadata, item->storage_path);
                        if (err && err->code != ERR_NOT_FOUND) {
                            metadata_free(metadata);
                            return error_wrap(err, "Failed to remove metadata entry");
                        }
                        if (err) {
                            error_free(err);
                            err = NULL;
                        }
                        if (opts->verbose) {
                            printf("Removed metadata: %s\n", item->filesystem_path);
                        }
                    }
                    /* Deleted files don't advance file_idx (no stat captured) */
                    continue;
                }

                /* Use pre-captured stat from copy_file_to_worktree()
                 * CRITICAL: file_stats is indexed by FILE position, not all items */
                if (!file_stats || file_idx >= item_count) {
                    /* Safety check - should never happen */
                    metadata_free(metadata);
                    return ERROR(ERR_INTERNAL, "File stat index out of bounds");
                }

                const struct stat *file_stat = &file_stats[file_idx];

                /* Capture metadata from pre-captured stat data */
                metadata_item_t *meta_item = NULL;
                err = metadata_capture_from_file(
                    item->filesystem_path,
                    item->storage_path,
                    file_stat,
                    &meta_item
                );

                if (err) {
                    metadata_free(metadata);
                    return error_wrap(err, "Failed to capture metadata for: %s",
                                     item->filesystem_path);
                }

                /* meta_item will be NULL for symlinks - skip them */
                if (meta_item) {
                    /* Use tracked encryption status from copy_file_to_worktree() */
                    if (encryption_status) {
                        meta_item->file.encrypted = encryption_status[file_idx];
                    } else {
                        /* Fallback: assume plaintext if no tracked status */
                        meta_item->file.encrypted = false;
                    }

                    /* Save metadata before adding (for verbose output) */
                    mode_t mode = meta_item->mode;
                    char *owner = meta_item->owner ? strdup(meta_item->owner) : NULL;
                    char *group = meta_item->group ? strdup(meta_item->group) : NULL;
                    bool is_encrypted = meta_item->file.encrypted;

                    /* Add to metadata collection */
                    err = metadata_add_item(metadata, meta_item);
                    metadata_item_free(meta_item);

                    if (err) {
                        free(owner);
                        free(group);
                        metadata_free(metadata);
                        return error_wrap(err, "Failed to add metadata entry");
                    }

                    captured_file_count++;

                    if (opts->verbose) {
                        if (owner || group) {
                            printf("Captured metadata: %s (mode: %04o, owner: %s:%s%s)\n",
                                  item->filesystem_path, mode,
                                  owner ? owner : "?",
                                  group ? group : "?",
                                  is_encrypted ? ", encrypted" : "");
                        } else {
                            printf("Captured metadata: %s (mode: %04o%s)\n",
                                  item->filesystem_path, mode,
                                  is_encrypted ? ", encrypted" : "");
                        }
                    }
                    free(owner);
                    free(group);
                }

                /* Advance file index for next file */
                file_idx++;
                break;
            }

            case WORKSPACE_ITEM_DIRECTORY: {
                /* Handle directory metadata */

                /* Stat directory to capture current metadata */
                struct stat dir_stat;
                if (stat(item->filesystem_path, &dir_stat) != 0) {
                    if (opts->verbose && out) {
                        output_warning(out, "Failed to stat directory '%s': %s",
                                       item->filesystem_path, strerror(errno));
                    }
                    continue;
                }

                /* Capture directory metadata */
                metadata_item_t *meta_item = NULL;
                err = metadata_capture_from_directory(
                    item->filesystem_path,
                    item->storage_path,  /* storage_prefix for directories */
                    &dir_stat,
                    &meta_item
                );

                if (err) {
                    if (opts->verbose && out) {
                        output_warning(out, "Failed to capture metadata for directory '%s': %s",
                                       item->filesystem_path, error_message(err));
                    }
                    error_free(err);
                    err = NULL;
                    continue;
                }

                /* Save metadata for verbose output before adding */
                mode_t mode = meta_item->mode;
                char *owner = meta_item->owner ? strdup(meta_item->owner) : NULL;
                char *group = meta_item->group ? strdup(meta_item->group) : NULL;

                /* Add to metadata collection (upsert - updates if exists) */
                err = metadata_add_item(metadata, meta_item);
                metadata_item_free(meta_item);

                if (err) {
                    free(owner);
                    free(group);
                    metadata_free(metadata);
                    return error_wrap(err, "Failed to update directory metadata for '%s'",
                                     item->filesystem_path);
                }

                updated_dir_count++;

                if (opts->verbose && out) {
                    if (owner || group) {
                        output_info(out, "  Updated directory metadata: %s (mode: %04o, owner: %s:%s)",
                                    item->filesystem_path, mode,
                                    owner ? owner : "?",
                                    group ? group : "?");
                    } else {
                        output_info(out, "  Updated directory metadata: %s (mode: %04o)",
                                    item->filesystem_path, mode);
                    }
                }

                free(owner);
                free(group);
                break;
            }
        }

        /* Check for error after each item */
        if (err) {
            metadata_free(metadata);
            return err;
        }
    }

    /* Save metadata to worktree (single save for both files and directories) */
    err = metadata_save_to_worktree(worktree_path, metadata);
    metadata_free(metadata);

    if (err) {
        return error_wrap(err, "Failed to save metadata");
    }

    /* Stage metadata.json file (single stage operation) */
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

    if (opts->verbose && (captured_file_count > 0 || updated_dir_count > 0)) {
        printf("Updated metadata for %zu file(s) and %zu director%s\n",
               captured_file_count,
               updated_dir_count,
               updated_dir_count == 1 ? "y" : "ies");
    }

    return NULL;
}

/**
 * Update a single profile with workspace items
 *
 * ARCHITECTURE NOTE: This function now receives a pre-created worktree
 * that has been checked out to the target profile branch.
 *
 * @param wt Worktree handle (must not be NULL, already checked out to profile branch)
 * @param profile Profile to update (must not be NULL)
 * @param items Array of workspace items to update (must not be NULL)
 * @param item_count Number of items
 * @param opts Update options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @param config Configuration (can be NULL)
 * @param ws Workspace for metadata cache access (can be NULL)
 * @return Error or NULL on success
 */
static error_t *update_profile(
    worktree_handle_t *wt,
    profile_t *profile,
    const workspace_item_t **items,
    size_t item_count,
    const cmd_update_options_t *opts,
    output_ctx_t *out,
    const dotta_config_t *config,
    workspace_t *ws
) {
    CHECK_NULL(wt);
    CHECK_NULL(profile);
    CHECK_NULL(items);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    if (item_count == 0) {
        return NULL;
    }

    /* Get repository from worktree (shared object DB and refs) */
    git_repository *wt_repo = worktree_get_repo(wt);
    if (!wt_repo) {
        return ERROR(ERR_INTERNAL, "Failed to get repository from worktree");
    }

    /* Initialize all resources to NULL for goto cleanup */
    git_index *index = NULL;
    git_tree *tree = NULL;
    char **storage_paths = NULL;
    char *message = NULL;
    error_t *err = NULL;
    metadata_t *existing_metadata = NULL;
    bool owns_metadata = false;
    keymanager_t *key_mgr = NULL;
    bool *encryption_status = NULL;
    struct stat *file_stats = NULL;

    /* Try to get metadata from workspace cache first */
    if (ws) {
        existing_metadata = (metadata_t *)workspace_get_metadata(ws, profile->name);
        if (existing_metadata) {
            owns_metadata = false;  /* Borrowed from workspace */
        }
    }

    /* Fallback: load from Git if not in cache */
    if (!existing_metadata) {
        err = metadata_load_from_branch(wt_repo, profile->name, &existing_metadata);
        if (err) {
            if (err->code == ERR_NOT_FOUND) {
                error_free(err);
                err = metadata_create_empty(&existing_metadata);
                if (err) {
                    return error_wrap(err, "Failed to create empty metadata");
                }
            } else {
                return error_wrap(err, "Failed to load metadata from profile '%s'", profile->name);
            }
        }
        owns_metadata = true;
    }

    /* Get keymanager if encryption may be needed */
    bool needs_encryption = false;

    if (existing_metadata && config && config->encryption_enabled) {
        for (size_t i = 0; i < existing_metadata->count; i++) {
            const metadata_item_t *meta_item = &existing_metadata->items[i];
            if (meta_item->kind == METADATA_ITEM_FILE && meta_item->file.encrypted) {
                needs_encryption = true;
                break;
            }
        }
    }

    if (!needs_encryption && config && config->encryption_enabled &&
        config->auto_encrypt_patterns && config->auto_encrypt_pattern_count > 0) {
        needs_encryption = true;
    }

    if (needs_encryption && config && config->encryption_enabled) {
        key_mgr = keymanager_get_global(config);
        if (!key_mgr) {
            if (owns_metadata && existing_metadata) metadata_free(existing_metadata);
            return ERROR(ERR_INTERNAL, "Failed to get encryption key manager");
        }
    }

    /* Count files that need stat tracking (non-deleted files only) */
    size_t file_count = 0;
    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];
        if (item->item_kind == WORKSPACE_ITEM_FILE && item->state != WORKSPACE_STATE_DELETED) {
            file_count++;
        }
    }

    /* Allocate tracking arrays for files that need stats */
    if (file_count > 0) {
        encryption_status = calloc(file_count, sizeof(bool));
        if (!encryption_status) {
            err = ERROR(ERR_MEMORY, "Failed to allocate encryption status array");
            goto cleanup;
        }

        file_stats = calloc(file_count, sizeof(struct stat));
        if (!file_stats) {
            err = ERROR(ERR_MEMORY, "Failed to allocate file stats array");
            goto cleanup;
        }
    }

    /* Get worktree index for staging */
    err = worktree_get_index(wt, &index);
    if (err) {
        err = error_wrap(err, "Failed to get worktree index");
        goto cleanup;
    }

    /* Process all items in a single unified loop */
    size_t file_idx = 0;  /* Track position in encryption_status/file_stats arrays */

    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        /* Dispatch by item kind */
        switch (item->item_kind) {
            case WORKSPACE_ITEM_FILE: {
                /* Handle file operations */

                if (opts->verbose) {
                    output_info(out, "  %s", item->filesystem_path);
                }

                /* Handle deleted files */
                if (item->state == WORKSPACE_STATE_DELETED) {
                    /* Remove from index (stage deletion) */
                    int git_err = git_index_remove_bypath(index, item->storage_path);
                    if (git_err < 0) {
                        err = error_from_git(git_err);
                        goto cleanup;
                    }
                    /* Deleted files don't advance file_idx (no stat captured) */
                    continue;
                }

                /* Handle encryption divergence for files missing from filesystem
                 *
                 * EDGE CASE: File has DIVERGENCE_ENCRYPTION but doesn't exist on filesystem.
                 * This occurs when:
                 *   1. File exists in Git (detected via profile scan)
                 *   2. File matches auto_encrypt_patterns (policy violation detected)
                 *   3. File is NOT on filesystem (deleted locally, or never deployed)
                 *
                 * DEFENSIVE: Cannot re-encrypt a file that doesn't exist. Skip gracefully
                 * to prevent errors from copy_file_to_worktree() trying to read missing file.
                 *
                 * RESOLUTION PATHS:
                 *   - User can re-create the file and run update again to fix encryption
                 *   - User can remove file from profile with 'dotta remove'
                 *   - If file is BOTH deleted AND has encryption divergence, deletion
                 *     divergence takes precedence (already handled above)
                 */
                if ((item->divergence & DIVERGENCE_ENCRYPTION) && !item->on_filesystem) {
                    if (opts->verbose) {
                        output_warning(out,
                            "Skipping encryption fix for missing file: %s",
                            item->filesystem_path);
                        output_info(out,
                            "  File violates encryption policy but doesn't exist on filesystem.");
                        output_info(out,
                            "  To resolve: re-create file and run update, or remove from profile.");
                    }
                    /* Skip this file - don't advance file_idx (no stat captured) */
                    continue;
                }

                /* Copy to worktree and capture stat atomically */
                err = copy_file_to_worktree(
                    wt,
                    item->filesystem_path,
                    item->storage_path,
                    profile->name,
                    key_mgr,
                    config,
                    existing_metadata,
                    &encryption_status[file_idx],
                    &file_stats[file_idx]
                );
                if (err) {
                    err = error_wrap(err, "Failed to copy '%s'", item->filesystem_path);
                    goto cleanup;
                }

                /* Stage file */
                int git_err = git_index_add_bypath(index, item->storage_path);
                if (git_err < 0) {
                    err = error_from_git(git_err);
                    goto cleanup;
                }

                /* Advance file index for next file */
                file_idx++;
                break;
            }

            case WORKSPACE_ITEM_DIRECTORY: {
                /* Directories are handled purely in metadata - no file operations needed */
                /* Metadata update happens in update_metadata_for_profile() call below */
                break;
            }
        }

        /* Check for error after each item */
        if (err) {
            goto cleanup;
        }
    }

    /* Update metadata for both files and directories */
    err = update_metadata_for_profile(wt, items, item_count,
                                         encryption_status, file_stats, opts, out);
    if (err) {
        err = error_wrap(err, "Failed to update metadata");
        goto cleanup;
    }

    /* Note: metadata function already wrote the index */

    /* Create commit */
    git_oid tree_oid;
    int git_err = git_index_write_tree(&tree_oid, index);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    git_err = git_tree_lookup(&tree, wt_repo, &tree_oid);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Build array of storage paths for commit message (files only) */
    storage_paths = malloc(item_count * sizeof(char *));
    if (!storage_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
        goto cleanup;
    }

    size_t path_count = 0;
    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];
        /* Include all items (files and directories) in commit message */
        storage_paths[path_count++] = item->storage_path;
    }

    /* Build commit message context */
    commit_message_context_t ctx = {
        .action = COMMIT_ACTION_UPDATE,
        .profile = profile->name,
        .files = storage_paths,
        .file_count = path_count,
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
    if (owns_metadata && existing_metadata) metadata_free(existing_metadata);
    if (file_stats) free(file_stats);
    if (encryption_status) free(encryption_status);

    return err;
}

/**
 * Context for update_profile_callback
 */
typedef struct {
    worktree_handle_t *wt;       /* Shared worktree for all profiles */
    hashmap_t *profile_index;
    const cmd_update_options_t *opts;
    output_ctx_t *out;
    const dotta_config_t *config;
    workspace_t *ws;
    size_t *total_updated;
    error_t **err_out;
} update_profile_context_t;

/**
 * Callback for hashmap_foreach in update_execute_for_all_profiles
 */
static bool update_profile_callback(const char *profile_name, void *value, void *user_data) {
    update_profile_context_t *ctx = (update_profile_context_t *)user_data;
    item_array_t *array = (item_array_t *)value;

    /* Look up profile pointer */
    profile_t *profile = hashmap_get(ctx->profile_index, profile_name);

    if (!profile) {
        /* Profile not in enabled set - skip (shouldn't happen due to filtering) */
        output_warning(ctx->out, "Profile '%s' not found in enabled profiles, skipping",
                      profile_name);
        return true;  /* Continue iteration */
    }

    if (array->count == 0) {
        return true;  /* Continue iteration */
    }

    /* Display profile header */
    char *colored_name = output_colorize(ctx->out, OUTPUT_COLOR_CYAN, profile->name);
    if (colored_name) {
        output_info(ctx->out, "Updating profile '%s':", colored_name);
        free(colored_name);
    } else {
        output_info(ctx->out, "Updating profile '%s':", profile->name);
    }

    /* Checkout profile branch in shared worktree */
    error_t *err = worktree_checkout_branch(ctx->wt, profile->name);
    if (err) {
        *(ctx->err_out) = error_wrap(err, "Failed to checkout profile '%s'", profile->name);
        return false;  /* Stop iteration */
    }

    /* Update this profile using shared worktree */
    err = update_profile(
        ctx->wt, profile,
        array->items, array->count,
        ctx->opts, ctx->out, ctx->config, ctx->ws
    );

    if (err) {
        *(ctx->err_out) = error_wrap(err, "Failed to update profile '%s'", profile->name);
        return false;  /* Stop iteration */
    }

    *(ctx->total_updated) += array->count;

    if (!ctx->opts->verbose) {
        output_success(ctx->out, "  Updated %zu item%s",
                      array->count, array->count == 1 ? "" : "s");
    }

    return true;  /* Continue iteration */
}

/**
 * Context for manifest sync callback
 */
typedef struct {
    git_repository *repo;
    state_t *state;
    string_array_t *enabled_profiles;
    const cmd_update_options_t *opts;
    output_ctx_t *out;
    size_t synced_count;
    error_t **err_out;
} manifest_sync_context_t;

/**
 * Callback to sync manifest for one profile
 *
 * Called for each profile that was updated. Syncs all items from that profile
 * to the manifest if the profile is enabled.
 *
 * Algorithm:
 *   1. Check if profile is enabled (skip if not)
 *   2. Get branch HEAD oid for git_oid field
 *   3. For each item in profile:
 *      - Skip directories (not in manifest)
 *      - If deleted: call manifest_remove_file()
 *      - Else: call manifest_sync_file() with DEPLOYED status
 *
 * @param profile_name Profile name (hashmap key)
 * @param value item_array_t* with items for this profile
 * @param user_data manifest_sync_context_t* context
 * @return true to continue iteration, false to stop on error
 */
static bool sync_profile_callback(
    const char *profile_name,
    void *value,
    void *user_data
) {
    manifest_sync_context_t *ctx = user_data;
    item_array_t *items = value;
    error_t *err = NULL;

    /* Stop iteration if previous error */
    if (*(ctx->err_out)) {
        return false;
    }

    /* Check if this profile is enabled (optimization: skip entire profile) */
    bool profile_enabled = false;
    for (size_t i = 0; i < string_array_size(ctx->enabled_profiles); i++) {
        if (strcmp(string_array_get(ctx->enabled_profiles, i), profile_name) == 0) {
            profile_enabled = true;
            break;
        }
    }

    if (!profile_enabled) {
        /* Profile not enabled - skip gracefully */
        if (ctx->opts->verbose) {
            output_info(ctx->out,
                "  Manifest: skipped profile '%s' (not enabled)",
                profile_name);
        }
        return true;  /* Continue to next profile */
    }

    /* Get branch HEAD oid for this profile */
    git_reference *branch_ref = NULL;

    /* Build branch reference name */
    size_t ref_name_size = strlen("refs/heads/") + strlen(profile_name) + 1;
    char *ref_name = malloc(ref_name_size);
    if (!ref_name) {
        *(ctx->err_out) = ERROR(ERR_MEMORY, "Failed to allocate reference name");
        return false;  /* Stop iteration */
    }
    snprintf(ref_name, ref_name_size, "refs/heads/%s", profile_name);

    int ret = git_reference_lookup(&branch_ref, ctx->repo, ref_name);
    free(ref_name);

    if (ret < 0) {
        *(ctx->err_out) = error_from_git(ret);
        return false;  /* Stop iteration */
    }

    const git_oid *commit_oid = git_reference_target(branch_ref);
    if (!commit_oid) {
        git_reference_free(branch_ref);
        *(ctx->err_out) = ERROR(ERR_GIT, "Branch '%s' has no target", profile_name);
        return false;  /* Stop iteration */
    }

    char git_oid_str[GIT_OID_HEXSZ + 1];
    git_oid_tostr(git_oid_str, sizeof(git_oid_str), commit_oid);
    git_reference_free(branch_ref);

    /* Sync each file item in this profile */
    for (size_t i = 0; i < items->count; i++) {
        const workspace_item_t *item = items->items[i];

        /* Skip directories (not in manifest table) */
        if (item->item_kind != WORKSPACE_ITEM_FILE) {
            continue;
        }

        /* Handle deleted files differently */
        if (item->state == WORKSPACE_STATE_DELETED) {
            /* Use manifest_remove_file() - handles fallback automatically */
            err = manifest_remove_file(
                ctx->repo,
                ctx->state,
                item->filesystem_path,
                ctx->enabled_profiles
            );

            if (err) {
                *(ctx->err_out) = error_wrap(err,
                    "Failed to remove '%s' from manifest",
                    item->filesystem_path);
                return false;  /* Stop iteration */
            }

            if (ctx->opts->verbose) {
                output_info(ctx->out, "  Manifest: removed %s",
                           item->filesystem_path);
            }
            ctx->synced_count++;
            continue;
        }

        /* Convert filesystem path to storage path */
        char *storage_path = NULL;
        path_prefix_t prefix;
        err = path_to_storage(item->filesystem_path, &storage_path, &prefix);
        if (err) {
            *(ctx->err_out) = error_wrap(err,
                "Failed to convert path '%s'", item->filesystem_path);
            return false;  /* Stop iteration */
        }

        /* Sync modified/new file with DEPLOYED status
         *
         * Key insight: UPDATE captures files FROM filesystem, so they're
         * already deployed. Setting PENDING_DEPLOYMENT would be misleading.
         */
        err = manifest_sync_file(
            ctx->repo,
            ctx->state,
            profile_name,
            storage_path,
            item->filesystem_path,
            git_oid_str,
            ctx->enabled_profiles,
            MANIFEST_STATUS_DEPLOYED  /* File already on filesystem */
        );

        free(storage_path);

        if (err) {
            *(ctx->err_out) = error_wrap(err,
                "Failed to sync '%s' to manifest", item->filesystem_path);
            return false;  /* Stop iteration */
        }

        if (ctx->opts->verbose) {
            output_info(ctx->out, "  Manifest: synced %s (DEPLOYED)",
                       item->filesystem_path);
        }
        ctx->synced_count++;
    }

    return true;  /* Continue to next profile */
}

/**
 * Update manifest after successful update operation
 *
 * Called after ALL profile updates succeed. Updates manifest for files
 * that were modified/added/deleted, maintaining the manifest as a
 * Virtual Working Directory.
 *
 * This function implements the VWD integration for the update command.
 * After Git commits succeed, the manifest is synced to reflect the new
 * state. This keeps the three-way consistency: Git ↔ Manifest ↔ Filesystem.
 *
 * Status Semantics:
 *   - Modified/New files: DEPLOYED (already on filesystem)
 *   - Deleted files: handled by manifest_remove_file() (PENDING_REMOVAL or fallback)
 *
 * Algorithm:
 *   1. Check if any profiles enabled (read-only, upfront optimization)
 *   2. If none enabled: return NULL (skip manifest update gracefully)
 *   3. Open transaction (state_load_for_update)
 *   4. Get enabled profiles list
 *   5. For each updated profile:
 *      a. Check if profile is in enabled list (skip if not)
 *      b. Get branch HEAD oid for git_oid field
 *      c. For each item in profile:
 *         - Skip directories (not in manifest)
 *         - If DELETED: manifest_remove_file()
 *         - Else: manifest_sync_file() with DEPLOYED status
 *   6. Commit transaction (state_save)
 *   7. Set *out_updated = true
 *
 * Preconditions:
 *   - All profile updates already succeeded (Git commits done)
 *   - items_by_profile contains profile_name → item_array_t mappings
 *
 * Postconditions:
 *   - Manifest entries synced for enabled profiles only
 *   - Transaction committed or rolled back atomically
 *   - out_updated flag reflects whether manifest was updated
 *
 * Error Handling:
 *   - Non-fatal: Git commits succeeded, manifest is a cache
 *   - Caller should warn user and suggest repair options
 *
 * Performance:
 *   - O(N*M) where N = updated files, M = total files in profiles
 *   - Acceptable: profile enable already O(N*M)
 *   - Future optimization: cache precedence manifest per profile
 *
 * @param repo Git repository (must not be NULL)
 * @param items_by_profile Hashmap: profile_name → item_array_t* (must not be NULL)
 * @param opts Update options for verbose flag (must not be NULL)
 * @param out Output context for verbose logging (can be NULL)
 * @param out_updated Output flag: true if manifest was updated (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *update_manifest_after_update(
    git_repository *repo,
    const hashmap_t *items_by_profile,
    const cmd_update_options_t *opts,
    output_ctx_t *out,
    bool *out_updated
) {
    CHECK_NULL(repo);
    CHECK_NULL(items_by_profile);
    CHECK_NULL(opts);
    CHECK_NULL(out_updated);

    error_t *err = NULL;
    state_t *state = NULL;
    string_array_t *enabled_profiles = NULL;

    /* Initialize output */
    *out_updated = false;

    /* OPTIMIZATION: Check if ANY profiles enabled (upfront, read-only) */
    err = state_load(repo, &state);
    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            /* State file doesn't exist yet - no profiles enabled */
            error_free(err);
            return NULL;  /* Success - nothing to do */
        }
        return error_wrap(err, "Failed to load state for manifest check");
    }

    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        state_free(state);
        return error_wrap(err, "Failed to get enabled profiles");
    }

    if (string_array_size(enabled_profiles) == 0) {
        /* No profiles enabled - skip manifest update gracefully */
        string_array_free(enabled_profiles);
        state_free(state);
        return NULL;  /* Success - nothing to do */
    }

    /* Free read-only state, will reopen for update */
    state_free(state);
    state = NULL;

    /* Open transaction for manifest updates */
    err = state_load_for_update(repo, &state);
    if (err) {
        string_array_free(enabled_profiles);
        return error_wrap(err, "Failed to open state transaction for manifest update");
    }

    /* Context for hashmap iteration */
    manifest_sync_context_t sync_ctx = {
        .repo = repo,
        .state = state,
        .enabled_profiles = enabled_profiles,
        .opts = opts,
        .out = out,
        .synced_count = 0,
        .err_out = &err
    };

    /* Sync all updated profiles */
    hashmap_foreach(items_by_profile, sync_profile_callback, &sync_ctx);

    /* Commit transaction if no errors */
    if (!err) {
        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to save manifest updates");
            goto cleanup;
        }

        *out_updated = true;

        /* Verbose summary */
        if (opts->verbose && sync_ctx.synced_count > 0) {
            output_info(out, "Manifest synced %zu file%s",
                       sync_ctx.synced_count,
                       sync_ctx.synced_count == 1 ? "" : "s");
        }
    }

cleanup:
    if (enabled_profiles) {
        string_array_free(enabled_profiles);
    }
    if (state) {
        state_free(state);  /* Rolls back if err != NULL */
    }

    return err;
}

/**
 * Execute profile updates for all profiles
 *
 * PERFORMANCE NOTE: This function creates a single shared worktree and reuses it
 * for all profile updates, eliminating expensive worktree creation/destruction
 * overhead. Each profile is checked out into the same worktree before updating.
 *
 * @param repo Git repository (must not be NULL)
 * @param profiles Profile list for lookup (must not be NULL)
 * @param update_items Pre-filtered items to update (must not be NULL)
 * @param update_count Number of items
 * @param opts Update options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @param config Configuration (can be NULL)
 * @param ws Workspace for metadata cache access (can be NULL)
 * @param total_updated Output: total items updated across all profiles (must not be NULL)
 * @param out_by_profile Output: hashmap of items grouped by profile (must not be NULL, freed by caller)
 * @return Error or NULL on success
 */
static error_t *update_execute_for_all_profiles(
    git_repository *repo,
    profile_list_t *profiles,
    const workspace_item_t **update_items,
    size_t update_count,
    const cmd_update_options_t *opts,
    output_ctx_t *out,
    const dotta_config_t *config,
    workspace_t *ws,
    size_t *total_updated,
    hashmap_t **out_by_profile
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(update_items);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(total_updated);
    CHECK_NULL(out_by_profile);

    *total_updated = 0;
    *out_by_profile = NULL;

    if (update_count == 0) {
        return NULL;
    }

    /* Initialize all resources to NULL for goto cleanup */
    worktree_handle_t *wt = NULL;
    hashmap_t *by_profile = NULL;
    hashmap_t *profile_index = NULL;
    error_t *err = NULL;

    /* Create shared temporary worktree for all profile updates */
    err = worktree_create_temp(repo, &wt);
    if (err) {
        return error_wrap(err, "Failed to create temporary worktree");
    }

    /* Group items by profile */
    err = group_items_by_profile(update_items, update_count, &by_profile);
    if (err) {
        err = error_wrap(err, "Failed to group items by profile");
        goto cleanup;
    }

    /* Create hashmap for O(1) profile lookup */
    profile_index = hashmap_create(32);
    if (!profile_index) {
        err = ERROR(ERR_MEMORY, "Failed to create profile index");
        goto cleanup;
    }

    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];
        error_t *index_err = hashmap_set(profile_index, profile->name, profile);
        if (index_err) {
            err = error_wrap(index_err, "Failed to index profile");
            goto cleanup;
        }
    }

    /* Update each profile using hashmap_foreach callback */
    update_profile_context_t ctx = {
        .wt = wt,
        .profile_index = profile_index,
        .opts = opts,
        .out = out,
        .config = config,
        .ws = ws,
        .total_updated = total_updated,
        .err_out = &err
    };

    /* Execute foreach with callback */
    hashmap_foreach(by_profile, update_profile_callback, &ctx);

cleanup:
    /* Cleanup resources in reverse order */
    if (profile_index) {
        hashmap_free(profile_index, NULL);
    }
    /* Pass by_profile to caller (for manifest sync), or free on error */
    if (by_profile) {
        if (err) {
            /* Error path: free resources */
            hashmap_free(by_profile, item_array_free);
        } else {
            /* Success path: pass to caller */
            *out_by_profile = by_profile;
        }
    }
    if (wt) {
        worktree_cleanup(wt);
    }

    return err;
}

/**
 * Display summary of items to be updated
 *
 * Multi-profile overlap detection uses item->all_profiles directly,
 * which is computed during workspace load (no Git operations needed).
 *
 * @param out Output context (must not be NULL)
 * @param items Items to display (must not be NULL)
 * @param item_count Number of items
 * @param opts Update options (can be NULL)
 * @return Error or NULL on success
 */
static error_t *update_display_summary(
    output_ctx_t *out,
    const workspace_item_t **items,
    size_t item_count,
    const cmd_update_options_t *opts
) {
    CHECK_NULL(out);
    CHECK_NULL(items);

    /* Early exit for empty data - not an error */
    if (item_count == 0) {
        return NULL;
    }

    /* Show dry-run banner if applicable */
    if (opts && opts->dry_run) {
        output_printf(out, OUTPUT_NORMAL, "%sDRY RUN MODE%s - No changes will be committed\n\n",
                     output_color_code(out, OUTPUT_COLOR_BOLD),
                     output_color_code(out, OUTPUT_COLOR_RESET));
    }

    /* Show filter context if any filters are active */
    if (opts) {
        bool has_filters = false;

        if (opts->only_new) {
            output_info(out, "Filter: Showing only new files (--only-new)");
            has_filters = true;
        } else if (opts->include_new) {
            output_info(out, "Filter: Including new files from tracked directories (--include-new)");
            has_filters = true;
        }

        if (opts->file_count > 0) {
            output_info(out, "Filter: Limiting to %zu specified file%s",
                       opts->file_count, opts->file_count == 1 ? "" : "s");
            has_filters = true;
        }

        if (opts->exclude_count > 0) {
            output_info(out, "Filter: Excluding %zu pattern%s",
                       opts->exclude_count, opts->exclude_count == 1 ? "" : "s");
            has_filters = true;
        }

        if (has_filters) {
            output_newline(out);
        }
    }

    /* Categorize items for display */
    size_t modified_count = 0;
    size_t new_count = 0;
    size_t deleted_count = 0;
    size_t dir_count = 0;
    size_t encryption_count = 0;

    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        if (item->item_kind == WORKSPACE_ITEM_FILE) {
            /* Count by state */
            switch (item->state) {
                case WORKSPACE_STATE_DEPLOYED:
                    /* Has some divergence (filtered items always have divergence) */
                    modified_count++;
                    /* Also count encryption divergence separately for informational display */
                    if (item->divergence & DIVERGENCE_ENCRYPTION) {
                        encryption_count++;
                    }
                    break;

                case WORKSPACE_STATE_DELETED:
                    deleted_count++;
                    break;

                case WORKSPACE_STATE_UNTRACKED:
                    new_count++;
                    break;

                case WORKSPACE_STATE_UNDEPLOYED:
                case WORKSPACE_STATE_ORPHANED:
                    /* Should not appear in filtered results, but be defensive */
                    break;
            }
        } else if (item->item_kind == WORKSPACE_ITEM_DIRECTORY) {
            dir_count++;
        }
    }

    /* Track multi-profile files for warning */
    size_t multi_profile_count = 0;

    /* Display modified files section */
    if (modified_count > 0) {
        output_section(out, "Modified files");
        output_newline(out);

        for (size_t i = 0; i < item_count; i++) {
            const workspace_item_t *item = items[i];

            if (item->item_kind != WORKSPACE_ITEM_FILE) {
                continue;
            }

            /* Check if file is deployed and has any divergence */
            bool is_modified = (item->state == WORKSPACE_STATE_DEPLOYED &&
                               item->divergence != DIVERGENCE_NONE);

            if (!is_modified) {
                continue;
            }

            /* Check if file exists in multiple profiles (multi-profile overlap).
             * item->all_profiles contains ALL profiles with this file (if >1),
             * with the winning profile as the last entry. Extract other profiles
             * for display (all except the winning one).
             */
            string_array_t *other_profiles = NULL;
            if (item->all_profiles && item->all_profiles->count > 1) {
                /* Multi-profile: extract all except the winner (last entry) */
                other_profiles = string_array_create();
                if (other_profiles) {
                    size_t count = item->all_profiles->count;
                    /* Include all profiles except the last one (winner) */
                    for (size_t j = 0; j < count - 1; j++) {
                        string_array_push(other_profiles, item->all_profiles->items[j]);
                    }
                }
            }

            /* Build info string */
            buffer_t *info_buf = buffer_create();
            if (!info_buf) {
                string_array_free(other_profiles);
                continue;
            }

            if (other_profiles && string_array_size(other_profiles) > 0) {
                buffer_append_string(info_buf, item->filesystem_path);
                buffer_append_string(info_buf, " (from ");
                buffer_append_string(info_buf, item->profile);
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
                buffer_append_string(info_buf, item->filesystem_path);
                buffer_append_string(info_buf, " (from ");
                buffer_append_string(info_buf, item->profile);
                buffer_append_string(info_buf, ")");
            }

            /* In verbose mode, show detailed divergence flags */
            if (opts && opts->verbose) {
                bool first_flag = true;
                buffer_append_string(info_buf, " ");
                buffer_append_string(info_buf, output_color_code(out, OUTPUT_COLOR_DIM));

                if (item->divergence & DIVERGENCE_CONTENT) {
                    buffer_append_string(info_buf, "[content]");
                    first_flag = false;
                }
                if (item->divergence & DIVERGENCE_MODE) {
                    if (!first_flag) buffer_append_string(info_buf, " ");
                    buffer_append_string(info_buf, "[mode]");
                    first_flag = false;
                }
                if (item->divergence & DIVERGENCE_OWNERSHIP) {
                    if (!first_flag) buffer_append_string(info_buf, " ");
                    buffer_append_string(info_buf, "[ownership]");
                    first_flag = false;
                }
                if (item->divergence & DIVERGENCE_ENCRYPTION) {
                    if (!first_flag) buffer_append_string(info_buf, " ");
                    buffer_append_string(info_buf, "[encryption]");
                    first_flag = false;
                }

                buffer_append_string(info_buf, output_color_code(out, OUTPUT_COLOR_RESET));
            }

            char *info = NULL;
            error_t *release_err = buffer_release_data(info_buf, &info);
            if (release_err) {
                error_free(release_err);
                string_array_free(other_profiles);
                continue;
            }

            /* Determine label and color (prioritize by severity) */
            const char *status_label = NULL;
            output_color_t color = OUTPUT_COLOR_YELLOW;

            /* Prioritize TYPE (most severe), then CONTENT, then metadata */
            if (item->divergence & DIVERGENCE_TYPE) {
                status_label = "[type]";
                color = OUTPUT_COLOR_RED;
            } else if (item->divergence & DIVERGENCE_CONTENT) {
                status_label = "[modified]";
            } else if (item->divergence & DIVERGENCE_MODE) {
                status_label = "[mode]";
            } else if (item->divergence & DIVERGENCE_OWNERSHIP) {
                status_label = "[ownership]";
                color = OUTPUT_COLOR_MAGENTA;
            } else if (item->divergence & DIVERGENCE_ENCRYPTION) {
                status_label = "[encryption]";
                color = OUTPUT_COLOR_MAGENTA;
            } else {
                /* Should not happen for filtered deployed items, but be defensive */
                status_label = "[modified]";
            }

            output_item(out, status_label, color, info);

            free(info);
            string_array_free(other_profiles);
        }
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

    /* Display new files section */
    if (new_count > 0) {
        output_section(out, "New files");
        output_newline(out);

        for (size_t i = 0; i < item_count; i++) {
            const workspace_item_t *item = items[i];

            if (item->item_kind == WORKSPACE_ITEM_FILE && item->state == WORKSPACE_STATE_UNTRACKED) {
                char info[1024];
                snprintf(info, sizeof(info), "%s (in %s)",
                        item->filesystem_path, item->profile);
                output_item(out, "[new]", OUTPUT_COLOR_CYAN, info);
            }
        }
    }

    /* Display deleted files section (if any - rare in update context) */
    if (deleted_count > 0) {
        output_section(out, "Deleted files");
        output_newline(out);

        for (size_t i = 0; i < item_count; i++) {
            const workspace_item_t *item = items[i];

            if (item->item_kind == WORKSPACE_ITEM_FILE && item->state == WORKSPACE_STATE_DELETED) {
                char info[1024];
                snprintf(info, sizeof(info), "%s (from %s)",
                        item->filesystem_path, item->profile);
                output_item(out, "[deleted]", OUTPUT_COLOR_RED, info);
            }
        }
    }

    /* Display modified directories section */
    if (dir_count > 0) {
        output_section(out, "Modified directories");
        output_newline(out);

        for (size_t i = 0; i < item_count; i++) {
            const workspace_item_t *item = items[i];

            if (item->item_kind != WORKSPACE_ITEM_DIRECTORY) {
                continue;
            }

            /* Determine label and color based on divergence */
            const char *label = NULL;
            output_color_t color = OUTPUT_COLOR_YELLOW;

            /* Directories can have mode and/or ownership divergence */
            if (item->divergence & DIVERGENCE_MODE) {
                label = "[mode]";
                color = OUTPUT_COLOR_YELLOW;
            } else if (item->divergence & DIVERGENCE_OWNERSHIP) {
                label = "[ownership]";
                color = OUTPUT_COLOR_MAGENTA;
            } else {
                /* Should not happen for filtered directories, but be defensive */
                label = "[metadata]";
                color = OUTPUT_COLOR_YELLOW;
            }

            /* Build info string with trailing slash */
            buffer_t *info_buf = buffer_create();
            if (!info_buf) {
                continue;
            }

            buffer_append_string(info_buf, item->filesystem_path);
            buffer_append_string(info_buf, "/ ");
            buffer_append_string(info_buf, output_color_code(out, OUTPUT_COLOR_DIM));
            buffer_append_string(info_buf, "(directory from ");
            buffer_append_string(info_buf, item->profile);
            buffer_append_string(info_buf, ")");
            buffer_append_string(info_buf, output_color_code(out, OUTPUT_COLOR_RESET));

            /* In verbose mode, show detailed divergence flags for directories */
            if (opts && opts->verbose) {
                bool first_flag = true;
                buffer_append_string(info_buf, " ");
                buffer_append_string(info_buf, output_color_code(out, OUTPUT_COLOR_DIM));

                if (item->divergence & DIVERGENCE_MODE) {
                    buffer_append_string(info_buf, "[mode]");
                    first_flag = false;
                }
                if (item->divergence & DIVERGENCE_OWNERSHIP) {
                    if (!first_flag) buffer_append_string(info_buf, " ");
                    buffer_append_string(info_buf, "[ownership]");
                    first_flag = false;
                }
                if (item->divergence & DIVERGENCE_ENCRYPTION) {
                    if (!first_flag) buffer_append_string(info_buf, " ");
                    buffer_append_string(info_buf, "[encryption]");
                }

                buffer_append_string(info_buf, output_color_code(out, OUTPUT_COLOR_RESET));
            }

            char *info = NULL;
            error_t *release_err = buffer_release_data(info_buf, &info);
            if (release_err) {
                error_free(release_err);
                continue;
            }

            output_item(out, label, color, info);
            free(info);
        }
    }

    /* Display encryption policy violations section */
    if (encryption_count > 0) {
        output_section(out, "Encryption policy violations");
        output_newline(out);

        output_warning(out,
            "The following files match auto-encrypt patterns but are stored as plaintext:");
        output_newline(out);

        for (size_t i = 0; i < item_count; i++) {
            const workspace_item_t *item = items[i];

            if (item->item_kind != WORKSPACE_ITEM_FILE ||
                !(item->divergence & DIVERGENCE_ENCRYPTION)) {
                continue;
            }

            /* Build info string with security context and resolution status */
            buffer_t *info_buf = buffer_create();
            if (!info_buf) {
                continue;
            }

            buffer_append_string(info_buf, item->filesystem_path);
            buffer_append_string(info_buf, " (from ");
            buffer_append_string(info_buf, item->profile);
            buffer_append_string(info_buf, ") ");
            buffer_append_string(info_buf, output_color_code(out, OUTPUT_COLOR_DIM));

            /* Show resolution status based on filesystem presence */
            if (item->on_filesystem) {
                buffer_append_string(info_buf, "[will be encrypted]");
            } else {
                buffer_append_string(info_buf, "[file missing - cannot fix]");
            }

            buffer_append_string(info_buf, output_color_code(out, OUTPUT_COLOR_RESET));

            char *info = NULL;
            error_t *release_err = buffer_release_data(info_buf, &info);
            if (release_err) {
                error_free(release_err);
                continue;
            }

            output_item(out, "[plaintext]", OUTPUT_COLOR_RED, info);
            free(info);
        }

        output_newline(out);
        output_info(out,
            "These files will be re-encrypted according to your auto_encrypt_patterns config.");
        output_info(out,
            "To keep a file as plaintext, use: dotta update --no-encrypt <file>");
    }

    output_newline(out);
    return NULL;
}

/**
 * Handle user confirmations for update operation
 *
 * @param out Output context (must not be NULL)
 * @param opts Update options (must not be NULL)
 * @param items Items to update (must not be NULL)
 * @param item_count Number of items
 * @param config Configuration (can be NULL)
 * @param result Output parameter for confirmation result (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *update_confirm_operation(
    output_ctx_t *out,
    const cmd_update_options_t *opts,
    const workspace_item_t **items,
    size_t item_count,
    const dotta_config_t *config,
    confirm_result_t *result
) {
    CHECK_NULL(out);
    CHECK_NULL(opts);
    CHECK_NULL(items);
    CHECK_NULL(result);

    *result = CONFIRM_PROCEED;

    /* Count items by category */
    size_t modified_count = 0;
    size_t new_count = 0;
    size_t dir_count = 0;

    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        if (item->item_kind == WORKSPACE_ITEM_FILE) {
            if (item->state == WORKSPACE_STATE_UNTRACKED) {
                new_count++;
            } else {
                modified_count++;
            }
        } else if (item->item_kind == WORKSPACE_ITEM_DIRECTORY) {
            dir_count++;
        }
    }

    /* Dry run - just show and exit */
    if (opts->dry_run) {
        if (dir_count > 0) {
            output_info(out, "Dry run: would update %zu file%s, %zu director%s, and add %zu new file%s",
                       modified_count, modified_count == 1 ? "" : "s",
                       dir_count, dir_count == 1 ? "y" : "ies",
                       new_count, new_count == 1 ? "" : "s");
        } else {
            output_info(out, "Dry run: would update %zu modified file%s and add %zu new file%s",
                       modified_count, modified_count == 1 ? "" : "s",
                       new_count, new_count == 1 ? "" : "s");
        }
        *result = CONFIRM_DRY_RUN;
        return NULL;
    }

    /* Interactive confirmation */
    if (opts->interactive) {
        printf("Update these items? [y/N] ");
        fflush(stdout);

        char response[10];
        if (!fgets(response, sizeof(response), stdin) ||
            (response[0] != 'y' && response[0] != 'Y')) {
            output_info(out, "Cancelled");
            *result = CONFIRM_CANCELLED;
            return NULL;
        }
    }

    /* Confirmation for new files (if auto-detected, not explicit flag) */
    if (new_count > 0 &&
        config && config->confirm_new_files &&
        !opts->include_new && !opts->only_new &&
        config->auto_detect_new_files) {

        printf("Found %zu new file%s. Add %s to profiles? [y/N] ",
               new_count, new_count == 1 ? "" : "s",
               new_count == 1 ? "it" : "them");
        fflush(stdout);

        char response[10];
        if (!fgets(response, sizeof(response), stdin) ||
            (response[0] != 'y' && response[0] != 'Y')) {
            /* User declined - would need to filter out new files */
            /* For now, just proceed without them - filtering would require
             * rebuilding the array which is complex. Better to handle this
             * in the calling code. */
            *result = CONFIRM_SKIP_NEW_FILES;
            return NULL;
        }
    }

    *result = CONFIRM_PROCEED;
    return NULL;
}

/**
 * Update command implementation
 */
error_t *cmd_update(
    git_repository *repo,
    const cmd_update_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;
    profile_list_t *profiles = NULL;
    workspace_t *ws = NULL;
    hook_context_t *hook_ctx = NULL;
    char *repo_dir = NULL;
    char *profiles_str = NULL;
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
        char **profile_names_array = malloc(profiles->count * sizeof(char *));
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

    /* Load workspace and filter items in one step
     *
     * workspace_load() provides the unified three-state analysis
     * filter_items_for_update() handles ALL filtering logic internally:
     * - --only-new flag
     * - --include-new flag
     * - config auto_detect_new_files
     * - MODE_DIFF/OWNERSHIP for both files AND directories
     */
    workspace_load_t ws_opts = {
        .analyze_files = true,                              /* Need to see file changes */
        .analyze_orphans = false,                           /* Update doesn't do cleanup */
        .analyze_untracked = (opts->include_new || opts->only_new ||      /* Explicit flags */
                             (config && config->auto_detect_new_files)),  /* Or config auto-detect */
        .analyze_directories = true,                        /* Detect directory metadata changes */
        .analyze_encryption = true                          /* Detect encryption policy violations */
    };
    err = workspace_load(repo, profiles, config, &ws_opts, &ws);
    if (err) {
        err = error_wrap(err, "Failed to analyze workspace");
        goto cleanup;
    }

    /* Filter items for update (handles all flags and edge cases internally) */
    const workspace_item_t **update_items = NULL;
    size_t update_count = 0;
    err = filter_items_for_update(ws, opts, config, out, &update_items, &update_count);
    if (err) {
        err = error_wrap(err, "Failed to filter items for update");
        goto cleanup;
    }

    /* Check if we have anything to update */
    if (update_count == 0) {
        if (opts->only_new) {
            output_info(out, "No new files to add");
        } else if (opts->include_new) {
            output_info(out, "No modified or new files/directories to update");
        } else {
            output_info(out, "No modified files or directories to update");
        }
        err = NULL;  /* Not an error */
        goto cleanup;
    }

    /* PRE-FLIGHT PRIVILEGE CHECK
     *
     * This check happens AFTER finding modified files but BEFORE any write
     * operations begin. If elevation is needed, the process will re-exec with
     * sudo, and all operations will restart cleanly from main().
     *
     * NOTE: Pre-update hook may run twice on re-exec (once before privilege
     * check, once after). Hooks should be idempotent to handle this correctly.
     *
     * If re-exec succeeds, this function DOES NOT RETURN.
     */
    {
        /* Count files that need privilege check (exclude directories) */
        size_t file_count = 0;
        for (size_t i = 0; i < update_count; i++) {
            if (update_items[i]->item_kind == WORKSPACE_ITEM_FILE) {
                file_count++;
            }
        }

        if (file_count > 0) {
            /* Extract storage paths from file items */
            const char **storage_paths = calloc(file_count, sizeof(char *));
            if (!storage_paths) {
                err = ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
                if (update_items) free(update_items);
                goto cleanup;
            }

            size_t path_idx = 0;
            for (size_t i = 0; i < update_count; i++) {
                const workspace_item_t *item = update_items[i];
                if (item->item_kind == WORKSPACE_ITEM_FILE) {
                    storage_paths[path_idx++] = item->storage_path;
                }
            }

            /* Check privilege requirements
             *
             * If root/ files detected without root privileges:
             * - Interactive: Prompts user, re-execs with sudo if approved
             * - Non-interactive: Returns error with clear message
             *
             * If re-exec succeeds, this function DOES NOT RETURN.
             * If re-exec fails or user declines, returns error.
             */
            err = privilege_ensure_for_operation(
                storage_paths,
                file_count,
                "update",
                opts->interactive,  /* Use existing interactive flag */
                opts->argc,
                opts->argv,
                out
            );

            free(storage_paths);

            if (err) {
                /* User declined elevation or non-interactive mode blocked it */
                if (update_items) free(update_items);
                goto cleanup;
            }

            /* If we reach here, privileges are OK - proceed with operation */
        }
    }

    /* Display summary of items to update */
    err = update_display_summary(out, update_items, update_count, opts);
    if (err) {
        if (update_items) free(update_items);
        goto cleanup;
    }

    /* Handle user confirmations */
    confirm_result_t confirm_result;
    err = update_confirm_operation(out, opts, update_items, update_count, config, &confirm_result);
    if (err) {
        if (update_items) free(update_items);
        goto cleanup;
    }

    /* Handle confirmation result */
    switch (confirm_result) {
        case CONFIRM_CANCELLED:
        case CONFIRM_DRY_RUN:
            /* User cancelled or dry run - clean exit (not an error) */
            if (update_items) free(update_items);
            goto cleanup;

        case CONFIRM_SKIP_NEW_FILES:
            /* User declined new files - would need to filter array
             * For now, treat as cancellation (complex to re-filter) */
            output_info(out, "Skipping new files not yet implemented in v2");
            if (update_items) free(update_items);
            goto cleanup;

        case CONFIRM_PROCEED:
            /* Continue with operation */
            break;
    }

    /* Execute profile updates - workspace provides metadata cache for O(1) lookups */
    hashmap_t *by_profile = NULL;
    err = update_execute_for_all_profiles(repo, profiles, update_items, update_count,
                                             opts, out, config, ws, &total_updated, &by_profile);

    /* Free update_items array (items themselves are owned by workspace) */
    if (update_items) {
        free(update_items);
        update_items = NULL;
    }
    if (err) {
        if (by_profile) {
            hashmap_free(by_profile, item_array_free);
        }
        goto cleanup;
    }

    /* Update manifest if any profiles enabled
     *
     * This maintains the manifest as a Virtual Working Directory - a staging
     * area between Git and the filesystem. Files are marked DEPLOYED because
     * UPDATE captures them FROM the filesystem (already at target locations).
     *
     * Non-fatal: If manifest update fails, Git commits still succeeded.
     * User can repair manifest by running 'dotta profile enable <profile>'.
     */
    bool manifest_updated = false;
    error_t *manifest_err = update_manifest_after_update(
        repo, by_profile, opts, out, &manifest_updated
    );

    /* Free by_profile hashmap after manifest sync */
    if (by_profile) {
        hashmap_free(by_profile, item_array_free);
        by_profile = NULL;
    }

    if (manifest_err) {
        /* Non-fatal: commits succeeded but manifest update failed */
        output_warning(out, "Failed to update manifest: %s",
                      error_message(manifest_err));
        output_info(out, "Files committed to Git successfully");
        output_hint(out, "Run 'dotta status' to check manifest state");
        output_hint(out, "Or run 'dotta profile enable <profile>' to repair");
        error_free(manifest_err);
        /* Continue to post-update hook and success output */
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
    output_success(out, "Updated %zu item%s across %zu profile%s",
                   total_updated, total_updated == 1 ? "" : "s",
                   profiles->count, profiles->count == 1 ? "" : "s");

    /* Manifest status feedback */
    output_newline(out);
    if (manifest_updated) {
        output_info(out, "Manifest updated (%zu item%s synced)",
                   total_updated, total_updated == 1 ? "" : "s");
        output_hint(out, "Files committed from filesystem (marked as DEPLOYED)");
        output_hint(out, "Run 'dotta status' to verify manifest state");
    } else {
        output_info(out, "No enabled profiles - manifest not updated");
        output_hint(out, "Run 'dotta profile enable <profile>' to activate manifest tracking");
    }

cleanup:
    /* Free all resources in reverse order */
    if (hook_ctx) hook_context_free(hook_ctx);
    if (ws) workspace_free(ws);
    if (profiles_str) free(profiles_str);
    if (repo_dir) free(repo_dir);
    if (profiles) profile_list_free(profiles);
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}
