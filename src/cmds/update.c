/**
 * update.c - Update profiles with modified files
 */

#include "cmds/update.h"

#include <dirent.h>
#include <errno.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/match.h"
#include "base/output.h"
#include "base/string.h"
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
#include "sys/filesystem.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/hooks.h"
#include "utils/privilege.h"

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
    const config_t *config,
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

        /* Capture symlink stat so metadata_capture_from_file detects S_ISLNK */
        if (out_stat) {
            if (lstat(filesystem_path, out_stat) != 0) {
                err = ERROR(
                    ERR_INTERNAL, "Failed to stat symlink '%s': %s",
                    filesystem_path, strerror(errno)
                );
                goto cleanup;
            }
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
            err = error_wrap(
                err, "Failed to determine encryption policy for '%s'",
                storage_path
            );
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
 * Per-item result from file copy operations
 *
 * Tracks results from copy_file_to_worktree() for each workspace item.
 * Indexed by item position (not file-only position) to prevent index
 * misalignment between update_profile() and update_metadata_for_profile().
 *
 * Memory: calloc-initialized, so unprocessed items have copied=false.
 */
typedef struct {
    bool copied;          /* File was successfully copied to worktree */
    bool encrypted;       /* File was encrypted during copy */
    struct stat stat;     /* Captured stat data (valid only if copied=true) */
} file_copy_result_t;

/**
 * Check if storage path should be excluded by CLI patterns
 *
 * Helper function for filter_items_for_update(). Matches against storage
 * paths (VWD namespace) for portable, machine-independent patterns.
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
 * Check if a workspace item's state/divergence qualifies for update
 *
 * Pure predicate — no side effects, no filtering by path/profile/exclusion.
 * Extracted to single source of truth for state eligibility logic.
 */
static bool is_update_candidate(
    const workspace_item_t *item,
    const cmd_update_options_t *opts,
    const config_t *config
) {
    /* Determine if item should be included based on state + divergence */
    switch (item->state) {
        case WORKSPACE_STATE_DEPLOYED:
            /* Deployed files/dirs with divergence - check what kind.
             *
             * Mask DIVERGENCE_STALE: stale-only files have no local changes
             * (content matches current Git state after in-memory patching). */
            if ((item->divergence & ~DIVERGENCE_STALE) != DIVERGENCE_NONE) {
                return !opts->only_new;
            }
            /* DEPLOYED + NONE/STALE-only = clean, exclude */
            return false;

        case WORKSPACE_STATE_DELETED:
            /* File removed from filesystem - include unless --only-new */
            return !opts->only_new;

        case WORKSPACE_STATE_UNTRACKED:
            /* New files - include if:
             * - Explicit flags set (--include-new or --only-new), OR
             * - Config auto_detect_new_files is enabled (for confirmation prompt) */
            return (opts->include_new || opts->only_new ||
                   (config && config->auto_detect_new_files));

        case WORKSPACE_STATE_UNDEPLOYED:
        case WORKSPACE_STATE_ORPHANED:
        case WORKSPACE_STATE_RELEASED:
            /* Not relevant for update command:
             * - UNDEPLOYED: handled by apply command
             * - ORPHANED: handled by remove command
             * - RELEASED: handled by apply command */
            return false;
    }

    return false;
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
 * - operation_profiles: Only items from specified profiles (CLI -p filter)
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
 * @param file_filter Pre-resolved file filter (NULL = all files, matches by storage_path)
 * @param operation_profiles Profile filter (NULL = all profiles, filters by item->profile)
 * @param config Configuration (can be NULL, used for auto_detect_new_files)
 * @param out Output context (for verbose logging, can be NULL)
 * @param out_items Output array of pointers to workspace_item_t (must not be NULL, caller must free array)
 * @param count_out Output count (must not be NULL)
 * @return Error or NULL on success (out_items will be NULL if no matches)
 */
static error_t *filter_items_for_update(
    const workspace_t *ws,
    const cmd_update_options_t *opts,
    const path_filter_t *file_filter,
    const char *const *filter_names,
    size_t filter_count,
    const config_t *config,
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

        if (!is_update_candidate(item, opts, config)) {
            continue;
        }

        /* Apply CLI file filter (using storage_path for canonical matching) */
        if (!path_filter_matches(file_filter, item->storage_path)) {
            continue;
        }

        /* Apply exclusion patterns */
        if (matches_exclude_pattern(item->storage_path, opts)) {
            output_info(out, OUTPUT_VERBOSE, "Excluded: %s", item->filesystem_path);
            continue;
        }

        /* Apply profile filter (CLI -p filtering) */
        if (!profile_filter_matches(item->profile, filter_names, filter_count)) {
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

        if (!is_update_candidate(item, opts, config)) {
            continue;
        }

        /* Apply CLI file filter (using storage_path for canonical matching) */
        if (!path_filter_matches(file_filter, item->storage_path)) {
            continue;
        }
        if (matches_exclude_pattern(item->storage_path, opts)) {
            continue;
        }
        /* Apply profile filter (CLI -p filtering) */
        if (!profile_filter_matches(item->profile, filter_names, filter_count)) {
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

    hashmap_t *groups = hashmap_borrow(32);
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
 * copy_results is indexed by item position (same index as items array).
 * Only items with copy_results[i].copied == true have valid stat/encryption data.
 *
 * @param wt Worktree handle (must not be NULL)
 * @param items Array of workspace items to update (must not be NULL)
 * @param item_count Number of items
 * @param copy_results Per-item copy results indexed by item position (can be NULL)
 * @param opts Update options (must not be NULL)
 * @param out Output context (can be NULL)
 * @return Error or NULL on success
 */
static error_t *update_metadata_for_profile(
    worktree_handle_t *wt,
    const workspace_item_t **items,
    size_t item_count,
    const file_copy_result_t *copy_results,
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
                        output_info(
                            out, OUTPUT_VERBOSE, "  Removed metadata: %s",
                            item->filesystem_path
                        );
                    }
                    continue;
                }

                /* Skip files not copied to worktree (e.g., encryption-divergence
                 * on files missing from filesystem). Indexed by item position. */
                if (!copy_results || !copy_results[i].copied) {
                    continue;
                }

                const struct stat *file_stat = &copy_results[i].stat;

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
                    return error_wrap(
                        err, "Failed to capture metadata for: %s",
                        item->filesystem_path
                    );
                }

                /* meta_item is NULL for home/ prefix symlinks (no metadata needed).
                 * Non-NULL for files and root/ prefix symlinks (ownership tracked). */
                if (meta_item) {
                    /* Only set encrypted flag for FILE kind (symlinks are never encrypted) */
                    if (meta_item->kind == METADATA_ITEM_FILE) {
                        meta_item->file.encrypted = copy_results[i].encrypted;
                    }

                    /* Save metadata before adding (for verbose output) */
                    mode_t mode = meta_item->mode;
                    char *owner = meta_item->owner ? strdup(meta_item->owner) : NULL;
                    char *group = meta_item->group ? strdup(meta_item->group) : NULL;
                    bool is_encrypted = (meta_item->kind == METADATA_ITEM_FILE)
                                      ? meta_item->file.encrypted : false;

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

                    if (owner || group) {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "  Captured metadata: %s (mode: %04o, owner: %s:%s%s)",
                            item->filesystem_path, mode, owner ? owner : "?",
                            group ? group : "?", is_encrypted ? ", encrypted" : ""
                        );
                    } else {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "  Captured metadata: %s (mode: %04o%s)",
                            item->filesystem_path, mode, is_encrypted ? ", encrypted" : ""
                        );
                    }
                    free(owner);
                    free(group);
                }

                break;
            }

            case WORKSPACE_ITEM_DIRECTORY: {
                /* Handle directory metadata */

                /* Stat directory to capture current metadata */
                struct stat dir_stat;
                if (stat(item->filesystem_path, &dir_stat) != 0) {
                    output_warning(
                        out, OUTPUT_VERBOSE, "Failed to stat directory '%s': %s",
                        item->filesystem_path, strerror(errno)
                    );
                    continue;
                }

                /* Capture directory metadata */
                metadata_item_t *meta_item = NULL;
                err = metadata_capture_from_directory(
                    item->storage_path, &dir_stat, &meta_item
                );

                if (err) {
                    output_warning(
                        out, OUTPUT_VERBOSE,
                        "Failed to capture metadata for directory '%s': %s",
                        item->filesystem_path, error_message(err)
                    );
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
                    return error_wrap(
                        err, "Failed to update directory metadata for '%s'",
                        item->filesystem_path
                    );
                }

                updated_dir_count++;

                if (owner || group) {
                    output_info(
                        out, OUTPUT_VERBOSE,
                        "  Updated directory metadata: %s (mode: %04o, owner: %s:%s)",
                        item->filesystem_path, mode, owner ? owner : "?", group ? group : "?"
                    );
                } else {
                    output_info(
                        out, OUTPUT_VERBOSE,
                        "  Updated directory metadata: %s (mode: %04o)",
                        item->filesystem_path, mode
                    );
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
    err = worktree_stage_file(wt, METADATA_FILE_PATH);
    if (err) {
        return error_wrap(err, "Failed to stage metadata");
    }

    if (captured_file_count > 0 || updated_dir_count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "Updated metadata for %zu file(s) and %zu director%s",
            captured_file_count, updated_dir_count, updated_dir_count == 1 ? "y" : "ies"
        );
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
 * @param out_processed Output: number of items committed (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *update_profile(
    worktree_handle_t *wt,
    profile_t *profile,
    const workspace_item_t **items,
    size_t item_count,
    const cmd_update_options_t *opts,
    output_ctx_t *out,
    const config_t *config,
    workspace_t *ws,
    size_t *out_processed
) {
    CHECK_NULL(wt);
    CHECK_NULL(profile);
    CHECK_NULL(items);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(out_processed);

    *out_processed = 0;

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
    char **storage_paths = NULL;
    char *message = NULL;
    error_t *err = NULL;
    metadata_t *existing_metadata = NULL;
    bool owns_metadata = false;
    keymanager_t *key_mgr = NULL;
    file_copy_result_t *copy_results = NULL;

    /* Try to get metadata from workspace cache first */
    if (ws) {
        existing_metadata = (metadata_t *) workspace_get_metadata(ws, profile->name);
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
                return error_wrap(
                    err, "Failed to load metadata from profile '%s'",
                    profile->name
                );
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

    /* Allocate per-item result tracking (indexed by item position, not file-only position).
     * This prevents index misalignment between update_profile and update_metadata_for_profile
     * when files are skipped (e.g., encryption-divergence on missing files). */
    copy_results = calloc(item_count, sizeof(file_copy_result_t));
    if (!copy_results) {
        err = ERROR(ERR_MEMORY, "Failed to allocate copy results array");
        goto cleanup;
    }

    /* Get worktree index for staging */
    err = worktree_get_index(wt, &index);
    if (err) {
        err = error_wrap(err, "Failed to get worktree index");
        goto cleanup;
    }

    /* Process all items in a single unified loop */
    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        /* Dispatch by item kind */
        switch (item->item_kind) {
            case WORKSPACE_ITEM_FILE: {
                /* Handle file operations */
                output_info(out, OUTPUT_VERBOSE, "  %s", item->filesystem_path);

                /* Handle deleted files */
                if (item->state == WORKSPACE_STATE_DELETED) {
                    /* Remove from index (stage deletion) */
                    int git_err = git_index_remove_bypath(index, item->storage_path);
                    if (git_err < 0) {
                        err = error_from_git(git_err);
                        goto cleanup;
                    }
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
                    output_warning(
                        out, OUTPUT_VERBOSE,
                        "Skipping encryption fix for missing file: %s", item->filesystem_path
                    );
                    output_info(
                        out, OUTPUT_VERBOSE,
                        "  File violates encryption policy but doesn't exist on filesystem."
                    );
                    output_info(
                        out, OUTPUT_VERBOSE,
                        "  To resolve: re-create file and run update, or remove from profile."
                    );
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
                    &copy_results[i].encrypted,
                    &copy_results[i].stat
                );
                if (err) {
                    err = error_wrap(err, "Failed to copy '%s'", item->filesystem_path);
                    goto cleanup;
                }

                copy_results[i].copied = true;

                /* Stage file */
                int git_err = git_index_add_bypath(index, item->storage_path);
                if (git_err < 0) {
                    err = error_from_git(git_err);
                    goto cleanup;
                }

                break;
            }

            case WORKSPACE_ITEM_DIRECTORY: {
                /* Directories are handled purely in metadata - no file operations needed */
                /* Metadata update happens in update_metadata_for_profile() call below */
                break;
            }
        }
    }

    /* Update metadata for both files and directories */
    err = update_metadata_for_profile(
        wt, items, item_count, copy_results, opts, out
    );
    if (err) {
        err = error_wrap(err, "Failed to update metadata");
        goto cleanup;
    }

    /* Note: metadata function already wrote the index */

    /* Build array of storage paths for commit message */
    storage_paths = malloc(item_count * sizeof(char *));
    if (!storage_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
        goto cleanup;
    }

    size_t path_count = 0;
    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        if (item->item_kind == WORKSPACE_ITEM_FILE) {
            /* Include deleted files (staged for removal) */
            if (item->state == WORKSPACE_STATE_DELETED) {
                storage_paths[path_count++] = item->storage_path;
            } else if (copy_results && copy_results[i].copied) {
                /* Include files that were copied to worktree */
                storage_paths[path_count++] = item->storage_path;
            }
            /* Skip files not processed (e.g., encryption-divergence on missing) */
        } else if (item->item_kind == WORKSPACE_ITEM_DIRECTORY) {
            storage_paths[path_count++] = item->storage_path;
        }
    }

    /* Skip commit if nothing was processed */
    if (path_count == 0) {
        goto cleanup;
    }

    /* Build commit message context */
    commit_message_context_t ctx = {
        .action        = COMMIT_ACTION_UPDATE,
        .profile       = profile->name,
        .files         = storage_paths,
        .file_count    = path_count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };

    message = build_commit_message(config, &ctx);
    if (!message) {
        err = ERROR(ERR_MEMORY, "Failed to build commit message");
        goto cleanup;
    }

    /* Create commit */
    err = worktree_commit(wt, profile->name, message, NULL);
    if (err) {
        err = error_wrap(err, "Failed to create commit");
        goto cleanup;
    }

    *out_processed = path_count;

cleanup:
    /* Free resources in reverse order */
    if (message) free(message);
    if (storage_paths) free(storage_paths);
    if (index) git_index_free(index);
    if (owns_metadata && existing_metadata) metadata_free(existing_metadata);
    if (copy_results) free(copy_results);

    return err;
}

/**
 * Flatten items_by_profile hashmap into single array
 *
 * Converts hashmap<profile → item_array> into flat array of item pointers.
 * Items are borrowed references (valid while hashmap lives).
 *
 * @param items_by_profile Hashmap to flatten (must not be NULL)
 * @param out_items Output array of borrowed pointers (caller must free array, not items)
 * @param out_count Output count (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *flatten_items_to_array(
    const hashmap_t *items_by_profile,
    const workspace_item_t ***out_items,
    size_t *out_count
) {
    CHECK_NULL(items_by_profile);
    CHECK_NULL(out_items);
    CHECK_NULL(out_count);

    /* First pass: count total items across all profiles */
    size_t total_count = 0;
    hashmap_iter_t iter;
    hashmap_iter_init(&iter, items_by_profile);
    void *value;

    while (hashmap_iter_next(&iter, NULL, &value)) {
        item_array_t *arr = value;
        total_count += arr->count;
    }

    if (total_count == 0) {
        *out_items = NULL;
        *out_count = 0;
        return NULL;
    }

    /* Allocate array for flattened items */
    const workspace_item_t **items = calloc(total_count, sizeof(workspace_item_t *));
    if (!items) {
        return ERROR(ERR_MEMORY, "Failed to allocate items array");
    }

    /* Second pass: collect all items into flat array */
    size_t idx = 0;
    hashmap_iter_init(&iter, items_by_profile);

    while (hashmap_iter_next(&iter, NULL, &value)) {
        item_array_t *arr = value;
        for (size_t i = 0; i < arr->count; i++) {
            items[idx++] = arr->items[i];
        }
    }

    *out_items = items;
    *out_count = total_count;

    return NULL;
}

/**
 * Update manifest after successful update operation
 *
 * NEW IMPLEMENTATION: Uses bulk sync API for optimal O(M+N) performance.
 * Builds fresh manifest from Git once, then batch-processes all files.
 *
 * Called after ALL profile updates succeed. Updates manifest for files
 * that were modified/added/deleted, maintaining the manifest as a
 * Virtual Working Directory.
 *
 * This function implements the VWD integration for the update command.
 * After Git commits succeed, the manifest is synced to reflect the new
 * state. This keeps the three-way consistency: Git ↔ Manifest ↔ Filesystem.
 *
 * Lifecycle Tracking:
 *   - Modified/New files: deployed_at set based on lstat() (already on filesystem)
 *   - Deleted files: handled by bulk function (entries remain for orphan detection or fallback)
 *
 * Algorithm:
 *   1. Check if any profiles enabled (read-only, upfront optimization)
 *   2. If none enabled: return NULL (skip manifest update gracefully)
 *   3. Open transaction (state_load_for_update)
 *   4. Flatten items_by_profile hashmap into single array
 *   5. Call manifest_update_files() ONCE (O(M+N))
 *   6. Commit transaction (state_save)
 *   7. Set *out_updated = true
 *
 * Preconditions:
 *   - All profile updates already succeeded (Git commits done)
 *   - items_by_profile contains profile_name → item_array_t mappings
 *   - ws contains valid workspace with metadata cache
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
 * Performance: O(M + N) where M = total files in profiles, N = updated files
 * Old implementation: O(N × M) - up to 833x slower!
 *
 * @param repo Git repository (must not be NULL)
 * @param ws Workspace for accessing km and metadata cache (must not be NULL)
 * @param items_by_profile Hashmap: profile_name → item_array_t* (must not be NULL)
 * @param opts Update options for verbose flag (must not be NULL)
 * @param out Output context for verbose logging (can be NULL)
 * @param out_updated Output flag: true if manifest was updated (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *update_manifest_after_update(
    git_repository *repo,
    workspace_t *ws,
    const hashmap_t *items_by_profile,
    const cmd_update_options_t *opts,
    output_ctx_t *out,
    bool *out_updated
) {
    CHECK_NULL(repo);
    CHECK_NULL(ws);
    CHECK_NULL(items_by_profile);
    CHECK_NULL(opts);
    CHECK_NULL(out_updated);

    error_t *err = NULL;
    state_t *state = NULL;
    string_array_t *enabled_profiles = NULL;
    const workspace_item_t **all_items = NULL;
    size_t item_count = 0;

    /* Initialize output */
    *out_updated = false;

    /* Check if ANY profiles enabled (upfront optimization) */
    err = state_load(repo, &state);
    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            error_free(err);
            return NULL;  /* No state file - nothing to do */
        }
        return error_wrap(err, "Failed to load state for manifest check");
    }

    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        state_free(state);
        return error_wrap(err, "Failed to get enabled profiles");
    }

    if (enabled_profiles->count == 0) {
        string_array_free(enabled_profiles);
        state_free(state);
        return NULL;  /* No profiles enabled - nothing to do */
    }

    state_free(state);
    state = NULL;

    /* Open transaction for manifest updates */
    err = state_load_for_update(repo, &state);
    if (err) {
        string_array_free(enabled_profiles);
        return error_wrap(err, "Failed to open state transaction");
    }

    /* Flatten items_by_profile into single array */
    err = flatten_items_to_array(items_by_profile, &all_items, &item_count);
    if (err) {
        goto cleanup;
    }

    if (item_count == 0) {
        /* No items to sync */
        goto cleanup;
    }

    /* Get workspace resources
     *
     * IMPORTANT: Do NOT use workspace metadata cache - it was loaded before
     * Git commits and is now stale. Pass NULL to manifest_update_files() to
     * force fresh metadata loading from the updated Git state. */
    /* Use bulk sync operation (O(M + N) - optimal!) */
    size_t synced = 0, removed = 0, fallbacks = 0;
    err = manifest_update_files(
        repo,
        state,
        all_items,
        item_count,
        enabled_profiles,
        NULL,  /* metadata_cache - pass NULL for fresh load */
        &synced,
        &removed,
        &fallbacks
    );

    if (err) {
        err = error_wrap(err, "Failed to sync manifest in bulk");
        goto cleanup;
    }

    /* Record stat cache for updated files (fast-path optimization)
     *
     * Files were just captured from filesystem — content matches blob_oid.
     * Skip deleted items (file doesn't exist) and directories (no stat cache). */
    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = all_items[i];
        if (item->item_kind != WORKSPACE_ITEM_FILE ||
            item->state == WORKSPACE_STATE_DELETED) {
            continue;
        }
        struct stat st;
        if (lstat(item->filesystem_path, &st) == 0) {
            stat_cache_t sc = stat_cache_from_stat(&st);
            state_update_stat_cache(state, item->filesystem_path, &sc);
        }
    }

    /* Commit transaction */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to save manifest updates");
        goto cleanup;
    }

    *out_updated = true;

    /* Verbose summary */
    if (synced > 0 || removed > 0 || fallbacks > 0) {
        output_info(
            out, OUTPUT_VERBOSE,
            "Manifest synced: %zu updated, %zu removed, %zu fallbacks",
            synced, removed, fallbacks
        );
    }

cleanup:
    free(all_items);  /* Free array, not items (borrowed) */
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
    const config_t *config,
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
    profile_index = hashmap_borrow(32);
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

    /* Update each profile using iterator */
    hashmap_iter_t iter;
    hashmap_iter_init(&iter, by_profile);
    const char *profile_name;
    void *value;

    while (hashmap_iter_next(&iter, &profile_name, &value)) {
        item_array_t *array = (item_array_t *) value;

        /* Look up profile pointer */
        profile_t *profile = hashmap_get(profile_index, profile_name);

        if (!profile) {
            /* Profile not in enabled set - skip (shouldn't happen due to filtering) */
            output_warning(
                out, OUTPUT_NORMAL,
                "Profile '%s' not found in enabled profiles, skipping",
                profile_name
            );
            continue;
        }

        if (array->count == 0) {
            continue;
        }

        /* Display profile header */
        output_info(
            out, OUTPUT_NORMAL, "Updating profile '{cyan}%s{reset}':",
            profile->name
        );

        /* Checkout profile branch in shared worktree */
        err = worktree_checkout_branch(wt, profile->name);
        if (err) {
            err = error_wrap(
                err, "Failed to checkout profile '%s'",
                profile->name
            );
            break;
        }

        /* Update this profile using shared worktree */
        size_t processed = 0;
        err = update_profile(
            wt, profile, array->items, array->count, opts,
            out, config, ws, &processed
        );

        if (err) {
            err = error_wrap(
                err, "Failed to update profile '%s'",
                profile->name
            );
            break;
        }

        *total_updated += processed;

        if (!output_is_verbose(out) && processed > 0) {
            output_success(
                out, OUTPUT_NORMAL, "  Updated %zu item%s",
                processed, processed == 1 ? "" : "s"
            );
        }
    }

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
    if (wt) worktree_cleanup(&wt);

    return err;
}

/**
 * Display summary of items to be updated
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
        output_styled(
            out, OUTPUT_NORMAL, "{bold}Dry Run{reset} - No changes will be committed\n\n"
        );
    }

    /* Show filter context if any filters are active */
    if (opts) {
        bool has_filters = false;

        if (opts->only_new) {
            output_info(
                out, OUTPUT_NORMAL,
                "Filter: Showing only new files (--only-new)"
            );
            has_filters = true;
        } else if (opts->include_new) {
            output_info(
                out, OUTPUT_NORMAL,
                "Filter: Including new files from tracked directories (--include-new)"
            );
            has_filters = true;
        }

        if (opts->file_count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Filter: Limiting to %zu specified file%s",
                opts->file_count, opts->file_count == 1 ? "" : "s"
            );
            has_filters = true;
        }

        if (opts->exclude_count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Filter: Excluding %zu pattern%s",
                opts->exclude_count, opts->exclude_count == 1 ? "" : "s"
            );
            has_filters = true;
        }

        if (has_filters) {
            output_newline(out, OUTPUT_NORMAL);
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
                case WORKSPACE_STATE_RELEASED:
                    /* Should not appear in filtered results, but be defensive */
                    break;
            }
        } else if (item->item_kind == WORKSPACE_ITEM_DIRECTORY) {
            dir_count++;
        }
    }

    /* Display modified files section */
    if (modified_count > 0) {
        output_list_t *list = output_list_create(
            out, "Modified files",
            "use \"dotta update\" to commit these changes"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->item_kind != WORKSPACE_ITEM_FILE) {
                    continue;
                }

                /* Check if file is deployed and has (non-stale) divergence */
                bool is_modified = (item->state == WORKSPACE_STATE_DEPLOYED &&
                    (item->divergence & ~DIVERGENCE_STALE) != DIVERGENCE_NONE);

                if (!is_modified) {
                    continue;
                }

                /* Extract tags using shared helper */
                const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                size_t tag_count;
                output_color_t color;
                char base_metadata[256];

                if (!workspace_item_extract_display_info(
                    item, tags, &tag_count, &color,
                    base_metadata, sizeof(base_metadata)
                    )) {
                    continue;
                }

                output_list_add(
                    list, tags, tag_count, color,
                    item->filesystem_path, base_metadata
                );
            }

            output_list_render(list);
            output_list_free(list);
        }
    }

    /* Display new files section */
    if (new_count > 0) {
        output_list_t *list = output_list_create(
            out, "New files",
            "use \"dotta update --include-new\" to track these files"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->item_kind == WORKSPACE_ITEM_FILE &&
                    item->state == WORKSPACE_STATE_UNTRACKED
                ) {
                    const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                    size_t tag_count;
                    output_color_t color;
                    char metadata[256];

                    if (workspace_item_extract_display_info(
                        item, tags, &tag_count, &color,
                        metadata, sizeof(metadata)
                        )) {
                        output_list_add(
                            list, tags, tag_count, color,
                            item->filesystem_path, metadata
                        );
                    }
                }
            }

            output_list_render(list);
            output_list_free(list);
        }
    }

    /* Display deleted files section (if any - rare in update context) */
    if (deleted_count > 0) {
        output_list_t *list = output_list_create(
            out, "Deleted files",
            "these files will be removed from the profile"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->item_kind == WORKSPACE_ITEM_FILE &&
                    item->state == WORKSPACE_STATE_DELETED
                ) {
                    const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                    size_t tag_count;
                    output_color_t color;
                    char metadata[256];

                    if (workspace_item_extract_display_info(
                        item, tags, &tag_count, &color,
                        metadata, sizeof(metadata)
                        )) {
                        output_list_add(
                            list, tags, tag_count, color,
                            item->filesystem_path, metadata
                        );
                    }
                }
            }

            output_list_render(list);
            output_list_free(list);
        }
    }

    /* Display modified directories section */
    if (dir_count > 0) {
        output_list_t *list = output_list_create(
            out, "Modified directories",
            "directory metadata will be updated"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->item_kind != WORKSPACE_ITEM_DIRECTORY) {
                    continue;
                }

                /* Extract tags and metadata using helper */
                const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                size_t tag_count;
                output_color_t color;
                char base_metadata[256];

                if (workspace_item_extract_display_info(
                    item, tags, &tag_count, &color,
                    base_metadata, sizeof(base_metadata)
                    )) {
                    /* Build custom content with trailing slash for directories */
                    char path_with_slash[PATH_MAX + 2];
                    snprintf(
                        path_with_slash, sizeof(path_with_slash), "%s/",
                        item->filesystem_path
                    );

                    /* Build custom metadata with explicit "directory" indicator */
                    char metadata[256];
                    snprintf(
                        metadata, sizeof(metadata), "directory %s",
                        base_metadata
                    );

                    output_list_add(
                        list, tags, tag_count, color,
                        path_with_slash, metadata
                    );
                }
            }

            output_list_render(list);
            output_list_free(list);
        }
    }

    /* Display encryption policy violations section */
    if (encryption_count > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "The following files match auto-encrypt "
            "patterns but are stored as plaintext:"
        );

        output_list_t *list = output_list_create(
            out, "Encryption policy violations",
            NULL
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->item_kind != WORKSPACE_ITEM_FILE ||
                    !(item->divergence & DIVERGENCE_ENCRYPTION)) {
                    continue;
                }

                /* Build metadata with profile and resolution status */
                char metadata[512];
                const char *status = item->on_filesystem
                    ? "will be encrypted" : "file missing - cannot fix";

                snprintf(
                    metadata, sizeof(metadata), "from %s, %s",
                    item->profile, status
                );

                /* Single tag for policy violation */
                const char *tags[] = { "plaintext" };
                output_list_add(
                    list, tags, 1, OUTPUT_COLOR_RED,
                    item->filesystem_path, metadata
                );
            }

            output_list_render(list);
            output_list_free(list);
        }

        output_newline(out, OUTPUT_NORMAL);
        output_info(
            out, OUTPUT_NORMAL, "These files will be re-encrypted according to "
            "your auto_encrypt_patterns config."
        );
        output_info(
            out, OUTPUT_NORMAL, "To keep a file as plaintext, use: "
            "dotta update --no-encrypt <file>"
        );
    }

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
    const config_t *config,
    confirm_result_t *result
) {
    CHECK_NULL(out);
    CHECK_NULL(opts);
    CHECK_NULL(items);
    CHECK_NULL(result);

    *result = CONFIRM_PROCEED;

    /* Count items by category */
    size_t modified_count = 0;
    size_t deleted_count = 0;
    size_t new_count = 0;
    size_t dir_count = 0;

    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        if (item->item_kind == WORKSPACE_ITEM_FILE) {
            if (item->state == WORKSPACE_STATE_UNTRACKED) {
                new_count++;
            } else if (item->state == WORKSPACE_STATE_DELETED) {
                deleted_count++;
            } else {
                modified_count++;
            }
        } else if (item->item_kind == WORKSPACE_ITEM_DIRECTORY) {
            dir_count++;
        }
    }

    /* Dry run - show breakdown and exit */
    if (opts->dry_run) {
        output_info(out, OUTPUT_NORMAL, "Dry run: no changes will be committed");
        if (modified_count > 0)
            output_info(
                out, OUTPUT_NORMAL, "  %zu modified file%s to update",
                modified_count, modified_count == 1 ? "" : "s"
            );
        if (deleted_count > 0)
            output_info(
                out, OUTPUT_NORMAL, "  %zu deleted file%s to remove",
                deleted_count, deleted_count == 1 ? "" : "s"
            );
        if (new_count > 0)
            output_info(
                out, OUTPUT_NORMAL, "  %zu new file%s to add",
                new_count, new_count == 1 ? "" : "s"
            );
        if (dir_count > 0)
            output_info(
                out, OUTPUT_NORMAL, "  %zu director%s to update metadata",
                dir_count, dir_count == 1 ? "y" : "ies"
            );
        *result = CONFIRM_DRY_RUN;
        return NULL;
    }

    /* Interactive confirmation */
    if (opts->interactive) {
        if (!output_confirm(out, "Update these items?", false)) {
            output_info(out, OUTPUT_NORMAL, "Cancelled");
            *result = CONFIRM_CANCELLED;
            return NULL;
        }
    }

    /* Confirmation for new files (if auto-detected, not explicit flag) */
    if (new_count > 0 && config && config->confirm_new_files &&
        !opts->include_new && !opts->only_new && config->auto_detect_new_files) {

        char confirm_msg[128];
        snprintf(
            confirm_msg, sizeof(confirm_msg), "Found %zu new file%s. Add %s to profiles?",
            new_count, new_count == 1 ? "" : "s", new_count == 1 ? "it" : "them"
        );
        if (!output_confirm(out, confirm_msg, false)) {
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
    const config_t *config,
    output_ctx_t *out,
    const cmd_update_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(config);
    CHECK_NULL(opts);

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    profile_list_t *workspace_profiles = NULL;
    profile_list_t *operation_profiles = NULL;
    const char **filter_names = NULL;
    size_t filter_count = 0;
    workspace_t *ws = NULL;
    hook_context_t *hook_ctx = NULL;
    char *repo_dir = NULL;
    char *profiles_str = NULL;
    path_filter_t *file_filter = NULL;
    const workspace_item_t **update_items = NULL;
    size_t update_count = 0;
    size_t total_updated = 0;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Load profiles
     *
     * Dual-list pattern ensures workspace scope consistency:
     * - workspace_profiles: Persistent enabled profiles for VWD scope and orphan detection
     * - operation_profiles: CLI filter or shared pointer for update operations
     *
     * This separation maintains accurate workspace analysis while supporting
     * selective update operations via CLI filtering.
     */

    /* Phase 1: Load workspace profiles (persistent enabled profiles) */
    err = profile_resolve_for_workspace(
        repo, config->strict_mode, &workspace_profiles
    );
    if (err) {
        err = error_wrap(err, "Failed to resolve enabled profiles");
        goto cleanup;
    }

    if (workspace_profiles->count == 0) {
        err = ERROR(
            ERR_NOT_FOUND, "No enabled profiles found\n"
            "Hint: Run 'dotta profile enable <name>' to enable profiles"
        );
        goto cleanup;
    }

    /* Phase 2: Load operation profiles (CLI filter or shared pointer) */
    if (opts->profiles && opts->profile_count > 0) {
        /* CLI filter specified - load operation filter profiles */
        err = profile_resolve_for_operations(
            repo, opts->profiles, opts->profile_count,
            config->strict_mode, &operation_profiles
        );
        if (err) {
            err = error_wrap(err, "Failed to resolve operation profiles");
            goto cleanup;
        }

        /* Validate: filter profiles must be enabled in workspace */
        err = profile_validate_filter(workspace_profiles, operation_profiles);
        if (err) goto cleanup;

        /* Extract filter names for downstream filtering (name-only consumers) */
        filter_names = profile_list_extract_names(operation_profiles, &filter_count);
        if (!filter_names) {
            err = ERROR(ERR_MEMORY, "Failed to extract filter profile names");
            goto cleanup;
        }
    } else {
        /* No CLI filter - share workspace profiles (optimization) */
        operation_profiles = workspace_profiles;
    }

    /* Get repository directory for hooks */
    err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        goto cleanup;
    }

    /* Execute pre-update hook (using operation profiles for context) */
    if (config && repo_dir) {
        /* Build array of profile names and join with spaces */
        const char **profile_names_array = malloc(operation_profiles->count * sizeof(const char *));
        if (profile_names_array) {
            for (size_t i = 0; i < operation_profiles->count; i++) {
                profile_names_array[i] = operation_profiles->profiles[i].name;
            }
            profiles_str = str_join(profile_names_array, operation_profiles->count, " ");
            free(profile_names_array);
        }

        if (profiles_str) {
            /* Create hook context with operation profiles */
            hook_ctx = hook_context_create(repo_dir, "update", profiles_str);
            if (hook_ctx) {
                hook_ctx->dry_run = opts->dry_run;
                err = hook_context_add_files(hook_ctx, opts->files, opts->file_count);
                if (err) goto cleanup;

                hook_result_t *hook_result = NULL;
                err = hook_execute(config, HOOK_PRE_UPDATE, hook_ctx, &hook_result);

                if (err) {
                    /* Hook failed - abort operation */
                    if (hook_result && hook_result->output && hook_result->output[0]) {
                        output_print(
                            out, OUTPUT_NORMAL, "Hook output:\n%s\n",
                            hook_result->output
                        );
                    }
                    hook_result_free(hook_result);
                    err = error_wrap(err, "Pre-update hook failed");
                    goto cleanup;
                }
                hook_result_free(hook_result);
            }
        }
    }

    /* Load workspace for update analysis
     *
     * Update processes files from the filesystem (either modified tracked files or new files)
     * and commits them to Git profiles. Analysis configuration:
     *
     * - analyze_files: Detects content and metadata changes in tracked files
     * - analyze_orphans: Disabled - update doesn't process orphaned state entries
     * - analyze_untracked: Discovers new files in tracked directories (when enabled)
     * - analyze_directories: Detects directory metadata changes for update
     * - analyze_encryption: Validates encryption policy for files being updated
     *
     * Orphan detection is unnecessary because update operates on manifest entries
     * (files from enabled profiles) and new files. Orphaned files (in state but not
     * in any enabled profile) are out of scope for update operations.
     *
     * State is NULL - this is read-only analysis. The transaction for manifest updates
     * opens later in update_manifest_after_update().
     */
    workspace_load_t ws_opts = {
        .analyze_files       = true,                    /* Detect content and metadata changes */
        .analyze_orphans     = false,                   /* Update doesn't process orphaned files */
        .analyze_untracked   = (opts->include_new || opts->only_new ||
            (config && config->auto_detect_new_files)), /* Explicit flags or config auto-detect */
        .analyze_directories = true,                    /* Directory metadata change detection */
        .analyze_encryption  = true                     /* Encryption policy validation */
    };
    err = workspace_load(repo, NULL, workspace_profiles, config, &ws_opts, &ws);
    if (err) {
        err = error_wrap(err, "Failed to analyze workspace");
        goto cleanup;
    }

    /* Create file filter from CLI arguments (pre-resolve to storage paths)
     *
     * Extract custom prefixes from operation profiles to enable proper resolution
     * of filesystem paths like /mnt/jail/etc/nginx.conf to custom/etc/nginx.conf.
     * Without this, such paths would incorrectly resolve to root/mnt/jail/etc/nginx.conf.
     */
    if (opts->files && opts->file_count > 0) {
        /* Extract custom prefixes from operation profiles */
        const char **custom_prefixes = NULL;
        size_t prefix_count = 0;

        if (operation_profiles && operation_profiles->count > 0) {
            custom_prefixes = calloc(operation_profiles->count, sizeof(char *));
            if (custom_prefixes) {
                for (size_t i = 0; i < operation_profiles->count; i++) {
                    if (operation_profiles->profiles[i].custom_prefix) {
                        custom_prefixes[prefix_count++] = operation_profiles->profiles[i].
                            custom_prefix;
                    }
                }
            }
        }

        err = path_filter_create(
            (const char **) opts->files, opts->file_count, custom_prefixes,
            prefix_count, &file_filter
        );
        free(custom_prefixes);  /* Array only, strings are borrowed from profiles */

        if (err) {
            err = error_wrap(err, "Failed to create file filter");
            goto cleanup;
        }
    }

    /* Filter items for update (handles all flags and edge cases internally)
     *
     * Uses operation_profiles for CLI -p filtering. This ensures display
     * matches execution - only items from specified profiles are shown.
     */
    err = filter_items_for_update(
        ws, opts, file_filter, filter_names, filter_count, config, out,
        &update_items, &update_count
    );
    if (err) {
        err = error_wrap(err, "Failed to filter items for update");
        goto cleanup;
    }

    /* Check if we have anything to update */
    if (update_count == 0) {
        if (opts->only_new) {
            output_info(out, OUTPUT_NORMAL, "No new files to add");
        } else if (opts->include_new) {
            output_info(out, OUTPUT_NORMAL, "No modified or new files/directories to update");
        } else {
            output_info(out, OUTPUT_NORMAL, "No modified files or directories to update");
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
            /* Extract paths needing elevation from file items.
             * Uses privilege_needs_elevation() which considers whether each
             * entry's custom prefix is under $HOME. */
            const char **storage_paths = calloc(file_count, sizeof(char *));
            if (!storage_paths) {
                err = ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
                goto cleanup;
            }

            size_t elevation_count = 0;
            for (size_t i = 0; i < update_count; i++) {
                const workspace_item_t *item = update_items[i];
                if (item->item_kind == WORKSPACE_ITEM_FILE) {
                    const char *prefix = item->source_profile
                                       ? item->source_profile->custom_prefix : NULL;

                    if (privilege_needs_elevation(item->storage_path, prefix)) {
                        storage_paths[elevation_count++] = item->storage_path;
                    }
                }
            }

            /* Check privilege requirements
             *
             * If paths needing root detected without root privileges:
             * - Interactive: Prompts user, re-execs with sudo if approved
             * - Non-interactive: Returns error with clear message
             *
             * If re-exec succeeds, this function DOES NOT RETURN.
             * If re-exec fails or user declines, returns error.
             */
            err = privilege_ensure_for_operation(
                storage_paths,
                elevation_count,
                "update",
                opts->interactive,  /* Use existing interactive flag */
                opts->argc,
                opts->argv,
                out
            );

            free(storage_paths);

            if (err) {
                /* User declined elevation or non-interactive mode blocked it */
                goto cleanup;
            }

            /* If we reach here, privileges are OK - proceed with operation */
        }
    }

    /* Display summary of items to update */
    err = update_display_summary(out, update_items, update_count, opts);
    if (err) {
        goto cleanup;
    }

    /* Handle user confirmations */
    confirm_result_t confirm_result;
    err = update_confirm_operation(
        out, opts, update_items, update_count, config, &confirm_result
    );
    if (err) {
        goto cleanup;
    }

    /* Handle confirmation result */
    switch (confirm_result) {
        case CONFIRM_CANCELLED:
        case CONFIRM_DRY_RUN:
            /* User cancelled or dry run - clean exit (not an error) */
            goto cleanup;

        case CONFIRM_SKIP_NEW_FILES: {
            /* User declined new files - filter them out, keep modified/deleted */
            size_t filtered = 0;
            for (size_t i = 0; i < update_count; i++) {
                if (update_items[i]->state != WORKSPACE_STATE_UNTRACKED) {
                    update_items[filtered++] = update_items[i];
                }
            }
            update_count = filtered;

            if (update_count == 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "No modified files remaining after skipping new files"
                );
                goto cleanup;
            }
            break;
        }

        case CONFIRM_PROCEED:
            /* Continue with operation */
            break;
    }

    /* Execute profile updates - workspace provides metadata cache for O(1) lookups
     *
     * Use operation_profiles to determine which profiles to update. This allows
     * CLI filtering while maintaining accurate workspace analysis with persistent profiles.
     */
    hashmap_t *by_profile = NULL;
    err = update_execute_for_all_profiles(
        repo, operation_profiles, update_items, update_count,
        opts, out, config, ws, &total_updated, &by_profile
    );

    /* Capture count before by_profile is freed */
    size_t updated_profile_count = by_profile ? hashmap_size(by_profile) : 0;

    if (err) {
        if (by_profile) {
            hashmap_free(by_profile, item_array_free);
        }
        goto cleanup;
    }

    /* Update manifest if any profiles enabled
     *
     * This maintains the manifest as a Virtual Working Directory - an expected
     * state cache between Git and the filesystem. Files get deployed_at set based
     * on lstat() because UPDATE captures them FROM the filesystem (already at target locations).
     *
     * Non-fatal: If manifest update fails, Git commits still succeeded.
     * User can repair manifest by running 'dotta profile enable <profile>'.
     */
    bool manifest_updated = false;
    error_t *manifest_err = update_manifest_after_update(
        repo, ws, by_profile, opts, out, &manifest_updated
    );

    /* Free by_profile hashmap after manifest sync */
    if (by_profile) {
        hashmap_free(by_profile, item_array_free);
        by_profile = NULL;
    }

    if (manifest_err) {
        /* Non-fatal: commits succeeded but manifest update failed */
        output_warning(
            out, OUTPUT_NORMAL, "Failed to update manifest: %s",
            error_message(manifest_err)
        );

        output_info(
            out, OUTPUT_NORMAL, "Files committed to Git successfully"
        );
        output_hint(
            out, OUTPUT_NORMAL, "Re-enable profile to repair state"
        );
        error_free(manifest_err);
        /* Continue to post-update hook and success output */
    }

    /* Execute post-update hook */
    if (hook_ctx && !opts->dry_run) {
        hook_result_t *hook_result = NULL;
        error_t *hook_err = hook_execute(
            config, HOOK_POST_UPDATE, hook_ctx, &hook_result
        );

        if (hook_err) {
            /* Hook failed - warn but don't abort (files already updated) */
            output_warning(
                out, OUTPUT_NORMAL, "Post-update hook failed: %s",
                error_message(hook_err)
            );
            if (hook_result && hook_result->output && hook_result->output[0]) {
                output_print(
                    out, OUTPUT_NORMAL, "Hook output:\n%s\n",
                    hook_result->output
                );
            }
            error_free(hook_err);
        }
        hook_result_free(hook_result);
    }

    /* Summary (report updated profile count) */
    output_newline(out, OUTPUT_NORMAL);
    output_success(
        out, OUTPUT_NORMAL, "Updated %zu item%s across %zu profile%s",
        total_updated, total_updated == 1 ? "" : "s",
        updated_profile_count, updated_profile_count == 1 ? "" : "s"
    );

    /* Manifest status feedback */
    output_newline(out, OUTPUT_NORMAL);
    if (manifest_updated) {
        output_info(
            out, OUTPUT_NORMAL,
            "Manifest updated (%zu item%s synced)",
            total_updated, total_updated == 1 ? "" : "s"
        );
        output_hint(
            out, OUTPUT_NORMAL,
            "Run 'dotta status' to verify state"
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL,
            "No enabled profiles - manifest not updated"
        );
        output_hint(
            out, OUTPUT_NORMAL,
            "Run 'dotta profile enable <profile>' to activate"
        );
    }

cleanup:
    /* Free all resources in reverse order */
    if (update_items) free(update_items);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (ws) workspace_free(ws);
    if (profiles_str) free(profiles_str);
    if (file_filter) path_filter_free(file_filter);
    if (repo_dir) free(repo_dir);
    /* Free operation profiles only if not shared with workspace profiles */
    if (filter_names) free(filter_names);
    if (operation_profiles && operation_profiles != workspace_profiles) {
        profile_list_free(operation_profiles);
    }
    if (workspace_profiles) profile_list_free(workspace_profiles);

    return err;
}
