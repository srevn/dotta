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
#include "crypto/keymanager.h"
#include "utils/array.h"
#include "utils/hashmap.h"

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
 *
 * Initializes all counters to 0 and allocates string arrays for detailed tracking.
 */
static error_t *create_result(cleanup_result_t **out) {
    CHECK_NULL(out);

    cleanup_result_t *result = calloc(1, sizeof(cleanup_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate cleanup result");
    }

    /* Allocate detailed tracking arrays (for caller display) */
    result->removed_files = string_array_create();
    result->skipped_files = string_array_create();
    result->failed_files = string_array_create();
    result->removed_dirs = string_array_create();
    result->skipped_dirs = string_array_create();
    result->failed_dirs = string_array_create();

    /* Check allocations */
    if (!result->removed_files || !result->skipped_files || !result->failed_files ||
        !result->removed_dirs || !result->skipped_dirs || !result->failed_dirs) {
        cleanup_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate cleanup result arrays");
    }

    /* All other fields initialized to 0/NULL by calloc */
    *out = result;
    return NULL;
}

/**
 * Free cleanup result
 *
 * Frees all allocated resources including detailed tracking arrays and safety violations.
 */
void cleanup_result_free(cleanup_result_t *result) {
    if (!result) {
        return;
    }

    /* Free detailed tracking arrays */
    if (result->removed_files) string_array_free(result->removed_files);
    if (result->skipped_files) string_array_free(result->skipped_files);
    if (result->failed_files) string_array_free(result->failed_files);
    if (result->removed_dirs) string_array_free(result->removed_dirs);
    if (result->skipped_dirs) string_array_free(result->skipped_dirs);
    if (result->failed_dirs) string_array_free(result->failed_dirs);

    /* Free embedded safety violations */
    if (result->safety_violations) {
        safety_result_free(result->safety_violations);
    }

    free(result);
}

/**
 * Free cleanup preflight result
 *
 * Frees all allocated resources including string arrays and safety violations.
 */
void cleanup_preflight_result_free(cleanup_preflight_result_t *result) {
    if (!result) {
        return;
    }

    /* Free string arrays */
    if (result->orphaned_files) {
        string_array_free(result->orphaned_files);
    }
    if (result->orphaned_directories) {
        string_array_free(result->orphaned_directories);
    }

    /* Free embedded safety violations */
    if (result->safety_violations) {
        safety_result_free(result->safety_violations);
    }

    free(result);
}

/**
 * Identify orphaned files
 *
 * Returns list of files in deployment state that are not present in target
 * manifest, with both filesystem and storage paths included to avoid lookups.
 */
error_t *cleanup_identify_orphans(
    const state_t *state,
    const manifest_t *manifest,
    orphan_list_t **out_orphans
) {
    CHECK_NULL(state);
    CHECK_NULL(manifest);
    CHECK_NULL(out_orphans);

    error_t *err = NULL;
    orphan_list_t *list = NULL;
    hashmap_t *manifest_index = NULL;
    state_file_entry_t *state_files = NULL;
    size_t state_count = 0;

    /* Allocate orphan list */
    list = calloc(1, sizeof(orphan_list_t));
    if (!list) {
        return ERROR(ERR_MEMORY, "Failed to allocate orphan list");
    }

    /* Get all state files */
    err = state_get_all_files(state, &state_files, &state_count);
    if (err) {
        free(list);
        return error_wrap(err, "Failed to get state files");
    }

    /* Early exit: no files in state means no orphans */
    if (state_count == 0) {
        state_free_all_files(state_files, state_count);
        *out_orphans = list;
        return NULL;
    }

    /* Build manifest index for O(1) lookups */
    manifest_index = hashmap_create(manifest->count > 0 ? manifest->count : 16);
    if (!manifest_index) {
        state_free_all_files(state_files, state_count);
        free(list);
        return ERROR(ERR_MEMORY, "Failed to create manifest index");
    }

    for (size_t i = 0; i < manifest->count; i++) {
        err = hashmap_set(manifest_index,
                         manifest->entries[i].filesystem_path,
                         (void *)1);
        if (err) {
            hashmap_free(manifest_index, NULL);
            state_free_all_files(state_files, state_count);
            free(list);
            return error_wrap(err, "Failed to build manifest index");
        }
    }

    /* Identify orphans (in state, not in manifest) */
    for (size_t i = 0; i < state_count; i++) {
        const state_file_entry_t *entry = &state_files[i];

        /* Check if file exists in manifest (O(1) lookup) */
        if (!hashmap_has(manifest_index, entry->filesystem_path)) {
            /* Orphaned - grow array if needed */
            if (list->count >= list->capacity) {
                size_t new_cap = list->capacity == 0 ? 16 : list->capacity * 2;
                orphan_entry_t *new_entries = realloc(list->entries,
                                                      new_cap * sizeof(orphan_entry_t));
                if (!new_entries) {
                    orphan_list_free(list);
                    hashmap_free(manifest_index, NULL);
                    state_free_all_files(state_files, state_count);
                    return ERROR(ERR_MEMORY, "Failed to grow orphan list");
                }
                list->entries = new_entries;
                list->capacity = new_cap;
            }

            /* Add orphan entry with both paths */
            orphan_entry_t *orphan = &list->entries[list->count];
            orphan->filesystem_path = strdup(entry->filesystem_path);
            orphan->storage_path = strdup(entry->storage_path);

            if (!orphan->filesystem_path || !orphan->storage_path) {
                free(orphan->filesystem_path);
                free(orphan->storage_path);
                orphan_list_free(list);
                hashmap_free(manifest_index, NULL);
                state_free_all_files(state_files, state_count);
                return ERROR(ERR_MEMORY, "Failed to allocate orphan paths");
            }

            list->count++;
        }
    }

    /* Cleanup */
    hashmap_free(manifest_index, NULL);
    state_free_all_files(state_files, state_count);

    *out_orphans = list;
    return NULL;
}

/**
 * Free orphan list
 *
 * Frees all orphan entries (including their strings) and the list structure.
 */
void orphan_list_free(orphan_list_t *list) {
    if (!list) {
        return;
    }

    for (size_t i = 0; i < list->count; i++) {
        free(list->entries[i].filesystem_path);
        free(list->entries[i].storage_path);
    }
    free(list->entries);
    free(list);
}

/**
 * Identify orphaned directories
 *
 * Returns list of directories in deployment state that are not present in
 * target metadata. Mirrors cleanup_identify_orphans() for directories.
 */
error_t *cleanup_identify_orphaned_directories(
    const state_t *state,
    const metadata_t *metadata,
    orphan_directory_list_t **out_orphans
) {
    CHECK_NULL(state);
    CHECK_NULL(metadata);
    CHECK_NULL(out_orphans);

    error_t *err = NULL;
    orphan_directory_list_t *list = NULL;
    hashmap_t *metadata_index = NULL;
    state_directory_entry_t *state_dirs = NULL;
    size_t state_count = 0;
    const metadata_item_t **meta_dirs = NULL;
    size_t meta_count = 0;

    /* Allocate orphan list */
    list = calloc(1, sizeof(orphan_directory_list_t));
    if (!list) {
        return ERROR(ERR_MEMORY, "Failed to allocate orphan directory list");
    }

    /* Get all state directories */
    err = state_get_all_directories(state, &state_dirs, &state_count);
    if (err) {
        free(list);
        return error_wrap(err, "Failed to get state directories");
    }

    /* Early exit: no directories in state means no orphans */
    if (state_count == 0) {
        state_free_all_directories(state_dirs, state_count);
        *out_orphans = list;
        return NULL;
    }

    /* Get all metadata directories for comparison */
    meta_dirs = metadata_get_items_by_kind(metadata, METADATA_ITEM_DIRECTORY, &meta_count);

    /* Build metadata index for O(1) lookups (key = filesystem_path for directories) */
    metadata_index = hashmap_create(meta_count > 0 ? meta_count : 16);
    if (!metadata_index) {
        if (meta_dirs) free(meta_dirs);
        state_free_all_directories(state_dirs, state_count);
        free(list);
        return ERROR(ERR_MEMORY, "Failed to create metadata index");
    }

    for (size_t i = 0; i < meta_count; i++) {
        /* For directories, key is filesystem_path */
        err = hashmap_set(metadata_index,
                         meta_dirs[i]->key,
                         (void *)1);
        if (err) {
            hashmap_free(metadata_index, NULL);
            free(meta_dirs);
            state_free_all_directories(state_dirs, state_count);
            free(list);
            return error_wrap(err, "Failed to build metadata index");
        }
    }

    /* Identify orphans (in state, not in metadata) */
    for (size_t i = 0; i < state_count; i++) {
        const state_directory_entry_t *entry = &state_dirs[i];

        /* Check if directory exists in metadata (O(1) lookup) */
        if (!hashmap_has(metadata_index, entry->directory_path)) {
            /* Orphaned - grow array if needed */
            if (list->count >= list->capacity) {
                size_t new_cap = list->capacity == 0 ? 16 : list->capacity * 2;
                orphan_directory_entry_t *new_entries = realloc(list->entries,
                                                                new_cap * sizeof(orphan_directory_entry_t));
                if (!new_entries) {
                    orphan_directory_list_free(list);
                    hashmap_free(metadata_index, NULL);
                    free(meta_dirs);
                    state_free_all_directories(state_dirs, state_count);
                    return ERROR(ERR_MEMORY, "Failed to grow orphan directory list");
                }
                list->entries = new_entries;
                list->capacity = new_cap;
            }

            /* Add orphan entry with all needed fields */
            orphan_directory_entry_t *orphan = &list->entries[list->count];
            orphan->filesystem_path = strdup(entry->directory_path);
            orphan->storage_prefix = strdup(entry->storage_prefix);
            orphan->profile = strdup(entry->profile);

            if (!orphan->filesystem_path || !orphan->storage_prefix || !orphan->profile) {
                free(orphan->filesystem_path);
                free(orphan->storage_prefix);
                free(orphan->profile);
                orphan_directory_list_free(list);
                hashmap_free(metadata_index, NULL);
                free(meta_dirs);
                state_free_all_directories(state_dirs, state_count);
                return ERROR(ERR_MEMORY, "Failed to allocate orphan directory paths");
            }

            list->count++;
        }
    }

    /* Cleanup */
    hashmap_free(metadata_index, NULL);
    if (meta_dirs) free(meta_dirs);
    state_free_all_directories(state_dirs, state_count);

    *out_orphans = list;
    return NULL;
}

/**
 * Free orphaned directory list
 *
 * Frees all orphan entries (including their strings) and the list structure.
 */
void orphan_directory_list_free(orphan_directory_list_t *list) {
    if (!list) {
        return;
    }

    for (size_t i = 0; i < list->count; i++) {
        free(list->entries[i].filesystem_path);
        free(list->entries[i].storage_prefix);
        free(list->entries[i].profile);
    }
    free(list->entries);
    free(list);
}

/**
 * Remove orphaned files from filesystem
 *
 * Uses pre-computed orphan list from opts->orphaned_files to remove files
 * after safety validation. Integrates with safety module to prevent data loss.
 *
 * Algorithm:
 * 1. Use pre-computed orphan list (must not be NULL)
 * 2. Extract filesystem paths for safety check
 * 3. Run safety checks (unless force=true or skip_safety_check=true)
 * 4. Remove safe files, skip violated files, track failures
 *
 * @param repo Repository (must not be NULL)
 * @param state State for safety check lookups (must not be NULL)
 * @param manifest Current manifest (unused, kept for API consistency)
 * @param result Cleanup result to update (must not be NULL)
 * @param opts Cleanup options (must not be NULL, orphaned_files must not be NULL)
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
    CHECK_NULL(opts->orphaned_files);

    error_t *err = NULL;
    char **filesystem_paths = NULL;
    hashmap_t *violations_map = NULL;

    bool dry_run = opts->dry_run;
    bool force = opts->force;

    const orphan_list_t *orphans = opts->orphaned_files;
    result->orphaned_files_found = orphans->count;

    /* Early exit if no orphaned files */
    if (orphans->count == 0) {
        return NULL;
    }

    /* Extract filesystem paths for safety check */
    filesystem_paths = calloc(orphans->count, sizeof(char *));
    if (!filesystem_paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate filesystem paths array");
    }

    for (size_t i = 0; i < orphans->count; i++) {
        filesystem_paths[i] = orphans->entries[i].filesystem_path;
    }

    /* Safety check: detect modified orphaned files (unless already done in preflight) */
    if (!force && !opts->skip_safety_check) {
        /* Get keymanager for decryption (if needed) */
        keymanager_t *keymanager = keymanager_get_global(NULL);

        err = safety_check_removal(
            repo,
            state,
            filesystem_paths,
            orphans->count,
            force,
            opts->enabled_metadata,  /* Pass pre-loaded metadata */
            keymanager,              /* Pass keymanager for decryption */
            opts->cache,             /* Pass content cache for performance */
            &result->safety_violations
        );

        if (err) {
            /* Fatal error during safety check */
            free(filesystem_paths);
            return error_wrap(err, "Safety check failed");
        }

        /* Build violations map for O(1) lookup during removal */
        if (result->safety_violations && result->safety_violations->count > 0) {
            violations_map = hashmap_create(result->safety_violations->count);
            if (!violations_map) {
                free(filesystem_paths);
                return ERROR(ERR_MEMORY, "Failed to create violations hashmap");
            }

            for (size_t i = 0; i < result->safety_violations->count; i++) {
                const safety_violation_t *v = &result->safety_violations->violations[i];
                hashmap_set(violations_map, v->filesystem_path, (void *)1);
            }
        }
    }

    /* Remove orphaned files and populate result arrays for caller display */
    for (size_t i = 0; i < orphans->count; i++) {
        const char *path = orphans->entries[i].filesystem_path;

        /* Skip if file has safety violation */
        if (violations_map && hashmap_has(violations_map, path)) {
            result->orphaned_files_skipped++;
            err = string_array_push(result->skipped_files, path);
            if (err) {
                err = error_wrap(err, "Failed to track skipped file");
                if (violations_map) hashmap_free(violations_map, NULL);
                free(filesystem_paths);
                return err;
            }
            continue;
        }

        /* Skip if file doesn't exist (already deleted) */
        if (!fs_exists(path)) {
            /* Don't count as skipped or failed - file is already gone */
            continue;
        }

        /* Dry run: don't remove */
        if (dry_run) {
            /* In dry-run mode, we don't remove but still track what would be removed
             * Caller can check dry_run flag to display appropriately */
            continue;
        }

        /* Remove file */
        error_t *remove_err = fs_remove_file(path);
        if (remove_err) {
            /* Non-fatal: track failure and continue */
            result->orphaned_files_failed++;
            err = string_array_push(result->failed_files, path);
            if (err) {
                error_free(remove_err);
                err = error_wrap(err, "Failed to track failed file");
                if (violations_map) hashmap_free(violations_map, NULL);
                free(filesystem_paths);
                return err;
            }
            error_free(remove_err);
        } else {
            /* File removed successfully */
            result->orphaned_files_removed++;
            err = string_array_push(result->removed_files, path);
            if (err) {
                err = error_wrap(err, "Failed to track removed file");
                if (violations_map) hashmap_free(violations_map, NULL);
                free(filesystem_paths);
                return err;
            }
        }
    }

    /* Cleanup */
    if (violations_map) hashmap_free(violations_map, NULL);
    free(filesystem_paths);
    return NULL;
}

/**
 * Reset parent directory state to UNKNOWN (for orphan directories)
 *
 * Variant for orphaned directory entries. Same logic but works with
 * orphan_directory_entry_t array instead of state_directory_entry_t.
 *
 * @param orphan_entries Array of orphaned directory entries
 * @param dir_count Number of directories
 * @param states Array of directory states (parallel to entries)
 * @param removed_path Path of directory that was just removed
 */
static void reset_parent_directory_state_orphans(
    const orphan_directory_entry_t *orphan_entries,
    size_t dir_count,
    directory_state_t *states,
    const char *removed_path
) {
    if (!orphan_entries || !states || !removed_path || dir_count == 0) {
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

    /* Find parent in orphan entries list */
    for (size_t i = 0; i < dir_count; i++) {
        if (strcmp(orphan_entries[i].filesystem_path, parent_path) == 0) {
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
 * Prune orphaned directories (with inline safety check)
 *
 * Iteratively removes orphaned directories that are:
 * 1. In orphaned_dirs list (not in enabled profile metadata)
 * 2. Empty (contain no files or subdirectories)
 *
 * Safety Check (INLINE):
 * - If directory is non-empty: SKIP (contains untracked files - data loss risk)
 * - If directory is empty: SAFE (no data loss possible)
 *
 * This mirrors file pruning but with simpler safety logic:
 * - Files: Complex safety (Git comparison, hash checks, decryption)
 * - Directories: Simple safety (filesystem empty check)
 *
 * Algorithm:
 * - Iteration 1: Check all orphaned dirs, remove empty ones, skip non-empty
 * - Iteration 2: Parent dirs might now be empty, check unknowns only
 * - Repeat until no progress made (stable state)
 *
 * State Tracking Optimization:
 * - DIR_STATE_REMOVED: Skip in all future iterations
 * - DIR_STATE_NOT_EMPTY: Skipped (safety violation - contains untracked files)
 * - DIR_STATE_NONEXISTENT: Skip in all future iterations
 * - DIR_STATE_FAILED: Skip in all future iterations
 * - DIR_STATE_UNKNOWN: Check in this iteration
 *
 * @param orphaned_dirs Pre-computed orphan list (must not be NULL)
 * @param result Cleanup result to update (must not be NULL)
 * @param opts Cleanup options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *prune_orphaned_directories(
    const orphan_directory_list_t *orphaned_dirs,
    cleanup_result_t *result,
    const cleanup_options_t *opts
) {
    CHECK_NULL(orphaned_dirs);
    CHECK_NULL(result);
    CHECK_NULL(opts);

    bool dry_run = opts->dry_run;

    const orphan_directory_list_t *orphans = orphaned_dirs;
    result->orphaned_directories_found = orphans->count;

    /* Early exit: no orphaned directories */
    if (orphans->count == 0) {
        return NULL;
    }

    size_t dir_count = orphans->count;

    /* Allocate state tracking array */
    directory_state_t *states = calloc(dir_count, sizeof(directory_state_t));
    if (!states) {
        /* Non-fatal: allocation failure skips directory pruning entirely.
         * This is safer than attempting unoptimized pruning, which could
         * be prohibitively expensive for large directory hierarchies.
         * Caller can check if orphaned_directories_removed is 0 to detect this case. */
        return NULL;
    }

    /* All states initialized to DIR_STATE_UNKNOWN by calloc */

    bool made_progress = true;

    /* Iteratively remove empty orphaned directories until stable */
    while (made_progress) {
        made_progress = false;

        for (size_t i = 0; i < dir_count; i++) {
            const char *dir_path = orphans->entries[i].filesystem_path;

            /* Optimization: Skip directories with known state */
            if (states[i] == DIR_STATE_REMOVED ||
                states[i] == DIR_STATE_NONEXISTENT ||
                states[i] == DIR_STATE_FAILED) {
                continue;
            }

            /* Skip non-empty directories (safety violation - already tracked) */
            if (states[i] == DIR_STATE_NOT_EMPTY) {
                continue;
            }

            /* Check if directory exists */
            if (!fs_exists(dir_path)) {
                states[i] = DIR_STATE_NONEXISTENT;
                continue;
            }

            /* INLINE SAFETY CHECK: Is directory empty? */
            if (!fs_is_directory_empty(dir_path)) {
                /* Safety violation: contains untracked files */
                if (states[i] != DIR_STATE_NOT_EMPTY) {
                    /* First time seeing this violation - track it */
                    result->orphaned_directories_skipped++;

                    /* Populate skipped_dirs array for caller display */
                    error_t *push_err = string_array_push(result->skipped_dirs, dir_path);
                    if (push_err) {
                        /* Free resources and return fatal error */
                        free(states);
                        return error_wrap(push_err, "Failed to track skipped directory");
                    }

                    states[i] = DIR_STATE_NOT_EMPTY;
                }
                continue;  /* Won't re-check until child removed */
            }

            /* Dry run: don't remove */
            if (dry_run) {
                /* In dry-run mode, we don't remove but caller can infer what would happen
                 * from orphaned_directories_found and orphaned_directories_removed counters */
                continue;
            }

            /* Remove empty orphaned directory */
            error_t *remove_err = fs_remove_dir(dir_path, false);
            if (remove_err) {
                /* Non-fatal: track failure, populate result array, and continue */
                result->orphaned_directories_failed++;
                states[i] = DIR_STATE_FAILED;

                /* Populate failed_dirs array for caller display */
                error_t *push_err = string_array_push(result->failed_dirs, dir_path);
                if (push_err) {
                    error_free(remove_err);
                    /* Free resources and return fatal error */
                    free(states);
                    return error_wrap(push_err, "Failed to track failed directory");
                }

                error_free(remove_err);
            } else {
                /* Directory removed successfully */
                result->orphaned_directories_removed++;
                states[i] = DIR_STATE_REMOVED;
                made_progress = true;

                /* Reset parent directory state (might now be empty) */
                reset_parent_directory_state_orphans(orphans->entries, dir_count, states, dir_path);

                /* Populate removed_dirs array for caller display */
                error_t *push_err = string_array_push(result->removed_dirs, dir_path);
                if (push_err) {
                    /* Free resources and return fatal error */
                    free(states);
                    return error_wrap(push_err, "Failed to track removed directory");
                }
            }
        }
    }

    /* Cleanup */
    free(states);
    return NULL;
}

/**
 * Run cleanup preflight checks
 *
 * Analyzes what cleanup will do WITHOUT modifying filesystem.
 * Uses pre-computed orphan list from opts->orphaned_files.
 * Enables informed user consent by revealing orphan removal impact.
 */
error_t *cleanup_preflight_check(
    git_repository *repo,
    const state_t *state,
    const manifest_t *manifest,
    const cleanup_options_t *opts,
    cleanup_preflight_result_t **out_result
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(opts->orphaned_files);
    CHECK_NULL(opts->orphaned_directories);
    CHECK_NULL(out_result);

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    cleanup_preflight_result_t *result = NULL;
    string_array_t *orphaned_files = NULL;
    string_array_t *orphaned_dirs_display = NULL;
    char **filesystem_paths = NULL;

    const orphan_list_t *file_orphans = opts->orphaned_files;
    const orphan_directory_list_t *dir_orphans = opts->orphaned_directories;

    /* Allocate result structure */
    result = calloc(1, sizeof(cleanup_preflight_result_t));
    if (!result) {
        err = ERROR(ERR_MEMORY, "Failed to allocate cleanup preflight result");
        goto cleanup;
    }

    /* Initialize all fields */
    result->orphaned_files_count = file_orphans->count;
    result->orphaned_files = NULL;
    result->safety_violations = NULL;
    result->orphaned_directories_count = dir_orphans->count;
    result->orphaned_directories_nonempty = 0;
    result->orphaned_directories = NULL;
    result->has_blocking_violations = false;
    result->has_blocking_directories = false;
    result->will_prune_orphans = (file_orphans->count > 0);
    result->will_prune_directories = (dir_orphans->count > 0);

    /* Early exit: no orphaned files or directories */
    if (file_orphans->count == 0 && dir_orphans->count == 0) {
        /* Success - no orphans to check */
        *out_result = result;
        result = NULL;
        err = NULL;
        goto cleanup;
    }

    /* Convert file orphans to string array for display */
    if (file_orphans->count > 0) {
        orphaned_files = string_array_create();
        if (!orphaned_files) {
            err = ERROR(ERR_MEMORY, "Failed to allocate orphan file list for display");
            goto cleanup;
        }

        for (size_t i = 0; i < file_orphans->count; i++) {
            err = string_array_push(orphaned_files, file_orphans->entries[i].filesystem_path);
            if (err) {
                err = error_wrap(err, "Failed to add orphaned file to display list");
                goto cleanup;
            }
        }

        /* Transfer ownership to result */
        result->orphaned_files = orphaned_files;
        orphaned_files = NULL;  /* Prevent double-free */

        /* Run file safety checks (unless force=true) */
        if (!opts->force) {
            /* Extract filesystem paths for safety check */
            filesystem_paths = calloc(file_orphans->count, sizeof(char *));
            if (!filesystem_paths) {
                err = ERROR(ERR_MEMORY, "Failed to allocate filesystem paths array");
                goto cleanup;
            }

            for (size_t i = 0; i < file_orphans->count; i++) {
                filesystem_paths[i] = file_orphans->entries[i].filesystem_path;
            }

            /* Get keymanager for decryption (if needed) */
            keymanager_t *keymanager = keymanager_get_global(NULL);

            err = safety_check_removal(
                repo,
                state,
                filesystem_paths,
                file_orphans->count,
                opts->force,
                opts->enabled_metadata,
                keymanager,
                opts->cache,
                &result->safety_violations
            );

            if (err) {
                err = error_wrap(err, "Safety check failed");
                goto cleanup;
            }

            /* Set blocking flag if violations found */
            if (result->safety_violations && result->safety_violations->count > 0) {
                result->has_blocking_violations = true;
            }
        }
    }

    /* Preview orphaned directories (check which are non-empty) */
    if (dir_orphans->count > 0) {
        /* Allocate directory array for preview */
        orphaned_dirs_display = string_array_create();
        if (!orphaned_dirs_display) {
            /* Non-fatal: continue without directory preview */
        } else {
            /* Check which orphaned directories are non-empty (read-only preview) */
            for (size_t i = 0; i < dir_orphans->count; i++) {
                const char *dir_path = dir_orphans->entries[i].filesystem_path;

                /* Add to display list */
                err = string_array_push(orphaned_dirs_display, dir_path);
                if (err) {
                    /* Non-fatal: best-effort directory preview */
                    error_free(err);
                    err = NULL;
                    break;
                }

                /* Check if directory exists and is non-empty (safety violation) */
                if (fs_exists(dir_path) && !fs_is_directory_empty(dir_path)) {
                    result->orphaned_directories_nonempty++;
                }
            }

            /* Transfer ownership to result */
            result->orphaned_directories = orphaned_dirs_display;
            orphaned_dirs_display = NULL;  /* Prevent double-free */

            /* Set blocking flag if non-empty orphaned directories found */
            if (result->orphaned_directories_nonempty > 0 && !opts->force) {
                result->has_blocking_directories = true;
            }
        }
    }

    /* Success - set output and prevent cleanup from freeing result */
    *out_result = result;
    result = NULL;
    err = NULL;

cleanup:
    /* Free resources in reverse order of allocation */
    if (orphaned_dirs_display) string_array_free(orphaned_dirs_display);
    if (orphaned_files) string_array_free(orphaned_files);
    if (filesystem_paths) free(filesystem_paths);
    if (result) cleanup_preflight_result_free(result);

    return err;
}

/**
 * Execute cleanup operations
 *
 * Main entry point for cleanup module. Coordinates orphaned file removal
 * and empty directory pruning with safety checks.
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
    CHECK_NULL(opts->orphaned_files);
    CHECK_NULL(opts->orphaned_directories);
    CHECK_NULL(out_result);

    error_t *err = NULL;
    cleanup_result_t *result = NULL;

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

    /* Step 2: Prune orphaned directories (with inline safety check) */
    err = prune_orphaned_directories(opts->orphaned_directories, result, opts);
    if (err) {
        cleanup_result_free(result);
        return error_wrap(err, "Failed to prune orphaned directories");
    }

    /* Return result */
    *out_result = result;
    return NULL;
}
