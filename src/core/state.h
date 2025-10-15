/**
 * state.h - Deployment state tracking
 *
 * Tracks which files have been deployed to enable cleanup,
 * conflict detection, and status reporting.
 *
 * State file location: .git/dotta-state.json
 *
 * JSON Schema:
 * {
 *   "version": 2,
 *   "timestamp": "2025-01-15T10:30:00Z",
 *   "profiles": ["global", "darwin"],
 *   "files": [
 *     {
 *       "storage_path": "home/.bashrc",
 *       "filesystem_path": "/home/user/.bashrc",
 *       "profile": "global",
 *       "type": "file",
 *       "hash": "sha256:abc123...",
 *       "mode": "0644"
 *     }
 *   ]
 * }
 *
 * Design principles:
 * - Human-readable JSON format
 * - Atomic writes (write to temp, then rename)
 * - Validate on load
 * - Graceful handling of missing/corrupt state
 */

#ifndef DOTTA_STATE_H
#define DOTTA_STATE_H

#include <git2.h>
#include <time.h>

#include "types.h"

/**
 * File type in state
 */
typedef enum {
    STATE_FILE_REGULAR,
    STATE_FILE_SYMLINK,
    STATE_FILE_EXECUTABLE
} state_file_type_t;

/**
 * State file entry
 */
typedef struct {
    char *storage_path;      /* Path in profile (home/.bashrc) */
    char *filesystem_path;   /* Deployed path (/home/user/.bashrc) */
    char *profile;           /* Source profile name */
    state_file_type_t type;  /* File type */
    char *hash;              /* Content hash (sha256:...) */
    char *mode;              /* Permission mode (e.g., "0644") */
} state_file_entry_t;


/**
 * State structure (opaque)
 */
typedef struct state state_t;

/**
 * Load state from repository (read-only)
 *
 * If state file doesn't exist, returns empty state.
 * If state file is corrupt, returns error.
 *
 * Use this function for read-only operations (status, list).
 * For operations that will modify and save state, use state_load_for_update().
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_load(git_repository *repo, state_t **out);

/**
 * Load state for update (with locking)
 *
 * Acquires an exclusive lock on the state file to prevent concurrent modifications.
 * The lock is automatically released when state_save() is called or when
 * state_free() is called (cleanup on error paths).
 *
 * Use this function for operations that will modify state (add, apply, remove, etc.).
 * For read-only operations, use state_load().
 *
 * If another process holds the lock, returns ERR_CONFLICT immediately (non-blocking).
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_load_for_update(git_repository *repo, state_t **out);

/**
 * Save state to repository
 *
 * Writes atomically (temp file + rename).
 * If the state was loaded with state_load_for_update(), the lock is
 * automatically released after a successful save.
 *
 * @param repo Repository (must not be NULL)
 * @param state State to save (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_save(git_repository *repo, state_t *state);

/**
 * Create empty state
 *
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_create_empty(state_t **out);

/**
 * Free state structure
 *
 * @param state State to free (can be NULL)
 */
void state_free(state_t *state);

/**
 * Add file entry to state
 *
 * @param state State (must not be NULL)
 * @param entry File entry to add (must not be NULL, copied into state)
 * @return Error or NULL on success
 */
error_t *state_add_file(state_t *state, const state_file_entry_t *entry);

/**
 * Remove file entry from state
 *
 * @param state State (must not be NULL)
 * @param filesystem_path File path to remove (must not be NULL)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_remove_file(state_t *state, const char *filesystem_path);

/**
 * Check if file exists in state
 *
 * @param state State (must not be NULL)
 * @param filesystem_path File path to check (must not be NULL)
 * @return true if file exists in state
 */
bool state_file_exists(const state_t *state, const char *filesystem_path);

/**
 * Get file entry from state
 *
 * @param state State (must not be NULL)
 * @param filesystem_path File path to lookup (must not be NULL)
 * @param out File entry (must not be NULL, borrowed reference - do not free)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_get_file(
    const state_t *state,
    const char *filesystem_path,
    const state_file_entry_t **out
);

/**
 * Get all file entries
 *
 * @param state State (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Array of entries (borrowed reference - do not free individual entries)
 */
const state_file_entry_t *state_get_all_files(const state_t *state, size_t *count);

/**
 * Set active profiles
 *
 * @param state State (must not be NULL)
 * @param profiles Array of profile names (must not be NULL)
 * @param count Number of profiles
 * @return Error or NULL on success
 */
error_t *state_set_profiles(
    state_t *state,
    const char **profiles,
    size_t count
);

/**
 * Get active profiles
 *
 * @param state State (must not be NULL)
 * @param out Profile names (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_profiles(const state_t *state, string_array_t **out);

/**
 * Get state timestamp
 *
 * @param state State (must not be NULL)
 * @return Timestamp (0 if not set)
 */
time_t state_get_timestamp(const state_t *state);

/**
 * Clear all file entries (keeps profiles and timestamp)
 *
 * @param state State (must not be NULL)
 */
void state_clear_files(state_t *state);

/**
 * Helper: Create file entry
 *
 * @param storage_path Storage path (must not be NULL)
 * @param filesystem_path Filesystem path (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param type File type
 * @param hash Content hash (can be NULL)
 * @param mode Permission mode (can be NULL)
 * @param out Entry (must not be NULL, caller must free with state_free_entry)
 * @return Error or NULL on success
 */
error_t *state_create_entry(
    const char *storage_path,
    const char *filesystem_path,
    const char *profile,
    state_file_type_t type,
    const char *hash,
    const char *mode,
    state_file_entry_t **out
);

/**
 * Free file entry
 *
 * @param entry Entry to free (can be NULL)
 */
void state_free_entry(state_file_entry_t *entry);

#endif /* DOTTA_STATE_H */
