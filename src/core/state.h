/**
 * state.h - SQLite-based deployment state tracking
 *
 * Tracks which files have been deployed to enable cleanup,
 * conflict detection, and status reporting.
 *
 * Database location: .git/dotta.db
 *
 * Schema:
 *   - schema_meta: Schema versioning
 *   - enabled_profiles: User's profile management (authority: profile commands)
 *   - deployed_files: Deployed file manifest (authority: apply/revert)
 *
 * Design principles:
 * - Binary format (fast, compact)
 * - WAL mode (concurrent access, atomic commits)
 * - Prepared statements (100x faster for bulk operations)
 * - Persistent indexes (O(1) lookups without rebuilding)
 * - Separate tables enforce authority model at storage level
 *
 * Performance targets:
 * - Profile enable: < 10ms (even with 10,000 deployed files)
 * - File existence check: < 0.1ms
 * - Apply 1000 files: < 200ms
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
 * If database doesn't exist, returns empty state.
 * If database is corrupt or wrong version, returns error.
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
 * Load state for update (with transaction)
 *
 * Opens database with write lock (BEGIN IMMEDIATE transaction).
 * The transaction is automatically committed when state_save() is called
 * or rolled back when state_free() is called (cleanup on error paths).
 *
 * Use this function for operations that will modify state (add, apply, remove, etc.).
 * For read-only operations, use state_load().
 *
 * If another process holds the write lock, waits up to 5 seconds (SQLITE_BUSY).
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_load_for_update(git_repository *repo, state_t **out);

/**
 * Save state to repository
 *
 * Commits the transaction started by state_load_for_update().
 * All modifications made since load are atomically committed.
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
 * Automatically rolls back transaction if not committed (error path cleanup).
 * Closes database connection and frees all memory.
 *
 * @param state State to free (can be NULL)
 */
void state_free(state_t *state);

/**
 * Add file entry to state
 *
 * Uses prepared statement for performance (critical for bulk operations).
 * Can be called 1000+ times in a loop during apply.
 *
 * @param state State (must not be NULL)
 * @param entry File entry to add (must not be NULL, copied into database)
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
 * Uses PRIMARY KEY index for O(1) lookup.
 * Hot path - called frequently during status checks.
 *
 * @param state State (must not be NULL)
 * @param filesystem_path File path to check (must not be NULL)
 * @return true if file exists in state
 */
bool state_file_exists(const state_t *state, const char *filesystem_path);

/**
 * Get file entry from state
 *
 * IMPORTANT: Memory ownership changed from original API.
 * Caller owns the returned entry and must free it with state_free_entry().
 *
 * @param state State (must not be NULL)
 * @param filesystem_path File path to lookup (must not be NULL)
 * @param out File entry (must not be NULL, caller must free with state_free_entry)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_get_file(
    const state_t *state,
    const char *filesystem_path,
    state_file_entry_t **out
);

/**
 * Get all file entries
 *
 * BREAKING CHANGE: Memory ownership changed from original API.
 * Returns allocated array that caller MUST free with state_free_all_files().
 *
 * This change is necessary because SQLite implementation doesn't keep
 * all files in memory - they're queried on demand.
 *
 * @param state State (must not be NULL)
 * @param out Output array (must not be NULL, caller must free with state_free_all_files)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_all_files(
    const state_t *state,
    state_file_entry_t **out,
    size_t *count
);

/**
 * Free array returned by state_get_all_files()
 *
 * @param entries Array to free (can be NULL)
 * @param count Number of entries in array
 */
void state_free_all_files(state_file_entry_t *entries, size_t count);

/**
 * Set enabled profiles
 *
 * Hot path - must be fast even with 10,000 deployed files.
 * Only modifies enabled_profiles table (deployed_files table untouched).
 *
 * @param state State (must not be NULL)
 * @param profiles Array of profile names (must not be NULL)
 * @param count Number of profiles
 * @return Error or NULL on success
 */
error_t *state_set_profiles(
    state_t *state,
    char **profiles,
    size_t count
);

/**
 * Get enabled profiles
 *
 * Returns copy that caller must free.
 *
 * @param state State (must not be NULL)
 * @param out Profile names (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *state_get_profiles(const state_t *state, string_array_t **out);

/**
 * Get unique profiles that have deployed files
 *
 * Extracts all unique profile names from the deployed_files table.
 * This represents "all profiles we've ever applied on this machine",
 * including both enabled and disabled profiles.
 *
 * Returns copy that caller must free with string_array_free().
 * Returns empty array if no files are deployed (not an error).
 *
 * Use cases:
 * - Determining which profiles' metadata to load for cleanup operations
 * - Identifying profiles that need to be synced
 * - Auditing deployment history
 *
 * @param state State (must not be NULL)
 * @param out Profile names (must not be NULL, caller must free with string_array_free)
 * @return Error or NULL on success (empty array if no deployed files)
 */
error_t *state_get_deployed_profiles(const state_t *state, string_array_t **out);

/**
 * Get last deployed timestamp for a profile
 *
 * Returns the most recent deployment timestamp for files from the specified profile.
 *
 * @param state State (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @return Timestamp (0 if profile has no deployed files)
 */
time_t state_get_profile_timestamp(const state_t *state, const char *profile_name);

/**
 * Clear all file entries (keeps profiles)
 *
 * Efficiently truncates deployed_files table.
 *
 * @param state State (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_clear_files(state_t *state);

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
