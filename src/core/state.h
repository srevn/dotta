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
 *   - enabled_profiles: User's profile management
 *   - virtual_manifest: Deployed file manifest
 *   - tracked_directories: Tracked directories from metadata
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

#include "metadata.h"
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
 * State lifecycle constants
 *
 * These constants define the lifecycle state of manifest entries.
 * The state field implements an explicit state machine for file management.
 */
#define STATE_ACTIVE "active"       /* Normal entry, file is in scope and should be managed */
#define STATE_INACTIVE "inactive"   /* Marked for removal, awaiting cleanup by apply */

/**
 * State file entry (virtual manifest entry)
 *
 * Represents the manifest (scope definition) - which files should exist
 * based on enabled profiles. The manifest defines scope, not operations.
 *
 * SCOPE-BASED ARCHITECTURE:
 * - Manifest existence = file should be managed
 * - deployed_at = lifecycle tracking (see SCOPE_BASED_ARCHITECTURE_PLAN.md)
 *   - 0 = file never deployed by dotta (shows as [undeployed] if missing)
 *   - > 0 = file known to dotta (either deployed or existed when profile enabled)
 *
 * Key fields:
 * - git_oid: Git commit reference
 * - blob_oid: Git blob OID for content identity and fast path lookups
 * - owner/group: For root/ files
 * - encrypted: Encryption flag
 * - state: Lifecycle state (STATE_ACTIVE or STATE_INACTIVE)
 * - deployed_at: Lifecycle tracking timestamp (NOT operational control)
 */
typedef struct {
    /* Paths */
    char *storage_path;         /* Path in profile (home/.bashrc) */
    char *filesystem_path;      /* Deployed path (/home/user/.bashrc) */
    char *profile;              /* Source profile name */
    char *old_profile;          /* Previous owner if changed, NULL otherwise */

    /* Type */
    state_file_type_t type;     /* File type */

    /* Git tracking */
    char *git_oid;              /* Git commit reference (40-char hex) */
    char *blob_oid;             /* Git blob OID (40-char hex) */

    /* Metadata */
    mode_t mode;                /* Permission mode (e.g., 0644), 0 if no metadata tracked */
    char *owner;                /* Owner username (root/ files only, can be NULL) */
    char *group;                /* Group name (root/ files only, can be NULL) */
    bool encrypted;             /* Encryption flag */

    /* Lifecycle tracking */
    char *state;                /* Lifecycle state (STATE_ACTIVE or STATE_INACTIVE) */
    time_t deployed_at;         /* Lifecycle timestamp (0 = never deployed, >0 = known) */
} state_file_entry_t;

/**
 * State directory entry
 */
typedef struct {
    char *filesystem_path;    /* Deployed path (PRIMARY KEY, e.g., /home/user/.config/fish) */
    char *storage_path;       /* Portable path (e.g., home/.config/fish) */
    char *profile;            /* Source profile */
    mode_t mode;              /* Permissions */
    char *owner;              /* Owner (optional, root/ prefix only) */
    char *group;              /* Group (optional, root/ prefix only) */

    /* Lifecycle tracking */
    time_t deployed_at;       /* Lifecycle timestamp (0 = never deployed, >0 = known) */
} state_directory_entry_t;

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
 * Enable profile with optional custom prefix
 *
 * If profile already enabled, updates its custom_prefix (UPSERT behavior).
 * Position assigned automatically as MAX(position) + 1 for new profiles.
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - profile_name MUST NOT be NULL or empty
 *
 * Postconditions:
 *   - Profile added to enabled_profiles or existing entry updated
 *   - custom_prefix column set to prefix (or NULL if not provided)
 *   - enabled_at timestamp updated to current time
 *   - Transaction remains open (caller commits)
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param profile_name Profile name (must not be NULL)
 * @param custom_prefix Custom prefix or NULL for home/root profiles
 * @return Error or NULL on success
 */
error_t *state_enable_profile(
    state_t *state,
    const char *profile_name,
    const char *custom_prefix
);

/**
 * Disable profile
 *
 * Removes profile from enabled_profiles table.
 *
 * Preconditions:
 *   - state MUST have active transaction
 *
 * Postconditions:
 *   - Profile removed from enabled_profiles (if exists)
 *   - Transaction remains open (caller commits)
 *   - Not an error if profile wasn't enabled
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param profile_name Profile name (must not be NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t *state_disable_profile(
    state_t *state,
    const char *profile_name
);

/**
 * Get custom prefix map
 *
 * Builds a hashmap of profile_name → custom_prefix for all enabled profiles
 * that have a custom prefix set (WHERE custom_prefix IS NOT NULL).
 *
 * Returns empty map if no custom prefixes exist (not an error).
 *
 * Map values are dynamically allocated strings (caller must free map with
 * hashmap_free(map, free) to free both keys and values).
 *
 * Performance: Single SQL query, O(N) where N = profiles with custom prefixes
 *
 * @param state State handle (must not be NULL)
 * @param out_map Output hashmap (caller must free with hashmap_free(..., free))
 * @return Error or NULL on success (empty map if no custom prefixes)
 */
error_t *state_get_prefix_map(
    const state_t *state,
    hashmap_t **out_map
);

/**
 * Set enabled profiles (bulk operation)
 *
 * BULK API: For atomic profile list replacement (clone, reorder, interactive).
 * For individual profile enable/disable, prefer state_enable_profile() and
 * state_disable_profile() which provide explicit custom prefix management.
 *
 * Custom Prefix Preservation:
 *   Automatically preserves custom_prefix values for profiles that remain
 *   enabled after the operation. This enables safe profile reordering without
 *   losing custom prefix associations.
 *
 * Use Cases:
 *   - Clone: Initial profile list setup (no custom prefixes exist yet)
 *   - Reorder: Change precedence order while preserving custom_prefix values
 *   - Interactive: Bulk enable/disable selection with prefix preservation
 *
 * Position Assignment:
 *   Profiles are assigned sequential positions starting from 0.
 *   Any gaps in position numbering from previous operations are eliminated.
 *
 * Hot path - must be fast even with 10,000 deployed files.
 * Only modifies enabled_profiles table (virtual_manifest table untouched).
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *
 * Postconditions:
 *   - enabled_profiles table replaced with new profile list
 *   - Positions assigned as 0, 1, 2, ... (n-1)
 *   - custom_prefix values preserved for matching profile names
 *   - enabled_at timestamp updated to current time for all profiles
 *   - Transaction remains open (caller commits)
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
 * Check if a profile is enabled
 *
 * Fast O(n) check where n = number of enabled profiles (typically < 10).
 * Useful for commands that need to conditionally update manifest based on
 * whether a profile is enabled.
 *
 * @param state State (must not be NULL)
 * @param profile_name Profile name to check (must not be NULL)
 * @return true if profile is enabled, false otherwise
 */
bool state_has_profile(const state_t *state, const char *profile_name);

/**
 * Get unique profiles that have deployed files
 *
 * Extracts all unique profile names from the virtual_manifest table.
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
 * Efficiently truncates virtual_manifest table.
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
 * @param old_profile Previous profile (can be NULL)
 * @param type File type
 * @param git_oid Git commit reference (can be NULL)
 * @param blob_oid Git blob OID (can be NULL)
 * @param mode Permission mode (0 if no metadata tracked)
 * @param owner Owner username (can be NULL)
 * @param group Group name (can be NULL)
 * @param encrypted Encryption flag
 * @param state Lifecycle state (STATE_ACTIVE or STATE_INACTIVE, can be NULL for default)
 * @param deployed_at Lifecycle timestamp (0 = never deployed, >0 = known)
 * @param out Entry (must not be NULL, caller must free with state_free_entry)
 * @return Error or NULL on success
 */
error_t *state_create_entry(
    const char *storage_path,
    const char *filesystem_path,
    const char *profile,
    const char *old_profile,
    state_file_type_t type,
    const char *git_oid,
    const char *blob_oid,
    mode_t mode,
    const char *owner,
    const char *group,
    bool encrypted,
    const char *state,
    time_t deployed_at,
    state_file_entry_t **out
);

/**
 * Free file entry
 *
 * @param entry Entry to free (can be NULL)
 */
void state_free_entry(state_file_entry_t *entry);

/**
 * Update deployed_at timestamp (optimized hot path for apply)
 *
 * Updates only the deployed_at field of a manifest entry.
 * Used during apply after successful deployment to record lifecycle state.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path File path to update (must not be NULL)
 * @param deployed_at New deployed_at timestamp (use time(NULL) for current time)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_update_deployed_at(
    state_t *state,
    const char *filesystem_path,
    time_t deployed_at
);

/**
 * Clear old_profile for a manifest entry
 *
 * Acknowledges profile ownership change after successful deployment.
 * Used by apply to clear the ownership change flag once the user has
 * been informed about the change via preflight.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path File path (must not be NULL)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_clear_old_profile(
    state_t *state,
    const char *filesystem_path
);

/**
 * Set file entry state (active/inactive)
 *
 * Updates the state column for a manifest entry. Used by manifest layer
 * to mark files as inactive when they become orphaned (removed with no fallback).
 *
 * Valid states:
 *   - STATE_ACTIVE   - Normal entry, file is in scope
 *   - STATE_INACTIVE - Marked for removal, awaiting cleanup by apply
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - filesystem_path MUST exist in virtual_manifest
 *   - new_state MUST be STATE_ACTIVE or STATE_INACTIVE
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param filesystem_path File to update (must not be NULL)
 * @param new_state New state value (must not be NULL)
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *state_set_file_state(
    state_t *state,
    const char *filesystem_path,
    const char *new_state
);

/**
 * Update full entry
 *
 * Updates all fields of a manifest entry.
 * Used by manifest sync operations to update entries when Git changes.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param entry Entry with updated fields (must not be NULL)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_update_entry(
    state_t *state,
    const state_file_entry_t *entry
);

/**
 * Get entries by profile
 *
 * Returns all manifest entries from the specified profile.
 * Used by profile disable to determine impact of disabling a profile.
 *
 * Returns allocated array that caller must free with state_free_all_files().
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to filter by (must not be NULL)
 * @param out Output array (must not be NULL, caller must free with state_free_all_files)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success (empty array if no matches)
 */
error_t *state_get_entries_by_profile(
    const state_t *state,
    const char *profile,
    state_file_entry_t **out,
    size_t *count
);

/**
 * Create state directory entry from metadata item
 *
 * Converts portable metadata (storage_path) to state entry (both paths).
 * Derives filesystem_path from metadata's storage_path using path_from_storage().
 *
 * @param meta_item Metadata item (must not be NULL, must be DIRECTORY kind)
 * @param profile_name Source profile name (must not be NULL)
 * @param custom_prefix Custom prefix for this profile (NULL for home/root)
 * @param out State directory entry (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *state_directory_entry_create_from_metadata(
    const metadata_item_t *meta_item,
    const char *profile_name,
    const char *custom_prefix,
    state_directory_entry_t **out
);

/**
 * Add directory entry to state
 *
 * @param state State (must not be NULL)
 * @param entry Directory entry (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_add_directory(
    state_t *state,
    const state_directory_entry_t *entry
);

/**
 * Get all tracked directories
 *
 * Returns allocated array that caller must free with state_free_all_directories().
 *
 * @param state State (must not be NULL)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_all_directories(
    const state_t *state,
    state_directory_entry_t **out,
    size_t *count
);

/**
 * Get directories by profile
 *
 * Returns all directory entries from the specified profile.
 * Used by profile disable to determine impact on directories.
 *
 * Returns allocated array that caller must free with state_free_all_directories().
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to filter by (must not be NULL)
 * @param out Output array (must not be NULL, caller must free)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success (empty array if no matches)
 */
error_t *state_get_directories_by_profile(
    const state_t *state,
    const char *profile,
    state_directory_entry_t **out,
    size_t *count
);

/**
 * Update directory entry
 *
 * Updates all fields except filesystem_path (primary key) and deployed_at.
 * The deployed_at field is preserved to maintain lifecycle tracking.
 *
 * Updated fields: storage_path, profile, mode, owner, group
 * Preserved fields: filesystem_path (WHERE clause), deployed_at (lifecycle)
 *
 * This is used during profile disable to update directory entries to their
 * fallback profiles while preserving the original deployment timestamp.
 *
 * @param state State (must not be NULL)
 * @param entry Entry to update (must not be NULL, filesystem_path must exist)
 * @return Error or NULL on success
 */
error_t *state_update_directory(
    state_t *state,
    const state_directory_entry_t *entry
);

/**
 * Remove directory entry by path
 *
 * Deletes directory entry from state. Used during orphan cleanup after
 * the directory has been removed from the filesystem.
 *
 * @param state State (must not be NULL)
 * @param filesystem_path Filesystem path (PRIMARY KEY, must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_remove_directory(state_t *state, const char *filesystem_path);

/**
 * Clear all tracked directories
 *
 * @param state State (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_clear_directories(state_t *state);

/**
 * Free single directory entry
 *
 * @param entry Entry to free (can be NULL)
 */
void state_free_directory_entry(state_directory_entry_t *entry);

/**
 * Free array of directory entries
 *
 * @param entries Array to free (can be NULL)
 * @param count Number of entries in array
 */
void state_free_all_directories(
    state_directory_entry_t *entries,
    size_t count
);

#endif /* DOTTA_STATE_H */
