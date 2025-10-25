/**
 * metadata.h - File metadata preservation system
 *
 * Captures and restores file permissions (mode) across different machines.
 * Metadata is stored in .dotta/metadata.json within each profile branch,
 * enabling permissions to travel with files through git operations.
 *
 * Design principles:
 * - Track mode (permissions) for all files
 * - Track ownership (user/group) ONLY for root/ prefix files when running as root
 * - home/ prefix files always owned by current user (no ownership tracking)
 * - Per-profile storage for natural layering (darwin overrides global)
 * - Automatic capture during add/update operations
 * - Automatic restoration during apply/revert operations
 * - Graceful degradation when metadata is missing or users don't exist
 *
 * JSON Schema:
 * {
 *   "version": 3,
 *   "files": {
 *     "home/.ssh/config": {"mode": "0600"},
 *     "home/.ssh/id_rsa": {"mode": "0600", "encrypted": true},
 *     "home/.local/bin/backup.sh": {"mode": "0755"},
 *     "root/home/user/script.sh": {"mode": "0755", "owner": "user", "group": "user"},
 *     "root/etc/nginx.conf": {"mode": "0644", "owner": "root", "group": "wheel"}
 *   },
 *   "directories": [
 *     {
 *       "filesystem_path": "/home/user/.config/nvim",
 *       "storage_prefix": "home/.config/nvim",
 *       "added_at": "2025-01-15T10:30:00Z"
 *     }
 *   ]
 * }
 */

#ifndef DOTTA_METADATA_H
#define DOTTA_METADATA_H

#include <git2.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "types.h"

#define METADATA_FILE_PATH ".dotta/metadata.json"
#define METADATA_VERSION 3

/**
 * Metadata entry for a single file
 */
typedef struct {
    char *storage_path;    /* Path in profile (e.g., home/.bashrc) */
    mode_t mode;           /* Permission mode (e.g., 0600, 0644, 0755) */
    char *owner;           /* Owner username (optional, only for root/ prefix) */
    char *group;           /* Group name (optional, only for root/ prefix) */

    /* Encryption field */
    bool encrypted;        /* Is file encrypted in Git? */
} metadata_entry_t;

/**
 * Tracked directory entry
 *
 * Tracks directories that were explicitly added via `dotta add`,
 * enabling detection of new files that appear in those directories.
 * Also preserves directory metadata (permissions and ownership) for
 * proper replication across machines.
 *
 * Metadata preservation follows the same rules as files:
 * - mode: Always captured and applied
 * - owner/group: Only for root/ prefix when running as root
 * - home/ prefix: Directories owned by current user (or actual user when sudo)
 */
typedef struct {
    char *filesystem_path;   /* Original directory path (/home/user/.config/nvim) */
    char *storage_prefix;    /* Storage prefix in profile (home/.config/nvim) */
    time_t added_at;         /* When this directory was added */
    mode_t mode;             /* Permission mode (e.g., 0700, 0755, 0750) */
    char *owner;             /* Owner username (optional, only for root/ prefix) */
    char *group;             /* Group name (optional, only for root/ prefix) */
} metadata_directory_entry_t;

/* Forward declaration */
typedef struct hashmap hashmap_t;

/**
 * Metadata collection
 *
 * Uses both array (for iteration/serialization) and hashmap (for O(1) lookups).
 * The hashmap values point to entries in the array (no separate allocation).
 */
typedef struct metadata {
    /* File metadata */
    metadata_entry_t *entries;
    size_t count;
    size_t capacity;
    int version;           /* Schema version (currently 2) */
    hashmap_t *index;      /* Maps storage_path -> metadata_entry_t* (O(1) lookup) */

    /* Tracked directories */
    metadata_directory_entry_t *directories;
    size_t directory_count;
    size_t directory_capacity;
    hashmap_t *directory_index;  /* Maps filesystem_path -> metadata_directory_entry_t* (O(1) lookup) */
} metadata_t;

/**
 * Create empty metadata collection
 *
 * @param out Metadata structure (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success
 */
error_t *metadata_create_empty(metadata_t **out);

/**
 * Free metadata structure
 *
 * Frees all entries and the structure itself.
 *
 * @param metadata Metadata to free (can be NULL)
 */
void metadata_free(metadata_t *metadata);

/**
 * Create metadata entry
 *
 * @param storage_path Path in profile (must not be NULL)
 * @param mode Permission mode (e.g., 0600, 0644, 0755)
 * @param out Entry (must not be NULL, caller must free with metadata_entry_free)
 * @return Error or NULL on success
 */
error_t *metadata_entry_create(
    const char *storage_path,
    mode_t mode,
    metadata_entry_t **out
);

/**
 * Free metadata entry
 *
 * @param entry Entry to free (can be NULL)
 */
void metadata_entry_free(metadata_entry_t *entry);

/**
 * Add or update metadata entry (mode only)
 *
 * If an entry with the same storage_path exists, it is replaced.
 * Otherwise, a new entry is added.
 * This function only sets mode - owner/group will be NULL.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 * @param mode Permission mode
 * @return Error or NULL on success
 */
error_t *metadata_set_entry(
    metadata_t *metadata,
    const char *storage_path,
    mode_t mode
);

/**
 * Add or update metadata entry from captured entry
 *
 * Copies all fields (mode, owner, group) from the source entry.
 * If an entry with the same storage_path exists, it is replaced.
 * Otherwise, a new entry is added.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param source Source entry to copy from (must not be NULL)
 * @return Error or NULL on success
 */
error_t *metadata_add_entry(
    metadata_t *metadata,
    const metadata_entry_t *source
);

/**
 * Get metadata entry for a file (const version)
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 * @param out Entry pointer (must not be NULL, borrowed reference - do not free)
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *metadata_get_entry(
    const metadata_t *metadata,
    const char *storage_path,
    const metadata_entry_t **out
);

/**
 * Get mutable metadata entry for a file
 *
 * Internal helper for modifying metadata entries. Should only be used when
 * you own the metadata structure and need to modify the entry.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 * @param out Entry pointer (must not be NULL, borrowed reference - do not free)
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *metadata_get_entry_mut(
    metadata_t *metadata,
    const char *storage_path,
    metadata_entry_t **out
);

/**
 * Remove metadata entry
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *metadata_remove_entry(
    metadata_t *metadata,
    const char *storage_path
);

/**
 * Check if metadata entry exists
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 * @return true if entry exists
 */
bool metadata_has_entry(
    const metadata_t *metadata,
    const char *storage_path
);

/**
 * Merge metadata from multiple sources
 *
 * Merges metadata collections according to precedence order.
 * Later sources override earlier ones for conflicting entries.
 * This implements profile layering (e.g., darwin overrides global).
 *
 * Example:
 *   sources[0] = global metadata
 *   sources[1] = darwin metadata
 *   Result: darwin entries override global entries
 *
 * @param sources Array of metadata collections (must not be NULL)
 * @param count Number of sources
 * @param out Merged metadata (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *metadata_merge(
    const metadata_t **sources,
    size_t count,
    metadata_t **out
);

/**
 * Capture metadata from filesystem file
 *
 * Creates a metadata entry from file stat data.
 * Symlinks are skipped (returns NULL with no error - caller should check *out).
 *
 * Ownership capture (user/group):
 * - ONLY captured for root/ prefix files when running as root (UID 0)
 * - home/ prefix files: ownership never captured (always current user)
 * - Regular users: ownership never captured (can't chown anyway)
 *
 * @param filesystem_path Path to file on disk (must not be NULL, for error messages)
 * @param storage_path Path in profile (must not be NULL)
 * @param st File stat data (must not be NULL)
 * @param out Entry (must not be NULL, caller must free with metadata_entry_free)
 *            Set to NULL if file is a symlink (not an error)
 * @return Error or NULL on success
 */
error_t *metadata_capture_from_file(
    const char *filesystem_path,
    const char *storage_path,
    const struct stat *st,
    metadata_entry_t **out
);

/**
 * Load metadata from profile branch
 *
 * Reads .dotta/metadata.json from the specified branch.
 * If the file doesn't exist, returns ERR_NOT_FOUND (not a fatal error).
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param out Metadata (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success (ERR_NOT_FOUND if file doesn't exist)
 */
error_t *metadata_load_from_branch(
    git_repository *repo,
    const char *branch_name,
    metadata_t **out
);

/**
 * Load metadata from file path
 *
 * Reads and parses metadata from a JSON file.
 * Returns ERR_NOT_FOUND if file doesn't exist.
 *
 * @param file_path Path to metadata JSON file (must not be NULL)
 * @param out Metadata (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success
 */
error_t *metadata_load_from_file(
    const char *file_path,
    metadata_t **out
);

/**
 * Load and merge metadata from multiple profiles
 *
 * Convenience function that loads .dotta/metadata.json from each profile
 * branch and merges them according to array order (later profiles override
 * earlier ones).
 *
 * Gracefully handles missing profiles and missing metadata files:
 * - Profile branch doesn't exist: skipped (non-fatal)
 * - Metadata file doesn't exist in profile: skipped (non-fatal)
 * - Returns empty metadata if no profiles have metadata files
 *
 * This is useful for operations that need metadata from multiple profiles
 * without knowing which profiles actually have metadata files.
 *
 * Use cases:
 * - Loading metadata from all deployed profiles for cleanup operations
 * - Bulk metadata loading for multi-profile operations
 *
 * @param repo Repository (must not be NULL)
 * @param profile_names Array of profile names to load (must not be NULL)
 * @param out Merged metadata (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success (empty metadata if no profiles have metadata)
 */
error_t *metadata_load_from_profiles(
    git_repository *repo,
    const string_array_t *profile_names,
    metadata_t **out
);

/**
 * Save metadata to worktree
 *
 * Writes .dotta/metadata.json to a worktree directory.
 * Creates the .dotta/ directory if it doesn't exist.
 * The file should then be staged and committed by the caller.
 *
 * @param worktree_path Path to worktree root (must not be NULL)
 * @param metadata Metadata to save (must not be NULL)
 * @return Error or NULL on success
 */
error_t *metadata_save_to_worktree(
    const char *worktree_path,
    const metadata_t *metadata
);

/**
 * Parse mode string to mode_t
 *
 * Parses octal mode string (e.g., "0600", "0644", "0755") to mode_t.
 * Validates that mode is within valid range (0000-0777).
 *
 * @param mode_str Mode string (must not be NULL)
 * @param out Mode value (must not be NULL)
 * @return Error or NULL on success
 */
error_t *metadata_parse_mode(const char *mode_str, mode_t *out);

/**
 * Format mode_t to string
 *
 * Formats mode_t as octal string (e.g., 0600 -> "0600").
 *
 * @param mode Mode value
 * @param out Mode string (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *metadata_format_mode(mode_t mode, char **out);

/**
 * Resolve ownership from owner/group strings to UID/GID
 *
 * Converts owner and group names to UID/GID values.
 * This is pure data transformation - no filesystem operations.
 *
 * Rules:
 * - Only works when running as root (returns ERR_PERMISSION otherwise)
 * - Validates that user/group exist on the system
 * - If owner is set but group is not, uses owner's primary group
 * - Returns uid=-1 or gid=-1 to indicate "don't change ownership"
 *
 * The caller is responsible for applying the resolved ownership
 * using fchown() or similar system calls.
 *
 * This function works with raw strings, making it usable for both
 * file entries (metadata_entry_t) and directory entries
 * (metadata_directory_entry_t) without requiring temporary structs.
 *
 * @param owner Owner username (can be NULL if no owner change desired)
 * @param group Group name (can be NULL if no group change desired)
 * @param out_uid Resolved UID or -1 if no ownership change (must not be NULL)
 * @param out_gid Resolved GID or -1 if no ownership change (must not be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_PERMISSION: Not running as root
 * - ERR_NOT_FOUND: User or group doesn't exist on this system
 */
error_t *metadata_resolve_ownership(
    const char *owner,
    const char *group,
    uid_t *out_uid,
    gid_t *out_gid
);

/**
 * Capture metadata from filesystem directory
 *
 * Creates a directory metadata entry from stat data.
 * Follows the same rules as file metadata capture.
 *
 * Ownership capture (user/group):
 * - ONLY captured for root/ prefix directories when running as root (UID 0)
 * - home/ prefix directories: ownership never captured (always current user)
 * - Regular users: ownership never captured (can't chown anyway)
 *
 * @param filesystem_path Path to directory on disk (must not be NULL, for error messages)
 * @param storage_prefix Storage prefix in profile (must not be NULL)
 * @param st Directory stat data (must not be NULL)
 * @param out Entry (must not be NULL, caller must free with metadata_directory_entry_free)
 * @return Error or NULL on success
 */
error_t *metadata_capture_from_directory(
    const char *filesystem_path,
    const char *storage_prefix,
    const struct stat *st,
    metadata_directory_entry_t **out
);

/**
 * Free directory entry
 *
 * @param entry Entry to free (can be NULL)
 */
void metadata_directory_entry_free(metadata_directory_entry_t *entry);

/**
 * Add tracked directory to metadata
 *
 * Records that a directory was explicitly added via `dotta add`,
 * enabling detection of new files that appear in this directory later.
 * Also captures directory metadata (permissions and ownership).
 * If the directory already exists, it is updated.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param filesystem_path Directory path on disk (must not be NULL)
 * @param storage_prefix Storage prefix in profile (must not be NULL)
 * @param added_at Timestamp when added (use time(NULL) for current time)
 * @param mode Permission mode (e.g., 0700, 0755, 0750)
 * @param owner Owner username (optional, can be NULL)
 * @param group Group name (optional, can be NULL)
 * @return Error or NULL on success
 */
error_t *metadata_add_tracked_directory(
    metadata_t *metadata,
    const char *filesystem_path,
    const char *storage_prefix,
    time_t added_at,
    mode_t mode,
    const char *owner,
    const char *group
);

/**
 * Remove tracked directory from metadata
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param filesystem_path Directory path to remove (must not be NULL)
 * @return Error or NULL on success (ERR_NOT_FOUND if not tracked)
 */
error_t *metadata_remove_tracked_directory(
    metadata_t *metadata,
    const char *filesystem_path
);

/**
 * Get tracked directory entry
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param filesystem_path Directory path to lookup (must not be NULL)
 * @param out Directory entry (must not be NULL, borrowed reference - do not free)
 * @return Error or NULL on success (ERR_NOT_FOUND if not tracked)
 */
error_t *metadata_get_tracked_directory(
    const metadata_t *metadata,
    const char *filesystem_path,
    const metadata_directory_entry_t **out
);

/**
 * Check if directory is tracked
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param filesystem_path Directory path to check (must not be NULL)
 * @return true if directory is tracked
 */
bool metadata_has_tracked_directory(
    const metadata_t *metadata,
    const char *filesystem_path
);

/**
 * Get all tracked directories
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Array of directory entries (borrowed reference - do not free individual entries)
 */
const metadata_directory_entry_t *metadata_get_all_tracked_directories(
    const metadata_t *metadata,
    size_t *count
);

#endif /* DOTTA_METADATA_H */
