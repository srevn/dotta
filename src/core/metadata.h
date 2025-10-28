/**
 * metadata.h - Unified metadata system (Version 4)
 *
 * UNIFIED DESIGN: Single discriminated union for files and directories.
 *
 * Design principles:
 * - Common fields (mode, owner, group) apply to both files and directories
 * - Kind-specific fields stored in discriminated union
 * - Single hashmap for O(1) lookup of both kinds
 * - Ownership tracking: ONLY for root/ prefix when running as root
 * - home/ prefix: always owned by current user
 * - Per-profile storage for natural layering
 * - Automatic capture during add/update operations
 * - Automatic restoration during apply/revert operations
 *
 * JSON Schema (Version 4):
 * {
 *   "version": 4,
 *   "items": [
 *     {
 *       "kind": "file",
 *       "key": "home/.bashrc",
 *       "mode": "0644"
 *     },
 *     {
 *       "kind": "file",
 *       "key": "home/.ssh/id_rsa",
 *       "mode": "0600",
 *       "encrypted": true
 *     },
 *     {
 *       "kind": "file",
 *       "key": "root/etc/nginx.conf",
 *       "mode": "0644",
 *       "owner": "root",
 *       "group": "wheel"
 *     },
 *     {
 *       "kind": "directory",
 *       "key": "/home/user/.config/nvim",
 *       "storage_prefix": "home/.config/nvim",
 *       "added_at": "2025-01-15T10:30:00Z",
 *       "mode": "0700"
 *     },
 *     {
 *       "kind": "directory",
 *       "key": "/etc/nginx",
 *       "storage_prefix": "root/etc/nginx",
 *       "added_at": "2025-01-15T10:30:00Z",
 *       "mode": "0755",
 *       "owner": "root",
 *       "group": "wheel"
 *     }
 *   ]
 * }
 */

#ifndef DOTTA_METADATA_V2_H
#define DOTTA_METADATA_V2_H

#include <git2.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "types.h"

#define METADATA_FILE_PATH ".dotta/metadata.json"
#define METADATA_VERSION 4

/**
 * Metadata item kind discriminator
 */
typedef enum {
    METADATA_ITEM_FILE = 0,
    METADATA_ITEM_DIRECTORY = 1
} metadata_item_kind_t;

/**
 * Unified metadata item (files and directories)
 *
 * This structure uses a discriminated union to store both file and directory
 * metadata efficiently. Common fields (mode, owner, group) are shared, while
 * kind-specific fields are stored in the union.
 *
 * Key interpretation (depends on kind):
 * - FILES: key = storage_path (e.g., "home/.bashrc")
 * - DIRECTORIES: key = filesystem_path (e.g., "/home/user/.config")
 *
 * The dual-key approach is necessary because:
 * - Files need storage path for manifest lookups
 * - Directories need filesystem path for stat operations
 * - Storage prefix stored separately for directories in union
 */
typedef struct {
    metadata_item_kind_t kind;       /* Discriminator: FILE or DIRECTORY */

    /* Lookup key (interpretation depends on kind) */
    char *key;                       /* storage_path for FILE, filesystem_path for DIRECTORY */

    /* Common metadata fields (all items have these) */
    mode_t mode;                     /* Permission mode (e.g., 0600, 0644, 0755) */
    char *owner;                     /* Owner username (optional, only for root/ prefix) */
    char *group;                     /* Group name (optional, only for root/ prefix) */

    /* Kind-specific data (discriminated union) */
    union {
        struct {
            bool encrypted;          /* Encryption flag (files only) */
        } file;

        struct {
            char *storage_prefix;    /* Storage path in profile (e.g., "home/.config/nvim") */
            time_t added_at;         /* Timestamp when added */
        } directory;
    };
} metadata_item_t;

/* Forward declaration */
typedef struct hashmap hashmap_t;

/**
 * Unified metadata collection
 *
 * Uses single array (for iteration/serialization) and single hashmap (for O(1) lookups).
 * The hashmap values point to items in the array (no separate allocation).
 */
typedef struct metadata {
    metadata_item_t *items;          /* Unified array of files and directories */
    size_t count;                    /* Number of items */
    size_t capacity;                 /* Array capacity */
    int version;                     /* Schema version (4) */
    hashmap_t *index;                /* Maps key -> item* (O(1) lookup for both kinds) */
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
 * Frees all items and the structure itself.
 * Handles kind-specific union fields correctly.
 *
 * @param metadata Metadata to free (can be NULL)
 */
void metadata_free(metadata_t *metadata);

/**
 * Create file metadata item
 *
 * @param storage_path Path in profile (must not be NULL)
 * @param mode Permission mode (e.g., 0600, 0644, 0755)
 * @param encrypted Encryption flag
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_item_create_file(
    const char *storage_path,
    mode_t mode,
    bool encrypted,
    metadata_item_t **out
);

/**
 * Create directory metadata item
 *
 * @param filesystem_path Directory path on disk (must not be NULL)
 * @param storage_prefix Storage prefix in profile (must not be NULL)
 * @param added_at Timestamp when added
 * @param mode Permission mode (e.g., 0700, 0755)
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_item_create_directory(
    const char *filesystem_path,
    const char *storage_prefix,
    time_t added_at,
    mode_t mode,
    metadata_item_t **out
);

/**
 * Free metadata item
 *
 * Handles both file and directory items correctly.
 * Frees kind-specific union fields based on kind.
 *
 * @param item Item to free (can be NULL)
 */
void metadata_item_free(metadata_item_t *item);

/**
 * Add or update metadata item
 *
 * Works for both files and directories.
 * If an item with the same key exists, it is updated.
 * Otherwise, a new item is added.
 *
 * IMPORTANT: This function COPIES the item, so caller must still free the source item.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param source Source item to copy from (must not be NULL)
 * @return Error or NULL on success
 */
error_t *metadata_add_item(
    metadata_t *metadata,
    const metadata_item_t *source
);

/**
 * Get metadata item (const version)
 *
 * Works for both files and directories.
 * Caller should check item->kind after retrieval if type matters.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param key Lookup key (storage_path for files, filesystem_path for directories)
 * @param out Item pointer (must not be NULL, borrowed reference - do not free)
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *metadata_get_item(
    const metadata_t *metadata,
    const char *key,
    const metadata_item_t **out
);

/**
 * Remove metadata item
 *
 * Works for both files and directories.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param key Lookup key (storage_path for files, filesystem_path for directories)
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *metadata_remove_item(
    metadata_t *metadata,
    const char *key
);

/**
 * Check if metadata item exists
 *
 * Works for both files and directories.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param key Lookup key (storage_path for files, filesystem_path for directories)
 * @return true if item exists
 */
bool metadata_has_item(
    const metadata_t *metadata,
    const char *key
);

/**
 * Get all items with optional kind filtering
 *
 * Returns direct pointer to internal array (borrowed reference).
 * Filtering is done by iterating and counting, not by copying.
 *
 * IMPORTANT: The returned pointer is only valid until the next modification to metadata.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param kind_filter Kind to filter by (METADATA_ITEM_FILE, METADATA_ITEM_DIRECTORY, or -1 for all)
 * @param count Output count (must not be NULL)
 * @return Array of items (borrowed reference - do not free)
 */
const metadata_item_t *metadata_get_items(
    const metadata_t *metadata,
    int kind_filter,
    size_t *count
);

/**
 * Capture metadata from filesystem file
 *
 * Creates a file metadata item from stat data.
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
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 *            Set to NULL if file is a symlink (not an error)
 * @return Error or NULL on success
 */
error_t *metadata_capture_from_file(
    const char *filesystem_path,
    const char *storage_path,
    const struct stat *st,
    metadata_item_t **out
);

/**
 * Capture metadata from filesystem directory
 *
 * Creates a directory metadata item from stat data.
 * Follows the same ownership rules as file capture.
 *
 * Ownership capture (user/group):
 * - ONLY captured for root/ prefix directories when running as root (UID 0)
 * - home/ prefix directories: ownership never captured (always current user)
 * - Regular users: ownership never captured (can't chown anyway)
 *
 * @param filesystem_path Path to directory on disk (must not be NULL)
 * @param storage_prefix Storage prefix in profile (must not be NULL)
 * @param st Directory stat data (must not be NULL)
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_capture_from_directory(
    const char *filesystem_path,
    const char *storage_prefix,
    const struct stat *st,
    metadata_item_t **out
);

/* ============================================================================
 * Merge Operations
 * ============================================================================ */

/**
 * Merge metadata from multiple sources
 *
 * Merges metadata collections according to precedence order.
 * Later sources override earlier ones for conflicting items (same key).
 * This implements profile layering (e.g., darwin overrides global).
 *
 * Example:
 *   sources[0] = global metadata
 *   sources[1] = darwin metadata
 *   Result: darwin items override global items
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
 * Load metadata from profile branch
 *
 * Reads .dotta/metadata.json from the specified branch.
 * If the file doesn't exist, returns ERR_NOT_FOUND (not a fatal error).
 * Rejects version mismatches with clear error message (no migration code).
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
 * Rejects version mismatches with clear error message (no migration code).
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
 * file and directory items without requiring temporary structs.
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

#endif /* DOTTA_METADATA_V2_H */
