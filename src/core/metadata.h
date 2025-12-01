/**
 * metadata.h - Unified metadata system
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
 *       "key": "home/.config/nvim",
 *       "mode": "0700"
 *     },
 *     {
 *       "kind": "directory",
 *       "key": "root/etc/nginx",
 *       "mode": "0755",
 *       "owner": "root",
 *       "group": "wheel"
 *     }
 *   ]
 * }
 */

#ifndef DOTTA_METADATA_H
#define DOTTA_METADATA_H

#include <git2.h>
#include <sys/stat.h>
#include <time.h>
#include <types.h>

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
 * Key interpretation (unified for all kinds):
 * - ALL ITEMS: key = storage_path (e.g., "home/.bashrc", "home/.config/nvim")
 *
 * This ensures metadata portability across machines.
 * Filesystem paths are derived on-demand using path_from_storage() when needed
 * for deployment or stat operations.
 */
typedef struct {
    metadata_item_kind_t kind;       /* Discriminator: FILE or DIRECTORY */

    /* Lookup key */
    char *key;                       /* storage_path for both files and directories */

    /* Common metadata fields */
    mode_t mode;                     /* Permission mode (e.g., 0600, 0644, 0755) */
    char *owner;                     /* Owner username (optional, only for root/ prefix) */
    char *group;                     /* Group name (optional, only for root/ prefix) */

    /* Kind-specific data (discriminated union) */
    union {
        struct {
            bool encrypted;          /* Encryption flag (files only) */
        } file;

        struct {
            char _reserved;          /* Reserved for C11 compliance */
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
    int version;                     /* Schema version */
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
 * Generic callback signature for use with containers (e.g., hashmap_free).
 * Accepts void* to match standard C cleanup callback pattern.
 *
 * @param ptr Metadata to free (can be NULL)
 */
void metadata_free(void *ptr);

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
 * @param storage_path Storage path in profile (must not be NULL, e.g., "home/.config/nvim")
 * @param mode Permission mode (e.g., 0700, 0755)
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_item_create_directory(
    const char *storage_path,
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
 * Clone metadata item (deep copy)
 *
 * Creates a deep copy of a metadata item, duplicating all strings and
 * union fields based on the item's kind. Useful when preserving an item
 * while modifying the original collection.
 *
 * @param source Source item to clone (must not be NULL)
 * @param out Cloned item (must not be NULL, caller must free with metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_item_clone(
    const metadata_item_t *source,
    metadata_item_t **out
);

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
 * @param key Lookup key (storage_path for both files and directories)
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
 * @param key Lookup key (storage_path for both files and directories)
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
 * @param key Lookup key (storage_path for both files and directories)
 * @return true if item exists
 */
bool metadata_has_item(
    const metadata_t *metadata,
    const char *key
);

/**
 * Get encrypted flag for file from metadata
 *
 * Convenience accessor that safely extracts the encrypted flag for a specific
 * file entry. This is a type-safe accessor that validates the item is a file
 * (not a directory) before accessing the file-specific encrypted field.
 *
 * Gracefully handles all error conditions by returning false:
 * - NULL metadata or storage_path
 * - Item not found in metadata
 * - Item exists but is a directory (not a file)
 *
 * Common usage pattern for historical operations:
 *   bool encrypted = metadata_get_file_encrypted(metadata, storage_path);
 *   err = content_get_from_blob_oid(..., encrypted, ...);
 *
 * Note: VWD operations use entry->encrypted directly from state database.
 *
 * @param metadata Metadata collection (can be NULL)
 * @param storage_path Storage path to lookup (can be NULL)
 * @return Encrypted flag (false if not found, error, or not a file)
 */
bool metadata_get_file_encrypted(
    const metadata_t *metadata,
    const char *storage_path
);

/**
 * Get all items (unfiltered)
 *
 * Returns direct pointer to internal items array (borrowed reference).
 * Zero-cost operation - no allocation, no copying.
 *
 * The returned pointer is only valid until the next modification to metadata.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Array of items (borrowed reference - do not free), or NULL if empty
 */
const metadata_item_t *metadata_get_all_items(
    const metadata_t *metadata,
    size_t *count
);

/**
 * Get items filtered by kind
 *
 * Returns allocated array of pointers to matching items.
 * Caller must free the returned pointer array (but not the items themselves).
 *
 * This performs a small allocation (pointers only, ~8 bytes per item).
 * Items themselves remain in the metadata structure and are not copied.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param kind Item kind to filter by (METADATA_ITEM_FILE or METADATA_ITEM_DIRECTORY)
 * @param count Output count (must not be NULL)
 * @return Allocated array of item pointers (caller must free), or NULL if no matches
 *
 * Return value semantics:
 * - NULL with count=0: No matches, or allocation failure, or invalid input
 * - Non-NULL with count=N: Array of N item pointers (caller must free array)
 */
const metadata_item_t **metadata_get_items_by_kind(
    const metadata_t *metadata,
    metadata_item_kind_t kind,
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
 * @param storage_path Storage path in profile (must not be NULL, e.g., "home/.config/nvim")
 * @param st Directory stat data (must not be NULL)
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_capture_from_directory(
    const char *storage_path,
    const struct stat *st,
    metadata_item_t **out
);

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
 * Load metadata from a Git tree
 *
 * Loads metadata.json from a specific Git tree. This is useful for
 * loading metadata from historical commits or arbitrary tree objects.
 *
 * @param repo Repository (must not be NULL)
 * @param tree Git tree to load from (must not be NULL)
 * @param profile_name Profile name for error messages (must not be NULL)
 * @param out Metadata (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success (ERR_NOT_FOUND if file doesn't exist in tree)
 */
error_t *metadata_load_from_tree(
    git_repository *repo,
    git_tree *tree,
    const char *profile_name,
    metadata_t **out
);

/**
 * Convert metadata to JSON string
 *
 * Serializes metadata to JSON format
 *
 * @param metadata Metadata to serialize (must not be NULL)
 * @param out JSON buffer (must not be NULL, caller must free with buffer_free)
 * @return Error or NULL on success
 */
error_t *metadata_to_json(
    const metadata_t *metadata,
    buffer_t **out
);

/**
 * Parse metadata from JSON string
 *
 * Parses metadata from JSON content.
 * Rejects version mismatches with clear error message (no migration code).
 *
 * @param json_str JSON string (must not be NULL)
 * @param out Metadata (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success
 */
error_t *metadata_from_json(
    const char *json_str,
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

#endif /* DOTTA_METADATA_H */
