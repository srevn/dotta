/**
 * metadata.h - Unified metadata system
 *
 * UNIFIED DESIGN: Single discriminated union for files, directories, and symlinks.
 *
 * Design principles:
 * - Common fields (mode, owner, group) apply to all kinds
 * - Kind-specific fields stored in discriminated union
 * - Single hashmap for O(1) lookup of all kinds
 * - Ownership tracking: only for paths whose label tracks it (root/, custom/),
 *   and only when running as root
 * - home/ prefix: always owned by current user
 * - Per-profile storage for natural layering
 * - Automatic capture during add/update operations
 * - Automatic restoration during apply/revert operations
 *
 * Symlink metadata:
 * - mode is always 0 (symlink permissions are OS-dependent and not settable)
 * - Only ownership is tracked (lchown changes the link itself, not its target)
 * - Only created for symlinks whose label tracks ownership, when running as root
 * - home/ prefix symlinks: no metadata entry needed (always current user)
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
 *     },
 *     {
 *       "kind": "symlink",
 *       "key": "root/etc/alternatives/python",
 *       "mode": "0000",
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
#include <types.h>

#define METADATA_DIR ".dotta"
#define METADATA_FILE_PATH METADATA_DIR "/metadata.json"
#define METADATA_VERSION 4

/**
 * Default mode for tracked directories without an explicit override.
 *
 * Mirrors the umask default any newly-mkdir'd directory gets on Linux/ macOS/BSD
 * (0755 = rwxr-xr-x) — the same mode file deploy's fs_create_dir(parents=true)
 * produces when materialising an ancestor that no metadata.json entry claims.
 *
 * Used by metadata_prune_directories as the residue discriminator: a kind=directory
 * entry with this mode and no ownership carries no preservation intent over what
 * the filesystem already does by default, so when it has no anchoring descendants
 * either, the entry is walker residue from a path the user no longer tracks and
 * can be dropped without information loss.
 */
#define DIR_MODE_DEFAULT 0755

/**
 * Metadata item kind discriminator
 */
typedef enum {
    METADATA_ITEM_FILE      = 0,
    METADATA_ITEM_DIRECTORY = 1,
    METADATA_ITEM_SYMLINK   = 2
} metadata_item_kind_t;

/**
 * Unified metadata item (files, directories, and symlinks)
 *
 * This structure uses a discriminated union to store file, directory, and symlink
 * metadata efficiently. Common fields (mode, owner, group) are shared, while
 * kind-specific fields are stored in the union.
 *
 * Key interpretation (unified for all kinds):
 * - ALL ITEMS: key = storage_path (e.g., "home/.bashrc", "home/.config/nvim")
 *
 * This ensures metadata portability across machines. Filesystem paths are derived
 * on-demand via mount_resolve() when needed for deployment or stat operations.
 *
 * Symlink semantics:
 * - mode is always 0 (symlink permissions are not settable via symlink())
 * - owner/group are tracked for ownership-tracking labels (applied via lchown)
 * - No encrypted flag (symlinks are never encrypted)
 */
typedef struct {
    metadata_item_kind_t kind;       /* Discriminator: FILE, DIRECTORY, or SYMLINK */

    /* Lookup key */
    char *key;                       /* storage_path for all kinds */

    /* Common metadata fields */
    mode_t mode;                     /* Permission mode (0 for symlinks) */
    char *owner;                     /* Owner username (optional, ownership-tracking labels only) */
    char *group;                     /* Group name (optional, ownership-tracking labels only) */

    /* Kind-specific data (discriminated union) */
    union {
        struct {
            bool encrypted;          /* Encryption flag (files only) */
        } file;

        struct {
            char _reserved;          /* Reserved for C11 compliance */
        } directory;

        struct {
            char _reserved;          /* Reserved for C11 compliance */
        } symlink;
    };
} metadata_item_t;

/**
 * Unified metadata collection (opaque)
 *
 * Owns every item it holds and hands them out borrowed. An item pointer stays
 * valid until that item is itself removed or the collection is freed, whatever
 * else is added or removed meanwhile; the slice metadata_items returns is the
 * collection's own storage and does not survive either.
 */
typedef struct metadata metadata_t;

/**
 * Create empty metadata collection
 *
 * @param out Metadata structure (must not be NULL, caller must free with
 *            metadata_free)
 * @return Error or NULL on success
 */
error_t *metadata_create_empty(metadata_t **out);

/**
 * Free metadata structure
 *
 * Frees every item it holds and the structure itself.
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
 * @param storage_path Storage path in profile (must not be NULL, e.g.,
 *                     "home/.config/nvim")
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
 * Create symlink metadata item
 *
 * Creates a metadata item for a symbolic link. Mode is always 0 because symlink
 * permissions are not settable (symlink() has no mode parameter, and chmod() on
 * a symlink changes the target or fails, OS-dependent).
 *
 * Only ownership (owner/group) is meaningful for symlinks, applied via lchown()
 * during deployment.
 *
 * @param storage_path Path in profile (must not be NULL)
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_item_create_symlink(
    const char *storage_path,
    metadata_item_t **out
);

/**
 * Free metadata item
 *
 * Handles both file and directory items correctly. Frees kind-specific union
 * fields based on kind.
 *
 * @param item Item to free (can be NULL)
 */
void metadata_item_free(metadata_item_t *item);

/**
 * Clone metadata item (deep copy)
 *
 * Creates a deep copy of a metadata item, duplicating all strings and union fields
 * based on the item's kind. Useful when preserving an item while modifying the
 * original collection.
 *
 * @param source Source item to clone (must not be NULL)
 * @param out Cloned item (must not be NULL, caller must free with
 *            metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_item_clone(
    const metadata_item_t *source,
    metadata_item_t **out
);

/**
 * Add or update metadata item, transferring ownership
 *
 * Works for every kind. If an item with the same key exists it is replaced in
 * place; otherwise the item is appended.
 *
 * The collection TAKES the item it is handed rather than duplicating it: the
 * item keeps its place in memory, the collection keeps the pointer, and *item
 * is left NULL. On error nothing was published — the collection is exactly as
 * it was and the caller still owns the item.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param item Item to hand over (neither it nor *item may be NULL; *item is NULL
 *             on success, unchanged on error)
 * @return Error or NULL on success
 */
error_t *metadata_add_item(
    metadata_t *metadata,
    metadata_item_t **item
);

/**
 * Look up an item by key
 *
 * Works for every kind; callers that want one test item->kind. A key the collection
 * does not hold is the answer, not a failure — it is NULL.
 *
 * @param metadata Metadata collection (NULL returns NULL)
 * @param key Lookup key, the storage path for every kind (NULL returns NULL)
 * @return Borrowed item pointer (do not free), or NULL if the key is not held
 */
const metadata_item_t *metadata_lookup(
    const metadata_t *metadata,
    const char *key
);

/**
 * Remove metadata item
 *
 * Works for every kind. Removing a key the collection does not hold changes nothing
 * and is not a failure — the answer is false.
 *
 * @param metadata Metadata collection (NULL returns false)
 * @param key Lookup key, the storage path for every kind (NULL returns false)
 * @return true if an item was removed
 */
bool metadata_remove_item(
    metadata_t *metadata,
    const char *key
);

/**
 * Prune redundant directory entries
 *
 * Removes kind=directory items that carry no actionable information beyond what
 * an unwritten entry would. An entry is "redundant" when ALL of these hold:
 *
 *   - No index entry lives under it (no anchoring descendants in the tree the
 *     impending commit will record).
 *   - mode == DIR_MODE_DEFAULT (no mode override to preserve over the filesystem's
 *     umask default).
 *   - owner == NULL AND group == NULL (no ownership override to preserve).
 *
 * Anchoring is judged against the post-edit index (the tree the impending commit
 * will record) — the sole authority for which paths the profile tracks. Metadata
 * items are deliberately NOT the universe: the collection is sparse by design
 * (a symlink carries an item only when captured with ownership, i.e. elevated),
 * so "no item descendants" does not imply "no tracked descendants". A directory
 * whose only tracked content is an item-less symlink is anchored by the index
 * and survives.
 *
 * Such an entry has no role in any downstream pipeline: file deploy already mkdirs
 * ancestors at the same default mode, the view would only claim it as a
 * default-mode scan anchor for an emptied subtree, and divergence detection has
 * nothing to compare against. Typically it's walker residue from a path the user
 * no longer tracks (e.g., `dotta add ~/dir/` followed by `dotta remove` of every
 * file underneath). Without this prune, the view would keep claiming the entry
 * indefinitely.
 *
 * Custom-attribute entries (mode != default, or non-NULL owner/group) are preserved
 * even when unanchored: they may represent legitimate "track this empty directory
 * with these attributes" intent. Today the schema cannot distinguish that from
 * leftover residue, so we err on the side of preservation for entries that carry
 * distinguishing information.
 *
 * Caller pattern: invoke after every index edit for the impending commit (additions
 * staged, deletions removed) and before the metadata blob is serialized for the
 * commit (worktree file or ODB blob alike), so the prune sees the commit's exact
 * tracked set and lands in the same commit as the triggering removals. The keys
 * pruned are appended to `pruned`, in item order: the entry leaves the view by
 * the verb's own commit, so the verb retires its record the way it does a path
 * it removed. Nothing appended means nothing was pruned (caller may use this to
 * skip a no-op rewrite).
 *
 * @param metadata Metadata collection (must not be NULL; mutated in place)
 * @param index Post-edit worktree index (must not be NULL)
 * @param pruned Receives the keys pruned, appended (must not be NULL)
 * @return Error or NULL on success
 */
error_t *metadata_prune_directories(
    metadata_t *metadata,
    git_index *index,
    string_array_t *pruned
);

/**
 * Encrypted flag for a file entry
 *
 * Type-safe accessor: it reads the file union member from behind its discriminator,
 * so a key that is absent, or held as a directory or a symlink, answers false
 * rather than misreading a union.
 *
 * Common usage pattern for historical operations:
 *   bool encrypted = metadata_file_encrypted(metadata, storage_path);
 *   err = content_get_from_blob_oid(..., encrypted, ...);
 *
 * Note: the view carries the flag on its rows (manifest_row_t.encrypted, projected
 * from this metadata at build); workspace-backed operations read it there.
 *
 * @param metadata Metadata collection (can be NULL)
 * @param storage_path Storage path to lookup (can be NULL)
 * @return Encrypted flag (false if not found or not a file)
 */
bool metadata_file_encrypted(
    const metadata_t *metadata,
    const char *storage_path
);

/**
 * Every item the collection holds, in insertion order
 *
 * Returns the collection's own storage, borrowed. Zero-cost operation - no
 * allocation, no copying.
 *
 * Anything that grows or shrinks the collection invalidates the returned array;
 * the items it points at are not moved by it — each stands until it is itself
 * removed.
 *
 * @param metadata Metadata collection (NULL yields count 0)
 * @param count Output count (must not be NULL)
 * @return Borrowed array of item pointers (do not free), NULL only when metadata
 *         is NULL
 */
const metadata_item_t *const *metadata_items(
    const metadata_t *metadata,
    size_t *count
);

/**
 * Capture metadata from filesystem file
 *
 * Creates a file metadata item from stat data. For symlinks, delegates to
 * metadata_capture_from_symlink().
 *
 * Ownership capture (user/group):
 * - ONLY captured for files whose label tracks ownership (root/, custom/), and
 *   only when running as root (UID 0)
 * - home/ prefix files: ownership never captured (always current user)
 * - Regular users: ownership never captured (can't chown anyway)
 *
 * @param filesystem_path Path to file on disk (must not be NULL, for error
 *                        messages)
 * @param storage_path Path in profile (must not be NULL)
 * @param st File stat data (must not be NULL)
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 *            Set to NULL if symlink with no ownership to track (not an error)
 * @return Error or NULL on success
 */
error_t *metadata_capture_from_file(
    const char *filesystem_path,
    const char *storage_path,
    const struct stat *st,
    metadata_item_t **out
);

/**
 * Capture metadata from filesystem symlink
 *
 * Creates a symlink metadata item with ownership data only. Mode is always 0
 * (symlink permissions are not settable).
 *
 * Symlinks only need metadata for ownership tracking on paths whose label tracks
 * it. For home/ prefix or non-root users, returns *out = NULL (no metadata needed).
 *
 * Ownership capture (user/group):
 * - ONLY captured for symlinks whose label tracks ownership (root/, custom/),
 *   and only when running as root (UID 0)
 * - home/ prefix symlinks: always owned by current user, no metadata needed
 * - Regular users: can't lchown anyway, no metadata needed
 *
 * @param storage_path Path in profile (must not be NULL)
 * @param st Symlink stat data from lstat (must not be NULL, must be S_ISLNK)
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 *            Set to NULL if no ownership to track (not an error)
 * @return Error or NULL on success
 */
error_t *metadata_capture_from_symlink(
    const char *storage_path,
    const struct stat *st,
    metadata_item_t **out
);

/**
 * Capture metadata from filesystem directory
 *
 * Creates a directory metadata item from stat data. Follows the same ownership
 * rules as file capture.
 *
 * Ownership capture (user/group):
 * - ONLY captured for directories whose label tracks ownership (root/, custom/),
 *   and only when running as root (UID 0)
 * - home/ prefix directories: ownership never captured (always current user)
 * - Regular users: ownership never captured (can't chown anyway)
 *
 * @param storage_path Storage path in profile (must not be NULL, e.g.,
 *                     "home/.config/nvim")
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
 * Load metadata from profile branch
 *
 * Reads .dotta/metadata.json from the specified branch. If the file doesn't exist,
 * returns ERR_NOT_FOUND (not a fatal error). Rejects version mismatches with
 * clear error message (no migration code).
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
 * Loads metadata.json from a specific Git tree. This is useful for loading metadata
 * from historical commits or arbitrary tree objects.
 *
 * @param repo Repository (must not be NULL)
 * @param tree Git tree to load from (must not be NULL)
 * @param profile Profile name for error messages (must not be NULL)
 * @param out Metadata (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success (ERR_NOT_FOUND if file doesn't exist in tree)
 */
error_t *metadata_load_from_tree(
    git_repository *repo,
    git_tree *tree,
    const char *profile,
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
    buffer_t *out
);

/**
 * Parse metadata from JSON string
 *
 * Parses metadata from JSON content. Rejects version mismatches with clear error
 * message (no migration code).
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
 * Reads and parses metadata from a JSON file. Returns ERR_NOT_FOUND if file doesn't
 * exist. Rejects version mismatches with clear error message (no migration code).
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
 * Save metadata to worktree
 *
 * Writes .dotta/metadata.json to a worktree directory. Creates the .dotta/
 * directory if it doesn't exist. The file should then be staged and committed
 * by the caller.
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
 * Resolve ownership from owner/group strings to UID/GID
 *
 * Converts owner and group names to UID/GID values. This is pure data
 * transformation - no filesystem operations, no privilege questions: whether
 * the resolved pair can be applied (chown needs root) is the applier's to ask.
 *
 * Rules:
 * - Validates that user/group exist on the system
 * - If owner is set but group is not, uses owner's primary group
 * - Returns uid=-1 or gid=-1 to indicate "don't change ownership"
 *
 * The caller is responsible for applying the resolved ownership using fchown()
 * or similar system calls.
 *
 * This function works with raw strings, making it usable for both file and
 * directory items without requiring temporary structs.
 *
 * @param owner Owner username (can be NULL if no owner change desired)
 * @param group Group name (can be NULL if no group change desired)
 * @param out_uid Resolved UID or -1 if no ownership change (must not be NULL)
 * @param out_gid Resolved GID or -1 if no ownership change (must not be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_NOT_FOUND: User or group doesn't exist on this system
 */
error_t *metadata_resolve_ownership(
    const char *owner,
    const char *group,
    uid_t *out_uid,
    gid_t *out_gid
);

#endif /* DOTTA_METADATA_H */
