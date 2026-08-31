/**
 * metadata.h - The claim sheet
 *
 * Each profile branch carries one document, .dotta/metadata.json: the claims
 * the profile makes about its paths beyond what its tree can say. An item exists
 * iff it claims something — every field beyond the key is a claim (or the one
 * cache), a capture whose answer claims nothing authors no item, and one that
 * finds a stale item standing at its key retires it.
 *
 * Authority, per fact:
 * - content and type: the tree's (a blob, a link, an executable) — never restated
 *   here, and the tree's word wins over a stale item's kind
 * - permission bits: the sheet's ("mode") — Git's filemode holds one bit of them
 *   (owner-execute), the sheet holds them all
 * - ownership: the sheet's ("owner"/"group") — captured only for paths whose
 *   label tracks it (root/, custom/), and only when running elevated; home/ paths
 *   are always the current user's
 * - a directory's existence: the sheet's (kind=directory) — the one claim a tree
 *   cannot hold, since Git trees have no empty directories
 * - encrypted: a cache of the blob's own bytes, stamped at the write boundary
 *
 * The sheet is sparse and the view completes it: manifest_build resolves an
 * unclaimed mode into an answer at build (the filemode floor for blob rows,
 * DIR_MODE_DEFAULT for directory claims), so no consumer downstream of the view
 * ever meets a hole.
 *
 * Symlinks claim no mode: symlink(2) takes none, and though lchmod(2) exists on
 * macOS/BSD, the bits it sets govern nothing — non-portable and functionally
 * inert. A link's entry exists to carry ownership (lchown is real), so it is a
 * "file" item without a mode; a link with no ownership to track has no entry at
 * all.
 *
 * Out of scope, deliberately: timestamps (cross-machine noise by design);
 * xattrs, ACLs, SELinux contexts, capabilities, chflags; hardlinks, devices,
 * FIFOs; symlink mode; umask-relative mode classes. Each would need its own
 * capture/deploy/divergence story; none is blocked by this schema.
 *
 * JSON Schema (Version 5) — items sorted by key, fields present iff claimed:
 * {
 *   "version": 5,
 *   "items": [
 *     {
 *       "kind": "directory",
 *       "key": "home/.config/nvim",
 *       "mode": "0700"
 *     },
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
 *       "key": "root/etc/alternatives/python",
 *       "owner": "root",
 *       "group": "wheel"
 *     },
 *     {
 *       "kind": "file",
 *       "key": "root/etc/nginx.conf",
 *       "mode": "0644",
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

#define METADATA_VERSION 5
#define METADATA_DIR ".dotta"
#define METADATA_FILE_PATH METADATA_DIR "/metadata.json"

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
 * The mode a claim does not make
 *
 * Permission bits run 0000–0777 and 0000 is one of them: `chmod 000` is a real
 * mode a user can mean. Absence therefore needs a value outside the domain, not
 * the domain's floor. Private to the claim sheet: the view resolves absence into
 * an answer at build (the filemode floor for blob rows, DIR_MODE_DEFAULT for
 * directory claims), so no row, record or verdict ever carries it.
 */
#define MODE_UNCLAIMED ((mode_t) -1)

/**
 * A claim
 *
 * One row of the sheet. The key is the storage path (e.g., "home/.bashrc") —
 * portable across machines, the join key every consumer looks up by; filesystem
 * paths are derived on demand via mount_resolve(). kind is the shared path_kind_t
 * (types.h): FILE claims about a path the tree names — any blob type, a symlink's
 * entry being a FILE item without a mode — while DIRECTORY is itself the claim,
 * the one path a tree cannot hold.
 *
 * Absence is a value: mode MODE_UNCLAIMED, owner/group NULL. encrypted is not a
 * claim but the cache of the blob's own bytes, false for DIRECTORY by construction
 * at both boundaries (the factories and the parser).
 */
typedef struct {
    path_kind_t kind;   /* FILE: the tree names the path. DIRECTORY: the item is the claim. */
    char *key;          /* Storage path — the join key for every consumer */
    mode_t mode;        /* Claimed permission bits, or MODE_UNCLAIMED */
    char *owner;        /* Claimed owner, or NULL */
    char *group;        /* Claimed group, or NULL */
    bool encrypted;     /* The blob's ciphertext stamp (false for DIRECTORY) */
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
 * @param mode Claimed permission bits (e.g., 0600, 0644), or MODE_UNCLAIMED
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
 * Accepts MODE_UNCLAIMED for the parse path (a hand-sparse document may omit
 * the mode); the capture path always claims one from its stat.
 *
 * @param storage_path Storage path in profile (must not be NULL, e.g.,
 *                     "home/.config/nvim")
 * @param mode Claimed permission bits (e.g., 0700, 0755), or MODE_UNCLAIMED
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
 * @param item Item to free (can be NULL)
 */
void metadata_item_free(metadata_item_t *item);

/**
 * Clone metadata item (deep copy)
 *
 * Creates a deep copy of a metadata item, duplicating all strings. Useful when
 * preserving an item while modifying the original collection.
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
 *     umask default), or MODE_UNCLAIMED (a hand-sparse entry claiming even less).
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
 * A key that is absent, held as a directory, or held unstamped answers false.
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
 * Capture a path's claim from stat data (regular file or symlink)
 *
 * One existence rule: an item exists iff it claims something. A regular file
 * always claims its mode (0000 included); a symlink claims none — symlink(2)
 * takes none — so its item carries ownership alone, and when there is no ownership
 * to claim either, no item is authored and *out is NULL. A NULL answer is therefore
 * a links-only answer, and the producers read it as "the capture claims nothing":
 * retire whatever stale item stands at the key.
 *
 * Ownership capture (user/group):
 * - ONLY captured for paths whose label tracks ownership (root/, custom/), and
 *   only when running as root (UID 0)
 * - home/ prefix paths: ownership never captured (always current user)
 * - Regular users: ownership never captured (can't chown anyway)
 *
 * For a symlink, pass lstat data: the link's own uid/gid, not the target's.
 *
 * @param filesystem_path Path to file on disk (must not be NULL, for error
 *                        messages)
 * @param storage_path Path in profile (must not be NULL)
 * @param st File stat data (must not be NULL)
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 *            Set to NULL if the capture claims nothing (not an error)
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
 * Creates a directory metadata item from stat data. Follows the same ownership
 * rules as file capture; the mode is always claimed from the stat. Callers treat
 * a directory-capture failure as a warning where a file-capture failure is fatal:
 * a directory item is an attributes overlay, never content, so a missed capture
 * loses a claim and nothing else.
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
 * Serializes metadata to JSON: items in key order (a write-side norm buying
 * byte-determinism across machines; the parser accepts any order), fields present
 * iff claimed — an unclaimed mode, a NULL owner/group and a false encrypted have
 * no line to print.
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
