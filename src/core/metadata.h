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
 *   are always the current user's. A capture names both halves or neither: the
 *   read side reads a lone half as a narrow claim deliberately made, so a name
 *   the host cannot spell fails the capture rather than authoring one
 * - a directory's existence: the sheet's ("tracked") — the one claim a tree cannot
 *   hold, since Git trees have no empty directories
 * - encrypted: a cache of the blob's own bytes, stamped at the write boundary
 *
 * Two kinds of directory claim, one field between them. "tracked" says the profile
 * manages the directory itself: a walk went into it, so the directory exists
 * because the profile says so, its attributes are the profile's to enforce and
 * its contents the profile's to scan. Without the field the item is only the
 * attributes to give the path if dotta has to create it — an ancestor claim,
 * derived from the chain above a managed path, binding dotta's own creation of
 * that path and nothing else.
 *
 * The polarity is the fail-safe one and the sparse one at once: an item that
 * loses the field — a hand edit, a tool that drops what it does not know — degrades
 * to the class dotta does less with, and the derived claims, one per rung of
 * every chain and so the numerous kind, carry no field at all.
 *
 * An ancestor claim exists because something beneath it does, so its mode is
 * all it has left to say. One that claims no mode says nothing at all — the view
 * answers an unclaimed directory mode with DIR_MODE_DEFAULT, which is what an
 * unclaimed path would have got anyway — and metadata_prune_directories reaps
 * it as the residue it is.
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
 * JSON Schema (Version 6) — items sorted by key, fields present iff claimed:
 * {
 *   "version": 6,
 *   "items": [
 *     {
 *       "kind": "directory",
 *       "key": "home/.config",
 *       "mode": "0700"
 *     },
 *     {
 *       "kind": "directory",
 *       "key": "home/.config/nvim",
 *       "mode": "0755",
 *       "tracked": true
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
 *
 * home/.config is an ancestor claim: dotta creates it 0700 if it has to create
 * it at all, and leaves it exactly as it finds it otherwise. home/.config/nvim
 * was walked into, so the profile manages it.
 */

#ifndef DOTTA_METADATA_H
#define DOTTA_METADATA_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

#define METADATA_VERSION 6
#define METADATA_DIR ".dotta"
#define METADATA_FILE_PATH METADATA_DIR "/metadata.json"

/**
 * Default mode for tracked directories without an explicit override.
 *
 * Mirrors the umask default any newly-mkdir'd directory gets on Linux/ macOS/BSD
 * (0755 = rwxr-xr-x) — the mode a chain of parents gets when nothing claims them.
 *
 * Used by metadata_prune_directories as half the residue discriminator: a tracked
 * claim at this mode and with no ownership carries no preservation intent over
 * what the filesystem already does by default, so with nothing anchoring it either,
 * the entry is walker residue from a path the user no longer tracks and can be
 * dropped without information loss. An ancestor claim needs no such reading of
 * its attributes — it is a derivation, so the anchor question is the whole of it.
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
 * Absence is a value: mode MODE_UNCLAIMED, owner/group NULL, and a tracked that
 * is false — an ancestor claim's whole spelling. The two flags are one kind's
 * each, encrypted the cache of a blob's own bytes and tracked the claim that
 * the profile manages a directory, and each is false for the other kind by
 * construction at both boundaries (the factories and the parser).
 */
typedef struct {
    path_kind_t kind;   /* FILE: the tree names the path. DIRECTORY: the item is the claim. */
    char *key;          /* Storage path — the join key for every consumer */
    mode_t mode;        /* Claimed permission bits, or MODE_UNCLAIMED */
    char *owner;        /* Claimed owner, or NULL */
    char *group;        /* Claimed group, or NULL */
    bool encrypted;     /* The blob's ciphertext stamp (false for DIRECTORY) */
    bool tracked;       /* The profile manages the directory (false for FILE) */
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
 * The class is the author's to answer, which is why it is a parameter and not a
 * default: a walk that entered the directory says true, a derivation of the chain
 * above a managed path says false, and nothing else authors a directory claim.
 *
 * Accepts MODE_UNCLAIMED for the parse path (a hand-sparse document may omit
 * the mode); the capture path always claims one from its stat.
 *
 * @param storage_path Storage path in profile (must not be NULL, e.g.,
 *                     "home/.config/nvim")
 * @param mode Claimed permission bits (e.g., 0700, 0755), or MODE_UNCLAIMED
 * @param tracked The profile manages the directory itself
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_item_create_directory(
    const char *storage_path,
    mode_t mode,
    bool tracked,
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
 * and is not a failure — the answer is false, arrived at by one index probe.
 *
 * A key the collection does hold costs a walk on top of that: closing the gap
 * in insertion order needs the item's position, and only the spine has it. Callers
 * removing many keys pay that walk once per key.
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
 * Removes kind=directory items whose reason to exist is gone. Every such item
 * is asked two questions, and one that answers no to both is removed:
 *
 *   - Does it claim anything of its own? A tracked claim at a mode the umask
 *     would not have produced, or carrying any ownership overlay, is the walk's
 *     word about a directory the profile manages, and it is kept with nothing
 *     beneath it: that is exactly the legitimate "track this empty directory
 *     with these attributes" intent. A tracked claim at DIR_MODE_DEFAULT — or
 *     at no mode at all, a hand-sparse entry claiming even less — says nothing
 *     a plain mkdir would not. An ancestor claim claims nothing of its own by
 *     construction: it is derived from the chain above a managed path, so no
 *     attribute it carries can make it mean anything else.
 *
 *   - Is anything managed beneath it? The profile's managed set is the index's
 *     paths and the sheet's own directory claims together. The index names every
 *     path a tree can hold and is the sole authority for those — deliberately
 *     not the metadata items, which are sparse by design (a symlink carries an
 *     item only when captured with ownership, i.e. elevated), so a directory
 *     whose only tracked content is an item-less symlink is anchored by the index
 *     and survives. What no index can name is an empty directory, and only a
 *     claim names one — a claim that answered yes to the first question, since
 *     one that did not survives solely by being anchored itself and would otherwise
 *     hold a doomed chain alive one command per rung.
 *
 * Anchoring is judged against the post-edit index (the tree the impending commit
 * will record). An entry that answers no twice has no role in any downstream
 * pipeline: the view would only claim it as a default-mode scan anchor for an
 * emptied subtree, and divergence detection has nothing to compare against.
 * Typically it's walker residue from a path the user no longer tracks (e.g.,
 * `dotta add ~/dir/` followed by `dotta remove` of every file underneath), or
 * the tail of an ancestry whose leaf has just gone. Without this prune, the view
 * would keep claiming the entry indefinitely.
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
 * - Both names or neither: where ownership is captured at all, a UID or GID this
 *   host cannot name fails the capture (ERR_NOT_FOUND). Half a claim would read
 *   downstream as a claim deliberately made narrow, and the path would land owned
 *   by whoever deploy created it as
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
 * rules as file capture — the unnameable UID among them — while the mode is always
 * claimed from the stat. The class is the caller's: a stat cannot say whether a
 * walk entered the directory or only passed above it, so `tracked` is carried
 * through to the factory unread. Callers treat a directory-capture failure as a
 * warning where a file-capture failure is fatal: a directory item is an attributes
 * overlay, never content, so a missed capture loses a claim and nothing else.
 * It loses the mode with the ownership, though, and with it the directory's own
 * row — an add does not track it, an update leaves the standing claim alone —
 * so the callers' warning is one the user reads at any verbosity.
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
 * @param tracked The profile manages the directory itself
 * @param out Item (must not be NULL, caller must free with metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_capture_from_directory(
    const char *storage_path,
    const struct stat *st,
    bool tracked,
    metadata_item_t **out
);

/**
 * Author the claims for every directory on the way to a path
 *
 * The sheet's completeness rule for the chain. Every component between the mount
 * root and `storage_path` that is a real directory right now claims the attributes
 * it has, as an ancestor claim: the profile does not manage the directory, it
 * passes through it, so `tracked` is absent and the claim binds only dotta's
 * own creation of that path (core/deploy's ancestors pass). The mount root itself
 * is never a key — a target is not a path any profile claims — and neither is
 * the leaf, which is its own capture's business.
 *
 * The two spellings of the one path are the whole input. A storage path is its
 * label plus the mount-relative tail; the filesystem path is its mount target
 * plus that same tail, the very bytes, whichever direction the pair was derived
 * in (mount_classify hands the tail out of the filesystem path, mount_resolve
 * joins a target to it). So the tail's own separators name every ancestor twice,
 * once in each namespace, at the same offset from each end — no mount table, no
 * arena, no allocation beyond one scratch copy of each name. A pair that does
 * not hold that is not two names for one path, and is refused.
 *
 * Per rung, root-first:
 *   - a tracked claim standing at the key is the walk's own word and is left
 *     exactly as it is; the climb continues past it, since a tracked claim says
 *     nothing about the rungs above it
 *   - a FILE item standing at the key is the tree's business, not this rule's
 *   - a directory on disk  -> captured and upserted; counted only when the claim
 *     it makes differs from the one standing, so a re-derivation that found nothing
 *     new rewrites nothing and drives no commit
 *   - anything else on disk -> the derivation claims no directory here, so a
 *     standing ancestor claim is retired (the sheet's own producer rule) and
 *     its key appended to `retired`
 *   - nothing there, or nothing this host could see or name -> the rung has no
 *     answer, and no answer is not an answer of "no": nothing authored, nothing
 *     retired
 *
 * The two outs are shaped by what a caller can do with them, not by symmetry: a
 * claim authored has no consequence beyond the sheet, so its count is the whole
 * report, while a claim retired leaves the view by the caller's commit and its
 * record behind — and only the key names that.
 *
 * Idempotent, and total over the chain: no rung stops the climb. O(depth) lstats
 * per call; the callers pay it once per captured leaf.
 *
 * @param metadata Collection to author into (must not be NULL; mutated)
 * @param storage_path Leaf's storage path, label-first (must not be NULL)
 * @param filesystem_path The same leaf under its other name (must not be NULL)
 * @param captured Count of rungs whose claim this call authored or changed, added
 *                 to (must not be NULL)
 * @param retired Keys this call retired, appended (must not be NULL)
 * @return Error or NULL on success
 */
error_t *metadata_capture_ancestors(
    metadata_t *metadata,
    const char *storage_path,
    const char *filesystem_path,
    size_t *captured,
    string_array_t *retired
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
