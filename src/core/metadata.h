/**
 * metadata.h - The claim sheet
 *
 * Beside its tree, each profile carries a sheet, .dotta/metadata.json: the claims
 * the profile makes about its paths beyond what its tree can say. An item exists
 * iff it claims something — every field beyond the key is a claim (or the one
 * cache) — and the sheet keeps the rule at the one way a claim enters it
 * (metadata_write_item): a file's item that claims nothing is no item, and written,
 * it retires the one standing at its key — a capture's whose look claims nothing,
 * a restore's of a claim that says nothing (core/profiles.h
 * profile_stage_capture_file, profile_stage_restore_file) — while a document's
 * is read past (metadata_from_json).
 *
 * Authority, per fact:
 * - content and type: the tree's (a blob, a link, an executable) — never restated
 *   here, and the tree's word wins over a stale item's kind (read for one name
 *   by core/profiles.h profile_entry, which profile_holds and profile_find ask
 *   — and, for the claim an orphan's record remembers, by core/workspace.c
 *   workspace_orphan_authority, through profile_entry for a file and profile_find
 *   for a directory; for the whole profile by core/profiles.c profile_walk)
 * - permission bits: the sheet's ("mode") — Git's filemode holds one bit of them
 *   (owner-execute), the sheet holds them all
 * - ownership: the sheet's ("owner"/"group"), two names either of which may be
 *   absent, read per half and never by the label (metadata_ownership): an absent
 *   owner is the invoker — whoever runs dotta where the sheet is read — and an
 *   absent group no change. So a capture names the owner exactly where absence
 *   would say someone else: every owner that is not the capturing invoker, under
 *   every label, and the invoker's own where the invoker is root outside home/
 *   (metadata_capture_ownership). A claim a capture authors is then, on the host
 *   it was captured on, the node it was captured from, and whatever ownership
 *   the user moves a capture can commit. Both halves or neither: the read side
 *   reads a lone half as a narrow claim deliberately made, so a name the host
 *   cannot spell fails the capture rather than authoring one. A claim a hand
 *   wrote is honoured wherever it stands and replaced by the next capture over
 *   that path, which writes the item whole (metadata_write_item): a capture states
 *   what disk holds, and cannot tell a hand's intent from a claim that went stale
 * - a directory's existence: the sheet's ("tracked") — the one claim a tree cannot
 *   hold, since Git trees have no empty directories
 * - encrypted: a cache of the blob's own bytes, stamped at the write boundary
 *
 * A claim is a kind and a name. A FILE item says what the blob at its key carries
 * beyond the tree, a DIRECTORY item is a directory claim, and a key holds at
 * most one of each — so it may hold both: a blob's item beside a directory claim
 * the blob contradicts, which every write that does not aim at it carries
 * (core/profiles.h, the decode), or a directory claim beside a FILE item no blob
 * backs, residue a hand left. Each is found, replaced and removed by its own
 * kind, so a write of one kind never reaches the other's claim at its key; the
 * one write across kinds is a blob's where a directory claim stands, no blob at
 * or above its name, which takes that claim's place — a profile's next commit
 * spells it as its put rule (core/profiles.h profile_stage_t), for every writer.
 *
 * Two kinds of directory claim, one field between them. "tracked" says the profile
 * tracks the directory itself: a walk went into it, so the directory exists because
 * the profile says so, its attributes are the profile's to enforce and its contents
 * the profile's to scan. Without the field the item is only the attributes to
 * give the path if dotta has to create it — an ancestor claim, derived from the
 * chain above a tracked path, binding dotta's own creation of that path and nothing
 * else.
 *
 * Nothing infers a tracked claim away. It leaves the sheet where a verb takes
 * it — `remove` of the directory, or `update` committing the deletion of a
 * directory dotta saw — and no attribute of it reads back as intent: a walked
 * directory at the umask default, or claiming no mode at all, is kept for the
 * word alone.
 *
 * The polarity is the fail-safe one and the sparse one at once: an item that
 * loses the field — a hand edit, a tool that drops what it does not know — degrades
 * to the class dotta does less with, and the derived claims, one per rung of
 * every chain and so the numerous kind, carry no field at all.
 *
 * An ancestor claim exists because something beneath it does, so its mode is
 * all it has left to say. One that claims no mode says nothing the view could
 * not say alone — an unclaimed directory mode projects as DIR_MODE_DEFAULT, which
 * is what an unclaimed path would have got anyway. The prune weighs no attribute
 * at all: a derivation survives by what stands beneath it, a tracked claim by
 * the word itself (core/profiles.c profile_stage_prune_ancestors).
 *
 * The sheet is sparse and the view completes it: an unclaimed mode is resolved
 * into an answer at build, by the claim's floor (core/profiles.h
 * profile_claim_mode: the filemode floor for a blob, DIR_MODE_DEFAULT for a
 * directory claim), so no consumer downstream of the view ever meets a hole.
 *
 * Symlinks claim no mode: symlink(2) takes none, and though lchmod(2) exists on
 * macOS/BSD, the bits it sets govern nothing — non-portable and functionally
 * inert. A link's entry exists to carry ownership (lchown is real), so it is a
 * "file" item without a mode; a link with no ownership to track has no entry at
 * all.
 *
 * Out of scope, deliberately: timestamps (cross-machine noise by design); the
 * special mode bits — setuid, setgid, sticky — which a capture masks off (the
 * stat's & 0777), the parser refuses past 0777, and a deployment's chmod clears;
 * xattrs, ACLs, SELinux contexts, capabilities, chflags; hardlinks, devices,
 * FIFOs; symlink mode; umask-relative mode classes. Each would need its own
 * capture/deploy/divergence story; none is blocked by this schema.
 *
 * Two halves, read apart. The sheet — the item, the collection, the codec, the
 * load from a tree and the save to a stage — is a profile's own, read by one
 * module: the handle decodes it, and a profile's next commit edits a copy of it
 * (core/profiles.c profile_load_sheet, profile_walk, profile_stage_seed and the
 * stage's edits). The claim's attributes on this host — the directory default,
 * the unclaimed mode, ownership as this host's ids, and the captures that read
 * a claim off a look — are every layer's that places or prints a claim, each
 * name below listing its readers.
 *
 * Memory: a sheet is a container (include/runtime.h "Memory"). It lives in the
 * arena it was made in — a profile's, which keeps the sheet its tree holds, or
 * a profile's next commit's, which keeps the copy it edits — with every claim
 * it holds and every name a claim spells; nothing frees a sheet or a claim, and
 * the arena goes with its owner. A claim enters by value and the sheet copies
 * what it keeps, so an item a caller builds borrows its names for the call alone.
 *
 * JSON Schema (Version 6) — items sorted by key, then kind (a file's item before
 * a directory's at one key), fields present iff claimed:
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
 * was walked into, so the profile tracks it.
 */

#ifndef DOTTA_METADATA_H
#define DOTTA_METADATA_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

#include "sys/stage.h"

#define METADATA_VERSION 6
#define METADATA_DIR ".dotta"
#define METADATA_FILE_PATH METADATA_DIR "/metadata.json"

/**
 * Default mode for a directory claim that names none
 *
 * Mirrors the umask default any newly-mkdir'd directory gets on Linux/ macOS/BSD
 * (0755 = rwxr-xr-x) — the mode a chain of parents gets when nothing claims them.
 *
 * A value, never evidence: what a directory claim means is said by its kind and
 * its "tracked" word, never by the bits it carries, so nothing compares a mode
 * against this to read intent back out of it. Readers, each supplying the answer
 * where a claim named none: the claim's floor, which the view's rows take
 * (core/profiles.c profile_claim_mode), deploy's creation of a rung no claim
 * covers (core/deploy.c), and export's materialisation (cmds/export.c).
 */
#define DIR_MODE_DEFAULT 0755

/**
 * The mode a claim does not make
 *
 * Permission bits run 0000–0777 and 0000 is one of them: `chmod 000` is a real
 * mode a user can mean. Absence therefore needs a value outside the domain, not
 * the domain's floor. A sheet's item carries it, and so does the claim a profile
 * decodes from one (core/profiles.h profile_claim_t); it ends wherever a mode
 * is placed — the view's rows, export's copy and a capture's record take the
 * claim's floor (core/profiles.h profile_claim_mode: the filemode floor for a
 * blob, DIR_MODE_DEFAULT for a directory, and on a link, the one capture that
 * claims no mode, the record's don't-care) — so no row, record, entry or verdict
 * carries it. The header show prints and the capture lines add and update print
 * test it on the decoded claim, where a mode is claimed (cmds/show.c
 * show_print_blob, cmds/add.c add_print_capture, cmds/update.c update_profile).
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
 * is false — an ancestor claim's whole spelling. A mode of 0 is a claim, `chmod
 * 000`'s, so an item built by hand spells its absence. The two flags are one
 * kind's each, encrypted the cache of a blob's own bytes and tracked the claim
 * that the profile tracks a directory, and each is false for the other kind,
 * which the one way into a sheet holds its caller to (metadata_write_item).
 *
 * A value. One a caller builds borrows its names for the call it is handed to;
 * one a sheet lends is the sheet's, written once and never again, so it stands
 * as it was lent — its names with it — for the life of the arena the sheet stands
 * in, whatever is written or removed after it.
 *
 * Every field is read off the item metadata_find_item hands back; the sheet offers
 * no per-field reader, so a consumer that holds the item reads the field and
 * one that holds only a key looks the item up first. `encrypted` is cross-checked
 * nowhere: the content reader classifies the blob's own bytes and consults no
 * claim (infra/content.h content_get_from_blob_oid), so the stamp answers "was
 * it sealed when it was written" — a screen's question, or a schedule's. Readers,
 * each through the claim the profile decodes from it (core/profiles.c
 * profile_decode_blob): cmds/export.c export_entry_from_claim (which blobs phase
 * 1 reads), cmds/list.c list_files (the mark, and the framing taken off the size
 * beside it) and list_size_claim (the same framing, in the fold the rows' total
 * must agree with), cmds/show.c show_print_blob (the annotation) and, onto the
 * view's rows (core/manifest.h manifest_row_t.encrypted), cmds/export.c
 * export_entry_from_row, core/workspace.c workspace_analyze_file and cmds/key.c
 * key_status.
 *
 * So the link rule is the decode's alone, spelled in the arm where it already
 * branches on the type (core/profiles.c profile_decode_blob): there is no per-field
 * reader here to hold it, and no reader of a profile's stamp reads the item.
 */
typedef struct {
    path_kind_t kind;       /* FILE: the tree names the path. DIRECTORY: the item is the claim. */
    const char *key;        /* Storage path — the join key for every consumer */
    mode_t mode;            /* Claimed permission bits, or MODE_UNCLAIMED */
    const char *owner;      /* Claimed owner, or NULL */
    const char *group;      /* Claimed group, or NULL */
    bool encrypted;         /* The blob's ciphertext stamp (false for DIRECTORY) */
    bool tracked;           /* The profile tracks the directory (false for FILE) */
} metadata_item_t;

/**
 * The sheet (opaque): each kind's claims apart, in key order
 *
 * Key order is the document's (metadata_to_json): byte order on the key, whatever
 * order the claims were written or a hand spelled them in. The order is the one
 * representation: a claim is found, written and removed by its key's place in
 * it, and the claims beneath a name are one slice of it. A container (the module
 * header): it lives in the arena it was made in, with every claim and name it
 * holds, and nothing frees it.
 */
typedef struct metadata metadata_t;

/**
 * One kind's claims, lent: the sheet's own, in key order
 *
 * The slice metadata_items and metadata_items_beneath answer, the tree's shape
 * for a lent collection (core/manifest.h manifest_rows_t). It survives every
 * edit of the other kind, each kind's claims standing apart, and none of its
 * own: a write or a removal of its kind moves the entries, though never a claim
 * they point at.
 */
typedef struct {
    const metadata_item_t *const *entries;
    size_t count;
} metadata_items_t;

/**
 * An empty sheet, in `arena`
 *
 * Readers: the loader, for a tree that holds no sheet (metadata_load_from_tree),
 * the parser (metadata_from_json) and the copy (metadata_clone).
 *
 * @param arena The arena the sheet lives in, and every claim written into it
 *              (must not be NULL)
 * @return The sheet; never NULL
 */
metadata_t *metadata_create(arena_t *arena);

/**
 * A copy of the sheet, in `arena`: every claim, its names the copy's own
 *
 * For the reader that edits and must leave the source as it read it: a profile's
 * next commit edits a copy of the sheet its base decoded (core/profiles.h
 * profile_stage_open, profile_stage_orphan), so the claims the base lends stand
 * whatever the commit does, and the commit saves the copy only where its claims
 * are no longer the base's (metadata_same). The same sheet a second parse of
 * the bytes would give, at a fraction of its cost.
 *
 * Reader: core/profiles.c profile_stage_seed, both openers' one body.
 *
 * @param arena The arena the copy lives in (must not be NULL)
 * @param metadata The sheet to copy (must not be NULL)
 * @return The copy; never NULL
 */
metadata_t *metadata_clone(arena_t *arena, const metadata_t *metadata);

/**
 * Write a claim: the one way a claim enters a sheet
 *
 * Of the item's own kind: the claim of that kind at its key is made over — or
 * left as it stands, where it says the same — and the other kind's at the key
 * stays as it stands; otherwise the claim takes its key's place in its kind's
 * order, the claims past it moved up one. The sheet copies what it keeps into
 * its arena, so the item and its names are the caller's, borrowed for the call
 * alone.
 *
 * An item exists iff it claims something (the module header): a file's item that
 * claims nothing — no mode, no owner, no group, no stamp: a link the invoker
 * owns, a restore of a claim that says nothing — is no claim, and its write retires
 * the file's item standing at its key. A directory's item is the claim itself,
 * and stands whatever it carries.
 *
 * The item's contract is held here, at the one way in: a mode is claimed bits
 * or MODE_UNCLAIMED, and each flag is its own kind's — a caller that breaks either
 * is a caller's bug, and dies. A document's mode past 0777 is the parser's refusal,
 * and the flag a hand wrote onto the other kind is read past there
 * (metadata_from_json).
 *
 * Readers: the parser and the copy (metadata_from_json, metadata_clone); and a
 * profile's next commit, its every edit that writes a claim (core/profiles.c
 * profile_stage_admit, profile_stage_capture_file, profile_stage_capture_directory,
 * profile_stage_capture_rung, profile_stage_restore_ancestors and
 * profile_stage_restore_file), the rung counting what it moved.
 *
 * @param metadata The sheet (must not be NULL)
 * @param item The claim (must not be NULL; its key must not be NULL)
 * @return true where the sheet moved: a claim new to its key, one made over, or
 *         one retired
 */
bool metadata_write_item(metadata_t *metadata, const metadata_item_t *item);

/**
 * The item of `kind` at `key`, or NULL
 *
 * One kind's: the other kind's item at the key, where one stands, is another
 * claim and never this answer (the module header). A key the sheet does not hold
 * under that kind is the answer, not a failure — NULL. Found by its place in
 * its kind's order: one comparison past the last claim, and a search otherwise.
 *
 * @param metadata The sheet (NULL returns NULL)
 * @param kind The claim's kind
 * @param key The storage path (NULL returns NULL)
 * @return The claim, lent for the life of the sheet's arena, no write editing
 *         it; or NULL where none is held
 */
const metadata_item_t *metadata_find_item(
    const metadata_t *metadata,
    path_kind_t kind,
    const char *key
);

/**
 * Two sheets that say the same thing
 *
 * The same claims of each kind, each the same in every field, absence included:
 * each kind stands in key order, so two sheets holding the same claims hold them
 * at the same places, and serialize alike (metadata_to_json), and a sheet whose
 * claims differ from another's has one to write. The sheet carries what the tree
 * cannot — the mode below the owner-execute bit, and ownership — so a comparison
 * of the trees alone cannot answer this.
 *
 * Readers: a profile's next commit, which compares the sheet it carries with
 * the one it opened, as sys/stage compares the trees (sys/stage.h stage_changed,
 * stage_commit) — its change test, and its save's gate, so a sheet no claim of
 * which moved keeps the bytes it has, a hand's spelling included (core/profiles.c
 * profile_stage_changed, profile_stage_commit).
 *
 * @param a A sheet (must not be NULL)
 * @param b Another (must not be NULL)
 * @return true where the two hold the same claims
 */
bool metadata_same(const metadata_t *a, const metadata_t *b);

/**
 * Remove the item of `kind` at `key`
 *
 * One kind's: the other kind's item at the key, where one stands, stays as it
 * stands. A key the sheet does not hold under that kind changes nothing and is
 * not a failure — the answer is false. One search finds the key's place in its
 * kind's order, and the gap a removal leaves is closed, every claim past it moved
 * down one. Nothing is freed: a claim lent stands for whoever holds it.
 *
 * @param metadata The sheet (NULL returns false)
 * @param kind The claim's kind
 * @param key The storage path (NULL returns false)
 * @return true if an item was removed
 */
bool metadata_remove_item(
    metadata_t *metadata,
    path_kind_t kind,
    const char *key
);

/**
 * One kind's items, in key order
 *
 * The sheet's own entries, lent (metadata_items_t): no allocation, no copy. A
 * sheet that is not there holds none — a tolerant read past a sheet that will
 * not load has none to lend (core/profiles.c profile_walk) — so a NULL sheet
 * answers the empty slice, as a NULL view answers its rows (core/manifest.h
 * manifest_rows).
 *
 * @param metadata The sheet (NULL answers the empty slice)
 * @param kind Which kind's items
 * @return The slice, borrowed: good until a write or a removal of that kind
 */
metadata_items_t metadata_items(const metadata_t *metadata, path_kind_t kind);

/**
 * One kind's items strictly beneath `key`, lent: one slice of the kind's key order
 *
 * The claims beneath a name are one block of the order — every key the name and
 * a separator begin, and none other: "x.bak" sorts before "x/y" and "x0" after,
 * '/' being neither the least byte nor the greatest — so two searches find them
 * and nothing is copied. Strictly beneath, at a component boundary: the claim
 * at `key` is not among them, nor a sibling whose name merely starts the same
 * way. In key order, so the first is the byte-least. A name with nothing beneath
 * it answers the empty slice, and so does a NULL sheet, as metadata_items answers.
 *
 * Readers: a profile's next commit — the admission's sheet half, of the name a
 * blob would stand at (core/profiles.c profile_stage_refuse_beneath), and the
 * prune's, of a derivation's key (profile_stage_tracked_beneath).
 *
 * @param metadata The sheet (NULL answers the empty slice)
 * @param kind Which kind's items
 * @param key The name (NULL answers the empty slice)
 * @return The slice, borrowed: good until a write or a removal of that kind
 */
metadata_items_t metadata_items_beneath(
    const metadata_t *metadata,
    path_kind_t kind,
    const char *key
);

/**
 * Capture a path's claim from stat data (regular file or symlink)
 *
 * The claim off the look, whatever it claims. A regular file always claims its
 * mode (0000 included); a symlink claims none — symlink(2) takes none — so its
 * item carries ownership alone, and where there is no ownership to claim either
 * the item claims nothing: a link the invoker owns, which absence already says.
 * Written, such an item is no item, and retires whatever stale one stands at
 * the key (metadata_write_item) — the sheet's existence rule, kept where a claim
 * enters it.
 *
 * Ownership capture (user/group): the ownership half is authored where absence,
 * which every machine reads as its own invoker (metadata_ownership), would misstate
 * the owner — an owner that is not the capturing invoker, under every label,
 * and the invoker's own where the invoker is root outside home/ (the module
 * header). No privilege enters: an lstat needs none, so a user captures root's
 * file as root's, and root captures its own. Both names or neither: where ownership
 * is captured at all, a UID or GID this host cannot name fails the capture
 * (ERR_NOT_FOUND). Half a claim would read downstream as a claim deliberately
 * made narrow, its other half the invoker or whatever the creation gave.
 *
 * For a symlink, pass lstat data: the link's own uid/gid, not the target's.
 *
 * The seal is the caller's, as the directory sibling's class is: a stat cannot
 * say what the bytes an entry holds classify as, so `encrypted` is carried through
 * to the item unread. Its producer is the capture that made those bytes, which
 * is the authority on them (infra/content.h, the capture's write-time invariant).
 *
 * `st` is a regular file's or a symlink's, and nothing else — the kind is the
 * caller's to have established, and both producers take it from a capture that
 * refuses every other occupant. A stat of any other kind is a contract breach
 * and reads as one, not as a refusal with a remedy: no user input reaches here.
 *
 * Reader: a profile's next commit, at the one door every capture of a file meets
 * its name through (core/profiles.c profile_stage_capture_file).
 *
 * @param storage_path Path in profile (must not be NULL): the item's key, borrowed
 *                     by it
 * @param st File stat data (must not be NULL; a regular file's or a symlink's)
 * @param encrypted Whether the entry's bytes are sealed (the caller's word)
 * @param arena The arena the item's owner and group are named in (must not be NULL)
 * @param out The item (must not be NULL; written on success alone)
 * @return Error or NULL on success
 */
error_t metadata_capture_file(
    const char *storage_path,
    const struct stat *st,
    bool encrypted,
    arena_t *arena,
    metadata_item_t *out
);

/**
 * Capture a directory's claim from stat data
 *
 * Creates a directory metadata item from stat data. Follows the same ownership
 * rules as file capture — the unnameable UID among them — while the mode is always
 * claimed from the stat. The class is the caller's: a stat cannot say whether a
 * walk entered the directory or only passed above it, so `tracked` is carried
 * through to the item unread.
 *
 * The two callers that capture a claim answer a failure here differently, and
 * the difference is what the claim is for, each through a profile's next commit
 * (core/profiles.h profile_stage_capture_directory). **add refuses**: a directory
 * it listed is the name its walk composed beneath, so a claim that does not land
 * leaves files committed under a name nothing authors — and the listing, which
 * the command reads as a promise of its own commit, would be a wish (cmds/add.c
 * cmd_add). **update warns and carries on**: a claim it could not refresh keeps
 * standing, nothing was named from this run, and the sheet goes on saying what
 * it said (cmds/update.c update_profile). Either way the loss is the mode with
 * the ownership, so update's warning is one the user reads at any verbosity.
 *
 * Ownership capture (user/group): the file capture's rule, above. An owner or a
 * group this host has no name for is ERR_NOT_FOUND — the lookup's absence or
 * its failure alike, the claim unmakeable either way — and a derivation reads
 * it (core/profiles.c profile_stage_capture_rung): its rung keeps the claim it
 * had, as it does for a path it could not look at. That is the one refusal.
 *
 * `st` is a directory's, and nothing else — the kind is the caller's to have
 * established, and every caller holds its look to one first: a profile's next
 * commit's directory capture, whose writers each lstat and hold to S_ISDIR —
 * add's directory loop and update's (cmds/add.c cmd_add, cmds/update.c
 * update_profile) — and the climb's rung, a look that found a directory
 * (core/profiles.c profile_stage_capture_rung). A stat of any other kind is a
 * contract breach and reads as one, not as a refusal with a remedy.
 *
 * @param storage_path Storage path in profile (must not be NULL, e.g.,
 *                     "home/.config/nvim"): the item's key, borrowed by it
 * @param st Directory stat data (must not be NULL; a directory's)
 * @param tracked The profile tracks the directory itself
 * @param arena The arena the item's owner and group are named in (must not be NULL)
 * @param out The item (must not be NULL; written on success alone)
 * @return Error or NULL on success
 */
error_t metadata_capture_directory(
    const char *storage_path,
    const struct stat *st,
    bool tracked,
    arena_t *arena,
    metadata_item_t *out
);

/**
 * Load metadata from a Git tree
 *
 * Loads metadata.json from a specific Git tree — a branch head or a historical
 * commit's tree alike — through the repository the tree was read from, which a
 * tree knows (lib/libgit2/src/libgit2/object.c git_object_owner), the blob's
 * bytes lent to the parse with their length (sys/gitops.h gitops_blob_view_open).
 *
 * A tree without a sheet holds an empty sheet: no .dotta, or a .dotta directory
 * without the file. The absent entry is a settled answer (nothing claimed), not
 * a failure to look, and this loader is its one producer: a reader receives a
 * sheet on every success and never folds a not-found into one of its own. Every
 * error is real — a lookup that failed, a file at .dotta, which Git's lookup
 * reads as nothing there (lib/libgit2/src/libgit2/tree.c git_tree_entry_bypath),
 * an unreadable blob, a document the parser refuses (a version mismatch, a
 * duplicated claim) — and a reader that folds one into an empty sheet is reading
 * a corrupt sheet as "no claims".
 *
 * The view holds to that without exception: the profile's walk reads the sheet
 * of the tree it walks, strictly for the view, and one that will not load fails
 * the build (core/profiles.h profile_walk, core/manifest.h). So do the profile's
 * counts, which are where a listing's question of what a profile holds ends
 * (core/profiles.h profile_counts).
 *
 * The readers that deliberately do otherwise are counted here, and each is that
 * command's decision about its own output, never a second answer from here:
 * export's materialisation floor through the profile's tolerant walk and point
 * questions (core/profiles.h profile_walk and profile_find, from cmds/export.c
 * export_collect_profile and export_collect_storage; the bytes come out of a
 * damaged profile, warned once by cmd_export, and a copy left with nothing in
 * it is refused in the loader's words), the header show prints over a blob it
 * can read anyway — the mode, the ownership and the annotation alike, warned —
 * through the profile's tolerant read (core/profiles.h profile_find, from
 * cmds/show.c show_file), the file listing's verbose marks through the profile's
 * tolerant walk (core/profiles.h profile_walk, from cmds/list.c list_files, warned;
 * the listing is the tree's and stands, the marks are the sheet's and do not),
 * the orphan authority's third answer through the profile's strict read
 * (core/profiles.h profile_find, from core/workspace.c workspace_orphan_authority,
 * which folds the failure to UNVERIFIED and never to "no claims"), the completion's
 * offer through the profile's strict walk (core/profiles.h profile_walk, from
 * cmds/completion.c completion_directories, which drops the failure as every
 * completion source drops its own: cmds/completion.h), remove's own directory
 * offer the same way through its strict walk and profile_contradicted
 * (core/profiles.h, from cmds/remove.c remove_complete), and the claims a profile's
 * deletion takes, whose paths its hooks are handed, through the profile's tolerant
 * walk and profile_contradicted (core/profiles.h, from cmds/remove.c
 * remove_profile, through remove_list_claims; the profile goes all the same,
 * its hooks handed the tree's files alone, warned before the preview). A further
 * reader would have to argue for one.
 *
 * @param tree Git tree to load from (must not be NULL)
 * @param profile The profile whose sheet this is, named over every failure —
 *                its callers name it nowhere (must not be NULL)
 * @param arena The arena the sheet lives in (must not be NULL); a load that fails
 *              leaves what it parsed there, unreachable, until the arena goes
 * @param out The sheet (must not be NULL); untouched on failure, so the NULL a
 *            caller passed is still no sheet (core/profiles.c profile_load_sheet's
 *            handle)
 * @return Error or NULL on success
 */
error_t metadata_load_from_tree(
    const git_tree *tree,
    const char *profile,
    arena_t *arena,
    metadata_t **out
);

/**
 * Convert metadata to JSON string
 *
 * Serializes metadata to JSON: items in key order, a file's item before a
 * directory's at one key (a write-side norm buying byte-determinism across
 * machines; the parser accepts any order), fields present iff claimed — an
 * unclaimed mode, a NULL owner/group and a false encrypted have no line to print.
 *
 * @param metadata Metadata to serialize (must not be NULL)
 * @return The JSON document (the caller frees it with buffer_deinit)
 */
buffer_t metadata_to_json(const metadata_t *metadata);

/**
 * Parse metadata from JSON string
 *
 * Parses metadata from JSON content, `size` bytes of it, which need no terminator.
 * Rejects version mismatches with clear error message (no migration code), and
 * a claim the document makes twice — a second item of one kind at a key, refused
 * by its kind; a file's item and a directory's at one key are two claims, both
 * read. A file's item that claims nothing is no claim (the module header): read
 * past, it is a second of none. A document in any order parses, each kind read
 * into key order (metadata_write_item).
 *
 * @param json The document's bytes (must not be NULL)
 * @param size Their count
 * @param arena The arena the sheet lives in (must not be NULL); a refusal leaves
 *              what it parsed there, unreachable, until the arena goes
 * @param out The sheet (must not be NULL); untouched on failure, so
 *            metadata_load_from_tree hands the parse its own out
 * @return Error or NULL on success
 */
error_t metadata_from_json(
    const char *json,
    size_t size,
    arena_t *arena,
    metadata_t **out
);

/**
 * Save metadata to a stage
 *
 * Puts the sheet — .dotta/metadata.json, serialized by metadata_to_json — on
 * the stage as a regular blob; the caller's commit carries it. The one writer
 * of the sheet: a profile's next commit's (core/profiles.c profile_stage_commit),
 * every claim writer's. A sheet this serializer wrote, loaded and saved unchanged,
 * puts the blob the tree already holds (the serializer's byte-determinism). A
 * hand-written one the parser accepts — other whitespace, another item order,
 * inert fields — is normalized by the save and moves its blob; nothing here
 * promises otherwise, so the caller saves only a sheet whose claims moved
 * (metadata_same), and a commit that moved none keeps a hand's spelling.
 *
 * @param stage The stage the sheet goes on (must not be NULL)
 * @param metadata Metadata to save (must not be NULL)
 * @return Error or NULL on success
 */
error_t metadata_save_to_stage(
    stage_t *stage,
    const metadata_t *metadata
);

/**
 * Whether a claim's names are this host's (metadata_ownership)
 *
 * The half that did not resolve, where one did not — the answer the landing words
 * and the compare reads as "unresolvable", no sentence minted on the way: the
 * compare asks it of every row on every load.
 */
typedef enum {
    METADATA_OWNERSHIP_RESOLVED = 0,   /* both halves are this host's ids */
    METADATA_OWNERSHIP_NO_SUCH_USER,   /* the owner names a user this host cannot resolve */
    METADATA_OWNERSHIP_NO_SUCH_GROUP   /* the owner resolved; the group names one it cannot */
} metadata_ownership_t;

/**
 * The sheet's word on a path's ownership, as this host's ids
 *
 * Two names, two absences, one rule each — and no label in either, and no
 * privilege:
 *   - an absent owner is the invoker (sys/identity), whoever runs dotta where
 *     the sheet is read: a capture names every owner absence would misstate (the
 *     module header), so absence is the invoker's own on every machine, and a
 *     path it covers converges to the invoker
 *   - an absent group is no change, (gid_t) -1, chown's own sentinel: no capture
 *     authors a group alone, a named owner brings its group with it, and a group
 *     is as often a directory's inheritance as an intent — what a creation gives,
 *     it keeps
 * A named half is that name on this host, or the half this host cannot resolve
 * with the outs untouched: a claim this host cannot spell is never guessed at,
 * and never answered by halves.
 *
 * "Ownership" here is the file's — its uid and gid, the axis status prints as
 * [ownership]. The record's ownership (core/state.h: an ownership event, dotta
 * putting a path where it stands) is a different word wearing the same spelling.
 *
 * The one producer of the rule, asked whole by each reader, so what status accuses
 * and what apply sets cannot drift and an account this host knows by two names
 * satisfies both: the compare (core/workspace.c workspace_compare_ownership,
 * the pair against a look, id to id), the landing (core/deploy.c
 * resolve_deployment_ownership, the pair a write applies) and a parent no row
 * claims (core/deploy.c create_ancestor, the pair of no claim at all). Whether
 * the pair can be applied is the applier's to ask (sys/identity.h
 * identity_may_chown). A reader not on this list is a bug.
 *
 * @param owner The claimed owner, or NULL
 * @param group The claimed group, or NULL
 * @param out_uid The owner: the claim's, or the invoker's (must not be NULL)
 * @param out_gid The group: the claim's, or (gid_t) -1 (must not be NULL)
 * @return RESOLVED with both outs written, or the half this host cannot resolve
 *         — the owner asked first — with neither
 */
metadata_ownership_t metadata_ownership(
    const char *owner,
    const char *group,
    uid_t *out_uid,
    gid_t *out_gid
);

#endif /* DOTTA_METADATA_H */
