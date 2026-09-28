/**
 * metadata.c - Unified metadata system implementation
 */

#include "core/metadata.h"

#include <cJSON.h>
#include <git2.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/heap.h"
#include "base/string.h"
#include "core/state.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/identity.h"

#define INITIAL_CAPACITY 16

/**
 * Unified metadata collection
 *
 * A spine of pointers to items the collection owns, and a key index over them.
 * An item is stable from the moment it is created — only the spine is ever
 * reallocated — so the index stores item pointers directly and metadata_items
 * hands the spine out as the public slice. The index borrows each item's own
 * key (hashmap_borrow), which is why metadata_add_item's update arm must adopt
 * the standing key before it overwrites the slot: the key-adoption dance is the
 * borrow's cost.
 *
 * The sheet is a handle whose lifetime is its own, so it owns an arena: the struct,
 * the spine and the index live and go with it. The items are the heap's, each
 * freed by metadata_free before the arena goes.
 *
 * The schema version is the document's, not the collection's: metadata_to_json
 * writes METADATA_VERSION and metadata_from_json refuses anything else, so there
 * is nothing here for a version field to say.
 */
struct metadata {
    arena_t *arena;             /* The sheet's own: the struct, the spine, the index */
    metadata_item_t **items;    /* Spine of stable items, in insertion order */
    size_t count;               /* Items held */
    size_t capacity;            /* Spine slots allocated */
    hashmap_t *index;           /* key -> item*, borrowing the item's own key */
};

/**
 * Create empty metadata collection
 */
metadata_t *metadata_create_empty(void) {
    /* The sheet's own arena, and the sheet in it: the spine is made there — room
     * at once, so metadata_items answers an array for an empty sheet too — and
     * so is the index, for O(1) lookups */
    arena_t *arena = arena_create(0);
    metadata_t *metadata = arena_calloc(arena, 1, sizeof(*metadata));
    metadata->arena = arena;
    metadata->items = arena_grow(
        arena, NULL, &metadata->capacity, INITIAL_CAPACITY, sizeof(*metadata->items)
    );
    metadata->index = hashmap_borrow(arena, INITIAL_CAPACITY);

    return metadata;
}

/**
 * Free metadata item
 */
void metadata_item_free(metadata_item_t *item) {
    if (!item) return;

    free(item->key);
    free(item->owner);
    free(item->group);

    free(item);
}

/**
 * Free metadata structure
 *
 * Frees every item it holds, then the sheet's arena — the structure, the spine
 * and the index with it.
 */
void metadata_free(metadata_t *metadata) {
    if (!metadata) return;

    /* Free all items (files, directories, and symlinks). The index borrows their
     * keys, and nothing reads it again before its arena goes below. */
    for (size_t i = 0; i < metadata->count; i++) {
        metadata_item_free(metadata->items[i]);
    }

    arena_free(metadata->arena);
}

/**
 * Create file metadata item
 */
metadata_item_t *metadata_item_create_file(
    const char *storage_path,
    mode_t mode,
    bool encrypted
) {
    CHECK_NULL(storage_path);

    /* A mode is claimed bits or absence — nothing in between */
    CHECK_ARG(mode == MODE_UNCLAIMED || mode <= 0777, "mode past 0777");

    metadata_item_t *item = heap_calloc(1, sizeof(metadata_item_t));

    item->kind = PATH_KIND_FILE;
    item->key = heap_strdup(storage_path);
    item->mode = mode;
    item->owner = NULL;    /* Optional, set by caller if needed */
    item->group = NULL;    /* Optional, set by caller if needed */
    item->encrypted = encrypted;
    item->tracked = false; /* A file is no directory to track */

    return item;
}

/**
 * Create directory metadata item
 */
metadata_item_t *metadata_item_create_directory(
    const char *storage_path,
    mode_t mode,
    bool tracked
) {
    CHECK_NULL(storage_path);

    /* A mode is claimed bits or absence — nothing in between */
    CHECK_ARG(mode == MODE_UNCLAIMED || mode <= 0777, "mode past 0777");

    metadata_item_t *item = heap_calloc(1, sizeof(metadata_item_t));

    item->kind = PATH_KIND_DIRECTORY;
    item->key = heap_strdup(storage_path);
    item->mode = mode;
    item->owner = NULL;      /* Optional, set by caller if needed */
    item->group = NULL;      /* Optional, set by caller if needed */
    item->encrypted = false; /* A directory has no blob to stamp */
    item->tracked = tracked;

    return item;
}

/**
 * Clone a claim under the name it is being written to
 */
metadata_item_t *metadata_item_clone(
    const metadata_item_t *source,
    const char *storage_path
) {
    CHECK_NULL(source);
    CHECK_NULL(storage_path);

    metadata_item_t *item = heap_calloc(1, sizeof(metadata_item_t));

    /* Everything that is not a pointer copies wholesale — kind, mode and the
     * two flags, so a field added later needs no line here. The three strings
     * are then owned here: the key the caller named, and the two ownership names
     * the source carries, an absent one copied as absent. */
    *item = *source;
    item->key = heap_strdup(storage_path);
    item->owner = heap_strdup(source->owner);
    item->group = heap_strdup(source->group);

    return item;
}

/**
 * The claim an item makes, as the record keeps it
 *
 * The mode as the item claims it, 0 where it claims none (a link's); the names
 * copied into the arena.
 */
void metadata_item_claim(
    const metadata_item_t *item,
    arena_t *arena,
    state_record_t *record
) {
    CHECK_NULL(arena);
    CHECK_NULL(record);

    /* The empty claim first, what no item says: a link that claims nothing */
    record->mode = 0;
    record->owner = NULL;
    record->group = NULL;
    if (!item) return;

    if (item->mode != MODE_UNCLAIMED) record->mode = item->mode;
    record->owner = arena_strdup(arena, item->owner);
    record->group = arena_strdup(arena, item->group);
}

/**
 * Add or update metadata item, transferring ownership
 *
 * Works for every kind. If an item with the same key exists it is replaced in
 * place; otherwise the item is appended.
 *
 * The collection stores pointers, so an item handed to it is taken rather than
 * copied: it keeps its place in memory, the collection keeps the pointer, and
 * the caller's handle is cleared.
 *
 * A mode arrives already validated: the two factories are the only construction
 * paths, metadata_item_clone copies an item one of them built, and no caller
 * mutates the field afterwards. Re-checking it here would be a second boundary
 * for a fact this function does not own.
 */
void metadata_add_item(
    metadata_t *metadata,
    metadata_item_t **item
) {
    CHECK_NULL(metadata);
    CHECK_NULL(item);
    CHECK_NULL(*item);
    CHECK_NULL((*item)->key);

    metadata_item_t *incoming = *item;

    metadata_item_t *existing = hashmap_get(metadata->index, incoming->key);
    if (existing) {
        /* UPDATE EXISTING ITEM
         *
         * The slot keeps the key it was indexed under — the index borrows that
         * pointer, so it must outlive the overwrite — and the incoming key, equal
         * to it by construction, is dropped and its place taken before the copy,
         * so nothing reads a pointer that has been freed. Everything else the
         * slot held is freed and replaced wholesale, the kind and every field
         * only one kind reads included, so a kind change leaves no residue of
         * the old one. */
        free(incoming->key);
        incoming->key = existing->key;

        free(existing->owner);
        free(existing->group);

        *existing = *incoming;
        free(incoming);
        *item = NULL;

        return;
    }

    /* APPEND NEW ITEM. Room for it grows in the sheet's arena; only the spine
     * moves — the items it points at stay where they were created — so the index
     * needs no maintenance here. */
    metadata->items = arena_grow(
        metadata->arena, metadata->items, &metadata->capacity, metadata->count + 1,
        sizeof(*metadata->items)
    );

    hashmap_set(metadata->index, incoming->key, incoming);

    metadata->items[metadata->count++] = incoming;
    *item = NULL;
}

/**
 * Look up an item by key
 *
 * Works for every kind. A key the collection does not hold is the answer, not a
 * failure.
 */
const metadata_item_t *metadata_lookup(
    const metadata_t *metadata,
    const char *key
) {
    if (!metadata || !key) return NULL;

    return hashmap_get(metadata->index, key);
}

const metadata_item_t *metadata_directory_beneath(
    const metadata_t *metadata,
    const char *storage_path
) {
    if (!metadata || !storage_path) return NULL;

    size_t count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &count);
    const size_t len = strlen(storage_path);

    for (size_t i = 0; i < count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY) continue;
        if (str_path_beneath(items[i]->key, storage_path, len)) {
            return items[i];
        }
    }

    return NULL;
}

/**
 * Two claims that say the same thing
 *
 * Field by field, absence included. Two claims of the same key can differ in
 * what only the sheet carries — the mode's lower bits, an owner, a group — so
 * the tree's entry cannot stand in for this comparison.
 */
bool metadata_same_claim(const metadata_item_t *a, const metadata_item_t *b) {
    if (a == b) {
        return true;
    }
    if (!a || !b) {
        return false;
    }

    return a->kind == b->kind && a->mode == b->mode &&
           a->encrypted == b->encrypted && a->tracked == b->tracked &&
           str_equal(a->key, b->key) && str_equal(a->owner, b->owner) &&
           str_equal(a->group, b->group);
}

/**
 * Remove metadata item
 *
 * Unified removal function that replaces:
 * - metadata_remove_entry() (files)
 * - metadata_remove_tracked_directory() (directories)
 *
 * Works for every kind. A key the collection does not hold changes nothing.
 */
bool metadata_remove_item(
    metadata_t *metadata,
    const char *key
) {
    if (!metadata || !key) return false;

    /* The index answers identity. A key the collection does not hold is answered
     * here and costs one probe — the walk below is for position, and there is
     * no position to find. */
    metadata_item_t *item = hashmap_get(metadata->index, key);
    if (!item) return false;

    /* Only the spine carries position, so only a walk gives it. What the index
     * bought is the comparison: the item is already named, so this reads the
     * spine's own pointers rather than chasing each item's key into a strcmp.
     * The two agree by construction — the add publishes to both or neither and
     * its update arm mutates the standing item in place, so the value the index
     * holds is the pointer some spine slot holds. */
    for (size_t i = 0; i < metadata->count; i++) {
        if (metadata->items[i] != item) continue;

        /* Unpublish before freeing: the index borrows this item's key, so the
         * removal's own strcmp reads it. */
        hashmap_remove(metadata->index, item->key, NULL);
        metadata_item_free(item);
        metadata->count--;

        /* Close the gap. Only the spine shifts — every surviving item stays where
         * it was, so every index entry stays valid. */
        if (i < metadata->count) {
            memmove(
                &metadata->items[i], &metadata->items[i + 1],
                (metadata->count - i) * sizeof(*metadata->items)
            );
        }

        return true;
    }

    /* Unreachable while the spine and the index agree. Reached, it would mean
     * the index named an item no slot holds — nothing above changed anything,
     * so the honest answer is that nothing was removed. */
    return false;
}

/**
 * Does a tracked claim stand beneath this key?
 *
 * The sheet's half of the tracked set. An empty directory is named by its own
 * claim and by nothing else, so a tracked claim is the one thing beneath a
 * derivation that no index can name. A derivation anchors nothing — it survives
 * by being anchored itself, and letting one anchor another would hold a doomed
 * chain alive a rung per command. The word that decides the prune's subject decides
 * this too, so the two readings cannot drift: they are one field.
 *
 * Strictly beneath, at a component boundary: a claim AT the key is the key, and
 * one above it is the ancestry every path has.
 *
 * @param items The sheet's items, borrowed — the caller's own snapshot (must
 *              not be NULL)
 * @param count How many it holds (zero answers false)
 * @param key The derivation's key (must not be NULL)
 * @return true iff a tracked directory claim stands strictly beneath it
 */
static bool tracked_beneath(
    const metadata_item_t *const *items, size_t count, const char *key
) {
    const size_t len = strlen(key);

    for (size_t i = 0; i < count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY || !items[i]->tracked) continue;
        if (str_path_beneath(items[i]->key, key, len)) return true;
    }

    return false;
}

/**
 * Prune the derivations nothing stands beneath
 *
 * Two-pass collect-then-prune: metadata_remove_item frees the item it removes
 * and shifts the spine behind it, so the pass that decides cannot also be the
 * pass that acts. string_array_push copies each key into the array's own arena,
 * so the prune pass operates on strings the removals cannot free.
 */
error_t *metadata_prune_ancestors(
    metadata_t *metadata, git_index *index, string_array_t *pruned
) {
    CHECK_NULL(metadata);
    CHECK_NULL(index);
    CHECK_NULL(pruned);

    /* The keys this call appends start here; the removal pass below walks only
     * them. */
    const size_t first = pruned->count;

    size_t item_count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &item_count);

    for (size_t d = 0; d < item_count; d++) {
        const metadata_item_t *dir = items[d];

        /* The subject: a derivation, which exists because something beneath it
         * does. A tracked claim is the walk's own word that the profile tracks
         * the directory — it stands with nothing beneath it and at any attributes,
         * and it leaves the sheet where a verb takes it, never by inference
         * (metadata.h). The two fields capture_ancestor reads to leave a standing
         * claim alone, asked here for the same reason. */
        if (dir->kind != PATH_KIND_DIRECTORY || dir->tracked) continue;

        /* Half of what stands beneath: any path under the directory that a tree
         * can hold. Metadata items are not the universe there — a symlink tracked
         * without elevation carries no item, yet still anchors its parent — so
         * the index is the authority. It is sorted, so one prefix probe answers;
         * a failed look must not prune. */
        char *prefix = heap_str_format("%s/", dir->key);
        size_t position;
        int rc = git_index_find_prefix(&position, index, prefix);
        free(prefix);
        if (rc == 0) continue;
        if (rc != GIT_ENOTFOUND) return error_from_git(rc);

        /* And the other half: the one path a tree cannot hold. */
        if (tracked_beneath(items, item_count, dir->key)) continue;

        string_array_push(pruned, dir->key);
    }

    /* Every key here was read off an item the walk above just saw, so each names
     * something that is there to remove. */
    for (size_t i = first; i < pruned->count; i++) {
        metadata_remove_item(metadata, pruned->entries[i]);
    }

    return NULL;
}

/**
 * Every item the collection holds, in insertion order
 *
 * Returns the spine itself (borrowed reference). Zero-cost operation - no
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
) {
    /* Handle invalid inputs */
    if (!metadata || !count) {
        if (count) {
            *count = 0;
        }
        return NULL;
    }

    *count = metadata->count;

    /* Return the spine (borrowed reference) Note: it is always allocated (even
     * for an empty collection), so this is safe even when count=0 */
    return (const metadata_item_t *const *) metadata->items;
}

/**
 * The ownership half of a capture: the stat's owner and group by name, wherever
 * absence would say someone else
 *
 * Absence is the invoker on every machine (metadata_ownership), so it says the
 * owner exactly where the capturing invoker owns the path and the next machine's
 * invoker would own it too — everywhere but one place, root's own outside home/.
 * Every other owner is named, under every label, so the claim a capture authors
 * resolves, on the host it was captured on, to the node it was captured from.
 * The group rides with the owner: the invoker's own file under another group is
 * the invoker's to the capture, a group being as often a directory's inheritance
 * (macOS's /tmp is wheel's) as an intent.
 *
 * Both names or neither. A capture states what it saw, and half of what it saw
 * is a different statement: the read boundary takes a lone "group" as a narrow
 * claim deliberately made, which the owner's resolution then fills with the
 * invoker, so a name that merely failed to resolve would become indistinguishable
 * from a claim the profile meant to make narrow. The claim this host cannot spell
 * is an error here, where the user is at the terminal and the path is still theirs
 * to fix, rather than a silence for deploy to act on a year later on another
 * machine.
 *
 * On failure item fields may be partially set — the caller frees the item on
 * error either way, and the sheet only ever sees an item this function returned
 * success for.
 *
 * @param item Item to set ownership on (must not be NULL)
 * @param storage_path The item's key, for the one clause its label decides (must
 *                     not be NULL, under a label)
 * @param st Stat data with uid/gid (must not be NULL)
 * @return Error or NULL on success — NULL with nothing named where absence says it
 *
 * Errors:
 * - ERR_NOT_FOUND: the UID or the GID has no name on this system
 */
static error_t *metadata_capture_ownership(
    metadata_item_t *item,
    const char *storage_path,
    const struct stat *st
) {
    const uid_t invoker = identity()->uid;

    /* The invoker's own is absence, which every machine reads as its own invoker
     * — under home/ whoever the invoker is, since home/ mounts at the invoker's
     * home on every machine, and outside it save a root login's: root's own under
     * root/ and custom/ is the system's, and the next machine's invoker is not
     * root. The label enters ownership here, for that clause, and nowhere else. */
    if (st->st_uid == invoker) {
        switch (label_of(storage_path)) {
            case LABEL_HOME:
                return NULL;
            case LABEL_ROOT:
            case LABEL_CUSTOM:
                if (invoker != 0) {
                    return NULL;
                }
                break;
        }
    }

    /* Resolve UID to username. "Cannot resolve" rather than "does not exist": a
     * NULL answer is an absent entry or a lookup that failed (a directory service
     * down), and the claim is equally unmakeable either way. */
    struct passwd *pwd = getpwuid(st->st_uid);
    if (!pwd || !pwd->pw_name) {
        return ERROR(
            ERR_NOT_FOUND, "Cannot resolve UID %u to a user name on this system",
            (unsigned) st->st_uid
        );
    }

    item->owner = heap_strdup(pwd->pw_name);

    /* Resolve GID to groupname: the owner brings its group with it */
    struct group *grp = getgrgid(st->st_gid);
    if (!grp || !grp->gr_name) {
        return ERROR(
            ERR_NOT_FOUND, "Cannot resolve GID %u to a group name on this system",
            (unsigned) st->st_gid
        );
    }

    item->group = heap_strdup(grp->gr_name);

    return NULL;
}

/**
 * Capture a path's claim from stat data (regular file or symlink)
 *
 * One existence rule: an item exists iff it claims something. A regular file
 * always claims its mode (0000 included), so a NULL answer is a links-only answer
 * — a link claims no mode, and when it has no ownership to claim either, no item
 * is authored.
 */
error_t *metadata_capture_file(
    const char *storage_path,
    const struct stat *st,
    bool encrypted,
    metadata_item_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(st);
    CHECK_NULL(out);

    *out = NULL;

    /* The kind the capture established, asked once more as a contract and not
     * as a refusal: no path reaches here that a capture did not take (the header),
     * so a device, a FIFO or a socket is a caller's error. */
    CHECK_ARG(
        S_ISREG(st->st_mode) || S_ISLNK(st->st_mode),
        "st must be a regular file's or a symlink's"
    );

    /* A link claims no mode — symlink(2) takes none */
    mode_t mode = S_ISLNK(st->st_mode) ? MODE_UNCLAIMED : (st->st_mode & 0777);

    metadata_item_t *item = metadata_item_create_file(storage_path, mode, encrypted);

    /* Ownership, where absence would misstate it (metadata_capture_ownership).
     * The lstat needs no privilege, so the claim is authored by whoever can read
     * the path. */
    error_t *err = metadata_capture_ownership(item, storage_path, st);
    if (err) {
        metadata_item_free(item);
        return err;
    }

    /* An item exists iff it claims something. Only a link reaches the branch —
     * a regular file always claims its mode — and only one kind of link: asked
     * after ownership resolution, which by now has either named both halves or
     * failed, what falls out here is a link absence already says — the invoker's
     * own — never one whose owner this host could not spell. No empty entry is
     * ever authored. */
    if (item->mode == MODE_UNCLAIMED && !item->owner && !item->group) {
        metadata_item_free(item);
        *out = NULL;
        return NULL;
    }

    *out = item;
    return NULL;
}

/**
 * Capture a directory's claim from stat data
 *
 * Creates a directory metadata item from stat data. Follows the same ownership
 * rule as file capture (metadata_capture_ownership); the class is the caller's,
 * carried through unread.
 *
 * This function creates a metadata_item_t with kind=DIRECTORY.
 */
error_t *metadata_capture_directory(
    const char *storage_path,
    const struct stat *st,
    bool tracked,
    metadata_item_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(st);
    CHECK_NULL(out);

    /* Verify it's actually a directory */
    if (!S_ISDIR(st->st_mode)) {
        return ERROR(ERR_INVALID_ARG, "Path is not a directory: %s", storage_path);
    }

    /* Create directory item via factory, its mode the stat's permission bits */
    mode_t mode = st->st_mode & 0777;
    metadata_item_t *item = metadata_item_create_directory(storage_path, mode, tracked);

    /* Ownership, by the file capture's rule (metadata_capture_ownership) */
    error_t *err = metadata_capture_ownership(item, storage_path, st);
    if (err) {
        metadata_item_free(item);
        return err;
    }

    *out = item;
    return NULL;
}

/**
 * Author, refresh or retire the derived claim at one rung of a chain
 *
 * One component, spelled by the climb below and standing where its own name
 * resolves. The rule is metadata.h's own, read one level up: an item exists iff
 * it claims something, so a rung the disk answers "directory" for claims its
 * attributes, a rung it answers anything else for retires the claim that said
 * otherwise, and a rung it does not answer at all leaves the sheet exactly as
 * it found it.
 *
 * `tracked` is false throughout: this rule authors derivations, never intent.
 *
 * @param metadata Collection to author into (must not be NULL; mutated)
 * @param mounts The table the rung's name resolves through (must not be NULL)
 * @param profile The rung's profile, for a custom/ name (must not be NULL)
 * @param storage_path The rung's key (must not be NULL)
 * @param arena Arena the rung's path is spelled into (must not be NULL)
 * @param captured Incremented when the rung's claim moved (must not be NULL)
 * @param retired Receives the key when the rung's claim goes (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *capture_ancestor(
    metadata_t *metadata, const mount_table_t *mounts, const char *profile,
    const char *storage_path, arena_t *arena, size_t *captured,
    string_array_t *retired
) {
    /* Two standing items are not a derivation's to touch. A tracked claim is
     * the walk's own word about a directory the profile tracks, and nothing derived
     * refreshes or retires it. A FILE item is the tree's business: a path is a
     * blob or a tree, so an item of that kind at a directory's key is stale
     * metadata, and the tree is its authority — the view drops it where its own
     * walk met the blob (core/manifest.c manifest_contribute), and a capture at
     * that key replaces it. The prune is no authority over it: it takes
     * derivations, and this item is not one. */
    const metadata_item_t *held = metadata_lookup(metadata, storage_path);
    if (held && (held->kind != PATH_KIND_DIRECTORY || held->tracked)) {
        return NULL;
    }

    /* Where the rung stands is where its own name resolves. The climb carries
     * one string, not a pair that must agree: a resolve is a root's spelling
     * and a tail, and truncating the leaf's path would land the same bytes — at
     * the cost of a second string the caller must have got right, which is what
     * the cross-check this shape deleted used to assert. One producer places a
     * name (infra/mount.h mount_resolve); the cost is one table scan per rung
     * per leaf, bounded by the profile count. */
    const char *filesystem_path = NULL;
    RETURN_IF_ERROR(
        mount_resolve(mounts, profile, storage_path, arena, &filesystem_path)
    );

    /* A rung this machine cannot place — an unbound custom/ name — has no answer
     * to give, the same silence as a rung nothing stands at. */
    if (!filesystem_path) return NULL;

    struct stat st;
    fs_occupant_t occupant = fs_lstat_occupant(filesystem_path, &st);

    /* Nothing there, or nothing this host could see: the rung has no answer,
     * and no answer is not an answer of "no". A chain the world moved under between
     * the leaf's capture and this climb keeps the claims it already had. */
    if (occupant == FS_OCCUPANT_NONE || occupant == FS_OCCUPANT_UNKNOWN) {
        return NULL;
    }

    /* Something stands here that is not a directory, so the profile passes through
     * no directory at this rung and a claim that says it does has just been
     * contradicted by the disk. The case that matters is a symlink the user put
     * there after the first capture: writing through it is what they asked for,
     * and dropping the claim is what lets dotta — the row leaves the view with
     * the claim, and the caller retires the record that named the path (the two
     * halves core/workspace reads to call a directory displaced). A symlink that
     * was there at capture time never authored a claim to drop; this is the same
     * consent, one command later. */
    if (occupant != FS_OCCUPANT_DIRECTORY) {
        if (metadata_remove_item(metadata, storage_path)) {
            string_array_push(retired, storage_path);
        }
        return NULL;
    }

    metadata_item_t *item = NULL;
    error_t *err = metadata_capture_directory(storage_path, &st, false, &item);
    if (err) {
        /* A name this host cannot spell is the same silence as a path it cannot
         * see: a directory capture that fails loses a claim and nothing else,
         * so the rung keeps what it had and dotta creates it as it would have
         * before. */
        if (err->code != ERR_NOT_FOUND) {
            return err;
        }
        error_free(err);
        return NULL;
    }

    /* A re-derivation that found nothing new authors nothing: the standing claim
     * keeps its place, so nothing is counted and the caller's commit gate never
     * fires on a chain that has not moved. Ownership is both names or neither
     * (metadata_capture_ownership), so an absent one compares as the value it
     * is. */
    if (held && held->mode == item->mode &&
        str_equal(held->owner, item->owner) &&
        str_equal(held->group, item->group)) {
        metadata_item_free(item);
        return NULL;
    }

    metadata_add_item(metadata, &item);

    (*captured)++;

    return NULL;
}

/**
 * Author the claims for every directory on the way to a path
 *
 * The climb: this names every rung, capture_ancestor decides each one.
 */
error_t *metadata_capture_ancestors(
    metadata_t *metadata, const mount_table_t *mounts, const char *profile,
    const char *storage_path, arena_t *arena, size_t *captured,
    string_array_t *retired
) {
    CHECK_NULL(metadata);
    CHECK_NULL(mounts);
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(arena);
    CHECK_NULL(captured);
    CHECK_NULL(retired);

    /* One rung per separator in the mount-relative tail. The mount root is excluded
     * by where the scan starts and the leaf by where it ends — arithmetic, not
     * a special case — so a path directly beneath a mount root climbs nowhere. */
    const char *first = strchr(label_tail(storage_path), '/');
    if (!first) return NULL;

    /* Every rung is a prefix of the leaf's own name, so one copy spells them
     * all: each separator truncates it in place and is restored before the next
     * one extends past it. The scan reads the caller's string, which is never
     * written, so the cut is an offset into it. */
    char *rung = heap_strdup(storage_path);

    error_t *err = NULL;
    for (const char *sep = first; sep; sep = strchr(sep + 1, '/')) {
        size_t cut = (size_t) (sep - storage_path);

        rung[cut] = '\0';
        err = capture_ancestor(
            metadata, mounts, profile, rung, arena, captured, retired
        );
        rung[cut] = '/';

        if (err) break;
    }

    free(rung);

    return err;
}

/**
 * Sort helper for the serializer: byte order on the item key
 */
static int item_key_cmp(const void *a, const void *b) {
    const metadata_item_t *const *ia = a;
    const metadata_item_t *const *ib = b;

    return strcmp((*ia)->key, (*ib)->key);
}

/**
 * Convert metadata to JSON
 *
 * One "items" array, key-ordered, each object carrying its "kind" discriminator
 * and then only what the item claims.
 */
buffer_t metadata_to_json(const metadata_t *metadata) {
    CHECK_NULL(metadata);

    /* Every node is cJSON's, and cJSON allocates from the heap that cannot fail
     * (the hooks src/main.c main installs), so no node below is refused: an add
     * refuses only a NULL argument, and none stands here. */
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", METADATA_VERSION);
    cJSON *items_array = cJSON_CreateArray();

    /* Serialize in key order — a write-side norm only (the parser accepts any
     * order, so a hand-edit cannot brick on placement), buying byte-determinism
     * across machines: sync's merge then conflicts only on genuine same-path
     * edits, never on capture-order divergence. The sort is over a transient
     * copy of the spine; the collection's insertion order is untouched. */
    const metadata_item_t **sorted = NULL;
    if (metadata->count > 0) {
        sorted = heap_calloc(metadata->count, sizeof(*sorted));
        memcpy(sorted, metadata->items, metadata->count * sizeof(*sorted));
        qsort(sorted, metadata->count, sizeof(*sorted), item_key_cmp);
    }

    for (size_t i = 0; i < metadata->count; i++) {
        const metadata_item_t *item = sorted[i];
        cJSON *item_obj = cJSON_CreateObject();

        /* Add kind discriminator */
        const char *kind_str = item->kind == PATH_KIND_DIRECTORY ? "directory" : "file";
        cJSON_AddStringToObject(item_obj, "kind", kind_str);

        /* Add key (storage_path for both files and directories) */
        cJSON_AddStringToObject(item_obj, "key", item->key);

        /* Add mode — a claimed one; an unclaimed one has no line to print */
        if (item->mode != MODE_UNCLAIMED) {
            char mode_str[8];
            snprintf(mode_str, sizeof(mode_str), "%04o", (unsigned) item->mode);
            cJSON_AddStringToObject(item_obj, "mode", mode_str);
        }

        /* Add optional owner (present iff the item claims one) */
        if (item->owner) {
            cJSON_AddStringToObject(item_obj, "owner", item->owner);
        }

        /* Add optional group (present iff the item claims one) */
        if (item->group) {
            cJSON_AddStringToObject(item_obj, "group", item->group);
        }

        /* Add encrypted flag iff true — false for DIRECTORY by construction at
         * both boundaries, so no kind test stands here */
        if (item->encrypted) {
            cJSON_AddBoolToObject(item_obj, "encrypted", true);
        }

        /* And tracked, the other flag one kind carries: false for FILE by the
         * same construction, and absent on a directory that says the profile
         * only passes through it. The two are mutually exclusive, so they print
         * in one place. */
        if (item->tracked) {
            cJSON_AddBoolToObject(item_obj, "tracked", true);
        }

        /* Add item object to items array (ownership transferred to array) */
        cJSON_AddItemToArray(items_array, item_obj);
    }
    free(sorted);

    /* Add items array to root (ownership transferred to root) */
    cJSON_AddItemToObject(root, "items", items_array);

    /* The formatted document, copied into the buffer the caller owns. cJSON counts
     * a document's bytes in an int, so a print past INT_MAX is the one refusal
     * left to it: a count it cannot hold, exhaustion as a count that wraps is
     * (base/heap.h heap_die). */
    char *json_str = cJSON_Print(root);
    if (!json_str) heap_die(SIZE_MAX);

    buffer_t out = BUFFER_INIT;
    buffer_append_string(&out, json_str);
    cJSON_free(json_str);
    cJSON_Delete(root);

    return out;
}

/**
 * Parse mode string to mode_t
 *
 * Parses octal mode string (e.g., "0600", "0644", "0755") to mode_t. Validates
 * that mode is within valid range (0000-0777).
 */
static error_t *parse_mode(const char *mode_str, mode_t *out) {
    CHECK_NULL(mode_str);
    CHECK_NULL(out);

    char *endptr;
    unsigned long mode = strtoul(mode_str, &endptr, 8); /* Octal base */

    /* Reject empty/whitespace-only strings and trailing non-octal characters */
    if (endptr == mode_str || *endptr != '\0') {
        return ERROR(
            ERR_INVALID_ARG, "Invalid mode string: '%s' (not valid octal)",
            mode_str
        );
    }

    if (mode > 0777) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid mode: %04lo (must be <= 0777)",
            mode
        );
    }

    *out = (mode_t) mode;
    return NULL;
}

/**
 * Parse metadata from JSON
 *
 * Parses unified JSON with single "items" array. REJECTS other versions with a
 * clear error message (NO migration code), and refuses a duplicated key — ambiguity
 * is not noise. Absence parses as itself: a missing mode is MODE_UNCLAIMED, missing
 * owner/group NULL, a missing "tracked" an ancestor claim, and an item that claims
 * nothing is accepted and inert — strictness lives where the fact is authored,
 * not here. A present mode, owner or group is a value of its kind or a refusal
 * all the same: a mode that parses, a name.
 */
error_t *metadata_from_json(const char *json_str, metadata_t **out) {
    CHECK_NULL(json_str);
    CHECK_NULL(out);

    /* Three resources, one tail. Every refusal below names the item it refused,
     * and the name it prints is borrowed from `root` — cJSON owns those strings
     * and the message is formatted out of them. The one tail is what keeps the
     * two in order: the refusal is built while the tree still stands, and the
     * tree is deleted once, after it. `item` is the loop's scratch and the tail's
     * too, so an iteration that gives up midway leaves nothing behind. */
    error_t *err = NULL;
    cJSON *root = NULL;
    metadata_t *metadata = NULL;
    metadata_item_t *item = NULL;

    /* Parse JSON */
    root = cJSON_Parse(json_str);
    if (!root) {
        /* cJSON hands back the position the parse stopped at, not the token that
         * failed, so printing that pointer prints the whole remainder of the
         * document — a 50 KB sheet with an early syntax error yields a 50 KB
         * message. The offset is the fact; the excerpt beside it is a courtesy
         * and is bounded, a sheet being as long as a branch is wide.
         *
         * The pointer is inside json_str, so the subtraction is defined: the
         * parse that just failed set the position from the value it was handed
         * (lib/cjson/cJSON.c), and CHECK_NULL above says there was one. */
        const char *parse_end = cJSON_GetErrorPtr();
        err = ERROR(
            ERR_INVALID_ARG, "Failed to parse metadata JSON at byte %zu: '%.24s'",
            (size_t) (parse_end - json_str), parse_end
        );
        goto cleanup;
    }

    /* Get and validate version */
    cJSON *version_obj = cJSON_GetObjectItem(root, "version");
    if (!version_obj || !cJSON_IsNumber(version_obj)) {
        err = ERROR(
            ERR_INVALID_ARG, "Missing or invalid version in metadata"
        );
        goto cleanup;
    }

    int version = version_obj->valueint;
    if (version != METADATA_VERSION) {
        err = ERROR(
            ERR_INVALID_ARG,
            "Unsupported metadata version: %d (this build reads %d)",
            version, METADATA_VERSION
        );
        goto cleanup;
    }

    /* Get items array */
    cJSON *items_array = cJSON_GetObjectItem(root, "items");
    if (!items_array || !cJSON_IsArray(items_array)) {
        err = ERROR(
            ERR_INVALID_ARG, "Missing or invalid items array in metadata"
        );
        goto cleanup;
    }

    /* Create metadata collection */
    metadata = metadata_create_empty();

    /* Parse each item in the unified array */
    cJSON *item_obj = NULL;
    cJSON_ArrayForEach(item_obj, items_array) {
        if (!cJSON_IsObject(item_obj)) {
            err = ERROR(
                ERR_INVALID_ARG, "Invalid item in items array (not an object)"
            );
            goto cleanup;
        }

        /* Get kind discriminator (required) */
        cJSON *kind_obj = cJSON_GetObjectItem(item_obj, "kind");
        if (!kind_obj || !cJSON_IsString(kind_obj) || !kind_obj->valuestring) {
            err = ERROR(
                ERR_INVALID_ARG, "Item missing kind field"
            );
            goto cleanup;
        }

        path_kind_t kind;
        if (strcmp(kind_obj->valuestring, "file") == 0) {
            kind = PATH_KIND_FILE;
        } else if (strcmp(kind_obj->valuestring, "directory") == 0) {
            kind = PATH_KIND_DIRECTORY;
        } else {
            err = ERROR(
                ERR_INVALID_ARG, "Invalid kind value: %s "
                "(expected 'file' or 'directory')", kind_obj->valuestring
            );
            goto cleanup;
        }

        /* Get key (required) */
        cJSON *key_obj = cJSON_GetObjectItem(item_obj, "key");
        if (!key_obj || !cJSON_IsString(key_obj) || !key_obj->valuestring) {
            err = ERROR(
                ERR_INVALID_ARG, "Item missing key field"
            );
            goto cleanup;
        }

        /* Validate key format (prevent path traversal) */
        err = label_validate_storage(key_obj->valuestring);
        if (err) {
            err = error_wrap(
                err, "Invalid key in metadata: %s",
                key_obj->valuestring
            );
            goto cleanup;
        }

        /* Refuse a duplicated key before the factory runs. The collection's upsert
         * would resolve the contradiction silently, last-wins; a document saying
         * two things about one path gets the same loud refusal every other
         * malformation does. Only a hand-edit or a mis-resolved merge can author
         * one. */
        if (metadata_lookup(metadata, key_obj->valuestring)) {
            err = ERROR(
                ERR_INVALID_ARG, "Duplicate key in metadata: %s",
                key_obj->valuestring
            );
            goto cleanup;
        }

        /* Get mode (optional — absence is the mode a claim does not make) */
        mode_t mode = MODE_UNCLAIMED;
        cJSON *mode_obj = cJSON_GetObjectItem(item_obj, "mode");
        if (mode_obj) {
            if (!cJSON_IsString(mode_obj) || !mode_obj->valuestring) {
                err = ERROR(
                    ERR_INVALID_ARG, "Invalid mode field (key: %s)",
                    key_obj->valuestring
                );
                goto cleanup;
            }
            err = parse_mode(mode_obj->valuestring, &mode);
            if (err) {
                err = error_wrap(
                    err, "Failed to parse mode for item: %s",
                    key_obj->valuestring
                );
                goto cleanup;
            }
        }

        /* Build the item through the factory its kind names, the way every other
         * producer does. Each owns its kind's invariants: each of the two flags
         * is consulted for its own kind and never handed to the other's factory,
         * so one hand-written onto the kind that cannot carry it is waved through
         * inert, not refused — and the next rewrite drops it.
         *
         * A directory item with no "tracked" is an ancestor claim, never a walked
         * one read leniently: the field's absence is its meaning, which is what
         * makes losing it fail safe. */
        switch (kind) {
            case PATH_KIND_FILE: {
                cJSON *encrypted_obj = cJSON_GetObjectItem(item_obj, "encrypted");
                item = metadata_item_create_file(
                    key_obj->valuestring, mode,
                    encrypted_obj && cJSON_IsTrue(encrypted_obj)
                );
                break;
            }
            case PATH_KIND_DIRECTORY: {
                cJSON *tracked_obj = cJSON_GetObjectItem(item_obj, "tracked");
                item = metadata_item_create_directory(
                    key_obj->valuestring, mode,
                    tracked_obj && cJSON_IsTrue(tracked_obj)
                );
                break;
            }
        }

        /* Ownership is the overlay every producer stamps beside the factory,
         * present iff the item claims it — and a present half is a name, mode's
         * own rule: a field that is here says something, so a non-string (a uid
         * typed as a number, a null) or an empty name is refused as a field,
         * never dropped and never kept for a resolver no host can answer. No
         * producer writes one; a hand does, and the parser is where a hand is
         * answered. What an absent half means is decided where the claim is read
         * (metadata_ownership), never here: a claim standing under any label is
         * parsed as it stands. */
        cJSON *owner_obj = cJSON_GetObjectItem(item_obj, "owner");
        if (owner_obj) {
            if (!cJSON_IsString(owner_obj) || !owner_obj->valuestring ||
                !*owner_obj->valuestring) {
                err = ERROR(
                    ERR_INVALID_ARG, "Invalid owner field (key: %s)",
                    key_obj->valuestring
                );
                goto cleanup;
            }
            item->owner = heap_strdup(owner_obj->valuestring);
        }

        /* The group, the other half of the same overlay, by the same rule */
        cJSON *group_obj = cJSON_GetObjectItem(item_obj, "group");
        if (group_obj) {
            if (!cJSON_IsString(group_obj) || !group_obj->valuestring ||
                !*group_obj->valuestring) {
                err = ERROR(
                    ERR_INVALID_ARG, "Invalid group field (key: %s)",
                    key_obj->valuestring
                );
                goto cleanup;
            }
            item->group = heap_strdup(group_obj->valuestring);
        }

        /* Hand the item to the collection; it takes it, and leaves the loop's
         * scratch pointer NULL for the next iteration and the tail. */
        metadata_add_item(metadata, &item);
    }

    /* Success - transfer to caller */
    *out = metadata;
    metadata = NULL;

cleanup:
    metadata_item_free(item);
    metadata_free(metadata);
    cJSON_Delete(root);

    return err;
}

/**
 * Load metadata from profile branch
 *
 * Composed: the branch's tree via gitops_load_branch_tree (which accepts both
 * commit-backed branches and orphan refs pointing directly at a tree), then
 * metadata_load_from_tree. A branch without a sheet loads as an empty one, as
 * the tree loader says; a missing branch is the tree loader's failure (ERR_GIT),
 * never a sheet with nothing in it.
 */
error_t *metadata_load_from_branch(
    git_repository *repo,
    const char *branch_name,
    metadata_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out);

    git_tree *tree = NULL;
    error_t *err = gitops_load_branch_tree(repo, branch_name, &tree, NULL);
    if (err) {
        return error_wrap(err, "Failed to load tree of branch '%s'", branch_name);
    }

    err = metadata_load_from_tree(repo, tree, branch_name, out);
    git_tree_free(tree);
    return err;
}

/**
 * Load metadata from a Git tree
 *
 * Loads metadata.json from a specific Git tree — a branch tip or a historical
 * commit's tree alike. A tree without the entry holds an empty sheet: the
 * absent-entry arm is the one producer of that answer, so no reader folds a
 * not-found into a collection of its own.
 */
error_t *metadata_load_from_tree(
    git_repository *repo,
    const git_tree *tree,
    const char *profile,
    metadata_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    error_t *err = NULL;
    git_tree_entry *entry = NULL;
    char *json_str = NULL;
    metadata_t *metadata = NULL;

    /* Look for .dotta/metadata.json (use bypath for nested paths). No entry is
     * a sheet claiming nothing — the settled answer every reader wants — and
     * only a lookup that failed to look is an error. */
    int git_err = git_tree_entry_bypath(&entry, tree, METADATA_FILE_PATH);
    if (git_err == GIT_ENOTFOUND) {
        *out = metadata_create_empty();
        return NULL;
    }
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Read blob content (null-terminated for JSON parsing) */
    size_t size = 0;
    err = gitops_read_blob_content(
        repo, git_tree_entry_id(entry), (void **) &json_str, &size
    );
    if (err) goto cleanup;

    /* Parse JSON */
    err = metadata_from_json(json_str, &metadata);
    if (err) {
        err = error_wrap(
            err, "Failed to parse metadata from profile: %s",
            profile
        );
        goto cleanup;
    }

    /* Success - transfer ownership to caller */
    *out = metadata;
    metadata = NULL;

cleanup:
    if (json_str) free(json_str);
    if (entry) git_tree_entry_free(entry);
    if (metadata) metadata_free(metadata);

    return err;
}

/**
 * Save metadata to a stage
 *
 * The sheet serialized, then put at .dotta/metadata.json as a regular blob.
 */
error_t *metadata_save_to_stage(
    stage_t *stage,
    const metadata_t *metadata
) {
    CHECK_NULL(stage);
    CHECK_NULL(metadata);

    buffer_t json = metadata_to_json(metadata);

    error_t *err = stage_put(
        stage, METADATA_FILE_PATH, json.data, json.size, GIT_FILEMODE_BLOB, NULL
    );
    buffer_deinit(&json);

    return err;
}

/**
 * The sheet's word on a path's ownership, as this host's ids
 *
 * Each half by its own rule (metadata.h), written to the outs together, so a
 * half that resolved never survives the other's failure.
 */
error_t *metadata_ownership(
    const char *owner,
    const char *group,
    uid_t *out_uid,
    gid_t *out_gid
) {
    CHECK_NULL(out_uid);
    CHECK_NULL(out_gid);

    /* The invoker where no owner is named, no change where no group is */
    uid_t uid = identity()->uid;
    gid_t gid = (gid_t) -1;

    /* A named owner is its uid on this host, or no answer at all */
    if (owner) {
        struct passwd *pwd = getpwnam(owner);
        if (!pwd) {
            return ERROR(
                ERR_NOT_FOUND, "User '%s' does not exist on this system",
                owner
            );
        }
        uid = pwd->pw_uid;
    }

    /* And a named group its gid — never the owner's primary: a claim that names
     * no group constrains none */
    if (group) {
        struct group *grp = getgrnam(group);
        if (!grp) {
            return ERROR(
                ERR_NOT_FOUND, "Group '%s' does not exist on this system",
                group
            );
        }
        gid = grp->gr_gid;
    }

    *out_uid = uid;
    *out_gid = gid;
    return NULL;
}
