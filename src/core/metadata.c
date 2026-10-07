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
#include "base/buffer.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/string.h"
#include "infra/label.h"
#include "sys/gitops.h"
#include "sys/identity.h"

#define INITIAL_CAPACITY 16

/**
 * One kind's claims: its items, in key order
 *
 * The order is the document's (metadata_to_json): byte order on the key. So a
 * sheet the serializer wrote parses in place, a writer's edits land where their
 * keys fall, and every question the sheet asks of its items is one search of
 * the order — where a key stands (metadata_place), and which claims stand beneath
 * a name (metadata_bound). The order is the one representation: nothing beside
 * it says where an item is, so nothing has to agree with it. An item is stable
 * from the moment it is created — only the entries move, grown or shifted — so
 * metadata_items lends the entries as the kind's slice.
 */
typedef struct {
    metadata_item_t **entries;  /* Stable items, in key order */
    size_t count;               /* Items held */
    size_t capacity;            /* Entries allocated */
} metadata_claims_t;

/**
 * The sheet: each kind's claims apart
 *
 * A key holds at most one item of each kind (metadata.h), and the two kinds never
 * share an order, so a write of one kind cannot reach the other's claim at its
 * key. One kind's claims are chosen where they are read — a directory's, or else
 * a file's — and the readers of both at once take the files first.
 *
 * The sheet is a handle whose lifetime is its own, so it owns an arena: the struct
 * and each kind's entries live and go with it. The items are the heap's, each
 * freed by metadata_free before the arena goes.
 *
 * The schema version is the document's, not the sheet's: metadata_to_json writes
 * METADATA_VERSION and metadata_from_json refuses anything else, so there is
 * nothing here for a version field to say.
 */
struct metadata {
    arena_t *arena;                   /* The sheet's own: the struct, the entries */
    metadata_claims_t files;          /* FILE items: what a blob at the key carries */
    metadata_claims_t directories;    /* DIRECTORY items: the directory claims */
};

/**
 * The first of one kind's entries not before `name` and `byte` after it
 *
 * The entries are in strcmp order, and every key a name prefixes sorts after it
 * in one block — the claims beneath it, the name and a separator, and the siblings
 * it merely prefixes, "x.bak" before "x/y" and "x0" after, '/' being neither
 * the least byte nor the greatest (core/workspace.c workspace_orphan_beneath,
 * the same block over the orphans). So one lower bound answers each place the
 * sheet asks of its order: `byte` NUL, where the name itself stands or would;
 * '/', the first claim beneath it; '/' + 1, the first key past those — no byte
 * lies between the two. Nothing is spelled to search.
 *
 * Readers: metadata_place, a key's place; metadata_items_beneath, the block's
 * two ends.
 *
 * @param claims One kind's claims, in key order
 * @param name The name searched for
 * @param byte What follows its bytes in the bound searched for
 * @return The place, in [0, claims->count]
 */
static size_t metadata_bound(
    const metadata_claims_t *claims, const char *name, unsigned char byte
) {
    const size_t len = strlen(name);
    size_t lo = 0;
    size_t hi = claims->count;

    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const char *key = claims->entries[mid]->key;

        /* The key against the name and the byte: the name's bytes, then the byte
         * after them, read unsigned as strcmp reads every byte, where a key the
         * name is all of reads its terminator */
        int order = strncmp(key, name, len);
        if (order == 0) order = (unsigned char) key[len] - byte;

        if (order < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    return lo;
}

/**
 * Where `key` stands in one kind's order, or would: whether an item stands there
 *
 * Readers: metadata_add_item, metadata_find_item and metadata_remove_item.
 *
 * @param claims One kind's claims, in key order
 * @param key The key
 * @param place Its place, in [0, claims->count]
 * @return true where an item stands at `key`
 */
static bool metadata_place(const metadata_claims_t *claims, const char *key, size_t *place) {
    /* Past the last item: a document the serializer wrote, and a copy, arrive
     * in key order, so each of their keys falls here, one comparison deciding it */
    if (claims->count == 0 || strcmp(claims->entries[claims->count - 1]->key, key) < 0) {
        *place = claims->count;
        return false;
    }

    /* Any other key is one search. The last item is not before it, so the place
     * the search finds holds an item: the key's own, or the next */
    *place = metadata_bound(claims, key, '\0');
    return strcmp(claims->entries[*place]->key, key) == 0;
}

/**
 * Create an empty sheet
 */
metadata_t *metadata_create_empty(void) {
    /* The sheet's own arena, and the sheet in it: each kind's entries are made
     * there — room at once, so each kind lends an array even while it holds
     * nothing, which every slice of it offsets into (metadata_items,
     * metadata_items_beneath) */
    arena_t *arena = arena_create(0);
    metadata_t *metadata = arena_calloc(arena, 1, sizeof(*metadata));
    metadata->arena = arena;

    metadata_claims_t *claims[] = { &metadata->files, &metadata->directories };
    for (size_t k = 0; k < sizeof(claims) / sizeof(claims[0]); k++) {
        claims[k]->entries = arena_grow(
            arena, NULL, &claims[k]->capacity, INITIAL_CAPACITY,
            sizeof(*claims[k]->entries)
        );
    }

    return metadata;
}

/**
 * The same claim, deep-copied
 *
 * Every field travels — kind, key, mode, ownership and the two flags — and the
 * copy owns its three strings, an absent name copied as absent.
 *
 * Reader: metadata_clone, item by item.
 *
 * @param source The item to copy (must not be NULL)
 * @return The copy (caller frees with metadata_item_free)
 */
static metadata_item_t *metadata_item_clone(const metadata_item_t *source) {
    metadata_item_t *item = heap_calloc(1, sizeof(metadata_item_t));

    /* Everything that is not a pointer copies wholesale — kind, mode and the
     * two flags, so a field added later needs no line here. The three strings
     * are then owned here: the key, and the two ownership names the source carries,
     * an absent one copied as absent. */
    *item = *source;
    item->key = heap_strdup(source->key);
    item->owner = heap_strdup(source->owner);
    item->group = heap_strdup(source->group);

    return item;
}

/**
 * A copy of the sheet
 *
 * Each item cloned under its own key and handed to a sheet of the copy's own,
 * each kind in the source's key order: a key is held once in each kind's claims,
 * so every add lands past the last, one comparison deciding it, and the copy's
 * entries read as the source's.
 */
metadata_t *metadata_clone(const metadata_t *metadata) {
    CHECK_NULL(metadata);

    metadata_t *copy = metadata_create_empty();
    const metadata_claims_t *claims[] = { &metadata->files, &metadata->directories };
    for (size_t k = 0; k < sizeof(claims) / sizeof(claims[0]); k++) {
        for (size_t i = 0; i < claims[k]->count; i++) {
            metadata_item_t *item = metadata_item_clone(claims[k]->entries[i]);
            metadata_add_item(copy, &item);
        }
    }

    return copy;
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
 * Free a sheet
 *
 * Frees every item it holds, then the sheet's arena — the struct and each kind's
 * entries with it.
 */
void metadata_free(metadata_t *metadata) {
    if (!metadata) return;

    /* Every item of each kind, the heap's; then the arena below, which holds
     * the entries that pointed at them */
    const metadata_claims_t *claims[] = { &metadata->files, &metadata->directories };
    for (size_t k = 0; k < sizeof(claims) / sizeof(claims[0]); k++) {
        for (size_t i = 0; i < claims[k]->count; i++) {
            metadata_item_free(claims[k]->entries[i]);
        }
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
 * Add or update metadata item, transferring ownership
 *
 * Of the item's own kind: an item of that kind at the same key is replaced in
 * place, and the other kind's at the key stays; otherwise the item takes its
 * key's place in its kind's order.
 *
 * The sheet stores pointers, so an item handed to it is taken rather than copied:
 * it keeps its place in memory, the sheet keeps the pointer, and the caller's
 * handle is cleared.
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

    /* The item's own kind's claims, the only ones it can meet: the other kind's
     * item at its key is another claim, and stays as it stands */
    metadata_item_t *incoming = *item;
    metadata_claims_t *claims = incoming->kind == PATH_KIND_DIRECTORY
        ? &metadata->directories : &metadata->files;

    size_t place;
    if (metadata_place(claims, incoming->key, &place)) {
        /* UPDATE EXISTING ITEM
         *
         * The standing item keeps its place in memory, so a pointer to it stays
         * good, and takes the incoming item whole: its own three names are freed,
         * and every field the incoming item carries for its kind replaces them
         * — the key too, equal to its own — before the incoming struct goes. */
        metadata_item_t *existing = claims->entries[place];
        free(existing->key);
        free(existing->owner);
        free(existing->group);

        *existing = *incoming;
        free(incoming);
        *item = NULL;

        return;
    }

    /* INSERT NEW ITEM, at its key's place in the kind's order. Room for it grows
     * in the sheet's arena, and the entries past the place move up one: pointers
     * alone, every item staying where it was created, but one move an item out
     * of place — so a writer adding in an order of its own, a walk in readdir's,
     * pays a run of them, where a document in key order lands past the last. */
    claims->entries = arena_grow(
        metadata->arena, claims->entries, &claims->capacity, claims->count + 1,
        sizeof(*claims->entries)
    );
    memmove(
        &claims->entries[place + 1], &claims->entries[place],
        (claims->count - place) * sizeof(*claims->entries)
    );

    claims->entries[place] = incoming;
    claims->count++;
    *item = NULL;
}

/**
 * The item of `kind` at `key`
 *
 * A key the sheet does not hold under that kind is the answer, not a failure.
 */
const metadata_item_t *metadata_find_item(
    const metadata_t *metadata,
    path_kind_t kind,
    const char *key
) {
    if (!metadata || !key) return NULL;

    /* The kind's own claims: the other kind's item at the key is never this
     * answer */
    const metadata_claims_t *claims = kind == PATH_KIND_DIRECTORY
        ? &metadata->directories : &metadata->files;

    size_t place;
    return metadata_place(claims, key, &place) ? claims->entries[place] : NULL;
}

/**
 * One kind's items strictly beneath `key`
 *
 * The block of the kind's order the name and a separator begin, lent: its two
 * ends are two lower bounds (metadata_bound), and nothing is copied.
 */
metadata_items_t metadata_items_beneath(
    const metadata_t *metadata, path_kind_t kind, const char *key
) {
    /* A sheet a tolerant read went on without holds none (core/profiles.c
     * profile_walk), and a name not given has nothing beneath it: the empty slice,
     * as metadata_items answers */
    if (!metadata || !key) return (metadata_items_t){ 0 };

    /* The kind's own entries, from the name and a separator to the name and the
     * byte after it */
    const metadata_claims_t *claims = kind == PATH_KIND_DIRECTORY
        ? &metadata->directories : &metadata->files;
    const size_t first = metadata_bound(claims, key, '/');
    const size_t past = metadata_bound(claims, key, '/' + 1);

    return (metadata_items_t){
        .entries = (const metadata_item_t *const *) claims->entries + first,
        .count = past - first,
    };
}

/**
 * Two claims that say the same thing
 *
 * Every field, the key included: a claim is one row of the sheet, and two rows
 * are the same row when nothing about them differs. Absence is a value on both
 * sides — a NULL owner is a claim of no owner, and two of them are equal. Two
 * claims of the same key can differ in what only the sheet carries — the mode's
 * lower bits, an owner, a group — so the tree's entry cannot stand in for this
 * comparison.
 *
 * Reader: metadata_same, claim by claim, the two sheets in step.
 *
 * @param a First claim (must not be NULL)
 * @param b Second claim (must not be NULL)
 * @return true if the two say the same thing
 */
static bool metadata_same_claim(const metadata_item_t *a, const metadata_item_t *b) {
    return a->kind == b->kind && a->mode == b->mode &&
           a->encrypted == b->encrypted && a->tracked == b->tracked &&
           str_equal(a->key, b->key) && str_equal(a->owner, b->owner) &&
           str_equal(a->group, b->group);
}

/**
 * Two sheets that say the same thing
 *
 * Each kind apart: as many claims, each the same. Both sheets hold each kind in
 * key order, a key held once in each kind's, so two sheets holding the same claims
 * hold them at the same places, and the two are read in step.
 */
bool metadata_same(const metadata_t *a, const metadata_t *b) {
    CHECK_NULL(a);
    CHECK_NULL(b);

    const metadata_claims_t *in_a[] = { &a->files, &a->directories };
    const metadata_claims_t *in_b[] = { &b->files, &b->directories };
    for (size_t k = 0; k < sizeof(in_a) / sizeof(in_a[0]); k++) {
        if (in_a[k]->count != in_b[k]->count) return false;

        for (size_t i = 0; i < in_a[k]->count; i++) {
            if (!metadata_same_claim(in_a[k]->entries[i], in_b[k]->entries[i])) {
                return false;
            }
        }
    }

    return true;
}

/**
 * Remove the item of `kind` at `key`
 *
 * A key the sheet does not hold under that kind changes nothing.
 */
bool metadata_remove_item(
    metadata_t *metadata,
    path_kind_t kind,
    const char *key
) {
    if (!metadata || !key) return false;

    /* The kind's own claims: the other kind's item at the key stays as it stands */
    metadata_claims_t *claims = kind == PATH_KIND_DIRECTORY
        ? &metadata->directories : &metadata->files;

    /* The key's place in the kind's order; a key the kind does not hold changes
     * nothing */
    size_t place;
    if (!metadata_place(claims, key, &place)) return false;

    /* The item freed — after the search, which read `key`, and `key` may be the
     * item's own — and the gap closed: the entries past it move down one, every
     * other item staying where it was. */
    metadata_item_free(claims->entries[place]);
    claims->count--;
    memmove(
        &claims->entries[place], &claims->entries[place + 1],
        (claims->count - place) * sizeof(*claims->entries)
    );

    return true;
}

/**
 * One kind's items, in key order
 *
 * The kind's own entries, lent: no allocation, no copy.
 */
metadata_items_t metadata_items(const metadata_t *metadata, path_kind_t kind) {
    /* A sheet a tolerant read went on without holds none (core/profiles.c
     * profile_walk): the empty slice, never a contract breach */
    if (!metadata) return (metadata_items_t){ 0 };

    /* The kind's own entries, borrowed. They are made with the sheet
     * (metadata_create_empty), so an empty kind lends an array too. */
    const metadata_claims_t *claims = kind == PATH_KIND_DIRECTORY
        ? &metadata->directories : &metadata->files;

    return (metadata_items_t){
        .entries = (const metadata_item_t *const *) claims->entries,
        .count = claims->count,
    };
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
static error_t metadata_capture_ownership(
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
     * down), and the claim is equally unmakeable either way. The refusal names
     * the path it was handed, so no caller names it again. */
    struct passwd *pwd = getpwuid(st->st_uid);
    if (!pwd || !pwd->pw_name) {
        return error_create(
            ERR_NOT_FOUND, "Cannot resolve UID %u, the owner of '%s', to a user name "
            "on this system", (unsigned) st->st_uid, storage_path
        );
    }

    item->owner = heap_strdup(pwd->pw_name);

    /* Resolve GID to groupname: the owner brings its group with it */
    struct group *grp = getgrgid(st->st_gid);
    if (!grp || !grp->gr_name) {
        return error_create(
            ERR_NOT_FOUND, "Cannot resolve GID %u, the group of '%s', to a group name "
            "on this system", (unsigned) st->st_gid, storage_path
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
error_t metadata_capture_file(
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
    error_t err = metadata_capture_ownership(item, storage_path, st);
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
error_t metadata_capture_directory(
    const char *storage_path,
    const struct stat *st,
    bool tracked,
    metadata_item_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(st);
    CHECK_NULL(out);

    /* The kind the caller established, asked once more as a contract and not as
     * a refusal: every caller held its look to a directory first (the header),
     * so a file, a link or anything else is a caller's error. */
    CHECK_ARG(S_ISDIR(st->st_mode), "st must be a directory's");

    /* Create directory item via factory, its mode the stat's permission bits */
    mode_t mode = st->st_mode & 0777;
    metadata_item_t *item = metadata_item_create_directory(storage_path, mode, tracked);

    /* Ownership, by the file capture's rule (metadata_capture_ownership) */
    error_t err = metadata_capture_ownership(item, storage_path, st);
    if (err) {
        metadata_item_free(item);
        return err;
    }

    *out = item;
    return NULL;
}

/**
 * Convert metadata to JSON
 *
 * One "items" array, ordered by key and then kind, each object carrying its "kind"
 * discriminator and then only what the item claims.
 */
buffer_t metadata_to_json(const metadata_t *metadata) {
    CHECK_NULL(metadata);

    /* Every node is cJSON's, and cJSON allocates from the heap that cannot fail
     * (the hooks src/main.c main installs), so no node below is refused: an add
     * refuses only a NULL argument, and none stands here. */
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", METADATA_VERSION);
    cJSON *items_array = cJSON_CreateArray();

    /* Serialize in key order, then kind — a write-side norm only (the parser
     * accepts any order, so a hand-edit cannot brick on placement), buying
     * byte-determinism across machines: sync's merge then conflicts only on genuine
     * same-path edits, never on capture-order divergence, and two sheets holding
     * the same claims write one spelling. Each kind stands in key order already
     * (metadata_add_item), so the document's order is one merge of the two, a
     * file's item first at a key both kinds hold: no copy, no sort. */
    const metadata_claims_t *files = &metadata->files;
    const metadata_claims_t *directories = &metadata->directories;
    for (size_t f = 0, d = 0; f < files->count || d < directories->count;) {
        const bool file_first = d == directories->count || (
            f < files->count &&
            strcmp(files->entries[f]->key, directories->entries[d]->key) <= 0
        );
        const metadata_item_t *item = file_first
            ? files->entries[f++] : directories->entries[d++];
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
static error_t metadata_parse_mode(const char *mode_str, mode_t *out) {
    CHECK_NULL(mode_str);
    CHECK_NULL(out);

    char *endptr;
    unsigned long mode = strtoul(mode_str, &endptr, 8); /* Octal base */

    /* Reject empty/whitespace-only strings and trailing non-octal characters */
    if (endptr == mode_str || *endptr != '\0') {
        return error_create(
            ERR_INVALID_ARG, "Invalid mode string: '%s' (not valid octal)",
            mode_str
        );
    }

    if (mode > 0777) {
        return error_create(
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
 * clear error message (NO migration code), and refuses a duplicated claim —
 * ambiguity is not noise. Absence parses as itself: a missing mode is
 * MODE_UNCLAIMED, missing owner/group NULL, a missing "tracked" an ancestor claim,
 * and an item that claims nothing is accepted and inert — strictness lives where
 * the fact is authored, not here. A present mode, owner or group is a value of
 * its kind or a refusal all the same: a mode that parses, a name.
 */
error_t metadata_from_json(const char *json_str, metadata_t **out) {
    CHECK_NULL(json_str);
    CHECK_NULL(out);

    /* Three resources, one tail. Every refusal below names the item it refused,
     * and the name it prints is borrowed from `root` — cJSON owns those strings
     * and the message is formatted out of them. The one tail is what keeps the
     * two in order: the refusal is built while the tree still stands, and the
     * tree is deleted once, after it. `item` is the loop's scratch and the tail's
     * too, so an iteration that gives up midway leaves nothing behind. */
    error_t err = NULL;
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
         * and is bounded, a sheet being as long as a profile is wide.
         *
         * The pointer is inside json_str, so the subtraction is defined: the
         * parse that just failed set the position from the value it was handed
         * (lib/cjson/cJSON.c), and CHECK_NULL above says there was one. */
        const char *parse_end = cJSON_GetErrorPtr();
        err = error_create(
            ERR_INVALID_ARG, "Failed to parse metadata JSON at byte %zu: '%.24s'",
            (size_t) (parse_end - json_str), parse_end
        );
        goto cleanup;
    }

    /* Get and validate version */
    cJSON *version_obj = cJSON_GetObjectItem(root, "version");
    if (!version_obj || !cJSON_IsNumber(version_obj)) {
        err = error_create(
            ERR_INVALID_ARG, "Missing or invalid version in metadata"
        );
        goto cleanup;
    }

    int version = version_obj->valueint;
    if (version != METADATA_VERSION) {
        err = error_create(
            ERR_INVALID_ARG,
            "Unsupported metadata version: %d (this build reads %d)",
            version, METADATA_VERSION
        );
        goto cleanup;
    }

    /* Get items array */
    cJSON *items_array = cJSON_GetObjectItem(root, "items");
    if (!items_array || !cJSON_IsArray(items_array)) {
        err = error_create(
            ERR_INVALID_ARG, "Missing or invalid items array in metadata"
        );
        goto cleanup;
    }

    /* The sheet the items go into */
    metadata = metadata_create_empty();

    /* Parse each item in the unified array */
    cJSON *item_obj = NULL;
    cJSON_ArrayForEach(item_obj, items_array) {
        if (!cJSON_IsObject(item_obj)) {
            err = error_create(
                ERR_INVALID_ARG, "Invalid item in items array (not an object)"
            );
            goto cleanup;
        }

        /* Get kind discriminator (required) */
        cJSON *kind_obj = cJSON_GetObjectItem(item_obj, "kind");
        if (!kind_obj || !cJSON_IsString(kind_obj) || !kind_obj->valuestring) {
            err = error_create(
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
            err = error_create(
                ERR_INVALID_ARG, "Invalid kind value: '%s' "
                "(expected 'file' or 'directory')", kind_obj->valuestring
            );
            goto cleanup;
        }

        /* Get key (required) */
        cJSON *key_obj = cJSON_GetObjectItem(item_obj, "key");
        if (!key_obj || !cJSON_IsString(key_obj) || !key_obj->valuestring) {
            err = error_create(
                ERR_INVALID_ARG, "Item missing key field"
            );
            goto cleanup;
        }

        /* Validate key format (prevent path traversal): the refusal names the
         * key, which is a storage path */
        err = label_validate_storage(key_obj->valuestring);
        if (err) goto cleanup;

        /* Refuse a duplicated claim before the factory runs. A key holds one
         * item of each kind — a file's and a directory's at one key are two claims,
         * a document the decode reads — so a second item of one kind at a key
         * says two things about one claim. The kind's upsert would resolve that
         * silently, last-wins; a document that disagrees with itself gets the
         * same loud refusal every other malformation does, and names the kind,
         * which is what the key alone no longer says. Only a hand-edit or a
         * mis-resolved merge can author one. */
        if (metadata_find_item(metadata, kind, key_obj->valuestring)) {
            err = error_create(
                ERR_INVALID_ARG, "Duplicate %s item in metadata: '%s'",
                kind_obj->valuestring, key_obj->valuestring
            );
            goto cleanup;
        }

        /* Get mode (optional — absence is the mode a claim does not make) */
        mode_t mode = MODE_UNCLAIMED;
        cJSON *mode_obj = cJSON_GetObjectItem(item_obj, "mode");
        if (mode_obj) {
            if (!cJSON_IsString(mode_obj) || !mode_obj->valuestring) {
                err = error_create(
                    ERR_INVALID_ARG, "Invalid mode field (key: '%s')",
                    key_obj->valuestring
                );
                goto cleanup;
            }
            err = metadata_parse_mode(mode_obj->valuestring, &mode);
            if (err) {
                err = error_wrap(
                    err, "Failed to parse mode for item: '%s'",
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
                err = error_create(
                    ERR_INVALID_ARG, "Invalid owner field (key: '%s')",
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
                err = error_create(
                    ERR_INVALID_ARG, "Invalid group field (key: '%s')",
                    key_obj->valuestring
                );
                goto cleanup;
            }
            item->group = heap_strdup(group_obj->valuestring);
        }

        /* Hand the item to the sheet; it takes it, and leaves the loop's scratch
         * pointer NULL for the next iteration and the tail. */
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
 * Load metadata from a Git tree
 *
 * Loads metadata.json from a specific Git tree — a branch head or a historical
 * commit's tree alike. A tree without the sheet — no .dotta, or a .dotta directory
 * without the file — holds an empty sheet: the absence's arm is the one producer
 * of that answer, so no reader folds a not-found into a sheet of its own, and a
 * file at .dotta is never read as the absence. Every failure meets one tail,
 * which names the profile over it.
 */
error_t metadata_load_from_tree(
    git_repository *repo,
    const git_tree *tree,
    const char *profile,
    metadata_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    error_t err = NULL;
    git_tree_entry *entry = NULL;

    /* The sheet at its one name. No entry is a sheet claiming nothing — the settled
     * answer every reader wants — but Git's lookup answers not-found where a
     * file stands on the way exactly as where nothing does, and only the second
     * is that answer. A subtree that will not load on the way is -1, never
     * not-found: only a lookup that failed to look is an error, and a not-found
     * through a tree is the file's own absence (lib/libgit2/src/libgit2/tree.c
     * git_tree_entry_bypath). */
    int rc = git_tree_entry_bypath(&entry, tree, METADATA_FILE_PATH);
    if (rc == GIT_ENOTFOUND) {
        /* One rung can stand in the way, the sheet's directory, so it alone is
         * asked: absent, or a tree without the file, is the absence; a blob, a
         * link or a gitlink there is no sheet a reader may read as empty. */
        const git_tree_entry *dir = git_tree_entry_byname(tree, METADATA_DIR);
        if (!dir || git_tree_entry_type(dir) == GIT_OBJECT_TREE) {
            *out = metadata_create_empty();
            return NULL;
        }
        err = error_create(ERR_CONFLICT, "'%s' is a file in this tree", METADATA_DIR);
    } else if (rc < 0) {
        err = error_git(rc, "Cannot read '%s'", METADATA_FILE_PATH);
    }

    /* The blob's bytes, NUL-terminated for the parser, which writes *out on success
     * alone (metadata_from_json): nothing here holds a sheet across the tail */
    char *json_str = NULL;
    size_t size = 0;
    if (!err) {
        err = gitops_read_blob_content(
            repo, git_tree_entry_id(entry), (void **) &json_str, &size
        );
    }
    if (!err) err = metadata_from_json(json_str, out);

    free(json_str);
    git_tree_entry_free(entry);             /* NULL-safe, and NULL unless rc == 0 */

    /* Each step names its own — the file at .dotta, the entry, the blob, the
     * byte the parse stopped at — and none the profile, which this loader alone
     * was handed: said once, over whichever refused, so no caller says it again */
    return error_wrap(err, "Failed to load metadata for profile '%s'", profile);
}

/**
 * Save metadata to a stage
 *
 * The sheet serialized, then put at .dotta/metadata.json as a regular blob.
 */
error_t metadata_save_to_stage(
    stage_t *stage,
    const metadata_t *metadata
) {
    CHECK_NULL(stage);
    CHECK_NULL(metadata);

    buffer_t json = metadata_to_json(metadata);

    error_t err = stage_put(
        stage, METADATA_FILE_PATH, json.data, json.size, GIT_FILEMODE_BLOB, NULL
    );
    buffer_deinit(&json);

    return err;
}

/**
 * The sheet's word on a path's ownership, as this host's ids
 *
 * Each half by its own rule (metadata.h), written to the outs together, so a
 * half that resolved never survives the other's miss.
 */
metadata_ownership_t metadata_ownership(
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
        if (!pwd) return METADATA_OWNERSHIP_NO_SUCH_USER;
        uid = pwd->pw_uid;
    }

    /* And a named group its gid — never the owner's primary: a claim that names
     * no group constrains none */
    if (group) {
        struct group *grp = getgrnam(group);
        if (!grp) return METADATA_OWNERSHIP_NO_SUCH_GROUP;
        gid = grp->gr_gid;
    }

    *out_uid = uid;
    *out_gid = gid;
    return METADATA_OWNERSHIP_RESOLVED;
}
