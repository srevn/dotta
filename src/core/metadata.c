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
 * One kind's claims, in key order
 *
 * The order is the document's (metadata_to_json): byte order on the key. So a
 * sheet the serializer wrote parses in place, a writer's edits land where their
 * keys fall, and every question the sheet asks of its claims is one search of
 * the order — where a key stands (metadata_place), and which claims stand beneath
 * a name (metadata_bound). The order is the one representation: nothing beside
 * it says where a claim is, so nothing has to agree with it. A claim is written
 * once and never again — a write that makes one over stores another — so the
 * entries move and the claims never do, and the kind lends its entries as they
 * are typed.
 */
typedef struct {
    const metadata_item_t **entries;   /* The claims, in key order */
    size_t count;                      /* Claims held */
    size_t capacity;                   /* Entries allocated */
} metadata_claims_t;

/**
 * The sheet: each kind's claims apart
 *
 * A key holds at most one claim of each kind (metadata.h), and the two kinds
 * never share an order, so a write of one kind cannot reach the other's claim
 * at its key. One kind's claims are chosen where they are read — a directory's,
 * or else a file's — and the readers of both at once take the files first.
 *
 * A container in its owner's arena (metadata.h): the struct, each kind's entries
 * and every name a claim spells live there, and go with the arena.
 *
 * The schema version is the document's, not the sheet's: metadata_to_json writes
 * METADATA_VERSION and metadata_from_json refuses anything else, so there is
 * nothing here for a version field to say.
 */
struct metadata {
    arena_t *arena;                   /* The owner's: the struct, the entries, the claims */
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
 * Where `key` stands in one kind's order, or would: whether a claim stands there
 *
 * Readers: metadata_write_item, metadata_find_item and metadata_remove_item.
 *
 * @param claims One kind's claims, in key order
 * @param key The key
 * @param place Its place, in [0, claims->count]
 * @return true where a claim stands at `key`
 */
static bool metadata_place(const metadata_claims_t *claims, const char *key, size_t *place) {
    /* Past the last claim: a document the serializer wrote, and a copy, arrive
     * in key order, so each of their keys falls here, one comparison deciding it */
    if (claims->count == 0 || strcmp(claims->entries[claims->count - 1]->key, key) < 0) {
        *place = claims->count;
        return false;
    }

    /* Any other key is one search. The last claim is not before it, so the place
     * the search finds holds a claim: the key's own, or the next */
    *place = metadata_bound(claims, key, '\0');
    return strcmp(claims->entries[*place]->key, key) == 0;
}

/**
 * An empty sheet, in `arena`
 */
metadata_t *metadata_create(arena_t *arena) {
    CHECK_NULL(arena);

    /* The sheet in its owner's arena, each kind's entries made there with it —
     * room at once, so each kind lends an array even while it holds nothing,
     * which every slice of it offsets into (metadata_items,
     * metadata_items_beneath) */
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
 * A copy of the sheet
 *
 * Each claim written into a sheet of the copy's own, each kind in the source's
 * key order, so every write lands past the last, one comparison deciding it,
 * and the copy's names are its arena's.
 */
metadata_t *metadata_clone(arena_t *arena, const metadata_t *metadata) {
    CHECK_NULL(arena);
    CHECK_NULL(metadata);

    /* Each kind's room made at the source's count, so the copy grows no array
     * and abandons none to the arena; then each claim written, in the source's
     * order */
    metadata_t *copy = metadata_create(arena);
    const metadata_claims_t *from[] = { &metadata->files, &metadata->directories };
    metadata_claims_t *into[] = { &copy->files, &copy->directories };
    for (size_t k = 0; k < sizeof(from) / sizeof(from[0]); k++) {
        into[k]->entries = arena_grow(
            arena, into[k]->entries, &into[k]->capacity, from[k]->count,
            sizeof(*into[k]->entries)
        );
        for (size_t i = 0; i < from[k]->count; i++) {
            metadata_write_item(copy, from[k]->entries[i]);
        }
    }

    return copy;
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
 * Readers: metadata_same, claim by claim, the two sheets in step; and
 * metadata_write_item, a claim against the one standing at its key.
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
 * Write a claim
 *
 * Its contract first, the one way in; then the existence rule; then its place
 * in its kind's order, a claim there made over unless it says the same, or room
 * made for one new to the kind.
 */
bool metadata_write_item(metadata_t *metadata, const metadata_item_t *item) {
    CHECK_NULL(metadata);
    CHECK_NULL(item);
    CHECK_NULL(item->key);

    /* A mode is claimed bits or absence — nothing in between — and each flag is
     * its own kind's: every producer masks a stat's bits or parses a mode that
     * refuses more, and builds the flag of the kind it builds */
    CHECK_ARG(item->mode == MODE_UNCLAIMED || item->mode <= 0777, "mode past 0777");
    CHECK_ARG(
        item->kind == PATH_KIND_DIRECTORY ? !item->encrypted : !item->tracked,
        "a flag the item's kind cannot carry"
    );

    /* An item exists iff it claims something: a file's that claims nothing is
     * no claim, and its write retires the one standing at its key. The parse
     * reads such an item past by the same test (metadata_from_json), so a sheet
     * it reads and a copy of it, written claim by claim, hold the same claims */
    if (item->kind == PATH_KIND_FILE && item->mode == MODE_UNCLAIMED &&
        !item->owner && !item->group && !item->encrypted) {
        return metadata_remove_item(metadata, PATH_KIND_FILE, item->key);
    }

    /* The item's own kind's claims, the only ones it can meet: the other kind's
     * claim at its key is another claim, and stays as it stands */
    metadata_claims_t *claims = item->kind == PATH_KIND_DIRECTORY
        ? &metadata->directories : &metadata->files;

    size_t place;
    if (metadata_place(claims, item->key, &place)) {
        /* The claim at its key: left as it stands where the item says the same,
         * so a write that changes nothing moves nothing */
        if (metadata_same_claim(claims->entries[place], item)) return false;
    } else {
        /* None: room at the key's place, the claims past it moved up one — the
         * entries alone, every claim staying where it was written, but one move
         * a claim out of place: a writer writing in an order of its own, a walk
         * in readdir's, pays a run of them, where a document in key order lands
         * past the last */
        claims->entries = arena_grow(
            metadata->arena, claims->entries, &claims->capacity, claims->count + 1,
            sizeof(*claims->entries)
        );
        memmove(
            &claims->entries[place + 1], &claims->entries[place],
            (claims->count - place) * sizeof(*claims->entries)
        );
        claims->count++;
    }

    /* The claim the sheet keeps at its key: its own copy in the arena, the names
     * with it, written here and never again — so a claim the sheet lent stands
     * as it was lent, and one this write replaces stays whole for whoever holds
     * it */
    metadata_item_t *claim = arena_alloc(metadata->arena, sizeof(*claim));
    *claim = *item;
    claim->key = arena_strdup(metadata->arena, item->key);
    claim->owner = arena_strdup(metadata->arena, item->owner);
    claim->group = arena_strdup(metadata->arena, item->group);
    claims->entries[place] = claim;

    return true;
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
        .entries = claims->entries + first,
        .count = past - first,
    };
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

    /* The gap closed: the entries past it move down one, and nothing is freed —
     * the claim stays whole in the arena for whoever holds it, `key` among it
     * where `key` is the claim's own */
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

    /* The kind's own entries, borrowed. Their room is made with the sheet
     * (metadata_create), so an empty kind lends an array too. */
    const metadata_claims_t *claims = kind == PATH_KIND_DIRECTORY
        ? &metadata->directories : &metadata->files;

    return (metadata_items_t){
        .entries = claims->entries,
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
 * On failure the item's owner may be set without its group — the caller's item
 * is a local it hands out on success alone, so no sheet and no caller ever sees
 * half of one, and the name left in the arena is unreachable.
 *
 * @param item Item to set ownership on (must not be NULL)
 * @param storage_path The item's key, for the one clause its label decides (must
 *                     not be NULL, under a label)
 * @param st Stat data with uid/gid (must not be NULL)
 * @param arena The arena the names are spelled in
 * @return Error or NULL on success — NULL with nothing named where absence says it
 *
 * Errors:
 * - ERR_NOT_FOUND: the UID or the GID has no name on this system
 */
static error_t metadata_capture_ownership(
    metadata_item_t *item,
    const char *storage_path,
    const struct stat *st,
    arena_t *arena
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

    item->owner = arena_strdup(arena, pwd->pw_name);

    /* Resolve GID to groupname: the owner brings its group with it */
    struct group *grp = getgrgid(st->st_gid);
    if (!grp || !grp->gr_name) {
        return error_create(
            ERR_NOT_FOUND, "Cannot resolve GID %u, the group of '%s', to a group name "
            "on this system", (unsigned) st->st_gid, storage_path
        );
    }

    item->group = arena_strdup(arena, grp->gr_name);

    return NULL;
}

/**
 * Capture a path's claim from stat data (regular file or symlink)
 *
 * The claim off the look, whatever it claims: a link the invoker owns claims
 * nothing, and its write is no item (metadata_write_item).
 */
error_t metadata_capture_file(
    const char *storage_path,
    const struct stat *st,
    bool encrypted,
    arena_t *arena,
    metadata_item_t *out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(st);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The kind the capture established, asked once more as a contract and not
     * as a refusal: no path reaches here that a capture did not take (the header),
     * so a device, a FIFO or a socket is a caller's error. */
    CHECK_ARG(
        S_ISREG(st->st_mode) || S_ISLNK(st->st_mode),
        "st must be a regular file's or a symlink's"
    );

    /* The look's mode — a link claims none, symlink(2) taking none — and the
     * seal the caller's word */
    metadata_item_t item = {
        .kind      = PATH_KIND_FILE,
        .key       = storage_path,
        .mode      = S_ISLNK(st->st_mode) ? MODE_UNCLAIMED : (st->st_mode & 0777),
        .encrypted = encrypted,
    };

    /* Ownership, where absence would misstate it (metadata_capture_ownership).
     * The lstat needs no privilege, so the claim is authored by whoever can read
     * the path. */
    error_t err = metadata_capture_ownership(&item, storage_path, st, arena);
    if (err) return err;

    *out = item;
    return NULL;
}

/**
 * Capture a directory's claim from stat data
 *
 * A directory item off the look: the stat's permission bits, ownership by the
 * file capture's rule (metadata_capture_ownership), and the class the caller's,
 * carried through unread.
 */
error_t metadata_capture_directory(
    const char *storage_path,
    const struct stat *st,
    bool tracked,
    arena_t *arena,
    metadata_item_t *out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(st);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The kind the caller established, asked once more as a contract and not as
     * a refusal: every caller held its look to a directory first (the header),
     * so a file, a link or anything else is a caller's error. */
    CHECK_ARG(S_ISDIR(st->st_mode), "st must be a directory's");

    /* The stat's permission bits, and the class the caller's */
    metadata_item_t item = {
        .kind    = PATH_KIND_DIRECTORY,
        .key     = storage_path,
        .mode    = st->st_mode & 0777,
        .tracked = tracked,
    };

    /* Ownership, by the file capture's rule (metadata_capture_ownership) */
    error_t err = metadata_capture_ownership(&item, storage_path, st, arena);
    if (err) return err;

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
     * (metadata_write_item), so the document's order is one merge of the two, a
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

        /* Add encrypted flag iff true — false for DIRECTORY, held at the one
         * way into a sheet (metadata_write_item), so no kind test stands here */
        if (item->encrypted) {
            cJSON_AddBoolToObject(item_obj, "encrypted", true);
        }

        /* And tracked, the other flag one kind carries: false for FILE by the
         * same contract, and absent on a directory that says the profile only
         * passes through it. The two are mutually exclusive, so they print in
         * one place. */
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
 * and a file's item that claims nothing is no claim, read past as the sheet's
 * own rule reads it (metadata_write_item) — strictness lives where the fact is
 * authored, not here. A present mode, owner or group is a value of its kind or
 * a refusal all the same: a mode that parses, a name.
 */
error_t metadata_from_json(const char *json, size_t size, arena_t *arena, metadata_t **out) {
    CHECK_NULL(json);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The document's bytes, `size` of them: a blob a view lends carries no
     * terminator, and the parse reads none (lib/cjson/cJSON.c
     * cJSON_ParseWithLengthOpts) */
    cJSON *root = cJSON_ParseWithLength(json, size);
    if (!root) {
        /* cJSON hands back the position the parse stopped at, not the token that
         * failed, so printing to the end prints the whole remainder of the document
         * — a 50 KB sheet with an early syntax error yields a 50 KB message.
         * The offset is the fact; the excerpt beside it is a courtesy, bounded
         * by the bytes left as much as by its own width, nothing past them being
         * the document's.
         *
         * The pointer is inside the bytes, so the subtraction is defined: the
         * parse that just failed set the position from the value it was handed,
         * short of its length — at most the last byte, and the first where there
         * is none (lib/cjson/cJSON.c cJSON_ParseWithLengthOpts) — and CHECK_NULL
         * above says there was one. */
        const char *parse_end = cJSON_GetErrorPtr();
        const size_t offset = (size_t) (parse_end - json);
        return error_create(
            ERR_INVALID_ARG, "Failed to parse metadata JSON at byte %zu: '%.*s'",
            offset, (int) (size - offset < 24 ? size - offset : 24), parse_end
        );
    }

    /* One resource, one tail. Every refusal below names the item it refused,
     * and the name it prints is borrowed from `root` — cJSON owns those strings
     * and the message is formatted out of them, as each item's write copies what
     * the sheet keeps. The one tail is what keeps the two in order: the refusal
     * is built while the tree still stands, and the tree is deleted once, after
     * it. The sheet is the arena's, so a refusal past the first item leaves what
     * was written there, unreachable. */
    error_t err = NULL;
    metadata_t *metadata = NULL;

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

    /* The sheet the items go into, each kind's room made at once from the
     * document's own count of it, so a sheet as large as a profile is wide grows
     * no array and abandons none to the arena. A count is a reserve, not a promise:
     * an item the loop below refuses ends the parse, and one it reads past leaves
     * a slot unused. */
    metadata = metadata_create(arena);
    size_t file_count = 0;
    size_t directory_count = 0;
    cJSON *counted = NULL;
    cJSON_ArrayForEach(counted, items_array) {
        const cJSON *kind_obj = cJSON_GetObjectItem(counted, "kind");
        if (!cJSON_IsString(kind_obj) || !kind_obj->valuestring) continue;

        if (strcmp(kind_obj->valuestring, "file") == 0) {
            file_count++;
        } else if (strcmp(kind_obj->valuestring, "directory") == 0) {
            directory_count++;
        }
    }
    metadata->files.entries = arena_grow(
        arena, metadata->files.entries, &metadata->files.capacity, file_count,
        sizeof(*metadata->files.entries)
    );
    metadata->directories.entries = arena_grow(
        arena, metadata->directories.entries, &metadata->directories.capacity,
        directory_count, sizeof(*metadata->directories.entries)
    );

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

        /* Ownership, present iff the item claims it — and a present half is a
         * name, mode's own rule: a field that is here says something, so a
         * non-string (a uid typed as a number, a null) or an empty name is refused
         * as a field, never dropped and never kept for a resolver no host can
         * answer. No producer writes one; a hand does, and the parser is where
         * a hand is answered. What an absent half means is decided where the
         * claim is read (metadata_ownership), never here: a claim standing under
         * any label is parsed as it stands. */
        cJSON *owner_obj = cJSON_GetObjectItem(item_obj, "owner");
        if (owner_obj &&
            (!cJSON_IsString(owner_obj) || !owner_obj->valuestring || !*owner_obj->valuestring)) {
            err = error_create(
                ERR_INVALID_ARG, "Invalid owner field (key: '%s')",
                key_obj->valuestring
            );
            goto cleanup;
        }

        /* The group, the other half of the same claim, by the same rule */
        cJSON *group_obj = cJSON_GetObjectItem(item_obj, "group");
        if (group_obj &&
            (!cJSON_IsString(group_obj) || !group_obj->valuestring || !*group_obj->valuestring)) {
            err = error_create(
                ERR_INVALID_ARG, "Invalid group field (key: '%s')",
                key_obj->valuestring
            );
            goto cleanup;
        }

        /* The claim as the document makes it, its names borrowed from the tree
         * until its write copies them. Each of the two flags is read for its
         * own kind alone, so one hand-written onto the kind that cannot carry
         * it is read past, inert — and the next rewrite drops it. A directory
         * item with no "tracked" is an ancestor claim, never a walked one read
         * leniently: the field's absence is its meaning, which is what makes
         * losing it fail safe. */
        const metadata_item_t item = {
            .kind      = kind,
            .key       = key_obj->valuestring,
            .mode      = mode,
            .owner     = owner_obj ? owner_obj->valuestring : NULL,
            .group     = group_obj ? group_obj->valuestring : NULL,
            .encrypted = kind == PATH_KIND_FILE &&
                cJSON_IsTrue(cJSON_GetObjectItem(item_obj, "encrypted")),
            .tracked   = kind == PATH_KIND_DIRECTORY &&
                cJSON_IsTrue(cJSON_GetObjectItem(item_obj, "tracked")),
        };

        /* A file's item that claims nothing is no claim, by the test the write
         * keeps the sheet's rule with (metadata_write_item), so it is read past:
         * the write would retire what stands at its key, and a copy of the sheet,
         * written claim by claim, would no longer be the sheet. Read past before
         * the duplicate test, it is a second of nothing, whichever order the
         * document spells it and a claim at its key in. */
        if (item.kind == PATH_KIND_FILE && item.mode == MODE_UNCLAIMED &&
            !item.owner && !item.group && !item.encrypted) {
            continue;
        }

        /* Refuse a duplicated claim. A key holds one claim of each kind — a file's
         * item and a directory's at one key are two claims, a document the decode
         * reads — so a second claim of one kind at a key says two things about
         * one claim. The kind's write would resolve that silently, last-wins; a
         * document that disagrees with itself gets the same loud refusal every
         * other malformation does, and names the kind, which is what the key
         * alone no longer says. Only a hand-edit or a mis-resolved merge can
         * author one. */
        if (metadata_find_item(metadata, kind, item.key)) {
            err = error_create(
                ERR_INVALID_ARG, "Duplicate %s item in metadata: '%s'",
                kind_obj->valuestring, key_obj->valuestring
            );
            goto cleanup;
        }

        metadata_write_item(metadata, &item);
    }

    /* Success - transfer to caller */
    *out = metadata;

cleanup:
    cJSON_Delete(root);

    return err;
}

/**
 * Load metadata from a Git tree
 *
 * Loads metadata.json from a specific Git tree — a branch head or a historical
 * commit's tree alike — through the tree's own repository. A tree without the
 * sheet — no .dotta, or a .dotta directory without the file — holds an empty
 * sheet: the absence's arm is the one producer of that answer, so no reader folds
 * a not-found into a sheet of its own, and a file at .dotta is never read as
 * the absence. Every failure meets one tail, which names the profile over it.
 */
error_t metadata_load_from_tree(
    const git_tree *tree,
    const char *profile,
    arena_t *arena,
    metadata_t **out
) {
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(arena);
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
            *out = metadata_create(arena);
            return NULL;
        }
        err = error_create(ERR_CONFLICT, "'%s' is a file in this tree", METADATA_DIR);
    } else if (rc < 0) {
        err = error_git(rc, "Cannot read '%s'", METADATA_FILE_PATH);
    }

    /* The blob's bytes, lent for the parse, through the repository the tree was
     * read from, which a tree knows (lib/libgit2/src/libgit2/object.c
     * git_object_owner): the parse takes them with their length and copies what
     * the sheet keeps, writing *out on success alone (metadata_from_json), so
     * nothing here holds a sheet across the tail. A view never opened closes as
     * nothing (sys/gitops.h gitops_blob_view_close). */
    gitops_blob_view_t view = { 0 };
    if (!err) err = gitops_blob_view_open(git_tree_owner(tree), git_tree_entry_id(entry), &view);
    if (!err) err = metadata_from_json(view.data, view.size, arena, out);

    gitops_blob_view_close(&view);
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
