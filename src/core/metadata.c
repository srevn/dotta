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

#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "infra/mount.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/privilege.h"

#define INITIAL_CAPACITY 16

/**
 * Unified metadata collection
 *
 * A spine of pointers to items the collection owns, and a key index over them.
 * An item is stable from the moment it is created — only the spine is ever
 * reallocated — so the index stores item pointers directly and metadata_items
 * hands the spine out as the public slice. The index borrows each item's own
 * key (hashmap_borrow), which is why it is freed before the items are — and why
 * metadata_add_item's update arm must adopt the standing key before it overwrites
 * the slot: the key-adoption dance is the borrow's cost.
 *
 * The schema version is the document's, not the collection's: metadata_to_json
 * writes METADATA_VERSION and metadata_from_json refuses anything else, so there
 * is nothing here for a version field to say.
 */
struct metadata {
    metadata_item_t **items;         /* Spine of stable items, in insertion order */
    size_t count;                    /* Items held */
    size_t capacity;                 /* Spine slots allocated */
    hashmap_t *index;                /* key -> item*, borrowing the item's own key */
};

/**
 * Create empty metadata collection
 */
error_t *metadata_create_empty(metadata_t **out) {
    CHECK_NULL(out);

    metadata_t *metadata = calloc(1, sizeof(metadata_t));
    if (!metadata) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata structure");
    }

    /* Allocate the item spine */
    metadata->items = calloc(INITIAL_CAPACITY, sizeof(*metadata->items));
    if (!metadata->items) {
        free(metadata);
        return ERROR(ERR_MEMORY, "Failed to allocate metadata items array");
    }

    /* Create unified hashmap for O(1) lookups */
    metadata->index = hashmap_borrow(INITIAL_CAPACITY);
    if (!metadata->index) {
        free(metadata->items);
        free(metadata);
        return ERROR(ERR_MEMORY, "Failed to allocate metadata index");
    }

    metadata->count = 0;
    metadata->capacity = INITIAL_CAPACITY;

    *out = metadata;
    return NULL;
}

/**
 * Free metadata item
 */
void metadata_item_free(metadata_item_t *item) {
    if (!item) {
        return;
    }

    free(item->key);
    free(item->owner);
    free(item->group);

    free(item);
}

/**
 * Free metadata structure
 *
 * Frees every item it holds and the structure itself.
 */
void metadata_free(metadata_t *metadata) {
    if (!metadata) {
        return;
    }

    /* Free index first — it borrows the key pointer of every item */
    hashmap_free(metadata->index, NULL);

    /* Free all items (files, directories, and symlinks) */
    for (size_t i = 0; i < metadata->count; i++) {
        metadata_item_free(metadata->items[i]);
    }

    free(metadata->items);
    free(metadata);
}

/**
 * Create file metadata item
 */
error_t *metadata_item_create_file(
    const char *storage_path,
    mode_t mode,
    bool encrypted,
    metadata_item_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    /* A mode is claimed bits or absence — nothing in between */
    if (mode != MODE_UNCLAIMED && mode > 0777) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)",
            mode
        );
    }

    metadata_item_t *item = calloc(1, sizeof(metadata_item_t));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata item");
    }

    item->kind = PATH_KIND_FILE;

    item->key = strdup(storage_path);
    if (!item->key) {
        free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate storage path");
    }

    item->mode = mode;
    item->owner = NULL;    /* Optional, set by caller if needed */
    item->group = NULL;    /* Optional, set by caller if needed */
    item->encrypted = encrypted;
    item->tracked = false; /* A file is no directory to manage */

    *out = item;
    return NULL;
}

/**
 * Create directory metadata item
 */
error_t *metadata_item_create_directory(
    const char *storage_path,
    mode_t mode,
    bool tracked,
    metadata_item_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    /* A mode is claimed bits or absence — nothing in between */
    if (mode != MODE_UNCLAIMED && mode > 0777) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)",
            mode
        );
    }

    metadata_item_t *item = calloc(1, sizeof(metadata_item_t));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata item");
    }

    item->kind = PATH_KIND_DIRECTORY;

    item->key = strdup(storage_path);
    if (!item->key) {
        free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate storage path");
    }

    item->mode = mode;
    item->owner = NULL;      /* Optional, set by caller if needed */
    item->group = NULL;      /* Optional, set by caller if needed */
    item->encrypted = false; /* A directory has no blob to stamp */
    item->tracked = tracked;

    *out = item;
    return NULL;
}

/**
 * Clone metadata item (deep copy)
 *
 * Creates a deep copy of a metadata item, duplicating all strings. This is useful
 * when you need to preserve an item while modifying the original collection.
 *
 * @param source Source item to clone (must not be NULL)
 * @param out Cloned item (must not be NULL, caller must free with
 *            metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_item_clone(const metadata_item_t *source, metadata_item_t **out) {
    CHECK_NULL(source);
    CHECK_NULL(out);

    metadata_item_t *item = calloc(1, sizeof(metadata_item_t));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata item");
    }

    /* Everything that is not a pointer copies wholesale — kind, mode and encrypted,
     * so a field added later needs no line here. The three strings are then
     * re-owned, and the one refusal covers all three. */
    *item = *source;
    item->key = strdup(source->key);
    item->owner = source->owner ? strdup(source->owner) : NULL;
    item->group = source->group ? strdup(source->group) : NULL;

    if (!item->key ||
        (source->owner && !item->owner) ||
        (source->group && !item->group)) {
        metadata_item_free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate metadata item strings");
    }

    *out = item;
    return NULL;
}

/**
 * Grow the item spine if it is full
 *
 * Doubles the spine when it fills. Only the spine moves — the items it points
 * at stay where they were created — so the index needs no maintenance here.
 *
 * @param metadata Metadata structure (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *ensure_capacity(metadata_t *metadata) {
    CHECK_NULL(metadata);

    if (metadata->count < metadata->capacity) {
        return NULL; /* No need to grow */
    }

    size_t new_capacity = metadata->capacity * 2;
    if (new_capacity < metadata->capacity ||
        new_capacity > SIZE_MAX / sizeof(*metadata->items)) {
        return ERROR(ERR_MEMORY, "Metadata collection too large to grow");
    }

    metadata_item_t **new_items = realloc(
        metadata->items,
        new_capacity * sizeof(*new_items)
    );

    if (!new_items) {
        return ERROR(ERR_MEMORY, "Failed to grow metadata items array");
    }

    metadata->items = new_items;
    metadata->capacity = new_capacity;

    return NULL;
}

/**
 * Add or update metadata item, transferring ownership
 *
 * Works for every kind. If an item with the same key exists it is replaced in
 * place; otherwise the item is appended.
 *
 * The collection stores pointers, so an item handed to it is taken rather than
 * copied: it keeps its place in memory, the collection keeps the pointer, and
 * the caller's handle is cleared. Both steps that can refuse — growing the spine
 * and indexing the item — run before anything is published, so a refusal leaves
 * the collection exactly as it was and the item still the caller's.
 *
 * A mode arrives already validated: the two factories are the only construction
 * paths, metadata_item_clone copies an item one of them built, and no caller
 * mutates the field afterwards. Re-checking it here would be a second boundary
 * for a fact this function does not own.
 */
error_t *metadata_add_item(
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
         * the old one. Nothing here can fail. */
        free(incoming->key);
        incoming->key = existing->key;

        free(existing->owner);
        free(existing->group);

        *existing = *incoming;
        free(incoming);
        *item = NULL;

        return NULL;
    }

    /* APPEND NEW ITEM
     *
     * Both refusals come first: a spine that cannot grow, and an index that cannot
     * take the key. Neither has published anything, so the caller keeps the item
     * and the collection is untouched. */
    error_t *err = ensure_capacity(metadata);
    if (err) {
        return err;
    }

    err = hashmap_set(metadata->index, incoming->key, incoming);
    if (err) {
        return error_wrap(err, "Failed to index metadata item");
    }

    metadata->items[metadata->count++] = incoming;
    *item = NULL;

    return NULL;
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
    if (!metadata || !key) {
        return NULL;
    }

    return hashmap_get(metadata->index, key);
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
    if (!metadata || !key) {
        return false;
    }

    /* The index answers identity. A key the collection does not hold is answered
     * here and costs one probe — the walk below is for position, and there is
     * no position to find. */
    metadata_item_t *item = hashmap_get(metadata->index, key);
    if (!item) {
        return false;
    }

    /* Only the spine carries position, so only a walk gives it. What the index
     * bought is the comparison: the item is already named, so this reads the
     * spine's own pointers rather than chasing each item's key into a strcmp.
     * The two agree by construction — the add publishes to both or neither and
     * its update arm mutates the standing item in place, so the value the index
     * holds is the pointer some spine slot holds. */
    for (size_t i = 0; i < metadata->count; i++) {
        if (metadata->items[i] != item) {
            continue;
        }

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
 * Does this directory claim anything of its own?
 *
 * The one predicate two questions read: whether an item is residue-eligible at
 * all, and whether it can anchor a claim above it. They are the same question —
 * an item that claims nothing of its own survives solely by being anchored, so
 * it is never the reason another item survives, and letting the two drift would
 * hold a doomed chain alive one command per rung.
 *
 * A tracked claim is the walk's word about a directory the profile manages: a
 * mode the umask would not have produced, or any ownership overlay, is intent
 * the sheet keeps with nothing beneath it. An ancestor claim is derived from
 * the chain above a managed path — it exists because something beneath it does,
 * and no attribute it carries can make it say anything else.
 *
 * @param dir Directory item (must not be NULL; asked of no other kind)
 * @return true if the claim stands without anything beneath it
 */
static bool claims_intent(const metadata_item_t *dir) {
    if (!dir->tracked) {
        return false;
    }
    if (dir->mode != DIR_MODE_DEFAULT && dir->mode != MODE_UNCLAIMED) {
        return true;
    }

    return dir->owner != NULL || dir->group != NULL;
}

/**
 * Prune redundant directory entries
 *
 * Two-pass collect-then-prune: metadata_remove_item frees the item it removes
 * and shifts the spine behind it, so the pass that decides cannot also be the
 * pass that acts. string_array_push duplicates each key, so the prune pass operates
 * on independent strings.
 */
error_t *metadata_prune_directories(
    metadata_t *metadata,
    git_index *index,
    string_array_t *pruned
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
        if (dir->kind != PATH_KIND_DIRECTORY) continue;

        /* The first question: an entry that claims something of its own is kept
         * whatever stands beneath it. */
        if (claims_intent(dir)) continue;

        /* The second, half of it: any path under the directory that a tree can
         * hold. Metadata items are not the universe there — a symlink tracked
         * without elevation carries no item, yet still anchors its parent — so
         * the index is the authority. It is sorted, so one prefix probe answers;
         * a failed look must not prune. */
        char *prefix = str_format("%s/", dir->key);
        if (!prefix) {
            return ERROR(ERR_MEMORY, "Failed to build directory prefix");
        }
        size_t position;
        int rc = git_index_find_prefix(&position, index, prefix);
        free(prefix);
        if (rc == 0) continue;
        if (rc != GIT_ENOTFOUND) return error_from_git(rc);

        /* And the other half: the paths a tree cannot hold. An empty directory
         * is named by its own claim and by nothing else, so a claim that stands
         * on its own anchors everything above it — and one that does not is passed
         * over, since it survives only by being anchored itself. */
        const size_t key_len = strlen(dir->key);
        bool anchored = false;
        for (size_t a = 0; !anchored && a < item_count; a++) {
            anchored = items[a]->kind == PATH_KIND_DIRECTORY &&
                claims_intent(items[a]) &&
                str_path_beneath(items[a]->key, dir->key, key_len);
        }
        if (anchored) continue;

        error_t *err = string_array_push(pruned, dir->key);
        if (err) {
            return error_wrap(err, "Failed to record redundant directory");
        }
    }

    /* Every key here was read off an item the walk above just saw, so each names
     * something that is there to remove. */
    for (size_t i = first; i < pruned->count; i++) {
        metadata_remove_item(metadata, pruned->items[i]);
    }

    return NULL;
}

/**
 * Encrypted flag for a file entry
 *
 * A key that is absent, held as a directory, or held unstamped answers false.
 *
 * Used by historical operations (diff, show, revert) to extract the encrypted
 * flag from metadata loaded from Git commits. Workspace-backed operations read
 * the view row's encrypted flag, which manifest_build projects from this metadata.
 *
 * @param metadata Metadata collection (can be NULL)
 * @param storage_path Storage path to lookup (can be NULL)
 * @return Encrypted flag (false if not found or not a stamped file)
 */
bool metadata_file_encrypted(
    const metadata_t *metadata,
    const char *storage_path
) {
    const metadata_item_t *item = metadata_lookup(metadata, storage_path);

    return item && item->kind == PATH_KIND_FILE && item->encrypted;
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
 * Capture ownership from stat data into metadata item
 *
 * Names the stat's UID and GID, both or neither. A capture states what it saw,
 * and half of what it saw is a different statement: the read boundary takes a
 * lone "group" as a deliberate chgrp-only intent (metadata_resolve_ownership
 * leaves the UID at -1) and a lone "owner" as "and the user's primary group",
 * so a name that merely failed to resolve becomes indistinguishable from a claim
 * the profile meant to make narrow. The claim this host cannot spell is an error
 * here, where the user is at the terminal and the path is still theirs to fix,
 * rather than a silence for deploy to act on a year later on another machine.
 *
 * On failure item fields may be partially set — the caller frees the item on
 * error either way, and the sheet only ever sees an item this function returned
 * success for.
 *
 * @param item Item to set ownership on (must not be NULL)
 * @param st Stat data with uid/gid (must not be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_NOT_FOUND: the UID or the GID has no name on this system
 */
static error_t *capture_ownership(
    metadata_item_t *item,
    const struct stat *st
) {
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

    item->owner = strdup(pwd->pw_name);
    if (!item->owner) {
        return ERROR(ERR_MEMORY, "Failed to allocate owner string");
    }

    /* Resolve GID to groupname */
    struct group *grp = getgrgid(st->st_gid);
    if (!grp || !grp->gr_name) {
        return ERROR(
            ERR_NOT_FOUND, "Cannot resolve GID %u to a group name on this system",
            (unsigned) st->st_gid
        );
    }

    item->group = strdup(grp->gr_name);
    if (!item->group) {
        return ERROR(ERR_MEMORY, "Failed to allocate group string");
    }

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
error_t *metadata_capture_from_file(
    const char *filesystem_path,
    const char *storage_path,
    const struct stat *st,
    metadata_item_t **out
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(st);
    CHECK_NULL(out);

    /* Reject devices, FIFOs, sockets */
    if (!S_ISREG(st->st_mode) && !S_ISLNK(st->st_mode)) {
        return ERROR(
            ERR_INVALID_ARG, "Not a regular file or symlink: %s",
            filesystem_path
        );
    }

    /* A link claims no mode — symlink(2) takes none */
    mode_t mode = S_ISLNK(st->st_mode) ? MODE_UNCLAIMED : (st->st_mode & 0777);

    metadata_item_t *item = NULL;
    error_t *err = metadata_item_create_file(storage_path, mode, false, &item);
    if (err) {
        return err;
    }

    /* Capture ownership for paths whose label tracks it (root/ and custom/).
     * The vocabulary lives in the mount spec; the elevation gate stays here because
     * ownership capture needs root either way. */
    const mount_spec_t *spec = mount_spec_for_path(storage_path);
    if (spec && spec->tracks_ownership && privilege_is_elevated()) {
        err = capture_ownership(item, st);
        if (err) {
            metadata_item_free(item);
            return err;
        }
    }
    /* For home/ prefix or when not running as root: owner/group remain NULL */

    /* An item exists iff it claims something. Only a link reaches the branch —
     * a regular file always claims its mode — and only one kind of link: asked
     * after ownership resolution, which by now has either named both halves or
     * failed, what falls out here is a link the capture had no ownership to take
     * (a label that does not track it, or an unelevated run), never one whose
     * owner this host could not spell. No empty entry is ever authored. */
    if (item->mode == MODE_UNCLAIMED && !item->owner && !item->group) {
        metadata_item_free(item);
        *out = NULL;
        return NULL;
    }

    *out = item;
    return NULL;
}

/**
 * Capture metadata from filesystem directory
 *
 * Creates a directory metadata item from stat data. Follows the same ownership
 * rules as file capture; the class is the caller's, carried through unread.
 *
 * Ownership capture (user/group):
 * - ONLY captured for root/ and custom/ prefix directories when running as root
 *   (UID 0)
 * - home/ prefix directories: ownership never captured (always current user)
 * - Regular users: ownership never captured (can't chown anyway)
 *
 * This function creates a metadata_item_t with kind=DIRECTORY.
 */
error_t *metadata_capture_from_directory(
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

    /* Create directory item via factory (handles allocation, key duplication,
     * mode validation) */
    mode_t mode = st->st_mode & 0777;
    metadata_item_t *item = NULL;
    error_t *err = metadata_item_create_directory(storage_path, mode, tracked, &item);
    if (err) {
        return err;
    }

    /* Capture ownership for paths whose label tracks it (root/ and custom/).
     * Mirrors the file-capture branch above. */
    const mount_spec_t *spec = mount_spec_for_path(storage_path);
    if (spec && spec->tracks_ownership && privilege_is_elevated()) {
        err = capture_ownership(item, st);
        if (err) {
            metadata_item_free(item);
            return err;
        }
    }
    /* For home/ prefix or when not running as root: owner/group remain NULL */

    *out = item;
    return NULL;
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
error_t *metadata_to_json(const metadata_t *metadata, buffer_t *out) {
    CHECK_NULL(metadata);
    CHECK_NULL(out);

    *out = (buffer_t){ 0 };

    error_t *err = NULL;
    cJSON *root = NULL;
    cJSON *items_array = NULL;
    const metadata_item_t **sorted = NULL;
    char *json_str = NULL;
    buffer_t buf = BUFFER_INIT;

    /* Create root object */
    root = cJSON_CreateObject();
    if (!root) {
        err = ERROR(ERR_MEMORY, "Failed to create JSON root object");
        goto cleanup;
    }

    /* Add version */
    if (!cJSON_AddNumberToObject(root, "version", METADATA_VERSION)) {
        err = ERROR(ERR_MEMORY, "Failed to add version to JSON");
        goto cleanup;
    }

    /* Create items array */
    items_array = cJSON_CreateArray();
    if (!items_array) {
        err = ERROR(ERR_MEMORY, "Failed to create items array");
        goto cleanup;
    }

    /* Serialize in key order — a write-side norm only (the parser accepts any
     * order, so a hand-edit cannot brick on placement), buying byte-determinism
     * across machines: sync's merge then conflicts only on genuine same-path
     * edits, never on capture-order divergence. The sort is over a transient
     * copy of the spine; the collection's insertion order is untouched. */
    if (metadata->count > 0) {
        sorted = malloc(metadata->count * sizeof(*sorted));
        if (!sorted) {
            err = ERROR(ERR_MEMORY, "Failed to allocate serialization order");
            goto cleanup;
        }
        memcpy(sorted, metadata->items, metadata->count * sizeof(*sorted));
        qsort(sorted, metadata->count, sizeof(*sorted), item_key_cmp);
    }

    for (size_t i = 0; i < metadata->count; i++) {
        const metadata_item_t *item = sorted[i];

        /* Create item object */
        cJSON *item_obj = cJSON_CreateObject();
        if (!item_obj) {
            err = ERROR(ERR_MEMORY, "Failed to create item object");
            goto cleanup;
        }

        /* Add kind discriminator */
        const char *kind_str = item->kind == PATH_KIND_DIRECTORY ? "directory" : "file";
        if (!cJSON_AddStringToObject(item_obj, "kind", kind_str)) {
            cJSON_Delete(item_obj);
            err = ERROR(ERR_MEMORY, "Failed to add kind to item object");
            goto cleanup;
        }

        /* Add key (storage_path for both files and directories) */
        if (!cJSON_AddStringToObject(item_obj, "key", item->key)) {
            cJSON_Delete(item_obj);
            err = ERROR(ERR_MEMORY, "Failed to add key to item object");
            goto cleanup;
        }

        /* Add mode — a claimed one; an unclaimed one has no line to print */
        if (item->mode != MODE_UNCLAIMED) {
            char mode_str[8];
            snprintf(mode_str, sizeof(mode_str), "%04o", (unsigned) item->mode);
            if (!cJSON_AddStringToObject(item_obj, "mode", mode_str)) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_MEMORY, "Failed to add mode to item object");
                goto cleanup;
            }
        }

        /* Add optional owner (only present for ownership-tracking labels) */
        if (item->owner) {
            if (!cJSON_AddStringToObject(item_obj, "owner", item->owner)) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_MEMORY, "Failed to add owner to item object");
                goto cleanup;
            }
        }

        /* Add optional group (only present for ownership-tracking labels) */
        if (item->group) {
            if (!cJSON_AddStringToObject(item_obj, "group", item->group)) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_MEMORY, "Failed to add group to item object");
                goto cleanup;
            }
        }

        /* Add encrypted flag iff true — false for DIRECTORY by construction at
         * both boundaries, so no kind test stands here */
        if (item->encrypted) {
            if (!cJSON_AddBoolToObject(item_obj, "encrypted", true)) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_MEMORY, "Failed to add encrypted flag to item object");
                goto cleanup;
            }
        }

        /* And tracked, the other flag one kind carries: false for FILE by the
         * same construction, and absent on a directory that says the profile
         * only passes through it. The two are mutually exclusive, so they print
         * in one place. */
        if (item->tracked) {
            if (!cJSON_AddBoolToObject(item_obj, "tracked", true)) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_MEMORY, "Failed to add tracked flag to item object");
                goto cleanup;
            }
        }

        /* Add item object to items array (ownership transferred to array). A
         * NULL array or item is cJSON's only refusal here, and neither can stand,
         * so there is nothing to check. */
        cJSON_AddItemToArray(items_array, item_obj);
    }

    /* Add items array to root (ownership transferred to root). This one duplicates
     * the key, so unlike the array above it can refuse — and a dropped refusal
     * would leak the array, print a claimless document, and report success: a
     * sheet our own parser then refuses to read. */
    if (!cJSON_AddItemToObject(root, "items", items_array)) {
        err = ERROR(ERR_MEMORY, "Failed to add items array to JSON");
        goto cleanup;
    }
    items_array = NULL;  /* Owned by root now */

    /* Convert to formatted string */
    json_str = cJSON_Print(root);
    if (!json_str) {
        err = ERROR(ERR_MEMORY, "Failed to print JSON");
        goto cleanup;
    }

    /* Create buffer from string */
    err = buffer_append_string(&buf, json_str);
    if (err) goto cleanup;

    /* Success - transfer to caller */
    *out = buf;
    buf = (buffer_t){ 0 };

cleanup:
    buffer_free(&buf);
    free(sorted);
    if (json_str) cJSON_free(json_str);
    if (items_array) cJSON_Delete(items_array);  /* Only if not added to root */
    if (root) cJSON_Delete(root);

    return err;
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
 * not here.
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
        err = ERROR(
            ERR_INVALID_ARG, "Failed to parse metadata JSON: %s",
            cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown error"
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
    err = metadata_create_empty(&metadata);
    if (err) {
        goto cleanup;
    }

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
        err = mount_validate_storage(key_obj->valuestring);
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
                err = metadata_item_create_file(
                    key_obj->valuestring, mode,
                    encrypted_obj && cJSON_IsTrue(encrypted_obj), &item
                );
                break;
            }
            case PATH_KIND_DIRECTORY: {
                cJSON *tracked_obj = cJSON_GetObjectItem(item_obj, "tracked");
                err = metadata_item_create_directory(
                    key_obj->valuestring, mode,
                    tracked_obj && cJSON_IsTrue(tracked_obj), &item
                );
                break;
            }
        }
        if (err) {
            err = error_wrap(
                err, "Failed to build item from metadata: %s",
                key_obj->valuestring
            );
            goto cleanup;
        }

        /* Ownership is the overlay every producer stamps beside the factory,
         * present only for the labels that track it. */
        cJSON *owner_obj = cJSON_GetObjectItem(item_obj, "owner");
        if (owner_obj && cJSON_IsString(owner_obj) && owner_obj->valuestring) {
            item->owner = strdup(owner_obj->valuestring);
            if (!item->owner) {
                err = ERROR(ERR_MEMORY, "Failed to duplicate owner string");
                goto cleanup;
            }
        }

        /* Parse optional group (only present for root/ prefix) */
        cJSON *group_obj = cJSON_GetObjectItem(item_obj, "group");
        if (group_obj && cJSON_IsString(group_obj) && group_obj->valuestring) {
            item->group = strdup(group_obj->valuestring);
            if (!item->group) {
                err = ERROR(ERR_MEMORY, "Failed to duplicate group string");
                goto cleanup;
            }
        }

        /* Hand the item to the collection; it takes it, and leaves the loop's
         * scratch pointer NULL for the next iteration and the tail. */
        err = metadata_add_item(metadata, &item);
        if (err) {
            err = error_wrap(
                err, "Failed to add item to metadata: %s",
                key_obj->valuestring
            );
            goto cleanup;
        }
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
 * metadata_load_from_tree. ERR_NOT_FOUND still means "no metadata file in the
 * branch"; a missing branch is the tree loader's failure (ERR_GIT), no longer
 * folded into the same code.
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
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    error_t *err = NULL;
    git_tree_entry *entry = NULL;
    char *json_str = NULL;
    metadata_t *metadata = NULL;

    /* Look for .dotta/metadata.json (use bypath for nested paths) */
    int git_err = git_tree_entry_bypath(&entry, tree, METADATA_FILE_PATH);
    if (git_err < 0) {
        if (git_err == GIT_ENOTFOUND) {
            err = ERROR(
                ERR_NOT_FOUND, "Metadata file not found in profile: %s",
                profile
            );
        } else {
            err = error_from_git(git_err);
        }
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
 * Load metadata from file path
 *
 * Reads and parses metadata from filesystem. Returns ERR_NOT_FOUND if file doesn't
 * exist.
 */
error_t *metadata_load_from_file(
    const char *file_path,
    metadata_t **out
) {
    CHECK_NULL(file_path);
    CHECK_NULL(out);

    /* Check if file exists */
    if (!fs_exists(file_path)) {
        return ERROR(
            ERR_NOT_FOUND, "Metadata file not found: %s",
            file_path
        );
    }

    /* Read file content */
    buffer_t content = BUFFER_INIT;
    error_t *err = fs_read_file(file_path, &content);
    if (err) {
        return error_wrap(err, "Failed to read metadata file");
    }

    /* Parse JSON - release buffer as null-terminated string */
    char *json_str = NULL;
    json_str = buffer_detach(&content);

    metadata_t *metadata = NULL;
    err = metadata_from_json(json_str, &metadata);
    free(json_str);

    if (err) {
        return error_wrap(
            err, "Failed to parse metadata from file: %s",
            file_path
        );
    }

    *out = metadata;
    return NULL;
}

/**
 * Save metadata to worktree
 *
 * Writes metadata as JSON to .dotta/metadata.json in worktree. Creates .dotta/
 * directory if it doesn't exist.
 */
error_t *metadata_save_to_worktree(
    const char *worktree_path,
    const metadata_t *metadata
) {
    CHECK_NULL(worktree_path);
    CHECK_NULL(metadata);

    error_t *err = NULL;
    char *dotta_dir = NULL;
    char *metadata_path = NULL;
    buffer_t json_buf = BUFFER_INIT;

    /* Build path to .dotta directory */
    dotta_dir = str_format("%s/%s", worktree_path, METADATA_DIR);
    if (!dotta_dir) {
        err = ERROR(ERR_MEMORY, "Failed to allocate .dotta directory path");
        goto cleanup;
    }

    /* Create .dotta directory if it doesn't exist */
    err = fs_create_dir(dotta_dir, true);  /* true = create parents */
    if (err) {
        err = error_wrap(err, "Failed to create .dotta directory");
        goto cleanup;
    }

    /* Build path to metadata.json */
    metadata_path = str_format("%s/%s", worktree_path, METADATA_FILE_PATH);
    if (!metadata_path) {
        err = ERROR(ERR_MEMORY, "Failed to allocate metadata file path");
        goto cleanup;
    }

    /* Convert metadata to JSON */
    err = metadata_to_json(metadata, &json_buf);
    if (err) {
        err = error_wrap(err, "Failed to convert metadata to JSON");
        goto cleanup;
    }

    /* Write to file */
    err = fs_write_file(metadata_path, &json_buf);
    if (err) {
        err = error_wrap(err, "Failed to write metadata file");
        goto cleanup;
    }

cleanup:
    buffer_free(&json_buf);
    if (metadata_path) free(metadata_path);
    if (dotta_dir) free(dotta_dir);

    return err;
}

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
 */
error_t *metadata_resolve_ownership(
    const char *owner,
    const char *group,
    uid_t *out_uid,
    gid_t *out_gid
) {
    CHECK_NULL(out_uid);
    CHECK_NULL(out_gid);

    /* Initialize to "no change" */
    *out_uid = (uid_t) -1;
    *out_gid = (gid_t) -1;

    /* Skip if no ownership specified */
    if (!owner && !group) {
        return NULL;
    }

    /* Resolve owner to UID */
    if (owner) {
        struct passwd *pwd = getpwnam(owner);
        if (!pwd) {
            return ERROR(
                ERR_NOT_FOUND, "User '%s' does not exist on this system",
                owner
            );
        }
        *out_uid = pwd->pw_uid;

        /* If no group specified, use user's primary group */
        if (!group) {
            *out_gid = pwd->pw_gid;
        }
    }

    /* Resolve group to GID (if specified and not already set from user) */
    if (group && *out_gid == (gid_t) -1) {
        struct group *grp = getgrnam(group);
        if (!grp) {
            return ERROR(
                ERR_NOT_FOUND, "Group '%s' does not exist on this system",
                group
            );
        }
        *out_gid = grp->gr_gid;
    }

    return NULL;
}
