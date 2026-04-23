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
#include <time.h>
#include <unistd.h>

#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "infra/path.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/privilege.h"

#define INITIAL_CAPACITY 16

/**
 * Create empty metadata collection
 */
error_t *metadata_create_empty(metadata_t **out) {
    CHECK_NULL(out);

    metadata_t *metadata = calloc(1, sizeof(metadata_t));
    if (!metadata) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata structure");
    }

    /* Allocate unified items array */
    metadata->items = calloc(INITIAL_CAPACITY, sizeof(metadata_item_t));
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
    metadata->version = METADATA_VERSION;

    *out = metadata;
    return NULL;
}

/**
 * Free metadata item
 *
 * Handles both file and directory items correctly.
 * Frees kind-specific union fields based on kind discriminator.
 */
void metadata_item_free(metadata_item_t *item) {
    if (!item) {
        return;
    }

    /* Free common fields */
    free(item->key);
    free(item->owner);
    free(item->group);

    free(item);
}

/**
 * Free metadata structure
 *
 * Frees all items (handling union fields correctly) and the structure itself.
 *
 * Generic callback signature for use with containers (e.g., hashmap_free).
 * Accepts void* to match standard C cleanup callback pattern.
 */
void metadata_free(void *ptr) {
    /* Safe cast: this function is designed to accept metadata_t* via void* */
    metadata_t *metadata = ptr;

    if (!metadata) {
        return;
    }

    /* Free index first — it borrows key pointers from items array */
    if (metadata->index) {
        hashmap_free(metadata->index, NULL);
    }

    /* Free all items (files, directories, and symlinks) */
    for (size_t i = 0; i < metadata->count; i++) {
        metadata_item_t *item = &metadata->items[i];

        /* Free common fields */
        free(item->key);
        free(item->owner);
        free(item->group);
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

    /* Validate mode */
    if (mode > 0777) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)",
            mode
        );
    }

    metadata_item_t *item = calloc(1, sizeof(metadata_item_t));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata item");
    }

    item->kind = METADATA_ITEM_FILE;

    item->key = strdup(storage_path);
    if (!item->key) {
        free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate storage path");
    }

    item->mode = mode;
    item->owner = NULL;  /* Optional, set by caller if needed */
    item->group = NULL;  /* Optional, set by caller if needed */

    /* Set file-specific union field */
    item->file.encrypted = encrypted;

    *out = item;
    return NULL;
}

/**
 * Create directory metadata item
 */
error_t *metadata_item_create_directory(
    const char *storage_path,
    mode_t mode,
    metadata_item_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    /* Validate mode */
    if (mode > 0777) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)",
            mode
        );
    }

    metadata_item_t *item = calloc(1, sizeof(metadata_item_t));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata item");
    }

    item->kind = METADATA_ITEM_DIRECTORY;

    item->key = strdup(storage_path);
    if (!item->key) {
        free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate storage path");
    }

    item->mode = mode;
    item->owner = NULL;  /* Optional, set by caller if needed */
    item->group = NULL;  /* Optional, set by caller if needed */

    /* Initialize directory union */
    item->directory._reserved = 0;

    *out = item;
    return NULL;
}

/**
 * Create symlink metadata item
 *
 * Mode is always 0: symlink permissions are not settable via symlink() syscall,
 * and chmod() on symlinks changes the target or fails (OS-dependent).
 * Only ownership is meaningful (applied via lchown during deployment).
 */
error_t *metadata_item_create_symlink(
    const char *storage_path,
    metadata_item_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    metadata_item_t *item = calloc(1, sizeof(metadata_item_t));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata item");
    }

    item->kind = METADATA_ITEM_SYMLINK;

    item->key = strdup(storage_path);
    if (!item->key) {
        free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate storage path");
    }

    item->mode = 0;       /* Symlink permissions are not trackable */
    item->owner = NULL;   /* Optional, set by caller if needed */
    item->group = NULL;   /* Optional, set by caller if needed */

    /* Initialize symlink union */
    item->symlink._reserved = 0;

    *out = item;
    return NULL;
}

/**
 * Clone metadata item (deep copy)
 *
 * Creates a deep copy of a metadata item, duplicating all strings and
 * union fields based on the item's kind. This is useful when you need
 * to preserve an item while modifying the original collection.
 *
 * @param source Source item to clone (must not be NULL)
 * @param out Cloned item (must not be NULL, caller must free with metadata_item_free)
 * @return Error or NULL on success
 */
error_t *metadata_item_clone(const metadata_item_t *source, metadata_item_t **out) {
    CHECK_NULL(source);
    CHECK_NULL(out);

    metadata_item_t *item = calloc(1, sizeof(metadata_item_t));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata item");
    }

    /* Copy kind discriminator */
    item->kind = source->kind;

    /* Deep copy common fields */
    item->key = strdup(source->key);
    if (!item->key) {
        free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate key");
    }

    item->mode = source->mode;

    if (source->owner) {
        item->owner = strdup(source->owner);
        if (!item->owner) {
            free(item->key);
            free(item);
            return ERROR(ERR_MEMORY, "Failed to duplicate owner");
        }
    } else {
        item->owner = NULL;
    }

    if (source->group) {
        item->group = strdup(source->group);
        if (!item->group) {
            free(item->owner);
            free(item->key);
            free(item);
            return ERROR(ERR_MEMORY, "Failed to duplicate group");
        }
    } else {
        item->group = NULL;
    }

    /* Deep copy kind-specific union fields */
    switch (source->kind) {
        case METADATA_ITEM_FILE:
            item->file.encrypted = source->file.encrypted;
            break;
        case METADATA_ITEM_DIRECTORY:
            item->directory._reserved = 0;
            break;
        case METADATA_ITEM_SYMLINK:
            item->symlink._reserved = 0;
            break;
    }

    *out = item;
    return NULL;
}

/**
 * Safely rebuild hashmap index after array reallocation
 *
 * After realloc, all pointers in the hashmap are invalid and must be updated.
 * If rebuild fails, the hashmap is freed and set to NULL, causing fallback to
 * linear search. This ensures the data structure remains consistent even if
 * hashmap rebuild fails.
 *
 * @param metadata Metadata structure (must not be NULL)
 */
static void rebuild_hashmap_index(metadata_t *metadata) {
    if (!metadata || !metadata->index) {
        return;
    }

    /* Clear existing index (all pointers are stale after realloc) */
    hashmap_clear(metadata->index, NULL);

    /* Rebuild index with new pointers */
    for (size_t i = 0; i < metadata->count; i++) {
        metadata_item_t *item = &metadata->items[i];

        error_t *err = hashmap_set(metadata->index, item->key, item);
        if (err) {
            /* Rebuild failed - free hashmap and set to NULL
             * This causes fallback to linear search (slower but correct) */
            hashmap_free(metadata->index, NULL);
            metadata->index = NULL;
            error_free(err);
            return;
        }
    }
}

/**
 * Grow metadata items array if needed
 *
 * Doubles the array capacity when full. After realloc, the hashmap index
 * must be rebuilt since all pointers have changed.
 *
 * @param metadata Metadata structure (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *ensure_capacity(metadata_t *metadata) {
    CHECK_NULL(metadata);

    if (metadata->count < metadata->capacity) {
        return NULL; /* No need to grow */
    }

    /* Check for overflow before doubling capacity */
    if (metadata->capacity > SIZE_MAX / 2) {
        return ERROR(ERR_MEMORY, "Metadata capacity would overflow");
    }

    size_t new_capacity = metadata->capacity * 2;
    metadata_item_t *new_items = realloc(
        metadata->items,
        new_capacity * sizeof(metadata_item_t)
    );

    if (!new_items) {
        return ERROR(ERR_MEMORY, "Failed to grow metadata items array");
    }

    metadata->items = new_items;
    metadata->capacity = new_capacity;

    /* Rebuild hashmap index since array pointers changed after realloc
     * Non-fatal: if rebuild fails, index is set to NULL and we fall back to linear search */
    rebuild_hashmap_index(metadata);

    return NULL;
}

/**
 * Add or update metadata item
 *
 * Works for both files and directories. If an item with the same key exists,
 * it is updated. Otherwise, a new item is added.
 *
 * IMPORTANT: This function COPIES the source item. Caller must still free
 * the source item after calling this function.
 *
 * Memory allocation strategy:
 * 1. For UPDATE: Allocate all new strings first (fail-fast), then update in-place
 * 2. For ADD: Allocate all strings first (fail-fast), then append to array
 * 3. This ensures no partial updates on allocation failure
 */
error_t *metadata_add_item(
    metadata_t *metadata,
    const metadata_item_t *source
) {
    CHECK_NULL(metadata);
    CHECK_NULL(source);
    CHECK_NULL(source->key);

    /* Validate mode */
    if (source->mode > 0777) {
        return ERROR(ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)", source->mode);
    }

    /* Check if item exists (try hashmap O(1) lookup first) */
    metadata_item_t *existing = NULL;
    if (metadata->index) {
        existing = (metadata_item_t *) hashmap_get(metadata->index, source->key);
    } else {
        /* Hashmap rebuild failed - fallback to linear search O(n) */
        for (size_t i = 0; i < metadata->count; i++) {
            if (strcmp(metadata->items[i].key, source->key) == 0) {
                existing = &metadata->items[i];
                break;
            }
        }
    }

    if (existing) {
        /* UPDATE EXISTING ITEM */

        /* Allocate new strings first (fail-fast before modifying anything) */
        char *new_owner = NULL;
        char *new_group = NULL;

        if (source->owner) {
            new_owner = strdup(source->owner);
            if (!new_owner) {
                return ERROR(ERR_MEMORY, "Failed to duplicate owner");
            }
        }

        if (source->group) {
            new_group = strdup(source->group);
            if (!new_group) {
                free(new_owner);
                return ERROR(ERR_MEMORY, "Failed to duplicate group");
            }
        }

        /* All allocations succeeded - now update */

        /* Free old strings */
        free(existing->owner);
        free(existing->group);

        /* Update common fields */
        existing->owner = new_owner;
        existing->group = new_group;
        existing->mode = source->mode;

        /* Update kind (can change between file/directory/symlink) */
        existing->kind = source->kind;

        /* Update kind-specific union fields */
        switch (source->kind) {
            case METADATA_ITEM_FILE:
                existing->file.encrypted = source->file.encrypted;
                break;
            case METADATA_ITEM_DIRECTORY:
                existing->directory._reserved = 0;
                break;
            case METADATA_ITEM_SYMLINK:
                existing->symlink._reserved = 0;
                break;
        }

        return NULL;
    }

    /* ADD NEW ITEM */

    /* Ensure we have capacity (may trigger realloc + hashmap rebuild) */
    error_t *err = ensure_capacity(metadata);
    if (err) {
        return err;
    }

    /* Get pointer to new slot (append to end) */
    metadata_item_t *item = &metadata->items[metadata->count];
    memset(item, 0, sizeof(metadata_item_t));

    /* Allocate all strings first (fail-fast) */
    item->key = strdup(source->key);
    if (!item->key) {
        return ERROR(ERR_MEMORY, "Failed to duplicate key");
    }

    if (source->owner) {
        item->owner = strdup(source->owner);
        if (!item->owner) {
            free(item->key);
            return ERROR(ERR_MEMORY, "Failed to duplicate owner");
        }
    }

    if (source->group) {
        item->group = strdup(source->group);
        if (!item->group) {
            free(item->key);
            free(item->owner);
            return ERROR(ERR_MEMORY, "Failed to duplicate group");
        }
    }

    /* Copy kind and common fields */
    item->kind = source->kind;
    item->mode = source->mode;

    /* Copy kind-specific union fields */
    switch (source->kind) {
        case METADATA_ITEM_FILE:
            item->file.encrypted = source->file.encrypted;
            break;
        case METADATA_ITEM_DIRECTORY:
            item->directory._reserved = 0;
            break;
        case METADATA_ITEM_SYMLINK:
            item->symlink._reserved = 0;
            break;
    }

    /* Add to hashmap (if available) */
    if (metadata->index) {
        err = hashmap_set(metadata->index, item->key, item);
        if (err) {
            /* Hashmap insertion failed - clean up and return error */
            free(item->key);
            free(item->owner);
            free(item->group);
            return error_wrap(err, "Failed to update index");
        }
    }

    /* Success - increment count */
    metadata->count++;

    return NULL;
}

/**
 * Get metadata item (const version)
 *
 * Works for both files and directories. Caller should check item->kind
 * after retrieval if type matters.
 */
error_t *metadata_get_item(
    const metadata_t *metadata,
    const char *key,
    const metadata_item_t **out
) {
    CHECK_NULL(metadata);
    CHECK_NULL(key);
    CHECK_NULL(out);

    const metadata_item_t *item = NULL;

    /* Try hashmap first (O(1)) */
    if (metadata->index) {
        item = (const metadata_item_t *) hashmap_get(metadata->index, key);
    } else {
        /* Hashmap rebuild failed - fallback to linear search (O(n)) */
        for (size_t i = 0; i < metadata->count; i++) {
            if (strcmp(metadata->items[i].key, key) == 0) {
                item = &metadata->items[i];
                break;
            }
        }
    }

    if (!item) {
        return ERROR(ERR_NOT_FOUND, "Metadata item not found: %s", key);
    }

    *out = item;
    return NULL;
}

/**
 * Remove metadata item
 *
 * Unified removal function that replaces:
 * - metadata_remove_entry() (files)
 * - metadata_remove_tracked_directory() (directories)
 *
 * Works for both files and directories.
 */
error_t *metadata_remove_item(
    metadata_t *metadata,
    const char *key
) {
    CHECK_NULL(metadata);
    CHECK_NULL(key);

    /* Find item index (use linear search since we need index anyway) */
    ssize_t index = -1;
    for (size_t i = 0; i < metadata->count; i++) {
        if (strcmp(metadata->items[i].key, key) == 0) {
            index = (ssize_t) i;
            break;
        }
    }

    if (index < 0) {
        return ERROR(ERR_NOT_FOUND, "Metadata item not found: %s", key);
    }

    metadata_item_t *item = &metadata->items[index];

    /* Remove from hashmap first (before freeing key) */
    if (metadata->index) {
        hashmap_remove(metadata->index, item->key, NULL);
    }

    /* Free item's allocated fields */
    free(item->key);
    free(item->owner);
    free(item->group);

    /* Shift array left to fill gap (if not last item) */
    if ((size_t) index < metadata->count - 1) {
        memmove(
            &metadata->items[index],
            &metadata->items[index + 1],
            (metadata->count - index - 1) * sizeof(metadata_item_t)
        );
    }

    /* Decrement count */
    metadata->count--;

    /* Rebuild hashmap since array pointers changed after memmove
     * Non-fatal: if rebuild fails, index is set to NULL and we fall back to linear search */
    if (metadata->index && (size_t) index < metadata->count) {
        /* Only rebuild if we moved items (not if we removed the last item) */
        rebuild_hashmap_index(metadata);
    }

    return NULL;
}

/**
 * Check if metadata item exists
 *
 * Works for both files and directories.
 */
bool metadata_has_item(
    const metadata_t *metadata,
    const char *key
) {
    if (!metadata || !key) {
        return false;
    }

    /* Try hashmap first (O(1)) */
    if (metadata->index) {
        return hashmap_get(metadata->index, key) != NULL;
    }

    /* Fallback to linear search (O(n)) */
    for (size_t i = 0; i < metadata->count; i++) {
        if (strcmp(metadata->items[i].key, key) == 0) {
            return true;
        }
    }

    return false;
}

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
 * This function is used by historical operations (diff, show, revert) to
 * extract the encrypted flag from metadata loaded from Git commits.
 * VWD operations use entry->encrypted directly from the state database.
 *
 * @param metadata Metadata collection (can be NULL)
 * @param storage_path Storage path to lookup (can be NULL)
 * @return Encrypted flag (false if not found, error, or not a file)
 */
bool metadata_get_file_encrypted(
    const metadata_t *metadata,
    const char *storage_path
) {
    /* Graceful handling - return safe default for invalid input */
    if (!metadata || !storage_path) {
        return false;
    }

    /* Lookup item using existing accessor (reuse lookup logic) */
    const metadata_item_t *item = NULL;
    error_t *err = metadata_get_item(metadata, storage_path, &item);

    /* Extract encrypted flag with type safety */
    bool encrypted = false;
    if (err == NULL && item && item->kind == METADATA_ITEM_FILE) {
        /* Safe to access file union member */
        encrypted = item->file.encrypted;
    }

    /* Cleanup - free error if lookup failed (not found is expected) */
    error_free(err);

    return encrypted;
}

bool metadata_has_encrypted_files(const metadata_t *metadata) {
    if (!metadata) {
        return false;
    }

    for (size_t i = 0; i < metadata->count; i++) {
        const metadata_item_t *item = &metadata->items[i];
        if (item->kind == METADATA_ITEM_FILE && item->file.encrypted) {
            return true;
        }
    }

    return false;
}

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
) {
    /* Handle invalid inputs */
    if (!metadata || !count) {
        if (count) {
            *count = 0;
        }
        return NULL;
    }

    *count = metadata->count;

    /* Return direct pointer to array (borrowed reference)
     * Note: metadata->items is always allocated (even for empty metadata),
     * so this is safe even when count=0 */
    return metadata->items;
}

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
 *
 * Important: Always maintain invariant: if return is NULL, count must be 0
 */
const metadata_item_t **metadata_get_items_by_kind(
    const metadata_t *metadata,
    metadata_item_kind_t kind,
    size_t *count
) {
    /* Handle invalid inputs */
    if (!metadata || !count) {
        if (count) *count = 0;
        return NULL;
    }

    ptr_array_t matches PTR_ARRAY_AUTO = { 0 };
    for (size_t i = 0; i < metadata->count; i++) {
        if (metadata->items[i].kind == kind) {
            error_t *err = ptr_array_push(
                &matches,
                &metadata->items[i]
            );
            if (err) {
                /* Surface NULL/0 to preserve the documented
                 * "return == NULL <=> count == 0" invariant. */
                error_free(err);
                *count = 0;
                return NULL;
            }
        }
    }

    return (const metadata_item_t **) ptr_array_steal(&matches, count);
}

/**
 * Capture ownership from stat data into metadata item
 *
 * Resolves UID to username and GID to groupname, storing as strings.
 * Gracefully handles unresolvable UIDs/GIDs (leaves field NULL).
 *
 * On failure (memory allocation), item fields may be partially set.
 * Caller is responsible for freeing the item on error.
 *
 * @param item Item to set ownership on (must not be NULL)
 * @param st Stat data with uid/gid (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *capture_ownership(
    metadata_item_t *item,
    const struct stat *st
) {
    /* Resolve UID to username */
    struct passwd *pwd = getpwuid(st->st_uid);
    if (pwd && pwd->pw_name) {
        item->owner = strdup(pwd->pw_name);
        if (!item->owner) {
            return ERROR(ERR_MEMORY, "Failed to allocate owner string");
        }
    }

    /* Resolve GID to groupname */
    struct group *grp = getgrgid(st->st_gid);
    if (grp && grp->gr_name) {
        item->group = strdup(grp->gr_name);
        if (!item->group) {
            return ERROR(ERR_MEMORY, "Failed to allocate group string");
        }
    }

    return NULL;
}

/**
 * Capture metadata from filesystem file
 *
 * Creates a file metadata item from stat data.
 * For symlinks, delegates to metadata_capture_from_symlink().
 *
 * Ownership capture (user/group):
 * - ONLY captured for root/ and custom/ prefix files when running as root (UID 0)
 * - home/ prefix files: ownership never captured (always current user)
 * - Regular users: ownership never captured (can't chown anyway)
 *
 * This function creates a metadata_item_t with kind=FILE.
 * The encryption flag is set to false by default; caller should update it if needed.
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

    /* Symlinks need ownership tracking, not file metadata.
     * Delegate to symlink-specific capture (handles root/ prefix check). */
    if (S_ISLNK(st->st_mode)) {
        return metadata_capture_from_symlink(storage_path, st, out);
    }

    /* Reject non-regular files (devices, FIFOs, sockets) */
    if (!S_ISREG(st->st_mode)) {
        return ERROR(ERR_INVALID_ARG, "Not a regular file: %s", filesystem_path);
    }

    /* Create file item via factory
     * (handles allocation, key duplication, mode validation) */
    mode_t mode = st->st_mode & 0777;
    metadata_item_t *item = NULL;
    error_t *err = metadata_item_create_file(storage_path, mode, false, &item);
    if (err) {
        return err;
    }

    /* Capture ownership for paths requiring root privileges (root/ and custom/) */
    if (privilege_path_requires_root(storage_path) && privilege_is_elevated()) {
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
 * Capture metadata from filesystem symlink
 *
 * Creates a symlink metadata item with ownership data only.
 * Mode is always 0 (symlink permissions are not settable).
 *
 * Symlinks only need metadata for ownership tracking on root/ prefix paths.
 * For home/ prefix or non-root users, returns *out = NULL (no metadata needed).
 *
 * Ownership capture uses lstat data (st parameter), which returns the
 * symlink's own uid/gid, not the target's.
 */
error_t *metadata_capture_from_symlink(
    const char *storage_path,
    const struct stat *st,
    metadata_item_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(st);
    CHECK_NULL(out);

    /* Only capture metadata for root/custom prefix when running as root.
     * home/ prefix symlinks are always owned by the current user — no metadata needed.
     * Non-root users can't lchown anyway — no metadata needed. */
    if (!privilege_path_requires_root(storage_path) || !privilege_is_elevated()) {
        *out = NULL;
        return NULL;
    }

    /* Create symlink item via factory */
    metadata_item_t *item = NULL;
    error_t *err = metadata_item_create_symlink(storage_path, &item);
    if (err) {
        return err;
    }

    /* Capture ownership from lstat data */
    err = capture_ownership(item, st);
    if (err) {
        metadata_item_free(item);
        return err;
    }

    *out = item;
    return NULL;
}

/**
 * Capture metadata from filesystem directory
 *
 * Creates a directory metadata item from stat data.
 * Follows the same ownership rules as file capture.
 *
 * Ownership capture (user/group):
 * - ONLY captured for root/ and custom/ prefix directories when running as root (UID 0)
 * - home/ prefix directories: ownership never captured (always current user)
 * - Regular users: ownership never captured (can't chown anyway)
 *
 * This function creates a metadata_item_t with kind=DIRECTORY.
 */
error_t *metadata_capture_from_directory(
    const char *storage_path,
    const struct stat *st,
    metadata_item_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(st);
    CHECK_NULL(out);

    /* Verify it's actually a directory */
    if (!S_ISDIR(st->st_mode)) {
        return ERROR(ERR_INVALID_ARG, "Path is not a directory: %s", storage_path);
    }

    /* Create directory item via factory
     * (handles allocation, key duplication, mode validation) */
    mode_t mode = st->st_mode & 0777;
    metadata_item_t *item = NULL;
    error_t *err = metadata_item_create_directory(storage_path, mode, &item);
    if (err) {
        return err;
    }

    /* Capture ownership for paths requiring root privileges (root/ and custom/) */
    if (privilege_path_requires_root(storage_path) && privilege_is_elevated()) {
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
 * Convert metadata to JSON
 *
 * Creates unified JSON with single "items" array containing both files and directories.
 * Each item has explicit "kind" discriminator.
 */
error_t *metadata_to_json(const metadata_t *metadata, buffer_t *out) {
    CHECK_NULL(metadata);
    CHECK_NULL(out);

    error_t *err = NULL;
    cJSON *root = NULL;
    cJSON *items_array = NULL;
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

    /* Serialize each item (unified loop for files and directories) */
    for (size_t i = 0; i < metadata->count; i++) {
        const metadata_item_t *item = &metadata->items[i];

        /* Create item object */
        cJSON *item_obj = cJSON_CreateObject();
        if (!item_obj) {
            err = ERROR(ERR_MEMORY, "Failed to create item object");
            goto cleanup;
        }

        /* Add kind discriminator */
        const char *kind_str;
        switch (item->kind) {
            case METADATA_ITEM_FILE:      kind_str = "file"; break;
            case METADATA_ITEM_DIRECTORY: kind_str = "directory"; break;
            case METADATA_ITEM_SYMLINK:   kind_str = "symlink"; break;
            default:
                cJSON_Delete(item_obj);
                err = ERROR(ERR_INTERNAL, "Unknown metadata item kind: %d", item->kind);
                goto cleanup;
        }
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

        /* Format and add mode */
        char *mode_str = NULL;
        err = metadata_format_mode(item->mode, &mode_str);
        if (err) {
            cJSON_Delete(item_obj);
            goto cleanup;
        }

        if (!cJSON_AddStringToObject(item_obj, "mode", mode_str)) {
            free(mode_str);
            cJSON_Delete(item_obj);
            err = ERROR(ERR_MEMORY, "Failed to add mode to item object");
            goto cleanup;
        }
        free(mode_str);

        /* Add optional owner (only present for root/ prefix) */
        if (item->owner) {
            if (!cJSON_AddStringToObject(item_obj, "owner", item->owner)) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_MEMORY, "Failed to add owner to item object");
                goto cleanup;
            }
        }

        /* Add optional group (only present for root/ prefix) */
        if (item->group) {
            if (!cJSON_AddStringToObject(item_obj, "group", item->group)) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_MEMORY, "Failed to add group to item object");
                goto cleanup;
            }
        }

        /* Add kind-specific fields */
        if (item->kind == METADATA_ITEM_FILE) {
            /* FILE: Add encrypted flag (only if true - omit if false) */
            if (item->file.encrypted) {
                if (!cJSON_AddBoolToObject(item_obj, "encrypted", true)) {
                    cJSON_Delete(item_obj);
                    err = ERROR(ERR_MEMORY, "Failed to add encrypted flag to item object");
                    goto cleanup;
                }
            }
        }
        /* DIRECTORY, SYMLINK: No additional fields */

        /* Add item object to items array (ownership transferred to array) */
        cJSON_AddItemToArray(items_array, item_obj);
    }

    /* Add items array to root (ownership transferred to root) */
    cJSON_AddItemToObject(root, "items", items_array);
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
    if (json_str) cJSON_free(json_str);
    if (items_array) cJSON_Delete(items_array);  /* Only if not added to root */
    if (root) cJSON_Delete(root);

    return err;
}

/**
 * Parse metadata from JSON
 *
 * Parses unified JSON with single "items" array.
 * REJECTS old versions with clear error message (NO migration code).
 */
error_t *metadata_from_json(const char *json_str, metadata_t **out) {
    CHECK_NULL(json_str);
    CHECK_NULL(out);

    /* Parse JSON */
    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        return ERROR(
            ERR_INVALID_ARG, "Failed to parse metadata JSON: %s",
            cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown error"
        );
    }

    /* Get and validate version */
    cJSON *version_obj = cJSON_GetObjectItem(root, "version");
    if (!version_obj || !cJSON_IsNumber(version_obj)) {
        cJSON_Delete(root);
        return ERROR(
            ERR_INVALID_ARG, "Missing or invalid version in metadata"
        );
    }

    int version = version_obj->valueint;
    if (version != METADATA_VERSION) {
        cJSON_Delete(root);
        return ERROR(
            ERR_INVALID_ARG,
            "Unsupported metadata version: %d (expected %d). "
            "Please re-run 'dotta add' for all your files.",
            version, METADATA_VERSION
        );
    }

    /* Get items array */
    cJSON *items_array = cJSON_GetObjectItem(root, "items");
    if (!items_array || !cJSON_IsArray(items_array)) {
        cJSON_Delete(root);
        return ERROR(
            ERR_INVALID_ARG, "Missing or invalid items array in metadata"
        );
    }

    /* Create metadata collection */
    metadata_t *metadata = NULL;
    error_t *err = metadata_create_empty(&metadata);
    if (err) {
        cJSON_Delete(root);
        return err;
    }

    metadata->version = version;

    /* Parse each item in the unified array */
    cJSON *item_obj = NULL;
    cJSON_ArrayForEach(item_obj, items_array) {
        if (!cJSON_IsObject(item_obj)) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(
                ERR_INVALID_ARG, "Invalid item in items array (not an object)"
            );
        }

        /* Get kind discriminator (required) */
        cJSON *kind_obj = cJSON_GetObjectItem(item_obj, "kind");
        if (!kind_obj || !cJSON_IsString(kind_obj) || !kind_obj->valuestring) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(
                ERR_INVALID_ARG, "Item missing kind field"
            );
        }

        metadata_item_kind_t kind;
        if (strcmp(kind_obj->valuestring, "file") == 0) {
            kind = METADATA_ITEM_FILE;
        } else if (strcmp(kind_obj->valuestring, "directory") == 0) {
            kind = METADATA_ITEM_DIRECTORY;
        } else if (strcmp(kind_obj->valuestring, "symlink") == 0) {
            kind = METADATA_ITEM_SYMLINK;
        } else {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(
                ERR_INVALID_ARG, "Invalid kind value: %s "
                "(expected 'file', 'directory', or 'symlink')",
                kind_obj->valuestring
            );
        }

        /* Get key (required) */
        cJSON *key_obj = cJSON_GetObjectItem(item_obj, "key");
        if (!key_obj || !cJSON_IsString(key_obj) || !key_obj->valuestring) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(
                ERR_INVALID_ARG, "Item missing key field"
            );
        }

        /* Validate key format (prevent path traversal) */
        err = path_validate_storage(key_obj->valuestring);
        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(
                err, "Invalid key in metadata: %s",
                key_obj->valuestring
            );
        }

        /* Get mode (required) */
        cJSON *mode_obj = cJSON_GetObjectItem(item_obj, "mode");
        if (!mode_obj || !cJSON_IsString(mode_obj) || !mode_obj->valuestring) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(
                ERR_INVALID_ARG, "Item missing mode field (key: %s)",
                key_obj->valuestring
            );
        }

        /* Parse mode string */
        mode_t mode;
        err = metadata_parse_mode(mode_obj->valuestring, &mode);
        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(
                err, "Failed to parse mode for item: %s",
                key_obj->valuestring
            );
        }

        /* Create temporary item structure */
        metadata_item_t *item = calloc(1, sizeof(metadata_item_t));
        if (!item) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_MEMORY, "Failed to allocate temporary item");
        }

        item->kind = kind;
        item->key = strdup(key_obj->valuestring);
        if (!item->key) {
            metadata_item_free(item);
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_MEMORY, "Failed to duplicate key string");
        }
        item->mode = mode;

        /* Symlink mode invariant: always 0 (permissions are not settable) */
        if (kind == METADATA_ITEM_SYMLINK) {
            item->mode = 0;
        }

        /* Parse optional owner (only present for root/ prefix) */
        cJSON *owner_obj = cJSON_GetObjectItem(item_obj, "owner");
        if (owner_obj && cJSON_IsString(owner_obj) && owner_obj->valuestring) {
            item->owner = strdup(owner_obj->valuestring);
            if (!item->owner) {
                metadata_item_free(item);
                metadata_free(metadata);
                cJSON_Delete(root);
                return ERROR(ERR_MEMORY, "Failed to duplicate owner string");
            }
        }

        /* Parse optional group (only present for root/ prefix) */
        cJSON *group_obj = cJSON_GetObjectItem(item_obj, "group");
        if (group_obj && cJSON_IsString(group_obj) && group_obj->valuestring) {
            item->group = strdup(group_obj->valuestring);
            if (!item->group) {
                metadata_item_free(item);
                metadata_free(metadata);
                cJSON_Delete(root);
                return ERROR(ERR_MEMORY, "Failed to duplicate group string");
            }
        }

        /* Parse kind-specific fields */
        if (kind == METADATA_ITEM_FILE) {
            /* FILE: Parse optional encrypted flag */
            cJSON *encrypted_obj = cJSON_GetObjectItem(item_obj, "encrypted");
            item->file.encrypted = (encrypted_obj && cJSON_IsTrue(encrypted_obj));
        }
        /* DIRECTORY, SYMLINK: No additional fields to parse */

        /* Add item to metadata collection (copies item internally) */
        err = metadata_add_item(metadata, item);
        metadata_item_free(item);  /* Free temporary item (add_item copied it) */

        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(
                err, "Failed to add item to metadata: %s",
                key_obj->valuestring
            );
        }
    }

    /* Success */
    cJSON_Delete(root);
    *out = metadata;
    return NULL;
}

/**
 * Load metadata from profile branch
 *
 * Reads .dotta/metadata.json from Git tree.
 * Returns ERR_NOT_FOUND if branch or file doesn't exist.
 */
error_t *metadata_load_from_branch(
    git_repository *repo,
    const char *branch_name,
    metadata_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out);

    error_t *err = NULL;
    git_reference *ref = NULL;
    git_commit *commit = NULL;
    git_tree *tree = NULL;
    git_tree_entry *entry = NULL;
    char *json_str = NULL;
    metadata_t *metadata = NULL;

    /* Look up branch reference */
    char ref_name[DOTTA_REFNAME_MAX];
    err = gitops_build_refname(
        ref_name, sizeof(ref_name), "refs/heads/%s", branch_name
    );
    if (err) {
        err = error_wrap(err, "Invalid branch name '%s'", branch_name);
        goto cleanup;
    }

    int git_err = git_reference_lookup(&ref, repo, ref_name);
    if (git_err < 0) {
        if (git_err == GIT_ENOTFOUND) {
            err = ERROR(ERR_NOT_FOUND, "Branch not found: %s", branch_name);
        } else {
            err = error_from_git(git_err);
        }
        goto cleanup;
    }

    /* Get commit */
    git_err = git_commit_lookup(&commit, repo, git_reference_target(ref));
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Get tree */
    git_err = git_commit_tree(&tree, commit);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Look for .dotta/metadata.json (use bypath for nested paths) */
    git_err = git_tree_entry_bypath(&entry, tree, METADATA_FILE_PATH);
    if (git_err < 0) {
        if (git_err == GIT_ENOTFOUND) {
            err = ERROR(
                ERR_NOT_FOUND, "Metadata file not found in branch: %s",
                branch_name
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
            err, "Failed to parse metadata from branch: %s",
            branch_name
        );
        goto cleanup;
    }

    /* Success - transfer ownership to caller */
    *out = metadata;
    metadata = NULL;

cleanup:
    if (json_str) free(json_str);
    if (entry) git_tree_entry_free(entry);
    if (tree) git_tree_free(tree);
    if (commit) git_commit_free(commit);
    if (ref) git_reference_free(ref);
    if (metadata) metadata_free(metadata);

    return err;
}

/**
 * Load metadata from a Git tree
 *
 * Loads metadata.json from a specific Git tree. This is useful for
 * loading metadata from historical commits or arbitrary tree objects.
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
 * Reads and parses metadata from filesystem.
 * Returns ERR_NOT_FOUND if file doesn't exist.
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
 * Writes metadata as JSON to .dotta/metadata.json in worktree.
 * Creates .dotta/ directory if it doesn't exist.
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
    dotta_dir = str_format("%s/.dotta", worktree_path);
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
 * Load and merge metadata from multiple profiles
 *
 * Loads metadata from each profile and merges according to precedence order.
 * Gracefully handles missing profiles and missing metadata files.
 * Returns empty metadata if no profiles have metadata.
 */
error_t *metadata_load_from_profiles(
    git_repository *repo,
    const string_array_t *profiles,
    metadata_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    error_t *err = NULL;
    size_t profile_count = profiles->count;

    /* Handle empty profile list */
    if (profile_count == 0) {
        /* Return empty metadata (not an error) */
        return metadata_create_empty(out);
    }

    /* Allocate array to hold metadata from each profile */
    const metadata_t **profile_metadata = calloc(profile_count, sizeof(metadata_t *));
    if (!profile_metadata) {
        return ERROR(ERR_MEMORY, "Failed to allocate profile metadata array");
    }

    size_t loaded_count = 0;

    /* Load metadata from each profile (in order for proper layering) */
    for (size_t i = 0; i < profile_count; i++) {
        const char *profile = profiles->items[i];
        metadata_t *meta = NULL;

        error_t *load_err = metadata_load_from_branch(repo, profile, &meta);
        if (load_err) {
            if (load_err->code == ERR_NOT_FOUND) {
                /* Profile or metadata file doesn't exist - skip gracefully */
                error_free(load_err);
                continue;
            } else {
                /* Real error - clean up and propagate */
                for (size_t j = 0; j < i; j++) {
                    if (profile_metadata[j]) {
                        metadata_free((metadata_t *) profile_metadata[j]);
                    }
                }
                free(profile_metadata);
                return error_wrap(
                    load_err, "Failed to load metadata from profile '%s'",
                    profile
                );
            }
        }

        /* Successfully loaded */
        profile_metadata[i] = meta;
        loaded_count++;
    }

    /* Merge metadata according to profile precedence */
    if (loaded_count > 0) {
        err = metadata_merge(profile_metadata, profile_count, out);

        /* Free individual profile metadata */
        for (size_t i = 0; i < profile_count; i++) {
            if (profile_metadata[i]) {
                metadata_free((metadata_t *) profile_metadata[i]);
            }
        }
        free(profile_metadata);

        if (err) {
            return error_wrap(err, "Failed to merge metadata from profiles");
        }
    } else {
        /* No metadata found in any profile - return empty metadata */
        free(profile_metadata);
        err = metadata_create_empty(out);
        if (err) {
            return error_wrap(err, "Failed to create empty metadata");
        }
    }

    return NULL;
}

/**
 * Merge metadata from multiple sources
 *
 * Combines metadata collections according to precedence order.
 * Later sources override earlier ones for conflicting items (same key).
 * This implements profile layering (e.g., darwin overrides global).
 *
 * Works for both files and directories using unified items array.
 */
error_t *metadata_merge(
    const metadata_t **sources,
    size_t count,
    metadata_t **out
) {
    CHECK_NULL(sources);
    CHECK_NULL(out);

    /* Create empty metadata for result */
    metadata_t *result = NULL;
    error_t *err = metadata_create_empty(&result);
    if (err) {
        return err;
    }

    /* Merge each source in order (later sources override earlier ones) */
    for (size_t i = 0; i < count; i++) {
        const metadata_t *source = sources[i];
        if (!source) {
            continue; /* Skip NULL sources (gracefully handle sparse arrays) */
        }

        /* Copy all items from this source (unified - both files and directories) */
        for (size_t j = 0; j < source->count; j++) {
            const metadata_item_t *item = &source->items[j];

            /* Use add_item to copy item (handles both kinds, handles update if exists) */
            err = metadata_add_item(result, item);
            if (err) {
                metadata_free(result);
                return error_wrap(
                    err, "Failed to merge metadata item: %s",
                    item->key
                );
            }
        }
    }

    /* Success - transfer ownership to caller */
    *out = result;
    return NULL;
}

/**
 * Parse mode string to mode_t
 *
 * Parses octal mode string (e.g., "0600", "0644", "0755") to mode_t.
 * Validates that mode is within valid range (0000-0777).
 */
error_t *metadata_parse_mode(const char *mode_str, mode_t *out) {
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
 * Format mode_t to string
 *
 * Formats mode_t as octal string (e.g., 0600 -> "0600").
 */
error_t *metadata_format_mode(mode_t mode, char **out) {
    CHECK_NULL(out);

    if (mode > 0777) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)",
            mode
        );
    }

    char *mode_str = str_format("%04o", mode);
    if (!mode_str) {
        return ERROR(
            ERR_MEMORY, "Failed to format mode string"
        );
    }

    *out = mode_str;
    return NULL;
}

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

    /* Commands enforce privileges upfront to prevent partial operations */
    if (!privilege_is_elevated()) {
        return ERROR(
            ERR_PERMISSION, "Cannot resolve ownership (not running as root)"
        );
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
