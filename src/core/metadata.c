/**
 * metadata_v2.c - Unified metadata system implementation (Version 4)
 */

#include "metadata.h"

#include <cJSON.h>
#include <errno.h>
#include <git2.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"
#include "utils/string.h"
#include "utils/timeutil.h"

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
    metadata->index = hashmap_create(INITIAL_CAPACITY);
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

    /* Free kind-specific union fields */
    if (item->kind == METADATA_ITEM_DIRECTORY) {
        /* Directory has storage_prefix in union */
        free(item->directory.storage_prefix);
    }
    /* File kind has no allocated fields in union (only bool encrypted) */

    free(item);
}

/**
 * Free metadata structure
 *
 * Frees all items (handling union fields correctly) and the structure itself.
 */
void metadata_free(metadata_t *metadata) {
    if (!metadata) {
        return;
    }

    /* Free all items (both files and directories) */
    for (size_t i = 0; i < metadata->count; i++) {
        metadata_item_t *item = &metadata->items[i];

        /* Free common fields */
        free(item->key);
        free(item->owner);
        free(item->group);

        /* Free kind-specific union fields */
        if (item->kind == METADATA_ITEM_DIRECTORY) {
            free(item->directory.storage_prefix);
        }
        /* File kind has no allocated fields in union */
    }

    free(metadata->items);

    /* Free unified hashmap (values point to items array, so no value free callback) */
    if (metadata->index) {
        hashmap_free(metadata->index, NULL);
    }

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
        return ERROR(ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)", mode);
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
    const char *filesystem_path,
    const char *storage_prefix,
    time_t added_at,
    mode_t mode,
    metadata_item_t **out
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_prefix);
    CHECK_NULL(out);

    /* Validate mode */
    if (mode > 0777) {
        return ERROR(ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)", mode);
    }

    metadata_item_t *item = calloc(1, sizeof(metadata_item_t));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata item");
    }

    item->kind = METADATA_ITEM_DIRECTORY;

    item->key = strdup(filesystem_path);
    if (!item->key) {
        free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate filesystem path");
    }

    item->mode = mode;
    item->owner = NULL;  /* Optional, set by caller if needed */
    item->group = NULL;  /* Optional, set by caller if needed */

    /* Set directory-specific union fields */
    item->directory.storage_prefix = strdup(storage_prefix);
    if (!item->directory.storage_prefix) {
        free(item->key);
        free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate storage prefix");
    }

    item->directory.added_at = added_at;

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
 * This is a UNIFIED function that works for both files and directories since
 * they share the same array and hashmap.
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
 * This is a UNIFIED function that grows the single items array (no separate
 * files/directories arrays like in v3).
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
 * This is the UNIFIED add function that replaces:
 * - metadata_set_entry() (files)
 * - metadata_add_entry() (files)
 * - metadata_add_tracked_directory() (directories)
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
        existing = (metadata_item_t *)hashmap_get(metadata->index, source->key);
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
        char *new_storage_prefix = NULL;  /* For directories only */

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

        if (source->kind == METADATA_ITEM_DIRECTORY) {
            if (!source->directory.storage_prefix) {
                free(new_owner);
                free(new_group);
                return ERROR(ERR_INVALID_ARG, "Directory item missing storage_prefix");
            }
            new_storage_prefix = strdup(source->directory.storage_prefix);
            if (!new_storage_prefix) {
                free(new_owner);
                free(new_group);
                return ERROR(ERR_MEMORY, "Failed to duplicate storage_prefix");
            }
        }

        /* All allocations succeeded - now update (no failure paths beyond this point) */

        /* Free old strings */
        free(existing->owner);
        free(existing->group);

        /* Update common fields */
        existing->owner = new_owner;
        existing->group = new_group;
        existing->mode = source->mode;

        /* Update kind (can change from file to directory or vice versa) */
        if (existing->kind != source->kind) {
            /* Free old union fields before changing kind */
            if (existing->kind == METADATA_ITEM_DIRECTORY) {
                free(existing->directory.storage_prefix);
            }
            existing->kind = source->kind;
        }

        /* Update kind-specific union fields */
        if (source->kind == METADATA_ITEM_FILE) {
            existing->file.encrypted = source->file.encrypted;
        } else {
            /* Free old storage_prefix if we're updating a directory */
            if (existing->kind == METADATA_ITEM_DIRECTORY) {
                free(existing->directory.storage_prefix);
            }
            existing->directory.storage_prefix = new_storage_prefix;
            existing->directory.added_at = source->directory.added_at;
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
    if (source->kind == METADATA_ITEM_FILE) {
        item->file.encrypted = source->file.encrypted;
    } else {
        if (!source->directory.storage_prefix) {
            free(item->key);
            free(item->owner);
            free(item->group);
            return ERROR(ERR_INVALID_ARG, "Directory item missing storage_prefix");
        }
        item->directory.storage_prefix = strdup(source->directory.storage_prefix);
        if (!item->directory.storage_prefix) {
            free(item->key);
            free(item->owner);
            free(item->group);
            return ERROR(ERR_MEMORY, "Failed to duplicate storage_prefix");
        }
        item->directory.added_at = source->directory.added_at;
    }

    /* Add to hashmap (if available) */
    if (metadata->index) {
        err = hashmap_set(metadata->index, item->key, item);
        if (err) {
            /* Hashmap insertion failed - clean up and return error */
            free(item->key);
            free(item->owner);
            free(item->group);
            if (item->kind == METADATA_ITEM_DIRECTORY) {
                free(item->directory.storage_prefix);
            }
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
 * Unified lookup function that replaces:
 * - metadata_get_entry() (files)
 * - metadata_get_tracked_directory() (directories)
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
        item = (const metadata_item_t *)hashmap_get(metadata->index, key);
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
            index = (ssize_t)i;
            break;
        }
    }

    if (index < 0) {
        return ERROR(ERR_NOT_FOUND, "Metadata item not found: %s", key);
    }

    metadata_item_t *item = &metadata->items[index];

    /* Remove from hashmap first (before freeing key) */
    if (metadata->index) {
        error_t *err = hashmap_remove(metadata->index, item->key, NULL);
        if (err) {
            /* Non-fatal: hashmap is now inconsistent but we continue with removal */
            error_free(err);
        }
    }

    /* Free item's allocated fields */
    free(item->key);
    free(item->owner);
    free(item->group);
    if (item->kind == METADATA_ITEM_DIRECTORY) {
        free(item->directory.storage_prefix);
    }

    /* Shift array left to fill gap (if not last item) */
    if ((size_t)index < metadata->count - 1) {
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
    if (metadata->index && (size_t)index < metadata->count) {
        /* Only rebuild if we moved items (not if we removed the last item) */
        rebuild_hashmap_index(metadata);
    }

    return NULL;
}

/**
 * Check if metadata item exists
 *
 * Unified existence check that replaces:
 * - metadata_has_entry() (files)
 * - metadata_has_tracked_directory() (directories)
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
 * Get all items with optional kind filtering
 *
 * Replaces metadata_get_all_tracked_directories().
 * Returns pointer to internal items array (borrowed reference).
 *
 * IMPORTANT:
 * - Always returns pointer to full items array
 * - If kind_filter == -1: count = total items
 * - If kind_filter == specific kind: count = number of that kind (but array contains all items)
 * - Caller must iterate all items and check item->kind if filtering
 *
 * The returned pointer is only valid until the next modification to metadata.
 */
const metadata_item_t *metadata_get_items(
    const metadata_t *metadata,
    int kind_filter,
    size_t *count
) {
    if (!metadata || !count) {
        return NULL;
    }

    /* Calculate count based on filter */
    if (kind_filter == -1) {
        /* No filtering - return all items */
        *count = metadata->count;
    } else {
        /* Count matching items */
        size_t matching = 0;
        for (size_t i = 0; i < metadata->count; i++) {
            if (metadata->items[i].kind == (metadata_item_kind_t)kind_filter) {
                matching++;
            }
        }
        *count = matching;
    }

    /* Always return pointer to full array */
    return metadata->items;
}

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

    /* Check if file is a symlink - skip metadata for symlinks */
    if (S_ISLNK(st->st_mode)) {
        *out = NULL; /* Not an error, just skip */
        return NULL;
    }

    /* Extract mode (permissions only, not file type bits) */
    mode_t mode = st->st_mode & 0777;

    /* Create file item */
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
    item->owner = NULL;  /* Set below if applicable */
    item->group = NULL;  /* Set below if applicable */

    /* Set file-specific union field (caller may update this) */
    item->file.encrypted = false;

    /* Capture ownership ONLY for root/ prefix files when running as root
     * Use effective UID (geteuid) to check privilege, not real UID (getuid).
     * This ensures correct behavior for both sudo and setuid binaries. */
    bool is_root_prefix = str_starts_with(storage_path, "root/");
    bool running_as_root = (geteuid() == 0);

    if (is_root_prefix && running_as_root) {
        /* Resolve UID to username */
        struct passwd *pwd = getpwuid(st->st_uid);
        if (pwd && pwd->pw_name) {
            item->owner = strdup(pwd->pw_name);
            if (!item->owner) {
                metadata_item_free(item);
                return ERROR(ERR_MEMORY, "Failed to allocate owner string");
            }
        }

        /* Resolve GID to groupname */
        struct group *grp = getgrgid(st->st_gid);
        if (grp && grp->gr_name) {
            item->group = strdup(grp->gr_name);
            if (!item->group) {
                metadata_item_free(item);
                return ERROR(ERR_MEMORY, "Failed to allocate group string");
            }
        }
    }
    /* For home/ prefix or when not running as root: owner/group remain NULL */

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
 * - ONLY captured for root/ prefix directories when running as root (UID 0)
 * - home/ prefix directories: ownership never captured (always current user)
 * - Regular users: ownership never captured (can't chown anyway)
 *
 * This function creates a metadata_item_t with kind=DIRECTORY.
 * The added_at timestamp is set to current time (time(NULL)).
 */
error_t *metadata_capture_from_directory(
    const char *filesystem_path,
    const char *storage_prefix,
    const struct stat *st,
    metadata_item_t **out
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_prefix);
    CHECK_NULL(st);
    CHECK_NULL(out);

    /* Verify it's actually a directory */
    if (!S_ISDIR(st->st_mode)) {
        return ERROR(ERR_INVALID_ARG, "Path is not a directory: %s", filesystem_path);
    }

    /* Extract mode (permissions only, not file type bits) */
    mode_t mode = st->st_mode & 0777;

    /* Create directory item */
    metadata_item_t *item = calloc(1, sizeof(metadata_item_t));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata item");
    }

    item->kind = METADATA_ITEM_DIRECTORY;

    item->key = strdup(filesystem_path);
    if (!item->key) {
        free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate filesystem path");
    }

    item->mode = mode;
    item->owner = NULL;  /* Set below if applicable */
    item->group = NULL;  /* Set below if applicable */

    /* Set directory-specific union fields */
    item->directory.storage_prefix = strdup(storage_prefix);
    if (!item->directory.storage_prefix) {
        free(item->key);
        free(item);
        return ERROR(ERR_MEMORY, "Failed to duplicate storage prefix");
    }

    item->directory.added_at = time(NULL);

    /* Capture ownership ONLY for root/ prefix directories when running as root
     * Use effective UID (geteuid) to check privilege, not real UID (getuid).
     * This ensures correct behavior for both sudo and setuid binaries. */
    bool is_root_prefix = str_starts_with(storage_prefix, "root/");
    bool running_as_root = (geteuid() == 0);

    if (is_root_prefix && running_as_root) {
        /* Resolve UID to username */
        struct passwd *pwd = getpwuid(st->st_uid);
        if (pwd && pwd->pw_name) {
            item->owner = strdup(pwd->pw_name);
            if (!item->owner) {
                metadata_item_free(item);
                return ERROR(ERR_MEMORY, "Failed to allocate owner string");
            }
        }

        /* Resolve GID to groupname */
        struct group *grp = getgrgid(st->st_gid);
        if (grp && grp->gr_name) {
            item->group = strdup(grp->gr_name);
            if (!item->group) {
                metadata_item_free(item);
                return ERROR(ERR_MEMORY, "Failed to allocate group string");
            }
        }
    }
    /* For home/ prefix or when not running as root: owner/group remain NULL */

    *out = item;
    return NULL;
}

/**
 * Convert metadata to JSON (Version 4 format)
 *
 * Creates unified JSON with single "items" array containing both files and directories.
 * Each item has explicit "kind" discriminator.
 */
static error_t *metadata_to_json(const metadata_t *metadata, buffer_t **out) {
    CHECK_NULL(metadata);
    CHECK_NULL(out);

    error_t *err = NULL;
    cJSON *root = NULL;
    cJSON *items_array = NULL;
    char *json_str = NULL;
    buffer_t *buf = NULL;

    /* Create root object */
    root = cJSON_CreateObject();
    if (!root) {
        err = ERROR(ERR_MEMORY, "Failed to create JSON root object");
        goto cleanup;
    }

    /* Add version 4 */
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
        const char *kind_str = (item->kind == METADATA_ITEM_FILE) ? "file" : "directory";
        if (!cJSON_AddStringToObject(item_obj, "kind", kind_str)) {
            cJSON_Delete(item_obj);
            err = ERROR(ERR_MEMORY, "Failed to add kind to item object");
            goto cleanup;
        }

        /* Add key (storage_path for files, filesystem_path for directories) */
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
        } else {
            /* DIRECTORY: Add storage_prefix and added_at */

            /* Add storage_prefix */
            if (!cJSON_AddStringToObject(item_obj, "storage_prefix", item->directory.storage_prefix)) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_MEMORY, "Failed to add storage_prefix to item object");
                goto cleanup;
            }

            /* Format timestamp as ISO 8601 UTC */
            char time_str[64];
            struct tm tm_info;

            /* Use thread-safe gmtime_r instead of gmtime */
            if (gmtime_r(&item->directory.added_at, &tm_info) == NULL) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_INTERNAL, "Failed to convert timestamp to UTC");
                goto cleanup;
            }

            /* Format timestamp - validate return value */
            if (strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_info) == 0) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_INTERNAL, "Failed to format timestamp");
                goto cleanup;
            }

            if (!cJSON_AddStringToObject(item_obj, "added_at", time_str)) {
                cJSON_Delete(item_obj);
                err = ERROR(ERR_MEMORY, "Failed to add added_at to item object");
                goto cleanup;
            }
        }

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
    buf = buffer_create();
    if (!buf) {
        err = ERROR(ERR_MEMORY, "Failed to allocate buffer");
        goto cleanup;
    }

    buffer_append_string(buf, json_str);

    /* Success - transfer ownership to caller */
    *out = buf;
    buf = NULL;

cleanup:
    if (buf) buffer_free(buf);
    if (json_str) cJSON_free(json_str);
    if (items_array) cJSON_Delete(items_array);  /* Only if not added to root */
    if (root) cJSON_Delete(root);

    return err;
}

/**
 * Parse metadata from JSON (Version 4 format)
 *
 * Parses unified JSON with single "items" array.
 * REJECTS old versions with clear error message (NO migration code).
 */
static error_t *metadata_from_json(const char *json_str, metadata_t **out) {
    CHECK_NULL(json_str);
    CHECK_NULL(out);

    /* Parse JSON */
    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        return ERROR(ERR_INVALID_ARG, "Failed to parse metadata JSON: %s",
                    cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown error");
    }

    /* Get and validate version */
    cJSON *version_obj = cJSON_GetObjectItem(root, "version");
    if (!version_obj || !cJSON_IsNumber(version_obj)) {
        cJSON_Delete(root);
        return ERROR(ERR_INVALID_ARG, "Missing or invalid version in metadata");
    }

    int version = version_obj->valueint;
    if (version != METADATA_VERSION) {
        cJSON_Delete(root);
        return ERROR(ERR_INVALID_ARG,
                    "Unsupported metadata version: %d (expected %d). "
                    "This is ALPHA software with breaking changes. "
                    "Please re-run 'dotta add' for all your files.",
                    version, METADATA_VERSION);
    }

    /* Get items array */
    cJSON *items_array = cJSON_GetObjectItem(root, "items");
    if (!items_array || !cJSON_IsArray(items_array)) {
        cJSON_Delete(root);
        return ERROR(ERR_INVALID_ARG, "Missing or invalid items array in metadata");
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
            return ERROR(ERR_INVALID_ARG, "Invalid item in items array (not an object)");
        }

        /* Get kind discriminator (required) */
        cJSON *kind_obj = cJSON_GetObjectItem(item_obj, "kind");
        if (!kind_obj || !cJSON_IsString(kind_obj)) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Item missing kind field");
        }

        metadata_item_kind_t kind;
        if (strcmp(kind_obj->valuestring, "file") == 0) {
            kind = METADATA_ITEM_FILE;
        } else if (strcmp(kind_obj->valuestring, "directory") == 0) {
            kind = METADATA_ITEM_DIRECTORY;
        } else {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Invalid kind value: %s (expected 'file' or 'directory')",
                        kind_obj->valuestring);
        }

        /* Get key (required) */
        cJSON *key_obj = cJSON_GetObjectItem(item_obj, "key");
        if (!key_obj || !cJSON_IsString(key_obj)) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Item missing key field");
        }

        /* Get mode (required) */
        cJSON *mode_obj = cJSON_GetObjectItem(item_obj, "mode");
        if (!mode_obj || !cJSON_IsString(mode_obj)) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Item missing mode field (key: %s)", key_obj->valuestring);
        }

        /* Parse mode string */
        mode_t mode;
        err = metadata_parse_mode(mode_obj->valuestring, &mode);
        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to parse mode for item: %s", key_obj->valuestring);
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
        } else {
            /* DIRECTORY: Parse required storage_prefix and added_at */

            /* Get storage_prefix (required for directories) */
            cJSON *prefix_obj = cJSON_GetObjectItem(item_obj, "storage_prefix");
            if (!prefix_obj || !cJSON_IsString(prefix_obj)) {
                metadata_item_free(item);
                metadata_free(metadata);
                cJSON_Delete(root);
                return ERROR(ERR_INVALID_ARG, "Directory item missing storage_prefix field (key: %s)",
                            key_obj->valuestring);
            }

            item->directory.storage_prefix = strdup(prefix_obj->valuestring);
            if (!item->directory.storage_prefix) {
                metadata_item_free(item);
                metadata_free(metadata);
                cJSON_Delete(root);
                return ERROR(ERR_MEMORY, "Failed to duplicate storage_prefix string");
            }

            /* Get added_at timestamp (required for directories) */
            cJSON *added_obj = cJSON_GetObjectItem(item_obj, "added_at");
            if (!added_obj || !cJSON_IsString(added_obj)) {
                metadata_item_free(item);
                metadata_free(metadata);
                cJSON_Delete(root);
                return ERROR(ERR_INVALID_ARG, "Directory item missing added_at field (key: %s)",
                            key_obj->valuestring);
            }

            /* Parse ISO 8601 timestamp */
            struct tm tm_info = {0};
            if (strptime(added_obj->valuestring, "%Y-%m-%dT%H:%M:%SZ", &tm_info) == NULL) {
                metadata_item_free(item);
                metadata_free(metadata);
                cJSON_Delete(root);
                return ERROR(ERR_INVALID_ARG, "Invalid timestamp format for directory (key: %s, value: %s)",
                            key_obj->valuestring, added_obj->valuestring);
            }

            /* Convert UTC time to time_t using portable function */
            time_t added_at = portable_timegm(&tm_info);
            if (added_at == (time_t)-1) {
                metadata_item_free(item);
                metadata_free(metadata);
                cJSON_Delete(root);
                return ERROR(ERR_INVALID_ARG, "Invalid timestamp value for directory (key: %s)",
                            key_obj->valuestring);
            }

            item->directory.added_at = added_at;
        }

        /* Add item to metadata collection (copies item internally) */
        err = metadata_add_item(metadata, item);
        metadata_item_free(item);  /* Free temporary item (add_item copied it) */

        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to add item to metadata: %s", key_obj->valuestring);
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
    git_blob *blob = NULL;
    char *json_str = NULL;
    metadata_t *metadata = NULL;

    /* Look up branch reference */
    char ref_name[256];
    snprintf(ref_name, sizeof(ref_name), "refs/heads/%s", branch_name);

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
            err = ERROR(ERR_NOT_FOUND, "Metadata file not found in branch: %s", branch_name);
        } else {
            err = error_from_git(git_err);
        }
        goto cleanup;
    }

    /* Get OID */
    const git_oid *oid = git_tree_entry_id(entry);
    if (!oid) {
        err = ERROR(ERR_INTERNAL, "Failed to get metadata file OID");
        goto cleanup;
    }

    /* Get blob */
    git_err = git_blob_lookup(&blob, repo, oid);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Get content */
    const char *content = (const char *)git_blob_rawcontent(blob);
    git_object_size_t size = git_blob_rawsize(blob);

    /* Null-terminate content (cJSON requires null-terminated string) */
    json_str = malloc(size + 1);
    if (!json_str) {
        err = ERROR(ERR_MEMORY, "Failed to allocate JSON buffer");
        goto cleanup;
    }

    memcpy(json_str, content, size);
    json_str[size] = '\0';

    /* Parse JSON */
    err = metadata_from_json(json_str, &metadata);
    if (err) {
        err = error_wrap(err, "Failed to parse metadata from branch: %s", branch_name);
        goto cleanup;
    }

    /* Success - transfer ownership to caller */
    *out = metadata;
    metadata = NULL;

cleanup:
    if (json_str) free(json_str);
    if (blob) git_blob_free(blob);
    if (entry) git_tree_entry_free(entry);
    if (tree) git_tree_free(tree);
    if (commit) git_commit_free(commit);
    if (ref) git_reference_free(ref);
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
        return ERROR(ERR_NOT_FOUND, "Metadata file not found: %s", file_path);
    }

    /* Read file content */
    buffer_t *content = NULL;
    error_t *err = fs_read_file(file_path, &content);
    if (err) {
        return error_wrap(err, "Failed to read metadata file");
    }

    /* Parse JSON - release buffer as null-terminated string */
    char *json_str = NULL;
    err = buffer_release_data(content, &json_str);
    if (err) {
        return error_wrap(err, "Failed to release buffer");
    }

    metadata_t *metadata = NULL;
    err = metadata_from_json(json_str, &metadata);
    free(json_str);

    if (err) {
        return error_wrap(err, "Failed to parse metadata from file: %s", file_path);
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
    buffer_t *json_buf = NULL;

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
    err = fs_write_file(metadata_path, json_buf);
    if (err) {
        err = error_wrap(err, "Failed to write metadata file");
        goto cleanup;
    }

cleanup:
    if (json_buf) buffer_free(json_buf);
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
    const string_array_t *profile_names,
    metadata_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_names);
    CHECK_NULL(out);

    error_t *err = NULL;
    size_t profile_count = string_array_size(profile_names);

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
        const char *profile_name = string_array_get(profile_names, i);
        metadata_t *meta = NULL;

        error_t *load_err = metadata_load_from_branch(repo, profile_name, &meta);
        if (load_err) {
            if (load_err->code == ERR_NOT_FOUND) {
                /* Profile or metadata file doesn't exist - skip gracefully */
                error_free(load_err);
                continue;
            } else {
                /* Real error - clean up and propagate */
                for (size_t j = 0; j < i; j++) {
                    if (profile_metadata[j]) {
                        metadata_free((metadata_t *)profile_metadata[j]);
                    }
                }
                free(profile_metadata);
                return error_wrap(load_err,
                    "Failed to load metadata from profile '%s'", profile_name);
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
                metadata_free((metadata_t *)profile_metadata[i]);
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
                return error_wrap(err, "Failed to merge metadata item: %s", item->key);
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

    if (*endptr != '\0') {
        return ERROR(ERR_INVALID_ARG, "Invalid mode string: %s (not octal)", mode_str);
    }

    if (mode > 0777) {
        return ERROR(ERR_INVALID_ARG, "Invalid mode: %04lo (must be <= 0777)", mode);
    }

    *out = (mode_t)mode;
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
        return ERROR(ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)", mode);
    }

    char *mode_str = str_format("%04o", mode);
    if (!mode_str) {
        return ERROR(ERR_MEMORY, "Failed to format mode string");
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
    *out_uid = (uid_t)-1;
    *out_gid = (gid_t)-1;

    /* Skip if no ownership specified */
    if (!owner && !group) {
        return NULL;
    }

    /* Only works when running as root
     * Use effective UID (geteuid) to check privilege level, not real UID (getuid).
     * This correctly handles both sudo (real=0, effective=0) and setuid scenarios. */
    if (geteuid() != 0) {
        return ERROR(ERR_PERMISSION,
                    "Cannot resolve ownership (not running as root)");
    }

    /* Resolve owner to UID */
    if (owner) {
        struct passwd *pwd = getpwnam(owner);
        if (!pwd) {
            return ERROR(ERR_NOT_FOUND,
                        "User '%s' does not exist on this system",
                        owner);
        }
        *out_uid = pwd->pw_uid;

        /* If no group specified, use user's primary group */
        if (!group) {
            *out_gid = pwd->pw_gid;
        }
    }

    /* Resolve group to GID (if specified and not already set from user) */
    if (group && *out_gid == (gid_t)-1) {
        struct group *grp = getgrnam(group);
        if (!grp) {
            return ERROR(ERR_NOT_FOUND,
                        "Group '%s' does not exist on this system",
                        group);
        }
        *out_gid = grp->gr_gid;
    }

    return NULL;
}
