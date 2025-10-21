/**
 * metadata.c - File metadata preservation system implementation
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

    metadata->entries = calloc(INITIAL_CAPACITY, sizeof(metadata_entry_t));
    if (!metadata->entries) {
        free(metadata);
        return ERROR(ERR_MEMORY, "Failed to allocate metadata entries");
    }

    /* Create hashmap for O(1) lookups */
    metadata->index = hashmap_create(INITIAL_CAPACITY);
    if (!metadata->index) {
        free(metadata->entries);
        free(metadata);
        return ERROR(ERR_MEMORY, "Failed to allocate metadata index");
    }

    metadata->count = 0;
    metadata->capacity = INITIAL_CAPACITY;
    metadata->version = METADATA_VERSION;

    /* Initialize directory tracking */
    metadata->directories = calloc(INITIAL_CAPACITY, sizeof(metadata_directory_entry_t));
    if (!metadata->directories) {
        hashmap_free(metadata->index, NULL);
        free(metadata->entries);
        free(metadata);
        return ERROR(ERR_MEMORY, "Failed to allocate directory tracking");
    }

    metadata->directory_index = hashmap_create(INITIAL_CAPACITY);
    if (!metadata->directory_index) {
        free(metadata->directories);
        hashmap_free(metadata->index, NULL);
        free(metadata->entries);
        free(metadata);
        return ERROR(ERR_MEMORY, "Failed to allocate directory index");
    }

    metadata->directory_count = 0;
    metadata->directory_capacity = INITIAL_CAPACITY;

    *out = metadata;
    return NULL;
}

/**
 * Free metadata structure
 */
void metadata_free(metadata_t *metadata) {
    if (!metadata) {
        return;
    }

    /* Free all file entries */
    for (size_t i = 0; i < metadata->count; i++) {
        free(metadata->entries[i].storage_path);
        free(metadata->entries[i].owner);
        free(metadata->entries[i].group);
    }

    free(metadata->entries);

    /* Free hashmap (values point to entries array, so no value free callback) */
    if (metadata->index) {
        hashmap_free(metadata->index, NULL);
    }

    /* Free all directory entries */
    for (size_t i = 0; i < metadata->directory_count; i++) {
        free(metadata->directories[i].filesystem_path);
        free(metadata->directories[i].storage_prefix);
        free(metadata->directories[i].owner);
        free(metadata->directories[i].group);
    }

    free(metadata->directories);

    /* Free directory index (values point to directories array, so no value free callback) */
    if (metadata->directory_index) {
        hashmap_free(metadata->directory_index, NULL);
    }

    free(metadata);
}

/**
 * Create metadata entry
 */
error_t *metadata_entry_create(
    const char *storage_path,
    mode_t mode,
    metadata_entry_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    /* Validate mode */
    if (mode > 0777) {
        return ERROR(ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)", mode);
    }

    metadata_entry_t *entry = calloc(1, sizeof(metadata_entry_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata entry");
    }

    entry->storage_path = strdup(storage_path);
    if (!entry->storage_path) {
        free(entry);
        return ERROR(ERR_MEMORY, "Failed to duplicate storage path");
    }

    entry->mode = mode;
    entry->owner = NULL;  /* Optional, set by caller if needed */
    entry->group = NULL;  /* Optional, set by caller if needed */

    *out = entry;
    return NULL;
}

/**
 * Free metadata entry
 */
void metadata_entry_free(metadata_entry_t *entry) {
    if (!entry) {
        return;
    }

    free(entry->storage_path);
    free(entry->owner);
    free(entry->group);
    free(entry);
}

/**
 * Find entry index by storage path
 *
 * @return Index of entry, or -1 if not found
 */
static ssize_t find_entry_index(const metadata_t *metadata, const char *storage_path) {
    if (!metadata || !storage_path) {
        return -1;
    }

    for (size_t i = 0; i < metadata->count; i++) {
        if (strcmp(metadata->entries[i].storage_path, storage_path) == 0) {
            return (ssize_t)i;
        }
    }

    return -1;
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
 * @param entries Array of entries to index
 * @param count Number of entries
 * @return Error or NULL on success (non-fatal - sets index to NULL on failure)
 */
static void rebuild_hashmap_index(metadata_t *metadata, metadata_entry_t *entries, size_t count) {
    if (!metadata || !metadata->index) {
        return;
    }

    /* Clear existing index (all pointers are stale after realloc) */
    hashmap_clear(metadata->index, NULL);

    /* Rebuild index with new pointers */
    for (size_t i = 0; i < count; i++) {
        error_t *err = hashmap_set(metadata->index,
                                   entries[i].storage_path,
                                   &entries[i]);
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
 * Safely rebuild directory hashmap index after array reallocation
 *
 * Similar to rebuild_hashmap_index but for directory entries.
 *
 * @param metadata Metadata structure (must not be NULL)
 * @param directories Array of directory entries to index
 * @param count Number of directory entries
 */
static void rebuild_directory_hashmap_index(metadata_t *metadata,
                                           metadata_directory_entry_t *directories,
                                           size_t count) {
    if (!metadata || !metadata->directory_index) {
        return;
    }

    /* Clear existing index (all pointers are stale after realloc) */
    hashmap_clear(metadata->directory_index, NULL);

    /* Rebuild index with new pointers */
    for (size_t i = 0; i < count; i++) {
        error_t *err = hashmap_set(metadata->directory_index,
                                   directories[i].filesystem_path,
                                   &directories[i]);
        if (err) {
            /* Rebuild failed - free hashmap and set to NULL */
            hashmap_free(metadata->directory_index, NULL);
            metadata->directory_index = NULL;
            error_free(err);
            return;
        }
    }
}

/**
 * Grow metadata entries array if needed
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
    metadata_entry_t *new_entries = realloc(
        metadata->entries,
        new_capacity * sizeof(metadata_entry_t)
    );

    if (!new_entries) {
        return ERROR(ERR_MEMORY, "Failed to grow metadata entries array");
    }

    metadata->entries = new_entries;
    metadata->capacity = new_capacity;

    /* Rebuild hashmap index since array pointers changed after realloc
     * Non-fatal: if rebuild fails, index is set to NULL and we fall back to linear search */
    rebuild_hashmap_index(metadata, metadata->entries, metadata->count);

    return NULL;
}

/**
 * Add or update metadata entry
 */
error_t *metadata_set_entry(
    metadata_t *metadata,
    const char *storage_path,
    mode_t mode
) {
    CHECK_NULL(metadata);
    CHECK_NULL(storage_path);

    /* Validate mode */
    if (mode > 0777) {
        return ERROR(ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)", mode);
    }

    /* Check if entry already exists (use hashmap for O(1) lookup) */
    metadata_entry_t *existing = NULL;
    if (metadata->index) {
        existing = hashmap_get(metadata->index, storage_path);
    } else {
        /* Fallback to linear search */
        ssize_t index = find_entry_index(metadata, storage_path);
        if (index >= 0) {
            existing = &metadata->entries[index];
        }
    }

    if (existing) {
        /* Update existing entry */
        existing->mode = mode;
        return NULL;
    }

    /* Add new entry */
    error_t *err = ensure_capacity(metadata);
    if (err) {
        return err;
    }

    metadata->entries[metadata->count].storage_path = strdup(storage_path);
    if (!metadata->entries[metadata->count].storage_path) {
        return ERROR(ERR_MEMORY, "Failed to duplicate storage path");
    }

    metadata->entries[metadata->count].mode = mode;
    metadata->entries[metadata->count].owner = NULL;  /* Optional, set by caller if needed */
    metadata->entries[metadata->count].group = NULL;  /* Optional, set by caller if needed */

    /* Add to hashmap index (points to entry in array) */
    if (metadata->index) {
        err = hashmap_set(metadata->index, storage_path, &metadata->entries[metadata->count]);
        if (err) {
            /* Clean up on failure */
            free(metadata->entries[metadata->count].storage_path);
            return error_wrap(err, "Failed to update metadata index");
        }
    }

    metadata->count++;

    return NULL;
}

/**
 * Add or update metadata entry from captured entry
 */
error_t *metadata_add_entry(
    metadata_t *metadata,
    const metadata_entry_t *source
) {
    CHECK_NULL(metadata);
    CHECK_NULL(source);

    /* First, add/update the basic entry with mode */
    error_t *err = metadata_set_entry(metadata, source->storage_path, source->mode);
    if (err) {
        return err;
    }

    /* Now get the entry we just added/updated so we can set owner/group
     * Use mutable getter since we need to modify the entry */
    metadata_entry_t *entry = NULL;
    err = metadata_get_entry_mut(metadata, source->storage_path, &entry);
    if (err) {
        return error_wrap(err, "Failed to get metadata entry after adding");
    }

    /* Allocate new owner/group strings FIRST (fail-fast before modifying entry)
     * This prevents memory leaks on partial allocation failure */
    char *new_owner = NULL;
    char *new_group = NULL;

    if (source->owner) {
        new_owner = strdup(source->owner);
        if (!new_owner) {
            return ERROR(ERR_MEMORY, "Failed to duplicate owner string");
        }
    }

    if (source->group) {
        new_group = strdup(source->group);
        if (!new_group) {
            free(new_owner);  /* Clean up owner on failure */
            return ERROR(ERR_MEMORY, "Failed to duplicate group string");
        }
    }

    /* All allocations succeeded - now update entry (no failure paths beyond here) */
    free(entry->owner);
    free(entry->group);
    entry->owner = new_owner;
    entry->group = new_group;

    return NULL;
}

/**
 * Get metadata entry (const version)
 */
error_t *metadata_get_entry(
    const metadata_t *metadata,
    const char *storage_path,
    const metadata_entry_t **out
) {
    CHECK_NULL(metadata);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    /* Use hashmap for O(1) lookup */
    if (metadata->index) {
        metadata_entry_t *entry = hashmap_get(metadata->index, storage_path);
        if (!entry) {
            return ERROR(ERR_NOT_FOUND, "Metadata entry not found: %s", storage_path);
        }
        *out = entry;
        return NULL;
    }

    /* Fallback to linear search if no index */
    ssize_t index = find_entry_index(metadata, storage_path);

    if (index < 0) {
        return ERROR(ERR_NOT_FOUND, "Metadata entry not found: %s", storage_path);
    }

    *out = &metadata->entries[index];
    return NULL;
}

/**
 * Get mutable metadata entry
 *
 * Internal helper that returns a mutable pointer for modifying entries.
 * Implements the same logic as metadata_get_entry but returns non-const.
 */
error_t *metadata_get_entry_mut(
    metadata_t *metadata,
    const char *storage_path,
    metadata_entry_t **out
) {
    CHECK_NULL(metadata);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    /* Use hashmap for O(1) lookup */
    if (metadata->index) {
        metadata_entry_t *entry = hashmap_get(metadata->index, storage_path);
        if (!entry) {
            return ERROR(ERR_NOT_FOUND, "Metadata entry not found: %s", storage_path);
        }
        *out = entry;
        return NULL;
    }

    /* Fallback to linear search if no index */
    ssize_t index = find_entry_index(metadata, storage_path);

    if (index < 0) {
        return ERROR(ERR_NOT_FOUND, "Metadata entry not found: %s", storage_path);
    }

    *out = &metadata->entries[index];
    return NULL;
}

/**
 * Remove metadata entry
 */
error_t *metadata_remove_entry(
    metadata_t *metadata,
    const char *storage_path
) {
    CHECK_NULL(metadata);
    CHECK_NULL(storage_path);

    ssize_t index = find_entry_index(metadata, storage_path);

    if (index < 0) {
        return ERROR(ERR_NOT_FOUND, "Metadata entry not found: %s", storage_path);
    }

    /* Remove from hashmap index */
    if (metadata->index) {
        error_t *err = hashmap_remove(metadata->index, storage_path, NULL);
        if (err) {
            /* Log but don't fail - we'll still remove from array */
            error_free(err);
        }
    }

    /* Free the entry's contents */
    free(metadata->entries[index].storage_path);
    free(metadata->entries[index].owner);
    free(metadata->entries[index].group);

    /* Shift remaining entries down using memmove for efficiency */
    if ((size_t)index < metadata->count - 1) {
        memmove(&metadata->entries[index], &metadata->entries[index + 1],
                (metadata->count - 1 - (size_t)index) * sizeof(metadata_entry_t));
    }

    metadata->count--;

    /* Rebuild hashmap index since pointers changed after memmove
     * Non-fatal: if rebuild fails, index is set to NULL and we fall back to linear search */
    rebuild_hashmap_index(metadata, metadata->entries, metadata->count);

    return NULL;
}

/**
 * Check if metadata entry exists
 */
bool metadata_has_entry(
    const metadata_t *metadata,
    const char *storage_path
) {
    if (!metadata || !storage_path) {
        return false;
    }

    /* Use hashmap for O(1) lookup */
    if (metadata->index) {
        return hashmap_has(metadata->index, storage_path);
    }

    /* Fallback to linear search if no index */
    return find_entry_index(metadata, storage_path) >= 0;
}

/**
 * Parse mode string to mode_t
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
 * Convert metadata to JSON
 */
static error_t *metadata_to_json(const metadata_t *metadata, buffer_t **out) {
    CHECK_NULL(metadata);
    CHECK_NULL(out);

    error_t *err = NULL;
    cJSON *root = NULL;
    cJSON *files = NULL;
    char *json_str = NULL;
    buffer_t *buf = NULL;

    /* Create root object */
    root = cJSON_CreateObject();
    if (!root) {
        err = ERROR(ERR_MEMORY, "Failed to create JSON root object");
        goto cleanup;
    }

    /* Add version */
    if (!cJSON_AddNumberToObject(root, "version", metadata->version)) {
        err = ERROR(ERR_MEMORY, "Failed to add version to JSON");
        goto cleanup;
    }

    /* Create files object */
    files = cJSON_CreateObject();
    if (!files) {
        err = ERROR(ERR_MEMORY, "Failed to create files object");
        goto cleanup;
    }

    /* Add each file entry */
    for (size_t i = 0; i < metadata->count; i++) {
        const metadata_entry_t *entry = &metadata->entries[i];

        /* Create file metadata object */
        cJSON *file_obj = cJSON_CreateObject();
        if (!file_obj) {
            err = ERROR(ERR_MEMORY, "Failed to create file object");
            goto cleanup;
        }

        /* Format mode as string */
        char *mode_str = NULL;
        err = metadata_format_mode(entry->mode, &mode_str);
        if (err) {
            cJSON_Delete(file_obj);
            goto cleanup;
        }

        /* Add mode */
        if (!cJSON_AddStringToObject(file_obj, "mode", mode_str)) {
            free(mode_str);
            cJSON_Delete(file_obj);
            err = ERROR(ERR_MEMORY, "Failed to add mode to file object");
            goto cleanup;
        }
        free(mode_str);

        /* Add owner if present (optional, only for root/ prefix) */
        if (entry->owner) {
            if (!cJSON_AddStringToObject(file_obj, "owner", entry->owner)) {
                cJSON_Delete(file_obj);
                err = ERROR(ERR_MEMORY, "Failed to add owner to file object");
                goto cleanup;
            }
        }

        /* Add group if present (optional, only for root/ prefix) */
        if (entry->group) {
            if (!cJSON_AddStringToObject(file_obj, "group", entry->group)) {
                cJSON_Delete(file_obj);
                err = ERROR(ERR_MEMORY, "Failed to add group to file object");
                goto cleanup;
            }
        }

        /* Add file object to files (ownership transferred) */
        cJSON_AddItemToObject(files, entry->storage_path, file_obj);
    }

    /* Add files to root (ownership transferred) */
    cJSON_AddItemToObject(root, "files", files);
    files = NULL;  /* Owned by root now */

    /* Create directories array */
    cJSON *tracked_dirs = cJSON_CreateArray();
    if (!tracked_dirs) {
        err = ERROR(ERR_MEMORY, "Failed to create directories array");
        goto cleanup;
    }

    /* Add each tracked directory */
    for (size_t i = 0; i < metadata->directory_count; i++) {
        const metadata_directory_entry_t *dir_entry = &metadata->directories[i];

        cJSON *dir_obj = cJSON_CreateObject();
        if (!dir_obj) {
            cJSON_Delete(tracked_dirs);
            err = ERROR(ERR_MEMORY, "Failed to create directory object");
            goto cleanup;
        }

        /* Add filesystem_path */
        if (!cJSON_AddStringToObject(dir_obj, "filesystem_path", dir_entry->filesystem_path)) {
            cJSON_Delete(dir_obj);
            cJSON_Delete(tracked_dirs);
            err = ERROR(ERR_MEMORY, "Failed to add filesystem_path to directory object");
            goto cleanup;
        }

        /* Add storage_prefix */
        if (!cJSON_AddStringToObject(dir_obj, "storage_prefix", dir_entry->storage_prefix)) {
            cJSON_Delete(dir_obj);
            cJSON_Delete(tracked_dirs);
            err = ERROR(ERR_MEMORY, "Failed to add storage_prefix to directory object");
            goto cleanup;
        }

        /* Add added_at timestamp */
        char time_str[64];
        struct tm tm_info;

        /* Use thread-safe gmtime_r instead of gmtime */
        if (gmtime_r(&dir_entry->added_at, &tm_info) == NULL) {
            cJSON_Delete(dir_obj);
            cJSON_Delete(tracked_dirs);
            err = ERROR(ERR_INTERNAL, "Failed to convert timestamp to UTC");
            goto cleanup;
        }

        /* Format timestamp - validate return value */
        if (strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_info) == 0) {
            cJSON_Delete(dir_obj);
            cJSON_Delete(tracked_dirs);
            err = ERROR(ERR_INTERNAL, "Failed to format timestamp");
            goto cleanup;
        }

        if (!cJSON_AddStringToObject(dir_obj, "added_at", time_str)) {
            cJSON_Delete(dir_obj);
            cJSON_Delete(tracked_dirs);
            err = ERROR(ERR_MEMORY, "Failed to add added_at to directory object");
            goto cleanup;
        }

        /* Add mode */
        char *mode_str = NULL;
        err = metadata_format_mode(dir_entry->mode, &mode_str);
        if (err) {
            cJSON_Delete(dir_obj);
            cJSON_Delete(tracked_dirs);
            goto cleanup;
        }

        if (!cJSON_AddStringToObject(dir_obj, "mode", mode_str)) {
            free(mode_str);
            cJSON_Delete(dir_obj);
            cJSON_Delete(tracked_dirs);
            err = ERROR(ERR_MEMORY, "Failed to add mode to directory object");
            goto cleanup;
        }
        free(mode_str);

        /* Add owner if present (optional, only for root/ prefix) */
        if (dir_entry->owner) {
            if (!cJSON_AddStringToObject(dir_obj, "owner", dir_entry->owner)) {
                cJSON_Delete(dir_obj);
                cJSON_Delete(tracked_dirs);
                err = ERROR(ERR_MEMORY, "Failed to add owner to directory object");
                goto cleanup;
            }
        }

        /* Add group if present (optional, only for root/ prefix) */
        if (dir_entry->group) {
            if (!cJSON_AddStringToObject(dir_obj, "group", dir_entry->group)) {
                cJSON_Delete(dir_obj);
                cJSON_Delete(tracked_dirs);
                err = ERROR(ERR_MEMORY, "Failed to add group to directory object");
                goto cleanup;
            }
        }

        /* Add directory object to array (ownership transferred) */
        cJSON_AddItemToArray(tracked_dirs, dir_obj);
    }

    /* Add directories to root (ownership transferred) */
    cJSON_AddItemToObject(root, "directories", tracked_dirs);
    tracked_dirs = NULL;  /* Owned by root now */

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

    /* Success */
    *out = buf;
    buf = NULL;  /* Transfer ownership */

cleanup:
    if (buf) buffer_free(buf);
    if (json_str) cJSON_free(json_str);
    if (files) cJSON_Delete(files);  /* Only if not added to root */
    if (root) cJSON_Delete(root);

    return err;
}

/**
 * Parse metadata from JSON
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

    /* Get version */
    cJSON *version_obj = cJSON_GetObjectItem(root, "version");
    if (!version_obj || !cJSON_IsNumber(version_obj)) {
        cJSON_Delete(root);
        return ERROR(ERR_INVALID_ARG, "Missing or invalid version in metadata");
    }

    int version = version_obj->valueint;
    if (version != METADATA_VERSION) {
        cJSON_Delete(root);
        return ERROR(ERR_INVALID_ARG, "Unsupported metadata version: %d (expected %d)",
                    version, METADATA_VERSION);
    }

    /* Get files object */
    cJSON *files = cJSON_GetObjectItem(root, "files");
    if (!files || !cJSON_IsObject(files)) {
        cJSON_Delete(root);
        return ERROR(ERR_INVALID_ARG, "Missing or invalid files object in metadata");
    }

    /* Create metadata structure */
    metadata_t *metadata = NULL;
    error_t *err = metadata_create_empty(&metadata);
    if (err) {
        cJSON_Delete(root);
        return err;
    }

    metadata->version = version;

    /* Parse each file entry */
    cJSON *file_obj = NULL;
    cJSON_ArrayForEach(file_obj, files) {
        const char *storage_path = file_obj->string;
        if (!storage_path) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "File entry missing storage path");
        }

        /* Get mode */
        cJSON *mode_obj = cJSON_GetObjectItem(file_obj, "mode");
        if (!mode_obj || !cJSON_IsString(mode_obj)) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Missing or invalid mode for file: %s",
                        storage_path);
        }

        /* Parse mode string */
        mode_t mode;
        err = metadata_parse_mode(mode_obj->valuestring, &mode);
        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to parse mode for file: %s", storage_path);
        }

        /* Add entry to metadata (creates the entry internally) */
        err = metadata_set_entry(metadata, storage_path, mode);
        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to add metadata entry for: %s", storage_path);
        }

        /* Get the entry we just added so we can set owner/group
         * Use mutable getter since we need to modify the entry */
        metadata_entry_t *entry = NULL;
        err = metadata_get_entry_mut(metadata, storage_path, &entry);
        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to get metadata entry for: %s", storage_path);
        }

        /* Parse optional owner (only present for root/ prefix files) */
        cJSON *owner_obj = cJSON_GetObjectItem(file_obj, "owner");
        if (owner_obj && cJSON_IsString(owner_obj) && owner_obj->valuestring) {
            entry->owner = strdup(owner_obj->valuestring);
            if (!entry->owner) {
                metadata_free(metadata);
                cJSON_Delete(root);
                return ERROR(ERR_MEMORY, "Failed to duplicate owner string");
            }
        }

        /* Parse optional group (only present for root/ prefix files) */
        cJSON *group_obj = cJSON_GetObjectItem(file_obj, "group");
        if (group_obj && cJSON_IsString(group_obj) && group_obj->valuestring) {
            entry->group = strdup(group_obj->valuestring);
            if (!entry->group) {
                metadata_free(metadata);
                cJSON_Delete(root);
                return ERROR(ERR_MEMORY, "Failed to duplicate group string");
            }
        }
    }

    /* Parse directories array (required in v2) */
    cJSON *tracked_dirs = cJSON_GetObjectItem(root, "directories");
    if (!tracked_dirs || !cJSON_IsArray(tracked_dirs)) {
        metadata_free(metadata);
        cJSON_Delete(root);
        return ERROR(ERR_INVALID_ARG, "Missing or invalid directories array");
    }

    cJSON *dir_obj = NULL;
    cJSON_ArrayForEach(dir_obj, tracked_dirs) {
        if (!cJSON_IsObject(dir_obj)) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Invalid directory entry in directories array");
        }

        /* Get filesystem_path */
        cJSON *fs_path_obj = cJSON_GetObjectItem(dir_obj, "filesystem_path");
        if (!fs_path_obj || !cJSON_IsString(fs_path_obj)) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Missing or invalid filesystem_path in directory entry");
        }

        /* Get storage_prefix */
        cJSON *storage_prefix_obj = cJSON_GetObjectItem(dir_obj, "storage_prefix");
        if (!storage_prefix_obj || !cJSON_IsString(storage_prefix_obj)) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Missing or invalid storage_prefix in directory entry");
        }

        /* Get added_at timestamp */
        cJSON *added_at_obj = cJSON_GetObjectItem(dir_obj, "added_at");
        if (!added_at_obj || !cJSON_IsString(added_at_obj)) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Missing or invalid added_at in directory entry");
        }

        /* Parse timestamp */
        struct tm tm_info = {0};
        if (strptime(added_at_obj->valuestring, "%Y-%m-%dT%H:%M:%SZ", &tm_info) == NULL) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Invalid timestamp format in directory entry");
        }

        /* Convert UTC time to time_t using portable function */
        time_t added_at = portable_timegm(&tm_info);
        if (added_at == (time_t)-1) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Invalid timestamp value in directory entry");
        }

        /* Parse mode (required in v2 with directory metadata) */
        cJSON *mode_obj = cJSON_GetObjectItem(dir_obj, "mode");
        if (!mode_obj || !cJSON_IsString(mode_obj)) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return ERROR(ERR_INVALID_ARG, "Missing or invalid mode in directory entry");
        }

        mode_t mode;
        err = metadata_parse_mode(mode_obj->valuestring, &mode);
        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to parse mode for directory");
        }

        /* Parse optional owner (only present for root/ prefix directories) */
        const char *owner = NULL;
        cJSON *owner_obj = cJSON_GetObjectItem(dir_obj, "owner");
        if (owner_obj && cJSON_IsString(owner_obj) && owner_obj->valuestring) {
            owner = owner_obj->valuestring;
        }

        /* Parse optional group (only present for root/ prefix directories) */
        const char *group = NULL;
        cJSON *group_obj = cJSON_GetObjectItem(dir_obj, "group");
        if (group_obj && cJSON_IsString(group_obj) && group_obj->valuestring) {
            group = group_obj->valuestring;
        }

        /* Add directory to metadata */
        err = metadata_add_tracked_directory(metadata,
                                              fs_path_obj->valuestring,
                                              storage_prefix_obj->valuestring,
                                              added_at,
                                              mode,
                                              owner,
                                              group);
        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to add tracked directory");
        }
    }

    cJSON_Delete(root);
    *out = metadata;
    return NULL;
}

/**
 * Merge metadata from multiple sources
 *
 * Combines metadata collections according to precedence order.
 * Later sources override earlier ones for conflicting entries.
 * This implements profile layering (e.g., darwin overrides global).
 *
 * Merges BOTH file entries AND tracked directory entries.
 * Directory entries from later profiles override earlier ones with same path.
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
            continue; /* Skip NULL sources */
        }

        /* Copy all file entries from this source */
        for (size_t j = 0; j < source->count; j++) {
            const metadata_entry_t *entry = &source->entries[j];

            /* Use add_entry to copy all fields (mode, owner, group) */
            err = metadata_add_entry(result, entry);
            if (err) {
                metadata_free(result);
                return error_wrap(err, "Failed to merge metadata entry: %s",
                                entry->storage_path);
            }
        }

        /* Copy all tracked directory entries from this source */
        for (size_t j = 0; j < source->directory_count; j++) {
            const metadata_directory_entry_t *dir_entry = &source->directories[j];

            /* Add/update tracked directory (later sources override earlier ones) */
            err = metadata_add_tracked_directory(
                result,
                dir_entry->filesystem_path,
                dir_entry->storage_prefix,
                dir_entry->added_at,
                dir_entry->mode,
                dir_entry->owner,
                dir_entry->group
            );

            if (err) {
                metadata_free(result);
                return error_wrap(err, "Failed to merge tracked directory: %s",
                                dir_entry->filesystem_path);
            }
        }
    }

    *out = result;
    return NULL;
}

/**
 * Capture metadata from filesystem file
 */
error_t *metadata_capture_from_file(
    const char *filesystem_path,
    const char *storage_path,
    metadata_entry_t **out
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    /* Check if file is a symlink - skip metadata for symlinks */
    if (fs_is_symlink(filesystem_path)) {
        *out = NULL; /* Not an error, just skip */
        return NULL;
    }

    /* Get file stats */
    struct stat st;
    if (stat(filesystem_path, &st) != 0) {
        return ERROR(ERR_FS, "Failed to stat file: %s", filesystem_path);
    }

    /* Extract mode (permissions only, not file type bits) */
    mode_t mode = st.st_mode & 0777;

    /* Create entry */
    metadata_entry_t *entry = NULL;
    error_t *err = metadata_entry_create(storage_path, mode, &entry);
    if (err) {
        return err;
    }

    /* Capture ownership ONLY for root/ prefix files when running as root */
    bool is_root_prefix = str_starts_with(storage_path, "root/");
    bool running_as_root = (getuid() == 0);

    if (is_root_prefix && running_as_root) {
        /* Resolve UID to username */
        struct passwd *pwd = getpwuid(st.st_uid);
        if (pwd && pwd->pw_name) {
            entry->owner = strdup(pwd->pw_name);
            if (!entry->owner) {
                metadata_entry_free(entry);
                return ERROR(ERR_MEMORY, "Failed to allocate owner string");
            }
        }

        /* Resolve GID to groupname */
        struct group *grp = getgrgid(st.st_gid);
        if (grp && grp->gr_name) {
            entry->group = strdup(grp->gr_name);
            if (!entry->group) {
                metadata_entry_free(entry);
                return ERROR(ERR_MEMORY, "Failed to allocate group string");
            }
        }
    }
    /* For home/ prefix or when not running as root: owner/group remain NULL */

    *out = entry;
    return NULL;
}

/**
 * Load metadata from profile branch
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

    /* Null-terminate content */
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

    /* Success */
    *out = metadata;
    metadata = NULL;  /* Transfer ownership */

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

    /* Parse JSON */
    const char *json_str = (const char *)buffer_data(content);
    metadata_t *metadata = NULL;
    err = metadata_from_json(json_str, &metadata);
    buffer_free(content);

    if (err) {
        return error_wrap(err, "Failed to parse metadata from file: %s", file_path);
    }

    *out = metadata;
    return NULL;
}

/**
 * Load and merge metadata from multiple profiles
 *
 * Loads metadata from each profile and merges them according to precedence.
 * Gracefully handles missing profiles and missing metadata files.
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
                for (size_t j = 0; j < loaded_count; j++) {
                    metadata_free((metadata_t *)profile_metadata[j]);
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
 * Apply ownership to a file
 */
error_t *metadata_apply_ownership(
    const metadata_entry_t *entry,
    const char *filesystem_path
) {
    CHECK_NULL(entry);
    CHECK_NULL(filesystem_path);

    /* Skip if no ownership metadata */
    if (!entry->owner && !entry->group) {
        return NULL;  /* Nothing to do */
    }

    /* Only works when running as root */
    if (getuid() != 0) {
        return ERROR(ERR_PERMISSION,
                    "Cannot set ownership (not running as root): %s",
                    filesystem_path);
    }

    uid_t uid = (uid_t)-1;  /* -1 means don't change */
    gid_t gid = (gid_t)-1;  /* -1 means don't change */

    /* Resolve owner to UID */
    if (entry->owner) {
        struct passwd *pwd = getpwnam(entry->owner);
        if (!pwd) {
            return ERROR(ERR_NOT_FOUND,
                        "User '%s' does not exist on this system (for %s)",
                        entry->owner, filesystem_path);
        }
        uid = pwd->pw_uid;

        /* If no group specified, use user's primary group */
        if (!entry->group) {
            gid = pwd->pw_gid;
        }
    }

    /* Resolve group to GID (if specified and not already set from user) */
    if (entry->group && gid == (gid_t)-1) {
        struct group *grp = getgrnam(entry->group);
        if (!grp) {
            return ERROR(ERR_NOT_FOUND,
                        "Group '%s' does not exist on this system (for %s)",
                        entry->group, filesystem_path);
        }
        gid = grp->gr_gid;
    }

    /* Apply ownership */
    if (chown(filesystem_path, uid, gid) != 0) {
        return ERROR(ERR_FS,
                    "Failed to set ownership on %s: %s",
                    filesystem_path, strerror(errno));
    }

    return NULL;
}

/**
 * Capture metadata from filesystem directory
 */
error_t *metadata_capture_from_directory(
    const char *filesystem_path,
    const char *storage_prefix,
    metadata_directory_entry_t **out
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_prefix);
    CHECK_NULL(out);

    /* Get directory stats */
    struct stat st;
    if (stat(filesystem_path, &st) != 0) {
        return ERROR(ERR_FS, "Failed to stat directory: %s", filesystem_path);
    }

    /* Verify it's actually a directory */
    if (!S_ISDIR(st.st_mode)) {
        return ERROR(ERR_INVALID_ARG, "Path is not a directory: %s", filesystem_path);
    }

    /* Extract mode (permissions only, not file type bits) */
    mode_t mode = st.st_mode & 0777;

    /* Allocate entry */
    metadata_directory_entry_t *entry = calloc(1, sizeof(metadata_directory_entry_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate directory metadata entry");
    }

    entry->filesystem_path = strdup(filesystem_path);
    entry->storage_prefix = strdup(storage_prefix);

    if (!entry->filesystem_path || !entry->storage_prefix) {
        metadata_directory_entry_free(entry);
        return ERROR(ERR_MEMORY, "Failed to duplicate directory paths");
    }

    entry->added_at = time(NULL);
    entry->mode = mode;
    entry->owner = NULL;  /* Set below if applicable */
    entry->group = NULL;  /* Set below if applicable */

    /* Capture ownership ONLY for root/ prefix directories when running as root */
    bool is_root_prefix = str_starts_with(storage_prefix, "root/");
    bool running_as_root = (getuid() == 0);

    if (is_root_prefix && running_as_root) {
        /* Resolve UID to username */
        struct passwd *pwd = getpwuid(st.st_uid);
        if (pwd && pwd->pw_name) {
            entry->owner = strdup(pwd->pw_name);
            if (!entry->owner) {
                metadata_directory_entry_free(entry);
                return ERROR(ERR_MEMORY, "Failed to allocate owner string");
            }
        }

        /* Resolve GID to groupname */
        struct group *grp = getgrgid(st.st_gid);
        if (grp && grp->gr_name) {
            entry->group = strdup(grp->gr_name);
            if (!entry->group) {
                metadata_directory_entry_free(entry);
                return ERROR(ERR_MEMORY, "Failed to allocate group string");
            }
        }
    }
    /* For home/ prefix or when not running as root: owner/group remain NULL */

    *out = entry;
    return NULL;
}

/**
 * Free directory entry
 */
void metadata_directory_entry_free(metadata_directory_entry_t *entry) {
    if (!entry) {
        return;
    }

    free(entry->filesystem_path);
    free(entry->storage_prefix);
    free(entry->owner);
    free(entry->group);
    free(entry);
}

/**
 * Apply ownership to a directory
 */
error_t *metadata_apply_directory_ownership(
    const metadata_directory_entry_t *entry,
    const char *filesystem_path
) {
    CHECK_NULL(entry);
    CHECK_NULL(filesystem_path);

    /* Skip if no ownership metadata */
    if (!entry->owner && !entry->group) {
        return NULL;  /* Nothing to do */
    }

    /* Only works when running as root */
    if (getuid() != 0) {
        return ERROR(ERR_PERMISSION,
                    "Cannot set directory ownership (not running as root): %s",
                    filesystem_path);
    }

    uid_t uid = (uid_t)-1;  /* -1 means don't change */
    gid_t gid = (gid_t)-1;  /* -1 means don't change */

    /* Resolve owner to UID */
    if (entry->owner) {
        struct passwd *pwd = getpwnam(entry->owner);
        if (!pwd) {
            return ERROR(ERR_NOT_FOUND,
                        "User '%s' does not exist on this system (for %s)",
                        entry->owner, filesystem_path);
        }
        uid = pwd->pw_uid;

        /* If no group specified, use user's primary group */
        if (!entry->group) {
            gid = pwd->pw_gid;
        }
    }

    /* Resolve group to GID (if specified and not already set from user) */
    if (entry->group && gid == (gid_t)-1) {
        struct group *grp = getgrnam(entry->group);
        if (!grp) {
            return ERROR(ERR_NOT_FOUND,
                        "Group '%s' does not exist on this system (for %s)",
                        entry->group, filesystem_path);
        }
        gid = grp->gr_gid;
    }

    /* Apply ownership */
    if (chown(filesystem_path, uid, gid) != 0) {
        return ERROR(ERR_FS,
                    "Failed to set directory ownership on %s: %s",
                    filesystem_path, strerror(errno));
    }

    return NULL;
}

/**
 * Add tracked directory to metadata
 */
error_t *metadata_add_tracked_directory(
    metadata_t *metadata,
    const char *filesystem_path,
    const char *storage_prefix,
    time_t added_at,
    mode_t mode,
    const char *owner,
    const char *group
) {
    CHECK_NULL(metadata);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_prefix);

    /* Validate mode */
    if (mode > 0777) {
        return ERROR(ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)", mode);
    }

    /* Check if directory already exists (use hashmap for O(1) lookup) */
    metadata_directory_entry_t *existing = NULL;
    if (metadata->directory_index) {
        existing = hashmap_get(metadata->directory_index, filesystem_path);
    }

    if (existing) {
        /* Update existing entry */
        free(existing->storage_prefix);
        existing->storage_prefix = strdup(storage_prefix);
        if (!existing->storage_prefix) {
            return ERROR(ERR_MEMORY, "Failed to duplicate storage prefix");
        }
        existing->added_at = added_at;
        existing->mode = mode;

        /* Update owner if provided */
        free(existing->owner);
        existing->owner = NULL;
        if (owner) {
            existing->owner = strdup(owner);
            if (!existing->owner) {
                return ERROR(ERR_MEMORY, "Failed to duplicate owner string");
            }
        }

        /* Update group if provided */
        free(existing->group);
        existing->group = NULL;
        if (group) {
            existing->group = strdup(group);
            if (!existing->group) {
                return ERROR(ERR_MEMORY, "Failed to duplicate group string");
            }
        }

        return NULL;
    }

    /* Add new entry - grow array if needed */
    if (metadata->directory_count >= metadata->directory_capacity) {
        /* Check for overflow before doubling capacity */
        if (metadata->directory_capacity > SIZE_MAX / 2) {
            return ERROR(ERR_MEMORY, "Directory capacity would overflow");
        }

        size_t new_capacity = metadata->directory_capacity * 2;
        metadata_directory_entry_t *new_dirs = realloc(
            metadata->directories,
            new_capacity * sizeof(metadata_directory_entry_t)
        );

        if (!new_dirs) {
            return ERROR(ERR_MEMORY, "Failed to grow directories array");
        }

        metadata->directories = new_dirs;
        metadata->directory_capacity = new_capacity;

        /* Rebuild hashmap index since array pointers changed after realloc
         * Non-fatal: if rebuild fails, index is set to NULL and we fall back to linear search */
        rebuild_directory_hashmap_index(metadata, metadata->directories, metadata->directory_count);
    }

    /* Allocate and populate new entry */
    metadata_directory_entry_t *entry = &metadata->directories[metadata->directory_count];
    memset(entry, 0, sizeof(metadata_directory_entry_t));

    entry->filesystem_path = strdup(filesystem_path);
    entry->storage_prefix = strdup(storage_prefix);

    if (!entry->filesystem_path || !entry->storage_prefix) {
        free(entry->filesystem_path);
        free(entry->storage_prefix);
        return ERROR(ERR_MEMORY, "Failed to duplicate directory entry fields");
    }

    entry->added_at = added_at;
    entry->mode = mode;

    /* Copy owner if provided */
    if (owner) {
        entry->owner = strdup(owner);
        if (!entry->owner) {
            free(entry->filesystem_path);
            free(entry->storage_prefix);
            return ERROR(ERR_MEMORY, "Failed to duplicate owner string");
        }
    } else {
        entry->owner = NULL;
    }

    /* Copy group if provided */
    if (group) {
        entry->group = strdup(group);
        if (!entry->group) {
            free(entry->filesystem_path);
            free(entry->storage_prefix);
            free(entry->owner);
            return ERROR(ERR_MEMORY, "Failed to duplicate group string");
        }
    } else {
        entry->group = NULL;
    }

    /* Add to hashmap index (points to entry in array) */
    if (metadata->directory_index) {
        error_t *err = hashmap_set(metadata->directory_index, filesystem_path, entry);
        if (err) {
            free(entry->filesystem_path);
            free(entry->storage_prefix);
            return error_wrap(err, "Failed to update directory index");
        }
    }

    metadata->directory_count++;

    return NULL;
}

/**
 * Remove tracked directory from metadata
 */
error_t *metadata_remove_tracked_directory(
    metadata_t *metadata,
    const char *filesystem_path
) {
    CHECK_NULL(metadata);
    CHECK_NULL(filesystem_path);

    /* Use hashmap for O(1) lookup if available */
    ssize_t found_index = -1;

    if (metadata->directory_index) {
        /* Fast O(1) lookup using hashmap */
        metadata_directory_entry_t *entry = hashmap_get(metadata->directory_index, filesystem_path);
        if (!entry) {
            return ERROR(ERR_NOT_FOUND, "Directory not tracked: %s", filesystem_path);
        }

        /* Calculate index from pointer arithmetic */
        found_index = (ssize_t)(entry - metadata->directories);

        /* Sanity check: ensure index is valid */
        if (found_index < 0 || (size_t)found_index >= metadata->directory_count) {
            return ERROR(ERR_INTERNAL, "Invalid directory index from hashmap");
        }
    } else {
        /* Fallback to linear search if no index (O(N)) */
        for (size_t i = 0; i < metadata->directory_count; i++) {
            if (strcmp(metadata->directories[i].filesystem_path, filesystem_path) == 0) {
                found_index = (ssize_t)i;
                break;
            }
        }

        if (found_index < 0) {
            return ERROR(ERR_NOT_FOUND, "Directory not tracked: %s", filesystem_path);
        }
    }

    /* Remove from hashmap index */
    if (metadata->directory_index) {
        error_t *err = hashmap_remove(metadata->directory_index, filesystem_path, NULL);
        if (err) {
            /* Log but don't fail - we'll still remove from array */
            error_free(err);
        }
    }

    /* Free the entry's contents */
    free(metadata->directories[found_index].filesystem_path);
    free(metadata->directories[found_index].storage_prefix);
    free(metadata->directories[found_index].owner);
    free(metadata->directories[found_index].group);

    /* Shift remaining entries down using memmove for efficiency */
    if ((size_t)found_index < metadata->directory_count - 1) {
        memmove(&metadata->directories[found_index], &metadata->directories[found_index + 1],
                (metadata->directory_count - 1 - (size_t)found_index) * sizeof(metadata_directory_entry_t));
    }

    metadata->directory_count--;

    /* Rebuild hashmap index since pointers changed after memmove
     * Non-fatal: if rebuild fails, index is set to NULL and we fall back to linear search */
    rebuild_directory_hashmap_index(metadata, metadata->directories, metadata->directory_count);

    return NULL;
}

/**
 * Get tracked directory entry
 */
error_t *metadata_get_tracked_directory(
    const metadata_t *metadata,
    const char *filesystem_path,
    const metadata_directory_entry_t **out
) {
    CHECK_NULL(metadata);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(out);

    /* Use hashmap for O(1) lookup */
    if (metadata->directory_index) {
        metadata_directory_entry_t *entry = hashmap_get(metadata->directory_index, filesystem_path);
        if (!entry) {
            return ERROR(ERR_NOT_FOUND, "Directory not tracked: %s", filesystem_path);
        }
        *out = entry;
        return NULL;
    }

    /* Fallback to linear search if no index */
    for (size_t i = 0; i < metadata->directory_count; i++) {
        if (strcmp(metadata->directories[i].filesystem_path, filesystem_path) == 0) {
            *out = &metadata->directories[i];
            return NULL;
        }
    }

    return ERROR(ERR_NOT_FOUND, "Directory not tracked: %s", filesystem_path);
}

/**
 * Check if directory is tracked
 */
bool metadata_has_tracked_directory(
    const metadata_t *metadata,
    const char *filesystem_path
) {
    if (!metadata || !filesystem_path) {
        return false;
    }

    /* Use hashmap for O(1) lookup */
    if (metadata->directory_index) {
        return hashmap_has(metadata->directory_index, filesystem_path);
    }

    /* Fallback to linear search if no index */
    for (size_t i = 0; i < metadata->directory_count; i++) {
        if (strcmp(metadata->directories[i].filesystem_path, filesystem_path) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Get all tracked directories
 */
const metadata_directory_entry_t *metadata_get_all_tracked_directories(
    const metadata_t *metadata,
    size_t *count
) {
    if (!metadata || !count) {
        if (count) *count = 0;
        return NULL;
    }

    *count = metadata->directory_count;
    return metadata->directories;
}

/**
 * Save metadata to worktree
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
