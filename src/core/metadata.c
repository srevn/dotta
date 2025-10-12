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
#include "utils/buffer.h"
#include "utils/hashmap.h"
#include "utils/string.h"

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

    /* Free all entries */
    for (size_t i = 0; i < metadata->count; i++) {
        free(metadata->entries[i].storage_path);
    }

    free(metadata->entries);

    /* Free hashmap (values point to entries array, so no value free callback) */
    if (metadata->index) {
        hashmap_free(metadata->index, NULL);
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
 * Grow metadata entries array if needed
 */
static error_t *ensure_capacity(metadata_t *metadata) {
    CHECK_NULL(metadata);

    if (metadata->count < metadata->capacity) {
        return NULL; /* No need to grow */
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

    /* Now get the entry we just added/updated so we can set owner/group */
    const metadata_entry_t *const_entry = NULL;
    err = metadata_get_entry(metadata, source->storage_path, &const_entry);
    if (err) {
        return error_wrap(err, "Failed to get metadata entry after adding");
    }

    /* Cast away const - safe since we own the metadata */
    metadata_entry_t *entry = (metadata_entry_t *)const_entry;

    /* Copy owner if present */
    if (source->owner) {
        free(entry->owner);  /* Free existing if any */
        entry->owner = strdup(source->owner);
        if (!entry->owner) {
            return ERROR(ERR_MEMORY, "Failed to duplicate owner string");
        }
    }

    /* Copy group if present */
    if (source->group) {
        free(entry->group);  /* Free existing if any */
        entry->group = strdup(source->group);
        if (!entry->group) {
            return ERROR(ERR_MEMORY, "Failed to duplicate group string");
        }
    }

    return NULL;
}

/**
 * Get metadata entry
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

    /* Free the storage_path string */
    free(metadata->entries[index].storage_path);

    /* Shift remaining entries down */
    for (size_t i = index; i < metadata->count - 1; i++) {
        metadata->entries[i] = metadata->entries[i + 1];
    }

    metadata->count--;

    /* Rebuild hashmap index since pointers changed */
    if (metadata->index) {
        hashmap_clear(metadata->index, NULL);
        for (size_t i = 0; i < metadata->count; i++) {
            error_t *err = hashmap_set(metadata->index,
                                       metadata->entries[i].storage_path,
                                       &metadata->entries[i]);
            if (err) {
                /* This is bad but we can't easily recover */
                error_free(err);
            }
        }
    }

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

        /* Get the entry we just added so we can set owner/group */
        const metadata_entry_t *const_entry = NULL;
        err = metadata_get_entry(metadata, storage_path, &const_entry);
        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to get metadata entry for: %s", storage_path);
        }

        /* Cast away const - safe since we own the metadata */
        metadata_entry_t *entry = (metadata_entry_t *)const_entry;

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

    cJSON_Delete(root);
    *out = metadata;
    return NULL;
}

/**
 * Merge metadata from multiple sources
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

        /* Copy all entries from this source */
        for (size_t j = 0; j < source->count; j++) {
            const metadata_entry_t *entry = &source->entries[j];

            err = metadata_set_entry(result, entry->storage_path, entry->mode);
            if (err) {
                metadata_free(result);
                return error_wrap(err, "Failed to merge metadata entry: %s",
                                entry->storage_path);
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
    bool is_root_prefix = (strncmp(storage_path, "root/", 5) == 0);
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
