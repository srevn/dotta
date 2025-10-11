/**
 * metadata.c - File metadata preservation system implementation
 */

#include "metadata.h"

#include <cJSON.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "utils/buffer.h"
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

    /* Check if entry already exists */
    ssize_t index = find_entry_index(metadata, storage_path);

    if (index >= 0) {
        /* Update existing entry */
        metadata->entries[index].mode = mode;
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
    metadata->count++;

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

    /* Free the storage_path string */
    free(metadata->entries[index].storage_path);

    /* Shift remaining entries down */
    for (size_t i = index; i < metadata->count - 1; i++) {
        metadata->entries[i] = metadata->entries[i + 1];
    }

    metadata->count--;

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

    /* Create root object */
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return ERROR(ERR_MEMORY, "Failed to create JSON root object");
    }

    /* Add version */
    if (!cJSON_AddNumberToObject(root, "version", metadata->version)) {
        cJSON_Delete(root);
        return ERROR(ERR_MEMORY, "Failed to add version to JSON");
    }

    /* Create files object */
    cJSON *files = cJSON_CreateObject();
    if (!files) {
        cJSON_Delete(root);
        return ERROR(ERR_MEMORY, "Failed to create files object");
    }

    /* Add each file entry */
    for (size_t i = 0; i < metadata->count; i++) {
        const metadata_entry_t *entry = &metadata->entries[i];

        /* Create file metadata object */
        cJSON *file_obj = cJSON_CreateObject();
        if (!file_obj) {
            cJSON_Delete(files);
            cJSON_Delete(root);
            return ERROR(ERR_MEMORY, "Failed to create file object");
        }

        /* Format mode as string */
        char *mode_str = NULL;
        error_t *err = metadata_format_mode(entry->mode, &mode_str);
        if (err) {
            cJSON_Delete(file_obj);
            cJSON_Delete(files);
            cJSON_Delete(root);
            return err;
        }

        /* Add mode */
        if (!cJSON_AddStringToObject(file_obj, "mode", mode_str)) {
            free(mode_str);
            cJSON_Delete(file_obj);
            cJSON_Delete(files);
            cJSON_Delete(root);
            return ERROR(ERR_MEMORY, "Failed to add mode to file object");
        }
        free(mode_str);

        /* Add file object to files */
        cJSON_AddItemToObject(files, entry->storage_path, file_obj);
    }

    /* Add files to root */
    cJSON_AddItemToObject(root, "files", files);

    /* Convert to formatted string */
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    if (!json_str) {
        return ERROR(ERR_MEMORY, "Failed to print JSON");
    }

    /* Create buffer from string */
    buffer_t *buf = buffer_create();
    if (!buf) {
        cJSON_free(json_str);
        return ERROR(ERR_MEMORY, "Failed to allocate buffer");
    }

    buffer_append_string(buf, json_str);
    cJSON_free(json_str);

    *out = buf;
    return NULL;
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

        /* Add entry */
        err = metadata_set_entry(metadata, storage_path, mode);
        if (err) {
            metadata_free(metadata);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to add metadata entry for: %s", storage_path);
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
    return metadata_entry_create(storage_path, mode, out);
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

    /* Look up branch reference */
    char ref_name[256];
    snprintf(ref_name, sizeof(ref_name), "refs/heads/%s", branch_name);

    git_reference *ref = NULL;
    int git_err = git_reference_lookup(&ref, repo, ref_name);
    if (git_err < 0) {
        if (git_err == GIT_ENOTFOUND) {
            return ERROR(ERR_NOT_FOUND, "Branch not found: %s", branch_name);
        }
        return error_from_git(git_err);
    }

    /* Get commit */
    git_commit *commit = NULL;
    git_err = git_commit_lookup(&commit, repo, git_reference_target(ref));
    git_reference_free(ref);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Get tree */
    git_tree *tree = NULL;
    git_err = git_commit_tree(&tree, commit);
    git_commit_free(commit);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Look for .dotta/metadata.json (use bypath for nested paths) */
    git_tree_entry *entry = NULL;
    git_err = git_tree_entry_bypath(&entry, tree, METADATA_FILE_PATH);
    if (git_err < 0) {
        git_tree_free(tree);
        if (git_err == GIT_ENOTFOUND) {
            return ERROR(ERR_NOT_FOUND, "Metadata file not found in branch: %s", branch_name);
        }
        return error_from_git(git_err);
    }

    /* Get OID */
    const git_oid *oid = git_tree_entry_id(entry);
    if (!oid) {
        git_tree_entry_free(entry);
        git_tree_free(tree);
        return ERROR(ERR_INTERNAL, "Failed to get metadata file OID");
    }

    /* Get blob */
    git_blob *blob = NULL;
    git_err = git_blob_lookup(&blob, repo, oid);
    git_tree_entry_free(entry);
    git_tree_free(tree);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Get content */
    const char *content = (const char *)git_blob_rawcontent(blob);
    git_object_size_t size = git_blob_rawsize(blob);

    /* Null-terminate content */
    char *json_str = malloc(size + 1);
    if (!json_str) {
        git_blob_free(blob);
        return ERROR(ERR_MEMORY, "Failed to allocate JSON buffer");
    }

    memcpy(json_str, content, size);
    json_str[size] = '\0';

    git_blob_free(blob);

    /* Parse JSON */
    metadata_t *metadata = NULL;
    error_t *err = metadata_from_json(json_str, &metadata);
    free(json_str);

    if (err) {
        return error_wrap(err, "Failed to parse metadata from branch: %s", branch_name);
    }

    *out = metadata;
    return NULL;
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
 * Save metadata to worktree
 */
error_t *metadata_save_to_worktree(
    const char *worktree_path,
    const metadata_t *metadata
) {
    CHECK_NULL(worktree_path);
    CHECK_NULL(metadata);

    /* Build path to .dotta directory */
    char *dotta_dir = str_format("%s/.dotta", worktree_path);
    if (!dotta_dir) {
        return ERROR(ERR_MEMORY, "Failed to allocate .dotta directory path");
    }

    /* Create .dotta directory if it doesn't exist */
    error_t *err = fs_create_dir(dotta_dir, true);  /* true = create parents */
    free(dotta_dir);

    if (err) {
        return error_wrap(err, "Failed to create .dotta directory");
    }

    /* Build path to metadata.json */
    char *metadata_path = str_format("%s/%s", worktree_path, METADATA_FILE_PATH);
    if (!metadata_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata file path");
    }

    /* Convert metadata to JSON */
    buffer_t *json_buf = NULL;
    err = metadata_to_json(metadata, &json_buf);
    if (err) {
        free(metadata_path);
        return error_wrap(err, "Failed to convert metadata to JSON");
    }

    /* Write to file */
    err = fs_write_file(metadata_path, json_buf);
    buffer_free(json_buf);
    free(metadata_path);

    if (err) {
        return error_wrap(err, "Failed to write metadata file");
    }

    return NULL;
}
