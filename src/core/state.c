/**
 * state.c - Deployment state tracking implementation
 *
 * Uses JSON format for human readability.
 * Uses cJSON library for robust JSON parsing/generation.
 */

/* FreeBSD exposes both strptime and timegm by default */
#if !defined(__FreeBSD__)
#define _XOPEN_SOURCE 700  /* For strptime */
#endif

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE   /* For timegm on macOS */
#endif

#include "state.h"

#include <errno.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "base/error.h"
#include "base/filesystem.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"

#define STATE_FILE_NAME "dotta-state.json"
#define STATE_VERSION 2

/**
 * State structure
 *
 * Uses both arrays (for iteration/serialization) and hashmaps (for O(1) lookups).
 * The hashmap values point to entries in the arrays (no separate allocation).
 */
struct state {
    int version;
    time_t timestamp;
    string_array_t *profiles;

    /* File tracking */
    state_file_entry_t *files;
    size_t file_count;
    size_t file_capacity;
    hashmap_t *file_index;           /* Maps filesystem_path -> state_file_entry_t* (O(1) lookup) */

    /* Directory tracking */
    state_directory_entry_t *directories;
    size_t directory_count;
    size_t directory_capacity;
    hashmap_t *directory_index;      /* Maps filesystem_path -> state_directory_entry_t* (O(1) lookup) */
};

/**
 * Get state file path
 */
static error_t *get_state_file_path(git_repository *repo, char **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    const char *git_dir = git_repository_path(repo);
    if (!git_dir) {
        return ERROR(ERR_GIT, "Failed to get repository path");
    }

    return fs_path_join(git_dir, STATE_FILE_NAME, out);
}

/**
 * Write state to JSON (using cJSON)
 */
static error_t *state_to_json(const state_t *state, buffer_t **out) {
    CHECK_NULL(state);
    CHECK_NULL(out);

    /* Create root object */
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return ERROR(ERR_MEMORY, "Failed to create JSON object");
    }

    /* Add version */
    cJSON_AddNumberToObject(root, "version", STATE_VERSION);

    /* Add timestamp */
    char time_str[64];
    struct tm *tm_info = gmtime(&state->timestamp);
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    cJSON_AddStringToObject(root, "timestamp", time_str);

    /* Add profiles array */
    cJSON *profiles_array = cJSON_CreateArray();
    if (!profiles_array) {
        cJSON_Delete(root);
        return ERROR(ERR_MEMORY, "Failed to create profiles array");
    }
    cJSON_AddItemToObject(root, "profiles", profiles_array);

    if (state->profiles) {
        for (size_t i = 0; i < string_array_size(state->profiles); i++) {
            cJSON *profile_str = cJSON_CreateString(string_array_get(state->profiles, i));
            if (!profile_str) {
                cJSON_Delete(root);
                return ERROR(ERR_MEMORY, "Failed to create profile string");
            }
            cJSON_AddItemToArray(profiles_array, profile_str);
        }
    }

    /* Add files array */
    cJSON *files_array = cJSON_CreateArray();
    if (!files_array) {
        cJSON_Delete(root);
        return ERROR(ERR_MEMORY, "Failed to create files array");
    }
    cJSON_AddItemToObject(root, "files", files_array);

    for (size_t i = 0; i < state->file_count; i++) {
        const state_file_entry_t *entry = &state->files[i];

        cJSON *file_obj = cJSON_CreateObject();
        if (!file_obj) {
            cJSON_Delete(root);
            return ERROR(ERR_MEMORY, "Failed to create file object");
        }

        cJSON_AddStringToObject(file_obj, "storage_path", entry->storage_path);
        cJSON_AddStringToObject(file_obj, "filesystem_path", entry->filesystem_path);
        cJSON_AddStringToObject(file_obj, "profile", entry->profile);

        const char *type_str = entry->type == STATE_FILE_REGULAR ? "file" :
                              entry->type == STATE_FILE_SYMLINK ? "symlink" :
                              "executable";
        cJSON_AddStringToObject(file_obj, "type", type_str);

        if (entry->hash) {
            cJSON_AddStringToObject(file_obj, "hash", entry->hash);
        }
        if (entry->mode) {
            cJSON_AddStringToObject(file_obj, "mode", entry->mode);
        }

        cJSON_AddItemToArray(files_array, file_obj);
    }

    /* Add directories array */
    cJSON *directories_array = cJSON_CreateArray();
    if (!directories_array) {
        cJSON_Delete(root);
        return ERROR(ERR_MEMORY, "Failed to create directories array");
    }
    cJSON_AddItemToObject(root, "directories", directories_array);

    for (size_t i = 0; i < state->directory_count; i++) {
        const state_directory_entry_t *entry = &state->directories[i];

        cJSON *dir_obj = cJSON_CreateObject();
        if (!dir_obj) {
            cJSON_Delete(root);
            return ERROR(ERR_MEMORY, "Failed to create directory object");
        }

        cJSON_AddStringToObject(dir_obj, "filesystem_path", entry->filesystem_path);
        cJSON_AddStringToObject(dir_obj, "storage_prefix", entry->storage_prefix);
        cJSON_AddStringToObject(dir_obj, "profile", entry->profile);

        /* Format timestamp */
        char time_str[64];
        struct tm *tm_info = gmtime(&entry->added_at);
        strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", tm_info);
        cJSON_AddStringToObject(dir_obj, "added_at", time_str);

        cJSON_AddItemToArray(directories_array, dir_obj);
    }

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
 * Create empty state
 */
error_t *state_create_empty(state_t **out) {
    CHECK_NULL(out);

    error_t *err = NULL;
    state_t *state = NULL;

    state = calloc(1, sizeof(state_t));
    if (!state) {
        err = ERROR(ERR_MEMORY, "Failed to allocate state");
        goto cleanup;
    }

    state->version = STATE_VERSION;
    state->timestamp = time(NULL);

    state->profiles = string_array_create();
    if (!state->profiles) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profiles array");
        goto cleanup;
    }

    /* Initialize file tracking */
    state->files = NULL;
    state->file_count = 0;
    state->file_capacity = 0;
    state->file_index = hashmap_create(16);  /* Initial capacity */
    if (!state->file_index) {
        err = ERROR(ERR_MEMORY, "Failed to allocate file index");
        goto cleanup;
    }

    /* Initialize directory tracking */
    state->directories = NULL;
    state->directory_count = 0;
    state->directory_capacity = 0;
    state->directory_index = hashmap_create(16);  /* Initial capacity */
    if (!state->directory_index) {
        err = ERROR(ERR_MEMORY, "Failed to allocate directory index");
        goto cleanup;
    }

    /* Success */
    *out = state;
    state = NULL;  /* Transfer ownership */

cleanup:
    if (state) {
        if (state->directory_index) hashmap_free(state->directory_index, NULL);
        if (state->file_index) hashmap_free(state->file_index, NULL);
        if (state->profiles) string_array_free(state->profiles);
        free(state);
    }

    return err;
}

/**
 * Load state from repository (using cJSON)
 */
error_t *state_load(git_repository *repo, state_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    /* Get state file path */
    char *state_path = NULL;
    error_t *err = get_state_file_path(repo, &state_path);
    if (err) {
        return err;
    }

    /* Check if state file exists */
    if (!fs_file_exists(state_path)) {
        free(state_path);
        /* No state file - return empty state */
        return state_create_empty(out);
    }

    /* Read state file */
    buffer_t *content = NULL;
    err = fs_read_file(state_path, &content);
    free(state_path);
    if (err) {
        return error_wrap(err, "Failed to read state file");
    }

    /* Parse JSON with cJSON */
    const char *json_str = (const char *)buffer_data(content);
    cJSON *root = cJSON_Parse(json_str);
    buffer_free(content);

    if (!root) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr) {
            return ERROR(ERR_STATE_INVALID, "JSON parse error: %s", error_ptr);
        }
        return ERROR(ERR_STATE_INVALID, "Failed to parse state file");
    }

    /* Create state structure */
    state_t *state = calloc(1, sizeof(state_t));
    if (!state) {
        cJSON_Delete(root);
        return ERROR(ERR_MEMORY, "Failed to allocate state");
    }

    state->file_index = hashmap_create(16);
    if (!state->file_index) {
        state_free(state);
        cJSON_Delete(root);
        return ERROR(ERR_MEMORY, "Failed to create file index");
    }

    state->directory_index = hashmap_create(16);
    if (!state->directory_index) {
        state_free(state);
        cJSON_Delete(root);
        return ERROR(ERR_MEMORY, "Failed to create directory index");
    }

    /* Parse version */
    cJSON *version_obj = cJSON_GetObjectItem(root, "version");
    if (!version_obj || !cJSON_IsNumber(version_obj)) {
        state_free(state);
        cJSON_Delete(root);
        return ERROR(ERR_STATE_INVALID, "Missing or invalid version field");
    }
    state->version = version_obj->valueint;
    
    if (state->version != STATE_VERSION) {
        state_free(state);
        cJSON_Delete(root);
        return ERROR(ERR_STATE_INVALID,
                    "State file version %d is incompatible with supported version %d",
                    state->version, STATE_VERSION);
    }

    /* Parse timestamp */
    cJSON *timestamp_obj = cJSON_GetObjectItem(root, "timestamp");
    if (!timestamp_obj || !cJSON_IsString(timestamp_obj)) {
        state_free(state);
        cJSON_Delete(root);
        return ERROR(ERR_STATE_INVALID, "Missing or invalid timestamp field");
    }

    struct tm tm_info = {0};
    if (strptime(timestamp_obj->valuestring, "%Y-%m-%dT%H:%M:%SZ", &tm_info) == NULL) {
        state_free(state);
        cJSON_Delete(root);
        return ERROR(ERR_STATE_INVALID, "Invalid timestamp format");
    }

    /* Convert to time_t (UTC) - thread-safe version */
    state->timestamp = timegm(&tm_info);

    /* Parse profiles array */
    cJSON *profiles_array = cJSON_GetObjectItem(root, "profiles");
    if (!profiles_array || !cJSON_IsArray(profiles_array)) {
        state_free(state);
        cJSON_Delete(root);
        return ERROR(ERR_STATE_INVALID, "Missing or invalid profiles field");
    }

    state->profiles = string_array_create();
    if (!state->profiles) {
        state_free(state);
        cJSON_Delete(root);
        return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
    }

    cJSON *profile_item = NULL;
    cJSON_ArrayForEach(profile_item, profiles_array) {
        if (!cJSON_IsString(profile_item)) {
            state_free(state);
            cJSON_Delete(root);
            return ERROR(ERR_STATE_INVALID, "Invalid profile name in array");
        }
        err = string_array_push(state->profiles, profile_item->valuestring);
        if (err) {
            state_free(state);
            cJSON_Delete(root);
            return err;
        }
    }

    /* Parse files array */
    cJSON *files_array = cJSON_GetObjectItem(root, "files");
    if (!files_array || !cJSON_IsArray(files_array)) {
        state_free(state);
        cJSON_Delete(root);
        return ERROR(ERR_STATE_INVALID, "Missing or invalid files field");
    }

    cJSON *file_obj = NULL;
    cJSON_ArrayForEach(file_obj, files_array) {
        if (!cJSON_IsObject(file_obj)) {
            state_free(state);
            cJSON_Delete(root);
            return ERROR(ERR_STATE_INVALID, "Invalid file entry in array");
        }

        /* Extract required fields */
        cJSON *storage_path_obj = cJSON_GetObjectItem(file_obj, "storage_path");
        cJSON *filesystem_path_obj = cJSON_GetObjectItem(file_obj, "filesystem_path");
        cJSON *profile_obj = cJSON_GetObjectItem(file_obj, "profile");
        cJSON *type_obj = cJSON_GetObjectItem(file_obj, "type");

        if (!storage_path_obj || !cJSON_IsString(storage_path_obj) ||
            !filesystem_path_obj || !cJSON_IsString(filesystem_path_obj) ||
            !profile_obj || !cJSON_IsString(profile_obj) ||
            !type_obj || !cJSON_IsString(type_obj)) {
            state_free(state);
            cJSON_Delete(root);
            return ERROR(ERR_STATE_INVALID, "Missing required file entry fields");
        }

        /* Parse file type */
        state_file_type_t type = STATE_FILE_REGULAR;
        if (strcmp(type_obj->valuestring, "symlink") == 0) {
            type = STATE_FILE_SYMLINK;
        } else if (strcmp(type_obj->valuestring, "executable") == 0) {
            type = STATE_FILE_EXECUTABLE;
        }

        /* Extract optional fields */
        cJSON *hash_obj = cJSON_GetObjectItem(file_obj, "hash");
        cJSON *mode_obj = cJSON_GetObjectItem(file_obj, "mode");

        const char *hash = (hash_obj && cJSON_IsString(hash_obj)) ? hash_obj->valuestring : NULL;
        const char *mode = (mode_obj && cJSON_IsString(mode_obj)) ? mode_obj->valuestring : NULL;

        /* Create file entry */
        state_file_entry_t *file_entry = NULL;
        err = state_create_entry(
            storage_path_obj->valuestring,
            filesystem_path_obj->valuestring,
            profile_obj->valuestring,
            type,
            hash,
            mode,
            &file_entry
        );

        if (err) {
            state_free(state);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to create file entry");
        }

        err = state_add_file(state, file_entry);
        state_free_entry(file_entry);

        if (err) {
            state_free(state);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to add file entry");
        }
    }

    /* Parse directories array */
    cJSON *directories_array = cJSON_GetObjectItem(root, "directories");
    if (!directories_array || !cJSON_IsArray(directories_array)) {
        state_free(state);
        cJSON_Delete(root);
        return ERROR(ERR_STATE_INVALID, "Missing or invalid directories field");
    }

    /* Initialize directories storage */
    state->directories = NULL;
    state->directory_count = 0;
    state->directory_capacity = 0;

    cJSON *dir_obj = NULL;
    cJSON_ArrayForEach(dir_obj, directories_array) {
        if (!cJSON_IsObject(dir_obj)) {
            state_free(state);
            cJSON_Delete(root);
            return ERROR(ERR_STATE_INVALID, "Invalid directory entry in array");
        }

        /* Extract required fields */
        cJSON *fs_path_obj = cJSON_GetObjectItem(dir_obj, "filesystem_path");
        cJSON *storage_prefix_obj = cJSON_GetObjectItem(dir_obj, "storage_prefix");
        cJSON *profile_obj = cJSON_GetObjectItem(dir_obj, "profile");
        cJSON *added_at_obj = cJSON_GetObjectItem(dir_obj, "added_at");

        if (!fs_path_obj || !cJSON_IsString(fs_path_obj) ||
            !storage_prefix_obj || !cJSON_IsString(storage_prefix_obj) ||
            !profile_obj || !cJSON_IsString(profile_obj) ||
            !added_at_obj || !cJSON_IsString(added_at_obj)) {
            state_free(state);
            cJSON_Delete(root);
            return ERROR(ERR_STATE_INVALID, "Missing required directory entry fields");
        }

        /* Parse timestamp */
        struct tm tm_info = {0};
        if (strptime(added_at_obj->valuestring, "%Y-%m-%dT%H:%M:%SZ", &tm_info) == NULL) {
            state_free(state);
            cJSON_Delete(root);
            return ERROR(ERR_STATE_INVALID, "Invalid directory timestamp format");
        }
        time_t added_at = timegm(&tm_info);

        /* Create directory entry */
        state_directory_entry_t *dir_entry = NULL;
        err = state_create_directory_entry(
            fs_path_obj->valuestring,
            storage_prefix_obj->valuestring,
            profile_obj->valuestring,
            added_at,
            &dir_entry
        );

        if (err) {
            state_free(state);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to create directory entry");
        }

        err = state_add_directory(state, dir_entry);
        state_free_directory_entry(dir_entry);

        if (err) {
            state_free(state);
            cJSON_Delete(root);
            return error_wrap(err, "Failed to add directory entry");
        }
    }

    cJSON_Delete(root);
    *out = state;
    return NULL;
}

/**
 * Save state to repository
 */
error_t *state_save(git_repository *repo, const state_t *state) {
    CHECK_NULL(repo);
    CHECK_NULL(state);

    /* Get state file path */
    char *state_path = NULL;
    error_t *err = get_state_file_path(repo, &state_path);
    if (err) {
        return err;
    }

    /* Convert state to JSON */
    buffer_t *json = NULL;
    err = state_to_json(state, &json);
    if (err) {
        free(state_path);
        return err;
    }

    /* Write to temporary file first (atomic write) */
    char temp_path[PATH_MAX];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", state_path);

    err = fs_write_file(temp_path, json);
    buffer_free(json);
    if (err) {
        free(state_path);
        return error_wrap(err, "Failed to write state file");
    }

    /* Rename to final location (atomic) */
    if (rename(temp_path, state_path) < 0) {
        fs_remove_file(temp_path);
        free(state_path);
        return ERROR(ERR_FS, "Failed to save state file: %s", strerror(errno));
    }

    free(state_path);
    return NULL;
}

/**
 * Free state
 */
void state_free(state_t *state) {
    if (!state) {
        return;
    }

    string_array_free(state->profiles);

    /* Free file entries */
    for (size_t i = 0; i < state->file_count; i++) {
        state_file_entry_t *entry = &state->files[i];
        free(entry->storage_path);
        free(entry->filesystem_path);
        free(entry->profile);
        free(entry->hash);
        free(entry->mode);
    }
    free(state->files);

    /* Free file index (values point to entries array, so no value free callback) */
    if (state->file_index) {
        hashmap_free(state->file_index, NULL);
    }

    /* Free directory entries */
    for (size_t i = 0; i < state->directory_count; i++) {
        state_directory_entry_t *entry = &state->directories[i];
        free(entry->filesystem_path);
        free(entry->storage_prefix);
        free(entry->profile);
    }
    free(state->directories);

    /* Free directory index (values point to entries array, so no value free callback) */
    if (state->directory_index) {
        hashmap_free(state->directory_index, NULL);
    }

    free(state);
}

/**
 * Add file to state
 */
error_t *state_add_file(state_t *state, const state_file_entry_t *entry) {
    CHECK_NULL(state);
    CHECK_NULL(entry);

    bool need_rebuild = false;

    /* Grow array if needed */
    if (state->file_count >= state->file_capacity) {
        size_t new_capacity = state->file_capacity == 0 ? 16 : state->file_capacity * 2;
        state_file_entry_t *new_files = realloc(state->files,
                                                 new_capacity * sizeof(state_file_entry_t));
        if (!new_files) {
            return ERROR(ERR_MEMORY, "Failed to grow files array");
        }
        state->files = new_files;
        state->file_capacity = new_capacity;
        need_rebuild = true;  /* Array moved, need to rebuild hashmap */
    }

    /* Copy entry */
    state_file_entry_t *dst = &state->files[state->file_count];
    memset(dst, 0, sizeof(state_file_entry_t));

    dst->storage_path = strdup(entry->storage_path);
    dst->filesystem_path = strdup(entry->filesystem_path);
    dst->profile = strdup(entry->profile);
    dst->type = entry->type;
    dst->hash = entry->hash ? strdup(entry->hash) : NULL;
    dst->mode = entry->mode ? strdup(entry->mode) : NULL;

    if (!dst->storage_path || !dst->filesystem_path || !dst->profile) {
        free(dst->storage_path);
        free(dst->filesystem_path);
        free(dst->profile);
        free(dst->hash);
        free(dst->mode);
        return ERROR(ERR_MEMORY, "Failed to copy file entry");
    }

    state->file_count++;

    /* Update hashmap index */
    if (state->file_index) {
        if (need_rebuild) {
            /* Rebuild entire index since array was reallocated */
            hashmap_clear(state->file_index, NULL);
            for (size_t i = 0; i < state->file_count; i++) {
                error_t *err = hashmap_set(state->file_index,
                                           state->files[i].filesystem_path,
                                           &state->files[i]);
                if (err) {
                    /* Continue despite error - index will be incomplete but functional */
                    error_free(err);
                }
            }
        } else {
            /* Just add the new entry */
            error_t *err = hashmap_set(state->file_index, dst->filesystem_path, dst);
            if (err) {
                /* Not fatal - fallback to linear search */
                error_free(err);
            }
        }
    }

    return NULL;
}

/**
 * Remove file entry from state
 *
 * Uses swap-with-last optimization for O(1) removal.
 * Correctly handles memory management to avoid dangling pointers.
 */
error_t *state_remove_file(state_t *state, const char *filesystem_path) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);

    /* Find file in array to get its index */
    size_t found_index = SIZE_MAX;
    for (size_t i = 0; i < state->file_count; i++) {
        if (strcmp(state->files[i].filesystem_path, filesystem_path) == 0) {
            found_index = i;
            break;
        }
    }

    if (found_index == SIZE_MAX) {
        return ERROR(ERR_NOT_FOUND, "File '%s' not found in state", filesystem_path);
    }

    /* Remove from hashmap first (using the entry we're about to free) */
    if (state->file_index) {
        hashmap_remove(state->file_index, filesystem_path, NULL);
    }

    /* Free the strings at found_index BEFORE any swapping */
    state_file_entry_t *entry_to_remove = &state->files[found_index];
    free(entry_to_remove->storage_path);
    free(entry_to_remove->filesystem_path);
    free(entry_to_remove->profile);
    free(entry_to_remove->hash);
    free(entry_to_remove->mode);

    /* Calculate last element index */
    size_t last_index = state->file_count - 1;

    /* If not removing last element, move last element into the gap */
    if (found_index < last_index) {
        /* Shallow copy is safe now since we freed the old strings */
        state->files[found_index] = state->files[last_index];

        /* Update hashmap to point to the moved entry's new location */
        if (state->file_index) {
            error_t *err = hashmap_set(state->file_index,
                                       state->files[found_index].filesystem_path,
                                       &state->files[found_index]);
            if (err) {
                /* Continue despite hashmap inconsistency - linear search fallback exists */
                error_free(err);
            }
        }
    }

    /* Decrement count (last element is now unused) */
    state->file_count--;

    return NULL;
}

/**
 * Check if file exists in state
 */
bool state_file_exists(const state_t *state, const char *filesystem_path) {
    if (!state || !filesystem_path) {
        return false;
    }

    /* Use hashmap for O(1) lookup */
    if (state->file_index) {
        return hashmap_has(state->file_index, filesystem_path);
    }

    /* Fallback to linear search if no index */
    for (size_t i = 0; i < state->file_count; i++) {
        if (strcmp(state->files[i].filesystem_path, filesystem_path) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Get file entry
 */
error_t *state_get_file(
    const state_t *state,
    const char *filesystem_path,
    const state_file_entry_t **out
) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(out);

    /* Use hashmap for O(1) lookup */
    if (state->file_index) {
        state_file_entry_t *entry = hashmap_get(state->file_index, filesystem_path);
        if (!entry) {
            return ERROR(ERR_NOT_FOUND, "File not found in state: %s", filesystem_path);
        }
        *out = entry;
        return NULL;
    }

    /* Fallback to linear search if no index */
    for (size_t i = 0; i < state->file_count; i++) {
        if (strcmp(state->files[i].filesystem_path, filesystem_path) == 0) {
            *out = &state->files[i];
            return NULL;
        }
    }

    return ERROR(ERR_NOT_FOUND, "File not found in state: %s", filesystem_path);
}

/**
 * Get all files
 */
const state_file_entry_t *state_get_all_files(const state_t *state, size_t *count) {
    if (!state || !count) {
        if (count) *count = 0;
        return NULL;
    }

    *count = state->file_count;
    return state->files;
}

/**
 * Set profiles
 */
error_t *state_set_profiles(
    state_t *state,
    const char **profiles,
    size_t count
) {
    CHECK_NULL(state);
    CHECK_NULL(profiles);

    string_array_clear(state->profiles);

    for (size_t i = 0; i < count; i++) {
        error_t *err = string_array_push(state->profiles, profiles[i]);
        if (err) {
            return err;
        }
    }

    return NULL;
}

/**
 * Get profiles
 */
error_t *state_get_profiles(const state_t *state, string_array_t **out) {
    CHECK_NULL(state);
    CHECK_NULL(out);

    /* Create copy */
    string_array_t *copy = string_array_create();
    if (!copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
    }

    for (size_t i = 0; i < string_array_size(state->profiles); i++) {
        error_t *err = string_array_push(copy, string_array_get(state->profiles, i));
        if (err) {
            string_array_free(copy);
            return err;
        }
    }

    *out = copy;
    return NULL;
}

/**
 * Get timestamp
 */
time_t state_get_timestamp(const state_t *state) {
    if (!state) {
        return 0;
    }
    return state->timestamp;
}

/**
 * Clear files
 */
void state_clear_files(state_t *state) {
    if (!state) {
        return;
    }

    for (size_t i = 0; i < state->file_count; i++) {
        state_file_entry_t *entry = &state->files[i];
        free(entry->storage_path);
        free(entry->filesystem_path);
        free(entry->profile);
        free(entry->hash);
        free(entry->mode);
    }

    state->file_count = 0;

    /* Clear file index */
    if (state->file_index) {
        hashmap_clear(state->file_index, NULL);
    }
}

/**
 * Create file entry
 */
error_t *state_create_entry(
    const char *storage_path,
    const char *filesystem_path,
    const char *profile,
    state_file_type_t type,
    const char *hash,
    const char *mode,
    state_file_entry_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    state_file_entry_t *entry = calloc(1, sizeof(state_file_entry_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate entry");
    }

    entry->storage_path = strdup(storage_path);
    entry->filesystem_path = strdup(filesystem_path);
    entry->profile = strdup(profile);
    entry->type = type;
    entry->hash = hash ? strdup(hash) : NULL;
    entry->mode = mode ? strdup(mode) : NULL;

    if (!entry->storage_path || !entry->filesystem_path || !entry->profile) {
        state_free_entry(entry);
        return ERROR(ERR_MEMORY, "Failed to copy entry fields");
    }

    *out = entry;
    return NULL;
}

/**
 * Free file entry
 */
void state_free_entry(state_file_entry_t *entry) {
    if (!entry) {
        return;
    }

    free(entry->storage_path);
    free(entry->filesystem_path);
    free(entry->profile);
    free(entry->hash);
    free(entry->mode);
    free(entry);
}

/**
 * Add directory to state
 */
error_t *state_add_directory(state_t *state, const state_directory_entry_t *entry) {
    CHECK_NULL(state);
    CHECK_NULL(entry);

    bool need_rebuild = false;

    /* Grow array if needed */
    if (state->directory_count >= state->directory_capacity) {
        size_t new_capacity = state->directory_capacity == 0 ? 16 : state->directory_capacity * 2;
        state_directory_entry_t *new_dirs = realloc(state->directories,
                                                     new_capacity * sizeof(state_directory_entry_t));
        if (!new_dirs) {
            return ERROR(ERR_MEMORY, "Failed to grow directories array");
        }
        state->directories = new_dirs;
        state->directory_capacity = new_capacity;
        need_rebuild = true;  /* Array moved, need to rebuild hashmap */
    }

    /* Copy entry */
    state_directory_entry_t *dst = &state->directories[state->directory_count];
    memset(dst, 0, sizeof(state_directory_entry_t));

    dst->filesystem_path = strdup(entry->filesystem_path);
    dst->storage_prefix = strdup(entry->storage_prefix);
    dst->profile = strdup(entry->profile);
    dst->added_at = entry->added_at;

    if (!dst->filesystem_path || !dst->storage_prefix || !dst->profile) {
        free(dst->filesystem_path);
        free(dst->storage_prefix);
        free(dst->profile);
        return ERROR(ERR_MEMORY, "Failed to copy directory entry");
    }

    state->directory_count++;

    /* Update hashmap index */
    if (state->directory_index) {
        if (need_rebuild) {
            /* Rebuild entire index since array was reallocated */
            hashmap_clear(state->directory_index, NULL);
            for (size_t i = 0; i < state->directory_count; i++) {
                error_t *err = hashmap_set(state->directory_index,
                                           state->directories[i].filesystem_path,
                                           &state->directories[i]);
                if (err) {
                    /* Continue despite error - index will be incomplete but functional */
                    error_free(err);
                }
            }
        } else {
            /* Just add the new entry */
            error_t *err = hashmap_set(state->directory_index, dst->filesystem_path, dst);
            if (err) {
                /* Not fatal - fallback to linear search */
                error_free(err);
            }
        }
    }

    return NULL;
}

/**
 * Remove directory entry from state
 *
 * Uses swap-with-last optimization for O(1) removal.
 * Correctly handles memory management to avoid dangling pointers.
 */
error_t *state_remove_directory(state_t *state, const char *filesystem_path) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);

    /* Find directory in array to get its index */
    size_t found_index = SIZE_MAX;
    for (size_t i = 0; i < state->directory_count; i++) {
        if (strcmp(state->directories[i].filesystem_path, filesystem_path) == 0) {
            found_index = i;
            break;
        }
    }

    if (found_index == SIZE_MAX) {
        return ERROR(ERR_NOT_FOUND, "Directory '%s' not found in state", filesystem_path);
    }

    /* Remove from hashmap first (using the entry we're about to free) */
    if (state->directory_index) {
        hashmap_remove(state->directory_index, filesystem_path, NULL);
    }

    /* Free the strings at found_index BEFORE any swapping */
    state_directory_entry_t *entry_to_remove = &state->directories[found_index];
    free(entry_to_remove->filesystem_path);
    free(entry_to_remove->storage_prefix);
    free(entry_to_remove->profile);

    /* Calculate last element index */
    size_t last_index = state->directory_count - 1;

    /* If not removing last element, move last element into the gap */
    if (found_index < last_index) {
        /* Shallow copy is safe now since we freed the old strings */
        state->directories[found_index] = state->directories[last_index];

        /* Update hashmap to point to the moved entry's new location */
        if (state->directory_index) {
            error_t *err = hashmap_set(state->directory_index,
                                       state->directories[found_index].filesystem_path,
                                       &state->directories[found_index]);
            if (err) {
                /* Continue despite hashmap inconsistency - linear search fallback exists */
                error_free(err);
            }
        }
    }

    /* Decrement count (last element is now unused) */
    state->directory_count--;

    return NULL;
}

/**
 * Check if directory exists in state
 */
bool state_directory_exists(const state_t *state, const char *filesystem_path) {
    if (!state || !filesystem_path) {
        return false;
    }

    /* Use hashmap for O(1) lookup */
    if (state->directory_index) {
        return hashmap_has(state->directory_index, filesystem_path);
    }

    /* Fallback to linear search if no index */
    for (size_t i = 0; i < state->directory_count; i++) {
        if (strcmp(state->directories[i].filesystem_path, filesystem_path) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Get directory entry
 */
error_t *state_get_directory(
    const state_t *state,
    const char *filesystem_path,
    const state_directory_entry_t **out
) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(out);

    /* Use hashmap for O(1) lookup */
    if (state->directory_index) {
        state_directory_entry_t *entry = hashmap_get(state->directory_index, filesystem_path);
        if (!entry) {
            return ERROR(ERR_NOT_FOUND, "Directory not found in state: %s", filesystem_path);
        }
        *out = entry;
        return NULL;
    }

    /* Fallback to linear search if no index */
    for (size_t i = 0; i < state->directory_count; i++) {
        if (strcmp(state->directories[i].filesystem_path, filesystem_path) == 0) {
            *out = &state->directories[i];
            return NULL;
        }
    }

    return ERROR(ERR_NOT_FOUND, "Directory not found in state: %s", filesystem_path);
}

/**
 * Get all directories
 */
const state_directory_entry_t *state_get_all_directories(const state_t *state, size_t *count) {
    if (!state || !count) {
        if (count) *count = 0;
        return NULL;
    }

    *count = state->directory_count;
    return state->directories;
}

/**
 * Clear directories
 */
void state_clear_directories(state_t *state) {
    if (!state) {
        return;
    }

    for (size_t i = 0; i < state->directory_count; i++) {
        state_directory_entry_t *entry = &state->directories[i];
        free(entry->filesystem_path);
        free(entry->storage_prefix);
        free(entry->profile);
    }

    state->directory_count = 0;

    /* Clear directory index */
    if (state->directory_index) {
        hashmap_clear(state->directory_index, NULL);
    }
}

/**
 * Create directory entry
 */
error_t *state_create_directory_entry(
    const char *filesystem_path,
    const char *storage_prefix,
    const char *profile,
    time_t added_at,
    state_directory_entry_t **out
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_prefix);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    state_directory_entry_t *entry = calloc(1, sizeof(state_directory_entry_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate entry");
    }

    entry->filesystem_path = strdup(filesystem_path);
    entry->storage_prefix = strdup(storage_prefix);
    entry->profile = strdup(profile);
    entry->added_at = added_at;

    if (!entry->filesystem_path || !entry->storage_prefix || !entry->profile) {
        state_free_directory_entry(entry);
        return ERROR(ERR_MEMORY, "Failed to copy entry fields");
    }

    *out = entry;
    return NULL;
}

/**
 * Free directory entry
 */
void state_free_directory_entry(state_directory_entry_t *entry) {
    if (!entry) {
        return;
    }

    free(entry->filesystem_path);
    free(entry->storage_prefix);
    free(entry->profile);
    free(entry);
}

/**
 * Remove all file and directory entries for a specific profile
 *
 * Implementation note: We must collect paths first, then remove them.
 * Cannot remove during iteration because state_remove_file/directory
 * may reorder the array (swap-with-last optimization).
 */
error_t *state_cleanup_profile(
    state_t *state,
    const char *profile,
    size_t *removed_count
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);

    size_t total_removed = 0;
    error_t *err = NULL;

    /* Step 1: Collect file paths that match this profile */
    string_array_t *files_to_remove = string_array_create();
    if (!files_to_remove) {
        return ERROR(ERR_MEMORY, "Failed to create file removal array");
    }

    for (size_t i = 0; i < state->file_count; i++) {
        if (strcmp(state->files[i].profile, profile) == 0) {
            err = string_array_push(files_to_remove, state->files[i].filesystem_path);
            if (err) {
                string_array_free(files_to_remove);
                return error_wrap(err, "Failed to collect file paths");
            }
        }
    }

    /* Step 2: Remove collected files */
    for (size_t i = 0; i < string_array_size(files_to_remove); i++) {
        const char *path = string_array_get(files_to_remove, i);
        err = state_remove_file(state, path);
        if (err) {
            /* Individual removal failure shouldn't stop the whole cleanup
             * (defensive: continue cleaning up other entries) */
            error_free(err);
            err = NULL;
        } else {
            total_removed++;
        }
    }

    string_array_free(files_to_remove);

    /* Step 3: Collect directory paths that match this profile */
    string_array_t *dirs_to_remove = string_array_create();
    if (!dirs_to_remove) {
        /* Already removed some files, return partial success with warning */
        if (removed_count) {
            *removed_count = total_removed;
        }
        return ERROR(ERR_MEMORY, "Failed to create directory removal array (partial cleanup completed)");
    }

    for (size_t i = 0; i < state->directory_count; i++) {
        if (strcmp(state->directories[i].profile, profile) == 0) {
            err = string_array_push(dirs_to_remove, state->directories[i].filesystem_path);
            if (err) {
                string_array_free(dirs_to_remove);
                if (removed_count) {
                    *removed_count = total_removed;
                }
                return error_wrap(err, "Failed to collect directory paths (partial cleanup completed)");
            }
        }
    }

    /* Step 4: Remove collected directories */
    for (size_t i = 0; i < string_array_size(dirs_to_remove); i++) {
        const char *path = string_array_get(dirs_to_remove, i);
        err = state_remove_directory(state, path);
        if (err) {
            /* Individual removal failure shouldn't stop the whole cleanup */
            error_free(err);
            err = NULL;
        } else {
            total_removed++;
        }
    }

    string_array_free(dirs_to_remove);

    /* Return total count (caller can handle removed_count being NULL) */
    if (removed_count) {
        *removed_count = total_removed;
    }

    return NULL;
}
