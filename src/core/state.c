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
#include <fcntl.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "base/error.h"
#include "base/filesystem.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"

#define STATE_FILE_NAME "dotta-state.json"
#define STATE_VERSION 2

/**
 * State lock handle
 *
 * Used to coordinate concurrent access to the state file across processes.
 * Uses fcntl advisory locking for robustness and portability.
 */
typedef struct {
    int fd;
    char *lock_path;
} state_lock_t;

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
    hashmap_t *file_index;     /* Maps filesystem_path -> state_file_entry_t* (O(1) lookup) */

    /* Locking for write transactions */
    state_lock_t *lock;        /* NULL for read-only, non-NULL if acquired via state_load_for_update() */
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
 * Acquire state file lock
 *
 * Creates a .lock file to prevent concurrent state modifications.
 * Uses fcntl advisory locking for robustness and portability.
 *
 * @param repo Repository (must not be NULL)
 * @param lock Output lock handle (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *state_lock_acquire(git_repository *repo, state_lock_t **lock) {
    CHECK_NULL(repo);
    CHECK_NULL(lock);

    const char *git_dir = git_repository_path(repo);
    if (!git_dir) {
        return ERROR(ERR_INTERNAL, "Failed to get repository path");
    }

    /* Build lock file path */
    char lock_path[PATH_MAX];
    int ret = snprintf(lock_path, sizeof(lock_path), "%s/dotta-state.json.lock", git_dir);
    if (ret < 0 || (size_t)ret >= sizeof(lock_path)) {
        return ERROR(ERR_FS, "Lock path too long");
    }

    /* Open lock file with O_CLOEXEC to prevent fd leaks to child processes */
    int fd = open(lock_path, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
    if (fd < 0) {
        return ERROR(ERR_FS, "Failed to open lock file: %s", strerror(errno));
    }

    /* Try to acquire exclusive lock (non-blocking) */
    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0  /* Lock entire file */
    };

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        close(fd);
        if (errno == EACCES || errno == EAGAIN) {
            return ERROR(ERR_CONFLICT,
                        "State file is locked by another process\n"
                        "Hint: Wait for the other operation to complete");
        }
        return ERROR(ERR_FS, "Failed to acquire lock: %s", strerror(errno));
    }

    /* Write PID to lock file for debugging */
    pid_t pid = getpid();
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", pid);
    if (write(fd, pid_str, strlen(pid_str)) < 0) {
        /* Non-fatal - lock is still acquired */
    }

    /* Create lock handle */
    state_lock_t *l = calloc(1, sizeof(state_lock_t));
    if (!l) {
        close(fd);
        unlink(lock_path);
        return ERROR(ERR_MEMORY, "Failed to allocate lock");
    }

    l->fd = fd;
    l->lock_path = strdup(lock_path);
    if (!l->lock_path) {
        close(fd);
        free(l);
        unlink(lock_path);
        return ERROR(ERR_MEMORY, "Failed to allocate lock path");
    }

    *lock = l;
    return NULL;
}

/**
 * Release state file lock
 *
 * @param lock Lock handle (can be NULL)
 */
static void state_lock_release(state_lock_t *lock) {
    if (!lock) {
        return;
    }

    if (lock->fd >= 0) {
        /* Release lock (automatically released on close, but explicit is better) */
        struct flock fl = {
            .l_type = F_UNLCK,
            .l_whence = SEEK_SET,
            .l_start = 0,
            .l_len = 0
        };
        fcntl(lock->fd, F_SETLK, &fl);

        close(lock->fd);
    }

    if (lock->lock_path) {
        /* Remove lock file */
        unlink(lock->lock_path);
        free(lock->lock_path);
    }

    free(lock);
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

    /* Initialize lock (no lock by default) */
    state->lock = NULL;

    /* Success */
    *out = state;
    state = NULL;  /* Transfer ownership */

cleanup:
    if (state) {
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

    cJSON_Delete(root);
    *out = state;
    return NULL;
}

/**
 * Load state for update (with locking)
 *
 * This function loads state and acquires an exclusive lock to prevent
 * concurrent modifications. The lock is stored in the state structure
 * and automatically released by state_save() or state_free().
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_load_for_update(git_repository *repo, state_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    error_t *err = NULL;
    state_t *state = NULL;
    state_lock_t *lock = NULL;

    /* Acquire lock first (before loading state) */
    err = state_lock_acquire(repo, &lock);
    if (err) {
        return err;
    }

    /* Load state */
    err = state_load(repo, &state);
    if (err) {
        state_lock_release(lock);
        return err;
    }

    /* Attach lock to state for automatic cleanup */
    state->lock = lock;

    *out = state;
    return NULL;
}

/**
 * Save state to repository
 */
error_t *state_save(git_repository *repo, state_t *state) {
    CHECK_NULL(repo);
    CHECK_NULL(state);

    error_t *err = NULL;
    bool acquired_lock_here = false;

    /* If no lock is held, acquire one for this save operation
     * This handles cases like state_create_empty() where we create
     * state without loading (init, clone commands).
     */
    if (!state->lock) {
        err = state_lock_acquire(repo, &state->lock);
        if (err) {
            return err;
        }
        acquired_lock_here = true;
    }

    /* Get state file path */
    char *state_path = NULL;
    err = get_state_file_path(repo, &state_path);
    if (err) {
        if (acquired_lock_here) {
            state_lock_release(state->lock);
            state->lock = NULL;
        }
        return err;
    }

    /* Convert state to JSON */
    buffer_t *json = NULL;
    err = state_to_json(state, &json);
    if (err) {
        free(state_path);
        if (acquired_lock_here) {
            state_lock_release(state->lock);
            state->lock = NULL;
        }
        return err;
    }

    /* Write to temporary file first (atomic write) */
    char temp_path[PATH_MAX];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", state_path);

    err = fs_write_file(temp_path, json);
    buffer_free(json);
    if (err) {
        free(state_path);
        if (acquired_lock_here) {
            state_lock_release(state->lock);
            state->lock = NULL;
        }
        return error_wrap(err, "Failed to write state file");
    }

    /* Rename to final location (atomic) */
    if (rename(temp_path, state_path) < 0) {
        fs_remove_file(temp_path);
        free(state_path);
        if (acquired_lock_here) {
            state_lock_release(state->lock);
            state->lock = NULL;
        }
        return ERROR(ERR_FS, "Failed to save state file: %s", strerror(errno));
    }

    free(state_path);

    /* Always release lock after successful save */
    state_lock_release(state->lock);
    state->lock = NULL;

    return NULL;
}

/**
 * Free state
 */
void state_free(state_t *state) {
    if (!state) {
        return;
    }

    /* Release lock if still held (cleanup for error paths) */
    if (state->lock) {
        state_lock_release(state->lock);
        state->lock = NULL;
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
