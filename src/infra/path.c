/**
 * path.c - Path resolution and conversion implementation
 *
 * SECURITY: All path operations validate against path traversal attacks.
 */

#include "path.h"

#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/string.h"

/**
 * Get $HOME directory
 */
error_t *path_get_home(char **out) {
    CHECK_NULL(out);

    /* Try $HOME environment variable first */
    const char *home = getenv("HOME");
    if (home && home[0] != '\0') {
        *out = strdup(home);
        if (!*out) {
            return ERROR(ERR_MEMORY, "Failed to allocate HOME path");
        }
        return NULL;
    }

    /* Fall back to passwd database */
    struct passwd *pw = getpwuid(getuid());
    if (!pw || !pw->pw_dir) {
        return ERROR(ERR_FS, "Unable to determine HOME directory");
    }

    *out = strdup(pw->pw_dir);
    if (!*out) {
        return ERROR(ERR_MEMORY, "Failed to allocate HOME path");
    }

    return NULL;
}

/**
 * Validate storage path (SECURITY CRITICAL)
 */
error_t *path_validate_storage(const char *storage_path) {
    CHECK_NULL(storage_path);

    if (storage_path[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Storage path cannot be empty");
    }

    /* SECURITY: Reject absolute paths */
    if (storage_path[0] == '/') {
        return ERROR(ERR_INVALID_ARG,
                    "Storage path must be relative (got '%s')", storage_path);
    }

    /* SECURITY: Must start with home/ or root/ */
    if (!str_starts_with(storage_path, "home/") &&
        !str_starts_with(storage_path, "root/")) {
        return ERROR(ERR_INVALID_ARG,
                    "Storage path must start with 'home/' or 'root/' (got '%s')",
                    storage_path);
    }

    /* SECURITY: Additional checks */
    /* Check for consecutive slashes */
    if (strstr(storage_path, "//") != NULL) {
        return ERROR(ERR_INVALID_ARG,
                    "Invalid path format (consecutive slashes): '%s'", storage_path);
    }

    /* SECURITY: Validate path component-by-component to prevent traversal */
    /* Split path and check each component */
    char *path_copy = strdup(storage_path);
    if (!path_copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate path copy");
    }

    char *saveptr = NULL;
    char *component = strtok_r(path_copy, "/", &saveptr);

    while (component != NULL) {
        /* Check if component is exactly ".." (path traversal) */
        if (strcmp(component, "..") == 0) {
            free(path_copy);
            return ERROR(ERR_INVALID_ARG,
                        "Path traversal not allowed (component '..' in '%s')",
                        storage_path);
        }

        /* Check if component is "." (redundant, but potentially suspicious) */
        if (strcmp(component, ".") == 0) {
            free(path_copy);
            return ERROR(ERR_INVALID_ARG,
                        "Invalid path component '.' in '%s'", storage_path);
        }

        /* Check for empty component (would indicate //) */
        if (component[0] == '\0') {
            free(path_copy);
            return ERROR(ERR_INVALID_ARG,
                        "Empty path component in '%s'", storage_path);
        }

        component = strtok_r(NULL, "/", &saveptr);
    }

    free(path_copy);
    return NULL;
}

/**
 * Validate filesystem path
 */
error_t *path_validate_filesystem(const char *filesystem_path) {
    CHECK_NULL(filesystem_path);

    if (filesystem_path[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Filesystem path cannot be empty");
    }

    /* For now, just require absolute paths */
    if (filesystem_path[0] != '/' && filesystem_path[0] != '~') {
        return ERROR(ERR_INVALID_ARG,
                    "Filesystem path must be absolute (got '%s')", filesystem_path);
    }

    return NULL;
}

/**
 * Check if path is under $HOME
 */
bool path_is_under_home(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    char *home = NULL;
    if (path_get_home(&home) != NULL) {
        return false;
    }

    bool result = str_starts_with(path, home);
    free(home);
    return result;
}

/**
 * Expand ~ to $HOME
 */
error_t *path_expand_home(const char *path, char **out) {
    CHECK_NULL(path);
    CHECK_NULL(out);

    if (path[0] != '~') {
        /* Not a tilde path, return as-is */
        *out = strdup(path);
        if (!*out) {
            return ERROR(ERR_MEMORY, "Failed to duplicate path");
        }
        return NULL;
    }

    /* Get HOME directory */
    char *home = NULL;
    error_t *err = path_get_home(&home);
    if (err) {
        return err;
    }

    /* Build expanded path */
    const char *rest = path + 1;  /* Skip ~ */
    if (rest[0] == '/' || rest[0] == '\0') {
        /* ~/foo or ~ */
        err = fs_path_join(home, rest[0] == '/' ? rest + 1 : "", out);
    } else {
        /* ~user/foo - not supported for now */
        free(home);
        return ERROR(ERR_INVALID_ARG,
                    "~user syntax not supported (got '%s')", path);
    }

    free(home);
    return err;
}

/**
 * Convert filesystem path to storage path
 */
error_t *path_to_storage(
    const char *filesystem_path,
    char **storage_path,
    path_prefix_t *prefix_out
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);

    /* Validate input */
    error_t *err = path_validate_filesystem(filesystem_path);
    if (err) {
        return err;
    }

    /* Expand ~ if needed */
    char *expanded = NULL;
    if (filesystem_path[0] == '~') {
        err = path_expand_home(filesystem_path, &expanded);
        if (err) {
            return err;
        }
        filesystem_path = expanded;
    }

    /* Canonicalize path */
    char *canonical = NULL;
    err = fs_canonicalize_path(filesystem_path, &canonical);
    if (expanded) {
        free(expanded);
    }
    if (err) {
        return err;
    }

    /* Check if under $HOME */
    char *home = NULL;
    err = path_get_home(&home);
    if (err) {
        free(canonical);
        return err;
    }

    size_t home_len = strlen(home);
    path_prefix_t prefix;

    if (str_starts_with(canonical, home)) {
        /* Path is under $HOME */
        prefix = PREFIX_HOME;

        /* Extract relative part */
        const char *rel = canonical + home_len;
        if (rel[0] == '/') {
            rel++;  /* Skip leading slash */
        }

        if (rel[0] == '\0') {
            /* Home directory itself - not supported */
            free(home);
            free(canonical);
            return ERROR(ERR_INVALID_ARG,
                        "Cannot store HOME directory itself");
        }

        /* Build storage path: home/... */
        *storage_path = str_format("home/%s", rel);
        if (!*storage_path) {
            free(home);
            free(canonical);
            return ERROR(ERR_MEMORY, "Failed to format storage path");
        }
    } else {
        /* Path is outside $HOME - use root/ prefix */
        prefix = PREFIX_ROOT;

        /* Build storage path: root/... */
        *storage_path = str_format("root%s", canonical);
        if (!*storage_path) {
            free(home);
            free(canonical);
            return ERROR(ERR_MEMORY, "Failed to format storage path");
        }
    }

    free(home);
    free(canonical);

    /* Validate generated storage path */
    err = path_validate_storage(*storage_path);
    if (err) {
        free(*storage_path);
        *storage_path = NULL;
        return err;
    }

    if (prefix_out) {
        *prefix_out = prefix;
    }

    return NULL;
}

/**
 * Convert storage path to filesystem path
 */
error_t *path_from_storage(
    const char *storage_path,
    char **filesystem_path
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(filesystem_path);

    /* Validate storage path */
    error_t *err = path_validate_storage(storage_path);
    if (err) {
        return err;
    }

    if (str_starts_with(storage_path, "home/")) {
        /* home/.bashrc -> $HOME/.bashrc */
        char *home = NULL;
        err = path_get_home(&home);
        if (err) {
            return err;
        }

        const char *rel = storage_path + strlen("home/");
        err = fs_path_join(home, rel, filesystem_path);
        free(home);
        return err;

    } else if (str_starts_with(storage_path, "root/")) {
        /* root/etc/hosts -> /etc/hosts */
        const char *abs = storage_path + strlen("root");
        *filesystem_path = strdup(abs);
        if (!*filesystem_path) {
            return ERROR(ERR_MEMORY, "Failed to allocate filesystem path");
        }
        return NULL;

    } else {
        /* Should never happen due to validation */
        return ERROR(ERR_INTERNAL,
                    "Invalid storage path prefix: '%s'", storage_path);
    }
}

/**
 * Splits a path into its components.
 */
static error_t *path_split(const char *path, string_array_t **out) {
    char *path_copy = strdup(path);
    if (!path_copy) {
        return ERROR(ERR_MEMORY, "Failed to copy path");
    }

    string_array_t *arr = string_array_create();
    if (!arr) {
        free(path_copy);
        return ERROR(ERR_MEMORY, "Failed to create string array");
    }

    char *saveptr = NULL;
    char *component = strtok_r(path_copy, "/", &saveptr);
    while (component) {
        string_array_push(arr, component);
        component = strtok_r(NULL, "/", &saveptr);
    }

    free(path_copy);
    *out = arr;
    return NULL;
}

/**
 * Make path relative to base
 */
error_t *path_make_relative(
    const char *base,
    const char *full,
    char **out
) {
    CHECK_NULL(base);
    CHECK_NULL(full);
    CHECK_NULL(out);

    error_t *err = NULL;
    string_array_t *base_parts = NULL;
    string_array_t *full_parts = NULL;
    buffer_t *result_buf = NULL;

    err = path_split(base, &base_parts);
    if (err) goto cleanup;

    err = path_split(full, &full_parts);
    if (err) goto cleanup;

    size_t base_len = string_array_size(base_parts);
    size_t full_len = string_array_size(full_parts);
    size_t common_prefix_len = 0;

    while (common_prefix_len < base_len && common_prefix_len < full_len &&
           strcmp(string_array_get(base_parts, common_prefix_len),
                  string_array_get(full_parts, common_prefix_len)) == 0) {
        common_prefix_len++;
    }

    result_buf = buffer_create();
    if (!result_buf) {
        err = ERROR(ERR_MEMORY, "Failed to create result buffer");
        goto cleanup;
    }

    /* Add ".." for each remaining part in base */
    for (size_t i = common_prefix_len; i < base_len; i++) {
        buffer_append_string(result_buf, "../");
    }

    /* Add remaining parts from full */
    for (size_t i = common_prefix_len; i < full_len; i++) {
        buffer_append_string(result_buf, string_array_get(full_parts, i));
        if (i < full_len - 1) {
            buffer_append_string(result_buf, "/");
        }
    }

    /* Handle case where paths are identical */
    if (buffer_size(result_buf) == 0) {
        *out = strdup(".");
        if (!*out) {
            err = ERROR(ERR_MEMORY, "Failed to allocate relative path");
        }
    } else {
        /* Transfer ownership from buffer to avoid copy */
        err = buffer_release_data(result_buf, out);
        if (err) {
            goto cleanup;
        }

        /* Remove trailing slash if present */
        size_t len = strlen(*out);
        if (len > 0 && (*out)[len - 1] == '/') {
            (*out)[len - 1] = '\0';
        }

        /* Set result_buf to NULL since ownership was transferred */
        result_buf = NULL;
    }

cleanup:
    if (base_parts) string_array_free(base_parts);
    if (full_parts) string_array_free(full_parts);
    if (result_buf) buffer_free(result_buf);

    return err;
}

/**
 * Resolve flexible path input to canonical storage format
 *
 * This is the unified path resolution function used by all commands.
 * Handles both filesystem and storage path formats intelligently.
 */
error_t *path_resolve_input(
    const char *input,
    bool require_exists,
    char **out_storage_path
) {
    CHECK_NULL(input);
    CHECK_NULL(out_storage_path);

    error_t *err = NULL;
    char *storage_path = NULL;

    if (input[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* Detect path type and route to appropriate handler */

    /* Case 1: Filesystem path (absolute or tilde-prefixed) */
    if (input[0] == '/' || input[0] == '~') {
        if (require_exists) {
            /* Mode A: Strict canonicalization (for add, update) */
            /* Expand tilde if needed */
            char *expanded = NULL;
            if (input[0] == '~') {
                err = path_expand_home(input, &expanded);
                if (err) {
                    return error_wrap(err, "Failed to expand path '%s'", input);
                }
            } else {
                expanded = strdup(input);
                if (!expanded) {
                    return ERROR(ERR_MEMORY, "Failed to allocate path");
                }
            }

            /* Canonicalize: resolves symlinks and verifies existence */
            char *canonical = NULL;
            err = fs_canonicalize_path(expanded, &canonical);
            free(expanded);
            if (err) {
                return error_wrap(err,
                    "Failed to resolve path '%s'\n"
                    "Hint: File must exist for this operation", input);
            }

            /* Convert to storage format */
            path_prefix_t prefix;
            err = path_to_storage(canonical, &storage_path, &prefix);
            free(canonical);
            if (err) {
                return error_wrap(err, "Failed to convert path '%s'", input);
            }
        } else {
            /* Mode B: Pattern-based conversion (for show, revert, remove) */
            /* File need not exist - used for querying Git data */

            /* Expand tilde if present */
            char *working_path = NULL;
            if (input[0] == '~') {
                err = path_expand_home(input, &working_path);
                if (err) {
                    return error_wrap(err, "Failed to expand path '%s'", input);
                }
            } else {
                working_path = strdup(input);
                if (!working_path) {
                    return ERROR(ERR_MEMORY, "Failed to allocate path");
                }
            }

            /* Must be absolute path at this point */
            if (working_path[0] != '/') {
                free(working_path);
                return ERROR(ERR_INVALID_ARG,
                    "Path must be absolute after tilde expansion (got '%s')", input);
            }

            /* Get HOME directory for path classification */
            char *home = NULL;
            err = path_get_home(&home);
            if (err) {
                free(working_path);
                return err;
            }

            size_t home_len = strlen(home);

            /* Check if path is under $HOME */
            if (strncmp(working_path, home, home_len) == 0 &&
                (working_path[home_len] == '/' || working_path[home_len] == '\0')) {
                /* Under home directory */
                const char *rel = working_path + home_len;
                if (rel[0] == '/') rel++;  /* Skip leading slash */

                if (rel[0] == '\0') {
                    free(working_path);
                    free(home);
                    return ERROR(ERR_INVALID_ARG,
                        "Cannot specify HOME directory itself");
                }

                /* Build storage path: home/... */
                storage_path = str_format("home/%s", rel);
                if (!storage_path) {
                    free(working_path);
                    free(home);
                    return ERROR(ERR_MEMORY, "Failed to format storage path");
                }
            } else {
                /* Outside home - use root/ prefix */
                storage_path = str_format("root%s", working_path);
                if (!storage_path) {
                    free(working_path);
                    free(home);
                    return ERROR(ERR_MEMORY, "Failed to format storage path");
                }
            }

            free(working_path);
            free(home);
        }

    /* Case 2: Storage path (home/... or root/...) */
    } else if (str_starts_with(input, "home/") || str_starts_with(input, "root/")) {
        /* Validate storage path format */
        err = path_validate_storage(input);
        if (err) {
            return error_wrap(err, "Invalid storage path '%s'", input);
        }

        /* Already in storage format - duplicate and return */
        storage_path = strdup(input);
        if (!storage_path) {
            return ERROR(ERR_MEMORY, "Failed to allocate storage path");
        }

    /* Case 3: Invalid/ambiguous path */
    } else {
        return ERROR(ERR_INVALID_ARG,
            "Path '%s' is neither a valid filesystem path nor storage path\n"
            "Hint: Filesystem paths must be absolute (/) or tilde (~) prefixed\n"
            "      Storage paths must start with 'home/' or 'root/'",
            input);
    }

    /* Success - transfer ownership */
    *out_storage_path = storage_path;
    return NULL;
}
