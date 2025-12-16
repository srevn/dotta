/**
 * path.c - Path resolution and conversion implementation
 *
 * SECURITY: All path operations validate against path traversal attacks.
 */

#include "path.h"

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"
#include "utils/match.h"
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
 * Validate storage path
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

    /* SECURITY: Must start with home/, root/, or custom/ */
    if (!str_starts_with(storage_path, "home/") &&
        !str_starts_with(storage_path, "root/") &&
        !str_starts_with(storage_path, "custom/")) {
        return ERROR(ERR_INVALID_ARG,
                    "Storage path must start with 'home/', 'root/', or 'custom/' (got '%s')",
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
 * Extract relative path after stripping prefix
 *
 * Checks if absolute path starts with prefix (with proper boundary verification),
 * and extracts the relative part after the prefix.
 *
 * Boundary verification ensures prefix matches a complete path component:
 *   /home/user matches /home/user/.bashrc
 *   /home/user does NOT match /home/username/.bashrc
 *
 * Returns:
 *   >0 : Match succeeded, returns length of relative part, sets *out_relative
 *    0 : Prefix matched but relative part is empty (directory itself)
 *   -1 : No match (prefix doesn't match or boundary violation)
 *
 * @param absolute Absolute filesystem path
 * @param prefix Prefix to match against
 * @param out_relative Output relative part (points into absolute, caller doesn't own)
 * @return Match status (see above)
 */
static int extract_relative_after_prefix(
    const char *absolute,
    const char *prefix,
    const char **out_relative
) {
    size_t prefix_len = strlen(prefix);

    /* Check if absolute starts with prefix */
    if (!str_starts_with(absolute, prefix)) {
        return -1;
    }

    /* Verify boundary: next character must be '/' or '\0' */
    char boundary = absolute[prefix_len];
    if (boundary != '/' && boundary != '\0') {
        return -1;  /* False match: /home/user vs /home/username */
    }

    /* Extract relative part, skipping leading slash */
    const char *relative = absolute + prefix_len;
    if (relative[0] == '/') {
        relative++;
    }

    /* Check if relative part is empty (would be storing directory itself) */
    if (relative[0] == '\0') {
        return 0;
    }

    *out_relative = relative;
    return (int)strlen(relative);
}

/**
 * Detect if path is under HOME directory, considering both original
 * and canonicalized HOME (to handle symlinks).
 *
 * Returns:
 *   >0 : Match succeeded, returns length of relative part, sets *out_relative
 *    0 : Prefix matched but relative part is empty (directory itself)
 *   -1 : No match (prefix doesn't match or boundary violation)
 *
 * @param absolute Absolute filesystem path
 * @param home Original HOME directory
 * @param home_canonical Canonicalized HOME (may be NULL or same as home)
 * @param out_relative Output relative part (points into absolute, caller doesn't own)
 * @return Match status (see above)
 */
static int detect_home_prefix(
    const char *absolute,
    const char *home,
    const char *home_canonical,
    const char **out_relative
) {
    const char *relative;
    int match;

    match = extract_relative_after_prefix(absolute, home, &relative);
    if (match >= 0) {
        *out_relative = relative;
        return match;
    }

    if (home_canonical && home_canonical != home) {
        match = extract_relative_after_prefix(absolute, home_canonical, &relative);
        if (match >= 0) {
            *out_relative = relative;
            return match;
        }
    }

    return -1;
}

/**
 * Try prepending custom prefix to absolute path.
 *
 * Resolution strategy:
 *   1. If path already under prefix -> return NULL (use as-is)
 *   2. Try prepending prefix -> if exists on filesystem, return prepended
 *   3. Otherwise -> return NULL (fallback to original)
 *
 * This enables intuitive smart resolution where both explicit and implicit
 * forms work correctly:
 *   --prefix /jail /jail/etc/nginx.conf  (explicit, already under prefix)
 *   --prefix /jail /etc/nginx.conf       (implicit, prepends if file exists)
 *
 * When both files exist (/etc/nginx.conf and /jail/etc/nginx.conf), the
 * prefixed version is preferred to honor the user's explicit --prefix intent.
 *
 * Example:
 *   Input: absolute="/etc/nginx.conf", custom_prefix="/jail"
 *   Check: Is /etc/nginx.conf already under /jail? NO
 *   Try: Does /jail/etc/nginx.conf exist? YES
 *   Return: "/jail/etc/nginx.conf" (caller must free)
 *
 * @param absolute Absolute filesystem path (must not be NULL)
 * @param custom_prefix Custom prefix to try (must not be NULL)
 * @return Prepended path if resolution succeeded (caller frees), or NULL
 */
static char *try_prepend_custom_prefix(
    const char *absolute,
    const char *custom_prefix
) {
    const char *relative;

    /* Check if path is already under prefix */
    int match = extract_relative_after_prefix(absolute, custom_prefix, &relative);
    if (match >= 0) {
        /*
         * Already under prefix (match > 0) or IS the prefix directory (match == 0).
         * Use original path as-is - no prepending needed.
         */
        return NULL;
    }

    /* Try prepending custom prefix to the path */
    char *prefixed = str_format("%s%s", custom_prefix, absolute);
    if (!prefixed) {
        /* Allocation failed - gracefully fallback to original path */
        return NULL;
    }

    /* Check if prefixed version exists on filesystem */
    if (fs_exists(prefixed)) {
        /* File exists under prefix - use this version */
        return prefixed;  /* Caller takes ownership */
    }

    /* Prefixed path doesn't exist - fallback to original */
    free(prefixed);
    return NULL;
}

/**
 * Normalize user input path to absolute filesystem path.
 *
 * Transformation order:
 *   1. Tilde expansion (~/ -> $HOME)
 *   2. Custom prefix joining (relative + prefix)
 *   3. Absolute path pass-through
 *   4. CWD joining (relative, no prefix)
 *
 * Security: Rejects path traversal (..) in relative paths with custom_prefix.
 *
 * Examples:
 *   ("~/file", NULL)             -> "$HOME/file"
 *   ("relative/file", "/jail")   -> "/jail/relative/file"
 *   ("/abs/file", "/jail")       -> "/abs/file" (absolute unchanged)
 *   ("relative/file", NULL)      -> "$CWD/relative/file"
 *   ("../escape", "/jail")       -> ERROR
 *
 * @param user_path User-provided path (filesystem or tilde)
 * @param custom_prefix Optional custom prefix for relative path context (can be NULL)
 * @param out Normalized absolute path (caller frees)
 * @return Error or NULL on success
 */
error_t *path_normalize_input(
    const char *user_path,
    const char *custom_prefix,
    char **out
) {
    CHECK_NULL(user_path);
    CHECK_NULL(out);

    error_t *err = NULL;
    char *expanded = NULL;
    char *joined = NULL;
    const char *path_to_make_absolute = user_path;

    /* Step 1: Expand tilde (highest priority - canonical) */
    if (user_path[0] == '~') {
        err = path_expand_home(user_path, &expanded);
        if (err) {
            return err;
        }
        path_to_make_absolute = expanded;
    }

    /* Step 2: Join relative paths with custom prefix */
    else if (custom_prefix && custom_prefix[0] != '\0' && user_path[0] != '/') {
        /* Security: Block path traversal in relative paths with custom prefix */
        if (strstr(user_path, "..") != NULL) {
            free(expanded);
            return ERROR(ERR_INVALID_ARG,
                "Path traversal (..) not allowed in relative paths with --prefix.\n"
                "  Use absolute paths if you need to reference files outside the prefix.");
        }

        err = fs_path_join(custom_prefix, user_path, &joined);
        if (err) {
            free(expanded);
            return error_wrap(err, "Failed to join custom prefix with relative path");
        }
        path_to_make_absolute = joined;
    }

    /* Step 3: Make absolute (handles absolute pass-through and CWD joining) */
    err = fs_make_absolute(path_to_make_absolute, out);

    /* Cleanup */
    free(expanded);
    free(joined);

    return err;
}

/**
 * Convert filesystem path to storage path
 *
 * Detection order (CANONICAL REPRESENTATION):
 *  1. $HOME (canonical for user files) - FIRST
 *  2. Custom prefix (if provided and matches) - SECOND
 *  3. Root (fallback for system files)
 *
 * This ensures files under $HOME ALWAYS use home/ prefix,
 * even if --prefix matches $HOME (canonical representation).
 */
error_t *path_to_storage(
    const char *filesystem_path,
    const char *custom_prefix,
    char **storage_path,
    path_prefix_t *prefix_out
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    char *absolute = NULL;
    char *home = NULL;
    char *result = NULL;
    path_prefix_t detected_prefix;

    /* Normalize user input path (handles tilde, relative+prefix, etc.) */
    err = path_normalize_input(filesystem_path, custom_prefix, &absolute);
    if (err) {
        return err;
    }

    /* Try $HOME prefix first (most canonical) */
    err = path_get_home(&home);
    if (err) {
        goto cleanup;
    }

    const char *relative;
    int match = extract_relative_after_prefix(absolute, home, &relative);

    if (match > 0) {
        /* HOME prefix matched with non-empty relative part */
        /* Validate file exists */
        if (!fs_lexists(absolute)) {
            err = ERROR(ERR_NOT_FOUND, "File not found: %s", absolute);
            goto cleanup;
        }

        result = str_format("home/%s", relative);
        if (!result) {
            err = ERROR(ERR_MEMORY, "Failed to format home storage path");
            goto cleanup;
        }
        detected_prefix = PREFIX_HOME;
        goto validate;

    } else if (match == 0) {
        /* HOME directory itself - not supported */
        err = ERROR(ERR_INVALID_ARG, "Cannot store HOME directory itself");
        goto cleanup;
    }

    /* Try custom prefix second (if provided) */
    if (custom_prefix && custom_prefix[0] != '\0') {
        /* Smart resolution: try prepending prefix if path not already under it */
        char *resolved = try_prepend_custom_prefix(absolute, custom_prefix);
        const char *path_to_check = resolved ? resolved : absolute;

        match = extract_relative_after_prefix(path_to_check, custom_prefix, &relative);

        if (match > 0) {
            /* Custom prefix matched with non-empty relative part */
            /* Validate file exists (either via smart resolution or already under prefix) */
            if (!resolved && !fs_lexists(path_to_check)) {
                /* Path was already under prefix but doesn't exist */
                free(resolved);
                err = ERROR(ERR_NOT_FOUND, "File not found: %s", path_to_check);
                goto cleanup;
            }

            result = str_format("custom/%s", relative);
            free(resolved);  /* Free prepended path if allocated */
            if (!result) {
                err = ERROR(ERR_MEMORY, "Failed to format custom storage path");
                goto cleanup;
            }
            detected_prefix = PREFIX_CUSTOM;
            goto validate;

        } else if (match == 0) {
            /* Custom prefix directory itself - not supported */
            free(resolved);  /* Free prepended path if allocated */
            err = ERROR(ERR_INVALID_ARG,
                "Cannot store custom prefix directory itself");
            goto cleanup;
        }

        /* No match - custom prefix provided but cannot be satisfied */
        free(resolved);  /* Free prepended path if allocated */
        err = ERROR(ERR_INVALID_ARG,
            "File '%s' not found under custom prefix '%s'.\n"
            "  Checked: %s%s\n"
            "  Either create the file at that location first, or omit --prefix to use system file.",
            absolute, custom_prefix, custom_prefix, absolute);
        goto cleanup;
    }

    /* Fallback to ROOT prefix for absolute paths */
    /* Validate file exists before storing */
    if (!fs_lexists(absolute)) {
        err = ERROR(ERR_NOT_FOUND, "File not found: %s", absolute);
        goto cleanup;
    }

    /* Note: For root, we include the leading slash in the relative part */
    relative = absolute;
    if (relative[0] == '/') {
        relative++;  /* Skip leading slash for consistency */
    }

    result = str_format("root/%s", relative);
    if (!result) {
        err = ERROR(ERR_MEMORY, "Failed to format root storage path");
        goto cleanup;
    }
    detected_prefix = PREFIX_ROOT;

validate:
    /* Validate generated storage path format */
    err = path_validate_storage(result);
    if (err) {
        free(result);
        result = NULL;
        goto cleanup;
    }

    /* Success: set outputs */
    if (prefix_out) {
        *prefix_out = detected_prefix;
    }
    *storage_path = result;
    err = NULL;

cleanup:
    free(absolute);
    free(home);
    return err;
}

/**
 * Convert storage path to filesystem path
 */
error_t *path_from_storage(
    const char *storage_path,
    const char *custom_prefix,
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

        const char *relative_path = storage_path + strlen("home/");
        err = fs_path_join(home, relative_path, filesystem_path);
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

    } else if (str_starts_with(storage_path, "custom/")) {
        /* custom/etc/nginx.conf -> <prefix>/etc/nginx.conf */

        /* Require custom_prefix parameter */
        if (!custom_prefix || custom_prefix[0] == '\0') {
            return ERROR(ERR_INVALID_ARG,
                "Storage path '%s' requires custom_prefix parameter\n"
                "This is a custom/ path - provide --prefix flag when enabling profile",
                storage_path);
        }

        /* Strip "custom" prefix and prepend custom_prefix
         * storage_path = "custom/etc/nginx.conf"
         * After strlen("custom"): "/etc/nginx.conf" (with leading slash)
         * Build: <prefix> + <relative> = "/mnt/jail" + "/etc/nginx.conf" */
        const char *relative_path = storage_path + strlen("custom");

        *filesystem_path = str_format("%s%s", custom_prefix, relative_path);
        if (!*filesystem_path) {
            return ERROR(ERR_MEMORY, "Failed to format custom filesystem path");
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
 * Resolve relative path to absolute using CWD
 *
 * Pure string operation - does NOT check file existence.
 * Used for flexible mode path resolution where file need not exist.
 *
 * Handles:
 * - ./foo -> $CWD/foo (strips ./)
 * - ../bar -> $CWD/../bar (keeps ..)
 * - relative/path -> $CWD/relative/path
 *
 * @param relative_path Relative path (must not be NULL)
 * @param out Absolute path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *path_resolve_relative(const char *relative_path, char **out) {
    CHECK_NULL(relative_path);
    CHECK_NULL(out);

    /* Already absolute - just duplicate */
    if (relative_path[0] == '/') {
        *out = strdup(relative_path);
        if (!*out) {
            return ERROR(ERR_MEMORY, "Failed to duplicate path");
        }
        return NULL;
    }

    /* Get current working directory */
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        return ERROR(ERR_FS, "Failed to get current working directory: %s",
                    strerror(errno));
    }

    /* Strip leading ./ from relative path */
    const char *clean_path = relative_path;
    while (clean_path[0] == '.' && clean_path[1] == '/') {
        clean_path += 2;
        /* Skip any additional slashes */
        while (*clean_path == '/') {
            clean_path++;
        }
    }

    /* Handle edge case: path was just "./" or "." */
    if (*clean_path == '\0' || (clean_path[0] == '.' && clean_path[1] == '\0')) {
        /* Just return CWD */
        *out = strdup(cwd);
        if (!*out) {
            return ERROR(ERR_MEMORY, "Failed to duplicate CWD");
        }
        return NULL;
    }

    /* Join CWD with cleaned relative path */
    return fs_path_join(cwd, clean_path, out);
}

/**
 * Check if input looks like a relative path
 *
 * Relative paths are:
 * - Paths starting with . (./foo, ../bar, .hidden)
 * - Paths containing / but not starting with a known prefix
 *
 * NOT relative:
 * - Absolute paths (/...)
 * - Tilde paths (~...)
 * - Storage paths (home/..., root/..., custom/...)
 */
static bool path_is_relative(const char *input) {
    if (!input || input[0] == '\0') {
        return false;
    }

    /* Starts with . - definitely relative */
    if (input[0] == '.') {
        return true;
    }

    /* Absolute or tilde - not relative */
    if (input[0] == '/' || input[0] == '~') {
        return false;
    }

    /* Storage paths - not relative */
    if (str_starts_with(input, "home/") ||
        str_starts_with(input, "root/") ||
        str_starts_with(input, "custom/")) {
        return false;
    }

    /* Contains slash but not a storage path - treat as relative
     * e.g., "config/file.txt" from CWD */
    if (strchr(input, '/') != NULL) {
        return true;
    }

    /* Single component without slash - ambiguous, not treated as relative
     * Could be a profile name or a file in CWD, but we can't tell.
     * User should use ./ prefix for clarity. */
    return false;
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

            /* Make absolute without following symlinks */
            char *absolute = NULL;
            err = fs_make_absolute(expanded, &absolute);
            free(expanded);
            if (err) {
                return error_wrap(err, "Failed to resolve path '%s'\n"
                    "Hint: File must exist for this operation", input);
            }

            /* Normalize path to resolve any .. components before storage conversion */
            char *normalized = NULL;
            err = fs_normalize_path(absolute, &normalized);
            free(absolute);
            if (err) {
                return error_wrap(err, "Failed to normalize path '%s'", input);
            }

            /* Convert to storage format */
            path_prefix_t prefix;
            err = path_to_storage(normalized, NULL, &storage_path, &prefix);
            free(normalized);
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

            /* Normalize path to resolve any .. components before HOME comparison */
            char *normalized = NULL;
            err = fs_normalize_path(working_path, &normalized);
            free(working_path);
            if (err) {
                return error_wrap(err, "Failed to normalize path '%s'", input);
            }
            working_path = normalized;

            /* Get HOME directory for path classification */
            char *home = NULL;
            err = path_get_home(&home);
            if (err) {
                free(working_path);
                return err;
            }

            /* Canonicalize HOME to handle symlinks (e.g., /tmp -> /private/tmp on macOS)
             * This ensures consistent comparison with normalized paths. */
            char *home_canonical = NULL;
            if (fs_canonicalize_path(home, &home_canonical) == NULL) {
                /* Success: home_canonical now contains canonical path */
                /* Keep original home as well for detection */
            }
            /* If canonicalization failed, home_canonical remains NULL */

            /* Check if path is under $HOME (original or canonical) */
            const char *relative_path = NULL;
            int match = detect_home_prefix(working_path, home, home_canonical, &relative_path);

            if (match >= 0) {
                /* Under home directory (or is home directory itself) */
                if (match == 0) {
                    /* HOME directory itself - not allowed */
                    free(working_path);
                    free(home);
                    free(home_canonical);
                    return ERROR(ERR_INVALID_ARG,
                        "Cannot specify HOME directory itself");
                }

                /* Build storage path: home/... */
                storage_path = str_format("home/%s", relative_path);
                if (!storage_path) {
                    free(working_path);
                    free(home);
                    free(home_canonical);
                    return ERROR(ERR_MEMORY, "Failed to format storage path");
                }
            } else {
                /* Outside home - use root/ prefix */
                storage_path = str_format("root%s", working_path);
                if (!storage_path) {
                    free(working_path);
                    free(home);
                    free(home_canonical);
                    return ERROR(ERR_MEMORY, "Failed to format storage path");
                }
            }

            free(home_canonical);

            free(working_path);
            free(home);
        }

    /* Case 2: Relative path (./foo, ../bar, or path/with/slash) */
    } else if (path_is_relative(input)) {
        char *absolute = NULL;

        if (require_exists) {
            /* Strict mode: Use fs_make_absolute which validates existence */
            err = fs_make_absolute(input, &absolute);
            if (err) {
                return error_wrap(err, "Failed to resolve relative path '%s'\n"
                    "Hint: File must exist for this operation", input);
            }
        } else {
            /* Flexible mode: Resolve via CWD without existence check */
            err = path_resolve_relative(input, &absolute);
            if (err) {
                return error_wrap(err, "Failed to resolve relative path '%s'", input);
            }
        }

        /* Normalize path to resolve any .. components before HOME comparison */
        char *normalized = NULL;
        err = fs_normalize_path(absolute, &normalized);
        free(absolute);
        if (err) {
            return error_wrap(err, "Failed to normalize relative path '%s'", input);
        }
        absolute = normalized;

        /* Convert absolute path to storage format (same as Mode B above) */
        char *home = NULL;
        err = path_get_home(&home);
        if (err) {
            free(absolute);
            return err;
        }

        /* Canonicalize HOME to handle symlinks (e.g., /tmp -> /private/tmp on macOS)
         * This is necessary because getcwd() returns canonical paths, but $HOME
         * may contain symlinks. If canonicalization fails (e.g., $HOME doesn't exist),
         * fall back to the original HOME path. */
        char *home_canonical = NULL;
        if (fs_canonicalize_path(home, &home_canonical) == NULL) {
            /* Success: home_canonical now contains canonical path */
            /* Keep original home as well for detection */
        }
        /* If canonicalization failed, home_canonical remains NULL */

        /* Check if path is under $HOME (original or canonical) */
        const char *relative_path = NULL;
        int match = detect_home_prefix(absolute, home, home_canonical, &relative_path);

        if (match >= 0) {
            /* Under home directory (or is home directory itself) */
            if (match == 0) {
                /* HOME directory itself - not allowed */
                free(absolute);
                free(home);
                free(home_canonical);
                return ERROR(ERR_INVALID_ARG, "Cannot specify HOME directory itself");
            }

            /* Build storage path: home/... */
            storage_path = str_format("home/%s", relative_path);
            if (!storage_path) {
                free(absolute);
                free(home);
                free(home_canonical);
                return ERROR(ERR_MEMORY, "Failed to format storage path");
            }
        } else {
            /* Outside home - use root/ prefix */
            storage_path = str_format("root%s", absolute);
            if (!storage_path) {
                free(absolute);
                free(home);
                free(home_canonical);
                return ERROR(ERR_MEMORY, "Failed to format storage path");
            }
        }

        free(home_canonical);

        free(absolute);
        free(home);

    /* Case 3: Storage path (home/..., root/..., or custom/...) */
    } else if (str_starts_with(input, "home/") ||
               str_starts_with(input, "root/") ||
               str_starts_with(input, "custom/")) {
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

    /* Case 4: Invalid/ambiguous path */
    } else {
        return ERROR(ERR_INVALID_ARG,
            "Path '%s' is neither a valid filesystem path nor storage path\n"
            "Hint: Use absolute (/path), tilde (~/.file), relative (./path), or\n"
            "      storage format (home/..., root/..., custom/...)",
            input);
    }

    /* Success - transfer ownership */
    *out_storage_path = storage_path;
    return NULL;
}

/**
 * Create path filter from user input paths
 *
 * Handles three types of inputs:
 * 1. Glob patterns (*, ?, []) - stored in glob_patterns array for iteration
 * 2. Storage paths (home/..., root/..., custom/...) - stored in exact_paths hashmap
 * 3. Filesystem paths (/, ~, ./) - resolved to storage format, then stored in hashmap
 *
 * Performance: Separates exact paths (O(1) lookup) from globs (O(G) iteration).
 */
error_t *path_filter_create(
    const char **inputs,
    size_t count,
    path_filter_t **out
) {
    CHECK_NULL(out);

    /* No inputs = no filter (matches all) */
    if (!inputs || count == 0) {
        *out = NULL;
        return NULL;
    }

    path_filter_t *filter = calloc(1, sizeof(*filter));
    if (!filter) {
        return ERROR(ERR_MEMORY, "Failed to allocate path filter");
    }

    /* Create hashmap for exact paths */
    filter->exact_paths = hashmap_create(0);
    if (!filter->exact_paths) {
        free(filter);
        return ERROR(ERR_MEMORY, "Failed to allocate filter hashmap");
    }

    /* First pass: count glob patterns for allocation */
    size_t glob_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (inputs[i] && strpbrk(inputs[i], "*?[")) {
            glob_count++;
        }
    }

    /* Allocate glob patterns array if needed */
    if (glob_count > 0) {
        filter->glob_patterns = calloc(glob_count, sizeof(char *));
        if (!filter->glob_patterns) {
            hashmap_free(filter->exact_paths, NULL);
            free(filter);
            return ERROR(ERR_MEMORY, "Failed to allocate glob patterns");
        }
    }

    /* Second pass: populate hashmap and glob array */
    error_t *err = NULL;
    for (size_t i = 0; i < count; i++) {
        const char *input = inputs[i];

        /* Case 1: Glob pattern - validate and store in glob array */
        if (input && strpbrk(input, "*?[")) {
            /*
             * Glob patterns are used directly for matching.
             * They should be in one of these formats:
             * - Basename-only: "*.vim", "config.*"
             * - Recursive: doublestar followed by path component
             * - Storage path with glob: "home/..." with wildcards
             *
             * Validate that patterns with / use proper prefix (unless doublestar)
             */
            if (strchr(input, '/') != NULL &&
                !str_starts_with(input, "home/") &&
                !str_starts_with(input, "root/") &&
                !str_starts_with(input, "custom/") &&
                !str_starts_with(input, "**/") &&
                !str_starts_with(input, "*/")) {
                err = ERROR(ERR_INVALID_ARG,
                    "Glob pattern '%s' must use storage format or be basename-only\n"
                    "Examples: 'home/ * * / *.vim', '*.vim' (spaces for doc only)", input);
                goto cleanup;
            }

            filter->glob_patterns[filter->glob_count] = strdup(input);
            if (!filter->glob_patterns[filter->glob_count]) {
                err = ERROR(ERR_MEMORY, "Failed to duplicate pattern");
                goto cleanup;
            }
            filter->glob_count++;
            filter->count++;
            continue;
        }

        /* Case 2: Exact path - resolve and store in hashmap */
        char *resolved = NULL;
        err = path_resolve_input(input, false, &resolved);
        if (err) {
            err = error_wrap(err, "Invalid path '%s'", input);
            goto cleanup;
        }

        /* Store in hashmap (hashmap duplicates key internally) */
        err = hashmap_set(filter->exact_paths, resolved, (void *)1);
        free(resolved);
        if (err) {
            goto cleanup;
        }
        filter->count++;
    }

    *out = filter;
    return NULL;

cleanup:
    /* Free already allocated glob patterns */
    for (size_t j = 0; j < filter->glob_count; j++) {
        free(filter->glob_patterns[j]);
    }
    free(filter->glob_patterns);
    hashmap_free(filter->exact_paths, NULL);
    free(filter);
    return err;
}

/**
 * Check if storage path matches filter
 *
 * Matching semantics:
 * - Exact match: "home/.bashrc" matches "home/.bashrc"
 * - Directory prefix: "home/.config" matches "home/.config/fish/config.fish"
 * - Glob patterns: recursive globs match nested file paths
 * - Basename patterns: "*.vim" matches "home/.vim/foo.vim"
 */
bool path_filter_matches(
    const path_filter_t *filter,
    const char *storage_path
) {
    /* No filter = match all */
    if (!filter) {
        return true;
    }

    /* NULL storage_path never matches */
    if (!storage_path) {
        return false;
    }

    /* Fast path 1: O(1) exact match via hashmap
     *
     * Checks if the full storage path exists as a filter entry.
     */
    if (hashmap_has(filter->exact_paths, storage_path)) {
        return true;
    }

    /* Fast path 2: O(D) ancestor prefix matching
     *
     * This preserves gitignore-style directory matching where filter
     * "home/.config" matches all files under that directory.
     */
    size_t len = strlen(storage_path);
    if (len < PATH_MAX) {
        char path_buf[PATH_MAX];
        memcpy(path_buf, storage_path, len + 1);

        char *last_slash;
        while ((last_slash = strrchr(path_buf, '/')) != NULL) {
            *last_slash = '\0';
            if (hashmap_has(filter->exact_paths, path_buf)) {
                return true;
            }
        }
    }

    /* Slow path: O(G) glob pattern matching
     *
     * Iterate through glob patterns using full match_pattern() semantics.
     * This handles wildcards (*, ?, []), recursive globs (**), and
     * basename-only patterns that match at any depth.
     */
    for (size_t i = 0; i < filter->glob_count; i++) {
        if (match_pattern(filter->glob_patterns[i], storage_path, MATCH_DOUBLESTAR)) {
            return true;
        }
    }

    return false;
}

/**
 * Free path filter
 */
void path_filter_free(path_filter_t *filter) {
    if (!filter) {
        return;
    }

    /* Free glob patterns (owned strings) */
    for (size_t i = 0; i < filter->glob_count; i++) {
        free(filter->glob_patterns[i]);
    }
    free(filter->glob_patterns);

    /* Free hashmap (keys owned by hashmap, values are just markers) */
    hashmap_free(filter->exact_paths, NULL);

    free(filter);
}

/**
 * Validate custom prefix parameter
 */
error_t *path_validate_custom_prefix(const char *prefix) {
    CHECK_NULL(prefix);

    /* 1. Must be absolute path */
    if (prefix[0] != '/') {
        return ERROR(ERR_INVALID_ARG,
            "Custom prefix must be absolute path (got '%s')\n"
            "Example: --prefix /mnt/jails/web", prefix);
    }

    /* 2. No path traversal components */
    if (strstr(prefix, "/./") || strstr(prefix, "/../") || strstr(prefix, "//")) {
        return ERROR(ERR_INVALID_ARG,
            "Custom prefix contains invalid path components: '%s'\n"
            "Components like '..', '.', or '//' are not allowed", prefix);
    }

    /* 3. Must not end with slash (normalize) */
    size_t len = strlen(prefix);
    if (len > 1 && prefix[len - 1] == '/') {
        return ERROR(ERR_INVALID_ARG,
            "Custom prefix must not end with slash: '%s'\n"
            "Use: %.*s", prefix, (int)(len - 1), prefix);
    }

    /* 4. Normalize and validate with realpath() */
    char *resolved = realpath(prefix, NULL);
    if (!resolved) {
        if (errno == ENOENT) {
            return ERROR(ERR_INVALID_ARG,
                "Custom prefix directory does not exist: '%s'\n"
                "Create it first: mkdir -p '%s'", prefix, prefix);
        } else {
            return ERROR(ERR_INVALID_ARG,
                "Cannot resolve custom prefix '%s': %s", prefix, strerror(errno));
        }
    }

    /* 5. Verify it's a directory */
    struct stat st;
    if (stat(resolved, &st) != 0) {
        free(resolved);
        return ERROR(ERR_INVALID_ARG,
            "Cannot stat custom prefix: %s", strerror(errno));
    }

    if (!S_ISDIR(st.st_mode)) {
        free(resolved);
        return ERROR(ERR_INVALID_ARG,
            "Custom prefix must be a directory: '%s'", prefix);
    }

    free(resolved);
    return NULL;
}
