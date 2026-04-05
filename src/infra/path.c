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
        return ERROR(
            ERR_INVALID_ARG, "Storage path must be relative (got '%s')",
            storage_path
        );
    }

    /* SECURITY: Must start with home/, root/, or custom/ */
    if (!str_starts_with(storage_path, "home/") &&
        !str_starts_with(storage_path, "root/") &&
        !str_starts_with(storage_path, "custom/")) {
        return ERROR(
            ERR_INVALID_ARG, "Storage path must start with "
            "'home/', 'root/', or 'custom/' (got '%s')", storage_path
        );
    }

    /* Must reference a file, not just a prefix directory */
    if (storage_path[strlen(storage_path) - 1] == '/') {
        return ERROR(
            ERR_INVALID_ARG, "Storage path must not end with '/': '%s'",
            storage_path
        );
    }

    /* SECURITY: Additional checks */
    /* Check for consecutive slashes */
    if (strstr(storage_path, "//") != NULL) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid path format ('//'): '%s'",
            storage_path
        );
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
            return ERROR(
                ERR_INVALID_ARG, "Path traversal not allowed "
                "(component '..' in '%s')", storage_path
            );
        }

        /* Check if component is "." (redundant, but potentially suspicious) */
        if (strcmp(component, ".") == 0) {
            free(path_copy);
            return ERROR(
                ERR_INVALID_ARG, "Invalid path component '.' in '%s'",
                storage_path
            );
        }

        component = strtok_r(NULL, "/", &saveptr);
    }

    free(path_copy);
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
        return ERROR(
            ERR_INVALID_ARG, "~user syntax not supported (got '%s')",
            path
        );
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
    return (int) strlen(relative);
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

    if (home_canonical && strcmp(home_canonical, home) != 0) {
        match = extract_relative_after_prefix(
            absolute, home_canonical, &relative
        );
        if (match >= 0) {
            *out_relative = relative;
            return match;
        }
    }

    return -1;
}

/**
 * Normalize user input path to absolute filesystem path.
 *
 * The custom_prefix defines a virtual filesystem root. All paths (relative
 * and absolute) are resolved within that context. An absolute path like
 * /etc/hosts with prefix /jail becomes /jail/etc/hosts.
 *
 * Transformation order:
 *   1. Tilde expansion (~/ -> $HOME)
 *   2. Custom prefix resolution:
 *      - Relative paths: join with prefix
 *      - Absolute paths already under prefix: pass through
 *      - Absolute paths not under prefix: prepend prefix
 *   3. CWD joining (relative, no prefix)
 *
 * Security: Rejects path traversal (..) in relative paths with custom_prefix.
 *
 * Examples:
 *   ("~/file", NULL)                  -> "$HOME/file"
 *   ("relative/file", "/jail")        -> "/jail/relative/file"
 *   ("/etc/hosts", "/jail")           -> "/jail/etc/hosts"
 *   ("/jail/etc/hosts", "/jail")      -> "/jail/etc/hosts" (already under prefix)
 *   ("relative/file", NULL)           -> "$CWD/relative/file"
 *   ("../escape", "/jail")            -> ERROR
 *
 * @param user_path User-provided path (filesystem or tilde)
 * @param custom_prefix Optional prefix defining virtual filesystem root (can be NULL)
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

    /* Step 1: Expand tilde (highest priority - canonical, bypasses prefix) */
    if (user_path[0] == '~') {
        err = path_expand_home(user_path, &expanded);
        if (err) {
            return err;
        }
        path_to_make_absolute = expanded;
    }
    /* Step 2: Resolve paths within custom prefix context
     * Tilde paths skip this - ~/file always means $HOME/file regardless of prefix */
    else if (custom_prefix && custom_prefix[0] != '\0') {
        const char *path = path_to_make_absolute;

        if (path[0] != '/') {
            /* SECURITY: Reject '..' as a path component (not as substring).
             * Prevents prefix escape: ../foo + /jail -> /jail/../foo -> /foo */
            for (const char *p = path; *p; p++) {
                if ((p == path || *(p - 1) == '/') && p[0] == '.' && p[1] == '.' &&
                    (p[2] == '/' || p[2] == '\0')) {
                    free(expanded);
                    return ERROR(
                        ERR_INVALID_ARG,
                        "Path traversal (..) not allowed in relative paths with --prefix.\n"
                        "Use absolute paths if you need to reference files outside the prefix."
                    );
                }
            }

            err = fs_path_join(custom_prefix, path, &joined);
            if (err) {
                free(expanded);
                return error_wrap(err, "Failed to join custom prefix with relative path");
            }
            path_to_make_absolute = joined;
        } else {
            /* Absolute path: prepend prefix unless already under it */
            const char *relative;
            int match = extract_relative_after_prefix(path, custom_prefix, &relative);

            if (match < 0) {
                /* Not under prefix - prepend it (path is absolute within the virtual root) */
                joined = str_format("%s%s", custom_prefix, path);
                if (!joined) {
                    free(expanded);
                    return ERROR(ERR_MEMORY, "Failed to prepend custom prefix to path");
                }
                path_to_make_absolute = joined;
            }
            /* match >= 0: already under prefix, pass through unchanged */
        }
    }

    /* Step 3: Make absolute (handles absolute pass-through and CWD joining) */
    char *absolute = NULL;
    err = fs_make_absolute(path_to_make_absolute, &absolute);
    if (!err) {
        /* Step 4: Normalize (resolve ., .., consecutive slashes) */
        err = fs_normalize_path(absolute, out);
        free(absolute);
    }

    /* Cleanup */
    free(expanded);
    free(joined);

    return err;
}

/**
 * Classify absolute filesystem path into storage path
 *
 * Pure classifier — requires pre-normalized absolute path.
 * Callers must call path_normalize_input() first for raw user input.
 *
 * Detection order:
 *  1. Custom prefix (if explicitly provided and matches) - FIRST
 *  2. $HOME (canonical for user files) - SECOND
 *  3. Root (fallback for system files)
 *
 * Explicit user intent (--prefix) takes priority over implicit $HOME
 * detection. When no custom prefix is provided, $HOME is checked first
 * as before (no behavior change for the common case).
 */
error_t *path_to_storage(
    const char *filesystem_path,
    const char *custom_prefix,
    char **storage_path,
    path_prefix_t *prefix_out
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);

    /* Require absolute path — callers must normalize before calling */
    if (filesystem_path[0] != '/') {
        return ERROR(
            ERR_INVALID_ARG, "path_to_storage requires an absolute path, got: %s\n"
            "Use path_normalize_input() first for raw user input", filesystem_path
        );
    }

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    char *home = NULL;
    char *home_canonical = NULL;
    char *result = NULL;
    path_prefix_t detected_prefix;

    const char *relative;
    int match;

    /* Try custom prefix first when explicitly provided (user intent wins)
     *
     * path_normalize_input already resolved the path within the prefix context
     * (prepending prefix to absolute paths, joining with relative paths), so
     * absolute is guaranteed to be under the prefix if the path is valid.
     *
     * This allows files under $HOME to use custom/ prefix when the user
     * explicitly provides --prefix (e.g., managing remote system configs
     * stored locally under $HOME).
     */
    if (custom_prefix && custom_prefix[0] != '\0') {
        match = extract_relative_after_prefix(
            filesystem_path, custom_prefix, &relative
        );

        if (match > 0) {
            /* Custom prefix matched - validate file exists */
            if (!fs_lexists(filesystem_path)) {
                err = ERROR(ERR_NOT_FOUND, "File not found: %s", filesystem_path);
                goto cleanup;
            }

            result = str_format("custom/%s", relative);
            if (!result) {
                err = ERROR(
                    ERR_MEMORY, "Failed to format custom storage path"
                );
                goto cleanup;
            }
            detected_prefix = PREFIX_CUSTOM;
            goto validate;

        } else if (match == 0) {
            /* Custom prefix directory itself - not supported */
            err = ERROR(
                ERR_INVALID_ARG, "Cannot store custom prefix directory itself"
            );
            goto cleanup;
        }

        /* No match - path not under prefix (e.g., tilde-expanded $HOME path) */
        /* Fall through to HOME/root detection below */
    }

    /* Try $HOME prefix (canonical for user files without explicit prefix) */
    err = path_get_home(&home);
    if (err) {
        goto cleanup;
    }

    /* Canonicalize HOME to handle symlinks (e.g., /tmp -> /private/tmp on macOS).
     * getcwd() returns canonical paths, but $HOME may contain symlinks. */
    error_t *canon_err = fs_canonicalize_path(home, &home_canonical);
    if (canon_err) {
        error_free(canon_err);
    }

    match = detect_home_prefix(filesystem_path, home, home_canonical, &relative);

    if (match > 0) {
        /* HOME prefix matched with non-empty relative part */
        /* Validate file exists */
        if (!fs_lexists(filesystem_path)) {
            err = ERROR(ERR_NOT_FOUND, "File not found: %s", filesystem_path);
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

    /* Fallback to ROOT prefix for absolute paths */
    /* Validate file exists before storing */
    if (!fs_lexists(filesystem_path)) {
        err = ERROR(ERR_NOT_FOUND, "File not found: %s", filesystem_path);
        goto cleanup;
    }

    /* Note: For root, we include the leading slash in the relative part */
    relative = filesystem_path;
    if (relative[0] == '/') {
        relative++;  /* Skip leading slash for consistency */
    }

    /* Reject root directory itself (parallel to HOME directory rejection above) */
    if (relative[0] == '\0') {
        err = ERROR(ERR_INVALID_ARG, "Cannot store root directory itself");
        goto cleanup;
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
    free(home);
    free(home_canonical);

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
            return ERROR(
                ERR_MEMORY, "Failed to allocate filesystem path"
            );
        }
        return NULL;

    } else if (str_starts_with(storage_path, "custom/")) {
        /* custom/etc/nginx.conf -> <prefix>/etc/nginx.conf */

        /* Require custom_prefix parameter */
        if (!custom_prefix || custom_prefix[0] == '\0') {
            return ERROR(
                ERR_INVALID_ARG, "Storage path '%s' requires prefix parameter\n"
                "Provide --prefix flag when enabling profile", storage_path
            );
        }

        /* Strip "custom" prefix and prepend custom_prefix
         * storage_path = "custom/etc/nginx.conf"
         * After strlen("custom"): "/etc/nginx.conf" (with leading slash)
         * Build: <prefix> + <relative> = "/mnt/jail" + "/etc/nginx.conf" */
        const char *relative_path = storage_path + strlen("custom");

        *filesystem_path = str_format("%s%s", custom_prefix, relative_path);
        if (!*filesystem_path) {
            return ERROR(
                ERR_MEMORY, "Failed to format custom filesystem path"
            );
        }

        return NULL;

    } else {
        /* Should never happen due to validation */
        return ERROR(
            ERR_INTERNAL, "Invalid storage path prefix: '%s'",
            storage_path
        );
    }
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
        return ERROR(
            ERR_FS, "Failed to get current working directory: %s",
            strerror(errno)
        );
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
    const char **custom_prefixes,
    size_t prefix_count,
    char **out_storage_path
) {
    CHECK_NULL(input);
    CHECK_NULL(out_storage_path);

    /* Initialize all resources to NULL for goto cleanup */
    error_t *err = NULL;
    char *storage_path = NULL;
    char *expanded = NULL;
    char *absolute = NULL;
    char *normalized = NULL;
    char *home = NULL;
    char *home_canonical = NULL;

    if (input[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* Detect path type and route to appropriate handler */

    /* Case 1: Storage path (home/..., root/..., or custom/...)
     * Check this first to avoid unnecessary processing */
    if (str_starts_with(input, "home/") ||
        str_starts_with(input, "root/") ||
        str_starts_with(input, "custom/")) {

        /* Validate storage path format */
        err = path_validate_storage(input);
        if (err) {
            err = error_wrap(err, "Invalid storage path '%s'", input);
            goto cleanup;
        }

        /* Already in storage format - duplicate and return */
        storage_path = strdup(input);
        if (!storage_path) {
            err = ERROR(ERR_MEMORY, "Failed to allocate storage path");
        }
        goto cleanup;
    }

    /* Resolve input to absolute path */

    /* Case 2: Filesystem path (absolute or tilde-prefixed) */
    if (input[0] == '/' || input[0] == '~') {
        /* Expand tilde if needed */
        if (input[0] == '~') {
            err = path_expand_home(input, &expanded);
            if (err) {
                err = error_wrap(err, "Failed to expand path '%s'", input);
                goto cleanup;
            }
        } else {
            expanded = strdup(input);
            if (!expanded) {
                err = ERROR(ERR_MEMORY, "Failed to allocate path");
                goto cleanup;
            }
        }

        /* Make absolute (validates existence if require_exists) */
        err = fs_make_absolute(expanded, &absolute);
        if (err) {
            err = error_wrap(
                err, "Failed to resolve path '%s'%s", input,
                require_exists ? "\nHint: File must exist for this operation" : ""
            );
            goto cleanup;
        }
    }
    /* Case 3: Relative path (./foo, ../bar, or path/with/slash) */
    else if (path_is_relative(input)) {
        if (require_exists) {
            /* Strict mode: Use fs_make_absolute which validates existence */
            err = fs_make_absolute(input, &absolute);
            if (err) {
                err = error_wrap(
                    err, "Failed to resolve relative path '%s'\n"
                    "Hint: File must exist for this operation", input
                );
                goto cleanup;
            }
        } else {
            /* Flexible mode: Resolve via CWD without existence check */
            err = path_resolve_relative(input, &absolute);
            if (err) {
                err = error_wrap(
                    err, "Failed to resolve relative path '%s'", input
                );
                goto cleanup;
            }
        }
    }
    /* Case 4: Invalid/ambiguous path */
    else {
        err = ERROR(
            ERR_INVALID_ARG,
            "Path '%s' is neither a valid filesystem path nor storage path\n"
            "Hint: Use absolute (/path), tilde (~/.file), relative (./path), or\n"
            "      storage format (home/..., root/..., custom/...)", input
        );
        goto cleanup;
    }

    /* Normalize path to resolve any .. components before storage conversion */
    err = fs_normalize_path(absolute, &normalized);
    if (err) {
        err = error_wrap(err, "Failed to normalize path '%s'", input);
        goto cleanup;
    }

    /* Convert to storage format */
    if (require_exists) {
        /* Mode A: Strict canonicalization (for add, update)
         *
         * Uses path_to_storage() which already supports custom prefix via its
         * second parameter. However, path_to_storage() only accepts a single
         * prefix and is designed for add/update operations where --prefix is
         * explicit. For filter resolution, we try each prefix.
         *
         * Detection order:
         * 1. Custom prefixes - Explicit user intent, first match wins
         * 2. $HOME - Canonical for user files
         * 3. Root - Fallback for system files
         */
        path_prefix_t prefix;

        /* First try with NULL (detects home/ and root/) */
        err = path_to_storage(normalized, NULL, &storage_path, &prefix);
        if (err) {
            err = error_wrap(err, "Failed to convert path '%s'", input);
            goto cleanup;
        }

        /* If resolved to home/ or root/ but we have custom prefixes,
         * check if any match (explicit prefix wins over implicit detection) */
        if ((prefix == PREFIX_ROOT || prefix == PREFIX_HOME) &&
            custom_prefixes && prefix_count > 0) {
            /* Try each custom prefix to see if we should use custom/ instead */
            for (size_t i = 0; i < prefix_count; i++) {
                if (!custom_prefixes[i]) continue;

                const char *relative = NULL;
                int match = extract_relative_after_prefix(
                    normalized, custom_prefixes[i], &relative
                );
                if (match > 0) {
                    /* Found a matching custom prefix - rebuild as custom/ */
                    char *new_path = str_format("custom/%s", relative);
                    if (!new_path) {
                        err = ERROR(ERR_MEMORY, "Failed to format custom storage path");
                        goto cleanup;
                    }
                    err = path_validate_storage(new_path);
                    if (err) {
                        free(new_path);
                        goto cleanup;
                    }
                    free(storage_path);
                    storage_path = new_path;
                    break;
                }
            }
        }
    } else {
        /* Mode B: Pattern-based conversion (for show, revert, remove)
         * File need not exist - used for querying Git data */

        /* Get HOME directory for path classification */
        err = path_get_home(&home);
        if (err) {
            goto cleanup;
        }

        /* Canonicalize HOME to handle symlinks (e.g., /tmp -> /private/tmp on macOS)
         * This ensures consistent comparison with normalized paths.
         *
         * For relative paths (Case 3), this is necessary because getcwd() returns
         * canonical paths, but $HOME may contain symlinks. If canonicalization
         * fails (e.g., $HOME doesn't exist), fall back to the original HOME path.
         */
        error_t *canon_err = fs_canonicalize_path(home, &home_canonical);
        if (canon_err) {
            /* Canonicalization failed - free the error and continue with home_canonical = NULL */
            error_free(canon_err);
        }
        /* If canonicalization succeeded, home_canonical now contains canonical path */
        /* Keep original home as well for detection */

        /* Detection order:
         * 1. Custom prefixes - Explicit user intent, first match wins
         * 2. $HOME - Canonical for user files
         * 3. Root - Fallback for system files
         */

        /* Try custom prefixes first (explicit user intent wins) */
        if (custom_prefixes && prefix_count > 0) {
            for (size_t i = 0; i < prefix_count; i++) {
                if (!custom_prefixes[i]) continue;

                const char *rel = NULL;
                int cmatch = extract_relative_after_prefix(
                    normalized, custom_prefixes[i], &rel
                );
                if (cmatch > 0) {
                    /* Found a matching custom prefix */
                    storage_path = str_format("custom/%s", rel);
                    if (!storage_path) {
                        err = ERROR(
                            ERR_MEMORY, "Failed to format custom storage path"
                        );
                        goto cleanup;
                    }
                    break;
                }
            }
        }

        /* Try $HOME if no custom prefix matched */
        if (!storage_path) {
            const char *relative_path = NULL;
            int match = detect_home_prefix(
                normalized, home, home_canonical, &relative_path
            );

            if (match >= 0) {
                /* Under home directory (or is home directory itself) */
                if (match == 0) {
                    /* HOME directory itself - not allowed */
                    err = ERROR(
                        ERR_INVALID_ARG, "Cannot specify HOME directory itself"
                    );
                    goto cleanup;
                }

                /* Build storage path: home/... */
                storage_path = str_format("home/%s", relative_path);
                if (!storage_path) {
                    err = ERROR(ERR_MEMORY, "Failed to format storage path");
                    goto cleanup;
                }
            }
        }

        /* Fallback to root/ if neither custom nor HOME matched */
        if (!storage_path) {
            storage_path = str_format("root%s", normalized);
            if (!storage_path) {
                err = ERROR(ERR_MEMORY, "Failed to format storage path");
                goto cleanup;
            }
        }
    }

cleanup:
    free(expanded);
    free(absolute);
    free(normalized);
    free(home);
    free(home_canonical);

    if (err) {
        free(storage_path);
        return err;
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
    const char **custom_prefixes,
    size_t prefix_count,
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
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Glob pattern '%s' must use storage format or be basename-only\n"
                    "Examples: 'home/ * * / *.vim', '*.vim' (spaces for doc only)", input
                );
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
        err = path_resolve_input(
            input, false, custom_prefixes, prefix_count, &resolved
        );
        if (err) {
            err = error_wrap(err, "Invalid path '%s'", input);
            goto cleanup;
        }

        /* Store in hashmap (hashmap duplicates key internally) */
        err = hashmap_set(filter->exact_paths, resolved, (void *) 1);
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
        if (match_pattern(
            filter->glob_patterns[i], storage_path, MATCH_DOUBLESTAR
            )) {
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
        return ERROR(
            ERR_INVALID_ARG,
            "Custom prefix must be absolute path (got '%s')\n"
            "Example: --prefix /mnt/jails/web", prefix
        );
    }

    /* 2. No path traversal or redundant components */
    if (strstr(prefix, "//") != NULL) {
        return ERROR(
            ERR_INVALID_ARG, "Custom prefix contains '//': '%s'", prefix
        );
    }

    /* 3. Validate each component (catches . and .. at any position) */
    char *prefix_copy = strdup(prefix + 1);  /* skip leading / */
    if (!prefix_copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate path copy");
    }
    char *saveptr = NULL;
    char *comp = strtok_r(prefix_copy, "/", &saveptr);
    while (comp) {
        if (strcmp(comp, ".") == 0 || strcmp(comp, "..") == 0) {
            /* Save before free — comp points into prefix_copy */
            const char *bad = strcmp(comp, ".") == 0 ? "." : "..";
            free(prefix_copy);
            return ERROR(
                ERR_INVALID_ARG,
                "Custom prefix contains '%s' component: '%s'\n"
                "Use canonical paths without '.', '..', or '//'", bad, prefix
            );
        }
        comp = strtok_r(NULL, "/", &saveptr);
    }
    free(prefix_copy);

    /* 4. Must not end with slash (normalize) */
    size_t len = strlen(prefix);
    if (len > 1 && prefix[len - 1] == '/') {
        return ERROR(
            ERR_INVALID_ARG,
            "Custom prefix must not end with slash: '%s'\n"
            "Use: %.*s", prefix, (int) (len - 1), prefix
        );
    }

    /* 5. Normalize and validate with realpath() */
    char *resolved = realpath(prefix, NULL);
    if (!resolved) {
        if (errno == ENOENT) {
            return ERROR(
                ERR_INVALID_ARG,
                "Custom prefix directory does not exist: '%s'\n"
                "Create it first: mkdir -p '%s'", prefix, prefix
            );
        } else {
            return ERROR(
                ERR_INVALID_ARG,
                "Cannot resolve custom prefix '%s': %s",
                prefix, strerror(errno)
            );
        }
    }

    /* 6. Verify it's a directory */
    struct stat st;
    if (stat(resolved, &st) != 0) {
        free(resolved);
        return ERROR(
            ERR_INVALID_ARG, "Cannot stat custom prefix: %s",
            strerror(errno)
        );
    }

    if (!S_ISDIR(st.st_mode)) {
        free(resolved);
        return ERROR(
            ERR_INVALID_ARG,
            "Custom prefix must be a directory: '%s'", prefix
        );
    }

    free(resolved);
    return NULL;
}
