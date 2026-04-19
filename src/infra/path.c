/**
 * path.c - Path resolution and conversion implementation
 *
 * SECURITY: All path operations validate against path traversal attacks.
 */

#include "infra/path.h"

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/error.h"
#include "base/hashmap.h"
#include "base/match.h"
#include "base/string.h"
#include "sys/filesystem.h"

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
 * Return the relative part of `absolute` after stripping `prefix`, with
 * path-component boundary verification (next character must be '/' or '\0').
 *
 * Boundary verification ensures prefix matches a complete path component:
 *   /home/user matches /home/user/.bashrc
 *   /home/user does NOT match /home/username/.bashrc
 *
 * Returns:
 *   NULL    - prefix doesn't match or boundary violation
 *   ""      - absolute == prefix exactly (points at '\0' in absolute)
 *   "path"  - absolute is prefix/path (points into absolute)
 *
 * Returned pointer aliases into `absolute` and is valid for its lifetime.
 *
 * @param absolute Absolute filesystem path
 * @param prefix Prefix to match against
 */
static const char *path_relative_after_prefix(
    const char *absolute,
    const char *prefix
) {
    if (!absolute || !prefix) {
        return NULL;
    }

    /* Check if absolute starts with prefix */
    size_t prefix_len = strlen(prefix);
    if (strncmp(absolute, prefix, prefix_len) != 0) {
        return NULL;
    }

    /* Verify boundary: next character must be '/' or '\0' */
    char boundary = absolute[prefix_len];
    if (boundary != '/' && boundary != '\0') {
        return NULL;  /* False match: /home/user vs /home/username */
    }

    /* Extract relative part, skipping leading slash */
    const char *relative = absolute + prefix_len;
    if (*relative == '/') {
        relative++;
    }

    return relative;  /* "" on exact match, non-empty otherwise */
}

/**
 * Storage classification candidate.
 *
 * The candidate list is logically a SET — classify picks the longest-
 * matching prefix (the tightest container). Input order matters only as
 * a stable tiebreaker when two candidates match with equal prefix length.
 *
 * Borrowed pointers: `prefix`, `label`, and `display` must outlive the
 * classify call. An empty prefix ("") matches any absolute path with
 * length 0, serving as the universal root fallback.
 */
typedef struct {
    const char *prefix;    /* filesystem prefix to match ("" for root) */
    const char *label;     /* storage label: "custom", "home", "root" */
    const char *display;   /* human label for errors: "custom prefix", "HOME", "root" */
    path_prefix_t kind;
} path_candidate_t;

/**
 * Classify an absolute filesystem path against a candidate set.
 *
 * Picks the longest matching prefix (tightest container wins — same
 * semantic as filesystem mounts or URL routers). Ties on equal prefix
 * length are broken by input order (stable, earlier wins). A match whose
 * relative part is empty (path equals the winning prefix exactly) is
 * rejected as "directory itself".
 *
 * The empty prefix ("") has length 0, so it always loses to any non-
 * empty match and serves as the universal root fallback when no custom
 * or HOME prefix contains the path.
 *
 * @param filesystem_path Absolute path to classify
 * @param cands Candidate set (order affects only tiebreaks)
 * @param count Number of candidates
 * @param out_storage_path Allocated storage path on success (caller frees)
 * @param out_kind Optional: receives winning candidate's kind
 * @return Error or NULL on success
 */
static error_t *path_classify(
    const char *filesystem_path,
    const path_candidate_t *cands,
    size_t count,
    char **out_storage_path,
    path_prefix_t *out_kind
) {
    const path_candidate_t *candidate = NULL;
    const char *candidate_relative = NULL;
    size_t candidate_plen = 0;

    for (size_t i = 0; i < count; i++) {
        const path_candidate_t *c = &cands[i];
        const char *relative = path_relative_after_prefix(
            filesystem_path,
            c->prefix
        );
        if (!relative) continue;

        /* Strictly longer wins; equal length keeps the earlier candidate. */
        size_t plen = strlen(c->prefix);
        if (!candidate || plen > candidate_plen) {
            candidate = c;
            candidate_relative = relative;
            candidate_plen = plen;
        }
    }

    if (!candidate) {
        /* Unreachable when caller includes the empty-prefix root candidate
         * (matches every absolute path). Kept as a defensive guard. */
        return ERROR(
            ERR_INTERNAL, "No classification candidate matched: %s",
            filesystem_path
        );
    }

    if (*candidate_relative == '\0') {
        return ERROR(
            ERR_INVALID_ARG, "Cannot use the %s directory as a file path",
            candidate->display
        );
    }

    char *result = str_format("%s/%s", candidate->label, candidate_relative);
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to format storage path");
    }
    *out_storage_path = result;
    if (out_kind) *out_kind = candidate->kind;

    return NULL;
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
            if (!path_relative_after_prefix(path, custom_prefix)) {
                /* Not under prefix - prepend it (path is absolute within the virtual root) */
                joined = str_format("%s%s", custom_prefix, path);
                if (!joined) {
                    free(expanded);
                    return ERROR(ERR_MEMORY, "Failed to prepend custom prefix to path");
                }
                path_to_make_absolute = joined;
            }
            /* Otherwise already under prefix, pass through unchanged */
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
 * Selection is delegated to path_classify: longest matching prefix
 * wins. An explicit --prefix naturally wins over HOME when it is
 * more specific, and loses to HOME when HOME is more specific. The
 * empty-prefix root is the universal fallback.
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

    /* Existence gate: add/update callers require the file to be on disk. */
    if (!fs_lexists(filesystem_path)) {
        return ERROR(ERR_NOT_FOUND, "File not found: %s", filesystem_path);
    }

    char *home = NULL;
    char *home_canonical = NULL;
    char *result = NULL;

    error_t *err = path_get_home(&home);
    if (err) {
        goto cleanup;
    }

    /* Canonicalize HOME to handle symlinks (e.g., /tmp -> /private/tmp on macOS).
     * Best-effort: if it fails, fall back to the original HOME. */
    error_t *canon_err = fs_canonicalize_path(home, &home_canonical);
    if (canon_err) {
        error_free(canon_err);
    }

    /* Build candidate set: explicit custom (if any), HOME (with canonical
     * fallback for symlinks), and the root fallback. classify picks the
     * tightest matching prefix — order only breaks length ties. */
    path_candidate_t cands[4];
    size_t n = 0;
    if (custom_prefix && custom_prefix[0] != '\0') {
        cands[n++] = (path_candidate_t){
            custom_prefix, "custom", "custom prefix", PREFIX_CUSTOM
        };
    }
    cands[n++] = (path_candidate_t){ home, "home", "HOME", PREFIX_HOME };
    if (home_canonical && strcmp(home_canonical, home) != 0) {
        cands[n++] = (path_candidate_t){
            home_canonical, "home", "HOME", PREFIX_HOME
        };
    }
    cands[n++] = (path_candidate_t){ "", "root", "root", PREFIX_ROOT };

    err = path_classify(filesystem_path, cands, n, &result, prefix_out);
    if (err) {
        goto cleanup;
    }

    /* Validate generated storage path format */
    err = path_validate_storage(result);
    if (err) {
        free(result);
        goto cleanup;
    }

    *storage_path = result;

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
    const char *const *prefixes,
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
    path_candidate_t *cands = NULL;

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

        /* Make absolute */
        err = fs_make_absolute(expanded, &absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve path '%s'", input);
            goto cleanup;
        }
    }
    /* Case 3: Relative path (./foo, ../bar, or path/with/slash) */
    else if (path_is_relative(input)) {
        /* Resolve via CWD without existence check */
        err = path_resolve_relative(input, &absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve relative path '%s'", input);
            goto cleanup;
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

    /* Convert to storage format via shared classifier (no existence check). */

    err = path_get_home(&home);
    if (err) goto cleanup;

    /* Canonicalize HOME to handle symlinks (e.g., /tmp -> /private/tmp on macOS).
     * For relative paths (Case 3), this matters because getcwd() returns
     * canonical paths, but $HOME may contain symlinks. Best-effort: on
     * failure, fall back to the original HOME path. */
    error_t *canon_err = fs_canonicalize_path(home, &home_canonical);
    if (canon_err) {
        error_free(canon_err);
    }

    /* Build candidate set: each custom prefix, HOME (with canonical fallback
     * for symlinks), and the root fallback. classify picks the tightest
     * matching prefix — overlapping customs resolve by length, not by
     * enable order. */
    size_t cap = prefix_count + 3;
    cands = calloc(cap, sizeof(*cands));
    if (!cands) {
        err = ERROR(ERR_MEMORY, "Failed to allocate classification candidates");
        goto cleanup;
    }
    size_t n = 0;
    for (size_t i = 0; i < prefix_count; i++) {
        const char *p = prefixes ? prefixes[i] : NULL;
        if (p && p[0]) {
            cands[n++] = (path_candidate_t){
                p, "custom", "custom prefix", PREFIX_CUSTOM
            };
        }
    }
    cands[n++] = (path_candidate_t){ home, "home", "HOME", PREFIX_HOME };
    if (home_canonical && strcmp(home_canonical, home) != 0) {
        cands[n++] = (path_candidate_t){
            home_canonical, "home", "HOME", PREFIX_HOME
        };
    }
    cands[n++] = (path_candidate_t){ "", "root", "root", PREFIX_ROOT };

    err = path_classify(normalized, cands, n, &storage_path, NULL);
    if (err) goto cleanup;

    err = path_validate_storage(storage_path);
    if (err) goto cleanup;

cleanup:
    free(expanded);
    free(absolute);
    free(normalized);
    free(home);
    free(home_canonical);
    free(cands);

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
    char *const *inputs,
    size_t count,
    const char *const *prefixes,
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
        err = path_resolve_input(input, prefixes, prefix_count, &resolved);
        if (err) {
            err = error_wrap(err, "Invalid path '%s'", input);
            goto cleanup;
        }

        /* Store in hashmap (hashmap duplicates key internally) */
        err = hashmap_set(filter->exact_paths, resolved, (void *) 1);
        free(resolved);
        if (err) goto cleanup;
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

    /* 2. Reject the filesystem root — inert at classify time (boundary
     * check rejects any match) but always a misconfiguration. */
    if (prefix[1] == '\0') {
        return ERROR(
            ERR_INVALID_ARG,
            "Custom prefix cannot be the filesystem root '/'\n"
            "Choose a specific directory: --prefix /mnt/jails/web"
        );
    }

    /* 3. No path traversal or redundant components */
    if (strstr(prefix, "//") != NULL) {
        return ERROR(
            ERR_INVALID_ARG, "Custom prefix contains '//': '%s'", prefix
        );
    }

    /* 4. Validate each component (catches . and .. at any position) */
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

    /* 5. Must not end with slash (normalize) */
    size_t len = strlen(prefix);
    if (len > 1 && prefix[len - 1] == '/') {
        return ERROR(
            ERR_INVALID_ARG,
            "Custom prefix must not end with slash: '%s'\n"
            "Use: %.*s", prefix, (int) (len - 1), prefix
        );
    }

    /* 6. Normalize and validate with realpath() */
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

    /* 7. Verify it's a directory */
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
