/**
 * path.h - Path resolution and conversion
 *
 * Handles conversion between filesystem paths and storage paths.
 *
 * Storage path format:
 * - home/.bashrc   -> $HOME/.bashrc
 * - root/etc/hosts -> /etc/hosts
 *
 * SECURITY CRITICAL: Prevents path traversal attacks.
 *
 * Design principles:
 * - Reject any path containing ".."
 * - Validate all paths before conversion
 * - Canonicalize when needed
 * - Clear error messages
 */

#ifndef DOTTA_PATH_H
#define DOTTA_PATH_H

#include <types.h>

/**
 * Normalize user input path to absolute filesystem path
 *
 * Transformation order:
 * 1. Tilde expansion (~/ → $HOME)
 * 2. Custom prefix joining (relative + prefix)
 * 3. Absolute path pass-through
 * 4. CWD joining (relative, no prefix)
 *
 * Security: Rejects path traversal (..) in relative paths with custom_prefix.
 *
 * Examples:
 *   ("~/file", NULL)        → "$HOME/file"
 *   ("rel/file", "/jail")   → "/jail/rel/file"
 *   ("/abs/file", "/jail")  → "/abs/file"
 *   ("rel/file", NULL)      → "$CWD/rel/file"
 *   ("../escape", "/jail")  → ERROR
 *
 * @param user_path User-provided path (filesystem or tilde)
 * @param custom_prefix Optional custom prefix for relative paths (can be NULL)
 * @param out Normalized absolute path (caller must free)
 * @return Error or NULL on success
 */
error_t *path_normalize_input(
    const char *user_path,
    const char *custom_prefix,
    char **out
);

/**
 * Convert filesystem path to storage path
 *
 * Detection order (CANONICAL REPRESENTATION):
 * 1. $HOME (canonical for user files) - FIRST
 * 2. Custom prefix (if provided and matches) - SECOND
 * 3. Root (fallback for system files)
 *
 * This ensures files under $HOME ALWAYS use home/ prefix,
 * even if --prefix matches $HOME (canonical representation).
 *
 * Examples:
 *   ~/.bashrc (NULL)              -> home/.bashrc (PREFIX_HOME)
 *   ~/.bashrc ($HOME)             -> home/.bashrc (PREFIX_HOME, prefix ignored)
 *   /jail/etc/nginx.conf (/jail) -> custom/etc/nginx.conf (PREFIX_CUSTOM)
 *   /etc/hosts (NULL)             -> root/etc/hosts (PREFIX_ROOT)
 *
 * @param filesystem_path Filesystem path (e.g., "/mnt/jail/etc/nginx.conf")
 * @param custom_prefix Custom prefix to detect (NULL if not using custom/)
 * @param storage_path Output storage path (caller must free)
 * @param prefix_out Output prefix type (can be NULL)
 * @return Error or NULL on success
 */
error_t *path_to_storage(
    const char *filesystem_path,
    const char *custom_prefix,
    char **storage_path,
    path_prefix_t *prefix_out
);

/**
 * Convert storage path to filesystem path
 *
 * For custom/ paths, requires custom_prefix parameter.
 * For home/ and root/ paths, custom_prefix is ignored (can be NULL).
 *
 * Examples:
 *   home/.bashrc (NULL)           -> $HOME/.bashrc
 *   root/etc/hosts (NULL)         -> /etc/hosts
 *   custom/etc/nginx.conf (/jail) -> /jail/etc/nginx.conf
 *
 * @param storage_path Storage path (e.g., "custom/etc/nginx.conf")
 * @param custom_prefix Custom prefix for custom/ paths (NULL for home/root)
 * @param filesystem_path Output filesystem path (caller must free)
 * @return Error or NULL on success
 */
error_t *path_from_storage(
    const char *storage_path,
    const char *custom_prefix,
    char **filesystem_path
);

/**
 * Validate storage path
 *
 * Checks:
 * - No ".." components (path traversal)
 * - Starts with "home/" or "root/"
 * - Not absolute (no leading /)
 * - Not empty
 *
 * @param storage_path Path to validate (must not be NULL)
 * @return Error or NULL if valid
 */
error_t *path_validate_storage(const char *storage_path);

/**
 * Validate filesystem path
 *
 * Checks:
 * - Not empty
 * - Absolute path (starts with /)
 * - No suspicious patterns
 *
 * @param filesystem_path Path to validate (must not be NULL)
 * @return Error or NULL if valid
 */
error_t *path_validate_filesystem(const char *filesystem_path);

/**
 * Check if path is under $HOME
 *
 * @param path Absolute filesystem path (must not be NULL)
 * @return true if path is under $HOME directory
 */
bool path_is_under_home(const char *path);

/**
 * Expand ~ to $HOME
 *
 * Examples:
 *   ~/.bashrc -> /home/user/.bashrc
 *   ~/foo/bar -> /home/user/foo/bar
 *
 * @param path Path with ~ prefix (must not be NULL)
 * @param out Expanded path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_expand_home(const char *path, char **out);

/**
 * Make path relative to base
 *
 * Examples:
 *   base=/home/user, full=/home/user/.bashrc -> .bashrc
 *   base=/home/user, full=/etc/hosts         -> ../../etc/hosts
 *
 * @param base Base directory (must not be NULL)
 * @param full Full path (must not be NULL)
 * @param out Relative path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_make_relative(
    const char *base,
    const char *full,
    char **out
);

/**
 * Get $HOME directory
 *
 * @param out HOME directory path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_get_home(char **out);

/**
 * Resolve flexible path input to canonical storage format
 *
 * Accepts two input formats:
 *   1. Filesystem paths: /path/to/file, ~/path/to/file
 *   2. Storage paths: home/path/to/file, root/path/to/file
 *
 * Behavior modes:
 *   - require_exists=true: Filesystem paths MUST exist and will be canonicalized
 *                          (resolves symlinks, verifies existence)
 *                          Critical for add/update to track correct files
 *
 *   - require_exists=false: Filesystem paths converted by pattern only
 *                           (file need not exist on disk)
 *                           Used for show/revert/remove (operations on Git data)
 *
 * Examples:
 *   ~/.bashrc (exists=true)     -> canonicalized to home/.bashrc
 *   ~/.bashrc (exists=false)    -> pattern-converted to home/.bashrc
 *   home/.bashrc (either mode)  -> validated and returned as home/.bashrc
 *   /etc/hosts (exists=true)    -> canonicalized to root/etc/hosts
 *   .bashrc (either mode)       -> ERROR: ambiguous/invalid path
 *
 * @param input User-provided path string (must not be NULL)
 * @param require_exists Whether to canonicalize and verify existence
 * @param out_storage_path Output in storage format (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_resolve_input(
    const char *input,
    bool require_exists,
    char **out_storage_path
);

/**
 * Path filter for batch matching
 *
 * Stores pre-resolved storage paths for efficient O(N) matching.
 * Created from user-provided paths (filesystem or storage format).
 *
 * NULL filter semantics: matches all paths (no filtering).
 */
typedef struct {
    char **storage_paths;    /* Normalized storage paths (owned) */
    size_t count;            /* Number of paths */
} path_filter_t;

/**
 * Create path filter from user input paths
 *
 * Pre-resolves all inputs to storage format using path_resolve_input().
 * Accepts filesystem paths (~/.bashrc, /etc/hosts) and storage paths
 * (home/.bashrc, root/etc/hosts, custom/etc/nginx.conf).
 *
 * NULL semantics:
 * - If inputs is NULL or count is 0, returns NULL filter (matches all)
 * - A NULL filter passed to path_filter_matches() matches all paths
 *
 * Error handling:
 * - If any path resolution fails, returns error and cleans up
 * - Partial results are not returned
 *
 * @param inputs User-provided path strings (can be NULL if count is 0)
 * @param count Number of input paths
 * @param out Path filter (must not be NULL, receives NULL if no filter)
 * @return Error or NULL on success
 */
error_t *path_filter_create(
    const char **inputs,
    size_t count,
    path_filter_t **out
);

/**
 * Check if storage path matches filter
 *
 * Returns true if:
 * - Filter is NULL (no restrictions, matches all)
 * - storage_path matches any filter entry (exact match)
 *
 * Thread safety: Safe for concurrent reads with same filter.
 *
 * @param filter Path filter (NULL = match all)
 * @param storage_path Storage path to check (must not be NULL)
 * @return true if matches, false otherwise
 */
bool path_filter_matches(
    const path_filter_t *filter,
    const char *storage_path
);

/**
 * Free path filter
 *
 * Frees all allocated storage paths and the filter structure.
 * Safe to call with NULL.
 *
 * @param filter Filter to free (can be NULL)
 */
void path_filter_free(path_filter_t *filter);

/**
 * Validate custom prefix parameter
 *
 * Validates that a user-provided custom prefix is safe to use.
 *
 * Checks:
 * - Absolute path (starts with /)
 * - No path traversal (no ../, ./, //)
 * - No trailing slash (normalized)
 * - Directory exists (via realpath)
 * - Is a directory (not a file)
 *
 * Security Notes:
 * - Uses realpath() to normalize and verify existence
 * - Follows symlinks (documented behavior)
 * - Prevents path traversal attacks
 *
 * @param prefix Custom prefix to validate (must not be NULL)
 * @return Error or NULL if valid
 */
error_t *path_validate_custom_prefix(const char *prefix);

#endif /* DOTTA_PATH_H */
