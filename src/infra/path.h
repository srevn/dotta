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
 * Accepts multiple input formats:
 *   1. Absolute paths: /path/to/file
 *   2. Tilde paths: ~/path/to/file
 *   3. Relative paths: ./path, ../path, path/to/file (resolved via CWD)
 *   4. Storage paths: home/..., root/..., custom/...
 *
 * Behavior modes:
 *   - require_exists=true: Paths MUST exist and will be canonicalized
 *                          (validates existence via lstat)
 *                          Critical for add/update to track correct files
 *
 *   - require_exists=false: Paths converted by pattern only
 *                           (file need not exist on disk)
 *                           Used for show/revert/remove/filters
 *
 * Examples:
 *   ~/.bashrc (exists=true)     -> canonicalized to home/.bashrc
 *   ~/.bashrc (exists=false)    -> pattern-converted to home/.bashrc
 *   ./config (in $HOME)         -> home/config
 *   ./config (in /etc)          -> root/etc/config
 *   home/.bashrc (either mode)  -> validated and returned as home/.bashrc
 *   /etc/hosts (exists=true)    -> canonicalized to root/etc/hosts
 *   config (no slash)           -> ERROR: ambiguous (use ./config)
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
 * Path filter for selective file operations
 *
 * Supports three types of filter entries:
 *   1. Exact paths: "home/.bashrc" - matches single file
 *   2. Directory prefixes: "home/.config/fish" - matches all files under directory
 *   3. Glob patterns: "*.vim", "home/ ** / *.conf" - pattern-based matching
 *
 * NULL filter semantics: matches all paths (no filtering).
 */
typedef struct {
    char **storage_paths;    /* Storage paths or glob patterns (owned) */
    size_t count;            /* Number of entries */
} path_filter_t;

/**
 * Create path filter from user input paths
 *
 * Accepts three types of inputs:
 *   1. Glob patterns (*, ?, []) - stored as-is for pattern matching
 *      Examples: "*.vim", "home/ ** / *.conf" (recursive)
 *
 *   2. Filesystem paths - resolved to storage format
 *      Examples: ~/.bashrc, /etc/hosts, ./config, ../path
 *
 *   3. Storage paths - validated and stored directly
 *      Examples: home/.bashrc, root/etc/hosts, custom/etc/nginx.conf
 *
 * Glob pattern rules:
 * - Basename-only patterns ("*.vim") match at any depth
 * - Patterns with "/" must use storage format (e.g., home/ followed by glob)
 * - Recursive patterns (doublestar followed by /foo) match at any depth
 *
 * NULL semantics:
 * - If inputs is NULL or count is 0, returns NULL filter (matches all)
 * - A NULL filter passed to path_filter_matches() matches all paths
 *
 * Error handling:
 * - If any path resolution fails, returns error and cleans up
 * - Partial results are not returned
 *
 * @param inputs User-provided path or pattern strings (can be NULL if count is 0)
 * @param count Number of inputs
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
 * Matching semantics (gitignore-style via match module):
 * - Exact match: "home/.bashrc" matches "home/.bashrc"
 * - Directory prefix: "home/.config" matches "home/.config/fish/config.fish"
 * - Glob patterns: recursive globs match nested paths
 * - Basename patterns: "*.vim" matches "home/.vim/vimrc.vim"
 *
 * Returns true if:
 * - Filter is NULL (no restrictions, matches all)
 * - storage_path matches any filter entry
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
