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
 * 2. Custom prefix: join with relative paths, prepend to absolute paths
 *    (absolute paths already under prefix pass through unchanged)
 * 3. CWD joining (relative, no prefix)
 *
 * The custom_prefix defines a virtual filesystem root. All paths (relative
 * and absolute) are resolved within that context. An absolute path like
 * /etc/hosts with prefix /jail becomes /jail/etc/hosts because the path
 * is "absolute within the jail".
 *
 * Security: Rejects path traversal (..) in relative paths with custom_prefix.
 *
 * Examples:
 *   ("~/file", NULL)              → "$HOME/file"
 *   ("rel/file", "/jail")         → "/jail/rel/file"
 *   ("/etc/hosts", "/jail")       → "/jail/etc/hosts"
 *   ("/jail/etc/hosts", "/jail")  → "/jail/etc/hosts" (already under prefix)
 *   ("rel/file", NULL)            → "$CWD/rel/file"
 *   ("../escape", "/jail")        → ERROR
 *
 * @param user_path User-provided path (filesystem or tilde)
 * @param custom_prefix Optional prefix defining virtual filesystem root (can be NULL)
 * @param out Normalized absolute path (caller must free)
 * @return Error or NULL on success
 */
error_t *path_normalize_input(
    const char *user_path,
    const char *custom_prefix,
    char **out
);

/**
 * Classify absolute filesystem path into storage path
 *
 * Pure classifier — does NOT normalize the input. Callers must provide
 * an already-resolved absolute filesystem path (use path_normalize_input()
 * first if working with raw user input).
 *
 * Detection order:
 * 1. Custom prefix (if explicitly provided and matches) - FIRST
 * 2. $HOME (canonical for user files) - SECOND
 * 3. Root (fallback for system files)
 *
 * Explicit user intent (--prefix) takes priority over implicit $HOME
 * detection. When no custom prefix is provided, $HOME is checked first
 * (no behavior change for the common case).
 *
 * Examples:
 *   ("/home/user/.bashrc", NULL)           -> home/.bashrc (PREFIX_HOME)
 *   ("/jail/etc/nginx.conf", "/jail")      -> custom/etc/nginx.conf (PREFIX_CUSTOM)
 *   ("/home/user/.bashrc", "/home/user/r") -> home/.bashrc (not under prefix)
 *   ("/etc/hosts", NULL)                   -> root/etc/hosts (PREFIX_ROOT)
 *
 * @param filesystem_path Absolute filesystem path (must start with '/')
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
 * - No ".." or "." components (path traversal)
 * - Starts with "home/", "root/", or "custom/"
 * - Not absolute (no leading /)
 * - Not empty
 * - No trailing slash (must reference a file, not a directory)
 *
 * @param storage_path Path to validate (must not be NULL)
 * @return Error or NULL if valid
 */
error_t *path_validate_storage(const char *storage_path);

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
 *   3. Relative paths: ./path, ../path, .dotfile, path/to/file (resolved via CWD)
 *   4. Storage paths: home/..., root/..., custom/...
 *
 * Note on relative paths:
 *   Paths starting with '.' are treated as relative, including dotfiles like
 *   '.bashrc'. This allows convenient shorthand: typing '.bashrc' in $HOME
 *   resolves to 'home/.bashrc'. For single-component paths without '.', use
 *   explicit './' prefix to indicate relative path intent.
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
 * Custom prefix detection:
 *   When custom_prefixes is provided (non-NULL with count > 0),
 *   filesystem paths are checked against each prefix BEFORE $HOME detection.
 *   First matching prefix wins. This enables proper resolution of paths
 *   like /mnt/jail/etc/nginx.conf to custom/etc/nginx.conf when /mnt/jail
 *   is in the custom_prefixes array, even when the path is under $HOME.
 *
 *   Detection order:
 *   1. Custom prefixes - Explicit user intent, first match wins
 *   2. $HOME - Canonical for user files
 *   3. Root - Fallback for system files
 *
 * Path normalization:
 *   All paths are normalized to resolve '.' and '..' components before
 *   conversion to storage format. This ensures consistent HOME detection
 *   regardless of how the path is expressed.
 *
 * Examples:
 *   ~/.bashrc (exists=true)     -> canonicalized to home/.bashrc
 *   ~/.bashrc (exists=false)    -> pattern-converted to home/.bashrc
 *   ./config (in $HOME)         -> home/config
 *   ./config (in /etc)          -> root/etc/config
 *   .bashrc (in $HOME)          -> home/.bashrc (dotfile as relative path)
 *   ../file (in $HOME/project)  -> home/file (.. resolved)
 *   home/.bashrc (either mode)  -> validated and returned as home/.bashrc
 *   /etc/hosts (exists=true)    -> canonicalized to root/etc/hosts
 *   /mnt/jail/etc/nginx.conf    -> custom/etc/nginx.conf (if /mnt/jail in prefixes)
 *   config (no slash)           -> ERROR: ambiguous (use ./config)
 *
 * @param input User-provided path string (must not be NULL)
 * @param require_exists Whether to canonicalize and verify existence
 * @param custom_prefixes Custom prefixes to try (NULL = no custom prefixes)
 * @param out_storage_path Output in storage format (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_resolve_input(
    const char *input,
    bool require_exists,
    const string_array_t *custom_prefixes,
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
    struct hashmap *exact_paths;  /* Exact paths for O(1) lookup (hashmap owns keys) */
    char **glob_patterns;         /* Glob patterns for iteration (owned) */
    size_t glob_count;            /* Number of glob patterns */
    size_t count;                 /* Total entries (exact + globs) */
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
 * Custom prefix detection:
 *   When custom_prefixes is provided (non-NULL with count > 0),
 *   filesystem path inputs are checked against each prefix during resolution.
 *   This enables users to specify /mnt/jail/etc/nginx.conf as a filter and
 *   have it correctly match custom/etc/nginx.conf in the manifest.
 *
 * NULL semantics:
 * - If inputs is NULL or count is 0, returns NULL filter (matches all)
 * - A NULL filter passed to path_filter_matches() matches all paths
 * - custom_prefixes can be NULL (no custom prefix resolution)
 *
 * Error handling:
 * - If any path resolution fails, returns error and cleans up
 * - Partial results are not returned
 *
 * @param inputs User-provided path or pattern strings (can be NULL if count is 0)
 * @param count Number of inputs
 * @param custom_prefixes Custom prefixes for resolution (NULL = no custom prefixes)
 * @param out Path filter (must not be NULL, receives NULL if no filter)
 * @return Error or NULL on success
 */
error_t *path_filter_create(
    char *const *inputs,
    size_t count,
    const string_array_t *custom_prefixes,
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
