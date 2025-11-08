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

#include "types.h"

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
