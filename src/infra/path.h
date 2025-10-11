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
 * Examples:
 *   /home/user/.bashrc  -> home/.bashrc (PREFIX_HOME)
 *   /etc/hosts          -> root/etc/hosts (PREFIX_ROOT)
 *
 * @param filesystem_path Absolute filesystem path (must not be NULL)
 * @param storage_path Output storage path (must not be NULL, caller must free)
 * @param prefix Output prefix type (can be NULL if not needed)
 * @return Error or NULL on success
 */
error_t *path_to_storage(
    const char *filesystem_path,
    char **storage_path,
    path_prefix_t *prefix
);

/**
 * Convert storage path to filesystem path
 *
 * Examples:
 *   home/.bashrc     -> /home/user/.bashrc
 *   root/etc/hosts   -> /etc/hosts
 *
 * @param storage_path Storage path (must not be NULL, must start with home/ or root/)
 * @param filesystem_path Output filesystem path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_from_storage(
    const char *storage_path,
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

#endif /* DOTTA_PATH_H */
