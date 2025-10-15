/**
 * filesystem.h - Safe filesystem operations
 *
 * Provides filesystem operations with comprehensive error handling,
 * input validation, and resource management.
 *
 * Design principles:
 * - Validate all inputs before use
 * - Return errors for all failure cases
 * - Clean up resources on error paths
 * - No silent failures
 */

#ifndef DOTTA_FILESYSTEM_H
#define DOTTA_FILESYSTEM_H

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "types.h"

/**
 * File operations
 */

/**
 * Read entire file into buffer
 *
 * @param path File path (must not be NULL)
 * @param out Output buffer (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_read_file(const char *path, buffer_t **out);

/**
 * Write raw bytes to file (overwrites if exists)
 *
 * Creates parent directories if needed.
 * This is a lower-level function for writing data directly from memory
 * without the buffer_t abstraction. Useful for writing directly from
 * git blobs or other external data sources.
 *
 * @param path File path (must not be NULL)
 * @param data Raw data bytes (can be NULL if size is 0)
 * @param size Number of bytes to write
 * @param uid Target UID for file ownership (use -1 to preserve current)
 * @param gid Target GID for file ownership (use -1 to preserve current)
 * @return Error or NULL on success
 */
error_t *fs_write_file_raw(const char *path, const unsigned char *data, size_t size,
                           uid_t uid, gid_t gid);

/**
 * Write buffer to file (overwrites if exists)
 *
 * Creates parent directories if needed.
 *
 * @param path File path (must not be NULL)
 * @param content Buffer to write (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_write_file(const char *path, const buffer_t *content);

/**
 * Copy file preserving permissions
 *
 * @param src Source path (must exist, must not be NULL)
 * @param dst Destination path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_copy_file(const char *src, const char *dst);

/**
 * Remove file
 *
 * Not an error if file doesn't exist.
 *
 * @param path File path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_remove_file(const char *path);

/**
 * Check if file exists
 *
 * @param path File path (must not be NULL)
 * @return true if file exists and is a regular file
 */
bool fs_file_exists(const char *path);

/**
 * Directory operations
 */

/**
 * Create directory
 *
 * @param path Directory path (must not be NULL)
 * @param parents Create parent directories if true
 * @return Error or NULL on success
 */
error_t *fs_create_dir(const char *path, bool parents);

/**
 * Remove directory
 *
 * @param path Directory path (must not be NULL)
 * @param recursive Remove contents recursively if true
 * @return Error or NULL on success
 */
error_t *fs_remove_dir(const char *path, bool recursive);

/**
 * Check if path is a directory
 *
 * @param path Path to check (must not be NULL)
 * @return true if path exists and is a directory
 */
bool fs_is_directory(const char *path);

/**
 * List directory contents
 *
 * @param path Directory path (must not be NULL)
 * @param out String array of filenames (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_list_dir(const char *path, string_array_t **out);

/**
 * Ensure parent directories exist
 *
 * Creates all parent directories for the given path if they don't exist.
 * Similar to `mkdir -p $(dirname path)`.
 *
 * @param path Full path to file/directory (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_ensure_parent_dirs(const char *path);

/**
 * Path operations
 */

/**
 * Canonicalize path (resolve symlinks, . and ..)
 *
 * Path must exist.
 *
 * @param path Path to resolve (must not be NULL)
 * @param out Canonical path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *fs_canonicalize_path(const char *path, char **out);

/**
 * Get parent directory path
 *
 * @param path Path (must not be NULL)
 * @param out Parent directory (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *fs_get_parent_dir(const char *path, char **out);

/**
 * Join path components
 *
 * @param base Base path (must not be NULL)
 * @param component Component to append (must not be NULL)
 * @param out Joined path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *fs_path_join(const char *base, const char *component, char **out);

/**
 * Check if path is writable
 *
 * @param path Path to check (must not be NULL)
 * @return true if path is writable (or parent is writable if doesn't exist)
 */
bool fs_is_writable(const char *path);

/**
 * Symlink operations
 */

/**
 * Create symbolic link
 *
 * @param target Link target (must not be NULL)
 * @param linkpath Link path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_create_symlink(const char *target, const char *linkpath);

/**
 * Read symbolic link target
 *
 * @param linkpath Link path (must not be NULL, must be a symlink)
 * @param out Target path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *fs_read_symlink(const char *linkpath, char **out);

/**
 * Check if path is a symbolic link
 *
 * @param path Path to check (must not be NULL)
 * @return true if path is a symbolic link
 */
bool fs_is_symlink(const char *path);

/**
 * Permission operations
 */

/**
 * Get file permissions
 *
 * @param path File path (must not be NULL, must exist)
 * @param out Mode (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_get_permissions(const char *path, mode_t *out);

/**
 * Set file permissions
 *
 * @param path File path (must not be NULL, must exist)
 * @param mode Permission mode
 * @return Error or NULL on success
 */
error_t *fs_set_permissions(const char *path, mode_t mode);

/**
 * Check if file is executable
 *
 * @param path File path (must not be NULL)
 * @return true if file has execute permission for owner
 */
bool fs_is_executable(const char *path);

/**
 * Check if path exists (any type)
 *
 * @param path Path to check (must not be NULL)
 * @return true if path exists
 */
bool fs_exists(const char *path);

/**
 * Check if path exists (without following symlinks)
 *
 * @param path Path to check (must not be NULL)
 * @return true if path exists
 */
bool fs_lexists(const char *path);

/**
 * Privilege and ownership operations
 */

/**
 * Get the actual user's UID/GID when running under sudo
 *
 * When dotta is run via sudo, this returns the original user's credentials
 * (from SUDO_UID/SUDO_GID environment variables). When not running under sudo,
 * returns the current process's UID/GID.
 *
 * @param uid Output for user ID (must not be NULL)
 * @param gid Output for group ID (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_get_actual_user(uid_t *uid, gid_t *gid);

/**
 * Check if running as root (effective UID is 0)
 *
 * @return true if effective UID is 0
 */
bool fs_is_running_as_root(void);

#endif /* DOTTA_FILESYSTEM_H */
