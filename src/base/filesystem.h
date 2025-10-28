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
 * SECURITY: This function atomically sets permissions using fchmod() after
 * creating the file and setting ownership, ensuring there is no window where
 * the file has incorrect permissions (critical for sensitive files like SSH keys).
 *
 * @param path File path (must not be NULL)
 * @param data Raw data bytes (can be NULL if size is 0)
 * @param size Number of bytes to write
 * @param mode Permission mode (e.g., 0600, 0644, 0755)
 * @param uid Target UID for file ownership (use -1 to preserve current)
 * @param gid Target GID for file ownership (use -1 to preserve current)
 * @return Error or NULL on success
 */
error_t *fs_write_file_raw(const char *path, const unsigned char *data, size_t size,
                           mode_t mode, uid_t uid, gid_t gid);

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
 * Create directory with specific mode (idempotent)
 *
 * Ensures a directory exists with the exact specified permissions.
 * This function is idempotent - it can be safely called multiple times
 * and will ensure the directory has the correct permissions each time.
 *
 * Behavior:
 * - If directory doesn't exist: creates it with exact mode
 * - If directory already exists: updates its mode to match (useful with --force)
 * - Uses chmod() to enforce exact mode (not affected by umask)
 *
 * If parents is true, parent directories are created with default mode (0755),
 * while the target directory is ensured to have the specified mode.
 *
 * Consistency: Matches file behavior where fs_write_file_raw() always
 * sets exact permissions regardless of whether file exists.
 *
 * @param path Directory path (must not be NULL)
 * @param mode Permission mode for the target directory (e.g., 0700, 0755)
 * @param parents Create parent directories if true
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_FS: Failed to create directory (permission denied, etc.)
 * - ERR_FS: Failed to set permissions (not owner, etc.)
 * - ERR_INVALID_ARG: Invalid mode (> 0777)
 */
error_t *fs_create_dir_with_mode(const char *path, mode_t mode, bool parents);

/**
 * Create directory with specific mode and ownership (atomic, idempotent)
 *
 * Ensures a directory exists with exact permissions and ownership.
 * This function atomically sets ownership and mode using file descriptor
 * operations (fchown + fchmod), eliminating any security window where
 * the directory has incorrect attributes.
 *
 * Atomic sequence:
 * 1. Create directory with restrictive mode (0700) or open existing
 * 2. Open directory to obtain file descriptor
 * 3. fchown(fd, uid, gid) - atomic ownership change
 * 4. fchmod(fd, mode) - atomic permission change
 * 5. Close file descriptor
 *
 * Behavior:
 * - If directory doesn't exist: creates with atomic ownership + mode
 * - If directory exists: updates ownership + mode atomically
 * - Use uid=-1 or gid=-1 to skip ownership change
 * - Parent directories created with default ownership (0755)
 *
 * @param path Directory path (must not be NULL)
 * @param mode Permission mode for target directory (e.g., 0700, 0755)
 * @param uid Target UID for directory ownership (use -1 to preserve)
 * @param gid Target GID for directory ownership (use -1 to preserve)
 * @param parents Create parent directories if true
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_INVALID_ARG: Invalid mode (> 0777)
 * - ERR_FS: Failed to create directory
 * - ERR_FS: Failed to set ownership (not running as root)
 * - ERR_FS: Failed to set permissions
 */
error_t *fs_create_dir_with_ownership(
    const char *path,
    mode_t mode,
    uid_t uid,
    gid_t gid,
    bool parents
);

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
 * Check if directory is empty
 *
 * A directory is considered empty if it contains only "." and ".." entries.
 * Returns false if the directory cannot be opened (doesn't exist, not a directory,
 * permission denied, or read error) for safety (don't delete what we can't verify).
 *
 * @param path Directory path to check (can be NULL, treated as empty)
 * @return true if directory is empty and readable, false otherwise
 */
bool fs_is_directory_empty(const char *path);

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
 * Stat-based type checking helpers
 *
 * These helpers accept pre-captured stat data to avoid redundant syscalls.
 * Use these when you've already stat'd a file and need to check its type.
 */

/**
 * Check if stat represents a symlink
 *
 * @param st Stat data (must not be NULL)
 * @return true if S_ISLNK(st->st_mode)
 */
bool fs_stat_is_symlink(const struct stat *st);

/**
 * Check if stat represents a regular file
 *
 * @param st Stat data (must not be NULL)
 * @return true if S_ISREG(st->st_mode)
 */
bool fs_stat_is_regular(const struct stat *st);

/**
 * Check if stat represents a directory
 *
 * @param st Stat data (must not be NULL)
 * @return true if S_ISDIR(st->st_mode)
 */
bool fs_stat_is_directory(const struct stat *st);

/**
 * Check if stat represents an executable file
 *
 * @param st Stat data (must not be NULL)
 * @return true if owner execute bit is set (st->st_mode & S_IXUSR)
 */
bool fs_stat_is_executable(const struct stat *st);

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

/**
 * Fix ownership recursively for a directory tree
 *
 * Recursively changes ownership of all files and directories under path
 * to the specified UID/GID. This is used to restore normal user ownership
 * of repository files after operations that ran under sudo.
 *
 * Uses lchown() to handle symlinks safely (changes link ownership, not target).
 * Uses nftw() for efficient recursive traversal with minimal memory usage.
 *
 * Error Handling Philosophy:
 * - Individual file failures (e.g., permission denied): Continue, count as failed
 * - Fatal errors (path doesn't exist, nftw fails): Return error immediately
 * - This ensures we fix as many files as possible even if some fail
 *
 * Behavior:
 * - Traverses entire directory tree depth-first
 * - For each file/directory: checks current ownership, calls lchown() if different
 * - Tracks statistics: files successfully fixed, files that failed
 * - Continues processing even if individual files fail
 * - Safe to run multiple times (idempotent)
 *
 * Security:
 * - Only call this when running as root (effective UID 0)
 * - Uses lchown() to prevent symlink attacks
 * - Validates all inputs before traversal
 *
 * @param path Root path to fix (must not be NULL, must exist, must be a directory)
 * @param uid Target UID for ownership
 * @param gid Target GID for ownership
 * @param out_fixed Optional output: number of files/dirs successfully fixed (can be NULL)
 * @param out_failed Optional output: number of files/dirs that failed to fix (can be NULL)
 * @return Error for fatal failures, NULL on success (even if some individual files failed)
 */
error_t *fs_fix_ownership_recursive(
    const char *path,
    uid_t uid,
    gid_t gid,
    size_t *out_fixed,
    size_t *out_failed
);

#endif /* DOTTA_FILESYSTEM_H */
