/**
 * filesystem.h - Safe filesystem operations
 *
 * Provides filesystem operations with comprehensive error handling, input
 * validation, and resource management.
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
#include <types.h>

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
error_t *fs_read_file(const char *path, buffer_t *out);

/**
 * Write raw bytes to file (overwrites if exists)
 *
 * Creates parent directories if needed, with default attributes (0755, the running
 * user) — a caller that owns its ancestors' attributes (core/deploy) creates
 * them first and never reaches this path. This is a lower-level function for
 * writing data directly from memory without the buffer_t abstraction. Useful
 * for writing directly from git blobs or other external data sources.
 *
 * One strategy, no fallback: the content is written to a temp file in the target's
 * own directory and rename(2)d over it. So the permission the write needs is
 * write+search on the *parent*, never on the path — and an existing target is
 * replaced whole or not at all, whatever it is (a regular file, or the symlink
 * itself rather than what it points at). A caller that must predict whether the
 * write can land asks about the parent and nothing else; core/deploy's preflight
 * is built on exactly that. Directories are the one thing rename cannot replace:
 * clear them first.
 *
 * SECURITY: This function atomically sets permissions using fchmod() after creating
 * the file and setting ownership, ensuring there is no window where the file
 * has incorrect permissions (critical for sensitive files like SSH keys).
 *
 * @param path File path (must not be NULL)
 * @param data Raw data bytes (can be NULL if size is 0)
 * @param size Number of bytes to write
 * @param mode Permission mode (e.g., 0600, 0644, 0755)
 * @param uid Target UID for file ownership (use -1 to preserve current)
 * @param gid Target GID for file ownership (use -1 to preserve current)
 * @return Error or NULL on success
 */
error_t *fs_write_file_raw(
    const char *path,
    const unsigned char *data,
    size_t size,
    mode_t mode,
    uid_t uid,
    gid_t gid
);

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
 * Check if filename is OS metadata (should be ignored during cleanup)
 *
 * Detects OS-generated metadata files that are not user content and should be
 * transparent to dotta operations (especially directory empty checks).
 *
 * Recognized metadata files:
 * - macOS: .DS_Store, ._* (AppleDouble resource forks)
 * - Linux: .directory (KDE folder settings)
 * - Windows: Thumbs.db, desktop.ini, Desktop.ini
 *
 * @param filename Basename of file to check (e.g., ".DS_Store", not
 *                 "/path/.DS_Store")
 * @return true if filename matches known OS metadata pattern, false otherwise
 */
bool fs_is_os_metadata_file(const char *filename);

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
 * Ensures a directory exists with the exact specified permissions. This function
 * is idempotent - it can be safely called multiple times and will ensure the
 * directory has the correct permissions each time.
 *
 * Behavior:
 * - If directory doesn't exist: creates it with exact mode
 * - If directory already exists: updates its mode to match (useful with --force)
 * - Uses chmod() to enforce exact mode (not affected by umask)
 *
 * If parents is true, parent directories are created with default mode (0755),
 * while the target directory is ensured to have the specified mode.
 *
 * Consistency: Matches file behavior where fs_write_file_raw() always sets exact
 * permissions regardless of whether file exists.
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
 * Ensures a directory exists with exact permissions and ownership. This function
 * atomically sets ownership and mode using file descriptor operations (fchown +
 * fchmod), eliminating any security window where the directory has incorrect
 * attributes.
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
 * - The parent must exist: this primitive never invents attributes for ancestors
 *   — the caller decides those (core/deploy materializes them with tracked metadata
 *   or the target's ownership)
 *
 * @param path Directory path (must not be NULL)
 * @param mode Permission mode for target directory (e.g., 0700, 0755)
 * @param uid Target UID for directory ownership (use -1 to preserve)
 * @param gid Target GID for directory ownership (use -1 to preserve)
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
    gid_t gid
);

/**
 * Remove directory
 *
 * With `recursive`, this deletes the whole subtree — every path beneath `path`,
 * tracked or not. Callers that may only remove the directory itself want
 * fs_remove_empty_dir, which refuses rather than descends.
 *
 * @param path Directory path (must not be NULL)
 * @param recursive Remove contents recursively if true
 * @return Error or NULL on success
 */
error_t *fs_remove_dir(const char *path, bool recursive);

/**
 * Clear path for replacement (remove file, symlink, or directory)
 *
 * Removes whatever exists at the given path to prepare for deployment. Handles
 * all filesystem entity types:
 * - Regular files: removed via unlink()
 * - Symlinks: removed via unlink() (does NOT follow to target)
 * - Directories: removed via recursive rmdir
 *
 * @param path Path to clear (must not be NULL or empty)
 * @return Error or NULL on success
 */
error_t *fs_clear_path(const char *path);

/**
 * Check if path is a directory
 *
 * @param path Path to check (must not be NULL)
 * @return true if path exists and is a directory
 */
bool fs_is_directory(const char *path);

/**
 * Predicate over a directory entry's full path, with caller context
 */
typedef bool (*fs_path_pred_fn)(const char *path, void *ctx);

/**
 * Check if directory is empty once the entries the caller vouches for are gone
 *
 * fs_is_directory_empty with a hole: an entry is looked past when it is OS metadata
 * — exactly what fs_remove_empty_dir clears — or when `gone`, handed the entry's
 * full path, answers true. That lets a caller who is about to remove things beneath
 * a directory ask whether the directory will then be empty, without mutating
 * anything and without a second walk of its own. With gone == NULL this is
 * fs_is_directory_empty.
 *
 * One walk, so a prediction and the removal that follows it cannot mean different
 * things by "empty".
 *
 * Returns false if the directory cannot be opened or read — don't promise a removal
 * you cannot verify. An entry whose path cannot be built counts as present, for
 * the same reason.
 *
 * @param path Directory path to check (can be NULL, treated as empty)
 * @param gone Predicate answering "this caller removes that entry" (may be NULL)
 * @param ctx Opaque context handed to gone
 * @return true if the directory holds nothing but metadata and vouched-for entries
 */
bool fs_is_directory_empty_except(const char *path, fs_path_pred_fn gone, void *ctx);

/**
 * Check if directory is empty (ignoring OS metadata)
 *
 * A directory is considered empty if it contains only:
 * - "." and ".." entries (standard directory entries)
 * - OS metadata files (.DS_Store, ._*, Thumbs.db, etc.)
 *
 * Metadata is recognized by name AND by type: only a regular file is OS metadata.
 * A directory or a symlink wearing one of those names is a user object, and looking
 * past it would promise a removal fs_remove_empty_dir cannot deliver.
 *
 * Returns false if the directory cannot be opened (doesn't exist, not a directory,
 * permission denied, or read error) for safety (don't delete what we can't verify).
 *
 * The gone == NULL case of fs_is_directory_empty_except.
 *
 * @param path Directory path to check (can be NULL, treated as empty)
 * @return true if directory contains no user content, false otherwise
 */
bool fs_is_directory_empty(const char *path);

/**
 * Remove a directory that holds nothing but OS metadata
 *
 * The mechanical counterpart of fs_is_directory_empty, and deliberately its
 * neighbour: that predicate calls a directory empty when every entry is OS
 * metadata, so the removal that honours it must clear exactly those entries and
 * nothing else. rmdir(2) alone cannot — .DS_Store counts as an entry, and on
 * macOS that is every directory Finder has ever opened.
 *
 * Removes the OS-metadata entries, then the directory. Refuses with ERR_CONFLICT,
 * before removing anything, if any entry is one it may not remove — so a file
 * that appeared since an emptiness probe stops the removal instead of going with
 * it, and a refused directory keeps its metadata too. That is what makes this
 * safe to call on a prediction.
 *
 * Absence is success: a caller that must tell "removed" from "was never there"
 * probes presence first (cleanup's directory probe does).
 *
 * Never recurses. For a directory whose whole subtree is dotta's to delete, that
 * is fs_remove_dir(path, true).
 *
 * @param path Directory path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_remove_empty_dir(const char *path);

/**
 * List directory contents (excludes . and ..)
 *
 * @param path Directory path (must not be NULL)
 * @param out String array of filenames (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_list_dir(const char *path, string_array_t **out);

/**
 * Ensure parent directories exist
 *
 * Creates all parent directories for the given path if they don't exist. Similar
 * to `mkdir -p $(dirname path)`.
 *
 * @param path Full path to file/directory (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_ensure_parent_dirs(const char *path);

/**
 * Path operations
 */

/**
 * Make path absolute without resolving symlinks
 *
 * Unlike fs_canonicalize_path() which uses realpath() and resolves all symlinks,
 * this function makes a path absolute while preserving symlink locations.
 *
 * Converts relative paths to absolute by prepending current working directory.
 * A pure string operation: the path need not exist — a command that names a
 * file dotta manages but the disk no longer has (apply to redeploy it, remove,
 * revert, show) resolves it like any other. Callers that need the path to
 * exist check that themselves (add does, with lexists).
 *
 * This preserves symlink locations for storage path determination, preventing
 * accidental tracking of symlink targets at unintended locations.
 *
 * Examples:
 *   /home/user/mylink -> /home/user/mylink (even if mylink is a symlink)
 *   mylink            -> /current/dir/mylink
 *   relative/path     -> /current/dir/relative/path
 *
 * @param path Input path (must not be NULL, must not contain ~)
 * @param out Absolute path (caller frees, must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_make_absolute(const char *path, char **out);

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
 * Normalize path by resolving . and .. components (no filesystem access)
 *
 * This function performs pure string manipulation to resolve `.` and `..` path
 * components WITHOUT accessing the filesystem. Unlike fs_canonicalize_path()
 * which requires the path to exist, this function works on any path string.
 *
 * Use cases:
 * - Normalizing paths before prefix comparison (e.g., HOME detection)
 * - Processing user input that may not exist yet
 * - Resolving relative paths joined with CWD
 *
 * Behavior:
 * - Removes all `.` components (current directory references)
 * - Resolves `..` by removing the preceding component
 * - Preserves leading `/` for absolute paths
 * - Collapses multiple consecutive slashes to single slash
 * - `..` at root level is ignored (cannot go above root)
 *
 * Examples:
 *   /home/user/project/../file   -> /home/user/file
 *   /home/user/./config          -> /home/user/config
 *   /home/user/../../../etc      -> /etc
 *   ./foo/../bar                 -> bar
 *   foo/bar/../baz               -> foo/baz
 *
 * Limitations:
 * - Does NOT resolve symlinks (use fs_canonicalize_path for that)
 * - Does NOT validate path existence
 * - Does NOT handle tilde expansion (expand ~ before calling)
 *
 * @param path Path to normalize (must not be NULL)
 * @param out Normalized path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *fs_normalize_path(const char *path, char **out);

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
 * Get the invoking user's HOME directory.
 *
 * Single source of truth for "the actual user's home", sudo-aware so every
 * downstream consumer agrees regardless of how sudo configured $HOME. Resolution
 * order:
 *
 *   1. Under sudo (SUDO_UID set): getpwuid(SUDO_UID)->pw_dir. Bypasses `sudo
 *      -H` rewrites and varying env_keep policies.
 *   2. Not under sudo: $HOME from getenv(3). Honors the test isolation pattern
 *      (HOME=/tmp/dotta-test...).
 *   3. Last resort: passwd lookup of the effective uid.
 *
 * Returns ERR_FS only when no source yields a usable directory (no HOME env, no
 * passwd entry).
 *
 * @param out HOME directory path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *fs_get_home(char **out);

/**
 * Expand a leading tilde to $HOME.
 *
 * Examples:
 *   ~/.bashrc -> /home/user/.bashrc
 *   ~/foo/bar -> /home/user/foo/bar
 *   ~         -> /home/user          (so does ~/)
 *
 * Inputs without a leading '~' are duplicated verbatim. ~user/foo (other-user
 * expansion) is rejected.
 *
 * @param path Path with optional ~ prefix (must not be NULL)
 * @param out  Expanded path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *fs_expand_tilde(const char *path, char **out);

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
 * These helpers accept pre-captured stat data to avoid redundant syscalls. Use
 * these when you've already stat'd a file and need to check its type.
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
 * Fix ownership recursively for a directory tree
 *
 * Recursively changes ownership of all files and directories under path to the
 * specified UID/GID. This is used to restore normal user ownership of repository
 * files after operations that ran under sudo.
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
 * @param out_fixed Optional output: number of files/dirs successfully fixed (can
 *                  be NULL)
 * @param out_failed Optional output: number of files/dirs that failed to fix
 *                   (can be NULL)
 * @return Error for fatal failures, NULL on success (even if some individual
 *         files failed)
 */
error_t *fs_fix_ownership_recursive(
    const char *path,
    uid_t uid,
    gid_t gid,
    size_t *out_fixed,
    size_t *out_failed
);

#endif /* DOTTA_FILESYSTEM_H */
