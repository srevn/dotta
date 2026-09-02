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
 *
 * The funnel: every question core/, infra/ and cmds/ ask the kernel about a managed
 * path — what stands there, may it be opened, read, entered, written beneath —
 * is asked through this module, never through the raw call. What the run may do
 * to a path is answered in one place, and every reader inherits whatever that
 * answer becomes.
 *
 * The reach: a run that holds root for a user (sys/identity — `sudo dotta`, dropped
 * to the invoker at main()) takes it back one syscall at a time. Every kernel
 * call this module makes on a path is the invoker's first, and on a refusal —
 * EACCES, EPERM — the same call once more as root. So a path only root can reach
 * reads as present to a sudo'd run and as absent or refused to a plain one, and
 * what the second try creates is root's, as sudo would have made it; the claim's
 * fchown and the invoker's default (core/deploy) then say whose it becomes. Nothing
 * outside this module ever runs as root, and no second try spans a call into
 * libgit2, SQLite, the keymgr or a fork: it is one syscall wide, inside one
 * wrapper.
 *
 * The word: every error this module makes from a kernel refusal is
 * error_from_errno's — the site's prose, strerror's word, the errno's code — so
 * a reader acts on the code and never on the prose: ERR_PERMISSION is what the
 * hint tails of add and update read, ERR_NOT_FOUND what compare's absence rule
 * and the mount target's validation read. A site that tells two refusals apart
 * by errno before the error is made (ENOENT is "already gone" to a removal) keeps
 * doing so at the syscall; the error carries the rest.
 *
 * Dotta's own artifacts are the exception and keep their raw calls: the session
 * cache (crypto/session), the temp scripts (cmds/ignore, the bootstrap trio),
 * libgit2's and SQLite's files. Those paths are the invoker's by construction —
 * the drop is what makes them so under sudo — and a refusal on one is a broken
 * installation to report, not a question about reach. Three primitives serve
 * both worlds (fs_create_dir, fs_remove_dir, fs_write_file: a temp worktree's
 * directory, init's repository) and carry the reach with them; on the invoker's
 * own paths it never fires.
 */

#ifndef DOTTA_FILESYSTEM_H
#define DOTTA_FILESYSTEM_H

#include <dirent.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <types.h>
#include <unistd.h>

/**
 * The kernel's calls on managed paths
 *
 * The syscalls the funnel is made of — one wrapper per kind, syscall-shaped on
 * purpose: the return and errno are the kernel's, untouched — the second try's,
 * where the reach ran — so a caller's classification of a failure (ENOENT read
 * as absence, EACCES as a refusal) stays its own. The primitives below are built
 * on these and never on the raw call, so a reader that wants an error_t and a
 * reader that wants the errno make the same call at the same site. The five here
 * have outside readers; the write kinds (mkdir, unlink, rename, …) are the
 * primitives' own and stay inside the module.
 */

/**
 * lstat(2) — the node at the path, a link itself and never its target
 *
 * @param path Path (must not be NULL)
 * @param st Receives the stat (must not be NULL)
 * @return 0, or -1 with errno
 */
int fs_lstat(const char *path, struct stat *st);

/**
 * stat(2) — through a link to what it names
 *
 * @param path Path (must not be NULL)
 * @param st Receives the stat (must not be NULL)
 * @return 0, or -1 with errno
 */
int fs_stat(const char *path, struct stat *st);

/**
 * open(2)
 *
 * @param path Path (must not be NULL)
 * @param flags open(2) flags
 * @param mode Read iff flags carry O_CREAT; 0 otherwise
 * @return The descriptor, or -1 with errno
 */
int fs_open(const char *path, int flags, mode_t mode);

/**
 * opendir(3)
 *
 * @param path Directory path (must not be NULL)
 * @return The stream, or NULL with errno
 */
DIR *fs_opendir(const char *path);

/**
 * May the effective user do `amode` at the path?
 *
 * faccessat(2) with AT_EACCESS, with the reach: a run that holds root answers
 * as root would (a read-only filesystem or an immutable flag still refuses).
 * access(2) answers for the real user, which is the wrong one the moment the
 * two differ, and only the effective one lands a write. Knows what a mode test
 * does not: ownership, groups, ACLs, root. A directory's W_OK | X_OK is "may a
 * new entry be made in it" — the question every write beneath a path asks of
 * its nearest present ancestor (core/deploy).
 *
 * @param path Path (must not be NULL)
 * @param amode R_OK, W_OK, X_OK, or'd
 * @return true iff permitted
 */
bool fs_eaccess(const char *path, int amode);

/**
 * File operations
 */

/**
 * Read entire file into buffer
 *
 * Opens the path and delegates to fs_read_fd: follows symlinks (the fd's fstat
 * sees the resolved target), refuses non-regular files through the primitive's
 * own gate.
 *
 * @param path File path (must not be NULL)
 * @param out Output buffer (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_read_file(const char *path, buffer_t *out);

/**
 * Read a file descriptor to EOF into buffer
 *
 * The primitive beneath fs_read_file, for callers that must bind the bytes they
 * read to the descriptor they hold: an fd's fstat and its content are one inode
 * by construction, where a path-based re-open is a second look that can land on
 * a different file.
 *
 * Refuses descriptors that are not regular files — "the entire file" is defined
 * only for a file with an extent; a FIFO or device would drain without bound.
 * Reads from the descriptor's current offset to EOF; never closes it. Errors
 * carry no path (an fd has none): callers wrap with the name they opened.
 *
 * @param fd Readable file descriptor
 * @param out Output buffer (must not be NULL)
 * @return Error or NULL on success
 */
error_t *fs_read_fd(int fd, buffer_t *out);

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
 * @param out_st Optional (may be NULL): receives the fstat of the written
 *        descriptor, taken after the last mutation and before the rename that
 *        publishes it — it describes exactly the bytes and metadata this call
 *        wrote, never what a later look at the path would find (rename preserves
 *        inode, size and mtime). What a caller recording the write as its own
 *        act reads (core/deploy)
 * @return Error or NULL on success
 */
error_t *fs_write_file_raw(
    const char *path,
    const unsigned char *data,
    size_t size,
    mode_t mode,
    uid_t uid,
    gid_t gid,
    struct stat *out_st
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
 * - A directory this call made and could not attribute is unmade — the exclusive
 *   sibling's rule — so a refusal leaves the path as the call found it; one it
 *   opened stands as found, its attributes as they were
 * - The parent must exist: this primitive never invents attributes for ancestors
 *   — the caller decides those (core/deploy materializes them from their own
 *   claims, and invents nothing for the rest)
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
 * Create a directory that must not already exist (atomic, create-only)
 *
 * The create-only sibling of fs_create_dir_with_ownership: the same atomic
 * ownership + mode application through the directory's own descriptor, but an
 * existing path is ERR_EXISTS, never opened and converged. mkdir(2) itself is
 * the exclusivity — O_EXCL semantics, with no window in which whatever now stands
 * at the path could be re-attributed.
 *
 * For the caller whose authority is creation alone: core/deploy's ancestors pass
 * creates the absent chain above a planned path, and a path the world made present
 * between its probe and the mkdir is not that run's to converge — the refusal
 * is the row's outcome (deploy.h), where the idempotent sibling would have silently
 * chmod'd and chown'd what it met.
 *
 * Atomic sequence:
 * 1. mkdir() with restrictive mode (0700) — EEXIST is the refusal
 * 2. Open the new directory (O_NOFOLLOW) to obtain the descriptor
 * 3. fchown(fd, uid, gid) - atomic ownership change
 * 4. fchmod(fd, mode) - atomic permission change
 * 5. Close file descriptor
 *
 * All or nothing: a refusal at step 3 or 4 removes the directory step 1 made,
 * so a pair the run cannot set (a foreign-owned claim, no root held) leaves the
 * path absent for the run that can, never a directory of the wrong owner that
 * no later run converges. The parent must exist, as for the sibling.
 *
 * @param path Directory path (must not be NULL)
 * @param mode Permission mode for the directory (e.g., 0700, 0755)
 * @param uid Target UID for directory ownership (use -1 to leave as created)
 * @param gid Target GID for directory ownership (use -1 to leave as created)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_INVALID_ARG: Invalid mode (> 0777)
 * - ERR_EXISTS: Something already stands at the path
 * - ERR_FS: Failed to create, open or attribute the directory
 */
error_t *fs_create_dir_exclusive(
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
 * What a directory holds, once OS metadata and vouched-for entries are looked past
 *
 * Three answers, because "not empty" and "cannot tell" are different facts: a
 * caller that removes what it has verified empty treats the two alike, but a
 * caller that reports on the directory must not call one the other.
 */
typedef enum {
    FS_DIR_EMPTY,        /* nothing but OS metadata and vouched-for entries */
    FS_DIR_OCCUPIED,     /* an entry nobody vouched for — the walk stopped at it */
    FS_DIR_UNREADABLE    /* opendir or readdir failed; nothing can be said */
} fs_emptiness_t;

/**
 * Is the directory empty once the entries the caller vouches for are looked past?
 *
 * An entry is looked past when it is OS metadata — exactly what fs_remove_empty_dir
 * clears — or when `vouch`, handed the entry's full path, answers true: the caller
 * is about to remove it, or has decided it does not count. That lets a caller
 * who is about to remove things beneath a directory ask whether the directory
 * will then be empty, without mutating anything and without a second walk of
 * its own. With vouch == NULL only metadata is looked past.
 *
 * One walk, so a prediction and the removal that follows it cannot mean different
 * things by "empty". The walk stops at the first entry nobody vouches for, so
 * the predicate is not asked about every entry.
 *
 * UNREADABLE when the directory cannot be opened or read (absent, not a directory,
 * permission denied, an I/O error) and for a NULL path. An entry whose path cannot
 * be built is OCCUPIED — don't promise a removal you cannot verify.
 *
 * @param path Directory path to check (NULL reads UNREADABLE)
 * @param vouch Predicate answering "look past that entry" (may be NULL)
 * @param ctx Opaque context handed to vouch
 * @return What the directory holds
 */
fs_emptiness_t fs_directory_emptiness(const char *path, fs_path_pred_fn vouch, void *ctx);

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
 * permission denied, or read error) for safety (don't delete what we can't verify):
 * the FS_DIR_EMPTY reading of fs_directory_emptiness with no predicate, for the
 * callers that treat "occupied" and "cannot tell" alike.
 *
 * @param path Directory path to check (must not be NULL)
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
 * probes presence first (cleanup_execute does, with fs_lstat_occupant).
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
 * A pure string operation: the path need not exist — a command that names a file
 * dotta manages but the disk no longer has (apply to redeploy it, remove, revert,
 * show) resolves it like any other. Callers that need the path to exist check
 * that themselves (add does, with lexists).
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
 * Path must exist: a path that does not (ENOENT, or ENOTDIR — a component above
 * it is not a directory) is ERR_NOT_FOUND; any other failure carries its errno's
 * code (error_code_from_errno).
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
 * Expand a leading tilde to the invoker's home (sys/identity).
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
 * With its ownership: a link carries no mode (symlink(2) takes none, and most
 * filesystems ignore one) but it has an owner, and that matters for auditing
 * and consistency. The link is the one node without a descriptor to fchown, so
 * the path-based call lives here, inside the primitive — lchown, which changes
 * the link itself and never its target. -1 for either half leaves it as created.
 *
 * @param target Link target (must not be NULL)
 * @param linkpath Link path (must not be NULL)
 * @param uid Owner to set on the link, or (uid_t) -1 to leave it
 * @param gid Group to set on the link, or (gid_t) -1 to leave it
 * @return Error or NULL on success
 */
error_t *fs_create_symlink(
    const char *target,
    const char *linkpath,
    uid_t uid,
    gid_t gid
);

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
 * The running user's own question, not a managed path's: a hook is executable
 * iff the user who will run it may execute it, so this asks for the effective
 * user (faccessat, AT_EACCESS) and nothing more.
 *
 * @param path File path (must not be NULL)
 * @return true if the effective user may execute the file
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
 * What occupies a path, from one lstat
 *
 * The link itself, never its target: a symlink is a distinct occupant, not the
 * thing it points to. Every reader that removes or replaces a path acts on the
 * node at the path, so the target's type and permissions are none of its business.
 *
 * Two failures are absence: ENOENT, and ENOTDIR — a component above the path is
 * not a directory, so nothing can be at the path either. Any other failure (EACCES,
 * ELOOP, EIO, …) is UNKNOWN: something may well be there, and a reader must never
 * infer absence from a failure to look.
 */
typedef enum {
    FS_OCCUPANT_NONE,        /* absent, or beneath a non-directory */
    FS_OCCUPANT_REGULAR,
    FS_OCCUPANT_SYMLINK,     /* the link itself, never its target */
    FS_OCCUPANT_DIRECTORY,
    FS_OCCUPANT_OTHER,       /* fifo, socket, device */
    FS_OCCUPANT_UNKNOWN      /* unstattable for a reason other than absence */
} fs_occupant_t;

/**
 * lstat a path and name what it found
 *
 * On FS_OCCUPANT_UNKNOWN, errno is lstat's — read it before anything else runs.
 * *st is meaningful only for a present occupant; a caller that wants the type
 * alone passes NULL.
 *
 * @param path Path to probe (must not be NULL)
 * @param st Receives the lstat of a present occupant (may be NULL)
 * @return What stands at the path
 */
fs_occupant_t fs_lstat_occupant(const char *path, struct stat *st);

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

#endif /* DOTTA_FILESYSTEM_H */
