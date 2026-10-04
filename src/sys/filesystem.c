/**
 * filesystem.c - Safe filesystem operations implementation
 */

#include "sys/filesystem.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/string.h"
#include "sys/identity.h"

/* Buffer size for file I/O */
#define IO_BUFFER_SIZE 8192

/* Maximum file size for fs_read_file (256 MB) */
#define FS_MAX_READ_SIZE ((size_t) 256 * 1024 * 1024)

/* A write's temp file, beside its target: the target's directory, then this —
 * mkstemp's template, whose six Xs fs_mkstemp reads */
#define FS_TMP_SUFFIX "/.dotta-tmp-XXXXXX"

/**
 * The kernel's calls on managed paths
 *
 * One site per syscall kind: the module's own primitives and every outside reader
 * make the same call here (filesystem.h's funnel), and the reach lives here and
 * nowhere else — the invoker's call, and on a refusal the same call once more
 * as root when the run holds it (sys/identity). Each wrapper is the whole of
 * one raise: the second call is the raw syscall, so no raise ever nests, spans
 * another wrapper, or outlives the return. The six with outside readers are
 * filesystem.h's; the write kinds are static until one appears.
 */
int fs_lstat(const char *path, struct stat *st) {
    int rc = lstat(path, st);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = lstat(path, st);
        identity_lower();
    }
    return rc;
}

int fs_stat(const char *path, struct stat *st) {
    int rc = stat(path, st);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = stat(path, st);
        identity_lower();
    }
    return rc;
}

int fs_open(const char *path, int flags, mode_t mode) {
    int fd = open(path, flags, mode);
    if (fd < 0 && identity_raise_on_refusal(errno)) {
        fd = open(path, flags, mode);
        identity_lower();
    }
    return fd;
}

DIR *fs_opendir(const char *path) {
    DIR *dir = opendir(path);
    if (!dir && identity_raise_on_refusal(errno)) {
        dir = opendir(path);
        identity_lower();
    }
    return dir;
}

int fs_eaccess(const char *path, int amode) {
    int rc = faccessat(AT_FDCWD, path, amode, AT_EACCESS);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = faccessat(AT_FDCWD, path, amode, AT_EACCESS);
        identity_lower();
    }
    return rc;
}

static int fs_mkdir(const char *path, mode_t mode) {
    int rc = mkdir(path, mode);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = mkdir(path, mode);
        identity_lower();
    }
    return rc;
}

static int fs_rmdir(const char *path) {
    int rc = rmdir(path);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = rmdir(path);
        identity_lower();
    }
    return rc;
}

static int fs_unlink(const char *path) {
    int rc = unlink(path);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = unlink(path);
        identity_lower();
    }
    return rc;
}

static int fs_rename(const char *from, const char *to) {
    int rc = rename(from, to);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = rename(from, to);
        identity_lower();
    }
    return rc;
}

static int fs_symlink(const char *target, const char *linkpath) {
    int rc = symlink(target, linkpath);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = symlink(target, linkpath);
        identity_lower();
    }
    return rc;
}

static ssize_t fs_readlink(const char *path, char *buf, size_t size) {
    ssize_t len = readlink(path, buf, size);
    if (len < 0 && identity_raise_on_refusal(errno)) {
        len = readlink(path, buf, size);
        identity_lower();
    }
    return len;
}

static int fs_chmod(const char *path, mode_t mode) {
    int rc = chmod(path, mode);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = chmod(path, mode);
        identity_lower();
    }
    return rc;
}

static int fs_fchmod(int fd, mode_t mode) {
    int rc = fchmod(fd, mode);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = fchmod(fd, mode);
        identity_lower();
    }
    return rc;
}

static int fs_fchown(int fd, uid_t uid, gid_t gid) {
    int rc = fchown(fd, uid, gid);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = fchown(fd, uid, gid);
        identity_lower();
    }
    return rc;
}

static int fs_lchown(const char *path, uid_t uid, gid_t gid) {
    int rc = lchown(path, uid, gid);
    if (rc < 0 && identity_raise_on_refusal(errno)) {
        rc = lchown(path, uid, gid);
        identity_lower();
    }
    return rc;
}

/* The template ends in exactly six Xs — mkstemp's own requirement, and what the
 * arithmetic below reads. A failed mkstemp leaves its last candidate where the
 * Xs were, and glibc refuses a template without them: the second try gets its
 * six back. */
static int fs_mkstemp(char *tmpl) {
    int fd = mkstemp(tmpl);
    if (fd < 0 && identity_raise_on_refusal(errno)) {
        memset(tmpl + strlen(tmpl) - 6, 'X', 6);
        fd = mkstemp(tmpl);
        identity_lower();
    }
    return fd;
}

char *fs_realpath(const char *path, char *resolved) {
    char *out = realpath(path, resolved);
    if (!out && identity_raise_on_refusal(errno)) {
        out = realpath(path, resolved);
        identity_lower();
    }
    return out;
}

/**
 * Check if filename is OS metadata
 *
 * Detects OS-generated metadata files that should be transparent to dotta. These
 * files are created automatically by operating systems and do not represent user
 * content.
 *
 * - Takes basename only (not full path) for simplicity and efficiency
 * - Uses exact string matching for safety (no regex overhead or complexity)
 * - Ordered by frequency: most common zombies checked first
 * - AppleDouble pattern (._*) requires special handling
 */
bool fs_is_os_metadata_file(const char *filename) {
    /* Input validation */
    if (!filename || filename[0] == '\0') {
        return false;
    }

    /* macOS Finder metadata - by far the most common zombie */
    if (strcmp(filename, ".DS_Store") == 0) {
        return true;
    }

    /* Linux KDE folder settings - common on KDE systems */
    if (strcmp(filename, ".directory") == 0) {
        return true;
    }

    /* Windows metadata - dual-boot or network access scenarios */
    if (strcmp(filename, "Thumbs.db") == 0) {
        return true;
    }
    if (strcmp(filename, "desktop.ini") == 0) {
        return true;
    }
    if (strcmp(filename, "Desktop.ini") == 0) {
        return true;
    }

    /* Pattern match: AppleDouble resource fork files (._*)
     *
     * Safety check: Require at least one character after ._ to avoid matching
     * malformed filenames like "._" (edge case but defensive).
     */
    if (filename[0] == '.' && filename[1] == '_' && filename[2] != '\0') {
        return true;
    }

    return false;
}

/**
 * File operations
 */
error_t fs_read_fd(int fd, buffer_t *out) {
    CHECK_NULL(out);

    *out = (buffer_t){ 0 };

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        return error_errno(errno, "Failed to stat");
    }

    /* "The entire file" is defined only for a regular file: a FIFO or device
     * has no extent — st_size tells the size guard below nothing and the loop
     * would drain without bound. */
    if (!S_ISREG(st.st_mode)) {
        return error_create(ERR_FS, "Not a regular file");
    }

    /* Guard against unreasonably large files. st_size is signed (off_t); reject
     * negatives (pathological) before the unsigned comparison so we never widen
     * a negative into a huge size_t. */
    if (st.st_size < 0 || (size_t) st.st_size > FS_MAX_READ_SIZE) {
        return error_create(
            ERR_FS, "File too large (%lld bytes, max %zu)",
            (long long) st.st_size, (size_t) FS_MAX_READ_SIZE
        );
    }

    /* Pre-size to the extent fstat reported, exactly: the chunked appends below
     * then land on the last byte of the reservation and never reallocate. A file
     * that grew between the stat and the read overruns it and falls back to the
     * append path's geometric growth, which is the case the reserve cannot answer.
     * st_size of 0 is a regular file that will not say how long it is; one chunk
     * is the guess, and the appends take it from there. */
    buffer_reserve(out, st.st_size > 0 ? (size_t) st.st_size : IO_BUFFER_SIZE);

    /* Read in chunks from the descriptor's current offset */
    char chunk[IO_BUFFER_SIZE];
    ssize_t bytes_read;

    for (;;) {
        bytes_read = read(fd, chunk, sizeof(chunk));

        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted by signal, retry */
            }
            int saved_errno = errno;
            buffer_deinit(out);
            return error_errno(saved_errno, "Read error");
        }

        if (bytes_read == 0) {
            break;  /* EOF */
        }

        buffer_append(out, chunk, (size_t) bytes_read);
    }

    return NULL;
}

error_t fs_write_fd(int fd, const char *path, const void *data, size_t size) {
    CHECK_NULL(path);
    CHECK_ARG(data != NULL || size == 0, "data cannot be NULL with a size");

    /* Until every byte is down: a short write resumes past what it wrote, and a
     * write a signal interrupted before it wrote anything is asked again */
    const unsigned char *bytes = data;
    size_t written = 0;
    while (written < size) {
        ssize_t n = write(fd, bytes + written, size - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            return error_errno(errno, "Cannot write '%s'", path);
        }
        written += (size_t) n;
    }

    return NULL;
}

error_t fs_read_file(const char *path, buffer_t *out) {
    CHECK_NULL(path);
    CHECK_NULL(out);

    /* fs_read_fd clears this too, but an open that fails never reaches it. */
    *out = (buffer_t){ 0 };

    /* O_NONBLOCK keeps a FIFO with no writer from wedging the open, harmless
     * for a regular file — fs_read_fd then refuses what is not one — and O_CLOEXEC
     * is hygiene, as a managed path's read opens (infra/compare.c,
     * infra/content.c) */
    int fd = fs_open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0) {
        return error_errno(errno, "Failed to open '%s'", path);
    }

    error_t err = fs_read_fd(fd, out);
    close(fd);
    if (err) {
        return error_wrap(err, "Failed to read '%s'", path);
    }

    return NULL;
}

/**
 * Helper: Apply metadata, write data, sync, and close a file descriptor
 *
 * The core write sequence of fs_write_file_raw's temp file. Ownership and
 * permissions are set via fd-based operations (fchown/fchmod) BEFORE any data
 * is written, preserving the security invariant that sensitive content is never
 * exposed with wrong metadata.
 *
 * The fd is always closed on return (both success and error).
 *
 * @param fd Open file descriptor (ownership transferred, always closed)
 * @param path Target path (for error messages only, not accessed)
 * @param data Raw data bytes (can be NULL if size is 0)
 * @param size Number of bytes to write
 * @param mode Permission mode
 * @param uid Target UID (-1 to skip)
 * @param gid Target GID (-1 to skip)
 * @param out_st Optional: the descriptor's fstat after the last mutation
 * @return Error or NULL on success
 */
static error_t write_and_close_fd(
    int fd,
    const char *path,
    const unsigned char *data,
    size_t size,
    mode_t mode,
    uid_t uid,
    gid_t gid,
    struct stat *out_st
) {
    /* SECURITY CRITICAL: Apply ownership BEFORE writing data
     *
     * This ensures that if the file contains sensitive data (e.g., SSH keys,
     * API tokens, passwords), it has the correct owner from the moment data is
     * written, preventing unauthorized access.
     *
     * Use -1 to skip ownership change (preserve current user ownership).
     */
    if (uid != (uid_t) -1 || gid != (gid_t) -1) {
        if (fs_fchown(fd, uid, gid) < 0) {
            int saved_errno = errno;
            close(fd);
            return error_errno(
                saved_errno, "Failed to set ownership on '%s'", path
            );
        }
    }

    /* SECURITY CRITICAL: Set exact permissions BEFORE writing data
     *
     * At this point, the file has correct ownership and is about to receive correct
     * permissions. It's still empty, so even if the process crashes here, no
     * sensitive data has been exposed.
     *
     * Using fchmod() on the file descriptor (not chmod() on path) ensures:
     * 1. Atomicity: No TOCTOU race with file replacement
     * 2. Not affected by umask: Exact mode is applied
     * 3. Works even if file was just created
     */
    if (fs_fchmod(fd, mode) < 0) {
        int saved_errno = errno;
        close(fd);
        return error_errno(
            saved_errno, "Failed to set permissions on '%s'", path
        );
    }

    /* Write data - SAFE: File now has correct ownership + permissions
     *
     * At this point:
     * - File is owned by the correct user (if uid != -1)
     * - File has exact permissions requested (mode)
     * - File is still empty (no data exposure risk)
     *
     * Now it's safe to write sensitive data. If the process crashes during write,
     * we have an incomplete file with correct metadata (acceptable).
     */
    error_t err = fs_write_fd(fd, path, data, size);
    if (err) {
        close(fd);
        return err;
    }

    /* Sync to disk */
    if (fsync(fd) < 0) {
        int saved_errno = errno;
        close(fd);
        return error_errno(saved_errno, "Failed to sync '%s'", path);
    }

    /* The descriptor's own stat, after the last mutation that shapes it: the
     * caller reads the truth of what THIS write produced, not of whatever a later
     * look at the path would find. */
    if (out_st && fstat(fd, out_st) < 0) {
        int saved_errno = errno;
        close(fd);
        return error_errno(
            saved_errno, "Failed to stat written '%s'", path
        );
    }

    close(fd);
    return NULL;
}

error_t fs_write_file_raw(
    const char *path,
    const unsigned char *data,
    size_t size,
    mode_t mode,
    uid_t uid,
    gid_t gid,
    struct stat *out_st
) {
    CHECK_NULL(path);
    CHECK_ARG(data != NULL || size == 0, "data cannot be NULL with a size");

    /* Ensure parent directory exists */
    char *parent = fs_parent_dir(path);
    error_t err = fs_exists(parent) ? NULL : fs_create_dir(parent, true);
    if (err) {
        free(parent);
        return error_wrap(err, "Failed to create parent directory for '%s'", path);
    }

    /* Build temp file path in the target's own directory. Two names in one
     * directory are necessarily on one filesystem, so the rename below can never
     * fail with EXDEV — there is no cross-device case to fall back from, and no
     * second write strategy at all. The name spells the parent whole before its
     * suffix, so the parent goes here, and the refusal below reads it there. */
    char tmp_path[PATH_MAX];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s" FS_TMP_SUFFIX, parent);
    free(parent);
    if (n < 0 || (size_t) n >= sizeof(tmp_path)) {
        return error_create(ERR_FS, "Path too long for atomic write of '%s'", path);
    }

    /* Create temp file with restrictive 0600 mode (mkstemp guarantee).
     *
     * A failure here is the directory refusing a new entry, and it is final:
     * the alternative — opening the target itself with O_TRUNC — destroys the
     * file before a single byte of the replacement is written, and does so for
     * every mkstemp errno, ENOSPC included. A write that cannot be atomic is
     * reported, not attempted. */
    int fd = fs_mkstemp(tmp_path);
    if (fd < 0) {
        return error_errno(
            errno, "Failed to create a temporary file in '%.*s' for '%s'",
            n - (int) (sizeof(FS_TMP_SUFFIX) - 1), tmp_path, path
        );
    }

    /* Write data to temp file with correct ownership and permissions.
     * SECURITY: All metadata is applied via fd operations before data is written.
     * If anything fails, the original file is untouched. */
    err = write_and_close_fd(fd, path, data, size, mode, uid, gid, out_st);
    if (err) {
        fs_unlink(tmp_path);
        return err;
    }

    /* Atomic replace: rename temp over target. POSIX guarantees this is atomic
     * on the same filesystem — at no point does the target path contain partial
     * content. */
    if (fs_rename(tmp_path, path) < 0) {
        int saved_errno = errno;
        fs_unlink(tmp_path);

        return error_errno(saved_errno, "Failed to replace '%s'", path);
    }

    return NULL;
}

error_t fs_write_file(const char *path, const buffer_t *content) {
    CHECK_NULL(path);
    CHECK_NULL(content);

    return fs_write_file_raw(
        path,
        (const unsigned char *) content->data,
        content->size,
        0644,
        -1,
        -1,
        NULL
    );
}

error_t fs_copy_file(const char *src, const char *dst) {
    CHECK_NULL(src);
    CHECK_NULL(dst);

    /* Get source permissions: the first look at the source, so one that is not
     * there, or not the invoker's to read, is refused here in the kernel's words */
    mode_t mode;
    error_t err = fs_get_permissions(src, &mode);
    if (err) return err;

    /* Read source */
    buffer_t content = BUFFER_INIT;
    err = fs_read_file(src, &content);
    if (err) {
        return error_wrap(err, "Failed to copy '%s' to '%s'", src, dst);
    }

    /* Write destination with source permissions atomically
     * SECURITY: Use fs_write_file_raw() to set permissions atomically via fchmod(),
     * eliminating the security window where sensitive files (e.g., SSH keys)
     * would have incorrect permissions (0644 instead of 0600). */
    err = fs_write_file_raw(
        dst, (const unsigned char *) content.data, content.size, mode, -1, -1, NULL
    );
    buffer_deinit(&content);
    if (err) {
        return error_wrap(err, "Failed to copy '%s' to '%s'", src, dst);
    }

    return NULL;
}

error_t fs_remove_file(const char *path) {
    CHECK_NULL(path);

    if (fs_unlink(path) < 0) {
        if (errno == ENOENT) {
            return NULL;  /* Not an error if file doesn't exist */
        }
        return error_errno(errno, "Failed to remove '%s'", path);
    }

    return NULL;
}

bool fs_file_exists(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    struct stat st;
    if (fs_stat(path, &st) < 0) {
        return false;
    }

    return S_ISREG(st.st_mode);
}

/**
 * Directory operations
 */
error_t fs_create_dir(const char *path, bool parents) {
    CHECK_NULL(path);

    /* Already exists? */
    if (fs_is_directory(path)) {
        return NULL;
    }

    if (parents) {
        /* Create parent first */
        char *parent = fs_parent_dir(path);
        error_t err = fs_is_directory(parent) ? NULL : fs_create_dir(parent, true);
        free(parent);
        if (err) return err;
    }

    /* Create directory */
    if (fs_mkdir(path, 0755) < 0) {
        if (errno == EEXIST && fs_is_directory(path)) {
            return NULL;  /* Race condition - another process created it */
        }
        return error_errno(errno, "Failed to create directory '%s'", path);
    }

    return NULL;
}

error_t fs_create_dir_with_mode(const char *path, mode_t mode, bool parents) {
    CHECK_NULL(path);

    /* A mode is at most 0777 by every producer's rule (the sheet's parse, the
     * factories, a stat's permission bits): a caller that hands more is broken. */
    CHECK_ARG(mode <= 0777, "a mode past 0777");

    bool existed = fs_is_directory(path);

    if (!existed) {
        /* Create parent directories if requested, at the default 0755 */
        if (parents) {
            char *parent = fs_parent_dir(path);
            error_t err = fs_is_directory(parent) ? NULL : fs_create_dir(parent, true);
            free(parent);
            if (err) return err;
        }

        /* Try to create directory with specified mode */
        if (fs_mkdir(path, mode) < 0) {
            if (errno == EEXIST && fs_is_directory(path)) {
                existed = true;
            } else {
                return error_errno(
                    errno, "Failed to create directory '%s' with mode %04o",
                    path, mode
                );
            }
        }
    }

    /* Ensure exact permissions with chmod() (idempotent operation)
     *
     * Why chmod() is needed in BOTH cases:
     *
     * 1. New directory: mkdir() mode is affected by umask Example: mkdir(path,
     *    0700) with umask 022 creates 0755 chmod() enforces exact mode regardless
     *    of umask
     *
     * 2. Existing directory: May have wrong permissions Example: User runs `dotta
     *    apply --force` to fix ~/.ssh/ from 0755 to 0700 chmod() updates mode
     *    to match metadata (security fix!)
     *
     * This makes the function idempotent: "ensure directory exists with exact
     * mode" Matches file behavior (fs_write_file_raw always sets exact mode)
     */
    if (fs_chmod(path, mode) < 0) {
        return error_errno(
            errno, "Failed to set permissions on directory '%s'%s",
            path, existed ? " (already existed)" : ""
        );
    }

    return NULL;
}

error_t fs_create_dir_with_ownership(
    const char *path,
    mode_t mode,
    uid_t uid,
    gid_t gid
) {
    CHECK_NULL(path);

    /* A mode is at most 0777 by every producer's rule (the sheet's parse, the
     * factories, a stat's permission bits): a caller that hands more is broken. */
    CHECK_ARG(mode <= 0777, "a mode past 0777");

    /* Whether the directory below is this call's own making: one it made and
     * cannot attribute is unmade, one it opened stands as found. */
    bool created = false;

    /* Try to open existing directory first (eliminates TOCTOU race)
     * SECURITY: This open-first pattern prevents race conditions where a directory
     * is checked, then deleted/replaced before we operate on it. By attempting
     * to open first, we either get a valid fd or a clear error. O_NOFOLLOW prevents
     * symlink substitution attacks - if an attacker replaces the directory with
     * a symlink, open() fails with ELOOP instead of following. */
    int dirfd = fs_open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
    if (dirfd >= 0) {
        /* Directory exists - update ownership and mode atomically */
        goto apply_metadata;
    }

    /* Directory doesn't exist - verify it's actually missing */
    if (errno != ENOENT && errno != ENOTDIR) {
        /* Unexpected error (permission denied, etc.) */
        return error_errno(errno, "Failed to open directory '%s'", path);
    }

    /* Create directory with restrictive initial mode for security
     * SECURITY: Start with 0700 to prevent unauthorized access during setup,
     * then atomically set final mode via fchmod() on the file descriptor. */
    if (fs_mkdir(path, 0700) < 0) {
        if (errno == EEXIST) {
            /* Race condition: directory created concurrently, open it directly */
            dirfd = fs_open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
            if (dirfd < 0) {
                return error_errno(
                    errno, "Directory '%s' created but cannot open", path
                );
            }
            goto apply_metadata;
        }
        return error_errno(errno, "Failed to create directory '%s'", path);
    }
    created = true;

    /* Open newly created directory for atomic operations
     * SECURITY: O_NOFOLLOW closes the TOCTOU window - if an attacker replaced
     * the directory with a symlink between mkdir() and open(), this fails safely
     * with ELOOP instead of applying ownership to the symlink target. */
    dirfd = fs_open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
    if (dirfd < 0) {
        return error_errno(
            errno, "Failed to open newly created directory '%s'", path
        );
    }

apply_metadata:
    /* Apply ownership atomically via file descriptor
     * SECURITY: Using fchown() on the file descriptor ensures atomicity. The
     * ownership is applied to the directory we have open, not to whatever might
     * be at 'path' if a race condition occurred.
     *
     * A refusal here or at the mode below unmakes a directory this call made
     * (fs_create_dir_exclusive's rule: what it could not create as claimed it
     * did not create, and the next run meets the same absent path rather than a
     * directory of the wrong owner that no later run converges — empty by
     * construction, so the rmdir cannot fail on content). One it opened stands
     * as it was found, save the owner a landed fchown gave it before the mode
     * refused. */
    if (uid != (uid_t) -1 || gid != (gid_t) -1) {
        if (fs_fchown(dirfd, uid, gid) < 0) {
            int saved_errno = errno;
            close(dirfd);
            if (created) (void) fs_rmdir(path);
            return error_errno(
                saved_errno, "Failed to set ownership on '%s'", path
            );
        }
    }

    /* Apply final mode atomically via file descriptor
     * SECURITY: fchmod() ensures the mode is set on the directory we have open.
     * This is the final step - after this completes, the directory has the exact
     * ownership and permissions requested, with no security windows. */
    if (fs_fchmod(dirfd, mode) < 0) {
        int saved_errno = errno;
        close(dirfd);
        if (created) (void) fs_rmdir(path);
        return error_errno(
            saved_errno, "Failed to set mode on '%s'", path
        );
    }

    close(dirfd);
    return NULL;
}

error_t fs_create_dir_exclusive(
    const char *path,
    mode_t mode,
    uid_t uid,
    gid_t gid
) {
    CHECK_NULL(path);

    /* A mode is at most 0777 by every producer's rule (the sheet's parse, the
     * factories, a stat's permission bits): a caller that hands more is broken. */
    CHECK_ARG(mode <= 0777, "a mode past 0777");

    /* mkdir(2) is the exclusivity: it creates or it refuses, atomically — there
     * is no open-existing arm, which is the whole difference from
     * fs_create_dir_with_ownership. The restrictive initial mode closes the setup
     * window; the final attributes apply through the descriptor below. */
    if (fs_mkdir(path, 0700) < 0) {
        if (errno == EEXIST) {
            return error_create(
                ERR_EXISTS, "Path '%s' already exists",
                path
            );
        }
        return error_errno(errno, "Failed to create directory '%s'", path);
    }

    /* SECURITY: O_NOFOLLOW closes the TOCTOU window — if an attacker replaced
     * the directory with a symlink between mkdir() and open(), this fails safely
     * with ELOOP instead of applying attributes to the symlink target. */
    int dirfd = fs_open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
    if (dirfd < 0) {
        return error_errno(
            errno, "Failed to open newly created directory '%s'", path
        );
    }

    /* Apply ownership atomically via file descriptor. A refusal here or at the
     * mode below unmakes the directory: this caller's authority is creation alone,
     * and what it could not create as claimed it did not create — the next run
     * meets the same absent path, and the same refusal until it holds what the
     * claim needs, rather than a directory of the wrong owner that no later run
     * converges (an ancestor claim binds the creation and nothing else). Empty
     * by construction, so the rmdir cannot fail on content. */
    if (uid != (uid_t) -1 || gid != (gid_t) -1) {
        if (fs_fchown(dirfd, uid, gid) < 0) {
            int saved_errno = errno;
            close(dirfd);
            (void) fs_rmdir(path);
            return error_errno(
                saved_errno, "Failed to set ownership on '%s'", path
            );
        }
    }

    /* Apply final mode atomically via file descriptor */
    if (fs_fchmod(dirfd, mode) < 0) {
        int saved_errno = errno;
        close(dirfd);
        (void) fs_rmdir(path);
        return error_errno(
            saved_errno, "Failed to set mode on '%s'", path
        );
    }

    close(dirfd);
    return NULL;
}

error_t fs_set_dir_mode(const char *path, mode_t mode) {
    CHECK_NULL(path);

    /* A mode is at most 0777 by every producer's rule (the sheet's parse, the
     * factories, a stat's permission bits): a caller that hands more is broken. */
    CHECK_ARG(mode <= 0777, "a mode past 0777");

    /* The directory that stands, or none: a link at the path is refused, never
     * followed. ENOENT and ENOTDIR are no directory to set — the absence rule —
     * and anything else is a directory this call could not reach. */
    int dirfd = fs_open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
    if (dirfd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) return NULL;
        return error_errno(errno, "Failed to open directory '%s'", path);
    }

    /* The mode lands on the node opened, whatever the path names by now; the
     * refusal is worded before the close can move errno */
    error_t err = fs_fchmod(dirfd, mode) < 0
        ? error_errno(errno, "Failed to set mode on '%s'", path)
        : NULL;

    close(dirfd);
    return err;
}

/**
 * A directory and everything beneath it, in one walk of fs_remove_dir
 *
 * A frame per directory, each over a listing in the walk's scratch (fs_listing_t).
 * A failure leaves the scratch as it stands: the walk's driver frees it whole.
 */
static error_t fs_remove_subtree(arena_t *scratch, const char *path) {
    fs_listing_t listing;
    error_t err = fs_listing_init(&listing, scratch, path);
    if (err) return err;

    for (const char *full_path; (full_path = fs_listing_next(&listing)) != NULL;) {
        /* Use lstat to determine type WITHOUT following symlinks. This prevents
         * symlink-traversal attacks where a symlink inside the tree points to a
         * directory outside it - using stat() would follow the symlink and
         * recursively delete the target directory's contents. */
        struct stat st;
        if (fs_lstat(full_path, &st) < 0) {
            /* Gone since the listing, it leaves nothing to remove; any other
             * refusal ends the walk. */
            if (errno == ENOENT) continue;
            return error_errno(errno, "Failed to stat '%s'", full_path);
        }

        if (S_ISDIR(st.st_mode)) {
            err = fs_remove_subtree(scratch, full_path);
            if (err) return err;
        } else {
            /* Regular file, symlink, or any other type: unlink */
            err = fs_remove_file(full_path);
            if (err) return err;
        }
    }

    /* Remove directory itself */
    if (fs_rmdir(path) < 0) {
        if (errno == ENOENT) {
            return NULL;  /* Not an error if doesn't exist */
        }
        return error_errno(errno, "Failed to remove directory '%s'", path);
    }

    return NULL;
}

error_t fs_remove_dir(const char *path) {
    CHECK_NULL(path);

    if (!fs_is_directory(path)) {
        return NULL;  /* Not an error if doesn't exist */
    }

    /* The walk's one scratch, freed here whatever the walk met */
    arena_t *scratch = arena_create(0);
    error_t err = fs_remove_subtree(scratch, path);
    arena_free(scratch);

    return err;
}

error_t fs_clear_path(const char *path) {
    CHECK_NULL(path);

    struct stat st;
    if (fs_lstat(path, &st) != 0) {
        if (errno == ENOENT) {
            return NULL;  /* Nothing to clear - success */
        }
        return error_errno(errno, "Failed to stat '%s'", path);
    }

    if (S_ISDIR(st.st_mode)) {
        /* Directory - remove recursively */
        return fs_remove_dir(path);
    }

    /* File or symlink - use unlink */
    if (fs_unlink(path) != 0) {
        if (errno == ENOENT) {
            return NULL;  /* Race condition - already gone, success */
        }
        return error_errno(errno, "Failed to remove '%s'", path);
    }

    return NULL;
}

bool fs_is_directory(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    struct stat st;
    if (fs_stat(path, &st) < 0) {
        return false;
    }

    return S_ISDIR(st.st_mode);
}

/**
 * Is this directory entry OS metadata dotta may remove?
 *
 * Name and type together, because two functions act on the answer and they must
 * not disagree: fs_is_directory_empty looks past such an entry, fs_remove_empty_dir
 * unlinks it. The name rule is fs_is_os_metadata_file's; the type rule is this
 * one's — metadata is a regular file, so a directory or a symlink wearing one
 * of those names is a user object that neither function may pretend away.
 *
 * Anything that cannot be stat'd is not metadata: the conservative answer for
 * both callers.
 */
static bool entry_is_removable_metadata(const char *dir, const char *name) {
    if (!fs_is_os_metadata_file(name)) {
        return false;
    }

    /* Not metadata when it cannot be named: a path past PATH_MAX, the kernel's
     * own bound, which no lstat would answer for either. */
    char child[PATH_MAX];
    int n = snprintf(child, sizeof(child), "%s/%s", dir, name);
    if (n < 0 || (size_t) n >= sizeof(child)) return false;

    struct stat st;
    return fs_lstat(child, &st) == 0 && S_ISREG(st.st_mode);
}

fs_emptiness_t fs_directory_emptiness(
    const char *path, fs_path_pred_fn vouch, void *ctx
) {
    if (!path) {
        return FS_DIR_UNREADABLE;
    }

    /* Try to open directory (opendir checks stat internally) */
    DIR *dir = fs_opendir(path);
    if (!dir) {
        /* Can't open (doesn't exist, not a dir, or permission denied): nothing
         * can be said about what it holds. */
        return FS_DIR_UNREADABLE;
    }

    /* Check if directory contains only metadata and vouched-for entries
     *
     * This prevents "zombie" directories that contain only OS-generated metadata
     * (like .DS_Store on macOS) from blocking cleanup operations.
     */
    fs_emptiness_t answer = FS_DIR_EMPTY;

    for (;;) {
        /* readdir returns NULL on both EOF and error, and the entry test below
         * stats — so errno is reset immediately before each call rather than
         * once for the whole walk. */
        errno = 0;
        struct dirent *entry = readdir(dir);

        if (!entry) {
            if (errno != 0) {
                answer = FS_DIR_UNREADABLE;  /* read error: the walk is incomplete */
            }
            break;
        }

        /* Skip . and .. entries */
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Skip exactly what fs_remove_empty_dir can clear away, so "empty" means
         * the same thing to the predicate and to the mechanism. */
        if (entry_is_removable_metadata(path, entry->d_name)) {
            continue;
        }

        /* Skip what the caller vouches for. Its full path, because the caller
         * reasons about paths, not about basenames. */
        if (vouch) {
            char child[PATH_MAX];
            int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
            if (n < 0 || (size_t) n >= sizeof(child)) {
                /* Cannot name it, so cannot let the caller vouch for it — and
                 * an entry nobody could be asked about is not an entry nobody
                 * vouched for. The walk is incomplete, which is what the read
                 * error above answers too: nothing can be said. Only a path past
                 * PATH_MAX, the kernel's own bound, meets this. */
                answer = FS_DIR_UNREADABLE;
                break;
            }
            if (vouch(child, ctx)) continue;
        }

        /* Found a real entry - directory is not empty */
        answer = FS_DIR_OCCUPIED;
        break;
    }

    closedir(dir);
    return answer;
}

bool fs_is_directory_empty(const char *path) {
    return fs_directory_emptiness(path, NULL, NULL) == FS_DIR_EMPTY;
}

/**
 * POSIX permits either code for "the directory is not empty"
 */
static inline bool errno_means_not_empty(int code) {
    return code == ENOTEMPTY || code == EEXIST;
}

error_t fs_remove_empty_dir(const char *path) {
    CHECK_NULL(path);

    /* The whole story for a directory that is empty by the kernel's definition,
     * which is nearly all of them. */
    if (fs_rmdir(path) == 0 || errno == ENOENT) {
        return NULL;
    }
    if (!errno_means_not_empty(errno)) {
        return error_errno(errno, "Failed to remove directory '%s'", path);
    }

    /* Not empty by the kernel's definition; it may still be empty by ours. List
     * first — removing entries from an open DIR* leaves the rest of the walk
     * unspecified — into a frame of this call's own, freed once the entries are
     * judged and gone. */
    arena_t *frame = arena_create(0);
    string_array_t listing = { 0 };
    error_t err = fs_list_dir(path, frame, &listing);

    /* Two passes: refuse before touching anything. A directory refused here keeps
     * every entry it had, metadata included — the caller reports "not empty",
     * and nothing of the user's has moved. */
    for (size_t i = 0; i < listing.count && !err; i++) {
        if (!entry_is_removable_metadata(path, listing.entries[i])) {
            err = error_create(ERR_CONFLICT, "Directory '%s' is not empty", path);
        }
    }

    for (size_t i = 0; i < listing.count && !err; i++) {
        err = fs_remove_file(str_path_join(frame, path, listing.entries[i]));
    }

    arena_free(frame);
    if (err) return err;

    /* An entry that appeared while the metadata was being cleared lands here,
     * and it is the same refusal by another route. */
    if (fs_rmdir(path) != 0 && errno != ENOENT) {
        if (errno_means_not_empty(errno)) {
            return error_create(ERR_CONFLICT, "Directory '%s' is not empty", path);
        }
        return error_errno(errno, "Failed to remove directory '%s'", path);
    }

    return NULL;
}

error_t fs_list_dir(const char *path, arena_t *arena, string_array_t *out) {
    CHECK_NULL(path);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    DIR *dir = fs_opendir(path);
    if (!dir) {
        return error_errno(errno, "Failed to open directory '%s'", path);
    }

    /* errno cleared before every readdir: a NULL is the end, or the error it names */
    string_array_t names;
    string_array_init(&names, arena);
    struct dirent *entry;
    for (errno = 0; (entry = readdir(dir)) != NULL; errno = 0) {
        /* Skip . and .. - no caller ever wants these */
        if (entry->d_name[0] == '.' && (entry->d_name[1] == '\0' ||
            (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
            continue;
        }

        string_array_push(&names, entry->d_name);
    }

    if (errno != 0) {
        int saved_errno = errno;
        closedir(dir);
        return error_errno(
            saved_errno, "Error reading directory '%s'", path
        );
    }

    closedir(dir);
    *out = names;
    return NULL;
}

error_t fs_listing_init(fs_listing_t *listing, arena_t *scratch, const char *directory) {
    CHECK_NULL(listing);

    /* The mark before the names, so a listing that fails part-way leaves nothing
     * it read behind it. */
    const arena_mark_t frame = arena_mark(scratch);
    string_array_t names;
    error_t err = fs_list_dir(directory, scratch, &names);
    if (err) {
        arena_reset(scratch, frame);
        return err;
    }

    *listing = (fs_listing_t){
        .scratch = scratch,
        .directory = directory,
        .names = names,
        .frame = frame,
        .entry = arena_mark(scratch),
    };
    return NULL;
}

const char *fs_listing_next(fs_listing_t *listing) {
    CHECK_NULL(listing);

    if (listing->next == listing->names.count) {
        arena_reset(listing->scratch, listing->frame);
        return NULL;
    }

    arena_reset(listing->scratch, listing->entry);
    return str_path_join(
        listing->scratch, listing->directory, listing->names.entries[listing->next++]
    );
}

/**
 * Path operations
 */

/* pwd -L's rule: $PWD is the working directory when it is the fold's own spelling
 * (str_path_folded) and names the directory the process is in — one device and
 * inode with ".". It is carried as it stands, so anything the fold would move
 * is refused with it: a `..` behind a symlink folds to a directory other than
 * the one it named, and a doubled slash misses every prefix a reader tests it
 * against. Every shell writes a fixed point; only a hand-set variable is refused
 * here. */
static bool pwd_is_here(const char *pwd) {
    if (!str_path_folded(pwd)) return false;

    struct stat named, here;
    return fs_stat(pwd, &named) == 0 && fs_stat(".", &here) == 0 &&
           named.st_dev == here.st_dev && named.st_ino == here.st_ino;
}

error_t fs_working_directory(arena_t *arena, const char **out) {
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The shell's spelling where it set one that stands, the kernel's otherwise. */
    const char *cwd = getenv("PWD");
    char physical[PATH_MAX];
    if (!pwd_is_here(cwd)) {
        if (getcwd(physical, sizeof(physical)) == NULL) {
            return error_errno(errno, "Failed to get current directory");
        }
        cwd = physical;
    }

    *out = arena_strdup(arena, cwd);

    return NULL;
}

/**
 * Does the kernel read a `..` after `through` as the string does — as the directory
 * holding its last component?
 *
 * Where that component is a directory, yes, whatever links stand above it: `c/..`
 * names the directory `c` stands in. Where it is a file or nothing at all (ENOENT,
 * or ENOTDIR above it), the kernel has no reading of the `..` to disagree with,
 * and the string's stands. Where it is a link, no: the kernel steps out of what
 * the link reaches. And where the look is refused, nobody here knows, so the
 * `..` is left for the open, which meets that refusal with its own errno. Asked
 * as the invoker, with the raw call: what this reads is dotta's own directory,
 * which libgit2 and a hook open as the invoker and never with the reach (the
 * header).
 */
static bool fs_folds(const char *through) {
    struct stat st;

    return lstat(through, &st) == 0
        ? !S_ISLNK(st.st_mode)
        : errno == ENOENT || errno == ENOTDIR;
}

error_t fs_make_absolute(const char *path, arena_t *arena, const char **out) {
    CHECK_NULL(path);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The empty string names no path, and a user can type it (`dotta init ""`):
     * refused in git's words for it (lib/git/abspath.c strbuf_add_absolute_path),
     * ahead of the join below, which takes no empty name. */
    if (path[0] == '\0') {
        return error_create(ERR_INVALID_ARG, "The empty string is not a valid path");
    }

    /* The shell's order: the tilde, then the working directory beneath a path
     * still relative, then the fold over the whole — the kernel's, which keeps
     * a `..` only it can read. */
    const char *expanded = NULL;
    error_t err = fs_expand_tilde(path, arena, &expanded);
    if (err) return err;

    if (expanded[0] != '/') {
        const char *cwd = NULL;
        err = fs_working_directory(arena, &cwd);
        if (err) return err;
        expanded = str_path_join(arena, cwd, expanded);
    }

    *out = str_path_fold(arena, expanded, fs_folds);
    return NULL;
}

error_t fs_canonicalize_path(const char *path, arena_t *arena, const char **out) {
    CHECK_NULL(path);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    char resolved[PATH_MAX];
    if (fs_realpath(path, resolved) == NULL) {
        return error_errno(errno, "Failed to resolve path '%s'", path);
    }

    *out = arena_strdup(arena, resolved);

    return NULL;
}

char *fs_parent_dir(const char *path) {
    CHECK_NULL(path);
    CHECK_ARG(path[0] != '\0', "the parent of an empty path");

    /* Three runs from the end: the trailing separators, the last component, the
     * separators before it. None reaches past the first byte, so the root keeps
     * its one separator and a relative component leaves nothing: "." */
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') len--;
    while (len > 0 && path[len - 1] != '/') len--;
    while (len > 1 && path[len - 1] == '/') len--;

    return len == 0 ? heap_strdup(".") : heap_strndup(path, len);
}

error_t fs_expand_tilde(const char *path, arena_t *arena, const char **out) {
    CHECK_NULL(path);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    if (path[0] != '~') {
        *out = arena_strdup(arena, path);
        return NULL;
    }

    /* The home the prefix names, up to the first '/': none, the invoker's; a
     * login, that user's, as the system's user database answers it. The login
     * is asked for and let go: a transient of the call's. */
    size_t login = strcspn(path + 1, "/");
    const char *rest = path + 1 + login;
    const char *home = identity()->home;
    if (login > 0) {
        char *name = heap_strndup(path + 1, login);
        const struct passwd *pw = getpwnam(name);
        free(name);

        if (!pw) {
            return error_create(
                ERR_INVALID_ARG, "'%s' names a user this system does not know", path
            );
        }
        if (!pw->pw_dir || pw->pw_dir[0] == '\0') {
            return error_create(ERR_INVALID_ARG, "'%s' names a user with no home directory", path);
        }
        home = pw->pw_dir;
    }

    /* The home itself, alone or with its '/'; else the tail, whose own separators
     * fold into the one the join writes. */
    *out = rest[0] == '\0' || (rest[0] == '/' && rest[1] == '\0')
        ? arena_strdup(arena, home) : str_path_join(arena, home, rest);
    return NULL;
}

/**
 * Symlink operations
 */
error_t fs_create_symlink(
    const char *target, const char *linkpath,
    uid_t uid, gid_t gid
) {
    CHECK_NULL(target);
    CHECK_NULL(linkpath);

    if (fs_symlink(target, linkpath) < 0) {
        return error_errno(
            errno, "Failed to create symlink '%s' -> '%s'", linkpath, target
        );
    }

    if (uid != (uid_t) -1 || gid != (gid_t) -1) {
        if (fs_lchown(linkpath, uid, gid) < 0) {
            return error_errno(
                errno, "Failed to set ownership on symlink '%s'", linkpath
            );
        }
    }

    return NULL;
}

error_t fs_read_symlink(const char *linkpath, buffer_t *out) {
    CHECK_NULL(linkpath);
    CHECK_NULL(out);

    *out = (buffer_t){ 0 };

    /* The whole buffer is offered, and a read that fills it is refused: readlink
     * cuts a longer target short without a word, so a full buffer cannot tell a
     * target of that length from one cut to it (the header). */
    char buf[PATH_MAX];
    ssize_t len = fs_readlink(linkpath, buf, sizeof(buf));

    if (len < 0) {
        return error_errno(errno, "Failed to read symlink '%s'", linkpath);
    }
    if ((size_t) len == sizeof(buf)) {
        return error_errno(
            ENAMETOOLONG, "Failed to read symlink '%s'", linkpath
        );
    }

    buffer_append(out, buf, (size_t) len);

    return NULL;
}

/**
 * Permission operations
 */
error_t fs_get_permissions(const char *path, mode_t *out) {
    CHECK_NULL(path);
    CHECK_NULL(out);

    struct stat st;
    if (fs_stat(path, &st) < 0) {
        return error_errno(errno, "Failed to stat '%s'", path);
    }

    *out = st.st_mode & 0777;
    return NULL;
}

error_t fs_set_permissions(const char *path, mode_t mode) {
    CHECK_NULL(path);

    if (fs_chmod(path, mode) < 0) {
        return error_errno(
            errno, "Failed to set permissions on '%s'", path
        );
    }

    return NULL;
}

bool fs_is_executable(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    /* The running user's own question (filesystem.h): the raw call, on purpose. */
    return faccessat(AT_FDCWD, path, X_OK, AT_EACCESS) == 0;
}

bool fs_exists(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    struct stat st;
    return fs_stat(path, &st) == 0;
}

bool fs_lexists(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    struct stat st;
    return fs_lstat(path, &st) == 0;
}

fs_occupant_t fs_lstat_occupant(const char *path, struct stat *st) {
    struct stat local;
    if (!st) {
        st = &local;
    }

    if (fs_lstat(path, st) != 0) {
        /* ENOTDIR: a component above the path is not a directory, so nothing
         * can be at the path either. Whether that ancestor is anyone's to replace
         * is the caller's question, not this one's. */
        return (errno == ENOENT || errno == ENOTDIR) ? FS_OCCUPANT_NONE
                                                     : FS_OCCUPANT_UNKNOWN;
    }

    if (S_ISREG(st->st_mode)) return FS_OCCUPANT_REGULAR;
    if (S_ISLNK(st->st_mode)) return FS_OCCUPANT_SYMLINK;
    if (S_ISDIR(st->st_mode)) return FS_OCCUPANT_DIRECTORY;

    return FS_OCCUPANT_OTHER;
}

bool fs_denied(const char *path, int amode) {
    /* EACCES alone: the bits refuse this identity. A flag's EPERM and a read-only
     * mount's EROFS refuse root as well, and a loop or a path gone answers nothing
     * of identity — the call this predicts meets each of them. */
    return fs_eaccess(path, amode) < 0 && errno == EACCES;
}

const char *fs_stat_noun(const struct stat *st) {
    return S_ISREG(st->st_mode) ? "regular file" :
           S_ISLNK(st->st_mode) ? "symlink" :
           S_ISDIR(st->st_mode) ? "directory" :
           S_ISFIFO(st->st_mode) ? "FIFO" :
           S_ISSOCK(st->st_mode) ? "socket" :
           S_ISCHR(st->st_mode) ? "character device" :
           S_ISBLK(st->st_mode) ? "block device" : "special file";
}

/**
 * Ensure parent directories exist
 */
error_t fs_ensure_parent_dirs(const char *path) {
    CHECK_NULL(path);

    /* The directory the path stands in, made with its own parents where it is
     * missing; "." and "/" always stand. */
    char *parent = fs_parent_dir(path);
    error_t err = fs_is_directory(parent) ? NULL : fs_create_dir(parent, true);
    free(parent);

    return err ? error_wrap(err, "Failed to create parent directories for '%s'", path) : NULL;
}
