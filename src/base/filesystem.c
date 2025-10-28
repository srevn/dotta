/**
 * filesystem.c - Safe filesystem operations implementation
 *
 * All functions validate inputs and handle errors explicitly.
 */

#define _XOPEN_SOURCE 700  /* For realpath and other POSIX functions */

#include "filesystem.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "error.h"
#include "utils/array.h"
#include "utils/buffer.h"

/* Buffer size for file I/O */
#define IO_BUFFER_SIZE 8192

/**
 * Helper: Validate path argument
 */
static inline error_t *validate_path(const char *path) {
    CHECK_NULL(path);
    if (path[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }
    return NULL;
}

/**
 * File operations
 */

error_t *fs_read_file(const char *path, buffer_t **out) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(out);

    /* Open file */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return ERROR(ERR_FS, "Failed to open '%s': %s", path, strerror(errno));
    }

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved_errno = errno;
        close(fd);
        return ERROR(ERR_FS, "Failed to stat '%s': %s", path, strerror(saved_errno));
    }

    /* Create buffer */
    buffer_t *buf = buffer_create_with_capacity(st.st_size > 0 ? st.st_size : IO_BUFFER_SIZE);
    if (!buf) {
        close(fd);
        return ERROR(ERR_MEMORY, "Failed to allocate buffer for '%s'", path);
    }

    /* Read file in chunks */
    unsigned char chunk[IO_BUFFER_SIZE];
    ssize_t bytes_read;

    while ((bytes_read = read(fd, chunk, sizeof(chunk))) > 0) {
        error_t *err = buffer_append(buf, chunk, bytes_read);
        if (err) {
            close(fd);
            buffer_free(buf);
            return error_wrap(err, "Failed to read '%s'", path);
        }
    }

    if (bytes_read < 0) {
        int saved_errno = errno;
        close(fd);
        buffer_free(buf);
        return ERROR(ERR_FS, "Read error on '%s': %s", path, strerror(saved_errno));
    }

    close(fd);
    *out = buf;
    return NULL;
}

error_t *fs_write_file_raw(const char *path, const unsigned char *data, size_t size,
                           mode_t mode, uid_t uid, gid_t gid) {
    RETURN_IF_ERROR(validate_path(path));
    /* Note: data can be NULL if size is 0 (empty file) */

    /* Ensure parent directory exists */
    char *parent = NULL;
    error_t *err = fs_get_parent_dir(path, &parent);
    if (err) {
        return err;
    }

    if (parent && !fs_exists(parent)) {
        err = fs_create_dir(parent, true);
        free(parent);
        if (err) {
            return error_wrap(err, "Failed to create parent directory for '%s'", path);
        }
    } else {
        free(parent);
    }

    /* SECURITY: Open with restrictive mode 0600 initially
     *
     * Rationale: We must set ownership and permissions BEFORE writing any data
     * to prevent security windows. Using 0600 ensures that even if the process
     * is killed after open() but before fchmod(), the file remains protected.
     *
     * The umask cannot make this less restrictive (can only clear bits, not set them),
     * so 0600 is safe regardless of the process umask setting.
     */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return ERROR(ERR_FS, "Failed to open '%s' for writing: %s",
                    path, strerror(errno));
    }

    /* SECURITY CRITICAL: Apply ownership BEFORE writing data
     *
     * This ensures that if the file contains sensitive data (e.g., SSH keys,
     * API tokens, passwords), it has the correct owner from the moment data
     * is written, preventing unauthorized access.
     *
     * Use -1 to skip ownership change (preserve current user ownership).
     */
    if (uid != (uid_t)-1 || gid != (gid_t)-1) {
        if (fchown(fd, uid, gid) < 0) {
            int saved_errno = errno;
            close(fd);
            return ERROR(ERR_FS, "Failed to set ownership on '%s': %s",
                        path, strerror(saved_errno));
        }
    }

    /* SECURITY CRITICAL: Set exact permissions BEFORE writing data
     *
     * At this point, the file has correct ownership and is about to receive
     * correct permissions. It's still empty, so even if the process crashes
     * here, no sensitive data has been exposed.
     *
     * Using fchmod() on the file descriptor (not chmod() on path) ensures:
     * 1. Atomicity: No TOCTOU race with file replacement
     * 2. Not affected by umask: Exact mode is applied
     * 3. Works even if file was just created
     */
    if (fchmod(fd, mode) < 0) {
        int saved_errno = errno;
        close(fd);
        return ERROR(ERR_FS, "Failed to set permissions on '%s': %s",
                    path, strerror(saved_errno));
    }

    /* Write data - SAFE: File now has correct ownership + permissions
     *
     * At this point:
     * - File is owned by the correct user (if uid != -1)
     * - File has exact permissions requested (mode)
     * - File is still empty (no data exposure risk)
     *
     * Now it's safe to write sensitive data. If the process crashes during
     * write, we have an incomplete file with correct metadata (acceptable).
     */
    size_t written = 0;
    while (written < size) {
        ssize_t n = write(fd, data + written, size - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted, retry */
            }
            int saved_errno = errno;
            close(fd);
            return ERROR(ERR_FS, "Write error on '%s': %s",
                        path, strerror(saved_errno));
        }
        written += n;
    }

    /* Sync to disk */
    if (fsync(fd) < 0) {
        int saved_errno = errno;
        close(fd);
        return ERROR(ERR_FS, "Failed to sync '%s': %s",
                    path, strerror(saved_errno));
    }

    close(fd);
    return NULL;
}

error_t *fs_write_file(const char *path, const buffer_t *content) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(content);

    return fs_write_file_raw(path, buffer_data(content), buffer_size(content), 0644, -1, -1);
}

error_t *fs_copy_file(const char *src, const char *dst) {
    RETURN_IF_ERROR(validate_path(src));
    RETURN_IF_ERROR(validate_path(dst));

    /* Check source exists */
    if (!fs_file_exists(src)) {
        return ERROR(ERR_NOT_FOUND, "Source file not found: %s", src);
    }

    /* Get source permissions */
    mode_t mode;
    error_t *err = fs_get_permissions(src, &mode);
    if (err) {
        return err;
    }

    /* Read source */
    buffer_t *content = NULL;
    err = fs_read_file(src, &content);
    if (err) {
        return error_wrap(err, "Failed to copy '%s' to '%s'", src, dst);
    }

    /* Write destination with source permissions atomically
     * SECURITY: Use fs_write_file_raw() to set permissions atomically via fchmod(),
     * eliminating the security window where sensitive files (e.g., SSH keys)
     * would have incorrect permissions (0644 instead of 0600). */
    err = fs_write_file_raw(dst, buffer_data(content), buffer_size(content),
                           mode, -1, -1);
    buffer_free(content);
    if (err) {
        return error_wrap(err, "Failed to copy '%s' to '%s'", src, dst);
    }

    return NULL;
}

error_t *fs_remove_file(const char *path) {
    RETURN_IF_ERROR(validate_path(path));

    if (unlink(path) < 0) {
        if (errno == ENOENT) {
            return NULL;  /* Not an error if file doesn't exist */
        }
        return ERROR(ERR_FS, "Failed to remove '%s': %s", path, strerror(errno));
    }

    return NULL;
}

bool fs_file_exists(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    struct stat st;
    if (stat(path, &st) < 0) {
        return false;
    }

    return S_ISREG(st.st_mode);
}

/**
 * Directory operations
 */

error_t *fs_create_dir(const char *path, bool parents) {
    RETURN_IF_ERROR(validate_path(path));

    /* Already exists? */
    if (fs_is_directory(path)) {
        return NULL;
    }

    if (parents) {
        /* Create parent first */
        char *parent = NULL;
        error_t *err = fs_get_parent_dir(path, &parent);
        if (err) {
            return err;
        }

        if (parent && !fs_is_directory(parent)) {
            err = fs_create_dir(parent, true);
            free(parent);
            if (err) {
                return err;
            }
        } else {
            free(parent);
        }
    }

    /* Create directory */
    if (mkdir(path, 0755) < 0) {
        if (errno == EEXIST && fs_is_directory(path)) {
            return NULL;  /* Race condition - another process created it */
        }
        return ERROR(ERR_FS, "Failed to create directory '%s': %s",
                    path, strerror(errno));
    }

    return NULL;
}

error_t *fs_create_dir_with_mode(const char *path, mode_t mode, bool parents) {
    RETURN_IF_ERROR(validate_path(path));

    /* Validate mode */
    if (mode > 0777) {
        return ERROR(ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)", mode);
    }

    /* If directory already exists, return success */
    if (fs_is_directory(path)) {
        return NULL;
    }

    /* Create parent directories if requested */
    if (parents) {
        char *parent = NULL;
        error_t *err = fs_get_parent_dir(path, &parent);
        if (err) {
            return err;
        }

        if (parent && !fs_is_directory(parent)) {
            /* Use default 0755 for parent directories */
            err = fs_create_dir(parent, true);
            free(parent);
            if (err) {
                return err;
            }
        } else {
            free(parent);
        }
    }

    /* Try to create directory with specified mode */
    bool existed = false;
    if (mkdir(path, mode) < 0) {
        if (errno == EEXIST && fs_is_directory(path)) {
            /* Directory already exists - will ensure correct mode below */
            existed = true;
        } else {
            return ERROR(ERR_FS, "Failed to create directory '%s' with mode %04o: %s",
                        path, mode, strerror(errno));
        }
    }

    /* Ensure exact permissions with chmod() (idempotent operation)
     *
     * Why chmod() is needed in BOTH cases:
     *
     * 1. New directory: mkdir() mode is affected by umask
     *    Example: mkdir(path, 0700) with umask 022 creates 0755
     *    chmod() enforces exact mode regardless of umask
     *
     * 2. Existing directory: May have wrong permissions
     *    Example: User runs `dotta apply --force` to fix ~/.ssh/ from 0755 to 0700
     *    deploy.c only calls this function when --force is set for existing dirs
     *    chmod() updates mode to match metadata (security fix!)
     *
     * This makes the function idempotent: "ensure directory exists with exact mode"
     * Matches file behavior (fs_write_file_raw always sets exact mode)
     */
    if (chmod(path, mode) < 0) {
        return ERROR(ERR_FS, "Failed to set permissions on directory '%s'%s: %s",
                    path, existed ? " (already existed)" : "", strerror(errno));
    }

    return NULL;
}

error_t *fs_create_dir_with_ownership(
    const char *path,
    mode_t mode,
    uid_t uid,
    gid_t gid,
    bool parents
) {
    RETURN_IF_ERROR(validate_path(path));

    /* Validate mode */
    if (mode > 0777) {
        return ERROR(ERR_INVALID_ARG, "Invalid mode: %04o (must be <= 0777)", mode);
    }

    /* Try to open existing directory first (eliminates TOCTOU race)
     * SECURITY: This open-first pattern prevents race conditions where
     * a directory is checked, then deleted/replaced before we operate on it.
     * By attempting to open first, we either get a valid fd or a clear error. */
    int dirfd = open(path, O_RDONLY | O_DIRECTORY);
    if (dirfd >= 0) {
        /* Directory exists - update ownership and mode atomically */
        goto apply_metadata;
    }

    /* Directory doesn't exist - verify it's actually missing */
    if (errno != ENOENT && errno != ENOTDIR) {
        /* Unexpected error (permission denied, etc.) */
        return ERROR(ERR_FS, "Failed to open directory '%s': %s",
                    path, strerror(errno));
    }

    /* Create parent directories if requested */
    if (parents) {
        char *parent = NULL;
        error_t *err = fs_get_parent_dir(path, &parent);
        if (err) {
            return err;
        }

        if (parent && !fs_is_directory(parent)) {
            /* Use default 0755 for parent directories */
            err = fs_create_dir(parent, true);
            free(parent);
            if (err) {
                return err;
            }
        } else {
            free(parent);
        }
    }

    /* Create directory with restrictive initial mode for security
     * SECURITY: Start with 0700 to prevent unauthorized access during setup,
     * then atomically set final mode via fchmod() on the file descriptor. */
    if (mkdir(path, 0700) < 0) {
        if (errno == EEXIST) {
            /* Race condition: directory created concurrently, retry via open path */
            return fs_create_dir_with_ownership(path, mode, uid, gid, false);
        }
        return ERROR(ERR_FS, "Failed to create directory '%s': %s",
                    path, strerror(errno));
    }

    /* Open newly created directory for atomic operations */
    dirfd = open(path, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        return ERROR(ERR_FS, "Failed to open newly created directory '%s': %s",
                    path, strerror(errno));
    }

apply_metadata:
    /* Apply ownership atomically via file descriptor
     * SECURITY: Using fchown() on the file descriptor ensures atomicity.
     * The ownership is applied to the directory we have open, not to whatever
     * might be at 'path' if a race condition occurred. */
    if (uid != (uid_t)-1 || gid != (gid_t)-1) {
        if (fchown(dirfd, uid, gid) < 0) {
            int saved_errno = errno;
            close(dirfd);
            return ERROR(ERR_FS, "Failed to set ownership on '%s': %s",
                        path, strerror(saved_errno));
        }
    }

    /* Apply final mode atomically via file descriptor
     * SECURITY: fchmod() ensures the mode is set on the directory we have open.
     * This is the final step - after this completes, the directory has the
     * exact ownership and permissions requested, with no security windows. */
    if (fchmod(dirfd, mode) < 0) {
        int saved_errno = errno;
        close(dirfd);
        return ERROR(ERR_FS, "Failed to set mode on '%s': %s",
                    path, strerror(saved_errno));
    }

    close(dirfd);
    return NULL;
}

error_t *fs_remove_dir(const char *path, bool recursive) {
    RETURN_IF_ERROR(validate_path(path));

    if (!fs_is_directory(path)) {
        return NULL;  /* Not an error if doesn't exist */
    }

    if (recursive) {
        /* List and remove contents first */
        string_array_t *entries = NULL;
        error_t *err = fs_list_dir(path, &entries);
        if (err) {
            return err;
        }

        for (size_t i = 0; i < string_array_size(entries); i++) {
            const char *entry = string_array_get(entries, i);

            /* Skip . and .. */
            if (strcmp(entry, ".") == 0 || strcmp(entry, "..") == 0) {
                continue;
            }

            char *full_path = NULL;
            err = fs_path_join(path, entry, &full_path);
            if (err) {
                string_array_free(entries);
                return err;
            }

            /* Remove recursively */
            if (fs_is_directory(full_path)) {
                err = fs_remove_dir(full_path, true);
            } else {
                err = fs_remove_file(full_path);
            }

            free(full_path);
            if (err) {
                string_array_free(entries);
                return err;
            }
        }

        string_array_free(entries);
    }

    /* Remove directory itself */
    if (rmdir(path) < 0) {
        if (errno == ENOENT) {
            return NULL;  /* Not an error if doesn't exist */
        }
        return ERROR(ERR_FS, "Failed to remove directory '%s': %s",
                    path, strerror(errno));
    }

    return NULL;
}

bool fs_is_directory(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    struct stat st;
    if (stat(path, &st) < 0) {
        return false;
    }

    return S_ISDIR(st.st_mode);
}

bool fs_is_directory_empty(const char *path) {
    if (!path) {
        return true;  /* NULL path is considered "empty" */
    }

    /* Try to open directory (no need for separate stat - opendir checks internally) */
    DIR *dir = opendir(path);
    if (!dir) {
        /* Can't open (doesn't exist, not a dir, or permission denied).
         * For safety (don't delete what we can't verify), return false.
         * Non-existent directories handled gracefully by caller (fs_exists check).
         */
        return false;
    }

    /* Check if directory only contains . and .. entries */
    bool is_empty = true;
    struct dirent *entry;
    errno = 0;

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. entries */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Found a real entry - directory is not empty */
        is_empty = false;
        break;
    }

    /* Check for readdir() errors (readdir returns NULL on both EOF and error) */
    if (errno != 0) {
        /* Read error occurred - assume not empty for safety */
        is_empty = false;
    }

    closedir(dir);
    return is_empty;
}

error_t *fs_list_dir(const char *path, string_array_t **out) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(out);

    DIR *dir = opendir(path);
    if (!dir) {
        return ERROR(ERR_FS, "Failed to open directory '%s': %s",
                    path, strerror(errno));
    }

    string_array_t *entries = string_array_create();
    if (!entries) {
        closedir(dir);
        return ERROR(ERR_MEMORY, "Failed to allocate directory listing for '%s'", path);
    }

    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        error_t *err = string_array_push(entries, entry->d_name);
        if (err) {
            closedir(dir);
            string_array_free(entries);
            return error_wrap(err, "Failed to build directory listing for '%s'", path);
        }
        errno = 0;
    }

    if (errno != 0) {
        int saved_errno = errno;
        closedir(dir);
        string_array_free(entries);
        return ERROR(ERR_FS, "Error reading directory '%s': %s",
                    path, strerror(saved_errno));
    }

    closedir(dir);
    *out = entries;
    return NULL;
}

/**
 * Path operations
 */

error_t *fs_canonicalize_path(const char *path, char **out) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(out);

    char resolved[PATH_MAX];
    if (realpath(path, resolved) == NULL) {
        return ERROR(ERR_FS, "Failed to resolve path '%s': %s",
                    path, strerror(errno));
    }

    *out = strdup(resolved);
    if (!*out) {
        return ERROR(ERR_MEMORY, "Failed to allocate canonical path for '%s'", path);
    }

    return NULL;
}

error_t *fs_get_parent_dir(const char *path, char **out) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(out);

    /* Strip trailing slashes (except for root "/") */
    size_t path_len = strlen(path);
    while (path_len > 1 && path[path_len - 1] == '/') {
        path_len--;
    }

    /* Make a copy without trailing slashes for processing */
    char *clean_path = strndup(path, path_len);
    if (!clean_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate clean path");
    }

    /* Find last slash in cleaned path */
    const char *last_slash = strrchr(clean_path, '/');

    if (!last_slash) {
        /* No slash - current directory */
        free(clean_path);
        *out = strdup(".");
        if (!*out) {
            return ERROR(ERR_MEMORY, "Failed to allocate parent path");
        }
        return NULL;
    }

    if (last_slash == clean_path) {
        /* Root directory */
        free(clean_path);
        *out = strdup("/");
        if (!*out) {
            return ERROR(ERR_MEMORY, "Failed to allocate parent path");
        }
        return NULL;
    }

    /* Extract parent */
    size_t len = last_slash - clean_path;
    *out = strndup(clean_path, len);
    free(clean_path);

    if (!*out) {
        return ERROR(ERR_MEMORY, "Failed to allocate parent path for '%s'", path);
    }

    return NULL;
}

error_t *fs_path_join(const char *base, const char *component, char **out) {
    RETURN_IF_ERROR(validate_path(base));
    RETURN_IF_ERROR(validate_path(component));
    CHECK_NULL(out);

    /* Calculate length */
    size_t base_len = strlen(base);
    size_t comp_len = strlen(component);
    bool needs_slash = (base_len > 0 && base[base_len - 1] != '/');
    size_t total_len = base_len + comp_len + (needs_slash ? 1 : 0);

    /* Allocate */
    char *result = malloc(total_len + 1);
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate joined path");
    }

    /* Build path */
    char *ptr = result;
    memcpy(ptr, base, base_len);
    ptr += base_len;

    if (needs_slash) {
        *ptr++ = '/';
    }

    memcpy(ptr, component, comp_len);
    ptr[comp_len] = '\0';

    *out = result;
    return NULL;
}

bool fs_is_writable(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    if (fs_exists(path)) {
        return access(path, W_OK) == 0;
    }

    /* Check parent directory - walk up until we find an existing directory */
    char *check_path = NULL;
    if (fs_get_parent_dir(path, &check_path) != NULL) {
        return false;
    }

    /* Walk up the directory tree until we find an existing directory */
    while (check_path && !fs_exists(check_path)) {
        char *parent = NULL;
        if (fs_get_parent_dir(check_path, &parent) != NULL) {
            free(check_path);
            return false;
        }
        free(check_path);
        check_path = parent;
    }

    /* Check if the existing ancestor directory is writable */
    bool writable = check_path && access(check_path, W_OK) == 0;
    free(check_path);
    return writable;
}

/**
 * Symlink operations
 */

error_t *fs_create_symlink(const char *target, const char *linkpath) {
    RETURN_IF_ERROR(validate_path(target));
    RETURN_IF_ERROR(validate_path(linkpath));

    if (symlink(target, linkpath) < 0) {
        return ERROR(ERR_FS, "Failed to create symlink '%s' -> '%s': %s",
                    linkpath, target, strerror(errno));
    }

    return NULL;
}

error_t *fs_read_symlink(const char *linkpath, char **out) {
    RETURN_IF_ERROR(validate_path(linkpath));
    CHECK_NULL(out);

    char buf[PATH_MAX];
    ssize_t len = readlink(linkpath, buf, sizeof(buf) - 1);

    if (len < 0) {
        return ERROR(ERR_FS, "Failed to read symlink '%s': %s",
                    linkpath, strerror(errno));
    }

    buf[len] = '\0';
    *out = strdup(buf);
    if (!*out) {
        return ERROR(ERR_MEMORY, "Failed to allocate symlink target for '%s'", linkpath);
    }

    return NULL;
}

bool fs_is_symlink(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    struct stat st;
    if (lstat(path, &st) < 0) {
        return false;
    }

    return S_ISLNK(st.st_mode);
}

/**
 * Permission operations
 */

error_t *fs_get_permissions(const char *path, mode_t *out) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(out);

    struct stat st;
    if (stat(path, &st) < 0) {
        return ERROR(ERR_FS, "Failed to stat '%s': %s", path, strerror(errno));
    }

    *out = st.st_mode & 0777;
    return NULL;
}

error_t *fs_set_permissions(const char *path, mode_t mode) {
    RETURN_IF_ERROR(validate_path(path));

    if (chmod(path, mode) < 0) {
        return ERROR(ERR_FS, "Failed to set permissions on '%s': %s",
                    path, strerror(errno));
    }

    return NULL;
}

bool fs_is_executable(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    struct stat st;
    if (stat(path, &st) < 0) {
        return false;
    }

    return (st.st_mode & S_IXUSR) != 0;
}

bool fs_exists(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    struct stat st;
    return stat(path, &st) == 0;
}

bool fs_lexists(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    struct stat st;
    return lstat(path, &st) == 0;
}

/**
 * Stat-based type checking helpers
 */

bool fs_stat_is_symlink(const struct stat *st) {
    if (!st) {
        return false;
    }
    return S_ISLNK(st->st_mode);
}

bool fs_stat_is_regular(const struct stat *st) {
    if (!st) {
        return false;
    }
    return S_ISREG(st->st_mode);
}

bool fs_stat_is_directory(const struct stat *st) {
    if (!st) {
        return false;
    }
    return S_ISDIR(st->st_mode);
}

bool fs_stat_is_executable(const struct stat *st) {
    if (!st) {
        return false;
    }
    return (st->st_mode & S_IXUSR) != 0;
}

/**
 * Ensure parent directories exist
 */
error_t *fs_ensure_parent_dirs(const char *path) {
    RETURN_IF_ERROR(validate_path(path));

    /* Get parent directory */
    char *path_copy = strdup(path);
    if (!path_copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate path copy");
    }

    char *parent = dirname(path_copy);
    if (!parent || strcmp(parent, ".") == 0 || strcmp(parent, "/") == 0) {
        /* No parent to create, or parent is root */
        free(path_copy);
        return NULL;
    }

    /* Check if parent exists */
    if (fs_is_directory(parent)) {
        free(path_copy);
        return NULL;
    }

    /* Create parent directories recursively */
    error_t *err = fs_create_dir(parent, true);  /* true = recursive */
    free(path_copy);

    if (err) {
        return error_wrap(err, "Failed to create parent directories for: %s", path);
    }

    return NULL;
}

/**
 * Privilege and ownership operations
 */

bool fs_is_running_as_root(void) {
    return geteuid() == 0;
}

error_t *fs_get_actual_user(uid_t *uid, gid_t *gid) {
    CHECK_NULL(uid);
    CHECK_NULL(gid);

    /* Check if running under sudo by examining SUDO_UID environment variable */
    const char *sudo_uid_str = getenv("SUDO_UID");
    const char *sudo_gid_str = getenv("SUDO_GID");

    if (sudo_uid_str && sudo_gid_str) {
        /* Running under sudo - parse the environment variables */
        char *endptr;

        /* Parse UID */
        errno = 0;
        long parsed_uid = strtol(sudo_uid_str, &endptr, 10);
        if (errno != 0 || *endptr != '\0' || parsed_uid < 0) {
            return ERROR(ERR_INVALID_ARG,
                        "Invalid SUDO_UID environment variable: %s", sudo_uid_str);
        }

        /* Parse GID */
        errno = 0;
        long parsed_gid = strtol(sudo_gid_str, &endptr, 10);
        if (errno != 0 || *endptr != '\0' || parsed_gid < 0) {
            return ERROR(ERR_INVALID_ARG,
                        "Invalid SUDO_GID environment variable: %s", sudo_gid_str);
        }

        /* Validate that the UID actually exists in the system */
        struct passwd *pw = getpwuid((uid_t)parsed_uid);
        if (!pw) {
            return ERROR(ERR_NOT_FOUND,
                        "User with UID %ld (from SUDO_UID) not found in system", parsed_uid);
        }

        *uid = (uid_t)parsed_uid;
        *gid = (gid_t)parsed_gid;
        return NULL;
    }

    /* Not running under sudo - return current effective UID/GID */
    *uid = geteuid();
    *gid = getegid();
    return NULL;
}

/**
 * Context for ownership fix callback
 *
 * Since nftw() doesn't support passing user data to the callback,
 * we use a static context pointer. This is safe because:
 * 1. dotta is single-threaded
 * 2. nftw() is not re-entrant
 * 3. We only use this during a single fix operation
 */
typedef struct {
    uid_t target_uid;      /* UID to set */
    gid_t target_gid;      /* GID to set */
    size_t fixed_count;    /* Number of files successfully fixed */
    size_t failed_count;   /* Number of files that failed */
} ownership_fix_context_t;

/* Static context for nftw callback (safe: single-threaded, non-reentrant) */
static ownership_fix_context_t *g_fix_context = NULL;

/**
 * Callback for nftw() - fixes ownership of a single file/directory
 *
 * This function is called by nftw() for each file/directory in the tree.
 * It checks if the current ownership matches the target, and if not,
 * calls lchown() to fix it.
 *
 * Error handling:
 * - lstat() failure: Count as failed, continue
 * - Ownership already correct: Skip, continue
 * - lchown() success: Count as fixed, continue
 * - lchown() failure: Count as failed, continue
 *
 * @param fpath Path to file/directory
 * @param sb Stat buffer (from nftw)
 * @param typeflag File type flag (from nftw)
 * @param ftwbuf FTW info (from nftw)
 * @return 0 to continue traversal
 */
static int fix_ownership_callback(
    const char *fpath,
    const struct stat *sb,
    int typeflag,
    struct FTW *ftwbuf
) {
    (void)typeflag;  /* Unused - we handle all types the same way */
    (void)ftwbuf;    /* Unused - we don't need traversal info */

    /* Sanity check: context must be set */
    if (!g_fix_context) {
        return 0;  /* Continue traversal even if context missing (shouldn't happen) */
    }

    /* Sanity check: stat buffer must be valid */
    if (!sb) {
        g_fix_context->failed_count++;
        return 0;  /* Continue traversal */
    }

    /* Check if ownership already correct */
    if (sb->st_uid == g_fix_context->target_uid &&
        sb->st_gid == g_fix_context->target_gid) {
        /* Already correct - skip */
        return 0;
    }

    /* Ownership needs fixing - use lchown() for safety (doesn't follow symlinks) */
    if (lchown(fpath, g_fix_context->target_uid, g_fix_context->target_gid) == 0) {
        /* Success */
        g_fix_context->fixed_count++;
    } else {
        /* Failed (e.g., permission denied on some system files)
         * This is expected and not fatal - just count it */
        g_fix_context->failed_count++;
    }

    return 0;  /* Continue traversal */
}

error_t *fs_fix_ownership_recursive(
    const char *path,
    uid_t uid,
    gid_t gid,
    size_t *out_fixed,
    size_t *out_failed
) {
    RETURN_IF_ERROR(validate_path(path));

    /* Verify path exists and is a directory */
    if (!fs_is_directory(path)) {
        return ERROR(ERR_INVALID_ARG,
                    "Path '%s' does not exist or is not a directory", path);
    }

    /* Initialize context */
    ownership_fix_context_t context = {
        .target_uid = uid,
        .target_gid = gid,
        .fixed_count = 0,
        .failed_count = 0
    };

    /* Set global context pointer for callback
     * Safe because we're single-threaded and nftw is not re-entrant */
    g_fix_context = &context;

    /* Traverse directory tree and fix ownership
     *
     * Flags:
     * - FTW_PHYS: Don't follow symlinks (safer)
     * - FTW_DEPTH: Process directories after their contents (cleaner)
     *
     * nopenfd: Maximum number of file descriptors nftw may use.
     * 64 is a reasonable limit that avoids exhausting fd limit while
     * still allowing efficient traversal.
     */
    int result = nftw(path, fix_ownership_callback, 64, FTW_PHYS | FTW_DEPTH);

    /* Clear global context */
    g_fix_context = NULL;

    /* Check for fatal nftw errors */
    if (result != 0) {
        /* nftw() returns -1 on error, or non-zero if callback requested stop
         * Since our callback always returns 0, non-zero means nftw() failed */
        return ERROR(ERR_FS,
                    "Failed to traverse directory '%s': %s",
                    path, strerror(errno));
    }

    /* Return statistics if requested */
    if (out_fixed) {
        *out_fixed = context.fixed_count;
    }
    if (out_failed) {
        *out_failed = context.failed_count;
    }

    /* Success - even if some individual files failed, we did our best */
    return NULL;
}
