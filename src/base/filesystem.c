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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "error.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/string.h"

/* Buffer size for file I/O */
#define IO_BUFFER_SIZE 8192

/**
 * Helper: Validate path argument
 */
static inline dotta_error_t *validate_path(const char *path) {
    CHECK_NULL(path);
    if (path[0] == '\0') {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Path cannot be empty");
    }
    return NULL;
}

/**
 * File operations
 */

dotta_error_t *fs_read_file(const char *path, buffer_t **out) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(out);

    /* Open file */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return ERROR(DOTTA_ERR_FS, "Failed to open '%s': %s", path, strerror(errno));
    }

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved_errno = errno;
        close(fd);
        return ERROR(DOTTA_ERR_FS, "Failed to stat '%s': %s", path, strerror(saved_errno));
    }

    /* Create buffer */
    buffer_t *buf = buffer_create_with_capacity(st.st_size > 0 ? st.st_size : IO_BUFFER_SIZE);
    if (!buf) {
        close(fd);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate buffer for '%s'", path);
    }

    /* Read file in chunks */
    unsigned char chunk[IO_BUFFER_SIZE];
    ssize_t bytes_read;

    while ((bytes_read = read(fd, chunk, sizeof(chunk))) > 0) {
        dotta_error_t *err = buffer_append(buf, chunk, bytes_read);
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
        return ERROR(DOTTA_ERR_FS, "Read error on '%s': %s", path, strerror(saved_errno));
    }

    close(fd);
    *out = buf;
    return NULL;
}

dotta_error_t *fs_write_file(const char *path, const buffer_t *content) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(content);

    /* Ensure parent directory exists */
    char *parent = NULL;
    dotta_error_t *err = fs_get_parent_dir(path, &parent);
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

    /* Open file for writing (create if not exists, truncate if exists) */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return ERROR(DOTTA_ERR_FS, "Failed to open '%s' for writing: %s",
                    path, strerror(errno));
    }

    /* Write data */
    const unsigned char *data = buffer_data(content);
    size_t total = buffer_size(content);
    size_t written = 0;

    while (written < total) {
        ssize_t n = write(fd, data + written, total - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted, retry */
            }
            int saved_errno = errno;
            close(fd);
            return ERROR(DOTTA_ERR_FS, "Write error on '%s': %s",
                        path, strerror(saved_errno));
        }
        written += n;
    }

    /* Sync to disk */
    if (fsync(fd) < 0) {
        int saved_errno = errno;
        close(fd);
        return ERROR(DOTTA_ERR_FS, "Failed to sync '%s': %s",
                    path, strerror(saved_errno));
    }

    close(fd);
    return NULL;
}

dotta_error_t *fs_copy_file(const char *src, const char *dst) {
    RETURN_IF_ERROR(validate_path(src));
    RETURN_IF_ERROR(validate_path(dst));

    /* Check source exists */
    if (!fs_file_exists(src)) {
        return ERROR(DOTTA_ERR_NOT_FOUND, "Source file not found: %s", src);
    }

    /* Get source permissions */
    mode_t mode;
    dotta_error_t *err = fs_get_permissions(src, &mode);
    if (err) {
        return err;
    }

    /* Read source */
    buffer_t *content = NULL;
    err = fs_read_file(src, &content);
    if (err) {
        return error_wrap(err, "Failed to copy '%s' to '%s'", src, dst);
    }

    /* Write destination */
    err = fs_write_file(dst, content);
    buffer_free(content);
    if (err) {
        return error_wrap(err, "Failed to copy '%s' to '%s'", src, dst);
    }

    /* Set permissions */
    err = fs_set_permissions(dst, mode);
    if (err) {
        return error_wrap(err, "Failed to set permissions on '%s'", dst);
    }

    return NULL;
}

dotta_error_t *fs_remove_file(const char *path) {
    RETURN_IF_ERROR(validate_path(path));

    if (unlink(path) < 0) {
        if (errno == ENOENT) {
            return NULL;  /* Not an error if file doesn't exist */
        }
        return ERROR(DOTTA_ERR_FS, "Failed to remove '%s': %s", path, strerror(errno));
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

dotta_error_t *fs_create_dir(const char *path, bool parents) {
    RETURN_IF_ERROR(validate_path(path));

    /* Already exists? */
    if (fs_is_directory(path)) {
        return NULL;
    }

    if (parents) {
        /* Create parent first */
        char *parent = NULL;
        dotta_error_t *err = fs_get_parent_dir(path, &parent);
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
        return ERROR(DOTTA_ERR_FS, "Failed to create directory '%s': %s",
                    path, strerror(errno));
    }

    return NULL;
}

dotta_error_t *fs_remove_dir(const char *path, bool recursive) {
    RETURN_IF_ERROR(validate_path(path));

    if (!fs_is_directory(path)) {
        return NULL;  /* Not an error if doesn't exist */
    }

    if (recursive) {
        /* List and remove contents first */
        string_array_t *entries = NULL;
        dotta_error_t *err = fs_list_dir(path, &entries);
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
        return ERROR(DOTTA_ERR_FS, "Failed to remove directory '%s': %s",
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

dotta_error_t *fs_list_dir(const char *path, string_array_t **out) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(out);

    DIR *dir = opendir(path);
    if (!dir) {
        return ERROR(DOTTA_ERR_FS, "Failed to open directory '%s': %s",
                    path, strerror(errno));
    }

    string_array_t *entries = string_array_create();
    if (!entries) {
        closedir(dir);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate directory listing for '%s'", path);
    }

    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        dotta_error_t *err = string_array_push(entries, entry->d_name);
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
        return ERROR(DOTTA_ERR_FS, "Error reading directory '%s': %s",
                    path, strerror(saved_errno));
    }

    closedir(dir);
    *out = entries;
    return NULL;
}

/**
 * Path operations
 */

dotta_error_t *fs_canonicalize_path(const char *path, char **out) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(out);

    char resolved[PATH_MAX];
    if (realpath(path, resolved) == NULL) {
        return ERROR(DOTTA_ERR_FS, "Failed to resolve path '%s': %s",
                    path, strerror(errno));
    }

    *out = strdup(resolved);
    if (!*out) {
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate canonical path for '%s'", path);
    }

    return NULL;
}

dotta_error_t *fs_get_parent_dir(const char *path, char **out) {
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
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate clean path");
    }

    /* Find last slash in cleaned path */
    const char *last_slash = strrchr(clean_path, '/');

    if (!last_slash) {
        /* No slash - current directory */
        free(clean_path);
        *out = strdup(".");
        if (!*out) {
            return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate parent path");
        }
        return NULL;
    }

    if (last_slash == clean_path) {
        /* Root directory */
        free(clean_path);
        *out = strdup("/");
        if (!*out) {
            return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate parent path");
        }
        return NULL;
    }

    /* Extract parent */
    size_t len = last_slash - clean_path;
    *out = strndup(clean_path, len);
    free(clean_path);

    if (!*out) {
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate parent path for '%s'", path);
    }

    return NULL;
}

dotta_error_t *fs_path_join(const char *base, const char *component, char **out) {
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
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate joined path");
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

dotta_error_t *fs_create_symlink(const char *target, const char *linkpath) {
    RETURN_IF_ERROR(validate_path(target));
    RETURN_IF_ERROR(validate_path(linkpath));

    if (symlink(target, linkpath) < 0) {
        return ERROR(DOTTA_ERR_FS, "Failed to create symlink '%s' -> '%s': %s",
                    linkpath, target, strerror(errno));
    }

    return NULL;
}

dotta_error_t *fs_read_symlink(const char *linkpath, char **out) {
    RETURN_IF_ERROR(validate_path(linkpath));
    CHECK_NULL(out);

    char buf[PATH_MAX];
    ssize_t len = readlink(linkpath, buf, sizeof(buf) - 1);

    if (len < 0) {
        return ERROR(DOTTA_ERR_FS, "Failed to read symlink '%s': %s",
                    linkpath, strerror(errno));
    }

    buf[len] = '\0';
    *out = strdup(buf);
    if (!*out) {
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate symlink target for '%s'", linkpath);
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

dotta_error_t *fs_get_permissions(const char *path, mode_t *out) {
    RETURN_IF_ERROR(validate_path(path));
    CHECK_NULL(out);

    struct stat st;
    if (stat(path, &st) < 0) {
        return ERROR(DOTTA_ERR_FS, "Failed to stat '%s': %s", path, strerror(errno));
    }

    *out = st.st_mode & 0777;
    return NULL;
}

dotta_error_t *fs_set_permissions(const char *path, mode_t mode) {
    RETURN_IF_ERROR(validate_path(path));

    if (chmod(path, mode) < 0) {
        return ERROR(DOTTA_ERR_FS, "Failed to set permissions on '%s': %s",
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
