/**
 * compare.c - File comparison engine implementation
 */

#include "compare.h"

#include <errno.h>
#include <fcntl.h>
#include <git2.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "utils/buffer.h"

const char *compare_result_string(compare_result_t result) {
    switch (result) {
        case CMP_EQUAL:     return "equal";
        case CMP_DIFFERENT: return "different";
        case CMP_MISSING:   return "missing";
        case CMP_TYPE_DIFF: return "type mismatch";
        case CMP_MODE_DIFF: return "mode mismatch";
        default:            return "unknown";
    }
}

/**
 * Compare buffer content to disk file
 *
 * Pure function with zero git/encryption knowledge.
 * Designed for use with decrypted content from the content layer.
 */
error_t *compare_buffer_to_disk(
    const buffer_t *content,
    const char *disk_path,
    git_filemode_t expected_mode,
    compare_result_t *result
) {
    CHECK_NULL(content);
    CHECK_NULL(disk_path);
    CHECK_NULL(result);

    /* Check file exists */
    if (!fs_exists(disk_path)) {
        *result = CMP_MISSING;
        return NULL;
    }

    /* Handle symlinks */
    if (expected_mode == GIT_FILEMODE_LINK) {
        if (!fs_is_symlink(disk_path)) {
            *result = CMP_TYPE_DIFF;
            return NULL;
        }

        /* Compare symlink targets */
        char *disk_target = NULL;
        error_t *err = fs_read_symlink(disk_path, &disk_target);
        if (err) {
            return error_wrap(err, "Failed to read symlink '%s'", disk_path);
        }

        size_t expected_len = buffer_size(content);
        bool targets_equal = (strlen(disk_target) == expected_len) &&
                            (memcmp(buffer_data(content), disk_target, expected_len) == 0);

        free(disk_target);
        *result = targets_equal ? CMP_EQUAL : CMP_DIFFERENT;
        return NULL;
    }

    /* Handle regular files */
    if (expected_mode == GIT_FILEMODE_BLOB ||
        expected_mode == GIT_FILEMODE_BLOB_EXECUTABLE) {

        /* Check disk is also regular file */
        if (fs_is_symlink(disk_path)) {
            *result = CMP_TYPE_DIFF;
            return NULL;
        }

        if (!fs_file_exists(disk_path)) {
            *result = CMP_TYPE_DIFF;
            return NULL;
        }

        /* Open disk file for optimized comparison */
        int fd = open(disk_path, O_RDONLY);
        if (fd < 0) {
            return ERROR(ERR_FS, "Failed to open '%s': %s", disk_path, strerror(errno));
        }

        /* Get disk file size */
        struct stat st;
        if (fstat(fd, &st) < 0) {
            int saved_errno = errno;
            close(fd);
            return ERROR(ERR_FS, "Failed to stat '%s': %s", disk_path, strerror(saved_errno));
        }

        /* Compare sizes first - fast path */
        if (buffer_size(content) != (size_t)st.st_size) {
            *result = CMP_DIFFERENT;
            close(fd);
            return NULL;
        }

        /* For non-empty files, compare content */
        if (st.st_size > 0) {
            /* Memory-map the disk file for efficient comparison */
            void *disk_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (disk_data == MAP_FAILED) {
                /* mmap failed - fall back to buffered reading */
                close(fd);

                buffer_t *disk_content = NULL;
                error_t *err = fs_read_file(disk_path, &disk_content);
                if (err) {
                    return error_wrap(err, "Failed to read '%s'", disk_path);
                }

                int cmp = memcmp(buffer_data(content), buffer_data(disk_content),
                                buffer_size(content));
                buffer_free(disk_content);

                if (cmp != 0) {
                    *result = CMP_DIFFERENT;
                    return NULL;
                }
            } else {
                /* Compare content using memory-mapped data */
                int cmp = memcmp(buffer_data(content), disk_data, buffer_size(content));

                /* Cleanup */
                munmap(disk_data, st.st_size);
                close(fd);

                if (cmp != 0) {
                    *result = CMP_DIFFERENT;
                    return NULL;
                }
            }
        } else {
            /* Empty files - content trivially equal */
            close(fd);
        }

        /* Content equal - check executable bit */
        bool expect_exec = (expected_mode == GIT_FILEMODE_BLOB_EXECUTABLE);
        bool is_exec = fs_is_executable(disk_path);

        if (expect_exec != is_exec) {
            *result = CMP_MODE_DIFF;
        } else {
            *result = CMP_EQUAL;
        }

        return NULL;
    }

    /* Unsupported mode */
    return ERROR(ERR_INTERNAL, "Unsupported git filemode: %d", expected_mode);
}

/**
 * Diff line callback - accumulates diff output
 */
typedef struct {
    buffer_t *output;
    bool has_binary;
} diff_callback_data_t;

static int diff_line_callback(
    const git_diff_delta *delta,
    const git_diff_hunk *hunk,
    const git_diff_line *line,
    void *payload
) {
    diff_callback_data_t *data = (diff_callback_data_t *)payload;

    /* Suppress unused parameter warnings */
    (void)delta;
    (void)hunk;

    if (!data || !data->output) {
        return -1;
    }

    /* Check for binary content marker */
    if (line->origin == GIT_DIFF_LINE_BINARY) {
        data->has_binary = true;
        buffer_append_string(data->output, "Binary files differ\n");
        return 0;
    }

    /* Add origin character for context/addition/deletion */
    if (line->origin == GIT_DIFF_LINE_CONTEXT ||
        line->origin == GIT_DIFF_LINE_ADDITION ||
        line->origin == GIT_DIFF_LINE_DELETION) {
        buffer_append(data->output, (const unsigned char *)&line->origin, 1);
    }

    /* Add line content */
    buffer_append(data->output, (const unsigned char *)line->content, line->content_len);

    /* Handle files without trailing newline like git diff does */
    if (line->origin != GIT_DIFF_LINE_ADD_EOFNL &&
        line->origin != GIT_DIFF_LINE_DEL_EOFNL &&
        (line->content_len == 0 || line->content[line->content_len - 1] != '\n')) {
        buffer_append_string(data->output, "\n\\ No newline at end of file\n");
    }

    return 0;
}

/**
 * Generate symlink diff from buffer
 *
 * Helper for compare_generate_diff().
 * Generates a human-readable diff for symlink target changes.
 */
static error_t *generate_symlink_diff(
    const buffer_t *content,
    const char *disk_path,
    compare_direction_t direction,
    char **diff_text
) {
    CHECK_NULL(content);
    CHECK_NULL(disk_path);
    CHECK_NULL(diff_text);

    const char *blob_target = (const char *)buffer_data(content);
    size_t blob_target_len = buffer_size(content);

    /* Read disk symlink target */
    char *disk_target = NULL;
    if (fs_exists(disk_path) && fs_is_symlink(disk_path)) {
        error_t *err = fs_read_symlink(disk_path, &disk_target);
        if (err) {
            return err;
        }
    }

    /* Format diff based on direction */
    buffer_t *buf = buffer_create();
    if (!buf) {
        free(disk_target);
        return ERROR(ERR_MEMORY, "Failed to allocate buffer");
    }

    buffer_append_string(buf, "Symlink target changed:\n");

    if (direction == CMP_DIR_UPSTREAM) {
        /* Upstream: show filesystem → repo (what apply would do) */
        buffer_append_string(buf, "- ");
        if (disk_target) {
            buffer_append_string(buf, disk_target);
        } else {
            buffer_append_string(buf, "(not a symlink)");
        }
        buffer_append_string(buf, "\n+ ");
        buffer_append(buf, (const unsigned char *)blob_target, blob_target_len);
        buffer_append_string(buf, "\n");
    } else {
        /* Downstream: show repo → filesystem (what update would commit) */
        buffer_append_string(buf, "- ");
        buffer_append(buf, (const unsigned char *)blob_target, blob_target_len);
        buffer_append_string(buf, "\n+ ");
        if (disk_target) {
            buffer_append_string(buf, disk_target);
        } else {
            buffer_append_string(buf, "(not a symlink)");
        }
        buffer_append_string(buf, "\n");
    }

    /* Transfer ownership and free buffer structure */
    error_t *err = buffer_release_data(buf, diff_text);
    free(disk_target);

    if (err) {
        return error_wrap(err, "Failed to release symlink diff text");
    }

    return NULL;
}

/**
 * Generate text diff from buffer
 *
 * Helper for compare_generate_diff().
 * Creates temporary git blobs to leverage libgit2's diff functionality.
 */
static error_t *generate_text_diff(
    git_repository *repo,
    const buffer_t *content,
    const char *disk_path,
    const char *path_label,
    compare_direction_t direction,
    char **diff_text
) {
    CHECK_NULL(repo);
    CHECK_NULL(content);
    CHECK_NULL(disk_path);
    CHECK_NULL(diff_text);

    error_t *err = NULL;
    git_oid repo_oid, disk_oid;
    git_blob *repo_blob = NULL;
    git_blob *disk_blob = NULL;
    buffer_t *disk_content = NULL;
    diff_callback_data_t callback_data = {0};

    /* Create temporary blob from repo content (e.g., decrypted content) */
    int git_err = git_blob_create_from_buffer(
        &repo_oid,
        repo,
        buffer_data(content),
        buffer_size(content)
    );
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_err = git_blob_lookup(&repo_blob, repo, &repo_oid);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Read disk file and create temporary blob */
    if (fs_exists(disk_path)) {
        err = fs_read_file(disk_path, &disk_content);
        if (err) {
            git_blob_free(repo_blob);
            return error_wrap(err, "Failed to read disk file");
        }

        git_err = git_blob_create_from_buffer(
            &disk_oid,
            repo,
            buffer_data(disk_content),
            buffer_size(disk_content)
        );
        if (git_err < 0) {
            buffer_free(disk_content);
            git_blob_free(repo_blob);
            return error_from_git(git_err);
        }

        git_err = git_blob_lookup(&disk_blob, repo, &disk_oid);
        if (git_err < 0) {
            buffer_free(disk_content);
            git_blob_free(repo_blob);
            return error_from_git(git_err);
        }
    } else {
        /* File doesn't exist on disk - create empty blob */
        static const char empty[] = "";
        git_err = git_blob_create_from_buffer(&disk_oid, repo, empty, 0);
        if (git_err < 0) {
            git_blob_free(repo_blob);
            return error_from_git(git_err);
        }

        git_err = git_blob_lookup(&disk_blob, repo, &disk_oid);
        if (git_err < 0) {
            git_blob_free(repo_blob);
            return error_from_git(git_err);
        }
    }

    /* Prepare callback data */
    callback_data.output = buffer_create();
    callback_data.has_binary = false;

    if (!callback_data.output) {
        if (disk_content) buffer_free(disk_content);
        if (disk_blob) git_blob_free(disk_blob);
        git_blob_free(repo_blob);
        return ERROR(ERR_MEMORY, "Failed to allocate diff buffer");
    }

    /* Configure diff options */
    git_diff_options diff_opts = GIT_DIFF_OPTIONS_INIT;
    diff_opts.context_lines = 3;
    diff_opts.interhunk_lines = 0;
    diff_opts.flags = GIT_DIFF_NORMAL;

    /* Generate diff based on direction using blob-to-blob diff */
    if (direction == CMP_DIR_UPSTREAM) {
        /* Upstream: filesystem → repo (what apply would do) */
        /* Show diff: disk (old) → repo (new) */
        git_err = git_diff_blobs(
            disk_blob,
            path_label ? path_label : disk_path,
            repo_blob,
            path_label ? path_label : disk_path,
            &diff_opts,
            NULL,  /* file callback */
            NULL,  /* binary callback */
            NULL,  /* hunk callback */
            diff_line_callback,
            &callback_data
        );
    } else {
        /* Downstream: repo → filesystem (what update would commit) */
        /* Show diff: repo (old) → disk (new) */
        git_err = git_diff_blobs(
            repo_blob,
            path_label ? path_label : disk_path,
            disk_blob,
            path_label ? path_label : disk_path,
            &diff_opts,
            NULL,  /* file callback */
            NULL,  /* binary callback */
            NULL,  /* hunk callback */
            diff_line_callback,
            &callback_data
        );
    }

    /* Cleanup blobs and disk content */
    if (disk_content) buffer_free(disk_content);
    if (disk_blob) git_blob_free(disk_blob);
    git_blob_free(repo_blob);

    if (git_err < 0) {
        buffer_free(callback_data.output);
        return error_from_git(git_err);
    }

    /* Extract result - transfer ownership and free buffer structure */
    if (buffer_size(callback_data.output) > 0) {
        err = buffer_release_data(callback_data.output, diff_text);
        if (err) {
            return error_wrap(err, "Failed to release diff text");
        }
    } else {
        *diff_text = NULL;
        buffer_free(callback_data.output);
    }

    return NULL;
}

/**
 * Generate diff from buffer content to disk file
 */
error_t *compare_generate_diff(
    git_repository *repo,
    const buffer_t *content,
    const char *disk_path,
    const char *path_label,
    git_filemode_t mode,
    compare_direction_t direction,
    file_diff_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(content);
    CHECK_NULL(disk_path);
    CHECK_NULL(out);

    /* Allocate diff structure */
    file_diff_t *diff = calloc(1, sizeof(file_diff_t));
    if (!diff) {
        return ERROR(ERR_MEMORY, "Failed to allocate diff structure");
    }

    diff->path = strdup(disk_path);
    if (!diff->path) {
        free(diff);
        return ERROR(ERR_MEMORY, "Failed to allocate path");
    }

    /* Perform comparison using buffer */
    error_t *err = compare_buffer_to_disk(content, disk_path, mode, &diff->status);
    if (err) {
        free(diff->path);
        free(diff);
        return err;
    }

    /* Generate diff text based on status */
    if (diff->status == CMP_MISSING) {
        diff->diff_text = strdup("File not deployed on disk");
    } else if (diff->status == CMP_TYPE_DIFF) {
        /* Type mismatch - describe what's different */
        const char *expected = (mode == GIT_FILEMODE_LINK) ? "symlink" : "regular file";
        const char *actual = "unknown";

        if (fs_exists(disk_path)) {
            actual = fs_is_symlink(disk_path) ? "symlink" : "regular file";
        }

        /* Calculate exact buffer size needed for format string */
        const char *format = "Type mismatch: expected %s, found %s";
        size_t msg_len = strlen(format) - 4 + strlen(expected) + strlen(actual) + 1;
        diff->diff_text = malloc(msg_len);
        if (diff->diff_text) {
            snprintf(diff->diff_text, msg_len, format, expected, actual);
        }
    } else if (diff->status == CMP_MODE_DIFF) {
        diff->diff_text = strdup("Executable bit differs");
    } else if (diff->status == CMP_DIFFERENT) {
        /* Generate actual unified diff */
        if (mode == GIT_FILEMODE_LINK) {
            /* Symlink diff - use buffer directly */
            err = generate_symlink_diff(content, disk_path, direction, &diff->diff_text);
        } else {
            /* Regular file diff - create temp blobs and use libgit2 */
            err = generate_text_diff(
                repo,
                content,
                disk_path,
                path_label,
                direction,
                &diff->diff_text
            );
        }

        if (err) {
            free(diff->path);
            free(diff);
            return err;
        }
    }

    *out = diff;
    return NULL;
}

/**
 * Free diff structure
 */
void compare_free_diff(file_diff_t *diff) {
    if (!diff) {
        return;
    }

    free(diff->path);
    free(diff->diff_text);
    free(diff);
}
