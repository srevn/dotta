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
 * Compare blob content with disk file
 *
 * Uses mmap() for efficient memory-mapped comparison without loading
 * the entire file into memory. Falls back to chunked reading for
 * files that cannot be mapped (e.g., empty files, special files).
 */
error_t *compare_blob_to_disk(
    git_repository *repo,
    const git_oid *blob_id,
    const char *disk_path,
    compare_result_t *result
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_id);
    CHECK_NULL(disk_path);
    CHECK_NULL(result);

    /* Check if disk file exists */
    if (!fs_file_exists(disk_path)) {
        *result = CMP_MISSING;
        return NULL;
    }

    /* Load blob */
    git_blob *blob = NULL;
    int err = git_blob_lookup(&blob, repo, blob_id);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Get blob content */
    const void *blob_data = git_blob_rawcontent(blob);
    git_object_size_t blob_size = git_blob_rawsize(blob);

    /* Open disk file */
    int fd = open(disk_path, O_RDONLY);
    if (fd < 0) {
        git_blob_free(blob);
        return ERROR(ERR_FS, "Failed to open '%s': %s", disk_path, strerror(errno));
    }

    /* Get disk file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved_errno = errno;
        close(fd);
        git_blob_free(blob);
        return ERROR(ERR_FS, "Failed to stat '%s': %s", disk_path, strerror(saved_errno));
    }

    /* Compare sizes first - fast path */
    if ((size_t)st.st_size != blob_size) {
        *result = CMP_DIFFERENT;
        close(fd);
        git_blob_free(blob);
        return NULL;
    }

    /* Handle empty files */
    if (st.st_size == 0) {
        *result = CMP_EQUAL;
        close(fd);
        git_blob_free(blob);
        return NULL;
    }

    /* Memory-map the disk file for efficient comparison */
    void *disk_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (disk_data == MAP_FAILED) {
        /* mmap failed - fall back to reading in chunks */
        close(fd);

        buffer_t *disk_content = NULL;
        error_t *derr = fs_read_file(disk_path, &disk_content);
        if (derr) {
            git_blob_free(blob);
            return derr;
        }

        int cmp = memcmp(blob_data, buffer_data(disk_content), blob_size);
        *result = (cmp == 0) ? CMP_EQUAL : CMP_DIFFERENT;

        buffer_free(disk_content);
        git_blob_free(blob);
        return NULL;
    }

    /* Compare content using memory-mapped data */
    int cmp = memcmp(blob_data, disk_data, blob_size);
    *result = (cmp == 0) ? CMP_EQUAL : CMP_DIFFERENT;

    /* Cleanup */
    munmap(disk_data, st.st_size);
    close(fd);
    git_blob_free(blob);
    return NULL;
}

/**
 * Compare tree entry with disk file
 */
error_t *compare_tree_entry_to_disk(
    git_repository *repo,
    const git_tree_entry *entry,
    const char *disk_path,
    compare_result_t *result
) {
    CHECK_NULL(repo);
    CHECK_NULL(entry);
    CHECK_NULL(disk_path);
    CHECK_NULL(result);

    /* Check if disk file exists */
    if (!fs_exists(disk_path)) {
        *result = CMP_MISSING;
        return NULL;
    }

    /* Get entry type and mode */
    git_object_t entry_type = git_tree_entry_type(entry);
    git_filemode_t entry_mode = git_tree_entry_filemode(entry);

    /* Handle symlinks */
    if (entry_mode == GIT_FILEMODE_LINK) {
        /* Entry is a symlink - check disk is also symlink */
        if (!fs_is_symlink(disk_path)) {
            *result = CMP_TYPE_DIFF;
            return NULL;
        }

        /* Compare symlink targets */
        git_blob *blob = NULL;
        const git_oid *oid = git_tree_entry_id(entry);
        int err = git_blob_lookup(&blob, repo, oid);
        if (err < 0) {
            return error_from_git(err);
        }

        const char *blob_target = (const char *)git_blob_rawcontent(blob);
        size_t blob_target_len = git_blob_rawsize(blob);

        char *disk_target = NULL;
        error_t *derr = fs_read_symlink(disk_path, &disk_target);
        if (derr) {
            git_blob_free(blob);
            return derr;
        }

        /* Compare targets */
        bool targets_equal = (strlen(disk_target) == blob_target_len) &&
                            (memcmp(disk_target, blob_target, blob_target_len) == 0);

        free(disk_target);
        git_blob_free(blob);

        *result = targets_equal ? CMP_EQUAL : CMP_DIFFERENT;
        return NULL;
    }

    /* Handle regular files and executables */
    if (entry_type == GIT_OBJECT_BLOB) {
        /* Check disk is also a regular file */
        if (fs_is_symlink(disk_path)) {
            *result = CMP_TYPE_DIFF;
            return NULL;
        }

        if (!fs_file_exists(disk_path)) {
            /* Exists but not a regular file */
            *result = CMP_TYPE_DIFF;
            return NULL;
        }

        /* Compare content */
        const git_oid *oid = git_tree_entry_id(entry);
        error_t *derr = compare_blob_to_disk(repo, oid, disk_path, result);
        if (derr) {
            return derr;
        }

        /* If content is equal, check executable bit */
        if (*result == CMP_EQUAL) {
            bool entry_executable = (entry_mode == GIT_FILEMODE_BLOB_EXECUTABLE);
            bool disk_executable = fs_is_executable(disk_path);

            if (entry_executable != disk_executable) {
                *result = CMP_MODE_DIFF;
            }
        }

        return NULL;
    }

    /* Unsupported entry type */
    return ERROR(ERR_INTERNAL,
                "Unsupported git object type: %d", entry_type);
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

        /* Load disk file */
        buffer_t *disk_content = NULL;
        error_t *err = fs_read_file(disk_path, &disk_content);
        if (err) {
            return error_wrap(err, "Failed to read '%s'", disk_path);
        }

        /* Compare sizes (fast path) */
        if (buffer_size(content) != buffer_size(disk_content)) {
            *result = CMP_DIFFERENT;
            buffer_free(disk_content);
            return NULL;
        }

        /* Compare content */
        int cmp = memcmp(buffer_data(content), buffer_data(disk_content),
                        buffer_size(content));

        buffer_free(disk_content);

        if (cmp != 0) {
            *result = CMP_DIFFERENT;
            return NULL;
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
 * Generate unified diff for regular file
 */
static error_t *generate_text_diff(
    git_repository *repo,
    const git_oid *blob_oid,
    const char *disk_path,
    const char *path_label,
    compare_direction_t direction,
    char **diff_text
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(disk_path);
    CHECK_NULL(diff_text);

    error_t *err = NULL;
    git_blob *repo_blob = NULL;
    git_blob *disk_blob = NULL;
    buffer_t *disk_content = NULL;
    diff_callback_data_t callback_data = {0};

    /* Load blob from git */
    int git_err = git_blob_lookup(&repo_blob, repo, blob_oid);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Read disk file */
    if (fs_exists(disk_path)) {
        err = fs_read_file(disk_path, &disk_content);
        if (err) {
            git_blob_free(repo_blob);
            return error_wrap(err, "Failed to read disk file");
        }
    }

    /* Prepare callback data */
    callback_data.output = buffer_create();
    callback_data.has_binary = false;

    if (!callback_data.output) {
        if (disk_content) buffer_free(disk_content);
        git_blob_free(repo_blob);
        return ERROR(ERR_MEMORY, "Failed to allocate diff buffer");
    }

    /* Configure diff options */
    git_diff_options diff_opts = GIT_DIFF_OPTIONS_INIT;
    diff_opts.context_lines = 3;
    diff_opts.interhunk_lines = 0;
    diff_opts.flags = GIT_DIFF_NORMAL;

    /* Generate diff based on direction */
    if (direction == CMP_DIR_UPSTREAM) {
        /* Upstream: filesystem → repo (what apply would do) */
        /* Need to create blob from disk content to diff disk→repo */
        const char *disk_data = disk_content ? (const char *)buffer_data(disk_content) : "";
        size_t disk_size = disk_content ? buffer_size(disk_content) : 0;

        /* Create temporary blob from disk content */
        git_oid disk_oid;
        git_err = git_blob_create_from_buffer(&disk_oid, repo, disk_data, disk_size);
        if (git_err < 0) {
            buffer_free(callback_data.output);
            if (disk_content) buffer_free(disk_content);
            git_blob_free(repo_blob);
            return error_from_git(git_err);
        }

        git_err = git_blob_lookup(&disk_blob, repo, &disk_oid);
        if (git_err < 0) {
            buffer_free(callback_data.output);
            if (disk_content) buffer_free(disk_content);
            git_blob_free(repo_blob);
            return error_from_git(git_err);
        }

        /* Diff: disk_blob (old) → repo_blob (new) */
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

        git_blob_free(disk_blob);
    } else {
        /* Downstream: repo → filesystem (what update would commit) */
        const char *disk_data = disk_content ? (const char *)buffer_data(disk_content) : "";
        size_t disk_size = disk_content ? buffer_size(disk_content) : 0;

        /* Diff: repo_blob (old) → disk_buffer (new) */
        git_err = git_diff_blob_to_buffer(
            repo_blob,
            path_label ? path_label : disk_path,
            disk_data,
            disk_size,
            path_label ? path_label : disk_path,
            &diff_opts,
            NULL,  /* file callback */
            NULL,  /* binary callback */
            NULL,  /* hunk callback */
            diff_line_callback,
            &callback_data
        );
    }

    if (disk_content) buffer_free(disk_content);
    git_blob_free(repo_blob);

    if (git_err < 0) {
        buffer_free(callback_data.output);
        return error_from_git(git_err);
    }

    /* Extract result - transfer ownership and free buffer structure */
    /* buffer_release_data() gives ownership of data to caller and frees the buffer_t */
    if (buffer_size(callback_data.output) > 0) {
        error_t *err = buffer_release_data(callback_data.output, diff_text);
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
 * Generate diff for symlink
 */
static error_t *generate_symlink_diff(
    git_repository *repo,
    const git_oid *blob_oid,
    const char *disk_path,
    compare_direction_t direction,
    char **diff_text
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(disk_path);
    CHECK_NULL(diff_text);

    /* Load blob (symlink target) */
    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, repo, blob_oid);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    const char *blob_target = (const char *)git_blob_rawcontent(blob);
    size_t blob_target_len = git_blob_rawsize(blob);

    /* Read disk symlink target */
    char *disk_target = NULL;
    if (fs_exists(disk_path) && fs_is_symlink(disk_path)) {
        error_t *err = fs_read_symlink(disk_path, &disk_target);
        if (err) {
            git_blob_free(blob);
            return err;
        }
    }

    /* Format diff based on direction */
    buffer_t *buf = buffer_create();
    if (!buf) {
        free(disk_target);
        git_blob_free(blob);
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
    /* buffer_release_data() gives ownership of data to caller and frees the buffer_t */
    error_t *err = buffer_release_data(buf, diff_text);

    free(disk_target);
    git_blob_free(blob);

    if (err) {
        return error_wrap(err, "Failed to release symlink diff text");
    }

    return NULL;
}

/**
 * Generate diff between tree entry and disk file
 */
error_t *compare_generate_diff(
    git_repository *repo,
    const git_tree_entry *entry,
    const char *disk_path,
    compare_direction_t direction,
    file_diff_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(entry);
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

    /* Perform comparison */
    error_t *err = compare_tree_entry_to_disk(repo, entry, disk_path, &diff->status);
    if (err) {
        free(diff->path);
        free(diff);
        return err;
    }

    /* Generate diff text based on status and file type */
    if (diff->status == CMP_MISSING) {
        diff->diff_text = strdup("File not deployed on disk");
    } else if (diff->status == CMP_TYPE_DIFF) {
        /* Type mismatch - describe what's different */
        git_filemode_t mode = git_tree_entry_filemode(entry);
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
        git_filemode_t mode = git_tree_entry_filemode(entry);
        const git_oid *oid = git_tree_entry_id(entry);
        const char *entry_name = git_tree_entry_name(entry);

        if (mode == GIT_FILEMODE_LINK) {
            /* Symlink diff */
            err = generate_symlink_diff(repo, oid, disk_path, direction, &diff->diff_text);
        } else {
            /* Regular file diff */
            err = generate_text_diff(repo, oid, disk_path, entry_name, direction, &diff->diff_text);
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
 * Generate symlink diff from buffer
 *
 * Helper for compare_generate_diff_from_buffer().
 * Generates a human-readable diff for symlink target changes.
 */
static error_t *generate_symlink_diff_from_buffer(
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
 * Helper for compare_generate_diff_from_buffer().
 * Creates temporary git blobs to leverage libgit2's diff functionality.
 */
static error_t *generate_text_diff_from_buffer(
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
error_t *compare_generate_diff_from_buffer(
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
            err = generate_symlink_diff_from_buffer(content, disk_path, direction, &diff->diff_text);
        } else {
            /* Regular file diff - create temp blobs and use libgit2 */
            err = generate_text_diff_from_buffer(
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
