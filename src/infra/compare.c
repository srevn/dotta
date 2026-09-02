/**
 * compare.c - File comparison engine implementation
 */

#include "infra/compare.h"

#include <errno.h>
#include <fcntl.h>
#include <git2.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"
#include "sys/filesystem.h"

const char *compare_result_string(compare_result_t result) {
    switch (result) {
        case CMP_EQUAL:      return "equal";
        case CMP_DIFFERENT:  return "different";
        case CMP_MISSING:    return "missing";
        case CMP_TYPE_DIFF:  return "type mismatch";
        case CMP_UNVERIFIED: return "unverified";
        default:             return "unknown";
    }
}

/**
 * The reference a disk copy is judged against
 *
 * The plaintext bytes, or the blob's id — exactly one. compare_buffer_to_disk
 * and compare_oid_to_disk ask one question with the reference in two encodings,
 * and the encoding matters at two points only: the size fast path (a buffer knows
 * its size; an id does not) and the judgment (memcmp, or hash and compare). Every
 * other step — the stat, the type against the expected mode, the read of a link's
 * target or a file's bytes — is one look, spelled once below.
 */
typedef struct {
    const buffer_t *content;    /* The plaintext bytes, or NULL */
    const git_oid *oid;         /* The blob's id, or NULL */
} reference_t;

/**
 * Judge the bytes the look found against the reference
 *
 * A symlink's target and a regular file's content arrive the same way: the bytes
 * Git would hash for this path, which is Git's own model of a link (a blob holding
 * the target as raw bytes). A buffer is judged by comparing them; an id by hashing
 * them as Git does — SHA-1("blob <size>\0" + bytes) — and comparing the ids.
 */
static error_t *judge(
    const reference_t *ref, const void *bytes, size_t size,
    const char *disk_path, compare_result_t *result
) {
    if (ref->content) {
        /* Re-check size: file may have changed between stat and read */
        bool equal = (size == ref->content->size) &&
            (memcmp(ref->content->data, bytes, size) == 0);
        *result = equal ? CMP_EQUAL : CMP_DIFFERENT;
        return NULL;
    }

    git_oid computed;
    if (git_odb_hash(&computed, bytes, size, GIT_OBJECT_BLOB) != 0) {
        const git_error *git_err = git_error_last();
        return ERROR(
            ERR_GIT, "Failed to hash '%s': %s", disk_path,
            git_err ? git_err->message : "unknown error"
        );
    }

    *result = git_oid_equal(ref->oid, &computed) ? CMP_EQUAL : CMP_DIFFERENT;

    return NULL;
}

/**
 * One look at the disk copy, judged against the reference
 *
 * Optimized to minimize filesystem syscalls by:
 * 1. Accepting pre-captured stat (in_stat parameter)
 * 2. Returning stat for caller reuse (out_stat parameter)
 * 3. Using single lstat/fstat for all type/size/mode checks
 *
 * NOTE: We do NOT check permissions here. Permission validation is a core-layer
 * concern handled by workspace.c, which checks:
 * 1. Git filemode (executable bit from tree)
 * 2. Full metadata (all permission bits + ownership from .dotta/metadata.json)
 *
 * This separation keeps the infrastructure layer pure and focused on content
 * comparison only.
 */
static error_t *compare_reference_to_disk(
    const reference_t *ref, const char *disk_path, git_filemode_t expected_mode,
    const struct stat *in_stat, compare_result_t *result, struct stat *out_stat
) {
    struct stat st;
    const struct stat *stat_ptr;

    /* Stat handling: use provided stat or capture new one
     *
     * Single-stat-per-file principle: When caller has already stat'd the file
     * (e.g., for existence check), we reuse that stat to avoid redundant syscall.
     * This is critical for performance in hot paths like workspace analysis.
     */
    if (in_stat) {
        /* Caller provided stat - use it (zero syscalls) */
        stat_ptr = in_stat;
        if (out_stat) memcpy(out_stat, in_stat, sizeof(struct stat));
    } else {
        /* Need to stat - use lstat to detect symlinks correctly */
        if (fs_lstat(disk_path, &st) != 0) {
            if (errno == ENOENT || errno == ENOTDIR) {
                /* File doesn't exist - not an error, just report it (ENOTDIR: a
                 * component above is no longer a directory — same absence) */
                *result = CMP_MISSING;
                if (out_stat) {
                    memset(out_stat, 0, sizeof(*out_stat));
                }
                return NULL;
            }
            return error_from_errno(errno, "Failed to stat '%s'", disk_path);
        }
        stat_ptr = &st;
        if (out_stat) {
            memcpy(out_stat, &st, sizeof(struct stat));
        }
    }

    /* Handle symlinks using captured stat */
    if (expected_mode == GIT_FILEMODE_LINK) {
        if (!fs_stat_is_symlink(stat_ptr)) {
            *result = CMP_TYPE_DIFF;
            return NULL;
        }

        /* The target is the bytes. A link that vanished mid-look (ERR_NOT_FOUND
         * — the errno's code, the caller's own absence rule) is CMP_MISSING;
         * anything else is the read's error, which names the link itself. */
        char *target = NULL;
        error_t *err = fs_read_symlink(disk_path, &target);
        if (err) {
            if (error_code(err) == ERR_NOT_FOUND) {
                error_free(err);
                *result = CMP_MISSING;
                return NULL;
            }
            return err;
        }

        err = judge(ref, target, strlen(target), disk_path, result);
        free(target);
        return err;
    }

    /* Handle regular files using captured stat — no other mode is supported */
    if (expected_mode != GIT_FILEMODE_BLOB &&
        expected_mode != GIT_FILEMODE_BLOB_EXECUTABLE) {
        return ERROR(ERR_INTERNAL, "Unsupported git filemode: %d", expected_mode);
    }

    /* Check disk is also regular file (using captured stat - no syscall): not a
     * symlink, and not a directory, device, FIFO, socket, etc. */
    if (fs_stat_is_symlink(stat_ptr) || !fs_stat_is_regular(stat_ptr)) {
        *result = CMP_TYPE_DIFF;
        return NULL;
    }

    /* Fast path: a buffer knows its size, so a size that differs is a verdict
     * with no open needed; an id knows nothing of the size and reads regardless. */
    if (ref->content && ref->content->size != (size_t) stat_ptr->st_size) {
        *result = CMP_DIFFERENT;
        return NULL;
    }

    /* One look: open a descriptor and read it to EOF — the bytes judged are one
     * inode's. O_NOFOLLOW refuses a symlink swapped in since the caller's lstat
     * (ELOOP); O_NONBLOCK keeps a swapped-in FIFO from wedging the open (fs_read_fd
     * then refuses it as not a regular file). read(2) cannot fault on a concurrent
     * truncation the way a stat-sized mmap could — it returns short, and
     * short-or-different is CMP_DIFFERENT in the judgment. libgit2's
     * git_odb_hashfile would open the path itself — a look sys/filesystem does
     * not make (filesystem.h's funnel), and with it the errno the absence rule
     * needs. The whole file is in memory for the length of the judgment, bounded
     * by fs_read_fd's cap; above it the look fails and the caller reads a failed
     * look, never a verdict. */
    int fd = fs_open(disk_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            /* The look itself found nothing standing: the file vanished between
             * the caller's stat and this open. A verdict, not a failed look. */
            *result = CMP_MISSING;
            return NULL;
        }
        return error_from_errno(errno, "Failed to open '%s'", disk_path);
    }

    buffer_t disk_content = BUFFER_INIT;
    error_t *err = fs_read_fd(fd, &disk_content);
    close(fd);
    if (err) {
        return error_wrap(err, "Failed to read '%s'", disk_path);
    }

    err = judge(ref, disk_content.data, disk_content.size, disk_path, result);
    buffer_free(&disk_content);
    return err;
}

error_t *compare_buffer_to_disk(
    const buffer_t *content,
    const char *disk_path,
    git_filemode_t expected_mode,
    const struct stat *in_stat,
    compare_result_t *result,
    struct stat *out_stat
) {
    CHECK_NULL(content);
    CHECK_NULL(disk_path);
    CHECK_NULL(result);

    reference_t ref = { .content = content };
    return compare_reference_to_disk(
        &ref, disk_path, expected_mode, in_stat, result, out_stat
    );
}

error_t *compare_oid_to_disk(
    const git_oid *blob_oid,
    const char *disk_path,
    git_filemode_t expected_mode,
    const struct stat *in_stat,
    compare_result_t *result,
    struct stat *out_stat
) {
    CHECK_NULL(blob_oid);
    CHECK_NULL(disk_path);
    CHECK_NULL(result);

    reference_t ref = { .oid = blob_oid };
    return compare_reference_to_disk(
        &ref, disk_path, expected_mode, in_stat, result, out_stat
    );
}

/**
 * Diff line callback - accumulates diff output into a buffer_t payload
 */
static int diff_line_callback(
    const git_diff_delta *delta,
    const git_diff_hunk *hunk,
    const git_diff_line *line,
    void *payload
) {
    buffer_t *output = (buffer_t *) payload;

    /* Suppress unused parameter warnings */
    (void) delta;
    (void) hunk;

    if (!output) {
        return -1;
    }

    /* Skip EOFNL lines — the manual marker below handles "no newline at end
     * of file" for all line types.  Letting EOFNL lines through would
     * duplicate the marker because libgit2 emits them with the same text.
     *
     * Note: GIT_DIFF_LINE_BINARY never reaches this callback because
     * git_diff_buffers only routes binary content to binary_cb (which we
     * pass as NULL).  Binary detection is handled in compare_generate_diff. */
    if (line->origin == GIT_DIFF_LINE_ADD_EOFNL ||
        line->origin == GIT_DIFF_LINE_DEL_EOFNL ||
        line->origin == GIT_DIFF_LINE_CONTEXT_EOFNL) {
        return 0;
    }

    error_t *err = NULL;

    /* Add origin character for context/addition/deletion */
    if (line->origin == GIT_DIFF_LINE_CONTEXT ||
        line->origin == GIT_DIFF_LINE_ADDITION ||
        line->origin == GIT_DIFF_LINE_DELETION) {
        err = buffer_append(output, &line->origin, 1);
        if (err) goto cleanup;
    }

    /* Add line content */
    err = buffer_append(output, line->content, line->content_len);
    if (err) goto cleanup;

    /* Handle files without trailing newline like git diff does */
    if (line->content_len == 0 || line->content[line->content_len - 1] != '\n') {
        err = buffer_append_string(output, "\n\\ No newline at end of file\n");
        if (err) goto cleanup;
    }

    return 0;

cleanup:
    error_free(err);
    return -1;
}

/**
 * Generate symlink diff from buffer
 *
 * Helper for compare_generate_diff(). Generates a human-readable diff for symlink
 * target changes.
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

    const char *blob_target = (const char *) content->data;
    size_t blob_target_len = content->size;

    /* Read disk symlink target (lstat-based check handles broken symlinks) */
    char *disk_target = NULL;
    if (fs_is_symlink(disk_path)) {
        error_t *err = fs_read_symlink(disk_path, &disk_target);
        if (err) return err;
    }

    /* Format diff based on direction */
    error_t *err = NULL;
    buffer_t buf = BUFFER_INIT;
    const char *disk_label = disk_target ? disk_target : "(not a symlink)";

    err = buffer_append_string(&buf, "Symlink target changed:\n");
    if (err) goto cleanup;

    if (direction == CMP_DIR_UPSTREAM) {
        /* Upstream: show filesystem → repo (what apply would do) */
        err = buffer_append_string(&buf, "- ");
        if (!err) err = buffer_append_string(&buf, disk_label);
        if (!err) err = buffer_append_string(&buf, "\n+ ");
        if (!err) err = buffer_append(&buf, blob_target, blob_target_len);
        if (!err) err = buffer_append_string(&buf, "\n");
    } else {
        /* Downstream: show repo → filesystem (what update would commit) */
        err = buffer_append_string(&buf, "- ");
        if (!err) err = buffer_append(&buf, blob_target, blob_target_len);
        if (!err) err = buffer_append_string(&buf, "\n+ ");
        if (!err) err = buffer_append_string(&buf, disk_label);
        if (!err) err = buffer_append_string(&buf, "\n");
    }
    if (err) goto cleanup;

    /* Transfer ownership and free buffer structure */
    *diff_text = buffer_detach(&buf);

cleanup:
    buffer_free(&buf);
    free(disk_target);
    return err;
}

/**
 * Generate text diff from buffer
 *
 * Helper for compare_generate_diff(). Uses in-memory buffers with libgit2's
 * buffer-based diff API.
 */
static error_t *generate_text_diff(
    const buffer_t *content,
    const char *disk_path,
    const char *path_label,
    compare_direction_t direction,
    char **diff_text
) {
    CHECK_NULL(content);
    CHECK_NULL(disk_path);
    CHECK_NULL(diff_text);

    error_t *err = NULL;
    buffer_t disk_content = BUFFER_INIT;

    /* Get repo buffer pointers (from input parameter - decrypted content) */
    const void *repo_data = content->data;
    size_t repo_size = content->size;

    /* Read disk file content This function is only called when
     * compare_buffer_to_disk returned CMP_DIFFERENT, so the file is known to
     * exist. Read directly without a separate existence check to avoid TOCTOU
     * races. */
    const void *disk_data = NULL;
    size_t disk_size = 0;

    err = fs_read_file(disk_path, &disk_content);
    if (err) {
        return error_wrap(err, "Failed to read disk file");
    }
    disk_data = disk_content.data;
    disk_size = disk_content.size;

    /* Output buffer passed directly as callback payload */
    buffer_t diff_output = BUFFER_INIT;

    /* Configure diff options */
    git_diff_options diff_opts;
    git_diff_options_init(&diff_opts, GIT_DIFF_OPTIONS_VERSION);
    diff_opts.context_lines = 3;
    diff_opts.interhunk_lines = 0;
    diff_opts.flags = GIT_DIFF_NORMAL;

    /* Generate diff based on direction using buffer-to-buffer diff */
    int git_err;
    if (direction == CMP_DIR_UPSTREAM) {
        /* Upstream: filesystem → repo (what apply would do) */
        /* Show diff: disk (old) → repo (new) */
        git_err = git_diff_buffers(
            disk_data, disk_size,
            path_label ? path_label : disk_path,
            repo_data, repo_size,
            path_label ? path_label : disk_path,
            &diff_opts,
            NULL,  /* file callback */
            NULL,  /* binary callback */
            NULL,  /* hunk callback */
            diff_line_callback,
            &diff_output
        );
    } else {
        /* Downstream: repo → filesystem (what update would commit) */
        /* Show diff: repo (old) → disk (new) */
        git_err = git_diff_buffers(
            repo_data, repo_size,
            path_label ? path_label : disk_path,
            disk_data, disk_size,
            path_label ? path_label : disk_path,
            &diff_opts,
            NULL,  /* file callback */
            NULL,  /* binary callback */
            NULL,  /* hunk callback */
            diff_line_callback,
            &diff_output
        );
    }

    /* Cleanup disk content buffer */
    buffer_free(&disk_content);

    if (git_err < 0) {
        buffer_free(&diff_output);
        return error_from_git(git_err);
    }

    /* Extract result - transfer ownership and free buffer structure */
    if (diff_output.size > 0) {
        *diff_text = buffer_detach(&diff_output);
    } else {
        *diff_text = NULL;
        buffer_free(&diff_output);
    }

    return NULL;
}

/**
 * Generate diff from buffer content to disk file with stat propagation
 */
error_t *compare_generate_diff(
    const buffer_t *content,
    const char *disk_path,
    const char *path_label,
    git_filemode_t mode,
    const struct stat *in_stat,
    compare_direction_t direction,
    file_diff_t **out
) {
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

    /* Perform comparison using buffer with optional stat */
    struct stat file_stat;
    error_t *err = compare_buffer_to_disk(
        content, disk_path, mode, in_stat, &diff->status, &file_stat
    );
    if (err) {
        free(diff->path);
        free(diff);
        return err;
    }

    /* Generate diff text based on status */
    if (diff->status == CMP_MISSING) {
        diff->diff_text = strdup("File not deployed on disk");
    } else if (diff->status == CMP_TYPE_DIFF) {
        /* Type mismatch - describe what's different using captured stat */
        const char *expected = (mode == GIT_FILEMODE_LINK) ? "symlink" : "regular file";
        const char *actual = "unknown";

        /* Use captured stat from compare_buffer_to_disk if available */
        if (file_stat.st_mode != 0) {
            actual = fs_stat_is_symlink(&file_stat) ? "symlink" : "regular file";
        }

        if (asprintf(
            &diff->diff_text,
            "Type mismatch: expected %s, found %s", expected, actual
            ) < 0) {
            diff->diff_text = NULL;
        }
    } else if (diff->status == CMP_DIFFERENT) {
        /* Generate actual unified diff */
        if (mode == GIT_FILEMODE_LINK) {
            /* Symlink diff - use buffer directly */
            err = generate_symlink_diff(
                content, disk_path, direction, &diff->diff_text
            );
        } else {
            /* Regular file diff - use in-memory buffer diff */
            err = generate_text_diff(
                content, disk_path, path_label, direction, &diff->diff_text
            );
        }

        if (err) {
            free(diff->path);
            free(diff);
            return err;
        }

        /* Binary files: libgit2 skips the line callback entirely when it detects
         * binary content, so generate_text_diff returns NULL. Provide an explicit
         * message rather than silent empty output. */
        if (!diff->diff_text) {
            diff->diff_text = strdup("Binary files differ");
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
