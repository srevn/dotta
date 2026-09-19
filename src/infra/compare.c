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
#include "base/secure.h"
#include "sys/filesystem.h"

/**
 * The reference a disk copy is judged against
 *
 * The plaintext bytes, or the blob's id — exactly one. compare_buffer_to_disk
 * and compare_oid_to_disk ask one question with the reference in two encodings,
 * and the encoding matters at two points only: the size fast path (a buffer knows
 * its size; an id does not) and the judgment (memcmp, or hash and compare). Every
 * other step — the type against the expected mode, off the caller's look, and
 * the read of a link's target or a file's bytes — is spelled once below.
 */
typedef struct {
    const buffer_t *content;    /* The plaintext bytes, or NULL */
    const git_oid *oid;         /* The blob's id, or NULL */
} reference_t;

/**
 * Judge the disk copy the look read against the reference
 *
 * A symlink's target and a regular file's content arrive the same way: the bytes
 * Git would hash for this path, which is Git's own model of a link (a blob holding
 * the target as raw bytes). A buffer is judged by comparing them; an id by hashing
 * them as Git does — SHA-1("blob <size>\0" + bytes) — and comparing the ids.
 *
 * One reader, judge_copy, which reaches it for both of the module's ladders:
 * the bytes in hand are whatever that read returned, and the verdict over them
 * is the same verdict whichever caller asked.
 */
static error_t *judge(
    const reference_t *ref, const buffer_t *copy, const char *disk_path,
    compare_result_t *result
) {
    if (ref->content) {
        /* Re-check size: file may have changed between stat and read. Two empty
         * byte sequences are equal, and nothing is asked of a pointer to say
         * so: an empty blob's buffer carries no pointer at all (infra/content.c
         * get_plaintext_from_blob leaves it cleared for a zero-length blob),
         * and memcmp is undefined over a null pointer even across zero bytes —
         * which every tracked empty file this repository holds would ask it to
         * do. */
        bool equal = (copy->size == ref->content->size) && (copy->size == 0 ||
            memcmp(ref->content->data, copy->data, copy->size) == 0);
        *result = equal ? CMP_EQUAL : CMP_DIFFERENT;
        return NULL;
    }

    git_oid computed;
    if (git_odb_hash(&computed, copy->data, copy->size, GIT_OBJECT_BLOB) != 0) {
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
 * The modes a comparison is defined over
 *
 * A blob's two spellings and a link: what a file row's type becomes
 * (core/manifest.h path_type_to_git_filemode). A tree — which that same function
 * returns for a directory row — or a mode from nowhere is the caller's error,
 * refused by both ladders before either touches the disk: read as a blob, a
 * directory would be opened and judged, and mode_stands below would ask a regular
 * file's question about it.
 *
 * Asked first in both ladders, so one caller error has one answer wherever it
 * is made. It used to sit after the pair's own stat, where an unsupported mode
 * at an absent path read CMP_MISSING and the same mode at a live one was refused
 * — one mistake, answered by what happened to stand at the path.
 */
static error_t *validate_mode(git_filemode_t expected_mode) {
    if (expected_mode != GIT_FILEMODE_LINK && expected_mode != GIT_FILEMODE_BLOB &&
        expected_mode != GIT_FILEMODE_BLOB_EXECUTABLE) {
        return ERROR(ERR_INTERNAL, "Unsupported git filemode: %d", expected_mode);
    }

    return NULL;
}

/**
 * Does the look find the kind the expected mode names standing?
 *
 * A link for GIT_FILEMODE_LINK; a regular file — not a directory, device, FIFO,
 * socket, or a link — for either blob mode, which is the whole of the domain
 * validate_mode admits. Two readers that must not disagree about one path: the
 * pair, whose answer is the CMP_TYPE_DIFF verdict, and the renderer, whose answer
 * is the line a caller prints beside that verdict. core/workspace.c asks the
 * same question one layer up, over an occupant and a path_type_t — the vocabulary
 * each layer speaks.
 */
static bool mode_stands(const struct stat *st, git_filemode_t expected_mode) {
    return expected_mode == GIT_FILEMODE_LINK ? S_ISLNK(st->st_mode)
                                              : S_ISREG(st->st_mode);
}

/**
 * The disk copy's bytes, as Git would hash them
 *
 * A link's target or a regular file's content — the bytes a blob at this path
 * holds — read after the caller's look found the expected kind standing. A regular
 * file is read through one descriptor: O_NOFOLLOW refuses a symlink swapped in
 * since the look (ELOOP); O_NONBLOCK keeps a swapped-in FIFO from wedging the
 * open (fs_read_fd then refuses it as not a regular file); read(2) cannot fault
 * on a concurrent truncation the way a stat-sized mmap could — it returns short,
 * and short-or-different is CMP_DIFFERENT in the judgment. libgit2's
 * git_odb_hashfile would open the path itself — a look sys/filesystem does not
 * make (filesystem.h's funnel), and with it the errno the absence rule needs.
 * The whole copy is in memory for the length of the judgment, bounded by
 * fs_read_fd's cap; above it the read fails and the caller reads a failed look,
 * never a verdict.
 *
 * Absence is the caller's to read: ENOENT/ENOTDIR at the open, or from the link's
 * read, come back as ERR_NOT_FOUND — the path left between the look and this
 * read. One reader, judge_copy, which maps that one code to CMP_MISSING and every
 * other failure to a failed look, so the absence rule compare.h states once is
 * spelled once.
 */
static error_t *read_copy(
    const char *disk_path, git_filemode_t expected_mode, buffer_t *out
) {
    /* fs_read_fd clears this too, but a link's read and a failed open never reach
     * it. */
    *out = (buffer_t){ 0 };

    if (expected_mode == GIT_FILEMODE_LINK) {
        char *target = NULL;
        RETURN_IF_ERROR(fs_read_symlink(disk_path, &target));

        error_t *err = buffer_append_string(out, target);
        free(target);

        return err;
    }

    int fd = fs_open(disk_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0) {
        return error_from_errno(errno, "Failed to open '%s'", disk_path);
    }

    error_t *err = fs_read_fd(fd, out);
    close(fd);

    return err ? error_wrap(err, "Failed to read '%s'", disk_path) : NULL;
}

/**
 * The verdict over the disk copy, read and judged — the ladder's third step
 *
 * The bytes are read_copy's and the judgment is judge's; the absence between
 * them is spelled here, once, for the two ladders that must not answer it
 * differently: a read that met ENOENT/ENOTDIR is the verdict CMP_MISSING — the
 * path left between the look and the read — where any other failure is a failed
 * look and the caller's to carry. So a status line printed off the pair's verdict
 * and a text rendered off the renderer's cannot call one path two things.
 *
 * `copy` is filled whole and is the caller's on every exit: wiped and freed by
 * whichever of the two took it, whatever the verdict (compare.h).
 */
static error_t *judge_copy(
    const reference_t *ref, const char *disk_path, git_filemode_t expected_mode,
    buffer_t *copy, compare_result_t *result
) {
    error_t *err = read_copy(disk_path, expected_mode, copy);

    if (!err) {
        return judge(ref, copy, disk_path, result);
    }
    if (error_code(err) != ERR_NOT_FOUND) {
        return err;
    }

    /* The read met the absence: the path left between the look and the read. A
     * verdict, not a failed look. */
    error_free(err);
    *result = CMP_MISSING;

    return NULL;
}

/**
 * The caller's look at the disk copy, judged against the reference
 *
 * The look is handed in, and every question is asked off that one stat: the kind
 * against the expected mode, and for a regular file under a buffer the size too
 * — so a copy of the wrong kind or the wrong size is a verdict with no open at
 * all. Past those the step is judge_copy's, the same one the renderer takes, so
 * the bytes a status line is printed from are read and judged exactly as the
 * bytes a text is rendered from.
 *
 * No look is taken here. Absence at the look's own moment is the caller's to
 * name and it never gets this far — the one absence this function reports is
 * the read's, a path that left between the look and it.
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
    const struct stat *st, compare_result_t *result
) {
    RETURN_IF_ERROR(validate_mode(expected_mode));

    /* Does disk hold the kind the expected mode names? Off the look, no syscall. */
    if (!mode_stands(st, expected_mode)) {
        *result = CMP_TYPE_DIFF;
        return NULL;
    }

    /* Fast path: a buffer knows its size, so a regular file whose size differs
     * is a verdict with no open needed; a link's st_size is not read (its meaning
     * is the filesystem's), and an id knows nothing of the size and reads
     * regardless. */
    if (expected_mode != GIT_FILEMODE_LINK && ref->content &&
        ref->content->size != (size_t) st->st_size) {
        *result = CMP_DIFFERENT;
        return NULL;
    }

    buffer_t copy = BUFFER_INIT;
    error_t *err = judge_copy(ref, disk_path, expected_mode, &copy, result);

    /* For an encrypted row the disk copy is the plaintext — the twin of the buffer
     * the content cache wipes before it frees. Wiped like it, whatever the read
     * left, and never left for the allocator: one tail for every exit past the
     * read (buffer.h's rule — on failure the caller owns what the callee left).
     * secure_wipe answers a NULL pointer and a zero length itself, so the tail
     * is total without a guard. */
    secure_wipe(copy.data, copy.size);
    buffer_free(&copy);

    return err;
}

error_t *compare_buffer_to_disk(
    const buffer_t *content,
    const char *disk_path,
    git_filemode_t expected_mode,
    const struct stat *st,
    compare_result_t *result
) {
    CHECK_NULL(content);
    CHECK_NULL(disk_path);
    CHECK_NULL(st);
    CHECK_NULL(result);

    reference_t ref = { .content = content };
    return compare_reference_to_disk(&ref, disk_path, expected_mode, st, result);
}

error_t *compare_oid_to_disk(
    const git_oid *blob_oid,
    const char *disk_path,
    git_filemode_t expected_mode,
    const struct stat *st,
    compare_result_t *result
) {
    CHECK_NULL(blob_oid);
    CHECK_NULL(disk_path);
    CHECK_NULL(st);
    CHECK_NULL(result);

    reference_t ref = { .oid = blob_oid };
    return compare_reference_to_disk(&ref, disk_path, expected_mode, st, result);
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
 * target changes, from the two targets in hand — the reference's and the one
 * the caller's look read.
 */
static error_t *generate_symlink_diff(
    const buffer_t *content,
    const buffer_t *copy,
    compare_direction_t direction,
    char **diff_text
) {
    /* Format diff based on direction */
    error_t *err = NULL;
    buffer_t buf = BUFFER_INIT;

    err = buffer_append_string(&buf, "Symlink target changed:\n");
    if (err) goto cleanup;

    if (direction == CMP_DIR_UPSTREAM) {
        /* Upstream: show filesystem → repo (what apply would do) */
        err = buffer_append_string(&buf, "- ");
        if (!err) err = buffer_append(&buf, copy->data, copy->size);
        if (!err) err = buffer_append_string(&buf, "\n+ ");
        if (!err) err = buffer_append(&buf, content->data, content->size);
        if (!err) err = buffer_append_string(&buf, "\n");
    } else {
        /* Downstream: show repo → filesystem (what update would commit) */
        err = buffer_append_string(&buf, "- ");
        if (!err) err = buffer_append(&buf, content->data, content->size);
        if (!err) err = buffer_append_string(&buf, "\n+ ");
        if (!err) err = buffer_append(&buf, copy->data, copy->size);
        if (!err) err = buffer_append_string(&buf, "\n");
    }
    if (err) goto cleanup;

    /* Transfer ownership and free buffer structure */
    *diff_text = buffer_detach(&buf);

cleanup:
    buffer_free(&buf);
    return err;
}

/**
 * Generate text diff from buffer
 *
 * Helper for compare_generate_diff(). Uses in-memory buffers with libgit2's
 * buffer-based diff API — the reference's bytes and the ones the caller's look
 * read, both in hand.
 */
static error_t *generate_text_diff(
    const buffer_t *content,
    const buffer_t *copy,
    const char *path_label,
    compare_direction_t direction,
    char **diff_text
) {
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
            copy->data, copy->size, path_label,
            content->data, content->size, path_label,
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
            content->data, content->size, path_label,
            copy->data, copy->size, path_label,
            &diff_opts,
            NULL,  /* file callback */
            NULL,  /* binary callback */
            NULL,  /* hunk callback */
            diff_line_callback,
            &diff_output
        );
    }

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
 * Render the disk copy's difference from the reference — the renderer's own look
 */
error_t *compare_generate_diff(
    const buffer_t *content, const char *disk_path, const char *path_label,
    git_filemode_t mode, compare_direction_t direction, file_diff_t *out
) {
    CHECK_NULL(content);
    CHECK_NULL(disk_path);
    CHECK_NULL(path_label);
    CHECK_NULL(out);

    *out = (file_diff_t){ 0 };

    RETURN_IF_ERROR(validate_mode(mode));

    /* The look, then the verdict off it and the read of what it found. */
    struct stat st;
    buffer_t copy = BUFFER_INIT;
    error_t *err = NULL;

    if (fs_lstat(disk_path, &st) != 0) {
        if (errno != ENOENT && errno != ENOTDIR) {
            err = error_from_errno(errno, "Failed to stat '%s'", disk_path);
            goto cleanup;
        }

        /* Nothing stands here — the look met the absence (ENOTDIR: a component
         * above is no longer a directory — same absence). */
        out->status = CMP_MISSING;
    } else if (!mode_stands(&st, mode)) {
        out->status = CMP_TYPE_DIFF;
    } else {
        reference_t ref = { .content = content };
        err = judge_copy(&ref, disk_path, mode, &copy, &out->status);
        if (err) goto cleanup;
    }

    /* The text, by the verdict: a line where there is nothing to render, the
     * diff where there is, nothing at all for a copy that matches. A caller holding
     * its own words for a verdict drops the line (cmds/diff.c
     * compare_tree_files_to_filesystem, for CMP_MISSING and CMP_TYPE_DIFF). */
    switch (out->status) {
        case CMP_EQUAL:
            break;

        case CMP_MISSING:
            out->diff_text = strdup("File not deployed on disk");
            break;

        case CMP_TYPE_DIFF: {
            /* Both kinds named, the disk's off this function's own look.
             * fs_stat_noun reads the type bits whole, so a directory or a device
             * standing here is named rather than folded into "regular file". */
            int n = asprintf(
                &out->diff_text, "Type mismatch: expected %s, found %s",
                mode == GIT_FILEMODE_LINK ? "symlink" : "regular file", fs_stat_noun(&st)
            );
            if (n < 0) out->diff_text = NULL;
            break;
        }

        case CMP_DIFFERENT:
            err = mode == GIT_FILEMODE_LINK
                ? generate_symlink_diff(content, &copy, direction, &out->diff_text)
                : generate_text_diff(content, &copy, path_label, direction, &out->diff_text);
            if (err) goto cleanup;

            /* Binary files: libgit2 skips the line callback entirely when it
             * detects binary content, so generate_text_diff returns NULL. Provide
             * an explicit message rather than silent empty output. */
            if (!out->diff_text) out->diff_text = strdup("Binary files differ");
            break;
    }

cleanup:
    /* The disk copy, wiped before it is freed — compare_reference_to_disk's rule:
     * for an encrypted row it is the plaintext. */
    secure_wipe(copy.data, copy.size);
    buffer_free(&copy);

    return err;
}

/**
 * Free a rendering's text and reset it
 */
void compare_free_diff(file_diff_t *diff) {
    if (!diff) {
        return;
    }

    free(diff->diff_text);
    *diff = (file_diff_t){ 0 };
}
