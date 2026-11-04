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
#include "base/heap.h"
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
static error_t judge(
    const reference_t *ref, const buffer_t *copy, const char *disk_path,
    compare_result_t *result
) {
    if (ref->content) {
        /* The sizes first. The copy holds exactly its look's length (read_copy),
         * which the pair asked against the buffer already, so there the two agree;
         * the renderer, whose look no size was asked of, meets another here.
         * Two empty byte sequences are equal, and nothing is asked of a pointer
         * to say so: memcmp is undefined over a null pointer even across zero
         * bytes, and an empty buffer may carry none (base/buffer.h's zero state).
         * Content's read makes an empty entry a C string (infra/content.c
         * content_plaintext), but the reference is whatever buffer the caller
         * hands in. */
        bool equal = (copy->size == ref->content->size) && (copy->size == 0 ||
            memcmp(ref->content->data, copy->data, copy->size) == 0);
        *result = equal ? CMP_EQUAL : CMP_DIFFERENT;
        return NULL;
    }

    git_oid computed;
    if (git_odb_hash(&computed, copy->data, copy->size, GIT_OBJECT_BLOB) != 0) {
        return error_create(
            ERR_GIT, "Failed to hash '%s': %s", disk_path, git_error_last()->message
        );
    }

    *result = git_oid_equal(ref->oid, &computed) ? CMP_EQUAL : CMP_DIFFERENT;

    return NULL;
}

/**
 * The modes a comparison is defined over
 *
 * A blob's two spellings and a link: what a file row's type becomes (sys/gitops.h
 * gitops_type_filemode). A tree — which that same function returns for a directory
 * row — or a mode from nowhere is the caller's bug, and dies in both ladders
 * before either touches the disk: read as a blob, a directory would be opened
 * and judged, and mode_stands below would ask a regular file's question about
 * it. Every caller maps a file row's type, and a tree entry's filemode reaches
 * none: the profile keys a blob's type off its entry (core/profiles.c
 * profile_decode_blob) and a gitlink claims nothing there. The type mismatch's
 * sentence takes no look, so it asks a domain of its own, a tree's mode among
 * it (compare_type_mismatch).
 *
 * Asked first in both ladders, so one caller error has one answer wherever it
 * is made. It used to sit after the pair's own stat, where an unsupported mode
 * at an absent path read CMP_MISSING and the same mode at a live one was refused
 * — one mistake, answered by what happened to stand at the path.
 */
static void validate_mode(git_filemode_t expected_mode) {
    CHECK_ARG(
        expected_mode == GIT_FILEMODE_LINK || expected_mode == GIT_FILEMODE_BLOB ||
        expected_mode == GIT_FILEMODE_BLOB_EXECUTABLE,
        "a comparison is defined over a blob's two modes and a link's"
    );
}

/**
 * Does the look find the kind the expected mode names standing?
 *
 * A link for GIT_FILEMODE_LINK; a regular file — not a directory, device, FIFO,
 * socket, or a link — for either blob mode, which is the whole of the domain
 * validate_mode admits. Two readers that must not disagree about one path: the
 * pair and the renderer, each answering CMP_TYPE_DIFF off its caller's look where
 * it says no. The division is the kind's (core/workspace.h workspace_type_occupant,
 * over a path_type_t in the look's words), asked here over a stat and a git
 * filemode — the vocabulary each layer speaks.
 */
static bool mode_stands(const struct stat *st, git_filemode_t expected_mode) {
    return expected_mode == GIT_FILEMODE_LINK ? S_ISLNK(st->st_mode)
                                              : S_ISREG(st->st_mode);
}

/**
 * The disk copy's bytes, as Git would hash them
 *
 * A link's target or a regular file's content — the bytes a blob at this path
 * holds — read after the look found the expected kind standing: the caller's
 * look, whichever ladder it was handed to. A regular file is read through one
 * descriptor, exactly the length the look recorded, as Git's refresh reads one
 * (lib/git/read-cache.c ce_compare_data, index_fd handed the lstat it took): so
 * an id judged equal is equal at the look's length, and the triple a caller
 * distills from that look stands behind the blob's own length.
 *
 * O_NOFOLLOW refuses a symlink swapped in since the look (ELOOP); O_NONBLOCK
 * keeps a swapped-in FIFO from wedging the open. Any other node swapped in since
 * is read no further than the look's extent and judged so, for that look: a file
 * renamed over whose first bytes, to the old look's length, are the reference's
 * reads equal, and the next look finds the new inode the triple does not name
 * (stated, as Git's refresh reads it). A file that shrank since the look is
 * refused: the bytes the look covers are not there to judge, and the caller reads
 * a failed look, never a verdict. libgit2's git_odb_hashfile would open the path
 * itself — a look sys/filesystem does not make (filesystem.h's funnel), and with
 * it the errno the absence rule needs. The whole copy is in memory for the length
 * of the judgment, bounded by the look's extent, which the read refuses past
 * the cap.
 *
 * Absence is the caller's to read: ENOENT/ENOTDIR at the open, or from the link's
 * read, come back as ERR_NOT_FOUND — the path left between the look and this
 * read. One reader, judge_copy, which maps that one code to CMP_MISSING and every
 * other failure to a failed look, so the absence rule compare.h states on each
 * of the pair's two forms is spelled once.
 */
static error_t read_copy(
    const char *disk_path, git_filemode_t expected_mode, const struct stat *st,
    buffer_t *out
) {
    /* A link's target is its bytes, read into the buffer as a file's are: its
     * st_size is the filesystem's to mean, so the look bounds no target */
    if (expected_mode == GIT_FILEMODE_LINK) return fs_read_symlink(disk_path, out);

    /* fs_read_fd clears this too, but a failed open never reaches it. */
    *out = (buffer_t){ 0 };

    int fd = fs_open(disk_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0) {
        return error_errno(errno, "Failed to open '%s'", disk_path);
    }

    error_t err = fs_read_fd(fd, st, out);
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
 * and a patch printed off the renderer's cannot call one path two things.
 *
 * The look is the ladder's caller's, and bounds the read (read_copy). `copy` is
 * filled whole and is the caller's on every exit: wiped and freed by whichever
 * of the two ladders took it, whatever the verdict (compare.h).
 */
static error_t judge_copy(
    const reference_t *ref, const char *disk_path, git_filemode_t expected_mode,
    const struct stat *st, buffer_t *copy, compare_result_t *result
) {
    error_t err = read_copy(disk_path, expected_mode, st, copy);

    if (!err) {
        return judge(ref, copy, disk_path, result);
    }
    if (error_code(err) != ERR_NOT_FOUND) {
        return err;
    }

    /* The read met the absence: the path left between the look and the read. A
     * verdict, not a failed look, and the read's error is dropped — one per path
     * that left in that window. */
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
 * bytes a patch is printed from.
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
static error_t compare_reference_to_disk(
    const reference_t *ref, const char *disk_path, git_filemode_t expected_mode,
    const struct stat *st, compare_result_t *result
) {
    validate_mode(expected_mode);

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
    error_t err = judge_copy(ref, disk_path, expected_mode, st, &copy, result);

    /* For an encrypted row the disk copy is the plaintext — the twin of the buffer
     * the content cache wipes before it frees. Wiped like it, whatever the read
     * left, and never left for the allocator: one tail for every exit past the
     * read (buffer.h's rule — on failure the caller owns what the callee left).
     * secure_wipe answers a NULL pointer and a zero length itself, so the tail
     * is total without a guard. */
    secure_wipe(copy.data, copy.size);
    buffer_deinit(&copy);

    return err;
}

error_t compare_buffer_to_disk(
    const buffer_t *content, const char *disk_path, git_filemode_t expected_mode,
    const struct stat *st, compare_result_t *result
) {
    CHECK_NULL(content);
    CHECK_NULL(disk_path);
    CHECK_NULL(st);
    CHECK_NULL(result);

    reference_t ref = { .content = content };
    return compare_reference_to_disk(&ref, disk_path, expected_mode, st, result);
}

error_t compare_oid_to_disk(
    const git_oid *blob_oid, const char *disk_path, git_filemode_t expected_mode,
    const struct stat *st, compare_result_t *result
) {
    CHECK_NULL(blob_oid);
    CHECK_NULL(disk_path);
    CHECK_NULL(st);
    CHECK_NULL(result);

    reference_t ref = { .oid = blob_oid };
    return compare_reference_to_disk(&ref, disk_path, expected_mode, st, result);
}

/**
 * Print the patch from one side to the other through the caller's callback
 *
 * libgit2's patch of two buffers under one name, at its defaults — three lines
 * of context, no hunk joined (lib/libgit2/src/libgit2/diff_xdiff.c git_xdiff_init,
 * handed no options) — printed whole and freed before this returns: the patch
 * borrows both buffers for its lines, so the copy it was made from is wiped after
 * it is gone (compare_generate_diff). An empty side is content, handed as "": a
 * NULL side is an absence to libgit2, which would print the patch of an addition
 * or a deletion, and a buffer's zero state carries no data (base/buffer.h) —
 * judge answers the same state for itself.
 */
static error_t compare_print_patch(
    const buffer_t *old_side, const buffer_t *new_side, const char *path_label,
    git_diff_line_cb print, void *payload
) {
    git_patch *patch = NULL;
    int rc = git_patch_from_buffers(
        &patch, old_side->data ? old_side->data : "", old_side->size, path_label,
        new_side->data ? new_side->data : "", new_side->size, path_label, NULL
    );
    if (rc < 0) {
        return error_git(rc, "Cannot compare the two versions of '%s'", path_label);
    }

    rc = git_patch_print(patch, print, payload);
    error_t err = rc < 0 ? error_git(rc, "Cannot print the patch of '%s'", path_label) : NULL;
    git_patch_free(patch);

    return err;
}

/**
 * Print the disk copy's difference from the reference, off the caller's look
 */
error_t compare_generate_diff(
    const buffer_t *content, const char *disk_path, const char *path_label,
    git_filemode_t mode, const struct stat *st, compare_direction_t direction,
    git_diff_line_cb print, void *payload, compare_result_t *result
) {
    CHECK_NULL(content);
    CHECK_NULL(disk_path);
    CHECK_NULL(path_label);
    CHECK_NULL(st);
    CHECK_NULL(print);
    CHECK_NULL(result);

    validate_mode(mode);

    /* Does disk hold the kind the mode names? Off the caller's look, no syscall,
     * and nothing printed: the caller holds the look that found another kind */
    if (!mode_stands(st, mode)) {
        *result = CMP_TYPE_DIFF;
        return NULL;
    }

    /* No size is asked, as compare_reference_to_disk asks one: a patch needs
     * the bytes a size would answer without */
    reference_t ref = { .content = content };
    buffer_t copy = BUFFER_INIT;
    error_t err = judge_copy(&ref, disk_path, mode, st, &copy, result);

    if (!err && *result == CMP_DIFFERENT) {
        /* Which side the hunk shows first, read off the direction once for the
         * module: upstream prints disk → repo, what apply would write; downstream
         * repo → disk, what update would commit. */
        const buffer_t *old_side = direction == CMP_DIR_UPSTREAM ? &copy : content;
        const buffer_t *new_side = direction == CMP_DIR_UPSTREAM ? content : &copy;

        err = compare_print_patch(old_side, new_side, path_label, print, payload);
    }

    /* The disk copy, wiped before it is freed, as compare_reference_to_disk wipes
     * its own: for an encrypted row it is the plaintext, and the patch that
     * borrowed it is gone */
    secure_wipe(copy.data, copy.size);
    buffer_deinit(&copy);

    return err;
}

/**
 * The text of a type mismatch: the kind a mode names, and the kind a look found
 */
char *compare_type_mismatch(git_filemode_t mode, const struct stat *st) {
    CHECK_NULL(st);

    /* The comparisons' domain and a tree's: a sentence takes no look, so the
     * mode a directory row stands as is named here, where both ladders refuse
     * it (validate_mode) */
    CHECK_ARG(
        mode == GIT_FILEMODE_LINK || mode == GIT_FILEMODE_BLOB ||
        mode == GIT_FILEMODE_BLOB_EXECUTABLE || mode == GIT_FILEMODE_TREE,
        "a type mismatch is named over a blob's two modes, a link's and a tree's"
    );

    /* fs_stat_noun reads the type bits whole, so a directory or a device standing
     * here is named rather than folded into "regular file"; the expected kind
     * is spelled in that same function's words, so the two halves of one sentence
     * name their kinds alike */
    return heap_str_format(
        "Type mismatch: expected %s, found %s",
        mode == GIT_FILEMODE_LINK ? "symlink" :
        mode == GIT_FILEMODE_TREE ? "directory" : "regular file",
        fs_stat_noun(st)
    );
}
