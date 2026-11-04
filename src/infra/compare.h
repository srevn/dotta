/**
 * compare.h - File comparison engine
 *
 * Compares expected content with filesystem state, and prints the difference:
 *
 * 1. Buffer-based (compare_buffer_to_disk): Compares plaintext buffers provided
 *    by the content layer (src/infra/content.h). Used for encrypted files where
 *    the blob OID is a ciphertext hash that cannot be compared to the plaintext
 *    on disk.
 *
 * 2. OID-based (compare_oid_to_disk): Hashes the filesystem file and compares
 *    to an expected git blob OID. Used for non-encrypted files where OID comparison
 *    avoids expensive blob loading from pack files.
 *
 * 3. The patch (compare_generate_diff): the buffer form's ladder less its size,
 *    and where the bytes differ, libgit2's patch of them printed through the
 *    caller's line callback. It reaches its verdict through the same kind test
 *    and the same judgment as the two above, and hands back that verdict alone.
 *
 * All three judge the look their caller took and return compare_result_t for
 * uniform caller integration. None of them accesses the git repository or object
 * database — all operations are pure computation against the filesystem.
 *
 * Design principles:
 * - A blob's two spellings and a link are the whole domain: a mode outside them
 *   is the caller's bug, which dies in both ladders before the disk is touched
 * - A look is the caller's to take: the module is handed one and takes none
 * - The disk copy is wiped before it is freed, by whichever ladder read it: for
 *   an encrypted row it is the plaintext, the twin of the buffer the content
 *   cache wipes on its side. A patch made from it borrows it, each line pointing
 *   into the two sides (lib/libgit2/src/libgit2/diff_file.c
 *   git_diff_file_content__init_from_src), and is freed before the wipe, so no
 *   text of either side outlives the print. The rule covers the copies read here
 *   and not what libgit2 makes of them: each hunk's header, which quotes the
 *   line enclosing the hunk, is libgit2's own and freed plainly, where nothing
 *   above libgit2 can reach
 */

#ifndef DOTTA_COMPARE_H
#define DOTTA_COMPARE_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

/**
 * Comparison result — what a completed look found
 *
 * Total over a look that completed: the copy is the reference, it is the
 * reference's kind holding other bytes, nothing stands at the path, or another
 * kind does. A look that could not be made is none of them — it is the error
 * the function returns, and what a failure means is the caller's. This module
 * cannot know whether an unreadable path annotates a row or sinks the command,
 * and the tree answers it three ways: core/workspace.c workspace_analyze_file
 * and workspace_analyze_orphans mark the path (the item's fault, never fatal to
 * the load); the second question the first of them asks — ours against the base
 * — reads a failure as "not at base", the conservative answer; and cmds/diff.c
 * says it in the row's block and goes on — diff_print_item under the load's
 * verdict, diff_print_view by the failure's class (core/workspace.h
 * workspace_code_fault), and under --raw on stderr, the patch going on
 * (diff_write_patch).
 *
 * One verdict in the tree is reached from no look at all: core/workspace.h
 * workspace_compare_confirmed judges a row against a pair dotta already found
 * standing on disk, by this ladder — the kind, then the bytes — and answers in
 * these same words, so a fast path that skips the look says what the look would
 * have. CMP_MISSING is not among its answers: nothing is read, so no absence
 * can be met.
 *
 * NOTE: The claim — the mode and the ownership — is explicitly NOT part of this
 * module. The compare module is infrastructure-layer, handling only content and
 * type. A claim's compare (the git filemode resolved into the mode, the rest
 * from .dotta/metadata.json) is a core-layer concern: core/workspace.c
 * workspace_analyze_claim for a row, workspace_compare_orphan for a record.
 */
typedef enum {
    CMP_EQUAL,      /* The copy is the reference — kind and content */
    CMP_DIFFERENT,  /* The reference's kind, other bytes */
    CMP_MISSING,    /* Nothing stands there — the look met the absence */
    CMP_TYPE_DIFF   /* Another kind does — a link, a directory, a device */
} compare_result_t;

/**
 * Does the disk copy hold these bytes? — the pair's buffer form
 *
 * The caller's look at the disk copy, judged against the plaintext bytes it should
 * hold. The ladder, in order:
 * 1. The kind the expected mode names is the kind the look found
 * 2. A regular file's size, which a buffer knows: another is a verdict with no
 *    open needed. A link's st_size is the filesystem's to mean, and is not asked
 * 3. The bytes — a link's target, or a regular file's through one descriptor,
 *    the length the look covers read exactly: never past it, and refused where
 *    the file holds fewer (sys/filesystem.h fs_read_fd) — compared byte for byte
 *
 * The look is the caller's: the stat it took before it called, required, taken
 * nowhere here and handed back nowhere. Steps 1 and 2 are asked off it, so the
 * pair spends no syscall of its own before step 3, and a caller that wants a
 * look takes one.
 *
 * CMP_MISSING means the *read* met the absence — ENOENT/ENOTDIR at the open, or
 * ERR_NOT_FOUND from the link's read — so the path left between the caller's
 * look and it, and the caller learns its look is one moment stale. Absence at
 * the look's own moment is the caller's own to name, in whatever vocabulary that
 * caller keeps for it; it never reaches here. A file shorter than the look is a
 * failed look (ERR_CONFLICT), never a verdict. compare_oid_to_disk answers both
 * in the same words: they are the one thing the pair's two forms must not answer
 * apart.
 *
 * Pure with respect to git and encryption: zero blob loading, zero decryption.
 * The bytes are the caller's, an encrypted row's plaintext among them, which
 * the content layer decrypted (infra/content.h).
 *
 * @param content Buffer containing expected content (must not be NULL)
 * @param disk_path Path to file on disk (must not be NULL)
 * @param expected_mode Expected git filemode (for type/mode checking)
 * @param st The look the caller took at disk_path (must not be NULL)
 * @param result Comparison result (must not be NULL)
 * @return Error or NULL on success
 */
error_t compare_buffer_to_disk(
    const buffer_t *content,
    const char *disk_path,
    git_filemode_t expected_mode,
    const struct stat *st,
    compare_result_t *result
);

/**
 * Does the disk copy hold this blob? — the pair's id form, plaintext blobs only
 *
 * The caller's look at the disk copy, judged against the blob's id: the ladder
 * and the look compare_buffer_to_disk states, less its size — an id knows none.
 * The kind the expected mode names is asked off the look; then the bytes — a
 * link's target, or a regular file's through one descriptor, the length the look
 * covers read exactly — are hashed as Git hashes a blob, SHA-1("blob <size>\0"
 * + bytes), Git's model of a link being a blob that holds its target, and the
 * ids compared, so a file's match is one at the look's length too. Pure with
 * respect to git and encryption: zero blob loading, zero decryption.
 *
 * Plaintext blobs only: an encrypted blob's id is the hash of ciphertext, while
 * the filesystem holds plaintext, so the comparison would never match. One rule,
 * and one reader keeping it: the caller must hold a stamp that is *this* blob's
 * own, made byte-true at the write boundary (the write-time invariant in
 * `infra/content.h content_capture_file`) — a stale or wrong-blob flag silently
 * misroutes. That reader is `core/workspace.c workspace_analyze_file`'s first
 * question, which reads `row->encrypted` for the row's own blob. A comparison
 * against a blob no stamp speaks for takes the buffer form, its kind and its
 * bytes coming off one read (`infra/content.h content_compare_blob_to_disk`).
 *
 * CMP_MISSING means the *read* met the absence — ENOENT/ENOTDIR at the open, or
 * ERR_NOT_FOUND from the link's read — so the path left between the caller's
 * look and it, and the caller learns its look is one moment stale. Absence at
 * the look's own moment is the caller's own to name, in whatever vocabulary that
 * caller keeps for it; it never reaches here. A file shorter than the look is a
 * failed look (ERR_CONFLICT), never a verdict. compare_buffer_to_disk answers
 * both in the same words: they are the one thing the pair's two forms must not
 * answer apart.
 *
 * @param blob_oid Expected blob OID from manifest (must not be NULL)
 * @param disk_path Path to file on disk (must not be NULL)
 * @param expected_mode Expected git filemode (BLOB, BLOB_EXECUTABLE, or LINK)
 * @param st The look the caller took at disk_path (must not be NULL)
 * @param result Comparison result (must not be NULL)
 * @return Error or NULL on success
 */
error_t compare_oid_to_disk(
    const git_oid *blob_oid,
    const char *disk_path,
    git_filemode_t expected_mode,
    const struct stat *st,
    compare_result_t *result
);

/**
 * Diff direction for compare_generate_diff()
 *
 * Controls which side is treated as "old" and "new" in the patch:
 *   CMP_DIR_UPSTREAM:   old=filesystem, new=repo — '-' is current disk content,
 *                       '+' is repo content apply would write.
 *   CMP_DIR_DOWNSTREAM: old=repo, new=filesystem — '-' is repo content, '+' is
 *                       local changes update would commit.
 */
typedef enum {
    CMP_DIR_UPSTREAM,    /* old=filesystem, new=repo (what apply would write) */
    CMP_DIR_DOWNSTREAM   /* old=repo, new=filesystem (what update would commit) */
} compare_direction_t;

/**
 * Print the disk copy's difference from the reference, off the caller's look
 *
 * The buffer form's ladder (compare_buffer_to_disk) over the look the caller
 * took — the mode, the kind off the look, then one read of the bytes it covers,
 * judged — less the size, since a patch needs the bytes a size would answer
 * without. Where they differ, libgit2's patch of the two buffers, both named
 * `path_label`, at libgit2's defaults — three lines of context, no hunk joined
 * — is handed to `print` line by line as libgit2 hands it: the file header once,
 * before the first hunk or the one binary line, then each hunk's header and lines
 * (lib/libgit2/src/libgit2/diff_print.c git_patch_print). A patch made from buffers
 * carries no mode, so it names both sides 100644, and its index line names each
 * by its plaintext's blob id (stated). Every other verdict prints nothing: another
 * kind is the caller's to draw, off the look it holds, and CMP_MISSING is the
 * read's, as the pair's — absence at the look's own moment is the caller's to name.
 *
 * The read is bounded by the look: a copy rewritten after it is judged and printed
 * at the look's length, as the pair judges one, and the next run reads it whole
 * (stated). `print`'s non-zero ends the print and comes back as libgit2's generic
 * error (lib/libgit2/src/util/errors.h git_error_set_after_callback_function):
 * a caller that needs why keeps it in its payload.
 *
 * @param content The reference's plaintext, e.g. decrypted (must not be NULL)
 * @param disk_path Disk file path (must not be NULL)
 * @param path_label The name both sides of the patch carry (must not be NULL)
 * @param mode Expected git filemode
 * @param st The look the caller took at disk_path (must not be NULL)
 * @param direction Which side the patch shows first
 * @param print Handed each line of the patch (must not be NULL)
 * @param payload Handed to `print` beside each line
 * @param result Comparison result (must not be NULL)
 * @return Error or NULL on success
 */
error_t compare_generate_diff(
    const buffer_t *content,
    const char *disk_path,
    const char *path_label,
    git_filemode_t mode,
    const struct stat *st,
    compare_direction_t direction,
    git_diff_line_cb print,
    void *payload,
    compare_result_t *result
);

/**
 * The text of a type mismatch: the kind a mode names, and the kind a look found
 *
 * "Type mismatch: expected <kind>, found <kind>", both kinds in one function's
 * words (sys/filesystem.h fs_stat_noun). Off whichever look the caller holds,
 * so the line a CMP_TYPE_DIFF verdict prints is one sentence wherever that verdict
 * was reached.
 *
 * Readers: cmds/diff.c diff_print_mismatch, the body diff draws where another
 * kind stands — off the workspace load's look, where no blob is read (a directory
 * row's among them), the render's, or the commit arm's own. A reader not on this
 * list is a bug.
 *
 * @param mode The mode the reference expects: a blob's two spellings, a link,
 *             or a tree — a directory row's, which no comparison takes but this
 *             sentence names
 * @param st The look that found another kind standing (must not be NULL)
 * @return The text, the caller's to free
 */
char *compare_type_mismatch(git_filemode_t mode, const struct stat *st);

#endif /* DOTTA_COMPARE_H */
