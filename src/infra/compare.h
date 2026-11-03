/**
 * compare.h - File comparison engine
 *
 * Compares expected content with filesystem state, and renders the difference:
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
 * 3. Rendering (compare_generate_diff): the module's one look, taken for itself
 *    rather than for a caller, and the bytes it read rendered as a unified diff.
 *    It reaches its verdict through the same kind test and the same judgment as
 *    the two above, and hands nothing else back — the pair returns a verdict,
 *    and a caller that wants a look takes one.
 *
 * The first two judge the look their caller took, and all three return
 * compare_result_t for uniform caller integration. None of them accesses the
 * git repository or object database — all operations are pure computation against
 * the filesystem.
 *
 * Design principles:
 * - A blob's two spellings and a link are the whole domain: a mode outside them
 *   is the caller's bug, which dies in both ladders before the disk is touched
 * - A look is the caller's to take: the pair is handed one and takes none
 * - The disk copy is wiped before it is freed, by whichever of the two callers
 *   took it: for an encrypted row it is the plaintext, the twin of the buffer
 *   the content cache wipes on its side. The rule covers the copies read here
 *   and not a rendering made from them: git_diff_buffers takes both sides into
 *   structures of its own and frees them plainly, where nothing above libgit2
 *   can reach, so file_diff_t.diff_text is freed plainly too — a wipe there would
 *   make the rule read total while half of the plaintext stayed loose
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
 * and the tree answers it four ways: core/workspace.c workspace_analyze_file
 * and workspace_analyze_orphans mark the path (the item's fault, never fatal to
 * the load); the second question the first of them asks — ours against the base
 * — reads a failure as "not at base", the conservative answer; cmds/diff.c
 * diff_print_item says it in the row's block and goes on; diff_print_view fails
 * the run.
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
 * 3. The bytes — a link's target, or a regular file's read through one descriptor
 *    — compared byte for byte
 *
 * The look is the caller's: the stat it took before it called, required, taken
 * nowhere here and handed back nowhere. Steps 1 and 2 are asked off it, so the
 * pair spends no syscall of its own before step 3, and a caller that wants a
 * look takes one — compare_generate_diff is the module's only looker.
 *
 * CMP_MISSING means the *read* met the absence — ENOENT/ENOTDIR at the open, or
 * ERR_NOT_FOUND from the link's read — so the path left between the caller's
 * look and it, and the caller learns its look is one moment stale. Absence at
 * the look's own moment is the caller's own to name, in whatever vocabulary that
 * caller keeps for it; it never reaches here. compare_oid_to_disk answers it in
 * the same words: it is the one thing the pair's two forms must not answer apart.
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
 * link's target, or a regular file's read through one descriptor — are hashed
 * as Git hashes a blob, SHA-1("blob <size>\0" + bytes), Git's model of a link
 * being a blob that holds its target, and the ids compared. Pure with respect
 * to git and encryption: zero blob loading, zero decryption.
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
 * caller keeps for it; it never reaches here. compare_buffer_to_disk answers it
 * in the same words: it is the one thing the pair's two forms must not answer
 * apart.
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
 * Controls which side is treated as "old" and "new" in the unified diff:
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
 * A rendering: the verdict a look reached, and the text for it
 *
 * The struct is the caller's — a stack local, cleared by compare_generate_diff
 * once its arguments are accepted, or filled whole by a caller that holds a verdict
 * of its own and the text for it (cmds/diff.c diff_print_item, a kind off the
 * load's look) — and one thing in it is owned: `diff_text`, which
 * compare_diff_deinit frees, resetting the whole struct with it, the verdict
 * too. NULL there is a copy that matches; every other verdict has a text, which
 * a caller holding its own words for that verdict may ignore.
 */
typedef struct {
    compare_result_t status; /* what the look found */
    char *diff_text;         /* the text for it, NULL for a match */
} file_diff_t;

/**
 * Render the disk copy's difference from the reference — the renderer's own look
 *
 * One lstat names what stands at the path; where it is the kind the mode expects,
 * one read takes the bytes that are judged and, where they differ, rendered. So
 * a file is read once, and no stat is carried out of a comparison to make it
 * happen: the pair (compare_buffer_to_disk, compare_oid_to_disk) returns a verdict
 * and nothing else, and a caller that wants a look takes one.
 *
 * `out->status` is that look's verdict, reached through the same judge and the
 * same kind test the pair uses, so a status line printed from one and a text
 * rendered by the other cannot call one path two things. A caller with no verdict
 * of its own reads it here rather than comparing first; a caller that already
 * holds one gets a look one moment fresher, and where the disk moved since, a
 * text that says so.
 *
 * Works with decrypted content from the content layer. Uses libgit2's
 * git_diff_buffers for pure in-memory diff generation.
 *
 * @param content Content buffer (e.g., decrypted content, must not be NULL)
 * @param disk_path Disk file path (must not be NULL)
 * @param path_label Label for diff output (must not be NULL)
 * @param mode Expected git filemode (for type/mode checking)
 * @param direction Diff direction
 * @param out Rendering (must not be NULL; cleared once the arguments are accepted,
 *            and left owning nothing on failure, so freeing it is correct either
 *            way)
 * @return Error or NULL on success
 */
error_t compare_generate_diff(
    const buffer_t *content,
    const char *disk_path,
    const char *path_label,
    git_filemode_t mode,
    compare_direction_t direction,
    file_diff_t *out
);

/**
 * Free a rendering's text and reset it
 *
 * buffer_deinit's shape: the contents go, the struct stays the caller's and is
 * left as if it had never been filled. Safe on a cleared struct, and safe twice.
 *
 * @param diff Rendering (can be NULL)
 */
void compare_diff_deinit(file_diff_t *diff);

/**
 * The text of a type mismatch: the kind a mode names, and the kind a look found
 *
 * "Type mismatch: expected <kind>, found <kind>", both kinds in one function's
 * words (sys/filesystem.h fs_stat_noun). Off whichever look the caller holds,
 * so the line a CMP_TYPE_DIFF verdict prints is one sentence wherever that verdict
 * was reached.
 *
 * Readers: compare_generate_diff (its own look's CMP_TYPE_DIFF), cmds/diff.c
 * diff_print_item (the load's look, where a row's kind is not what stands and
 * no blob is read — a directory row's among them). A reader not on this list is
 * a bug.
 *
 * @param mode The mode the reference expects: a blob's two spellings, a link,
 *             or a tree — a directory row's, which no comparison takes but this
 *             sentence names
 * @param st The look that found another kind standing (must not be NULL)
 * @return The text, the caller's to free
 */
char *compare_type_mismatch(git_filemode_t mode, const struct stat *st);

#endif /* DOTTA_COMPARE_H */
