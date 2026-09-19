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
 * - Handle all file types (regular, symlink)
 * - Clear comparison results
 * - A look is the caller's to take: the pair is handed one and takes none
 * - The disk copy is wiped before it is freed, by whichever of the two callers
 *   took it: for an encrypted row it is the plaintext, the twin of the buffer
 *   the content cache wipes on its side
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
 * and the tree answers it three ways: core/workspace.c analyze_file_divergence
 * and analyze_orphans hold the path (DIVERGENCE_UNVERIFIED and a fault class,
 * never fatal to the load); the second question the first of them asks — ours
 * against the base — reads a failure as "not at base", the conservative answer;
 * cmds/diff.c show_file_diff_from_workspace and compare_tree_files_to_filesystem
 * fail the run.
 *
 * NOTE: Permission checking is explicitly NOT part of this module. The compare
 * module is infrastructure-layer, handling only content and type. Permission
 * validation (git filemode + full metadata) is a core-layer concern handled by
 * workspace.c using metadata from .dotta/metadata.json.
 */
typedef enum {
    CMP_EQUAL,      /* The copy is the reference — kind and content */
    CMP_DIFFERENT,  /* The reference's kind, other bytes */
    CMP_MISSING,    /* Nothing stands there — the look met the absence */
    CMP_TYPE_DIFF   /* Another kind does — a link, a directory, a device */
} compare_result_t;

/**
 * A rendering: the verdict the renderer's own look reached, and the text for it
 *
 * The struct is the caller's — a stack local, cleared by compare_generate_diff
 * once its arguments are accepted — and one thing in it is owned: `diff_text`,
 * which compare_free_diff frees and resets. NULL there is a copy that matches;
 * every other verdict has a text, which a caller holding its own words for that
 * verdict may ignore.
 */
typedef struct {
    compare_result_t status; /* what the look found */
    char *diff_text;         /* the text for it, NULL for a match */
} file_diff_t;

/**
 * Does the disk copy match the reference? — the pair
 *
 * The caller's look at the disk copy, judged against a reference in one of two
 * encodings: the plaintext bytes (compare_buffer_to_disk) or the blob's id
 * (compare_oid_to_disk). The ladder is the same for both — the type against the
 * expected mode, then a link's target or a file's bytes through one descriptor
 * — and the encoding matters at two points only: a buffer knows its size, so a
 * size that differs is a verdict with no open needed; and the judgment is memcmp
 * for a buffer, hash-and-compare for an id (SHA-1("blob <size>\0" + bytes), Git's
 * own — a symlink is a blob holding its target). Pure with respect to git and
 * encryption otherwise: zero blob loading, zero decryption.
 *
 * The ladder, in order:
 * 1. The kind the expected mode names is the kind the look found
 * 2. For a buffer, the size — a difference here is a verdict with no open
 * 3. The bytes, read and judged (byte-for-byte, or by id)
 *
 * The look is the caller's: the stat it took before it called, required, taken
 * nowhere here and handed back nowhere. Steps 1 and 2 are asked off it, so the
 * pair spends no syscall of its own before step 3, and a caller that wants a
 * look takes one — compare_generate_diff below is the module's only looker.
 *
 * CMP_MISSING means the *read* met the absence — ENOENT/ENOTDIR at the open, or
 * ERR_NOT_FOUND from the link's read — so the path left between the caller's
 * look and it, and the caller learns its look is one moment stale. Absence at
 * the look's own moment is the caller's own to name, in whatever vocabulary that
 * caller keeps for it; it never reaches here.
 *
 * The id form is for plaintext blobs only: an encrypted blob's id is the hash
 * of ciphertext, while the filesystem holds plaintext, so the comparison would
 * never match. Two safe paths:
 *   - The kind-routing primitive `content_compare_blob_to_disk` decides internally
 *     and is always safe.
 *   - Direct callers must gate on a byte-truth flag (e.g.,
 *     `manifest_entry->encrypted`, byte-derived via the Phase 2 write-time
 *     invariant in `content_stage_file`); a stale or wrong-blob flag silently
 *     misroutes.
 */

/**
 * The buffer form of the pair above
 *
 * @param content Buffer containing expected content (must not be NULL)
 * @param disk_path Path to file on disk (must not be NULL)
 * @param expected_mode Expected git filemode (for type/mode checking)
 * @param st The look the caller took at disk_path (must not be NULL)
 * @param result Comparison result (must not be NULL)
 * @return Error or NULL on success
 */
error_t *compare_buffer_to_disk(
    const buffer_t *content,
    const char *disk_path,
    git_filemode_t expected_mode,
    const struct stat *st,
    compare_result_t *result
);

/**
 * The id form of the pair above — plaintext blobs only
 *
 * @param blob_oid Expected blob OID from manifest (must not be NULL)
 * @param disk_path Path to file on disk (must not be NULL)
 * @param expected_mode Expected git filemode (BLOB, BLOB_EXECUTABLE, or LINK)
 * @param st The look the caller took at disk_path (must not be NULL)
 * @param result Comparison result (must not be NULL)
 * @return Error or NULL on success
 */
error_t *compare_oid_to_disk(
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
 * Render the disk copy's difference from the reference — the renderer's own look
 *
 * One lstat names what stands at the path; where it is the kind the mode expects,
 * one read takes the bytes that are judged and, where they differ, rendered. So
 * a file is read once, and no stat is carried out of a comparison to make it
 * happen: the pair above returns a verdict and nothing else, and a caller that
 * wants a look takes one.
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
 * @param out Rendering (must not be NULL; cleared on entry, and left cleared on
 *            failure, so freeing it is correct either way)
 * @return Error or NULL on success
 */
error_t *compare_generate_diff(
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
 * buffer_free's shape: the contents go, the struct stays the caller's and is
 * left as if it had never been filled. Safe on a cleared struct, and safe twice.
 *
 * @param diff Rendering (can be NULL)
 */
void compare_free_diff(file_diff_t *diff);

#endif /* DOTTA_COMPARE_H */
