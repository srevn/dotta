/**
 * compare.h - File comparison engine
 *
 * Compares expected content with filesystem state using two strategies:
 *
 * 1. Buffer-based (compare_buffer_to_disk):
 *    Compares plaintext buffers provided by the content layer
 *    (src/infra/content.h). Used for encrypted files where the blob OID
 *    is a ciphertext hash that cannot be compared to the plaintext on disk.
 *
 * 2. OID-based (compare_oid_to_disk):
 *    Hashes the filesystem file and compares to an expected git blob OID.
 *    Used for non-encrypted files where OID comparison avoids expensive
 *    blob loading from pack files.
 *
 * Both strategies share the same stat propagation convention and return
 * compare_result_t for uniform caller integration. Neither strategy
 * accesses the git repository or object database — all operations are
 * pure computation against the filesystem.
 *
 * Design principles:
 * - Handle all file types (regular, symlink)
 * - Compare permissions accurately (executable bit)
 * - Clear comparison results
 * - Stat propagation to minimize redundant syscalls
 */

#ifndef DOTTA_COMPARE_H
#define DOTTA_COMPARE_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

/**
 * Comparison result
 *
 * NOTE: Permission checking is explicitly NOT part of this module.
 * The compare module is infrastructure-layer, handling only content and type.
 * Permission validation (git filemode + full metadata) is a core-layer concern
 * handled by workspace.c using metadata from .dotta/metadata.json.
 */
typedef enum {
    CMP_EQUAL,       /* Files are identical (content and type) */
    CMP_DIFFERENT,   /* Files have different content */
    CMP_MISSING,     /* File doesn't exist on disk */
    CMP_TYPE_DIFF,   /* Different types (file vs symlink) */
    CMP_UNVERIFIED   /* Verification skipped (file too large or error) */
} compare_result_t;

/**
 * File diff information
 */
typedef struct {
    char *path;              /* File path */
    compare_result_t status; /* Comparison status */
    char *diff_text;         /* Diff output (can be NULL) */
} file_diff_t;

/**
 * Compare buffer content to disk file (with stat propagation)
 *
 * Pure function with zero git/encryption knowledge.
 * Compares plaintext buffer to file on disk.
 *
 * Tests:
 * 1. File exists on disk
 * 2. File type matches (regular/symlink)
 * 3. Content matches (byte-for-byte)
 *
 * Stat propagation optimization:
 * - If in_stat != NULL: Uses provided stat data (zero syscalls)
 * - If in_stat == NULL: Performs lstat() internally
 * - If out_stat != NULL: Returns stat data for caller reuse
 * - Single stat used for all checks (type, size, mode)
 *
 * This eliminates redundant stat calls when integrated with metadata
 * checking, reducing filesystem syscalls by ~5x in hot paths.
 *
 * @param content Buffer containing expected content (must not be NULL)
 * @param disk_path Path to file on disk (must not be NULL)
 * @param expected_mode Expected git filemode (for type/mode checking)
 * @param in_stat Optional pre-captured stat (can be NULL for internal lstat)
 * @param result Comparison result (must not be NULL)
 * @param out_stat Optional stat output (can be NULL, filled if provided)
 * @return Error or NULL on success
 */
error_t *compare_buffer_to_disk(
    const buffer_t *content,
    const char *disk_path,
    git_filemode_t expected_mode,
    const struct stat *in_stat,
    compare_result_t *result,
    struct stat *out_stat
);

/**
 * Compare git blob OID to disk file (with stat propagation)
 *
 * OID-based comparison for non-encrypted files. Hashes the filesystem
 * file using the standard git blob hash algorithm and compares to the
 * expected blob OID. This avoids expensive blob loading from pack files.
 *
 * IMPORTANT: Only call for NON-ENCRYPTED files. For encrypted files, the
 * blob_oid is the hash of ciphertext, while the filesystem contains plaintext.
 * Use compare_buffer_to_disk with decrypted content instead.
 *
 * Stat propagation optimization:
 * - If in_stat != NULL: Uses provided stat data (zero syscalls)
 * - If in_stat == NULL: Performs lstat() internally
 * - If out_stat != NULL: Returns stat data for caller reuse
 * - Single stat used for all checks (type, size, mode)
 *
 * @param blob_oid Expected blob OID from manifest (must not be NULL)
 * @param disk_path Path to file on disk (must not be NULL)
 * @param expected_mode Expected git filemode (BLOB, BLOB_EXECUTABLE, or LINK)
 * @param in_stat Optional pre-captured stat (can be NULL for internal lstat)
 * @param result Comparison result (must not be NULL)
 * @param out_stat Optional stat output (can be NULL, filled if provided)
 * @return Error or NULL on success
 */
error_t *compare_oid_to_disk(
    const git_oid *blob_oid,
    const char *disk_path,
    git_filemode_t expected_mode,
    const struct stat *in_stat,
    compare_result_t *result,
    struct stat *out_stat
);

/**
 * Diff direction for compare_generate_diff()
 *
 * Controls which side is treated as "old" and "new" in the unified diff:
 *   CMP_DIR_UPSTREAM:   old=filesystem, new=repo — '-' is current disk content,
 *                       '+' is repo content apply would write.
 *   CMP_DIR_DOWNSTREAM: old=repo, new=filesystem — '-' is repo content,
 *                       '+' is local changes update would commit.
 */
typedef enum {
    CMP_DIR_UPSTREAM,    /* old=filesystem, new=repo (what apply would write) */
    CMP_DIR_DOWNSTREAM   /* old=repo, new=filesystem (what update would commit) */
} compare_direction_t;

/**
 * Generate diff from buffer content to disk file
 *
 * Works with decrypted content from the content layer.
 * Uses libgit2's git_diff_buffers for pure in-memory diff generation.
 *
 * Stat propagation: Accepts pre-captured stat to avoid redundant syscalls
 * during comparison phase. If in_stat is NULL, performs lstat() internally.
 *
 * @param content Content buffer (e.g., decrypted content, must not be NULL)
 * @param disk_path Disk file path (must not be NULL)
 * @param path_label Label for diff output (can be NULL, defaults to disk_path)
 * @param mode Expected git filemode (for type/mode checking)
 * @param in_stat Optional pre-captured stat (can be NULL for internal lstat)
 * @param direction Diff direction
 * @param out Diff information (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *compare_generate_diff(
    const buffer_t *content,
    const char *disk_path,
    const char *path_label,
    git_filemode_t mode,
    const struct stat *in_stat,
    compare_direction_t direction,
    file_diff_t **out
);

/**
 * Free diff structure
 *
 * @param diff Diff to free (can be NULL)
 */
void compare_free_diff(file_diff_t *diff);

/**
 * Get result description
 *
 * @param result Comparison result
 * @return Human-readable description
 */
const char *compare_result_string(compare_result_t result);

#endif /* DOTTA_COMPARE_H */
