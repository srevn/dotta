/**
 * compare.h - File comparison engine
 *
 * Compares git objects (blobs, trees) with filesystem state.
 *
 * Design principles:
 * - Efficient comparison (use checksums when possible)
 * - Handle all file types (regular, symlink)
 * - Compare permissions accurately
 * - Clear comparison results
 */

#ifndef DOTTA_COMPARE_H
#define DOTTA_COMPARE_H

#include <git2.h>

#include "types.h"

/**
 * Comparison result
 */
typedef enum {
    CMP_EQUAL,       /* Files are identical */
    CMP_DIFFERENT,   /* Files have different content */
    CMP_MISSING,     /* File doesn't exist on disk */
    CMP_TYPE_DIFF,   /* Different types (file vs symlink) */
    CMP_MODE_DIFF    /* Different permissions (executable bit) */
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
 * Compare blob content with disk file
 *
 * @param repo Repository (must not be NULL)
 * @param blob_id Blob OID (must not be NULL)
 * @param disk_path Disk file path (must not be NULL)
 * @param result Comparison result (must not be NULL)
 * @return Error or NULL on success
 */
error_t *compare_blob_to_disk(
    git_repository *repo,
    const git_oid *blob_id,
    const char *disk_path,
    compare_result_t *result
);

/**
 * Compare tree entry with disk file
 *
 * Handles all file types and permissions.
 *
 * @param repo Repository (must not be NULL)
 * @param entry Tree entry (must not be NULL)
 * @param disk_path Disk file path (must not be NULL)
 * @param result Comparison result (must not be NULL)
 * @return Error or NULL on success
 */
error_t *compare_tree_entry_to_disk(
    git_repository *repo,
    const git_tree_entry *entry,
    const char *disk_path,
    compare_result_t *result
);

/**
 * Compare buffer content to disk file
 *
 * Pure function with zero git/encryption knowledge.
 * Compares plaintext buffer to file on disk.
 *
 * Tests:
 * 1. File exists on disk
 * 2. File type matches (regular/symlink)
 * 3. Content matches
 * 4. Mode matches (executable bit)
 *
 * This function is designed to work with decrypted content from the
 * content layer, enabling transparent comparison of encrypted files.
 *
 * @param content Buffer containing expected content (must not be NULL)
 * @param disk_path Path to file on disk (must not be NULL)
 * @param expected_mode Expected git filemode (for type/mode checking)
 * @param result Comparison result (must not be NULL)
 * @return Error or NULL on success
 */
error_t *compare_buffer_to_disk(
    const buffer_t *content,
    const char *disk_path,
    git_filemode_t expected_mode,
    compare_result_t *result
);

/**
 * Diff direction (forward declaration from diff.h)
 */
typedef enum {
    CMP_DIR_UPSTREAM,      /* Show filesystem → repo (what apply would do) */
    CMP_DIR_DOWNSTREAM     /* Show repo → filesystem (what update would commit) */
} compare_direction_t;

/**
 * Generate diff between tree entry and disk file
 *
 * @param repo Repository (must not be NULL)
 * @param entry Tree entry (must not be NULL)
 * @param disk_path Disk file path (must not be NULL)
 * @param direction Diff direction
 * @param out Diff information (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *compare_generate_diff(
    git_repository *repo,
    const git_tree_entry *entry,
    const char *disk_path,
    compare_direction_t direction,
    file_diff_t **out
);

/**
 * Generate diff from buffer content to disk file
 *
 * Buffer-based variant for use with decrypted content from the content layer.
 * This function creates temporary git blobs from the buffer to leverage
 * libgit2's diff generation capabilities.
 *
 * Use case: Encrypted files that have been decrypted by the content layer
 * can use this function instead of compare_generate_diff() to generate
 * diffs without exposing encrypted content.
 *
 * @param repo Repository (must not be NULL)
 * @param content Content buffer (e.g., decrypted content, must not be NULL)
 * @param disk_path Disk file path (must not be NULL)
 * @param path_label Label for diff output (can be NULL, defaults to disk_path)
 * @param mode Expected git filemode (for type/mode checking)
 * @param direction Diff direction
 * @param out Diff information (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *compare_generate_diff_from_buffer(
    git_repository *repo,
    const buffer_t *content,
    const char *disk_path,
    const char *path_label,
    git_filemode_t mode,
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
