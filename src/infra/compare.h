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
