/**
 * compare.h - File comparison engine
 *
 * Compares buffer content with filesystem state.
 *
 * This module works exclusively with plaintext buffers provided by the
 * content layer (src/infra/content.h), which handles transparent decryption
 * of encrypted files. The compare module has no knowledge of encryption
 * or git internals - it simply compares buffers to disk files.
 *
 * Design principles:
 * - Pure buffer-based operations
 * - Handle all file types (regular, symlink)
 * - Compare permissions accurately (executable bit)
 * - Clear comparison results
 * - Integration with content layer for encrypted files
 */

#ifndef DOTTA_COMPARE_H
#define DOTTA_COMPARE_H

#include <git2.h>
#include <sys/stat.h>

#include "types.h"

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
    CMP_TYPE_DIFF    /* Different types (file vs symlink) */
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
 * Diff direction (forward declaration from diff.h)
 */
typedef enum {
    CMP_DIR_UPSTREAM,      /* Show filesystem → repo (what apply would do) */
    CMP_DIR_DOWNSTREAM     /* Show repo → filesystem (what update would commit) */
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
