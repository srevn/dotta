/**
 * safety.h - Data loss prevention for destructive filesystem operations
 *
 * This module provides safety validation before removing files from the filesystem.
 * It prevents data loss by detecting uncommitted changes in files scheduled for removal.
 *
 * Primary Use Case:
 * ─────────────────
 * The `apply` command uses this module to check orphaned files before pruning them.
 * When a profile is unselected, its files become orphaned. Before removing these files,
 * we verify they haven't been modified on the filesystem to prevent data loss.
 *
 * Design Principles:
 * ─────────────────
 * - Performance: Fast path (blob hash) + caching for large batches
 * - Clarity: Rich error context with actionable guidance
 * - Separation: Removal safety only (deploy conflicts in deploy.c)
 * - Stateless: All context passed as parameters
 *
 * Architecture:
 * ─────────────
 * 1. Fast Path: Use state->hash + compare_blob_to_disk() [O(1) per file]
 * 2. Fallback: Load profile trees + compare_tree_entry_to_disk() [O(profiles)]
 * 3. Adaptive: Linear search for small batches (< 20), hashmap for large batches
 * 4. Caching: Profile trees cached during batch operations to avoid redundant Git ops
 */

#ifndef DOTTA_SAFETY_H
#define DOTTA_SAFETY_H

#include <stdbool.h>
#include <stddef.h>

#include "base/error.h"
#include "core/state.h"

/**
 * Safety violation details
 *
 * Represents a single file that cannot be safely removed due to uncommitted
 * changes or verification failures.
 */
typedef struct {
    char *filesystem_path;      /* File path on disk */
    char *storage_path;         /* Path in profile (e.g., home/.bashrc) */
    char *source_profile;       /* Profile that originally tracked this file */
    char *reason;               /* Machine-readable reason code (see SAFETY_REASON_* below) */
    bool content_modified;      /* True if content differs (not just metadata) */
} safety_violation_t;

/**
 * Reason codes for safety violations
 *
 * Used in safety_violation_t.reason field for programmatic handling and display.
 */
#define SAFETY_REASON_MODIFIED         "modified"          /* Content changed */
#define SAFETY_REASON_MODE_CHANGED     "mode_changed"      /* Permissions changed */
#define SAFETY_REASON_TYPE_CHANGED     "type_changed"      /* File<->symlink conversion */
#define SAFETY_REASON_PROFILE_DELETED  "profile_deleted"   /* Source profile branch deleted */
#define SAFETY_REASON_FILE_REMOVED     "file_removed"      /* Removed from profile */
#define SAFETY_REASON_CANNOT_VERIFY    "cannot_verify"     /* Unable to verify (I/O, permissions) */

/**
 * Safety check result
 *
 * Contains list of files that are unsafe to remove.
 * Empty list (count == 0) means all files are safe to remove.
 */
typedef struct {
    safety_violation_t *violations;  /* Array of violations (owns memory) */
    size_t count;                     /* Number of violations */
    size_t capacity;                  /* Allocated capacity (internal use) */
} safety_result_t;

/**
 * Check if files can be safely removed from filesystem
 *
 * Purpose:
 *   Validates that files scheduled for removal don't have uncommitted changes.
 *   This prevents data loss during operations like orphan file pruning in `apply`.
 *
 * Algorithm:
 *   For each file:
 *     1. Lookup state entry (adaptive: hashmap or linear search)
 *     2. If file doesn't exist on disk: SAFE (already deleted)
 *     3. If state->hash available: Try fast path (compare_blob_to_disk)
 *     4. If fast path fails: Load profile tree and compare via tree entry
 *     5. If modified: Add violation with detailed reason
 *
 * Performance:
 *   - Best case (fast path succeeds): O(n) where n = number of files
 *   - Worst case (all fallback): O(n + p*log(t)) where p = profiles, t = tree size
 *   - Typical: Fast path succeeds 99% of time (profile active, hash available)
 *   - Adaptive strategy: Uses hashmap when path_count >= 20 OR path_count * state_count >= 400
 *     This prevents O(n*m) blowup (e.g., 19 paths × 10K state = 190K comparisons → hashmap)
 *
 * Edge Cases Handled:
 *   - Profile branch deleted → Explicit "profile_deleted" violation
 *   - Blob not found in repo → Falls back to tree loading
 *   - Cannot read file → Conservative "cannot_verify" violation (blocks removal)
 *   - File already deleted → Skipped (safe to prune from state)
 *   - Permission denied → Treated as potentially modified (safe default)
 *
 * @param repo Repository (must not be NULL)
 * @param state State for profile/storage_path lookups (must not be NULL)
 * @param filesystem_paths Array of filesystem paths to check (must not be NULL if path_count > 0)
 * @param path_count Number of paths to check
 * @param force If true, skip all checks and return empty result
 * @param out_result Safety result (must not be NULL, caller must free with safety_result_free)
 * @return NULL on success (check result->count for violations), error on fatal issues
 */
error_t *safety_check_removal(
    git_repository *repo,
    state_t *state,
    const char **filesystem_paths,
    size_t path_count,
    bool force,
    safety_result_t **out_result
);

/**
 * Free safety result
 *
 * Frees all contained violations and the result structure itself.
 *
 * Note: Individual violations are stored inline in the result array and
 * cannot be freed separately. This function handles all cleanup.
 *
 * @param result Result to free (can be NULL)
 */
void safety_result_free(safety_result_t *result);

#endif /* DOTTA_SAFETY_H */
