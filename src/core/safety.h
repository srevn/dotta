/**
 * safety.h - Safety checks for destructive operations
 *
 * Provides validation checks to prevent data loss during destructive
 * operations like file removal during profile unselection.
 *
 * Design principles:
 * - Detect uncommitted filesystem changes before removal
 * - Explicit detection of edge cases (profile deletion, etc.)
 * - Conservative defaults (fail safe: block when can't verify)
 * - Rich error context for user guidance
 * - Respect --force flag for intentional override
 */

#ifndef DOTTA_SAFETY_H
#define DOTTA_SAFETY_H

#include <git2.h>
#include <stdbool.h>
#include <stddef.h>

#include "types.h"
#include "core/state.h"
#include "utils/hashmap.h"

/**
 * Safety violation details
 *
 * Represents a single file that cannot be safely removed.
 * Provides detailed reason and context for user-friendly error reporting.
 */
typedef struct {
    char *filesystem_path;      /* File path on disk */
    char *reason;               /* Machine-readable reason:
                                 *   "modified" - content changed
                                 *   "mode_changed" - permissions changed
                                 *   "type_changed" - file<->symlink conversion
                                 *   "profile_deleted" - source profile branch deleted
                                 *   "file_removed" - removed from profile but exists on disk
                                 *   "cannot_verify" - unable to verify (permission, I/O error)
                                 */
    bool content_modified;      /* True if content differs (not just metadata) */
    char *source_profile;       /* Profile that originally tracked this file */
} safety_violation_t;

/**
 * Safety check result
 *
 * Contains list of files that are unsafe to remove.
 * Empty list (count == 0) means all files are safe to remove.
 */
typedef struct {
    safety_violation_t *violations;  /* Array of violations */
    size_t count;                     /* Number of violations */
    size_t capacity;                  /* Allocated capacity (internal) */
} safety_result_t;

/**
 * Check orphaned files for filesystem modifications
 *
 * Validates that files scheduled for removal haven't been modified by the user.
 * This prevents data loss when a profile is unselected and `dotta apply` removes
 * orphaned files.
 *
 * Algorithm:
 * 1. For each orphaned file path:
 *    - Find corresponding state entry
 *    - If exists on filesystem:
 *      a) Fast path: Compare using state hash (if available and blob accessible)
 *      b) Fallback: Load profile tree and compare (handles profile deletion)
 *    - If different: add to violations list with detailed reason
 * 2. If violations found and !force: return error
 *
 * Edge cases handled:
 * - Profile branch deleted: Explicit "profile_deleted" violation
 * - Blob inaccessible: Falls back to tree loading
 * - Cannot read file: Conservative "cannot_verify" violation
 * - File already deleted: Skipped (safe to prune from state)
 * - Permission denied: Treated as potentially modified (conservative)
 *
 * Performance:
 * - Fast path: O(M) where M = orphaned files (direct blob comparison)
 * - Slow path: O(M + P*T) where P = profiles, T = tree size (tree loading with caching)
 * - Typical case: Fast path succeeds, negligible overhead
 * - NOTE: Caller should pre-identify orphaned files to avoid redundant detection
 *
 * @param repo Repository (must not be NULL)
 * @param orphaned_paths Array of orphaned filesystem paths (must not be NULL if orphaned_count > 0)
 * @param orphaned_count Number of orphaned paths
 * @param state_entries All state file entries for lookup (must not be NULL)
 * @param state_count Number of state entries
 * @param force If true, skip checks and return empty result
 * @param out_result Output safety result (must not be NULL, caller must free with safety_result_free)
 * @return Error if violations found and !force, NULL otherwise
 */
error_t *safety_check_orphaned(
    git_repository *repo,
    const char **orphaned_paths,
    size_t orphaned_count,
    const state_file_entry_t *state_entries,
    size_t state_count,
    bool force,
    safety_result_t **out_result
);

/**
 * Free safety violation
 *
 * @param violation Violation to free (can be NULL)
 */
void safety_violation_free(safety_violation_t *violation);

/**
 * Free safety result
 *
 * Frees all contained violations and the result structure itself.
 *
 * @param result Result to free (can be NULL)
 */
void safety_result_free(safety_result_t *result);

#endif /* DOTTA_SAFETY_H */
