/**
 * safety.h - Data loss prevention for destructive filesystem operations
 *
 * This module provides safety validation before removing files from the filesystem.
 * It prevents data loss by detecting uncommitted changes in files scheduled for removal.
 *
 * Primary Use Case:
 * The `apply` command uses this module to check orphaned files before pruning them.
 * When a profile is disabled, its files become orphaned. Before removing these files,
 * we verify they haven't been modified on the filesystem to prevent data loss.
 *
 * Design Principles:
 * - Performance: Fast path (VWD) + caching for large batches
 * - Safety: Two independent verification paths for defense-in-depth
 * - Clarity: Rich error context with actionable guidance
 * - Separation: Removal safety only (deploy conflicts in deploy.c)
 *
 * Architecture:
 * Fast Path (Trust VWD/State):
 * - Uses state_entry as authoritative source
 * - Encryption flag from state_entry->encrypted (always correct!)
 * - File type from state_entry->type (handles symlinks correctly!)
 * - Permissions from state_entry->mode/owner/group
 * - Falls to slow path on content load failure (defense-in-depth)
 *
 * Slow Path (Trust Git Only):
 * - Loads all data directly from Git tree (independent source)
 * - Metadata loaded via metadata_load_from_tree()
 * - File mode from git_tree_entry_filemode()
 * - Provides true defense-in-depth if state is somehow corrupted
 *
 * Optimizations:
 * - Adaptive lookup: Linear for small batches, hashmap for large
 * - Profile tree caching: Each profile tree loaded once
 * - Tree metadata caching: Each profile's metadata loaded once
 * - Content cache integration: Reuses preflight-loaded content
 */

#ifndef DOTTA_SAFETY_H
#define DOTTA_SAFETY_H

#include <stdbool.h>
#include <stddef.h>

#include "base/error.h"
#include "core/state.h"

/* Forward declarations */
typedef struct keymanager keymanager_t;
typedef struct content_cache content_cache_t;

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
 * 1. Lookup state entry from VWD (adaptive: hashmap or linear search)
 * 2. If file doesn't exist on disk: SAFE (already deleted)
 * 3. Try fast path using state_entry (VWD):
 *    - Encryption from state_entry->encrypted (handles deleted profiles!)
 *    - Type from state_entry->type (handles symlinks correctly!)
 *    - Permissions from state_entry->mode/owner/group
 * 4. If fast path can't verify: Fall to slow path (Git tree)
 *    - Loads data directly from Git (independent verification)
 *    - Provides defense-in-depth against state corruption
 * 5. If modified: Add violation with detailed reason
 *
 * Performance:
 * - Best case (fast path + cache): O(n) where n = number of files
 * - With cache: Encrypted files use cached plaintext (no re-decryption)
 * - Without cache: Encrypted files decrypt on demand (slower but correct)
 * - Worst case (all fallback): O(n + p*log(t)) where p = profiles, t = tree size
 * - Typical: Fast path succeeds 99% of time
 * - Adaptive strategy: Uses hashmap when path_count >= 20 OR path_count * state_count >= 400
 *
 * Edge Cases Handled:
 * - Encrypted files from deleted profiles: Uses state_entry->encrypted (always correct)
 * - Symlinks: Uses state_entry->type for correct GIT_FILEMODE_LINK detection
 * - Profile branch deleted: Reports "profile_deleted" from slow path
 * - Content load failure: Falls to slow path (defense-in-depth)
 * - Decryption failure: Conservative "cannot_verify" violation
 * - Cannot read file: Conservative "cannot_verify" violation (blocks removal)
 * - File already deleted: Skipped (safe to prune from state)
 *
 * @param repo Repository (must not be NULL)
 * @param state State for VWD lookups (must not be NULL)
 * @param filesystem_paths Array of filesystem paths to check (must not be NULL if path_count > 0)
 * @param path_count Number of paths to check
 * @param force If true, skip all checks and return empty result
 * @param keymanager Key manager for decryption (can be NULL, uses global if needed)
 * @param cache Content cache for performance (can be NULL, decrypts on demand)
 * @param out_result Safety result (must not be NULL, caller must free with safety_result_free)
 * @return NULL on success (check result->count for violations), error on fatal issues
 */
error_t *safety_check_removal(
    git_repository *repo,
    const state_t *state,
    char **filesystem_paths,
    size_t path_count,
    bool force,
    keymanager_t *keymanager,
    content_cache_t *cache,
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
