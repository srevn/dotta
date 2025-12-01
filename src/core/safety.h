/**
 * safety.h - Data loss prevention for destructive filesystem operations
 *
 * This module validates orphaned file removal to prevent data loss.
 * It trusts workspace divergence analysis completely and focuses on edge cases:
 * 1. Branch existence checking (external deletion detection)
 * 2. Lifecycle state verification (controlled vs external deletion)
 *
 * Primary Use Case:
 * The `apply` command uses this module to check orphaned files before pruning them.
 * When a profile is disabled, its files become orphaned. Before removing these files,
 * we validate edge cases that workspace cannot detect.
 *
 * Architecture:
 * - Workspace performs comprehensive divergence analysis (trusted completely)
 * - Non-encrypted files: Streaming OID verification (any size, O(1) memory)
 * - Encrypted ≤100MB: Content comparison
 * - Encrypted >100MB: UNVERIFIED (OOM protection, maps to CANNOT_VERIFY)
 * - Safety trusts workspace divergence and routes to violations
 * - Branch existence is safety's unique responsibility
 *
 * Trust Model:
 * - DIVERGENCE_NONE: Safe to remove (workspace verified clean)
 * - DIVERGENCE_CONTENT/TYPE/MODE/OWNERSHIP: Map to violation directly
 * - DIVERGENCE_UNVERIFIED: Map to CANNOT_VERIFY (conservative)
 *
 * Optimizations:
 * - Targeted O(1) state queries (no bulk loading)
 * - Profile tree caching: Each profile tree loaded once
 */

#ifndef DOTTA_SAFETY_H
#define DOTTA_SAFETY_H

#include <stdbool.h>
#include <stddef.h>

#include "base/error.h"
#include "core/state.h"
#include "core/workspace.h"

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
#define SAFETY_REASON_RELEASED         "released"          /* Profile deleted externally, file released */
#define SAFETY_REASON_MODIFIED         "modified"          /* Content changed */
#define SAFETY_REASON_MODE_CHANGED     "mode_changed"      /* Permissions changed */
#define SAFETY_REASON_TYPE_CHANGED     "type_changed"      /* File<->symlink conversion */
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
 * Check removal safety for orphaned workspace items
 *
 * Validates that orphaned files can be safely removed by checking:
 * 1. Branch existence (external deletion detection)
 * 2. Lifecycle state (controlled vs external deletion)
 * 3. Workspace divergence (trusted completely)
 *
 * Trusts workspace divergence analysis completely:
 * - Non-encrypted: Streaming OID verification handles any file size
 * - Encrypted ≤100MB: Content comparison
 * - Encrypted >100MB: CANNOT_VERIFY violation (OOM protection)
 *
 * Algorithm:
 * 1. Skip if file not on filesystem (already deleted)
 * 2. Check branch existence (workspace cannot do this)
 *    - Branch exists: proceed with divergence routing
 *    - Branch deleted + STATE_INACTIVE: safe (controlled deletion)
 *    - Branch deleted + STATE_ACTIVE: RELEASED violation (external deletion)
 * 3. Route by divergence type (TRUST WORKSPACE):
 *    - DIVERGENCE_NONE: safe to remove (no violation)
 *    - DIVERGENCE_CONTENT: MODIFIED violation
 *    - DIVERGENCE_TYPE: TYPE_CHANGED violation
 *    - DIVERGENCE_MODE/OWNERSHIP: MODE_CHANGED violation
 *    - DIVERGENCE_UNVERIFIED: CANNOT_VERIFY violation
 *
 * Performance:
 * - O(n) where n = orphan count (workspace already verified)
 * - State queries: O(1) per orphan (targeted lookup, no bulk loading)
 * - Tree caching: Each profile tree loaded at most once
 *
 * Edge Cases:
 * - External branch deletion: RELEASED violation (protects user data)
 * - Controlled deletion (profile disable): Safe to remove
 * - Large non-encrypted files: Verified (streaming OID, any size)
 * - Large encrypted files (>100MB): CANNOT_VERIFY (OOM protection)
 * - File deleted during check: Safe (no violation)
 *
 * @param repo Git repository (must not be NULL)
 * @param state State database for lifecycle queries (must not be NULL)
 * @param orphans Workspace items marked as orphaned (can be NULL if count is 0)
 * @param orphan_count Number of orphan items
 * @param force If true, skip all checks (emergency override)
 * @param out_result Output safety result (must not be NULL, caller must free)
 * @return Error on fatal failure, NULL on success
 */
error_t *safety_check_orphans(
    git_repository *repo,
    const state_t *state,
    const workspace_item_t **orphans,
    size_t orphan_count,
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
