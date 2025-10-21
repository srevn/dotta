/**
 * cleanup.h - Orphaned file and empty directory cleanup
 *
 * This module handles cleanup operations during profile application:
 * 1. Identifies and removes orphaned files (files in state but not in manifest)
 * 2. Validates removal safety using the safety module
 * 3. Prunes empty tracked directories using optimized metadata loading
 *
 * Design Principles:
 * ─────────────────
 * - Separation: Isolates cleanup logic from apply command
 * - Safety: Integrates with safety module to prevent data loss
 * - Performance: Optimized metadata loading and directory state tracking
 * - Reporting: Rich result structure for detailed feedback
 *
 * Optimization Strategy:
 * ─────────────────────
 * - Metadata: Only load from deployed-but-not-active profiles (no duplication)
 * - Directory pruning: State tracking to avoid redundant filesystem checks
 * - Parent awareness: Reset parent directory state when child removed
 *
 * Integration Points:
 * ──────────────────
 * - safety.h: Validates file removal (uncommitted change detection)
 * - metadata.h: Tracks directories for cleanup
 * - state.h: Identifies orphaned files and deployed profiles
 * - filesystem.h: Low-level file/directory operations
 */

#ifndef DOTTA_CLEANUP_H
#define DOTTA_CLEANUP_H

#include <git2.h>
#include <stdbool.h>
#include <stddef.h>

#include "base/error.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/safety.h"
#include "core/state.h"
#include "utils/output.h"

/**
 * Cleanup operation options
 *
 * Configures cleanup behavior and provides pre-loaded data to avoid duplication.
 */
typedef struct {
    /* Pre-loaded data */
    const metadata_t *active_metadata;      /* Metadata from active profiles (can be NULL) */
    const profile_list_t *active_profiles;  /* Currently active profiles (can be NULL) */

    /* Output and control flags */
    output_ctx_t *out;                      /* Output context (must not be NULL) */
    bool verbose;                           /* Print detailed progress */
    bool dry_run;                           /* Don't actually remove anything */
    bool force;                             /* Skip safety checks (dangerous) */
} cleanup_options_t;

/**
 * Cleanup operation result
 *
 * Comprehensive statistics and details about cleanup operation.
 * Enables caller to present detailed feedback to user.
 */
typedef struct {
    /* Orphaned file statistics */
    size_t orphaned_files_found;     /* Total orphaned files detected */
    size_t orphaned_files_removed;   /* Successfully removed */
    size_t orphaned_files_failed;    /* Failed to remove (I/O errors) */
    size_t orphaned_files_skipped;   /* Skipped due to safety violations */

    /* Empty directory statistics */
    size_t directories_checked;      /* Total directories examined */
    size_t directories_removed;      /* Successfully removed */
    size_t directories_failed;       /* Failed to remove (I/O errors) */

    /* Safety violation details (owned by this structure) */
    safety_result_t *safety_violations;  /* NULL if no violations or force=true */
} cleanup_result_t;

/**
 * Execute cleanup operations
 *
 * Performs orphaned file removal and empty directory pruning in a single
 * coordinated operation. This function:
 *
 * 1. Identifies orphaned files (in state, not in manifest)
 * 2. Validates safety using safety module (unless force=true)
 * 3. Removes safe orphaned files from filesystem
 * 4. Loads metadata from deployed profiles (optimized loading)
 * 5. Prunes empty tracked directories iteratively
 *
 * State Management:
 * ────────────────
 * This function ONLY modifies the filesystem. It does NOT modify state.
 * The caller (typically apply command) must update state separately to
 * reflect the new filesystem reality.
 *
 * Metadata Loading Optimization:
 * ──────────────────────────────
 * If opts->active_metadata is provided, only loads metadata from profiles
 * that are deployed but not currently active. This eliminates duplicate
 * metadata loading when called from apply command.
 *
 * Example:
 *   Active profiles: {base, linux}
 *   Deployed profiles: {base, linux, work}  (work was previously active)
 *   → Only loads metadata from {work}
 *
 * Safety Integration:
 * ──────────────────
 * Before removing orphaned files, calls safety_check_removal() to detect
 * uncommitted changes. Files with violations are:
 * - Counted in orphaned_files_skipped
 * - Detailed in result->safety_violations
 * - NOT removed from filesystem
 * - Reported to user with guidance
 *
 * Directory Pruning Algorithm:
 * ───────────────────────────
 * Uses iterative approach with state tracking:
 * - Iteration 1: Remove deepest empty directories
 * - Iteration 2: Parent directories may now be empty, remove them
 * - Repeat until no more directories can be removed
 * - State tracking avoids redundant filesystem checks
 *
 * Error Handling:
 * ──────────────
 * - Individual file/directory removal failures are NON-FATAL
 * - Tracked in failed counters and reported
 * - Fatal errors: memory allocation, state loading, safety module errors
 *
 * @param repo Repository (must not be NULL)
 * @param state State for orphaned file detection (must not be NULL, read-only)
 * @param manifest Current file manifest (must not be NULL)
 * @param opts Cleanup options (must not be NULL)
 * @param out_result Cleanup result (must not be NULL, caller must free with cleanup_result_free)
 * @return Error or NULL on success (check result for operation details)
 */
error_t *cleanup_execute(
    git_repository *repo,
    state_t *state,
    const manifest_t *manifest,
    const cleanup_options_t *opts,
    cleanup_result_t **out_result
);

/**
 * Free cleanup result
 *
 * Frees all resources associated with cleanup result, including
 * embedded safety violations.
 *
 * @param result Result to free (can be NULL)
 */
void cleanup_result_free(cleanup_result_t *result);

#endif /* DOTTA_CLEANUP_H */
