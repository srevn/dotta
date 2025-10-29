/**
 * cleanup.h - Orphaned file and directory removal
 *
 * This module handles removal of orphaned files and directories during profile application.
 * Orphan detection is performed by the workspace module; this module focuses on safe removal.
 *
 * Responsibilities:
 * ────────────────
 * 1. Removes orphaned files (validated by safety module)
 * 2. Prunes orphaned directories (iterative empty-directory removal)
 * 3. Provides preflight analysis (safety violations, removal preview)
 * 4. Reports detailed cleanup results
 *
 * Design Principles:
 * ─────────────────
 * - Separation: Cleanup is decoupled from orphan detection (workspace responsibility)
 * - Safety: Dual approach - safety module for files, inline check for directories
 * - Performance: Accepts pre-detected orphans from workspace (zero redundancy)
 * - Reporting: Rich result structure for detailed feedback
 *
 * Orphan Sources:
 * ──────────────
 * - Workspace module detects ALL orphans during workspace_load()
 * - Orphans extracted via workspace_get_diverged_filtered(DIVERGENCE_ORPHANED)
 * - Passed to cleanup module as workspace_item_t** arrays
 * - See workspace.h for orphan detection algorithm details
 *
 * Safety Validation:
 * ─────────────────
 * - Files: safety_check_removal() - Complex Git comparison, hash checks, decryption
 * - Directories: Inline fs_is_directory_empty() - Simple filesystem check
 * - Rationale: Different complexity levels warrant different approaches
 *
 * Optimization Strategy:
 * ─────────────────────
 * - Zero redundancy: Orphans detected once by workspace, reused here
 * - Content cache: Reuse decrypted content from preflight checks (avoid re-decryption)
 * - Directory pruning: State tracking to avoid redundant filesystem checks
 * - Parent awareness: Reset parent directory state when child removed (iterative pruning)
 *
 * Integration Points:
 * ──────────────────
 * - workspace.h: Provides orphan detection and divergence analysis
 * - safety.h: Validates file removal (uncommitted change detection)
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
#include "core/workspace.h"

/**
 * Cleanup operation options
 *
 * Configures cleanup behavior and provides pre-loaded data to avoid duplication.
 * No presentation concerns, pure business logic flags.
 */
typedef struct {
    /* Pre-loaded data */
    const metadata_t *enabled_metadata;      /* Metadata covering files to be checked.
                                              * Safety module will load additional metadata
                                              * on-demand for orphaned files from disabled
                                              * profiles (with caching for efficiency).
                                              * Can be NULL (safety module handles gracefully). */
    const profile_list_t *enabled_profiles;  /* Currently enabled profiles (can be NULL) */
    content_cache_t *cache;                  /* Content cache for performance (can be NULL) */

    /**
     * Pre-computed file orphan array from workspace (REQUIRED)
     *
     * Must be extracted by caller from workspace using workspace_get_diverged_filtered().
     * Treated as borrowed reference (cleanup does not free).
     *
     * Rationale: Workspace already detected orphans during workspace_load().
     * Eliminates redundant orphan detection in cleanup module.
     *
     * Performance: Single orphan detection pass instead of multiple.
     */
    const workspace_item_t **orphaned_files;     /* Workspace item array (must not be NULL) */
    size_t orphaned_files_count;                 /* Number of orphaned files */

    /**
     * Pre-computed directory orphan array from workspace (REQUIRED)
     *
     * Must be extracted by caller from workspace using workspace_get_diverged_filtered().
     * Treated as borrowed reference (cleanup does not free).
     *
     * Rationale: Workspace already detected directory orphans during workspace_load().
     * Eliminates redundant orphan detection in cleanup module.
     *
     * Performance: Single orphan detection pass instead of multiple.
     */
    const workspace_item_t **orphaned_directories;  /* Workspace item array (must not be NULL) */
    size_t orphaned_directories_count;              /* Number of orphaned directories */

    /**
     * Pre-computed safety violations from preflight check (OPTIONAL)
     *
     * If provided, files in this list will be skipped during cleanup without
     * re-running expensive safety checks. This is a performance optimization
     * that avoids duplicate Git comparisons and content decryption.
     *
     * If NULL: Safety checks are run during cleanup (unless skip_safety_check=true).
     * If provided: Files in violations list are skipped, no re-check performed.
     *
     * Typical flow:
     * 1. apply.c runs cleanup_preflight_check() → produces safety_violations
     * 2. apply.c passes violations to cleanup_execute() via this field
     * 3. cleanup_execute() uses violations to build skip list
     * 4. apply.c frees cleanup_preflight_result (owns the data)
     */
    const safety_result_t *preflight_violations;

    /* Control flags */
    bool verbose;                           /* Kept for consistency (unused in module) */
    bool dry_run;                           /* Don't actually remove anything */
    bool force;                             /* Skip safety checks (dangerous) */
    bool skip_safety_check;                 /* Skip safety check (already done in preflight) */
} cleanup_options_t;

/**
 * Cleanup operation result
 *
 * Comprehensive statistics and details about cleanup operation.
 * Enables caller to present detailed feedback to user.
 */
typedef struct {
    /* Orphaned file statistics */
    size_t orphaned_files_found;         /* Total orphaned files detected */
    size_t orphaned_files_removed;       /* Successfully removed */
    size_t orphaned_files_failed;        /* Failed to remove (I/O errors) */
    size_t orphaned_files_skipped;       /* Skipped due to safety violations */

    /* Orphaned directory statistics */
    size_t orphaned_directories_found;   /* Total orphaned directories detected */
    size_t orphaned_directories_removed; /* Successfully removed */
    size_t orphaned_directories_skipped; /* Skipped (non-empty - safety) */
    size_t orphaned_directories_failed;  /* Failed to remove (I/O errors) */

    /* Safety violation details */
    safety_result_t *safety_violations;  /* NULL if no violations or force=true */

    /* Detailed file lists */
    string_array_t *removed_files;       /* Successfully removed file paths */
    string_array_t *skipped_files;       /* Skipped file paths (safety violations) */
    string_array_t *failed_files;        /* Failed file paths (with errors) */

    /* Detailed directory lists */
    string_array_t *removed_dirs;        /* Successfully removed directory paths */
    string_array_t *skipped_dirs;        /* Skipped directory paths (non-empty orphans) */
    string_array_t *failed_dirs;         /* Failed directory paths (with errors) */
} cleanup_result_t;

/**
 * Cleanup preflight result
 *
 * Read-only analysis of what cleanup_execute() will do, shown before user confirmation.
 * This enables informed consent by revealing the full impact of the apply operation.
 *
 * Design:
 * -------
 * - Identifies orphaned files without removing them
 * - Runs safety checks to detect uncommitted changes
 * - Previews empty directories that will be pruned
 * - Provides rich context for user decision-making
 *
 * Usage:
 * ------
 * Called by apply command BEFORE confirmation prompt to show users:
 * - "Will remove N orphaned files from disabled profiles"
 * - Safety violations (blocking unless --force)
 * - Empty directories to be pruned (verbose mode)
 */
typedef struct {
    /* Orphaned file detection */
    size_t orphaned_files_count;        /* Total files to be removed */
    string_array_t *orphaned_files;     /* File paths (for display) */

    /* Safety violations */
    safety_result_t *safety_violations; /* Blocking issues (NULL if none or force=true) */

    /* Orphaned directory pruning preview */
    size_t orphaned_directories_count;        /* Orphaned directories detected */
    size_t orphaned_directories_nonempty;     /* Non-empty orphaned dirs (blocking) */
    string_array_t *orphaned_directories;     /* Directory paths (for display) */

    /* Summary flags */
    bool has_blocking_violations;       /* True if file safety violations present */
    bool has_blocking_directories;      /* True if non-empty orphaned dirs present */
    bool will_prune_orphans;            /* True if orphaned_files_count > 0 */
    bool will_prune_directories;        /* True if orphaned_directories_count > 0 */
} cleanup_preflight_result_t;

/**
 * Run cleanup preflight checks
 *
 * Analyzes what cleanup_execute() will do WITHOUT modifying the filesystem.
 * This enables informed user consent before destructive operations by revealing
 * the full impact of orphan cleanup.
 *
 * Purpose:
 * --------
 * The apply command uses this to show users BEFORE confirmation:
 * - How many orphaned files will be removed
 * - Which profiles the orphans came from
 * - Safety violations (uncommitted changes)
 * - Empty directories to be pruned
 *
 * Architecture:
 * ------------
 * Orphans are PRE-DETECTED by workspace module and passed via opts:
 * - opts->orphaned_files: workspace_item_t** array from workspace
 * - opts->orphaned_directories: workspace_item_t** array from workspace
 *
 * This function focuses on safety validation and preview, not detection.
 *
 * Algorithm:
 * ----------
 * 1. Use pre-detected orphans from opts (NO orphan detection here)
 * 2. Run safety checks on orphaned files (unless force=true)
 * 3. Preview which directories will be pruned (read-only check)
 * 4. Build result summary for user display
 *
 * Performance:
 * ------------
 * - Complexity: O(N) where N=orphan count (NOT O(state + manifest))
 * - Zero redundancy: orphans detected once by workspace
 * - Reuses content cache from deploy preflight (no re-decryption)
 * - Typical: <50ms for 1,000 orphans
 *
 * Edge Cases:
 * -----------
 * - No orphans: Returns empty result (quick path)
 * - Safety violations: Returned in result, blocking (unless force=true)
 * - Empty orphan arrays: Valid, returns empty result
 *
 * Integration:
 * ------------
 * This function is READ-ONLY and does NOT modify:
 * - Filesystem (no files removed)
 * - State database (no changes)
 * - Git repository (no commits)
 *
 * The caller (apply command) displays results and blocks on violations.
 *
 * @param repo Repository (must not be NULL)
 * @param state State for safety validation (must not be NULL, read-only)
 * @param manifest Current file manifest (must not be NULL)
 * @param opts Cleanup options with PRE-DETECTED orphans (must not be NULL)
 * @param out_result Preflight result (must not be NULL, caller must free)
 * @return Error or NULL on success (check result for details)
 */
error_t *cleanup_preflight_check(
    git_repository *repo,
    const state_t *state,
    const manifest_t *manifest,
    const cleanup_options_t *opts,
    cleanup_preflight_result_t **out_result
);

/**
 * Execute cleanup operations
 *
 * Performs orphaned file removal and empty directory pruning using
 * pre-detected orphans from workspace module. This function:
 *
 * 1. Uses pre-detected orphans from opts (NO detection here)
 * 2. Validates safety using safety module (unless force=true)
 * 3. Removes safe orphaned files from filesystem
 * 4. Prunes empty orphaned directories iteratively
 *
 * Architecture:
 * ────────────
 * Orphans are PRE-DETECTED by workspace module and passed via opts:
 * - opts->orphaned_files: workspace_item_t** array
 * - opts->orphaned_directories: workspace_item_t** array
 *
 * This function focuses on removal operations, not detection.
 *
 * State Management:
 * ────────────────
 * This function ONLY modifies the filesystem. It does NOT modify state.
 * The caller (typically apply command) must update state separately to
 * reflect the new filesystem reality.
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
 * Performance:
 * ───────────
 * - Complexity: O(N) where N=orphan count (NOT O(state + manifest))
 * - Zero redundancy: orphans detected once by workspace
 * - Content cache reused (no re-decryption)
 *
 * Error Handling:
 * ──────────────
 * - Individual file/directory removal failures are NON-FATAL
 * - Tracked in failed counters and reported
 * - Fatal errors: memory allocation, safety module errors
 *
 * @param repo Repository (must not be NULL)
 * @param state State for safety validation (must not be NULL, read-only)
 * @param manifest Current file manifest (must not be NULL)
 * @param opts Cleanup options with PRE-DETECTED orphans (must not be NULL)
 * @param out_result Cleanup result (must not be NULL, caller must free with cleanup_result_free)
 * @return Error or NULL on success (check result for operation details)
 */
error_t *cleanup_execute(
    git_repository *repo,
    const state_t *state,
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

/**
 * Free cleanup preflight result
 *
 * Frees all resources associated with cleanup preflight result,
 * including embedded safety violations and string arrays.
 *
 * @param result Result to free (can be NULL)
 */
void cleanup_preflight_result_free(cleanup_preflight_result_t *result);

#endif /* DOTTA_CLEANUP_H */
