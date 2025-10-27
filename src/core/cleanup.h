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
 * - Metadata: Only load from deployed-but-not-enabled profiles (no duplication)
 * - Content cache: Reuse decrypted content from preflight checks (avoid re-decryption)
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

/* Forward declarations */
typedef struct content_cache content_cache_t;

/**
 * Cleanup operation options
 *
 * Configures cleanup behavior and provides pre-loaded data to avoid duplication.
 * No presentation concerns, pure business logic flags.
 */
typedef struct {
    /* Pre-loaded data */
    const metadata_t *enabled_metadata;      /* Metadata from enabled profiles (can be NULL) */
    const profile_list_t *enabled_profiles;  /* Currently enabled profiles (can be NULL) */
    content_cache_t *cache;                  /* Content cache for performance (can be NULL) */

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

    /* Empty directory statistics */
    size_t directories_checked;          /* Total directories examined */
    size_t directories_removed;          /* Successfully removed */
    size_t directories_failed;           /* Failed to remove (I/O errors) */

    /* Safety violation details */
    safety_result_t *safety_violations;  /* NULL if no violations or force=true */

    /* Detailed file lists */
    string_array_t *removed_files;       /* Successfully removed file paths */
    string_array_t *skipped_files;       /* Skipped file paths (safety violations) */
    string_array_t *failed_files;        /* Failed file paths (with errors) */

    /* Detailed directory lists */
    string_array_t *removed_dirs;        /* Successfully removed directory paths */
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

    /* Directory pruning preview */
    size_t directories_count;           /* Empty dirs that will be removed */
    string_array_t *directories;        /* Directory paths (for verbose display) */

    /* Summary flags */
    bool has_blocking_violations;       /* True if safety violations present */
    bool will_prune_orphans;            /* True if orphaned_files_count > 0 */
    bool will_prune_directories;        /* True if directories_count > 0 */
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
 * Algorithm:
 * ----------
 * 1. Early exit if --keep-orphans (nothing to analyze)
 * 2. Build manifest hashmap for O(1) orphan detection
 * 3. Load all state files
 * 4. Identify orphans (in state, not in manifest)
 * 5. Run safety checks (unless force=true)
 * 6. Preview empty tracked directories (read-only, no removal)
 *
 * Performance:
 * ------------
 * - Complexity: O(N + M) where N=state files, M=manifest files
 * - Uses hashmap for O(1) lookups (avoids O(N*M) nested loops)
 * - Reuses content cache from deploy preflight (no re-decryption)
 * - Typical: <100ms for 10,000 files
 *
 * Edge Cases:
 * -----------
 * - No orphans: Returns empty result (quick path)
 * - --keep-orphans: Returns empty result (skip analysis)
 * - Empty manifest: ALL deployed files are orphans (big warning)
 * - Safety violations: Returned in result, blocking (unless force=true)
 * - No state files: Returns empty result (nothing to check)
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
 * @param state State for file tracking (must not be NULL, read-only)
 * @param manifest Current file manifest (must not be NULL)
 * @param opts Cleanup options (must not be NULL)
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
 * If opts->enabled_metadata is provided, only loads metadata from profiles
 * that are deployed but not currently enabled. This eliminates duplicate
 * metadata loading when called from apply command.
 *
 * Example:
 *   Enabled profiles: {base, linux}
 *   Deployed profiles: {base, linux, work}  (work was previously enabled)
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
