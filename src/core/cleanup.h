/**
 * cleanup.h - Orphaned file and directory removal
 *
 * This module handles removal of orphaned files and directories during profile application.
 * Orphan detection is performed by the workspace module; this module focuses on safe removal.
 *
 * Responsibilities:
 * 1. Removes orphaned files (validated by safety module)
 * 2. Prunes orphaned directories (deepest-first, once found empty)
 * 3. Provides preflight analysis (safety violations, removal preview)
 * 4. Reports detailed cleanup results
 *
 * Design Principles:
 * - Separation: Cleanup is decoupled from orphan detection (workspace responsibility)
 * - Safety: Two authorities - the safety module for files, the emptiness
 *   predicate and its removal mechanism for directories
 * - Performance: Accepts pre-detected orphans from workspace (zero redundancy)
 * - Reporting: Rich result structure for detailed feedback
 *
 * Orphan Sources:
 * - Workspace module detects ALL orphans during workspace_load()
 * - Orphans extracted via inline filtering (state == WORKSPACE_STATE_ORPHANED)
 * - Passed to cleanup module as workspace_item_t** arrays
 * - See workspace.h for orphan detection algorithm details
 *
 * One producer per fact:
 * - Which present files go: safety_check_orphans' verdicts, partitioned
 *   once by cleanup_preflight_check into removable_files + violations
 * - What stands at an orphaned directory's path: one type probe, shared by
 *   the preview and the prune so they cannot label it differently
 * - Whether a directory ends up empty: fs_is_directory_empty_except, one
 *   walk with a hole — the preview passes the run's own removals, the
 *   prune passes nothing because by then they have happened — and
 *   fs_remove_empty_dir, which removes exactly what that walk looks past
 *
 * Directory pruning is one deepest-first pass. Children are decided before
 * parents, so a parent emptied by its children needs no second look and
 * the preview can predict the same outcome the prune arrives at.
 *
 * Optimization Strategy:
 * - Zero redundancy: Orphans detected once by workspace, reused here
 * - Trust workspace: Reuses pre-computed divergence (no redundant verification)
 *
 * Integration Points:
 * - workspace.h: Provides orphan detection and divergence analysis
 * - safety.h: Validates file removal (uncommitted change detection)
 * - filesystem.h: Low-level file/directory operations
 */

#ifndef DOTTA_CLEANUP_H
#define DOTTA_CLEANUP_H

#include <git2.h>
#include <stdbool.h>

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
    /**
     * Pre-computed file orphan slice from workspace
     *
     * Must be extracted by caller via workspace_extract_orphans(). Treated
     * as borrowed reference (cleanup does not free).
     *
     * Rationale: Workspace already detected orphans during workspace_load().
     * Eliminates redundant orphan detection in cleanup module. Empty slice
     * (count == 0) is valid.
     */
    workspace_items_t orphaned_files;

    /**
     * Pre-computed directory orphan slice from workspace
     *
     * Must be extracted by caller via workspace_extract_orphans(). Treated
     * as borrowed reference (cleanup does not free).
     *
     * Rationale: Workspace already detected directory orphans during
     * workspace_load(). Eliminates redundant orphan detection in cleanup
     * module. Empty slice (count == 0) is valid.
     */
    workspace_items_t orphaned_directories;

    /**
     * Paths this run's deployment will materialize (preflight only)
     *
     * An orphaned directory is prunable only if nothing is left in it, and
     * a run that deploys into one leaves something. Deployment runs before
     * cleanup, so by the time the prune looks these paths are on disk and
     * it sees them as ordinary entries — but the preview runs first, and
     * without them it would promise a prune the run then refuses.
     *
     * Borrowed slices, typically the deployment plan's pending buckets;
     * empty is valid and means "nothing arrives". Read by
     * cleanup_preflight_check only: cleanup_execute reads the disk that
     * deployment has already changed.
     */
    state_files_t arriving_files;
    state_directories_t arriving_directories;

    /**
     * Pre-computed safety violations from preflight check
     *
     * Semantic contract:
     * - Non-NULL: Preflight was performed, trust results completely
     *   - count > 0: Files in violations list will be skipped
     *   - count == 0: Preflight verified all files safe, none skipped
     * - NULL: No preflight performed (or invalidated), run fresh safety check
     *   - Behavior depends on skip_safety_check flag
     *
     * This avoids re-running expensive safety checks (Git comparisons,
     * content decryption) that were already performed in preflight.
     *
     * IMPORTANT - TOCTOU Considerations:
     * Preflight results become STALE if time passes between preflight and
     * execution. A file marked "safe" at preflight could be modified by
     * the user before execution, making deletion dangerous.
     *
     * Callers MUST pass NULL when:
     * - Interactive confirmation prompts introduce user delay
     * - Any scenario where files could change between preflight and execute
     *
     * When NULL is passed, cleanup_execute() runs fresh safety validation
     * at the moment of deletion, guaranteeing accurate protection.
     *
     * Typical flow (non-interactive):
     * 1. apply.c runs cleanup_preflight_check() -> produces safety_violations
     * 2. apply.c passes violations to cleanup_execute() via this field
     * 3. cleanup_execute() trusts preflight results (no re-verification)
     * 4. apply.c frees cleanup_preflight_result (owns the data)
     *
     * Typical flow (interactive):
     * 1. apply.c runs cleanup_preflight_check() -> displays to user
     * 2. User confirmation prompt (arbitrary delay)
     * 3. apply.c passes NULL to cleanup_execute() (preflight invalidated)
     * 4. cleanup_execute() runs fresh safety check at deletion time
     *
     * Memory: Borrowed reference. Caller owns and frees safety_result_t.
     */
    const safety_result_t *preflight_violations;

    /* Control flags */
    bool dry_run;                           /* Don't actually remove anything */
    bool force;                             /* Skip safety checks (dangerous) */
    bool skip_safety_check;                 /* Skip safety when preflight_violations is NULL */
} cleanup_options_t;

/**
 * Cleanup operation result
 *
 * Comprehensive statistics and details about cleanup operation.
 * Enables caller to present detailed feedback to user.
 */
typedef struct {
    /* Safety violation details (owned)
     *
     * Only populated when cleanup_execute runs its own safety check
     * (opts->preflight_violations was NULL). When preflight violations
     * are reused, this stays NULL — the caller already has the data.
     *
     * For skip tracking, use the skipped_files array (authoritative source).
     */
    safety_result_t *safety_violations;

    /* File path lists (count via arr->count; execution-only, not populated in dry-run)
     *
     * removed_files guarantees physical removal occurred. reclaimed_files
     * were already absent from the filesystem — no removal happened or was
     * needed; only the state row is retired. Callers drive state database
     * cleanup from both buckets but must report them distinctly (a
     * decision is not an effect). For dry-run preview of what would be
     * removed, use cleanup_preflight_check instead.
     */
    string_array_t *removed_files;       /* Successfully removed file paths */
    string_array_t *reclaimed_files;     /* Already absent — state retired, no filesystem effect */
    string_array_t *skipped_files;       /* Skipped file paths (safety violations) */
    string_array_t *failed_files;        /* Failed file paths (with errors) */
    string_array_t *released_files;      /* Released files (left on disk, state cleaned) */

    /* Directory path lists (execution-only, not populated in dry-run) */
    string_array_t *removed_dirs;        /* Successfully removed directory paths */
    string_array_t *reclaimed_dirs;      /* Already absent — state retired, no filesystem effect */
    string_array_t *skipped_dirs;        /* Kept: occupied, a symlink, or not a directory */
    string_array_t *failed_dirs;         /* Failed directory paths (with errors) */
} cleanup_result_t;

/**
 * Cleanup preflight result — what cleanup_execute will do, decided once
 *
 * Present-on-filesystem orphans, partitioned by outcome. The preview and
 * the confirmation prompt both read these arrays and neither recomputes a
 * verdict of its own, so what the user consents to is what the run does.
 * An already-absent orphan is a pure state reclaim with no filesystem
 * effect and appears in none of them.
 *
 * Every array is always allocated — an empty array is a valid answer, and
 * the summary flags this replaces existed only as NULL guards.
 */
typedef struct {
    /* Files — safety's verdict, partitioned once.
     *   removable_files ∪ safety_violations = present file orphans
     * (safety_check_orphans skips orphans that are not on the filesystem,
     * so no violation names an absent path). The violations carry their
     * own blocking/released split; read those counts off the safety
     * result rather than folding the array again. */
    string_array_t *removable_files;    /* Will be unlinked */
    safety_result_t *safety_violations; /* Never NULL; empty under force */

    /* Directories — what the prune will reach, predicted against this same
     * run's own effects. A directory is prunable iff everything in it is
     * OS metadata, a file in removable_files, or an orphaned directory
     * beneath it that is itself prunable — and nothing this run deploys
     * lands inside it. That is what prune_orphaned_directories arrives at
     * by acting, read off the plan here in one deepest-first pass, so the
     * preview can say "2 will be pruned" about directories that still hold
     * the files this run removes: the ordinary shape of disabling a
     * profile.
     *
     * Exact except where the world moves underneath it — a change made
     * while the confirmation prompt waits, or an I/O failure — and the run
     * reports whatever it could not do. Listed in prune order, deepest
     * first. */
    string_array_t *prunable_dirs;
    string_array_t *occupied_dirs;      /* Holding something else, or not a directory */
} cleanup_preflight_result_t;

/**
 * Run cleanup preflight checks
 *
 * Analyzes what cleanup_execute() will do WITHOUT modifying the filesystem.
 * This enables informed user consent before destructive operations by revealing
 * the full impact of orphan cleanup.
 *
 * Purpose:
 * The apply command uses this to show users BEFORE confirmation:
 * - How many orphaned files will be removed
 * - Safety violations (uncommitted changes)
 * - Which orphaned directories will be pruned, and which will be kept
 *
 * Architecture:
 * Orphans are PRE-DETECTED by workspace module and passed via opts:
 * - opts->orphaned_files: workspace_items_t slice from workspace
 * - opts->orphaned_directories: workspace_items_t slice from workspace
 *
 * This function focuses on safety validation and preview, not detection.
 *
 * Algorithm:
 * 1. Use pre-detected orphans from opts (NO orphan detection here)
 * 2. Run safety checks on orphaned files (force yields an empty verdict)
 * 3. Partition the present file orphans into removable + violations
 * 4. Walk the orphaned directories deepest-first, deciding each against
 *    the removals above and the deployments in opts->arriving_*
 *
 * Performance:
 * - Complexity: O(N) where N=orphan count, plus one readdir per present
 *   orphaned directory
 * - Zero redundancy: orphans detected once by workspace
 *
 * Edge Cases:
 * - No orphans: Returns an empty, fully allocated result
 * - Safety violations: Returned in result, blocking (unless force=true)
 * - Empty orphan arrays: Valid, returns an empty result
 *
 * Integration:
 * This function is READ-ONLY and does NOT modify:
 * - Filesystem (no files removed)
 * - State database (no changes)
 * - Git repository (no commits)
 *
 * The caller (apply command) displays results and blocks on violations.
 *
 * @param repo Repository (must not be NULL)
 * @param state State for safety validation (must not be NULL, read-only)
 * @param opts Cleanup options with PRE-DETECTED orphans (must not be NULL)
 * @param out_result Preflight result (must not be NULL, caller must free)
 * @return Error or NULL on success (check result for details)
 */
error_t *cleanup_preflight_check(
    git_repository *repo,
    const state_t *state,
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
 * 4. Prunes empty orphaned directories, deepest first
 *
 * Architecture:
 * Orphans are PRE-DETECTED by workspace module and passed via opts:
 * - opts->orphaned_files: workspace_items_t slice
 * - opts->orphaned_directories: workspace_items_t slice
 *
 * This function focuses on removal operations, not detection.
 *
 * State Management:
 * This function ONLY modifies the filesystem. It does NOT modify state.
 * The caller (typically apply command) must update state separately to
 * reflect the new filesystem reality.
 *
 * Safety Integration:
 * Before removing orphaned files, calls safety_check_orphans() to detect
 * uncommitted changes. Files with violations are:
 * - Added to result->skipped_files
 * - Detailed in result->safety_violations
 * - NOT removed from filesystem
 * - Reported to user with guidance
 *
 * Directory Pruning Algorithm:
 * One deepest-first pass. A child is always decided before its parent, so
 * a parent that the run empties is seen empty when its turn comes and no
 * second look is needed. Emptiness is read from the disk this run has just
 * changed — cleanup_preflight_check predicted the same answer from the
 * plan, and this is where the prediction is confirmed or reported broken.
 *
 * Performance:
 * - Complexity: O(N) where N=orphan count, plus O(N log N) to order the
 *   directories deepest-first
 * - Zero redundancy: orphans detected once by workspace
 *
 * Error Handling:
 * - Individual file/directory removal failures are NON-FATAL
 * - Tracked in failed counters and reported
 * - Fatal errors: memory allocation, safety module errors
 *
 * @param repo Repository (must not be NULL)
 * @param state State for safety validation (must not be NULL, read-only)
 * @param opts Cleanup options with PRE-DETECTED orphans (must not be NULL)
 * @param out_result Cleanup result (must not be NULL, caller must free with cleanup_result_free)
 * @return Error or NULL on success (check result for operation details)
 */
error_t *cleanup_execute(
    git_repository *repo,
    const state_t *state,
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
