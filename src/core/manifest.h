/**
 * Manifest Transparent Layer
 *
 * The manifest module is the single authority for all manifest table modifications.
 * It implements the "Virtual Working Directory" concept - maintaining the manifest
 * table as an expected state cache (scope + Git references + metadata).
 *
 * Core Principles:
 *   - Single Authority: Only this module modifies the manifest table
 *   - Precedence Oracle: Uses profile_build_manifest() for correctness
 *   - Eager Consistency: Manifest updated immediately when inputs change
 *   - Transaction Safety: All operations are atomic (rollback on error)
 *   - Convergence Model: VWD defines scope and expected state, workspace analyzes runtime divergence
 *
 * Workflow:
 *   Commands → manifest layer → state API → SQLite
 *
 * The manifest layer orchestrates existing components:
 *   - profile_build_manifest() for precedence resolution
 *   - metadata_load_from_profiles() for metadata merging
 *   - blob_oid extraction from tree entries for content identity
 *   - state_*() API for persistence
 */

#ifndef DOTTA_MANIFEST_H
#define DOTTA_MANIFEST_H

#include "types.h"
#include "core/state.h"
#include "core/workspace.h"
#include <git2.h>

/**
 * Statistics from profile enable operation
 */
typedef struct {
    size_t total_files;         /* Total files owned by profile (after precedence) */
    size_t already_deployed;    /* Files that exist on filesystem (deployed_at set) */
    size_t needs_deployment;    /* Files that don't exist on filesystem (deployed_at = 0) */
} manifest_enable_stats_t;

/**
 * Statistics from profile disable operation
 */
typedef struct {
    size_t total_files;                /* Total files owned by disabled profile */
    size_t files_with_fallback;        /* Files updated to fallback profile */
    size_t files_removed;              /* Files marked as orphaned (entry remains for detection) */
    size_t directories_with_fallback;  /* Directories updated to fallback profile */
    size_t directories_removed;        /* Directories marked as orphaned */
} manifest_disable_stats_t;

/**
 * Enable profile in manifest
 *
 * Called when a profile is enabled. Populates manifest from Git branch
 * with precedence resolution across all enabled profiles.
 *
 * Algorithm:
 *   1. Get HEAD oid for profile
 *   2. Build manifest from all enabled profiles (precedence oracle)
 *   3. Load merged metadata from all profiles
 *   4. For each file owned by this profile (highest precedence):
 *      - Compute content hash
 *      - Extract metadata
 *      - Insert/update manifest entry
 *
 * Preconditions:
 *   - profile_name MUST be in enabled_profiles
 *   - state MUST have active transaction (via state_load_for_update)
 *   - Git branch for profile_name MUST exist
 *
 * Postconditions:
 *   - All files from profile added/updated in manifest
 *   - Higher precedence files override lower precedence
 *   - Existing entries updated if profile has higher precedence
 *   - New entries inserted with deployed_at based on lstat() check
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_NOT_FOUND: Profile branch doesn't exist
 *   - ERR_GIT: Git operation failed
 *   - ERR_CRYPTO: Encrypted file but key unavailable
 *   - ERR_NOMEM: Memory allocation failed
 *   - ERR_STATE: Database operation failed
 *
 * Performance: O(N) where N = files in profile
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param profile_name Profile being enabled
 * @param enabled_profiles All enabled profiles (including profile_name)
 * @return Error or NULL on success
 */
error_t *manifest_enable_profile(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *enabled_profiles,
    manifest_enable_stats_t *out_stats
);

/**
 * Disable profile in manifest
 *
 * Called when a profile is disabled. Handles fallback to lower-precedence
 * profiles for files that exist in multiple profiles.
 *
 * Algorithm:
 *   1. Get all manifest entries owned by disabled profile
 *   2. Build manifest from remaining profiles (fallback check)
 *   3. For each entry:
 *      - If fallback found: update source_profile + git_oid (file ownership changes)
 *      - If no fallback: entry remains for orphan detection (removed by apply)
 *
 * Preconditions:
 *   - profile_name MUST NOT be in remaining_enabled
 *   - state MUST have active transaction
 *
 * Postconditions:
 *   - Files unique to profile remain for orphan detection (apply will remove)
 *   - Files with fallback updated to fallback profile (source and git_oid changed)
 *   - Entries with fallbacks keep same deployed_at timestamp
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_STATE: Database query failed
 *   - ERR_GIT: Git operation failed
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(F + N) where F = files in fallback profiles, N = files in disabled profile
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param profile_name Profile being disabled
 * @param remaining_enabled Remaining enabled profiles (excluding profile_name)
 * @return Error or NULL on success
 */
error_t *manifest_disable_profile(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *remaining_enabled,
    manifest_disable_stats_t *out_stats
);

/**
 * Update files in manifest (update command)
 *
 * High-performance batch operation that builds a FRESH manifest from Git
 * (post-commit state) instead of using stale workspace manifest. Designed
 * for the update command's workflow where many files are synced at once
 * after Git commits.
 *
 * CRITICAL DESIGN DECISION: This function builds a FRESH manifest from Git
 * because the workspace manifest is stale after commits. Using the stale
 * manifest would cause fallback to expensive single-file operations for
 * newly added files, resulting in O(N×M) complexity instead of O(M+N).
 *
 * Algorithm:
 *   1. Load enabled profiles from Git
 *   2. Build FRESH manifest via profile_build_manifest() (O(M))
 *   3. Use transferred index for O(1) lookups
 *   4. Build profile→oid map for git_oid field
 *   5. For each item (O(N)):
 *      - If DELETED: check fresh manifest for fallback
 *        → Fallback exists: update to fallback profile (deployed_at preserved)
 *        → No fallback: entry remains for orphan detection (apply removes)
 *      - Else (modified/new): lookup in fresh manifest
 *        → Found + precedence matches: sync to state (deployed_at = time(NULL))
 *        → Not found: file filtered/excluded (skip gracefully)
 *   6. All operations within caller's transaction
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - Git commits MUST be completed (branches at final state)
 *   - items MUST be FILE kind only (no directories)
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - Modified/new files synced with deployed_at = time(NULL) (files captured from filesystem)
 *   - Deleted files fallback (deployed_at preserved) or entries remain for orphan detection
 *   - Tracked directories synced from all enabled profiles
 *   - Transaction remains open (caller commits)
 *
 * Performance: O(M + N) where M = total files in profiles, N = items to sync
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param items Array of workspace items to sync (must not be NULL)
 * @param item_count Number of items
 * @param enabled_profiles All enabled profiles (must not be NULL)
 * @param metadata_cache Hashmap: profile_name → metadata_t* (optional).
 *                       Pass NULL to load fresh metadata from Git automatically.
 *                       Pass a hashmap for performance optimization if you have
 *                       fresh per-profile metadata already loaded.
 * @param out_synced Output: count of files synced (must not be NULL)
 * @param out_removed Output: count of files removed (must not be NULL)
 * @param out_fallbacks Output: count of fallback resolutions (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_update_files(
    git_repository *repo,
    state_t *state,
    const workspace_item_t **items,
    size_t item_count,
    const string_array_t *enabled_profiles,
    const hashmap_t *metadata_cache,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks
);

/**
 * Add files to manifest (add command)
 *
 * Optimized batch operation for adding newly-committed files to manifest.
 * Simpler than manifest_update_files() because:
 * - All files are from the same profile
 * - No deletions (only additions/updates)
 * - Files marked with deployed_at = time(NULL) (captured from filesystem)
 *
 * CRITICAL DESIGN: Like manifest_update_files(), this builds a FRESH
 * manifest from Git (post-commit state). This ensures all newly-added files
 * are found during precedence checks, maintaining O(M+N) performance.
 *
 * Algorithm:
 *   1. Load enabled profiles from Git (current HEAD, post-commit)
 *   2. Build fresh manifest with profile_build_manifest() (ONCE)
 *   3. Use transferred index for O(1) precedence lookups
 *   4. Build profile→oid map for git_oid field
 *   5. For each file:
 *      - Convert filesystem_path → storage_path
 *      - Lookup in fresh manifest
 *      - If precedence matches: sync to state with deployed_at = time(NULL)
 *      - If lower precedence or filtered: skip silently
 *   6. All operations within caller's transaction
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - Git commits MUST be completed (branches at final state)
 *   - filesystem_paths MUST be valid, canonical paths
 *   - profile_name SHOULD be enabled (function gracefully handles if not)
 *
 * Postconditions:
 *   - Files synced to manifest with deployed_at = time(NULL)
 *   - Lower-precedence files skipped (not an error)
 *   - Filtered files skipped (not an error)
 *   - Tracked directories synced from all enabled profiles
 *   - Transaction remains open (caller commits via state_save)
 *
 * Performance:
 *   - O(M + N) where M = total files in all profiles, N = files to add
 *   - Single fresh manifest build from Git
 *   - Batch-optimized state operations
 *
 * Error Handling:
 *   - Transactional: on error, entire batch fails
 *   - Returns error on first failure (fail-fast)
 *   - Path resolution errors are fatal
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param profile_name Profile files were added to (must not be NULL)
 * @param filesystem_paths Array of filesystem paths (must not be NULL)
 * @param enabled_profiles All enabled profiles (must not be NULL)
 * @param metadata_cache Hashmap: profile_name → metadata_t* (optional).
 *                       Pass NULL to load fresh metadata from Git automatically.
 *                       Pass a hashmap for performance optimization if you have
 *                       fresh per-profile metadata already loaded.
 * @param out_synced Output: count of files synced (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_add_files(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *filesystem_paths,
    const string_array_t *enabled_profiles,
    const hashmap_t *metadata_cache,
    size_t *out_synced
);

/**
 * Remove files from manifest (remove command)
 *
 * Called after remove command deletes files from a profile branch.
 * Handles fallback to lower-precedence profiles or marks for removal.
 *
 * Algorithm:
 *   1. Build fresh manifest from enabled profiles (precedence oracle)
 *   2. Build profile→oid map for git_oid field
 *   3. For each removed file:
 *      a. Resolve to filesystem path
 *      b. Lookup current manifest entry
 *      c. Check if removed profile owns it (precedence check)
 *      d. If yes:
 *         - Check fresh manifest for fallback
 *         - Fallback exists: Update to fallback profile (deployed_at preserved)
 *         - No fallback: Entry remains for orphan detection (apply removes)
 *      e. If no (different profile owns): Skip
 *
 * Preconditions:
 *   - state MUST have active transaction
 *   - Git commit MUST be completed (files removed from branch)
 *   - removed_storage_paths MUST be in storage format (home/.bashrc)
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - Files with fallback updated to fallback profile (deployed_at preserved)
 *   - Files without fallback: entries remain for orphan detection (apply removes)
 *   - Files not owned by removed_profile unchanged
 *   - Tracked directories synced from all enabled profiles
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT: Git operation failed
 *   - ERR_STATE: Database operation failed
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(M + N) where M = total files in profiles, N = files removed
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param removed_profile Profile files were removed from (must not be NULL)
 * @param removed_storage_paths Storage paths of removed files (must not be NULL)
 * @param enabled_profiles All enabled profiles (must not be NULL)
 * @param out_removed Output: files without fallback (entries remain for orphan detection) (can be NULL)
 * @param out_fallbacks Output: files updated to fallback (can be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_remove_files(
    git_repository *repo,
    state_t *state,
    const char *removed_profile,
    const string_array_t *removed_storage_paths,
    const string_array_t *enabled_profiles,
    size_t *out_removed,
    size_t *out_fallbacks
);

/**
 * Rebuild manifest from scratch
 *
 * Nuclear option: Clear and rebuild entire manifest from Git.
 * Used for repair/recovery operations only.
 *
 * Algorithm (optimized O(M) approach):
 *   1. Clear all file entries from manifest
 *   2. Build manifest ONCE from all enabled profiles (precedence oracle)
 *   3. Build profile→oid map for git_oid field
 *   4. Load merged metadata from all profiles
 *   5. Create keymanager for content hashing
 *   6. Sync ALL entries from manifest to state (single pass, no filtering)
 *   7. Sync tracked directories
 *
 * Key optimization: Builds manifest once and syncs all entries directly,
 * rather than calling manifest_enable_profile() N times (which would rebuild
 * the manifest N times). This reduces complexity from O(N × M) to O(M).
 *
 * WARNING: This is a destructive operation that clears all manifest entries.
 * However, lifecycle tracking is preserved: existing entries retain their deployed_at,
 * new entries use lstat() to check filesystem (deployed_at = time(NULL) if exists, else 0).
 *
 * Preconditions:
 *   - state MUST have active transaction
 *   - enabled_profiles MUST be current enabled set
 *   - Empty profile list supported (clears manifest, syncs empty directories)
 *
 * Postconditions:
 *   - Manifest cleared and rebuilt from enabled profiles
 *   - Existing entries preserve deployed_at (lifecycle history maintained)
 *   - New entries set deployed_at based on filesystem lstat() check
 *   - Empty profile list results in empty manifest
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_STATE: Database clear failed
 *   - ERR_GIT: Git operation failed
 *   - ERR_CRYPTO: Encrypted file but key unavailable
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(M) where M = total files across all enabled profiles
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param enabled_profiles Enabled profiles to build from
 * @return Error or NULL on success
 */
error_t *manifest_rebuild(
    git_repository *repo,
    state_t *state,
    const string_array_t *enabled_profiles
);

/**
 * Reorder profiles in manifest
 *
 * Called when profiles are reordered. Intelligently updates ownership
 * and status only for files that change owner, preserving DEPLOYED
 * status for files whose ownership remains unchanged.
 *
 * Algorithm:
 *   1. Build manifest from new profile order (precedence oracle)
 *   2. Get all current manifest entries and build hashmap for O(1) lookups
 *   3. For each file in new manifest:
 *      - If not in old manifest: add with deployed_at = 0 (rare, file never deployed)
 *      - If owner changed: update source_profile + git_oid (deployed_at preserved)
 *      - If owner unchanged: skip (preserve existing entry)
 *   4. For files in old manifest but not new: entries remain for orphan detection (apply removes)
 *
 * Key Benefit: Unlike manifest_rebuild(), this preserves deployed_at timestamps
 * for files whose ownership doesn't change, providing better UX when
 * reordering profiles.
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - new_profile_order MUST be valid enabled profiles
 *
 * Postconditions:
 *   - Files with changed ownership updated (deployed_at preserved)
 *   - Files with unchanged ownership preserve existing entry
 *   - Orphaned files: entries remain for orphan detection (apply removes)
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT: Git operation failed
 *   - ERR_CRYPTO: Encrypted file but key unavailable
 *   - ERR_STATE: Database operation failed
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(N + M) where N = files in old manifest, M = files in new manifest
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param new_profile_order New profile order (determines precedence)
 * @return Error or NULL on success
 */
error_t *manifest_reorder_profiles(
    git_repository *repo,
    state_t *state,
    const string_array_t *new_profile_order
);

/**
 * Sync manifest from Git diff (sync command)
 *
 * Updates manifest table based on changes between old_oid and new_oid for a
 * single profile. This is the core function for updating the manifest after
 * sync operations (pull, rebase, merge).
 *
 * Called by sync command after:
 *   - Fast-forward pull (REMOTE_AHEAD case)
 *   - Divergence resolution (REBASE/MERGE/THEIRS strategies)
 *
 * Algorithm:
 *   Phase 1: Build Context (O(M))
 *     - Load all enabled profiles
 *     - Build fresh manifest from current Git state (post-sync)
 *     - Use transferred index for O(1) file lookups
 *     - Build profile→oid map
 *     - Load or use cached metadata and keymanager
 *
 *   Phase 2: Compute Diff (O(D))
 *     - Lookup old and new trees
 *     - Generate Git diff between them
 *
 *   Phase 3: Process Deltas (O(D))
 *     - For additions/modifications: sync (deployed_at preserved if exists, else 0 for new files)
 *     - For deletions: check for fallbacks, entries remain for orphan detection if none
 *     - Handle precedence: only sync if profile won the file
 *
 * Deletion & Fallback Logic:
 *   When a file is deleted from profile-A:
 *     1. Check new precedence manifest (built from post-sync state)
 *     2. If another profile (profile-B) now wins: update to profile-B (fallback)
 *     3. If no other profile has it: check current state
 *     4. If profile-A owns it in state: entry remains for orphan detection (apply removes)
 *     5. Otherwise: skip (file wasn't ours to begin with)
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - old_oid and new_oid MUST be valid commits for profile_name's branch
 *   - profile_name MUST be in enabled_profiles
 *   - Branch HEAD for profile_name MUST point to new_oid (post-sync state)
 *
 * Postconditions:
 *   - Added/modified files synced (deployed_at preserved if exists, else 0 for new files)
 *   - Deleted files with fallbacks updated to new owner (deployed_at preserved)
 *   - Deleted files without fallbacks: entries remain for orphan detection (apply removes)
 *   - Files filtered by .dottaignore are skipped (expected behavior)
 *   - Files won by other profiles are skipped (they'll sync when their changes arrive)
 *   - Tracked directories synced from all enabled profiles
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT: Git tree lookup or diff failed
 *   - ERR_CRYPTO: Encrypted file but key unavailable
 *   - ERR_STATE: Database operation failed
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(M + D) where M = total files in all profiles, D = changed files
 *
 * Convergence Semantics:
 *   Sync updates VWD expected state (git_oid, blob_oid) but doesn't deploy to filesystem.
 *   User must run 'dotta apply' which uses runtime divergence analysis to deploy changes.
 *
 * @param repo Repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param profile_name Profile being synced (must not be NULL)
 * @param old_oid Old commit before sync (must not be NULL)
 * @param new_oid New commit after sync (must not be NULL)
 * @param enabled_profiles All enabled profiles for precedence (must not be NULL)
 * @param metadata_cache Pre-loaded metadata (can be NULL, will load if needed)
 * @param out_synced Output: number of files synced (can be NULL)
 * @param out_removed Output: number of files removed (can be NULL)
 * @param out_fallbacks Output: number of fallback resolutions (can be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_sync_diff(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles,
    const hashmap_t *metadata_cache,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks
);

/**
 * Sync tracked directories from enabled profiles
 *
 * Rebuilds the tracked_directories table from profile metadata.
 * Part of the Virtual Working Directory (VWD) consistency model.
 *
 * Called by profile operations (enable/disable/reorder) to keep directory
 * tracking synchronized with the enabled profile set.
 *
 * Unlike files (which have lifecycle states: pending/deployed/removal),
 * directories are simply tracked for profile attribution and metadata
 * preservation. This function uses a rebuild pattern (clear + repopulate)
 * rather than incremental updates.
 *
 * Algorithm:
 *   1. Clear all tracked directories
 *   2. For each enabled profile:
 *      a. Load metadata from Git (skip if not found)
 *      b. Extract directories from metadata
 *      c. Add to state with profile attribution
 *   3. All within caller's active transaction
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - tracked_directories table reflects enabled_profiles
 *   - Transaction remains open (caller commits)
 *   - Missing metadata handled gracefully (not an error)
 *
 * Error Conditions:
 *   - ERR_GIT: Git operation failed
 *   - ERR_STATE: Database operation failed
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(D) where D = total directories (typically < 50)
 *
 * @param repo Git repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param enabled_profiles Current enabled profiles (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_sync_directories(
    git_repository *repo,
    state_t *state,
    const string_array_t *enabled_profiles
);

#endif /* DOTTA_MANIFEST_H */
