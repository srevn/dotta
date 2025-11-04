/**
 * Manifest Transparent Layer
 *
 * The manifest module is the single authority for all manifest table modifications.
 * It implements the "Virtual Working Directory" concept - maintaining the manifest
 * table as a staging area between Git branches and the filesystem.
 *
 * Core Principles:
 *   - Single Authority: Only this module modifies the manifest table
 *   - Precedence Oracle: Uses profile_build_manifest() for correctness
 *   - Eager Consistency: Manifest updated immediately when inputs change
 *   - Transaction Safety: All operations are atomic (rollback on error)
 *
 * Workflow:
 *   Commands → manifest layer → state API → SQLite
 *
 * The manifest layer orchestrates existing components:
 *   - profile_build_manifest() for precedence resolution
 *   - metadata_load_from_profiles() for metadata merging
 *   - content_hash_*() for content comparison
 *   - state_*() API for persistence
 */

#ifndef DOTTA_MANIFEST_H
#define DOTTA_MANIFEST_H

#include "types.h"
#include "core/state.h"
#include "core/workspace.h"
#include "crypto/keymanager.h"
#include <git2.h>

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
 *   - New entries inserted with status = PENDING_DEPLOYMENT
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
    const string_array_t *enabled_profiles
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
 *      - If fallback found: update source_profile + git_oid, mark PENDING_DEPLOYMENT
 *      - If no fallback: mark PENDING_REMOVAL
 *
 * Preconditions:
 *   - profile_name MUST NOT be in remaining_enabled
 *   - state MUST have active transaction
 *
 * Postconditions:
 *   - Files unique to profile marked PENDING_REMOVAL
 *   - Files with fallback updated to fallback profile (PENDING_DEPLOYMENT)
 *   - No entries with source_profile = profile_name remain
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
    const string_array_t *remaining_enabled
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
 *        → Fallback exists: update to fallback profile
 *        → No fallback: mark PENDING_REMOVAL
 *      - Else (modified/new): lookup in fresh manifest
 *        → Found + precedence matches: sync to state (DEPLOYED status)
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
 *   - Modified/new files synced with status=DEPLOYED
 *   - Deleted files fallback or marked PENDING_REMOVAL
 *   - Transaction remains open (caller commits)
 *
 * Performance: O(M + N) where M = total files in profiles, N = items to sync
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param items Array of workspace items to sync (must not be NULL)
 * @param item_count Number of items
 * @param enabled_profiles All enabled profiles (must not be NULL)
 * @param km Keymanager for content hashing (can be NULL if no encryption)
 * @param metadata_cache Hashmap: profile_name → metadata_t* (must not be NULL)
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
    keymanager_t *km,
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
 * - Status is always MANIFEST_STATUS_DEPLOYED (captured from filesystem)
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
 *      - If precedence matches: sync to state with DEPLOYED status
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
 *   - Files synced to manifest with MANIFEST_STATUS_DEPLOYED
 *   - Lower-precedence files skipped (not an error)
 *   - Filtered files skipped (not an error)
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
 * @param km Keymanager for content hashing (can be NULL if no encryption)
 * @param metadata_cache Hashmap: profile_name → metadata_t* (must not be NULL)
 * @param out_synced Output: count of files synced (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_add_files(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *filesystem_paths,
    const string_array_t *enabled_profiles,
    keymanager_t *km,
    const hashmap_t *metadata_cache,
    size_t *out_synced
);

/**
 * Rebuild manifest from scratch
 *
 * Nuclear option: Clear and rebuild entire manifest from Git.
 * Used for repair/recovery operations only.
 *
 * Algorithm:
 *   1. Clear all file entries from manifest
 *   2. For each enabled profile:
 *      - Call manifest_sync_profile()
 *
 * WARNING: This is a destructive operation. All status tracking is lost.
 * All entries reset to PENDING_DEPLOYMENT.
 *
 * Preconditions:
 *   - state MUST have active transaction
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - Manifest cleared
 *   - All files from enabled profiles re-added
 *   - All entries have status = PENDING_DEPLOYMENT
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_STATE: Database clear failed
 *   - ERR_GIT: Git operation failed
 *   - ERR_CRYPTO: Encrypted file but key unavailable
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(N) where N = total files across all enabled profiles
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
 *      - If not in old manifest: add with PENDING_DEPLOYMENT (rare)
 *      - If owner changed: update source_profile + git_oid, mark PENDING_DEPLOYMENT
 *      - If owner unchanged: skip (preserve existing status)
 *   4. For files in old manifest but not new: mark PENDING_REMOVAL (O(1) index lookup)
 *
 * Key Benefit: Unlike manifest_rebuild(), this preserves DEPLOYED status
 * for files whose ownership doesn't change, providing better UX when
 * reordering profiles.
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - new_profile_order MUST be valid enabled profiles
 *
 * Postconditions:
 *   - Files with changed ownership marked PENDING_DEPLOYMENT
 *   - Files with unchanged ownership preserve existing status
 *   - Orphaned files marked PENDING_REMOVAL
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
 *     - For additions/modifications: sync with PENDING_DEPLOYMENT status
 *     - For deletions: check for fallbacks, mark PENDING_REMOVAL if none
 *     - Handle precedence: only sync if profile won the file
 *
 * Deletion & Fallback Logic:
 *   When a file is deleted from profile-A:
 *     1. Check new precedence manifest (built from post-sync state)
 *     2. If another profile (profile-B) now wins: update to profile-B (fallback)
 *     3. If no other profile has it: check current state
 *     4. If profile-A owns it in state: mark PENDING_REMOVAL
 *     5. Otherwise: skip (file wasn't ours to begin with)
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - old_oid and new_oid MUST be valid commits for profile_name's branch
 *   - profile_name MUST be in enabled_profiles
 *   - Branch HEAD for profile_name MUST point to new_oid (post-sync state)
 *
 * Postconditions:
 *   - Added/modified files marked PENDING_DEPLOYMENT
 *   - Deleted files with fallbacks updated to new owner, marked PENDING_DEPLOYMENT
 *   - Deleted files without fallbacks marked PENDING_REMOVAL
 *   - Files filtered by .dottaignore are skipped (expected behavior)
 *   - Files won by other profiles are skipped (they'll sync when their changes arrive)
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
 * Status Semantics:
 *   All changes marked PENDING_DEPLOYMENT because sync updates Git but doesn't
 *   deploy to filesystem. User must run 'dotta apply' to actually deploy changes.
 *
 * @param repo Repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param profile_name Profile being synced (must not be NULL)
 * @param old_oid Old commit before sync (must not be NULL)
 * @param new_oid New commit after sync (must not be NULL)
 * @param enabled_profiles All enabled profiles for precedence (must not be NULL)
 * @param km Keymanager for content hashing (can be NULL, will create if needed)
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
    keymanager_t *km,
    const hashmap_t *metadata_cache,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks
);

#endif /* DOTTA_MANIFEST_H */
