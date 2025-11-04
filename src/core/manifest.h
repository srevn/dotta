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
 * Sync entire profile to manifest (bulk population)
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
error_t *manifest_sync_profile(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *enabled_profiles
);

/**
 * Remove profile from manifest (bulk cleanup)
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
 * Performance: O(N*M) where N = files in profile, M = remaining profiles
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param profile_name Profile being disabled
 * @param remaining_enabled Remaining enabled profiles (excluding profile_name)
 * @return Error or NULL on success
 */
error_t *manifest_unsync_profile(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *remaining_enabled
);

/**
 * Sync single file to manifest
 *
 * Called when a file is added/updated in an enabled profile.
 * Handles precedence resolution automatically.
 *
 * Algorithm:
 *   1. Build manifest from all enabled profiles (precedence check)
 *   2. Check if this profile should own the file
 *   3. If yes: compute content hash, get metadata, sync to state
 *   4. If no: skip (lower precedence)
 *
 * Preconditions:
 *   - profile_name MUST be in enabled_profiles
 *   - state MUST have active transaction
 *   - git_oid MUST reference a valid commit
 *   - File MUST exist in profile branch at storage_path
 *
 * Postconditions:
 *   - Entry added/updated if profile has sufficient precedence
 *   - Entry skipped if lower precedence profile already owns file
 *   - Status set based on initial_status parameter
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT: Git operation failed (file not found, invalid oid)
 *   - ERR_CRYPTO: Encrypted file but key unavailable
 *   - ERR_NOMEM: Memory allocation failed
 *   - ERR_STATE: Database operation failed
 *
 * Performance: O(M) where M = total files across all enabled profiles
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param profile_name Profile containing the file
 * @param storage_path Path in profile (e.g., "home/.bashrc")
 * @param filesystem_path Resolved filesystem path
 * @param git_oid Git commit reference (40-char hex)
 * @param enabled_profiles All enabled profiles
 * @param initial_status Initial status (DEPLOYED for add, PENDING_DEPLOYMENT for update)
 * @return Error or NULL on success
 */
error_t *manifest_sync_file(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const char *storage_path,
    const char *filesystem_path,
    const char *git_oid,
    const string_array_t *enabled_profiles,
    manifest_status_t initial_status
);

/**
 * Remove file from manifest
 *
 * Called when a file is removed from a profile. Handles fallback to
 * lower-precedence profiles if file exists elsewhere.
 *
 * Algorithm:
 *   1. Get entry from manifest
 *   2. Build manifest from enabled profiles (fallback check)
 *   3. If fallback found: update to fallback profile, mark PENDING_DEPLOYMENT
 *   4. If no fallback: mark PENDING_REMOVAL
 *
 * Preconditions:
 *   - state MUST have active transaction
 *   - filesystem_path MUST exist in manifest
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - If no fallback: entry marked PENDING_REMOVAL
 *   - If fallback exists: entry updated to fallback profile (PENDING_DEPLOYMENT)
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_NOT_FOUND: File not in manifest
 *   - ERR_GIT: Git operation failed
 *   - ERR_STATE: Database operation failed
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(M) where M = total files across enabled profiles
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param filesystem_path File to remove
 * @param enabled_profiles All enabled profiles
 * @return Error or NULL on success
 */
error_t *manifest_remove_file(
    git_repository *repo,
    state_t *state,
    const char *filesystem_path,
    const string_array_t *enabled_profiles
);

/**
 * Sync multiple files to manifest in bulk (optimized for update command)
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
 *   3. Build hashmap index for O(1) lookups
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
error_t *manifest_sync_files_bulk(
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
 * Sync changes from git diff to manifest
 *
 * Called after sync pulls remote changes. Updates manifest based on
 * diff between old and new tree.
 *
 * Algorithm:
 *   1. Compute diff between old_oid and new_oid trees
 *   2. For added/modified files: sync each file (via manifest_sync_file)
 *   3. For deleted files: remove each file (via manifest_remove_file)
 *
 * Preconditions:
 *   - profile_name MUST be in enabled_profiles
 *   - state MUST have active transaction
 *   - old_oid and new_oid MUST reference valid commits
 *
 * Postconditions:
 *   - Added/modified files: git_oid and content_hash updated, status = PENDING_DEPLOYMENT
 *   - Deleted files: updated to fallback OR marked PENDING_REMOVAL
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT: Git diff operation failed
 *   - ERR_CRYPTO: Encrypted file but key unavailable
 *   - ERR_STATE: Database operation failed
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(D*M) where D = changed files, M = total files in profiles
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param profile_name Profile that was synced
 * @param old_oid Old HEAD oid (before pull)
 * @param new_oid New HEAD oid (after pull)
 * @param enabled_profiles All enabled profiles
 * @return Error or NULL on success
 */
error_t *manifest_sync_changes(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles
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
 * Update manifest after profile precedence change
 *
 * Called when profiles are reordered. Intelligently updates ownership
 * and status only for files that change owner, preserving DEPLOYED
 * status for files whose ownership remains unchanged.
 *
 * Algorithm:
 *   1. Build manifest from new profile order (precedence oracle)
 *   2. Get all current manifest entries
 *   3. For each file in new manifest:
 *      - If not in old manifest: add with PENDING_DEPLOYMENT (rare)
 *      - If owner changed: update source_profile + git_oid, mark PENDING_DEPLOYMENT
 *      - If owner unchanged: skip (preserve existing status)
 *   4. For files in old manifest but not new: mark PENDING_REMOVAL
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
 * Performance: O(N*M) where N = files in manifest, M = enabled profiles
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param new_profile_order New profile order (determines precedence)
 * @return Error or NULL on success
 */
error_t *manifest_update_for_precedence_change(
    git_repository *repo,
    state_t *state,
    const string_array_t *new_profile_order
);

#endif /* DOTTA_MANIFEST_H */
