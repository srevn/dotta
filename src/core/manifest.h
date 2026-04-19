/**
 * Manifest Module
 *
 * Owns the Virtual Working Directory (VWD) types and all manifest operations:
 *   - Type definitions: file_entry_t, manifest_t
 *   - Construction: manifest_build(), manifest_build_from_tree(), manifest_free()
 *   - Consistency layer: manifest_enable_profile(), manifest_sync_diff(), etc.
 *
 * The manifest module is the single authority for all manifest table modifications.
 * It implements the "Virtual Working Directory" concept - maintaining the manifest
 * table as an expected state cache (scope + Git references + metadata).
 *
 * Core Principles:
 *   - Single Authority: Only this module modifies the manifest table
 *   - Precedence Oracle: Uses manifest_build() for correctness
 *   - Eager Consistency: Manifest updated immediately when inputs change
 *   - Transaction Safety: All operations are atomic (rollback on error)
 *   - Convergence Model: VWD defines scope and expected state, workspace analyzes runtime divergence
 *
 * Workflow:
 *   Commands → manifest layer → state API → SQLite
 *
 * The manifest layer orchestrates existing components:
 *   - manifest_build() for precedence resolution
 *   - metadata_load_from_profiles() for metadata merging
 *   - blob_oid extraction from tree entries for content identity
 *   - state_*() API for persistence
 */

#ifndef DOTTA_MANIFEST_H
#define DOTTA_MANIFEST_H

#include <git2.h>
#include <types.h>

#include "core/state.h"
#include "core/workspace.h"

/**
 * File entry in manifest
 *
 * Represents a single file to be deployed. This structure serves as the
 * Virtual Working Directory (VWD) cache, storing both Git tree information
 * and expected state from the database for efficient divergence detection.
 *
 * Two-domain layout (mirrors state_file_entry_t):
 *   VWD cache    — git-derived expected state (blob_oid, type, mode,
 *                  owner, group, encrypted). Maintained by the manifest
 *                  layer (reconcile/sync/rebuild).
 *   Deployment   — dotta's record of "disk was confirmed to equal this
 *     anchor       blob, at this time, with this stat." Advanced only by
 *                  state_update_anchor() after a disk-matches-blob confirmation.
 *
 * The two domains differ on anchor.blob_oid vs blob_oid iff Git-expected has
 * advanced past the last disk confirmation — i.e., the entry is stale.
 *
 * VWD Architecture:
 * - The manifest is the authoritative cache of expected state
 * - Fields are populated from state database during workspace load
 * - Enables O(1) divergence checking without N database queries
 * - Identity fields (blob_oid, type, mode) are always populated regardless
 *   of construction path (Git tree walk or state DB)
 *
 * Memory ownership:
 * - All string fields are owned and must be freed in manifest_free()
 * - profile is borrowed (from caller's profiles array, workspace profile_index,
 *   state arena, or manifest's owned_profile for tree-based manifests)
 */
typedef struct file_entry {
    /* Paths */
    char *storage_path;              /* Path in profile (home/.bashrc) */
    char *filesystem_path;           /* Deployed path (/home/user/.bashrc) */

    /* Profile ownership */
    const char *profile;             /* Profile name (borrowed, used for all name-based operations) */
    char *old_profile;               /* Previous owner if changed, NULL otherwise (VWD cache) */

    /* VWD cache (git-derived, reconcile-maintained) */
    git_oid blob_oid;                /* Blob the composed profile layer expects on disk */
    state_file_type_t type;          /* File type (REGULAR, SYMLINK, EXECUTABLE) */
    mode_t mode;                     /* Permission mode (e.g., 0644), 0 if no metadata tracked */
    char *owner;                     /* Owner username (root/ files only, can be NULL) */
    char *group;                     /* Group name (root/ files only, can be NULL) */
    bool encrypted;                  /* Encryption flag */

    /* Deployment anchor (dotta-authored, advances only via state_update_anchor) */
    deployment_anchor_t anchor;
} file_entry_t;

/**
 * Manifest - collection of files to deploy
 *
 * The index field provides O(1) lookups by filesystem_path. It maps
 * filesystem_path -> array index (offset by 1 to distinguish NULL from index 0).
 * The index is populated by manifest_build() and can be NULL for
 * manifests built by other means (e.g., workspace_build_manifest_from_state).
 *
 * For tree-based manifests (manifest_build_from_tree), the manifest
 * owns the profile name string that entries borrow.
 * This is NULL for manifests from manifest_build() (which borrow
 * from the caller's profiles array) and workspace_build_manifest_from_state()
 * (which borrow from the workspace's profile_index).
 */
typedef struct manifest {
    file_entry_t *entries;
    size_t count;
    hashmap_t *index;              /* Maps filesystem_path -> index in entries array (offset by 1), can be NULL */
    char *owned_profile;           /* Owned profile name for tree-based manifests (NULL otherwise) */
    bool arena_backed;             /* If true, entry string fields are arena-owned (skip free) */
} manifest_t;

/**
 * Statistics from profile enable operation
 */
typedef struct {
    size_t total_files;         /* Total files owned by profile (after precedence) */
    size_t already_deployed;    /* Files that exist on filesystem (deployed_at set) */
    size_t needs_deployment;    /* Files that don't exist on filesystem (deployed_at = 0) */
    size_t access_errors;       /* Files with lstat errors (counted in needs_deployment) */
} manifest_enable_stats_t;

/**
 * Statistics from profile disable operation
 */
typedef struct {
    size_t total_files;                /* Total files owned by disabled profile */
    size_t files_with_fallback;        /* Files updated to fallback profile */
    size_t files_removed;              /* Files marked inactive (staged for removal) */
    size_t directories_with_fallback;  /* Directories updated to fallback profile */
    size_t directories_removed;        /* Directories marked as orphaned */
} manifest_disable_stats_t;

/**
 * Statistics from stale manifest repair
 */
typedef struct {
    size_t updated;     /* Files with changed blob_oid (content changed in Git) */
    size_t refreshed;   /* Files with only HEAD refresh (content unchanged) */
    size_t released;    /* Files set to STATE_RELEASED (removed from Git externally) */
    size_t reassigned;  /* Files whose owning profile shifted during repair */
} manifest_repair_stats_t;

/**
 * Enable profile in manifest
 *
 * Called when a profile is enabled. Populates manifest from Git branch
 * with precedence resolution across all enabled profiles.
 *
 * Algorithm:
 *   1. Build manifest from all enabled profiles (precedence oracle)
 *   2. Load merged metadata from all profiles
 *   3. For each file owned by this profile (highest precedence):
 *      - Extract blob OID from Git tree entry (content identity)
 *      - Extract metadata
 *      - Insert/update manifest entry
 *
 * Custom prefix resolution is handled internally by the oracle.
 * The caller must store the custom prefix via state_enable_profile()
 * BEFORE calling this function, so it's visible in the state database.
 *
 * Preconditions:
 *   - profile MUST be in enabled_profiles
 *   - state MUST have active transaction (via state_open)
 *   - Git branch for profile MUST exist
 *   - Custom prefix (if any) MUST already be stored via state_enable_profile()
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
 * @param profile Profile being enabled
 * @param enabled_profiles All enabled profiles (including profile)
 * @return Error or NULL on success
 */
error_t *manifest_enable_profile(
    git_repository *repo,
    state_t *state,
    const char *profile,
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
 *      - If fallback found: reassign to fallback profile
 *      - If no fallback: mark as STATE_INACTIVE (staged for removal by apply)
 *
 * Preconditions:
 *   - profile MUST NOT be in remaining_enabled
 *   - state MUST have active transaction
 *
 * Postconditions:
 *   - Files unique to profile marked STATE_INACTIVE (apply will remove)
 *   - Files with fallback updated to fallback profile (source changed)
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
 * @param profile Profile being disabled
 * @param remaining_enabled Remaining enabled profiles (excluding profile)
 * @return Error or NULL on success
 */
error_t *manifest_disable_profile(
    git_repository *repo,
    state_t *state,
    const char *profile,
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
 *   2. Build FRESH manifest via manifest_build() (O(M))
 *   3. Use transferred index for O(1) lookups
 *   4. Sync commit_oid in enabled_profiles after entry sync
 *   5. For each item (O(N)):
 *      - If DELETED: check fresh manifest for fallback
 *        → Fallback exists: update to fallback profile (deployed_at preserved)
 *        → No fallback: mark as STATE_INACTIVE (staged for removal)
 *      - Else (modified/new): lookup in fresh manifest
 *        → Found + precedence matches: sync to state (deployed_at = time(NULL))
 *        → Not found: file filtered/excluded (skip gracefully)
 *   6. All operations within caller's transaction
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - Git commits MUST be completed (branches at final state)
 *   - items MUST be FILE kind only (no directories)
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - Modified/new files synced with deployed_at = time(NULL) (files captured from filesystem)
 *   - Modified/new files also have their deployment anchor advanced
 *     (blob_oid + fresh disk stat, lifecycle timestamp preserved). Anchor-write
 *     failures are non-fatal — the VWD cache is already committed and the next
 *     status falls through to the slow path, which self-heals the anchor.
 *   - Deleted files fallback (deployed_at preserved) or marked STATE_INACTIVE;
 *     anchor left untouched (no disk confirmation for deleted/fallback paths)
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
 *   2. Build fresh manifest with manifest_build() (ONCE)
 *   3. Use transferred index for O(1) precedence lookups
 *   4. Sync commit_oid in enabled_profiles after entry sync
 *   5. For each file:
 *      - Convert filesystem_path → storage_path
 *      - Lookup in fresh manifest
 *      - If precedence matches: sync to state with deployed_at = time(NULL)
 *      - If lower precedence or filtered: skip silently
 *   6. All operations within caller's transaction
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - Git commits MUST be completed (branches at final state)
 *   - filesystem_paths MUST be valid, canonical paths
 *   - profile SHOULD be enabled (function gracefully handles if not)
 *
 * Postconditions:
 *   - Files synced to manifest with deployed_at = time(NULL)
 *   - Synced entries also have their deployment anchor advanced
 *     (blob_oid + fresh disk stat, lifecycle timestamp preserved). Anchor-write
 *     failures are non-fatal — the VWD cache is already committed and the next
 *     status falls through to the slow path, which self-heals the anchor.
 *   - Lower-precedence files skipped (no sync, no anchor advance — prevents
 *     poisoning the winning profile's anchor with a disk stat that may not
 *     correspond to the winner's blob_oid)
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
 * @param profile Profile files were added to (must not be NULL)
 * @param filesystem_paths Array of filesystem paths (must not be NULL)
 * @param enabled_profiles All enabled profiles (must not be NULL)
 * @param out_synced Output: count of files synced (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_add_files(
    git_repository *repo,
    state_t *state,
    const char *profile,
    const string_array_t *filesystem_paths,
    const string_array_t *enabled_profiles,
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
 *   2. Sync commit_oid in enabled_profiles after entry sync
 *   3. For each removed file:
 *      a. Resolve to filesystem path
 *      b. Lookup current manifest entry
 *      c. Check if removed profile owns it (precedence check)
 *      d. If yes:
 *         - Check fresh manifest for fallback
 *         - Fallback exists: Update to fallback profile (deployed_at preserved)
 *         - No fallback: Mark as STATE_DELETED (controlled deletion)
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
 *   - Files without fallback marked STATE_DELETED (controlled deletion)
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
 * @param out_removed Output: files without fallback (marked inactive) (can be NULL)
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
 *   3. Sync commit_oid in enabled_profiles after entry sync
 *   4. Load merged metadata from all profiles
 *   5. Sync ALL entries from manifest to state (single pass, no filtering)
 *   6. Sync tracked directories
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
 * Reconcile manifest with current Git state (drift repair)
 *
 * The single public entry point for drift-based VWD repair. Brings the
 * manifest into sync with Git by detecting profiles whose stored commit_oid
 * no longer matches the branch HEAD and updating affected state entries.
 * Used by workspace_load at load-start and by sync before push.
 *
 * Complements manifest_sync_diff(): reconcile is drift-driven ("don't know
 * what changed, figure it out"), while sync_diff applies a known old→new
 * diff. Both write the manifest; this function is the one callers reach for
 * when they only know "something in Git may have moved."
 *
 * Transaction management
 * ----------------------
 * This function handles transactions internally by inspecting state_locked():
 *   - Caller already holds a transaction (apply's dotta_ext_write, sync's
 *     state_begin) → writes commit with the caller's transaction.
 *   - Caller doesn't hold one (workspace loading from status/diff/update) →
 *     opens a scoped BEGIN IMMEDIATE, commits on success, rolls back on
 *     failure.
 *
 * Callers never need to pre-open a transaction for this function.
 *
 * Profile scope
 * -------------
 * Current enabled profiles are fetched internally. Callers that have already
 * fetched the list for their own reasons need not pass it; the primitive
 * reads under whatever transaction is active. Empty enabled set is a valid
 * no-op (reconcile early-returns).
 *
 * Preconditions:
 *   - state MUST be opened (read or write; transaction optional)
 *
 * Postconditions:
 *   - Drift repaired; manifest entries' VWD cache (blob_oid, type, mode, …)
 *     reflects current Git HEAD for each profile
 *   - The deployment anchor is left untouched — reconcile is a VWD-cache
 *     writer, not an anchor writer. Workspace divergence analysis reads
 *     anchor.blob_oid from persistent state to classify staleness; cross-
 *     process correct by construction
 *   - Caller's transaction state is unchanged (kept outer lock, or
 *     committed our scoped one)
 *
 * Performance:
 *   Common case (no staleness): O(P) state queries + O(P) ref lookups
 *   Stale case: O(M) fresh manifest build, M = total files in Git
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (must not be NULL)
 * @param out_stats Optional: repair statistics (NULL = don't care)
 * @return Error or NULL on success
 */
error_t *manifest_reconcile(
    git_repository *repo,
    state_t *state,
    manifest_repair_stats_t *out_stats
);

/**
 * Reorder profiles in manifest
 *
 * Called when profiles are reordered. Intelligently updates reassignment
 * and status only for files that change owner, preserving DEPLOYED
 * status for files whose profile assignment remains unchanged.
 *
 * Algorithm:
 *   1. Build manifest from new profile order (precedence oracle)
 *   2. Get all current manifest entries and build hashmap for O(1) lookups
 *   3. For each file in new manifest:
 *      - If not in old manifest: add with deployed_at = 0 (rare, file never deployed)
 *      - If owner changed: update profile assignment (deployed_at preserved)
 *      - If owner unchanged: skip (preserve existing entry)
 *   4. For files in old manifest but not new: remain for orphan detection (apply removes)
 *
 * Key Benefit: Unlike manifest_rebuild(), this preserves deployed_at timestamps
 * for files whose profile assignment doesn't change, providing better UX when
 * reordering profiles.
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - new_profile_order MUST be valid enabled profiles
 *
 * Postconditions:
 *   - Reassigned files updated (deployed_at preserved)
 *   - Files with unchanged assignment preserve existing entry
 *   - Orphaned files remain for orphan detection (apply removes)
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
 *     - Load or use cached metadata
 *
 *   Phase 2: Compute Diff (O(D))
 *     - Lookup old and new trees
 *     - Generate Git diff between them
 *
 *   Phase 3: Process Deltas (O(D))
 *     - For additions/modifications: sync (deployed_at preserved if exists, else 0 for new files)
 *     - For deletions: check for fallbacks, mark STATE_INACTIVE if none
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
 *   - state MUST have active transaction (via state_open)
 *   - old_oid and new_oid MUST be valid commits for profile's branch
 *   - profile MUST be in enabled_profiles
 *   - Branch HEAD for profile MUST point to new_oid (post-sync state)
 *
 * Postconditions:
 *   - Added/modified files synced (deployed_at preserved if exists, else 0 for new files)
 *   - Deleted files with fallbacks updated to new owner (deployed_at preserved)
 *   - Deleted files without fallbacks marked STATE_INACTIVE (staged for removal)
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
 *   Sync updates VWD expected state (blob_oid, metadata) but doesn't deploy to filesystem.
 *   User must run 'dotta apply' which uses runtime divergence analysis to deploy changes.
 *
 * @param repo Repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param profile Profile being synced (must not be NULL)
 * @param old_oid Old commit before sync (must not be NULL)
 * @param new_oid New commit after sync (must not be NULL)
 * @param enabled_profiles All enabled profiles for precedence (must not be NULL)
 * @param out_synced Output: number of files synced (can be NULL)
 * @param out_removed Output: number of files removed (can be NULL)
 * @param out_fallbacks Output: number of fallback resolutions (can be NULL)
 * @param out_skipped Output: number of custom/ files skipped due to missing prefix (can be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_sync_diff(
    git_repository *repo,
    state_t *state,
    const char *profile,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks,
    size_t *out_skipped
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
 *   - state MUST have active transaction (via state_open)
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

/**
 * Build manifest from profile names
 *
 * Merges files from all profiles according to precedence rules.
 * Later profiles override earlier ones. Loads each profile's Git tree
 * internally via gitops_load_branch_tree (one tree alive per iteration).
 *
 * Custom prefix resolution is handled internally: when state is non-NULL,
 * loads the prefix map from the state database to resolve custom/ files.
 * Profiles without a custom prefix deploy to home/root normally.
 * Custom/ files are skipped for profiles without a prefix entry.
 *
 * Memory: manifest entries borrow profile from the caller's profiles
 * array. The profiles array must outlive the returned manifest.
 *
 * @param repo Repository (must not be NULL)
 * @param profiles Profile names in precedence order (must not be NULL)
 * @param state State handle for custom prefix resolution (NULL = no custom prefixes)
 * @param arena Arena for string allocations (NULL = heap)
 * @param out Manifest (must not be NULL, caller must free with manifest_free)
 * @return Error or NULL on success
 */
error_t *manifest_build(
    git_repository *repo,
    const string_array_t *profiles,
    const state_t *state,
    arena_t *arena,
    manifest_t **out
);

/**
 * Build manifest from a single Git tree
 *
 * Creates a manifest from a specific Git tree, useful for historical diffs.
 * This is a simplified version of manifest_build() for a single tree.
 *
 * @param tree Git tree to build manifest from (must not be NULL)
 * @param profile Profile name for entries (must not be NULL)
 * @param custom_prefix Custom prefix for custom/ paths (NULL for graceful degradation)
 * @param out Manifest (must not be NULL, caller must free with manifest_free)
 * @return Error or NULL on success
 */
error_t *manifest_build_from_tree(
    git_tree *tree,
    const char *profile,
    const char *custom_prefix,
    manifest_t **out
);

/**
 * Free manifest
 *
 * @param manifest Manifest to free (can be NULL)
 */
void manifest_free(manifest_t *manifest);

#endif /* DOTTA_MANIFEST_H */
