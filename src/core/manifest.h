/**
 * Manifest Module
 *
 * Owns the Virtual Working Directory (VWD) types and all manifest operations:
 *   - Type definitions: file_entry_t, manifest_t
 *   - Construction: manifest_build(), manifest_build_from_tree(), manifest_free()
 *   - Consistency layer: manifest_apply_scope(), manifest_sync_diff(), etc.
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
 * Per-profile statistics from a scope transition
 *
 * Fields are populated conditionally based on the profile's role in the
 * transition. The same profile can gain and lose files simultaneously
 * (e.g., enable A while B was reordered above it), so gain-side and
 * loss-side fields are independent.
 *
 *   Gain-side  — the profile claimed file(s) in the new manifest.
 *   Loss-side  — the profile lost file(s) that were in the old manifest.
 *
 * Counters reflect what was observed at reconcile time; they do NOT
 * verify disk matches the profile blob. Verification is workspace
 * divergence analysis (status/diff/apply).
 */
typedef struct {
    const char *profile;         /* Profile name (borrowed from stats_filter) */

    /* Gain-side */
    size_t files_claimed;        /* Files this profile wins precedence for */
    size_t files_present;        /* lstat observed a file at the deploy path */
    size_t files_missing;        /* lstat returned ENOENT (includes access errors) */
    size_t access_errors;        /* lstat failed non-ENOENT (subset of files_missing) */

    /* Loss-side */
    size_t files_reassigned;     /* Files reassigned to a different profile */
    size_t files_orphaned;       /* Files that left scope entirely (→ STATE_INACTIVE) */
} manifest_scope_stats_t;

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
 * Reconcile virtual_manifest to the current enabled-profile scope
 *
 * Single authoritative primitive for every scope transition. The enabled
 * profile set is read from state (via state_peek_profiles); the caller
 * is responsible for making enabled_profiles authoritative *before*
 * calling this function (see ordering rule below). Idempotent: applying
 * the same scope twice is a no-op (UPSERT preserves every column that
 * a repeat call would rewrite to the same value).
 *
 * ORDERING RULE (all callers):
 *   1. Update enabled_profiles to reflect the target scope:
 *        enable    → state_enable_profile for each new profile,
 *                    then manifest_persist_profile_head for each to
 *                    fill the commit_oid column.
 *        disable   → state_disable_profile for each removed profile.
 *        reorder   → state_set_profiles(new_order) (preserves commit_oids).
 *        clone     → state_set_profiles(initial_set),
 *                    then manifest_persist_profile_head for each.
 *   2. Call manifest_apply_scope().
 *   3. No further state mutations required — apply_scope handles the
 *      virtual_manifest table and tracked_directories.
 *
 * Preconditions:
 *   - state MUST have an active write transaction.
 *   - enabled_profiles is fully authoritative for the target scope:
 *       name, position (precedence), custom_prefix, commit_oid.
 *   - Git branches are at the commits referenced by
 *     enabled_profiles.commit_oid.
 *   - stats_filter and out_stats are either both NULL or both non-NULL.
 *   - When stats_filter is non-NULL, out_stats points to an array of
 *     length stats_filter->count, and stats_filter's entries are
 *     pairwise unique (duplicates return ERR_INVALID_ARG — see below).
 *
 * Postconditions:
 *   - virtual_manifest reflects (enabled_profiles × Git trees) with
 *     correct precedence.
 *   - Rows whose filesystem_path left scope:
 *       STATE_ACTIVE  → STATE_INACTIVE (staged for removal by apply).
 *       STATE_INACTIVE / STATE_DELETED / STATE_RELEASED: preserved
 *       (downgrading them would break downstream intent signals).
 *   - tracked_directories rebuilt via manifest_sync_directories.
 *   - The deployment anchor (deployed_blob_oid, deployed_at, stat_*) is
 *     preserved on every UPDATE — apply_scope is a pure VWD-cache
 *     writer, not a confirmation event.
 *   - Transaction remains open (caller commits via state_save).
 *
 * Stats attribution (when stats_filter is non-NULL):
 *   A profile in stats_filter ∩ new_enabled receives gain-side fields
 *   (files_claimed + lstat-derived files_present / files_missing /
 *   access_errors) as the new-manifest sync processes its entries.
 *   A profile that owned rows no longer in scope receives loss-side
 *   fields (files_reassigned / files_orphaned) during the orphan pass.
 *   A profile can collect both simultaneously. Overlap semantics: if B
 *   overrides A for path X, B gets files_claimed for X and A gets
 *   files_reassigned for X. The sum is the true manifest size.
 *
 * Error Conditions:
 *   - ERR_INVALID_ARG: stats_filter contains a duplicate profile name,
 *                      or stats_filter/out_stats violate the pairing rule
 *   - ERR_GIT: Git operation failed (tree walk, branch resolution)
 *   - ERR_CRYPTO: Encrypted file but key unavailable
 *   - ERR_STATE_INVALID: Database operation failed
 *   - ERR_MEMORY: Memory allocation failed
 *
 * Performance: O(M + S + D)
 *   M = files in the new manifest (one manifest_build, one metadata load)
 *   S = rows in virtual_manifest (one state_get_all_files for orphan pass)
 *   D = directories across enabled profiles (one sync_directories rebuild)
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle with active transaction (must not be NULL)
 * @param stats_filter Optional: profiles to attribute stats to (NULL = none)
 * @param out_stats Parallel array (length stats_filter->count); zero-initialized
 *                  and populated during the call (must be non-NULL iff
 *                  stats_filter is non-NULL)
 * @return Error or NULL on success
 */
error_t *manifest_apply_scope(
    git_repository *repo,
    state_t *state,
    const string_array_t *stats_filter,
    manifest_scope_stats_t *out_stats
);

/**
 * Record a profile's current branch HEAD in enabled_profiles.commit_oid.
 *
 * Composes gitops_resolve_branch_head_oid + state_set_profile_commit_oid.
 * Callers pair this with the state mutation that introduces the profile
 * (state_enable_profile or state_set_profiles), which writes a zero-OID
 * sentinel; this call replaces the sentinel with the real HEAD so
 * enabled_profiles is fully authoritative before manifest_apply_scope.
 *
 * Preconditions:
 *   - state has an active write transaction.
 *   - profile is currently in enabled_profiles (just written by
 *     state_enable_profile or state_set_profiles).
 *   - The profile's Git branch exists and resolves to a commit.
 *
 * Postconditions:
 *   - enabled_profiles.commit_oid for profile equals the branch HEAD.
 *   - Transaction remains open.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle with active transaction (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_persist_profile_head(
    git_repository *repo,
    state_t *state,
    const char *profile
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
 *        → No fallback: decide the terminal row state from disk
 *          reality. The common path — file absent on disk
 *          (WORKSPACE_STATE_DELETED precondition held through the
 *          transaction) — purges the row so apply has no spurious
 *          orphan to clean up. If a racing recreation placed the path
 *          back on disk, the row is marked STATE_DELETED instead so
 *          apply's divergence routing can protect the user's edits.
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
 *   - Deleted files: fallback reassigns the row to the fallback profile
 *     (deployed_at preserved); no-fallback purges the row if the path
 *     is absent on disk, or marks it STATE_DELETED if a race has placed
 *     it back. Anchor left untouched (no disk confirmation for deleted
 *     / fallback paths).
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
 * @param out_removed Output: count of no-fallback deletions purged from state (must not be NULL)
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
 * @param out_removed Output: files without fallback (marked STATE_DELETED) (can be NULL)
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
 *     - For deletions: check for fallbacks. No-fallback terminates on
 *       disk reality: purge if the path is absent, else mark STATE_DELETED.
 *     - Handle precedence: only sync if profile won the file
 *
 * Deletion & Fallback Logic:
 *   When a file is deleted from profile-A:
 *     1. Check new precedence manifest (built from post-sync state)
 *     2. If another profile (profile-B) now wins: update to profile-B (fallback)
 *     3. If no other profile has it: check current state
 *     4. If profile-A owns it in state: the terminal row state comes
 *        from disk reality — purge when the path is absent (apply has
 *        no filesystem work), STATE_DELETED when it is still present
 *        (apply removes it via safety PHASE 1 bypass, sidestepping the
 *        RELEASED pathway).
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
 *   - Deleted files without fallbacks terminate on disk reality: the row
 *     is purged if the path is absent on disk, or marked STATE_DELETED
 *     if still present (apply removes it via safety PHASE 1 bypass)
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
