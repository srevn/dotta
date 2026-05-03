/**
 * Manifest Module — consistency layer for the virtual_manifest table
 *
 * Single authority for every modification of the manifest table (the
 * Virtual Working Directory's persistent cache). Surface is two-fold:
 *
 *   - Consistency layer: manifest_apply_scope, manifest_sync_diff,
 *     manifest_add_files, manifest_update_files, manifest_remove_files,
 *     manifest_reconcile, manifest_sync_directories. Each operates within
 *     a caller-managed transaction and updates the virtual_manifest +
 *     tracked_directories tables to reflect the post-operation Git
 *     state.
 *
 *   - Tree loader: manifest_load_tree_files projects a single Git
 *     tree's files into the public state_files_t carrier. Used by the
 *     historical-diff path (cmd_diff). Mirrors workspace_active and
 *     deploy_result_view — one carrier shape, three producers.
 *
 * The precedence builder that powers every consistency-layer entry is
 * private to manifest.c (see precedence_view_t). It produces
 * state_file_entry_t rows directly, removing the type bridge that used
 * to live between the build step and the persistence step.
 *
 * Core Principles:
 *   - Single Authority: Only this module modifies the manifest table
 *   - Eager Consistency: Manifest updated immediately when inputs change
 *   - Transaction Safety: All operations are atomic (rollback on error)
 *   - Convergence Model: VWD defines scope and expected state; workspace
 *     analyzes runtime divergence
 *
 * Workflow:
 *   Commands → manifest layer → state API → SQLite
 */

#ifndef DOTTA_MANIFEST_H
#define DOTTA_MANIFEST_H

#include <git2.h>
#include <types.h>

#include "core/metadata.h"
#include "core/state.h"
#include "core/workspace.h"
#include "infra/mount.h"

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
    size_t files_orphaned;       /* Files that left scope entirely (→ LIFECYCLE_INACTIVE) */
} manifest_scope_stats_t;

/**
 * Statistics from stale-entry drift repair
 *
 * Counts row outcomes when the persistent state entries are reconciled
 * against Git after external moves (the SQL virtual_manifest table; not
 * the in-memory precedence view).
 */
typedef struct {
    size_t updated;     /* Files with changed blob_oid (content changed in Git) */
    size_t refreshed;   /* Files with only HEAD refresh (content unchanged) */
    size_t released;    /* Files set to LIFECYCLE_RELEASED (removed from Git externally) */
    size_t reassigned;  /* Files whose owning profile shifted during repair */
} manifest_repair_stats_t;

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
 *       name, position (precedence), target, commit_oid.
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
 *       LIFECYCLE_ACTIVE  → LIFECYCLE_INACTIVE (staged for removal by apply).
 *       LIFECYCLE_INACTIVE / LIFECYCLE_DELETED / LIFECYCLE_RELEASED: preserved
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
 *   M = files in the new view (one precedence-view build, one metadata load)
 *   S = rows in virtual_manifest (one state_get_all_files for orphan pass)
 *   D = directories across enabled profiles (one sync_directories rebuild)
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle with active transaction (must not be NULL)
 * @param arena Scratch arena for the fresh precedence view and the
 *              orphan-pass state snapshot. Allocations live until the
 *              caller destroys the arena (typically command end). Must not
 *              be NULL.
 * @param mounts Per-machine mount table reflecting the post-mutation
 *               binding set the caller is reconciling to. Must not be NULL.
 *               Binding-mutating callers (profile enable/disable/reorder,
 *               clone, interactive) build a fresh local table after the
 *               state mutation; ctx->mounts is stale at those sites.
 * @param stats_filter Optional: profiles to attribute stats to (NULL = none)
 * @param out_stats Parallel array (length stats_filter->count); zero-initialized
 *                  and populated during the call (must be non-NULL iff
 *                  stats_filter is non-NULL)
 * @return Error or NULL on success
 */
error_t *manifest_apply_scope(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const string_array_t *stats_filter,
    manifest_scope_stats_t *out_stats
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
 *   This function handles transactions internally by inspecting state_locked():
 *     - Caller already holds a transaction (apply's dotta_ext_write, sync's
 *       state_begin) → writes commit with the caller's transaction.
 *     - Caller doesn't hold one (workspace loading from status/diff/update) →
 *       opens a scoped BEGIN IMMEDIATE, commits on success, rolls back on
 *       failure.
 *
 * Callers never need to pre-open a transaction for this function.
 *
 * Profile scope
 *   Current enabled profiles are fetched internally. Callers that have already
 *   fetched the list for their own reasons need not pass it; the primitive
 *   reads under whatever transaction is active. Empty enabled set is a valid
 *   no-op (reconcile early-returns).
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
 *   Stale case: O(M) fresh precedence-view build, M = total files in Git
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (must not be NULL)
 * @param arena Scratch arena for stale-profile detection and fresh
 *              precedence-view construction during repair. Allocations live
 *              until the caller destroys the arena (typically command end).
 *              Must not be NULL.
 * @param mounts Per-machine mount table covering the current enabled set.
 *               Must not be NULL. Reconcile does not mutate bindings; the
 *               only callers (workspace_load and sync's force branch)
 *               pass ctx->mounts.
 * @param out_stats Optional: repair statistics (NULL = don't care)
 * @return Error or NULL on success
 */
error_t *manifest_reconcile(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    manifest_repair_stats_t *out_stats
);

/**
 * Remove files from manifest (remove command)
 *
 * Called after remove command deletes files from a profile branch.
 * Handles fallback to lower-precedence profiles or marks for removal.
 *
 * Algorithm:
 *   1. Build fresh precedence view from enabled profiles
 *   2. Sync commit_oid in enabled_profiles after entry sync
 *   3. For each removed file:
 *      a. Resolve to filesystem path
 *      b. Lookup current state entry
 *      c. Check if removed profile owns it (precedence check)
 *      d. If yes:
 *         - Check fresh precedence view for fallback
 *         - Fallback exists: Update to fallback profile (deployed_at preserved)
 *         - No fallback: Mark as LIFECYCLE_DELETED (controlled deletion)
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
 *   - Files without fallback marked LIFECYCLE_DELETED (controlled deletion)
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
 * @param arena Scratch arena for the fresh precedence view (used for
 *              fallback detection). Allocations live until the caller
 *              destroys the arena (typically command end). Must not be NULL.
 * @param mounts Per-machine mount table covering enabled_profiles. Must not
 *               be NULL. Remove does not mutate the binding set before
 *               this call, so callers pass ctx->mounts directly.
 * @param removed_profile Profile files were removed from (must not be NULL)
 * @param removed_storage_paths Storage paths of removed files (must not be NULL)
 * @param enabled_profiles All enabled profiles (must not be NULL)
 * @param out_marked Output: filesystem paths just marked LIFECYCLE_DELETED (can be NULL)
 * @param out_removed Output: files without fallback (marked LIFECYCLE_DELETED) (can be NULL)
 * @param out_fallbacks Output: files updated to fallback (can be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_remove_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const char *removed_profile,
    const string_array_t *removed_storage_paths,
    const string_array_t *enabled_profiles,
    string_array_t *out_marked,
    size_t *out_removed,
    size_t *out_fallbacks
);

/**
 * Update files in manifest (update command)
 *
 * High-performance batch operation that builds a fresh precedence view
 * from Git (post-commit state) instead of using the stale workspace cache.
 * Designed for the update command's workflow where many files are synced
 * at once after Git commits.
 *
 * CRITICAL DESIGN DECISION: This function builds a fresh precedence view
 * from Git because the workspace's cached row snapshot is stale after
 * commits. Using the stale cache would cause fallback to expensive
 * single-file operations for newly added files, resulting in O(N×M)
 * complexity instead of O(M+N).
 *
 * Algorithm:
 *   1. Load enabled profiles from Git
 *   2. Build FRESH precedence view (O(M))
 *   3. Use the view's index for O(1) lookups
 *   4. Sync commit_oid in enabled_profiles after entry sync
 *   5. For each item (O(N)):
 *      - If DELETED: check fresh view for fallback
 *        → Fallback exists: update to fallback profile (deployed_at preserved)
 *        → No fallback: decide the terminal row state from disk
 *          reality. The common path — file absent on disk
 *          (WORKSPACE_STATE_DELETED precondition held through the
 *          transaction) — purges the row so apply has no spurious
 *          orphan to clean up. If a racing recreation placed the path
 *          back on disk, the row is marked LIFECYCLE_DELETED instead so
 *          apply's divergence routing can protect the user's edits.
 *      - Else (modified/new): lookup in fresh precedence view
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
 *     is absent on disk, or marks it LIFECYCLE_DELETED if a race has placed
 *     it back. Anchor left untouched (no disk confirmation for deleted
 *     / fallback paths).
 *   - Tracked directories synced from all enabled profiles
 *   - Transaction remains open (caller commits)
 *
 * Performance: O(M + N) where M = total files in profiles, N = items to sync
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param arena Scratch arena for the fresh precedence view. Allocations
 *              live until the caller destroys the arena (typically
 *              command end). Must not be NULL.
 * @param mounts Per-machine mount table covering enabled_profiles. Must not
 *               be NULL. Update doesn't mutate bindings, so callers pass
 *               ctx->mounts directly.
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
    arena_t *arena,
    const mount_table_t *mounts,
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
 * precedence view from Git (post-commit state). This ensures all newly-added
 * files are found during precedence checks, maintaining O(M+N) performance.
 *
 * Algorithm:
 *   1. Load enabled profiles from Git (current HEAD, post-commit)
 *   2. Build fresh precedence view (ONCE)
 *   3. Use the view's index for O(1) precedence lookups
 *   4. Sync commit_oid in enabled_profiles after entry sync
 *   5. For each file:
 *      - Convert filesystem_path → storage_path
 *      - Lookup in fresh view
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
 *   - Single fresh precedence-view build from Git
 *   - Batch-optimized state operations
 *
 * Error Handling:
 *   - Transactional: on error, entire batch fails
 *   - Returns error on first failure (fail-fast)
 *   - Path resolution errors are fatal
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param arena Scratch arena for the fresh precedence view. Allocations
 *              live until the caller destroys the arena (typically
 *              command end). Must not be NULL.
 * @param mounts Per-machine mount table reflecting the post-add binding
 *               set. Must not be NULL. Add may implicitly enable a profile
 *               (or store its --target) before this call, so callers build
 *               a fresh local table after that mutation; ctx->mounts is
 *               stale on the implicit-enable path.
 * @param profile Profile files were added to (must not be NULL)
 * @param filesystem_paths Array of filesystem paths (must not be NULL)
 * @param enabled_profiles All enabled profiles (must not be NULL)
 * @param out_synced Output: count of files synced (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_add_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const char *profile,
    const string_array_t *filesystem_paths,
    const string_array_t *enabled_profiles,
    size_t *out_synced
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
 *     - Build fresh precedence view from current Git state (post-sync)
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
 *       disk reality: purge if the path is absent, else mark LIFECYCLE_DELETED.
 *     - Handle precedence: only sync if profile won the file
 *
 * Deletion & Fallback Logic:
 *   When a file is deleted from profile-A:
 *     1. Check new precedence manifest (built from post-sync state)
 *     2. If another profile (profile-B) now wins: update to profile-B (fallback)
 *     3. If no other profile has it: check current state
 *     4. If profile-A owns it in state: the terminal row state comes
 *        from disk reality — purge when the path is absent (apply has
 *        no filesystem work), LIFECYCLE_DELETED when it is still present
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
 *     is purged if the path is absent on disk, or marked LIFECYCLE_DELETED
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
 * @param arena Scratch arena for the fresh precedence view. Allocations
 *              live until the caller destroys the arena (typically command end)
 * @param mounts Per-machine mount table covering enabled_profiles. Must not
 *               be NULL. Sync does not mutate bindings; callers pass ctx->mounts.
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
    arena_t *arena,
    const mount_table_t *mounts,
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
 * Rebuilds the tracked_directories table from metadata.
 * Called after profile enable/disable/reorder to maintain directory tracking.
 *
 * Algorithm:
 *   1. Clear all tracked directories (idempotent start)
 *   2. For each enabled profile:
 *      a. Load metadata from Git (or skip if doesn't exist)
 *      b. Extract directories via metadata_get_items_by_kind()
 *      c. Add to state via state_add_directory() with profile attribution
 *   3. All within caller's active transaction
 *
 * Pattern: Rebuild (not incremental)
 *   - Directories have no lifecycle states to preserve
 *   - Clear + repopulate is simple, correct, and fast
 *   - Already idempotent via INSERT OR REPLACE
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - enabled_profiles MUST be the engine's iteration set (caller built
 *     `mounts` from the same list)
 *
 * Postconditions:
 *   - tracked_directories table reflects enabled_profiles
 *   - Transaction remains open (caller commits)
 *   - Missing metadata handled gracefully (not an error)
 *
 * Performance: O(D) where D = total directories across enabled profiles
 *              (typically < 50 even for large configs)
 *
 * @param repo Git repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param enabled_profiles Current enabled profiles (must not be NULL)
 * @param mounts Per-machine mount table covering enabled_profiles
 *              (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_sync_directories(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const string_array_t *enabled_profiles,
    const mount_table_t *mounts
);

/**
 * Project a single Git tree's files into the public state_files_t carrier
 *
 * Used by the historical-diff path (cmd_diff): given a tree, profile,
 * mount table, and optional per-tree metadata, produces a state_file_entry_t
 * row for every blob the tree exposes (sans repository metadata files —
 * .dottaignore, .bootstrap, .git/, .dotta/). Mirrors workspace_active and
 * deploy_result_view: one carrier shape, three producers.
 *
 * Metadata, when supplied, is applied row-by-row in lockstep with the
 * tree walk — mode, owner, group, and encrypted are filled from the
 * tree's own metadata.json. Pass NULL to skip metadata application
 * (rows keep Git-derived defaults). Callers that have already loaded
 * the tree's metadata for their own purposes should pass it here.
 *
 * Custom-prefix resolution is delegated to `mounts`. The handle MUST
 * record a binding for `profile` (with target set) when the tree
 * contains custom/ entries; otherwise those entries are skipped silently
 * during the walk. Trees without custom/ entries can pass any mount
 * table, including one with no binding for `profile`.
 *
 * Memory: every allocation produced by the call (rows, per-row strings,
 * pointer array, internal view struct) lives in the caller's arena.
 * arena_destroy reclaims them at command end. No targeted free required.
 *
 * @param tree Git tree to project (must not be NULL)
 * @param profile Profile name carried on each row (must not be NULL)
 * @param mounts Per-machine mount table (must not be NULL)
 * @param metadata Optional per-tree metadata applied to rows (can be NULL)
 * @param arena Arena backing every allocation produced by the call
 *              (must not be NULL)
 * @param out State files slice (must not be NULL; entries borrowed from
 *            `arena`, lifetime tied to it)
 * @return Error or NULL on success
 */
error_t *manifest_load_tree_files(
    git_tree *tree,
    const char *profile,
    const mount_table_t *mounts,
    const metadata_t *metadata,
    arena_t *arena,
    state_files_t *out
);

#endif /* DOTTA_MANIFEST_H */
