/**
 * Manifest Module — consistency layer for the virtual_manifest table
 *
 * Single authority for every modification of the manifest table (the
 * Virtual Working Directory's persistent cache). Surface is two-fold:
 *
 *   - Consistency layer: manifest_apply_scope, manifest_reconcile,
 *     manifest_add_files, manifest_update_files, manifest_remove_files,
 *     manifest_sync_directories. Each operates within
 *     a caller-managed transaction and updates the virtual_manifest +
 *     tracked_directories tables to reflect the post-operation Git state.
 *     Every entry point ends its state writes with the directory rebuild
 *     (sweep + re-projection); the ones that demote file rows retire their
 *     own unwitnessed ghosts first. The demoter terminates its own
 *     demotions — there is no shared epilogue owning another's rows.
 *
 *   - Tree loader: manifest_load_tree_files projects a single Git
 *     tree's files into the public state_files_t carrier. Used by the
 *     historical-diff path (cmd_diff). Mirrors workspace_files and
 *     state_files_view — one carrier shape, three producers.
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
 * Per-profile statistics from a scope projection
 *
 * Fields are populated conditionally based on the profile's role in the
 * projection. The same profile can gain and lose files simultaneously
 * (e.g., enable A while B was reordered above it), so gain-side and
 * loss-side fields are independent.
 *
 *   Gain-side  — the profile claimed file(s) in the new manifest.
 *   Loss-side  — the profile lost file(s) that were in the old manifest.
 *
 * Counters reflect what was observed at projection time; they do NOT
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

    /* Gain-side, subsets of files_claimed (the remainder was unchanged) */
    size_t files_added;          /* No ACTIVE row before this call (new path, or a row reactivated) */
    size_t files_updated;        /* ACTIVE row whose expected blob, type or mode moved */

    /* Loss-side */
    size_t files_reassigned;     /* Files reassigned to a different profile */
    size_t files_orphaned;       /* Files that left scope entirely (→ the call's leftover lifecycle) */
    size_t files_reclaimed;      /* Ghost rows that left scope (retired; no cleanup pends) */
} manifest_scope_stats_t;

/**
 * Project the enabled-profile scope into virtual_manifest
 *
 * The one projection engine: manifest := project(enabled profiles × branch
 * HEADs, precedence resolved). Every scope transition and every drift
 * repair is this call. The enabled profile set is read from state (via
 * state_peek_profiles); the caller is responsible for making
 * enabled_profiles membership and order authoritative *before* calling
 * (see ordering rule below). Idempotent: applying the same scope twice is
 * a no-op (UPSERT preserves every column that a repeat call would rewrite
 * to the same value; the HEAD persist rewrites the same OID).
 *
 * `leftover` names the fate of an ACTIVE row whose path fell out of the
 * projection, and is chosen by the call site because the engine cannot
 * infer it from its inputs: a path leaves the projection when its
 * profile leaves the enabled set, when Git no longer has it, and when a
 * re-target moves a custom/ profile's paths — and only the caller knows
 * whether it changed the scope (membership, order, bindings) or merely
 * observed Git.
 *   LIFECYCLE_INACTIVE  — the user changed the scope here (profile
 *                         enable/disable/reorder, remove --delete-profile,
 *                         clone, interactive save). Staged for removal;
 *                         re-enable reverses it.
 *   LIFECYCLE_RELEASED  — the departure was discovered in Git (reconcile
 *                         after an external commit, a pulled removal, a
 *                         branch that no longer resolves). The deployed
 *                         copy is left alone and the row retires.
 * Any other value is ERR_INVALID_ARG.
 *
 * ORDERING RULE (all callers):
 *   1. Update enabled_profiles membership and order to the target scope:
 *        enable    → state_enable_profile for each new profile.
 *        disable   → state_disable_profile for each removed profile.
 *        reorder   → state_reorder_profiles(new_order) (rejects any
 *                    name not already enabled).
 *        clone     → state_enable_profile loop (clone is enable for an
 *                    initial set, not a separate primitive).
 *        interactive save → diff against the persisted set, then apply
 *                    additions/removals via the membership primitives
 *                    before state_reorder_profiles.
 *      Reconcile — and through it sync and revert — changes nothing: it
 *      calls this to project what Git did.
 *   2. Call manifest_apply_scope().
 *   3. No further state mutations required — the engine handles
 *      virtual_manifest, tracked_directories and
 *      enabled_profiles.commit_oid.
 *
 * Preconditions:
 *   - state MUST have an active write transaction.
 *   - enabled_profiles membership and order are the target scope.
 *     commit_oid is NOT a precondition — this function writes it.
 *   - mounts covers the enabled set.
 *   - stats_filter and out_stats are either both NULL or both non-NULL.
 *   - When stats_filter is non-NULL, out_stats points to an array of
 *     length stats_filter->count, and stats_filter's entries are
 *     pairwise unique (duplicates return ERR_INVALID_ARG — see below).
 *
 * Postconditions:
 *   - virtual_manifest's ACTIVE rows equal the precedence-resolved
 *     projection of every enabled profile whose branch resolves, at
 *     that branch's HEAD.
 *   - A row whose path re-entered the projection is ACTIVE whatever
 *     lifecycle it carried (the UPSERT writes state unconditionally).
 *   - An ACTIVE row whose path left the projection is `leftover`.
 *     LIFECYCLE_INACTIVE / LIFECYCLE_DELETED / LIFECYCLE_RELEASED rows
 *     that stay outside are preserved — their intent signal predates
 *     this call — and are not counted.
 *     Exception: out-of-scope rows never witnessed on disk
 *     (observed_at = 0) are reclaimed — deleted outright. A ghost row
 *     carries no filesystem obligation, so there is nothing to stage or
 *     clean. File rows are retired by this function's own reclaim,
 *     directory rows by the rebuild that follows it.
 *   - Git reference currency: for every enabled profile whose branch
 *     resolved, enabled_profiles.commit_oid equals the OID whose tree
 *     was projected — captured by the same git_reference_peel that
 *     produced the tree, so no second lookup and no race.
 *   - A profile whose branch does not resolve contributes no rows and
 *     its commit_oid is left untouched. Its ACTIVE rows take `leftover`
 *     like any other departure: under RELEASED that is the exact answer
 *     (Git cannot back them); under INACTIVE the workspace's authority
 *     probe reads them as released at load and cleanup releases. No
 *     special case — the scope layer already warns about the dead
 *     branch on every run.
 *   - The deployment anchor (deployed_blob_oid, deployed_at, stat_*) is
 *     preserved on every UPDATE — the engine is a pure VWD-cache writer,
 *     not a confirmation event. It advances the VWD cache's blob_oid to
 *     track Git while leaving the anchor pinned to dotta's last disk
 *     confirmation; the divergence between the two is how the workspace
 *     classifies staleness from persistent state. old_profile is
 *     auto-captured on a profile change; observed_at is monotonic.
 *   - tracked_directories swept and re-projected from enabled profiles.
 *   - Transaction remains open (caller commits via state_save).
 *
 * Stats attribution (when stats_filter is non-NULL):
 *   A profile in stats_filter ∩ new_enabled receives gain-side fields
 *   (files_claimed + lstat-derived files_present / files_missing /
 *   access_errors, and files_added / files_updated from the pre-
 *   projection snapshot) as the new-manifest projection processes its
 *   entries. A profile that owned rows no longer in scope receives
 *   loss-side fields during the leftover pass: files_reassigned, plus
 *   either files_orphaned (witnessed row — took `leftover`) or
 *   files_reclaimed (ghost row — retired at scope exit, no cleanup
 *   pends). Only rows this call demoted are counted. A profile can
 *   collect gain and loss simultaneously.
 *   Overlap semantics: if B overrides A for path X, B gets files_claimed
 *   for X and A gets files_reassigned for X. The sum is the true
 *   manifest size.
 *
 * Error Conditions:
 *   - ERR_INVALID_ARG: leftover is neither INACTIVE nor RELEASED,
 *                      stats_filter contains a duplicate profile name,
 *                      or stats_filter/out_stats violate the pairing rule
 *   - ERR_GIT: Git operation failed (tree walk, branch lookup or load)
 *   - ERR_CRYPTO: Encrypted file but key unavailable
 *   - ERR_STATE_INVALID: Database operation failed, including a failed
 *                        leftover write (the transaction must roll back;
 *                        a row left ACTIVE would be analysed against a
 *                        blob Git may no longer have)
 *   - ERR_MEMORY: Memory allocation failed
 *
 * Performance: O(P + M + S + D)
 *   P = enabled profiles (one ref lookup + one tree load each)
 *   M = files in the new view (one precedence-view build, one metadata
 *       load, one witness lstat and one UPSERT per row)
 *   S = rows in virtual_manifest (one state_get_all_files for the
 *       leftover pass; indexed when stats are requested)
 *   D = directories across enabled profiles (one directory rebuild)
 *   Low single-digit milliseconds for a few hundred rows.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle with active transaction (must not be NULL)
 * @param arena Scratch arena for the fresh precedence view and the
 *              leftover-pass state snapshot. Allocations live until the
 *              caller destroys the arena (typically command end). Must not
 *              be NULL.
 * @param mounts Per-machine mount table reflecting the post-mutation
 *               binding set the caller is projecting to. Must not be NULL.
 *               Binding-mutating callers (profile enable/disable/reorder,
 *               clone, interactive) build a fresh local table after the
 *               state mutation; ctx->mounts is stale at those sites.
 * @param leftover Fate of ACTIVE rows that left the projection:
 *                 LIFECYCLE_INACTIVE or LIFECYCLE_RELEASED (see above)
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
    state_lifecycle_t leftover,
    const string_array_t *stats_filter,
    manifest_scope_stats_t *out_stats
);

/**
 * Reconcile manifest with current Git state (drift check over the engine)
 *
 * The one entry point for "Git moved; bring the manifest along": detects
 * whether any enabled profile's stored commit_oid no longer matches its
 * branch HEAD and, if so, runs manifest_apply_scope with leftover =
 * LIFECYCLE_RELEASED. Three callers, one question each:
 *   - workspace_load, at load-start — something may have moved between
 *     dotta runs (an external commit, rebase, rm);
 *   - sync, after its Git phase — the pulls and resolutions it just made,
 *     plus any local drift that --force's skipped prelude left behind;
 *   - revert, after its commit — the one branch it moved.
 * The engine then projects everything, so an external addition is
 * projected, a removal (external or pulled) is released, and a path that
 * returned to Git is reactivated — whatever lifecycle its row carried.
 * The drift check is what keeps the call cheap when nothing moved:
 * a sync that pulled nothing and a load after a clean run cost O(P) ref
 * lookups and no write.
 *
 * Transaction management
 *   This function handles transactions internally by inspecting state_locked():
 *     - Caller already holds a transaction (apply's dotta_ext_write) →
 *       writes commit with the caller's transaction.
 *     - Caller doesn't hold one (workspace loading from status/diff/update,
 *       sync, revert) → opens a scoped BEGIN IMMEDIATE, commits on
 *       success, rolls back on failure — including a failed COMMIT, which
 *       SQLite leaves open until it is rolled back.
 *
 * Callers never need to pre-open a transaction for this function, and sync
 * and revert hold none: the projection is the only state write either
 * makes, so the write lock is held for the projection alone, never across
 * network IO or a Git commit.
 *
 * Profile scope
 *   Current enabled profiles are fetched internally. Callers that have already
 *   fetched the list for their own reasons need not pass it; the primitive
 *   reads under whatever transaction is active. Empty enabled set is a valid
 *   no-op (reconcile early-returns).
 *
 * Preconditions:
 *   - state MUST be opened (read or write; transaction optional)
 *   - stats_filter and out_stats are either both NULL or both non-NULL
 *     (manifest_apply_scope's pairing rule; when non-NULL, out_stats is an
 *     array of length stats_filter->count with pairwise-unique names)
 *
 * Postconditions:
 *   - If any enabled branch had moved: the manifest is the projection of
 *     every enabled profile at HEAD (manifest_apply_scope's
 *     postconditions); rows that left are LIFECYCLE_RELEASED; every
 *     resolving profile's commit_oid is current. Rows of disabled
 *     profiles are not projected — the workspace observes their Git
 *     authority itself at load
 *   - The deployment anchor is left untouched — reconcile is a VWD-cache
 *     writer, not an anchor writer. Workspace divergence analysis reads
 *     anchor.blob_oid from persistent state to classify staleness; cross-
 *     process correct by construction
 *   - out_stats, when requested, is zero-filled with each profile name set
 *     whether or not a projection ran, and carries the engine's
 *     attribution when one did. A caller therefore reads the counts
 *     without asking whether drift was found: all-zero means "nothing for
 *     apply to do came out of this call". On error the counts describe
 *     writes the rollback undid — do not read them
 *   - Caller's transaction state is unchanged (kept outer lock, or
 *     committed/rolled back our scoped one)
 *
 * Performance:
 *   Common case (no drift): O(P) state queries + O(P) ref lookups, zero
 *   writes. A branch that does not resolve is not drift (see
 *   manifest_detect_drift in manifest.c)
 *   Drift case: one manifest_apply_scope
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (must not be NULL)
 * @param arena Scratch arena for the projection. Allocations live until
 *              the caller destroys the arena (typically command end).
 *              Must not be NULL.
 * @param mounts Per-machine mount table covering the current enabled set.
 *               Must not be NULL. Reconcile does not mutate bindings; every
 *               caller passes ctx->mounts.
 * @param stats_filter Optional: profiles to attribute stats to (NULL = none).
 *                     Sync passes scope_enabled; the prelude and revert
 *                     pass NULL (their repair reports itself through
 *                     status's [stale] / [released] rows).
 * @param out_stats Parallel array (length stats_filter->count); zero-filled
 *                  on entry and populated when a projection runs (must be
 *                  non-NULL iff stats_filter is non-NULL)
 * @return Error or NULL on success
 */
error_t *manifest_reconcile(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const string_array_t *stats_filter,
    manifest_scope_stats_t *out_stats
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
 *   - Files without fallback marked LIFECYCLE_DELETED (controlled deletion),
 *     except rows never witnessed on disk (observed_at = 0): those are
 *     reclaimed outright — a ghost has nothing for apply to remove
 *   - Files not owned by removed_profile unchanged
 *   - Tracked directories rebuilt from all enabled profiles
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
 *   - Rows left LIFECYCLE_DELETED that were never witnessed on disk
 *     (observed_at = 0) are reclaimed outright — dotta does not stage the
 *     removal of a path it never confirmed deploying
 *   - Tracked directories rebuilt from all enabled profiles
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
 *   - Tracked directories rebuilt from all enabled profiles (no file
 *     reclaim: add never demotes a row)
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
 * Rebuild tracked directories from enabled profiles
 *
 * The directory-side counterpart to file projection: sweeps
 * tracked_directories, re-projects it from every enabled profile's
 * metadata, and retires the rows the sweep left behind. Self-contained —
 * one transaction-scoped operation establishing one postcondition.
 *
 * Every consistency-layer entry point ends its state writes with this
 * call. File rows are outside its scope: each entry point demotes its own
 * and reclaims its own (state_reclaim_unmaterialized_files), so this call
 * alone rebuilds directories and touches nothing in virtual_manifest.
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - enabled_profiles MUST be the engine's iteration set (caller built
 *     `mounts` from the same list)
 *
 * Postconditions:
 *   - tracked_directories reflects enabled_profiles: rows still in scope
 *     are LIFECYCLE_ACTIVE with their witness preserved; witnessed rows
 *     that left scope are LIFECYCLE_INACTIVE (staged for apply-time
 *     cleanup); unwitnessed rows that left scope are deleted outright
 *   - A profile without metadata.json contributes no directories and is
 *     skipped, not an error
 *   - Transaction remains open (caller commits)
 *
 * Performance: O(D) where D = total directories across enabled profiles
 *              (typically < 50 even for large configs)
 *
 * @param repo Git repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param arena Arena for the per-row state_directory_entry_t allocations.
 *              Entries live until the caller destroys the arena (typically
 *              command end). Must not be NULL.
 * @param enabled_profiles Current enabled profiles (must not be NULL)
 * @param mounts Per-machine mount table covering enabled_profiles
 *               (must not be NULL)
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
 * .dottaignore, .bootstrap, .git/, .dotta/). Mirrors workspace_files and
 * state_files_view: one carrier shape, three producers.
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
