/**
 * Manifest Module — consistency layer for the virtual_manifest table
 *
 * Single authority for every modification of the manifest table (the
 * Virtual Working Directory's persistent cache). Surface is two-fold:
 *
 *   - Consistency layer: manifest_apply_scope, manifest_reconcile,
 *     manifest_add_files, manifest_update_files, manifest_remove_files.
 *     Each operates within a caller-managed transaction and leaves
 *     virtual_manifest + tracked_directories reflecting the post-
 *     operation Git state. One projection engine — manifest_apply_scope
 *     — is the sole writer of the ACTIVE set and of
 *     enabled_profiles.commit_oid: it projects, demotes what left,
 *     reclaims its ghosts and rebuilds directories. manifest_reconcile
 *     gates it on drift; the three verbs run it and then overlay, on the
 *     rows they named, the one thing only the verb knows — an anchor
 *     captured from disk, or the fate the user chose for a deployed copy.
 *
 *   - Tree loader: manifest_load_tree_files projects a single Git
 *     tree's files into the public manifest_rows_t carrier. Used by the
 *     historical-diff path (cmd_diff). Mirrors workspace_files and
 *     manifest_rows_view — one carrier shape, three producers.
 *
 * The precedence builder that powers every consistency-layer entry is
 * private to manifest.c (see precedence_view_t). It produces
 * manifest_row_t rows directly (core/row.h), the one row shape every
 * consumer reads, so there is no bridge between the build step and the
 * persistence step. The engine writes the expected side only; the record
 * (anchors, core/state.h) is written by the verbs that touch disk, after
 * the engine ran, on the rows they won.
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
 *   - A settled row — ACTIVE, every VWD-cache column already at the
 *     view's value — is not written: the UPSERT would rewrite identical
 *     values and preserve everything else, so the writes of a
 *     projection are the rows that moved, not the view. The
 *     postconditions below hold either way.
 *   - An ACTIVE row whose path left the projection is `leftover`.
 *     LIFECYCLE_INACTIVE / LIFECYCLE_DELETED / LIFECYCLE_RELEASED rows
 *     that stay outside are preserved — their intent signal predates
 *     this call — and are not counted.
 *     Exception: out-of-scope rows never observed on disk (no record in
 *     anchors) are reclaimed — deleted outright. A ghost row carries no
 *     filesystem obligation, so there is nothing to stage or clean. File
 *     rows are retired by this function's own reclaim, directory rows by
 *     the rebuild that follows it.
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
 *   - The record (anchors) is untouched — the engine is a pure VWD-cache
 *     writer, not a confirmation event, and never names that table. It
 *     advances the VWD cache's blob_oid to track Git while the record
 *     stays pinned to dotta's last disk confirmation; the divergence
 *     between the two is how the workspace classifies staleness from
 *     persistent state. old_profile is auto-captured on a profile change.
 *   - tracked_directories swept and re-projected from enabled profiles.
 *   - Transaction remains open (caller commits via state_save).
 *
 * Stats attribution (when stats_filter is non-NULL):
 *   A profile in stats_filter ∩ new_enabled receives gain-side fields
 *   (files_claimed, and files_added / files_updated from the pre-
 *   projection snapshot) as the new-manifest projection processes its
 *   entries. A profile that owned rows no longer in scope receives
 *   loss-side fields during the leftover pass: files_reassigned, plus
 *   either files_orphaned (a record exists — the row took `leftover`)
 *   or files_reclaimed (no record — retired at scope exit, no cleanup
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
 * Performance: O(P + M + S + R + D)
 *   P = enabled profiles (one ref lookup + one tree load each)
 *   M = files in the new view (one precedence-view build, one metadata
 *       load, one snapshot lookup per row; one UPSERT per row that moved)
 *   S = rows in virtual_manifest (one state_get_all_files, indexed by
 *       filesystem_path, for the settled test and the leftover pass)
 *   R = rows in anchors (one state_get_all_anchors, indexed by
 *       filesystem_path, for the leftover pass's attribution)
 *   D = directories across enabled profiles (one directory rebuild)
 *   Low single-digit milliseconds for a few hundred rows; a projection
 *   that finds one row moved writes one row.
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
 * Called after the remove command committed the paths' removal from
 * removed_profile's branch. Runs the projection engine
 * (manifest_apply_scope, leftover = LIFECYCLE_RELEASED), then overlays
 * the verb's intent on the rows it named: a path another enabled
 * profile still provides was reassigned by the engine (counted as a
 * fallback); a path nothing provides was released by the engine and is
 * now given the fate the user chose — LIFECYCLE_DELETED when
 * delete_files (apply prunes a clean copy), otherwise the row is purged
 * and the deployed copy is left where it is.
 *
 * Preconditions:
 *   - state MUST have an active write transaction
 *   - the Git commit MUST be complete (paths removed from the branch)
 *   - removed_storage_paths are storage paths (home/.bashrc)
 *   - removed_profile is enabled (the caller checked)
 *
 * Postconditions:
 *   - manifest_apply_scope's postconditions (every enabled profile
 *     projected at HEAD, commit_oid current, directories rebuilt)
 *   - removed_profile's departed paths are LIFECYCLE_DELETED
 *     (delete_files) or absent from virtual_manifest and anchors
 *     (!delete_files — a release keeps no record); a path never observed
 *     on disk was reclaimed by the engine either way — a ghost has
 *     nothing for apply to remove
 *   - Paths another profile owns: reassigned rows keep their record;
 *     rows a higher profile owned all along are unchanged
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT / ERR_STATE_INVALID / ERR_MEMORY from the engine
 *   - ERR_STATE_INVALID: a row lookup or fate write failed (the caller
 *     rolls back; the next reconcile projects again, but the fate
 *     overlay is not replayed — the path then reads as released)
 *
 * Performance: one projection + O(N) point lookups, N = paths removed
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param arena Scratch arena for the projection. Allocations live until
 *              the caller destroys the arena (typically command end).
 *              Must not be NULL.
 * @param mounts Per-machine mount table covering the enabled set. Must
 *               not be NULL. Remove does not mutate the binding set
 *               before this call, so callers pass ctx->mounts directly.
 * @param removed_profile Profile files were removed from (must not be NULL)
 * @param removed_storage_paths Storage paths of removed files (must not be NULL)
 * @param delete_files The verb's choice for a deployed copy nothing
 *                     backs any more: true → LIFECYCLE_DELETED (apply
 *                     prunes), false → released now (row purged)
 * @param out_removed Output: paths given that fate (can be NULL)
 * @param out_fallbacks Output: paths reassigned to another profile (can be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_remove_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const char *removed_profile,
    const string_array_t *removed_storage_paths,
    bool delete_files,
    size_t *out_removed,
    size_t *out_fallbacks
);

/**
 * Update files in manifest (update command)
 *
 * Called after the update command committed every profile's changes.
 * Runs the projection engine (manifest_apply_scope, leftover =
 * LIFECYCLE_RELEASED), then overlays the verb's intent on the items it
 * committed:
 *   - a modified or new file was captured FROM disk, so its record is
 *     anchored to the just-committed blob with a fresh stat — only when
 *     this profile won the row (a shadowed path leaves the winner's
 *     record alone);
 *   - a deleted file (WORKSPACE_STATE_DELETED) left Git by this commit:
 *     a row the engine reassigned to a lower profile is a fallback for
 *     apply to deploy; a row the engine released is purged, record and
 *     all — nothing backs it and nothing is on disk. No lstat is taken:
 *     a file recreated between workspace load and this call is left on
 *     disk unmanaged, the release outcome, never a prune.
 *
 * Preconditions:
 *   - state MUST have an active write transaction
 *   - the Git commits MUST be complete (branches at their final state)
 *   - items may mix kinds; directory items are skipped (the engine's
 *     directory rebuild covers them)
 *
 * Postconditions:
 *   - manifest_apply_scope's postconditions (every enabled profile
 *     projected at HEAD, commit_oid current, directories rebuilt)
 *   - Captured rows are anchored to (blob_oid, now, fresh stat). An
 *     anchor-write failure is non-fatal — the VWD cache is already
 *     projected and the next status self-heals the record through the
 *     slow-path CMP_EQUAL flush
 *   - Deleted paths without a fallback are absent from virtual_manifest
 *     and anchors; the record of a fallback row is preserved (no disk
 *     confirmation for the fallback blob)
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT / ERR_STATE_INVALID / ERR_MEMORY from the engine
 *   - ERR_STATE_INVALID: a row lookup or purge failed (the caller rolls
 *     back; the next reconcile projects again)
 *
 * Performance: one projection + O(N) point lookups, N = items
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param arena Scratch arena for the projection. Allocations live until
 *              the caller destroys the arena (typically command end).
 *              Must not be NULL.
 * @param mounts Per-machine mount table covering the enabled set. Must
 *               not be NULL. Update doesn't mutate bindings, so callers
 *               pass ctx->mounts directly.
 * @param items Array of workspace items committed (must not be NULL)
 * @param item_count Number of items
 * @param out_synced Output: count of rows anchored (must not be NULL)
 * @param out_removed Output: count of deletions without a fallback (must not be NULL)
 * @param out_fallbacks Output: count of deletions reassigned to a lower profile (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_update_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const workspace_item_t **items,
    size_t item_count,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks
);

/**
 * Add files to manifest (add command)
 *
 * Called after the add command committed the files to `profile`. Runs
 * the projection engine (manifest_apply_scope, leftover =
 * LIFECYCLE_RELEASED), then overlays the verb's intent on the paths it
 * committed: they were captured FROM disk, so for each path whose row
 * this profile won, the record is anchored to the just-committed blob
 * with a fresh stat and the next status takes the fast path. A path a
 * higher-precedence profile owns receives nothing — its row is the
 * winner's, and a stat bound to this profile's blob would poison the
 * winner's fast path. A path with no row (filtered by .dottaignore)
 * receives nothing either.
 *
 * Preconditions:
 *   - state MUST have an active write transaction
 *   - the Git commit MUST be complete
 *   - filesystem_paths are canonical filesystem paths
 *   - `profile` is enabled, and its target binding (if any) is stored:
 *     the caller enables / re-binds before this call and builds `mounts`
 *     from the post-mutation row cache
 *
 * Postconditions:
 *   - manifest_apply_scope's postconditions (every enabled profile
 *     projected at HEAD, commit_oid current, directories rebuilt)
 *   - Rows `profile` won for the added paths are anchored to
 *     (blob_oid, now, fresh stat). An anchor-write failure is non-fatal
 *     — the VWD cache is already projected and the next status self-
 *     heals the record through the slow-path CMP_EQUAL flush
 *   - Transaction remains open (caller commits via state_save)
 *
 * Error Conditions:
 *   - ERR_GIT / ERR_STATE_INVALID / ERR_MEMORY from the engine
 *   - ERR_STATE_INVALID: a row lookup failed (the caller rolls back; the
 *     next reconcile projects again)
 *
 * Performance: one projection + O(N) point lookups, N = paths added
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param arena Scratch arena for the projection. Allocations live until
 *              the caller destroys the arena (typically command end).
 *              Must not be NULL.
 * @param mounts Per-machine mount table reflecting the post-add binding
 *               set. Must not be NULL. Add may implicitly enable a profile
 *               (or store its --target) before this call, so callers build
 *               a fresh local table after that mutation; ctx->mounts is
 *               stale on the implicit-enable path.
 * @param profile Profile files were added to (must not be NULL)
 * @param filesystem_paths Array of filesystem paths (must not be NULL)
 * @param out_synced Output: count of rows anchored (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_add_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const char *profile,
    const string_array_t *filesystem_paths,
    size_t *out_synced
);

/**
 * Project a single Git tree's files into the public manifest_rows_t carrier
 *
 * Used by the historical-diff path (cmd_diff): given a tree, profile,
 * mount table, and optional per-tree metadata, produces a manifest_row_t
 * row for every blob the tree exposes (sans repository metadata files —
 * .dottaignore, .bootstrap, .git/, .dotta/). Mirrors workspace_files and
 * manifest_rows_view: one carrier shape, three producers.
 *
 * Metadata, when supplied, is applied row-by-row in lockstep with the
 * tree walk — mode, owner, group, and encrypted are filled from the
 * tree's own metadata.json. Pass NULL to skip metadata application
 * (rows keep Git-derived defaults). Callers that have already loaded
 * the tree's metadata for their own purposes should pass it here.
 *
 * Custom-prefix resolution is delegated to `mounts`. The handle MUST
 * record a binding for `profile` (with target set) when the tree
 * contains custom/ entries; a missing binding is a hard error from the
 * build callback (ERR_STATE_INVALID with a repair hint). Trees without
 * custom/ entries can pass any mount table, including one with no
 * binding for `profile`.
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
 * @param out Rows slice (must not be NULL; entries borrowed from `arena`,
 *            lifetime tied to it)
 * @return Error or NULL on success
 */
error_t *manifest_load_tree_files(
    git_tree *tree,
    const char *profile,
    const mount_table_t *mounts,
    const metadata_t *metadata,
    arena_t *arena,
    manifest_rows_t *out
);

#endif /* DOTTA_MANIFEST_H */
