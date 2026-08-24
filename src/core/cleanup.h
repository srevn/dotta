/**
 * cleanup.h - Orphan pruning: plan / preflight / execute
 *
 *   cleanup_plan_build   — decide *which* orphans this run may touch, from
 *                          (workspace, scope), once
 *   cleanup_preflight    — decide *what happens* to each of them: the verdicts
 *   cleanup_execute      — carry the verdicts out and report what happened
 *
 * Same shape as core/deploy. Preview, privilege check, prompt, execution and
 * apply's record step all read the one plan and the one set of verdicts; execution
 * re-decides nothing and applies no filter of its own.
 *
 * Why the verdicts are a phase of their own and not part of the plan: the plan
 * is read before apply's privilege check (the root/ labels come from it), and
 * the directory verdicts need a look at the disk — the readdir — taken with the
 * identity the run will act under. Plan → privileges → verdicts is the order
 * the privilege boundary forces.
 *
 * The verdicts are a function of the workspace's load-time observation — the
 * occupant, divergence, Git authority — of the view, of the plan, and of --force.
 * A confirmation prompt may sit between preflight and execute; nothing here
 * re-observes across it, and nothing pretends to: execute reports what it finds
 * (a path gone by then, a directory that gained an entry) and re-decides nothing.
 * The same stance as core/deploy.
 *
 * One producer per fact:
 * - what stands at an orphan's path: the workspace's lstat, carried on the item
 *   (workspace_item_t.occupant). Preflight reads it and probes nothing; status
 *   reads the same item, so the two cannot disagree on whether a path is there.
 *   Execute probes once more, only to report what it found
 * - what becomes of a present orphan, either kind: cleanup_verdict, from the
 *   item — RELEASED ⇒ released (left on disk, record retires — never pruned,
 *   --force included: dotta removes what it deployed and Git still backs, and
 *   lets go of what Git lost, of what it never deployed, and of a path another
 *   kind of node stands at); a relocated home/ claim ⇒ skipped unless --force,
 *   either kind (the copy is the claim's old home — see the verdict table);
 *   a file with a cleanup_skip_reason ⇒ skipped unless --force; a directory
 *   the workspace could not verify ⇒ skipped, --force included; else prunable,
 *   a directory's remainder permitting
 * - what is left in a directory after this run: fs_directory_emptiness,
 *   vouching for what this run prunes and for what it merely holds (preflight;
 *   cleanup_preflight_result_t has the classes), and fs_remove_empty_dir, which
 *   removes exactly what that walk looks past as gone and refuses anything else
 *   before touching it (execute)
 *
 * Directory pruning is one deepest-first pass, ordered by the plan. Children
 * are decided before parents, so a parent emptied by its children needs no second
 * look and the preview predicts the outcome the prune arrives at.
 *
 * Buckets hold borrowed workspace_item_t pointers (workspace lifetime — the items
 * are arena-allocated, their addresses stable by construction); project them
 * with workspace_items_view. Free plan, verdicts and result BEFORE workspace_free.
 *
 * Integration:
 * - workspace.h: orphan detection, the occupant, Git authority, divergence; the
 *                view (the managed paths beneath a directory) and the items (an
 *                entry outside the plan) for a directory's remainder
 * - scope.h:     the three filter dimensions
 * - filesystem.h: the emptiness walk, the removals, execute's probe
 */

#ifndef DOTTA_CLEANUP_H
#define DOTTA_CLEANUP_H

#include <stdbool.h>

#include "core/scope.h"
#include "core/workspace.h"

/* ── Plan ─────────────────────────────────────────────────────────── */

/**
 * Cleanup plan — cleanup's reading of the orphan set under the scope
 *
 * Every ORPHANED / RELEASED item that passes the scope's profile and path
 * dimensions lands in exactly one bucket; out-of-scope items are invisible. The
 * exclude dimension does not drop an item, it spares it: `excluded` is reported
 * ("Skipped N paths (--exclude)") and never touched.
 *
 * The path dimension reaches an orphan the way it reaches an active row: `apply
 * <file>` plans the orphan at that path, `apply <dir>` the orphans beneath it,
 * so one orphan can be retired without a whole-scope run. Scope decides reach,
 * never verdict — an orphan named by path is still skipped when modified and
 * still released when Git lost it — and it reaches exactly what it names: a parent
 * directory the filter does not cover stays, and the next run that covers it
 * prunes it.
 *
 * `directories` is sorted deepest-first here, once, so preflight predicts and
 * execute prunes in the same order. Free with cleanup_plan_free BEFORE
 * workspace_free.
 */
typedef struct {
    ptr_array_t files;         /* ORPHANED / RELEASED file items in scope */
    ptr_array_t directories;   /* ORPHANED / RELEASED directory items in scope, deepest first (prune order) */
    ptr_array_t excluded;      /* Both kinds, spared by -e — reported, never touched */
} cleanup_plan_t;

/**
 * Build the cleanup plan
 *
 * Walks the workspace's diverged items once, keeping ORPHANED and RELEASED ones,
 * gating each on scope_accepts_profile ∧ scope_accepts_path(kind), then routing
 * by scope_is_excluded(kind) and item_kind.
 *
 * @param ws Workspace loaded with orphan analysis (must not be NULL)
 * @param scope Operation scope (must not be NULL)
 * @param keep_orphans --keep-orphans: plan nothing. An empty plan is the answer
 *        every later stage reads — no stage re-encodes the flag.
 * @param out Plan (must not be NULL; caller frees with cleanup_plan_free)
 * @return Error or NULL on success
 */
error_t *cleanup_plan_build(
    const workspace_t *ws,
    const scope_t *scope,
    bool keep_orphans,
    cleanup_plan_t **out
);

/**
 * Free a plan — bucket buffers only; the items belong to the workspace. No-op
 * on NULL.
 */
void cleanup_plan_free(cleanup_plan_t *plan);

/**
 * True when the plan carries nothing this run may act on
 *
 * Excluded items are not work: they are reported and left alone.
 */
static inline bool cleanup_plan_is_empty(const cleanup_plan_t *plan) {
    return plan->files.count == 0 && plan->directories.count == 0;
}

/**
 * How many items the plan classified — both kinds, every bucket
 *
 * Distinct from cleanup_plan_is_empty, which counts only *work*: a plan of nothing
 * but spared items is empty there and non-zero here. Apply reads this beside
 * deploy_plan_row_count to tell a path filter that named nothing dotta manages
 * from one whose paths are all skipped — an orphan the filter found is a match,
 * whatever its verdict.
 *
 * The bucket set lives here so a consumer never has to enumerate it.
 */
static inline size_t cleanup_plan_item_count(const cleanup_plan_t *plan) {
    return plan->files.count + plan->directories.count + plan->excluded.count;
}

/* ── Verdicts ─────────────────────────────────────────────────────── */

/**
 * Why a present orphaned file is skipped rather than pruned
 *
 * Pure in the item's divergence bits. Values are listed in precedence order —
 * cleanup_skip_reason answers the first that applies. Files only: a directory's
 * skip is cleanup_verdict's (the workspace could not verify it) or its remainder's
 * (cleanup_preflight_result_t), and needs no table.
 */
typedef enum {
    CLEANUP_SKIP_NONE = 0,       /* Not skipped — nothing stands in the way of the prune */
    CLEANUP_SKIP_UNVERIFIED,     /* The workspace could not settle it — see cleanup_skip_reason */
    CLEANUP_SKIP_RELOCATED,      /* The claim's home moved — held behind --force */
    CLEANUP_SKIP_MODIFIED,       /* Content differs from what dotta deployed */
    CLEANUP_SKIP_TYPE_CHANGED,   /* File ↔ symlink ↔ device (a directory in its place is released) */
    CLEANUP_SKIP_MODE_CHANGED    /* Mode or ownership differs */
} cleanup_skip_reason_t;

/**
 * Map an orphaned file's divergence to the reason it is skipped
 *
 * First match wins:
 *   DIVERGENCE_UNVERIFIED          UNVERIFIED   — a bit the workspace could
 *                                  not settle outranks the ones it could: Git
 *                                  could not vouch for the path, the content
 *                                  compare failed (encrypted file over 100MB —
 *                                  AEAD needs the whole ciphertext, so this is
 *                                  OOM protection; blob corruption; I/O), or
 *                                  the file is present but unstattable (EACCES,
 *                                  EIO). status ranks its [unverified] tag the
 *                                  same way, so one item has one name in both
 *                                  places.
 *   a held relocation              RELOCATED    — the item carries the claim's
 *                                  row (item->row, the relocation) under a
 *                                  label whose projection is not the user's to
 *                                  move (home/ — !per_profile): the copy here
 *                                  is the claim's old home, held even when
 *                                  byte-clean, so the hold outranks the
 *                                  user-change reasons below it. Guarded by
 *                                  the label, so a re-targeted custom/ copy
 *                                  never trips it and keeps the prune (or its
 *                                  own divergence reason)
 *   DIVERGENCE_CONTENT             MODIFIED     — disk differs from what dotta
 *                                  deployed (the record), not from the blob Git
 *                                  may have moved on to
 *   DIVERGENCE_TYPE                TYPE_CHANGED — a one-node swap unlink can
 *                                  undo under --force; a directory where the
 *                                  file was is RELEASED by the workspace and
 *                                  never reaches this table
 *   DIVERGENCE_MODE / OWNERSHIP    MODE_CHANGED
 *   ENCRYPTION / STALE only        NONE — a policy mismatch is not a user
 *                                  change; STALE is never emitted for an orphan
 *                                  (the orphan compare asks one question, of
 *                                  disk alone) and is listed so it cannot block
 *   DIVERGENCE_NONE                NONE — safe to prune
 *   an unnamed divergence bit      UNVERIFIED — blocks until this table
 *                                  names it (defensive default)
 *
 * Non-encrypted files are verified by streaming OID hash (git_odb_hashfile) at
 * any size, so they should never reach UNVERIFIED from the compare.
 *
 * Called twice per skipped file — by the verdict phase to bucket it and by the
 * preview to name its reason — which is one producer called twice, not two
 * producers.
 *
 * @param item Orphaned file item with the workspace's divergence verdict
 * @return The first reason that applies, or CLEANUP_SKIP_NONE
 */
cleanup_skip_reason_t cleanup_skip_reason(const workspace_item_t *item);

/**
 * What becomes of a planned orphan, read off the item alone
 *
 * The four verdict buckets of cleanup_preflight_result_t, as a value: one producer,
 * read by the verdict phase to fill them and by status to predict them, so the
 * two cannot route one item two ways. In the order the tests are taken — the
 * occupant, the state, the divergence bits:
 *
 *   occupant NONE                         ABSENT     record retires, no effect
 *   state RELEASED                        RELEASED   left alone, record retires
 *   a relocated home/ claim, unforced     SKIPPED    both kinds. The claim's row
 *                                                    (item->row — the relocation)
 *                                                    projects at a different
 *                                                    filesystem path under a
 *                                                    label the user cannot
 *                                                    re-target (!per_profile:
 *                                                    home/, since root/'s
 *                                                    projection is fixed), which
 *                                                    means $HOME itself differs
 *                                                    — and fs_get_home is
 *                                                    sudo-aware (SUDO_UID
 *                                                    bypasses `sudo -H`'s
 *                                                    rewrite), so that is a test
 *                                                    HOME, a second account, a
 *                                                    migrated home directory,
 *                                                    and the copy here is real
 *                                                    dotfiles under the real
 *                                                    home. --force lifts the
 *                                                    hold — the designed escape
 *                                                    for a deliberate home
 *                                                    migration. A re-targeted
 *                                                    custom/ claim is the user's
 *                                                    own move and prunes as
 *                                                    before, its preview naming
 *                                                    the move
 *   a file with a cleanup_skip_reason     SKIPPED    unless --force
 *   a directory with DIVERGENCE_UNVERIFIED
 *                                         SKIPPED    --force included: no flag
 *                                                    makes an unstattable or
 *                                                    unreadable directory one
 *                                                    the run can see into, and
 *                                                    the receipt would only read
 *                                                    [failed]
 *   else                                  PRUNABLE   a file: removed. A
 *                                                    directory: the candidate
 *                                                    the readdir finishes —
 *                                                    prunable once nothing but
 *                                                    gone entries is left in
 *                                                    it, skipped while a held
 *                                                    one is, released once a
 *                                                    permanent one is (the classes
 *                                                    are on
 *                                                    cleanup_preflight_result_t)
 *
 * The one verdict status cannot finish is a directory's PRUNABLE, and it says so.
 */
typedef enum {
    CLEANUP_ABSENT,      /* Not on disk at load → record retires, no filesystem effect */
    CLEANUP_RELEASED,    /* Left on disk → record retires */
    CLEANUP_SKIPPED,     /* Left on disk → record stays */
    CLEANUP_PRUNABLE     /* Removed — a directory, once the readdir agrees */
} cleanup_verdict_t;

/**
 * Decide a planned orphan's verdict from the item
 *
 * @param item Orphaned or released item, either kind (must not be NULL)
 * @param force --force: lifts a file's skip reasons and the relocation hold
 *        (either kind), never a release and never a directory's UNVERIFIED
 * @return The verdict (see cleanup_verdict_t)
 */
cleanup_verdict_t cleanup_verdict(const workspace_item_t *item, bool force);

/**
 * Cleanup verdicts — what cleanup_execute will do, decided once
 *
 * Every planned item lands in exactly one bucket:
 *   plan->files       = prunable_files ∪ skipped_files ∪ released_files ∪ absent_files
 *   plan->directories = prunable_dirs  ∪ skipped_dirs  ∪ released_dirs  ∪ absent_dirs
 *
 * Counts are bucket sizes: nothing downstream re-folds an array to recover a
 * split this phase already took. The preview and the confirmation prompt both
 * read these and neither recomputes a verdict of its own, so what the user consents
 * to is what the run does. A vanished or refused item is reported by execute as
 * what it found, never re-decided.
 *
 * Every bucket is always initialized — an empty answer is a valid answer, and
 * no consumer needs a NULL guard.
 *
 * A directory is predicted against this same run's own effects — what is left
 * in it once the run has acted. What the readdir meets falls into three classes,
 * and the verdict is the strongest one met:
 *
 *   gone        OS metadata; an entry this run prunes (prunable_files, and
 *               prunable_dirs beneath it)
 *   held        an entry this run skips (skipped_files, skipped_dirs beneath);
 *               an orphan the plan does not reach (-e spared, outside -p or the
 *               path filter) whose state is ORPHANED — transient by the same
 *               rule: scope decides reach, never verdict, so an unfiltered run
 *               would decide it and a filtered run must not change its parent's
 *               fate
 *   permanent   an entry this run releases (released_files, released_dirs
 *               beneath); an orphan the plan does not reach whose state is
 *               RELEASED; a managed path — the view has a row beneath the
 *               directory, on disk already or not, so the directory is the ancestor
 *               of an enabled row, one ensure_parents would make anyway; anything
 *               else — the user's
 *
 *   nothing but gone left      prunable
 *   a held entry left          skipped   — transient: update, --force, or the
 *                                          run that reaches it
 *   a permanent entry left     released  — nothing dotta will ever do empties it
 *
 * That is what the prune arrives at by acting, read off the plan here in one
 * deepest-first pass, so the preview can say "2 will be pruned" about directories
 * that still hold the files this run prunes: the ordinary shape of disabling a
 * profile.
 *
 * Released for a directory means what it means for a file — dotta's claim on
 * the path ends, the path stays. A directory holding something not dotta's to
 * remove is serving that something: the shape of the untracked parents
 * create_ancestor makes and never prunes. Re-enabling the profile re-projects
 * the row and the returning path reads clean (present, observed); what is lost
 * is the ownership bit, and with it the prune on a later scope exit once the
 * directory is empty by hand. That trade buys a status that goes quiet when there
 * is nothing left for apply to do, where a skip would nag every run.
 *
 * Exact except where the world moves underneath it — a change made while the
 * confirmation prompt waits, an I/O failure — and the run reports whatever it
 * could not do. prunable_dirs is in prune order, deepest first.
 */
typedef struct {
    /* Files */
    ptr_array_t prunable_files;    /* Present, no reason to skip it → unlinked */
    ptr_array_t skipped_files;     /* Present, a skip reason stands → left alone (unless --force) */
    ptr_array_t released_files;    /* Present, Git no longer backs it → left on disk, record retires */
    ptr_array_t absent_files;      /* Not on disk at load → record retires, no filesystem effect */

    /* Directories */
    ptr_array_t prunable_dirs;     /* Present; nothing but gone entries left → removed */
    ptr_array_t skipped_dirs;      /* Present; a held entry left, could not be verified, or its home moved → left alone, record stays */
    ptr_array_t released_dirs;     /* Released by the workspace, or a permanent entry left → left alone, record retires */
    ptr_array_t absent_dirs;       /* Not there → record retires */
} cleanup_preflight_result_t;

/**
 * Decide the verdicts
 *
 * Files from the items alone — cleanup_verdict, one test per item; O(n) in the
 * file count, no syscalls, because every observation it reads was made at workspace
 * load. Directories: cleanup_verdict from the item likewise (a released or
 * unverified directory is left alone, unprobed), then for each candidate the
 * view (a managed path beneath it) and one readdir, against the files above,
 * the directories already decided beneath them, and — for an entry outside the
 * plan — its workspace item.
 *
 * READ-ONLY: modifies neither the filesystem, the state database nor Git.
 *
 * @param ws Workspace the plan was built from (must not be NULL; the view answers
 *        for the managed paths beneath a directory, the items for the entries
 *        outside the plan)
 * @param plan Cleanup plan (must not be NULL)
 * @param force --force: prune what would be skipped too; never a released file,
 *        never a directory's UNVERIFIED (cleanup_verdict)
 * @param out Verdicts (must not be NULL; caller frees with
 *        cleanup_preflight_result_free)
 * @return Error on allocation failure, NULL otherwise
 */
error_t *cleanup_preflight(
    const workspace_t *ws,
    const cleanup_plan_t *plan,
    bool force,
    cleanup_preflight_result_t **out
);

/** Free verdicts. No-op on NULL. Call before workspace_free. */
void cleanup_preflight_result_free(cleanup_preflight_result_t *verdicts);

/* ── Outcomes ─────────────────────────────────────────────────────── */

/**
 * Cleanup result — the run's receipt, by outcome
 *
 * pruned_* guarantee a filesystem removal happened. reclaimed_* were absent —
 * at load, or by the time the run looked — so no removal happened or was needed
 * and only the record retires; callers report the two distinctly, because a
 * decision is not an effect. skipped_*, released_* and the absent verdicts are
 * confirmed here by passing them through, never re-decided: the result is the
 * one object apply's record step reads, so "what ran → which records retire" is
 * read in one place.
 *
 * Every planned item appears in exactly one bucket, so the receipt accounts for
 * the whole plan:
 *   plan->files       = pruned_files ∪ reclaimed_files ∪ released_files
 *                       ∪ skipped_files ∪ failed_files
 *   plan->directories = pruned_dirs ∪ reclaimed_dirs ∪ released_dirs ∪ skipped_dirs
 *                       ∪ failed_dirs
 *
 * Records that retire: pruned_files, reclaimed_files, released_files, pruned_dirs,
 * reclaimed_dirs, released_dirs. Records that stay: skipped_*, failed_*.
 */
typedef struct {
    ptr_array_t pruned_files;      /* Unlinked */
    ptr_array_t reclaimed_files;   /* Absent at load, or by the time the run looked; record retires */
    ptr_array_t released_files;    /* Left on disk; record retires */
    ptr_array_t skipped_files;     /* Skipped at preflight (cleanup_skip_reason); left alone */
    ptr_array_t failed_files;      /* The removal errored */
    ptr_array_t pruned_dirs;       /* Removed */
    ptr_array_t reclaimed_dirs;    /* Absent; record retires */
    ptr_array_t released_dirs;     /* Left alone; record retires */
    ptr_array_t skipped_dirs;      /* Skipped at preflight, or no longer a directory / refused on removal */
    ptr_array_t failed_dirs;       /* The removal errored */
} cleanup_result_t;

/**
 * Carry the verdicts out
 *
 * Pure filesystem: no repo, no state — the caller retires rows from the result.
 * Files first (every prunable file), then directories in the verdicts' prune
 * order. Individual removal failures are non-fatal and land in failed_*; the
 * only fatal error is an allocation failure, and then the partial result is
 * returned in *out alongside the error so the caller records what did happen —
 * as it does for deploy.
 *
 * @param verdicts Verdicts from cleanup_preflight (must not be NULL)
 * @param out Result (must not be NULL; caller frees with cleanup_result_free)
 * @return Error or NULL on success
 */
error_t *cleanup_execute(
    const cleanup_preflight_result_t *verdicts,
    cleanup_result_t **out
);

/** Free a result. No-op on NULL. Call before workspace_free. */
void cleanup_result_free(cleanup_result_t *result);

#endif /* DOTTA_CLEANUP_H */
