/**
 * cleanup.h - Orphan pruning: plan / preflight / execute
 *
 *   cleanup_plan_build   — decide *which* orphans this run may touch, from
 *                          (workspace, scope), once
 *   cleanup_preflight    — decide *what happens* to each of them: the verdicts
 *   cleanup_execute      — carry the verdicts out and report what happened
 *
 * Same shape as core/deploy. Preview, prompt, execution and apply's record step
 * all read the one plan and the one set of verdicts; execution re-decides nothing
 * and applies no filter of its own.
 *
 * Why the verdicts are a phase of their own and not part of the plan: the plan
 * is (workspace, scope) alone — which orphans this run may touch — and a verdict
 * needs looks at the disk that a plan has no business taking: the readdir that
 * finishes a directory's, and the one probe of the parent that finishes either
 * kind's (may this run make the removal at all).
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
 *   a file with a cleanup_skip_reason ⇒ skipped unless --force; a directory the
 *   workspace could not verify ⇒ skipped, --force included; else prunable, a
 *   directory's remainder permitting
 * - what is left in a directory after this run: fs_directory_emptiness,
 *   vouching for what this run prunes and for what it merely holds (preflight;
 *   cleanup_preflight_result_t has the classes), and fs_remove_empty_dir, which
 *   removes exactly what that walk looks past as gone and refuses anything else
 *   before touching it (execute)
 * - whether this run may make a removal the item's facts cleared: write and search
 *   on the parent, fs_eaccess, once per such item (preflight — the refused
 *   buckets). The one fact here that is the run's and not the path's, asked with
 *   the reach counted in: a run that holds root is never refused, so the buckets
 *   are empty under sudo by construction, and without it the refusal is a skip
 *   that names the parent and closes with the sudo line — the shape deploy's
 *   PERMISSION skip has on the other engine
 *
 * Directory pruning is one deepest-first pass, ordered by the plan. Children
 * are decided before parents, so a parent emptied by its children needs no second
 * look and the preview predicts the outcome the prune arrives at.
 *
 * The plan's and the verdicts' buckets hold borrowed workspace_item_t pointers
 * (workspace lifetime — the items are arena-allocated, their addresses stable
 * by construction); project them with workspace_items_view. The receipt's outcomes
 * borrow the same items. Free plan, verdicts and result BEFORE workspace_free.
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
 *                                  row (item->row, the relocation) under a label
 *                                  whose projection is not the user's to move
 *                                  (home/ — !per_profile): the copy here is the
 *                                  claim's old home, held even when byte-clean,
 *                                  so the hold outranks the user-change reasons
 *                                  below it. Guarded by the label, so a re-targeted
 *                                  custom/ copy never trips it and keeps the
 *                                  prune (or its own divergence reason)
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
 * A non-encrypted file is verified by hashing the disk copy, read through
 * sys/filesystem and bounded by fs_read_fd's cap (256 MB): only a file above
 * the cap, or one the look itself cannot make, reaches UNVERIFIED from the compare.
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
 * The verdict buckets of cleanup_preflight_result_t, as a value — PRUNABLE split
 * once more there, by the run's reach: one producer, read by the verdict phase
 * to fill them and by status to predict them, so the two cannot route one item
 * two ways. In the order the tests are taken — the
 * occupant, the state, the divergence bits:
 *
 *   occupant NONE                         ABSENT     record retires, no effect
 *   state RELEASED                        RELEASED   left alone, record retires
 *   a displaced ancestor above            RELEASED   both kinds. The occupant
 *   (the item's displaced class)                     was observed through the
 *                                                    squatter and speaks for
 *                                                    the wrong tree — not dotta's
 *                                                    to remove, --force and a
 *                                                    prune order included. Terminal
 *                                                    on purpose: a skip would
 *                                                    prune on the NEXT run, once
 *                                                    the displaced directory's
 *                                                    own released record has
 *                                                    retired and no witness of
 *                                                    the squat remains
 *   a relocated home/ claim, unforced     SKIPPED    both kinds. The claim's row
 *                                                    (item->row — the relocation)
 *                                                    projects at a different
 *                                                    filesystem path under a
 *                                                    label the user cannot
 *                                                    re-target (!per_profile:
 *                                                    home/, since root/'s
 *                                                    projection is fixed), which
 *                                                    means $HOME itself differs
 *                                                    — and the identity's HOME
 *                                                    is the invoker's under sudo
 *                                                    (sys/identity), so that is
 *                                                    a test HOME, a second account,
 *                                                    a migrated home directory,
 *                                                    and the copy here is real
 *                                                    dotfiles under the real
 *                                                    home. --force lifts the
 *                                                    hold — the designed escape
 *                                                    for a deliberate home
 *                                                    migration. A re-targeted
 *                                                    custom/ claim is the user's
 *                                                    own move and prunes as before,
 *                                                    its preview naming the move
 *   a file with a cleanup_skip_reason     SKIPPED    unless --force
 *   a directory with DIVERGENCE_UNVERIFIED
 *                                         SKIPPED    --force included: no flag
 *                                                    makes an unstattable or
 *                                                    unreadable directory one
 *                                                    the run can see into, and
 *                                                    the receipt would only read
 *                                                    [failed]
 *   else                                  PRUNABLE   the candidate preflight
 *                                                    finishes. A file: removed,
 *                                                    once the parent admits the
 *                                                    run. A directory: prunable
 *                                                    once nothing but gone entries
 *                                                    is left in it and the parent
 *                                                    admits the run, skipped
 *                                                    while a held one is, released
 *                                                    once a permanent one is
 *                                                    (the classes are on
 *                                                    cleanup_preflight_result_t)
 *
 * PRUNABLE is the one verdict status cannot finish — the remainder and the reach
 * are preflight's, from the disk — and its directory hint says so.
 */
typedef enum {
    CLEANUP_ABSENT,      /* Not on disk at load → record retires, no filesystem effect */
    CLEANUP_RELEASED,    /* Left on disk → record retires */
    CLEANUP_SKIPPED,     /* Left on disk → record stays */
    CLEANUP_PRUNABLE     /* Removed — a directory, once the readdir agrees */
} cleanup_verdict_t;

/**
 * Decide a planned orphan's verdict from the item alone
 *
 * @param item Orphaned or released item, either kind (must not be NULL)
 * @param force --force: lifts a file's skip reasons and the relocation hold (either
 *        kind), never a release and never a directory's UNVERIFIED
 * @return The verdict (see cleanup_verdict_t)
 */
cleanup_verdict_t cleanup_verdict(const workspace_item_t *item, bool force);

/**
 * Cleanup verdicts — what cleanup_execute will do, decided once
 *
 * Every planned item lands in exactly one bucket:
 *   plan->files       = prunable_files ∪ refused_files ∪ skipped_files ∪
 *                       released_files ∪ absent_files
 *   plan->directories = prunable_dirs  ∪ refused_dirs  ∪ skipped_dirs  ∪
 *                       released_dirs  ∪ absent_dirs
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
 * refused_* hold what every fact of its own cleared and the run cannot remove:
 * unlink and rmdir ask nothing of the path, only write and search on its parent,
 * and the parent refuses this run (fs_eaccess, with the reach — a run that holds
 * root fills neither bucket, and the sudo'd re-run the preview names meets no
 * refusal). Held exactly as a skip is — left alone, record stays, the directory
 * above waits with it, the screen counts it as skipped — and kept apart from
 * one because the reason is the run's, not the item's: --force lifts a skip reason
 * and never this, and the remedy is root, not consent. The last rung, as OWNERSHIP
 * is deploy's: an item a skip reason holds is never asked, so a modified orphan
 * under a root-owned parent reads modified unforced and refused under --force,
 * each honest about the one thing in the way. Two under-approximations the removal
 * meets with its cause instead (cleanup_result_t's failed): a sticky parent's
 * owner rule, and the OS-metadata entries fs_remove_empty_dir clears inside a
 * directory whose own write bit the invoker lacks.
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
    ptr_array_t refused_files;     /* Present, nothing of its own in the way, the parent refuses this run → left alone, record stays */
    ptr_array_t skipped_files;     /* Present, a skip reason stands → left alone (unless --force) */
    ptr_array_t released_files;    /* Present, Git no longer backs it → left on disk, record retires */
    ptr_array_t absent_files;      /* Not on disk at load → record retires, no filesystem effect */

    /* Directories */
    ptr_array_t prunable_dirs;     /* Present; nothing but gone entries left → removed */
    ptr_array_t refused_dirs;      /* Present; nothing but gone entries left, the parent refuses this run → left alone, record stays */
    ptr_array_t skipped_dirs;      /* Present; a held entry left, could not be verified, or its home moved → left alone, record stays */
    ptr_array_t released_dirs;     /* Released by the workspace, or a permanent entry left → left alone, record retires */
    ptr_array_t absent_dirs;       /* Not there → record retires */
} cleanup_preflight_result_t;

/**
 * Decide the verdicts
 *
 * Files: cleanup_verdict from the item — every observation it reads was made at
 * workspace load — then, for a prunable one, the parent's reach (one fs_eaccess).
 * Directories: cleanup_verdict from the item likewise (a released or unverified
 * directory is left alone, unprobed), then for each candidate the view (a managed
 * path beneath it) and one readdir, against the files above, the directories
 * already decided beneath them, and — for an entry outside the plan — its workspace
 * item; then, for one nothing but gone entries is left in, the parent's reach.
 * The reach is asked last, of what the run would otherwise remove: a directory
 * a permanent entry keeps is released whoever owns its parent.
 *
 * READ-ONLY: modifies neither the filesystem, the state database nor Git.
 *
 * @param ws Workspace the plan was built from (must not be NULL; the view answers
 *        for the managed paths beneath a directory, the items for the entries
 *        outside the plan)
 * @param plan Cleanup plan (must not be NULL)
 * @param force --force: prune what would be skipped too; never a released file,
 *        never a directory's UNVERIFIED (cleanup_verdict), never a refusal (root
 *        is not a flag)
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
 * One prunable item's outcome — the item, and the cause where the removal errored
 *
 * The item is borrowed from the verdicts' prunable buckets (workspace lifetime
 * — arena addresses, stable by construction). The error is the failed bucket's
 * tail: the mechanism's own refusal, verbatim (EACCES on the parent, EROFS, EBUSY,
 * an EIO the unlink met) — a prune's cause names its remedy the way a deploy's
 * does, and the remedies differ, so the receipt keeps it for the caller to render.
 * NULL in every other bucket: the bucket is the tag, as UNSET is for
 * deploy_outcome_t's stat. Owned by the receipt; cleanup_result_free frees it.
 */
typedef struct {
    const workspace_item_t *item;   /* Borrowed (workspace lifetime) */
    error_t *error;                 /* The failed bucket's cause; NULL elsewhere (owned) */
} cleanup_outcome_t;

/**
 * An outcome array with its count — the shape deploy_outcomes_t gives deploy's
 */
typedef struct {
    cleanup_outcome_t *entries;
    size_t count;
} cleanup_outcomes_t;

/**
 * Cleanup result — the run's receipt: what became of each prunable item
 *
 * Execute acts on prunable_files and prunable_dirs alone, so the receipt partitions
 * exactly those — the one split execute itself takes, and nothing else:
 *
 *   verdicts->prunable_files ∪ verdicts->prunable_dirs = pruned_files ∪
 *       reclaimed_files ∪ pruned_dirs ∪ reclaimed_dirs ∪ skipped_dirs ∪ failed
 *
 * — the mirror of deploy_result_t's equation. It holds by the loops' shape: every
 * iteration ends in exactly one bucket, and the occupant switch is total, so a
 * new occupant is a build error and never a dropped item. The fates execute never
 * touches — released, skipped at preflight, absent at load — are the verdicts'
 * and are read there: they are decisions, and this object reports effects. The
 * preview says both; the receipt's printer restates the decided ones from the
 * verdicts and reports the run's own from here, in the preview's order (apply's
 * print_cleanup_results reads both objects).
 *
 * pruned_* guarantee a filesystem removal happened. reclaimed_* were gone by
 * the time the run looked — after the prompt, before the removal — so no removal
 * happened or was needed and only the record retires; the caller reports the
 * two distinctly, because a decision is not an effect, and folds the verdicts'
 * absent_* (gone at load) into the same reclaimed line, since what the user has
 * in hand is the same either way: a path that is already gone. skipped_dirs is
 * execute's own refusal, re-decided by nothing — a directory retyped while the
 * run waited, or one an entry arrived in that the removal may not clear
 * (fs_remove_empty_dir's ERR_CONFLICT): what the run found is the next load's
 * to judge ([type], the entry), no remedy line depends on which, and "skipped"
 * is still the screen's word for it, so no cause rides on it. failed is both
 * kinds in act order, each with its cause.
 *
 * Each array is sized to its promise at entry (calloc, count + 1, so every array
 * is an array; the failed bucket to both kinds together — every promised item
 * could fail) and fills in act order: files, then the directories in the verdicts'
 * prune order. count gates every read, so an untaken slot is invisible and the
 * receipt holds exactly what happened, by construction. Nothing here can be
 * truncated by the run.
 *
 * Records that retire: pruned_* and reclaimed_* (here), absent_* (the verdicts).
 * Records that release: released_* (the verdicts). Records that stay: skipped_dirs
 * and failed (here), skipped_* and refused_* (the verdicts).
 *
 * Exit contract: `failed` alone reaches the exit code. Three columns, and the
 * two engines draw the line between them differently — deploy_skip_reason_t draws
 * the same table from its side:
 *
 *   never attempted: dotta could not     deploy   exit ≠ 0  the incapacity skips
 *                                        cleanup  exit 0    a directory's UNVERIFIED
 *                                                           (cleanup_verdict);
 *                                                           a parent that refuses
 *                                                           the run (refused_*)
 *   attempted: the world moved           deploy   exit ≠ 0  failed — EEXIST, EISDIR,
 *                                                           ENOTEMPTY are the
 *                                                           row's own outcome
 *                                        cleanup  exit 0    skipped_dirs
 *   attempted: the mechanism errored     both     exit ≠ 0  failed
 *
 * The line: a plan is a promise, an orphan set is a permission. A skip stays
 * out whichever phase took it — the skipped orphans are attempted-and-refused
 * only, never obligations — and a permission the world withdrew while the prompt
 * waited is not a broken one, where a promise the world moved under is. Both
 * lines are stated here so the next change picks a column on purpose.
 */
typedef struct {
    cleanup_outcomes_t pruned_files;      /* Unlinked */
    cleanup_outcomes_t reclaimed_files;   /* Gone by the time the run looked; nothing was needed */
    cleanup_outcomes_t pruned_dirs;       /* Removed */
    cleanup_outcomes_t reclaimed_dirs;    /* Gone by the time the run looked */
    cleanup_outcomes_t skipped_dirs;      /* Retyped, or gained an entry, while the run waited */
    cleanup_outcomes_t failed;            /* Both kinds, act order, each with its cause */
} cleanup_result_t;

/**
 * Carry the verdicts out
 *
 * Pure filesystem: no repo, no state — the caller settles the records from the
 * receipt and the verdicts. Files first (every prunable file), then directories
 * in the verdicts' prune order. Individual removal failures are non-fatal and
 * land in `failed` with their cause; the returned error is the run's infrastructure
 * alone — the receipt's own allocation failed, *out is unset, nothing ran and
 * there is nothing to record — deploy_execute's contract.
 *
 * @param verdicts Verdicts from cleanup_preflight (must not be NULL)
 * @param out Result (must not be NULL; caller frees with cleanup_result_free)
 * @return Error or NULL on success
 */
error_t *cleanup_execute(
    const cleanup_preflight_result_t *verdicts,
    cleanup_result_t **out
);

/**
 * Free a result — the failed causes, then the arrays. No-op on NULL. Call before
 * workspace_free.
 */
void cleanup_result_free(cleanup_result_t *result);

#endif /* DOTTA_CLEANUP_H */
