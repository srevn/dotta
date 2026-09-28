/**
 * deploy.h - File and directory deployment engine
 *
 * Plan / preflight / execute, in that order:
 *
 *   deploy_plan_build   — decide *what* from (workspace, scope), once
 *   deploy_preflight    — decide the fate of every planned row, from the
 *                         workspace's look and the row: a verdict (how it is
 *                         materialized) or a skip (why it is not)
 *   deploy_execute      — carry the verdicts out; decides nothing
 *
 * Preview, prompt, reporting and apply's record phase all read the one plan and
 * the one set of verdicts; execution applies no filter and takes no decision of
 * its own. Same shape as core/cleanup.
 *
 * Design principles:
 * - Every decision is taken at preflight, before anything changes, from the
 *   occupant the workspace's look found (workspace_item_t.occupant) and the row
 *   — one fate per planned row, a verdict or an explicit skip. A confirmation
 *   prompt may sit between preflight and execute; nothing looks again across
 *   it, and nothing pretends to: the mechanisms refuse what a verdict no longer
 *   describes (O_NOFOLLOW, EISDIR, EEXIST, ENOTEMPTY) and the refusal is that
 *   row's outcome, not the run's end. The same stance as core/cleanup
 * - One element type per phase: the plan buckets borrowed items and authors
 *   nothing; preflight authors the fates — a verdict or a skip, carrying everything
 *   decided about the row; execute authors the outcomes — one per verdict, landed
 *   or failed, the one split execute itself takes. A verb inside a landed bucket
 *   is derived from the fate, never stored twice
 * - A dry run is the preview: the caller reads the verdicts and calls no executor,
 *   so there is no dry-run flag beneath the plan
 * - Removals are single-node: what stands at a planned path, never a tree
 * - Directories are materialized in two phases: held at a working mode (recorded
 *   mode, owner rwx on) while the run writes beneath them, then released to the
 *   exact recorded mode, deepest-first — the same way cmd_export materializes a
 *   profile. A directory the view claims therefore never refuses a path beneath
 *   it, and preflight predicts no modes
 * - Metadata is reproduced, not negotiated: every write applies the row's mode
 *   and resolved ownership atomically through its own descriptor, so there is
 *   never a moment when a path stands with the wrong owner
 * - Silent: outcomes travel in the receipt — a row's failure among them, its
 *   cause on the outcome — verdicts and skips in the preflight, with the anomalies
 *   met while deciding (an identity that could not be resolved), which are the
 *   caller's to print; only the run's infrastructure travels in the returned
 *   error. This module emits no prose of its own; verbosity and tense are the
 *   caller's, the same convention as every other core module
 */

#ifndef DOTTA_DEPLOY_H
#define DOTTA_DEPLOY_H

#include <git2.h>
#include <types.h>

#include "base/error.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"

/* Forward declaration — the content cache is deploy_execute's input alone
 * (infra/content.h); everything else this header names is workspace vocabulary,
 * included above. */
typedef struct content_cache content_cache_t;

/**
 * Deployment options — read by deploy_preflight alone, as cleanup's are
 */
typedef struct {
    bool force;               /* Overwrite modified files; replace a type conflict */
    bool strict_ownership;    /* Fail if ownership cannot be resolved */
} deploy_options_t;

/**
 * How one planned row is materialized — decided once, at preflight
 *
 * Everything a consumer needs and nothing it has to go and get: the row's item
 * — the row, with its analysis — what stands at its path, and the metadata the
 * write applies. The occupant is the workspace's lstat, never a fresh one — or
 * FS_OCCUPANT_NONE for a row preflight planned absent beneath a squatter this
 * run replaces first (check_ancestry), whose own path the workspace never looked
 * at and which the run empties before anything lands there. The occupant is also
 * the receipt's verb for a directory: NONE → created, DIRECTORY → fixed, anything
 * else → replaced (deploy_convergence).
 *
 * The item is the one the fate is taken for, filled verbatim on every arm — the
 * planned-absent arms and the skip's included (deploy_skip_t). Its row is the
 * fate's: the view holds one row per path, and an active path's item is that
 * row's own, so the row is read off the item (item->row) and never carried beside
 * it. An item's join facts (row, record, profile) are sound on every fate; a
 * row beneath a squatter carries no look at all (core/workspace.h
 * workspace_displaced_t), which is why the fate's own occupant says what the
 * run will find. What a fate declines to consult it declines at the reader, never
 * by blanking the pointer.
 *
 * Never NULL, so a reader dereferences it without a test. A fate is taken for a
 * pending row, a verdict or a skip, or for an ancestor, a verdict alone, and
 * each holds an item by construction, since every active path has one
 * (core/workspace.h workspace_active): a pending row's is the item its bucket
 * holds, an ancestor's the directory item the pass walks (workspace_directories).
 *
 * The decided facts are exactly the ones not on the row: the occupant, and the
 * ownership the write applies (resolve_deployment_ownership: the claim resolved
 * on this host, half by half — the invoker where it names no owner, no change
 * where it names no group — on every run; (uid_t) -1 is no change, and an owner
 * is left unchanged only where the claim named one this host cannot resolve).
 * The mode the write applies is the row's, read there — total for every kind
 * that carries one (resolve_metadata carries the rationale).
 */
typedef struct {
    const workspace_item_t *item;    /* Borrowed (workspace lifetime), never NULL; the row is item->row */
    fs_occupant_t occupant;          /* What the run will find at the path */
    uid_t uid;                       /* Ownership the write applies; -1 = no change */
    gid_t gid;
} deploy_verdict_t;

/**
 * A verdict array with its count — the shape manifest_rows_t gives rows
 */
typedef struct {
    deploy_verdict_t *entries;
    size_t count;
} deploy_verdicts_t;

/**
 * Is something known to be standing at the path?
 *
 * FS_OCCUPANT_UNKNOWN deliberately answers no. Deploy judges nothing it could
 * not see: an occupant it failed to stat conflicts with nothing, and the row is
 * skipped as unreadable rather than judged on a guess (the ladders' leftover
 * rung). The workspace's own presence rule (occupant != FS_OCCUPANT_NONE,
 * workspace.h) assumes an unstattable path present; this is deploy's stricter
 * reading, for judgments — one producer, read by occupant_conflicts (both ladders'
 * type rung) and deploy_file (the symlink arm's clear) in deploy.c, and by
 * cmds/apply.c apply_print_deploy_preview (the overwrite count).
 */
static inline bool deploy_occupant_present(fs_occupant_t occ) {
    return occ != FS_OCCUPANT_NONE && occ != FS_OCCUPANT_UNKNOWN;
}

/**
 * How a directory verdict converges its row — and the receipt's word for it
 *
 * The verdict's occupant decides the whole of it: nothing stood → created; a
 * directory did → fixed, converged in place, no new entry lands; anything else
 * → replaced, one node cleared and then created. One producer for the mapping
 * deploy_verdict_t documents and deploy_receipt_t's verbs derive from, so the
 * preview, the receipt, apply's record phase and the executor's own poison rule
 * read one answer and cannot drift. Two facts ride on it and are read as it: a
 * new entry lands iff the convergence is not a fix (preflight's landing question,
 * and poisoned_above's "no directory stands"), and dotta made the directory iff
 * the convergence is not a fix (the record phase's ownership gate).
 *
 * Total over fs_occupant_t, so a new occupant is a build error here and not a
 * silent REPLACE. UNKNOWN is answered — preflight asks before it skips such a
 * row (UNREADABLE) — and never reaches a verdict, so no receipt folds it.
 */
typedef enum {
    DEPLOY_CONVERGE_CREATE,   /* Nothing stood at the path */
    DEPLOY_CONVERGE_FIX,      /* A directory stood there — converged in place */
    DEPLOY_CONVERGE_REPLACE   /* A squatter stood there — cleared, then created */
} deploy_convergence_t;

static inline deploy_convergence_t deploy_convergence(fs_occupant_t occ) {
    switch (occ) {
        case FS_OCCUPANT_NONE:      return DEPLOY_CONVERGE_CREATE;
        case FS_OCCUPANT_DIRECTORY: return DEPLOY_CONVERGE_FIX;
        case FS_OCCUPANT_REGULAR:
        case FS_OCCUPANT_SYMLINK:
        case FS_OCCUPANT_OTHER:
        case FS_OCCUPANT_UNKNOWN:   return DEPLOY_CONVERGE_REPLACE;
    }

    CHECK_ARG(false, "an occupant no enumerator names");
}

/**
 * Is this row's content not dotta's to overwrite unasked?
 *
 * The counterpart of occupant_conflicts (deploy.c), answered from the workspace's
 * divergence verdict: content is compared against a blob that is not on disk,
 * so the load-time verdict is the only authority there is — no lstat can improve
 * on it.
 *
 * A TYPE verdict counts, because it means the compare never produced a content
 * verdict at all: whatever stood at the path was never measured against the row.
 * A Git move without CONTENT — STALE, the bytes, or CLAIM_MOVED, a claim — never
 * conflicts: the bytes on disk are the ones dotta confirmed, so the overwrite
 * loses nothing. Mode, ownership and encryption divergence never conflict, whoever
 * moved them: a claim is never an edit (core/workspace.h workspace_item_route,
 * whose STALE arm rests on this).
 *
 * Two readers, two files: the file ladder's consent rung (deploy_preflight),
 * and the forced preview's counterweight (cmds/apply.c apply_print_deploy_preview)
 * — a verdict overwrites local content iff something stands at its path AND this
 * answers yes, so the preview reads it beside deploy_occupant_present. Each hands
 * it the row's item, which every fate carries (deploy_verdict_t).
 *
 * @param item The row's workspace verdict (must not be NULL)
 */
static inline bool deploy_content_conflicts(const workspace_item_t *item) {
    return item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE);
}

/**
 * Why a planned row is not deployed this run
 *
 * The counterpart of cleanup_skip_reason_t, and the same contract: values are
 * listed in precedence order, and the reason is the first that applies, so a
 * row several reasons claim is reported under the one that outranks the rest.
 *
 * Two classes, and the class is the whole of what a consumer needs beyond the
 * label (deploy_skip_needs_force):
 *
 *   consent      dotta could act and did not, because nothing said to —
 *                TYPE, CONTENT. --force lifts them; the run kept its promise,
 *                so they do not reach the exit code.
 *   incapacity   dotta could not act — PERMISSION, FOREIGN, ANCESTOR,
 *                OCCUPIED, UNREADABLE, OWNERSHIP. No flag lifts them (the posture
 *                cleanup takes towards a released file and a directory's
 *                UNVERIFIED); the run planned the row and did not deliver it,
 *                so the exit code says so. Three of them are the invoker's refusals
 *                and root's to lift — PERMISSION, FOREIGN, OWNERSHIP — and a run
 *                that holds none closes its skips by naming it (apply's sudo line);
 *                one that holds root meets neither, save where root itself is
 *                refused (a read-only filesystem, an immutable flag).
 *
 * The split is deploy's exit contract, and workspace_item_route's UNVERIFIABLE
 * arm (workspace.h) restates its incapacity half from the route side — a change
 * here keeps that description true. cleanup_receipt_t draws the same table from
 * its side, with a third column between these two — attempted, and the world
 * moved — where the engines part: deploy's execute-time refusal (EEXIST, EISDIR,
 * ENOTEMPTY) is a failed row, cleanup's a skipped directory, and both headers
 * say why.
 *
 * Precedence. ANCESTOR ranks first: a look taken through a squatted claimed
 * ancestor is void, so no judgment made through it can outrank the fact — the
 * ancestry rung (check_ancestry) asks it before any probe of the row's own, the
 * landing check included, whose access(2) resolves through a squatting symlink
 * and answers for the target's tree. The reason spans both producers: a squatter
 * at a path no row claims is the landing check's find, one at a directory row's
 * is the rung's — and, since the rung's reach is the view's directory rows rather
 * than the walk's, whether it is the rung that answers no longer depends on how
 * the user spelled the add. The two producers stay one reason and one exit
 * contribution; what a consumer may tell apart is the claim that holds the
 * squatter, which the skip carries (deploy_ancestor_class_t) — the remedy differs
 * by claimant where the refusal does not. And why UNREADABLE ranks after every
 * path rung where its siblings (cleanup_skip_reason, workspace_item_route) rank
 * the same fact first: the landing check, when it has something to say, names
 * the ancestry that refused the look — the actionable half of the very same fact.
 * UNREADABLE is what is left when the landing had nothing to say. FOREIGN is
 * the landing's twin for a directory already there: a create or a replace lands
 * a new entry through its parent, which PERMISSION asks, where a fix converges
 * the node in place, which only its owner may do — so a row takes one question
 * or the other, never both, and FOREIGN stands beside PERMISSION. OWNERSHIP ranks
 * last of all, an incapacity behind the consent reasons, because it is the row's
 * rung and not the path's: the ownership is resolved for a row every other rung
 * passed (a skipped row can neither warn nor fail strict_ownership —
 * deploy_preflight's invariant), so the question is never asked of a row another
 * reason already holds, and its place in the order is the place the decision takes.
 *
 * Each reason is a sentence about the row that carries it, read off that skip's
 * own fields (cmds/apply.c apply_print_deploy_skips): the ancestor it names
 * (PERMISSION, ANCESTOR, a TYPE that names one), its own occupant (TYPE, OCCUPIED),
 * its own item (CONTENT, UNREADABLE, and FOREIGN, the owner its look found),
 * its own claim (OWNERSHIP). So a row beneath a skipped squatter takes the
 * squatter's class and never its reason (check_ancestry): the squatter's sentence
 * is about the squatter, whatever reason a later rung adds.
 *
 * Symlink rows need no arm of their own: a foreign kind at a link row's path is
 * TYPE (deploy.c occupant_conflicts), a retargeted link is CONTENT (the target
 * compare), and the undecryptable arm of UNREADABLE cannot fire for one (a link's
 * blob is read raw, never through the content layer).
 */
typedef enum {
    DEPLOY_SKIP_NONE = 0,     /* Not skipped — the row has a verdict */
    DEPLOY_SKIP_ANCESTOR,     /* A non-directory squats an ancestor this run does not converge */
    DEPLOY_SKIP_PERMISSION,   /* The landing refuses: an ancestor not ours, or none reachable */
    DEPLOY_SKIP_FOREIGN,      /* A directory another owns stands at the path: only its owner converges it */
    DEPLOY_SKIP_OCCUPIED,     /* A directory holding untracked paths stands at the path */
    DEPLOY_SKIP_TYPE,         /* A different kind of path stands where the row lands (--force) */
    DEPLOY_SKIP_CONTENT,      /* Disk holds content dotta did not put there (--force) */
    DEPLOY_SKIP_UNREADABLE,   /* The path could not be read: no verdict, no guess */
    DEPLOY_SKIP_OWNERSHIP     /* The claim names a pair this run cannot set (no root held) */
} deploy_skip_reason_t;

/**
 * Is --force the remedy for this skip?
 *
 * The consent/incapacity split, as a value. "Needs force" is the module's own
 * word (CLEARANCE_NEEDS_FORCE) and the screen's ("Use --force to overwrite or
 * replace them"). Two consumers in different places — apply's closing hints and
 * apply's exit contract — so one producer.
 */
static inline bool deploy_skip_needs_force(deploy_skip_reason_t reason) {
    return reason == DEPLOY_SKIP_TYPE || reason == DEPLOY_SKIP_CONTENT;
}

/**
 * The claim standing at the squatted ancestor an ANCESTOR skip names
 *
 * One reason, one exit — but the remedy is the claimant's. A tracked row out of
 * the run's reach is planned by a wider scope, and the squatter is then that
 * row's own TYPE skip to lift (--force). An ancestor claim is never planned, so
 * no scope and no flag helps: the consent-preserving cure is the named
 * re-derivation ('dotta update <dir>'), which drops a claim the disk contradicts
 * and leaves the arrangement the user's. A squatter nothing claims is the landing
 * check's find past the rung: by hand is all there is. A record that alone
 * remembers a directory there is no claim on a planned row at all (the reach
 * rule, core/workspace.h): the rung never names it, the landing check meets what
 * stands there on its own terms, and apply's own cleanup releases the record in
 * the same run — so there is no fourth class.
 *
 * Written where the reason is decided. TRACKED and DERIVED by the ancestry rung
 * (check_ancestry), off the claim the load noted beside the squatter
 * (core/workspace.h workspace_squatted_t) — the claim every path beneath it carries
 * as its displaced class, so the remedy here and status's Displaced paths section
 * cannot name two claimants for one squatter; UNCLAIMED by the landing check
 * (check_landing), the one class it can find. Read by cmds/apply.c
 * apply_print_deploy_skips, whose remedies part on it.
 *
 * The class answers for ANCESTOR, where the reason is one and the cure is not —
 * and only where the skip is the squatter's only report: a squatter this run
 * never reached, or one nothing claims. NONE everywhere else: on every skip whose
 * reason is another, and on a row beneath a squatter this run planned and skipped,
 * which reads ANCESTOR and names it but whose remedy is that squatter's own skip,
 * listed above the row — TRACKED's line, a wider scope, is false of a squatter
 * already in it.
 */
typedef enum {
    DEPLOY_ANCESTOR_NONE = 0,  /* Another reason, or a squatter with a skip of its own */
    DEPLOY_ANCESTOR_TRACKED,   /* A tracked row holds the squatted path */
    DEPLOY_ANCESTOR_DERIVED,   /* An ancestor claim holds it */
    DEPLOY_ANCESTOR_UNCLAIMED  /* Nothing claims it — the landing check's find */
} deploy_ancestor_class_t;

/**
 * One planned row the run does not deploy
 *
 * The shape deploy_verdict_t gives a row the run does deploy: the row's item,
 * and the facts decided about it. `ancestor` is the path the reason names — the
 * ancestor that refused, the non-directory in the way, the squatted directory
 * above the row. Every such path is an ancestor of the row's own, and so a prefix
 * of the item's filesystem_path by construction (check_landing truncates the
 * planned path; a squatted directory stands strictly above every row that names
 * it, and the load lends its length with it — core/workspace.h
 * workspace_squatted_t) — carried as the byte length of that prefix, not a copy.
 * 0 where the reason has no ancestor to name: it is about the planned path itself
 * (OWNERSHIP always is), or (PERMISSION alone) the ancestry could not even be
 * reached to name its refusing node. `ancestor_class` says which claim holds
 * the named path where the skip is the squatter's only report — ANCESTOR's alone,
 * and NONE on a row beneath a skipped squatter (deploy_ancestor_class_t).
 *
 * The item is the verdict's: the one the row's bucket holds, and never NULL
 * (deploy_verdict_t). Whether it holds a look is the row's ancestry's to say,
 * and the item says so itself: a row its ancestry answered for — beneath a squatter
 * that stays, or planned absent and then refused by the row's rung — carries an
 * item nothing looked at, occupant UNKNOWN and no path bit (the displaced class
 * every reader of an item reads, core/workspace.h workspace_displaced_t), never
 * a blanked pointer. So a reader consults the look only where the reason is a
 * sentence about it — a CONTENT skip's route, an UNREADABLE skip's fault, a FOREIGN
 * skip's owner: path rungs, asked only where the ancestry did not answer.
 * OWNERSHIP, the row's rung, reads its claim off the row and never the item's
 * look, which a row planned absent does not have.
 *
 * Nothing here is owned: the item is borrowed (workspace lifetime), as every
 * item and row in this module is.
 */
typedef struct {
    const workspace_item_t *item;           /* Borrowed (workspace lifetime), as the verdict's — never NULL */
    deploy_skip_reason_t reason;
    size_t ancestor;                        /* Prefix length of the named ancestor; 0 = none */
    deploy_ancestor_class_t ancestor_class; /* ANCESTOR only: the claim at a squatter with no skip of its own */
} deploy_skip_t;

/**
 * A skip array with its count — the shape deploy_verdicts_t gives verdicts
 */
typedef struct {
    deploy_skip_t *entries;
    size_t count;
} deploy_skips_t;

/**
 * Preflight: the skips, the anomalies, and the verdicts
 *
 * The verdicts are the *how*, one per row the run WILL deploy, in plan order —
 * directories parents-first, the order deploy_execute converges them in — and
 * then the ancestors: the directory rows outside the plan that the run may make
 * on the way to a planned path — either class, since the plan holds the tracked
 * ones and the ancestors pass is where a derived claim is ever acted on at all
 * (see deploy_preflight). Every array is always allocated, so a consumer reads
 * counts and needs no NULL guard. A value of the arena it was decided in, as
 * every array it holds is: nothing frees one.
 */
typedef struct {
    /* The rows the run does not deploy, both kinds, in decision order — directories
     * parents-first, then files. A squatted directory therefore precedes the
     * rows beneath it. With the verdicts below this is a partition of the plan's
     * pending rows:
     *
     *   files.pending ∪ directories.pending = verdicts(files ∪ directories) ∪
     *       skipped
     *
     * — deploy's own totality equation, the counterpart of cleanup.h's. */
    deploy_skips_t skipped;

    /* Anomalies met while deciding — the run goes on; the caller prints them.
     * Only rows the run will touch contribute: a skipped row's ownership is not
     * resolved, so it can neither warn nor fail strict_ownership. */
    string_array_t warnings;

    /* The how — one per row the run WILL deploy */
    deploy_verdicts_t directories;       /* Pending directory rows, parents first */
    deploy_verdicts_t files;             /* Pending file rows */
    deploy_verdicts_t ancestors;         /* Directory rows the run may make on the way */
} deploy_preflight_t;

/**
 * One kind's partition of the active items in scope
 *
 * Every file item and every tracked directory item that passes the scope's profile
 * and path dimensions lands in exactly one bucket, or nowhere: one that is both
 * clean and excluded enters none (neither work nor apply's to own). Out-of-scope
 * items are invisible, and so is an ancestor claim, which is no convergence of
 * the run's — the plan drops it before scope (deploy_plan_build).
 *
 * Two buckets carry work the run deliberately does not do. They differ by reason,
 * and the reason is the only thing a consumer needs from them — so the bucket
 * an item sits in *is* its reason tag, and a path -e names is reported as excluded
 * even when --skip-existing would also skip it (a named path is the more explicit
 * intent).
 *
 * Buckets hold borrowed item pointers (workspace lifetime — the items are
 * arena-allocated, their addresses stable by construction), and the buckets live
 * in the plan's arena. Project a bucket with workspace_items: its one writer,
 * deploy.c deploy_classify, keeps the element type the projection reads.
 */
typedef struct {
    ptr_array_t pending;    /* Need work — deploy_preflight decides how, deploy_execute acts */
    ptr_array_t clean;      /* In scope, no work — apply's to adopt or acknowledge */
    ptr_array_t excluded;   /* Need work, skipped by -e — reported, never touched */

    /* Need work, skipped by --skip-existing: something already occupies the path.
     * Files only. A tracked directory row writes no data — it creates a container
     * and converges its metadata in place — so skipping one would preserve nothing
     * and would instead strand the tracked children the flag exists to deploy.
     * Its one destructive act, replacing a squatter, is force-gated at preflight
     * already. */
    ptr_array_t skipped_existing;
} deploy_partition_t;

/**
 * Deployment plan — deploy's classification of the active items in scope, one
 * partition per kind. A value of the arena it was built in: nothing frees one.
 *
 * Both kinds' items arrive ordered by filesystem_path (workspace_directories,
 * workspace_files), so a tracked parent precedes its tracked children within
 * directories.pending. Two consumers lean on that: preflight decides a directory
 * row after its ancestors' fates (the ancestry rung reads them), and the execute
 * loop converges a parent before the paths beneath it — which is what lets a
 * replaced directory settle its subtree for the rows that follow (see
 * deploy_preflight, deploy_execute).
 */
typedef struct {
    deploy_partition_t files;         /* workspace_item_t *: the file items */
    deploy_partition_t directories;   /* workspace_item_t *: the tracked directory items */
} deploy_plan_t;

/**
 * One verdict's outcome — the act's stat where it landed, the cause where it
 * did not
 *
 * The stat is the record's own triple (state_stat_from_write), distilled by the
 * executor from the fstat of the descriptor it wrote — taken after the last byte
 * and before the rename that publishes it, so it describes exactly what this
 * run wrote, never what a later look at the path would find. It is what lets
 * apply's record phase anchor a deployment with the write's own stat instead of
 * leaving the record blob-only.
 *
 * UNSET where the act authored no stat — the executor's fact, not a consumer's
 * re-derivation: a symlink is made by path (symlink(2) opens no descriptor to
 * describe, and readlink is its whole re-verification), and a directory's write
 * is fchmod/fchown through its own descriptor, whose record carries no triple
 * at all. The record phase passes the triple blind: an ownership event writes
 * UNSET as no stat (core/workspace.h workspace_anchor).
 *
 * The error is the failed bucket's tail — the row's own cause, verbatim (ENOSPC,
 * a blob that would not load, an ancestor this run did not converge) — and NULL
 * in every landed bucket: the bucket is the tag, as UNSET already is for the
 * stat. A failure has a dozen causes and the remedy differs by cause, so the
 * receipt keeps each for the caller to render, as cleanup's does
 * (cleanup_outcome_t). Borrowed, as every error is (base/error.h).
 *
 * The verdict is borrowed from the preflight, whose arrays are sized once and
 * never reallocated, so every address is stable for the receipt's life — which
 * is no longer than the preflight's (deploy_receipt_t).
 */
typedef struct {
    const deploy_verdict_t *verdict;   /* Borrowed (the preflight's lifetime) */
    state_stat_t stat;                 /* The write's stat; UNSET where it authored none */
    error_t error;                     /* The failed bucket's cause; NULL elsewhere (borrowed) */
} deploy_outcome_t;

/**
 * An outcome array with its count — the shape deploy_verdicts_t gives verdicts
 */
typedef struct {
    deploy_outcome_t *entries;
    size_t count;
} deploy_outcomes_t;

/**
 * Deployment receipt — the run's: one outcome per verdict, in act order
 *
 * Four arrays: three mirroring the preflight's split for the rows that landed,
 * and `failed` for the rows that did not — landed or failed is the one split
 * execute itself takes, so execute buckets it; everything else the receipt restates
 * rather than re-decides. The verb inside a landed array is derived, never stored
 * twice — a directory's is its verdict's occupant (the mapping is
 * deploy_convergence's), so the caller can still say "replaced" where a squatter
 * went and "fixed" where nothing was created. Work the run deliberately did not
 * do is the plan's to report, never the receipt's — the plan decided it, so only
 * the plan can report it before a run that ends up executing nothing. A failure
 * is a row's own outcome: it lands in `failed` with its cause, the run goes on,
 * and the caller's exit contract reads the count; the returned error is reserved
 * for the run's infrastructure (deploy_execute).
 *
 * With `failed` the receipt partitions the promise — execute's totality equation,
 * the mirror of preflight's:
 *
 *   verdicts(directories ∪ files) = converged ∪ deployed ∪ failed
 *
 * — every promised row accounted for, however the rows fared. The ancestors stay
 * outside it, as they stand outside the plan.
 *
 * Each landed array is sized to its verdict array at entry (calloc), `failed`
 * to both kinds together (every promised row could fail), and all fill in verdict
 * order; count gates every read, so an untaken slot is invisible and the receipt
 * holds exactly what happened, by construction.
 *
 * The derived verb is also the ownership gate apply's record phase reads: a
 * converged directory whose convergence is not a fix was made by dotta and anchors
 * as owned; one converged in place was not — anchoring it would set deployed_at
 * on a directory the user made, and hand it to the prune on the next scope exit.
 *
 * `ancestors` is outside the plan: the claimed directories the run made as parents
 * of a planned path (create_ancestor), each once, either class. They carry their
 * recorded mode and ownership like any other directory row, and dotta made them
 * — so the record phase anchors them as owned, the same event as a created
 * directory — but the plan never named them and the preview never counted them,
 * so the caller's summary keeps them apart from the created count. A parent no
 * row claims has no receipt and no record.
 *
 * A value of the arena its run was handed, as its four arrays are: nothing frees
 * one. Its outcomes borrow the verdicts, so a receipt lives in the arena they
 * were decided in, or in one they outlive.
 */
typedef struct {
    deploy_outcomes_t deployed;      /* Files written or linked, each with its write's stat */
    deploy_outcomes_t converged;     /* Planned directories — the verb is the verdict's occupant */
    deploy_outcomes_t ancestors;     /* Claimed directories made on the way, each once */
    deploy_outcomes_t failed;        /* Rows that did not land — both kinds, each with its cause */
} deploy_receipt_t;

/**
 * Build the deployment plan
 *
 * Walks the workspace's directory items and file items once — a directory only
 * where its profile tracks it, an ancestor claim being no convergence of the
 * run's — gating each on scope_accepts_profile ∧ scope_accepts_path(kind), then
 * classifying it by deploy's work predicate (missing, or diverged in content /
 * mode / ownership / type / stale) and by the reasons its work is skipped:
 * scope_is_excluded(kind), then skip_existing. Every item was analyzed — neither
 * kind is a load's to decline (workspace_load) — so a clean one is a path the
 * load looked at and found agreeing.
 *
 * A path beneath a squatted directory needs no rule of the plan's own: the
 * workspace looked at nothing there, so the row's item carries the displaced
 * class and no path bit (core/workspace.h workspace_displaced_t), and the work
 * predicate reads that class first (deploy_needs_work). Such a row is work, and
 * not occupied for --skip-existing's purpose; -e still excludes it. What becomes
 * of it is preflight's alone, asked of this run's own fates rather than guessed
 * from scope: the directory pass converges the ancestor and the row is written
 * fresh beneath it, or the pass does not and the row is skipped with it, in the
 * ancestor's class (check_ancestry, deploy_preflight). Scope still bounds the
 * plan in the ordinary way — a row scope rejects (-p, a path filter) is not planned
 * on its ancestor's account, Coherent Scope, and converges on the next apply
 * that covers it.
 *
 * @param arena Arena the plan and its buckets live in (must not be NULL)
 * @param ws Workspace with divergence analysis (must not be NULL)
 * @param scope Operation scope (must not be NULL; read at plan time alone —
 *        everything else a fate carries is workspace vocabulary)
 * @param skip_existing --skip-existing: a file row whose path is already occupied
 *        is not work. A plan fact, not an execution one — the occupancy comes
 *        from the workspace's own lstat, so preflight, the prompt and the executor
 *        all see one answer. Not overridden by --force: --force also overrides
 *        cleanup's skip reasons and the confirmation prompt, so the combination
 *        is meaningful and the narrower flag keeps its promise.
 * @return The plan
 */
deploy_plan_t *deploy_plan_build(
    arena_t *arena,
    const workspace_t *ws,
    const scope_t *scope,
    bool skip_existing
);

/**
 * True when the plan carries no work of either kind.
 */
static inline bool deploy_plan_is_empty(const deploy_plan_t *plan) {
    return plan->files.pending.count == 0 && plan->directories.pending.count == 0;
}

/**
 * How many items the plan classified — both kinds, every bucket
 *
 * Distinct from deploy_plan_is_empty, which counts only *work*: a plan of nothing
 * but clean items is empty there and non-zero here. Apply reads this to tell a
 * path filter that named nothing dotta manages from one whose paths are all
 * converged or skipped already.
 *
 * The bucket set lives here so a consumer never has to enumerate it. An item
 * that is both clean and excluded lands in no bucket at all, nor does an ancestor
 * claim (see deploy_partition_t), so a scope of only such items counts zero.
 */
static inline size_t deploy_plan_item_count(const deploy_plan_t *plan) {
    const deploy_partition_t *kinds[] = { &plan->files, &plan->directories };
    size_t total = 0;

    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        const deploy_partition_t *part = kinds[i];

        total += part->pending.count;
        total += part->clean.count;
        total += part->excluded.count;
        total += part->skipped_existing.count;
    }
    return total;
}

/**
 * Decide the fate of every planned row: a verdict, or a skip
 *
 * Decided in the order the run acts — the directory rows parents-first, then
 * the files, then the ancestors — so every fate is decided after the fates of
 * whatever the run reaches before it: a file's tracked ancestors are directory
 * rows, converged before anything is written beneath them. The skips and the
 * warnings come out in that order too.
 *
 * One fate per pending row (the totality equation, deploy_preflight_t), each
 * question asked of its one authority, the first skip reason that applies winning
 * (deploy_skip_reason_t):
 * - Ancestry — the look must bind. A squatted directory row above the path
 *   (workspace_squatted_ancestor) voids every probe taken beneath it, the landing
 *   check's included — the workspace took none there at all, so the row arrives
 *   with nothing measured — so this rung runs first and answers from the run's
 *   own fates (check_ancestry): an ancestor the directory pass converges first
 *   means the row is planned absent and asked nothing else; one the pass skips
 *   means the row takes that skip's class, ancestor named; one the run never
 *   acts on (scope, -p, -e, an ancestor claim) is ANCESTOR — an incapacity, and
 *   the remedy is a run that reaches it, or, for a claim the run cannot reach
 *   at all because nothing plans it, a re-derivation of the chain.
 * - Landing — the write must be able to land. Every arm of the executor writes
 *   through the *parent* — a temp file renamed over the target, a symlink unlinked
 *   and re-made, a mkdir — so the path's own permissions are never the question,
 *   and a directory being converged in place asks nothing at all. The question
 *   goes to the nearest present ancestor alone: everything absent beneath it is
 *   created by this run at a working mode and cannot refuse. A deployable or
 *   holdable claimed directory there is dotta's and never refuses; any other
 *   directory must accept a new entry now (access(2)) or the row is skipped
 *   (PERMISSION); a non-directory squatter at a path no row claims skips it too
 *   (ANCESTOR — the claimed ones were the ancestry rung's). Ancestors are not
 *   items, so this is the one fresh probe preflight takes; the mechanism
 *   (ensure_parents) asks the same questions of the same ancestor, so this predicts
 *   the run rather than modelling it.
 * - Type — the occupant the workspace's look found at the planned path, both
 *   kinds (workspace_item_t.occupant; a row planned beneath a squatter this run
 *   replaces is absent, and asked nothing). A different kind at the path — a
 *   non-directory where a directory belongs, the reverse, or a file row's other
 *   kind — is skipped unless --force (TYPE), save a file row's occupant the
 *   workspace proved is dotta's own copy with only its kind moved by Git (STALE):
 *   that one is replaced unasked, as a STALE row's bytes are overwritten. A
 *   directory holding untracked paths is skipped either way (OCCUPIED), because
 *   deploy removes single nodes and never a tree. A row the workspace could not
 *   settle (DIVERGENCE_UNVERIFIED — an unexaminable occupant, or a look at its
 *   content that failed) is skipped as UNREADABLE when the landing had nothing
 *   to say: no verdict can say what the run will find there.
 * - Content — the workspace's divergence verdict, the only authority for a fact
 *   no lstat can settle. Skipped unless --force (CONTENT; STALE without CONTENT
 *   never skips: disk still holds the blob dotta deployed, so the overwrite loses
 *   nothing); mode, ownership and encryption divergence never skip.
 * - Ownership — the row's rung, last, asked of a row every path rung passed and
 *   the one rung a row planned absent takes: the pair the write applies
 *   (resolve_deployment_ownership: the row's claim resolved on this host, half
 *   by half — the invoker's own owner where it names none, no group where it
 *   names none, on every run, core/metadata.h metadata_ownership), and whether
 *   this run may set it (identity_may_chown) — a pair that is not the invoker's
 *   to set is skipped (OWNERSHIP), the incapacity sudo lifts. The mode the write
 *   applies is the row's, total by build, and is not decided here. Under
 *   strict_ownership an owner or group this system does not know is an error,
 *   returned here — before the prompt, never mid-run; otherwise it is a warning
 *   and no change. A skipped row is not consulted, so it can neither warn nor
 *   fail strict_ownership.
 *
 * Then the ancestors: every directory row the plan does not act on — an ancestor
 * claim, which the plan never holds, or a tracked row out of scope or skipped —
 * absent as the plan reads it (the workspace's occupant, or beneath a squatter
 * this run replaces) and standing above a *deployable* row. ensure_parents creates
 * exactly these on the way to a planned path (the parents beside them that no
 * row claims carry no metadata to decide), so their metadata is decided here
 * like any other row's, and a warning or a strict_ownership error about one is
 * met before the prompt like any other. This pass is why the plan has no ancestors
 * partition of its own: whether such a row is created turns on facts only preflight
 * holds — that the path is absent, and that something deployable stands beneath it.
 *
 * The deployable gate rests on an invariant the ladders establish rather than
 * check: beneath a squatter this run does not converge, every planned row is
 * skipped. Where the squatter stands at a skipped pending row, in that skip's
 * class, whatever its reason — the rung reads the ancestor's own fate; where it
 * stands at an ancestor outside the run's reach, by ANCESTOR; where a skipped
 * chain is absent instead, by the row's own landing check — presence is monotone
 * up a path, so every planned row beneath meets the same refusing ancestor (an
 * unreadable one leaves its descendants' probes to fail the same way). So the
 * ancestors loop can never plan a parent for a subtree the run skips.
 *
 * Only rows the run will touch are consulted — the deployable ones, and the
 * ancestors it will make; a directory the run leaves alone cannot skip anything.
 * A planned row beneath a squatted ancestor this run converges (deploy_plan_build
 * routed it; the rung confirms it against the fates) is asked nothing: the path
 * is empty once the directory pass has replaced the squatter, and its landing
 * is that ancestor's — whose own row carries the conflict --force resolves, and
 * the landing question. Its verdict carries that absence; when the ancestor's
 * row is skipped instead, the row takes that skip's class, ancestor named (the
 * plan's premise — "the squatter is gone first" — holds row by row, never on
 * average).
 *
 * Runs as the invoker, the identity every write is made as (sys/identity), and
 * asks for no other: a landing the invoker cannot write is PERMISSION, a pair
 * it cannot set is OWNERSHIP — a row is OWNERSHIP-skipped iff its resolved pair
 * is not the invoker's to set and the run holds no root — and a run that holds
 * root meets neither refusal, since the executors land the row through the
 * syscall's second try (sys/filesystem) and root sets any pair. The ancestors
 * are not asked the ownership rung (a foreign-owned derived claim above a landing
 * the invoker can write meets the refusal at the create, and the row beneath
 * carries it as its outcome).
 *
 * READ-ONLY: modifies neither the filesystem, the state database nor Git.
 *
 * @param ws Workspace with pre-loaded divergence analysis (must not be NULL)
 * @param plan Deployment plan (must not be NULL)
 * @param opts Deployment options (must not be NULL)
 * @param arena Arena the preflight and every array it holds live in (must not
 *        be NULL)
 * @param out The preflight (must not be NULL; left as it was on a failure)
 * @return Error or NULL on success (a skip is not an error; a strict_ownership
 *         failure is)
 */
error_t deploy_preflight(
    const workspace_t *ws,
    const deploy_plan_t *plan,
    const deploy_options_t *opts,
    arena_t *arena,
    deploy_preflight_t **out
);

/**
 * Carry the verdicts out
 *
 * Directories first (a planned directory may be the parent of a planned file,
 * and under --force a squatting symlink must be gone before a file is written
 * beneath it), then files, each in verdict order. Every verdict is acted on;
 * nothing outside them is *fixed*, and nothing is re-decided: what the verdict
 * says stands at the path is what the executor clears or converges, and a path
 * the world has moved under since preflight meets the mechanism's refusal rather
 * than a fresh judgment. Whatever a planned path's occupant was, clearing it
 * removes exactly one node.
 *
 * Missing parents are the mechanics of landing a planned path, created top-down
 * as part of its write: a directory the view claims (any profile, in scope or
 * not, either class) with the mode and ownership its ancestor verdict carries,
 * anything else with the word no claim makes, DIR_MODE_DEFAULT and the invoker's
 * own owner — what a claimless row gets, so a directory a raised mkdir made is
 * handed back like the leaf beneath it, and no owner is borrowed from below.
 * Creation is all this pass may do: a parent the world made present after the
 * probe meets ERR_EXISTS rather than a convergence (fs_create_dir_exclusive),
 * since whatever now stands there is not this run's to fix. The claimed ones
 * land in the receipt's ancestors; the ones no row names are never reported. A
 * claimed parent the verdicts did not foresee — present at preflight, gone by
 * the time the run reaches it — is made like an unclaimed one, and the next load
 * reads whatever it has to say about its mode.
 *
 * Directories are materialized in two phases. Every directory the run creates
 * or converges carries its recorded mode with the owner triad forced on while
 * the run writes beneath it; a claimed, owned directory that already stands where
 * a planned path must land and refuses it is opened the same way, whichever class
 * it is — a claim's mode was captured with the very children it would refuse.
 * When the run is over — however the rows fared — each such directory is released
 * to its exact mode, deepest-first: recorded for the ones the plan materialized,
 * the mode it had for the ones merely opened. Group and other bits are never
 * widened. This is the one transient the run leaves during its life and none
 * afterwards; it is what lets a 0555 directory captured with children be redeployed
 * with them, and what makes the landing check a question about directories no
 * row claims.
 *
 * Individual row failures are non-fatal: the row lands in the receipt's failed
 * bucket with its cause and the run goes on — except that a failed directory
 * left without a standing directory poisons its subtree (poisoned_above, the
 * preflight invariant's execution mirror): every later verdict beneath it fails
 * against the ancestor without being attempted, since a write there would land
 * through whatever still squats the path. A failed converge-in-place poisons
 * nothing — the directory stands, and children land in it or fail on their own
 * merits.
 *
 * The returned error is the run's infrastructure alone: the release of held modes
 * failed, and *out holds the complete receipt beside it — every row ran, and
 * what landed is the record's to keep. The held directories are released on every
 * exit.
 *
 * View rows are self-contained (blob_oid, type, storage path); the content cache
 * handles encryption transparently. The record (path_records, observations) is
 * the caller's to write, after deployment succeeds.
 *
 * @param repo Repository (must not be NULL)
 * @param ws Workspace the plan was built from (must not be NULL; the
 *        claimed-ancestor lookup for a landing directory the run may hold)
 * @param verdicts The verdicts to carry out — deployable rows only, by
 *        construction: the skips never enter these arrays (must not be NULL)
 * @param cache Content cache for batch operations (must not be NULL)
 * @param arena Arena the receipt, its arrays and the run's held directories live
 *        in (must not be NULL; the verdicts' own, or one they outlive)
 * @param out The receipt, the arena's — set beside a release error too (must
 *        not be NULL)
 * @return Error or NULL on success
 */
error_t deploy_execute(
    git_repository *repo,
    const workspace_t *ws,
    const deploy_preflight_t *verdicts,
    content_cache_t *cache,
    arena_t *arena,
    deploy_receipt_t **out
);

#endif /* DOTTA_DEPLOY_H */
