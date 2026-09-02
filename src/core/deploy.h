/**
 * deploy.h - File and directory deployment engine
 *
 * Plan / preflight / execute, in that order:
 *
 *   deploy_plan_build   — decide *what* from (workspace, scope), once
 *   deploy_preflight    — decide the fate of every planned row, from the
 *                         workspace's observation and the row: a verdict (how
 *                         it is materialized) or a skip (why it is not)
 *   deploy_execute      — carry the verdicts out; decides nothing
 *
 * Preview, privilege check, prompt, reporting and apply's record step all read
 * the one plan and the one set of verdicts; execution applies no filter and takes
 * no decision of its own. Same shape as core/cleanup.
 *
 * Design principles:
 * - Every decision is taken at preflight, before anything changes, from the
 *   occupant the workspace observed (workspace_item_t.occupant) and the row —
 *   one fate per planned row, a verdict or an explicit skip. A confirmation prompt
 *   may sit between preflight and execute; nothing re-observes across it, and
 *   nothing pretends to: the mechanisms refuse what a verdict no longer describes
 *   (O_NOFOLLOW, EISDIR, EEXIST, ENOTEMPTY) and the refusal is that row's outcome,
 *   not the run's end. The same stance as core/cleanup
 * - One element type per phase: the plan buckets borrowed rows and authors nothing;
 *   preflight authors the fates — a verdict or a skip, carrying everything decided
 *   about the row; execute authors the outcomes — one per verdict, landed or
 *   failed, the one split execute itself takes. A verb inside a landed bucket
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
 * - Silent: outcomes travel in the result — a row's failure among them, its cause
 *   on the outcome — verdicts and skips in the preflight result, with the anomalies
 *   met while deciding (an identity that could not be resolved), which are the
 *   caller's to print; only the run's infrastructure travels in the returned
 *   error. This module emits no prose of its own; verbosity and tense are the
 *   caller's, the same convention as every other core module
 */

#ifndef DOTTA_DEPLOY_H
#define DOTTA_DEPLOY_H

#include <git2.h>
#include <types.h>

#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "sys/filesystem.h"

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
 * Everything a consumer needs and nothing it has to go and get: the row, its
 * analysis, what stands at its path, and the metadata the write applies. The
 * occupant is the workspace's lstat, never a fresh one — or FS_OCCUPANT_NONE
 * for a row planned beneath a squatter this run replaces first (deploy_plan_build),
 * whose own observation went through the squatter and describes a tree the run
 * dismantles. The occupant is also the receipt's verb for a directory: NONE →
 * created, DIRECTORY → fixed, anything else → replaced (deploy_convergence).
 *
 * The item is the index's answer, looked up once where the fate is decided and
 * filled verbatim on every arm — the planned-absent arms included. An item's
 * join facts (row, anchor, profile) are sound on every verdict; its observation
 * may speak for the squatter's target, which is why the fate's own occupant says
 * what the run will find. What a fate declines to consult it declines at the
 * reader, never by blanking the pointer. NULL only where the index holds nothing
 * — a clean row planned beneath a replaced squatter has no divergence to index.
 *
 * The decided facts are exactly the ones not on the row: the occupant, and the
 * resolved ownership (resolve_deployment_ownership; (uid_t) -1 / (gid_t) -1 is
 * no change). The mode the write applies is the row's, read there — total for
 * every kind that carries one (resolve_metadata carries the rationale).
 */
typedef struct {
    const manifest_row_t *row;       /* Borrowed (workspace lifetime) */
    const workspace_item_t *item;    /* The analysis object, or NULL — looked up once */
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
 * reading, for judgments — one producer, read by the ladders and the preview.
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
 * deploy_verdict_t documents and deploy_result_t's verbs derive from, so the
 * preview, the receipt, apply's record step and the executor's own poison rule
 * read one answer and cannot drift. Two facts ride on it and are read as it: a
 * new entry lands iff the convergence is not a fix (preflight's landing question,
 * and poisoned_above's "no directory stands"), and dotta made the directory iff
 * the convergence is not a fix (the record step's ownership gate).
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

    /* Unreachable once every enum value is handled */
    return DEPLOY_CONVERGE_REPLACE;
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
 * DIVERGENCE_STALE without CONTENT never conflicts: the bytes on disk are the
 * ones dotta itself deployed, so the overwrite loses nothing. Mode, ownership
 * and encryption divergence never conflict.
 *
 * Two readers, two files: the file ladder's consent rung, and the forced preview's
 * counterweight — a verdict overwrites local content iff something stands at
 * its path AND this answers yes, so the preview reads it beside
 * deploy_occupant_present.
 *
 * @param item Workspace verdict for the row (NULL = not in the index)
 */
static inline bool deploy_content_conflicts(const workspace_item_t *item) {
    return item != NULL &&
           (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE));
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
 *   incapacity   dotta could not act — PERMISSION, ANCESTOR, OCCUPIED,
 *                UNREADABLE. No flag lifts them (the posture cleanup takes towards
 *                a released file and a directory's UNVERIFIED); the run planned
 *                the row and did not deliver it, so the exit code says so.
 *
 * The split is deploy's exit contract, and workspace_item_route's UNVERIFIABLE
 * arm (workspace.h) restates its incapacity half from the route side — a change
 * here keeps that description true. cleanup_result_t draws the same table from
 * its side, with a third column between these two — attempted, and the world
 * moved — where the engines part: deploy's execute-time refusal (EEXIST, EISDIR,
 * ENOTEMPTY) is a failed row, cleanup's a skipped directory, and both headers
 * say why.
 *
 * Precedence. ANCESTOR ranks first: an observation taken through a displaced
 * claimed ancestor is void, so no judgment made through it can outrank the fact
 * — the ancestry rung (check_ancestry) asks it before any probe of the row's
 * own, the landing check included, whose access(2) resolves through a squatting
 * symlink and answers for the target's tree. The reason spans both producers: a
 * squatter at a path no row claims is the landing check's find, one at a directory
 * row's is the rung's — and, since the rung's reach is the view's directory rows
 * rather than the walk's, whether it is the rung that answers no longer depends
 * on how the user spelled the add. The two producers stay one reason and one
 * exit contribution; what a consumer may tell apart is the claim that holds the
 * squatter, which the skip carries (deploy_ancestor_class_t) — the remedy differs
 * by claimant where the refusal does not. And why UNREADABLE ranks last where
 * its siblings (cleanup_skip_reason, workspace_item_route) rank the same fact
 * first: the landing check, when it has something to say, names the ancestry
 * that refused the look — the actionable half of the very same fact. UNREADABLE
 * is what is left when the landing had nothing to say.
 *
 * Symlink rows need no arm of their own: a foreign kind at a link row's path is
 * TYPE (file_row_occupant), a retargeted link is CONTENT (the target compare),
 * and the undecryptable arm of UNREADABLE cannot fire for one (a link's blob is
 * read raw, never through the content layer).
 */
typedef enum {
    DEPLOY_SKIP_NONE = 0,     /* Not skipped — the row has a verdict */
    DEPLOY_SKIP_ANCESTOR,     /* A non-directory squats an ancestor this run does not converge */
    DEPLOY_SKIP_PERMISSION,   /* The landing refuses: an ancestor not ours, or none reachable */
    DEPLOY_SKIP_OCCUPIED,     /* A directory holding untracked paths stands at the path */
    DEPLOY_SKIP_TYPE,         /* A different kind of path stands where the row lands (--force) */
    DEPLOY_SKIP_CONTENT,      /* Disk holds content dotta did not put there (--force) */
    DEPLOY_SKIP_UNREADABLE    /* The path could not be read: no verdict, no guess */
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
 * NONE on every skip whose reason names no squatted ancestor — the class answers
 * for ANCESTOR alone, where the reason is one and the cure is not.
 */
typedef enum {
    DEPLOY_ANCESTOR_NONE = 0,  /* The reason names no squatted ancestor */
    DEPLOY_ANCESTOR_TRACKED,   /* A tracked row holds the squatted path */
    DEPLOY_ANCESTOR_DERIVED,   /* An ancestor claim holds it */
    DEPLOY_ANCESTOR_UNCLAIMED  /* Nothing claims it — the landing check's find */
} deploy_ancestor_class_t;

/**
 * One planned row the run does not deploy
 *
 * The shape deploy_verdict_t gives a row the run does deploy: the row, its
 * analysis, and the facts decided about it. `ancestor` is the path the reason
 * names — the ancestor that refused, the non-directory in the way, the squatted
 * directory row above an inheriting row. Every such path is an ancestor of the
 * row's own, and so a prefix of filesystem_path by construction (check_landing
 * truncates the planned path; an inheriting row's squatter stands strictly above
 * it) — carried as the byte length of that prefix, not a copy. 0 where the reason
 * has no ancestor to name: it is about the planned path itself, or (PERMISSION
 * alone) the ancestry could not even be reached to name its refusing node.
 * `ancestor_class` says which claim holds the named path — ANCESTOR's alone
 * (deploy_ancestor_class_t), NONE wherever the reason is another.
 *
 * The item is the verdict's rule with the one inversion a skip forces: a
 * self-judged skip carries its analysis object (a CONTENT skip carries one by
 * construction — content_conflicts(NULL) is false), while a row judged by its
 * ancestry carries NULL. Its own item describes the squatter's target, and a
 * walker must not mistake an inheriting row for the squatter itself; a skip has
 * no occupant field to express that refusal, so here NULL is the override.
 *
 * Nothing here is owned: the row is borrowed (workspace lifetime), as every row
 * in this module is.
 */
typedef struct {
    const manifest_row_t *row;              /* Borrowed (workspace lifetime) */
    const workspace_item_t *item;           /* As the verdict's; NULL for a row judged by its ancestry */
    deploy_skip_reason_t reason;
    size_t ancestor;                        /* Prefix length of the named ancestor; 0 = none */
    deploy_ancestor_class_t ancestor_class; /* ANCESTOR only: the claim at the named path */
} deploy_skip_t;

/**
 * A skip array with its count — the shape deploy_verdicts_t gives verdicts
 */
typedef struct {
    deploy_skip_t *entries;
    size_t count;
} deploy_skips_t;

/**
 * Pre-flight results: the skips, the anomalies, and the verdicts
 *
 * The verdicts are the *how*, one per row the run WILL deploy, in plan order —
 * directories parents-first, the order deploy_execute converges them in — and
 * then the ancestors: the directory rows outside the plan that the run may make
 * on the way to a planned path — either class, since the plan holds the tracked
 * ones and the ancestors pass is where a derived claim is ever acted on at all
 * (see deploy_preflight). Every array is always allocated, so a consumer reads
 * counts and needs no NULL guard.
 */
typedef struct {
    /* The rows the run does not deploy, both kinds, in decision order — directories
     * parents-first, then files. A squatted directory therefore precedes the
     * rows it holds back. With the verdicts below this is a partition of the
     * plan's pending rows:
     *
     *   files.pending ∪ directories.pending = verdicts(files ∪ directories) ∪
     *       skipped
     *
     * — deploy's own totality equation, the counterpart of cleanup.h's. */
    deploy_skips_t skipped;

    /* Anomalies met while deciding — the run goes on; the caller prints them.
     * Only rows the run will touch contribute: a skipped row's ownership is not
     * resolved, so it can neither warn nor fail strict_ownership. */
    string_array_t *warnings;

    /* The how — one per row the run WILL deploy */
    deploy_verdicts_t directories;       /* Pending directory rows, parents first */
    deploy_verdicts_t files;             /* Pending file rows */
    deploy_verdicts_t ancestors;         /* Directory rows the run may make on the way */
} deploy_preflight_result_t;

/**
 * One kind's partition of the in-scope active set
 *
 * Every active row that passes the scope's profile and path dimensions lands in
 * exactly one bucket, or nowhere: a row that is both clean and excluded enters
 * none (neither work nor adoptable). Out-of-scope rows are invisible.
 *
 * Two buckets carry work the run deliberately does not do. They differ by reason,
 * and the reason is the only thing a consumer needs from them — so the bucket a
 * row sits in *is* its reason tag, and a row -e names is reported as excluded
 * even when --skip-existing would also skip it (a named path is the more explicit
 * intent).
 *
 * Buckets hold borrowed row pointers into the workspace's arena snapshot (workspace
 * lifetime); the plan owns only the bucket buffers. Project a bucket with
 * manifest_rows_view.
 */
typedef struct {
    ptr_array_t pending;    /* Need work — deploy_preflight decides how, deploy_execute acts */
    ptr_array_t clean;      /* In scope, no work — adoption candidates */
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
 * Deployment plan — deploy's classification of the in-scope active set, one
 * partition per kind. Free with deploy_plan_free BEFORE workspace_free (the same
 * ordering rule scope.h documents for scope_free).
 *
 * Both of the workspace's slices arrive ordered by filesystem_path, so a tracked
 * parent precedes its tracked children within directories.pending. Two consumers
 * lean on that: preflight decides a directory row after its ancestors' fates
 * (the ancestry rung reads them), and the execute loop converges a parent before
 * the paths beneath it — which is what lets a replaced directory settle its subtree
 * for the rows that follow (see deploy_preflight, deploy_execute).
 */
typedef struct {
    deploy_partition_t files;         /* manifest_row_t * (blob types) */
    deploy_partition_t directories;   /* manifest_row_t * (PATH_TYPE_DIRECTORY) */
} deploy_plan_t;

/**
 * One verdict's outcome — the act's proof where it landed, the cause where it
 * did not
 *
 * The stat is the record's own triple (stat_cache_from_write), distilled by the
 * executor from the fstat of the descriptor it wrote — taken after the last byte
 * and before the rename that publishes it, so it describes exactly what this
 * run wrote, never what a later look at the path would find. It is what lets
 * apply's record step anchor a deployment with the write's own proof instead of
 * leaving the record blob-only.
 *
 * UNSET where the act authored no proof — the executor's fact, not a consumer's
 * re-derivation: a symlink is made by path (symlink(2) opens no descriptor to
 * describe, and readlink is its whole re-verification), and a directory's write
 * is fchmod/fchown through its own descriptor, whose record carries no triple
 * at all. UNSET and NULL say the same thing to state_anchor, so the record step
 * passes the triple blind.
 *
 * The error is the failed bucket's tail — the row's own cause, verbatim (ENOSPC,
 * a blob that would not load, an ancestor this run did not converge) — and NULL
 * in every landed bucket: the bucket is the tag, as UNSET already is for the
 * stat. A failure has a dozen causes and the remedy differs by cause, so the
 * receipt keeps each for the caller to render, as cleanup's does
 * (cleanup_outcome_t). Owned by the receipt; deploy_result_free frees it.
 *
 * The verdict is borrowed from the preflight result, whose arrays are sized once
 * and never reallocated, so every address is stable for the receipt's life. Free
 * the result before the preflight result.
 */
typedef struct {
    const deploy_verdict_t *verdict;    /* Borrowed (preflight-result lifetime) */
    stat_cache_t stat;                  /* The act's proof; UNSET where it authored none */
    error_t *error;                     /* The failed bucket's cause; NULL elsewhere (owned) */
} deploy_outcome_t;

/**
 * An outcome array with its count — the shape deploy_verdicts_t gives verdicts
 */
typedef struct {
    deploy_outcome_t *entries;
    size_t count;
} deploy_outcomes_t;

/**
 * Deployment result — the run's receipt: one outcome per verdict, in act order
 *
 * Four arrays: three mirroring the preflight's split for the rows that landed,
 * and `failed` for the rows that did not — landed or failed is the one split
 * execute itself takes, so execute buckets it; everything else the receipt restates
 * rather than re-decides. The verb inside a landed array is derived, never stored
 * twice — a directory's is its verdict's occupant (the mapping is
 * deploy_convergence's), so the caller can still say "replaced" where a squatter
 * went and "fixed" where nothing was created. Work the run deliberately did not
 * do is the plan's to report, never the result's — the plan decided it, so only
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
 * Each landed array is sized to its verdict array at entry (calloc, count + 1),
 * `failed` to both kinds together (every promised row could fail), and all fill
 * in verdict order; count gates every read, so an untaken slot is invisible and
 * the receipt holds exactly what happened, by construction.
 *
 * The derived verb is also the ownership gate apply's record step reads: a
 * converged directory whose convergence is not a fix was made by dotta and anchors
 * as owned; one converged in place was not — anchoring it would set deployed_at
 * on a directory the user made, and hand it to the prune on the next scope exit.
 *
 * `ancestors` is outside the plan: the claimed directories the run made as parents
 * of a planned path (create_ancestor), each once, either class. They carry their
 * recorded mode and ownership like any other directory row, and dotta made them
 * — so the record step anchors them as owned, the same event as a created directory
 * — but the plan never named them and the preview never counted them, so the
 * caller's summary keeps them apart from the created count. A parent no row claims
 * has no receipt and no record.
 *
 * Free with deploy_result_free, before deploy_preflight_result_free and before
 * workspace_free — the outcomes borrow the verdicts, the verdicts the rows.
 */
typedef struct {
    deploy_outcomes_t deployed;      /* Files written or linked, each with its write's proof */
    deploy_outcomes_t converged;     /* Planned directories — the verb is the verdict's occupant */
    deploy_outcomes_t ancestors;     /* Claimed directories made on the way, each once */
    deploy_outcomes_t failed;        /* Rows that did not land — both kinds, each with its cause */
} deploy_result_t;

/**
 * Build the deployment plan
 *
 * Walks the workspace's active file and directory slices once, gating each row
 * on scope_accepts_profile ∧ scope_accepts_path(kind), then classifying it by
 * deploy's work predicate (missing, or diverged in content / mode / ownership /
 * type / encryption / stale) and by the reasons a row's work is skipped:
 * scope_is_excluded(kind), then skip_existing.
 *
 * Requires a workspace loaded with file AND directory analysis: the plan is derived
 * from the divergence index, and a kind whose analysis did not run plans as clean.
 *
 * One verdict the plan overrules: a path beneath a displaced directory row this
 * scope converges (beneath_squatted_directory — the workspace's displaced fact,
 * gated on the ancestor's row being tracked and in reach) is planned as absent,
 * whatever the index says of it. Everything the workspace observed beneath that
 * ancestor it observed through the squatter — a symlink to a directory answers
 * for the link's target, so a child there reads clean — and the directory pass
 * replaces the squatter before anything beneath it is touched. Such a row is
 * work, and not occupied for --skip-existing's purpose; -e still holds it back.
 * Only an ancestor this scope reaches counts (one -e skips is not replaced this
 * run), and only an in-scope descendant is reached: a row scope itself rejects
 * (-p, a path filter) is not planned on its ancestor's account — Coherent Scope
 * — and converges on the next apply that covers it. Preflight asks the same premise
 * of the fates and carries the answer as the row's verdict or its inherited skip
 * (deploy_preflight).
 *
 * @param ws Workspace with divergence analysis (must not be NULL)
 * @param scope Operation scope (must not be NULL; read at plan time alone —
 *        everything else a fate carries is workspace vocabulary)
 * @param skip_existing --skip-existing: a file row whose path is already occupied
 *        is not work. A plan fact, not an execution one — the occupancy comes
 *        from the workspace's own lstat, so preflight, the privilege scan, the
 *        prompt and the executor all see one answer. Not overridden by --force:
 *        --force also overrides cleanup's skip reasons and the confirmation prompt,
 *        so the combination is meaningful and the narrower flag keeps its promise.
 * @param out Plan (must not be NULL; caller frees with deploy_plan_free)
 * @return Error or NULL on success
 */
error_t *deploy_plan_build(
    const workspace_t *ws,
    const scope_t *scope,
    bool skip_existing,
    deploy_plan_t **out
);

/**
 * Free a plan. No-op on NULL. Call before workspace_free.
 */
void deploy_plan_free(deploy_plan_t *plan);

/**
 * True when the plan carries no work of either kind.
 */
static inline bool deploy_plan_is_empty(const deploy_plan_t *plan) {
    return plan->files.pending.count == 0 && plan->directories.pending.count == 0;
}

/**
 * How many rows the plan classified — both kinds, every bucket
 *
 * Distinct from deploy_plan_is_empty, which counts only *work*: a plan of nothing
 * but clean rows is empty there and non-zero here. Apply reads this to tell a
 * path filter that named nothing dotta manages from one whose paths are all
 * converged or skipped already.
 *
 * The bucket set lives here so a consumer never has to enumerate it. A row that
 * is both clean and excluded lands in no bucket at all (see deploy_partition_t),
 * so a scope of only such rows counts zero.
 */
static inline size_t deploy_plan_row_count(const deploy_plan_t *plan) {
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
 * One fate per pending row (the totality equation, deploy_preflight_result_t),
 * each question asked of its one authority, the first skip reason that applies
 * winning (deploy_skip_reason_t):
 * - Ancestry — the observation must bind. A displaced directory row above the
 *   path (workspace_displaced_ancestor) voids every probe taken beneath it, the
 *   landing check's included, so this rung runs first and answers from the run's
 *   own fates (check_ancestry): an ancestor the directory pass converges first
 *   means the row is planned absent and asked nothing else; one the pass skips
 *   means the row inherits that skip, ancestor named; one the run never acts on
 *   (scope, -p, -e, an ancestor claim) is ANCESTOR — an incapacity, and the remedy
 *   is a run that reaches it, or, for a claim the run cannot reach at all because
 *   nothing plans it, a re-derivation of the chain.
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
 * - Type — the occupant the workspace observed at the planned path, both kinds
 *   (workspace_item_t.occupant; a row planned beneath a squatter this run replaces
 *   is absent, and asked nothing). A non-directory where a directory belongs
 *   (or the reverse) is skipped unless --force (TYPE); a directory holding
 *   untracked paths is skipped either way (OCCUPIED), because deploy removes
 *   single nodes and never a tree. A row the workspace could not settle
 *   (DIVERGENCE_UNVERIFIED — an unexaminable occupant, or a look at its content
 *   that failed) is skipped as UNREADABLE when the landing had nothing to say:
 *   no verdict can say what the run will find there.
 * - Content — the workspace's divergence verdict, the only authority for a fact
 *   no lstat can settle. Skipped unless --force (CONTENT; STALE without CONTENT
 *   never skips: disk still holds the blob dotta deployed, so the overwrite loses
 *   nothing); mode, ownership and encryption divergence never skip.
 * - Metadata — deployable rows only: the mode the write applies (the row's, total
 *   by build) and the ownership (resolve_deployment_ownership: the invoking user's
 *   for a path under their home when running as root, the row's owner and group
 *   resolved where the label tracks ownership, no change otherwise). Under
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
 * skipped. Where the squatter stands at a skipped pending row, by inheritance,
 * whatever the reason — the rung reads the ancestor's own fate; where it stands
 * at an ancestor outside the run's reach, by ANCESTOR; where a skipped chain is
 * absent instead, by the row's own landing check — presence is monotone up a
 * path, so every planned row beneath meets the same refusing ancestor (an
 * unreadable one leaves its descendants' probes to fail the same way). So the
 * ancestors loop can never plan a parent for a subtree the run holds.
 *
 * Only rows the run will touch are consulted — the deployable ones, and the
 * ancestors it will make; a directory the run leaves alone cannot skip anything.
 * A planned row beneath a displaced ancestor this run converges (deploy_plan_build
 * routed it; the rung confirms it against the fates) is asked nothing: the path
 * is empty once the directory pass has replaced the squatter, and its landing
 * is that ancestor's — whose own row carries the conflict --force resolves, and
 * the landing question. Its verdict carries that absence; when the ancestor's
 * row is skipped instead, the row inherits that skip, ancestor named (the plan's
 * premise — "the squatter is gone first" — holds row by row, never on average).
 *
 * Runs under the identity the run will act under: apply's privilege check precedes
 * it, so ownership resolves as the executors will apply it.
 *
 * READ-ONLY: modifies neither the filesystem, the state database nor Git.
 *
 * @param ws Workspace with pre-loaded divergence analysis (must not be NULL)
 * @param plan Deployment plan (must not be NULL)
 * @param opts Deployment options (must not be NULL)
 * @param out Pre-flight results (must not be NULL; caller frees with
 *        deploy_preflight_result_free, after deploy_result_free — the receipt
 *        borrows the verdicts — and before workspace_free)
 * @return Error or NULL on success (a skip is not an error; a strict_ownership
 *         failure is)
 */
error_t *deploy_preflight(
    const workspace_t *ws,
    const deploy_plan_t *plan,
    const deploy_options_t *opts,
    deploy_preflight_result_t **out
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
 * anything else DIR_MODE_DEFAULT as the running identity — a claim is the only
 * voice for an ancestor's attributes, and where none speaks dotta invents none.
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
 * The returned error is the run's infrastructure alone, and the receipt tells
 * the caller which: the receipt's own allocation failed (*out unset — nothing
 * ran, nothing to record), or the release of held modes failed (*out holds the
 * complete receipt beside the error — every row ran, and what landed is the
 * record's to keep). The held directories are released on every exit.
 *
 * View rows are self-contained (blob_oid, type, storage path); the content cache
 * handles encryption transparently. The record (path_anchors, observations) is
 * the caller's to write, after deployment succeeds.
 *
 * @param repo Repository (must not be NULL)
 * @param ws Workspace the plan was built from (must not be NULL; the
 *        claimed-ancestor lookup for a landing directory the run may hold)
 * @param verdicts The verdicts to carry out — deployable rows only, by
 *        construction: the skips never enter these arrays (must not be NULL)
 * @param cache Content cache for batch operations (must not be NULL)
 * @param out Deployment results (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *deploy_execute(
    git_repository *repo,
    const workspace_t *ws,
    const deploy_preflight_result_t *verdicts,
    content_cache_t *cache,
    deploy_result_t **out
);

/**
 * Free pre-flight results
 *
 * @param verdicts Verdicts to free (can be NULL)
 */
void deploy_preflight_result_free(deploy_preflight_result_t *verdicts);

/**
 * Free deployment results
 *
 * @param result Results to free (can be NULL)
 */
void deploy_result_free(deploy_result_t *result);

#endif /* DOTTA_DEPLOY_H */
