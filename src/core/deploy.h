/**
 * deploy.h - File and tracked-directory deployment engine
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
 *   (O_NOFOLLOW, EISDIR, EEXIST, ENOTEMPTY) and the run fail-stops with the partial
 *   receipt. The same stance as core/cleanup
 * - Fail-stop on error (not transactional, but clear reporting)
 * - A dry run is the preview: the caller reads the verdicts and calls no executor,
 *   so there is no dry-run flag beneath the plan
 * - Removals are single-node: what stands at a planned path, never a tree
 * - Directories are materialized in two phases: held at a working mode (recorded
 *   mode, owner rwx on) while the run writes beneath them, then released to the
 *   exact recorded mode, deepest-first — the same way cmd_export materializes a
 *   profile. A tracked directory therefore never refuses a tracked path beneath
 *   it, and preflight predicts no modes
 * - Metadata is reproduced, not negotiated: every write applies the row's mode
 *   and resolved ownership atomically through its own descriptor, so there is
 *   never a moment when a path stands with the wrong owner
 * - Silent: outcomes travel in the result, verdicts and skips in the preflight
 *   result — with the anomalies met while deciding (an identity that could not
 *   be resolved), which are the caller's to print — and failures in the error
 *   chain. This module emits no prose of its own; verbosity and tense are the
 *   caller's, the same convention as every other core module
 */

#ifndef DOTTA_DEPLOY_H
#define DOTTA_DEPLOY_H

#include <git2.h>
#include <types.h>

#include "core/state.h"
#include "sys/filesystem.h"

/* Forward declarations. Plan, verdict and result buckets hold manifest rows
 * (manifest_row_t, core/manifest.h) — consumers project the buckets with
 * manifest_rows_view. */
typedef struct content_cache content_cache_t;
typedef struct manifest_row manifest_row_t;
typedef struct workspace workspace_t;
typedef struct scope scope_t;

/**
 * Deployment options — read by deploy_preflight alone, as cleanup's are
 */
typedef struct {
    bool force;               /* Overwrite modified files; replace a type conflict */
    bool strict_ownership;    /* Fail if ownership cannot be resolved (strict_mode) */
} deploy_options_t;

/**
 * How one planned row is materialized — decided once, at preflight
 *
 * Everything an executor needs and nothing it has to go and get: the row, what
 * stands at its path, and the metadata the write applies. The occupant is the
 * workspace's lstat, never a fresh one — or FS_OCCUPANT_NONE for a row planned
 * beneath a squatter this run replaces first (deploy_plan_build), whose own
 * observation went through the squatter and describes a tree the run dismantles.
 * The occupant is also the receipt's verb for a directory: NONE → created,
 * DIRECTORY → fixed, anything else → replaced.
 *
 * The mode is the row's — total for every kind that carries one (the claim, or
 * the floor manifest_build resolved absence into); a symlink row carries mode 0
 * by design (symlink(2) takes none) and is never asked. Ownership is resolved
 * (resolve_deployment_ownership); (uid_t) -1 / (gid_t) -1 is no change.
 */
typedef struct {
    const manifest_row_t *row;    /* Borrowed (workspace lifetime) */
    fs_occupant_t occupant;       /* What the run will find at the path */
    mode_t mode;                  /* The mode the write applies */
    uid_t uid;                    /* Ownership the write applies; -1 = no change */
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
 * Precedence, and why UNREADABLE ranks last where its siblings
 * (cleanup_skip_reason, workspace_item_route) rank the same fact first: the landing
 * check, when it has something to say, names the ancestry that refused the look
 * — the actionable half of the very same fact. UNREADABLE is what is left when
 * the landing had nothing to say.
 *
 * Symlink rows need no arm of their own: a foreign kind at a link row's path is
 * TYPE (file_row_occupant), a retargeted link is CONTENT (the target compare),
 * and the undecryptable arm of UNREADABLE cannot fire for one (a link's blob is
 * read raw, never through the content layer).
 */
typedef enum {
    DEPLOY_SKIP_NONE = 0,     /* Not skipped — the row has a verdict */
    DEPLOY_SKIP_PERMISSION,   /* The landing refuses: an ancestor not ours, or none reachable */
    DEPLOY_SKIP_ANCESTOR,     /* An untracked non-directory squats an ancestor */
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
 * One planned row the run does not deploy
 *
 * The shape deploy_verdict_t gives a row the run does deploy: the row, and the
 * facts decided about it. `ancestor` is the path the reason names — the ancestor
 * that refused, the non-directory in the way, the squatted tracked directory
 * above an inheriting row. Every such path is an ancestor of the row's own, and
 * so a prefix of filesystem_path by construction (check_landing truncates the
 * planned path; an inheriting row's squatter stands strictly above it) — carried
 * as the byte length of that prefix, not a copy. 0 where the reason has no ancestor
 * to name: it is about the planned path itself, or (PERMISSION alone) the ancestry
 * could not even be reached to name its refusing node. Nothing here is owned:
 * the row is borrowed (workspace lifetime), as every row in this module is.
 */
typedef struct {
    const manifest_row_t *row;    /* Borrowed (workspace lifetime) */
    deploy_skip_reason_t reason;
    size_t ancestor;              /* Prefix length of the named ancestor; 0 = none */
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
 * then the ancestors: the tracked directories outside the plan that the run may
 * make on the way to a planned path (see deploy_preflight). Every array is always
 * allocated, so a consumer reads counts and needs no NULL guard.
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
     * resolved, so it can neither warn nor fail strict mode. */
    string_array_t *warnings;

    /* The how — one per row the run WILL deploy */
    deploy_verdicts_t directories;       /* Pending directory rows, parents first */
    deploy_verdicts_t files;             /* Pending file rows */
    deploy_verdicts_t ancestors;         /* Tracked directories the run may make on the way */
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
 * parent precedes its tracked children within directories.pending. Three consumers
 * lean on that: the planner classifies a directory row after its ancestors,
 * preflight keeps the verdicts in the same order, and the execute loop converges
 * a parent before the paths beneath it — which is what lets a replaced directory
 * settle its subtree for the rows that follow (see deploy_plan_build,
 * deploy_execute).
 */
typedef struct {
    deploy_partition_t files;         /* manifest_row_t * (blob types) */
    deploy_partition_t directories;   /* manifest_row_t * (PATH_TYPE_DIRECTORY) */
} deploy_plan_t;

/**
 * One written file — the row, and the proof the write authored
 *
 * The stat is the record's own triple (stat_cache_from_write), distilled by the
 * executor from the fstat of the descriptor it wrote — taken after the last byte
 * and before the rename that publishes it, so it describes exactly what this
 * run wrote, never what a later look at the path would find. It is what lets
 * apply's record step anchor a deployment with the write's own proof instead of
 * leaving the record blob-only.
 *
 * UNSET for a symlink row — the executor's fact, not a consumer's re-derivation:
 * a link is made by path (symlink(2) opens no descriptor to describe), and readlink
 * is its whole re-verification. UNSET and NULL say the same thing to state_anchor,
 * so the record step passes the triple blind.
 */
typedef struct {
    const manifest_row_t *row;    /* Borrowed (workspace lifetime) */
    stat_cache_t stat;            /* The write's proof; UNSET for a symlink */
} deploy_written_t;

/**
 * The written files with their count — the shape deploy_verdicts_t gives verdicts
 */
typedef struct {
    deploy_written_t *entries;
    size_t count;
} deploy_writes_t;

/**
 * Deployment result — the run's receipt, by outcome
 *
 * Plan buckets by kind, result buckets by outcome verb: every bucket names
 * something that happened, and a directory lands in the one for what its verdict
 * said stood at its path and the run did about it — so the caller can say
 * "replaced" where a squatter went and "fixed" where nothing was created. Work
 * the run deliberately did not do is the plan's to report, never the result's —
 * the plan decided it, so only the plan can report it before a run that ends up
 * executing nothing. A failure is the returned error's to name: fail-stop wraps
 * it with the path, and the partial receipt travels in *out beside it.
 *
 * One bucket is outside the plan: the tracked directories the run made as parents
 * of a planned path (create_ancestor). They carry their recorded mode and ownership
 * like any other tracked directory, and dotta made them — so the record step
 * anchors them as owned, the same event as a created directory — but the plan
 * never named them and the preview never counted them, so the caller's summary
 * keeps them apart from `created`. Untracked parents have no row, and so no bucket
 * and no record.
 *
 * The directory buckets carry borrowed row pointers (workspace-arena lifetime,
 * outlives the deploy_result_t); project with manifest_rows_view. The deployed
 * bucket carries deploy_written_t — the same borrowed row beside the write's
 * own proof — and is read directly. Free with deploy_result_free before
 * workspace_free.
 */
typedef struct {
    deploy_writes_t deployed;      /* Files written or linked, each with its write's proof */
    ptr_array_t created;           /* Directories made where nothing stood (manifest_row_t *) */
    ptr_array_t fixed;             /* Directories converged in place — mode, ownership */
    ptr_array_t replaced;          /* Directories that displaced a single-node squatter (--force) */
    ptr_array_t ancestors;         /* Tracked directories made on the way to a planned path */
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
 * One verdict the plan overrules: a path beneath a pending directory row the
 * workspace found squatted (TYPE — a non-directory at its path) is planned as
 * absent, whatever the index says of it. Everything the workspace observed beneath
 * that row it observed through the squatter — a symlink to a directory answers
 * for the link's target, so a child there reads clean — and the directory pass
 * replaces the squatter before anything beneath it is touched. Such a row is
 * work, and not occupied for --skip-existing's purpose; -e still holds it back.
 * Only a pending ancestor counts (one -e skips is not replaced this run), and
 * only an in-scope descendant is reached: a row scope itself rejects (-p, a path
 * filter) is not planned on its ancestor's account — Coherent Scope — and converges
 * on the next apply that covers it. Preflight carries the same fact through as
 * the row's verdict (deploy_preflight).
 *
 * @param ws Workspace with divergence analysis (must not be NULL)
 * @param scope Operation scope (must not be NULL)
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
 * - Landing — the write must be able to land. Every arm of the executor writes
 *   through the *parent* — a temp file renamed over the target, a symlink unlinked
 *   and re-made, a mkdir — so the path's own permissions are never the question,
 *   and a directory being converged in place asks nothing at all. The question
 *   goes to the nearest present ancestor alone: everything absent beneath it is
 *   created by this run at a working mode and cannot refuse. A deployable or
 *   holdable tracked directory there is dotta's and never refuses; any other
 *   directory must accept a new entry now (access(2)) or the row is skipped
 *   (PERMISSION); a non-directory squatter skips it too (ANCESTOR). Ancestors
 *   are not items, so this is the one fresh probe preflight takes; the mechanism
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
 *   fail strict mode.
 *
 * Then the ancestors: every tracked directory row the plan does not act on, absent
 * as the plan reads it — the workspace's occupant, or beneath a squatter this
 * run replaces — that stands above a *deployable* row. ensure_parents creates
 * exactly these on the way to a planned path (the untracked parents beside them
 * carry no metadata to decide), so their metadata is decided here like any other
 * row's, and a warning or a strict-mode error about one is met before the prompt
 * like any other.
 *
 * The deployable gate rests on an invariant the ladders establish rather than
 * check: beneath a skipped pending directory, every planned row is also skipped.
 * A TYPE skip propagates by inheritance (the squatter stays, so nothing beneath
 * it can land or be trusted); a landing-skipped directory stops nothing itself,
 * but presence is monotone up a path, so every planned row beneath one meets
 * the same refusing ancestor at its own landing check; an unreadable one leaves
 * its descendants' probes to fail on the way up. So the ancestors loop can never
 * plan a parent for a subtree the run holds.
 *
 * Only rows the run will touch are consulted — the deployable ones, and the
 * ancestors it will make; a directory the run leaves alone cannot skip anything.
 * A planned row beneath a squatted pending directory (deploy_plan_build) is asked
 * nothing: the path is empty once the directory pass has replaced the squatter,
 * and its landing is the pending ancestor's — whose own row carries the conflict
 * --force resolves, and the landing question. Its verdict carries that absence
 * when the squatter is replaced; when the squatter's row is skipped instead,
 * the row inherits that skip, ancestor named (the plan's premise — "the squatter
 * is gone first" — holds row by row, never on average).
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
 *        deploy_preflight_result_free, after deploy_execute and before
 *        workspace_free)
 * @return Error or NULL on success (a skip is not an error; a strict-mode ownership
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
 * as part of its write: a tracked directory (any profile, in scope or not) with
 * the mode and ownership its ancestor verdict carries, anything else 0755 owned
 * like the planned path. The tracked ones land in the receipt's ancestors bucket;
 * the untracked ones have no row and are never reported. A tracked parent the
 * verdicts did not foresee — present at preflight, gone by the time the run reaches
 * it — is made like an untracked one, and the next load reads whatever it has
 * to say about its mode.
 *
 * Directories are materialized in two phases. Every directory the run creates
 * or converges carries its recorded mode with the owner triad forced on while
 * the run writes beneath it; a tracked, owned directory that already stands where
 * a planned path must land and refuses it is opened the same way. When the run
 * is over — completed or fail-stopped — each such directory is released to its
 * exact mode, deepest-first: recorded for the ones the plan materialized, the
 * mode it had for the ones merely opened. Group and other bits are never widened.
 * This is the one transient the run leaves during its life and none afterwards;
 * it is what lets a 0555 directory captured with children be redeployed with
 * them, and what makes the landing check a question about untracked directories
 * only.
 *
 * Fail-stop: on the first error the partial result is returned in *out alongside
 * the wrapped error, after the held directories are released.
 *
 * View rows are self-contained (blob_oid, type, storage path); the content cache
 * handles encryption transparently. The record (path_anchors, observations) is
 * the caller's to write, after deployment succeeds.
 *
 * @param repo Repository (must not be NULL)
 * @param ws Workspace the plan was built from (must not be NULL; the
 *        tracked-ancestor lookup for a landing directory the run may hold)
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
 * @param result Results to free (can be NULL)
 */
void deploy_preflight_result_free(deploy_preflight_result_t *result);

/**
 * Free deployment results
 *
 * @param result Results to free (can be NULL)
 */
void deploy_result_free(deploy_result_t *result);

#endif /* DOTTA_DEPLOY_H */
