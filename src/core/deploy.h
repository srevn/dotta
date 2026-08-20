/**
 * deploy.h - File and tracked-directory deployment engine
 *
 * Plan / preflight / execute, in that order:
 *
 *   deploy_plan_build   — decide *what* from (workspace, scope), once
 *   deploy_preflight    — block on conflicts the plan would run into
 *   deploy_execute      — materialize the plan; decides *how* per item
 *                         from disk truth at execution time
 *
 * Preview, privilege check, prompt and reporting all read the one plan;
 * execution applies no filter of its own. Same shape as core/cleanup.
 *
 * Design principles:
 * - Pre-flight checks before any changes
 * - Explicit conflict detection
 * - Permission preservation
 * - Fail-stop on error (not transactional, but clear reporting)
 * - One dry-run gate per executor, ahead of every mutation and behind
 *   every decision: nothing a run concludes consults dry_run, so a dry
 *   run resolves, warns and refuses exactly as the real run does
 * - Removals are single-node: what stands at a planned path, never a tree
 * - Directories are materialized in two phases: held at a working mode
 *   (recorded mode, owner rwx on) while the run writes beneath them, then
 *   released to the exact recorded mode, deepest-first — the same way
 *   cmd_export materializes a profile. A tracked directory therefore
 *   never refuses a tracked path beneath it, and preflight predicts no
 *   modes
 * - Silent: outcomes travel in the result, by verb, and failures in the
 *   error chain; the only prose this module emits is a stderr warning
 *   about an anomaly it met (a corrupt row, an identity it could not
 *   resolve), never about an outcome. Verbosity and tense are the
 *   caller's — the same convention as every other core module
 */

#ifndef DOTTA_DEPLOY_H
#define DOTTA_DEPLOY_H

#include <git2.h>
#include <types.h>

/* Forward declarations. Plan and result buckets hold state rows
 * (state_file_entry_t / state_directory_entry_t, core/state.h) — consumers
 * project them with state_files_view / state_directories_view. */
typedef struct content_cache content_cache_t;
typedef struct workspace workspace_t;
typedef struct scope scope_t;

/**
 * Pre-flight check results
 *
 * Three findings, three remedies:
 *   conflicts          modified locally, or wrong type at the path — --force
 *   blocked            a planned path this run cannot land, and neither
 *                      --force nor privileges change that: an untracked
 *                      non-directory — a file, a dangling symlink — squats
 *                      an ancestor (remove it, or widen the scope so a
 *                      tracked ancestor is planned and --force can replace
 *                      it), or a directory holding untracked paths stands
 *                      at the planned path itself (remove it). Each entry
 *                      carries its own reason
 *   permission_errors  a directory that is not dotta's refuses the write —
 *                      the nearest present ancestor is untracked (or
 *                      tracked but not ours) and not writable, or the
 *                      ancestry cannot be reached — privileges, or the
 *                      directory's owner. Each entry names the directory
 */
typedef struct {
    bool has_errors;                     /* Are there any blocking errors? */
    string_array_t *conflicts;           /* Paths modified locally / wrong type */
    string_array_t *blocked;             /* "<path> (<reason>)" */
    string_array_t *permission_errors;   /* "<path> (<directory> is not writable)" */
} deploy_preflight_result_t;

/**
 * Deployment options
 */
typedef struct {
    bool force;               /* Overwrite modified files; replace a type conflict */
    bool dry_run;             /* Decide everything, mutate nothing */
    bool strict_ownership;    /* Fail if ownership cannot be resolved (strict_mode) */
} deploy_options_t;

/**
 * One kind's partition of the in-scope active set
 *
 * Every active row that passes the scope's profile and path dimensions
 * lands in exactly one bucket, or nowhere: a row that is both clean and
 * excluded enters none (neither work nor adoptable). Out-of-scope rows
 * are invisible.
 *
 * Two buckets carry work the run deliberately does not do. They differ by
 * reason, and the reason is the only thing a consumer needs from them —
 * so the bucket a row sits in *is* its reason tag, and a row -e names is
 * reported as excluded even when --skip-existing would also skip it (a
 * named path is the more explicit intent).
 *
 * Buckets hold borrowed row pointers into the workspace's arena snapshot
 * (workspace lifetime); the plan owns only the bucket buffers. Project a
 * bucket with state_files_view / state_directories_view.
 */
typedef struct {
    ptr_array_t pending;    /* Need work — deploy_execute acts on these */
    ptr_array_t clean;      /* In scope, no work — adoption candidates */
    ptr_array_t excluded;   /* Need work, skipped by -e — reported, never touched */

    /* Need work, skipped by --skip-existing: something already occupies
     * the path. Files only. A tracked directory row writes no data — it
     * creates a container and converges its metadata in place — so
     * skipping one would preserve nothing and would instead strand the
     * tracked children the flag exists to deploy. Its one destructive act,
     * replacing a squatter, is force-gated at preflight already. */
    ptr_array_t skipped_existing;
} deploy_partition_t;

/**
 * Deployment plan — deploy's classification of the in-scope active set,
 * one partition per kind. Free with deploy_plan_free BEFORE workspace_free
 * (the same ordering rule scope.h documents for scope_free).
 *
 * Both slices come out of state ordered by filesystem_path, so a tracked
 * parent precedes its tracked children within directories.pending. Three
 * consumers lean on that: the planner classifies a directory row after
 * its ancestors, the execute loop converges a parent before the paths
 * beneath it, and a replaced directory settles its subtree for the rows
 * that follow (see deploy_plan_build, deploy_execute).
 */
typedef struct {
    deploy_partition_t files;         /* state_file_entry_t * */
    deploy_partition_t directories;   /* state_directory_entry_t * */
} deploy_plan_t;

/**
 * Deployment result — the run's receipt, by outcome
 *
 * Plan buckets by kind, result buckets by outcome verb: every bucket
 * names something that happened, and a directory lands in the one for
 * what the executor found at its path and did about it — decided from
 * its fresh lstat, or from this receipt's own replaced bucket beneath a
 * directory the run has replaced, never from the plan — so the caller
 * can say "replaced" where a squatter went and "fixed" where nothing was
 * created. Work the run deliberately did not do is the plan's to report,
 * never the result's — the plan decided it, so only the plan can report
 * it before a run that ends up executing nothing. A failure is the
 * returned error's to name: fail-stop wraps it with the path, and the
 * partial receipt travels in *out beside it.
 *
 * Each bucket carries borrowed state-row pointers (workspace-arena
 * lifetime, outlives the deploy_result_t); project with
 * state_files_view / state_directories_view. Free with deploy_result_free
 * before workspace_free.
 *
 * In dry-run the same buckets are filled — they name what the run
 * *would* do, so the caller reports the preview from the same object as
 * the real run, differing only in tense.
 */
typedef struct {
    ptr_array_t deployed;          /* Files written or linked (state_file_entry_t *) */
    ptr_array_t created;           /* Directories made where nothing stood (state_directory_entry_t *) */
    ptr_array_t fixed;             /* Directories converged in place — mode, ownership */
    ptr_array_t replaced;          /* Directories that displaced a single-node squatter (--force) */
} deploy_result_t;

/**
 * Build the deployment plan
 *
 * Walks the workspace's active file and directory slices once, gating
 * each row on scope_accepts_profile ∧ scope_accepts_path(kind), then
 * classifying it by deploy's work predicate (missing, or diverged in
 * content / mode / ownership / type / encryption / stale) and by the
 * reasons a row's work is skipped:
 * scope_is_excluded(kind), then skip_existing.
 *
 * Requires a workspace loaded with file AND directory analysis: the plan
 * is derived from the divergence index, and a kind whose analysis did not
 * run plans as clean.
 *
 * One verdict the plan overrules: a path beneath a pending directory row
 * the workspace found squatted (TYPE — a non-directory at its path) is
 * planned as absent, whatever the index says of it. Everything the
 * workspace observed beneath that row it observed through the squatter —
 * a symlink to a directory answers for the link's target, so a child
 * there reads clean — and the directory pass replaces the squatter before
 * anything beneath it is touched. Such a row is work, and not occupied
 * for --skip-existing's purpose; -e still holds it back. Only a pending
 * ancestor counts (one held back by -e is not replaced this run), and
 * only an in-scope descendant is reached: a row scope itself rejects (-p,
 * a path filter) is not planned on its ancestor's account — Coherent
 * Scope — and converges on the next apply that covers it. Preflight and
 * the executors carry the same fact through (deploy_preflight,
 * deploy_execute).
 *
 * @param ws Workspace with divergence analysis (must not be NULL)
 * @param scope Operation scope (must not be NULL)
 * @param skip_existing --skip-existing: a file row whose path is already
 *        occupied is not work. A plan fact, not an execution one — the
 *        occupancy comes from the workspace's own lstat, so preflight, the
 *        privilege scan, the prompt and the executor all see one answer.
 *        Not overridden by --force: --force also overrides cleanup's skip
 *        reasons and the confirmation prompt, so the combination is
 *        meaningful and the narrower flag keeps its promise.
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
 * Distinct from deploy_plan_is_empty, which counts only *work*: a plan of
 * nothing but clean rows is empty there and non-zero here. Apply reads
 * this to tell a path filter that named nothing dotta manages from one
 * whose paths are all converged or skipped already.
 *
 * The bucket set lives here so a consumer never has to enumerate it. A row
 * that is both clean and excluded lands in no bucket at all (see
 * deploy_partition_t), so a scope of only such rows counts zero.
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
 * Run pre-flight checks over the plan
 *
 * Predicts what each executor will decide, asking each question of the
 * authority that will answer it again at execution time:
 * - Type — a fresh lstat of the planned path, both kinds. A non-directory
 *   where a directory belongs (or the reverse) blocks unless --force; a
 *   directory holding untracked paths blocks either way, because deploy
 *   removes single nodes and never a tree.
 * - Content — the workspace's divergence verdict, the only authority for
 *   a fact no lstat can settle. Blocks unless --force (STALE without
 *   CONTENT never blocks: disk still holds the blob dotta deployed, so
 *   the overwrite loses nothing); mode, ownership and encryption
 *   divergence never block.
 * - Landing — the write must be able to land. Every arm of the executor
 *   writes through the *parent* — a temp file renamed over the target, a
 *   symlink unlinked and re-made, a mkdir — so the path's own permissions
 *   are never the question, and a directory being converged in place asks
 *   nothing at all. The question goes to the nearest present ancestor
 *   alone: everything absent beneath it is created by this run at a
 *   working mode and cannot refuse. A pending or tracked directory there
 *   is dotta's to hold and never refuses; any other directory must accept
 *   a new entry now (access(2)) or it is a permission error; a
 *   non-directory squatter blocks. The mechanism (ensure_parents) asks
 *   the same questions of the same ancestor, so this predicts the run
 *   rather than modelling it.
 *
 * Only planned rows are consulted — a directory that will not be touched
 * cannot block. And a planned row beneath a squatted pending directory
 * (deploy_plan_build) is asked nothing: its probes would reach the
 * squatter's target and answer for the wrong tree, the path is empty once
 * the directory pass has replaced the squatter, and its landing is the
 * pending ancestor's — whose own row carries the conflict --force
 * resolves, and the landing question.
 *
 * @param ws Workspace with pre-loaded divergence analysis (must not be NULL)
 * @param plan Deployment plan (must not be NULL)
 * @param opts Deployment options (must not be NULL)
 * @param out Pre-flight results (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *deploy_preflight(
    const workspace_t *ws,
    const deploy_plan_t *plan,
    const deploy_options_t *opts,
    deploy_preflight_result_t **out
);

/**
 * Execute the plan
 *
 * Directories first (a planned directory may be the parent of a planned
 * file, and under --force a squatting symlink must be gone before a file
 * is written beneath it), then files. Every planned item is acted on;
 * nothing outside the plan is *fixed*. Each executor decides *how* from
 * a fresh look at disk (a prompt may have sat between plan and
 * execution) and mutates nothing in dry-run — including the --force
 * verdict on a type conflict, which is re-taken from that fresh look
 * rather than inherited from preflight. Whatever a planned path's own
 * occupant turns out to be, clearing it removes exactly one node.
 *
 * One look the run takes from its own receipt instead: beneath a
 * directory it has replaced, nothing stands — the replace left an empty
 * directory and the run creates beneath it only in prefix order — so a
 * planned path there is created, not fixed or cleared. In the real run
 * the fresh lstat agrees; in a dry run it would still reach the
 * squatter's target, and the receipt is what keeps the preview's verbs
 * the real run's. The receipt, not the plan, because a squatter that
 * healed into a directory before the run is fixed in place and leaves
 * its subtree to the fresh look.
 *
 * Missing parents are the mechanics of landing a planned path, created
 * top-down as part of its write: a tracked directory (any profile, in
 * scope or not) with its tracked mode and ownership, anything else 0755
 * owned like the planned path. Silent, never in the receipt — the
 * caller's presence witness covers them. The workspace is consulted for
 * that lookup only; the plan alone decides what is acted on.
 *
 * Directories are materialized in two phases. Every directory the run
 * creates or converges carries its recorded mode with the owner triad
 * forced on while the run writes beneath it; a tracked, owned directory
 * that already stands where a planned path must land and refuses it is
 * opened the same way. When the run is over — completed or fail-stopped
 * — each such directory is released to its exact mode, deepest-first:
 * recorded for the ones the plan materialized, the mode it had for the
 * ones merely opened. Group and other bits are never widened. This is
 * the one transient the run leaves during its life and none afterwards;
 * it is what lets a 0555 directory captured with children be redeployed
 * with them, and what makes the landing check a question about untracked
 * directories only.
 *
 * Fail-stop: on the first error the partial result is returned in *out
 * alongside the wrapped error, after the held directories are released.
 *
 * State rows are self-contained (mode, owner, group, blob_oid); the
 * content cache handles encryption transparently. State updates
 * (anchors, witnesses) are the caller's, after deployment succeeds.
 *
 * @param repo Repository (must not be NULL)
 * @param ws Workspace the plan was built from (must not be NULL)
 * @param plan Deployment plan (must not be NULL)
 * @param opts Deployment options (must not be NULL)
 * @param cache Content cache for batch operations (must not be NULL)
 * @param out Deployment results (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *deploy_execute(
    git_repository *repo,
    const workspace_t *ws,
    const deploy_plan_t *plan,
    const deploy_options_t *opts,
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
