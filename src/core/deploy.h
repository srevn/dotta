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
 * - One dry-run gate per executor, ahead of every mutation
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
 *   blocked            an absent planned path's nearest existing ancestor
 *                      is not a directory and is not itself planned (a
 *                      planned one is judged by its own conflict entry) —
 *                      bring the ancestor into scope with --force, or fix
 *                      by hand
 *   permission_errors  not writable — privileges
 */
typedef struct {
    bool has_errors;                     /* Are there any blocking errors? */
    string_array_t *conflicts;           /* Paths modified locally / wrong type */
    string_array_t *blocked;             /* "<file> (<ancestor> is not a directory)" */
    string_array_t *permission_errors;   /* Paths that are not writable */
} preflight_result_t;

/**
 * Deployment options
 */
typedef struct {
    bool force;               /* Overwrite modified files; replace type conflicts */
    bool dry_run;             /* Decide everything, mutate nothing */
    bool verbose;             /* Print per-item traces */
    bool skip_existing;       /* Skip files that already exist (don't overwrite) */
    bool strict_ownership;    /* Fail if ownership cannot be resolved (strict_mode) */
} deploy_options_t;

/**
 * One kind's partition of the in-scope active set
 *
 * Every active row that passes the scope's profile and path dimensions
 * lands in exactly one bucket, or nowhere:
 *
 *   pending   need work — deploy_execute acts on these
 *   clean     in scope, no work (adoption candidates)
 *   excluded  need work, held back by -e
 *
 * A row that is both clean and excluded enters no bucket: it is neither
 * work nor adoptable. Out-of-scope rows are invisible.
 *
 * Buckets hold borrowed row pointers into the workspace's arena snapshot
 * (workspace lifetime); the plan owns only the bucket buffers. Project a
 * bucket with state_files_view / state_directories_view.
 */
typedef struct {
    ptr_array_t pending;
    ptr_array_t clean;
    ptr_array_t excluded;
} deploy_partition_t;

/**
 * Deployment plan — deploy's classification of the in-scope active set,
 * one partition per kind. Free with deploy_plan_free BEFORE workspace_free
 * (the same ordering rule scope.h documents for scope_free).
 *
 * Both slices come out of state ordered by filesystem_path, so a tracked
 * parent precedes its tracked children within directories.pending.
 */
typedef struct {
    deploy_partition_t files;         /* state_file_entry_t * */
    deploy_partition_t directories;   /* state_directory_entry_t * */
} deploy_plan_t;

/**
 * Deployment result
 *
 * Reports outcomes per kind. Each bucket carries borrowed state-row
 * pointers (workspace-arena lifetime, outlives the deploy_result_t);
 * project with state_files_view / state_directories_view. Free with
 * deploy_result_free before workspace_free.
 *
 * In dry-run the deployed/converged buckets are still filled — they name
 * what the run *would* do, so the caller reports the preview from the
 * same object as the real run.
 */
typedef struct {
    ptr_array_t deployed;          /* Files written (state_file_entry_t *) */
    ptr_array_t converged;         /* Directories created/fixed/replaced (state_directory_entry_t *) */
    ptr_array_t skipped_existing;  /* Files left alone by --skip-existing (state_file_entry_t *) */
    ptr_array_t failed;            /* Fail-stop: the file whose write failed (at most one) */

    char *error_message;           /* Error message if deployment failed */
} deploy_result_t;

/**
 * Build the deployment plan
 *
 * Walks the workspace's active file and directory slices once, gating
 * each row on scope_accepts_profile ∧ scope_accepts_path(kind), then
 * classifying it by deploy's work predicate (missing, or diverged in
 * content / mode / ownership / type / encryption; STALE alone is not
 * work) and by scope_is_excluded(kind).
 *
 * Requires a workspace loaded with file AND directory analysis: the plan
 * is derived from the divergence index, and a kind whose analysis did not
 * run plans as clean.
 *
 * @param ws Workspace with divergence analysis (must not be NULL)
 * @param scope Operation scope (must not be NULL)
 * @param out Plan (must not be NULL; caller frees with deploy_plan_free)
 * @return Error or NULL on success
 */
error_t *deploy_plan_build(
    const workspace_t *ws,
    const scope_t *scope,
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
 * Run pre-flight checks over the plan
 *
 * Maps the workspace's divergence verdicts for the planned rows to
 * blocking decisions:
 * - Files: content or type divergence blocks unless --force (STALE-only
 *   content divergence is safe to overwrite and never blocks); an
 *   existing path that is not writable blocks.
 * - Directories: type divergence (a non-directory at the tracked path)
 *   blocks unless --force.
 * - Both kinds, when absent: the nearest existing ancestor must be a
 *   directory (or a planned one) and writable.
 *
 * Only planned rows are consulted — a directory that will not be touched
 * cannot block.
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
    preflight_result_t **out
);

/**
 * Execute the plan
 *
 * Directories first (a planned directory may be the parent of a planned
 * file, and under --force a squatting symlink must be gone before a file
 * is written beneath it), then files. Every planned item is acted on;
 * nothing outside the plan is *fixed*. Each executor decides *how* from
 * a fresh look at disk (a prompt may have sat between plan and
 * execution) and mutates nothing in dry-run.
 *
 * Missing parents are the mechanics of landing a planned path, created
 * top-down as part of its write: a tracked directory (any profile, in
 * scope or not) with its tracked mode and ownership, anything else 0755
 * owned like the planned path. Silent, never counted as converged — the
 * caller's presence witness covers them. The workspace is consulted for
 * that lookup only; the plan alone decides what is acted on.
 *
 * Fail-stop: on the first error the partial result is returned in *out
 * alongside the wrapped error.
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
void preflight_result_free(preflight_result_t *result);

/**
 * Free deployment results
 *
 * @param result Results to free (can be NULL)
 */
void deploy_result_free(deploy_result_t *result);

#endif /* DOTTA_DEPLOY_H */
