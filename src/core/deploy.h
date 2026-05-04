/**
 * deploy.h - File deployment engine
 *
 * Handles deploying files from git profiles to the filesystem.
 *
 * Design principles:
 * - Pre-flight checks before any changes
 * - Explicit conflict detection
 * - Permission preservation
 * - Fail-stop on error (not transactional, but clear reporting)
 * - Support for dry-run mode
 */

#ifndef DOTTA_DEPLOY_H
#define DOTTA_DEPLOY_H

#include <git2.h>
#include <types.h>

#include "core/metadata.h"
#include "core/state.h"

/* Forward declarations */
typedef struct hashmap hashmap_t;
typedef struct content_cache content_cache_t;
typedef struct keymgr keymgr;
typedef struct workspace workspace_t;
typedef struct scope scope_t;

/**
 * Profile reassignment entry
 *
 * Represents a file where the owning profile is changing.
 */
typedef struct {
    char *filesystem_path;      /* File path */
    char *old_profile;          /* Previous owning profile */
    char *new_profile;          /* New owning profile */
} reassignment_t;

/**
 * Pre-flight check results
 */
typedef struct {
    bool has_errors;                     /* Are there any blocking errors? */
    string_array_t *conflicts;           /* Files modified locally */
    string_array_t *permission_errors;   /* Files with permission issues */
    reassignment_t *reassignments;       /* Profile reassignments */
    size_t reassignment_count;           /* Number of profile reassignments */
} preflight_result_t;

/**
 * Deployment options
 */
typedef struct {
    bool force;               /* Overwrite modified files */
    bool dry_run;             /* Don't actually deploy */
    bool verbose;             /* Print verbose output */
    bool skip_existing;       /* Skip files that already exist (don't overwrite) */
    bool strict_ownership;    /* Fail if ownership cannot be resolved (strict_mode) */

    /**
     * Operation scope for directory processing.
     *
     * NULL means full-sync (process all tracked directories). Non-NULL
     * activates scoped directory processing:
     *
     *   scope_has_paths(scope)  → strictly-ancestor mode: only directories
     *                             that are ancestors of the requested files.
     *   scope_has_filter(scope) → inclusive mode: ancestors of in-scope
     *                             files AND directories owned by profiles
     *                             matching the CLI -p filter.
     *   Neither → ownership of the scope handle without active filtering;
     *             behaves like full sync.
     *
     * The path dimension (strict) takes precedence over the profile
     * dimension (inclusive) when both are active, mirroring the CLI's
     * "targeted files override profile scope" semantics.
     */
    const scope_t *scope;
} deploy_options_t;

/**
 * Deployment result
 *
 * Tracks only the categories that deploy_execute actually produces. Clean
 * in-scope entries never reach deploy_execute (apply's needs_deployment
 * filter drops them upstream) and apply's own adoption step handles their
 * lifecycle stamp.
 *
 * Each bucket carries borrowed state-row pointers (workspace-arena lifetime,
 * outlives the deploy_result_t). Consumers get a typed read-only view via
 * deploy_result_view() — same idiom as workspace_files().
 */
typedef struct {
    ptr_array_t deployed;          /* Files written to disk (state_file_entry_t *) */
    ptr_array_t skipped_existing;  /* --skip-existing flag applied */
    ptr_array_t failed;            /* Deployment failures */

    char *error_message;           /* Error message if deployment failed */
} deploy_result_t;

/**
 * Project a deploy_result bucket as a typed read-only state-row slice.
 *
 * The cast layers const onto both pointer levels — safe per the same C rule
 * workspace_files() relies on (T** → const T *const *). Returned view aliases
 * the bucket's storage; valid for the result's lifetime.
 */
static inline state_files_t deploy_result_view(const ptr_array_t *bucket) {
    return (state_files_t){
        .entries = (const state_file_entry_t *const *) bucket->items,
        .count = bucket->count,
    };
}

/**
 * Run pre-flight checks using workspace divergence analysis
 *
 * Simplified preflight that leverages workspace's pre-computed divergence
 * analysis instead of re-analyzing files. Maps divergence types to
 * deployment decisions.
 *
 * Checks performed:
 * - Conflict detection (modified files) - from workspace divergence
 * - Profile reassignments (profile switches) - from workspace tracking
 * - Writability checks - filesystem-level (not in workspace)
 *
 * @param ws Workspace with pre-loaded divergence analysis (must not be NULL)
 * @param files Borrowed slice of state rows to deploy (passed by value)
 * @param opts Deployment options (must not be NULL)
 * @param out Pre-flight results (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *deploy_workspace_preflight(
    const workspace_t *ws,
    state_files_t files,
    const deploy_options_t *opts,
    preflight_result_t **out
);

/**
 * Execute deployment
 *
 * Deploys every state row in `files` to the filesystem.
 *
 * Uses workspace for smart skip optimization - queries pre-computed divergence
 * analysis instead of re-analyzing files. This eliminates redundant content
 * comparisons and decryption operations.
 *
 * Architecture:
 * - Workspace: Single source of truth for divergence (already computed)
 * - Deploy: Pure execution engine, queries workspace for skip decisions
 * - State: Source of truth for directory entries and file metadata (VWD principle)
 * - State rows: Self-contained (mode, owner, group, blob_oid).
 *   Pointers in `files` borrow into the workspace's arena snapshot — valid
 *   for the workspace's lifetime, no allocation transfer to the deploy path.
 * - State management: Handled by caller after deployment succeeds
 *
 * @param repo Repository (must not be NULL)
 * @param ws Workspace with pre-computed divergence analysis (must not be NULL)
 * @param files Borrowed slice of state rows to deploy (passed by value)
 * @param opts Deployment options (must not be NULL)
 * @param cache Content cache for batch operations (must not be NULL)
 * @param out Deployment results (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *deploy_execute(
    git_repository *repo,
    const workspace_t *ws,
    state_files_t files,
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
