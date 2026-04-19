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

#include "core/manifest.h"
#include "core/metadata.h"

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
 */
typedef struct {
    /* Result arrays */
    string_array_t *deployed;          /* Files written to disk */
    string_array_t *skipped_existing;  /* --skip-existing flag applied */
    string_array_t *failed;            /* Deployment failures */

    char *error_message;               /* Error message if deployment failed */
} deploy_result_t;

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
 * @param manifest Manifest for iteration (must not be NULL)
 * @param opts Deployment options (must not be NULL)
 * @param out Pre-flight results (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *deploy_workspace_preflight(
    const workspace_t *ws,
    const manifest_t *manifest,
    const deploy_options_t *opts,
    preflight_result_t **out
);

/**
 * Execute deployment
 *
 * Deploys all files in manifest to filesystem.
 *
 * Uses workspace for smart skip optimization - queries pre-computed divergence
 * analysis instead of re-analyzing files. This eliminates redundant content
 * comparisons and decryption operations.
 *
 * Architecture (Manifest Authority):
 * - Workspace: Single source of truth for divergence (already computed)
 * - Deploy: Pure execution engine, queries workspace for skip decisions
 * - State: Source of truth for directory entries and file metadata (VWD principle)
 * - File entries: Self-contained (mode, owner, group, encrypted from state cache)
 * - State management: Handled by caller after deployment succeeds
 *
 * @param repo Repository (must not be NULL)
 * @param ws Workspace with pre-computed divergence analysis (must not be NULL)
 * @param manifest Manifest to deploy (must not be NULL)
 * @param state State database for tracked directories (can be NULL)
 * @param opts Deployment options (must not be NULL)
 * @param cache Content cache for batch operations (must not be NULL)
 * @param out Deployment results (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *deploy_execute(
    git_repository *repo,
    const workspace_t *ws,
    const manifest_t *manifest,
    const state_t *state,
    const deploy_options_t *opts,
    content_cache_t *cache,
    deploy_result_t **out
);

/**
 * Deploy single file
 *
 * Deploys a single file from the manifest to its target location.
 *
 * Architecture (VWD Authority):
 * - file_entry_t is self-contained (contains mode, owner, group, encrypted from state)
 * - No separate metadata parameter needed (eliminated redundant O(n) lookup)
 * - Encryption handled transparently by content cache
 *
 * VWD Model:
 * - entry->mode: Permission mode from state database (0 = use git mode fallback)
 * - entry->owner/group: Ownership strings for root/ prefix files (NULL for home/)
 * - entry->encrypted: Encryption flag from state (validated at manifest sync)
 *
 * @param repo Repository (must not be NULL)
 * @param cache Content cache for batch operations (must not be NULL)
 * @param entry File entry to deploy (must not be NULL, contains all deployment metadata).
 *              Non-const: may lazy-load git tree entry on first access.
 * @param opts Deployment options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *deploy_file(
    git_repository *repo,
    content_cache_t *cache,
    file_entry_t *entry,
    const deploy_options_t *opts
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
