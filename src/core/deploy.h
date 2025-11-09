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

#include "metadata.h"
#include "profiles.h"
#include "types.h"

/* Forward declarations */
typedef struct hashmap hashmap_t;
typedef struct content_cache content_cache_t;
typedef struct keymanager keymanager_t;
typedef struct workspace workspace_t;

/**
 * Ownership change entry
 *
 * Represents a file where the owning profile is changing.
 */
typedef struct {
    char *filesystem_path;       /* File path */
    char *old_profile;          /* Previous owning profile */
    char *new_profile;          /* New owning profile */
} ownership_change_t;

/**
 * Pre-flight check results
 */
typedef struct {
    bool has_errors;             /* Are there any blocking errors? */
    string_array_t *conflicts;   /* Files modified locally */
    string_array_t *permission_errors; /* Files with permission issues */
    string_array_t *overlaps;    /* Files in multiple profiles (warnings) */
    ownership_change_t *ownership_changes;  /* Files changing ownership */
    size_t ownership_change_count;         /* Number of ownership changes */
} preflight_result_t;

/**
 * Deployment options
 */
typedef struct {
    bool force;           /* Overwrite modified files */
    bool dry_run;         /* Don't actually deploy */
    bool verbose;         /* Print verbose output */
    bool skip_existing;   /* Skip files that already exist (don't overwrite) */
    bool skip_unchanged;  /* Skip files that match profile content (smart skip) */
} deploy_options_t;

/**
 * Deployment result
 */
typedef struct {
    size_t deployed_count;       /* Successfully deployed files */
    size_t skipped_count;        /* Skipped files */
    string_array_t *deployed;    /* List of deployed files */
    string_array_t *skipped;     /* List of skipped files */
    string_array_t *skipped_reasons;  /* Parallel array: skip reasons ("unchanged" | "exists") */
    string_array_t *failed;      /* List of failed files */
    char *error_message;         /* Error message if deployment failed */
} deploy_result_t;

/**
 * Run pre-flight checks using workspace divergence analysis
 *
 * Simplified preflight that leverages workspace's pre-computed divergence
 * analysis instead of re-analyzing files. Maps divergence types to
 * deployment decisions.
 *
 * Checks performed:
 * - Overlap detection (files in multiple profiles) - manifest-level
 * - Conflict detection (modified files) - from workspace divergence
 * - Ownership changes (profile switches) - from workspace tracking
 * - Writability checks - filesystem-level (not in workspace)
 *
 * @param ws Workspace with pre-loaded divergence analysis (must not be NULL)
 * @param manifest Manifest for overlap detection (must not be NULL)
 * @param opts Deployment options (must not be NULL)
 * @param out Pre-flight results (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *deploy_preflight_check_from_workspace(
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
 * @param km Key manager for encryption (can be NULL for plaintext-only)
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
    keymanager_t *km,
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
 * @param entry File entry to deploy (must not be NULL, contains all deployment metadata)
 * @param opts Deployment options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *deploy_file(
    git_repository *repo,
    content_cache_t *cache,
    const file_entry_t *entry,
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
