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

#include "dotta/types.h"
#include "profiles.h"
#include "state.h"

/**
 * Pre-flight check results
 */
typedef struct {
    bool has_errors;             /* Are there any blocking errors? */
    string_array_t *conflicts;   /* Files modified locally */
    string_array_t *permission_errors; /* Files with permission issues */
    string_array_t *overlaps;    /* Files in multiple profiles (warnings) */
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
    string_array_t *failed;      /* List of failed files */
    char *error_message;         /* Error message if deployment failed */
} deploy_result_t;

/**
 * Run pre-flight checks
 *
 * Checks for:
 * - Modified files (conflicts)
 * - Permission issues
 * - Path validity
 *
 * @param repo Repository (must not be NULL)
 * @param manifest Manifest to check (must not be NULL)
 * @param state Current state (can be NULL)
 * @param opts Deployment options (must not be NULL)
 * @param out Pre-flight results (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
dotta_error_t *deploy_preflight_check(
    git_repository *repo,
    const manifest_t *manifest,
    const state_t *state,
    const deploy_options_t *opts,
    preflight_result_t **out
);

/**
 * Execute deployment
 *
 * Deploys all files in manifest to filesystem.
 * Updates state on success.
 *
 * @param repo Repository (must not be NULL)
 * @param manifest Manifest to deploy (must not be NULL)
 * @param opts Deployment options (must not be NULL)
 * @param out Deployment results (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
dotta_error_t *deploy_execute(
    git_repository *repo,
    const manifest_t *manifest,
    const deploy_options_t *opts,
    deploy_result_t **out
);

/**
 * Deploy single file
 *
 * @param repo Repository (must not be NULL)
 * @param entry File entry to deploy (must not be NULL)
 * @param opts Deployment options (must not be NULL)
 * @return Error or NULL on success
 */
dotta_error_t *deploy_file(
    git_repository *repo,
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
