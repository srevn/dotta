/**
 * bootstrap.h - Bootstrap script execution system
 *
 * Provides per-profile bootstrap script execution for system setup.
 * Bootstrap scripts live in .bootstrap within each profile branch.
 *
 * Design principles:
 * - On-demand creation (not auto-created with profiles)
 * - Per-profile scripts for OS/host-specific setup
 * - Layered execution (global → OS → host)
 * - Environment variables for context
 */

#ifndef DOTTA_BOOTSTRAP_H
#define DOTTA_BOOTSTRAP_H

#include <git2.h>
#include <stdbool.h>

#include "types.h"

/* Forward declarations */
struct profile_list;

/**
 * Default bootstrap script name
 */
#define BOOTSTRAP_DEFAULT_SCRIPT_NAME ".bootstrap"

/**
 * Bootstrap execution context
 *
 * Provides context information to bootstrap scripts via environment variables.
 */
typedef struct {
    const char *repo_dir;           /* Repository directory (DOTTA_REPO_DIR) */
    const char *profile_name;       /* Current profile being bootstrapped (DOTTA_PROFILE) */
    const char *all_profiles;       /* All profiles being bootstrapped (DOTTA_PROFILES) */
    bool dry_run;                   /* Is this a dry-run? */
} bootstrap_context_t;

/**
 * Bootstrap execution result
 *
 * Note: Output is printed directly to stdout/stderr in real-time during
 * execution. This struct only captures the exit status for programmatic use.
 */
typedef struct {
    int exit_code;                  /* Exit code from bootstrap script */
    bool failed;                    /* Whether bootstrap failed */
} bootstrap_result_t;

/**
 * Check if bootstrap script exists for profile
 *
 * @param repo Repository (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param script_name Bootstrap script filename (default: "bootstrap")
 * @return true if bootstrap script exists in profile's root directory
 */
bool bootstrap_exists(
    git_repository *repo,
    const char *profile_name,
    const char *script_name
);

/**
 * Extract bootstrap script from Git blob to temporary file
 *
 * Creates a secure temporary file with executable permissions and writes
 * the bootstrap script content from the profile's Git tree.
 *
 * @param repo Repository (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param script_name Script filename (default: ".bootstrap")
 * @param out_temp_path Output: path to temporary file (caller must free and unlink)
 * @return Error or NULL on success
 */
error_t *bootstrap_extract_to_temp(
    git_repository *repo,
    const char *profile_name,
    const char *script_name,
    char **out_temp_path
);

/**
 * Read bootstrap script content from Git blob
 *
 * @param repo Repository (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param script_name Script filename (default: ".bootstrap")
 * @param out_content Output: buffer containing script content (caller must free)
 * @return Error or NULL on success
 */
error_t *bootstrap_read_content(
    git_repository *repo,
    const char *profile_name,
    const char *script_name,
    buffer_t **out_content
);

/**
 * Execute bootstrap script with environment
 *
 * Runs the bootstrap script with proper environment variables.
 *
 * Working directory: $HOME if accessible, otherwise repository root.
 * This provides a natural context for bootstrap operations (installing
 * packages, creating directories, configuring user environment) while
 * ensuring robustness in edge cases where $HOME is unavailable.
 *
 * Environment variables set:
 * - DOTTA_REPO_DIR: Repository directory (repository root)
 * - DOTTA_PROFILE: Current profile name
 * - DOTTA_PROFILES: Space-separated list of all profiles
 * - DOTTA_DRY_RUN: "1" if dry-run, "0" otherwise
 * - HOME: User home directory (inherited)
 *
 * @param script_path Path to bootstrap script (must not be NULL)
 * @param context Execution context (must not be NULL)
 * @param result Optional result struct (can be NULL)
 * @return Error or NULL on success
 */
error_t *bootstrap_execute(
    const char *script_path,
    const bootstrap_context_t *context,
    bootstrap_result_t **result
);

/**
 * Execute bootstrap for multiple profiles in order
 *
 * Runs bootstrap scripts for each profile in the provided order.
 * Stops on first error if stop_on_error is true.
 *
 * @param repo Repository (must not be NULL)
 * @param repo_dir Repository directory (must not be NULL)
 * @param profiles Profile list (must not be NULL)
 * @param dry_run If true, show what would be executed without running
 * @param stop_on_error If true, stop on first error; if false, continue
 * @return Error or NULL on success
 */
error_t *bootstrap_run_for_profiles(
    git_repository *repo,
    const char *repo_dir,
    struct profile_list *profiles,
    bool dry_run,
    bool stop_on_error
);

/**
 * Free bootstrap result
 *
 * @param result Result to free (can be NULL)
 */
void bootstrap_result_free(bootstrap_result_t *result);

#endif /* DOTTA_BOOTSTRAP_H */
