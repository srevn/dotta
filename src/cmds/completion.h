/**
 * completion.h - Shell completion helper
 *
 * Hidden subcommand providing completion data for shell scripts.
 * Outputs newline-separated results to stdout, no stderr output.
 *
 * Design principles:
 * - Silent failures: Never print errors, output nothing on failure
 * - Fast queries: Use state DB for O(1)/O(n) fast lookups
 * - Simple output: Newline-separated for fish consumption
 *
 * Usage:
 *   dotta __complete check              # Exit 0 if in repo, 1 otherwise
 *   dotta __complete profiles           # Enabled profiles
 *   dotta __complete profiles --all     # All available profiles (branches)
 *   dotta __complete files              # All managed files
 *   dotta __complete files -p <profile> # Files in specific profile
 *   dotta __complete files --storage    # Storage paths instead of filesystem
 *   dotta __complete commits            # Recent commits from first enabled profile
 *   dotta __complete commits -p <profile>  # Recent commits from specific profile
 *   dotta __complete commits --limit <n>   # Limit number of commits
 */

#ifndef DOTTA_CMD_COMPLETION_H
#define DOTTA_CMD_COMPLETION_H

#include <git2.h>
#include <types.h>

/**
 * Completion mode
 */
typedef enum {
    COMPLETE_CHECK,           /* Check if in dotta repo (exit 0/1) */
    COMPLETE_PROFILES,        /* List profiles (enabled or all) */
    COMPLETE_FILES,           /* List managed files */
    COMPLETE_COMMITS,         /* List recent commits */
    COMPLETE_REMOTES,         /* List git remotes */
} completion_mode_t;

/**
 * Completion options
 */
typedef struct {
    completion_mode_t mode;   /* What to complete */
    const char *profile;      /* Optional: filter by profile */
    bool all;                 /* For profiles: include all (not just enabled) */
    bool storage_paths;       /* For files: output storage_path instead of filesystem_path */
    int limit;                /* For commits: max results (default 20) */
} cmd_completion_options_t;

/**
 * Run completion command
 *
 * Outputs completion results to stdout.
 * Returns NULL on success (even if no results).
 * Never outputs to stderr - silent failure model.
 *
 * @param repo Repository (can be NULL for COMPLETE_CHECK mode)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_completion(
    git_repository *repo,
    const cmd_completion_options_t *opts
);

#endif /* DOTTA_CMD_COMPLETION_H */
