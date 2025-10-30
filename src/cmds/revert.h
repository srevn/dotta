/**
 * revert.h - Revert file to previous commit state
 *
 * Restores a file in a profile branch to its state at a specific commit,
 * optionally deploying the reverted file to the filesystem.
 */

#ifndef DOTTA_CMD_REVERT_H
#define DOTTA_CMD_REVERT_H

#include <git2.h>

#include "types.h"

/**
 * Revert command options
 */
typedef struct {
    const char *file_path;      /* File path within profile (required) */
    const char *commit;         /* Commit reference (required) */
    const char *profile;        /* Profile name (NULL = use state/config) */
    const char *message;        /* Commit message (NULL = auto-generate) */
    bool force;                 /* Skip confirmation and override conflicts */
    bool dry_run;               /* Preview without making changes */
    bool verbose;               /* Print verbose output */
} cmd_revert_options_t;

/**
 * Execute revert command
 *
 * Reverts a file in a profile branch to its state at the specified commit.
 * This command modifies the Git repository only - deployed files remain
 * unchanged until 'dotta apply' is run.
 *
 * The operation:
 * 1. Discovers file in profiles (requires --profile if ambiguous)
 * 2. Resolves commit reference in profile branch history
 * 3. Shows diff preview (current → target state)
 * 4. Prompts for confirmation (unless --force)
 * 5. Reverts file to target commit state
 * 6. Creates commit with restored file and metadata
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_revert(git_repository *repo, const cmd_revert_options_t *opts);

#endif /* DOTTA_CMD_REVERT_H */
