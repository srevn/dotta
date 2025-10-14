/**
 * remove.h - Remove files from profiles or delete profiles
 *
 * Provides two main operations:
 * 1. Remove specific files/directories from a profile branch
 * 2. Delete an entire profile branch
 *
 * Uses temporary worktrees to safely modify profile branches.
 */

#ifndef DOTTA_CMD_REMOVE_H
#define DOTTA_CMD_REMOVE_H

#include <git2.h>

#include "types.h"

/**
 * Command options
 */
typedef struct {
    const char *profile;        /* Profile name (required) */
    const char **paths;         /* Paths to remove (can be NULL for --delete-profile) */
    size_t path_count;          /* Number of paths */

    /* Operation modes */
    bool delete_profile;        /* Delete entire profile branch */
    bool keep_files;            /* Keep deployed files on filesystem */

    /* Safety flags */
    bool dry_run;               /* Show what would be removed without doing it */
    bool force;                 /* Skip confirmations */
    bool interactive;           /* Prompt for each file */

    /* Output flags */
    bool verbose;               /* Print verbose output */
    bool quiet;                 /* Minimal output */

    /* Git flags */
    const char *message;        /* Custom commit message (optional) */
} cmd_remove_options_t;

/**
 * Remove files from a profile or delete a profile
 *
 * Behavior depends on options:
 * - If delete_profile=true: Deletes the entire profile branch
 * - If delete_profile=false: Removes specified files from profile
 *
 * Uses temporary worktree to safely modify profile branches.
 * Updates state tracking and executes hooks.
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_remove(git_repository *repo, const cmd_remove_options_t *opts);

#endif /* DOTTA_CMD_REMOVE_H */
