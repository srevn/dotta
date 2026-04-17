/**
 * remove.h - Remove files from profiles or delete profiles
 *
 * Provides two main operations:
 * 1. Remove specific files/directories from a profile branch
 * 2. Delete an entire profile branch
 *
 * Architectural principle: This command modifies the Git repository only.
 * Filesystem synchronization is handled by 'dotta apply'.
 *
 * Uses temporary worktrees to safely modify profile branches.
 */

#ifndef DOTTA_CMD_REMOVE_H
#define DOTTA_CMD_REMOVE_H

#include <git2.h>
#include <types.h>

#include "cmds/runtime.h"

/**
 * Command options
 *
 * `profile` and `paths` are populated from the raw positional bucket
 * by `remove_post_parse`. Consumers read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_remove). */
    const char *profile;        /* Profile name (required) */
    char **paths;               /* Paths to remove (can be NULL for --delete-profile) */
    size_t path_count;          /* Number of paths */

    /* Operation modes */
    bool delete_profile;        /* Delete entire profile branch */
    bool delete_files;          /* Stage deployed files for deletion via apply */

    /* Safety flags */
    bool dry_run;               /* Show what would be removed without doing it */
    bool force;                 /* Skip confirmations */
    bool interactive;           /* Prompt for each file */

    /* Output flags */
    bool verbose;               /* Print verbose output */
    bool quiet;                 /* Minimal output */

    /* Git flags */
    const char *message;        /* Custom commit message (optional) */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_remove_options_t;

/**
 * Remove files from a profile or delete a profile
 *
 * Behavior depends on options:
 * - If delete_profile=true: Deletes the entire profile branch
 * - If delete_profile=false: Removes specified files from profile
 *
 * This command modifies the Git repository only. By default, deployed files
 * are released from management and remain on the filesystem. With delete_files=true,
 * they are staged for removal and deleted when 'dotta apply' is run.
 *
 * Uses temporary worktree to safely modify profile branches.
 * Executes hooks but does not modify deployed files or state file entries.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_remove(const dotta_ctx_t *ctx, const cmd_remove_options_t *opts);

/**
 * Spec-engine command specification for `dotta remove`.
 *
 * Registered in cmds/registry.c. Defined in remove.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_remove;

#endif /* DOTTA_CMD_REMOVE_H */
