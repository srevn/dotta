/**
 * revert.h - Revert file to previous commit state
 *
 * Restores a file in a profile branch to its state at a specific commit,
 * optionally deploying the reverted file to the filesystem.
 */

#ifndef DOTTA_CMD_REVERT_H
#define DOTTA_CMD_REVERT_H

#include <git2.h>
#include <types.h>

#include "cmds/runtime.h"

/**
 * Revert command options
 *
 * The trailing `positional_args` / `positional_count` pair is a raw
 * bucket populated by the spec engine; `revert_post_parse` reads it and
 * assigns the user-facing `profile`/`file_path`/`commit` fields based
 * on how many positionals the user provided. Consumers of cmd_revert
 * read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_revert). */
    const char *profile;        /* Profile name (NULL = discover via manifest) */
    const char *file_path;      /* File path within profile (required) */
    const char *commit;         /* Commit reference (required) */
    const char *message;        /* Commit message (NULL = auto-generate) */
    bool force;                 /* Skip confirmation and override conflicts */
    bool dry_run;               /* Preview without making changes */
    bool verbose;               /* Print verbose output */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
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
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_revert(const dotta_ctx_t *ctx, const cmd_revert_options_t *opts);

/**
 * Spec-engine command specification for `dotta revert`.
 *
 * Registered in cmds/registry.c. Defined in revert.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_revert;

#endif /* DOTTA_CMD_REVERT_H */
