/**
 * revert.h - Revert file to previous commit state
 *
 * Restores a file in a profile branch to its state at a specific commit, optionally
 * deploying the reverted file to the filesystem.
 */

#ifndef DOTTA_CMD_REVERT_H
#define DOTTA_CMD_REVERT_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * Revert command options
 *
 * The trailing `positional_args` / `positional_count` pair is a raw bucket
 * populated by the spec engine; `revert_post_parse` reads it and assigns the
 * user-facing `profile`/`file_path`/`commit` fields based on how many positionals
 * the user provided. Consumers of cmd_revert read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_revert). */
    const char *profile;        /* Profile name (NULL = discover via manifest) */
    const char *file_path;      /* File path within profile (required) */
    const char *commit;         /* Commit reference (required) */
    const char *message;        /* Commit message (NULL = auto-generate) */
    bool force;                 /* Skip confirmation */
    bool dry_run;               /* Preview without making changes */
    bool verbose;               /* Print verbose output */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_revert_options_t;

/**
 * Execute revert command
 *
 * Reverts a file in a profile branch to its state at the specified commit. This
 * command modifies the Git repository only - deployed files remain unchanged
 * until 'dotta apply' is run.
 *
 * Everything the revert writes is decided before any of it is shown, and shown
 * before it is asked: a dry run and a real run reach the same verdict on the
 * same argument — the same admission, semantic and structural, the stage's own
 * refusals included — and the prompt is the only gate between the preview and
 * the commit. What no preview can foresee is what is left: memory, a ref another
 * writer moved between the preview and the commit, a repository that will not
 * write.
 *
 * The operation:
 * 1. Discovers which profile holds the argument (requires --profile if ambiguous)
 * 2. Resolves commit reference in profile branch history
 * 3. Reads both entries — the commit's, which must be a blob, and the branch
 *    tip's, which may be absent — the restored blob's own bytes, and the claims
 *    both sheets record at the name
 * 4. Answers "nothing to do" when that whole write already stands
 * 5. Puts the entry on the stage — the write's own admission, made here so that
 *    a tree that cannot hold it refuses before the preview and not after the
 *    prompt; no object is written by it
 * 6. Shows the preview (restored / diff / mode and ownership only)
 * 7. Prompts for confirmation (unless --force)
 * 8. Creates one commit with the restored blob and the merged metadata
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_revert(const dotta_ctx_t *ctx, const cmd_revert_options_t *opts);

/**
 * Spec-engine command specification for `dotta revert`.
 *
 * Registered in cmds/registry.c. Defined in revert.c beside the post_parse and
 * dispatch wrappers.
 */
extern const args_command_t spec_revert;

#endif /* DOTTA_CMD_REVERT_H */
