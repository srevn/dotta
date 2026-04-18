/**
 * update.h - Update profiles with modified files
 *
 * Syncs filesystem changes back into profile branches.
 * The reverse operation of apply (filesystem -> repo instead of repo -> filesystem).
 */

#ifndef DOTTA_CMD_UPDATE_H
#define DOTTA_CMD_UPDATE_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * Update command options
 *
 * `files` and `profiles` are populated from the raw positional bucket
 * by `update_post_parse`. The first positional is classified as a file
 * path or profile name via `str_looks_like_file_path`; remaining
 * positionals are always file paths.
 */
typedef struct {
    /* User-facing (read by cmd_update). */
    char **files;                   /* Specific files to update (NULL = all) */
    size_t file_count;              /* Number of files */
    char **profiles;                /* Specific profiles (NULL = use state/config) */
    size_t profile_count;           /* Number of profiles */
    const char *message;            /* Custom commit message */
    char **exclude_patterns;        /* Exclude patterns (glob) - read-only */
    size_t exclude_count;           /* Number of exclude patterns */
    bool dry_run;                   /* Don't commit, just show changes */
    bool interactive;               /* Prompt for confirmation */
    bool verbose;                   /* Verbose output */
    bool include_new;               /* Include new files from tracked directories */
    bool only_new;                  /* Only process new files (ignore modified) */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_update_options_t;

/**
 * Update command implementation
 *
 * Finds modified files and updates their source profiles with the changes.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_update(const dotta_ctx_t *ctx, const cmd_update_options_t *opts);

/**
 * Spec-engine command specification for `dotta update`.
 *
 * Registered in cmds/registry.c. Defined in update.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_update;

#endif /* DOTTA_CMD_UPDATE_H */
