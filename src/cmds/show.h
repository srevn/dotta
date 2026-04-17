/**
 * show.h - Show file content or commit details
 */

#ifndef DOTTA_CMD_SHOW_H
#define DOTTA_CMD_SHOW_H

#include <git2.h>
#include <types.h>

#include "cmds/runtime.h"

/**
 * Show mode
 */
typedef enum {
    SHOW_FILE,          /* Show file content (default) */
    SHOW_COMMIT         /* Show commit with diff */
} show_mode_t;

/**
 * Show command options
 *
 * The trailing `positional_args` / `positional_count` pair is a raw
 * bucket populated by the spec engine; `show_post_parse` reads it and
 * assigns the user-facing `profile`/`file_path`/`commit` fields based
 * on how many positionals the user provided. Consumers of cmd_show
 * read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_show). */
    show_mode_t mode;        /* Display mode */
    const char *profile;     /* Profile name (NULL = use enabled profiles) */
    const char *file_path;   /* File path within profile (for SHOW_FILE mode) */
    const char *commit;      /* Commit reference (NULL = HEAD) */
    bool raw;                /* Show raw content without formatting */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_show_options_t;

/**
 * Show file content or commit details
 *
 * In SHOW_FILE mode, displays the content of a file from a profile branch.
 * In SHOW_COMMIT mode, displays a commit with its diff.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_show(const dotta_ctx_t *ctx, const cmd_show_options_t *opts);

/**
 * Spec-engine command specification for `dotta show`.
 *
 * Registered in cmds/registry.c. Defined in show.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_show;

#endif /* DOTTA_CMD_SHOW_H */
