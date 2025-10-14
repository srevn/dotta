/**
 * show.h - Show file content from profile
 */

#ifndef DOTTA_CMD_SHOW_H
#define DOTTA_CMD_SHOW_H

#include <git2.h>

#include "types.h"

/**
 * Show command options
 */
typedef struct {
    const char *profile;     /* Profile name (NULL = use state/config) */
    const char *file_path;   /* File path within profile (required) */
    const char *commit;      /* Commit reference (NULL = HEAD of profile branch) */
    bool raw;                /* Show raw content without formatting */
} cmd_show_options_t;

/**
 * Execute show command
 */
error_t *cmd_show(git_repository *repo, const cmd_show_options_t *opts);

#endif /* DOTTA_CMD_SHOW_H */
