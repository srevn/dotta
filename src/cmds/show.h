/**
 * show.h - Show file content or commit details
 */

#ifndef DOTTA_CMD_SHOW_H
#define DOTTA_CMD_SHOW_H

#include <git2.h>

#include "types.h"

/**
 * Show mode
 */
typedef enum {
    SHOW_FILE,          /* Show file content (default) */
    SHOW_COMMIT         /* Show commit with diff */
} show_mode_t;

/**
 * Show command options
 */
typedef struct {
    show_mode_t mode;        /* Display mode */
    const char *profile;     /* Profile name (NULL = use active profiles) */
    const char *file_path;   /* File path within profile (for SHOW_FILE mode) */
    const char *commit;      /* Commit reference (NULL = HEAD) */
    bool raw;                /* Show raw content without formatting */
} cmd_show_options_t;

/**
 * Execute show command
 */
error_t *cmd_show(git_repository *repo, const cmd_show_options_t *opts);

#endif /* DOTTA_CMD_SHOW_H */
