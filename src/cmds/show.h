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

/**
 * Parse refspec: [profile:]<path>[@commit]
 *
 * Extracts profile, file path, and commit from refspec string.
 * All output parameters are set to NULL on error.
 * Caller must free all non-NULL output strings.
 *
 * @param input Refspec string (must not be NULL)
 * @param out_profile Profile name or NULL if not specified (caller must free)
 * @param out_file File path (always set if success, caller must free)
 * @param out_commit Commit ref or NULL if not specified (caller must free)
 * @return Error or NULL on success
 */
error_t *parse_refspec(
    const char *input,
    char **out_profile,
    char **out_file,
    char **out_commit
);

#endif /* DOTTA_CMD_SHOW_H */
