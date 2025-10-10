/**
 * list.h - List profiles and files
 *
 * Shows available profiles and their contents.
 */

#ifndef DOTTA_CMD_LIST_H
#define DOTTA_CMD_LIST_H

#include <git2.h>

#include "dotta/types.h"

/**
 * List mode
 */
typedef enum {
    LIST_PROFILES,   /* List all profiles */
    LIST_FILES,      /* List files in profiles */
    LIST_LOG         /* Show commit history */
} list_mode_t;

/**
 * Command options
 */
typedef struct {
    list_mode_t mode;           /* What to list */
    const char *profile;        /* Profile name (for LIST_FILES or LIST_LOG mode) */
    bool verbose;               /* Print verbose output */
    size_t max_count;           /* Max commits for log mode (0 = all) */
    bool oneline;               /* Show commits in one-line format */
    bool remote;                /* Fetch and show remote state */
} cmd_list_options_t;

/**
 * List profiles or files
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
dotta_error_t *cmd_list(git_repository *repo, const cmd_list_options_t *opts);

#endif /* DOTTA_CMD_LIST_H */
