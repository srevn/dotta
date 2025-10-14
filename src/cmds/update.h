/**
 * update.h - Update profiles with modified files
 *
 * Syncs filesystem changes back into profile branches.
 * The reverse operation of apply (filesystem -> repo instead of repo -> filesystem).
 */

#ifndef DOTTA_CMD_UPDATE_H
#define DOTTA_CMD_UPDATE_H

#include <git2.h>

#include "types.h"

/**
 * Update command options
 */
typedef struct {
    const char **files;          /* Specific files to update (NULL = all) */
    size_t file_count;           /* Number of files */
    const char **profiles;       /* Specific profiles (NULL = use state/config) */
    size_t profile_count;        /* Number of profiles */
    const char *message;         /* Custom commit message */
    bool dry_run;                /* Don't commit, just show changes */
    bool interactive;            /* Prompt for confirmation */
    bool verbose;                /* Verbose output */
    bool include_new;            /* Include new files from tracked directories */
    bool only_new;               /* Only process new files (ignore modified) */
} cmd_update_options_t;

/**
 * Update command implementation
 *
 * Finds modified files and updates their source profiles with the changes.
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_update(git_repository *repo, const cmd_update_options_t *opts);

#endif /* DOTTA_CMD_UPDATE_H */
