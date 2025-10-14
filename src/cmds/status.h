/**
 * status.h - Show status of managed files
 *
 * Displays deployment status and local modifications.
 */

#ifndef DOTTA_CMD_STATUS_H
#define DOTTA_CMD_STATUS_H

#include <git2.h>

#include "types.h"

/**
 * Command options
 */
typedef struct {
    const char **profiles;      /* Profile names (NULL = use state/config) */
    size_t profile_count;       /* Number of profiles */
    bool verbose;               /* Print verbose output */
    bool show_local;            /* Show filesystem status (default: true) */
    bool show_remote;           /* Show remote sync status (default: true) */
    bool no_fetch;              /* Skip fetch before remote status check */
} cmd_status_options_t;

/**
 * Show status of managed files
 *
 * Compares current filesystem state with profiles and deployment state.
 * Reports:
 * - Files that would be deployed
 * - Files that have been modified locally
 * - Files that are up to date
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_status(git_repository *repo, const cmd_status_options_t *opts);

#endif /* DOTTA_CMD_STATUS_H */
