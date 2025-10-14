/**
 * clean.h - Remove untracked managed files
 *
 * Removes files that were deployed but are no longer in active profiles.
 */

#ifndef DOTTA_CMD_CLEAN_H
#define DOTTA_CMD_CLEAN_H

#include <git2.h>

#include "types.h"

/**
 * Command options
 */
typedef struct {
    const char **profiles;      /* Profile names (NULL = use state/config) */
    size_t profile_count;       /* Number of profiles */
    bool dry_run;               /* Don't actually remove files */
    bool force;                 /* Remove without confirmation */
    bool verbose;               /* Print verbose output */
    bool quiet;                 /* Minimal output */
} cmd_clean_options_t;

/**
 * Clean orphaned files
 *
 * Removes files that were deployed by previous 'apply' but are no longer
 * in any active profile.
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_clean(git_repository *repo, const cmd_clean_options_t *opts);

#endif /* DOTTA_CMD_CLEAN_H */
