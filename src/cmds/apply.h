/**
 * apply.h - Apply profiles to filesystem
 *
 * Deploys files from profile branches to the filesystem.
 */

#ifndef DOTTA_CMD_APPLY_H
#define DOTTA_CMD_APPLY_H

#include <git2.h>

#include "types.h"

/**
 * Command options
 */
typedef struct {
    const char **profiles;      /* Profile names (NULL = auto-detect) */
    size_t profile_count;       /* Number of profiles */
    bool force;                 /* Overwrite modified files */
    bool dry_run;               /* Don't actually deploy */
    bool prune;                 /* Remove untracked managed files */
    bool verbose;               /* Print verbose output */
    bool skip_existing;         /* Skip files that already exist */
    bool skip_unchanged;        /* Skip files that match profile content (default: true) */
    const char *mode;           /* Profile mode override: "local", "auto", "all" (CLI only) */
} cmd_apply_options_t;

/**
 * Apply profiles to filesystem
 *
 * Orchestrates profile detection/loading, manifest building,
 * pre-flight checks, and deployment.
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_apply(git_repository *repo, const cmd_apply_options_t *opts);

#endif /* DOTTA_CMD_APPLY_H */
