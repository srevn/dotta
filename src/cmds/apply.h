/**
 * apply.h - Apply profiles to filesystem
 *
 * Deploys files from profile branches to the filesystem.
 */

#ifndef DOTTA_CMD_APPLY_H
#define DOTTA_CMD_APPLY_H

#include <git2.h>
#include <types.h>

/**
 * Command options
 */
typedef struct {
    char **profiles;            /* Profile names (NULL = use state/config) */
    size_t profile_count;       /* Number of profiles */
    bool force;                 /* Overwrite modified files */
    bool dry_run;               /* Don't actually deploy */
    bool keep_orphans;          /* Don't remove orphaned files (opt-out from default cleanup) */
    bool verbose;               /* Print verbose output */
    bool skip_existing;         /* Skip files that already exist */
    bool skip_unchanged;        /* Skip files that match profile content (default: true) */
    char **exclude_patterns;    /* Exclude patterns (glob) - read-only */
    size_t exclude_count;       /* Number of exclude patterns */

    /* Privilege re-exec support */
    int argc;                   /* Original argc (for privilege re-exec) */
    char **argv;                /* Original argv (for privilege re-exec) */
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
