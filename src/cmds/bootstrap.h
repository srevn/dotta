/**
 * bootstrap.h - Bootstrap command
 *
 * Executes bootstrap scripts for profiles.
 */

#ifndef DOTTA_CMD_BOOTSTRAP_H
#define DOTTA_CMD_BOOTSTRAP_H

#include <stdbool.h>

#include "types.h"

/**
 * Bootstrap command options
 */
typedef struct {
    const char **profiles;      /* Specific profiles to bootstrap (NULL = auto-detect) */
    size_t profile_count;       /* Number of profiles */
    bool all_profiles;          /* Bootstrap all available profiles */
    bool edit;                  /* Edit bootstrap script */
    bool show;                  /* Show bootstrap script content */
    bool list;                  /* List bootstrap scripts */
    bool dry_run;               /* Show what would be executed without running */
    bool yes;                   /* Skip confirmation prompts */
    bool continue_on_error;     /* Continue if a bootstrap script fails */
} cmd_bootstrap_options_t;

/**
 * Execute bootstrap command
 *
 * @param opts Bootstrap options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_bootstrap(const cmd_bootstrap_options_t *opts);

#endif /* DOTTA_CMD_BOOTSTRAP_H */
