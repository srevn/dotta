/**
 * profile.h - Profile lifecycle management
 *
 * Explicit profile management: list, fetch, activate, deactivate, validate.
 * Separates profile availability from activation.
 */

#ifndef DOTTA_CMD_PROFILE_H
#define DOTTA_CMD_PROFILE_H

#include <git2.h>
#include <stdbool.h>

#include "types.h"

/**
 * Profile command subcommands
 */
typedef enum {
    PROFILE_LIST,        /* List profiles (active vs available) */
    PROFILE_FETCH,       /* Fetch profiles without activating */
    PROFILE_ACTIVATE,    /* Add profiles to active set */
    PROFILE_DEACTIVATE,  /* Remove profiles from active set */
    PROFILE_VALIDATE     /* Validate and fix state consistency */
} profile_subcommand_t;

/**
 * Profile command options
 */
typedef struct {
    profile_subcommand_t subcommand;

    /* Profile names (for activate/deactivate/fetch) */
    const char **profiles;
    size_t profile_count;

    /* List options */
    bool show_remote;       /* Show remote profiles */
    bool show_available;    /* Show available (non-active) profiles */

    /* Fetch options */
    bool fetch_all;         /* Fetch all remote profiles */

    /* Activate/deactivate options */
    bool all_profiles;      /* Activate/deactivate all local profiles */

    /* Validate options */
    bool fix;               /* Auto-fix issues */

    /* Common options */
    bool verbose;
    bool quiet;
} cmd_profile_options_t;

/**
 * Execute profile command
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_profile(git_repository *repo, const cmd_profile_options_t *opts);

#endif /* DOTTA_CMD_PROFILE_H */
