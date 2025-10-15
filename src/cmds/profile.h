/**
 * profile.h - Profile lifecycle management
 *
 * Explicit profile management: list, fetch, select, unselect, validate.
 * Separates profile availability from selection.
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
    PROFILE_FETCH,       /* Fetch profiles without selecting */
    PROFILE_SELECT,      /* Add profiles to active set */
    PROFILE_UNSELECT,    /* Remove profiles from active set */
    PROFILE_REORDER,     /* Reorder active profiles */
    PROFILE_VALIDATE     /* Validate and fix state consistency */
} profile_subcommand_t;

/**
 * Profile command options
 */
typedef struct {
    profile_subcommand_t subcommand;

    /* Profile names (for select/unselect/fetch) */
    const char **profiles;
    size_t profile_count;

    /* List options */
    bool show_remote;       /* Show remote profiles */
    bool show_available;    /* Show available (non-active) profiles */

    /* Fetch options */
    bool fetch_all;         /* Fetch all remote profiles */

    /* Select/unselect options */
    bool all_profiles;      /* Select/unselect all local profiles */
    bool dry_run;           /* Show what would be changed without doing it */

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
