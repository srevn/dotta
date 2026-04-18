/**
 * profile.h - Profile lifecycle management
 *
 * Explicit profile management: list, fetch, enable, disable, validate.
 * Separates profile availability from management.
 */

#ifndef DOTTA_CMD_PROFILE_H
#define DOTTA_CMD_PROFILE_H

#include <git2.h>
#include <runtime.h>
#include <stdbool.h>
#include <types.h>

/**
 * Profile command subcommands
 */
typedef enum {
    PROFILE_LIST,        /* List profiles (enabled vs available) */
    PROFILE_FETCH,       /* Fetch profiles without enabling */
    PROFILE_ENABLE,      /* Add profiles to enabled set */
    PROFILE_DISABLE,     /* Remove profiles from enabled set */
    PROFILE_REORDER,     /* Reorder enabled profiles */
    PROFILE_VALIDATE     /* Validate and fix state consistency */
} profile_subcommand_t;

/**
 * Profile command options
 */
typedef struct {
    profile_subcommand_t subcommand;

    /* Profile names (for enable/disable/fetch) */
    char **profiles;
    size_t profile_count;

    /* Custom prefix (for enable with custom/ files) */
    const char *custom_prefix;

    /* List options */
    bool show_remote;       /* Show remote profiles */
    bool show_available;    /* Show available (non-enabled) profiles */

    /* Fetch options */
    bool fetch_all;         /* Fetch all remote profiles */

    /* Enable/disable options */
    bool all_profiles;      /* Enable/disable all local profiles */
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
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_profile(const dotta_ctx_t *ctx, const cmd_profile_options_t *opts);

/**
 * Spec-engine command specification for `dotta profile`.
 *
 * Subcommand tree: list / fetch / enable / disable / reorder / validate.
 * All subs share `cmd_profile_options_t` and dispatch through a single
 * wrapper that calls cmd_profile(). Registered in cmds/registry.c;
 * defined in profile.c beside the dispatch wrapper.
 */
extern const args_command_t spec_profile;

#endif /* DOTTA_CMD_PROFILE_H */
