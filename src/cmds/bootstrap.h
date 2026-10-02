/**
 * bootstrap.h - Bootstrap command
 *
 * Executes bootstrap scripts for profiles.
 */

#ifndef DOTTA_CMD_BOOTSTRAP_H
#define DOTTA_CMD_BOOTSTRAP_H

#include <runtime.h>
#include <stdbool.h>
#include <types.h>

/**
 * What the command does with its selection
 *
 * One field, not three bools: the three flags are one FLAG_SET group, so the
 * engine refuses two of them on one line (base/args.h "Tri-state flags"), and
 * cmd_bootstrap switches on the one given. No flag runs the scripts.
 */
typedef enum {
    BOOTSTRAP_MODE_RUN = 0,   /* No flag given: run the selection's scripts */
    BOOTSTRAP_MODE_EDIT,      /* --edit: edit the one named profile's script */
    BOOTSTRAP_MODE_SHOW,      /* --show: print the one named profile's script */
    BOOTSTRAP_MODE_LIST       /* --list: list the selection's scripts */
} bootstrap_mode_t;

/**
 * Bootstrap command options
 */
typedef struct {
    char **profiles;            /* Specific profiles to bootstrap (NULL = the enabled set) */
    size_t profile_count;       /* Number of profiles */
    bool all_profiles;          /* Bootstrap all available profiles */
    int mode;                   /* bootstrap_mode_t (int for ARGS_FLAG_SET) */
    bool dry_run;               /* Show what would be executed without running */
    bool yes;                   /* Skip confirmation prompts */
    bool continue_on_error;     /* Continue if a bootstrap script fails */
} cmd_bootstrap_options_t;

/**
 * Execute bootstrap command
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Bootstrap options (must not be NULL)
 * @return Error or NULL on success
 */
error_t cmd_bootstrap(const dotta_ctx_t *ctx, const cmd_bootstrap_options_t *opts);

/**
 * Spec-engine command specification for `dotta bootstrap`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in bootstrap.c beside
 * the dispatch wrapper.
 */
extern const args_command_t spec_bootstrap;

#endif /* DOTTA_CMD_BOOTSTRAP_H */
