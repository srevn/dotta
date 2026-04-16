/**
 * status.h - Show status of managed files
 *
 * Displays deployment status and local modifications.
 */

#ifndef DOTTA_CMD_STATUS_H
#define DOTTA_CMD_STATUS_H

#include <git2.h>
#include <types.h>

#include "base/args.h"

/**
 * Command options
 *
 * `show_local` / `show_remote` are derived by `status_post_parse`
 * from the explicit `want_local` / `want_remote` intent flags. If
 * neither was given, both derived fields are true (show both scopes,
 * matching the legacy default).
 */
typedef struct {
    char **profiles;            /* Profile names (NULL = use state/config) */
    size_t profile_count;       /* Number of profiles */
    bool verbose;               /* Print verbose output */
    bool no_fetch;              /* Skip fetch before remote status check */
    bool all_profiles;          /* Show all profiles, not just enabled ones */
    bool no_sudo;               /* Skip privilege elevation (ownership checks disabled) */

    /* Intent flags (written by ARGS_FLAG; derived outputs below). */
    int want_local;             /* 1 if --local was seen */
    int want_remote;            /* 1 if --remote was seen */

    /* Derived by post_parse — consumers read these. */
    bool show_local;            /* Show filesystem status */
    bool show_remote;           /* Show remote sync status */
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
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_status(const args_ctx_t *ctx, const cmd_status_options_t *opts);

/**
 * Spec-engine command specification for `dotta status`.
 *
 * Registered in cmds/registry.c. Defined in status.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_status;

#endif /* DOTTA_CMD_STATUS_H */
