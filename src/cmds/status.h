/**
 * status.h - Show status of managed files
 *
 * Displays deployment status and local modifications.
 */

#ifndef DOTTA_CMD_STATUS_H
#define DOTTA_CMD_STATUS_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * Command options
 *
 * `show_local` / `show_remote` are derived by `status_post_parse` from the explicit
 * `want_local` / `want_remote` intent flags: neither given, both halves, and
 * under `raw` the workspace's alone, the remote's state having no raw form.
 */
typedef struct {
    char **profiles;            /* Profile names (NULL = use state/config) */
    size_t profile_count;       /* Number of profiles */
    int verbosity;              /* dotta_verbosity_t (int for ARGS_FLAG_SET) */
    bool no_fetch;              /* Skip fetch before remote status check */
    bool all_profiles;          /* Show all profiles, not just enabled ones */
    bool full;                  /* List the whole manifest: every active path with its state */
    bool raw;                   /* Print the items for a program, the workspace's half alone */

    /* Intent flags (written by ARGS_FLAG; derived outputs below). */
    bool want_local;            /* --local was given */
    bool want_remote;           /* --remote was given */

    /* Derived by post_parse — consumers read these. */
    bool show_local;            /* Show filesystem status */
    bool show_remote;           /* Show remote sync status */
} cmd_status_options_t;

/**
 * Show status of managed files
 *
 * Compares the filesystem with the view and the record, and each profile with
 * its remote: the enabled profiles, the workspace's diverged items in the sections
 * that settle them, the remote's rows, and a summary of each half. Under --raw,
 * the workspace's items alone, for a program: each once, the sections' in their
 * order, then under --full the clean rows (cmds/status.c status_write).
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t cmd_status(const dotta_ctx_t *ctx, const cmd_status_options_t *opts);

/**
 * Spec-engine command specification for `dotta status`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in status.c beside
 * the post_parse and dispatch wrappers.
 */
extern const args_command_t spec_status;

#endif /* DOTTA_CMD_STATUS_H */
