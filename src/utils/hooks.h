/**
 * hooks.h - Hook execution system
 *
 * Provides pre/post command hooks for extensibility. Hooks are shell
 * scripts that run before or after commands. The entire public surface
 * is two functions — hook_fire_pre and hook_fire_post — plus the value
 * type used to describe one invocation.
 */

#ifndef DOTTA_HOOKS_H
#define DOTTA_HOOKS_H

#include <stdbool.h>
#include <stddef.h>
#include <types.h>

/**
 * Hook-bearing command
 *
 * The four commands that invoke pre/post hooks. Maps internally to a
 * pre_<cmd> / post_<cmd> hook script pair.
 */
typedef enum {
    HOOK_CMD_ADD,
    HOOK_CMD_REMOVE,
    HOOK_CMD_APPLY,
    HOOK_CMD_UPDATE,
} hook_cmd_t;

/**
 * Hook invocation description
 *
 * Describes one pre/post hook pair. Value type — callers allocate on
 * the stack and populate via designated initializers. All pointer
 * fields are borrowed; callers must keep them valid for the span
 * between hook_fire_pre() and hook_fire_post().
 *
 * Fields:
 *   cmd        Which command is firing (ADD/REMOVE/APPLY/UPDATE).
 *   profile    NULL → no DOTTA_PROFILE env. Single profile name for
 *              add/remove; space-joined profile list for apply/update.
 *   files      NULL → no DOTTA_FILE_* env. Otherwise borrowed array.
 *   file_count Number of entries in files (0 if files is NULL).
 *   dry_run    Sets DOTTA_DRY_RUN for pre-hook; suppresses post-hook.
 */
typedef struct {
    hook_cmd_t cmd;
    const char *profile;
    char *const *files;
    size_t file_count;
    bool dry_run;
} hook_invocation_t;

/**
 * Fire a pre-command hook
 *
 * Builds a hook environment from inv and runs the pre_<cmd> hook
 * script (if configured and present). On failure, prints captured hook
 * output (if any) at OUTPUT_NORMAL and returns a wrapped error
 * "Pre-<cmd> hook failed". Callers should goto-cleanup on non-NULL
 * return.
 *
 * `repo_dir` is exported to the hook as DOTTA_REPO_DIR. Expected to
 * come from ctx->repo_path — the dispatcher already resolved it when
 * opening the repo, so callers borrow the string rather than re-
 * resolving. NULL suppresses the DOTTA_REPO_DIR export.
 */
error_t *hook_fire_pre(
    const config_t *config,
    output_t *out,
    const char *repo_dir,
    const hook_invocation_t *inv
);

/**
 * Fire a post-command hook
 *
 * No-op if inv->dry_run is true. Otherwise builds a hook environment
 * from inv and runs the post_<cmd> hook script (if configured and
 * present). Failures never propagate: on error, prints a warning and
 * any captured hook output, then swallows the error.
 *
 * `repo_dir` is exported as DOTTA_REPO_DIR (see hook_fire_pre).
 */
void hook_fire_post(
    const config_t *config,
    output_t *out,
    const char *repo_dir,
    const hook_invocation_t *inv
);

#endif /* DOTTA_HOOKS_H */
