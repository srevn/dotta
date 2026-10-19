/**
 * hooks.h - Hook execution system
 *
 * A hook is a file in the configured hooks directory, named for its phase and
 * its command — pre-add, post-sync — and run before or after that command where
 * the file is executable: the file is the switch, git's, and the configuration
 * holds none beside it. The entire public surface is two functions — hook_fire_pre
 * and hook_fire_post — plus the value type used to describe one invocation.
 */

#ifndef DOTTA_HOOKS_H
#define DOTTA_HOOKS_H

#include <stdbool.h>
#include <stddef.h>
#include <types.h>

/**
 * Hook-bearing command
 *
 * The commands that invoke pre/post hooks. Each names a pre-<cmd> / post-<cmd>
 * hook pair by its word.
 */
typedef enum {
    HOOK_CMD_ADD,
    HOOK_CMD_REMOVE,
    HOOK_CMD_APPLY,
    HOOK_CMD_UPDATE,
    HOOK_CMD_SYNC,
} hook_cmd_t;

/**
 * Hook invocation description
 *
 * Describes one pre/post hook pair. Value type — callers allocate on the stack
 * and populate via designated initializers. All pointer fields are borrowed;
 * callers must keep them valid for the span between hook_fire_pre() and
 * hook_fire_post().
 *
 * Fields:
 *   cmd        Which command is firing (ADD/REMOVE/APPLY/UPDATE/SYNC).
 *   profile    NULL → no DOTTA_PROFILE env. Single profile name for
 *              add/remove; space-joined profile list for apply/update/sync.
 *   paths      NULL → DOTTA_PATH_COUNT=0 alone. Otherwise borrowed array, each
 *              a file or a directory: add's and update's arguments as given (none
 *              on an update given none), remove's every path a claim the removal
 *              takes stands at — its name where this machine places the claim
 *              nowhere (cmds/remove.c remove_hook_paths). Apply and sync hand none.
 *   path_count Number of entries in paths (0 if paths is NULL).
 *   extras     NULL → no extra env vars. Otherwise NULL-terminated
 *              "DOTTA_<KEY>=VALUE" string array, the command's own surface,
 *              appended after the standard DOTTA_* and DOTTA_PATH_N surface.
 *              The process's environment comes first with every DOTTA_* of its
 *              left out (utils/config.h config_child_env), so nothing shadows
 *              them. Borrowed pointers — must outlive the fire.
 *   dry_run    Sets DOTTA_DRY_RUN for pre-hook; suppresses post-hook.
 */
typedef struct {
    hook_cmd_t cmd;
    const char *profile;
    char *const *paths;
    size_t path_count;
    char *const *extras;
    bool dry_run;
} hook_invocation_t;

/**
 * Fire a pre-command hook
 *
 * Builds a hook environment from inv and runs the pre-<cmd> hook where its file
 * is executable. Absent — nothing at its name, or a link to nothing — nothing
 * runs and nothing is said; what the exec would refuse — no execute bit, no regular
 * file — is ignored with a notice naming why, so a guard that loses its execute
 * bit fails open, said by its notice; and a hooks directory whose names cannot
 * be looked up is said once, naming the directory. On failure, prints captured
 * hook output (if any) at OUTPUT_QUIET, the refusal's reason at every level,
 * and returns the refusal, which names its hook (Hook 'pre-<cmd>' …, or its path
 * where the process layer could not spawn it). Callers should goto-cleanup on
 * non-NULL return.
 *
 * The hook's stdout and stderr go into a file in the temporary directory, read
 * once the hook exits — the wait is on the hook alone, so a task it leaves running
 * holds nothing — its first PROCESS_CAPTURE_MAX bytes kept and the rest counted
 * ("... and N more bytes"): a hook is never stopped for what it writes
 * (sys/process.h PROCESS_OUTPUT_FILE). So a runnable hook needs a temporary
 * directory where a file can be created, or it is refused as a spawn the process
 * layer could not make; a hook writing without bound fills that directory while
 * it runs; and what a hook prints stands there until the file's last close.
 *
 * A runnable hook that could not be run, or ran and failed, is ERR_INTERNAL —
 * an exec that failed, a timeout, a signal, a non-zero exit — never ERR_PERMISSION,
 * however permission-shaped the cause: that code is a refusal an identity met
 * (base/error.h "Codes"), and a hook that did not run is none. Beside them a
 * context past 10,000 paths is ERR_INVALID_ARG, and a spawn the process layer
 * could not make keeps its own code (sys/process.h process_run) — a temporary
 * directory whose bits refuse the invoker the file is ERR_PERMISSION — and nothing
 * branches on the code.
 *
 * The hook's DOTTA_REPO_DIR is the store's directory the configuration settled
 * (`config->repo_dir`), its DOTTA_CONFIG_FILE the file the configuration was
 * read from (`config->file`) — both absolute, so a dotta the hook runs is the
 * run's own (utils/config.h config_child_env) — and its path the configured hooks
 * directory's.
 */
error_t hook_fire_pre(
    const config_t *config,
    output_t *out,
    const hook_invocation_t *inv
);

/**
 * Fire a post-command hook
 *
 * No-op if inv->dry_run is true. Otherwise builds a hook environment from inv
 * and runs the post-<cmd> hook where its file is executable, as hook_fire_pre
 * runs its own — a hooks directory whose names cannot be looked up said by the
 * pre-fire alone, which every post-fire follows. Failures never propagate: on
 * error, prints a warning and any captured hook output, then swallows the error.
 * Its environment is hook_fire_pre's.
 */
void hook_fire_post(
    const config_t *config,
    output_t *out,
    const hook_invocation_t *inv
);

#endif /* DOTTA_HOOKS_H */
