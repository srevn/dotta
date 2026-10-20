/**
 * sync.h - Remote synchronization command
 *
 * Synchronizes local repository with remote (fetch, pull, push). Handles branch
 * divergence resolution strategies. Requires clean workspace - use 'update' command
 * first to commit local changes.
 */

#ifndef DOTTA_CMD_SYNC_H
#define DOTTA_CMD_SYNC_H

#include <config.h>
#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * Sync command options
 */
typedef struct {
    char **profiles;             /* Specific profiles (NULL = use state/config) */
    size_t profile_count;        /* Number of profiles */
    bool dry_run;                /* Preview only */
    bool no_push;                /* Pull only: the remote's branches stay as they are */
    bool no_pull;                /* Push only: the local branches stay as they are */
    int verbosity;               /* dotta_verbosity_t (int for ARGS_FLAG_SET) */
    bool force;                  /* Force sync even with uncommitted changes */
    const char *diverged;        /* --diverged's word (NULL: the config's strategy) */
    sync_strategy_t diverged_strategy; /* Its strategy, iff diverged (sync_post_parse) */
} cmd_sync_options_t;

/**
 * Sync command implementation
 *
 * The run, in its order: the workspace guard — none under --force — then the
 * pre-sync hook and the guard's question; the epoch, the fetch and each profile's
 * state against the remote; then the run decided whole, a verdict a profile from
 * its state, the divergence strategy and the user's word (--no-push, --no-pull,
 * auto_pull), and one question where a force push or a reset discards commits
 * and the configuration asks one — beneath the preview, before any profile acts;
 * then the acts, their receipt, the Manifest block, and post-sync.
 *
 * A dry run speaks for the Git phase alone: what each verdict would do, and its
 * end. The view a pull would leave is unknown without the pull, so the standing
 * view's health and the apply hint are status's and the live run's.
 *
 * Requires workspace to be clean (no uncommitted changes) unless --force is used.
 * Run 'update' command first to commit local changes to profile branches.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t cmd_sync(const dotta_ctx_t *ctx, const cmd_sync_options_t *opts);

/**
 * Spec-engine command specification for `dotta sync`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in sync.c beside
 * the dispatch wrapper.
 */
extern const args_command_t spec_sync;

#endif /* DOTTA_CMD_SYNC_H */
