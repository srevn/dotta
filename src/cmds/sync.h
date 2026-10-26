/**
 * sync.h - Remote synchronization command
 *
 * Exchanges commits with the remote (fetch, pull, push), each profile's branch
 * against its remote's, a divergence by the strategy. The files on disk and the
 * record are no part of it: apply lands what a pull brought, and update commits
 * what disk holds.
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
    const char *diverged;        /* --diverged's word (NULL: the config's strategy) */
    sync_strategy_t diverged_strategy; /* Its strategy, iff diverged (sync_post_parse) */
} cmd_sync_options_t;

/**
 * Sync command implementation
 *
 * The run, in its order: the pre-sync hook; the epoch, the fetch and each profile's
 * state against the remote; then the run decided whole, a verdict a profile from
 * its state, the divergence strategy and the user's word (--no-push, --no-pull,
 * auto_pull), and one question where a force push or a reset discards commits
 * and the configuration asks one — beneath the preview, before any profile acts;
 * then the acts and their receipt — beneath a resolution that landed, each name
 * its two sides took, one deleting it and the other removing it — the Manifest
 * block, and post-sync.
 *
 * A dry run speaks for the Git phase alone: what each verdict would do, and its
 * end. The view a pull would leave is unknown without the pull, so the standing
 * view's health and the apply hint are status's and the live run's.
 *
 * The run reads no file on disk and writes no record, so an edit not yet committed
 * is not sent, and a pull over it leaves it where it stands for the next load
 * to read.
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
