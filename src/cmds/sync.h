/**
 * sync.h - The store meets its remote
 *
 * One session (sys/remote.h): what the remote holds read once; the fetch on that
 * connection, each tracking ref moved forward alone; the epoch reconciled; then
 * each enabled row — its branch here, or none — read against the remote three
 * ways (remote_relation_t) and given one act: a push, a pull, the profile's merge,
 * a deletion learned, a branch created back, or none, said with its way out.
 * The run is decided whole before any row acts — a merge's draft opened there,
 * so a conflict refuses its row before anything moves, in a dry run too — and
 * nothing is asked: no act discards a commit. A merge keeps both histories as
 * its parents, its claims composed name by name over the merged tree
 * (core/profiles.h profile_draft_merge); a learned deletion takes a branch only
 * where the remote held all of it; a re-creation is taken only where the branch
 * here holds nothing beyond the old line; and a conflict refuses its row until
 * --conflicts settles it. An act that writes a branch here off the remote moves
 * its tracking ref to the remote's head after it. Then the receipt, and the
 * Manifest block over two views the live run builds itself. The files on disk
 * and the record are no part of it: apply lands what a pull brought, and update
 * commits what disk holds — and an enabled row whose profile the remote deleted
 * stays, said at every sync, until `profile disable`.
 */

#ifndef DOTTA_CMD_SYNC_H
#define DOTTA_CMD_SYNC_H

#include <runtime.h>
#include <types.h>

#include "core/profiles.h"

/**
 * Sync command options
 */
typedef struct {
    char **profiles;             /* The enabled profiles to sync (NULL: every one) */
    size_t profile_count;        /* Number of profiles */
    bool dry_run;                /* Preview only */
    bool no_push;                /* The remote's branches stay as they are: every push skipped */
    int verbosity;               /* dotta_verbosity_t (int for ARGS_FLAG_SET) */
    const char *conflicts;       /* --conflicts' word (NULL: none) */
    profile_side_t conflicts_side; /* Its side, PROFILE_SIDE_NONE without it (sync_post_parse) */
} cmd_sync_options_t;

/**
 * Sync command implementation
 *
 * The run, in its order: the pre-sync hook; the remote's listing, the fetch and
 * the epoch; then the run decided whole — each row read three ways, its act off
 * its reading, a merge's draft opened, a conflict refusing its row — before any
 * row acts; then the view before, the acts, which say nothing but the remote's
 * words a push brings, and their receipt — beneath a merge that landed, each
 * name its two sides took, one deleting it and the other removing it, and beneath
 * a merge each conflict it met, refusing it or kept for --conflicts' side — the
 * Manifest block over the view after and the import's health, the summary and
 * its remedies, and post-sync.
 *
 * A dry run speaks for the Git phase alone: what each row would do, a merge's
 * conflicts among it, and its end. It builds no view: the view a pull would leave
 * is unknown without the pull, so its health is the live run's, and the standing
 * view's is status's.
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
