/**
 * sync.h - Remote synchronization command
 *
 * Synchronizes local repository with remote (fetch, pull, push).
 * Handles branch divergence resolution strategies.
 * Requires clean workspace - use 'update' command first to commit local changes.
 */

#ifndef DOTTA_CMD_SYNC_H
#define DOTTA_CMD_SYNC_H

#include <git2.h>
#include <types.h>

#include "core/upstream.h"

/* Use upstream module's state tracking */
typedef upstream_state_t sync_branch_state_t;

/**
 * Divergence resolution strategy for sync command
 *
 * Note: This is a sync-level enum. The core/divergence module has its own
 * strategy enum. These are mapped in sync.c's switch statements.
 */
typedef enum {
    DIVERGE_WARN,         /* Warn user, manual resolution (default) */
    DIVERGE_REBASE,       /* Rebase local onto remote */
    DIVERGE_MERGE,        /* Create merge commit */
    DIVERGE_OURS,         /* Keep local, force push (destructive) */
    DIVERGE_THEIRS        /* Keep remote, reset local (destructive) */
} sync_divergence_strategy_t;

/**
 * Sync command options
 */
typedef struct {
    char **profiles;             /* Specific profiles (NULL = use state/config) */
    size_t profile_count;        /* Number of profiles */
    bool dry_run;                /* Preview only */
    bool no_push;                /* Don't push (fetch and analyze only) */
    bool no_pull;                /* Don't pull remote changes (push-only) */
    bool verbose;                /* Verbose output */
    bool force;                  /* Force sync even with uncommitted changes */
    const char *diverged;        /* Divergence strategy override (CLI only) */
} cmd_sync_options_t;

/**
 * Sync command implementation
 *
 * Synchronizes local repository with remote repository.
 * Fetches from remote, analyzes branch states, and pushes/pulls as needed.
 * Handles divergence resolution using configured strategy.
 *
 * Requires workspace to be clean (no uncommitted changes) unless --force is used.
 * Run 'update' command first to commit local changes to profile branches.
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_sync(git_repository *repo, const cmd_sync_options_t *opts);

#endif /* DOTTA_CMD_SYNC_H */
