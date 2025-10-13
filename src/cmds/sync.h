/**
 * sync.h - Intelligent synchronization command
 *
 * Combines update, fetch, and conditional push into a single safe operation.
 * The "do what I mean" command for dotfile synchronization.
 */

#ifndef DOTTA_CMD_SYNC_H
#define DOTTA_CMD_SYNC_H

#include <git2.h>

#include "core/upstream.h"
#include "types.h"

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
    const char **profiles;       /* Specific profiles (NULL = use state/config) */
    size_t profile_count;        /* Number of profiles */
    const char *message;         /* Commit message for update */
    bool dry_run;                /* Preview only */
    bool no_push;                /* Update but don't push */
    bool no_pull;                /* Don't pull remote changes (push-only) */
    bool verbose;                /* Verbose output */
    bool include_new;            /* Include new files from tracked directories */
    bool only_new;               /* Only process new files (ignore modified) */
    bool skip_undeployed;        /* Allow sync with undeployed files (skip workspace check) */
    const char *diverged;        /* Divergence strategy override (CLI only) */
} cmd_sync_options_t;

/**
 * Sync command implementation
 *
 * Intelligently synchronizes local changes with remote repository.
 * Combines update + fetch + conditional push with safety checks.
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_sync(git_repository *repo, const cmd_sync_options_t *opts);

#endif /* DOTTA_CMD_SYNC_H */
