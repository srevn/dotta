/**
 * remote.h - Manage remote repositories
 *
 * Provides intuitive, dotta-native interface for managing git remotes.
 * Essential for completing the dotta init workflow.
 */

#ifndef DOTTA_CMD_REMOTE_H
#define DOTTA_CMD_REMOTE_H

#include <git2.h>
#include <types.h>

/**
 * Remote subcommand type
 */
typedef enum {
    REMOTE_LIST,       /* List remotes */
    REMOTE_ADD,        /* Add new remote */
    REMOTE_REMOVE,     /* Remove remote */
    REMOTE_SET_URL,    /* Change remote URL */
    REMOTE_RENAME,     /* Rename remote */
    REMOTE_SHOW        /* Show remote details */
} remote_subcommand_t;

/**
 * Remote command options
 */
typedef struct {
    remote_subcommand_t subcommand;
    const char *name;        /* Remote name */
    const char *url;         /* Remote URL (for add/set-url) */
    const char *new_name;    /* New name (for rename) */
    bool verbose;            /* Show URLs (for list) */
} cmd_remote_options_t;

/**
 * Remote command implementation
 *
 * Manages git remote repositories with an intuitive interface.
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_remote(git_repository *repo, const cmd_remote_options_t *opts);

#endif /* DOTTA_CMD_REMOTE_H */
