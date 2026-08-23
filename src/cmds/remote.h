/**
 * remote.h - Manage remote repositories
 *
 * Provides intuitive, dotta-native interface for managing git remotes. Essential
 * for completing the dotta init workflow.
 */

#ifndef DOTTA_CMD_REMOTE_H
#define DOTTA_CMD_REMOTE_H

#include <git2.h>
#include <runtime.h>
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
 *
 * `subcommand` is set by the subcommand's `init_defaults`; the operands are
 * its positional rows.
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
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_remote(const dotta_ctx_t *ctx, const cmd_remote_options_t *opts);

/**
 * Spec-engine command specification for `dotta remote`: a tree of `list`
 * (the default), `add`, `remove`, `set-url`, `rename` and `show`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in remote.c
 * beside the subcommand specs and the dispatch wrapper.
 */
extern const args_command_t spec_remote;

#endif /* DOTTA_CMD_REMOTE_H */
