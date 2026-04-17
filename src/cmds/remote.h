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

#include "cmds/runtime.h"

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
 * `subcommand`, `name`, `url`, and `new_name` are populated by
 * remote_post_parse from the positional bucket (args[0] is the
 * subcommand verb; the remainder are its operands). The bareword
 * fallback `dotta remote <name>` lands in REMOTE_SHOW with name=args[0].
 */
typedef struct {
    remote_subcommand_t subcommand;
    const char *name;        /* Remote name */
    const char *url;         /* Remote URL (for add/set-url) */
    const char *new_name;    /* New name (for rename) */
    bool verbose;            /* Show URLs (for list) */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
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
 * Spec-engine command specification for `dotta remote`.
 *
 * Single spec + post_parse — not a subcommand tree. Every "subcommand"
 * shares the same options struct and the same flag set; the discriminator
 * is the first positional, so a tree of seven near-identical subspecs
 * would be redundant. post_parse maps (positional_count, args[0]) onto
 * remote_subcommand_t and preserves the bareword fallback `dotta remote
 * <name>` → `remote show <name>`.
 *
 * Registered in cmds/registry.c; defined in remote.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_remote;

#endif /* DOTTA_CMD_REMOTE_H */
