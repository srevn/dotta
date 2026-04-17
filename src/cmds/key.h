/**
 * key.h - Encryption key management command
 *
 * Manages encryption passphrases and key caching lifecycle.
 * Provides explicit control over the keymgr session state.
 */

#ifndef DOTTA_CMD_KEY_H
#define DOTTA_CMD_KEY_H

#include <git2.h>
#include <stdbool.h>
#include <types.h>

#include "cmds/runtime.h"

/**
 * Key command actions
 */
typedef enum {
    KEY_ACTION_SET,      /* Set/cache encryption passphrase */
    KEY_ACTION_CLEAR,    /* Clear cached passphrase */
    KEY_ACTION_STATUS    /* Show key and encryption status */
} key_action_t;

/**
 * Key command options
 *
 * `action` is derived by `key_post_parse` from the first positional
 * token (set | clear | status).
 */
typedef struct {
    /* User-facing (read by cmd_key). */
    key_action_t action;
    bool verbose;

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_key_options_t;

/**
 * Execute key command
 *
 * Manages encryption key lifecycle:
 * - set: Prompts for passphrase and caches it in memory
 * - clear: Securely clears cached passphrase
 * - status: Shows encryption configuration and key cache status
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_key(const dotta_ctx_t *ctx, const cmd_key_options_t *opts);

/**
 * Spec-engine command specification for `dotta key`.
 *
 * Registered in cmds/registry.c. Defined in key.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_key;

#endif /* DOTTA_CMD_KEY_H */
