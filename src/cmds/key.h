/**
 * key.h - Encryption key management command
 *
 * Manages encryption passphrases and key caching lifecycle.
 * Provides explicit control over the keymanager session state.
 */

#ifndef DOTTA_CMD_KEY_H
#define DOTTA_CMD_KEY_H

#include <git2.h>
#include <stdbool.h>

#include "types.h"

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
 */
typedef struct {
    key_action_t action;

    /* Common options */
    bool verbose;
} cmd_key_options_t;

/**
 * Execute key command
 *
 * Manages encryption key lifecycle:
 * - set: Prompts for passphrase and caches it in memory
 * - clear: Securely clears cached passphrase
 * - status: Shows encryption configuration and key cache status
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_key(git_repository *repo, const cmd_key_options_t *opts);

#endif /* DOTTA_CMD_KEY_H */
