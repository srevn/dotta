/**
 * key.c - Encryption key management command
 */

#include "key.h"

#include <git2.h>
#include <stdio.h>
#include <string.h>

#include "base/error.h"
#include "core/metadata.h"
#include "core/state.h"
#include "crypto/keymanager.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"

/**
 * Execute key set action
 *
 * Prompts user for passphrase and caches it in the global keymanager.
 */
static error_t *cmd_key_set(
    git_repository *repo,
    const cmd_key_options_t *opts
) {
    (void)repo;  /* Not needed for set operation */

    /* Load configuration to get session timeout */
    dotta_config_t *config = NULL;
    error_t *err = config_load(NULL, &config);
    if (err) {
        return error_wrap(err, "Failed to load configuration");
    }

    /* Check if encryption is enabled */
    if (!config->encryption_enabled) {
        config_free(config);
        return ERROR(ERR_VALIDATION,
                    "Encryption is disabled in configuration\n"
                    "Set 'encryption.enabled = true' in config file");
    }

    /* Get global keymanager */
    keymanager_t *key_mgr = keymanager_get_global(config);
    if (!key_mgr) {
        config_free(config);
        return ERROR(ERR_INTERNAL, "Failed to initialize key manager");
    }

    /* Check if key is already cached */
    if (keymanager_has_key(key_mgr)) {
        int64_t seconds_remaining = keymanager_time_until_expiry(key_mgr, NULL);
        if (seconds_remaining == -1) {
            printf("Note: A passphrase is already cached (no expiration)\n");
        } else if (seconds_remaining > 0) {
            printf("Note: A passphrase is already cached (expires in %ld seconds)\n",
                   (long)seconds_remaining);
        }
        printf("Enter a new passphrase to replace it.\n\n");
    }

    /* Prompt for passphrase */
    char *passphrase = NULL;
    size_t passphrase_len = 0;
    err = keymanager_prompt_passphrase("Enter encryption passphrase: ",
                                       &passphrase, &passphrase_len);
    if (err) {
        config_free(config);
        return error_wrap(err, "Failed to read passphrase");
    }

    /* Set passphrase in keymanager (derives and caches master key) */
    err = keymanager_set_passphrase(key_mgr, passphrase, passphrase_len);

    /* Securely clear passphrase from memory */
    if (passphrase) {
        memset(passphrase, 0, passphrase_len);
        free(passphrase);
    }

    if (err) {
        config_free(config);
        return error_wrap(err, "Failed to set passphrase");
    }

    /* Display success message */
    if (config->session_timeout == 0) {
        printf("✓ Passphrase set (will be prompted on each use)\n");
    } else if (config->session_timeout > 0) {
        printf("✓ Passphrase cached for %u seconds\n", config->session_timeout);
    } else {
        printf("✓ Passphrase cached (no expiration)\n");
    }

    if (opts->verbose) {
        printf("\nThe encryption key will be used for encrypting and decrypting files\n");
        printf("in all profiles until the cache expires or is explicitly cleared.\n");
    }

    config_free(config);
    return NULL;
}

/**
 * Execute key clear action
 *
 * Clears the cached passphrase from the global keymanager.
 */
static error_t *cmd_key_clear(
    git_repository *repo,
    const cmd_key_options_t *opts
) {
    (void)repo;  /* Not needed for clear operation */

    /* Load configuration */
    dotta_config_t *config = NULL;
    error_t *err = config_load(NULL, &config);
    if (err) {
        return error_wrap(err, "Failed to load configuration");
    }

    /* Check if encryption is enabled */
    if (!config->encryption_enabled) {
        config_free(config);
        return ERROR(ERR_VALIDATION,
                    "Encryption is disabled in configuration\n"
                    "Set 'encryption.enabled = true' in config file");
    }

    /* Get global keymanager */
    keymanager_t *key_mgr = keymanager_get_global(config);
    if (!key_mgr) {
        config_free(config);
        return ERROR(ERR_INTERNAL, "Failed to initialize key manager");
    }

    /* Check if key is cached in memory */
    bool had_key = keymanager_has_key(key_mgr);

    /* Always clear both memory and file cache (even if no in-memory key) */
    keymanager_clear(key_mgr);

    /* Display success message */
    if (had_key) {
        printf("✓ Encryption key cleared from memory and disk cache\n");
    } else {
        printf("✓ Disk cache cleared (no key was cached in memory)\n");
    }

    if (opts->verbose) {
        printf("\nCache location: ~/.cache/dotta/session\n");
        printf("\nYou will be prompted for your passphrase on the next\n");
        printf("operation that requires encryption or decryption.\n");
    }

    config_free(config);
    return NULL;
}

/**
 * Count encrypted files in current profiles
 *
 * Helper for status display.
 */
static error_t *count_encrypted_files(
    git_repository *repo,
    dotta_config_t *config,
    size_t *out_count
) {
    CHECK_NULL(repo);
    CHECK_NULL(config);
    CHECK_NULL(out_count);

    *out_count = 0;

    /* Load state to get enabled profiles */
    state_t *state = NULL;
    error_t *err = state_load(repo, &state);
    if (err) {
        /* No state file is not an error - no profiles deployed yet */
        if (error_code(err) == ERR_NOT_FOUND) {
            error_free(err);
            return NULL;
        }
        return error_wrap(err, "Failed to load state");
    }

    /* Get profile names from state */
    string_array_t *profile_names = NULL;
    err = state_get_profiles(state, &profile_names);
    if (err) {
        state_free(state);
        return error_wrap(err, "Failed to get profiles from state");
    }

    if (!profile_names || profile_names->count == 0) {
        if (profile_names) {
            string_array_free(profile_names);
        }
        state_free(state);
        return NULL;
    }

    /* Load metadata from all profiles */
    metadata_t *metadata = NULL;
    err = metadata_load_from_profiles(repo, profile_names, &metadata);
    if (err) {
        /* If metadata loading fails, it's not fatal for status display */
        if (error_code(err) == ERR_NOT_FOUND) {
            error_free(err);
            state_free(state);
            return NULL;
        }
        state_free(state);
        return error_wrap(err, "Failed to load metadata");
    }

    /* Count encrypted files */
    for (size_t i = 0; i < metadata->count; i++) {
        if (metadata->entries[i].encrypted) {
            (*out_count)++;
        }
    }

    metadata_free(metadata);
    string_array_free(profile_names);
    state_free(state);
    return NULL;
}

/**
 * Execute key status action
 *
 * Displays encryption configuration and key cache status.
 */
static error_t *cmd_key_status(
    git_repository *repo,
    const cmd_key_options_t *opts
) {
    /* Load configuration */
    dotta_config_t *config = NULL;
    error_t *err = config_load(NULL, &config);
    if (err) {
        return error_wrap(err, "Failed to load configuration");
    }

    /* Create output context */
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* Display encryption status */
    output_section(out, "Encryption Configuration");

    if (config->encryption_enabled) {
        output_printf(out, OUTPUT_NORMAL, "  Status: ");
        char *enabled_text = output_colorize(out, OUTPUT_COLOR_GREEN, "enabled");
        if (enabled_text) {
            output_printf(out, OUTPUT_NORMAL, "%s\n", enabled_text);
            free(enabled_text);
        } else {
            output_printf(out, OUTPUT_NORMAL, "enabled\n");
        }

        /* Show configuration parameters */
        if (opts->verbose) {
            output_printf(out, OUTPUT_NORMAL, "  KDF opslimit: %lu\n",
                         (unsigned long)config->encryption_opslimit);
            output_printf(out, OUTPUT_NORMAL, "  KDF memlimit: %zu bytes (%zu MB)\n",
                         config->encryption_memlimit,
                         config->encryption_memlimit / (1024 * 1024));
            output_printf(out, OUTPUT_NORMAL, "  KDF threads: %u\n",
                         (unsigned int)config->encryption_threads);
        }

        /* Show session timeout */
        output_printf(out, OUTPUT_NORMAL, "  Session timeout: ");
        if (config->session_timeout == 0) {
            output_printf(out, OUTPUT_NORMAL, "always prompt\n");
        } else if (config->session_timeout > 0) {
            output_printf(out, OUTPUT_NORMAL, "%u seconds", config->session_timeout);
            if (opts->verbose) {
                unsigned int minutes = config->session_timeout / 60;
                unsigned int hours = minutes / 60;
                if (hours > 0) {
                    output_printf(out, OUTPUT_NORMAL, " (%u hour%s)",
                                 hours, hours == 1 ? "" : "s");
                } else if (minutes > 0) {
                    output_printf(out, OUTPUT_NORMAL, " (%u minute%s)",
                                 minutes, minutes == 1 ? "" : "s");
                }
            }
            output_newline(out);
        } else {
            output_printf(out, OUTPUT_NORMAL, "no expiration\n");
        }

        /* Show auto-encrypt patterns */
        if (config->auto_encrypt_pattern_count > 0 && opts->verbose) {
            output_printf(out, OUTPUT_NORMAL, "  Auto-encrypt patterns: %zu\n",
                         config->auto_encrypt_pattern_count);
            for (size_t i = 0; i < config->auto_encrypt_pattern_count; i++) {
                output_printf(out, OUTPUT_NORMAL, "    - %s\n",
                             config->auto_encrypt_patterns[i]);
            }
        }
    } else {
        output_printf(out, OUTPUT_NORMAL, "  Status: ");
        char *disabled_text = output_colorize(out, OUTPUT_COLOR_RED, "disabled");
        if (disabled_text) {
            output_printf(out, OUTPUT_NORMAL, "%s\n", disabled_text);
            free(disabled_text);
        } else {
            output_printf(out, OUTPUT_NORMAL, "disabled\n");
        }

        output_printf(out, OUTPUT_NORMAL, "\n");
        output_printf(out, OUTPUT_NORMAL, "To enable encryption, add to config file:\n");
        output_printf(out, OUTPUT_NORMAL, "  [encryption]\n");
        output_printf(out, OUTPUT_NORMAL, "  enabled = true\n");

        config_free(config);
        output_free(out);
        return NULL;
    }

    output_newline(out);

    /* Display key cache status */
    output_section(out, "Key Cache Status");

    keymanager_t *key_mgr = keymanager_get_global(config);
    if (!key_mgr) {
        config_free(config);
        output_free(out);
        return ERROR(ERR_INTERNAL, "Failed to initialize key manager");
    }

    bool key_cached = keymanager_has_key(key_mgr);
    output_printf(out, OUTPUT_NORMAL, "  Key cached: ");

    if (key_cached) {
        char *yes_text = output_colorize(out, OUTPUT_COLOR_GREEN, "yes");
        if (yes_text) {
            output_printf(out, OUTPUT_NORMAL, "%s", yes_text);
            free(yes_text);
        } else {
            output_printf(out, OUTPUT_NORMAL, "yes");
        }

        /* Show time until expiry */
        time_t expires_at = 0;
        int64_t seconds_remaining = keymanager_time_until_expiry(key_mgr, &expires_at);

        if (seconds_remaining == -1) {
            output_printf(out, OUTPUT_NORMAL, " (no expiration)");
        } else if (seconds_remaining > 0) {
            output_printf(out, OUTPUT_NORMAL, " (expires in %ld seconds", (long)seconds_remaining);

            if (opts->verbose && expires_at > 0) {
                struct tm *tm_info = localtime(&expires_at);
                char time_buf[64];
                strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);
                output_printf(out, OUTPUT_NORMAL, " at %s", time_buf);
            }

            output_printf(out, OUTPUT_NORMAL, ")");
        } else {
            output_printf(out, OUTPUT_NORMAL, " (expired)");
        }

        output_newline(out);
    } else {
        char *no_text = output_colorize(out, OUTPUT_COLOR_YELLOW, "no");
        if (no_text) {
            output_printf(out, OUTPUT_NORMAL, "%s\n", no_text);
            free(no_text);
        } else {
            output_printf(out, OUTPUT_NORMAL, "no\n");
        }

        if (opts->verbose) {
            output_printf(out, OUTPUT_NORMAL, "  (You will be prompted for passphrase on next use)\n");
        }
    }

    output_newline(out);

    /* Count and display encrypted files */
    output_section(out, "Encrypted Files");

    size_t encrypted_count = 0;
    err = count_encrypted_files(repo, config, &encrypted_count);
    if (err) {
        /* Non-fatal error - just show that we couldn't count */
        if (opts->verbose) {
            output_printf(out, OUTPUT_NORMAL, "  Unable to count encrypted files: %s\n",
                         error_message(err));
        } else {
            output_printf(out, OUTPUT_NORMAL, "  Unknown (state not initialized)\n");
        }
        error_free(err);
    } else {
        output_printf(out, OUTPUT_NORMAL, "  Encrypted files in current profiles: %zu\n",
                     encrypted_count);

        if (encrypted_count == 0 && opts->verbose) {
            output_printf(out, OUTPUT_NORMAL, "\n");
            output_printf(out, OUTPUT_NORMAL, "To encrypt files, use:\n");
            output_printf(out, OUTPUT_NORMAL, "  dotta add --encrypt -p <profile> <file>\n");
        }
    }

    output_free(out);
    config_free(config);
    return NULL;
}

/**
 * Execute key command
 */
error_t *cmd_key(git_repository *repo, const cmd_key_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Dispatch to appropriate action */
    switch (opts->action) {
        case KEY_ACTION_SET:
            return cmd_key_set(repo, opts);

        case KEY_ACTION_CLEAR:
            return cmd_key_clear(repo, opts);

        case KEY_ACTION_STATUS:
            return cmd_key_status(repo, opts);

        default:
            return ERROR(ERR_INVALID_ARG, "Invalid key action: %d", opts->action);
    }
}
