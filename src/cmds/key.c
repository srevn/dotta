/**
 * key.c - Encryption key management command
 */

#include "key.h"

#include <git2.h>
#include <hydrogen.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <config.h>

#include "base/error.h"
#include "core/metadata.h"
#include "core/state.h"
#include "crypto/keymanager.h"
#include "utils/array.h"
#include "utils/output.h"

/**
 * Count encrypted files in current profiles
 *
 * Helper for status display.
 */
static error_t *count_encrypted_files(
    git_repository *repo,
    size_t *out_count
) {
    CHECK_NULL(repo);
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
            string_array_free(profile_names);
            state_free(state);
            return NULL;
        }
        string_array_free(profile_names);
        state_free(state);
        return error_wrap(err, "Failed to load metadata");
    }

    /* Count encrypted files */
    size_t count;
    const metadata_item_t **files = metadata_get_items_by_kind(
        metadata, METADATA_ITEM_FILE, &count
    );
    if (files) {
        for (size_t i = 0; i < count; i++) {
            if (files[i]->file.encrypted) {
                (*out_count)++;
            }
        }
        free(files);  /* Free pointer array only */
    }

    metadata_free(metadata);
    string_array_free(profile_names);
    state_free(state);
    return NULL;
}

/**
 * Execute key set action
 *
 * Prompts user for passphrase and caches it in the global keymanager.
 */
static error_t *cmd_key_set(
    const config_t *config,
    output_ctx_t *out
) {
    /* Check if encryption is enabled */
    if (!config->encryption_enabled) {
        return ERROR(
            ERR_VALIDATION, "Encryption is disabled in configuration\n"
            "Set 'encryption.enabled = true' in config file"
        );
    }

    /* Get global keymanager */
    keymanager_t *key_mgr = keymanager_get_global(config);
    if (!key_mgr) {
        return ERROR(ERR_INTERNAL, "Failed to initialize key manager");
    }

    /* Notify if key is already cached (check both memory and disk) */
    if (keymanager_probe_key(key_mgr)) {
        int64_t seconds_remaining = keymanager_time_until_expiry(key_mgr, NULL);
        if (seconds_remaining == -1) {
            output_info(
                out, OUTPUT_NORMAL, "A passphrase is already cached (no expiration)"
            );
        } else if (seconds_remaining > 0) {
            output_info(
                out, OUTPUT_NORMAL, "A passphrase is already cached (expires in %ld seconds)",
                (long) seconds_remaining
            );
        }
        output_info(out, OUTPUT_NORMAL, "Enter a new passphrase to replace it.");
        output_newline(out, OUTPUT_NORMAL);
    }

    /* Prompt for passphrase */
    char *passphrase = NULL;
    size_t passphrase_len = 0;
    error_t *err = keymanager_prompt_passphrase(
        "Enter encryption passphrase: ", &passphrase, &passphrase_len
    );
    if (err) {
        return error_wrap(err, "Failed to read passphrase");
    }

    /* Set passphrase in keymanager (derives and caches master key) */
    err = keymanager_set_passphrase(key_mgr, passphrase, passphrase_len);

    /* Securely clear passphrase from memory.
     * keymanager_prompt_passphrase returns a buffer of exactly passphrase_len+1
     * bytes with mlock. Use hydro_memzero (not memset) to resist optimization. */
    if (passphrase) {
        munlock(passphrase, passphrase_len + 1);
        hydro_memzero(passphrase, passphrase_len + 1);
        free(passphrase);
    }

    if (err) {
        return error_wrap(err, "Failed to set passphrase");
    }

    /* Display success message */
    if (config->session_timeout == 0) {
        output_success(
            out, OUTPUT_NORMAL, "Passphrase set (will be prompted on each use)"
        );
    } else if (config->session_timeout > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Passphrase cached for %d seconds",
            config->session_timeout
        );
    } else {
        output_success(
            out, OUTPUT_NORMAL, "Passphrase cached (no expiration)"
        );
    }

    output_print(
        out, OUTPUT_VERBOSE,
        "\nThe encryption key will be used for encrypting and decrypting files\n"
        "in all profiles until the cache expires or is explicitly cleared.\n"
    );

    return NULL;
}

/**
 * Execute key clear action
 *
 * Clears the cached passphrase from the global keymanager.
 */
static error_t *cmd_key_clear(
    const config_t *config,
    output_ctx_t *out
) {
    /* Check if encryption is enabled */
    if (!config->encryption_enabled) {
        return ERROR(
            ERR_VALIDATION, "Encryption is disabled in configuration\n"
            "Set 'encryption.enabled = true' in config file"
        );
    }

    /* Get global keymanager */
    keymanager_t *key_mgr = keymanager_get_global(config);
    if (!key_mgr) {
        return ERROR(ERR_INTERNAL, "Failed to initialize key manager");
    }

    /* Check if key is cached in memory */
    bool had_key = keymanager_has_key(key_mgr);

    /* Always clear both memory and file cache (even if no in-memory key) */
    keymanager_clear(key_mgr);

    /* Display result */
    if (had_key) {
        output_success(
            out, OUTPUT_NORMAL, "Encryption key cleared from memory and disk cache"
        );
    } else {
        output_success(
            out, OUTPUT_NORMAL, "Disk cache cleared (no key was cached in memory)"
        );
    }

    output_print(
        out, OUTPUT_VERBOSE,
        "\nCache location: ~/.cache/dotta/session\n"
        "You will be prompted for your passphrase on the next "
        "operation that requires encryption or decryption.\n"
    );

    return NULL;
}

/**
 * Execute key status action
 *
 * Displays encryption configuration and key cache status.
 */
static error_t *cmd_key_status(
    git_repository *repo,
    const config_t *config,
    output_ctx_t *out
) {
    /* Display encryption status */
    output_section(out, OUTPUT_NORMAL, "Encryption Configuration");

    if (config->encryption_enabled) {
        output_styled(
            out, OUTPUT_NORMAL, "  Status: {green}enabled{reset}\n"
        );

        /* Show configuration parameters */
        output_print(
            out, OUTPUT_VERBOSE, "  KDF opslimit: %lu\n",
            (unsigned long) config->encryption_opslimit
        );
        output_print(
            out, OUTPUT_VERBOSE, "  KDF memlimit: %zu MB\n",
            config->encryption_memlimit
        );

        /* Show session timeout */
        output_print(
            out, OUTPUT_NORMAL, "  Session timeout: "
        );
        if (config->session_timeout == 0) {
            output_print(
                out, OUTPUT_NORMAL, "always prompt\n"
            );
        } else if (config->session_timeout > 0) {
            output_print(
                out, OUTPUT_NORMAL, "%u seconds",
                config->session_timeout
            );

            unsigned int minutes = config->session_timeout / 60;
            unsigned int hours = minutes / 60;

            if (hours > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, " (%u hour%s)",
                    hours, hours == 1 ? "" : "s"
                );
            } else if (minutes > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, " (%u minute%s)",
                    minutes, minutes == 1 ? "" : "s"
                );
            }
            output_newline(out, OUTPUT_NORMAL);
        } else {
            output_print(
                out, OUTPUT_NORMAL, "no expiration\n"
            );
        }

        /* Show auto-encrypt patterns */
        if (config->auto_encrypt_pattern_count > 0) {
            output_print(
                out, OUTPUT_VERBOSE, "  Auto-encrypt patterns: %zu\n",
                config->auto_encrypt_pattern_count
            );
            for (size_t i = 0; i < config->auto_encrypt_pattern_count; i++) {
                output_print(
                    out, OUTPUT_VERBOSE, "    - %s\n",
                    config->auto_encrypt_patterns[i]
                );
            }
        }
    } else {
        output_styled(
            out, OUTPUT_NORMAL, "  Status: {red}disabled{reset}\n"
        );

        output_newline(out, OUTPUT_NORMAL);
        output_hint(out, OUTPUT_NORMAL, "To enable encryption, add to config file:");
        output_hintline(out, OUTPUT_NORMAL, "  [encryption]");
        output_hintline(out, OUTPUT_NORMAL, "  enabled = true");

        return NULL;
    }

    /* Display key cache status */
    output_section(out, OUTPUT_NORMAL, "Key Cache Status");

    keymanager_t *key_mgr = keymanager_get_global(config);
    if (!key_mgr) {
        return ERROR(ERR_INTERNAL, "Failed to initialize key manager");
    }

    bool key_cached = keymanager_probe_key(key_mgr);
    output_print(
        out, OUTPUT_NORMAL, "  Key cached: "
    );

    if (key_cached) {
        output_styled(
            out, OUTPUT_NORMAL, "{green}yes{reset}"
        );

        /* Show time until expiry */
        time_t expires_at = 0;
        int64_t seconds_remaining =
            keymanager_time_until_expiry(key_mgr, &expires_at);

        if (seconds_remaining == -1) {
            output_print(
                out, OUTPUT_NORMAL, " (no expiration)"
            );
        } else if (seconds_remaining > 0) {
            output_print(
                out, OUTPUT_NORMAL, " (expires in %ld seconds",
                (long) seconds_remaining
            );

            if (expires_at > 0) {
                struct tm *tm_info = localtime(&expires_at);

                char time_buf[64];
                strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);
                output_print(
                    out, OUTPUT_VERBOSE, " at %s",
                    time_buf
                );
            }

            output_print(out, OUTPUT_NORMAL, ")");
        } else {
            output_print(out, OUTPUT_NORMAL, " (expired)");
        }

        output_newline(out, OUTPUT_NORMAL);
    } else {
        output_styled(out, OUTPUT_NORMAL, "{yellow}no{reset}\n");

        output_print(
            out, OUTPUT_VERBOSE,
            "  (You will be prompted for passphrase on next use)\n"
        );
    }

    /* Count and display encrypted files */
    output_section(out, OUTPUT_NORMAL, "Encrypted Files");

    size_t encrypted_count = 0;
    error_t *err = count_encrypted_files(repo, &encrypted_count);
    if (err) {
        /* Non-fatal error - concise at normal, detail at verbose */
        output_print(
            out, OUTPUT_NORMAL, "  Unable to count encrypted files\n"
        );
        output_print(
            out, OUTPUT_VERBOSE, "  %s\n",
            error_message(err)
        );
        error_free(err);
    } else {
        output_print(
            out, OUTPUT_NORMAL, "  Encrypted files in current profiles: %zu\n",
            encrypted_count
        );

        if (encrypted_count == 0) {
            output_newline(out, OUTPUT_NORMAL);
            output_hint(out, OUTPUT_NORMAL, "To encrypt files, use:");
            output_hintline(out, OUTPUT_NORMAL, "  dotta add --encrypt -p <profile> <file>");
        }
    }

    return NULL;
}

/**
 * Execute key command
 */
error_t *cmd_key(git_repository *repo, const config_t *config, const cmd_key_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Create output context */
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Dispatch to appropriate action */
    error_t *err = NULL;
    switch (opts->action) {
        case KEY_ACTION_SET:
            err = cmd_key_set(config, out);
            break;

        case KEY_ACTION_CLEAR:
            err = cmd_key_clear(config, out);
            break;

        case KEY_ACTION_STATUS:
            err = cmd_key_status(repo, config, out);
            break;

        default:
            err = ERROR(
                ERR_INVALID_ARG, "Invalid key action: %d",
                opts->action
            );
            break;
    }

    output_free(out);
    return err;
}
