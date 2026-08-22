/**
 * key.c - Encryption key management command
 */

#include "cmds/key.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>

#include "base/args.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/output.h"
#include "core/manifest.h"
#include "core/state.h"
#include "crypto/keymgr.h"
#include "sys/passphrase.h"

/**
 * Execute key set action
 *
 * Prompts user for passphrase and caches it in the dispatcher-owned keymgr.
 */
static error_t *cmd_key_set(
    keymgr *keymgr,
    const config_t *config,
    output_t *out
) {
    /* Check if encryption is enabled */
    if (!config->encryption_enabled) {
        return ERROR(
            ERR_VALIDATION, "Encryption is disabled in configuration\n"
            "Set 'encryption.enabled = true' in config file"
        );
    }

    /* Invariant: encryption_enabled implies ctx->keymgr != NULL for a command
     * declaring crypto_mode = KEY. See runtime.h ctx invariants. */
    CHECK_NULL(keymgr);

    error_t *err = NULL;

    /* Notify if key is already cached (check both memory and disk). Rotation
     * UX: when a key is already cached, the new passphrase silently invalidates
     * every blob encrypted under the old one. Surfacing the warning here (per
     * sketch §5.4) keeps the keymgr_set_passphrase contract narrow — the function
     * does the derivation; the CLI owns the human-facing warning. */
    if (keymgr_probe_key(keymgr)) {
        int64_t seconds_remaining = keymgr_time_until_expiry(keymgr, NULL);
        if (seconds_remaining == -1) {
            output_info(
                out, OUTPUT_NORMAL,
                "A passphrase is already cached (no expiration)"
            );
        } else if (seconds_remaining > 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "A passphrase is already cached (expires in %ld seconds)",
                (long) seconds_remaining
            );
        }
        output_warning(
            out, OUTPUT_NORMAL,
            "Setting a new passphrase will invalidate every file already "
            "encrypted under the current one — those files will fail "
            "authentication on next decrypt. To replace the cached "
            "passphrase without rotation, run `dotta key clear` first, "
            "then `dotta key set` again with the same passphrase."
        );
        output_info(
            out, OUTPUT_NORMAL,
            "Enter a new passphrase to replace it."
        );
        output_newline(out, OUTPUT_NORMAL);
    }

    /* Prompt for passphrase */
    char *passphrase = NULL;
    size_t passphrase_len = 0;
    err = passphrase_prompt(
        "Enter encryption passphrase: ", &passphrase, &passphrase_len
    );
    if (err) {
        err = error_wrap(err, "Failed to read passphrase");
        goto cleanup;
    }

    /* Set passphrase in keymgr (derives and caches master key). The cast bridges
     * the passphrase API (`char *` for TTY ergonomics)
     * with the crypto API (`uint8_t *` for byte-array discipline);
     * both types alias `unsigned char` on every platform with <stdint.h>. */
    err = keymgr_set_passphrase(
        keymgr, (const uint8_t *) passphrase, passphrase_len
    );

    /* Securely clear passphrase from memory. passphrase_prompt returns a buffer
     * of exactly passphrase_len + 1 bytes with mlock. */
    buffer_secure_free(passphrase, passphrase_len + 1);

    if (err) {
        err = error_wrap(err, "Failed to set passphrase");
        goto cleanup;
    }

    /* Display success message */
    if (config->session_timeout == 0) {
        output_success(
            out, OUTPUT_NORMAL,
            "Passphrase set (will be prompted on each use)"
        );
    } else if (config->session_timeout > 0) {
        output_success(
            out, OUTPUT_NORMAL,
            "Passphrase cached for %d seconds",
            config->session_timeout
        );
    } else {
        output_success(
            out, OUTPUT_NORMAL,
            "Passphrase cached (no expiration)"
        );
    }

    output_print(
        out, OUTPUT_VERBOSE,
        "\nThe encryption key will be used for encrypting and decrypting files\n"
        "in all profiles until the cache expires or is explicitly cleared.\n"
    );

cleanup:
    /* keymgr borrowed from ctx — never freed here. */
    return err;
}

/**
 * Execute key clear action
 *
 * Clears the cached passphrase from the dispatcher-owned keymgr and its on-disk
 * session cache.
 */
static error_t *cmd_key_clear(
    keymgr *keymgr,
    const config_t *config,
    output_t *out
) {
    /* Check if encryption is enabled */
    if (!config->encryption_enabled) {
        return ERROR(
            ERR_VALIDATION, "Encryption is disabled in configuration\n"
            "Set 'encryption.enabled = true' in config file"
        );
    }

    /* Invariant: encryption_enabled implies ctx->keymgr != NULL for a command
     * declaring crypto_mode = KEY. See runtime.h ctx invariants. */
    CHECK_NULL(keymgr);

    /* Probe consults both in-memory and on-disk caches, loading the latter into
     * memory if present. ctx->keymgr is freshly-created for this command (one
     * process, one dispatch), so an in-memory hit is impossible — `true` here
     * means the on-disk cache existed, which is what users mean by "had a key". */
    bool had_key = keymgr_probe_key(keymgr);

    /* Always clear both memory and file cache (even if no in-memory key) */
    keymgr_clear(keymgr);

    /* Display result */
    if (had_key) {
        output_success(
            out, OUTPUT_NORMAL,
            "Encryption key cleared from memory and disk cache"
        );
    } else {
        output_success(
            out, OUTPUT_NORMAL,
            "Disk cache cleared (no key was cached)"
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
    keymgr *keymgr,
    git_repository *repo,
    const state_t *state,
    arena_t *arena,
    const config_t *config,
    output_t *out
) {
    /* Display encryption status */
    output_section(out, OUTPUT_NORMAL, "Encryption Configuration");

    if (config->encryption_enabled) {
        output_styled(
            out, OUTPUT_NORMAL, "  Status: {green}enabled{reset}\n"
        );

        /* Show Argon2id derivation parameters. The pair is what the config schema
         * exposes (either as a `strength` preset or as raw `memory` (MiB) /
         * `passes`); printing the resolved values keeps the status output
         * independent of which input form the user wrote. */
        output_print(
            out, OUTPUT_VERBOSE, "  Argon2id: %u MiB, %u passes\n",
            (unsigned) config->encryption_argon2_memory_mib,
            (unsigned) config->encryption_argon2_passes
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

    /* Encryption-enabled path guarantees ctx->keymgr is populated by the dispatcher
     * under crypto_mode = KEY. */
    CHECK_NULL(keymgr);

    bool key_cached = keymgr_probe_key(keymgr);
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
            keymgr_time_until_expiry(keymgr, &expires_at);

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

    /* Count and display encrypted files: the view over the enabled set, whose
     * rows carry the metadata-projected flag */
    output_section(out, OUTPUT_NORMAL, "Encrypted Files");

    manifest_t *manifest = NULL;
    error_t *err = manifest_build(repo, state, arena, &manifest);
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
        size_t encrypted_count = 0;
        manifest_rows_t rows = manifest_rows(manifest);
        for (size_t i = 0; i < rows.count; i++) {
            if (rows.entries[i]->encrypted) encrypted_count++;
        }
        manifest_free(manifest);

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
error_t *cmd_key(const dotta_ctx_t *ctx, const cmd_key_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->state);
    CHECK_NULL(opts);

    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Dispatch to appropriate action. Each handler takes the borrowed ctx->keymgr
     * (NULL when encryption is disabled — each handler short-circuits on that
     * via its own config->encryption_enabled check). */
    error_t *err = NULL;
    switch (opts->action) {
        case KEY_ACTION_SET:
            err = cmd_key_set(ctx->keymgr, config, out);
            break;

        case KEY_ACTION_CLEAR:
            err = cmd_key_clear(ctx->keymgr, config, out);
            break;

        case KEY_ACTION_STATUS:
            err = cmd_key_status(
                ctx->keymgr, ctx->repo, ctx->state, ctx->arena, config, out
            );
            break;

        default:
            err = ERROR(
                ERR_INVALID_ARG, "Invalid key action: %d",
                opts->action
            );
            break;
    }

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Single dispatch wrapper shared by every subcommand.
 *
 * Each sub's `init_defaults` already set the `action` discriminator, so
 * `cmd_key`'s switch routes the call.
 */
static error_t *key_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_key(ctx, (const cmd_key_options_t *) opts_v);
}

/* --- set --- */

static void key_set_defaults(void *o) {
    ((cmd_key_options_t *) o)->action = KEY_ACTION_SET;
}

static const args_opt_t key_set_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "v verbose",
        cmd_key_options_t, verbose,
        "Verbose output"
    ),
    ARGS_END,
};

static const args_command_t spec_key_set = {
    .name          = "key set",
    .summary       = "Cache the passphrase for the session",
    .usage         = "%s key set [-v]",
    .description   =
        "Prompts for the passphrase, derives the master key and caches it for\n"
        "the session; a passphrase already cached is replaced.\n",
    .opts_size     = sizeof(cmd_key_options_t),
    .opts          = key_set_opts,
    .init_defaults = key_set_defaults,
    .payload       = &dotta_ext_read_crypto,
    .dispatch      = key_dispatch,
};

/* --- clear --- */

static void key_clear_defaults(void *o) {
    ((cmd_key_options_t *) o)->action = KEY_ACTION_CLEAR;
}

static const args_opt_t key_clear_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "v verbose",
        cmd_key_options_t, verbose,
        "Verbose output"
    ),
    ARGS_END,
};

static const args_command_t spec_key_clear = {
    .name          = "key clear",
    .summary       = "Clear the cached key from memory and disk",
    .usage         = "%s key clear [-v]",
    .opts_size     = sizeof(cmd_key_options_t),
    .opts          = key_clear_opts,
    .init_defaults = key_clear_defaults,
    .payload       = &dotta_ext_read_crypto,
    .dispatch      = key_dispatch,
};

/* --- status --- */

static void key_status_defaults(void *o) {
    ((cmd_key_options_t *) o)->action = KEY_ACTION_STATUS;
}

static const args_opt_t key_status_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "v verbose",
        cmd_key_options_t, verbose,
        "Include the KDF parameters and the auto-encrypt patterns"
    ),
    ARGS_END,
};

static const args_command_t spec_key_status = {
    .name          = "key status",
    .summary       = "Show key status",
    .usage         = "%s key [status] [-v]",
    .opts_size     = sizeof(cmd_key_options_t),
    .opts          = key_status_opts,
    .init_defaults = key_status_defaults,
    .payload       = &dotta_ext_read_crypto,
    .dispatch      = key_dispatch,
};

/* --- parent: subcommand index + spec --- */

static const args_subcommand_t key_subs[] = {
    /* aliases   spec              hidden shortcut */
    { "set",    &spec_key_set,    false, false },
    { "clear",  &spec_key_clear,  false, false },
    { "status", &spec_key_status, false, false },
    { NULL,     NULL,             false, false }
};

const args_command_t spec_key = {
    .name               = "key",
    .summary            = "Manage encryption keys and passphrases",
    .usage              = "%s key [<subcommand>] [options]",
    .description        =
        "Manages the passphrase-derived master key and its session cache.\n"
        "Without a subcommand, shows the status.\n",
    .notes              =
        "Configuration:\n"
        "  [encryption]\n"
        "  enabled          = true\n"
        "  session_timeout  = 3600      # 1 hour\n"
        "  strength         = \"balanced\" # \"fast\", \"balanced\", or \"paranoid\"\n",
    .examples           =
        "  %s key set               # Cache passphrase for the session\n"
        "  %s key                   # Show cache state and config\n"
        "  %s key status -v         # Include auto-encrypt patterns\n"
        "  %s key clear             # Drop cached key\n",
    .epilogue           =
        "See also:\n"
        "  %s add --encrypt       # Encrypt a file on add\n"
        "  %s apply               # Decrypts on deployment\n",
    .opts_size          = sizeof(cmd_key_options_t),
    .subcommands        = key_subs,
    .default_subcommand = &spec_key_status,
};
