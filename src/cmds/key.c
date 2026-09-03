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
#include "crypto/kdf.h"
#include "crypto/keymgr.h"
#include "sys/passphrase.h"

/**
 * Execute key set action
 *
 * Prompts user for passphrase and caches it in the dispatcher-owned keymgr.
 */
static error_t *cmd_key_set(const dotta_ctx_t *ctx) {
    keymgr *keymgr = ctx->run.keymgr;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Check if encryption is enabled */
    if (!config->encryption_enabled) {
        return ERROR(
            ERR_VALIDATION, "Encryption is disabled in configuration\n"
            "Set 'encryption.enabled = true' in config file"
        );
    }

    /* Invariant: encryption_enabled implies ctx->run.keymgr != NULL for a command
     * that declares crypto. See runtime.h's run invariants. */
    CHECK_NULL(keymgr);

    error_t *err = NULL;

    /* Notify if key is already cached (check both memory and disk). Rotation
     * UX: when a key is already cached, the new passphrase silently invalidates
     * every blob encrypted under the old one. Surfacing the warning here (per
     * sketch §5.4) keeps the keymgr_set_passphrase contract narrow — the function
     * does the derivation; the CLI owns the human-facing warning. */
    time_t expires_at = 0;
    if (keymgr_cached(keymgr, &expires_at)) {
        if (expires_at == 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "A passphrase is already cached (no expiration)"
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL,
                "A passphrase is already cached (expires in %lld seconds)",
                (long long) (expires_at - time(NULL))
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
static error_t *cmd_key_clear(const dotta_ctx_t *ctx) {
    keymgr *keymgr = ctx->run.keymgr;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Check if encryption is enabled */
    if (!config->encryption_enabled) {
        return ERROR(
            ERR_VALIDATION, "Encryption is disabled in configuration\n"
            "Set 'encryption.enabled = true' in config file"
        );
    }

    /* Invariant: encryption_enabled implies ctx->run.keymgr != NULL for a command
     * that declares crypto. See runtime.h's run invariants. */
    CHECK_NULL(keymgr);

    /* The slot is this process's and empty (one process, one dispatch), so the
     * clear's answer is the file's: whether this epoch's session file was there
     * and is gone — which is what users mean by "had a key". */
    if (keymgr_clear(keymgr)) {
        output_success(out, OUTPUT_NORMAL, "Session cache cleared");
    } else {
        output_success(out, OUTPUT_NORMAL, "No session cache to clear");
    }

    output_print(
        out, OUTPUT_VERBOSE,
        "\nCache location: ~/.cache/dotta/session-<epoch> "
        "(one file per repository epoch)\n"
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
static error_t *cmd_key_status(const dotta_ctx_t *ctx) {
    git_repository *repo = ctx->run.repo;
    const state_t *state = ctx->run.state;
    keymgr *keymgr = ctx->run.keymgr;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Display encryption status */
    output_section(out, OUTPUT_NORMAL, "Encryption Configuration");

    if (config->encryption_enabled) {
        output_styled(
            out, OUTPUT_NORMAL, "  Status: {green}enabled{reset}\n"
        );

        /* The Argon2id pair is the repository's epoch — minted at init, the same
         * on every machine — named by the preset that matches it when one does.
         * Encryption-enabled implies the dispatcher created the keymgr. */
        CHECK_NULL(keymgr);
        const kdf_epoch_t *epoch = keymgr_epoch(keymgr);
        const char *preset = NULL;
        for (size_t i = 0; i < KDF_PRESET_COUNT; i++) {
            if (kdf_presets[i].memory_mib == epoch->memory_mib
                && kdf_presets[i].passes == epoch->passes) {
                preset = kdf_presets[i].name;
            }
        }
        output_print(
            out, OUTPUT_VERBOSE, "  Argon2id: %u MiB, %u passes%s%s%s\n",
            (unsigned) epoch->memory_mib, (unsigned) epoch->passes,
            preset ? " (" : "", preset ? preset : "", preset ? ")" : ""
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

    time_t expires_at = 0;
    bool key_cached = keymgr_cached(keymgr, &expires_at);
    output_print(
        out, OUTPUT_NORMAL, "  Key cached: "
    );

    if (key_cached) {
        output_styled(
            out, OUTPUT_NORMAL, "{green}yes{reset}"
        );

        /* The expiry is the session file's own, so the number counts down across
         * processes instead of restarting at each. A loaded file is unexpired
         * by the loader's contract; 0 is the file that never expires. */
        if (expires_at == 0) {
            output_print(
                out, OUTPUT_NORMAL, " (no expiration)"
            );
        } else {
            output_print(
                out, OUTPUT_NORMAL, " (expires in %lld seconds",
                (long long) (expires_at - time(NULL))
            );

            struct tm *tm_info = localtime(&expires_at);
            char time_buf[64];
            strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);
            output_print(
                out, OUTPUT_VERBOSE, " at %s",
                time_buf
            );

            output_print(out, OUTPUT_NORMAL, ")");
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
    error_t *err = manifest_build(repo, state, ctx->arena, &manifest);
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
    CHECK_NULL(opts);

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(ctx->out, OUTPUT_VERBOSE);
    }

    /* Dispatch to appropriate action. Each handler reads the borrowed
     * ctx->run.keymgr (NULL when encryption is disabled — each handler
     * short-circuits on that via its own config->encryption_enabled check). */
    error_t *err = NULL;
    switch (opts->action) {
        case KEY_ACTION_SET:
            err = cmd_key_set(ctx);
            break;

        case KEY_ACTION_CLEAR:
            err = cmd_key_clear(ctx);
            break;

        case KEY_ACTION_STATUS:
            err = cmd_key_status(ctx);
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
 * Each sub's `init_defaults` already set the `action` discriminator, so `cmd_key`'s
 * switch routes the call.
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
    .payload       = &(const dotta_needs_t){
        .repo      = DOTTA_REPO_OPEN,
        .crypto    = true,
    },
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
    .payload       = &(const dotta_needs_t){
        .repo      = DOTTA_REPO_OPEN,
        .crypto    = true,
    },
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
    .payload       = &(const dotta_needs_t){
        .repo      = DOTTA_REPO_OPEN,          .state= DOTTA_STATE_READ,
        .crypto    = true,
    },
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
        "The Argon2id strength is the repository's, minted once by\n"
        "'dotta init --strength <fast|balanced|paranoid>'.\n",
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
