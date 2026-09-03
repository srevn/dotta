/**
 * key.c - Encryption key management command
 */

#include "cmds/key.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>

#include "base/args.h"
#include "base/error.h"
#include "base/output.h"
#include "core/manifest.h"
#include "core/state.h"
#include "crypto/kdf.h"
#include "crypto/keymgr.h"

/**
 * Execute key set action
 *
 * Obtains the passphrase through the keymgr's ladder — DOTTA_ENCRYPTION_PASSPHRASE
 * when it is set, the prompt otherwise — verified against the repository's own
 * ciphertext, and caches it in the dispatcher-owned keymgr. The command never
 * holds passphrase bytes: what to verify against, how many times to ask, and
 * what stands after a refusal are the keymgr's decisions.
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

    /* What stands is replaced: say so, with the window it had. There is no rotation
     * to warn about — a passphrase that opens none of the repository's encrypted
     * files is refused below, so nothing can be silently sealed away. */
    time_t expires_at = 0;
    if (keymgr_cached(keymgr, &expires_at)) {
        if (expires_at == 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "A passphrase is already cached (no expiration); the one you "
                "enter replaces it"
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL,
                "A passphrase is already cached (expires in %lld seconds); the "
                "one you enter replaces it",
                (long long) (expires_at - time(NULL))
            );
        }
    }

    /* The ladder's refusal names its cause and the way out; the save's error is
     * the verb's own failure. Neither gains a wrap here. */
    RETURN_IF_ERROR(keymgr_set(keymgr));

    if (config->session_timeout == 0) {
        output_success(
            out, OUTPUT_NORMAL,
            "Passphrase verified (not cached: session_timeout = 0)"
        );
    } else if (config->session_timeout > 0) {
        output_success(
            out, OUTPUT_NORMAL,
            "Passphrase cached for %d seconds", config->session_timeout
        );
    } else {
        output_success(
            out, OUTPUT_NORMAL,
            "Passphrase cached (no expiration)"
        );
    }

    /* What the passphrase was proved against */
    const char *profile = NULL; const char *storage_path = NULL;
    if (keymgr_witness(keymgr, &profile, &storage_path)) {
        output_print(
            out, OUTPUT_VERBOSE, "Verified against %s:%s\n", profile,
            storage_path
        );
    } else {
        output_print(
            out, OUTPUT_VERBOSE, "No encrypted file to verify against\n"
        );
    }

    return NULL;
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
        "\nCache location: ~/.cache/dotta/session-<epoch>\n"
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
            if (kdf_presets[i].memory_mib == epoch->memory_mib &&
                kdf_presets[i].passes == epoch->passes) {
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
        "Name the file the passphrase was verified against"
    ),
    ARGS_END,
};

static const args_command_t spec_key_set = {
    .name          = "key set",
    .summary       = "Cache the passphrase for the session",
    .usage         = "%s key set [-v]",
    .description   =
        "Obtains the passphrase — DOTTA_ENCRYPTION_PASSPHRASE when it is\n"
        "set, a prompt otherwise — verifies it against an encrypted file\n"
        "the repository holds (or confirms it by asking twice when there is\n"
        "none), derives the master key and caches it for the session; a\n"
        "passphrase already cached is replaced. A passphrase that opens none\n"
        "of the repository's encrypted files is refused.\n",
    .opts_size     = sizeof(cmd_key_options_t),
    .opts          = key_set_opts,
    .init_defaults = key_set_defaults,
    .payload       = &(const dotta_needs_t){
        .repo      = DOTTA_REPO_OPEN,
        .crypto    = DOTTA_CRYPTO_OBTAIN,
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
        "Show where the session cache lives"
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
        .crypto    = DOTTA_CRYPTO_CACHED,
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
        .crypto    = DOTTA_CRYPTO_CACHED,
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
        "'dotta init --strength <fast|balanced|paranoid>'.\n"
        "\n"
        "Automation:\n"
        "  DOTTA_ENCRYPTION_PASSPHRASE, when set, is read instead of\n"
        "  prompting — by 'key set' and by every command that obtains a\n"
        "  passphrase (add, update, apply, diff, show, export, revert). It is\n"
        "  unset once read, so a child of the run does not inherit it.\n",
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
