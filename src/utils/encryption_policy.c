/**
 * encryption_policy.c - Centralized encryption policy decision logic
 *
 * Implements the single source of truth for encryption decisions.
 * Consolidates logic previously scattered across add.c, update.c, etc.
 */

#include "utils/encryption_policy.h"

#include "base/error.h"
#include "core/metadata.h"
#include "utils/config.h"
#include "utils/pattern.h"

error_t *encryption_policy_should_encrypt(
    const dotta_config_t *config,
    const char *storage_path,
    bool explicit_encrypt,
    bool explicit_no_encrypt,
    const metadata_t *metadata,
    bool *out_should_encrypt
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out_should_encrypt);

    /* Default: no encryption (safe default) */
    *out_should_encrypt = false;

    /* Priority 1: Explicit --encrypt flag wins (highest priority) */
    if (explicit_encrypt) {
        *out_should_encrypt = true;
        return NULL;
    }

    /* Priority 2: Explicit --no-encrypt blocks all encryption */
    if (explicit_no_encrypt) {
        *out_should_encrypt = false;
        return NULL;
    }

    /* Priority 3: Maintain previous encryption state (update.c pattern)
     *
     * If file was previously encrypted, maintain encryption to avoid
     * accidental decryption. This is important for workflows like:
     *   1. dotta add --encrypt file
     *   2. ... modify file on disk ...
     *   3. dotta update file  (should stay encrypted)
     */
    if (metadata) {
        const metadata_entry_t *existing = NULL;
        error_t *err = metadata_get_entry(metadata, storage_path, &existing);

        if (err == NULL && existing && existing->encrypted) {
            /* File was previously encrypted - maintain encryption */
            *out_should_encrypt = true;
            return NULL;
        }

        /* ERR_NOT_FOUND is expected for new files - not an error */
        if (err && err->code != ERR_NOT_FOUND) {
            /* Real error (corruption, etc.) - propagate */
            return error_wrap(err, "Failed to check metadata for '%s'", storage_path);
        }

        /* Clean up ERR_NOT_FOUND */
        if (err) {
            error_free(err);
        }
    }

    /* Priority 4: Check auto-encrypt patterns
     *
     * If config has auto_encrypt patterns enabled, check if this file
     * matches any pattern (e.g., ".ssh/id_*", "*.key").
     */
    if (config && config->encryption_enabled) {
        bool matches_pattern = false;
        error_t *err = encrypt_should_auto_encrypt(config, storage_path, &matches_pattern);

        if (err) {
            /* Non-fatal: Pattern matching errors shouldn't block operations.
             * Log warning and default to plaintext (safer than blocking).
             * The caller can choose to log this if verbose mode is enabled.
             */
            error_free(err);
            *out_should_encrypt = false;
            return NULL;
        }

        *out_should_encrypt = matches_pattern;
        return NULL;
    }

    /* Priority 5: Default to plaintext
     *
     * If none of the above conditions apply, default to plaintext.
     * Encryption is opt-in, not opt-out (safer default).
     */
    *out_should_encrypt = false;
    return NULL;
}
