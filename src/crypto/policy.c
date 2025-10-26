/**
 * policy.c - Centralized encryption policy decision logic
 *
 * Implements the single source of truth for encryption decisions.
 * Consolidates logic previously scattered across add.c, update.c, etc.
 */

#include "crypto/policy.h"

#include <string.h>

#include "base/error.h"
#include "core/metadata.h"
#include "utils/config.h"
#include "utils/match.h"
#include "utils/string.h"

/**
 * System files that must NEVER be encrypted
 *
 * These files are critical for dotta operations and must remain in
 * plaintext to be readable/executable by dotta and the system.
 *
 * - .bootstrap: Must be executable after extraction from Git
 * - .dottaignore: Must be readable for ignore pattern evaluation
 * - .dotta/metadata.json: Must be readable for permissions/encryption tracking
 *
 * This list acts as a safeguard against both user error (explicit --encrypt)
 * and accidental encryption via auto-encrypt patterns (e.g., ".*").
 */
static const char *PROTECTED_META_FILES[] = {
    ".bootstrap",
    ".dottaignore",
    ".dotta/metadata.json",
    NULL  /* Sentinel for iteration */
};

/**
 * Check if path is a protected system meta-file
 *
 * Meta-files are system files that must never be encrypted to ensure
 * dotta can read/execute them. This function performs an exact string
 * match against the list of protected files.
 *
 * Note: Meta-files never have home/ or root/ prefixes since they live
 * at the profile root, so simple strcmp() is sufficient.
 *
 * @param storage_path Path within profile (e.g., ".bootstrap")
 * @return true if file is a protected meta-file, false otherwise
 */
static bool is_protected_meta_file(const char *storage_path) {
    if (!storage_path) {
        return false;
    }

    for (int i = 0; PROTECTED_META_FILES[i] != NULL; i++) {
        if (strcmp(storage_path, PROTECTED_META_FILES[i]) == 0) {
            return true;
        }
    }

    return false;
}

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

    /* Priority 0: Meta-file protection (prevent system file corruption)
     *
     * System files (.bootstrap, .dottaignore, .dotta/metadata.json) must
     * NEVER be encrypted. These files are critical for dotta operations:
     *   - .bootstrap must be executable after extraction
     *   - .dottaignore must be readable for ignore pattern evaluation
     *   - .dotta/metadata.json must be readable for permission tracking
     *
     * This check happens BEFORE explicit --encrypt to catch user mistakes
     * early with a clear error message. It also silently overrides:
     *   - Auto-encrypt patterns (prevents accidental encryption via wildcards)
     *   - Previous encryption state (self-healing if meta-file was corrupted)
     *
     * Security note: This is a circuit breaker that prevents ANY path to
     * encrypting these files, ensuring system integrity.
     */
    if (is_protected_meta_file(storage_path)) {
        if (explicit_encrypt) {
            return ERROR(ERR_VALIDATION,
                "Cannot encrypt system file '%s': this file must remain plaintext "
                "for dotta to function correctly.\n\n"
                "System files that cannot be encrypted:\n"
                "  - .bootstrap (must be executable)\n"
                "  - .dottaignore (must be readable for ignore patterns)\n"
                "  - .dotta/metadata.json (must be readable for file tracking)\n\n"
                "These files are critical for dotta operations and should never be encrypted.",
                storage_path);
        }

        /* Meta-file protection silently overrides auto-encrypt patterns and
         * previous encryption state (self-healing). No error - just force plaintext. */
        *out_should_encrypt = false;
        return NULL;
    }

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
        error_t *err = encryption_policy_matches_auto_patterns(
            config,
            storage_path,
            &matches_pattern
        );

        if (err) {
            /* Non-fatal: Pattern matching errors shouldn't block operations.
             * Log warning and default to plaintext (safer than blocking).
             * The caller can choose to log this if verbose mode is enabled.
             *
             * Note: Current implementation never returns errors (pattern
             * matching is pure computation), but we keep error handling
             * for future robustness.
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

error_t *encryption_policy_matches_auto_patterns(
    const dotta_config_t *config,
    const char *storage_path,
    bool *out_matches
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out_matches);

    /* Default: no match */
    *out_matches = false;

    /* If config is NULL, no patterns to match */
    if (!config) {
        return NULL;
    }

    /* If encryption disabled, never auto-encrypt */
    if (!config->encryption_enabled) {
        return NULL;
    }

    /* If no patterns configured, never auto-encrypt */
    if (!config->auto_encrypt_patterns || config->auto_encrypt_pattern_count == 0) {
        return NULL;
    }

    /* Strip "home/" or "root/" prefix for pattern matching
     *
     * This allows patterns like ".ssh/id_*" to match "home/.ssh/id_rsa"
     * without requiring users to write "home/.ssh/id_*" in their config.
     *
     * Both prefixes are exactly 5 characters ("home/" and "root/").
     */
    const char *path_for_matching = storage_path;

    if (str_starts_with(storage_path, "home/")) {
        path_for_matching = storage_path + 5;  /* Skip "home/" */
    } else if (str_starts_with(storage_path, "root/")) {
        path_for_matching = storage_path + 5;  /* Skip "root/" */
    }

    /* Check if path matches any auto-encrypt pattern
     *
     * Uses new match module with MATCH_DOUBLESTAR flag for full gitignore
     * semantics including double-star recursive glob support.
     *
     * Examples:
     *   Pattern: ".ssh/id_*" matches ".ssh/id_rsa"
     *   Pattern: "*.key" matches "api.key" and "dir/api.key"
     *   Pattern: "secrets" with recursive glob matches "proj/secrets/file.txt"
     */
    *out_matches = match_any(
        config->auto_encrypt_patterns,
        config->auto_encrypt_pattern_count,
        path_for_matching,
        MATCH_DOUBLESTAR  /* Enable ** support */
    );

    return NULL;
}
