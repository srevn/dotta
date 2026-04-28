/**
 * policy.c - Centralized encryption policy decision logic
 *
 * Implements the single source of truth for encryption decisions.
 * The compiled auto-encrypt ruleset lives on the config handle
 * (see include/config.h); policy calls read it directly and never
 * own or free it.
 */

#include "core/policy.h"

#include <config.h>
#include <string.h>

#include "base/error.h"
#include "base/gitignore.h"
#include "infra/path.h"

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

bool encryption_policy_is_active(const config_t *config) {
    return config && config->auto_encrypt.rules != NULL;
}

error_t *encryption_policy_should_encrypt(
    const config_t *config,
    const char *storage_path,
    bool explicit_encrypt,
    bool explicit_no_encrypt,
    bool previously_encrypted,
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
            return ERROR(
                ERR_VALIDATION,
                "Cannot encrypt system file '%s': this file must remain plaintext "
                "for dotta to function correctly.\n\n"
                "System files that cannot be encrypted:\n"
                "  - .bootstrap (must be executable)\n"
                "  - .dottaignore (must be readable for ignore patterns)\n"
                "  - .dotta/metadata.json (must be readable for file tracking)\n\n",
                storage_path
            );
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

    /* Priority 3: Maintain previous encryption state.
     *
     * Source: byte truth, threaded in by the caller. The caller has
     * already classified the relevant blob (or passed false when no
     * prior blob exists) — policy reads it as a pure bool with no
     * metadata side-channel, no I/O, no allocation. Important for
     * workflows like:
     *   1. dotta add --encrypt file
     *   2. ... modify file on disk ...
     *   3. dotta update file  (should stay encrypted)
     */
    if (previously_encrypted) {
        *out_should_encrypt = true;
        return NULL;
    }

    /* Priority 4: Check auto-encrypt patterns.
     *
     * Pattern matching is pure computation on the pre-compiled ruleset;
     * it cannot fail. An inactive policy (no config, disabled, or no
     * patterns) is treated as a non-match. */
    *out_should_encrypt =
        encryption_policy_matches_auto_patterns(config, storage_path);
    return NULL;
}

bool encryption_policy_matches_auto_patterns(
    const config_t *config,
    const char *storage_path
) {
    if (!config || !config->auto_encrypt.rules || !storage_path) {
        return false;
    }

    /* Strip storage prefix so patterns like ".ssh/id_*" match
     * "home/.ssh/id_rsa" without forcing users to write "home/" in config. */
    const char *path_for_matching = path_strip_storage_prefix(storage_path);

    /* Encryption applies to files, not directories — is_dir is always
     * false. Gitignore's last-match-wins with negation support is what
     * the user actually wants: `*.key` + `!public.key` correctly excludes
     * `public.key` from auto-encryption. */
    return gitignore_is_ignored(
        config->auto_encrypt.rules, path_for_matching, false
    );
}

bool encryption_policy_violation(
    const config_t *config,
    const char *storage_path,
    content_kind_t kind
) {
    /* Only plaintext blobs can violate the auto-encrypt policy.
     *
     * ENCRYPTED blobs satisfy the intent. UNSUPPORTED_VERSION blobs
     * also carry encryption intent (just at a version this build does
     * not understand) — flagging them as "missing encryption" would be
     * misleading; the version-skew surfaces from the content read path
     * when callers actually attempt to decrypt. */
    if (kind != CONTENT_PLAINTEXT) {
        return false;
    }

    /* matches_auto_patterns is NULL-safe and pure. */
    return encryption_policy_matches_auto_patterns(config, storage_path);
}
