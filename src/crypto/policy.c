/**
 * policy.c - Centralized encryption policy decision logic
 *
 * Implements the single source of truth for encryption decisions.
 * Consolidates logic previously scattered across add.c, update.c, etc.
 */

#include "crypto/policy.h"

#include <config.h>
#include <string.h>

#include "base/error.h"
#include "base/gitignore.h"
#include "base/string.h"
#include "core/metadata.h"

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

error_t *encryption_policy_build_auto_rules(
    const config_t *config,
    arena_t *arena,
    gitignore_ruleset_t **out_rules
) {
    CHECK_NULL(arena);
    CHECK_NULL(out_rules);

    *out_rules = NULL;

    /* Short-circuit: nothing to compile when encryption is off, no
     * patterns are configured, or no config was provided. Callers treat
     * *out_rules == NULL as the fast "no auto-encrypt" sentinel. */
    if (!config || !config->encryption_enabled ||
        !config->auto_encrypt_patterns ||
        config->auto_encrypt_pattern_count == 0) {
        return NULL;
    }

    gitignore_ruleset_t *rules = NULL;
    error_t *err = gitignore_ruleset_create(arena, &rules);
    if (err) {
        return error_wrap(err, "Failed to allocate auto-encrypt ruleset");
    }

    /* Origin tag is unused for auto-encrypt — no per-rule attribution. */
    err = gitignore_ruleset_append_patterns(
        rules,
        (const char *const *) config->auto_encrypt_patterns,
        config->auto_encrypt_pattern_count,
        0
    );
    if (err) {
        return error_wrap(err, "Failed to compile auto-encrypt patterns");
    }

    *out_rules = rules;
    return NULL;
}

error_t *encryption_policy_should_encrypt(
    const gitignore_ruleset_t *auto_rules,
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

    /* Priority 3: Maintain previous encryption state (update.c pattern)
     *
     * If file was previously encrypted, maintain encryption to avoid
     * accidental decryption. This is important for workflows like:
     *   1. dotta add --encrypt file
     *   2. ... modify file on disk ...
     *   3. dotta update file  (should stay encrypted)
     */
    if (metadata) {
        const metadata_item_t *existing = NULL;
        error_t *err = metadata_get_item(
            metadata, storage_path, &existing
        );

        if (err == NULL && existing &&
            existing->kind == METADATA_ITEM_FILE &&
            existing->file.encrypted) {
            /* File was previously encrypted - maintain encryption */
            *out_should_encrypt = true;
            return NULL;
        }

        /* ERR_NOT_FOUND is expected for new files - not an error */
        if (err && err->code != ERR_NOT_FOUND) {
            /* Real error (corruption, etc.) - propagate */
            return error_wrap(
                err, "Failed to check metadata for '%s'", storage_path
            );
        }

        /* Clean up ERR_NOT_FOUND */
        if (err) {
            error_free(err);
        }
    }

    /* Priority 4: Check auto-encrypt patterns.
     *
     * Pattern matching is pure computation on the pre-compiled ruleset;
     * it cannot fail. A NULL auto_rules is the sentinel meaning "no
     * auto-encrypt applies" and is treated as a non-match. */
    *out_should_encrypt =
        encryption_policy_matches_auto_patterns(auto_rules, storage_path);
    return NULL;
}

bool encryption_policy_matches_auto_patterns(
    const gitignore_ruleset_t *auto_rules,
    const char *storage_path
) {
    if (!auto_rules || !storage_path) {
        return false;
    }

    /* Strip storage prefix for pattern matching
     *
     * This allows patterns like ".ssh/id_*" to match "home/.ssh/id_rsa"
     * without requiring users to write "home/.ssh/id_*" in their config.
     *
     * Prefixes: "home/" (5 chars), "root/" (5 chars), "custom/" (7 chars)
     */
    const char *path_for_matching = storage_path;
    if (str_starts_with(storage_path, "home/") ||
        str_starts_with(storage_path, "root/")) {
        path_for_matching = storage_path + 5;
    } else if (str_starts_with(storage_path, "custom/")) {
        path_for_matching = storage_path + 7;
    }

    /* Encryption applies to files, not directories — is_dir is always
     * false. Gitignore's last-match-wins with negation support is what
     * the user actually wants: `*.key` + `!public.key` correctly excludes
     * `public.key` from auto-encryption. */
    return gitignore_is_ignored(auto_rules, path_for_matching, false);
}
