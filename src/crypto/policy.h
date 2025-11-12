/**
 * policy.h - Centralized encryption policy decision logic
 *
 * Single source of truth for determining whether a file should be encrypted.
 * Consolidates decision logic from add, update, and other commands to ensure
 * consistent behavior across the codebase.
 *
 * Design principle: This module provides POLICY (should we encrypt?), while
 * the content layer provides MECHANISM (how to encrypt). This separation of
 * concerns improves testability and maintainability.
 *
 * Policy hierarchy (priority order):
 * 0. Meta-file protection → PLAINTEXT or ERROR (system integrity)
 * 1. Explicit --encrypt flag → ENCRYPT (highest priority)
 * 2. Explicit --no-encrypt flag → PLAINTEXT (override auto-encrypt)
 * 3. File previously encrypted (metadata) → ENCRYPT (maintain state)
 * 4. Auto-encrypt patterns → ENCRYPT (pattern match)
 * 5. Default → PLAINTEXT (safe default)
 *
 * Usage:
 *   bool should_encrypt;
 *   error_t *err = encryption_policy_should_encrypt(
 *       config, storage_path,
 *       opts->encrypt, opts->no_encrypt,
 *       metadata, &should_encrypt
 *   );
 *   if (err) { handle error }
 *
 *   // Now use should_encrypt to decide encryption...
 */

#ifndef DOTTA_CRYPTO_POLICY_H
#define DOTTA_CRYPTO_POLICY_H

#include <stdbool.h>
#include <types.h>

/* Forward declarations */
typedef struct dotta_config dotta_config_t;
typedef struct metadata metadata_t;

/**
 * Determine if file should be encrypted based on policy
 *
 * This is the SINGLE SOURCE OF TRUTH for encryption decisions across all
 * commands (add, update, etc.). Consolidates scattered decision logic into
 * one testable, maintainable function.
 *
 * Policy hierarchy (priority order):
 * 0. If path is a protected meta-file → PLAINTEXT or ERROR (system integrity)
 *    Example: .bootstrap, .dottaignore, .dotta/metadata.json
 *    Behavior: If explicit --encrypt → ERROR; otherwise → PLAINTEXT
 *    Rationale: System files must be readable/executable by dotta
 *
 * 1. If explicit_encrypt=true → ENCRYPT (highest priority)
 *    Example: User ran `dotta add --encrypt file`
 *
 * 2. If explicit_no_encrypt=true → PLAINTEXT (override auto-encrypt)
 *    Example: User ran `dotta add --no-encrypt file`
 *
 * 3. If file previously encrypted (in metadata) → ENCRYPT (maintain state)
 *    Example: `dotta update` on already-encrypted file
 *    Rationale: Preserve encryption state to avoid accidental decryption
 *
 * 4. If file matches auto_encrypt patterns → ENCRYPT (pattern match)
 *    Example: File matches config pattern like ".ssh/id_*"
 *
 * 5. Otherwise → PLAINTEXT (default)
 *    Rationale: Encryption is opt-in, not opt-out (safer default)
 *
 * Implementation notes:
 * - Metadata lookup errors (except ERR_NOT_FOUND) are propagated
 * - Auto-encrypt pattern matching errors are treated as non-fatal (default to plaintext)
 * - NULL metadata is valid (means file is new or metadata unavailable)
 * - NULL config is valid (disables auto-encrypt checking)
 *
 * @param config Configuration (for auto_encrypt patterns, can be NULL)
 * @param storage_path File path in profile (e.g., "home/.bashrc", must not be NULL)
 * @param explicit_encrypt Explicit --encrypt flag from user
 * @param explicit_no_encrypt Explicit --no-encrypt flag from user
 * @param metadata Metadata for checking previous encryption state (can be NULL)
 * @param out_should_encrypt Output decision (must not be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_INVALID_ARG: Required arguments are NULL
 * - ERR_*: Propagated from metadata lookup (serious errors only)
 */
error_t *encryption_policy_should_encrypt(
    const dotta_config_t *config,
    const char *storage_path,
    bool explicit_encrypt,
    bool explicit_no_encrypt,
    const metadata_t *metadata,
    bool *out_should_encrypt
);

/**
 * Check if file path matches auto-encrypt patterns
 *
 * Tests storage path against auto_encrypt patterns from config.
 * Returns true if ANY pattern matches (logical OR).
 *
 * This is a helper function used by encryption_policy_should_encrypt()
 * and also exposed publicly for validation/diagnostic purposes (e.g.,
 * workspace divergence analysis).
 *
 * Pattern matching:
 * - Uses gitignore-style glob matching with double-star support
 * - Patterns are matched against path with "home/" or "root/" prefix stripped
 * - Example: storage_path "home/.ssh/id_rsa" is matched against ".ssh/id_rsa"
 * - Supports recursive globs: double-star patterns match at any depth
 *
 * Pattern examples:
 *   Pattern: ".ssh/id_*"
 *   Matches: "home/.ssh/id_rsa", "root/.ssh/id_ed25519"
 *   No match: "home/backup/.ssh/id_rsa" (pattern is anchored)
 *
 *   Pattern: "*.key"
 *   Matches: "home/api.key", "home/dir/secret.key" (basename match)
 *
 *   Pattern: "secrets" followed by recursive glob
 *   Matches: "home/secrets/api.key", "home/proj/secrets/data/file.txt"
 *
 * Behavior:
 * - If encryption disabled in config: returns false (no auto-encrypt)
 * - If no patterns configured: returns false (no auto-encrypt)
 * - If config is NULL: returns false (no configuration)
 * - Empty patterns never match
 * - Pattern matching uses new match module with full double-star support
 *
 * @param config Configuration (for auto_encrypt patterns, can be NULL)
 * @param storage_path File path in profile (e.g., "home/.bashrc", must not be NULL)
 * @param out_matches Output: true if path matches any pattern (must not be NULL)
 * @return Always returns NULL (no errors possible from pattern matching)
 *
 * Note: This function never fails. Pattern matching is purely computational
 * and does not perform I/O or allocations that could fail.
 */
error_t *encryption_policy_matches_auto_patterns(
    const dotta_config_t *config,
    const char *storage_path,
    bool *out_matches
);

#endif /* DOTTA_CRYPTO_POLICY_H */
