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

#include "types.h"

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

#endif /* DOTTA_CRYPTO_POLICY_H */
