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
 * Ruleset ownership:
 *   The compiled auto-encrypt ruleset lives on the config handle
 *   (config->auto_encrypt.rules), materialized once at config_load and
 *   destroyed by config_free. Policy calls read it directly from config —
 *   callers never build, thread, or free the compiled form themselves.
 */

#ifndef DOTTA_POLICY_H
#define DOTTA_POLICY_H

#include <stdbool.h>
#include <types.h>

/* Forward declaration */
typedef struct metadata metadata_t;

/**
 * Report whether auto-encrypt policy applies to this config.
 *
 * True iff the config has a compiled auto-encrypt ruleset — i.e.
 * encryption is enabled AND at least one pattern was configured AND
 * the patterns compiled successfully at config_load.
 *
 * Used by command dispatchers that want to know "is it worth fetching
 * a keymgr for pattern matches?" without reaching into the compiled
 * form. Also used by workspace analysis to short-circuit scans when
 * nothing would match.
 *
 * NULL-safe (returns false).
 */
bool encryption_policy_is_active(const config_t *config);

/**
 * Report whether a command should acquire a keymgr for this batch.
 *
 * Answers the upfront question "is there any path through this
 * operation that will need to encrypt or decrypt?". Each caller's
 * per-file decision is still made by `encryption_policy_should_encrypt`;
 * this helper just avoids the keymgr round-trip when no file can
 * possibly need one.
 *
 * Consolidates the disjunction that add.c and update.c previously
 * duplicated verbatim. Returns true iff encryption is enabled AND one
 * or more of:
 *   - `explicit_encrypt` — caller's `--encrypt` (or equivalent) flag
 *   - auto-encrypt policy is active for this config
 *   - `metadata` is non-NULL and contains encrypted files
 *
 * The `metadata` parameter lets each caller decide whether to consult
 * existing encrypted state: update.c always passes its loaded metadata;
 * add.c passes it only during `--force` re-adds. Passing NULL skips the
 * metadata check entirely.
 *
 * Callers that want to reject "encryption requested on a disabled
 * config" with a friendly CLI error should still do so explicitly
 * before invoking this helper — the bool return can't carry that
 * message.
 *
 * NULL-safe for both pointer arguments (returns false for NULL config
 * or config with `encryption_enabled == false`).
 *
 * @param config Configuration (NULL → false)
 * @param explicit_encrypt User-supplied encryption flag (`--encrypt`)
 * @param metadata Metadata to consult for prior encrypted state (NULL → skip)
 * @return true if the caller must fetch a keymgr before proceeding
 */
bool encryption_policy_needs_keymgr(
    const config_t *config,
    bool explicit_encrypt,
    const metadata_t *metadata
);

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
 * 4. If file matches auto-encrypt patterns → ENCRYPT (pattern match)
 *    Example: File matches config pattern like ".ssh/id_*"
 *
 * 5. Otherwise → PLAINTEXT (default)
 *    Rationale: Encryption is opt-in, not opt-out (safer default)
 *
 * Implementation notes:
 * - Metadata lookup errors (except ERR_NOT_FOUND) are propagated
 * - NULL metadata is valid (means file is new or metadata unavailable)
 * - NULL config (or config without compiled rules) disables priority-4
 *
 * @param config Configuration (can be NULL; disables priority-4)
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
    const config_t *config,
    const char *storage_path,
    bool explicit_encrypt,
    bool explicit_no_encrypt,
    const metadata_t *metadata,
    bool *out_should_encrypt
);

/**
 * Check if file path matches auto-encrypt patterns
 *
 * Tests storage path against the config's compiled auto-encrypt ruleset.
 * Returns true iff the last-match-wins verdict is "ignored" (i.e. the
 * path matches a positive rule that no later negation un-matches).
 *
 * This helper is used by encryption_policy_should_encrypt() and also
 * exposed publicly for validation/diagnostic purposes (e.g. workspace
 * divergence analysis).
 *
 * Pattern matching:
 * - Full gitignore semantics (including `!` negation, directory-only,
 *   anchoring, `**` recursive globs) via base/gitignore.
 * - Storage-path prefix (`home/`, `root/`, `custom/`) is stripped before
 *   matching, so users can write `.ssh/id_*` instead of `home/.ssh/id_*`.
 *
 * Pattern examples:
 *   Pattern: ".ssh/id_*"
 *   Matches: "home/.ssh/id_rsa", "root/.ssh/id_ed25519"
 *   No match: "home/backup/.ssh/id_rsa" (pattern is anchored)
 *
 *   Pattern: "*.key"
 *   Matches: "home/api.key", "home/dir/secret.key" (basename match)
 *
 *   Pattern: "secrets/"
 *   Matches: "home/secrets/api.key" (directory walk-up)
 *
 * Never fails. Returns false when:
 * - config is NULL or auto-encrypt is inactive
 * - storage_path is NULL
 * - No rule matches, or the winning rule is a negation
 *
 * @param config Configuration (can be NULL)
 * @param storage_path File path in profile (e.g., "home/.bashrc")
 * @return true if path matches an auto-encrypt rule, false otherwise
 */
bool encryption_policy_matches_auto_patterns(
    const config_t *config,
    const char *storage_path
);

#endif /* DOTTA_POLICY_H */
