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
 * Auto-encrypt ruleset lifecycle:
 *   Patterns are compiled once per command via
 *   encryption_policy_build_auto_rules; the resulting ruleset is then
 *   threaded into every per-file decision. Callers own the arena backing
 *   the ruleset and must keep it alive for the duration of all policy
 *   queries. NULL rules are explicitly accepted (encryption disabled,
 *   no patterns, or no config) and propagate as "no auto-encrypt".
 */

#ifndef DOTTA_POLICY_H
#define DOTTA_POLICY_H

#include <stdbool.h>
#include <types.h>

/* Forward declarations */
typedef struct metadata metadata_t;
typedef struct gitignore_ruleset gitignore_ruleset_t;

/**
 * Compile auto-encrypt patterns from config into a gitignore ruleset.
 *
 * Returns success with *out_rules = NULL when any of:
 *   - config is NULL
 *   - config->encryption_enabled is false
 *   - config->auto_encrypt_pattern_count is 0
 *
 * These are not errors — they simply mean "no auto-encrypt ruleset
 * applies". Callers should treat NULL as a fast-path sentinel.
 *
 * The returned ruleset is arena-backed; the caller owns the arena and
 * must ensure it outlives every policy call that receives auto_rules.
 *
 * @param config Configuration (can be NULL)
 * @param arena Arena providing storage (must not be NULL; must outlive rules)
 * @param out_rules Output ruleset (must not be NULL; set to NULL when no rules apply)
 * @return Error or NULL on success
 */
error_t *encryption_policy_build_auto_rules(
    const config_t *config,
    arena_t *arena,
    gitignore_ruleset_t **out_rules
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
 * 4. If file matches auto_rules → ENCRYPT (pattern match)
 *    Example: File matches config pattern like ".ssh/id_*"
 *
 * 5. Otherwise → PLAINTEXT (default)
 *    Rationale: Encryption is opt-in, not opt-out (safer default)
 *
 * Implementation notes:
 * - Metadata lookup errors (except ERR_NOT_FOUND) are propagated
 * - NULL metadata is valid (means file is new or metadata unavailable)
 * - NULL auto_rules is valid (disables priority-4 check)
 *
 * @param auto_rules Compiled auto-encrypt ruleset (can be NULL; see
 *                   encryption_policy_build_auto_rules)
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
    const gitignore_ruleset_t *auto_rules,
    const char *storage_path,
    bool explicit_encrypt,
    bool explicit_no_encrypt,
    const metadata_t *metadata,
    bool *out_should_encrypt
);

/**
 * Check if file path matches auto-encrypt patterns
 *
 * Tests storage path against the pre-compiled auto-encrypt ruleset.
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
 * - auto_rules is NULL (encryption disabled or no patterns)
 * - storage_path is NULL
 * - No rule matches, or the winning rule is a negation
 *
 * @param auto_rules Compiled auto-encrypt ruleset (can be NULL)
 * @param storage_path File path in profile (e.g., "home/.bashrc")
 * @return true if path matches an auto-encrypt rule, false otherwise
 */
bool encryption_policy_matches_auto_patterns(
    const gitignore_ruleset_t *auto_rules,
    const char *storage_path
);

#endif /* DOTTA_POLICY_H */
