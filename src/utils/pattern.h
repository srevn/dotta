/**
 * pattern.h - Auto-encrypt pattern matching
 *
 * Provides pattern matching for automatic encryption based on file paths.
 * Uses gitignore-style glob patterns (via libgit2 pathspec) for consistency
 * with the ignore system.
 *
 * Pattern syntax (gitignore-compatible):
 *   - Wildcards: * (any), ? (single char), [abc] (character class)
 *   - Recursive: use ** for matching at any depth
 *
 *   - Pattern rules (following gitignore semantics):
 *       Pattern WITHOUT '/': matches basename at any depth
 *           Example: "id_rsa" matches .ssh/id_rsa, backup/.ssh/id_rsa, etc.
 *
 *       Pattern WITH '/': matches relative path from root (anchored)
 *           Example: ".ssh/id_*" matches ONLY .ssh/id_rsa (not backup/.ssh/id_rsa)
 *
 *       Pattern WITH leading '/': explicitly anchored to root
 *           Example: "/.ssh/id_*" matches ONLY .ssh/id_rsa
 *
 *   - Examples:
 *       *.key            - matches any .key file at any depth (basename matching)
 *       id_*             - matches id_rsa at any depth (basename matching)
 *       .ssh/id_*        - matches .ssh/id_rsa only at root (path anchored by slash)
 *       .aws/credentials - matches .aws/credentials only at root (path anchored by slash)
 *
 * Note: Paths are matched relative to home/ or root/ prefix
 */

#ifndef DOTTA_PATTERN_H
#define DOTTA_PATTERN_H

#include <stdbool.h>

#include "types.h"

/* Forward declarations */
typedef struct dotta_config dotta_config_t;

/**
 * Check if file should be auto-encrypted
 *
 * Tests storage path against auto_encrypt patterns from config.
 * Returns true if ANY pattern matches (logical OR).
 *
 * Pattern matching:
 * - Uses gitignore-style glob matching (via libgit2)
 * - Patterns are matched against storage_path (e.g., "home/.ssh/id_rsa")
 * - Directory prefix (home/, root/) is included in matching
 *
 * Examples:
 *   storage_path: "home/.ssh/id_rsa"
 *   patterns: [".ssh/id_*", "*.key"]
 *   result: true (matches first pattern)
 *
 *   storage_path: "home/.bashrc"
 *   patterns: [".ssh/id_*", "*.key"]
 *   result: false (no match)
 *
 * @param config Configuration (must not be NULL, must have encryption_enabled = true)
 * @param storage_path File path in profile (must not be NULL)
 * @param out_matches Output: true if path matches any pattern (must not be NULL)
 * @return Error or NULL on success
 */
error_t *encrypt_should_auto_encrypt(
    const dotta_config_t *config,
    const char *storage_path,
    bool *out_matches
);

#endif /* DOTTA_PATTERN_H */
