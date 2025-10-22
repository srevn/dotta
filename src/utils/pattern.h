/**
 * pattern.h - Pattern matching utilities
 *
 * Provides gitignore-style glob pattern matching for file paths.
 * Used for auto-encrypt patterns and other pattern matching needs.
 *
 * Pattern syntax (gitignore-compatible):
 *   - Wildcards: * (any), ? (single char), [abc] (character class)
 *
 *   - Pattern rules (following gitignore semantics):
 *       Pattern WITHOUT '/': matches basename at any depth
 *           Example: "id_rsa" matches .ssh/id_rsa, backup/.ssh/id_rsa, etc.
 *           Example: "*.key" matches api.key, dir/api.key, etc.
 *
 *       Pattern WITH '/': matches relative path from root (anchored)
 *           Example: ".ssh/id_*" matches ONLY .ssh/id_rsa (not backup/.ssh/id_rsa)
 *
 *       Pattern WITH leading '/': explicitly anchored to root
 *           Example: "/.ssh/id_*" same as ".ssh/id_*" (leading / is stripped)
 *
 * Implementation:
 *   - Uses fnmatch() with FNM_PATHNAME for full path matching
 *   - Falls back to basename matching for patterns without '/'
 *   - Consistent with gitignore semantics used in ignore system
 *
 * Limitations (compared to full gitignore):
 *   - No support for '**' (recursive glob) - use '*' for basename matching
 *   - No support for '!' (negation) - not needed for auto-encrypt
 *   - No support for trailing '/' (directory-only matching)
 *
 * Note: Paths are matched relative to home/ or root/ prefix (prefix stripped before matching)
 */

#ifndef DOTTA_PATTERN_H
#define DOTTA_PATTERN_H

#include <stdbool.h>

#include "types.h"

/* Forward declarations */
typedef struct dotta_config dotta_config_t;

/**
 * Check if path matches pattern using gitignore-style semantics
 *
 * Pattern matching rules:
 * - Pattern without '/': Matches basename at any depth
 *   Example: "*.key" matches "api.key" and "dir/api.key"
 *
 * - Pattern with '/': Matches full path from root (anchored)
 *   Example: ".ssh/id_*" matches ".ssh/id_rsa" but not "backup/.ssh/id_rsa"
 *
 * - Leading '/' in pattern: Stripped (paths are relative to home/root)
 *   Example: "/.ssh/id_*" treated same as ".ssh/id_*"
 *
 * @param pattern Glob pattern (must not be NULL)
 * @param path Path to test (must not be NULL)
 * @return true if path matches pattern, false otherwise
 */
bool pattern_matches(const char *pattern, const char *path);

/**
 * Check if path matches any pattern in array
 *
 * Tests path against all patterns, returns true if ANY pattern matches.
 * Uses gitignore-style semantics via pattern_matches().
 *
 * @param patterns Array of patterns (can be NULL if count is 0)
 * @param pattern_count Number of patterns
 * @param path Path to test (must not be NULL)
 * @return true if path matches any pattern, false otherwise
 */
bool pattern_matches_any(
    char **patterns,
    size_t pattern_count,
    const char *path
);

/**
 * Check if file should be auto-encrypted
 *
 * Tests storage path against auto_encrypt patterns from config.
 * Returns true if ANY pattern matches (logical OR).
 *
 * Pattern matching:
 * - Uses gitignore-style glob matching (via fnmatch)
 * - Patterns are matched against path with "home/" or "root/" prefix stripped
 * - Example: storage_path "home/.ssh/id_rsa" is matched against ".ssh/id_rsa"
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
 *   storage_path: "home/dir/api.key"
 *   patterns: ["*.key"]
 *   result: true (matches basename)
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
