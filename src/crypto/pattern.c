/**
 * pattern.c - Pattern matching utilities
 *
 * Provides gitignore-style glob pattern matching using fnmatch().
 * Used for auto-encrypt patterns and can be reused for other pattern matching needs.
 */

#include "crypto/pattern.h"

#include <fnmatch.h>
#include <string.h>

#include "base/error.h"
#include "utils/config.h"
#include "utils/string.h"

/**
 * Check if path matches pattern using gitignore-style semantics
 *
 * Pattern matching rules (simplified gitignore):
 * - Pattern without '/': Matches basename at any depth
 *   Example: "*.key" matches "api.key" and "dir/api.key"
 *
 * - Pattern with '/': Matches full path from root (anchored)
 *   Example: ".ssh/id_*" matches ".ssh/id_rsa" but not "backup/.ssh/id_rsa"
 *
 * - Leading '/' in pattern: Stripped (paths are relative to home/root)
 *   Example: "/.ssh/id_*" treated same as ".ssh/id_*"
 *
 * Implementation uses fnmatch() with FNM_PATHNAME for full path matching
 * and falls back to basename matching (matching ignore system semantics).
 *
 * @param pattern Glob pattern (must not be NULL)
 * @param path Path to test (must not be NULL)
 * @return true if path matches pattern, false otherwise
 */
bool pattern_matches(const char *pattern, const char *path) {
    if (!pattern || !path) {
        return false;
    }

    /* Empty pattern never matches */
    if (pattern[0] == '\0') {
        return false;
    }

    /* Strip leading '/' from pattern (paths are already relative) */
    if (pattern[0] == '/') {
        pattern++;
        /* After stripping, empty pattern never matches */
        if (pattern[0] == '\0') {
            return false;
        }
    }

    /* Extract basename from path for fallback matching */
    const char *basename = strrchr(path, '/');
    if (basename) {
        basename++; /* Skip the '/' */
    } else {
        basename = path;
    }

    /* Try matching full path with FNM_PATHNAME
     * FNM_PATHNAME prevents wildcards from matching '/' */
    if (fnmatch(pattern, path, FNM_PATHNAME) == 0) {
        return true;
    }

    /* Try matching basename without FNM_PATHNAME
     * This handles patterns like "*.key" matching "dir/file.key" */
    if (fnmatch(pattern, basename, 0) == 0) {
        return true;
    }

    return false;
}

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
) {
    if (!path || !patterns || pattern_count == 0) {
        return false;
    }

    /* Test each pattern */
    for (size_t i = 0; i < pattern_count; i++) {
        if (pattern_matches(patterns[i], path)) {
            return true;
        }
    }

    return false;
}

error_t *encrypt_should_auto_encrypt(
    const dotta_config_t *config,
    const char *storage_path,
    bool *out_matches
) {
    CHECK_NULL(config);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_matches);

    /* Default: no match */
    *out_matches = false;

    /* If encryption disabled, never auto-encrypt */
    if (!config->encryption_enabled) {
        return NULL;
    }

    /* If no patterns configured, never auto-encrypt */
    if (!config->auto_encrypt_patterns || config->auto_encrypt_pattern_count == 0) {
        return NULL;
    }

    /* Strip "home/" or "root/" prefix for pattern matching
     * This allows patterns like ".ssh/id_*" to match "home/.ssh/id_rsa"
     * without requiring users to write "home/.ssh/id_*" */
    const char *path_for_matching = storage_path;

    if (str_starts_with(storage_path, "home/")) {
        path_for_matching = storage_path + 5;  /* Skip "home/" */
    } else if (str_starts_with(storage_path, "root/")) {
        path_for_matching = storage_path + 5;  /* Skip "root/" */
    }

    /* Check if path matches any auto-encrypt pattern */
    *out_matches = pattern_matches_any(
        config->auto_encrypt_patterns,
        config->auto_encrypt_pattern_count,
        path_for_matching
    );

    return NULL;
}
