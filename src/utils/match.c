/**
 * match.c - Comprehensive pattern matching implementation
 *
 * Implements robust gitignore-style glob pattern matching with full
 * support for **, directory matching, and all edge cases.
 */

#include "match.h"

#include <fnmatch.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static bool match_pattern_internal(
    const char *pattern,
    const char *path,
    match_flags_t flags,
    bool is_basename_match
);

static bool match_doublestar_pattern(
    const char *pattern,
    const char *path,
    match_flags_t flags
);

/**
 * Extract basename from path
 */
const char *match_basename(const char *path) {
    if (!path) {
        return "";
    }

    const char *basename = strrchr(path, '/');
    if (basename) {
        return basename + 1; /* Skip the '/' */
    }
    return path;
}

/**
 * Find valid recursive glob in pattern
 *
 * A valid recursive glob is a sequence of 2+ asterisks at a component boundary:
 *   - Preceded by '/' or at start of pattern
 *   - Followed by '/' or at end of pattern
 *
 * Valid:   "**", "***", "** /foo", "*** /foo", "foo/ **"  (no spaces in real patterns)
 * Invalid: "a**b", "test_**", "**suffix" (not at component boundary)
 */
const char *match_has_doublestar(const char *pattern) {
    if (!pattern) {
        return NULL;
    }

    const char *p = pattern;
    while (*p) {
        if (*p != '*') {
            p++;
            continue;
        }

        /* Found asterisk - consume entire sequence */
        const char *seq_start = p;
        while (*p == '*') {
            p++;
        }

        /* Need 2+ asterisks for recursive glob */
        if (p - seq_start < 2) {
            continue;
        }

        /* Must be at component boundary */
        bool at_start = (seq_start == pattern) || (seq_start[-1] == '/');
        bool at_end = (*p == '\0') || (*p == '/');

        if (at_start && at_end) {
            return seq_start;
        }
    }

    return NULL;
}

/**
 * Check if pattern is basename-only (no /)
 *
 * Returns true if pattern has no '/' after stripping leading '/'.
 * Basename-only patterns match at any depth.
 */
bool match_is_basename_pattern(const char *pattern) {
    if (!pattern) {
        return false;
    }

    /* Strip leading '/' */
    if (*pattern == '/') {
        pattern++;
    }

    /* Check if remaining pattern has any '/' */
    return strchr(pattern, '/') == NULL;
}

/**
 * Check if pattern has trailing slash
 */
static bool has_trailing_slash(const char *pattern) {
    if (!pattern || *pattern == '\0') {
        return false;
    }

    size_t len = strlen(pattern);
    return pattern[len - 1] == '/';
}

/**
 * Strip leading slash from pattern
 *
 * Returns pointer into pattern after leading '/'.
 * Does not modify the original string.
 */
static const char *strip_leading_slash(const char *pattern) {
    if (!pattern) {
        return pattern;
    }

    while (*pattern == '/') {
        pattern++;
    }
    return pattern;
}

/**
 * Strip trailing slash from pattern
 *
 * Creates a copy without trailing slash.
 * Caller must free the result if different from original.
 */
static const char *strip_trailing_slash(
    const char *pattern,
    char *buffer,
    size_t buffer_size
) {
    if (!pattern || *pattern == '\0') {
        return pattern;
    }

    size_t len = strlen(pattern);
    if (pattern[len - 1] != '/') {
        return pattern; /* No trailing slash */
    }

    /* Copy to buffer without trailing slash */
    if (len >= buffer_size) {
        return pattern; /* Buffer too small, use original */
    }

    memcpy(buffer, pattern, len - 1);
    buffer[len - 1] = '\0';
    return buffer;
}

/**
 * Match using fnmatch (for patterns without **)
 *
 * Fast path for simple patterns using fnmatch(3).
 *
 * @param pattern Pattern to match
 * @param path Path to test
 * @param flags Match flags
 * @param is_basename True if path is a basename (no '/' characters)
 * @return true if pattern matches path
 */
static bool match_fnmatch(
    const char *pattern,
    const char *path,
    match_flags_t flags,
    bool is_basename
) {
    if (!pattern || !path) {
        return false;
    }

    /* Build fnmatch flags */
    int fnm_flags = 0;

    /* Use FNM_PATHNAME unless matching a basename
     *
     * FNM_PATHNAME prevents wildcards from matching '/' characters.
     * When matching a basename, the path has no '/' by definition,
     * so FNM_PATHNAME is unnecessary (micro-optimization).
     *
     * This also provides slightly more intuitive behavior for basename
     * matches, though the practical difference is negligible.
     */
    if (!is_basename) {
        fnm_flags |= FNM_PATHNAME;
    }

    /* Case folding */
    if (flags & MATCH_CASEFOLD) {
#ifdef FNM_CASEFOLD
        fnm_flags |= FNM_CASEFOLD;
#endif
    }

    return fnmatch(pattern, path, fnm_flags) == 0;
}

/**
 * Match double-star pattern
 *
 * Handles patterns containing ** (recursive glob).
 * Examples:
 *   - Double-star/foo matches "foo", "a/foo", "a/b/foo"
 *   - foo/double-star matches "foo/bar", "foo/a/b/c"
 *   - Recursive patterns match at multiple levels
 *
 * Algorithm:
 *   1. Split pattern at ** boundaries
 *   2. Match prefix before **
 *   3. Try matching suffix at all possible depths
 *   4. Handle multiple ** by recursion
 */
static bool match_doublestar_pattern(
    const char *pattern,
    const char *path,
    match_flags_t flags
) {
    if (!pattern || !path) {
        return false;
    }

    /* Find valid recursive glob ** in pattern */
    const char *doublestar = match_has_doublestar(pattern);
    if (!doublestar) {
        /* No valid ** - fall back to fnmatch (handles ** as regular wildcard) */
        return match_fnmatch(pattern, path, flags, false);
    }

    /* Split pattern into prefix, **, and suffix */
    size_t prefix_len = doublestar - pattern;

    /* Extract prefix (before **) */
    char prefix[4096] = {0};
    if (prefix_len > 0) {
        if (prefix_len >= sizeof(prefix)) {
            return false; /* Pattern too long */
        }
        memcpy(prefix, pattern, prefix_len);
        prefix[prefix_len] = '\0';

        /* Remove trailing / from prefix if present */
        if (prefix_len > 0 && prefix[prefix_len - 1] == '/') {
            prefix[prefix_len - 1] = '\0';
            prefix_len--;
        }
    }

    /* Extract suffix (after **) */
    const char *suffix = doublestar + 2; /* Skip ** */

    /* Skip leading / after ** */
    while (*suffix == '/') {
        suffix++;
    }

    /* Special case: ** at end (e.g., foo/double-star) - matches everything under prefix */
    if (*suffix == '\0') {
        if (prefix_len == 0) {
            /* Pattern is just "**" - matches everything */
            return true;
        }

        /* Check if path starts with prefix */
        if (strncmp(path, prefix, prefix_len) == 0) {
            /* Exact match or prefix/ match */
            if (path[prefix_len] == '\0' || path[prefix_len] == '/') {
                return true;
            }
        }
        return false;
    }

    /* Special case: ** at start (e.g., double-star/foo) - matches at any depth */
    if (prefix_len == 0) {
        /* Try matching suffix at current path */
        if (match_pattern_internal(suffix, path, flags, false)) {
            return true;
        }

        /* Try matching suffix at all subdirectory levels */
        const char *slash = path;
        while ((slash = strchr(slash, '/')) != NULL) {
            slash++; /* Skip the / */
            if (match_pattern_internal(suffix, slash, flags, false)) {
                return true;
            }
        }
        return false;
    }

    /* General case: prefix with double-star followed by suffix */

    /* Path must start with prefix */
    if (strncmp(path, prefix, prefix_len) != 0) {
        return false;
    }

    /* After prefix, must be end or / */
    if (path[prefix_len] != '\0' && path[prefix_len] != '/') {
        return false;
    }

    /* Start search after prefix */
    const char *search_start = path + prefix_len;
    if (*search_start == '/') {
        search_start++; /* Skip the / */
    }

    /* Try matching suffix at all depths under prefix */

    /* Zero-length ** match: recursive glob can match zero components */
    if (match_pattern_internal(suffix, search_start, flags, false)) {
        return true;
    }

    /* Non-zero length ** matches: try at each subdirectory */
    const char *slash = search_start;
    while ((slash = strchr(slash, '/')) != NULL) {
        slash++; /* Skip the / */
        if (match_pattern_internal(suffix, slash, flags, false)) {
            return true;
        }
    }

    return false;
}

/**
 * Internal pattern matching with recursion control
 *
 * @param pattern Pattern to match
 * @param path Path to test
 * @param flags Matching flags
 * @param is_basename_match True if this is a basename-only match
 */
static bool match_pattern_internal(
    const char *pattern,
    const char *path,
    match_flags_t flags,
    bool is_basename_match
) {
    if (!pattern || !path) {
        return false;
    }

    /* Empty pattern never matches */
    if (*pattern == '\0') {
        return false;
    }

    /* Empty path never matches (unless pattern is ** which matches zero components) */
    if (*path == '\0') {
        /* Only double-star patterns (with or without trailing slash) match empty path */
        if (strcmp(pattern, "**") == 0 || strcmp(pattern, "**/") == 0) {
            return true;
        }
        return false;
    }

    /* Optimization: Skip ** processing for basename matches
     *
     * Basenames never contain '/' characters by definition (they're the last
     * path component). Patterns with ** are designed to match across directory
     * levels, which is meaningless for basenames.
     *
     * Example:
     *   Pattern: double-star followed by .log extension
     *   Basename: "app.log"
     *   Result: No match (double-star requires directory structure)
     *
     * This optimization avoids the expensive recursive match_doublestar_pattern()
     * call when we know it cannot possibly match.
     */
    if (is_basename_match && match_has_doublestar(pattern)) {
        return false;
    }

    /* Handle ** patterns (recursive glob) */
    if ((flags & MATCH_DOUBLESTAR) && match_has_doublestar(pattern)) {
        return match_doublestar_pattern(pattern, path, flags);
    }

    /* Use fnmatch for simple patterns
     *
     * Pass through is_basename_match to enable micro-optimization:
     * - If true, path is a basename (no '/'), so FNM_PATHNAME is unnecessary
     * - If false, path may contain '/', so use FNM_PATHNAME
     */
    return match_fnmatch(pattern, path, flags, is_basename_match);
}

/**
 * Match path against glob pattern (main entry point)
 */
bool match_pattern(const char *pattern, const char *path, match_flags_t flags) {
    if (!pattern || !path) {
        return false;
    }

    /* Empty pattern never matches */
    if (*pattern == '\0') {
        return false;
    }

    /* Strip leading '/' from pattern (paths are relative) */
    pattern = strip_leading_slash(pattern);

    /* After stripping, empty pattern never matches */
    if (*pattern == '\0') {
        return false;
    }

    /* Check for trailing / (directory-only match) */
    bool pattern_is_directory = has_trailing_slash(pattern);

    if (pattern_is_directory) {
        /* Pattern matches directories only */
        if (!(flags & MATCH_DIRECTORY)) {
            /* Path is not a directory - no match */
            return false;
        }

        /* Strip trailing / for matching */
        char pattern_buf[4096];
        pattern = strip_trailing_slash(pattern, pattern_buf, sizeof(pattern_buf));
    }

    /* Normalize path - strip leading / */
    const char *normalized_path = path;
    while (*normalized_path == '/') {
        normalized_path++;
    }

    /* Empty path after normalization */
    if (*normalized_path == '\0') {
        return false;
    }

    /* Extract basename for fallback matching */
    const char *basename = match_basename(normalized_path);

    /* Determine if this is a basename-only pattern */
    bool is_basename_pattern = match_is_basename_pattern(pattern);

    /* Try matching full path (anchored) */
    if (match_pattern_internal(pattern, normalized_path, flags, false)) {
        return true;
    }

    /* Try matching basename (if pattern has no /) */
    if (is_basename_pattern && basename != normalized_path) {
        /* Pattern has no / - try matching basename */
        if (match_pattern_internal(pattern, basename, flags, true)) {
            return true;
        }
    }

    /* Directory prefix matching (gitignore-style)
     *
     * Pattern "foo" matches "foo/bar/baz"
     * Pattern ".config" matches ".config/fish/config.fish"
     *
     * This works for both basename-only patterns and anchored patterns:
     * - Basename pattern ".vim" matches ".vim/vimrc"
     * - Anchored pattern ".config/fish" matches ".config/fish/config.fish"
     *
     * Check if normalized_path starts with pattern followed by /
     */
    size_t pattern_len = strlen(pattern);
    if (strncmp(pattern, normalized_path, pattern_len) == 0 &&
        normalized_path[pattern_len] == '/') {
        return true;
    }

    return false;
}

/**
 * Match path against multiple patterns (logical OR)
 */
bool match_any(
    char **patterns,
    size_t pattern_count,
    const char *path,
    match_flags_t flags
) {
    if (!path || !patterns || pattern_count == 0) {
        return false;
    }

    /* Test each pattern */
    for (size_t i = 0; i < pattern_count; i++) {
        if (match_pattern(patterns[i], path, flags)) {
            return true;
        }
    }

    return false;
}
