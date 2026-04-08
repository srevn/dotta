/**
 * match.c - Comprehensive pattern matching implementation
 *
 * Implements robust gitignore-style glob pattern matching with full
 * support for **, directory matching, and all edge cases.
 */

#include "base/match.h"

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
 * Valid recursive glob - sequence of 2+ asterisks at a component boundary:
 *   - Preceded by '/' or at start of pattern
 *   - Followed by '/' or at end of pattern
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
 * @param is_basename True if path is a basename (no '/' characters)
 * @return true if pattern matches path
 */
static bool match_fnmatch(
    const char *pattern,
    const char *path,
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

    return fnmatch(pattern, path, fnm_flags) == 0;
}

/**
 * Match a glob pattern against a path prefix at equivalent component depth
 *
 * Counts the depth (number of components) in the pattern, extracts the same
 * number of leading components from the path, and compares them using fnmatch.
 * This correctly handles glob metacharacters (*, ?, [...]) in the prefix.
 *
 * @param pattern Prefix pattern (must not be NULL or empty)
 * @param path Path to match against (must not be NULL)
 * @return Pointer to boundary position in path (/ or \0), or NULL on no match
 */
static const char *match_path_prefix(
    const char *pattern,
    const char *path
) {
    if (!pattern || !*pattern || !path) {
        return NULL;
    }

    /* Count slashes in pattern to determine component depth */
    size_t n_slashes = 0;
    for (const char *p = pattern; *p; p++) {
        if (*p == '/') n_slashes++;
    }

    /* Walk path to the boundary after the same number of components.
     * Break at the (n_slashes + 1)-th slash, which separates the prefix
     * portion from the rest of the path. */
    const char *end = path;
    size_t seen = 0;
    while (*end) {
        if (*end == '/') {
            seen++;
            if (seen > n_slashes) break;
        }
        end++;
    }

    /* Path must have at least as many components as the pattern */
    if (seen < n_slashes) {
        return NULL;
    }

    /* Extract path prefix up to boundary */
    size_t len = (size_t) (end - path);
    char buf[4096];
    if (len >= sizeof(buf)) {
        return NULL;
    }
    memcpy(buf, path, len);
    buf[len] = '\0';

    /* Compare using fnmatch (handles glob characters correctly) */
    if (!match_fnmatch(pattern, buf, false)) {
        return NULL;
    }

    return end;
}

/**
 * Match double-star pattern
 *
 * Handles patterns containing ** (recursive glob).
 *
 * Algorithm:
 *   1. Split pattern at ** boundaries
 *   2. Match prefix before ** using fnmatch (via match_path_prefix)
 *   3. Try matching suffix at all possible depths
 *   4. Handle multiple ** by recursion
 */
static bool match_doublestar_pattern(
    const char *pattern,
    const char *path,
    match_flags_t flags,
    const char *doublestar
) {
    if (!pattern || !path) {
        return false;
    }

    /* Split pattern into prefix, **, and suffix */
    size_t prefix_len = doublestar - pattern;

    /* Extract prefix (before **) */
    char prefix[4096] = { 0 };
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

    /* Extract suffix (after **) - skip ALL consecutive asterisks (*** = **) */
    const char *suffix = doublestar;
    while (*suffix == '*') {
        suffix++;
    }

    /* Skip leading / after ** */
    while (*suffix == '/') {
        suffix++;
    }

    /* Special case: ** at end - matches everything under prefix */
    if (*suffix == '\0') {
        if (prefix_len == 0) {
            /* Pattern is just "**" - matches everything */
            return true;
        }

        /* Prefix must match path prefix, with more path following */
        const char *boundary = match_path_prefix(prefix, path);
        return boundary && *boundary == '/';
    }

    /* Special case: ** at start - matches at any depth */
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

    /* General case: prefix + ** + suffix */

    /* Match prefix against path using fnmatch */
    const char *boundary = match_path_prefix(prefix, path);
    if (!boundary) {
        return false;
    }

    /* After prefix, must be / or end */
    if (*boundary != '\0' && *boundary != '/') {
        return false;
    }

    /* Start search after prefix */
    const char *search_start = (*boundary == '/') ? boundary + 1 : boundary;

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

    /* Check once for valid ** in pattern */
    const char *doublestar = match_has_doublestar(pattern);

    /* Optimization: basenames never contain '/' so ** (which matches across
     * directory levels) is meaningless. Skip the expensive recursive call. */
    if (is_basename_match && doublestar) {
        return false;
    }

    /* Handle ** patterns (recursive glob) */
    if ((flags & MATCH_DOUBLESTAR) && doublestar) {
        return match_doublestar_pattern(pattern, path, flags, doublestar);
    }

    /* Use fnmatch for simple patterns
     *
     * Pass through is_basename_match to enable micro-optimization:
     * - If true, path is a basename (no '/'), so FNM_PATHNAME is unnecessary
     * - If false, path may contain '/', so use FNM_PATHNAME
     */
    return match_fnmatch(pattern, path, is_basename_match);
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

    /* Track explicit anchoring before stripping.
     * A leading / means the pattern is anchored to root and must NOT
     * fall back to basename matching, even if the stripped pattern has no /. */
    bool is_anchored = (*pattern == '/');

    /* Strip leading '/' from pattern (paths are relative) */
    pattern = strip_leading_slash(pattern);

    /* After stripping, empty pattern never matches */
    if (*pattern == '\0') {
        return false;
    }

    /* Check for trailing / (directory-only match) */
    bool pattern_is_directory = has_trailing_slash(pattern);

    /* Buffer must outlive the if-block since pattern may point into it */
    char pattern_buf[4096];

    if (pattern_is_directory) {
        /* Pattern matches directories only */
        if (!(flags & MATCH_DIRECTORY)) {
            /* Path is not a directory - no match */
            return false;
        }

        /* Strip trailing / for matching */
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

    /* Determine if this is a basename-only pattern.
     * A pattern is basename-only when it has no / AND was not explicitly anchored
     * with a leading /. Basename-only patterns match at any depth. */
    bool is_basename_pattern = !is_anchored && match_is_basename_pattern(pattern);

    /* Try matching full path (anchored) */
    if (match_pattern_internal(pattern, normalized_path, flags, false)) {
        return true;
    }

    /* Extract basename for fallback matching */
    const char *basename = match_basename(normalized_path);

    /* Try matching basename (if basename-only pattern and path has depth) */
    if (is_basename_pattern && basename != normalized_path) {
        if (match_pattern_internal(pattern, basename, flags, true)) {
            return true;
        }
    }

    /* Directory prefix matching (gitignore-style)
     *
     * If a pattern matches a directory component, everything under that
     * directory also matches. This works differently for each pattern type:
     *
     * Basename patterns: try against each intermediate component at any depth
     *   ".vim" matches "home/.vim/vimrc" (matches .vim component)
     *   "*.d" matches "home/conf.d/something" (glob against conf.d)
     *
     * Anchored patterns: try against each path prefix at / boundaries
     *   ".config/fish" matches ".config/fish/config.fish"
     *   "*.d/conf" matches "test.d/conf/file" (glob in prefix)
     */
    const char *comp_start = normalized_path;
    while (*comp_start) {
        const char *slash = strchr(comp_start, '/');
        if (!slash) break; /* Last component is not a directory prefix */

        if (is_basename_pattern) {
            /* Try pattern against this individual component */
            size_t comp_len = (size_t) (slash - comp_start);
            char comp[4096];
            if (comp_len < sizeof(comp)) {
                memcpy(comp, comp_start, comp_len);
                comp[comp_len] = '\0';
                if (match_pattern_internal(pattern, comp, flags, true)) {
                    return true;
                }
            }
        } else {
            /* Try pattern against path prefix up to this boundary */
            size_t plen = (size_t) (slash - normalized_path);
            char pbuf[4096];
            if (plen < sizeof(pbuf)) {
                memcpy(pbuf, normalized_path, plen);
                pbuf[plen] = '\0';
                if (match_pattern_internal(pattern, pbuf, flags, false)) {
                    return true;
                }
            }
        }

        comp_start = slash + 1;
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
