/**
 * match.h - Comprehensive pattern matching utilities
 *
 * Provides robust gitignore-style glob pattern matching with full support for:
 *   - Standard wildcards: * ? [abc]
 *   - Recursive globs: **
 *   - Directory matching: trailing /
 *   - Path anchoring: leading /
 *   - Basename vs full path matching
 *
 * This module consolidates all pattern matching logic used across the codebase
 * (previously duplicated between pattern.c and ignore.c).
 *
 * Pattern Syntax (gitignore-compatible):
 *
 *   Wildcards:
 *     *        Matches any characters except /
 *     ?        Matches any single character except /
 *     [abc]    Matches one character from set
 *     [a-z]    Matches one character from range
 *     [!abc]   Matches one character NOT in set
 *
 *   Double-star (recursive glob):
 *     Double-star followed by /foo   Matches foo at any depth
 *     foo followed by double-star    Matches everything under foo/
 *     Path components separated      Matches at any nesting level
 *
 *   Path semantics:
 *     foo      Pattern without / matches basename at any depth
 *              Examples: "*.key" matches "api.key", "dir/api.key"
 *
 *     foo/bar  Pattern with / matches from root (anchored)
 *              Examples: ".ssh/id_*" matches ".ssh/id_rsa"
 *                       but NOT "backup/.ssh/id_rsa"
 *
 *     /foo     Leading / explicitly anchors to root (/ is stripped)
 *              Examples: "/.ssh" same as ".ssh"
 *
 *     foo/     Trailing / matches directories only
 *              Examples: "cache/" matches directory "cache"
 *                       but NOT file "cache"
 *
 *   Directory prefix matching:
 *     .config  Matches .config and everything under it
 *              Examples: ".config" matches ".config/fish/config.fish"
 *              This is gitignore-style directory prefix matching
 *
 * Edge Cases Handled:
 *   - Empty patterns never match
 *   - Empty paths never match
 *   - Patterns like "**" match everything
 *   - Patterns with double-star handle zero-length matches
 *   - Multiple consecutive ** are treated as single **
 *   - Proper escaping in character classes
 *   - Case-sensitive matching by default (configurable)
 *
 * Performance Notes:
 *   - Simple patterns (no **) use fast fnmatch()
 *   - Patterns with ** use recursive matching (slower but still fast)
 *   - Basename matching is optimized with single strcmp
 *   - No dynamic allocation in hot paths
 */

#ifndef DOTTA_MATCH_H
#define DOTTA_MATCH_H

#include <stdbool.h>
#include <stddef.h>

/**
 * Match flags - control matching behavior
 */
typedef enum {
    MATCH_DEFAULT     = 0,        /* Default behavior */
    MATCH_PATHNAME    = 1 << 0,   /* Wildcards don't match / (always on for *) */
    MATCH_DIRECTORY   = 1 << 1,   /* Path is a directory (enables trailing /) */
    MATCH_CASEFOLD    = 1 << 2,   /* Case-insensitive matching */
    MATCH_DOUBLESTAR  = 1 << 3,   /* Enable ** recursive glob support */
} match_flags_t;

/**
 * Match a path against a glob pattern
 *
 * Core pattern matching function implementing gitignore-style semantics.
 *
 * Pattern rules:
 *   - Pattern without '/': Matches basename at any depth
 *     Example: "*.log" matches "app.log" and "dir/app.log"
 *
 *   - Pattern with '/': Matches full path from root (anchored)
 *     Example: ".ssh/id_*" matches ".ssh/id_rsa" but not "backup/.ssh/id_rsa"
 *
 *   - Leading '/' in pattern: Stripped (paths are relative)
 *     Example: "/.ssh/id_*" treated as ".ssh/id_*"
 *
 *   - Trailing '/' in pattern: Matches directories only (requires MATCH_DIRECTORY flag)
 *     Example: "cache/" matches directory "cache" but not file "cache"
 *
 *   - Double-star (recursive glob): Matches zero or more path components
 *     Example: Recursive patterns match at multiple directory levels
 *     Requires MATCH_DOUBLESTAR flag
 *
 * Flags:
 *   - MATCH_PATHNAME: Wildcards (star and question mark) do not match / (default for star)
 *   - MATCH_DIRECTORY: Path is a directory (enables trailing / matching)
 *   - MATCH_CASEFOLD: Case-insensitive matching
 *   - MATCH_DOUBLESTAR: Enable double-star recursive glob (recommended)
 *
 * @param pattern Glob pattern (must not be NULL)
 * @param path Path to test (must not be NULL)
 * @param flags Matching flags (bitwise OR of match_flags_t)
 * @return true if path matches pattern, false otherwise
 */
bool match_pattern(const char *pattern, const char *path, match_flags_t flags);

/**
 * Match path against multiple patterns (logical OR)
 *
 * Tests path against all patterns, returns true if ANY pattern matches.
 * Useful for allow-lists and exclude lists.
 *
 * The patterns array is never modified by this function - it is read-only.
 * The signature uses char** for compatibility with various string array types.
 *
 * @param patterns Array of patterns (can be NULL if count is 0) - NOT MODIFIED
 * @param pattern_count Number of patterns
 * @param path Path to test (must not be NULL)
 * @param flags Matching flags (same for all patterns)
 * @return true if path matches ANY pattern, false otherwise
 */
bool match_any(
    char **patterns,
    size_t pattern_count,
    const char *path,
    match_flags_t flags
);

/**
 * Check if pattern contains double-star (**)
 *
 * Utility function to detect if a pattern uses ** recursive glob.
 * Useful for optimization - patterns without ** can use faster code paths.
 *
 * @param pattern Pattern to check (must not be NULL)
 * @return true if pattern contains **, false otherwise
 */
bool match_has_doublestar(const char *pattern);

/**
 * Check if pattern is basename-only (no /)
 *
 * Utility function to detect if a pattern matches basename at any depth.
 * Basename-only patterns are those without any '/' character.
 *
 * Examples:
 *   "*.log" -> true (basename-only)
 *   ".ssh/id_*" -> false (has /, anchored)
 *   "/foo" -> false (has /, anchored even after stripping leading /)
 *
 * @param pattern Pattern to check (must not be NULL)
 * @return true if pattern is basename-only, false otherwise
 */
bool match_is_basename_pattern(const char *pattern);

/**
 * Extract basename from path
 *
 * Returns pointer to the last component of the path.
 * If path has no '/', returns the path itself.
 *
 * Examples:
 *   "foo/bar/baz" -> "baz"
 *   "foo" -> "foo"
 *   "/foo/bar" -> "bar"
 *   "foo/" -> "" (empty basename)
 *
 * @param path Path (must not be NULL)
 * @return Pointer to basename (within path, do not free)
 */
const char *match_basename(const char *path);

#endif /* DOTTA_MATCH_H */
