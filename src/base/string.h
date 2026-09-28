/**
 * string.h - String utility functions
 *
 * Helper functions for common string operations. Strings are read here as strings:
 * no product's grammar lives in this file, so a question whose answer turns on
 * what a word *means* to dotta or to Git belongs with the module that owns the
 * words — a storage name's shape with the labels (infra/label.h, infra/path.h),
 * a commit's with the syntax that spells one (base/refspec.h).
 */

#ifndef DOTTA_STRING_H
#define DOTTA_STRING_H

#include <stdbool.h>
#include <stdlib.h>
#include <types.h>

/**
 * Two strings that say the same thing, either of which may be absent
 *
 * NULL is a value here, not a programming error: the fields this compares are
 * optional by design — a claim's owner and group, an item's key — and "neither
 * side has one" is as much an equality as "both say root". Two NULLs are equal,
 * a NULL and a string are not, and strcmp is reached only when both are there.
 *
 * @param a First string (can be NULL)
 * @param b Second string (can be NULL)
 * @return true if both are absent, or both are present and equal
 */
bool str_equal(const char *a, const char *b);

/**
 * Check if string starts with prefix
 *
 * @param str String to check
 * @param prefix Prefix to look for
 * @return true if str starts with prefix
 */
bool str_starts_with(const char *str, const char *prefix);

/**
 * Check if string ends with suffix
 *
 * @param str String to check
 * @param suffix Suffix to look for
 * @return true if str ends with suffix
 */
bool str_ends_with(const char *str, const char *suffix);

/**
 * Is `path` strictly beneath directory `dir`?
 *
 * A prefix and then a separator, so "/a/bc" is not beneath "/a/b" — and neither
 * is "/a/b" itself. strncmp == 0 guarantees `path` has at least dir_len bytes,
 * so reading path[dir_len] is in bounds: it is either the terminator or a real
 * character.
 *
 * `dir` carries no trailing separator — the boundary byte is read at dir_len.
 * `path` is read as written: a prefix and then a separator is beneath, whatever
 * else the spelling holds, so a caller testing an argument before it is folded
 * gets the lexical answer it asked for.
 *
 * @param path Candidate path
 * @param dir Directory path
 * @param dir_len strlen(dir), passed so a caller testing many pairs hoists it
 * @return true if path is strictly beneath dir
 */
bool str_path_beneath(const char *path, const char *dir, size_t dir_len);

/**
 * Length of an absolute path's parent
 *
 * The index of the last separator, or 1 for a path directly beneath the root:
 * "/etc/hosts" → 4, "/etc" → 1 (the root keeps its slash). A path with no separator
 * answers 0 — not absolute, which a caller handed canonical paths never meets
 * and reads as "cannot happen". Pure in the string; whether the parent is there
 * is the caller's question.
 *
 * @param path Canonical absolute path
 * @return The parent's length, or 0 when the path has no separator
 */
size_t str_path_parent_len(const char *path);

/**
 * Trim whitespace from both ends of string (in-place)
 *
 * @param str String to trim (modified in place)
 * @return Pointer to trimmed string (same as input)
 */
char *str_trim(char *str);

/**
 * Join a slice of strings with a delimiter, into an arena
 *
 * The delimiter stands between every two positions; a NULL string is an empty
 * one. A joined length no memory could hold is exhaustion (base/heap.h heap_die).
 * The slice is an argv's type, so a string array's entries and a command's
 * arguments pass without a cast.
 *
 * @param arena Arena the joined string lives in (must not be NULL)
 * @param strings The strings (may be NULL when count is 0)
 * @param count Number of strings
 * @param delimiter Delimiter to insert between strings (NULL is none)
 * @return The joined string, "" for none; never NULL
 */
char *str_join(
    arena_t *arena, char *const *strings, size_t count, const char *delimiter
);

/**
 * RAII cleanup for strings
 */
static inline void cleanup_string(char **str) {
    if (str && *str) {
        free(*str);
        *str = NULL;
    }
}

#define STRING_CLEANUP __attribute__((cleanup(cleanup_string)))

#endif /* DOTTA_STRING_H */
