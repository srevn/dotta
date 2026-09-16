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
 * Join array of strings with delimiter
 *
 * @param strings Array of strings
 * @param count Number of strings
 * @param delimiter Delimiter to insert between strings
 * @return Newly allocated joined string (must be freed)
 */
char *str_join(const char *const *strings, size_t count, const char *delimiter);

/**
 * Format string (like sprintf but allocates)
 *
 * @param fmt Format string
 * @param ... Format arguments
 * @return Newly allocated formatted string (must be freed)
 */
char *str_format(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * Duplicate string (like strdup but with error handling)
 *
 * @param str String to duplicate
 * @param out Output pointer for duplicated string
 * @return Error or NULL on success
 */
error_t *str_dup(const char *str, char **out);

/**
 * Replace owned string pointer with copy of new value
 *
 * Safely replaces a heap-allocated string pointer by:
 * 1. Freeing the old value (safe if NULL or uninitialized)
 * 2. Allocating a copy of the new value (NULL if new_value is NULL)
 * 3. Returning error if allocation fails (target left as NULL)
 *
 * Use this when you own a string pointer and need to replace it with a different
 * value while ensuring proper memory management.
 *
 * Example:
 *   char *name = strdup("Alice");
 *   err = str_replace_owned(&name, "Bob");  // Frees "Alice", allocates "Bob"
 *   err = str_replace_owned(&name, NULL);   // Frees "Bob", sets to NULL
 *   free(name);  // Safe even if replace failed
 *
 * @param target Pointer to owned string pointer (must not be NULL)
 * @param new_value New value to copy (can be NULL to free without replacing)
 * @return Error or NULL on success
 */
error_t *str_replace_owned(char **target, const char *new_value);

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
