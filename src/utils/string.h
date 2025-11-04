/**
 * string.h - String utility functions
 *
 * Helper functions for common string operations.
 */

#ifndef DOTTA_STRING_H
#define DOTTA_STRING_H

#include <stdbool.h>
#include <stdlib.h>

#include "types.h"

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
char *str_join(char **strings, size_t count, const char *delimiter);

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
 * Use this when you own a string pointer and need to replace it with a
 * different value while ensuring proper memory management.
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
 * Check if string looks like a Git reference
 *
 * Recognizes:
 * - Commit SHAs (7-40 hex chars)
 * - HEAD and variations (HEAD~1, HEAD^, HEAD~3^2)
 * - SHA with modifiers (abc123^, def456~2)
 * - @ symbol (current commit shorthand)
 *
 * Note: Does not verify ref exists in repository.
 *
 * @param str String to check (can be NULL)
 * @return true if str looks like a git reference
 */
bool str_looks_like_git_ref(const char *str);

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
