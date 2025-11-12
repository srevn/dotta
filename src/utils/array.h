/**
 * array.h - Dynamic string array utilities
 *
 * Provides a dynamic array of strings with automatic growth.
 */

#ifndef DOTTA_ARRAY_H
#define DOTTA_ARRAY_H

#include <types.h>

/**
 * Create a new string array
 *
 * @return Newly allocated array (must be freed with string_array_free)
 */
string_array_t *string_array_create(void);

/**
 * Create string array with initial capacity
 *
 * @param capacity Initial capacity
 * @return Newly allocated array
 */
string_array_t *string_array_create_with_capacity(size_t capacity);

/**
 * Free string array and all contained strings
 *
 * Generic callback signature for use with containers (e.g., hashmap_free).
 * Accepts void* to match standard C cleanup callback pattern.
 *
 * @param ptr Array to free (can be NULL)
 */
void string_array_free(void *ptr);

/**
 * Deep clone string array
 *
 * Creates a new array with duplicates of all strings. The returned array
 * is completely independent of the source array.
 *
 * @param src Source array (can be NULL)
 * @return Cloned array or NULL if src is NULL or allocation fails (must free with string_array_free)
 */
string_array_t *string_array_clone(const string_array_t *src);

/**
 * Push a string to the array (copies the string)
 *
 * @param arr Array
 * @param str String to push (will be duplicated)
 * @return Error or NULL on success
 */
error_t *string_array_push(string_array_t *arr, const char *str);

/**
 * Push a string without copying (transfers ownership)
 *
 * @param arr Array
 * @param str String to push (must be heap-allocated, ownership transferred)
 * @return Error or NULL on success
 */
error_t *string_array_push_take(string_array_t *arr, char *str);

/**
 * Get string at index
 *
 * @param arr Array
 * @param index Index
 * @return String at index (NULL if out of bounds)
 */
const char *string_array_get(const string_array_t *arr, size_t index);

/**
 * Remove string at index
 *
 * @param arr Array
 * @param index Index
 * @return Error or NULL on success
 */
error_t *string_array_remove(string_array_t *arr, size_t index);

/**
 * Remove string by value (first occurrence)
 *
 * @param arr Array
 * @param str String to remove
 * @return Error or NULL on success (not an error if not found)
 */
error_t *string_array_remove_value(string_array_t *arr, const char *str);

/**
 * Check if array contains string
 *
 * @param arr Array
 * @param str String to search for
 * @return true if found, false otherwise
 */
bool string_array_contains(const string_array_t *arr, const char *str);

/**
 * Clear array (removes all strings)
 *
 * @param arr Array
 */
void string_array_clear(string_array_t *arr);

/**
 * Get array size
 *
 * @param arr Array
 * @return Number of strings in array
 */
size_t string_array_size(const string_array_t *arr);

/**
 * Reserve capacity for array
 *
 * Ensures array can hold at least the specified number of elements
 * without reallocation.
 *
 * @param arr Array
 * @param capacity Desired minimum capacity
 * @return Error or NULL on success
 */
error_t *string_array_reserve(string_array_t *arr, size_t capacity);

/**
 * Sort array alphabetically
 *
 * @param arr Array
 */
void string_array_sort(string_array_t *arr);

/**
 * Compute set difference (A - B)
 *
 * Returns all elements in set_a that are NOT in set_b.
 * Uses hashmap internally for efficient O(n+m) performance.
 *
 * Duplicates in either set are handled naturally - each occurrence
 * in set_a is checked independently against set_b.
 *
 * Examples:
 *   A = ["a", "b", "c"], B = ["b", "d"] → Result = ["a", "c"]
 *   A = ["x", "y"], B = [] → Result = ["x", "y"]
 *   A = [], B = ["a"] → Result = []
 *   A = ["a", "a"], B = ["a"] → Result = []
 *
 * @param set_a Elements to filter (must not be NULL)
 * @param set_b Elements to exclude (must not be NULL)
 * @param out_difference Result array (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *string_array_difference(
    const string_array_t *set_a,
    const string_array_t *set_b,
    string_array_t **out_difference
);

/**
 * RAII cleanup attribute helper
 */
static inline void cleanup_string_array(string_array_t **arr) {
    if (arr && *arr) {
        string_array_free(*arr);
        *arr = NULL;
    }
}

#define STRING_ARRAY_CLEANUP __attribute__((cleanup(cleanup_string_array)))

#endif /* DOTTA_ARRAY_H */
