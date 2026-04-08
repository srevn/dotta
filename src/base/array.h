/**
 * array.h - Dynamic string array
 *
 * Growable array of heap-allocated strings with ownership semantics.
 * The struct is transparent: direct field access (arr->count, arr->items[i])
 * is the intended usage pattern.
 *
 * Supports both stack and heap allocation:
 *   Stack:  string_array_t arr = {0};  ... string_array_deinit(&arr);
 *   Heap:   string_array_t *arr = string_array_new(0);  ... string_array_free(arr);
 */

#ifndef DOTTA_ARRAY_H
#define DOTTA_ARRAY_H

#include <types.h>

/**
 * Initialize array to empty state.
 * Equivalent to zero-initialization: string_array_t arr = {0};
 */
void string_array_init(string_array_t *arr);

/**
 * Initialize array with pre-allocated capacity.
 *
 * @param arr Array to initialize
 * @param cap Desired initial capacity
 * @return Error on allocation failure
 */
error_t *string_array_init_cap(string_array_t *arr, size_t cap);

/**
 * Release all owned memory (strings + backing array).
 * Resets struct to zero state. Safe to call on zero-initialized or
 * already-deinitialized arrays. No-op on NULL.
 */
void string_array_deinit(string_array_t *arr);

/**
 * Allocate and initialize a new array on the heap.
 *
 * @param cap Initial capacity (0 for no pre-allocation)
 * @return New array, or NULL on allocation failure
 */
string_array_t *string_array_new(size_t cap);

/**
 * Deinitialize and free a heap-allocated array. No-op on NULL.
 */
void string_array_free(string_array_t *arr);

/**
 * Callback-compatible free for use with hashmap_free() and similar APIs.
 * Casts void* to string_array_t* and calls string_array_free().
 */
void string_array_free_cb(void *ptr);

/**
 * Append a copy of str to the array.
 *
 * @param arr Array (must not be NULL)
 * @param str String to copy and append (must not be NULL)
 * @return Error on allocation failure
 */
error_t *string_array_push(string_array_t *arr, const char *str);

/**
 * Append str to the array, transferring ownership.
 * str must be heap-allocated. On error, caller retains ownership.
 *
 * @param arr Array (must not be NULL)
 * @param str Heap-allocated string (must not be NULL, ownership transferred)
 * @return Error on allocation failure
 */
error_t *string_array_push_owned(string_array_t *arr, char *str);

/**
 * Ensure capacity for at least cap elements without reallocation.
 *
 * @return Error on allocation failure
 */
error_t *string_array_reserve(string_array_t *arr, size_t cap);

/**
 * Remove element at index, shifting subsequent elements left. O(n).
 * No-op if arr is NULL or index is out of bounds.
 */
void string_array_remove(string_array_t *arr, size_t index);

/**
 * Remove element at index by swapping with the last element. O(1).
 * Does not preserve order. No-op if arr is NULL or index is out of bounds.
 */
void string_array_swap_remove(string_array_t *arr, size_t index);

/**
 * Remove first occurrence of str (strcmp match).
 *
 * @return true if found and removed, false otherwise
 */
bool string_array_remove_value(string_array_t *arr, const char *str);

/**
 * Remove all elements, freeing each string. Retains allocated capacity.
 */
void string_array_clear(string_array_t *arr);

/**
 * Linear search for str (strcmp match).
 *
 * @return true if found
 */
bool string_array_contains(const string_array_t *arr, const char *str);

/**
 * Sort elements lexicographically in place (strcmp order).
 */
void string_array_sort(string_array_t *arr);

/**
 * Deep-copy src into dst.
 * dst is initialized by this function — caller must deinit any previous
 * contents before calling to avoid leaks.
 *
 * @param src Source array (must not be NULL)
 * @param dst Destination (must not be NULL, overwritten)
 * @return Error on allocation failure (dst left in clean zero state)
 */
error_t *string_array_clone(const string_array_t *src, string_array_t *dst);

/** Cleanup helper for heap-allocated arrays (string_array_t *) */
static inline void cleanup_string_array(string_array_t **arr) {
    if (arr && *arr) {
        string_array_free(*arr);
        *arr = NULL;
    }
}

/** Cleanup helper for stack/embedded arrays (string_array_t) */
static inline void cleanup_string_array_val(string_array_t *arr) {
    if (arr) {
        string_array_deinit(arr);
    }
}

/** For heap-allocated: string_array_t *p STRING_ARRAY_CLEANUP = ...; */
#define STRING_ARRAY_CLEANUP __attribute__((cleanup(cleanup_string_array)))

/** For stack/embedded: string_array_t arr STRING_ARRAY_AUTO = {0}; */
#define STRING_ARRAY_AUTO __attribute__((cleanup(cleanup_string_array_val)))

#endif /* DOTTA_ARRAY_H */
