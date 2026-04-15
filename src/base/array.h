/**
 * array.h - Dynamic arrays
 *
 * Two flavors with different ownership semantics:
 *
 *   string_array_t — owns each element string (push duplicates, deinit frees).
 *   ptr_array_t    — owns only the buffer; elements are borrowed pointers.
 *
 * Both structs are transparent (direct field access is the intended usage)
 * and support stack and heap lifecycles via matching init/deinit and
 * new/free pairs.
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

/**
 * Join array elements into a single delimiter-separated string.
 *
 * @param arr Array (NULL or empty returns strdup(""))
 * @param delimiter Separator between elements (NULL treated as empty)
 * @return Heap-allocated string, or NULL on allocation failure
 */
char *string_array_join(const string_array_t *arr, const char *delimiter);

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

/* === ptr_array_t — borrowed-pointer dynamic array === */

/**
 * Initialize array to empty state.
 * Equivalent to zero-initialization: ptr_array_t arr = {0};
 */
void ptr_array_init(ptr_array_t *arr);

/**
 * Initialize array with pre-allocated capacity.
 *
 * @param arr Array to initialize
 * @param cap Desired initial capacity
 * @return Error on allocation failure
 */
error_t *ptr_array_init_cap(ptr_array_t *arr, size_t cap);

/**
 * Release the backing buffer and reset to zero state.
 *
 * Pointed-to elements are NOT freed (they are borrowed). Safe on
 * zero-initialized, already-deinitialized, or NULL arrays.
 */
void ptr_array_deinit(ptr_array_t *arr);

/**
 * Allocate and initialize a new array on the heap.
 *
 * @param cap Initial capacity (0 for no pre-allocation)
 * @return New array, or NULL on allocation failure
 */
ptr_array_t *ptr_array_new(size_t cap);

/**
 * Deinitialize and free a heap-allocated array. No-op on NULL.
 */
void ptr_array_free(ptr_array_t *arr);

/**
 * Callback-compatible free for use with hashmap_free() and similar APIs.
 * Casts void* to ptr_array_t* and calls ptr_array_free().
 */
void ptr_array_free_cb(void *ptr);

/**
 * Append a pointer to the array.
 *
 * NULL is a valid element value.
 *
 * @param arr Array (must not be NULL)
 * @param p   Pointer to store (may be NULL)
 * @return Error on allocation failure
 */
error_t *ptr_array_push(ptr_array_t *arr, const void *p);

/**
 * Ensure capacity for at least cap elements without reallocation.
 *
 * @return Error on allocation failure
 */
error_t *ptr_array_reserve(ptr_array_t *arr, size_t cap);

/**
 * Reset count to 0 without freeing the backing buffer.
 * No-op on NULL.
 */
void ptr_array_clear(ptr_array_t *arr);

/**
 * Hand off the backing buffer to the caller and reset the array.
 *
 * On success:
 *   - arr is reset to the empty state ({0}); safe to reuse or deinit.
 *   - Caller owns the returned buffer and must free() it.
 *
 * Empty-array contract: if the array holds zero elements, the internal
 * buffer (if any) is freed and NULL is returned. This guarantees the
 * invariant (return == NULL) <=> (*out_count == 0).
 *
 * Invalid-input contract: if arr or out_count is NULL the transfer is
 * refused — arr is left intact and NULL is returned. *out_count is set
 * to 0 whenever non-NULL.
 *
 * @param arr       Array to drain (must not be NULL)
 * @param out_count Receives element count (must not be NULL)
 * @return Buffer of `count` pointers (caller frees), or NULL when empty
 *         or on invalid input
 */
const void **ptr_array_steal(ptr_array_t *arr, size_t *out_count);

/** Cleanup helper for heap-allocated arrays (ptr_array_t *) */
static inline void cleanup_ptr_array(ptr_array_t **arr) {
    if (arr && *arr) {
        ptr_array_free(*arr);
        *arr = NULL;
    }
}

/** Cleanup helper for stack/embedded arrays (ptr_array_t) */
static inline void cleanup_ptr_array_val(ptr_array_t *arr) {
    if (arr) {
        ptr_array_deinit(arr);
    }
}

/** For heap-allocated: ptr_array_t *p PTR_ARRAY_CLEANUP = ...; */
#define PTR_ARRAY_CLEANUP __attribute__((cleanup(cleanup_ptr_array)))

/** For stack/embedded: ptr_array_t arr PTR_ARRAY_AUTO = {0}; */
#define PTR_ARRAY_AUTO __attribute__((cleanup(cleanup_ptr_array_val)))

#endif /* DOTTA_ARRAY_H */
