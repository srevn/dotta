/**
 * array.h - Dynamic arrays
 *
 * Two vectors, with different owners:
 *
 *   string_array_t — owns each element string (push duplicates, deinit frees);
 *                    the heap's, with matching init/deinit and new/free pairs.
 *   ptr_array_t    — borrows every pointer it holds; its spine lives in the
 *                    arena it was made in, and goes with it: nothing releases a
 *                    pointer array.
 *
 * Both structs are transparent: direct field access is the intended usage.
 *
 * A pointer array remembers its arena. ptr_array_init names it once, where the
 * array is made — the one place its lifetime is known — and every growth takes
 * its room there, so no push names an arena and a callee that fills a caller's
 * array takes none. A zeroed array ({ 0 }) is empty and may be read; a push to
 * one dies at its site.
 *
 * Growth cannot fail: a push, a reserve or a clone succeeds or the run dies of
 * exhaustion (base/heap.h, base/arena.h), so none of them answers anything, and
 * a count whose bytes no memory could hold is exhaustion too.
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
 */
void string_array_init_cap(string_array_t *arr, size_t cap);

/**
 * Release all owned memory (strings + backing array). Resets struct to zero state.
 * Safe to call on zero-initialized or already-deinitialized arrays. No-op on NULL.
 */
void string_array_deinit(string_array_t *arr);

/**
 * Allocate and initialize a new array on the heap.
 *
 * @param cap Initial capacity (0 for no pre-allocation)
 * @return New array; never NULL
 */
string_array_t *string_array_new(size_t cap);

/**
 * Deinitialize and free a heap-allocated array. No-op on NULL.
 */
void string_array_free(string_array_t *arr);

/**
 * Callback-compatible free for use with hashmap_free() and similar APIs. Casts
 * void* to string_array_t* and calls string_array_free().
 */
void string_array_free_cb(void *ptr);

/**
 * Append a copy of str to the array.
 *
 * @param arr Array (must not be NULL)
 * @param str String to copy and append (must not be NULL)
 */
void string_array_push(string_array_t *arr, const char *str);

/**
 * Append str to the array, transferring ownership. str must be heap-allocated.
 *
 * @param arr Array (must not be NULL)
 * @param str Heap-allocated string (must not be NULL, ownership transferred)
 */
void string_array_push_owned(string_array_t *arr, char *str);

/**
 * Ensure capacity for at least cap elements without reallocation.
 */
void string_array_reserve(string_array_t *arr, size_t cap);

/**
 * Remove element at index, shifting subsequent elements left. O(n). No-op if
 * arr is NULL or index is out of bounds.
 */
void string_array_remove(string_array_t *arr, size_t index);

/**
 * Remove element at index by swapping with the last element. O(1). Does not
 * preserve order. No-op if arr is NULL or index is out of bounds.
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
 * Deep-copy src into dst. dst is initialized by this function — caller must deinit
 * any previous contents before calling to avoid leaks.
 *
 * @param src Source array (must not be NULL)
 * @param dst Destination (must not be NULL, overwritten)
 */
void string_array_clone(const string_array_t *src, string_array_t *dst);

/**
 * Join array elements into a single delimiter-separated string.
 *
 * @param arr Array (NULL or empty joins to "")
 * @param delimiter Separator between elements (NULL treated as empty)
 * @return Heap-allocated string; never NULL
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

/* === ptr_array_t — borrowed pointers, in the arena it was made in === */

/**
 * Make an empty pointer array whose spine lives in `arena`
 *
 * @param arr   Array to initialize (must not be NULL)
 * @param arena Arena every growth takes its room from (must not be NULL)
 */
void ptr_array_init(ptr_array_t *arr, arena_t *arena);

/**
 * Make an empty pointer array with room for `cap` pointers, in `arena`
 *
 * Pushes up to `cap` move nothing: ptr_array_init, then ptr_array_reserve.
 *
 * @param arr   Array to initialize (must not be NULL)
 * @param arena Arena every growth takes its room from (must not be NULL)
 * @param cap   Pointers to make room for (0 makes none)
 */
void ptr_array_init_cap(ptr_array_t *arr, arena_t *arena, size_t cap);

/**
 * Append a pointer, borrowed
 *
 * NULL is a value like any other. The spine grows in the array's arena
 * (base/arena.h arena_grow): a pointer kept into the old spine is stale after a
 * push that grew, and traps under AddressSanitizer.
 *
 * @param arr Array (must not be NULL; given its arena by ptr_array_init)
 * @param p   Pointer to store (may be NULL)
 */
void ptr_array_push(ptr_array_t *arr, const void *p);

/**
 * Make room for at least `cap` pointers, in the array's arena
 *
 * @param arr Array (must not be NULL; given its arena by ptr_array_init)
 * @param cap Pointers the array must hold without a growth
 */
void ptr_array_reserve(ptr_array_t *arr, size_t cap);

/**
 * Empty the array; its room stays. No-op on NULL.
 */
void ptr_array_clear(ptr_array_t *arr);

#endif /* DOTTA_ARRAY_H */
