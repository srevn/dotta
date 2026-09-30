/**
 * array.h - Dynamic arrays
 *
 * Two vectors, each living in the arena it was made in and going with it: nothing
 * releases an array.
 *
 *   string_array_t — keeps a copy of every string it is handed, beside its spine;
 *                    entries[count] is NULL after every change, so the array is
 *                    an argv or an envp as it stands.
 *   ptr_array_t    — borrows every pointer it holds.
 *
 * Both structs are transparent: direct field access is the intended usage.
 *
 * An array remembers its arena. Its init names it once, where the array is made
 * — the one place its lifetime is known — and every growth and every copy takes
 * its room there, so no push names an arena and a callee that fills a caller's
 * array takes none. The strings of one string array therefore share one lifetime,
 * whatever their sources' were. A zeroed array ({ 0 }) is empty and may be read;
 * a push to one dies at its site.
 *
 * Growth cannot fail: a push, a reserve or a clone succeeds or the run dies of
 * exhaustion (base/heap.h, base/arena.h), so none of them answers anything, and
 * a count whose bytes no memory could hold is exhaustion too.
 */

#ifndef DOTTA_ARRAY_H
#define DOTTA_ARRAY_H

#include <types.h>

/* === string_array_t — names, each a copy in the arena it was made in === */

/**
 * Make an empty string array whose spine and copies live in `arena`
 *
 * @param arr   Array to initialize (must not be NULL)
 * @param arena Arena every growth and every copy takes its room from (must not
 *              be NULL)
 */
void string_array_init(string_array_t *arr, arena_t *arena);

/**
 * Make an empty string array with room for `cap` strings, in `arena`
 *
 * Pushes up to `cap` move nothing: string_array_init, then string_array_reserve.
 *
 * @param arr   Array to initialize (must not be NULL)
 * @param arena Arena every growth and every copy takes its room from (must not
 *              be NULL)
 * @param cap   Strings to make room for (0 makes none)
 */
void string_array_init_cap(string_array_t *arr, arena_t *arena, size_t cap);

/**
 * Append a copy of `str`, made in the array's arena
 *
 * The source may change or go once the push returns: the array holds its own
 * copy. The spine grows in the array's arena (base/arena.h arena_grow), so a
 * pointer kept into the old spine is stale after a push that grew; a string the
 * array holds never moves.
 *
 * @param arr Array (must not be NULL; given its arena by string_array_init)
 * @param str String to copy (must not be NULL)
 */
void string_array_push(string_array_t *arr, const char *str);

/**
 * Append a string formatted into the array's arena
 *
 * string_array_push of what arena_str_format would answer, with no second copy.
 * The format is dotta's own, so one that cannot be formatted is its writer's bug.
 *
 * @param arr Array (must not be NULL; given its arena by string_array_init)
 * @param fmt Format string (must not be NULL)
 */
void string_array_pushf(string_array_t *arr, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

/**
 * Make room for at least `cap` strings and the terminator after them, in the
 * array's arena
 *
 * @param arr Array (must not be NULL; given its arena by string_array_init)
 * @param cap Strings the array must hold without a growth (0 makes none)
 */
void string_array_reserve(string_array_t *arr, size_t cap);

/**
 * Copy `src` into `arena`: the spine and every string
 *
 * The clone is a value of `arena` alone, so a clone into a longer-lived arena
 * is how names outlive the arena they were listed in.
 *
 * @param src   Source array (must not be NULL)
 * @param arena Arena the clone lives in (must not be NULL)
 * @param dst   Destination, overwritten (must not be NULL)
 */
void string_array_clone(const string_array_t *src, arena_t *arena, string_array_t *dst);

/**
 * Remove the string at index, shifting those after it left. O(n). The string
 * stays its arena's. No-op if arr is NULL or index is out of bounds.
 */
void string_array_remove(string_array_t *arr, size_t index);

/**
 * Remove the string at index by moving the last into its place. O(1). Does not
 * preserve order. No-op if arr is NULL or index is out of bounds.
 */
void string_array_swap_remove(string_array_t *arr, size_t index);

/**
 * Remove the first occurrence of str (strcmp match).
 *
 * @return true if found and removed, false otherwise
 */
bool string_array_remove_value(string_array_t *arr, const char *str);

/**
 * Empty the array; its room stays. No-op on NULL.
 */
void string_array_clear(string_array_t *arr);

/**
 * Linear search for str (strcmp match).
 *
 * @return true if found
 */
bool string_array_contains(const string_array_t *arr, const char *str);

/**
 * Sort the strings lexicographically in place (strcmp order).
 */
void string_array_sort(string_array_t *arr);

/**
 * Join the strings with a delimiter, into `arena` (base/string.h str_join)
 *
 * @param arena     Arena the joined string lives in (must not be NULL)
 * @param arr       Array (NULL or empty joins to "")
 * @param delimiter Separator between two strings (NULL is none)
 * @return The joined string; never NULL
 */
char *string_array_join(arena_t *arena, const string_array_t *arr, const char *delimiter);

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

/**
 * Linear search for p, by identity: the pointer itself, NULL a value like any
 * other (ptr_array_push).
 *
 * @return true if found; false on NULL
 */
bool ptr_array_contains(const ptr_array_t *arr, const void *p);

#endif /* DOTTA_ARRAY_H */
