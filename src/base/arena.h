/**
 * arena.h - Bump allocator with O(1) bulk deallocation
 *
 * Chained-block arena: an allocation bumps a pointer within the current block;
 * one that does not fit chains a new block. Everything the arena holds is freed
 * in a single arena_free() call.
 *
 * An allocation cannot fail: it succeeds, or the run dies of exhaustion
 * (base/heap.h heap_die), so no answer here is NULL but the copy of a NULL string.
 * All allocations are 8-byte aligned.
 *
 * Typical usage:
 *   arena_t *a = arena_create(64 * 1024);
 *   char *s = arena_strdup(a, "hello");
 *   void *p = arena_alloc(a, 128);
 *   arena_free(a);   // frees everything in one shot
 */

#ifndef DOTTA_ARENA_H
#define DOTTA_ARENA_H

#include <types.h>

/**
 * Create arena with initial block capacity.
 *
 * @param initial_capacity  Size hint in bytes (0 = default 4096).
 * @return Arena; never NULL.
 */
arena_t *arena_create(size_t initial_capacity);

/**
 * Bump-allocate aligned memory. NOT zeroed.
 *
 * Chains a new block if the current one is exhausted. A zero size is a place of
 * its own, like any other: never another allocation's, and never dereferenced.
 *
 * @param arena Arena (must not be NULL)
 * @return 8-byte aligned pointer; never NULL.
 */
void *arena_alloc(arena_t *arena, size_t size);

/**
 * Bump-allocate zeroed memory (calloc semantics).
 *
 * A count × size that wraps is a request no allocation meets: exhaustion.
 *
 * @return Zeroed, 8-byte aligned pointer; never NULL.
 */
void *arena_calloc(arena_t *arena, size_t count, size_t size);

/**
 * Arena-backed strdup. Returns NULL if str is NULL.
 *
 * @return Arena-allocated copy, or NULL if str is NULL.
 */
char *arena_strdup(arena_t *arena, const char *str);

/**
 * Arena-backed strndup: copies up to `n` bytes from `str`, stopping at a NUL,
 * and null-terminates — strndup(3)'s sense, so the copy's strlen is its length.
 *
 * Never reads past `str + n`, even if no null byte is present in that range,
 * and never past the NUL of a string shorter than `n`. Returns NULL if `str` is
 * NULL; "" when `n == 0`.
 *
 * @return Arena-allocated copy, or NULL if str is NULL.
 */
char *arena_strndup(arena_t *arena, const char *str, size_t n);

/**
 * Arena-backed printf-style string formatter.
 *
 * Mirrors `str_format` from base/string but allocates the result from the arena
 * instead of the heap. Two-pass implementation: vsnprintf once to size the buffer,
 * allocate, vsnprintf again to fill. Never returns a partial string. The format
 * is dotta's own, so one that cannot be formatted is its writer's bug.
 *
 * @param fmt Format string (must not be NULL)
 * @return Arena-allocated formatted string; never NULL.
 */
char *arena_str_format(arena_t *arena, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

/**
 * Reset arena to empty, retaining only the initial block.
 *
 * Frees all expansion blocks and resets the initial block's bump
 * pointer.  Pointers obtained before the reset become invalid.
 *
 * @param arena Arena (NULL is a no-op).
 */
void arena_reset(arena_t *arena);

/**
 * Free all blocks and the arena struct itself.
 *
 * @param arena Arena to free (NULL is a no-op).
 */
void arena_free(arena_t *arena);

#endif /* DOTTA_ARENA_H */
