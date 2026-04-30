/**
 * arena.h - Bump allocator with O(1) bulk deallocation
 *
 * Chained-block arena: allocations bump a pointer within the current
 * block; when exhausted, a new block is chained.  All memory is freed
 * in a single arena_destroy() call.
 *
 * All allocations are 8-byte aligned.  Returns NULL only on OOM.
 *
 * Typical usage:
 *   arena_t *a = arena_create(64 * 1024);
 *   char *s = arena_strdup(a, "hello");
 *   void *p = arena_alloc(a, 128);
 *   arena_destroy(a);   // frees everything in one shot
 */

#ifndef DOTTA_ARENA_H
#define DOTTA_ARENA_H

#include <types.h>

/**
 * Create arena with initial block capacity.
 *
 * @param initial_capacity  Size hint in bytes (0 = default 4096).
 * @return Arena, or NULL on OOM.
 */
arena_t *arena_create(size_t initial_capacity);

/**
 * Bump-allocate aligned memory. NOT zeroed.
 *
 * Chains a new block if the current one is exhausted.
 *
 * @return 8-byte aligned pointer, or NULL on OOM.
 */
void *arena_alloc(arena_t *arena, size_t size);

/**
 * Bump-allocate zeroed memory (calloc semantics).
 *
 * @return Zeroed, 8-byte aligned pointer, or NULL on OOM.
 */
void *arena_calloc(arena_t *arena, size_t count, size_t size);

/**
 * Arena-backed strdup. Returns NULL if str is NULL.
 *
 * @return Arena-allocated copy, or NULL if str is NULL or OOM.
 */
char *arena_strdup(arena_t *arena, const char *str);

/**
 * Arena-backed strndup: copies up to `n` bytes from `str` and null-terminates.
 *
 * Never reads past `str + n`, even if no null byte is present in that range.
 * Returns NULL if `str` is NULL; a zero-length (but null-terminated) buffer
 * when `n == 0`.
 *
 * @return Arena-allocated copy, or NULL if str is NULL or OOM.
 */
char *arena_strndup(arena_t *arena, const char *str, size_t n);

/**
 * Arena-backed printf-style string formatter.
 *
 * Mirrors `str_format` from base/string but allocates the result from the
 * arena instead of the heap. Two-pass implementation: vsnprintf once to
 * size the buffer, allocate, vsnprintf again to fill. Never returns a
 * partial string.
 *
 * @return Arena-allocated formatted string, or NULL if `fmt` is NULL,
 *         on encoding error, or on OOM.
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
 * @param arena Arena to destroy (NULL is a no-op).
 */
void arena_destroy(arena_t *arena);

#endif /* DOTTA_ARENA_H */
