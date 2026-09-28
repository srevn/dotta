/**
 * arena.h - Bump allocator with O(1) bulk deallocation
 *
 * Chained-block arena: an allocation bumps a pointer within the current block;
 * one that does not fit chains a new block. Everything the arena holds is freed
 * in a single arena_free() call, and everything after a mark by arena_reset().
 *
 * An allocation cannot fail: it succeeds, or the run dies of exhaustion
 * (base/heap.h heap_die), so no answer here is NULL but the copy of a NULL string.
 * All allocations are 8-byte aligned.
 *
 * Under AddressSanitizer an arena is as visible as the heap: an allocation's
 * own bytes alone are addressable, a redzone follows each, and what a growth
 * leaves behind or a reset drops is poisoned again — a write past an allocation,
 * or through a pointer kept past its growth or its reset, traps as it would on
 * the heap.
 *
 * Typical usage:
 *   arena_t *a = arena_create(64 * 1024);
 *   char *s = arena_strdup(a, "hello");
 *   void *p = arena_alloc(a, 128);
 *   arena_free(a);   // frees everything in one shot
 */

#ifndef DOTTA_ARENA_H
#define DOTTA_ARENA_H

#include <stdarg.h>
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
 * Mirrors base/heap.h heap_str_format, but allocates the result from the arena
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
 * arena_str_format over a va_list, for a formatter of its own
 *
 * The format is dotta's own, so one that cannot be formatted is its writer's
 * bug. Readers: base/array.c string_array_pushf.
 *
 * @param fmt  Format string (must not be NULL)
 * @param args The arguments, as a variadic caller received them
 * @return Arena-allocated formatted string; never NULL.
 */
char *arena_str_vformat(arena_t *arena, const char *fmt, va_list args)
__attribute__((format(printf, 2, 0)));

/**
 * Room for `want` entries in an array the arena holds
 *
 * A no-op while want <= *capacity. Otherwise a new array of twice the capacity
 * — eight at least, and `want` where that is more — is allocated from the arena,
 * and the old one's *capacity entries are copied into it: at a push the old array
 * is full, so that is every entry it holds. An arena has no realloc, so the old
 * array is abandoned to it (arena_abandon): a pointer still aimed at it traps
 * under AddressSanitizer. The one growth an array in an arena has: a push asks
 * for count + 1, a reserve for the capacity it names. A byte count no memory
 * could hold is exhaustion.
 *
 * @param arena    Arena the array lives in (must not be NULL)
 * @param entries  The array: one this arena allocated, *capacity entries long, or
 *                 NULL when *capacity is 0
 * @param capacity The array's capacity in entries, updated (must not be NULL)
 * @param want     The entries the array must hold
 * @param size     One entry's size in bytes
 * @return The array: `entries` itself where nothing grew; never NULL
 */
void *arena_grow(
    arena_t *arena, void *entries, size_t *capacity, size_t want, size_t size
);

/**
 * Give up a region of the arena: its bytes stay the arena's until the arena is
 * freed, and nothing reads or writes them again
 *
 * Under AddressSanitizer the region is poisoned, so a pointer still aimed at it
 * traps as one into a freed heap block would. The way a container that outgrows
 * a region it cannot extend in place says so: arena_grow's old array, a hash
 * map's old slots (base/hashmap.c). A region this arena does not hold is a caller's
 * bug.
 *
 * @param arena  Arena the region was allocated from (must not be NULL)
 * @param region The region: an allocation of this arena, or part of one (must
 *               not be NULL)
 * @param size   The region's bytes
 */
void arena_abandon(arena_t *arena, void *region, size_t size);

/**
 * A position in an arena, for arena_reset to return to
 *
 * A value arena_mark takes: nothing holds it, and nothing frees it.
 */
typedef struct {
    const arena_t *arena;   /* the arena it was taken in */
    size_t position;        /* the arena's bytes then, every older block's whole */
} arena_mark_t;

/**
 * The arena's position, for arena_reset to return to
 *
 * Everything allocated after the mark goes at the reset — so an array made before
 * the mark is never grown after it: its larger array would be allocated above
 * the mark, and dropped with it. A walk takes a mark per frame, once its listing
 * is made, and returns to it per entry.
 *
 * @param arena Arena (must not be NULL)
 * @return The mark
 */
arena_mark_t arena_mark(const arena_t *arena);

/**
 * Return the arena to a mark: everything allocated after it is dropped
 *
 * The blocks chained after the mark are freed and the mark's own block rewound:
 * what was allocated before the mark stands, and a pointer into what came after
 * is no longer valid. "Empty" is the mark taken as the arena was created. A mark
 * taken in another arena, or one past the arena's position — a mark an earlier
 * reset to one below it dropped — is a caller's bug.
 *
 * @param arena Arena (must not be NULL)
 * @param mark  A mark arena_mark took of this arena
 */
void arena_reset(arena_t *arena, arena_mark_t mark);

/**
 * Free all blocks and the arena struct itself.
 *
 * @param arena Arena to free (NULL is a no-op).
 */
void arena_free(arena_t *arena);

#endif /* DOTTA_ARENA_H */
