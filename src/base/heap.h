/**
 * heap.h - The heap's allocators, which cannot fail
 *
 * malloc(3) and its family, answered with their value or not at all: every
 * allocation here succeeds, or the run dies of exhaustion (heap_die), so dotta's
 * own exhaustion is never an answer a caller could take for a fact about its
 * data. A request whose byte count cannot be represented — a count times a size
 * that wraps — is one no allocation meets, and dies the same way before malloc
 * sees it. A zero size is one byte, so an answer is never NULL and never another
 * allocation's.
 *
 * Beside base/arena.h, whose bytes go only with their arena: these are released
 * one by one, with free(3), by whoever holds them.
 */

#ifndef DOTTA_HEAP_H
#define DOTTA_HEAP_H

#include <types.h>

/**
 * The run dies of exhaustion
 *
 * "fatal: out of memory, malloc failed (tried to allocate <size> bytes)", through
 * base/error.h error_die. The one reporter of dotta's exhaustion: every allocator
 * here, and base/arena's blocks and its byte counts that cannot be represented.
 *
 * @param size The bytes that could not be allocated; SIZE_MAX for a count no
 *             size can hold
 */
_Noreturn void heap_die(size_t size);

/**
 * Allocate `size` bytes, uninitialized
 *
 * @return Never NULL; a zero size is one byte
 */
void *heap_alloc(size_t size);

/**
 * Allocate `count` entries of `size` bytes, zeroed
 *
 * @return Never NULL; a zero product is one byte
 */
void *heap_calloc(size_t count, size_t size);

/**
 * Resize an allocation to `size` bytes, its prefix kept
 *
 * realloc(p, 0) is the implementation's to answer, and one answer frees; a zero
 * size is one byte here, so this never frees what the caller still holds.
 *
 * @param ptr An allocation of the heap's, or NULL for a new one
 * @return Never NULL
 */
void *heap_realloc(void *ptr, size_t size);

/**
 * A copy of `str`
 *
 * @return The copy; NULL for a NULL `str`, which is a value, not a failure
 */
char *heap_strdup(const char *str);

/**
 * A copy of up to `n` bytes of `str`, stopping at a NUL, and terminated —
 * strndup(3)'s sense, as base/arena.h arena_strndup
 *
 * @return The copy; NULL for a NULL `str`
 */
char *heap_strndup(const char *str, size_t n);

#endif /* DOTTA_HEAP_H */
