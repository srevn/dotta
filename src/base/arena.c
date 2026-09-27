/**
 * arena.c - Chained-block bump allocator
 *
 * Singly-linked list of contiguous blocks. The first block is sized by the caller;
 * subsequent blocks double the previous capacity (or match
 * the request, whichever is larger).  Typical workloads fit in one block. Every
 * block is the heap's, which dies rather than answer NULL (base/heap.h), and so
 * does a request whose size no block could hold.
 */

#include "base/arena.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/heap.h"

#define ARENA_DEFAULT_CAPACITY 4096
#define ARENA_ALIGNMENT        8

/* --- Internal types ------------------------------------------------ */

typedef struct arena_block {
    struct arena_block *next;       /* Older block (chain prepends; head=current) */
    size_t capacity;                /* usable bytes in data[] */
    size_t used;                    /* bytes consumed so far  */
    char data[];                    /* flexible array member   */
} arena_block_t;

struct arena {
    arena_block_t *current;         /* active block (head of chain) */
};

/* --- Helpers ------------------------------------------------------- */

/* A size rounded up to the alignment; one no rounding can represent is
 * exhaustion. */
static size_t arena_align(size_t size) {
    if (size > SIZE_MAX - (ARENA_ALIGNMENT - 1)) heap_die(size);

    return (size + ARENA_ALIGNMENT - 1) & ~((size_t) ARENA_ALIGNMENT - 1);
}

/**
 * Chain a new block of at least min_capacity usable bytes onto the arena, the
 * current one. Doubles the current block's capacity for amortised growth; falls
 * back to min_capacity on overflow.
 */
static void arena_chain(arena_t *arena, size_t min_capacity) {
    arena_block_t *current = arena->current;

    size_t capacity = current ? current->capacity * 2 : 0;
    if (current && capacity < current->capacity) capacity = min_capacity;   /* multiplication overflow */
    if (capacity < min_capacity) capacity = min_capacity;

    /* The header and its bytes are one request, and one no size can hold is
     * exhaustion. */
    if (capacity > SIZE_MAX - sizeof(arena_block_t)) heap_die(SIZE_MAX);

    arena_block_t *block = heap_alloc(sizeof(arena_block_t) + capacity);
    block->next = current;
    block->capacity = capacity;
    block->used = 0;
    arena->current = block;
}

/* --- Public API ---------------------------------------------------- */

arena_t *arena_create(size_t initial_capacity) {
    if (initial_capacity == 0)
        initial_capacity = ARENA_DEFAULT_CAPACITY;

    arena_t *arena = heap_alloc(sizeof(*arena));
    arena->current = NULL;
    arena_chain(arena, initial_capacity);

    return arena;
}

void *arena_alloc(arena_t *arena, size_t size) {
    CHECK_NULL(arena);

    /* A zero size takes one unit of the alignment, so its answer is a place of
     * its own: never another allocation's, and never dereferenced. */
    size_t aligned = arena_align(size ? size : 1);
    arena_block_t *block = arena->current;

    if (aligned > block->capacity - block->used) {
        arena_chain(arena, aligned);
        block = arena->current;
    }

    void *ptr = block->data + block->used;
    block->used += aligned;
    return ptr;
}

void *arena_calloc(arena_t *arena, size_t count, size_t size) {
    /* A product no memory could hold is a request no allocation meets. */
    if (count != 0 && size > SIZE_MAX / count) heap_die(SIZE_MAX);

    size_t total = count * size;
    void *ptr = arena_alloc(arena, total);
    memset(ptr, 0, total);
    return ptr;
}

char *arena_strdup(arena_t *arena, const char *str) {
    if (!str) return NULL;

    size_t len = strlen(str) + 1;
    char *dst = arena_alloc(arena, len);
    memcpy(dst, str, len);
    return dst;
}

char *arena_strndup(arena_t *arena, const char *str, size_t n) {
    if (!str) return NULL;

    /* Up to n bytes and never past a NUL: a span holding one copies the string
     * it holds, and a string shorter than n is read no further than its end.
     * The length is an object's, so its terminator cannot overflow it. */
    size_t len = strnlen(str, n);

    char *dst = arena_alloc(arena, len + 1);
    memcpy(dst, str, len);
    dst[len] = '\0';
    return dst;
}

char *arena_str_format(arena_t *arena, const char *fmt, ...) {
    CHECK_NULL(fmt);

    va_list args;
    va_start(args, fmt);

    /* Pass 1: size the buffer. A format that cannot be formatted is its writer's
     * bug. */
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);
    CHECK_ARG(len >= 0, "fmt cannot be formatted");

    /* Pass 2: allocate and format. The +1 is the null terminator; vsnprintf's
     * `len` excludes it but its `size` argument includes it. */
    char *buf = arena_alloc(arena, (size_t) len + 1);
    vsnprintf(buf, (size_t) len + 1, fmt, args);
    va_end(args);

    return buf;
}

void arena_reset(arena_t *arena) {
    if (!arena) return;

    /* Free all blocks except the tail */
    arena_block_t *b = arena->current;
    while (b->next) {
        arena_block_t *next = b->next;
        free(b);
        b = next;
    }

    b->used = 0;
    arena->current = b;
}

void arena_free(arena_t *arena) {
    if (!arena) return;

    arena_block_t *b = arena->current;
    while (b) {
        arena_block_t *next = b->next;
        free(b);
        b = next;
    }
    free(arena);
}
