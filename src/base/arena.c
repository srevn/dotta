/**
 * arena.c - Chained-block bump allocator
 *
 * Singly-linked list of contiguous blocks. The first block is sized by
 * the caller; subsequent blocks double the previous capacity (or match
 * the request, whichever is larger).  Typical workloads fit in one block.
 */

#include "base/arena.h"

#include <stdlib.h>
#include <string.h>

#define ARENA_DEFAULT_CAPACITY 4096
#define ARENA_ALIGNMENT        8

/* --- Internal types ------------------------------------------------ */

typedef struct arena_block {
    struct arena_block *next;       /* previous block in chain */
    size_t capacity;                /* usable bytes in data[] */
    size_t used;                    /* bytes consumed so far  */
    char data[];                    /* flexible array member   */
} arena_block_t;

struct arena {
    arena_block_t *current;         /* active block (head of chain) */
};

/* --- Helpers ------------------------------------------------------- */

static inline size_t align_up(size_t n) {
    return (n + ARENA_ALIGNMENT - 1) & ~((size_t) ARENA_ALIGNMENT - 1);
}

/**
 * Allocate a new block with at least min_cap usable bytes.
 * Doubles prev_cap for amortised growth; falls back to min_cap on overflow.
 */
static arena_block_t *block_new(size_t prev_cap, size_t min_cap) {
    size_t cap = prev_cap * 2;
    if (cap < prev_cap) cap = min_cap;      /* multiplication overflow */
    if (cap < min_cap)  cap = min_cap;

    if (cap > SIZE_MAX - sizeof(arena_block_t))
        return NULL;

    arena_block_t *b = malloc(sizeof(arena_block_t) + cap);
    if (!b) return NULL;

    b->next = NULL;
    b->capacity = cap;
    b->used = 0;
    return b;
}

/* --- Public API ---------------------------------------------------- */

arena_t *arena_create(size_t initial_capacity) {
    if (initial_capacity == 0)
        initial_capacity = ARENA_DEFAULT_CAPACITY;

    arena_t *arena = malloc(sizeof(*arena));
    if (!arena) return NULL;

    arena_block_t *block = block_new(0, initial_capacity);
    if (!block) {
        free(arena);
        return NULL;
    }

    arena->current = block;
    return arena;
}

void *arena_alloc(arena_t *arena, size_t size) {
    if (!arena || size == 0)
        return NULL;

    size_t aligned = align_up(size);
    if (aligned < size) return NULL;        /* alignment overflow */

    arena_block_t *block = arena->current;

    if (aligned > block->capacity - block->used) {
        arena_block_t *nb = block_new(block->capacity, aligned);
        if (!nb) return NULL;

        nb->next = block;
        arena->current = nb;
        block = nb;
    }

    void *ptr = block->data + block->used;
    block->used += aligned;
    return ptr;
}

void *arena_calloc(arena_t *arena, size_t count, size_t size) {
    if (count && size > SIZE_MAX / count)
        return NULL;

    size_t total = count * size;
    void *ptr = arena_alloc(arena, total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

char *arena_strdup(arena_t *arena, const char *str) {
    if (!str) return NULL;

    size_t len = strlen(str) + 1;
    char *dst = arena_alloc(arena, len);
    if (dst) memcpy(dst, str, len);
    return dst;
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

void arena_destroy(arena_t *arena) {
    if (!arena) return;

    arena_block_t *b = arena->current;
    while (b) {
        arena_block_t *next = b->next;
        free(b);
        b = next;
    }
    free(arena);
}
