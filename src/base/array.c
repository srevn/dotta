/**
 * array.c - Dynamic arrays
 *
 * A string array's spine and every copied string are the heap's, which dies rather
 * than answer NULL (base/heap.h); a pointer array's spine is in the arena it
 * remembers, grown by the one growth an arena has (base/arena.h arena_grow).
 * Either way a count whose bytes no memory could hold is exhaustion, said before
 * any memory is asked.
 */

#include "base/array.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/heap.h"

#define DEFAULT_CAP 8

/* === string_array_t — owned-string dynamic array === */

/* --- Lifecycle (stack / embedded) --- */

void string_array_init(string_array_t *arr) {
    *arr = (string_array_t){ 0 };
}

void string_array_init_cap(string_array_t *arr, size_t cap) {
    CHECK_NULL(arr);

    *arr = (string_array_t){ 0 };

    if (cap == 0) return;

    arr->items = heap_calloc(cap, sizeof(char *));
    arr->capacity = cap;
}

void string_array_deinit(string_array_t *arr) {
    if (!arr) return;

    for (size_t i = 0; i < arr->count; i++) {
        free(arr->items[i]);
    }
    free(arr->items);

    *arr = (string_array_t){ 0 };
}

/* --- Lifecycle (heap) --- */

string_array_t *string_array_new(size_t cap) {
    string_array_t *arr = heap_calloc(1, sizeof(*arr));
    string_array_init_cap(arr, cap);

    return arr;
}

void string_array_free(string_array_t *arr) {
    if (!arr) return;
    string_array_deinit(arr);
    free(arr);
}

void string_array_free_cb(void *ptr) {
    string_array_free(ptr);
}

/* --- Internal --- */

static void string_array_ensure_capacity(string_array_t *arr) {
    if (arr->count < arr->capacity) return;

    /* The capacity's bytes stand in memory, so its double cannot wrap; the double's
     * bytes can, and that is exhaustion. */
    size_t new_cap = arr->capacity ? arr->capacity * 2 : DEFAULT_CAP;
    if (new_cap > SIZE_MAX / sizeof(char *)) {
        heap_die(SIZE_MAX);
    }

    arr->items = heap_realloc(arr->items, new_cap * sizeof(char *));
    arr->capacity = new_cap;
}

/* --- Mutation --- */

void string_array_push(string_array_t *arr, const char *str) {
    CHECK_NULL(arr);
    CHECK_NULL(str);

    string_array_push_owned(arr, heap_strdup(str));
}

void string_array_push_owned(string_array_t *arr, char *str) {
    CHECK_NULL(arr);
    CHECK_NULL(str);

    string_array_ensure_capacity(arr);
    arr->items[arr->count++] = str;
}

void string_array_reserve(string_array_t *arr, size_t cap) {
    CHECK_NULL(arr);

    if (cap <= arr->capacity) return;

    if (cap > SIZE_MAX / sizeof(char *)) {
        heap_die(SIZE_MAX);
    }

    arr->items = heap_realloc(arr->items, cap * sizeof(char *));
    arr->capacity = cap;
}

void string_array_remove(string_array_t *arr, size_t index) {
    if (!arr || index >= arr->count) return;

    free(arr->items[index]);
    arr->count--;

    if (index < arr->count) {
        memmove(
            &arr->items[index], &arr->items[index + 1],
            (arr->count - index) * sizeof(char *)
        );
    }
}

void string_array_swap_remove(string_array_t *arr, size_t index) {
    if (!arr || index >= arr->count) return;

    free(arr->items[index]);
    arr->count--;

    if (index < arr->count) {
        arr->items[index] = arr->items[arr->count];
    }
}

bool string_array_remove_value(string_array_t *arr, const char *str) {
    if (!arr || !str) return false;

    for (size_t i = 0; i < arr->count; i++) {
        if (strcmp(arr->items[i], str) == 0) {
            string_array_remove(arr, i);
            return true;
        }
    }

    return false;
}

void string_array_clear(string_array_t *arr) {
    if (!arr) return;

    for (size_t i = 0; i < arr->count; i++) {
        free(arr->items[i]);
    }
    arr->count = 0;
}

/* --- Query --- */

bool string_array_contains(const string_array_t *arr, const char *str) {
    if (!arr || !str) return false;

    for (size_t i = 0; i < arr->count; i++) {
        if (strcmp(arr->items[i], str) == 0) return true;
    }

    return false;
}

/* --- Ordering --- */

static int cmp_strings(const void *a, const void *b) {
    return strcmp(*(const char *const *) a, *(const char *const *) b);
}

void string_array_sort(string_array_t *arr) {
    if (!arr || arr->count < 2) return;
    qsort(arr->items, arr->count, sizeof(char *), cmp_strings);
}

/* --- Copy --- */

void string_array_clone(const string_array_t *src, string_array_t *dst) {
    CHECK_NULL(src);
    CHECK_NULL(dst);

    *dst = (string_array_t){ 0 };

    if (src->count == 0) return;

    dst->items = heap_calloc(src->count, sizeof(char *));
    dst->capacity = src->count;

    for (size_t i = 0; i < src->count; i++) {
        dst->items[i] = heap_strdup(src->items[i]);
    }
    dst->count = src->count;
}

char *string_array_join(const string_array_t *arr, const char *delimiter) {
    if (!arr || arr->count == 0) return heap_strdup("");

    size_t delim_len = delimiter ? strlen(delimiter) : 0;

    /* Measure total length, caching individual lengths to avoid double strlen.
     * Small arrays use stack; larger arrays fall back to heap. */
    size_t stack_lengths[64];
    size_t *heap_lengths = NULL;
    size_t *lengths;
    if (arr->count <= 64) {
        lengths = stack_lengths;
    } else {
        heap_lengths = heap_calloc(arr->count, sizeof(size_t));
        lengths = heap_lengths;
    }

    /* The strings, the delimiters between them and the terminator are one byte
     * count, and one no memory could hold is exhaustion. */
    size_t total = 0;
    for (size_t i = 0; i < arr->count; i++) {
        lengths[i] = strlen(arr->items[i]);
        if (lengths[i] >= SIZE_MAX - total) {
            heap_die(SIZE_MAX);
        }
        total += lengths[i];
    }
    if (delim_len > 0 && arr->count > 1) {
        if (delim_len >= (SIZE_MAX - total) / (arr->count - 1)) {
            heap_die(SIZE_MAX);
        }
        total += delim_len * (arr->count - 1);
    }

    /* Allocate result */
    char *result = heap_alloc(total + 1);

    /* Build result */
    char *p = result;
    for (size_t i = 0; i < arr->count; i++) {
        if (i > 0 && delim_len > 0) {
            memcpy(p, delimiter, delim_len);
            p += delim_len;
        }
        memcpy(p, arr->items[i], lengths[i]);
        p += lengths[i];
    }
    *p = '\0';

    free(heap_lengths);
    return result;
}

/* === ptr_array_t — borrowed pointers, in the arena it was made in === */

void ptr_array_init(ptr_array_t *arr, arena_t *arena) {
    CHECK_NULL(arr);
    CHECK_NULL(arena);

    *arr = (ptr_array_t){ .arena = arena };
}

void ptr_array_init_cap(ptr_array_t *arr, arena_t *arena, size_t cap) {
    ptr_array_init(arr, arena);
    ptr_array_reserve(arr, cap);
}

void ptr_array_push(ptr_array_t *arr, const void *p) {
    CHECK_NULL(arr);
    CHECK_ARG(arr->arena != NULL, "a pointer array was pushed before it was given an arena");

    /* Room for one more, in the arena the array remembers */
    arr->entries = arena_grow(
        arr->arena, arr->entries, &arr->capacity, arr->count + 1, sizeof(*arr->entries)
    );

    /* Storage is type-erased void *; the caller's const intent (if any) is
     * re-applied at retrieval through their cast back to T ** / const T **. */
    arr->entries[arr->count++] = (void *) p;
}

void ptr_array_reserve(ptr_array_t *arr, size_t cap) {
    CHECK_NULL(arr);
    CHECK_ARG(arr->arena != NULL, "a pointer array was reserved before it was given an arena");

    arr->entries = arena_grow(
        arr->arena, arr->entries, &arr->capacity, cap, sizeof(*arr->entries)
    );
}

void ptr_array_clear(ptr_array_t *arr) {
    if (!arr) return;
    arr->count = 0;
}
