/**
 * array.c - Dynamic arrays
 *
 * Every spine is in the arena its array remembers, grown by the one growth an
 * arena has (base/arena.h arena_grow), and so is every string a string array
 * copies. A count whose bytes no memory could hold is exhaustion, said before
 * any memory is asked.
 */

#include "base/array.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/string.h"

/* === string_array_t — names, each a copy in the arena it was made in === */

void string_array_init(string_array_t *arr, arena_t *arena) {
    CHECK_NULL(arr);
    CHECK_NULL(arena);

    *arr = (string_array_t){ .arena = arena };
}

void string_array_init_cap(string_array_t *arr, arena_t *arena, size_t cap) {
    string_array_init(arr, arena);
    string_array_reserve(arr, cap);
}

/* The one way a string enters the array: a string its arena already holds, at
 * the end, and the terminator after it. The arena was asked for by the function
 * that made the string, before it made the string there. */
static void string_array_append(string_array_t *arr, char *str) {
    arr->entries = arena_grow(
        arr->arena,
        arr->entries,
        &arr->capacity,
        arr->count + 2,
        sizeof(*arr->entries)
    );
    arr->entries[arr->count++] = str;
    arr->entries[arr->count] = NULL;
}

void string_array_push(string_array_t *arr, const char *str) {
    CHECK_NULL(arr);
    CHECK_NULL(str);
    CHECK_ARG(
        arr->arena != NULL,
        "a string array was pushed before it was given an arena"
    );

    string_array_append(arr, arena_strdup(arr->arena, str));
}

void string_array_pushf(string_array_t *arr, const char *fmt, ...) {
    CHECK_NULL(arr);
    CHECK_ARG(
        arr->arena != NULL,
        "a string array was pushed before it was given an arena"
    );

    va_list args;
    va_start(args, fmt);
    char *str = arena_str_vformat(arr->arena, fmt, args);
    va_end(args);

    string_array_append(arr, str);
}

void string_array_reserve(string_array_t *arr, size_t cap) {
    CHECK_NULL(arr);
    CHECK_ARG(
        arr->arena != NULL,
        "a string array was reserved before it was given an arena"
    );

    /* Nothing to hold makes no spine; a count whose terminator's slot wraps is
     * one no memory could hold */
    if (cap == 0) return;
    if (cap == SIZE_MAX) heap_die(SIZE_MAX);

    arr->entries = arena_grow(
        arr->arena,
        arr->entries,
        &arr->capacity,
        cap + 1,
        sizeof(*arr->entries)
    );
    arr->entries[arr->count] = NULL;   /* a spine a reserve made is an argv too */
}

void string_array_clone(
    const string_array_t *src, arena_t *arena, string_array_t *dst
) {
    CHECK_NULL(src);
    CHECK_NULL(dst);

    string_array_init_cap(dst, arena, src->count);
    for (size_t i = 0; i < src->count; i++) {
        string_array_push(dst, src->entries[i]);
    }
}

void string_array_remove(string_array_t *arr, size_t index) {
    if (!arr || index >= arr->count) return;

    /* The strings after it, and the terminator after them, one place left */
    memmove(
        &arr->entries[index], &arr->entries[index + 1],
        (arr->count - index) * sizeof(*arr->entries)
    );
    arr->count--;
}

void string_array_swap_remove(string_array_t *arr, size_t index) {
    if (!arr || index >= arr->count) return;

    arr->entries[index] = arr->entries[arr->count - 1];
    arr->entries[--arr->count] = NULL;
}

bool string_array_remove_value(string_array_t *arr, const char *str) {
    if (!arr || !str) return false;

    for (size_t i = 0; i < arr->count; i++) {
        if (strcmp(arr->entries[i], str) == 0) {
            string_array_remove(arr, i);
            return true;
        }
    }

    return false;
}

void string_array_clear(string_array_t *arr) {
    if (!arr) return;

    arr->count = 0;
    if (arr->entries) arr->entries[0] = NULL;
}

bool string_array_contains(const string_array_t *arr, const char *str) {
    if (!arr || !str) return false;

    for (size_t i = 0; i < arr->count; i++) {
        if (strcmp(arr->entries[i], str) == 0) return true;
    }

    return false;
}

static int string_array_order(const void *a, const void *b) {
    return strcmp(*(const char *const *) a, *(const char *const *) b);
}

void string_array_sort(string_array_t *arr) {
    if (!arr || arr->count < 2) return;

    qsort(
        arr->entries,
        arr->count,
        sizeof(*arr->entries),
        string_array_order
    );
}

char *string_array_join(
    arena_t *arena, const string_array_t *arr, const char *delimiter
) {
    if (!arr) return str_join(arena, NULL, 0, delimiter);

    return str_join(arena, arr->entries, arr->count, delimiter);
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
    CHECK_ARG(
        arr->arena != NULL,
        "a pointer array was pushed before it was given an arena"
    );

    /* Room for one more, in the arena the array remembers */
    arr->entries = arena_grow(
        arr->arena,
        arr->entries,
        &arr->capacity,
        arr->count + 1,
        sizeof(*arr->entries)
    );

    /* The slot is a void *, so a const the pointer carried is dropped here, and
     * the reader's own type restores it as each slot is read (include/types.h
     * ptr_array_t) */
    arr->entries[arr->count++] = (void *) p;
}

void ptr_array_reserve(ptr_array_t *arr, size_t cap) {
    CHECK_NULL(arr);
    CHECK_ARG(
        arr->arena != NULL,
        "a pointer array was reserved before it was given an arena"
    );

    arr->entries = arena_grow(
        arr->arena,
        arr->entries,
        &arr->capacity,
        cap,
        sizeof(*arr->entries)
    );
}

void ptr_array_clear(ptr_array_t *arr) {
    if (!arr) return;
    arr->count = 0;
}

bool ptr_array_contains(const ptr_array_t *arr, const void *p) {
    if (!arr) return false;

    for (size_t i = 0; i < arr->count; i++) {
        if (arr->entries[i] == p) return true;
    }

    return false;
}
