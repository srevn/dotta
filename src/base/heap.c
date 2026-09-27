/**
 * heap.c - The heap's allocators, which cannot fail
 */

#include "base/heap.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"

_Noreturn void heap_die(size_t size) {
    error_die("fatal: out of memory, malloc failed (tried to allocate %zu bytes)", size);
}

void *heap_alloc(size_t size) {
    /* malloc(0) may answer NULL, which is no exhaustion: one byte, then */
    void *ptr = malloc(size ? size : 1);
    if (!ptr) heap_die(size);

    return ptr;
}

void *heap_calloc(size_t count, size_t size) {
    /* A product no memory could hold is a request no allocation meets, refused
     * before calloc(3) sees it */
    if (count != 0 && size > SIZE_MAX / count) heap_die(SIZE_MAX);

    size_t bytes = count * size;
    void *ptr = calloc(1, bytes ? bytes : 1);
    if (!ptr) heap_die(bytes);

    return ptr;
}

void *heap_realloc(void *ptr, size_t size) {
    void *resized = realloc(ptr, size ? size : 1);
    if (!resized) heap_die(size);

    return resized;
}

char *heap_strdup(const char *str) {
    if (!str) return NULL;

    size_t size = strlen(str) + 1;
    char *copy = heap_alloc(size);
    memcpy(copy, str, size);

    return copy;
}

char *heap_strndup(const char *str, size_t n) {
    if (!str) return NULL;

    /* Up to n bytes and never past a NUL, as arena_strndup reads them */
    size_t len = strnlen(str, n);
    char *copy = heap_alloc(len + 1);
    memcpy(copy, str, len);
    copy[len] = '\0';

    return copy;
}
