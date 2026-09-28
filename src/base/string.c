/**
 * string.c - String utility functions implementation
 */

#include "base/string.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/heap.h"

bool str_equal(const char *a, const char *b) {
    return a == b || (a && b && strcmp(a, b) == 0);
}

bool str_starts_with(const char *str, const char *prefix) {
    if (!str || !prefix) return false;

    /* No need to check str length */
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

bool str_ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) return false;

    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    if (suffix_len > str_len) return false;

    return strcmp(str + (str_len - suffix_len), suffix) == 0;
}

bool str_path_beneath(const char *path, const char *dir, size_t dir_len) {
    return strncmp(path, dir, dir_len) == 0 && path[dir_len] == '/';
}

size_t str_path_parent_len(const char *path) {
    const char *slash = strrchr(path, '/');

    if (!slash) return 0;

    return (slash == path) ? 1 : (size_t) (slash - path);
}

char *str_trim(char *str) {
    if (!str) return NULL;

    /* Trim leading whitespace */
    char *start = str;
    while (*start && isspace((unsigned char) *start)) {
        start++;
    }

    /* All whitespace */
    if (*start == '\0') {
        *str = '\0';
        return str;
    }

    /* Trim trailing whitespace */
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char) *end)) {
        end--;
    }
    *(end + 1) = '\0';

    /* Move trimmed string to beginning if necessary */
    if (start != str) {
        size_t trimmed_len = (size_t) (end - start) + 1;
        memmove(str, start, trimmed_len + 1);  /* +1 for null terminator */
    }

    return str;
}

char *str_join(
    arena_t *arena, char *const *strings, size_t count, const char *delimiter
) {
    CHECK_NULL(arena);
    if (!delimiter) delimiter = "";

    size_t delim_len = strlen(delimiter);

    /* One pass sizes: the strings, the delimiters between them and the terminator
     * are one byte count, and one no memory could hold is exhaustion. A string
     * and a delimiter are each an object's length, so their sum cannot wrap. */
    size_t total = 1;
    for (size_t i = 0; i < count; i++) {
        size_t len = (strings[i] ? strlen(strings[i]) : 0) + (i > 0 ? delim_len : 0);
        if (len > SIZE_MAX - total) heap_die(SIZE_MAX);
        total += len;
    }

    /* One pass fills */
    char *joined = arena_alloc(arena, total);
    char *at = joined;
    for (size_t i = 0; i < count; i++) {
        if (i > 0) {
            memcpy(at, delimiter, delim_len);
            at += delim_len;
        }
        if (strings[i]) {
            size_t len = strlen(strings[i]);
            memcpy(at, strings[i], len);
            at += len;
        }
    }
    *at = '\0';

    return joined;
}
