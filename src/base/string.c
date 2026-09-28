/**
 * string.c - String utility functions implementation
 */

#include "base/string.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

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

char *str_join(const char *const *strings, size_t count, const char *delimiter) {
    if (!strings || count == 0) {
        return heap_strdup("");
    }

    if (!delimiter) {
        delimiter = "";
    }

    size_t delim_len = strlen(delimiter);
    bool has_delimiter = (delim_len > 0);

    /* Calculate total length. The strings, the delimiters between them and the
     * terminator are one count, and one no memory could hold is exhaustion. */
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++) {
        if (strings[i]) {
            size_t slen = strlen(strings[i]);
            if (slen >= SIZE_MAX - total_len) {
                heap_die(SIZE_MAX);
            }
            total_len += slen;
        }
        if (i < count - 1 && has_delimiter) {
            if (delim_len >= SIZE_MAX - total_len) {
                heap_die(SIZE_MAX);
            }
            total_len += delim_len;
        }
    }

    /* Allocate result */
    char *result = heap_alloc(total_len + 1);

    /* Build result */
    char *ptr = result;
    for (size_t i = 0; i < count; i++) {
        if (strings[i]) {
            size_t len = strlen(strings[i]);
            memcpy(ptr, strings[i], len);
            ptr += len;
        }

        if (i < count - 1 && has_delimiter) {
            memcpy(ptr, delimiter, delim_len);
            ptr += delim_len;
        }
    }

    *ptr = '\0';
    return result;
}
