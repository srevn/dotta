/**
 * string.c - String utility functions implementation
 */

#include "string.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"

bool str_starts_with(const char *str, const char *prefix) {
    if (!str || !prefix) {
        return false;
    }

    size_t str_len = strlen(str);
    size_t prefix_len = strlen(prefix);

    if (prefix_len > str_len) {
        return false;
    }

    return strncmp(str, prefix, prefix_len) == 0;
}

bool str_ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) {
        return false;
    }

    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    if (suffix_len > str_len) {
        return false;
    }

    return strcmp(str + (str_len - suffix_len), suffix) == 0;
}

char *str_trim(char *str) {
    if (!str) {
        return NULL;
    }

    /* Trim leading whitespace */
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    /* All whitespace */
    if (*start == '\0') {
        *str = '\0';
        return str;
    }

    /* Trim trailing whitespace */
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';

    /* Move trimmed string to beginning if necessary */
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }

    return str;
}

char *str_join(const char **strings, size_t count, const char *delimiter) {
    if (!strings || count == 0) {
        return strdup("");
    }

    if (!delimiter) {
        delimiter = "";
    }

    /* Calculate total length */
    size_t total_len = 0;
    size_t delim_len = strlen(delimiter);

    for (size_t i = 0; i < count; i++) {
        if (strings[i]) {
            total_len += strlen(strings[i]);
        }
        if (i < count - 1) {
            total_len += delim_len;
        }
    }

    /* Allocate result */
    char *result = malloc(total_len + 1);
    if (!result) {
        return NULL;
    }

    /* Build result */
    char *ptr = result;
    for (size_t i = 0; i < count; i++) {
        if (strings[i]) {
            size_t len = strlen(strings[i]);
            memcpy(ptr, strings[i], len);
            ptr += len;
        }

        if (i < count - 1 && delim_len > 0) {
            memcpy(ptr, delimiter, delim_len);
            ptr += delim_len;
        }
    }

    *ptr = '\0';
    return result;
}

char *str_format(const char *fmt, ...) {
    if (!fmt) {
        return NULL;
    }

    va_list args;
    va_start(args, fmt);

    /* Calculate required size */
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);

    if (len < 0) {
        va_end(args);
        return NULL;
    }

    /* Allocate and format */
    char *result = malloc(len + 1);
    if (!result) {
        va_end(args);
        return NULL;
    }

    vsnprintf(result, len + 1, fmt, args);
    va_end(args);

    return result;
}

error_t *str_dup(const char *str, char **out) {
    CHECK_NULL(str);
    CHECK_NULL(out);

    *out = strdup(str);
    if (!*out) {
        return error_create(ERR_MEMORY, "Failed to duplicate string");
    }

    return NULL;
}

bool str_looks_like_commit(const char *str) {
    if (!str) {
        return false;
    }

    size_t len = strlen(str);

    /* Git commit SHAs: minimum 7 chars (short SHA), maximum 40 chars (full SHA) */
    if (len < 7 || len > 40) {
        return false;
    }

    /* All characters must be hexadecimal */
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)str[i])) {
            return false;
        }
    }

    return true;
}
