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

char *str_path_join(arena_t *arena, const char *dir, const char *name) {
    CHECK_NULL(arena);
    CHECK_NULL(dir);
    CHECK_NULL(name);
    CHECK_ARG(dir[0] != '\0' && name[0] != '\0', "a join with an empty side");

    /* The seam's separators, both sides' — the root's one included — are the
     * one written between them. Two objects' lengths and two bytes cannot wrap. */
    size_t dir_len = strlen(dir);
    while (dir_len > 0 && dir[dir_len - 1] == '/') dir_len--;
    while (*name == '/') name++;
    size_t name_len = strlen(name);

    char *joined = arena_alloc(arena, dir_len + 1 + name_len + 1);
    memcpy(joined, dir, dir_len);
    joined[dir_len] = '/';
    memcpy(joined + dir_len + 1, name, name_len + 1);

    return joined;
}

char *str_path_fold(
    arena_t *arena, const char *path, bool (*folds)(const char *through)
) {
    CHECK_NULL(arena);
    CHECK_NULL(path);
    CHECK_ARG(path[0] != '\0', "the fold of an empty path");

    /* Written in place, never longer than the path: a component is kept as it
     * is met, and a `..` takes back the last one kept. The floor is what no `..`
     * reaches below — an absolute path's root, and every `..` kept, which raises
     * it: a relative path's leading ones, and one `folds` would not let take
     * the component before it. */
    bool absolute = path[0] == '/';
    char *folded = arena_alloc(arena, strlen(path) + 1);
    char *w = folded;
    if (absolute) *w++ = '/';
    char *floor = w;

    for (const char *r = path; *r;) {
        while (*r == '/') r++;
        if (!*r) break;

        const char *seg = r;
        while (*r && *r != '/') r++;
        size_t n = (size_t) (r - seg);

        if (n == 1 && seg[0] == '.') continue;
        if (n == 2 && seg[0] == '.' && seg[1] == '.') {
            /* The last component kept goes, and the separator before it — asked
             * of `folds` first, over the fold so far through that component,
             * which the terminator makes a path of its own until the next byte
             * is written over it. */
            if (w > floor) {
                *w = '\0';
                if (!folds || folds(folded)) {
                    while (w > floor && w[-1] != '/') w--;
                    if (w > floor) w--;
                    continue;
                }
            } else if (absolute && w == folded + 1) {
                continue;   /* the root's `..` is the root */
            }

            /* Kept, and the floor rises past it */
            if (w > folded && w[-1] != '/') *w++ = '/';
            *w++ = '.';
            *w++ = '.';
            floor = w;
            continue;
        }

        if (w > folded && w[-1] != '/') *w++ = '/';
        memcpy(w, seg, n);
        w += n;
    }

    if (w == folded) *w++ = '.';
    *w = '\0';

    return folded;
}

bool str_path_folded(const char *path) {
    if (!path || path[0] != '/') return false;

    /* Every separator decides the component that follows it: an empty one (a
     * doubled slash, or a trailing one past the root), a `.` or a `..`. A component
     * is one of those by its first bytes and whatever ends it, so the walk reads
     * neither a length nor a token. */
    for (const char *p = path; *p; p++) {
        if (*p != '/') continue;
        if (p[1] == '/' || (p[1] == '\0' && p != path)) return false;
        if (p[1] != '.') continue;
        if (p[2] == '\0' || p[2] == '/') return false;
        if (p[2] == '.' && (p[3] == '\0' || p[3] == '/')) return false;
    }

    return true;
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
