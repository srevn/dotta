/**
 * path.c - The grammar of a path's spelling
 */

#include "base/path.h"

#include <string.h>

#include "base/arena.h"
#include "base/error.h"

const char *path_beneath(const char *path, const char *dir, size_t dir_len) {
    if (strncmp(path, dir, dir_len) != 0) return NULL;

    /* The separator the tail starts past: the root directory's own, which is
     * all its spelling holds — so something must follow it, "/" lying beneath
     * nothing — else the byte past any other directory */
    if (dir_len == 1 && dir[0] == '/') return path[1] ? path + 1 : NULL;

    return path[dir_len] == '/' ? path + dir_len + 1 : NULL;
}

const char *path_under(const char *path, const char *dir, size_t dir_len) {
    /* The directory itself, nothing past it; else what lies beneath it */
    return strncmp(path, dir, dir_len) == 0 && path[dir_len] == '\0'
        ? path + dir_len
        : path_beneath(path, dir, dir_len);
}

int path_beneath_order(const char *path, const char *dir, size_t dir_len) {
    /* Where the path parts from the directory's spelling, it sorts that way from
     * every path beneath, each carrying the spelling whole */
    const int order = strncmp(path, dir, dir_len);
    if (order != 0) return order;

    /* The root directory's separator is all its spelling holds: every path past
     * it lies beneath, and "/" itself, the one it is all of, before them */
    if (dir_len == 1 && dir[0] == '/') return path[1] ? 0 : -1;

    /* Any other directory's separator is the byte past its spelling, read unsigned
     * as strcmp reads it: a lesser byte sorts before the block, the directory's
     * own terminator among them, and a greater one past */
    return (unsigned char) path[dir_len] - '/';
}

size_t path_parent_len(const char *path) {
    return path_parent_len_n(path, strlen(path));
}

size_t path_parent_len_n(const char *path, size_t len) {
    /* Back to the last separator among the first len bytes: len then ends just
     * past it, and the parent before it — but the root's own, the first byte,
     * which the parent keeps */
    while (len > 0 && path[len - 1] != '/') len--;

    return len > 1 ? len - 1 : len;
}

char *path_join(arena_t *arena, const char *dir, const char *name) {
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

char *path_fold(
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

bool path_folded(const char *path) {
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
