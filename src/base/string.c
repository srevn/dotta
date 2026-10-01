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

/* The length of the well-formed UTF-8 sequence that starts at `s`, or 0 where
 * none does: Unicode's Table 3-7, so no overlong form, no surrogate and nothing
 * past U+10FFFF is one */
static size_t str_utf8_sequence(const unsigned char *s, size_t n) {
    const unsigned char b = s[0];
    if (b < 0x80) return 1;

    /* The sequence's length by its lead, and the range its second byte keeps */
    size_t need;
    unsigned char lo = 0x80, hi = 0xBF;
    if (b >= 0xC2 && b <= 0xDF) {
        need = 2;
    } else if (b == 0xE0) {
        need = 3;
        lo = 0xA0;
    } else if (b == 0xED) {
        need = 3;
        hi = 0x9F;
    } else if (b >= 0xE1 && b <= 0xEF) {
        need = 3;
    } else if (b == 0xF0) {
        need = 4;
        lo = 0x90;
    } else if (b == 0xF4) {
        need = 4;
        hi = 0x8F;
    } else if (b >= 0xF1 && b <= 0xF3) {
        need = 4;
    } else {
        return 0;
    }

    /* Then every byte the lead promised, each a continuation */
    if (n < need || s[1] < lo || s[1] > hi) return 0;
    for (size_t i = 2; i < need; i++) {
        if (s[i] < 0x80 || s[i] > 0xBF) return 0;
    }

    return need;
}

/* One byte as Git spells a byte it quotes, into `out`: a letter for the controls
 * that have one, three octal digits for every other. Answers how many bytes it
 * wrote — 2 or 4. */
static size_t str_escape(char *out, unsigned char b) {
    static const char letters[] = "abtnvfr";   /* 0x07 through 0x0d */

    out[0] = '\\';
    if (b >= 0x07 && b <= 0x0d) {
        out[1] = letters[b - 0x07];
        return 2;
    }

    out[1] = (char) ('0' + (b >> 6));
    out[2] = (char) ('0' + ((b >> 3) & 7));
    out[3] = (char) ('0' + (b & 7));
    return 4;
}

size_t str_display(char *dst, size_t size, const char *src, size_t len) {
    const unsigned char *s = (const unsigned char *) src;
    const size_t room = size > 0 ? size - 1 : 0;
    size_t need = 0;      /* the whole spelling's length */
    size_t written = 0;   /* what dst holds: whole units, never part of one */

    for (size_t i = 0; i < len;) {
        /* A run of bytes shown as they are — printable ASCII and TAB, nearly
         * all of any datum — is taken whole: each of its bytes a unit, so a cut
         * may end inside it */
        size_t run = 0;
        while (i + run < len && (s[i + run] == '\t' || (s[i + run] >= 0x20 && s[i + run] < 0x7F))) {
            run++;
        }
        if (run > 0) {
            size_t fit = written == need ? room - written : 0;
            if (fit > run) fit = run;
            if (fit > 0) {
                memcpy(dst + written, s + i, fit);
                written += fit;
            }
            need += run;
            i += run;
            continue;
        }

        /* A unit: one character shown as it is, or each byte it spans spelled —
         * a C1's two, a control's one, a byte no well-formed sequence holds */
        const size_t sequence = str_utf8_sequence(s + i, len - i);
        const bool c1 = sequence == 2 && s[i] == 0xC2 && s[i + 1] <= 0x9F;
        const bool shown = sequence > 1
            ? !c1 : sequence == 1 && (s[i] == '\t' || (s[i] >= 0x20 && s[i] < 0x7F));
        const size_t take = sequence > 0 ? sequence : 1;

        char unit[8];     /* four bytes shown, or two spelled */
        size_t unit_len = 0;
        if (shown) {
            memcpy(unit, s + i, take);
            unit_len = take;
        } else {
            for (size_t k = 0; k < take; k++) unit_len += str_escape(unit + unit_len, s[i + k]);
        }

        /* Written only while every unit before it was, so a cut answer ends on
         * a whole one, never after a gap a larger one left */
        if (written == need && need + unit_len <= room) {
            memcpy(dst + written, unit, unit_len);
            written += unit_len;
        }
        need += unit_len;
        i += take;
    }

    if (size > 0) dst[written] = '\0';
    return need;
}

/* The bytes every shell reads as themselves, wherever they stand in a word */
#define SHELL_PLAIN \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./,:@+-"

const char *str_shell_quote(arena_t *arena, const char *word) {
    CHECK_NULL(arena);
    CHECK_NULL(word);

    /* The shell's own expansion first: a `~` standing as the first component is
     * HOME's, and stays outside the quotes with the `/` behind it. */
    size_t home = 0;
    if (word[0] == '~' && (word[1] == '\0' || word[1] == '/')) home = word[1] ? 2 : 1;
    const char *rest = word + home;

    /* A word the shell reads as itself stands as it is, the tilde form's bare
     * `~` and `~/` among them; only the empty word needs quotes to be one. */
    if (rest[strspn(rest, SHELL_PLAIN)] == '\0') {
        return *word ? word : "''";
    }

    /* Sized for the worst: a byte costs at most three — the quotes of a run of
     * one around it — and a quote or a backslash two. A count no memory could
     * hold is exhaustion. */
    size_t len = strlen(rest);
    if (len > (SIZE_MAX - home - 1) / 3) heap_die(SIZE_MAX);

    char *quoted = arena_alloc(arena, home + 3 * len + 1);
    char *at = quoted;
    memcpy(at, word, home);
    at += home;

    /* A run of ordinary bytes stands inside one pair of quotes, and a quote or
     * a backslash stands outside every pair, escaped, where each shell reads
     * `\'` and `\\` alike: a quote is written wherever an ordinary byte opens a
     * run or an escaped one closes it. */
    bool quoting = false;
    for (const char *p = rest; *p; p++) {
        bool escaped = *p == '\'' || *p == '\\';
        if (escaped == quoting) {
            *at++ = '\'';
            quoting = !quoting;
        }
        if (escaped) *at++ = '\\';
        *at++ = *p;
    }
    if (quoting) *at++ = '\'';
    *at = '\0';

    return quoted;
}
