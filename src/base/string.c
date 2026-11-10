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
            for (size_t k = 0; k < take; k++) {
                unit_len += str_escape(unit + unit_len, s[i + k]);
            }
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
