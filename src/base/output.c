/**
 * output.c - Output formatting and styling implementation
 *
 * Every line the layer writes is built whole and written once (the line): a format
 * is walked by the layer's own printf (output_walk), its literal runs copied
 * with their {tags} expanded and each conversion written as a datum or a number.
 * Tags are resolved via a sorted lookup table with binary search; compound tags
 * ({bold;red}) are supported.
 *
 * Tag syntax:
 *   {red}, {bold}, {dim}, ...  — apply style/color
 *   {bold;red}                 — compound (multiple styles)
 *   {reset}                    — explicit reset
 *
 * Tags expand to ANSI codes when colors are enabled, to nothing when not. A style
 * a line leaves open is closed where its text ends, before its own newlines
 * (output_put).
 */

#include "base/output.h"

#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/heap.h"

/* ═══════════════════════════════════════════════════════════════════
 * ANSI Escape Codes
 *
 * Defined as macros (not variables) to enable compile-time string concatenation:
 * ANSI_BOLD ANSI_RED "text" ANSI_RESET collapses to a single string literal in
 * the binary.
 * ═══════════════════════════════════════════════════════════════════ */

#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_DIM     "\033[2m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_WHITE   "\033[37m"

/* Indexed by output_color_t enum for O(1) runtime lookup */
static const char *ANSI_CODES[] = {
    [OUTPUT_COLOR_RESET] = ANSI_RESET,
    [OUTPUT_COLOR_BOLD] = ANSI_BOLD,
    [OUTPUT_COLOR_DIM] = ANSI_DIM,
    [OUTPUT_COLOR_RED] = ANSI_RED,
    [OUTPUT_COLOR_GREEN] = ANSI_GREEN,
    [OUTPUT_COLOR_YELLOW] = ANSI_YELLOW,
    [OUTPUT_COLOR_BLUE] = ANSI_BLUE,
    [OUTPUT_COLOR_MAGENTA] = ANSI_MAGENTA,
    [OUTPUT_COLOR_CYAN] = ANSI_CYAN,
    [OUTPUT_COLOR_WHITE] = ANSI_WHITE,
};

#define ANSI_CODE_COUNT (sizeof(ANSI_CODES) / sizeof(ANSI_CODES[0]))

/* ═══════════════════════════════════════════════════════════════════
 * The Line
 *
 * One emitter call's bytes, built whole and written once (output_start,
 * output_put). 512 bytes on the stack cover nearly every line; a longer one grows
 * on the heap, and exhaustion is the run's death (base/heap.h). Written with
 * one fwrite, a line on stderr — which stdio does not buffer — is one write(2):
 * nothing another process writes lands inside it.
 *
 * A style a tag or a colour opens is tracked, and closed where the line's text
 * ends, before its own trailing newlines, never after them: so no line hands
 * the next one a colour, none opens on a reset, and a style a reset already closed
 * is not closed again.
 * ═══════════════════════════════════════════════════════════════════ */

#define LINE_STACK_SIZE 512

typedef struct {
    FILE *stream;                 /* Where output_put writes it */
    char *data;                   /* stack[] or the heap */
    size_t len;                   /* The line's bytes so far */
    size_t cap;                   /* data's room, the terminator's byte among it */
    bool color;                   /* Styles are written; else every one is nothing */
    bool styled;                  /* A style is open that no reset has closed */
    char stack[LINE_STACK_SIZE];
} line_t;

/**
 * Room for `more` bytes, and for the terminator snprintf writes past them
 *
 * The stack's room first; past it the heap, doubled. A capacity whose doubling
 * wraps is one no memory could hold: exhaustion (base/heap.h).
 */
static void output_reserve(line_t *line, size_t more) {
    if (more < line->cap - line->len) return;
    if (more > SIZE_MAX - line->len - 1) heap_die(SIZE_MAX);

    size_t want = line->len + more + 1;
    size_t cap = line->cap;
    while (cap < want) {
        if (cap > SIZE_MAX / 2) heap_die(SIZE_MAX);
        cap *= 2;
    }

    if (line->data == line->stack) {
        line->data = heap_alloc(cap);
        memcpy(line->data, line->stack, line->len);
    } else {
        line->data = heap_realloc(line->data, cap);
    }
    line->cap = cap;
}

/**
 * Bytes onto the line, as they are
 */
static void output_bytes(line_t *line, const char *bytes, size_t len) {
    output_reserve(line, len);
    memcpy(line->data + line->len, bytes, len);
    line->len += len;
}

/**
 * Spaces onto the line: a datum's padding
 */
static void output_pad(line_t *line, size_t count) {
    output_reserve(line, count);
    memset(line->data + line->len, ' ', count);
    line->len += count;
}

/**
 * A colour's code onto the line, where the line writes styles
 *
 * Any colour but OUTPUT_COLOR_RESET opens a style; the reset closes one that is
 * open and writes nothing where none is. A colour no enumerator names, which
 * only a cast can make, writes nothing: the answer that changes no byte.
 */
static void output_style(line_t *line, output_color_t color) {
    if (!line->color || (unsigned) color >= ANSI_CODE_COUNT) return;
    if (color == OUTPUT_COLOR_RESET && !line->styled) return;

    line->styled = color != OUTPUT_COLOR_RESET;
    output_bytes(line, ANSI_CODES[color], strlen(ANSI_CODES[color]));
}

/**
 * One value onto the line, as printf writes it under `spec`
 *
 * Formatted into the room the line has; a number that needs more is formatted
 * again once the room is made.
 */
__attribute__((format(printf, 2, 3)))
static void output_snprintf(line_t *line, const char *spec, ...) {
    va_list args;
    va_start(args, spec);
    va_list again;
    va_copy(again, args);

    size_t room = line->cap - line->len;
    int len = vsnprintf(line->data + line->len, room, spec, args);
    CHECK_ARG(len >= 0, "a number that cannot be formatted");
    if ((size_t) len >= room) {
        output_reserve(line, (size_t) len);
        vsnprintf(line->data + line->len, (size_t) len + 1, spec, again);
    }

    va_end(again);
    va_end(args);
    line->len += (size_t) len;
}

/* ═══════════════════════════════════════════════════════════════════
 * Tag Table
 *
 * Sorted alphabetically for binary search; a tag names a colour, and its code
 * is ANSI_CODES'. The STYLE_TAG macro computes a name's length at compile time
 * — no runtime strlen.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *name;       /* Tag name (e.g., "red", "bold") */
    output_color_t color;   /* The colour it names */
    uint8_t name_len;       /* strlen(name), computed at compile time */
} tag_t;

#define STYLE_TAG(n, c) { n, c, sizeof(n) - 1 }

/* MUST remain sorted by name (ASCII order) for binary search */
static const tag_t TAG_TABLE[] = {
    STYLE_TAG("blue",    OUTPUT_COLOR_BLUE),
    STYLE_TAG("bold",    OUTPUT_COLOR_BOLD),
    STYLE_TAG("cyan",    OUTPUT_COLOR_CYAN),
    STYLE_TAG("dim",     OUTPUT_COLOR_DIM),
    STYLE_TAG("green",   OUTPUT_COLOR_GREEN),
    STYLE_TAG("magenta", OUTPUT_COLOR_MAGENTA),
    STYLE_TAG("red",     OUTPUT_COLOR_RED),
    STYLE_TAG("reset",   OUTPUT_COLOR_RESET),
    STYLE_TAG("white",   OUTPUT_COLOR_WHITE),
    STYLE_TAG("yellow",  OUTPUT_COLOR_YELLOW),
};

#define TAG_COUNT (sizeof(TAG_TABLE) / sizeof(TAG_TABLE[0]))

/**
 * Binary search for a tag by name
 *
 * Lexicographic comparison against the sorted TAG_TABLE. Returns pointer to
 * matching entry, or NULL for unknown tags.
 */
static const tag_t *output_find_tag(const char *name, size_t len) {
    int lo = 0;
    int hi = (int) TAG_COUNT - 1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        const tag_t *entry = &TAG_TABLE[mid];

        size_t cmp_len = len < entry->name_len ? len : entry->name_len;
        int cmp = memcmp(name, entry->name, cmp_len);

        if (cmp == 0) {
            /* Common prefix matches — shorter string sorts first */
            if (len < entry->name_len)
                cmp = -1;
            else if (len > entry->name_len)
                cmp = 1;
        }

        if (cmp < 0)
            hi = mid - 1;
        else if (cmp > 0)
            lo = mid + 1;
        else
            return entry;
    }

    return NULL;
}

/**
 * Expand a (possibly compound) tag onto the line
 *
 * Handles simple tags ({red}) and compound tags ({bold;red}). Splits on ';',
 * resolves each part independently. If ANY part is unknown, the entire tag is
 * rejected (caller passes it through literally). Empty parts from
 * leading/trailing/double semicolons are silently skipped. A recognised tag writes
 * each part's code by the line's rule (output_style).
 *
 * @param line Line to write the codes onto
 * @param tag Tag content (between '{' and '}')
 * @param tag_len Length of tag content
 * @return true if tag was recognized, false to pass through literally
 */
static bool output_expand_tag(line_t *line, const char *tag, size_t tag_len) {
    const tag_t *resolved[8];
    size_t count = 0;
    const char *p = tag;
    const char *end = tag + tag_len;

    /* First pass: resolve all parts (reject if any unknown) */
    while (p < end) {
        const char *semi = memchr(p, ';', (size_t) (end - p));
        size_t part_len = semi ? (size_t) (semi - p) : (size_t) (end - p);

        if (part_len > 0) {
            if (count >= sizeof(resolved) / sizeof(resolved[0]))
                return false;

            const tag_t *entry = output_find_tag(p, part_len);
            if (!entry) return false;

            resolved[count++] = entry;
        }

        p = semi ? semi + 1 : end;
    }

    if (count == 0) return false;

    /* Second pass: each part's code */
    for (size_t i = 0; i < count; i++)
        output_style(line, resolved[i]->color);

    return true;
}

/* Maximum characters scanned for a tag name (prevents runaway on '{') */
#define TAG_SCAN_LIMIT 16

/**
 * A literal run of a format onto the line, its {tags} expanded
 *
 * The run's bytes are its author's: copied as they are, but for a recognised
 * tag — a brace, a known name or parts of one, and its closing brace within the
 * scan's limit — which is expanded. An unknown or empty name and an unclosed
 * brace pass through literally.
 */
static void output_markup(line_t *line, const char *text, size_t len) {
    const char *end = text + len;

    for (const char *p = text; p < end;) {
        /* The bytes up to the next brace, as they are */
        const char *brace = memchr(p, '{', (size_t) (end - p));
        output_bytes(line, p, (size_t) ((brace ? brace : end) - p));
        if (!brace) return;

        /* The tag the brace opens, or the brace alone */
        const char *name = brace + 1;
        size_t scan = (size_t) (end - name) < TAG_SCAN_LIMIT
            ? (size_t) (end - name) : TAG_SCAN_LIMIT;
        const char *close = memchr(name, '}', scan);
        if (close && close > name && output_expand_tag(line, name, (size_t) (close - name))) {
            p = close + 1;
        } else {
            output_bytes(line, "{", 1);
            p = name;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * The Walker
 *
 * The layer's own printf: a format's literal runs are its author's layout, and
 * each conversion is a datum (%s, %c) or a number. The arguments are the emitter's
 * own list, handed down by pointer, so every va_arg below moves the one list —
 * a va_list handed by value to a function that reads from it leaves the caller's
 * indeterminate (C11 7.16p3), and on arm64 a copy re-reads. Its va_arg types
 * are the ones the emitter's format attribute checked at the call.
 * ═══════════════════════════════════════════════════════════════════ */

/* A length modifier: the type a conversion's argument was passed as */
typedef enum {
    LENGTH_NONE,         /* int, unsigned, double, a pointer */
    LENGTH_CHAR,         /* hh */
    LENGTH_SHORT,        /* h */
    LENGTH_LONG,         /* l */
    LENGTH_LONG_LONG,    /* ll */
    LENGTH_INTMAX,       /* j */
    LENGTH_SIZE,         /* z */
    LENGTH_PTRDIFF,      /* t */
    LENGTH_LONG_DOUBLE   /* L */
} length_t;

/* As a spec spells it, indexed by length_t */
static const char *const LENGTHS[] = { "", "hh", "h", "l", "ll", "j", "z", "t", "L" };

/* One conversion of a format, its stars read */
typedef struct {
    char flags[8];       /* As written, '-' added for a negative star width */
    int width;           /* -1: none */
    int precision;       /* -1: none, a negative star's among them */
    length_t length;
    char verb;
} conversion_t;

/**
 * The conversion a format spells past its '%'
 *
 * Its flags as written; its width and precision, a star's read from `args` in
 * the order the format spells them — a negative width left-justifying, a negative
 * precision none, a period with no digits zero; its length and its verb. A
 * positional argument (%1$s) is no conversion the layer writes.
 *
 * @return The format past the verb
 */
static const char *output_conversion(
    const char *spec, va_list *args, conversion_t *out
) {
    conversion_t c = { .width = -1, .precision = -1 };
    const char *p = spec;

    /* The flags: -Wformat refuses a repeated one, so five at most */
    size_t flags = 0;
    while (*p && strchr("-+ #0", *p)) {
        CHECK_ARG(flags < sizeof(c.flags) - 2, "a conversion with more flags than printf has");
        c.flags[flags++] = *p++;
    }

    /* The width: a star's value, or its digits */
    if (*p == '*') {
        int width = va_arg(*args, int);
        CHECK_ARG(width > INT_MIN, "a width no line can hold");
        if (width < 0) c.flags[flags++] = '-';
        c.width = width < 0 ? -width : width;
        p++;
    } else if (isdigit((unsigned char) *p)) {
        char *after;
        long width = strtol(p, &after, 10);
        CHECK_ARG(width <= INT_MAX, "a width no line can hold");
        c.width = (int) width;
        p = after;
    }
    CHECK_ARG(*p != '$', "a positional conversion the output layer does not write");

    /* The precision: a star's value, its digits, or a period alone */
    if (*p == '.') {
        p++;
        if (*p == '*') {
            int precision = va_arg(*args, int);
            c.precision = precision < 0 ? -1 : precision;
            p++;
        } else if (isdigit((unsigned char) *p)) {
            char *after;
            long precision = strtol(p, &after, 10);
            CHECK_ARG(precision <= INT_MAX, "a precision no line can hold");
            c.precision = (int) precision;
            p = after;
        } else {
            c.precision = 0;
        }
    }

    /* The length */
    switch (*p) {
        case 'h':
            c.length = p[1] == 'h' ? LENGTH_CHAR : LENGTH_SHORT;
            p += p[1] == 'h' ? 2 : 1;
            break;
        case 'l':
            c.length = p[1] == 'l' ? LENGTH_LONG_LONG : LENGTH_LONG;
            p += p[1] == 'l' ? 2 : 1;
            break;
        case 'j': c.length = LENGTH_INTMAX; p++; break;
        case 'z': c.length = LENGTH_SIZE; p++; break;
        case 't': c.length = LENGTH_PTRDIFF; p++; break;
        case 'L': c.length = LENGTH_LONG_DOUBLE; p++; break;
        default: break;
    }

    c.verb = *p;
    CHECK_ARG(c.verb != '\0', "a format that ends inside a conversion");

    *out = c;
    return p + 1;
}

/**
 * A string's or a character's bytes onto the line, padded to the width
 */
static void output_datum(
    line_t *line, const char *bytes, size_t len, const conversion_t *c
) {
    size_t pad = c->width > 0 && (size_t) c->width > len ? (size_t) c->width - len : 0;
    bool left = strchr(c->flags, '-') != NULL;

    if (!left) output_pad(line, pad);
    output_bytes(line, bytes, len);
    if (left) output_pad(line, pad);
}

/**
 * A number onto the line, as printf writes it
 *
 * The conversion is spelled again with its stars read — its flags, its width
 * and precision as digits, its length and its verb — and the one value is fetched
 * by the type its length names after the default promotions (C11 7.21.6.1p7),
 * so printf converts it as it would have.
 */
static void output_number(line_t *line, const conversion_t *c, va_list *args) {
    char spec[48];
    int at = snprintf(spec, sizeof(spec), "%%%s", c->flags);
    if (c->width >= 0) {
        at += snprintf(spec + at, sizeof(spec) - (size_t) at, "%d", c->width);
    }
    if (c->precision >= 0) {
        at += snprintf(spec + at, sizeof(spec) - (size_t) at, ".%d", c->precision);
    }
    snprintf(spec + at, sizeof(spec) - (size_t) at, "%s%c", LENGTHS[c->length], c->verb);

    switch (c->verb) {
        case 'd':
        case 'i':
            switch (c->length) {
                case LENGTH_NONE:
                case LENGTH_CHAR:
                case LENGTH_SHORT:
                    output_snprintf(line, spec, va_arg(*args, int));
                    return;
                case LENGTH_LONG:
                    output_snprintf(line, spec, va_arg(*args, long));
                    return;
                case LENGTH_LONG_LONG:
                    output_snprintf(line, spec, va_arg(*args, long long));
                    return;
                case LENGTH_INTMAX:
                    output_snprintf(line, spec, va_arg(*args, intmax_t));
                    return;
                case LENGTH_SIZE:
                    output_snprintf(line, spec, va_arg(*args, ssize_t));
                    return;
                case LENGTH_PTRDIFF:
                    output_snprintf(line, spec, va_arg(*args, ptrdiff_t));
                    return;
                case LENGTH_LONG_DOUBLE:
                    break;
            }
            break;

        case 'o':
        case 'u':
        case 'x':
        case 'X':
            switch (c->length) {
                case LENGTH_NONE:
                case LENGTH_CHAR:
                case LENGTH_SHORT:
                    output_snprintf(line, spec, va_arg(*args, unsigned int));
                    return;
                case LENGTH_LONG:
                    output_snprintf(line, spec, va_arg(*args, unsigned long));
                    return;
                case LENGTH_LONG_LONG:
                    output_snprintf(line, spec, va_arg(*args, unsigned long long));
                    return;
                case LENGTH_INTMAX:
                    output_snprintf(line, spec, va_arg(*args, uintmax_t));
                    return;
                case LENGTH_SIZE:
                    output_snprintf(line, spec, va_arg(*args, size_t));
                    return;
                case LENGTH_PTRDIFF:
                    /* t "applies to a ptrdiff_t or the corresponding unsigned
                     * integer type" (C11 7.21.6.1p7): the one type passed */
                    output_snprintf(line, spec, va_arg(*args, ptrdiff_t));
                    return;
                case LENGTH_LONG_DOUBLE:
                    break;
            }
            break;

        case 'a':
        case 'A':
        case 'e':
        case 'E':
        case 'f':
        case 'F':
        case 'g':
        case 'G':
            if (c->length == LENGTH_NONE || c->length == LENGTH_LONG) {
                output_snprintf(line, spec, va_arg(*args, double));
                return;
            }
            if (c->length == LENGTH_LONG_DOUBLE) {
                output_snprintf(line, spec, va_arg(*args, long double));
                return;
            }
            break;

        case 'p':
            if (c->length == LENGTH_NONE) {
                output_snprintf(line, spec, va_arg(*args, void *));
                return;
            }
            break;

        default:
            break;
    }

    /* %n, a length printf does not pair with the verb, or a verb printf does
     * not have: a conversion the compiler took and the layer does not write,
     * which dies at the first run that asks */
    CHECK_ARG(false, "a conversion the output layer does not write");
}

/**
 * A format walked onto the line: each literal run its author's, each conversion
 * a datum or a number
 *
 * A NULL %s writes "(null)", as libc does; a %% is the one byte, and anything
 * written on it is no conversion the layer writes.
 */
static void output_walk(line_t *line, const char *fmt, va_list *args) {
    for (const char *p = fmt; *p;) {
        /* The author's layout up to the next conversion */
        const char *percent = strchr(p, '%');
        output_markup(line, p, percent ? (size_t) (percent - p) : strlen(p));
        if (!percent) return;

        /* The conversion, its stars read in their order */
        conversion_t c;
        p = output_conversion(percent + 1, args, &c);

        switch (c.verb) {
            case '%':
                CHECK_ARG(
                    c.flags[0] == '\0' && c.width < 0 && c.precision < 0
                    && c.length == LENGTH_NONE,
                    "a % written with more than its two bytes"
                );
                output_bytes(line, "%", 1);
                break;

            case 's': {
                CHECK_ARG(c.length == LENGTH_NONE, "a wide string the output layer does not write");
                const char *s = va_arg(*args, const char *);
                if (!s) s = "(null)";
                size_t len = c.precision >= 0 ? strnlen(s, (size_t) c.precision) : strlen(s);
                output_datum(line, s, len, &c);
                break;
            }

            case 'c': {
                CHECK_ARG(
                    c.length == LENGTH_NONE,
                    "a wide character the output layer does not write"
                );
                const char ch = (char) va_arg(*args, int);
                output_datum(line, &ch, 1, &c);
                break;
            }

            default:
                output_number(line, &c, args);
                break;
        }
    }
}

/**
 * A format walked onto the line, from its arguments as they are passed
 */
__attribute__((format(printf, 2, 3)))
static void output_appendf(line_t *line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    output_walk(line, fmt, &args);
    va_end(args);
}

/* ═══════════════════════════════════════════════════════════════════
 * Terminal and Color Detection
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Are colours on for a stream, under a mode
 *
 * AUTO's is a terminal's yes: the stream a terminal, NO_COLOR unset or empty,
 * and TERM set to anything but "dumb".
 */
static bool output_colors_on(output_color_mode_t mode, FILE *stream) {
    switch (mode) {
        case OUTPUT_COLOR_ALWAYS:
            return true;
        case OUTPUT_COLOR_NEVER:
            return false;
        case OUTPUT_COLOR_AUTO: {
            if (!isatty(fileno(stream))) return false;

            const char *no_color = getenv("NO_COLOR");
            if (no_color && no_color[0] != '\0') return false;

            const char *term = getenv("TERM");
            return term && strcmp(term, "dumb") != 0;
        }
    }

    /* A mode no enumerator names, which only a cast can make: no colour, the
     * answer that writes nothing (base/error.h CHECK_ARG) */
    return false;
}

/* ═══════════════════════════════════════════════════════════════════
 * Context Management
 * ═══════════════════════════════════════════════════════════════════ */

output_t *output_create(
    FILE *stream, output_verbosity_t verbosity, output_color_mode_t color_mode
) {
    output_t *ctx = heap_calloc(1, sizeof(output_t));

    ctx->stream = stream ? stream : stdout;
    ctx->verbosity = verbosity;
    ctx->color_mode = color_mode;
    ctx->color_enabled = output_colors_on(color_mode, ctx->stream);
    ctx->stderr_color_enabled = output_colors_on(color_mode, stderr);

    return ctx;
}

void output_free(output_t *ctx) {
    if (ctx) {
        free(ctx);
    }
}

void output_set_verbosity(output_t *ctx, output_verbosity_t verbosity) {
    if (ctx) {
        ctx->verbosity = verbosity;
    }
}

void output_set_stream(output_t *ctx, FILE *stream) {
    if (!ctx || !stream) return;

    ctx->stream = stream;
    ctx->color_enabled = output_colors_on(ctx->color_mode, stream);

    /* The new stream holds none of the report, so a boundary owed on the old
     * one is dropped rather than paid where it does not belong. */
    ctx->report = OUTPUT_REPORT_START;
}

error_t output_parse_verbosity(const char *word, output_verbosity_t *out) {
    CHECK_NULL(word);
    CHECK_NULL(out);

    if (strcmp(word, "quiet") == 0) {
        *out = OUTPUT_QUIET;
    } else if (strcmp(word, "normal") == 0) {
        *out = OUTPUT_NORMAL;
    } else if (strcmp(word, "verbose") == 0) {
        *out = OUTPUT_VERBOSE;
    } else {
        return ERROR(
            ERR_INVALID_ARG,
            "Unknown verbosity '%s' (valid: quiet, normal, verbose)", word
        );
    }
    return NULL;
}

error_t output_parse_color_mode(const char *word, output_color_mode_t *out) {
    CHECK_NULL(word);
    CHECK_NULL(out);

    if (strcmp(word, "auto") == 0) {
        *out = OUTPUT_COLOR_AUTO;
    } else if (strcmp(word, "always") == 0) {
        *out = OUTPUT_COLOR_ALWAYS;
    } else if (strcmp(word, "never") == 0) {
        *out = OUTPUT_COLOR_NEVER;
    } else {
        return ERROR(
            ERR_INVALID_ARG,
            "Unknown color mode '%s' (valid: auto, always, never)", word
        );
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * Color Support
 * ═══════════════════════════════════════════════════════════════════ */

bool output_colors_enabled(const output_t *ctx) {
    return ctx ? ctx->color_enabled : false;
}

bool output_is_tty(const output_t *ctx) {
    if (!ctx || !ctx->stream)
        return false;

    return isatty(fileno(ctx->stream));
}

/* ═══════════════════════════════════════════════════════════════════
 * Formatted Output
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * A line of the report is about to land on `stream`
 *
 * Every line's first act (output_start). Three things happen here and nowhere
 * else: the report is flushed when this line crosses to another stream, so a
 * question or a failure arrives under the run it is about rather than inside
 * it; a boundary the report owes is paid, on the stream this line lands on; and
 * the report is recorded as standing, which is what lets the next block ask for
 * a boundary at all.
 *
 * A line on stderr settles the debt but does not make the report stand — a run
 * whose first line is a failure opens no report to separate from. output_endline
 * comes nowhere near here: it ends a line that already stands, so there is nothing
 * to record, and a boundary asked mid-line is better left standing than spent
 * closing a line (output.h).
 */
static void output_land(output_t *ctx, FILE *stream) {
    if (stream != ctx->stream) {
        fflush(ctx->stream);
    }

    if (ctx->report == OUTPUT_REPORT_GAP) {
        fputc('\n', stream);
        ctx->report = OUTPUT_REPORT_LINE;
    }

    if (stream == ctx->stream) {
        ctx->report = OUTPUT_REPORT_LINE;
    }
}

/**
 * Start a line on `stream` — the report's own, or stderr
 *
 * The line lands first (output_land), so a boundary the report owes is paid above
 * it; its colour is its stream's: the report's decision, or stderr's.
 */
static void output_start(line_t *line, output_t *ctx, FILE *stream) {
    output_land(ctx, stream);

    line->stream = stream;
    line->data = line->stack;
    line->len = 0;
    line->cap = sizeof(line->stack);
    line->color = stream == ctx->stream ? ctx->color_enabled : ctx->stderr_color_enabled;
    line->styled = false;
}

/**
 * Write the line, once, and give back what it grew
 *
 * A style left open is closed where the text ends: before the line's own trailing
 * newlines, so the next line opens on nothing.
 */
static void output_put(line_t *line) {
    if (line->styled) {
        size_t end = line->len;
        while (end > 0 && line->data[end - 1] == '\n') end--;

        const size_t reset = sizeof(ANSI_RESET) - 1;
        output_reserve(line, reset);
        memmove(line->data + end + reset, line->data + end, line->len - end);
        memcpy(line->data + end, ANSI_RESET, reset);
        line->len += reset;
    }

    (void) fwrite(line->data, 1, line->len, line->stream);
    if (line->data != line->stack) free(line->data);
}

void output_print(
    output_t *ctx, output_verbosity_t min_level, const char *fmt, ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    line_t line;
    output_start(&line, ctx, ctx->stream);

    va_list args;
    va_start(args, fmt);
    output_walk(&line, fmt, &args);
    va_end(args);

    output_put(&line);
}

void output_colored(
    output_t *ctx, output_verbosity_t min_level, output_color_t color,
    const char *fmt, ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    line_t line;
    output_start(&line, ctx, ctx->stream);

    /* The colour opens the line, and output_put closes it: RESET, the sentinel
     * for none, writes nothing on a line that has nothing open */
    output_style(&line, color);

    va_list args;
    va_start(args, fmt);
    output_walk(&line, fmt, &args);
    va_end(args);

    output_put(&line);
}

void output_error(output_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) return;

    line_t line;
    output_start(&line, ctx, stderr);
    output_appendf(&line, "{bold;red}Error:{reset} ");

    va_list args;
    va_start(args, fmt);
    output_walk(&line, fmt, &args);
    va_end(args);

    output_bytes(&line, "\n", 1);
    output_put(&line);
}

void output_warning(
    output_t *ctx, output_verbosity_t min_level, const char *fmt, ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    line_t line;
    output_start(&line, ctx, ctx->stream);
    output_appendf(&line, "{bold;yellow}Warning:{reset} ");

    va_list args;
    va_start(args, fmt);
    output_walk(&line, fmt, &args);
    va_end(args);

    output_bytes(&line, "\n", 1);
    output_put(&line);
}

void output_success(
    output_t *ctx, output_verbosity_t min_level, const char *fmt, ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    line_t line;
    output_start(&line, ctx, ctx->stream);
    output_appendf(&line, "{green}\xe2\x9c\x93{reset} ");

    va_list args;
    va_start(args, fmt);
    output_walk(&line, fmt, &args);
    va_end(args);

    output_bytes(&line, "\n", 1);
    output_put(&line);
}

void output_info(
    output_t *ctx, output_verbosity_t min_level, const char *fmt, ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    line_t line;
    output_start(&line, ctx, ctx->stream);

    va_list args;
    va_start(args, fmt);
    output_walk(&line, fmt, &args);
    va_end(args);

    output_bytes(&line, "\n", 1);
    output_put(&line);
}

void output_hint(
    output_t *ctx, output_verbosity_t min_level, const char *fmt, ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    line_t line;
    output_start(&line, ctx, ctx->stream);

    /* Preserve leading whitespace (printed uncolored for indentation) */
    const char *p = fmt;
    while (*p == ' ' || *p == '\t') p++;
    output_bytes(&line, fmt, (size_t) (p - fmt));

    /* Dim wraps the entire hint: prefix + body */
    output_style(&line, OUTPUT_COLOR_DIM);
    output_bytes(&line, "Hint: ", 6);

    va_list args;
    va_start(args, fmt);
    output_walk(&line, p, &args);
    va_end(args);

    output_bytes(&line, "\n", 1);
    output_put(&line);
}

void output_hintline(
    output_t *ctx, output_verbosity_t min_level, const char *fmt, ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    line_t line;
    output_start(&line, ctx, ctx->stream);
    output_style(&line, OUTPUT_COLOR_DIM);

    va_list args;
    va_start(args, fmt);
    output_walk(&line, fmt, &args);
    va_end(args);

    output_bytes(&line, "\n", 1);
    output_put(&line);
}

void output_endline(output_t *ctx, output_verbosity_t min_level) {
    if (!ctx || ctx->verbosity < min_level) return;
    fputc('\n', ctx->stream);
}

void output_gap(output_t *ctx, output_verbosity_t min_level) {
    if (!ctx || ctx->verbosity < min_level) return;
    if (ctx->report == OUTPUT_REPORT_LINE) ctx->report = OUTPUT_REPORT_GAP;
}

void output_section(
    output_t *ctx, output_verbosity_t min_level, const char *fmt, ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    /* A section is a block, and it owns the boundary above it */
    output_gap(ctx, min_level);

    line_t line;
    output_start(&line, ctx, ctx->stream);
    output_style(&line, OUTPUT_COLOR_BOLD);

    va_list args;
    va_start(args, fmt);
    output_walk(&line, fmt, &args);
    va_end(args);

    output_bytes(&line, "\n", 1);
    output_put(&line);
}

void output_clear_line(output_t *ctx) {
    if (!ctx) return;

    if (isatty(fileno(ctx->stream)))
        fputs("\r\033[2K", ctx->stream);
    else
        fputc('\n', ctx->stream);

    fflush(ctx->stream);
}

/* ═══════════════════════════════════════════════════════════════════
 * Diff Output
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * The colour a patch line carries, or NULL for one that carries none
 *
 * The origin character is the whole rule, and the second byte is what tells a
 * change from a file header: `+++` and `---` repeat their first byte where `+x`
 * and `-x` do not. Reading the second needs no length — the caller walks a
 * NUL-terminated text and enters only on a line that has a first byte, so the
 * second is at worst the terminator.
 */
static const char *output_diff_color(const char *line) {
    if (line[0] == '+' && line[1] != '+') return ANSI_GREEN;
    if (line[0] == '-' && line[1] != '-') return ANSI_RED;
    if (line[0] == '@' && line[1] == '@') return ANSI_CYAN;

    return NULL;
}

void output_print_diff(
    output_t *ctx, output_verbosity_t min_level, const char *diff_text
) {
    if (!ctx || !diff_text || !*diff_text) return;
    if (ctx->verbosity < min_level) return;

    output_land(ctx, ctx->stream);

    const char *line = diff_text;

    /* A line and its newline are one step; the last line needs no newline. */
    while (*line) {
        size_t len = strcspn(line, "\n");
        const char *color = ctx->color_enabled ? output_diff_color(line) : NULL;

        if (color)
            fprintf(
                ctx->stream, "%s%.*s" ANSI_RESET "\n",
                color, (int) len, line
            );
        else
            fprintf(ctx->stream, "%.*s\n", (int) len, line);

        line += len + (line[len] == '\n');
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Utilities
 * ═══════════════════════════════════════════════════════════════════ */

void output_format_size(size_t bytes, char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return;

    if (bytes < 1024)
        snprintf(
            buffer, buffer_size, "%zu B",
            bytes
        );
    else if (bytes < (size_t) 1024 * 1024)
        snprintf(
            buffer, buffer_size, "%.1f KiB",
            bytes / 1024.0
        );
    else if (bytes < (size_t) 1024 * 1024 * 1024)
        snprintf(
            buffer, buffer_size, "%.1f MiB",
            bytes / (1024.0 * 1024.0)
        );
    else
        snprintf(
            buffer, buffer_size, "%.1f GiB",
            bytes / (1024.0 * 1024.0 * 1024.0)
        );
}

void output_format_counts(
    size_t files, size_t directories, char *buffer, size_t buffer_size
) {
    if (!buffer || buffer_size == 0) return;

    if (files > 0 && directories > 0)
        snprintf(
            buffer, buffer_size, "%zu file%s, %zu director%s",
            files, files == 1 ? "" : "s",
            directories, directories == 1 ? "y" : "ies"
        );
    else if (files > 0)
        snprintf(
            buffer, buffer_size, "%zu file%s",
            files, files == 1 ? "" : "s"
        );
    else if (directories > 0)
        snprintf(
            buffer, buffer_size, "%zu director%s",
            directories, directories == 1 ? "y" : "ies"
        );
    else
        snprintf(buffer, buffer_size, "empty");
}

void output_format_path(
    const char *path, const char *home, char *buffer, size_t buffer_size
) {
    if (!buffer || buffer_size == 0) return;

    size_t home_len = strlen(home);
    if (strncmp(path, home, home_len) == 0 &&
        (path[home_len] == '\0' || path[home_len] == '/')) {
        snprintf(buffer, buffer_size, "~%s", path + home_len);
    } else {
        snprintf(buffer, buffer_size, "%s", path);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * User Confirmation Prompts
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * The answer typed: y or Y is yes, an empty line the default, anything else no
 */
static bool output_read_answer(bool default_value) {
    char response[16];

    if (fgets(response, sizeof(response), stdin) == NULL)
        return default_value;

    /* An answer longer than the buffer: the rest of its line is drained, so it
     * never reaches the next question */
    size_t len = strlen(response);
    if (len > 0 && response[len - 1] != '\n') {
        int c;
        while ((c = getchar()) != '\n' && c != EOF) { }
    }

    if (len == 0 || response[0] == '\n')
        return default_value;

    return (response[0] == 'y' || response[0] == 'Y');
}

/**
 * Put the question and read the answer
 *
 * The question alone, with no boundary of its own: the block it closes is the
 * caller's, and only the caller knows how much of it has already printed — a
 * destructive prompt's warning and its question are one block, and asking twice
 * inside it would put a blank between them.
 */
static bool output_ask(
    output_t *ctx, bool default_value, const char *fmt, va_list *args
) {
    /* The preview this asks about is the report above it, and the question must
     * not land inside the line it ends on: the line lands first (output_start) */
    line_t line;
    output_start(&line, ctx, stderr);
    output_style(&line, OUTPUT_COLOR_BOLD);
    output_walk(&line, fmt, args);
    output_style(&line, OUTPUT_COLOR_RESET);
    output_appendf(&line, default_value ? " [Y/n] " : " [y/N] ");
    output_put(&line);
    fflush(stderr);

    return output_read_answer(default_value);
}

bool output_confirm(
    output_t *ctx, bool default_value, const char *fmt, ...
) {
    if (!ctx || !fmt) return false;

    /* A question is a block. Asked at QUIET because a prompt is not gated. */
    output_gap(ctx, OUTPUT_QUIET);

    va_list args;
    va_start(args, fmt);
    const bool confirmed = output_ask(ctx, default_value, fmt, &args);
    va_end(args);

    return confirmed;
}

bool output_confirm_or_default(
    output_t *ctx, bool default_value, bool non_interactive_default,
    const char *fmt, ...
) {
    if (!ctx || !fmt) return false;

    /* Both arms are the same block, so the boundary is asked once above the
     * branch */
    output_gap(ctx, OUTPUT_QUIET);

    va_list args;
    va_start(args, fmt);
    bool confirmed = non_interactive_default;
    if (isatty(STDIN_FILENO)) {
        confirmed = output_ask(ctx, default_value, fmt, &args);
    } else {
        /* Off a terminal the question cannot be asked: the default is its answer,
         * and the line says which, the question its subject */
        line_t line;
        output_start(&line, ctx, stderr);
        output_appendf(
            &line, non_interactive_default
            ? "{bold;yellow}Warning:{reset} Running non-interactively, auto-confirming: "
            : "{bold;red}Error:{reset} Running non-interactively, refusing: "
        );
        output_walk(&line, fmt, &args);
        output_bytes(&line, "\n", 1);
        output_put(&line);
    }
    va_end(args);

    return confirmed;
}

bool output_confirm_destructive(
    output_t *ctx, bool confirm_destructive, bool force_flag, const char *fmt, ...
) {
    if (!ctx || !fmt) return false;
    if (force_flag) return true;
    if (!confirm_destructive) return true;

    /* The warning and the question are one block: one boundary, above both, paid
     * by whichever of them lands first. */
    output_gap(ctx, OUTPUT_QUIET);

    va_list args;
    va_start(args, fmt);
    bool confirmed = false;
    line_t line;
    output_start(&line, ctx, stderr);
    if (isatty(STDIN_FILENO)) {
        output_appendf(&line, "{bold;yellow}Warning:{reset} This is a destructive operation!\n");
        output_put(&line);
        confirmed = output_ask(ctx, false, fmt, &args);
    } else {
        output_appendf(
            &line, "{bold;red}Error:{reset} Running non-interactively, refusing "
            "destructive operation: "
        );
        output_walk(&line, fmt, &args);
        output_bytes(&line, "\n", 1);
        output_put(&line);
    }
    va_end(args);

    return confirmed;
}

/* ═══════════════════════════════════════════════════════════════════
 * List Builder
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *tags;      /* Bracketed and joined, "[a] [b]", the list's arena's */
    output_color_t color;  /* Color for tags */
    const char *content;   /* Content string, the list's arena's */
    const char *metadata;  /* Metadata string, the list's arena's (nullable) */
} item_t;

struct output_list {
    arena_t *arena;     /* The list's own: the struct, its strings and its items */
    output_t *ctx;      /* Borrowed reference (caller owns) */
    const char *title;  /* Section title */
    const char *hint;   /* Hint text (nullable) */
    item_t *items;      /* The items, grown in the arena */
    size_t count;       /* Current item count */
    size_t capacity;    /* Allocated capacity */
};

output_list_t *output_list_create(
    output_t *ctx, const char *title, const char *hint
) {
    CHECK_NULL(ctx);
    CHECK_NULL(title);

    arena_t *arena = arena_create(0);
    output_list_t *list = arena_calloc(arena, 1, sizeof(*list));

    list->arena = arena;
    list->ctx = ctx;
    list->title = arena_strdup(arena, title);
    list->hint = arena_strdup(arena, hint);

    return list;
}

void output_list_add(
    output_list_t *list, const char **tags, size_t tag_count,
    output_color_t color, const char *content,
    const char *metadata
) {
    CHECK_NULL(list);
    CHECK_ARG(tags != NULL || tag_count == 0, "tags cannot be NULL with a count");

    arena_t *arena = list->arena;
    list->items = arena_grow(
        arena, list->items, &list->capacity, list->count + 1, sizeof(*list->items)
    );

    /* The tags as the row writes them, bracketed with a space between, joined
     * once: a NULL tag is an empty one */
    size_t len = 0;
    for (size_t i = 0; i < tag_count; i++) {
        len += (i > 0) + 1 + (tags[i] ? strlen(tags[i]) : 0) + 1;
    }
    char *joined = arena_alloc(arena, len + 1);
    char *at = joined;
    for (size_t i = 0; i < tag_count; i++) {
        const char *tag = tags[i] ? tags[i] : "";
        size_t n = strlen(tag);
        if (i > 0) *at++ = ' ';
        *at++ = '[';
        memcpy(at, tag, n);
        at += n;
        *at++ = ']';
    }
    *at = '\0';

    list->items[list->count++] = (item_t){
        .tags = joined,
        .color = color,
        .content = arena_strdup(arena, content ? content : ""),
        .metadata = arena_strdup(arena, metadata),
    };
}

void output_list_render(output_list_t *list) {
    CHECK_NULL(list);
    if (list->count == 0) return;

    output_t *ctx = list->ctx;
    if (ctx->verbosity < OUTPUT_NORMAL) return;

    /* A list is a block, and it owns the boundary above it. Its level is the
     * gate's: a list is a NORMAL block or it is nothing. */
    output_gap(ctx, OUTPUT_NORMAL);

    /* The widest row's tags: every row's are padded to them */
    size_t width = 0;
    for (size_t i = 0; i < list->count; i++) {
        size_t tags = strlen(list->items[i].tags);
        if (tags > width) width = tags;
    }

    /* The header — the title, the count and the hint — and the blank between it
     * and the rows, which is the list's shape rather than a boundary */
    line_t line;
    output_start(&line, ctx, ctx->stream);
    output_appendf(
        &line, "{bold}%s (%zu item%s){reset}",
        list->title, list->count, list->count == 1 ? "" : "s"
    );
    if (list->hint) output_appendf(&line, " {dim}(%s){reset}", list->hint);
    output_bytes(&line, "\n\n", 2);
    output_put(&line);

    /* The rows: the tags in the row's colour, padded, then the content and its
     * metadata dimmed */
    for (size_t i = 0; i < list->count; i++) {
        const item_t *item = &list->items[i];

        output_start(&line, ctx, ctx->stream);
        output_bytes(&line, "  ", 2);
        output_style(&line, item->color);
        output_appendf(&line, "%-*s", (int) width, item->tags);
        output_style(&line, OUTPUT_COLOR_RESET);
        output_appendf(&line, " %s", item->content);
        if (item->metadata) output_appendf(&line, " {dim}(%s){reset}", item->metadata);
        output_bytes(&line, "\n", 1);
        output_put(&line);
    }
}

size_t output_list_count(const output_list_t *list) {
    CHECK_NULL(list);

    return list->count;
}

void output_list_free(output_list_t *list) {
    if (!list) return;

    /* The list stands in its own arena: read the arena out, then free it whole */
    arena_free(list->arena);
}
