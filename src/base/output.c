/**
 * output.c - Output formatting and styling implementation
 *
 * Style engine with {tag} markup, verbosity control, and a list builder.
 *
 * Tag expansion uses a single-pass scanner with a stack-allocated buffer
 * (heap fallback on overflow). Tags are resolved via a sorted lookup
 * table with binary search. Compound tags ({bold;red}) are supported.
 *
 * Tag syntax:
 *   {red}, {bold}, {dim}, ...  — apply style/color
 *   {bold;red}                 — compound (multiple styles)
 *   {reset}                    — explicit reset
 *
 * Tags expand to ANSI codes when colors enabled, empty strings when not.
 * Auto-reset appends ANSI_RESET when an unclosed color span is detected.
 */

#include "base/output.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ═══════════════════════════════════════════════════════════════════
 * ANSI Escape Codes
 *
 * Defined as macros (not variables) to enable compile-time string
 * concatenation: ANSI_BOLD ANSI_RED "text" ANSI_RESET collapses to
 * a single string literal in the binary.
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

/* Empty string returned when colors are disabled */
static const char *EMPTY = "";

/* ═══════════════════════════════════════════════════════════════════
 * Style Buffer
 *
 * Stack-primary, heap-fallback buffer for building expanded format
 * strings. The 512-byte stack covers the vast majority of format
 * strings without heap allocation. Overflow promotes to heap.
 * ═══════════════════════════════════════════════════════════════════ */

#define STYLE_BUF_STACK_SIZE 512

typedef struct {
    char *data;                        /* Points to stack[] or heap */
    size_t len;                        /* Current content length */
    size_t cap;                        /* Total capacity */
    char stack[STYLE_BUF_STACK_SIZE];  /* Inline storage */
} style_buf_t;

static inline void style_buf_init(style_buf_t *sb) {
    sb->data = sb->stack;
    sb->len = 0;
    sb->cap = STYLE_BUF_STACK_SIZE;
}

static inline void style_buf_free(style_buf_t *sb) {
    if (sb->data != sb->stack)
        free(sb->data);
}

/**
 * Ensure buffer has room for `need` more bytes
 *
 * On first overflow, copies stack to a heap allocation. Subsequent
 * overflows realloc the heap buffer. Returns false on OOM (data is
 * preserved but truncated).
 */
static bool style_buf_grow(style_buf_t *sb, size_t need) {
    size_t required = sb->len + need;
    if (required < sb->cap)
        return true;

    size_t new_cap = sb->cap;
    while (new_cap <= required) {
        if (new_cap > SIZE_MAX / 2)
            return false;
        new_cap *= 2;
    }

    if (sb->data == sb->stack) {
        char *heap = malloc(new_cap);
        if (!heap) return false;
        memcpy(heap, sb->stack, sb->len);
        sb->data = heap;
    } else {
        char *grown = realloc(sb->data, new_cap);
        if (!grown) return false;
        sb->data = grown;
    }

    sb->cap = new_cap;
    return true;
}

static inline void style_buf_putc(style_buf_t *sb, char ch) {
    if (style_buf_grow(sb, 1))
        sb->data[sb->len++] = ch;
}

static inline void style_buf_puts(style_buf_t *sb, const char *s, size_t n) {
    if (n > 0 && style_buf_grow(sb, n)) {
        memcpy(sb->data + sb->len, s, n);
        sb->len += n;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Tag Table
 *
 * Sorted alphabetically for binary search. The STYLE_TAG macro
 * computes string lengths at compile time — no runtime strlen.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *name;       /* Tag name (e.g., "red", "bold") */
    const char *ansi;       /* ANSI escape sequence */
    uint8_t name_len;       /* strlen(name), computed at compile time */
    uint8_t ansi_len;       /* strlen(ansi), computed at compile time */
} style_tag_t;

#define STYLE_TAG(n, a) { n, a, sizeof(n) - 1, sizeof(a) - 1 }

/* MUST remain sorted by name (ASCII order) for binary search */
static const style_tag_t TAG_TABLE[] = {
    STYLE_TAG("blue",    ANSI_BLUE),
    STYLE_TAG("bold",    ANSI_BOLD),
    STYLE_TAG("cyan",    ANSI_CYAN),
    STYLE_TAG("dim",     ANSI_DIM),
    STYLE_TAG("green",   ANSI_GREEN),
    STYLE_TAG("magenta", ANSI_MAGENTA),
    STYLE_TAG("red",     ANSI_RED),
    STYLE_TAG("reset",   ANSI_RESET),
    STYLE_TAG("white",   ANSI_WHITE),
    STYLE_TAG("yellow",  ANSI_YELLOW),
};

#define TAG_COUNT (sizeof(TAG_TABLE) / sizeof(TAG_TABLE[0]))

/**
 * Binary search for a tag by name
 *
 * Lexicographic comparison against the sorted TAG_TABLE.
 * Returns pointer to matching entry, or NULL for unknown tags.
 */
static const style_tag_t *resolve_tag(const char *name, size_t len) {
    int lo = 0;
    int hi = (int) TAG_COUNT - 1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        const style_tag_t *entry = &TAG_TABLE[mid];

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
 * Expand a (possibly compound) tag into ANSI codes
 *
 * Handles simple tags ({red}) and compound tags ({bold;red}).
 * Splits on ';', resolves each part independently. If ANY part
 * is unknown, the entire tag is rejected (caller passes it through
 * literally). Empty parts from leading/trailing/double semicolons
 * are silently skipped.
 *
 * @param sb Buffer to append ANSI codes to
 * @param color_on Whether to emit ANSI codes (false = strip tags)
 * @param tag Tag content (between '{' and '}')
 * @param tag_len Length of tag content
 * @return true if tag was recognized, false to pass through literally
 */
static bool expand_tag(
    style_buf_t *sb,
    bool color_on,
    const char *tag,
    size_t tag_len
) {
    const style_tag_t *resolved[8];
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

            const style_tag_t *entry = resolve_tag(p, part_len);
            if (!entry) return false;

            resolved[count++] = entry;
        }

        p = semi ? semi + 1 : end;
    }

    if (count == 0) return false;

    /* Second pass: emit ANSI codes */
    if (color_on) {
        for (size_t i = 0; i < count; i++)
            style_buf_puts(sb, resolved[i]->ansi, resolved[i]->ansi_len);
    }

    return true;
}

/* Maximum characters scanned for a tag name (prevents runaway on '{') */
#define TAG_SCAN_LIMIT 16

/**
 * Expand {tag} markup in a format string
 *
 * Single-pass scan: literal characters are copied directly, recognized
 * {tag} sequences are replaced with ANSI codes (or stripped when colors
 * disabled). Unknown tags and unclosed braces pass through literally.
 *
 * @param color_on  Whether to emit ANSI codes or strip tags
 * @param fmt       Format string with {tag} markup
 * @param sb        Destination buffer (must be initialized, gets NUL-terminated)
 * @return true if any tags were expanded (auto-reset may be needed)
 */
static bool expand_format(bool color_on, const char *fmt, style_buf_t *sb) {
    bool has_tags = false;
    const char *p = fmt;

    while (*p) {
        if (*p != '{') {
            /* Fast path: bulk-copy runs of literal characters */
            const char *run = p;
            while (*p && *p != '{') p++;
            style_buf_puts(sb, run, (size_t) (p - run));
            continue;
        }

        /* Found '{' — scan for closing '}' within limit */
        const char *tag_start = p + 1;
        const char *tag_end = NULL;

        for (const char *q = tag_start;
            *q && (size_t) (q - tag_start) < TAG_SCAN_LIMIT;
            q++) {
            if (*q == '}') {
                tag_end = q;
                break;
            }
        }

        if (!tag_end || tag_end == tag_start) {
            /* Unclosed or empty brace — pass through '{' literally */
            style_buf_putc(sb, '{');
            p++;
            continue;
        }

        if (expand_tag(
            sb, color_on, tag_start,
            (size_t) (tag_end - tag_start)
            )) {
            has_tags = true;
            p = tag_end + 1;  /* Advance past '}' */
        } else {
            /* Unknown tag — pass through '{' literally */
            style_buf_putc(sb, '{');
            p++;
        }
    }

    /* NUL-terminate (not counted in sb->len) */
    style_buf_putc(sb, '\0');
    sb->len--;

    return has_tags;
}

/**
 * Expand {tags} in fmt, then vfprintf with args
 *
 * Core output primitive — all styled variadic output routes through here.
 */
static void styled_vfprintf(
    bool color_on,
    FILE *stream,
    const char *fmt,
    va_list args
) {
    style_buf_t sb;
    style_buf_init(&sb);

    bool has_tags = expand_format(color_on, fmt, &sb);
    vfprintf(stream, sb.data, args);

    if (has_tags && color_on)
        fputs(ANSI_RESET, stream);

    style_buf_free(&sb);
}

/**
 * Expand {tags} in str, then fputs (no printf formatting)
 *
 * Use for styled prefixes and labels. Avoids format-string risks
 * since the expanded string is never interpreted by printf.
 */
static void styled_fputs(bool color_on, FILE *stream, const char *str) {
    style_buf_t sb;
    style_buf_init(&sb);

    bool has_tags = expand_format(color_on, str, &sb);
    fputs(sb.data, stream);

    if (has_tags && color_on)
        fputs(ANSI_RESET, stream);

    style_buf_free(&sb);
}

/* ═══════════════════════════════════════════════════════════════════
 * Terminal and Color Detection
 * ═══════════════════════════════════════════════════════════════════ */

static bool fd_supports_color(int fd) {
    if (!isatty(fd))
        return false;

    const char *no_color = getenv("NO_COLOR");
    if (no_color && no_color[0] != '\0')
        return false;

    const char *term = getenv("TERM");
    if (!term || strcmp(term, "dumb") == 0)
        return false;

    return true;
}

static bool should_enable_colors(output_color_mode_t mode, FILE *stream) {
    switch (mode) {
        case OUTPUT_COLOR_ALWAYS:  return true;
        case OUTPUT_COLOR_NEVER:   return false;
        case OUTPUT_COLOR_AUTO:    return fd_supports_color(fileno(stream));
        default:                   return false;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Context Management
 * ═══════════════════════════════════════════════════════════════════ */

output_ctx_t *output_create(
    FILE *stream,
    output_verbosity_t verbosity,
    output_color_mode_t color_mode
) {
    output_ctx_t *ctx = calloc(1, sizeof(output_ctx_t));
    if (!ctx) {
        return NULL;
    }

    ctx->stream = stream ? stream : stdout;
    ctx->verbosity = verbosity;
    ctx->color_mode = color_mode;
    ctx->color_enabled = should_enable_colors(color_mode, ctx->stream);
    ctx->stderr_color_enabled = should_enable_colors(color_mode, stderr);

    return ctx;
}

void output_free(output_ctx_t *ctx) {
    if (ctx) {
        free(ctx);
    }
}

void output_set_verbosity(output_ctx_t *ctx, output_verbosity_t verbosity) {
    if (ctx) {
        ctx->verbosity = verbosity;
    }
}

output_verbosity_t output_parse_verbosity(const char *str) {
    if (!str) return OUTPUT_NORMAL;

    if (strcmp(str, "normal") == 0)    return OUTPUT_NORMAL;
    if (strcmp(str, "quiet") == 0)     return OUTPUT_QUIET;
    if (strcmp(str, "verbose") == 0)   return OUTPUT_VERBOSE;

    /* Invalid value, use default */
    return OUTPUT_NORMAL;
}

output_color_mode_t output_parse_color_mode(const char *str) {
    if (!str) return OUTPUT_COLOR_AUTO;

    if (strcmp(str, "auto") == 0)      return OUTPUT_COLOR_AUTO;
    if (strcmp(str, "always") == 0)    return OUTPUT_COLOR_ALWAYS;
    if (strcmp(str, "never") == 0)     return OUTPUT_COLOR_NEVER;

    /* Invalid value, use default */
    return OUTPUT_COLOR_AUTO;
}

/* ═══════════════════════════════════════════════════════════════════
 * Color Support
 * ═══════════════════════════════════════════════════════════════════ */

bool output_colors_enabled(const output_ctx_t *ctx) {
    return ctx ? ctx->color_enabled : false;
}

bool output_is_tty(const output_ctx_t *ctx) {
    if (!ctx || !ctx->stream)
        return false;

    return isatty(fileno(ctx->stream));
}

const char *output_color_code(const output_ctx_t *ctx, output_color_t color) {
    if (!ctx || !ctx->color_enabled)
        return EMPTY;

    if ((unsigned) color >= ANSI_CODE_COUNT)
        return EMPTY;

    return ANSI_CODES[color];
}

/* ═══════════════════════════════════════════════════════════════════
 * Formatted Output
 * ═══════════════════════════════════════════════════════════════════ */

void output_print(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    va_list args;
    va_start(args, fmt);
    vfprintf(ctx->stream, fmt, args);
    va_end(args);
}

void output_styled(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    va_list args;
    va_start(args, fmt);
    styled_vfprintf(ctx->color_enabled, ctx->stream, fmt, args);
    va_end(args);
}

void output_colored(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    output_color_t color,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    bool apply_color = color != OUTPUT_COLOR_RESET
        && ctx->color_enabled && (unsigned) color < ANSI_CODE_COUNT;

    if (apply_color) fputs(ANSI_CODES[color], ctx->stream);

    va_list args;
    va_start(args, fmt);
    styled_vfprintf(ctx->color_enabled, ctx->stream, fmt, args);
    va_end(args);

    if (apply_color) fputs(ANSI_RESET, ctx->stream);
}

void output_error(const output_ctx_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) return;

    styled_fputs(
        ctx->stderr_color_enabled, stderr,
        "{bold;red}Error:{reset} "
    );

    va_list args;
    va_start(args, fmt);
    styled_vfprintf(ctx->stderr_color_enabled, stderr, fmt, args);
    va_end(args);

    fputc('\n', stderr);
}

void output_warning(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    styled_fputs(
        ctx->stderr_color_enabled, stderr,
        "{bold;yellow}Warning:{reset} "
    );

    va_list args;
    va_start(args, fmt);
    styled_vfprintf(ctx->stderr_color_enabled, stderr, fmt, args);
    va_end(args);

    fputc('\n', stderr);
}

void output_success(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    styled_fputs(
        ctx->color_enabled, ctx->stream,
        "{green}\xe2\x9c\x93{reset} "
    );

    va_list args;
    va_start(args, fmt);
    styled_vfprintf(ctx->color_enabled, ctx->stream, fmt, args);
    va_end(args);

    fputc('\n', ctx->stream);
}

void output_info(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    va_list args;
    va_start(args, fmt);
    styled_vfprintf(ctx->color_enabled, ctx->stream, fmt, args);
    va_end(args);

    fputc('\n', ctx->stream);
}

void output_hint(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    /* Preserve leading whitespace (printed uncolored for indentation) */
    const char *p = fmt;
    while (*p == ' ' || *p == '\t') p++;
    size_t leading_ws = (size_t) (p - fmt);

    if (leading_ws > 0)
        fprintf(ctx->stream, "%.*s", (int) leading_ws, fmt);

    /* Dim wraps the entire hint: prefix + body */
    if (ctx->color_enabled) fputs(ANSI_DIM, ctx->stream);
    fputs("Hint: ", ctx->stream);

    va_list args;
    va_start(args, fmt);
    styled_vfprintf(ctx->color_enabled, ctx->stream, p, args);
    va_end(args);

    if (ctx->color_enabled) fputs(ANSI_RESET, ctx->stream);
    fputc('\n', ctx->stream);
}

void output_hintline(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    if (ctx->color_enabled) fputs(ANSI_DIM, ctx->stream);

    va_list args;
    va_start(args, fmt);
    styled_vfprintf(ctx->color_enabled, ctx->stream, fmt, args);
    va_end(args);

    if (ctx->color_enabled) fputs(ANSI_RESET, ctx->stream);
    fputc('\n', ctx->stream);
}

void output_newline(const output_ctx_t *ctx, output_verbosity_t min_level) {
    if (!ctx || ctx->verbosity < min_level) return;
    fputc('\n', ctx->stream);
}

void output_section(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) return;
    if (ctx->verbosity < min_level) return;

    /* Automatic section separator */
    if (ctx->has_content) {
        fputc('\n', ctx->stream);
    }
    ((output_ctx_t *) ctx)->has_content = true;

    const char *bold = output_color_code(ctx, OUTPUT_COLOR_BOLD);
    const char *reset = output_color_code(ctx, OUTPUT_COLOR_RESET);

    fputs(bold, ctx->stream);
    va_list args;
    va_start(args, fmt);
    vfprintf(ctx->stream, fmt, args);
    va_end(args);
    fputs(reset, ctx->stream);
    fputc('\n', ctx->stream);
}

void output_clear_line(const output_ctx_t *ctx) {
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

void output_print_diff(const output_ctx_t *ctx, const char *diff_text) {
    if (!ctx || !diff_text) return;

    if (!ctx->color_enabled) {
        output_print(ctx, OUTPUT_NORMAL, "%s\n", diff_text);
        return;
    }

    const char *line = diff_text;
    while (line && *line) {
        const char *next = strchr(line, '\n');
        size_t len = next ? (size_t) (next - line) : strlen(line);

        const char *color = NULL;
        if (len > 0 && line[0] == '+' && (len == 1 || line[1] != '+'))
            color = ANSI_GREEN;
        else if (len > 0 && line[0] == '-' && (len == 1 || line[1] != '-'))
            color = ANSI_RED;
        else if (len > 1 && line[0] == '@' && line[1] == '@')
            color = ANSI_CYAN;

        if (color)
            fprintf(
                ctx->stream, "%s%.*s" ANSI_RESET "\n",
                color, (int) len, line
            );
        else
            fprintf(ctx->stream, "%.*s\n", (int) len, line);

        line = next ? next + 1 : NULL;
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
    else if (bytes < 1024 * 1024)
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

/* ═══════════════════════════════════════════════════════════════════
 * User Confirmation Prompts
 * ═══════════════════════════════════════════════════════════════════ */

static void clear_stdin_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) { }
}

static bool read_user_response(bool default_value) {
    char response[16];

    if (fgets(response, sizeof(response), stdin) == NULL)
        return default_value;

    size_t len = strlen(response);
    if (len > 0 && response[len - 1] != '\n')
        clear_stdin_buffer();

    if (len == 0 || response[0] == '\n')
        return default_value;

    return (response[0] == 'y' || response[0] == 'Y');
}

bool output_confirm(
    const output_ctx_t *ctx,
    const char *message,
    bool default_value
) {
    if (!ctx || !message) return false;

    FILE *prompt = stderr;
    const char *suffix = default_value ? " [Y/n] " : " [y/N] ";

    const char *bold = ctx->stderr_color_enabled ? ANSI_BOLD : "";
    const char *reset = ctx->stderr_color_enabled ? ANSI_RESET : "";

    fprintf(prompt, "%s%s%s%s", bold, message, reset, suffix);
    fflush(prompt);

    return read_user_response(default_value);
}

bool output_confirm_or_default(
    const output_ctx_t *ctx,
    const char *message,
    bool default_value,
    bool non_interactive_default
) {
    if (!ctx || !message) return false;

    if (!isatty(STDIN_FILENO)) {
        if (non_interactive_default) {
            styled_fputs(
                ctx->stderr_color_enabled, stderr,
                "{bold;yellow}Warning:{reset} "
            );
            fprintf(
                stderr,
                "Running non-interactively, auto-confirming: %s\n",
                message
            );
        } else {
            styled_fputs(
                ctx->stderr_color_enabled, stderr,
                "{bold;red}Error:{reset} "
            );
            fprintf(
                stderr,
                "Running non-interactively, refusing: %s\n",
                message
            );
        }
        return non_interactive_default;
    }

    return output_confirm(ctx, message, default_value);
}

bool output_confirm_destructive(
    const output_ctx_t *ctx,
    bool confirm_destructive,
    const char *message,
    bool force_flag
) {
    if (!ctx || !message) return false;
    if (force_flag) return true;
    if (!confirm_destructive) return true;

    if (!isatty(STDIN_FILENO)) {
        styled_fputs(
            ctx->stderr_color_enabled, stderr,
            "{bold;red}Error:{reset} "
        );
        fprintf(
            stderr,
            "Running non-interactively, refusing destructive operation: %s\n",
            message
        );
        return false;
    }

    styled_fputs(
        ctx->stderr_color_enabled, stderr,
        "{bold;yellow}Warning:{reset} This is a destructive operation!\n"
    );

    return output_confirm(ctx, message, false);
}

/* ═══════════════════════════════════════════════════════════════════
 * List Builder
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    char **tags;           /* Array of owned tag strings */
    size_t tag_count;      /* Number of tags */
    output_color_t color;  /* Color for tags */
    char *content;         /* Owned content string */
    char *metadata;        /* Owned metadata string (nullable) */
} list_item_t;

struct output_list {
    output_ctx_t *ctx;     /* Borrowed reference (caller owns) */
    char *title;           /* Owned section title */
    char *hint;            /* Owned hint text (nullable) */
    list_item_t *items;    /* Dynamic array of items */
    size_t count;          /* Current item count */
    size_t capacity;       /* Allocated capacity */
};

static void free_list_item(list_item_t *item) {
    if (!item) return;

    if (item->tags) {
        for (size_t i = 0; i < item->tag_count; i++)
            free(item->tags[i]);
        free(item->tags);
    }

    free(item->content);
    free(item->metadata);
    memset(item, 0, sizeof(list_item_t));
}

static int list_ensure_capacity(output_list_t *list) {
    if (list->count < list->capacity) return 0;

    size_t new_capacity = list->capacity * 2;
    list_item_t *new_items = realloc(
        list->items, new_capacity * sizeof(list_item_t)
    );
    if (!new_items) return -1;

    list->items = new_items;
    list->capacity = new_capacity;
    memset(
        &list->items[list->count], 0,
        (new_capacity - list->count) * sizeof(list_item_t)
    );

    return 0;
}

static void format_tags_with_brackets(
    char **tags,
    size_t tag_count,
    char *buffer,
    size_t buffer_size
) {
    if (!tags || tag_count == 0 || !buffer || buffer_size == 0) {
        if (buffer && buffer_size > 0) buffer[0] = '\0';
        return;
    }

    size_t offset = 0;
    for (size_t i = 0; i < tag_count && offset < buffer_size - 1; i++) {
        if (i > 0 && offset < buffer_size - 1) {
            offset += snprintf(buffer + offset, buffer_size - offset, " ");
        }
        offset += snprintf(
            buffer + offset, buffer_size - offset, "[%s]", tags[i]
        );
    }
}

output_list_t *output_list_create(
    output_ctx_t *ctx,
    const char *title,
    const char *hint
) {
    if (!ctx || !title) return NULL;

    output_list_t *list = calloc(1, sizeof(output_list_t));
    if (!list) return NULL;

    list->ctx = ctx;

    list->title = strdup(title);
    if (!list->title)
        goto cleanup;

    if (hint) {
        list->hint = strdup(hint);
        if (!list->hint)
            goto cleanup;
    }

    list->capacity = 16;
    list->items = calloc(16, sizeof(list_item_t));
    if (!list->items)
        goto cleanup;

    return list;

cleanup:
    free(list->hint);
    free(list->title);
    free(list);
    return NULL;
}

int output_list_add(
    output_list_t *list,
    const char **tags,
    size_t tag_count,
    output_color_t color,
    const char *content,
    const char *metadata
) {
    if (!list) return -1;
    if (tag_count > 0 && !tags) return -1;
    if (list_ensure_capacity(list) != 0) return -1;

    list_item_t *item = &list->items[list->count];

    if (tag_count > 0) {
        item->tags = calloc(tag_count, sizeof(char *));
        if (!item->tags) return -1;

        for (size_t i = 0; i < tag_count; i++) {
            item->tags[i] = tags[i] ? strdup(tags[i]) : strdup("");
            if (!item->tags[i]) {
                for (size_t j = 0; j < i; j++)
                    free(item->tags[j]);
                free(item->tags);
                item->tags = NULL;
                goto error;
            }
        }
        item->tag_count = tag_count;
    }

    item->color = color;

    item->content = content ? strdup(content) : strdup("");
    if (!item->content)
        goto error;

    if (metadata) {
        item->metadata = strdup(metadata);
        if (!item->metadata)
            goto error;
    }

    list->count++;
    return 0;

error:
    free_list_item(item);
    return -1;
}

void output_list_render(output_list_t *list) {
    if (!list || list->count == 0) return;

    output_ctx_t *ctx = list->ctx;
    if (ctx->verbosity < OUTPUT_NORMAL) return;

    /* Automatic section separator */
    if (ctx->has_content) {
        fputc('\n', ctx->stream);
    }
    ctx->has_content = true;

    /* Pass 1: Calculate maximum tag width */
    size_t max_tag_width = 0;
    for (size_t i = 0; i < list->count; i++) {
        list_item_t *item = &list->items[i];
        size_t tag_width = 0;
        for (size_t j = 0; j < item->tag_count; j++) {
            tag_width += strlen(item->tags[j]) + 2;
            if (j > 0) tag_width += 1;
        }
        if (tag_width > max_tag_width) max_tag_width = tag_width;
    }

    /* Pass 2: Render header */
    const char *bold = output_color_code(ctx, OUTPUT_COLOR_BOLD);
    const char *dim = output_color_code(ctx, OUTPUT_COLOR_DIM);
    const char *reset = output_color_code(ctx, OUTPUT_COLOR_RESET);

    fprintf(
        ctx->stream, "%s%s (%zu item%s)%s",
        bold, list->title, list->count,
        list->count == 1 ? "" : "s", reset
    );

    if (list->hint)
        fprintf(ctx->stream, " %s(%s)%s", dim, list->hint, reset);

    fprintf(ctx->stream, "\n\n");

    /* Pass 3: Render items with alignment */
    for (size_t i = 0; i < list->count; i++) {
        list_item_t *item = &list->items[i];

        char tag_buf[256];
        format_tags_with_brackets(
            item->tags, item->tag_count, tag_buf, sizeof(tag_buf)
        );

        const char *color = output_color_code(ctx, item->color);

        fprintf(
            ctx->stream, "  %s%-*s%s %s",
            color, (int) max_tag_width, tag_buf,
            reset, item->content
        );

        if (item->metadata)
            fprintf(
                ctx->stream, " %s(%s)%s",
                dim, item->metadata, reset
            );

        fputc('\n', ctx->stream);
    }
}

size_t output_list_count(const output_list_t *list) {
    return list ? list->count : 0;
}

void output_list_free(output_list_t *list) {
    if (!list) return;

    if (list->items) {
        for (size_t i = 0; i < list->count; i++)
            free_list_item(&list->items[i]);
        free(list->items);
    }

    free(list->hint);
    free(list->title);
    free(list);
}
