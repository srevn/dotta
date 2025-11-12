/**
 * output.c - Output formatting and styling implementation
 */

#include "output.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"  /* For dotta_config_t */

/* ANSI color code strings */
static const char *ANSI_RESET   = "\033[0m";
static const char *ANSI_BOLD    = "\033[1m";
static const char *ANSI_DIM     = "\033[2m";
static const char *ANSI_RED     = "\033[31m";
static const char *ANSI_GREEN   = "\033[32m";
static const char *ANSI_YELLOW  = "\033[33m";
static const char *ANSI_BLUE    = "\033[34m";
static const char *ANSI_MAGENTA = "\033[35m";
static const char *ANSI_CYAN    = "\033[36m";
static const char *ANSI_WHITE   = "\033[37m";

/* Empty string for no-color mode */
static const char *EMPTY = "";

/**
 * Check if a file descriptor supports colors
 */
static bool fd_supports_color(int fd) {
    /* Check if fd is a terminal */
    if (!isatty(fd)) {
        return false;
    }

    /* Check NO_COLOR environment variable */
    const char *no_color = getenv("NO_COLOR");
    if (no_color && no_color[0] != '\0') {
        return false;
    }

    /* Check TERM variable */
    const char *term = getenv("TERM");
    if (!term || strcmp(term, "dumb") == 0) {
        return false;
    }

    return true;
}

/**
 * Determine if colors should be enabled based on mode and stream
 */
static bool should_enable_colors(output_color_mode_t mode, FILE *stream) {
    int fd = fileno(stream);

    switch (mode) {
    case OUTPUT_COLOR_ALWAYS:
        return true;
    case OUTPUT_COLOR_NEVER:
        return false;
    case OUTPUT_COLOR_AUTO:
        return fd_supports_color(fd);
    default:
        return false;
    }
}

/* Context Management */

output_ctx_t *output_create(void) {
    return output_create_with(
        stdout,
        OUTPUT_FORMAT_COMPACT,
        OUTPUT_NORMAL,
        OUTPUT_COLOR_AUTO
    );
}

output_ctx_t *output_create_with(
    FILE *stream,
    output_format_t format,
    output_verbosity_t verbosity,
    output_color_mode_t color_mode
) {
    output_ctx_t *ctx = calloc(1, sizeof(output_ctx_t));
    if (!ctx) {
        return NULL;
    }

    ctx->stream = stream ? stream : stdout;
    ctx->format = format;
    ctx->verbosity = verbosity;
    ctx->color_mode = color_mode;
    ctx->color_enabled = should_enable_colors(color_mode, ctx->stream);

    return ctx;
}

void output_free(output_ctx_t *ctx) {
    if (ctx) {
        free(ctx);
    }
}

void output_set_format(output_ctx_t *ctx, output_format_t format) {
    if (ctx) {
        ctx->format = format;
    }
}

void output_set_verbosity(output_ctx_t *ctx, output_verbosity_t verbosity) {
    if (ctx) {
        ctx->verbosity = verbosity;
    }
}

void output_set_color_mode(output_ctx_t *ctx, output_color_mode_t mode) {
    if (ctx) {
        ctx->color_mode = mode;
        ctx->color_enabled = should_enable_colors(mode, ctx->stream);
    }
}

/**
 * Parse verbosity string to enum
 */
static output_verbosity_t parse_verbosity(const char *str) {
    if (!str) {
        return OUTPUT_NORMAL;
    }

    if (strcmp(str, "quiet") == 0) {
        return OUTPUT_QUIET;
    } else if (strcmp(str, "normal") == 0) {
        return OUTPUT_NORMAL;
    } else if (strcmp(str, "verbose") == 0) {
        return OUTPUT_VERBOSE;
    } else if (strcmp(str, "debug") == 0) {
        return OUTPUT_DEBUG;
    }

    /* Invalid value, use default */
    return OUTPUT_NORMAL;
}

/**
 * Parse color mode string to enum
 */
static output_color_mode_t parse_color_mode(const char *str) {
    if (!str) {
        return OUTPUT_COLOR_AUTO;
    }

    if (strcmp(str, "auto") == 0) {
        return OUTPUT_COLOR_AUTO;
    } else if (strcmp(str, "always") == 0) {
        return OUTPUT_COLOR_ALWAYS;
    } else if (strcmp(str, "never") == 0) {
        return OUTPUT_COLOR_NEVER;
    }

    /* Invalid value, use default */
    return OUTPUT_COLOR_AUTO;
}

/**
 * Parse format string to enum
 */
static output_format_t parse_format(const char *str) {
    if (!str) {
        return OUTPUT_FORMAT_COMPACT;
    }

    if (strcmp(str, "compact") == 0) {
        return OUTPUT_FORMAT_COMPACT;
    } else if (strcmp(str, "detailed") == 0) {
        return OUTPUT_FORMAT_DETAILED;
    } else if (strcmp(str, "json") == 0) {
        return OUTPUT_FORMAT_JSON;
    }

    /* Invalid value, use default */
    return OUTPUT_FORMAT_COMPACT;
}

output_ctx_t *output_create_from_config(const dotta_config_t *config) {
    output_verbosity_t verbosity = OUTPUT_NORMAL;
    output_color_mode_t color_mode = OUTPUT_COLOR_AUTO;
    output_format_t format = OUTPUT_FORMAT_COMPACT;

    /* Parse config if provided */
    if (config) {
        verbosity = parse_verbosity(config->verbosity);
        color_mode = parse_color_mode(config->color);
        format = parse_format(config->format);
    }

    return output_create_with(stdout, format, verbosity, color_mode);
}

/* Color Support */

bool output_colors_enabled(const output_ctx_t *ctx) {
    return ctx ? ctx->color_enabled : false;
}

const char *output_color_code(const output_ctx_t *ctx, output_color_t color) {
    if (!ctx || !ctx->color_enabled) {
        return EMPTY;
    }

    switch (color) {
    case OUTPUT_COLOR_RESET:   return ANSI_RESET;
    case OUTPUT_COLOR_BOLD:    return ANSI_BOLD;
    case OUTPUT_COLOR_DIM:     return ANSI_DIM;
    case OUTPUT_COLOR_RED:     return ANSI_RED;
    case OUTPUT_COLOR_GREEN:   return ANSI_GREEN;
    case OUTPUT_COLOR_YELLOW:  return ANSI_YELLOW;
    case OUTPUT_COLOR_BLUE:    return ANSI_BLUE;
    case OUTPUT_COLOR_MAGENTA: return ANSI_MAGENTA;
    case OUTPUT_COLOR_CYAN:    return ANSI_CYAN;
    case OUTPUT_COLOR_WHITE:   return ANSI_WHITE;
    default:                   return EMPTY;
    }
}

char *output_colorize(
    const output_ctx_t *ctx,
    output_color_t color,
    const char *text
) {
    if (!ctx || !text) {
        return NULL;
    }

    if (!ctx->color_enabled) {
        return strdup(text);
    }

    const char *color_code = output_color_code(ctx, color);
    const char *reset_code = output_color_code(ctx, OUTPUT_COLOR_RESET);

    size_t len = strlen(color_code) + strlen(text) + strlen(reset_code) + 1;
    char *result = malloc(len);
    if (!result) {
        return NULL;
    }

    snprintf(result, len, "%s%s%s", color_code, text, reset_code);
    return result;
}

/* Formatted Output */

void output_print(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) {
        return;
    }

    /* Check verbosity level */
    if (ctx->verbosity < min_level) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    vfprintf(ctx->stream, fmt, args);
    va_end(args);
}

void output_error(const output_ctx_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) {
        return;
    }

    FILE *stream = ctx->stream == stdout ? stderr : ctx->stream;

    if (ctx->color_enabled) {
        fprintf(stream, "%s%sError:%s ", ANSI_BOLD, ANSI_RED, ANSI_RESET);
    } else {
        fprintf(stream, "Error: ");
    }

    va_list args;
    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    va_end(args);

    fprintf(stream, "\n");
}

void output_warning(const output_ctx_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) {
        return;
    }

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    if (ctx->color_enabled) {
        fprintf(ctx->stream, "%s%sWarning:%s ", ANSI_BOLD, ANSI_YELLOW, ANSI_RESET);
    } else {
        fprintf(ctx->stream, "Warning: ");
    }

    va_list args;
    va_start(args, fmt);
    vfprintf(ctx->stream, fmt, args);
    va_end(args);

    fprintf(ctx->stream, "\n");
}

void output_success(const output_ctx_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) {
        return;
    }

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    if (ctx->color_enabled) {
        fprintf(ctx->stream, "%s✓%s ", ANSI_GREEN, ANSI_RESET);
    }

    va_list args;
    va_start(args, fmt);
    vfprintf(ctx->stream, fmt, args);
    va_end(args);

    fprintf(ctx->stream, "\n");
}

void output_info(const output_ctx_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) {
        return;
    }

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    vfprintf(ctx->stream, fmt, args);
    va_end(args);

    fprintf(ctx->stream, "\n");
}

void output_debug(const output_ctx_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) {
        return;
    }

    if (ctx->verbosity < OUTPUT_DEBUG) {
        return;
    }

    if (ctx->color_enabled) {
        fprintf(ctx->stream, "%s[DEBUG]%s ", ANSI_DIM, ANSI_RESET);
    } else {
        fprintf(ctx->stream, "[DEBUG] ");
    }

    va_list args;
    va_start(args, fmt);
    vfprintf(ctx->stream, fmt, args);
    va_end(args);

    fprintf(ctx->stream, "\n");
}

void output_hint(const output_ctx_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) {
        return;
    }

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    /* Count leading whitespace in format string */
    const char *p = fmt;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    size_t leading_ws = p - fmt;

    if (ctx->color_enabled) {
        /* Print leading whitespace (uncolored) */
        if (leading_ws > 0) {
            fprintf(ctx->stream, "%.*s", (int)leading_ws, fmt);
        }

        /* Print "Hint: " and message content with DIM color */
        fprintf(ctx->stream, "%sHint: ", ANSI_DIM);

        va_list args;
        va_start(args, fmt);
        vfprintf(ctx->stream, p, args);  /* Use p to skip leading whitespace */
        va_end(args);

        fprintf(ctx->stream, "%s\n", ANSI_RESET);
    } else {
        /* No color mode */
        /* Print leading whitespace */
        if (leading_ws > 0) {
            fprintf(ctx->stream, "%.*s", (int)leading_ws, fmt);
        }

        fprintf(ctx->stream, "Hint: ");

        va_list args;
        va_start(args, fmt);
        vfprintf(ctx->stream, p, args);  /* Use p to skip leading whitespace */
        va_end(args);

        fprintf(ctx->stream, "\n");
    }
}

void output_hint_line(const output_ctx_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) {
        return;
    }

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    if (ctx->color_enabled) {
        /* No prefix, but still DIM color */
        fprintf(ctx->stream, "%s", ANSI_DIM);

        va_list args;
        va_start(args, fmt);
        vfprintf(ctx->stream, fmt, args);
        va_end(args);

        fprintf(ctx->stream, "%s\n", ANSI_RESET);
    } else {
        /* No color mode */
        va_list args;
        va_start(args, fmt);
        vfprintf(ctx->stream, fmt, args);
        va_end(args);

        fprintf(ctx->stream, "\n");
    }
}

void output_newline(const output_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    fprintf(ctx->stream, "\n");
}

void output_printf(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) {
    if (!ctx || !fmt) {
        return;
    }

    /* Check verbosity level */
    if (ctx->verbosity < min_level) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    vfprintf(ctx->stream, fmt, args);
    va_end(args);
}

/* Structured Output */

void output_section(const output_ctx_t *ctx, const char *title) {
    if (!ctx || !title) {
        return;
    }

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    if (ctx->color_enabled) {
        fprintf(ctx->stream, "%s%s%s\n", ANSI_BOLD, title, ANSI_RESET);
    } else {
        fprintf(ctx->stream, "%s\n", title);
    }
}

void output_item(
    const output_ctx_t *ctx,
    const char *status,
    output_color_t status_color,
    const char *text
) {
    if (!ctx || !status || !text) {
        return;
    }

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    const char *color = output_color_code(ctx, status_color);
    const char *reset = output_color_code(ctx, OUTPUT_COLOR_RESET);

    fprintf(ctx->stream, "  %s%-12s%s %s\n", color, status, reset, text);
}

void output_kv(
    const output_ctx_t *ctx,
    const char *key,
    const char *value
) {
    if (!ctx || !key || !value) {
        return;
    }

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    if (ctx->color_enabled) {
        fprintf(ctx->stream, "  %s%s:%s %s\n", ANSI_BOLD, key, ANSI_RESET, value);
    } else {
        fprintf(ctx->stream, "  %s: %s\n", key, value);
    }
}

void output_progress(
    const output_ctx_t *ctx,
    size_t current,
    size_t total,
    const char *item
) {
    if (!ctx) {
        return;
    }

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    if (item) {
        fprintf(ctx->stream, "  [%zu/%zu] %s\r", current, total, item);
    } else {
        fprintf(ctx->stream, "  [%zu/%zu]\r", current, total);
    }

    fflush(ctx->stream);

    /* Print newline on completion */
    if (current == total) {
        fprintf(ctx->stream, "\n");
    }
}

void output_format_size(size_t bytes, char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) {
        return;
    }

    if (bytes < 1024) {
        snprintf(buffer, buffer_size, "%zu B", bytes);
    } else if (bytes < 1024 * 1024) {
        snprintf(buffer, buffer_size, "%.1f KB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        snprintf(buffer, buffer_size, "%.1f MB", bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buffer, buffer_size, "%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

/* JSON Output Helpers */

void output_json_begin(const output_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    fprintf(ctx->stream, "{\n");
}

void output_json_end(const output_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    fprintf(ctx->stream, "}\n");
}

void output_json_string(
    const output_ctx_t *ctx,
    const char *key,
    const char *value,
    bool last
) {
    if (!ctx || !key) {
        return;
    }

    if (value) {
        fprintf(ctx->stream, "  \"%s\": \"%s\"%s\n", key, value, last ? "" : ",");
    } else {
        fprintf(ctx->stream, "  \"%s\": null%s\n", key, last ? "" : ",");
    }
}

void output_json_number(
    const output_ctx_t *ctx,
    const char *key,
    long value,
    bool last
) {
    if (!ctx || !key) {
        return;
    }

    fprintf(ctx->stream, "  \"%s\": %ld%s\n", key, value, last ? "" : ",");
}

void output_json_bool(
    const output_ctx_t *ctx,
    const char *key,
    bool value,
    bool last
) {
    if (!ctx || !key) {
        return;
    }

    fprintf(ctx->stream, "  \"%s\": %s%s\n", key, value ? "true" : "false", last ? "" : ",");
}

void output_json_array_begin(const output_ctx_t *ctx, const char *key) {
    if (!ctx || !key) {
        return;
    }

    fprintf(ctx->stream, "  \"%s\": [\n", key);
}

void output_json_array_end(const output_ctx_t *ctx, bool last) {
    if (!ctx) {
        return;
    }

    fprintf(ctx->stream, "  ]%s\n", last ? "" : ",");
}

/* User Confirmation Prompts */

/**
 * Clear stdin buffer to prevent input pollution
 *
 * This ensures that any remaining characters in the input buffer
 * (from user pressing more than just y/n) don't affect subsequent reads.
 */
static void clear_stdin_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        /* Discard remaining characters */
    }
}

/**
 * Read and validate user response
 *
 * Reads a single line, handles buffer overflow safely, and validates
 * the response. Returns true for yes, false for no/error.
 */
static bool read_user_response(bool default_value) {
    char response[16];

    if (fgets(response, sizeof(response), stdin) == NULL) {
        /* EOF or read error - return default */
        return default_value;
    }

    /* Check if we read a complete line */
    size_t len = strlen(response);
    if (len > 0 && response[len - 1] != '\n') {
        /* Buffer was too small - clear remaining input */
        clear_stdin_buffer();
    }

    /* Empty input (just Enter) - use default */
    if (len == 0 || response[0] == '\n') {
        return default_value;
    }

    /* Check first character for y/Y or n/N */
    char first = response[0];
    return (first == 'y' || first == 'Y');
}

bool output_confirm(
    const output_ctx_t *ctx,
    const char *message,
    bool default_value
) {
    if (!ctx || !message) {
        return false;
    }

    /* Use stderr for prompts (standard practice for interactive input) */
    FILE *prompt_stream = stderr;

    /* Format prompt with default indicator */
    const char *prompt_suffix = default_value ? " [Y/n] " : " [y/N] ";

    if (ctx->color_enabled) {
        fprintf(prompt_stream, "%s%s%s%s",
                output_color_code(ctx, OUTPUT_COLOR_BOLD),
                message,
                output_color_code(ctx, OUTPUT_COLOR_RESET),
                prompt_suffix);
    } else {
        fprintf(prompt_stream, "%s%s", message, prompt_suffix);
    }

    fflush(prompt_stream);

    return read_user_response(default_value);
}

bool output_confirm_or_default(
    const output_ctx_t *ctx,
    const char *message,
    bool default_value,
    bool non_interactive_default
) {
    if (!ctx || !message) {
        return false;
    }

    /* Check if stdin is a TTY (interactive terminal) */
    if (!isatty(STDIN_FILENO)) {
        /* Non-interactive mode */
        FILE *warn_stream = stderr;

        if (non_interactive_default) {
            if (ctx->color_enabled) {
                fprintf(warn_stream, "%sWARNING:%s Running non-interactively, auto-confirming: %s\n",
                        output_color_code(ctx, OUTPUT_COLOR_YELLOW),
                        output_color_code(ctx, OUTPUT_COLOR_RESET),
                        message);
            } else {
                fprintf(warn_stream, "WARNING: Running non-interactively, auto-confirming: %s\n", message);
            }
        } else {
            if (ctx->color_enabled) {
                fprintf(warn_stream, "%sERROR:%s Running non-interactively, refusing: %s\n",
                        output_color_code(ctx, OUTPUT_COLOR_RED),
                        output_color_code(ctx, OUTPUT_COLOR_RESET),
                        message);
            } else {
                fprintf(warn_stream, "ERROR: Running non-interactively, refusing: %s\n", message);
            }
        }

        return non_interactive_default;
    }

    /* Interactive mode - use standard confirmation */
    return output_confirm(ctx, message, default_value);
}

bool output_confirm_destructive(
    const output_ctx_t *ctx,
    const dotta_config_t *config,
    const char *message,
    bool force_flag
) {
    if (!ctx || !message) {
        return false;
    }

    /* Skip confirmation if force flag is set */
    if (force_flag) {
        return true;
    }

    /* Check config for confirm_destructive setting */
    bool require_confirmation = true;
    if (config) {
        require_confirmation = config->confirm_destructive;
    }

    /* If confirmation not required by config, proceed */
    if (!require_confirmation) {
        return true;
    }

    /* Show warning and ask for confirmation */
    if (ctx->color_enabled) {
        fprintf(stderr, "%sWARNING:%s This is a destructive operation!\n",
                output_color_code(ctx, OUTPUT_COLOR_YELLOW),
                output_color_code(ctx, OUTPUT_COLOR_RESET));
    } else {
        fprintf(stderr, "WARNING: This is a destructive operation!\n");
    }

    return output_confirm(ctx, message, false);  /* Default to NO for destructive ops */
}

/* List Builder Implementation */

/**
 * Internal list item structure
 */
typedef struct {
    char **tags;           /* Array of owned tag strings */
    size_t tag_count;      /* Number of tags */
    output_color_t color;  /* Color for tags */
    char *content;         /* Owned content string */
    char *metadata;        /* Owned metadata string (nullable) */
} list_item_t;

/**
 * List builder structure
 */
struct output_list {
    output_ctx_t *ctx;     /* Borrowed reference (caller owns) */
    char *title;           /* Owned section title */
    char *hint;            /* Owned hint text (nullable) */
    list_item_t *items;    /* Dynamic array of items */
    size_t count;          /* Current item count */
    size_t capacity;       /* Allocated capacity */
};

/**
 * Free a single list item and its internal allocations
 */
static void free_list_item(list_item_t *item) {
    if (!item) {
        return;
    }

    if (item->tags) {
        for (size_t i = 0; i < item->tag_count; i++) {
            free(item->tags[i]);
        }
        free(item->tags);
    }

    free(item->content);
    free(item->metadata);

    memset(item, 0, sizeof(list_item_t));
}

/**
 * Format tags with brackets and spacing
 */
static void format_tags_with_brackets(
    char **tags,
    size_t tag_count,
    char *buffer,
    size_t buffer_size
) {
    if (!tags || tag_count == 0 || !buffer || buffer_size == 0) {
        if (buffer && buffer_size > 0) {
            buffer[0] = '\0';
        }
        return;
    }

    size_t offset = 0;
    for (size_t i = 0; i < tag_count && offset < buffer_size - 1; i++) {
        if (i > 0 && offset < buffer_size - 1) {
            offset += snprintf(buffer + offset, buffer_size - offset, " ");
        }
        offset += snprintf(buffer + offset, buffer_size - offset,
                          "[%s]", tags[i]);
    }
}

output_list_t *output_list_create(
    output_ctx_t *ctx,
    const char *title,
    const char *hint
) {
    if (!ctx || !title) {
        return NULL;
    }

    output_list_t *list = calloc(1, sizeof(output_list_t));
    if (!list) {
        return NULL;
    }

    list->ctx = ctx;

    list->title = strdup(title);
    if (!list->title) {
        goto cleanup_list;
    }

    if (hint) {
        list->hint = strdup(hint);
        if (!list->hint) {
            goto cleanup_title;
        }
    }

    /* Start with capacity 16 */
    list->capacity = 16;
    list->items = calloc(16, sizeof(list_item_t));
    if (!list->items) {
        goto cleanup_hint;
    }

    return list;

cleanup_hint:
    free(list->hint);
cleanup_title:
    free(list->title);
cleanup_list:
    free(list);
    return NULL;
}

int output_list_add(
    output_list_t *list,
    const char *tag,
    output_color_t color,
    const char *content,
    const char *metadata
) {
    if (!list) {
        return -1;
    }

    /* Grow array if needed (double capacity) */
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity * 2;
        list_item_t *new_items = realloc(list->items,
                                         new_capacity * sizeof(list_item_t));
        if (!new_items) {
            return -1;
        }
        list->items = new_items;
        list->capacity = new_capacity;

        /* Zero out new slots */
        memset(&list->items[list->count], 0,
               (new_capacity - list->count) * sizeof(list_item_t));
    }

    list_item_t *item = &list->items[list->count];

    /* Build single-tag array */
    item->tags = calloc(1, sizeof(char *));
    if (!item->tags) {
        return -1;
    }

    item->tags[0] = tag ? strdup(tag) : strdup("");
    if (!item->tags[0]) {
        goto error;
    }

    item->tag_count = 1;
    item->color = color;

    item->content = content ? strdup(content) : strdup("");
    if (!item->content) {
        goto error;
    }

    if (metadata) {
        item->metadata = strdup(metadata);
        if (!item->metadata) {
            goto error;
        }
    }

    list->count++;
    return 0;

error:
    free_list_item(item);
    return -1;
}

int output_list_add_multi(
    output_list_t *list,
    const char **tags,
    size_t tag_count,
    output_color_t color,
    const char *content,
    const char *metadata
) {
    if (!list) {
        return -1;
    }

    if (tag_count > 0 && !tags) {
        return -1;
    }

    /* Grow array if needed (double capacity) */
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity * 2;
        list_item_t *new_items = realloc(list->items,
                                         new_capacity * sizeof(list_item_t));
        if (!new_items) {
            return -1;
        }
        list->items = new_items;
        list->capacity = new_capacity;

        /* Zero out new slots */
        memset(&list->items[list->count], 0,
               (new_capacity - list->count) * sizeof(list_item_t));
    }

    list_item_t *item = &list->items[list->count];

    /* Build multi-tag array */
    if (tag_count > 0) {
        item->tags = calloc(tag_count, sizeof(char *));
        if (!item->tags) {
            return -1;
        }

        for (size_t i = 0; i < tag_count; i++) {
            item->tags[i] = tags[i] ? strdup(tags[i]) : strdup("");
            if (!item->tags[i]) {
                /* Free previously allocated tags */
                for (size_t j = 0; j < i; j++) {
                    free(item->tags[j]);
                }
                free(item->tags);
                item->tags = NULL;
                goto error;
            }
        }

        item->tag_count = tag_count;
    }

    item->color = color;

    item->content = content ? strdup(content) : strdup("");
    if (!item->content) {
        goto error;
    }

    if (metadata) {
        item->metadata = strdup(metadata);
        if (!item->metadata) {
            goto error;
        }
    }

    list->count++;
    return 0;

error:
    free_list_item(item);
    return -1;
}

void output_list_render(output_list_t *list) {
    if (!list || list->count == 0) {
        return;
    }

    output_ctx_t *ctx = list->ctx;

    if (ctx->verbosity < OUTPUT_NORMAL) {
        return;
    }

    /* Pass 1: Calculate maximum tag width across all items */
    size_t max_tag_width = 0;

    for (size_t i = 0; i < list->count; i++) {
        list_item_t *item = &list->items[i];

        /* Calculate formatted tag width: "[tag1] [tag2] ..." */
        size_t tag_width = 0;
        for (size_t j = 0; j < item->tag_count; j++) {
            tag_width += strlen(item->tags[j]) + 2;  /* +2 for brackets */
            if (j > 0) {
                tag_width += 1;  /* +1 for space separator */
            }
        }

        if (tag_width > max_tag_width) {
            max_tag_width = tag_width;
        }
    }

    /* Pass 2: Render header with count and optional hint */
    if (ctx->color_enabled) {
        fprintf(ctx->stream, "%s%s (%zu item%s)%s",
                ANSI_BOLD, list->title, list->count,
                list->count == 1 ? "" : "s", ANSI_RESET);

        if (list->hint) {
            fprintf(ctx->stream, " %s(%s)%s", ANSI_DIM, list->hint, ANSI_RESET);
        }

        fprintf(ctx->stream, "\n");
    } else {
        fprintf(ctx->stream, "%s (%zu item%s)",
                list->title, list->count, list->count == 1 ? "" : "s");

        if (list->hint) {
            fprintf(ctx->stream, " (%s)", list->hint);
        }

        fprintf(ctx->stream, "\n");
    }

    /* Add blank line between header and items */
    fprintf(ctx->stream, "\n");

    /* Pass 3: Render items with alignment */
    for (size_t i = 0; i < list->count; i++) {
        list_item_t *item = &list->items[i];

        /* Format tags into buffer */
        char tag_buffer[256];
        format_tags_with_brackets(item->tags, item->tag_count,
                                  tag_buffer, sizeof(tag_buffer));

        /* Get color codes */
        const char *color = output_color_code(ctx, item->color);
        const char *dim = output_color_code(ctx, OUTPUT_COLOR_DIM);
        const char *reset = output_color_code(ctx, OUTPUT_COLOR_RESET);

        /* Print: "  [colored tags padded to max_width] content" */
        fprintf(ctx->stream, "  %s%-*s%s %s",
                color,
                (int)max_tag_width,
                tag_buffer,
                reset,
                item->content);

        /* Print metadata if present */
        if (item->metadata) {
            fprintf(ctx->stream, " %s(%s)%s", dim, item->metadata, reset);
        }

        fprintf(ctx->stream, "\n");
    }

    output_newline(ctx);
}

size_t output_list_count(const output_list_t *list) {
    return list ? list->count : 0;
}

void output_list_free(output_list_t *list) {
    if (!list) {
        return;
    }

    if (list->items) {
        for (size_t i = 0; i < list->count; i++) {
            free_list_item(&list->items[i]);
        }
        free(list->items);
    }

    free(list->hint);
    free(list->title);
    free(list);
}
