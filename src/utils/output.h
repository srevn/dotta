/**
 * output.h - Output formatting and styling
 *
 * Provides centralized output formatting with color support, verbosity
 * levels, and different output formats.
 */

#ifndef DOTTA_OUTPUT_H
#define DOTTA_OUTPUT_H

#include <stdbool.h>
#include <stdio.h>

#include "config.h"  /* For dotta_config_t */

/**
 * Output format types
 */
typedef enum {
    OUTPUT_FORMAT_COMPACT,   /* Compact output (default) */
    OUTPUT_FORMAT_DETAILED,  /* Detailed/verbose output */
    OUTPUT_FORMAT_JSON       /* JSON output for scripting */
} output_format_t;

/**
 * Verbosity levels
 */
typedef enum {
    OUTPUT_QUIET = 0,   /* Suppress all output except errors */
    OUTPUT_NORMAL = 1,  /* Normal output */
    OUTPUT_VERBOSE = 2, /* Verbose output */
    OUTPUT_DEBUG = 3    /* Debug output */
} output_verbosity_t;

/**
 * Color mode
 */
typedef enum {
    OUTPUT_COLOR_AUTO,    /* Auto-detect (based on terminal) */
    OUTPUT_COLOR_ALWAYS,  /* Always use colors */
    OUTPUT_COLOR_NEVER    /* Never use colors */
} output_color_mode_t;

/**
 * Color codes
 */
typedef enum {
    OUTPUT_COLOR_RESET = 0,
    OUTPUT_COLOR_BOLD,
    OUTPUT_COLOR_DIM,
    OUTPUT_COLOR_RED,
    OUTPUT_COLOR_GREEN,
    OUTPUT_COLOR_YELLOW,
    OUTPUT_COLOR_BLUE,
    OUTPUT_COLOR_MAGENTA,
    OUTPUT_COLOR_CYAN,
    OUTPUT_COLOR_WHITE
} output_color_t;

/**
 * Output context
 */
typedef struct {
    FILE *stream;
    output_format_t format;
    output_verbosity_t verbosity;
    output_color_mode_t color_mode;
    bool color_enabled;  /* Computed from color_mode */
} output_ctx_t;

/* ========================================================================
 * Context Management
 * ======================================================================== */

/**
 * Create output context with defaults
 */
output_ctx_t *output_create(void);

/**
 * Create output context with specific settings
 */
output_ctx_t *output_create_with(
    FILE *stream,
    output_format_t format,
    output_verbosity_t verbosity,
    output_color_mode_t color_mode
);

/**
 * Create output context from config
 *
 * Parses config settings and creates output context.
 * Falls back to defaults if config is NULL or parsing fails.
 */
output_ctx_t *output_create_from_config(const dotta_config_t *config);

/**
 * Free output context
 */
void output_free(output_ctx_t *ctx);

/**
 * Set output format
 */
void output_set_format(output_ctx_t *ctx, output_format_t format);

/**
 * Set verbosity level
 */
void output_set_verbosity(output_ctx_t *ctx, output_verbosity_t verbosity);

/**
 * Set color mode
 */
void output_set_color_mode(output_ctx_t *ctx, output_color_mode_t mode);

/* ========================================================================
 * Color Support
 * ======================================================================== */

/**
 * Check if colors are enabled for the given context
 */
bool output_colors_enabled(const output_ctx_t *ctx);

/**
 * Get color code string
 */
const char *output_color_code(const output_ctx_t *ctx, output_color_t color);

/**
 * Apply color to text (returns formatted string, caller must free)
 */
char *output_colorize(
    const output_ctx_t *ctx,
    output_color_t color,
    const char *text
);

/* ========================================================================
 * Formatted Output
 * ======================================================================== */

/**
 * Print with verbosity check
 */
void output_print(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Print error message
 */
void output_error(const output_ctx_t *ctx, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/**
 * Print warning message
 */
void output_warning(const output_ctx_t *ctx, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/**
 * Print success message
 */
void output_success(const output_ctx_t *ctx, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/**
 * Print info message
 */
void output_info(const output_ctx_t *ctx, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/**
 * Print debug message (only shown at DEBUG verbosity)
 */
void output_debug(const output_ctx_t *ctx, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* ========================================================================
 * Structured Output (for status-like displays)
 * ======================================================================== */

/**
 * Print section header
 */
void output_section(const output_ctx_t *ctx, const char *title);

/**
 * Print item with status indicator
 */
void output_item(
    const output_ctx_t *ctx,
    const char *status,
    output_color_t status_color,
    const char *text
);

/**
 * Print key-value pair
 */
void output_kv(
    const output_ctx_t *ctx,
    const char *key,
    const char *value
);

/**
 * Print progress indicator
 */
void output_progress(
    const output_ctx_t *ctx,
    size_t current,
    size_t total,
    const char *item
);

/* ========================================================================
 * JSON Output Helpers
 * ======================================================================== */

/**
 * Begin JSON output
 */
void output_json_begin(const output_ctx_t *ctx);

/**
 * End JSON output
 */
void output_json_end(const output_ctx_t *ctx);

/**
 * Add JSON string field
 */
void output_json_string(
    const output_ctx_t *ctx,
    const char *key,
    const char *value,
    bool last
);

/**
 * Add JSON number field
 */
void output_json_number(
    const output_ctx_t *ctx,
    const char *key,
    long value,
    bool last
);

/**
 * Add JSON boolean field
 */
void output_json_bool(
    const output_ctx_t *ctx,
    const char *key,
    bool value,
    bool last
);

/**
 * Begin JSON array
 */
void output_json_array_begin(const output_ctx_t *ctx, const char *key);

/**
 * End JSON array
 */
void output_json_array_end(const output_ctx_t *ctx, bool last);

#endif /* DOTTA_OUTPUT_H */
