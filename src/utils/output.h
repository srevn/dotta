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

#include "config.h"

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

/**
 * Print hint message (always dimmed when colors enabled)
 *
 * Automatically adds "Hint: " prefix and applies DIM styling to the entire
 * message. Supports printf-style formatting. Respects verbosity (requires
 * OUTPUT_NORMAL). Leading whitespace is preserved for indentation support.
 *
 * @param ctx Output context
 * @param fmt Printf-style format string
 *
 * Examples:
 *   output_hint(out, "Run 'dotta apply' to deploy files");
 *   → "Hint: Run 'dotta apply' to deploy files" (entire line dimmed)
 *
 *   output_hint(out, "  Run 'dotta profile fetch %s' first", name);
 *   → "  Hint: Run 'dotta profile fetch foo' first" (dimmed, indented)
 */
void output_hint(const output_ctx_t *ctx, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/**
 * Print hint continuation line (no "Hint:" prefix, but still dimmed)
 *
 * For multi-line hints where only the first line has "Hint:" prefix.
 * Still applies DIM color and respects verbosity. Use for continuation lines.
 * Leading whitespace is preserved for indentation.
 *
 * @param ctx Output context
 * @param fmt Printf-style format string
 *
 * Example:
 *   output_hint(out, "Create a bootstrap script with:");
 *   output_hint_line(out, "  dotta bootstrap --profile <profile> --edit");
 *   → Output:
 *   "Hint: Create a bootstrap script with:" (dimmed)
 *   "  dotta bootstrap --profile <profile> --edit" (dimmed)
 */
void output_hint_line(const output_ctx_t *ctx, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/**
 * Print newline (respects verbosity)
 *
 * Use this instead of fprintf(out->stream, "\n") for consistent
 * output that respects verbosity settings.
 */
void output_newline(const output_ctx_t *ctx);

/**
 * Print formatted text (respects output context)
 *
 * Use this instead of fprintf(out->stream, ...) or printf(...).
 * Respects verbosity settings and output context.
 *
 * Example:
 *   output_printf(out, "Files: %zu\n", count);
 */
void output_printf(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Print section header
 *
 * Note: Does NOT add leading newline automatically. Use output_newline()
 * before this function to add spacing between sections.
 *
 * Example:
 *   output_section(out, "First Section");      // No leading newline
 *   output_info(out, "content...");
 *
 *   output_newline(out);                       // Add spacing
 *   output_section(out, "Second Section");
 *   output_info(out, "more content...");
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

/**
 * Format file size in human-readable form
 *
 * Formats byte sizes into human-readable strings (B, KB, MB, GB).
 * The buffer must be at least 32 bytes to accommodate all formats.
 *
 * @param bytes Size in bytes
 * @param buffer Output buffer for formatted string
 * @param buffer_size Size of output buffer (minimum 32 bytes)
 */
void output_format_size(size_t bytes, char *buffer, size_t buffer_size);

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

/**
 * Prompt user for confirmation
 *
 * Displays a yes/no prompt and waits for user input. Handles input buffer
 * clearing to prevent pollution. Uses stderr for prompts (standard practice).
 *
 * @param ctx Output context (for color/format settings)
 * @param message Confirmation message to display
 * @param default_value Default if user just presses Enter (true=Y, false=N)
 * @return true if user confirms (y/Y), false otherwise
 *
 * Example:
 *   if (output_confirm(out, "Delete all files?", false)) {
 *       // User confirmed
 *   }
 */
bool output_confirm(
    const output_ctx_t *ctx,
    const char *message,
    bool default_value
);

/**
 * Prompt for confirmation with TTY detection
 *
 * Like output_confirm() but handles non-interactive mode gracefully.
 * When stdin is not a TTY (e.g., piped input, CI/CD), uses the
 * non_interactive_default value and prints a warning or error.
 *
 * @param ctx Output context
 * @param message Confirmation message
 * @param default_value Default for Enter key in interactive mode
 * @param non_interactive_default Return value when not a TTY
 * @return true if confirmed or non_interactive_default if not a TTY
 *
 * Example:
 *   // In sync operations, auto-confirm non-destructive pulls
 *   if (output_confirm_or_default(out, "Pull changes?", true, true)) {
 *       // Proceed
 *   }
 */
bool output_confirm_or_default(
    const output_ctx_t *ctx,
    const char *message,
    bool default_value,
    bool non_interactive_default
);

/**
 * Prompt for destructive operation (checks config)
 *
 * Specialized confirmation for destructive operations. Respects the
 * config->confirm_destructive setting and force_flag. Shows warning
 * before prompting. Always defaults to NO for safety.
 *
 * @param ctx Output context
 * @param config Config (checks confirm_destructive setting, can be NULL)
 * @param message Confirmation message
 * @param force_flag If true, skip confirmation and return true
 * @return true if should proceed, false if user declined
 *
 * Example:
 *   if (output_confirm_destructive(out, config, "Remove all files?", opts->force)) {
 *       // User confirmed or force flag set
 *   }
 */
bool output_confirm_destructive(
    const output_ctx_t *ctx,
    const dotta_config_t *config,
    const char *message,
    bool force_flag
);

#endif /* DOTTA_OUTPUT_H */
