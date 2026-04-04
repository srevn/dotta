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
 * Verbosity levels
 */
typedef enum {
    OUTPUT_QUIET = 0,   /* Suppress all output except errors */
    OUTPUT_NORMAL = 1,  /* Normal output */
    OUTPUT_VERBOSE = 2  /* Verbose output */
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
    output_verbosity_t verbosity;
    output_color_mode_t color_mode;
    bool color_enabled;         /* Computed from color_mode for stream */
    bool stderr_color_enabled;  /* Computed from color_mode for stderr */
} output_ctx_t;

/**
 * Create output context
 */
output_ctx_t *output_create(
    FILE *stream,
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
 * Set verbosity level
 */
void output_set_verbosity(output_ctx_t *ctx, output_verbosity_t verbosity);

/**
 * Check if colors are enabled for the given context
 */
bool output_colors_enabled(const output_ctx_t *ctx);

/**
 * Check if the output stream is a TTY
 *
 * Returns true if ctx->stream is connected to a terminal.
 * This is distinct from output_colors_enabled():
 *   - colors_enabled can be true on non-TTY (--color=always)
 *   - is_tty can be true with colors disabled (NO_COLOR, TERM=dumb)
 *
 * Use for decisions about ephemeral output (progress indicators,
 * inline status), not for color decisions.
 *
 * @param ctx Output context (returns false if NULL)
 * @return true if ctx->stream is a terminal
 */
bool output_is_tty(const output_ctx_t *ctx);

/**
 * Get color code string
 */
const char *output_color_code(const output_ctx_t *ctx, output_color_t color);

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
 * Print with inline style tags and verbosity check
 *
 * Like output_print() but supports {tag} markup for inline coloring.
 * Tags are replaced with ANSI codes when colors are enabled, or removed
 * when disabled. Unknown tags pass through literally.
 *
 * Supported tags:
 *   {red}, {green}, {yellow}, {blue}, {magenta}, {cyan}, {white}
 *   {bold}, {dim}
 *   {reset}
 *   {bold;red} (compound tags via semicolon)
 *
 * Auto-appends RESET if any color tag was used (prevents color bleed).
 * Printf format specifiers (%s, %d, %zu) work normally alongside tags.
 *
 * @param ctx Output context
 * @param min_level Minimum verbosity level
 * @param fmt Format string with optional {tag} markup
 *
 * Example:
 *   output_styled(out, OUTPUT_NORMAL, "  {red}✗{reset} %s\n", path);
 *   output_styled(out, OUTPUT_NORMAL, "  {cyan}%s{reset} → {cyan}%s{reset}\n", old, new);
 */
void output_styled(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Print with a runtime-determined color wrapping the output
 *
 * Applies `color` to the entire formatted output and auto-resets.
 * Use when the color is determined at runtime (variable output_color_t).
 * For compile-time colors, prefer output_styled() with {tags} instead.
 *
 * When color is OUTPUT_COLOR_RESET, no color wrapping is applied
 * (content prints plain). This allows using RESET as a "no color" sentinel.
 *
 * The format string also supports {tag} markup (routes through the style engine).
 */
void output_colored(
    const output_ctx_t *ctx,
    output_verbosity_t min_level,
    output_color_t color,
    const char *fmt,
    ...
) __attribute__((format(printf, 4, 5)));

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
 * Clear current line and flush (for inline progress)
 *
 * Designed for cleaning up ephemeral progress output (spinners,
 * progress bars, status lines that should vanish when done).
 *
 * TTY: carriage return + ANSI clear line
 * Non-TTY: newline (ANSI clear doesn't work on pipes)
 * Always flushes the stream.
 *
 * @param ctx Output context
 */
void output_clear_line(const output_ctx_t *ctx);

/**
 * Print diff text with line-by-line colorization
 *
 * Parses a unified diff string and applies standard diff colors:
 *   Green  (+): additions (excludes +++ headers)
 *   Red    (-): deletions (excludes --- headers)
 *   Cyan  (@@): hunk headers
 *
 * When colors are disabled, prints the diff text as-is in one call.
 * No-op when ctx or diff_text is NULL.
 *
 * @param ctx Output context (must not be NULL)
 * @param diff_text Unified diff text (NULL-safe, no-op)
 */
void output_print_diff(const output_ctx_t *ctx, const char *diff_text);

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

/**
 * List builder - opaque structure for building aligned lists
 *
 * Provides a generic list rendering utility that automatically calculates
 * alignment based on tag widths. Suitable for any module that needs to
 * display lists of items with variable-width labels.
 *
 * Usage pattern:
 *   1. Create list with title and optional hint
 *   2. Add items with tags, content, and metadata
 *   3. Render (calculates alignment automatically)
 */
typedef struct output_list output_list_t;

/**
 * Create list builder with section title
 *
 * Creates a new list builder for rendering aligned items. The builder
 * will display a section header with item count and optional hint text.
 *
 * @param ctx Output context (must not be NULL, borrowed reference)
 * @param title Section title (e.g., "Uncommitted changes")
 * @param hint Optional hint text shown after title (NULL if none)
 * @return List builder or NULL on allocation failure
 */
output_list_t *output_list_create(
    output_ctx_t *ctx,
    const char *title,
    const char *hint
);

/**
 * Add item to list with tags
 *
 * Adds an item with multiple tags (e.g., ["modified", "mode"]).
 * Tags will be formatted as: [modified] [mode]
 *
 * All strings are copied internally - caller retains ownership of inputs.
 *
 * @param list List builder (must not be NULL)
 * @param tags Array of tag strings (must not be NULL if tag_count > 0)
 * @param tag_count Number of tags
 * @param color Color for the tags
 * @param content Main content text (NULL treated as empty)
 * @param metadata Optional metadata shown dimmed in parentheses (NULL if none)
 * @return 0 on success, -1 on allocation failure
 */
int output_list_add(
    output_list_t *list,
    const char **tags,
    size_t tag_count,
    output_color_t color,
    const char *content,
    const char *metadata
);

/**
 * Render list with auto-calculated alignment
 *
 * Performs two-pass rendering:
 *   Pass 1: Calculate maximum tag width across all items
 *   Pass 2: Render all items with tags aligned to max width
 *
 * Does nothing if list is empty (count == 0).
 * Respects output context verbosity and color settings.
 *
 * @param list List builder (must not be NULL)
 */
void output_list_render(output_list_t *list);

/**
 * Get item count
 *
 * Returns the number of items currently in the list.
 * Useful for conditional rendering (only render if count > 0).
 *
 * @param list List builder (must not be NULL)
 * @return Number of items added to list
 */
size_t output_list_count(const output_list_t *list);

/**
 * Free list builder and all associated memory
 *
 * Frees the list builder and all internal allocations (tags, content,
 * metadata strings). Safe to call with NULL.
 *
 * @param list List builder (NULL-safe)
 */
void output_list_free(output_list_t *list);

#endif /* DOTTA_OUTPUT_H */
