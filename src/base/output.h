/**
 * output.h - Output formatting and styling
 *
 * Provides centralized output formatting with color support, verbosity levels,
 * and different output formats.
 */

#ifndef DOTTA_OUTPUT_H
#define DOTTA_OUTPUT_H

#include <stdio.h>
#include <types.h>

/**
 * Verbosity levels
 */
typedef enum {
    OUTPUT_QUIET   = 0,   /* Suppress all output except errors */
    OUTPUT_NORMAL  = 1,   /* Normal output */
    OUTPUT_VERBOSE = 2    /* Verbose output */
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
 * Where the report stands on its stream
 *
 * A report is a sequence of blocks on `stream`: between two blocks there is exactly
 * one blank line, before the first and after the last there is none. No block
 * knows whether another follows it, so no block writes that separator — it *owes*
 * one (output_gap), and the next line that lands pays it, on whatever stream
 * that line writes to (base/output.c `land`).
 *
 * Three guarantees fall out of that, and none of them needs a call site to reason
 * about its neighbours. A debt nobody pays writes nothing, so a report cannot
 * end in a blank line. A debt asked before any line stands is refused, so a report
 * cannot begin with one. A debt asked twice is one debt, so a block and whatever
 * precedes it may each ask for the boundary between them without knowing of the
 * other.
 *
 * The position is the report's alone. A failure or a question on stderr settles
 * a standing debt there — the blank lands above the block it belongs to on a
 * terminal, and a redirected report keeps no blank it never earned — but neither
 * makes the report stand: a run whose first line is a failure opens no report
 * to separate from. Moving the report to another stream (output_set_stream) starts
 * it over, because the new stream holds none of it.
 *
 * Read in two places, both in base/output.c: `land` asks what is owed, and
 * output_gap asks whether anything stands to owe it.
 */
typedef enum {
    OUTPUT_REPORT_START,  /* Nothing of the report stands on `stream` */
    OUTPUT_REPORT_LINE,   /* A line stands; the next one follows it */
    OUTPUT_REPORT_GAP     /* A line stands; a blank is owed before the next */
} output_report_t;

/**
 * Output context
 */
typedef struct output {
    FILE *stream;
    output_verbosity_t verbosity;
    output_color_mode_t color_mode;
    bool color_enabled;         /* Computed from color_mode for stream */
    bool stderr_color_enabled;  /* Computed from color_mode for stderr (errors, prompts) */
    output_report_t report;     /* Where the report stands on `stream` */
} output_t;

/**
 * The verbosity a word names: "quiet", "normal" or "verbose".
 *
 * An unknown word is refused (ERR_INVALID_ARG) with the three it could be. Its
 * reader is the configuration's [output] verbosity, read at load (utils/config),
 * which names the key around the refusal.
 *
 * @param word The word (must not be NULL)
 * @param out  The verbosity (must not be NULL)
 * @return Error or NULL on success
 */
error_t *output_parse_verbosity(const char *word, output_verbosity_t *out);

/**
 * The color mode a word names: "auto", "always" or "never".
 *
 * An unknown word is refused (ERR_INVALID_ARG) with the three it could be. Its
 * reader is the configuration's [output] color, read at load (utils/config),
 * which names the key around the refusal.
 *
 * @param word The word (must not be NULL)
 * @param out  The color mode (must not be NULL)
 * @return Error or NULL on success
 */
error_t *output_parse_color_mode(const char *word, output_color_mode_t *out);

/**
 * Create output context
 */
output_t *output_create(
    FILE *stream,
    output_verbosity_t verbosity,
    output_color_mode_t color_mode
);

/**
 * Free output context
 */
void output_free(output_t *ctx);

/**
 * Set verbosity level
 */
void output_set_verbosity(output_t *ctx, output_verbosity_t verbosity);

/**
 * Move all subsequent output to another stream
 *
 * For a command that dedicates stdout to a byte payload (export -o -): every
 * line dotta itself says — a warning, a dry-run preview, verbose chatter — moves
 * to the given stream so the payload arrives alone. Color capability is recomputed
 * for the new stream: under AUTO, the payload's pipe and the chatter's tty are
 * different answers. Errors and prompts already live on stderr and are unaffected.
 *
 * The report starts over, because the new stream holds none of it: a boundary
 * owed on the old one is dropped rather than paid somewhere it does not belong,
 * and the first line to land on the new one opens a report with nothing above it.
 */
void output_set_stream(output_t *ctx, FILE *stream);

/**
 * Check if verbose output is enabled
 *
 * NULL-safe: returns false if ctx is NULL.
 */
static inline bool output_is_verbose(const output_t *ctx) {
    return ctx && ctx->verbosity >= OUTPUT_VERBOSE;
}

/**
 * Check if colors are enabled for the given context
 */
bool output_colors_enabled(const output_t *ctx);

/**
 * Check if the output stream is a TTY
 *
 * Returns true if ctx->stream is connected to a terminal. This is distinct from
 * output_colors_enabled():
 *   - colors_enabled can be true on non-TTY (--color=always)
 *   - is_tty can be true with colors disabled (NO_COLOR, TERM=dumb)
 *
 * Use for decisions about ephemeral output (progress indicators, inline status),
 * not for color decisions.
 *
 * @param ctx Output context (returns false if NULL)
 * @return true if ctx->stream is a terminal
 */
bool output_is_tty(const output_t *ctx);

/**
 * Get color code string
 */
const char *output_color_code(const output_t *ctx, output_color_t color);

/**
 * Print with verbosity check
 */
void output_print(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Print with inline style tags and verbosity check
 *
 * Like output_print() but supports {tag} markup for inline coloring. Tags are
 * replaced with ANSI codes when colors are enabled, or removed when disabled.
 * Unknown tags pass through literally.
 *
 * Supported tags:
 *   {red}, {green}, {yellow}, {blue}, {magenta}, {cyan}, {white}
 *   {bold}, {dim}
 *   {reset}
 *   {bold;red} (compound tags via semicolon)
 *
 * Auto-appends RESET if any color tag was used (prevents color bleed). Printf
 * format specifiers (%s, %d, %zu) work normally alongside tags.
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
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Print with a runtime-determined color wrapping the output
 *
 * Applies `color` to the entire formatted output and auto-resets. Use when the
 * color is determined at runtime (variable output_color_t). For compile-time
 * colors, prefer output_styled() with {tags} instead.
 *
 * When color is OUTPUT_COLOR_RESET, no color wrapping is applied (content prints
 * plain). This allows using RESET as a "no color" sentinel.
 *
 * The format string also supports {tag} markup (routes through the style engine).
 */
void output_colored(
    output_t *ctx,
    output_verbosity_t min_level,
    output_color_t color,
    const char *fmt,
    ...
) __attribute__((format(printf, 4, 5)));

/**
 * Print error message
 *
 * The terminal failure: stderr, no verbosity gate, and the report is flushed
 * first so it lands after the partial run it ends. A boundary the report owes
 * is paid here rather than left standing, but an error asks none of its own:
 * one that follows a complete block prints directly under it.
 */
void output_error(output_t *ctx, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

/**
 * Print warning message
 *
 * A line of the report, prefixed "Warning: " — same destination and same color
 * decision as the section, list or hint it belongs with.
 */
void output_warning(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Print success message
 */
void output_success(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Print info message
 */
void output_info(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Print hint message (always dimmed when colors enabled)
 *
 * Automatically adds "Hint: " prefix and applies DIM styling to the entire message.
 * Supports printf-style formatting. Leading whitespace is preserved for indentation
 * support.
 *
 * @param ctx Output context
 * @param min_level Minimum verbosity level
 * @param fmt Printf-style format string
 *
 * Examples:
 *   output_hint(out, OUTPUT_NORMAL, "Run 'dotta apply' to deploy files");
 *   → "Hint: Run 'dotta apply' to deploy files" (entire line dimmed)
 *
 *   output_hint(out, OUTPUT_NORMAL, "  Run 'dotta profile fetch %s' first", name);
 *   → "  Hint: Run 'dotta profile fetch foo' first" (dimmed, indented)
 */
void output_hint(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Print hint continuation line (no "Hint:" prefix, but still dimmed)
 *
 * For multi-line hints where only the first line has "Hint:" prefix. Still applies
 * DIM color and respects verbosity. Use for continuation lines. Leading whitespace
 * is preserved for indentation.
 *
 * @param ctx Output context
 * @param min_level Minimum verbosity level
 * @param fmt Printf-style format string
 *
 * Example:
 *   output_hint(out, OUTPUT_NORMAL, "Create a bootstrap script with:");
 *   output_hintline(out, OUTPUT_NORMAL, "  dotta bootstrap --profile <profile> --edit");
 *   → Output: "Hint: Create a bootstrap script with:" (dimmed)
 *   "  dotta bootstrap --profile <profile> --edit" (dimmed)
 */
void output_hintline(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * End the line this code is building
 *
 * For a line assembled from several output_print / output_styled / output_colored
 * calls whose formats carry no trailing newline. Not a separator: output_gap is
 * the boundary between two blocks, and the two were one word until 0.148.7.
 *
 * Its level is the level of the line it ends, which is the level of that line's
 * first part — an endline below its opener writes a bare newline into a run where
 * the line itself never printed.
 *
 * Alone among the words that write, it moves the report nowhere: the line it
 * ends already stands, and a boundary asked mid-line is left standing so the
 * block that follows still pays it — or, if none follows, so nobody does.
 *
 * @param ctx Output context
 * @param min_level Minimum verbosity level
 */
void output_endline(output_t *ctx, output_verbosity_t min_level);

/**
 * A block boundary belongs here
 *
 * Records that a blank line is owed; writes nothing. The next line that lands
 * pays it — on whatever stream that line lands, so a question pays it on stderr
 * — and a line that never comes pays nothing. Refused while no line of the report
 * stands, so a boundary at the top of a run is silent; idempotent, so a block
 * and whatever precedes it may both ask for the one between them.
 *
 * The level is the block's own. A boundary at OUTPUT_VERBOSE before a verbose
 * trace line is not owed in a normal run, so the normal block that follows spaces
 * itself against what actually printed rather than against what would have.
 *
 * Every block opens with its boundary and no block closes with one. output_section,
 * output_list_render and the three prompts ask theirs inside, so a call site
 * places one only above a block the layer does not recognise as one — a verdict
 * line, a warning, a hint, a row of its own.
 *
 * @param ctx Output context
 * @param min_level Minimum verbosity level
 */
void output_gap(output_t *ctx, output_verbosity_t min_level);

/**
 * Print section header
 *
 * Supports printf-style format strings for dynamic titles. Opens with its own
 * boundary (output_gap at `min_level`), so a section is separated from whatever
 * stands above it — another section, a plain line, a hint — and from nothing at
 * all when it is the report's first. A section the verbosity suppresses asks
 * for none, so the block that follows spaces itself against what printed.
 *
 * @param ctx Output context
 * @param min_level Minimum verbosity level
 * @param fmt Printf-style format string
 *
 * Example:
 *   output_section(out, OUTPUT_NORMAL, "First Section");
 *   output_section(out, OUTPUT_NORMAL, "Second Section");
 */
void output_section(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Clear current line and flush (for inline progress)
 *
 * Designed for cleaning up ephemeral progress output (spinners, progress bars,
 * status lines that should vanish when done).
 *
 * TTY: carriage return + ANSI clear line Non-TTY: newline (ANSI clear doesn't
 * work on pipes) Always flushes the stream.
 *
 * @param ctx Output context
 */
void output_clear_line(output_t *ctx);

/**
 * Print a patch, one line at a time
 *
 * Each line is written once and ended once: a patch that already ends in a newline
 * leaves no blank line behind it, and an empty one writes nothing. The colour a
 * line carries is read off its origin character — green for an addition, red
 * for a deletion, cyan for a hunk header, none for a `---` or `+++` file header,
 * whose second byte repeats its first. It changes a line's bytes and never their
 * number: the patch a pipe reads and the one a terminal reads have the same shape.
 *
 * @param ctx Output context (NULL-safe, no-op)
 * @param min_level Minimum verbosity level
 * @param diff_text Unified diff text (NULL or empty: no-op)
 */
void output_print_diff(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *diff_text
);

/**
 * Format file size in human-readable form
 *
 * Formats byte sizes into human-readable strings (B, KB, MB, GB). The buffer
 * must be at least 32 bytes to accommodate all formats.
 *
 * @param bytes Size in bytes
 * @param buffer Output buffer for formatted string
 * @param buffer_size Size of output buffer (minimum 32 bytes)
 */
void output_format_size(size_t bytes, char *buffer, size_t buffer_size);

/**
 * Format a count of files and directories in one phrase
 *
 * "3 files, 2 directories" — naming only the kinds that are actually there, so
 * a set of two directories reads as "2 directories" rather than as "0 files"
 * with a rider, and "empty" when there is nothing of either kind. Always writes
 * a non-empty phrase.
 *
 * The phrase, not its frame: callers put it in parentheses after a name, in a
 * padded column, or on a line of its own, and none of them has to agree about
 * anything but the words. 64 bytes is enough for any pair of counts.
 *
 * @param files Number of files
 * @param directories Number of directories
 * @param buffer Output buffer for the phrase
 * @param buffer_size Size of output buffer (minimum 64 bytes)
 */
void output_format_counts(
    size_t files,
    size_t directories,
    char *buffer,
    size_t buffer_size
);

/**
 * Spell a filesystem path the way the shell prints it: `~` for a leading `home`
 *
 * `home` itself reads as `~`, a path beneath it as `~/<rest>`, and every other
 * path as it is — a sibling of `home` with the same leading bytes is not beneath
 * it, so the match stops at a component boundary. Pure string work: `home` is
 * passed in because the base layer reads no identity, and every reader passes
 * the invoker's: the screens that print a bound target (profile list, status,
 * the interactive rows, disable's receipt, add's label line), and the sentences
 * that name a path beside its names — status's unused-path listing, where the
 * path is the shared term of three paths on one line and the absolute spelling
 * would be the longest of them, and add's and revert's refusals that say which
 * name a path has. A screen listing managed paths one to a line prints them
 * absolute and does not come here. PATH_MAX bytes hold any path the table
 * validated.
 *
 * @param path Absolute path to spell (must not be NULL)
 * @param home The directory `~` stands for (must not be NULL; no trailing slash)
 * @param buffer Output buffer for the spelling
 * @param buffer_size Size of output buffer
 */
void output_format_path(
    const char *path,
    const char *home,
    char *buffer,
    size_t buffer_size
);

/**
 * Prompt user for confirmation
 *
 * Displays a yes/no prompt and waits for user input. Handles input buffer clearing
 * to prevent pollution. Uses stderr for prompts (standard practice).
 *
 * A question is a block, so it opens with its own boundary — paid on stderr,
 * where the blank stands above the question on a terminal and never reaches a
 * redirected report. The boundary is asked at OUTPUT_QUIET because a prompt has
 * no verbosity gate either.
 *
 * @param ctx Output context (for color/format settings)
 * @param message Confirmation message to display
 * @param default_value Default if user just presses Enter (true=Y, false=N)
 * @return true if user confirms (y/Y), false otherwise
 */
bool output_confirm(
    output_t *ctx,
    const char *message,
    bool default_value
);

/**
 * Prompt for confirmation with TTY detection
 *
 * Like output_confirm() but handles non-interactive mode gracefully. When stdin
 * is not a TTY (e.g., piped input, CI/CD), uses the non_interactive_default value
 * and prints a warning or error.
 *
 * Both arms are the same block, so the boundary is asked once above the branch.
 * The interactive arm delegates to output_confirm, which asks again — and that
 * second ask is the idempotency clause earning its place: one debt, one blank.
 *
 * @param ctx Output context
 * @param message Confirmation message
 * @param default_value Default for Enter key in interactive mode
 * @param non_interactive_default Return value when not a TTY
 * @return true if confirmed or non_interactive_default if not a TTY
 */
bool output_confirm_or_default(
    output_t *ctx,
    const char *message,
    bool default_value,
    bool non_interactive_default
);

/**
 * Prompt for destructive operation
 *
 * Specialized confirmation for destructive operations. Shows warning before
 * prompting. Always defaults to NO for safety.
 *
 * The warning and the question are one block, so the boundary is asked once above
 * both and paid by whichever lands first — the warning on the interactive path,
 * the refusal on the other. Only the code here knows they are one block, which
 * is why the question it asks goes through no boundary of its own.
 *
 * @param ctx Output context
 * @param confirm_destructive Whether to require confirmation (false = skip prompt)
 * @param message Confirmation message
 * @param force_flag If true, skip confirmation and return true
 * @return true if should proceed, false if user declined
 */
bool output_confirm_destructive(
    output_t *ctx,
    bool confirm_destructive,
    const char *message,
    bool force_flag
);

/**
 * List builder - opaque structure for building aligned lists
 *
 * Provides a generic list rendering utility that automatically calculates alignment
 * based on tag widths. Suitable for any module that needs to display lists of
 * items with variable-width labels.
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
 * Creates a new list builder for rendering aligned items. The builder will display
 * a section header with item count and optional hint text.
 *
 * @param ctx Output context (must not be NULL, borrowed reference)
 * @param title Section title (e.g., "Uncommitted changes")
 * @param hint Optional hint text shown after title (NULL if none)
 * @return List builder or NULL on allocation failure
 */
output_list_t *output_list_create(
    output_t *ctx,
    const char *title,
    const char *hint
);

/**
 * Add item to list with tags
 *
 * Adds an item with multiple tags (e.g., ["modified", "mode"]). Tags will be
 * formatted as: [modified] [mode]
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
 * Opens with its own boundary (output_gap), so a list is separated from whatever
 * stands above it. The blank between its title and its first row is the list's
 * shape rather than a boundary, and is written either way. An empty list asks
 * for nothing and writes nothing.
 *
 * Performs two-pass rendering:
 *   Pass 1: Calculate maximum tag width across all items Pass 2: Render all items
 *   with tags aligned to max width
 *
 * Does nothing if list is empty (count == 0). Respects output context verbosity
 * and color settings.
 *
 * @param list List builder (must not be NULL)
 */
void output_list_render(output_list_t *list);

/**
 * Get item count
 *
 * Returns the number of items currently in the list. Useful for conditional
 * rendering (only render if count > 0).
 *
 * @param list List builder (must not be NULL)
 * @return Number of items added to list
 */
size_t output_list_count(const output_list_t *list);

/**
 * Free list builder and all associated memory
 *
 * Frees the list builder and all internal allocations (tags, content, metadata
 * strings). Safe to call with NULL.
 *
 * @param list List builder (NULL-safe)
 */
void output_list_free(output_list_t *list);

#endif /* DOTTA_OUTPUT_H */
