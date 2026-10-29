/**
 * output.h - Output formatting and styling
 *
 * Provides centralized output formatting with color support, verbosity levels,
 * and different output formats.
 *
 * Layout and data
 * ---------------
 * A format is its author's layout: its literal bytes and {tags} reach the stream
 * as written, newlines included. Every conversion is a datum: a string's or a
 * character's bytes as a terminal may show them (base/string.h str_display), a
 * number as printf writes it. A string handed to output any other way — a list's
 * title, tags and rows — is a datum whole. Bytes as they are reach the stream
 * through output_write alone: a payload the user asked to see verbatim — save
 * show's file text (cmds/show.c show_write), written past the layer because a
 * failed write is the run's error, and output_write returns nothing.
 *
 * A line closes as a message does (base/error.h "Messages"), with no period and
 * no exclamation mark: a question keeps its question mark, and a progress line
 * git's "done." (sys/transfer.h transfer_op_end).
 */

#ifndef DOTTA_OUTPUT_H
#define DOTTA_OUTPUT_H

#include <stdio.h>
#include <types.h>

/**
 * Verbosity levels
 *
 * Quiet keeps what the exit counts: a refusal that counts failures is read with
 * them, so every row it counts prints at OUTPUT_QUIET and names its own subject,
 * since the line above it is the report's and does not print.
 */
typedef enum {
    OUTPUT_QUIET   = 0,   /* Errors alone: the refusal, and every row its exit counts */
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
 * that line writes to (base/output.c `output_land`).
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
 * A report ends on its summary (output_summary, output_success): what the run
 * did, did not do, or found, said at the margin in one block. The block is the
 * summary's from its first line to the next boundary asked, and every line that
 * lands in it is one of its lines, so a summary line said there joins it rather
 * than opening another: a run that sums up several acts says a line an act, and
 * they stand together. A boundary closes it once asked, whether or not the block
 * that asked it prints, so a summary line said after one opens a block of its
 * own. What the run says after its summary stands at the margin too: a caveat a
 * later phase raises, the remedy it calls for (output_hint), a post-hook's account
 * (utils/hooks.h hook_fire_post). So no report ends on a section's or a list's
 * rows, which read as a block still open above whatever follows the run. A run
 * asked for a payload ends where the payload does, its bytes its own
 * (output_write).
 *
 * On a terminal, the line an act draws while it runs (output_progress) is no
 * line of the report: it pays no boundary, owes none, and moves the report nowhere,
 * so what follows it spaces itself against what stood before it, on the row the
 * line held — every line that lands takes it down first. Off a terminal no such
 * line is drawn: a redirected report holds what an act did, never that it ran.
 *
 * Read in base/output.c alone: `output_land` asks what is owed and keeps the
 * summary's block, output_gap asks whether anything stands to owe it, and the
 * summary's two words whether their block stands.
 */
typedef enum {
    OUTPUT_REPORT_START,    /* Nothing of the report stands on `stream` */
    OUTPUT_REPORT_LINE,     /* A line stands; the next one follows it */
    OUTPUT_REPORT_SUMMARY,  /* A line of the summary's block stands; the next one is the block's */
    OUTPUT_REPORT_GAP       /* A line stands; a blank is owed before the next */
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
    bool progress_drawn;        /* A progress line stands on `stream`, the cursor at its end */
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
error_t output_parse_verbosity(const char *word, output_verbosity_t *out);

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
error_t output_parse_color_mode(const char *word, output_color_mode_t *out);

/**
 * Make an output context in place
 *
 * A value its holder keeps — main's, for the process — so nothing frees it: the
 * report starts with nothing standing, and both colour decisions are made for
 * the mode, the report's stream's and stderr's.
 *
 * @param ctx The context (must not be NULL)
 * @param stream Where the report goes (NULL: stdout)
 * @param verbosity The level the run speaks at
 * @param color_mode When colours are written
 */
void output_init(
    output_t *ctx,
    FILE *stream,
    output_verbosity_t verbosity,
    output_color_mode_t color_mode
);

/**
 * Set verbosity level
 *
 * The context is made at OUTPUT_NORMAL, before the configuration is read: main
 * sets the configuration's level once it is, and the dispatcher a spec's -v or
 * -q over it (main.c run_spec).
 */
void output_set_verbosity(output_t *ctx, output_verbosity_t verbosity);

/**
 * Set the colour mode: both decisions made again, the report's stream's and
 * stderr's, as output_init makes them
 *
 * The context is made before the configuration is read, so a failure before it
 * is told in AUTO's colours; main sets the configuration's mode once it is (main.c
 * main).
 */
void output_set_color_mode(output_t *ctx, output_color_mode_t color_mode);

/**
 * Move all subsequent output to another stream
 *
 * For a command that dedicates stdout to a byte payload (export -o -): every
 * line dotta itself says — a warning, a dry-run preview, verbose chatter — moves
 * to the given stream so the payload arrives alone. Color capability is recomputed
 * for the new stream: under AUTO, the payload's pipe and the chatter's tty are
 * different answers. Errors and prompts already live on stderr and are unaffected.
 *
 * A progress line standing on the old stream is taken down there first
 * (output_clear_line). Then the report starts over, because the new stream holds
 * none of it: a boundary owed on the old one is dropped rather than paid somewhere
 * it does not belong, and the first line to land on the new one opens a report
 * with nothing above it.
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
 * Whether the report's stream is a terminal: the medium, asked at the call
 *
 * On a terminal alone a line is drawn while an act runs (output_progress) and
 * taken down once it is done (output_clear_line), as sys/transfer's progress
 * frames are. Not the colours' question: they can be on off a terminal (the
 * configuration's color = "always") and off on one (NO_COLOR, TERM=dumb).
 *
 * @param ctx Output context (false for NULL)
 * @return Whether the report's stream is a terminal
 */
bool output_is_tty(const output_t *ctx);

/**
 * Print with inline style tags and verbosity check
 *
 * The format as it is written — no prefix, and no newline of its own — with {tag}
 * markup for inline coloring, as every formatted emitter here reads its format.
 * Tags are replaced with ANSI codes when colors are enabled, or removed when
 * disabled. Unknown tags pass through literally.
 *
 * Supported tags:
 *   {red}, {green}, {yellow}, {blue}, {magenta}, {cyan}, {white}
 *   {bold}, {dim}
 *   {reset}
 *   {bold;red} (compound tags via semicolon)
 *
 * A style the line leaves open is closed where its text ends, before its own
 * trailing newlines (prevents color bleed). Printf format specifiers (%s, %d,
 * %zu) work normally alongside tags.
 *
 * @param ctx Output context
 * @param min_level Minimum verbosity level
 * @param fmt Format string with optional {tag} markup
 *
 * Example:
 *   output_print(out, OUTPUT_NORMAL, "  {red}✗{reset} %s\n", path);
 *   output_print(out, OUTPUT_NORMAL, "  {cyan}%s{reset} → {cyan}%s{reset}\n", old, new);
 */
void output_print(
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
 * colors, prefer output_print() with {tags} instead.
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
 * Write a payload, as it is
 *
 * Bytes the user asked to see verbatim — a child's output, a file's text, a patch's
 * lines — are not dotta's to spell, so nothing in them is escaped: they land
 * like a line (the owed boundary paid), in `color` where one is given
 * (OUTPUT_COLOR_RESET for none, output_colored's sentinel), closed before the
 * payload's own trailing newlines. Its newlines are its own; nothing is added.
 *
 * @param ctx Output context (NULL-safe, no-op)
 * @param min_level Minimum verbosity level
 * @param color The payload's colour, or OUTPUT_COLOR_RESET for none
 * @param bytes The payload (NULL: no-op)
 * @param len Its length
 */
void output_write(
    output_t *ctx,
    output_verbosity_t min_level,
    output_color_t color,
    const char *bytes,
    size_t len
);

/**
 * Tell a failure
 *
 * The run's refusal, on stderr, ungated, one block written once: "Error: " and
 * the outermost fact, then "  Caused by: " and each fact beneath it (base/error.h
 * error_cause). Every message is a datum, spelled as every %s is ("Layout and
 * data" above), so what one holds is shown on its line and moves nothing. The
 * block lands as every line does — the report flushed, a boundary it owes paid
 * above the block — so a failure is read beneath the partial run it ends; it
 * asks none of its own, and one that follows a complete block prints directly
 * under it.
 *
 * Its callers are main.c's: run_spec for the run's refusal, and main for a word
 * the root does not know, a refused line and the prologue's refusal.
 *
 * @param ctx Output context (NULL: nothing)
 * @param err The failure (NULL: nothing)
 */
void output_error(output_t *ctx, error_t err);

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
 * Say a line of the run's summary: what it did, did not do, or found
 *
 * A line at the margin, ended, in the summary's block ("Where the report stands").
 * The block's first line asks its boundary, as a section's title does (output_gap
 * at `min_level`); a line said while the block stands joins it, whatever landed
 * in it between. So a run that sums up several acts says a line an act, in the
 * order its arms print them, and no printer of a summary asks a boundary for it.
 *
 * The report ends on it. A run of phases may close each with its own (cmds/clone.c
 * cmd_clone), and the last is the run's. A line that tells an act done carries
 * its mark (output_success); what the run did not do, or found, is said plainly,
 * here.
 *
 * @param ctx Output context (NULL: nothing)
 * @param min_level Minimum verbosity level
 * @param fmt The line's format, with no newline (printf-style)
 */
void output_summary(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Say a line of the run's summary that tells an act done: "✓ " before it
 *
 * output_summary's line, in its block and by its rules, marked as an act the
 * run carried out, as a receipt names it: Updated, Removed, Enabled. The mark
 * is the word's, as "Warning: " is output_warning's; a row's ✓ is its format's
 * glyph, as every row's ✗ and = are.
 *
 * @param ctx Output context (NULL: nothing)
 * @param min_level Minimum verbosity level
 * @param fmt The line's format, with no newline (printf-style)
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
 * Print hint message: the remedy, one line, dimmed whole
 *
 * The next step a run calls for, said in one sentence ("Run 'dotta …' to …") at
 * the margin: "Hint: " opens the line, as "Warning: " opens a warning's, and
 * DIM spans the prefix and the body. A format's own leading whitespace lands
 * after the prefix, as it does after every prefix the layer writes.
 *
 * @param ctx Output context
 * @param min_level Minimum verbosity level
 * @param fmt Printf-style format string
 *
 * Example:
 *   output_hint(out, OUTPUT_NORMAL, "Run 'dotta apply' to deploy files");
 *   → "Hint: Run 'dotta apply' to deploy files" (entire line dimmed)
 */
void output_hint(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Print a dimmed line: a hint's voice with no "Hint: ", for what reads beside a
 * block without being its remedy
 *
 * The format as it is written, its leading whitespace included, ended and dimmed
 * whole. A remedy is one line of its own (output_hint); this one is a key beneath
 * the list it keys (cmds/status.c status_print_legend, status_print_profiles'
 * repairs), or the cause a warning gives beneath it (cmds/revert.c cmd_revert's
 * "Reconstructed from the commit …").
 *
 * @param ctx Output context
 * @param min_level Minimum verbosity level
 * @param fmt Printf-style format string
 *
 * Example:
 *   output_hintline(out, OUTPUT_NORMAL, "  %-*s - %s", width, tags, meaning);
 *   → "  [unreadable] - permissions refused the read" (dimmed)
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
 * For a line assembled from several output_print / output_colored calls whose
 * formats carry no trailing newline. Not a separator: output_gap is the boundary
 * between two blocks, and the two were one word until 0.148.7.
 *
 * Its level is the level of the line it ends, which is the level of that line's
 * first part — an endline below its opener writes a bare newline into a run where
 * the line itself never printed.
 *
 * It moves the report nowhere: the line it ends already stands, and a boundary
 * asked mid-line is left standing so the block that follows still pays it — or,
 * if none follows, so nobody does.
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
 * output_list_render, the summary's two words (output_summary, output_success)
 * and the two questions ask theirs inside, so a call site places one only above
 * a block the layer does not recognise as one — a warning, a note, a hint, a
 * row of its own. A function that prints such a block asks it first, as the layer's
 * own blocks do, so no caller asks it for one. Asked while the summary's block
 * stands, it closes the block: the line that pays it opens the next.
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
 * Draw a progress line: on a terminal alone, taken down once its act is done
 *
 * The line an act draws while it runs (a fetch's) is no line of the report: it
 * pays no boundary, owes none, and moves the report nowhere, so the block after
 * it spaces itself against what stood before it. Built as every line is — its
 * format the author's, with no newline, its arguments data — written where the
 * cursor stands, and flushed; over one that stands, from that row's start, the
 * row erased in the same write, as a take-down erases it (output_clear_line).
 * The layer keeps that one stands (output_t's progress_drawn), so every line
 * that lands, on the report's stream or on stderr, takes it down first: a refusal,
 * a warning, a remote's words each stand on a row of their own. Its act's end
 * takes it down. sys/transfer's frames draw over it while objects move, and take
 * their row down when their op ends (sys/transfer.h transfer_op_end). Off a
 * terminal nothing is drawn: a redirected report holds what an act did, never
 * that it ran.
 *
 * Readers: cmds/sync.c sync_fetch, cmds/profile.c profile_fetch, cmds/status.c
 * status_remote.
 *
 * @param ctx Output context (NULL: nothing)
 * @param min_level Minimum verbosity level
 * @param fmt The line's format, with no newline (printf-style)
 */
void output_progress(
    output_t *ctx,
    output_verbosity_t min_level,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Take down the progress line that stands (output_progress), or the frame
 * sys/transfer drew over it on its row: on a terminal, the row erased and the
 * cursor at its start
 *
 * The layer keeps whether one stands, so where none does nothing is written:
 * none drawn below its level, none ever off a terminal — as git's own take-down
 * writes nothing there (lib/git/pager.c term_clear_line) — and none once taken
 * down. A terminal whose TERM declares it reads no escape (unset, "dumb") receives
 * the erase all the same: a stated limit — where it drops the erase, the next
 * line written over the row leaves the row's longer tail beside it, where git
 * pads the row with spaces.
 *
 * Readers: output_progress's three; and the layer's own, before every line that
 * lands (output_land) and before the stream moves (output_set_stream).
 *
 * @param ctx Output context (NULL: nothing)
 */
void output_clear_line(output_t *ctx);

/**
 * Print a patch, one line at a time
 *
 * Each line is written once and ended once: a patch that already ends in a newline
 * leaves no blank line behind it, and an empty one writes nothing. A patch is a
 * payload: each line's bytes are written as they are (output_write). The colour
 * a line carries is read off its origin character — green for an addition, red
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
 * Formats byte sizes into human-readable strings (B, KiB, MiB, GiB). The buffer
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
 * @param path Path to spell, absolute or as a user typed it — only one beneath
 *        `home` changes (must not be NULL)
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
 * What a question came to
 *
 * NONE where nothing answered: stdin at its end before a line, or not a terminal
 * where only a person at one may answer (output_ask_destructive). A question
 * refuses nothing and says nothing of an answer it did not get: its caller decides
 * what the run does without one, and says it.
 */
typedef enum {
    OUTPUT_ANSWER_NONE,   /* Nothing answered */
    OUTPUT_ANSWER_NO,     /* Declined, or the default no */
    OUTPUT_ANSWER_YES     /* Confirmed, or the default yes */
} output_answer_t;

/**
 * Ask a question, answered by the next line of stdin — a terminal's, or a pipe's
 *
 * The question is a format, written as every line's is (output_print): its literal
 * text the author's, each argument a datum. The answer is the line judged whole:
 * y or yes in any case is yes, an empty line the default, anything else no —
 * and the end of input before a line is no answer (OUTPUT_ANSWER_NONE). A
 * question's line no echo closed — an answer a pipe carried, none at all — is
 * closed here, so whatever follows opens a line of its own.
 *
 * A question is a block, so it opens with its own boundary — paid on stderr,
 * where the blank stands above the question on a terminal and never reaches a
 * redirected report. The boundary is asked at OUTPUT_QUIET because a question
 * has no verbosity gate either.
 *
 * @param ctx Output context (NULL: nothing asked, OUTPUT_ANSWER_NONE)
 * @param default_value What an empty line answers (true: yes)
 * @param fmt The question's format (printf-style)
 * @return The answer
 */
output_answer_t output_ask(
    output_t *ctx,
    bool default_value,
    const char *fmt,
    ...
) __attribute__((format(printf, 3, 4)));

/**
 * Ask a destructive question: only a person at a terminal answers one
 *
 * A pipe may carry a line meant for something else — a loop's input — and a closed
 * stdin carries none, so off a terminal nothing is asked and nothing answered
 * (OUTPUT_ANSWER_NONE). At one, a warning stands above the question, whose default
 * is no. Whether to ask at all — a --force, confirm_destructive = false — is
 * the caller's.
 *
 * The warning and the question are one block, so the boundary is asked once above
 * both and paid by the warning; the question goes through no boundary of its own.
 *
 * @param ctx Output context (NULL: nothing asked, OUTPUT_ANSWER_NONE)
 * @param fmt The question's format (printf-style)
 * @return The answer
 */
output_answer_t output_ask_destructive(output_t *ctx, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

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
 *   4. Free: the list is an arena of its own, freed whole
 *
 * A list's lifetime is its printing's, shorter than the command's: a status over
 * 70,000 offers builds 8.6 MB of lists, 6.0 MB of them live at once, which the
 * command's arena would hold to its end (include/runtime.h "Memory"). So a list
 * owns an arena — the struct, its title and hint, its items and every string
 * they copy — and output_list_free gives all of it back at once.
 */
typedef struct output_list output_list_t;

/**
 * Create list builder with section title
 *
 * Creates a new list builder for rendering aligned items. The builder will display
 * a section header with item count and optional hint text.
 *
 * @param ctx Output context (must not be NULL, borrowed reference)
 * @param title Section title (must not be NULL; e.g., "Uncommitted changes")
 * @param hint Optional hint text shown after title (NULL if none)
 * @return List builder; never NULL
 */
output_list_t *output_list_create(
    output_t *ctx,
    const char *title,
    const char *hint
);

/**
 * Add a row: its tags in the row's colour, padded to the widest row's, then its
 * content and its metadata
 *
 * The tags arrive as the row shows them ("[modified] [mode]"): the list prints
 * them, it does not spell them. Every string is copied into the list's arena;
 * the caller keeps its inputs.
 *
 * @param list List builder (must not be NULL)
 * @param tags The row's tags, as it shows them (NULL treated as empty)
 * @param color Color for the tags
 * @param content Main content text (NULL treated as empty)
 * @param metadata Optional metadata shown dimmed in parentheses (NULL if none)
 */
void output_list_add(
    output_list_t *list,
    const char *tags,
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
 * Two passes: the widest row's tags, as they show, then every row, its tags padded
 * to that width. Respects output context verbosity and color settings.
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
 * The list's arena, whole: the builder, its strings and its items. Safe to call
 * with NULL.
 *
 * @param list List builder (NULL-safe)
 */
void output_list_free(output_list_t *list);

#endif /* DOTTA_OUTPUT_H */
