/**
 * string.h - String utility functions
 *
 * Helper functions for common string operations. Strings are read here as strings:
 * no product's grammar lives in this file, so a question whose answer turns on
 * what a word *means* to dotta or to Git belongs with the module that owns the
 * words — a storage name's shape with the labels (infra/label.h, infra/input.h),
 * a commit's with the syntax that spells one (base/refspec.h), a path's with
 * the grammar of its spelling (base/path.h).
 */

#ifndef DOTTA_STRING_H
#define DOTTA_STRING_H

#include <stdbool.h>
#include <stdlib.h>
#include <types.h>

/**
 * Two strings that say the same thing, either of which may be absent
 *
 * NULL is a value here, not a programming error: the fields this compares are
 * optional by design — a claim's owner and group, an item's key — and "neither
 * side has one" is as much an equality as "both say root". Two NULLs are equal,
 * a NULL and a string are not, and strcmp is reached only when both are there.
 *
 * @param a First string (can be NULL)
 * @param b Second string (can be NULL)
 * @return true if both are absent, or both are present and equal
 */
bool str_equal(const char *a, const char *b);

/**
 * Check if string starts with prefix
 *
 * @param str String to check
 * @param prefix Prefix to look for
 * @return true if str starts with prefix
 */
bool str_starts_with(const char *str, const char *prefix);

/**
 * Check if string ends with suffix
 *
 * @param str String to check
 * @param suffix Suffix to look for
 * @return true if str ends with suffix
 */
bool str_ends_with(const char *str, const char *suffix);

/**
 * Trim whitespace from both ends of string (in-place)
 *
 * @param str String to trim (modified in place)
 * @return Pointer to trimmed string (same as input)
 */
char *str_trim(char *str);

/**
 * Join a slice of strings with a delimiter, into an arena
 *
 * The delimiter stands between every two positions; a NULL string is an empty
 * one. A joined length no memory could hold is exhaustion (base/heap.h heap_die).
 * The slice is an argv's type, so a string array's entries and a command's
 * arguments pass without a cast.
 *
 * @param arena Arena the joined string lives in (must not be NULL)
 * @param strings The strings (may be NULL when count is 0)
 * @param count Number of strings
 * @param delimiter Delimiter to insert between strings (NULL is none)
 * @return The joined string, "" for none; never NULL
 */
char *str_join(
    arena_t *arena, char *const *strings, size_t count, const char *delimiter
);

/**
 * A word as a shell reads it back, into an arena
 *
 * For a line the user runs: the word itself where each of its bytes is one every
 * shell reads as itself — a letter, a digit, or one of `_ . / , : @ + -` — and
 * otherwise single-quoted, with each `'` and `\` spelled between the quoted runs
 * as `\'` and `\\`. That is the one spelling sh, bash, zsh and fish all read
 * back byte for byte: fish reads `\'` and `\\` as escapes inside single quotes
 * too, so neither is ever left there. A word with nothing in it is `''`.
 *
 * One expansion is the shell's and stays outside the quotes: a `~` that is the
 * word's first component, alone or before a `/`, which is how output_format_path
 * spells a path beneath HOME — `~/Library/Application Support` reads back as
 * the path it names, `~/'Library/Application Support'`. Any other `~` is quoted.
 *
 * @param arena Arena a quoted word lives in (must not be NULL)
 * @param word  The word (must not be NULL)
 * @return `word` itself where it needs no quotes, else its quoted spelling in
 *         the arena; never NULL
 */
const char *str_shell_quote(arena_t *arena, const char *word);

/**
 * Bytes as a terminal may show them, into a buffer
 *
 * What a datum carries is shown, never sent: every control — C0 but TAB, DEL,
 * and C1 (U+0080–U+009F) — and every byte no well-formed UTF-8 sequence holds
 * is spelled as Git spells a byte it quotes (lib/libgit2/src/util/str.c
 * git_str_quote): \a \b \n \v \f \r by letter, \ooo for every other byte, each
 * byte of a C1 its own (U+009B is \302\233). Everything else is itself: printable
 * ASCII, TAB, a backslash, every well-formed sequence above U+009F. So nothing
 * a datum holds starts a line, moves the cursor or sets a colour, and no two
 * data written side by side join into one control: every byte kept above 0x7f
 * stands inside a whole sequence of its own datum. Not reversible — an authored
 * "\n" and an escaped LF read alike — and idempotent.
 *
 * snprintf's contract: at most `size` bytes, NUL-terminated where size > 0, and
 * the answer is the length the whole spelling needs, so a caller measures with
 * (NULL, 0). A unit that would not fit whole is not begun: a cut answer ends on
 * a whole character or a whole escape.
 *
 * Readers: base/output.c output_datum (every %s and %c a format carries, the
 * editor's rows among them) and output_list_render (a row's tags, measured);
 * infra/commit.c commit_spelled (every name a commit message's template inserts);
 * cmds/completion.c commits_walk (a candidate's description) and cmds/list.c
 * list_profiles and list_files (a verbose row's summary), each cut to its limit.
 *
 * @param dst  Where the spelling goes (may be NULL when size is 0)
 * @param size dst's bytes, its terminator's among them
 * @param src  The bytes (may be NULL when len is 0)
 * @param len  How many
 * @return The whole spelling's length, its terminator not counted
 */
size_t str_display(char *dst, size_t size, const char *src, size_t len);

/**
 * RAII cleanup for strings
 */
static inline void cleanup_string(char **str) {
    if (str && *str) {
        free(*str);
        *str = NULL;
    }
}

#define STRING_CLEANUP __attribute__((cleanup(cleanup_string)))

#endif /* DOTTA_STRING_H */
