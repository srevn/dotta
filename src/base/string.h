/**
 * string.h - String utility functions
 *
 * Helper functions for common string operations. Strings are read here as strings:
 * no product's grammar lives in this file, so a question whose answer turns on
 * what a word *means* to dotta or to Git belongs with the module that owns the
 * words — a storage name's shape with the labels (infra/label.h, infra/path.h),
 * a commit's with the syntax that spells one (base/refspec.h).
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
 * Is `path` strictly beneath directory `dir`?
 *
 * A prefix and then a separator, so "/a/bc" is not beneath "/a/b" — and neither
 * is "/a/b" itself. strncmp == 0 guarantees `path` has at least dir_len bytes,
 * so reading path[dir_len] is in bounds: it is either the terminator or a real
 * character.
 *
 * `dir` carries no trailing separator — the boundary byte is read at dir_len.
 * `path` is read as written: a prefix and then a separator is beneath, whatever
 * else the spelling holds, so a caller testing an argument before it is folded
 * gets the lexical answer it asked for.
 *
 * @param path Candidate path
 * @param dir Directory path
 * @param dir_len strlen(dir), passed so a caller testing many pairs hoists it
 * @return true if path is strictly beneath dir
 */
bool str_path_beneath(const char *path, const char *dir, size_t dir_len);

/**
 * Length of an absolute path's parent
 *
 * The index of the last separator, or 1 for a path directly beneath the root:
 * "/etc/hosts" → 4, "/etc" → 1 (the root keeps its slash). A path with no separator
 * answers 0 — not absolute, which a caller handed canonical paths never meets
 * and reads as "cannot happen". Pure in the string; whether the parent is there
 * is the caller's question.
 *
 * @param path Canonical absolute path
 * @return The parent's length, or 0 when the path has no separator
 */
size_t str_path_parent_len(const char *path);

/**
 * Join a directory and a name, into an arena
 *
 * One separator at the seam, whatever either side carries there: the directory's
 * trailing separators and the name's leading ones fold into it, so the root joins
 * as every directory does ("/" and "x" is "/x"), and a name spelled from the
 * root joins as a relative one does ("/t" and "/etc/x" is "/t/etc/x" — the
 * re-rooting under add's --target reads it so). Nothing else is folded: a `.`,
 * a `..` or a doubled separator inside either side stands, for str_path_fold.
 *
 * @param arena Arena the joined path lives in (must not be NULL)
 * @param dir Directory (must not be NULL or empty)
 * @param name Name beneath it (must not be NULL or empty)
 * @return The joined path; never NULL
 */
char *str_path_join(arena_t *arena, const char *dir, const char *name);

/**
 * Fold a path, into an arena
 *
 * `.` components and empty ones (a doubled or a trailing separator) go, and a
 * `..` takes the component before it. With `folds` NULL that is the string's
 * reading alone, never the filesystem's, so a `..` after a symlink takes the
 * link's name rather than stepping out of what it reaches — the fold of a key.
 * Where `folds` is given it is asked before each such take, of the fold so far
 * through the component the `..` would take, and a `..` it refuses stays: in
 * place, and a floor no later `..` reaches below — the fold of a path the kernel
 * will open, whose `..` only the kernel can read after a link (sys/filesystem.h
 * fs_make_absolute). An absolute path keeps its root, where a `..` has nothing
 * to take; a relative one keeps the leading `..`s nothing before them takes,
 * and folds to "." when nothing is left. The answer is never longer than the
 * path, and for an absolute one folded whole it is the fold's own spelling
 * (str_path_folded).
 *
 * Examples, `folds` NULL:
 *   /home/user/project/../file   -> /home/user/file
 *   /home/user/./config/         -> /home/user/config
 *   /home/user/../../../etc      -> /etc
 *   ./foo/../bar                 -> bar
 *   ../a/../../b                 -> ../../b
 *   a/..                         -> .
 * and where `folds` refuses "/w/link":
 *   /w/link/../s                 -> /w/link/../s
 *   /w/link/../b/../s            -> /w/link/../s
 *   /w/link/../../s              -> /w/link/../../s
 *
 * @param arena Arena the folded path lives in (must not be NULL)
 * @param path Path (must not be NULL or empty)
 * @param folds Whether a `..` may take the last component of `through`, the fold
 *              so far; NULL, every one may
 * @return The folded path; never NULL
 */
char *str_path_fold(
    arena_t *arena, const char *path, bool (*folds)(const char *through)
);

/**
 * Is this path the fold's own spelling?
 *
 * Absolute, with no empty, `.` or `..` component — "/" or "/a/b": what
 * str_path_fold returns for an absolute input it folds whole, and returns unchanged
 * for one of these. The shape every key has (infra/mount.h): a root's spelling
 * is one, and so is a root's spelling joined with a tail. A relative path answers
 * no whatever it spells — the fold keeps a leading `..` on one, and every reader
 * here asks of an absolute path, which the fold joins a relative one onto first
 * (sys/filesystem.h fs_make_absolute, infra/path.h path_input_filesystem_path).
 * NULL answers no: getenv's answer flows in (sys/filesystem.h
 * fs_working_directory).
 *
 * Pure: no allocation, no filesystem. Readers: the working directory's pwd -L
 * rule (sys/filesystem.h fs_working_directory); a deployment target's shape at
 * the binders and the mount table's own precondition (infra/mount.h
 * mount_validate_target, mount_table_build); and the invoker's HOME, which
 * sys/identity produces by folding rather than asking. The store spells the same
 * rule in its own language on the column that holds a target (core/state.c),
 * and one list of shapes is driven through both (tests/test-mount.c,
 * tests/test-state.c), and through this predicate itself (tests/test-string.c).
 *
 * @param path Path, or NULL
 * @return true iff path is absolute and the fold would return it unchanged
 */
bool str_path_folded(const char *path);

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
 * Readers: base/output.c output_datum (every %s and %c a format carries) and
 * output_list_render (a row's tags, measured).
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
