/**
 * path.h - The grammar of a path's spelling
 *
 * What a path's bytes say with no filesystem in hand: whether it lies beneath a
 * directory and where it sorts against the paths that do, where its parent ends
 * and its last component begins, how a directory and a name join, and the fold
 * — the one spelling a key has. A path is read as bytes: separators, the root
 * directory — the one directory whose spelling is its separator — and the
 * components between them. Whether anything stands at a path is sys/filesystem's
 * question, where a label lands infra/mount's, what makes a storage name one
 * infra/label's, and the kinds a managed path has are the prelude's
 * (include/types.h).
 */

#ifndef DOTTA_PATH_H
#define DOTTA_PATH_H

#include <types.h>

/**
 * What lies strictly beneath directory `dir` in `path`: the tail past `dir` and
 * the separator that ends it, or NULL where `path` is not beneath it
 *
 * A prefix and then a separator, so "/a/bc" is not beneath "/a/b" — and neither
 * is "/a/b" itself. The root directory is the one directory whose spelling is
 * its separator, so every absolute path but "/" lies beneath "/", its tail past
 * that one byte: "/etc/hosts" beneath "/" is "etc/hosts". strncmp == 0 guarantees
 * `path` has at least dir_len bytes, so reading the byte past them is in bounds:
 * it is either the terminator or a real character.
 *
 * `dir` is a directory as a key spells it: no trailing separator but the root's,
 * which is all it is. `path` is read as written: a prefix and then a separator
 * is beneath, whatever else the spelling holds — "/a/b/" lies beneath "/a/b",
 * its tail empty — so a caller testing an argument before it is folded gets the
 * lexical answer it asked for. A name lies beneath a name alike ("home/x" beneath
 * "home"), and a relative path beneath no absolute directory.
 *
 * NULL is the one answer "not beneath" has, so a caller that wants the test alone
 * reads the answer as one; a search over paths sorted by strcmp reads
 * path_beneath_order, zero exactly where this answers a tail.
 *
 * @param path Candidate path
 * @param dir Directory path
 * @param dir_len strlen(dir), passed so a caller testing many pairs hoists it
 * @return The tail beneath `dir`, aliasing `path`; NULL where it is not beneath
 */
const char *path_beneath(const char *path, const char *dir, size_t dir_len);

/**
 * What lies at or beneath directory `dir` in `path`: "" where `path` is `dir`
 * itself, the tail beneath it otherwise (path_beneath), or NULL where it is neither
 *
 * The inclusive reading of the same boundary: "/a/b" lies under "/a/b" and "/a/bc"
 * does not, and "/" lies under "/" as every absolute path does. The empty tail
 * aliases `path`'s terminator, so every tail starts where `dir`'s spelling ends
 * or just past it: of two directories one path lies under, the deeper one's tail
 * starts further into the path, and pointer order is depth order.
 *
 * @param path Candidate path
 * @param dir Directory path
 * @param dir_len strlen(dir), as path_beneath takes it
 * @return The tail at or beneath `dir`, aliasing `path`; NULL where it is neither
 */
const char *path_under(const char *path, const char *dir, size_t dir_len);

/**
 * Where `path` sorts against the paths beneath directory `dir`: before them,
 * among them, or past them all, by the sign of the answer
 *
 * The order a search needs over paths sorted by strcmp. Every path beneath `dir`
 * opens with one prefix, its spelling and a separator, the root's spelling being
 * its separator already (path_beneath). So those paths sort in one block past
 * the siblings `dir` merely prefixes: "x.bak" before "x/y" and "x0" after, '/'
 * being neither the least byte nor the greatest. The root's own "/", the one
 * path that opens so and lies beneath nothing, sorts before the block. `path`
 * is read as path_beneath reads it, each byte unsigned as strcmp reads it, and
 * sorts where it parts from the prefix; so the answer is zero exactly where
 * path_beneath answers a tail, for any `path` and `dir`, and a lower bound by
 * "negative" finds where the block opens and one by "not positive" where it ends.
 * A name reads as a path does ("home/x" beneath "home").
 *
 * Readers: core/workspace.c workspace_items_beneath (each kind's active items,
 * the orphans: both bounds) and core/deploy.c deploy_reach (the copies beneath
 * a blob row, among the landing's orphans). A reader not on this list is a bug.
 *
 * @param path Candidate path
 * @param dir Directory path
 * @param dir_len strlen(dir), as path_beneath takes it
 * @return Negative where `path` sorts before every path beneath `dir`, zero where
 *         it lies beneath, positive where it sorts past them all
 */
int path_beneath_order(const char *path, const char *dir, size_t dir_len);

/**
 * Length of a path's parent
 *
 * The index of the last separator, or 1 for a path directly beneath the root:
 * "/etc/hosts" → 4, "/etc" → 1 (the root keeps its slash), and "/" → 1, the root
 * directory its own parent. A name reads as a path does: "home/x" → 4, and a
 * component alone, "home", holds no separator and answers 0 — no parent, where
 * a climb up a name stops (infra/pathspec.c rungs_up). Pure in the string; whether
 * the parent is there is the caller's question.
 *
 * @param path A path, absolute or a name
 * @return The parent's length, or 0 when the path has no separator
 */
size_t path_parent_len(const char *path);

/**
 * Length of the parent of the path `path`'s first `len` bytes spell
 *
 * path_parent_len over a prefix, so a climb reads each rung off the key's own
 * bytes by its length and copies nothing (base/hashmap.h hashmap_get_n): "/a/b/c"
 * over 6, 4, 2 and 1 answers 4, 2, 1 and 1 — the root directory is its own parent,
 * so the climb stops where the length stops shrinking.
 *
 * @param path A path at least `len` bytes long
 * @param len The span of `path` asked about
 * @return The parent's length, or 0 when the span has no separator
 */
size_t path_parent_len_n(const char *path, size_t len);

/**
 * A path's last component
 *
 * What follows the last separator, or the path itself where it holds none:
 * "/etc/hosts" → "hosts", "/etc" → "etc", and a name reads as a path does,
 * "hosts/mbp" → "mbp" and "home" → "home". The other half of the split
 * path_parent_len measures: a path parts at its last separator, the parent ending
 * before it — or keeping it, where the parent is the root directory, whose spelling
 * is its separator — and the last component starting past it. Read as written,
 * as the family reads a path: a trailing separator is the last one, and nothing
 * follows it — "a/b/" and "/" answer "", where basename(3) sheds the separator
 * and answers "b" and "/". The last component as git reads one (lib/git/dir.c
 * last_matching_pattern), which base/gitignore.c's port asks here. Pure in the
 * string: nothing is copied, and nothing written.
 *
 * @param path A path, absolute or a name
 * @return The last component, aliasing `path`; "" where a separator ends it
 */
const char *path_basename(const char *path);

/**
 * Join a directory and a name, into an arena
 *
 * One separator at the seam, whatever either side carries there: the directory's
 * trailing separators and the name's leading ones fold into it, so the root joins
 * as every directory does ("/" and "x" is "/x"), and a name spelled from the
 * root joins as a relative one does ("/t" and "/etc/x" is "/t/etc/x" — the
 * re-rooting under add's --target reads it so). A name of separators alone is
 * no empty side: its separators are the seam's, and the join is the directory
 * and that one separator ("/a" and "/" is "/a/", which a home spelled "~//" reaches
 * through sys/filesystem.h fs_expand_tilde). Nothing else is folded: a `.`, a
 * `..` or a doubled separator inside either side stands, for path_fold.
 *
 * @param arena Arena the joined path lives in (must not be NULL)
 * @param dir Directory (must not be NULL or empty)
 * @param name Name beneath it (must not be NULL or empty)
 * @return The joined path; never NULL
 */
char *path_join(arena_t *arena, const char *dir, const char *name);

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
 * (path_folded).
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
char *path_fold(
    arena_t *arena, const char *path, bool (*folds)(const char *through)
);

/**
 * Is this path the fold's own spelling?
 *
 * Absolute, with no empty, `.` or `..` component — "/" or "/a/b": what path_fold
 * returns for an absolute input it folds whole, and returns unchanged for one
 * of these. The shape every key has (infra/mount.h): a root's spelling is one,
 * and so is a root's spelling joined with a tail. A relative path answers no
 * whatever it spells — the fold keeps a leading `..` on one, and every reader
 * here asks of an absolute path, which the fold joins a relative one onto first
 * (sys/filesystem.h fs_make_absolute, infra/input.h input_filesystem_path). NULL
 * answers no: getenv's answer flows in (sys/filesystem.h fs_working_directory).
 *
 * Pure: no allocation, no filesystem. Readers: the working directory's pwd -L
 * rule (sys/filesystem.h fs_working_directory); a deployment target's shape at
 * the binders and the mount table's own precondition (infra/mount.h
 * mount_validate_target, mount_table_build); and the invoker's HOME, which
 * sys/identity produces by folding rather than asking. The store spells the same
 * rule in its own language on the column that holds a target (core/state.c),
 * and one list of shapes is driven through both (tests/test-mount.c,
 * tests/test-state.c), and through this predicate itself (tests/test-path.c).
 *
 * @param path Path, or NULL
 * @return true iff path is absolute and the fold would return it unchanged
 */
bool path_folded(const char *path);

#endif /* DOTTA_PATH_H */
