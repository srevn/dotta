/**
 * pathspec.h - The positional path filter
 *
 * Every input compiled into one matcher over the two keys a managed path has
 * (infra/path.h) — its location and its storage path — each entry read against
 * the subject of its own vocabulary. The vocabulary is the input's shape, never
 * an asker's: a filesystem shape is a location, a storage shape or a bare pattern
 * is a name. An exact entry selects the path it names and everything beneath
 * it. A rule — an input holding a glob metacharacter, in gitignore's grammar —
 * is one line of one ordered program: at each rung of the subject, deepest first,
 * the rules in reverse, each against its own vocabulary's subject, and the first
 * to match decides, a negation deciding "not in scope". An exact hit selects
 * whatever any rule says. Every rule stands as typed: the pathspec selects rows
 * and walks nothing, so gitignore's "a parent directory cannot be re-included"
 * — the ruleset's gate, a traversal rule — has no subject here, and each rule
 * is parsed and asked on its own (base/gitignore.h, the rule alone). A
 * filesystem-shaped rule is an anchor and a tail: the components before the first
 * that holds a wildcard are a directory spelling, located and compared literally;
 * the rest is the pattern, rooted there as a `.gitignore` is rooted in its
 * directory. The rungs are the matcher's own walk.
 *
 * NULL semantics: a NULL pathspec matches all paths (no filtering).
 *
 * The pathspec is opaque. The compiled entries are read in insertion order by
 * the coverage answers (diff), which ask each entry alone whether it matches a
 * subject (pathspec_entry_matches_at).
 */

#ifndef DOTTA_PATHSPEC_H
#define DOTTA_PATHSPEC_H

#include <stdbool.h>
#include <stddef.h>
#include <types.h>

typedef struct mount_table mount_table_t;
typedef struct pathspec pathspec_t;

/**
 * One compiled input, as the coverage answers read it: the input as typed, and
 * whether it is a rule. The input is the one honest echo — a location rule is
 * an anchor and a tail and has no one compiled string — and it is what the user
 * wrote. Borrowed; lives with the pathspec.
 */
typedef struct {
    const char *text;
    bool glob;
} pathspec_entry_t;

/**
 * Compile a pathspec from a list of user-provided inputs.
 *
 * An input holding a glob metacharacter ('*', '?', '[') is a rule; any other is
 * an exact entry in the key it names (path_input_resolve: a filesystem shape
 * located through `table`, a storage path validated and kept as typed). Two inputs
 * naming one key — two spellings of one location, one storage path typed twice
 * — are one exact entry; a name beside a location is two, since they are two
 * keys. Rules are never collapsed: their order is their meaning.
 *
 * Glob rules:
 *   - Basename-only globs ("*.vim") match at any depth
 *   - Patterns containing '/' must use storage format (home/, root/, custom/),
 *     start with doublestar (recursive) or single star, or be a filesystem shape
 *     (absolute, tilde, relative dot): the components before the first that holds
 *     a wildcard are a directory, located through `table` and compared literally,
 *     and the rest is the pattern rooted there — `~/<star>.conf` is the conf
 *     files directly under HOME, `~/.config/<star><star>/<star>.lua` every lua
 *     beneath `.config`, `~/myd<star>/` the directories directly under HOME whose
 *     name says so (the trailing '/' is gitignore's directory marker, and the
 *     tail is never normalized). What HOME, the working directory or a declared
 *     alias insert is never pattern syntax; what the user typed past the wildcard
 *     is. A wildcard in the first component is rooted where the first byte says:
 *     `/<star>/etc` at the root, `.<star>/x` at the working directory (a leading
 *     dot is relative, as the resolver reads it); `~<star>/x` is no tilde path
 *     and is refused.
 *   - The shape is read past a leading '!', so a negation is a rule in either
 *     vocabulary
 *   - A pattern that makes no rule — gitignore reads a leading '#' as a comment
 *     — is refused rather than compiled to nothing
 *
 * NULL / empty inputs short-circuit: `*out` is NULL (matches all). A NULL pathspec
 * passed to pathspec_matches matches all paths.
 *
 * `table` must be non-NULL even when no custom mounts are configured — callers
 * without state pass a zero-decl table so HOME and the root sentinel are still
 * available for locating a filesystem shape.
 *
 * The pathspec and everything in it are the arena's; nothing is freed.
 *
 * @param inputs User-provided strings, each NUL-terminated (may be NULL when
 *               count is 0)
 * @param count  Number of inputs
 * @param table  Mount table for locating filesystem shapes (must not be NULL)
 * @param arena  Arena backing the pathspec (must not be NULL, must outlive it)
 * @param out    Pathspec or NULL when inputs were empty (must not be NULL)
 * @return Error or NULL on success
 */
error_t *pathspec_create(
    char *const *inputs,
    size_t count,
    const mount_table_t *table,
    arena_t *arena,
    pathspec_t **out
);

/**
 * Return true when the subject is in the matcher's scope.
 *
 * Every site has both names (a row, an item); a subject the caller has no name
 * for is NULL and is read by no entry of that vocabulary — a delta with no location
 * here (an unbound custom/ claim) is selected by a storage-shaped entry alone.
 *
 * The exact entries first: the location against a location entry, itself or beneath
 * it (an entry of "/" is beneath everything); the storage path against a storage
 * entry likewise, down to its label. An exact hit selects whatever any rule says:
 * two tiers, one policy. Then the rules, one program over both subjects, read
 * rung by rung from the leaf (`kind` says whether the leaf is a directory; every
 * rung above it is): the rules in reverse insertion order, each read at the rung
 * of its own vocabulary — a storage rule the storage rung, a location rule the
 * location rung past its anchor and nothing at or above it — and the first to
 * match decides. In one sentence, the nearest rung at which any rule matches
 * decides, and at that rung the later input wins, a negation deciding "not in
 * scope". The rungs of the two subjects are counted from the leaf — the tail is
 * one tail under two roots — and the storage subject runs out at its label while
 * the location climbs to the root, so `~/etc/<star>.conf` followed by
 * `!<star>.conf` excludes what the first selected whichever vocabulary each is
 * written in, which two rulesets OR'd would have broken. The last storage rung
 * is the label, as gitignore's walk stops at the last component: `*.conf` reaches
 * a conf at any depth, `cache/` a file beneath any cache directory, and a bare
 * rule meets the label itself at the last rung. Beneath a declared alias whose
 * physical depth differs from its spelling's, the rungs above the alias drift
 * apart; each rule still reads its own subject at its own rung, and only a tie
 * between a location rule and a storage rule deciding at one count is then between
 * two directories.
 *
 * `kind` is the manifest's kind of the path (a tracked directory squatted by a
 * file is still a directory): gitignore's directory-only rules (`dir/`) match a
 * directory itself only when the caller says it is one; files beneath it match
 * at the rung above regardless. Never fails: a copy of a subject that cannot be
 * made ends the ascent for both — no vocabulary is read a rung further than the
 * other — and the answer is the leaf's.
 *
 * @param spec         Pathspec (NULL = match all)
 * @param location     The path's location (NULL: no location entry reads it)
 * @param storage_path The path's storage path (NULL: no storage entry reads it)
 * @param kind         What the path refers to in the manifest
 * @return true when matches
 */
bool pathspec_matches(
    const pathspec_t *spec,
    const char *location,
    const char *storage_path,
    path_kind_t kind
);

/**
 * Total number of compiled entries (exact paths + rules).
 *
 * NULL-safe (returns 0 for a NULL pathspec, matching the "no filter" semantics
 * of pathspec_matches).
 */
size_t pathspec_count(const pathspec_t *spec);

/**
 * The entry at index `i`, in insertion order — the i-th input that made an entry,
 * exact duplicates collapsed into the first. `i` MUST be < pathspec_count(spec);
 * out-of-bounds is undefined behaviour (asserted in debug builds).
 */
pathspec_entry_t pathspec_entry_at(const pathspec_t *spec, size_t i);

/**
 * The entry alone, for coverage attribution (diff): an exact entry by equality
 * or ancestry in its vocabulary; a rule by whether it matches the subject of
 * its vocabulary at any rung — either polarity, so a negation that excluded
 * something is not reported as matching nothing. `kind` as for pathspec_matches;
 * a subject the caller has no name for is NULL, and an entry of that vocabulary
 * answers false.
 *
 * Returns false for a NULL pathspec. `i` MUST be < pathspec_count(spec);
 * out-of-bounds is undefined behaviour (asserted in debug builds).
 */
bool pathspec_entry_matches_at(
    const pathspec_t *spec,
    size_t i,
    const char *location,
    const char *storage_path,
    path_kind_t kind
);

#endif /* DOTTA_PATHSPEC_H */
