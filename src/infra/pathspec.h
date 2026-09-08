/**
 * pathspec.h - The positional path filter
 *
 * Every input compiled into one matcher over storage paths. An exact entry — a
 * storage path, or a filesystem shape resolved to one — selects the path it names
 * and everything beneath it. A rule — an input holding a glob metacharacter, in
 * gitignore's grammar — is one line of one ordered program: at each rung of the
 * subject, deepest first, the rules in reverse, and the first to match decides,
 * a negation deciding "not in scope". An exact hit selects whatever any rule
 * says. Every rule stands as typed: the pathspec selects rows and walks nothing,
 * so gitignore's "a parent directory cannot be re-included" — the ruleset's gate,
 * a traversal rule — has no subject here, and each rule is parsed and asked on
 * its own (base/gitignore.h, the rule alone). The rungs are the matcher's own walk.
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
 * One compiled input, as the coverage answers read it: the entry as compiled —
 * the storage path, or the pattern in its storage-space form — and whether it
 * is a rule. Borrowed; lives with the pathspec.
 */
typedef struct {
    const char *text;
    bool glob;
} pathspec_entry_t;

/**
 * Compile a pathspec from a list of user-provided inputs.
 *
 * Inputs may be glob patterns (containing '*', '?', or '['), filesystem paths
 * (resolved through `table` to storage form), or already-storage paths (validated
 * and stored as-is). Two inputs naming one storage path are one exact entry;
 * rules are never collapsed, since their order is their meaning.
 *
 * Glob rules:
 *   - Basename-only globs ("*.vim") match at any depth
 *   - Patterns containing '/' must use storage format (home/, root/, custom/),
 *     start with doublestar (recursive) or single star, or be a filesystem shape
 *     (absolute, tilde, relative dot) — the whole input then rides through the
 *     same resolver as an exact path and compiles in its storage form
 *     ("~/.config/conf" globs become "home/.config/conf" globs); a trailing '/'
 *     (gitignore's directory-only marker) survives the ride
 *   - A pattern that makes no rule — gitignore reads a leading '#' as a comment
 *     — is refused rather than compiled to nothing
 *
 * NULL / empty inputs short-circuit: `*out` is NULL (matches all). A NULL pathspec
 * passed to pathspec_matches matches all paths.
 *
 * `table` must be non-NULL even when no custom mounts are configured — callers
 * without state pass a zero-decl table so HOME and the root sentinel are still
 * available for filesystem-input classification.
 *
 * The pathspec and everything in it are the arena's; nothing is freed.
 *
 * @param inputs User-provided strings, each NUL-terminated (may be NULL when
 *               count is 0)
 * @param count  Number of inputs
 * @param table  Mount table for filesystem-input resolution (must not be NULL)
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
 * Return true when `storage_path` is in the matcher's scope.
 *
 * The exact entries first: the path itself, or one beneath an entry — an entry
 * names a directory and everything under it. An exact hit selects whatever any
 * rule says: two tiers, one policy. Then the rules, one program read rung by
 * rung from the leaf (`kind` says whether the leaf is a directory; every rung
 * above it is): the rules in reverse insertion order, and the first to match
 * decides. In one sentence, the nearest rung at which any rule matches decides,
 * and at that rung the later input wins, a negation deciding "not in scope".
 * The last rung is the label, as gitignore's walk stops at the last component:
 * `*.conf` reaches a conf at any depth, `cache/` a file beneath any cache
 * directory, and a bare rule meets the label itself at the last rung.
 *
 * `kind` is the manifest's kind of the path (a tracked directory squatted by a
 * file is still a directory): gitignore's directory-only rules (`dir/`) match a
 * directory itself only when the caller says it is one; files beneath it match
 * at the rung above regardless. Never fails: a copy of the subject that cannot
 * be made ends the ascent, and the answer is the leaf's.
 *
 * @param spec         Pathspec (NULL = match all)
 * @param storage_path Storage path to test (NULL: false)
 * @param kind         What the path refers to in the manifest
 * @return true when matches
 */
bool pathspec_matches(
    const pathspec_t *spec, const char *storage_path, path_kind_t kind
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
 * or ancestry; a rule by whether it matches the subject at any rung — either
 * polarity, so a negation that excluded something is not reported as matching
 * nothing. `kind` as for pathspec_matches.
 *
 * Returns false for a NULL pathspec or NULL path. `i` MUST be <
 * pathspec_count(spec); out-of-bounds is undefined behaviour (asserted in debug
 * builds).
 */
bool pathspec_entry_matches_at(
    const pathspec_t *spec, size_t i, const char *storage_path, path_kind_t kind
);

#endif /* DOTTA_PATHSPEC_H */
