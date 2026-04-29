/**
 * pathspec.h - Path matcher for selective file operations
 *
 * Compiles a heterogeneous mix of user inputs (exact paths, directory
 * prefixes, glob patterns) into a single matcher that decides whether
 * a storage path is in the operation's scope.
 *
 * Supports three input shapes:
 *   1. Exact paths       "home/.bashrc"
 *   2. Directory prefixes "home/.config/fish"  (matches everything under)
 *   3. Glob patterns     "*.vim", "home/<doublestar>/conf"
 *
 * Matching semantics follow gitignore (via base/gitignore): rule
 * ordering, negation, anchoring, and `**` recursive globs.
 *
 * NULL semantics: a NULL pathspec matches all paths (no filtering).
 *
 * The pathspec is opaque. Callers that need to enumerate the compiled
 * entries (e.g. building a libgit2 git_strarray, validating coverage)
 * use the indexed accessors below; the internal layout is private to
 * pathspec.c.
 */

#ifndef DOTTA_PATHSPEC_H
#define DOTTA_PATHSPEC_H

#include <stdbool.h>
#include <stddef.h>
#include <types.h>

typedef struct mount_table mount_table_t;
typedef struct pathspec pathspec_t;

/**
 * Compile a pathspec from a list of user-provided inputs.
 *
 * Inputs may be glob patterns (containing '*', '?', or '['),
 * filesystem paths (resolved through `table` to storage form), or
 * already-storage paths (validated and stored as-is).
 *
 * Glob rules:
 *   - Basename-only globs ("*.vim") match at any depth
 *   - Patterns containing '/' must use storage format (home/, root/,
 *     custom/) or start with doublestar (recursive) or single star
 *
 * NULL / empty inputs short-circuit: `*out` is NULL (matches all). A
 * NULL pathspec passed to pathspec_matches matches all paths.
 *
 * `table` must be non-NULL even when no custom mounts are configured —
 * callers without state pass a zero-decl table so HOME and the root
 * sentinel are still available for filesystem-input classification.
 *
 * @param inputs User-provided strings (may be NULL when count is 0)
 * @param count  Number of inputs
 * @param table  Mount table for filesystem-input resolution (must not be NULL)
 * @param arena  Arena backing the compiled glob storage (must not be NULL,
 *               must outlive the pathspec)
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
 * Lookup order:
 *   1. NULL pathspec -> matches all.
 *   2. Exact match in the exact-path set (O(1)).
 *   3. Walk-up: any ancestor directory in the exact-path set matches.
 *   4. Combined glob ruleset evaluation (gitignore last-match-wins
 *      semantics; honours negation across patterns).
 *
 * @param spec         Pathspec (NULL = match all)
 * @param storage_path Storage path to test (must not be NULL)
 * @return true when matches
 */
bool pathspec_matches(const pathspec_t *spec, const char *storage_path);

/**
 * Free a pathspec. Releases the heap-owned exact-path storage; the
 * arena-borrowed glob storage is reclaimed when the arena is destroyed.
 * Safe with NULL.
 */
void pathspec_free(pathspec_t *spec);

/**
 * Total number of compiled entries (exact paths + glob patterns).
 *
 * NULL-safe (returns 0 for a NULL pathspec, matching the "no filter"
 * semantics of pathspec_matches).
 */
size_t pathspec_count(const pathspec_t *spec);

/**
 * Number of compiled exact paths. NULL-safe (returns 0).
 */
size_t pathspec_exact_count(const pathspec_t *spec);

/**
 * Number of compiled glob patterns. NULL-safe (returns 0).
 */
size_t pathspec_glob_count(const pathspec_t *spec);

/**
 * Exact path at index `i`. The pointer borrows into pathspec storage;
 * its lifetime ends at pathspec_free.
 *
 * Iteration order is stable for a given pathspec but otherwise
 * unspecified.
 *
 * `i` MUST be < pathspec_exact_count(spec). Out-of-bounds is undefined
 * behaviour (asserted in debug builds).
 */
const char *pathspec_exact_at(const pathspec_t *spec, size_t i);

/**
 * Glob pattern (raw user input string) at index `i`. The pointer
 * borrows into pathspec storage; its lifetime ends at pathspec_free.
 *
 * Insertion order: index `i` corresponds to the i-th glob encountered
 * during pathspec_create's input scan.
 *
 * `i` MUST be < pathspec_glob_count(spec). Out-of-bounds is undefined
 * behaviour (asserted in debug builds).
 */
const char *pathspec_glob_at(const pathspec_t *spec, size_t i);

/**
 * Per-pattern isolated match: tests whether the glob at index `i`
 * matches `storage_path` *as if it were the only rule in the ruleset*.
 *
 * Used by filter-coverage validation: a combined-ruleset evaluation
 * folds one pattern's negation (or shadowing) into another's verdict,
 * which under-counts coverage on overlap. Per-pattern isolation gives
 * each input independent attribution.
 *
 * Returns false for a NULL pathspec or NULL path. `i` MUST be <
 * pathspec_glob_count(spec); out-of-bounds is undefined behaviour
 * (asserted in debug builds).
 */
bool pathspec_glob_matches_at(
    const pathspec_t *spec, size_t i, const char *storage_path
);

#endif /* DOTTA_PATHSPEC_H */
