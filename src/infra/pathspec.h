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
 */

#ifndef DOTTA_PATHSPEC_H
#define DOTTA_PATHSPEC_H

#include <stdbool.h>
#include <stddef.h>
#include <types.h>

/* Forward declarations — keep this header light. */
typedef struct mount_table mount_table_t;
typedef struct gitignore_ruleset gitignore_ruleset_t;
struct hashmap;

/**
 * Compiled path matcher.
 *
 * The struct is intentionally visible so the few consumers that need
 * to inspect the matcher's internals (cmds/diff.c builds libgit2
 * pathspecs from the same data) can do so without a fan-out of
 * accessors. New consumers should prefer pathspec_matches.
 *
 * Storage layout:
 *   - exact_paths is heap-owned; lifetime ends at pathspec_free.
 *   - glob_ruleset and glob_patterns are arena-borrowed; their
 *     lifetime is the arena passed to pathspec_create. The arena MUST
 *     outlive the pathspec, otherwise the glob fields dangle.
 *
 * (Lifetime hazard noted as observation: pathspec mixes heap + arena
 * ownership. A future cleanup may move the entire structure into the
 * arena and reduce pathspec_free to a no-op.)
 */
typedef struct {
    struct hashmap *exact_paths;         /* heap-owned; O(1) lookup */
    gitignore_ruleset_t *glob_ruleset;   /* arena-borrowed; NULL when glob_count == 0 */
    char **glob_patterns;                /* arena-borrowed; raw strings for diagnostics */
    size_t glob_count;                   /* number of glob patterns */
    size_t count;                        /* total entries (exact + globs) */
} pathspec_t;

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
 * @param arena  Arena backing the compiled glob ruleset (must not be NULL)
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
 *   2. Exact match in `exact_paths` (O(1)).
 *   3. Walk-up: any ancestor directory in `exact_paths` matches.
 *   4. Glob ruleset evaluation (gitignore semantics).
 *
 * @param spec         Pathspec (NULL = match all)
 * @param storage_path Storage path to test (must not be NULL)
 * @return true when matches
 */
bool pathspec_matches(const pathspec_t *spec, const char *storage_path);

/**
 * Free a pathspec. Releases the heap-owned exact_paths hashmap; the
 * arena-borrowed glob fields are reclaimed when the arena is destroyed.
 * Safe with NULL.
 */
void pathspec_free(pathspec_t *spec);

#endif /* DOTTA_PATHSPEC_H */
