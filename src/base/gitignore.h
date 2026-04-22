/**
 * gitignore.h - gitignore ruleset parsing and evaluation
 *
 * A self-contained implementation of the `.gitignore` matching grammar
 * with:
 *   - last-match-wins rule ordering
 *   - `!` negation
 *   - directory-only patterns (trailing `/`)
 *   - anchored patterns (leading `/`)
 *   - `**` recursive globs via base/wildmatch
 *   - exact match attribution via per-rule origin tags
 *
 * Lifetime: the ruleset is arena-backed. All memory (rule array, pattern
 * copies) lives until arena_destroy; there is no separate free.
 *
 * Thread safety: concurrent readers of a ruleset are safe once all
 * gitignore_ruleset_append calls have returned. Concurrent appends are
 * not safe.
 */

#ifndef DOTTA_GITIGNORE_H
#define DOTTA_GITIGNORE_H

#include <types.h>

/*
 * Origin tag - an opaque identifier assigned by the caller when
 * appending rules, returned verbatim by gitignore_eval to identify
 * which source decided the match. Dotta uses 0=builtin, 1=baseline,
 * 2=profile; callers are free to choose.
 */
typedef uint8_t gitignore_origin_t;

typedef struct gitignore_ruleset gitignore_ruleset_t;

typedef struct {
    bool decided;                  /* true if any rule matched */
    bool ignored;                  /* winning rule's effect (negation-aware) */
    gitignore_origin_t origin;     /* origin of winning rule */
    size_t rule_index;             /* index in the ruleset (diagnostic) */
} gitignore_match_t;

/**
 * Create an empty ruleset backed by the given arena.
 *
 * @param arena Arena providing storage (borrowed; must outlive ruleset)
 * @param out   Output ruleset pointer (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitignore_ruleset_create(arena_t *arena, gitignore_ruleset_t **out);

/**
 * Parse `content` as a gitignore file and append the resulting rules,
 * each tagged with `origin`. Safe to call repeatedly to layer sources
 * (e.g. baseline then profile).
 *
 * Blank and comment lines are skipped. Empty content is accepted (no
 * rules appended). Returns ERR_VALIDATION if any line exceeds 4096
 * bytes or the cumulative rule count exceeds 10000; ERR_MEMORY on
 * arena exhaustion.
 *
 * @param ruleset Ruleset to append into (must not be NULL)
 * @param content Gitignore source text (must not be NULL; may be empty)
 * @param origin  Caller-chosen origin tag
 * @return Error or NULL on success
 */
error_t *gitignore_ruleset_append(
    gitignore_ruleset_t *ruleset,
    const char *content,
    gitignore_origin_t origin
);

/**
 * Append an array of single-line patterns, each becoming one rule tagged
 * with `origin`. Convenience form for callers holding patterns as an
 * array (CLI flags, config arrays) rather than a gitignore file body.
 *
 * Semantically equivalent to joining `patterns[i]` with '\n' and calling
 * `gitignore_ruleset_append`. NULL entries in the array are skipped.
 * Empty arrays (NULL array or count==0, or all entries NULL) are a
 * successful no-op.
 *
 * Per-pattern length (4096) and cumulative rule count (10000) caps are
 * enforced by the underlying parser; callers are expected to wrap the
 * returned error with caller-specific context (e.g. "Failed to compile
 * CLI exclude patterns").
 *
 * @param ruleset  Ruleset to append into (must not be NULL)
 * @param patterns Array of NUL-terminated pattern strings (may be NULL
 *                 when count == 0; individual entries may be NULL)
 * @param count    Number of entries in patterns
 * @param origin   Caller-chosen origin tag applied to every rule
 * @return Error or NULL on success
 */
error_t *gitignore_ruleset_append_patterns(
    gitignore_ruleset_t *ruleset,
    const char *const *patterns,
    size_t count,
    gitignore_origin_t origin
);

/**
 * Evaluate `path` against the ruleset.
 *
 * `path` is a relative path; leading and trailing slashes are stripped
 * defensively, and a trailing slash is treated as a directory hint.
 * `is_dir` distinguishes files from directories for directory-only
 * rules.
 *
 * Semantics mirror gitignore exactly: rules are scanned in reverse
 * insertion order (last-match-wins). If no rule matches at the given
 * path, the evaluator walks up one directory at a time, re-scanning at
 * each parent (with is_dir=true), which is what makes `cache/` match
 * `cache/file.txt`.
 *
 * Never fails. Always populates every field of *out; decided=false
 * means no rule matched (caller treats as not-ignored).
 *
 * @param ruleset Ruleset (must not be NULL)
 * @param path    Relative path (must not be NULL)
 * @param is_dir  True if path refers to a directory
 * @param out     Match result (must not be NULL)
 */
void gitignore_eval(
    const gitignore_ruleset_t *ruleset,
    const char *path,
    bool is_dir,
    gitignore_match_t *out
);

/**
 * Ignored-verdict shortcut for callers that do not care about origin
 * attribution. Wraps gitignore_eval and returns the last-match-wins
 * boolean — true iff a rule decided the path is ignored.
 *
 * Negation-aware: when the winning rule is `!pattern`, returns false
 * (the path is un-ignored). When no rule matches, returns false.
 *
 * Safe on NULL ruleset or NULL path (returns false). Never fails.
 *
 * @param ruleset Ruleset (can be NULL)
 * @param path    Relative path (can be NULL)
 * @param is_dir  True if path refers to a directory
 * @return true iff the ruleset's verdict is "ignored"
 */
bool gitignore_is_ignored(
    const gitignore_ruleset_t *ruleset,
    const char *path,
    bool is_dir
);

/**
 * Number of rules in the set (diagnostic).
 *
 * @param ruleset Ruleset (can be NULL)
 * @return Rule count, or 0 if ruleset is NULL
 */
size_t gitignore_ruleset_size(const gitignore_ruleset_t *ruleset);

#endif /* DOTTA_GITIGNORE_H */
