/**
 * gitignore.h - gitignore ruleset parsing and evaluation
 *
 * A self-contained implementation of the `.gitignore` matching grammar with:
 *   - last-match-wins rule ordering
 *   - `!` negation
 *   - directory-only patterns (trailing `/`)
 *   - anchored patterns (leading `/`)
 *   - `**` recursive globs via base/wildmatch
 *   - exact match attribution via per-rule origin tags
 *
 * The ruleset is the whole grammar: the gate at parse (a non-wildcard negation
 * no earlier rule could match is dropped — git's "a parent directory cannot be
 * re-included"), the reverse scan at a rung, and the walk up the ancestors until
 * one rung decides (`gitignore_eval`). A rule is one line of it, parsed and asked
 * alone (`gitignore_rule_t`, at the end of this header), for a caller whose program
 * is its own — infra/pathspec, which reads its rules in its own order and walks
 * the rungs itself.
 *
 * Lifetime: the ruleset and every rule are arena-backed. All memory (rule array,
 * pattern copies) lives until arena_destroy; there is no separate free.
 *
 * Thread safety: concurrent readers of a ruleset are safe once all
 * gitignore_ruleset_append calls have returned. Concurrent appends are not safe.
 */

#ifndef DOTTA_GITIGNORE_H
#define DOTTA_GITIGNORE_H

#include <types.h>

/*
 * Origin tag - an opaque identifier assigned by the caller when appending rules,
 * returned verbatim by gitignore_eval to identify which source decided the match.
 * Dotta uses 0=builtin, 1=baseline, 2=profile; callers are free to choose.
 */
typedef uint8_t gitignore_origin_t;

typedef struct gitignore_ruleset gitignore_ruleset_t;

typedef struct {
    bool decided;                  /* true if any rule matched */
    bool ignored;                  /* winning rule's effect (negation-aware) */
    gitignore_origin_t origin;     /* origin of winning rule */
    const char *pattern;           /* winning rule as written (arena-owned); NULL when undecided */
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
 * Parse `content` as a gitignore file and append the resulting rules, each tagged
 * with `origin`. Safe to call repeatedly to layer sources (e.g. baseline then
 * profile).
 *
 * Blank and comment lines are skipped. Empty content is accepted (no rules
 * appended). Returns ERR_VALIDATION if any line exceeds 4096 bytes or the
 * cumulative rule count exceeds 10000; ERR_MEMORY on arena exhaustion.
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
 * Append an array of single-line patterns, each becoming one rule tagged with
 * `origin`. Convenience form for callers holding patterns as an array (CLI flags,
 * config arrays) rather than a gitignore file body.
 *
 * Semantically equivalent to joining `patterns[i]` with '\n' and calling
 * `gitignore_ruleset_append`. NULL entries in the array are skipped. Empty arrays
 * (NULL array or count==0, or all entries NULL) are a successful no-op.
 *
 * Per-pattern length (4096) and cumulative rule count (10000) caps are enforced
 * by the underlying parser; callers are expected to wrap the returned error with
 * caller-specific context (e.g. "Failed to compile CLI exclude patterns").
 *
 * @param ruleset  Ruleset to append into (must not be NULL)
 * @param patterns Array of NUL-terminated pattern strings (may be NULL when count
 *                 == 0; individual entries may be NULL)
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
 * `path` is relative to the ruleset's root — the directory the rules were written
 * for, as a `.gitignore`'s are relative to the directory it sits in. The walk-up
 * below visits every ancestor of `path`, so an absolute path is evaluated against
 * the filesystem root with the whole ancestry taking part, which is never what
 * a caller wants. Leading and trailing slashes are stripped for gitignore parity,
 * and a trailing slash is treated as a directory hint. `is_dir` distinguishes
 * files from directories for directory-only rules.
 *
 * Semantics mirror gitignore exactly: rules are scanned in reverse insertion
 * order (last-match-wins). If no rule matches at the given path, the evaluator
 * walks up one directory at a time, re-scanning at each parent (with is_dir=true),
 * which is what makes `cache/` match `cache/file.txt`. Each of those scans reads
 * every rule at that rung as gitignore_rule_matches reads one.
 *
 * Never fails. Always populates every field of *out; decided=false means no rule
 * matched (caller treats as not-ignored). `pattern` is the winning rule's source
 * line, trimmed, as the user wrote it (`!build/`, `/.cache/`), so a verdict can
 * be reported by the rule that gave it; it borrows the ruleset's arena.
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
 * Ignored-verdict shortcut for callers that do not care about origin attribution.
 * Wraps gitignore_eval and returns the last-match-wins boolean — true iff a rule
 * decided the path is ignored.
 *
 * Negation-aware: when the winning rule is `!pattern`, returns false (the path
 * is un-ignored). When no rule matches, returns false.
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

/* -------------------------------------------------------------------- */
/* The rule alone                                                       */
/* -------------------------------------------------------------------- */

/*
 * One line of the grammar as a rule of its own — no ruleset around it, and none
 * of the ruleset's context: a negation stands whatever came before it, since
 * there is no before. For a caller whose program is its own and reads each rule
 * itself (infra/pathspec: its rules in its own order, over rungs of its own walk);
 * a ruleset of one rule is not the rule the line wrote, because the gate drops
 * a non-wildcard negation with nothing before it to negate.
 */
typedef struct gitignore_rule gitignore_rule_t;

/**
 * Parse one line into a rule.
 *
 * The line as the ruleset's parser reads one: the `!` and the anchor slash, the
 * trailing slash as the directory marker, escapes, trailing whitespace trimmed.
 * A line that makes no rule — blank, a comment (`#` first), whitespace only,
 * trimmed to nothing — answers NULL with no error; a line past 4096 bytes, or
 * one holding a newline (a rule is one line), is refused (ERR_VALIDATION). The
 * rule is the arena's.
 *
 * @param arena Arena providing storage (borrowed; must outlive the rule)
 * @param line  One line of gitignore grammar (must not be NULL)
 * @param out   The rule, or NULL when the line makes none (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitignore_rule_parse(
    arena_t *arena,
    const char *line,
    gitignore_rule_t **out
);

/**
 * Does the rule match this rung?
 *
 * `rung` and `is_dir` as for the ruleset's scan at one rung: a leading slash is
 * shed (the subject's, never an anchor), a trailing slash is not read — say so
 * with `is_dir` — and a rung that is empty or nothing but slashes matches nothing.
 * A directory-only rule matches only when `is_dir`; an anchored rule reads the
 * whole rung, a bare one its basename. No ancestor is consulted: the walk is
 * the caller's. Never fails, allocates nothing.
 *
 * @param rule   The rule (can be NULL: false)
 * @param rung   One rung, relative to the rule's root (can be NULL: false)
 * @param is_dir True if the rung refers to a directory
 * @return true iff the rule matches
 */
bool gitignore_rule_matches(
    const gitignore_rule_t *rule,
    const char *rung,
    bool is_dir
);

/**
 * Is the rule a negation (`!…`)?
 *
 * A match then un-ignores — or, for a selector, un-selects. The polarity is the
 * parser's, not the first byte's: `\!x` is a literal.
 *
 * @param rule The rule (can be NULL: false)
 * @return true iff the rule negates
 */
bool gitignore_rule_negated(const gitignore_rule_t *rule);

#endif /* DOTTA_GITIGNORE_H */
