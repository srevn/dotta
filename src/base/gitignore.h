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
 * The parse is the grammar: the `!` and the anchor, the directory marker, the
 * escapes. Every rule it makes is kept as written. A ruleset is a *program over
 * the rungs of a path*, and there are two of them here:
 *
 *   Exclusion (`gitignore_eval`, `gitignore_is_ignored`) is git's. A rule that
 *   matches a directory excludes everything beneath it and no rule beneath it
 *   can re-include anything — so the ancestors are asked first, shallowest first,
 *   and the first one a rule excludes is both the verdict and the rule it is
 *   reported under. `.dottaignore`'s layers and `--exclude` read this.
 *
 *   Selection (`gitignore_is_selected`) is not. A rule that matches an ancestor
 *   *reaches* everything beneath it, and nothing is final: the last rule in the
 *   list that reaches the path decides. A list that picks files prunes no
 *   traversal, so git's barrier — which exists because git does not list an
 *   excluded directory — has no subject. The config's `auto_encrypt` reads this.
 *
 * The two agree on every ruleset with no negation in it: both answer "some rung
 * matched". A `!` beneath a rule that matched an ancestor is the whole of what
 * separates them.
 *
 * A rule is one line of the grammar, parsed and asked alone (`gitignore_rule_t`,
 * at the end of this header), for a caller whose program is neither —
 * infra/pathspec, which reads its rules in its own order and walks the rungs
 * itself.
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
 * Blank and comment lines are skipped. A UTF-8 byte-order mark at the head of
 * `content` is shed before the first line — it is the file's, not its first rule's;
 * one anywhere else is pattern content. A final line needs no terminator. Empty
 * content is accepted (no rules appended). Returns ERR_VALIDATION if any line
 * exceeds 4096 bytes or the cumulative rule count exceeds 10000; ERR_MEMORY on
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
 * Append an array of single-line patterns, each becoming one rule tagged with
 * `origin`. Convenience form for callers holding patterns as an array (CLI flags,
 * config arrays) rather than a gitignore file body.
 *
 * Semantically equivalent to joining `patterns[i]` with '\n' and calling
 * `gitignore_ruleset_append` — including that door's byte-order mark, which a
 * pattern has no occasion to carry. NULL entries in the array are skipped. Empty
 * arrays (NULL array or count==0, or all entries NULL) are a successful no-op.
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
 * Exclusion, attributed — the reading `gitignore_is_ignored` answers as a bool.
 *
 * `path` is relative to the ruleset's root — the directory the rules were written
 * for, as a `.gitignore`'s are relative to the directory it sits in. The walk
 * visits every ancestor of `path`, so an absolute path is evaluated against the
 * filesystem root with the whole ancestry taking part, which is never what a
 * caller wants. Leading and trailing slashes are stripped for gitignore parity,
 * and a trailing slash is treated as a directory hint. `is_dir` distinguishes
 * files from directories for directory-only rules.
 *
 * The order is git's (dir.c: prep_exclude, then last_matching_pattern): every
 * ancestor, shallowest first, each read as a directory, and then the path itself.
 * At one rung the rules are scanned in reverse insertion order (last-match-wins),
 * each read as gitignore_rule_matches reads one. An ancestor a rule excludes
 * ends the walk — nothing beneath an excluded directory can be re-included —
 * and is the rule the verdict is reported under; an ancestor a rule un-excludes
 * settles nothing about what lies beneath it and the walk continues.
 *
 * Never fails. Always populates every field of *out; decided=false means no rule
 * matched any rung — the ruleset was silent, which is what core/ignore's readers
 * turn their source-tree ladder on, and it is a fact about the rungs rather than
 * about the walk: any order over them answers it the same. `pattern` and `origin`
 * name the excluding rule when `ignored`; when `decided && !ignored` they name
 * the deepest rule that matched and excluded nothing (git reports no pattern at
 * all for that path), and no caller reads them there. `pattern` is the rule's
 * source line, trimmed, as the user wrote it (`!build/`, `/.cache/`); it borrows
 * the ruleset's arena.
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
 * Does the ruleset select `path`?
 *
 * Selection, not exclusion: the rules are read in reverse insertion order and
 * the first one that *reaches* the path decides — a rule reaches a path when it
 * matches the path itself or any directory above it. So `.ssh/` selects everything
 * under `~/.ssh`, and a later `!.ssh/id_*.pub` un-selects the public keys,
 * whichever of the two names the deeper rung. Nothing is final: a list that picks
 * files walks no tree, so git's "a parent directory cannot be re-included" — a
 * rule about a traversal git prunes — has no subject here, and every rule the
 * user wrote keeps its say in the order they wrote it.
 *
 * `path`, `is_dir` and the ruleset's root as for gitignore_eval. Safe on NULL
 * ruleset or NULL path (returns false). Never fails.
 *
 * @param ruleset Ruleset (can be NULL)
 * @param path    Relative path (can be NULL)
 * @param is_dir  True if path refers to a directory
 * @return true iff the ruleset's verdict is "selected"
 */
bool gitignore_is_selected(
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
 * One line of the grammar as a rule of its own — no ruleset around it, and so
 * neither of the ruleset's programs: no ancestors, no order, nothing final. For
 * a caller whose program is its own and reads each rule itself (infra/pathspec:
 * its rules in its own order, over rungs of its own walk).
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
