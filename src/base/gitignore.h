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
 *   and the first one a rule excludes is the verdict: that rule, at that rung.
 *   `.dottaignore`'s layers and `--exclude` read this.
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
 * A rule is one line of the grammar (`gitignore_rule_t`): what a ruleset holds
 * and answers with — the rule deciding one rung, and each rule in order — and
 * what a caller whose program is neither parses and asks alone (infra/pathspec,
 * which reads its rules in its own order and walks the rungs itself). A rule
 * knows the pattern it was written as, the line of the file it was read from,
 * and the origin its set gave it.
 *
 * Two kinds of input reach the grammar. A *file* is lines
 * (gitignore_ruleset_append_file): a byte-order mark at its head is the file's,
 * a comment or a blank line makes no rule, and a `\r` that ends a line is its
 * terminator. A *pattern* is one line of that grammar meant as one rule
 * (gitignore_validate_pattern, gitignore_rule_parse,
 * gitignore_ruleset_append_pattern): it is read as the line it would be in a
 * file — trailing spaces trimmed, a final `\r` a terminator, a leading `#` a
 * comment — and where that line would make no rule, the pattern is refused, never
 * read as nothing. git reads a command-line entry unread (`ls-files -x '#foo'`
 * matches a file named `#foo`); a pattern here cannot be, because `ignore --add`
 * writes it into a file as a line and `--exclude` is promised the file's meaning.
 * So `foo ` means `foo`, and a name that begins with `#` is matched by `\#`.
 * One line that does make a rule is refused as well: a pattern opening with `~/`,
 * past a `!`, which a shell reads as home and the grammar as a directory named
 * `~` — typed quoted to keep a glob from the shell, or written in a file no shell
 * reads, it matches nothing its writer named. `/` anchors the pattern at the
 * top of the rules' directory, and `\~/` names the directory called `~`. A list
 * of patterns is its caller's to walk, each entry one pattern — never the lines
 * of a file: no mark is shed from an entry and no newline splits one. A line
 * may be of any length and a set may hold any number of rules, as git's may:
 * what bounds either is the medium it came in.
 *
 * And a ruleset takes a third input, which the grammar never reads again: the
 * rules another ruleset compiled (gitignore_ruleset_append_rules), copied in
 * order and re-tagged, their strings borrowed — how a caller compiles a layer
 * once and composes it into as many rulesets as it needs.
 *
 * Lifetime: every ruleset and rule is arena-backed, and there is no separate
 * free. A rule's strings live in the arena it was parsed into; a ruleset composed
 * from another holds copies of the records and borrows those strings, so every
 * arena a ruleset borrows from must outlive it — resetting or freeing one
 * invalidates every ruleset that borrows it.
 *
 * Thread safety: concurrent readers of a ruleset are safe once every append to
 * it has returned. Concurrent appends are not safe.
 */

#ifndef DOTTA_GITIGNORE_H
#define DOTTA_GITIGNORE_H

#include <types.h>

/*
 * Origin tag - an opaque identifier assigned by the caller when appending rules,
 * returned verbatim by gitignore_rule_origin to say which of the caller's inputs
 * a rule came from. Its values are the caller's (core/ignore's ignore_origin_t);
 * a rule parsed alone carries 0.
 */
typedef uint8_t gitignore_origin_t;

typedef struct gitignore_ruleset gitignore_ruleset_t;

/*
 * How a ruleset compares a rule's letters with a subject's — git's core.ignoreCase,
 * held per set where git holds it per run. A storage path is a key in a tree
 * that travels between machines, and is compared byte for byte; a name on a
 * filesystem that folds case is compared with ASCII's letters folded, as git
 * compares one.
 */
typedef enum {
    GITIGNORE_CASE_SENSITIVE,      /* Byte for byte */
    GITIGNORE_CASE_INSENSITIVE     /* ASCII's letters folded, in literals and globs alike */
} gitignore_case_t;

/*
 * One line of the grammar, parsed: what a ruleset holds and answers with — its
 * own record, which the set's next append may move — or a rule of its own, parsed
 * and asked alone (gitignore_rule_parse, at the end of this header) — no ruleset
 * around it, and so neither of the ruleset's programs: no ancestors, no order,
 * nothing final — for a caller whose program is its own and reads each rule itself
 * (infra/pathspec: its rules in its own order, over rungs of its own walk).
 */
typedef struct gitignore_rule gitignore_rule_t;

/*
 * The exclusion program's answer for one path — git's, as check-ignore reports
 * a pattern or none: the rule that excludes it, and the rung it names, counted
 * up from the path itself. A negation is never the answer: a rung it re-includes
 * settles nothing beneath it, and a path no rule excludes has no rule to name.
 */
typedef struct {
    const gitignore_rule_t *rule;  /* The rule that excludes the path; NULL: none does */
    size_t rung;                   /* How far above the path it excluded: 0 the path itself */
} gitignore_match_t;

/**
 * Create an empty ruleset backed by the given arena, comparing letters as `casing`
 * says. Every rule the set holds is matched so, whichever set it was parsed into:
 * a copy (gitignore_ruleset_append_rules) is read as its new set reads its own,
 * as it is tagged with its new set's origin.
 *
 * @param arena  Arena providing storage (borrowed; must outlive ruleset)
 * @param casing How the set's rules compare letters with a subject's
 * @return The ruleset, the arena's; never NULL
 */
gitignore_ruleset_t *gitignore_ruleset_create(
    arena_t *arena,
    gitignore_case_t casing
);

/**
 * Parse `content` as a gitignore file and append the resulting rules, each tagged
 * with `origin`. Safe to call repeatedly to compose layers (e.g. baseline then
 * profile). A file, not a pattern: one string meant as one rule goes through
 * gitignore_ruleset_append_pattern, which refuses what this door would split on
 * a newline or skip as a comment.
 *
 * Blank and comment lines are skipped. A UTF-8 byte-order mark at the head of
 * `content` is shed before the first line (gitignore_file_lines) — it is the
 * file's, not its first rule's; one anywhere else is pattern content. A final
 * line needs no terminator. Empty content is accepted (no rules appended). Each
 * rule keeps the line it was read from (gitignore_rule_line), counted as git
 * counts one: from 1, every line counted, comments and blanks among them. Never
 * fails: every line is a rule or none.
 *
 * @param ruleset Ruleset to append into (must not be NULL)
 * @param content A gitignore file's text (must not be NULL; may be empty)
 * @param origin  Caller-chosen origin tag
 */
void gitignore_ruleset_append_file(
    gitignore_ruleset_t *ruleset,
    const char *content,
    gitignore_origin_t origin
);

/**
 * Where a gitignore file's lines begin: past a UTF-8 byte-order mark at its head,
 * which is the file's and not its first rule's (git's skip_utf8_bom, once per
 * buffer); at `content` itself otherwise. A mark anywhere else is pattern content,
 * and so is a head that only begins like one.
 *
 * Every reader of a file's lines starts here — gitignore_ruleset_append_file,
 * and an editor finding or dropping a rule (cmds/ignore) — so no two can disagree
 * about which rule the first line names. An editor that rewrites the file keeps
 * the bytes before the answer: they are the file's.
 *
 * @param content A gitignore file's text (must not be NULL)
 * @return The first line, inside `content`
 */
const char *gitignore_file_lines(const char *content);

/**
 * Append one pattern as one rule, tagged with `origin`.
 *
 * The pattern is read as gitignore_rule_parse reads one — the line it would be
 * in a file — and refused exactly as it refuses one (gitignore_validate_pattern).
 * It is not a file: no byte-order mark is shed from it and no newline is split.
 * A refusal stores nothing. The rule's strings are the set's arena's.
 *
 * @param ruleset Ruleset to append into (must not be NULL)
 * @param pattern One pattern (must not be NULL)
 * @param origin  Caller-chosen origin tag
 * @return Error or NULL on success
 */
error_t gitignore_ruleset_append_pattern(
    gitignore_ruleset_t *ruleset,
    const char *pattern,
    gitignore_origin_t origin
);

/**
 * Append another ruleset's rules: each record copied, in order, and re-tagged
 * with `origin`.
 *
 * A compiled ruleset is not read again. The strings its records hold are borrowed,
 * not copied — whatever arena backs them must outlive `ruleset`, and transitively:
 * a ruleset that was itself composed lends strings it borrowed. Appending to
 * `from` later does not reach `ruleset`; resetting or freeing a backing arena
 * invalidates it. `from` may be `ruleset` itself, and a NULL `from` is an absent
 * layer that appends nothing. Never fails.
 *
 * @param ruleset Ruleset to append into (must not be NULL)
 * @param from    Rules to copy (can be NULL: nothing)
 * @param origin  Caller-chosen origin tag applied to every copy
 */
void gitignore_ruleset_append_rules(
    gitignore_ruleset_t *ruleset,
    const gitignore_ruleset_t *from,
    gitignore_origin_t origin
);

/**
 * Evaluate `path` against the ruleset: exclusion, as git reads it — the rule
 * that excludes the path and the rung it names, or none.
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
 * and is the answer: that rule, and how many rungs of the path lie beneath it.
 * An ancestor a rule un-excludes settles nothing about what lies beneath it,
 * and the walk continues.
 *
 * Never fails; a path past 4096 bytes is copied to the heap, and let go before
 * the answer. The rule is the set's own record, valid until the next append
 * (gitignore_ruleset_find), and says the rest through its accessors: its pattern
 * as written, its origin, its line. Readers: gitignore_is_ignored, for core/scope.c
 * scope_is_excluded; core/ignore.c ignore_verdict, the ladder's four layers,
 * which the source layer is asked beneath only where they exclude nothing.
 *
 * @param ruleset Ruleset (can be NULL: no rule)
 * @param path    Relative path (can be NULL: no rule)
 * @param is_dir  True if path refers to a directory
 * @return The rule that excludes the path and its rung; NULL and 0 where none does
 */
gitignore_match_t gitignore_eval(
    const gitignore_ruleset_t *ruleset,
    const char *path,
    bool is_dir
);

/**
 * Does a rule exclude `path` — gitignore_eval's answer, for a caller that needs
 * no more than whether?
 *
 * A negation is never the answer: when the last rule to match is `!pattern`,
 * and no ancestor was excluded, the path is not. When no rule matches, it is not.
 *
 * Safe on NULL ruleset or NULL path (returns false). Never fails.
 *
 * @param ruleset Ruleset (can be NULL)
 * @param path    Relative path (can be NULL)
 * @param is_dir  True if path refers to a directory
 * @return true iff a rule excludes the path
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
 * The rule that decides one rung, or NULL where the set says nothing of it.
 *
 * git's last_matching_pattern_from_list: the set's rules in reverse insertion
 * order, each read as gitignore_rule_matches reads one, and the first that matches
 * — a negation as readily as any, for the caller to read (gitignore_rule_negated).
 * No ancestor is asked: the climb over a path's rungs is the caller's, for a
 * program that is more than one ruleset. gitignore_eval is this asked of every
 * rung of one path, an excluded ancestor final. `rung` and `is_dir` as for
 * gitignore_rule_matches.
 *
 * The rule is the set's own record, valid until the next append to the set, which
 * may move every record (base/arena.h arena_grow). Never fails, allocates nothing.
 *
 * @param ruleset Ruleset (can be NULL: NULL)
 * @param rung    One rung, relative to the ruleset's root (can be NULL: NULL)
 * @param is_dir  True if the rung refers to a directory
 * @return The deciding rule, borrowed from the set; NULL when no rule matches
 */
const gitignore_rule_t *gitignore_ruleset_find(
    const gitignore_ruleset_t *ruleset,
    const char *rung,
    bool is_dir
);

/**
 * Number of rules in the set (diagnostic).
 *
 * @param ruleset Ruleset (can be NULL)
 * @return Rule count, or 0 if ruleset is NULL
 */
size_t gitignore_ruleset_size(const gitignore_ruleset_t *ruleset);

/**
 * The index-th rule, in the order appended — for a listing of the rules a set
 * holds (`dotta key status -v`, each as written: gitignore_rule_pattern). The
 * set's own record, valid until the next append to the set.
 *
 * @param ruleset Ruleset (must not be NULL)
 * @param index   Below gitignore_ruleset_size(ruleset)
 * @return The rule (never NULL)
 */
const gitignore_rule_t *gitignore_ruleset_rule(
    const gitignore_ruleset_t *ruleset,
    size_t index
);

/* -------------------------------------------------------------------- */
/* The rule                                                             */
/* -------------------------------------------------------------------- */

/**
 * Refuse a pattern that is not one rule.
 *
 * gitignore_rule_parse's refusals with nothing kept, for a caller that writes
 * the pattern itself and asks the grammar first (cmds/ignore's --add and --remove).
 * In order: a newline (a pattern is one line), a line that would make no rule —
 * a comment, in its own words and with the escape that makes it a pattern; anything
 * else as naming nothing — and a rule spelled from home, a `~/` opening it past
 * a `!`, with its anchored spelling and the escape that names a directory called
 * `~`. A refusal about what the pattern says quotes it, bounded by that order
 * to one line; one about its shape quotes nothing. The caller names its door
 * around the refusal and repeats none of it.
 *
 * @param pattern One pattern (must not be NULL)
 * @return Error (ERR_VALIDATION), or NULL when the pattern is one rule
 */
error_t gitignore_validate_pattern(const char *pattern);

/**
 * Parse one pattern into a rule of its own.
 *
 * The pattern is read as the line it would be in a file — the `!` and the anchor
 * slash, the trailing slash as the directory marker, escapes, trailing spaces
 * trimmed, a final `\r` its terminator — and must make a rule: it is refused
 * exactly as gitignore_validate_pattern refuses it. The rule is the arena's.
 *
 * @param arena   Arena providing storage (borrowed; must outlive the rule)
 * @param pattern One pattern (must not be NULL)
 * @param out     The rule; NULL on a refusal (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitignore_rule_parse(
    arena_t *arena,
    const char *pattern,
    gitignore_rule_t **out
);

/**
 * Does the rule match this rung?
 *
 * `rung` and `is_dir` as for the ruleset's scan at one rung: a leading slash is
 * shed (the subject's, never an anchor), a trailing slash is not read — say so
 * with `is_dir` — and a rung that is empty or nothing but slashes matches nothing.
 * A directory-only rule matches only when `is_dir`; an anchored rule reads the
 * whole rung, a bare one its basename. Its letters are compared as the set that
 * holds it compares them (gitignore_case_t); a rule parsed alone, byte for byte.
 * No ancestor is consulted: the walk is the caller's. Never fails, allocates
 * nothing.
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

/**
 * The rule as written: the bytes gitignore_rule_span answers for its line, the
 * `!` and the anchor slash kept (`!build/`, `/.cache/`). A span, not a line: a
 * trailing space the grammar trimmed is not in it, and written back alone it
 * may name another rule. Borrowed from the arena the rule was parsed into,
 * whichever set holds the record now.
 *
 * @param rule The rule (can be NULL: NULL)
 * @return The pattern; NULL for no rule
 */
const char *gitignore_rule_pattern(const gitignore_rule_t *rule);

/**
 * The line of the file the rule was read from, 1-based as git counts it
 * (gitignore_ruleset_append_file), kept wherever the record is copied — so a
 * composed set's rule still names its line in its own file. 0 for a rule no file
 * gave: a pattern, appended or parsed alone.
 *
 * @param rule The rule (can be NULL: 0)
 * @return The line, or 0
 */
size_t gitignore_rule_line(const gitignore_rule_t *rule);

/**
 * The origin the set holding the rule tagged it with — the last set it was appended
 * to, since a copy is re-tagged (gitignore_ruleset_append_rules); 0 for a rule
 * parsed alone.
 *
 * @param rule The rule (can be NULL: 0)
 * @return The origin tag
 */
gitignore_origin_t gitignore_rule_origin(const gitignore_rule_t *rule);

/**
 * How many leading bytes of `line` are the rule it makes, as written.
 *
 * The grammar takes nothing off the front of a line — the `!` and the anchor
 * slash are consumed by the parse but are part of the rule the user wrote, and
 * leading whitespace is pattern content. Off the back it takes a `\r` that is
 * the line's last byte — a CRLF terminator; one with spaces behind it is inside
 * the rule, as it is to git — and then a run of trailing spaces (an escaped one,
 * `foo\ `, is kept; a tab is not a space and is kept). What is left is the rule
 * as written — the same bytes gitignore_rule_pattern answers for the rule it makes.
 *
 * So the span is the *identity* of a rule for anyone editing the file it lives
 * in: two lines name the same rule iff their spans are equal byte for byte,
 * which makes `foo` and `foo   ` one rule and `foo` and `  foo` two. Zero says
 * the line makes no rule at all — empty, a comment (`#` at column 0), a head
 * with nothing left behind it, or a directory marker with nothing to mark (`//`)
 * — and is exactly where the parse makes none; zero equals nothing, itself
 * included.
 *
 * The span is not a line. Read back alone, a span that ends in a `\r` — one a
 * trailing space kept inside the rule, `foo<CR><SP>` — names another rule, the
 * `\r` then its terminator. An editor compares by span and writes the line it
 * was given.
 *
 * `line` is one line: a `\n` inside it is pattern content here, where the ruleset's
 * own door would have split on it. A caller holding a whole file splits first;
 * a caller holding one string it means as a single rule should put it through
 * `gitignore_validate_pattern` (or `gitignore_rule_parse`, which keeps the rule),
 * which refuses an embedded newline and a line that makes no rule, by name.
 *
 * Allocates nothing, never fails. Safe on a NULL line (0).
 *
 * @param line One line, not necessarily NUL-terminated (can be NULL: 0)
 * @param len  Bytes of `line` to read
 * @return Byte count from `line`, or 0 when the line makes no rule
 */
size_t gitignore_rule_span(const char *line, size_t len);

#endif /* DOTTA_GITIGNORE_H */
