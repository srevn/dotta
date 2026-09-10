/*
 * gitignore.c - gitignore ruleset parsing and evaluation.
 *
 * Parser and matcher adapted from libgit2:
 *   src/libgit2/attr_file.c  (git_attr_fnmatch__parse,
 *                             git_attr_fnmatch__match, trailing_space_length,
 *                             unescape_spaces, parse_optimized_patterns)
 *   src/libgit2/ignore.c     (ignore_lookup_in_rules)
 * Copyright (C) the libgit2 contributors. GPLv2 with Linking Exception.
 *
 * Adaptations from the original:
 *  - Drops macros/attributes/assignments (gitignore-only, no gitattributes).
 *  - Drops ICASE handling. Matches libgit2's gitignore ALLOWSPACE semantics:
 *    leading whitespace is preserved as pattern content; the caller pre-splits
 *    on `\n`, so the body scan runs to end-of-line.
 *  - Drops containing_dir / subdirectory .gitignore inheritance (dotta stores
 *    .dottaignore at repo root only).
 *  - Drops file source abstraction; rules come from caller-supplied content
 *    strings.
 *  - Replaces git_pool with base/arena and git_vector with a small inline dynamic
 *    array.
 *  - Adds per-rule origin tag for exact source attribution.
 *  - Every rule is kept as written. libgit2 drops a non-wildcard negation at
 *    parse when no earlier pattern appears able to match it; that heuristic
 *    compares two patterns without a path, so it also drops negations that do
 *    match one (`x/y*.txt` then `!ya.txt`), and it is not the rule it is named
 *    for — the walk is. Its `*` parse shortcut goes with it: a bare `*` parsed
 *    the ordinary way carries neither flag and matches every basename, which is
 *    what the shortcut was for.
 *  - unescape_spaces is libgit2's and answer-neutral: it resolves the escapes
 *    wildmatch resolves anyway, so a literal reads its full length, and a dangling
 *    escape is kept rather than dropped — dropping one made `foo\` match `foo`,
 *    where git matches nothing at all.
 *  - The trailing-whitespace rule is git's: libgit2 trims a trailing tab as well
 *    as a space, which drops a rule git keeps. gitignore(5) says spaces, and
 *    git's trim_trailing_spaces (dir.c:1029) trims those alone.
 *  - The walk is git's (dir.c: prep_exclude, then last_matching_pattern), not
 *    libgit2's: libgit2 stops at the first rung that decides, which re-includes
 *    a file beneath an excluded directory (libgit2#7339, open upstream).
 *    tests/test-gitignore-parity.c is the differential against git(1) itself.
 */

#include "base/gitignore.h"

#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/wildmatch.h"

/* Size limits — match the existing core/ignore.c conventions. */
#define MAX_PATTERN_LENGTH 4096
#define MAX_RULES          10000
#define PATH_STACK_BUFFER  4096
#define INITIAL_CAPACITY   16

/* Rule flags — module-private. */
#define GITIGNORE_FLAG_NEGATIVE  (1U << 0)
#define GITIGNORE_FLAG_DIRECTORY (1U << 1)
#define GITIGNORE_FLAG_FULLPATH  (1U << 2)

struct gitignore_rule {
    const char *pattern;              /* arena-owned, NUL-terminated */
    unsigned int flags;               /* GITIGNORE_FLAG_* bitmask */
    gitignore_origin_t origin;        /* the ruleset's tag; 0 for a rule alone */
    const char *source;               /* the line as written, trimmed (arena-owned) */
};

struct gitignore_ruleset {
    arena_t *arena;                   /* borrowed */
    gitignore_rule_t *rules;          /* arena-allocated; grown by realloc+copy */
    size_t count;
    size_t capacity;
};

/* --- Character predicates ------------------------------------------- */
/* Mirrors libgit2's git__isspace so parse behaviour stays identical. Inline and
 * private to avoid cross-module coupling. */

static inline bool is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n'
           || c == '\f' || c == '\r' || c == '\v';
}

/* --- Trailing-space counting (dir.c:1029) --------------------------- */

/* Spaces, and only spaces: gitignore(5) says a trailing space, and git trims
 * that alone (trim_trailing_spaces resets on every other byte). A tab is pattern
 * content, and a line ending in one is a rule. Counted backwards over a slice
 * the caller owns, where git walks forward over a NUL-terminated buffer it may
 * cut; the two agree on every escape shape. */
static size_t trailing_space_length(const char *p, size_t len) {
    size_t n, i;
    for (n = len; n; n--) {
        if (p[n - 1] != ' ')
            break;

        /* Odd escape count before the space keeps it escaped; even count means
         * the backslash is escaped and the space is free to trim. */
        i = n;
        while (i > 1 && p[i - 2] == '\\')
            i--;
        if ((n - i) % 2)
            break;
    }

    return len - n;
}

/* --- Space-unescape in place (attr_file.c:684) ---------------------- */

/* Resolves the escapes wildmatch would resolve anyway — `\ ` becomes a space,
 * and every other escape keeps its backslash — so a pattern that cannot glob is
 * as long as it reads. git has no such pass; it hands the line to the matcher
 * as written, which answers the same. The one shape where the two could part is
 * a *dangling* escape (`foo\`), and it is kept: wildmatch reads a trailing
 * backslash as an escape with nothing behind it and refuses every subject, which
 * is what git answers for such a rule. */
static void unescape_spaces(char *str) {
    char *scan, *pos = str;
    bool escaped = false;

    for (scan = str; *scan; scan++) {
        if (!escaped && *scan == '\\') {
            escaped = true;
            continue;
        }

        /* Preserve the escape for non-space escapes. */
        if (escaped && !is_ws(*scan))
            *pos++ = '\\';

        *pos++ = *scan;
        escaped = false;
    }

    if (escaped)
        *pos++ = '\\';       /* nothing behind it, and the matcher says so */

    *pos = '\0';
}

/* --- Rule storage growth -------------------------------------------- */

/* Arena allocators have no in-place realloc, so growth allocates a larger block
 * and copies. The old block is reclaimed on arena_destroy. */
static error_t *ensure_capacity(gitignore_ruleset_t *set) {
    if (set->count < set->capacity)
        return NULL;

    size_t new_cap = set->capacity ? set->capacity * 2 : INITIAL_CAPACITY;

    gitignore_rule_t *resized = arena_alloc(
        set->arena, new_cap * sizeof(*resized)
    );
    if (!resized)
        return ERROR(ERR_MEMORY, "gitignore: arena exhausted");

    if (set->count > 0)
        memcpy(resized, set->rules, set->count * sizeof(*resized));

    set->rules = resized;
    set->capacity = new_cap;

    return NULL;
}

/* --- Per-line parse ------------------------------------------------- */

/* A line that makes no rule — blank, a comment, trimmed to nothing — leaves
 * out_rule->pattern NULL, which is what the module's public door already answers
 * for one (gitignore_rule_parse: *out = NULL). The origin is not the line's:
 * the ruleset tags the rule after the parse, and a rule alone carries none. Returns
 * an error on arena exhaustion. */
static error_t *parse_one_rule(
    arena_t *arena, const char *line, size_t line_len, gitignore_rule_t *out_rule
) {
    out_rule->pattern = NULL;

    const char *pattern = line;
    size_t rem = line_len;

    /* Blank line produced by the caller's `\n` split. */
    if (rem == 0)
        return NULL;
    /* Comment: `#` at column 0 only. Leading whitespace is preserved verbatim
     * as pattern content (libgit2 ALLOWSPACE semantics), so a
     * line like `  # literal` is a three-char-indented pattern, not a
     * comment. */
    if (*pattern == '#')
        return NULL;

    unsigned int flags = 0;

    if (*pattern == '!') {
        flags |= GITIGNORE_FLAG_NEGATIVE;
        pattern++;
        rem--;
    }

    /* Body scan: every `/` over the full line, an escaped one included — git
     * reads the separators without reading escapes at all (dir.c:715), and what
     * an escape protects is the wildmatch later. No early break at whitespace:
     * spaces, tabs and `\r` are pattern content, and only what trails them is
     * stripped below. */
    int slash_count = 0;
    const char *end = pattern + rem;

    for (const char *scan = pattern; scan < end; scan++) {
        if (*scan != '/')
            continue;

        flags |= GITIGNORE_FLAG_FULLPATH;
        slash_count++;
        if (slash_count == 1 && pattern == scan)
            pattern++;                   /* consume leading anchor slash */
    }

    size_t length = (size_t) (end - pattern);
    if (length == 0)
        return NULL;

    /* Trim a single trailing `\r` (CRLF files). The caller splits on `\n`, so
     * the `\r` of a CRLF terminator is the last byte of the line. Done before
     * trailing_space_length so a mixed
     * `pattern\r   ` does not swallow the `\r` inside the pattern —
     * parity with attr_file.c:791-798. */
    if (pattern[length - 1] == '\r') {
        length--;
        if (length == 0)
            return NULL;
    }

    length -= trailing_space_length(pattern, length);
    if (length == 0)
        return NULL;

    /* The rule as written — from the line's first byte (the `!` and the anchor
     * slash included) to the end of the trimmed body — kept for the verdict's
     * report. */
    char *source = arena_strndup(arena, line, (size_t) (pattern + length - line));
    if (!source)
        return ERROR(ERR_MEMORY, "gitignore: arena exhausted");

    if (pattern[length - 1] == '/') {
        length--;
        flags |= GITIGNORE_FLAG_DIRECTORY;
        if (--slash_count <= 0)
            flags &= ~GITIGNORE_FLAG_FULLPATH;
    }

    if (length == 0)
        return NULL;

    char *copy = arena_strndup(arena, pattern, length);
    if (!copy)
        return ERROR(ERR_MEMORY, "gitignore: arena exhausted");

    unescape_spaces(copy);

    out_rule->pattern = copy;
    out_rule->flags = flags;
    out_rule->origin = 0;
    out_rule->source = source;

    return NULL;
}

/* --- The match at one rung ------------------------------------------ */

/* One rule against one rung: the directory marker against is_dir, then the pattern
 * against the whole rung (anchored) or its basename (bare). The core both readers
 * share — the ruleset's scan over every rule, and the rule asked alone. */
static bool rule_matches(
    const gitignore_rule_t *r, const char *rung, const char *basename,
    bool is_dir
) {
    if ((r->flags & GITIGNORE_FLAG_DIRECTORY) && !is_dir)
        return false;
    if (r->flags & GITIGNORE_FLAG_FULLPATH)
        return wildmatch(r->pattern, rung, WM_PATHNAME) == WM_MATCH;

    return wildmatch(r->pattern, basename, 0) == WM_MATCH;
}

/* The rule that decides at one rung: the rules in reverse, the first to match
 * (last-match-wins), and no ancestor consulted — the walk is the caller's. NULL
 * when the ruleset says nothing about this rung. The rung and its basename are
 * the caller's to cut; a walk over a path knows where its separators are. */
static const gitignore_rule_t *match_rung(
    const gitignore_ruleset_t *set, const char *rung, const char *basename,
    bool is_dir
) {
    for (size_t i = set->count; i > 0; --i) {
        const gitignore_rule_t *r = &set->rules[i - 1];
        if (rule_matches(r, rung, basename, is_dir))
            return r;
    }

    return NULL;
}

/* Does one rule reach this path — matching the path itself, or a directory above
 * it? A rule that matches a directory reaches everything beneath it. The subject
 * is cut in place at each separator and restored before the answer, so the caller
 * keeps the whole path. */
static bool rule_reaches(
    const gitignore_rule_t *rule, char *subject, const char *basename, bool is_dir
) {
    if (rule_matches(rule, subject, basename, is_dir))
        return true;

    const char *base = subject;
    for (char *slash = strchr(subject, '/'); slash; slash = strchr(slash + 1, '/')) {
        if (slash == base) {          /* an empty component is no rung */
            base = slash + 1;
            continue;
        }
        *slash = '\0';
        bool hit = rule_matches(rule, subject, base, true);
        *slash = '/';
        base = slash + 1;
        if (hit)
            return true;
    }

    return false;
}

/* --- The subject ----------------------------------------------------- */

/* The subject a walk cuts, copied into `dst` (room for strlen(path) + 1): the
 * leading slashes are the caller's spelling and are dropped, and a trailing one
 * is read as the directory hint it is — `*is_dir` is set by one, never cleared.
 * Answers the length written; 0 for a subject with nothing left in it, so no
 * scan is ever asked about an empty rung. */
static size_t copy_subject(char *dst, const char *path, bool *is_dir) {
    while (*path == '/')
        path++;

    size_t len = strlen(path);
    while (len > 0 && path[len - 1] == '/') {
        len--;
        *is_dir = true;
    }

    memcpy(dst, path, len);
    dst[len] = '\0';

    return len;
}

/* --- Public API ------------------------------------------------------ */

error_t *gitignore_ruleset_create(arena_t *arena, gitignore_ruleset_t **out) {
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    gitignore_ruleset_t *set = arena_calloc(arena, 1, sizeof(*set));
    if (!set)
        return ERROR(ERR_MEMORY, "gitignore: arena exhausted");

    set->arena = arena;
    *out = set;
    return NULL;
}

error_t *gitignore_ruleset_append(
    gitignore_ruleset_t *set, const char *content, gitignore_origin_t origin
) {
    CHECK_NULL(set);
    CHECK_NULL(content);

    /* A byte-order mark belongs to the file, not to the rule its bytes sit in
     * front of — an editor that writes one would otherwise cost the caller its
     * first pattern, silently. One at the head is shed and any other is content,
     * which is git's own rule (dir.c:1226 add_patterns_from_buffer, calling
     * skip_utf8_bom once over the whole buffer). strncmp, not memcmp: a content
     * shorter than the mark is a content that does not carry one. */
    const char *cursor = content;
    if (strncmp(cursor, "\xEF\xBB\xBF", 3) == 0)
        cursor += 3;

    while (*cursor) {
        const char *nl = strchr(cursor, '\n');
        size_t line_len = nl ? (size_t) (nl - cursor) : strlen(cursor);

        if (line_len > MAX_PATTERN_LENGTH)
            return ERROR(
                ERR_VALIDATION,
                "gitignore: line exceeds %d bytes",
                MAX_PATTERN_LENGTH
            );

        gitignore_rule_t rule = { 0 };
        RETURN_IF_ERROR(parse_one_rule(set->arena, cursor, line_len, &rule));

        /* Gate MAX_RULES only when we're actually about to store — a blank/comment
         * line at index 10 000 must not falsely trip the limit. */
        if (rule.pattern) {
            rule.origin = origin;
            if (set->count >= MAX_RULES)
                return ERROR(
                    ERR_VALIDATION, "gitignore: exceeds %d rules", MAX_RULES
                );
            RETURN_IF_ERROR(ensure_capacity(set));
            set->rules[set->count++] = rule;
        }

        if (!nl)
            break;
        cursor = nl + 1;
    }

    return NULL;
}

error_t *gitignore_ruleset_append_patterns(
    gitignore_ruleset_t *set, const char *const *patterns, size_t count,
    gitignore_origin_t origin
) {
    CHECK_NULL(set);

    if (!patterns || count == 0)
        return NULL;

    /* Compute buffer size in one pass; NULL entries are skipped. Each pattern
     * contributes strlen + 1 (for the trailing '\n' separator). */
    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        if (!patterns[i])
            continue;
        total += strlen(patterns[i]) + 1;
    }
    if (total == 0)
        return NULL;

    /* Join into an arena-backed buffer. The buffer is transient — only used during
     * the append call — but using the ruleset's arena keeps the allocator path
     * consistent with the rest of gitignore.c. The extra bytes are reclaimed at
     * arena_destroy alongside the rules. */
    char *joined = arena_alloc(set->arena, total + 1);
    if (!joined)
        return ERROR(ERR_MEMORY, "gitignore: arena exhausted");

    size_t offset = 0;
    for (size_t i = 0; i < count; i++) {
        if (!patterns[i])
            continue;
        size_t len = strlen(patterns[i]);
        memcpy(joined + offset, patterns[i], len);
        offset += len;
        joined[offset++] = '\n';
    }
    joined[offset] = '\0';

    return gitignore_ruleset_append(set, joined, origin);
}

void gitignore_eval(
    const gitignore_ruleset_t *set, const char *path, bool is_dir,
    gitignore_match_t *out
) {
    if (!out)
        return;

    out->decided = false;
    out->ignored = false;
    out->origin = 0;
    out->pattern = NULL;

    if (!set || !path)
        return;

    /* Copy to a mutable, NUL-terminated buffer. The walk cuts the subject in
     * place at each `/` and restores it, so the buffer holds the whole path at
     * every step; wildmatch reads until NUL, so no length tracking is needed.
     *
     * Buffer strategy: stack covers the common case; longer paths borrow heap
     * so the matcher never silently degrades. A heap-alloc failure on a single
     * path-sized block means the system is in dire straits; we keep the never-fails
     * contract by leaving out->decided = false (caller treats as not-ignored). */
    char stack_buf[PATH_STACK_BUFFER];
    char *heap = NULL;
    char *p = stack_buf;
    size_t n = strlen(path);

    if (n >= sizeof(stack_buf)) {
        heap = malloc(n + 1);
        if (!heap)
            return;
        p = heap;
    }

    /* Git's own order (dir.c: prep_exclude, then last_matching_pattern): every
     * ancestor of the path, shallowest first, and then the path itself. An excluded
     * directory is final — nothing beneath it can be re-included — so the first
     * ancestor a rule excludes ends the walk and is the rule the verdict is
     * reported under. An ancestor a rule *un*-excludes settles nothing about
     * what lies beneath it; it is kept only so a caller can tell "our rules spoke"
     * from "our rules were silent" (`decided`), which is what the source-tree
     * ladder in core/ignore's readers turns on. */
    const gitignore_rule_t *match = NULL;

    if (copy_subject(p, path, &is_dir) > 0) {
        const char *base = p;
        for (char *slash = strchr(p, '/'); slash; slash = strchr(slash + 1, '/')) {
            if (slash == base) {          /* an empty component is no rung */
                base = slash + 1;
                continue;
            }
            *slash = '\0';
            const gitignore_rule_t *rung = match_rung(set, p, base, true);
            *slash = '/';
            base = slash + 1;

            if (rung) {
                match = rung;
                if (!(rung->flags & GITIGNORE_FLAG_NEGATIVE))
                    goto cleanup;
            }
        }

        const gitignore_rule_t *leaf = match_rung(set, p, base, is_dir);
        if (leaf)
            match = leaf;
    }

cleanup:
    free(heap);

    if (match) {
        out->decided = true;
        out->ignored = !(match->flags & GITIGNORE_FLAG_NEGATIVE);
        out->origin = match->origin;
        out->pattern = match->source;
    }
}

bool gitignore_is_ignored(
    const gitignore_ruleset_t *set, const char *path, bool is_dir
) {
    gitignore_match_t m;
    gitignore_eval(set, path, is_dir, &m);
    return m.decided && m.ignored;
}

bool gitignore_is_selected(
    const gitignore_ruleset_t *set, const char *path, bool is_dir
) {
    if (!set || !path)
        return false;

    char stack_buf[PATH_STACK_BUFFER];
    char *heap = NULL;
    char *p = stack_buf;
    size_t n = strlen(path);

    if (n >= sizeof(stack_buf)) {
        heap = malloc(n + 1);
        if (!heap)
            return false;
        p = heap;
    }

    /* The rules in reverse, and the first that reaches the path decides
     * (last-match-wins over the whole list, a directory rule reaching everything
     * beneath it). No barrier: a list that picks files prunes no traversal, so
     * a `!` beneath a directory rule stands — and a later rule outranks an earlier
     * one wherever the two speak about the same path. */
    const gitignore_rule_t *match = NULL;

    if (copy_subject(p, path, &is_dir) > 0) {
        const char *slash = strrchr(p, '/');
        const char *basename = slash ? slash + 1 : p;

        for (size_t i = set->count; i > 0; --i) {
            const gitignore_rule_t *rule = &set->rules[i - 1];
            if (rule_reaches(rule, p, basename, is_dir)) {
                match = rule;
                break;
            }
        }
    }

    free(heap);

    return match && !(match->flags & GITIGNORE_FLAG_NEGATIVE);
}

size_t gitignore_ruleset_size(const gitignore_ruleset_t *set) {
    return set ? set->count : 0;
}

/* --- The rule alone -------------------------------------------------- */

error_t *gitignore_rule_parse(
    arena_t *arena, const char *line, gitignore_rule_t **out
) {
    CHECK_NULL(arena);
    CHECK_NULL(line);
    CHECK_NULL(out);

    *out = NULL;

    size_t len = strlen(line);
    if (len > MAX_PATTERN_LENGTH)
        return ERROR(
            ERR_VALIDATION,
            "gitignore: line exceeds %d bytes", MAX_PATTERN_LENGTH
        );
    if (memchr(line, '\n', len))
        return ERROR(ERR_VALIDATION, "gitignore: a rule is one line");

    gitignore_rule_t rule = { 0 };
    RETURN_IF_ERROR(parse_one_rule(arena, line, len, &rule));
    if (!rule.pattern)
        return NULL;

    gitignore_rule_t *copy = arena_alloc(arena, sizeof(*copy));
    if (!copy)
        return ERROR(ERR_MEMORY, "gitignore: arena exhausted");
    *copy = rule;

    *out = copy;
    return NULL;
}

bool gitignore_rule_matches(
    const gitignore_rule_t *rule, const char *rung, bool is_dir
) {
    if (!rule || !rung)
        return false;

    while (*rung == '/')    /* the subject's leading slash, never an anchor */
        rung++;
    if (*rung == '\0')
        return false;

    const char *slash = strrchr(rung, '/');

    return rule_matches(rule, rung, slash ? slash + 1 : rung, is_dir);
}

bool gitignore_rule_negated(const gitignore_rule_t *rule) {
    return rule && (rule->flags & GITIGNORE_FLAG_NEGATIVE);
}
