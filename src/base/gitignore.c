/*
 * gitignore.c - gitignore ruleset parsing and evaluation.
 *
 * Parser and matcher adapted from libgit2:
 *   src/libgit2/attr_file.c  (git_attr_fnmatch__parse,
 *                             git_attr_fnmatch__match,
 *                             trailing_space_length, unescape_spaces,
 *                             parse_optimized_patterns)
 *   src/libgit2/ignore.c     (ignore_lookup_in_rules and the walk-up
 *                             inside git_ignore_path_is_ignored,
 *                             does_negate_rule, does_negate_pattern)
 * Copyright (C) the libgit2 contributors. GPLv2 with Linking Exception.
 *
 * Adaptations from the original:
 *  - Drops macros/attributes/assignments (gitignore-only, no gitattributes).
 *  - Drops ICASE handling. Matches libgit2's gitignore ALLOWSPACE
 *    semantics: leading whitespace is preserved as pattern content;
 *    the caller pre-splits on `\n`, so the body scan runs to end-of-line.
 *  - Drops containing_dir / subdirectory .gitignore inheritance
 *    (dotta stores .dottaignore at repo root only).
 *  - Drops file source abstraction; rules come from caller-supplied
 *    content strings.
 *  - Replaces git_pool with base/arena and git_vector with a small
 *    inline dynamic array.
 *  - Adds per-rule origin tag for exact source attribution.
 *  - Optimizes only "*" (not "."): libgit2's "." shortcut fires only at
 *    end-of-buffer, which a line-based port would generalise to every
 *    "." line, diverging from gitignore's literal-filename semantics.
 *  - Walk-up is inlined into gitignore_eval, mirroring the outer
 *    git_ignore_path_is_ignored so parent-directory matching works when
 *    callers pass is_dir=false against a nested file.
 */

#include "base/gitignore.h"

#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/wildmatch.h"

/* Size limits — match the existing core/ignore.c conventions. */
#define MAX_PATTERN_LENGTH 4096
#define MAX_RULES          10000
#define PATH_BUFFER_SIZE   4096
#define INITIAL_CAPACITY   16

/* Rule flags — module-private. */
#define GITIGNORE_FLAG_NEGATIVE  (1U << 0)
#define GITIGNORE_FLAG_DIRECTORY (1U << 1)
#define GITIGNORE_FLAG_FULLPATH  (1U << 2)
#define GITIGNORE_FLAG_HASWILD   (1U << 3)
#define GITIGNORE_FLAG_MATCH_ALL (1U << 4)

typedef struct {
    const char *pattern;              /* arena-owned, NUL-terminated */
    size_t length;                    /* strlen(pattern) post-unescape */
    unsigned int flags;               /* GITIGNORE_FLAG_* bitmask */
    gitignore_origin_t origin;        /* caller-assigned tag */
} gitignore_rule_t;

struct gitignore_ruleset {
    arena_t *arena;                   /* borrowed */
    gitignore_rule_t *rules;          /* arena-allocated; grown by realloc+copy */
    size_t count;
    size_t capacity;
};

/* --- Character predicates ------------------------------------------- */
/* Mirror libgit2's git__isspace and git__iswildcard so parse behaviour
 * stays identical. Inline and private to avoid cross-module coupling. */

static inline bool is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n'
        || c == '\f' || c == '\r' || c == '\v';
}

static inline bool is_wildcard(char c) {
    return c == '*' || c == '?' || c == '[';
}

/* --- Trailing-space counting (attr_file.c:661) ---------------------- */

static size_t trailing_space_length(const char *p, size_t len) {
    size_t n, i;
    for (n = len; n; n--) {
        if (p[n - 1] != ' ' && p[n - 1] != '\t')
            break;

        /* Odd escape count before the space keeps it escaped; even count
         * means the backslash is escaped and the space is free to trim. */
        i = n;
        while (i > 1 && p[i - 2] == '\\')
            i--;
        if ((n - i) % 2)
            break;
    }
    return len - n;
}

/* --- Space-unescape in place (attr_file.c:684) ---------------------- */

static size_t unescape_spaces(char *str) {
    char *scan, *pos = str;
    bool escaped = false;

    if (!str)
        return 0;

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

    if (pos != scan)
        *pos = '\0';

    return (size_t) (pos - str);
}

/* --- Rule storage growth -------------------------------------------- */

/* Arena allocators have no in-place realloc, so growth allocates a
 * larger block and copies. The old block is reclaimed on arena_destroy. */
static error_t *ensure_capacity(gitignore_ruleset_t *set) {
    if (set->count < set->capacity)
        return NULL;

    size_t new_cap = set->capacity ? set->capacity * 2 : INITIAL_CAPACITY;

    gitignore_rule_t *resized =
        arena_alloc(set->arena, new_cap * sizeof(*resized));
    if (!resized)
        return ERROR(ERR_MEMORY, "gitignore: arena exhausted");

    if (set->count > 0)
        memcpy(resized, set->rules, set->count * sizeof(*resized));

    set->rules = resized;
    set->capacity = new_cap;
    return NULL;
}

/* --- Per-line parse ------------------------------------------------- */

/* On success, *have_rule is true for a produced rule, false for
 * blank/comment/trimmed-to-empty lines. Returns an error on arena
 * exhaustion. */
static error_t *parse_one_rule(
    arena_t *arena,
    const char *line,
    size_t line_len,
    gitignore_origin_t origin,
    gitignore_rule_t *out_rule,
    bool *have_rule
) {
    *have_rule = false;

    const char *pattern = line;
    size_t rem = line_len;

    /* Blank line produced by the caller's `\n` split. */
    if (rem == 0)
        return NULL;
    /* Comment: `#` at column 0 only. Leading whitespace is preserved
     * verbatim as pattern content (libgit2 ALLOWSPACE semantics), so a
     * line like `  # literal` is a three-char-indented pattern, not a
     * comment. */
    if (*pattern == '#')
        return NULL;

    /* `*` shortcut mirrors libgit2 parse_optimized_patterns (scoped to
     * `*` only; see module header for why `.` is intentionally skipped).
     * Kept before the negation strip to match libgit2's call order. */
    if (rem == 1 && *pattern == '*') {
        char *copy = arena_strndup(arena, pattern, 1);
        if (!copy)
            return ERROR(ERR_MEMORY, "gitignore: arena exhausted");
        out_rule->pattern = copy;
        out_rule->length = 1;
        out_rule->flags = GITIGNORE_FLAG_MATCH_ALL;
        out_rule->origin = origin;
        *have_rule = true;
        return NULL;
    }

    unsigned int flags = 0;

    if (*pattern == '!') {
        flags |= GITIGNORE_FLAG_NEGATIVE;
        pattern++;
        rem--;
    }

    /* Body scan: track slashes and wildcards over the full line. No
     * early break at whitespace — libgit2 ALLOWSPACE mode lets spaces,
     * tabs, and `\r` be part of the pattern. Trailing whitespace and a
     * trailing `\r` are stripped below. Mirrors attr_file.c:763-784. */
    int slash_count = 0;
    bool escaped = false;
    const char *scan = pattern;
    const char *end = pattern + rem;

    while (scan < end) {
        char c = *scan;

        if (c == '\\' && !escaped) {
            escaped = true;
            scan++;
            continue;
        }

        if (c == '/') {
            flags |= GITIGNORE_FLAG_FULLPATH;
            slash_count++;
            if (slash_count == 1 && pattern == scan)
                pattern++;               /* consume leading anchor slash */
        } else if (is_wildcard(c) && !escaped) {
            flags |= GITIGNORE_FLAG_HASWILD;
        }

        escaped = false;
        scan++;
    }

    size_t length = (size_t) (scan - pattern);
    if (length == 0)
        return NULL;

    /* Trim a single trailing `\r` (CRLF files). The caller splits on
     * `\n`, so the `\r` of a CRLF terminator is the last byte of the
     * line. Done before trailing_space_length so a mixed
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

    size_t final_length = unescape_spaces(copy);

    out_rule->pattern = copy;
    out_rule->length = final_length;
    out_rule->flags = flags;
    out_rule->origin = origin;
    *have_rule = true;
    return NULL;
}

/* --- Negation filter ------------------------------------------------- */
/* gitignore's "a parent directory cannot be re-included" rule: a
 * non-wildcard negation that no earlier rule could match is silently
 * discarded during parse. Without this filter, `build/` followed by
 * `!build/important.log` would leave the negation live and the file
 * unignored — diverging from git(1). Mirrors libgit2 ignore.c:50-168. */

static bool does_negate_pattern(
    const gitignore_rule_t *rule,
    const gitignore_rule_t *neg
) {
    if ((rule->flags & GITIGNORE_FLAG_NEGATIVE) != 0 ||
        (neg->flags & GITIGNORE_FLAG_NEGATIVE) == 0)
        return false;

    if (rule->length == neg->length)
        return memcmp(rule->pattern, neg->pattern, rule->length) == 0;

    const gitignore_rule_t *shorter = rule->length < neg->length ? rule : neg;
    const gitignore_rule_t *longer = rule->length < neg->length ? neg : rule;

    /* shorter must be basename-only AND match the tail of longer on a
     * `/` boundary. Length inequality guarantees tail > longer->pattern,
     * so tail[-1] is always inside longer's buffer. */
    const char *tail = longer->pattern + longer->length - shorter->length;
    if (tail[-1] != '/')
        return false;
    if (memchr(shorter->pattern, '/', shorter->length) != NULL)
        return false;
    return memcmp(tail, shorter->pattern, shorter->length) == 0;
}

/* Return true if `neg` could actually un-ignore a file matched by some
 * earlier rule in `set`. Called only for non-wildcard negations — the
 * wildcard case is indeterminate and libgit2 keeps them unconditionally. */
static bool negation_has_effect(
    const gitignore_ruleset_t *set,
    const gitignore_rule_t *neg
) {
    for (size_t i = 0; i < set->count; i++) {
        const gitignore_rule_t *rule = &set->rules[i];

        if (!(rule->flags & GITIGNORE_FLAG_HASWILD)) {
            if (does_negate_pattern(rule, neg))
                return true;
            continue;
        }

        /* For wildcard predecessors, mirror libgit2's wildmatch of the
         * neg's pattern against the predecessor's pattern. WM_PATHNAME
         * is gated on the predecessor having FULLPATH so that e.g.
         * `*.log` still matches nested `path/foo.log`. */
        unsigned int flags = (rule->flags & GITIGNORE_FLAG_FULLPATH)
                                 ? WM_PATHNAME
                                 : 0;
        if (wildmatch(rule->pattern, neg->pattern, flags) == WM_MATCH)
            return true;
    }
    return false;
}

/* --- Public API ------------------------------------------------------ */

error_t *gitignore_ruleset_create(
    arena_t *arena,
    gitignore_ruleset_t **out
) {
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
    gitignore_ruleset_t *set,
    const char *content,
    gitignore_origin_t origin
) {
    CHECK_NULL(set);
    CHECK_NULL(content);

    const char *cursor = content;
    while (*cursor) {
        const char *nl = strchr(cursor, '\n');
        size_t line_len = nl ? (size_t) (nl - cursor) : strlen(cursor);

        if (line_len > MAX_PATTERN_LENGTH)
            return ERROR(
                ERR_VALIDATION,
                "gitignore: line exceeds %d bytes",
                MAX_PATTERN_LENGTH
            );

        gitignore_rule_t rule = {0};
        bool have = false;
        RETURN_IF_ERROR(parse_one_rule(
            set->arena, cursor, line_len, origin, &rule, &have
        ));

        /* Drop a non-wildcard negation that no earlier rule could match
         * (gitignore's "parent directory cannot be re-included" rule).
         * Mirrors the gate in libgit2's parse_ignore_file. */
        if (have &&
            (rule.flags & GITIGNORE_FLAG_NEGATIVE) &&
            !(rule.flags & GITIGNORE_FLAG_HASWILD) &&
            !negation_has_effect(set, &rule))
            have = false;

        /* Gate MAX_RULES only when we're actually about to store — a
         * blank/comment/discarded line at index 10 000 must not falsely
         * trip the limit. */
        if (have) {
            if (set->count >= MAX_RULES)
                return ERROR(
                    ERR_VALIDATION,
                    "gitignore: exceeds %d rules",
                    MAX_RULES
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
    gitignore_ruleset_t *set,
    const char *const *patterns,
    size_t count,
    gitignore_origin_t origin
) {
    CHECK_NULL(set);

    if (!patterns || count == 0)
        return NULL;

    /* Compute buffer size in one pass; NULL entries are skipped. Each
     * pattern contributes strlen + 1 (for the trailing '\n' separator). */
    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        if (!patterns[i])
            continue;
        total += strlen(patterns[i]) + 1;
    }
    if (total == 0)
        return NULL;

    /* Join into an arena-backed buffer. The buffer is transient — only
     * used during the append call — but using the ruleset's arena keeps
     * the allocator path consistent with the rest of gitignore.c. The
     * extra bytes are reclaimed at arena_destroy alongside the rules. */
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
    const gitignore_ruleset_t *set,
    const char *path,
    bool is_dir,
    gitignore_match_t *out
) {
    if (!out)
        return;

    out->decided = false;
    out->ignored = false;
    out->origin = 0;
    out->rule_index = 0;

    if (!set || !path)
        return;

    /* Copy to a mutable, NUL-terminated buffer. Walk-up shortens the
     * logical path in place by inserting NUL at each `/`; strrchr and
     * wildmatch both read until NUL, so no explicit length tracking
     * is needed. Paths longer than the buffer leave out->decided=false. */
    char buf[PATH_BUFFER_SIZE];
    size_t n = strlen(path);
    if (n >= sizeof(buf))
        return;
    memcpy(buf, path, n + 1);

    char *p = buf;
    while (*p == '/')
        p++;
    if (*p == '\0')
        return;

    /* A trailing slash conveys "directory"; strip and flip is_dir so
     * callers may pass either form. */
    size_t len = strlen(p);
    while (len > 0 && p[len - 1] == '/') {
        p[--len] = '\0';
        is_dir = true;
    }
    if (len == 0)
        return;

    while (true) {
        char *slash = strrchr(p, '/');
        const char *basename = slash ? slash + 1 : p;

        for (size_t i = set->count; i > 0; --i) {
            const gitignore_rule_t *r = &set->rules[i - 1];

            if ((r->flags & GITIGNORE_FLAG_DIRECTORY) && !is_dir)
                continue;

            bool matched;
            if (r->flags & GITIGNORE_FLAG_MATCH_ALL) {
                matched = true;
            } else if (r->flags & GITIGNORE_FLAG_FULLPATH) {
                matched = wildmatch(r->pattern, p, WM_PATHNAME) == WM_MATCH;
            } else {
                matched = wildmatch(r->pattern, basename, 0) == WM_MATCH;
            }

            if (matched) {
                out->decided = true;
                out->ignored = !(r->flags & GITIGNORE_FLAG_NEGATIVE);
                out->origin = r->origin;
                out->rule_index = i - 1;
                return;
            }
        }

        /* Walk up one directory. Single-component paths terminate the
         * scan (matches the basename == path check in libgit2's
         * git_ignore_path_is_ignored). */
        if (!slash)
            break;
        *slash = '\0';
        is_dir = true;
    }
}

bool gitignore_is_ignored(
    const gitignore_ruleset_t *set,
    const char *path,
    bool is_dir
) {
    gitignore_match_t m;
    gitignore_eval(set, path, is_dir, &m);
    return m.decided && m.ignored;
}

size_t gitignore_ruleset_size(const gitignore_ruleset_t *set) {
    return set ? set->count : 0;
}
