/**
 * pathspec.c - The positional path filter
 */

#include "infra/pathspec.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/string.h"
#include "infra/mount.h"
#include "infra/path.h"

/* The ascent's copy of a subject: the stack covers the common case, the heap
 * the rest, so a long path is walked and never silently skipped. */
#define PATH_STACK_BUFFER 4096

/* One compiled input. `text` is what the coverage line prints — the entry as
 * compiled: the storage path, or the pattern in its storage-space form. An exact
 * entry keeps its storage path in `prefix`, its length hoisted, for the beneath
 * test the matcher and the attribution share; a rule keeps the parsed rule and
 * no prefix. Every byte is the arena's. */
typedef struct {
    const char *text;
    gitignore_rule_t *rule;          /* the rule; NULL for an exact entry */
    const char *prefix;              /* an exact entry's storage path; NULL for a rule */
    size_t prefix_len;
} entry_t;

struct pathspec {
    entry_t *entries;                /* insertion order; exact duplicates collapsed */
    size_t count;
    size_t rules;                    /* how many are rules: the program runs only when some are */
};

/* --- Compile ---------------------------------------------------------- */

/* A rule: the pattern in its storage-space form, parsed alone.
 *
 * A slash-bearing glob speaks one of two vocabularies. Storage space — a label
 * prefix, or a leading `<star><star>`/`<star>` component — compiles as-is. A
 * filesystem shape (absolute, tilde, relative dot) is the exact arm's vocabulary
 * wearing a glob tail: the whole input rides through the same resolver
 * (metacharacters are ordinary characters to the mount table) and compiles in
 * its storage form; gitignore's directory-only marker (a trailing '/') is
 * semantics, not directory spelling, so it is re-applied after the resolver sheds
 * it. Anything else — a bare `conf<star>/x` could mean either vocabulary — is
 * refused toward the self-announcing spellings. */
static error_t *compile_rule(
    const mount_table_t *table,
    const char *input,
    arena_t *arena,
    entry_t *out
) {
    const char *pattern = NULL;

    if (strchr(input, '/') != NULL &&
        mount_spec_for_path(input) == NULL &&
        !str_starts_with(input, "**/") &&
        !str_starts_with(input, "*/")) {
        if (input[0] != '/' && input[0] != '~' && input[0] != '.') {
            return ERROR(
                ERR_INVALID_ARG,
                "Glob pattern '%s' must be basename-only, storage format, "
                "or a filesystem path (absolute, ~/, ./)\n"
                "Examples: '*.vim', 'home/nvim/*.lua', '~/.config/*.conf'",
                input
            );
        }

        const char *resolved = NULL;
        error_t *err = path_input_resolve(table, input, arena, &resolved);
        if (err) {
            return error_wrap(err, "Invalid glob pattern '%s'", input);
        }
        pattern = input[strlen(input) - 1] == '/'
                  ? arena_str_format(arena, "%s/", resolved)
                  : resolved;
    } else {
        pattern = arena_strdup(arena, input);
    }
    if (!pattern) {
        return ERROR(ERR_MEMORY, "Failed to allocate pattern");
    }

    gitignore_rule_t *rule = NULL;
    error_t *err = gitignore_rule_parse(arena, pattern, &rule);
    if (err) {
        return error_wrap(err, "Failed to compile glob pattern '%s'", input);
    }
    if (!rule) {
        return ERROR(
            ERR_INVALID_ARG,
            "Glob pattern '%s' makes no rule "
            "(gitignore reads a leading '#' as a comment)",
            input
        );
    }

    *out = (entry_t){ .text = pattern, .rule = rule };
    return NULL;
}

/* Is the storage path already an exact entry? Two spellings of one path — a tilde
 * form beside its absolute — are one entry, as the count and the coverage lines
 * read them. */
static bool listed(const pathspec_t *spec, const char *storage_path) {
    for (size_t i = 0; i < spec->count; i++) {
        const entry_t *e = &spec->entries[i];
        if (e->prefix && strcmp(e->prefix, storage_path) == 0) {
            return true;
        }
    }
    return false;
}

error_t *pathspec_create(
    char *const *inputs,
    size_t count,
    const mount_table_t *table,
    arena_t *arena,
    pathspec_t **out
) {
    CHECK_NULL(table);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* No inputs -> NULL pathspec (matches all) */
    if (!inputs || count == 0) {
        *out = NULL;
        return NULL;
    }

    /* Each input makes at most one entry, so the inputs bound the list. */
    pathspec_t *spec = arena_calloc(arena, 1, sizeof(*spec));
    if (!spec) {
        return ERROR(ERR_MEMORY, "Failed to allocate pathspec");
    }
    spec->entries = arena_calloc(arena, count, sizeof(*spec->entries));
    if (!spec->entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate pathspec entries");
    }

    for (size_t i = 0; i < count; i++) {
        const char *input = inputs[i];
        entry_t entry = { 0 };

        if (strpbrk(input, "*?[")) {
            RETURN_IF_ERROR(compile_rule(table, input, arena, &entry));
            spec->rules++;
        } else {
            /* An exact path: resolved through the table, one entry per storage
             * path however many inputs spell it. */
            const char *resolved = NULL;
            error_t *err = path_input_resolve(table, input, arena, &resolved);
            if (err) {
                return error_wrap(err, "Invalid path '%s'", input);
            }
            if (listed(spec, resolved)) {
                continue;
            }
            entry = (entry_t){
                .text = resolved, .prefix = resolved, .prefix_len = strlen(resolved)
            };
        }

        spec->entries[spec->count++] = entry;
    }

    *out = spec;
    return NULL;
}

/* --- Match ------------------------------------------------------------ */

/* Is the subject the exact entry, or beneath it? The one test both tiers of readers
 * share — the matcher and the coverage attribution. */
static bool exact_covers(const entry_t *e, const char *storage_path) {
    return strcmp(storage_path, e->prefix) == 0 ||
           str_path_beneath(storage_path, e->prefix, e->prefix_len);
}

/* One subject's rungs above the leaf, deepest first: a copy of the subject,
 * shortened in place at each parent separator. The leaf is read from the subject
 * as given — most subjects decide there — so the copy is made only for an ascent,
 * on the stack where it fits and on the heap past it. */
typedef struct {
    char *rung;                      /* the current rung: the copy, shortened in place */
    char *heap;                      /* the copy when it outgrew the stack */
    char stack[PATH_STACK_BUFFER];
} rungs_t;

/* The copy, or false when it cannot be made: the ascent is then abandoned and
 * the answer stays the leaf's. Close in either case. */
static bool rungs_open(rungs_t *r, const char *subject) {
    size_t n = strlen(subject);

    r->heap = NULL;
    r->rung = n < sizeof(r->stack) ? r->stack : (r->heap = malloc(n + 1));
    if (!r->rung) {
        return false;
    }
    memcpy(r->rung, subject, n + 1);
    return true;
}

/* Up one rung. False past the last: the parent of a single component is no rung
 * (str_path_parent_len answers 0 — the label of a storage path), and neither is
 * the root of an absolute one (1 — "/" is nothing a rule reads). */
static bool rungs_up(rungs_t *r) {
    size_t n = str_path_parent_len(r->rung);
    if (n <= 1) {
        return false;
    }
    r->rung[n] = '\0';
    return true;
}

static void rungs_close(rungs_t *r) {
    free(r->heap);
}

/* What the program answers at one rung. */
typedef enum {
    VERDICT_NONE,                    /* no rule matched: the rung above decides, or none does */
    VERDICT_OUT,                     /* a negation matched: not in scope */
    VERDICT_IN                       /* a rule matched: in scope */
} verdict_t;

/* The program at one rung: the rules in reverse insertion order, and the first
 * to match decides. */
static verdict_t program_at(
    const pathspec_t *spec, const char *rung, bool is_dir
) {
    for (size_t i = spec->count; i > 0; --i) {
        const entry_t *e = &spec->entries[i - 1];
        if (e->rule && gitignore_rule_matches(e->rule, rung, is_dir)) {
            return gitignore_rule_negated(e->rule) ? VERDICT_OUT : VERDICT_IN;
        }
    }
    return VERDICT_NONE;
}

bool pathspec_matches(
    const pathspec_t *spec, const char *storage_path, path_kind_t kind
) {
    /* NULL pathspec matches all (no filter applied). */
    if (!spec) return true;
    if (!storage_path) return false;

    /* The exact tier: the path, or one beneath an entry. */
    for (size_t i = 0; i < spec->count; i++) {
        const entry_t *e = &spec->entries[i];
        if (e->prefix && exact_covers(e, storage_path)) {
            return true;
        }
    }
    if (spec->rules == 0) return false;

    /* The program: at the leaf as given, then up the rungs until one decides. */
    verdict_t verdict = program_at(spec, storage_path, kind == PATH_KIND_DIRECTORY);
    if (verdict == VERDICT_NONE) {
        rungs_t rungs;
        if (rungs_open(&rungs, storage_path)) {
            while (verdict == VERDICT_NONE && rungs_up(&rungs)) {
                verdict = program_at(spec, rungs.rung, true);
            }
        }
        rungs_close(&rungs);
    }
    return verdict == VERDICT_IN;
}

size_t pathspec_count(const pathspec_t *spec) {
    return spec ? spec->count : 0;
}

pathspec_entry_t pathspec_entry_at(const pathspec_t *spec, size_t i) {
    assert(spec != NULL);
    assert(i < spec->count);
    const entry_t *e = &spec->entries[i];
    return (pathspec_entry_t){ .text = e->text, .glob = e->rule != NULL };
}

bool pathspec_entry_matches_at(
    const pathspec_t *spec, size_t i, const char *storage_path, path_kind_t kind
) {
    if (!spec || !storage_path) return false;
    assert(i < spec->count);
    const entry_t *e = &spec->entries[i];

    if (!e->rule) {
        return exact_covers(e, storage_path);
    }

    /* The rule at the leaf, then at every rung above it; a match either way is
     * the entry doing something to the subject. */
    if (gitignore_rule_matches(e->rule, storage_path, kind == PATH_KIND_DIRECTORY)) {
        return true;
    }
    bool matched = false;
    rungs_t rungs;
    if (rungs_open(&rungs, storage_path)) {
        while (!matched && rungs_up(&rungs)) {
            matched = gitignore_rule_matches(e->rule, rungs.rung, true);
        }
    }
    rungs_close(&rungs);
    return matched;
}
