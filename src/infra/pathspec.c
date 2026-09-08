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
 * the rest, so a long path is walked and never silently skipped. The same constant
 * and the same reason as base/gitignore.c's own ascent. */
#define PATH_STACK_BUFFER 4096

/* One compiled input. `text` is what the coverage line prints — the input as
 * typed, since a location rule is an anchor and a tail and has no one compiled
 * string. `key` is the vocabulary its subject is read in, decided by the input's
 * shape and never by an asker. An exact entry keeps the spelling it names in
 * `prefix`, its length hoisted, for the beneath test the matcher and the
 * attribution share; a location rule keeps its anchor there, the rung past which
 * it reads; a storage rule keeps none. Every byte is the arena's. */
typedef struct {
    const char *text;                /* the input as typed: what a coverage line prints */
    path_key_t key;                  /* the vocabulary its subject is read in */
    gitignore_rule_t *rule;          /* the rule; NULL for an exact entry */
    const char *prefix;              /* an exact entry's spelling, or a location rule's anchor; NULL for a storage rule */
    size_t prefix_len;               /* strlen(prefix), hoisted for the beneath test */
} entry_t;

struct pathspec {
    entry_t *entries;                /* insertion order; exact duplicates collapsed */
    size_t count;                    /* how many entries, both tiers */
    size_t rule_count;               /* how many of them are rules: the program runs only when some are */
};

/* --- Compile ---------------------------------------------------------- */

/* A location as an entry's prefix. The root is spelled "" as the table spells
 * it: the one prefix every absolute path is beneath at depth zero (str_path_beneath
 * reads the leading slash alone), and the one a rule anchored there reads past
 * with the same arithmetic as any other anchor. */
static void prefix_location(entry_t *e, const char *location) {
    e->prefix = strcmp(location, "/") == 0 ? "" : location;
    e->prefix_len = strlen(e->prefix);
}

/* A rule, parsed alone in the vocabulary its shape names.
 *
 * A slash-bearing glob speaks one of two vocabularies. Storage space — a label
 * prefix, or a leading `<star><star>`/`<star>` component — compiles as typed. A
 * filesystem shape (absolute, tilde, relative dot) is an anchor and a tail: the
 * components before the first that holds a metacharacter are a directory spelling,
 * resolved to its location and compared literally, and the rest is the pattern,
 * rooted there as a .gitignore is rooted in its directory — a leading slash on
 * the tail so gitignore anchors it. The split is what keeps filesystem bytes
 * out of pattern syntax: what HOME, the working directory or an alias inserts
 * is never read as a class or a wildcard, while what the user typed past the
 * split is, as a shell would read it. A wildcard in the first component leaves
 * no head: under `/` the anchor is the root, and under `.` the working directory
 * — the resolver's own reading of a leading dot, so `.<star>/x` typed from HOME
 * is the dotdirs' x there — while `~<star>/x` is no tilde path and is refused;
 * anything else — a bare `conf<star>/x` could mean either vocabulary — is refused
 * toward the self-announcing spellings. The shape is read past a leading '!',
 * so a negated rule is a rule in either vocabulary. */
static error_t *compile_rule(
    const mount_table_t *table, const char *input, arena_t *arena, entry_t *out
) {
    bool negated = input[0] == '!';
    const char *body = input + (negated ? 1 : 0);
    const char *line = input; /* what gitignore parses: the input, or the anchored tail */

    *out = (entry_t){ .key = PATH_KEY_STORAGE };

    if (strchr(body, '/') != NULL &&
        mount_spec_for_path(body) == NULL &&
        !str_starts_with(body, "**/") &&
        !str_starts_with(body, "*/")) {
        /* The tail starts at the component holding the first metacharacter; the
         * head is what stands before that component's slash — or, when nothing
         * does, the root or the working directory the first byte names. */
        const char *tail = strpbrk(body, "*?[");
        while (tail > body && tail[-1] != '/') tail--;
        size_t head_len = (size_t) (tail - body);
        if (head_len > 0) head_len--;

        if ((body[0] != '/' && body[0] != '~' && body[0] != '.') ||
            (head_len == 0 && body[0] == '~')) {
            return ERROR(
                ERR_INVALID_ARG,
                "Glob pattern '%s' must be basename-only, storage format, "
                "or a filesystem path (absolute, ~/, ./)\n"
                "Examples: '*.vim', 'home/nvim/*.lua', '~/.config/*.conf'", input
            );
        }

        /* A wildcard in the first component leaves no head, and the first byte
         * says where the pattern is rooted — the guard above has already refused
         * every byte but these two there. Only the arm that allocates can fail. */
        const char *head = body[0] == '/' ? "/" : ".";
        if (head_len > 0) {
            head = arena_strndup(arena, body, head_len);
            if (!head) {
                return ERROR(ERR_MEMORY, "Failed to allocate the pattern's anchor");
            }
        }

        path_input_t anchor;
        error_t *err = path_input_resolve(table, head, arena, &anchor);
        if (err) {
            return error_wrap(err, "Invalid glob pattern '%s'", input);
        }
        if (anchor.key != PATH_KEY_LOCATION) {
            return ERROR(
                ERR_INTERNAL, "Glob pattern '%s': the anchor '%s' is not a location",
                input, head
            );
        }

        line = arena_str_format(arena, "%s/%s", negated ? "!" : "", tail);
        if (!line) {
            return ERROR(ERR_MEMORY, "Failed to allocate pattern");
        }
        out->key = PATH_KEY_LOCATION;
        prefix_location(out, anchor.location);
    }

    gitignore_rule_t *rule = NULL;
    error_t *err = gitignore_rule_parse(arena, line, &rule);
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

    out->rule = rule;
    return NULL;
}

/* Is the key already an exact entry? Two spellings of one location — a tilde
 * form beside its absolute, the binder's spelling beside the physical — are one
 * entry, as the count and the coverage lines read them; a name beside a location
 * is two, since they are two keys. A rule's anchor is no entry. */
static bool listed(const pathspec_t *spec, const entry_t *entry) {
    for (size_t i = 0; i < spec->count; i++) {
        const entry_t *e = &spec->entries[i];
        if (!e->rule && e->key == entry->key && strcmp(e->prefix, entry->prefix) == 0) {
            return true;
        }
    }
    return false;
}

error_t *pathspec_create(
    char *const *inputs, size_t count, const mount_table_t *table, arena_t *arena,
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
            spec->rule_count++;
        } else {
            /* An exact entry in the key the input names, one per key however
             * many inputs spell it. */
            path_input_t arg;
            error_t *err = path_input_resolve(table, input, arena, &arg);
            if (err) {
                return error_wrap(err, "Invalid path '%s'", input);
            }
            entry.key = arg.key;
            if (arg.key == PATH_KEY_LOCATION) {
                prefix_location(&entry, arg.location);
            } else {
                entry.prefix = arg.storage_path;
                entry.prefix_len = strlen(arg.storage_path);
            }
            if (listed(spec, &entry)) {
                continue;
            }
        }

        entry.text = arena_strdup(arena, input);
        if (!entry.text) {
            return ERROR(ERR_MEMORY, "Failed to copy the input");
        }
        spec->entries[spec->count++] = entry;
    }

    *out = spec;
    return NULL;
}

/* --- Match ------------------------------------------------------------ */

/* The subject an entry reads: the one in its own vocabulary, or NULL when the
 * caller has no name of that kind for the path. */
static const char *own_subject(
    const entry_t *e, const char *location, const char *storage_path
) {
    return e->key == PATH_KEY_LOCATION ? location : storage_path;
}

/* Is the subject the exact entry, or beneath it? The one test both tiers of readers
 * share — the matcher and the coverage attribution. The root's "" equals nothing
 * and encloses every absolute path. */
static bool exact_covers(const entry_t *e, const char *subject) {
    return strcmp(subject, e->prefix) == 0 ||
           str_path_beneath(subject, e->prefix, e->prefix_len);
}

/* What a rule reads at a rung of its own subject: a storage rule the rung itself;
 * a location rule the rung past its anchor — the pattern is rooted there — and
 * nothing at or above the anchor. */
static const char *rule_subject(const entry_t *e, const char *rung) {
    if (!rung) {
        return NULL;
    }
    if (e->key == PATH_KEY_STORAGE) {
        return rung;
    }
    return str_path_beneath(rung, e->prefix, e->prefix_len)
           ? rung + e->prefix_len + 1
           : NULL;
}

/* One subject's rungs above the leaf, deepest first: a copy of the subject,
 * shortened in place at each parent separator. The leaf is read from the subject
 * as given — most subjects decide there — so the copy is made only for an ascent,
 * on the stack where it fits and on the heap past it. A subject the caller has
 * none of stays absent: no rung, and nothing to copy. */
typedef struct {
    char *rung;                      /* the current rung: the copy, shortened in place; NULL when absent or spent */
    char *heap;                      /* the copy when it outgrew the stack */
    char stack[PATH_STACK_BUFFER];   /* where it fits, which is nearly always */
} rungs_t;

/* The copy, or false when it cannot be made: the ascent is then abandoned and
 * the answer stays the leaf's. Close in either case. */
static bool rungs_open(rungs_t *r, const char *subject) {
    r->heap = NULL;
    r->rung = NULL;
    if (!subject) {
        return true;
    }

    size_t n = strlen(subject);
    r->rung = n < sizeof(r->stack) ? r->stack : (r->heap = malloc(n + 1));
    if (!r->rung) {
        return false;
    }
    memcpy(r->rung, subject, n + 1);
    return true;
}

/* Up one rung. False past the last, and the subject is then spent — no rule reads
 * it at a rung above: the parent of a single component is no rung
 * (str_path_parent_len answers 0 — the label of a storage path), and neither is
 * the root of an absolute one (1 — "/" is nothing a rule reads). */
static bool rungs_up(rungs_t *r) {
    if (!r->rung) {
        return false;
    }
    size_t n = str_path_parent_len(r->rung);
    if (n <= 1) {
        r->rung = NULL;
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
    VERDICT_NONE,               /* no rule matched: the rung above decides, or none does */
    VERDICT_OUT,                /* a negation matched: not in scope */
    VERDICT_IN                  /* a rule matched: in scope */
} verdict_t;

/* The scan at one rung: the rules in reverse insertion order, each read at the
 * rung of its own vocabulary, and the first to match decides. The ruleset's own
 * scan (base/gitignore.c) is this over one subject; the walk is the caller's
 * there as it is here. */
static verdict_t scan_rung(
    const pathspec_t *spec, const char *location, const char *storage_path,
    bool is_dir
) {
    for (size_t i = spec->count; i > 0; --i) {
        const entry_t *e = &spec->entries[i - 1];
        if (!e->rule) {
            continue;
        }
        const char *subject = rule_subject(e, own_subject(e, location, storage_path));
        if (subject && gitignore_rule_matches(e->rule, subject, is_dir)) {
            return gitignore_rule_negated(e->rule) ? VERDICT_OUT : VERDICT_IN;
        }
    }

    return VERDICT_NONE;
}

bool pathspec_matches(
    const pathspec_t *spec, const char *location, const char *storage_path,
    path_kind_t kind
) {
    /* NULL pathspec matches all (no filter applied). */
    if (!spec) return true;

    /* The exact tier: the path, or one beneath an entry, in the entry's own key. */
    for (size_t i = 0; i < spec->count; i++) {
        const entry_t *e = &spec->entries[i];
        const char *subject = own_subject(e, location, storage_path);
        if (!e->rule && subject && exact_covers(e, subject)) {
            return true;
        }
    }
    if (spec->rule_count == 0) return false;

    /* The leaf as given: most subjects decide there, and nothing is copied. */
    verdict_t verdict = scan_rung(
        spec, location, storage_path, kind == PATH_KIND_DIRECTORY
    );
    if (verdict != VERDICT_NONE) return verdict == VERDICT_IN;

    /* Up the rungs. The two subjects climb together — rung k of each is one
     * directory as far as the tail goes — and both copies are made or neither:
     * a vocabulary still climbing while the other could not would let a positive
     * rule in one select what a negation in the other would have excluded. Each
     * open is named on its own line, so neither is skipped by a short circuit
     * and both are closed. */
    rungs_t l, s;
    bool opened_l = rungs_open(&l, location);
    bool opened_s = rungs_open(&s, storage_path);
    while (opened_l && opened_s && verdict == VERDICT_NONE) {
        bool up_l = rungs_up(&l);
        bool up_s = rungs_up(&s);
        if (!up_l && !up_s) {
            break;
        }
        verdict = scan_rung(spec, l.rung, s.rung, true);
    }
    rungs_close(&l);
    rungs_close(&s);

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
    const pathspec_t *spec,
    size_t i,
    const char *location,
    const char *storage_path,
    path_kind_t kind
) {
    if (!spec) return false;
    assert(i < spec->count);
    const entry_t *e = &spec->entries[i];
    const char *subject = own_subject(e, location, storage_path);
    if (!subject) return false;

    if (!e->rule) {
        return exact_covers(e, subject);
    }

    /* The rule at the leaf, then at every rung above it; a match either way is
     * the entry doing something to the subject. */
    const char *leaf = rule_subject(e, subject);
    if (leaf && gitignore_rule_matches(e->rule, leaf, kind == PATH_KIND_DIRECTORY)) {
        return true;
    }
    bool matched = false;
    rungs_t rungs;
    if (rungs_open(&rungs, subject)) {
        while (!matched && rungs_up(&rungs)) {
            const char *rung = rule_subject(e, rungs.rung);
            matched = rung && gitignore_rule_matches(e->rule, rung, true);
        }
    }
    rungs_close(&rungs);
    return matched;
}
