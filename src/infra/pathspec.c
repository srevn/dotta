/**
 * pathspec.c - Path matcher implementation
 */

#include "infra/pathspec.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "infra/mount.h"

/* Compiled glob entry: the raw user input string and a single-rule
 * ruleset isolating the pattern from its siblings. Both are arena-
 * backed; their lifetime ends when the caller's arena is destroyed.
 *
 * The isolated ruleset preserves per-pattern coverage attribution: a
 * combined-ruleset evaluation folds one pattern's negation into
 * another's verdict, which under-counts coverage on overlap. A
 * one-rule ruleset evaluated alone gives each input independent
 * attribution. */
typedef struct {
    char *pattern;
    gitignore_ruleset_t *isolated;
} pathspec_glob_t;

struct pathspec {
    /* Exact paths.
     *
     * The hashmap supports O(1) match lookup in pathspec_matches and
     * walk-up ancestor probing. The parallel exact_keys array gives
     * stable indexed iteration without leaking the hashmap's iterator
     * type into the public API. Pointers in exact_keys borrow into the
     * hashmap-owned key storage; the hashmap is immutable post-
     * construction, so they are stable for the pathspec's lifetime. */
    hashmap_t *exact_paths;     /* heap-owned */
    const char **exact_keys;    /* heap-owned; NULL when exact_count == 0 */
    size_t exact_count;

    /* Glob patterns.
     *
     * glob_combined gives last-match-wins semantics across patterns
     * (negation between sibling patterns works as users expect from
     * gitignore). The per-pattern isolated rulesets in globs[] support
     * coverage validation. */
    gitignore_ruleset_t *glob_combined; /* arena-borrowed; NULL when glob_count == 0 */
    pathspec_glob_t *globs;             /* arena-borrowed; NULL when glob_count == 0 */
    size_t glob_count;

    size_t count;                       /* exact_count + glob_count */
};

/* Materialize a borrowed-pointer view of the hashmap's keys for
 * indexed iteration. Called once after the hashmap is fully populated
 * and never modified again, so the borrowed pointers are stable. */
static error_t *materialize_exact_keys(pathspec_t *spec) {
    size_t n = hashmap_size(spec->exact_paths);
    spec->exact_count = n;
    if (n == 0) {
        spec->exact_keys = NULL;
        return NULL;
    }

    const char **keys = malloc(n * sizeof(*keys));
    if (!keys) {
        return ERROR(ERR_MEMORY, "Failed to allocate exact-path index");
    }

    hashmap_iter_t iter;
    hashmap_iter_init(&iter, spec->exact_paths);
    const char *key;
    size_t idx = 0;
    while (hashmap_iter_next(&iter, &key, NULL) && idx < n) {
        keys[idx++] = key;
    }
    /* Hashmap is unmodified between size and iteration, so idx == n. */
    assert(idx == n);

    spec->exact_keys = keys;
    return NULL;
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

    pathspec_t *spec = calloc(1, sizeof(*spec));
    if (!spec) {
        return ERROR(ERR_MEMORY, "Failed to allocate pathspec");
    }

    spec->exact_paths = hashmap_create(0);
    if (!spec->exact_paths) {
        free(spec);
        return ERROR(ERR_MEMORY, "Failed to allocate pathspec hashmap");
    }

    error_t *err = NULL;

    /* First pass: count globs so the per-glob storage can be sized
     * exactly. The arena is only touched when at least one glob is
     * present, keeping the "exact paths only" common path allocation-
     * free beyond the hashmap. */
    size_t glob_capacity = 0;
    for (size_t i = 0; i < count; i++) {
        if (inputs[i] && strpbrk(inputs[i], "*?[")) glob_capacity++;
    }

    if (glob_capacity > 0) {
        err = gitignore_ruleset_create(arena, &spec->glob_combined);
        if (err) {
            err = error_wrap(err, "Failed to allocate glob ruleset");
            goto cleanup;
        }
        spec->globs = arena_calloc(
            arena, glob_capacity, sizeof(*spec->globs)
        );
        if (!spec->globs) {
            err = ERROR(ERR_MEMORY, "Failed to allocate glob entry table");
            goto cleanup;
        }
    }

    /* Second pass: classify and store each input. */
    for (size_t i = 0; i < count; i++) {
        const char *input = inputs[i];

        /* Glob pattern */
        if (input && strpbrk(input, "*?[")) {
            /* Patterns with '/' must use a storage label or recursive prefix. */
            mount_kind_t kind_unused;
            if (strchr(input, '/') != NULL &&
                !mount_kind_extract(input, &kind_unused) &&
                !str_starts_with(input, "**/") &&
                !str_starts_with(input, "*/")) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Glob pattern '%s' must use storage format or be basename-only\n"
                    "Examples: 'home/<star><star>/*.vim', '*.vim'", input
                );
                goto cleanup;
            }

            char *arena_copy = arena_strdup(arena, input);
            if (!arena_copy) {
                err = ERROR(ERR_MEMORY, "Failed to duplicate pattern");
                goto cleanup;
            }

            size_t slot = spec->glob_count;
            err = gitignore_ruleset_create(arena, &spec->globs[slot].isolated);
            if (err) {
                err = error_wrap(
                    err, "Failed to allocate isolated ruleset for '%s'", input
                );
                goto cleanup;
            }

            /* Append to combined ruleset (last-match-wins matching) and
             * to the isolated ruleset (per-pattern coverage validation).
             *
             * Subtle: gitignore drops a non-wildcard negation like
             * `!literal` when no earlier rule could match. In a single-
             * rule ruleset there are no earlier rules, so the rule is
             * dropped and the isolated check returns false — which is
             * the correct "this pattern alone matches nothing" verdict
             * for coverage purposes. */
            err = gitignore_ruleset_append(spec->glob_combined, arena_copy, 0);
            if (err) {
                err = error_wrap(err, "Failed to compile glob pattern '%s'", input);
                goto cleanup;
            }
            err = gitignore_ruleset_append(
                spec->globs[slot].isolated, arena_copy, 0
            );
            if (err) {
                err = error_wrap(err, "Failed to compile glob pattern '%s'", input);
                goto cleanup;
            }

            spec->globs[slot].pattern = arena_copy;
            spec->glob_count++;
            continue;
        }

        /* Exact path: resolve via shared mount table, store in hashmap. */
        const char *resolved = NULL;
        err = mount_resolve_input(table, input, arena, &resolved);
        if (err) {
            err = error_wrap(err, "Invalid path '%s'", input);
            goto cleanup;
        }

        err = hashmap_set(spec->exact_paths, resolved, (void *) 1);
        if (err) goto cleanup;
    }

    /* Materialize a borrowed-pointer view of the hashmap keys for the
     * indexed accessors. Done last so it sees the final, deduplicated
     * key set — duplicate inputs collapse into a single hashmap entry. */
    err = materialize_exact_keys(spec);
    if (err) goto cleanup;

    spec->count = spec->exact_count + spec->glob_count;

    *out = spec;
    return NULL;

cleanup:
    /* Arena-borrowed fields (glob_combined, globs[].pattern,
     * globs[].isolated) are reclaimed when the caller's arena is
     * destroyed; nothing to do here.
     *
     * exact_keys is only set on the success path of materialize_exact_keys
     * — failure leaves it NULL. free(NULL) is well-defined. */
    free(spec->exact_keys);
    hashmap_free(spec->exact_paths, NULL);
    free(spec);
    return err;
}

bool pathspec_matches(const pathspec_t *spec, const char *storage_path) {
    /* NULL pathspec matches all (no filter applied). */
    if (!spec) return true;
    if (!storage_path) return false;

    /* Fast path 1: O(1) exact match via hashmap. */
    if (hashmap_has(spec->exact_paths, storage_path)) return true;

    /* Fast path 2: ancestor-prefix matching. Preserves gitignore-style
     * directory matching where filter "home/.config" matches all files
     * under that directory. */
    size_t len = strlen(storage_path);
    if (len < PATH_MAX) {
        char buf[PATH_MAX];
        memcpy(buf, storage_path, len + 1);

        char *last_slash;
        while ((last_slash = strrchr(buf, '/')) != NULL) {
            *last_slash = '\0';
            if (hashmap_has(spec->exact_paths, buf)) return true;
        }
    }

    /* Slow path: combined gitignore ruleset.
     *
     * One gitignore_eval scan honours rule ordering, negation, directory
     * walk-up, and `**` recursive globs consistently with the rest of
     * the ignore stack. Storage paths always reference files, so is_dir
     * is false; directory-only globs still match via walk-up. */
    return gitignore_is_ignored(spec->glob_combined, storage_path, false);
}

void pathspec_free(pathspec_t *spec) {
    if (!spec) return;

    /* Free the borrowed-pointer view first. The pointers it holds
     * borrow into hashmap-owned key storage, so the order of these
     * two frees is purely semantic — the array contents are not read
     * during hashmap_free. */
    free(spec->exact_keys);
    hashmap_free(spec->exact_paths, NULL);

    /* Arena-borrowed fields (glob_combined, globs) are released when
     * the caller's arena is destroyed; nothing to do here. */

    free(spec);
}

size_t pathspec_count(const pathspec_t *spec) {
    return spec ? spec->count : 0;
}

size_t pathspec_exact_count(const pathspec_t *spec) {
    return spec ? spec->exact_count : 0;
}

size_t pathspec_glob_count(const pathspec_t *spec) {
    return spec ? spec->glob_count : 0;
}

const char *pathspec_exact_at(const pathspec_t *spec, size_t i) {
    assert(spec != NULL);
    assert(i < spec->exact_count);
    return spec->exact_keys[i];
}

const char *pathspec_glob_at(const pathspec_t *spec, size_t i) {
    assert(spec != NULL);
    assert(i < spec->glob_count);
    return spec->globs[i].pattern;
}

bool pathspec_glob_matches_at(
    const pathspec_t *spec, size_t i, const char *storage_path
) {
    if (!spec || !storage_path) return false;
    assert(i < spec->glob_count);
    return gitignore_is_ignored(
        spec->globs[i].isolated, storage_path, false
    );
}
