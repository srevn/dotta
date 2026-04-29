/**
 * pathspec.c - Path matcher implementation
 */

#include "infra/pathspec.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "infra/mount.h"

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

    /* First pass: count globs so we can size the storage exactly. The
     * arena is only touched when at least one glob is present, keeping
     * the "exact paths only" common path allocation-free beyond the
     * hashmap. */
    size_t glob_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (inputs[i] && strpbrk(inputs[i], "*?[")) glob_count++;
    }

    if (glob_count > 0) {
        error_t *rules_err = gitignore_ruleset_create(arena, &spec->glob_ruleset);
        if (rules_err) {
            err = error_wrap(rules_err, "Failed to allocate glob ruleset");
            goto cleanup;
        }
        spec->glob_patterns = arena_calloc(
            arena, glob_count, sizeof(*spec->glob_patterns)
        );
        if (!spec->glob_patterns) {
            err = ERROR(ERR_MEMORY, "Failed to allocate glob pattern table");
            goto cleanup;
        }
    }

    /* Second pass: populate hashmap and glob storage. */
    for (size_t i = 0; i < count; i++) {
        const char *input = inputs[i];

        /* Glob pattern */
        if (input && strpbrk(input, "*?[")) {
            /* Patterns with '/' must use a storage label or recursive prefix. */
            if (strchr(input, '/') != NULL &&
                !str_starts_with(input, "home/") &&
                !str_starts_with(input, "root/") &&
                !str_starts_with(input, "custom/") &&
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
            spec->glob_patterns[spec->glob_count++] = arena_copy;
            spec->count++;

            err = gitignore_ruleset_append(spec->glob_ruleset, arena_copy, 0);
            if (err) {
                err = error_wrap(err, "Failed to compile glob pattern '%s'", input);
                goto cleanup;
            }
            continue;
        }

        /* Exact path: resolve via shared mount table, store in hashmap. */
        char *resolved = NULL;
        err = mount_resolve_input(input, table, &resolved);
        if (err) {
            err = error_wrap(err, "Invalid path '%s'", input);
            goto cleanup;
        }

        err = hashmap_set(spec->exact_paths, resolved, (void *) 1);
        free(resolved);
        if (err) goto cleanup;
        spec->count++;
    }

    *out = spec;
    return NULL;

cleanup:
    /* glob_ruleset and glob_patterns are arena-borrowed — released
     * with the caller's arena, not here. */
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

    /* Slow path: compiled gitignore ruleset.
     *
     * One gitignore_eval scan honors rule ordering, negation, directory
     * walk-up, and `**` recursive globs consistently with the rest of
     * the ignore stack. Storage paths always reference files, so is_dir
     * is false; directory-only globs still match via walk-up. */
    return gitignore_is_ignored(spec->glob_ruleset, storage_path, false);
}

void pathspec_free(pathspec_t *spec) {
    if (!spec) return;

    /* glob_ruleset and glob_patterns are arena-borrowed — released
     * with the caller's arena, not here. */
    hashmap_free(spec->exact_paths, NULL);
    free(spec);
}
