/**
 * scope.c - Operation scope implementation
 */

#include "core/scope.h"

#include <stdlib.h>
#include <string.h>

#include "base/array.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "core/ignore.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"
#include "infra/pathspec.h"

/**
 * Internal scope representation.
 *
 * `enabled` and `filter` are owned by scope_t and freed in scope_free. `active`
 * is a borrowed pointer into either `enabled` or `filter` — set once during build,
 * dangles after scope_free returns (which is fine: no one is meant to dereference
 * it post-free).
 *
 * `paths` and `excludes_ruleset` are arena-borrowed (typically from `ctx->arena`);
 * released by arena_destroy, not scope_free. The excludes are the -e layer
 * core/ignore compiles (ignore_excludes_compile) — the rules add's builder takes
 * as its top layer, asked alone here (scope_is_excluded).
 *
 * The mount table is supplied by the caller (typically `ctx->run.mounts`) and
 * consumed by pathspec_create only. scope_t does not store it — per-machine
 * topology has process scope, not per-scope_build scope.
 */
struct scope {
    string_array_t *enabled;            /* Persistent enabled set; non-NULL, may be empty */
    string_array_t *filter;             /* CLI filter; NULL when no -p */
    const gitignore_ruleset_t *excludes_ruleset; /* The -e layer; arena-borrowed; NULL when no excludes */
    pathspec_t *paths;                  /* CLI path filter; arena-borrowed; NULL when no positional args */
    const string_array_t *active;       /* Borrowed: filter if set, else enabled */
};

/* -------------------------------------------------------------------- */
/* Construction                                                         */
/* -------------------------------------------------------------------- */

/**
 * Resolve the enabled set, converting ERR_NOT_FOUND to an empty array.
 *
 * profile_resolve_enabled returns ERR_NOT_FOUND on zero enabled profiles;
 * scope_build's contract is "empty enabled is not an error". This helper smooths
 * that boundary.
 */
static error_t *resolve_enabled_lenient(
    git_repository *repo, const state_t *state, string_array_t **out_enabled
) {
    error_t *err = profile_resolve_enabled(repo, state, out_enabled);
    if (!err) return NULL;

    if (err->code != ERR_NOT_FOUND) {
        return error_wrap(err, "Failed to resolve enabled profiles");
    }

    error_free(err);
    *out_enabled = string_array_new(0);
    if (!*out_enabled) {
        return ERROR(ERR_MEMORY, "Failed to allocate empty enabled array");
    }

    return NULL;
}

error_t *scope_build(
    git_repository *repo, const state_t *state, const scope_inputs_t *in,
    const mount_table_t *mounts, arena_t *arena, scope_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(in);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    scope_t *s = calloc(1, sizeof(*s));
    if (!s) {
        return ERROR(ERR_MEMORY, "Failed to allocate scope");
    }

    error_t *err = NULL;

    /* 1. Resolve enabled (empty-on-ERR_NOT_FOUND). */
    err = resolve_enabled_lenient(repo, state, &s->enabled);
    if (err) goto fail;

    /* 2. The CLI filter: every name must be enabled here. That is the one question
     *    — the enabled set was checked against the branches on the way in, so a
     *    name in it is a branch, and a name not in it is refused whether it is
     *    a disabled profile or a typo: a filter that narrowed to nothing would
     *    touch nothing and say nothing. The refusal tells the two apart by asking
     *    the refusing verb, one lookup paid only here: when it does not refuse,
     *    the branch is here and the fact is that it is not enabled. */
    if (in->profile_count > 0) {
        s->filter = string_array_new(in->profile_count);
        if (!s->filter) {
            err = ERROR(ERR_MEMORY, "Failed to allocate filter profiles");
            goto fail;
        }

        for (size_t i = 0; i < in->profile_count; i++) {
            const char *name = in->profiles[i];
            if (!string_array_contains(s->enabled, name)) {
                err = profile_require(repo, name);
                if (!err) {
                    err = ERROR(
                        ERR_INVALID_ARG, "Profile '%s' is not enabled\n"
                        "Hint: Run 'dotta profile enable %s' first", name, name
                    );
                }
                goto fail;
            }
            err = string_array_push(s->filter, name);
            if (err) goto fail;
        }
    }

    /* 3. Derive active pointer — used by scope_active accessor. Valid as long
     *    as scope is alive. */
    s->active = s->filter ? s->filter : s->enabled;

    /* 4. Build path filter consuming the caller-supplied mount table — its
     *    filesystem shapes located through it, no intermediate round-trip. The
     *    mount table is borrowed for this call only; scope_t does not store it. */
    if (in->file_count > 0) {
        err = pathspec_create(in->files, in->file_count, mounts, arena, &s->paths);
        if (err) {
            err = error_wrap(err, "Failed to build path filter");
            goto fail;
        }
    }

    /* 5. The -e layer, compiled once (core/ignore): a pattern the grammar refuses
     *    refuses the scope, under the flag's name. */
    err = ignore_excludes_compile(
        in->exclude_patterns, in->exclude_count, arena, &s->excludes_ruleset
    );
    if (err) goto fail;

    *out = s;
    return NULL;

fail:
    scope_free(s);
    return err;
}

void scope_free(scope_t *s) {
    if (!s) return;
    string_array_free(s->enabled);
    string_array_free(s->filter);
    /* s->paths and s->excludes_ruleset are the arena's; s->active is a borrow. */
    free(s);
}

/* -------------------------------------------------------------------- */
/* Definitional accessors                                               */
/* -------------------------------------------------------------------- */

const string_array_t *scope_enabled(const scope_t *s) {
    return s->enabled;
}

const string_array_t *scope_active(const scope_t *s) {
    return s->active;
}

const pathspec_t *scope_paths(const scope_t *s) {
    return s->paths;
}

/* -------------------------------------------------------------------- */
/* Build-shape predicates                                               */
/* -------------------------------------------------------------------- */

bool scope_has_filter(const scope_t *s) {
    return s->filter != NULL;
}

bool scope_has_paths(const scope_t *s) {
    return s->paths != NULL;
}

/* -------------------------------------------------------------------- */
/* Per-iteration predicates                                             */
/* -------------------------------------------------------------------- */

bool scope_accepts_profile(const scope_t *s, const char *profile) {
    /* Defensive: a NULL profile never matches anything, even "match all". */
    if (!profile) return false;

    /* No CLI filter → every non-NULL profile is in scope. */
    if (!s->filter) return true;

    for (size_t i = 0; i < s->filter->count; i++) {
        if (strcmp(profile, s->filter->items[i]) == 0) return true;
    }
    return false;
}

bool scope_accepts_path(
    const scope_t *s, const char *filesystem_path, const char *storage_path,
    path_kind_t kind
) {
    return pathspec_matches(s->paths, filesystem_path, storage_path, kind);
}

bool scope_is_excluded(
    const scope_t *s, const char *storage_path, path_kind_t kind
) {
    return gitignore_is_ignored(
        s->excludes_ruleset, mount_strip_label(storage_path),
        kind == PATH_KIND_DIRECTORY
    );
}

bool scope_accepts_entry(
    const scope_t *s, const char *profile, const char *filesystem_path,
    const char *storage_path, path_kind_t kind
) {
    return scope_accepts_profile(s, profile)
           && scope_accepts_path(s, filesystem_path, storage_path, kind)
           && !scope_is_excluded(s, storage_path, kind);
}
