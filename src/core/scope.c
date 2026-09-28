/**
 * scope.c - Operation scope implementation
 */

#include "core/scope.h"

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "core/ignore.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/label.h"
#include "infra/pathspec.h"

/**
 * Internal scope representation.
 *
 * A value of the arena scope_build is handed, as everything it holds is: the
 * two name lists, the path filter and the exclude layer. `profiles` points at
 * one of the two lists — the filter when -p was given, else the enabled set —
 * set once during build. The excludes are the -e layer core/ignore compiles
 * (ignore_excludes_compile) — the rules add's builder takes as its top layer,
 * asked alone here (scope_is_excluded).
 */
struct scope {
    string_array_t enabled;             /* Persistent enabled set; may be empty */
    string_array_t filter;              /* CLI filter: every name -p gave, each enabled; empty without -p */
    const gitignore_ruleset_t *excludes_ruleset; /* The -e layer; NULL when no excludes */
    pathspec_t *paths;                  /* CLI path filter; NULL when no positional args */
    const string_array_t *profiles;     /* &filter when -p was given, else &enabled */
};

/* -------------------------------------------------------------------- */
/* Construction                                                         */
/* -------------------------------------------------------------------- */

error_t *scope_build(
    git_repository *repo, const state_t *state, const scope_inputs_t *in,
    arena_t *arena, scope_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(in);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The scope and everything it holds are the arena's: nothing frees one, and
     * a refusal below leaves only the arena's bytes behind */
    scope_t *s = arena_calloc(arena, 1, sizeof(*s));

    /* 1. The enabled set, which may be empty: an empty scope is not an error
     *    ("Empty-enabled policy", scope.h). */
    error_t *err = profile_resolve_enabled(repo, state, arena, &s->enabled);
    if (err) return error_wrap(err, "Failed to resolve enabled profiles");
    s->profiles = &s->enabled;

    /* 2. The CLI filter: every name must be enabled here. That is the one question
     *    — the enabled set was checked against the branches on the way in, so a
     *    name in it is a branch, and a name not in it is refused whether it is
     *    a disabled profile or a typo: a filter that narrowed to nothing would
     *    touch nothing and say nothing. The refusal tells the two apart by asking
     *    the refusing verb, one lookup paid only here: when it does not refuse,
     *    the branch is here and the fact is that it is not enabled. */
    if (in->profile_count > 0) {
        string_array_init_cap(&s->filter, arena, in->profile_count);

        for (size_t i = 0; i < in->profile_count; i++) {
            const char *name = in->profiles[i];
            if (!string_array_contains(&s->enabled, name)) {
                RETURN_IF_ERROR(profile_require(repo, name));
                return ERROR(
                    ERR_INVALID_ARG, "Profile '%s' is not enabled\n"
                    "Hint: Run 'dotta profile enable %s' first", name, name
                );
            }
            string_array_push(&s->filter, name);
        }

        /* 3. The filter is the scope's face — scope_profiles' answer — where it
         *    was given. */
        s->profiles = &s->filter;
    }

    /* 4. The path filter: one matcher over both keys a managed path has, each
     *    input read in the key its own shape names (infra/pathspec). */
    if (in->file_count > 0) {
        err = pathspec_create(in->files, in->file_count, arena, &s->paths);
        if (err) return error_wrap(err, "Failed to build path filter");
    }

    /* 5. The -e layer, compiled once (core/ignore): a pattern the grammar refuses
     *    refuses the scope, under the flag's name. */
    RETURN_IF_ERROR(
        ignore_excludes_compile(
        in->exclude_patterns, in->exclude_count, arena, &s->excludes_ruleset
        )
    );

    *out = s;
    return NULL;
}

/* -------------------------------------------------------------------- */
/* Definitional accessors                                               */
/* -------------------------------------------------------------------- */

const string_array_t *scope_enabled(const scope_t *s) {
    return &s->enabled;
}

const string_array_t *scope_profiles(const scope_t *s) {
    return s->profiles;
}

const pathspec_t *scope_paths(const scope_t *s) {
    return s->paths;
}

/* -------------------------------------------------------------------- */
/* Build-shape predicates                                               */
/* -------------------------------------------------------------------- */

bool scope_filters_profiles(const scope_t *s) {
    return s->filter.count > 0;
}

bool scope_filters_paths(const scope_t *s) {
    return s->paths != NULL;
}

/* -------------------------------------------------------------------- */
/* Per-iteration predicates                                             */
/* -------------------------------------------------------------------- */

bool scope_accepts_profile(const scope_t *s, const char *profile) {
    /* Defensive: a NULL profile never matches anything, even "match all". */
    if (!profile) return false;

    /* No CLI filter → every non-NULL profile is in scope. */
    return s->filter.count == 0 || string_array_contains(&s->filter, profile);
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
        s->excludes_ruleset, label_tail(storage_path),
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
