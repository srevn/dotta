/**
 * scope.c - Operation scope implementation
 */

#include "core/scope.h"

#include <stdlib.h>
#include <string.h>

#include "base/array.h"
#include "base/error.h"
#include "base/match.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/path.h"

/**
 * Internal scope representation.
 *
 * All fields except `active` are owned by scope_t and freed in
 * scope_free. `active` is a borrowed pointer into either `enabled` or
 * `filter` — set once during build, dangles after scope_free returns
 * (which is fine: no one is meant to dereference it post-free).
 */
struct scope {
    string_array_t *enabled;        /* Persistent enabled set; non-NULL, may be empty */
    string_array_t *filter;         /* CLI filter; NULL when no -p */
    string_array_t *excludes;       /* Deep-copied exclude patterns; NULL when none */
    path_filter_t *paths;           /* CLI path filter; NULL when no positional args */
    const string_array_t *active;   /* Borrowed: filter if set, else enabled */
};

/* -------------------------------------------------------------------- */
/* Construction                                                         */
/* -------------------------------------------------------------------- */

/**
 * Resolve the enabled set, converting ERR_NOT_FOUND to an empty array.
 *
 * profile_resolve_enabled returns ERR_NOT_FOUND on zero enabled
 * profiles; scope_build's contract is "empty enabled is not an error".
 * This helper smooths that boundary.
 */
static error_t *resolve_enabled_lenient(
    git_repository *repo,
    const state_t *state,
    string_array_t **out_enabled
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

/**
 * Deep-copy exclude patterns into a fresh string_array_t.
 *
 * Centralizing this (rather than borrowing the opts pointer) removes
 * the implicit "scope lifetime ⊆ opts lifetime" constraint — scope_t
 * becomes entirely self-contained after scope_build returns.
 */
static error_t *copy_excludes(
    char *const *patterns,
    size_t count,
    string_array_t **out
) {
    *out = NULL;
    if (count == 0) return NULL;

    string_array_t *copy = string_array_new(count);
    if (!copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate excludes array");
    }

    for (size_t i = 0; i < count; i++) {
        error_t *err = string_array_push(copy, patterns[i]);
        if (err) {
            string_array_free(copy);
            return error_wrap(err, "Failed to copy exclude pattern");
        }
    }

    *out = copy;
    return NULL;
}

error_t *scope_build(
    git_repository *repo,
    const state_t *state,
    const scope_inputs_t *in,
    scope_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(in);
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

    /* 2. Resolve and validate CLI filter, if any. */
    if (in->profile_count > 0) {
        err = profile_resolve_filter(
            repo, in->profiles, in->profile_count, in->strict_mode, &s->filter
        );
        if (err) {
            err = error_wrap(err, "Failed to resolve filter profiles");
            goto fail;
        }

        err = profile_validate_filter(s->enabled, s->filter);
        if (err) goto fail;  /* validate_filter returns a user-facing message */
    }

    /* 3. Derive active pointer — used for prefix harvest and by
     *    scope_active accessor. Valid as long as scope is alive. */
    s->active = s->filter ? s->filter : s->enabled;

    /* 4. Build path filter with prefixes harvested from the active set.
     *    Narrowing the filter narrows prefix harvest: a profile that
     *    is enabled-but-filtered-out does not contribute its custom
     *    prefix to path resolution for this invocation. */
    if (in->file_count > 0) {
        string_array_t *prefixes = NULL;
        err = profile_load_custom_prefixes(repo, state, s->active, &prefixes);
        if (err) {
            err = error_wrap(err, "Failed to harvest custom prefixes");
            goto fail;
        }

        err = path_filter_create(
            in->files, in->file_count, (const char *const *) prefixes->items,
            prefixes->count, &s->paths
        );
        string_array_free(prefixes);
        if (err) {
            err = error_wrap(err, "Failed to build path filter");
            goto fail;
        }
    }

    /* 5. Deep-copy excludes. */
    err = copy_excludes(in->exclude_patterns, in->exclude_count, &s->excludes);
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
    string_array_free(s->excludes);
    path_filter_free(s->paths);
    /* s->active is a borrow; do not free. */
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

const path_filter_t *scope_paths(const scope_t *s) {
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

bool scope_accepts_path(const scope_t *s, const char *storage_path) {
    return path_filter_matches(s->paths, storage_path);
}

bool scope_is_excluded(const scope_t *s, const char *storage_path) {
    if (!storage_path || !s->excludes || s->excludes->count == 0) {
        return false;
    }
    return match_any(
        s->excludes->items,
        s->excludes->count,
        storage_path,
        MATCH_DOUBLESTAR
    );
}

bool scope_accepts_entry(
    const scope_t *s,
    const char *profile,
    const char *storage_path
) {
    return scope_accepts_profile(s, profile)
           && scope_accepts_path(s, storage_path)
           && !scope_is_excluded(s, storage_path);
}
