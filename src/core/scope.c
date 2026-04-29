/**
 * scope.c - Operation scope implementation
 */

#include "core/scope.h"

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "base/array.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"
#include "infra/pathspec.h"

/**
 * Internal scope representation.
 *
 * `enabled`, `filter`, and `paths` are owned by scope_t and freed in
 * scope_free. `active` is a borrowed pointer into either `enabled` or
 * `filter` — set once during build, dangles after scope_free returns
 * (which is fine: no one is meant to dereference it post-free).
 *
 * `excludes_ruleset` and `mounts` are arena-borrowed (typically from
 * `ctx->arena`); both are released by arena_destroy, not scope_free.
 * Matching for the excludes ruleset goes through base/gitignore for full
 * `!`-negation, directory walk-up, and anchoring semantics — the same
 * engine that powers the layered `.dottaignore` ruleset in core/ignore.
 *
 * `mounts` is always non-NULL post-build: scope_build always calls
 * profile_build_mount_table (even when there are no positional file args
 * and no custom targets). Downstream consumers (pathspec_create,
 * manifest_build in PR 3+) consult it without per-callsite NULL guards.
 */
struct scope {
    string_array_t *enabled;            /* Persistent enabled set; non-NULL, may be empty */
    string_array_t *filter;             /* CLI filter; NULL when no -p */
    gitignore_ruleset_t *excludes_ruleset; /* Compiled -e patterns; arena-borrowed; NULL when no excludes */
    pathspec_t *paths;                  /* CLI path filter; NULL when no positional args */
    const mount_table_t *mounts;        /* Mount table; arena-borrowed; non-NULL post-build */
    const string_array_t *active;       /* Borrowed: filter if set, else enabled */
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
 * Compile exclude patterns into a gitignore ruleset in the caller's arena.
 *
 * Pre-compiling the ruleset (rather than storing raw strings) lets
 * scope_is_excluded reduce to a single gitignore_is_ignored call per
 * query, with full gitignore semantics: `!`-negation, directory walk-up,
 * anchoring, and `**` recursive globs. Matches the engine used for
 * .dottaignore so the `-e` CLI flag is consistent with all other
 * exclusion surfaces.
 *
 * The ruleset is borrowed from `arena`; the caller's arena lifetime
 * governs it. Leaves *out_rules NULL when the input array is empty —
 * the zero-excludes case touches the arena only when patterns exist.
 */
static error_t *compile_excludes(
    char *const *patterns,
    size_t count,
    arena_t *arena,
    gitignore_ruleset_t **out_rules
) {
    *out_rules = NULL;
    if (count == 0) return NULL;

    gitignore_ruleset_t *rules = NULL;
    error_t *err = gitignore_ruleset_create(arena, &rules);
    if (err) {
        return error_wrap(err, "Failed to allocate excludes ruleset");
    }

    err = gitignore_ruleset_append_patterns(
        rules, (const char *const *) patterns, count, 0
    );
    if (err) {
        return error_wrap(err, "Failed to compile CLI exclude patterns");
    }

    *out_rules = rules;
    return NULL;
}

error_t *scope_build(
    git_repository *repo,
    const state_t *state,
    const scope_inputs_t *in,
    const config_t *config,
    arena_t *arena,
    scope_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(in);
    CHECK_NULL(config);
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

    /* 2. Resolve and validate CLI filter, if any. */
    if (in->profile_count > 0) {
        err = profile_resolve_filter(
            repo, in->profiles, in->profile_count, config->strict_mode, &s->filter
        );
        if (err) {
            err = error_wrap(err, "Failed to resolve filter profiles");
            goto fail;
        }

        err = profile_validate_filter(s->enabled, s->filter);
        if (err) goto fail;  /* validate_filter returns a user-facing message */
    }

    /* 3. Derive active pointer — used for the mount-table build and by
     *    scope_active accessor. Valid as long as scope is alive. */
    s->active = s->filter ? s->filter : s->enabled;

    /* 4. Build the mount table from the active set.
     *    Always built — empty active set still yields a usable handle
     *    (HOME + root sentinel only), and downstream consumers
     *    (pathspec_create, future manifest_build) can rely on a
     *    non-NULL scope_mounts without per-callsite guards.
     *    Narrowing the filter narrows the mount table: a profile that is
     *    enabled-but-filtered-out does not contribute its custom target
     *    to path classification for this invocation. */
    mount_table_t *mounts = NULL;
    err = profile_build_mount_table(state, s->active, arena, &mounts);
    if (err) {
        err = error_wrap(err, "Failed to build mount table");
        goto fail;
    }
    s->mounts = mounts;

    /* 5. Build path filter consuming the mount table directly — no
     *    intermediate prefix-array round-trip. */
    if (in->file_count > 0) {
        err = pathspec_create(
            in->files, in->file_count, s->mounts, arena, &s->paths
        );
        if (err) {
            err = error_wrap(err, "Failed to build path filter");
            goto fail;
        }
    }

    /* 6. Compile excludes into a ruleset borrowed from the caller's arena. */
    err = compile_excludes(
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
    /* excludes_ruleset and mounts are arena-borrowed — released with the
     * caller's arena, not here. */
    pathspec_free(s->paths);
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

const pathspec_t *scope_paths(const scope_t *s) {
    return s->paths;
}

const mount_table_t *scope_mounts(const scope_t *s) {
    return s->mounts;
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
    return pathspec_matches(s->paths, storage_path);
}

bool scope_is_excluded(const scope_t *s, const char *storage_path) {
    /* Storage paths always reference files (validated by
     * mount_validate_storage), so is_dir is always false. Directory-
     * only exclude patterns (e.g. `-e 'build/'`) still match files
     * inside the directory via gitignore's walk-up semantics. */
    return gitignore_is_ignored(s->excludes_ruleset, storage_path, false);
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
