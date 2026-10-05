/**
 * scope.c - What a command works on: implementation
 */

#include "core/scope.h"

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/label.h"
#include "infra/pathspec.h"
#include "sys/gitops.h"
#include "sys/revision.h"

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

error_t scope_build(
    git_repository *repo, const manifest_t *view, const scope_inputs_t *in,
    arena_t *arena, scope_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(view);
    CHECK_NULL(in);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The scope and everything it holds are the arena's: nothing frees one, and
     * a refusal below leaves only the arena's bytes behind */
    scope_t *s = arena_calloc(arena, 1, sizeof(*s));

    /* 1. The enabled set: the view's profiles — the enabled rows whose branch
     *    the build found (core/manifest.h manifest_profiles) — so the scope and
     *    the view answer one instant's question once. May be empty: an empty
     *    scope is not an error ("Empty-enabled policy", scope.h). */
    size_t count = 0;
    const char *const *names = manifest_profiles(view, &count);
    string_array_init_cap(&s->enabled, arena, count);
    for (size_t i = 0; i < count; i++) {
        string_array_push(&s->enabled, names[i]);
    }
    s->profiles = &s->enabled;

    /* 2. The CLI filter: every name must be enabled here. That is the one question
     *    — the view read the branches on the way in, so a name in the enabled
     *    set is a branch, and a name not in it is refused whether it is a disabled
     *    profile or a typo: a filter that narrowed to nothing would touch nothing
     *    and say nothing. The refusal tells the two apart by asking the refusing
     *    verb, one lookup paid only here: when it does not refuse, the branch
     *    is here and the fact is that it is not enabled. */
    if (in->profile_count > 0) {
        string_array_init_cap(&s->filter, arena, in->profile_count);

        for (size_t i = 0; i < in->profile_count; i++) {
            const char *name = in->profiles[i];
            if (!string_array_contains(&s->enabled, name)) {
                error_t err = profile_require(repo, name);
                if (err) return err;
                return error_create(ERR_INVALID_ARG, "Profile '%s' is not enabled", name);
            }
            string_array_push(&s->filter, name);
        }

        /* 3. The filter is the scope's face — scope_profiles' answer — where it
         *    was given. */
        s->profiles = &s->filter;
    }

    /* 4. The path filter: one matcher over both keys a managed path has, each
     *    input read in the key its own shape names (infra/pathspec) — and none,
     *    every path in, where no positional was given. */
    error_t err = pathspec_create(in->files, in->file_count, arena, &s->paths);
    if (err) return err;

    /* 5. The -e layer, compiled once (core/ignore): a pattern the grammar refuses
     *    refuses the scope, under the flag's name. */
    err = ignore_excludes_compile(
        in->exclude_patterns, in->exclude_count, arena, &s->excludes_ruleset
    );
    if (err) return err;

    *out = s;
    return NULL;
}

/* -------------------------------------------------------------------- */
/* The enabled set as a value                                           */
/* -------------------------------------------------------------------- */

error_t scope_resolve_enabled(
    git_repository *repo, const state_t *state, arena_t *arena, string_array_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The enabled rows, where the handle holds them: nothing below moves them
     * (core/state.h state_profiles) */
    state_profiles_t enabled_profiles = state_profiles(state);

    /* The answer, the arena's: each profile whose branch is here. One that is
     * gone is dropped unsaid — the health commands say it, off the view
     * (core/manifest.h manifest_missing). */
    string_array_t valid_profiles;
    string_array_init(&valid_profiles, arena);

    for (size_t i = 0; i < enabled_profiles.count; i++) {
        const char *profile = enabled_profiles.entries[i].name;

        bool exists = false;
        error_t err = gitops_branch_exists(repo, profile, &exists);
        if (err) return err;
        if (exists) string_array_push(&valid_profiles, profile);
    }

    *out = valid_profiles;
    return NULL;
}

error_t scope_require_enabled(
    const state_t *state, const string_array_t *enabled, arena_t *arena
) {
    CHECK_NULL(state);
    CHECK_NULL(enabled);
    CHECK_NULL(arena);

    if (enabled->count > 0) return NULL;

    /* Empty: the rows say which of the two facts it is. None at all is a set
     * nothing enabled. */
    state_profiles_t enabled_profiles = state_profiles(state);
    if (enabled_profiles.count == 0) {
        return error_create(ERR_NOT_FOUND, "No profile is enabled");
    }

    /* Every row's branch is gone — the set holds each row whose branch is here
     * (the header) — named in apply's words for the same fact (cmds/apply.c
     * cmd_apply's Profiles with no branch), in the arena the caller lent */
    string_array_t names;
    string_array_init_cap(&names, arena, enabled_profiles.count);
    for (size_t i = 0; i < enabled_profiles.count; i++) {
        string_array_push(&names, enabled_profiles.entries[i].name);
    }
    return error_create(
        ERR_NOT_FOUND, "%s '%s' %s enabled, and Git holds no branch for %s",
        enabled_profiles.count == 1 ? "Profile" : "Profiles",
        string_array_join(arena, &names, "', '"),
        enabled_profiles.count == 1 ? "is" : "are",
        enabled_profiles.count == 1 ? "it" : "any of them"
    );
}

/*
 * The search's absence, said of what it searched: every enabled profile, or the
 * ones the filter names — a filter that left the holder out has not made the
 * commit "any enabled profile"'s absence. No cause under it: one profile's sentence
 * is not this one's.
 */
static error_t scope_unheld(const char *commit_ref, const string_array_t *filter) {
    if (!filter) {
        return error_create(
            ERR_NOT_FOUND, "Commit '%s' not found in any enabled profile",
            commit_ref
        );
    }

    /* The names -p gave, joined in the arena the filter keeps them in: an array
     * remembers its arena (base/array.h) */
    return error_create(
        ERR_NOT_FOUND, "Commit '%s' not found in profile%s '%s'", commit_ref,
        filter->count == 1 ? "" : "s", string_array_join(filter->arena, filter, "', '")
    );
}

error_t scope_resolve_commit(
    git_repository *repo, const string_array_t *enabled, const string_array_t *filter,
    const char *commit_ref, git_commit **out_commit, const char **out_profile
) {
    CHECK_NULL(repo);
    CHECK_NULL(enabled);
    CHECK_NULL(commit_ref);
    CHECK_NULL(out_commit);
    CHECK_NULL(out_profile);

    /* The revision once, whatever the set: a spelling that names nothing is its
     * own failure, before any profile could be passed over for it. */
    revision_t rev;
    error_t err = revision_resolve(repo, commit_ref, &rev);
    if (err) return err;

    /* From the highest precedence down: the last enabled wins every path it shares,
     * so its head is the HEAD the view reads. */
    for (size_t i = enabled->count; i-- > 0;) {
        const char *profile = enabled->entries[i];
        if (filter && !string_array_contains(filter, profile)) continue;

        /* The profile's head, read once, and the revision asked of it. A head
         * or a history that will not read ends the search where it stands, whatever
         * a later profile would have said: what comes back is the first holder
         * in precedence order, a claim about every profile ahead of it, and a
         * branch that would not read is one the claim cannot be made over. */
        git_commit *head = NULL;
        err = gitops_load_branch_commit(repo, profile, &head);
        if (err) return err;

        git_commit *commit = NULL;
        err = revision_find(repo, &rev, profile, head, &commit);
        git_commit_free(head);
        if (err) return err;

        /* Nothing is published until a profile answers. */
        if (commit) {
            *out_commit = commit;
            *out_profile = profile;
            return NULL;
        }
    }

    /* Every profile searched was asked, and each said the commit is not its. */
    return scope_unheld(commit_ref, filter);
}

error_t scope_resolve_range(
    git_repository *repo, const string_array_t *enabled, const string_array_t *filter,
    const char *commit1_ref, const char *commit2_ref, git_commit **out_commit1,
    git_commit **out_commit2, const char **out_profile
) {
    CHECK_NULL(repo);
    CHECK_NULL(enabled);
    CHECK_NULL(commit1_ref);
    CHECK_NULL(commit2_ref);
    CHECK_NULL(out_commit1);
    CHECK_NULL(out_commit2);
    CHECK_NULL(out_profile);

    /* Both ends once, before any profile is asked: a spelling that names nothing
     * is its own failure, at either end. */
    revision_t rev1;
    revision_t rev2;
    error_t err = revision_resolve(repo, commit1_ref, &rev1);
    if (err) return err;
    err = revision_resolve(repo, commit2_ref, &rev2);
    if (err) return err;

    /* Each end's first holder alone, for the refusal */
    const char *holder1 = NULL;
    const char *holder2 = NULL;

    /* The single search's order: from the highest precedence down, among what
     * the filter admits. */
    for (size_t i = enabled->count; i-- > 0;) {
        const char *profile = enabled->entries[i];
        if (filter && !string_array_contains(filter, profile)) continue;

        /* The head read once and both ends asked of it, so a range is one head's
         * history. A head or a history that will not read ends the search, as
         * the single search's does. */
        git_commit *head = NULL;
        err = gitops_load_branch_commit(repo, profile, &head);
        if (err) return err;

        git_commit *commit1 = NULL;
        git_commit *commit2 = NULL;
        err = revision_find(repo, &rev1, profile, head, &commit1);
        if (!err) err = revision_find(repo, &rev2, profile, head, &commit2);
        git_commit_free(head);

        /* Nothing is published until a profile holds both. */
        if (commit1 && commit2) {
            *out_commit1 = commit1;
            *out_commit2 = commit2;
            *out_profile = profile;
            return NULL;
        }

        if (commit1 && !holder1) holder1 = profile;
        if (commit2 && !holder2) holder2 = profile;
        git_commit_free(commit1);
        git_commit_free(commit2);
        if (err) return err;
    }

    /* Every profile searched was asked: an end none holds is its absence, and
     * ends held only apart are no one profile's history. */
    if (!holder1) return scope_unheld(commit1_ref, filter);
    if (!holder2) return scope_unheld(commit2_ref, filter);
    return error_create(
        ERR_VALIDATION, "Commits belong to different profiles ('%s' and '%s')",
        holder1, holder2
    );
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
