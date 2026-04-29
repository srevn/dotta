/**
 * scope.h - Operation scope for VWD-touching commands
 *
 * A single typed abstraction for "what subset of the Virtual Working
 * Directory does this invocation touch?". Bundles the three filter
 * dimensions every VWD-touching command carries:
 *
 *   1. Profile filter     — CLI -p <names> (optional)
 *   2. Path filter        — CLI positional file arguments (optional)
 *   3. Exclude patterns   — CLI -e <patterns>            (optional)
 *
 * Plus the persistent enabled set resolved from state. Constructed once
 * per command via scope_build; consulted many times via predicates that
 * replace the per-iteration triplet of `continue` guards at filter sites.
 *
 * Vocabulary
 * ----------
 *   enabled — persistent enabled profile names, always non-NULL, may be
 *             empty. Workspace scope (VWD invariant): workspace_load
 *             reads this via scope_enabled internally; callers pass the
 *             whole scope_t to workspace_load.
 *   active  — display/hook face of the scope. Equal to the CLI filter
 *             names when one was given, else equal to enabled. "What the
 *             user asked for, not the underlying world."
 *   paths   — the CLI-derived path filter (NULL when no positional args).
 *             Exposed for the historical diff paths that thread a raw
 *             pathspec_t through libgit2 pathspec APIs and have no
 *             profile or exclude semantics to honor. In-workspace sites
 *             should prefer scope_accepts_path.
 *
 * The CRITICAL invariant previously expressed as prose comments in
 * apply.c / sync.c ("use enabled, not active, for workspace_load") is
 * now type-enforced: workspace_load takes `const scope_t *` and reads
 * the enabled set internally. Callers cannot pass the wrong array by
 * mistake.
 *
 * Lifetime and ownership
 * ----------------------
 * scope_t is command-scoped and immutable after scope_build returns.
 * All CLI-derived inputs are deep-copied; the caller may free its inputs
 * immediately after scope_build returns. scope_t is entirely
 * self-contained.
 *
 * Lifetime ordering at command cleanup:
 *
 *     workspace_free(ws)   // borrows scope's enabled array — free FIRST
 *     scope_free(scope)    // releases the enabled array — free SECOND
 *
 * scope_enabled's underlying array is owned by scope_t; workspace_t
 * borrows it via its `profiles` field (resolved inside workspace_load).
 * Freeing in the wrong order is a use-after-free in workspace_free's
 * teardown.
 *
 * Empty-enabled policy
 * --------------------
 * scope_build returns success with an empty enabled set — it does NOT
 * translate "no enabled profiles" into an error. Callers apply their own
 * policy:
 *
 *   apply   — empty is a valid convergence target (zero VWD, orphan
 *             cleanup runs). No special handling needed.
 *   status  — empty is a valid degraded mode (everything is an orphan).
 *             No special handling needed.
 *   diff    — empty is user error with exit 0 ("nothing to diff"). Caller
 *             inspects scope_enabled(s)->count and emits its hint.
 *   sync    — empty is user error with exit 1. Each caller emits its own
 *   update    hint inline — the wording differs (sync mentions
 *             --remote), so no shared helper is provided.
 */

#ifndef DOTTA_SCOPE_H
#define DOTTA_SCOPE_H

#include <git2.h>
#include <stdbool.h>
#include <types.h>

#include "infra/pathspec.h"
#include "infra/mount.h"

/* Forward decl: state_t's full API lives in core/state.h. scope only
 * passes the pointer through to profile_resolve_enabled and
 * profile_build_mount_table, so the header stays free of the state
 * dependency. C11 §6.7p3 permits typedef-name redeclaration. */
typedef struct state state_t;

/**
 * Opaque scope handle.
 *
 * Definition lives in scope.c; consumers interact only via the accessors
 * and predicates below.
 */
typedef struct scope scope_t;

/**
 * Aggregated build inputs.
 *
 * A command-agnostic view of the three CLI-derived filter dimensions.
 * All array fields may be NULL when the corresponding count is zero.
 * Config-derived behavior (strict_mode) is read from the config handle
 * passed separately to scope_build, keeping this struct a pure CLI bundle.
 *
 * Ownership: borrowed. scope_build deep-copies everything it needs; the
 * caller may free the backing arrays immediately after scope_build
 * returns.
 */
typedef struct scope_inputs {
    char *const *profiles;          /* -p profile names (raw CLI) */
    size_t profile_count;
    char *const *files;             /* Positional file arguments (raw CLI) */
    size_t file_count;
    char *const *exclude_patterns;  /* -e exclude patterns (raw CLI) */
    size_t exclude_count;
} scope_inputs_t;

/**
 * Build a scope from resolved repo+state and raw CLI inputs.
 *
 * Steps performed (in order):
 *   1. Resolve enabled profile names from state (catches ERR_NOT_FOUND
 *      and converts to empty set — see "Empty-enabled policy" above).
 *   2. If in->profile_count > 0, resolve and validate the CLI filter
 *      against the enabled set (error if any filter name is not enabled).
 *      Strictness of the filter resolution is read from config->strict_mode.
 *   3. Build the mount table from the ACTIVE set (filter if present,
 *      else enabled). Always built — empty active set still yields a
 *      usable handle (HOME + root sentinel only). Narrowing the filter
 *      narrows the topology for path classification.
 *   4. If in->file_count > 0, build the pathspec consuming the mount table.
 *   5. If in->exclude_count > 0, compile patterns into a borrowed-arena
 *      gitignore ruleset.
 *
 * @param repo   Repository (must not be NULL)
 * @param state  State handle (must not be NULL, borrowed for the call)
 * @param in     Inputs (must not be NULL)
 * @param config Configuration (must not be NULL, read for strict_mode)
 * @param arena  Borrowed allocator backing the compiled exclude ruleset
 *               and the path filter's glob storage; must outlive the
 *               returned scope (must not be NULL)
 * @param out    Scope (must not be NULL, caller frees with scope_free)
 * @return Error or NULL on success
 */
error_t *scope_build(
    git_repository *repo,
    const state_t *state,
    const scope_inputs_t *in,
    const config_t *config,
    arena_t *arena,
    scope_t **out
);

/**
 * Free a scope. No-op on NULL.
 */
void scope_free(scope_t *s);

/* -------------------------------------------------------------------- */
/* Definitional accessors                                               */
/* -------------------------------------------------------------------- */

/**
 * Persistent enabled set — VWD scope.
 *
 * Pass this (and ONLY this) to workspace_load. Never the filter.
 * Always non-NULL; the array may be empty (empty VWD is a valid state).
 *
 * The returned pointer is borrowed from scope_t and valid until
 * scope_free.
 */
const string_array_t *scope_enabled(const scope_t *s);

/**
 * Active set — display and hook face of the scope.
 *
 * Equal to the CLI filter names when -p was given, else equal to
 * scope_enabled(s). Use this for hook context strings ("what the user
 * asked for") and for verbose output.
 *
 * Always non-NULL. Borrowed; valid until scope_free.
 */
const string_array_t *scope_active(const scope_t *s);

/* -------------------------------------------------------------------- */
/* Raw-dimension accessors                                              */
/* -------------------------------------------------------------------- */

/**
 * Raw path filter (NULL when no positional file args were given).
 *
 * Long-term: consumers that only care about the path dimension and
 * inspect the pathspec_t struct directly (e.g., diff's historical
 * modes passing through to libgit2 pathspecs, filter-coverage
 * validation) use this. Per-iteration path-vs-filter checks should use
 * scope_accepts_path instead.
 *
 * Borrowed; valid until scope_free.
 */
const pathspec_t *scope_paths(const scope_t *s);

/**
 * Per-machine deployment topology, built from the active set.
 *
 * Always non-NULL after scope_build returns. When the active set is
 * empty or no profile has a deployment target, the handle still carries
 * HOME and the empty-prefix root sentinel, so path classification still
 * works.
 *
 * Lifetime: arena-borrowed. The pointer is valid until the arena
 * passed to scope_build is destroyed; that arena MUST outlive scope_t.
 * scope_free does not release the roots — arena_destroy does.
 *
 * Borrow chain: target strings come from the state row cache.
 * The VWD-command structure (no enabled_profiles shape mutation between
 * scope_build and scope_free) keeps them valid. profile names are
 * arena_strdup'd into the bindings, so they are decoupled from
 * scope_t's heap-owned filter/enabled arrays.
 */
const mount_table_t *scope_roots(const scope_t *s);

/* -------------------------------------------------------------------- */
/* Build-shape predicates                                               */
/* -------------------------------------------------------------------- */

/** True if a CLI profile filter was given (-p). */
bool scope_has_filter(const scope_t *s);

/** True if CLI positional file arguments were given. */
bool scope_has_paths(const scope_t *s);

/* -------------------------------------------------------------------- */
/* Per-iteration predicates                                             */
/* -------------------------------------------------------------------- */

/**
 * Profile dimension check.
 *
 * NULL profile returns false (defensive — a NULL name never matches,
 * even the "match all" case). When no CLI filter was given, every
 * non-NULL profile matches.
 */
bool scope_accepts_profile(const scope_t *s, const char *profile);

/**
 * Path dimension check.
 *
 * When no path filter was built, any non-NULL storage_path matches
 * (matches pathspec_matches semantics). NULL storage_path returns
 * false.
 */
bool scope_accepts_path(const scope_t *s, const char *storage_path);

/**
 * Exclude dimension check.
 *
 * Returns true when storage_path IS excluded by a CLI -e pattern
 * (asymmetric with scope_accepts_* by design — reads naturally at call
 * sites: `if (scope_is_excluded(s, p)) { ... }`).
 *
 * Uses gitignore semantics via base/gitignore: `!`-negation, directory
 * walk-up (so `-e 'build/'` matches files under `build/`), anchoring,
 * and `**` recursive globs. NULL storage_path or no exclude patterns
 * returns false.
 */
bool scope_is_excluded(const scope_t *s, const char *storage_path);

/**
 * Combined per-iteration check.
 *
 * Equivalent to:
 *     scope_accepts_profile(s, profile)
 *         && scope_accepts_path(s, storage_path)
 *         && !scope_is_excluded(s, storage_path)
 *
 * Use at sites that do not need by-reason granularity. Sites that count
 * or report exclusion reasons separately should use the three granular
 * predicates above.
 */
bool scope_accepts_entry(
    const scope_t *s,
    const char *profile,
    const char *storage_path
);

#endif /* DOTTA_SCOPE_H */
