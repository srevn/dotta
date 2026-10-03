/**
 * scope.h - Operation scope for view-touching commands
 *
 * A single typed abstraction for "what subset of the view — every enabled profile
 * at HEAD, precedence resolved — does this invocation touch?". Bundles the three
 * filter dimensions every such command carries:
 *
 *   1. Profile filter     — CLI -p <names> (optional)
 *   2. Path filter        — CLI positional file arguments (optional)
 *   3. Exclude patterns   — CLI -e <patterns>            (optional)
 *
 * Plus the persistent enabled set, read off the view. Constructed once per command
 * via scope_build; consulted many times via predicates that replace the
 * per-iteration triplet of `continue` guards at filter sites.
 *
 * Vocabulary
 * ----------
 *   enabled  — persistent enabled profile names, always non-NULL, may be empty:
 *              the view's profiles (manifest_profiles), the enabled rows whose
 *              branch the build found, so the scope and the view answer one
 *              instant's question once — the set the CLI filter is checked against,
 *              and the one the receipts attribute to (sync). The workspace reads
 *              the same names off the view itself.
 *   profiles — display/hook face of the scope. Equal to the CLI filter names
 *              when one was given, else equal to enabled. "What the user asked
 *              for, not the underlying world."
 *   paths    — the CLI-derived path filter (NULL when no positional args), one
 *              matcher over the two keys a managed path has: its filesystem path
 *              and its storage path (infra/pathspec). Exposed for diff, which
 *              selects a commit range delta by delta, compares a commit's view
 *              under it, and answers the filter's coverage over the view each
 *              arm compares (pathspec_entry_at, pathspec_entry_matches_at), and
 *              for apply's count line (pathspec_count); none of them has a profile
 *              or exclude semantics to honor. In-workspace sites should prefer
 *              scope_accepts_path.
 *
 * The CRITICAL invariant previously expressed as prose comments in apply.c /
 * sync.c — load the enabled set, never the filter — is enforced by construction:
 * the workspace never takes a profile list — the view it joins is built over
 * the state's rows, and its profile set is the view's. A CLI filter narrows what
 * a command touches, never what it loads.
 *
 * Lifetime and ownership
 * ----------------------
 * scope_t is a value of the arena scope_build is handed — the struct, both name
 * lists and the compiled filters — immutable once built, and nothing frees one.
 * Every CLI-derived input is copied there, so the caller's inputs may go once
 * scope_build returns.
 *
 * Empty-enabled policy
 * --------------------
 * scope_build returns success with an empty enabled set — it does NOT translate
 * "no enabled profiles" into an error. The set is the readable one, the enabled
 * rows whose branch is here, so empty it is one of two facts: nothing enabled,
 * or no enabled profile Git holds a branch for. Callers apply their own policy,
 * and those that speak of an empty set take its words from one producer
 * (core/profiles.h profile_require_enabled), which tells the two apart:
 *
 *   apply   — empty is a valid convergence target (an empty view, orphan
 *             cleanup runs). No special handling needed.
 *   status  — empty is a valid degraded mode (everything is an orphan).
 *             No special handling needed.
 *   diff    — nothing to diff: warned, exit 0.
 *   sync    — refused, exit 1.
 *   update
 */

#ifndef DOTTA_SCOPE_H
#define DOTTA_SCOPE_H

#include <git2.h>
#include <stdbool.h>
#include <types.h>

#include "infra/pathspec.h"

/* Forward decl: manifest_t's full API lives in core/manifest.h. scope reads the
 * view's profiles alone, so the header stays free of the manifest dependency.
 * C11 §6.7p3 permits typedef-name redeclaration. */
typedef struct manifest manifest_t;

/**
 * Opaque scope handle.
 *
 * Definition lives in scope.c; consumers interact only via the accessors and
 * predicates below.
 */
typedef struct scope scope_t;

/**
 * Aggregated build inputs.
 *
 * A command-agnostic view of the three CLI-derived filter dimensions. All array
 * fields may be NULL when the corresponding count is zero.
 *
 * Ownership: borrowed. scope_build deep-copies everything it needs; the caller
 * may free the backing arrays immediately after scope_build returns.
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
 * Build a scope from the view and raw CLI inputs.
 *
 * Steps performed (in order):
 *   1. Read the enabled profile names off the view — the enabled rows whose branch
 *      the build found (core/manifest.h manifest_profiles) — which may be none
 *      (see "Empty-enabled policy" above).
 *   2. If in->profile_count > 0, check every CLI filter name against the enabled
 *      set: one not in it is refused, whether it is a disabled profile ("is not
 *      enabled") or no profile here at all (profile_require's refusal). A filter
 *      never narrows in silence.
 *   3. Compile the positional arguments into the path filter (infra/pathspec):
 *      one matcher over the two keys a managed path has, each input read in the
 *      key its own shape names — none, every path in, where none was given.
 *   4. Compile the -e layer into `arena` (ignore_excludes_compile): a pattern
 *      the grammar refuses refuses the build, under the flag's name.
 *
 * @param repo   Repository: a -p name that is not enabled is asked of it, to tell
 *               a disabled profile from none here (must not be NULL)
 * @param view   The view the command reads, ctx->run.manifest or one it built
 *               (must not be NULL, borrowed for the call)
 * @param in     Inputs (must not be NULL)
 * @param arena  Arena the scope lives in, and everything it holds (must not be
 *               NULL)
 * @param out    Scope (must not be NULL; left as it was on a refusal)
 * @return Error or NULL on success
 */
error_t scope_build(
    git_repository *repo,
    const manifest_t *view,
    const scope_inputs_t *in,
    arena_t *arena,
    scope_t **out
);

/* -------------------------------------------------------------------- */
/* Definitional accessors                                               */
/* -------------------------------------------------------------------- */

/**
 * Persistent enabled set — the view's scope.
 *
 * The enabled profiles, validated against the branches, in precedence order.
 * Never the filter. Always non-NULL; the array may be empty (an empty view is a
 * valid state). Borrowed from the scope.
 */
const string_array_t *scope_enabled(const scope_t *s);

/**
 * The scope's profiles — its display and hook face.
 *
 * Equal to the CLI filter names when -p was given, else equal to scope_enabled(s).
 * Use this for hook context strings ("what the user asked for") and for verbose
 * output.
 *
 * Always non-NULL. Borrowed from the scope.
 */
const string_array_t *scope_profiles(const scope_t *s);

/* -------------------------------------------------------------------- */
/* Raw-dimension accessors                                              */
/* -------------------------------------------------------------------- */

/**
 * Raw path filter (NULL when no positional file args were given).
 *
 * Consumers that read the filter itself — diff (a commit range selected delta
 * by delta, a commit's view compared under it, the coverage answers over the
 * compiled entries: cmds/diff.c select_delta, compare_tree_files_to_filesystem,
 * validate_filter_paths) and apply's count line (cmds/apply.c cmd_apply) — use
 * this with the pathspec accessors (pathspec_count / pathspec_entry_at /
 * pathspec_entry_matches_at). Per-iteration path-vs-filter checks should use
 * scope_accepts_path instead.
 *
 * Borrowed from the scope.
 */
const pathspec_t *scope_paths(const scope_t *s);

/* -------------------------------------------------------------------- */
/* Build-shape predicates                                               */
/* -------------------------------------------------------------------- */

/** True if a CLI profile filter was given (-p). */
bool scope_filters_profiles(const scope_t *s);

/** True if CLI positional file arguments were given. */
bool scope_filters_paths(const scope_t *s);

/* -------------------------------------------------------------------- */
/* Per-iteration predicates                                             */
/* -------------------------------------------------------------------- */

/**
 * Profile dimension check.
 *
 * NULL profile returns false (defensive — a NULL name never matches, even the
 * "match all" case). When no CLI filter was given, every non-NULL profile matches.
 */
bool scope_accepts_profile(const scope_t *s, const char *profile);

/**
 * Path dimension check.
 *
 * Both names of the subject: a filter entry reads the one in its own vocabulary
 * — a filesystem shape the filesystem path, a storage shape or a bare pattern
 * the name (pathspec_matches). When no path filter was built, every subject
 * matches. A name the caller does not have is NULL and is read by no entry of
 * that vocabulary; a subject with neither name matches nothing under a filter.
 *
 * `kind` is the manifest's kind of the path — PATH_KIND_DIRECTORY for a tracked
 * directory even when a file currently squats it on disk. State file rows are
 * always PATH_KIND_FILE; workspace items carry item_kind.
 */
bool scope_accepts_path(
    const scope_t *s,
    const char *filesystem_path,
    const char *storage_path,
    path_kind_t kind
);

/**
 * Exclude dimension check.
 *
 * Returns true when storage_path IS excluded by a CLI -e pattern (asymmetric
 * with scope_accepts_* by design — reads naturally at call sites: `if
 * (scope_is_excluded(s, p, k)) { ... }`).
 *
 * Uses gitignore semantics via base/gitignore: `!`-negation, directory walk-up
 * (so `-e 'build/'` matches files under `build/`), anchoring, and `**` recursive
 * globs, evaluated on the mount-relative path (infra/label.h `label_tail`): `-e
 * '.cache/x/'` names `~/.cache/x`, as it would in `.dottaignore`. A directory-only
 * pattern (`build/`) matches the directory itself only for PATH_KIND_DIRECTORY
 * — the kind is what makes `-e 'dir/'` mean "leave that directory alone" for
 * the directory as well as its contents. NULL storage_path or no exclude patterns
 * returns false.
 *
 * It is exclusion, not selection, and an excluded directory is final: `-e 'build/'
 * -e '!build/keep'` does not keep the file, because nothing beneath an excluded
 * directory can be re-included (base/gitignore.h). The escape is git's own idiom:
 * name the contents rather than the directory — `build/` with a star after the
 * slash — and the `!` beneath it stands, because a pattern that matches no
 * directory builds no barrier. One flag, one compile (ignore_excludes_compile),
 * one program — exclusion, as add's walk reads it — and two roles. Here the rules
 * are asked alone, of paths the command already holds, which `.dottaignore` has
 * no say over: a `!` answers only the -e rules before it. On `add`, whose walk
 * discovers paths, the same rules are the top layer of `.dottaignore`'s ruleset,
 * and a `!` also re-admits what a lower layer excluded. update's discovery scan
 * reads no -e (core/workspace), so on update a new file a lower layer excluded
 * is never nominated, whatever -e says.
 */
bool scope_is_excluded(
    const scope_t *s, const char *storage_path, path_kind_t kind
);

/**
 * Combined per-iteration check.
 *
 * Equivalent to:
 *     scope_accepts_profile(s, profile) && scope_accepts_path(s, filesystem_path,
 *         storage_path, kind) && !scope_is_excluded(s, storage_path, kind)
 *
 * Use at sites that do not need by-reason granularity. Sites that count or report
 * exclusion reasons separately should use the three granular predicates above.
 */
bool scope_accepts_entry(
    const scope_t *s,
    const char *profile,
    const char *filesystem_path,
    const char *storage_path,
    path_kind_t kind
);

#endif /* DOTTA_SCOPE_H */
