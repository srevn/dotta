/**
 * scope.h - What a command works on
 *
 * The enabled set — the enabled rows whose branch is here, in precedence order
 * — and the filters a command narrows it by. The set is read one of two ways:
 *
 *   - off the view, which lends the set it was built from (core/manifest.h
 *     manifest_profiles): a scope borrows it (scope_build) and lends it on
 *     (scope_enabled), and a command that holds the view and no scope reads it
 *     there;
 *   - without it: scope_resolve_enabled reads the state's rows and asks Git which
 *     branches stand.
 *
 * The questions asked of the set take what they read, whichever way the set was
 * read: the filter -p's names make over it (scope_filter), the refusal an empty
 * set earns (scope_require_enabled) and which of the set holds a commit
 * (scope_resolve_commit, scope_resolve_range) take the set as a value, and the
 * claim a file argument names (scope_resolve_claim) takes the set's view,
 * precedence resolved. The commands that build no scope would give one nothing
 * but the set to carry: sync narrows a set of its own, every enabled row whether
 * its branch is here or not, by the same filter (scope_filter), and every other
 * one's -p names any local profile, enabled or not, and never reads the set.
 *
 * A scope answers, for a command that holds the view, "what subset of the view
 * — every enabled profile at its head, precedence resolved — does this invocation
 * touch?". It bundles the set with the three filter dimensions every such command
 * carries:
 *
 *   1. Profile filter     — CLI -p <names> (optional)
 *   2. Path filter        — CLI positional path arguments (optional)
 *   3. Exclude patterns   — CLI -e <patterns>            (optional)
 *
 * Constructed once per command via scope_build; consulted many times via predicates
 * that replace the per-iteration triplet of `continue` guards at filter sites;
 * and asked, entry by entry, what its path filter reached among the subjects a
 * verb hands it (scope_coverage_t).
 *
 * Vocabulary
 * ----------
 *   enabled  — persistent enabled profile names, always non-NULL, may be empty:
 *              the view's own set (manifest_profiles), borrowed — the enabled
 *              rows whose branch the build found, one list, so the scope and
 *              the view answer one instant's question once — the set the CLI
 *              filter is checked against. The workspace reads the same names
 *              off the view itself.
 *   profiles — display/hook face of the scope. Equal to the CLI filter names
 *              when one was given, each once, else equal to enabled. "What the
 *              user asked for, not the underlying world."
 *   paths    — the CLI-derived path filter (NULL when no positional args), one
 *              matcher over the two keys a managed path has: its filesystem path
 *              and its storage path (infra/pathspec). Exposed for diff, which
 *              selects a commit range delta by delta, compares a commit's view
 *              under it, and counts its entries against the coverage's misses,
 *              for apply's count line — both through pathspec_count — and for
 *              update's named re-derivation, which asks it of each rung of the
 *              chains it climbs (core/profiles.h profile_derive_ancestors); none
 *              of them has a profile or exclude semantics to honor — the rungs
 *              above a leaf the scope accepted are in no -e's way, an excluded
 *              directory excluding everything beneath it. In-workspace sites
 *              should prefer scope_accepts_path, and what each entry reached is
 *              the coverage's to answer, -p read beside it (scope_coverage_t).
 *
 * The CRITICAL invariant — load the enabled set, never the filter — is enforced
 * by construction: the workspace never takes a profile list — the view it joins
 * is built over the state's rows, and its profile set is the view's. A CLI filter
 * narrows what a command touches, never what it loads.
 *
 * Lifetime and ownership
 * ----------------------
 * scope_t is a value of the arena scope_build is handed — the struct, the filter's
 * names and the compiled filters — immutable once built, and nothing frees one.
 * Every CLI-derived input is copied there, so the caller's inputs may go once
 * scope_build returns. The enabled set is the view's, borrowed, so the view
 * outlives the scope: both are the command arena's, as every caller builds them.
 *
 * Empty-enabled policy
 * --------------------
 * Neither way of reading the set translates "no enabled profiles" into an error:
 * an empty set is an answer of scope_build and scope_resolve_enabled alike, and
 * what it means is each command's own. apply converges to it (an empty view,
 * orphan cleanup running) and status reads it as a degraded mode (everything an
 * orphan), neither with special handling; a command that speaks of it — refusing
 * it, or warning it and going on — takes its words from scope_require_enabled,
 * which says which of two facts the empty set is.
 */

#ifndef DOTTA_SCOPE_H
#define DOTTA_SCOPE_H

#include <git2.h>
#include <stdbool.h>
#include <types.h>

#include "infra/path.h"
#include "infra/pathspec.h"

/* Forward decls: the view's and the state's full APIs live in core/manifest.h
 * and core/state.h. scope reads the view — its set, and its row for an argument
 * — and the state's enabled rows alone, so the header names the three types and
 * stays free of both dependencies. C11 §6.7p3 permits typedef-name
 * redeclaration. */
typedef struct manifest manifest_t;
typedef struct manifest_row manifest_row_t;
typedef struct state state_t;

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
    char *const *paths;             /* Positional path arguments (raw CLI) */
    size_t path_count;
    char *const *exclude_patterns;  /* -e exclude patterns (raw CLI) */
    size_t exclude_count;
} scope_inputs_t;

/**
 * Build a scope from the view and raw CLI inputs.
 *
 * Steps performed (in order):
 *   1. Borrow the enabled set off the view — the enabled rows whose branch the
 *      build found (core/manifest.h manifest_profiles) — which may be none (see
 *      "Empty-enabled policy" above).
 *   2. Check every CLI filter name against the enabled set (scope_filter): one
 *      not in it is refused, a name given twice is one profile, and the filter,
 *      where given, is the scope's face (scope_profiles).
 *   3. Compile the positional arguments into the path filter (infra/pathspec):
 *      one matcher over the two keys a managed path has, each input read in the
 *      key its own shape names — none, every path in, where none was given.
 *   4. Compile the -e layer into `arena` (ignore_excludes_compile): a pattern
 *      the grammar refuses refuses the build, under the flag's name.
 *
 * @param repo   Repository: a -p name that is not enabled is asked of it, to tell
 *               a disabled profile from none here (must not be NULL)
 * @param view   The view the command reads, ctx->run.manifest or one it built
 *               (must not be NULL; borrowed for the scope's life, whose enabled
 *               set is the view's)
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
/* The enabled set, and the questions asked of it                       */
/* -------------------------------------------------------------------- */

/**
 * The enabled set without a view: each enabled profile whose branch is here
 *
 * Lightweight name-only resolution: reads the enabled rows the handle holds
 * (core/state.h state_profiles), keeps each whose branch is here, and returns
 * their names in the rows' order. One whose branch is gone is dropped unsaid:
 * the health commands say it, off the view (core/manifest.h manifest_missing).
 * None enabled, or none of them here, is an empty answer and not an error: every
 * reader decides what an empty set means to it, and words it through
 * scope_require_enabled, which tells the two apart.
 *
 * Readers: show's commit search (cmds/show.c cmd_show), cmds/bootstrap.c
 * cmd_bootstrap, cmds/ignore.c ignore_test, for either key it takes, and cmds/key.c
 * key_status, the profiles whose encrypted files it counts. A command that holds
 * the view reads the same set off it (core/manifest.h manifest_profiles): the
 * scope it builds borrows it (scope_build), and show's and list's file arms ask
 * it there.
 *
 * Asks every enabled branch at once whether it is here (sys/gitops.h
 * gitops_branches_exist), as the view's build does, and loads no tree.
 *
 * @param repo Repository (must not be NULL)
 * @param state State handle (must not be NULL; borrowed, not freed). Nothing is
 *              executed on it — the rows are the handle's own — so a handle in
 *              any shape serves.
 * @param arena Arena the answer lives in (must not be NULL)
 * @param out Validated profile names, possibly none (must not be NULL; left as
 *            it was on a failure)
 * @return Error or NULL on success
 */
error_t scope_resolve_enabled(
    git_repository *repo,
    const state_t *state,
    arena_t *arena,
    string_array_t *out
);

/**
 * The filter -p's names make over the set a command reads: each name the set
 * holds, once
 *
 * Every name checked against `enabled`: one the set lacks is refused, whether
 * it names a profile not enabled ("is not enabled") or none here at all
 * (core/profiles.h profile_require's refusal) — a filter never narrows in silence.
 * A name given twice is one profile, kept where it was first given. No name is
 * no filter: an empty one, which narrows nothing.
 *
 * Readers: scope_build, over the view's set; cmds/sync.c cmd_sync, over every
 * enabled row, its branch here or not.
 *
 * @param repo Repository: a name the set lacks is asked of it, to tell a profile
 *             not enabled from none here (must not be NULL)
 * @param enabled The set the command reads (must not be NULL)
 * @param names -p's names, raw (must not be NULL where count > 0)
 * @param count How many
 * @param arena Arena the filter lives in (must not be NULL)
 * @param out The filter, in the order its names were first given (must not be
 *            NULL; left as it was on a refusal)
 * @return Error or NULL on success
 */
error_t scope_filter(
    git_repository *repo,
    const string_array_t *enabled,
    char *const *names,
    size_t count,
    arena_t *arena,
    string_array_t *out
);

/**
 * The refusal an empty enabled set earns, or NULL where it holds a profile
 *
 * `enabled` is the set a command reads: the enabled rows whose branch is here —
 * the view's (core/manifest.h manifest_profiles, asked there or through
 * scope_enabled) or the resolver's (scope_resolve_enabled). Empty, it is one of
 * two facts, and the rows say which: none is enabled, or each one is and Git
 * holds no branch for it — a row whose branch is here is in the set, since both
 * producers drop a row only on a proven absence and fail on every other answer.
 * A set of every enabled row, its branch here or not, is empty only where none
 * is enabled, and so earns the first fact alone.
 *
 * Readers: cmds/update.c cmd_update, cmds/show.c cmd_show — its commit search
 * and its file search — and cmds/list.c list_file_history refuse with it, each
 * the set it searches or acts on, and cmds/sync.c cmd_sync over every enabled
 * row, its branch here or not; cmds/diff.c cmd_diff, cmds/bootstrap.c cmd_bootstrap
 * and cmds/ignore.c ignore_test warn it and go on.
 *
 * @param state State handle (must not be NULL): its enabled rows
 * @param enabled The set the command reads (must not be NULL)
 * @param arena Arena the names are joined in (must not be NULL)
 * @return The refusal (ERR_NOT_FOUND), or NULL where `enabled` holds one
 */
error_t scope_require_enabled(
    const state_t *state,
    const string_array_t *enabled,
    arena_t *arena
);

/**
 * The enabled profile that holds a commit, and the commit
 *
 * The revision is read once, before any profile is asked (sys/revision.h
 * revision_resolve): a spelling that names no commit refuses there, and no profile
 * is passed over for it. Then the enabled set is asked from its highest precedence
 * down — the last enabled first, the profile that wins every path it shares —
 * so `HEAD` is the head of the profile the view reads, and a history too short
 * for `HEAD~N`, or holding no commit `HEAD^{/pattern}` matches, is passed for
 * the next one down. Each profile's head is read once and the revision asked of
 * it (revision_find), and the first profile holding it is the answer: the head
 * itself or a commit its history reaches, or for HEAD's steps a history that
 * takes them. A profile behind that one is never asked: the order has already
 * decided.
 *
 * `filter` narrows the search to the profiles it names — the ones -p named, each
 * an enabled profile (scope_build refuses any other) — still asked in the enabled
 * set's order; NULL asks every enabled profile.
 *
 * Answered for every profile ahead of the answer, or an error. A profile whose
 * history does not hold the revision is an answer, and the search moves on; a
 * head or a history that will not read is a failure, naming the branch, and it
 * ends the search where it stands, whatever a later profile would have said.
 * The asymmetry is the whole of the rule: what comes back is the first holder
 * *in precedence order*, which is a claim about every profile ahead of it, and
 * a branch that would not read is one the claim cannot be made over — where a
 * profile after the holder was never part of the answer. This is the first-match
 * shape of what the complete searches promise (cmds/revert.c revert_select_profile:
 * a falsely unique answer is one a verb acts on).
 *
 * Absence is every searched profile's: ERR_NOT_FOUND naming the commit and what
 * was searched — any enabled profile, or the profiles the filter names — with
 * no cause under it, because one profile's sentence is not this one's. An empty
 * set is that same absence; both readers refuse an empty enabled set in their
 * own words before they ask.
 *
 * Readers: cmds/diff.c diff_commit_to_workspace (the filter -p's), cmds/show.c
 * cmd_show (a commit named with no profile, no filter). A range's two ends are
 * searched for together (scope_resolve_range). A caller that names one profile
 * resolves in it directly (sys/revision.h revision_load) — the question there
 * is not which profile.
 *
 * @param repo Repository (must not be NULL)
 * @param enabled The enabled set, in precedence order (must not be NULL)
 * @param filter The profiles the search may ask, or NULL for all of `enabled`
 * @param commit_ref Commit reference (must not be NULL)
 * @param out_commit The resolved commit (must not be NULL, caller must free with
 *                   git_commit_free); its OID is git_commit_id's
 * @param out_profile The profile that holds it (must not be NULL; borrowed from
 *                    `enabled`, valid for as long as it is)
 * @return Error (ERR_NOT_FOUND when no profile searched holds it) or NULL on
 *         success
 */
error_t scope_resolve_commit(
    git_repository *repo,
    const string_array_t *enabled,
    const string_array_t *filter,
    const char *commit_ref,
    git_commit **out_commit,
    const char **out_profile
);

/**
 * The enabled profile that holds both ends of a range, and the two commits
 *
 * A range is one profile's history, so its ends are searched for together: both
 * read once, before any profile is asked, then scope_resolve_commit's order and
 * failure rule — from the highest precedence down, among what `filter` names, a
 * head or a history that will not read ending the search — with each head read
 * once and both ends asked of it. The answer is the first profile holding both:
 * `HEAD~1 HEAD` the first history long enough for both, `<id> HEAD` the id's
 * own profile, whatever either end alone would have answered.
 *
 * An end no profile searched holds is that end's absence, in scope_resolve_commit's
 * words; ends held only apart are refused naming the first profile holding each,
 * in the ends' order, a range across two orphan branches being no range.
 *
 * Readers: cmds/diff.c diff_commits.
 *
 * @param repo Repository (must not be NULL)
 * @param enabled The enabled set, in precedence order (must not be NULL)
 * @param filter The profiles the search may ask, or NULL for all of `enabled`
 * @param commit1_ref The first end, as typed (must not be NULL)
 * @param commit2_ref The second end, as typed (must not be NULL)
 * @param out_commit1 The first end's commit (must not be NULL; git_commit_free)
 * @param out_commit2 The second end's commit (must not be NULL; git_commit_free)
 * @param out_profile The profile holding both (must not be NULL; borrowed from
 *                    `enabled`)
 * @return Error or NULL on success; nothing is written on a failure
 */
error_t scope_resolve_range(
    git_repository *repo,
    const string_array_t *enabled,
    const string_array_t *filter,
    const char *commit1_ref,
    const char *commit2_ref,
    git_commit **out_commit1,
    git_commit **out_commit2,
    const char **out_profile
);

/**
 * The claim a file argument names in the enabled set: the view's row for it
 *
 * Asked of the set's view (core/manifest.h manifest_build) — every enabled profile
 * at its head, precedence resolved — in the key the argument names (infra/path.h):
 * a path is the row standing there, whatever its name and whoever holds it, the
 * layer's rung among them, a directory no document holds (core/manifest.c
 * manifest_layer); a name keys within one profile, so the view holds it once —
 * under home/ or root/, or one binding — or once per binding under custom/, and
 * then no profile is the answer: the refusal names each holder with the path
 * that tells them apart (core/manifest.h manifest_holder), returned as it is.
 *
 * Absence is every enabled profile's, as the commit search's is: ERR_NOT_FOUND,
 * "'<x>' not found in any enabled profile", <x> the argument in its key — the
 * path, or the name with its directory spelling shed — the set's half of the
 * sentence one profile's absence says (core/profiles.h profile_held_kind_t).
 * The view answers what stands, so a claim an enabled profile holds that stands
 * nowhere here — one this machine cannot place, one its profile did not keep,
 * one beneath another profile's blob — is absent all the same, and -p reads a
 * profile's own claims. An empty set is that same absence; both readers refuse
 * an empty enabled set in their own words before they ask.
 *
 * Readers: cmds/show.c cmd_show and cmds/list.c list_file_history, each without
 * a profile. With one, the profile names the argument itself (core/manifest.h
 * manifest_claim_name).
 *
 * @param view The enabled set's view (must not be NULL)
 * @param arg The argument, read (must not be NULL; infra/path.h path_input_resolve)
 * @param arena Arena a refusal's holders are joined in (must not be NULL)
 * @param out_row The row, borrowed from the view (must not be NULL; NULL beside
 *                a refusal)
 * @return Error or NULL on success
 */
error_t scope_resolve_claim(
    const manifest_t *view,
    const path_input_t *arg,
    arena_t *arena,
    const manifest_row_t **out_row
);

/* -------------------------------------------------------------------- */
/* Definitional accessors                                               */
/* -------------------------------------------------------------------- */

/**
 * Persistent enabled set — the view's scope.
 *
 * The enabled profiles, validated against the branches, in precedence order.
 * Never the filter. Always non-NULL; the array may be empty (an empty view is a
 * valid state). The view's own (core/manifest.h manifest_profiles), lent on by
 * the scope: valid for as long as the view is.
 */
const string_array_t *scope_enabled(const scope_t *s);

/**
 * The scope's profiles — its display and hook face.
 *
 * Equal to the CLI filter names when -p was given — each once, in the order first
 * given — else equal to scope_enabled(s). Use this for hook context strings ("what
 * the user asked for") and for verbose output.
 *
 * Always non-NULL. Borrowed from the scope.
 */
const string_array_t *scope_profiles(const scope_t *s);

/* -------------------------------------------------------------------- */
/* Raw-dimension accessors                                              */
/* -------------------------------------------------------------------- */

/**
 * Raw path filter (NULL when no positional path args were given).
 *
 * Consumers that read the filter itself — diff (a commit range selected delta
 * by delta, a commit's view compared under it, the entries counted against the
 * coverage's misses: cmds/diff.c diff_select_delta_cb, diff_print_view,
 * diff_write_view, diff_print_coverage) and apply's count line (cmds/apply.c
 * cmd_apply), the last two through pathspec_count; update's named re-derivation
 * hands it to the draft, which asks it of each rung of the chains it climbs
 * (cmds/update.c cmd_update, core/profiles.h profile_derive_ancestors); and
 * update's partition asks it of a place the scan could not look, whether a path
 * it may select lies beneath (cmds/update.c update_partition, infra/pathspec.h
 * pathspec_matches_beneath). Per-iteration checks of a path itself should use
 * scope_accepts_path instead, and what each entry reached is the coverage's to
 * answer (scope_coverage_t).
 *
 * Borrowed from the scope.
 */
const pathspec_t *scope_paths(const scope_t *s);

/* -------------------------------------------------------------------- */
/* Build-shape predicates                                               */
/* -------------------------------------------------------------------- */

/** True if a CLI profile filter was given (-p). */
bool scope_filters_profiles(const scope_t *s);

/** True if CLI positional path arguments were given. */
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

/* -------------------------------------------------------------------- */
/* The path filter's coverage                                           */
/* -------------------------------------------------------------------- */

/**
 * A path filter's coverage: what each of its entries reached among the subjects
 * a verb hands it
 *
 * One question per entry: did it reach a subject of the verb's universe? Each
 * entry is asked alone — an exact one by equality or ancestry, a rule at any
 * rung, either polarity (infra/pathspec.h pathspec_entry_matches) — so no entry's
 * negation folds into another's answer, and a negation that left a subject out
 * has reached it. A subject of the run's profiles (scope_accepts_profile) answers
 * the entry; one of a profile -p leaves out answers nothing, and the first such
 * an entry reached is kept, so an entry whose subjects were all hidden says whose
 * the first was. -e plays no part: what a flag withholds counts as reached.
 *
 * Each verb names its universe, hands its subjects in one at a time, in the one
 * shape every subject has whatever the verb holds it as — a profile, two names
 * and a kind (scope_coverage_add) — and words the misses itself. Readers:
 * cmds/diff.c diff_validate_filter, over a view's rows, and diff_commits, over
 * the names a commit range's two trees hold; cmds/apply.c cmd_apply, over the
 * workspace's items, active and orphaned. A reader not on this list is a bug.
 *
 * A value of the arena it was made in, the misses with it; nothing frees one.
 */
typedef struct scope_coverage scope_coverage_t;

/**
 * An entry no subject of the run's profiles reached
 */
typedef struct {
    pathspec_entry_t entry;          /* The entry, as typed */
    const char *hidden;              /* The profile -p left out whose subject it reached first; NULL: none reached */
} scope_miss_t;

/**
 * The misses, in the path filter's order
 */
typedef struct {
    const scope_miss_t *entries;
    size_t count;
} scope_misses_t;

/**
 * A coverage of the scope's path filter, no entry reached yet
 *
 * Under no path filter there is nothing to reach: scope_coverage_add answers
 * false at once, and the misses are none.
 *
 * @param s     The scope whose filters every subject is asked under (must not
 *              be NULL; borrowed for the coverage's life)
 * @param arena Arena the coverage and its misses live in (must not be NULL)
 * @return The coverage; never NULL
 */
scope_coverage_t *scope_coverage_create(const scope_t *s, arena_t *arena);

/**
 * Hand the coverage one subject of the verb's universe
 *
 * The subject in the shape scope_accepts_entry reads one: each entry no subject
 * of the run's profiles reached yet is asked of its names and kind, and one that
 * matches is reached where the profile is the run's, else keeps the profile where
 * it kept none before.
 *
 * @param c               The coverage (must not be NULL)
 * @param profile         The subject's profile (borrowed: a miss lends it on)
 * @param filesystem_path Where the subject stands (NULL: no filesystem entry
 *                        reads it)
 * @param storage_path    The subject's name (NULL: no storage entry reads it)
 * @param kind            What the subject is, as scope_accepts_path reads it
 * @return Whether an entry is left to reach — false once every one is, and at
 *         once under no filter, so a verb may stop handing subjects in
 */
bool scope_coverage_add(
    scope_coverage_t *c,
    const char *profile,
    const char *filesystem_path,
    const char *storage_path,
    path_kind_t kind
);

/**
 * The entries no subject of the run's profiles reached, in the path filter's order
 *
 * @param c The coverage (must not be NULL)
 * @return The misses, in the coverage's arena; none under no filter
 */
scope_misses_t scope_coverage_misses(const scope_coverage_t *c);

#endif /* DOTTA_SCOPE_H */
