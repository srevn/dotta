/**
 * profiles.h - Profile name resolution and Git queries
 *
 * Handles profile detection, name resolution, and branch-level queries. The
 * questions asked of one branch, or of every branch, answered from Git and this
 * machine's topology; the searches by path build one branch's view to ask it
 * (core/manifest.h), in the caller's arena, and answer from it, so no manifest
 * type crosses this surface.
 *
 * The layering convention, least specific first:
 * 1. global
 * 2. <os> (darwin, linux, freebsd) - base OS profile
 * 3. <os>/<variant> (darwin/name, freebsd/services) - OS sub-profiles (sorted
 *    alphabetically)
 * 4. hosts/<hostname> - host base profile
 * 5. hosts/<hostname>/<variant> - host sub-profiles (sorted alphabetically)
 *
 * The convention is a seed, not the precedence. Precedence is this machine's
 * enabled order (enabled_profiles.position, core/state.h): later enabled wins,
 * enable appends, reorder moves, and the repository knows nothing of it. The
 * convention is the order a set the machine enumerated is enabled or run in —
 * detection at clone, and every --all — because such a set has no other; named
 * profiles keep the order they were typed in (profile_order).
 *
 * Hierarchical OS profiles:
 * - Base profile: <os> (e.g., darwin, freebsd)
 * - Sub-profiles: <os>/<variant> (e.g., darwin/name, freebsd/services)
 * - Sub-profiles are limited to one level deep for safety
 * - Multiple sub-profiles are applied in alphabetical order
 * - Example: darwin → darwin/name → darwin/work (alphabetical)
 *
 * Hierarchical host profiles:
 * - Base profile: hosts/<hostname> (e.g., hosts/visavis)
 * - Sub-profiles: hosts/<hostname>/<variant> (e.g., hosts/visavis/github)
 * - Sub-profiles are limited to one level deep for safety
 * - Multiple sub-profiles are applied in alphabetical order
 * - Git limitation: Cannot have both base AND sub-profiles (ref namespace conflict)
 *   Use either hosts/<hostname> OR hosts/<hostname>/<variant>, not both
 *
 * Design principles:
 * - Auto-detect system profiles
 * - Support manual profile specification
 * - Clear precedence rules
 */

#ifndef DOTTA_PROFILES_H
#define DOTTA_PROFILES_H

#include <git2.h>
#include <types.h>

#include "base/hashmap.h"
#include "core/branch.h"
#include "core/metadata.h"
#include "core/state.h"
#include "infra/mount.h"
#include "infra/path.h"

/**
 * Detect matching profile names from a list of available branches
 *
 * Pure name-based detection using system information (OS, hostname). Returns
 * names in the convention's order (profile_order). Always includes "global" first
 * if present in the available branches.
 *
 * Detection order:
 * 1. "global" — always included if available
 * 2. <os> — OS base profile (darwin, linux, freebsd)
 * 3. <os>/<variant> — OS sub-profiles (sorted alphabetically, one level deep)
 * 4. hosts/<hostname> — host base profile
 * 5. hosts/<hostname>/<variant> — host sub-profiles (sorted alphabetically)
 *
 * No Git operations — takes a branch name list, returns matching names. All
 * detection steps are non-fatal (skip on system call failure).
 *
 * @param arena Arena the answer lives in (must not be NULL)
 * @param available_branches List of branch names to match against (must not be
 *                           NULL)
 * @return Matched profile names in the convention's order, possibly none
 */
string_array_t profile_detect(arena_t *arena, const string_array_t *available_branches);

/**
 * Order profile names by the layering convention — least specific first.
 *
 *     rank 0   "global"          the universal base
 *     rank 1   everything else   a base sorts before its own variants, because
 *                                '\0' < '/' — "darwin" < "darwin/home"
 *     rank 2   "hosts/..."       the most specific layer
 *
 * Within a rank, byte order on the name. That is a total order on names alone:
 * it needs no machine, so a hub machine enabling every profile and a bare clone
 * enabling the three that match it seed the three in the same relative order.
 *
 * The seed, and nothing after it. A set the machine enumerated has no order of
 * its own, and this is the one it gets: profile_detect returns its answer in
 * it, and every --all — profile enable, clone, bootstrap — sorts its set with
 * it before the loop that enables or runs. A set the user typed keeps the order
 * typed, and once a row exists its position is the machine's: enable appends,
 * reorder moves, and no command sorts an enabled set again.
 *
 * Sorts in place. Stable is not required — the key is total on distinct names,
 * and branch names are distinct.
 *
 * @param names Profile names to order in place (NULL is a no-op)
 */
void profile_order(string_array_t *names);

/**
 * Resolve enabled profile names from state database
 *
 * Lightweight name-only resolution: reads the enabled rows the handle holds
 * (core/state.h state_profiles), keeps each whose branch is here, and returns
 * their names in the rows' order. One whose branch is gone is dropped unsaid:
 * the health commands say it, off the view (core/manifest.h manifest_missing).
 * None enabled, or none of them here, is an empty answer and not an error: every
 * reader decides what an empty set means to it, and words it through
 * profile_require_enabled, which tells the two apart.
 *
 * Readers: the commands that search the enabled set and hold no view — cmds/show.c
 * cmd_show, cmds/ignore.c ignore_test and cmds/bootstrap.c cmd_bootstrap. A command
 * that holds the view reads the same set off it (core/manifest.h manifest_profiles,
 * through core/scope.h scope_build).
 *
 * Asks each enabled branch whether it is here (sys/gitops.h gitops_branch_exists)
 * and loads no tree.
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
error_t profile_resolve_enabled(
    git_repository *repo,
    const state_t *state,
    arena_t *arena,
    string_array_t *out
);

/**
 * The refusal an empty enabled set earns, or NULL where it holds a profile
 *
 * `profiles` is the set a command reads: the enabled rows whose branch is here
 * — the view's (core/manifest.h manifest_profiles, through core/scope.h
 * scope_enabled) or the resolver's (profile_resolve_enabled). Empty, it is one
 * of two facts, and the rows say which: none is enabled, or each one is and Git
 * holds no branch for it — a row whose branch is here is in the set, since both
 * producers drop a row only on a proven absence and fail on every other answer.
 *
 * Readers: cmds/update.c cmd_update, cmds/sync.c cmd_sync and cmds/show.c cmd_show
 * refuse with it; cmds/diff.c cmd_diff, cmds/bootstrap.c cmd_bootstrap and
 * cmds/ignore.c ignore_test warn it and go on.
 *
 * @param state State handle (must not be NULL): its enabled rows
 * @param profiles The set the command reads (must not be NULL)
 * @param arena Arena the names are joined in (must not be NULL)
 * @return The refusal (ERR_NOT_FOUND), or NULL where `profiles` holds one
 */
error_t profile_require_enabled(
    const state_t *state,
    const string_array_t *profiles,
    arena_t *arena
);

/**
 * The enabled profile that holds a commit, and the commit
 *
 * The revision is read once, before any profile is asked (sys/revision.h
 * revision_resolve): a spelling that names no commit refuses there, and no profile
 * is passed over for it. Then the enabled set is asked from its highest precedence
 * down — the last enabled first, the profile that wins every path it shares —
 * so `HEAD` is the tip of the profile the view reads, and a history too short
 * for `HEAD~N`, or holding no commit `HEAD^{/pattern}` matches, is passed for
 * the next one down. Each profile's tip is read once and the revision asked of
 * it (revision_find), and the first profile holding it is the answer: the tip
 * itself or a commit its history reaches, or for HEAD's steps a history that
 * takes them. A profile behind that one is never asked: the order has already
 * decided.
 *
 * `filter` narrows the search to the profiles it names — the ones -p named, each
 * an enabled profile (core/scope.h scope_build refuses any other) — still asked
 * in the enabled set's order; NULL asks every enabled profile.
 *
 * Answered for every profile ahead of the answer, or an error. A profile whose
 * history does not hold the revision is an answer, and the search moves on; a
 * tip or a history that will not read is a failure, naming the branch, and it
 * ends the search where it stands, whatever a later profile would have said.
 * The asymmetry is the whole of the rule: what comes back is the first holder
 * *in precedence order*, which is a claim about every profile ahead of it, and
 * a branch that would not read is one the claim cannot be made over — where a
 * profile after the holder was never part of the answer. This is the first-match
 * shape of what the complete searches beside it promise (profile_discover_claims:
 * a falsely unique answer is one a verb acts on).
 *
 * Absence is every searched profile's: ERR_NOT_FOUND naming the commit and what
 * was searched — any enabled profile, or the profiles the filter names — with
 * no cause under it, because one profile's sentence is not this one's. An empty
 * set is that same absence; both readers refuse an empty enabled set in their
 * own words before they ask.
 *
 * Readers: diff.c diff_commit_to_workspace (the filter -p's), show.c cmd_show
 * (a commit named with no profile, no filter). A range's two ends are searched
 * for together (profile_resolve_range). A caller that names one profile resolves
 * in it directly (sys/revision.h revision_load) — the question there is not which
 * profile.
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
error_t profile_resolve_commit(
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
 * read once, before any profile is asked, then profile_resolve_commit's order
 * and failure rule — from the highest precedence down, among what `filter` names,
 * a tip or a history that will not read ending the search — with each tip read
 * once and both ends asked of it. The answer is the first profile holding both:
 * `HEAD~1 HEAD` the first history long enough for both, `<id> HEAD` the id's
 * own profile, whatever either end alone would have answered.
 *
 * An end no profile searched holds is that end's absence, in
 * profile_resolve_commit's words; ends held only apart are refused naming the
 * first profile holding each, in the ends' order, a range across two orphan
 * branches being no range.
 *
 * Readers: diff.c diff_commits.
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
error_t profile_resolve_range(
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
 * Is there a profile of this name here, or refuse
 *
 * The refusing shape of gitops_branch_exists, for the verbs whose only use of
 * the answer is to stop: NULL iff the branch is here; the lookup's own error
 * when Git could not say — an unreadable or corrupt loose ref is an error, never
 * an absence (a bool that read it as "no" sent the user to fetch a profile that
 * was here, let --force delete nothing and call it done, and had validate --fix
 * offer to disable a healthy profile); otherwise ERR_NOT_FOUND, "Profile '<name>'
 * doesn't exist locally" — "locally" leaving both readings open, because no verb
 * can tell a typo from a profile not yet fetched — then the verb that brings
 * one, which the fact does not imply: "'dotta profile fetch <name>' brings it
 * from a remote that holds it", true of both readings (the natural guess, sync,
 * fetches the enabled profiles alone).
 *
 * Readers: ignore (--test, and the edit), bootstrap (the names its selection
 * reads, --edit's and --show's among them), show, export, list (a profile's files;
 * an explicit profile's history), revert (the -p arm), and scope's filter on
 * its refusal path. A verb that acts on both answers — add (checkout or create),
 * enable's skip, remove's --force arm, validate's probe, the view's build — asks
 * gitops_branch_exists itself and reads the bool.
 *
 * @param repo Repository (must not be NULL)
 * @param name Profile name (must not be NULL)
 * @return NULL when the branch is here; else the refusal, or Git's error
 */
error_t profile_require(git_repository *repo, const char *name);

/**
 * What a profile branch holds
 *
 * Counted from the branch, not from the view: the listings that report these
 * name available profiles too, and a profile nothing has enabled owns no rows.
 * The two sources are the ones the branch's walk shows the view when the profile
 * *is* enabled (core/branch.h branch_walk) — the tree's content blobs and the
 * branch metadata's tracked directories — and both sides read one content gate
 * (infra/label.h label_prefixes), so a profile that wins every path it claims
 * counts the same here as its rows do there. The directory side's staleness probe
 * is the one place the two read different witnesses: the walk contradicts a claim
 * from the blob it met, this count asks the tree (core/profiles.c
 * profile_get_tree_stats). They answer alike for every key the grammar admits,
 * and the proof is written where the probe is.
 *
 * Readers: the screens that name what a branch holds — `dotta list`'s profile
 * rows and its no-files arm (cmds/list.c list_profiles, cmds/list.c list_files),
 * `profile list`'s enabled and available rows (cmds/profile.c profile_list),
 * and the deletion's preview and confirmation (cmds/remove.c remove_profile). A
 * reader not on this list is a bug, and a screen that counts what a branch holds
 * beside this one is the second producer this count exists to be: list_files
 * kept its own directory fold until it took this one. The verbose file listing's
 * `Total:` is the one that remains, and it is not a second answer but the same
 * one by the other route — the rows it prints, summed as it prints them, which
 * is what a total under a table has to be. What makes the two routes meet is
 * that both take the framing off the same claim; nothing structural does, and
 * the raw sum here disagreed with those rows by it on every profile holding a
 * sealed file until 228 C2c. `status -v` is no such screen — it counts the view's
 * rows a profile wins (cmds/status.c status_print_profiles), the other half of
 * the holds/wins split above, and the two are free to disagree (docs/profiles.md).
 */
typedef struct {
    size_t file_count;       /* Blobs standing under a storage label */
    size_t directory_count;  /* Tracked directories the branch metadata claims */
    size_t total_size;       /* Bytes those blobs stand for, the seal's framing off */
} profile_stats_t;

/**
 * Count what a profile branch holds, in a tree already open
 *
 * The branch's metadata first, then one walk of the tree — each content blob
 * counted and its size taken from the object header, nothing inflated — then
 * the metadata's DIRECTORY items. A branch with no metadata.json claims no
 * directories; that absence is not a failure. For callers that already hold the
 * tree, so one branch read serves the count and whatever else the caller does
 * with it; the tree is borrowed and never freed here.
 *
 * The sheet is read before the walk because the size half wants it too. What a
 * screen calls a file's size is the bytes the file stands for, so the cipher's
 * framing comes off a blob the branch stamps sealed (infra/content.h
 * content_estimated_plaintext_size) — the same subtraction, off the same claim,
 * that the file listing makes row by row (cmds/list.c list_files). The two are
 * a fold and its elements and must agree: a total that names one number while
 * the rows beneath it sum to another is one screen of `dotta list` contradicting
 * the next, which is what the raw sum did for every profile holding a sealed
 * file. Nothing structural holds them together — each reads the claim where it
 * stands, as every reader of that field does (core/metadata.h metadata_item_t)
 * — so the agreement is pinned by a scenario instead (tests/test-encrypt.sh).
 *
 * Complete or an error on both sides: an entry whose name the storage grammar
 * refuses fails the count rather than being skipped past, and a sheet that will
 * not load fails it rather than reading as a branch with no claims (core/metadata.h
 * metadata_load_from_tree). A caller that would rather print than refuse decides
 * that on its own screen, as the listings do.
 *
 * `out` is written once, at the end and on success alone: a walk that stopped
 * short or a probe that refused leaves it as the caller supplied it, so no screen
 * can print half a count.
 *
 * Performance: O(files + directories), one tree walk and one metadata load.
 *
 * @param repo Repository (must not be NULL) — the object database the blob sizes
 *             and the sheet are read through
 * @param tree Git tree to count over (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param out Statistics (must not be NULL; written on success, untouched otherwise)
 * @return Error or NULL on success
 */
error_t profile_get_tree_stats(
    git_repository *repo,
    const git_tree *tree,
    const char *profile,
    profile_stats_t *out
);

/**
 * Count what a profile branch holds
 *
 * Loads the profile's Git tree internally and counts over it. Tree is freed before
 * return. The count is profile_get_tree_stats', and so are its answer to a branch
 * that will not read and its all-or-nothing write of `out`.
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param out Statistics (must not be NULL; written on success, untouched otherwise)
 * @return Error or NULL on success
 */
error_t profile_get_stats(
    git_repository *repo,
    const char *profile,
    profile_stats_t *out
);

/**
 * What `profile` holds at `name` in `tree`, read with the caller's sheet
 *
 * The four answers of core/branch.h branch_holds, asked of a tree and a sheet
 * the caller already holds: the tree first, so an entry is the whole answer;
 * the caller's sheet on the tree's silence alone, read as the caller read it.
 *
 * Its one reader is export's name arm (cmds/export.c collect_storage), which
 * hands in the sheet it read tolerantly and warned over (cmds/export.c load_sheet),
 * so a damaged sheet costs the copy its claims and never the tree's answer. A
 * name the tree is silent about is then read against that sheet as export folded
 * it, empty where the load failed, so a claim only the sheet holds reads as absent
 * there. Every other reader asks the branch, whose sheet is the handle's own
 * and whose read of it is strict.
 *
 * `out` is written on success alone; on any error it is left as the caller supplied
 * it, as profile_get_tree_stats leaves its own.
 *
 * @param tree The tree the name is asked of — a tip's or a commit's (must not
 *             be NULL)
 * @param sheet The caller's sheet of that tree (must not be NULL)
 * @param profile Whose branch it is, for the refusals (must not be NULL)
 * @param name A validated storage path (must not be NULL)
 * @param out The answer (must not be NULL; written on success alone)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s'"
 */
error_t profile_holds(
    const git_tree *tree,
    const metadata_t *sheet,
    const char *profile,
    const char *name,
    branch_held_t *out
);

/**
 * List deployable files in a Git tree
 *
 * Walks the tree past the branch's machinery (infra/label.h label_prefixes, the
 * content gate), and returns the storage paths of its content blobs. This is
 * the lightweight primitive for "files in a branch" — takes a pre-loaded tree
 * and returns storage paths. For callers that already hold the tree, so one branch
 * read serves the walk and whatever else the caller does with it.
 *
 * Complete or an error: an entry whose name the storage grammar refuses is
 * corruption and fails the walk rather than being skipped, since a listing short
 * by a name would still read as complete. A branch this machine authored holds
 * no such entry; one that arrived by clone, sync or foreign push can. A name is
 * never refused for its length: Git's only bound on one is memory. Every failure
 * is said under the profile, since the walk's own name a path in the tree and
 * never the branch it is, and no reader names it again.
 *
 * Readers: cmds/list.c list_files, cmds/remove.c remove_resolve, and
 * profile_list_files.
 *
 * @param tree Git tree to walk (must not be NULL)
 * @param profile The profile whose branch the tree is (must not be NULL)
 * @param arena Arena the listing lives in (must not be NULL)
 * @param out The storage paths (must not be NULL; left as it was on a failure)
 * @return Error or NULL on success
 */
error_t profile_list_tree_files(
    const git_tree *tree,
    const char *profile,
    arena_t *arena,
    string_array_t *out
);

/**
 * List files in profile
 *
 * Loads the profile's Git tree internally and walks it to collect storage paths.
 * Tree is freed before return. The walk is profile_list_tree_files', and so is
 * its answer to a malformed entry.
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param arena Arena the listing lives in (must not be NULL)
 * @param out The storage paths (must not be NULL; left as it was on a failure)
 * @return Error or NULL on success
 */
error_t profile_list_files(
    git_repository *repo,
    const char *profile,
    arena_t *arena,
    string_array_t *out
);

/**
 * Does this profile's branch need a deployment target?
 *
 * Definitional, not a rule of its own: the branch's contribution is built under
 * the one table no state row can produce — HOME and the root sentinel, no binding
 * — and the answer is whether it left anything unplaced (core/manifest.h
 * manifest_unbound). Every home/ and root/ claim places there; a custom/ claim
 * — a blob under custom/, a custom/ item of the sheet, tracked or derived — cannot,
 * so a non-zero count is the answer, and a claim the contribution learns to place
 * or to record moves the answer with it, no clause here having to follow. An
 * empty custom tree needs none, by the same reading: a binding would place nothing
 * for it.
 *
 * The branch's fact and not this machine's: asked under a table with no binding
 * so that what the branch needs and what this machine binds are two facts, the
 * first answerable where the second is not in scope (clone holds no state at
 * its skip), and unchanged by a row this machine writes.
 *
 * Complete or an error: a branch that will not load, a sheet this build cannot
 * read, and a tree entry no mount can place all fail here — the three the next
 * view build over the same branch would fail on, one phase earlier than `profile
 * enable` failed until now, before the row was written. A caller that must not
 * fail whole on one branch absorbs the error and renders the row as unreadable
 * (cmds/interactive.c read_targets), as cmds/profile.c's listing already does
 * for a statistics error.
 *
 * Readers: the three enablers' skip — `profile enable` (cmds/profile.c), clone
 * (cmds/clone.c), the editor's OFF→ON gate (cmds/interactive.c) — the two marks,
 * the listing's available rows (cmds/profile.c) and the editor's, and the editor's
 * `t`, live only on a row that can be bound. The rule these keep is "a profile
 * that needs a target is not enabled without one", and its scope is theirs alone,
 * not an invariant of the rows: the editor prompts and lets a row be saved unbound
 * (cmds/interactive.c plan_classify says why), add's implicit enable authors no
 * such row (a created profile's custom/ claim requires --target, which the row
 * takes), sync and a re-bind can leave an enabled row needing one, and `profile
 * validate` does not ask — an enabled row with no binding is a lifecycle stage
 * the health channel names, not an inconsistency. add asks no producer: it holds
 * a view over its own opened tree under its own table and reads the slice on
 * that (cmds/add.c add_print_enable).
 *
 * Cost: one tree walk and one sheet load, in an arena of the call's own — the
 * product is a bool and nothing outlives the call (include/runtime.h "Memory",
 * a frame's). Measured at 0.144.2 on a 1,000-path branch: 2.5 ms, against 31 ms
 * for the statistics beside it, whose object-header read per blob is the larger
 * half.
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param needs_target Output flag: the branch holds a claim no binding-less table
 *                     places — the view's own unbound count, non-zero (must not
 *                     be NULL)
 * @return Error or NULL on success
 */
error_t profile_needs_target(
    git_repository *repo,
    const char *profile,
    bool *needs_target
);

/**
 * The name a branch has for `filesystem_path`: the claim standing there, or the
 * name a claim there would take
 *
 * A filesystem key, and the only one. The resolver answers two and the other is
 * already settled where the argument was read (infra/path.h): a name the user
 * typed is Git's key, so the caller's own question of the branch decides whether
 * the profile holds it (core/branch.h branch_holds) and there is nothing here
 * to ask — a name no claim sheet mentions, a bare subtree, a name the view did
 * not keep, is held by the branch and never by its view. What arrives here is
 * the key that needs the branch to answer it.
 *
 * Asked of the branch's own view (core/manifest.h manifest_build_branch, its
 * sheet read strictly), in this order: the row standing there answers with its
 * own name whatever its kind, so home/jail/etc/x under a binding at ~/jail is
 * found by ~/jail/etc/x and the chain above a file captured before the binding
 * answers as the claim it is; else the name the profile would give the path
 * (manifest_name) — the word a history search and a not-found line need, which
 * at a root of the profile's own is that root's label's word. Two arms and no
 * third: naming is total, so every path this is asked about has a name.
 *
 * The row before the namer is the contract, not a shortcut: a derived claim is
 * something the profile holds and nothing it names (manifest_is_derived), so
 * the namer alone would climb past it and answer a name the branch never held.
 * Search first, name second.
 *
 * A name, never an enumeration. A DIRECTORY claim names its path and says
 * nothing about what stands beneath it (core/manifest.h manifest_lookup_claim);
 * a verb that means everything at a place selects rows by path (cmds/export.c)
 * and never walks this answer's subtree.
 *
 * `mounts` is the table the rows are placed by, and the path keys against them
 * by strcmp (infra/mount.h). The answer is the arena's — the view's own row string,
 * or the namer's — as the view this call builds is.
 *
 * Cost: one tree walk every call, and the sheet loaded at the branch's first
 * question (core/branch.h). Its other face: a profile whose sheet will not load
 * refuses a path where the name its caller answers unaided proceeds — the view
 * is strict, a verb's own read is not (core/manifest.h). A ref or a tree that
 * will not load refuses both.
 *
 * Readers: `show -p` and `list -p` over the branch the verb opened at the tree
 * it selected (the tip, or the commit the user named, so a name that changed
 * since is found as of then: cmds/show.c cmd_show, cmds/list.c list_file_history).
 * `export` selects rows instead, `remove` matches its own claims, `revert` reads
 * the claim standing in the tree it edits (cmds/revert.c claim_standing), and
 * `ignore --test` asks manifest_name itself.
 *
 * @param branch The branch the claim is looked for in — its tip, or a commit's,
 *               so a commit's answers as of then (must not be NULL; its sheet
 *               read through it)
 * @param mounts The table the rows are placed by (must not be NULL)
 * @param filesystem_path Where to ask, spelled as the rows are keyed (must not
 *        be NULL)
 * @param arena Arena that owns the answer (must not be NULL)
 * @param out_storage Arena-borrowed storage path; NULL after an error (must not
 *                    be NULL)
 * @return Error or NULL on success
 */
error_t profile_claim_name(
    branch_t *branch,
    const mount_table_t *mounts,
    const char *filesystem_path,
    arena_t *arena,
    const char **out_storage
);

/* A claim is (profile, name) — the pair that keys within one profile
 * (infra/mount.h). No kind: its readers print a profile and a name, and the one
 * verb that acts on a claim reads the kind from the tree entry it opens. */
typedef struct {
    const char *profile;
    const char *storage_path;
} profile_claim_t;

/* Bound carrier over claims, the manifest_rows_t idiom: the entries and their
 * count, both the producing call's arena's. */
typedef struct {
    const profile_claim_t *entries;
    size_t count;
} profile_claims_t;

/**
 * Every claim standing at what the user named, across the local branches
 *
 * A STORAGE argument: every branch that holds the name — in its tree, a subtree
 * counting as a name has always counted, or, where the tree is silent, as a
 * directory claim in its sheet (core/branch.h branch_holds); the claim is the
 * name as typed. A LOCATION argument: every branch whose view of its own tip,
 * under this machine's table, holds a row there — the claim being that branch's
 * own name for the place, since a path may be held under a non-canonical name
 * and the caller must not name it again.
 *
 * The table is this machine's, and this machine's table is the enabled set's
 * (core/manifest.h manifest_mount_table): a profile nothing has enabled has no
 * binding here at all, so its custom/ claims stand nowhere and no path reaches
 * them. That is the model being consistent, not a gap — by name they are found
 * as they always were.
 *
 * Complete or an error: a branch that will not load, a lookup that fails for
 * any reason but absence, a claim that could not be recorded — each is the call's
 * failure and never a shorter list, a falsely unique answer being one a verb
 * acts on. None holding it is the empty set, an answer; every error is the
 * search's, a branch the listing named and a delete took before its load among
 * them — the load's own "not found" (sys/gitops.h gitops_load_branch_tree), a
 * branch that could not be read and never one that holds nothing. The branch
 * list is one enumeration, not a snapshot: a ref born between it and the reads
 * is not consulted.
 *
 * Cost, and the asymmetry it carries: a path builds one view per branch — a tree
 * walk and a sheet load each, every branch's rows kept in the arena until the
 * command ends — where a name is one tree lookup per branch and a sheet parse
 * for each branch whose tree is silent about it, which for a name one branch
 * holds is every other branch. So a branch whose sheet will not load refuses
 * `revert <path>` always and `revert <name>` wherever its tree does not hold
 * the name; a name its tree holds is answered without its sheet, which is all
 * that is left of the strict/tolerant split here. Naming the profile skips the
 * search entirely, and the one caller says so where it refuses.
 *
 * Reader: revert without a profile (cmds/revert.c select_profile), whose question
 * is every local branch and not the enabled set, and which reads the empty set
 * as no profile holding the argument. A caller that wants the owning profile
 * among the enabled set asks the view instead (manifest_lookup, manifest_holder
 * — list, show).
 *
 * The key is the input here, where its sibling takes a filesystem path outright
 * (profile_claim_name): both keys run this one search — the same enumeration,
 * the same collection, the same answer when nothing holds it — and the tag chooses
 * which probe each branch is asked. Over there the other key is an answer the
 * caller already holds, so nothing is left for the call to do with it. A sum
 * that chooses among a function's own behaviours is its input; one whose arm
 * means "there was nothing to ask" is the caller's question smuggled in.
 *
 * @param repo Repository (must not be NULL)
 * @param mounts This machine's mount table (must not be NULL)
 * @param arg The argument, in the key it named — a filesystem path or a storage
 *        path (must not be NULL)
 * @param arena Arena that owns the claims (must not be NULL)
 * @param out The claims, none where no branch holds it (must not be NULL; zeroed
 *        after an error)
 * @return Error or NULL on success
 */
error_t profile_discover_claims(
    git_repository *repo,
    const mount_table_t *mounts,
    const path_input_t *arg,
    arena_t *arena,
    profile_claims_t *out
);

/**
 * filesystem path → the claims every local branch but `exclude` places there
 *
 * Each branch read once through its own view of its tip under this machine's
 * table, so a claim is keyed by where it stands and never by what it is called:
 * two profiles bound at two targets holding one name are two paths and meet no
 * key of each other's, and one profile's two names for one path are one row and
 * one entry. A claim this machine cannot place stands nowhere and is not indexed.
 * Directory claims are indexed like any row — the branch claims the directory,
 * and a caller asking who else is at a place is owed it.
 *
 * The map, its keys — each a row's own path string — and its values are the
 * arena's: nothing frees the index.
 *
 * Complete or an error, like its sibling: a short index is an "also in" a user
 * reads as complete. What a failure means is the caller's, and remove's is advisory
 * — it says what it could not read and drops the section rather than refuse the
 * untrack, since a local branch nobody enabled must not stop the repair and must
 * not hide a claim in silence either.
 *
 * Cost: one view per branch — a tree walk and a sheet load each — then O(T log
 * T) over T placed rows for the runs.
 *
 * Reader: cmds/remove.c remove_overlaps.
 *
 * @param repo Repository (must not be NULL)
 * @param mounts This machine's mount table (must not be NULL)
 * @param exclude A branch to leave out, or NULL for every one of them
 * @param arena Arena the index, its keys and its claims live in (must not be NULL)
 * @param out_index filesystem path (const char *) -> profile_claims_t * (must
 *        not be NULL)
 * @return Error or NULL on success
 */
error_t profile_build_filesystem_index(
    git_repository *repo,
    const mount_table_t *mounts,
    const char *exclude,
    arena_t *arena,
    hashmap_t **out_index
);

#endif /* DOTTA_PROFILES_H */
