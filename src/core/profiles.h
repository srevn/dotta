/**
 * profiles.h - Profile name resolution and Git queries
 *
 * Handles profile detection, name resolution, and branch-level queries. The
 * questions asked of one branch, or of every branch, answered from Git and this
 * machine's topology; the searches by location build one branch's view to ask
 * it (core/manifest.h) and free it before they answer, so no manifest type crosses
 * this surface.
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
 * @param available_branches List of branch names to match against (must not be
 *                           NULL)
 * @param out_profiles Matched profile names in the convention's order (must not
 *                     be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_detect(
    const string_array_t *available_branches,
    string_array_t **out_profiles
);

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
 * Lightweight name-only resolution: reads enabled profiles from state, validates
 * that each exists as a branch, and returns validated names. Warns on stderr
 * about profiles referenced in state that no longer exist.
 *
 * Does NOT resolve Git references or load profile trees.
 *
 * @param repo Repository (must not be NULL)
 * @param state State handle (must not be NULL; borrowed, not freed). Only SELECTs
 *              are executed — safe to pass a state_open() handle.
 * @param out Validated profile names (must not be NULL, caller must free)
 * @return Error (ERR_NOT_FOUND if no enabled profiles) or NULL on success
 */
error_t *profile_resolve_enabled(
    git_repository *repo,
    const state_t *state,
    string_array_t **out
);

/**
 * The enabled profile that holds a commit, and the commit
 *
 * The set is asked in the order it is given — the enabled set's precedence order
 * at both readers — and the first profile the commit is reachable from is the
 * answer. A profile behind that one is never asked: the order has already decided.
 *
 * Answered for every profile ahead of the answer, or an error. ERR_NOT_FOUND is
 * one profile's own answer — the commit is not its — and the search moves on;
 * every other code is a rung of the resolution that could not be made, arriving
 * under a sentence that names both the rung and the branch (sys/gitops.h), and
 * it ends the search where it stands, whatever a later profile would have said.
 * The asymmetry is the whole of the rule: what comes back is the first holder
 * *in precedence order*, which is a claim about every profile ahead of it, and
 * a branch that would not read is one the claim cannot be made over — where a
 * profile after the holder was never part of the answer. This is the first-match
 * shape of what the complete searches beside it promise (profile_discover_claims:
 * a falsely unique answer is one a verb acts on).
 *
 * Absence is every profile's: ERR_NOT_FOUND naming the commit, with no cause
 * under it, because one profile's sentence is not this one's. An empty set is
 * that same absence; both readers refuse an empty enabled set in their own words
 * before they ask.
 *
 * Readers: diff.c diff_commit_to_workspace and diff_commits (the workspace arm,
 * and both ends of a range), show.c cmd_show (a commit named with no profile).
 * A caller that names the profile resolves in it directly
 * (gitops_resolve_commit_in_branch) — the question there is not which profile.
 *
 * @param repo Repository (must not be NULL)
 * @param enabled Profile names, asked in this order (must not be NULL)
 * @param commit_ref Commit reference (must not be NULL)
 * @param out_commit The resolved commit (must not be NULL, caller must free with
 *                   git_commit_free); its OID is git_commit_id's
 * @param out_profile The profile that holds it (must not be NULL; borrowed from
 *                    `enabled`, valid for as long as it is)
 * @return Error (ERR_NOT_FOUND when no profile holds it) or NULL on success
 */
error_t *profile_resolve_commit(
    git_repository *repo,
    const string_array_t *enabled,
    const char *commit_ref,
    git_commit **out_commit,
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
 * offer to disable a healthy profile); otherwise ERR_NOT_FOUND with one message,
 * naming both ways out, because no verb can tell a typo from a profile not yet
 * fetched:
 *
 *     Profile '<name>' doesn't exist locally Hint: Run 'dotta profile list' for
 *     the local profiles, or 'dotta profile fetch <name>' to bring it from the
 *     remote
 *
 * Readers: ignore (--test, and the edit), bootstrap (the explicit names, and
 * --edit's template), show, export, list (a profile's files; an explicit profile's
 * history), revert (the -p arm), and scope's filter on its refusal path. A verb
 * that acts on both answers — add (checkout or create), enable's skip, remove's
 * --force arm, validate's probe, the view's build — asks gitops_branch_exists
 * itself and reads the bool.
 *
 * @param repo Repository (must not be NULL)
 * @param name Profile name (must not be NULL)
 * @return NULL when the branch is here; else the refusal, or Git's error
 */
error_t *profile_require(git_repository *repo, const char *name);

/**
 * What a profile branch holds
 *
 * Counted from the branch, not from the view: the listings that report these
 * name available profiles too, and a profile nothing has enabled owns no rows.
 * The two sources are the ones the view's per-profile step reads when the profile
 * *is* enabled (manifest_contribute) — the tree's content blobs and the branch
 * metadata's tracked directories — and both sides read one content gate
 * (infra/label.h label_prefixes), so a profile that wins every path it claims
 * counts the same here as its rows do there. The directory side's staleness probe
 * is the one place the two builds read different witnesses: the view contradicts
 * a claim from the blob its own walk met, this count asks the tree (core/profiles.c
 * profile_get_tree_stats). They answer alike for every key the grammar admits,
 * and the proof is written where the probe is.
 *
 * Readers: the screens that name what a branch holds — `dotta list`'s profile
 * rows and its no-files arm (cmds/list.c list_profiles, cmds/list.c list_files),
 * `profile list`'s enabled and available rows (cmds/profile.c profile_list),
 * and the deletion's preview and confirmation (cmds/remove.c
 * delete_profile_branch). A reader not on this list is a bug, and a screen that
 * counts what a branch holds beside this one is the second producer this count
 * exists to be: list_files kept its own directory fold until it took this one.
 * `status -v` is no such screen — it counts the view's rows a profile wins
 * (cmds/status.c display_enabled_profiles), the other half of the holds/wins
 * split above, and the two are free to disagree (docs/profiles.md).
 */
typedef struct {
    size_t file_count;       /* Blobs standing under a storage label */
    size_t directory_count;  /* Tracked directories the branch metadata claims */
    size_t total_size;       /* Bytes of those blobs */
} profile_stats_t;

/**
 * Count what a profile branch holds, in a tree already open
 *
 * One walk of the tree — each content blob counted and its size taken from the
 * object header, nothing inflated — then the branch metadata's DIRECTORY items.
 * A branch with no metadata.json claims no directories; that absence is not a
 * failure. For callers that already hold the tree, so one branch read serves
 * the count and whatever else the caller does with it; the tree is borrowed and
 * never freed here.
 *
 * Complete or an error on both sides: an entry whose path no mount can place
 * fails the count rather than being skipped past, and a sheet that will not load
 * fails it rather than reading as a branch with no claims (core/metadata.h
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
error_t *profile_get_tree_stats(
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
error_t *profile_get_stats(
    git_repository *repo,
    const char *profile,
    profile_stats_t *out
);

/**
 * What a profile holds at one name
 *
 * The four things that can stand at a storage name, from the tree's three entry
 * kinds and the one claim a tree cannot hold. FILE is any blob — bytes, an
 * executable, a link's target — the filemode beside it saying which; DIRECTORY
 * is a subtree, or a directory claim the sheet alone holds (a tracked directory
 * with nothing beneath it, an ancestor chain the tree no longer has); SUBMODULE
 * is a gitlink, which dotta never writes (sys/stage.c put_entry refuses the mode)
 * and every verb refuses by its noun; NOTHING is neither document holding the name.
 */
typedef enum {
    PROFILE_HELD_NOTHING,       /* neither document holds the name */
    PROFILE_HELD_FILE,          /* the tree: a blob, of any filemode */
    PROFILE_HELD_DIRECTORY,     /* the tree: a subtree, or the sheet alone: a claim */
    PROFILE_HELD_SUBMODULE,     /* the tree: a gitlink */
} profile_held_kind_t;

/**
 * The answer whole: which of the four, and for the tree's entries the two facts
 * a verb reads off one, by value — so no entry outlives the call that read it.
 */
typedef struct {
    profile_held_kind_t kind;   /* which of the four stands at the name */
    git_oid oid;                /* the entry's id, zero where the sheet answered */
    git_filemode_t filemode;    /* the entry's mode word, 0 where the sheet answered */
} profile_held_t;

/**
 * What `profile` holds at `name` in `tree`
 *
 * A name is asked of the branch's two documents in the order the authority rule
 * reads them (core/metadata.h): the tree first, because a name is Git's key and
 * the tree is the content authority; the sheet on the tree's silence alone, because
 * a directory claim with nothing beneath it stands there and nowhere else, and
 * because an item standing at a name the tree holds a blob for is stale and cannot
 * change the tree's answer. A FILE item without a blob claims nothing and answers
 * NOTHING.
 *
 * Three answers from the tree read as three: an intermediate object that will
 * not load is a failure to read, never an absence. The sheet is read strictly —
 * a branch whose sheet will not load refuses a name its tree is silent about,
 * and says so, since dotta cannot then say whether the branch holds it. A tree
 * without a sheet holds an empty one (metadata_load_from_tree), so a branch that
 * never wrote one answers NOTHING there, not an error.
 *
 * `sheet` is the caller's where it holds one — read as the caller read it, so a
 * verb's own sheet policy is its own here too: show hands in the sheet it loaded
 * tolerantly for its header (cmds/show.c show_file), export the one it warned
 * over (cmds/export.c load_sheet), revert the commit's, loaded strictly
 * (cmds/revert.c cmd_revert). NULL where the caller holds none, and the sheet
 * is then loaded here on the tree's silence alone and freed before the return.
 * No caller pays a parse the tree has already answered for, and none pays one
 * twice.
 *
 * The payload is the tree's entry and only the tree's: `oid` and `filemode` are
 * that entry's for the three answers the tree gives, and both are zero exactly
 * where the sheet alone answered — the one convention this contract asks a reader
 * to know, and the one reader that needs it is export's name arm, which walks a
 * subtree where the tree held one (cmds/export.c collect_name reads `filemode
 * == GIT_FILEMODE_TREE`). No other reader looks past `kind`.
 *
 * `out` is written on success alone; on any error it is left as the caller supplied
 * it, as profile_get_tree_stats leaves its own.
 *
 * Readers: the four verbs that act on one name — `show -p` (cmds/show.c show_file),
 * the entry a revert restores (cmds/revert.c entry_to_restore), the history's
 * pre-check (cmds/list.c list_file_history), export's name arm (cmds/export.c
 * collect_name) — and the search by name across the local branches (core/profiles.c
 * claim_by_name). A reader not on this list is a bug. Three neighbours ask a
 * different question and are not readers: revert's read of the tip at the name
 * it writes (cmds/revert.c cmd_revert, step 11) asks Git's one-entry rule, which
 * the sheet must not answer — a directory claim there is retired by the write,
 * not refused; the orphan probe (core/workspace.c compute_orphan_authority) asks
 * the one document the record's kind lives in and folds every failure to
 * UNVERIFIED; the count's staleness probe (core/profiles.c profile_get_tree_stats)
 * and export's claim append (cmds/export.c append_claim_dirs) hold the sheet's
 * item and ask whether the tree contradicts it, which is the enumeration's question
 * (core/manifest.c manifest_claim_blob's contradiction index).
 *
 * The point query, where the enumeration is its sibling: "what does this branch
 * hold" is asked of one name here and of the whole branch at the sites the
 * contradiction index serves. A producer of the second would answer the first
 * from a list it already holds, and `sheet` is the parameter that would go with
 * it — so it is the seam to re-cut, not a settled part of this shape.
 *
 * Cost: one tree lookup; one sheet parse where the tree is silent and the caller
 * handed none.
 *
 * @param repo Repository the tree's blobs, the sheet among them, are read from
 *             (must not be NULL)
 * @param tree The tree the name is asked of — a tip's or a commit's (must not
 *             be NULL)
 * @param sheet The caller's sheet of that tree, or NULL to read it here on the
 *              tree's silence
 * @param profile Whose branch it is, for the sheet's load and the refusals (must
 *                not be NULL)
 * @param name A validated storage path (must not be NULL)
 * @param out The answer (must not be NULL; written on success alone)
 * @return Error or NULL on success
 */
error_t *profile_holds(
    git_repository *repo,
    const git_tree *tree,
    const metadata_t *sheet,
    const char *profile,
    const char *name,
    profile_held_t *out
);

/**
 * List deployable files in a Git tree
 *
 * Walks the tree, filters metadata paths, and returns storage paths. This is
 * the lightweight primitive for "files in a branch" — takes a pre-loaded tree
 * and returns storage paths. For callers that already hold the tree, so one branch
 * read serves the walk and whatever else the caller does with it.
 *
 * Complete or an error: an entry whose path no mount can place is corruption
 * and fails the walk rather than being skipped, since a listing short by a path
 * the caller cannot place would still read as complete. A branch this machine
 * authored holds no such entry; one that arrived by clone, sync or foreign push
 * can.
 *
 * @param tree Git tree to walk (must not be NULL)
 * @param out String array of storage paths (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_list_tree_files(
    const git_tree *tree,
    string_array_t **out
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
 * @param out String array of storage paths (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_list_files(
    git_repository *repo,
    const char *profile,
    string_array_t **out
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
 * (plan_validate says why), add's implicit enable authors no such row (a created
 * profile's custom/ claim requires --target, which the row takes), sync and a
 * re-bind can leave an enabled row needing one, and `profile validate` does not
 * ask — an enabled row with no binding is a lifecycle stage the health channel
 * names, not an inconsistency. add asks no producer: it holds a view over its
 * own opened tree under its own table and reads the slice on that (cmds/add.c
 * report_enable_hint).
 *
 * Cost: one tree walk and one sheet load, in an arena of the call's own — the
 * product is a bool and nothing outlives the call (include/runtime.h, the
 * frame-scope lifetime). Measured at 0.144.2 on a 1,000-path branch: 2.5 ms,
 * against 31 ms for the statistics beside it, whose object-header read per blob
 * is the larger half.
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param needs_target Output flag: the branch holds a claim no binding-less table
 *                     places — the view's own unbound count, non-zero (must not
 *                     be NULL)
 * @return Error or NULL on success
 */
error_t *profile_needs_target(
    git_repository *repo,
    const char *profile,
    bool *needs_target
);

/**
 * The name `profile` has for `location` in `tree`: the claim standing there, or
 * the name a claim there would take
 *
 * A location key, and the only one. The resolver answers two and the other is
 * already settled where the argument was read (infra/path.h): a name the user
 * typed is Git's key, so the caller's own read of the branch's two documents
 * decides whether the profile holds it (profile_holds) and there is nothing here
 * to ask — a name no claim sheet mentions, a bare subtree, a name the view did
 * not keep, is held by the branch and never by its view. What arrives here is
 * the key that needs the branch to answer it.
 *
 * Asked of the profile's own view of `tree` (manifest_build_tree, the sheet loaded
 * strictly), in this order: the row standing there answers with its own name
 * whatever its kind, so home/jail/etc/x under a binding at ~/jail is found by
 * ~/jail/etc/x and the chain above a file captured before the binding answers
 * as the claim it is; else the name the profile would give the location
 * (manifest_name) — the word a history search and a not-found line need, which
 * at a root of the profile's own is that root's label's word. Two arms and no
 * third: naming is total, so every location this is asked about has a name.
 *
 * The row before the namer is the contract, not a shortcut: a derived claim is
 * something the profile holds and nothing it names (manifest_is_derived), so
 * the namer alone would climb past it and answer a name the branch never held.
 * Search first, name second.
 *
 * A name, never an enumeration. A DIRECTORY claim names its location and says
 * nothing about what stands beneath it (core/manifest.h manifest_lookup_claim);
 * a verb that means everything at a place selects rows by location (cmds/export.c)
 * and never walks this answer's subtree.
 *
 * `mounts` is the table the rows are placed by, and the location keys against
 * them by strcmp (infra/mount.h). The answer is the arena's — the view's own
 * row string, or the namer's — and outlives the view this call builds and frees.
 *
 * Cost: one tree walk and one sheet load, every call. Its other face: a profile
 * whose sheet will not load refuses a location where the name its caller answers
 * unaided proceeds — the view is strict, a verb's own read is not
 * (core/manifest.h). A ref or a tree that will not load refuses both.
 *
 * Readers: `show -p` and `list -p` over the tree the verb selected (the branch's
 * tip, or the commit the user named, so a name that changed since is found as
 * of then). `export` selects rows instead, `remove` matches its own claims,
 * `revert` reads the claim standing in the tree it edits (cmds/revert.c
 * claim_standing), and `ignore --test` asks manifest_name itself.
 *
 * @param repo Repository the tree's blobs (the sheet among them) are read from
 *             (must not be NULL)
 * @param tree The tree the claim is looked for in (must not be NULL)
 * @param mounts The table the rows are placed by (must not be NULL)
 * @param profile Whose claims these are (must not be NULL)
 * @param location Where to ask, spelled as the rows are keyed (must not be NULL)
 * @param arena Arena that owns the answer (must not be NULL)
 * @param out_storage Arena-borrowed storage path; NULL after an error (must not
 *                    be NULL)
 * @return Error or NULL on success
 */
error_t *profile_claim_name(
    git_repository *repo,
    const git_tree *tree,
    const mount_table_t *mounts,
    const char *profile,
    const char *location,
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
 * directory claim in its sheet (profile_holds); the claim is the name as typed.
 * A LOCATION argument: every branch whose view of its own tip, under this machine's
 * table, holds a row there — the claim being that branch's own name for the place,
 * since a location may be held under a non-canonical name and the caller must
 * not name it again.
 *
 * The table is this machine's, and this machine's table is the enabled set's
 * (core/manifest.h manifest_mount_table): a profile nothing has enabled has no
 * binding here at all, so its custom/ claims stand nowhere and no location reaches
 * them. That is the model being consistent, not a gap — by name they are found
 * as they always were.
 *
 * Complete or an error: a branch that will not load, a lookup that fails for
 * any reason but absence, a claim that could not be recorded — each is the call's
 * failure and never a shorter list, a falsely unique answer being one a verb
 * acts on. Empty is ERR_NOT_FOUND naming the argument in its own key. The branch
 * list is one enumeration, not a snapshot: a ref born between it and the reads
 * is not consulted.
 *
 * Cost, and the asymmetry it carries: a location builds one view per branch — a
 * tree walk and a sheet load each, every branch's rows kept in the arena until
 * the command ends — where a name is one tree lookup per branch and a sheet parse
 * for each branch whose tree is silent about it, which for a name one branch
 * holds is every other branch. So a branch whose sheet will not load refuses
 * `revert <location>` always and `revert <name>` wherever its tree does not hold
 * the name; a name its tree holds is answered without its sheet, which is all
 * that is left of the strict/tolerant split here. Naming the profile skips the
 * search entirely, and the one caller says so where it refuses.
 *
 * Reader: revert without a profile, whose question is every local branch and
 * not the enabled set. A caller that wants the owning profile among the enabled
 * set asks the view instead (manifest_lookup, manifest_holders — list, show).
 *
 * The key is the input here, where its sibling takes a location outright
 * (profile_claim_name): both keys run this one search — the same enumeration,
 * the same collection, the same refusal when nothing holds it — and the tag chooses
 * which probe each branch is asked. Over there the other key is an answer the
 * caller already holds, so nothing is left for the call to do with it. A sum
 * that chooses among a function's own behaviours is its input; one whose arm
 * means "there was nothing to ask" is the caller's question smuggled in.
 *
 * @param repo Repository (must not be NULL)
 * @param mounts This machine's mount table (must not be NULL)
 * @param arg The argument, in the key it named — a location or a storage path
 *            (must not be NULL)
 * @param arena Arena that owns the claims (must not be NULL)
 * @param out The claims, at least one (must not be NULL; zeroed after an error)
 * @return Error (ERR_NOT_FOUND when no branch holds it) or NULL on success
 */
error_t *profile_discover_claims(
    git_repository *repo,
    const mount_table_t *mounts,
    const path_input_t *arg,
    arena_t *arena,
    profile_claims_t *out
);

/**
 * location → the claims every local branch but `exclude` places there
 *
 * Each branch read once through its own view of its tip under this machine's
 * table, so a claim is keyed by where it stands and never by what it is called:
 * two profiles bound at two targets holding one name are two locations and meet
 * no key of each other's, and one profile's two names for one location are one
 * row and one entry. A claim this machine cannot place stands nowhere and is
 * not indexed. Directory claims are indexed like any row — the branch claims
 * the directory, and a caller asking who else is at a place is owed it.
 *
 * The map borrows its keys — a row's own location string, the arena's — and its
 * values are the arena's: free the map alone, hashmap_free(index, NULL).
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
 * Reader: remove's overlap analysis.
 *
 * @param repo Repository (must not be NULL)
 * @param mounts This machine's mount table (must not be NULL)
 * @param exclude A branch to leave out, or NULL for every one of them
 * @param arena Arena that owns the claims (must not be NULL)
 * @param out_index location (const char *) -> profile_claims_t * (must not be
 *                  NULL; free with hashmap_free(index, NULL))
 * @return Error or NULL on success
 */
error_t *profile_build_location_index(
    git_repository *repo,
    const mount_table_t *mounts,
    const char *exclude,
    arena_t *arena,
    hashmap_t **out_index
);

#endif /* DOTTA_PROFILES_H */
