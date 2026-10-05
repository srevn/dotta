/**
 * profiles.h - Profile name resolution and Git queries
 *
 * Handles profile detection, name resolution, and branch-level queries: the
 * questions asked of one branch, answered from Git and this machine's topology.
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

#include "core/branch.h"

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
 * Does this profile's branch need a deployment target?
 *
 * Definitional, not a rule of its own: the labels the branch's walk shows claims
 * under (core/branch.h branch_walk), each asked of the one table no state row
 * can produce — HOME and the root sentinel, no binding — for the profile's root
 * of it (infra/mount.h mount_root_of). A label with no root there is one only a
 * binding places, so a claim under it is the answer. Every home/ and root/ claim
 * has its root; a custom/ claim — a blob under custom/ or at the word itself, a
 * custom/ item of the sheet, tracked or derived — has none. Which labels a binding
 * places is the table's to say (mount_table_build), so a label it learns to bind
 * moves the answer with it, no clause here having to follow. An empty custom
 * tree needs none, by the same reading: the walk shows no claim in it, and a
 * binding would place nothing for it.
 *
 * It is the view's own answer by another route, and agrees with it by construction:
 * the view's contribution places every claim the same walk shows, and records
 * on the health slice exactly the claims whose label the table has no root of
 * (core/manifest.c manifest_place_claim, through mount_resolve, whose absence
 * is mount_root_of's). So a view built over the branch under that table holds
 * an unbound claim exactly where this says yes (tests/test-profiles.c holds the
 * two together), and none is built here.
 *
 * The branch's fact and not this machine's: asked under a table with no binding
 * so that what the branch needs and what this machine binds are two facts, the
 * first answerable where the second is not in scope (clone holds no state at
 * its skip), and unchanged by a row this machine writes.
 *
 * Complete or an error: a sheet this build cannot read, and a tree the walk refuses
 * — a name outside the storage grammar, a subtree the store lacks — fail here,
 * the failures the next view build over the same branch would fail on, met before
 * `profile enable` writes the row. A branch that will not load is its caller's,
 * which loads it (core/branch.h branch_load). A caller that must not fail whole
 * on one branch absorbs the error and renders the row as unreadable
 * (cmds/interactive.c read_targets), as cmds/profile.c's listing already does
 * for a count's error.
 *
 * Readers: the three enablers' skip — `profile enable` (cmds/profile.c
 * profile_enable), clone (cmds/clone.c cmd_clone), the editor's OFF→ON gate —
 * the two marks, the listing's available rows and the editor's, and the editor's
 * `t`, live only on a row that can be bound. The listing asks it of the handle
 * its row counted over (cmds/profile.c profile_list); the editor's three read
 * the one answer its rows keep (cmds/interactive.c read_targets). The rule these
 * keep is "a profile that needs a target is not enabled without one", and its
 * scope is theirs alone, not an invariant of the rows: the editor prompts and
 * lets a row be saved unbound (cmds/interactive.c plan_classify says why), add's
 * implicit enable authors no such row (a created profile's custom/ claim requires
 * --target, which the row takes), sync and a re-bind can leave an enabled row
 * needing one, and `profile validate` does not ask — an enabled row with no binding
 * is a lifecycle stage the health channel names, not an inconsistency. add asks
 * no producer: it holds a view over its own opened tree under its own table and
 * reads the slice on that (cmds/add.c add_print_enable).
 *
 * Cost: one walk of the branch — whose sheet a question before it may have parsed
 * already, the handle keeping it — and a two-root table in a frame of the call's
 * own: the product is a bool and nothing outlives the call (include/runtime.h
 * "Memory", no arena in reach). Measured at 0.165.12, a walk past the parse costs
 * about 0.13 µs a claim; the view built here before cost 2.5 ms per 1,000 paths.
 *
 * @param branch The profile's branch, at its tip as every reader loads it (must
 *               not be NULL; its sheet read through it)
 * @param needs_target Output flag: the branch holds a claim under a label the
 *                     binding-less table has no root of (must not be NULL; false
 *                     after an error)
 * @return Error or NULL on success: the sheet's, in the loader's words; the tree's,
 *         under "Cannot read profile '%s'"
 */
error_t profile_needs_target(branch_t *branch, bool *needs_target);

#endif /* DOTTA_PROFILES_H */
