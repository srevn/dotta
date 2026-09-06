/**
 * profiles.h - Profile name resolution and Git queries
 *
 * Handles profile detection, name resolution, and branch-level queries. Pure
 * query module — no manifest types or construction.
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
#include "core/state.h"
#include "infra/mount.h"

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
 * Build a per-machine mount table from state
 *
 * Materializes the profile→target bindings recorded in enabled_profiles into a
 * mount_table_t handle, augmented internally with HOME and the empty-prefix root
 * sentinel. The handle is the single downstream entry point for both
 * filesystem→storage classification and profile-keyed storage→filesystem
 * resolution.
 *
 * Single mode: every enabled profile contributes a binding (full row-cache scan
 * in position order). The mount table is per-machine topology, not a CLI artifact
 * — narrowing happens at the operation level (scope filters, profile predicates),
 * never on the topology view.
 *
 * Lifetime contract:
 *   - The returned handle is allocated entirely from `arena`, every string
 *     included: the row cache is read for the call only, so the table stands
 *     across the enabled_profiles mutations that invalidate the cache — it is
 *     the topology at the instant it was built.
 *
 * Failure modes:
 *   - A state with no database has no rows and yields the bare table (HOME +
 *     root sentinel); a row read that fails on an opened database propagates.
 *   - Arena allocation failure surfaces as ERR_MEMORY.
 *
 * @param state State handle (must not be NULL; borrowed, not freed)
 * @param arena Arena backing the handle (must not be NULL; outlives handle)
 * @param out Output handle (must not be NULL; lifetime tracks arena)
 * @return Error or NULL on success
 */
error_t *profile_build_mount_table(
    const state_t *state,
    arena_t *arena,
    mount_table_t **out
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
 * history), revert (the -p fast path), and scope's filter on its refusal path.
 * A verb that acts on both answers — add (checkout or create), enable's skip,
 * remove's --force arm, validate's probe, the view's build — asks
 * gitops_branch_exists itself and reads the bool.
 *
 * @param repo Repository (must not be NULL)
 * @param name Profile name (must not be NULL)
 * @return NULL when the branch is here; else the refusal, or Git's error
 */
error_t *profile_require(git_repository *repo, const char *name);

/**
 * Is this path inside a profile branch dotta's own bookkeeping?
 *
 * A profile branch holds two kinds of thing: the paths it tracks, every one of
 * them under a storage label (home/, root/, custom/), and dotta's own files beside
 * them at the branch root — the ignore ruleset, the bootstrap script, the metadata
 * sidecar, and what Git or a reader leaves there. Only the first kind deploys,
 * is listed, is counted, or reaches the view.
 *
 * The one producer of that distinction: every walk over a profile tree — the
 * file listing, the cross-profile index, the view's claim routine, the branch
 * statistics — asks here rather than spelling the set again.
 *
 * @param storage_path Path within the branch ("home/.bashrc",
 *                     ".dotta/metadata.json"); NULL reads as content
 * @return true when the path is bookkeeping rather than tracked content
 */
bool profile_is_repo_metadata(const char *storage_path);

/**
 * What a profile branch holds
 *
 * Counted from the branch, not from the view: the listings that report these
 * name available profiles too, and a profile nothing has enabled owns no rows.
 * The two sources are the ones the view's claim routine reads when the profile
 * *is* enabled (manifest_claim_tree) — the tree's content blobs and the branch
 * metadata's tracked directories — so a profile that wins every path it claims
 * counts the same here as its rows do there.
 */
typedef struct {
    size_t file_count;       /* Content blobs in the tree (bookkeeping excluded) */
    size_t directory_count;  /* Tracked directories the branch metadata claims */
    size_t total_size;       /* Bytes of those blobs */
    bool has_custom;         /* A custom/ tree at the top — paths a target places here */
} profile_stats_t;

/**
 * Count what a profile branch holds
 *
 * One walk of the branch tree — each content blob counted and its size taken
 * from the object header, nothing inflated — then the branch metadata's DIRECTORY
 * items. A branch with no metadata.json claims no directories; that absence is
 * not a failure. The custom/ probe (profile_has_custom_files) is answered from
 * the same tree, so a listing that marks such a profile reads the branch once.
 *
 * Performance: O(files + directories), one tree walk and one metadata load.
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param out Statistics (must not be NULL; zeroed, then filled)
 * @return Error or NULL on success
 */
error_t *profile_get_stats(
    git_repository *repo,
    const char *profile,
    profile_stats_t *out
);

/**
 * List deployable files in a Git tree
 *
 * Walks the tree, filters metadata paths, and returns storage paths. This is
 * the lightweight primitive for "files in a branch" — takes a pre-loaded tree
 * and returns storage paths. For callers that already hold the tree, so one branch
 * read serves the walk and whatever else the caller does with it.
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
 * Tree is freed before return.
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
 * Check if profile contains any custom/ files
 *
 * The branch probe: does this profile hold a tree that needs a target here? A
 * profile with custom/ paths is enabled only with one, and the three enable sites
 * read this before the row is written — `profile enable` (the skip), clone (the
 * skip), the interactive rows (the gate on space, and the mark). The probe reads
 * the branch, so it answers for a set the build refuses too.
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param out_has_custom Output flag (must not be NULL)
 * @return Error or NULL on success
 */
error_t *profile_has_custom_files(
    git_repository *repo,
    const char *profile,
    bool *out_has_custom
);

/**
 * Build inverted index of all files across profiles
 *
 * Creates a hashmap that maps storage paths to lists of profile names, enabling
 * O(1) lookups for multi-profile conflict detection and overlap analysis.
 *
 * The index maps: storage_path (char*) -> string_array_t* (list of profile names)
 *
 * This is a performance optimization for operations that need to check which
 * profiles contain specific files. Instead of loading each profile's tree
 * repeatedly (O(N×M×GitOps)), this function loads all profiles once (O(M×P))
 * and provides O(1) lookups.
 *
 * Usage:
 * - Multi-profile conflict detection (update, remove commands)
 * - File overlap analysis
 * - Profile relationship mapping
 *
 * Complexity: O(M×P) where M = profile count, P = avg files per profile
 *
 * @param repo Repository (must not be NULL)
 * @param exclude_profile Optional profile name to exclude from index (can be NULL)
 * @param out_index Output hashmap: storage_path -> string_array_t* of profile names
 *                  (must not be NULL, caller must free with hashmap_free(...,
 *                  string_array_free))
 * @return Error or NULL on success
 */
error_t *profile_build_file_index(
    git_repository *repo,
    const char *exclude_profile,
    hashmap_t **out_index
);

/**
 * Discover which profile(s) contain a file, across every local branch
 *
 * Branch scan, O(M×D) where D = path depth: each branch's HEAD tree is asked
 * for the one path. Returns ALL profiles containing the file, enabled or not —
 * revert's question. A caller that wants the owning profile among the enabled
 * set asks the view instead (manifest_lookup_storage on a manifest_build over
 * the enabled profiles — list, show).
 *
 * The storage_path must already be resolved (use path_input_resolve() first).
 *
 * @param repo Repository (must not be NULL)
 * @param storage_path Storage path (e.g., "home/.bashrc")
 * @param out_profiles Matching profile names (caller frees with string_array_free)
 * @return Error (ERR_NOT_FOUND if no match) or NULL on success
 */
error_t *profile_discover_file(
    git_repository *repo,
    const char *storage_path,
    string_array_t **out_profiles
);

#endif /* DOTTA_PROFILES_H */
