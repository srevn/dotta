/**
 * profiles.h - Profile name resolution and Git queries
 *
 * Handles profile detection, name resolution, and branch-level queries.
 * Pure query module — no manifest types or construction.
 *
 * Profile precedence (lowest to highest):
 * 1. global
 * 2. <os> (darwin, linux, freebsd) - base OS profile
 * 3. <os>/<variant> (darwin/name, freebsd/services) - OS sub-profiles (sorted alphabetically)
 * 4. hosts/<hostname> - host base profile
 * 5. hosts/<hostname>/<variant> - host sub-profiles (sorted alphabetically)
 *
 * Later profiles override earlier ones for conflicting files.
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
 * Pure name-based detection using system information (OS, hostname).
 * Returns names in precedence order. Always includes "global" first
 * if present in the available branches.
 *
 * Detection order:
 * 1. "global" — always included if available
 * 2. <os> — OS base profile (darwin, linux, freebsd)
 * 3. <os>/<variant> — OS sub-profiles (sorted alphabetically, one level deep)
 * 4. hosts/<hostname> — host base profile
 * 5. hosts/<hostname>/<variant> — host sub-profiles (sorted alphabetically)
 *
 * No Git operations — takes a branch name list, returns matching names.
 * All detection steps are non-fatal (skip on system call failure).
 *
 * @param available_branches List of branch names to match against (must not be NULL)
 * @param out_profiles Matched profile names in precedence order (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_detect(
    const string_array_t *available_branches,
    string_array_t **out_profiles
);

/**
 * Resolve CLI profile names for operation filtering
 *
 * Lightweight validation of CLI profile arguments: checks that each name
 * corresponds to an existing branch without resolving Git refs or loading
 * profile objects. Returns validated names as a string array.
 *
 * Use this when opts->profiles != NULL && opts->profile_count > 0.
 *
 * @param repo Repository (must not be NULL)
 * @param cli_profiles CLI profile arguments (must not be NULL)
 * @param cli_count Number of CLI profiles (must be > 0)
 * @param strict_mode If true, error on non-existent profiles; if false, skip them
 * @param out Validated profile names (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_resolve_filter(
    git_repository *repo,
    char *const *cli_profiles,
    size_t cli_count,
    bool strict_mode,
    string_array_t **out
);

/**
 * Resolve enabled profile names from state database
 *
 * Lightweight name-only resolution: reads enabled profiles from state,
 * validates that each exists as a branch, and returns validated names.
 * Warns on stderr about profiles referenced in state that no longer exist.
 *
 * Does NOT resolve Git references or load profile trees.
 *
 * @param repo Repository (must not be NULL)
 * @param state State handle (must not be NULL; borrowed, not freed).
 *              Only SELECTs are executed — safe to pass a state_open() handle.
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
 * Materializes the profile→target bindings recorded in
 * enabled_profiles into a mount_table_t handle, augmented internally with
 * HOME and the empty-prefix root sentinel. The handle is the single
 * downstream entry point for both filesystem→storage classification and
 * profile-keyed storage→filesystem resolution.
 *
 * Two modes (selected by the names argument):
 *   - names == NULL: every enabled profile contributes a binding (full
 *     row-cache scan in position order). Used by read-only callers
 *     (list/show/revert) that resolve paths without a narrowing filter.
 *   - names != NULL: only the named profiles contribute (per-name peek in
 *     the caller's order). Used by scope_build to feed CLI -p narrowing
 *     into path classification. Names outside the enabled set yield
 *     bindings with NULL target, which mount_table_t records for
 *     forward-resolution lookups but does not add to the candidate set.
 *
 * Lifetime contract:
 *   - The returned handle is allocated entirely from `arena`.
 *   - In the names != NULL branch, profile names are arena_strdup'd into
 *     the bindings (decoupled from the caller's array lifetime). This
 *     makes the handle safe to consult between any caller-side cleanup
 *     of `names` and arena destruction.
 *   - In the names == NULL branch, profile names are borrowed directly
 *     from the state row cache. The borrow stays valid as long as no
 *     enabled_profiles shape mutation runs (state_enable_profile,
 *     state_disable_profile, state_set_profiles, state_rollback,
 *     state_free).
 *   - target strings are always borrowed from the state row cache
 *     (same shape-mutation invariant).
 *
 * Failure modes:
 *   - State-read failure (cold clone, transient DB issue) is absorbed:
 *     the function falls back to a bare table (HOME + root sentinel
 *     only). Callers do not need to handle this case.
 *   - Arena allocation failure surfaces as ERR_MEMORY.
 *
 * @param state State handle (must not be NULL; borrowed, not freed)
 * @param names Profile names to build bindings for, or NULL for all enabled
 * @param arena Arena backing the handle (must not be NULL; outlives handle)
 * @param out Output handle (must not be NULL; lifetime tracks arena)
 * @return Error or NULL on success
 */
error_t *profile_build_mount_table(
    const state_t *state,
    const string_array_t *names,
    arena_t *arena,
    mount_table_t **out
);

/**
 * Validate that filter profiles are enabled
 *
 * Ensures CLI filter only references profiles that are actually enabled
 * in the workspace. This prevents confusing behavior where user filters
 * to a disabled profile.
 *
 * @param enabled_profiles Enabled profile names from state (must not be NULL)
 * @param filter CLI filter profile names (NULL = no filter)
 * @return Error if any filter profile is not enabled, NULL on success
 */
error_t *profile_validate_filter(
    const string_array_t *enabled_profiles,
    const string_array_t *filter
);

/**
 * List all local profile branch names
 *
 * Returns names of all local branches except 'dotta-worktree'.
 * Iterates Git refs and extracts branch names without resolving
 * references or loading trees.
 *
 * @param repo Repository (must not be NULL)
 * @param out String array of branch names (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_list_all_local(
    git_repository *repo,
    string_array_t **out
);

/**
 * Check if profile exists
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @return true if profile branch exists
 */
bool profile_exists(git_repository *repo, const char *profile);

/**
 * List files in profile
 *
 * Loads the profile's Git tree internally and walks it to collect
 * storage paths. Tree is freed before return.
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
 * Loads profile and scans for files with custom/ prefix.
 * Used by command layer to validate --target requirement.
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
 * Creates a hashmap that maps storage paths to lists of profile names,
 * enabling O(1) lookups for multi-profile conflict detection and overlap analysis.
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
 *                  (must not be NULL, caller must free with hashmap_free(..., string_array_free))
 * @return Error or NULL on success
 */
error_t *profile_build_file_index(
    git_repository *repo,
    const char *exclude_profile,
    hashmap_t **out_index
);

/**
 * Discover which profile(s) own a file
 *
 * Two-tier resolution:
 * 1. enabled_only=true: Manifest fast path, O(1) via state DB index.
 *    Returns the single owning profile (precedence already resolved).
 *
 * 2. enabled_only=false: Branch scan, O(M×P) via profile_build_file_index().
 *    Returns ALL profiles containing the file across all local branches.
 *
 * The storage_path must already be resolved (use mount_resolve_input() first).
 *
 * @param repo Repository (must not be NULL)
 * @param state State handle (must not be NULL; borrowed, not freed).
 *              Required on both paths for signature consistency, but
 *              read only on the enabled_only=true (manifest) path; the
 *              branch-scan path does not touch state.
 * @param storage_path Storage path (e.g., "home/.bashrc")
 * @param enabled_only If true, only search manifest (enabled profiles).
 *                     If false, search all local branches.
 * @param out_profiles Matching profile names (caller frees with string_array_free)
 * @return Error (ERR_NOT_FOUND if no match) or NULL on success
 */
error_t *profile_discover_file(
    git_repository *repo,
    const state_t *state,
    const char *storage_path,
    bool enabled_only,
    string_array_t **out_profiles
);

#endif /* DOTTA_PROFILES_H */
