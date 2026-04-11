/**
 * profiles.h - Profile management
 *
 * Handles profile detection, loading, and file manifest generation.
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
 * - Efficient manifest building
 */

#ifndef DOTTA_PROFILES_H
#define DOTTA_PROFILES_H

#include <git2.h>
#include <time.h>
#include <types.h>

#include "base/hashmap.h"
#include "core/state.h"

/**
 * Profile structure
 *
 * head_oid is the peeled commit (or tree, for orphan branches) OID of the
 * profile's branch HEAD at load time. profile_load populates it via a single
 * git_reference_peel, so any profile_t constructed through the loader carries
 * its current HEAD OID without further Git operations. Stack-initialized
 * profile_t bypassing profile_load would have a zero head_oid — none exist
 * in the codebase.
 *
 * peeled retains the git_object produced by that single peel so profile_load_tree
 * can reuse it instead of re-peeling the same ref. It is consumed (freed or
 * ownership-transferred to profile->tree) by the first profile_load_tree call;
 * if tree loading is never invoked, profile_free releases it. NULL after
 * consumption.
 */
typedef struct {
    char *name;              /* Profile name (e.g., "global", "darwin") */
    git_reference *ref;      /* Branch reference */
    git_tree *tree;          /* Profile tree (loaded lazily) */
    git_object *peeled;      /* Peeled ref object from profile_load, consumed by
                                profile_load_tree or released by profile_free */
    git_oid head_oid;        /* Peeled HEAD OID (set by profile_load) */
} profile_t;

/**
 * File entry in manifest
 *
 * Represents a single file to be deployed. This structure serves as the
 * Virtual Working Directory (VWD) cache, storing both Git tree information
 * and expected state from the database for efficient divergence detection.
 *
 * VWD Architecture:
 * - The manifest is the authoritative cache of expected state
 * - Fields are populated from state database during workspace load
 * - Enables O(1) divergence checking without N database queries
 * - Tree entries are lazy-loaded on demand (NULL until needed)
 * - For manifests built from Git trees, tree entries are pre-populated
 *
 * Memory ownership:
 * - All string fields are owned and must be freed in manifest_free()
 * - git_tree_entry is owned and must be freed (NULL is valid, means not loaded)
 * - source_profile is borrowed (from profile_list_t or workspace profile_index)
 * - profile_name is borrowed (same lifetime as source_profile
 *   or manifest's owned_profile_name for tree-based manifests)
 */
typedef struct {
    /* Paths */
    char *storage_path;              /* Path in profile (home/.bashrc) */
    char *filesystem_path;           /* Deployed path (/home/user/.bashrc) */

    /* Git tree reference */
    git_tree_entry *entry;           /* Git tree entry (owned, lazy-loaded, can be NULL) */

    /* Profile ownership
     *
     * source_profile is a tree-loading handle — only used by
     * file_entry_ensure_tree_entry() for lazy Git tree access and by
     * patch_entry_from_fresh() for pointer identity comparison.
     * All name-based operations use profile_name instead.
     *
     * NULL invariant: For manifests from profile_build_manifest() and
     * workspace_build_manifest_from_state(), profile_name is NULL iff
     * source_profile is NULL (set together at all assignment sites).
     * For tree-based manifests (profile_build_manifest_from_tree()),
     * source_profile is NULL while profile_name is set (tree entries
     * are pre-populated, so lazy loading is never needed).
     */
    profile_t *source_profile;       /* Git tree-loading handle (borrowed, core-internal) */
    const char *profile_name;        /* Profile name (borrowed, used for all name-based operations) */

    /* VWD Expected State Cache (populated from state database)
     *
     * These fields cache the expected state from the manifest table,
     * eliminating N+1 queries during divergence analysis. They represent
     * what the file SHOULD be according to enabled profiles.
     */
    char *old_profile;               /* Previous owner if changed, NULL otherwise (VWD cache) */
    char *git_oid;                   /* Git commit reference (40-char hex, can be NULL) */
    char *blob_oid;                  /* Git blob OID (40-char hex, can be NULL) */
    state_file_type_t type;          /* File type (REGULAR, SYMLINK, EXECUTABLE) */
    mode_t mode;                     /* Permission mode (e.g., 0644), 0 if no metadata tracked */
    char *owner;                     /* Owner username (root/ files only, can be NULL) */
    char *group;                     /* Group name (root/ files only, can be NULL) */
    bool encrypted;                  /* Encryption flag */
    time_t deployed_at;              /* Lifecycle timestamp (0 = never deployed, >0 = known) */
    stat_cache_t stat_cache;         /* Filesystem stat at last known-good state (all-zero = unset) */
} file_entry_t;

/**
 * Manifest - collection of files to deploy
 *
 * The index field provides O(1) lookups by filesystem_path. It maps
 * filesystem_path -> array index (offset by 1 to distinguish NULL from index 0).
 * The index is populated by profile_build_manifest() and can be NULL for
 * manifests built by other means (e.g., workspace_build_manifest_from_state).
 *
 * For tree-based manifests (profile_build_manifest_from_tree), the manifest
 * owns the profile name string that entries borrow.
 * This is NULL for manifests from profile_build_manifest() (which borrow
 * from the caller's profile_list_t) and workspace_build_manifest_from_state()
 * (which borrow from the workspace's profile_index).
 */
typedef struct {
    file_entry_t *entries;
    size_t count;
    hashmap_t *index;              /* Maps filesystem_path -> index in entries array (offset by 1), can be NULL */
    char *owned_profile_name;      /* Owned name for tree-based manifests (NULL otherwise) */
    bool arena_backed;             /* If true, entry string fields are arena-owned (skip free) */
} manifest_t;

/**
 * Profile list
 */
typedef struct {
    profile_t *profiles;
    size_t count;
} profile_list_t;

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
 * @param out_names Matched profile names in precedence order (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_detect_names(
    const string_array_t *available_branches,
    string_array_t **out_names
);

/**
 * Load specific profile
 *
 * @param repo Repository (must not be NULL)
 * @param name Profile name (must not be NULL)
 * @param out Profile (must not be NULL, caller must free with profile_free)
 * @return Error or NULL on success
 */
error_t *profile_load(
    git_repository *repo,
    const char *name,
    profile_t **out
);

/**
 * Load multiple profiles
 *
 * @param repo Repository (must not be NULL)
 * @param names Profile names (must not be NULL)
 * @param strict If true, error on non-existent profiles; if false, skip them
 * @param out Profile list (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_list_load(
    git_repository *repo,
    const string_array_t *names,
    bool strict,
    profile_list_t **out
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
error_t *profile_resolve_cli_names(
    git_repository *repo,
    char **cli_profiles,
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
 * Does NOT resolve Git references or allocate profile_t structs.
 *
 * @param repo Repository (must not be NULL)
 * @param state State handle for connection reuse (NULL = load internally)
 *              When non-NULL, only reads from the handle (const). Safe to
 *              pass a state_load_for_update() handle — only SELECTs executed.
 * @param out Validated profile names (must not be NULL, caller must free)
 * @return Error (ERR_NOT_FOUND if no enabled profiles) or NULL on success
 */
error_t *profile_resolve_state_names(
    git_repository *repo,
    const state_t *state,
    string_array_t **out
);

/**
 * Get custom deployment prefixes for named profiles
 *
 * Queries the state database for custom prefixes associated with the given
 * profile names. Returns only non-NULL prefixes (profiles with standard
 * home/root deployment are omitted).
 *
 * Used by commands that need custom prefix information for path resolution
 * (apply, update, diff). Commands that only filter by name (status, sync)
 * do not need this.
 *
 * @param repo Repository (only used when state==NULL)
 * @param state State handle for connection reuse (NULL = load internally)
 *              When non-NULL, only reads from the handle (const).
 * @param names Profile names to query (must not be NULL)
 * @param out_prefixes Non-NULL custom prefixes (must not be NULL, caller frees)
 * @return Error or NULL on success (empty array if no custom prefixes)
 */
error_t *profile_get_custom_prefixes(
    git_repository *repo,
    const state_t *state,
    const string_array_t *names,
    string_array_t **out_prefixes
);

/**
 * Validate that filter profiles are enabled
 *
 * Ensures CLI filter only references profiles that are actually enabled
 * in the workspace. This prevents confusing behavior where user filters
 * to a disabled profile.
 *
 * @param workspace_names Enabled profile names from state (must not be NULL)
 * @param filter CLI filter profile names (NULL = no filter)
 * @return Error if any filter profile is not enabled, NULL on success
 */
error_t *profile_validate_filter(
    const string_array_t *workspace_names,
    const string_array_t *filter
);

/**
 * Check if profile name matches operation filter
 *
 * Helper for filtering operations by profile. Use in loops to skip
 * items not matching the filter.
 *
 * NULL filter semantics: Returns true (no filter = match all profiles).
 * This enables clean code: if (!profile_filter_matches(...)) continue;
 *
 * NULL name semantics: Returns false (defensive, NULL name never matches).
 *
 * @param profile_name Profile name to check (NULL returns false)
 * @param filter Profile names to match against (NULL = match all)
 * @return true if profile matches filter, false otherwise
 */
bool profile_filter_matches(
    const char *profile_name,
    const string_array_t *filter
);

/**
 * List all local profile branch names
 *
 * Returns names of all local branches except 'dotta-worktree'.
 * Lightweight alternative to profile_list_load — iterates Git refs
 * but only extracts branch names without resolving references or
 * allocating profile_t structs.
 *
 * @param repo Repository (must not be NULL)
 * @param out String array of branch names (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_list_all_local_names(
    git_repository *repo,
    string_array_t **out
);

/**
 * Check if profile exists
 *
 * @param repo Repository (must not be NULL)
 * @param name Profile name (must not be NULL)
 * @return true if profile branch exists
 */
bool profile_exists(git_repository *repo, const char *name);

/**
 * Load profile tree (lazy loading)
 *
 * Loads the Git tree for a profile if not already loaded.
 * The tree is cached in the profile structure.
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile (must not be NULL)
 * @return Error or NULL on success
 */
error_t *profile_load_tree(
    git_repository *repo,
    profile_t *profile
);

/**
 * Ensure tree entry is loaded for file entry (lazy load if NULL)
 *
 * Loads the git_tree_entry for a file entry if not already loaded.
 * Safe to call multiple times (idempotent). Profile tree loading is
 * cached in profile structure, so redundant calls are cheap.
 *
 * This enables lazy loading for manifests built from state database
 * (VWD architecture), where tree entries are only needed for specific
 * operations (encryption analysis, content deployment, diff generation).
 *
 * PERFORMANCE: First call is O(Git tree lookup), potentially expensive.
 * Only call when tree entry is actually needed. Callers should lazy-load
 * as late as possible (after early returns) to avoid unnecessary work.
 *
 * ERROR SEMANTICS:
 * - Returns ERR_NOT_FOUND if file doesn't exist in Git tree
 * - Returns wrapped error if profile tree fails to load
 * - Caller decides fatal (deploy/diff) vs non-fatal (encryption analysis)
 *
 * @param entry File entry (must not be NULL)
 * @param repo Repository (must not be NULL)
 * @return Error or NULL on success
 */
error_t *file_entry_ensure_tree_entry(
    file_entry_t *entry,
    git_repository *repo
);

/**
 * List files in profile
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile (must not be NULL, may load tree lazily)
 * @param out String array of storage paths (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_list_files(
    git_repository *repo,
    profile_t *profile,
    string_array_t **out
);

/**
 * Check if profile contains any custom/ files
 *
 * Loads profile and scans for files with custom/ prefix.
 * Used by command layer to validate --prefix requirement.
 *
 * @param repo Repository (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param out_has_custom Output flag (must not be NULL)
 * @return Error or NULL on success
 */
error_t *profile_has_custom_files(
    git_repository *repo,
    const char *profile_name,
    bool *out_has_custom
);

/**
 * Build manifest from profiles
 *
 * Merges files from all profiles according to precedence rules.
 * Later profiles override earlier ones.
 *
 * For profiles with custom/ files, resolves deployment prefix from
 * prefix_map (profile_name → custom_prefix). Profiles not in the map
 * or with NULL prefix deploy to home/root normally. Custom/ files are
 * skipped for profiles without a prefix entry.
 *
 * @param repo Repository (must not be NULL)
 * @param profiles Profile list (must not be NULL)
 * @param prefix_map Custom prefix map (can be NULL — all profiles use home/root)
 * @param arena Arena for string allocations (NULL = heap)
 * @param out Manifest (must not be NULL, caller must free with manifest_free)
 * @return Error or NULL on success
 */
error_t *profile_build_manifest(
    git_repository *repo,
    profile_list_t *profiles,
    const hashmap_t *prefix_map,
    arena_t *arena,
    manifest_t **out
);

/**
 * Build manifest from a single Git tree
 *
 * Creates a manifest from a specific Git tree, useful for historical diffs.
 * This is a simplified version of profile_build_manifest() for a single tree.
 *
 * @param tree Git tree to build manifest from (must not be NULL)
 * @param profile_name Profile name for entries (must not be NULL)
 * @param custom_prefix Custom prefix for custom/ paths (NULL for graceful degradation)
 * @param out Manifest (must not be NULL, caller must free with manifest_free)
 * @return Error or NULL on success
 */
error_t *profile_build_manifest_from_tree(
    git_tree *tree,
    const char *profile_name,
    const char *custom_prefix,
    manifest_t **out
);

/**
 * Free profile
 *
 * @param profile Profile to free (can be NULL)
 */
void profile_free(profile_t *profile);

/**
 * Free profile list
 *
 * @param list Profile list to free (can be NULL)
 */
void profile_list_free(profile_list_t *list);

/**
 * Free manifest
 *
 * Frees all resources including git_tree_entry objects.
 *
 * @param manifest Manifest to free (can be NULL)
 */
void manifest_free(manifest_t *manifest);

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
 * The storage_path must already be resolved (use path_resolve_input() first).
 *
 * @param repo Repository (must not be NULL)
 * @param state Optional borrowed state handle for connection reuse.
 *              NULL to load internally. Ignored when enabled_only is false
 *              (the branch-scan path does not touch state).
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
