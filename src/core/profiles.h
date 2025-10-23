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

#include "types.h"
#include "utils/hashmap.h"

/**
 * Profile structure
 */
typedef struct {
    char *name;              /* Profile name (e.g., "global", "darwin") */
    git_reference *ref;      /* Branch reference */
    git_tree *tree;          /* Profile tree (loaded lazily) */
    bool auto_detected;      /* Auto-detected vs manually specified */
} profile_t;

/**
 * File entry in manifest
 *
 * Represents a single file to be deployed.
 */
typedef struct {
    char *storage_path;              /* Path in profile (home/.bashrc) */
    char *filesystem_path;           /* Deployed path (/home/user/.bashrc) */
    git_tree_entry *entry;           /* Git tree entry (borrowed from tree) */
    profile_t *source_profile;       /* Which profile provides this file (highest precedence) */
    string_array_t *all_profiles;    /* All profile names containing this file (for overlap detection) */
} file_entry_t;

/**
 * Manifest - collection of files to deploy
 */
typedef struct {
    file_entry_t *entries;
    size_t count;
} manifest_t;

/**
 * Profile list
 */
typedef struct {
    profile_t *profiles;
    size_t count;
} profile_list_t;

/**
 * Auto-detect profiles
 *
 * Detects profiles in precedence order:
 * 1. global - Universal settings
 * 2. <os> - OS base profile (darwin, linux, freebsd)
 * 3. <os>/<variant> - OS sub-profiles (darwin/name, one level deep, sorted alphabetically)
 * 4. hosts/<hostname> - Host base profile
 * 5. hosts/<hostname>/<variant> - Host sub-profiles (one level deep, sorted alphabetically)
 *
 * Only includes profiles that exist as branches.
 *
 * Examples:
 * - OS "darwin" with profiles "darwin", "darwin/name", "darwin/work":
 *   → global → darwin → darwin/name → darwin/work
 *
 * - Hostname "visavis" with profile "hosts/visavis":
 *   → global → darwin → hosts/visavis
 *
 * - Hostname "visavis" with profiles "hosts/visavis/github" and "hosts/visavis/work":
 *   → global → darwin → hosts/visavis/github → hosts/visavis/work
 *
 * - Combined hierarchical profiles:
 *   → global → darwin → darwin/name → hosts/visavis → hosts/visavis/work
 *
 * Note: Git refs don't allow both hosts/<hostname> and hosts/<hostname>/<variant>
 * to coexist. Use either a base profile OR sub-profiles, not both.
 *
 * @param repo Repository (must not be NULL)
 * @param out Profile list (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_detect_auto(
    git_repository *repo,
    profile_list_t **out
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
 * @param count Number of profiles
 * @param strict If true, error on non-existent profiles; if false, skip them
 * @param out Profile list (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_list_load(
    git_repository *repo,
    const char **names,
    size_t count,
    bool strict,
    profile_list_t **out
);

/**
 * Resolve profiles based on priority hierarchy (unified profile resolution)
 *
 * This is the primary function for loading profiles throughout the application.
 * All commands (apply, update, sync, status, etc.) use this function.
 *
 * Resolution priority (highest to lowest):
 * 1. Explicit profiles (CLI -p/--profile) - Temporary override
 * 2. State file profiles - Persistent management (via 'dotta profile enable')
 *
 * If no profiles are found from any source, returns an error. Profiles must be
 * explicitly enabled using 'dotta profile enable' or specified via CLI.
 *
 * @param repo Repository (must not be NULL)
 * @param explicit_profiles CLI profiles (can be NULL)
 * @param explicit_count Count of CLI profiles (0 if none)
 * @param strict_mode If true, error on missing profiles; if false, skip them
 * @param out Profile list (must not be NULL, caller must free)
 * @param source_out Optional: receives the source of resolved profiles (can be NULL)
 * @return Error or NULL on success
 */
error_t *profile_resolve(
    git_repository *repo,
    const char **explicit_profiles,
    size_t explicit_count,
    bool strict_mode,
    profile_list_t **out,
    profile_source_t *source_out
);

/**
 * List all local profile branches
 *
 * Returns all local branches except 'dotta-worktree'.
 * Used by sync in 'local' mode to sync all existing local profiles.
 *
 * @param repo Repository (must not be NULL)
 * @param out Profile list (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_list_all_local(
    git_repository *repo,
    profile_list_t **out
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
 * Build manifest from profiles
 *
 * Merges files from all profiles according to precedence rules.
 * Later profiles override earlier ones.
 *
 * @param repo Repository (must not be NULL)
 * @param profiles Profile list (must not be NULL)
 * @param out Manifest (must not be NULL, caller must free with manifest_free)
 * @return Error or NULL on success
 */
error_t *profile_build_manifest(
    git_repository *repo,
    profile_list_t *profiles,
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

#endif /* DOTTA_PROFILES_H */
