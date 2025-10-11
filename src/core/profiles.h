/**
 * profiles.h - Profile management
 *
 * Handles profile detection, loading, and file manifest generation.
 *
 * Profile precedence (lowest to highest):
 * 1. global
 * 2. <os> (darwin, linux, freebsd)
 * 3. hosts/<hostname>
 *
 * Later profiles override earlier ones for conflicting files.
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
    char *storage_path;      /* Path in profile (home/.bashrc) */
    char *filesystem_path;   /* Deployed path (/home/user/.bashrc) */
    git_tree_entry *entry;   /* Git tree entry (borrowed from tree) */
    profile_t *source_profile; /* Which profile provides this file */
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
 * Detects: global, OS name, hosts/<hostname>
 * Only includes profiles that exist as branches.
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
 * Load profiles with config and auto-detect fallback
 *
 * Priority:
 * 1. If profile names are provided, loads those specific profiles
 * 2. If config->profile_order is set, uses those profiles
 * 3. If auto_detect is true, auto-detects profiles (global, OS, host)
 * 4. Otherwise, returns empty profile list
 *
 * @param repo Repository (must not be NULL)
 * @param names Profile names (can be NULL for auto-detect)
 * @param count Number of profiles (0 for auto-detect)
 * @param config_profiles Profile names from config (can be NULL)
 * @param config_profile_count Number of config profiles (0 if none)
 * @param auto_detect Enable auto-detection (from config)
 * @param strict_mode If true, error on non-existent profiles in config; if false, skip them
 * @param out Profile list (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_load_with_fallback(
    git_repository *repo,
    const char **names,
    size_t count,
    const char **config_profiles,
    size_t config_profile_count,
    bool auto_detect,
    bool strict_mode,
    profile_list_t **out
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
 * List files in profile
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile (must not be NULL)
 * @param out String array of storage paths (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_list_files(
    git_repository *repo,
    const profile_t *profile,
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
 * Get OS name for profile detection
 *
 * @param out OS name (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_get_os_name(char **out);

/**
 * Get hostname for profile detection
 *
 * @param out Hostname (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_get_hostname(char **out);

#endif /* DOTTA_PROFILES_H */
