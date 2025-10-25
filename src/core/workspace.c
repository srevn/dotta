/**
 * workspace.c - Workspace abstraction implementation
 *
 * Manages three-state consistency: Profile (git), Deployment (state.db), Filesystem (disk).
 * Detects and categorizes divergence to prevent data loss and enable safe operations.
 */

#include "workspace.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "core/ignore.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "crypto/keymanager.h"
#include "crypto/policy.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/string.h"

/**
 * Workspace structure
 *
 * Contains indexed views of all three states plus divergence analysis.
 * Uses hashmaps for O(1) lookups during analysis.
 */
struct workspace {
    git_repository *repo;          /* Borrowed reference */

    /* State data */
    manifest_t *manifest;          /* Profile state (owned) */
    state_t *state;                /* Deployment state (owned) */
    profile_list_t *profiles;      /* Selected profiles for this workspace (borrowed) */
    hashmap_t *manifest_index;     /* Maps filesystem_path -> file_entry_t* */
    hashmap_t *profile_index;      /* Maps profile_name -> profile_t* (for O(1) lookup) */

    /* Encryption and caching infrastructure */
    keymanager_t *keymanager;      /* Borrowed from global */
    content_cache_t *content_cache; /* Owned - caches decrypted content */
    hashmap_t *metadata_cache;     /* Owned - maps profile_name -> metadata_t* */

    /* Divergence tracking */
    workspace_file_t *diverged;    /* Array of diverged files */
    size_t diverged_count;
    size_t diverged_capacity;
    hashmap_t *diverged_index;     /* Maps filesystem_path -> workspace_file_t */

    /* Divergence count cache */
    size_t divergence_counts[9];   /* Cached counts for O(1) access */

    /* Status cache */
    workspace_status_t status;
    bool status_computed;
};

/**
 * Get cached metadata for profile
 *
 * Helper function to retrieve metadata from the workspace cache.
 * Returns NULL if profile has no metadata (non-fatal).
 *
 * @param ws Workspace (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @return Metadata or NULL if not available
 */
static const metadata_t *ws_get_metadata(
    const workspace_t *ws,
    const char *profile_name
) {
    if (!ws || !ws->metadata_cache || !profile_name) {
        return NULL;
    }
    return hashmap_get(ws->metadata_cache, profile_name);
}

/**
 * Create empty workspace
 */
static error_t *workspace_create_empty(
    git_repository *repo,
    profile_list_t *profiles,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    workspace_t *ws = calloc(1, sizeof(workspace_t));
    if (!ws) {
        return ERROR(ERR_MEMORY, "Failed to allocate workspace");
    }

    ws->repo = repo;
    ws->profiles = profiles;  /* Borrowed reference */

    ws->manifest_index = hashmap_create(256);  /* Initial capacity */
    if (!ws->manifest_index) {
        free(ws);
        return ERROR(ERR_MEMORY, "Failed to create manifest index");
    }

    ws->profile_index = hashmap_create(32);  /* Initial capacity for profiles */
    if (!ws->profile_index) {
        hashmap_free(ws->manifest_index, NULL);
        free(ws);
        return ERROR(ERR_MEMORY, "Failed to create profile index");
    }

    ws->diverged_index = hashmap_create(256);  /* Initial capacity */
    if (!ws->diverged_index) {
        hashmap_free(ws->profile_index, NULL);
        hashmap_free(ws->manifest_index, NULL);
        free(ws);
        return ERROR(ERR_MEMORY, "Failed to create diverged index");
    }

    /* Build profile index for O(1) profile lookup */
    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];
        error_t *err = hashmap_set(ws->profile_index, profile->name, profile);
        if (err) {
            hashmap_free(ws->diverged_index, NULL);
            hashmap_free(ws->profile_index, NULL);
            hashmap_free(ws->manifest_index, NULL);
            free(ws);
            return error_wrap(err, "Failed to index profile");
        }
    }

    ws->diverged = NULL;
    ws->diverged_count = 0;
    ws->diverged_capacity = 0;

    /* Initialize divergence count cache */
    for (size_t i = 0; i < 9; i++) {
        ws->divergence_counts[i] = 0;
    }

    ws->status = WORKSPACE_CLEAN;
    ws->status_computed = false;

    *out = ws;
    return NULL;
}

/**
 * Add diverged file to workspace
 */
static error_t *workspace_add_diverged(
    workspace_t *ws,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    divergence_type_t type,
    bool in_profile,
    bool in_state,
    bool on_filesystem,
    bool content_differs
) {
    CHECK_NULL(ws);
    CHECK_NULL(filesystem_path);

    /* Grow array if needed */
    if (ws->diverged_count >= ws->diverged_capacity) {
        size_t new_capacity = ws->diverged_capacity == 0 ? 32 : ws->diverged_capacity * 2;
        workspace_file_t *new_diverged = realloc(ws->diverged,
                                                  new_capacity * sizeof(workspace_file_t));
        if (!new_diverged) {
            return ERROR(ERR_MEMORY, "Failed to grow diverged array");
        }
        ws->diverged = new_diverged;
        ws->diverged_capacity = new_capacity;
    }

    /* Add entry */
    workspace_file_t *entry = &ws->diverged[ws->diverged_count];
    memset(entry, 0, sizeof(workspace_file_t));

    entry->filesystem_path = strdup(filesystem_path);
    entry->storage_path = storage_path ? strdup(storage_path) : NULL;
    entry->profile = profile ? strdup(profile) : NULL;
    entry->type = type;
    entry->in_profile = in_profile;
    entry->in_state = in_state;
    entry->on_filesystem = on_filesystem;
    entry->content_differs = content_differs;

    if (!entry->filesystem_path ||
        (storage_path && !entry->storage_path) ||
        (profile && !entry->profile)) {
        free(entry->filesystem_path);
        free(entry->storage_path);
        free(entry->profile);
        return ERROR(ERR_MEMORY, "Failed to allocate diverged entry");
    }

    /* Add to diverged index for O(1) lookup */
    error_t *err = hashmap_set(ws->diverged_index, entry->filesystem_path, entry);
    if (err) {
        free(entry->filesystem_path);
        free(entry->storage_path);
        free(entry->profile);
        return error_wrap(err, "Failed to index diverged entry");
    }

    ws->diverged_count++;

    /* Update divergence count cache */
    if (type < 9) {  /* Bounds check */
        ws->divergence_counts[type]++;
    }

    return NULL;
}

/**
 * Build manifest index for O(1) lookups
 */
static error_t *workspace_build_manifest_index(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->manifest);

    for (size_t i = 0; i < ws->manifest->count; i++) {
        file_entry_t *entry = &ws->manifest->entries[i];
        error_t *err = hashmap_set(ws->manifest_index,
                                   entry->filesystem_path,
                                   entry);
        if (err) {
            return error_wrap(err, "Failed to index manifest entry");
        }
    }

    return NULL;
}

/**
 * Analyze single file for divergence
 */
static error_t *analyze_file_divergence(
    workspace_t *ws,
    const file_entry_t *manifest_entry,
    const state_file_entry_t *state_entry
) {
    CHECK_NULL(ws);
    CHECK_NULL(manifest_entry);

    const char *fs_path = manifest_entry->filesystem_path;
    const char *storage_path = manifest_entry->storage_path;
    const char *profile = manifest_entry->source_profile->name;

    bool in_profile = true;  /* By definition - we're iterating manifest */
    bool in_state = (state_entry != NULL);
    bool on_filesystem = fs_lexists(fs_path);
    bool content_differs = false;
    divergence_type_t div_type = DIVERGENCE_CLEAN;

    /* Case 1: File not deployed (in profile, not in state) */
    if (!in_state) {
        div_type = DIVERGENCE_UNDEPLOYED;
    }
    /* Case 2: File deployed but missing from filesystem */
    else if (in_state && !on_filesystem) {
        div_type = DIVERGENCE_DELETED;
    }
    /* Case 3: File deployed and exists - check for modifications */
    else if (in_state && on_filesystem) {
        /* Get plaintext content (cached, automatic decryption) */
        const buffer_t *content = NULL;
        error_t *err = content_cache_get_from_tree_entry(
            ws->content_cache,
            manifest_entry->entry,
            manifest_entry->storage_path,
            manifest_entry->source_profile->name,
            ws_get_metadata(ws, manifest_entry->source_profile->name),
            &content
        );

        if (err) {
            return error_wrap(err, "Failed to get content for '%s'", fs_path);
        }

        /* Compare buffer to disk (pure function) */
        git_filemode_t mode = git_tree_entry_filemode(manifest_entry->entry);
        compare_result_t cmp_result;
        err = compare_buffer_to_disk(content, fs_path, mode, &cmp_result);

        if (err) {
            return error_wrap(err, "Failed to compare '%s'", fs_path);
        }

        /* Don't free content - cache owns it! */

        switch (cmp_result) {
            case CMP_EQUAL:
                /* Clean - no divergence */
                return NULL;

            case CMP_DIFFERENT:
                div_type = DIVERGENCE_MODIFIED;
                content_differs = true;
                break;

            case CMP_MODE_DIFF:
                div_type = DIVERGENCE_MODE_DIFF;
                content_differs = false;
                break;

            case CMP_TYPE_DIFF:
                div_type = DIVERGENCE_TYPE_DIFF;
                content_differs = true;
                break;

            case CMP_MISSING:
                /* Shouldn't happen - we checked on_filesystem above */
                div_type = DIVERGENCE_DELETED;
                break;
        }
    }

    /* Add to diverged list if not clean */
    if (div_type != DIVERGENCE_CLEAN) {
        return workspace_add_diverged(ws, fs_path, storage_path, profile,
                                     div_type, in_profile, in_state,
                                     on_filesystem, content_differs);
    }

    return NULL;
}

/**
 * Analyze state for orphaned entries
 *
 * An entry is orphaned if:
 * 1. Its profile is in our enabled profile list (in scope), AND
 * 2. The file no longer exists in that profile's branch
 *
 * State entries from profiles NOT in our enabled list are ignored (out of scope).
 */
static error_t *analyze_orphaned_state(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->profile_index);

    /* Get all files in state */
    size_t state_file_count = 0;
    state_file_entry_t *state_files = NULL;
    error_t *err = state_get_all_files(ws->state, &state_files, &state_file_count);
    if (err) {
        return err;
    }

    /* Check each state entry */
    for (size_t i = 0; i < state_file_count; i++) {
        const state_file_entry_t *state_entry = &state_files[i];
        const char *fs_path = state_entry->filesystem_path;
        const char *entry_profile = state_entry->profile;

        /* Skip if this state entry's profile is not in our enabled profile list */
        if (!hashmap_get(ws->profile_index, entry_profile)) {
            continue;  /* Out of scope - ignore */
        }

        /* Check if this file exists in manifest (profile state) */
        file_entry_t *manifest_entry = hashmap_get(ws->manifest_index, fs_path);

        if (!manifest_entry) {
            /* Orphaned: In state, profile is enabled, but not in profile branch */
            bool on_filesystem = fs_lexists(fs_path);

            error_t *err = workspace_add_diverged(
                ws,
                fs_path,
                state_entry->storage_path,
                state_entry->profile,
                DIVERGENCE_ORPHANED,
                false,     /* not in profile */
                true,      /* in state */
                on_filesystem,
                false      /* content_differs N/A */
            );

            if (err) {
                state_free_all_files(state_files, state_file_count);
                return err;
            }
        }
    }

    state_free_all_files(state_files, state_file_count);
    return NULL;
}

/**
 * Perform divergence analysis
 */
static error_t *workspace_analyze_divergence(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->manifest);
    CHECK_NULL(ws->state);

    error_t *err = NULL;

    /* Analyze each file in manifest */
    for (size_t i = 0; i < ws->manifest->count; i++) {
        const file_entry_t *manifest_entry = &ws->manifest->entries[i];

        /* Check if file is in deployment state */
        state_file_entry_t *state_entry = NULL;
        error_t *lookup_err = state_get_file(ws->state,
                                             manifest_entry->filesystem_path,
                                             &state_entry);

        if (lookup_err && lookup_err->code != ERR_NOT_FOUND) {
            /* Real error */
            state_free_entry(state_entry);
            return lookup_err;
        }

        /* Not found is OK - means not deployed */
        if (lookup_err) {
            error_free(lookup_err);
            state_entry = NULL;
        }

        /* Analyze this file */
        err = analyze_file_divergence(ws, manifest_entry, state_entry);
        state_free_entry(state_entry);  /* Free owned memory from SQLite */

        if (err) {
            return err;
        }
    }

    /* Analyze state for orphaned entries */
    err = analyze_orphaned_state(ws);
    if (err) {
        return err;
    }

    return NULL;
}

/**
 * Compute workspace status
 */
static workspace_status_t compute_workspace_status(const workspace_t *ws) {
    if (!ws) {
        return WORKSPACE_INVALID;
    }

    bool has_orphaned = false;
    bool has_warnings = false;

    for (size_t i = 0; i < ws->diverged_count; i++) {
        const workspace_file_t *file = &ws->diverged[i];

        switch (file->type) {
            case DIVERGENCE_ORPHANED:
                has_orphaned = true;
                break;

            case DIVERGENCE_UNDEPLOYED:
            case DIVERGENCE_MODIFIED:
            case DIVERGENCE_DELETED:
            case DIVERGENCE_MODE_DIFF:
            case DIVERGENCE_TYPE_DIFF:
            case DIVERGENCE_UNTRACKED:
            case DIVERGENCE_ENCRYPTION:
                has_warnings = true;
                break;

            case DIVERGENCE_CLEAN:
                /* Should not be in diverged list */
                break;
        }
    }

    if (has_orphaned) {
        return WORKSPACE_INVALID;
    } else if (has_warnings) {
        return WORKSPACE_DIRTY;
    } else {
        return WORKSPACE_CLEAN;
    }
}

/**
 * Recursively scan directory for untracked files
 */
static error_t *scan_directory_for_untracked(
    const char *dir_path,
    const char *storage_prefix,
    const char *profile,
    const hashmap_t *manifest_index,
    ignore_context_t *ignore_ctx,
    workspace_t *ws
) {
    CHECK_NULL(dir_path);
    CHECK_NULL(storage_prefix);
    CHECK_NULL(profile);
    CHECK_NULL(manifest_index);
    CHECK_NULL(ws);

    DIR *dir = opendir(dir_path);
    if (!dir) {
        /* Non-fatal: directory might have been deleted or permissions issue */
        return NULL;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Build full path */
        char *full_path = str_format("%s/%s", dir_path, entry->d_name);
        if (!full_path) {
            closedir(dir);
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }

        /* Check if path exists and get its type (single syscall, don't follow symlinks) */
        struct stat st;
        if (lstat(full_path, &st) != 0) {
            /* Path might have been deleted (race condition) */
            free(full_path);
            continue;
        }

        /* Check if ignored */
        bool is_dir = S_ISDIR(st.st_mode);
        if (ignore_ctx) {
            bool ignored = false;
            error_t *err = ignore_should_ignore(ignore_ctx, full_path, is_dir, &ignored);
            if (!err && ignored) {
                free(full_path);
                continue;
            }
            error_free(err);  /* Ignore errors in ignore checking */
        }

        if (is_dir) {
            /* Recurse into subdirectory */
            char *sub_storage_prefix = str_format("%s/%s", storage_prefix, entry->d_name);
            if (!sub_storage_prefix) {
                free(full_path);
                closedir(dir);
                return ERROR(ERR_MEMORY, "Failed to allocate storage prefix");
            }

            error_t *err = scan_directory_for_untracked(
                full_path,
                sub_storage_prefix,
                profile,
                manifest_index,
                ignore_ctx,
                ws
            );

            free(sub_storage_prefix);
            free(full_path);

            if (err) {
                closedir(dir);
                return err;
            }
        } else {
            /* Check if this file is already in manifest */
            file_entry_t *manifest_entry = hashmap_get(manifest_index, full_path);

            if (!manifest_entry) {
                /* This is an untracked file! */
                char *storage_path = str_format("%s/%s", storage_prefix, entry->d_name);
                if (!storage_path) {
                    free(full_path);
                    closedir(dir);
                    return ERROR(ERR_MEMORY, "Failed to allocate storage path");
                }

                error_t *err = workspace_add_diverged(
                    ws,
                    full_path,
                    storage_path,
                    profile,
                    DIVERGENCE_UNTRACKED,
                    false,  /* not in profile */
                    false,  /* not in state */
                    true,   /* on filesystem */
                    false   /* content_differs N/A */
                );

                free(storage_path);
                free(full_path);

                if (err) {
                    closedir(dir);
                    return err;
                }
            } else {
                free(full_path);
            }
        }
    }

    closedir(dir);
    return NULL;
}

/**
 * Analyze tracked directories for untracked files
 *
 * Only scans tracked directories for profiles in the enabled profile list.
 */
static error_t *analyze_untracked_files(
    workspace_t *ws,
    const dotta_config_t *config
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->profiles);

    error_t *err = NULL;

    if (ws->profiles->count == 0) {
        return NULL;  /* No profiles to analyze */
    }

    /* Scan tracked directories from each enabled profile's metadata */
    for (size_t p = 0; p < ws->profiles->count; p++) {
        const char *profile_name = ws->profiles->profiles[p].name;

        /* Load metadata for this profile */
        metadata_t *metadata = NULL;
        err = metadata_load_from_branch(ws->repo, profile_name, &metadata);
        if (err) {
            /* Non-fatal: profile may not have metadata yet */
            error_free(err);
            err = NULL;
            continue;
        }

        /* Get tracked directories from metadata */
        size_t dir_count = 0;
        const metadata_directory_entry_t *directories =
            metadata_get_all_tracked_directories(metadata, &dir_count);

        /* Scan each tracked directory */
        for (size_t i = 0; i < dir_count; i++) {
            const metadata_directory_entry_t *dir_entry = &directories[i];

            /* Check if directory still exists */
            if (!fs_exists(dir_entry->filesystem_path)) {
                continue;
            }

            /* Create profile-specific ignore context for this directory */
            ignore_context_t *ignore_ctx = NULL;
            err = ignore_context_create(
                ws->repo,
                config,
                profile_name,
                NULL,
                0,
                &ignore_ctx
            );

            if (err) {
                /* Non-fatal: continue without ignore filtering */
                fprintf(stderr, "warning: failed to load ignore patterns for '%s' in profile '%s': %s\n",
                        dir_entry->filesystem_path, profile_name, err->message);
                error_free(err);
                err = NULL;
                ignore_ctx = NULL;
            }

            /* Scan this directory for untracked files */
            err = scan_directory_for_untracked(
                dir_entry->filesystem_path,
                dir_entry->storage_prefix,
                profile_name,
                ws->manifest_index,
                ignore_ctx,
                ws
            );

            /* Free ignore context */
            ignore_context_free(ignore_ctx);

            if (err) {
                /* Non-fatal: continue with other directories */
                fprintf(stderr, "warning: failed to scan directory '%s' in profile '%s': %s\n",
                        dir_entry->filesystem_path, profile_name, err->message);
                error_free(err);
                err = NULL;
            }
        }

        metadata_free(metadata);
    }

    return NULL;
}

/**
 * Analyze encryption policy mismatches
 *
 * Detects files that should be encrypted (per auto-encrypt patterns)
 * but are stored as plaintext in the profile.
 *
 * Only checks if:
 * - Encryption is globally enabled
 * - Auto-encrypt patterns are configured
 *
 * This is a security-focused check: files matching sensitive patterns
 * (e.g., "*.key", ".ssh/id_*") should be encrypted.
 */
static error_t *analyze_encryption_policy_mismatch(
    workspace_t *ws,
    const dotta_config_t *config
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->manifest);

    /* Skip if encryption disabled globally */
    if (!config || !config->encryption_enabled) {
        return NULL;
    }

    /* Skip if no auto-encrypt patterns configured */
    if (!config->auto_encrypt_patterns || config->auto_encrypt_pattern_count == 0) {
        return NULL;
    }

    /* Check each file in manifest */
    for (size_t i = 0; i < ws->manifest->count; i++) {
        const file_entry_t *manifest_entry = &ws->manifest->entries[i];
        const char *storage_path = manifest_entry->storage_path;
        const char *profile_name = manifest_entry->source_profile->name;

        /* Check if file should be auto-encrypted */
        bool should_auto_encrypt = false;
        error_t *err = encryption_policy_matches_auto_patterns(
            config,
            storage_path,
            &should_auto_encrypt
        );
        if (err) {
            /* Non-fatal: pattern matching errors shouldn't block status */
            error_free(err);
            continue;
        }

        /* If file doesn't match patterns, no mismatch */
        if (!should_auto_encrypt) {
            continue;
        }

        /* Get metadata to check actual encryption state */
        const metadata_t *metadata = ws_get_metadata(ws, profile_name);
        bool is_encrypted = false;

        if (metadata) {
            const metadata_entry_t *meta_entry = NULL;
            error_t *lookup_err = metadata_get_entry(metadata, storage_path, &meta_entry);

            if (lookup_err == NULL && meta_entry) {
                is_encrypted = meta_entry->encrypted;
            }

            /* Clean up lookup error if any */
            if (lookup_err) {
                error_free(lookup_err);
            }
        }

        /* Policy mismatch: should be encrypted but isn't */
        if (should_auto_encrypt && !is_encrypted) {
            err = workspace_add_diverged(
                ws,
                manifest_entry->filesystem_path,
                storage_path,
                profile_name,
                DIVERGENCE_ENCRYPTION,
                true,  /* in profile */
                false, /* in_state (not relevant for policy mismatch) */
                false, /* on_filesystem (not relevant for policy mismatch) */
                false  /* content_differs (not relevant for policy mismatch) */
            );

            if (err) {
                return err;
            }
        }
    }

    return NULL;
}

/**
 * Load workspace from repository
 */
error_t *workspace_load(
    git_repository *repo,
    profile_list_t *profiles,
    const dotta_config_t *config,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    workspace_t *ws = NULL;
    error_t *err = NULL;

    /* Create empty workspace */
    err = workspace_create_empty(repo, profiles, &ws);
    if (err) {
        return err;
    }

    /* Initialize encryption infrastructure */
    /* Note: keymanager can be NULL if encryption is not configured - this is valid */
    ws->keymanager = keymanager_get_global(config);

    ws->content_cache = content_cache_create(ws->repo, ws->keymanager);
    if (!ws->content_cache) {
        workspace_free(ws);
        return ERROR(ERR_MEMORY, "Failed to create content cache");
    }

    ws->metadata_cache = hashmap_create(16);
    if (!ws->metadata_cache) {
        workspace_free(ws);
        return ERROR(ERR_MEMORY, "Failed to create metadata cache");
    }

    /* Pre-load metadata for all profiles (performance optimization) */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile_name = profiles->profiles[i].name;
        metadata_t *metadata = NULL;

        error_t *meta_err = metadata_load_from_branch(repo, profile_name, &metadata);
        if (meta_err) {
            /* Graceful fallback: create empty metadata if loading fails.
             * This ensures content layer always has metadata for validation.
             * Empty metadata will cause "file not in metadata" errors during
             * divergence analysis, which is the correct behavior for profiles
             * without metadata (new profiles or corrupted metadata files). */
            error_free(meta_err);
            error_t *create_err = metadata_create_empty(&metadata);
            if (create_err) {
                workspace_free(ws);
                return error_wrap(create_err,
                    "Failed to create metadata for profile '%s'", profile_name);
            }
        }

        error_t *set_err = hashmap_set(ws->metadata_cache, profile_name, metadata);
        if (set_err) {
            metadata_free(metadata);
            workspace_free(ws);
            return error_wrap(set_err, "Failed to cache metadata for profile '%s'", profile_name);
        }
    }

    /* Load profile state (manifest) */
    err = profile_build_manifest(repo, profiles, &ws->manifest);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to build manifest");
    }

    /* Build manifest index for O(1) lookups */
    err = workspace_build_manifest_index(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to build manifest index");
    }

    /* Load deployment state */
    err = state_load(repo, &ws->state);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to load state");
    }

    /* Perform divergence analysis */
    err = workspace_analyze_divergence(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to analyze divergence");
    }

    /* Analyze tracked directories for untracked files */
    err = analyze_untracked_files(ws, config);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to analyze untracked files");
    }

    /* Analyze encryption policy mismatches */
    err = analyze_encryption_policy_mismatch(ws, config);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to analyze encryption policy");
    }

    /* Compute status */
    ws->status = compute_workspace_status(ws);
    ws->status_computed = true;

    *out = ws;
    return NULL;
}

/**
 * Get workspace status
 */
workspace_status_t workspace_get_status(const workspace_t *ws) {
    if (!ws) {
        return WORKSPACE_INVALID;
    }
    return ws->status;
}

/**
 * Get diverged files by category
 */
const workspace_file_t **workspace_get_diverged(
    const workspace_t *ws,
    divergence_type_t type,
    size_t *count
) {
    if (!ws || !count) {
        if (count) *count = 0;
        return NULL;
    }

    /* For CLEAN, return nothing */
    if (type == DIVERGENCE_CLEAN) {
        *count = 0;
        return NULL;
    }

    /* First pass: count matching entries */
    size_t match_count = 0;
    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (ws->diverged[i].type == type) {
            match_count++;
        }
    }

    /* If none found, return NULL */
    if (match_count == 0) {
        *count = 0;
        return NULL;
    }

    /* Allocate array of pointers */
    const workspace_file_t **result = malloc(match_count * sizeof(workspace_file_t *));
    if (!result) {
        *count = 0;
        return NULL;
    }

    /* Second pass: populate pointer array */
    size_t idx = 0;
    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (ws->diverged[i].type == type) {
            result[idx++] = &ws->diverged[i];
        }
    }

    *count = match_count;
    return result;
}

/**
 * Get all diverged files
 */
const workspace_file_t *workspace_get_all_diverged(
    const workspace_t *ws,
    size_t *count
) {
    if (!ws || !count) {
        if (count) *count = 0;
        return NULL;
    }

    *count = ws->diverged_count;
    return ws->diverged;
}

/**
 * Check if file has divergence
 */
bool workspace_file_diverged(
    const workspace_t *ws,
    const char *filesystem_path,
    divergence_type_t *type
) {
    if (!ws || !filesystem_path) {
        return false;
    }

    /* O(1) lookup via hashmap index */
    workspace_file_t *entry = hashmap_get(ws->diverged_index, filesystem_path);

    if (entry) {
        if (type) {
            *type = entry->type;
        }
        return true;
    }

    if (type) {
        *type = DIVERGENCE_CLEAN;
    }
    return false;
}

/**
 * Validate workspace for operation
 */
error_t *workspace_validate(
    const workspace_t *ws,
    const char *operation,
    bool allow_dirty
) {
    CHECK_NULL(ws);
    CHECK_NULL(operation);

    workspace_status_t status = workspace_get_status(ws);

    switch (status) {
        case WORKSPACE_CLEAN:
            return NULL;  /* All good */

        case WORKSPACE_DIRTY:
            if (allow_dirty) {
                return NULL;  /* Warnings only */
            }
            return ERROR(ERR_VALIDATION,
                        "Cannot %s: workspace has divergence (use --force or resolve first)",
                        operation);

        case WORKSPACE_INVALID:
            return ERROR(ERR_VALIDATION,
                        "Cannot %s: workspace has orphaned state entries (run 'dotta profile validate --fix')",
                        operation);
    }

    return ERROR(ERR_INTERNAL, "Unknown workspace status");
}

/**
 * Get divergence count by type
 *
 * Returns cached count computed during workspace load.
 * This is O(1) instead of O(n), significantly improving performance
 * when multiple counts are queried (e.g., in cmd_sync).
 */
size_t workspace_count_divergence(
    const workspace_t *ws,
    divergence_type_t type
) {
    if (!ws) {
        return 0;
    }

    /* Return cached count for O(1) access */
    if (type < 9) {
        return ws->divergence_counts[type];
    }

    /* Fallback for invalid type (should never happen) */
    return 0;
}

/**
 * Check if workspace is clean
 */
bool workspace_is_clean(const workspace_t *ws) {
    return workspace_get_status(ws) == WORKSPACE_CLEAN;
}

/**
 * Free workspace
 */
void workspace_free(workspace_t *ws) {
    if (!ws) {
        return;
    }

    /* Free diverged entries */
    for (size_t i = 0; i < ws->diverged_count; i++) {
        free(ws->diverged[i].filesystem_path);
        free(ws->diverged[i].storage_path);
        free(ws->diverged[i].profile);
    }
    free(ws->diverged);

    /* Free indices (values are borrowed, so pass NULL for value free function) */
    hashmap_free(ws->manifest_index, NULL);
    hashmap_free(ws->profile_index, NULL);
    hashmap_free(ws->diverged_index, NULL);

    /* Free encryption infrastructure */
    if (ws->metadata_cache) {
        hashmap_free(ws->metadata_cache, (void (*)(void *))metadata_free);
    }
    content_cache_free(ws->content_cache);
    /* Don't free keymanager - it's global */

    /* Free owned state */
    manifest_free(ws->manifest);
    state_free(ws->state);

    free(ws);
}
