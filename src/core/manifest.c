/**
 * manifest.c - Manifest transparent layer implementation
 *
 * The manifest module is the single authority for all manifest table modifications.
 * It maintains the manifest as a Virtual Working Directory (VWD) - a staging area
 * between Git branches and the filesystem.
 *
 * Key patterns:
 *   - Precedence Oracle: Reuses profile_build_manifest() for correctness
 *   - Transaction Management: Caller manages transactions, we operate within them
 *   - Content Hashing: Uses content_hash_*() which handles decryption transparently
 *   - Metadata Integration: Uses metadata_load_from_profiles() for merged view
 */

#include "manifest.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "crypto/keymanager.h"
#include "infra/content.h"
#include "infra/path.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/string.h"

/* ========================================================================
 * Internal Utilities
 * ======================================================================== */

/**
 * Get current HEAD oid for branch
 */
static error_t *get_branch_head_oid(
    git_repository *repo,
    const char *branch_name,
    git_oid *out_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out_oid);

    error_t *err = NULL;
    git_reference *ref = NULL;

    /* Construct reference name */
    char refname[256];
    int ret = snprintf(refname, sizeof(refname), "refs/heads/%s", branch_name);
    if (ret < 0 || (size_t)ret >= sizeof(refname)) {
        return ERROR(ERR_INTERNAL, "Branch name too long: %s", branch_name);
    }

    /* Lookup reference */
    err = gitops_lookup_reference(repo, refname, &ref);
    if (err) {
        return error_wrap(err, "Failed to lookup branch '%s'", branch_name);
    }

    /* Get target oid */
    const git_oid *target = git_reference_target(ref);
    if (!target) {
        git_reference_free(ref);
        return ERROR(ERR_GIT, "Branch '%s' has no target", branch_name);
    }

    git_oid_cpy(out_oid, target);
    git_reference_free(ref);

    return NULL;
}

/**
 * Convert mode_t to string
 */
static char *mode_to_string(mode_t mode) {
    char *mode_str = malloc(8);
    if (!mode_str) {
        return NULL;
    }

    snprintf(mode_str, 8, "%04o", mode & 07777);
    return mode_str;
}

/**
 * Find file in manifest by storage_path
 */
static file_entry_t *find_file_in_manifest(
    const manifest_t *manifest,
    const char *storage_path
) {
    if (!manifest || !storage_path) {
        return NULL;
    }

    for (size_t i = 0; i < manifest->count; i++) {
        file_entry_t *entry = &manifest->entries[i];
        if (entry->storage_path && strcmp(entry->storage_path, storage_path) == 0) {
            return entry;
        }
    }

    return NULL;
}

/**
 * Build manifest from profiles and optionally find specific file
 *
 * This is the "precedence oracle" pattern - we use profile_build_manifest()
 * to determine who should own what files, then use that authoritative answer.
 *
 * @param repo Git repository
 * @param profile_names Profile names to build from
 * @param storage_path Optional storage path to find (NULL to skip)
 * @param out_entry Optional output for found entry (borrowed, don't free)
 * @param out_manifest Output manifest (caller must free)
 * @return Error or NULL on success
 */
static error_t *build_manifest_and_find(
    git_repository *repo,
    const string_array_t *profile_names,
    const char *storage_path,
    file_entry_t **out_entry,
    manifest_t **out_manifest
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_names);
    CHECK_NULL(out_manifest);

    error_t *err = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *manifest = NULL;

    /* Load profiles */
    err = profile_list_load(repo, profile_names->items, profile_names->count,
                            false /* strict */, &profiles);
    if (err) {
        return error_wrap(err, "Failed to load profiles for manifest build");
    }

    /* Build manifest (applies precedence rules) */
    err = profile_build_manifest(repo, profiles, &manifest);
    if (err) {
        profile_list_free(profiles);
        return error_wrap(err, "Failed to build manifest from profiles");
    }

    profile_list_free(profiles);

    /* Find entry if requested */
    if (storage_path && out_entry) {
        *out_entry = find_file_in_manifest(manifest, storage_path);
    }

    *out_manifest = manifest;
    return NULL;
}

/**
 * Compute content hash from tree entry
 *
 * Wrapper around content_hash_from_tree_entry with proper error handling.
 * Content hash is Blake2b of **plaintext** content (decrypted if needed).
 */
static error_t *compute_content_hash_from_entry(
    git_repository *repo,
    const git_tree_entry *entry,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    char **out_hash
) {
    CHECK_NULL(repo);
    CHECK_NULL(entry);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_hash);

    error_t *err = content_hash_from_tree_entry(
        repo, entry, storage_path, profile_name, metadata, km, out_hash
    );

    if (err) {
        return error_wrap(err, "Failed to compute content hash for %s", storage_path);
    }

    return NULL;
}

/* ========================================================================
 * Core Translation: file_entry_t → state_file_entry_t
 * ======================================================================== */

/**
 * Sync single entry from in-memory manifest to state
 *
 * This is the central translation function that converts from the in-memory
 * manifest representation (file_entry_t from profile_build_manifest) to the
 * persistent state representation (state_file_entry_t in SQLite).
 *
 * Responsibilities:
 *   - Compute content hash (with transparent decryption)
 *   - Extract metadata (mode, owner, group, encrypted flag)
 *   - Build state entry structure
 *   - Insert or update in state database
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param manifest_entry Entry from in-memory manifest (borrowed)
 * @param git_oid Git commit reference (40-char hex)
 * @param metadata Merged metadata from all profiles
 * @param status Initial status for entry
 * @param km Keymanager for content hashing
 * @return Error or NULL on success
 */
static error_t *sync_entry_to_state(
    git_repository *repo,
    state_t *state,
    const file_entry_t *manifest_entry,
    const char *git_oid,
    const metadata_t *metadata,
    manifest_status_t status,
    keymanager_t *km
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(manifest_entry);
    CHECK_NULL(git_oid);
    CHECK_NULL(manifest_entry->source_profile);

    error_t *err = NULL;
    char *content_hash = NULL;
    metadata_item_t *meta_item = NULL;
    char *mode_str = NULL;
    state_file_entry_t *existing = NULL;

    /* 1. Compute content hash (plaintext, with decryption if needed) */
    err = compute_content_hash_from_entry(
        repo,
        manifest_entry->entry,
        manifest_entry->storage_path,
        manifest_entry->source_profile->name,
        metadata,
        km,
        &content_hash
    );
    if (err) {
        goto cleanup;
    }

    /* 2. Get metadata item (may not exist for old profiles) */
    if (metadata) {
        err = metadata_get_item(
            metadata,
            manifest_entry->storage_path,
            (const metadata_item_t **)&meta_item
        );
        /* Allow NOT_FOUND (old profiles without metadata) */
        if (err && err->code != ERR_NOT_FOUND) {
            goto cleanup;
        }
        if (err) {
            error_free(err);
            err = NULL;
        }
    }

    /* 3. Build mode string */
    if (meta_item) {
        mode_str = mode_to_string(meta_item->mode);
    } else {
        /* Default: 0644 for files */
        mode_str = strdup("0644");
    }

    if (!mode_str) {
        err = ERROR(ERR_MEMORY, "Failed to allocate mode string");
        goto cleanup;
    }

    /* 4. Build state entry */
    state_file_entry_t state_entry = {
        .storage_path = manifest_entry->storage_path,
        .filesystem_path = manifest_entry->filesystem_path,
        .profile = manifest_entry->source_profile->name,
        .type = STATE_FILE_REGULAR,
        .status = status,
        .git_oid = (char *)git_oid,
        .content_hash = content_hash,
        .mode = mode_str,
        .owner = meta_item ? meta_item->owner : NULL,
        .group = meta_item ? meta_item->group : NULL,
        .encrypted = meta_item ? meta_item->file.encrypted : false,
        .staged_at = time(NULL),
        .deployed_at = 0  /* Not deployed yet (or preserved by update) */
    };

    /* 5. Check if entry exists (to preserve deployed_at) */
    err = state_get_file(state, manifest_entry->filesystem_path, &existing);
    if (err == NULL && existing != NULL) {
        /* Preserve deployed_at for existing entries */
        state_entry.deployed_at = existing->deployed_at;

        /* Update existing entry */
        err = state_update_entry(state, &state_entry);
        if (err) {
            err = error_wrap(err, "Failed to update manifest entry for %s",
                           manifest_entry->storage_path);
        }
    } else {
        /* Insert new entry */
        if (err && err->code == ERR_NOT_FOUND) {
            error_free(err);
            err = NULL;
        }

        err = state_add_file(state, &state_entry);
        if (err) {
            err = error_wrap(err, "Failed to add manifest entry for %s",
                           manifest_entry->storage_path);
        }
    }

cleanup:
    if (existing) {
        state_free_entry(existing);
    }
    free(mode_str);
    free(content_hash);
    return err;
}

/* ========================================================================
 * Public API: Manifest Synchronization Operations
 * ======================================================================== */

/**
 * Sync entire profile to manifest (bulk population)
 *
 * Implementation follows the precedence oracle pattern:
 *   1. Build manifest from all enabled profiles (precedence resolution)
 *   2. For each file owned by this profile (highest precedence):
 *      - Compute content hash
 *      - Extract metadata
 *      - Sync to state
 */
error_t *manifest_sync_profile(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *enabled_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profile_name);
    CHECK_NULL(enabled_profiles);

    error_t *err = NULL;
    manifest_t *manifest = NULL;
    metadata_t *metadata = NULL;
    keymanager_t *km = NULL;
    dotta_config_t *config = NULL;
    git_oid head_oid;
    char head_oid_str[GIT_OID_HEXSZ + 1];

    /* 1. Get HEAD oid for profile */
    err = get_branch_head_oid(repo, profile_name, &head_oid);
    if (err) {
        return error_wrap(err, "Failed to get HEAD for profile '%s'", profile_name);
    }
    git_oid_tostr(head_oid_str, sizeof(head_oid_str), &head_oid);

    /* 2. Build manifest from all enabled profiles (precedence oracle) */
    err = build_manifest_and_find(repo, enabled_profiles, NULL, NULL, &manifest);
    if (err) {
        return error_wrap(err, "Failed to build manifest for profile sync");
    }

    /* 3. Load merged metadata from all profiles */
    err = metadata_load_from_profiles(repo, enabled_profiles, &metadata);
    if (err) {
        /* Metadata may not exist for old profiles - continue with NULL */
        if (err->code != ERR_NOT_FOUND) {
            goto cleanup;
        }
        error_free(err);
        err = NULL;
    }

    /* 4. Create keymanager for content hashing */
    err = config_load(NULL, &config);
    if (err) {
        goto cleanup;
    }

    err = keymanager_create(config, &km);
    if (err) {
        goto cleanup;
    }

    /* 6. Sync entries owned by this profile (highest precedence) */
    for (size_t i = 0; i < manifest->count; i++) {
        file_entry_t *entry = &manifest->entries[i];

        /* Only process files owned by this profile */
        if (strcmp(entry->source_profile->name, profile_name) != 0) {
            continue;
        }

        /* Sync to state with PENDING_DEPLOYMENT status */
        err = sync_entry_to_state(
            repo, state, entry, head_oid_str, metadata,
            MANIFEST_STATUS_PENDING_DEPLOYMENT, km
        );
        if (err) {
            goto cleanup;
        }
    }

cleanup:
    if (km) {
        keymanager_free(km);
    }
    if (config) {
        config_free(config);
    }
    if (metadata) {
        metadata_free(metadata);
    }
    if (manifest) {
        manifest_free(manifest);
    }

    return err;
}

/**
 * Remove profile from manifest (bulk cleanup)
 *
 * Implementation handles fallback:
 *   1. Get all entries owned by disabled profile
 *   2. Build manifest from remaining profiles (fallback check)
 *   3. For each entry:
 *      - If found in fallback: update source + mark PENDING_DEPLOYMENT
 *      - If not found: mark PENDING_REMOVAL
 */
error_t *manifest_unsync_profile(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *remaining_enabled
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profile_name);
    CHECK_NULL(remaining_enabled);

    error_t *err = NULL;
    state_file_entry_t *entries = NULL;
    size_t count = 0;
    manifest_t *fallback_manifest = NULL;

    /* 1. Get all entries from disabled profile */
    err = state_get_entries_by_profile(state, profile_name, &entries, &count);
    if (err) {
        return error_wrap(err, "Failed to get entries for profile '%s'", profile_name);
    }

    if (count == 0) {
        /* No entries, nothing to do */
        return NULL;
    }

    /* 2. Build manifest from remaining profiles (fallback check) */
    if (remaining_enabled->count > 0) {
        err = build_manifest_and_find(repo, remaining_enabled, NULL, NULL,
                                      &fallback_manifest);
        if (err) {
            state_free_all_files(entries, count);
            return error_wrap(err, "Failed to build fallback manifest");
        }
    }

    /* 3. Process each entry */
    for (size_t i = 0; i < count; i++) {
        state_file_entry_t *entry = &entries[i];

        /* Check for fallback in remaining profiles */
        file_entry_t *fallback = NULL;
        if (fallback_manifest) {
            fallback = find_file_in_manifest(fallback_manifest, entry->storage_path);
        }

        if (fallback) {
            /* File exists in lower-precedence profile - update to fallback */
            git_oid fallback_oid;
            char fallback_oid_str[GIT_OID_HEXSZ + 1];

            err = get_branch_head_oid(repo, fallback->source_profile->name,
                                      &fallback_oid);
            if (err) {
                goto cleanup;
            }
            git_oid_tostr(fallback_oid_str, sizeof(fallback_oid_str), &fallback_oid);

            /* Update entry to use fallback profile */
            entry->profile = fallback->source_profile->name;
            entry->git_oid = fallback_oid_str;
            entry->status = MANIFEST_STATUS_PENDING_DEPLOYMENT;
            entry->staged_at = time(NULL);

            err = state_update_entry(state, entry);
            if (err) {
                err = error_wrap(err, "Failed to update entry to fallback for %s",
                               entry->storage_path);
                goto cleanup;
            }
        } else {
            /* No fallback - mark for removal */
            err = state_update_entry_status(state, entry->filesystem_path,
                                            MANIFEST_STATUS_PENDING_REMOVAL);
            if (err) {
                err = error_wrap(err, "Failed to mark entry for removal: %s",
                               entry->storage_path);
                goto cleanup;
            }
        }
    }

cleanup:
    if (fallback_manifest) {
        manifest_free(fallback_manifest);
    }
    state_free_all_files(entries, count);
    return err;
}

/**
 * Sync single file to manifest
 *
 * Implementation uses precedence oracle:
 *   1. Build manifest to check if this profile should own the file
 *   2. If yes: compute hash, get metadata, sync to state
 *   3. If no: skip (lower precedence)
 */
error_t *manifest_sync_file(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const char *storage_path,
    const char *filesystem_path,
    const char *git_oid,
    const string_array_t *enabled_profiles,
    manifest_status_t initial_status
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profile_name);
    CHECK_NULL(storage_path);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(git_oid);
    CHECK_NULL(enabled_profiles);

    error_t *err = NULL;
    manifest_t *manifest = NULL;
    file_entry_t *manifest_entry = NULL;
    metadata_t *metadata = NULL;
    keymanager_t *km = NULL;
    dotta_config_t *config = NULL;

    /* 1. Build manifest and find file (precedence check) */
    err = build_manifest_and_find(repo, enabled_profiles, storage_path,
                                  &manifest_entry, &manifest);
    if (err) {
        return error_wrap(err, "Failed to build manifest for file sync");
    }

    /* 2. Check precedence */
    if (manifest_entry) {
        /* File exists in manifest - check if this profile owns it */
        if (strcmp(manifest_entry->source_profile->name, profile_name) != 0) {
            /* Different profile owns it (higher precedence) - skip */
            goto cleanup;
        }
    } else {
        /* File not in manifest - shouldn't happen if profile is enabled */
        /* This can occur if file was just added and manifest not yet built */
        /* We'll handle by loading the profile and getting the entry directly */
        profile_t *profile = NULL;
        git_tree_entry *entry = NULL;

        err = profile_load(repo, profile_name, &profile);
        if (err) {
            goto cleanup;
        }

        err = profile_load_tree(repo, profile);
        if (err) {
            profile_free(profile);
            goto cleanup;
        }

        int ret = git_tree_entry_bypath(&entry, profile->tree, storage_path);
        if (ret != 0) {
            profile_free(profile);
            err = ERROR(ERR_GIT, "File not found in profile tree: %s", storage_path);
            goto cleanup;
        }

        /* Create temporary manifest entry */
        file_entry_t temp_entry = {
            .storage_path = (char *)storage_path,
            .filesystem_path = (char *)filesystem_path,
            .entry = entry,
            .source_profile = profile,
            .all_profiles = NULL
        };

        /* Load metadata and sync */
        err = metadata_load_from_profiles(repo, enabled_profiles, &metadata);
        if (err && err->code != ERR_NOT_FOUND) {
            git_tree_entry_free(entry);
            profile_free(profile);
            goto cleanup;
        }
        if (err) {
            error_free(err);
            err = NULL;
        }

        err = config_load(NULL, &config);
        if (err) {
            git_tree_entry_free(entry);
            profile_free(profile);
            goto cleanup;
        }

        err = keymanager_create(config, &km);
        if (err) {
            git_tree_entry_free(entry);
            profile_free(profile);
            goto cleanup;
        }

        err = sync_entry_to_state(repo, state, &temp_entry, git_oid, metadata,
                                  initial_status, km);

        git_tree_entry_free(entry);
        profile_free(profile);
        goto cleanup;
    }

    /* 3. Load metadata and keymanager */
    err = metadata_load_from_profiles(repo, enabled_profiles, &metadata);
    if (err && err->code != ERR_NOT_FOUND) {
        goto cleanup;
    }
    if (err) {
        error_free(err);
        err = NULL;
    }

    err = config_load(NULL, &config);
    if (err) {
        goto cleanup;
    }

    err = keymanager_create(config, &km);
    if (err) {
        goto cleanup;
    }

    /* 4. Sync entry to state */
    err = sync_entry_to_state(repo, state, manifest_entry, git_oid, metadata,
                              initial_status, km);

cleanup:
    if (km) {
        keymanager_free(km);
    }
    if (config) {
        config_free(config);
    }
    if (metadata) {
        metadata_free(metadata);
    }
    if (manifest) {
        manifest_free(manifest);
    }

    return err;
}

/**
 * Remove file from manifest
 *
 * Similar to unsync_profile but for single file:
 *   1. Get entry from state
 *   2. Build manifest from enabled profiles (fallback check)
 *   3. Update to fallback OR mark PENDING_REMOVAL
 */
error_t *manifest_remove_file(
    git_repository *repo,
    state_t *state,
    const char *filesystem_path,
    const string_array_t *enabled_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(enabled_profiles);

    error_t *err = NULL;
    state_file_entry_t *existing = NULL;
    manifest_t *fallback_manifest = NULL;
    file_entry_t *fallback = NULL;

    /* 1. Get existing entry */
    err = state_get_file(state, filesystem_path, &existing);
    if (err) {
        return error_wrap(err, "File not in manifest: %s", filesystem_path);
    }

    /* 2. Build manifest from enabled profiles (fallback check) */
    if (enabled_profiles->count > 0) {
        err = build_manifest_and_find(repo, enabled_profiles,
                                      existing->storage_path, &fallback,
                                      &fallback_manifest);
        if (err) {
            state_free_entry(existing);
            return error_wrap(err, "Failed to build fallback manifest");
        }
    }

    /* 3. Check for fallback */
    if (fallback) {
        /* File exists in enabled profile - update to fallback */
        git_oid fallback_oid;
        char fallback_oid_str[GIT_OID_HEXSZ + 1];

        err = get_branch_head_oid(repo, fallback->source_profile->name,
                                  &fallback_oid);
        if (err) {
            goto cleanup;
        }
        git_oid_tostr(fallback_oid_str, sizeof(fallback_oid_str), &fallback_oid);

        /* Update to fallback profile */
        existing->profile = fallback->source_profile->name;
        existing->git_oid = fallback_oid_str;
        existing->status = MANIFEST_STATUS_PENDING_DEPLOYMENT;
        existing->staged_at = time(NULL);

        err = state_update_entry(state, existing);
        if (err) {
            err = error_wrap(err, "Failed to update entry to fallback");
        }
    } else {
        /* No fallback - mark for removal */
        err = state_update_entry_status(state, filesystem_path,
                                        MANIFEST_STATUS_PENDING_REMOVAL);
        if (err) {
            err = error_wrap(err, "Failed to mark entry for removal");
        }
    }

cleanup:
    if (fallback_manifest) {
        manifest_free(fallback_manifest);
    }
    if (existing) {
        state_free_entry(existing);
    }

    return err;
}

/**
 * Sync changes from git diff to manifest
 *
 * Implementation uses git diff API:
 *   1. Get old and new trees
 *   2. Diff trees to get added/modified/deleted files
 *   3. For each change: call appropriate manifest function
 */
error_t *manifest_sync_changes(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profile_name);
    CHECK_NULL(old_oid);
    CHECK_NULL(new_oid);
    CHECK_NULL(enabled_profiles);

    error_t *err = NULL;
    git_tree *old_tree = NULL;
    git_tree *new_tree = NULL;
    git_diff *diff = NULL;
    char new_oid_str[GIT_OID_HEXSZ + 1];

    /* Get new oid as string */
    git_oid_tostr(new_oid_str, sizeof(new_oid_str), new_oid);

    /* 1. Lookup trees */
    int ret = git_tree_lookup(&old_tree, repo, old_oid);
    if (ret != 0) {
        err = ERROR(ERR_GIT, "Failed to lookup old tree: %s",
                   git_error_last()->message);
        goto cleanup;
    }

    ret = git_tree_lookup(&new_tree, repo, new_oid);
    if (ret != 0) {
        err = ERROR(ERR_GIT, "Failed to lookup new tree: %s",
                   git_error_last()->message);
        goto cleanup;
    }

    /* 2. Diff trees */
    ret = git_diff_tree_to_tree(&diff, repo, old_tree, new_tree, NULL);
    if (ret != 0) {
        err = ERROR(ERR_GIT, "Failed to diff trees: %s",
                   git_error_last()->message);
        goto cleanup;
    }

    /* 3. Process each delta */
    size_t num_deltas = git_diff_num_deltas(diff);
    for (size_t i = 0; i < num_deltas; i++) {
        const git_diff_delta *delta = git_diff_get_delta(diff, i);
        if (!delta) {
            continue;
        }

        const char *storage_path = delta->new_file.path;
        if (delta->status == GIT_DELTA_DELETED) {
            storage_path = delta->old_file.path;
        }

        /* Resolve filesystem path */
        char *filesystem_path = NULL;
        error_t *path_err = path_from_storage(storage_path, &filesystem_path);
        if (path_err) {
            error_free(path_err);
            continue;  /* Skip files we can't resolve */
        }

        /* Handle based on change type */
        if (delta->status == GIT_DELTA_ADDED || delta->status == GIT_DELTA_MODIFIED) {
            /* Added or modified - sync file */
            err = manifest_sync_file(
                repo, state, profile_name, storage_path, filesystem_path,
                new_oid_str, enabled_profiles,
                MANIFEST_STATUS_PENDING_DEPLOYMENT
            );
        } else if (delta->status == GIT_DELTA_DELETED) {
            /* Deleted - remove file */
            err = manifest_remove_file(repo, state, filesystem_path,
                                       enabled_profiles);
        }

        free(filesystem_path);

        if (err) {
            /* Log error but continue with other files */
            error_free(err);
            err = NULL;
        }
    }

cleanup:
    if (diff) {
        git_diff_free(diff);
    }
    if (new_tree) {
        git_tree_free(new_tree);
    }
    if (old_tree) {
        git_tree_free(old_tree);
    }

    return err;
}

/**
 * Rebuild manifest from scratch
 *
 * Nuclear option for recovery:
 *   1. Clear all file entries
 *   2. Sync each enabled profile
 */
error_t *manifest_rebuild(
    git_repository *repo,
    state_t *state,
    const string_array_t *enabled_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(enabled_profiles);

    error_t *err = NULL;

    /* 1. Clear all file entries */
    err = state_clear_files(state);
    if (err) {
        return error_wrap(err, "Failed to clear manifest for rebuild");
    }

    /* 2. Sync each enabled profile */
    for (size_t i = 0; i < enabled_profiles->count; i++) {
        const char *profile_name = enabled_profiles->items[i];

        err = manifest_sync_profile(repo, state, profile_name, enabled_profiles);
        if (err) {
            return error_wrap(err, "Failed to sync profile '%s' during rebuild",
                            profile_name);
        }
    }

    return NULL;
}

/**
 * Update manifest after profile precedence change
 *
 * Implementation strategy:
 *   1. Build new manifest with precedence oracle
 *   2. Compare with current state to detect ownership changes
 *   3. Update only changed files (preserves DEPLOYED status for unchanged)
 *   4. Handle orphaned files (mark PENDING_REMOVAL)
 */
error_t *manifest_update_for_precedence_change(
    git_repository *repo,
    state_t *state,
    const string_array_t *new_profile_order
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(new_profile_order);

    error_t *err = NULL;
    manifest_t *new_manifest = NULL;
    state_file_entry_t *old_entries = NULL;
    size_t old_count = 0;
    metadata_t *metadata = NULL;
    keymanager_t *km = NULL;
    dotta_config_t *config = NULL;

    /* 1. Build new manifest with new precedence order (precedence oracle) */
    err = build_manifest_and_find(repo, new_profile_order, NULL, NULL, &new_manifest);
    if (err) {
        return error_wrap(err, "Failed to build manifest for precedence update");
    }

    /* 2. Get all current manifest entries */
    err = state_get_all_files(state, &old_entries, &old_count);
    if (err) {
        goto cleanup;
    }

    /* 3. Load metadata and keymanager (needed for content hash computation) */
    err = metadata_load_from_profiles(repo, new_profile_order, &metadata);
    if (err && err->code != ERR_NOT_FOUND) {
        goto cleanup;
    }
    if (err) {
        error_free(err);
        err = NULL;
    }

    err = config_load(NULL, &config);
    if (err) {
        goto cleanup;
    }

    err = keymanager_create(config, &km);
    if (err) {
        goto cleanup;
    }

    /* 4. Process each file in new manifest */
    for (size_t i = 0; i < new_manifest->count; i++) {
        file_entry_t *new_entry = &new_manifest->entries[i];

        /* Check if exists in old state */
        state_file_entry_t *old_entry = NULL;
        err = state_get_file(state, new_entry->filesystem_path, &old_entry);

        if (err && err->code == ERR_NOT_FOUND) {
            /* New file (rare in reorder, but handle it) */
            error_free(err);
            err = NULL;

            /* Add new entry with PENDING_DEPLOYMENT */
            git_oid oid;
            char oid_str[GIT_OID_HEXSZ + 1];
            err = get_branch_head_oid(repo, new_entry->source_profile->name, &oid);
            if (err) {
                goto cleanup;
            }
            git_oid_tostr(oid_str, sizeof(oid_str), &oid);

            err = sync_entry_to_state(repo, state, new_entry, oid_str, metadata,
                                      MANIFEST_STATUS_PENDING_DEPLOYMENT, km);
            if (err) {
                goto cleanup;
            }
        } else if (err) {
            /* Real error */
            goto cleanup;
        } else {
            /* Existing entry - check if owner changed */
            bool owner_changed = strcmp(old_entry->profile, new_entry->source_profile->name) != 0;

            if (owner_changed) {
                /* Owner changed - update entry to new owner */
                git_oid oid;
                char oid_str[GIT_OID_HEXSZ + 1];
                err = get_branch_head_oid(repo, new_entry->source_profile->name, &oid);
                if (err) {
                    state_free_entry(old_entry);
                    goto cleanup;
                }
                git_oid_tostr(oid_str, sizeof(oid_str), &oid);

                /* Sync with new owner (status = PENDING_DEPLOYMENT) */
                err = sync_entry_to_state(repo, state, new_entry, oid_str, metadata,
                                          MANIFEST_STATUS_PENDING_DEPLOYMENT, km);
                if (err) {
                    state_free_entry(old_entry);
                    goto cleanup;
                }
            }
            /* else: owner unchanged, preserve existing entry status */

            state_free_entry(old_entry);
        }
    }

    /* 5. Check for files in old manifest but not in new (mark for removal) */
    for (size_t i = 0; i < old_count; i++) {
        state_file_entry_t *old_entry = &old_entries[i];

        /* Check if still exists in new manifest */
        file_entry_t *new_entry = find_file_in_manifest(new_manifest, old_entry->storage_path);

        if (new_entry == NULL) {
            /* File no longer in any profile - mark for removal */
            err = state_update_entry_status(state, old_entry->filesystem_path,
                                            MANIFEST_STATUS_PENDING_REMOVAL);
            if (err) {
                goto cleanup;
            }
        }
    }

cleanup:
    if (km) {
        keymanager_free(km);
    }
    if (config) {
        config_free(config);
    }
    if (metadata) {
        metadata_free(metadata);
    }
    state_free_all_files(old_entries, old_count);
    if (new_manifest) {
        manifest_free(new_manifest);
    }

    return err;
}
