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
#include "infra/content.h"
#include "infra/path.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/string.h"

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
 * Build manifest from profiles
 *
 * This is the "precedence oracle" pattern - we use profile_build_manifest()
 * to determine who should own what files, then use that authoritative answer.
 *
 * IMPORTANT: Manifest entries reference profile structures (source_profile field).
 * The profile_list must remain alive while the manifest is in use, otherwise
 * accessing entry->source_profile->name results in use-after-free.
 *
 * @param repo Git repository (must not be NULL)
 * @param profile_names Profile names to build from (must not be NULL)
 * @param out_manifest Output manifest (caller must free with manifest_free)
 * @param out_profiles Output profile list (caller must free with profile_list_free, must not be NULL)
 * @return Error or NULL on success
 */
static error_t *build_manifest(
    git_repository *repo,
    const string_array_t *profile_names,
    manifest_t **out_manifest,
    profile_list_t **out_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_names);
    CHECK_NULL(out_manifest);
    CHECK_NULL(out_profiles);

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

    /* DO NOT free profiles here - caller must keep them alive while using manifest */

    *out_manifest = manifest;
    *out_profiles = profiles;
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
    content_cache_t *cache,
    char **out_hash
) {
    CHECK_NULL(repo);
    CHECK_NULL(entry);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_hash);

    error_t *err = content_hash_from_tree_entry(
        repo, entry, storage_path, profile_name, metadata, km, cache, out_hash
    );

    if (err) {
        return error_wrap(err, "Failed to compute content hash for %s", storage_path);
    }

    return NULL;
}

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
 * @param cache Content cache (can be NULL)
 * @return Error or NULL on success
 */
static error_t *sync_entry_to_state(
    git_repository *repo,
    state_t *state,
    const file_entry_t *manifest_entry,
    const char *git_oid,
    const metadata_t *metadata,
    manifest_status_t status,
    keymanager_t *km,
    content_cache_t *cache
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
        cache,
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
error_t *manifest_enable_profile(
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
    profile_list_t *profiles = NULL;
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
    err = build_manifest(repo, enabled_profiles, &manifest, &profiles);
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
            MANIFEST_STATUS_PENDING_DEPLOYMENT, km, NULL
        );
        if (err) {
            goto cleanup;
        }
    }

cleanup:
    if (profiles) {
        profile_list_free(profiles);
    }
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
error_t *manifest_disable_profile(
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
    profile_list_t *fallback_profiles = NULL;

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
        err = build_manifest(repo, remaining_enabled,
                            &fallback_manifest, &fallback_profiles);
        if (err) {
            state_free_all_files(entries, count);
            return error_wrap(err, "Failed to build fallback manifest");
        }
    }

    /* 3. Process each entry */
    for (size_t i = 0; i < count; i++) {
        state_file_entry_t *entry = &entries[i];

        /* Check for fallback in remaining profiles using O(1) index lookup */
        file_entry_t *fallback = NULL;
        if (fallback_manifest && fallback_manifest->index) {
            void *idx_ptr = hashmap_get(fallback_manifest->index, entry->filesystem_path);
            if (idx_ptr) {
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
                fallback = &fallback_manifest->entries[idx];
            }
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

            /* Update entry to use fallback profile
             * MEMORY SAFETY: Must use str_replace_owned() to properly free old
             * strings and allocate independent copies. Direct assignment would cause:
             * 1. Memory leak (old values not freed)
             * 2. Use-after-free (aliasing memory freed with fallback_profiles)
             * 3. Double-free crash (cleanup path tries to free already-freed memory) */
            err = str_replace_owned(&entry->profile, fallback->source_profile->name);
            if (err) {
                goto cleanup;
            }

            err = str_replace_owned(&entry->git_oid, fallback_oid_str);
            if (err) {
                goto cleanup;
            }

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
    if (fallback_profiles) {
        profile_list_free(fallback_profiles);
    }
    if (fallback_manifest) {
        manifest_free(fallback_manifest);
    }
    state_free_all_files(entries, count);
    return err;
}

/**
 * Remove files from manifest (remove command)
 *
 * Called after remove command deletes files from a profile branch.
 * Handles fallback to lower-precedence profiles or marks for removal.
 *
 * Algorithm:
 *   1. Build fresh manifest from enabled profiles (precedence oracle)
 *   2. Build profile→oid map for git_oid field
 *   3. For each removed file:
 *      a. Resolve to filesystem path
 *      b. Lookup current manifest entry
 *      c. Check if removed profile owns it (precedence check)
 *      d. If yes:
 *         - Check fresh manifest for fallback
 *         - Fallback exists: Update to fallback profile, mark PENDING_DEPLOYMENT
 *         - No fallback: Mark PENDING_REMOVAL
 *      e. If no (different profile owns): Skip
 *
 * Preconditions:
 *   - state MUST have active transaction
 *   - Git commit MUST be completed (files removed from branch)
 *   - removed_storage_paths MUST be in storage format (home/.bashrc)
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - Files with fallback updated to fallback profile (PENDING_DEPLOYMENT)
 *   - Files without fallback marked PENDING_REMOVAL
 *   - Files not owned by removed_profile unchanged
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT: Git operation failed
 *   - ERR_STATE: Database operation failed
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(M + N) where M = total files in profiles, N = files removed
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param removed_profile Profile files were removed from (must not be NULL)
 * @param removed_storage_paths Storage paths of removed files (must not be NULL)
 * @param enabled_profiles All enabled profiles (must not be NULL)
 * @param out_removed Output: files marked PENDING_REMOVAL (can be NULL)
 * @param out_fallbacks Output: files updated to fallback (can be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_remove_files(
    git_repository *repo,
    state_t *state,
    const char *removed_profile,
    const string_array_t *removed_storage_paths,
    const string_array_t *enabled_profiles,
    size_t *out_removed,
    size_t *out_fallbacks
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(removed_profile);
    CHECK_NULL(removed_storage_paths);
    CHECK_NULL(enabled_profiles);

    error_t *err = NULL;
    manifest_t *fresh_manifest = NULL;
    profile_list_t *profiles = NULL;
    hashmap_t *profile_oids = NULL;
    size_t removed_count = 0;
    size_t fallback_count = 0;

    /* 1. Build fresh manifest from current Git state (post-removal) */
    err = build_manifest(repo, enabled_profiles, &fresh_manifest, &profiles);
    if (err) {
        return error_wrap(err, "Failed to build manifest for fallback detection");
    }

    /* 2. Build hashmap: profile_name → git_oid for fast lookups */
    profile_oids = hashmap_create(string_array_size(enabled_profiles));
    if (!profile_oids) {
        err = ERROR(ERR_MEMORY, "Failed to create profile OID map");
        goto cleanup;
    }

    for (size_t i = 0; i < string_array_size(enabled_profiles); i++) {
        const char *profile = string_array_get(enabled_profiles, i);
        git_oid *oid = malloc(sizeof(git_oid));
        if (!oid) {
            err = ERROR(ERR_MEMORY, "Failed to allocate OID");
            goto cleanup;
        }

        err = get_branch_head_oid(repo, profile, oid);
        if (err) {
            free(oid);
            err = error_wrap(err, "Failed to get HEAD for profile '%s'", profile);
            goto cleanup;
        }

        err = hashmap_set(profile_oids, profile, oid);
        if (err) {
            free(oid);
            goto cleanup;
        }
    }

    /* 3. Process each removed file */
    for (size_t i = 0; i < string_array_size(removed_storage_paths); i++) {
        const char *storage_path = string_array_get(removed_storage_paths, i);

        /* Resolve to filesystem path */
        char *filesystem_path = NULL;
        err = path_from_storage(storage_path, &filesystem_path);
        if (err) {
            err = error_wrap(err, "Failed to resolve path: %s", storage_path);
            goto cleanup;
        }

        /* Lookup current manifest entry */
        state_file_entry_t *current_entry = NULL;
        error_t *get_err = state_get_file(state, filesystem_path, &current_entry);

        if (get_err || !current_entry) {
            /* Not in manifest (profile was disabled or file never deployed) */
            if (get_err) {
                error_free(get_err);
            }
            free(filesystem_path);
            continue;
        }

        /* Check ownership: does removed_profile own this file? */
        if (strcmp(current_entry->profile, removed_profile) != 0) {
            /* Different profile owns it, skip */
            state_free_entry(current_entry);
            free(filesystem_path);
            continue;
        }

        /* removed_profile owns it, need to update */

        /* Check for fallback in fresh manifest using O(1) index lookup */
        file_entry_t *fallback = NULL;
        if (fresh_manifest && fresh_manifest->index) {
            void *idx_ptr = hashmap_get(fresh_manifest->index, filesystem_path);
            if (idx_ptr) {
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
                fallback = &fresh_manifest->entries[idx];
            }
        }

        if (fallback) {
            /* Fallback found: update to use fallback profile */
            const char *fallback_profile = fallback->source_profile->name;

            /* Get HEAD oid for fallback profile */
            git_oid *fallback_oid = (git_oid *)hashmap_get(profile_oids, fallback_profile);
            if (!fallback_oid) {
                err = ERROR(ERR_INTERNAL, "Missing OID for profile '%s'", fallback_profile);
                state_free_entry(current_entry);
                free(filesystem_path);
                goto cleanup;
            }

            char fallback_oid_str[GIT_OID_HEXSZ + 1];
            git_oid_tostr(fallback_oid_str, sizeof(fallback_oid_str), fallback_oid);

            /* Update manifest entry to use fallback
             * MEMORY SAFETY: Use str_replace_owned() to properly free old strings
             * before replacing them with new values. Direct assignment would leak
             * the old allocated strings. */
            err = str_replace_owned(&current_entry->profile, fallback_profile);
            if (err) {
                state_free_entry(current_entry);
                free(filesystem_path);
                goto cleanup;
            }

            err = str_replace_owned(&current_entry->git_oid, fallback_oid_str);
            if (err) {
                state_free_entry(current_entry);
                free(filesystem_path);
                goto cleanup;
            }

            current_entry->status = MANIFEST_STATUS_PENDING_DEPLOYMENT;
            current_entry->staged_at = time(NULL);

            err = state_update_entry(state, current_entry);
            if (err) {
                state_free_entry(current_entry);
                free(filesystem_path);
                goto cleanup;
            }

            fallback_count++;
        } else {
            /* No fallback: mark for removal */
            err = state_update_entry_status(state, filesystem_path,
                                            MANIFEST_STATUS_PENDING_REMOVAL);
            if (err) {
                state_free_entry(current_entry);
                free(filesystem_path);
                goto cleanup;
            }

            removed_count++;
        }

        state_free_entry(current_entry);
        free(filesystem_path);
    }

    /* Set output counts */
    if (out_removed) *out_removed = removed_count;
    if (out_fallbacks) *out_fallbacks = fallback_count;

cleanup:
    if (profile_oids) {
        /* Free allocated OIDs */
        hashmap_iter_t iter;
        hashmap_iter_init(&iter, profile_oids);
        const char *key;
        void *value;
        while (hashmap_iter_next(&iter, &key, &value)) {
            free(value);
        }
        hashmap_free(profile_oids, NULL);
    }

    if (fresh_manifest) {
        manifest_free(fresh_manifest);
    }

    if (profiles) {
        profile_list_free(profiles);
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

        err = manifest_enable_profile(repo, state, profile_name, enabled_profiles);
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
error_t *manifest_reorder_profiles(
    git_repository *repo,
    state_t *state,
    const string_array_t *new_profile_order
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(new_profile_order);

    error_t *err = NULL;
    manifest_t *new_manifest = NULL;
    profile_list_t *profiles = NULL;
    state_file_entry_t *old_entries = NULL;
    size_t old_count = 0;
    hashmap_t *old_map = NULL;
    metadata_t *metadata = NULL;
    keymanager_t *km = NULL;
    dotta_config_t *config = NULL;

    /* 1. Build new manifest with new precedence order (precedence oracle) */
    err = build_manifest(repo, new_profile_order, &new_manifest, &profiles);
    if (err) {
        return error_wrap(err, "Failed to build manifest for precedence update");
    }

    /* 2. Verify new manifest has index */
    if (!new_manifest->index) {
        err = ERROR(ERR_INTERNAL, "New manifest missing index");
        goto cleanup;
    }

    /* 3. Get all current manifest entries and build hashmap for O(1) lookups */
    err = state_get_all_files(state, &old_entries, &old_count);
    if (err) {
        goto cleanup;
    }

    /* Build hashmap for O(1) old entry lookups */
    old_map = hashmap_create(old_count > 0 ? old_count : 16);
    if (!old_map) {
        err = ERROR(ERR_MEMORY, "Failed to create old entries hashmap");
        goto cleanup;
    }

    for (size_t i = 0; i < old_count; i++) {
        err = hashmap_set(old_map, old_entries[i].filesystem_path, &old_entries[i]);
        if (err) {
            err = error_wrap(err, "Failed to populate old entries hashmap");
            goto cleanup;
        }
    }

    /* 4. Load metadata and keymanager (needed for content hash computation) */
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

    /* 5. Process each file in new manifest */
    for (size_t i = 0; i < new_manifest->count; i++) {
        file_entry_t *new_entry = &new_manifest->entries[i];

        /* Check if exists in old state using O(1) hashmap lookup */
        state_file_entry_t *old_entry = hashmap_get(old_map, new_entry->filesystem_path);

        if (!old_entry) {
            /* New file (rare in reorder, but handle it) */

            /* Add new entry with PENDING_DEPLOYMENT */
            git_oid oid;
            char oid_str[GIT_OID_HEXSZ + 1];
            err = get_branch_head_oid(repo, new_entry->source_profile->name, &oid);
            if (err) {
                goto cleanup;
            }
            git_oid_tostr(oid_str, sizeof(oid_str), &oid);

            err = sync_entry_to_state(repo, state, new_entry, oid_str, metadata,
                                      MANIFEST_STATUS_PENDING_DEPLOYMENT, km, NULL);
            if (err) {
                goto cleanup;
            }
        } else {
            /* Existing entry - check if owner changed */
            bool owner_changed = strcmp(old_entry->profile, new_entry->source_profile->name) != 0;

            if (owner_changed) {
                /* Owner changed - update entry to new owner */
                git_oid oid;
                char oid_str[GIT_OID_HEXSZ + 1];
                err = get_branch_head_oid(repo, new_entry->source_profile->name, &oid);
                if (err) {
                    goto cleanup;
                }
                git_oid_tostr(oid_str, sizeof(oid_str), &oid);

                /* Sync with new owner (status = PENDING_DEPLOYMENT) */
                err = sync_entry_to_state(repo, state, new_entry, oid_str, metadata,
                                          MANIFEST_STATUS_PENDING_DEPLOYMENT, km, NULL);
                if (err) {
                    goto cleanup;
                }
            }
            /* else: owner unchanged, preserve existing entry status */
        }
    }

    /* 6. Check for files in old manifest but not in new (mark for removal) */
    for (size_t i = 0; i < old_count; i++) {
        state_file_entry_t *old_entry = &old_entries[i];

        /* Check if still exists in new manifest using O(1) index lookup */
        void *idx_ptr = hashmap_get(new_manifest->index, old_entry->filesystem_path);
        file_entry_t *new_entry = NULL;
        if (idx_ptr) {
            size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
            new_entry = &new_manifest->entries[idx];
        }

        if (!new_entry) {
            /* File no longer in any profile - mark for removal */
            err = state_update_entry_status(state, old_entry->filesystem_path,
                                            MANIFEST_STATUS_PENDING_REMOVAL);
            if (err) {
                goto cleanup;
            }
        }
    }

cleanup:
    if (old_map) {
        hashmap_free(old_map, NULL);
    }
    if (profiles) {
        profile_list_free(profiles);
    }
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

/**
 * Build hashmap of profile names to their current HEAD oids
 *
 * Helper for bulk operations that need git_oid for multiple profiles.
 * Creates a map: profile_name (string) -> git_oid (40-char hex string).
 *
 * @param repo Git repository
 * @param profiles Profile list (with loaded references)
 * @param out_map Output hashmap (caller must free with hashmap_free(map, free))
 * @return Error or NULL on success
 */
static error_t *build_profile_oid_map(
    git_repository *repo,
    const profile_list_t *profiles,
    hashmap_t **out_map
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out_map);

    error_t *err = NULL;

    /* Create hashmap */
    hashmap_t *map = hashmap_create(profiles->count);
    if (!map) {
        return ERROR(ERR_MEMORY, "Failed to create profile oid map");
    }

    /* Get HEAD oid for each profile */
    for (size_t i = 0; i < profiles->count; i++) {
        const profile_t *profile = &profiles->profiles[i];
        git_oid oid;

        /* Get branch HEAD */
        err = get_branch_head_oid(repo, profile->name, &oid);
        if (err) {
            hashmap_free(map, free);
            return error_wrap(err, "Failed to get HEAD for profile '%s'",
                            profile->name);
        }

        /* Convert to hex string */
        char *oid_str = malloc(GIT_OID_HEXSZ + 1);
        if (!oid_str) {
            hashmap_free(map, free);
            return ERROR(ERR_MEMORY, "Failed to allocate oid string");
        }

        git_oid_tostr(oid_str, GIT_OID_HEXSZ + 1, &oid);

        /* Store in map */
        err = hashmap_set(map, profile->name, oid_str);
        if (err) {
            free(oid_str);
            hashmap_free(map, free);
            return error_wrap(err, "Failed to add oid to map");
        }
    }

    *out_map = map;
    return NULL;
}

/**
 * Sync multiple files to manifest in bulk (optimized for update command)
 *
 * High-performance batch operation that builds a FRESH manifest from Git
 * (post-commit state) instead of using stale workspace manifest. Designed
 * for the update command's workflow where many files are synced at once
 * after Git commits.
 *
 * CRITICAL DESIGN DECISION: This function builds a FRESH manifest from Git
 * because the workspace manifest is stale after commits. Using the stale
 * manifest would cause fallback to expensive single-file operations for
 * newly added files, resulting in O(N×M) complexity instead of O(M+N).
 *
 * Algorithm:
 *   1. Load enabled profiles from Git
 *   2. Build FRESH manifest via profile_build_manifest() (O(M))
 *   3. Build hashmap index for O(1) lookups
 *   4. Build profile→oid map for git_oid field
 *   5. For each item (O(N)):
 *      - If DELETED: check fresh manifest for fallback
 *        → Fallback exists: update to fallback profile
 *        → No fallback: mark PENDING_REMOVAL
 *      - Else (modified/new): lookup in fresh manifest
 *        → Found + precedence matches: sync to state (DEPLOYED status)
 *        → Not found: file filtered/excluded (skip gracefully)
 *   6. All operations within caller's transaction
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - Git commits MUST be completed (branches at final state)
 *   - items MUST be FILE kind only (no directories)
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - Modified/new files synced with status=DEPLOYED
 *   - Deleted files fallback or marked PENDING_REMOVAL
 *   - Transaction remains open (caller commits)
 *
 * Performance: O(M + N) where M = total files in profiles, N = items to sync
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param items Array of workspace items to sync (must not be NULL)
 * @param item_count Number of items
 * @param enabled_profiles All enabled profiles (must not be NULL)
 * @param km Keymanager for content hashing (can be NULL if no encryption)
 * @param metadata_cache Hashmap: profile_name → metadata_t* (must not be NULL)
 * @param out_synced Output: count of files synced (must not be NULL)
 * @param out_removed Output: count of files removed (must not be NULL)
 * @param out_fallbacks Output: count of fallback resolutions (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_update_files(
    git_repository *repo,
    state_t *state,
    const workspace_item_t **items,
    size_t item_count,
    const string_array_t *enabled_profiles,
    keymanager_t *km,
    const hashmap_t *metadata_cache,
    content_cache_t *content_cache,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(items);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(metadata_cache);
    CHECK_NULL(out_synced);
    CHECK_NULL(out_removed);
    CHECK_NULL(out_fallbacks);

    /* Initialize outputs */
    *out_synced = 0;
    *out_removed = 0;
    *out_fallbacks = 0;

    if (item_count == 0) {
        return NULL;  /* Nothing to do */
    }

    error_t *err = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *fresh_manifest = NULL;
    hashmap_t *profile_oids = NULL;

    /* 1. Load enabled profiles from Git */
    err = profile_list_load(repo, enabled_profiles->items,
                           enabled_profiles->count, false, &profiles);
    if (err) {
        return error_wrap(err, "Failed to load profiles for bulk sync");
    }

    /* 2. Build FRESH manifest from Git (post-commit state) */
    err = profile_build_manifest(repo, profiles, &fresh_manifest);
    if (err) {
        profile_list_free(profiles);
        return error_wrap(err, "Failed to build fresh manifest for bulk sync");
    }

    /* 3. Verify manifest has index (should be populated by profile_build_manifest) */
    if (!fresh_manifest->index) {
        err = ERROR(ERR_INTERNAL, "Fresh manifest missing index");
        goto cleanup;
    }

    /* 4. Build profile oid map (profile_name -> git_oid string) */
    err = build_profile_oid_map(repo, profiles, &profile_oids);
    if (err) {
        err = error_wrap(err, "Failed to build profile oid map");
        goto cleanup;
    }

    /* 5. Process each item */
    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        /* Skip directories (not in manifest table) */
        if (item->item_kind != WORKSPACE_ITEM_FILE) {
            continue;
        }

        if (item->state == WORKSPACE_STATE_DELETED) {
            /* Handle deleted file - check for fallback in fresh manifest */
            void *idx_ptr = hashmap_get(fresh_manifest->index, item->filesystem_path);
            file_entry_t *fallback = NULL;
            if (idx_ptr) {
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
                fallback = &fresh_manifest->entries[idx];
            }

            if (fallback) {
                /* Fallback exists - update to fallback profile */
                const char *git_oid = hashmap_get(profile_oids,
                                                 fallback->source_profile->name);
                const metadata_t *metadata = hashmap_get(metadata_cache,
                                                        fallback->source_profile->name);

                err = sync_entry_to_state(repo, state, fallback, git_oid, metadata,
                                         MANIFEST_STATUS_PENDING_DEPLOYMENT, km, content_cache);
                if (err) {
                    err = error_wrap(err, "Failed to sync fallback for '%s'",
                                   item->filesystem_path);
                    goto cleanup;
                }

                (*out_fallbacks)++;
            } else {
                /* No fallback - mark for removal */
                err = state_update_entry_status(state, item->filesystem_path,
                                               MANIFEST_STATUS_PENDING_REMOVAL);
                if (err) {
                    err = error_wrap(err, "Failed to mark '%s' for removal",
                                   item->filesystem_path);
                    goto cleanup;
                }

                (*out_removed)++;
            }
        } else {
            /* Handle modified/new file */
            void *idx_ptr = hashmap_get(fresh_manifest->index, item->filesystem_path);
            file_entry_t *entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
                entry = &fresh_manifest->entries[idx];
            }

            if (!entry) {
                /* File not in fresh manifest - filtered/excluded
                 * This is expected behavior (e.g., .dottaignore) - skip gracefully */
                continue;
            }

            /* Check precedence matches */
            if (entry->source_profile &&
                strcmp(entry->source_profile->name, item->profile) != 0) {
                /* Different profile won precedence - skip this file
                 * (higher precedence profile will handle it) */
                continue;
            }

            /* Sync to state with DEPLOYED status
             *
             * Key insight: UPDATE captures files FROM filesystem, so they're
             * already deployed. Setting PENDING_DEPLOYMENT would be misleading. */
            const char *git_oid = hashmap_get(profile_oids, item->profile);
            const metadata_t *metadata = hashmap_get(metadata_cache, item->profile);

            err = sync_entry_to_state(repo, state, entry, git_oid, metadata,
                                     MANIFEST_STATUS_DEPLOYED, km, content_cache);
            if (err) {
                err = error_wrap(err, "Failed to sync '%s' to manifest",
                               item->filesystem_path);
                goto cleanup;
            }

            (*out_synced)++;
        }
    }

cleanup:
    if (profile_oids) {
        hashmap_free(profile_oids, free);  /* Free oid strings */
    }
    if (fresh_manifest) {
        manifest_free(fresh_manifest);
    }
    if (profiles) {
        profile_list_free(profiles);
    }

    return err;
}

/**
 * Sync multiple files to manifest in bulk - simplified for add command
 *
 * Optimized bulk operation for adding newly-committed files to manifest.
 * Simpler than manifest_update_files() because:
 * - All files are from the same profile
 * - No deletions (only additions/updates)
 * - Status is always MANIFEST_STATUS_DEPLOYED (captured from filesystem)
 *
 * CRITICAL DESIGN: Like manifest_update_files(), this builds a FRESH
 * manifest from Git (post-commit state). This ensures all newly-added files
 * are found during precedence checks, avoiding O(N×M) fallback to
 * manifest_sync_file().
 *
 * Algorithm:
 *   1. Load enabled profiles from Git (current HEAD, post-commit)
 *   2. Build fresh manifest with profile_build_manifest() (ONCE)
 *   3. Build hashmap index for O(1) precedence lookups
 *   4. Build profile→oid map for git_oid field
 *   5. For each file:
 *      - Convert filesystem_path → storage_path
 *      - Lookup in fresh manifest
 *      - If precedence matches: sync to state with DEPLOYED status
 *      - If lower precedence or filtered: skip silently
 *   6. All operations within caller's transaction
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - Git commits MUST be completed (branches at final state)
 *   - filesystem_paths MUST be valid, canonical paths
 *   - profile_name SHOULD be enabled (function gracefully handles if not)
 *
 * Postconditions:
 *   - Files synced to manifest with MANIFEST_STATUS_DEPLOYED
 *   - Lower-precedence files skipped (not an error)
 *   - Filtered files skipped (not an error)
 *   - Transaction remains open (caller commits via state_save)
 *
 * Performance:
 *   - O(M + N) where M = total files in all profiles, N = files to add
 *   - Single fresh manifest build from Git
 *   - Batch-optimized state operations
 *
 * Error Handling:
 *   - Transactional: on error, entire batch fails
 *   - Returns error on first failure (fail-fast)
 *   - Path resolution errors are fatal
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param profile_name Profile files were added to (must not be NULL)
 * @param filesystem_paths Array of filesystem paths (must not be NULL)
 * @param enabled_profiles All enabled profiles (must not be NULL)
 * @param km Keymanager for content hashing (can be NULL if no encryption)
 * @param metadata_cache Hashmap: profile_name → metadata_t* (must not be NULL)
 * @param out_synced Output: count of files synced (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_add_files(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *filesystem_paths,
    const string_array_t *enabled_profiles,
    keymanager_t *km,
    const hashmap_t *metadata_cache,
    content_cache_t *content_cache,
    size_t *out_synced
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profile_name);
    CHECK_NULL(filesystem_paths);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(metadata_cache);
    CHECK_NULL(out_synced);

    /* Initialize output */
    *out_synced = 0;

    if (string_array_size(filesystem_paths) == 0) {
        return NULL;  /* Nothing to do */
    }

    error_t *err = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *fresh_manifest = NULL;
    hashmap_t *profile_oids = NULL;

    /* 1. Load enabled profiles from Git */
    err = profile_list_load(repo, enabled_profiles->items,
                           enabled_profiles->count, false, &profiles);
    if (err) {
        return error_wrap(err, "Failed to load profiles for bulk sync");
    }

    /* 2. Build FRESH manifest from Git (post-commit state) */
    err = profile_build_manifest(repo, profiles, &fresh_manifest);
    if (err) {
        profile_list_free(profiles);
        return error_wrap(err, "Failed to build fresh manifest for bulk sync");
    }

    /* 3. Verify manifest has index (should be populated by profile_build_manifest) */
    if (!fresh_manifest->index) {
        err = ERROR(ERR_INTERNAL, "Fresh manifest missing index");
        goto cleanup;
    }

    /* 4. Build profile oid map (profile_name -> git_oid string) */
    err = build_profile_oid_map(repo, profiles, &profile_oids);
    if (err) {
        err = error_wrap(err, "Failed to build profile oid map");
        goto cleanup;
    }

    /* 5. Process each file */
    for (size_t i = 0; i < string_array_size(filesystem_paths); i++) {
        const char *filesystem_path = string_array_get(filesystem_paths, i);

        /* Lookup in fresh manifest using filesystem_path */
        void *idx_ptr = hashmap_get(fresh_manifest->index, filesystem_path);
        file_entry_t *entry = NULL;
        if (idx_ptr) {
            size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
            entry = &fresh_manifest->entries[idx];
        }

        if (!entry) {
            /* File not in fresh manifest - filtered/excluded
             * This is expected behavior (e.g., .dottaignore, README.md) - skip gracefully */
            continue;
        }

        /* Check precedence matches */
        if (entry->source_profile &&
            strcmp(entry->source_profile->name, profile_name) != 0) {
            /* Different profile won precedence - skip this file
             * (higher precedence profile owns it) */
            continue;
        }

        /* Sync to state with DEPLOYED status
         *
         * Key insight: ADD captures files FROM filesystem, so they're
         * already deployed. Setting PENDING_DEPLOYMENT would be misleading. */
        const char *profile_git_oid = hashmap_get(profile_oids, entry->source_profile->name);
        const metadata_t *metadata = hashmap_get(metadata_cache, entry->source_profile->name);

        err = sync_entry_to_state(repo, state, entry, profile_git_oid, metadata,
                                 MANIFEST_STATUS_DEPLOYED, km, content_cache);

        if (err) {
            err = error_wrap(err, "Failed to sync '%s' to manifest",
                           filesystem_path);
            goto cleanup;
        }

        (*out_synced)++;
    }

cleanup:
    if (profile_oids) {
        hashmap_free(profile_oids, free);  /* Free oid strings */
    }
    if (fresh_manifest) {
        manifest_free(fresh_manifest);
    }
    if (profiles) {
        profile_list_free(profiles);
    }

    return err;
}

/**
 * Sync manifest from Git diff (bulk operation)
 *
 * Updates manifest table based on changes between old_oid and new_oid for a
 * single profile. Uses O(M+D) bulk pattern instead of O(D×M) per-file operations.
 *
 * This is the core function for updating the manifest after sync operations
 * (pull, rebase, merge). It efficiently processes an entire Git diff by:
 *   1. Building the fresh manifest from Git ONCE (O(M))
 *   2. Creating hashmap indexes for O(1) lookups
 *   3. Processing each delta with fast lookups (O(D))
 *
 * Algorithm:
 *   Phase 1: Build Context
 *     - Load all enabled profiles
 *     - Build fresh manifest from current Git state (post-sync)
 *     - Create hashmap index for O(1) file lookups
 *     - Build profile→oid map
 *     - Load or use cached metadata and keymanager
 *
 *   Phase 2: Compute Diff
 *     - Lookup old and new trees
 *     - Generate Git diff between them
 *
 *   Phase 3: Process Deltas
 *     - For additions/modifications: sync with PENDING_DEPLOYMENT status
 *     - For deletions: check for fallbacks, mark PENDING_REMOVAL if none
 *     - Handle precedence: only sync if profile won the file
 *
 * Performance: O(M + D) where M = total files in all profiles, D = changed files
 *   Old implementation: O(D × M) with repeated manifest builds
 *   Speedup: ~50-100x for typical workloads
 *
 * Transaction: Caller must open transaction (state_load_for_update) and commit
 *              (state_save) after calling. This function works within an active
 *              transaction.
 *
 * Status Semantics: All changes marked PENDING_DEPLOYMENT because sync updates
 *                   Git but doesn't deploy to filesystem. User must run 'dotta apply'
 *                   to actually deploy changes.
 *
 * @param repo Repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param profile_name Profile being synced (must not be NULL)
 * @param old_oid Old commit before sync (must not be NULL)
 * @param new_oid New commit after sync (must not be NULL)
 * @param enabled_profiles All enabled profiles for precedence (must not be NULL)
 * @param km Keymanager for content hashing (can be NULL, will create if needed)
 * @param metadata_cache Pre-loaded metadata (can be NULL, will load if needed)
 * @param out_synced Output: number of files synced (can be NULL)
 * @param out_removed Output: number of files removed (can be NULL)
 * @param out_fallbacks Output: number of fallback resolutions (can be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_sync_diff(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles,
    keymanager_t *km,
    const hashmap_t *metadata_cache,
    content_cache_t *content_cache,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profile_name);
    CHECK_NULL(old_oid);
    CHECK_NULL(new_oid);
    CHECK_NULL(enabled_profiles);

    error_t *err = NULL;

    /* Resources to clean up */
    profile_list_t *profiles = NULL;
    manifest_t *fresh_manifest = NULL;
    hashmap_t *profile_oids = NULL;
    metadata_t *metadata_merged = NULL;
    keymanager_t *km_owned = NULL;
    dotta_config_t *config = NULL;
    git_commit *old_commit = NULL;
    git_commit *new_commit = NULL;
    git_tree *old_tree = NULL;
    git_tree *new_tree = NULL;
    git_diff *diff = NULL;

    size_t synced = 0, removed = 0, fallbacks = 0;

    /* PHASE 1: BUILD CONTEXT (O(M)) */
    /* ============================== */

    /* 1.1. Load all enabled profiles from Git (current state) */
    err = profile_list_load(
        repo,
        enabled_profiles->items,
        enabled_profiles->count,
        false,  /* strict=false: skip missing profiles */
        &profiles
    );
    if (err) {
        err = error_wrap(err, "Failed to load enabled profiles");
        goto cleanup;
    }

    /* 1.2. Build FRESH manifest from Git (post-sync state)
     *
     * This reflects the NEW state after sync. We build from current branch HEADs,
     * not from specific OIDs, because profile_build_manifest() reads current state.
     * This is correct because after pull/rebase/merge, branch HEAD already points
     * to the new commit. */
    err = profile_build_manifest(repo, profiles, &fresh_manifest);
    if (err) {
        err = error_wrap(err, "Failed to build fresh manifest");
        goto cleanup;
    }

    /* 1.3. Verify manifest has index (should be populated by profile_build_manifest) */
    if (!fresh_manifest->index) {
        err = ERROR(ERR_INTERNAL, "Fresh manifest missing index");
        goto cleanup;
    }

    /* 1.4. Build profile→oid map (profile_name -> git_oid string) */
    err = build_profile_oid_map(repo, profiles, &profile_oids);
    if (err) {
        err = error_wrap(err, "Failed to build profile oid map");
        goto cleanup;
    }

    /* 1.5. Load or use cached metadata
     *
     * Note: metadata_cache is a hashmap (profile_name → metadata_t*) from workspace.
     * If not provided, we load merged metadata for all profiles. For lookups, we
     * need to handle both patterns. */

    if (!metadata_cache) {
        /* No cache provided - load merged metadata for all enabled profiles */
        err = metadata_load_from_profiles(repo, enabled_profiles, &metadata_merged);
        if (err && err->code != ERR_NOT_FOUND) {
            err = error_wrap(err, "Failed to load metadata");
            goto cleanup;
        }
        if (err) {
            error_free(err);
            err = NULL;
        }
    }

    /* 1.6. Create or use provided keymanager */
    if (!km) {
        /* No keymanager provided - create one */
        err = config_load(NULL, &config);
        if (err) {
            err = error_wrap(err, "Failed to create config");
            goto cleanup;
        }

        err = keymanager_create(config, &km_owned);
        if (err) {
            err = error_wrap(err, "Failed to create keymanager");
            goto cleanup;
        }

        km = km_owned;
    }

    /* PHASE 2: COMPUTE DIFF (O(D)) */
    /* ============================= */

    /* 2.1. Lookup commits and extract trees for diff
     *
     * Note: old_oid and new_oid are commit OIDs (from branch refs), not tree OIDs.
     * We must lookup the commit object first, then extract the tree from it.
     * This is the standard pattern used throughout the codebase. */

    /* Old commit → tree */
    int git_err = git_commit_lookup(&old_commit, repo, old_oid);
    if (git_err != 0) {
        err = ERROR(ERR_GIT, "Failed to lookup old commit: %s",
                   git_error_last()->message);
        goto cleanup;
    }

    git_err = git_commit_tree(&old_tree, old_commit);
    if (git_err != 0) {
        err = ERROR(ERR_GIT, "Failed to extract tree from old commit: %s",
                   git_error_last()->message);
        goto cleanup;
    }

    /* New commit → tree */
    git_err = git_commit_lookup(&new_commit, repo, new_oid);
    if (git_err != 0) {
        err = ERROR(ERR_GIT, "Failed to lookup new commit: %s",
                   git_error_last()->message);
        goto cleanup;
    }

    git_err = git_commit_tree(&new_tree, new_commit);
    if (git_err != 0) {
        err = ERROR(ERR_GIT, "Failed to extract tree from new commit: %s",
                   git_error_last()->message);
        goto cleanup;
    }

    /* 2.2. Compute diff between old and new trees */
    git_err = git_diff_tree_to_tree(&diff, repo, old_tree, new_tree, NULL);
    if (git_err != 0) {
        err = ERROR(ERR_GIT, "Failed to diff trees: %s",
                   git_error_last()->message);
        goto cleanup;
    }

    size_t num_deltas = git_diff_num_deltas(diff);

    /* PHASE 3: PROCESS DELTAS (O(D)) */
    /* =============================== */

    for (size_t i = 0; i < num_deltas; i++) {
        const git_diff_delta *delta = git_diff_get_delta(diff, i);
        if (!delta) {
            continue;
        }

        /* Determine storage path based on delta type */
        const char *storage_path = delta->new_file.path;
        if (delta->status == GIT_DELTA_DELETED) {
            storage_path = delta->old_file.path;
        }

        /* Resolve filesystem path */
        char *filesystem_path = NULL;
        error_t *path_err = path_from_storage(storage_path, &filesystem_path);
        if (path_err) {
            /* Skip files we can't resolve (invalid paths) */
            error_free(path_err);
            continue;
        }

        /* Handle based on delta type */
        if (delta->status == GIT_DELTA_ADDED || delta->status == GIT_DELTA_MODIFIED) {
            /* ADDITION / MODIFICATION */
            /* ======================= */

            /* Lookup in fresh manifest (O(1)) */
            void *idx_ptr = hashmap_get(fresh_manifest->index, filesystem_path);
            file_entry_t *entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
                entry = &fresh_manifest->entries[idx];
            }

            if (!entry) {
                /* File not in fresh manifest (filtered by .dottaignore or other rules)
                 * This is expected behavior - skip gracefully */
                free(filesystem_path);
                continue;
            }

            /* Check precedence: Does profile_name win?
             *
             * This is critical: if a different profile won precedence for this file,
             * we should NOT update the manifest entry. The winning profile will handle
             * it when its changes are synced. */
            if (entry->source_profile &&
                strcmp(entry->source_profile->name, profile_name) != 0) {
                /* Different profile won precedence - skip this file */
                free(filesystem_path);
                continue;
            }

            /* Sync entry to state with PENDING_DEPLOYMENT status
             *
             * Key: We use PENDING_DEPLOYMENT (not DEPLOYED) because sync only updates
             * Git, it doesn't deploy to filesystem. User must run 'dotta apply' to
             * actually deploy these changes. */
            const char *git_oid_str = hashmap_get(profile_oids, profile_name);

            /* Get metadata - from cache if available, otherwise use merged */
            const metadata_t *profile_metadata = NULL;
            if (metadata_cache) {
                profile_metadata = hashmap_get(metadata_cache, profile_name);
            } else {
                profile_metadata = metadata_merged;
            }

            err = sync_entry_to_state(
                repo, state, entry, git_oid_str, profile_metadata,
                MANIFEST_STATUS_PENDING_DEPLOYMENT,
                km, content_cache
            );

            if (err) {
                err = error_wrap(err, "Failed to sync '%s' to manifest", filesystem_path);
                free(filesystem_path);
                goto cleanup;
            }

            synced++;

        } else if (delta->status == GIT_DELTA_DELETED) {
            /* DELETION */
            /* ======== */

            /* Check if file exists in manifest from OTHER profiles (fallback check)
             *
             * When a file is deleted from one profile, it might still exist in another
             * lower-precedence profile. If so, that profile now "wins" and we should
             * update the manifest to point to it. */
            void *idx_ptr = hashmap_get(fresh_manifest->index, filesystem_path);
            file_entry_t *entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
                entry = &fresh_manifest->entries[idx];
            }

            if (entry && entry->source_profile &&
                strcmp(entry->source_profile->name, profile_name) != 0) {
                /* File exists in another profile (fallback found!)
                 *
                 * Update manifest entry to point to the new profile owner.
                 * Mark as PENDING_DEPLOYMENT because ownership changed. */

                const char *fallback_git_oid = hashmap_get(profile_oids,
                                                           entry->source_profile->name);

                /* Get metadata - from cache if available, otherwise use merged */
                const metadata_t *fallback_metadata = NULL;
                if (metadata_cache) {
                    fallback_metadata = hashmap_get(metadata_cache, entry->source_profile->name);
                } else {
                    fallback_metadata = metadata_merged;
                }

                err = sync_entry_to_state(
                    repo, state, entry, fallback_git_oid, fallback_metadata,
                    MANIFEST_STATUS_PENDING_DEPLOYMENT,
                    km, content_cache
                );

                if (err) {
                    err = error_wrap(err, "Failed to sync fallback for '%s'", filesystem_path);
                    free(filesystem_path);
                    goto cleanup;
                }

                fallbacks++;

            } else {
                /* No fallback exists - check if we own this file in current state */

                state_file_entry_t *state_entry = NULL;
                err = state_get_file(state, filesystem_path, &state_entry);

                if (err) {
                    /* File not in state (never deployed) - nothing to do */
                    if (err->code == ERR_NOT_FOUND) {
                        error_free(err);
                        err = NULL;
                    }
                    free(filesystem_path);
                    continue;
                }

                /* Check if profile_name owns this file */
                if (strcmp(state_entry->profile, profile_name) == 0) {
                    /* We own it and no fallback exists - mark for removal
                     *
                     * Set status to PENDING_REMOVAL. When user runs 'dotta apply',
                     * the file will be removed from filesystem and deleted from manifest. */

                    state_entry->status = MANIFEST_STATUS_PENDING_REMOVAL;
                    err = state_update_entry(state, state_entry);

                    if (err) {
                        err = error_wrap(err, "Failed to mark '%s' for removal", filesystem_path);
                        state_free_entry(state_entry);
                        free(filesystem_path);
                        goto cleanup;
                    }

                    removed++;
                }

                state_free_entry(state_entry);
            }
        }

        free(filesystem_path);
    }

    /* Set output counters */
    if (out_synced) *out_synced = synced;
    if (out_removed) *out_removed = removed;
    if (out_fallbacks) *out_fallbacks = fallbacks;

cleanup:
    /* Free resources in reverse order of acquisition */
    if (diff) {
        git_diff_free(diff);
    }
    if (new_tree) {
        git_tree_free(new_tree);
    }
    if (old_tree) {
        git_tree_free(old_tree);
    }
    if (new_commit) {
        git_commit_free(new_commit);
    }
    if (old_commit) {
        git_commit_free(old_commit);
    }
    if (config) {
        config_free(config);
    }
    if (km_owned) {
        keymanager_free(km_owned);
    }
    if (metadata_merged) {
        metadata_free(metadata_merged);
    }
    if (profile_oids) {
        hashmap_free(profile_oids, free);  /* Free oid strings */
    }
    if (fresh_manifest) {
        manifest_free(fresh_manifest);
    }
    if (profiles) {
        profile_list_free(profiles);
    }

    return err;
}
