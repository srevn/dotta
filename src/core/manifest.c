/**
 * manifest.c - Manifest transparent layer implementation
 *
 * The manifest module is the single authority for all manifest table modifications.
 * It maintains the manifest as a Virtual Working Directory (VWD) - an expected state
 * cache between Git branches and the filesystem, enabling runtime convergence.
 *
 * Key patterns:
 *   - Precedence Oracle: Reuses profile_build_manifest() for correctness
 *   - Transaction Management: Caller manages transactions, we operate within them
 *   - Blob OID Extraction: Reads pre-populated blob_oid from file_entry_t for O(1) content identity
 *   - Metadata Integration: Uses metadata_load_from_profiles() for merged view
 */

#include "core/manifest.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/path.h"
#include "sys/gitops.h"

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

    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", branch_name
    );
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    return gitops_resolve_reference_oid(repo, refname, out_oid);
}

/**
 * Find a profile's cached HEAD OID from a loaded profile list
 *
 * Linear scan over the list (P < 10 typically). Every profile_t in a list
 * built by profile_list_load carries its peeled HEAD OID, so this avoids
 * a redundant ref lookup via get_branch_head_oid.
 *
 * @param list Loaded profile list (must not be NULL)
 * @param name Profile name to find (must not be NULL)
 * @return Pointer to cached head_oid, or NULL if name not in list
 */
static const git_oid *profile_list_head_oid(
    const profile_list_t *list,
    const char *name
) {
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->profiles[i].name, name) == 0)
            return &list->profiles[i].head_oid;
    }
    return NULL;
}

/**
 * Build manifest from profiles (precedence oracle)
 *
 * Loads profile objects from Git and builds a precedence-resolved manifest.
 * The caller owns prefix_map (borrowed, not freed by this function).
 *
 * Note: Manifest entries borrow profile_name strings from the profile_list.
 * The profile_list must remain alive while the manifest is in use.
 *
 * @param repo Git repository (must not be NULL)
 * @param profiles Profile names to build from (must not be NULL)
 * @param prefix_map Custom prefix map (borrowed, can be NULL)
 * @param arena Arena for manifest string allocations (NULL = heap)
 * @param out_manifest Output manifest (caller must free with manifest_free)
 * @param out_profiles Output profile list (caller must free with profile_list_free)
 * @return Error or NULL on success
 */
static error_t *build_manifest(
    git_repository *repo,
    const string_array_t *profiles,
    const hashmap_t *prefix_map,
    arena_t *arena,
    manifest_t **out_manifest,
    profile_list_t **out_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out_manifest);
    CHECK_NULL(out_profiles);

    error_t *err = NULL;
    profile_list_t *list = NULL;
    manifest_t *manifest = NULL;

    /* Load profiles from Git (profiles module - pure Git operations) */
    err = profile_list_load(repo, profiles, &list);
    if (err) {
        return error_wrap(err, "Failed to load profiles for manifest build");
    }

    /* Build manifest from profiles with prefix map (applies precedence rules) */
    err = profile_build_manifest(repo, list, prefix_map, arena, &manifest);
    if (err) {
        profile_list_free(list);
        return error_wrap(err, "Failed to build manifest from profiles");
    }

    *out_manifest = manifest;
    *out_profiles = list;
    return NULL;
}

/**
 * Sync single entry from in-memory manifest to state
 *
 * Translates from in-memory manifest representation (file_entry_t) to
 * persistent state representation (state_file_entry_t in SQLite).
 *
 * RESPONSIBILITY CONTRACT ("Dumb Writer" Pattern):
 *   - Caller MUST determine the correct deployed_at value
 *   - Function writes exactly what caller provides (no preservation)
 *   - Uses INSERT OR REPLACE for atomic upsert
 *
 * To preserve existing deployed_at:
 *   1. Caller calls state_get_file() to fetch existing entry
 *   2. Caller passes existing->deployed_at to this function
 *   3. Function writes that exact value
 *
 * Callers must use entries from profile_build_manifest (or equivalent) where
 * the tree entry is pre-populated (needed for blob_oid extraction).
 *
 * Responsibilities:
 *   - Extract blob_oid from tree entry
 *   - Extract metadata (mode, owner, group, encrypted flag)
 *   - Build state entry structure with caller-provided deployed_at
 *   - Write to state database (INSERT OR REPLACE)
 *
 * Note: commit_oid is stored per-profile in enabled_profiles, not per-file.
 * Callers are responsible for calling state_set_profile_commit_oid after syncing,
 * using the cached head_oid from the loaded profile_list_t.
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param manifest_entry Entry from in-memory manifest (borrowed); MUST have
 *                       tree entry and profile_name set (guaranteed for entries
 *                       from profile_build_manifest)
 * @param metadata Merged metadata from all profiles
 * @param deployed_at Caller-determined lifecycle timestamp (NOT modified):
 *       - 0: File never deployed (shows as [undeployed] if missing)
 *       - time(NULL): File exists on filesystem (initial capture)
 *       - existing->deployed_at: Preserve history (caller must fetch)
 * @return Error or NULL on success
 */
static error_t *sync_entry_to_state(
    git_repository *repo,
    state_t *state,
    const file_entry_t *manifest_entry,
    const metadata_t *metadata,
    time_t deployed_at,
    const char *old_profile
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(manifest_entry);
    CHECK_NULL(manifest_entry->profile_name);

    error_t *err = NULL;
    metadata_item_t *meta_item = NULL;

    /* 1. Read blob_oid from pre-populated entry field (set during tree walk). */
    const git_oid *blob_oid_obj = &manifest_entry->blob_oid;

    /* 2. Get metadata item (may not exist for old profiles) */
    if (metadata) {
        err = metadata_get_item(
            metadata, manifest_entry->storage_path, (const metadata_item_t **) &meta_item
        );
        /* Allow NOT_FOUND (old profiles without metadata) */
        if (err && err->code != ERR_NOT_FOUND) {
            return err;
        }
        if (err) {
            error_free(err);
            err = NULL;
        }
    }

    /* 3. Read file type and mode from pre-populated entry fields.
     *
     * These were derived from git_tree_entry_filemode() during the tree walk
     * callback and stored as scalar fields on file_entry_t. */
    state_file_type_t file_type = manifest_entry->type;
    mode_t git_mode = manifest_entry->mode;

    /* 4. Determine mode with metadata precedence (no allocation needed!)
     *
     * Precedence Rules:
     *   1. Metadata mode (if present) - explicit user intent, may differ from Git
     *      Example: User wants 0600 (private) instead of Git's 0644
     *   2. Git mode (fallback) - authoritative for type, good default for permissions */
    mode_t mode = meta_item ? meta_item->mode : git_mode;

    /* 5. Build state entry. blob_oid is an inline struct copy from the
     * pre-populated entry field. commit_oid lives in enabled_profiles
     * (per-profile, not per-file) and is set via state_set_profile_commit_oid
     * using the cached head_oid from the loaded profile_list_t. */
    state_file_entry_t state_entry = {
        .storage_path    = manifest_entry->storage_path,
        .filesystem_path = manifest_entry->filesystem_path,
        .profile         = (char *) manifest_entry->profile_name,
        .old_profile     = (char *) old_profile,
        .type            = file_type,
        .blob_oid        = *blob_oid_obj,
        .mode            = mode,
        .owner           = meta_item ? meta_item->owner : NULL,
        .group           = meta_item ? meta_item->group : NULL,
        .encrypted       = (meta_item && meta_item->kind == METADATA_ITEM_FILE)
                         ? meta_item->file.encrypted : false,
        .state           = STATE_ACTIVE,
        .deployed_at     = deployed_at
    };

    /* 6. Write entry to state (INSERT OR REPLACE)
     *
     * Uses INSERT OR REPLACE for atomic upsert. The SQL's COALESCE on
     * old_profile preserves existing values when NULL, overrides when
     * non-NULL — enabling atomic reassignment tracking in one operation.
     */
    err = state_add_file(state, &state_entry);
    if (err) {
        err = error_wrap(
            err, "Failed to sync manifest entry for %s",
            manifest_entry->storage_path
        );
    }

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
    const char *custom_prefix,
    const string_array_t *enabled_profiles,
    manifest_enable_stats_t *out_stats
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profile_name);
    CHECK_NULL(enabled_profiles);

    /* Initialize output stats (access_errors is incremented inline, must start at 0) */
    if (out_stats) {
        memset(out_stats, 0, sizeof(*out_stats));
    }

    error_t *err = NULL;
    manifest_t *manifest = NULL;
    profile_list_t *profiles = NULL;
    hashmap_t *prefix_map = NULL;
    metadata_t *metadata = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Load prefix map and build manifest */
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to get custom prefix map");
    }

    /* Apply transient prefix override (enable path only).
     *
     * When enabling a profile with --prefix, the prefix isn't in state yet
     * (it's about to be stored). Override the map value so the manifest
     * oracle includes custom/ files for this profile. */
    if (custom_prefix) {
        char *dup_value = strdup(custom_prefix);
        if (!dup_value) {
            hashmap_free(prefix_map, free);
            arena_destroy(arena);
            return ERROR(ERR_MEMORY, "Failed to set transient custom prefix");
        }
        void *old_value = NULL;
        err = hashmap_put(prefix_map, profile_name, dup_value, &old_value);
        free(old_value);
        if (err) {
            free(dup_value);
            hashmap_free(prefix_map, free);
            arena_destroy(arena);
            return error_wrap(err, "Failed to set transient custom prefix");
        }
    }

    /* 2. Build FRESH manifest from Git (post-add state) */
    err = build_manifest(
        repo, enabled_profiles, prefix_map, arena, &manifest, &profiles
    );
    if (err) {
        hashmap_free(prefix_map, free);
        arena_destroy(arena);
        return error_wrap(err, "Failed to build manifest for profile sync");
    }

    /* Defensive: build_manifest should always set outputs on success */
    if (!manifest || !profiles) {
        err = ERROR(
            ERR_INTERNAL,
            "build_manifest succeeded but returned NULL outputs"
        );
        goto cleanup;
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

    /* 4. Sync entries owned by this profile (highest precedence)
     *
     * deployed_at for INSERT (new files) is determined by lstat: time(NULL) if
     * the file exists on disk, 0 if it doesn't. For UPDATE (existing entries),
     * deployed_at is preserved by the SQL UPSERT — the caller-provided value
     * is only used on the INSERT path. */

    /* Track counts for user feedback */
    size_t total_files = 0;
    size_t already_deployed = 0;
    size_t needs_deployment = 0;

    for (size_t i = 0; i < manifest->count; i++) {
        file_entry_t *entry = &manifest->entries[i];

        /* Only process files owned by this profile */
        if (strcmp(entry->profile_name, profile_name) != 0) {
            continue;
        }

        total_files++;

        /* Determine deployed_at and count statistics via lstat.
         *
         * For UPDATE (existing entries): SQL UPSERT preserves the existing
         * deployed_at regardless of the value passed here.
         * For INSERT (new entries): lstat determines the initial value.
         *   time(NULL) = file exists on disk ("known to dotta")
         *   0          = file missing or inaccessible ("never deployed") */
        time_t deployed_at;
        struct stat st;

        /* New entry - check if file exists on filesystem */
        if (lstat(entry->filesystem_path, &st) == 0) {
            /* File exists - mark as "known to dotta" */
            deployed_at = time(NULL);
            already_deployed++;
        } else if (errno == ENOENT) {
            /* File doesn't exist - mark as "never deployed" */
            deployed_at = 0;
            needs_deployment++;
        } else {
            /* Unexpected error (permission denied, I/O error, etc.)
             *
             * Non-fatal approach: Use conservative default (deployed_at = 0) and
             * count as needs_deployment rather than blocking the entire operation.
             * This maintains the VWD scope invariant (all profile files in manifest)
             * while deferring deployment decisions to runtime convergence.
             *
             * Rationale: The deployed_at timestamp is only an initial guess for
             * statistics. The real divergence is determined at runtime during
             * status/apply commands via workspace divergence analysis. Using a
             * conservative default (0) allows the operation to proceed while
             * signaling to the user that these files need attention. */
            deployed_at = 0;
            needs_deployment++;

            /* Track access errors for user feedback */
            if (out_stats) {
                out_stats->access_errors++;
            }
        }

        /* Sync entry with deployed_at timestamp */
        err = sync_entry_to_state(repo, state, entry, metadata, deployed_at, NULL);
        if (err) goto cleanup;
    }

    /* Populate output stats if requested */
    if (out_stats) {
        out_stats->total_files = total_files;
        out_stats->already_deployed = already_deployed;
        out_stats->needs_deployment = needs_deployment;
    }

    /* 5. Record profile's current HEAD in enabled_profiles.commit_oid.
     *
     * state_enable_profile inserts with zeroblob(20); this replaces the
     * sentinel with the real HEAD. Uses the already-loaded profile_list_t
     * to avoid a redundant ref lookup. */
    const git_oid *head_oid = profile_list_head_oid(profiles, profile_name);
    if (!head_oid) {
        err = ERROR(
            ERR_INTERNAL,
            "Profile '%s' not found in loaded profile list", profile_name
        );
        goto cleanup;
    }
    err = state_set_profile_commit_oid(state, profile_name, head_oid);
    if (err) {
        err = error_wrap(err, "Failed to set commit_oid for profile '%s'", profile_name);
        goto cleanup;
    }

    /* 6. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (prefix_map) hashmap_free(prefix_map, free);
    if (profiles) profile_list_free(profiles);
    if (metadata) metadata_free(metadata);
    if (manifest) manifest_free(manifest);
    arena_destroy(arena);

    return err;
}

/**
 * Build directory fallback index from remaining enabled profiles
 *
 * Loads metadata from each remaining profile and builds O(1) lookup hashmaps
 * for directory fallback resolution. This implements "last wins" precedence,
 * matching the file fallback pattern (build_manifest()) and workspace metadata
 * merge pattern.
 *
 * PRECEDENCE MODEL:
 * - Profiles iterated in precedence order (low→high): global < OS < host
 * - Later profiles override earlier ones ("last wins")
 * - Result: Highest precedence profile wins for each directory
 *
 * MEMORY MODEL:
 * - Returns borrowed pointers into loaded_metadata array
 * - Caller MUST keep loaded_metadata alive while using hashmaps
 * - Caller responsible for cleanup via provided pattern (see manifest_disable_profile)
 *
 * EDGE CASES HANDLED:
 * - Empty remaining_enabled: Returns empty hashmaps (not an error)
 * - No directories in any profile: Returns empty hashmaps
 * - Metadata file missing: Skips gracefully (continues to next profile)
 * - Memory allocation failure: Cleans up loaded metadata and returns error
 *
 * @param repo Git repository (must not be NULL)
 * @param remaining_enabled Profile names in precedence order (must not be NULL)
 * @param out_fallback_dirs Storage path → metadata_item_t* hashmap (caller must free)
 * @param out_fallback_profiles Storage path → profile name hashmap (caller must free)
 * @param out_loaded_metadata Array of loaded metadata for cleanup (caller must free all)
 * @param out_loaded_count Number of loaded metadata instances
 * @return Error or NULL on success
 */
static error_t *build_directory_fallback_index(
    git_repository *repo,
    const string_array_t *remaining_enabled,
    hashmap_t **out_fallback_dirs,
    hashmap_t **out_fallback_profiles,
    metadata_t ***out_loaded_metadata,
    size_t *out_loaded_count
) {
    CHECK_NULL(repo);
    CHECK_NULL(remaining_enabled);
    CHECK_NULL(out_fallback_dirs);
    CHECK_NULL(out_fallback_profiles);
    CHECK_NULL(out_loaded_metadata);
    CHECK_NULL(out_loaded_count);

    error_t *err = NULL;
    hashmap_t *fallback_dirs = NULL;
    hashmap_t *fallback_dir_profiles = NULL;
    metadata_t **loaded_metadata = NULL;
    size_t loaded_metadata_count = 0;

    /* Handle empty profile list (edge case: all profiles disabled) */
    if (remaining_enabled->count == 0) {
        *out_fallback_dirs = hashmap_create(1);  /* Empty hashmap */
        *out_fallback_profiles = hashmap_create(1);
        if (!*out_fallback_dirs || !*out_fallback_profiles) {
            if (*out_fallback_dirs) hashmap_free(*out_fallback_dirs, NULL);
            if (*out_fallback_profiles) hashmap_free(*out_fallback_profiles, NULL);
            return ERROR(ERR_MEMORY, "Failed to create empty hashmaps");
        }
        *out_loaded_metadata = NULL;
        *out_loaded_count = 0;
        return NULL;
    }

    /* Initialize hashmaps */
    fallback_dirs = hashmap_borrow(64);
    fallback_dir_profiles = hashmap_borrow(64);

    if (!fallback_dirs || !fallback_dir_profiles) {
        if (fallback_dirs) hashmap_free(fallback_dirs, NULL);
        if (fallback_dir_profiles) hashmap_free(fallback_dir_profiles, NULL);
        return ERROR(ERR_MEMORY, "Failed to create fallback hashmaps");
    }

    /* Allocate array to track loaded metadata (for proper cleanup) */
    loaded_metadata = malloc(remaining_enabled->count * sizeof(metadata_t *));
    if (!loaded_metadata) {
        hashmap_free(fallback_dirs, NULL);
        hashmap_free(fallback_dir_profiles, NULL);
        return ERROR(ERR_MEMORY, "Failed to allocate metadata array");
    }

    /* Load metadata from each profile and build index with "last wins" precedence */
    for (size_t i = 0; i < remaining_enabled->count; i++) {
        const char *profile = remaining_enabled->items[i];
        metadata_t *metadata = NULL;

        /* Load metadata (may not exist for old profiles - gracefully skip) */
        err = metadata_load_from_branch(repo, profile, &metadata);
        if (err) {
            if (err->code == ERR_NOT_FOUND) {
                /* No metadata file - old profile or no directories tracked */
                error_free(err);
                err = NULL;
                continue;
            }
            /* Other error - fatal */
            err = error_wrap(err, "Failed to load metadata for profile '%s'", profile);
            goto cleanup;
        }

        /* Track loaded metadata for cleanup */
        loaded_metadata[loaded_metadata_count++] = metadata;

        /* Extract directories from metadata */
        size_t meta_dir_count = 0;
        const metadata_item_t **directories =
            metadata_get_items_by_kind(metadata, METADATA_ITEM_DIRECTORY, &meta_dir_count);

        /* Add each directory to fallback index (precedence: LAST profile wins)
         *
         * Unconditionally set/update - later profiles override (last wins).
         * This implements the same precedence as:
         *   - File fallback: build_manifest()
         *   - Metadata merge: metadata_merge()
         *
         * Precedence order: global < OS < host (see profiles.h)
         * Iteration order: same as precedence (low→high)
         * Result: Later iterations override earlier ones → highest precedence wins
         */
        for (size_t j = 0; j < meta_dir_count; j++) {
            const metadata_item_t *dir_item = directories[j];
            const char *storage_path = dir_item->key;  /* Storage path (portable) */

            /* Unconditionally set/update - later profiles override (last wins) */
            hashmap_set(fallback_dirs, storage_path, (void *) dir_item);
            hashmap_set(fallback_dir_profiles, storage_path, (void *) profile);
        }

        /* Free the pointer array (items themselves are owned by metadata) */
        free(directories);
    }

    /* Success - transfer ownership to caller */
    *out_fallback_dirs = fallback_dirs;
    *out_fallback_profiles = fallback_dir_profiles;
    *out_loaded_metadata = loaded_metadata;
    *out_loaded_count = loaded_metadata_count;
    return NULL;

cleanup:
    if (fallback_dirs) hashmap_free(fallback_dirs, NULL);
    if (fallback_dir_profiles) hashmap_free(fallback_dir_profiles, NULL);
    if (loaded_metadata) {
        for (size_t i = 0; i < loaded_metadata_count; i++) {
            metadata_free(loaded_metadata[i]);
        }
        free(loaded_metadata);
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
 *      - If found in fallback: update source (deployed_at preserved)
 *      - If not found: entry remains for orphan detection (apply removes)
 */
error_t *manifest_disable_profile(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *remaining_enabled,
    manifest_disable_stats_t *out_stats
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
    hashmap_t *prefix_map = NULL;
    metadata_t *fallback_metadata = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* Track stats for output */
    size_t total_files = 0;
    size_t fallback_count = 0;
    size_t removed_count = 0;

    /* 1. Get all entries from disabled profile */
    err = state_get_entries_by_profile(state, profile_name, arena, &entries, &count);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to get entries for profile '%s'", profile_name);
    }

    if (count == 0) {
        /* No entries, nothing to do */
        arena_destroy(arena);
        return NULL;
    }

    /* 2. Build manifest from remaining profiles (fallback check) */
    if (remaining_enabled->count > 0) {
        err = state_get_prefix_map(state, &prefix_map);
        if (err) {
            arena_destroy(arena);
            return error_wrap(err, "Failed to get custom prefix map");
        }
        err = build_manifest(
            repo, remaining_enabled, prefix_map, arena, &fallback_manifest,
            &fallback_profiles
        );
        if (err) {
            hashmap_free(prefix_map, free);
            arena_destroy(arena);
            return error_wrap(err, "Failed to build fallback manifest");
        }
    }

    /* Load merged metadata from remaining profiles for fallback resolution
     *
     * When files fall back to lower-precedence profiles, we need their metadata
     * (.dotta/metadata.json) to correctly set mode, owner, group, encrypted.
     *
     * This is the authoritative source for file metadata - NOT the Git tree.
     * Git tree provides basic type and default permissions, but metadata.json
     * contains the user's explicit intent (custom mode, ownership, encryption).
     *
     * Pattern: Same as manifest_sync_diff, manifest_add_files, manifest_update_files.
     * All operations that handle fallbacks use this metadata-loading pattern.
     */
    if (remaining_enabled->count > 0) {
        err = metadata_load_from_profiles(repo, remaining_enabled, &fallback_metadata);
        if (err && err->code != ERR_NOT_FOUND) {
            /* Fatal error - cannot proceed without metadata for correctness */
            goto cleanup;
        }
        if (err) {
            /* Non-fatal: Old profiles may not have metadata.json
             * sync_entry_to_state handles NULL metadata gracefully (uses Git defaults) */
            error_free(err);
            err = NULL;
        }
    }

    /* 3. Process each entry */
    for (size_t i = 0; i < count; i++) {
        state_file_entry_t *entry = &entries[i];
        total_files++;

        /* Check for fallback in remaining profiles using O(1) index lookup */
        file_entry_t *fallback = NULL;
        if (fallback_manifest && fallback_manifest->index) {
            void *idx_ptr = hashmap_get(fallback_manifest->index, entry->filesystem_path);
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                fallback = &fallback_manifest->entries[idx];
            }
        }

        if (fallback) {
            /* File exists in lower-precedence profile — update to fallback.
             * deployed_at preserved by SQL UPSERT (lifecycle history unchanged),
             * old_profile auto-captured by SQL (profile is changing). */
            err = sync_entry_to_state(repo, state, fallback, fallback_metadata, 0, NULL);
            if (err) {
                err = error_wrap(
                    err, "Failed to sync entry to fallback for %s",
                    entry->storage_path
                );
                goto cleanup;
            }

            /* Track profile reassignment (old_profile metadata) */
            fallback_count++;
        } else {
            /* No fallback - mark as inactive (staged for removal)
             *
             * ARCHITECTURE: Separation of concerns for orphan cleanup.
             *
             * The entry is marked STATE_INACTIVE and remains in state for orphan detection:
             *   1. Entry marked inactive with profile=<disabled_profile_name>
             *   2. Workspace skips inactive entries during manifest building (no Git validation)
             *   3. Workspace orphan detection loads inactive entries → marks as ORPHANED
             *   4. Apply removes: file from filesystem + entry from state
             *
             * This design enables:
             *   - Silent handling: No false warnings during workspace operations
             *   - Safe re-enable: Profile can be re-enabled (marks active again)
             *   - Orphan detection: Workspace analysis detects for cleanup
             *   - User visibility: Status shows orphans before removal
             *   - Explicit action: User runs apply to execute destructive cleanup
             *
             * The state field makes the lifecycle explicit:
             *   STATE_ACTIVE → file should exist in Git (validate)
             *   STATE_INACTIVE → file staged for removal (skip validation)
             *
             * This follows the Git staging model:
             *   profile disable = git rm (staging)
             *   apply = git commit (execution)
             *
             * Cleanup deferred to apply - DO NOT call state_remove_file() here.
             */

            /* Mark entry as inactive for silent workspace handling */
            err = state_set_file_state(state, entry->filesystem_path, STATE_INACTIVE);
            if (err) {
                /* Non-fatal: log warning but continue. Even if marking fails,
                 * orphan detection still works (Git validation warning will appear,
                 * but orphan will be detected and can be cleaned up). */
                fprintf(
                    stderr, "warning: failed to mark '%s' as inactive: %s\n",
                    entry->filesystem_path, error_message(err)
                );
                error_free(err);
                err = NULL;  /* Clear error, continue operation */
            }

            removed_count++;  /* Stats: file marked for removal (user visibility) */
        }
    }

    /* Populate output stats if requested */
    if (out_stats) {
        out_stats->total_files = total_files;
        out_stats->files_with_fallback = fallback_count;
        out_stats->files_removed = removed_count;
    }

    /* 4. Process directories from disabled profile (mirrors file handling above)
     *
     * CRITICAL ARCHITECTURE CHANGE: Use incremental fallback/orphan pattern instead
     * of rebuild pattern to preserve orphan detection.
     *
     * Iterate directories from disabled profile, find fallback in remaining profiles,
     * update to fallback OR leave for orphan detection. Deferred cleanup via apply.
     */

    /* 4a. Get directories from disabled profile */
    state_directory_entry_t *dir_entries = NULL;
    size_t dir_count = 0;
    hashmap_t *fallback_dirs = NULL;          /* storage_path -> metadata_item_t* */
    hashmap_t *fallback_dir_profiles = NULL;  /* storage_path -> profile_name */
    metadata_t **loaded_metadata = NULL;      /* Array of loaded metadata (for cleanup) */
    size_t loaded_metadata_count = 0;

    err = state_get_directories_by_profile(state, profile_name, arena, &dir_entries, &dir_count);
    if (err) {
        goto directory_cleanup;
    }

    /* Early exit: no directories in this profile */
    if (dir_count == 0) {
        goto directory_cleanup;
    }

    /* 4b. Build fallback directory index from remaining enabled profiles
     *
     * Uses helper function that implements "last wins" precedence (matching file
     * fallback pattern). See build_directory_fallback_index() for details.
     */
    err = build_directory_fallback_index(
        repo, remaining_enabled, &fallback_dirs, &fallback_dir_profiles,
        &loaded_metadata, &loaded_metadata_count
    );
    if (err) {
        err = error_wrap(err, "Failed to build directory fallback index");
        goto directory_cleanup;
    }

    /* 4c. Process each directory entry */
    size_t dir_fallback_count = 0;
    size_t dir_removed_count = 0;

    for (size_t i = 0; i < dir_count; i++) {
        state_directory_entry_t *entry = &dir_entries[i];

        /* Check for fallback in remaining profiles using O(1) index lookup
         * IMPORTANT: Hashmap is indexed by storage_path (portable), not filesystem_path */
        const metadata_item_t *fallback = hashmap_get(fallback_dirs, entry->storage_path);
        const char *fallback_profile = hashmap_get(fallback_dir_profiles, entry->storage_path);

        if (fallback && fallback_profile) {
            /* Directory exists in lower-precedence profile - update to fallback.
             *
             * entry->{profile,owner,group,storage_path} were allocated from the
             * function-local arena by state_get_directories_by_profile(). We
             * overwrite them with fresh arena_strdup() pointers — the old
             * pointers leak into the arena and are reclaimed wholesale by
             * arena_destroy() at function exit. state_update_directory() binds
             * with SQLITE_TRANSIENT, so SQLite copies the strings immediately. */
            entry->profile = arena_strdup(arena, fallback_profile);
            if (!entry->profile) {
                err = ERROR(ERR_MEMORY, "Failed to allocate fallback profile name");
                goto directory_cleanup;
            }

            /* Update metadata from fallback */
            entry->mode = fallback->mode;

            /* owner and group may legitimately be NULL for non-root/ directories.
             * Skip the strdup in that case to keep the NULL semantics intact —
             * arena_strdup(NULL) returns NULL (same as OOM), so a NULL return
             * can't be distinguished from failure without this explicit check. */
            if (fallback->owner) {
                entry->owner = arena_strdup(arena, fallback->owner);
                if (!entry->owner) {
                    err = ERROR(ERR_MEMORY, "Failed to allocate fallback owner");
                    goto directory_cleanup;
                }
            } else {
                entry->owner = NULL;
            }

            if (fallback->group) {
                entry->group = arena_strdup(arena, fallback->group);
                if (!entry->group) {
                    err = ERROR(ERR_MEMORY, "Failed to allocate fallback group");
                    goto directory_cleanup;
                }
            } else {
                entry->group = NULL;
            }

            entry->storage_path = arena_strdup(arena, fallback->key);
            if (!entry->storage_path) {
                err = ERROR(ERR_MEMORY, "Failed to allocate fallback storage path");
                goto directory_cleanup;
            }

            /* Update in state (preserves deployed_at) */
            err = state_update_directory(state, entry);
            if (err) {
                err = error_wrap(
                    err, "Failed to update directory to fallback for %s",
                    entry->filesystem_path
                );
                goto directory_cleanup;
            }

            dir_fallback_count++;
        } else {
            /* No fallback - mark as inactive (staged for removal)
             *
             * ARCHITECTURE: Explicit state tracking for directory lifecycle.
             *
             * The entry is marked STATE_INACTIVE and remains in state:
             *   1. Entry marked inactive with profile=<disabled_profile_name>
             *   2. Workspace skips inactive entries during manifest building
             *   3. Workspace orphan detection loads inactive entries → ORPHANED
             *   4. Apply removes: directory from filesystem + entry from state
             *
             * The state field makes the lifecycle explicit:
             *   STATE_ACTIVE → directory should exist (check divergence)
             *   STATE_INACTIVE → directory staged for removal (skip validation)
             */
            err = state_set_directory_state(state, entry->filesystem_path, STATE_INACTIVE);
            if (err) {
                /* Non-fatal: log warning but continue. Even if marking fails,
                 * orphan detection will still work (directory won't be in merged_metadata).
                 * The explicit state just makes it cleaner. */
                error_t *wrapped = error_wrap(
                    err, "Failed to mark directory '%s' as inactive",
                    entry->filesystem_path
                );
                fprintf(stderr, "Warning: %s\n", error_message(wrapped));
                error_free(wrapped);  /* Frees wrapped + chained cause (err) */
                err = NULL;
            }
            dir_removed_count++;  /* Stats: directory marked for removal (user visibility) */
        }
    }

    /* Populate directory stats if requested */
    if (out_stats) {
        out_stats->directories_with_fallback = dir_fallback_count;
        out_stats->directories_removed = dir_removed_count;
    }

directory_cleanup:
    /* Free directory-specific resources */
    if (fallback_dirs) hashmap_free(fallback_dirs, NULL);                  /* Values are borrowed */
    if (fallback_dir_profiles) hashmap_free(fallback_dir_profiles, NULL);  /* Values are borrowed */

    /* Free loaded metadata */
    if (loaded_metadata) {
        for (size_t i = 0; i < loaded_metadata_count; i++) {
            metadata_free(loaded_metadata[i]);
        }
        free(loaded_metadata);
    }

cleanup:
    if (prefix_map) hashmap_free(prefix_map, free);
    if (fallback_metadata) metadata_free(fallback_metadata);
    if (fallback_profiles) profile_list_free(fallback_profiles);
    if (fallback_manifest) manifest_free(fallback_manifest);
    arena_destroy(arena);
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
 *   2. Build profile→oid map for commit_oid field
 *   3. For each removed file:
 *      a. Resolve to filesystem path
 *      b. Lookup current manifest entry
 *      c. Check if removed profile owns it (precedence check)
 *      d. If yes:
 *         - Check fresh manifest for fallback
 *         - Fallback exists: Update to fallback profile (deployed_at preserved)
 *         - No fallback: Entry remains for orphan detection (apply removes)
 *      e. If no (different profile owns): Skip
 *
 * Preconditions:
 *   - state MUST have active transaction
 *   - Git commit MUST be completed (files removed from branch)
 *   - removed_storage_paths MUST be in storage format (home/.bashrc)
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - Files with fallback updated to fallback profile (deployed_at preserved)
 *   - Files without fallback: entries remain for orphan detection (apply removes)
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
 * @param out_removed Output: files without fallback (entries remain for orphan detection) (can be NULL)
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
    hashmap_t *prefix_map = NULL;
    metadata_t *metadata = NULL;
    size_t removed_count = 0;
    size_t fallback_count = 0;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Build fresh manifest from current Git state (post-removal) */
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to get custom prefix map");
    }
    err = build_manifest(
        repo, enabled_profiles, prefix_map, arena, &fresh_manifest, &profiles
    );
    if (err) {
        hashmap_free(prefix_map, free);
        arena_destroy(arena);
        return error_wrap(
            err, "Failed to build manifest for fallback detection"
        );
    }

    /* Defensive: build_manifest should always set outputs on success */
    if (!fresh_manifest || !profiles) {
        err = ERROR(
            ERR_INTERNAL, "build_manifest succeeded but returned NULL outputs"
        );
        goto cleanup;
    }

    /* 2. Load merged metadata from enabled profiles for fallback resolution
     *
     * Pattern: Same as manifest_disable_profile, manifest_sync_diff.
     * Metadata is authoritative for mode, owner, group, encrypted fields.
     * sync_entry_to_state uses this to correctly populate fallback entries.
     */
    err = metadata_load_from_profiles(repo, enabled_profiles, &metadata);
    if (err && err->code != ERR_NOT_FOUND) {
        err = error_wrap(err, "Failed to load metadata");
        goto cleanup;
    }
    if (err) {
        /* Non-fatal: Old profiles may not have metadata.json
         * sync_entry_to_state handles NULL metadata gracefully (uses Git defaults) */
        error_free(err);
        err = NULL;
    }

    /* 3. Lookup custom prefix for the removed profile (prefix_map already loaded above) */
    const char *removed_profile_custom_prefix =
        prefix_map ? (const char *) hashmap_get(prefix_map, removed_profile) : NULL;

    /* 4. Process each removed file */
    for (size_t i = 0; i < removed_storage_paths->count; i++) {
        const char *storage_path = removed_storage_paths->items[i];
        const char *custom_prefix = removed_profile_custom_prefix;

        /* Resolve to filesystem path with appropriate prefix */
        char *filesystem_path = NULL;
        err = path_from_storage(storage_path, custom_prefix, &filesystem_path);
        if (err) {
            err = error_wrap(
                err, "Failed to resolve path: %s",
                storage_path
            );
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
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                fallback = &fresh_manifest->entries[idx];
            }
        }

        if (fallback) {
            /* Fallback found — sync complete entry from fallback profile.
             * deployed_at preserved by SQL UPSERT, old_profile auto-captured
             * by SQL when the owning profile changes. */
            err = sync_entry_to_state(repo, state, fallback, metadata, 0, NULL);
            if (err) {
                state_free_entry(current_entry);
                free(filesystem_path);
                err = error_wrap(
                    err, "Failed to sync fallback for %s",
                    filesystem_path
                );
                goto cleanup;
            }

            /* Track profile reassignment (old_profile metadata) */
            fallback_count++;
        } else {
            /* No fallback - mark as deleted (controlled deletion)
             *
             * Entry marked STATE_DELETED (controlled deletion via remove command)
             * and remains in state for orphan detection.
             *
             * STATE_DELETED bypasses branch existence checks in safety module,
             * since user intent is unambiguous (explicit remove command).
             *
             * The orphan cleanup flow:
             *   1. Entry marked deleted (this function)
             *   2. Workspace skips removal-pending entries (no Git validation)
             *   3. Workspace orphan detection loads entries → marks as ORPHANED
             *   4. Apply removes (filesystem + state cleanup)
             *
             * Cleanup deferred to apply - DO NOT call state_remove_file() here.
             */

            /* Mark entry as deleted for controlled deletion */
            err = state_set_file_state(state, filesystem_path, STATE_DELETED);
            if (err) {
                /* Non-fatal: log warning but continue */
                fprintf(
                    stderr, "warning: failed to mark '%s' as deleted: %s\n",
                    filesystem_path, error_message(err)
                );
                error_free(err);
                err = NULL;  /* Clear error, continue operation */
            }

            removed_count++;
        }

        state_free_entry(current_entry);
        free(filesystem_path);
    }

    /* Set output counts */
    if (out_removed) *out_removed = removed_count;
    if (out_fallbacks) *out_fallbacks = fallback_count;

    /* After removing files, the profile's branch HEAD has moved to a new commit.
     * Update the per-profile commit_oid in enabled_profiles. */
    const git_oid *head_oid = profile_list_head_oid(profiles, removed_profile);
    if (!head_oid) {
        err = ERROR(
            ERR_INTERNAL,
            "Profile '%s' not found in loaded profile list", removed_profile
        );
        goto cleanup;
    }
    err = state_set_profile_commit_oid(state, removed_profile, head_oid);
    if (err) {
        err = error_wrap(
            err, "Failed to sync commit_oid for profile '%s'",
            removed_profile
        );
        goto cleanup;
    }

    /* 5. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (metadata) metadata_free(metadata);
    if (prefix_map) hashmap_free(prefix_map, free);
    if (fresh_manifest) manifest_free(fresh_manifest);
    if (profiles) profile_list_free(profiles);
    arena_destroy(arena);

    return err;
}

/**
 * Rebuild manifest from scratch
 *
 * Nuclear option for recovery operations. Clears all manifest state and
 * rebuilds from Git by building a complete manifest once and syncing all
 * entries.
 *
 * Algorithm:
 *   1. Clear all file entries from state
 *   2. Build manifest ONCE from all enabled profiles (precedence oracle)
 *   3. Build profile→oid map for commit_oid field
 *   4. Load merged metadata from all profiles
 *   5. Sync ALL entries from manifest to state (single pass, no filtering)
 *   6. Sync tracked directories
 *
 * Performance: O(M) where M = total files across all enabled profiles
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
    manifest_t *manifest = NULL;
    profile_list_t *profiles = NULL;
    hashmap_t *prefix_map = NULL;
    state_file_entry_t *old_entries = NULL;
    size_t old_count = 0;
    hashmap_t *old_map = NULL;
    metadata_t *metadata = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Snapshot existing entries BEFORE clearing (for deployed_at preservation) */
    err = state_get_all_files(state, arena, &old_entries, &old_count);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to snapshot manifest for rebuild");
    }

    /* Build hashmap for O(1) old entry lookups */
    old_map = hashmap_borrow(old_count > 0 ? old_count : 16);
    if (!old_map) {
        arena_destroy(arena);
        return ERROR(ERR_MEMORY, "Failed to create old entries hashmap");
    }

    for (size_t i = 0; i < old_count; i++) {
        err = hashmap_set(old_map, old_entries[i].filesystem_path, &old_entries[i]);
        if (err) {
            err = error_wrap(err, "Failed to populate old entries hashmap");
            hashmap_free(old_map, NULL);  /* Don't free values - they're in old_entries */
            arena_destroy(arena);
            return err;
        }
    }

    /* 2. Clear all file entries (snapshot is independent) */
    err = state_clear_files(state);
    if (err) {
        err = error_wrap(err, "Failed to clear manifest for rebuild");
        goto cleanup;
    }

    /* Early exit if no profiles (only sync directories which will be empty) */
    if (enabled_profiles->count == 0) {
        err = manifest_sync_directories(repo, state, enabled_profiles);
        goto cleanup;
    }

    /* 3. Build manifest ONCE from all enabled profiles (precedence oracle) */
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        err = error_wrap(err, "Failed to get custom prefix map");
        goto cleanup;
    }
    err = build_manifest(
        repo, enabled_profiles, prefix_map, arena, &manifest, &profiles
    );
    if (err) {
        err = error_wrap(err, "Failed to build manifest for rebuild");
        goto cleanup;
    }

    /* Defensive: build_manifest should always set outputs on success */
    if (!manifest || !profiles) {
        err = ERROR(
            ERR_INTERNAL, "build_manifest succeeded but returned NULL outputs"
        );
        goto cleanup;
    }

    /* 4. Load merged metadata from all profiles */
    err = metadata_load_from_profiles(repo, enabled_profiles, &metadata);
    if (err) {
        /* Metadata may not exist for old profiles - continue with NULL */
        if (err->code != ERR_NOT_FOUND) {
            goto cleanup;
        }
        error_free(err);
        err = NULL;
    }

    /* 5. Sync ALL entries from manifest to state (single pass, no filtering)
     *
     * Key difference from manifest_enable_profile: We sync ALL entries because
     * the state is empty (cleared in step 1). No filtering needed - every file
     * in the manifest belongs in the rebuilt state. */
    for (size_t i = 0; i < manifest->count; i++) {
        file_entry_t *entry = &manifest->entries[i];

        /* Check if entry existed before rebuild (preserve deployed_at for lifecycle tracking) */
        state_file_entry_t *old_entry = hashmap_get(old_map, entry->filesystem_path);

        time_t deployed_at;
        if (old_entry) {
            /* Existing entry - preserve deployed_at (lifecycle history) */
            deployed_at = old_entry->deployed_at;
        } else {
            /* New entry - check filesystem for initial deployed_at value */
            struct stat st;
            if (lstat(entry->filesystem_path, &st) == 0) {
                /* File exists - mark as known to dotta */
                deployed_at = time(NULL);
            } else {
                /* File doesn't exist - mark as never deployed */
                deployed_at = 0;
            }
        }

        /* Sync to state with preserved/computed deployed_at */
        err = sync_entry_to_state(repo, state, entry, metadata, deployed_at, NULL);
        if (err) goto cleanup;
    }

    /* 6. Record each profile's current HEAD in enabled_profiles.commit_oid.
     *
     * Uses the already-loaded profile_list_t to avoid redundant ref lookups.
     * This replaces the zero sentinel that state_set_profiles wrote for new
     * profiles (clone path) and refreshes the value for existing profiles. */
    for (size_t p = 0; p < profiles->count; p++) {
        err = state_set_profile_commit_oid(
            state, profiles->profiles[p].name, &profiles->profiles[p].head_oid
        );
        if (err) {
            err = error_wrap(
                err, "Failed to set commit_oid for profile '%s'",
                profiles->profiles[p].name
            );
            goto cleanup;
        }
    }

    /* 7. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (old_map) hashmap_free(old_map, NULL);
    if (prefix_map) hashmap_free(prefix_map, free);
    if (profiles) profile_list_free(profiles);
    if (metadata) metadata_free(metadata);
    if (manifest) manifest_free(manifest);
    arena_destroy(arena);

    return err;
}

/**
 * Detect which enabled profiles have stale manifest entries
 *
 * Iterates in-scope profiles and compares each profile's stored commit_oid
 * (from enabled_profiles) against its branch's current HEAD. Mismatch means
 * external Git operations occurred since the last dotta operation.
 *
 * HEAD OID source: profile_scope values are optional profile_t * pointers.
 * When non-NULL, the cached profile->head_oid is used directly (zero Git
 * calls). When NULL, the function resolves the branch HEAD via ref lookup.
 *
 * O(P) state queries + O(P) ref lookups where P = profile count.
 * Zero ref lookups when profile_scope values carry loaded profile_t *.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (must not be NULL)
 * @param profile_scope Profile scope filter (must not be NULL). Keys are
 *                      in-scope profile names; values are profile_t * with
 *                      cached head_oid (fast path) or NULL (ref lookup fallback).
 * @param out_stale Output: hashmap of profile_name -> (void*)1 sentinel for
 *                  stale profiles. NULL if none stale. Caller frees with
 *                  hashmap_free(map, NULL).
 * @return Error or NULL on success
 */
error_t *manifest_detect_stale_profiles(
    git_repository *repo,
    const state_t *state,
    const hashmap_t *profile_scope,
    hashmap_t **out_stale
) {
    *out_stale = NULL;

    error_t *err = NULL;
    hashmap_t *stale_map = NULL;

    /* Iterate profile_scope keys — one check per profile, no dedup needed. */
    hashmap_iter_t iter;
    hashmap_iter_init(&iter, profile_scope);

    const char *name;
    while (hashmap_iter_next(&iter, &name, NULL)) {
        /* Read stored commit_oid for this profile */
        git_oid stored_oid;
        error_t *read_err = state_get_profile_commit_oid(state, name, &stored_oid);
        if (read_err) {
            if (read_err->code == ERR_NOT_FOUND) {
                /* Profile in scope but not in DB (race with disable) — skip */
                error_free(read_err);
                continue;
            }
            hashmap_free(stale_map, NULL);
            return read_err;
        }

        /* Fetch current branch HEAD via lightweight ref-to-OID lookup.
         *
         * profile_scope is a name-only membership set (NULL values) — both
         * callers (workspace and manifest_repair_stale) pass name sets, not
         * loaded profile_t objects. */
        git_oid head_oid;
        err = get_branch_head_oid(repo, name, &head_oid);
        if (err) {
            /* Branch may have been deleted — skip (safety handles this) */
            error_free(err);
            err = NULL;
            continue;
        }

        if (!git_oid_equal(&stored_oid, &head_oid)) {
            /* Profile is stale — HEAD moved since last dotta operation */
            if (!stale_map) {
                stale_map = hashmap_borrow(16);
                if (!stale_map) {
                    return ERROR(ERR_MEMORY, "Failed to create stale profile map");
                }
            }

            err = hashmap_set(stale_map, name, (void *) (uintptr_t) 1);
            if (err) {
                hashmap_free(stale_map, NULL);
                return err;
            }
        }
    }

    *out_stale = stale_map;
    return NULL;
}

/**
 * Repair stale manifest entries from external Git changes
 *
 * Persistent repair: detects state entries whose commit_oid no longer matches
 * the profile branch HEAD, then either updates them from fresh Git state
 * or marks them STATE_RELEASED for release.
 *
 * Complements workspace's in-memory patching. After this function runs,
 * workspace_load() sees accurate state with zero staleness overhead.
 */
error_t *manifest_repair_stale(
    git_repository *repo,
    state_t *state,
    const string_array_t *enabled_profiles,
    manifest_repair_stats_t *out_stats,
    hashmap_t **out_repaired_paths
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(out_stats);

    memset(out_stats, 0, sizeof(*out_stats));
    if (out_repaired_paths) {
        *out_repaired_paths = NULL;
    }

    error_t *err = NULL;
    size_t all_count = 0;
    state_file_entry_t *all_entries = NULL;
    hashmap_t *profile_scope = NULL;
    hashmap_t *stale_profiles = NULL;
    hashmap_t *prefix_map = NULL;
    manifest_t *fresh_manifest = NULL;
    profile_list_t *fresh_profiles = NULL;
    hashmap_t *repaired_paths = NULL;
    metadata_t *metadata = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* Phase 1: Detect stale profiles via per-profile commit_oid comparison.
     *
     * O(P) state queries + O(P) ref lookups. If no profile is stale, exits
     * immediately without loading file entries (zero cost common case). */
    profile_scope = hashmap_borrow(enabled_profiles->count);
    if (!profile_scope) {
        err = ERROR(ERR_MEMORY, "Failed to create profile scope map");
        goto cleanup;
    }
    for (size_t i = 0; i < enabled_profiles->count; i++) {
        err = hashmap_set(profile_scope, enabled_profiles->items[i], NULL);
        if (err) goto cleanup;
    }

    err = manifest_detect_stale_profiles(
        repo, state, profile_scope, &stale_profiles
    );
    if (err) {
        err = error_wrap(err, "Failed to detect stale profiles");
        goto cleanup;
    }

    if (!stale_profiles) {
        goto cleanup;  /* All profiles current — nothing to repair */
    }

    /* Load all state entries for Phase 3 repair loop. Only loaded when
     * staleness is detected — common case (no staleness) pays zero cost. */
    err = state_get_all_files(state, arena, &all_entries, &all_count);
    if (err) {
        err = error_wrap(err, "Failed to load state entries for stale repair");
        goto cleanup;
    }

    /* Create repaired_paths map if caller wants it */
    if (out_repaired_paths) {
        repaired_paths = hashmap_create(64);
        if (!repaired_paths) {
            err = ERROR(ERR_MEMORY, "Failed to create repaired paths map");
            goto cleanup;
        }
    }

    /* Phase 2: Build fresh manifest from current Git state.
     * This gives us the ground truth for what files should exist. */
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        err = error_wrap(err, "Failed to get custom prefix map");
        goto cleanup;
    }
    err = build_manifest(
        repo, enabled_profiles, prefix_map, arena, &fresh_manifest, &fresh_profiles
    );
    if (err) {
        err = error_wrap(err, "Failed to build fresh manifest for stale repair");
        goto cleanup;
    }

    /* Load merged metadata from all enabled profiles */
    err = metadata_load_from_profiles(repo, enabled_profiles, &metadata);
    if (err) {
        if (err->code != ERR_NOT_FOUND) {
            goto cleanup;
        }
        /* Old profiles without metadata — proceed with NULL */
        error_free(err);
        err = NULL;
    }

    /* Phase 3: Process ACTIVE state entries from stale profiles.
     *
     * Single pass over pre-loaded entries, filtering by stale_profiles map.
     * For each entry: compare against fresh manifest to determine update
     * (file still in Git) or release (file removed from Git externally).
     */
    for (size_t i = 0; i < all_count; i++) {
        state_file_entry_t *entry = &all_entries[i];

        /* Only repair ACTIVE entries from stale profiles */
        if (!entry->state || strcmp(entry->state, STATE_ACTIVE) != 0) {
            continue;
        }
        if (!entry->profile || !hashmap_get(stale_profiles, entry->profile)) {
            continue;
        }

        /* Look up in fresh manifest (O(1) index lookup) */
        file_entry_t *fresh_entry = NULL;
        if (fresh_manifest && fresh_manifest->index) {
            void *idx_ptr = hashmap_get(fresh_manifest->index, entry->filesystem_path);
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                fresh_entry = &fresh_manifest->entries[idx];
            }
        }

        if (fresh_entry) {
            /* File still in Git (same or different profile via fallback).
             *
             * Use sync_entry_to_state to update with current Git truth.
             * Preserve deployed_at — the file's lifecycle history is unchanged,
             * only the expected state cache needs updating.
             */

            /* Determine if file content actually changed (blob_oid differs).
             *
             * A profile HEAD can move without changing this file's blob
             * (other files in the commit changed). Distinguishing content
             * changes from HEAD-only refreshes enables:
             *   - Accurate repaired_paths (Path B only verifies content-changed files)
             *   - Accurate stats (user sees real content changes, not bookkeeping)
             *
             * Mirrors the blob_changed check in workspace_build_manifest_from_state()
             * (Path A) for symmetric treatment across both staleness paths.
             */
            bool blob_changed = !git_oid_equal(&entry->blob_oid, &fresh_entry->blob_oid);

            /* Save old blob_oid for content-changed entries BEFORE updating.
             *
             * The caller (apply's Path B) uses this to verify that files on disk
             * still match what dotta deployed (old blob), preventing user
             * modifications from being silently overwritten.
             *
             * Only tracked when blob actually changed — unchanged-blob entries
             * won't trigger DIVERGENCE_CONTENT in workspace, so Path B's
             * content-divergence guard would skip them anyway.
             */
            if (repaired_paths && blob_changed) {
                /* Heap-allocate a standalone git_oid: the map outlives this arena
                 * (it escapes to apply.c) and hashmap_free(..., free) releases it. */
                git_oid *old_blob = malloc(sizeof(git_oid));
                if (!old_blob) {
                    err = ERROR(ERR_MEMORY, "Failed to save old blob_oid");
                    goto cleanup;
                }
                git_oid_cpy(old_blob, &entry->blob_oid);
                err = hashmap_set(repaired_paths, entry->filesystem_path, old_blob);
                if (err) {
                    free(old_blob);
                    goto cleanup;
                }
            }

            /* deployed_at preserved by SQL UPSERT, old_profile auto-captured
             * by SQL when the owning profile shifts during repair. */
            bool profile_shifted = strcmp(fresh_entry->profile_name, entry->profile) != 0;

            err = sync_entry_to_state(repo, state, fresh_entry, metadata, 0, NULL);
            if (err) {
                err = error_wrap(
                    err, "Failed to repair stale entry '%s'",
                    entry->storage_path
                );
                goto cleanup;
            }

            /* Track profile reassignment when owning profile shifts during repair */
            if (profile_shifted) {
                out_stats->reassigned++;
            }

            if (blob_changed) {
                out_stats->updated++;
            } else {
                out_stats->refreshed++;
            }
        } else {
            /* File removed from all enabled profiles — loss of authority.
             *
             * Mark STATE_RELEASED so the orphan→safety→cleanup pipeline releases
             * it (leaves file on filesystem, removes state entry).
             *
             * Do NOT remove the state entry here — the full pipeline ensures
             * user visibility and safety checks before any cleanup.
             */
            err = state_set_file_state(state, entry->filesystem_path, STATE_RELEASED);
            if (err) {
                err = error_wrap(
                    err, "Failed to mark '%s' as stale",
                    entry->storage_path
                );
                goto cleanup;
            }

            out_stats->released++;
        }
    }

    /* Phase 4: Update stored commit_oid for each repaired profile.
     *
     * fresh_profiles carries the current HEAD OID for each enabled profile
     * (loaded by build_manifest via profile_list_load). Use it directly
     * instead of re-resolving the same refs. */
    hashmap_iter_t stale_iter;
    hashmap_iter_init(&stale_iter, stale_profiles);

    const char *stale_name;
    while (hashmap_iter_next(&stale_iter, &stale_name, NULL)) {
        const git_oid *head_oid = profile_list_head_oid(fresh_profiles, stale_name);
        if (!head_oid) {
            err = ERROR(
                ERR_INTERNAL,
                "Stale profile '%s' not found in loaded profile list", stale_name
            );
            goto cleanup;
        }
        err = state_set_profile_commit_oid(state, stale_name, head_oid);
        if (err) {
            err = error_wrap(
                err, "Failed to sync commit_oid for repaired profile '%s'",
                stale_name
            );
            goto cleanup;
        }
    }

    /* Phase 5: Sync tracked directories to reflect current Git state.
     *
     * External Git changes may have added/removed directories in metadata.
     * Re-syncing ensures the tracked_directories table is consistent. */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        err = error_wrap(err, "Failed to sync directories after stale repair");
        goto cleanup;
    }

    /* Transfer repaired_paths ownership to caller on success */
    if (out_repaired_paths && repaired_paths) {
        *out_repaired_paths = repaired_paths;
        repaired_paths = NULL;  /* Prevent cleanup from freeing */
    }

cleanup:
    if (stale_profiles) hashmap_free(stale_profiles, NULL);
    if (profile_scope) hashmap_free(profile_scope, NULL);
    if (prefix_map) hashmap_free(prefix_map, free);
    if (fresh_profiles) profile_list_free(fresh_profiles);
    if (metadata) metadata_free(metadata);
    if (fresh_manifest) manifest_free(fresh_manifest);
    if (repaired_paths) hashmap_free(repaired_paths, free);
    arena_destroy(arena);

    return err;
}

/**
 * Update manifest after profile precedence change
 *
 * Implementation strategy:
 *   1. Build new manifest with precedence oracle
 *   2. Compare with current state to detect reassignments
 *   3. Update only changed files (preserves deployed_at for unchanged)
 *   4. Handle orphaned files (entries remain for orphan detection, apply removes)
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
    hashmap_t *prefix_map = NULL;
    state_file_entry_t *old_entries = NULL;
    size_t old_count = 0;
    hashmap_t *old_map = NULL;
    metadata_t *metadata = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Build new manifest with new precedence order (precedence oracle) */
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to get custom prefix map");
    }
    err = build_manifest(
        repo, new_profile_order, prefix_map, arena, &new_manifest, &profiles
    );
    if (err) {
        hashmap_free(prefix_map, free);
        arena_destroy(arena);
        return error_wrap(err, "Failed to build manifest for precedence update");
    }

    /* Defensive: build_manifest should always set outputs on success */
    if (!new_manifest || !profiles) {
        err = ERROR(ERR_INTERNAL, "build_manifest succeeded but returned NULL outputs");
        goto cleanup;
    }

    /* 2. Verify new manifest has index */
    if (!new_manifest->index) {
        err = ERROR(ERR_INTERNAL, "New manifest missing index");
        goto cleanup;
    }

    /* 3. Get all current manifest entries and build hashmap for O(1) lookups */
    err = state_get_all_files(state, arena, &old_entries, &old_count);
    if (err) {
        goto cleanup;
    }

    /* Build hashmap for O(1) old entry lookups */
    old_map = hashmap_borrow(old_count > 0 ? old_count : 16);
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

    /* 4. Load metadata */
    err = metadata_load_from_profiles(repo, new_profile_order, &metadata);
    if (err && err->code != ERR_NOT_FOUND) {
        goto cleanup;
    }
    if (err) {
        error_free(err);
        err = NULL;
    }

    /* 5. Process each file in new manifest */
    for (size_t i = 0; i < new_manifest->count; i++) {
        file_entry_t *new_entry = &new_manifest->entries[i];

        /* Check if exists in old state using O(1) hashmap lookup */
        state_file_entry_t *old_entry = hashmap_get(old_map, new_entry->filesystem_path);

        if (!old_entry) {
            /* New file (rare in reorder, but handle it) */

            /* New file - deployed_at = 0 (never deployed) */
            err = sync_entry_to_state(repo, state, new_entry, metadata, 0, NULL);
            if (err) {
                goto cleanup;
            }
        } else {
            /* Existing entry - check if owner changed */
            bool owner_changed =
                strcmp(old_entry->profile, new_entry->profile_name) != 0;

            if (owner_changed) {
                /* Owner changed — sync with new owner. deployed_at preserved
                 * by SQL UPSERT, old_profile auto-captured by SQL. */
                err = sync_entry_to_state(repo, state, new_entry, metadata, 0, NULL);
                if (err) {
                    goto cleanup;
                }
            }
            /* else: owner unchanged, preserve existing entry */
        }
    }

    /* 6. Check for files in old manifest but not in new (mark for removal) */
    for (size_t i = 0; i < old_count; i++) {
        state_file_entry_t *old_entry = &old_entries[i];

        /* Check if still exists in new manifest using O(1) index lookup */
        void *idx_ptr = hashmap_get(new_manifest->index, old_entry->filesystem_path);
        file_entry_t *new_entry = NULL;
        if (idx_ptr) {
            size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
            new_entry = &new_manifest->entries[idx];
        }

        if (!new_entry) {
            /* File no longer in any profile - entry becomes orphaned
             *
             * Entry remains in state for orphan detection. Profile reordering
             * can cause a file to lose all coverage (all profiles reordered above
             * it, or removed from all profiles).
             *
             * The orphan cleanup flow applies (see manifest_disable_profile()).
             * Cleanup deferred to apply - DO NOT call state_remove_file() here.
             */

            /* Mark entry as inactive for silent workspace handling */
            err = state_set_file_state(state, old_entry->filesystem_path, STATE_INACTIVE);
            if (err) {
                /* Non-fatal: log warning but continue */
                fprintf(
                    stderr, "warning: failed to mark '%s' as inactive: %s\n",
                    old_entry->filesystem_path, error_message(err)
                );
                error_free(err);
                err = NULL;  /* Clear error, continue operation */
            }
        }
    }

    /* 7. Sync tracked directories with new profile order */
    err = manifest_sync_directories(repo, state, new_profile_order);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (old_map) hashmap_free(old_map, NULL);
    if (prefix_map) hashmap_free(prefix_map, free);
    if (profiles) profile_list_free(profiles);
    if (metadata) metadata_free(metadata);
    if (new_manifest) manifest_free(new_manifest);
    arena_destroy(arena);

    return err;
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
 *   4. Build profile→oid map for commit_oid field
 *   5. For each item (O(N)):
 *      - If DELETED: check fresh manifest for fallback
 *        → Fallback exists: update to fallback profile
 *        → No fallback: entry remains for orphan detection (apply removes)
 *      - Else (modified/new): lookup in fresh manifest
 *        → Found + precedence matches: sync to state (deployed_at set based on lstat())
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
 *   - Modified/new files synced with deployed_at set based on lstat()
 *   - Deleted files fallback or entries remain for orphan detection
 *   - Transaction remains open (caller commits)
 *
 * Performance: O(M + N) where M = total files in profiles, N = items to sync
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (with active transaction, must not be NULL)
 * @param items Array of workspace items to sync (must not be NULL)
 * @param item_count Number of items
 * @param enabled_profiles All enabled profiles (must not be NULL)
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
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(items);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(out_synced);
    CHECK_NULL(out_removed);
    CHECK_NULL(out_fallbacks);

    /* Initialize outputs */
    *out_synced = 0;
    *out_removed = 0;
    *out_fallbacks = 0;

    if (item_count == 0) {
        /* No file items to process, but still sync directories.
         * Handles cases where only directory metadata changed. */
        return manifest_sync_directories(repo, state, enabled_profiles);
    }

    error_t *err = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *fresh_manifest = NULL;
    hashmap_t *prefix_map = NULL;
    metadata_t *metadata = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Build FRESH manifest from Git (post-commit state) */
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to get custom prefix map");
    }
    err = build_manifest(
        repo, enabled_profiles, prefix_map, arena, &fresh_manifest, &profiles
    );
    if (err) {
        hashmap_free(prefix_map, free);
        arena_destroy(arena);
        return error_wrap(err, "Failed to build fresh manifest for bulk sync");
    }

    /* 2. Verify manifest has index (should be populated by profile_build_manifest) */
    if (!fresh_manifest->index) {
        err = ERROR(ERR_INTERNAL, "Fresh manifest missing index");
        goto cleanup;
    }

    /* 3. Load fresh merged metadata from Git (post-commit state) */
    err = metadata_load_from_profiles(repo, enabled_profiles, &metadata);
    if (err && err->code != ERR_NOT_FOUND) {
        err = error_wrap(err, "Failed to load metadata for manifest sync");
        goto cleanup;
    }
    if (err) {
        /* Non-fatal: Old profiles may not have metadata.json
         * sync_entry_to_state handles NULL metadata gracefully (uses Git defaults) */
        error_free(err);
        err = NULL;
    }

    /* 4. Process each item */
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
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                fallback = &fresh_manifest->entries[idx];
            }

            if (fallback) {
                /* Fallback found — update manifest to the fallback profile.
                 * deployed_at preserved by SQL UPSERT, old_profile auto-captured
                 * by SQL when the owning profile changes. */
                err = sync_entry_to_state(repo, state, fallback, metadata, 0, NULL);
                if (err) {
                    err = error_wrap(
                        err, "Failed to sync fallback for '%s'",
                        item->filesystem_path
                    );
                    goto cleanup;
                }

                (*out_fallbacks)++;
            } else {
                /* No fallback - mark as inactive (staged for removal)
                 *
                 * Entry marked STATE_INACTIVE and remains in state for orphan detection.
                 * This bulk operation may process multiple files simultaneously, but the
                 * architectural principle remains: deferred cleanup via apply.
                 *
                 * See manifest_disable_profile() for detailed rationale.
                 * Cleanup deferred to apply - DO NOT call state_remove_file() here.
                 */

                /* Mark entry as inactive for silent workspace handling */
                err = state_set_file_state(state, item->filesystem_path, STATE_INACTIVE);
                if (err) {
                    /* Non-fatal: log warning but continue */
                    fprintf(
                        stderr, "warning: failed to mark '%s' as inactive: %s\n",
                        item->filesystem_path, error_message(err)
                    );
                    error_free(err);
                    err = NULL;  /* Clear error, continue operation */
                }

                (*out_removed)++;
            }
        } else {
            /* Handle modified/new file */
            void *idx_ptr = hashmap_get(fresh_manifest->index, item->filesystem_path);
            file_entry_t *entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                entry = &fresh_manifest->entries[idx];
            }

            if (!entry) {
                /* File not in fresh manifest - filtered/excluded
                 * This is expected behavior (e.g., .dottaignore) - skip gracefully */
                continue;
            }

            /* Check precedence matches */
            if (entry->profile_name &&
                strcmp(entry->profile_name, item->profile) != 0) {
                /* Different profile won precedence - skip this file
                 * (higher precedence profile will handle it) */
                continue;
            }

            /* Sync to state with deployed_at = now()
             *
             * Key insight: UPDATE captures files FROM filesystem, so they're
             * already deployed. We set deployed_at to mark them as known. */

            err = sync_entry_to_state(repo, state, entry, metadata, time(NULL), NULL);
            if (err) {
                err = error_wrap(
                    err, "Failed to sync '%s' to manifest",
                    item->filesystem_path
                );
                goto cleanup;
            }

            (*out_synced)++;
        }
    }

    /* 5. After updating files, synchronize commit_oid for ALL files from affected profiles.
     * Each profile that had files updated has a new HEAD commit.
     * Build set of unique profile names from items and sync each. */
    string_array_t *updated_profiles = string_array_new(0);
    if (!updated_profiles) {
        err = ERROR(ERR_MEMORY, "Failed to allocate updated_profiles array");
        goto cleanup;
    }

    for (size_t i = 0; i < item_count; i++) {
        const char *prof = items[i]->profile;

        /* Check if already processed */
        bool found = false;
        for (size_t j = 0; j < updated_profiles->count; j++) {
            if (strcmp(updated_profiles->items[j], prof) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            err = string_array_push(updated_profiles, prof);
            if (err) {
                string_array_free(updated_profiles);
                goto cleanup;
            }
        }
    }

    /* 6. Set stored commit_oid for each profile whose HEAD moved */
    for (size_t i = 0; i < updated_profiles->count; i++) {
        const char *prof = updated_profiles->items[i];
        const git_oid *head_oid = profile_list_head_oid(profiles, prof);
        if (!head_oid) {
            string_array_free(updated_profiles);
            err = ERROR(
                ERR_INTERNAL,
                "Profile '%s' not found in loaded profile list", prof
            );
            goto cleanup;
        }
        err = state_set_profile_commit_oid(state, prof, head_oid);
        if (err) {
            string_array_free(updated_profiles);
            err = error_wrap(err, "Failed to sync commit_oid for profile '%s'", prof);
            goto cleanup;
        }
    }

    string_array_free(updated_profiles);

    /* 7. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (metadata) metadata_free(metadata);
    if (prefix_map) hashmap_free(prefix_map, free);
    if (fresh_manifest) manifest_free(fresh_manifest);
    if (profiles) profile_list_free(profiles);
    arena_destroy(arena);

    return err;
}

/**
 * Sync multiple files to manifest in bulk - simplified for add command
 *
 * Optimized bulk operation for adding newly-committed files to manifest.
 * Simpler than manifest_update_files() because:
 * - All files are from the same profile
 * - No deletions (only additions/updates)
 * - Files marked with deployed_at = time(NULL) (captured from filesystem)
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
 *   4. Build profile→oid map for commit_oid field
 *   5. For each file:
 *      - Convert filesystem_path → storage_path
 *      - Lookup in fresh manifest
 *      - If precedence matches: sync to state with deployed_at = time(NULL)
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
 *   - Files synced to manifest with deployed_at = time(NULL)
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
 * @param out_synced Output: count of files synced (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_add_files(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const string_array_t *filesystem_paths,
    const string_array_t *enabled_profiles,
    size_t *out_synced
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profile_name);
    CHECK_NULL(filesystem_paths);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(out_synced);

    /* Initialize output */
    *out_synced = 0;

    if (filesystem_paths->count == 0) {
        /* No files to add, but still sync directories.
         * Handles directory-only adds where filesystem_paths
         * is empty but metadata.json has tracked directories. */
        return manifest_sync_directories(repo, state, enabled_profiles);
    }

    error_t *err = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *fresh_manifest = NULL;
    hashmap_t *prefix_map = NULL;
    metadata_t *metadata = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Build FRESH manifest from Git (post-commit state) */
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to get custom prefix map");
    }
    err = build_manifest(
        repo, enabled_profiles, prefix_map, arena, &fresh_manifest, &profiles
    );
    if (err) {
        hashmap_free(prefix_map, free);
        arena_destroy(arena);
        return error_wrap(err, "Failed to build fresh manifest for bulk sync");
    }

    /* 2. Verify manifest has index (should be populated by profile_build_manifest) */
    if (!fresh_manifest->index) {
        err = ERROR(ERR_INTERNAL, "Fresh manifest missing index");
        goto cleanup;
    }

    /* 3. Load fresh merged metadata from Git (post-commit state) */
    err = metadata_load_from_profiles(repo, enabled_profiles, &metadata);
    if (err && err->code != ERR_NOT_FOUND) {
        err = error_wrap(err, "Failed to load metadata for manifest sync");
        goto cleanup;
    }
    if (err) {
        /* Non-fatal: Old profiles may not have metadata.json
         * sync_entry_to_state handles NULL metadata gracefully (uses Git defaults) */
        error_free(err);
        err = NULL;
    }

    /* 4. Process each file */
    for (size_t i = 0; i < filesystem_paths->count; i++) {
        const char *filesystem_path = filesystem_paths->items[i];

        /* Lookup in fresh manifest using filesystem_path */
        void *idx_ptr = hashmap_get(fresh_manifest->index, filesystem_path);
        file_entry_t *entry = NULL;
        if (idx_ptr) {
            size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
            entry = &fresh_manifest->entries[idx];
        }

        if (!entry) {
            /* File not in fresh manifest - filtered/excluded
             * This is expected behavior (e.g., .dottaignore, README.md) - skip gracefully */
            continue;
        }

        /* Defensive: Verify entry has profile name (should never be NULL) */
        if (!entry->profile_name) {
            /* Should never happen - indicates data corruption or manifest bug */
            err = ERROR(
                ERR_INTERNAL, "Manifest entry '%s' has NULL profile_name",
                filesystem_path
            );
            goto cleanup;
        }

        /* Check precedence matches */
        if (strcmp(entry->profile_name, profile_name) != 0) {
            /* Different profile won precedence - skip this file
             * (higher precedence profile owns it) */
            continue;
        }

        /* Sync to state with deployed_at = now()
         *
         * Key insight: ADD captures files FROM filesystem, so they're
         * already deployed. We set deployed_at to mark them as known. */

        err = sync_entry_to_state(repo, state, entry, metadata, time(NULL), NULL);

        if (err) {
            err = error_wrap(
                err, "Failed to sync '%s' to manifest",
                filesystem_path
            );
            goto cleanup;
        }

        (*out_synced)++;
    }

    /* After adding files, the profile's branch HEAD has moved to a new commit.
     * Update the per-profile commit_oid in enabled_profiles. */
    const git_oid *head_oid = profile_list_head_oid(profiles, profile_name);
    if (!head_oid) {
        err = ERROR(
            ERR_INTERNAL,
            "Profile '%s' not found in loaded profile list", profile_name
        );
        goto cleanup;
    }
    err = state_set_profile_commit_oid(state, profile_name, head_oid);
    if (err) {
        err = error_wrap(
            err, "Failed to sync commit_oid for profile '%s'",
            profile_name
        );
        goto cleanup;
    }

    /* 5. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (metadata) metadata_free(metadata);
    if (prefix_map) hashmap_free(prefix_map, free);
    if (fresh_manifest) manifest_free(fresh_manifest);
    if (profiles) profile_list_free(profiles);
    arena_destroy(arena);

    return err;
}

/**
 * Sync manifest from Git diff (bulk operation)
 *
 * Updates manifest table based on changes between old_oid and new_oid for a
 * single profile. Uses O(M+D) bulk pattern.
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
 *     - Load merged metadata from Git
 *
 *   Phase 2: Compute Diff
 *     - Lookup old and new trees
 *     - Generate Git diff between them
 *
 *   Phase 3: Process Deltas
 *     - For additions/modifications: sync (deployed_at preserved if exists, else set based on lstat())
 *     - For deletions: check for fallbacks, entries remain for orphan detection if none
 *     - Handle precedence: only sync if profile won the file
 *
 * Transaction: Caller must open transaction (state_load_for_update) and commit
 *              (state_save) after calling. This function works within an active
 *              transaction.
 *
 * Convergence: Sync updates VWD expected state (commit_oid, blob_oid) but doesn't
 * Semantics    deploy to filesystem. User must run 'dotta apply' which uses runtime
 *              divergence analysis to deploy changes.
 *
 * @param repo Repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param profile_name Profile being synced (must not be NULL)
 * @param old_oid Old commit before sync (must not be NULL)
 * @param new_oid New commit after sync (must not be NULL)
 * @param enabled_profiles All enabled profiles for precedence (must not be NULL)
 * @param out_synced Output: number of files synced (can be NULL)
 * @param out_removed Output: number of files removed (can be NULL)
 * @param out_fallbacks Output: number of fallback resolutions (can be NULL)
 * @param out_skipped Output: number of custom/ files skipped due to missing prefix (can be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_sync_diff(
    git_repository *repo,
    state_t *state,
    const char *profile_name,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks,
    size_t *out_skipped
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
    hashmap_t *prefix_map = NULL;
    metadata_t *metadata = NULL;
    git_tree *old_tree = NULL;
    git_tree *new_tree = NULL;
    git_diff *diff = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    size_t synced = 0, removed = 0, fallbacks = 0, skipped = 0;

    /* PHASE 1: BUILD CONTEXT (O(M)) */
    /* 1.1. Load prefix map and build fresh manifest from Git (post-sync state) */
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        err = error_wrap(err, "Failed to get custom prefix map");
        goto cleanup;
    }
    err = build_manifest(
        repo, enabled_profiles, prefix_map, arena, &fresh_manifest, &profiles
    );
    if (err) {
        err = error_wrap(err, "Failed to build fresh manifest");
        goto cleanup;
    }

    /* 1.2. Verify manifest has index (should be populated by profile_build_manifest) */
    if (!fresh_manifest->index) {
        err = ERROR(ERR_INTERNAL, "Fresh manifest missing index");
        goto cleanup;
    }

    /* 1.3. Load merged metadata from Git (post-sync state) */
    err = metadata_load_from_profiles(repo, enabled_profiles, &metadata);
    if (err && err->code != ERR_NOT_FOUND) {
        err = error_wrap(err, "Failed to load metadata");
        goto cleanup;
    }
    if (err) {
        /* Non-fatal: Old profiles may not have metadata.json
         * sync_entry_to_state handles NULL metadata gracefully (uses Git defaults) */
        error_free(err);
        err = NULL;
    }

    /* PHASE 2: COMPUTE DIFF (O(D)) */
    /* 2.1. Extract trees from old and new commits for diff */
    err = gitops_get_tree_from_commit(repo, old_oid, &old_tree);
    if (err) {
        err = error_wrap(err, "Failed to get tree from old commit");
        goto cleanup;
    }

    err = gitops_get_tree_from_commit(repo, new_oid, &new_tree);
    if (err) {
        err = error_wrap(err, "Failed to get tree from new commit");
        goto cleanup;
    }

    /* 2.2. Compute diff between old and new trees */
    err = gitops_diff_trees(repo, old_tree, new_tree, NULL, &diff);
    if (err) {
        err = error_wrap(err, "Failed to diff trees");
        goto cleanup;
    }

    size_t num_deltas = git_diff_num_deltas(diff);

    /* PHASE 3: PROCESS DELTAS (O(D)) */

    /* Lookup custom prefix for the synced profile from prefix map */
    const char *synced_profile_custom_prefix =
        prefix_map ? (const char *) hashmap_get(prefix_map, profile_name) : NULL;

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

        /* Use custom prefix from profile (attached by orchestrator) */
        const char *custom_prefix = synced_profile_custom_prefix;

        /* Skip custom/ files when deployment prefix is unknown */
        if (str_starts_with(storage_path, "custom/") && !custom_prefix) {
            skipped++;
            continue;
        }

        /* Resolve filesystem path with appropriate prefix */
        char *filesystem_path = NULL;
        err = path_from_storage(storage_path, custom_prefix, &filesystem_path);
        if (err) {
            /* Skip files we can't resolve (invalid paths) */
            error_free(err);
            err = NULL;  /* Clear for next iteration */
            continue;
        }

        /* Handle based on delta type */
        if (delta->status == GIT_DELTA_ADDED || delta->status == GIT_DELTA_MODIFIED) {
            /* ADDITION / MODIFICATION */

            /* Lookup in fresh manifest (O(1)) */
            void *idx_ptr = hashmap_get(fresh_manifest->index, filesystem_path);
            file_entry_t *entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
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
            if (entry->profile_name &&
                strcmp(entry->profile_name, profile_name) != 0) {
                /* Different profile won precedence - skip this file */
                free(filesystem_path);
                continue;
            }

            /* Sync entry to state. deployed_at is preserved by SQL UPSERT on
             * UPDATE; 0 is used for INSERT (new file, never deployed). old_profile
             * auto-captured by SQL when the owning profile changes. */
            err = sync_entry_to_state(repo, state, entry, metadata, 0, NULL);
            if (err) {
                err = error_wrap(
                    err, "Failed to sync '%s' to manifest",
                    filesystem_path
                );
                free(filesystem_path);
                goto cleanup;
            }

            synced++;

        } else if (delta->status == GIT_DELTA_DELETED) {
            /* DELETION */

            /* Check if file exists in manifest from OTHER profiles (fallback check)
             *
             * When a file is deleted from one profile, it might still exist in another
             * lower-precedence profile. If so, that profile now "wins" and we should
             * update the manifest to point to it. */
            void *idx_ptr = hashmap_get(fresh_manifest->index, filesystem_path);
            file_entry_t *entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                entry = &fresh_manifest->entries[idx];
            }

            if (entry && entry->profile_name &&
                strcmp(entry->profile_name, profile_name) != 0) {
                /* Fallback found — update manifest to the new profile owner.
                 * deployed_at preserved by SQL UPSERT, old_profile auto-captured
                 * by SQL when the owning profile changes. */
                err = sync_entry_to_state(repo, state, entry, metadata, 0, NULL);
                if (err) {
                    err = error_wrap(
                        err, "Failed to sync fallback for '%s'",
                        filesystem_path
                    );
                    free(filesystem_path);
                    goto cleanup;
                }

                /* Track profile reassignment for user visibility */
                fallbacks++;

            } else {
                /* No fallback exists - check if we own this file in current state */

                state_file_entry_t *state_entry = NULL;
                err = state_get_file(state, filesystem_path, &state_entry);

                if (err) {
                    if (err->code == ERR_NOT_FOUND) {
                        /* File not in state (never deployed) - nothing to do */
                        error_free(err);
                        err = NULL;
                        free(filesystem_path);
                        continue;
                    }
                    /* Fatal state error - propagate */
                    free(filesystem_path);
                    goto cleanup;
                }

                /* Check if profile_name owns this file */
                if (strcmp(state_entry->profile, profile_name) == 0) {
                    /* We own it and no fallback exists - mark as inactive
                     *
                     * File deleted from Git during sync (pull/rebase/merge), with no
                     * fallback coverage. Entry marked STATE_INACTIVE for cleanup.
                     *
                     * Entry marked inactive and remains in state for orphan detection.
                     * This maintains consistency with other manifest operations: sync
                     * updates scope (what's in Git), apply executes cleanup (removal).
                     *
                     * The orphan cleanup flow applies (see manifest_disable_profile()).
                     * Cleanup deferred to apply - DO NOT call state_remove_file() here.
                     */

                    /* Mark entry as inactive for silent workspace handling */
                    err = state_set_file_state(state, filesystem_path, STATE_INACTIVE);
                    if (err) {
                        /* Non-fatal: log warning but continue */
                        fprintf(
                            stderr, "warning: failed to mark '%s' as inactive: %s\n",
                            filesystem_path, error_message(err)
                        );
                        error_free(err);
                        err = NULL;  /* Clear error, continue operation */
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
    if (out_skipped) *out_skipped = skipped;

    /* Update the per-profile commit_oid in enabled_profiles to match the new HEAD.
     * Use new_oid directly — it's the explicit sync target passed by the caller,
     * and matches the branch HEAD that profile_list_load would resolve. */
    err = state_set_profile_commit_oid(state, profile_name, new_oid);
    if (err) {
        err = error_wrap(
            err, "Failed to sync commit_oid for profile '%s'",
            profile_name
        );
        goto cleanup;
    }

    /* 4. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    /* Free resources in reverse order of acquisition */
    if (diff) git_diff_free(diff);
    if (new_tree) git_tree_free(new_tree);
    if (old_tree) git_tree_free(old_tree);
    if (metadata) metadata_free(metadata);
    if (prefix_map) hashmap_free(prefix_map, free);
    if (fresh_manifest) manifest_free(fresh_manifest);
    if (profiles) profile_list_free(profiles);
    arena_destroy(arena);

    return err;
}

/**
 * Sync tracked directories from enabled profiles
 *
 * Rebuilds the tracked_directories table from metadata.
 * Called after profile enable/disable/reorder to maintain directory tracking.
 *
 * Algorithm:
 *   1. Clear all tracked directories (idempotent start)
 *   2. For each enabled profile:
 *      a. Load metadata from Git (or skip if doesn't exist)
 *      b. Extract directories via metadata_get_items_by_kind()
 *      c. Add to state via state_add_directory() with profile attribution
 *   3. All within caller's active transaction
 *
 * Pattern: Rebuild (not incremental)
 *   - Directories have no lifecycle states to preserve
 *   - Clear + repopulate is simple, correct, and fast
 *   - Already idempotent via INSERT OR REPLACE
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - tracked_directories table reflects enabled_profiles
 *   - Transaction remains open (caller commits)
 *   - Missing metadata handled gracefully (not an error)
 *
 * Performance: O(D) where D = total directories across enabled profiles
 *              (typically < 50 even for large configs)
 *
 * @param repo Git repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param enabled_profiles Current enabled profiles (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_sync_directories(
    git_repository *repo,
    state_t *state,
    const string_array_t *enabled_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(enabled_profiles);

    error_t *err = NULL;
    hashmap_t *prefix_map = NULL;
    metadata_t *metadata = NULL;
    const metadata_item_t **directories = NULL;

    arena_t *arena = arena_create(8 * 1024);
    if (!arena) {
        return ERROR(ERR_MEMORY, "Failed to create directory sync arena");
    }

    /* 1. Mark all directories as inactive (soft delete for orphan detection)
     *
     * This preserves directory entries for orphan detection instead of deleting them.
     * Directories not reactivated during rebuild become orphaned and are cleaned by apply.
     */
    err = state_mark_all_directories_inactive(state);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to mark directories inactive");
    }

    /* 2. Load prefix map from state for custom prefix resolution */
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to load prefix map from state");
    }

    /* 3. Rebuild from each enabled profile */
    for (size_t i = 0; i < enabled_profiles->count; i++) {
        const char *profile_name = enabled_profiles->items[i];

        /* Reset per-iteration state */
        metadata = NULL;
        directories = NULL;

        /* Load metadata (may not exist for old profiles - gracefully skip) */
        err = metadata_load_from_branch(repo, profile_name, &metadata);
        if (err) {
            if (err->code == ERR_NOT_FOUND) {
                /* No metadata file - old profile or no directories tracked */
                error_free(err);
                err = NULL;
                continue;
            }
            err = error_wrap(
                err, "Failed to load metadata for profile '%s'",
                profile_name
            );
            goto cleanup;
        }

        /* Lookup custom prefix for this profile */
        const char *custom_prefix = NULL;
        if (prefix_map) {
            custom_prefix = (const char *) hashmap_get(prefix_map, profile_name);
        }

        /* Extract directories from metadata */
        size_t dir_count = 0;
        directories =
            metadata_get_items_by_kind(metadata, METADATA_ITEM_DIRECTORY, &dir_count);

        /* Reactivate or add each directory to state
         *
         * ARCHITECTURE: Mark-inactive-then-reactivate pattern.
         *
         * For each directory in enabled profile metadata:
         *   - If exists in state → reactivate (STATE_ACTIVE) and update metadata
         *   - If not in state → add new entry with STATE_ACTIVE
         *
         * This preserves deployed_at timestamps and enables clean orphan detection.
         */
        for (size_t j = 0; j < dir_count; j++) {
            /* Skip custom/ directories when prefix is unknown */
            if (str_starts_with(directories[j]->key, "custom/") && !custom_prefix) {
                continue;
            }

            state_directory_entry_t *state_dir = NULL;

            err = state_directory_entry_create_from_metadata(
                directories[j],
                profile_name,  /* Profile attribution */
                custom_prefix, /* Custom prefix for path resolution */
                arena,
                &state_dir
            );

            if (err) {
                err = error_wrap(
                    err, "Failed to create state directory entry for '%s'",
                    directories[j]->key
                );
                break;
            }

            /* Check if directory already exists in state (may be inactive) */
            state_directory_entry_t *existing = NULL;
            error_t *get_err = state_get_directory(state, state_dir->filesystem_path, &existing);

            if (get_err && get_err->code != ERR_NOT_FOUND) {
                /* Fatal error - failed to query state */
                if (existing) state_free_directory_entry(existing);
                err = error_wrap(get_err, "Failed to check directory state");
                break;
            }

            if (get_err && get_err->code == ERR_NOT_FOUND) {
                /* New directory - add with STATE_ACTIVE */
                error_free(get_err);
                state_dir->state = arena_strdup(arena, STATE_ACTIVE);
                if (!state_dir->state) {
                    err = ERROR(ERR_MEMORY, "Failed to allocate state string");
                    break;
                }
                err = state_add_directory(state, state_dir);
            } else {
                /* Existing directory - reactivate and always update
                 *
                 * CRITICAL: Always call state_update_directory, not conditionally.
                 *
                 * Rationale:
                 * - profile field may have changed (directory moved between profiles)
                 * - storage_path may have changed (different profile conventions)
                 * - UPDATE is cheap (single row, indexed by filesystem_path)
                 * - Ensures state consistency regardless of metadata changes
                 * - deployed_at is preserved (stmt_update_entry excludes it)
                 */
                err = state_set_directory_state(state, state_dir->filesystem_path, STATE_ACTIVE);

                /* Always update profile, storage_path, and metadata (preserves deployed_at) */
                if (!err) {
                    err = state_update_directory(state, state_dir);
                }

                state_free_directory_entry(existing);
            }

            if (err) {
                err = error_wrap(
                    err, "Failed to add/update directory '%s' in state",
                    directories[j]->key
                );
                break;
            }
        }

        /* Free per-iteration resources (always, whether error or success) */
        free(directories);
        directories = NULL;
        metadata_free(metadata);
        metadata = NULL;

        if (err) goto cleanup;
    }

cleanup:
    /* Per-iteration resources are NULL on normal exit (freed in loop above).
     * Non-NULL only if outer loop exited before per-iteration cleanup (e.g.,
     * metadata_load_from_branch error before inner loop). */
    if (directories) free(directories);
    if (metadata) metadata_free(metadata);
    if (prefix_map) hashmap_free(prefix_map, free);
    arena_destroy(arena);

    /* After rebuild, any directories still in STATE_INACTIVE are orphaned
     * (belonged to disabled profiles with no fallback).
     *
     * They will be detected by workspace orphan analysis and cleaned by apply.
     * This completes the mark-inactive-then-reactivate lifecycle.
     */

    return err;
}
