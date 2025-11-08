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
 *   - Blob OID Extraction: Uses git_tree_entry_id() for O(1) content identity
 *   - Metadata Integration: Uses metadata_load_from_profiles() for merged view
 */

#include "manifest.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    char refname[DOTTA_REFNAME_MAX];
    err = gitops_build_refname(refname, sizeof(refname), "refs/heads/%s", branch_name);
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
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
 * Extract file metadata from Git tree entry
 *
 * Authoritative extraction of file type and mode from Git tree entry.
 * This implements the VWD principle: Git is the single source of truth.
 *
 * File TYPE is always derived from Git filemode (authoritative).
 * File MODE is extracted as fallback for when metadata is unavailable.
 *
 * Metadata mode can override the returned mode, but NOT the type.
 *
 * Algorithm:
 *   1. Extract git_filemode via git_tree_entry_filemode()
 *   2. Map to state_file_type_t (blob → regular, blob_executable → executable, link → symlink)
 *   3. Extract permission bits (0755, 0644, 0777)
 *
 * Error Handling:
 *   - GIT_FILEMODE_TREE: Returns ERR_INTERNAL (directories never in manifest)
 *   - Unknown filemode: Returns ERR_INTERNAL (defensive programming)
 *   - NULL inputs: Returns ERR_INVALID_ARG via CHECK_NULL
 *
 * @param entry Git tree entry (must not be NULL)
 * @param out_type File type (must not be NULL)
 * @param out_mode Permission mode (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *extract_file_metadata_from_tree_entry(
    const git_tree_entry *entry,
    state_file_type_t *out_type,
    mode_t *out_mode
) {
    CHECK_NULL(entry);
    CHECK_NULL(out_type);
    CHECK_NULL(out_mode);

    /* Extract authoritative filemode from Git tree entry */
    git_filemode_t filemode = git_tree_entry_filemode(entry);

    /* Map Git filemode to state file type and mode
     *
     * This is the ONLY place where Git filemode is converted to state type.
     * Precedence: Git is authoritative for TYPE, metadata can override MODE. */
    state_file_type_t type;
    mode_t mode;

    switch (filemode) {
        case GIT_FILEMODE_BLOB:
            /* Regular non-executable file */
            type = STATE_FILE_REGULAR;
            mode = 0644;
            break;

        case GIT_FILEMODE_BLOB_EXECUTABLE:
            /* Executable file */
            type = STATE_FILE_EXECUTABLE;
            mode = 0755;
            break;

        case GIT_FILEMODE_LINK:
            /* Symbolic link */
            type = STATE_FILE_SYMLINK;
            mode = 0777;  /* Conventional, not actually used by filesystem */
            break;

        case GIT_FILEMODE_TREE:
            /* Directories should never appear in manifest entries.
             * File entries are extracted from tree walks which skip directories.
             * If we see this, it indicates a bug in the tree traversal logic. */
            return ERROR(ERR_INTERNAL,
                "Unexpected directory in manifest tree entry (bug in tree traversal)");

        default:
            /* Unknown/unsupported filemode - defensive programming.
             * Git may add new filemodes in future versions. Fail explicitly
             * rather than silently mishandling. */
            return ERROR(ERR_INTERNAL,
                "Unknown or unsupported git filemode: 0%o", filemode);
    }

    *out_type = type;
    *out_mode = mode;
    return NULL;
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
 * Responsibilities:
 *   - Extract blob_oid from tree entry
 *   - Extract metadata (mode, owner, group, encrypted flag)
 *   - Build state entry structure with caller-provided deployed_at
 *   - Write to state database (INSERT OR REPLACE)
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param manifest_entry Entry from in-memory manifest (borrowed)
 * @param git_oid Git commit reference (40-char hex)
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
    const char *git_oid,
    const metadata_t *metadata,
    time_t deployed_at
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(manifest_entry);
    CHECK_NULL(git_oid);
    CHECK_NULL(manifest_entry->source_profile);

    error_t *err = NULL;
    char *blob_oid = NULL;
    metadata_item_t *meta_item = NULL;

    /* 1. Extract blob_oid from tree entry */
    const struct git_oid *blob_oid_obj = git_tree_entry_id(manifest_entry->entry);
    if (!blob_oid_obj) {
        return ERROR(ERR_INTERNAL, "Tree entry has no OID for '%s'",
                     manifest_entry->storage_path);
    }

    char oid_str[GIT_OID_HEXSZ + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), blob_oid_obj);

    blob_oid = strdup(oid_str);
    if (!blob_oid) {
        return ERROR(ERR_MEMORY, "Failed to allocate blob_oid string");
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

    /* 3. Extract file type and mode from Git tree entry (authoritative source) */
    state_file_type_t file_type;
    mode_t git_mode;

    err = extract_file_metadata_from_tree_entry(
        manifest_entry->entry,
        &file_type,
        &git_mode
    );
    if (err) {
        goto cleanup;
    }

    /* 4. Determine mode with metadata precedence (no allocation needed!)
     *
     * Precedence Rules:
     *   1. Metadata mode (if present) - explicit user intent, may differ from Git
     *      Example: User wants 0600 (private) instead of Git's 0644
     *   2. Git mode (fallback) - authoritative for type, good default for permissions */
    mode_t mode = meta_item ? meta_item->mode : git_mode;

    /* 5. Build state entry */
    state_file_entry_t state_entry = {
        .storage_path = manifest_entry->storage_path,
        .filesystem_path = manifest_entry->filesystem_path,
        .profile = manifest_entry->source_profile->name,
        .type = file_type,
        .git_oid = (char *)git_oid,
        .blob_oid = blob_oid,
        .mode = mode,
        .owner = meta_item ? meta_item->owner : NULL,
        .group = meta_item ? meta_item->group : NULL,
        .encrypted = meta_item ? meta_item->file.encrypted : false,
        .deployed_at = deployed_at
    };

    /* 6. Write entry to state (INSERT OR REPLACE with caller's deployed_at)
     *
     * Uses INSERT OR REPLACE for atomic upsert - handles both new entries
     * and updates to existing entries. The deployed_at value comes directly
     * from the caller, who is responsible for preservation logic.
     */
    err = state_add_file(state, &state_entry);
    if (err) {
        err = error_wrap(err, "Failed to sync manifest entry for %s",
                       manifest_entry->storage_path);
    }

cleanup:
    free(blob_oid);
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
    const string_array_t *enabled_profiles,
    manifest_enable_stats_t *out_stats
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

    /* Track counts for user feedback */
    size_t total_files = 0;
    size_t already_deployed = 0;
    size_t needs_deployment = 0;

    for (size_t i = 0; i < manifest->count; i++) {
        file_entry_t *entry = &manifest->entries[i];

        /* Only process files owned by this profile */
        if (strcmp(entry->source_profile->name, profile_name) != 0) {
            continue;
        }

        total_files++;

        /* Determine deployed_at timestamp for lifecycle tracking
         *
         * For NEW entries: Check filesystem to set initial deployed_at
         * For EXISTING entries: Preserve existing deployed_at (handled in sync_entry_to_state)
         *
         * deployed_at = 0   → File never deployed by dotta
         * deployed_at > 0   → File known to dotta (either deployed or existed when profile enabled)
         */
        time_t deployed_at;
        struct stat st;

        /* Check if entry already exists in state (to preserve deployed_at) */
        state_file_entry_t *existing_entry = NULL;
        error_t *check_err = state_get_file(state, entry->filesystem_path, &existing_entry);

        if (check_err == NULL && existing_entry != NULL) {
            /* File already in manifest - preserve existing timestamp */
            deployed_at = existing_entry->deployed_at;

            /* Check filesystem to update stats only */
            if (lstat(entry->filesystem_path, &st) == 0) {
                already_deployed++;
            } else if (errno == ENOENT) {
                /* File doesn't exist - needs deployment */
                needs_deployment++;
            } else {
                /* Access error (permission denied, I/O error, etc.)
                 *
                 * Conservative approach: Count as needs_deployment rather than
                 * blocking the entire enable operation. The apply command will
                 * perform fresh divergence analysis with proper error handling.
                 *
                 * Rationale: For existing entries, deployed_at is already known
                 * from state. The lstat() check here is purely for statistics.
                 * Statistics inaccuracy is acceptable to avoid blocking manifest
                 * updates in scenarios like non-root users managing root-owned files.
                 */
                needs_deployment++;
            }

            state_free_entry(existing_entry);
        } else {
            /* New entry - check if file exists on filesystem */
            if (check_err && check_err->code == ERR_NOT_FOUND) {
                error_free(check_err);
                check_err = NULL;
            } else if (check_err) {
                err = check_err;
                goto cleanup;
            }

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
                 * signaling to the user that these files need attention.
                 *
                 * This matches the approach for existing entries (lines 519-531) where
                 * lstat() failures are tolerated for statistics. The consistency ensures
                 * that a single inaccessible file cannot prevent enabling a profile
                 * containing hundreds of other valid files.
                 */
                deployed_at = 0;
                needs_deployment++;

                /* Track access errors for user feedback */
                if (out_stats) {
                    out_stats->access_errors++;
                }
            }
        }

        /* Sync entry with deployed_at timestamp */
        err = sync_entry_to_state(repo, state, entry, head_oid_str, metadata, deployed_at);
        if (err) {
            goto cleanup;
        }
    }

    /* Populate output stats if requested */
    if (out_stats) {
        out_stats->total_files = total_files;
        out_stats->already_deployed = already_deployed;
        out_stats->needs_deployment = needs_deployment;
    }

    /* 7. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (profiles) profile_list_free(profiles);
    if (km) keymanager_free(km);
    if (config) config_free(config);
    if (metadata) metadata_free(metadata);
    if (manifest) manifest_free(manifest);

    return err;
}

/**
 * Build directory fallback index from remaining enabled profiles
 *
 * Loads metadata from each remaining profile and builds O(1) lookup hashmaps
 * for directory fallback resolution. This implements "last wins" precedence,
 * matching the file fallback pattern (build_manifest()) and workspace metadata
 * merge pattern (workspace.c:1936-1939).
 *
 * PRECEDENCE MODEL (profiles.h:6-14):
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
    if (string_array_size(remaining_enabled) == 0) {
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
    fallback_dirs = hashmap_create(64);  /* Initial capacity: 64 directories */
    fallback_dir_profiles = hashmap_create(64);

    if (!fallback_dirs || !fallback_dir_profiles) {
        if (fallback_dirs) hashmap_free(fallback_dirs, NULL);
        if (fallback_dir_profiles) hashmap_free(fallback_dir_profiles, NULL);
        return ERROR(ERR_MEMORY, "Failed to create fallback hashmaps");
    }

    /* Allocate array to track loaded metadata (for proper cleanup) */
    loaded_metadata = malloc(string_array_size(remaining_enabled) * sizeof(metadata_t*));
    if (!loaded_metadata) {
        hashmap_free(fallback_dirs, NULL);
        hashmap_free(fallback_dir_profiles, NULL);
        return ERROR(ERR_MEMORY, "Failed to allocate metadata array");
    }

    /* Load metadata from each profile and build index with "last wins" precedence */
    for (size_t i = 0; i < string_array_size(remaining_enabled); i++) {
        const char *profile = string_array_get(remaining_enabled, i);
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
         *   - File fallback: build_manifest() (manifest.c:646-681)
         *   - Workspace merge: (workspace.c:1936-1939)
         *   - Metadata merge: metadata_merge() (metadata.c:1816)
         *
         * Precedence order: global < OS < host (profiles.h:6-14)
         * Iteration order: same as precedence (low→high)
         * Result: Later iterations override earlier ones → highest precedence wins
         */
        for (size_t j = 0; j < meta_dir_count; j++) {
            const metadata_item_t *dir_item = directories[j];
            const char *storage_path = dir_item->key;  /* Storage path (portable) */

            /* Unconditionally set/update - later profiles override (last wins) */
            hashmap_set(fallback_dirs, storage_path, (void*)dir_item);
            hashmap_set(fallback_dir_profiles, storage_path, (void*)profile);
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
    hashmap_t *profile_oids = NULL;

    /* Track stats for output */
    size_t total_files = 0;
    size_t fallback_count = 0;
    size_t removed_count = 0;

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

    /* Build profile→oid map for O(1) lookups in fallback processing */
    if (fallback_profiles) {
        err = build_profile_oid_map(repo, fallback_profiles, &profile_oids);
        if (err) {
            err = error_wrap(err, "Failed to build profile OID map");
            goto cleanup;
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
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
                fallback = &fallback_manifest->entries[idx];
            }
        }

        if (fallback) {
            /* File exists in lower-precedence profile - update to fallback */

            /* Get OID from pre-built map (O(1) lookup) */
            const char *fallback_oid_str = hashmap_get(profile_oids,
                                                       fallback->source_profile->name);
            if (!fallback_oid_str) {
                err = ERROR(ERR_INTERNAL, "Missing OID for profile '%s'",
                           fallback->source_profile->name);
                goto cleanup;
            }

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

            err = state_update_entry(state, entry);
            if (err) {
                err = error_wrap(err, "Failed to update entry to fallback for %s",
                               entry->storage_path);
                goto cleanup;
            }

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
                fprintf(stderr, "warning: failed to mark '%s' as inactive: %s\n",
                        entry->filesystem_path, error_message(err));
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

    err = state_get_directories_by_profile(state, profile_name, &dir_entries, &dir_count);
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
    err = build_directory_fallback_index(repo, remaining_enabled,
                                        &fallback_dirs, &fallback_dir_profiles,
                                        &loaded_metadata, &loaded_metadata_count);
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
            /* Directory exists in lower-precedence profile - update to fallback */

            /* MEMORY SAFETY: Must use str_replace_owned() to properly free old
             * strings and allocate independent copies. Direct assignment would cause:
             * 1. Memory leak (old values not freed)
             * 2. Use-after-free (aliasing memory freed with loaded_metadata)
             * 3. Double-free crash (cleanup path tries to free already-freed memory)
             *
             * This mirrors file handling pattern (see file fallback section above).
             */
            err = str_replace_owned(&entry->profile, fallback_profile);
            if (err) {
                goto directory_cleanup;
            }

            /* Update metadata from fallback */
            entry->mode = fallback->mode;

            err = str_replace_owned(&entry->owner, fallback->owner);
            if (err) {
                goto directory_cleanup;
            }

            err = str_replace_owned(&entry->group, fallback->group);
            if (err) {
                goto directory_cleanup;
            }

            err = str_replace_owned(&entry->storage_path, fallback->key);
            if (err) {
                goto directory_cleanup;
            }

            /* Update in state (preserves deployed_at) */
            err = state_update_directory(state, entry);
            if (err) {
                err = error_wrap(err, "Failed to update directory to fallback for %s",
                               entry->filesystem_path);
                goto directory_cleanup;
            }

            dir_fallback_count++;
        } else {
            /* No fallback - entry becomes orphaned (cleanup deferred to apply)
             *
             * ARCHITECTURE: Separation of concerns for directory orphan cleanup.
             *
             * The entry remains in state for workspace orphan detection:
             *   1. Entry stays in state with profile=<disabled_profile_name>
             *   2. Workspace filters merged_metadata by enabled profiles (skips this entry)
             *   3. Workspace detects: entry in state, NOT in merged_metadata → orphaned
             *   4. Apply removes: directory from filesystem + entry from state
             *
             * This design enables:
             *   - Safe re-enable: Profile can be re-enabled without data loss
             *   - Orphan detection: Workspace analysis works (workspace.c:767-799)
             *   - User visibility: Status shows orphans before removal
             *   - Explicit action: User runs apply to execute destructive cleanup
             *
             * Why not delete immediately?
             *   - Breaks orphan detection (entry gone → can't detect)
             *   - Prevents safe re-enable (data lost → must recreate)
             *   - Violates separation (profile cmd shouldn't do filesystem ops)
             *
             * This mirrors file orphan handling (manifest.c:756-782).
             * Cleanup deferred to apply - DO NOT call state_remove_directory() here.
             */
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
    if (fallback_dirs) hashmap_free(fallback_dirs, NULL);  /* Values are borrowed */
    if (fallback_dir_profiles) hashmap_free(fallback_dir_profiles, NULL);  /* Values are borrowed */

    /* Free loaded metadata */
    if (loaded_metadata) {
        for (size_t i = 0; i < loaded_metadata_count; i++) {
            metadata_free(loaded_metadata[i]);
        }
        free(loaded_metadata);
    }

    state_free_all_directories(dir_entries, dir_count);

    if (err) {
        goto cleanup;  /* Jump to existing cleanup in manifest_disable_profile */
    }

cleanup:
    if (profile_oids) hashmap_free(profile_oids, free);
    if (fallback_profiles) profile_list_free(fallback_profiles);
    if (fallback_manifest) manifest_free(fallback_manifest);
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
    hashmap_t *profile_oids = NULL;
    size_t removed_count = 0;
    size_t fallback_count = 0;

    /* 1. Build fresh manifest from current Git state (post-removal) */
    err = build_manifest(repo, enabled_profiles, &fresh_manifest, &profiles);
    if (err) {
        return error_wrap(err, "Failed to build manifest for fallback detection");
    }

    /* 2. Build profile→oid map (profile_name → git_oid string) for fast lookups */
    err = build_profile_oid_map(repo, profiles, &profile_oids);
    if (err) {
        err = error_wrap(err, "Failed to build profile OID map");
        goto cleanup;
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

            /* Get HEAD oid for fallback profile (hex string) */
            const char *fallback_oid_str = hashmap_get(profile_oids, fallback_profile);
            if (!fallback_oid_str) {
                err = ERROR(ERR_INTERNAL, "Missing OID for profile '%s'", fallback_profile);
                state_free_entry(current_entry);
                free(filesystem_path);
                goto cleanup;
            }

            /* Track ownership change: save old profile before updating
             *
             * Profile ownership change occurs when a file is removed from
             * high-precedence profile and falls back to lower-precedence.
             * Track old_profile to inform user via workspace divergence analysis.
             */
            const char *old_profile_name = current_entry->profile;

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

            /* Set old_profile to track the ownership change */
            err = str_replace_owned(&current_entry->old_profile, old_profile_name);
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

            err = state_update_entry(state, current_entry);
            if (err) {
                state_free_entry(current_entry);
                free(filesystem_path);
                goto cleanup;
            }

            fallback_count++;
        } else {
            /* No fallback - mark as inactive (staged for removal)
             *
             * Entry marked STATE_INACTIVE and remains in state for orphan detection.
             * See manifest_disable_profile() for detailed architectural rationale.
             *
             * The orphan cleanup flow:
             *   1. Entry marked inactive (this function)
             *   2. Workspace skips inactive entries (no Git validation)
             *   3. Workspace orphan detection loads inactive entries → marks as ORPHANED
             *   4. Apply removes (filesystem + state cleanup)
             *
             * Cleanup deferred to apply - DO NOT call state_remove_file() here.
             */

            /* Mark entry as inactive for silent workspace handling */
            err = state_set_file_state(state, filesystem_path, STATE_INACTIVE);
            if (err) {
                /* Non-fatal: log warning but continue */
                fprintf(stderr, "warning: failed to mark '%s' as inactive: %s\n",
                        filesystem_path, error_message(err));
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

    /* 4. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (profile_oids) {
        hashmap_free(profile_oids, free);
    }

    if (fresh_manifest) manifest_free(fresh_manifest);
    if (profiles) profile_list_free(profiles);

    return err;
}

/**
 * Rebuild manifest from scratch
 *
 * Nuclear option for recovery operations. Clears all manifest state and
 * rebuilds from Git by building a complete manifest once and syncing all
 * entries.
 *
 * Algorithm (optimized O(M) approach):
 *   1. Clear all file entries from state
 *   2. Build manifest ONCE from all enabled profiles (precedence oracle)
 *   3. Build profile→oid map for git_oid field
 *   4. Load merged metadata from all profiles
 *   5. Create keymanager for content hashing
 *   6. Sync ALL entries from manifest to state (single pass, no filtering)
 *   7. Sync tracked directories
 *
 * Performance: O(M) where M = total files across all enabled profiles
 *
 * Previous implementation: O(N × M) - called manifest_enable_profile() N times,
 * each rebuilding the full manifest. This version builds once and syncs all
 * entries directly, following the pattern from manifest_reorder_profiles().
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
    state_file_entry_t *old_entries = NULL;
    size_t old_count = 0;
    hashmap_t *old_map = NULL;
    hashmap_t *profile_oids = NULL;
    metadata_t *metadata = NULL;
    keymanager_t *km = NULL;
    dotta_config_t *config = NULL;

    /* 1. Snapshot existing entries BEFORE clearing (for deployed_at preservation) */
    err = state_get_all_files(state, &old_entries, &old_count);
    if (err) {
        return error_wrap(err, "Failed to snapshot manifest for rebuild");
    }

    /* Build hashmap for O(1) old entry lookups */
    old_map = hashmap_create(old_count > 0 ? old_count : 16);
    if (!old_map) {
        state_free_all_files(old_entries, old_count);
        return ERROR(ERR_MEMORY, "Failed to create old entries hashmap");
    }

    for (size_t i = 0; i < old_count; i++) {
        err = hashmap_set(old_map, old_entries[i].filesystem_path, &old_entries[i]);
        if (err) {
            err = error_wrap(err, "Failed to populate old entries hashmap");
            hashmap_free(old_map, NULL);  /* Don't free values - they're in old_entries */
            state_free_all_files(old_entries, old_count);
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
    err = build_manifest(repo, enabled_profiles, &manifest, &profiles);
    if (err) {
        err = error_wrap(err, "Failed to build manifest for rebuild");
        goto cleanup;
    }

    /* 4. Build profile→oid map for git_oid field */
    err = build_profile_oid_map(repo, profiles, &profile_oids);
    if (err) {
        err = error_wrap(err, "Failed to build profile oid map");
        goto cleanup;
    }

    /* 5. Load merged metadata from all profiles */
    err = metadata_load_from_profiles(repo, enabled_profiles, &metadata);
    if (err) {
        /* Metadata may not exist for old profiles - continue with NULL */
        if (err->code != ERR_NOT_FOUND) {
            goto cleanup;
        }
        error_free(err);
        err = NULL;
    }

    /* 6. Create keymanager for content hashing */
    err = config_load(NULL, &config);
    if (err) {
        goto cleanup;
    }

    err = keymanager_create(config, &km);
    if (err) {
        goto cleanup;
    }

    /* 7. Sync ALL entries from manifest to state (single pass, no filtering)
     *
     * Key difference from manifest_enable_profile: We sync ALL entries because
     * the state is empty (cleared in step 1). No filtering needed - every file
     * in the manifest belongs in the rebuilt state. */
    for (size_t i = 0; i < manifest->count; i++) {
        file_entry_t *entry = &manifest->entries[i];

        /* Get git_oid for this entry's source profile */
        const char *git_oid = hashmap_get(profile_oids, entry->source_profile->name);
        if (!git_oid) {
            err = ERROR(ERR_INTERNAL, "Missing OID for profile '%s'",
                       entry->source_profile->name);
            goto cleanup;
        }

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
        err = sync_entry_to_state(repo, state, entry, git_oid, metadata, deployed_at);
        if (err) {
            goto cleanup;
        }
    }

    /* 8. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (old_map) hashmap_free(old_map, NULL);
    state_free_all_files(old_entries, old_count);
    if (profile_oids) hashmap_free(profile_oids, free);
    if (profiles) profile_list_free(profiles);
    if (km) keymanager_free(km);
    if (config) config_free(config);
    if (metadata) metadata_free(metadata);
    if (manifest) manifest_free(manifest);

    return err;
}

/**
 * Update manifest after profile precedence change
 *
 * Implementation strategy:
 *   1. Build new manifest with precedence oracle
 *   2. Compare with current state to detect ownership changes
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
    state_file_entry_t *old_entries = NULL;
    size_t old_count = 0;
    hashmap_t *old_map = NULL;
    hashmap_t *profile_oids = NULL;
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

    /* Build profile→oid map for O(1) lookups in reorder processing */
    err = build_profile_oid_map(repo, profiles, &profile_oids);
    if (err) {
        err = error_wrap(err, "Failed to build profile OID map");
        goto cleanup;
    }

    /* 5. Process each file in new manifest */
    for (size_t i = 0; i < new_manifest->count; i++) {
        file_entry_t *new_entry = &new_manifest->entries[i];

        /* Check if exists in old state using O(1) hashmap lookup */
        state_file_entry_t *old_entry = hashmap_get(old_map, new_entry->filesystem_path);

        if (!old_entry) {
            /* New file (rare in reorder, but handle it) */

            /* Get OID from pre-built map (O(1) lookup) */
            const char *oid_str = hashmap_get(profile_oids,
                                              new_entry->source_profile->name);
            if (!oid_str) {
                err = ERROR(ERR_INTERNAL, "Missing OID for profile '%s'",
                           new_entry->source_profile->name);
                goto cleanup;
            }

            /* New file - deployed_at=0 (never deployed) */
            err = sync_entry_to_state(repo, state, new_entry, oid_str, metadata, 0);
            if (err) {
                goto cleanup;
            }
        } else {
            /* Existing entry - check if owner changed */
            bool owner_changed = strcmp(old_entry->profile, new_entry->source_profile->name) != 0;

            if (owner_changed) {
                /* Owner changed - update entry to new owner */

                /* Get OID from pre-built map (O(1) lookup) */
                const char *oid_str = hashmap_get(profile_oids,
                                                  new_entry->source_profile->name);
                if (!oid_str) {
                    err = ERROR(ERR_INTERNAL, "Missing OID for profile '%s'",
                               new_entry->source_profile->name);
                    goto cleanup;
                }

                /* Sync with new owner, preserve existing deployed_at */
                err = sync_entry_to_state(repo, state, new_entry, oid_str, metadata,
                                          old_entry->deployed_at);
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
            size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
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
        }
    }

    /* 7. Sync tracked directories with new profile order */
    err = manifest_sync_directories(repo, state, new_profile_order);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (profile_oids) hashmap_free(profile_oids, free);
    if (old_map) hashmap_free(old_map, NULL);
    if (profiles) profile_list_free(profiles);
    if (km) keymanager_free(km);
    if (config) config_free(config);
    if (metadata) metadata_free(metadata);
    state_free_all_files(old_entries, old_count);
    if (new_manifest) manifest_free(new_manifest);

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
 *   4. Build profile→oid map for git_oid field
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
    const hashmap_t *metadata_cache,
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
        return NULL;  /* Nothing to do */
    }

    error_t *err = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *fresh_manifest = NULL;
    hashmap_t *profile_oids = NULL;
    metadata_t *metadata_merged = NULL;
    bool using_cache = (metadata_cache != NULL);

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

    /* 5. Load fresh metadata if not provided (NULL handling)
     *
     * CRITICAL: If metadata_cache is NULL, load merged metadata from Git.
     * This ensures we have current metadata including all newly-committed files.
     *
     * Pattern: Same as manifest_sync_diff() (lines 1671-1688).
     * Merged metadata contains all enabled profiles with precedence applied.
     */
    if (!metadata_cache) {
        /* No cache provided - load merged metadata for all enabled profiles */
        err = metadata_load_from_profiles(repo, enabled_profiles, &metadata_merged);
        if (err && err->code != ERR_NOT_FOUND) {
            err = error_wrap(err, "Failed to load metadata for manifest sync");
            goto cleanup;
        }
        if (err) {
            /* No metadata file exists - create empty metadata (old profiles without metadata.json)
             * This is required for metadata resolution (even if file has no custom metadata) */
            error_free(err);
            err = metadata_create_empty(&metadata_merged);
            if (err) {
                err = error_wrap(err, "Failed to create empty metadata");
                goto cleanup;
            }
        }
    }

    /* 6. Process each item */
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

                /* Get metadata - from cache if available, otherwise use merged */
                const metadata_t *metadata = NULL;
                if (using_cache) {
                    metadata = hashmap_get(metadata_cache, fallback->source_profile->name);
                } else {
                    metadata = metadata_merged;
                }

                /* Preserve existing deployed_at and track old_profile when falling back */
                time_t deployed_at = 0;
                char *old_profile_name = NULL;
                state_file_entry_t *existing_entry = NULL;
                error_t *get_err = state_get_file(state, item->filesystem_path, &existing_entry);
                if (get_err == NULL && existing_entry != NULL) {
                    deployed_at = existing_entry->deployed_at;
                    /* Save old profile for ownership change tracking */
                    if (existing_entry->profile) {
                        old_profile_name = strdup(existing_entry->profile);
                    }
                    state_free_entry(existing_entry);
                } else if (get_err) {
                    if (get_err->code == ERR_NOT_FOUND) {
                        error_free(get_err);
                    } else {
                        err = get_err;
                        goto cleanup;
                    }
                }

                err = sync_entry_to_state(repo, state, fallback, git_oid, metadata, deployed_at);
                if (err) {
                    free(old_profile_name);
                    err = error_wrap(err, "Failed to sync fallback for '%s'",
                                   item->filesystem_path);
                    goto cleanup;
                }

                /* Update old_profile if ownership changed */
                if (old_profile_name) {
                    state_file_entry_t *updated_entry = NULL;
                    error_t *get_err2 = state_get_file(state, item->filesystem_path, &updated_entry);
                    if (get_err2 == NULL && updated_entry != NULL) {
                        /* Set old_profile to track ownership change */
                        err = str_replace_owned(&updated_entry->old_profile, old_profile_name);
                        if (!err) {
                            err = state_update_entry(state, updated_entry);
                        }
                        state_free_entry(updated_entry);
                    } else if (get_err2) {
                        error_free(get_err2);
                    }
                    free(old_profile_name);

                    if (err) {
                        err = error_wrap(err, "Failed to track ownership change for '%s'",
                                       item->filesystem_path);
                        goto cleanup;
                    }
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
                    fprintf(stderr, "warning: failed to mark '%s' as inactive: %s\n",
                            item->filesystem_path, error_message(err));
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

            /* Sync to state with deployed_at = now()
             *
             * Key insight: UPDATE captures files FROM filesystem, so they're
             * already deployed. We set deployed_at to mark them as known. */
            const char *git_oid = hashmap_get(profile_oids, item->profile);

            /* Get metadata - from cache if available, otherwise use merged */
            const metadata_t *metadata = NULL;
            if (using_cache) {
                metadata = hashmap_get(metadata_cache, item->profile);
            } else {
                metadata = metadata_merged;
            }

            err = sync_entry_to_state(repo, state, entry, git_oid, metadata, time(NULL));
            if (err) {
                err = error_wrap(err, "Failed to sync '%s' to manifest",
                               item->filesystem_path);
                goto cleanup;
            }

            (*out_synced)++;
        }
    }

    /* 7. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (metadata_merged) metadata_free(metadata_merged);
    if (profile_oids) hashmap_free(profile_oids, free);
    if (fresh_manifest) manifest_free(fresh_manifest);
    if (profiles) profile_list_free(profiles);

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
 *   4. Build profile→oid map for git_oid field
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
    const hashmap_t *metadata_cache,
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

    if (string_array_size(filesystem_paths) == 0) {
        return NULL;  /* Nothing to do */
    }

    error_t *err = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *fresh_manifest = NULL;
    hashmap_t *profile_oids = NULL;
    metadata_t *metadata_merged = NULL;
    bool using_cache = (metadata_cache != NULL);

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

    /* 5. Load fresh metadata if not provided (NULL handling)
     *
     * CRITICAL: If metadata_cache is NULL, load merged metadata from Git.
     * This ensures we have current metadata including all newly-committed files.
     *
     * Pattern: Same as manifest_sync_diff() (lines 1671-1688).
     * Merged metadata contains all enabled profiles with precedence applied.
     */
    if (!metadata_cache) {
        /* No cache provided - load merged metadata for all enabled profiles */
        err = metadata_load_from_profiles(repo, enabled_profiles, &metadata_merged);
        if (err && err->code != ERR_NOT_FOUND) {
            err = error_wrap(err, "Failed to load metadata for manifest sync");
            goto cleanup;
        }
        if (err) {
            /* No metadata file exists - create empty metadata (old profiles without metadata.json)
             * This is required for metadata resolution (even if file has no custom metadata) */
            error_free(err);
            err = metadata_create_empty(&metadata_merged);
            if (err) {
                err = error_wrap(err, "Failed to create empty metadata");
                goto cleanup;
            }
        }
    }

    /* 6. Process each file */
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

        /* Sync to state with deployed_at = now()
         *
         * Key insight: ADD captures files FROM filesystem, so they're
         * already deployed. We set deployed_at to mark them as known. */
        const char *profile_git_oid = hashmap_get(profile_oids, entry->source_profile->name);

        /* Get metadata - from cache if available, otherwise use merged */
        const metadata_t *metadata = NULL;
        if (using_cache) {
            metadata = hashmap_get(metadata_cache, entry->source_profile->name);
        } else {
            metadata = metadata_merged;
        }

        err = sync_entry_to_state(repo, state, entry, profile_git_oid, metadata, time(NULL));

        if (err) {
            err = error_wrap(err, "Failed to sync '%s' to manifest",
                           filesystem_path);
            goto cleanup;
        }

        (*out_synced)++;
    }

    /* 7. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (metadata_merged) metadata_free(metadata_merged);
    if (profile_oids) hashmap_free(profile_oids, free);
    if (fresh_manifest) manifest_free(fresh_manifest);
    if (profiles) profile_list_free(profiles);

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
 *     - For additions/modifications: sync (deployed_at preserved if exists, else set based on lstat())
 *     - For deletions: check for fallbacks, entries remain for orphan detection if none
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
 * Convergence Semantics: Sync updates VWD expected state (git_oid, blob_oid) but doesn't
 *                        deploy to filesystem. User must run 'dotta apply' which uses runtime
 *                        divergence analysis to deploy changes.
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
    const hashmap_t *metadata_cache,
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
            /* No metadata file exists - create empty metadata (old profiles without metadata.json)
             * This is required for metadata resolution (even if file has no custom metadata) */
            error_free(err);
            err = metadata_create_empty(&metadata_merged);
            if (err) {
                err = error_wrap(err, "Failed to create empty metadata");
                goto cleanup;
            }
        }
    }

    /* 1.6. Create keymanager */
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

    /* PHASE 2: COMPUTE DIFF (O(D)) */
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

            /* Sync entry to state, preserving deployed_at for existing files
             *
             * Key: Sync only updates Git, it doesn't deploy to filesystem.
             * User must run 'dotta apply' to actually deploy these changes.
             * We preserve deployed_at to maintain lifecycle tracking. */
            const char *git_oid_str = hashmap_get(profile_oids, profile_name);

            /* Get metadata - from cache if available, otherwise use merged */
            const metadata_t *profile_metadata = NULL;
            if (metadata_cache) {
                profile_metadata = hashmap_get(metadata_cache, profile_name);
            } else {
                profile_metadata = metadata_merged;
            }

            /* Preserve existing deployed_at if file already in manifest */
            time_t deployed_at = 0;
            state_file_entry_t *existing = NULL;
            error_t *get_err = state_get_file(state, filesystem_path, &existing);
            if (get_err == NULL && existing != NULL) {
                deployed_at = existing->deployed_at;
                state_free_entry(existing);
            } else if (get_err) {
                if (get_err->code == ERR_NOT_FOUND) {
                    error_free(get_err);
                } else {
                    err = get_err;
                    free(filesystem_path);
                    goto cleanup;
                }
            }

            err = sync_entry_to_state(
                repo, state, entry, git_oid_str, profile_metadata, deployed_at);

            if (err) {
                err = error_wrap(err, "Failed to sync '%s' to manifest", filesystem_path);
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
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
                entry = &fresh_manifest->entries[idx];
            }

            if (entry && entry->source_profile &&
                strcmp(entry->source_profile->name, profile_name) != 0) {
                /* File exists in another profile (fallback found!)
                 *
                 * Update manifest entry to point to the new profile owner.
                 * Preserve deployed_at to maintain lifecycle tracking. */

                const char *fallback_git_oid = hashmap_get(profile_oids,
                                                           entry->source_profile->name);

                /* Get metadata - from cache if available, otherwise use merged */
                const metadata_t *fallback_metadata = NULL;
                if (metadata_cache) {
                    fallback_metadata = hashmap_get(metadata_cache, entry->source_profile->name);
                } else {
                    fallback_metadata = metadata_merged;
                }

                /* Preserve existing deployed_at when falling back */
                time_t deployed_at = 0;
                state_file_entry_t *existing_fb = NULL;
                error_t *get_err_fb = state_get_file(state, filesystem_path, &existing_fb);
                if (get_err_fb == NULL && existing_fb != NULL) {
                    deployed_at = existing_fb->deployed_at;
                    state_free_entry(existing_fb);
                } else if (get_err_fb) {
                    if (get_err_fb->code == ERR_NOT_FOUND) {
                        error_free(get_err_fb);
                    } else {
                        err = get_err_fb;
                        free(filesystem_path);
                        goto cleanup;
                    }
                }

                err = sync_entry_to_state(
                    repo, state, entry, fallback_git_oid, fallback_metadata, deployed_at);

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
                        fprintf(stderr, "warning: failed to mark '%s' as inactive: %s\n",
                                filesystem_path, error_message(err));
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
    if (new_commit) git_commit_free(new_commit);
    if (old_commit) git_commit_free(old_commit);
    if (config) config_free(config);
    if (km_owned) keymanager_free(km_owned);
    if (metadata_merged) metadata_free(metadata_merged);
    if (profile_oids) hashmap_free(profile_oids, free);
    if (fresh_manifest) manifest_free(fresh_manifest);
    if (profiles) profile_list_free(profiles);

    return err;
}

/**
 * Sync tracked directories from enabled profiles
 *
 * Rebuilds the tracked_directories table from metadata.
 * Called after profile enable/disable/reorder to maintain directory tracking.
 *
 * This is part of the Virtual Working Directory (VWD) consistency model.
 * While files in the manifest have lifecycle states (pending/deployed/removal),
 * directories are simply tracked for profile attribution and metadata preservation.
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

    /* 1. Clear all tracked directories */
    err = state_clear_directories(state);
    if (err) {
        return error_wrap(err, "Failed to clear tracked directories");
    }

    /* 2. Rebuild from each enabled profile */
    for (size_t i = 0; i < string_array_size(enabled_profiles); i++) {
        const char *profile_name = string_array_get(enabled_profiles, i);
        metadata_t *metadata = NULL;

        /* Load metadata (may not exist for old profiles - gracefully skip) */
        err = metadata_load_from_branch(repo, profile_name, &metadata);
        if (err) {
            if (err->code == ERR_NOT_FOUND) {
                /* No metadata file - old profile or no directories tracked */
                error_free(err);
                err = NULL;
                continue;
            }
            /* Other error - fatal */
            return error_wrap(err, "Failed to load metadata for profile '%s'", profile_name);
        }

        /* Extract directories from metadata */
        size_t dir_count = 0;
        const metadata_item_t **directories =
            metadata_get_items_by_kind(metadata, METADATA_ITEM_DIRECTORY, &dir_count);

        /* Add each directory to state with profile attribution */
        for (size_t j = 0; j < dir_count; j++) {
            state_directory_entry_t *state_dir = NULL;

            err = state_directory_entry_create_from_metadata(
                directories[j],
                profile_name,  /* Profile attribution */
                &state_dir
            );

            if (err) {
                free(directories);
                metadata_free(metadata);
                return error_wrap(err, "Failed to create state directory entry for '%s'",
                                directories[j]->key);
            }

            err = state_add_directory(state, state_dir);
            state_free_directory_entry(state_dir);

            if (err) {
                free(directories);
                metadata_free(metadata);
                return error_wrap(err, "Failed to add directory '%s' to state",
                                directories[j]->key);
            }
        }

        /* Free the pointer array (items themselves are owned by metadata) */
        free(directories);
        metadata_free(metadata);
    }

    return NULL;
}
