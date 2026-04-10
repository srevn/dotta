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
 * Synchronize git_oid for all files in a profile to match branch HEAD
 *
 * Maintains critical invariant: all files from profile P have git_oid = P's HEAD.
 *
 * Called after any operation that moves a profile's branch HEAD:
 * - After sync (remote changes pulled)
 * - After add (new files committed)
 * - After update (file changes committed)
 * - After remove (file deletions committed)
 *
 * @param repo Repository (must not be NULL)
 * @param state State (must not be NULL, must have active transaction)
 * @param profile_name Profile name (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *sync_profile_git_oids(
    git_repository *repo,
    state_t *state,
    const char *profile_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profile_name);

    /* Get current HEAD for profile */
    git_oid head_oid;
    error_t *err = get_branch_head_oid(repo, profile_name, &head_oid);
    if (err) {
        return error_wrap(err, "Failed to get HEAD for profile '%s'", profile_name);
    }

    /* Update all entries from this profile */
    return state_update_git_oid_for_profile(state, profile_name, &head_oid);
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
    arena_t *arena,
    hashmap_t **out_map
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out_map);

    error_t *err = NULL;

    /* Create hashmap */
    hashmap_t *map = hashmap_borrow(profiles->count);
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
            hashmap_free(map, arena ? NULL : free);
            return error_wrap(err, "Failed to get HEAD for profile '%s'", profile->name);
        }

        /* Convert to hex string */
        char *oid_str = arena
            ? arena_alloc(arena, GIT_OID_HEXSZ + 1)
            : malloc(GIT_OID_HEXSZ + 1);
        if (!oid_str) {
            hashmap_free(map, arena ? NULL : free);
            return ERROR(ERR_MEMORY, "Failed to allocate oid string");
        }

        git_oid_tostr(oid_str, GIT_OID_HEXSZ + 1, &oid);

        /* Store in map */
        err = hashmap_set(map, profile->name, oid_str);
        if (err) {
            if (!arena) free(oid_str);
            hashmap_free(map, arena ? NULL : free);
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
            /* Symbolic link - mode=0 (no mode to track).
             *
             * Symlink permissions are not deployable:
             * - symlink() syscall has no mode parameter
             * - chmod() on symlink changes target or fails (OS-dependent)
             * - lstat() st_mode varies by OS (Linux: 0777, BSD: 0755)
             *
             * Access control is determined by target, not symlink. */
            type = STATE_FILE_SYMLINK;
            mode = 0;
            break;

        case GIT_FILEMODE_TREE:
            /* Directories should never appear in manifest entries.
             * File entries are extracted from tree walks which skip directories.
             * If we see this, it indicates a bug in the tree traversal logic. */
            return ERROR(
                ERR_INTERNAL, "Unexpected directory in manifest tree entry"
            );

        default:
            /* Unknown/unsupported filemode - defensive programming.
             * Git may add new filemodes in future versions. Fail explicitly
             * rather than silently mishandling. */
            return ERROR(
                ERR_INTERNAL, "Unknown or unsupported git filemode: 0%o",
                filemode
            );
    }

    *out_type = type;
    *out_mode = mode;
    return NULL;
}

/**
 * Enrich profiles with custom prefixes from state
 *
 * Modifies profiles in-place by attaching custom_prefix strings.
 * Caller owns profiles and must free with profile_list_free().
 *
 * Transient Override:
 * Used during profile enable when custom_prefix isn't in state yet.
 * Transient parameters override state for the specified profile, enabling
 * re-enabling a profile with a different prefix.
 *
 * @param state State handle (must not be NULL)
 * @param profiles Profile list to enrich (must not be NULL, modified in-place)
 * @param transient_profile Optional profile for transient override (can be NULL)
 * @param transient_prefix Optional prefix for transient profile (can be NULL)
 * @return Error or NULL on success
 */
static error_t *enrich_profiles_with_prefixes(
    const state_t *state,
    profile_list_t *profiles,
    const char *transient_profile,
    const char *transient_prefix
) {
    CHECK_NULL(state);
    CHECK_NULL(profiles);

    /* Validate transient parameters: both or neither */
    if ((transient_profile && !transient_prefix) ||
        (!transient_profile && transient_prefix)) {
        return ERROR(
            ERR_INVALID_ARG,
            "transient_profile and transient_prefix must be provided together"
        );
    }

    /* Validate non-empty prefix */
    if (transient_prefix && transient_prefix[0] == '\0') {
        return ERROR(
            ERR_INVALID_ARG,
            "transient_prefix must not be empty string"
        );
    }

    /* Early return for empty profile list */
    if (profiles->count == 0) {
        return NULL;
    }

    error_t *err = NULL;
    hashmap_t *prefix_map = NULL;

    /* Query custom prefix configuration from state */
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        return error_wrap(
            err, "Failed to load custom prefix configuration"
        );
    }

    /* Enrich each profile with custom prefix */
    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];
        const char *custom_prefix = NULL;

        /* Check transient override FIRST (takes precedence over state) */
        if (transient_profile && profile->name &&
            strcmp(profile->name, transient_profile) == 0) {
            custom_prefix = transient_prefix;
        } else {
            /* Normal case: query from state */
            custom_prefix = (const char *) hashmap_get(prefix_map, profile->name);
        }

        /* Attach to profile (owned by profile, freed in profile_list_free) */
        if (custom_prefix) {
            profile->custom_prefix = strdup(custom_prefix);
            if (!profile->custom_prefix) {
                hashmap_free(prefix_map, free);
                return ERROR(
                    ERR_MEMORY, "Failed to duplicate custom_prefix for profile '%s'",
                    profile->name
                );
            }
        }
        /* else: custom_prefix remains NULL (normal for home/root profiles) */
    }

    /* Cleanup temporary resources */
    hashmap_free(prefix_map, free);
    return NULL;
}

/**
 * Build manifest from profiles
 *
 * Orchestrates profile loading (Git), prefix enrichment (State),
 * and manifest building (Profiles). This is the "precedence oracle" pattern -
 * profile_build_manifest() determines file ownership, then we use that answer.
 *
 * IMPORTANT: Manifest entries reference profile structures (source_profile field).
 * The profile_list must remain alive while the manifest is in use, otherwise
 * accessing entry->source_profile->name results in use-after-free.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle for prefix resolution (must not be NULL)
 * @param profile_names Profile names to build from (must not be NULL)
 * @param transient_profile Optional profile for transient override (can be NULL)
 * @param transient_prefix Optional prefix for transient profile (can be NULL)
 * @param out_manifest Output manifest (caller must free with manifest_free)
 * @param out_profiles Output profile list (caller must free with profile_list_free, must not be NULL)
 * @return Error or NULL on success
 */
static error_t *build_manifest(
    git_repository *repo,
    const state_t *state,
    const string_array_t *profile_names,
    const char *transient_profile,
    const char *transient_prefix,
    arena_t *arena,
    manifest_t **out_manifest,
    profile_list_t **out_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profile_names);
    CHECK_NULL(out_manifest);
    CHECK_NULL(out_profiles);

    error_t *err = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *manifest = NULL;

    /* Load profiles from Git (profiles module - pure Git operations) */
    err = profile_list_load(
        repo, profile_names->items, profile_names->count, false /* strict */, &profiles
    );
    if (err) {
        return error_wrap(err, "Failed to load profiles for manifest build");
    }

    /* Enrich profiles with prefixes */
    err = enrich_profiles_with_prefixes(
        state, profiles, transient_profile, transient_prefix
    );
    if (err) {
        profile_list_free(profiles);
        return error_wrap(err, "Failed to enrich profiles with prefixes");
    }

    /* Build manifest from enriched profiles (applies precedence rules) */
    err = profile_build_manifest(repo, profiles, arena, &manifest);
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
    time_t deployed_at,
    arena_t *arena
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(manifest_entry);
    CHECK_NULL(git_oid);
    CHECK_NULL(manifest_entry->profile_name);

    error_t *err = NULL;
    char *blob_oid = NULL;
    metadata_item_t *meta_item = NULL;

    /* 1. Extract blob_oid from tree entry */
    const struct git_oid *blob_oid_obj = git_tree_entry_id(manifest_entry->entry);
    if (!blob_oid_obj) {
        return ERROR(
            ERR_INTERNAL, "Tree entry has no OID for '%s'",
            manifest_entry->storage_path
        );
    }

    char oid_str[GIT_OID_HEXSZ + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), blob_oid_obj);

    blob_oid = arena ? arena_strdup(arena, oid_str) : strdup(oid_str);
    if (!blob_oid) {
        return ERROR(ERR_MEMORY, "Failed to allocate blob_oid string");
    }

    /* 2. Get metadata item (may not exist for old profiles) */
    if (metadata) {
        err = metadata_get_item(
            metadata, manifest_entry->storage_path, (const metadata_item_t **) &meta_item
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
    mode_t git_mode = 0;

    err = extract_file_metadata_from_tree_entry(
        manifest_entry->entry, &file_type, &git_mode
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
        .storage_path    = manifest_entry->storage_path,
        .filesystem_path = manifest_entry->filesystem_path,
        .profile         = (char *) manifest_entry->profile_name,
        .type            = file_type,
        .git_oid         = (char *) git_oid,
        .blob_oid        = blob_oid,
        .mode            = mode,
        .owner           = meta_item ? meta_item->owner : NULL,
        .group           = meta_item ? meta_item->group : NULL,
        .encrypted       = (meta_item && meta_item->kind == METADATA_ITEM_FILE)
                         ? meta_item->file.encrypted : false,
        .state           = STATE_ACTIVE,
        .deployed_at     = deployed_at
    };

    /* 6. Write entry to state (INSERT OR REPLACE with caller's deployed_at)
     *
     * Uses INSERT OR REPLACE for atomic upsert - handles both new entries
     * and updates to existing entries. The deployed_at value comes directly
     * from the caller, who is responsible for preservation logic.
     */
    err = state_add_file(state, &state_entry);
    if (err) {
        err = error_wrap(
            err, "Failed to sync manifest entry for %s",
            manifest_entry->storage_path
        );
    }

cleanup:
    if (!arena) free(blob_oid);
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
    metadata_t *metadata = NULL;
    git_oid head_oid;
    char head_oid_str[GIT_OID_HEXSZ + 1];

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Get HEAD oid for profile */
    err = get_branch_head_oid(repo, profile_name, &head_oid);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to get HEAD for profile '%s'", profile_name);
    }
    git_oid_tostr(head_oid_str, sizeof(head_oid_str), &head_oid);

    /* 2. Build manifest with proper transient parameter handling
     *
     * Transient parameters are for temporary custom prefix operations (e.g., dotta add -p temp --prefix /opt),
     * NOT for normal profile enable (which modifies persistent state).
     *
     * Validator requires "both or neither" - only pass transient override when custom_prefix is non-NULL.
     */
    const char *transient_prof = custom_prefix ? profile_name : NULL;
    const char *transient_pfx = custom_prefix;

    err = build_manifest(
        repo, state, enabled_profiles, transient_prof, transient_pfx, arena, &manifest, &profiles
    );
    if (err) {
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

    /* 4. Sync entries owned by this profile (highest precedence) */

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
        err = sync_entry_to_state(repo, state, entry, head_oid_str, metadata, deployed_at, arena);
        if (err) goto cleanup;
    }

    /* Populate output stats if requested */
    if (out_stats) {
        out_stats->total_files = total_files;
        out_stats->already_deployed = already_deployed;
        out_stats->needs_deployment = needs_deployment;
    }

    /* 5. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
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
    hashmap_t *profile_oids = NULL;
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
        err = build_manifest(
            repo, state, remaining_enabled, NULL, NULL, arena, &fallback_manifest,
            &fallback_profiles
        );
        if (err) {
            arena_destroy(arena);
            return error_wrap(err, "Failed to build fallback manifest");
        }
    }

    /* Build profile→oid map for O(1) lookups in fallback processing */
    if (fallback_profiles) {
        err = build_profile_oid_map(repo, fallback_profiles, arena, &profile_oids);
        if (err) {
            err = error_wrap(err, "Failed to build profile OID map");
            goto cleanup;
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
            /* File exists in lower-precedence profile - update to fallback
             *
             * CRITICAL: Use sync_entry_to_state to ensure consistent, correct metadata
             * handling. This reuses the proven logic for:
             *
             * 1. Extracting blob_oid from Git tree entry (content hash)
             * 2. Loading rich metadata from .dotta/metadata.json:
             *    - Custom mode (user's intended permissions, not Git's default)
             *    - Ownership (owner/group for root/ files)
             *    - Encryption flag (from metadata, not Git)
             * 3. Applying metadata precedence (metadata.mode overrides git.mode)
             * 4. Handling NULL values (non-root files, missing metadata)
             * 5. Writing complete, consistent state entry
             *
             * We preserve entry->deployed_at to maintain the file's lifecycle history.
             * The file was deployed under the disabled profile; fallback doesn't change
             * that historical fact.
             *
             * VWD Invariant: Entry metadata must match source profile's Git tree + metadata.json.
             */

            /* Get git_oid from pre-built map (O(1) lookup) */
            const char *fallback_oid_str = hashmap_get(
                profile_oids, fallback->profile_name
            );
            if (!fallback_oid_str) {
                err = ERROR(
                    ERR_INTERNAL, "Missing OID for profile '%s'",
                    fallback->profile_name
                );
                goto cleanup;
            }

            /* Sync to state using proven, tested logic */
            err = sync_entry_to_state(
                repo, state, fallback, fallback_oid_str, fallback_metadata,
                entry->deployed_at, arena
            );
            if (err) {
                err = error_wrap(
                    err, "Failed to sync entry to fallback for %s",
                    entry->storage_path
                );
                goto cleanup;
            }

            /* Track profile reassignment (old_profile metadata)
             *
             * ARCHITECTURE: Separation of concerns between Git-sync and reassignment.
             *
             * sync_entry_to_state() is a low-level Git→State sync primitive used across
             * the codebase. It correctly writes the fallback entry but does NOT set
             * old_profile (Git-sync concern, not profile management semantics).
             *
             * Profile reassignment tracking is a higher-level semantic that provides
             * user visibility into transitions (e.g., "file moved from darwin to global").
             * This layered approach maintains clean separation:
             *   Layer 1: Git→State sync (proven metadata extraction, blob_oid, etc.)
             *   Layer 2: Reassignment tracking (profile change attribution)
             *
             * The old_profile field enables:
             *   - User visibility: status shows "home/.bashrc (darwin → global)"
             *   - Informed decisions: user sees why file is modified before apply
             *   - Audit trail: track reassignment history until deployment acknowledges it
             *
             * Post-deployment: apply clears old_profile after successful deployment,
             * acknowledging the reassignment is complete.
             */
            state_file_entry_t *updated_entry = NULL;
            err = state_get_file(state, entry->filesystem_path, &updated_entry);
            if (err) {
                err = error_wrap(
                    err, "Failed to read entry for reassignment tracking: %s",
                    entry->filesystem_path
                );
                goto cleanup;
            }

            /* Set old_profile to the disabled profile name (reassignment)
             *
             * MEMORY SAFETY:
             * - entry->profile is owned by entries[] array (valid until cleanup)
             * - str_replace_owned() creates independent copy in updated_entry
             * - updated_entry is heap-allocated by state_get_file()
             *
             * INVARIANT: entry->profile is never NULL for manifest entries
             */
            if (!entry->profile) {
                /* Should never happen - defensive check */
                state_free_entry(updated_entry);
                err = ERROR(
                    ERR_INTERNAL, "Manifest entry missing profile field: %s",
                    entry->storage_path
                );
                goto cleanup;
            }

            err = str_replace_owned(&updated_entry->old_profile, entry->profile);
            if (err) {
                state_free_entry(updated_entry);
                err = error_wrap(
                    err, "Failed to set old_profile for %s",
                    entry->storage_path
                );
                goto cleanup;
            }

            /* Persist the reassignment tracking */
            err = state_update_entry(state, updated_entry);
            state_free_entry(updated_entry);  /* Always free, even on success */
            if (err) {
                err = error_wrap(
                    err, "Failed to persist old_profile for %s",
                    entry->storage_path
                );
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
    if (fallback_metadata) metadata_free(fallback_metadata);
    if (profile_oids) hashmap_free(profile_oids, NULL);
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
    metadata_t *metadata = NULL;
    size_t removed_count = 0;
    size_t fallback_count = 0;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Build fresh manifest from current Git state (post-removal) */
    err = build_manifest(
        repo, state, enabled_profiles, NULL, NULL, arena, &fresh_manifest, &profiles
    );
    if (err) {
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

    /* 2. Build profile→oid map (profile_name → git_oid string) for fast lookups */
    err = build_profile_oid_map(repo, profiles, arena, &profile_oids);
    if (err) {
        err = error_wrap(err, "Failed to build profile OID map");
        goto cleanup;
    }

    /* 3. Load merged metadata from enabled profiles for fallback resolution
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

    /* 4. Lookup custom prefix for the removed profile (if in profiles list) */
    const char *removed_profile_custom_prefix = NULL;
    for (size_t i = 0; i < profiles->count; i++) {
        if (strcmp(profiles->profiles[i].name, removed_profile) == 0) {
            removed_profile_custom_prefix = profiles->profiles[i].custom_prefix;
            break;
        }
    }

    /* 5. Process each removed file */
    for (size_t i = 0; i < removed_storage_paths->count; i++) {
        const char *storage_path = removed_storage_paths->items[i];

        /* Use custom prefix from profile (attached by orchestrator) */
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
            /* Fallback found: sync complete entry from fallback profile
             *
             * CRITICAL: Use sync_entry_to_state to ensure consistent metadata.
             * This extracts blob_oid, type, mode from fallback's Git tree entry
             * and applies metadata precedence from .dotta/metadata.json.
             */
            const char *fallback_profile = fallback->profile_name;

            /* Get HEAD oid for fallback profile (hex string) */
            const char *fallback_oid_str = hashmap_get(profile_oids, fallback_profile);
            if (!fallback_oid_str) {
                err = ERROR(
                    ERR_INTERNAL, "Missing OID for profile '%s'",
                    fallback_profile
                );
                state_free_entry(current_entry);
                free(filesystem_path);
                goto cleanup;
            }

            /* Preserve deployed_at (lifecycle history) before sync overwrites entry */
            time_t preserved_deployed_at = current_entry->deployed_at;

            /* Save old profile name for reassignment tracking
             *
             * MEMORY SAFETY: Must copy before sync_entry_to_state, which uses
             * state_add_file (INSERT OR REPLACE) and overwrites the entry.
             * current_entry->profile is guaranteed non-NULL (verified above).
             */
            char *old_profile_name = arena_strdup(arena, current_entry->profile);
            if (!old_profile_name) {
                err = ERROR(ERR_MEMORY, "Failed to copy old profile name");
                state_free_entry(current_entry);
                free(filesystem_path);
                goto cleanup;
            }

            /* Sync complete entry from fallback (proven pattern)
             *
             * sync_entry_to_state correctly:
             * 1. Extracts blob_oid from fallback's Git tree entry
             * 2. Gets metadata (mode, owner, group, encrypted) from merged metadata
             * 3. Uses INSERT OR REPLACE for atomic, complete entry update
             */
            err = sync_entry_to_state(
                repo, state, fallback, fallback_oid_str, metadata, preserved_deployed_at, arena
            );
            if (err) {
                state_free_entry(current_entry);
                free(filesystem_path);
                err = error_wrap(
                    err, "Failed to sync fallback for %s",
                    filesystem_path
                );
                goto cleanup;
            }

            /* Track profile reassignment (old_profile metadata)
             *
             * ARCHITECTURE: Separation of concerns between Git-sync and reassignment.
             *
             * sync_entry_to_state() is a low-level Git→State sync primitive.
             * Reassignment tracking is a higher-level semantic that provides user
             * visibility into transitions (e.g., "file moved from darwin to global").
             *
             * The old_profile field enables:
             *   - User visibility: status shows "home/.bashrc (darwin → global)"
             *   - Informed decisions: user sees why file is modified before apply
             *   - Audit trail: track reassignment history until deployment acknowledges it
             */
            state_file_entry_t *updated_entry = NULL;
            err = state_get_file(state, filesystem_path, &updated_entry);
            if (err) {
                state_free_entry(current_entry);
                free(filesystem_path);
                err = error_wrap(
                    err, "Failed to read entry for old_profile tracking"
                );
                goto cleanup;
            }

            err = str_replace_owned(&updated_entry->old_profile, old_profile_name);
            old_profile_name = NULL;

            if (err) {
                state_free_entry(updated_entry);
                state_free_entry(current_entry);
                free(filesystem_path);
                goto cleanup;
            }

            err = state_update_entry(state, updated_entry);
            state_free_entry(updated_entry);
            if (err) {
                state_free_entry(current_entry);
                free(filesystem_path);
                err = error_wrap(
                    err, "Failed to persist old_profile"
                );
                goto cleanup;
            }

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
     * ALL files from this profile must have their git_oid updated to match the new HEAD,
     * not just the removed files. */
    err = sync_profile_git_oids(repo, state, removed_profile);
    if (err) {
        err = error_wrap(
            err, "Failed to sync git_oid for profile '%s'",
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
    if (profile_oids) hashmap_free(profile_oids, NULL);
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
 *   3. Build profile→oid map for git_oid field
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
    state_file_entry_t *old_entries = NULL;
    size_t old_count = 0;
    hashmap_t *old_map = NULL;
    hashmap_t *profile_oids = NULL;
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
    err = build_manifest(
        repo, state, enabled_profiles, NULL, NULL, arena, &manifest, &profiles
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

    /* 4. Build profile→oid map for git_oid field */
    err = build_profile_oid_map(repo, profiles, arena, &profile_oids);
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

    /* 6. Sync ALL entries from manifest to state (single pass, no filtering)
     *
     * Key difference from manifest_enable_profile: We sync ALL entries because
     * the state is empty (cleared in step 1). No filtering needed - every file
     * in the manifest belongs in the rebuilt state. */
    for (size_t i = 0; i < manifest->count; i++) {
        file_entry_t *entry = &manifest->entries[i];

        /* Get git_oid for this entry's source profile */
        const char *git_oid = hashmap_get(profile_oids, entry->profile_name);
        if (!git_oid) {
            err = ERROR(
                ERR_INTERNAL, "Missing OID for profile '%s'",
                entry->profile_name
            );
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
        err = sync_entry_to_state(repo, state, entry, git_oid, metadata, deployed_at, arena);
        if (err) goto cleanup;
    }

    /* 7. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (old_map) hashmap_free(old_map, NULL);
    if (profile_oids) hashmap_free(profile_oids, NULL);
    if (profiles) profile_list_free(profiles);
    if (metadata) metadata_free(metadata);
    if (manifest) manifest_free(manifest);
    arena_destroy(arena);

    return err;
}

/**
 * Detect which enabled profiles have stale manifest entries
 *
 * Single-pass scan of state entries to find profiles whose stored git_oid
 * doesn't match the profile branch's current HEAD. Mismatch means external
 * Git operations occurred (commit, rebase, etc.) since the last dotta operation.
 *
 * Uses a dedup hashmap to ensure each profile is checked exactly once,
 * regardless of how many entries it has.
 *
 * @param repo Git repository (must not be NULL)
 * @param entries State file entries to scan (must not be NULL if count > 0)
 * @param entry_count Number of entries
 * @param profile_scope Profile scope filter (must not be NULL).
 *                      Only profiles present as keys are checked.
 * @param out_stale Output: hashmap of profile_name -> head_hex for stale profiles.
 *                  NULL if no profiles are stale. Caller frees with hashmap_free(map, free).
 * @return Error or NULL on success
 */
error_t *manifest_detect_stale_profiles(
    git_repository *repo,
    const state_file_entry_t *entries,
    size_t entry_count,
    const hashmap_t *profile_scope,
    hashmap_t **out_stale
) {
    *out_stale = NULL;

    if (entry_count == 0) return NULL;

    error_t *err = NULL;
    hashmap_t *stale_map = NULL;

    /* Track which profiles we've already checked (avoid redundant ref lookups) */
    hashmap_t *checked = hashmap_borrow(16);
    if (!checked) {
        return ERROR(ERR_MEMORY, "Failed to create profile check set");
    }

    for (size_t i = 0; i < entry_count; i++) {
        const state_file_entry_t *entry = &entries[i];

        /* Only check ACTIVE entries with valid profile and git_oid */
        if (!entry->state || strcmp(entry->state, STATE_ACTIVE) != 0) {
            continue;
        }
        if (!entry->profile || !entry->git_oid) {
            continue;
        }
        if (!hashmap_get(profile_scope, entry->profile)) {
            continue;  /* Profile not in scope */
        }

        /* Skip if already checked this profile */
        if (hashmap_get(checked, entry->profile)) {
            continue;
        }

        /* Mark as checked (store non-NULL sentinel) */
        err = hashmap_set(checked, entry->profile, (void *) (uintptr_t) 1);
        if (err) goto cleanup;

        /* Get profile's current HEAD */
        git_oid head_oid;
        err = get_branch_head_oid(repo, entry->profile, &head_oid);
        if (err) {
            /* Branch may have been deleted — skip (safety handles this) */
            error_free(err);
            err = NULL;
            continue;
        }

        char head_hex[GIT_OID_HEXSZ + 1];
        git_oid_tostr(head_hex, sizeof(head_hex), &head_oid);

        if (strcmp(entry->git_oid, head_hex) != 0) {
            /* Profile is stale — HEAD moved since last dotta operation */
            if (!stale_map) {
                stale_map = hashmap_borrow(16);
                if (!stale_map) {
                    err = ERROR(ERR_MEMORY, "Failed to create stale profile map");
                    goto cleanup;
                }
            }

            char *oid_copy = strdup(head_hex);
            if (!oid_copy) {
                err = ERROR(ERR_MEMORY, "Failed to allocate HEAD oid string");
                goto cleanup;
            }

            err = hashmap_set(stale_map, entry->profile, oid_copy);
            if (err) {
                free(oid_copy);
                goto cleanup;
            }
        }
    }

    hashmap_free(checked, NULL);
    *out_stale = stale_map;
    return NULL;

cleanup:
    hashmap_free(checked, NULL);
    hashmap_free(stale_map, free);
    return err;
}

/**
 * Repair stale manifest entries from external Git changes
 *
 * Persistent repair: detects state entries whose git_oid no longer matches
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
    manifest_t *fresh_manifest = NULL;
    profile_list_t *fresh_profiles = NULL;
    hashmap_t *profile_oids = NULL;
    hashmap_t *repaired_paths = NULL;
    metadata_t *metadata = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* Phase 1: Load all state entries and detect staleness (single DB query).
     *
     * Loads all entries once, then single-pass detects stale profiles via
     * manifest_detect_stale_profiles(). Pre-loaded entries are reused in
     * Phase 3, eliminating per-profile DB queries entirely.
     *
     * If no profile is stale, exits immediately (zero cost common case). */
    err = state_get_all_files(state, arena, &all_entries, &all_count);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to load state entries for stale detection");
    }

    /* Build profile scope hashmap for O(1) lookups during detection */
    profile_scope = hashmap_borrow(enabled_profiles->count);
    if (!profile_scope) {
        err = ERROR(ERR_MEMORY, "Failed to create profile scope map");
        goto cleanup;
    }
    for (size_t i = 0; i < enabled_profiles->count; i++) {
        err = hashmap_set(
            profile_scope, enabled_profiles->items[i], (void *) (uintptr_t) 1
        );
        if (err) goto cleanup;
    }

    err = manifest_detect_stale_profiles(
        repo, all_entries, all_count, profile_scope, &stale_profiles
    );
    if (err) {
        err = error_wrap(err, "Failed to detect stale profiles");
        goto cleanup;
    }

    if (!stale_profiles) {
        goto cleanup;  /* All profiles current — nothing to repair */
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
    err = build_manifest(
        repo, state, enabled_profiles, NULL, NULL, arena, &fresh_manifest, &fresh_profiles
    );
    if (err) {
        err = error_wrap(err, "Failed to build fresh manifest for stale repair");
        goto cleanup;
    }

    /* Build profile→oid map for git_oid field updates */
    err = build_profile_oid_map(repo, fresh_profiles, arena, &profile_oids);
    if (err) {
        err = error_wrap(err, "Failed to build profile oid map for repair");
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
            const char *git_oid = hashmap_get(profile_oids, fresh_entry->profile_name);
            if (!git_oid) {
                err = ERROR(
                    ERR_INTERNAL, "Missing OID for profile '%s'",
                    fresh_entry->profile_name
                );
                goto cleanup;
            }

            /* Determine if file content actually changed (blob_oid differs).
             *
             * A profile HEAD can move without changing this file's blob
             * (other files in the commit changed). Distinguishing content
             * changes from git_oid-only refreshes enables:
             *   - Accurate repaired_paths (Path B only verifies content-changed files)
             *   - Accurate stats (user sees real content changes, not bookkeeping)
             *
             * Mirrors the blob_changed check in workspace_build_manifest_from_state()
             * (Path A) for symmetric treatment across both staleness paths.
             */
            bool blob_changed = true;  /* Default: assume changed (safe) */
            const struct git_oid *new_blob_oid = git_tree_entry_id(fresh_entry->entry);
            if (new_blob_oid && entry->blob_oid) {
                char new_blob_hex[GIT_OID_HEXSZ + 1];
                git_oid_tostr(new_blob_hex, sizeof(new_blob_hex), new_blob_oid);
                blob_changed = (strcmp(entry->blob_oid, new_blob_hex) != 0);
            }

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
            if (repaired_paths && entry->blob_oid && blob_changed) {
                /* Heap-allocate: values escape to caller, outliving this arena */
                char *old_blob = strdup(entry->blob_oid);
                if (!old_blob) {
                    err = ERROR(ERR_MEMORY, "Failed to save old blob_oid");
                    goto cleanup;
                }
                err = hashmap_set(repaired_paths, entry->filesystem_path, old_blob);
                if (err) {
                    free(old_blob);
                    goto cleanup;
                }
            }

            err = sync_entry_to_state(
                repo, state, fresh_entry, git_oid, metadata, entry->deployed_at, arena
            );
            if (err) {
                err = error_wrap(
                    err, "Failed to repair stale entry '%s'",
                    entry->storage_path
                );
                goto cleanup;
            }

            /* Track profile reassignment when owning profile shifts during repair.
             *
             * Same read-modify-write pattern as manifest_reorder_profiles,
             * manifest_disable_profile, manifest_remove_files, manifest_sync_diff.
             *
             * entry->profile is still valid (pre-loaded all_entries array, not
             * modified by sync_entry_to_state's DB write). Verified non-NULL
             * by the filter at the top of this loop iteration.
             *
             * Triggers: external git rm (fallback to lower precedence),
             *           external git add (higher precedence takes over). */
            if (strcmp(fresh_entry->profile_name, entry->profile) != 0) {
                state_file_entry_t *updated_entry = NULL;
                err = state_get_file(state, entry->filesystem_path, &updated_entry);
                if (err) {
                    err = error_wrap(
                        err, "Failed to read entry for reassignment tracking"
                    );
                    goto cleanup;
                }

                err = str_replace_owned(&updated_entry->old_profile, entry->profile);
                if (err) {
                    state_free_entry(updated_entry);
                    goto cleanup;
                }

                err = state_update_entry(state, updated_entry);
                state_free_entry(updated_entry);
                if (err) {
                    err = error_wrap(
                        err, "Failed to track reassignment for '%s'",
                        entry->storage_path
                    );
                    goto cleanup;
                }

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

    /* Phase 4: Sync tracked directories to reflect current Git state.
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
    if (stale_profiles) hashmap_free(stale_profiles, free);
    if (profile_scope) hashmap_free(profile_scope, NULL);
    if (profile_oids) hashmap_free(profile_oids, NULL);
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
    state_file_entry_t *old_entries = NULL;
    size_t old_count = 0;
    hashmap_t *old_map = NULL;
    hashmap_t *profile_oids = NULL;
    metadata_t *metadata = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Build new manifest with new precedence order (precedence oracle) */
    err = build_manifest(
        repo, state, new_profile_order, NULL, NULL, arena, &new_manifest, &profiles
    );
    if (err) {
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

    /* 4. Load metadata and build profile→oid map */
    err = metadata_load_from_profiles(repo, new_profile_order, &metadata);
    if (err && err->code != ERR_NOT_FOUND) {
        goto cleanup;
    }
    if (err) {
        error_free(err);
        err = NULL;
    }

    err = build_profile_oid_map(repo, profiles, arena, &profile_oids);
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
            const char *oid_str = hashmap_get(profile_oids, new_entry->profile_name);
            if (!oid_str) {
                err = ERROR(
                    ERR_INTERNAL, "Missing OID for profile '%s'",
                    new_entry->profile_name
                );
                goto cleanup;
            }

            /* New file - deployed_at=0 (never deployed) */
            err = sync_entry_to_state(repo, state, new_entry, oid_str, metadata, 0, arena);
            if (err) {
                goto cleanup;
            }
        } else {
            /* Existing entry - check if owner changed */
            bool owner_changed =
                strcmp(old_entry->profile, new_entry->profile_name) != 0;

            if (owner_changed) {
                /* Owner changed - update entry to new owner */

                /* Get OID from pre-built map (O(1) lookup) */
                const char *oid_str = hashmap_get(profile_oids, new_entry->profile_name);
                if (!oid_str) {
                    err = ERROR(
                        ERR_INTERNAL, "Missing OID for profile '%s'",
                        new_entry->profile_name
                    );
                    goto cleanup;
                }

                /* Sync with new owner, preserve existing deployed_at */
                err = sync_entry_to_state(
                    repo, state, new_entry, oid_str, metadata, old_entry->deployed_at, arena
                );
                if (err) {
                    goto cleanup;
                }

                /* Track profile reassignment for user visibility
                 *
                 * Pattern: Same as manifest_disable_profile and manifest_remove_files.
                 * Enables status to show "home/.bashrc (darwin → global)" after reorder.
                 */
                state_file_entry_t *updated_entry = NULL;
                err = state_get_file(state, new_entry->filesystem_path, &updated_entry);
                if (err) {
                    err = error_wrap(
                        err, "Failed to read entry for old_profile tracking: %s",
                        new_entry->filesystem_path
                    );
                    goto cleanup;
                }

                err = str_replace_owned(&updated_entry->old_profile, old_entry->profile);
                if (err) {
                    state_free_entry(updated_entry);
                    goto cleanup;
                }

                err = state_update_entry(state, updated_entry);
                state_free_entry(updated_entry);
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
    if (profile_oids) hashmap_free(profile_oids, NULL);
    if (old_map) hashmap_free(old_map, NULL);
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
        /* No file items to process, but still sync directories.
         * Handles cases where only directory metadata changed. */
        return manifest_sync_directories(repo, state, enabled_profiles);
    }

    error_t *err = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *fresh_manifest = NULL;
    hashmap_t *profile_oids = NULL;
    metadata_t *metadata_merged = NULL;
    bool using_cache = (metadata_cache != NULL);

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Load enabled profiles from Git */
    err = profile_list_load(
        repo, enabled_profiles->items, enabled_profiles->count, false, &profiles
    );
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to load profiles for bulk sync");
    }

    /* 2. Enrich profiles with prefixes */
    err = enrich_profiles_with_prefixes(state, profiles, NULL, NULL);
    if (err) {
        profile_list_free(profiles);
        arena_destroy(arena);
        return error_wrap(err, "Failed to enrich profiles with prefixes");
    }

    /* 3. Build FRESH manifest from Git (post-commit state) */
    err = profile_build_manifest(repo, profiles, arena, &fresh_manifest);
    if (err) {
        profile_list_free(profiles);
        arena_destroy(arena);
        return error_wrap(err, "Failed to build fresh manifest for bulk sync");
    }

    /* 4. Verify manifest has index (should be populated by profile_build_manifest) */
    if (!fresh_manifest->index) {
        err = ERROR(ERR_INTERNAL, "Fresh manifest missing index");
        goto cleanup;
    }

    /* 5. Build profile oid map (profile_name -> git_oid string) */
    err = build_profile_oid_map(repo, profiles, arena, &profile_oids);
    if (err) {
        err = error_wrap(err, "Failed to build profile oid map");
        goto cleanup;
    }

    /* 6. Load fresh metadata if not provided (NULL handling)
     *
     * CRITICAL: If metadata_cache is NULL, load merged metadata from Git.
     * This ensures we have current metadata including all newly-committed files.
     *
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

    /* 7. Process each item */
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
                /* Fallback exists - update to fallback profile */
                const char *git_oid = hashmap_get(profile_oids, fallback->profile_name);
                if (!git_oid) {
                    err = ERROR(
                        ERR_INTERNAL, "Missing OID for profile '%s'",
                        fallback->profile_name
                    );
                    goto cleanup;
                }

                /* Get metadata - from cache if available, otherwise use merged */
                const metadata_t *metadata = NULL;
                if (using_cache) {
                    metadata = hashmap_get(metadata_cache, fallback->profile_name);
                } else {
                    metadata = metadata_merged;
                }

                /* Preserve existing deployed_at and track old_profile when falling back */
                time_t deployed_at = 0;
                char *old_profile_name = NULL;
                state_file_entry_t *existing_entry = NULL;
                error_t *get_err1 = state_get_file(
                    state, item->filesystem_path, &existing_entry
                );
                if (get_err1 == NULL && existing_entry != NULL) {
                    deployed_at = existing_entry->deployed_at;
                    /* Save old profile for reassignment tracking */
                    if (existing_entry->profile) {
                        old_profile_name = arena_strdup(arena, existing_entry->profile);
                    }
                    state_free_entry(existing_entry);
                } else if (get_err1) {
                    if (get_err1->code == ERR_NOT_FOUND) {
                        error_free(get_err1);
                    } else {
                        err = get_err1;
                        goto cleanup;
                    }
                }

                err = sync_entry_to_state(
                    repo, state, fallback, git_oid, metadata, deployed_at, arena
                );
                if (err) {
                    err = error_wrap(
                        err, "Failed to sync fallback for '%s'",
                        item->filesystem_path
                    );
                    goto cleanup;
                }

                /* Update old_profile if profile was reassigned */
                if (old_profile_name) {
                    state_file_entry_t *updated_entry = NULL;
                    error_t *get_err2 = state_get_file(
                        state, item->filesystem_path, &updated_entry
                    );
                    if (get_err2 == NULL && updated_entry != NULL) {
                        /* Set old_profile to track reassignment */
                        err = str_replace_owned(&updated_entry->old_profile, old_profile_name);
                        if (!err) {
                            err = state_update_entry(state, updated_entry);
                        }
                        state_free_entry(updated_entry);
                    } else if (get_err2) {
                        error_free(get_err2);
                    }

                    if (err) {
                        err = error_wrap(
                            err, "Failed to track reassignment for '%s'",
                            item->filesystem_path
                        );
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
            const char *git_oid = hashmap_get(profile_oids, item->profile);
            if (!git_oid) {
                err = ERROR(
                    ERR_INTERNAL, "Missing OID for profile '%s'",
                    item->profile
                );
                goto cleanup;
            }

            /* Get metadata - from cache if available, otherwise use merged */
            const metadata_t *metadata = NULL;
            if (using_cache) {
                metadata = hashmap_get(metadata_cache, item->profile);
            } else {
                metadata = metadata_merged;
            }

            err = sync_entry_to_state(repo, state, entry, git_oid, metadata, time(NULL), arena);
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

    /* After updating files, synchronize git_oid for ALL files from affected profiles.
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

    /* Sync git_oid for each unique profile */
    for (size_t i = 0; i < updated_profiles->count; i++) {
        const char *prof = updated_profiles->items[i];
        err = sync_profile_git_oids(repo, state, prof);
        if (err) {
            string_array_free(updated_profiles);
            err = error_wrap(err, "Failed to sync git_oid for profile '%s'", prof);
            goto cleanup;
        }
    }

    string_array_free(updated_profiles);

    /* 8. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (metadata_merged) metadata_free(metadata_merged);
    if (profile_oids) hashmap_free(profile_oids, NULL);
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

    if (filesystem_paths->count == 0) {
        /* No files to add, but still sync directories.
         * Handles directory-only adds where filesystem_paths
         * is empty but metadata.json has tracked directories. */
        return manifest_sync_directories(repo, state, enabled_profiles);
    }

    error_t *err = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *fresh_manifest = NULL;
    hashmap_t *profile_oids = NULL;
    metadata_t *metadata_merged = NULL;
    bool using_cache = (metadata_cache != NULL);

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    /* 1. Load enabled profiles from Git */
    err = profile_list_load(
        repo, enabled_profiles->items, enabled_profiles->count, false, &profiles
    );
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to load profiles for bulk sync");
    }

    /* 2. Enrich profiles with prefixes */
    err = enrich_profiles_with_prefixes(state, profiles, NULL, NULL);
    if (err) {
        profile_list_free(profiles);
        arena_destroy(arena);
        return error_wrap(err, "Failed to enrich profiles with prefixes");
    }

    /* 3. Build FRESH manifest from Git (post-commit state) */
    err = profile_build_manifest(repo, profiles, arena, &fresh_manifest);
    if (err) {
        profile_list_free(profiles);
        arena_destroy(arena);
        return error_wrap(err, "Failed to build fresh manifest for bulk sync");
    }

    /* 4. Verify manifest has index (should be populated by profile_build_manifest) */
    if (!fresh_manifest->index) {
        err = ERROR(ERR_INTERNAL, "Fresh manifest missing index");
        goto cleanup;
    }

    /* 5. Build profile oid map (profile_name -> git_oid string) */
    err = build_profile_oid_map(repo, profiles, arena, &profile_oids);
    if (err) {
        err = error_wrap(err, "Failed to build profile oid map");
        goto cleanup;
    }

    /* 6. Load fresh metadata if not provided (NULL handling)
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

    /* 7. Process each file */
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
        const char *profile_git_oid = hashmap_get(profile_oids, entry->profile_name);

        /* Get metadata - from cache if available, otherwise use merged */
        const metadata_t *metadata = NULL;
        if (using_cache) {
            metadata = hashmap_get(metadata_cache, entry->profile_name);
        } else {
            metadata = metadata_merged;
        }

        err = sync_entry_to_state(repo, state, entry, profile_git_oid, metadata, time(NULL), arena);

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
     * ALL files from this profile must have their git_oid updated to match the new HEAD,
     * not just the newly added files. */
    err = sync_profile_git_oids(repo, state, profile_name);
    if (err) {
        err = error_wrap(
            err, "Failed to sync git_oid for profile '%s'",
            profile_name
        );
        goto cleanup;
    }

    /* 8. Sync tracked directories */
    err = manifest_sync_directories(repo, state, enabled_profiles);
    if (err) {
        goto cleanup;
    }

cleanup:
    if (metadata_merged) metadata_free(metadata_merged);
    if (profile_oids) hashmap_free(profile_oids, NULL);
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
 *     - Load or use cached metadata
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
 * Convergence: Sync updates VWD expected state (git_oid, blob_oid) but doesn't
 * Semantics    deploy to filesystem. User must run 'dotta apply' which uses runtime
 *              divergence analysis to deploy changes.
 *
 * @param repo Repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param profile_name Profile being synced (must not be NULL)
 * @param old_oid Old commit before sync (must not be NULL)
 * @param new_oid New commit after sync (must not be NULL)
 * @param enabled_profiles All enabled profiles for precedence (must not be NULL)
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
    hashmap_t *profile_oids = NULL;
    metadata_t *metadata_merged = NULL;
    git_tree *old_tree = NULL;
    git_tree *new_tree = NULL;
    git_diff *diff = NULL;

    arena_t *arena = arena_create(64 * 1024);
    if (!arena) return ERROR(ERR_MEMORY, "Failed to create manifest arena");

    size_t synced = 0, removed = 0, fallbacks = 0, skipped = 0;

    /* PHASE 1: BUILD CONTEXT (O(M)) */
    /* 1.0. Load all enabled profiles from Git (current state) */
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

    /* 1.1. Enrich profiles with prefixes */
    err = enrich_profiles_with_prefixes(state, profiles, NULL, NULL);
    if (err) {
        err = error_wrap(err, "Failed to enrich profiles with prefixes");
        goto cleanup;
    }

    /* 1.2. Build FRESH manifest from Git (post-sync state)
     *
     * This reflects the NEW state after sync. We build from current branch HEADs,
     * not from specific OIDs, because profile_build_manifest() reads current state.
     * This is correct because after pull/rebase/merge, branch HEAD already points
     * to the new commit. */
    err = profile_build_manifest(repo, profiles, arena, &fresh_manifest);
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
    err = build_profile_oid_map(repo, profiles, arena, &profile_oids);
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

    /* Lookup custom prefix for the synced profile (if in profiles list) */
    const char *synced_profile_custom_prefix = NULL;
    for (size_t i = 0; i < profiles->count; i++) {
        if (strcmp(profiles->profiles[i].name, profile_name) == 0) {
            synced_profile_custom_prefix = profiles->profiles[i].custom_prefix;
            break;
        }
    }

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

            /* Sync entry to state, preserving deployed_at for existing files
             *
             * Key: Sync only updates Git, it doesn't deploy to filesystem.
             * User must run 'dotta apply' to actually deploy these changes.
             * We preserve deployed_at to maintain lifecycle tracking. */
            const char *git_oid_str = hashmap_get(profile_oids, profile_name);
            if (!git_oid_str) {
                err = ERROR(
                    ERR_INTERNAL, "Missing OID for profile '%s'",
                    profile_name
                );
                free(filesystem_path);
                goto cleanup;
            }

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
                repo, state, entry, git_oid_str, profile_metadata, deployed_at, arena
            );
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
                /* File exists in another profile (fallback found!)
                 *
                 * Update manifest entry to point to the new profile owner.
                 * Preserve deployed_at to maintain lifecycle tracking. */

                const char *fallback_git_oid = hashmap_get(
                    profile_oids,
                    entry->profile_name
                );
                if (!fallback_git_oid) {
                    err = ERROR(
                        ERR_INTERNAL, "Missing OID for profile '%s'",
                        entry->profile_name
                    );
                    free(filesystem_path);
                    goto cleanup;
                }

                /* Get metadata - from cache if available, otherwise use merged */
                const metadata_t *fallback_metadata = NULL;
                if (metadata_cache) {
                    fallback_metadata = hashmap_get(metadata_cache, entry->profile_name);
                } else {
                    fallback_metadata = metadata_merged;
                }

                /* Preserve existing deployed_at and track old_profile when falling back */
                time_t deployed_at = 0;
                char *old_profile_name = NULL;
                state_file_entry_t *existing_fb = NULL;
                error_t *get_err_fb = state_get_file(state, filesystem_path, &existing_fb);
                if (get_err_fb == NULL && existing_fb != NULL) {
                    deployed_at = existing_fb->deployed_at;
                    /* Save old profile for reassignment tracking */
                    if (existing_fb->profile) {
                        old_profile_name = arena_strdup(arena, existing_fb->profile);
                    }
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
                    repo, state, entry, fallback_git_oid, fallback_metadata, deployed_at, arena
                );
                if (err) {
                    err = error_wrap(
                        err, "Failed to sync fallback for '%s'",
                        filesystem_path
                    );
                    free(filesystem_path);
                    goto cleanup;
                }

                /* Track profile reassignment for user visibility
                 *
                 * Pattern: Same as manifest_update_files and manifest_disable_profile.
                 * Enables status to show "home/.bashrc (darwin → global)" after sync.
                 */
                if (old_profile_name) {
                    state_file_entry_t *updated_entry = NULL;
                    error_t *get_err2 = state_get_file(state, filesystem_path, &updated_entry);
                    if (get_err2 == NULL && updated_entry != NULL) {
                        err = str_replace_owned(&updated_entry->old_profile, old_profile_name);
                        if (!err) {
                            err = state_update_entry(state, updated_entry);
                        }
                        state_free_entry(updated_entry);
                    } else if (get_err2) {
                        error_free(get_err2);
                    }

                    if (err) {
                        err = error_wrap(
                            err, "Failed to track reassignment for '%s'",
                            filesystem_path
                        );
                        free(filesystem_path);
                        goto cleanup;
                    }
                }

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

    /* Synchronize git_oid for ALL files from this profile.
     * After sync, the branch HEAD has moved to new_oid. ALL files from this
     * profile must have their git_oid updated to match, not just files in the diff.
     * This maintains the invariant: all files from profile P have git_oid = P's HEAD. */
    err = sync_profile_git_oids(repo, state, profile_name);
    if (err) {
        err = error_wrap(
            err, "Failed to sync git_oid for profile '%s'",
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
    if (metadata_merged) metadata_free(metadata_merged);
    if (profile_oids) hashmap_free(profile_oids, NULL);
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
    free(directories);
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
