/**
 * workspace.c - Workspace abstraction implementation
 *
 * Manages three-state consistency: Profile (git), Deployment (state.db), Filesystem (disk).
 * Detects and categorizes divergence to prevent data loss and enable safe operations.
 *
 * METADATA ARCHITECTURE:
 * ===================================
 * Profiles layer with precedence (global < OS < host). The merged_metadata map
 * pre-applies precedence during workspace_load(), ensuring all analysis functions
 * compare against the "winning" metadata. This prevents false divergence when
 * multiple profiles track the same path with different metadata.
 *
 * Key Design:
 * - merged_metadata: Single hashmap with precedence already applied
 * - Maps: key -> metadata_item_t* (borrowed pointers from metadata_cache)
 * - Key interpretation: FILES use storage_path, DIRECTORIES use filesystem_path
 * - Built once in workspace_load(), used by all analysis functions
 */

#include "workspace.h"

#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "core/ignore.h"
#include "crypto/encryption.h"
#include "crypto/keymanager.h"
#include "crypto/policy.h"
#include "infra/content.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/string.h"

/**
 * Merged metadata entry (internal structure)
 *
 * Pairs a metadata item with its source profile name to track provenance
 * after profile precedence is applied.
 */
typedef struct {
    const metadata_item_t *item;      /* Borrowed from metadata_cache */
    const char *profile_name;         /* Which profile provided this (borrowed) */
} merged_metadata_entry_t;

/**
 * Workspace structure
 *
 * Contains indexed views of all three states plus divergence analysis.
 * Uses hashmaps for O(1) lookups during analysis.
 */
struct workspace {
    git_repository *repo;            /* Borrowed reference */

    /* State data */
    manifest_t *manifest;            /* Profile state (owned) */
    state_t *state;                  /* Deployment state (owned or borrowed) */
    bool owns_state;                 /* True if state is owned, false if borrowed */
    profile_list_t *profiles;        /* Selected profiles for this workspace (borrowed) */
    hashmap_t *profile_index;        /* Maps profile_name -> profile_t* (for O(1) lookup) */

    /* Encryption and caching infrastructure */
    keymanager_t *keymanager;        /* Borrowed from global */
    content_cache_t *content_cache;  /* Owned - caches decrypted content */
    hashmap_t *metadata_cache;       /* Owned - maps profile_name -> metadata_t* */

    /* Unified metadata view with profile precedence applied */
    hashmap_t *merged_metadata;      /* Owned map: key -> merged_metadata_entry_t* */
    merged_metadata_entry_t *merged_entries;  /* Owned array of entries */
    size_t merged_count;
    size_t merged_capacity;

    /* Divergence tracking */
    workspace_item_t *diverged;      /* Array of diverged items (files and directories) */
    size_t diverged_count;
    size_t diverged_capacity;
    hashmap_t *diverged_index;       /* Maps filesystem_path -> workspace_item_t* */

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

    ws->profile_index = hashmap_create(32);  /* Initial capacity for profiles */
    if (!ws->profile_index) {
        free(ws);
        return ERROR(ERR_MEMORY, "Failed to create profile index");
    }

    ws->diverged_index = hashmap_create(256);  /* Initial capacity */
    if (!ws->diverged_index) {
        hashmap_free(ws->profile_index, NULL);
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
            free(ws);
            return error_wrap(err, "Failed to index profile");
        }
    }

    ws->diverged = NULL;
    ws->diverged_count = 0;
    ws->diverged_capacity = 0;

    ws->status = WORKSPACE_CLEAN;
    ws->status_computed = false;

    *out = ws;
    return NULL;
}

/**
 * Check for metadata (mode and ownership) divergence (optimized with stat propagation)
 *
 * Compares filesystem metadata with stored metadata to detect changes in
 * permissions (mode) and ownership (user/group). Always checks both mode and
 * ownership independently, setting flags for each.
 *
 * Works for both FILE and DIRECTORY kinds - uses only common fields (mode, owner, group).
 *
 * @param item Metadata item (FILE or DIRECTORY, must not be NULL)
 * @param fs_path Filesystem path to check (must not be NULL)
 * @param st File stat data (must not be NULL, pre-captured by caller)
 * @param out_mode_differs Output flag for mode divergence (must not be NULL)
 * @param out_ownership_differs Output flag for ownership divergence (must not be NULL)
 * @return Error or NULL on success
 */
error_t *check_item_metadata_divergence(
    const metadata_item_t *item,
    const char *fs_path,
    const struct stat *st,
    bool *out_mode_differs,
    bool *out_ownership_differs
) {
    CHECK_NULL(item);
    CHECK_NULL(fs_path);
    CHECK_NULL(st);
    CHECK_NULL(out_mode_differs);
    CHECK_NULL(out_ownership_differs);

    /* Clear output flags */
    *out_mode_differs = false;
    *out_ownership_differs = false;

    /* Use provided stat (no syscall - caller already stat'd via compare) */
    mode_t actual_mode = st->st_mode & 0777;

    /* Check full mode (all permission bits, not just executable) */
    if (actual_mode != item->mode) {
        *out_mode_differs = true;
    }

    /* Check ownership (always check, no early return).
     * Only when running as root AND item has ownership.
     * Use effective UID (geteuid) to check privilege, not real UID (getuid).
     * This correctly detects whether we have the capability to read ownership. */
    bool running_as_root = (geteuid() == 0);
    bool has_ownership = (item->owner != NULL || item->group != NULL);

    if (running_as_root && has_ownership) {
        bool owner_differs = false;
        bool group_differs = false;

        /* Check owner independently */
        if (item->owner) {
            struct passwd *pwd = getpwuid(st->st_uid);
            if (pwd && pwd->pw_name) {
                if (strcmp(item->owner, pwd->pw_name) != 0) {
                    owner_differs = true;
                }
            }
            /* If getpwuid fails, skip check (graceful degradation) */
        }

        /* Check group independently - no short-circuit */
        if (item->group) {
            struct group *grp = getgrgid(st->st_gid);
            if (grp && grp->gr_name) {
                if (strcmp(item->group, grp->gr_name) != 0) {
                    group_differs = true;
                }
            }
            /* If getgrgid fails, skip check (graceful degradation) */
        }

        if (owner_differs || group_differs) {
            *out_ownership_differs = true;
        }
    }

    return NULL;
}

/**
 * Add diverged item to workspace
 *
 * Adds a file or directory with divergence to the workspace tracking list.
 *
 * @param ws Workspace context (must not be NULL)
 * @param filesystem_path Target path on filesystem (must not be NULL)
 * @param storage_path Path in profile (can be NULL for directories)
 * @param profile Source profile name (can be NULL for orphans)
 * @param old_profile Previous profile from state (can be NULL, takes ownership)
 * @param all_profiles All profiles containing file (can be NULL, deep copied)
 * @param state Where the item exists (deployed/undeployed/etc.)
 * @param divergence What's wrong with it (bit flags, can combine)
 * @param item_kind FILE or DIRECTORY (explicit type)
 * @param in_profile Exists in profile branch
 * @param in_state Exists in deployment state (must be false for directories)
 * @param on_filesystem Exists on actual filesystem
 * @param profile_enabled Is source profile in enabled list?
 * @param profile_changed Has owning profile changed vs state?
 */
static error_t *workspace_add_diverged(
    workspace_t *ws,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    char *old_profile,
    const string_array_t *all_profiles,
    workspace_state_t state,
    divergence_type_t divergence,
    workspace_item_kind_t item_kind,
    bool in_profile,
    bool in_state,
    bool on_filesystem,
    bool profile_enabled,
    bool profile_changed
) {
    CHECK_NULL(ws);
    CHECK_NULL(filesystem_path);

    /* Validate invariant: directories never in deployment state */
    if (item_kind == WORKSPACE_ITEM_DIRECTORY && in_state) {
        return ERROR(ERR_INTERNAL,
            "Invariant violation: directory '%s' marked as in_state (directories never in deployment state)",
            filesystem_path);
    }

    /* Grow array if needed */
    if (ws->diverged_count >= ws->diverged_capacity) {
        size_t new_capacity = ws->diverged_capacity == 0 ? 32 : ws->diverged_capacity * 2;
        workspace_item_t *new_diverged = realloc(ws->diverged,
                                                  new_capacity * sizeof(workspace_item_t));
        if (!new_diverged) {
            return ERROR(ERR_MEMORY, "Failed to grow diverged array");
        }
        ws->diverged = new_diverged;
        ws->diverged_capacity = new_capacity;
    }

    /* Add entry */
    workspace_item_t *entry = &ws->diverged[ws->diverged_count];
    memset(entry, 0, sizeof(workspace_item_t));

    entry->filesystem_path = strdup(filesystem_path);
    entry->storage_path = storage_path ? strdup(storage_path) : NULL;
    entry->profile = profile ? strdup(profile) : NULL;
    entry->metadata_profile = NULL;  /* Will be set below if metadata exists */

    /* Lookup profile pointer from profile_index (borrowed, can be NULL if profile not in enabled set) */
    entry->source_profile = profile ? hashmap_get(ws->profile_index, profile) : NULL;

    entry->state = state;
    entry->divergence = divergence;
    entry->item_kind = item_kind;
    entry->in_profile = in_profile;
    entry->in_state = in_state;
    entry->on_filesystem = on_filesystem;
    entry->profile_enabled = profile_enabled;
    entry->profile_changed = profile_changed;
    entry->old_profile = old_profile;  /* Takes ownership (can be NULL) */

    /* Deep copy all_profiles if present (NULL optimization for single-profile files) */
    entry->all_profiles = string_array_clone(all_profiles);
    if (all_profiles && !entry->all_profiles) {
        free(entry->filesystem_path);
        free(entry->storage_path);
        free(entry->profile);
        free(entry->old_profile);
        return ERROR(ERR_MEMORY, "Failed to clone all_profiles array");
    }

    if (!entry->filesystem_path ||
        (storage_path && !entry->storage_path) ||
        (profile && !entry->profile)) {
        free(entry->filesystem_path);
        free(entry->storage_path);
        free(entry->profile);
        free(entry->old_profile);  /* Clean up if early return */
        string_array_free(entry->all_profiles);  /* Clean up all_profiles */
        return ERROR(ERR_MEMORY, "Failed to allocate diverged entry");
    }

    /* Check if this item has metadata in merged_metadata and populate provenance */
    if (ws->merged_metadata) {
        const char *lookup_key = (item_kind == WORKSPACE_ITEM_FILE)
            ? storage_path
            : filesystem_path;

        if (lookup_key) {
            const merged_metadata_entry_t *meta_entry = hashmap_get(ws->merged_metadata, lookup_key);
            if (meta_entry && meta_entry->profile_name) {
                entry->metadata_profile = strdup(meta_entry->profile_name);
                if (!entry->metadata_profile) {
                    free(entry->filesystem_path);
                    free(entry->storage_path);
                    free(entry->profile);
                    free(entry->old_profile);
                    string_array_free(entry->all_profiles);
                    return ERROR(ERR_MEMORY, "Failed to allocate metadata_profile");
                }
            }
        }
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

    return NULL;
}

/**
 * Analyze single file for divergence
 *
 * ARCHITECTURE: Filesystem-first comparison logic.
 * Compares content for ALL files that exist on filesystem (deployed AND undeployed).
 * This prevents data loss by detecting conflicts before deployment.
 *
 * Example scenario this fixes:
 * - Profile has: home/.bashrc
 * - State: empty (never deployed)
 * - Filesystem: ~/.bashrc exists with different content
 * - Old logic: UNDEPLOYED state (no comparison!) → would overwrite on deploy
 * - New logic: UNDEPLOYED state + DIVERGENCE_CONTENT flag → blocks deploy
 */
/**
 * Analyze divergence for a single file using VWD cache
 *
 * This function uses the VWD (Virtual Working Directory) cache stored in
 * manifest_entry to perform divergence detection without database queries.
 * All expected state (content_hash, type, deployed_at, etc.) is cached in
 * the manifest entry during workspace load.
 *
 * @param ws Workspace (must not be NULL)
 * @param manifest_entry Manifest entry with VWD cache (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *analyze_file_divergence(
    workspace_t *ws,
    const file_entry_t *manifest_entry
) {
    CHECK_NULL(ws);
    CHECK_NULL(manifest_entry);

    const char *fs_path = manifest_entry->filesystem_path;
    const char *storage_path = manifest_entry->storage_path;
    const char *profile = manifest_entry->source_profile->name;

    bool in_profile = true;  /* By definition - we're iterating manifest */

    /* Determine if entry came from state database using VWD cache
     *
     * If manifest was built from state, VWD fields are populated (content_hash != NULL).
     * If manifest was built from Git, VWD fields are NULL/0.
     *
     * content_hash is the most reliable indicator because it's always populated
     * during sync_entry_to_state() when writing to the manifest table.
     */
    bool in_state = (manifest_entry->content_hash != NULL);

    bool on_filesystem = fs_lexists(fs_path);

    /* Divergence accumulator (bit flags, can combine) */
    divergence_type_t divergence = DIVERGENCE_NONE;

    /* State will be determined in PHASE 2 based on deployment status */
    workspace_state_t state = WORKSPACE_STATE_DEPLOYED;

    /* PHASE 1: Filesystem content analysis (if file exists)
     * Hash-based comparison for fast divergence detection.
     *
     * VWD Architecture: The manifest table stores expected state from Git
     * (content_hash computed during profile enable). We compute the hash from
     * the filesystem file and compare.
     *
     * This provides:
     * - O(1) comparison (hash comparison vs buffer comparison)
     * - No redundant Git tree walking (expected state pre-cached in manifest)
     * - Transparent decryption (content_hash_file handles encrypted files)
     *
     * Note: For orphan detection, we DO load git_tree_entry from Git to get
     * file metadata, but for divergence analysis we use cached content_hash.
     */
    if (on_filesystem) {
        /* Capture stat early for metadata checking and permission analysis */
        struct stat file_stat;
        if (lstat(fs_path, &file_stat) != 0) {
            return ERROR(ERR_FS, "Failed to stat '%s': %s", fs_path, strerror(errno));
        }

        /* Get metadata for hash computation (needed for decryption) and metadata checking */
        const metadata_t *metadata = ws_get_metadata(ws, manifest_entry->source_profile->name);
        if (!metadata) {
            return ERROR(ERR_INTERNAL,
                "Metadata cache missing entry for profile '%s' (invariant violation)",
                manifest_entry->source_profile->name);
        }

        /* Hash-based content comparison using VWD cache
         *
         * The content_hash from VWD cache represents expected state from the
         * manifest table. We compare it against the filesystem file's hash. */
        if (manifest_entry->content_hash) {
            /* Compute hash from filesystem file (with transparent decryption) */
            char *fs_content_hash = NULL;
            error_t *err = content_hash_file(
                fs_path,
                storage_path,
                profile,
                metadata,
                ws->keymanager,
                &fs_content_hash
            );

            if (err) {
                return error_wrap(err, "Failed to compute content hash for '%s'", fs_path);
            }

            /* Compare hashes: VWD cache (expected) vs filesystem (actual) */
            if (strcmp(manifest_entry->content_hash, fs_content_hash) != 0) {
                /* Content differs - accumulate CONTENT flag */
                divergence |= DIVERGENCE_CONTENT;
            }

            free(fs_content_hash);
        }

        /* PERMISSION CHECKING: Two-phase approach
         *
         * PHASE A: Git filemode (executable bit)
         *   - Always check, even without metadata
         *   - Catches: file is 0755 in git but 0644 on disk (or vice versa)
         *   - Fixes bug: files without metadata losing exec bit divergence
         *
         * PHASE B: Full metadata (all permission bits + ownership)
         *   - Only if metadata exists for this file
         *   - Catches: granular changes like 0600→0644, ownership changes
         */

        /* PHASE A: Check filemode (executable bit) from VWD cache */
        if (in_state) {
            /* Get executable bit from VWD cache type field.
             * manifest_entry->type is STATE_FILE_EXECUTABLE or STATE_FILE_REGULAR. */
            bool expect_exec = (manifest_entry->type == STATE_FILE_EXECUTABLE);
            bool is_exec = fs_stat_is_executable(&file_stat);

            if (expect_exec != is_exec) {
                /* Executable bit differs between expected (VWD cache) and filesystem */
                divergence |= DIVERGENCE_MODE;
            }
        }
        /* If not in_state: skip exec bit check (manifest from Git, not state) */

        /* PHASE B: Check full metadata (mode and ownership) if available */
        if (metadata) {
            const metadata_item_t *meta_entry = NULL;
            error_t *meta_err = metadata_get_item(metadata, storage_path, &meta_entry);

            if (meta_err == NULL && meta_entry) {
                /* Validate kind (should be FILE) */
                if (meta_entry->kind != METADATA_ITEM_FILE) {
                    error_free(meta_err);
                    return ERROR(ERR_INTERNAL,
                        "Expected FILE metadata for '%s', got DIRECTORY",
                        storage_path);
                }

                /* Check FULL mode (all 9 permission bits) and ownership.
                 * This may detect additional divergence beyond executable bit.
                 *
                 * Examples:
                 * - Phase A passed (both non-exec), but file is 0600 in metadata, 0644 on disk
                 * - Phase A detected exec bit diff, metadata also detects group/other bits differ
                 *
                 * The |= operator means we accumulate flags, never lose information. */
                bool mode_differs = false;
                bool ownership_differs = false;
                error_t *check_err = check_item_metadata_divergence(
                    meta_entry, fs_path, &file_stat,
                    &mode_differs, &ownership_differs);

                if (check_err) {
                    error_free(meta_err);
                    return error_wrap(check_err,
                        "Failed to check metadata for '%s'", fs_path);
                }

                /* Accumulate metadata divergence flags */
                if (mode_differs) divergence |= DIVERGENCE_MODE;
                if (ownership_differs) divergence |= DIVERGENCE_OWNERSHIP;
            }

            error_free(meta_err);
        }
    }

    /* PHASE 2: Reality-based classification
     *
     * SCOPE-BASED ARCHITECTURE:
     * Use deployed_at timestamp to distinguish lifecycle states.
     *
     * deployed_at semantics (from SCOPE_BASED_ARCHITECTURE_PLAN.md Annex A):
     * - deployed_at = 0 → File never deployed by dotta
     * - deployed_at > 0 → File known to dotta (deployed or pre-existing)
     *
     * Classification:
     * 1. File missing + deployed_at = 0 → UNDEPLOYED (needs initial deployment)
     * 2. File missing + deployed_at > 0 → DELETED (was deployed, needs restoration)
     * 3. File present → DEPLOYED (may have divergence)
     */
    if (!on_filesystem) {
        /* File in manifest but missing from filesystem */

        /* Use deployed_at from VWD cache to distinguish never-deployed vs deleted
         *
         * The VWD cache stores the lifecycle timestamp:
         * - deployed_at = 0: File never deployed by dotta
         * - deployed_at > 0: File was deployed or known to dotta */
        if (in_state && manifest_entry->deployed_at > 0) {
            /* File was deployed/known (deployed_at > 0), now deleted */
            state = WORKSPACE_STATE_DELETED;
        } else {
            /* File never deployed (deployed_at = 0) or not in state (manifest from Git) */
            state = WORKSPACE_STATE_UNDEPLOYED;
        }

        /* Clear divergence flags - can't detect divergence on missing files */
        divergence = DIVERGENCE_NONE;
    } else {
        /* File in manifest and on filesystem */
        state = WORKSPACE_STATE_DEPLOYED;
        /* Keep accumulated divergence flags from Phase 1 */
    }

    /* PHASE 3: Profile ownership change detection
     *
     * Check VWD cache for old_profile to detect ownership changes.
     * old_profile is set by manifest layer when file ownership changes
     * (e.g., removed from high-precedence profile, fell back to lower).
     *
     * The old_profile field is persisted in the database and populated
     * into the VWD cache during workspace_build_manifest_from_state().
     * It remains set until acknowledged by successful deployment.
     */
    bool profile_changed = (manifest_entry->old_profile != NULL);
    char *old_profile = profile_changed ? strdup(manifest_entry->old_profile) : NULL;

    /* Add to workspace if there's any state change or divergence */
    if (state != WORKSPACE_STATE_DEPLOYED || divergence != DIVERGENCE_NONE || profile_changed) {
        error_t *err = workspace_add_diverged(ws, fs_path, storage_path, profile,
                                              old_profile, manifest_entry->all_profiles,
                                              state, divergence,
                                              WORKSPACE_ITEM_FILE,
                                              in_profile, in_state,
                                              on_filesystem,
                                              true, profile_changed);
        if (err) {
            /* On error, free old_profile since workspace_add_diverged didn't take ownership */
            free(old_profile);
            return err;
        }
    } else {
        /* No divergence - free old_profile if allocated */
        free(old_profile);
    }

    return NULL;
}

/**
 * Analyze state for orphaned file entries
 *
 * Detects ALL orphaned files (enabled + disabled profiles) using cleanup
 * module's robust algorithm. Each orphan is marked with profile_enabled
 * flag to enable caller filtering.
 *
 * An entry is orphaned if it exists in state but not in manifest.
 * - Enabled profile orphans: File removed from branch (profile_enabled=true)
 * - Disabled profile orphans: Profile disabled, needs cleanup (profile_enabled=false)
 *
 * Callers filter by profile_enabled:
 * - status: only show profile_enabled=true (enabled profiles)
 * - apply: use all (cleanup disabled profiles too)
 */
static error_t *analyze_orphaned_files(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->manifest);
    CHECK_NULL(ws->manifest->index);
    CHECK_NULL(ws->profile_index);

    error_t *err = NULL;
    state_file_entry_t *state_files = NULL;
    size_t state_count = 0;

    /* Get all files in state */
    err = state_get_all_files(ws->state, &state_files, &state_count);
    if (err) {
        return error_wrap(err, "Failed to get state files");
    }

    /* Early exit: no files in state means no orphans */
    if (state_count == 0) {
        state_free_all_files(state_files, state_count);
        return NULL;
    }

    /* Identify orphans: in state, not in manifest */
    for (size_t i = 0; i < state_count; i++) {
        const state_file_entry_t *state_entry = &state_files[i];

        const char *fs_path = state_entry->filesystem_path;
        const char *storage_path = state_entry->storage_path;
        const char *profile = state_entry->profile;

        /* Check if file exists in manifest (O(1) lookup using index) */
        void *idx_ptr = hashmap_get(ws->manifest->index, fs_path);
        file_entry_t *manifest_entry = NULL;
        if (idx_ptr) {
            size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
            manifest_entry = &ws->manifest->entries[idx];
        }

        if (!manifest_entry) {
            /* Orphaned: in state, not in manifest (out of scope) */
            bool profile_enabled = (hashmap_get(ws->profile_index, profile) != NULL);
            bool on_filesystem = fs_lexists(fs_path);

            err = workspace_add_diverged(
                ws,
                fs_path,
                storage_path,
                profile,
                NULL, NULL,       /* No old_profile or all_profiles for orphans */
                WORKSPACE_STATE_ORPHANED,  /* State: in deployment state, not in profile */
                DIVERGENCE_NONE,           /* Divergence: none */
                WORKSPACE_ITEM_FILE,
                false,            /* not in profile */
                true,             /* in state (was deployed) */
                on_filesystem,
                profile_enabled,
                false             /* No profile change for orphans */
            );

            if (err) {
                state_free_all_files(state_files, state_count);
                return error_wrap(err, "Failed to add orphaned file");
            }
        }
    }

    state_free_all_files(state_files, state_count);
    return NULL;
}

/**
 * Analyze state for orphaned directory entries
 *
 * Mirrors analyze_orphaned_files but compares state directories
 * against merged_metadata instead of manifest.
 *
 * Detects ALL orphaned directories (enabled + disabled profiles) and
 * marks each with profile_enabled flag for caller filtering.
 *
 * Directories in state but not in any profile's metadata are orphaned
 * and should be pruned.
 */
static error_t *analyze_orphaned_directories(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->merged_metadata);
    CHECK_NULL(ws->profile_index);

    error_t *err = NULL;
    state_directory_entry_t *state_dirs = NULL;
    size_t state_count = 0;

    /* Get all directories in state */
    err = state_get_all_directories(ws->state, &state_dirs, &state_count);
    if (err) {
        return error_wrap(err, "Failed to get state directories");
    }

    /* Early exit: no directories in state means no orphans */
    if (state_count == 0) {
        state_free_all_directories(state_dirs, state_count);
        return NULL;
    }

    /* Identify orphans: in state, not in merged_metadata */
    for (size_t i = 0; i < state_count; i++) {
        const state_directory_entry_t *state_entry = &state_dirs[i];
        const char *dir_path = state_entry->directory_path;
        const char *storage_prefix = state_entry->storage_prefix;
        const char *profile = state_entry->profile;

        /* Check if directory exists in merged_metadata (O(1) lookup)
         * For directories: key in merged_metadata = filesystem_path */
        const merged_metadata_entry_t *meta_entry =
            hashmap_get(ws->merged_metadata, dir_path);

        /* Orphaned if: not in metadata OR wrong kind (defensive check) */
        bool is_orphaned = (!meta_entry ||
                           meta_entry->item->kind != METADATA_ITEM_DIRECTORY);

        if (is_orphaned) {
            /* Orphaned: in state, not in metadata */
            bool profile_enabled = (hashmap_get(ws->profile_index, profile) != NULL);
            bool on_filesystem = fs_exists(dir_path);

            err = workspace_add_diverged(
                ws,
                dir_path,
                storage_prefix,
                profile,
                NULL, NULL,       /* No old_profile or all_profiles for orphans */
                WORKSPACE_STATE_ORPHANED,  /* State: in state, not in profile */
                DIVERGENCE_NONE,           /* Divergence: none */
                WORKSPACE_ITEM_DIRECTORY,
                false,            /* not in profile */
                false,            /* NOT in state (semantic: directories never deployed) */
                on_filesystem,
                profile_enabled,
                false             /* No profile change for orphans */
            );

            if (err) {
                state_free_all_directories(state_dirs, state_count);
                return error_wrap(err, "Failed to add orphaned directory");
            }
        }
    }

    state_free_all_directories(state_dirs, state_count);
    return NULL;
}

/**
 * Analyze state for orphaned entries (files + directories)
 *
 * Unified orphan detection for both files and directories.
 * Detects ALL orphans regardless of profile scope, marking each
 * with profile_enabled flag for caller filtering.
 */
static error_t *analyze_orphaned_state(workspace_t *ws) {
    CHECK_NULL(ws);

    error_t *err = NULL;

    /* Analyze file orphans */
    err = analyze_orphaned_files(ws);
    if (err) {
        return error_wrap(err, "Failed to analyze orphaned files");
    }

    /* Analyze directory orphans */
    err = analyze_orphaned_directories(ws);
    if (err) {
        return error_wrap(err, "Failed to analyze orphaned directories");
    }

    return NULL;
}

/**
 * Analyze divergence for all files in manifest using VWD cache
 *
 * Compares each file in the manifest against filesystem reality to detect
 * modifications, deletions, and undeployed files.
 *
 * Performance: O(N) where N = manifest count. No database queries needed
 * because all expected state is cached in the manifest entries (VWD cache).
 * This eliminates the previous N+1 query problem.
 */
static error_t *analyze_files_divergence(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->manifest);
    CHECK_NULL(ws->state);

    /* Analyze each file in manifest using VWD cache
     *
     * The manifest_entry contains all necessary state information in its
     * VWD cache fields (content_hash, type, deployed_at, etc.), so we
     * don't need to query the database for each file. This eliminates
     * N individual state_get_file() queries. */
    for (size_t i = 0; i < ws->manifest->count; i++) {
        const file_entry_t *manifest_entry = &ws->manifest->entries[i];

        /* Analyze this file using VWD cache (no database query needed) */
        error_t *err = analyze_file_divergence(ws, manifest_entry);

        if (err) {
            return err;
        }
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
        const workspace_item_t *item = &ws->diverged[i];

        switch (item->state) {
            case WORKSPACE_STATE_ORPHANED:
                has_orphaned = true;
                break;

            case WORKSPACE_STATE_UNDEPLOYED:
            case WORKSPACE_STATE_DELETED:
            case WORKSPACE_STATE_UNTRACKED:
                has_warnings = true;
                break;

            case WORKSPACE_STATE_DEPLOYED:
                /* Check metadata divergence */
                if (item->divergence != DIVERGENCE_NONE) {
                    has_warnings = true;
                }
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
    ignore_context_t *ignore_ctx,
    workspace_t *ws
) {
    CHECK_NULL(dir_path);
    CHECK_NULL(storage_prefix);
    CHECK_NULL(profile);
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
            /* Check if this file is already in manifest (O(1) lookup using index) */
            void *idx_ptr = hashmap_get(ws->manifest->index, full_path);
            file_entry_t *manifest_entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
                manifest_entry = &ws->manifest->entries[idx];
            }

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
                    NULL, NULL,  /* No old_profile or all_profiles for untracked */
                    WORKSPACE_STATE_UNTRACKED,  /* State: on filesystem in tracked dir */
                    DIVERGENCE_NONE,            /* Divergence: none */
                    WORKSPACE_ITEM_FILE,
                    false,  /* not in profile */
                    false,  /* not in state */
                    true,   /* on filesystem */
                    true,   /* profile_enabled */
                    false   /* No profile change */
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

        /* Get cached metadata for this profile */
        const metadata_t *metadata = ws_get_metadata(ws, profile_name);
        if (!metadata) {
            /* Profile has no metadata - skip */
            continue;
        }

        /* Get tracked directories from metadata (filtered by kind) */
        size_t dir_count = 0;
        const metadata_item_t **directories =
            metadata_get_items_by_kind(metadata, METADATA_ITEM_DIRECTORY, &dir_count);

        /* Create profile-specific ignore context once for all directories */
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
            fprintf(stderr, "warning: failed to load ignore patterns for profile '%s': %s\n",
                    profile_name, err->message);
            error_free(err);
            err = NULL;
            ignore_ctx = NULL;
        }

        /* Scan each tracked directory */
        for (size_t i = 0; i < dir_count; i++) {
            const metadata_item_t *dir_entry = directories[i];

            /* Check if directory still exists
             * For directories: key = filesystem_path (absolute path) */
            if (!fs_exists(dir_entry->key)) {
                continue;
            }

            /* Scan this directory for untracked files */
            err = scan_directory_for_untracked(
                dir_entry->key,                         /* filesystem_path */
                dir_entry->directory.storage_prefix,    /* storage_prefix (union field) */
                profile_name,
                ignore_ctx,
                ws
            );

            if (err) {
                /* Non-fatal: continue with other directories */
                fprintf(stderr, "warning: failed to scan directory '%s' in profile '%s': %s\n",
                        dir_entry->key, profile_name, err->message);
                error_free(err);
                err = NULL;
            }
        }

        /* Free ignore context after scanning all directories in this profile */
        ignore_context_free(ignore_ctx);

        /* Free the pointer array (items themselves remain in metadata) */
        free(directories);
    }

    return NULL;
}

/**
 * Analyze directory metadata for divergence
 *
 * Detects:
 * - DELETED state: Directory removed from filesystem
 * - DIVERGENCE_MODE: Directory permissions changed
 * - DIVERGENCE_OWNERSHIP: Directory owner/group changed (requires root)
 *
 * @param ws Workspace (must not be NULL, merged_metadata must be initialized)
 * @return Error or NULL on success
 */
static error_t *analyze_directory_metadata_divergence(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->merged_metadata);

    /* Iterate merged metadata to find and check tracked directories */
    hashmap_iter_t iter;
    hashmap_iter_init(&iter, ws->merged_metadata);
    void *value;

    while (hashmap_iter_next(&iter, NULL, &value)) {
        const merged_metadata_entry_t *entry = value;
        const metadata_item_t *item = entry->item;

        /* Filter: Only process directories */
        if (item->kind != METADATA_ITEM_DIRECTORY) {
            continue;
        }

        /* For directories: key = filesystem_path (absolute) */
        const char *filesystem_path = item->key;
        const char *storage_prefix = item->directory.storage_prefix;

        /* Check if directory still exists */
        if (!fs_exists(filesystem_path)) {
            /* Directory deleted - record divergence */
            error_t *err = workspace_add_diverged(
                ws,
                filesystem_path,
                storage_prefix,
                entry->profile_name,
                NULL, NULL,  /* No old_profile or all_profiles for directories */
                WORKSPACE_STATE_DELETED,  /* State: was in profile, removed from filesystem */
                DIVERGENCE_NONE,          /* Divergence: none (file is gone) */
                WORKSPACE_ITEM_DIRECTORY,
                true,   /* in_profile */
                false,  /* in_state */
                false,  /* on_filesystem (deleted) */
                true,   /* profile_enabled */
                false   /* No profile change */
            );

            if (err) {
                return error_wrap(err, "Failed to record deleted directory '%s'",
                                filesystem_path);
            }
            continue;  /* Successfully recorded, check next directory */
        }

        /* Stat directory to get current metadata */
        struct stat dir_stat;
        if (stat(filesystem_path, &dir_stat) != 0) {
            /* Stat failed but exists: race condition or permission issue */
            fprintf(stderr, "warning: failed to stat directory '%s': %s\n",
                    filesystem_path, strerror(errno));
            continue;  /* Non-fatal, skip this directory */
        }

        /* Verify it's actually a directory (type may have changed) */
        if (!S_ISDIR(dir_stat.st_mode)) {
            fprintf(stderr, "warning: '%s' is no longer a directory (type changed)\n",
                    filesystem_path);
            continue;  /* Non-fatal, skip - apply/revert don't handle type changes */
        }

        /* Check metadata divergence using unified helper */
        bool mode_differs = false;
        bool ownership_differs = false;

        error_t *err = check_item_metadata_divergence(
            item,
            filesystem_path,
            &dir_stat,
            &mode_differs,
            &ownership_differs
        );

        if (err) {
            return error_wrap(err, "Failed to check metadata for directory '%s'",
                            filesystem_path);
        }

        /* Record divergence if any metadata differs */
        if (mode_differs || ownership_differs) {
            /* Accumulate divergence flags */
            divergence_type_t divergence = DIVERGENCE_NONE;
            if (mode_differs) divergence |= DIVERGENCE_MODE;
            if (ownership_differs) divergence |= DIVERGENCE_OWNERSHIP;

            err = workspace_add_diverged(
                ws,
                filesystem_path,
                storage_prefix,
                entry->profile_name,
                NULL, NULL,  /* No old_profile or all_profiles for directories */
                WORKSPACE_STATE_DEPLOYED,  /* State: directory exists as expected */
                divergence,                /* Divergence: mode/ownership flags */
                WORKSPACE_ITEM_DIRECTORY,
                true,   /* in_profile */
                false,  /* in_state */
                true,   /* on_filesystem */
                true,   /* profile_enabled */
                false   /* No profile change */
            );

            if (err) {
                return error_wrap(err,
                                "Failed to record directory metadata divergence for '%s'",
                                filesystem_path);
            }
        }
    }

    return NULL;  /* Success - all directories checked */
}

/**
 * Analyze encryption policy mismatches
 *
 * Detects files that should be encrypted (per auto-encrypt patterns)
 * but are stored as plaintext in the profile.
 *
 * Uses two-tier validation to determine actual encryption state:
 * - Tier 1 (Source of Truth): Checks magic header in git blob
 * - Tier 2 (Defense in Depth): Cross-validates with metadata
 *
 * If magic header and metadata disagree, warns about corruption but
 * uses magic header truth for policy enforcement. This ensures policy
 * violations are always detected even with corrupted metadata.
 *
 * Only checks if:
 * - Encryption is globally enabled
 * - Auto-encrypt patterns are configured
 *
 * Error handling:
 * - Git read errors: Non-fatal, warns and skips file
 * - Metadata corruption: Non-fatal, warns and uses magic header
 * - Pattern match errors: Non-fatal, skips file
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

        /* Validate actual encryption state using two-tier validation */
        bool is_encrypted = false;

        /* Tier 1: Check magic header in blob (source of truth) */
        const git_oid *blob_oid = git_tree_entry_id(manifest_entry->entry);
        git_blob *blob = NULL;
        int git_err = git_blob_lookup(&blob, ws->repo, blob_oid);

        if (git_err != 0) {
            /* Non-fatal: can't read blob - skip this file */
            fprintf(stderr, "warning: failed to read blob for '%s' in profile '%s': %s\n",
                    storage_path, profile_name,
                    git_error_last() ? git_error_last()->message : "unknown error");
            continue;
        }

        const unsigned char *blob_data = git_blob_rawcontent(blob);
        size_t blob_size = (size_t)git_blob_rawsize(blob);
        is_encrypted = encryption_is_encrypted(blob_data, blob_size);

        /* Tier 2: Cross-validate with metadata (defense in depth) */
        const metadata_t *metadata = ws_get_metadata(ws, profile_name);
        if (metadata) {
            const metadata_item_t *meta_entry = NULL;
            error_t *lookup_err = metadata_get_item(metadata, storage_path, &meta_entry);

            if (lookup_err == NULL && meta_entry) {
                /* Validate kind: encryption metadata only applies to files.
                 * This should always be FILE (manifest contains only files), but
                 * check defensively since this is corruption detection code. */
                if (meta_entry->kind != METADATA_ITEM_FILE) {
                    fprintf(stderr,
                        "warning: metadata corruption for '%s' in profile '%s': "
                        "expected FILE, got DIRECTORY. Skipping encryption validation.\n",
                        storage_path, profile_name);
                } else {
                    /* Detect mismatch between magic header and metadata */
                    if (is_encrypted != meta_entry->file.encrypted) {
                        fprintf(stderr,
                            "warning: metadata corruption detected for '%s' in profile '%s'\n"
                            "  Magic header says: %s\n"
                            "  Metadata says: %s\n"
                            "  Using actual state from magic header. To fix, run:\n"
                            "    dotta update -p %s '%s'\n",
                            storage_path, profile_name,
                            is_encrypted ? "encrypted" : "plaintext",
                            is_encrypted ? "plaintext" : "encrypted",
                            profile_name, storage_path);
                    }
                }
            }

            error_free(lookup_err);
        }

        git_blob_free(blob);

        /* Policy mismatch: should be encrypted but isn't */
        if (should_auto_encrypt && !is_encrypted) {
            /* Check if file already has divergence (O(1) hashmap lookup).
             * This prevents last-write-wins bug when multiple analysis functions
             * detect different divergence types for the same file. */
            workspace_item_t *existing = hashmap_get(
                ws->diverged_index,
                manifest_entry->filesystem_path
            );

            if (existing) {
                /* File already diverged - accumulate encryption flag
                 *
                 * Example: File is DEPLOYED with CONTENT divergence AND violates encryption
                 * policy. We accumulate: divergence |= DIVERGENCE_ENCRYPTION.
                 * Result: User sees both flags: "modified [encryption]" in status. */
                existing->divergence |= DIVERGENCE_ENCRYPTION;
            } else {
                /* File has NO other divergence - encryption policy is the only issue.
                 * Determine state: if in state, it's deployed; otherwise undeployed. */
                bool in_state = false;

                if (ws->state) {
                    state_file_entry_t *state_entry = NULL;
                    error_t *state_err = state_get_file(ws->state, manifest_entry->filesystem_path, &state_entry);
                    if (state_err == NULL && state_entry) {
                        in_state = true;
                        state_free_entry(state_entry);
                    }
                    error_free(state_err);
                }

                workspace_state_t item_state = in_state ?
                    WORKSPACE_STATE_DEPLOYED : WORKSPACE_STATE_UNDEPLOYED;

                err = workspace_add_diverged(
                    ws,
                    manifest_entry->filesystem_path,
                    storage_path,
                    profile_name,
                    NULL, manifest_entry->all_profiles,
                    item_state,            /* State: deployed or undeployed */
                    DIVERGENCE_ENCRYPTION, /* Divergence: encryption policy violated */
                    WORKSPACE_ITEM_FILE,
                    true,  /* in profile */
                    in_state,
                    false, /* on_filesystem (unknown, encryption check is in-repo only) */
                    true,  /* profile_enabled */
                    false  /* No profile change */
                );

                if (err) {
                    return err;
                }
            }
        }
    }

    return NULL;
}

/**
 * Build in-memory manifest from state manifest table
 *
 * Reads manifest entries from state DB and constructs manifest_t structure.
 * Does NOT load git_tree_entry* pointers (set to NULL). Tree entries are
 * lazy-loaded only when needed for content display (diffs, conflict resolution).
 *
 * This is the core of the Virtual Working Directory architecture - we read
 * the expected state cache (manifest table) instead of walking Git trees. This makes
 * status operations O(M) where M = entries in manifest, not O(N) where N =
 * all files across all enabled profiles.
 *
 * Files from profiles not in the workspace scope are filtered out with a warning.
 * This can happen if a profile is disabled but manifest still has orphaned entries.
 *
 * Performance: O(M) where M = entries in manifest table (typically much smaller than Git)
 *
 * @param ws Workspace (must not be NULL, state must be loaded)
 * @return Error or NULL on success
 */
static error_t *workspace_build_manifest_from_state(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->profile_index);

    error_t *err = NULL;
    state_file_entry_t *state_entries = NULL;
    size_t state_count = 0;

    /* Read all entries from manifest table */
    err = state_get_all_files(ws->state, &state_entries, &state_count);
    if (err) {
        return error_wrap(err, "Failed to read manifest from state");
    }

    /* Allocate manifest structure */
    ws->manifest = calloc(1, sizeof(manifest_t));
    if (!ws->manifest) {
        state_free_all_files(state_entries, state_count);
        return ERROR(ERR_MEMORY, "Failed to allocate manifest");
    }

    /* Allocate entries array (max size = state_count, actual may be smaller due to filtering) */
    ws->manifest->entries = calloc(state_count, sizeof(file_entry_t));
    if (!ws->manifest->entries) {
        free(ws->manifest);
        ws->manifest = NULL;
        state_free_all_files(state_entries, state_count);
        return ERROR(ERR_MEMORY, "Failed to allocate manifest entries");
    }

    /*
     * Create hash map for O(1) lookups
     * Maps: filesystem_path -> index in entries array (offset by 1)
     * Use state_count as initial capacity (optimal sizing, no rehashing needed)
     */
    hashmap_t *path_map = hashmap_create(state_count > 0 ? state_count : 64);
    if (!path_map) {
        free(ws->manifest->entries);
        free(ws->manifest);
        ws->manifest = NULL;
        state_free_all_files(state_entries, state_count);
        return ERROR(ERR_MEMORY, "Failed to create manifest index");
    }

    size_t manifest_idx = 0;

    /* Build manifest entries from state */
    for (size_t i = 0; i < state_count; i++) {
        const state_file_entry_t *state_entry = &state_entries[i];
        file_entry_t *entry = &ws->manifest->entries[manifest_idx];

        /* Find profile in workspace's profile list (O(1) hashmap lookup) */
        entry->source_profile = hashmap_get(ws->profile_index, state_entry->profile);

        if (!entry->source_profile) {
            /* Profile not in workspace scope - this is expected when:
             * 1. Profile was disabled but manifest has orphaned entries
             * 2. Profile branch was deleted outside dotta
             *
             * Skip silently. Orphan detection (analyze_orphaned_files) will identify
             * these entries and status will show them clearly to the user. This
             * follows the Git staging model where profile disable stages removal
             * and apply executes it. */
            continue;
        }

        /* Copy paths (owned by manifest) */
        entry->storage_path = strdup(state_entry->storage_path);
        entry->filesystem_path = strdup(state_entry->filesystem_path);

        if (!entry->storage_path || !entry->filesystem_path) {
            /* Cleanup on allocation failure */
            free(entry->storage_path);
            free(entry->filesystem_path);

            /* Free previously allocated entries */
            for (size_t j = 0; j < manifest_idx; j++) {
                free(ws->manifest->entries[j].storage_path);
                free(ws->manifest->entries[j].filesystem_path);
                free(ws->manifest->entries[j].old_profile);
                free(ws->manifest->entries[j].git_oid);
                free(ws->manifest->entries[j].content_hash);
                free(ws->manifest->entries[j].mode);
                free(ws->manifest->entries[j].owner);
                free(ws->manifest->entries[j].group);
                if (ws->manifest->entries[j].entry) {
                    git_tree_entry_free(ws->manifest->entries[j].entry);
                }
            }
            hashmap_free(path_map, NULL);
            free(ws->manifest->entries);
            free(ws->manifest);
            ws->manifest = NULL;
            state_free_all_files(state_entries, state_count);
            return ERROR(ERR_MEMORY, "Failed to allocate manifest entry paths");
        }

        /* Populate VWD expected state cache from database
         *
         * These fields enable O(1) divergence checking without N database queries.
         * They represent the cached expected state that workspace divergence
         * analysis will compare against filesystem reality.
         *
         * NULL fields: Some optional fields (mode, owner, group, git_oid, content_hash)
         * may be NULL in state database. Use conditional strdup to handle gracefully.
         */
        entry->old_profile = state_entry->old_profile ? strdup(state_entry->old_profile) : NULL;
        entry->git_oid = state_entry->git_oid ? strdup(state_entry->git_oid) : NULL;
        entry->content_hash = state_entry->content_hash ? strdup(state_entry->content_hash) : NULL;
        entry->type = state_entry->type;
        entry->mode = state_entry->mode ? strdup(state_entry->mode) : NULL;
        entry->owner = state_entry->owner ? strdup(state_entry->owner) : NULL;
        entry->group = state_entry->group ? strdup(state_entry->group) : NULL;
        entry->encrypted = state_entry->encrypted;
        entry->deployed_at = state_entry->deployed_at;

        /* Check for allocation failures in VWD fields */
        if ((state_entry->old_profile && !entry->old_profile) ||
            (state_entry->git_oid && !entry->git_oid) ||
            (state_entry->content_hash && !entry->content_hash) ||
            (state_entry->mode && !entry->mode) ||
            (state_entry->owner && !entry->owner) ||
            (state_entry->group && !entry->group)) {

            /* Cleanup current entry's allocated fields */
            free(entry->storage_path);
            free(entry->filesystem_path);
            free(entry->old_profile);
            free(entry->git_oid);
            free(entry->content_hash);
            free(entry->mode);
            free(entry->owner);
            free(entry->group);

            /* Free previously allocated entries */
            for (size_t j = 0; j < manifest_idx; j++) {
                free(ws->manifest->entries[j].storage_path);
                free(ws->manifest->entries[j].filesystem_path);
                free(ws->manifest->entries[j].old_profile);
                free(ws->manifest->entries[j].git_oid);
                free(ws->manifest->entries[j].content_hash);
                free(ws->manifest->entries[j].mode);
                free(ws->manifest->entries[j].owner);
                free(ws->manifest->entries[j].group);
                if (ws->manifest->entries[j].entry) {
                    git_tree_entry_free(ws->manifest->entries[j].entry);
                }
            }
            hashmap_free(path_map, NULL);
            free(ws->manifest->entries);
            free(ws->manifest);
            ws->manifest = NULL;
            state_free_all_files(state_entries, state_count);
            return ERROR(ERR_MEMORY, "Failed to allocate VWD cache fields");
        }

        /* Load profile tree (lazy-loaded, cached in profile structure) */
        err = profile_load_tree(ws->repo, entry->source_profile);
        if (err) {
            /* Cleanup allocated fields for current entry */
            free(entry->storage_path);
            free(entry->filesystem_path);
            free(entry->git_oid);
            free(entry->content_hash);
            free(entry->mode);
            free(entry->owner);
            free(entry->group);

            /* Free previously allocated entries */
            for (size_t j = 0; j < manifest_idx; j++) {
                free(ws->manifest->entries[j].storage_path);
                free(ws->manifest->entries[j].filesystem_path);
                free(ws->manifest->entries[j].old_profile);
                free(ws->manifest->entries[j].git_oid);
                free(ws->manifest->entries[j].content_hash);
                free(ws->manifest->entries[j].mode);
                free(ws->manifest->entries[j].owner);
                free(ws->manifest->entries[j].group);
                if (ws->manifest->entries[j].entry) {
                    git_tree_entry_free(ws->manifest->entries[j].entry);
                }
            }
            hashmap_free(path_map, NULL);
            free(ws->manifest->entries);
            free(ws->manifest);
            ws->manifest = NULL;
            state_free_all_files(state_entries, state_count);
            return error_wrap(err, "Failed to load tree for profile '%s'",
                            entry->source_profile->name);
        }

        /* Lookup tree entry from Git (creates owned reference) */
        int git_err = git_tree_entry_bypath(&entry->entry,
                                             entry->source_profile->tree,
                                             entry->storage_path);
        if (git_err != 0) {
            if (git_err == GIT_ENOTFOUND) {
                /* File in state but not in Git - data inconsistency.
                 * Skip with warning, similar to orphan profile handling.
                 * Apply will reconcile state with Git reality. */
                fprintf(stderr,
                    "warning: manifest entry '%s' not found in profile '%s' - "
                    "skipping (state inconsistency, will be cleaned up)\n",
                    entry->filesystem_path,
                    entry->source_profile->name);

                /* Free allocated fields and skip this entry */
                free(entry->storage_path);
                free(entry->filesystem_path);
                free(entry->git_oid);
                free(entry->content_hash);
                free(entry->mode);
                free(entry->owner);
                free(entry->group);
                continue;  /* Don't increment manifest_idx */
            } else {
                /* Other Git errors - propagate */
                free(entry->storage_path);
                free(entry->filesystem_path);
                free(entry->git_oid);
                free(entry->content_hash);
                free(entry->mode);
                free(entry->owner);
                free(entry->group);

                /* Free previously allocated entries */
                for (size_t j = 0; j < manifest_idx; j++) {
                    free(ws->manifest->entries[j].storage_path);
                    free(ws->manifest->entries[j].filesystem_path);
                    free(ws->manifest->entries[j].git_oid);
                    free(ws->manifest->entries[j].content_hash);
                    free(ws->manifest->entries[j].mode);
                    free(ws->manifest->entries[j].owner);
                    free(ws->manifest->entries[j].group);
                    if (ws->manifest->entries[j].entry) {
                        git_tree_entry_free(ws->manifest->entries[j].entry);
                    }
                }
                hashmap_free(path_map, NULL);
                free(ws->manifest->entries);
                free(ws->manifest);
                ws->manifest = NULL;
                state_free_all_files(state_entries, state_count);

                err = error_from_git(git_err);
                return error_wrap(err, "Failed to lookup tree entry for '%s' in profile '%s'",
                                entry->storage_path, entry->source_profile->name);
            }
        }

        /* all_profiles not populated (not needed for hash-based divergence detection) */
        entry->all_profiles = NULL;

        /* Store index in hashmap (offset by 1 to distinguish from NULL).
         * We cast the index through uintptr_t to store it as a void pointer.
         * This is safe because:
         * 1. Array indices are always much smaller than SIZE_MAX
         * 2. uintptr_t can hold any pointer value (by definition)
         * 3. We never dereference these "pointers" - they're just tagged integers
         */
        err = hashmap_set(path_map, entry->filesystem_path,
                         (void *)(uintptr_t)(manifest_idx + 1));
        if (err) {
            /* Cleanup: free hashmap and all allocated entries */
            hashmap_free(path_map, NULL);
            for (size_t j = 0; j <= manifest_idx; j++) {
                free(ws->manifest->entries[j].storage_path);
                free(ws->manifest->entries[j].filesystem_path);
                free(ws->manifest->entries[j].git_oid);
                free(ws->manifest->entries[j].content_hash);
                free(ws->manifest->entries[j].mode);
                free(ws->manifest->entries[j].owner);
                free(ws->manifest->entries[j].group);
                if (ws->manifest->entries[j].entry) {
                    git_tree_entry_free(ws->manifest->entries[j].entry);
                }
            }
            free(ws->manifest->entries);
            free(ws->manifest);
            ws->manifest = NULL;
            state_free_all_files(state_entries, state_count);
            return error_wrap(err, "Failed to populate manifest index");
        }

        manifest_idx++;
    }

    /* Transfer index ownership to manifest */
    ws->manifest->index = path_map;

    /* Set final count (may be less than state_count due to filtering) */
    ws->manifest->count = manifest_idx;

    state_free_all_files(state_entries, state_count);
    return NULL;
}

/**
 * Load workspace from repository
 */
error_t *workspace_load(
    git_repository *repo,
    state_t *state,
    profile_list_t *profiles,
    const dotta_config_t *config,
    const workspace_load_t *options,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(options);
    CHECK_NULL(out);

    /* Copy provided options */
    workspace_load_t resolved_opts = *options;

    /* Handle analysis dependencies.
     * Orphan analysis requires file analysis (can't detect orphans without
     * knowing what files exist in profiles). Auto-enable file analysis if
     * orphans are requested to prevent invalid state. */
    if (resolved_opts.analyze_orphans && !resolved_opts.analyze_files) {
        resolved_opts.analyze_files = true;
    }

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

    /* Build unified metadata view with profile precedence.
     * CRITICAL INVARIANT: profiles array is in precedence order (global → OS → host).
     * Iterating in order naturally implements "last profile wins" - we update existing
     * entries to track the winning profile. */

    /* Initialize merged entries array */
    ws->merged_entries = NULL;
    ws->merged_count = 0;
    ws->merged_capacity = 0;

    ws->merged_metadata = hashmap_create(256);
    if (!ws->merged_metadata) {
        workspace_free(ws);
        return ERROR(ERR_MEMORY, "Failed to create merged metadata map");
    }

    for (size_t p = 0; p < profiles->count; p++) {
        const char *profile_name = profiles->profiles[p].name;
        const metadata_t *metadata = hashmap_get(ws->metadata_cache, profile_name);

        if (!metadata) {
            /* Profile has no metadata - skip (empty metadata was created above) */
            continue;
        }

        /* Get ALL items from this profile (files + directories) */
        size_t item_count = 0;
        const metadata_item_t *items = metadata_get_all_items(metadata, &item_count);

        if (!items || item_count == 0) {
            continue;  /* No items in this profile */
        }

        /* Add/update items in merged map - last profile wins (precedence) */
        for (size_t i = 0; i < item_count; i++) {
            const metadata_item_t *item = &items[i];

            /* Use item's key field as map key.
             * - For FILES: key = storage_path (relative, e.g., "home/.bashrc")
             * - For DIRECTORIES: key = filesystem_path (absolute, e.g., "/home/user/.config")
             * No collision risk: different namespaces (relative vs absolute paths). */

            /* Check if entry exists (for updating profile_name on override) */
            merged_metadata_entry_t *existing = hashmap_get(ws->merged_metadata, item->key);

            if (existing) {
                /* Update existing entry - last profile wins (precedence) */
                existing->item = item;
                existing->profile_name = profile_name;
            } else {
                /* Grow array if needed */
                if (ws->merged_count >= ws->merged_capacity) {
                    size_t new_cap = ws->merged_capacity == 0 ? 256 : ws->merged_capacity * 2;
                    merged_metadata_entry_t *new_entries = realloc(
                        ws->merged_entries,
                        new_cap * sizeof(merged_metadata_entry_t)
                    );
                    if (!new_entries) {
                        workspace_free(ws);
                        return ERROR(ERR_MEMORY, "Failed to grow merged entries");
                    }
                    ws->merged_entries = new_entries;
                    ws->merged_capacity = new_cap;
                }

                /* Add new entry */
                merged_metadata_entry_t *entry = &ws->merged_entries[ws->merged_count++];
                entry->item = item;
                entry->profile_name = profile_name;

                /* Add to hashmap */
                error_t *map_err = hashmap_set(ws->merged_metadata, item->key, entry);
                if (map_err) {
                    workspace_free(ws);
                    return error_wrap(map_err, "Failed to add entry to merged metadata");
                }
            }
        }
    }

    /* Load or borrow deployment state */
    if (state) {
        /* Borrow caller's state (typically from state_load_for_update).
         * This ensures workspace analyzes state within the active transaction,
         * not a stale committed snapshot. Caller retains ownership. */
        ws->state = state;
        ws->owns_state = false;
    } else {
        /* Allocate our own state (read-only mode for status/diff commands).
         * Workspace owns this and will free it in workspace_free(). */
        err = state_load(repo, &ws->state);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to load state");
        }
        ws->owns_state = true;
    }

    /* Build manifest from state (Virtual Working Directory architecture)
     * This replaces the old profile_build_manifest() which walked Git trees.
     * Now we read from the manifest table (expected state cache) for O(M) performance
     * where M = entries in manifest, not O(N) where N = all files in Git. */
    err = workspace_build_manifest_from_state(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to build manifest from state");
    }

    /* Verify manifest index was populated (architectural invariant)
     * This check ensures workspace_build_manifest_from_state() correctly
     * built the index, maintaining consistency with the write path pattern. */
    if (!ws->manifest->index) {
        workspace_free(ws);
        return ERROR(ERR_INTERNAL,
            "Manifest index not populated by workspace_build_manifest_from_state() - "
            "this is a programming error");
    }

    /* Execute analyses based on resolved_opts flags. Each analysis is
     * independently controllable for optimal performance. */

    /* Analyze file divergence (most common requirement) */
    if (resolved_opts.analyze_files) {
        err = analyze_files_divergence(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze file divergence");
        }
    }

    /* Analyze orphaned state entries (requires files) */
    if (resolved_opts.analyze_orphans) {
        err = analyze_orphaned_state(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze orphaned state");
        }
    }

    /* Analyze tracked directories for untracked files */
    if (resolved_opts.analyze_untracked) {
        err = analyze_untracked_files(ws, config);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze untracked files");
        }
    }

    /* Analyze directory metadata divergence */
    if (resolved_opts.analyze_directories) {
        err = analyze_directory_metadata_divergence(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze directory metadata");
        }
    }

    /* Analyze encryption policy mismatches */
    if (resolved_opts.analyze_encryption) {
        err = analyze_encryption_policy_mismatch(ws, config);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze encryption policy");
        }
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
 * Get all diverged items
 */
const workspace_item_t *workspace_get_all_diverged(
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
 * Get workspace item by filesystem path
 *
 * O(1) lookup via diverged_index hashmap. Returns NULL if item has no
 * divergence (CLEAN items are not indexed).
 */
const workspace_item_t *workspace_get_item(
    const workspace_t *ws,
    const char *filesystem_path
) {
    if (!ws || !filesystem_path) {
        return NULL;
    }

    /* O(1) lookup via hashmap - returns NULL if not found or CLEAN */
    return hashmap_get(ws->diverged_index, filesystem_path);
}

/**
 * Get cached metadata for profile
 */
const metadata_t *workspace_get_metadata(
    const workspace_t *ws,
    const char *profile_name
) {
    return ws_get_metadata(ws, profile_name);
}

/**
 * Get the repository associated with the workspace
 */
git_repository *workspace_get_repo(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->repo;
}

/**
 * Get the list of profiles managed by the workspace
 */
const profile_list_t *workspace_get_profiles(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->profiles;
}

/**
 * Get the manifest of files managed by the workspace
 */
const manifest_t *workspace_get_manifest(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->manifest;
}

/**
 * Get the deployment state from workspace
 */
const state_t *workspace_get_state(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->state;
}

/**
 * Get keymanager from workspace
 *
 * Returns the keymanager borrowed from global configuration. This is used
 * for content hashing and encryption operations. Can be NULL if encryption
 * is not configured.
 *
 * @param ws Workspace (must not be NULL)
 * @return Keymanager (borrowed reference, do not free, can be NULL)
 */
keymanager_t *workspace_get_keymanager(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->keymanager;
}

/**
 * Get content cache from workspace
 *
 * Returns the content cache used by the workspace for transparent
 * encryption/decryption. The cache is pre-populated during workspace
 * analysis and can be reused by commands to avoid redundant decryption.
 *
 * @param ws Workspace (must not be NULL)
 * @return Content cache (borrowed reference, do not free, can be NULL)
 */
content_cache_t *workspace_get_content_cache(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->content_cache;
}

/**
 * Get metadata cache from workspace
 *
 * Returns the pre-loaded metadata cache (hashmap: profile_name → metadata_t*)
 * populated during workspace_load(). This cache remains valid for the
 * workspace's lifetime and can be passed to bulk operations that need
 * per-profile metadata without redundant loads.
 *
 * @param ws Workspace (must not be NULL)
 * @return Metadata cache hashmap (borrowed reference, do not free, can be NULL)
 */
const hashmap_t *workspace_get_metadata_cache(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->metadata_cache;
}

/**
 * Get merged metadata from workspace
 *
 * Builds metadata_t from workspace's pre-merged view instead of re-merging
 * from scratch. This avoids redundant precedence resolution since workspace_load()
 * already applied profile precedence when building merged_metadata.
 */
error_t *workspace_get_merged_metadata(
    const workspace_t *ws,
    metadata_t **out
) {
    CHECK_NULL(ws);
    CHECK_NULL(out);

    /* Validate workspace has merged metadata hashmap (invariant: created by workspace_load).
     * The hashmap is always allocated even when empty, so NULL indicates incomplete initialization. */
    if (!ws->merged_metadata) {
        return ERROR(ERR_INTERNAL,
            "Workspace missing merged metadata (invariant violation - workspace_load incomplete)");
    }

    /* Create empty metadata collection for result */
    metadata_t *result = NULL;
    error_t *err = metadata_create_empty(&result);
    if (err) {
        return error_wrap(err, "Failed to create merged metadata result");
    }

    /* Build metadata from workspace's pre-merged view.
     *
     * The merged_entries array contains all items with profile precedence
     * already applied during workspace_load() (global → OS → host, last wins).
     * We just need to copy them into a new metadata_t for the caller to own.
     *
     * Edge cases handled:
     * - Empty workspace (merged_count=0): Creates empty metadata, loop skipped ✓
     * - Profiles without metadata: Already filtered out during workspace_load ✓
     * - No overlaps: All items copied (same as old behavior) ✓
     * - Full overlaps: Only winning items copied (avoids redundant overwrites) ✓
     */
    for (size_t i = 0; i < ws->merged_count; i++) {
        const merged_metadata_entry_t *entry = &ws->merged_entries[i];
        const metadata_item_t *item = entry->item;

        /* Copy item into result (metadata_add_item performs deep copy) */
        err = metadata_add_item(result, item);
        if (err) {
            metadata_free(result);
            return error_wrap(err, "Failed to copy merged metadata item: %s", item->key);
        }
    }

    /* Success - transfer ownership to caller */
    *out = result;
    return NULL;
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
        free(ws->diverged[i].metadata_profile);
        free(ws->diverged[i].old_profile);  /* Free profile change tracking */
        string_array_free(ws->diverged[i].all_profiles);  /* Free multi-profile tracking */
    }
    free(ws->diverged);

    /* Free indices (values are borrowed, so pass NULL for value free function) */
    hashmap_free(ws->profile_index, NULL);
    hashmap_free(ws->diverged_index, NULL);

    /* Free merged_metadata BEFORE metadata_cache (borrowed pointers) */
    hashmap_free(ws->merged_metadata, NULL);  /* NULL = don't free values (they're in merged_entries) */

    /* Free merged_entries array (strings are borrowed, just free array) */
    free(ws->merged_entries);

    /* Free encryption infrastructure */
    if (ws->metadata_cache) {
        hashmap_free(ws->metadata_cache, metadata_free);
    }
    content_cache_free(ws->content_cache);
    /* Don't free keymanager - it's global */

    /* Free owned state */
    manifest_free(ws->manifest);

    /* Only free state if we own it (allocated via state_load).
     * If borrowed from caller (state_load_for_update), caller is responsible. */
    if (ws->owns_state) {
        state_free(ws->state);
    }

    free(ws);
}
