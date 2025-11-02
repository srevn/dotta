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
#include "infra/compare.h"
#include "infra/content.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/string.h"

/**
 * Get default workspace load options
 *
 * Returns options with all analyses enabled for backward compatibility.
 * This matches the behavior of workspace_load() before the refactor.
 */
workspace_load_t workspace_load_default(void) {
    workspace_load_t opts = {
        .analyze_files       = true,
        .analyze_orphans     = true,
        .analyze_untracked   = true,
        .analyze_directories = true,
        .analyze_encryption  = true
    };
    return opts;
}

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
    state_t *state;                  /* Deployment state (owned) */
    profile_list_t *profiles;        /* Selected profiles for this workspace (borrowed) */
    hashmap_t *manifest_index;       /* Maps filesystem_path -> file_entry_t* */
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

    /* Divergence accumulator (bit flags, can combine) */
    divergence_type_t divergence = DIVERGENCE_NONE;

    /* State will be determined in PHASE 2 based on deployment status */
    workspace_state_t state = WORKSPACE_STATE_DEPLOYED;

    /* PHASE 1: Filesystem content analysis (if file exists)
     * Compare content for ALL files on filesystem, regardless of deployment state.
     * This catches conflicts for both deployed AND undeployed files.
     */
    if (on_filesystem) {
        /* Get metadata for decryption policy and metadata checking */
        const metadata_t *metadata = ws_get_metadata(ws, manifest_entry->source_profile->name);
        if (!metadata) {
            return ERROR(ERR_INTERNAL,
                "Metadata cache missing entry for profile '%s' (invariant violation)",
                manifest_entry->source_profile->name);
        }

        /* Get plaintext content (cached, automatic decryption) */
        const buffer_t *content = NULL;
        error_t *err = content_cache_get_from_tree_entry(
            ws->content_cache,
            manifest_entry->entry,
            manifest_entry->storage_path,
            manifest_entry->source_profile->name,
            metadata,
            &content
        );

        if (err) {
            return error_wrap(err, "Failed to get content for '%s'", fs_path);
        }

        /* Compare buffer to disk - capture stat for reuse in metadata check */
        git_filemode_t mode = git_tree_entry_filemode(manifest_entry->entry);
        compare_result_t cmp_result;
        struct stat file_stat;  /* Captured from compare, reused for metadata */
        err = compare_buffer_to_disk(content, fs_path, mode, NULL, &cmp_result, &file_stat);

        if (err) {
            return error_wrap(err, "Failed to compare '%s'", fs_path);
        }

        /* Don't free content - cache owns it! */

        /* Accumulate divergence from content comparison */
        switch (cmp_result) {
            case CMP_EQUAL:
                /* Content and type match - no divergence from content comparison.
                 * Permission checking happens below in the metadata section. */
                break;

            case CMP_DIFFERENT:
                /* Content differs - accumulate CONTENT flag */
                divergence |= DIVERGENCE_CONTENT;
                break;

            case CMP_TYPE_DIFF:
                /* Type differs (file vs symlink vs dir) - block immediately */
                /* Early return for TYPE_DIFF (critical blocking case) */
                return workspace_add_diverged(ws, fs_path, storage_path, profile,
                                             NULL, manifest_entry->all_profiles,
                                             WORKSPACE_STATE_DEPLOYED,
                                             DIVERGENCE_TYPE,
                                             WORKSPACE_ITEM_FILE,
                                             in_profile, in_state,
                                             on_filesystem,
                                             true, false);

            case CMP_MISSING:
                /* Shouldn't happen (we checked on_filesystem), but be defensive */
                /* Early return for MISSING (defensive case) */
                return workspace_add_diverged(ws, fs_path, storage_path, profile,
                                             NULL, manifest_entry->all_profiles,
                                             WORKSPACE_STATE_DELETED,
                                             DIVERGENCE_NONE,
                                             WORKSPACE_ITEM_FILE,
                                             in_profile, in_state,
                                             on_filesystem,
                                             true, false);
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
         *
         * Both phases use the SAME file_stat (already captured above), so no
         * extra syscalls. Flags are accumulated with |=, so detecting the same
         * divergence twice is idempotent and harmless.
         */

        /* PHASE A: Check git filemode (executable bit) */
        {
            git_filemode_t expected_mode = git_tree_entry_filemode(manifest_entry->entry);
            bool expect_exec = (expected_mode == GIT_FILEMODE_BLOB_EXECUTABLE);
            bool is_exec = fs_stat_is_executable(&file_stat);

            if (expect_exec != is_exec) {
                /* Executable bit differs between git and filesystem */
                divergence |= DIVERGENCE_MODE;
            }
        }

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

    /* PHASE 2: State-based classification
     * Determine final state based on deployment and filesystem status.
     */
    if (!in_state) {
        /* File not deployed yet */
        state = WORKSPACE_STATE_UNDEPLOYED;
        /* Keep accumulated divergence flags (may have CONTENT from conflict check) */
    } else if (!on_filesystem) {
        /* File was deployed but now missing */
        state = WORKSPACE_STATE_DELETED;
        divergence = DIVERGENCE_NONE;  /* No divergence for deleted files */
    } else {
        /* File is deployed and on filesystem */
        state = WORKSPACE_STATE_DEPLOYED;
        /* Keep accumulated divergence flags */
    }

    /* PHASE 3: Profile ownership change detection
     * Detect when a file moves from one profile to another.
     * Example: file was in 'global', now in 'darwin'.
     */
    bool profile_changed = false;
    char *old_profile = NULL;

    if (in_state && state_entry) {
        /* Compare state profile vs manifest profile */
        if (strcmp(state_entry->profile, manifest_entry->source_profile->name) != 0) {
            profile_changed = true;
            old_profile = strdup(state_entry->profile);
            if (!old_profile) {
                return ERROR(ERR_MEMORY,
                    "Failed to allocate old_profile for '%s'", fs_path);
            }
        }
    }

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
    CHECK_NULL(ws->manifest_index);
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

        /* Check if file exists in manifest (O(1) lookup) */
        file_entry_t *manifest_entry = hashmap_get(ws->manifest_index, fs_path);

        if (!manifest_entry) {
            /* Orphaned: in state, not in manifest */
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
 * Analyze divergence for all files in manifest
 *
 * Compares each file in the manifest against deployment state and filesystem
 * reality to detect modifications, deletions, and undeployed files.
 */
static error_t *analyze_files_divergence(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->manifest);
    CHECK_NULL(ws->state);

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
        error_t *err = analyze_file_divergence(ws, manifest_entry, state_entry);
        state_free_entry(state_entry);  /* Free owned memory from SQLite */

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
                ws->manifest_index,
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
 * Context for directory metadata checking callback
 */
typedef struct {
    workspace_t *ws;
    error_t *error;  /* Set on first error, stops iteration */
} directory_check_context_t;

/**
 * Callback to check one directory for metadata divergence
 *
 * Called by hashmap_foreach for each item in merged_metadata.
 * Filters for DIRECTORY kind and checks against filesystem.
 *
 * @param key Unused (item->key contains the actual key)
 * @param value Pointer to merged_metadata_entry_t
 * @param user_data Pointer to directory_check_context_t
 * @return true to continue iteration, false to stop on error
 */
static bool check_directory_callback(const char *key, void *value, void *user_data) {
    (void)key;  /* Unused - item has the key */

    const merged_metadata_entry_t *entry = (const merged_metadata_entry_t *)value;
    const metadata_item_t *item = entry->item;
    directory_check_context_t *ctx = (directory_check_context_t *)user_data;
    workspace_t *ws = ctx->ws;

    /* Filter: Only process directories */
    if (item->kind != METADATA_ITEM_DIRECTORY) {
        return true;  /* Continue iteration */
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
            ctx->error = error_wrap(err, "Failed to record deleted directory '%s'",
                                   filesystem_path);
            return false;  /* Stop iteration on error */
        }
        return true;  /* Continue with next directory */
    }

    /* Stat directory to get current metadata */
    struct stat dir_stat;
    if (stat(filesystem_path, &dir_stat) != 0) {
        /* Stat failed but exists: race condition or permission issue */
        fprintf(stderr, "warning: failed to stat directory '%s': %s\n",
                filesystem_path, strerror(errno));
        return true;  /* Non-fatal, continue */
    }

    /* Verify it's actually a directory (type may have changed) */
    if (!S_ISDIR(dir_stat.st_mode)) {
        fprintf(stderr, "warning: '%s' is no longer a directory (type changed)\n",
                filesystem_path);
        return true;  /* Non-fatal, skip - apply/revert don't handle type changes */
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
        ctx->error = error_wrap(err, "Failed to check metadata for directory '%s'",
                               filesystem_path);
        return false;  /* Stop iteration on error */
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
            ctx->error = error_wrap(err,
                                   "Failed to record directory metadata divergence for '%s'",
                                   filesystem_path);
            return false;  /* Stop iteration on error */
        }
    }

    return true;  /* Continue with next directory */
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

    /* Setup context for callback iteration */
    directory_check_context_t ctx = {
        .ws = ws,
        .error = NULL
    };

    /* Iterate merged metadata to find and check tracked directories.
     * No need to build temporary map - merged_metadata already has what we need
     * with precedence applied. Callback filters for DIRECTORY kind. */
    hashmap_foreach(ws->merged_metadata, check_directory_callback, &ctx);

    /* Return any error that occurred during iteration */
    return ctx.error;
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
 * Load workspace from repository
 */
error_t *workspace_load(
    git_repository *repo,
    profile_list_t *profiles,
    const dotta_config_t *config,
    const workspace_load_t *options,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    /* Resolve options: NULL means default (all analyses enabled).
     * This provides backward compatibility - callers not using the new
     * options parameter get the same behavior as before. */
    workspace_load_t resolved_opts;
    if (options) {
        resolved_opts = *options;  /* Copy provided options */
    } else {
        resolved_opts = workspace_load_default();  /* Default to all analyses */
    }

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
    hashmap_free(ws->manifest_index, NULL);
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
    state_free(ws->state);

    free(ws);
}
