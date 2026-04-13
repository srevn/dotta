/**
 * workspace.c - Workspace abstraction implementation
 *
 * Manages three-state consistency: Profile (git), Deployment (state.db), Filesystem (disk).
 * Detects and categorizes divergence to prevent data loss and enable safe operations.
 *
 * Trust Model:
 * Files trust the VWD manifest (virtual_manifest table), maintained by manifest layer.
 * Directories trust the tracked_directories state column, maintained by
 * manifest_sync_directories() with mark-inactive-then-reactivate semantics.
 * Both are patched in-memory for stale profiles (external Git changes).
 */

#include "core/workspace.h"

#include <config.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "crypto/encryption.h"
#include "crypto/keymanager.h"
#include "crypto/policy.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/privilege.h"

/**
 * Pending stat cache update (internal type)
 *
 * Accumulated during analyze_file_divergence() when the slow path confirms
 * CMP_EQUAL. The verified filesystem stat should be persisted so subsequent
 * runs benefit from the fast path.
 *
 * Path is borrowed from the manifest entry (valid for workspace lifetime).
 */
typedef struct {
    const char *filesystem_path;     /* Target path (borrowed from manifest entry) */
    stat_cache_t stat;               /* Captured stat triple for cache seeding */
} stat_cache_update_t;

/**
 * Workspace structure
 *
 * Contains indexed views of all three states plus divergence analysis.
 * Uses hashmaps for O(1) lookups during analysis.
 */
struct workspace {
    git_repository *repo;            /* Borrowed reference */
    arena_t *arena;                  /* Bump allocator for workspace-lifetime strings */

    /* State data */
    manifest_t *manifest;            /* Profile state (owned) */
    state_t *state;                  /* Deployment state (owned or borrowed) */
    bool owns_state;                 /* True if state is owned, false if borrowed */
    const string_array_t *profiles;  /* Borrowed from caller — valid for workspace lifetime */
    hashmap_t *profile_index;        /* Maps profile_name -> NULL (membership set, O(1) lookup) */

    /* Cached state query (shared between workspace_build_manifest_from_state
     * and analyze_orphaned_files to avoid redundant full-table scan) */
    state_file_entry_t *cached_state_files;  /* Owned, freed in workspace_free (NULL if empty) */
    size_t cached_state_count;               /* Number of entries in cached_state_files */

    /* Encryption and caching infrastructure */
    keymanager_t *keymanager;        /* Borrowed from global */
    content_cache_t *content_cache;  /* Owned - caches decrypted content */
    hashmap_t *metadata_cache;       /* Owned - maps profile_name -> metadata_t* */

    /* Cached directory state (shared between analyze_orphaned_directories
     * and analyze_directory_metadata_divergence to avoid redundant table scans) */
    state_directory_entry_t *cached_state_dirs;  /* Arena-allocated (NULL until first load) */
    size_t cached_state_dir_count;               /* Number of cached directory entries */

    /* Divergence tracking */
    workspace_item_t *diverged;      /* Array of diverged items (files and directories) */
    size_t diverged_count;           /* Number of diverged items */
    size_t diverged_capacity;        /* Allocated capacity of diverged array */
    hashmap_t *diverged_index;       /* Maps filesystem_path -> array index+1 (as void*) */

    /* Staleness tracking */
    bool manifest_stale;             /* True if any profile's stored HEAD was stale */
    hashmap_t *stale_paths;          /* Patched entries (NULL if no staleness) */
    hashmap_t *released_paths;       /* Entries removed from Git (NULL if no staleness) */
    hashmap_t *stale_profiles;       /* profile_name -> sentinel for stale profiles (NULL if none) */
    const hashmap_t *repaired_paths; /* From manifest_repair_stale: path -> old_blob_oid (borrowed) */

    /* Stat cache updates (accumulated during divergence analysis) */
    stat_cache_update_t *stat_updates; /* Pending slow-path updates (owned) */
    size_t stat_update_count;          /* Number of pending updates */
    size_t stat_update_capacity;       /* Allocated capacity of updates array */

    /* Status cache */
    workspace_status_t status;       /* Cached cleanliness assessment */
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
    const string_array_t *profiles,
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
    ws->profiles = profiles;           /* Borrowed — caller keeps alive past workspace_free */

    ws->profile_index = hashmap_borrow(32); /* Keys: borrowed from profiles->items[] */
    if (!ws->profile_index) {
        free(ws);
        return ERROR(ERR_MEMORY, "Failed to create profile index");
    }

    ws->diverged_index = hashmap_borrow(256);  /* Keys: arena-backed filesystem_path */
    if (!ws->diverged_index) {
        hashmap_free(ws->profile_index, NULL);
        free(ws);
        return ERROR(ERR_MEMORY, "Failed to create diverged index");
    }

    /* Build profile membership set for O(1) scope checks.
     * Values are NULL — this is a pure name set, not a value map. */
    for (size_t i = 0; i < profiles->count; i++) {
        error_t *err = hashmap_set(ws->profile_index, profiles->items[i], NULL);
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

    *out = ws;
    return NULL;
}

/**
 * Check for metadata (mode and ownership) divergence (data-centric design)
 *
 * Compares filesystem metadata with expected values to detect changes in
 * permissions (mode) and ownership (user/group). Always checks both mode and
 * ownership independently, setting flags for each.
 *
 * Data-centric approach: Accepts values directly instead of structs, enabling use with
 * both VWD cache (file_entry_t) and metadata (metadata_item_t) without conversion.
 * This eliminates Git loads for files (uses VWD cache) while preserving metadata
 * functionality for directories.
 *
 * @param expected_mode Expected permission mode (0 = skip mode check, no metadata tracked)
 * @param expected_owner Expected owner username (NULL = skip owner check)
 * @param expected_group Expected group name (NULL = skip group check)
 * @param st File stat data (must not be NULL, pre-captured by caller)
 * @param out_mode_differs Output flag for mode divergence (must not be NULL)
 * @param out_ownership_differs Output flag for ownership divergence (must not be NULL)
 * @return Error or NULL on success
 */
error_t *check_item_metadata_divergence(
    mode_t expected_mode,
    const char *expected_owner,
    const char *expected_group,
    const struct stat *st,
    bool *out_mode_differs,
    bool *out_ownership_differs
) {
    CHECK_NULL(st);
    CHECK_NULL(out_mode_differs);
    CHECK_NULL(out_ownership_differs);

    /* Clear output flags */
    *out_mode_differs = false;
    *out_ownership_differs = false;

    /* Check full mode (all permission bits, not just executable) */
    if (expected_mode > 0) {
        mode_t actual_mode = st->st_mode & 0777;
        if (actual_mode != expected_mode) {
            *out_mode_differs = true;
        }
    }

    /* Check ownership - only when running as root AND expected values provided */
    bool running_as_root = privilege_is_elevated();
    bool has_ownership = (expected_owner != NULL || expected_group != NULL);

    if (running_as_root && has_ownership) {
        bool owner_differs = false;
        bool group_differs = false;

        /* Check owner independently */
        if (expected_owner) {
            struct passwd *pwd = getpwuid(st->st_uid);
            if (pwd && pwd->pw_name) {
                if (strcmp(expected_owner, pwd->pw_name) != 0) {
                    owner_differs = true;
                }
            } else {
                /* getpwuid failed - orphaned UID or system error
                 * Treat as divergence: unknown ≠ expected (security-first) */
                owner_differs = true;
            }
        }

        /* Check group independently - no short-circuit */
        if (expected_group) {
            struct group *grp = getgrgid(st->st_gid);
            if (grp && grp->gr_name) {
                if (strcmp(expected_group, grp->gr_name) != 0) {
                    group_differs = true;
                }
            } else {
                /* getgrgid failed - orphaned GID or system error
                 * Treat as divergence: unknown ≠ expected (security-first) */
                group_differs = true;
            }
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
 * @param old_profile Previous profile from state (can be NULL, caller must free on error)
 * @param state Where the item exists (deployed/undeployed/etc.)
 * @param divergence What's wrong with it (bit flags, can combine)
 * @param item_kind FILE or DIRECTORY (explicit type)
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
    workspace_state_t state,
    divergence_type_t divergence,
    workspace_item_kind_t item_kind,
    bool on_filesystem,
    bool profile_enabled,
    bool profile_changed
) {
    CHECK_NULL(ws);
    CHECK_NULL(filesystem_path);

    /* Grow array if needed */
    if (ws->diverged_count >= ws->diverged_capacity) {
        size_t new_capacity = ws->diverged_capacity == 0 ? 32 : ws->diverged_capacity * 2;
        workspace_item_t *new_diverged = realloc(
            ws->diverged,
            new_capacity * sizeof(workspace_item_t)
        );
        if (!new_diverged) {
            return ERROR(ERR_MEMORY, "Failed to grow diverged array");
        }
        ws->diverged = new_diverged;
        ws->diverged_capacity = new_capacity;
    }

    /* Add entry */
    workspace_item_t *entry = &ws->diverged[ws->diverged_count];
    memset(entry, 0, sizeof(workspace_item_t));

    /* Borrow filesystem_path and storage_path directly — callers must
     * ensure these are arena-backed or arena_strdup'd before passing. */
    entry->filesystem_path = (char *) filesystem_path;
    entry->storage_path = (char *) storage_path;
    entry->profile = arena_strdup(ws->arena, profile);

    entry->state = state;
    entry->divergence = divergence;
    entry->item_kind = item_kind;
    entry->on_filesystem = on_filesystem;
    entry->profile_enabled = profile_enabled;
    entry->profile_changed = profile_changed;
    entry->old_profile = old_profile;  /* Ownership transfers on success (can be NULL) */

    if (profile && !entry->profile) {
        return ERROR(ERR_MEMORY, "Failed to allocate diverged entry");
    }

    /* Store array index in hashmap for O(1) lookup */
    error_t *err = hashmap_set(
        ws->diverged_index, entry->filesystem_path, (void *) (uintptr_t) (ws->diverged_count + 1)
    );
    if (err) {
        return error_wrap(err, "Failed to index diverged entry");
    }

    ws->diverged_count++;

    return NULL;
}

/**
 * Record a stat cache update for later flushing
 *
 * Called from analyze_file_divergence() when the slow path confirms CMP_EQUAL.
 * Accumulates the verified stat so workspace_flush_stat_caches() can persist it.
 *
 * Best-effort: silently skips on OOM rather than failing the analysis.
 *
 * @param ws Workspace (must not be NULL)
 * @param filesystem_path Path (borrowed from manifest, valid for workspace lifetime)
 * @param st Verified filesystem stat
 */
static void workspace_record_stat_update(
    workspace_t *ws,
    const char *filesystem_path,
    const struct stat *st
) {
    if (ws->stat_update_count >= ws->stat_update_capacity) {
        size_t new_cap = ws->stat_update_capacity ? ws->stat_update_capacity * 2 : 16;
        stat_cache_update_t *new_arr = realloc(
            ws->stat_updates,
            new_cap * sizeof(stat_cache_update_t)
        );
        if (!new_arr) return;
        ws->stat_updates = new_arr;
        ws->stat_update_capacity = new_cap;
    }

    ws->stat_updates[ws->stat_update_count++] = (stat_cache_update_t){
        .filesystem_path = filesystem_path,
        .stat = stat_cache_from_stat(st),
    };
}

/**
 * Analyze divergence for a single file using VWD cache
 *
 * This function uses the VWD (Virtual Working Directory) cache stored in
 * manifest_entry to perform divergence detection without database queries.
 * All expected state (blob_oid, type, deployed_at, etc.) is cached in
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
    const char *profile = manifest_entry->profile_name;

    /* Determine if entry came from state database using VWD cache
     *
     * Workspace manifests are always built from state (via
     * workspace_build_manifest_from_state), so blob_oid is always a real OID
     * here. The zero-check is a defensive guard — not a type discriminant.
     *
     * Note: Git-built manifests (from profile_build_manifest) now also carry
     * non-zero blob_oid, but those manifests are transient and never enter the
     * workspace divergence pipeline. */
    bool in_state = !git_oid_is_zero(&manifest_entry->blob_oid);

    /* Single stat capture for the entire analysis
     *
     * This stat is reused for:
     * 1. Existence check (on_filesystem flag)
     * 2. Type verification in comparison functions
     * 3. Metadata divergence checks (mode, ownership)
     */
    struct stat initial_stat;
    bool on_filesystem;

    if (lstat(fs_path, &initial_stat) != 0) {
        if (errno == ENOENT) {
            on_filesystem = false;
            memset(&initial_stat, 0, sizeof(initial_stat));
        } else {
            return ERROR(
                ERR_FS, "Failed to stat '%s': %s",
                fs_path, strerror(errno)
            );
        }
    } else {
        on_filesystem = true;
    }

    /* Divergence accumulator (bit flags, can combine) */
    divergence_type_t divergence = DIVERGENCE_NONE;

    /* State will be determined in PHASE 2 based on deployment status */
    workspace_state_t state = WORKSPACE_STATE_DEPLOYED;

    /* PHASE 1: Content and type analysis (if file exists and in state)
     * Buffer-based comparison for accurate divergence detection.
     *
     * Architecture:
     * - Use blob_oid from VWD cache (when in_state) for content loading
     * - Extract expected mode from VWD cache type field
     * - Compare directly to filesystem file (compare_buffer_to_disk)
     * - Capture stat for permission checking (zero extra syscalls)
     *
     * This provides:
     * - Architectural consistency (blob_oid unification)
     * - Accurate byte-level comparison with early exit
     * - Transparent encryption handling via content cache
     * - Stat propagation (single stat used for all checks)
     * - TOCTOU-aware (handles files deleted during analysis)
     */
    if (on_filesystem && in_state) {
        /* VWD cache blob_oid is already a 20-byte binary OID — no parse step.
         * The in_state guard above (git_oid_is_zero check) protects us from
         * operating on an un-populated entry. */
        const git_oid *blob_oid_ptr = &manifest_entry->blob_oid;

        /* Extract expected filemode from VWD cache type field
         *
         * Extracted before comparison strategy selection because both paths
         * need this value. Uses shared helper for consistent mapping.
         */
        git_filemode_t expected_mode = state_type_to_git_filemode(manifest_entry->type);

        /* Prepare for comparison - both paths capture stat for permission checking */
        struct stat file_stat;
        memset(&file_stat, 0, sizeof(file_stat));
        compare_result_t cmp_result;
        error_t *err = NULL;

        /* STAT CACHE FAST PATH
         *
         * If the filesystem stat matches the cached stat from when content was
         * last verified/deployed, skip content comparison entirely. This is the
         * same approach Git uses with its index.
         *
         * The stat cache is valid if the filesystem file was last verified or
         * deployed to match the current blob_oid. On match, we know content is
         * unchanged — set CMP_EQUAL and use initial_stat for permission checks.
         *
         * On miss (stat differs or cache unset), fall through to the existing
         * content comparison. False misses are harmless (just slower). False
         * positives cannot occur through normal filesystem operations because
         * the mtime+size+ino triple catches all content-changing operations.
         */
        const stat_cache_t *cached = &manifest_entry->stat_cache;
        if (cached->mtime != 0
            && cached->mtime == (int64_t) initial_stat.st_mtime
            && cached->size == (int64_t) initial_stat.st_size
            && cached->ino == (uint64_t) initial_stat.st_ino) {
            cmp_result = CMP_EQUAL;
            file_stat = initial_stat;
        } else {
            /* SLOW PATH: Full content comparison
             *
             * Strategy selection based on encryption status:
             * - Non-encrypted: Hash filesystem file and compare OID directly
             * - Encrypted: blob_oid is ciphertext hash; must load, decrypt, compare
             *
             * Both paths receive initial_stat to avoid redundant lstat syscalls.
             */
            if (!manifest_entry->encrypted) {
                err = compare_oid_to_disk(
                    blob_oid_ptr,
                    fs_path,
                    expected_mode,
                    &initial_stat,
                    &cmp_result,
                    &file_stat
                );
            } else {
                const buffer_t *expected_content = NULL;
                err = content_cache_get_from_blob_oid(
                    ws->content_cache,
                    blob_oid_ptr,
                    storage_path,
                    profile,
                    manifest_entry->encrypted,
                    &expected_content
                );

                if (!err) {
                    err = compare_buffer_to_disk(
                        expected_content,
                        fs_path,
                        expected_mode,
                        &initial_stat,
                        &cmp_result,
                        &file_stat
                    );
                }
                /* Note: Don't free expected_content - cache owns it! */
            }

            if (err) {
                return error_wrap(err, "Failed to verify '%s'", fs_path);
            }

            /* Slow path verified content — seed stat cache for fast path.
             * On next run, the stat cache check above will hit and skip comparison. */
            if (cmp_result == CMP_EQUAL) {
                workspace_record_stat_update(ws, fs_path, &file_stat);
            }
        }

        /* Set divergence flags based on comparison result */
        switch (cmp_result) {
            case CMP_EQUAL:
                /* Content and type match - no divergence from content comparison.
                 * Permission checking happens below. */
                break;

            case CMP_DIFFERENT:
                /* Content differs - accumulate CONTENT flag */
                divergence |= DIVERGENCE_CONTENT;
                break;

            case CMP_TYPE_DIFF:
                /* Type differs (file vs symlink) - this is a blocking condition.
                 * Return immediately with TYPE divergence. */
                return workspace_add_diverged(
                    ws, fs_path, storage_path, profile, NULL, WORKSPACE_STATE_DEPLOYED,
                    DIVERGENCE_TYPE, WORKSPACE_ITEM_FILE, on_filesystem, true, false
                );

            case CMP_MISSING:
                /* File was deleted during analysis (rare edge case).
                 * With stat propagation this case is unlikely but kept for
                 * robustness. Update flag and skip permission checks below. */
                on_filesystem = false;
                break;

            case CMP_UNVERIFIED:
                /* Verification could not be completed.
                 *
                 * This is a defensive fallback for rare edge cases where
                 * comparison could not determine file state. Accumulate
                 * UNVERIFIED flag and continue to permission checks.
                 */
                divergence |= DIVERGENCE_UNVERIFIED;
                break;
        }

        /* PERMISSION CHECKING: Two-phase approach
         *
         * Only check permissions if file still exists and no critical divergence.
         * Guards against file deletion (CMP_MISSING) and type mismatches.
         *
         * PHASE A: Git filemode (executable bit)
         *   - Check using VWD cache type field (converted to expected_mode)
         *   - Skip symlinks (exec bit doesn't apply)
         *   - Catches: file is 0755 in git but 0644 on disk (or vice versa)
         *
         * PHASE B: Full metadata (all permission bits + ownership)
         *   - Only if metadata exists for this file
         *   - Catches: granular changes like 0600->0644, ownership changes
         *
         * Both phases use the SAME file_stat (captured above), so no
         * extra syscalls. Flags are accumulated with |=.
         */
        if (on_filesystem && cmp_result != CMP_TYPE_DIFF && cmp_result != CMP_MISSING) {
            /* PHASE A: Check executable bit (skip symlinks) */
            if (expected_mode != GIT_FILEMODE_LINK) {
                bool expect_exec = (expected_mode == GIT_FILEMODE_BLOB_EXECUTABLE);
                bool is_exec = fs_stat_is_executable(&file_stat);

                if (expect_exec != is_exec) {
                    /* Executable bit differs between git and filesystem */
                    divergence |= DIVERGENCE_MODE;
                }
            }

            /* PHASE B: Check full metadata using VWD cache
             *
             * Mode sentinel: manifest_entry->mode == 0 means "no metadata tracked",
             * check will be skipped by check_item_metadata_divergence().
             */
            bool mode_differs = false;
            bool ownership_differs = false;

            error_t *check_err = check_item_metadata_divergence(
                manifest_entry->mode,     /* From VWD cache (mode_t, 0 = no metadata) */
                manifest_entry->owner,    /* From VWD cache (can be NULL) */
                manifest_entry->group,    /* From VWD cache (can be NULL) */
                &file_stat,
                &mode_differs,
                &ownership_differs
            );

            if (check_err) {
                return error_wrap(check_err, "Failed to check metadata for '%s'", fs_path);
            }

            /* Accumulate metadata divergence flags
             *
             * Examples of detected divergence:
             * - Phase A passed (both non-exec), but file is 0600 in VWD, 0644 on disk
             * - Phase A detected exec bit diff, also detects group/other bits differ */
            if (mode_differs) divergence |= DIVERGENCE_MODE;
            if (ownership_differs) divergence |= DIVERGENCE_OWNERSHIP;
        }
    }

    /* PHASE 2: Reality-based classification
     *
     * SCOPE-BASED ARCHITECTURE:
     * Use deployed_at timestamp to distinguish lifecycle states.
     *
     * deployed_at semantics (from SCOPE_BASED_ARCHITECTURE_PLAN.md Annex A):
     * - deployed_at = 0 -> File never deployed by dotta
     * - deployed_at > 0 -> File known to dotta (deployed or pre-existing)
     *
     * Classification:
     * 1. File missing + deployed_at = 0 -> UNDEPLOYED (needs initial deployment)
     * 2. File missing + deployed_at > 0 -> DELETED (was deployed, needs restoration)
     * 3. File present -> DEPLOYED (may have divergence)
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

    /* PHASE 3: Staleness flag
     *
     * Two complementary detection paths:
     *
     * Path A (in-memory patching): For read-only commands (status, diff).
     * workspace_build_manifest_from_state detected stale profile HEAD, patched VWD
     * cache from fresh Git manifest. Unconditional DIVERGENCE_STALE — safe
     * because read-only commands don't modify files.
     *
     * Path B (persistent repair): For apply command.
     * manifest_repair_stale() already updated state, workspace sees repaired
     * entries. repaired_paths maps path -> old_blob_oid. We verify the file
     * on disk matches old_blob_oid (what dotta deployed) before setting
     * DIVERGENCE_STALE. This prevents overwriting user modifications:
     *   - File matches old blob: DIVERGENCE_STALE (safe to deploy new content)
     *   - File matches neither: DIVERGENCE_CONTENT only (user modified, block)
     *
     * DIVERGENCE_STALE can combine with other flags:
     *   [stale]              — expected state changed, content matches new state
     *   [stale, modified]    — expected state changed, file has old deployed content
     */
    if (ws->stale_paths && hashmap_get(ws->stale_paths, fs_path)) {
        /* Path A: In-memory patching (read-only commands) */
        divergence |= DIVERGENCE_STALE;
    } else if (ws->repaired_paths && on_filesystem && (divergence & DIVERGENCE_CONTENT)) {
        /* Path B: Persistent repair — verify file matches old deployed blob.
         *
         * Only check when content diverges (file ≠ new expected blob). If content
         * matches new blob, there's no divergence and no need for STALE flag.
         */
        const git_oid *old_blob_oid = hashmap_get((hashmap_t *) ws->repaired_paths, fs_path);
        if (old_blob_oid) {
            /* Compare file on disk against OLD blob (what dotta deployed).
             * Reuse the same verification strategy as Phase 1. */
            git_filemode_t expected_mode = state_type_to_git_filemode(manifest_entry->type);
            struct stat verify_stat;
            compare_result_t verify_result;

            if (!manifest_entry->encrypted) {
                error_t *verify_err = compare_oid_to_disk(
                    old_blob_oid,
                    fs_path,
                    expected_mode,
                    &initial_stat,
                    &verify_result,
                    &verify_stat
                );
                if (!verify_err && verify_result == CMP_EQUAL) {
                    /* File matches old deployed content — stale repair is safe */
                    divergence |= DIVERGENCE_STALE;
                }
                if (verify_err) error_free(verify_err);
            } else {
                /* Encrypted: compare decrypted content */
                const buffer_t *old_content = NULL;
                error_t *verify_err = content_cache_get_from_blob_oid(
                    ws->content_cache,
                    old_blob_oid,
                    storage_path,
                    profile,
                    manifest_entry->encrypted,
                    &old_content
                );
                if (!verify_err && old_content) {
                    verify_err = compare_buffer_to_disk(
                        old_content,
                        fs_path,
                        expected_mode,
                        &initial_stat,
                        &verify_result,
                        &verify_stat
                    );
                    if (!verify_err && verify_result == CMP_EQUAL) {
                        divergence |= DIVERGENCE_STALE;
                    }
                }
                if (verify_err) error_free(verify_err);
            }
        }
    }

    /* PHASE 4: Profile reassignment detection
     *
     * Check VWD cache for old_profile to detect reassignments.
     * old_profile is set by manifest layer when a file's owning profile changes
     * (e.g., removed from high-precedence profile, fell back to lower).
     *
     * The old_profile field is persisted in the database and populated
     * into the VWD cache during workspace_build_manifest_from_state().
     * It remains set until acknowledged by successful deployment.
     * Borrow from arena-backed manifest entry (same lifetime as workspace)
     */
    bool profile_changed = (manifest_entry->old_profile != NULL);
    char *old_profile = profile_changed ? manifest_entry->old_profile : NULL;

    /* Maintain invariant: profile_changed implies old_profile is non-NULL */
    if (profile_changed && !old_profile) profile_changed = false;

    /* Add to workspace if there's any state change or divergence */
    if (state != WORKSPACE_STATE_DEPLOYED || divergence != DIVERGENCE_NONE || profile_changed) {
        error_t *err = workspace_add_diverged(
            ws, fs_path, storage_path, profile, old_profile, state,
            divergence, WORKSPACE_ITEM_FILE, on_filesystem, true, profile_changed
        );
        if (err) return err;
    }

    return NULL;
}

/**
 * Compute divergence for orphaned file
 *
 * Mirrors analyze_file_divergence() logic but optimized for orphan context.
 * Compares filesystem state against expected state from state database entry.
 *
 * Architecture:
 * - Uses VWD cached metadata (blob_oid, encrypted, mode, owner, group)
 * - Leverages content cache with transparent encryption handling
 * - Two-phase permission checking (exec bit + full metadata)
 * - Single-stat-per-file (caller provides pre-captured stat)
 *
 * Performance Safeguards:
 * - 100MB size limit (prevents loading huge files into memory)
 * - Content cache (reuses decrypted content across checks)
 * - Stat propagation (zero redundant lstat syscalls)
 *
 * @param ws Workspace (provides content_cache, repo)
 * @param state_entry State database entry with expected state (VWD cache)
 * @param fs_path Filesystem path
 * @param storage_path Storage path (for AAD in encryption)
 * @param profile Profile name
 * @param in_stat Pre-captured stat from caller (must not be NULL)
 * @return Divergence flags or DIVERGENCE_UNVERIFIED on error
 */
static divergence_type_t compute_orphan_divergence(
    workspace_t *ws,
    const state_file_entry_t *state_entry,
    const char *fs_path,
    const char *storage_path,
    const char *profile,
    const struct stat *in_stat
) {
    /* Defensive NULL checks */
    if (!ws || !state_entry || !fs_path || !in_stat) {
        return DIVERGENCE_UNVERIFIED;
    }

    /* Step 1: Validate blob_oid (defensive programming)
     *
     * state.c's read path already rejects wrong-sized BLOB columns, so by the
     * time we get here the OID should be well-formed. A zero OID (Git null)
     * still indicates a bad row — treat it as corruption.
     */
    if (git_oid_is_zero(&state_entry->blob_oid)) {
        return DIVERGENCE_UNVERIFIED;
    }
    const git_oid *blob_oid_ptr = &state_entry->blob_oid;

    /* Step 2: Extract expected filemode from type field
     *
     * Calculate once, use for both content comparison and mode checking.
     * Uses shared helper for consistent mapping across modules.
     */
    git_filemode_t expected_mode = state_type_to_git_filemode(state_entry->type);

    /* Stat for permission checking (receives copy from in_stat via comparison functions) */
    struct stat fresh_stat;
    memset(&fresh_stat, 0, sizeof(fresh_stat));
    compare_result_t cmp_result;
    error_t *err = NULL;

    /* Step 3: Content and type comparison with strategy selection
     *
     * Non-encrypted: Hash filesystem file and compare OID directly.
     * Encrypted: blob_oid is ciphertext hash; must load, decrypt, compare.
     *
     * Both paths receive in_stat to avoid redundant lstat syscalls.
     */
    if (!state_entry->encrypted) {
        /* Fast path: OID hash verification */
        err = compare_oid_to_disk(
            blob_oid_ptr,
            fs_path,
            expected_mode,
            in_stat,
            &cmp_result,
            &fresh_stat
        );

        if (err) {
            /* Hash verification failed (I/O error, permissions, etc.)
             * Return UNVERIFIED to prevent false "clean" indication. */
            error_free(err);
            return DIVERGENCE_UNVERIFIED;
        }
    } else {
        /* SLOW PATH: Content comparison for encrypted files
         *
         * Content cache provides:
         * - Automatic decryption (uses state_entry->encrypted flag)
         * - Caching (repeated checks for same blob don't re-decrypt)
         * - Error handling (missing key, corrupt data, etc.)
         *
         * VWD Pattern: Use state_entry->encrypted directly.
         * This flag was set atomically with blob_oid when entry was synced.
         */
        const buffer_t *expected_content = NULL;
        err = content_cache_get_from_blob_oid(
            ws->content_cache,
            blob_oid_ptr,
            storage_path,
            profile,
            state_entry->encrypted, /* VWD pattern: use cached flag */
            &expected_content
        );

        if (err) {
            /* Cannot load/decrypt content
             *
             * Possible causes:
             * - Encrypted file but no passphrase available (missing key)
             * - Decryption failed (wrong passphrase, corrupted ciphertext)
             * - I/O error reading blob from git
             * - Blob missing from repository (corruption)
             *
             * Conservative approach: Return UNVERIFIED to prevent false "clean" indication.
             * User will see [orphaned, unverified] and can investigate.
             */
            error_free(err);
            return DIVERGENCE_UNVERIFIED;
        }

        /* Content and type comparison using caller's stat */
        err = compare_buffer_to_disk(
            expected_content,
            fs_path,
            expected_mode,
            in_stat,
            &cmp_result,
            &fresh_stat
        );
        /* Note: Don't free expected_content - cache owns it! */

        if (err) {
            /* Comparison failed (I/O error, permissions, etc.) */
            error_free(err);
            return DIVERGENCE_UNVERIFIED;
        }
    }

    /* Step 4: Interpret comparison result
     *
     * Use switch statement (not if-else) for exhaustive handling.
     */
    divergence_type_t divergence = DIVERGENCE_NONE;
    bool file_exists = true;  /* Track for permission checking guard */

    switch (cmp_result) {
        case CMP_EQUAL:
            /* Content and type match - continue to permission checking */
            break;

        case CMP_DIFFERENT:
            /* Content differs between Git and filesystem */
            divergence |= DIVERGENCE_CONTENT;
            break;

        case CMP_TYPE_DIFF:
            /* Type differs (file vs symlink vs directory)
             *
             * Note: analyze_file_divergence returns early here, but for orphans
             * we accumulate divergence and check metadata too. This provides
             * more information to the user (e.g., "type + mode divergence").
             */
            divergence |= DIVERGENCE_TYPE;
            break;

        case CMP_MISSING:
            /* File deleted between caller's stat and content read (rare race)
             *
             * With stat propagation, CMP_MISSING can only occur if the file was
             * removed after the caller's single lstat but before the comparison
             * function read its contents. This is rare but handled gracefully.
             *
             * Report as DIVERGENCE_NONE - the orphan was already removed manually.
             * Apply will skip it (nothing to remove), state will be pruned.
             */
            file_exists = false;
            break;

        case CMP_UNVERIFIED:
            /* Verification could not be completed.
             *
             * This is a defensive fallback for rare edge cases where
             * comparison could not determine file state. Accumulate
             * UNVERIFIED flag and continue to permission checks.
             */
            divergence |= DIVERGENCE_UNVERIFIED;
            break;
    }

    /* Step 5: Permission checking (two-phase, if file still exists)
     *
     * Only check permissions if:
     * 1. File still exists (not deleted during analysis)
     * 2. No type divergence (type mismatch makes mode checking nonsensical)
     * 3. Verification didn't fail (we have fresh_stat from compare)
     *
     * PHASE A: Git filemode (executable bit)
     *   - Uses expected_mode from Step 2
     *   - Skips symlinks (exec bit doesn't apply)
     *   - Catches: file is 0755 in git but 0644 on disk (or vice versa)
     *
     * PHASE B: Full metadata (all permission bits + ownership)
     *   - Uses check_item_metadata_divergence() helper
     *   - Reuses fresh_stat from Step 3 (zero extra syscalls)
     *   - Skipped if state_entry->mode == 0 (no metadata tracked)
     *   - Separately tracks MODE and OWNERSHIP divergence
     */
    if (file_exists && !(divergence & DIVERGENCE_TYPE)) {
        /* PHASE A: Check executable bit (skip symlinks) */
        if (expected_mode != GIT_FILEMODE_LINK) {
            bool expect_exec = (expected_mode == GIT_FILEMODE_BLOB_EXECUTABLE);
            bool is_exec = fs_stat_is_executable(&fresh_stat);

            if (expect_exec != is_exec) {
                /* Executable bit differs between git and filesystem */
                divergence |= DIVERGENCE_MODE;
            }
        }

        /* PHASE B: Check full metadata using helper function
         *
         * Mode sentinel: state_entry->mode == 0 means "no metadata tracked",
         * check will be skipped by check_item_metadata_divergence().
         *
         * Uses fresh_stat populated by comparison function (same data as in_stat,
         * copied via out_stat parameter for consistent access pattern).
         */
        bool mode_differs = false;
        bool ownership_differs = false;

        error_t *check_err = check_item_metadata_divergence(
            state_entry->mode,    /* From VWD cache (mode_t, 0 = no metadata) */
            state_entry->owner,   /* From VWD cache (can be NULL) */
            state_entry->group,   /* From VWD cache (can be NULL) */
            &fresh_stat,          /* Reuse stat from compare (CRITICAL: not initial_stat!) */
            &mode_differs,
            &ownership_differs
        );

        if (check_err) {
            /* Metadata check failed (rare: getpwuid/getgrgid failure)
             * Preserve already-accumulated divergence (content/type) while
             * signaling that metadata verification was incomplete. */
            error_free(check_err);
            return divergence | DIVERGENCE_UNVERIFIED;
        }

        /* Accumulate metadata divergence flags
         *
         * OWNERSHIP is tracked separately for granular reporting.
         */
        if (mode_differs) divergence |= DIVERGENCE_MODE;
        if (ownership_differs) divergence |= DIVERGENCE_OWNERSHIP;
    }

    return divergence;
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

    /* Reuse state entries cached by workspace_build_manifest_from_state.
     * Both functions need the same full-table scan — caching avoids the
     * redundant query. Entries are owned by ws, freed in workspace_free(). */
    const state_file_entry_t *state_files = ws->cached_state_files;
    size_t state_count = ws->cached_state_count;

    /* Early exit: no files in state means no orphans */
    if (state_count == 0) {
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
            size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
            manifest_entry = &ws->manifest->entries[idx];
        }

        if (!manifest_entry) {
            /* In state but not in manifest — either orphaned or released.
             *
             * Released detection has two complementary paths:
             *
             * 1. In-memory patching (status/diff): workspace_build_manifest_from_state()
             *    detected stale entries, built fresh Git manifest, found file missing.
             *    Tracked in ws->released_paths.
             *
             * 2. Persistent repair (apply): manifest_repair_stale() already ran and
             *    set STATE_RELEASED in database. The in-memory patching path doesn't
             *    trigger (stored HEAD matches post-repair), so released_paths is empty.
             *    Check state lifecycle directly.
             *
             * Orphaned: File out of scope for other reasons (profile disabled,
             * branch deleted, etc.). Standard orphan handling applies.
             */
            bool is_released =
                (ws->released_paths && hashmap_get(ws->released_paths, fs_path) != NULL) ||
                (state_entry->state && strcmp(state_entry->state, STATE_RELEASED) == 0);

            bool profile_enabled = hashmap_has(ws->profile_index, profile);

            if (is_released) {
                /* RELEASED: File removed from Git externally (loss of authority)
                 *
                 * No divergence computation needed — we're not deleting this file.
                 * It will be left on filesystem and state entry cleaned up.
                 * Check filesystem presence only for display purposes.
                 */
                bool on_filesystem = (lstat(fs_path, &(struct stat){ 0 }) == 0);

                err = workspace_add_diverged(
                    ws,
                    fs_path,
                    storage_path,
                    profile,
                    NULL,
                    WORKSPACE_STATE_RELEASED,
                    DIVERGENCE_NONE,
                    WORKSPACE_ITEM_FILE,
                    on_filesystem,
                    profile_enabled,
                    false
                );
            } else {
                /* Standard orphan analysis */

                /* Single stat capture for orphan analysis
                 *
                 * This stat is reused for type verification, content comparison,
                 * and metadata checks - eliminating redundant lstat syscalls.
                 *
                 * stat_valid tracks whether we have usable stat data:
                 * - true: lstat succeeded, orphan_stat contains valid data
                 * - false: lstat failed, orphan_stat is zeroed (unusable)
                 */
                struct stat orphan_stat;
                bool on_filesystem;
                bool stat_valid = false;

                if (lstat(fs_path, &orphan_stat) != 0) {
                    if (errno == ENOENT) {
                        /* File doesn't exist - orphan was already removed manually */
                        on_filesystem = false;
                    } else {
                        /* Cannot stat file (EACCES, EIO, ELOOP, etc.)
                         *
                         * Conservative handling: Assume file exists but is inaccessible.
                         * We lack valid stat data, so divergence cannot be computed.
                         * Mark as UNVERIFIED below so:
                         * - Status shows [orphaned, unverified] (user visibility)
                         * - Apply skips removal (safety - can't verify what we can't stat)
                         */
                        on_filesystem = true;
                    }
                    memset(&orphan_stat, 0, sizeof(orphan_stat));
                } else {
                    on_filesystem = true;
                    stat_valid = true;
                }

                /* Compute divergence for orphaned file
                 *
                 * Only compute if file exists AND we have valid stat data.
                 *
                 * Cases:
                 * - File doesn't exist (ENOENT): divergence = NONE (nothing to compare)
                 * - File inaccessible (other error): divergence = UNVERIFIED (unsafe to act)
                 * - File accessible: divergence = computed from content/metadata analysis
                 *
                 * This enables status to predict apply behavior:
                 * - DIVERGENCE_NONE -> Clean orphan, will be removed
                 * - DIVERGENCE_CONTENT/TYPE -> Modified, apply will skip (safety check)
                 * - DIVERGENCE_MODE/OWNERSHIP -> Metadata changed, apply will skip
                 * - DIVERGENCE_UNVERIFIED -> Cannot verify, apply will skip
                 */
                divergence_type_t divergence = DIVERGENCE_NONE;
                if (stat_valid) {
                    divergence = compute_orphan_divergence(
                        ws,
                        state_entry,
                        fs_path,
                        storage_path,
                        profile,
                        &orphan_stat
                    );
                } else if (on_filesystem) {
                    /* File exists but stat failed - cannot verify divergence safely */
                    divergence = DIVERGENCE_UNVERIFIED;
                }

                err = workspace_add_diverged(
                    ws,
                    fs_path,
                    storage_path,
                    profile,
                    NULL,                       /* No old_profile for orphans */
                    WORKSPACE_STATE_ORPHANED,   /* State: in deployment state, not in profile */
                    divergence,                 /* Divergence: computed from filesystem comparison */
                    WORKSPACE_ITEM_FILE,
                    on_filesystem,
                    profile_enabled,
                    false                       /* No profile change for orphans */
                );
            }

            if (err) {
                return error_wrap(err, "Failed to add orphaned/released file");
            }
        }
    }

    return NULL;
}

/**
 * Analyze state for orphaned directory entries
 *
 * Uses the tracked_directories state column as the VWD authority for directories.
 * manifest_sync_directories() maintains this column with mark-inactive-then-reactivate
 * semantics on every manifest write operation, making it the single source of truth.
 *
 * Trust model (mirrors file orphan detection against the manifest):
 *   - Profile not in workspace scope -> ORPHANED (disabled or deleted profile)
 *   - State column not ACTIVE -> ORPHANED (manifest_sync_directories marked it)
 *   - Profile is stale + directory not in current Git metadata -> ORPHANED
 *   - Otherwise -> trust the state column (non-stale, ACTIVE = valid)
 *
 * The stale case uses the eagerly-loaded metadata_cache, which is always warm.
 *
 * Detects ALL orphaned directories (enabled + disabled profiles) and marks
 * each with profile_enabled flag for caller filtering.
 */
static error_t *analyze_orphaned_directories(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->profile_index);

    error_t *err = NULL;

    /* Load directories from state (cached for analyze_directory_metadata_divergence) */
    if (!ws->cached_state_dirs) {
        error_t *load_err = state_get_all_directories(
            ws->state,
            ws->arena,
            &ws->cached_state_dirs,
            &ws->cached_state_dir_count
        );
        if (load_err) {
            return error_wrap(load_err, "Failed to load state directories");
        }
    }

    if (ws->cached_state_dir_count == 0) return NULL;

    for (size_t i = 0; i < ws->cached_state_dir_count; i++) {
        const state_directory_entry_t *dir = &ws->cached_state_dirs[i];
        const char *profile = dir->profile;
        bool profile_in_scope = hashmap_has(ws->profile_index, profile);

        /* Determine orphan status from state column authority */
        bool is_orphaned = false;

        if (!profile_in_scope) {
            /* Profile disabled or deleted — directory is orphaned */
            is_orphaned = true;
        } else if (dir->state && (strcmp(dir->state, STATE_INACTIVE) == 0 ||
            strcmp(dir->state, STATE_DELETED) == 0)) {
            /* manifest_sync_directories() marked it non-active */
            is_orphaned = true;
        } else if (ws->stale_profiles && hashmap_has(ws->stale_profiles, profile)) {
            /* Profile is stale — verify directory still exists in current Git metadata.
             * metadata_cache is eagerly loaded for all profiles, so this is O(1). */
            const metadata_t *meta = ws_get_metadata(ws, profile);
            if (!meta) {
                is_orphaned = true;
            } else {
                const metadata_item_t *meta_item = NULL;
                error_t *get_err = metadata_get_item(meta, dir->storage_path, &meta_item);
                if (get_err) {
                    /* Not found or error — directory removed from metadata externally */
                    error_free(get_err);
                    is_orphaned = true;
                } else if (meta_item->kind != METADATA_ITEM_DIRECTORY) {
                    /* Kind changed (was directory, now file/symlink) */
                    is_orphaned = true;
                }
            }
        }
        /* else: profile in scope, state ACTIVE, not stale -> trust state column */

        if (is_orphaned) {
            bool profile_enabled = profile_in_scope;
            bool on_filesystem = fs_exists(dir->filesystem_path);

            err = workspace_add_diverged(
                ws,
                dir->filesystem_path,       /* Already arena-allocated */
                dir->storage_path,          /* Already arena-allocated */
                profile,
                NULL,                       /* No old_profile for orphans */
                WORKSPACE_STATE_ORPHANED,   /* State: in state, not in profile */
                DIVERGENCE_NONE,            /* Divergence: none */
                WORKSPACE_ITEM_DIRECTORY,
                on_filesystem,
                profile_enabled,
                false                       /* No profile change for orphans */
            );
            if (err) {
                return error_wrap(err, "Failed to add orphaned directory");
            }
        }
    }

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
     * VWD cache fields (blob_oid, type, deployed_at, etc.), so we
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
            case WORKSPACE_STATE_RELEASED:
                has_orphaned = true;
                break;

            case WORKSPACE_STATE_UNDEPLOYED:
            case WORKSPACE_STATE_DELETED:
            case WORKSPACE_STATE_UNTRACKED:
                has_warnings = true;
                break;

            case WORKSPACE_STATE_DEPLOYED:
                if (item->divergence != DIVERGENCE_NONE || item->profile_changed) {
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
 *
 * Depth-limited to prevent stack overflow from pathological directory nesting.
 */
#define SCAN_MAX_DEPTH 128

static error_t *scan_directory_for_untracked(
    const char *dir_path,
    const char *storage_prefix,
    const char *profile,
    ignore_context_t *ignore_ctx,
    workspace_t *ws,
    int depth
) {
    CHECK_NULL(dir_path);
    CHECK_NULL(storage_prefix);
    CHECK_NULL(profile);
    CHECK_NULL(ws);

    if (depth >= SCAN_MAX_DEPTH) {
        return NULL;
    }

    DIR *dir = opendir(dir_path);
    if (!dir) {
        /* Non-fatal: directory might have been deleted or permissions issue */
        return NULL;
    }

    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            errno = 0;  /* Clear before next readdir() — see post-loop check */
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
            errno = 0;
            continue;
        }

        /* Check if ignored */
        bool is_dir = S_ISDIR(st.st_mode);
        if (ignore_ctx) {
            bool ignored = false;
            error_t *err = ignore_should_ignore(ignore_ctx, full_path, is_dir, &ignored);
            if (!err && ignored) {
                free(full_path);
                errno = 0;
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
                ws,
                depth + 1
            );

            free(sub_storage_prefix);
            free(full_path);

            if (err) {
                closedir(dir);
                return err;
            }
        } else {
            /* Check if this file is already tracked.
             *
             * Two checks needed:
             * 1. Manifest index: file is in an active enabled profile
             * 2. Diverged index: file already classified (e.g., as released
             *    or orphaned by prior analysis phases). Released files are
             *    excluded from manifest but already have diverged entries —
             *    adding them as untracked would create duplicates.
             */
            bool already_tracked =
                (hashmap_get(ws->manifest->index, full_path) != NULL) ||
                (hashmap_get(ws->diverged_index, full_path) != NULL);

            if (!already_tracked) {
                /* This is an untracked file! */
                char *storage_path = str_format("%s/%s", storage_prefix, entry->d_name);
                if (!storage_path) {
                    free(full_path);
                    closedir(dir);
                    return ERROR(ERR_MEMORY, "Failed to allocate storage path");
                }

                /* Arena-copy heap strings — originals freed immediately after */
                char *arena_fp = arena_strdup(ws->arena, full_path);
                char *arena_sp = arena_strdup(ws->arena, storage_path);
                free(storage_path);
                free(full_path);

                if (!arena_fp || !arena_sp) {
                    closedir(dir);
                    return ERROR(ERR_MEMORY, "Failed to arena-copy untracked paths");
                }

                error_t *err = workspace_add_diverged(
                    ws,
                    arena_fp,
                    arena_sp,
                    profile,
                    NULL,                       /* No old_profile for untracked */
                    WORKSPACE_STATE_UNTRACKED,  /* State: on filesystem in tracked dir */
                    DIVERGENCE_NONE,            /* Divergence: none */
                    WORKSPACE_ITEM_FILE,
                    true,                       /* on filesystem */
                    true,                       /* profile_enabled */
                    false                       /* No profile change */
                );

                if (err) {
                    closedir(dir);
                    return err;
                }
            } else {
                free(full_path);
            }
        }
        errno = 0;
    }

    /* readdir() returns NULL on both end-of-directory and error.
     * With errno cleared before each call, non-zero errno means I/O error. */
    if (errno != 0) {
        int saved_errno = errno;
        closedir(dir);
        return ERROR(
            ERR_FS, "Error reading directory '%s': %s", dir_path,
            strerror(saved_errno)
        );
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
    const config_t *config
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->profiles);

    error_t *err = NULL;

    if (ws->profiles->count == 0) {
        return NULL;  /* No profiles to analyze */
    }

    /* Scan tracked directories from each enabled profile's state database */
    for (size_t p = 0; p < ws->profiles->count; p++) {
        const char *profile_name = ws->profiles->items[p];

        /* Get tracked directories from state database for this profile */
        state_directory_entry_t *directories = NULL;
        size_t dir_count = 0;
        err = state_get_directories_by_profile(
            ws->state, profile_name, ws->arena, &directories, &dir_count
        );
        if (err) {
            fprintf(
                stderr, "warning: failed to load directories for profile '%s': %s\n",
                profile_name, err->message
            );
            error_free(err);
            err = NULL;
            continue;
        }

        if (dir_count == 0) {
            /* Profile has no tracked directories - skip */
            continue;
        }

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
            fprintf(
                stderr, "warning: failed to load ignore patterns for profile '%s': %s\n",
                profile_name, err->message
            );
            error_free(err);
            err = NULL;
            ignore_ctx = NULL;
        }

        /* Scan each tracked directory */
        for (size_t i = 0; i < dir_count; i++) {
            const state_directory_entry_t *dir_entry = &directories[i];

            /* Skip removal-pending directories (STATE_INACTIVE or STATE_DELETED)
             *
             * ARCHITECTURE: These directories are staged for removal.
             * We should NOT scan them for untracked files because:
             * 1. The directory is being removed (profile disabled or released)
             * 2. Scanning would report spurious untracked files
             * 3. The profile may be re-enabled later (directories reactivated)
             *
             * This ensures untracked file detection only applies to active directories.
             */
            if (dir_entry->state && (strcmp(dir_entry->state, STATE_INACTIVE) == 0 ||
                strcmp(dir_entry->state, STATE_DELETED) == 0)) {
                continue;  /* Skip silently - these will be handled by orphan detection */
            }

            /* Skip directories already classified as orphaned by prior analysis.
             *
             * In the in-memory stale detection path (read-only commands), the
             * directory state in the database is still ACTIVE (state not modified),
             * but analyze_orphaned_directories() has already identified it as
             * orphaned (verified against current Git metadata). Scanning such
             * directories would report files as [new] that are actually
             * [released] — creating confusing duplicate entries.
             */
            if (hashmap_get(ws->diverged_index, dir_entry->filesystem_path) != NULL) {
                continue;
            }

            /* State directory entries contain:
             * - filesystem_path: Already resolved with custom_prefix (VWD principle)
             * - storage_path: Portable path for storage
             */

            /* Use filesystem path directly from state (already resolved) */
            const char *filesystem_path = dir_entry->filesystem_path;

            /* Check if directory still exists */
            if (!fs_exists(filesystem_path)) {
                continue;
            }

            /* Scan this directory for untracked files */
            err = scan_directory_for_untracked(
                filesystem_path,           /* Already resolved filesystem path */
                dir_entry->storage_path,   /* Portable storage path */
                profile_name,
                ignore_ctx,
                ws,
                0                          /* Initial depth */
            );

            if (err) {
                /* Non-fatal: continue with other directories */
                fprintf(
                    stderr, "warning: failed to scan directory '%s' in profile '%s': %s\n",
                    filesystem_path, profile_name, err->message
                );
                error_free(err);
                err = NULL;
            }
        }

        /* Free ignore context after scanning all directories in this profile */
        ignore_context_free(ignore_ctx);
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
 * ARCHITECTURE: Uses state (VWD) instead of metadata (Git) for directory resolution.
 * State contains filesystem_path already resolved with custom_prefix, enabling
 * correct divergence detection for custom/ prefix directories.
 *
 * @param ws Workspace (must not be NULL, state must be initialized)
 * @return Error or NULL on success
 */
static error_t *analyze_directory_metadata_divergence(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);

    error_t *err = NULL;

    /* Use cached directories (shared with analyze_orphaned_directories) */
    if (!ws->cached_state_dirs) {
        error_t *load_err = state_get_all_directories(
            ws->state,
            ws->arena,
            &ws->cached_state_dirs,
            &ws->cached_state_dir_count
        );
        if (load_err) {
            return error_wrap(
                load_err, "Failed to load tracked directories from state"
            );
        }
    }

    if (ws->cached_state_dir_count == 0) {
        return NULL;  /* No tracked directories */
    }

    /* Check each tracked directory for divergence */
    for (size_t i = 0; i < ws->cached_state_dir_count; i++) {
        const state_directory_entry_t *dir_entry = &ws->cached_state_dirs[i];

        /* Skip removal-pending directories (STATE_INACTIVE, STATE_DELETED)
         *
         * ARCHITECTURE: These directories are staged for removal and shouldn't
         * participate in divergence analysis. They'll be detected as orphans
         * by analyze_orphaned_directories() and cleaned by apply.
         *
         * This mirrors file handling pattern and the untracked directory scan skip.
         */
        if (dir_entry->state && (strcmp(dir_entry->state, STATE_INACTIVE) == 0 ||
            strcmp(dir_entry->state, STATE_DELETED) == 0)) {
            continue;  /* Skip silently - orphan detection will handle this */
        }

        /* Skip directories from profiles not in the enabled set.
         * Metadata divergence is only meaningful for active profiles. */
        if (!hashmap_has(ws->profile_index, dir_entry->profile)) {
            continue;
        }

        /* State directory entries contain:
         * - filesystem_path: Already resolved with custom_prefix (VWD principle)
         * - storage_path: Portable path
         * - profile: Source profile
         * - mode, owner, group: Expected metadata
         *
         * All strings are arena-allocated — no explicit free needed. */
        const char *filesystem_path = dir_entry->filesystem_path;
        const char *storage_path = dir_entry->storage_path;
        const char *profile_name = dir_entry->profile;

        /* Stat directory to get current metadata
         *
         * Use lstat() for both existence and type checking:
         * - ENOENT: Directory truly deleted
         * - Success + !S_ISDIR: Type changed (file, symlink - including broken ones)
         * - Success + S_ISDIR: Actual directory, check metadata  */
        struct stat dir_stat;
        if (lstat(filesystem_path, &dir_stat) != 0) {
            if (errno == ENOENT) {
                /* Directory truly deleted - record divergence */
                err = workspace_add_diverged(
                    ws,
                    filesystem_path,
                    storage_path,
                    profile_name,
                    NULL,                     /* No old_profile for directories */
                    WORKSPACE_STATE_DELETED,  /* State: was in profile, removed from filesystem */
                    DIVERGENCE_NONE,          /* Divergence: none (file is gone) */
                    WORKSPACE_ITEM_DIRECTORY,
                    false,                    /* on_filesystem (deleted) */
                    true,                     /* profile_enabled */
                    false                     /* No profile change */
                );

                if (err) {
                    return error_wrap(
                        err, "Failed to record deleted directory '%s'",
                        filesystem_path
                    );
                }
                continue;  /* Successfully recorded, check next directory */
            }

            /* Stat failed for other reason: race condition or permission issue */
            fprintf(
                stderr, "warning: failed to stat directory '%s': %s\n",
                filesystem_path, strerror(errno)
            );
            continue;  /* Non-fatal, skip this directory */
        }

        /* Verify it's actually a directory (type may have changed)
         *
         * Type changes (dir -> file, dir -> symlink) are detected here because:
         * 1. lstat() doesn't follow symlinks, so symlinks are caught
         * 2. S_ISDIR() fails for regular files and symlinks
         *
         * Record DIVERGENCE_TYPE to enable:
         * - status shows [type] divergence
         * - preflight blocks without --force
         * - apply clears and recreates with --force
         */
        if (!S_ISDIR(dir_stat.st_mode)) {
            err = workspace_add_diverged(
                ws,
                filesystem_path,
                storage_path,
                profile_name,
                NULL,                      /* No old_profile for directories */
                WORKSPACE_STATE_DEPLOYED,  /* Path exists, just wrong type */
                DIVERGENCE_TYPE,           /* Type changed (dir -> file/symlink) */
                WORKSPACE_ITEM_DIRECTORY,
                true,                      /* on_filesystem (path exists, wrong type) */
                true,                      /* profile_enabled */
                false                      /* No profile change */
            );

            if (err) {
                return error_wrap(
                    err, "Failed to record type change for directory '%s'",
                    filesystem_path
                );
            }
            continue;  /* Recorded, move to next directory */
        }

        /* Check metadata divergence using unified helper */
        bool mode_differs = false;
        bool ownership_differs = false;

        err = check_item_metadata_divergence(
            dir_entry->mode,   /* Expected mode from state */
            dir_entry->owner,  /* Expected owner from state */
            dir_entry->group,  /* Expected group from state */
            &dir_stat,
            &mode_differs,
            &ownership_differs
        );

        if (err) {
            return error_wrap(
                err, "Failed to check metadata for directory '%s'",
                filesystem_path
            );
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
                storage_path,
                profile_name,
                NULL,                      /* No old_profile for directories */
                WORKSPACE_STATE_DEPLOYED,  /* State: directory exists as expected */
                divergence,                /* Divergence: mode/ownership flags */
                WORKSPACE_ITEM_DIRECTORY,
                true,                      /* on_filesystem */
                true,                      /* profile_enabled */
                false                      /* No profile change */
            );

            if (err) {
                return error_wrap(
                    err, "Failed to record directory metadata divergence for '%s'",
                    filesystem_path
                );
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
    const config_t *config
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
        const char *profile_name = manifest_entry->profile_name;

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

        /* Tier 1: Check magic header in blob (source of truth).
         * Uses VWD-cached blob_oid directly — no tree entry loading needed.
         * Zero-copy view — we only peek at the first few header bytes,
         * so copying the full blob here would be wasteful. */
        gitops_blob_view_t blob_view;
        error_t *view_err = gitops_blob_view_open(
            ws->repo, &manifest_entry->blob_oid, &blob_view
        );
        if (view_err) {
            /* Non-fatal: can't read blob - skip this file */
            fprintf(
                stderr, "warning: failed to read blob for '%s' in profile '%s': %s\n",
                storage_path, profile_name,
                view_err->message ? view_err->message : "unknown error"
            );
            error_free(view_err);
            continue;
        }

        is_encrypted = encryption_is_encrypted(blob_view.data, blob_view.size);

        /* Close view immediately — only needed for magic header check above.
         * Prevents leak if future code adds early returns in metadata block. */
        gitops_blob_view_close(&blob_view);

        /* Tier 2: Cross-validate against VWD expected state (defense in depth)
         *
         * manifest_entry->encrypted is set from metadata by sync_entry_to_state()
         * and updated by patch_entry_from_fresh() for stale entries. It always
         * equals what metadata says — zero Git reads needed. */
        if (is_encrypted != manifest_entry->encrypted) {
            fprintf(
                stderr,
                "warning: encryption mismatch for '%s' in profile '%s'\n"
                "  Blob content says: %s\n"
                "  VWD expected state says: %s\n"
                "  Using actual state from blob content. To fix, run:\n"
                "    dotta update -p %s '%s'\n",
                storage_path, profile_name,
                is_encrypted ? "encrypted" : "plaintext",
                is_encrypted ? "plaintext" : "encrypted",
                profile_name, storage_path
            );
        }

        /* Policy mismatch: should be encrypted but isn't */
        if (should_auto_encrypt && !is_encrypted) {
            /* Check if file already has divergence (O(1) index lookup).
             * This prevents last-write-wins bug when multiple analysis functions
             * detect different divergence types for the same file. */
            void *idx_ptr = hashmap_get(ws->diverged_index, manifest_entry->filesystem_path);
            workspace_item_t *existing = NULL;
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;  /* Convert index+1 back to index */
                existing = &ws->diverged[idx];
            }

            if (existing) {
                /* File already diverged - accumulate encryption flag
                 *
                 * Example: File is DEPLOYED with CONTENT divergence AND violates encryption
                 * policy. We accumulate: divergence |= DIVERGENCE_ENCRYPTION.
                 * Result: User sees both flags: "modified [encryption]" in status. */
                existing->divergence |= DIVERGENCE_ENCRYPTION;
            } else {
                /* File has NO other divergence — encryption policy is the only issue.
                 *
                 * Use deployed_at from VWD cache to determine lifecycle state.
                 * Manifest is built from state (workspace_build_manifest_from_state),
                 * so deployed_at is always populated:
                 *   > 0  -> file known/deployed
                 *   == 0 -> file never deployed */
                workspace_state_t item_state = manifest_entry->deployed_at > 0
                    ? WORKSPACE_STATE_DEPLOYED
                    : WORKSPACE_STATE_UNDEPLOYED;

                struct stat enc_stat;
                bool on_filesystem = (lstat(manifest_entry->filesystem_path, &enc_stat) == 0);

                err = workspace_add_diverged(
                    ws,
                    manifest_entry->filesystem_path,
                    storage_path,
                    profile_name,
                    NULL,
                    item_state,            /* State: deployed or undeployed */
                    DIVERGENCE_ENCRYPTION, /* Divergence: encryption policy violated */
                    WORKSPACE_ITEM_FILE,
                    on_filesystem,
                    true,                  /* profile_enabled */
                    false                  /* No profile change */
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
 * Patch a manifest entry's VWD cache from a fresh Git manifest entry
 *
 * Replaces stale cached state (blob_oid, type, mode, metadata) with
 * current values from the fresh manifest built from Git.
 *
 * The fresh_entry has a git_tree_entry from which we extract blob_oid and type.
 * Metadata comes from the workspace's pre-loaded metadata cache.
 *
 * @param vwd_entry Manifest entry to patch (VWD cache fields will be replaced)
 * @param fresh_entry Fresh entry from profile_build_manifest (has tree entry)
 * @param metadata Pre-loaded metadata for the profile (can be NULL)
 * @return Error or NULL on success
 */
static error_t *patch_entry_from_fresh(
    file_entry_t *vwd_entry,
    const file_entry_t *fresh_entry,
    const metadata_t *metadata,
    arena_t *arena
) {
    /* Read identity fields from fresh entry (populated during tree walk) */
    const git_oid *blob_oid = &fresh_entry->blob_oid;
    state_file_type_t new_type = fresh_entry->type;
    mode_t new_mode = fresh_entry->mode;

    /* Look up metadata for this file (may override mode, provide owner/group/encrypted) */
    const char *new_owner = NULL;
    const char *new_group = NULL;
    bool new_encrypted = false;

    if (metadata) {
        const metadata_item_t *meta_item = NULL;
        error_t *meta_err = metadata_get_item(metadata, fresh_entry->storage_path, &meta_item);
        if (meta_err) {
            /* NOT_FOUND is fine (old profiles without metadata) */
            if (meta_err->code != ERR_NOT_FOUND) return meta_err;
            error_free(meta_err);
        } else if (meta_item) {
            if (meta_item->mode != 0) new_mode = meta_item->mode;

            new_owner = meta_item->owner;
            new_group = meta_item->group;

            if (meta_item->kind == METADATA_ITEM_FILE) {
                new_encrypted = meta_item->file.encrypted;
            }
        }
    }

    /* Arena-allocate replacement strings. Owner/group are the only strings the
     * patch actually replaces now that blob_oid is inline binary. */
    char *dup_owner = arena_strdup(arena, new_owner);
    char *dup_group = arena_strdup(arena, new_group);

    if ((new_owner && !dup_owner) || (new_group && !dup_group)) {
        return ERROR(
            ERR_MEMORY, "Failed to allocate patched fields for '%s'",
            fresh_entry->storage_path
        );
    }

    git_oid_cpy(&vwd_entry->blob_oid, blob_oid);
    vwd_entry->type = new_type;
    vwd_entry->mode = new_mode;
    vwd_entry->owner = dup_owner;
    vwd_entry->group = dup_group;

    vwd_entry->encrypted = new_encrypted;

    /* Invalidate stat cache — blob_oid may have changed, so the cached stat
     * (recorded against the OLD blob_oid) is no longer valid. Clearing forces
     * the slow path in analyze_file_divergence(), which correctly compares
     * filesystem content against the NEW expected blob_oid. */
    vwd_entry->stat_cache = STAT_CACHE_UNSET;

    /* Update profile ownership if owner changed (precedence shift).
     *
     * Arena-strdup the name so the VWD entry is self-contained — the fresh
     * manifest (and the local profile_list_t that built it) may be freed
     * before the workspace. */
    if (fresh_entry->profile_name &&
        strcmp(vwd_entry->profile_name, fresh_entry->profile_name) != 0) {
        vwd_entry->profile_name = arena_strdup(arena, fresh_entry->profile_name);
        if (!vwd_entry->profile_name) {
            return ERROR(
                ERR_MEMORY, "Failed to allocate profile name for '%s'",
                fresh_entry->storage_path
            );
        }
    }

    return NULL;
}

/**
 * Build in-memory manifest from state manifest table
 *
 * Reads manifest entries from state DB and constructs manifest_t structure.
 * Does NOT load git_tree_entry* pointers (set to NULL). Consumers use the
 * VWD-cached blob_oid for content access instead of tree entry loading.
 *
 * Staleness Detection and In-Memory Patching:
 * After loading state entries, compares each profile's stored HEAD against
 * the branch's current HEAD. If any profile is stale (external Git changes):
 *   - Builds a fresh manifest from Git via profile_build_manifest()
 *   - Patches VWD cache fields for stale entries found in fresh manifest
 *   - Marks entries removed from Git in ws->released_paths (for orphan analysis)
 *   - Tracks patched entries in ws->stale_paths (for DIVERGENCE_STALE flag)
 *
 * This in-memory patching provides visibility in read-only commands (status)
 * without modifying the state database.
 *
 * Files from profiles not in the workspace scope are filtered out silently.
 * This can happen if a profile is disabled but manifest still has orphaned entries.
 *
 * Performance:
 *   Common case (no staleness): O(M × DB) + O(P) ref lookups
 *   Stale case: O(M × DB) + O(F) fresh manifest build, F = total files in Git
 *
 * @param ws Workspace (must not be NULL, state must be loaded)
 * @param skip_stale_detection If true, assume state is current and bypass both
 *                             manifest_detect_stale_profiles() and the in-memory
 *                             patching path. Only safe when the caller has
 *                             persistently repaired staleness via
 *                             manifest_repair_stale() within the same transaction.
 * @return Error or NULL on success
 */
static error_t *workspace_build_manifest_from_state(
    workspace_t *ws,
    bool skip_stale_detection
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->profile_index);

    error_t *err = NULL;
    state_file_entry_t *state_entries = NULL;
    size_t state_count = 0;
    hashmap_t *stale_profiles = NULL;
    manifest_t *fresh_manifest = NULL;
    profile_list_t *local_profiles = NULL;  /* Only loaded when stale — freed before return */

    /* Create workspace arena for all workspace-lifetime string allocations.
     * 128 KB fits ~200 files comfortably in a single block. */
    ws->arena = arena_create(128 * 1024);
    if (!ws->arena) {
        return ERROR(ERR_MEMORY, "Failed to create workspace arena");
    }

    /* Read all entries from manifest table (arena-allocated).
     *
     * Cached on workspace for reuse by analyze_orphaned_files().
     * Arena handles cleanup — no state_free_all_files() needed. */
    err = state_get_all_files(ws->state, ws->arena, &state_entries, &state_count);
    if (err) {
        return error_wrap(err, "Failed to read manifest from state");
    }
    ws->cached_state_files = state_entries;
    ws->cached_state_count = state_count;

    /* Staleness Detection (Phase 1 of stale manifest healing)
     *
     * Compare each profile's stored commit_oid (from enabled_profiles) against
     * its branch's current HEAD. If any mismatch: external Git operations
     * occurred, VWD cache is stale.
     *
     * Cost: O(P) state queries + O(P) ref-to-OID lookups where P = enabled
     * profile count (typically < 10). profile_index is a membership set (NULL
     * values), so manifest_detect_stale_profiles resolves HEAD via lightweight
     * git_reference_name_to_id — no profile_list_load overhead.
     *
     * When the caller has already persisted a fresh manifest via
     * manifest_repair_stale() within its transaction (apply.c), the state we
     * just read is current by construction. Skipping detection avoids the
     * redundant ref lookups and leaves stale_profiles NULL, which naturally
     * routes the loop below through the non-stale branch.
     */
    if (!skip_stale_detection) {
        err = manifest_detect_stale_profiles(
            ws->repo, ws->state, ws->profile_index, &stale_profiles
        );
        if (err) {
            return error_wrap(err, "Failed to detect stale profiles");
        }
    }

    /* If staleness detected, build fresh manifest from Git for patching.
     *
     * The fresh manifest represents the current truth in Git after external
     * operations. We'll use it to:
     * - Patch VWD cache for files that still exist (updated blob_oid/metadata)
     * - Identify files removed from Git (mark for release)
     *
     * Cost: O(F) where F = total files across all enabled profiles (rare path).
     */
    if (stale_profiles) {
        ws->manifest_stale = true;

        /* Load full profile_t objects — needed by profile_build_manifest for
         * Git tree walks. Scoped to the stale repair path; freed below after
         * the fresh manifest is consumed and profile names are arena_strdup'd. */
        err = profile_list_load(ws->repo, ws->profiles, &local_profiles);
        if (err) {
            hashmap_free(stale_profiles, NULL);
            return error_wrap(err, "Failed to load profiles for stale repair");
        }

        /* Load metadata for all profiles (not just stale ones — precedence
         * resolution in the fresh manifest may assign files to non-stale
         * profiles, and patch_entry_from_fresh needs their metadata).
         *
         * Stored on ws->metadata_cache so analyze_orphaned_directories can
         * also access it later via ws_get_metadata(). */
        ws->metadata_cache = hashmap_borrow(16);
        if (!ws->metadata_cache) {
            profile_list_free(local_profiles);
            hashmap_free(stale_profiles, NULL);
            return ERROR(ERR_MEMORY, "Failed to create metadata cache");
        }

        for (size_t i = 0; i < ws->profiles->count; i++) {
            const char *profile_name = ws->profiles->items[i];
            metadata_t *metadata = NULL;

            error_t *meta_err = metadata_load_from_branch(ws->repo, profile_name, &metadata);
            if (meta_err) {
                /* Graceful fallback: create empty metadata if loading fails.
                 * This ensures content layer always has metadata for validation.
                 * Empty metadata will cause "file not in metadata" errors during
                 * divergence analysis, which is the correct behavior for profiles
                 * without metadata (new profiles or corrupted metadata files). */
                error_free(meta_err);
                error_t *create_err = metadata_create_empty(&metadata);
                if (create_err) {
                    profile_list_free(local_profiles);
                    hashmap_free(stale_profiles, NULL);
                    return error_wrap(
                        create_err, "Failed to create metadata for profile '%s'",
                        profile_name
                    );
                }
            }

            error_t *set_err = hashmap_set(ws->metadata_cache, profile_name, metadata);
            if (set_err) {
                metadata_free(metadata);
                profile_list_free(local_profiles);
                hashmap_free(stale_profiles, NULL);
                return error_wrap(
                    set_err, "Failed to cache metadata for profile '%s'",
                    profile_name
                );
            }
        }

        /* Get prefix map for path resolution during fresh manifest build */
        hashmap_t *prefix_map = NULL;
        err = state_get_prefix_map(ws->state, &prefix_map);
        if (err) {
            profile_list_free(local_profiles);
            hashmap_free(stale_profiles, NULL);
            return error_wrap(err, "Failed to get prefix map for stale repair");
        }

        err = profile_build_manifest(ws->repo, local_profiles, prefix_map, NULL, &fresh_manifest);
        hashmap_free(prefix_map, free);
        if (err) {
            profile_list_free(local_profiles);
            hashmap_free(stale_profiles, NULL);
            return error_wrap(err, "Failed to build fresh manifest for stale repair");
        }

        /* Allocate tracking hashmaps */
        ws->stale_paths = hashmap_borrow(64);
        ws->released_paths = hashmap_borrow(16);
        if (!ws->stale_paths || !ws->released_paths) {
            manifest_free(fresh_manifest);
            profile_list_free(local_profiles);
            hashmap_free(stale_profiles, NULL);
            return ERROR(ERR_MEMORY, "Failed to allocate staleness tracking");
        }
    }

    /* Allocate manifest structure */
    ws->manifest = calloc(1, sizeof(manifest_t));
    if (!ws->manifest) {
        manifest_free(fresh_manifest);
        hashmap_free(stale_profiles, NULL);
        return ERROR(ERR_MEMORY, "Failed to allocate manifest");
    }

    /* Allocate entries array (max size = state_count) */
    ws->manifest->entries = calloc(state_count, sizeof(file_entry_t));
    if (!ws->manifest->entries) {
        free(ws->manifest);
        ws->manifest = NULL;
        manifest_free(fresh_manifest);
        hashmap_free(stale_profiles, NULL);
        return ERROR(ERR_MEMORY, "Failed to allocate manifest entries");
    }

    /*
     * Create hash map for O(1) lookups
     * Maps: filesystem_path -> index in entries array (offset by 1)
     * Use state_count as initial capacity (optimal sizing, no rehashing needed)
     */
    hashmap_t *path_map = hashmap_borrow(state_count > 0 ? state_count : 64);
    if (!path_map) {
        free(ws->manifest->entries);
        free(ws->manifest);
        ws->manifest = NULL;
        manifest_free(fresh_manifest);
        hashmap_free(stale_profiles, NULL);
        return ERROR(ERR_MEMORY, "Failed to create manifest index");
    }

    size_t manifest_idx = 0;

    /* Build manifest entries from state */
    for (size_t i = 0; i < state_count; i++) {
        const state_file_entry_t *state_entry = &state_entries[i];
        file_entry_t *entry = &ws->manifest->entries[manifest_idx];

        /* Check profile is in workspace scope (O(1) hashmap lookup) */
        if (!hashmap_has(ws->profile_index, state_entry->profile)) {
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

        /* Borrow profile name from state entry (same arena lifetime as workspace) */
        entry->profile_name = state_entry->profile;

        /* Borrow paths from arena-backed state entries (same lifetime) */
        entry->storage_path = state_entry->storage_path;
        entry->filesystem_path = state_entry->filesystem_path;

        /* Skip non-active entries (marked for removal or stale)
         *
         * These entries remain in the manifest table for orphan detection.
         * The orphan detection phase (analyze_orphaned_files) will load them
         * and mark them as ORPHANED or RELEASED for cleanup by apply.
         */
        if (state_entry->state && (strcmp(state_entry->state, STATE_INACTIVE) == 0 ||
            strcmp(state_entry->state, STATE_DELETED) == 0 ||
            strcmp(state_entry->state, STATE_RELEASED) == 0)) {
            continue;  /* Don't increment manifest_idx */
        }

        /* Check if this entry is from a stale profile and needs patching */
        bool entry_is_stale = stale_profiles && state_entry->profile &&
            hashmap_has(stale_profiles, state_entry->profile);

        if (entry_is_stale && fresh_manifest && fresh_manifest->index) {
            /* Stale entry — look up in fresh manifest for patching
             *
             * The fresh manifest represents current Git truth. Three cases:
             *
             * CASE A: File found in fresh manifest (same or different profile)
             *   -> Patch VWD cache with current values. File stays in manifest.
             *
             * CASE B: File NOT in fresh manifest (removed from all profiles)
             *   -> File removed from Git externally. Add to released_paths,
             *     skip from manifest. Orphan analysis will classify as RELEASED.
             */
            void *fresh_idx_ptr = hashmap_get(fresh_manifest->index, state_entry->filesystem_path);

            if (fresh_idx_ptr) {
                /* CASE A: File still in Git — populate from state, then patch */
                size_t fresh_idx = (size_t) (uintptr_t) fresh_idx_ptr - 1;
                const file_entry_t *fresh_entry = &fresh_manifest->entries[fresh_idx];

                /* Save the old blob OID before patching — needed to determine
                 * whether the file's content actually changed (as opposed to
                 * only the profile HEAD moving). Inline copy is 20 bytes. */
                git_oid old_blob_oid = state_entry->blob_oid;

                /* Populate VWD fields from state (baseline).
                 *
                 * Borrow arena-backed strings (old_profile, owner, group) from
                 * state entries. blob_oid is an inline binary struct copy;
                 * patch_entry_from_fresh will overwrite it below. */
                entry->old_profile = state_entry->old_profile;
                entry->blob_oid = state_entry->blob_oid;
                entry->type = state_entry->type;
                entry->mode = state_entry->mode;
                entry->owner = state_entry->owner;
                entry->group = state_entry->group;
                entry->encrypted = state_entry->encrypted;
                entry->deployed_at = state_entry->deployed_at;
                /* stat_cache set after blob_changed check below — preserved when
                 * blob_oid unchanged, left at STAT_CACHE_UNSET when changed */

                /* Now overwrite stale fields from fresh manifest */
                const metadata_t *meta = ws_get_metadata(ws, fresh_entry->profile_name);
                err = patch_entry_from_fresh(entry, fresh_entry, meta, ws->arena);
                if (err) {
                    err = error_wrap(
                        err, "Failed to patch stale entry '%s'", state_entry->
                        storage_path
                    );
                    goto cleanup;
                }

                /* Track as stale ONLY if blob_oid actually changed.
                 *
                 * When blob_oid is unchanged (profile HEAD moved but this file's
                 * content was not modified in Git), the file is not stale from the
                 * user's perspective. Flagging these as DIVERGENCE_STALE would show
                 * them as "uncommitted changes" even though their content is correct.
                 *
                 * Only files whose content actually changed in Git (new blob_oid)
                 * need the DIVERGENCE_STALE flag for deployment/display purposes.
                 */
                bool blob_changed = !git_oid_equal(&old_blob_oid, &entry->blob_oid);

                /* Preserve stat cache when blob_oid is unchanged.
                 *
                 * When profile HEAD moved but this file's blob is identical,
                 * the cached stat triple is still valid (it was recorded against
                 * the same blob_oid). Restoring it avoids the slow content-
                 * comparison path for files that only had a HEAD refresh.
                 *
                 * When blob_oid changed, stat_cache stays STAT_CACHE_UNSET
                 * (from patch_entry_from_fresh), correctly forcing the slow path. */
                if (!blob_changed) {
                    entry->stat_cache = state_entry->stat_cache;
                }

                if (blob_changed) {
                    error_t *track_err = hashmap_set(
                        ws->stale_paths,
                        entry->filesystem_path,
                        (void *) (uintptr_t) 1
                    );
                    if (track_err) {
                        manifest_idx++;  /* entry populated — track for cleanup */
                        err = track_err;
                        goto cleanup;
                    }
                }
            } else {
                /* CASE B: File removed from Git externally
                 *
                 * No enabled profile contains this file. Add to released_paths
                 * so analyze_orphaned_files emits WORKSPACE_STATE_RELEASED.
                 * Skip from manifest (file is no longer in scope). */
                err = hashmap_set(
                    ws->released_paths,
                    state_entry->filesystem_path,
                    (void *) (uintptr_t) 1
                );
                if (err) {
                    goto cleanup;
                }

                continue;  /* Don't add to manifest */
            }
        } else {
            /* Non-stale entry — borrow VWD cache from arena-backed state entries.
             *
             * These fields enable O(1) divergence checking without N database queries.
             * They represent the cached expected state that workspace divergence
             * analysis will compare against filesystem reality.
             *
             * Both state entries and manifest entries share the workspace lifetime. */
            entry->old_profile = state_entry->old_profile;
            entry->blob_oid = state_entry->blob_oid;
            entry->type = state_entry->type;
            entry->mode = state_entry->mode;
            entry->owner = state_entry->owner;
            entry->group = state_entry->group;
            entry->encrypted = state_entry->encrypted;
            entry->deployed_at = state_entry->deployed_at;
            entry->stat_cache = state_entry->stat_cache;
        }

        /* Track entry for cleanup — must precede any further fallible operations
         * so the centralized cleanup loop (j < manifest_idx) covers this entry. */
        manifest_idx++;

        /* Store index in hashmap (offset by 1 to distinguish from NULL).
         * manifest_idx already holds the 1-based value after the increment above.
         * The cast through uintptr_t is safe: indices are much smaller than
         * SIZE_MAX, and we never dereference these "pointers". */
        err = hashmap_set(path_map, entry->filesystem_path, (void *) (uintptr_t) (manifest_idx));
        if (err) {
            err = error_wrap(err, "Failed to populate manifest index");
            goto cleanup;
        }
    }

    /* Transfer index ownership to manifest */
    ws->manifest->index = path_map;
    path_map = NULL;  /* Prevent double-free on cleanup */

    /* Set final count (may be less than state_count due to filtering) */
    ws->manifest->count = manifest_idx;
    ws->manifest->arena_backed = true;

    manifest_free(fresh_manifest);

    /* Free local profiles — all VWD profile_name pointers that were patched
     * from fresh_manifest entries are now arena_strdup'd (see
     * patch_entry_from_fresh), so no dangling references remain. */
    profile_list_free(local_profiles);

    /* Transfer stale_profiles ownership to workspace for use by
     * analyze_orphaned_directories() — freed in workspace_free() */
    ws->stale_profiles = stale_profiles;

    return NULL;

cleanup:
    /* Simplified error cleanup — arena handles all string fields.
     * Only free heap-allocated structures. */
    hashmap_free(path_map, NULL);
    free(ws->manifest->entries);
    free(ws->manifest);
    ws->manifest = NULL;
    manifest_free(fresh_manifest);
    profile_list_free(local_profiles);
    hashmap_free(stale_profiles, NULL);
    return err;
}

/**
 * Load workspace from repository
 */
error_t *workspace_load(
    git_repository *repo,
    state_t *state,
    const string_array_t *profiles,
    const config_t *config,
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

    /* Create empty workspace — borrows profile names from caller.
     *
     * No profile_list_load here. Full profile_t objects (Git ref resolution,
     * peel, tree loading) are deferred to the rare stale repair path inside
     * workspace_build_manifest_from_state. In the common (non-stale) case,
     * the workspace never touches Git for profile loading.
     *
     * Metadata loading is similarly deferred — only needed when stale entries
     * must be patched from fresh Git state. */
    err = workspace_create_empty(repo, profiles, &ws);
    if (err) {
        return err;
    }

    /* Store repaired_paths from caller (borrowed reference, not freed by workspace) */
    ws->repaired_paths = resolved_opts.repaired_paths;

    /* Initialize encryption infrastructure */
    /* Note: keymanager can be NULL if encryption is not configured - this is valid */
    ws->keymanager = keymanager_get_global(config);

    ws->content_cache = content_cache_create(ws->repo, ws->keymanager);
    if (!ws->content_cache) {
        workspace_free(ws);
        return ERROR(ERR_MEMORY, "Failed to create content cache");
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
    err = workspace_build_manifest_from_state(ws, resolved_opts.repair_completed);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to build manifest from state");
    }

    /* Verify manifest index was populated (architectural invariant)
     * This check ensures workspace_build_manifest_from_state() correctly
     * built the index, maintaining consistency with the write path pattern. */
    if (!ws->manifest->index) {
        workspace_free(ws);
        return ERROR(
            ERR_INTERNAL, "Manifest index not populated by "
            "workspace_build_manifest_from_state() - programming error"
        );
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
 * Extract orphaned files and directories from workspace
 *
 * Two-pass extraction: count by kind, then populate both arrays.
 * Caller owns returned arrays; items are borrowed from workspace.
 *
 * Profile filtering: When profile_filter is non-NULL, only orphans from
 * matching profiles are extracted (Coherent Scope principle).
 */
error_t *workspace_extract_orphans(
    const workspace_t *ws,
    const string_array_t *filter,
    const workspace_item_t ***out_file_orphans,
    size_t *out_file_count,
    const workspace_item_t ***out_dir_orphans,
    size_t *out_dir_count
) {
    CHECK_NULL(ws);

    /* Initialize all outputs to safe defaults */
    if (out_file_orphans) *out_file_orphans = NULL;
    if (out_file_count) *out_file_count = 0;
    if (out_dir_orphans) *out_dir_orphans = NULL;
    if (out_dir_count) *out_dir_count = 0;

    /* Early exit if nothing requested */
    bool want_files = (out_file_orphans != NULL);
    bool want_dirs = (out_dir_orphans != NULL);
    if (!want_files && !want_dirs) {
        return NULL;
    }

    /* Pass 1: Count orphans by kind (with optional profile filter)
     *
     * When profile_filter is set, only count orphans from matching profiles.
     * This enables coherent scope for profile-filtered operations.
     */
    size_t file_count = 0, dir_count = 0;
    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (ws->diverged[i].state == WORKSPACE_STATE_ORPHANED ||
            ws->diverged[i].state == WORKSPACE_STATE_RELEASED) {
            /* Apply profile filter if specified */
            if (filter &&
                !profile_filter_matches(ws->diverged[i].profile, filter)) {
                continue;  /* Skip orphans from other profiles */
            }

            if (ws->diverged[i].item_kind == WORKSPACE_ITEM_FILE) {
                file_count++;
            } else {
                dir_count++;
            }
        }
    }

    /* Early exit if no orphans found */
    if (file_count == 0 && dir_count == 0) {
        return NULL;
    }

    /* Allocate arrays for requested kinds */
    const workspace_item_t **file_arr = NULL;
    const workspace_item_t **dir_arr = NULL;

    if (want_files && file_count > 0) {
        file_arr = malloc(file_count * sizeof(workspace_item_t *));
        if (!file_arr) {
            return ERROR(ERR_MEMORY, "Failed to allocate file orphan array");
        }
    }

    if (want_dirs && dir_count > 0) {
        dir_arr = malloc(dir_count * sizeof(workspace_item_t *));
        if (!dir_arr) {
            free(file_arr);
            return ERROR(ERR_MEMORY, "Failed to allocate directory orphan array");
        }
    }

    /* Pass 2: Populate both arrays in single iteration (with same filter) */
    size_t f_idx = 0, d_idx = 0;
    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (ws->diverged[i].state == WORKSPACE_STATE_ORPHANED ||
            ws->diverged[i].state == WORKSPACE_STATE_RELEASED) {
            /* Apply same profile filter as Pass 1 */
            if (filter &&
                !profile_filter_matches(ws->diverged[i].profile, filter)) {
                continue;
            }

            if (ws->diverged[i].item_kind == WORKSPACE_ITEM_FILE) {
                if (file_arr) {
                    file_arr[f_idx++] = &ws->diverged[i];
                }
            } else {
                if (dir_arr) {
                    dir_arr[d_idx++] = &ws->diverged[i];
                }
            }
        }
    }

    /* Set outputs (use actual pass-2 indices, not pass-1 counts, to stay
     * correct even if the two passes ever diverge due to future changes) */
    if (out_file_orphans) *out_file_orphans = file_arr;
    if (out_file_count) *out_file_count = f_idx;
    if (out_dir_orphans) *out_dir_orphans = dir_arr;
    if (out_dir_count) *out_dir_count = d_idx;

    return NULL;
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

    /* O(1) lookup via index - returns NULL if not found or CLEAN */
    void *idx_ptr = hashmap_get(ws->diverged_index, filesystem_path);
    if (!idx_ptr) {
        return NULL;
    }

    /* Convert stored index+1 back to actual array index */
    size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
    return &ws->diverged[idx];
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
 * Extract display tags and metadata from workspace item
 */
bool workspace_item_extract_display_info(
    const workspace_item_t *item,
    const char **tags_out,
    size_t *tag_count_out,
    output_color_t *color_out,
    char *metadata_buf,
    size_t metadata_size
) {
    /* Initialize all outputs defensively before validation */
    if (tag_count_out) {
        *tag_count_out = 0;
    }
    if (color_out) {
        *color_out = OUTPUT_COLOR_RESET;
    }
    if (metadata_buf && metadata_size > 0) {
        metadata_buf[0] = '\0';
    }

    /* Validate required parameters */
    if (!item || !tags_out || !tag_count_out || !color_out ||
        !metadata_buf || metadata_size < 32) {
        return false;
    }

    /* Validate item has a profile name (critical for metadata formatting) */
    if (!item->profile || item->profile[0] == '\0') {
        return false;
    }

    size_t tag_count = 0;
    *color_out = OUTPUT_COLOR_YELLOW;  /* Default color for most states */

    switch (item->state) {
        case WORKSPACE_STATE_UNDEPLOYED:
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "undeployed";
            }
            *color_out = OUTPUT_COLOR_CYAN;
            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;

        case WORKSPACE_STATE_DELETED:
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "deleted";
            }
            *color_out = OUTPUT_COLOR_RED;
            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;

        case WORKSPACE_STATE_DEPLOYED: {
            /* Primary tag based on most severe divergence
             *
             * Priority order (by severity):
             *   TYPE > CONTENT > MODE/OWNERSHIP/ENCRYPTION
             */
            if (item->divergence & DIVERGENCE_TYPE) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "type";
                }
                *color_out = OUTPUT_COLOR_RED;
            } else if (item->divergence & DIVERGENCE_CONTENT) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "modified";
                }
                /* Keep default YELLOW color */
            }

            /* Secondary tags for other divergence
             *
             * MODE: Skip if TYPE divergence present (type change makes mode irrelevant)
             *       The condition !((item->divergence & DIVERGENCE_TYPE) && tag_count > 0)
             *       prevents MODE from showing when TYPE is the primary tag
             * OWNERSHIP: Always show if present
             * ENCRYPTION: Always show if present
             * UNVERIFIED: Always show if present (file too large to verify)
             */
            if ((item->divergence & DIVERGENCE_MODE) &&
                !((item->divergence & DIVERGENCE_TYPE) && tag_count > 0)) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "mode";
                }
            }

            if (item->divergence & DIVERGENCE_OWNERSHIP) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "ownership";
                }
            }

            if (item->divergence & DIVERGENCE_ENCRYPTION) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "unencrypted";
                }
                /* Upgrade color to MAGENTA if still default (not TYPE divergence)
                 * This gives encryption issues special visual treatment */
                if (*color_out == OUTPUT_COLOR_YELLOW) {
                    *color_out = OUTPUT_COLOR_MAGENTA;
                }
            }

            if (item->divergence & DIVERGENCE_UNVERIFIED) {
                /* Verification could not be completed (rare edge case).
                 *
                 * Cannot verify content match, so marked for conservative handling
                 * (redeployment on apply, skipped removal for orphans).
                 */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "unverified";
                }
                /* Upgrade color to MAGENTA (special visual treatment for unverifiable state) */
                if (*color_out == OUTPUT_COLOR_YELLOW) {
                    *color_out = OUTPUT_COLOR_MAGENTA;
                }
            }

            if (item->divergence & DIVERGENCE_STALE) {
                /* VWD cache was stale due to external Git changes.
                 * Entry has been patched in-memory with current Git state.
                 * This is informational — the patched values are authoritative. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "stale";
                }
                /* Upgrade color to MAGENTA to highlight external changes */
                if (*color_out == OUTPUT_COLOR_YELLOW) {
                    *color_out = OUTPUT_COLOR_MAGENTA;
                }
            }

            /* Profile reassignment tag (can coexist with divergence tags)
             *
             * Added after divergence tags as secondary information.
             * Color only set for pure reassignment (sole tag) to avoid
             * overriding severity-based colors from divergence. */
            if (item->profile_changed) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "reassigned";
                }
                if (tag_count == 1) {
                    *color_out = OUTPUT_COLOR_CYAN;
                }
            }

            /* Format metadata string */
            if (item->profile_changed && item->old_profile) {
                snprintf(
                    metadata_buf, metadata_size, "%s → %s",
                    item->old_profile, item->profile
                );
            } else {
                snprintf(
                    metadata_buf, metadata_size, "from %s",
                    item->profile
                );
            }
            break;
        }

        case WORKSPACE_STATE_ORPHANED: {
            /* Primary tag (always shown) */
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "orphaned";
            }

            /* Determine color and secondary tags based on divergence */
            if (item->divergence & DIVERGENCE_UNVERIFIED) {
                /* Cannot verify state - could be large file, missing key, I/O error, etc.
                 * Conservative: Treat as modified (apply will skip). */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "unverified";
                }
                *color_out = OUTPUT_COLOR_MAGENTA;

            } else if (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE)) {
                /* Content or type divergence - blocking issue
                 * Apply will detect this via safety check and skip removal. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "modified";
                }
                *color_out = OUTPUT_COLOR_RED;

            } else if (item->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
                /* Metadata divergence only - warning level
                 * File content matches but permissions/ownership changed.
                 * Apply will skip (safety check considers this a modification). */
                if (item->divergence & DIVERGENCE_MODE) {
                    if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                        tags_out[tag_count++] = "mode";
                    }
                }
                if (item->divergence & DIVERGENCE_OWNERSHIP) {
                    if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                        tags_out[tag_count++] = "ownership";
                    }
                }
                *color_out = OUTPUT_COLOR_YELLOW;

            } else {
                /* No divergence - clean orphan
                 * File exactly matches last known state. Apply will remove it.
                 * Use RED to indicate action will be taken (file deletion). */
                *color_out = OUTPUT_COLOR_RED;
            }

            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;
        }

        case WORKSPACE_STATE_UNTRACKED:
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "new";
            }
            *color_out = OUTPUT_COLOR_CYAN;
            snprintf(metadata_buf, metadata_size, "in %s", item->profile);
            break;

        case WORKSPACE_STATE_RELEASED:
            /* File removed from Git externally — released from management.
             * File left on filesystem, state entry will be cleaned up. */
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "released";
            }
            *color_out = OUTPUT_COLOR_MAGENTA;
            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;

        default:
            /* Unknown state - defensive fallback
             * Should never happen in normal operation, but handle gracefully */
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "unknown";
            }
            *color_out = OUTPUT_COLOR_DIM;
            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;
    }

    *tag_count_out = tag_count;
    return true;
}

/**
 * Check if workspace detected stale manifest entries
 */
bool workspace_is_stale(const workspace_t *ws) {
    return ws ? ws->manifest_stale : false;
}

/**
 * Flush accumulated stat cache updates to the state database
 *
 * When the workspace owns its state (read-only mode, e.g. status/diff),
 * no transaction is active — wraps the batch in BEGIN/COMMIT to avoid
 * N individual autocommits (each triggering a WAL write + fsync).
 *
 * When state is borrowed (e.g. apply), the caller's transaction is already
 * active — flushes directly into it.
 */
error_t *workspace_flush_stat_caches(workspace_t *ws) {
    CHECK_NULL(ws);

    if (ws->stat_update_count == 0) {
        return NULL;
    }

    /* state may be NULL for empty databases (no manifest, no files).
     * stat_update_count should be 0 in this case, but guard defensively. */
    if (!ws->state) {
        return NULL;
    }

    /* Begin our own transaction only when no external transaction is active.
     * This handles all cases:
     *   - apply: borrowed state_load_for_update -> transaction active -> skip
     *   - status/diff/sync: borrowed state_load -> no transaction -> begin/commit
     *   - legacy workspace-owned: state_load -> no transaction -> begin/commit */
    bool needs_transaction = !state_in_transaction(ws->state);

    if (needs_transaction) {
        error_t *err = state_begin_transaction(ws->state);
        if (err) {
            return error_wrap(
                err, "Failed to begin stat cache transaction"
            );
        }
    }

    for (size_t i = 0; i < ws->stat_update_count; i++) {
        error_t *err = state_update_stat_cache(
            ws->state,
            ws->stat_updates[i].filesystem_path,
            &ws->stat_updates[i].stat
        );
        if (err) {
            if (needs_transaction) {
                state_rollback_transaction(ws->state);
            }
            return error_wrap(
                err, "Failed to flush stat cache for '%s'",
                ws->stat_updates[i].filesystem_path
            );
        }
    }

    if (needs_transaction) {
        error_t *err = state_commit_transaction(ws->state);
        if (err) {
            return error_wrap(
                err, "Failed to commit stat cache transaction"
            );
        }
    }

    ws->stat_update_count = 0;

    return NULL;
}

/**
 * Free workspace
 */
void workspace_free(workspace_t *ws) {
    if (!ws) {
        return;
    }

    /* Free diverged array (string fields are arena-backed, not freed individually) */
    free(ws->diverged);

    /* Free stat cache updates (paths are borrowed, stat is plain data) */
    free(ws->stat_updates);

    /* Free indices (values are borrowed, so pass NULL for value free function) */
    hashmap_free(ws->profile_index, NULL);
    hashmap_free(ws->diverged_index, NULL);

    /* Free encryption infrastructure */
    if (ws->metadata_cache) {
        hashmap_free(ws->metadata_cache, metadata_free);
    }
    content_cache_free(ws->content_cache);
    /* Don't free keymanager - it's global */

    /* Free staleness tracking (NULL-safe) */
    hashmap_free(ws->stale_paths, NULL);
    hashmap_free(ws->released_paths, NULL);
    hashmap_free(ws->stale_profiles, NULL);

    /* Free manifest (arena_backed mode: frees git_tree_entry objects,
     * entries array, hashmap, and struct — all heap-allocated) */
    manifest_free(ws->manifest);

    /* Free arena AFTER manifest_free — arena owns all string fields
     * in manifest entries, state entries, and diverged items.
     * Also frees cached_state_files array (arena_calloc'd). */
    arena_destroy(ws->arena);

    /* Only free state if we own it (allocated via state_load).
     * If borrowed from caller (state_load_for_update), caller is responsible. */
    if (ws->owns_state) {
        state_free(ws->state);
    }

    free(ws);
}
