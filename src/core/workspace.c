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
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/scope.h"
#include "crypto/encryption.h"
#include "crypto/keymgr.h"
#include "crypto/policy.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/source.h"
#include "utils/privilege.h"

/**
 * Pending anchor update (internal type)
 *
 * Accumulated during analyze_file_divergence() when the slow path confirms
 * CMP_EQUAL. The verified (blob_oid, stat) pair should be persisted so the
 * next run can both short-circuit via the fast-path stat witness and, if
 * Git advances blob_oid in the meantime, classify the file as stale from
 * the fast path instead of re-hashing.
 *
 * blob_oid is carried alongside stat because the anchor ties its witness to
 * a specific blob — a stat triple without a blob pointer is meaningless.
 *
 * Path is borrowed from the manifest entry (valid for workspace lifetime).
 */
typedef struct {
    const char *filesystem_path;     /* Target path (borrowed from manifest entry) */
    git_oid blob_oid;                /* Blob dotta just verified disk matches */
    stat_cache_t stat;               /* Captured stat triple (fast-path witness) */
} anchor_update_t;

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
    state_t *state;                  /* Deployment state (borrowed from caller) */
    const string_array_t *profiles;  /* Borrowed from caller — valid for workspace lifetime */
    hashmap_t *profile_index;        /* Maps profile -> NULL (membership set, O(1) lookup) */

    /* Cached state query (shared between workspace_build_manifest_from_state
     * and analyze_orphaned_files to avoid redundant full-table scan) */
    state_file_entry_t *cached_state_files;  /* Owned, freed in workspace_free (NULL if empty) */
    size_t cached_state_count;               /* Number of entries in cached_state_files */

    /* Encryption and caching infrastructure */
    keymgr *keymgr;                  /* Borrowed from global */
    content_cache_t *content_cache;  /* Owned - caches decrypted content */

    /* Cached directory state (shared between analyze_orphaned_directories
     * and analyze_directory_metadata_divergence to avoid redundant table scans) */
    state_directory_entry_t *cached_state_dirs;  /* Arena-allocated (NULL until first load) */
    size_t cached_state_dir_count;               /* Number of cached directory entries */

    /* Divergence tracking */
    workspace_item_t *diverged;      /* Array of diverged items (files and directories) */
    size_t diverged_count;           /* Number of diverged items */
    size_t diverged_capacity;        /* Allocated capacity of diverged array */
    hashmap_t *diverged_index;       /* Maps filesystem_path -> array index+1 (as void*) */

    /* Anchor updates (accumulated during divergence analysis) */
    anchor_update_t *anchor_updates;   /* Pending slow-path updates (owned) */
    size_t anchor_update_count;        /* Number of pending updates */
    size_t anchor_update_capacity;     /* Allocated capacity of updates array */

    /* Status cache */
    workspace_status_t status;         /* Cached cleanliness assessment */
};

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
        ws->diverged_index,
        entry->filesystem_path,
        (void *) (uintptr_t) (ws->diverged_count + 1)
    );
    if (err) {
        return error_wrap(err, "Failed to index diverged entry");
    }

    ws->diverged_count++;

    return NULL;
}

/**
 * Record an anchor advance for later flushing
 *
 * Called from analyze_file_divergence() when the slow path confirms CMP_EQUAL.
 * Accumulates the (blob_oid, stat) pair so workspace_flush_anchor_updates() can
 * persist it via state_update_anchor(). The blob_oid is required because the
 * anchor binds its fast-path witness to a specific blob.
 *
 * OOM asymmetry — returns void on realloc failure. Every other path in
 * workspace analysis propagates ERR_MEMORY; this one deliberately does not.
 * The anchor advance is a pure performance optimization — it converts the
 * NEXT slow-path CMP_EQUAL into a fast-path short-circuit — not a correctness
 * invariant of the current analysis (which is already complete by the time
 * this is called). Dropping the record on realloc failure:
 *   - Preserves the caller's already-correct divergence result.
 *   - Self-heals on the next status: the slow-path CMP_EQUAL re-confirms
 *     and re-records the anchor (assuming memory pressure has cleared).
 *   - Never produces an incorrect classification — worst case is one extra
 *     slow-path verification per dropped record.
 * Failing here to surface OOM would abort a workspace load that had already
 * succeeded in every respect that affects user-visible output — strictly
 * worse UX for zero correctness gain.
 *
 * @param ws Workspace (must not be NULL)
 * @param filesystem_path Path (borrowed from manifest, valid for workspace lifetime)
 * @param blob_oid Blob dotta just confirmed disk matches (must not be NULL)
 * @param st Verified filesystem stat
 */
static void workspace_record_anchor_update(
    workspace_t *ws,
    const char *filesystem_path,
    const git_oid *blob_oid,
    const struct stat *st
) {
    if (ws->anchor_update_count >= ws->anchor_update_capacity) {
        size_t new_cap = ws->anchor_update_capacity
                       ? ws->anchor_update_capacity * 2 : 16;

        anchor_update_t *new_arr = realloc(
            ws->anchor_updates,
            new_cap * sizeof(anchor_update_t)
        );
        if (!new_arr) return;

        ws->anchor_updates = new_arr;
        ws->anchor_update_capacity = new_cap;
    }

    ws->anchor_updates[ws->anchor_update_count++] = (anchor_update_t){
        .filesystem_path = filesystem_path,
        .blob_oid = *blob_oid,
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
    const char *profile = manifest_entry->profile;

    /* Determine if entry came from state database using VWD cache
     *
     * Workspace manifests are always built from state (via
     * workspace_build_manifest_from_state), so blob_oid is always a real OID
     * here. The zero-check is a defensive guard — not a type discriminant.
     *
     * Note: Git-built manifests (from manifest_build) now also carry
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
                ERR_FS, "Failed to stat '%s': %s", fs_path,
                strerror(errno)
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

        /* ANCHOR FAST PATH (safety-grade)
         *
         * The deployment anchor binds three pieces of information: the blob
         * dotta last confirmed on disk (anchor.blob_oid), the stat triple
         * captured at that confirmation (anchor.stat), and the time of
         * confirmation (anchor.deployed_at). If the live stat matches
         * anchor.stat, the following invariant holds by construction:
         *
         *     stat_match  ⟹  disk == anchor.blob_oid
         *
         * The anchor is advanced only by state_update_anchor() after dotta
         * has verified disk content. The UPSERT never clobbers it. So a
         * stat match is a cryptographically-grade witness that disk still
         * equals anchor.blob_oid — no re-hash needed.
         *
         * Cross-check anchor.blob_oid against the Git-expected blob_oid
         * (manifest_entry->blob_oid) to classify:
         *   - equal   → CMP_EQUAL.  disk == anchor == expected (clean).
         *   - differ  → CMP_DIFFERENT + DIVERGENCE_STALE.
         *                disk == anchor ≠ expected (external Git drift;
         *                file is still at the last-deployed blob).
         *
         * This is the key Stage-A win: STALE is tagged directly from the
         * fast path, without loading blobs or hashing. The slow-path
         * straggler case (touch(1) / editor rename-write invalidated the
         * stat witness) is still handled by Phase 3. */
        const deployment_anchor_t *anchor = &manifest_entry->anchor;
        if (anchor->stat.mtime != 0
            && anchor->stat.mtime == (int64_t) initial_stat.st_mtime
            && anchor->stat.size == (int64_t) initial_stat.st_size
            && anchor->stat.ino == (uint64_t) initial_stat.st_ino) {
            /* stat match ⟹ disk == anchor.blob_oid */
            file_stat = initial_stat;
            if (git_oid_equal(&anchor->blob_oid, blob_oid_ptr)) {
                cmp_result = CMP_EQUAL;
            } else {
                /* disk == anchor ≠ expected — file is still at the blob
                 * dotta last deployed; Git has since advanced expected.
                 * Tag STALE here; Phase 3 is a no-op for this file. */
                cmp_result = CMP_DIFFERENT;
                divergence |= DIVERGENCE_STALE;
            }
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

            /* Slow path confirmed disk == expected blob — seed the anchor
             * with the current (blob_oid, stat) pair so the next run can
             * short-circuit via the fast path above. */
            if (cmp_result == CMP_EQUAL) {
                workspace_record_anchor_update(ws, fs_path, blob_oid_ptr, &file_stat);
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
     * Use anchor.observed_at to distinguish lifecycle states for missing
     * files. observed_at is stamped the first time dotta lstat-confirms
     * the path on disk in scope. Writers:
     *   - sync_entry_to_state INSERT path (scope-entry observation).
     *   - state_update_anchor (every witness/ownership advance — apply
     *     deploy, adoption, add, update, CMP_EQUAL flush).
     * All writes go through the SQL CASE that preserves the first
     * non-zero value, so observed_at is monotonic once set.
     *
     * anchor.observed_at semantics:
     * - 0  -> dotta has never lstat-confirmed this path on disk in scope
     *         (ghost file: profile enabled but the file was never there).
     * - >0 -> dotta has seen this file on disk in scope at least once
     *         (was present at enable, during any status, or after a
     *         content-verification event).
     *
     * Classification:
     * 1. File missing + anchor.observed_at = 0 -> UNDEPLOYED (ghost, no-op)
     * 2. File missing + anchor.observed_at > 0 -> DELETED (user removed it)
     * 3. File present                          -> DEPLOYED (may diverge)
     *
     * The ownership signal (anchor.deployed_at) is still the authority for
     * "(deployed X ago)" display and the adoption-loop gate; it just no
     * longer controls classification.
     */
    if (!on_filesystem) {
        /* File in manifest but missing from filesystem */

        /* Use anchor.observed_at to distinguish ghost files from deletions
         * (see classification table above for the full decision matrix). */
        if (in_state && manifest_entry->anchor.observed_at > 0) {
            /* Path has been lstat-observed on disk in scope; current
             * absence means the user deleted a previously-seen file. */
            state = WORKSPACE_STATE_DELETED;
        } else {
            /* Path has never been observed (ghost file) or the manifest
             * was built directly from Git with no state row (in_state = false). */
            state = WORKSPACE_STATE_UNDEPLOYED;
        }

        /* Clear divergence flags - can't detect divergence on missing files */
        divergence = DIVERGENCE_NONE;
    } else {
        /* File in manifest and on filesystem */
        state = WORKSPACE_STATE_DEPLOYED;
        /* Keep accumulated divergence flags from Phase 1 */
    }

    /* PHASE 3: Staleness flag (slow-path straggler)
     *
     * The fast path in Phase 1 already tagged DIVERGENCE_STALE for the common
     * case where the anchor's stat witness is still valid (disk untouched since
     * dotta last confirmed it). This phase handles the slow-path straggler:
     * the stat witness was invalidated (touch(1), editor rename-write, fresh
     * checkout) but disk content may still match the blob dotta last deployed.
     *
     * Source of truth: the persistent deployment anchor (manifest_entry->anchor),
     * populated from the virtual_manifest.deployed_blob_oid column. Cross-process
     * correct by construction — every invocation sees the same answer.
     *
     * Activation conditions (all must hold):
     *   1. File exists on disk.
     *   2. Content diverges from the current expected blob (else no staleness question).
     *   3. STALE not already tagged by the fast path.
     *   4. Anchor blob is set (dotta has a deployed reference to compare against).
     *   5. Anchor blob ≠ current expected blob (Git has advanced past the anchor).
     *
     * When all conditions hold, hash-compare disk against anchor.blob_oid to
     * confirm "disk is still at the last-deployed blob." On match, tag STALE
     * so the preflight gate allows overwrite. On mismatch, leave flags
     * unchanged — the existing DIVERGENCE_CONTENT causes preflight to block.
     *
     * DIVERGENCE_STALE can combine with other flags:
     *   [stale]              — expected state changed, content matches new state
     *   [stale, modified]    — expected state changed, file has old deployed content
     */
    if (on_filesystem && (divergence & DIVERGENCE_CONTENT) && !(divergence & DIVERGENCE_STALE)
        && !git_oid_is_zero(&manifest_entry->anchor.blob_oid)
        && !git_oid_equal(&manifest_entry->anchor.blob_oid, &manifest_entry->blob_oid)) {

        git_filemode_t expected_mode = state_type_to_git_filemode(manifest_entry->type);
        compare_result_t verify_result = CMP_UNVERIFIED;

        struct stat verify_stat;
        error_t *verify_err = NULL;

        /* Unified verification: load the anchor blob through the same path
         * for both encrypted and non-encrypted files (content_cache handles
         * decryption transparently), then byte-compare against disk.
         * compare_oid_to_disk is the shorter route for non-encrypted blobs
         * (avoids the content_cache buffer allocation) - fast branch. */
        if (!manifest_entry->encrypted) {
            verify_err = compare_oid_to_disk(
                &manifest_entry->anchor.blob_oid,
                fs_path,
                expected_mode,
                &initial_stat,
                &verify_result,
                &verify_stat
            );
        } else {
            const buffer_t *anchor_content = NULL;
            verify_err = content_cache_get_from_blob_oid(
                ws->content_cache,
                &manifest_entry->anchor.blob_oid,
                storage_path,
                profile,
                manifest_entry->encrypted,
                &anchor_content
            );
            if (!verify_err && anchor_content) {
                verify_err = compare_buffer_to_disk(
                    anchor_content,
                    fs_path,
                    expected_mode,
                    &initial_stat,
                    &verify_result,
                    &verify_stat
                );
            }
        }

        if (!verify_err && verify_result == CMP_EQUAL) {
            /* File matches old deployed content — stale repair is safe */
            divergence |= DIVERGENCE_STALE;
        }
        if (verify_err) error_free(verify_err);
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
            /* In state but not in manifest — either released or orphaned.
             *
             * Released: File removed from Git externally (loss of authority).
             * manifest_reconcile (run from workspace_load's prelude) marked
             * the row STATE_RELEASED before we got here; state_entry's
             * lifecycle column is the single source of truth.
             *
             * Orphaned: File out of scope for other reasons (profile
             * disabled, branch deleted, etc.). Standard orphan handling
             * applies. */
            bool is_released = state_entry->state &&
                strcmp(state_entry->state, STATE_RELEASED) == 0;

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
 *   - Otherwise -> trust the state column (ACTIVE = valid)
 *
 * manifest_reconcile (run upstream from workspace_load) has already synced
 * tracked directories against current Git, so the state column is
 * authoritative here.
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

        /* Determine orphan status from the state column — manifest_reconcile
         * (from workspace_load's prelude) already ran manifest_sync_directories
         * for any drift, so the lifecycle column reflects current Git truth. */
        bool is_orphaned = false;

        if (!profile_in_scope) {
            /* Profile disabled or deleted — directory is orphaned */
            is_orphaned = true;
        } else if (dir->state && (strcmp(dir->state, STATE_INACTIVE) == 0 ||
            strcmp(dir->state, STATE_DELETED) == 0)) {
            /* manifest_sync_directories() marked it non-active */
            is_orphaned = true;
        }
        /* else: profile in scope, state ACTIVE -> trust state column */

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
    const gitignore_ruleset_t *rules,
    source_filter_t *source_filter,
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
        bool ignored = rules && gitignore_is_ignored(rules, full_path, is_dir);
        if (!ignored && source_filter) {
            error_t *err = source_filter_is_excluded(
                source_filter, full_path, is_dir, &ignored
            );
            error_free(err);  /* Non-fatal: layer-5 errors fall through */
        }
        if (ignored) {
            free(full_path);
            errno = 0;
            continue;
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
                rules,
                source_filter,
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

    /* Source-tree .gitignore filter — built once for the whole scan so
     * the discovered source-repo handle is reused across every profile
     * and directory. Driven by config; policy decision lives here, not
     * in the ignore module. Non-fatal on build failure: we continue
     * without layer-5 filtering rather than blocking status. */
    source_filter_t *source_filter = NULL;
    if (config && config->respect_gitignore) {
        error_t *sf_err = source_filter_create(&source_filter);
        if (sf_err) {
            fprintf(
                stderr,
                "warning: failed to build source .gitignore filter: %s\n",
                sf_err->message
            );
            error_free(sf_err);
        }
    }

    /* Layered-rules builder — one per scan. Baseline and config are
     * loaded here; each profile's `.dottaignore` is parsed once on
     * first use and cached, so the profile loop below amortises the
     * cost across the whole status (the previous shape rebuilt an
     * entire context per profile, re-loading the baseline each time). */
    ignore_rules_t *ignore_rules = NULL;
    {
        error_t *init_err = ignore_rules_create(
            ws->repo, config, NULL, 0, &ignore_rules
        );
        if (init_err) {
            source_filter_free(source_filter);
            return error_wrap(init_err, "Failed to build ignore rules");
        }
    }

    /* Scan tracked directories from each enabled profile's state database */
    for (size_t p = 0; p < ws->profiles->count; p++) {
        const char *profile = ws->profiles->items[p];

        /* Get tracked directories from state database for this profile */
        state_directory_entry_t *directories = NULL;
        size_t dir_count = 0;
        err = state_get_directories_by_profile(
            ws->state, profile, ws->arena, &directories, &dir_count
        );
        if (err) {
            fprintf(
                stderr, "warning: failed to load directories for profile '%s': %s\n",
                profile, err->message
            );
            error_free(err);
            err = NULL;
            continue;
        }

        if (dir_count == 0) {
            /* Profile has no tracked directories - skip */
            continue;
        }

        /* Resolve the profile-specific ruleset (memoised in the builder).
         *
         * Fatal on failure: scanning a profile without its ignore rules
         * risks reporting genuinely ignored files as untracked, which
         * the user could then `dotta add` by accident. A corrupt
         * .dottaignore must surface so the user can fix it. */
        const gitignore_ruleset_t *profile_rules = NULL;
        err = ignore_rules_for_profile(ignore_rules, profile, &profile_rules);
        if (err) {
            ignore_rules_free(ignore_rules);
            source_filter_free(source_filter);
            return error_wrap(
                err, "Failed to load ignore patterns for profile '%s'", profile
            );
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
                profile,
                profile_rules,
                source_filter,
                ws,
                0                          /* Initial depth */
            );

            if (err) {
                /* Non-fatal: continue with other directories */
                fprintf(
                    stderr, "warning: failed to scan directory '%s' in profile '%s': %s\n",
                    filesystem_path, profile, err->message
                );
                error_free(err);
                err = NULL;
            }
        }
    }

    ignore_rules_free(ignore_rules);
    source_filter_free(source_filter);
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
        const char *profile = dir_entry->profile;

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
                    profile,
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
                profile,
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
                profile,
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
 * Only fires when encryption is active — i.e. the config has a compiled
 * auto-encrypt ruleset (see encryption_policy_is_active). Nothing to
 * check without one.
 *
 * Error handling:
 * - Git read errors: Non-fatal, warns and skips file
 * - Metadata corruption: Non-fatal, warns and uses magic header
 *
 * This is a security-focused check: files matching sensitive patterns
 * (e.g., "*.key", ".ssh/id_*") should be encrypted.
 *
 * The compiled auto-encrypt ruleset lives on the config handle; matching
 * is pure computation and cannot fail.
 */
static error_t *analyze_encryption_policy_mismatch(
    workspace_t *ws,
    const config_t *config
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->manifest);

    /* Fast-path: no auto-encrypt ruleset means nothing to validate. */
    if (!encryption_policy_is_active(config)) {
        return NULL;
    }

    error_t *err = NULL;

    /* Check each file in manifest */
    for (size_t i = 0; i < ws->manifest->count; i++) {
        const file_entry_t *manifest_entry = &ws->manifest->entries[i];
        const char *storage_path = manifest_entry->storage_path;
        const char *profile = manifest_entry->profile;

        /* Check if file should be auto-encrypted (pure computation) */
        if (!encryption_policy_matches_auto_patterns(config, storage_path)) {
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
            ws->repo,
            &manifest_entry->blob_oid,
            &blob_view
        );
        if (view_err) {
            /* Non-fatal: can't read blob - skip this file */
            fprintf(
                stderr, "warning: failed to read blob for '%s' in profile '%s': %s\n",
                storage_path, profile,
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
         * (run via manifest_reconcile when profile HEAD drifts). It always
         * equals what metadata says — zero Git reads needed. */
        if (is_encrypted != manifest_entry->encrypted) {
            fprintf(
                stderr,
                "warning: encryption mismatch for '%s' in profile '%s'\n"
                "  Blob content says: %s\n"
                "  VWD expected state says: %s\n"
                "  Using actual state from blob content. To fix, run:\n"
                "    dotta update -p %s '%s'\n",
                storage_path, profile,
                is_encrypted ? "encrypted" : "plaintext",
                is_encrypted ? "plaintext" : "encrypted",
                profile, storage_path
            );
        }

        /* Policy mismatch: should be encrypted but isn't.
         * At this point we know the pattern matched (continue above would
         * have skipped otherwise), so the original `should_auto_encrypt &&`
         * guard collapses to the plaintext check. */
        if (!is_encrypted) {
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
                 * Classify lifecycle state from presence + observation anchor,
                 * mirroring analyze_file_divergence Phase 2. on_filesystem is
                 * checked first: a file on disk is DEPLOYED regardless of
                 * whether dotta has stamped observation yet. A missing file
                 * is DELETED if ever observed (observed_at > 0), else
                 * UNDEPLOYED (ghost file that was never on disk in scope). */
                struct stat enc_stat;
                bool on_filesystem = (lstat(manifest_entry->filesystem_path, &enc_stat) == 0);

                workspace_state_t item_state;
                if (on_filesystem) {
                    item_state = WORKSPACE_STATE_DEPLOYED;
                } else if (manifest_entry->anchor.observed_at > 0) {
                    item_state = WORKSPACE_STATE_DELETED;
                } else {
                    item_state = WORKSPACE_STATE_UNDEPLOYED;
                }

                err = workspace_add_diverged(
                    ws,
                    manifest_entry->filesystem_path,
                    storage_path,
                    profile,
                    NULL,
                    item_state,
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
 * Build in-memory manifest from state manifest table
 *
 * Reads manifest entries from state DB and constructs manifest_t structure.
 * Does NOT load git_tree_entry* pointers (set to NULL). Consumers use the
 * VWD-cached blob_oid for content access instead of tree entry loading.
 *
 * Drift repair is handled upstream by workspace_load's manifest_reconcile
 * call, so state entries read here are current with Git by construction.
 * This function just projects state rows into the in-memory manifest shape.
 *
 * Files from profiles not in the workspace scope are filtered out silently.
 * This can happen if a profile is disabled but manifest still has orphaned entries.
 *
 * Performance: O(M) where M = state entries.
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

    /* Allocate manifest structure */
    ws->manifest = calloc(1, sizeof(manifest_t));
    if (!ws->manifest) {
        return ERROR(ERR_MEMORY, "Failed to allocate manifest");
    }

    /* Allocate entries array (max size = state_count).
     *
     * calloc(0, X) is implementation-defined per C17 §7.22.3.2p2 — may
     * return NULL or a unique non-NULL pointer depending on the libc.
     * Skip the allocation entirely for empty state: a manifest_t with
     * entries=NULL, count=0 is a valid empty manifest, and manifest_free
     * already tolerates entries == NULL (free(NULL) is a no-op). */
    if (state_count > 0) {
        ws->manifest->entries = calloc(state_count, sizeof(file_entry_t));
        if (!ws->manifest->entries) {
            free(ws->manifest);
            ws->manifest = NULL;
            return ERROR(ERR_MEMORY, "Failed to allocate manifest entries");
        }
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

        /* Borrow profile from state entry (same arena lifetime as workspace) */
        entry->profile = state_entry->profile;

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

        /* Borrow VWD cache and anchor from arena-backed state entries.
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
        entry->anchor = state_entry->anchor;

        /* Track entry for cleanup — must precede any further fallible operations
         * so the centralized cleanup loop (j < manifest_idx) covers this entry. */
        manifest_idx++;

        /* Store index in hashmap (offset by 1 to distinguish from NULL).
         * manifest_idx already holds the 1-based value after the increment above.
         * The cast through uintptr_t is safe: indices are much smaller than
         * SIZE_MAX, and we never dereference these "pointers". */
        err = hashmap_set(path_map, entry->filesystem_path, (void *) (uintptr_t) manifest_idx);
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

    return NULL;

cleanup:
    /* Simplified error cleanup — arena handles all string fields.
     * Only free heap-allocated structures. */
    hashmap_free(path_map, NULL);
    free(ws->manifest->entries);
    free(ws->manifest);
    ws->manifest = NULL;

    return err;
}

/**
 * Load workspace from repository
 */
error_t *workspace_load(
    git_repository *repo,
    state_t *state,
    const scope_t *scope,
    const config_t *config,
    const workspace_load_t *options,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(scope);
    CHECK_NULL(options);
    CHECK_NULL(out);

    /* Workspace scope is the persistent VWD enabled set — never the CLI
     * filter. The scope accessor type-enforces this invariant (see
     * scope.h's "Vocabulary" section). The pointer is borrowed from scope,
     * which must outlive the returned workspace. */
    const string_array_t *profiles = scope_enabled(scope);

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

    /* Reconcile VWD with Git before loading.
     *
     * External Git operations (git commit, rebase, rm, etc.) between dotta
     * runs leave the manifest's commit_oid references behind the branch HEAD.
     * manifest_reconcile detects drift per profile and persists corrections
     * in state — advances blob_oid for entries whose content changed and
     * marks externally-removed entries STATE_RELEASED. The deployment anchor
     * is preserved by the UPSERT across this repair, so analyze_file_divergence
     * can classify staleness from the persistent (anchor, blob_oid) pair
     * regardless of whether reconcile actually ran on this invocation.
     *
     * Transaction scoping is internal to manifest_reconcile: uses the
     * caller's transaction when locked, opens a scoped BEGIN IMMEDIATE
     * otherwise. Common case (no drift) is O(P) and zero writes. */
    err = manifest_reconcile(repo, state, NULL);
    if (err) {
        return error_wrap(err, "Failed to reconcile manifest with Git");
    }

    err = workspace_create_empty(repo, profiles, &ws);
    if (err) {
        return err;
    }

    /* Initialize encryption infrastructure */
    /* Note: keymgr can be NULL if encryption is not configured - this is valid */
    ws->keymgr = keymgr_get_global(config);

    ws->content_cache = content_cache_create(ws->repo, ws->keymgr);
    if (!ws->content_cache) {
        workspace_free(ws);
        return ERROR(ERR_MEMORY, "Failed to create content cache");
    }

    /* Borrow caller's state. Caller retains ownership and must free it. */
    ws->state = state;

    /* Build manifest from state (Virtual Working Directory architecture)
     * This replaces the old manifest_build() which walked Git trees.
     * Now we read from the manifest table (expected state cache) for O(M) performance
     * where M = entries in manifest, not O(N) where N = all files in Git.
     *
     * Staleness was already repaired by manifest_reconcile above; this
     * function now reads current state directly. */
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
 * Single-pass extraction: gathers each requested kind into its own
 * borrowed-pointer array. Caller owns returned buffers; items are borrowed
 * from workspace.
 *
 * Scope filtering: When `scope` is non-NULL, orphans that fail the
 * profile or path dimensions are dropped silently; orphans that match
 * those two but are excluded (-e) are counted via `out_excluded_count`
 * and optionally collected into `out_excluded` for per-item reporting.
 */
error_t *workspace_extract_orphans(
    const workspace_t *ws,
    const scope_t *scope,
    const workspace_item_t ***out_file_orphans,
    size_t *out_file_count,
    const workspace_item_t ***out_dir_orphans,
    size_t *out_dir_count,
    const workspace_item_t ***out_excluded,
    size_t *out_excluded_count
) {
    CHECK_NULL(ws);

    /* Initialize all outputs to safe defaults */
    if (out_file_orphans) *out_file_orphans = NULL;
    if (out_file_count) *out_file_count = 0;
    if (out_dir_orphans) *out_dir_orphans = NULL;
    if (out_dir_count) *out_dir_count = 0;
    if (out_excluded) *out_excluded = NULL;
    if (out_excluded_count) *out_excluded_count = 0;

    /* Early exit if nothing requested */
    bool want_files = (out_file_orphans != NULL);
    bool want_dirs = (out_dir_orphans != NULL);
    bool want_excluded = (out_excluded != NULL);
    if (!want_files && !want_dirs && !want_excluded) return NULL;

    ptr_array_t files PTR_ARRAY_AUTO = { 0 };
    ptr_array_t dirs PTR_ARRAY_AUTO = { 0 };
    ptr_array_t excluded_items PTR_ARRAY_AUTO = { 0 };
    size_t excluded = 0;

    for (size_t i = 0; i < ws->diverged_count; i++) {
        const workspace_item_t *item = &ws->diverged[i];

        if (item->state != WORKSPACE_STATE_ORPHANED &&
            item->state != WORKSPACE_STATE_RELEASED) {
            continue;
        }

        if (scope) {
            /* Profile / path dimensions: silent rejection — the orphan
             * is outside the user's declared operation scope. */
            if (!scope_accepts_profile(scope, item->profile) ||
                !scope_accepts_path(scope, item->storage_path)) {
                continue;
            }
            /* Exclude dimension: count, and optionally collect for
             * per-item reporting by the caller. */
            if (scope_is_excluded(scope, item->storage_path)) {
                excluded++;
                if (want_excluded) {
                    RETURN_IF_ERROR(ptr_array_push(&excluded_items, item));
                }
                continue;
            }
        }

        if (item->item_kind == WORKSPACE_ITEM_FILE) {
            if (want_files) RETURN_IF_ERROR(ptr_array_push(&files, item));
        } else {
            if (want_dirs) RETURN_IF_ERROR(ptr_array_push(&dirs, item));
        }
    }

    if (out_file_orphans) {
        *out_file_orphans =
            (const workspace_item_t **) ptr_array_steal(&files, out_file_count);
    }
    if (out_dir_orphans) {
        *out_dir_orphans =
            (const workspace_item_t **) ptr_array_steal(&dirs, out_dir_count);
    }
    if (want_excluded) {
        /* ptr_array_steal requires a non-NULL count pointer; use a
         * local when the caller didn't request out_excluded_count. */
        size_t stolen = 0;
        *out_excluded =
            (const workspace_item_t **) ptr_array_steal(&excluded_items, &stolen);

        if (out_excluded_count) {
            *out_excluded_count = stolen;
        }
    } else if (out_excluded_count) {
        *out_excluded_count = excluded;
    }

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
 * Get the manifest of files managed by the workspace
 */
const manifest_t *workspace_get_manifest(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->manifest;
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
 * Advance the deployment anchor with in-memory consistency
 *
 * Single workspace-scope writer for anchor advances: persists via
 * state_update_anchor, then patches ws->manifest's entry so the two
 * views cannot drift. Mirrors state_update_anchor's preserve-on-zero
 * semantic on deployed_at (a zero timestamp preserves the in-memory
 * value) and the monotonic-once-set semantic on observed_at (the first
 * non-zero value wins).
 *
 * DB write runs first; on error we return without touching memory so a
 * failed write cannot leave the in-memory view ahead of reality.
 */
error_t *workspace_advance_anchor(
    workspace_t *ws,
    const char *filesystem_path,
    const deployment_anchor_t *anchor
) {
    CHECK_NULL(ws);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(anchor);

    error_t *err = state_update_anchor(ws->state, filesystem_path, anchor);
    if (err) {
        return err;
    }

    /* Patch the in-memory manifest entry to match what the DB now holds.
     * Not-found is tolerated: the DB write already no-op'd for rows
     * filtered by precedence / disabled profile, and the in-memory
     * manifest may likewise not carry the path. */
    if (!ws->manifest || !ws->manifest->index) {
        return NULL;
    }

    void *idx_ptr = hashmap_get(ws->manifest->index, filesystem_path);
    if (!idx_ptr) {
        return NULL;
    }

    size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
    deployment_anchor_t *in_mem = &ws->manifest->entries[idx].anchor;

    in_mem->blob_oid = anchor->blob_oid;
    in_mem->stat = anchor->stat;
    if (anchor->deployed_at != 0) {
        in_mem->deployed_at = anchor->deployed_at;
    }
    if (in_mem->observed_at == 0 && anchor->observed_at != 0) {
        in_mem->observed_at = anchor->observed_at;   /* monotonic once set */
    }

    return NULL;
}

/**
 * Flush accumulated anchor updates to the state database
 *
 * Advances the deployment anchor for entries that hit CMP_EQUAL on the
 * slow path during analyze_file_divergence. The anchor carries both the
 * fast-path stat witness and the blob_oid it witnesses — persisting them
 * lets the next run short-circuit (fast path) or tag STALE directly
 * (fast path with Git-advanced blob_oid).
 *
 * deployed_at is passed as 0 so state_update_anchor preserves the row's
 * existing timestamp — this flush confirms the anchor witness but does
 * not create a new deployment lifecycle event (apply owns that).
 *
 * Routed through workspace_advance_anchor so each persisted update also
 * patches ws->manifest's in-memory anchor; no staleness window opens
 * between DB and memory for downstream readers in the same run.
 *
 * Begins its own transaction only when state isn't already in one
 * (status/diff/sync). Apply always passes state already-in-transaction.
 */
error_t *workspace_flush_anchor_updates(workspace_t *ws) {
    CHECK_NULL(ws);

    if (ws->anchor_update_count == 0) {
        return NULL;
    }

    /* Begin our own transaction only when no external transaction is active:
     *   - apply: state_open -> already in transaction -> skip
     *   - status/diff/sync: state_load -> no transaction -> begin/commit */
    bool needs_transaction = !state_locked(ws->state);

    if (needs_transaction) {
        error_t *err = state_begin(ws->state);
        if (err) {
            return error_wrap(
                err, "Failed to begin anchor flush transaction"
            );
        }
    }

    time_t now = time(NULL);
    for (size_t i = 0; i < ws->anchor_update_count; i++) {
        const anchor_update_t *update = &ws->anchor_updates[i];
        deployment_anchor_t anchor = {
            .blob_oid    = update->blob_oid,
            .deployed_at = 0,      /* preserve — flush is a witness advance, not a deploy */
            .observed_at = now,    /* monotonic CASE in SQL preserves any prior observation stamp */
            .stat        = update->stat,
        };
        error_t *err = workspace_advance_anchor(
            ws, update->filesystem_path, &anchor
        );
        if (err) {
            if (needs_transaction) {
                state_rollback(ws->state);
            }
            return error_wrap(
                err, "Failed to flush anchor for '%s'",
                update->filesystem_path
            );
        }
    }

    if (needs_transaction) {
        error_t *err = state_commit(ws->state);
        if (err) {
            return error_wrap(
                err, "Failed to commit anchor flush transaction"
            );
        }
    }

    ws->anchor_update_count = 0;

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

    /* Free anchor updates (paths are borrowed, anchor is plain data) */
    free(ws->anchor_updates);

    /* Free indices (values are borrowed, so pass NULL for value free function) */
    hashmap_free(ws->profile_index, NULL);
    hashmap_free(ws->diverged_index, NULL);

    /* Free encryption infrastructure */
    content_cache_free(ws->content_cache);
    /* Don't free keymgr - it's global */

    /* Free manifest (arena_backed mode: frees git_tree_entry objects,
     * entries array, hashmap, and struct — all heap-allocated) */
    manifest_free(ws->manifest);

    /* Free arena AFTER manifest_free — arena owns all string fields
     * in manifest entries, state entries, and diverged items.
     * Also frees cached_state_files array (arena_calloc'd). */
    arena_destroy(ws->arena);

    free(ws);
}
