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
#include "core/policy.h"
#include "core/scope.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "sys/filesystem.h"
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
    arena_t *arena;                  /* Borrowed; backs every workspace-lifetime string */

    /* Active in-scope state slice
     *
     * Pointer array into the arena snapshot returned by state_get_all_files
     * at load time. Pointers are mutable to permit in-place anchor patches
     * via workspace_advance_anchor; external accessors cast to const.
     *
     * Stable storage — no realloc during workspace lifetime — so the
     * active_index can store row pointers directly (no idx+1 encoding).
     */
    state_file_entry_t **active;     /* Active rows (mutable; arena-allocated) */
    size_t active_count;             /* Number of active rows */
    hashmap_t *active_index;         /* fs_path → state_file_entry_t * (heap-allocated) */

    /* State data */
    state_t *state;                  /* Deployment state (borrowed from caller) */
    const string_array_t *profiles;  /* Borrowed from caller — valid for workspace lifetime */
    hashmap_t *profile_index;        /* Maps profile -> NULL (membership set, O(1) lookup) */

    /* Content cache for encrypted blob reads during divergence analysis */
    content_cache_t *content_cache;  /* Borrowed — NOT freed in workspace_free */

    /* Divergence tracking
     *
     * The diverged array grows via realloc as workspace_add_diverged appends
     * items during analysis, so pointers into it would dangle on growth.
     * diverged_index stores (idx+1) cast to void* and decodes back to the
     * array index at lookup time. The +1 disambiguates idx=0 from
     * hashmap_get's "absent key" return value (which is also NULL)
     */
    workspace_item_t *diverged;      /* Diverged items (files + directories) */
    size_t diverged_count;           /* Number of diverged items */
    size_t diverged_capacity;        /* Allocated capacity of diverged array */
    hashmap_t *diverged_index;       /* Maps filesystem_path -> array index+1 (as void*) */

    /* Anchor updates (accumulated during divergence analysis) */
    anchor_update_t *anchor_updates; /* Pending slow-path updates (owned) */
    size_t anchor_update_count;      /* Number of pending updates */
    size_t anchor_update_capacity;   /* Allocated capacity of updates array */

    /* Status cache */
    workspace_status_t status;       /* Cached cleanliness assessment */
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
 * both state rows (state_file_entry_t) and metadata (metadata_item_t) without conversion.
 * This eliminates Git loads for files (uses cached VWD fields) while preserving metadata
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
 * Analyze divergence for a single active row using VWD cache
 *
 * Uses the VWD (Virtual Working Directory) cache embedded in the state
 * row to perform divergence detection without database queries. All
 * expected state (blob_oid, type, anchor, etc.) is already in the row.
 *
 * @param ws Workspace (must not be NULL)
 * @param row Active state row with VWD cache (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *analyze_file_divergence(
    workspace_t *ws,
    const state_file_entry_t *row
) {
    CHECK_NULL(ws);
    CHECK_NULL(row);

    const char *fs_path = row->filesystem_path;
    const char *storage_path = row->storage_path;
    const char *profile = row->profile;

    /* Determine if the row carries a hydrated VWD cache.
     *
     * Active rows reaching this analysis path always come from the state
     * snapshot, so blob_oid is a real OID by construction. The zero-check
     * is a defensive guard against an un-hydrated row, not a type
     * discriminant. */
    bool in_state = !git_oid_is_zero(&row->blob_oid);

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
        const git_oid *blob_oid_ptr = &row->blob_oid;

        /* Extract expected filemode from VWD cache type field
         *
         * Extracted before comparison strategy selection because both paths
         * need this value. Uses shared helper for consistent mapping.
         */
        git_filemode_t expected_mode = state_type_to_git_filemode(row->type);

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
         * (row->blob_oid) to classify:
         *   - equal   → CMP_EQUAL.  disk == anchor == expected (clean).
         *   - differ  → CMP_DIFFERENT + DIVERGENCE_STALE.
         *                disk == anchor ≠ expected (external Git drift;
         *                file is still at the last-deployed blob).
         *
         * This is the key Stage-A win: STALE is tagged directly from the
         * fast path, without loading blobs or hashing. The slow-path
         * straggler case (touch(1) / editor rename-write invalidated the
         * stat witness) is still handled by Phase 3. */
        const deployment_anchor_t *anchor = &row->anchor;
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
             *
             * Asymmetry with the Phase 3 anchor-staleness site below: that site routes
             * through content_compare_blob_to_disk (byte-classify internally) because
             * anchor.blob_oid can differ from row->blob_oid and there is no
             * anchor-side cache to trust. Here we route on row->encrypted
             * directly — the cache IS byte-truth for *this* blob via the Phase 2
             * write-time invariant in content_store_file_to_worktree.
             */
            if (!row->encrypted) {
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
             * Mode sentinel: row->mode == 0 means "no metadata tracked";
             * the check will be skipped by check_item_metadata_divergence().
             */
            bool mode_differs = false;
            bool ownership_differs = false;

            error_t *check_err = check_item_metadata_divergence(
                row->mode,     /* From VWD cache (mode_t, 0 = no metadata) */
                row->owner,    /* From VWD cache (can be NULL) */
                row->group,    /* From VWD cache (can be NULL) */
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
        /* Row claims this path but the filesystem doesn't have it. */

        /* Use anchor.observed_at to distinguish ghost files from deletions
         * (see classification table above for the full decision matrix). */
        if (in_state && row->anchor.observed_at > 0) {
            /* Path has been lstat-observed on disk in scope; current
             * absence means the user deleted a previously-seen file. */
            state = WORKSPACE_STATE_DELETED;
        } else {
            /* Path has never been observed (ghost file) or the row was
             * never hydrated with a real blob (in_state = false). */
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
     * Source of truth: the persistent deployment anchor (row->anchor),
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
        && !git_oid_is_zero(&row->anchor.blob_oid)
        && !git_oid_equal(&row->anchor.blob_oid, &row->blob_oid)) {

        git_filemode_t expected_mode = state_type_to_git_filemode(row->type);
        compare_result_t verify_result = CMP_UNVERIFIED;

        struct stat verify_stat;
        error_t *verify_err = NULL;

        /* Route the anchor comparison by the anchor blob's own bytes.
         *
         * The latent bug class this avoids: routing on row->encrypted
         * silently miscategorised the staleness check across encryption-policy
         * transitions. Both directions failed:
         *   - encrypted anchor / plaintext current → compare_oid_to_disk
         *     hashed plaintext disk against an encrypted-blob OID, never
         *     equal, STALE never set.
         *   - plaintext anchor / encrypted current → content_cache called
         *     with expected_encrypted=true on a plaintext blob, the old
         *     cross-check raised ERR_STATE_INVALID, swallowed below.
         *
         * content_compare_blob_to_disk classifies by bytes, so the routing
         * decision lives with the blob whose comparison we are doing. A
         * routing-on-stale-flag bug is structurally impossible. */
        verify_err = content_compare_blob_to_disk(
            ws->repo,
            &row->anchor.blob_oid,
            fs_path,
            expected_mode,
            &initial_stat,
            storage_path,
            profile,
            ws->content_cache,
            &verify_result,
            &verify_stat
        );

        if (!verify_err && verify_result == CMP_EQUAL) {
            /* File matches old deployed content — stale repair is safe */
            divergence |= DIVERGENCE_STALE;
        }
        if (verify_err) error_free(verify_err);
    }

    /* PHASE 4: Profile reassignment detection
     *
     * Read old_profile from the row to detect reassignments. The manifest
     * layer sets it when a file's owning profile changes (e.g., removed
     * from high-precedence profile, fell back to lower). It is persisted
     * in the database and remains set until acknowledged by successful
     * deployment. The pointer is arena-backed (same lifetime as workspace).
     */
    bool profile_changed = (row->old_profile != NULL);
    char *old_profile = profile_changed ? row->old_profile : NULL;

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

    /* Step 3: Content and type comparison.
     *
     * content_compare_blob_to_disk classifies the blob by magic header and routes;
     * plaintext takes the fast OID-hash-of-disk path, encrypted decrypts via the
     * cache and byte-compares. The routing decision lives with the blob, so the
     * orphan walker cannot route a different blob's state via state_entry->encrypted
     * by accident. in_stat is forwarded to avoid redundant lstat. */
    err = content_compare_blob_to_disk(
        ws->repo,
        blob_oid_ptr,
        fs_path,
        expected_mode,
        in_stat,
        storage_path,
        profile,
        ws->content_cache,
        &cmp_result,
        &fresh_stat
    );

    if (err) {
        /* Cannot classify, load, decrypt, or compare. Possible causes:
         * - Encrypted file but no passphrase available (missing key)
         * - Decryption failed (wrong passphrase, corrupted ciphertext)
         * - Blob uses an unsupported cipher version (skew)
         * - I/O error reading blob from git
         * - Blob missing from repository (corruption)
         *
         * Conservative approach: return UNVERIFIED so the user sees
         * [orphaned, unverified] and can investigate, rather than a
         * false [orphaned, clean] or noisy [orphaned, modified]. */
        error_free(err);
        return DIVERGENCE_UNVERIFIED;
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
 * Analyze partitioned orphan candidates from the active-slice build
 *
 * Each candidate was rejected by workspace_build_active for
 * exactly one of two reasons:
 *   - Profile out of workspace scope (disabled or branch deleted)
 *   - Lifecycle terminal (STATE_INACTIVE / STATE_DELETED / STATE_RELEASED)
 *
 * No manifest probe is needed: the partition itself is the orphan
 * predicate. The RELEASED branch (loss of authority via external Git
 * removal) is detected from state_entry->state — the lifecycle column
 * is the single source of truth, set by manifest_reconcile.
 *
 * Each orphan is tagged with profile_enabled so callers can filter:
 * - status: only show profile_enabled=true (enabled profiles)
 * - apply: use all (cleanup disabled profiles too)
 */
static error_t *analyze_orphaned_files(
    workspace_t *ws,
    const state_file_entry_t * const *candidates,
    size_t candidate_count
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->profile_index);

    if (candidate_count == 0) return NULL;
    CHECK_NULL(candidates);

    error_t *err = NULL;

    for (size_t i = 0; i < candidate_count; i++) {
        const state_file_entry_t *state_entry = candidates[i];

        const char *fs_path = state_entry->filesystem_path;
        const char *storage_path = state_entry->storage_path;
        const char *profile = state_entry->profile;

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
            /* Standard orphan analysis
             *
             * Single stat capture, reused for type verification, content
             * comparison, and metadata checks — eliminates redundant lstat
             * syscalls.
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

    return NULL;
}

/**
 * Partition tracked_directories rows by orphan status
 *
 * Single pass over loaded directory rows producing two arena-allocated
 * pointer arrays:
 *   - active_dirs: profile in scope AND state not in {INACTIVE, DELETED}
 *   - orphan_dirs: everything else
 *
 * Mirrors the partition logic in workspace_build_active for
 * symmetry: filter is established here, consumers trust the partition.
 *
 * manifest_reconcile (run upstream from workspace_load) has already synced
 * tracked_directories against current Git, so dir->state reflects current
 * Git truth — STATE_INACTIVE / STATE_DELETED are authoritative.
 *
 * Note: state_directory_entry_t never carries STATE_RELEASED (file-only
 * lifecycle); the partition predicates intentionally only check INACTIVE
 * and DELETED.
 *
 * Lifetime: pointers reference rows in `all_dirs`, which itself is
 * arena-allocated by state_get_all_directories. The arena outlives the
 * workspace, so the pointers remain valid until arena destruction.
 *
 * @param ws Workspace (must not be NULL, profile_index populated)
 * @param all_dirs Buffer returned by state_get_all_directories (may be NULL when count=0)
 * @param all_count Number of rows in all_dirs
 * @param out_active Arena-allocated pointer array; NULL if no actives
 * @param out_active_count Number of entries in out_active
 * @param out_orphans Arena-allocated pointer array; NULL if no orphans
 * @param out_orphan_count Number of entries in out_orphans
 * @return Error or NULL on success
 */
static error_t *partition_state_directories(
    workspace_t *ws,
    const state_directory_entry_t *all_dirs,
    size_t all_count,
    const state_directory_entry_t ***out_active,
    size_t *out_active_count,
    const state_directory_entry_t ***out_orphans,
    size_t *out_orphan_count
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->arena);
    CHECK_NULL(ws->profile_index);
    CHECK_NULL(out_active);
    CHECK_NULL(out_active_count);
    CHECK_NULL(out_orphans);
    CHECK_NULL(out_orphan_count);

    *out_active = NULL;
    *out_active_count = 0;
    *out_orphans = NULL;
    *out_orphan_count = 0;

    if (all_count == 0) return NULL;
    CHECK_NULL(all_dirs);

    /* Allocate worst-case arrays (all-active or all-orphan are both possible). */
    const state_directory_entry_t **actives =
        arena_calloc(ws->arena, all_count, sizeof(*actives));
    if (!actives) {
        return ERROR(ERR_MEMORY, "Failed to allocate active directory partition");
    }

    const state_directory_entry_t **orphans =
        arena_calloc(ws->arena, all_count, sizeof(*orphans));
    if (!orphans) {
        return ERROR(ERR_MEMORY, "Failed to allocate orphan directory partition");
    }

    size_t active_count = 0;
    size_t orphan_count = 0;

    for (size_t i = 0; i < all_count; i++) {
        const state_directory_entry_t *dir = &all_dirs[i];

        bool profile_in_scope = hashmap_has(ws->profile_index, dir->profile);

        /* NULL state defaults to active per state.c read path. */
        bool lifecycle_terminal = dir->state && (
            strcmp(dir->state, STATE_INACTIVE) == 0 ||
            strcmp(dir->state, STATE_DELETED) == 0);

        if (!profile_in_scope || lifecycle_terminal) {
            orphans[orphan_count++] = dir;
        } else {
            actives[active_count++] = dir;
        }
    }

    *out_active = (active_count > 0) ? actives : NULL;
    *out_active_count = active_count;
    *out_orphans = (orphan_count > 0) ? orphans : NULL;
    *out_orphan_count = orphan_count;

    return NULL;
}

/**
 * Analyze partitioned orphan-directory candidates
 *
 * Each entry in the candidate slice was rejected from active scope by
 * partition_state_directories: profile out of scope, or state INACTIVE/DELETED.
 * No skip checks here — every input is by construction an orphan.
 *
 * Each orphan is tagged with profile_enabled so callers can filter:
 *   - status: only show profile_enabled=true (enabled profiles)
 *   - apply: use all (cleanup disabled profiles too)
 */
static error_t *analyze_orphaned_directories(
    workspace_t *ws,
    const state_directory_entry_t * const *candidates,
    size_t candidate_count
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->profile_index);

    if (candidate_count == 0) return NULL;
    CHECK_NULL(candidates);

    for (size_t i = 0; i < candidate_count; i++) {
        const state_directory_entry_t *dir = candidates[i];

        bool profile_enabled = hashmap_has(ws->profile_index, dir->profile);
        bool on_filesystem = fs_exists(dir->filesystem_path);

        error_t *err = workspace_add_diverged(
            ws,
            dir->filesystem_path,       /* Already arena-allocated */
            dir->storage_path,          /* Already arena-allocated */
            dir->profile,
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

    return NULL;
}

/**
 * Analyze divergence for every active row using VWD cache
 *
 * Walks ws->active and compares each row against filesystem reality.
 *
 * Performance: O(N) where N = active row count. The row's VWD cache
 * (blob_oid, type, anchor, etc.) eliminates N+1 database queries.
 */
static error_t *analyze_files_divergence(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);

    for (size_t i = 0; i < ws->active_count; i++) {
        const state_file_entry_t *row = ws->active[i];

        error_t *err = analyze_file_divergence(ws, row);
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
             * 1. Active index: file is in an active enabled profile
             * 2. Diverged index: file already classified (e.g., as released
             *    or orphaned by prior analysis phases). Released files are
             *    excluded from the active slice but already have diverged
             *    entries — adding them as untracked would create duplicates.
             */
            bool already_tracked =
                (hashmap_get(ws->active_index, full_path) != NULL) ||
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
            ws->repo, config, NULL, 0, ws->arena, &ignore_rules
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

        /* Scan each tracked directory.
         *
         * Tree-root suppression: entries arrive parent-first thanks to
         * state_get_directories_by_profile's ORDER BY filesystem_path. If
         * the last scanned entry is a directory-prefix ancestor of the
         * current one, this subtree is already covered by the ancestor's
         * recursive scan — ws->diverged_index dedupes the RESULT either
         * way, but the IO was still being paid per-level. Resets per
         * profile (different ignore rules). */
        const char *last_scanned = NULL;
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
             * - filesystem_path: Already resolved with target (VWD principle)
             * - storage_path: Portable path for storage
             */

            /* Use filesystem path directly from state (already resolved) */
            const char *filesystem_path = dir_entry->filesystem_path;

            /* Check if directory still exists */
            if (!fs_exists(filesystem_path)) {
                continue;
            }

            /* Nested-scan suppression: if the previously-scanned directory is
             * a strict directory-prefix ancestor, this subtree was already
             * walked. Boundary-aware ('/' terminator) to avoid false matches
             * like /foo/bar vs /foo/barn. Order guarantees ancestor-first. */
            if (last_scanned) {
                size_t plen = strlen(last_scanned);
                if (strncmp(last_scanned, filesystem_path, plen) == 0 &&
                    filesystem_path[plen] == '/') {
                    continue;
                }
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

            /* Record this scan root regardless of outcome — a failed scan
             * still visited the subtree, so deeper entries are redundant. */
            last_scanned = filesystem_path;
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
 * State contains filesystem_path already resolved with target, enabling
 * correct divergence detection for custom/ prefix directories.
 *
 * Consumes the active slice from partition_state_directories — every input
 * is by construction profile_in_scope AND state ACTIVE. No skip checks.
 *
 * @param ws Workspace (must not be NULL)
 * @param actives Pointer slice of active in-scope dirs from the partition
 * @param active_count Number of entries in actives
 * @return Error or NULL on success
 */
static error_t *analyze_directory_metadata_divergence(
    workspace_t *ws,
    const state_directory_entry_t * const *actives,
    size_t active_count
) {
    CHECK_NULL(ws);

    if (active_count == 0) return NULL;
    CHECK_NULL(actives);

    error_t *err = NULL;

    /* Check each active in-scope directory for divergence */
    for (size_t i = 0; i < active_count; i++) {
        const state_directory_entry_t *dir_entry = actives[i];

        /* State directory entries contain:
         * - filesystem_path: Already resolved with target (VWD principle)
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
 * Trusts the cache. After the write-time invariant established in
 * cmds/add.c and cmds/update.c, row->encrypted is byte-truth
 * (metadata.json:encrypted is stamped from content_classify_bytes at
 * the write boundary, then projected to the state DB column, then to
 * the in-memory state row). The audit reads the cached bool and
 * defers to encryption_policy_violation. Zero blob inflations.
 *
 * Per-blob byte-classification was the previous implementation's
 * regression: O(N) inflations per workspace_load against libgit2's
 * pack backend, on a hot path. The cache discipline makes the cached
 * answer authoritative.
 *
 * Only fires when encryption is active — i.e. the config has a compiled
 * auto-encrypt ruleset (see encryption_policy_is_active). Nothing to
 * check without one.
 *
 * This is a security-focused check: files matching sensitive patterns
 * (e.g., "*.key", ".ssh/id_*") should be encrypted.
 */
static error_t *analyze_encryption_policy_mismatch(
    workspace_t *ws,
    const config_t *config
) {
    CHECK_NULL(ws);

    /* Fast-path: no auto-encrypt ruleset means nothing to validate. */
    if (!encryption_policy_is_active(config)) return NULL;

    error_t *err = NULL;

    /* Check each active row */
    for (size_t i = 0; i < ws->active_count; i++) {
        const state_file_entry_t *row = ws->active[i];
        const char *storage_path = row->storage_path;
        const char *profile = row->profile;

        /* Project the cached bool to a content_kind_t for the policy predicate.
         * The 3-valued enum's UNSUPPORTED_VERSION case is unreachable here -
         * row->encrypted is a bool and collapses ENCRYPTED +
         * UNSUPPORTED_VERSION onto true. That collapse is exhaustive for
         * encryption_policy_violation: any non-PLAINTEXT kind carries encryption
         * intent and is treated as not-a-violation. The version-skew distinction
         * surfaces ia the content read path, not here. */
        content_kind_t kind = row->encrypted ? CONTENT_ENCRYPTED
                                             : CONTENT_PLAINTEXT;

        if (!encryption_policy_violation(config, storage_path, kind)) {
            continue;
        }

        /* Merge the violation into the existing divergence index — the file may already have
         * CONTENT/MODE/etc. divergence, in which case we OR the ENCRYPTION flag in alongside.
         * The O(1) index lookup prevents last-write-wins between analysis passes. */
        void *idx_ptr = hashmap_get(ws->diverged_index, row->filesystem_path);
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
            /* No existing divergence row for this file — encryption policy is the only issue.
             * Classify lifecycle state from presence + observation anchor, mirroring
             * analyze_file_divergence Phase 2: a file on disk is DEPLOYED, a missing file is
             * DELETED if ever observed (observed_at > 0), else UNDEPLOYED (ghost). */
            struct stat enc_stat;
            bool on_filesystem = (lstat(row->filesystem_path, &enc_stat) == 0);

            workspace_state_t item_state;
            if (on_filesystem) {
                item_state = WORKSPACE_STATE_DEPLOYED;
            } else if (row->anchor.observed_at > 0) {
                item_state = WORKSPACE_STATE_DELETED;
            } else {
                item_state = WORKSPACE_STATE_UNDEPLOYED;
            }

            err = workspace_add_diverged(
                ws,
                row->filesystem_path,
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

    return NULL;
}

/**
 * Partition state rows into the active slice and orphan candidates
 *
 * Walks the state DB once and produces two outputs:
 *   1. ws->active — pointer array into the arena snapshot for in-scope
 *      ACTIVE rows; ws->active_index maps fs_path → row pointer.
 *   2. orphan_candidates — pointers into the same snapshot for rejected
 *      rows (out-of-scope profile or terminal lifecycle:
 *      INACTIVE/DELETED/RELEASED).
 *
 * The partition is the single source of truth for "is this row in the
 * workspace?". analyze_orphaned_files consumes the candidate slice
 * directly; analyses over the active set walk ws->active.
 *
 * Drift repair is handled upstream by workspace_load's manifest_reconcile
 * call, so state entries read here are current with Git by construction.
 *
 * Lifetime: every pointer (active rows, orphan candidates, the active
 * pointer array, the snapshot rows themselves) lives in ws->arena. The
 * arena outlives the workspace, so all pointers are valid until arena
 * destruction. Only ws->active_index is heap-allocated (hashmap_borrow).
 *
 * Performance: O(M) where M = state entries. One pass, no probes.
 *
 * @param ws Workspace (must not be NULL, state must be loaded)
 * @param out_orphan_candidates Arena-allocated array of pointers to state
 *        rows that did not enter the active slice. NULL if none. Caller
 *        does not free (arena-owned).
 * @param out_orphan_count Number of entries in out_orphan_candidates.
 * @return Error or NULL on success
 */
static error_t *workspace_build_active(
    workspace_t *ws,
    const state_file_entry_t ***out_orphan_candidates,
    size_t *out_orphan_count
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->arena);
    CHECK_NULL(ws->profile_index);
    CHECK_NULL(out_orphan_candidates);
    CHECK_NULL(out_orphan_count);

    *out_orphan_candidates = NULL;
    *out_orphan_count = 0;

    state_file_entry_t *snapshot = NULL;
    size_t snap_count = 0;

    /* Read every manifest row into the workspace arena. The snapshot
     * outlives this function; every active and orphan pointer below
     * references rows inside it. */
    error_t *err = state_get_all_files(
        ws->state, ws->arena, &snapshot, &snap_count
    );
    if (err) {
        return error_wrap(err, "Failed to read manifest from state");
    }

    /* Active index always exists, even when empty. Sized to the snapshot
     * (worst case = every row is active). hashmap_borrow keeps fs_path
     * keys by reference — they live in the arena alongside the rows. */
    ws->active_index = hashmap_borrow(snap_count > 0 ? snap_count : 64);
    if (!ws->active_index) {
        return ERROR(ERR_MEMORY, "Failed to create active index");
    }

    if (snap_count == 0) {
        ws->active = NULL;
        ws->active_count = 0;
        return NULL;
    }

    /* Allocate the active pointer array and the orphan candidate array
     * at worst-case size. Both partitions share the snapshot — the row
     * buffer never gets duplicated. */
    ws->active = arena_calloc(ws->arena, snap_count, sizeof(*ws->active));
    const state_file_entry_t **candidates = arena_calloc(
        ws->arena, snap_count, sizeof(*candidates)
    );
    if (!ws->active || !candidates) {
        hashmap_free(ws->active_index, NULL);
        ws->active_index = NULL;
        ws->active = NULL;
        return ERROR(ERR_MEMORY, "Failed to allocate active partition");
    }

    size_t active_count = 0;
    size_t candidate_count = 0;

    /* Partition state rows: in-scope active → ws->active, others → candidates */
    for (size_t i = 0; i < snap_count; i++) {
        state_file_entry_t *row = &snapshot[i];

        bool profile_in_scope = hashmap_has(ws->profile_index, row->profile);

        /* Lifecycle terminal states are rejected from the active slice and surfaced
         * to orphan detection. NULL state defaults to active per state.c read path */
        bool lifecycle_terminal = row->state && (
            strcmp(row->state, STATE_INACTIVE) == 0 ||
            strcmp(row->state, STATE_DELETED) == 0 ||
            strcmp(row->state, STATE_RELEASED) == 0);

        if (!profile_in_scope || lifecycle_terminal) {
            /* Rejected: surface to orphan analysis.
             *
             * - Out-of-scope profile: profile disabled or branch deleted.
             *   analyze_orphaned_files handles via profile_enabled flag.
             * - Lifecycle terminal: INACTIVE/DELETED/RELEASED. The
             *   RELEASED branch (loss of authority) is detected from
             *   row->state inside analyze_orphaned_files. */
            candidates[candidate_count++] = row;
            continue;
        }

        ws->active[active_count++] = row;

        /* Index by row pointer directly: the active array is allocated at
         * load time and never grows, so pointers into it are stable for
         * the workspace lifetime — no idx+1 encoding needed. */
        err = hashmap_set(ws->active_index, row->filesystem_path, row);
        if (err) {
            hashmap_free(ws->active_index, NULL);
            ws->active_index = NULL;
            ws->active = NULL;
            return error_wrap(err, "Failed to populate active index");
        }
    }

    ws->active_count = active_count;

    *out_orphan_candidates = (candidate_count > 0) ? candidates : NULL;
    *out_orphan_count = candidate_count;

    return NULL;
}

/**
 * Load workspace from repository
 */
error_t *workspace_load(
    git_repository *repo,
    state_t *state,
    const scope_t *scope,
    const config_t *config,
    content_cache_t *content_cache,
    const mount_table_t *mounts,
    const workspace_load_t *options,
    arena_t *arena,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(scope);
    CHECK_NULL(content_cache);
    CHECK_NULL(mounts);
    CHECK_NULL(options);
    CHECK_NULL(arena);
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
    err = manifest_reconcile(repo, state, arena, mounts, NULL);
    if (err) {
        return error_wrap(err, "Failed to reconcile manifest with Git");
    }

    err = workspace_create_empty(repo, profiles, &ws);
    if (err) {
        return err;
    }

    /* Borrow caller-owned resources. Lifetime guarantees: state comes from
     * ctx->state (command-scoped); content_cache comes from ctx->content_cache
     * (command-scoped, wraps ctx->keymgr); arena is ctx->arena (command-scoped).
     * All three must outlive workspace_free. */
    ws->state = state;
    ws->content_cache = content_cache;
    ws->arena = arena;

    /* Partition the state snapshot into the active slice and orphan
     * candidates. The active slice (ws->active + ws->active_index) is
     * borrowed pointers into the arena snapshot returned by
     * state_get_all_files — no parallel projection, no second cache.
     *
     * Orphan candidates (rows out-of-scope or in a terminal lifecycle
     * state) flow to analyze_orphaned_files. The partition is the
     * single source of truth for orphan-ness — no later hashmap probe
     * is needed.
     *
     * Drift was already repaired by manifest_reconcile above; this
     * function reads current state directly. */
    const state_file_entry_t **file_orphans = NULL;
    size_t file_orphan_count = 0;
    err = workspace_build_active(ws, &file_orphans, &file_orphan_count);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to build active slice from state");
    }

    /* Load and partition tracked directories once when any consumer needs them.
     * Both analyze_orphaned_directories and analyze_directory_metadata_divergence
     * read disjoint slices of the partition, so a single load + single partition
     * serves both. */
    const state_directory_entry_t **active_dirs = NULL;
    size_t active_dir_count = 0;
    const state_directory_entry_t **orphan_dirs = NULL;
    size_t orphan_dir_count = 0;

    if (resolved_opts.analyze_orphans || resolved_opts.analyze_directories) {
        state_directory_entry_t *all_dirs = NULL;
        size_t all_dir_count = 0;
        err = state_get_all_directories(state, arena, &all_dirs, &all_dir_count);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to load tracked directories from state");
        }

        err = partition_state_directories(
            ws, all_dirs, all_dir_count,
            &active_dirs, &active_dir_count,
            &orphan_dirs, &orphan_dir_count
        );
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to partition tracked directories");
        }
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

    /* Analyze orphaned state entries (files + directories).
     * Both consume partition slices produced above; no probe-based filter. */
    if (resolved_opts.analyze_orphans) {
        err = analyze_orphaned_files(ws, file_orphans, file_orphan_count);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze orphaned files");
        }

        err = analyze_orphaned_directories(ws, orphan_dirs, orphan_dir_count);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze orphaned directories");
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
        err = analyze_directory_metadata_divergence(
            ws, active_dirs, active_dir_count
        );
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
    workspace_items_t *out_files,
    workspace_items_t *out_dirs,
    workspace_items_t *out_excluded,
    size_t *out_excluded_count
) {
    CHECK_NULL(ws);

    /* Initialize all outputs to safe defaults — first thing, before any
     * work that can fail, so an early error path leaves callers with
     * clean zero values rather than uninitialized garbage. */
    if (out_files) *out_files = (workspace_items_t){ 0 };
    if (out_dirs) *out_dirs = (workspace_items_t){ 0 };
    if (out_excluded) *out_excluded = (workspace_items_t){ 0 };
    if (out_excluded_count) *out_excluded_count = 0;

    /* Early exit if nothing requested */
    bool want_files = (out_files != NULL);
    bool want_dirs = (out_dirs != NULL);
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

    if (want_files) {
        out_files->entries = (const workspace_item_t *const *)
            ptr_array_steal(&files, &out_files->count);
    }
    if (want_dirs) {
        out_dirs->entries = (const workspace_item_t *const *)
            ptr_array_steal(&dirs, &out_dirs->count);
    }
    if (want_excluded) {
        out_excluded->entries = (const workspace_item_t *const *)
            ptr_array_steal(&excluded_items, &out_excluded->count);

        if (out_excluded_count) {
            *out_excluded_count = out_excluded->count;
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
 * Get the active in-scope state file slice
 *
 * The cast adds const at both pointer levels — safe per the C standard's
 * "T**  → const T *const *" rule (no diagnostic required).
 */
state_files_t workspace_active(const workspace_t *ws) {
    if (!ws) return (state_files_t){ 0 };
    return (state_files_t){
        .entries = (const state_file_entry_t *const *) ws->active,
        .count = ws->active_count,
    };
}

/**
 * Look up an active row by filesystem path
 *
 * O(1) hashmap probe over the active slice. The map's value is a
 * mutable row pointer (workspace_advance_anchor patches in place);
 * external callers receive a const view via narrowing cast.
 */
const state_file_entry_t *workspace_lookup_active(
    const workspace_t *ws,
    const char *filesystem_path
) {
    if (!ws || !filesystem_path) return NULL;
    return hashmap_get(ws->active_index, filesystem_path);
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
 * state_update_anchor, then patches the active row's anchor so the
 * snapshot does not drift from the DB. Mirrors state_update_anchor's
 * preserve-on-zero semantic on deployed_at (a zero timestamp preserves
 * the in-memory value) and the monotonic-once-set semantic on
 * observed_at (the first non-zero value wins).
 *
 * DB write runs first; on error we return without touching memory so a
 * failed write cannot leave the in-memory view ahead of reality.
 *
 * Partition safety: ws->active_index covers exactly the rows in the
 * active partition, which is disjoint from orphan candidates. So a
 * lookup hit never lands on a row outside the active set.
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

    /* Patch the snapshot row; state_update_anchor wrote the DB above.
     * Not-found is tolerated: the DB write already no-op'd for rows
     * filtered by precedence / disabled profile, and the active index
     * may likewise not carry the path. */
    state_file_entry_t *row = hashmap_get(ws->active_index, filesystem_path);
    if (!row) return NULL;

    row->anchor.blob_oid = anchor->blob_oid;
    row->anchor.stat = anchor->stat;
    if (anchor->deployed_at != 0) {
        row->anchor.deployed_at = anchor->deployed_at;
    }
    if (row->anchor.observed_at == 0 && anchor->observed_at != 0) {
        row->anchor.observed_at = anchor->observed_at;   /* monotonic once set */
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
 * patches the active row's anchor in place; no staleness window opens
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

    /* Free diverged array (string fields are arena-borrowed, not freed individually) */
    free(ws->diverged);

    /* Free anchor updates (paths are borrowed, anchor is plain data) */
    free(ws->anchor_updates);

    /* Free indices (values are borrowed, so pass NULL for value free function).
     * active_index values are state-row pointers into ws->arena — also borrowed. */
    hashmap_free(ws->profile_index, NULL);
    hashmap_free(ws->diverged_index, NULL);
    hashmap_free(ws->active_index, NULL);

    /* ws->active is arena-allocated (pointer array into the snapshot);
     * the caller's arena releases it when destroyed. ws->arena is
     * borrowed — never destroyed here. */

    free(ws);
}
