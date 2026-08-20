/**
 * workspace.c - Workspace abstraction implementation
 *
 * Manages three-state consistency: Profile (git), Deployment (state.db), Filesystem (disk).
 * Detects and categorizes divergence to prevent data loss and enable safe operations.
 *
 * Trust Model:
 * Files trust the VWD manifest (virtual_manifest table), maintained by manifest layer.
 * Directories trust the tracked_directories state column, maintained by the
 * manifest layer's directory rebuild (sweep + re-projection + ghost reclaim).
 * Both are repaired in state by the load-time reconcile when an enabled
 * profile's branch has moved — an external commit, a pull, a revert: the
 * projection engine projects every enabled profile at HEAD.
 * That maintenance covers the enabled set — the only profiles with a
 * commit_oid baseline — so orphan analysis observes Git authority for the
 * rows the engine leaves alone (a disabled profile's, a dead branch's, a
 * re-enabled profile's INACTIVE leftovers) instead of trusting a cache
 * nothing repairs.
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
#include "sys/gitops.h"
#include "sys/source.h"
#include "utils/privilege.h"

/**
 * Pending anchor update (internal type)
 *
 * Accumulated during analyze_file_divergence() when the slow path confirms
 * CMP_EQUAL. The verified (blob_oid, stat) pair should be persisted so the
 * next run can both short-circuit via the fast-path stat and, if
 * Git advances blob_oid in the meantime, classify the file as stale from
 * the fast path instead of re-hashing.
 *
 * blob_oid is carried alongside stat because the anchor ties that stat to
 * a specific blob — a stat triple without a blob pointer is meaningless.
 *
 * The row pointer is borrowed from ws->active_files (workspace lifetime).
 * Carrying the row directly lets the flush call state_update_anchor with the
 * row's filesystem_path AND assign the resolved anchor straight into
 * row->anchor — no second hashmap probe to recover the snapshot handle.
 */
typedef struct {
    state_file_entry_t *row;         /* Active row this update targets (borrowed) */
    git_oid blob_oid;                /* Blob dotta just verified disk matches */
    stat_cache_t stat;               /* Captured stat triple (fast-path proof) */
} anchor_update_t;

/**
 * Workspace structure
 *
 * Contains indexed views of all three states plus divergence analysis.
 * Uses hashmaps for O(1) lookups during analysis.
 */
struct workspace {
    git_repository *repo;                        /* Borrowed reference */
    arena_t *arena;                              /* Borrowed; backs every workspace-lifetime string */

    /* Active in-scope file slice.
     *
     * Pointer array into the arena snapshot returned by state_get_all_files
     * at load time. Pointers are mutable to permit in-place anchor patches
     * via workspace_advance_anchor; external accessors cast to const. Storage
     * is stable — no realloc during workspace lifetime — so active_file_index
     * can store row pointers directly (no idx+1 encoding). */
    state_file_entry_t **active_files;           /* Active rows (mutable; arena-allocated) */
    size_t active_file_count;                    /* Number of active rows */
    hashmap_t *active_file_index;                /* fs_path → state_file_entry_t * (heap-allocated) */

    /* Orphan file slice (out-of-scope or terminal lifecycle).
     * Mirror of the active slice — pointers borrow into the same arena snapshot. */
    const state_file_entry_t **orphan_files;     /* Arena-borrowed */
    size_t orphan_file_count;                    /* Number of orphan files */

    /* Active in-scope directory slice.
     *
     * Mirror of the active file slice: a pointer array into the arena
     * snapshot returned by state_get_all_directories at load time. Pointers
     * are mutable to permit in-place witness patches via
     * workspace_advance_witness; external accessors cast to const. Storage
     * is stable — no realloc during workspace lifetime — so active_dir_index
     * can store row pointers directly. */
    state_directory_entry_t **active_dirs;       /* Active rows (mutable; arena-allocated) */
    size_t active_dir_count;                     /* Number of active directories */
    hashmap_t *active_dir_index;                 /* fs_path → state_directory_entry_t * (heap-allocated) */

    /* Orphan directory slice (out-of-scope or terminal lifecycle).
     * Mirror of the active dir slice — pointers borrow into the same arena snapshot. */
    const state_directory_entry_t **orphan_dirs; /* Arena-borrowed */
    size_t orphan_dir_count;                     /* Number of orphan directories */

    /* State and profile scope */
    state_t *state;                              /* Deployment state (borrowed from caller) */
    const string_array_t *profiles;              /* Borrowed; valid for workspace lifetime */
    hashmap_t *profile_index;                    /* Maps profile -> NULL (membership set, O(1) lookup) */

    /* Content cache for encrypted blob reads during divergence analysis */
    content_cache_t *content_cache;              /* Borrowed — NOT freed in workspace_free */

    /* Divergence tracking.
     *
     * The diverged array grows via realloc as workspace_add_diverged appends
     * items during analysis, so pointers into it would dangle on growth.
     * diverged_index stores (idx+1) cast to void* and decodes back to the
     * array index at lookup time. The +1 disambiguates idx=0 from
     * hashmap_get's "absent key" return value (which is also NULL). */
    workspace_item_t *diverged;                  /* Diverged items (files + directories) */
    size_t diverged_count;                       /* Number of diverged items */
    size_t diverged_capacity;                    /* Allocated capacity of diverged array */
    hashmap_t *diverged_index;                   /* Maps filesystem_path -> array index+1 (as void*) */

    /* Anchor updates accumulated during divergence analysis */
    anchor_update_t *anchor_updates;             /* Pending slow-path updates (owned) */
    size_t anchor_update_count;                  /* Number of pending updates */
    size_t anchor_update_capacity;               /* Allocated capacity of updates array */

    /* Witness updates accumulated during directory analysis.
     *
     * Directory counterpart of anchor_updates. A witness advance needs only
     * the row — the timestamp is the flush's; an anchor advance also carries
     * the blob and stat it confirmed, hence the richer element type above. */
    state_directory_entry_t **witness_updates;   /* Rows borrowed from ws->active_dirs (array owned) */
    size_t witness_update_count;                 /* Number of pending updates */
    size_t witness_update_capacity;              /* Allocated capacity of updates array */

    /* Status cache */
    workspace_status_t status;                   /* Cached cleanliness assessment */
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
 * @param profile Source profile name — every producer passes one (a state
 *                row's, NOT NULL in the schema, or a metadata claim's)
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
    path_kind_t item_kind,
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
 * Accumulates the (blob_oid, stat) pair so workspace_flush_updates() can
 * persist it via state_update_anchor(). The blob_oid is required because the
 * anchor binds its fast-path stat to a specific blob.
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
 * @param row Active row whose anchor should advance (borrowed; workspace lifetime)
 * @param blob_oid Blob dotta just confirmed disk matches (must not be NULL)
 * @param st Verified filesystem stat
 */
static void workspace_record_anchor_update(
    workspace_t *ws,
    state_file_entry_t *row,
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
        .row = row,
        .blob_oid = *blob_oid,
        .stat = stat_cache_from_stat(st),
    };
}

/**
 * Record a witness advance for later flushing
 *
 * Directory sibling of workspace_record_anchor_update: analysis observed
 * the path on disk but the row carries no witness. Only the row is
 * accumulated — the observation timestamp is the flush's.
 *
 * Same OOM asymmetry as the anchor recorder, for the same reason: a
 * dropped witness costs no correctness, only a deferral to the next
 * observation event (projection probe, next flush, apply's post-deploy
 * pass), each of which re-derives it from a live lstat.
 *
 * @param ws Workspace (must not be NULL)
 * @param row Active row whose witness should advance (borrowed; workspace lifetime)
 */
static void workspace_record_witness_update(
    workspace_t *ws,
    state_directory_entry_t *row
) {
    if (!ws || !row) return;

    if (ws->witness_update_count >= ws->witness_update_capacity) {
        size_t new_cap = ws->witness_update_capacity
                       ? ws->witness_update_capacity * 2 : 16;

        state_directory_entry_t **new_arr = realloc(
            ws->witness_updates,
            new_cap * sizeof(*new_arr)
        );
        if (!new_arr) return;

        ws->witness_updates = new_arr;
        ws->witness_update_capacity = new_cap;
    }

    ws->witness_updates[ws->witness_update_count++] = row;
}

/**
 * Witness-gated absence classification — the single decision for every
 * absent managed path, file or directory.
 *
 * observed_at == 0 means dotta has never lstat-confirmed the path on disk
 * in scope: there is no filesystem obligation, so absence is UNDEPLOYED
 * (apply's job: create it) — never DELETED (update's job: commit the
 * deletion and propagate it to every machine).
 */
static workspace_state_t classify_absent(time_t observed_at) {
    return (observed_at > 0) ? WORKSPACE_STATE_DELETED
                             : WORKSPACE_STATE_UNDEPLOYED;
}

/**
 * Analyze divergence for a single active row using VWD cache
 *
 * Uses the VWD (Virtual Working Directory) cache embedded in the state
 * row to perform divergence detection without database queries. All
 * expected state (blob_oid, type, anchor, etc.) is already in the row.
 *
 * Content is judged three-way, with the deployment anchor as base (see
 * Phase 1): DIVERGENCE_STALE says Git moved past the blob dotta last
 * deployed, DIVERGENCE_CONTENT says disk left it. Each is a verdict in
 * its own right — STALE without CONTENT is apply-side work that
 * overwrites nothing of the user's; CONTENT without STALE is a local
 * edit Git has not raced; both together is a conflict.
 *
 * The row pointer is non-const because a slow-path CMP_EQUAL outcome enqueues
 * an anchor advance against this exact row (workspace_record_anchor_update);
 * the function does not mutate the row directly, but the deferred mutation
 * is real, so const would mislead.
 *
 * @param ws Workspace (must not be NULL)
 * @param row Active state row with VWD cache (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *analyze_file_divergence(
    workspace_t *ws,
    state_file_entry_t *row
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
        if (errno != ENOENT) {
            /* Inaccessible, not absent (EACCES, ELOOP, ENOTDIR, EIO).
             * Same policy as the orphan path below: assume the path is
             * there and record the uncertainty, rather than failing the
             * load and taking every other managed path down with one
             * unreadable one.
             *
             * DEPLOYED is the load-bearing half — absence must never be
             * inferred from a failure to look, or update commits a
             * deletion that never happened. UNVERIFIED keeps consumers
             * conservative: apply retries the write and surfaces the real
             * errno, cleanup's UNVERIFIED skip blocks removal.
             *
             * Returns here because every phase below needs a valid stat. */
            return workspace_add_diverged(
                ws, fs_path, storage_path, profile, row->old_profile,
                WORKSPACE_STATE_DEPLOYED, DIVERGENCE_UNVERIFIED,
                PATH_KIND_FILE,
                true,                      /* on_filesystem (assumed present) */
                true,                      /* profile_enabled */
                row->old_profile != NULL   /* profile_changed */
            );
        }

        on_filesystem = false;
        memset(&initial_stat, 0, sizeof(initial_stat));
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
     *
     * The content verdict is a three-way comparison with the deployment
     * anchor as base:
     *
     *   theirs = row->blob_oid          what Git expects now
     *   base   = row->anchor.blob_oid   what dotta last confirmed on disk
     *   ours   = disk
     *
     *   git_moved   := base set  && base ≠ theirs   Git advanced since dotta
     *                                               last deployed this path
     *   user_edited := base unset || ours ≠ base    disk left the blob dotta
     *                                               put there
     *
     * When ours ≠ theirs: CONTENT iff user_edited, STALE iff git_moved.
     * STALE without CONTENT means "overwrite loses nothing"; CONTENT
     * without STALE means "Git has not moved since this was deployed";
     * both means both sides moved. Without a base there is no second
     * question — any difference from theirs is the user's.
     *
     * Source of truth for the base: the persistent deployment anchor
     * (row->anchor, the virtual_manifest.deployed_blob_oid column).
     * Cross-process correct by construction — every invocation sees the
     * same answer.
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

        /* The first question of the three-way frame is answered from the
         * row alone; the second (disk_at_anchor — ours == base) is answered
         * by whichever path below settles it, and only when it can change
         * the verdict. */
        const deployment_anchor_t *anchor = &row->anchor;
        bool git_moved = !git_oid_is_zero(&anchor->blob_oid) &&
            !git_oid_equal(&anchor->blob_oid, blob_oid_ptr);
        bool disk_at_anchor = false;

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
         * stat match is a cryptographically-grade proof that disk still
         * equals anchor.blob_oid — no re-hash needed, and the second
         * question is answered for free: ours == base. Whether that is
         * CMP_EQUAL (base == theirs: clean) or CMP_DIFFERENT (Git moved:
         * STALE alone) is then read straight from git_moved, without
         * loading blobs or hashing. */
        if (anchor->stat.mtime != 0
            && anchor->stat.mtime == (int64_t) initial_stat.st_mtime
            && anchor->stat.size == (int64_t) initial_stat.st_size
            && anchor->stat.ino == (uint64_t) initial_stat.st_ino) {
            /* stat match ⟹ disk == anchor.blob_oid */
            file_stat = initial_stat;
            disk_at_anchor = true;
            cmp_result = git_moved ? CMP_DIFFERENT : CMP_EQUAL;
        } else {
            /* SLOW PATH: Full content comparison, ours vs theirs
             *
             * Strategy selection based on encryption status:
             * - Non-encrypted: Hash filesystem file and compare OID directly
             * - Encrypted: blob_oid is ciphertext hash; must load, decrypt, compare
             *
             * Both paths receive initial_stat to avoid redundant lstat syscalls.
             *
             * Asymmetry with the second question below: that one routes
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
                workspace_record_anchor_update(ws, row, blob_oid_ptr, &file_stat);
            }

            /* Second question — ours vs base — asked only when it can change
             * the verdict: Git moved, and the stat triple did not vouch for
             * disk (touch(1), an editor's rename-write, a fresh checkout)
             * although disk content may still be the blob dotta last
             * deployed.
             *
             * Route the anchor comparison by the anchor blob's own bytes.
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
             * routing-on-stale-flag bug is structurally impossible.
             *
             * A failed or inconclusive compare leaves disk_at_anchor false:
             * the edit is taken as real (CONTENT), the conservative answer —
             * STALE still holds, because git_moved is a fact about two OIDs. */
            if (cmp_result == CMP_DIFFERENT && git_moved) {
                compare_result_t at_anchor = CMP_UNVERIFIED;
                error_t *verify_err = content_compare_blob_to_disk(
                    ws->repo,
                    &anchor->blob_oid,
                    fs_path,
                    expected_mode,
                    &initial_stat,
                    storage_path,
                    profile,
                    ws->content_cache,
                    &at_anchor,
                    NULL
                );
                if (verify_err) error_free(verify_err);
                disk_at_anchor = (at_anchor == CMP_EQUAL);
            }
        }

        /* Set divergence flags based on comparison result */
        switch (cmp_result) {
            case CMP_EQUAL:
                /* Content and type match - no divergence from content comparison.
                 * Permission checking happens below. */
                break;

            case CMP_DIFFERENT:
                /* ours ≠ theirs — name which side moved; both can have */
                if (!disk_at_anchor) divergence |= DIVERGENCE_CONTENT;
                if (git_moved) divergence |= DIVERGENCE_STALE;
                break;

            case CMP_TYPE_DIFF:
                /* Type differs (file vs symlink) - this is a blocking condition.
                 * Return immediately with TYPE divergence. */
                return workspace_add_diverged(
                    ws, fs_path, storage_path, profile, NULL, WORKSPACE_STATE_DEPLOYED,
                    DIVERGENCE_TYPE, PATH_KIND_FILE, on_filesystem, true, false
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
     *   - the projection engine's INSERT path (scope-entry observation).
     *   - state_update_anchor (every observation/ownership advance — apply
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
        /* Row claims this path but the filesystem doesn't have it.
         * classify_absent gates on the witness (see the classification
         * table above); an un-hydrated row (in_state = false) is treated
         * as never-observed regardless. */
        state = in_state ? classify_absent(row->anchor.observed_at)
                         : WORKSPACE_STATE_UNDEPLOYED;

        /* Clear divergence flags - can't detect divergence on missing files */
        divergence = DIVERGENCE_NONE;
    } else {
        /* File in manifest and on filesystem */
        state = WORKSPACE_STATE_DEPLOYED;
        /* Keep accumulated divergence flags from Phase 1 */
    }

    /* PHASE 3: Profile reassignment detection
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
            divergence, PATH_KIND_FILE, on_filesystem, true, profile_changed
        );
        if (err) return err;
    }

    return NULL;
}

/**
 * Compute divergence for orphaned file
 *
 * Mirrors analyze_file_divergence() logic but optimized for orphan context.
 * Compares filesystem state against what dotta last deployed.
 *
 * An orphan asks one question — is disk still what dotta put there? — so
 * prune safety is measured against the deployment anchor, never against
 * the VWD blob: Git may have moved on after the deployment and before the
 * path left scope, and that move is not the user's edit. The VWD blob
 * stands in only for a row dotta witnessed but never deployed (anchor
 * unset) — then it is the only content this row has ever been measured
 * against. DIVERGENCE_STALE is therefore never emitted here.
 *
 * Architecture:
 * - Uses the anchor (blob_oid, stat) and VWD cached metadata (type, mode,
 *   owner, group)
 * - Anchor stat triple as the fast path, the same proof the active slice
 *   relies on: a match means the exact node dotta wrote, no hashing
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

    /* Step 1: Choose the reference blob and validate it
     *
     * The anchor when dotta has ever confirmed disk against a blob; the
     * VWD blob otherwise. state.c's read path already rejects wrong-sized
     * BLOB columns, so by the time we get here the OID should be
     * well-formed. A zero reference (neither set) still indicates a bad
     * row — treat it as corruption.
     */
    const deployment_anchor_t *anchor = &state_entry->anchor;
    const git_oid *reference = !git_oid_is_zero(&anchor->blob_oid) ? &anchor->blob_oid
                                                                   : &state_entry->blob_oid;
    if (git_oid_is_zero(reference)) {
        return DIVERGENCE_UNVERIFIED;
    }

    /* Step 2: Extract expected filemode from type field
     *
     * Calculate once, use for both content comparison and mode checking.
     * Uses shared helper for consistent mapping across modules. The anchor
     * records no type, so a type Git changed after the deployment is
     * still compared on the slow path — held as [type], the safe side.
     */
    git_filemode_t expected_mode = state_type_to_git_filemode(state_entry->type);

    /* Stat for permission checking (receives copy from in_stat via comparison functions) */
    struct stat fresh_stat;
    memset(&fresh_stat, 0, sizeof(fresh_stat));
    compare_result_t cmp_result;
    error_t *err = NULL;

    /* Step 3: Content and type comparison.
     *
     * Anchor fast path first: a live stat matching the triple captured at
     * the last confirmation is proof that disk still equals anchor.blob_oid
     * (see analyze_file_divergence for the invariant), so the exact node
     * dotta wrote is recognised without loading or hashing anything.
     *
     * Otherwise content_compare_blob_to_disk classifies the blob by magic
     * header and routes; plaintext takes the fast OID-hash-of-disk path,
     * encrypted decrypts via the cache and byte-compares. The routing
     * decision lives with the blob, so the orphan walker cannot route a
     * different blob's state via state_entry->encrypted by accident — an
     * anchor may sit on the other side of an encryption-policy flip from
     * the VWD blob. in_stat is forwarded to avoid redundant lstat. */
    if (anchor->stat.mtime != 0
        && anchor->stat.mtime == (int64_t) in_stat->st_mtime
        && anchor->stat.size == (int64_t) in_stat->st_size
        && anchor->stat.ino == (uint64_t) in_stat->st_ino) {
        /* stat match ⟹ disk == anchor.blob_oid */
        fresh_stat = *in_stat;
        cmp_result = CMP_EQUAL;
    } else {
        err = content_compare_blob_to_disk(
            ws->repo,
            reference,
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
            /* Disk left the blob dotta deployed (or, un-anchored, the VWD blob) */
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
     * 3. Verification didn't fail (we have fresh_stat from the fast path
     *    or the compare)
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
 * Per-profile authority cache entry (one analysis pass)
 *
 * exists: refs/heads/<profile> resolved at first sight.
 * tree:   the branch's HEAD tree, loaded lazily on the first in-tree
 *         question and kept for the rest of the pass; NULL until then and
 *         forever if !exists. Stored only on success, so "tree == NULL"
 *         also reads as "not loaded yet — try again" for the next row.
 */
typedef struct {
    bool exists;
    git_tree *tree;
} authority_cache_t;

/**
 * Free an authority cache entry (hashmap value callback)
 */
static void authority_cache_free(void *value) {
    authority_cache_t *entry = value;
    if (!entry) {
        return;
    }
    git_tree_free(entry->tree);   /* NULL-safe */
    free(entry);
}

/**
 * What the profile that deployed an orphan currently says about it
 */
typedef enum {
    ORPHAN_AUTHORITY_BACKED,      /* Branch exists and its HEAD tree has the path */
    ORPHAN_AUTHORITY_LOST,        /* Branch gone, or the path is not in its HEAD tree */
    ORPHAN_AUTHORITY_UNVERIFIED   /* A Git lookup failed — cannot tell, must not guess */
} orphan_authority_t;

/**
 * Observe Git authority for an orphaned file
 *
 * "Does the profile that deployed this path still claim it?" — its branch
 * resolves and its HEAD tree has storage_path. It is the one observation
 * the workspace did not make before: the projection engine
 * (manifest_apply_scope, run by reconcile and every scope transition)
 * covers enabled profiles at HEAD, and a row it deliberately leaves alone
 * can still lose its Git backing. Three kinds of row reach this probe:
 *   - a disabled profile's rows — never projected, and its branch can be
 *     deleted, rebased or git rm'd behind them;
 *   - rows a scope change demoted for a reason the change did not cause
 *     — a dead branch, or another enabled profile's external removal
 *     projected in the same call — the engine gives every departure the
 *     call's INACTIVE leftover without asking why;
 *   - a re-enabled profile's INACTIVE rows whose path its HEAD no longer
 *     has — the engine preserves non-ACTIVE rows outside the view.
 * Only a live look at Git says which. Apply's cleanup preflight used to
 * take that look; status read the same items and could not see it, so it
 * predicted a prune where apply then released. Observed here, every
 * reader of orphan items shares one verdict, and cleanup's verdict phase
 * reads nothing but the item.
 *
 * Answers:
 *   BACKED      the orphan is dotta's to prune, divergence permitting
 *   LOST        Git cannot back the file: branch deleted externally
 *               (content irrecoverable from any profile), or the path
 *               removed from a branch that still exists (git rm, rebase,
 *               fetch). The caller emits WORKSPACE_STATE_RELEASED — left
 *               on disk, row retires.
 *   UNVERIFIED  transient I/O, a locked packfile, a corrupt ref or tree.
 *               Authority cannot be determined and must not be guessed:
 *               LOST would retire the row, BACKED would prune the file.
 *               The caller marks DIVERGENCE_UNVERIFIED and the orphan is
 *               held until Git answers.
 *
 * @param repo Repository (must not be NULL)
 * @param cache profile → authority_cache_t (borrowed keys, owned values)
 * @param profile Row's profile (NOT NULL in the schema)
 * @param storage_path Row's storage path (NOT NULL in the schema)
 * @param out Receives the answer (must not be NULL)
 * @return ERR_MEMORY if the cache entry cannot be created; NULL otherwise
 */
static error_t *compute_orphan_authority(
    git_repository *repo,
    hashmap_t *cache,
    const char *profile,
    const char *storage_path,
    orphan_authority_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(cache);
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    *out = ORPHAN_AUTHORITY_UNVERIFIED;

    authority_cache_t *entry = hashmap_get(cache, profile);
    if (!entry) {
        /* First row of this profile: does the branch still exist? A ref
         * lookup, not a tree load — most profiles answer here. Git errors
         * are not cached: a transient failure must stay retryable. */
        bool exists = false;
        error_t *err = gitops_branch_exists(repo, profile, &exists);
        if (err) {
            error_free(err);
            return NULL;                    /* UNVERIFIED */
        }

        entry = calloc(1, sizeof(*entry));
        if (!entry) {
            return ERROR(ERR_MEMORY, "Failed to allocate authority cache entry");
        }
        entry->exists = exists;

        err = hashmap_set(cache, profile, entry);
        if (err) {
            authority_cache_free(entry);
            return error_wrap(err, "Failed to cache authority for '%s'", profile);
        }
    }

    if (!entry->exists) {
        *out = ORPHAN_AUTHORITY_LOST;       /* Branch deleted externally */
        return NULL;
    }

    if (!entry->tree) {
        /* Lazy-load the HEAD tree on the first in-tree question for this
         * profile; stored only on success, so a failure is retried by the
         * next row instead of condemning the whole profile. */
        git_tree *tree = NULL;
        error_t *err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            error_free(err);
            return NULL;                    /* UNVERIFIED */
        }
        entry->tree = tree;                 /* Ownership transfers to the cache */
    }

    /* Check if file exists in tree via path traversal
     *
     * Distinguish between "file not in tree" (GIT_ENOTFOUND) and actual
     * errors (GIT_ERROR, OOM). ENOTFOUND is the normal "removed from Git"
     * case. Actual errors should propagate so the caller can treat them
     * as CANNOT_VERIFY rather than RELEASED — preserving the state entry
     * is more conservative than removing it.
     */
    git_tree_entry *tree_entry = NULL;
    int rc = git_tree_entry_bypath(&tree_entry, entry->tree, storage_path);

    if (rc == 0) {
        git_tree_entry_free(tree_entry);
        *out = ORPHAN_AUTHORITY_BACKED;
    } else if (rc == GIT_ENOTFOUND) {
        *out = ORPHAN_AUTHORITY_LOST;
    }
    /* Anything else: *out stays UNVERIFIED */

    return NULL;
}

/**
 * Analyze partitioned orphan candidates from the active-slice build
 *
 * Each candidate was rejected by workspace_partition_files for
 * exactly one of two reasons:
 *   - Profile out of workspace scope (disabled or branch deleted)
 *   - Lifecycle terminal (LIFECYCLE_INACTIVE / LIFECYCLE_DELETED / LIFECYCLE_RELEASED)
 *
 * No manifest probe is needed: the partition itself is the orphan
 * predicate.
 *
 * Per orphan, in order: presence (one lstat), Git authority
 * (compute_orphan_authority — asked for present rows that are neither
 * the engine's RELEASED nor dotta's own DELETED), divergence (disk
 * against what dotta last deployed — the anchor, or the VWD blob for a
 * row it never deployed; compute_orphan_divergence). The three feed one
 * item: state (ORPHANED or RELEASED), divergence bits, on_filesystem.
 * RELEASED therefore has two sources that read identically downstream —
 * the lifecycle column, for the rows the consistency layer covers, and
 * the load-time observation, for the rows it does not.
 *
 * Each orphan is tagged with profile_enabled — whether its profile is in
 * the workspace's enabled set. It is a label, not a filter: every reader
 * sees every orphan, and apply's verbose breakdown ("N from disabled
 * profiles" / "N from enabled profiles") is its only consumer.
 */
static error_t *analyze_orphaned_files(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->profile_index);

    if (ws->orphan_file_count == 0) {
        return NULL;
    }

    /* profile → authority_cache_t for this pass. Keys borrow the rows'
     * arena-backed profile strings, which outlive it. */
    hashmap_t *authority_cache = hashmap_borrow(8);
    if (!authority_cache) {
        return ERROR(ERR_MEMORY, "Failed to create authority cache");
    }

    error_t *err = NULL;

    for (size_t i = 0; i < ws->orphan_file_count; i++) {
        const state_file_entry_t *state_entry = ws->orphan_files[i];

        const char *fs_path = state_entry->filesystem_path;
        const char *storage_path = state_entry->storage_path;
        const char *profile = state_entry->profile;

        bool profile_enabled = hashmap_has(ws->profile_index, profile);

        /* Single stat capture, reused for type verification, content
         * comparison, and metadata checks — eliminates redundant lstat
         * syscalls. One rule for every orphan, whatever its lifecycle.
         *
         * stat_valid tracks whether we have usable stat data:
         * - true: lstat succeeded, orphan_stat contains valid data
         * - false: lstat failed, orphan_stat is zeroed (unusable)
         */
        struct stat orphan_stat;
        bool on_filesystem;
        bool stat_valid = false;

        if (lstat(fs_path, &orphan_stat) != 0) {
            /* ENOENT: the orphan was already removed by hand — a reclaim.
             *
             * Anything else (EACCES, EIO, ELOOP, …): assume the file exists
             * but is inaccessible. We lack valid stat data, so divergence
             * cannot be computed and becomes UNVERIFIED below, so:
             * - Status shows [orphaned, unverified] (user visibility)
             * - Apply skips removal (can't verify what we can't stat)
             */
            on_filesystem = (errno != ENOENT);
            memset(&orphan_stat, 0, sizeof(orphan_stat));
        } else {
            on_filesystem = true;
            stat_valid = true;
        }

        workspace_state_t item_state = WORKSPACE_STATE_ORPHANED;
        divergence_type_t divergence = DIVERGENCE_NONE;

        if (state_entry->lifecycle == LIFECYCLE_RELEASED) {
            /* RELEASED by the engine: the path left its profile in Git — an
             * external commit, a pulled removal, a vanished branch — and the
             * consistency layer recorded it. No divergence computation
             * needed — we're not deleting this file.
             * It is left on the filesystem and its state entry retires.
             *
             * Presence is not consulted for the state — a row released
             * while its file is gone still reads RELEASED here — but
             * on_filesystem travels with the item and cleanup's verdict
             * phase checks it first, so an absent released row is a
             * reclaim there. The two orders agree on the outcome. */
            item_state = WORKSPACE_STATE_RELEASED;

        } else if (on_filesystem) {
            /* LIFECYCLE_DELETED needs no authority question: dotta committed
             * that deletion itself, so the profile's claim is not in doubt —
             * asking would find the blob gone by design and misread it as
             * external loss. Everything else asks Git. */
            orphan_authority_t authority = ORPHAN_AUTHORITY_BACKED;

            if (state_entry->lifecycle != LIFECYCLE_DELETED) {
                err = compute_orphan_authority(
                    ws->repo, authority_cache, profile, storage_path, &authority
                );
                if (err) {
                    break;
                }
            }

            if (authority == ORPHAN_AUTHORITY_LOST) {
                /* Git cannot back the file. Left on disk, row retires — so
                 * there is nothing a content comparison would decide. */
                item_state = WORKSPACE_STATE_RELEASED;

            } else {
                /* Divergence for a prunable orphan: disk against what dotta
                 * last deployed (the anchor; the VWD blob only for a row
                 * dotta never deployed).
                 *
                 * This enables status to predict apply behavior
                 * (cleanup_skip_reason maps the same bits to the skip):
                 * - DIVERGENCE_NONE -> Clean orphan, apply will prune
                 * - DIVERGENCE_CONTENT/TYPE -> Modified, apply will skip
                 * - DIVERGENCE_MODE/OWNERSHIP -> Metadata changed, apply will skip
                 * - DIVERGENCE_UNVERIFIED -> Cannot verify, apply will skip
                 * - WORKSPACE_STATE_RELEASED -> Git let go, apply releases
                 */
                if (stat_valid) {
                    divergence = compute_orphan_divergence(
                        ws, state_entry, fs_path, storage_path, profile, &orphan_stat
                    );
                } else {
                    /* Present but unstattable — nothing to compare against */
                    divergence = DIVERGENCE_UNVERIFIED;
                }

                if (authority == ORPHAN_AUTHORITY_UNVERIFIED) {
                    /* Git could not vouch for the path: skip the orphan
                     * until it can. */
                    divergence |= DIVERGENCE_UNVERIFIED;
                }
            }
        }
        /* else absent: ORPHANED with no divergence — a reclaim whatever Git
         * says, which keeps the planners' "absent ⇒ DIVERGENCE_NONE" rule. */

        err = workspace_add_diverged(
            ws,
            fs_path,
            storage_path,
            profile,
            NULL,               /* No old_profile for orphans */
            item_state,
            divergence,
            PATH_KIND_FILE,
            on_filesystem,
            profile_enabled,
            false               /* No profile change for orphans */
        );
        if (err) {
            err = error_wrap(err, "Failed to add orphaned/released file");
            break;
        }
    }

    hashmap_free(authority_cache, authority_cache_free);

    return err;
}

/**
 * Partition tracked_directories rows into the active slice and orphan slice
 *
 * Mirror of workspace_partition_files for tracked_directories. Loads the
 * directory snapshot via state_get_all_directories and walks it once to
 * populate both workspace partitions:
 *   - ws->active_dirs / ws->active_dir_count / ws->active_dir_index:
 *     in-scope ACTIVE rows (profile in enabled set, lifecycle ACTIVE).
 *   - ws->orphan_dirs / ws->orphan_dir_count: rows out-of-scope or with
 *     terminal lifecycle (INACTIVE / DELETED).
 *
 * manifest_reconcile (run upstream of workspace_load) has already synced
 * tracked_directories against current Git, so dir->lifecycle reflects current
 * Git truth — LIFECYCLE_INACTIVE / LIFECYCLE_DELETED are authoritative.
 *
 * Note: state_directory_entry_t never carries LIFECYCLE_RELEASED (file-only
 * lifecycle); the predicate uses (lifecycle != LIFECYCLE_ACTIVE) without
 * needing the file-side RELEASED branch.
 *
 * Lifetime: every pointer (active rows, orphan rows, both pointer arrays,
 * the snapshot rows themselves) lives in ws->arena. Only ws->active_dir_index
 * is heap-allocated (hashmap_borrow), freed in workspace_free.
 */
static error_t *workspace_partition_directories(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->arena);
    CHECK_NULL(ws->profile_index);

    state_directory_entry_t *snapshot = NULL;
    size_t snap_count = 0;

    error_t *err = state_get_all_directories(
        ws->state, ws->arena, &snapshot, &snap_count
    );
    if (err) {
        return error_wrap(err, "Failed to read tracked directories from state");
    }

    /* Active index always exists, even when empty. Sized to the snapshot
     * (worst case = every row is active). */
    ws->active_dir_index = hashmap_borrow(snap_count > 0 ? snap_count : 64);
    if (!ws->active_dir_index) {
        return ERROR(ERR_MEMORY, "Failed to create active directory index");
    }

    if (snap_count == 0) {
        return NULL;  /* active_dirs / orphan_dirs / counts left zero by calloc */
    }

    state_directory_entry_t **active_dirs = arena_calloc(
        ws->arena, snap_count, sizeof(*active_dirs)
    );
    const state_directory_entry_t **orphan_dirs = arena_calloc(
        ws->arena, snap_count, sizeof(*orphan_dirs)
    );
    if (!active_dirs || !orphan_dirs) {
        return ERROR(ERR_MEMORY, "Failed to allocate directory partition");
    }

    size_t active_count = 0;
    size_t orphan_count = 0;

    /* Partition state rows: in-scope active → ws->active_dirs, others → orphans */
    for (size_t i = 0; i < snap_count; i++) {
        state_directory_entry_t *row = &snapshot[i];

        bool profile_in_scope = hashmap_has(ws->profile_index, row->profile);
        bool lifecycle_terminal = (row->lifecycle != LIFECYCLE_ACTIVE);

        if (!profile_in_scope || lifecycle_terminal) {
            orphan_dirs[orphan_count++] = row;
            continue;
        }

        active_dirs[active_count++] = row;

        /* The map stores the mutable row pointer (workspace_advance_witness
         * patches in place); workspace_lookup_directory narrows it to const
         * for external callers. */
        err = hashmap_set(ws->active_dir_index, row->filesystem_path, row);
        if (err) {
            return error_wrap(err, "Failed to populate active directory index");
        }
    }

    /* Commit partition — only after every error path has returned. */
    ws->active_dirs = (active_count > 0) ? active_dirs : NULL;
    ws->active_dir_count = active_count;
    ws->orphan_dirs = (orphan_count > 0) ? orphan_dirs : NULL;
    ws->orphan_dir_count = orphan_count;

    return NULL;
}

/**
 * Analyze partitioned orphan directories
 *
 * Each entry in ws->orphan_dirs was rejected from active scope by
 * workspace_partition_directories: profile out of scope, or state
 * INACTIVE/DELETED. No skip checks here — every input is by construction an
 * orphan.
 *
 * Presence is the whole observation: no authority question is asked for a
 * directory. Directories have no blob-level identity in Git to lose (the
 * tracked_directories vocabulary has no RELEASED for exactly that reason —
 * see state_lifecycle_t), and a directory row is only ever removed empty,
 * so acting on a stale claim can cost the user nothing.
 *
 * Each orphan is tagged with profile_enabled — whether its profile is in
 * the workspace's enabled set. It is a label, not a filter: every reader
 * sees every orphan, and apply's verbose breakdown ("N from disabled
 * profiles" / "N from enabled profiles") is its only consumer.
 */
static error_t *analyze_orphaned_directories(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->profile_index);

    for (size_t i = 0; i < ws->orphan_dir_count; i++) {
        const state_directory_entry_t *row = ws->orphan_dirs[i];

        bool profile_enabled = hashmap_has(ws->profile_index, row->profile);
        bool on_filesystem = fs_exists(row->filesystem_path);

        error_t *err = workspace_add_diverged(
            ws,
            row->filesystem_path,       /* Already arena-allocated */
            row->storage_path,          /* Already arena-allocated */
            row->profile,
            NULL,                       /* No old_profile for orphans */
            WORKSPACE_STATE_ORPHANED,   /* State: in state, not in profile */
            DIVERGENCE_NONE,            /* Divergence: none */
            PATH_KIND_DIRECTORY,
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
 * Walks ws->active_files and compares each row against filesystem reality.
 *
 * Performance: O(N) where N = active row count. The row's VWD cache
 * (blob_oid, type, anchor, etc.) eliminates N+1 database queries.
 */
static error_t *analyze_files_divergence(workspace_t *ws) {
    CHECK_NULL(ws);

    for (size_t i = 0; i < ws->active_file_count; i++) {
        state_file_entry_t *row = ws->active_files[i];

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
                (hashmap_get(ws->active_file_index, full_path) != NULL) ||
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
                    PATH_KIND_FILE,
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

    /* Iterate the active directory partition, filtering by profile per
     * outer iteration. The outer loop runs in scope_enabled order — the
     * user's enabled-precedence position — so when two profiles share an
     * ancestor directory, the highest-precedence profile scans first and
     * claims new files via ws->diverged_index (subsequent profiles' scans
     * skip the entry via the dedup check in scan_directory_for_untracked).
     *
     * The dirs.count × ws->profiles->count strcmp filter below is trivially
     * negligible (P ≤ 10, D ≤ 10²) and replaces a per-profile SQL query. */
    state_directories_t dirs = workspace_directories(ws);

    for (size_t p = 0; p < ws->profiles->count; p++) {
        const char *profile = ws->profiles->items[p];

        /* Resolve the profile-specific ruleset (memoised in the builder).
         *
         * Fatal on failure: scanning a profile without its ignore rules
         * risks reporting genuinely ignored files as untracked, which the
         * user could then `dotta add` by accident. A corrupt .dottaignore
         * must surface so the user can fix it. */
        const gitignore_ruleset_t *profile_rules = NULL;
        err = ignore_rules_for_profile(ignore_rules, profile, &profile_rules);
        if (err) {
            ignore_rules_free(ignore_rules);
            source_filter_free(source_filter);
            return error_wrap(
                err, "Failed to load ignore patterns for profile '%s'", profile
            );
        }

        /* Per-profile ancestor-suppression cursor — resets per outer
         * iteration. Profiles with shared-ancestor directories use
         * independent ignore rules, so each profile's tree must scan from
         * a clean cursor. */
        const char *last_scanned = NULL;

        for (size_t i = 0; i < dirs.count; i++) {
            const state_directory_entry_t *row = dirs.entries[i];

            /* Filter to this profile's rows. dirs is in (filesystem_path)
             * order from the snapshot; rows for this profile remain in
             * that relative order, so the ancestor-first invariant the
             * last_scanned suppression depends on holds within each
             * profile slice. */
            if (strcmp(row->profile, profile) != 0) continue;

            /* Skip directories already classified as orphaned by prior
             * analysis (in-memory stale detection path: state still
             * ACTIVE, but analyze_orphaned_directories has flagged the
             * row against current Git). Scanning such directories would
             * report [new] files that are actually [released]. */
            if (hashmap_get(ws->diverged_index, row->filesystem_path) != NULL) {
                continue;
            }

            /* State directory entries contain:
             * - filesystem_path: Already resolved with target (VWD principle)
             * - storage_path: Portable path for storage
             */

            /* Use filesystem path directly from state (already resolved) */
            const char *filesystem_path = row->filesystem_path;

            /* Check if directory still exists */
            if (!fs_exists(filesystem_path)) continue;

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
                row->storage_path,         /* Portable storage path */
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
 * - DIVERGENCE_UNVERIFIED: Directory could not be stat'd (inaccessible)
 *
 * ARCHITECTURE: Uses state (VWD) instead of metadata (Git) for directory
 * resolution. State contains filesystem_path already resolved with target,
 * enabling correct divergence detection for custom/ prefix directories.
 *
 * Consumes ws->active_dirs from workspace_partition_directories — every input
 * is by construction profile_in_scope AND lifecycle ACTIVE. No skip checks.
 */
static error_t *analyze_directory_metadata_divergence(workspace_t *ws) {
    CHECK_NULL(ws);

    error_t *err = NULL;

    /* Iterate the internal slice, not workspace_directories(): the witness
     * accumulator below needs the mutable row, same as the file loop in
     * workspace_analyze_files. */
    for (size_t i = 0; i < ws->active_dir_count; i++) {
        state_directory_entry_t *row = ws->active_dirs[i];

        /* State directory entries contain:
         * - filesystem_path: Already resolved with target (VWD principle)
         * - storage_path: Portable path
         * - profile: Source profile
         * - mode, owner, group: Expected metadata
         *
         * All strings are arena-allocated — no explicit free needed. */
        const char *filesystem_path = row->filesystem_path;
        const char *storage_path = row->storage_path;
        const char *profile = row->profile;

        /* Stat directory to get current metadata
         *
         * Use lstat() for both existence and type checking:
         * - ENOENT: Directory truly deleted
         * - Other errno: Inaccessible — state undeterminable, not absent
         * - Success + !S_ISDIR: Type changed (file, symlink - including broken ones)
         * - Success + S_ISDIR: Actual directory, check metadata  */
        struct stat dir_stat;
        if (lstat(filesystem_path, &dir_stat) != 0) {
            if (errno == ENOENT) {
                /* Absent path: witness-gated classification. A witnessed
                 * directory was deleted by the user (update propagates the
                 * removal); a never-witnessed one is a ghost — apply's job
                 * is to create it, never to commit a phantom deletion. */
                err = workspace_add_diverged(
                    ws,
                    filesystem_path,
                    storage_path,
                    profile,
                    NULL,                     /* No old_profile for directories */
                    classify_absent(row->observed_at),
                    DIVERGENCE_NONE,          /* Divergence: none (path is absent) */
                    PATH_KIND_DIRECTORY,
                    false,                    /* on_filesystem (absent) */
                    true,                     /* profile_enabled */
                    false                     /* No profile change */
                );

                if (err) {
                    return error_wrap(
                        err, "Failed to record absent directory '%s'",
                        filesystem_path
                    );
                }
                continue;  /* Successfully recorded, check next directory */
            }

            /* Inaccessible, not absent: record the uncertainty rather
             * than dropping the row, which left status reporting a clean
             * workspace for a path it had just failed to read. Same
             * three-way policy as the file rows. */
            err = workspace_add_diverged(
                ws,
                filesystem_path,
                storage_path,
                profile,
                NULL,                     /* No old_profile for directories */
                WORKSPACE_STATE_DEPLOYED,
                DIVERGENCE_UNVERIFIED,    /* Divergence: state undeterminable */
                PATH_KIND_DIRECTORY,
                true,                     /* on_filesystem (assumed present) */
                true,                     /* profile_enabled */
                false                     /* No profile change */
            );

            if (err) {
                return error_wrap(
                    err, "Failed to record unverifiable directory '%s'",
                    filesystem_path
                );
            }
            continue;  /* Successfully recorded, check next directory */
        }

        /* Presence flush accumulator — mirror of the file side's CMP_EQUAL
         * anchor flush. The lstat above just observed the path in scope
         * (any type counts, same semantics as the projection probe); if
         * the row carries no witness yet, queue it for the batched write
         * in workspace_flush_updates. Closes the "user created the path
         * after scope entry" gap with the mechanism files already use. */
        if (row->observed_at == 0) {
            workspace_record_witness_update(ws, row);
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
                PATH_KIND_DIRECTORY,
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
            row->mode,   /* Expected mode from state */
            row->owner,  /* Expected owner from state */
            row->group,  /* Expected group from state */
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
                PATH_KIND_DIRECTORY,
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
    for (size_t i = 0; i < ws->active_file_count; i++) {
        const state_file_entry_t *row = ws->active_files[i];
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
             * analyze_file_divergence Phase 2. */
            struct stat enc_stat;
            bool on_filesystem = (lstat(row->filesystem_path, &enc_stat) == 0);

            workspace_state_t item_state = on_filesystem
                ? WORKSPACE_STATE_DEPLOYED
                : classify_absent(row->anchor.observed_at);

            err = workspace_add_diverged(
                ws,
                row->filesystem_path,
                storage_path,
                profile,
                NULL,
                item_state,
                DIVERGENCE_ENCRYPTION, /* Divergence: encryption policy violated */
                PATH_KIND_FILE,
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
 * Partition state file rows into the active slice and orphan slice
 *
 * Loads the manifest snapshot via state_get_all_files and walks it once to
 * produce both workspace partitions:
 *   - ws->active_files / ws->active_file_count / ws->active_file_index:
 *     in-scope ACTIVE rows (profile in enabled set, lifecycle ACTIVE).
 *   - ws->orphan_files / ws->orphan_file_count: rejected rows (out-of-scope
 *     profile or terminal lifecycle: INACTIVE/DELETED/RELEASED).
 *
 * The partition is the single source of truth for "is this row in scope?".
 * analyze_orphaned_files consumes ws->orphan_files; analyses over the active
 * set walk ws->active_files. No defensive cleanup on error: workspace_free
 * is the single cleanup authority.
 *
 * Drift repair is handled upstream by workspace_load's manifest_reconcile
 * call, so active rows read here are current with Git by construction:
 * reconcile projects every enabled profile at HEAD, which is precisely
 * the active slice. The orphan slice holds the rows that projection does
 * not touch — a disabled profile's rows, and non-ACTIVE rows whose path
 * is not in any enabled HEAD — so for them analyze_orphaned_files
 * observes Git authority itself.
 *
 * Lifetime: every pointer (active rows, orphan rows, both pointer arrays,
 * the snapshot rows themselves) lives in ws->arena. Only ws->active_file_index
 * is heap-allocated (hashmap_borrow), freed in workspace_free.
 *
 * Performance: O(M) where M = manifest rows. One pass, no probes.
 */
static error_t *workspace_partition_files(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->arena);
    CHECK_NULL(ws->profile_index);

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
    ws->active_file_index = hashmap_borrow(snap_count > 0 ? snap_count : 64);
    if (!ws->active_file_index) {
        return ERROR(ERR_MEMORY, "Failed to create active file index");
    }

    if (snap_count == 0) {
        return NULL;  /* active_files / orphan_files / counts left zero by calloc */
    }

    /* Allocate worst-case arrays (both partitions share the snapshot — the
     * row buffer never gets duplicated). */
    state_file_entry_t **active_files = arena_calloc(
        ws->arena, snap_count, sizeof(*active_files)
    );
    const state_file_entry_t **orphan_files = arena_calloc(
        ws->arena, snap_count, sizeof(*orphan_files)
    );
    if (!active_files || !orphan_files) {
        return ERROR(ERR_MEMORY, "Failed to allocate file partition");
    }

    size_t active_count = 0;
    size_t orphan_count = 0;

    /* Partition state rows: in-scope active → ws->active_files, others → orphans */
    for (size_t i = 0; i < snap_count; i++) {
        state_file_entry_t *row = &snapshot[i];

        bool profile_in_scope = hashmap_has(ws->profile_index, row->profile);

        /* Lifecycle terminal phases are rejected from the active slice and
         * surfaced to orphan detection. */
        bool lifecycle_terminal = (row->lifecycle != LIFECYCLE_ACTIVE);

        if (!profile_in_scope || lifecycle_terminal) {
            /* Rejected: surface to orphan analysis.
             *   - Out-of-scope profile: disabled or branch deleted; tagged
             *     via profile_enabled in analyze_orphaned_files.
             *   - Lifecycle terminal: INACTIVE/DELETED/RELEASED. Loss of
             *     authority is read from row->lifecycle, or observed
             *     against Git, inside analyze_orphaned_files. */
            orphan_files[orphan_count++] = row;
            continue;
        }

        active_files[active_count++] = row;

        /* Index by row pointer directly: the active array is allocated at
         * load time and never grows, so pointers into it are stable for
         * the workspace lifetime — no idx+1 encoding needed. */
        err = hashmap_set(ws->active_file_index, row->filesystem_path, row);
        if (err) {
            return error_wrap(err, "Failed to populate active file index");
        }
    }

    /* Commit partition — only after every error path has returned. */
    ws->active_files = active_files;
    ws->active_file_count = active_count;
    ws->orphan_files = (orphan_count > 0) ? orphan_files : NULL;
    ws->orphan_file_count = orphan_count;

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
     * manifest_reconcile detects drift per profile and, on drift, projects
     * every enabled profile at HEAD: additions are projected, moved blobs
     * advanced, rows that left are LIFECYCLE_RELEASED, and a path that
     * returned to Git is reactivated. The deployment anchor is preserved by
     * the UPSERT across this repair, so analyze_file_divergence can
     * classify staleness from the persistent (anchor, blob_oid) pair
     * regardless of whether reconcile actually ran on this invocation.
     *
     * Transaction scoping is internal to manifest_reconcile: uses the
     * caller's transaction when locked, opens a scoped BEGIN IMMEDIATE
     * otherwise. Common case (no drift) is O(P) and zero writes. */
    err = manifest_reconcile(repo, state, arena, mounts, NULL, NULL);
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

    /* Partition file and directory snapshots into active + orphan slices.
     * Both partitions populate workspace fields directly; consumers read
     * via workspace_files() / workspace_directories() and the *_index
     * accessors. Drift was repaired upstream by manifest_reconcile, so
     * the snapshots reflect current Git truth by construction. */
    err = workspace_partition_files(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to partition file slice");
    }

    err = workspace_partition_directories(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to partition directory slice");
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

    /* Analyze orphaned state entries (files + directories) */
    if (resolved_opts.analyze_orphans) {
        err = analyze_orphaned_files(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze orphaned files");
        }

        err = analyze_orphaned_directories(ws);
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
state_files_t workspace_files(const workspace_t *ws) {
    if (!ws) return (state_files_t){ 0 };
    return (state_files_t){
        .entries = (const state_file_entry_t *const *) ws->active_files,
        .count = ws->active_file_count,
    };
}

/**
 * Look up an active row by filesystem path
 *
 * O(1) hashmap probe over the active slice. The map's value is a
 * mutable row pointer (workspace_advance_anchor patches in place);
 * external callers receive a const view via narrowing cast.
 */
const state_file_entry_t *workspace_lookup_file(
    const workspace_t *ws,
    const char *filesystem_path
) {
    if (!ws || !filesystem_path) return NULL;
    return hashmap_get(ws->active_file_index, filesystem_path);
}

/**
 * Get the active in-scope state directory slice
 *
 * The cast adds const at both pointer levels — safe per the C standard's
 * "T**  → const T *const *" rule (no diagnostic required).
 */
state_directories_t workspace_directories(const workspace_t *ws) {
    if (!ws) return (state_directories_t){ 0 };
    return (state_directories_t){
        .entries = (const state_directory_entry_t *const *) ws->active_dirs,
        .count = ws->active_dir_count,
    };
}

/**
 * Look up an active directory row by filesystem path
 *
 * O(1) hashmap probe over the active directory slice. The map's value is a
 * mutable row pointer (workspace_advance_witness patches in place);
 * external callers receive a const view via narrowing cast.
 */
const state_directory_entry_t *workspace_lookup_directory(
    const workspace_t *ws,
    const char *filesystem_path
) {
    if (!ws || !filesystem_path) return NULL;
    return hashmap_get(ws->active_dir_index, filesystem_path);
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
             *   TYPE > CONTENT > STALE > MODE/OWNERSHIP/ENCRYPTION
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

            if (item->divergence & DIVERGENCE_STALE) {
                /* Git moved past the deployed blob. Alone it is apply-side
                 * work — the same CYAN as [undeployed], nothing of the
                 * user's is overwritten; next to [modified] it names a
                 * conflict and the primary tag's colour stands. */
                if (tag_count == 0) {
                    *color_out = OUTPUT_COLOR_CYAN;
                }
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "stale";
                }
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
            if (!item->on_filesystem) {
                /* Gone from disk already: apply reclaims the row and
                 * removes nothing. Cyan, the receipt's colour for a
                 * reclaim — no action on the user's files is coming.
                 * Checked before the divergence arms because an absent
                 * orphan carries DIVERGENCE_NONE by construction, so they
                 * would only report it clean and promise a prune. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "absent";
                }
                *color_out = OUTPUT_COLOR_CYAN;

            } else if (item->divergence & DIVERGENCE_UNVERIFIED) {
                /* Cannot verify state - could be large file, missing key, I/O error, etc.
                 * Conservative: apply skips it (CLEANUP_SKIP_UNVERIFIED,
                 * ranked first there as it is here — one item, one name). */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "unverified";
                }
                *color_out = OUTPUT_COLOR_MAGENTA;

            } else if (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE)) {
                /* Content or type divergence - blocking issue
                 * Apply skips it (cleanup_skip_reason: MODIFIED / TYPE_CHANGED). */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "modified";
                }
                *color_out = OUTPUT_COLOR_RED;

            } else if (item->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
                /* Metadata divergence only - warning level
                 * File content matches but permissions/ownership changed.
                 * Apply skips it (cleanup_skip_reason: MODE_CHANGED). */
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
            /* The path left its profile in Git — released from management.
             * File left on filesystem, state entry will be cleaned up. */
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "released";
            }
            *color_out = OUTPUT_COLOR_MAGENTA;

            if (!item->on_filesystem) {
                /* Nothing is left to leave on disk: apply retires the row
                 * and reports a reclaim, so the display says so too. The
                 * ORPHANED arm reads the same flag for the same reason. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "absent";
                }
                *color_out = OUTPUT_COLOR_CYAN;
            }

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
 * state_update_anchor and assigns the canonical post-write anchor
 * (returned by SQL RETURNING) into the caller's row. The SQL UPDATE is
 * the single specification of preserve-on-zero / monotonic-once-set
 * rules; this function holds none of that logic.
 *
 * The row is borrowed from ws->active_files. The workspace owns that
 * storage as mutable (state_file_entry_t **active_files); the const
 * decoration on the parameter is a public-API guard against mutation by
 * non-anchor callers — internally we exercise the workspace's mutability
 * privilege to write the resolved anchor in place.
 */
error_t *workspace_advance_anchor(
    workspace_t *ws,
    const state_file_entry_t *row,
    const deployment_anchor_t *anchor
) {
    CHECK_NULL(ws);
    CHECK_NULL(row);
    CHECK_NULL(anchor);

    deployment_anchor_t resolved;
    error_t *err = state_update_anchor(
        ws->state, row->filesystem_path, anchor, &resolved
    );
    if (err) return err;

    ((state_file_entry_t *) row)->anchor = resolved;
    return NULL;
}

/**
 * Advance a tracked directory's witness with in-memory consistency
 *
 * Directory sibling of workspace_advance_anchor and the single
 * workspace-scope writer of tracked_directories.observed_at: persists via
 * state_update_witness, then patches the snapshot row so DB and memory
 * agree for downstream readers in the same run.
 *
 * Monotonicity is the SQL WHERE clause's job (observed_at = 0), so a row
 * already witnessed is a no-op in the database. The in-memory assignment
 * is unconditional but harmless for the same reason — callers gate on
 * row->observed_at == 0 before advancing.
 *
 * The row is borrowed from ws->active_dirs, which the workspace owns as
 * mutable; the const decoration on the parameter is a public-API guard
 * against mutation by non-witness callers.
 */
error_t *workspace_advance_witness(
    workspace_t *ws,
    const state_directory_entry_t *row,
    time_t observed_at
) {
    CHECK_NULL(ws);
    CHECK_NULL(row);

    error_t *err = state_update_witness(
        ws->state, row->filesystem_path, observed_at
    );
    if (err) return err;

    ((state_directory_entry_t *) row)->observed_at = observed_at;
    return NULL;
}

/**
 * Flush accumulated anchor and witness updates to the state database
 *
 * Anchor half: advances the deployment anchor for entries that hit
 * CMP_EQUAL on the slow path during analyze_file_divergence. The anchor
 * carries both the fast-path stat triple and the blob_oid it confirms —
 * persisting them lets the next run short-circuit (fast path) or tag
 * STALE directly (fast path with Git-advanced blob_oid). deployed_at is
 * passed as 0 so state_update_anchor preserves the row's existing
 * timestamp — this flush confirms an observation but does not create a
 * new deployment lifecycle event (apply owns that).
 *
 * Witness half: stamps tracked directories observed during directory
 * analysis whose row carried no witness.
 *
 * Both route through their snapshot-write API — the accumulators already
 * carry the row pointers recorded at analyze time, which is exactly what
 * those wrappers expect. One such API per table; no parallel inline path.
 *
 * Begins its own transaction only when state isn't already in one
 * (status/diff/sync). Apply always passes state already-in-transaction.
 */
error_t *workspace_flush_updates(workspace_t *ws) {
    CHECK_NULL(ws);

    if (ws->anchor_update_count == 0 && ws->witness_update_count == 0) {
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
        deployment_anchor_t input = {
            .blob_oid    = update->blob_oid,
            .deployed_at = 0,      /* preserve — flush is an observation, not a deploy */
            .observed_at = now,    /* monotonic CASE in SQL preserves any prior observation stamp */
            .stat        = update->stat,
        };
        error_t *err = workspace_advance_anchor(ws, update->row, &input);
        if (err) {
            if (needs_transaction) {
                state_rollback(ws->state);
            }
            return error_wrap(
                err, "Failed to flush anchor for '%s'",
                update->row->filesystem_path
            );
        }
    }

    /* Witness advances queued during directory analysis. Routes through
     * workspace_advance_witness for the same reason the loop above routes
     * through workspace_advance_anchor: one snapshot-write API per table,
     * no parallel inline path. */
    for (size_t i = 0; i < ws->witness_update_count; i++) {
        const state_directory_entry_t *row = ws->witness_updates[i];

        error_t *err = workspace_advance_witness(ws, row, now);
        if (err) {
            if (needs_transaction) {
                state_rollback(ws->state);
            }
            return error_wrap(
                err, "Failed to flush witness for '%s'", row->filesystem_path
            );
        }
    }

    if (needs_transaction) {
        error_t *err = state_commit(ws->state);
        if (err) {
            /* A failed COMMIT leaves the transaction open; release it so
             * the next scoped writer (sync's post-phase reconcile runs
             * right after this flush) does not inherit it. */
            state_rollback(ws->state);
            return error_wrap(
                err, "Failed to commit anchor flush transaction"
            );
        }
    }

    ws->anchor_update_count = 0;
    ws->witness_update_count = 0;

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

    /* Free the anchor and witness update arrays (row pointers are borrowed
     * from ws->arena snapshot) */
    free(ws->anchor_updates);
    free(ws->witness_updates);

    /* Free indices (values are borrowed, so pass NULL for value free function).
     * active_file_index / active_dir_index values are state-row pointers into
     * ws->arena — also borrowed. */
    hashmap_free(ws->profile_index, NULL);
    hashmap_free(ws->diverged_index, NULL);
    hashmap_free(ws->active_file_index, NULL);
    hashmap_free(ws->active_dir_index, NULL);

    /* ws->active_files is arena-allocated (pointer array into the snapshot);
     * the caller's arena releases it when destroyed. ws->arena is
     * borrowed — never destroyed here. */

    free(ws);
}
