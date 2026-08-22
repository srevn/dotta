/**
 * workspace.c - Workspace abstraction implementation
 *
 * The join of the view (Git), the record (.git/dotta.db) and the filesystem.
 * Detects and categorizes divergence to prevent data loss and enable safe
 * operations.
 *
 * The expected side is computed, never stored: every load builds the manifest
 * (core/manifest.h) from the enabled profiles at HEAD — both kinds, one row per
 * path, precedence resolved — so an external commit, a pull, a revert or a scope
 * change is simply in the next view. Nothing repairs a cache because there is
 * none. The record dotta keeps of each path (the anchors table: what it deployed
 * or observed there, when, with what stat) is loaded beside the view and paired
 * with it by path. It is dotta's own and nothing repairs it either: the analyses
 * read it as the base of every three-way question, and the two writers here
 * (workspace_observe, workspace_anchor) advance it only after a live look at
 * disk. A record whose path the view lacks is an orphan, and the orphan analysis
 * asks Git — the only authority that knows — why it is one.
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
#include "core/metadata.h"
#include "core/policy.h"
#include "core/scope.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/source.h"
#include "utils/privilege.h"

/**
 * Pending confirmation (internal type)
 *
 * Accumulated during analyze_file_divergence() when the slow path confirms
 * CMP_EQUAL — disk is row->blob_oid. The verified stat should be persisted beside
 * that blob so the next run can both short-circuit via the fast-path stat and,
 * if Git advances blob_oid in the meantime, classify the file as stale from the
 * fast path instead of re-hashing.
 *
 * The blob is the row's: a confirmation binds the stat to the blob the row expected
 * when disk was found equal to it, and state_confirm reads it from the row it
 * is handed — a stat triple without a blob is meaningless, and the row is the
 * one the stat was verified against.
 *
 * The row pointer is borrowed from ws->active_files (workspace lifetime). Carrying
 * the row directly lets the flush call state_confirm with the row itself and
 * patch the record by the row's path.
 */
typedef struct {
    const manifest_row_t *row;       /* Active row this confirmation targets (borrowed) */
    stat_cache_t stat;               /* Captured stat triple (fast-path proof) */
} confirmation_t;

/**
 * Workspace structure
 *
 * Holds the view, the record and the divergence analysis over both. Uses hashmaps
 * for O(1) lookups during analysis.
 */
struct workspace {
    git_repository *repo;                        /* Borrowed reference */
    arena_t *arena;                              /* Borrowed; backs every workspace-lifetime string */

    /* The view: every enabled profile at HEAD, built by the partition and owned
     * here (the rows are the arena's; manifest_free releases the index). Rows
     * are read-only for the whole run — the record a writer patches lives in
     * the anchors snapshot below, never in a row. The view's own index answers
     * workspace_lookup: a path is one managed thing, and every lookup tests
     * row->type for the kind it wants. */
    manifest_t *manifest;                        /* Owned; freed in workspace_free */

    /* Active slices, both kinds, each in filesystem_path order — the view's rows
     * split by kind and sorted, so deploy's parent-before-child walk and the
     * untracked scan's ancestor suppression see prefix order. Pointer arrays
     * into the view (arena-allocated). */
    const manifest_row_t **active_files;         /* Active file rows (arena-allocated array) */
    size_t active_file_count;                    /* Number of active file rows */
    const manifest_row_t **active_dirs;          /* Active directory rows (arena-allocated array) */
    size_t active_dir_count;                     /* Number of active directory rows */

    /* The record: every anchor, snapshot at load in filesystem_path order and
     * indexed by path. Values are mutable — workspace_observe and workspace_anchor
     * patch a record in place (or create one in the arena and index it) so every
     * later reader in the run sees the post-write value. */
    anchor_t *anchors;                           /* Arena snapshot from state_get_all_anchors */
    size_t anchor_count;                         /* Number of anchors in the snapshot */
    hashmap_t *anchor_index;                     /* fs_path → anchor_t * (heap-allocated) */

    /* Orphans: the records whose path the view lacks, in the snapshot's path
     * order. Read-only — no row names an orphan's path, so no writer ever reaches
     * one; the orphan analysis asks Git why each is here. */
    const anchor_t **orphans;                    /* Arena-allocated array into the snapshot */
    size_t orphan_count;                         /* Number of orphans */

    /* State and profile scope */
    state_t *state;                              /* The record's handle (borrowed from caller) */
    const string_array_t *profiles;              /* Borrowed; valid for workspace lifetime */
    hashmap_t *profile_index;                    /* Maps profile -> NULL (membership set, O(1) lookup) */

    /* Content cache for encrypted blob reads during divergence analysis */
    content_cache_t *content_cache;              /* Borrowed — NOT freed in workspace_free */

    /* Divergence tracking.
     *
     * The diverged array grows via realloc as workspace_add_diverged appends
     * items during analysis, so pointers into it would dangle on growth.
     * diverged_index stores (idx+1) cast to void* and decodes back to the array
     * index at lookup time. The +1 disambiguates idx=0 from hashmap_get's "absent
     * key" return value (which is also NULL). */
    workspace_item_t *diverged;                  /* Diverged items (files + directories) */
    size_t diverged_count;                       /* Number of diverged items */
    size_t diverged_capacity;                    /* Allocated capacity of diverged array */
    hashmap_t *diverged_index;                   /* Maps filesystem_path -> array index+1 (as void*) */

    /* Confirmations accumulated during divergence analysis */
    confirmation_t *confirmations;               /* Pending slow-path confirmations (owned) */
    size_t confirmation_count;                   /* Number of pending confirmations */
    size_t confirmation_capacity;                /* Allocated capacity of confirmations array */

    /* Observations accumulated during analysis.
     *
     * Rows of either kind found on disk with no record. An observation needs
     * only the row — the timestamp is the flush's; a confirmation also carries
     * the stat it confirmed, hence the richer element type above. */
    const manifest_row_t **observations;         /* Rows borrowed from the active slices (array owned) */
    size_t observation_count;                    /* Number of pending observations */
    size_t observation_capacity;                 /* Allocated capacity of observations array */

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

    /* Build profile membership set for O(1) scope checks. Values are NULL — this
     * is a pure name set, not a value map. */
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
 * Data-centric approach: Accepts values directly instead of structs, enabling
 * use with both manifest rows (manifest_row_t) and metadata (metadata_item_t)
 * without conversion. This eliminates Git loads for files (uses the row's fields)
 * while preserving metadata functionality for directories.
 *
 * @param expected_mode Expected permission mode (0 = skip mode check, no metadata
 *                      tracked)
 * @param expected_owner Expected owner username (NULL = skip owner check)
 * @param expected_group Expected group name (NULL = skip group check)
 * @param st File stat data (must not be NULL, pre-captured by caller)
 * @param out_mode_differs Output flag for mode divergence (must not be NULL)
 * @param out_ownership_differs Output flag for ownership divergence (must not
 *                              be NULL)
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
                /* getpwuid failed - orphaned UID or system error Treat as
                 * divergence: unknown ≠ expected (security-first) */
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
                /* getgrgid failed - orphaned GID or system error Treat as
                 * divergence: unknown ≠ expected (security-first) */
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
 * Every string is borrowed for the workspace's lifetime: a row's (the view, arena),
 * a record's (the anchors snapshot, arena), the untracked scan's arena copies,
 * or — the profile of an untracked item — the enabled set's, which the scope
 * keeps alive past workspace_free by contract. Nothing is copied here.
 *
 * @param ws Workspace context (must not be NULL)
 * @param filesystem_path Target path on filesystem (must not be NULL)
 * @param storage_path Path in profile (can be NULL for directories)
 * @param profile Source profile name — every producer passes one (a row's, a
 *                record's, or the enabled set's)
 * @param old_profile The record's profile when it differs from the row's (can
 *                    be NULL)
 * @param state Where the item exists (deployed/undeployed/etc.)
 * @param divergence What's wrong with it (bit flags, can combine)
 * @param item_kind FILE or DIRECTORY (explicit type)
 * @param on_filesystem Exists on actual filesystem
 * @param profile_enabled Is source profile in enabled list?
 * @param profile_changed Has owning profile changed vs the record?
 */
static error_t *workspace_add_diverged(
    workspace_t *ws,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    const char *old_profile,
    workspace_state_t state,
    divergence_type_t divergence,
    path_kind_t item_kind,
    bool on_filesystem,
    bool profile_enabled,
    bool profile_changed
) {
    CHECK_NULL(ws);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(profile);

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

    /* Borrow every string — callers pass workspace-lifetime pointers (see the
     * doc above); the casts discard the const the producers' read-only views
     * carry. */
    entry->filesystem_path = (char *) filesystem_path;
    entry->storage_path = (char *) storage_path;
    entry->profile = (char *) profile;
    entry->old_profile = (char *) old_profile;

    entry->state = state;
    entry->divergence = divergence;
    entry->item_kind = item_kind;
    entry->on_filesystem = on_filesystem;
    entry->profile_enabled = profile_enabled;
    entry->profile_changed = profile_changed;

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
 * Record a confirmation for later flushing
 *
 * Called from analyze_file_divergence() when the slow path confirms CMP_EQUAL.
 * Accumulates the row and the stat it was verified with so
 * workspace_flush_updates() can persist them via state_confirm(). The blob the
 * stat binds to is the row's — disk was found equal to it.
 *
 * OOM asymmetry — returns void on realloc failure. Every other path in workspace
 * analysis propagates ERR_MEMORY; this one deliberately does not. The confirmation
 * is a performance optimization — it converts the NEXT slow-path CMP_EQUAL into
 * a fast-path short-circuit — and, for a record carrying a prune order, the write
 * that voids the order; neither is a correctness invariant of the current analysis
 * (which is already complete by the time this is called). Dropping the record
 * on realloc failure:
 *   - Preserves the caller's already-correct divergence result.
 *   - Self-heals on the next status: the slow-path CMP_EQUAL re-confirms and
 *     re-records the confirmation, and a fast-path hit on an ordered record queues
 *     it again (assuming memory pressure has cleared).
 *   - Never produces an incorrect classification — worst case is one extra
 *     slow-path verification per dropped record.
 * Failing here to surface OOM would abort a workspace load that had already
 * succeeded in every respect that affects user-visible output — strictly worse
 * UX for zero correctness gain.
 *
 * @param ws Workspace (must not be NULL)
 * @param row Active row disk was found equal to (borrowed; workspace lifetime)
 * @param st Verified filesystem stat
 */
static void workspace_record_confirmation(
    workspace_t *ws,
    const manifest_row_t *row,
    const struct stat *st
) {
    if (ws->confirmation_count >= ws->confirmation_capacity) {
        size_t new_cap = ws->confirmation_capacity
                       ? ws->confirmation_capacity * 2 : 16;

        confirmation_t *new_arr = realloc(
            ws->confirmations,
            new_cap * sizeof(confirmation_t)
        );
        if (!new_arr) return;

        ws->confirmations = new_arr;
        ws->confirmation_capacity = new_cap;
    }

    ws->confirmations[ws->confirmation_count++] = (confirmation_t){
        .row = row,
        .stat = stat_cache_from_stat(st),
    };
}

/**
 * Record an observation for later flushing
 *
 * Sibling of workspace_record_confirmation for the path with no record: analysis
 * found it on disk, either kind, and dotta has never observed it in scope. Only
 * the row is accumulated — the observation timestamp is the flush's.
 *
 * Same OOM asymmetry as the confirmation recorder, for the same reason: a dropped
 * observation costs no correctness, only a deferral to the next observation event
 * (next flush, apply's post-deploy pass), each of which re-derives it from a
 * live lstat.
 *
 * @param ws Workspace (must not be NULL)
 * @param row Active row found on disk without a record (borrowed; workspace
 *            lifetime)
 */
static void workspace_record_observation(
    workspace_t *ws,
    const manifest_row_t *row
) {
    if (!ws || !row) return;

    if (ws->observation_count >= ws->observation_capacity) {
        size_t new_cap = ws->observation_capacity
                       ? ws->observation_capacity * 2 : 16;

        const manifest_row_t **new_arr = realloc(
            ws->observations,
            new_cap * sizeof(*new_arr)
        );
        if (!new_arr) return;

        ws->observations = new_arr;
        ws->observation_capacity = new_cap;
    }

    ws->observations[ws->observation_count++] = row;
}

/**
 * Record-gated absence classification — the single decision for every absent
 * managed path, file or directory.
 *
 * A record exists iff dotta has lstat-confirmed the path on disk in scope
 * (observed_at is never zero on one). No record means there is no filesystem
 * obligation, so absence is UNDEPLOYED (apply's job: create it) — never DELETED
 * (update's job: commit the deletion and propagate it to every machine). A path
 * once observed that is now missing was deleted.
 */
static workspace_state_t classify_absent(const anchor_t *anchor) {
    return anchor ? WORKSPACE_STATE_DELETED
                  : WORKSPACE_STATE_UNDEPLOYED;
}

/**
 * Analyze divergence for a single active row
 *
 * All expected state (blob_oid, type, mode, etc.) is in the view row — no database
 * queries, no Git; the record dotta keeps of the path is paired with it from
 * the anchors snapshot.
 *
 * Content is judged three-way, with the deployment anchor as base (see Phase
 * 1): DIVERGENCE_STALE says Git moved past the blob dotta last deployed,
 * DIVERGENCE_CONTENT says disk left it. Each is a verdict in its own right —
 * STALE without CONTENT is apply-side work that overwrites nothing of the user's;
 * CONTENT without STALE is a local edit Git has not raced; both together is a
 * conflict.
 *
 * Reassignment is the same pairing read on the profile axis: the record says
 * who deployed the disk content, the row says who owns the path now, and the
 * two differing is a state — "disk holds what A deployed; B owns the path now"
 * — that apply acknowledges by rewriting the record (the adoption loop for a
 * clean row, the deployment itself for a stale one). Only an owned record
 * qualifies: an observed or confirmed record that dotta never deployed names
 * the row the path was first seen under, not a deployer, and apply adopts such
 * a path rather than acknowledging it.
 *
 * @param ws Workspace (must not be NULL)
 * @param row Active view row (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *analyze_file_divergence(
    workspace_t *ws,
    const manifest_row_t *row
) {
    CHECK_NULL(ws);
    CHECK_NULL(row);

    const char *fs_path = row->filesystem_path;
    const char *storage_path = row->storage_path;
    const char *profile = row->profile;

    /* The record dotta keeps of this path, if any. NULL means dotta has never
     * observed the path on disk in scope: no base for the content question, no
     * fast path, and absence reads UNDEPLOYED. */
    const anchor_t *anchor = workspace_get_anchor(ws, fs_path);

    /* Reassignment, derived (see the doc above): an owned record under a profile
     * other than the row's. old_profile borrows the record's string for the item
     * (workspace lifetime). */
    bool profile_changed = anchor && anchor->deployed_at > 0 &&
        strcmp(anchor->profile, profile) != 0;
    const char *old_profile = profile_changed ? anchor->profile : NULL;

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
        if (errno != ENOENT && errno != ENOTDIR) {
            /* Inaccessible, not absent (EACCES, ELOOP, EIO). ENOTDIR is absence:
             * a component above the path is not a directory, so nothing can be
             * at the path either — deploy's lstat_occupant reads it the same
             * way. Same policy as the orphan path below: assume the path is there
             * and record the uncertainty, rather than failing the load and taking
             * every other managed path down with one unreadable one.
             *
             * DEPLOYED is the load-bearing half — absence must never be inferred
             * from a failure to look, or update commits a deletion that never
             * happened. UNVERIFIED keeps consumers conservative: apply retries
             * the write and surfaces the real errno, cleanup's UNVERIFIED skip
             * blocks removal.
             *
             * Returns here because every phase below needs a valid stat. */
            return workspace_add_diverged(
                ws, fs_path, storage_path, profile, old_profile,
                WORKSPACE_STATE_DEPLOYED, DIVERGENCE_UNVERIFIED,
                PATH_KIND_FILE,
                true,                        /* on_filesystem (assumed present) */
                true,                        /* profile_enabled */
                profile_changed
            );
        }

        on_filesystem = false;
        memset(&initial_stat, 0, sizeof(initial_stat));
    } else {
        on_filesystem = true;

        /* The lstat just observed the path in scope (any type counts). A path
         * with no record gets one — presence only; a CMP_EQUAL below supersedes
         * it with a confirmation, and the flush writes each path once. Closes
         * the "user created the path after scope entry" gap: the next absence
         * reads DELETED, not UNDEPLOYED. */
        if (!anchor) {
            workspace_record_observation(ws, row);
        }
    }

    /* Divergence accumulator (bit flags, can combine) */
    divergence_type_t divergence = DIVERGENCE_NONE;

    /* State will be determined in PHASE 2 based on deployment status */
    workspace_state_t state = WORKSPACE_STATE_DEPLOYED;

    /* PHASE 1: Content and type analysis (if file exists) Buffer-based comparison
     * for accurate divergence detection.
     *
     * Architecture:
     * - Use the row's blob_oid for content loading
     * - Extract expected mode from the row's type field
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
     * The content verdict is a three-way comparison with the deployment anchor
     * as base:
     *
     *   theirs = row->blob_oid          what Git expects now
     *   base   = anchor->blob_oid       what dotta last confirmed on disk
     *   ours   = disk
     *
     *   git_moved   := base set  && base ≠ theirs   Git advanced since dotta
     *                                               last deployed this path
     *   user_edited := base unset || ours ≠ base    disk left the blob dotta
     *                                               put there
     *
     * When ours ≠ theirs: CONTENT iff user_edited, STALE iff git_moved. STALE
     * without CONTENT means "overwrite loses nothing"; CONTENT without STALE
     * means "Git has not moved since this was deployed"; both means both sides
     * moved. Without a base there is no second question — any difference from
     * theirs is the user's.
     *
     * Source of truth for the base: the persistent record (the anchors row's
     * blob_oid). A path with no record, or one observed but never confirmed (zero
     * blob), has no base. Cross-process correct by construction — every invocation
     * sees the same answer.
     */
    if (on_filesystem) {
        /* The row's blob_oid is already a 20-byte binary OID — no parse step. */
        const git_oid *blob_oid_ptr = &row->blob_oid;

        /* Extract expected filemode from the row's type field
         *
         * Extracted before comparison strategy selection because both paths need
         * this value. Uses shared helper for consistent mapping.
         */
        git_filemode_t expected_mode = path_type_to_git_filemode(row->type);

        /* Prepare for comparison - both paths capture stat for permission checking */
        struct stat file_stat;
        memset(&file_stat, 0, sizeof(file_stat));
        compare_result_t cmp_result;

        error_t *err = NULL;

        /* The first question of the three-way frame is answered from the row
         * and the record alone; the second (disk_at_anchor — ours == base) is
         * answered by whichever path below settles it, and only when it can change
         * the verdict. */
        bool git_moved = anchor && !git_oid_is_zero(&anchor->blob_oid) &&
                         !git_oid_equal(&anchor->blob_oid, blob_oid_ptr);
        bool disk_at_anchor = false;

        /* ANCHOR FAST PATH (safety-grade)
         *
         * The record binds three pieces of information: the blob dotta last
         * confirmed on disk (anchor->blob_oid), the stat triple captured at that
         * confirmation (anchor->stat), and the time of ownership
         * (anchor->deployed_at). If the live stat matches anchor->stat, the
         * following invariant holds by construction:
         *
         *     stat_match  ⟹  disk == anchor->blob_oid
         *
         * The pair is advanced only by state_anchor() after dotta has verified
         * disk content; nothing else writes it. So a stat match is a
         * cryptographically-grade proof that disk still equals anchor->blob_oid
         * — no re-hash needed, and the second question is answered for free:
         * ours == base. Whether that is CMP_EQUAL (base == theirs: clean) or
         * CMP_DIFFERENT (Git moved: STALE alone) is then read straight from
         * git_moved, without loading blobs or hashing. A path with no record
         * has no triple to match. */
        if (anchor && anchor->stat.mtime != 0
            && anchor->stat.mtime == (int64_t) initial_stat.st_mtime
            && anchor->stat.size == (int64_t) initial_stat.st_size
            && anchor->stat.ino == (uint64_t) initial_stat.st_ino) {
            /* stat match ⟹ disk == anchor.blob_oid */
            file_stat = initial_stat;
            disk_at_anchor = true;
            cmp_result = git_moved ? CMP_DIFFERENT : CMP_EQUAL;

            /* A standing prune order (remove --delete-files) is void once the
             * path is back under a live row and clean — the removal it answered
             * was reverted. The slow path's CMP_EQUAL clears it through
             * state_confirm; a fast-path hit is the same confirmation (disk is
             * the row's blob, the stat vouched for it) and must take the same
             * write, or the order outlives the removal and prunes the copy at
             * the next scope exit instead of the probe releasing it. Queued only
             * when there is an order to void: the fast path stays write-free
             * otherwise. */
            if (cmp_result == CMP_EQUAL && anchor->prune_ordered) {
                workspace_record_confirmation(ws, row, &file_stat);
            }
        } else {
            /* SLOW PATH: Full content comparison, ours vs theirs
             *
             * Strategy selection based on encryption status:
             * - Non-encrypted: Hash filesystem file and compare OID directly
             * - Encrypted: blob_oid is ciphertext hash; must load, decrypt, compare
             *
             * Both paths receive initial_stat to avoid redundant lstat syscalls.
             *
             * Asymmetry with the second question below: that one routes through
             * content_compare_blob_to_disk (byte-classify internally) because
             * anchor.blob_oid can differ from row->blob_oid and there is no
             * anchor-side cache to trust. Here we route on row->encrypted directly
             * — the cache IS byte-truth for *this* blob via the Phase 2 write-time
             * invariant in content_store_file_to_worktree.
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

            /* Slow path confirmed disk == expected blob — confirm the record
             * with the row's blob and the current stat so the next run can
             * short-circuit via the fast path above. */
            if (cmp_result == CMP_EQUAL) {
                workspace_record_confirmation(ws, row, &file_stat);
            }

            /* Second question — ours vs base — asked only when it can change
             * the verdict: Git moved, and the stat triple did not vouch for disk
             * (touch(1), an editor's rename-write, a fresh checkout) although
             * disk content may still be the blob dotta last deployed.
             *
             * Route the anchor comparison by the anchor blob's own bytes.
             *
             * The latent bug class this avoids: routing on row->encrypted silently
             * miscategorised the staleness check across encryption-policy
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
             * A failed or inconclusive compare leaves disk_at_anchor false: the
             * edit is taken as real (CONTENT), the conservative answer — STALE
             * still holds, because git_moved is a fact about two OIDs. */
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
                /* File was deleted during analysis (rare edge case). With stat
                 * propagation this case is unlikely but kept for robustness.
                 * Update flag and skip permission checks below. */
                on_filesystem = false;
                break;

            case CMP_UNVERIFIED:
                /* Verification could not be completed.
                 *
                 * This is a defensive fallback for rare edge cases where comparison
                 * could not determine file state. Accumulate UNVERIFIED flag
                 * and continue to permission checks.
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
         *   - Check using the row's type field (converted to expected_mode)
         *   - Skip symlinks (exec bit doesn't apply)
         *   - Catches: file is 0755 in git but 0644 on disk (or vice versa)
         *
         * PHASE B: Full metadata (all permission bits + ownership)
         *   - Only if metadata exists for this file
         *   - Catches: granular changes like 0600->0644, ownership changes
         *
         * Both phases use the SAME file_stat (captured above), so no extra
         * syscalls. Flags are accumulated with |=.
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

            /* PHASE B: Check full metadata using the row
             *
             * Mode sentinel: row->mode == 0 means "no metadata tracked";
             * the check will be skipped by check_item_metadata_divergence().
             */
            bool mode_differs = false;
            bool ownership_differs = false;

            error_t *check_err = check_item_metadata_divergence(
                row->mode,     /* From the row (mode_t, 0 = no metadata) */
                row->owner,    /* From the row (can be NULL) */
                row->group,    /* From the row (can be NULL) */
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
             * - Phase A passed (both non-exec), but file is 0600 in the row,
             *   0644 on disk
             * - Phase A detected exec bit diff, also detects group/other bits
             *   differ */
            if (mode_differs) divergence |= DIVERGENCE_MODE;
            if (ownership_differs) divergence |= DIVERGENCE_OWNERSHIP;
        }
    }

    /* PHASE 2: Reality-based classification
     *
     * Use the record's existence to distinguish the workspace states of missing
     * files. A record is created the first time dotta lstat-confirms the path
     * on disk in scope. Writers:
     *   - state_observe (the flush, for a path analysis found present with no
     *     record; apply, for a directory it fixed rather than made).
     *   - state_anchor's INSERT arm (every ownership event or confirmation on a
     *     path with no record — apply deploy, adoption, add, update, CMP_EQUAL
     *     flush).
     * observed_at is written once, by whichever of those creates the row, and
     * never again.
     *
     * Record semantics:
     * - none -> dotta has never lstat-confirmed this path on disk in scope
     *           (profile enabled but the file was never there).
     * - some -> dotta has seen this file on disk in scope at least once
     *           (during any status, or after a content-verification event).
     *
     * Classification:
     * 1. File missing + no record -> UNDEPLOYED (never there, no-op)
     * 2. File missing + record    -> DELETED (user removed it)
     * 3. File present             -> DEPLOYED (may diverge)
     *
     * The ownership signal (anchor->deployed_at) is still the authority for
     * "(deployed X ago)" display and the adoption-loop gate; it just no longer
     * controls classification.
     */
    if (!on_filesystem) {
        /* Row claims this path but the filesystem doesn't have it. classify_absent
         * gates on the record (see the classification table above). */
        state = classify_absent(anchor);

        /* Clear divergence flags - can't detect divergence on missing files */
        divergence = DIVERGENCE_NONE;
    } else {
        /* File in manifest and on filesystem */
        state = WORKSPACE_STATE_DEPLOYED;
        /* Keep accumulated divergence flags from Phase 1 */
    }

    /* Add to workspace if there's any state change, divergence, or a reassignment
     * (derived at the top, beside the record pairing). */
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
 * An orphan asks one question — is disk still what dotta put there? — so prune
 * safety is measured against the deployment anchor, never against a view blob:
 * Git may have moved on after the deployment and before the path left scope,
 * and that move is not the user's edit. The record is the honest reference on
 * every axis — its blob and stat for content, its type, mode, owner and group
 * for metadata: what dotta set there, not what the row later came to claim.
 * DIVERGENCE_STALE is therefore never emitted here.
 *
 * Precondition: the record carries a confirmed blob. The caller (analyze_orphans)
 * measures only a record dotta owns or one the user ordered pruned against a
 * confirmed blob; a record with nothing to measure against is released, not
 * measured.
 *
 * Architecture:
 * - Uses the record alone (blob_oid, stat, type, mode, owner, group)
 * - Anchor stat triple as the fast path, the same proof the active slice relies
 *   on: a match means the exact node dotta wrote, no hashing
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
 * @param anchor The record dotta keeps of the path (must not be NULL;
 *               non-zero blob_oid)
 * @param in_stat Pre-captured stat from caller (must not be NULL)
 * @return Divergence flags or DIVERGENCE_UNVERIFIED on error
 */
static divergence_type_t compute_orphan_divergence(
    workspace_t *ws,
    const anchor_t *anchor,
    const struct stat *in_stat
) {
    /* Defensive NULL checks */
    if (!ws || !anchor || !in_stat) {
        return DIVERGENCE_UNVERIFIED;
    }

    const char *fs_path = anchor->filesystem_path;
    const char *storage_path = anchor->storage_path;
    const char *profile = anchor->profile;

    /* Step 1: The reference blob
     *
     * The record's — the blob dotta last confirmed disk against. state.c's read
     * path already rejects wrong-sized BLOB columns, and the caller guarantees
     * a non-zero one, so by the time we get here the OID is well-formed.
     */
    const git_oid *reference = &anchor->blob_oid;

    /* Step 2: Extract expected filemode from the record's type field
     *
     * Calculate once, use for both content comparison and mode checking. Uses
     * shared helper for consistent mapping across modules.
     */
    git_filemode_t expected_mode = path_type_to_git_filemode(anchor->type);

    /* Stat for permission checking (receives copy from in_stat via comparison functions) */
    struct stat fresh_stat;
    memset(&fresh_stat, 0, sizeof(fresh_stat));
    compare_result_t cmp_result;
    error_t *err = NULL;

    /* Step 3: Content and type comparison.
     *
     * Anchor fast path first: a live stat matching the triple captured at the
     * last confirmation is proof that disk still equals anchor.blob_oid (see
     * analyze_file_divergence for the invariant), so the exact node dotta wrote
     * is recognised without loading or hashing anything.
     *
     * Otherwise content_compare_blob_to_disk classifies the blob by magic header
     * and routes; plaintext takes the fast OID-hash-of-disk path, encrypted
     * decrypts via the cache and byte-compares. The routing decision lives with
     * the blob, so the orphan walker cannot route a different blob's state by a
     * cached flag by accident — the record carries no encrypted flag, and the
     * blob dotta deployed may sit on the other side of an encryption-policy flip
     * from what Git holds now. in_stat is forwarded to avoid redundant lstat. */
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
             * Conservative approach: return UNVERIFIED so the user sees [orphaned,
             * unverified] and can investigate, rather than a false [orphaned,
             * clean] or noisy [orphaned, modified]. */
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
            /* Disk left the blob dotta deployed */
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
             * This is a defensive fallback for rare edge cases where comparison
             * could not determine file state. Accumulate UNVERIFIED flag and
             * continue to permission checks.
             */
            divergence |= DIVERGENCE_UNVERIFIED;
            break;
    }

    /* Step 5: Permission checking (two-phase, if file still exists)
     *
     * Only check permissions if:
     * 1. File still exists (not deleted during analysis)
     * 2. No type divergence (type mismatch makes mode checking nonsensical)
     * 3. Verification didn't fail (we have fresh_stat from the fast path or the
     *    compare)
     *
     * PHASE A: Git filemode (executable bit)
     *   - Uses expected_mode from Step 2
     *   - Skips symlinks (exec bit doesn't apply)
     *   - Catches: file is 0755 in git but 0644 on disk (or vice versa)
     *
     * PHASE B: Full metadata (all permission bits + ownership)
     *   - Uses check_item_metadata_divergence() helper
     *   - Reuses fresh_stat from Step 3 (zero extra syscalls)
     *   - Skipped if anchor->mode == 0 (no metadata claim recorded)
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
         * Mode sentinel: anchor->mode == 0 means "no metadata claim recorded",
         * check will be skipped by check_item_metadata_divergence().
         *
         * Uses fresh_stat populated by comparison function (same data as in_stat,
         * copied via out_stat parameter for consistent access pattern).
         */
        bool mode_differs = false;
        bool ownership_differs = false;

        error_t *check_err = check_item_metadata_divergence(
            anchor->mode,         /* From the record (mode_t, 0 = no claim) */
            anchor->owner,        /* From the record (can be NULL) */
            anchor->group,        /* From the record (can be NULL) */
            &fresh_stat,          /* Reuse stat from compare (CRITICAL: not initial_stat!) */
            &mode_differs,
            &ownership_differs
        );

        if (check_err) {
            /* Metadata check failed (rare: getpwuid/getgrgid failure) Preserve
             * already-accumulated divergence (content/type) while signaling that
             * metadata verification was incomplete. */
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
 * exists:   refs/heads/<profile> resolved at first sight.
 * tree:     the branch's HEAD tree, loaded lazily on the first in-tree
 *           question and kept for the rest of the pass; NULL until then and forever
 *           if !exists. Stored only on success, so "tree == NULL" also reads as
 *           "not loaded yet — try again" for the next row.
 * metadata: the tree's metadata.json, loaded lazily on the first directory question
 *           (a directory is backed by a DIRECTORY item, not by a tree entry)
 *           and kept likewise. A tree without metadata.json stores an empty
 *           collection — a profile without metadata backs no directory, and the
 *           lookup says so — so the same rule holds: NULL is "not loaded yet",
 *           never "absent".
 */
typedef struct {
    bool exists;
    git_tree *tree;
    metadata_t *metadata;
} authority_cache_t;

/**
 * Free an authority cache entry (hashmap value callback)
 */
static void authority_cache_free(void *value) {
    authority_cache_t *entry = value;
    if (!entry) {
        return;
    }
    metadata_free(entry->metadata);   /* NULL-safe */
    git_tree_free(entry->tree);       /* NULL-safe */
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
 * Observe Git authority for an orphan
 *
 * "Does the profile that deployed this path still claim it?" — its branch resolves
 * and its HEAD claims storage_path: a tree entry for a file, a DIRECTORY item
 * of its metadata.json for a directory. One kind of row reaches this probe — a
 * record whose path the view lacks — and three reasons it may be there are what
 * the probe tells apart:
 *   - the profile is disabled: its branch still claims the path, and the deployed
 *     copy is dotta's to prune;
 *   - the profile moved: it is enabled, but its --target changed between a disable
 *     and an enable, so Git still backs the storage path at a new location and
 *     the old one is dotta's to prune;
 *   - Git let go: the branch was deleted, rebased or git rm'd behind the record,
 *     an enabled branch is dead, or a pulled removal arrived — the deployed copy
 *     is left alone.
 * The enabled set cannot tell the second from the third; only a live look at
 * Git can. Apply's cleanup preflight used to take that look; status read the
 * same items and could not see it, so it predicted a prune where apply then
 * released. Observed here, every reader of orphan items shares one verdict, and
 * cleanup's verdict phase reads nothing but the item.
 *
 * Answers:
 *   BACKED      the orphan is dotta's to prune, divergence permitting
 *   LOST        Git cannot back the path: branch deleted externally
 *               (content irrecoverable from any profile), or the path removed
 *               from a branch that still exists (git rm, rebase, fetch; a directory
 *               item dropped from metadata). The caller emits
 *               WORKSPACE_STATE_RELEASED — left on disk, record retires.
 *   UNVERIFIED  transient I/O, a locked packfile, a corrupt ref, tree or
 *               metadata. Authority cannot be determined and must not be guessed:
 *               LOST would retire the record, BACKED would prune the file. The
 *               caller marks a file DIVERGENCE_UNVERIFIED and the orphan is held
 *               until Git answers.
 *
 * @param repo Repository (must not be NULL)
 * @param cache profile → authority_cache_t (borrowed keys, owned values)
 * @param profile Record's profile (NOT NULL in the schema)
 * @param storage_path Record's storage path (NOT NULL in the schema)
 * @param kind What the record says stood there — decides which claim is asked for
 * @param out Receives the answer (must not be NULL)
 * @return ERR_MEMORY if the cache entry cannot be created; NULL otherwise
 */
static error_t *compute_orphan_authority(
    git_repository *repo,
    hashmap_t *cache,
    const char *profile,
    const char *storage_path,
    path_kind_t kind,
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
        /* First row of this profile: does the branch still exist? A ref lookup,
         * not a tree load — most profiles answer here. Git errors are not cached:
         * a transient failure must stay retryable. */
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
        /* Lazy-load the HEAD tree on the first in-tree question for this profile;
         * stored only on success, so a failure is retried by the next row instead
         * of condemning the whole profile. */
        git_tree *tree = NULL;
        error_t *err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            error_free(err);
            return NULL;                    /* UNVERIFIED */
        }
        entry->tree = tree;                 /* Ownership transfers to the cache */
    }

    if (kind == PATH_KIND_DIRECTORY) {
        /* A directory is claimed by metadata, not by the tree. Lazy-load the
         * tree's metadata.json on the first directory question for this profile,
         * under the same stored-only-on-success rule as the tree; a tree without
         * one stores an empty collection, because "no metadata" is a settled
         * answer (no directory is backed), not a failure to look. */
        if (!entry->metadata) {
            metadata_t *metadata = NULL;
            error_t *err = metadata_load_from_tree(repo, entry->tree, profile, &metadata);
            if (err) {
                if (err->code != ERR_NOT_FOUND) {
                    error_free(err);
                    return NULL;                /* UNVERIFIED */
                }
                error_free(err);
                err = metadata_create_empty(&metadata);
                if (err) {
                    error_free(err);
                    return NULL;                /* UNVERIFIED */
                }
            }
            entry->metadata = metadata;         /* Ownership transfers to the cache */
        }

        /* Backed iff metadata still claims the path as a directory. An item of
         * another kind at the key is a path Git turned into a blob: the directory
         * dotta made is no longer claimed as one. */
        const metadata_item_t *item = NULL;
        error_t *err = metadata_get_item(entry->metadata, storage_path, &item);
        if (!err) {
            *out = (item->kind == METADATA_ITEM_DIRECTORY)
                ? ORPHAN_AUTHORITY_BACKED : ORPHAN_AUTHORITY_LOST;
        } else if (err->code == ERR_NOT_FOUND) {
            error_free(err);
            *out = ORPHAN_AUTHORITY_LOST;
        } else {
            error_free(err);                    /* *out stays UNVERIFIED */
        }

        return NULL;
    }

    /* Check if file exists in tree via path traversal
     *
     * Distinguish between "file not in tree" (GIT_ENOTFOUND) and actual errors
     * (GIT_ERROR, OOM). ENOTFOUND is the normal "removed from Git" case. Actual
     * errors should propagate so the caller can treat them as CANNOT_VERIFY rather
     * than RELEASED — preserving the record is more conservative than removing it.
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
 * Analyze the orphans — the records whose path the view lacks
 *
 * Each was set aside by workspace_partition because no active row names its path:
 * the partition itself is the orphan predicate, and nothing about why a record
 * is here is stored anywhere. Both kinds walk one loop; the record's type says
 * which questions apply.
 *
 * Per orphan, in order — presence, the prune order, the ownership gate, then
 * Git authority:
 *   - presence (one lstat, either kind — a dangling link is present): an absent
 *     orphan is a reclaim whatever Git says, which keeps the planners' "absent
 *     ⇒ DIVERGENCE_NONE" rule;
 *   - the prune order (remove --delete-files): the user chose the fate of the
 *     deployed copy, and Git is not asked. Honoured only with a reference to
 *     measure the copy against — a directory (cleanup's emptiness rule decides)
 *     or a file with a confirmed blob. A prune-ordered file dotta never matched
 *     against anything falls through to the gate: nothing could tell a clean
 *     copy from an edited one, and the user learns at status and apply that the
 *     copy stays, instead of a skip every run;
 *   - the ownership gate: a record dotta never owned — observed, or confirmed
 *     but never deployed — names a path the user put there before it was managed.
 *     Released: the copy is left alone, the record retires, and no tree is asked
 *     about it;
 *   - Git authority (compute_orphan_authority) for an owned record: a departure
 *     dotta discovers in Git — the branch deleted, rebased or git rm'd, a pulled
 *     removal, a dead enabled branch — is LOST, and the deployed copy is left
 *     alone (RELEASED); BACKED (a disabled profile, a moved target) is dotta's
 *     to prune, divergence permitting; UNVERIFIED holds a file until Git answers
 *     and is not surfaced on a directory — an empty directory Git cannot vouch
 *     for is still an empty directory, and the legend's "apply skips it" would
 *     be a lie for it.
 * Divergence for a prunable file is disk against what dotta last deployed — the
 * record (compute_orphan_divergence); a directory's verdict is cleanup's emptiness
 * rule, so its divergence stays NONE.
 *
 * This enables status to predict apply behavior (cleanup_skip_reason maps the
 * same bits to the skip):
 * - DIVERGENCE_NONE -> Clean orphan, apply will prune
 * - DIVERGENCE_CONTENT/TYPE -> Modified, apply will skip
 * - DIVERGENCE_MODE/OWNERSHIP -> Metadata changed, apply will skip
 * - DIVERGENCE_UNVERIFIED -> Cannot verify, apply will skip
 * - WORKSPACE_STATE_RELEASED -> Git let go, or dotta never deployed it;
 *   apply releases
 *
 * Presence comes first, so an absent record never reaches a RELEASED arm: whatever
 * Git would have said, it reads [orphaned] [absent] and apply reclaims it.
 * on_filesystem still travels with the item for cleanup's verdict phase, which
 * reads the same flag.
 *
 * Each orphan is tagged with profile_enabled — whether its profile is in the
 * workspace's enabled set. It is a label, not a filter: every reader sees every
 * orphan, and apply's verbose breakdown ("N from disabled profiles" / "N from
 * enabled profiles") is its only consumer.
 */
static error_t *analyze_orphans(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->profile_index);

    if (ws->orphan_count == 0) {
        return NULL;
    }

    /* profile → authority_cache_t for this pass. Keys borrow the records'
     * arena-backed profile strings, which outlive it. */
    hashmap_t *authority_cache = hashmap_borrow(8);
    if (!authority_cache) {
        return ERROR(ERR_MEMORY, "Failed to create authority cache");
    }

    error_t *err = NULL;

    for (size_t i = 0; i < ws->orphan_count; i++) {
        const anchor_t *anchor = ws->orphans[i];

        const char *fs_path = anchor->filesystem_path;
        const char *storage_path = anchor->storage_path;
        const char *profile = anchor->profile;
        path_kind_t kind = path_type_kind(anchor->type);

        bool profile_enabled = hashmap_has(ws->profile_index, profile);

        /* Single stat capture, reused for type verification, content comparison,
         * and metadata checks — eliminates redundant lstat syscalls. One rule
         * for every orphan, whatever its kind.
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
             * ENOTDIR: a component above it is not a directory, so the path cannot
             * be there either — the same reclaim.
             *
             * Anything else (EACCES, EIO, ELOOP, …): assume the path exists but
             * is inaccessible. We lack valid stat data, so a file's divergence
             * cannot be computed and becomes UNVERIFIED below, so:
             * - Status shows [orphaned, unverified] (user visibility)
             * - Apply skips removal (can't verify what we can't stat)
             */
            on_filesystem = (errno != ENOENT && errno != ENOTDIR);
            memset(&orphan_stat, 0, sizeof(orphan_stat));
        } else {
            on_filesystem = true;
            stat_valid = true;
        }

        workspace_state_t item_state = WORKSPACE_STATE_ORPHANED;
        divergence_type_t divergence = DIVERGENCE_NONE;

        /* Whether the copy can be measured at all: a directory against cleanup's
         * emptiness rule, a file against a confirmed blob. */
        bool measurable = (kind == PATH_KIND_DIRECTORY) ||
            !git_oid_is_zero(&anchor->blob_oid);

        if (!on_filesystem) {
            /* Absent: ORPHANED with no divergence — a reclaim whatever Git says. */

        } else if (anchor->prune_ordered && measurable) {
            /* The user ordered the deployed copy pruned (remove --delete-files);
             * Git is not asked. Divergence still protects an edited copy —
             * cleanup's skip reasons read the same bits. */
            if (kind == PATH_KIND_FILE) {
                divergence = stat_valid
                    ? compute_orphan_divergence(ws, anchor, &orphan_stat)
                    : DIVERGENCE_UNVERIFIED;
            }

        } else if (anchor->deployed_at == 0) {
            /* The ownership gate: dotta never put this here. Released — the copy
             * is left alone and the record retires. A prune-ordered file with
             * no confirmed blob lands here too: there is nothing to measure the
             * order against. */
            item_state = WORKSPACE_STATE_RELEASED;

        } else {
            /* Owned: ask the profile that deployed it whether it still claims
             * the path. */
            orphan_authority_t authority = ORPHAN_AUTHORITY_UNVERIFIED;
            err = compute_orphan_authority(
                ws->repo, authority_cache, profile, storage_path, kind, &authority
            );
            if (err) {
                break;
            }

            if (authority == ORPHAN_AUTHORITY_LOST) {
                /* Git cannot back the path. Left on disk, record retires — so
                 * there is nothing a content comparison would decide. */
                item_state = WORKSPACE_STATE_RELEASED;

            } else if (kind == PATH_KIND_FILE) {
                /* Divergence for a prunable orphan: disk against what dotta last
                 * deployed. */
                divergence = stat_valid
                    ? compute_orphan_divergence(ws, anchor, &orphan_stat)
                    : DIVERGENCE_UNVERIFIED;

                if (authority == ORPHAN_AUTHORITY_UNVERIFIED) {
                    /* Git could not vouch for the path: skip the orphan until
                     * it can. */
                    divergence |= DIVERGENCE_UNVERIFIED;
                }
            }
            /* else a directory: cleanup's emptiness rule decides, and an unanswered
             * probe is not surfaced (see the doc above). */
        }

        err = workspace_add_diverged(
            ws,
            fs_path,
            storage_path,
            profile,
            NULL,               /* No old_profile for orphans */
            item_state,
            divergence,
            kind,
            on_filesystem,
            profile_enabled,
            false               /* No profile change for orphans */
        );
        if (err) {
            err = error_wrap(err, "Failed to add orphaned/released path");
            break;
        }
    }

    hashmap_free(authority_cache, authority_cache_free);

    return err;
}

/**
 * Analyze divergence for every active file row
 *
 * Walks the active file slice and compares each row against filesystem reality.
 *
 * Performance: O(N) where N = active row count. The row (blob_oid, type, mode,
 * etc.) and the indexed record eliminate N+1 database queries.
 */
static error_t *analyze_files_divergence(workspace_t *ws) {
    CHECK_NULL(ws);

    for (size_t i = 0; i < ws->active_file_count; i++) {
        error_t *err = analyze_file_divergence(ws, ws->active_files[i]);
        if (err) {
            return err;
        }
    }

    return NULL;
}

/**
 * Compute workspace status
 *
 * INVALID is reserved for what the analysis could not establish: an item carrying
 * DIVERGENCE_UNVERIFIED (an unreadable path, a comparison that could not run, a
 * Git probe that did not answer) is one apply cannot resolve — it skips the item
 * and the user must look. Everything else that is not clean is DIRTY: apply
 * deploys, adopts, prunes, reclaims or releases it. An orphan is pending work,
 * not an invalid workspace.
 */
static workspace_status_t compute_workspace_status(const workspace_t *ws) {
    if (!ws) {
        return WORKSPACE_INVALID;
    }

    bool has_unverified = false;
    bool has_warnings = false;

    for (size_t i = 0; i < ws->diverged_count; i++) {
        const workspace_item_t *item = &ws->diverged[i];

        if (item->divergence & DIVERGENCE_UNVERIFIED) {
            has_unverified = true;
        }

        switch (item->state) {
            case WORKSPACE_STATE_ORPHANED:
            case WORKSPACE_STATE_RELEASED:
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

    if (has_unverified) {
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
             * 1. The view: the path is managed by an enabled profile — as a file,
             *    or as a tracked directory a file now sits in
             *    place of (the directory analysis reports that as [type];
             *    it is not a new file)
             * 2. Diverged index: file already classified (e.g., as released or
             *    orphaned by prior analysis phases). Orphans are not in the view
             *    but already have diverged entries — adding them as untracked
             *    would create duplicates.
             */
            bool already_tracked =
                (manifest_lookup(ws->manifest, full_path) != NULL) ||
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

    /* readdir() returns NULL on both end-of-directory and error. With errno cleared
     * before each call, non-zero errno means I/O error. */
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

    /* Source-tree .gitignore filter — built once for the whole scan so the
     * discovered source-repo handle is reused across every profile and directory.
     * Driven by config; policy decision lives here, not in the ignore module.
     * Non-fatal on build failure: we continue without layer-5 filtering rather
     * than blocking status. */
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

    /* Layered-rules builder — one per scan. Baseline and config are loaded here;
     * each profile's `.dottaignore` is parsed once on first use and cached, so
     * the profile loop below amortises the cost across the whole status (the
     * previous shape rebuilt an entire context per profile, re-loading the baseline
     * each time). */
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

    /* Iterate the active directory partition, filtering by profile per outer
     * iteration. The outer loop runs in scope_enabled order — the user's
     * enabled-precedence position — so when two profiles share an ancestor
     * directory, the highest-precedence profile scans first and claims new files
     * via ws->diverged_index (subsequent profiles' scans skip the entry via the
     * dedup check in scan_directory_for_untracked).
     *
     * The dirs.count × ws->profiles->count strcmp filter below is trivially
     * negligible (P ≤ 10, D ≤ 10²) and replaces a per-profile SQL query. */
    manifest_rows_t dirs = workspace_directories(ws);

    for (size_t p = 0; p < ws->profiles->count; p++) {
        const char *profile = ws->profiles->items[p];

        /* Resolve the profile-specific ruleset (memoised in the builder).
         *
         * Fatal on failure: scanning a profile without its ignore rules risks
         * reporting genuinely ignored files as untracked, which the user could
         * then `dotta add` by accident. A corrupt .dottaignore must surface so
         * the user can fix it. */
        const gitignore_ruleset_t *profile_rules = NULL;
        err = ignore_rules_for_profile(ignore_rules, profile, &profile_rules);
        if (err) {
            ignore_rules_free(ignore_rules);
            source_filter_free(source_filter);
            return error_wrap(
                err, "Failed to load ignore patterns for profile '%s'", profile
            );
        }

        /* Per-profile ancestor-suppression cursor — resets per outer iteration.
         * Profiles with shared-ancestor directories use independent ignore rules,
         * so each profile's tree must scan from a clean cursor. */
        const char *last_scanned = NULL;

        for (size_t i = 0; i < dirs.count; i++) {
            const manifest_row_t *row = dirs.entries[i];

            /* Filter to this profile's rows. dirs is in (filesystem_path) order
             * from the snapshot; rows for this profile remain in that relative
             * order, so the ancestor-first invariant the last_scanned suppression
             * depends on holds within each profile slice. */
            if (strcmp(row->profile, profile) != 0) continue;

            /* Directory rows carry:
             * - filesystem_path: Already resolved with target (mount table)
             * - storage_path: Portable path for storage
             */

            /* Use filesystem path directly from the row (already resolved) */
            const char *filesystem_path = row->filesystem_path;

            /* Check if directory still exists */
            if (!fs_exists(filesystem_path)) continue;

            /* Nested-scan suppression: if the previously-scanned directory is a
             * strict directory-prefix ancestor, this subtree was already walked.
             * Boundary-aware ('/' terminator) to avoid false matches like /foo/bar
             * vs /foo/barn. Order guarantees ancestor-first. */
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

            /* Record this scan root regardless of outcome — a failed scan still
             * visited the subtree, so deeper entries are redundant. */
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
 * ARCHITECTURE: Reads the view's directory rows, not metadata (Git) directly. A
 * row carries filesystem_path already resolved with target, enabling correct
 * divergence detection for custom/ prefix directories.
 *
 * Consumes ws->active_dirs from workspace_partition — every input is by
 * construction a directory row of the view. No skip checks.
 */
static error_t *analyze_directory_metadata_divergence(workspace_t *ws) {
    CHECK_NULL(ws);

    error_t *err = NULL;

    for (size_t i = 0; i < ws->active_dir_count; i++) {
        const manifest_row_t *row = ws->active_dirs[i];

        /* Directory rows carry:
         * - filesystem_path: Already resolved with target (mount table)
         * - storage_path: Portable path
         * - profile: Source profile
         * - mode, owner, group: Expected metadata
         *
         * All strings are arena-allocated — no explicit free needed. */
        const char *filesystem_path = row->filesystem_path;
        const char *storage_path = row->storage_path;
        const char *profile = row->profile;

        /* The record dotta keeps of this path, if any — the same pairing the
         * file analyzer makes. */
        const anchor_t *anchor = workspace_get_anchor(ws, filesystem_path);

        /* Stat directory to get current metadata
         *
         * Use lstat() for both existence and type checking:
         * - ENOENT: Directory truly deleted
         * - ENOTDIR: A component above it is not a directory — nothing can be
         *   at the path either; as absent as ENOENT
         * - Other errno: Inaccessible — state undeterminable, not absent
         * - Success + !S_ISDIR: Type changed (file, symlink - including broken
         *   ones)
         * - Success + S_ISDIR: Actual directory, check metadata */
        struct stat dir_stat;
        if (lstat(filesystem_path, &dir_stat) != 0) {
            if (errno == ENOENT || errno == ENOTDIR) {
                /* Absent path: record-gated classification. An observed directory
                 * was deleted by the user (update propagates the removal); a
                 * never-observed one was never there — apply's job is to create
                 * it, never to commit a phantom deletion. */
                err = workspace_add_diverged(
                    ws,
                    filesystem_path,
                    storage_path,
                    profile,
                    NULL,                     /* No old_profile for directories */
                    classify_absent(anchor),
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

            /* Inaccessible, not absent: record the uncertainty rather than dropping
             * the row, which left status reporting a clean workspace for a path
             * it had just failed to read. Same three-way policy as the file
             * rows. */
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

        /* Presence flush accumulator — the same rule as the file side. The
         * lstat above just observed the path in scope (any type counts);
         * if the path has no record yet, queue it for the batched write in
         * workspace_flush_updates. Closes the "user created the path after scope
         * entry" gap with the mechanism files already use. */
        if (!anchor) {
            workspace_record_observation(ws, row);
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
 * Detects files that should be encrypted (per auto-encrypt patterns) but are
 * stored as plaintext in the profile.
 *
 * Trusts the cache. After the write-time invariant established in cmds/add.c
 * and cmds/update.c, row->encrypted is byte-truth (metadata.json:encrypted is
 * stamped from content_classify_bytes at the write boundary, then projected onto
 * the view row at build). The audit reads the cached bool and defers to
 * encryption_policy_violation. Zero blob inflations.
 *
 * Per-blob byte-classification was the previous implementation's regression:
 * O(N) inflations per workspace_load against libgit2's pack backend, on a hot
 * path. The cache discipline makes the cached answer authoritative.
 *
 * Only fires when encryption is active — i.e. the config has a compiled
 * auto-encrypt ruleset (see encryption_policy_is_active). Nothing to check without
 * one.
 *
 * This is a security-focused check: files matching sensitive patterns (e.g.,
 * "*.key", ".ssh/id_*") should be encrypted.
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
        const manifest_row_t *row = ws->active_files[i];
        const char *storage_path = row->storage_path;
        const char *profile = row->profile;

        /* Project the cached bool to a content_kind_t for the policy predicate.
         * The 3-valued enum's UNSUPPORTED_VERSION case is unreachable here -
         * row->encrypted is a bool and collapses ENCRYPTED + UNSUPPORTED_VERSION
         * onto true. That collapse is exhaustive for encryption_policy_violation:
         * any non-PLAINTEXT kind carries encryption intent and is treated as
         * not-a-violation. The version-skew distinction surfaces ia the content
         * read path, not here. */
        content_kind_t kind = row->encrypted ? CONTENT_ENCRYPTED
                                             : CONTENT_PLAINTEXT;

        if (!encryption_policy_violation(config, storage_path, kind)) {
            continue;
        }

        /* Merge the violation into the existing divergence index — the file may
         * already have CONTENT/MODE/etc. divergence, in which case we OR the
         * ENCRYPTION flag in alongside. The O(1) index lookup prevents
         * last-write-wins between analysis passes. */
        void *idx_ptr = hashmap_get(ws->diverged_index, row->filesystem_path);
        workspace_item_t *existing = NULL;
        if (idx_ptr) {
            size_t idx = (size_t) (uintptr_t) idx_ptr - 1;  /* Convert index+1 back to index */
            existing = &ws->diverged[idx];
        }

        if (existing) {
            /* File already diverged - accumulate encryption flag
             *
             * Example: File is DEPLOYED with CONTENT divergence AND violates
             * encryption policy. We accumulate: divergence |=
             * DIVERGENCE_ENCRYPTION. Result: User sees both flags: "modified
             * [encryption]" in status. */
            existing->divergence |= DIVERGENCE_ENCRYPTION;
        } else {
            /* No existing divergence row for this file — encryption policy is
             * the only issue. Classify the workspace state from presence + the
             * record, mirroring analyze_file_divergence Phase 2. */
            struct stat enc_stat;
            bool on_filesystem = (lstat(row->filesystem_path, &enc_stat) == 0);

            workspace_state_t item_state = on_filesystem
                ? WORKSPACE_STATE_DEPLOYED
                : classify_absent(workspace_get_anchor(ws, row->filesystem_path));

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
 * Order two rows by filesystem path (qsort callback)
 *
 * strcmp order is SQLite's BINARY order, which the slices carried when they were
 * read from a table: a parent sorts before every path beneath it, which deploy's
 * parent-before-child walk and the untracked scan's ancestor suppression both
 * rely on.
 */
static int compare_rows_by_path(const void *a, const void *b) {
    const manifest_row_t *const *ra = a;
    const manifest_row_t *const *rb = b;
    return strcmp((*ra)->filesystem_path, (*rb)->filesystem_path);
}

/**
 * Build the view, slice it by kind, snapshot the record, and set the orphans aside
 *
 * The join at the centre of every load. manifest_build computes the expected
 * side — every enabled profile at HEAD, both kinds, one row per path — into
 * ws->manifest; the rows are split into ws->active_files / ws->active_dirs (+
 * counts) and each slice is sorted by filesystem_path. Then the anchors snapshot
 * (state_get_all_anchors) is indexed by path as ws->anchor_index — the analyses
 * pair each row with its record through workspace_get_anchor, and the two writers
 * patch the index's values — and every record whose path the view lacks is
 * collected into ws->orphans, in the snapshot's path order.
 *
 * The partition is the single source of truth for "is this row in scope?": a
 * path is managed iff the view has a row for it, and a record is an orphan iff
 * it does not. The orphan analysis consumes ws->orphans; analyses over the active
 * set walk the active slices. No defensive cleanup on error: workspace_free is
 * the single cleanup authority.
 *
 * Lifetime: every pointer (the view's rows, the slices, the snapshot, the orphans
 * array) lives in ws->arena. Only the two indexes (the view's and the anchors')
 * are heap-allocated, freed in workspace_free through manifest_free and
 * hashmap_free.
 *
 * Performance: O(M log M + A) — one tree walk per enabled profile (manifest_build),
 * two sorts, one pass over the record; no probes.
 */
static error_t *workspace_partition(workspace_t *ws, const mount_table_t *mounts) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->arena);
    CHECK_NULL(ws->profiles);
    CHECK_NULL(mounts);

    /* The expected side, computed. mounts covers the enabled set (the caller
     * built it from the same list). */
    error_t *err = manifest_build(
        ws->repo, ws->profiles, mounts, ws->arena, &ws->manifest
    );
    if (err) {
        return error_wrap(err, "Failed to build manifest");
    }

    /* Slice by kind. Counted first so each slice is exact; the view's row order
     * is unspecified, so each slice is sorted into prefix order afterwards. */
    manifest_rows_t rows = manifest_rows(ws->manifest);
    size_t file_count = 0;
    size_t dir_count = 0;
    for (size_t i = 0; i < rows.count; i++) {
        if (rows.entries[i]->type == PATH_TYPE_DIRECTORY) dir_count++;
        else file_count++;
    }

    if (file_count > 0) {
        ws->active_files = arena_calloc(ws->arena, file_count, sizeof(*ws->active_files));
        if (!ws->active_files) {
            return ERROR(ERR_MEMORY, "Failed to allocate file slice");
        }
    }
    if (dir_count > 0) {
        ws->active_dirs = arena_calloc(ws->arena, dir_count, sizeof(*ws->active_dirs));
        if (!ws->active_dirs) {
            return ERROR(ERR_MEMORY, "Failed to allocate directory slice");
        }
    }

    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];
        if (row->type == PATH_TYPE_DIRECTORY) {
            ws->active_dirs[ws->active_dir_count++] = row;
        } else {
            ws->active_files[ws->active_file_count++] = row;
        }
    }

    if (ws->active_file_count > 0) {
        qsort(
            ws->active_files, ws->active_file_count, sizeof(*ws->active_files),
            compare_rows_by_path
        );
    }
    if (ws->active_dir_count > 0) {
        qsort(
            ws->active_dirs, ws->active_dir_count, sizeof(*ws->active_dirs),
            compare_rows_by_path
        );
    }

    /* The record. Indexed by path so each row above finds its anchor in O(1);
     * the values are the snapshot's own records, which the writers patch in place.
     * Keys borrow the snapshot's arena-backed paths. A record no row pairs with
     * is an orphan; the snapshot is in path order, so the orphans come out in
     * path order for free. */
    err = state_get_all_anchors(
        ws->state, ws->arena, &ws->anchors, &ws->anchor_count
    );
    if (err) {
        return error_wrap(err, "Failed to read anchors from state");
    }

    ws->anchor_index = hashmap_borrow(ws->anchor_count > 0 ? ws->anchor_count : 64);
    if (!ws->anchor_index) {
        return ERROR(ERR_MEMORY, "Failed to create anchor index");
    }

    if (ws->anchor_count > 0) {
        ws->orphans = arena_calloc(ws->arena, ws->anchor_count, sizeof(*ws->orphans));
        if (!ws->orphans) {
            return ERROR(ERR_MEMORY, "Failed to allocate orphans");
        }
    }

    for (size_t i = 0; i < ws->anchor_count; i++) {
        anchor_t *anchor = &ws->anchors[i];

        err = hashmap_set(ws->anchor_index, anchor->filesystem_path, anchor);
        if (err) {
            return error_wrap(err, "Failed to populate anchor index");
        }

        if (!manifest_lookup(ws->manifest, anchor->filesystem_path)) {
            ws->orphans[ws->orphan_count++] = anchor;
        }
    }

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

    /* Workspace scope is the persistent enabled set — never the CLI filter. The
     * scope accessor type-enforces this invariant (see scope.h's "Vocabulary"
     * section). The pointer is borrowed from scope, which must outlive the returned
     * workspace. */
    const string_array_t *profiles = scope_enabled(scope);

    workspace_t *ws = NULL;
    error_t *err = NULL;

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

    /* Build the view, slice it, snapshot the record and set the orphans aside.
     * The partition populates workspace fields directly; consumers read via
     * workspace_files() / workspace_directories() / workspace_lookup() and pair
     * rows with their records through workspace_get_anchor(). The view is computed
     * from Git here, so it is current by construction — nothing upstream repairs
     * anything. */
    err = workspace_partition(ws, mounts);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to partition workspace");
    }

    /* Execute analyses based on the options. Each analysis is independently
     * controllable for optimal performance. */

    /* Analyze file divergence (most common requirement) */
    if (options->analyze_files) {
        err = analyze_files_divergence(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze file divergence");
        }
    }

    /* Analyze the orphans (records of either kind the view lacks) */
    if (options->analyze_orphans) {
        err = analyze_orphans(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze orphans");
        }
    }

    /* Analyze tracked directories for untracked files */
    if (options->analyze_untracked) {
        err = analyze_untracked_files(ws, config);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze untracked files");
        }
    }

    /* Analyze directory metadata divergence */
    if (options->analyze_directories) {
        err = analyze_directory_metadata_divergence(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze directory metadata");
        }
    }

    /* Analyze encryption policy mismatches */
    if (options->analyze_encryption) {
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
 * O(1) lookup via diverged_index hashmap. Returns NULL if item has no divergence
 * (CLEAN items are not indexed).
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
 * Get the active in-scope file slice
 *
 * The const on the outer pointer level is added implicitly — safe per the C
 * standard's "const T ** → const T *const *" rule.
 */
manifest_rows_t workspace_files(const workspace_t *ws) {
    if (!ws) return (manifest_rows_t){ 0 };
    return (manifest_rows_t){
        .entries = ws->active_files,
        .count = ws->active_file_count,
    };
}

/**
 * Get the active in-scope directory slice
 */
manifest_rows_t workspace_directories(const workspace_t *ws) {
    if (!ws) return (manifest_rows_t){ 0 };
    return (manifest_rows_t){
        .entries = ws->active_dirs,
        .count = ws->active_dir_count,
    };
}

/**
 * Look up an active row by filesystem path
 *
 * O(1) probe over the view's own index — the active set is the view.
 */
const manifest_row_t *workspace_lookup(
    const workspace_t *ws,
    const char *filesystem_path
) {
    if (!ws) return NULL;
    return manifest_lookup(ws->manifest, filesystem_path);
}

/**
 * The view the workspace was loaded against
 */
const manifest_t *workspace_manifest(const workspace_t *ws) {
    if (!ws) return NULL;
    return ws->manifest;
}

/**
 * Look up the record dotta keeps of a path
 *
 * O(1) hashmap probe over the anchors snapshot. The map's value is a mutable
 * record pointer (workspace_observe and workspace_anchor patch in place); external
 * callers receive a const view.
 */
const anchor_t *workspace_get_anchor(
    const workspace_t *ws,
    const char *filesystem_path
) {
    if (!ws || !filesystem_path) return NULL;
    return hashmap_get(ws->anchor_index, filesystem_path);
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

            /* A pending reassignment shows on a deleted path too: the record
             * still names the profile that deployed the copy, and apply's redeploy
             * from the new owner is what acknowledges it — the same pair the
             * DEPLOYED arm prints. */
            if (item->profile_changed) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "reassigned";
                }
            }

            if (item->profile_changed && item->old_profile) {
                snprintf(
                    metadata_buf, metadata_size, "%s → %s",
                    item->old_profile, item->profile
                );
            } else {
                snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            }
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
                /* Git moved past the deployed blob. Alone it is apply-side work
                 * — the same CYAN as [undeployed], nothing of the user's is
                 * overwritten; next to [modified] it names a conflict and the
                 * primary tag's colour stands. */
                if (tag_count == 0) {
                    *color_out = OUTPUT_COLOR_CYAN;
                }
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "stale";
                }
            }

            /* Secondary tags for other divergence
             *
             * MODE: Skip if TYPE divergence present (type change makes mode
             *       irrelevant) The condition !((item->divergence &
             *       DIVERGENCE_TYPE) && tag_count > 0) prevents MODE from showing
             *       when TYPE is the primary tag
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
             * Added after divergence tags as secondary information. Color only
             * set for pure reassignment (sole tag) to avoid overriding
             * severity-based colors from divergence. */
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
                /* Gone from disk already: apply reclaims the row and removes
                 * nothing. Cyan, the receipt's colour for a reclaim — no action
                 * on the user's files is coming. Checked before the divergence
                 * arms because an absent orphan carries DIVERGENCE_NONE by
                 * construction, so they would only report it clean and promise
                 * a prune. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "absent";
                }
                *color_out = OUTPUT_COLOR_CYAN;

            } else if (item->divergence & DIVERGENCE_UNVERIFIED) {
                /* Cannot verify state - could be large file, missing key, I/O
                 * error, etc. Conservative: apply skips it
                 * (CLEANUP_SKIP_UNVERIFIED, ranked first there as it is here —
                 * one item, one name). */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "unverified";
                }
                *color_out = OUTPUT_COLOR_MAGENTA;

            } else if (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE)) {
                /* Content or type divergence - blocking issue Apply skips it
                 * (cleanup_skip_reason: MODIFIED / TYPE_CHANGED). */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "modified";
                }
                *color_out = OUTPUT_COLOR_RED;

            } else if (item->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
                /* Metadata divergence only - warning level File content matches
                 * but permissions/ownership changed. Apply skips it
                 * (cleanup_skip_reason: MODE_CHANGED). */
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
                /* No divergence - clean orphan File exactly matches last known
                 * state. Apply will remove it. Use RED to indicate action will
                 * be taken (file deletion). */
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
            /* The path left its profile in Git — released from management. File
             * left on filesystem, the record retires. */
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "released";
            }
            *color_out = OUTPUT_COLOR_MAGENTA;

            if (!item->on_filesystem) {
                /* Nothing is left to leave on disk: apply retires the row and
                 * reports a reclaim, so the display says so too. The ORPHANED
                 * arm reads the same flag for the same reason. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "absent";
                }
                *color_out = OUTPUT_COLOR_CYAN;
            }

            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;

        default:
            /* Unknown state - defensive fallback Should never happen in normal
             * operation, but handle gracefully */
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
 * Observe a managed path with in-memory consistency
 *
 * Workspace-scope writer for observations: a path that already has a record —
 * loaded at partition, or created earlier in this run — is left alone without a
 * statement; otherwise state_observe creates the row and the same record is created
 * here, in the arena, and indexed. The record's fields are exactly what the INSERT
 * wrote: the row's identity and metadata, no blob, no stat, observed_at = now,
 * never owned.
 *
 * The in-memory test mirrors the statement's INSERT OR IGNORE: both sides leave
 * an existing record untouched, so the snapshot and the database agree whichever
 * of them answered.
 */
error_t *workspace_observe(
    workspace_t *ws,
    const manifest_row_t *row,
    time_t now
) {
    CHECK_NULL(ws);
    CHECK_NULL(row);

    if (hashmap_has(ws->anchor_index, row->filesystem_path)) {
        return NULL;
    }

    error_t *err = state_observe(ws->state, row, now);
    if (err) return err;

    anchor_t *anchor = arena_alloc(ws->arena, sizeof(*anchor));
    if (!anchor) {
        return ERROR(ERR_MEMORY, "Failed to allocate observation record");
    }

    *anchor = (anchor_t){
        .filesystem_path = row->filesystem_path,
        .storage_path = row->storage_path,
        .profile = row->profile,
        .type = row->type,
        .mode = row->mode,
        .owner = row->owner,
        .group = row->group,
        .blob_oid = { { 0 } },
        .stat = STAT_CACHE_UNSET,
        .observed_at = now,
        .deployed_at = 0,
        .prune_ordered = false,
    };

    err = hashmap_set(ws->anchor_index, anchor->filesystem_path, anchor);
    if (err) {
        return error_wrap(err, "Failed to index observation record");
    }

    return NULL;
}

/**
 * Anchor a managed path with in-memory consistency
 *
 * Single workspace-scope writer for ownership events: persists via state_anchor
 * and assigns the canonical post-write record (the inputs plus the one column
 * SQL RETURNING decided) into the snapshot — in place when the path has a record,
 * into a fresh arena record that is then indexed when it has none. The SQL UPSERT
 * is the single specification of the observed_at INSERT-arm rule; this function
 * holds none of that logic.
 *
 * The map's value is the mutable record pointer; workspace_get_anchor narrows
 * it to const for every reader.
 */
error_t *workspace_anchor(
    workspace_t *ws,
    const manifest_row_t *row,
    const stat_cache_t *stat,
    time_t now
) {
    CHECK_NULL(ws);
    CHECK_NULL(row);

    anchor_t resolved;
    error_t *err = state_anchor(ws->state, row, stat, now, &resolved);
    if (err) return err;

    anchor_t *existing = hashmap_get(ws->anchor_index, row->filesystem_path);
    if (existing) {
        *existing = resolved;
        return NULL;
    }

    anchor_t *anchor = arena_alloc(ws->arena, sizeof(*anchor));
    if (!anchor) {
        return ERROR(ERR_MEMORY, "Failed to allocate anchor record");
    }
    *anchor = resolved;

    err = hashmap_set(ws->anchor_index, anchor->filesystem_path, anchor);
    if (err) {
        return error_wrap(err, "Failed to index anchor record");
    }

    return NULL;
}

/**
 * Flush accumulated observations and confirmations to the state database
 *
 * Observation half, first: records the first sighting of paths analysis found
 * on disk with no record, either kind. Routes through workspace_observe, so the
 * snapshot gains the same record the INSERT creates.
 *
 * Confirmation half, second: for entries that hit CMP_EQUAL on the slow path
 * during analyze_file_divergence, state_confirm rewrites what the comparison
 * established — the kind, the blob and the fast-path stat triple — and nothing
 * of the claim the record carries: profile, storage path, mode, owner, group
 * stay whatever the last ownership event wrote, so a confirmation against another
 * profile's row keeps reading as the reassignment it is (the fast path, which
 * writes nothing, would otherwise disagree with the slow path). Persisting the
 * pair lets the next run short-circuit (fast path) or tag STALE directly (fast
 * path with Git-advanced blob_oid). The in-memory record is patched on exactly
 * the columns the UPDATE names — inline, because the flush is the one confirmer
 * and state_confirm takes no mirror.
 *
 * The order is load-bearing: a path in both halves had no record at analysis,
 * and a confirmation is an UPDATE that creates nothing — one cannot confirm what
 * one has not seen — so the observation's INSERT must land first. Observed first,
 * the confirmation then finds its row on both sides.
 *
 * Begins its own transaction only when state isn't already in one
 * (status/diff/sync). Apply always passes state already-in-transaction.
 */
error_t *workspace_flush_updates(workspace_t *ws) {
    CHECK_NULL(ws);

    if (ws->observation_count == 0 && ws->confirmation_count == 0) {
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
                err, "Failed to begin flush transaction"
            );
        }
    }

    time_t now = time(NULL);
    for (size_t i = 0; i < ws->observation_count; i++) {
        const manifest_row_t *row = ws->observations[i];

        error_t *err = workspace_observe(ws, row, now);
        if (err) {
            if (needs_transaction) {
                state_rollback(ws->state);
            }
            return error_wrap(
                err, "Failed to flush observation for '%s'", row->filesystem_path
            );
        }
    }

    for (size_t i = 0; i < ws->confirmation_count; i++) {
        const confirmation_t *c = &ws->confirmations[i];

        error_t *err = state_confirm(ws->state, c->row, &c->stat);
        if (err) {
            if (needs_transaction) {
                state_rollback(ws->state);
            }
            return error_wrap(
                err, "Failed to flush confirmation for '%s'",
                c->row->filesystem_path
            );
        }

        /* Mirror the UPDATE on the record — present by now, unless the observation
         * that would have created it was dropped under memory pressure
         * (workspace_record_observation); then the UPDATE matched no row either,
         * and both sides agree there is none. */
        anchor_t *anchor = hashmap_get(ws->anchor_index, c->row->filesystem_path);
        if (anchor) {
            anchor->type = c->row->type;
            anchor->blob_oid = c->row->blob_oid;
            anchor->stat = c->stat;
            anchor->prune_ordered = false;
        }
    }

    if (needs_transaction) {
        error_t *err = state_commit(ws->state);
        if (err) {
            /* A failed COMMIT leaves the transaction open; release it so the
             * next scoped writer does not inherit it. */
            state_rollback(ws->state);
            return error_wrap(
                err, "Failed to commit flush transaction"
            );
        }
    }

    ws->observation_count = 0;
    ws->confirmation_count = 0;

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

    /* Free the observation and confirmation arrays (row pointers are borrowed
     * from the view) */
    free(ws->observations);
    free(ws->confirmations);

    /* Free indices (values are borrowed, so pass NULL for value free function).
     * anchor_index values are records in ws->arena — also borrowed. */
    hashmap_free(ws->profile_index, NULL);
    hashmap_free(ws->diverged_index, NULL);
    hashmap_free(ws->anchor_index, NULL);

    /* The view: its index is the heap's, its rows the arena's. */
    manifest_free(ws->manifest);

    /* The slices, the snapshot and the orphans array are arena-allocated; the
     * caller's arena releases them when destroyed. ws->arena is borrowed — never
     * destroyed here. */

    free(ws);
}
