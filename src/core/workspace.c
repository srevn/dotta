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
 * none. The record dotta keeps of each path (the path_anchors table: what it
 * deployed or observed there, when, with what stat) is loaded beside the view
 * and paired with it by path. It is dotta's own and nothing repairs it either:
 * the analyses read it as the base of every three-way question, and the two writers
 * here (workspace_observe, workspace_anchor) advance it only after a live look
 * at disk. A record whose path the view lacks is an orphan, and the orphan analysis
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

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/policy.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/identity.h"
#include "sys/source.h"

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
 * A displaced directory: a DIRECTORY-kind item carrying DIVERGENCE_TYPE, with
 * the claim that holds the path
 *
 * The bit's two producers are the two authorities of the reach rule
 * (workspace_displaced_t): the directory analyzer's type arm emits a DEPLOYED
 * item over the view's row, the orphan analyzer's displaced arm a RELEASED item
 * over the record — so the item's state names the authority and, for the view's,
 * its row's class names the claim. The path is the item's own (borrowed), its
 * length hoisted for the two outermost-match scans (the stamp, the probe).
 */
typedef struct {
    const char *path;             /* The item's filesystem_path (borrowed) */
    size_t len;                   /* strlen(path), hoisted for str_path_beneath */
    workspace_displaced_t claim;  /* TRACKED / DERIVED (a view row's item), RECORD (an orphan's) */
} displaced_dir_t;

/**
 * Workspace structure
 *
 * Holds the view, the record and the divergence analysis over both. Uses hashmaps
 * for O(1) lookups during analysis.
 */
struct workspace {
    git_repository *repo;                        /* Borrowed reference */
    arena_t *arena;                              /* Borrowed; backs every workspace-lifetime string */

    /* The view: every enabled profile at HEAD, built by the dispatcher at the
     * start of the command and borrowed here (ctx->run.manifest — its rows are
     * the command arena's, its index the dispatcher's to release). Rows are
     * read-only for the whole run — the record a writer patches lives in the
     * anchors snapshot below, never in a row. The view's own index answers
     * workspace_lookup: a path is one managed thing, and every lookup tests
     * row->type for the kind it wants. */
    const manifest_t *manifest;                  /* Borrowed — NOT freed in workspace_free */

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

    /* The prune orders, snapshot at load beside the record — unconditionally:
     * the honour arm reads membership, and the flush's join must see the orders
     * even when no orphan stands for them (the path back in the view is exactly
     * the case with no orphan). The map's keys borrow the arena paths; NULL when
     * the table is empty (the probes are NULL-safe). */
    char **orders;                               /* Arena snapshot from state_get_prune_orders */
    size_t order_count;                          /* Number of orders */
    hashmap_t *order_index;                      /* fs_path → the order (membership; heap-allocated) */

    /* The released copies, snapshot at load the same way. Two readers only, by
     * design: the base derivation in analyze_file_divergence (through the index,
     * and only when the path's record carries no confirmed blob — a released
     * fact is not a claim) and the flush's join (through the array). No third
     * reader may grow without revisiting the reap design. */
    released_copy_t *released;                   /* Arena snapshot from state_get_released_copies */
    size_t released_count;                       /* Number of released copies */
    hashmap_t *released_index;                   /* fs_path → released_copy_t * (heap-allocated) */

    /* State and profile set — the view's profiles (manifest_profiles), in
     * precedence order: the untracked scan walks them in that order. */
    state_t *state;                              /* The record's handle (borrowed from caller) */
    const char *const *profiles;                 /* The view's names (arena); valid for workspace lifetime */
    size_t profile_count;                        /* Number of profiles */

    /* Content cache for encrypted blob reads during divergence analysis */
    content_cache_t *content_cache;              /* Borrowed — NOT freed in workspace_free */

    /* Divergence tracking.
     *
     * Items are arena-allocated, one per divergence, so their addresses are stable
     * for the workspace's lifetime — cleanup's buckets and apply's collections
     * hold them across phases by construction. The spine owns only the pointer
     * buffer; diverged_index maps a path straight to its item. */
    ptr_array_t diverged;                        /* workspace_item_t * (files + directories) */
    hashmap_t *diverged_index;                   /* filesystem_path → workspace_item_t * */

    /* The displaced directories: every path a claim names as a directory that
     * the load observed occupied by anything else, with the claim. Derived by
     * collect_displaced once every analysis has observed its slice, and the stamp
     * on the items (workspace_item_t.displaced) with it; arena-backed, paths
     * borrowed from the items. Almost always empty, which is what makes the stamp
     * and the probe (workspace_displaced_ancestor) free. */
    displaced_dir_t *displaced;                  /* One entry per displaced directory */
    size_t displaced_count;

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
 *
 * The profile set is the view's (manifest_profiles): the names are the arena's,
 * so the workspace borrows nothing that a caller has to keep alive beside it.
 */
static error_t *workspace_create_empty(
    git_repository *repo,
    const manifest_t *manifest,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(manifest);
    CHECK_NULL(out);

    workspace_t *ws = calloc(1, sizeof(workspace_t));
    if (!ws) {
        return ERROR(ERR_MEMORY, "Failed to allocate workspace");
    }

    ws->repo = repo;
    ws->profiles = manifest_profiles(manifest, &ws->profile_count);

    ws->diverged_index = hashmap_borrow(256);  /* Keys: arena-backed filesystem_path */
    if (!ws->diverged_index) {
        free(ws);
        return ERROR(ERR_MEMORY, "Failed to create diverged index");
    }

    ptr_array_init(&ws->diverged);

    ws->status = WORKSPACE_CLEAN;

    *out = ws;
    return NULL;
}

/**
 * Does disk ownership diverge from the claim?
 *
 * The ownership half of every divergence check — one rule for the file, orphan
 * and directory analyzers. A present claim is the sheet's word wherever it stands,
 * whatever the label: only the names actually claimed are compared (NULL skips
 * that half), and a UID/GID the system cannot resolve to a name reads as divergence
 * — unknown ≠ expected (security-first). An absent claim's meaning is the label's
 * (metadata.h): on a label that tracks ownership it is the invoker's own, so
 * the owner is compared to the invoker; on one that does not, the path carries
 * no ownership and nothing is compared. Whether this run could chown does not
 * enter — the lstat needs no privilege, and a claim the disk contradicts is a
 * fact about the path whoever reads it.
 *
 * @param storage_path The claim's key, for its label (must not be NULL)
 * @param owner The claimed owner, or NULL
 * @param group The claimed group, or NULL
 * @param st The path's lstat (must not be NULL)
 */
static bool ownership_diverges(
    const char *storage_path,
    const char *owner,
    const char *group,
    const struct stat *st
) {
    if (!owner && !group) {
        const mount_spec_t *spec = mount_spec_for_path(storage_path);
        return spec && spec->tracks_ownership && st->st_uid != identity()->uid;
    }

    if (owner) {
        struct passwd *pwd = getpwuid(st->st_uid);
        if (!pwd || !pwd->pw_name || strcmp(owner, pwd->pw_name) != 0) {
            return true;
        }
    }

    if (group) {
        struct group *grp = getgrgid(st->st_gid);
        if (!grp || !grp->gr_name || strcmp(group, grp->gr_name) != 0) {
            return true;
        }
    }

    return false;
}

/**
 * Add a diverged item from the join's sources
 *
 * The three join analyzers produce through here: at least one source is non-NULL,
 * and identity — the join key and the claim's coordinates — is aliased from the
 * source's strings, never a second copy (workspace.h has the per-state source
 * table). item_kind is likewise the identity source's, which is exactly each
 * producer's own: the file analyzer's rows are blob types, the directory analyzer's
 * DIRECTORY, the orphan loop's the record's.
 *
 * @param ws Workspace context (must not be NULL)
 * @param row The view's claim (NULL for orphans — except a relocated one, whose
 *            row is the same claim's at its new filesystem path)
 * @param anchor The record (NULL when the path has no record)
 * @param state Where the item exists (deployed/undeployed/etc.)
 * @param divergence What's wrong with it (bit flags, can combine)
 * @param occupant What the producer's lstat found at the path (workspace.h)
 */
static error_t *workspace_add_diverged(
    workspace_t *ws,
    const manifest_row_t *row,
    const anchor_t *anchor,
    workspace_state_t state,
    divergence_type_t divergence,
    fs_occupant_t occupant
) {
    CHECK_NULL(ws);

    /* Arena-allocated: the item's address is stable for the workspace's lifetime,
     * whatever the spine's growth does. */
    workspace_item_t *entry = arena_alloc(ws->arena, sizeof(*entry));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate diverged item");
    }
    memset(entry, 0, sizeof(*entry));

    entry->row = row;
    entry->anchor = anchor;

    /* The state names the identity source: ORPHANED/RELEASED are record-defined
     * — the view lacks the path — and every other state here is a row's. */
    if (state == WORKSPACE_STATE_ORPHANED || state == WORKSPACE_STATE_RELEASED) {
        CHECK_NULL(anchor);
        entry->filesystem_path = anchor->filesystem_path;
        entry->storage_path = anchor->storage_path;
        entry->profile = anchor->profile;
        entry->item_kind = path_type_kind(anchor->type);
    } else {
        CHECK_NULL(row);
        entry->filesystem_path = row->filesystem_path;
        entry->storage_path = row->storage_path;
        entry->profile = row->profile;
        entry->item_kind = path_type_kind(row->type);
    }

    entry->state = state;
    entry->divergence = divergence;
    entry->occupant = occupant;

    error_t *err = ptr_array_push(&ws->diverged, entry);
    if (err) {
        return error_wrap(err, "Failed to append diverged item");
    }

    err = hashmap_set(ws->diverged_index, entry->filesystem_path, entry);
    if (err) {
        return error_wrap(err, "Failed to index diverged entry");
    }

    return NULL;
}

/**
 * Add an untracked item — the one producer with neither source
 *
 * The untracked scan found a new file inside a tracked directory: no row (the
 * view does not claim the path), no record (dotta never observed it while managed).
 * Identity aliases the scan's arena copies; the profile is the view's profile
 * list's — the profile whose tracked directory the scan walked. State, divergence
 * and kind are the constants of the state.
 *
 * @param ws Workspace context (must not be NULL)
 * @param filesystem_path The scan's arena copy (must not be NULL)
 * @param storage_path The scan's arena copy (must not be NULL)
 * @param profile The view's profile list's (must not be NULL)
 * @param occupant What the scan's lstat found at the path (workspace.h)
 */
static error_t *workspace_add_untracked(
    workspace_t *ws,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    fs_occupant_t occupant
) {
    CHECK_NULL(ws);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);

    workspace_item_t *entry = arena_alloc(ws->arena, sizeof(*entry));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate untracked item");
    }
    memset(entry, 0, sizeof(*entry));

    /* The casts discard the const the scan's read-only views carry. */
    entry->filesystem_path = (char *) filesystem_path;
    entry->storage_path = (char *) storage_path;
    entry->profile = (char *) profile;

    entry->state = WORKSPACE_STATE_UNTRACKED;
    entry->divergence = DIVERGENCE_NONE;
    entry->item_kind = PATH_KIND_FILE;
    entry->occupant = occupant;

    error_t *err = ptr_array_push(&ws->diverged, entry);
    if (err) {
        return error_wrap(err, "Failed to append untracked item");
    }

    err = hashmap_set(ws->diverged_index, entry->filesystem_path, entry);
    if (err) {
        return error_wrap(err, "Failed to index untracked entry");
    }

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
 * a fast-path short-circuit — not a correctness invariant of the current analysis
 * (which is already complete by the time this is called). Dropping the record
 * on realloc failure:
 *   - Preserves the caller's already-correct divergence result.
 *   - Self-heals on the next status: the slow-path CMP_EQUAL re-confirms and
 *     re-records the confirmation (assuming memory pressure has cleared).
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
 * observation costs no correctness, only a deferral to the next load's flush,
 * which re-derives it from a live lstat.
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
 * Absence classification — the single decision for every absent managed path,
 * file or directory.
 *
 * DELETED is a statement of intent: the user removed something a profile says
 * stands here, and update's job is to commit that removal and propagate it to
 * every machine. Two facts have to hold before absence can be read that way,
 * and each answers half of it.
 *
 * The claim has to assert the path. Every kind does but one: an ancestor claim
 * says what to make the rung if dotta has to make it, never that the rung stands,
 * so its absence is the condition the claim exists to serve rather than a
 * contradiction of it. Reading that as a deletion would let a machine which never
 * deployed the profile commit the claim's removal for every machine that will —
 * and the sheet has an authority for when a derived claim's reason is gone
 * (metadata.h's residue rule: when the last managed path beneath it goes), which
 * this would answer over the top of.
 *
 * And dotta has to have seen the path there. A record exists iff dotta has
 * lstat-confirmed the path on disk in scope (observed_at is never zero on one),
 * so no record means there was no filesystem obligation to break: absence is
 * UNDEPLOYED, apply's to create.
 *
 * The record still answers "has dotta seen this path" for an ancestor claim —
 * the ownership gate reads it. Only a claim that asserts the path may read that
 * answer as intent.
 */
static workspace_state_t classify_absent(
    const manifest_row_t *row,
    const anchor_t *anchor
) {
    if (row->type == PATH_TYPE_DIRECTORY && !row->tracked) {
        return WORKSPACE_STATE_UNDEPLOYED;
    }

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
 * Content is judged three-way, with dotta's last content confirmation as base
 * (see Phase 1 — the record's blob, or a released fact's when the record carries
 * none): DIVERGENCE_STALE says Git moved past the blob dotta last deployed,
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
 * The blob-family ENCRYPTION verdict (types.h) is settled here too, once per
 * row, from the row and the config alone: row->encrypted is byte truth by the
 * write-boundary invariant (stamped from the blob's bytes at every committing
 * boundary — policy.h names them — projected onto the row at build), so the audit
 * costs one pattern match and inflates nothing. The filesystem is not one of
 * its operands, so every arm carries it — it survives absence and rides beside
 * TYPE and UNVERIFIED alike. A symlink row can never carry it: the predicate
 * answers only for content-bearing kinds (policy.h owns the rationale), so a
 * link whose path matches a pattern is not a violation the capture could never
 * resolve.
 *
 * @param ws Workspace (must not be NULL)
 * @param row Active view row (must not be NULL)
 * @param config Configuration for the auto-encrypt ruleset (can be NULL)
 * @return Error or NULL on success
 */
static error_t *analyze_file_divergence(
    workspace_t *ws,
    const manifest_row_t *row,
    const config_t *config
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

    /* Reassignment, for the add-or-not decision below (see the doc above): an
     * owned record under a profile other than the row's — the same expression
     * as workspace_item_reassigned, its inputs in hand. */
    bool profile_changed = anchor && anchor->deployed_at > 0 &&
        strcmp(anchor->profile, profile) != 0;

    /* The blob-family verdict (see the doc above): is the blob Git holds for
     * this row stored plaintext where the auto-encrypt policy claims the path?
     * DIVERGENCE_NONE or DIVERGENCE_ENCRYPTION, carried by every return below. */
    divergence_type_t policy =
        encryption_policy_violation(config, storage_path, row->type, row->encrypted)
        ? DIVERGENCE_ENCRYPTION : DIVERGENCE_NONE;

    /* Single stat capture for the entire analysis
     *
     * This stat is reused for:
     * 1. Existence check (the occupant)
     * 2. Type verification in comparison functions
     * 3. Metadata divergence checks (mode, ownership)
     */
    struct stat initial_stat;
    fs_occupant_t occupant = fs_lstat_occupant(fs_path, &initial_stat);

    if (occupant == FS_OCCUPANT_UNKNOWN) {
        /* Inaccessible, not absent (EACCES, ELOOP, EIO; ENOTDIR is absence —
         * fs_lstat_occupant reads it so). Same policy as the orphan path below:
         * assume the path is there and record the uncertainty, rather than failing
         * the load and taking every other managed path down with one unreadable
         * one. The content phase honours the same policy for the look it makes:
         * a blob it cannot load, decrypt, or compare maps to CMP_UNVERIFIED at
         * the call, never out of the load.
         *
         * DEPLOYED is the load-bearing half — absence must never be inferred
         * from a failure to look, or update commits a deletion that never happened.
         * UNVERIFIED keeps consumers conservative: apply plans the row and skips
         * it rather than write on a guess — the exit code says so — and cleanup's
         * UNVERIFIED skip blocks removal.
         *
         * Returns here because every phase below needs a valid stat. */
        return workspace_add_diverged(
            ws, row, anchor, WORKSPACE_STATE_DEPLOYED,
            DIVERGENCE_UNVERIFIED | policy,
            occupant                     /* assumed present */
        );
    }

    if (occupant == FS_OCCUPANT_NONE) {
        memset(&initial_stat, 0, sizeof(initial_stat));
    } else {
        /* The lstat just observed the path in scope (any type counts). A path
         * with no record gets one — presence only; a CMP_EQUAL below supersedes
         * it with a confirmation, and the flush writes each path once. Closes
         * the "user created the path after scope entry" gap: the next absence
         * reads DELETED, not UNDEPLOYED. */
        if (!anchor) {
            workspace_record_observation(ws, row);
        }
    }

    /* Divergence accumulator (bit flags, can combine), opened with the blob-family
     * verdict; the path-family bits accumulate below. */
    divergence_type_t divergence = policy;

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
     * The content verdict is a three-way comparison with dotta's last content
     * confirmation as base:
     *
     *   theirs = row->blob_oid          what Git expects now
     *   base   = the confirmed blob     what dotta last confirmed on disk
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
     * Source of truth for the base: the record (the path_anchors row's blob)
     * when it carries one; the released fact when it does not — a released path
     * re-claimed, whose record is gone or is the window's blob-less observation.
     * A path with neither has no base. Cross-process correct by construction —
     * every invocation sees the same answer.
     */
    if (occupant != FS_OCCUPANT_NONE) {
        /* The row's blob_oid is already a 20-byte binary OID — no parse step. */
        const git_oid *blob_oid_ptr = &row->blob_oid;

        /* Extract expected filemode from the row's type field
         *
         * Extracted before comparison strategy selection because both paths need
         * this value. Uses shared helper for consistent mapping.
         */
        git_filemode_t expected_filemode = path_type_to_git_filemode(row->type);

        /* Prepare for comparison - both paths capture stat for permission checking */
        struct stat file_stat;
        memset(&file_stat, 0, sizeof(file_stat));
        compare_result_t cmp_result;

        error_t *err = NULL;

        /* The base: dotta's last content confirmation at this path — the record's,
         * when it carries one; the released fact's, when it does not (a released
         * path re-claimed: the record is gone, or is the window's blob-less
         * observation). The claim questions — absence, reassignment, the item's
         * record column — stay the anchor's alone: a released fact is not a claim,
         * and never fabricates a record, a reassignment, or a DELETED absence.
         * The decryption pair rides with its base: an anchored base compares
         * under the row's (storage_path, profile); a released base under its
         * own recorded pair — the only binding on file, and the one its blob
         * was written whole with. */
        bool anchor_has_blob = anchor && !git_oid_is_zero(&anchor->blob_oid);
        const released_copy_t *released = anchor_has_blob ? NULL
            : hashmap_get(ws->released_index, fs_path);

        /* No base by default — the NULL blob is the no-base state; the row-derived
         * type and pair beside it are never read as a base's (every base question
         * below is gated on git_moved, which needs a base blob). */
        const git_oid *base_blob = NULL;
        const stat_cache_t *base_stat = NULL;
        path_type_t base_type = row->type;
        const char *base_storage = storage_path;
        const char *base_profile = profile;

        if (anchor_has_blob) {
            base_blob = &anchor->blob_oid;
            base_stat = &anchor->stat;
            base_type = anchor->type;   /* the pair stays the row's — see above */
        } else if (released) {
            base_blob = &released->blob_oid;
            base_stat = &released->stat;
            base_type = released->type;
            base_storage = released->storage_path;
            base_profile = released->profile;
        }

        /* The first question of the three-way frame is answered from the row
         * and the base alone; the second (disk_at_base — ours == base) is answered
         * by whichever path below settles it, and only when it can change the
         * verdict. */
        bool git_moved = base_blob && !git_oid_equal(base_blob, blob_oid_ptr);
        bool disk_at_base = false;

        /* BASE FAST PATH (safety-grade)
         *
         * The base binds the blob dotta last confirmed on disk and the stat triple
         * captured at that confirmation. If the live stat matches the triple,
         * the following invariant holds by construction:
         *
         *     stat_match  ⟹  disk == base blob
         *
         * The pair is advanced only after dotta has verified disk content —
         * state_anchor and state_confirm are its writers, and a released row's
         * pair was copied verbatim from a record those verbs advanced, so the
         * proof holds through the copy. A stat match is a cryptographically-grade
         * proof that disk still equals the base blob — no re-hash needed, and
         * the second question is answered for free: ours == base. Whether that
         * is CMP_EQUAL (base == theirs: clean) or CMP_DIFFERENT (Git moved: STALE
         * alone) is then read straight from git_moved, without loading blobs or
         * hashing. A path with no base has no triple to match. */
        if (base_stat && base_stat->mtime != 0
            && base_stat->mtime == (int64_t) initial_stat.st_mtime
            && base_stat->size == (int64_t) initial_stat.st_size
            && base_stat->ino == (uint64_t) initial_stat.st_ino) {
            /* stat match ⟹ disk == base blob */
            file_stat = initial_stat;
            disk_at_base = true;
            cmp_result = git_moved ? CMP_DIFFERENT : CMP_EQUAL;

            /* A verification that establishes a pair the record does not hold
             * is queued as the record's own confirmation — which is exactly the
             * released-base hit: the record is blob-less or absent, while an
             * anchored base IS the record's pair and re-writing it would be a
             * no-op (the fast path stays write-free for it). The record gains
             * the blob, and the flush's join then forgets the released row the
             * fresher confirmation subsumes. */
            if (cmp_result == CMP_EQUAL && released) {
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
                    expected_filemode,
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
                        expected_filemode,
                        &initial_stat,
                        &cmp_result,
                        &file_stat
                    );
                }
                /* Note: Don't free expected_content - cache owns it! */
            }

            if (err) {
                /* A failed look, not a verdict — the orphan analyzer's cause
                 * list (missing key, wrong passphrase, cipher-version skew, I/O
                 * error, missing blob) and the same word. The path is there (the
                 * lstat said so); only the look at its content failed, and a
                 * failed look is never fatal to the load. The CMP_UNVERIFIED
                 * arm below routes it; the confirmation and base-question gates
                 * between read EQUAL and DIFFERENT, so they skip themselves. */
                error_free(err);
                cmp_result = CMP_UNVERIFIED;
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
             * Route the base comparison by the base blob's own bytes.
             *
             * The latent bug class this avoids: routing on row->encrypted silently
             * miscategorised the staleness check across encryption-policy
             * transitions. Both directions failed:
             *   - encrypted base / plaintext current → compare_oid_to_disk hashed
             *     plaintext disk against an encrypted-blob OID, never equal,
             *     STALE never set.
             *   - plaintext base / encrypted current → content_cache called with
             *     expected_encrypted=true on a plaintext blob, the old cross-check
             *     raised ERR_STATE_INVALID, swallowed below.
             *
             * content_compare_blob_to_disk classifies by bytes, so the routing
             * decision lives with the blob whose comparison we are doing. A
             * routing-on-stale-flag bug is structurally impossible.
             *
             * A failed or inconclusive compare leaves disk_at_base false: the
             * edit is taken as real (CONTENT), the conservative answer — STALE
             * still holds, because git_moved is a fact about two OIDs. A failed
             * look on a released base retires nothing: only the sweep and the
             * join forget rows, and neither reads compare results. */
            if (cmp_result == CMP_DIFFERENT && git_moved) {
                compare_result_t at_base = CMP_UNVERIFIED;
                error_t *verify_err = content_compare_blob_to_disk(
                    ws->repo,
                    base_blob,
                    fs_path,
                    expected_filemode,
                    &initial_stat,
                    base_storage,
                    base_profile,
                    ws->content_cache,
                    &at_base,
                    NULL
                );
                if (verify_err) error_free(verify_err);
                disk_at_base = (at_base == CMP_EQUAL);
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
                if (!disk_at_base) divergence |= DIVERGENCE_CONTENT;
                if (git_moved) divergence |= DIVERGENCE_STALE;
                break;

            case CMP_TYPE_DIFF:
                /* The occupant is not the row's kind (file ↔ symlink, or a
                 * directory, FIFO, socket or device standing on the row). When
                 * Git moved the kind out from under an untouched deployment,
                 * the second question — asked against the base, routed by the
                 * base's own kind — answers it: an occupant that is exactly what
                 * dotta confirmed, kind and content, diverges by Git's move alone.
                 * STALE, the fast path's answer for the same state when the triple
                 * vouches for it; the base's kind is what keeps the two paths
                 * agreeing — the module's invariant that the verdict must not
                 * depend on which path looked rests on this routing. */
                if (git_moved) {
                    compare_result_t at_base = CMP_UNVERIFIED;
                    error_t *verify_err = content_compare_blob_to_disk(
                        ws->repo,
                        base_blob,
                        fs_path,
                        path_type_to_git_filemode(base_type),
                        &initial_stat,
                        base_storage,
                        base_profile,
                        ws->content_cache,
                        &at_base,
                        NULL
                    );
                    if (verify_err) error_free(verify_err);
                    if (at_base == CMP_EQUAL) {
                        divergence |= DIVERGENCE_STALE;
                        break;
                    }
                }

                /* Anything else is a blocking condition: return immediately with
                 * TYPE divergence. The sources ride along, the same shape as
                 * every early return, so a pending handover does not vanish behind
                 * a type change. */
                return workspace_add_diverged(
                    ws, row, anchor, WORKSPACE_STATE_DEPLOYED,
                    DIVERGENCE_TYPE | policy, occupant
                );

            case CMP_MISSING:
                /* The look itself met ENOENT/ENOTDIR: the path vanished between
                 * the lstat above and the content read. The verdict is absence,
                 * so the sighting that lstat queued is retracted — asked of the
                 * queue itself: its last entry is this row's iff this row queued
                 * one (nothing queues observations between the lstat and here;
                 * an OOM-dropped sighting simply is not there to retract). The
                 * record follows the run's verdict, never a moment the run itself
                 * outlived. Skip the permission checks below. */
                if (!anchor && ws->observation_count > 0 &&
                    ws->observations[ws->observation_count - 1] == row) {
                    ws->observation_count--;
                }
                occupant = FS_OCCUPANT_NONE;
                break;

            case CMP_UNVERIFIED:
                /* The failed look, mapped above — no compare path returns this
                 * verdict itself. UNVERIFIED beside the blob bit, the unstattable
                 * arm's shape: the stat is valid so the mode checks below could
                 * run, but every consumer reads UNVERIFIED first, so accumulated
                 * path bits would change nothing; the orphan slice already answers
                 * a failed look this way, and one policy beats two. */
                return workspace_add_diverged(
                    ws, row, anchor, WORKSPACE_STATE_DEPLOYED,
                    DIVERGENCE_UNVERIFIED | policy, occupant
                );
        }

        /* PERMISSION CHECKING
         *
         * Only when the path still stands and the content phase did not already
         * rule it absent or another type — properties of what is not there (or
         * not that) cannot be compared.
         *
         * The row's mode is total for every kind that carries one — the claim,
         * or the filemode floor manifest_build resolved absence into — so one
         * full-bit compare answers, the executable bit riding in it; a symlink
         * row is never asked (its 0 is a don't-care, not a value). Ownership is
         * its own axis, links included. Both read the same file_stat captured
         * above — no extra syscalls.
         */
        if (occupant != FS_OCCUPANT_NONE &&
            cmp_result != CMP_TYPE_DIFF && cmp_result != CMP_MISSING) {
            if (row->type != PATH_TYPE_SYMLINK && (file_stat.st_mode & 0777) != row->mode) {
                divergence |= DIVERGENCE_MODE;
            }
            if (ownership_diverges(row->storage_path, row->owner, row->group, &file_stat)) {
                divergence |= DIVERGENCE_OWNERSHIP;
            }
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
    if (occupant == FS_OCCUPANT_NONE) {
        /* Row claims this path but the filesystem doesn't have it. classify_absent
         * decides (see the classification table above; its claim gate is inert
         * here — a file row asserts its path by holding a blob for it). */
        state = classify_absent(row, anchor);

        /* Absence clears the path-family bits — properties of what is not there
         * cannot be compared. The blob-family verdict stands: the blob and the
         * policy are both still here to disagree ([undeployed] [unencrypted] is
         * exactly this row). */
        divergence = policy;
    } else {
        /* File in manifest and on filesystem */
        state = WORKSPACE_STATE_DEPLOYED;
        /* Keep accumulated divergence flags from Phase 1 */
    }

    /* Add to workspace if there's any state change, divergence, or a reassignment
     * (derived at the top, beside the record pairing). */
    if (state != WORKSPACE_STATE_DEPLOYED ||
        divergence != DIVERGENCE_NONE || profile_changed) {
        error_t *err = workspace_add_diverged(
            ws, row, anchor, state, divergence, occupant
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
 * - Full-bit permission checking against the record's mode, ownership beside it
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
    git_filemode_t expected_filemode = path_type_to_git_filemode(anchor->type);

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
            expected_filemode,
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
             * The active analyzer maps its content-phase errors the same way
             * (analyze_file_divergence): same causes, same word. The CMP_UNVERIFIED
             * arm below routes it. */
            error_free(err);
            cmp_result = CMP_UNVERIFIED;
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
            /* The look itself met ENOENT/ENOTDIR: the file was removed after
             * the caller's single lstat but before the comparison function read
             * its contents.
             *
             * Report as DIVERGENCE_NONE - the orphan was already removed manually.
             * Apply will skip it (nothing to remove; cleanup's execute re-probes
             * presence), state will be pruned.
             */
            file_exists = false;
            break;

        case CMP_UNVERIFIED:
            /* The failed look, mapped above — no compare path returns this verdict
             * itself. Conservative: the user sees [orphaned, unverified] and
             * investigates, rather than a false [orphaned, clean] or noisy
             * [orphaned, modified]; metadata checks on content dotta could not
             * read would say nothing more. */
            return DIVERGENCE_UNVERIFIED;
    }

    /* Step 5: Permission checking (if the path still stands)
     *
     * Only when the file still exists and its type still matches the record — a
     * mode question over a different type answers nothing. The record's mode is
     * total for every kind that carries one (written from a view row after the
     * build resolved absence), so one full-bit compare answers; a symlink record
     * is never asked. Both halves read fresh_stat — the stat the content verdict
     * was made from (the fast path's, or the compare's out-param), not the caller's
     * earlier look — for zero extra syscalls.
     */
    if (file_exists && !(divergence & DIVERGENCE_TYPE)) {
        if (anchor->type != PATH_TYPE_SYMLINK
            && (fresh_stat.st_mode & 0777) != anchor->mode) {
            divergence |= DIVERGENCE_MODE;
        }
        if (ownership_diverges(
            anchor->storage_path, anchor->owner, anchor->group, &fresh_stat
            )) {
            divergence |= DIVERGENCE_OWNERSHIP;
        }
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
 *   UNVERIFIED  the probe could not answer: a ref lookup, a tree or a metadata
 *               load that failed, transient I/O, a locked packfile, a corrupt
 *               ref, or an allocation the cache needed. Authority cannot be
 *               determined and must not be guessed: LOST would retire the record,
 *               BACKED would prune the file. The caller marks the orphan
 *               DIVERGENCE_UNVERIFIED and holds it until Git answers.
 *
 * No failure is raised. Every one of the six ways this probe can fail says the
 * same thing — it could not answer — and UNVERIFIED is the word for it, so an
 * error would carry nothing the answer does not: a probe that cannot answer is
 * the orphan's hold, never the load's, which is the rule every failed look in
 * this file takes. Nothing is cached on a failure, so a transient one stays
 * retryable by the next row.
 *
 * @param repo Repository (must not be NULL)
 * @param cache profile → authority_cache_t (borrowed keys, owned values)
 * @param profile Record's profile (NOT NULL in the schema)
 * @param storage_path Record's storage path (NOT NULL in the schema)
 * @param kind What the record says stood there — decides which claim is asked for
 * @param out Receives the answer (must not be NULL)
 */
static void compute_orphan_authority(
    git_repository *repo,
    hashmap_t *cache,
    const char *profile,
    const char *storage_path,
    path_kind_t kind,
    orphan_authority_t *out
) {
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
            return;                         /* UNVERIFIED */
        }

        entry = calloc(1, sizeof(*entry));
        if (!entry) {
            return;                         /* UNVERIFIED */
        }
        entry->exists = exists;

        err = hashmap_set(cache, profile, entry);
        if (err) {
            error_free(err);
            authority_cache_free(entry);
            return;                         /* UNVERIFIED */
        }
    }

    if (!entry->exists) {
        *out = ORPHAN_AUTHORITY_LOST;       /* Branch deleted externally */
        return;
    }

    if (!entry->tree) {
        /* Lazy-load the HEAD tree on the first in-tree question for this profile;
         * stored only on success, so a failure is retried by the next row instead
         * of condemning the whole profile. */
        git_tree *tree = NULL;
        error_t *err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            error_free(err);
            return;                         /* UNVERIFIED */
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
                    return;                     /* UNVERIFIED */
                }
                error_free(err);
                err = metadata_create_empty(&metadata);
                if (err) {
                    error_free(err);
                    return;                     /* UNVERIFIED */
                }
            }
            entry->metadata = metadata;         /* Ownership transfers to the cache */
        }

        /* Backed iff metadata still claims the path as a directory. An item of
         * another kind at the key is a path Git turned into a blob: the directory
         * dotta made is no longer claimed as one. */
        const metadata_item_t *item = metadata_lookup(entry->metadata, storage_path);
        *out = (item && item->kind == PATH_KIND_DIRECTORY) ? ORPHAN_AUTHORITY_BACKED
                                                           : ORPHAN_AUTHORITY_LOST;

        return;
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
}

/**
 * Analyze the orphans — the records whose path the view lacks
 *
 * Each was set aside by workspace_partition because no active row names its path:
 * the partition itself is the orphan predicate, and nothing about why a record
 * is here is stored anywhere. Both kinds walk one loop; the record's type says
 * which questions apply.
 *
 * Per orphan, in order — presence, the occupant's kind, the prune order, the
 * ownership gate, then Git authority:
 *   - presence (one lstat, either kind — a dangling link is present): an absent
 *     orphan is a reclaim whatever Git says, which keeps the planners' "absent
 *     ⇒ DIVERGENCE_NONE" rule;
 *   - the occupant's kind: a directory where dotta's file was, or anything but
 *     a directory where dotta's directory was, is a path dotta's copy has left
 *     — what dotta put there is gone, the same sentence as LOST below — and the
 *     node in its place is not dotta's to remove: unlink cannot take a directory,
 *     rmdir cannot take a file, and nothing authorizes either. Released, tagged
 *     [type]. Decided ahead of the prune order and the gate, because an order
 *     to prune a copy that is no longer there is moot and no tree needs asking.
 *     A file ↔ symlink ↔ device swap is not this: unlink undoes a one-node swap
 *     under --force, and the divergence names it TYPE. An occupant that could
 *     not be stat'd is not judged — it may be dotta's own directory, unreachable;
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
 *     to prune, divergence permitting — and carries the relocation read: a BACKED
 *     orphan whose claim still has a row elsewhere in the view rides that row
 *     on the item, and the storage label picks the fate (cleanup_verdict);
 *     UNVERIFIED holds the orphan until Git answers — either kind: LOST would
 *     retire the record, BACKED would remove the copy, and neither is a guess
 *     to make about an empty directory any more than about a file. Held and not
 *     measured: no reader shows a bit beside UNVERIFIED, so a compare would only
 *     give the item a second reason for the one fate it already has. The probe
 *     raises nothing, so a lookup it could not make is this orphan's hold and
 *     never the load's — the rule the file analyzer takes for its own looks.
 *
 * Divergence for a prunable file is disk against what dotta last deployed — the
 * record (compute_orphan_divergence). A prunable directory's verdict is cleanup's
 * emptiness rule, so there is nothing to measure, only whether it can be: a
 * directory dotta cannot stat, read or search — the path, or a component above
 * it — is UNVERIFIED, the bit an unstattable file carries, and held until the
 * user can say what is in it. That is one fs_eaccess per present directory orphan
 * (read and search: the walk lstat's an entry named like OS metadata to see that
 * it is a file); the readdir itself stays cleanup's, because what is left in a
 * directory depends on the plan.
 *
 * This enables status to predict apply behavior (cleanup_verdict reads the same
 * item, and cleanup_skip_reason maps the same bits to the skip):
 * - DIVERGENCE_NONE -> Clean orphan, apply will prune
 * - DIVERGENCE_CONTENT/TYPE -> Modified, apply will skip
 * - DIVERGENCE_MODE/OWNERSHIP -> Metadata changed, apply will skip
 * - DIVERGENCE_UNVERIFIED -> Cannot verify, apply will skip
 * - WORKSPACE_STATE_RELEASED -> Git let go, dotta never deployed it, or
 *   (with DIVERGENCE_TYPE) another kind of path stands there; apply releases
 *
 * Presence comes first, so an absent record never reaches a RELEASED arm: whatever
 * Git would have said, it reads [orphaned] [absent] and apply reclaims it. The
 * occupant travels with the item for cleanup's verdict phase, which reads the
 * same observation.
 */
static error_t *analyze_orphans(workspace_t *ws) {
    CHECK_NULL(ws);

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

        /* Single stat capture, reused for type verification, content comparison,
         * and metadata checks — eliminates redundant lstat syscalls. One rule
         * for every orphan, whatever its kind: FS_OCCUPANT_NONE is the orphan
         * already removed by hand (or a component above it no longer a directory)
         * — a reclaim; FS_OCCUPANT_UNKNOWN (EACCES, EIO, ELOOP, …) is assumed
         * present but leaves no usable stat, so a file's divergence cannot be
         * computed and becomes UNVERIFIED below:
         * - Status shows [orphaned, unverified] (user visibility)
         * - Apply skips removal (can't verify what we can't stat)
         */
        struct stat orphan_stat;
        fs_occupant_t occupant = fs_lstat_occupant(fs_path, &orphan_stat);

        workspace_state_t item_state = WORKSPACE_STATE_ORPHANED;
        divergence_type_t divergence = DIVERGENCE_NONE;

        /* The relocated claim's row, set only where the probe answers BACKED:
         * the record's own (profile, storage path) claim, still in the view,
         * projected at a different filesystem path. See the read below. */
        const manifest_row_t *row = NULL;

        /* Whether the copy can be measured at all: a directory against cleanup's
         * emptiness rule, a file against a confirmed blob. The schema CHECK
         * (state.c: ownership implies confirmation) guarantees an owned file
         * record its blob, so for files this discriminates only when deployed_at
         * == 0 — a prune-ordered record dotta never deployed. */
        bool measurable = (kind == PATH_KIND_DIRECTORY) ||
            !git_oid_is_zero(&anchor->blob_oid);

        /* Whether another kind of path stands where dotta's copy was (see the
         * doc above): a directory at a file record's path, anything but a directory
         * at a directory record's. An occupant that could not be stat'd is not
         * judged. The record's own kind, not the ancestry's: whether the copy
         * was observed through a squatter above it is the stamp's
         * (collect_displaced). */
        bool retyped = (kind == PATH_KIND_FILE)
            ? (occupant == FS_OCCUPANT_DIRECTORY)
            : (occupant != FS_OCCUPANT_DIRECTORY && occupant != FS_OCCUPANT_UNKNOWN);

        /* Set by the arms that find the copy dotta's to prune, divergence
         * permitting; measured once, below. */
        bool measure = false;

        if (occupant == FS_OCCUPANT_NONE) {
            /* Absent: ORPHANED with no divergence — a reclaim whatever Git says. */

        } else if (retyped) {
            /* What dotta put there is gone, and what stands there is not dotta's
             * to remove. Released, [type]: the record retires, the path stays. */
            item_state = WORKSPACE_STATE_RELEASED;
            divergence = DIVERGENCE_TYPE;

        } else if (hashmap_has(ws->order_index, fs_path) && measurable) {
            /* The user ordered the copy pruned — remove --delete-files over a
             * path the removal named or a copy dotta deployed, the only births
             * an order has (state_order_prune); Git is not asked. Read ahead of
             * the ownership gate below by design: a named path must go whether
             * dotta deployed it or only ever found it. Divergence still protects
             * an edited copy — cleanup's skip reasons read the same bits. */
            measure = true;

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
            compute_orphan_authority(
                ws->repo, authority_cache, profile, storage_path, kind, &authority
            );

            if (authority == ORPHAN_AUTHORITY_UNVERIFIED) {
                /* Git could not vouch for the path — a lookup that failed, or
                 * an allocation the probe needed — and neither LOST nor BACKED
                 * is a guess to make: held. Not measured, unlike the two arms
                 * below: no reader shows a bit beside UNVERIFIED, so a compare
                 * would only give the item a second reason for the fate it already
                 * has. */
                divergence = DIVERGENCE_UNVERIFIED;
            } else if (authority == ORPHAN_AUTHORITY_LOST) {
                /* Git cannot back the path. Left on disk, record retires — so
                 * there is nothing a content comparison would decide. */
                item_state = WORKSPACE_STATE_RELEASED;
            } else {
                measure = true;

                /* The relocation read — BACKED only, which is what this arm is:
                 * a relocated orphan is an orphan whose claim still has a row.
                 * The record's own (profile, storage path) pair is asked of the
                 * view; a row found here always projects elsewhere — the partition
                 * orphaned this record precisely because no view row stands at
                 * its filesystem path, this row included — so the claim deploys
                 * at a new location now: a moved custom/ target, a different
                 * $HOME. The item carries it (item->row non-NULL on an ORPHANED
                 * item IS the relocation; the label picks the fate at
                 * cleanup_verdict, and root/ never gets here — its projection
                 * is fixed). Strictly the record's own profile: a claim shadowed
                 * by another profile at its new home is not "relocated" — the
                 * copy here is simply no longer active — and the same-profile
                 * rule is what keeps workspace_item_reassigned false by
                 * construction on every orphan (the profiles are equal). A LOST
                 * or unanswered probe carries nothing: the first releases, the
                 * second holds, and neither fate reads the row. */
                row = manifest_lookup_storage(ws->manifest, storage_path, profile);
            }
        }

        if (measure) {
            /* A file: disk against what dotta last deployed. A directory: nothing
             * to measure — cleanup's emptiness rule decides — only whether it
             * can be: one dotta cannot stat or cannot read is held, as an
             * unstattable file is, until the user can say what is in it. */
            if (kind == PATH_KIND_FILE) {
                divergence = (occupant != FS_OCCUPANT_UNKNOWN)
                    ? compute_orphan_divergence(ws, anchor, &orphan_stat)
                    : DIVERGENCE_UNVERIFIED;
            } else if (occupant == FS_OCCUPANT_UNKNOWN
                || !fs_eaccess(fs_path, R_OK | X_OK)) {
                /* Read for the readdir, search for the walk's look at an entry
                 * named like OS metadata (fs_directory_emptiness). */
                divergence = DIVERGENCE_UNVERIFIED;
            }
        }

        err = workspace_add_diverged(
            ws, row,  /* The relocated claim's row, or NULL; identity is the record's */
            anchor, item_state, divergence, occupant
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
static error_t *analyze_files_divergence(workspace_t *ws, const config_t *config) {
    CHECK_NULL(ws);

    for (size_t i = 0; i < ws->active_file_count; i++) {
        error_t *err = analyze_file_divergence(ws, ws->active_files[i], config);
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

    for (size_t i = 0; i < ws->diverged.count; i++) {
        const workspace_item_t *item = ws->diverged.items[i];

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
                if (item->divergence != DIVERGENCE_NONE ||
                    workspace_item_reassigned(item)) {
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

    DIR *dir = fs_opendir(dir_path);
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

        /* Build both names: the filesystem path, and the storage path beneath
         * the row's — the tracked directory is the authority for what lies under
         * it. */
        char *full_path = str_format("%s/%s", dir_path, entry->d_name);
        char *storage_path = str_format("%s/%s", storage_prefix, entry->d_name);
        if (!full_path || !storage_path) {
            free(full_path);
            free(storage_path);
            closedir(dir);
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }

        /* What stands there, from one lstat (don't follow symlinks) */
        fs_occupant_t occupant = fs_lstat_occupant(full_path, NULL);
        if (occupant == FS_OCCUPANT_NONE || occupant == FS_OCCUPANT_UNKNOWN) {
            /* Deleted since readdir listed it (a race), or unstattable: nothing
             * this scan can say about it. */
            free(full_path);
            free(storage_path);
            errno = 0;
            continue;
        }

        /* Check if ignored: the rules on the mount-relative path; where no layer
         * decided, the source tree's .gitignore on the filesystem path (its root
         * is that repo's) — the lowest layer, so a `!` rule above it wins. */
        bool is_dir = (occupant == FS_OCCUPANT_DIRECTORY);
        gitignore_match_t match;
        gitignore_eval(rules, mount_strip_label(storage_path), is_dir, &match);
        bool ignored = match.decided && match.ignored;
        if (!match.decided && source_filter) {
            error_t *err = source_filter_is_excluded(
                source_filter, full_path, is_dir, &ignored
            );
            error_free(err);  /* Non-fatal: layer-5 errors fall through */
        }
        if (ignored) {
            free(full_path);
            free(storage_path);
            errno = 0;
            continue;
        }

        if (is_dir) {
            /* Recurse into subdirectory */
            error_t *err = scan_directory_for_untracked(
                full_path,
                storage_path,
                profile,
                rules,
                source_filter,
                ws,
                depth + 1
            );

            free(storage_path);
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
             *    or as a directory a file now sits in
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
                /* This is an untracked file! Arena-copy heap strings — originals
                 * freed immediately after */
                char *arena_fp = arena_strdup(ws->arena, full_path);
                char *arena_sp = arena_strdup(ws->arena, storage_path);
                free(storage_path);
                free(full_path);

                if (!arena_fp || !arena_sp) {
                    closedir(dir);
                    return ERROR(ERR_MEMORY, "Failed to arena-copy untracked paths");
                }

                error_t *err = workspace_add_untracked(
                    ws, arena_fp, arena_sp, profile, occupant
                );

                if (err) {
                    closedir(dir);
                    return err;
                }
            } else {
                free(storage_path);
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
        return error_from_errno(
            saved_errno, "Error reading directory '%s'", dir_path
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

    error_t *err = NULL;

    if (ws->profile_count == 0) {
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
     * iteration. The outer loop runs in the view's profile order — the user's
     * enabled-precedence position — so when two profiles share an ancestor
     * directory, the highest-precedence profile scans first and claims new files
     * via ws->diverged_index (subsequent profiles' scans skip the entry via the
     * dedup check in scan_directory_for_untracked).
     *
     * The dirs.count × ws->profile_count strcmp filter below is trivially
     * negligible (P ≤ 10, D ≤ 10²) and replaces a per-profile SQL query. */
    manifest_rows_t dirs = workspace_directories(ws);

    for (size_t p = 0; p < ws->profile_count; p++) {
        const char *profile = ws->profiles[p];

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

            /* An ancestor claim is not a scan root. The profile passes through
             * the directory on the way to something beneath it; its contents
             * are not the profile's to offer, and the nested-scan suppression
             * below would make the claim *replace* its own tracked descendants
             * as the root — so ~/.local/share, derived from one file under it,
             * would be walked whole and the walk would offer dotta's own repository
             * for adding. What the profile does manage inside such a directory
             * has its own tracked row, and this loop reaches that row directly. */
            if (!row->tracked) continue;

            /* Directory rows carry:
             * - filesystem_path: Already resolved with target (mount table)
             * - storage_path: Portable path for storage
             */

            /* Use filesystem path directly from the row (already resolved) */
            const char *filesystem_path = row->filesystem_path;

            /* The tracked directory must BE a directory, and must not stand beneath
             * a displaced one: anything else and every entry the readdir returns
             * comes from a tree that is not this path's, offered as new files
             * of this profile — opendir follows a symlinked root that lstat would
             * not, and beneath a displaced ancestor the whole path resolves through
             * the squatter. The lstat replaces the old existence probe (absence
             * still reads NONE) and closes the direct case whatever the command's
             * analyses; the displaced probe closes the nested one. */
            if (fs_lstat_occupant(filesystem_path, NULL) != FS_OCCUPANT_DIRECTORY) continue;
            if (workspace_displaced_ancestor(ws, filesystem_path)) continue;

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
 * Detects, for every directory row:
 * - DELETED state: Directory removed from filesystem
 * - DIVERGENCE_UNVERIFIED: Directory could not be stat'd (inaccessible)
 * - DIVERGENCE_TYPE: Something other than a directory stands at the path
 *
 * and for a tracked row alone — the profile's word about a directory it manages,
 * where an ancestor claim has none to give (the split is at the line itself):
 * - DIVERGENCE_MODE: Directory permissions changed
 * - DIVERGENCE_OWNERSHIP: Directory owner/group changed (requires root)
 * - A pending handover on a clean row: an item with no divergence, emitted so
 *   the reassignment is visible (the tail analyze_file_divergence has)
 *
 * ARCHITECTURE: Reads the view's directory rows, not metadata (Git) directly. A
 * row carries filesystem_path already resolved with target, enabling correct
 * divergence detection for custom/ prefix directories.
 *
 * Consumes ws->active_dirs from workspace_partition — every input is by
 * construction a directory row of the view. No scope checks: the class is the
 * only thing this loop asks of a row beyond its path.
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

        /* The record dotta keeps of this path, if any — the same pairing the
         * file analyzer makes. */
        const anchor_t *anchor = workspace_get_anchor(ws, filesystem_path);

        /* Reassignment, for the add-or-not decision at the bottom: an owned record
         * under a profile other than the row's — the same expression as
         * workspace_item_reassigned, its inputs in hand, the derivation the file
         * analyzer makes at its own pairing. One rule, both kinds: a pending
         * handover is apply's to acknowledge whatever the row's kind — of the
         * two directory classes, only the tracked one gets this far (below). */
        bool profile_changed = anchor && anchor->deployed_at > 0 &&
            strcmp(anchor->profile, row->profile) != 0;

        /* Stat directory to get current metadata
         *
         * One lstat, read as fs_lstat_occupant names it:
         * - NONE: Directory truly deleted, or a component above it is not a
         *   directory — nothing can be at the path either
         * - UNKNOWN: Inaccessible — state undeterminable, not absent
         * - Anything but DIRECTORY: Type changed (file, symlink - including broken
         *   ones)
         * - DIRECTORY: Actual directory, check metadata */
        struct stat dir_stat;
        fs_occupant_t occupant = fs_lstat_occupant(filesystem_path, &dir_stat);

        if (occupant == FS_OCCUPANT_NONE) {
            /* Absent path: classify_absent decides, and this is where its claim
             * gate earns its keep. An observed tracked directory was deleted by
             * the user (update propagates the removal); a never-observed one
             * was never there, and an ancestor claim asserts nothing to have
             * been deleted whatever its record says — apply's job is to create
             * it, never to commit a phantom deletion. The item is emitted either
             * way: deploy's ancestors pass reads absence off its occupant, not
             * its state. */
            err = workspace_add_diverged(
                ws,
                row,
                anchor,
                classify_absent(row, anchor),
                DIVERGENCE_NONE,          /* Divergence: none (path is absent) */
                occupant
            );

            if (err) {
                return error_wrap(
                    err, "Failed to record absent directory '%s'",
                    filesystem_path
                );
            }
            continue;  /* Successfully recorded, check next directory */
        }

        if (occupant == FS_OCCUPANT_UNKNOWN) {
            /* Inaccessible, not absent: record the uncertainty rather than dropping
             * the row, which left status reporting a clean workspace for a path
             * it had just failed to read. Same three-way policy as the file
             * rows. */
            err = workspace_add_diverged(
                ws,
                row,
                anchor,
                WORKSPACE_STATE_DEPLOYED,
                DIVERGENCE_UNVERIFIED,    /* Divergence: state undeterminable */
                occupant                  /* assumed present */
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
         * Type changes (dir -> file, dir -> symlink) are detected here because
         * the occupant is the link itself, never its target.
         *
         * Record DIVERGENCE_TYPE to enable:
         * - status shows [type] divergence
         * - preflight blocks without --force
         * - apply clears and recreates with --force
         */
        if (occupant != FS_OCCUPANT_DIRECTORY) {
            err = workspace_add_diverged(
                ws,
                row,
                anchor,
                WORKSPACE_STATE_DEPLOYED,  /* Path exists, just wrong type */
                DIVERGENCE_TYPE,           /* Type changed (dir -> file/symlink) */
                occupant                   /* path exists, wrong type */
            );

            if (err) {
                return error_wrap(
                    err, "Failed to record type change for directory '%s'",
                    filesystem_path
                );
            }
            continue;  /* Recorded, move to next directory */
        }

        /* An ancestor claim is a creation template, not a convergence target,
         * and this is the line the profile's word about the path begins at. Every
         * question above is asked of both classes: an unreadable path is a fact
         * about the path, the type question is the shadow guard's whole input —
         * a squatter above a managed path voids every observation beneath it
         * whether or not dotta manages the squatted path itself (collect_displaced,
         * core/deploy's ancestry rung) — and absence is what deploy's ancestors
         * pass reads off the item. Absence is the one whose ANSWER differs by
         * class, and it is not split here: classify_absent carries that gate,
         * so the two analyzers cannot read an absent path two ways.
         *
         * Everything below is the profile's word about a directory it manages,
         * and a derived claim has none to give. Its mode and ownership are a
         * snapshot of the machine the chain was captured on: they say what to
         * create the path as, never what to make of the one this machine already
         * has — asserting them here would let a ~/.ssh captured at a careless
         * 0755 loosen a correct 0700 elsewhere, a regression caused by the fix.
         * The handover tail goes with them: a claim nobody made carries no intent
         * to acknowledge, and the record keeps the profile dotta actually deployed
         * under, which is what a record is for. */
        if (!row->tracked) continue;

        /* One rule, three analyzers: the row's mode is total (claim or floor)
         * and a directory row is never a link, so the compare needs no gate. */
        bool mode_differs = (dir_stat.st_mode & 0777) != row->mode;
        bool ownership_differs = ownership_diverges(
            row->storage_path, row->owner, row->group, &dir_stat
        );

        /* Record divergence if any metadata differs, or a pending handover stands
         * (derived at the top, beside the record pairing) — the tail the file
         * analyzer has: a clean reassigned row emits an item, state DEPLOYED,
         * divergence NONE, so status's Reassigned section and apply's collection
         * see both kinds. */
        if (mode_differs || ownership_differs || profile_changed) {
            /* Accumulate divergence flags */
            divergence_type_t divergence = DIVERGENCE_NONE;
            if (mode_differs) divergence |= DIVERGENCE_MODE;
            if (ownership_differs) divergence |= DIVERGENCE_OWNERSHIP;

            err = workspace_add_diverged(
                ws,
                row,
                anchor,
                WORKSPACE_STATE_DEPLOYED,  /* State: directory exists as expected */
                divergence,                /* Divergence: mode/ownership flags */
                occupant
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
 * Collect the displaced directories from the load's own observations, and stamp
 * every item they reach
 *
 * A directory is displaced when a claim says a directory belongs at the path
 * and the load observed something else standing there. Both classes of directory
 * row qualify — the claim only has to say the path is a directory, not that the
 * profile manages it, since what an observation resolved through is the whole
 * question here — and so does a record the view lacks. The set is read off the
 * items: a DIRECTORY-kind item carrying DIVERGENCE_TYPE is exactly that
 * observation, and the bit's two producers (the directory analyzer's type arm,
 * the orphan analyzer's displaced arm) each stamp it only after ruling out absence
 * and an unstattable path — so the derivation costs no syscall, and the
 * one-producer rule cleanup.h states for the occupant holds for this fact too.
 * The two producers are the two authorities of the reach rule, and the item's
 * state says which: a DEPLOYED item is the directory analyzer's, over a view
 * row whose class names the claim; a RELEASED one is the orphan analyzer's, over
 * a record. An orphaned directory record with no item is not read off the disk
 * here: it exists only on a load that skipped the orphan analysis, and by the
 * reach rule a record's memory reaches nothing but the orphan items that same
 * analysis would have produced.
 *
 * Then the stamp: every present item takes the outermost displaced directory
 * that reaches it (workspace_item_t.displaced). Runs after every analysis has
 * observed its slice — the file analyzer runs before the directory analyzer
 * produces the squatter's item, so the fact cannot be stamped at emission — and
 * before the untracked scan, which must not open a directory whose path resolves
 * through a squatter (analyze_untracked_files) and whose items are therefore
 * never stamped. The view side is as complete as the directory analysis, which
 * every command's load runs (workspace_load_t — a load that routes items must
 * never read NULL over a squatter); the record side is complete exactly when
 * the orphan analysis ran, which is exactly when it has a reader. The list is
 * empty on every healthy load, and both passes are then one early return.
 */
static error_t *collect_displaced(workspace_t *ws) {
    size_t count = 0;

    for (size_t i = 0; i < ws->diverged.count; i++) {
        const workspace_item_t *item = ws->diverged.items[i];

        if (item->item_kind == PATH_KIND_DIRECTORY &&
            (item->divergence & DIVERGENCE_TYPE)) {
            count++;
        }
    }
    if (count == 0) {
        return NULL;
    }

    ws->displaced = arena_alloc(ws->arena, count * sizeof(*ws->displaced));
    if (!ws->displaced) {
        return ERROR(ERR_MEMORY, "Failed to allocate displaced directory list");
    }

    for (size_t i = 0; i < ws->diverged.count; i++) {
        const workspace_item_t *item = ws->diverged.items[i];

        if (item->item_kind != PATH_KIND_DIRECTORY ||
            !(item->divergence & DIVERGENCE_TYPE)) {
            continue;
        }

        /* The state names the authority: a DEPLOYED item is a view row's (the
         * join), so the row holds and its class is the claim's; anything else
         * here is the orphan analyzer's, over a record the view lacks. */
        ws->displaced[ws->displaced_count++] = (displaced_dir_t){
            .path = item->filesystem_path,
            .len = strlen(item->filesystem_path),
            .claim = item->state != WORKSPACE_STATE_DEPLOYED
                ? WORKSPACE_DISPLACED_RECORD
                : item->row->tracked
                ? WORKSPACE_DISPLACED_TRACKED
                : WORKSPACE_DISPLACED_DERIVED,
        };
    }

    /* The stamp: every present item takes the outermost displaced directory that
     * reaches it — the reach rule (workspace_displaced_t). Outermost among those
     * that reach, not outermost then tested: a DEPLOYED item beneath a
     * record-remembered rung and, deeper, a tracked squatter is displaced by
     * the tracked one. Absent items are never stamped — an absent reading beneath
     * a squatter is true: the lstat reached nothing, and there is no directory
     * for the path to exist in, so a deletion stays real work to commit and an
     * absent orphan a reclaim. Presence is the whole of the condition. */
    for (size_t i = 0; i < ws->diverged.count; i++) {
        workspace_item_t *item = ws->diverged.items[i];

        if (item->occupant == FS_OCCUPANT_NONE) continue;

        bool record_family = item->state == WORKSPACE_STATE_ORPHANED ||
            item->state == WORKSPACE_STATE_RELEASED;
        const displaced_dir_t *outer = NULL;

        for (size_t j = 0; j < ws->displaced_count; j++) {
            const displaced_dir_t *dir = &ws->displaced[j];

            if (dir->claim == WORKSPACE_DISPLACED_RECORD && !record_family) continue;
            if (str_path_beneath(item->filesystem_path, dir->path, dir->len) &&
                (!outer || dir->len < outer->len)) {
                outer = dir;
            }
        }
        item->displaced = outer ? outer->claim : WORKSPACE_DISPLACED_NONE;
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
 * Slice the view by kind, snapshot the record, and set the orphans aside
 *
 * The join at the centre of every load. The expected side — every enabled profile
 * at HEAD, both kinds, one row per path — is ws->manifest, the dispatcher's view;
 * its rows are split into ws->active_files / ws->active_dirs (+ counts) and each
 * slice is sorted by filesystem_path. Then the anchors snapshot
 * (state_get_all_anchors) is indexed by path as ws->anchor_index — the analyses
 * pair each row with its record through workspace_get_anchor, and the two writers
 * patch the index's values — and every record whose path the view lacks is
 * collected into ws->orphans, in the snapshot's path order. The prune orders
 * and the released copies load beside the record, unconditionally (the flush's
 * join needs both even when no analysis consults them).
 *
 * The partition is the single source of truth for "is this row in scope?": a
 * path is managed iff the view has a row for it, and a record is an orphan iff
 * it does not. The orphan analysis consumes ws->orphans; analyses over the active
 * set walk the active slices. No defensive cleanup on error: workspace_free is
 * the single cleanup authority.
 *
 * Lifetime: every pointer (the slices, the snapshot, the orphans array) lives
 * in ws->arena, beside the view's rows. The anchors index is heap-allocated,
 * freed in workspace_free through hashmap_free; the view's index is the
 * dispatcher's.
 *
 * Performance: O(M log M + A) — two sorts and one pass over the record; no Git,
 * no probes.
 */
static error_t *workspace_partition(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->arena);
    CHECK_NULL(ws->manifest);

    error_t *err = NULL;

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

    /* The prune orders, beside the record. Almost always empty; when not, the
     * membership index serves the honour arm the way the anchors index serves
     * the row pairing. */
    err = state_get_prune_orders(
        ws->state, ws->arena, &ws->orders, &ws->order_count
    );
    if (err) {
        return error_wrap(err, "Failed to read prune orders from state");
    }

    if (ws->order_count > 0) {
        ws->order_index = hashmap_borrow(ws->order_count);
        if (!ws->order_index) {
            return ERROR(ERR_MEMORY, "Failed to create order index");
        }
        for (size_t i = 0; i < ws->order_count; i++) {
            err = hashmap_set(ws->order_index, ws->orders[i], ws->orders[i]);
            if (err) {
                return error_wrap(err, "Failed to populate order index");
            }
        }
    }

    /* The released copies, the same way. */
    err = state_get_released_copies(
        ws->state, ws->arena, &ws->released, &ws->released_count
    );
    if (err) {
        return error_wrap(err, "Failed to read released copies from state");
    }

    if (ws->released_count > 0) {
        ws->released_index = hashmap_borrow(ws->released_count);
        if (!ws->released_index) {
            return ERROR(ERR_MEMORY, "Failed to create released index");
        }
        for (size_t i = 0; i < ws->released_count; i++) {
            err = hashmap_set(
                ws->released_index, ws->released[i].filesystem_path, &ws->released[i]
            );
            if (err) {
                return error_wrap(err, "Failed to populate released index");
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
    state_t *state,
    const config_t *config,
    content_cache_t *content_cache,
    const manifest_t *manifest,
    const workspace_load_t *options,
    arena_t *arena,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(content_cache);
    CHECK_NULL(manifest);
    CHECK_NULL(options);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    workspace_t *ws = NULL;
    error_t *err = NULL;

    /* The workspace's profile set is the view's — the persistent enabled set
     * the view was built over, never a CLI filter: `dotta status -p global` loads
     * the whole workspace and filters at display time. */
    err = workspace_create_empty(repo, manifest, &ws);
    if (err) {
        return err;
    }

    /* Borrow caller-owned resources. Lifetime guarantees: state comes from
     * ctx->run.state (command-scoped); content_cache comes from
     * ctx->run.content_cache (command-scoped, wraps ctx->run.keymgr); manifest
     * is ctx->run.manifest (the view the dispatcher built over the enabled set,
     * command-scoped); arena is ctx->arena (command-scoped). All four must outlive
     * workspace_free. */
    ws->state = state;
    ws->content_cache = content_cache;
    ws->manifest = manifest;
    ws->arena = arena;

    /* Slice the view, snapshot the record and set the orphans aside. The partition
     * populates workspace fields directly; consumers read via workspace_files()
     * / workspace_directories() / workspace_lookup() and pair rows with their
     * records through workspace_get_anchor(). The view was computed from Git at
     * dispatch, so it is current by construction — nothing upstream repairs
     * anything. */
    err = workspace_partition(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to partition workspace");
    }

    /* Execute analyses based on the options. Each analysis is independently
     * controllable for optimal performance. */

    /* Analyze file divergence (most common requirement) */
    if (options->analyze_files) {
        err = analyze_files_divergence(ws, config);
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

    /* Analyze directory metadata divergence */
    if (options->analyze_directories) {
        err = analyze_directory_metadata_divergence(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze directory metadata");
        }
    }

    /* The displaced directories, derived from the observations above, and the
     * stamp on every item they reach: the fact every consumer that judges a path
     * beneath one must ask, established here once and trusted downstream.
     * Unconditional — the view side must hold on every load that routes items,
     * and the record side on every load that produced orphan items. */
    err = collect_displaced(ws);
    if (err) {
        workspace_free(ws);
        return err;
    }

    /* Analyze tracked directories for untracked files */
    if (options->analyze_untracked) {
        err = analyze_untracked_files(ws, config);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze untracked files");
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
workspace_items_t workspace_get_all_diverged(const workspace_t *ws) {
    if (!ws) {
        return (workspace_items_t) { 0 };
    }

    return workspace_items_view(&ws->diverged);
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

    return hashmap_get(ws->diverged_index, filesystem_path);
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
 * The displaced managed directory above `path`, or NULL — the view's claims
 */
const char *workspace_displaced_ancestor(const workspace_t *ws, const char *path) {
    if (!ws || !path) {
        return NULL;
    }

    const displaced_dir_t *outermost = NULL;

    /* The shortest match is the outermost ancestor: a deeper displaced directory
     * was itself observed through the outer one, so the outer occupant's fate
     * settles both. The list is unordered — two analyses fill it — so the scan
     * asks for the minimum rather than the first hit. A record's memory is skipped:
     * it reaches only the record family, whose items carry the fact themselves
     * (the reach rule, workspace_displaced_t). */
    for (size_t i = 0; i < ws->displaced_count; i++) {
        const displaced_dir_t *dir = &ws->displaced[i];

        if (dir->claim == WORKSPACE_DISPLACED_RECORD) continue;
        if (str_path_beneath(path, dir->path, dir->len) &&
            (!outermost || dir->len < outermost->len)) {
            outermost = dir;
        }
    }

    return outermost ? outermost->path : NULL;
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
 * Decide which verb's work a deployed item is
 *
 * The table and its rationale are in workspace.h — kept in one place, where a
 * caller reading the enum finds them.
 */
workspace_route_t workspace_item_route(const workspace_item_t *item) {
    divergence_type_t divergence = item->divergence;

    /* An observation taken through a squatter the view claims is void: no bit
     * below was read off this path's tree — deploy's ANCESTOR rung and
     * cleanup_verdict's displaced arm rank the same fact the same way. RECORD
     * never stands on a deployed item (the reach rule), so the two view classes
     * are the whole test and falling through is what a record's memory says of
     * a view row. */
    if (item->displaced == WORKSPACE_DISPLACED_TRACKED) {
        return WORKSPACE_ROUTE_DISPLACED_TRACKED;
    }
    if (item->displaced == WORKSPACE_DISPLACED_DERIVED) {
        return WORKSPACE_ROUTE_DISPLACED_DERIVED;
    }

    /* A bit the analysis could not settle outranks the ones it could */
    if (divergence & DIVERGENCE_UNVERIFIED) {
        return WORKSPACE_ROUTE_UNVERIFIABLE;
    }

    /* Git moved past the deployed blob: a real edit beside it means both sides
     * moved; alone — mode riders included — the bytes are apply's */
    if (divergence & DIVERGENCE_STALE) {
        return (divergence & DIVERGENCE_CONTENT) ? WORKSPACE_ROUTE_CONFLICT
                                                 : WORKSPACE_ROUTE_STALE;
    }

    /* A kind mismatch is a capture only through the one pair the copy can commit:
     * file ↔ symlink on a file row. Every other occupant is no verb's default,
     * and a directory row's splits by the claim that holds the path: a tracked
     * row is the plan's (--force replaces the squatter), a derived rung is never
     * planned (the named re-derivation drops the claim). A deployed item is a
     * view row's (the join), so the row holds; a file row's tracked field is a
     * don't-care, so the kind gates the read. */
    if ((divergence & DIVERGENCE_TYPE) &&
        (item->item_kind == PATH_KIND_DIRECTORY ||
        (item->occupant != FS_OCCUPANT_REGULAR &&
        item->occupant != FS_OCCUPANT_SYMLINK))) {
        return (item->item_kind == PATH_KIND_DIRECTORY && !item->row->tracked)
               ? WORKSPACE_ROUTE_KIND_DERIVED : WORKSPACE_ROUTE_KIND;
    }

    if (divergence != DIVERGENCE_NONE) {
        return WORKSPACE_ROUTE_CAPTURE;
    }

    return workspace_item_reassigned(item) ? WORKSPACE_ROUTE_REASSIGNED
                                           : WORKSPACE_ROUTE_CLEAN;
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

            /* An encryption-policy violation is the one divergence bit that still
             * means something with nothing on disk: the blob apply is about to
             * write is plaintext the policy says to encrypt, and this is the
             * last screen before it lands. Magenta outright — cyan is the colour
             * for work that costs the user nothing, and this does. The DELETED
             * arm stays bare: a deletion resolves the violation rather than
             * carrying it out. */
            if (item->divergence & DIVERGENCE_ENCRYPTION) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "unencrypted";
                }
                *color_out = OUTPUT_COLOR_MAGENTA;
            }

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
            if (workspace_item_reassigned(item)) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "reassigned";
                }
                snprintf(
                    metadata_buf, metadata_size, "%s → %s",
                    item->anchor->profile, item->profile
                );
            } else {
                snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            }
            break;

        case WORKSPACE_STATE_DEPLOYED: {
            if (item->displaced != WORKSPACE_DISPLACED_NONE) {
                /* Observed through a squatter (workspace_displaced_t): every
                 * divergence bit was read off the squatter's target, so none of
                 * the tags below is true of this path — [modified] on a stranger's
                 * bytes would name work no verb takes. The one tag, at the default
                 * colour: the squatter's own row carries the severity, and the
                 * route lists this item under it. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "displaced";
                }
            } else {
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
                     * work — the same CYAN as [undeployed], nothing of the user's
                     * is overwritten; next to [modified] it names a conflict
                     * and the primary tag's colour stands. */
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
                 *       DIVERGENCE_TYPE) && tag_count > 0) prevents MODE from
                 *       showing when TYPE is the primary tag
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
                    /* Upgrade color to MAGENTA if still default (not TYPE
                     * divergence) This gives encryption issues special visual
                     * treatment */
                    if (*color_out == OUTPUT_COLOR_YELLOW) {
                        *color_out = OUTPUT_COLOR_MAGENTA;
                    }
                }

                if (item->divergence & DIVERGENCE_UNVERIFIED) {
                    /* The failed look: an unstattable path, or content that could
                     * not be loaded, decrypted, or compared. Conservative handling
                     * downstream (update refuses it, apply surfaces the real
                     * error, cleanup skips the orphan). */
                    if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                        tags_out[tag_count++] = "unverified";
                    }
                    /* Upgrade color to MAGENTA (special visual treatment for
                     * unverifiable state) */
                    if (*color_out == OUTPUT_COLOR_YELLOW) {
                        *color_out = OUTPUT_COLOR_MAGENTA;
                    }
                }
            }

            /* Profile reassignment tag (can coexist with divergence tags, and
             * with [displaced]: the record against the row, no observation
             * involved)
             *
             * Added after divergence tags as secondary information. Color only
             * set for pure reassignment (sole tag) to avoid overriding
             * severity-based colors from divergence. */
            if (workspace_item_reassigned(item)) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "reassigned";
                }
                if (tag_count == 1) {
                    *color_out = OUTPUT_COLOR_CYAN;
                }

                snprintf(
                    metadata_buf, metadata_size, "%s → %s",
                    item->anchor->profile, item->profile
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
            if (item->occupant == FS_OCCUPANT_NONE) {
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

            } else if (item->divergence & DIVERGENCE_TYPE) {
                /* A file ↔ symlink ↔ device swap at the path (a directory in a
                 * file's place is released, not orphaned). Apply skips it
                 * (cleanup_skip_reason: TYPE_CHANGED); the DEPLOYED arm and apply's
                 * preview use the same word. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "type";
                }
                *color_out = OUTPUT_COLOR_RED;

            } else if (item->divergence & DIVERGENCE_CONTENT) {
                /* Content divergence - blocking issue Apply skips it
                 * (cleanup_skip_reason: MODIFIED). */
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

            /* The relocation, ridden as a secondary tag beside the divergence
             * tags (the way [reassigned] rides on DEPLOYED): the record's claim
             * still has a row, projected elsewhere — item->row IS the fact
             * (workspace.h). The fate stays cleanup's (a re-targeted custom/
             * copy prunes, a moved home holds behind --force); this only names
             * what the copy is. */
            if (item->row) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "relocated";
                }
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
            /* Released from management — Git let the path go, dotta never deployed
             * it, or another kind of path stands in its place. The path is left
             * on disk, the record retires. Always present: the orphan analysis
             * decides presence first, so an absent record never reaches this
             * state. */
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "released";
            }
            *color_out = OUTPUT_COLOR_MAGENTA;

            if (item->divergence & DIVERGENCE_TYPE) {
                /* The third reason, named: a directory where dotta's file was,
                 * or a file, a link, a device where dotta's directory was. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "type";
                }
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
 *
 * A record created here backfills the path's item, if analysis produced one:
 * item->anchor is the live record, always — the invariant every derivation reads
 * through (workspace.h).
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
    };

    err = hashmap_set(ws->anchor_index, anchor->filesystem_path, anchor);
    if (err) {
        return error_wrap(err, "Failed to index observation record");
    }

    workspace_item_t *item = hashmap_get(
        ws->diverged_index, anchor->filesystem_path
    );
    if (item) {
        item->anchor = anchor;
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
 *
 * Either arm keeps item->anchor the live record: patching in place rewrites the
 * object the path's item already borrows, and a record created here backfills
 * the item, if analysis produced one.
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

    workspace_item_t *item = hashmap_get(
        ws->diverged_index, anchor->filesystem_path
    );
    if (item) {
        item->anchor = anchor;
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
 * The joins, last — each fact's lifetime rule, enforced where the view, the record
 * and both fact sets are in hand: every prune order whose path the view has is
 * void, and every released copy whose path's record again carries a confirmed
 * blob (post-patch) is forgotten.
 *
 * Begins its own transaction only when state isn't already in one
 * (status/diff/sync). Apply always passes state already-in-transaction.
 */
error_t *workspace_flush_updates(workspace_t *ws) {
    CHECK_NULL(ws);

    /* The joins' pending work, counted up front so the gate below is exact: a
     * pure-join flush (nothing observed, nothing confirmed, one stale order or
     * subsumed released row) still takes its scoped transaction, and the common
     * all-empty flush still costs nothing. One loop over each almost-always-empty
     * set. The released count is read against the pre-patch snapshot — exact
     * here, because with zero confirmations nothing below patches a record; with
     * any, the gate passes regardless and the join re-reads post-patch. */
    size_t pending_voids = 0;
    for (size_t i = 0; i < ws->order_count; i++) {
        if (manifest_lookup(ws->manifest, ws->orders[i])) pending_voids++;
    }
    size_t pending_forgets = 0;
    for (size_t i = 0; i < ws->released_count; i++) {
        const anchor_t *anchor =
            hashmap_get(ws->anchor_index, ws->released[i].filesystem_path);
        if (anchor && !git_oid_is_zero(&anchor->blob_oid)) pending_forgets++;
    }

    if (ws->observation_count == 0 && ws->confirmation_count == 0 &&
        pending_voids == 0 && pending_forgets == 0) {
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
        }
    }

    /* The joins: each fact's lifetime rule, enforced where the view, the record
     * and both fact sets are in hand.
     *
     * An order lives only while its path is out of the view, so every order whose
     * path the view has is void — the removal it answered was reverted (a revert,
     * a sync pulling the path back, an enable providing it), verified or not.
     * Left standing, the order would outlive the removal and prune the copy at
     * the next scope exit instead of the probe releasing it; voided here, a later
     * discovered departure executes as a release, which is the stated policy
     * for every discovered departure. */
    for (size_t i = 0; i < ws->order_count; i++) {
        if (!manifest_lookup(ws->manifest, ws->orders[i])) continue;

        error_t *err = state_void_prune_order(ws->state, ws->orders[i]);
        if (err) {
            if (needs_transaction) {
                state_rollback(ws->state);
            }
            return error_wrap(
                err, "Failed to void prune order for '%s'", ws->orders[i]
            );
        }
    }

    /* A released copy is subsumed once its path's record again carries a confirmed
     * blob — the record is then the base and the row is redundant (or false:
     * the fresher confirmation says what disk holds now). Read against the
     * post-patch snapshot — the confirmation loop above has advanced it — so a
     * released-base fast-path hit forgets its row in the same flush that confirms
     * it. Lazily covers every route back to managed, add/update's workspace-less
     * captures included: their row dies at the next flush-bearing load, and until
     * then the base derivation's no-confirmed-blob predicate shadows it
     * correctly. */
    for (size_t i = 0; i < ws->released_count; i++) {
        const anchor_t *anchor =
            hashmap_get(ws->anchor_index, ws->released[i].filesystem_path);
        if (!anchor || git_oid_is_zero(&anchor->blob_oid)) continue;

        error_t *err = state_forget_released(ws->state, ws->released[i].filesystem_path);
        if (err) {
            if (needs_transaction) {
                state_rollback(ws->state);
            }
            return error_wrap(
                err, "Failed to forget released copy for '%s'",
                ws->released[i].filesystem_path
            );
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

    /* Free the diverged spine (the items and their strings are arena-backed) */
    ptr_array_deinit(&ws->diverged);

    /* Free the observation and confirmation arrays (row pointers are borrowed
     * from the view) */
    free(ws->observations);
    free(ws->confirmations);

    /* Free indices (values are borrowed, so pass NULL for value free function).
     * anchor_index values are records in ws->arena — also borrowed, as are the
     * order index's arena paths and the released index's rows. */
    hashmap_free(ws->diverged_index, NULL);
    hashmap_free(ws->anchor_index, NULL);
    hashmap_free(ws->order_index, NULL);
    hashmap_free(ws->released_index, NULL);

    /* The view is borrowed (the dispatcher's); the slices, the snapshot and the
     * orphans array are arena-allocated and the caller's arena releases them
     * when destroyed. ws->arena is borrowed — never destroyed here. */

    free(ws);
}
