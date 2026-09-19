/**
 * workspace.c - Workspace abstraction implementation
 *
 * The join of the view (Git), the record (the store's dotta.db) and the filesystem.
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
#include <errno.h>
#include <grp.h>
#include <limits.h>
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
#include "infra/label.h"
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
 * And the row is the record's own claim: the blob a record carries is the blob
 * of the claim it names (core/state.h anchor_t), which is what makes it readable
 * at all when it is encrypted. A row that is not the record's claim records nothing
 * — see workspace_record_confirmation.
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
 * A displaced directory, and whose claim holds it
 *
 * A claim says a directory belongs at the path and the load observed something
 * else standing there. The two producers are the two authorities of the reach
 * rule (workspace_displaced_t): the directory analyzer's type arm, over a view
 * row whose class names the claim, and the orphan analyzer's retyped arm, over
 * a directory record. Each notes its own where it observed it (note_displaced),
 * so the claim is the producer's and is never read back off an item. The path
 * is the row's or the record's (borrowed), its length hoisted for the one
 * outermost-match scan (displaced_ancestor).
 */
typedef struct {
    const char *path;             /* The row's or the record's filesystem_path (borrowed) */
    size_t len;                   /* strlen(path), hoisted for str_path_beneath */
    workspace_displaced_t claim;  /* TRACKED / DERIVED (a view row's), RECORD (a record's) */
} displaced_dir_t;

/**
 * One entry the load knows, and what stands on it
 *
 * An entry is a name in a directory; a key is one spelling of it, and the two
 * facts the load holds about a path — a row of the view, a record — are keyed
 * by spelling. This is the one place the load reads the entry itself: the (dev,
 * ino) one lstat of the key gave, beside the row observed at that key or the
 * orphan record that remembers it. Exactly one of the two is set, because the
 * index is filled in two passes over two disjoint sets — the view's rows stand
 * at their own keys, and an orphan record is by definition a key no row stands at.
 *
 * Built once per load for the two verbs that act on an entry through a string
 * (index_entries), met by identity (find_entries) and never by string: both readers
 * asked the strings first, and this answers only where they could not. The
 * carriers' `.entries` (manifest_rows_t, workspace_items_t) are their own elements;
 * these are the disk's.
 */
typedef struct {
    dev_t dev;                     /* The entry, from one lstat of the key */
    ino_t ino;
    const manifest_row_t *row;     /* The view's row standing on it, or NULL */
    const anchor_t *anchor;        /* The orphan record standing on it, or NULL */
} entry_t;

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
     * split by kind and sorted, so deploy's parent-before-child walk sees prefix
     * order. Pointer arrays into the view (arena-allocated). */
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

    /* The record's handle: the store's database, borrowed from the caller
     * (workspace_load). Read once at the partition for the three snapshots above,
     * then written through by the two live writers (workspace_observe,
     * workspace_anchor) and the flush, each patching the snapshot it persists. */
    state_t *state;                              /* The record's handle (borrowed from caller) */

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
     * the load observed occupied by anything else, with the claim. Noted by each
     * analysis where it observed one (note_displaced), asked before every look
     * the load takes after it and by the one producer of items (displaced_ancestor,
     * workspace_item_t.displaced); arena-backed, paths borrowed from the rows
     * and the records. Almost always empty, which is what makes every ask free. */
    displaced_dir_t *displaced;                  /* One per displaced directory; NULL until the first */
    size_t displaced_count;

    /* The entries: every winning row observed at its own key and every orphan
     * record, by the (dev, ino) that key names — the load's one look at the disk
     * by identity, for the two verbs that act on an entry through a string:
     * cleanup's unlink (the orphan analysis's guard) and the scan's offer (the
     * leaf probe). Sorted by identity; built by index_entries only on a load
     * one of the two may ask in, else NULL and none. */
    entry_t *entries;                            /* Arena; sorted by (dev, ino) */
    size_t entry_count;

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
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    workspace_t *ws = calloc(1, sizeof(workspace_t));
    if (!ws) {
        return ERROR(ERR_MEMORY, "Failed to allocate workspace");
    }

    ws->repo = repo;

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
 * and directory analyzers. What the sheet says here is the sheet's to say
 * (core/metadata.h metadata_ownership) and this function is the comparison alone,
 * one per reading: the names it claimed, and only those, are compared by name
 * (NULL skips that half), and a UID/GID the system cannot resolve to one reads
 * as divergence — unknown ≠ expected (security-first); silence the sheet reads
 * as the invoker's own compares the owner to the invoker; and silence it says
 * nothing about compares nothing. Whether this run could chown does not enter —
 * the lstat needs no privilege, and a claim the disk contradicts is a fact about
 * the path whoever reads it.
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
    /* The sheet's word first: an absent claim is answered by the namespace it
     * stands in, a present one by the names below. */
    switch (metadata_ownership(storage_path, owner, group)) {
        case OWNERSHIP_SILENT:
            return false;
        case OWNERSHIP_INVOKER:
            return st->st_uid != identity()->uid;
        case OWNERSHIP_NAMED:
            break;
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
 * Class a failed look by whose remedy it is
 *
 * The root's code, and nothing else (workspace.h, workspace_fault_t): ERR_LOCKED
 * is the run's key, ERR_PERMISSION is root's, and everything else is a refusal
 * dotta cannot name one remedy for. The root, not the top — the layers above it
 * added the subject the row already names, and the code the producer chose is
 * the root's (crypto/keymgr.h, "The codes").
 */
static workspace_fault_t fault_class(error_code_t code) {
    switch (code) {
        case ERR_LOCKED:     return WORKSPACE_FAULT_LOCKED;
        case ERR_PERMISSION: return WORKSPACE_FAULT_UNREADABLE;
        default:             return WORKSPACE_FAULT_UNVERIFIED;
    }
}

/**
 * Class a failed look's error, and consume it
 *
 * The class is all the item keeps: the message is the failing verb's to print,
 * and this analysis is not failing — it is reporting a path it could not read.
 * Five folds call this, each holding the error of the look it just made.
 */
static workspace_fault_t fault_of(error_t *err) {
    workspace_fault_t fault = fault_class(error_code(error_root(err)));
    error_free(err);
    return fault;
}

/**
 * The displaced directory that reaches `path`, or NULL — the reach rule as a scan
 *
 * Proper ancestors only (str_path_beneath is strict), so a squatter is never
 * its own answer, and the outermost among those that reach the asker: the shortest
 * match, because the true offender is the one whose fate settles every claim
 * beneath it. The list is unordered — two analyses fill it — so the scan asks
 * for the minimum rather than the first hit. Whose claims reach the asker is
 * the rule's one input: a view claim reaches every path beneath it, a record's
 * memory (WORKSPACE_DISPLACED_RECORD) the record family alone
 * (workspace_displaced_t).
 *
 * Nothing beneath a squatter that reaches it is looked at, so nothing there is
 * ever noted: the list holds no view claim beneath a view claim and no record
 * claim beneath anything. It can hold a view claim beneath a record claim — a
 * directory row beneath a retyped directory record is looked at, the record's
 * memory not reaching it, and may be a squatter of its own — so the minimum is
 * load-bearing for an orphan beneath both, and costs the same scan either way.
 *
 * Empty on every healthy load, which is what makes every ask free.
 *
 * Readers: the three analyzers, before every look they take
 * (analyze_file_divergence, analyze_directory_metadata_divergence,
 * analyze_orphans), workspace_add_diverged, which classes the fact onto every
 * item, and workspace_displaced_ancestor, the view-only face for a path with no
 * item in hand.
 *
 * @param ws Workspace (must not be NULL)
 * @param path The asker's path (must not be NULL)
 * @param record_family Whether the asker is a record of the orphan family
 */
static const displaced_dir_t *displaced_ancestor(
    const workspace_t *ws,
    const char *path,
    bool record_family
) {
    const displaced_dir_t *outermost = NULL;

    for (size_t i = 0; i < ws->displaced_count; i++) {
        const displaced_dir_t *dir = &ws->displaced[i];

        if (dir->claim == WORKSPACE_DISPLACED_RECORD && !record_family) continue;
        if (str_path_beneath(path, dir->path, dir->len) &&
            (!outermost || dir->len < outermost->len)) {
            outermost = dir;
        }
    }

    return outermost;
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
 * Two verdicts are decided here rather than handed in, each a reading of what
 * this function already holds and of nothing else: a relocation's class
 * (workspace_relocation_t), read off the two sources, and the displaced class
 * (workspace_displaced_t), read off the squatters noted so far against this item's
 * own path and the family its state names. The second is what makes the class
 * total — no item can carry the wrong one, and none can be missing it. That every
 * displaced item was also spared its look is the analyzers' half, asked before
 * every look they take, and the two halves meet here: an item that carries a
 * class is an item with nothing measured.
 *
 * @param ws Workspace context (must not be NULL)
 * @param row The view's claim (NULL for orphans — except a relocated one, whose
 *            row is the same claim's at its new filesystem path)
 * @param anchor The record (NULL when the path has no record)
 * @param state Where the item exists (deployed/undeployed/etc.)
 * @param divergence What's wrong with it (bit flags, can combine)
 * @param occupant What the producer's lstat found at the path (workspace.h)
 * @param fault Whose remedy the failed look is — NONE unless the divergence carries
 *              DIVERGENCE_UNVERIFIED, which is the fold's invariant
 */
static error_t *workspace_add_diverged(
    workspace_t *ws,
    const manifest_row_t *row,
    const anchor_t *anchor,
    workspace_state_t state,
    divergence_type_t divergence,
    fs_occupant_t occupant,
    workspace_fault_t fault
) {
    CHECK_NULL(ws);

    /* Arena-allocated: the item's address is stable for the workspace's lifetime,
     * whatever the spine's growth does. */
    workspace_item_t *item = arena_alloc(ws->arena, sizeof(*item));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate diverged item");
    }
    memset(item, 0, sizeof(*item));

    item->row = row;
    item->anchor = anchor;

    /* The state names the identity source: ORPHANED/RELEASED are record-defined
     * — the view lacks the path — and every other state here is a row's. The
     * same reading names the family the reach rule asks for below. */
    bool record_family = state == WORKSPACE_STATE_ORPHANED ||
        state == WORKSPACE_STATE_RELEASED;

    if (record_family) {
        CHECK_NULL(anchor);
        item->filesystem_path = anchor->filesystem_path;
        item->storage_path = anchor->storage_path;
        item->profile = anchor->profile;
        item->item_kind = path_type_kind(anchor->type);
    } else {
        CHECK_NULL(row);
        item->filesystem_path = row->filesystem_path;
        item->storage_path = row->storage_path;
        item->profile = row->profile;
        item->item_kind = path_type_kind(row->type);
    }

    /* A row on an ORPHANED item is the relocation: the record's own claim, still
     * in the view, standing at another path (analyze_orphans). Which of the two
     * kinds of relocation it is, is the mounting rule of the namespace the claim
     * is named in — the label alone, and no place: a root's binder answers which
     * profile bound that one root, where the question here is whether the namespace
     * is anyone's to re-target (infra/mount.h mount_root_t). The record's name
     * and the row's are one string (manifest_lookup_storage matches it exactly),
     * and a name the view holds was validated where the branch was read, so the
     * projection below asserts nothing not already established. */
    if (row && state == WORKSPACE_STATE_ORPHANED) {
        switch (label_of(item->storage_path)) {
            case LABEL_HOME:
            case LABEL_ROOT:
                item->relocation = WORKSPACE_RELOCATION_SHARED;
                break;
            case LABEL_CUSTOM:
                item->relocation = WORKSPACE_RELOCATION_BOUND;
                break;
        }
    }

    item->state = state;
    item->divergence = divergence;
    item->occupant = occupant;
    item->fault = fault;

    /* Whose squatter stands above the path, or NONE (see the doc above). Read
     * after identity, because the path is the question's subject. */
    const displaced_dir_t *above = displaced_ancestor(
        ws, item->filesystem_path, record_family
    );
    item->displaced = above ? above->claim : WORKSPACE_DISPLACED_NONE;

    error_t *err = ptr_array_push(&ws->diverged, item);
    if (err) {
        return error_wrap(err, "Failed to append diverged item");
    }

    err = hashmap_set(ws->diverged_index, item->filesystem_path, item);
    if (err) {
        return error_wrap(err, "Failed to index diverged item");
    }

    return NULL;
}

/**
 * Add an untracked item — the one producer with neither source
 *
 * The untracked scan found a new file inside a tracked directory: no row (the
 * view does not claim the path), no record (dotta has no memory of having managed
 * it). The walk's leaf guard asks the view and the record, by string and by entry,
 * so a path either of them holds under any spelling never reaches here. State,
 * divergence and kind are the constants of the state.
 *
 * This is the one door the walk's strings leave their frame through, and it copies
 * them rather than aliasing: the location the walk joined and the name the namer
 * answered live in a frame's scratch arena that the frame's next entry reclaims,
 * while ws->diverged_index borrows the key it is handed (base/hashmap.h) and
 * the item outlives every frame. The profile is the owner's — the row's own,
 * whose tracked directory the walk began at — and is the view's arena's already.
 *
 * No earlier item stands at the path: the view's and the record's paths were
 * skipped at the leaf guard, and no directory is enumerated twice (one scan root
 * per directory, analyze_untracked_files), so the index takes the key fresh.
 * Stated rather than guarded — hashmap_set overwrites in silence — and pinned
 * by the exactly-once fixtures (tests/test-scan.sh).
 *
 * @param ws Workspace context (must not be NULL)
 * @param filesystem_path The location the walk joined (must not be NULL)
 * @param storage_path The name the namer answered (must not be NULL)
 * @param profile The owner's, the view's row's (must not be NULL)
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

    workspace_item_t *item = arena_alloc(ws->arena, sizeof(*item));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate untracked item");
    }
    memset(item, 0, sizeof(*item));

    item->filesystem_path = arena_strdup(ws->arena, filesystem_path);
    item->storage_path = arena_strdup(ws->arena, storage_path);
    item->profile = (char *) profile;   /* the cast discards the view's const */
    if (!item->filesystem_path || !item->storage_path) {
        return ERROR(ERR_MEMORY, "Failed to copy untracked paths");
    }

    item->state = WORKSPACE_STATE_UNTRACKED;
    item->divergence = DIVERGENCE_NONE;
    item->item_kind = PATH_KIND_FILE;
    item->occupant = occupant;

    error_t *err = ptr_array_push(&ws->diverged, item);
    if (err) {
        return error_wrap(err, "Failed to append untracked item");
    }

    err = hashmap_set(ws->diverged_index, item->filesystem_path, item);
    if (err) {
        return error_wrap(err, "Failed to index untracked item");
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
 * A confirmation belongs to the claim the record names, and this is where that
 * is enforced (core/state.h state_confirm's precondition): the blob it advances
 * is that claim's, and an encrypted blob opens under one (profile, storage path)
 * pair and no other, so a confirmation taken from another row would leave the
 * record carrying a blob no reader — this analysis's own base least of all —
 * can place. A row that is not the record's claim is a pending handover: apply's
 * acknowledgement is what moves the record onto it, and until then the path takes
 * the slow path on every load, which is the price of a record that means one
 * thing. A path with no record yet is confirmed from this row like any other:
 * the flush observes before it confirms, and the record it creates is this row's.
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
 * @param anchor The record dotta keeps of the path, or NULL when it has none
 * @param st Verified filesystem stat
 */
static void workspace_record_confirmation(
    workspace_t *ws,
    const manifest_row_t *row,
    const anchor_t *anchor,
    const struct stat *st
) {
    if (anchor && !manifest_is_claim(row, anchor->profile, anchor->storage_path)) {
        return;
    }

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
 * Note a displaced directory where the load observed it
 *
 * A claim says a directory belongs at the path and the load found something else
 * standing there. Two producers, the two authorities of the reach rule
 * (workspace_displaced_t): the directory analyzer's type arm over a view row,
 * whose class names the claim, and the orphan analyzer's retyped arm over a
 * directory record. Each notes its own inside the arm that decided, where the
 * claim and the look are both in hand and the arms above have already ruled out
 * absence and an unstattable path — so the note costs no look of its own, and
 * the fact keeps the one producer per authority that cleanup.h states for the
 * occupant.
 *
 * Each half is complete before anything asks it. The view's is complete after
 * the directory analysis, which every command's load runs first for that reason
 * (workspace_load_t) and which walks its rows parents-first, so a squatter above
 * a row is noted before the row's own turn. The record's fills as the orphan
 * analysis walks, in path order, so a retyped directory record is noted before
 * any record beneath it comes up — and that is exactly when it has a reader,
 * since a load that skips the orphan analysis emits no orphan item either and a
 * record's memory reaches nothing else (the reach rule).
 *
 * Nothing beneath a squatter is looked at, so no squatter beneath one is ever
 * noted: the outermost carries the whole answer, and the list holds one entry
 * per episode rather than one per rung.
 *
 * One arena block, taken at the first note and sized for every claim that could
 * say a directory stands somewhere — the view's directory rows and the records
 * the view lacks, both counted by the partition and fixed before any analysis
 * runs. A healthy load allocates nothing, and a third producer would have to be
 * over one of those two sets, because that is what the fact is about.
 *
 * Fallible, where the two recorders above are not: a dropped confirmation or
 * observation costs a deferral the next load re-derives, and a dropped displaced
 * directory costs a verdict — every item beneath the squatter would be judged
 * on an observation that resolved through it. The failure is the workspace's
 * own allocation and not a fact about the path, so neither producer wraps it
 * with one.
 *
 * Readers: displaced_ancestor, asked before every look the load takes
 * (analyze_file_divergence, analyze_directory_metadata_divergence,
 * analyze_orphans) and by the one producer of items (workspace_add_diverged);
 * and through workspace_displaced_ancestor by index_entries,
 * analyze_untracked_files' roots, core/deploy.c check_ancestry and cmds/apply.c's
 * released-copies sweep.
 *
 * @param ws Workspace (must not be NULL)
 * @param path The squatted path, the row's or the record's (borrowed; workspace
 *             lifetime)
 * @param claim Whose claim holds it (workspace_displaced_t)
 */
static error_t *note_displaced(
    workspace_t *ws,
    const char *path,
    workspace_displaced_t claim
) {
    if (!ws->displaced) {
        size_t cap = ws->active_dir_count + ws->orphan_count;

        ws->displaced = arena_alloc(ws->arena, cap * sizeof(*ws->displaced));
        if (!ws->displaced) {
            return ERROR(ERR_MEMORY, "Failed to allocate displaced directory list");
        }
    }

    ws->displaced[ws->displaced_count++] = (displaced_dir_t){
        .path = path,
        .len = strlen(path),
        .claim = claim,
    };

    return NULL;
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
    if (manifest_is_derived(row)) {
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

    /* The blob-family verdict (see the doc above): is the blob Git holds for
     * this row stored plaintext where the auto-encrypt policy claims the path?
     * DIVERGENCE_NONE or DIVERGENCE_ENCRYPTION, carried by every return below. */
    divergence_type_t policy =
        encryption_policy_violation(config, storage_path, row->type, row->encrypted)
        ? DIVERGENCE_ENCRYPTION : DIVERGENCE_NONE;

    /* Beneath a squatter the view claims, no look. A look here would answer for
     * the occupant — a symlink's target, a file's ENOTDIR — and no such answer
     * is this path's: not a byte, not a mode, not an absence. The row is an item
     * at birth, DEPLOYED-shaped with nothing measured: UNKNOWN is the occupant
     * every reader treats as "assumed present, nothing read", and the producer
     * classes the claim whose squatter every verb resolves first
     * (workspace_displaced_t). The blob-family bit rides — it is Git's, and the
     * filesystem is not a party to it — and the record pairs as on every item,
     * so a pending handover still shows. Nothing is queued: a record is what
     * dotta saw, and dotta saw nothing here. */
    if (displaced_ancestor(ws, fs_path, false)) {
        return workspace_add_diverged(
            ws, row, anchor, WORKSPACE_STATE_DEPLOYED, policy,
            FS_OCCUPANT_UNKNOWN, WORKSPACE_FAULT_NONE
        );
    }

    /* Single stat capture for the entire analysis
     *
     * This stat is reused for:
     * 1. Existence check (the occupant)
     * 2. Type verification in comparison functions
     * 3. Metadata divergence checks (mode, ownership)
     */
    struct stat initial_stat;
    fs_occupant_t occupant = fs_lstat_occupant(fs_path, &initial_stat);
    int lstat_errno = errno;   /* Valid on UNKNOWN (fs_lstat_occupant's contract) */

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
            occupant,                    /* assumed present */
            fault_class(error_code_from_errno(lstat_errno))
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

        /* Whose remedy a failed look is, folded where it fails and read by the
         * CMP_UNVERIFIED arm below — the one arm that can see it, since that
         * verdict has no other producer. */
        workspace_fault_t fault = WORKSPACE_FAULT_NONE;

        error_t *err = NULL;

        /* The base: dotta's last content confirmation at this path — the record's,
         * when it carries one; the released fact's, when it does not (a released
         * path re-claimed: the record is gone, or is the window's blob-less
         * observation). The claim questions — absence, reassignment, the item's
         * record column — stay the anchor's alone: a released fact is not a claim,
         * and never fabricates a record, a reassignment, or a DELETED absence.
         * A base compares under its own recorded binding, whichever of the two
         * it is: a blob opens under one (profile, storage path) pair and no other,
         * and each of these facts names the claim its blob was confirmed under
         * (core/state.h). The row's pair is never a base's — a row that is not
         * the record's claim is a handover the record has yet to follow, and
         * reading the base under it authenticates a ciphertext against a tree
         * path it was never sealed at. */
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
            base_type = anchor->type;
            base_storage = anchor->storage_path;
            base_profile = anchor->profile;
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
                workspace_record_confirmation(ws, row, anchor, &file_stat);
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
             * invariant in content_stage_file.
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
                    expected_filemode,
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
                fault = fault_of(err);
                cmp_result = CMP_UNVERIFIED;
            }

            /* Slow path confirmed disk == expected blob — confirm the record
             * with the row's blob and the current stat so the next run can
             * short-circuit via the fast path above. */
            if (cmp_result == CMP_EQUAL) {
                workspace_record_confirmation(ws, row, anchor, &file_stat);
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
                    DIVERGENCE_TYPE | policy, occupant, WORKSPACE_FAULT_NONE
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
                    DIVERGENCE_UNVERIFIED | policy, occupant, fault
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

    /* Add to workspace if there's any state change, divergence, or a pending
     * handover — the rule read over the pair this analysis has held throughout. */
    if (state != WORKSPACE_STATE_DEPLOYED ||
        divergence != DIVERGENCE_NONE || workspace_reassigned(row, anchor)) {
        error_t *err = workspace_add_diverged(
            ws, row, anchor, state, divergence, occupant, WORKSPACE_FAULT_NONE
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
 * A measure that can fail says so: the look's error is returned and the caller
 * decides what a failure to look means, which is the rule the active analyzer
 * already keeps for its own (never fatal to the load; the item holds the class
 * and the bit). Nothing is guarded here — the one caller cannot pass a NULL,
 * and a break that reached this would rather crash than be read as a silent
 * [orphaned, unverified].
 *
 * @param ws Workspace (provides content_cache, repo)
 * @param anchor The record dotta keeps of the path (must not be NULL;
 *               non-zero blob_oid)
 * @param in_stat Pre-captured stat from caller (must not be NULL)
 * @param out Receives the divergence flags (must not be NULL); DIVERGENCE_NONE
 *            when the look failed and the error is returned
 * @return The look's error when the compare could not be made; NULL otherwise
 */
static error_t *compute_orphan_divergence(
    workspace_t *ws,
    const anchor_t *anchor,
    const struct stat *in_stat,
    divergence_type_t *out
) {
    *out = DIVERGENCE_NONE;

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
            /* Cannot classify, load, decrypt, or compare — no key in reach, a
             * blob a held key refuses, an unsupported cipher version, an I/O
             * error, a blob missing from the repository. Handed back whole: the
             * caller folds its class onto the item and holds the orphan, which
             * is what the active analyzer does with the same causes at the same
             * step (analyze_file_divergence). */
            return err;
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
            /* Unreachable: a look that failed returned its error above, and no
             * compare path produces this verdict of its own. */
            break;
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

    *out = divergence;
    return NULL;
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
    authority_cache_t *cached = value;
    if (!cached) {
        return;
    }
    metadata_free(cached->metadata);   /* NULL-safe */
    git_tree_free(cached->tree);       /* NULL-safe */
    free(cached);
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

    authority_cache_t *cached = hashmap_get(cache, profile);
    if (!cached) {
        /* First row of this profile: does the branch still exist? A ref lookup,
         * not a tree load — most profiles answer here. Git errors are not cached:
         * a transient failure must stay retryable. */
        bool exists = false;
        error_t *err = gitops_branch_exists(repo, profile, &exists);
        if (err) {
            error_free(err);
            return;                         /* UNVERIFIED */
        }

        cached = calloc(1, sizeof(*cached));
        if (!cached) {
            return;                         /* UNVERIFIED */
        }
        cached->exists = exists;

        err = hashmap_set(cache, profile, cached);
        if (err) {
            error_free(err);
            authority_cache_free(cached);
            return;                         /* UNVERIFIED */
        }
    }

    if (!cached->exists) {
        *out = ORPHAN_AUTHORITY_LOST;       /* Branch deleted externally */
        return;
    }

    if (!cached->tree) {
        /* Lazy-load the HEAD tree on the first in-tree question for this profile;
         * stored only on success, so a failure is retried by the next row instead
         * of condemning the whole profile. */
        git_tree *tree = NULL;
        error_t *err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            error_free(err);
            return;                         /* UNVERIFIED */
        }
        cached->tree = tree;                /* Ownership transfers to the cache */
    }

    if (kind == PATH_KIND_DIRECTORY) {
        /* A directory is claimed by metadata, not by the tree. Lazy-load the
         * tree's metadata.json on the first directory question for this profile,
         * under the same stored-only-on-success rule as the tree. A tree without
         * one loads as an empty collection — "no metadata" is a settled answer
         * (no directory is backed), not a failure to look — so every error here
         * is a failure to look. */
        if (!cached->metadata) {
            metadata_t *metadata = NULL;
            error_t *err = metadata_load_from_tree(repo, cached->tree, profile, &metadata);
            if (err) {
                error_free(err);
                return;                         /* UNVERIFIED */
            }
            cached->metadata = metadata;        /* Ownership transfers to the cache */
        }

        /* Backed iff metadata still claims the path as a directory. An item of
         * another kind at the key is a path Git turned into a blob: the directory
         * dotta made is no longer claimed as one. */
        const metadata_item_t *item = metadata_lookup(cached->metadata, storage_path);
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
    int rc = git_tree_entry_bypath(&tree_entry, cached->tree, storage_path);

    if (rc == 0) {
        git_tree_entry_free(tree_entry);
        *out = ORPHAN_AUTHORITY_BACKED;
    } else if (rc == GIT_ENOTFOUND) {
        *out = ORPHAN_AUTHORITY_LOST;
    }
    /* Anything else: *out stays UNVERIFIED */
}

/**
 * Order two entries by identity (qsort callback): device, then inode
 *
 * The pair one lstat names, so every entry standing on one file is adjacent and
 * find_entries reads the run. Compared and never subtracted: dev_t is signed on
 * some platforms and unsigned on others, and a difference is not an order.
 *
 * No axis in the name, where compare_rows_by_path carries one: a row can be ordered
 * by any of the things it holds, and an entry is its identity.
 */
static int compare_entries(const void *a, const void *b) {
    const entry_t *ea = a;
    const entry_t *eb = b;

    if (ea->dev != eb->dev) return ea->dev < eb->dev ? -1 : 1;
    if (ea->ino != eb->ino) return ea->ino < eb->ino ? -1 : 1;

    return 0;
}

/**
 * The entries standing on one file: the first, and how many
 *
 * The lower bound of the identity the caller's lstat gave, then the run of equals
 * — two rows on one file through a hard link, or two spellings of one entry both
 * enabled (the two-writers class, infra/mount.h), are adjacent by the sort, in
 * an order within the run the sort does not fix (qsort is not stable, and the
 * comparator reads identity alone) and no reader may depend on.
 *
 * An empty answer is the empty index's and never a mode: the gate that builds
 * the index is the two readers' own preconditions spelled once (workspace_load),
 * so every ask is made on a load it exists in. A reader outside that gate would
 * read "nothing stands here" for "nobody looked", which on the orphan arm means
 * prunable. find_scan_root's verb, for the same question over the other (dev,
 * ino) array.
 *
 * @param ws    Workspace (must not be NULL)
 * @param st    The subject's own lstat; its identity is the key (must not be NULL)
 * @param count Receives how many entries stand there (must not be NULL)
 * @return The first of the run, or NULL when none stands there
 */
static const entry_t *find_entries(
    const workspace_t *ws, const struct stat *st, size_t *count
) {
    const entry_t key = { .dev = st->st_dev, .ino = st->st_ino };
    size_t lo = 0;
    size_t hi = ws->entry_count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;

        if (compare_entries(&ws->entries[mid], &key) < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    size_t n = 0;
    while (lo + n < ws->entry_count &&
        compare_entries(&ws->entries[lo + n], &key) == 0) {
        n++;
    }

    *count = n;
    return n > 0 ? &ws->entries[lo] : NULL;
}

/**
 * The directory a path is an entry of, by identity
 *
 * stat(2) of the parent, through a link standing at any rung — the chain two
 * spellings of one entry differ in (cleanup's parent_accepts_removal takes the
 * parent the same way). A path this cannot take apart — not absolute, or longer
 * than any the kernel takes — cannot happen to a key that was just lstat'ed,
 * and answers as a look that did not happen, which is its one caller's rule for it.
 *
 * @param path Canonical absolute path (must not be NULL)
 * @param st Receives the parent's stat (must not be NULL)
 * @return true when the parent was stat'd
 */
static bool stat_parent(const char *path, struct stat *st) {
    size_t len = str_path_parent_len(path);
    char parent[PATH_MAX];

    if (len == 0 || len >= sizeof(parent)) {
        return false;
    }

    memcpy(parent, path, len);
    parent[len] = '\0';

    return fs_stat(parent, st) == 0;
}

/**
 * Do two spellings that reach one file name one directory entry?
 *
 * Asked only once the file is one: the caller met `other` among the entries
 * standing on the (dev, ino) `st` names. A file with one name is one entry however
 * it is spelled — st_nlink counts the names — and so is a directory, whatever
 * its st_nlink says (2 + children: the '.' and '..' links, never a second name,
 * POSIX forbidding user-created directory hard links). So a link no binding names,
 * a target bound through a link, the dangling link under two spellings and a
 * name the volume folds (case, Unicode normalization: one entry at two strings,
 * measured deleting a managed file through a name compare) all pair here.
 *
 * A multiply-linked regular file has several names, and two of its spellings
 * are one entry only when they name it the same way in one directory: the names
 * by bytes, the directories by identity. Two hard links are two entries — unlinking
 * one leaves the other — so the one that is this name in this directory is this
 * path, and no other is. A parent that cannot be stat'd pairs nothing: the orphan
 * stays an orphan, the leaf stays an offer, the way every failed look in this
 * file is the item's and never the load's.
 *
 * The one shape the bytes cannot see: a multiply-linked file spelled two ways
 * in one directory by the volume's own fold. Two hard links cannot bear such
 * names in one directory — the volume refuses the second — so it takes a hard
 * link elsewhere as well, and the pair reads as two entries. Stated, not closed.
 *
 * @param path The subject's key (must not be NULL)
 * @param other A key standing on the same (dev, ino) (must not be NULL)
 * @param st The subject's lstat — nlink and the mode are the inode's, which both
 *           spellings share (must not be NULL)
 */
static bool same_entry(const char *path, const char *other, const struct stat *st) {
    if (st->st_nlink == 1 || S_ISDIR(st->st_mode)) {
        return true;
    }

    const char *name = strrchr(path, '/');
    const char *other_name = strrchr(other, '/');
    if (!name || !other_name || strcmp(name + 1, other_name + 1) != 0) {
        return false;
    }

    struct stat parent;
    struct stat other_parent;

    return stat_parent(path, &parent) && stat_parent(other, &other_parent) &&
           parent.st_dev == other_parent.st_dev && parent.st_ino == other_parent.st_ino;
}

/**
 * The winning row standing on the entry a path names, under another spelling
 *
 * The partition asked by string — no row stands at the path, or it would not be
 * an orphan; the scan's leaf probe asked the view by the walk's spelling — and
 * this asks of the entry: is there a row of the view whose file is this file
 * (find_entries), whose key is a spelling of this very entry (same_entry)? `st`
 * is the caller's own lstat of `path`, which both readers hold, so an ask costs
 * a binary search and, for a hard link, two stats of parents. It allocates nothing
 * and cannot fail: a failure here would have to read as "no row", which on the
 * orphan arm means prunable.
 *
 * Any row that pairs, in an order the sort does not fix: both readers ask whether
 * one stands, never which — a scan root is a selection with a winner (scan_root_t);
 * this is not.
 *
 * Readers: the orphan analysis's BACKED arm — a stale key of a managed path is
 * released, never pruned, whoever's row; the record's own claim standing on the
 * same entry was the special case of this the compare here used to make — and
 * the untracked scan's leaf probe: a file managed under another spelling of its
 * path is no discovery.
 */
static const manifest_row_t *standing_row(
    const workspace_t *ws, const char *path, const struct stat *st
) {
    size_t count = 0;
    const entry_t *entries = find_entries(ws, st, &count);

    for (size_t i = 0; i < count; i++) {
        if (entries[i].row && same_entry(path, entries[i].row->filesystem_path, st)) {
            return entries[i].row;
        }
    }

    return NULL;
}

/**
 * The orphan record standing on the entry a path names, under another spelling
 *
 * standing_row's twin over the record: a path dotta remembers is no discovery
 * (workspace_get_anchor at the leaf probe), and this is that rule read by identity
 * — a record at another spelling of the child's entry is an orphan cleanup is
 * about to prune, release or hold, and it holds the child back until it is retired
 * exactly as the same record at the child's own spelling does. Without it one
 * screen promised a commit and a deletion of one file.
 *
 * Its own loop rather than a flag on the one above: each is a question with its
 * own reader, and the leaf probe wants probes that read alike in one chain. Neither
 * could return the first entry of the run instead — the guard needs the first
 * entry *with a row*, and an orphan's own record can sort ahead of the row in
 * the run.
 *
 * Reader: the untracked scan's leaf probe.
 */
static const anchor_t *standing_record(
    const workspace_t *ws, const char *path, const struct stat *st
) {
    size_t count = 0;
    const entry_t *entries = find_entries(ws, st, &count);

    for (size_t i = 0; i < count; i++) {
        if (entries[i].anchor &&
            same_entry(path, entries[i].anchor->filesystem_path, st)) {
            return entries[i].anchor;
        }
    }

    return NULL;
}

/**
 * The load's look at where every row and every orphan record stands
 *
 * One lstat per winning row of either kind and per orphan record, the entry it
 * found kept beside its source and sorted by identity, so a reader's ask is a
 * binary search (find_entries). Two passes over two disjoint sets — the view's
 * rows all stand at their own keys, and an orphan is exactly a record no row
 * stands at — which is what makes each element one or the other (entry_t).
 *
 * Three looks decide whether a key names an entry its claim may vouch by, and
 * each of them drops rather than keeps:
 *   - a key beneath a displaced directory: a look there would reach the squatter's
 *     target, which every verdict refuses to act on, so it must vouch for nothing
 *     and none is taken — the scan driver's own rule for a root
 *     (workspace_displaced_ancestor, complete for the view's claims once the
 *     directory analysis has run, which is why this phase follows it);
 *   - a key that does not stand — [undeployed], a chain the invoker cannot read:
 *     an absent row is not the entry a present orphan stands on;
 *   - a key another kind of node holds — a directory claim with a symlink or a
 *     file in its place, a file claim with a directory: a squatted claim's own
 *     lstat is the squatter's, so the entry it names is exactly the one the
 *     verdicts refuse. The retyped arm's rule read at the build (analyze_orphans:
 *     two occupants cannot share an inode, a claim and an occupant can), and
 *     the probe above is why it is needed — that one answers for proper ancestors
 *     alone, so a claim whose own path is squatted is one rung past its reach.
 *
 * Dropping withholds — a release where a prune was right, an offer deferred a
 * run; keeping wrongly prunes a managed file or offers one twice. That direction
 * is why each look is named here, and why a fourth would have to be argued rather
 * than added.
 *
 * The first look is the view's claims alone, and this phase is the one place
 * the load looks beneath a squatter at all: the record's own squatters are the
 * orphan analysis's to note, and it cannot have run yet — its BACKED guard reads
 * this index. A record-side squatter is by definition a directory record another
 * kind of node stands at, which the third look drops; a record *beneath* one is
 * indexed by whatever its key reached, and the cost is an offer withheld for
 * the run, which is the direction above. So the load's rule — no look beneath a
 * squatter (workspace.h workspace_displaced_t) — is exact for the view's claims
 * and bounded here for the record's.
 *
 * The lstats are this phase's own. Not the analyses': a look taken there is the
 * item's, and its answer must not depend on which analyses a caller asked for
 * (the leaf probe's record guard learned that, workspace_load_t). Not the scan's:
 * its roots are a selection over the tracked directories — the later profile
 * wins a directory — not an index (scan_root_t). One allocation sized by the
 * view's rows and the orphans; the cost is rows + orphans syscalls once, on a
 * load a reader will run in, and nothing at all on any other. A later shape that
 * kept one look per path on the join would replace the two fs_lstat lines here
 * and move no reader.
 *
 * Readers: standing_row (the orphan analysis's BACKED arm, the untracked scan's
 * leaf probe), standing_record (the leaf probe).
 *
 * @param ws Workspace (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *index_entries(workspace_t *ws) {
    manifest_rows_t rows = manifest_rows(ws->manifest);
    size_t cap = rows.count + ws->orphan_count;

    if (cap == 0) {
        return NULL;
    }

    ws->entries = arena_calloc(ws->arena, cap, sizeof(*ws->entries));
    if (!ws->entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate the entries");
    }

    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];
        struct stat st;

        if (workspace_displaced_ancestor(ws, row->filesystem_path)) continue;
        if (fs_lstat(row->filesystem_path, &st) != 0) continue;

        bool is_dir = S_ISDIR(st.st_mode);
        if (is_dir != (row->type == PATH_TYPE_DIRECTORY)) continue;

        ws->entries[ws->entry_count++] = (entry_t){
            .dev = st.st_dev, .ino = st.st_ino, .row = row,
        };
    }

    for (size_t i = 0; i < ws->orphan_count; i++) {
        const anchor_t *anchor = ws->orphans[i];
        struct stat st;

        if (workspace_displaced_ancestor(ws, anchor->filesystem_path)) continue;
        if (fs_lstat(anchor->filesystem_path, &st) != 0) continue;

        bool is_dir = S_ISDIR(st.st_mode);
        if (is_dir != (anchor->type == PATH_TYPE_DIRECTORY)) continue;

        ws->entries[ws->entry_count++] = (entry_t){
            .dev = st.st_dev, .ino = st.st_ino, .anchor = anchor,
        };
    }

    qsort(
        ws->entries, ws->entry_count, sizeof(*ws->entries), compare_entries
    );

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
 * Per orphan, in order — the ancestry, presence, the occupant's kind, the prune
 * order, the ownership gate, then Git authority:
 *   - the ancestry, before the look: a squatter above the copy — a directory
 *     row of the view, or a directory record earlier in this same walk — means
 *     no look is taken at all, and the record is released with nothing measured
 *     (displaced_ancestor, and the file analyzer for the rule);
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
 *     on the item, which carries the class of the namespace the claim lands in
 *     (workspace_relocation_t), and that class picks the fate (cleanup_verdict).
 *     Elsewhere is another entry, never merely another string, and the guard is
 *     asked first: a row standing on the record's very entry under another spelling
 *     of its path — whoever's — makes the record a stale key, RELEASED, so the
 *     one copy is never pruned as the old one (standing_row). A target bound
 *     through a symlink, a HOME spelled two ways, a name the volume folds; apply
 *     adopts the row under its spelling and retires the key; UNVERIFIED holds
 *     the orphan until Git answers — either kind: LOST would retire the record,
 *     BACKED would remove the copy, and neither is a guess to make about an empty
 *     directory any more than about a file. Held and not measured: no reader
 *     shows a bit beside UNVERIFIED, so a compare would only give the item a
 *     second reason for the one fate it already has. The probe raises nothing,
 *     so a lookup it could not make is this orphan's hold and never the load's
 *     — the rule the file analyzer takes for its own looks.
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
 * - WORKSPACE_STATE_RELEASED -> Git let go, dotta never deployed it, a row of
 *   the view stands on this very entry under another spelling of its path, or
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

        /* Beneath a squatter of either authority — a record's memory reaches
         * the record family, which this is (the reach rule, workspace_displaced_t)
         * — no look, for the reason the file analyzer states. The orphans are
         * in path order (workspace_partition, over a snapshot SQLite ordered by
         * filesystem_path, and a parent sorts before everything beneath it), so
         * a retyped directory record was noted by the arm below before any record
         * beneath it came up. ORPHANED with nothing measured: cleanup's displaced
         * arm releases the copy and apply's settle retires the record. */
        if (displaced_ancestor(ws, fs_path, true)) {
            err = workspace_add_diverged(
                ws, NULL, anchor, WORKSPACE_STATE_ORPHANED, DIVERGENCE_NONE,
                FS_OCCUPANT_UNKNOWN, WORKSPACE_FAULT_NONE
            );
            if (err) {
                err = error_wrap(err, "Failed to add displaced orphan");
                break;
            }
            continue;
        }

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
        int lstat_errno = errno;   /* Valid on UNKNOWN (fs_lstat_occupant's contract) */

        workspace_state_t item_state = WORKSPACE_STATE_ORPHANED;
        divergence_type_t divergence = DIVERGENCE_NONE;
        workspace_fault_t fault = WORKSPACE_FAULT_NONE;

        /* The relocated claim's row, set only where the probe answers BACKED
         * and no row of the view stands on this very entry: the record's own
         * (profile, storage path) claim, still in the view, standing at another
         * file. See the reads below. */
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
         * judged. True of an absent directory record too — NONE is neither
         * DIRECTORY nor UNKNOWN — which the ladder's absence arm shadows, and
         * nothing outside the ladder may read this bit without it. The record's
         * own kind, not the ancestry's: whether a squatter stands above the copy
         * was asked before the look (displaced_ancestor), and no record that
         * reached here is beneath one. */
        bool retyped = (kind == PATH_KIND_FILE)
            ? (occupant == FS_OCCUPANT_DIRECTORY)
            : (occupant != FS_OCCUPANT_DIRECTORY && occupant != FS_OCCUPANT_UNKNOWN);

        /* Set by the arms that find the copy dotta's to prune — a candidacy,
         * not cleanup's verdict, which still holds the copy back on a divergence
         * or a hold of its own; measured once, below. */
        bool prunable = false;

        if (occupant == FS_OCCUPANT_NONE) {
            /* Absent: ORPHANED with no divergence — a reclaim whatever Git says. */

        } else if (retyped) {
            /* What dotta put there is gone, and what stands there is not dotta's
             * to remove. Released, [type]: the record retires, the path stays. */
            item_state = WORKSPACE_STATE_RELEASED;
            divergence = DIVERGENCE_TYPE;

            /* A directory record whose place another kind holds is a squatter,
             * noted here and not beside the emission below: outside this arm
             * `retyped` is also true of an absent record, which squats nothing,
             * and the absence arm above is the whole of what rules that out. A
             * file record with a directory in its place is retyped as well and
             * reaches nothing beneath it, so the record's own kind is the rest
             * of the filter (note_displaced). */
            if (kind == PATH_KIND_DIRECTORY) {
                err = note_displaced(ws, fs_path, WORKSPACE_DISPLACED_RECORD);
                if (err) break;
            }

        } else if (hashmap_has(ws->order_index, fs_path) && measurable) {
            /* The user ordered the copy pruned — remove --delete-files over a
             * path the removal named or a copy dotta deployed, the only births
             * an order has (state_order_prune); Git is not asked. Read ahead of
             * the ownership gate below by design: a named path must go whether
             * dotta deployed it or only ever found it. Divergence still protects
             * an edited copy — cleanup's skip reasons read the same bits. */
            prunable = true;

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
                 * has. Its class is UNVERIFIED whatever went wrong: the probe
                 * meets Git and its own allocations, never a key or a
                 * permission. */
                divergence = DIVERGENCE_UNVERIFIED;
                fault = WORKSPACE_FAULT_UNVERIFIED;
            } else if (authority == ORPHAN_AUTHORITY_LOST) {
                /* Git cannot back the path. Left on disk, record retires — so
                 * there is nothing a content comparison would decide. */
                item_state = WORKSPACE_STATE_RELEASED;
            } else if (occupant != FS_OCCUPANT_UNKNOWN &&
                standing_row(ws, fs_path, &orphan_stat)) {
                /* The guard — BACKED only, which is what these two arms are. A
                 * row of the view stands on this very entry under another spelling
                 * of its path: this profile's own claim after its root was
                 * re-spelled, another profile's through a link no binding names,
                 * a name the volume folds. The record is a stale key of a managed
                 * path, not a copy left behind — released, and the path stays
                 * for the row standing on it; what becomes of that row is apply's
                 * adoption, which reads its own gates (cmds/apply.c).
                 *
                 * By the entry and never by a name compare: a volume that folds
                 * case or normalization stands one entry at two strings, and
                 * cleanup was measured deleting a managed file through that fold.
                 * An occupant that could not be stat'd is not asked and falls
                 * through: orphan_stat is filled for a present occupant alone
                 * (fs_lstat_occupant), so the two conjuncts keep this order. */
                item_state = WORKSPACE_STATE_RELEASED;
            } else {
                /* The relocation read: a relocated orphan is an orphan whose
                 * claim still has a row, standing at another file. The record's
                 * own (profile, storage path) pair is asked of the view; a row
                 * found here always projects to another string — the partition
                 * orphaned this record precisely because no view row stands at
                 * its filesystem path, this row included — and, after the guard
                 * above, to another entry: a root re-spelled under another name
                 * of one directory is the guard's, not a relocation. So the claim
                 * deploys at a new location now: a moved custom/ target, a
                 * different $HOME. The item carries the row, and the producer
                 * reads the class of the namespace off it (workspace_add_diverged);
                 * the class picks the fate at cleanup_verdict, and root/ never
                 * gets here — its projection is fixed, so a root/ claim's old
                 * and new locations are one string and the record was never
                 * orphaned. Strictly the record's own profile: a claim shadowed
                 * by another profile at its new home is not "relocated" — the
                 * copy here is simply no longer active — and the same-profile
                 * rule is what keeps workspace_reassigned false by construction
                 * on every orphan (the profiles are equal). Asked on this arm
                 * alone: it is a linear scan of the view, and the three arms
                 * above read no row. */
                prunable = true;
                row = manifest_lookup_storage(ws->manifest, storage_path, profile);
            }
        }

        if (prunable) {
            /* A file: disk against what dotta last deployed. A directory: nothing
             * to measure — cleanup's emptiness rule decides — only whether it
             * can be: one dotta cannot stat or cannot read is held, as an
             * unstattable file is, until the user can say what is in it. */
            if (kind == PATH_KIND_FILE && occupant != FS_OCCUPANT_UNKNOWN) {
                error_t *look = compute_orphan_divergence(
                    ws, anchor, &orphan_stat, &divergence
                );
                if (look) {
                    divergence = DIVERGENCE_UNVERIFIED;
                    fault = fault_of(look);
                }
            } else if (occupant == FS_OCCUPANT_UNKNOWN) {
                /* Present but unstattable, either kind: nothing to measure the
                 * copy with, and the errno says whose refusal it was. */
                divergence = DIVERGENCE_UNVERIFIED;
                fault = fault_class(error_code_from_errno(lstat_errno));
            } else if (!fs_eaccess(fs_path, R_OK | X_OK)) {
                /* A directory: read for the readdir, search for the walk's look
                 * at an entry named like OS metadata (fs_directory_emptiness).
                 * fs_eaccess leaves faccessat's errno on false. */
                divergence = DIVERGENCE_UNVERIFIED;
                fault = fault_class(error_code_from_errno(errno));
            }
        }

        err = workspace_add_diverged(
            ws, row,  /* The relocated claim's row, or NULL; identity is the record's */
            anchor, item_state, divergence, occupant, fault
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
                /* The displaced read comes first and stands on its own: a row
                 * beneath a squatter has no bits because nothing there was looked
                 * at, and reading only the bits would call it clean — true only
                 * so long as the squatter's own TYPE item happens to be in this
                 * same fold. A fold over items answers from each item's own
                 * facts. */
                if (item->displaced != WORKSPACE_DISPLACED_NONE ||
                    item->divergence != DIVERGENCE_NONE ||
                    workspace_reassigned(item->row, item->anchor)) {
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
 * The blob the view holds over a directory — at it, or at a rung above it
 *
 * A directory standing where the view holds a blob is the [type] the file analysis
 * said, and nothing beneath it can stand: the view says a file belongs there,
 * so anything offered beneath is something no apply can ever place. Whichever
 * profile's blob, precedence applied (core/manifest.h manifest_lookup) — the
 * question is what stands at the location, not what the scanning profile holds.
 * A directory row of either kind stops nothing: an ancestor claim names neither
 * itself nor anything beneath it (manifest_is_derived), which is why a derived
 * row at one key is no answer about the other.
 *
 * A directory has one key — the one its frame joined, which is the one the view
 * holds a row at: the two producers of a key, mount_resolve and the walk's join,
 * agree by construction (infra/mount.h) — so one climb answers. Each step is
 * the last separator's index, or 1 for a rung beneath the root directory, so a
 * rung is strictly shorter than the one before it; the root directory is read
 * and ends the climb, because a claim can stand there — `root` spells it, and
 * `home` or `custom` on a machine whose HOME or target is one (infra/label.h) —
 * and the view places a blob at any of the three as a FILE row at that directory
 * (core/manifest.c manifest_claim_blob). The key is absolute; the copy the climb
 * truncates is the caller's scratch, and abandoned.
 *
 * The ascent over these very rungs floors on the asker's own root (core/manifest.c
 * manifest_ascend): it is naming a location for one profile, and nothing of that
 * profile's stands above its root. This climb has no asker — it asks what stands
 * at a location, whoever holds it — so the root directory is its floor, as it
 * is deploy's (core/deploy.c nearest_ancestor).
 *
 * Readers: the walk, of every directory child, and the driver, of every tracked
 * directory it is about to enumerate — an independent tracked root beneath a
 * file claim is as much beneath it as a child the walk would have stopped at.
 * The driver probes the same rungs from a deeper start, so a blob at the root
 * directory is always the driver's to meet first.
 *
 * @param view      The precedence-resolved view (must not be NULL)
 * @param directory The directory's key (must not be NULL)
 * @param scratch   Arena the climb's copy is taken in (must not be NULL)
 * @param out       The blob standing over it, or NULL (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *blob_over(
    const manifest_t *view,
    const char *directory,
    arena_t *scratch,
    const manifest_row_t **out
) {
    *out = NULL;

    char *rung = arena_strdup(scratch, directory);
    if (!rung) {
        return ERROR(ERR_MEMORY, "Failed to copy path");
    }

    /* The guard is on the truncation and not on the read, because the root
     * directory is its own parent (base/string.h str_path_parent_len): a climb
     * that tested before reading would never read it, and one that truncated
     * after it would never leave. */
    for (;;) {
        const manifest_row_t *row = manifest_lookup(view, rung);
        if (row && row->type != PATH_TYPE_DIRECTORY) {
            *out = row;
            return NULL;
        }
        if (!rung[1]) return NULL;

        rung[str_path_parent_len(rung)] = '\0';
    }
}

/**
 * One scan root: a directory to enumerate, whose walk it is, and its spelling
 *
 * Three facts and nothing else of whatever produced one: the identity, the disk's
 * word on which directory this is; the owner, whose names, rules and attribution
 * the walk runs under (scan_t); and the spelling the walk starts from, which
 * every child joins onto. A tracked row carries much besides and a walk reads
 * none of it, which is what makes a registration no row; the two strings are
 * the view's, borrowed, the rows and this array being one arena's
 * (include/runtime.h).
 *
 * Keyed by the directory's identity — the (dev, ino) the driver's look found at
 * the spelling it registers — because a traversal must not enumerate one directory
 * twice, and which directory a frame stands in is a fact about the filesystem,
 * not about naming: two tracked rows spelled through different links stand at
 * one directory (a link a binding is declared through, one no binding names, a
 * firmlink, a bind mount), and a walk reaches a directory by whatever spelling
 * its frame joined. Two keys at one directory are two paths to the view and one
 * walk to the scan. One entry per directory, so the array is both the boundaries
 * — a walk stops at any of them it meets, by whichever string (find_scan_root)
 * — and the walks: the driver enumerates each once, from a depth 0 of its own.
 * Where several rows stand at one directory the later-enabled profile's is the
 * one kept, owner and spelling together, the index's rule for a contested location
 * (core/manifest.c manifest_layer) applied where the keys differ; among one
 * profile's, the later in path order. The consequence: where two tracked rows
 * stand at one directory under two spellings, the later-enabled profile's walk
 * is the one that runs, and the other's namespace never sees an offer beneath it.
 *
 * The entries index (entry_t) reads the same fact off the same rows, for the
 * two verbs that act on an entry through a string, and the two are not one
 * structure: a root is a selection with a winner and a mutable registration, an
 * entry an observation with a run of equals — and the shapes differ with them,
 * an entry carrying the row its readers ask what stands on, a root the two strings
 * its walk reads.
 */
typedef struct {
    dev_t dev;              /* The directory's identity */
    ino_t ino;
    const char *profile;    /* The owner: its names, its rules, its attribution */
    const char *directory;  /* The spelling the walk starts from, and every child's prefix */
} scan_root_t;

/**
 * The scan root standing at a directory, or NULL
 *
 * Asked by the driver as it registers each tracked directory — is one already
 * standing here? — and by the walk of every directory child — is this another
 * root's? — each against one lstat the caller already took. Linear: every tracked
 * directory is a root and is met once as some root's child, so the compares are
 * the square of their count — three hundred is nothing, ten thousand is some
 * twenty milliseconds. A map keyed by the formatted pair is the upgrade if a
 * machine ever shows it.
 */
static scan_root_t *find_scan_root(
    scan_root_t *roots, size_t count, dev_t dev, ino_t ino
) {
    for (size_t i = 0; i < count; i++) {
        if (roots[i].dev == dev && roots[i].ino == ino) return &roots[i];
    }

    return NULL;
}

/**
 * What one walk of a tracked directory runs under
 *
 * `profile` is the owner of the scan root the walk began at: its own contribution
 * names what the walk finds (core/manifest.h manifest_name, `pending` NULL —
 * the scan admits nothing, and an offer is a file, never an authority another
 * offer composes under), its ignore layers decide what is offered, and every
 * offer is attributed to it. A walk that meets a directory another scan root
 * stands at — by identity, whatever spelling the frame joined — has reached that
 * root and does not enter it: the driver reaches every root directly, from a
 * depth 0 of its own. Nothing here is written by a frame; the struct is one value
 * the recursion passes down, the roots are read through it and never written,
 * and the strings a frame makes live in an allocator of its own.
 */
typedef struct {
    workspace_t *ws;                   /* The view, the record, the arena offers live in */
    scan_root_t *roots;                /* Every scan root — the boundaries — and how many */
    size_t root_count;
    const char *profile;               /* The owner of the root this walk began at */
    const gitignore_ruleset_t *rules;  /* That profile's layered ruleset */
    source_filter_t *source_filter;    /* The source tree's .gitignore, or NULL */
} scan_t;

/**
 * Scan one tracked directory for untracked files, and everything beneath it
 *
 * `directory` is a key — a tracked row's own — and every join beneath it is one
 * too (infra/mount.h: a child joined onto a key is a key), which is what makes
 * the namer's input exact and a leaf's managed probe hit the key the view holds.
 *
 * The walk descends only into directories the view does not track. A directory
 * child that is a scan root — by identity, whatever spelling this frame joined
 * — is the driver's to enumerate, and the walk stops at it before asking its
 * name or any rule: an owner's exclusion is the owner's, and a walk from outside
 * inherits none of it. Two walks can meet only where their roots are physically
 * nested or coincident, because a walk never follows a link and a joined child
 * is inside the directory that was listed, whatever the spelling. The one entry
 * that is a directory elsewhere is a bind mount inside a tracked directory: it
 * reaches a directory outside every root's subtree, which two walks may then
 * enumerate — the limit a visited set would close, left stated.
 *
 * Each kind asks the view its own question before the name, and they are not
 * the same question: a leaf asks whether its own path is already spoken for —
 * by its string, then by its entry — a directory whether anything beneath it
 * can be (blob_over). That is why neither needs the other's — a leaf's container
 * was cleared before this frame entered it, so a leaf climbs nothing; no offer
 * is ever made *at* a directory, so a directory asks no record. A directory the
 * record remembers is entered like any other: a record bounds what is offered,
 * never where the walk goes.
 *
 * The order is the order. The lstat first, because the kind and the identity
 * decide every arm; the occupant skip before any lookup, because nothing can
 * hold what it names; identity before the climb and the namer, because another
 * root's directory needs no string; the guards before the name, because an ascent
 * is paid only where a name is used and in a tracked directory most leaves are
 * managed; the name before the ignore layers, the name being the first layer's
 * subject; the layers before the descent, because an excluded directory is not
 * entered.
 *
 * A best-effort look, and neither a snapshot nor an admission: what the commit
 * can hold at an offered name is update's question at its capture (cmds/update.c).
 * The climb closes the one class the view can decide for itself and closes no
 * other — a name the branch's tree or its claim sheet cannot hold is still the
 * capture's to refuse.
 *
 * One arrangement the climb does not reach, and need not: where a later profile's
 * explicit DIRECTORY claim wins a location an earlier one holds a blob at, the
 * index answers with the directory row. That row is necessarily tracked — a derived
 * row never takes a held location — so it is a scan root, and the walk stops at
 * it by identity before the climb is asked; the directory is the winner's to
 * enumerate, under the winner's name.
 *
 * What the filesystem refuses is said where it happens and the siblings go on,
 * absence is silent, and an allocation anywhere is the run failing. The lines
 * go to stderr, as the driver's do — core has no output handle.
 *
 * @param scan      What the walk runs under (must not be NULL)
 * @param directory The location this frame enumerates (must not be NULL)
 * @param depth     Frames beneath the tracked directory the driver started at
 * @return Error or NULL on success
 */
static error_t *scan_directory_for_untracked(
    const scan_t *scan, const char *directory, size_t depth
) {
    CHECK_NULL(scan);
    CHECK_NULL(directory);

    workspace_t *ws = scan->ws;

    /* The bound is the walk's own: `depth` counts frames beneath the tracked
     * directory the driver started at, so a tracked directory 200 deep on disk
     * is still scanned from its own 0 (sys/filesystem.h FS_WALK_MAX_DEPTH). Said,
     * not an error — the siblings of a deep subtree are still this profile's,
     * where add refuses the argument whole. */
    if (depth >= FS_WALK_MAX_DEPTH) {
        fprintf(
            stderr,
            "warning: '%s' is %d directories inside the tracked directory it "
            "stands in; new files beneath it are not listed\n",
            directory, FS_WALK_MAX_DEPTH
        );
        return NULL;
    }

    /* The whole listing, and the stream closed with it: one open at a time down
     * the recursion rather than one per frame, and the errno discipline is
     * fs_list_dir's. The frames hold entry names where they held directory streams,
     * which is the trade add's walk already made — a deep walk no longer holds
     * one descriptor per level, and pays for the names instead. */
    string_array_t *listing = NULL;
    error_t *err = fs_list_dir(directory, &listing);
    if (err) {
        switch (error_code(err)) {
            case ERR_MEMORY:     /* the run failing; error_wrap keeps the cause's code */
                return err;

            case ERR_NOT_FOUND:  /* it left between the look that found it and this listing */
                break;

            default:             /* it would not open, or the read failed */
                fprintf(
                    stderr, "warning: %s; new files beneath it are not listed\n",
                    error_message(err)
                );
                break;
        }
        error_free(err);
        return NULL;
    }

    /* The frame's strings — one entry's join, the namer's copy and its answer —
     * reset before the next entry. What outlives the frame is an offer's, copied
     * at its door (workspace_add_untracked); a frame beneath this one allocates
     * in a scratch of its own, so this frame's `child` stands as that frame's
     * `directory` for the whole subtree (include/runtime.h). */
    arena_t *scratch = arena_create(0);
    if (!scratch) {
        string_array_free(listing);
        return ERROR(ERR_MEMORY, "Failed to allocate the scan's scratch");
    }

    /* "/" is the one directory whose spelling ends in its separator, and a tracked
     * directory can stand there: `add p /` writes a `root` item, a `home` or
     * `custom` one places there on a machine whose HOME or target is "/", and
     * the driver walks it from a depth 0 of its own. Joined with none, then, or
     * every child would read "//etc" — a key the view holds no row at and the
     * namer composes as "root//etc". add's walk, whose frame 0 is a typed argument,
     * reads the same rule (cmds/add.c collect_tree). */
    const char *separator = directory[1] ? "/" : "";

    for (size_t i = 0; i < listing->count; i++) {
        arena_reset(scratch);

        const char *child = arena_str_format(
            scratch, "%s%s%s", directory, separator, listing->items[i]
        );
        if (!child) {
            err = ERROR(ERR_MEMORY, "Failed to allocate path");
            goto cleanup;
        }

        /* One lstat names what stands there — its kind, and for a directory its
         * identity: a symlink is never a directory here. Absence is a skip —
         * the listing and this look are two moments. A look that failed is said,
         * its errno read in the line itself (sys/filesystem.h: it is lstat's
         * until something else runs): nothing downstream can name a path it could
         * not see. What no branch can hold — a device, a socket, a FIFO — is
         * not a new file; offered, the capture refuses it by its noun and takes
         * the whole profile's update with it (cmds/add.c reads it the same way). */
        struct stat st;
        fs_occupant_t occupant = fs_lstat_occupant(child, &st);
        switch (occupant) {
            case FS_OCCUPANT_NONE:
                continue;

            case FS_OCCUPANT_UNKNOWN:
                fprintf(
                    stderr, "warning: Failed to stat '%s': %s; it is not listed\n",
                    child, strerror(errno)
                );
                continue;

            case FS_OCCUPANT_OTHER:
                continue;

            case FS_OCCUPANT_DIRECTORY:
            case FS_OCCUPANT_REGULAR:
            case FS_OCCUPANT_SYMLINK:
                break;
        }

        bool is_dir = occupant == FS_OCCUPANT_DIRECTORY;

        if (is_dir) {
            /* Another scan root's directory — by identity, whatever this frame
             * joined — is that root's to enumerate, from a depth 0 of its own
             * and under its owner's names and rules. Asked before the name and
             * before any rule: an owner's exclusion is the owner's, and a walk
             * from outside inherits none of it. */
            if (find_scan_root(scan->roots, scan->root_count, st.st_dev, st.st_ino)) continue;

            /* A blob the view holds at the directory or above it. Asked before
             * the name and before any rule: an offer beneath it is one no apply
             * can place, whoever would name it, and committing it turns a
             * view-versus-disk conflict the user can resolve into a
             * view-versus-view one only `remove` can. Said on its own screen
             * rather than here — the file analysis stands the [type] at the blob's
             * own path, with the remedies beside it. */
            const manifest_row_t *blob = NULL;
            err = blob_over(ws->manifest, child, scratch, &blob);
            if (err) goto cleanup;
            if (blob) continue;
        } else if (manifest_lookup(ws->manifest, child) || workspace_get_anchor(ws, child) ||
            standing_row(ws, child, &st) || standing_record(ws, child, &st)) {
            /* Whether anything already speaks for the leaf — by its spelling
             * and then by its entry, in descending order of standing. The view
             * holds it: a claim of any kind puts a row at the location, a directory
             * row at a file's path being the [type] the directory analysis said.
             * The record holds it: dotta managed the path and has not let go —
             * an orphan for cleanup to prune or release, or a path `remove
             * --delete-files` has ordered deleted and still remembers — never a
             * discovery, and a discovery again only once the record is retired.
             * And either of the two under another spelling of the same entry: a
             * row or a record standing on the very file this frame joined its
             * way to — a link no binding names, a root two profiles spell two
             * ways, a name the volume folds — is managed or remembered however
             * it is spelled, and offering it would commit one file twice or promise
             * a commit of a copy cleanup is about to prune. All four are the
             * load's own facts, built before any analysis runs
             * (workspace_partition, index_entries), so status, sync and update
             * read one answer whatever else each ran. The two identity probes
             * are paid only for a child neither string claimed — the offers. */
            continue;
        }

        /* What this profile calls the child — the claim standing there, else
         * the composition beneath the nearest directory claim above it, else
         * the label of the root it lies under, the word alone where the child
         * is one of this profile's own roots. */
        const char *name = NULL;
        err = manifest_name(ws->manifest, scan->profile, child, NULL, scratch, &name);
        if (err) {
            err = error_wrap(err, "Failed to name '%s'", child);
            goto cleanup;
        }

        /* Check if ignored: the rules on the mount-relative path, which is ""
         * at a root of this profile — no rule reaches an empty subject
         * (base/gitignore.c), so a root's entries are matched and a root is not.
         * Where no layer decided, the source tree's .gitignore on the location
         * (its root is that repo's) — the lowest layer, so a `!` rule above it
         * wins. That one reads the place and not the subject, so a root standing
         * inside a repository whose rules name it is not entered, which is the
         * answer the directory would get under any other name. The layer's own
         * failure leaves no verdict, as today; its allocation failure is the
         * run's. */
        gitignore_match_t match;
        gitignore_eval(scan->rules, label_tail(name), is_dir, &match);
        bool ignored = match.decided && match.ignored;
        if (!match.decided && scan->source_filter) {
            error_t *layer = source_filter_is_excluded(
                scan->source_filter, child, is_dir, &ignored
            );
            if (error_code(layer) == ERR_MEMORY) {
                err = layer;
                goto cleanup;
            }
            error_free(layer);
        }
        if (ignored) continue;

        /* Settled, so the descent is one statement. */
        err = is_dir ? scan_directory_for_untracked(scan, child, depth + 1)
                     : workspace_add_untracked(ws, child, name, scan->profile, occupant);
        if (err) goto cleanup;
    }

cleanup:
    arena_destroy(scratch);
    string_array_free(listing);

    return err;
}

/**
 * Analyze tracked directories for untracked files
 *
 * Every regular file and symlink beneath a tracked directory that no enabled
 * profile manages and dotta has no record of, offered to the profile whose tracked
 * directory it lies in — the nearest, by the directory's own identity; the
 * later-enabled where two stand at one — under the name that profile's own claims
 * give it (core/manifest.h manifest_name), minus what that profile's ignore layers
 * and the source tree exclude — and nothing at all beneath a path the view holds
 * a blob at, a tracked root of its own included (blob_over). A best-effort look,
 * said once per directory it could not list and once per path it could not look
 * at: not a snapshot, and not an admission — what the commit can hold at that
 * name is update's question at its capture (cmds/update.c).
 *
 * The driver enumerates the view's tracked directories, one scan each, and the
 * walk descends only into directories the view does not track (scan_root_t).
 */
static error_t *analyze_untracked_files(
    workspace_t *ws,
    const config_t *config
) {
    CHECK_NULL(ws);

    manifest_rows_t dirs = workspace_directories(ws);

    /* Sized by the directory rows, which bounds the appends: a row is tested
     * once per profile and matches its own alone, so it is a candidate in exactly
     * one pass and `dirs.count` counts every candidate there is. A row that
     * coincides with one already registered overwrites it rather than appending.
     *
     * The scan roots: every tracked directory that is a directory on disk, one
     * per directory. An ancestor claim is not one — the profile passes through
     * the directory on the way to something beneath it, and what it does manage
     * inside has its own tracked row, registered here on its own. A row beneath
     * a displaced ancestor is not one either, whatever a look at its key would
     * find: the key resolves through the squatter, so the directory found is
     * one the claim has no standing at — apply refuses beneath a squatter by
     * the same probe — and registering it would make that directory a boundary
     * no honest walk may enter. Asked of the key, the workspace's fact about
     * it, before the look. The look is at the row's own key, the link itself
     * and never what it reaches: a claim of a directory that is a link now is
     * the [type] the directory analysis said, and enumerating the link's target
     * would offer that directory's files as this row's. Registered in the view's
     * order, lowest profile first, so a later profile's row standing at a directory
     * an earlier one already stands at takes it — the index's own rule for a
     * contested location (core/manifest.c manifest_layer), applied where the
     * keys differ — and within one profile the later row in path order. */
    scan_root_t *roots = arena_calloc(ws->arena, dirs.count, sizeof(*roots));
    if (!roots) {
        return ERROR(ERR_MEMORY, "Failed to allocate the scan's roots");
    }
    size_t root_count = 0;

    size_t profile_count = 0;
    const char *const *profiles = manifest_profiles(ws->manifest, &profile_count);

    for (size_t p = 0; p < profile_count; p++) {
        for (size_t i = 0; i < dirs.count; i++) {
            const manifest_row_t *row = dirs.entries[i];
            struct stat st;

            if (!row->tracked || strcmp(row->profile, profiles[p]) != 0) continue;
            if (workspace_displaced_ancestor(ws, row->filesystem_path)) continue;
            if (fs_lstat_occupant(row->filesystem_path, &st) != FS_OCCUPANT_DIRECTORY) continue;

            scan_root_t *root = find_scan_root(roots, root_count, st.st_dev, st.st_ino);
            if (!root) root = &roots[root_count++];

            *root = (scan_root_t){
                .dev = st.st_dev, .ino = st.st_ino,
                .profile = row->profile, .directory = row->filesystem_path,
            };
        }
    }
    if (root_count == 0) return NULL;

    error_t *err = NULL;
    source_filter_t *source_filter = NULL;

    /* Source-tree .gitignore filter — built once for the whole scan so the
     * discovered source-repo handle is reused across every root. Driven by config;
     * policy decision lives here, not in the ignore module. Fatal on failure:
     * it can only fail on allocation (sys/source.c), and a scan that ran without
     * the layer it was told to consult would offer what the source tree excludes.
     * Unwrapped — the failure names its own subject. */
    if (config && config->respect_gitignore) {
        err = source_filter_create(&source_filter);
        if (err) return err;
    }

    /* Layered-rules builder — one per scan. The baseline is read and compiled
     * here, once; each profile's ruleset is composed on first use and cached,
     * so the roots below amortise the cost across the whole status (the previous
     * shape rebuilt an entire context per profile, re-loading the baseline each
     * time). No CLI layer: the scan reads no -e, and update's excludes filter
     * the items it nominates, afterwards (scope_is_excluded). */
    ignore_rules_t *ignore_rules = NULL;
    err = ignore_rules_create(ws->repo, config, NULL, ws->arena, &ignore_rules);
    if (err) {
        err = error_wrap(err, "Failed to build ignore rules");
        goto cleanup;
    }

    for (size_t r = 0; r < root_count; r++) {
        const scan_root_t *root = &roots[r];

        /* The same question at a root the driver reached directly: an independent
         * scan root beneath a file claim is as much beneath it as a child the
         * walk would have stopped at. An owner that cannot be enumerated is not
         * replaced: the directory stays a boundary and is not scanned, whatever
         * a lower row standing at it under a cleaner spelling could have offered
         * — the view's word about the directory is its owner's. */
        const manifest_row_t *blob = NULL;
        err = blob_over(ws->manifest, root->directory, ws->arena, &blob);
        if (err) goto cleanup;
        if (blob) continue;

        /* The owner's ruleset (memoised in the builder). Fatal on failure: scanning
         * a profile without its ignore rules risks reporting genuinely ignored
         * files as untracked, which the user could then `dotta add` by accident.
         * A corrupt .dottaignore must surface so the user can fix it. */
        const gitignore_ruleset_t *rules = NULL;
        err = ignore_rules_for_profile(ignore_rules, root->profile, &rules);
        if (err) {
            err = error_wrap(
                err, "Failed to load ignore patterns for profile '%s'", root->profile
            );
            goto cleanup;
        }

        /* What this root's walk runs under: the rows it meets are named by the
         * owner's contribution and excluded by its layers, and the roots are
         * where it stops. */
        const scan_t scan = {
            .ws            = ws,
            .roots         = roots,
            .root_count    = root_count,
            .profile       = root->profile,
            .rules         = rules,
            .source_filter = source_filter,
        };
        err = scan_directory_for_untracked(&scan, root->directory, 0);
        if (err) goto cleanup;
    }

cleanup:
    source_filter_free(source_filter);

    return err;
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

        /* Beneath a squatter, no look — the file analyzer's rule, stated there.
         * The rows are walked parents-first (workspace_partition sorts the slice),
         * so the squatter above this one was noted before this row's turn; a
         * squatter beneath a squatter is therefore never noted, and the outer
         * one carries the whole answer. Both classes: an ancestor claim beneath
         * a squatter is as unlooked-at as a tracked one. */
        if (displaced_ancestor(ws, filesystem_path, false)) {
            err = workspace_add_diverged(
                ws, row, anchor, WORKSPACE_STATE_DEPLOYED, DIVERGENCE_NONE,
                FS_OCCUPANT_UNKNOWN, WORKSPACE_FAULT_NONE
            );

            if (err) {
                return error_wrap(
                    err, "Failed to record displaced directory '%s'",
                    filesystem_path
                );
            }
            continue;  /* Recorded, move to next directory */
        }

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
        int lstat_errno = errno;   /* Valid on UNKNOWN (fs_lstat_occupant's contract) */

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
                occupant,
                WORKSPACE_FAULT_NONE
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
                occupant,                 /* assumed present */
                fault_class(error_code_from_errno(lstat_errno))
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
            /* The squatter, noted where it was observed: absence and an unstattable
             * path are ruled out above, so something real stands here and no
             * look beneath this path is taken at all. The row's class is the
             * claim (note_displaced). */
            err = note_displaced(
                ws, filesystem_path,
                row->tracked ? WORKSPACE_DISPLACED_TRACKED
                             : WORKSPACE_DISPLACED_DERIVED
            );
            if (err) return err;

            err = workspace_add_diverged(
                ws,
                row,
                anchor,
                WORKSPACE_STATE_DEPLOYED,  /* Path exists, just wrong type */
                DIVERGENCE_TYPE,           /* Type changed (dir -> file/symlink) */
                occupant,                  /* path exists, wrong type */
                WORKSPACE_FAULT_NONE
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
         * whether or not dotta manages the squatted path itself (note_displaced,
         * core/deploy's ancestry rung) — and absence is what deploy's ancestors
         * pass reads off the item. Absence is the one whose ANSWER differs by
         * class, and it is not split here: classify_absent carries that gate,
         * so the two analyzers cannot read an absent path two ways.
         *
         * The ancestry is the one question asked ahead of all of them, because
         * an answer taken beneath a squatter is no answer about this path.
         *
         * Everything below is the profile's word about a directory it manages,
         * and a derived claim has none to give. Its mode and ownership are a
         * snapshot of the machine the chain was captured on: they say what to
         * create the path as, never what to make of the one this machine already
         * has — asserting them here would let a ~/.ssh captured at a careless
         * 0755 loosen a correct 0700 elsewhere, a regression caused by the fix.
         * The handover tail is the rule's own: a claim nobody made carries no
         * intent to acknowledge, so workspace_reassigned answers false for a
         * derived claim wherever it is asked, and the record keeps the profile
         * dotta actually deployed under, which is what a record is for. */
        if (!row->tracked) continue;

        /* One rule, three analyzers: the row's mode is total (claim or floor)
         * and a directory row is never a link, so the compare needs no gate. */
        bool mode_differs = (dir_stat.st_mode & 0777) != row->mode;
        bool ownership_differs = ownership_diverges(
            row->storage_path, row->owner, row->group, &dir_stat
        );

        /* Record divergence if any metadata differs, or a pending handover stands
         * — the rule read over the pair this loop has held throughout, and the
         * tail the file analyzer has: a clean reassigned row emits an item, state
         * DEPLOYED, divergence NONE, so status's Reassigned section and apply's
         * collection see both kinds. One rule, both kinds — and the rule asks
         * the row's class itself, so a derived claim answers false here whatever
         * its record says, and the tracked gate above is about everything else
         * this loop measures. */
        if (mode_differs || ownership_differs || workspace_reassigned(row, anchor)) {
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
                occupant,
                WORKSPACE_FAULT_NONE
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
 * Order two rows by filesystem path (qsort callback)
 *
 * strcmp order is SQLite's BINARY order, which the slices carried when they were
 * read from a table: a parent sorts before every path beneath it, which deploy's
 * parent-before-child walk relies on, and the untracked scan's registration reads
 * for the tie among one profile's rows standing at one directory.
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

    err = workspace_create_empty(repo, &ws);
    if (err) {
        return err;
    }

    /* Borrow caller-owned resources. Lifetime guarantees: state comes from
     * ctx->run.state (command-scoped); content_cache comes from
     * ctx->run.content_cache (command-scoped, wraps ctx->run.keymgr); manifest
     * is ctx->run.manifest (the view the dispatcher built over the enabled set,
     * command-scoped); arena is ctx->arena (command-scoped). All four must outlive
     * workspace_free. The view is the persistent enabled set's, never a CLI
     * filter's: `dotta status -p global` loads the whole workspace and filters
     * at display time. */
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

    /* The analyses, in the order the load's own contract groups them: the join
     * first and whole — the file and directory analyses, which every command's
     * load runs (workspace_load_t) — then the optional ones. The directory rows
     * come first within the join because they are the only producer of the view's
     * squatters (note_displaced), and every look the load takes after this one
     * asks first whether a squatter stands above the path: the file rows, the
     * orphan records, the entries index, the scan's roots. */

    /* The join: the view's directory rows; notes the displaced directories a
     * claim of the view holds */
    if (options->analyze_directories) {
        err = analyze_directory_metadata_divergence(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze directory metadata");
        }
    }

    /* The join: the view's file rows (most common requirement) */
    if (options->analyze_files) {
        err = analyze_files_divergence(ws, config);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze file divergence");
        }
    }

    /* The entries — where every row and every orphan record stands, by identity
     * — for the two verbs that act on an entry through a string. After the
     * directory analysis, whose displaced set says which rows were observed at
     * their own path; before the orphan analysis, whose guard reads it; and only
     * where a reader may ask, which is this gate said once for both: the orphan
     * analysis returns at its first line with no orphan, and the scan asks per
     * offer. Every ask below is therefore made on a load this built the index
     * in (find_entries). */
    if ((options->analyze_orphans && ws->orphan_count > 0) || options->analyze_untracked) {
        err = index_entries(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to index the entries");
        }
    }

    /* Optional: the orphans (records of either kind the view lacks); notes the
     * displaced directories only a record remembers, and its guard reads the
     * entries */
    if (options->analyze_orphans) {
        err = analyze_orphans(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze orphans");
        }
    }

    /* Optional: new files beneath the tracked directories */
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

    /* The view-only face of the one scan (displaced_ancestor): a record's memory
     * reaches the record family alone, whose items carry the fact themselves
     * (the reach rule, workspace_displaced_t), and this probe's askers hold no
     * item. */
    const displaced_dir_t *dir = displaced_ancestor(ws, path, false);

    return dir ? dir->path : NULL;
}

/**
 * Look up the record dotta keeps of a path
 *
 * O(1) hashmap probe over the anchors snapshot. The map's value is a mutable
 * record pointer (workspace_observe and workspace_anchor patch in place); external
 * callers receive a const view.
 *
 * The analyses pair each row with its record through this; the untracked scan
 * asks it of a leaf the view has no row for, a path dotta remembers being no
 * discovery of the scan's.
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

    /* A squatter the view claims stands above the path, so nothing there was
     * looked at and no bit below can be this path's — deploy's ANCESTOR rung
     * and cleanup_verdict's displaced arm rank the same fact the same way. RECORD
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
        return manifest_is_derived(item->row) ? WORKSPACE_ROUTE_KIND_DERIVED
                                              : WORKSPACE_ROUTE_KIND;
    }

    if (divergence != DIVERGENCE_NONE) {
        return WORKSPACE_ROUTE_CAPTURE;
    }

    return workspace_reassigned(item->row, item->anchor) ? WORKSPACE_ROUTE_REASSIGNED
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
            if (workspace_reassigned(item->row, item->anchor)) {
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
                /* Beneath a squatter (workspace_displaced_t): nothing here was
                 * looked at, so the item carries none of the bits the tags below
                 * name — and a tag read off a look nobody took would name work
                 * no verb takes. The one tag, at the default colour: the squatter's
                 * own row carries the severity, and the route lists this item
                 * under it. */
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
                    /* The failed look, worded by whose remedy it is
                     * (workspace_fault_t) — the same word the orphaned arm below
                     * prints, so one path has one name wherever it is listed.
                     * Conservative handling downstream (update refuses it, apply
                     * skips it at preflight, cleanup skips the orphan). */
                    if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                        switch (item->fault) {
                            case WORKSPACE_FAULT_LOCKED:
                                tags_out[tag_count++] = "locked";
                                break;
                            case WORKSPACE_FAULT_UNREADABLE:
                                tags_out[tag_count++] = "unreadable";
                                break;
                            case WORKSPACE_FAULT_NONE:
                            case WORKSPACE_FAULT_UNVERIFIED:
                                tags_out[tag_count++] = "unverified";
                                break;
                        }
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
            if (workspace_reassigned(item->row, item->anchor)) {
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

            } else if (item->displaced != WORKSPACE_DISPLACED_NONE) {
                /* A squatter stands above the path, so nothing there was looked
                 * at and no bit below was ever read (workspace_displaced_t).
                 * Checked here for the reason absence is checked above it: such
                 * an item carries DIVERGENCE_NONE by construction, so the arms
                 * below would report it clean and promise the prune apply does
                 * not make — cleanup_verdict releases it and the path stays.
                 * Ranked as that verdict ranks it, after absence and before the
                 * bits, and coloured as a release is. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "displaced";
                }
                *color_out = OUTPUT_COLOR_MAGENTA;

            } else if (item->divergence & DIVERGENCE_UNVERIFIED) {
                /* The failed look, worded by whose remedy it is (workspace_fault_t)
                 * — the deployed arm's switch, so one item has one name in both.
                 * Conservative: apply skips it (CLEANUP_SKIP_UNVERIFIED, ranked
                 * first there as it is here — one item, one name). */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    switch (item->fault) {
                        case WORKSPACE_FAULT_LOCKED:
                            tags_out[tag_count++] = "locked";
                            break;
                        case WORKSPACE_FAULT_UNREADABLE:
                            tags_out[tag_count++] = "unreadable";
                            break;
                        case WORKSPACE_FAULT_NONE:
                        case WORKSPACE_FAULT_UNVERIFIED:
                            tags_out[tag_count++] = "unverified";
                            break;
                    }
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
             * still has a row, projected elsewhere. Whether there is one at all
             * is the class against NONE, here as at every screen (workspace.h).
             * The fate stays cleanup's, and turns on which class it is (a
             * re-targeted custom/ copy prunes, a moved home holds behind --force);
             * this only names what the copy is. */
            if (item->relocation != WORKSPACE_RELOCATION_NONE) {
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
