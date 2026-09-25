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
 * the analyses read it as the base of every three-way question, and its writers
 * here (the flush, workspace_observe_retyped, workspace_anchor, workspace_confirm)
 * advance it only on disk's word — a live look there, or the run's own write —
 * all but the flush's void, which clears an order on the view's word: the path
 * is back in the view. A record whose path the view lacks is an orphan, and the
 * orphan analysis asks Git — the only authority that knows — why it is one.
 *
 * Each path the join holds is an item (core/workspace.h workspace_item_t): one
 * per active path and one per record the view lacks, made at the partition with
 * the record at its path paired onto it, before anything is looked at. The
 * filesystem side is looked at once, into the item (workspace_look), which notes
 * the squatters it finds as it goes. Two walks take the looks: the active items
 * in one, every directory before any file, each analyzed as its kind asks; and
 * the records the view lacks in a phase of their own, after it. Every phase after
 * a look reads the item rather than looking again. The entries index holds the
 * items whose look found their claim's kind, the orphan analysis measures the
 * copy off the item's own stat and errno, the scan's roots take their kind and
 * identity off the directory item's look. So no two phases can disagree about
 * what stands somewhere, and the load's cost is one look per active path and
 * per orphan record. The one look taken after the join is the untracked walk's,
 * at a child no claim settles — the one path the load holds no fact about at all.
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
 * Workspace structure
 *
 * Holds the view, the record and the divergence analysis over both, joined in
 * the items: one per active path and one per record the view lacks, each with
 * its sources, its look and its verdict (workspace_item_t).
 */
struct workspace {
    git_repository *repo;                        /* Borrowed reference */
    arena_t *arena;                              /* Borrowed; backs every workspace-lifetime string */

    /* The view: every enabled profile at HEAD, built by the dispatcher at the
     * start of the command and borrowed here (ctx->run.manifest — its rows are
     * the command arena's, its index the dispatcher's to release). Rows are
     * read-only for the whole run — the record a writer patches is the one its
     * item holds (workspace_item_t), never a row. The view's own index answers
     * the scan, at each child it lists and each rung above a root
     * (scan_directory_for_untracked, blob_over): a path is one row, and each
     * asks row->type for the kind it wants. A reader outside the module asks
     * for the path's item instead, which carries its row (workspace_find). */
    const manifest_t *manifest;                  /* Borrowed — NOT freed in workspace_free */

    /* The active items: one per row of the view, the directories and then the
     * files, each in strcmp order (workspace_kind_order) — the order they are
     * looked at in, the one a path is found by (workspace_find_active), and the
     * one they are lent in, whole and by kind (workspace_active,
     * workspace_directories, workspace_files). Pointers into one arena block,
     * never moved. Never NULL (workspace_partition). */
    workspace_item_t **active;                   /* Arena; active[0 .. dir_count) the directories */
    size_t dir_count;                            /* The directory items */
    size_t file_count;                           /* The file items, active[dir_count ..] */

    /* The orphan items: the records whose path the view lacks, in the snapshot's
     * strcmp order, which workspace_look_orphans' parents-first walk and their
     * search (workspace_find_item) rest on. Read-only — no row names an orphan's
     * path, so no writer ever reaches one; the orphan analysis asks Git why each
     * is here. Each is looked at by workspace_look_orphans, which runs where
     * one of its readers will (workspace_load); an orphan no look reached reads
     * a look nobody took, and no reader is lent one. Nor is one the load looked
     * at and never analyzed — a load with the orphan analysis declined looks at
     * them for the entries index alone — so the diverged items list, and a path
     * finds, the analyzed prefix and no other, which is every orphan or none
     * (workspace_list, workspace_find). Never NULL (workspace_partition). */
    workspace_item_t **orphans;                  /* Arena; singles, never moved */
    size_t orphan_count;                         /* Number of orphans */
    size_t analyzed_count;                       /* orphans[0 .. analyzed_count): the ones the load analyzed */

    /* The released copies, snapshot at load beside the record, unconditionally
     * (workspace_partition), in the getter's strcmp order. One reader, by design:
     * the base derivation in workspace_analyze_file, which searches it by path
     * (state_lookup_released_copy), and only when the path's record carries no
     * confirmed blob — a released copy is not a claim. Frozen at load: the database
     * forgets a copy with its path's next ownership event or content confirmation
     * (state_anchor, state_confirm), and nothing here follows, so a reader after
     * the analysis would read copies the database no longer holds. */
    released_copy_t *released;                   /* Arena snapshot from state_get_released_copies */
    size_t released_count;                       /* Number of released copies */

    /* The record's handle: the store's database, borrowed from the caller
     * (workspace_load). Read once at the partition — the record, which the items
     * hold, and the released copies above — then written through by the four
     * writers (the flush, workspace_observe_retyped, workspace_anchor,
     * workspace_confirm), each advancing the record it persists. */
    state_t *state;                              /* The record's handle (borrowed from caller) */

    /* Content cache for encrypted blob reads during divergence analysis */
    content_cache_t *content_cache;              /* Borrowed — NOT freed in workspace_free */

    /* The diverged items: every item the analyses left with something to say,
     * derived once every verdict is in (workspace_list), then the scan's
     * discoveries. The array owns only the pointer buffer. */
    ptr_array_t diverged;                        /* workspace_item_t *: active, analyzed orphans, discoveries */

    /* The squatted directories: every path a claim names as a directory that
     * the load's look found occupied by anything else, with the claim. Noted by
     * the look that found one and asked before every look after it, which writes
     * the answer onto the item it withholds the look from (workspace_look, squatted_ancestor);
     * lent whole to a caller holding a path (workspace_squatted_ancestor); paths
     * borrowed from the rows and the records. Almost always empty, which is what
     * makes every ask free. */
    workspace_squatted_t *squatted;              /* Arena; sized by the partition, never grown */
    size_t squatted_count;

    /* The entries: every item whose look found its claim's kind standing at its
     * key — an active item at its row's, an orphan at its record's — by the (dev,
     * ino) that look found: the load's one look at the disk by identity, for
     * the two verbs that act on an entry through a string: cleanup's unlink (the
     * orphan analysis's guard) and the scan's offer (the leaf probe). Sorted by
     * identity; built by index_entries only on a load one of the two may ask
     * in, else NULL and none. */
    const workspace_item_t **entries;            /* Arena; sorted by (dev, ino) */
    size_t entry_count;
};

/**
 * The active items' order: the directories, then the files, each in strcmp order
 *
 * The order the load looks in — its one walk over the active items is this array's
 * (workspace_load) — and why it is this one: a squatter is noted by the look
 * that finds it and asked before every look after it (workspace_look), so every
 * directory claim must be looked at before any file row, and among the directories
 * a parent before everything beneath it — which strcmp gives, a parent's path
 * being a prefix of its child's. The same order splits the array into the directory
 * items and the file items every kind-specific reader walks (workspace_directories,
 * workspace_files), deploy's directories before its files; is deploy's
 * parent-before-child walk within each; is what the untracked scan's registration
 * reads for the tie among one profile's rows standing at one directory; and is
 * the one each kind's search rests on (workspace_find_item). The view holds one
 * row per path, so the order is total.
 */
static int workspace_kind_order(const void *a, const void *b) {
    const workspace_item_t *ia = *(const workspace_item_t *const *) a;
    const workspace_item_t *ib = *(const workspace_item_t *const *) b;

    if (ia->item_kind != ib->item_kind) {
        return ia->item_kind == PATH_KIND_DIRECTORY ? -1 : 1;
    }

    return strcmp(ia->filesystem_path, ib->filesystem_path);
}

/* bsearch's: a path against an item's (strcmp) — the order of every array it
 * searches: each kind's active items by workspace_kind_order, the orphans by
 * the snapshot's own (core/state.h state_get_all_anchors) */
static int workspace_path_order(const void *key, const void *elem) {
    const workspace_item_t *const *item = elem;

    return strcmp(key, (*item)->filesystem_path);
}

/**
 * The item at a path in one sorted array — one kind's active items, or the orphans
 * — or NULL
 *
 * Two askers search the orphans, each to a bound of its own: workspace_find to
 * the analyzed prefix it lends, the scan's leaf guard to every record, analyzed
 * or not (scan_directory_for_untracked). No such array is ever NULL
 * (workspace_partition), so an empty one is searched as it stands.
 */
static workspace_item_t *workspace_find_item(
    workspace_item_t *const *items,
    size_t count,
    const char *path
) {
    workspace_item_t *const *found = bsearch(
        path, items, count, sizeof(*items), workspace_path_order
    );

    return found ? *found : NULL;
}

/**
 * The active item at a path, either kind: the directory items, then the file items
 *
 * Readers: the partition, pairing each record with the item at its path, and
 * workspace_find, which asks it before the orphans.
 */
static workspace_item_t *workspace_find_active(const workspace_t *ws, const char *path) {
    workspace_item_t *item = workspace_find_item(ws->active, ws->dir_count, path);

    return item ? item : workspace_find_item(ws->active + ws->dir_count, ws->file_count, path);
}

/**
 * Does disk ownership diverge from the claim?
 *
 * The ownership half of every divergence check — one rule for a row's claim
 * (workspace_analyze_claim, both kinds) and a record's (workspace_compare_orphan).
 * What the sheet says here is the sheet's to say (core/metadata.h
 * metadata_ownership) and this function is the comparison alone, one per reading:
 * the names it claimed, and only those, are compared by name (NULL skips that
 * half), and a UID/GID the system cannot resolve to one reads as divergence —
 * unknown ≠ expected (security-first); silence the sheet reads as the invoker's
 * own compares the owner to the invoker; and silence it says nothing about compares
 * nothing. Whether this run could chown does not enter — the lstat needs no
 * privilege, and a claim the disk contradicts is a fact about the path whoever
 * reads it.
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
static workspace_fault_t workspace_code_fault(error_code_t code) {
    switch (code) {
        case ERR_LOCKED:     return WORKSPACE_FAULT_LOCKED;
        case ERR_PERMISSION: return WORKSPACE_FAULT_UNREADABLE;
        default:             return WORKSPACE_FAULT_UNVERIFIED;
    }
}

/**
 * Class a look's outcome, and consume its error
 *
 * The class is all the item keeps: the message is the failing verb's to print,
 * and this analysis is not failing — it is reporting a path it could not read.
 * WORKSPACE_FAULT_NONE where the look succeeded and there is nothing to consume
 * — total over the convention every verb in the tree returns by, so a fold can
 * be written at the call itself rather than through a local whose only job is
 * to outlive the test (workspace_measure; Rule 5).
 *
 * Called at the two folds that hold an error of the look they just made —
 * workspace_analyze_file's look at the content, workspace_measure's compare.
 * The four that hold an errno instead reach workspace_code_fault directly:
 * workspace_analyze_file and workspace_analyze_directory at their lstat,
 * workspace_measure at its own and at a directory's access check.
 */
static workspace_fault_t workspace_error_fault(error_t *err) {
    if (!err) {
        return WORKSPACE_FAULT_NONE;
    }

    workspace_fault_t fault = workspace_code_fault(error_code(error_root(err)));
    error_free(err);
    return fault;
}

/**
 * The squatted directory that reaches `path`, or NULL — the reach rule as a scan
 *
 * Proper ancestors only (str_path_beneath is strict), so a squatter is never
 * its own answer, and the outermost among those that reach the asker: the shortest
 * match, because the true offender is the one whose fate settles every claim
 * beneath it. The list is in the order the load looks, not in path order — the
 * view's squatters are noted before the record's — so the scan asks for the minimum
 * rather than the first hit. Whose claims reach the asker is the rule's one input:
 * a view claim reaches every path beneath it, a record's memory
 * (WORKSPACE_DISPLACED_RECORD) the orphans alone (workspace_displaced_t).
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
 * Readers: workspace_look, before every look the load takes — the one door, which
 * writes the answer onto the item it withholds the look from — and
 * workspace_squatted_ancestor, the view-only face that lends the answer whole
 * to a caller that needs the squatter itself (core/deploy.c check_ancestry).
 *
 * @param ws Workspace (must not be NULL)
 * @param path The asker's path (must not be NULL)
 * @param orphan Whether the asker is an orphan, the one item a record's memory
 *        reaches
 */
static const workspace_squatted_t *squatted_ancestor(
    const workspace_t *ws,
    const char *path,
    bool orphan
) {
    const workspace_squatted_t *outermost = NULL;

    for (size_t i = 0; i < ws->squatted_count; i++) {
        const workspace_squatted_t *dir = &ws->squatted[i];

        if (dir->claim == WORKSPACE_DISPLACED_RECORD && !orphan) continue;
        if (str_path_beneath(path, dir->filesystem_path, dir->len) &&
            (!outermost || dir->len < outermost->len)) {
            outermost = dir;
        }
    }

    return outermost;
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
 * them rather than aliasing: the path the walk joined and the name the namer
 * answered live in a frame's scratch arena that the frame's next entry reclaims,
 * and the item outlives every frame. The profile is the owner's — the row's own,
 * whose tracked directory the walk began at — and is the view's arena's already.
 *
 * No earlier item stands at the path: the view's and the record's paths were
 * skipped at the leaf guard, and no directory is enumerated twice (one scan root
 * per directory, workspace_analyze_untracked), so the diverged items list the
 * path once. Stated rather than guarded, and pinned by the exactly-once fixtures
 * (tests/test-scan.sh).
 *
 * The look is the scan's own: the occupant and the stat its lstat found, so a
 * discovery's `st` is meaningful as every present item's is (workspace.h).
 *
 * @param ws Workspace context (must not be NULL)
 * @param filesystem_path The path the walk joined (must not be NULL)
 * @param storage_path The name the namer answered (must not be NULL)
 * @param profile The owner's, the view's row's (must not be NULL)
 * @param occupant What the scan's lstat found at the path (workspace.h)
 * @param st The scan's lstat of the path (must not be NULL)
 */
static error_t *workspace_add_untracked(
    workspace_t *ws,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    fs_occupant_t occupant,
    const struct stat *st
) {
    CHECK_NULL(ws);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);

    workspace_item_t *item = arena_alloc(ws->arena, sizeof(*item));
    if (!item) {
        return ERROR(ERR_MEMORY, "Failed to allocate untracked item");
    }

    *item = (workspace_item_t){
        .filesystem_path = arena_strdup(ws->arena, filesystem_path),
        .storage_path = arena_strdup(ws->arena, storage_path),
        .profile = profile,
        .item_kind = PATH_KIND_FILE,
        .occupant = occupant,
        .st = *st,
        .state = WORKSPACE_STATE_UNTRACKED,
    };
    if (!item->filesystem_path || !item->storage_path) {
        return ERROR(ERR_MEMORY, "Failed to copy untracked paths");
    }

    error_t *err = ptr_array_push(&ws->diverged, item);
    if (err) {
        return error_wrap(err, "Failed to append untracked item");
    }

    return NULL;
}

/**
 * Note that disk holds the row's content, for the record to learn
 *
 * The content half of the item's confirmation: the file analysis found disk to
 * be the row's pair — the slow path's CMP_EQUAL, or a released base's fast-path
 * hit — a pair the record does not hold, so the flush confirms it
 * (workspace_confirm), persisting the row's blob beside the look's triple: the
 * next run can both short-circuit via the fast-path stat and, if Git advances
 * the row's blob in the meantime, classify the file as stale from the fast path
 * instead of re-hashing. The claim's half has no gate and no proof, and its
 * analysis notes it itself (workspace_analyze_claim).
 *
 * The blob is the row's: the proof binds the stat to the blob the row expected
 * when disk was found equal to it, and state_confirm reads it from the row — a
 * stat triple without its blob is meaningless, and the row is the one the stat
 * was verified against. A path with no record yet is noted from this row like
 * any other: the flush observes it before it confirms, and the record the
 * observation makes is this row's.
 *
 * Callers: workspace_analyze_file's two content verdicts, each made where the
 * look stands at the row's kind.
 *
 * @param item The row's item, its look standing at the row's kind (must not be
 *             NULL); where the gate admits the content, its confirmation gains
 *             DIVERGENCE_CONTENT and its proof the look's triple
 */
static void workspace_note_content(workspace_item_t *item) {
    const manifest_row_t *row = item->row;
    const anchor_t *anchor = item->anchor;

    /* Only onto a record that is this row's content base. Bound to this row: an
     * encrypted blob opens under one binding and no other, and state_confirm's
     * statement refuses another at the write — asked of the record first, so a
     * confirmation that cannot land never opens the flush's transaction; a row
     * the binding does not name is one the record has yet to follow, which takes
     * the slow path on every load until apply's acknowledgement moves the record
     * onto it. And of this row's kind, the ladder's first rung (core/workspace.h
     * workspace_compare_confirmed), never path_type_kind, whose taxonomy files
     * a link beside the files: a record of another kind is a fact about a node
     * that is gone, and a confirmation would carry the ownership stamp dotta
     * earned for it onto a node dotta never wrote — a link the user made, a file
     * where dotta's directory was — which apply adopts instead, as it adopts a
     * row with no record (cmds/apply.c). */
    if (anchor &&
        (!manifest_is_claim(row, anchor->profile, anchor->storage_path) ||
        workspace_compare_confirmed(row, anchor->type, &anchor->blob_oid) == CMP_TYPE_DIFF)) {
        return;
    }

    /* The proof, distilled from the look where the comparison stood: whether
     * its mtime second had closed is asked of the clock now, never of the flush's
     * later one, which would take for proof a triple that a same-second rewrite
     * after the read could stand behind (core/state.h stat_cache_from_stat). */
    item->confirmation |= DIVERGENCE_CONTENT;
    item->proof = stat_cache_from_stat(&item->st);
}

/**
 * The load's one look at an item's path, and the squatter it finds
 *
 * The one door for every look the load takes at a path it knows — the directory
 * analysis's, the file analysis's, workspace_look_orphans' — so both halves of
 * the reach rule (core/workspace.h workspace_displaced_t) live here: no look is
 * taken beneath a squatter, and every squatter is noted by the look that found
 * it. The note is the squatted fact's one producer, as the look is the occupant's
 * (core/cleanup.h), and it cannot fail: the partition made room for every note.
 *
 * Readers of the notes: squatted_ancestor, asked here before each look; and
 * core/deploy.c check_ancestry, lent them through workspace_squatted_ancestor.
 *
 * @param ws Workspace (must not be NULL)
 * @param item The item to look at (must not be NULL)
 */
static void workspace_look(workspace_t *ws, workspace_item_t *item) {
    /* No look beneath a squatter: it would answer for the squatter — a link's
     * target, a file's ENOTDIR — and nothing it said would be this path's. The
     * item takes the claim's class instead and keeps UNKNOWN, a look nobody took.
     * An orphan (no row) is reached by a record's memory as well as by the view's
     * claims; an active item by the view's claims alone. */
    const workspace_squatted_t *above = squatted_ancestor(
        ws, item->filesystem_path, item->row == NULL
    );
    if (above) {
        item->displaced = above->claim;
        return;
    }

    /* One lstat into the item, errno read at once: it is lstat's until anything
     * else runs (fs_lstat_occupant's contract). */
    item->occupant = fs_lstat_occupant(item->filesystem_path, &item->st);
    item->lstat_errno = errno;

    /* A squatter is a directory claim with another kind of node in its place.
     * Absence squats nothing, and a look that failed proves nothing. */
    if (item->item_kind != PATH_KIND_DIRECTORY || item->occupant == FS_OCCUPANT_DIRECTORY ||
        item->occupant == FS_OCCUPANT_NONE || item->occupant == FS_OCCUPANT_UNKNOWN) {
        return;
    }

    /* Held by the item's claim: a record's memory, or the view row's class */
    workspace_displaced_t claim = WORKSPACE_DISPLACED_RECORD;
    if (item->row) {
        claim = item->row->tracked ? WORKSPACE_DISPLACED_TRACKED : WORKSPACE_DISPLACED_DERIVED;
    }

    /* Noted where it was found, for every later look to ask; the looks' order
     * makes that soon enough (workspace_kind_order). */
    ws->squatted[ws->squatted_count++] = (workspace_squatted_t){
        .filesystem_path = item->filesystem_path,
        .len = strlen(item->filesystem_path),
        .claim = claim,
    };
}

/**
 * Absence classification — the single decision for every absent active path,
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
 * (metadata.h's residue rule: when the last tracked path beneath it goes), which
 * this would answer over the top of.
 *
 * And dotta has to have seen the path there. A record exists iff dotta has seen
 * at the path in scope the node its kind names, or put it there — an observation
 * is made only where the row's own kind stands, so a node of another kind the
 * user removes leaves no witness — so no record means there was no filesystem
 * obligation to break: absence is UNDEPLOYED, apply's to create. And the record
 * has to have seen the claim's kind of node: one of another kind (the kind rung,
 * core/workspace.h workspace_compare_confirmed) saw a node that is gone — a file
 * where the claim is now a directory, a link where it is now a file — and the
 * node the claim asserts was never here to be removed, so its absence deletes
 * nothing and update must not commit it as a removal.
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

    return anchor &&
           workspace_compare_confirmed(row, anchor->type, &anchor->blob_oid) != CMP_TYPE_DIFF
           ? WORKSPACE_STATE_DELETED
           : WORKSPACE_STATE_UNDEPLOYED;
}

/**
 * The claim's half of a row's verdict: what differs, who moved it, and what the
 * record learns
 *
 * Axis by axis — DIVERGENCE_MODE, DIVERGENCE_OWNERSHIP — where the look stands
 * off the row's claim, with DIVERGENCE_CLAIM_MOVED beside them where Git moved
 * one of those past the record's (workspace_claims_moved), all added to the item's
 * divergence; and each claim Git moved that the look already stands on, added
 * to its confirmation for the record to learn. Asked only of a look standing at
 * the row's kind, the one whose stat says anything of the row: each analysis
 * rules out absence and another kind before it asks.
 *
 * One rule for the two analyses of an active item (workspace_analyze_file,
 * workspace_analyze_directory). The orphan analysis asks the same compare of
 * the record's claim, and learns nothing (workspace_compare_orphan).
 *
 * @param item The active row's item, a file's or a tracked directory's, its look
 *             standing at the row's kind (must not be NULL); the claim's bits
 *             are added to its divergence, the verdict so far, and what the record
 *             is to learn to its confirmation
 */
static void workspace_analyze_claim(workspace_item_t *item) {
    const manifest_row_t *row = item->row;
    const anchor_t *anchor = item->anchor;

    /* The mode, where the kind carries one. The row's is total — the claim, or
     * the filemode floor manifest_build resolved absence into — so one full-bit
     * compare answers, the executable bit riding in it; a link row is never asked
     * (its 0 is a don't-care, not a value), and a directory row is never a link. */
    divergence_type_t claims = DIVERGENCE_NONE;
    if (row->type != PATH_TYPE_SYMLINK && (item->st.st_mode & 0777) != row->mode) {
        claims |= DIVERGENCE_MODE;
    }

    /* The ownership, its own axis, links included: the sheet's word, compared
     * by the rule the orphan analysis asks of the record too
     * (ownership_diverges). */
    if (ownership_diverges(row->storage_path, row->owner, row->group, &item->st)) {
        claims |= DIVERGENCE_OWNERSHIP;
    }

    /* Who moved it. An axis Git moved past the claim the record last reconciled
     * and disk has not followed is Git's to bring — whoever else moved it, since
     * apply converges every claim, and update's capture would commit disk's over
     * Git's move. The bit rides beside the axis it attributes, never alone. */
    divergence_type_t moved = workspace_claims_moved(row, anchor);
    if (claims & moved) {
        claims |= DIVERGENCE_CLAIM_MOVED;
    }
    item->divergence |= claims;

    /* An axis Git moved that disk already stands on is the record's to learn,
     * whoever owns the path — a directory dotta never owned learns it too: the
     * record follows every agreement, so the user's next move on that axis reads
     * as the user's, and an orphan is measured against the claim disk stood on.
     * As it comes, whichever row the record's binding names: a claim opens nothing,
     * where the content's confirmation is bound to the row's binding because an
     * encrypted blob opens under one (workspace_note_content). And only onto a
     * base for it — no record, or one of another kind, is none, which
     * workspace_claims_moved has already asked. */
    item->confirmation |= moved & ~claims;
}

/**
 * Analyze divergence for a single active file row
 *
 * All expected state (blob_oid, type, mode, etc.) is in the view row — no database
 * queries, no Git; the record dotta keeps of the path is the item's, paired onto
 * it at the partition.
 *
 * The content's verdict is three-way, with dotta's last content confirmation as
 * base (see the content and type analysis below — the record's blob, or a released
 * fact's when the record carries none): DIVERGENCE_STALE says Git moved past
 * the pair dotta last confirmed, DIVERGENCE_CONTENT says disk left it. Each is
 * a verdict in its own right — STALE without CONTENT is apply-side work that
 * overwrites nothing of the user's; CONTENT without STALE is a local edit Git
 * has not raced; both together is a conflict.
 *
 * The claim's verdict is one question per axis (workspace_analyze_claim): did
 * Git move it past the claim the record last reconciled? DIVERGENCE_CLAIM_MOVED
 * says so, beside the axis that differs, and is STALE's twin for the routes — a
 * move of Git's that disk has not followed, a conflict beside CONTENT. The
 * content's second question has no claim twin: apply converges every claim whoever
 * moved it, so whether disk also left the record's claim would change no verb.
 *
 * Reassignment is the same pairing read on the profile axis: the record says
 * who deployed the disk content, the row says who owns the path now, and the
 * two differing is a state — "disk holds what A deployed; B owns the path now"
 * — that apply acknowledges by rewriting the record (the adoption loop for a
 * clean row, the deployment itself for a stale one). Only an owned record
 * qualifies: an observed or confirmed record that dotta never deployed names
 * the row the path was first seen under, not a deployer, and apply adopts such
 * a path rather than acknowledging it. And across kinds only while the look finds
 * the record's own node standing — that is when disk holds what A deployed
 * (workspace_reassigned). No bit of this verdict says so: the route reads it
 * off the item's sources and look, and a clean reassignment is among the diverged
 * items by that reading alone (workspace_list).
 *
 * The blob bit, ENCRYPTION (workspace.h, divergence_type_t), is settled here
 * too, once per row, from the row and the config alone: row->encrypted is byte
 * truth by the write-boundary invariant (stamped from the blob's bytes at every
 * committing boundary — policy.h names them — projected onto the row at build),
 * so the audit costs one pattern match and inflates nothing. The filesystem is
 * not one of its operands, so every arm carries it — it survives absence and
 * rides beside TYPE and UNVERIFIED alike. A symlink row can never carry it: the
 * predicate answers only for content-bearing kinds (policy.h owns the rationale),
 * so a link whose path matches a pattern is not a violation the capture could
 * never resolve.
 *
 * @param ws Workspace (must not be NULL)
 * @param item The row's item, its record paired at the partition (must not be
 *             NULL). Its look is taken here, and the phases after the join read it
 * @param config Configuration for the auto-encrypt ruleset (can be NULL)
 */
static void workspace_analyze_file(
    workspace_t *ws,
    workspace_item_t *item,
    const config_t *config
) {
    const manifest_row_t *row = item->row;
    const char *filesystem_path = item->filesystem_path;
    const char *storage_path = item->storage_path;
    const char *profile = item->profile;

    /* The record dotta keeps of this path, if any. NULL means dotta has never
     * seen the row's kind standing here in scope, or its record retired since:
     * absence reads UNDEPLOYED, and a released copy is the only base there can
     * be (below). */
    const anchor_t *anchor = item->anchor;

    /* The row's verdict, opened with the blob bit (see the doc above): is the
     * blob Git holds for this row stored plaintext where the auto-encrypt policy
     * claims the path? Git's alone, so every arm below carries it. The path bits
     * are written from the content's switch on, so an arm that returns before
     * the switch carries the blob bit alone. */
    item->divergence =
        encryption_policy_violation(config, storage_path, row->type, row->encrypted)
        ? DIVERGENCE_ENCRYPTION : DIVERGENCE_NONE;

    /* The load's one look at this path, taken into the item (workspace_look):
     * the existence question, the kind the comparisons verify, the mode and
     * ownership the metadata checks read — and, after this analysis has run,
     * the identity index_entries reads. Nothing below retakes it, and nothing
     * after the join does either. */
    workspace_look(ws, item);

    /* Beneath a squatter the view claims, no look was taken. A look here would
     * answer for the occupant — a symlink's target, a file's ENOTDIR — and no
     * such answer is this path's: not a byte, not a mode, not an absence. The
     * item stands as the partition made it, DEPLOYED-shaped with nothing measured:
     * UNKNOWN is the occupant every reader treats as "assumed present, nothing
     * read", and the look wrote the class of the claim whose squatter every verb
     * resolves first (workspace_displaced_t). The blob bit rides — it is Git's,
     * and the filesystem is not a party to it — and the record pairs as on every
     * item, so a pending reassignment still shows. Nothing is owed the record:
     * a record is what dotta saw, and dotta saw nothing here. */
    if (item->displaced != WORKSPACE_DISPLACED_NONE) {
        return;
    }

    if (item->occupant == FS_OCCUPANT_NONE) {
        /* Absent: classify_absent decides (its claim gate is inert here — a file
         * row asserts its path by holding a blob for it). No path bit: properties
         * of what is not there cannot be compared, and none has been written.
         * The blob bit rides — the blob and the policy are both still here to
         * disagree ([undeployed] [unencrypted] is exactly this row). */
        item->state = classify_absent(row, anchor);
        return;
    }

    if (item->occupant == FS_OCCUPANT_UNKNOWN) {
        /* Inaccessible, not absent (EACCES, ELOOP, EIO; ENOTDIR is absence —
         * fs_lstat_occupant reads it so). Same policy as the orphan path below:
         * assume the path is there and record the uncertainty, rather than failing
         * the load and taking every other managed path down with one unreadable
         * one. The content phase honours the same policy for the look it makes:
         * a blob it cannot load, decrypt, or compare is the UNVERIFIED item at
         * the call, never out of the load.
         *
         * DEPLOYED is the load-bearing half — absence must never be inferred
         * from a failure to look, or update commits a deletion that never happened.
         * UNVERIFIED keeps consumers conservative: apply plans the row and skips
         * it rather than write on a guess — the exit code says so — and cleanup's
         * UNVERIFIED skip blocks removal.
         *
         * Returns here because every phase below needs a valid stat. */
        item->divergence |= DIVERGENCE_UNVERIFIED;
        item->fault = workspace_code_fault(error_code_from_errno(item->lstat_errno));
        return;
    }

    /* The path stands — the arms above returned for a look withheld, absence
     * and a failed look — and the verdict over what stands there follows. Where
     * what stands is the row's own kind and dotta has no record, the path is
     * owed its observation too, which the flush makes off this same look
     * (workspace_flush).
     *
     * CONTENT AND TYPE ANALYSIS: Buffer-based comparison for accurate divergence
     * detection.
     *
     * Architecture:
     * - Use the row's blob_oid for content loading
     * - Extract expected mode from the row's type field
     * - Compare directly to filesystem file (compare_buffer_to_disk)
     *
     * This provides:
     * - Architectural consistency (blob_oid unification)
     * - Accurate byte-level comparison with early exit
     * - Transparent encryption handling via content cache
     * - The look above handed in, and every question below asked off it
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
     *                                               last confirmed this path
     *   user_edited := base unset || ours ≠ base    disk left the blob dotta
     *                                               confirmed there
     *
     * `base ≠ theirs` is a question about content, not about an id: another blob,
     * or the same blob under another kind. Git hashes a link's target exactly
     * as it hashes a file's bytes, so one object stands behind both and means a
     * different thing under each, and a retype Git made under an untouched copy
     * keeps the id it had. core/workspace.h workspace_compare_confirmed is where
     * that rule lives, and the two readings of it below — this bool, and the
     * fast path's whole verdict — are its.
     *
     * When ours ≠ theirs: CONTENT iff user_edited, STALE iff git_moved. STALE
     * without CONTENT means "overwrite loses nothing"; CONTENT without STALE
     * means "Git has not moved since this was deployed"; both means both sides
     * moved. Without a base there is no second question — any difference from
     * theirs is the user's.
     *
     * Source of truth for the base: the record (the path_anchors row's blob)
     * when it carries one; the released copy when it does not — a path re-claimed
     * after its record retired, whose record is gone or is the window's blob-less
     * observation. A path with neither has no base. Cross-process correct by
     * construction — every invocation sees the same answer.
     */
    compare_result_t cmp_result;

    /* The base: dotta's last content confirmation at this path — the record's,
     * when it carries one; the released copy's, when it does not (a path re-claimed
     * after its record retired: the record is gone, or is the window's blob-less
     * observation). The record's own questions — absence, reassignment, the item's
     * record column — stay the anchor's alone: a released copy is no record,
     * and never fabricates a record, a reassignment, or a DELETED absence. A
     * base compares under its own recorded binding, whichever of the two it is:
     * a blob opens under one (profile, storage path) pair and no other, and each
     * of these facts carries the binding its blob was confirmed under
     * (core/state.h). The row's pair is never a base's — a row the record's binding
     * does not name is one the record has yet to follow, and reading the base
     * under it authenticates a ciphertext against a tree path it was never sealed
     * at.
     *
     * No base by default — the NULL blob is the no-base state; the row-derived
     * type and pair beside it are never read as a base's (every base question
     * below is gated on git_moved, which needs a base blob). */
    const git_oid *base_blob = NULL;
    const stat_cache_t *base_stat = NULL;
    path_type_t base_type = row->type;
    const char *base_storage = storage_path;
    const char *base_profile = profile;

    /* The record's, when it carries a confirmed blob */
    if (anchor && !git_oid_is_zero(&anchor->blob_oid)) {
        base_blob = &anchor->blob_oid;
        base_stat = &anchor->stat;
        base_type = anchor->type;
        base_storage = anchor->storage_path;
        base_profile = anchor->profile;
    }

    /* Where it carries none, the base the path's last retired record left, if
     * the snapshot holds one */
    const released_copy_t *released = base_blob ? NULL
        : state_lookup_released_copy(ws->released, ws->released_count, filesystem_path);
    if (released) {
        base_blob = &released->blob_oid;
        base_stat = &released->stat;
        base_type = released->type;
        base_storage = released->storage_path;
        base_profile = released->profile;
    }

    /* The first question of the three-way frame is answered from the row and
     * the base alone; the second (disk_at_base — ours == base) is answered by
     * whichever path below settles it, and only when it can change the verdict. */
    bool git_moved = base_blob && workspace_stale(row, base_type, base_blob);
    bool disk_at_base = false;

    /* BASE FAST PATH (safety-grade)
     *
     * The base binds the blob dotta last confirmed on disk, the kind it was read
     * as, and the stat triple captured at that confirmation. A live look of that
     * kind that still stands behind that triple is proof that disk is the base's
     * pair — why it is proof and not a guess is the proof's own to say
     * (core/state.h stat_cache_matches) — so no blob is loaded and nothing is
     * hashed, and the second question is answered for free: ours == base. The
     * first question is then the whole of the comparison, because disk IS the
     * base: what the row is to the pair is what it is to disk, in the comparison's
     * own words (core/workspace.h workspace_compare_confirmed). A kind Git moved
     * under an untouched copy therefore answers CMP_TYPE_DIFF here and STALE
     * below, the same as the slow path reaches by reading — where an answer off
     * git_moved alone would have called one state clean and its mirror a mode
     * change. A path with no base has no triple to match. */
    if (base_stat && stat_cache_matches(base_stat, base_type, &item->st)) {
        /* the look stands behind the proof ⟹ disk == the base's pair */
        disk_at_base = true;
        cmp_result = workspace_compare_confirmed(row, base_type, base_blob);

        /* A verification that establishes a pair the record does not hold is
         * noted as the record's own confirmation — which is exactly the
         * released-base hit: the record is blob-less or absent. An anchored base
         * IS the record's pair under its own proof, and noting it again would
         * buy nothing and cost two things: the flush's transaction on every clean
         * load, and — where the deploy wrote the proof this very second — the
         * proof itself, which a read in an open second demotes to none
         * (core/state.h stat_cache_from_stat). So the fast path stays write-free
         * for it. The record gains the blob, and the confirmation that gives it
         * one forgets the released row it subsumes in the same breath
         * (state_confirm).
         *
         * The verdict is the whole gate: the proof held the look to the base's
         * kind, and a released base the row has since retyped answers CMP_TYPE_DIFF
         * above, so the pair state_confirm would write — the row's kind beside
         * a triple taken of another — is never noted from here. What this notes
         * stands on the row's kind, as the slow path's confirmation does by its
         * first rung: a content confirmation is never of a node the row does
         * not name. */
        if (cmp_result == CMP_EQUAL && released) {
            workspace_note_content(item);
        }
    } else {
        /* SLOW PATH: Full content comparison, ours vs theirs
         *
         * Strategy selection based on encryption status:
         * - Non-encrypted: Hash filesystem file and compare OID directly
         * - Encrypted: blob_oid is ciphertext hash; must load, decrypt, compare
         *
         * Both paths receive the load's look to avoid redundant lstat syscalls.
         *
         * Asymmetry with the second question below, and it is the stamp's:
         * row->encrypted is *this* blob's own, made byte-true at the write boundary
         * (infra/content.h content_capture_file), so the plaintext arm hashes
         * disk against the id and opens nothing. The base has no such boundary
         * — no record carries a stamp — so its kind is read off its own bytes,
         * in the one read that also yields them.
         *
         * The sealed arm's entry is the one memoised read another reader in the
         * run asks back for: apply's deploy takes it from the cache for every
         * row it writes, diff's renderer for every row it draws (infra/content.h
         * content_cache_get_from_blob_oid). That is why this arm reads through
         * the memo where the base question, whose key no reader can name, does not.
         */
        error_t *err = NULL;

        /* The row's own filemode, the kind both reads below are put under: the
         * ladder's expected kind for the plaintext read, one part of the memo's
         * key for the sealed one. The fast path needs none — the pair it answers
         * from carries its own kind — so the mapping is made here rather than
         * above the fork. */
        git_filemode_t expected_filemode = path_type_to_git_filemode(row->type);

        /* The ladder's first rung, asked of the look before anything is read:
         * another kind than the row's stands (core/workspace.h
         * workspace_type_occupant), and no byte can change that, so none is read
         * and no key is asked. The ladder asks the same rung first itself
         * (infra/compare.c compare_reference_to_disk), but only once it holds
         * the reference, and a sealed row's reference is a decrypt: asked there,
         * one node would read [locked] without the key and [type] with it. The
         * second question below still reads the base, under the base's own kind. */
        if (item->occupant != workspace_type_occupant(row->type)) {
            cmp_result = CMP_TYPE_DIFF;
        } else if (!row->encrypted) {
            err = compare_oid_to_disk(
                &row->blob_oid,
                filesystem_path,
                expected_filemode,
                &item->st,
                &cmp_result
            );
        } else {
            const buffer_t *expected_content = NULL;
            err = content_cache_get_from_blob_oid(
                ws->content_cache,
                &row->blob_oid,
                expected_filemode,
                storage_path,
                profile,
                &expected_content
            );

            if (!err) {
                err = compare_buffer_to_disk(
                    expected_content,
                    filesystem_path,
                    expected_filemode,
                    &item->st,
                    &cmp_result
                );
            }
            /* Note: Don't free expected_content - cache owns it! */
        }

        if (err) {
            /* A failed look, not a verdict — the orphan analysis's cause list
             * (missing key, wrong passphrase, cipher-version skew, I/O error,
             * missing blob) and the same word. The path is there (the lstat said
             * so); only the look at its content failed, and a failed look is
             * never fatal to the load. Written onto the item here, the unstattable
             * arm's shape: UNVERIFIED beside the blob bit, the stat valid so
             * the mode checks below could run, but every consumer reads UNVERIFIED
             * first and accumulated path bits would change nothing; the orphan
             * analysis answers a failed look this way, and one policy beats two.
             * The two gates below read EQUAL and DIFFERENT, so returning here
             * skips only what they would have skipped themselves. */
            item->divergence |= DIVERGENCE_UNVERIFIED;
            item->fault = workspace_error_fault(err);
            return;
        }

        /* Slow path found disk == expected blob — noted for the record, with
         * the row's blob and the look the verdict was reached from, so the next
         * run can short-circuit via the fast path above. */
        if (cmp_result == CMP_EQUAL) {
            workspace_note_content(item);
        }

        /* Second question — ours vs base — asked once, where it can change the
         * verdict: Git moved, and the first question found a difference (of bytes
         * or of kind) although the stat triple did not vouch for disk (touch(1),
         * an editor's rename-write, a fresh checkout) and disk may still be the
         * copy dotta last confirmed. git_moved carries both halves of the gate:
         * without a base there is no second question, and a base equal to theirs
         * deduces the answer from the first.
         *
         * Route the base comparison by the base blob's own kind and its own bytes
         * — each question is put to the side it compares against, where the first
         * is put under the row's. The kind is what makes the two verdicts one:
         * a base the row has since retyped is a link where a file now stands,
         * and reading disk as the row's kind hashes a regular file the user wrote
         * against the link's target — Git hashes a target exactly as it hashes
         * content — and calls it exactly what dotta deployed. One place asks
         * it, because two askers of one fact can disagree, and the kind is where
         * these two did.
         *
         * And the base's kind is asked of the look before anything is read, as
         * the first question asks the row's (the ladder's first rung,
         * core/workspace.h workspace_type_occupant): a node of neither kind is
         * not the pair dotta confirmed whatever its bytes, so reading the base
         * — a decrypt, for a sealed one — would only say what the look already
         * says, and disk_at_base keeps the answer it holds.
         *
         * The latent bug class the bytes avoid: routing on row->encrypted silently
         * miscategorised the staleness check across encryption-policy transitions.
         * Both directions failed:
         *   - encrypted base / plaintext current → compare_oid_to_disk hashed
         *     plaintext disk against an encrypted-blob OID, never equal, STALE
         *     never set.
         *   - plaintext base / encrypted current → content_cache called with
         *     expected_encrypted=true on a plaintext blob, the old cross-check
         *     raised ERR_STATE_INVALID, swallowed below.
         *
         * content_compare_blob_to_disk reads the base once, as the entry the
         * record's own type names, so the kind and the reference both come off
         * the blob whose comparison this is. There is no stamp for a record's
         * blob that could be read instead.
         *
         * A failed look answers nothing and leaves disk_at_base false: the edit
         * is taken as real (CONTENT), the conservative answer — STALE still holds,
         * because git_moved is a fact about two OIDs. A failed look on a released
         * base retires nothing — no look does: a copy dies only with its path's
         * next ownership event or content confirmation (core/state.h). */
        if (git_moved &&
            (cmp_result == CMP_DIFFERENT || cmp_result == CMP_TYPE_DIFF) &&
            item->occupant == workspace_type_occupant(base_type)) {
            compare_result_t at_base;
            error_t *verify_err = content_compare_blob_to_disk(
                ws->content_cache,
                base_blob,
                filesystem_path,
                path_type_to_git_filemode(base_type),
                &item->st,
                base_storage,
                base_profile,
                &at_base
            );

            if (verify_err) {
                error_free(verify_err);
            } else {
                disk_at_base = (at_base == CMP_EQUAL);
            }
        }
    }

    /* Set divergence flags based on comparison result */
    switch (cmp_result) {
        case CMP_EQUAL:
            /* Content and type match - no divergence from content comparison.
             * The claim is checked below. */
            break;

        case CMP_DIFFERENT:
            /* ours ≠ theirs — name which side moved; both can have */
            if (!disk_at_base) item->divergence |= DIVERGENCE_CONTENT;
            if (git_moved) item->divergence |= DIVERGENCE_STALE;
            break;

        case CMP_TYPE_DIFF:
            /* The occupant is not the row's kind (file ↔ symlink, or a directory,
             * FIFO, socket or device standing on the row). When Git moved the
             * kind out from under an untouched deployment, the second question
             * above answers it: an occupant that is exactly what dotta confirmed,
             * kind and content, diverges by Git's move alone. STALE — and this
             * is the arm the fast path lands in for that same state, having
             * answered the comparison off the base's pair instead of a read.
             * One question, asked under the base's own kind, whichever path asked
             * it.
             *
             * Anything else is a blocking condition: TYPE. Either way the look
             * stands at another kind than the row's, so the claim is not asked
             * of it; the sources ride along, the same shape as every early return,
             * so a pending reassignment does not vanish behind a type change. */
            item->divergence |= disk_at_base ? DIVERGENCE_STALE : DIVERGENCE_TYPE;
            return;

        case CMP_MISSING:
            /* The look itself met ENOENT/ENOTDIR: the path vanished between the
             * lstat above and the content read. The verdict is absence, and the
             * look follows the verdict — the one retraction of a look in the
             * whole load, its one writer beside look: a read that met absence
             * against a look that said a file stood there is the truer answer
             * about the path. So a path with no record is owed no observation
             * here, the flush observing off the look — the record follows the
             * run's verdict, never a moment the run itself outlived — and the
             * phases after the join read absence and index nothing, where an
             * identity left standing would vouch for a vanished file and could
             * meet a reused inode. Absence is then classified as the lstat's
             * is, above, and the claim is not asked. */
            item->occupant = FS_OCCUPANT_NONE;
            item->state = classify_absent(row, anchor);
            return;
    }

    /* CLAIM CHECKING (workspace_analyze_claim)
     *
     * The look stands at the row's kind: the switch returned on absence and on
     * another kind, the two verdicts under which the stat says nothing about
     * the row. The claim reads the load's one look — the stat the content verdict
     * was made from — for no extra syscalls.
     */
    workspace_analyze_claim(item);
}

/**
 * Compare an orphan's copy against its record
 *
 * The file analysis's comparison (workspace_analyze_file), asked of an orphan:
 * filesystem state against what dotta last deployed.
 *
 * An orphan asks one question — is disk still what dotta put there? — so prune
 * safety is measured against the deployment anchor, never against a view blob:
 * Git may have moved on after the deployment and before the path left scope,
 * and that move is not the user's edit. The record is the honest reference on
 * every axis — its type, blob and stat for the content, its mode, owner and group
 * for the claim — the claim dotta last reconciled the path against, which follows
 * every agreement a load found or a fix made (core/state.h anchor_t), so a claim
 * Git moved and disk followed while the path was active is measured as the one
 * disk stands on, not as an edit. Never what the row later came to claim, after
 * the path left scope. DIVERGENCE_STALE is therefore never written here, nor
 * DIVERGENCE_CLAIM_MOVED: the active items' analyses ask whether Git moved a
 * claim since the record reconciled it, and need no second question, since apply
 * converges every claim; this analysis has no row to ask that of, and asks whether
 * disk left the claim the record reconciled — the question prune safety turns on.
 *
 * Precondition: the record carries a confirmed blob. The caller
 * (workspace_analyze_orphans) measures only a record dotta owns or one the user
 * ordered pruned against a confirmed blob; a record with nothing to measure against
 * is released, not measured.
 *
 * Architecture:
 * - Uses the record alone (blob_oid, stat, type, mode, owner, group)
 * - Anchor stat triple as the fast path, the same proof the file analysis relies
 *   on: a match means the exact node dotta wrote, no hashing
 * - Past it, the node's kind off the look, which needs no read (the ladder's
 *   first rung, as the file analysis asks it)
 * - Past that, one read of the record's blob answers its kind and the reference
 *   together, and the plaintext ends with the judgment (infra/content.h
 *   content_compare_blob_to_disk)
 * - The claim checked against the record's: the full-bit mode, the ownership
 *   beside it
 * - Single-stat-per-file (the caller's look, which nothing below retakes)
 *
 * A measure that can fail says so: the look's error is returned and the caller
 * decides what a failure to look means, which is the rule the file analysis already
 * keeps for its own (never fatal to the load; the item holds the class and the
 * bit). Nothing is guarded here — the one caller cannot pass a NULL, and a break
 * that reached this would rather crash than be read as a silent [orphaned,
 * unverified].
 *
 * @param ws Workspace (provides the run's content reader)
 * @param item The orphan's item: its record, with a non-zero blob_oid, and the
 *             look taken at the record's path, a present kind (must not be NULL).
 *             The path bits the compare finds are added to its divergence, which
 *             the ladder hands in with none — only where the compare was made,
 *             so a failed look leaves it as it came
 * @return The look's error when the compare could not be made; NULL otherwise
 */
static error_t *workspace_compare_orphan(workspace_t *ws, workspace_item_t *item) {
    const anchor_t *anchor = item->anchor;
    const char *filesystem_path = item->filesystem_path;
    const char *storage_path = item->storage_path;
    const char *profile = item->profile;

    /* Step 1: The reference blob
     *
     * The record's — the blob dotta last confirmed disk against. state.c's read
     * path already rejects wrong-sized BLOB columns, and the caller guarantees
     * a non-zero one, so by the time we get here the OID is well-formed.
     */
    const git_oid *reference = &anchor->blob_oid;

    /* Step 2: The record's own filemode
     *
     * The kind the read below is put under, mapped from the record's type by
     * the shared helper, for one mapping across modules. The claim's mode check
     * reads the record's mode, never this.
     */
    git_filemode_t expected_filemode = path_type_to_git_filemode(anchor->type);

    compare_result_t cmp_result;

    /* Step 3: Content and type comparison.
     *
     * Anchor fast path first: a live look of the record's kind that still stands
     * behind the triple captured at the last confirmation is proof that disk
     * still equals anchor.blob_oid (core/state.h stat_cache_matches), so the
     * exact node dotta wrote is recognised without loading or hashing anything
     * — and the claim below is asked of that node, never of another kind's.
     *
     * Then the ladder's first rung, off the look before any read, as the file
     * analysis asks it (workspace_analyze_file): another kind than the record's
     * stands, which no byte can change — so no blob is opened and no key asked
     * to learn what the look already tells.
     *
     * Otherwise content_compare_blob_to_disk reads the record's blob once, as
     * the entry the record's own type names, and judges the look against what
     * it answers. The kind comes off that blob and nothing else, so the orphan
     * walker cannot route a different blob's state by a cached flag by accident
     * — the record carries no encrypted flag, and the blob dotta deployed may
     * sit on the other side of an encryption-policy flip from what Git holds
     * now. The caller's look is forwarded: the seam reads, the pair judges, and
     * neither takes a look of its own. */
    if (stat_cache_matches(&anchor->stat, anchor->type, &item->st)) {
        /* the look stands behind the proof ⟹ disk == anchor.blob_oid */
        cmp_result = CMP_EQUAL;
    } else if (item->occupant != workspace_type_occupant(anchor->type)) {
        cmp_result = CMP_TYPE_DIFF;
    } else {
        error_t *err = content_compare_blob_to_disk(
            ws->content_cache,
            reference,
            filesystem_path,
            expected_filemode,
            &item->st,
            storage_path,
            profile,
            &cmp_result
        );

        if (err) {
            /* Cannot classify, load, decrypt, or compare — no key in reach, a
             * blob a held key refuses, an unsupported cipher version, an I/O
             * error, a blob missing from the repository. Handed back whole: the
             * caller folds its class onto the item and the orphan reads unverified,
             * which is what the file analysis does with the same causes at the
             * same step (workspace_analyze_file). */
            return err;
        }
    }

    /* Step 4: Interpret comparison result
     *
     * Use switch statement (not if-else) for exhaustive handling.
     */
    switch (cmp_result) {
        case CMP_EQUAL:
            /* Content and type match - continue to the claim */
            break;

        case CMP_DIFFERENT:
            /* Disk left the blob dotta deployed */
            item->divergence |= DIVERGENCE_CONTENT;
            break;

        case CMP_TYPE_DIFF:
            /* Type differs (file vs symlink vs directory). The claim below skips
             * itself on this verdict, as workspace_analyze_file returns on it:
             * TYPE stands alone. */
            item->divergence |= DIVERGENCE_TYPE;
            break;

        case CMP_MISSING:
            /* The look itself met ENOENT/ENOTDIR: the file was removed after
             * the caller's single lstat but before the comparison function read
             * its contents.
             *
             * Report as DIVERGENCE_NONE — the orphan was already removed by hand.
             * The copy reads as the prune candidate its look said it was, and
             * cleanup's execute re-probes presence before it unlinks
             * (core/cleanup.c cleanup_execute): nothing is removed, and the record
             * retires as a reclaim. The claim checks below read the verdict and
             * skip themselves.
             *
             * The look is not retracted, where the file analysis retracts its
             * own (its CMP_MISSING arm): the entries index was built from this
             * look before the orphan analysis ran (workspace_load), so a retraction
             * could not take the entry back out of it. A stale entry can only
             * keep a new file standing on the reused inode from being offered
             * for one run — the direction every false answer of the index takes
             * (index_entries). */
            break;
    }

    /* Step 5: Claim checking (if the path still stands)
     *
     * Only when the content phase ruled neither absence nor another kind — a
     * mode question over what is not there, or is not that, answers nothing.
     * Read off the verdict alone, as workspace_analyze_file's switch returns on
     * the same two: a bit this function has just set is the verdict spelled twice.
     * The compare workspace_analyze_claim asks of a row, asked of the record's
     * claim: the record's mode is total for every kind that carries one (written
     * from a view row after the build resolved absence), so one full-bit compare
     * answers; a symlink record is never asked. Both halves read the caller's
     * look — the one stat the content verdict was made from — for zero extra
     * syscalls.
     */
    if (cmp_result != CMP_TYPE_DIFF && cmp_result != CMP_MISSING) {
        if (anchor->type != PATH_TYPE_SYMLINK
            && (item->st.st_mode & 0777) != anchor->mode) {
            item->divergence |= DIVERGENCE_MODE;
        }
        if (ownership_diverges(
            anchor->storage_path, anchor->owner, anchor->group, &item->st
            )) {
            item->divergence |= DIVERGENCE_OWNERSHIP;
        }
    }

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
 *           the tree leaves open (a blob at the name answers one alone) and kept
 *           likewise. A tree without metadata.json stores an empty collection —
 *           a profile without metadata backs no directory, and the lookup says
 *           so — so the same rule holds: NULL is "not loaded yet", never "absent".
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
 * What the profile that deployed an orphan says of the claim its record remembers
 */
typedef enum {
    ORPHAN_AUTHORITY_BACKED,      /* The branch holds the claim the record remembers, at its name */
    ORPHAN_AUTHORITY_LOST,        /* The branch is gone, or holds no such claim there */
    ORPHAN_AUTHORITY_UNVERIFIED   /* A Git lookup failed — cannot tell, must not guess */
} orphan_authority_t;

/**
 * Git's authority over an orphan
 *
 * "Does the profile that deployed this path still hold the claim its record
 * remembers?" — at the record's storage name, a claim of the record's kind: a
 * blob of any filemode for a file, a DIRECTORY item no blob stands at for a
 * directory. That is the view's contribution rule asked of one name before anything
 * is placed (core/manifest.h, "Within one profile, at one path"), so the probe
 * and the view agree on every name — a disabled profile's custom/ name among
 * them, which has no binding to be placed by.
 *
 * One kind of row reaches this probe — a record whose path the view lacks — and
 * three reasons it may be there are what the probe tells apart:
 *   - the profile is disabled: its branch still holds the claim, and the deployed
 *     copy is dotta's to prune;
 *   - the profile moved: it is enabled, but its --target changed between a disable
 *     and an enable, so Git still backs the storage path at a new path and the
 *     old one is dotta's to prune;
 *   - Git let go: the branch was deleted, rebased or git rm'd behind the record,
 *     an enabled branch is dead, a pulled removal arrived, or the name was retyped
 *     — a removal and an addition, the claim the record remembers the half removed
 *     — and the deployed copy is left alone.
 * The enabled set cannot tell the second from the third; only a live look at
 * Git can. Taken here, every reader of orphan items shares one verdict, and
 * cleanup's verdict phase reads nothing but the item.
 *
 * Answers:
 *   BACKED      the orphan is dotta's to prune, divergence permitting
 *   LOST        the claim is gone from Git; the caller writes
 *               WORKSPACE_STATE_RELEASED — left on disk, record retires
 *   UNVERIFIED  a lookup, a load or an allocation failed. LOST would retire the
 *               record and BACKED would prune the copy, so neither is guessed:
 *               the caller marks the orphan DIVERGENCE_UNVERIFIED and holds it
 *               until Git answers
 *
 * No failure is raised: each one says only that the probe could not answer, which
 * UNVERIFIED already says — the orphan's hold, never the load's, the rule every
 * failed look in this file takes.
 *
 * @param repo Repository (must not be NULL)
 * @param cache profile → authority_cache_t (borrowed keys, owned values)
 * @param profile Record's profile (NOT NULL in the schema)
 * @param storage_path Record's storage path (NOT NULL in the schema)
 * @param kind The record's kind: the kind of claim to find at the name
 * @return The answer
 */
static orphan_authority_t compute_orphan_authority(
    git_repository *repo,
    hashmap_t *cache,
    const char *profile,
    const char *storage_path,
    path_kind_t kind
) {
    authority_cache_t *cached = hashmap_get(cache, profile);
    if (!cached) {
        /* First row of this profile: does its branch still exist? A ref lookup,
         * not a tree load — a profile whose branch is gone answers here, and
         * every later row reads the cached answer. */
        bool exists = false;
        error_t *err = gitops_branch_exists(repo, profile, &exists);
        if (err) {
            error_free(err);
            return ORPHAN_AUTHORITY_UNVERIFIED;
        }

        /* Cached only once answered: a failure above caches nothing, so a transient
         * one is the next row's to retry rather than the profile's verdict. */
        cached = calloc(1, sizeof(*cached));
        if (!cached) {
            return ORPHAN_AUTHORITY_UNVERIFIED;
        }
        cached->exists = exists;

        err = hashmap_set(cache, profile, cached);
        if (err) {
            error_free(err);
            authority_cache_free(cached);
            return ORPHAN_AUTHORITY_UNVERIFIED;
        }
    }

    if (!cached->exists) {
        /* The branch was deleted behind the record: nothing in Git can back the
         * path, and its content may be recoverable from no profile at all. */
        return ORPHAN_AUTHORITY_LOST;
    }

    if (!cached->tree) {
        /* The branch's HEAD tree, on the first question that needs it and kept
         * for the pass. Stored on success alone, so a failed load is retried by
         * the next row instead of condemning the whole profile. */
        git_tree *tree = NULL;
        error_t *err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            error_free(err);
            return ORPHAN_AUTHORITY_UNVERIFIED;
        }
        cached->tree = tree;                /* Ownership transfers to the cache */
    }

    /* The tree at the name, asked first and for either kind: a blob there is
     * the file claim itself, and the one thing that unbacks a directory claim —
     * the tree is the content authority, and the view decides in this order too,
     * its blob walk contradicting an item before its directory pass reads one
     * (core/manifest.c manifest_contribute). Three answers, not two: a subtree
     * that will not load on the way is a failure to look, never an absence. */
    git_tree_entry *entry = NULL;
    int rc = git_tree_entry_bypath(&entry, cached->tree, storage_path);
    if (rc != 0 && rc != GIT_ENOTFOUND) {
        return ORPHAN_AUTHORITY_UNVERIFIED;
    }

    /* A blob at the name and only there: one above it reads GIT_ENOTFOUND and
     * contradicts nothing, as in the view, whose contradiction index is keyed
     * by the blob's own name. */
    bool blob_at_name = rc == 0 && git_tree_entry_type(entry) == GIT_OBJECT_BLOB;
    git_tree_entry_free(entry);             /* NULL-safe, and NULL unless rc == 0 */

    if (kind == PATH_KIND_FILE) {
        /* A file claim is a blob of any filemode — bytes, an executable, a link's
         * target — and nothing else at the name is one: a subtree is the way to
         * what lies beneath it and a gitlink is nothing dotta writes, so neither
         * holds a byte of the copy on disk. */
        return blob_at_name ? ORPHAN_AUTHORITY_BACKED : ORPHAN_AUTHORITY_LOST;
    }

    if (blob_at_name) {
        /* A DIRECTORY item where the tree holds a blob is stale metadata and
         * claims nothing (core/manifest.h): the branch holds a file claim here,
         * not the record's directory, and the sheet need not be read. */
        return ORPHAN_AUTHORITY_LOST;
    }

    if (!cached->metadata) {
        /* The sheet, on the first directory question the tree left open, kept
         * like the tree. A tree without one loads as an empty sheet — a settled
         * "no claims", not a failure — so every error here is a failure to look. */
        metadata_t *metadata = NULL;
        error_t *err = metadata_load_from_tree(repo, cached->tree, profile, &metadata);
        if (err) {
            error_free(err);
            return ORPHAN_AUTHORITY_UNVERIFIED;
        }
        cached->metadata = metadata;        /* Ownership transfers to the cache */
    }

    /* A directory claim lives in the sheet alone — a tree holds no empty directory
     * — so the item decides, and a subtree or a gitlink at the name vetoes nothing.
     * A FILE item standing where no blob does claims nothing. */
    const metadata_item_t *item = metadata_lookup(cached->metadata, storage_path);
    return item && item->kind == PATH_KIND_DIRECTORY ? ORPHAN_AUTHORITY_BACKED
                                                     : ORPHAN_AUTHORITY_LOST;
}

/**
 * The order of two looks by the entry each found: device, then inode
 *
 * The pair one lstat names. Compared and never subtracted: dev_t is signed on
 * some platforms and unsigned on others, and a difference is not an order. The
 * one rule entry_order sorts by and find_entries searches by.
 */
static int identity_order(const struct stat *a, const struct stat *b) {
    if (a->st_dev != b->st_dev) return a->st_dev < b->st_dev ? -1 : 1;
    if (a->st_ino != b->st_ino) return a->st_ino < b->st_ino ? -1 : 1;

    return 0;
}

/**
 * The entries' order (qsort's): by the identity each item's look found
 *
 * An entry is an item, standing where its look found it (index_entries), so every
 * entry standing on one file is adjacent and find_entries reads the run.
 *
 * No axis in the name, where workspace_kind_order carries one: an item can be
 * ordered by any of the things it holds, and an entry by its identity alone.
 */
static int entry_order(const void *a, const void *b) {
    const workspace_item_t *const *ea = a;
    const workspace_item_t *const *eb = b;

    return identity_order(&(*ea)->st, &(*eb)->st);
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
static const workspace_item_t *const *find_entries(
    const workspace_t *ws, const struct stat *st, size_t *count
) {
    size_t lo = 0;
    size_t hi = ws->entry_count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;

        if (identity_order(&ws->entries[mid]->st, st) < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    size_t n = 0;
    while (lo + n < ws->entry_count &&
        identity_order(&ws->entries[lo + n]->st, st) == 0) {
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
 * parent the same way). The one bound is the buffer's: a key that was just lstat'ed
 * fits in PATH_MAX, the kernel's own bound on a path, and so does its parent —
 * one that would not answers as a look that did not happen, which is its one
 * caller's rule for it.
 *
 * @param path A key (must not be NULL)
 * @param st Receives the parent's stat (must not be NULL)
 * @return true when the parent was stat'd
 */
static bool stat_parent(const char *path, struct stat *st) {
    size_t len = str_path_parent_len(path);
    char parent[PATH_MAX];

    if (len >= sizeof(parent)) {
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
 * measured deleting an active file through a name compare) all pair here.
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

    struct stat parent;
    struct stat other_parent;

    /* The names by bytes, each read from its key's last separator on — a key is
     * absolute (sys/filesystem.h fs_is_folded), so it holds one — then the
     * directories by identity */
    return strcmp(strrchr(path, '/'), strrchr(other, '/')) == 0 &&
           stat_parent(path, &parent) && stat_parent(other, &other_parent) &&
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
 * Any row that pairs, in an order the sort does not fix: the reader asks whether
 * one stands, never which — a scan root is a selection with a winner (scan_root_t);
 * this is not. An active item carries its row and an orphan none (the partition
 * bears an orphan with no row, and nothing gives it one), which is how this tells
 * the view's entries from the record's — and why the orphan asking, which the
 * index holds on its own entry, is never its own answer.
 *
 * Reader: the orphan analysis's BACKED arm — a stale key of an active path is
 * released, never pruned, whoever's row; the row the record's binding names
 * standing on the same entry was the special case of this the compare here used
 * to make.
 */
static const manifest_row_t *standing_row(
    const workspace_t *ws, const char *path, const struct stat *st
) {
    size_t count = 0;
    const workspace_item_t *const *entries = find_entries(ws, st, &count);

    for (size_t i = 0; i < count; i++) {
        if (entries[i]->row && same_entry(path, entries[i]->filesystem_path, st)) {
            return entries[i]->row;
        }
    }

    return NULL;
}

/**
 * The item standing on the entry a path names, under another spelling
 *
 * standing_row's question asked of every item, a row's or a record's: a path
 * the view claims or the record remembers is no discovery, and this is that rule
 * read by identity — a row or an orphan record at another spelling of the child's
 * entry keeps the child undiscovered, exactly as the same row or record at the
 * child's own spelling does. Without it one screen promised a commit and a deletion
 * of one file. Any item that pairs, in an order the sort does not fix: the reader
 * asks whether one stands, never which.
 *
 * Reader: the untracked scan's leaf probe.
 */
static const workspace_item_t *standing_item(
    const workspace_t *ws, const char *path, const struct stat *st
) {
    size_t count = 0;
    const workspace_item_t *const *entries = find_entries(ws, st, &count);

    for (size_t i = 0; i < count; i++) {
        if (same_entry(path, entries[i]->filesystem_path, st)) {
            return entries[i];
        }
    }

    return NULL;
}

/**
 * Does the look find the claim's own kind standing at its key?
 *
 * The three ways a key fails to name an entry its claim may vouch by, in one
 * expression — and each of them drops rather than keeps:
 *   - nothing stands there: [undeployed], or a chain whose component is no
 *     directory. An absent row is not the entry a present orphan stands on;
 *   - nothing was read: a look that failed (EACCES, ELOOP, EIO) or one never
 *     taken, beneath a squatter, where a look would have reached the squatter's
 *     target and vouched for something that is not this path's. Both are UNKNOWN
 *     and neither may vouch, which is why this need not tell them apart;
 *   - another kind of node holds the place — a directory claim with a symlink
 *     or a file in it, a file claim with a directory: a squatted claim's own
 *     look is the squatter's, so the entry it names is exactly the one every
 *     verdict refuses. The retyped arm's rule read at the build
 *     (workspace_analyze_orphans: two occupants cannot share an inode, a claim
 *     and an occupant can), and the reason a proper-ancestor probe cannot stand
 *     alone — that one answers for ancestors, so a claim whose own path is squatted
 *     is one rung past its reach.
 *
 * Read by index_entries' two passes, over each item's own kind — a row's or a
 * record's — and by the orphan analysis's retyped arm over the record's alone —
 * where the answer is not whether the key may vouch but whether what dotta put
 * there is gone (workspace_analyze_orphans). The scan's roots ask a narrower
 * question of their own items directly: over the directory items the kind is a
 * constant, and what they want is a directory to enumerate. Over path_kind_t,
 * which is coarser than the node a type stands as (core/workspace.h
 * workspace_type_occupant), and on purpose: a link at a file key names the entry
 * it stands on, and a retyped record is released only where a directory and a
 * non-directory swapped. core/deploy.c occupant_conflicts reads the finer kind
 * because deploy must replace a link with a file and back — a different question
 * that happens to look alike.
 *
 * @param occupant What the look found (workspace_item_t)
 * @param kind The kind the claim names — the item's own, a row's or a record's
 */
static bool claim_stands(fs_occupant_t occupant, path_kind_t kind) {
    if (occupant == FS_OCCUPANT_NONE || occupant == FS_OCCUPANT_UNKNOWN) {
        return false;
    }

    return (occupant == FS_OCCUPANT_DIRECTORY) == (kind == PATH_KIND_DIRECTORY);
}

/**
 * The orphans' looks, and their squatters
 *
 * One look per record the view lacks, taken into its item (workspace_look) and
 * kept for the two phases after it: the entries index, which reads the identity,
 * and the orphan analysis, which measures the copy off the same stat and reads
 * the same errno. Neither could have taken it — the index is read by the analysis,
 * so the analysis cannot look for it, and the analysis is a caller's to decline
 * (sync and update run the scan with it off), so the index cannot borrow the
 * analysis's look — which is why this is a phase of its own, under the gate that
 * admits either reader (workspace_load). An orphan on a load this does not run
 * for keeps UNKNOWN, a look nobody took, and no reader is lent it.
 *
 * The walk is in path order (workspace_partition, over a snapshot SQLite ordered
 * by filesystem_path, and a parent sorts before everything beneath it), and that
 * order is load-bearing twice. Before each look the reach rule is asked as an
 * orphan asks it: beneath a squatter the view claims, or one a directory record
 * earlier in this very walk was found squatted, no look is taken — one there
 * would answer for the squatter's target and nothing it said would be this path's.
 * After each look, a directory record another kind of node stands at is a squatter
 * only a record remembers, noted while the look is in hand so the records beneath
 * it, later in this walk, are not looked at — on every load the index is built
 * for, sync's and update's too, or the scan would read an identity the squatter's
 * target lent a record beneath it. Only a link to a directory is a squatter a
 * key beneath it resolves *through*: a file or a device in its place answers
 * ENOTDIR, which fs_lstat_occupant reads as absence. A file record with a directory
 * in its place is retyped too (the orphan analysis's arm) and reaches nothing
 * beneath it, which is why the look notes a directory claim alone.
 *
 * The orphan analysis reads the same look for its own verdict — RELEASED with
 * [type] — and the two agree by construction: for a directory record they are
 * one reading of one occupant (workspace_analyze_orphans).
 *
 * @param ws Workspace (must not be NULL)
 */
static void workspace_look_orphans(workspace_t *ws) {
    for (size_t i = 0; i < ws->orphan_count; i++) {
        workspace_look(ws, ws->orphans[i]);
    }
}

/**
 * Where every row and every orphan record stands, by identity
 *
 * An entry is a name in a directory; a key is one spelling of it, and the two
 * facts the load holds about a path — a row of the view, a record — are keyed
 * by spelling. This is the one place the load reads the entry itself: each item
 * whose look found its claim's kind standing, sorted by the (dev, ino) that look
 * found, so a reader's ask is a binary search (find_entries). Built once per
 * load for the two verbs that act on an entry through a string, and met by identity
 * and never by string: both readers asked the strings first, and this answers
 * only where they could not.
 *
 * Two passes over two disjoint arrays — the active items, each standing at its
 * row's key, and the orphans, each exactly a record no row stands at — so an
 * entry is a row's or a record's and never both: an active item carries its row,
 * an orphan none, which is how standing_row tells them apart. Whether a key may
 * vouch at all is claim_stands, one rule read over both; every false answer drops
 * rather than keeps — a release where a prune was right or an offer deferred a
 * run, never an active file pruned or offered twice — which is the direction a
 * third reading would have to be argued in.
 *
 * No look is taken here: each item's is the one the phase that owns it took —
 * the walk over the active items for the rows, workspace_look_orphans for the
 * records — so the entry indexed is the item analyzed on it and the two cannot
 * disagree. That is also what makes the load's rule — no look beneath a squatter
 * (workspace.h workspace_displaced_t) — exact here for both authorities: an item
 * beneath a squatter that reaches it was never looked at, reads UNKNOWN, and
 * vouches for nothing. Legal because the join is not a caller's to decline
 * (workspace_load) and the orphans' look runs under this phase's own gate — were
 * either optional, an index built from it would answer differently by which
 * analyses a caller asked for, and the leaf probe's record guard is exactly where
 * that would be felt (workspace_options_t).
 *
 * One allocation sized by the two arrays, and a sort.
 *
 * Readers: standing_row (the orphan analysis's BACKED arm), standing_item (the
 * untracked scan's leaf probe).
 *
 * @param ws Workspace (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *index_entries(workspace_t *ws) {
    size_t active_count = ws->dir_count + ws->file_count;

    ws->entries = arena_calloc(
        ws->arena, active_count + ws->orphan_count, sizeof(*ws->entries)
    );
    if (!ws->entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate the entries");
    }

    for (size_t i = 0; i < active_count; i++) {
        const workspace_item_t *item = ws->active[i];

        if (claim_stands(item->occupant, item->item_kind)) {
            ws->entries[ws->entry_count++] = item;
        }
    }

    for (size_t i = 0; i < ws->orphan_count; i++) {
        const workspace_item_t *item = ws->orphans[i];

        if (claim_stands(item->occupant, item->item_kind)) {
            ws->entries[ws->entry_count++] = item;
        }
    }

    qsort(ws->entries, ws->entry_count, sizeof(*ws->entries), entry_order);

    return NULL;
}

/**
 * Measure a copy dotta may prune — or say whose refusal kept it from being measured
 *
 * A file: disk against what dotta last deployed (workspace_compare_orphan). A
 * directory: nothing to measure — cleanup's emptiness rule decides — only whether
 * it can be: one dotta cannot stat or cannot read is skipped, as an unstattable
 * file is, until the user can say what is in it.
 *
 * Each arm answers one question and only that one — whose refusal, if any — and
 * the tail answers the other for all three: a copy dotta could not measure reads
 * unverified, whoever refused. The compare's error is classed at the call, the
 * producer still handing it back for the caller to decide what a failure to look
 * means (workspace_compare_orphan). The fault is NONE on every item handed in:
 * the one arm of the orphan analysis that writes one leaves the copy unmeasured
 * and never prunable.
 *
 * Callers: the orphan analysis's two arms that find the copy dotta's to prune —
 * the user's prune order, and Git's backing (workspace_analyze_orphans). A
 * candidacy, not cleanup's verdict, which still skips the copy for a divergence
 * or a reason of its own.
 *
 * @param ws Workspace (provides the run's content reader)
 * @param item The orphan's item, beneath no squatter and not absent: a present
 *             occupant, or one that could not be stat'd (must not be NULL)
 */
static void workspace_measure(workspace_t *ws, workspace_item_t *item) {
    if (item->occupant == FS_OCCUPANT_UNKNOWN) {
        /* Present but unstattable, either kind: nothing to measure the copy with,
         * and the errno says whose refusal it was. */
        item->fault = workspace_code_fault(error_code_from_errno(item->lstat_errno));
    } else if (item->item_kind == PATH_KIND_FILE) {
        item->fault = workspace_error_fault(workspace_compare_orphan(ws, item));
    } else if (!fs_eaccess(item->filesystem_path, R_OK | X_OK)) {
        /* A directory: read for the readdir, search for the walk's look at an
         * entry named like OS metadata (fs_directory_emptiness). fs_eaccess leaves
         * faccessat's errno on false. */
        item->fault = workspace_code_fault(error_code_from_errno(errno));
    }

    if (item->fault != WORKSPACE_FAULT_NONE) {
        item->divergence = DIVERGENCE_UNVERIFIED;
    }
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
 *   - the ancestry: a squatter above the copy — a directory row of the view, or
 *     a directory record the looker found squatted — means no look was taken at
 *     all, and the record is released with nothing measured (squatted_ancestor,
 *     and the file analysis for the rule);
 *   - presence, off the look the load took (workspace_look_orphans) — either
 *     kind, a dangling link is present: an absent orphan is a reclaim whatever
 *     Git says, which keeps the planners' "absent ⇒ DIVERGENCE_NONE" rule;
 *   - the occupant's kind: a directory where dotta's file was, or anything but
 *     a directory where dotta's directory was, is a path dotta's copy has left
 *     — what dotta put there is gone, the same sentence as LOST below — and the
 *     node in its place is not dotta's to remove: unlink cannot take a directory,
 *     rmdir cannot take a file, and nothing authorizes either. Released, tagged
 *     [type]. Decided ahead of the prune order and the gate, because an order
 *     to prune a copy that is no longer there is moot and no tree needs asking.
 *     A file ↔ symlink ↔ device swap is not this: unlink undoes a one-node swap
 *     under --force, and the divergence names it TYPE. An occupant that could
 *     not be stat'd is not taken for another kind — it may be dotta's own
 *     directory, unreachable;
 *   - the prune order (remove --delete-files): the user chose the fate of the
 *     deployed copy, and Git is not asked. Honoured only with a reference to
 *     measure the copy against — a directory (cleanup's emptiness rule decides)
 *     or a file with a confirmed blob. A prune-ordered file dotta never matched
 *     against anything falls through to the gate: nothing could tell a clean
 *     copy from an edited one, and the user learns at status and apply that the
 *     copy stays, instead of a skip every run;
 *   - the ownership gate: a record dotta never owned — observed, or confirmed
 *     but never deployed — names a path the user put there before it was active.
 *     Released: the copy is left alone, the record retires, and no tree is asked
 *     about it;
 *   - Git authority (compute_orphan_authority) for an owned record: a departure
 *     dotta discovers in Git — the branch deleted, rebased or git rm'd, a pulled
 *     removal, a dead enabled branch, the name retyped to the other kind — is
 *     LOST, and the deployed copy is left alone (RELEASED); BACKED (a disabled
 *     profile, a moved target) is dotta's to prune, divergence permitting — and
 *     carries the relocation read: a BACKED orphan whose claim still has a row
 *     elsewhere in the view carries the class of the namespace the claim lands
 *     in (workspace_relocation_t), read where the row is found and the row not
 *     kept, and that class picks the fate (cleanup_verdict). Elsewhere is another
 *     entry, never merely another string, and the guard is asked first: a row
 *     standing on the record's very entry under another spelling of its path —
 *     whoever's — makes the record a stale key, RELEASED, so the one copy is
 *     never pruned as the old one (standing_row). A target bound through a symlink,
 *     a HOME spelled two ways, a name the volume folds; apply adopts the row
 *     under its spelling and retires the key; UNVERIFIED keeps the orphan skipped
 *     until Git answers — either kind: LOST would retire the record, BACKED would
 *     remove the copy, and neither is a guess to make about an empty directory
 *     any more than about a file. Skipped and not measured: no reader shows a
 *     bit beside UNVERIFIED, so a compare would only give the item a second reason
 *     for the one fate it already has. The probe raises nothing, so a lookup it
 *     could not make is this orphan's skip and never the load's — the rule the
 *     file analysis takes for its own looks.
 *
 * Divergence for a prunable file is disk against what dotta last deployed — the
 * record (workspace_compare_orphan). A prunable directory's verdict is cleanup's
 * emptiness rule, so there is nothing to measure, only whether it can be: a
 * directory dotta cannot stat, read or search — the path, or a component above
 * it — is UNVERIFIED, the bit an unstattable file carries, and held until the
 * user can say what is in it. That is one fs_eaccess per present directory orphan
 * (read and search: the walk lstat's an entry named like OS metadata to see that
 * it is a file); the readdir itself stays cleanup's, because what is left in a
 * directory depends on the plan. Both are the measure's (workspace_measure).
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
 * same look.
 *
 * Each arm writes the orphan's verdict onto its item, and the partition's —
 * ORPHANED, nothing wrong — stands where an arm has nothing to write. Nothing
 * is listed here: the diverged items list the orphans once the walk is done
 * (workspace_list), up to the bound it writes last (analyzed_count).
 */
static error_t *workspace_analyze_orphans(workspace_t *ws) {
    if (ws->orphan_count == 0) {
        return NULL;
    }

    /* profile → authority_cache_t for this pass. Keys borrow the records'
     * arena-backed profile strings, which outlive it. */
    hashmap_t *authority_cache = hashmap_borrow(8);
    if (!authority_cache) {
        return ERROR(ERR_MEMORY, "Failed to create authority cache");
    }

    /* The walk cannot fail: a folded error is not the walk's — the probe's failures
     * are the orphan's hold and the measure's are its bit, and each is consumed
     * at the call that raised it, never carried. */
    for (size_t i = 0; i < ws->orphan_count; i++) {
        workspace_item_t *item = ws->orphans[i];
        const anchor_t *anchor = item->anchor;

        /* Beneath a squatter of either authority — a record's memory reaches
         * the orphans, which this is (the reach rule, workspace_displaced_t) —
         * no look was taken (workspace_look_orphans), and the item says so:
         * ORPHANED with nothing measured; cleanup's displaced arm releases the
         * copy and apply's settle retires the record. */
        if (item->displaced != WORKSPACE_DISPLACED_NONE) continue;

        /* The load's look at this record, on its item (workspace_look_orphans):
         * never UNKNOWN for "not looked at" here — that record returned above —
         * so UNKNOWN below is a look that failed, with lstat's errno behind it.
         * One rule for every orphan, whatever its kind: FS_OCCUPANT_NONE is the
         * orphan already removed by hand (or a component above it no longer a
         * directory) — a reclaim; FS_OCCUPANT_UNKNOWN (EACCES, EIO, ELOOP, …)
         * is assumed present but leaves no usable stat, so a file's divergence
         * cannot be computed and becomes UNVERIFIED in the measure
         * (workspace_measure):
         * - Status shows [orphaned, unverified] (user visibility)
         * - Apply skips removal (can't verify what we can't stat)
         *
         * Absent: ORPHANED with no divergence — a reclaim whatever Git says. */
        if (item->occupant == FS_OCCUPANT_NONE) continue;

        /* Another kind of path where dotta's copy was (see the doc above): a
         * directory at a file record's path, anything but a directory at a
         * directory record's — the claim's kind failing to stand at its key,
         * which is claim_stands' own question over the record's type. An occupant
         * that could not be stat'd is not taken for another kind, which is the
         * first term. claim_stands answers the same of an absent record — nothing
         * standing vouches for nothing — which is why the absence arm above decides
         * first. The record's own kind, not the ancestry's: whether a squatter
         * stands above the copy was asked before the look (squatted_ancestor),
         * and no record that reached here is beneath one; a directory record
         * that is retyped here is the squatter workspace_look_orphans noted when
         * it took this very look.
         *
         * What dotta put there is gone, and what stands there is not dotta's to
         * remove. Released, [type]: the record retires, the path stays. */
        if (item->occupant != FS_OCCUPANT_UNKNOWN &&
            !claim_stands(item->occupant, item->item_kind)) {
            item->state = WORKSPACE_STATE_RELEASED;
            item->divergence = DIVERGENCE_TYPE;
            continue;
        }

        /* The user ordered the copy pruned — remove --delete-files over a path
         * the removal named or a copy dotta deployed, the only births an order
         * has (state_order_prune); Git is not asked. Read ahead of the ownership
         * gate below by design: a named path must go whether dotta deployed it
         * or only ever found it. Divergence still protects an edited copy —
         * cleanup's skip reasons read the same bits.
         *
         * Only where the copy can be measured at all: a directory against cleanup's
         * emptiness rule, a file against a confirmed blob. The schema CHECK
         * (state.c: ownership implies confirmation) guarantees an owned file
         * record its blob, so for files this discriminates only when deployed_at
         * == 0 — a prune-ordered record dotta never deployed. */
        if (anchor->ordered_at > 0 &&
            (item->item_kind == PATH_KIND_DIRECTORY || !git_oid_is_zero(&anchor->blob_oid))) {
            workspace_measure(ws, item);
            continue;
        }

        /* The ownership gate: dotta never put this here. Released — the copy is
         * left alone and the record retires. A prune-ordered file with no confirmed
         * blob lands here too: there is nothing to measure the order against. */
        if (anchor->deployed_at == 0) {
            item->state = WORKSPACE_STATE_RELEASED;
            continue;
        }

        /* Owned: ask the profile that deployed it whether it still holds the
         * claim this record remembers. */
        switch (compute_orphan_authority(
            ws->repo, authority_cache, item->profile, item->storage_path, item->item_kind
            )) {
            case ORPHAN_AUTHORITY_UNVERIFIED:
                /* Git could not vouch for the path — a lookup that failed, or
                 * an allocation the probe needed — and neither LOST nor BACKED
                 * is a guess to make: held. Not measured, unlike a backed copy
                 * below: no reader shows a bit beside UNVERIFIED, so a compare
                 * would only give the item a second reason for the fate it already
                 * has. Its class is UNVERIFIED whatever went wrong: the probe
                 * meets Git and its own allocations, never a key or a
                 * permission. */
                item->divergence = DIVERGENCE_UNVERIFIED;
                item->fault = WORKSPACE_FAULT_UNVERIFIED;
                continue;

            case ORPHAN_AUTHORITY_LOST:
                /* Git cannot back the path. Left on disk, record retires — so
                 * there is nothing a content comparison would decide. */
                item->state = WORKSPACE_STATE_RELEASED;
                continue;

            case ORPHAN_AUTHORITY_BACKED:
                break;
        }

        /* The guard — BACKED only, which is all that reaches here. A row of the
         * view stands on this very entry under another spelling of its path:
         * this profile's own claim after its root was re-spelled, another profile's
         * through a link no binding names, a name the volume folds. The record
         * is a stale key of an active path, not a copy left behind — released,
         * and the path stays for the row standing on it; what becomes of that
         * row is apply's adoption, which reads its own gates (cmds/apply.c).
         *
         * By the entry and never by a name compare: a volume that folds case or
         * normalization stands one entry at two strings, and cleanup was measured
         * deleting an active file through that fold. An occupant that could not
         * be stat'd is not asked and falls through: the item's stat is meaningful
         * for a present occupant alone (workspace_item_t), so the two conjuncts
         * keep this order. */
        if (item->occupant != FS_OCCUPANT_UNKNOWN &&
            standing_row(ws, item->filesystem_path, &item->st)) {
            item->state = WORKSPACE_STATE_RELEASED;
            continue;
        }

        /* The relocation read: a relocated orphan is an orphan whose claim still
         * has a row, standing at another file. The record's own (profile, storage
         * path) pair is asked of the view; a row found here always projects to
         * another string — the partition orphaned this record precisely because
         * no view row stands at its filesystem path, this row included — and,
         * after the guard above, to another entry: a root re-spelled under another
         * name of one directory is the guard's, not a relocation. So the claim
         * deploys at a new location now: a moved custom/ target, a different
         * $HOME. The class picks the fate at cleanup_verdict, and root/ never
         * gets here — its projection is fixed, so a root/ claim's old and new
         * locations are one string and the record was never orphaned. Strictly
         * the record's own profile: a claim shadowed by another profile at its
         * new home is not "relocated" — the copy here is simply no longer active.
         * And strictly its own kind: BACKED said the branch holds a claim of
         * that kind at the name, and the view builds no row of the other kind
         * there. Asked on this arm alone: it is a linear scan of the view, and
         * the arms above read no row.
         *
         * The class is read here, where the row is found, and the row is not
         * kept: an orphan item carries none, which is how the entries tell a
         * view's item from a record's (standing_row), and nothing reads the new
         * location. Which of the two kinds of relocation it is, is the mounting
         * rule of the namespace the claim is named in — the label alone, and no
         * place: a root's binder answers which profile bound that one root, where
         * the question here is whether the namespace is anyone's to re-target
         * (infra/mount.h mount_root_t). The record's name and the row's are one
         * string (manifest_lookup_storage matches it exactly), and a name the
         * view holds was validated where the branch was read, so the projection
         * below asserts nothing not already established. */
        if (manifest_lookup_storage(ws->manifest, item->storage_path, item->profile)) {
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
        workspace_measure(ws, item);
    }

    hashmap_free(authority_cache, authority_cache_free);

    /* Every orphan analyzed, by a walk that cannot fail: the diverged items list
     * them from here (workspace_list). */
    ws->analyzed_count = ws->orphan_count;
    return NULL;
}

/**
 * The blob the view holds over a directory — at it, or at a rung above it
 *
 * A directory standing where the view holds a blob is the [type] the file analysis
 * said, and nothing beneath it can stand: the view says a file belongs there,
 * so anything offered beneath is something no apply can ever place. Whichever
 * profile's blob, precedence applied (core/manifest.h manifest_lookup) — the
 * question is what stands at the path, not what the scanning profile holds. A
 * directory row of either kind stops nothing: an ancestor claim names neither
 * itself nor anything beneath it (manifest_is_derived), which is why a derived
 * row at one key is no answer about the other.
 *
 * A directory has one key — the tracked row's own, which mount_resolve spelled
 * — and the walk's joins beneath it are keys by the same construction
 * (infra/mount.h: a child joined onto a key is a key), so one climb here answers
 * for every path in that walk. Each step is the last separator's index, or 1
 * for a rung beneath the root directory, so a rung is strictly shorter than the
 * one before it; the root directory is read and ends the climb, because a claim
 * can stand there — `root` spells it, and `home` or `custom` on a machine whose
 * HOME or target is one (infra/label.h) — and the view places a blob at any of
 * the three as a FILE row at that directory (core/manifest.c manifest_claim_blob).
 * The key is absolute; the copy the climb truncates is the caller's arena's,
 * one per ask, and abandoned.
 *
 * The ascent over these very rungs floors on the asker's own root (core/manifest.c
 * manifest_ascend): it is naming a path for one profile, and nothing of that
 * profile's stands above its root. This climb has no asker — it asks what stands
 * at a path, whoever holds it — so the root directory is its floor, as it is
 * deploy's (core/deploy.c nearest_ancestor).
 *
 * Reader: the scan driver (workspace_analyze_untracked), of every tracked directory
 * it is about to enumerate — an independent tracked root beneath a file claim
 * is as much beneath it as a child the walk would have stopped at. One ask per
 * root and none per child: the walk asks the view at each child's own key, which
 * is the one rung a frame adds to this answer (scan_directory_for_untracked).
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
 * Keyed by the directory's identity — the (dev, ino) the join's look found at
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
 * one kept, owner and spelling together, the index's rule for a contested path
 * (core/manifest.c manifest_layer) applied where the keys differ; among one
 * profile's, the later in path order. The consequence: where two tracked rows
 * stand at one directory under two spellings, the later-enabled profile's walk
 * is the one that runs, and the other's namespace never sees an offer beneath it.
 *
 * The entries index (index_entries) reads the same look off the same items, for
 * the two verbs that act on an entry through a string, and the two are not one
 * structure: a root is a selection with a winner and a mutable registration, an
 * entry a look with a run of equals — and the shapes differ with them, an entry
 * being the item its readers ask what stands on, a root the two strings its walk
 * reads.
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
 * the namer's input exact and a leaf's probe hit the key the view holds.
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
 * One question opens both kinds, and it is the view's word at the child's own
 * key: a claim that names its own path settles the child whatever stands there,
 * for no look at all — manifest_is_derived names the one row that names no path,
 * and the walk passes through it as through any unclaimed directory. What the
 * two kinds ask after the look is not the same question: a directory asks the
 * identity — is this another root's? — because a root is reached by whatever
 * spelling a frame joined and the key above answered one of them; a leaf asks
 * whether the record speaks for its path, and then whether a row or a record
 * stands on its very entry. Neither needs the other's: no offer is ever made
 * *at* a directory, so a directory asks no record, and a leaf is reached by a
 * frame that was cleared before it was entered, so a leaf climbs nothing. A
 * directory the record remembers is entered like any other — the view says what
 * belongs at a path whatever stands there, where a record says what dotta put
 * there, which only a look confirms: a record bounds what is offered, never where
 * the walk goes.
 *
 * Nothing beneath a blob the view holds is offered, and the climb that says so
 * is the driver's, asked once of the directory a walk begins at
 * (workspace_analyze_untracked, blob_over). A frame adds exactly one rung to
 * that answer — the child's own key, which is the question above — and every
 * rung over it was answered before the frame was entered, no frame being entered
 * whose directory a blob stands at or over. So the rule is this walk's induction
 * rather than a climb per child, and `directory` carries it as a precondition.
 *
 * The order is the order. The view's word first, because a claim that names its
 * own path settles the child whatever stands there and costs no look; the lstat
 * next, because the kind and the identity decide every arm that is left; the
 * occupant skip before the identity and the record, because nothing can hold
 * what it names; the guards before the name, because an ascent is paid only where
 * a name is used and in a tracked directory most leaves are active; the name
 * before the ignore layers, the name being the first layer's subject; the layers
 * before the descent, because an excluded directory is not entered.
 *
 * A best-effort look, and neither a snapshot nor an admission: what the commit
 * can hold at an offered name is update's question at its capture (cmds/update.c).
 * The view's word closes the one class the view can decide for itself and closes
 * no other — a name the branch's tree or its claim sheet cannot hold is still
 * the capture's to refuse.
 *
 * One arrangement the blob rule does not reach, and need not: where a later
 * profile's explicit DIRECTORY claim wins a path an earlier one holds a blob
 * at, the index answers with the directory row. That row is necessarily tracked
 * — a derived row never takes a held path — so the question above settles the
 * child by the view's own word, and the directory is the winner's to enumerate,
 * under the winner's name, from a depth 0 of its own.
 *
 * What the filesystem refuses is said where it happens and the siblings go on,
 * absence is silent, and an allocation anywhere is the run failing. The lines
 * go to stderr, as the driver's do — core has no output handle.
 *
 * @param scan      What the walk runs under (must not be NULL)
 * @param directory The path this frame enumerates: a key the view holds no blob
 *                  at or over (must not be NULL)
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

        /* The view's word at the child's own key, before any look. A claim that
         * names its own path settles the child whatever stands there: a blob
         * bounds the walk (the induction above), and a tracked directory is the
         * driver's to enumerate, from a depth 0 of its own, or the [type] the
         * directory analysis already said. Either way the load holds one verdict
         * for the path and says it on its own screen, where the remedies are —
         * the join is every load's (core/workspace.h workspace_options_t), so a
         * path this walk leaves unsaid is one the load has said already. An
         * ancestor claim is the one row that names neither itself nor what lies
         * beneath it (core/manifest.h manifest_is_derived): the walk passes through
         * it as through any unclaimed directory, and a look is paid there, and
         * for what no claim names at all. */
        const manifest_row_t *claim = manifest_lookup(ws->manifest, child);
        if (claim && !manifest_is_derived(claim)) continue;

        /* One lstat names what stands there — its kind, and for a directory its
         * identity: a symlink is never a directory here. Absence is a skip —
         * the listing and this look are two moments. A look that failed is said,
         * its errno read in the line itself (sys/filesystem.h: it is lstat's
         * until something else runs): nothing downstream can name a path it could
         * not see, and a claim that settles the child was skipped above, so what
         * reaches that line is an unclaimed child or a rung the walk only passes
         * through. What no branch can hold — a device, a socket, a FIFO — is
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
             * and under its owner's names and rules. Asked of the identity, the
             * one thing the key above could not answer: a root is reached by
             * whatever spelling a frame joins, and the view holds a row at one
             * of them. Asked before the name and before any rule: an owner's
             * exclusion is the owner's, and a walk from outside inherits none
             * of it. */
            if (find_scan_root(scan->roots, scan->root_count, st.st_dev, st.st_ino)) {
                continue;
            }
        } else if (claim || workspace_find_item(ws->orphans, ws->orphan_count, child) ||
            standing_item(ws, child, &st)) {
            /* Whether anything already speaks for the leaf — by its spelling
             * and then by its entry, in descending order of standing. The view
             * holds it: after the question above only a rung can stand here, an
             * ancestor claim with a file in its place — the [type] the directory
             * analysis said as a derived row — and offering it would tell a second,
             * contradicting story about one path. The record holds it: dotta
             * managed the path and has not let go — an orphan for cleanup to
             * prune or release, or a path `remove --delete-files` has ordered
             * deleted and still remembers — never a discovery, and a discovery
             * again only once the record is retired; no row stands at the child
             * here, so a record at its spelling is an orphan's. And either of
             * the two under another spelling of the same entry: a row or a record
             * standing on the very file this frame joined its way to — a link
             * no binding names, a root two profiles spell two ways, a name the
             * volume folds — is active or remembered however it is spelled, and
             * offering it would commit one file twice or promise a commit of a
             * copy cleanup is about to prune. All three are the load's own facts,
             * built before the scan runs (workspace_partition, index_entries),
             * so status, sync and update read one answer whatever else each ran.
             * The identity probe is paid only for a child neither string claimed
             * — the offers. */
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
         * Where no layer decided, the source tree's .gitignore on the path (its
         * root is that repo's) — the lowest layer, so a `!` rule above it wins.
         * That one reads the place and not the subject, so a root standing inside
         * a repository whose rules name it is not entered, which is the answer
         * the directory would get under any other name. The layer's own failure
         * leaves no verdict, as today; its allocation failure is the run's. */
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
                     : workspace_add_untracked(ws, child, name, scan->profile, occupant, &st);
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
 * profile claims and dotta has no record of, offered to the profile whose tracked
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
static error_t *workspace_analyze_untracked(
    workspace_t *ws,
    const config_t *config
) {
    CHECK_NULL(ws);

    /* Sized by the directory rows, which bounds the appends: a row is tested
     * once per profile and matches its own alone, so it is a candidate in exactly
     * one pass and the directory items count every candidate there is. A row
     * that coincides with one already registered overwrites it rather than
     * appending.
     *
     * The scan roots: every tracked directory that is a directory on disk, one
     * per directory. An ancestor claim is not one — the profile passes through
     * the directory on the way to something beneath it, and what it does track
     * inside has its own tracked row, registered here on its own. A row beneath
     * a squatted ancestor is not one either, whatever a look at its key would
     * find: the key resolves through the squatter, so the directory found is
     * one the claim has no standing at — apply refuses beneath a squatter by
     * the same probe — and registering it would make that directory a boundary
     * no honest walk may enter. Both are read off the directory item's look
     * (workspace_look): a row beneath a squatted ancestor was never looked at
     * and reads UNKNOWN; a row whose own key a link or a file holds reads that
     * occupant, the link itself and never what it reaches — a claim of a directory
     * that is a link now is the [type] the directory analysis said, and enumerating
     * the link's target would offer that directory's files as this row's. The
     * kind test is the walk's own question, not the index's — is there a directory
     * here to enumerate, where claim_stands asks whether a claim's kind stands
     * — and over the directory items the kind is a constant. Registered in the
     * view's order, lowest profile first, so a later profile's row standing at
     * a directory an earlier one already stands at takes it — the index's own
     * rule for a contested path (core/manifest.c manifest_layer), applied where
     * the keys differ — and within one profile the later row in path order. */
    scan_root_t *roots = arena_calloc(ws->arena, ws->dir_count, sizeof(*roots));
    if (!roots) {
        return ERROR(ERR_MEMORY, "Failed to allocate the scan's roots");
    }
    size_t root_count = 0;

    size_t profile_count = 0;
    const char *const *profiles = manifest_profiles(ws->manifest, &profile_count);

    for (size_t p = 0; p < profile_count; p++) {
        for (size_t i = 0; i < ws->dir_count; i++) {
            const workspace_item_t *item = ws->active[i];

            if (!item->row->tracked || strcmp(item->profile, profiles[p]) != 0) continue;
            if (item->occupant != FS_OCCUPANT_DIRECTORY) continue;

            scan_root_t *root = find_scan_root(
                roots, root_count, item->st.st_dev, item->st.st_ino
            );
            if (!root) root = &roots[root_count++];

            *root = (scan_root_t){
                .dev = item->st.st_dev, .ino = item->st.st_ino,
                .profile = item->profile, .directory = item->filesystem_path,
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

        /* A blob the view holds at this directory or over it, asked once for
         * the whole walk beneath it: an offer under a blob is one no apply can
         * place, whoever would name it, and committing it turns a view-versus-disk
         * conflict the user can resolve into a view-versus-view one only `remove`
         * can. Said on its own screen rather than here — the file analysis stands
         * the [type] at the blob's own path, with the remedies beside it. The
         * same question at a root the driver reached directly: an independent
         * scan root beneath a file claim is as much beneath it as a child the
         * walk would have stopped at. An owner that cannot be enumerated is not
         * replaced: the directory stays a boundary and is not scanned, whatever
         * a lower row standing at it under a cleaner spelling could have offered
         * — the view's word about the directory is its owner's. The walk beneath
         * inherits this answer and climbs nothing of its own: it asks the view
         * at each child's own key, and every rung over that key is this one
         * (scan_directory_for_untracked). */
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
 * Analyze divergence for a single active directory row
 *
 * Detects, for a directory row:
 * - DELETED state: Directory removed from filesystem
 * - DIVERGENCE_UNVERIFIED: Directory could not be stat'd (inaccessible)
 * - DIVERGENCE_TYPE: Something other than a directory stands at the path
 *
 * and for a tracked row alone — the profile's word about a directory it tracks,
 * where an ancestor claim has none to give (the split is at the line itself):
 * - DIVERGENCE_MODE: the mode is not the claim's
 * - DIVERGENCE_OWNERSHIP: the owner or group is not the claim's
 * - DIVERGENCE_CLAIM_MOVED: beside either, where Git moved it past the claim
 *   the record reconciled (workspace_analyze_claim)
 * - A pending reassignment on a clean row, which no bit carries: the route reads
 *   it off the item's sources and look, and the diverged items list the item
 *   for it (workspace_list), as they list a file row's
 *
 * ARCHITECTURE: Reads the view's directory rows, not metadata (Git) directly. A
 * row carries filesystem_path already resolved with target, enabling correct
 * divergence detection for custom/ prefix directories.
 *
 * The directory analysis of the load's walk over the active items (workspace_load),
 * which it reaches before any file — every input is by construction a directory
 * row of the view. No scope checks: the class is the only thing this analysis
 * asks of a row beyond its path. Each fate is decided in the arm that meets it
 * and returned from there, the file analysis's shape.
 *
 * @param ws Workspace (must not be NULL)
 * @param item The directory row's item, its record paired at the partition (must
 *             not be NULL). Its look is taken here, and the phases after the
 *             join read it
 */
static void workspace_analyze_directory(workspace_t *ws, workspace_item_t *item) {
    /* Directory rows carry:
     * - filesystem_path: Already resolved with target (mount table)
     * - storage_path: Portable path
     * - profile: Source profile
     * - mode, owner, group: Expected metadata
     *
     * All strings are arena-allocated — no explicit free needed. */
    const manifest_row_t *row = item->row;

    /* The record dotta keeps of this path, if any — paired at the partition, as
     * the file analysis's is. */
    const anchor_t *anchor = item->anchor;

    /* The load's one look at this row, into its item and kept for the phases
     * after (workspace_look) — or none, beneath a squatter: the file analysis's
     * rule, stated there. The directories are walked parents-first
     * (workspace_kind_order), so the squatter above this one was noted by its
     * own look before this row's turn; a squatter beneath a squatter is therefore
     * never noted, and the outer one carries the whole answer. Both classes: an
     * ancestor claim beneath a squatter is as unlooked-at as a tracked one. Read
     * as fs_lstat_occupant names it:
     * - NONE: Directory truly deleted, or a component above it is not a directory
     *   — nothing can be at the path either
     * - UNKNOWN: Inaccessible — state undeterminable, not absent
     * - Anything but DIRECTORY: Type changed (file, symlink - including broken
     *   ones)
     * - DIRECTORY: Actual directory, check metadata */
    workspace_look(ws, item);

    if (item->displaced != WORKSPACE_DISPLACED_NONE) {
        return;
    }

    if (item->occupant == FS_OCCUPANT_NONE) {
        /* Absent path: classify_absent decides, and this is where its claim gate
         * earns its keep. An observed tracked directory was deleted by the user
         * (update propagates the removal); a never-observed one was never there,
         * nor was one observed only as another kind of node (a file where the
         * claim is now a directory); and an ancestor claim asserts nothing to
         * have been deleted whatever its record says — apply's job is to create
         * it, never to commit a phantom deletion. No divergence: the path is
         * absent. The item is listed either way, its state not DEPLOYED
         * (workspace_list), and deploy's ancestors pass reads absence off its
         * occupant, not its state. */
        item->state = classify_absent(row, anchor);
        return;
    }

    if (item->occupant == FS_OCCUPANT_UNKNOWN) {
        /* Inaccessible, not absent: record the uncertainty rather than dropping
         * the row, which left status reporting a clean workspace for a path it
         * had just failed to read. Same three-way policy as the file rows. */
        item->divergence = DIVERGENCE_UNVERIFIED;
        item->fault = workspace_code_fault(error_code_from_errno(item->lstat_errno));
        return;
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
    if (item->occupant != FS_OCCUPANT_DIRECTORY) {
        /* The squatter, noted by the look that found it, the row's class the
         * claim (workspace_look): absence and an unstattable path are ruled out
         * above, so something real stands here and no look beneath this path is
         * taken at all. DEPLOYED, as the partition made it: the path exists,
         * just the wrong type. */
        item->divergence = DIVERGENCE_TYPE;
        return;
    }

    /* The directory stands, the row's own kind — the arms above having ruled on
     * absence, a failed look and every other kind — so where dotta has no record
     * the path is owed its observation, of either class, which the flush makes
     * off this look (workspace_flush), as it does a file's.
     *
     * An ancestor claim is a creation template, not a convergence target, and
     * this is the line the profile's word about the path begins at. Every question
     * above is asked of both classes: an unreadable path is a fact about the
     * path, a squatter is noted of either class by the look — a squatter above
     * an active path voids every look beneath it whether or not the profile tracks
     * the squatted path itself (workspace_look, core/deploy's ancestry rung) —
     * and absence is what deploy's ancestors pass reads off the item. Absence
     * is the one whose ANSWER differs by class, and it is not split here:
     * classify_absent carries that gate, so the two analyses cannot read an absent
     * path two ways.
     *
     * The ancestry is the one question asked ahead of all of them, because an
     * answer taken beneath a squatter is no answer about this path.
     *
     * Everything below is the profile's word about a directory it tracks, and a
     * derived claim has none to give. Its mode and ownership are a snapshot of
     * the machine the chain was captured on: they say what to create the path
     * as, never what to make of the one this machine already has — asserting
     * them here would let a ~/.ssh captured at a careless 0755 loosen a correct
     * 0700 elsewhere, a regression caused by the fix. The reassignment is the
     * rule's own: a claim nobody made carries no intent to acknowledge, so
     * workspace_reassigned answers false for a derived claim wherever it is asked
     * — the route's reading for the diverged items included (workspace_list) —
     * and the record keeps the profile dotta actually deployed under, which is
     * what a record is for. */
    if (!row->tracked) {
        return;
    }

    /* The claim, by the one rule the file analysis asks too
     * (workspace_analyze_claim): the look stands at the row's kind, since absence
     * and every other kind were ruled on above. */
    workspace_analyze_claim(item);
}

/**
 * An item per active path and per orphan record, each record paired onto its item
 *
 * The join at the centre of every load. The expected side — every enabled profile
 * at HEAD, both kinds, one row per path — is ws->manifest, the dispatcher's view:
 * each of its rows is made an item before anything is looked at, and the items
 * are sorted by kind (workspace_kind_order). The record is then read once and
 * walked once: a record an active item stands at is that item's, and a record
 * none stands at is an orphan, an item of its own. The released copies load beside
 * the record, unconditionally.
 *
 * The partition is the single source of truth for "is this row in scope?": a
 * path is active iff the view has a row for it, and a record is an orphan iff
 * no active item stands at its path — one search, asked once per record, decides
 * both. No defensive cleanup on error: workspace_free is the single cleanup
 * authority.
 *
 * Every array is allocated whatever its count: the arena answers a zero-byte
 * request with a pointer (NULL is OOM alone, base/arena.h), so no array is ever
 * NULL — qsort's and bsearch's base must be valid even for zero elements (C11
 * 7.22.5), and the file items', active + dir_count, is then a pointer on an empty
 * view too. On an empty view several of them are that one answer, the same address,
 * and none is read at count zero.
 *
 * Lifetime: every pointer (the items, their arrays, the record, the squatted
 * list, the copies) lives in ws->arena, beside the view's rows; the view's index
 * is the dispatcher's.
 *
 * Performance: O(M log M + A log M) — one sort, and a search per record; no Git,
 * no probes.
 */
static error_t *workspace_partition(workspace_t *ws) {
    manifest_rows_t view = manifest_rows(ws->manifest);

    /* The active items, one block, their count the view's and known before the
     * loop. Each is made with nothing looked at — UNKNOWN, a look nobody took —
     * and DEPLOYED with nothing wrong: the verdict an analysis that has nothing
     * to say leaves standing, so none writes it. */
    workspace_item_t *items = arena_calloc(ws->arena, view.count, sizeof(*items));
    ws->active = arena_calloc(ws->arena, view.count, sizeof(*ws->active));
    if (!items || !ws->active) {
        return ERROR(ERR_MEMORY, "Failed to allocate the active items");
    }

    for (size_t i = 0; i < view.count; i++) {
        const manifest_row_t *row = view.entries[i];

        items[i] = (workspace_item_t){
            .row = row,
            .filesystem_path = row->filesystem_path,
            .storage_path = row->storage_path,
            .profile = row->profile,
            .item_kind = path_type_kind(row->type),
            .occupant = FS_OCCUPANT_UNKNOWN,
            .state = WORKSPACE_STATE_DEPLOYED,
        };
        ws->active[i] = &items[i];

        if (items[i].item_kind == PATH_KIND_DIRECTORY) {
            ws->dir_count++;
        } else {
            ws->file_count++;
        }
    }

    /* The view's row order is unspecified: the items by kind, in the order the
     * load looks in */
    qsort(ws->active, view.count, sizeof(*ws->active), workspace_kind_order);

    /* The record, read once and held by the items alone. A record an active item
     * stands at is that item's, found by the search every later reader of an
     * active path makes; the rest are the orphans, in the snapshot's strcmp order
     * (core/state.h), which their search and workspace_look_orphans' parents-first
     * walk rest on. An orphan is a single, its count known only once the records
     * are paired — a block sized to the record would pay an item for every paired
     * one — and the array holding them is sized to the bound: any record may be
     * an orphan. */
    anchor_t *anchors = NULL;
    size_t anchor_count = 0;
    error_t *err = state_get_all_anchors(ws->state, ws->arena, &anchors, &anchor_count);
    if (err) {
        return error_wrap(err, "Failed to read anchors from state");
    }

    ws->orphans = arena_calloc(ws->arena, anchor_count, sizeof(*ws->orphans));
    if (!ws->orphans) {
        return ERROR(ERR_MEMORY, "Failed to allocate the orphans");
    }

    for (size_t i = 0; i < anchor_count; i++) {
        anchor_t *anchor = &anchors[i];

        workspace_item_t *active = workspace_find_active(ws, anchor->filesystem_path);
        if (active) {
            active->anchor = anchor;
            continue;
        }

        workspace_item_t *orphan = arena_alloc(ws->arena, sizeof(*orphan));
        if (!orphan) {
            return ERROR(ERR_MEMORY, "Failed to allocate an orphan item");
        }

        *orphan = (workspace_item_t){
            .anchor = anchor,
            .filesystem_path = anchor->filesystem_path,
            .storage_path = anchor->storage_path,
            .profile = anchor->profile,
            .item_kind = path_type_kind(anchor->type),
            .occupant = FS_OCCUPANT_UNKNOWN,
            .state = WORKSPACE_STATE_ORPHANED,
        };
        ws->orphans[ws->orphan_count++] = orphan;
    }

    /* Room for every squatter the looks can note, taken here, where the load
     * can still fail whole: a note dropped later would cost a verdict — every
     * item beneath the squatter analyzed on a look that resolved through it. A
     * squatter is a directory claim, a view row's or a record's, and each item
     * is looked at once (workspace_look), so the directory items and the orphans
     * bound the notes. */
    ws->squatted = arena_calloc(
        ws->arena, ws->dir_count + ws->orphan_count, sizeof(*ws->squatted)
    );
    if (!ws->squatted) {
        return ERROR(ERR_MEMORY, "Failed to allocate the squatted directory list");
    }

    /* The released copies, beside the record: almost always empty, and searched
     * as read — the getter's strcmp order is the whole of what the base
     * derivation's search needs (state_lookup_released_copy). */
    err = state_get_released_copies(
        ws->state, ws->arena, &ws->released, &ws->released_count
    );
    if (err) {
        return error_wrap(err, "Failed to read released copies from state");
    }

    return NULL;
}

/**
 * The diverged items: every active item with something to say, in the active
 * items' order, then every orphan the load analyzed
 *
 * Something to say: a state but DEPLOYED, or a DEPLOYED item the route does not
 * call clean (workspace_item_route) — a squatter above it, a bit, or a pending
 * reassignment. One rule, read here over the verdicts the analyses wrote, and
 * none of them lists anything, so no two can list by two rules; an active item
 * none had anything to write on keeps what the partition made it — DEPLOYED,
 * nothing wrong — and is not among them. An orphan is never DEPLOYED, so every
 * analyzed one has something to say: a reclaim, a release, a prune or a skip.
 *
 * The reassignment is the one term no analysis writes: a clean row whose owned
 * record names another profile is REASSIGNED by the route, read over the item's
 * sources and its own look (workspace_reassigned) — where that look found the
 * row's kind standing, a record of another kind is a node that is gone and no
 * reassignment — and listed for it, so the readers that show one see both kinds:
 * cmds/status.c status_print_workspace's Profile reassignments section and
 * cmds/diff.c diff_workspace's filter.
 *
 * Derived once, after every analysis and before any write, so it is a load product:
 * an ownership event that later makes an item's route CLEAN leaves it here (apply
 * reads its reassignment facts before its writes for that reason). The scan appends
 * its discoveries after it (workspace_add_untracked), so the order is the active
 * items', then the orphans', then the discoveries' — the order every screen prints.
 *
 * @param ws Workspace (must not be NULL)
 * @return ERR_MEMORY where the list could not grow, NULL otherwise
 */
static error_t *workspace_list(workspace_t *ws) {
    for (size_t i = 0; i < ws->dir_count + ws->file_count; i++) {
        workspace_item_t *item = ws->active[i];

        if (item->state == WORKSPACE_STATE_DEPLOYED &&
            workspace_item_route(item) == WORKSPACE_ROUTE_CLEAN) {
            continue;
        }

        error_t *err = ptr_array_push(&ws->diverged, item);
        if (err) return err;
    }

    /* The analyzed prefix, which is every orphan or none: a load that declined
     * the orphan analysis lists none, whatever it looked at (analyzed_count) */
    for (size_t i = 0; i < ws->analyzed_count; i++) {
        error_t *err = ptr_array_push(&ws->diverged, ws->orphans[i]);
        if (err) return err;
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
    const workspace_options_t *opts,
    arena_t *arena,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(content_cache);
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* Zeroed: every count starts at none — analyzed_count stays so on a load
     * that declines the orphan analysis — and a zeroed ptr_array_t is the diverged
     * items' empty state */
    workspace_t *ws = calloc(1, sizeof(*ws));
    if (!ws) {
        return ERROR(ERR_MEMORY, "Failed to allocate workspace");
    }

    /* Borrow caller-owned resources. Lifetime guarantees: repo is ctx->run.repo
     * (command-scoped); state comes from ctx->run.state (command-scoped);
     * content_cache comes from ctx->run.content_cache (command-scoped, wraps
     * ctx->run.keymgr); manifest is ctx->run.manifest (the view the dispatcher
     * built over the enabled set, command-scoped); arena is ctx->arena
     * (command-scoped). All five must outlive workspace_free. The view is the
     * persistent enabled set's, never a CLI filter's: `dotta status -p global`
     * loads the whole workspace and filters at display time. */
    ws->repo = repo;
    ws->state = state;
    ws->content_cache = content_cache;
    ws->manifest = manifest;
    ws->arena = arena;

    /* An item per active path and per orphan record, each record paired onto
     * its item. Consumers read the active items, whole or by kind, every one
     * with its record on it (workspace_active, workspace_directories,
     * workspace_files), and the item at a path (workspace_find). The view was
     * computed from Git at dispatch, so it is current by construction — nothing
     * upstream repairs anything. */
    error_t *err = workspace_partition(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to partition workspace");
    }

    /* The join, one walk over the active items in their order
     * (workspace_kind_order): every directory before any file, each analyzed as
     * its kind asks, the look taken into the item itself (workspace_look) — the
     * whole of the pairing the later phases read. The directories first, because
     * their looks are the only producer of the view's squatters (workspace_look),
     * and every look after them asks that fact before taking one — the file rows,
     * the orphan records (workspace_look_orphans), the scan's roots. Neither
     * kind is a caller's to decline; why not is workspace_load's own contract.
     * The walk cannot fail: an analysis writes its verdict, and the confirmation
     * the record is owed, onto the item, and a look that fails is a verdict too. */
    for (size_t i = 0; i < ws->dir_count + ws->file_count; i++) {
        workspace_item_t *item = ws->active[i];

        if (item->item_kind == PATH_KIND_DIRECTORY) {
            workspace_analyze_directory(ws, item);
        } else {
            workspace_analyze_file(ws, item, config);
        }
    }

    /* The orphans' looks and their squatters, then where every row and every
     * record stands by identity — for the two verbs that act on an entry through
     * a string. After the join's walk, which is where the rows' looks are taken
     * and where the view's squatted set is completed; before the orphan analysis,
     * whose guard reads the index; and only where a reader may ask, which is
     * this gate said once for both — the orphan analysis returns at its first
     * line with no orphan, and the scan asks per offer. Every ask below is
     * therefore made on a load this built the index in (find_entries).
     *
     * The left arm is the orphan analysis's own precondition for reading an
     * orphan's look, so an analysis that reads one ran under this block by
     * construction; where this did not run, every orphan keeps UNKNOWN, a look
     * nobody took, and no reader is lent one. The rows cost the index no look,
     * so what the gate buys is the orphans' looks and the array with its sort —
     * 2081 entries built and ordered for a reader that would return at its first
     * line. */
    if ((opts->analyze_orphans && ws->orphan_count > 0) || opts->analyze_untracked) {
        workspace_look_orphans(ws);

        err = index_entries(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to index the entries");
        }
    }

    /* Optional: the orphans analyzed (records of either kind the view lacks) —
     * on the looks taken above, against the index built from them */
    if (opts->analyze_orphans) {
        err = workspace_analyze_orphans(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze orphans");
        }
    }

    /* The diverged items, derived once every verdict is in: after the orphan
     * analysis, whose bound says which orphans they hold, and before the scan,
     * whose discoveries follow them */
    err = workspace_list(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to list the diverged items");
    }

    /* Optional: new files beneath the tracked directories */
    if (opts->analyze_untracked) {
        err = workspace_analyze_untracked(ws, config);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze untracked files");
        }
    }

    *out = ws;
    return NULL;
}

/**
 * The diverged items
 */
workspace_items_t workspace_diverged(const workspace_t *ws) {
    if (!ws) {
        return (workspace_items_t) { 0 };
    }

    return workspace_items(&ws->diverged);
}

/**
 * The active items, both kinds, in their order
 *
 * The cast adds const at both pointer levels (T ** → const T *const *) — legal
 * per the C standard's qualifier-conversion rule, no diagnostic required: the
 * workspace writes its items, and a reader only reads them. Each kind's slice
 * below casts the same way.
 */
workspace_items_t workspace_active(const workspace_t *ws) {
    if (!ws) return (workspace_items_t){ 0 };
    return (workspace_items_t){
        .entries = (const workspace_item_t *const *) ws->active,
        .count = ws->dir_count + ws->file_count,
    };
}

/**
 * The file items: the active items from the first file's, in their order
 */
workspace_items_t workspace_files(const workspace_t *ws) {
    if (!ws) return (workspace_items_t){ 0 };
    return (workspace_items_t){
        .entries = (const workspace_item_t *const *) (ws->active + ws->dir_count),
        .count = ws->file_count,
    };
}

/**
 * The directory items: the active items' prefix, in their order
 */
workspace_items_t workspace_directories(const workspace_t *ws) {
    if (!ws) return (workspace_items_t){ 0 };
    return (workspace_items_t){
        .entries = (const workspace_item_t *const *) ws->active,
        .count = ws->dir_count,
    };
}

/**
 * The managed item at a path, or NULL
 */
const workspace_item_t *workspace_find(
    const workspace_t *ws,
    const char *filesystem_path
) {
    if (!ws || !filesystem_path) {
        return NULL;
    }

    /* An active path's item, the clean ones too; else an orphan's, of the prefix
     * the load analyzed — every orphan or none, the bound the diverged items
     * list by (analyzed_count). No path is both: a record is an orphan exactly
     * where no active item stands (workspace_partition). */
    const workspace_item_t *item = workspace_find_active(ws, filesystem_path);

    return item ? item : workspace_find_item(ws->orphans, ws->analyzed_count, filesystem_path);
}

/**
 * The squatted directory above `path`, or NULL — the view's claims
 */
const workspace_squatted_t *workspace_squatted_ancestor(
    const workspace_t *ws,
    const char *path
) {
    if (!ws || !path) {
        return NULL;
    }

    /* The view-only face of the one scan (squatted_ancestor), lent whole: a
     * record's memory reaches the orphans alone, which carry the fact themselves
     * (the reach rule, workspace_displaced_t), and this probe's askers need the
     * squatter itself, which no item carries. */
    return squatted_ancestor(ws, path, false);
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

    /* Git moved past what dotta last reconciled — the bytes (STALE) or a claim
     * (CLAIM_MOVED) — and disk did not follow: a real edit beside it means both
     * sides moved; alone — the user's own claims riding included, since a claim
     * is never an edit — it is apply's to bring */
    if (divergence & (DIVERGENCE_STALE | DIVERGENCE_CLAIM_MOVED)) {
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

    return workspace_reassigned(item->row, item->anchor, item->occupant)
           ? WORKSPACE_ROUTE_REASSIGNED
           : WORKSPACE_ROUTE_CLEAN;
}

/**
 * An item's tags: the words its line carries, their colour, and whose it is
 */
bool workspace_item_tags(
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
            if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
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
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                    tags_out[tag_count++] = "unencrypted";
                }
                *color_out = OUTPUT_COLOR_MAGENTA;
            }

            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;

        case WORKSPACE_STATE_DELETED:
            if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                tags_out[tag_count++] = "deleted";
            }
            *color_out = OUTPUT_COLOR_RED;

            /* A pending reassignment shows on a deleted path too: the record
             * still names the profile that deployed the copy, and apply's redeploy
             * from the new owner is what acknowledges it — the same pair the
             * DEPLOYED arm prints. */
            if (workspace_reassigned(item->row, item->anchor, item->occupant)) {
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
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
            if (workspace_item_route(item) == WORKSPACE_ROUTE_CLEAN) {
                /* Nothing diverged, which only status's full listing renders
                 * (cmds/status.c status_print_manifest). What a row can agree
                 * with is its class's to say. A tracked row was compared and
                 * agreed: clean. An ancestor claim was compared with nothing —
                 * its mode and ownership say what to create the path as, never
                 * what to make of the one this machine has, so the directory
                 * analysis stops at the type question — and [clean], which promises
                 * that nothing diverged, would be a promise dotta never checked.
                 * A row beneath a squatter never reaches this arm at all: nothing
                 * there was looked at, so its route is the squatter's
                 * (workspace_displaced_t), and neither word could be honest of
                 * it. */
                if (manifest_is_derived(item->row)) {
                    if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                        tags_out[tag_count++] = "ancestor";
                    }
                    *color_out = OUTPUT_COLOR_DIM;
                } else {
                    if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                        tags_out[tag_count++] = "clean";
                    }
                    *color_out = OUTPUT_COLOR_GREEN;
                }

                snprintf(metadata_buf, metadata_size, "from %s", item->profile);
                break;
            }

            if (item->displaced != WORKSPACE_DISPLACED_NONE) {
                /* Beneath a squatter (workspace_displaced_t): nothing here was
                 * looked at, so the item carries no path bit — and a tag read
                 * off a look nobody took would name work no verb takes. The path's
                 * one tag, at the default colour: the squatter's own row carries
                 * the path's severity, and the route lists this item under it.
                 * What no look decides or disproves still rides below: the blob's
                 * verdict, and the reassignment — which a look ends across kinds,
                 * and none was taken here. */
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                    tags_out[tag_count++] = "displaced";
                }
            } else {
                /* Primary tag based on most severe divergence
                 *
                 * Priority order (by severity):
                 *   TYPE > CONTENT > STALE/CLAIM_MOVED > MODE/OWNERSHIP/ENCRYPTION
                 */
                if (item->divergence & DIVERGENCE_TYPE) {
                    if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                        tags_out[tag_count++] = "type";
                    }
                    *color_out = OUTPUT_COLOR_RED;
                } else if (item->divergence & DIVERGENCE_CONTENT) {
                    if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                        tags_out[tag_count++] = "modified";
                    }
                    /* Keep default YELLOW color */
                }

                if (item->divergence & (DIVERGENCE_STALE | DIVERGENCE_CLAIM_MOVED)) {
                    /* Git moved past what dotta last reconciled — the bytes or
                     * a claim, one tag for either: the axis tags beside it say
                     * what differs, not who moved each, since apply converges
                     * them alike. Alone it is apply-side work — the same CYAN
                     * as [undeployed], none of the user's bytes is overwritten;
                     * next to [modified] it names a conflict and the primary
                     * tag's colour stands. */
                    if (tag_count == 0) {
                        *color_out = OUTPUT_COLOR_CYAN;
                    }
                    if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                        tags_out[tag_count++] = "stale";
                    }
                }

                /* Secondary tags: the claim axes that differ
                 *
                 * MODE: Skip if TYPE divergence present (type change makes mode
                 *       irrelevant) The condition !((item->divergence &
                 *       DIVERGENCE_TYPE) && tag_count > 0) prevents MODE from
                 *       showing when TYPE is the primary tag
                 * OWNERSHIP: Always show if present
                 */
                if ((item->divergence & DIVERGENCE_MODE) &&
                    !((item->divergence & DIVERGENCE_TYPE) && tag_count > 0)) {
                    if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                        tags_out[tag_count++] = "mode";
                    }
                }

                if (item->divergence & DIVERGENCE_OWNERSHIP) {
                    if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                        tags_out[tag_count++] = "ownership";
                    }
                }
            }

            /* The blob's verdict, on either arm: Git's alone, so no look decides
             * it and it rides beside [displaced] too — the row is written fresh
             * once the squatter goes, so this may be the last screen before it
             * lands, as on an UNDEPLOYED row. Upgrade color to MAGENTA if still
             * the default (not TYPE divergence): encryption issues get their
             * own treatment, the displaced line's included. */
            if (item->divergence & DIVERGENCE_ENCRYPTION) {
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                    tags_out[tag_count++] = "unencrypted";
                }
                if (*color_out == OUTPUT_COLOR_YELLOW) {
                    *color_out = OUTPUT_COLOR_MAGENTA;
                }
            }

            /* The failed look, worded by whose remedy it is (workspace_fault_t)
             * — the same word the orphaned arm below prints, so one path has
             * one name wherever it is listed. A displaced item took no look, so
             * it never carries one. Conservative handling downstream (update
             * refuses it, apply skips it at preflight, cleanup skips the
             * orphan). */
            if (item->divergence & DIVERGENCE_UNVERIFIED) {
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
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

            /* Profile reassignment tag (can coexist with divergence tags, and
             * with [displaced]: the record against the row, and across kinds
             * against the item's look — workspace_reassigned)
             *
             * Added after divergence tags as secondary information. Color only
             * set for pure reassignment (sole tag) to avoid overriding
             * severity-based colors from divergence. */
            if (workspace_reassigned(item->row, item->anchor, item->occupant)) {
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
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
            if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
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
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
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
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                    tags_out[tag_count++] = "displaced";
                }
                *color_out = OUTPUT_COLOR_MAGENTA;

            } else if (item->divergence & DIVERGENCE_UNVERIFIED) {
                /* The failed look, worded by whose remedy it is (workspace_fault_t)
                 * — the deployed arm's switch, so one item has one name in both.
                 * Conservative: apply skips it (CLEANUP_SKIP_UNVERIFIED, ranked
                 * first there as it is here — one item, one name). */
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
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
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                    tags_out[tag_count++] = "type";
                }
                *color_out = OUTPUT_COLOR_RED;

            } else if (item->divergence & DIVERGENCE_CONTENT) {
                /* Content divergence - blocking issue Apply skips it
                 * (cleanup_skip_reason: MODIFIED). */
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                    tags_out[tag_count++] = "modified";
                }
                *color_out = OUTPUT_COLOR_RED;

            } else if (item->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
                /* The claim alone — the mode, the ownership, or both — left the
                 * one the record reconciled; the content is dotta's. Warning
                 * level: apply skips it (cleanup_skip_reason: CLAIM_CHANGED). */
                if (item->divergence & DIVERGENCE_MODE) {
                    if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                        tags_out[tag_count++] = "mode";
                    }
                }
                if (item->divergence & DIVERGENCE_OWNERSHIP) {
                    if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
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
             * tags (the way [reassigned] rides on DEPLOYED): the claim the record
             * remembers still has a row, projected elsewhere. Whether there is
             * one at all is the class against NONE, here as at every screen
             * (workspace.h). The fate stays cleanup's, and turns on which class
             * it is (a
             * re-targeted custom/ copy prunes, a moved home holds behind --force);
             * this only names what the copy is. */
            if (item->relocation != WORKSPACE_RELOCATION_NONE) {
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                    tags_out[tag_count++] = "relocated";
                }
            }

            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;
        }

        case WORKSPACE_STATE_UNTRACKED:
            if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                tags_out[tag_count++] = "new";
            }
            *color_out = OUTPUT_COLOR_CYAN;
            snprintf(metadata_buf, metadata_size, "in %s", item->profile);
            break;

        case WORKSPACE_STATE_RELEASED:
            /* Released from management — Git let the claim go, dotta never deployed
             * it, another kind of path stands in its place, or a row stands on
             * its very entry under another spelling of its path. The path is
             * left on disk, the record retires. Always present: the orphan analysis
             * decides presence first, so an absent record never reaches this
             * state. */
            if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                tags_out[tag_count++] = "released";
            }
            *color_out = OUTPUT_COLOR_MAGENTA;

            if (item->divergence & DIVERGENCE_TYPE) {
                /* The third reason, named: a directory where dotta's file was,
                 * or a file, a link, a device where dotta's directory was. */
                if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
                    tags_out[tag_count++] = "type";
                }
            }

            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;

        default:
            /* Unknown state - defensive fallback Should never happen in normal
             * operation, but handle gracefully */
            if (tag_count < WORKSPACE_ITEM_MAX_TAGS) {
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
 * Observe the directories standing where their records describe another kind of
 * node
 *
 * The rule is the header's. Here: the directory items are read, each with its
 * look and its record, and each record found wanting retires before its observation
 * is written, so the INSERT lands — the run's transaction was taken before the
 * load read the record, and nothing else writes inside it. The observation is
 * written into the record the path's item already holds: one object rewritten
 * in place, as workspace_anchor advances one — const to every reader, and cast
 * here, where it is written (workspace_item_t).
 */
error_t *workspace_observe_retyped(workspace_t *ws) {
    CHECK_NULL(ws);

    for (size_t i = 0; i < ws->dir_count; i++) {
        const workspace_item_t *item = ws->active[i];
        const manifest_row_t *row = item->row;
        const anchor_t *anchor = item->anchor;

        /* A directory standing: the row's own kind, found by the load's look at
         * the path. A look withheld or failed saw nothing stand, and absence or
         * another kind of node is not the row's. */
        if (item->occupant != FS_OCCUPANT_DIRECTORY) continue;

        /* Over a record of another kind: that record's node is gone */
        if (!anchor ||
            workspace_compare_confirmed(row, anchor->type, &anchor->blob_oid) != CMP_TYPE_DIFF) {
            continue;
        }

        /* The record retires, its base kept, and the directory is observed in
         * its place */
        error_t *err = state_retire_anchor(ws->state, row->filesystem_path);
        if (!err) {
            err = state_observe(ws->state, row, (anchor_t *) anchor);
        }
        if (err) {
            return error_wrap(
                err, "Failed to observe '%s' in its record's place", row->filesystem_path
            );
        }
    }

    return NULL;
}

/**
 * Anchor an active path with in-memory consistency
 *
 * The workspace-scope writer for ownership events: hands state_anchor the item's
 * row and the record the item holds, or one the item gains. The statement is
 * the one specification of what an ownership event writes, and checks the row;
 * this function holds none of it and reads nothing of the row. Either arm leaves
 * item->anchor the live record.
 */
error_t *workspace_anchor(
    workspace_t *ws,
    const workspace_item_t *item,
    const stat_cache_t *stat,
    time_t now
) {
    CHECK_NULL(ws);
    CHECK_NULL(item);

    /* The record the item holds, advanced in place: every holder of the item
     * reads the post-write record through the pointer it already holds. Const
     * to every reader, and cast here, where it is written (workspace_item_t). */
    if (item->anchor) {
        return state_anchor(ws->state, item->row, stat, now, (anchor_t *) item->anchor);
    }

    /* An item holding none: its record allocated before the statement, so a write
     * that landed is never followed by a failure to hold it, and the item's after
     * it — the item cast here, where it gains the record, as the record is where
     * it is advanced (workspace_item_t). */
    anchor_t *anchor = arena_alloc(ws->arena, sizeof(*anchor));
    if (!anchor) {
        return ERROR(ERR_MEMORY, "Failed to allocate anchor record");
    }

    error_t *err = state_anchor(ws->state, item->row, stat, now, anchor);
    if (err) return err;

    ((workspace_item_t *) item)->anchor = anchor;
    return NULL;
}

/**
 * Confirm an active path with in-memory consistency
 *
 * Workspace-scope writer for confirmations: the item's record is the one both
 * verbs are handed, so each advances it in place when its statement wrote, and
 * every holder of the item reads the same. No record is created here — a
 * confirmation is an UPDATE of what the load or the flush's observation made.
 */
error_t *workspace_confirm(
    workspace_t *ws,
    const workspace_item_t *item,
    divergence_type_t axes
) {
    CHECK_NULL(ws);
    CHECK_NULL(item);

    /* The row the axes were established against, read below for the claim's values
     * before any verb could check it: an orphan's item has none. */
    const manifest_row_t *row = item->row;
    CHECK_NULL(row);

    /* The item's record: the load's, or the one the flush's observation made.
     * Const to every reader, and cast here, where it is written
     * (workspace_item_t). */
    anchor_t *anchor = (anchor_t *) item->anchor;

    /* The content, under the row's binding (state_confirm), proven by the triple
     * the load distilled where its comparison stood (workspace_item_t's proof).
     * Either statement may run first: each binds the record as the snapshot holds
     * it and advances the snapshot when it writes, so the type the content writes
     * within its kind is the type the claim's then binds. */
    if (axes & DIVERGENCE_CONTENT) {
        error_t *err = state_confirm(ws->state, row, &item->proof, anchor);
        if (err) return err;
    }

    if (!(axes & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP))) {
        return NULL;
    }

    /* The claim, under no binding (state_confirm_claim): the row's on each axis
     * named, the record's own on the other — a value per column, the strings
     * borrowed from the row as the other two writers borrow them. */
    return state_confirm_claim(
        ws->state,
        (axes & DIVERGENCE_MODE) ? row->mode : anchor->mode,
        (axes & DIVERGENCE_OWNERSHIP) ? row->owner : anchor->owner,
        (axes & DIVERGENCE_OWNERSHIP) ? row->group : anchor->group,
        anchor
    );
}

/**
 * Write what the load owes the record
 *
 * The rule is the header's. Here: one walk over the active items — the paths
 * the view holds, where every debt stands; not the orphans, since the path back
 * in the view is exactly the case with no orphan — each written whole: its
 * observation, then its confirmation, then its void, so a path is observed before
 * it is confirmed, the one order the writes need: a confirmation is an UPDATE
 * that creates nothing, and one cannot confirm what one has not seen. Across
 * paths the order is free, every statement keyed by its own path and reading no
 * other. The first write takes the transaction where the caller holds none, so
 * a load that owes nothing takes none.
 */
error_t *workspace_flush(workspace_t *ws) {
    CHECK_NULL(ws);

    bool scoped = false;
    error_t *err = NULL;

    for (size_t i = 0; i < ws->dir_count + ws->file_count; i++) {
        workspace_item_t *item = ws->active[i];

        /* Owed nothing: a record the load learned nothing new of, standing on
         * no order; or no record, and no node of the row's own kind to observe
         * — nothing stands, another kind does, or no look was taken (withheld
         * beneath a squatter, failed, or retracted by a read that met absence).
         * A confirmation rides the observation: a content confirmation is noted
         * only where the row's kind stands (the ladder's first rung, and the
         * proof's), and a claim is learned only onto a record
         * (workspace_claims_moved), so a path skipped here is owed no confirmation
         * either. */
        if (item->anchor && item->confirmation == DIVERGENCE_NONE &&
            item->anchor->ordered_at == 0) {
            continue;
        }
        if (!item->anchor && item->occupant != workspace_type_occupant(item->row->type)) {
            continue;
        }

        /* The first write takes the store's lock where the caller holds none —
         * status, diff, sync, update and a preview of apply — and the flush owns
         * that transaction; a run of apply passes its dispatch transaction, and
         * the writes land in it (state_locked). Taken here, at a write, so a
         * load that owes nothing never waits on another writer's lock, nor brings
         * the store into being where none was (state_begin). */
        if (!state_locked(ws->state)) {
            err = state_begin(ws->state);
            if (err) {
                return error_wrap(err, "Failed to begin flush transaction");
            }
            scoped = true;
        }

        /* The observation: presence of the row's own kind, the path's first record,
         * file and directory rows alike and either class of directory — the record
         * answers whether dotta has seen the path for an ancestor claim too
         * (classify_absent). It closes the "user created the path after scope
         * entry" gap: the next absence reads DELETED, not UNDEPLOYED, and update
         * propagates the user's removal. A node of another kind is no observation:
         * the record would name the row's kind, which classify_absent reads as
         * the node dotta saw here, and the user removing what they put in its
         * place would read as the claim's deletion.
         *
         * The record is allocated before the statement, so a write that landed
         * is never followed by a failure to hold it, and state_observe writes
         * into it the INSERT's own values — the row's binding, kind and claim,
         * the strings borrowed from the row for the workspace's lifetime — whether
         * the INSERT landed or met a row another writer made since the load:
         * never that row, which is state_observe's rule and its reason. The item
         * holds it from here on, the live record every later reader in the run
         * reads off the item (cmds/apply.c cmd_apply's adoption test). A path
         * whose item holds a record is owed none, as the statement's DO NOTHING
         * leaves one standing: observation is idempotent on both sides. What
         * reads a record after a read command's flush asks it about ownership
         * alone — status's header, diff's reassignment, a preview's adoption
         * test — and a record never owned answers as none does; a run of apply
         * cannot meet an ignored INSERT at all, its load and its flush sharing
         * one transaction. */
        if (!item->anchor) {
            anchor_t *anchor = arena_alloc(ws->arena, sizeof(*anchor));
            err = anchor ? state_observe(ws->state, item->row, anchor)
                         : ERROR(ERR_MEMORY, "Failed to allocate observation record");
            if (err) {
                err = error_wrap(
                    err, "Failed to flush observation for '%s'", item->filesystem_path
                );
                goto rollback;
            }
            item->anchor = anchor;
        }

        /* The confirmation, onto the record the look was made against — the load's,
         * or the observation's a statement ago — and only where the database
         * still holds it (workspace_confirm): a record another writer moved since
         * the load stays theirs, and this one as read. Cleared once written,
         * landed or not: the load owes the record nothing more of it. */
        if (item->confirmation != DIVERGENCE_NONE) {
            err = workspace_confirm(ws, item, item->confirmation);
            if (err) {
                err = error_wrap(
                    err, "Failed to flush confirmation for '%s'", item->filesystem_path
                );
                goto rollback;
            }
            item->confirmation = DIVERGENCE_NONE;
        }

        /* The void: the order's view end (state.h's lifetime rule), here because
         * the view is. An order lives only while its path is out of the view,
         * so every order whose path the view has is void — the removal it answered
         * was reverted (a revert, a sync pulling the path back, an enable providing
         * it), verified or not. Left standing, the order would outlive the removal
         * and prune the copy at the next scope exit instead of the probe releasing
         * it; voided here, a later discovered departure executes as a release,
         * which is the stated policy for every discovered departure.
         *
         * Selected from the record the load read — the active items' own: an
         * ownership event writes the order away and an observation is made with
         * none, so a record a writer made or advanced since carries no order to
         * void — and voided on the order it read (state_void_prune): an order
         * placed since the load answers a removal this load's view predates,
         * and voiding it would undo the removal's intent — the compare-and-swap
         * leaves it standing. The record is the item's, const to every reader,
         * and cast here, where it is written (workspace_item_t). */
        if (item->anchor->ordered_at > 0) {
            err = state_void_prune(ws->state, (anchor_t *) item->anchor);
            if (err) {
                err = error_wrap(
                    err, "Failed to void prune order for '%s'", item->filesystem_path
                );
                goto rollback;
            }
        }
    }

    /* The transaction the flush took, committed: every write it owed landed in
     * it or found its record moved. One the caller holds is the caller's to
     * commit. */
    if (scoped) {
        err = state_commit(ws->state);
        if (err) {
            err = error_wrap(err, "Failed to commit flush transaction");
            goto rollback;
        }
    }

    return NULL;

rollback:
    /* A failure rolls back the transaction the flush took — a failed COMMIT's
     * too, which leaves it open, so the next scoped writer does not inherit it.
     * One the caller holds is the caller's to end: the failure is its run's. */
    if (scoped) {
        state_rollback(ws->state);
    }
    return err;
}

/**
 * Free workspace
 */
void workspace_free(workspace_t *ws) {
    if (!ws) {
        return;
    }

    /* Free the diverged items' array (the items and their strings are arena-backed) */
    ptr_array_deinit(&ws->diverged);

    /* The view is borrowed (the dispatcher's); the items, their arrays, the record
     * and the squatted list are arena-allocated and the caller's arena releases
     * them when destroyed. ws->arena is borrowed — never destroyed here. */

    free(ws);
}
