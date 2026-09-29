/**
 * cleanup.c - Orphaned file and directory pruning: plan / preflight / execute
 *
 * See cleanup.h for the contract. Orphan detection, Git authority and divergence
 * are the workspace's; this module decides which orphans the run may touch, what
 * becomes of each, and carries that out.
 *
 * The verdict re-verifies nothing and touches neither disk, Git nor state — every
 * input is a field of the workspace item, written once at load, and no vocabulary
 * of a lower layer is read to interpret one. Preflight takes two looks past it,
 * neither a property any earlier phase could have recorded: the readdir, because
 * what is left in a directory after this run's removals is decided by this run;
 * and the parent's reach, because whether this run may make a removal is a fact
 * about the run, not the item.
 */

#include "core/cleanup.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/scope.h"
#include "core/workspace.h"
#include "sys/filesystem.h"

/* ══════════════════════════════════════════════════════════════════
 * Plan
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Build the cleanup plan
 */
cleanup_plan_t *cleanup_plan_build(
    arena_t *arena,
    const workspace_t *ws,
    const scope_t *scope,
    bool keep_orphans
) {
    CHECK_NULL(arena);
    CHECK_NULL(ws);
    CHECK_NULL(scope);

    /* The plan and its three buckets are the arena's, beside the items they borrow,
     * and nothing frees a plan. */
    cleanup_plan_t *plan = arena_calloc(arena, 1, sizeof(*plan));

    /* --keep-orphans: nothing is planned, by request. The empty plan — three
     * empty buckets — is what every later stage reads, so no stage re-encodes
     * the flag. */
    if (keep_orphans) {
        return plan;
    }

    /* Each orphan in scope is added to its bucket as the walk decides it, and
     * the three are filled once the walk is done. */
    workspace_items_t items = workspace_diverged(ws);
    workspace_buckets_t *buckets = workspace_buckets_create(arena);

    for (size_t i = 0; i < items.count; i++) {
        const workspace_item_t *item = items.entries[i];

        /* Both kinds reach both states: the kind decides the bucket, the state
         * is a verdict's input. */
        if (item->state != WORKSPACE_STATE_ORPHANED &&
            item->state != WORKSPACE_STATE_RELEASED) {
            continue;
        }

        /* Coherent Scope principle: the same operation-scope triplet the deploy
         * planner applies. Profile / path dimensions reject silently — the orphan
         * is outside the user's declared operation scope. */
        if (!scope_accepts_profile(scope, item->profile) ||
            !scope_accepts_path(
            scope, item->filesystem_path, item->storage_path, item->item_kind
            )) {
            continue;
        }

        /* Exclude dimension: spared, reported by the caller, never touched. */
        if (scope_is_excluded(scope, item->storage_path, item->item_kind)) {
            workspace_buckets_add(buckets, item, &plan->excluded);
        } else if (item->item_kind == PATH_KIND_DIRECTORY) {
            workspace_buckets_add(buckets, item, &plan->directories);
        } else {
            workspace_buckets_add(buckets, item, &plan->files);
        }
    }

    workspace_buckets_fill(buckets);
    return plan;
}

/* ══════════════════════════════════════════════════════════════════
 * Verdicts
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Map an orphaned file's divergence to the reason it is skipped
 *
 * The table and its rationale are in cleanup.h — kept in one place, where a caller
 * reading the enum finds them.
 */
cleanup_skip_reason_t cleanup_skip_reason(const workspace_item_t *item) {
    divergence_type_t divergence = item->divergence;

    /* DIVERGENCE_UNVERIFIED: Verification failed */
    if (divergence & DIVERGENCE_UNVERIFIED) {
        return CLEANUP_SKIP_UNVERIFIED;
    }

    /* A shared relocation: the claim now lands in a namespace nobody re-targets,
     * so the copy here is the claim's old home. The same test as cleanup_verdict's
     * relocation arm, its one input in hand; a re-targeted custom/ copy is the
     * other class and never trips it. */
    if (item->relocation == WORKSPACE_RELOCATION_SHARED) {
        return CLEANUP_SKIP_RELOCATED;
    }

    /* DIVERGENCE_CONTENT: disk differs from what dotta deployed */
    if (divergence & DIVERGENCE_CONTENT) {
        return CLEANUP_SKIP_MODIFIED;
    }

    /* DIVERGENCE_TYPE: File type changed (file <-> symlink) */
    if (divergence & DIVERGENCE_TYPE) {
        return CLEANUP_SKIP_TYPE_CHANGED;
    }

    /* DIVERGENCE_MODE or DIVERGENCE_OWNERSHIP: the claim — the mode, the ownership,
     * or both */
    if (divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
        return CLEANUP_SKIP_CLAIM_CHANGED;
    }

    /* All priority flags handled above. Remaining flags:
     * - ENCRYPTION: never emitted for an orphan (the blob bit is computed over
     *   the view's rows, and an orphan is exactly a record the view lacks) —
     *   listed so it cannot block
     * - STALE, CLAIM_MOVED: never emitted for an orphan (workspace_compare_orphan
     *   asks one question, of disk alone; who moved a claim is asked of a row,
     *   and an orphan has none) — listed so they cannot block
     * Unknown flags: block removal until explicitly handled above. */
    static const divergence_type_t known_flags = DIVERGENCE_CONTENT |
        DIVERGENCE_TYPE | DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP |
        DIVERGENCE_UNVERIFIED | DIVERGENCE_ENCRYPTION | DIVERGENCE_STALE |
        DIVERGENCE_CLAIM_MOVED;

    return (divergence & ~known_flags) ? CLEANUP_SKIP_UNVERIFIED
                                       : CLEANUP_SKIP_NONE;
}

/**
 * What becomes of a planned orphan, read off the item alone
 *
 * The table and its rationale are in cleanup.h. Every input is a fact the workspace
 * established once at load and left on the item — its occupant, state, displaced
 * class and divergence bits: no syscall.
 */
cleanup_verdict_t cleanup_verdict(const workspace_item_t *item, bool force) {
    if (item->occupant == FS_OCCUPANT_NONE) {
        /* Already gone: nothing to protect, nothing to remove — a pure state
         * reclaim whatever Git or the divergence bits say. Absence is an lstat's
         * answer about this path, which is why no record beneath a squatter reaches
         * here: none was looked at, so none is absent (core/workspace.h
         * workspace_displaced_t), and the arm below is the one they take. */
        return CLEANUP_ABSENT;
    }

    if (item->state == WORKSPACE_STATE_RELEASED) {
        /* Git no longer backs the path — the branch was deleted, the path was
         * removed from it — dotta never deployed it (the workspace's ownership
         * gate), or another kind of node stands in its place; the workspace's
         * load found it either way. The path stays on disk to protect the user's
         * data, and the record retires because dotta cannot manage what Git cannot
         * restore, and does not remove what it did not put there: it is released
         * from dotta's management, not pruned.
         *
         * Decided before --force is consulted: --force prunes what would be
         * skipped, never what is released. */
        return CLEANUP_RELEASED;
    }

    if (item->displaced != WORKSPACE_DISPLACED_NONE) {
        /* A squatter stands above the path: dotta's copy went with the real
         * directory, and nothing at the path was looked at — not dotta's to remove,
         * --force included, and a prune order on the path does not outrank it
         * (deferred intent never destroys what dotta cannot vouch is its copy).
         * The path stays, the record retires: the same letting-go as a retyped
         * path, one level up. Terminal on purpose — a skip would prune on the
         * NEXT run, once the squatted path's own record has gone, released or
         * pruned in this one, and no witness of the squat remains. */
        return CLEANUP_RELEASED;
    }

    /* The relocation skip, both kinds (the table in cleanup.h): the claim moved
     * under a namespace nobody re-targets (SHARED — home/; root/'s projection
     * is fixed and never gets here), which means $HOME itself differs, so the
     * copy is real dotfiles under the claim's real home. --force lifts it — the
     * escape for a deliberate home migration. */
    if (!force && item->relocation == WORKSPACE_RELOCATION_SHARED) {
        return CLEANUP_SKIPPED;
    }

    if (item->item_kind == PATH_KIND_DIRECTORY) {
        /* A directory the workspace could not stat or read is skipped whatever
         * --force says; otherwise the readdir finishes the verdict. */
        return (item->divergence & DIVERGENCE_UNVERIFIED) ? CLEANUP_SKIPPED
                                                          : CLEANUP_PRUNABLE;
    }

    return (!force && cleanup_skip_reason(item) != CLEANUP_SKIP_NONE)
        ? CLEANUP_SKIPPED : CLEANUP_PRUNABLE;
}

/**
 * Order two orphaned directories deepest first
 *
 * Descending path length, then ascending path so the order is total and the reports
 * are reproducible.
 */
static int cleanup_depth_order(const void *a, const void *b) {
    const char *pa = (*(const workspace_item_t *const *) a)->filesystem_path;
    const char *pb = (*(const workspace_item_t *const *) b)->filesystem_path;

    size_t la = strlen(pa);
    size_t lb = strlen(pb);

    if (la != lb) {
        return (la < lb) ? 1 : -1;
    }

    return strcmp(pa, pb);
}

/**
 * What an entry met beneath an orphaned directory amounts to, for that directory's
 * own verdict
 *
 * A directory's fate is the strongest class left in it once this run has acted:
 * nothing but gone entries and it is prunable; a skipped one and it is skipped
 * too, the same transient as that entry; a permanent one and it is released,
 * because nothing dotta will ever do empties it. Every present planned item records
 * its class as its verdict is taken, so a directory's walk reads its children's
 * fates off the set; FATE_UNPLANNED is hashmap_get's NULL — the entry is outside
 * the plan — and the workspace item says which of the other two it is
 * (vouch_entry).
 */
typedef enum {
    FATE_UNPLANNED = 0,
    FATE_GONE,        /* This run prunes it — the hole the walk looks through */
    FATE_SKIPPED,     /* This run skips it — transient: update, --force, root, or the run that reaches it */
    FATE_PERMANENT    /* This run releases it, or never touches it — nothing of dotta's comes back for it */
} fate_t;

/**
 * The emptiness walk's context: the fate set, the workspace for an entry outside
 * the plan, and whether a skipped entry was met on the way
 */
typedef struct {
    const hashmap_t *fates;     /* filesystem path → fate_t, every present planned item */
    const workspace_t *ws;
    bool skipped;
} walk_t;

/**
 * Look past this directory entry?
 *
 * The vouch predicate of the verdict phase's emptiness walk. Gone and skipped
 * entries are looked past — a skipped one noted, because the directory then waits
 * with it — and a permanent one stops the walk: the directory is occupied by
 * something this run will not remove and no later run will either.
 *
 * An entry outside the plan is read off the item the load holds at its path
 * (workspace_find). ORPHANED is skipped: the scope did not reach it this run
 * (-e, -p, a path filter), an unfiltered run would decide it, and scope decides
 * reach, never verdict — so a filtered run must not change its parent's fate.
 * Everything else is permanent: a RELEASED orphan stays where it is; an active
 * path (the view has a row, and a row's item is never an orphan's) stands in an
 * enabled profile's name; an entry the load holds no item for is the user's.
 *
 * Membership is keyed by filesystem path, which is why the entry arrives as a
 * full path rather than a basename.
 */
static bool vouch_entry(const char *child, void *ctx) {
    walk_t *walk = ctx;
    fate_t fate = (fate_t) (uintptr_t) hashmap_get(walk->fates, child);

    if (fate == FATE_UNPLANNED) {
        const workspace_item_t *item = workspace_find(walk->ws, child);

        fate = (item && item->state == WORKSPACE_STATE_ORPHANED) ? FATE_SKIPPED
                                                                 : FATE_PERMANENT;
    }

    if (fate == FATE_SKIPPED) {
        walk->skipped = true;
    }

    return fate != FATE_PERMANENT;
}

/**
 * Does the view claim a path beneath this directory?
 *
 * An active path beneath an orphaned directory makes the directory the ancestor
 * of an enabled row — one ensure_parents would make anyway — and nothing dotta
 * does empties it: permanent, whether the row is on disk yet or not. The readdir
 * meets the rows already deployed (an active path's entry is permanent,
 * vouch_entry); this answers for the ones deployment will put there — this run,
 * or a later one that reaches them — which is exactly why the disk cannot answer
 * it. Read from the view, not from the deployment plan, so the answer does not
 * move with -p, -e or a path filter: scope decides reach, never verdict.
 *
 * Every directory above an active path is its ancestor, not just the immediate
 * parent: the ones deployment creates on the way count too.
 */
static bool cleanup_active_beneath(const workspace_t *ws, const char *dir) {
    size_t len = strlen(dir);
    workspace_items_t active = workspace_active(ws);

    for (size_t i = 0; i < active.count; i++) {
        if (str_path_beneath(active.entries[i]->filesystem_path, dir, len)) {
            return true;
        }
    }

    return false;
}

/**
 * May this run make the removal?
 *
 * unlink(2) and rmdir(2) ask nothing of the path itself: the entry is the parent's,
 * and write and search on the parent is the whole of the question (fs_eaccess,
 * with the reach — a run that holds root is never refused here). The parent is
 * the path's own, not the nearest present one deploy climbs to: a planned orphan
 * is present, so its parent is. Not asked, and met by the removal with its cause
 * instead: a sticky parent's owner rule, an immutable flag, a read-only mount,
 * and the OS-metadata entries fs_remove_empty_dir clears inside a directory whose
 * own write bit the invoker lacks. The one bound is the buffer's, and no boundary
 * makes it idle — the store refuses a key's shape, never its length — so a parent
 * that would not fit in PATH_MAX, the kernel's own bound on a path, reads as
 * admitted: the removal reports it.
 */
static bool parent_accepts_removal(const char *path) {
    size_t len = str_path_parent_len(path);
    char parent[PATH_MAX];

    if (len >= sizeof(parent)) {
        return true;
    }

    memcpy(parent, path, len);
    parent[len] = '\0';

    return fs_eaccess(parent, W_OK | X_OK);
}

/**
 * Decide the verdicts
 */
cleanup_preflight_t *cleanup_preflight(
    arena_t *arena,
    const workspace_t *ws,
    const cleanup_plan_t *plan,
    bool force
) {
    CHECK_NULL(arena);
    CHECK_NULL(ws);
    CHECK_NULL(plan);

    /* The verdicts and their ten buckets are the arena's, beside the items they
     * borrow, and nothing frees them. Neither pass reads a bucket — the directory
     * pass asks the fate set below — so each item is added to its bucket as its
     * verdict is taken, and the ten are filled once both passes are done: a bucket
     * nothing was added to is the empty slice, and needs no guard downstream. */
    cleanup_preflight_t *verdicts = arena_calloc(arena, 1, sizeof(*verdicts));
    workspace_buckets_t *buckets = workspace_buckets_create(arena);

    /* The fate of every present planned item, in one set: the directory pass
     * asks it about every entry it meets. Borrowed keys, all workspace-owned;
     * the values are fate_t, never NULL, so hashmap_get's NULL is "outside the
     * plan". The set is the arena's, as the verdicts are. */
    hashmap_t *fates = hashmap_borrow(
        arena, plan->files.count + plan->directories.count
    );

    /* One verdict per file, read off the item, then one probe for the ones it
     * cleared. An absent file joins neither the prune count nor the fate set:
     * no filesystem effect to preview, and no walk meets it. */
    for (size_t i = 0; i < plan->files.count; i++) {
        const workspace_item_t *item = plan->files.entries[i];
        fate_t fate = FATE_UNPLANNED;

        switch (cleanup_verdict(item, force)) {
            case CLEANUP_ABSENT:
                workspace_buckets_add(buckets, item, &verdicts->absent_files);
                break;

            case CLEANUP_RELEASED:
                workspace_buckets_add(buckets, item, &verdicts->released_files);
                fate = FATE_PERMANENT;
                break;

            case CLEANUP_SKIPPED:
                workspace_buckets_add(buckets, item, &verdicts->skipped_files);
                fate = FATE_SKIPPED;
                break;

            case CLEANUP_PRUNABLE:
                /* Nothing of its own in the way; the run's reach is the last
                 * rung, and a refusal leaves the file exactly as a skip does. */
                if (parent_accepts_removal(item->filesystem_path)) {
                    workspace_buckets_add(buckets, item, &verdicts->prunable_files);
                    fate = FATE_GONE;
                } else {
                    workspace_buckets_add(buckets, item, &verdicts->refused_files);
                    fate = FATE_SKIPPED;
                }
                break;
        }
        if (fate != FATE_UNPLANNED) {
            hashmap_set(fates, item->filesystem_path, (void *) (uintptr_t) fate);
        }
    }

    /* The directories deepest first, sorted here once, on a copy of the pass's
     * own: a child's path is its parent's plus a separator and a name, so it is
     * strictly longer, and descending length decides every directory after all
     * of those beneath it — two paths of one length are never parent and child.
     * The pass whose correctness rests on the order establishes it, rather than
     * borrow the plan's (the workspace's) or the state layer's ORDER BY
     * filesystem_path beneath that, which a producer two layers away is free to
     * change. At a count of zero the arena still answers a place of its own,
     * which is all qsort asks of an empty base. */
    size_t dir_count = plan->directories.count;
    const workspace_item_t **dirs = arena_calloc(arena, dir_count, sizeof(*dirs));

    for (size_t i = 0; i < dir_count; i++) dirs[i] = plan->directories.entries[i];
    qsort(dirs, dir_count, sizeof(*dirs), cleanup_depth_order);

    /* A directory's verdict is the strongest class left in it once this run has
     * acted (fate_t): prunable when everything in it is OS metadata or gone;
     * skipped while something skipped is left; released once something permanent
     * is. That is what the prune arrives at by acting, read here in one pass —
     * no second look, no iterating to a fixpoint: a directory's own fate enters
     * the set as it is decided, which is what lets a parent read each child's
     * class off the set — its pruned children gone, its skipped ones skipped,
     * its released ones permanent.
     *
     * Each is added to its bucket in walk order, so every directory bucket holds
     * its items deepest first. */
    for (size_t i = 0; i < dir_count; i++) {
        const workspace_item_t *item = dirs[i];
        const char *path = item->filesystem_path;
        fate_t fate = FATE_UNPLANNED;

        switch (cleanup_verdict(item, force)) {
            case CLEANUP_ABSENT:
                /* A pure state reclaim: no filesystem effect to preview, and no
                 * walk meets it. */
                workspace_buckets_add(buckets, item, &verdicts->absent_dirs);
                break;

            case CLEANUP_RELEASED:
                /* Left alone — unprobed, because nothing about its contents changes
                 * the answer — and the record retires. */
                workspace_buckets_add(buckets, item, &verdicts->released_dirs);
                fate = FATE_PERMANENT;
                break;

            case CLEANUP_SKIPPED:
                /* The workspace could not verify it; the directory above it waits
                 * with it. */
                workspace_buckets_add(buckets, item, &verdicts->skipped_dirs);
                fate = FATE_SKIPPED;
                break;

            case CLEANUP_PRUNABLE:
                /* A directory the workspace saw and can read (the occupant is
                 * DIRECTORY: anything else in its place was released above).
                 * What is left in it after this run, and then the run's reach,
                 * finish the verdict. An active path beneath it is known from
                 * the view before any look at the disk; otherwise one readdir,
                 * which stops at the first permanent entry and notes any skipped
                 * one it passed. UNREADABLE is a directory that was readable at
                 * load and is not now — the world moved, and it is skipped like
                 * a refusal on removal, not released. */
                if (cleanup_active_beneath(ws, path)) {
                    fate = FATE_PERMANENT;
                } else {
                    walk_t walk = { .fates = fates, .ws = ws, .skipped = false };

                    switch (fs_directory_emptiness(path, vouch_entry, &walk)) {
                        case FS_DIR_OCCUPIED:   fate = FATE_PERMANENT;
                            break;
                        case FS_DIR_UNREADABLE: fate = FATE_SKIPPED;
                            break;
                        case FS_DIR_EMPTY:      fate = walk.skipped ? FATE_SKIPPED : FATE_GONE;
                            break;
                    }
                }

                if (fate == FATE_GONE && !parent_accepts_removal(path)) {
                    /* Nothing but gone entries left, and not this run's to remove:
                     * skipped, as a refused file is, for the run that holds root.
                     * Asked last, of what the run would otherwise remove, so a
                     * directory a permanent entry keeps is released whoever owns
                     * its parent. */
                    workspace_buckets_add(buckets, item, &verdicts->refused_dirs);
                    fate = FATE_SKIPPED;
                } else {
                    workspace_items_t *slice = (fate == FATE_GONE) ? &verdicts->prunable_dirs
                                             : (fate == FATE_SKIPPED) ? &verdicts->skipped_dirs
                                                                      : &verdicts->released_dirs;
                    workspace_buckets_add(buckets, item, slice);
                }
                break;
        }
        if (fate != FATE_UNPLANNED) {
            /* Its parent must read it when its own turn comes. */
            hashmap_set(fates, path, (void *) (uintptr_t) fate);
        }
    }

    workspace_buckets_fill(buckets);
    return verdicts;
}

/* ══════════════════════════════════════════════════════════════════
 * Outcomes
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Carry the verdicts out
 *
 * Acts on prunable_files and prunable_dirs alone — the fates it does not touch
 * stay the verdicts', where they were decided (cleanup.h). Data-loss prevention
 * happened at preflight, in cleanup_skip_reason and the released test; nothing
 * is re-checked here and nothing pretends to be.
 *
 * Files first, then the directories those files emptied, deepest first, in the
 * verdicts' order (the preflight's): every child's turn comes before its parent's,
 * so a parent this run empties is seen empty when its own comes — the whole reason
 * the old iterate-until-stable loop existed.
 *
 * fs_remove_empty_dir is the mechanism and also the guard: it clears the OS
 * metadata the prediction looked past and nothing else, and it refuses — before
 * touching anything — the moment it meets an entry it may not remove. So an entry
 * that arrived while the prompt waited, or a child whose own removal failed above,
 * stops the removal instead of going with it. That refusal is the "not empty"
 * verdict by another route — ERR_CONFLICT — not a failure.
 *
 * Both probes run again here even though the verdicts are taken, because the
 * mechanisms cannot tell the receipt what they found: fs_remove_file and
 * fs_remove_empty_dir treat absence as success (an absent path would read "pruned",
 * not "reclaimed"), and rmdir on a symlink fails with ENOTDIR ("failed", not
 * "skipped"). One fs_lstat_occupant each — the workspace's probe, so a path reads
 * the same way at load and at removal.
 */
cleanup_receipt_t *cleanup_execute(arena_t *arena, const cleanup_preflight_t *verdicts) {
    CHECK_NULL(arena);
    CHECK_NULL(verdicts);

    cleanup_receipt_t *receipt = arena_calloc(arena, 1, sizeof(*receipt));

    /* The receipt is sized to the promise up front, in the arena the run names
     * — one slot per prunable item, zeroed, filled in act order as each removal
     * is attempted, the failed bucket to both kinds together — every promised
     * item could fail. count gates what a consumer reads, so an untaken slot is
     * invisible and the receipt holds exactly what happened. */
    receipt->pruned_files.entries = arena_calloc(
        arena, verdicts->prunable_files.count,
        sizeof(*receipt->pruned_files.entries)
    );
    receipt->reclaimed_files.entries = arena_calloc(
        arena, verdicts->prunable_files.count,
        sizeof(*receipt->reclaimed_files.entries)
    );
    receipt->pruned_dirs.entries = arena_calloc(
        arena, verdicts->prunable_dirs.count,
        sizeof(*receipt->pruned_dirs.entries)
    );
    receipt->reclaimed_dirs.entries = arena_calloc(
        arena, verdicts->prunable_dirs.count,
        sizeof(*receipt->reclaimed_dirs.entries)
    );
    receipt->skipped_dirs.entries = arena_calloc(
        arena, verdicts->prunable_dirs.count,
        sizeof(*receipt->skipped_dirs.entries)
    );
    receipt->failed.entries = arena_calloc(
        arena, verdicts->prunable_files.count + verdicts->prunable_dirs.count,
        sizeof(*receipt->failed.entries)
    );

    /* Step 1: Prune the orphaned files the verdicts cleared */
    for (size_t i = 0; i < verdicts->prunable_files.count; i++) {
        const workspace_item_t *item = verdicts->prunable_files.entries[i];
        const char *path = item->filesystem_path;

        /* Gone before we got here: no filesystem effect happened or was needed
         * — the record retires. Reporting it as "pruned" would claim an effect
         * that never occurred.
         *
         * The same probe the workspace took, so the two read one path one way:
         * a symlink row whose link now dangles is an object dotta deployed and
         * is here to remove, not an absence to reclaim around (stat would follow
         * the link, call it gone, retire the row and leave the link behind with
         * nothing left that knows about it); a path that cannot be stat'd is
         * not gone either — the unlink is attempted and reports its errno. */
        if (fs_lstat_occupant(path, NULL) == FS_OCCUPANT_NONE) {
            receipt->reclaimed_files.entries[receipt->reclaimed_files.count++].item = item;
            continue;
        }

        error_t remove_err = fs_remove_file(path);
        if (remove_err) {
            /* The item's own outcome; the cause already names its subject */
            cleanup_outcome_t *o = &receipt->failed.entries[receipt->failed.count++];

            o->item = item;
            o->error = remove_err;
            continue;
        }

        receipt->pruned_files.entries[receipt->pruned_files.count++].item = item;
    }

    /* Step 2: Prune the orphaned directories those files emptied */
    for (size_t i = 0; i < verdicts->prunable_dirs.count; i++) {
        const workspace_item_t *item = verdicts->prunable_dirs.entries[i];
        const char *path = item->filesystem_path;

        switch (fs_lstat_occupant(path, NULL)) {
            case FS_OCCUPANT_NONE:
                /* No filesystem effect happened or was needed — the record retires,
                 * nothing is removed. */
                receipt->reclaimed_dirs.entries[receipt->reclaimed_dirs.count++].item = item;
                continue;

            case FS_OCCUPANT_DIRECTORY:
                break;

            case FS_OCCUPANT_REGULAR:
            case FS_OCCUPANT_SYMLINK:
            case FS_OCCUPANT_OTHER:
            case FS_OCCUPANT_UNKNOWN:
                /* Replaced, or made unreachable, while the run waited: not ours
                 * to remove. The next load reads it as released [type], or as
                 * unverified. */
                receipt->skipped_dirs.entries[receipt->skipped_dirs.count++].item = item;
                continue;
        }

        error_t remove_err = fs_remove_empty_dir(path);
        if (!remove_err) {
            receipt->pruned_dirs.entries[receipt->pruned_dirs.count++].item = item;
            continue;
        }

        /* The refusal is the "not empty" verdict by another route, and the bucket
         * is the tag: the entry that stopped it is the next load's to read, so
         * the receipt keeps no cause — the error is dropped, one per directory
         * an entry still holds. Anything else is the item's own failure, kept
         * with its cause as above. */
        if (error_code(remove_err) == ERR_CONFLICT) {
            receipt->skipped_dirs.entries[receipt->skipped_dirs.count++].item = item;
            continue;
        }

        cleanup_outcome_t *o = &receipt->failed.entries[receipt->failed.count++];

        o->item = item;
        o->error = remove_err;
    }

    return receipt;
}
