/**
 * cleanup.c - Orphaned file and directory pruning: plan / preflight / execute
 *
 * See cleanup.h for the contract. Orphan detection, Git authority and divergence
 * are the workspace's; this module decides which orphans the run may touch, what
 * becomes of each, and carries that out.
 *
 * The verdict re-verifies nothing and touches neither disk, Git nor state — every
 * input is a field of the workspace item, observed once at load. The one look
 * the directory side takes is the readdir, because what is left in a directory
 * after this run's removals is not a property any earlier phase could have
 * recorded.
 */

#include "core/cleanup.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "core/scope.h"
#include "core/state.h"
#include "infra/mount.h"
#include "sys/filesystem.h"

/* ══════════════════════════════════════════════════════════════════
 * Plan
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Order two orphaned directories deepest first
 *
 * Descending path length, then ascending path so the order is total and the reports
 * are reproducible.
 */
static int compare_deepest_first(const void *a, const void *b) {
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
 * Build the cleanup plan
 */
error_t *cleanup_plan_build(
    const workspace_t *ws,
    const scope_t *scope,
    bool keep_orphans,
    cleanup_plan_t **out
) {
    CHECK_NULL(ws);
    CHECK_NULL(scope);
    CHECK_NULL(out);

    /* calloc zeroes the three ptr_array_t buckets — that IS their empty state */
    cleanup_plan_t *plan = calloc(1, sizeof(*plan));
    if (!plan) {
        return ERROR(ERR_MEMORY, "Failed to allocate cleanup plan");
    }

    /* --keep-orphans: nothing is planned, by request. The empty plan is what
     * every later stage reads, so no stage re-encodes the flag. */
    if (keep_orphans) {
        *out = plan;
        return NULL;
    }

    error_t *err = NULL;
    workspace_items_t items = workspace_get_all_diverged(ws);

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
            !scope_accepts_path(scope, item->storage_path, item->item_kind)) {
            continue;
        }

        /* Exclude dimension: spared, reported by the caller, never touched. */
        if (scope_is_excluded(scope, item->storage_path, item->item_kind)) {
            err = ptr_array_push(&plan->excluded, item);
        } else if (item->item_kind == PATH_KIND_DIRECTORY) {
            err = ptr_array_push(&plan->directories, item);
        } else {
            err = ptr_array_push(&plan->files, item);
        }
        if (err) goto cleanup;
    }

    /* Prune order, established once. A child's path is its parent's path plus a
     * separator and a name, so it is strictly longer; descending length therefore
     * places every directory after its own descendants, and two paths of equal
     * length can never be parent and child. That order is what lets a single
     * pass decide a directory whose emptiness depends on its children — no second
     * look, no iterating to a fixpoint.
     *
     * Established here rather than borrowed from the state layer's ORDER BY
     * filesystem_path: it is this module's correctness that rests on it, and a
     * producer two layers away is free to change its sort. */
    if (plan->directories.count > 1) {
        qsort(
            plan->directories.items, plan->directories.count,
            sizeof(*plan->directories.items), compare_deepest_first
        );
    }

    *out = plan;
    return NULL;

cleanup:
    cleanup_plan_free(plan);
    return error_wrap(err, "Failed to build cleanup plan");
}

void cleanup_plan_free(cleanup_plan_t *plan) {
    if (!plan) {
        return;
    }

    ptr_array_deinit(&plan->files);
    ptr_array_deinit(&plan->directories);
    ptr_array_deinit(&plan->excluded);

    free(plan);
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

    /* A held relocation: the claim's row rides the item and the label is not
     * the user's to re-target — the copy here is the claim's old home. The
     * same test as cleanup_verdict's hold arm, its inputs in hand; guarded by
     * the label so a re-targeted custom/ copy never trips it. */
    if (item->row) {
        const mount_spec_t *label = mount_spec_for_path(item->storage_path);
        if (label && !label->per_profile) {
            return CLEANUP_SKIP_RELOCATED;
        }
    }

    /* DIVERGENCE_CONTENT: disk differs from what dotta deployed */
    if (divergence & DIVERGENCE_CONTENT) {
        return CLEANUP_SKIP_MODIFIED;
    }

    /* DIVERGENCE_TYPE: File type changed (file <-> symlink) */
    if (divergence & DIVERGENCE_TYPE) {
        return CLEANUP_SKIP_TYPE_CHANGED;
    }

    /* DIVERGENCE_MODE or DIVERGENCE_OWNERSHIP: Permissions changed */
    if (divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
        return CLEANUP_SKIP_MODE_CHANGED;
    }

    /* All priority flags handled above. Remaining flags:
     * - ENCRYPTION: never emitted for an orphan (the blob-family bit is computed
     *   over the view's rows, and an orphan is exactly a record the view lacks)
     *   — listed so it cannot block
     * - STALE: never emitted for an orphan (compute_orphan_divergence asks one
     *   question, of disk alone) — listed so it cannot block
     * Unknown flags: block removal until explicitly handled above. */
    static const divergence_type_t known_flags = DIVERGENCE_CONTENT |
        DIVERGENCE_TYPE | DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP |
        DIVERGENCE_UNVERIFIED | DIVERGENCE_ENCRYPTION | DIVERGENCE_STALE;

    return (divergence & ~known_flags) ? CLEANUP_SKIP_UNVERIFIED
                                       : CLEANUP_SKIP_NONE;
}

/**
 * What becomes of a planned orphan, read off the item alone
 *
 * The table and its rationale are in cleanup.h. Every input is a field the
 * workspace observed once at load: no syscall, no query.
 */
cleanup_verdict_t cleanup_verdict(const workspace_item_t *item, bool force) {
    if (item->occupant == FS_OCCUPANT_NONE) {
        /* Already gone: nothing to protect, nothing to remove — a pure state
         * reclaim whatever Git or the divergence bits say. */
        return CLEANUP_ABSENT;
    }

    if (item->state == WORKSPACE_STATE_RELEASED) {
        /* Git no longer backs the path — the branch was deleted, the path was
         * removed from it — dotta never deployed it (the workspace's ownership
         * gate), or another kind of node stands in its place; the workspace
         * observed it either way. The path stays on disk to protect the user's
         * data, and the record retires because dotta cannot manage what Git cannot
         * restore, and does not remove what it did not put there: it is released
         * from dotta's management, not pruned.
         *
         * Decided before --force is consulted: --force prunes what would be
         * skipped, never what is released. */
        return CLEANUP_RELEASED;
    }

    /* The relocation hold, both kinds (the table in cleanup.h): the claim's
     * row rides the item, and a label the user cannot re-target (!per_profile
     * — home/; root/'s projection is fixed and never gets here) means $HOME
     * itself differs, so the copy is real dotfiles under the claim's real
     * home. --force lifts it — the escape for a deliberate home migration. */
    if (item->row && !force) {
        const mount_spec_t *label = mount_spec_for_path(item->storage_path);
        if (label && !label->per_profile) {
            return CLEANUP_SKIPPED;
        }
    }

    if (item->item_kind == PATH_KIND_DIRECTORY) {
        /* A directory the workspace could not stat or read is held whatever --force
         * says; otherwise the readdir finishes the verdict. */
        return (item->divergence & DIVERGENCE_UNVERIFIED) ? CLEANUP_SKIPPED
                                                          : CLEANUP_PRUNABLE;
    }

    return (!force && cleanup_skip_reason(item) != CLEANUP_SKIP_NONE)
        ? CLEANUP_SKIPPED : CLEANUP_PRUNABLE;
}

/**
 * What an entry met beneath an orphaned directory amounts to, for that directory's
 * own verdict
 *
 * A directory's fate is the strongest class left in it once this run has acted:
 * nothing but gone entries and it is prunable; a held one and it is skipped,
 * the same transient the held entry is; a permanent one and it is released, because
 * nothing dotta will ever do empties it. Every present planned item records its
 * class as its verdict is taken, so a directory's walk reads its children's fates
 * off the set; FATE_UNPLANNED is hashmap_get's NULL — the entry is outside the
 * plan — and the workspace item says which of the other two it is (vouch_entry).
 */
typedef enum {
    FATE_UNPLANNED = 0,
    FATE_GONE,        /* This run prunes it — the hole the walk looks through */
    FATE_HELD,        /* This run skips it — transient: update, --force, or the run that reaches it */
    FATE_PERMANENT    /* This run releases it, or never touches it — nothing of dotta's comes back for it */
} fate_t;

/**
 * The emptiness walk's context: the fate set, the workspace for an entry outside
 * the plan, and whether a held entry was met on the way
 */
typedef struct {
    const hashmap_t *fates;     /* filesystem path → fate_t, every present planned item */
    const workspace_t *ws;
    bool held;
} walk_t;

/**
 * Look past this directory entry?
 *
 * The vouch predicate of the verdict phase's emptiness walk. Gone and held entries
 * are looked past — a held one noted, because the directory then waits with it
 * — and a permanent one stops the walk: the directory is occupied by something
 * this run will not remove and no later run will either.
 *
 * An entry outside the plan is read off its workspace item. ORPHANED is held:
 * the scope did not reach it this run (-e, -p, a path filter), an unfiltered
 * run would decide it, and scope decides reach, never verdict — so a filtered
 * run must not change its parent's fate. Everything else is permanent: a RELEASED
 * orphan stays where it is; a managed path (the view has a row, and a row's item
 * is never an orphan's) stands in an enabled profile's name; an entry with no
 * item at all is the user's.
 *
 * Membership is keyed by filesystem path, which is why the entry arrives as a
 * full path rather than a basename.
 */
static bool vouch_entry(const char *child, void *ctx) {
    walk_t *walk = ctx;
    fate_t fate = (fate_t) (uintptr_t) hashmap_get(walk->fates, child);

    if (fate == FATE_UNPLANNED) {
        const workspace_item_t *item = workspace_get_item(walk->ws, child);

        fate = (item && item->state == WORKSPACE_STATE_ORPHANED) ? FATE_HELD
                                                                 : FATE_PERMANENT;
    }

    if (fate == FATE_HELD) {
        walk->held = true;
    }

    return fate != FATE_PERMANENT;
}

/**
 * Does the view claim a path beneath this directory?
 *
 * A managed path beneath an orphaned directory makes the directory the ancestor
 * of an enabled row — one ensure_parents would make anyway — and nothing dotta
 * does empties it: permanent, whether the row is on disk yet or not. The readdir
 * meets the rows already deployed (an entry with no item is permanent); this
 * answers for the ones deployment will put there — this run, or a later one that
 * reaches them — which is exactly why the disk cannot answer it. Read from the
 * view, not from the deployment plan, so the answer does not move with -p, -e
 * or a path filter: scope decides reach, never verdict.
 *
 * Every directory above a managed path is its ancestor, not just the immediate
 * parent: the ones deployment creates on the way count too.
 */
static bool managed_beneath(const workspace_t *ws, const char *dir) {
    size_t len = strlen(dir);
    const manifest_rows_t slices[] = { workspace_files(ws), workspace_directories(ws) };

    /* Strictly beneath: a prefix and then a separator, so "/a/bc" is not beneath
     * "/a/b" — and neither is "/a/b" itself. strncmp == 0 guarantees the candidate
     * has at least len bytes, so reading path[len] is in bounds: it is either
     * the terminator or a real character. Both sides are canonical filesystem
     * paths without a trailing separator. */
    for (size_t s = 0; s < sizeof(slices) / sizeof(slices[0]); s++) {
        for (size_t i = 0; i < slices[s].count; i++) {
            const char *path = slices[s].entries[i]->filesystem_path;

            if (strncmp(path, dir, len) == 0 && path[len] == '/') {
                return true;
            }
        }
    }

    return false;
}

/**
 * Decide the verdicts
 */
error_t *cleanup_preflight(
    const workspace_t *ws,
    const cleanup_plan_t *plan,
    bool force,
    cleanup_preflight_result_t **out
) {
    CHECK_NULL(ws);
    CHECK_NULL(plan);
    CHECK_NULL(out);

    /* calloc zeroes the eight buckets — an empty answer needs no NULL guard
     * downstream */
    cleanup_preflight_result_t *verdicts = calloc(1, sizeof(*verdicts));
    if (!verdicts) {
        return ERROR(ERR_MEMORY, "Failed to allocate cleanup verdicts");
    }

    /* The fate of every present planned item, in one set: the directory pass
     * asks it about every entry it meets. Borrowed keys, all workspace-owned;
     * the values are fate_t, never NULL, so hashmap_get's NULL is "outside the
     * plan". */
    hashmap_t *fates = hashmap_borrow(plan->files.count + plan->directories.count);
    if (!fates) {
        cleanup_preflight_result_free(verdicts);
        return ERROR(ERR_MEMORY, "Failed to allocate fate set");
    }

    error_t *err = NULL;

    /* One verdict per file, read straight off the item: no syscalls, no queries.
     * An absent file joins neither the prune count nor the fate set: no filesystem
     * effect to preview, and no walk meets it. */
    workspace_items_t files = workspace_items_view(&plan->files);

    for (size_t i = 0; i < files.count; i++) {
        const workspace_item_t *item = files.entries[i];
        fate_t fate = FATE_UNPLANNED;

        switch (cleanup_verdict(item, force)) {
            case CLEANUP_ABSENT:
                err = ptr_array_push(&verdicts->absent_files, item);
                break;

            case CLEANUP_RELEASED:
                err = ptr_array_push(&verdicts->released_files, item);
                fate = FATE_PERMANENT;
                break;

            case CLEANUP_SKIPPED:
                err = ptr_array_push(&verdicts->skipped_files, item);
                fate = FATE_HELD;
                break;

            case CLEANUP_PRUNABLE:
                err = ptr_array_push(&verdicts->prunable_files, item);
                fate = FATE_GONE;
                break;
        }
        if (!err && fate != FATE_UNPLANNED) {
            err = hashmap_set(fates, item->filesystem_path, (void *) (uintptr_t) fate);
        }
        if (err) goto cleanup;
    }

    /* A directory's verdict is the strongest class left in it once this run has
     * acted (fate_t): prunable when everything in it is OS metadata or gone;
     * skipped while something held is left; released once something permanent
     * is. That is what the prune arrives at by acting, read off the plan here
     * in one pass because the plan orders every child before its parent — a
     * directory's own fate enters the set as it is decided, which is what lets
     * a parent read its pruned children as gone, its skipped ones as held and
     * its released ones as permanent.
     *
     * The buckets fill in walk order, which is prune order: deepest first. */
    workspace_items_t dirs = workspace_items_view(&plan->directories);

    for (size_t i = 0; i < dirs.count; i++) {
        const workspace_item_t *item = dirs.entries[i];
        const char *path = item->filesystem_path;
        fate_t fate = FATE_UNPLANNED;

        switch (cleanup_verdict(item, force)) {
            case CLEANUP_ABSENT:
                /* A pure state reclaim: no filesystem effect to preview, and no
                 * walk meets it. */
                err = ptr_array_push(&verdicts->absent_dirs, item);
                break;

            case CLEANUP_RELEASED:
                /* Left alone — unprobed, because nothing about its contents changes
                 * the answer — and the record retires. */
                err = ptr_array_push(&verdicts->released_dirs, item);
                fate = FATE_PERMANENT;
                break;

            case CLEANUP_SKIPPED:
                /* The workspace could not verify it; the directory above it waits
                 * with it. */
                err = ptr_array_push(&verdicts->skipped_dirs, item);
                fate = FATE_HELD;
                break;

            case CLEANUP_PRUNABLE:
                /* A directory the workspace saw and can read (the occupant is
                 * DIRECTORY: anything else in its place was released above).
                 * What is left in it after this run finishes the verdict. A managed
                 * path beneath it is known from the view before any look at the
                 * disk; otherwise one readdir, which stops at the first permanent
                 * entry and notes any held one it passed. UNREADABLE is a directory
                 * that was readable at load and is not now — the world moved,
                 * and it is held like a refusal on removal, not released. */
                if (managed_beneath(ws, path)) {
                    fate = FATE_PERMANENT;
                } else {
                    walk_t walk = { .fates = fates, .ws = ws, .held = false };

                    switch (fs_directory_emptiness(path, vouch_entry, &walk)) {
                        case FS_DIR_OCCUPIED:   fate = FATE_PERMANENT; break;
                        case FS_DIR_UNREADABLE: fate = FATE_HELD; break;
                        case FS_DIR_EMPTY:      fate = walk.held ? FATE_HELD : FATE_GONE; break;
                    }
                }

                ptr_array_t *bucket = (fate == FATE_GONE) ? &verdicts->prunable_dirs
                                    : (fate == FATE_HELD) ? &verdicts->skipped_dirs
                                                          : &verdicts->released_dirs;
                err = ptr_array_push(bucket, item);
                break;
        }
        if (!err && fate != FATE_UNPLANNED) {
            /* Its parent must read it when its own turn comes. */
            err = hashmap_set(fates, path, (void *) (uintptr_t) fate);
        }
        if (err) goto cleanup;
    }

    hashmap_free(fates, NULL);

    *out = verdicts;
    return NULL;

cleanup:
    hashmap_free(fates, NULL);
    cleanup_preflight_result_free(verdicts);
    return error_wrap(err, "Failed to decide cleanup verdicts");
}

void cleanup_preflight_result_free(cleanup_preflight_result_t *verdicts) {
    if (!verdicts) {
        return;
    }

    ptr_array_deinit(&verdicts->prunable_files);
    ptr_array_deinit(&verdicts->skipped_files);
    ptr_array_deinit(&verdicts->released_files);
    ptr_array_deinit(&verdicts->absent_files);
    ptr_array_deinit(&verdicts->prunable_dirs);
    ptr_array_deinit(&verdicts->skipped_dirs);
    ptr_array_deinit(&verdicts->released_dirs);
    ptr_array_deinit(&verdicts->absent_dirs);

    free(verdicts);
}

/* ══════════════════════════════════════════════════════════════════
 * Outcomes
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Carry the verdicts out
 *
 * Acts on prunable_files and prunable_dirs alone; skipped, released and absent
 * are decided at preflight and confirmed here by passing them through, so the
 * receipt accounts for the whole plan and apply's record step reads one object
 * (cleanup.h). Data-loss prevention happened at preflight, in cleanup_skip_reason
 * and the released test; nothing is re-checked here and nothing pretends to be.
 *
 * Files first, then the directories those files emptied, in the verdicts' prune
 * order (deepest first, the plan's order): every child is decided before its
 * parent, so a parent this run empties is seen empty when its turn comes — the
 * whole reason the old iterate-until-stable loop existed.
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
error_t *cleanup_execute(
    const cleanup_preflight_result_t *verdicts,
    cleanup_result_t **out
) {
    CHECK_NULL(verdicts);
    CHECK_NULL(out);

    /* calloc zeroes the ten buckets. Handed to the caller at once so a fatal
     * error mid-run still leaves the partial receipt in its hands. */
    cleanup_result_t *result = calloc(1, sizeof(*result));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate cleanup result");
    }
    *out = result;

    /* Step 1: Prune the orphaned files the verdicts cleared */
    workspace_items_t files = workspace_items_view(&verdicts->prunable_files);

    for (size_t i = 0; i < files.count; i++) {
        const workspace_item_t *item = files.entries[i];
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
            RETURN_IF_ERROR(ptr_array_push(&result->reclaimed_files, item));
            continue;
        }

        error_t *remove_err = fs_remove_file(path);
        if (remove_err) {
            /* Non-fatal: record the failure and carry on. */
            error_free(remove_err);
            RETURN_IF_ERROR(ptr_array_push(&result->failed_files, item));
        } else {
            RETURN_IF_ERROR(ptr_array_push(&result->pruned_files, item));
        }
    }

    /* Step 2: Prune the orphaned directories those files emptied */
    workspace_items_t dirs = workspace_items_view(&verdicts->prunable_dirs);

    for (size_t i = 0; i < dirs.count; i++) {
        const workspace_item_t *item = dirs.entries[i];
        const char *path = item->filesystem_path;

        switch (fs_lstat_occupant(path, NULL)) {
            case FS_OCCUPANT_NONE:
                /* No filesystem effect happened or was needed — the record retires,
                 * nothing is removed. */
                RETURN_IF_ERROR(ptr_array_push(&result->reclaimed_dirs, item));
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
                RETURN_IF_ERROR(ptr_array_push(&result->skipped_dirs, item));
                continue;
        }

        error_t *remove_err = fs_remove_empty_dir(path);
        if (!remove_err) {
            RETURN_IF_ERROR(ptr_array_push(&result->pruned_dirs, item));
            continue;
        }

        /* Non-fatal either way: record which it was and carry on. */
        bool gained_content = (error_code(remove_err) == ERR_CONFLICT);
        error_free(remove_err);

        ptr_array_t *outcome = gained_content ? &result->skipped_dirs : &result->failed_dirs;
        RETURN_IF_ERROR(ptr_array_push(outcome, item));
    }

    /* The verdicts this run does not act on, confirmed. */
    const struct { const ptr_array_t *from; ptr_array_t *to; } confirmed[] = {
        { &verdicts->absent_files,   &result->reclaimed_files },
        { &verdicts->released_files, &result->released_files  },
        { &verdicts->skipped_files,  &result->skipped_files   },
        { &verdicts->absent_dirs,    &result->reclaimed_dirs  },
        { &verdicts->released_dirs,  &result->released_dirs   },
        { &verdicts->skipped_dirs,   &result->skipped_dirs    },
    };

    for (size_t b = 0; b < sizeof(confirmed) / sizeof(confirmed[0]); b++) {
        for (size_t i = 0; i < confirmed[b].from->count; i++) {
            RETURN_IF_ERROR(ptr_array_push(confirmed[b].to, confirmed[b].from->items[i]));
        }
    }

    return NULL;
}

void cleanup_result_free(cleanup_result_t *result) {
    if (!result) {
        return;
    }

    ptr_array_deinit(&result->pruned_files);
    ptr_array_deinit(&result->reclaimed_files);
    ptr_array_deinit(&result->released_files);
    ptr_array_deinit(&result->skipped_files);
    ptr_array_deinit(&result->failed_files);
    ptr_array_deinit(&result->pruned_dirs);
    ptr_array_deinit(&result->reclaimed_dirs);
    ptr_array_deinit(&result->released_dirs);
    ptr_array_deinit(&result->skipped_dirs);
    ptr_array_deinit(&result->failed_dirs);

    free(result);
}
