/**
 * deploy.c - File and directory deployment engine implementation
 */

#include "core/deploy.h"

#include <errno.h>
#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/string.h"
#include "core/metadata.h"
#include "core/scope.h"
#include "core/workspace.h"
#include "infra/content.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/identity.h"

/* ══════════════════════════════════════════════════════════════════
 * Plan
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Deploy's work predicate over a workspace verdict
 *
 * Two dimensions, in order: state (where does the path exist — Git, state database,
 * filesystem?) sets the baseline, divergence (what is wrong with it?) refines
 * it. A missing path is always work, and the only bit it can carry is the blob
 * bit, ENCRYPTION (core/workspace.h divergence_type_t) — no path bit survives
 * absence, so the two missing states answer from state alone.
 *
 * Kind-agnostic: directory analysis tags only MODE / OWNERSHIP / TYPE / UNVERIFIED,
 * so the DEPLOYED arm's test already covers every directory verdict — no
 * kind-specific arm. A file row can carry ENCRYPTION beside any of those; the
 * arm masks it either way.
 *
 * The planner walks the active items, so the three states an orphan or a discovery
 * takes never reach this: their arms name the owner that does handle them, keep
 * -Wswitch quiet, and die with the tail — answered false, the item would fall
 * to the clean bucket, which adoption reads.
 *
 * @param item An active item, the verdict on it (must not be NULL)
 * @return true when deploy must act on the path
 */
static bool deploy_needs_work(const workspace_item_t *item) {
    /* Decision tree: state (existence) determines baseline, then check divergence (quality) */
    switch (item->state) {
        case WORKSPACE_STATE_UNDEPLOYED:
            /* The view claims the path and nothing stands there, where dotta
             * saw none of its node — no record of its kind — or the claim is an
             * ancestor's, which asserts none (core/workspace.c classify_absent).
             * Needs deploying.
             *
             * No path bit survives absence (properties of non-existent files
             * cannot be compared); the blob bit, ENCRYPTION, can ride on a missing
             * row — [undeployed] [unencrypted] — and changes nothing here: the
             * row is work by state alone. */
            return true;

        case WORKSPACE_STATE_DELETED:
            /* The view claims the path and nothing stands there, where a record
             * of its kind says dotta saw its node — observed or put there: the
             * record's existence decides, never its ownership (core/workspace.c
             * classify_absent). Needs restoration. Absence and the blob bit read
             * as in the UNDEPLOYED arm: work by state alone. */
            return true;

        case WORKSPACE_STATE_DEPLOYED:
            /* File exists on filesystem and is tracked in Git. Needs deployment
             * only if properties diverged (content, mode, ownership, etc.).
             *
             * DIVERGENCE_STALE and DIVERGENCE_CLAIM_MOVED are deploy reasons
             * like any other: Git moved past what dotta last reconciled — the
             * bytes or a claim — and disk did not follow.
             *
             * DIVERGENCE_ENCRYPTION is the one bit that is never deploy's work:
             * it says the blob is stored plaintext in Git where the auto-encrypt
             * policy claims the path — a fact about the profile's tree, not about
             * what stands at the path. No write deploy makes can change how a
             * blob is stored; update is the verb that re-stores it, and
             * deploy_content_conflicts states the same rule for overwrites. A
             * deny-mask rather than an allow-list, so a bit added later inherits
             * the arm's default: any divergence of the path is work.
             *
             * A row beneath a squatter is work whatever its bits, because it
             * has no path bit: nothing there was looked at (core/workspace.h
             * workspace_displaced_t). Planned, it is written fresh beneath a
             * squatter this run replaces, or refused by its ancestry — and either
             * fate is preflight's to name (check_ancestry). Left out of the plan
             * it would fall to the clean bucket, which adoption reads, and adopting
             * a path nobody looked at would take ownership of a stranger's file. */
            return item->displaced != WORKSPACE_DISPLACED_NONE ||
                   (item->divergence & ~DIVERGENCE_ENCRYPTION) != DIVERGENCE_NONE;

        case WORKSPACE_STATE_ORPHANED:
        /* A record whose path the view lacks. Never deployment — cleanup owns
         * orphan removal. */
        case WORKSPACE_STATE_UNTRACKED:
        /* A file in a tracked directory that Git does not hold: the user adds
         * it. Never among the active items, which are made from the view's rows,
         * not filesystem scans. */
        case WORKSPACE_STATE_RELEASED:
            /* The path left its profile in Git (an external commit, a pulled
             * removal, a vanished branch), or dotta never deployed it, and it
             * was released from management. Never needs deployment — cleanup
             * reports it and apply's record phase retires its record. */
            break;
    }

    /* An item the planner cannot hand in: one of the three above, or a value no
     * enumerator names. */
    CHECK_ARG(false, "deploy_needs_work was handed an item that is not active");
}

/**
 * Why the plan skips a row's work
 *
 * At most one reason per row: a row both reasons claim is reported as excluded,
 * because -e names a path and --skip-existing is a blanket policy. Encoding the
 * answer rather than the two conditions keeps the precedence in one place and
 * leaves "both at once" unrepresentable.
 *
 * "Skip" is the word the buckets and the screen use ("Skipped N paths
 * (--exclude)"), and the word core/cleanup uses for the same shape
 * (cleanup_skip_reason_t). In this module "hold" means only what hold_directory
 * does — carry a directory at a working mode until release_directories lets it go.
 */
typedef enum {
    SKIP_NONE,       /* nothing stands in the way of the row's work */
    SKIP_EXCLUDED,   /* an -e pattern matched the row's storage path */
    SKIP_EXISTING    /* --skip-existing and something occupies the path */
} skip_reason_t;

/**
 * Route one active item in scope into its partition bucket, or drop it
 *
 * Three inputs, three owners: whether there is work is the item's to say
 * (deploy_needs_work), why its work is skipped the plan's (-e, --skip-existing),
 * and which partition it goes to the loop's, one per kind. An item with no work
 * is apply's to adopt or acknowledge unless -e named it: --exclude means "leave
 * this path alone entirely", while --skip-existing only means "do not overwrite",
 * and neither ownership event overwrites anything. So SKIP_EXISTING on a clean
 * item — every clean one with something standing, under --skip-existing — is
 * not a skip at all.
 *
 * The plan's one writer, and so the one place its buckets' element type is kept:
 * a ptr_array_t says nothing of what it holds, and every reader projects it as
 * items (core/workspace.h workspace_items).
 *
 * @param part Partition for the item's kind (must not be NULL)
 * @param item An active item in scope, borrowed (must not be NULL)
 * @param skip Why the item's work is skipped, if it is
 */
static void deploy_classify(
    deploy_partition_t *part,
    const workspace_item_t *item,
    skip_reason_t skip
) {
    if (!deploy_needs_work(item)) {
        /* Excluded: neither work nor apply's to own */
        if (skip != SKIP_EXCLUDED) ptr_array_push(&part->clean, item);
        return;
    }

    switch (skip) {
        case SKIP_NONE:     ptr_array_push(&part->pending, item); return;
        case SKIP_EXCLUDED: ptr_array_push(&part->excluded, item); return;
        case SKIP_EXISTING: ptr_array_push(&part->skipped_existing, item); return;
    }

    CHECK_ARG(false, "a skip reason no enumerator names");
}

/**
 * Build the deployment plan
 */
deploy_plan_t *deploy_plan_build(
    arena_t *arena, const workspace_t *ws, const scope_t *scope, bool skip_existing
) {
    CHECK_NULL(arena);
    CHECK_NULL(ws);
    CHECK_NULL(scope);

    /* The plan and its eight buckets are the arena's, beside the items they borrow:
     * each bucket is made in it, and nothing frees a plan. */
    deploy_plan_t *plan = arena_calloc(arena, 1, sizeof(*plan));
    ptr_array_init(&plan->directories.pending, arena);
    ptr_array_init(&plan->directories.clean, arena);
    ptr_array_init(&plan->directories.excluded, arena);
    ptr_array_init(&plan->directories.skipped_existing, arena);
    ptr_array_init(&plan->files.pending, arena);
    ptr_array_init(&plan->files.clean, arena);
    ptr_array_init(&plan->files.excluded, arena);
    ptr_array_init(&plan->files.skipped_existing, arena);

    /* Directories then files — the order preflight decides and the run acts in.
     * Convention alone: each row's classification reads the workspace and the
     * scope, never the buckets, so neither loop depends on the other having run. */
    workspace_items_t dirs = workspace_directories(ws);
    for (size_t i = 0; i < dirs.count; i++) {
        const workspace_item_t *item = dirs.entries[i];

        /* An ancestor claim is not the run's to converge, so it is not the plan's
         * to hold. dotta creates such a path on the way to something beneath it
         * — deploy_preflight's ancestors pass, which knows both that the path
         * is absent and that a deployable row stands under it, the pair the plan
         * cannot see — and does nothing at all to one that already stands. Neither
         * bucket, therefore: not pending, since there is no convergence to perform;
         * not clean, since there is nothing to adopt or acknowledge (an apply
         * must not take ownership of a parent it found already there). Prior to
         * scope, because scope decides reach and this decides whether there is
         * anything to reach for. */
        if (!item->row->tracked) continue;

        if (!scope_accepts_profile(scope, item->profile) ||
            !scope_accepts_path(
            scope, item->filesystem_path, item->storage_path, PATH_KIND_DIRECTORY
            )) {
            continue;                        /* out of scope: invisible */
        }

        /* No SKIP_EXISTING arm: --skip-existing does not reach tracked directories
         * (see deploy_partition_t). */
        deploy_classify(
            &plan->directories, item,
            scope_is_excluded(scope, item->storage_path, PATH_KIND_DIRECTORY)
                ? SKIP_EXCLUDED : SKIP_NONE
        );
    }

    workspace_items_t files = workspace_files(ws);
    for (size_t i = 0; i < files.count; i++) {
        const workspace_item_t *item = files.entries[i];

        if (!scope_accepts_profile(scope, item->profile) ||
            !scope_accepts_path(
            scope, item->filesystem_path, item->storage_path, PATH_KIND_FILE
            )) {
            continue;
        }

        /* Occupancy is the workspace's own lstat, not a fresh probe: every row's
         * item carries its look, and lstat truth counts a broken symlink as
         * occupying the path — which is what the flag says, and what a stat that
         * follows links could not tell us. A row beneath a squatter is the one
         * exception: no lstat was taken there (core/workspace.h
         * workspace_displaced_t), so nothing is "existing" for the flag to keep
         * — the path is empty once the squatter this run replaces is gone, and
         * one it leaves standing is refused by the ancestry rung either way.
         * Both fates are preflight's (check_ancestry). -e still holds: a named
         * path is intent, not a look's finding. */
        skip_reason_t skip = SKIP_NONE;
        if (scope_is_excluded(scope, item->storage_path, PATH_KIND_FILE)) {
            skip = SKIP_EXCLUDED;
        } else if (skip_existing && item->displaced == WORKSPACE_DISPLACED_NONE &&
            item->occupant != FS_OCCUPANT_NONE) {
            skip = SKIP_EXISTING;
        }

        deploy_classify(&plan->files, item, skip);
    }

    return plan;
}

/* ══════════════════════════════════════════════════════════════════
 * Occupancy
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Does what stands at the path disagree with what the row materializes?
 *
 * Something known to stand there that is not the node the row's type stands as
 * (core/workspace.h workspace_type_occupant) — the link itself, never its target:
 * deploy unlinks the link and never follows it, so the target's type and
 * permissions are none of its business.
 */
static bool occupant_conflicts(fs_occupant_t occ, path_type_t type) {
    return deploy_occupant_present(occ) && occ != workspace_type_occupant(type);
}

/**
 * May deploy remove what occupies a planned path?
 */
typedef enum {
    CLEARANCE_OK,           /* consented, and the occupant is one node */
    CLEARANCE_NEEDS_FORCE,  /* one node, but nothing said to replace it */
    CLEARANCE_REFUSED       /* a directory holding paths the plan does not name */
} clearance_t;

/**
 * Deploy's rule for clearing a planned path
 *
 * One rule, one consumer: preflight decides with it, and the executors clear
 * what the verdict says stood there — never re-deciding from a fresh look. A
 * prompt may have sat between the verdict and the syscall; what the verdict no
 * longer describes, the mechanism refuses (clear_occupant).
 *
 * Consent is the first half. Clearing an occupant is the destructive reading of
 * "overwrite modified files", so it is --force's to give — unless nothing of
 * the user's stands there: a file row's occupant the workspace proved is the
 * very copy dotta confirmed, Git having moved the kind beneath it, is replaced
 * unasked, as a STALE row's bytes are overwritten (the file ladder's type rung,
 * which hands the proof in).
 *
 * The second half is a limit no consent lifts. What deploy replaces is the tracked
 * path the user named: one node, whose disappearance is exactly what the preview
 * and the prompt describe. A directory holding anything else holds *other* paths
 * — untracked, unnamed, uncounted, and not restorable from Git — so nothing on
 * the apply command line authorizes removing them. core/cleanup never removes
 * an orphaned directory holding anything of the user's, --force included
 * (cleanup_preflight's directory verdicts release it); this is the same posture
 * on deploy's side of the house.
 *
 * "Holds something" is fs_is_directory_empty's negation, so a directory carrying
 * nothing but OS metadata is clearable and fs_remove_empty_dir removes exactly
 * that much. A directory that cannot be read answers "not empty" — don't remove
 * what you cannot verify — and its remedy is the same one. This readdir is the
 * one look preflight takes at a planned path itself; the occupant is the
 * workspace's.
 *
 * Asked only of a present occupant that conflicts (occupant_conflicts): an absent
 * path needs no clearing, and the answer is undefined for one.
 *
 * @param path Planned path (must not be NULL)
 * @param occ Its occupant, as the workspace's look found it
 * @param consent Whether replacing it is consented: --force, or on a file row
 *        the workspace's proof that the occupant is dotta's own copy
 */
static clearance_t path_clearance(const char *path, fs_occupant_t occ, bool consent) {
    if (occ == FS_OCCUPANT_DIRECTORY && !fs_is_directory_empty(path)) {
        return CLEARANCE_REFUSED;
    }

    return consent ? CLEARANCE_OK : CLEARANCE_NEEDS_FORCE;
}

/**
 * Remove the occupant of a planned path so the row's own type can land
 *
 * Every arm removes exactly one node: unlink for a file, a symlink or a device,
 * rmdir for a directory that holds nothing (fs_remove_empty_dir clears OS metadata
 * and refuses anything else). Deploy owns no recursive removal at all, which is
 * what lets path_clearance be a prediction rather than a guard: a directory that
 * fills up between the two stops the run instead of going with it. Absence is
 * success — a race that removes the occupant first has done this function's work.
 */
static error_t clear_occupant(const char *path, fs_occupant_t occ) {
    return (occ == FS_OCCUPANT_DIRECTORY) ? fs_remove_empty_dir(path)
                                          : fs_remove_file(path);
}

/* ══════════════════════════════════════════════════════════════════
 * Ancestors
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Byte length of the ancestor ending at the slash at index `slash`. The root is
 * the one ancestor that IS its slash: index 0 means "/", one byte.
 */
static size_t ancestor_len(size_t slash) {
    return slash ? slash : 1;
}

/**
 * What stands at the ancestor of `scratch` ending at the slash at index `slash`
 * — NUL-terminated in place for the probes, restored afterwards.
 *
 * Two probes, for two different questions. lstat says whether anything is there
 * at all: a dangling symlink is, and mkdir and rename trip over it exactly as
 * they would over a file. stat, for a symlink only, says whether the path leads
 * to a directory: a symlinked configuration directory is a directory for the
 * purpose of writing beneath it. *out_is_dir is that second answer; *out_st is
 * the lstat of a present ancestor. errno is lstat's on FS_OCCUPANT_UNKNOWN.
 *
 * The stat-through-the-link is exactly where a symlink squatting a CLAIMED
 * directory would read as a directory and wave the write through — which is why
 * the ancestry rung (check_ancestry) guards claimed ancestors, either class,
 * before any ladder reaches a probe; this probe's answer stands for the ones no
 * claim names, the user's own arrangement.
 */
static fs_occupant_t probe_ancestor(
    char *scratch, size_t slash, bool *out_is_dir, struct stat *out_st
) {
    size_t len = ancestor_len(slash);
    char saved = scratch[len];
    scratch[len] = '\0';

    fs_occupant_t occ = fs_lstat_occupant(scratch, out_st);
    int saved_errno = errno;

    if (occ == FS_OCCUPANT_DIRECTORY) {
        *out_is_dir = true;
    } else if (occ == FS_OCCUPANT_SYMLINK) {
        struct stat target;
        *out_is_dir = (fs_stat(scratch, &target) == 0) && S_ISDIR(target.st_mode);
    } else {
        *out_is_dir = false;
    }

    scratch[len] = saved;
    errno = saved_errno;

    return occ;
}

/**
 * Nearest present ancestor of an absolute path (parent, grandparent, …)
 *
 * Present by lstat — see probe_ancestor. `scratch` is a writable copy of the
 * path, intact on return; *out_slash receives the index of the slash that ends
 * the ancestor (0 for "/"), *out_occ what stands there, *out_is_dir whether the
 * path leads to a directory through it, *out_st its lstat. False only when lstat
 * fails for a reason other than absence; errno is preserved for the caller to
 * judge.
 */
static bool nearest_ancestor(
    char *scratch, size_t *out_slash,
    fs_occupant_t *out_occ, bool *out_is_dir, struct stat *out_st
) {
    size_t i = strlen(scratch);
    for (;;) {
        do {
            CHECK_ARG(i > 0, "the planned path is absolute");
        } while (scratch[--i] != '/');

        fs_occupant_t occ = probe_ancestor(scratch, i, out_is_dir, out_st);
        if (occ == FS_OCCUPANT_UNKNOWN) {
            return false;
        }
        if (occ != FS_OCCUPANT_NONE) {
            *out_slash = i;
            *out_occ = occ;
            return true;
        }
        if (i == 0) {
            errno = ENOENT;                     /* "/" itself absent — cannot happen */
            return false;
        }
        /* ENOENT: keep climbing. ENOTDIR: a higher ancestor is a non-directory
         * — keep climbing until the probe lands on it. */
    }
}

/**
 * The row of a present directory this run may hold, or NULL
 *
 * A directory the view names — any enabled profile, in scope or not, either class,
 * the same reach create_ancestor has — that we own. The run may carry it at a
 * working mode while the paths beneath it land and release it afterwards
 * (deploy_run_t), so its current mode can never refuse a path beneath it. The
 * class does not enter: a claim's mode is captured with the very children it
 * would refuse, and that argument is the ancestor claim's as much as the tracked
 * one's — the alternative would make the reach depend on whether the user typed
 * the directory or a file inside it. Nothing else is ours to touch: a directory
 * no row names and that refuses is a permission error, and a claimed one we do
 * not own cannot be fchmod'd at all (identity_may_chmod: the node's owner, or a
 * run that holds root).
 *
 * @param st lstat of the directory (must not be NULL)
 */
static const manifest_row_t *holdable_directory(
    const workspace_t *ws, const char *path, const struct stat *st
) {
    const workspace_item_t *item = workspace_find(ws, path);

    /* The view's claim, which an active item carries and an orphan's does not:
     * a directory only a record remembers is no claim to hold */
    if (item && item->row && item->item_kind == PATH_KIND_DIRECTORY
        && identity_may_chmod(identity(), st->st_uid)) {
        return item->row;
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Preflight
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Is `path` a directory row this run will deploy?
 *
 * A deployable row is one the directory pass acts on before any file is written:
 * it creates the path, replaces whatever squats it, or converges what is already
 * there — and whichever it does, once its verdict says it will, the directory
 * carries a working mode until the run is over, so nothing planned beneath it
 * is refused on its account. Asked of the verdicts rather than the plan: a skipped
 * directory row does none of that, and vouches for nothing beneath it.
 *
 * Within the directory ladder the verdicts decided so far are exactly the
 * ancestors' (parents-first); everywhere else the directory pass is complete.
 */
static bool directory_is_deployable(
    const deploy_preflight_t *verdicts, const char *path
) {
    for (size_t i = 0; i < verdicts->directories.count; i++) {
        if (strcmp(verdicts->directories.entries[i].item->filesystem_path, path) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * The fate a squatted ancestor imposes on a planned row
 *
 * The one question the ladders ask before any probe of their own, because a
 * squatted directory row above the path invalidates every probe beneath it —
 * the landing check's included: a symlink squatting a claimed directory points
 * somewhere real and writable, so the landing probe would wave the write through
 * and the run would deploy INTO the link's target, over whatever the user keeps
 * there. The workspace lends the offender whole (workspace_squatted_ancestor —
 * the outermost, fate-blind, with the claim the load noted beside it); this splits
 * the answer by what the run itself decided about that ancestor, the premise
 * the plan carried by scope now asked of the verdicts, so it is exactly true.
 * One arm per fate, in decision order, each writing what it decides:
 *
 *   deployable    the directory pass converges the ancestor before this row is
 *                 reached — created, fixed or replaced — so from here down the
 *                 path is empty at write time. *out_absent; the row is asked
 *                 nothing else
 *   skipped       the squatter stays: nothing beneath it can land, and no
 *                 probe of the path can be trusted about it. The row takes the
 *                 squatter's class, the squatter named — the fate is the
 *                 squatter's, so the class (--force or not) and the exit code
 *                 must be too — in the one sentence true of any squatter: TYPE
 *                 ("wrong type at" it) where --force lifts both, ANCESTOR ("is
 *                 not a directory") where no flag does. Never the squatter's
 *                 own reason: a reason is a sentence about the row that carries
 *                 it (deploy_skip_reason_t), and the squatter's — a parent refusing
 *                 it, a pair its own claim names — is false of the row beneath.
 *                 The squatter's own skip, listed above the row, says why it
 *                 stays and names the remedy for both
 *   no fate       this run never reaches the ancestor (out of scope, -p'd
 *                 away, -e'd, or an ancestor claim the plan never holds): ANCESTOR
 *                 — the same fate a squatter no row names earns at check_landing,
 *                 an incapacity. The skip carries which claim holds the squatter
 *                 — the load's own note of it, lent with the path — because the
 *                 remedies part ways there: a wider scope plans a tracked row,
 *                 the named re-derivation drops an ancestor claim
 *
 * The claimant is written in the no-fate arm alone — a row beneath a skipped
 * squatter leaves the class NONE, its remedy being that squatter's own line's
 * (deploy_ancestor_class_t). Called before check_landing in both ladders and
 * once more per ancestor candidate; directories are decided parents-first, so a
 * squatted ancestor's own fate is always already taken when a row beneath it is
 * reached. The skip and *out_absent are written only when an ancestor decides —
 * the caller's zero skip and false stand otherwise, and the row judges itself.
 *
 * @param ws Workspace, for the squatted-ancestor answer (must not be NULL)
 * @param verdicts The fates decided so far (must not be NULL)
 * @param path Planned path (must not be NULL)
 * @param skip The row's skip in the making (must not be NULL): the reason — TYPE
 *        or ANCESTOR — the named squatter's prefix length, and where the run
 *        gave the squatter no fate the claim at it
 * @param out_absent Whether the run empties the path before writing it (must
 *        not be NULL)
 */
static void check_ancestry(
    const workspace_t *ws, const deploy_preflight_t *verdicts, const char *path,
    deploy_skip_t *skip, bool *out_absent
) {
    const workspace_squatted_t *above = workspace_squatted_ancestor(ws, path);

    if (!above) return;

    /* Deployable: the directory pass converges the ancestor first */
    if (directory_is_deployable(verdicts, above->filesystem_path)) {
        *out_absent = true;
        return;
    }

    /* The two fates left both skip the row, and both name the squatter */
    skip->ancestor = above->len;

    /* Skipped: the squatter's class, never its sentence — consent stays TYPE,
     * and an incapacity reads what every squatter is, not a directory */
    for (size_t i = 0; i < verdicts->skipped.count; i++) {
        const deploy_skip_t *s = &verdicts->skipped.entries[i];

        if (strcmp(s->item->filesystem_path, above->filesystem_path) == 0) {
            skip->reason = deploy_skip_needs_force(s->reason)
                ? DEPLOY_SKIP_TYPE : DEPLOY_SKIP_ANCESTOR;
            return;
        }
    }

    /* No fate: ANCESTOR, and the claim the load noted beside the squatter — the
     * view's face lends a view claim alone, TRACKED or DERIVED */
    skip->reason = DEPLOY_SKIP_ANCESTOR;
    skip->ancestor_class = above->claim == WORKSPACE_DISPLACED_TRACKED
        ? DEPLOY_ANCESTOR_TRACKED : DEPLOY_ANCESTOR_DERIVED;
}

/**
 * Can this planned path's write land?
 *
 * One question per planned row, present or absent alike, and never about the
 * path itself: nothing deploy writes needs permission on the path.
 * fs_write_file_raw renames a temp file over it, fs_create_symlink unlinks and
 * re-links it, deploy_directory mkdirs it — every one of those is an operation
 * on the *parent*. A read-only file, or a symlink pointing into a read-only store,
 * is no obstacle at all.
 *
 * So the question goes to the nearest present ancestor, and to it alone. Every
 * component between it and the planned path is absent, and ensure_parents creates
 * those with the owner triad on for as long as the run lasts (working_mode) —
 * an absent component can refuse nothing. What stands at the ancestor decides:
 *
 *   a deployable directory    the directory pass converges it first —
 *   row                       created, fixed or replaced — and carries it at a
 *                             working mode; fine, whatever squats it now (a
 *                             squatter there means --force, and the pass replaces
 *                             it before anything lands beneath). A *skipped*
 *                             directory row converges nothing and vouches for
 *                             nothing — it answers below like any stranger's path
 *   a directory the view      ours to hold (holdable_directory), either class:
 *   names                     if it refuses, ensure_parents opens it for the run
 *                             and releases it afterwards; fine
 *   any other directory       must accept a new entry now — fs_eaccess,
 *                             which unlike a mode test knows about ownership,
 *                             groups, ACLs and root, and asks for the user the
 *                             write will be made as — or the row is skipped
 *                             (PERMISSION); a symlink to a directory is asked
 *                             through the link
 *   anything else             a non-directory no row names squats the
 *                             ancestry, and this run will not replace it (Coherent
 *                             Scope) — skipped (ANCESTOR), by hand. The rung
 *                             ran first, so nothing the load saw claims the
 *                             squatter: the skip's class is UNCLAIMED, the one
 *                             class this producer can find
 *   unreachable               EACCES is a refusal too (PERMISSION, with no
 *                             ancestor to name); any other errno is left for
 *                             the write to report
 *
 * The mechanism asks the very same questions of the very same ancestor
 * (ensure_parents), so this is a prediction of the run, not a model of it.
 *
 * The skip is written only on a refusal — the caller's zero skip stands when
 * the landing is clear — and its class only on the ANCESTOR one. The named ancestor
 * is a prefix of the planned path itself, so it travels as a byte length
 * (deploy_skip_t). A PERMISSION with an ancestor reads "<ancestor> is not
 * writable"; without one, "ancestry cannot be reached" — the zero length is itself
 * the honest fact (the offender could not be named).
 *
 * @param ws Workspace, for the claimed-ancestor lookup (must not be NULL)
 * @param verdicts The fates decided so far, for the deployable-directory test
 *        (must not be NULL)
 * @param path Planned path (must not be NULL)
 * @param skip The row's skip in the making (must not be NULL): PERMISSION or
 *        ANCESTOR, the refusing ancestor's prefix length (0 where none could be
 *        named), and UNCLAIMED on the ANCESTOR refusal alone
 */
static void check_landing(
    const workspace_t *ws, const deploy_preflight_t *verdicts,
    const char *path, deploy_skip_t *skip
) {
    char *scratch = heap_strdup(path);

    size_t slash;
    fs_occupant_t occ;
    bool is_dir;
    struct stat st;

    if (!nearest_ancestor(scratch, &slash, &occ, &is_dir, &st)) {
        if (errno == EACCES) {
            skip->reason = DEPLOY_SKIP_PERMISSION; /* no ancestor to name */
        }
        goto cleanup;                             /* anything else: the write reports it */
    }

    scratch[ancestor_len(slash)] = '\0';  /* the ancestor, on its own */

    if (directory_is_deployable(verdicts, scratch)) {
        goto cleanup;
    }
    if (is_dir && fs_eaccess(scratch, W_OK | X_OK)) {
        goto cleanup;
    }
    if (occ == FS_OCCUPANT_DIRECTORY && holdable_directory(ws, scratch, &st)) {
        goto cleanup;
    }

    skip->reason = is_dir ? DEPLOY_SKIP_PERMISSION : DEPLOY_SKIP_ANCESTOR;
    skip->ancestor = ancestor_len(slash);
    if (!is_dir) {
        skip->ancestor_class = DEPLOY_ANCESTOR_UNCLAIMED;
    }

cleanup:
    free(scratch);
}

/**
 * The ownership a row's write applies
 *
 * The sheet's word, resolved on this host (core/metadata.h metadata_ownership):
 * the claim's names where it names them, the invoker's own owner where it names
 * none, no change where it names no group. Applied on every run, raised or not:
 * on the invoker's own creation the owner restates what the kernel gave, and on
 * a refused syscall's second try (sys/filesystem.h) it is the correction that
 * hands root's node back — the pair is the same either way, so the primitive is
 * never asked which. The group is left to the creation: dotta reproduces no
 * kernel's rule for a new node's group. Whether this run may set the pair is
 * the ownership rung's question, not this one's.
 *
 * Strict ownership mode (strict_ownership=true): a name this host cannot resolve
 * is a fatal error, aborting deployment. Otherwise it is a warning, and no change
 * at all — the claim named someone, and a pair made up in its place would be
 * another claim.
 *
 * Pure decision, taken at preflight — no filesystem mutation — so the
 * strict_ownership abort is met before the prompt and never mid-run. A warning
 * is an anomaly report and travels in the preflight for the caller to print;
 * nothing here reads a verbosity flag, because the warning's visibility is not
 * this module's output policy to set.
 *
 * @param row The row, for its claim and its name in a message (must not be NULL)
 * @param strict_ownership Fail deployment if ownership cannot be resolved
 * @param warnings Preflight warnings, for a name this host cannot resolve (must
 *        not be NULL)
 * @param out_uid Resolved UID or -1 for no change (must not be NULL)
 * @param out_gid Resolved GID or -1 for no change (must not be NULL)
 * @return The strict_ownership refusal, or NULL — a name this host cannot resolve
 *         is otherwise a warning and no change
 */
static error_t resolve_deployment_ownership(
    const manifest_row_t *row, bool strict_ownership, string_array_t *warnings,
    uid_t *out_uid, gid_t *out_gid
) {
    CHECK_NULL(row);
    CHECK_NULL(warnings);
    CHECK_NULL(out_uid);
    CHECK_NULL(out_gid);

    /* The word as this host's ids, the pair the write applies whatever the run
     * holds — or a name this system does not know: which half, by the name the
     * claim gave it */
    const char *half = NULL;
    const char *name = NULL;
    switch (metadata_ownership(row->owner, row->group, out_uid, out_gid)) {
        case METADATA_OWNERSHIP_RESOLVED:
            return NULL;

        case METADATA_OWNERSHIP_NO_SUCH_USER:
            half = "User";
            name = row->owner;
            break;

        case METADATA_OWNERSHIP_NO_SUCH_GROUP:
            half = "Group";
            name = row->group;
            break;
    }

    /* Fatal under strict_ownership, a configuration or environment mismatch the
     * user asked to be stopped by */
    if (strict_ownership) {
        return error_wrap(
            ERROR(ERR_NOT_FOUND, "%s '%s' does not exist on this system", half, name),
            "Ownership resolution failed for '%s' (strict_ownership enabled)\n"
            "Hint: Create the user/group on this system, or disable "
            "strict_ownership", row->storage_path
        );
    }

    /* Otherwise a warning naming the half it could not find, and the deployment
     * continues */
    string_array_pushf(
        warnings, "Could not resolve ownership for %s: %s '%s' does not exist on "
        "this system", row->storage_path, half, name
    );

    /* No change, not a guess: a claim that cannot be honoured is not applied by
     * halves — not the half that resolved, and not the invoker for the half that
     * did not */
    *out_uid = (uid_t) -1;
    *out_gid = (gid_t) -1;
    return NULL;
}

/**
 * The ownership rung: the pair the write applies, and whether this run may set it
 *
 * The last rung, asked of a row every other rung passed. The ownership is resolved
 * for deployable rows alone — a skipped row can neither warn nor fail
 * strict_ownership (deploy_preflight's invariant) — so this is what is left once
 * the path's rungs had nothing to say, and the one rung a row planned absent
 * takes at all. The pair is resolve_deployment_ownership's, decided ahead of
 * the write so the write applies it atomically through the descriptor (fchown
 * on the file or directory fd, lchown on a link): there is never a moment when
 * the path exists with the wrong owner. Whether it is this run's to set is the
 * identity's (identity_may_chown): a run that holds root sets anything, one that
 * does not may neither give a file away nor set a group it does not hold — an
 * OWNERSHIP skip, an incapacity whose remedy is sudo. The pair a claimless row
 * resolves to — the invoker's own owner, no group — is always the run's to set,
 * and so is no change at all, an unknown owner under a warning.
 *
 * The mode is not decided here: the write reads it off the row, verbatim — total
 * for every kind that carries one (the claim, or the floor manifest_build resolved
 * absence into); a symlink row is never asked (symlink(2) takes no mode). The
 * verdict carries exactly the facts not on the row.
 *
 * @param opts Deployment options (must not be NULL)
 * @param warnings Preflight warnings (must not be NULL)
 * @param row The row (must not be NULL)
 * @param out_uid Ownership the write applies; -1 = no change (must not be NULL)
 * @param out_gid Same for the group (must not be NULL)
 * @param out_reason OWNERSHIP on a refusal, untouched otherwise (must not be NULL)
 * @return Error or NULL on success (a strict_ownership failure is one; a skip
 *         is not)
 */
static error_t check_ownership(
    const deploy_options_t *opts, string_array_t *warnings,
    const manifest_row_t *row, uid_t *out_uid, gid_t *out_gid,
    deploy_skip_reason_t *out_reason
) {
    error_t err = resolve_deployment_ownership(
        row, opts->strict_ownership, warnings, out_uid, out_gid
    );
    if (err) {
        return err;
    }

    if (!identity_may_chown(identity(), *out_uid, *out_gid)) {
        *out_reason = DEPLOY_SKIP_OWNERSHIP;
    }

    return NULL;
}

/**
 * Does a deployable row of either kind lie beneath `dir`?
 *
 * The question that makes a directory row outside the plan an ancestor the run
 * may create: ensure_parents climbs from each deployed path to its nearest present
 * ancestor and creates every component in between, so a directory row above no
 * deployable row is never reached. The reach is the verdicts', not the plan's:
 * a skipped row is never written, so an absent claimed ancestor whose only
 * descendants this run skips is never planned, never created, and can neither
 * warn nor fail strict_ownership (see deploy_preflight's invariant).
 *
 * @param verdicts Both verdict kinds decided (must not be NULL)
 * @param dir Directory path (must not be NULL)
 */
static bool above_deployable_row(
    const deploy_preflight_t *verdicts, const char *dir
) {
    const deploy_verdicts_t *kinds[] = { &verdicts->directories, &verdicts->files };
    size_t len = strlen(dir);

    for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
        for (size_t i = 0; i < kinds[k]->count; i++) {
            if (str_path_beneath(kinds[k]->entries[i].item->filesystem_path, dir, len)) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Decide the fate of every planned row: a verdict, or a skip
 *
 * Workspace = analysis layer, preflight = decision layer, execute = execution
 * layer. Divergence verdicts and occupants are read off the item each pending
 * bucket holds; the one filesystem-level question is the landing (and, for a
 * directory standing where a file belongs, the readdir under path_clearance).
 *
 * Every pending row gets exactly one fate — a verdict or a skip, the totality
 * equation — so the verdict arrays hold deployable rows alone and the executors
 * read them without a gate. A row planned beneath a squatter this run replaces
 * gets its verdict too — absent, nothing asked — so the executors read one shape
 * for every row; beneath a squatter this run skips, it takes that skip's class
 * instead, TYPE or ANCESTOR, and beneath one the run never reaches it is skipped
 * ANCESTOR — the ancestry rung (check_ancestry), asked before any probe of the
 * row's own.
 */
error_t deploy_preflight(
    const workspace_t *ws,
    const deploy_plan_t *plan,
    const deploy_options_t *opts,
    arena_t *arena,
    deploy_preflight_t **out
) {
    CHECK_NULL(ws);
    CHECK_NULL(plan);
    CHECK_NULL(opts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The verdicts and every array they are held in are the arena's, beside the
     * items they borrow: nothing frees them, and a failure below leaves a partial
     * preflight as the arena's bytes. */
    deploy_preflight_t *verdicts = arena_calloc(arena, 1, sizeof(*verdicts));
    string_array_init(&verdicts->warnings, arena);

    /* One slot per pending item — verdict or skip, so the skip array's bound is
     * both kinds together — and one per directory item for the ancestors (an
     * upper bound; the count says how many were decided). */
    workspace_items_t files = workspace_items(&plan->files.pending);
    workspace_items_t dirs = workspace_items(&plan->directories.pending);
    workspace_items_t all_dirs = workspace_directories(ws);

    verdicts->directories.entries = arena_calloc(arena, dirs.count, sizeof(deploy_verdict_t));
    verdicts->files.entries = arena_calloc(arena, files.count, sizeof(deploy_verdict_t));
    verdicts->ancestors.entries = arena_calloc(arena, all_dirs.count, sizeof(deploy_verdict_t));
    verdicts->skipped.entries = arena_calloc(
        arena, files.count + dirs.count, sizeof(deploy_skip_t)
    );

    /* Directories decide first, then files, then the ancestors — the order the
     * run acts in (deploy_execute), and the order deploy_plan_build classified
     * them in. A verdict is a prediction of what the run will find when it reaches
     * the row, so it is taken after the verdicts for everything the run reaches
     * first: a file's tracked ancestors are directory rows, converged and held
     * open before anything is written beneath them (an ancestor claim above it
     * is not converged at all — it is decided in the ancestors pass below), and
     * inside the directory pass the plan's prefix order puts every row after
     * its own ancestors. core/cleanup's preflight decides in its own run's order
     * for the same reason — there, children before parents, so a directory reads
     * the fates of everything it holds. The skips and the warnings come out in
     * that order too: the order the run would have met them.
     *
     * The ancestors come last though the run creates them first: which directory
     * rows it may make on the way is derived from the planned rows as a whole,
     * not decided row by row. */
    for (size_t i = 0; i < dirs.count; i++) {
        const workspace_item_t *item = dirs.entries[i];
        const char *path = item->filesystem_path;

        /* Its ancestry first, before any probe: a squatted directory row above
         * this path invalidates every look taken beneath it, the landing check's
         * included. Directories decide parents-first, so such an ancestor's own
         * fate is already taken. The row is decided into its skip: each rung
         * that refuses writes it — the reason, and the ancestor it names with
         * the claim there — and the row is skipped iff one did. */
        deploy_skip_t skip = { .item = item };
        bool absent = false;

        check_ancestry(ws, verdicts, path, &skip, &absent);

        /* The path's rungs, unless its ancestry answered. A row planned as absent
         * is asked none of them: the path is empty once the directory pass has
         * converged the ancestor — no type, no content, nothing in the way, and
         * the landing is that ancestor's. So its verdict's occupant is that
         * absence, where its item says only that nothing was looked at. */
        fs_occupant_t occupant = FS_OCCUPANT_NONE;

        if (skip.reason == DEPLOY_SKIP_NONE && !absent) {
            occupant = item->occupant;

            /* The rungs, first match wins — the enum's own order. A create or a
             * replace lands a new entry, which asks the parent (the landing); a
             * directory already there is converged in place, and fchmod and fchown
             * ask for the node's owner instead, the owner the load's look found
             * (FOREIGN). A row the workspace could not settle is asked too, and
             * skipped on its own account only when the landing had nothing to
             * say — as for a file. */
            if (deploy_convergence(occupant) != DEPLOY_CONVERGE_FIX) {
                check_landing(ws, verdicts, path, &skip);
            } else if (!identity_may_chmod(identity(), item->st.st_uid)) {
                skip.reason = DEPLOY_SKIP_FOREIGN;
            }

            /* A planned directory squatted by a non-directory (the link itself,
             * so a symlink to a directory counts) is replaced under --force,
             * one node at a time. The squatter can never be a directory — that
             * is the row converging in place — so path_clearance cannot refuse
             * here, TYPE is the only reachable arm, and "use --force" is always
             * the true remedy. */
            if (skip.reason == DEPLOY_SKIP_NONE && occupant_conflicts(occupant, item->row->type) &&
                path_clearance(path, occupant, opts->force) != CLEARANCE_OK) {
                skip.reason = DEPLOY_SKIP_TYPE;
            }

            /* The leftover, as for a file (the file ladder carries the rationale):
             * the fact is the UNVERIFIED bit; for an active directory row its
             * one producer today is the unstattable path (occupant UNKNOWN),
             * but the rung reads the fact, not its one current encoding, so the
             * two ladders keep one rule. */
            if (skip.reason == DEPLOY_SKIP_NONE && (item->divergence & DIVERGENCE_UNVERIFIED)) {
                skip.reason = DEPLOY_SKIP_UNREADABLE;
            }
        }

        /* The row's rung, last: the ownership the write applies, and whether
         * this run may set it (check_ownership). */
        uid_t uid = (uid_t) -1;
        gid_t gid = (gid_t) -1;

        if (skip.reason == DEPLOY_SKIP_NONE) {
            RETURN_IF_ERROR(
                check_ownership(
                opts, &verdicts->warnings, item->row, &uid, &gid, &skip.reason
                )
            );
        }

        if (skip.reason != DEPLOY_SKIP_NONE) {
            verdicts->skipped.entries[verdicts->skipped.count++] = skip;
            continue;
        }

        deploy_verdict_t *v = &verdicts->directories.entries[verdicts->directories.count++];

        v->item = item;
        v->occupant = occupant;
        v->uid = uid;
        v->gid = gid;
    }

    for (size_t i = 0; i < files.count; i++) {
        const workspace_item_t *item = files.entries[i];
        const char *path = item->filesystem_path;

        /* Its ancestry first (see the directory loop): the directory pass is
         * decided in full, so a squatted ancestor is converged, skipped, or out
         * of this run's reach by now. */
        deploy_skip_t skip = { .item = item };
        bool absent = false;

        check_ancestry(ws, verdicts, path, &skip, &absent);

        /* The path's rungs, unless its ancestry answered (see the directory loop):
         * a row planned as absent is written beneath a directory this run converges
         * first, so neither a conflict nor a landing question is its own. */
        fs_occupant_t occupant = FS_OCCUPANT_NONE;

        if (skip.reason == DEPLOY_SKIP_NONE && !absent) {
            occupant = item->occupant;

            /* The rungs, first match wins — the enum's own order. Every file
             * row lands through its parent, whichever arm writes it and whether
             * or not something is already at the path — so one question covers
             * both, and it is never about the path itself. */
            check_landing(ws, verdicts, path, &skip);

            if (skip.reason == DEPLOY_SKIP_NONE) {
                if (occupant_conflicts(occupant, item->row->type)) {
                    /* Type: what stands at the path decides the remedy, and whose
                     * it is decides the consent. STALE on a kind the row does
                     * not have is the workspace's proof that the occupant is
                     * exactly the copy dotta confirmed, Git having retyped the
                     * path beneath it (the file analysis's second question, asked
                     * under the base's kind): replacing it loses nothing, so it
                     * needs no --force, as a STALE row's bytes never do
                     * (deploy_content_conflicts). The proof is the bit and never
                     * an absence of conflict: the workspace's analyses read every
                     * kind mismatch it can see off the look, before any read
                     * and whatever the key (core/workspace.c
                     * workspace_analyze_file), so one without STALE carries TYPE
                     * and asks for --force. */
                    switch (path_clearance(
                        path, occupant, opts->force || (item->divergence & DIVERGENCE_STALE)
                        )) {
                        case CLEARANCE_OK:
                            break;

                        case CLEARANCE_NEEDS_FORCE:
                            skip.reason = DEPLOY_SKIP_TYPE;
                            break;

                        case CLEARANCE_REFUSED:
                            skip.reason = DEPLOY_SKIP_OCCUPIED;
                            break;
                    }
                } else if (!opts->force && deploy_content_conflicts(item)) {
                    /* Content, asked only when the occupant is the row's own
                     * type: a path holding something else has no content to compare
                     * — the mask's TYPE arm cannot fire here, a conflicting
                     * occupant took the TYPE rung above; it is load-bearing at
                     * the preview's other read. */
                    skip.reason = DEPLOY_SKIP_CONTENT;
                }
            }

            /* A row the workspace could not settle is no verdict — the UNVERIFIED
             * bit, not its unstattable symptom. The bit has two producers: the
             * path could not be lstat'd (occupant UNKNOWN, which no rung above
             * judges — UNKNOWN is not present), or the look at its content failed
             * with the row's own kind standing — a blob that could not be loaded,
             * decrypted or compared, an open the file refused — which the content
             * rung cannot catch either: a failed look accumulates no content
             * verdict. (A kind mismatch makes no content look to fail: it is
             * judged off the lstat before any read, and TYPE takes it above.)
             * Nothing can say what the run will find there, or that the write's
             * own read will fare better, and nothing is written on a guess. The
             * ancestry that refused an lstat is what refuses the write, and the
             * landing has just named it when it could (EACCES on the way up);
             * the row is skipped on its own account only when the landing had
             * nothing to say — a failure the run would otherwise have met mid-run,
             * after siblings already wrote. */
            if (skip.reason == DEPLOY_SKIP_NONE && (item->divergence & DIVERGENCE_UNVERIFIED)) {
                skip.reason = DEPLOY_SKIP_UNREADABLE;
            }
        }

        /* The row's rung, last (see the directory loop). */
        uid_t uid = (uid_t) -1;
        gid_t gid = (gid_t) -1;

        if (skip.reason == DEPLOY_SKIP_NONE) {
            RETURN_IF_ERROR(
                check_ownership(
                opts, &verdicts->warnings, item->row, &uid, &gid, &skip.reason
                )
            );
        }

        if (skip.reason != DEPLOY_SKIP_NONE) {
            verdicts->skipped.entries[verdicts->skipped.count++] = skip;
            continue;
        }

        deploy_verdict_t *v = &verdicts->files.entries[verdicts->files.count++];

        v->item = item;
        v->occupant = occupant;
        v->uid = uid;
        v->gid = gid;
    }

    /* The ancestors: every directory row the run does not act on, absent as the
     * run will find it, that stands above a deployable row. Absent has two
     * readings, both fate-aware now: the rung's — beneath a squatted ancestor
     * the run converges first — or the workspace's own occupant (a clean item's
     * is its look, present). ensure_parents creates exactly these on the way
     * down to a deployed path, with the metadata decided here; a candidate the
     * world makes present before then is simply not created and costs nothing,
     * and one made present past the probe meets the create's refusal, never a
     * convergence (fs_create_dir_exclusive).
     *
     * Every gate reads the verdicts, not the plan: a skipped directory row flows
     * past the first into the candidate pool, and the later gates keep it out —
     * one skipped beneath a squatted ancestor that stays is not a parent this
     * run can make (the rung's reason), a TYPE-, FOREIGN- or UNREADABLE-skipped
     * row is not absent (present, as its item read), and a landing-skipped one
     * has no deployable row beneath it (the invariant, deploy_preflight's doc). */
    for (size_t i = 0; i < all_dirs.count; i++) {
        const workspace_item_t *item = all_dirs.entries[i];
        const char *path = item->filesystem_path;

        if (directory_is_deployable(verdicts, path)) {
            continue;
        }

        /* Its ancestry, as the ladders ask it. An ancestor takes no skip (below),
         * so this one is the rung's answer alone: its reason is read and it is
         * never pushed. */
        deploy_skip_t skip = { .item = item };
        bool absent = false;

        check_ancestry(ws, verdicts, path, &skip, &absent);
        if (skip.reason != DEPLOY_SKIP_NONE) {
            continue;   /* skipped beneath a squatted ancestor that stays */
        }

        if (!(absent || item->occupant == FS_OCCUPANT_NONE) ||
            !above_deployable_row(verdicts, path)) {
            continue;
        }

        deploy_verdict_t *v = &verdicts->ancestors.entries[verdicts->ancestors.count++];

        v->item = item;
        v->occupant = FS_OCCUPANT_NONE;

        /* The pair, without the ownership rung: an ancestor is outside the plan
         * and has no skip to take, and the rows beneath it are decided by now.
         * A pair this run cannot set meets the refusal at the create, named on
         * the row beneath as its outcome (create_ancestor) and leaving nothing
         * behind (fs_create_dir_exclusive) — the under-approximation this pass
         * accepts for a foreign-owned derived claim above a landing the invoker
         * can write. */
        RETURN_IF_ERROR(
            resolve_deployment_ownership(
            item->row, opts->strict_ownership, &verdicts->warnings, &v->uid, &v->gid
            )
        );
    }

    *out = verdicts;
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Execute
 * ══════════════════════════════════════════════════════════════════ */

/**
 * A directory the run holds at a working mode until the paths beneath it have
 * landed
 */
typedef struct {
    const char *path;    /* borrowed from the directory row (workspace-arena lifetime) */
    mode_t mode;         /* the mode it is released to */
} held_directory_t;

/**
 * One execution of the verdicts: what deploy_execute was handed, plus the state
 * the run accumulates. Lives exactly as long as deploy_execute.
 */
typedef struct {
    git_repository *repo;
    content_cache_t *cache;
    const workspace_t *ws;              /* a landing directory's row (holdable_directory) */
    const deploy_preflight_t *verdicts; /* the ancestors' metadata (create_ancestor) */
    deploy_receipt_t *receipt;          /* the receipt so far (the ancestors bucket) */
    arena_t *arena;                     /* the held directories live here */
    ptr_array_t held;                   /* held_directory_t *, in the order taken */
} deploy_run_t;

/**
 * The mode a directory carries while this run writes beneath it
 *
 * The recorded mode with the owner triad forced on. Everything the run lands
 * beneath a directory lands through the owner's own write and search bits — mkdir
 * for a child directory, mkstemp and rename for a file, symlink for a link — so
 * a recorded mode that lacks them (0555, 0500, a 0600 captured on a directory
 * the walker could not enter) would refuse the very children it was captured
 * with. Two phases instead: materialize at the working mode, write the subtree,
 * then release each held directory to its exact recorded mode, deepest-first
 * (release_directories). Group and other bits are never widened — a 0700 directory
 * is 0700 throughout — and the window is the owner's own, for the duration of
 * the run. cmd_export materializes a profile the same way (export.c,
 * materialize_entries); this is the same rule on the other materializer.
 */
static mode_t working_mode(mode_t mode) {
    return mode | S_IRWXU;
}

/**
 * Remember a directory to release at the end of the run
 *
 * Only a directory whose target mode is narrower than its working mode needs
 * holding — for the rest (0755, 0700, …) the working mode IS the target, so nothing
 * is recorded and nothing is done twice. `path` must outlive the run: callers
 * pass the directory row's own filesystem_path.
 */
static void hold_directory(deploy_run_t *run, const char *path, mode_t mode) {
    if (working_mode(mode) == mode) return;

    held_directory_t *held = arena_alloc(run->arena, sizeof(*held));
    held->path = path;
    held->mode = mode;

    ptr_array_push(&run->held, held);
}

/**
 * Release every held directory to its exact mode, deepest-first
 *
 * Holds are taken top-down — the directory pass runs in prefix order and
 * ensure_parents creates from the nearest present ancestor downward — so reverse
 * order releases a child before its parent, and a parent released to a mode without
 * owner-search never stands between us and a child still to be released.
 *
 * Runs at the end of every deploy_execute: however the rows fared, every held
 * directory carries its recorded mode again, and the next run holds what it needs
 * afresh. Applied through fs_create_dir_with_ownership — the same fd-based fchmod
 * the converge arm uses, never a chmod(2) on a path that may have become a symlink
 * meanwhile. Every entry is attempted; the first failure is the one reported.
 */
static error_t release_directories(deploy_run_t *run) {
    error_t err = NULL;

    for (size_t i = run->held.count; i-- > 0;) {
        const held_directory_t *held = run->held.entries[i];
        error_t release_err = fs_create_dir_with_ownership(
            held->path, held->mode, (uid_t) -1, (gid_t) -1
        );

        /* The first failure is the one reported; the rest are dropped, one per
         * held directory that would not release */
        if (release_err && !err) {
            err = error_wrap(
                release_err, "Failed to release directory '%s' to mode %04o",
                held->path, held->mode
            );
        }
    }

    return err;
}

/**
 * Create or converge a claimed directory at its working mode
 *
 * Ownership applies atomically through the descriptor
 * (fs_create_dir_with_ownership); idempotent, so a directory already there is
 * converged in place. The idempotence is the planned row's privilege — a row in
 * the plan is the run's to converge; the ancestors pass, which may only create,
 * goes through fs_create_dir_exclusive instead (create_ancestor). The mode is
 * the row's, the ownership the verdict's, and the row is held for release when
 * its recorded mode is narrower than the working mode (hold_directory).
 *
 * @param run Run context (must not be NULL)
 * @param v Verdict for the directory row (must not be NULL; borrowed, read-only)
 * @return Error or NULL on success
 */
static error_t materialize_directory(
    deploy_run_t *run, const deploy_verdict_t *v
) {
    const manifest_row_t *dir = v->item->row;

    RETURN_IF_ERROR(
        fs_create_dir_with_ownership(
        dir->filesystem_path, working_mode(dir->mode), v->uid, v->gid
        )
    );
    hold_directory(run, dir->filesystem_path, dir->mode);

    return NULL;
}

/**
 * Materialize one absent ancestor whose own parent exists: a directory the view
 * claims (any profile, in scope or not, either class) with the metadata its
 * ancestor verdict carries, anything else with the word no claim makes — the
 * mode DIR_MODE_DEFAULT, the invoker's own owner, no group (core/metadata.h
 * metadata_ownership) — the pair a claimless row gets, so a directory the second
 * try made root's is handed back like the leaf beneath it. Not a borrowing: the
 * leaf's owner is never read, so a service user's claim below never reaches the
 * system directories above it. An identity that cannot create it meets the refusal
 * an invention would have papered over. The default is exact (fchmod), not
 * umask-masked — dotta reproduces modes, it does not negotiate them — and already
 * carries the owner triad, so a parent no row claims is never held.
 *
 * The verdicts are the authority for what is claimed here, not the view: a
 * directory row preflight did not foresee as absent (present then, gone since)
 * has no metadata decided for it, is made like an unclaimed parent, and is left
 * for the next load to read — which sees its record and its row, and, where the
 * row is tracked, says [mode] if the two disagree.
 *
 * Creation only, either class (fs_create_dir_exclusive): every path this pass
 * makes was absent when the run probed it, and one the world made present in
 * between meets ERR_EXISTS as the row's outcome — not this run's to converge,
 * the way a planned row would be (materialize_directory). The header's stance
 * on every mid-run surprise, applied to the make itself.
 *
 * @param run Run context (must not be NULL)
 * @param path Absent ancestor to create (must not be NULL)
 * @return Error or NULL on success
 */
static error_t create_ancestor(deploy_run_t *run, const char *path) {
    const deploy_verdicts_t *ancestors = &run->verdicts->ancestors;

    for (size_t i = 0; i < ancestors->count; i++) {
        const deploy_verdict_t *v = &ancestors->entries[i];

        if (strcmp(v->item->filesystem_path, path) != 0) {
            continue;
        }

        const manifest_row_t *dir = v->item->row;

        RETURN_IF_ERROR(
            fs_create_dir_exclusive(
            dir->filesystem_path, working_mode(dir->mode), v->uid, v->gid
            )
        );
        hold_directory(run, dir->filesystem_path, dir->mode);

        /* On the receipt once — and bounds the sized array: a parent present at
         * an earlier row's write and removed since is re-made here, and without
         * this scan the second re-make would write past entries[count]. */
        deploy_outcomes_t *receipt = &run->receipt->ancestors;
        for (size_t j = 0; j < receipt->count; j++) {
            if (receipt->entries[j].verdict == v) {
                return NULL;
            }
        }
        receipt->entries[receipt->count++].verdict = v;
        return NULL;
    }

    /* A parent no row claims: the word no claim makes, asked of its one producer
     * rather than spelled here a second time — two absences name nothing to miss,
     * so the pair always resolves. Left root's, the next climb through this
     * directory would claim it root's (metadata_capture_ancestors), and dotta's
     * own artefact would enter the sheet as intent. */
    uid_t uid;
    gid_t gid;
    (void) metadata_ownership(NULL, NULL, &uid, &gid);

    return fs_create_dir_exclusive(path, DIR_MODE_DEFAULT, uid, gid);
}

/**
 * Open a planned path's landing directory for the run
 *
 * The nearest present ancestor is where the write lands, and it must accept a
 * new entry. An absent chain below it is created at working modes and cannot
 * refuse; the ancestor itself can — a claimed 0555 directory that is already
 * exactly as recorded refuses the very child it was captured with. When it is
 * ours (holdable_directory) the run holds it at a working mode, built from its
 * current mode so that the release restores exactly what was there, recorded or
 * not (an excluded or out-of-scope row is not the plan's to converge). Anything
 * else is left alone and the write reports the refusal.
 *
 * The questions check_landing asked of the same ancestor, less the one time has
 * answered: a pending row has been converged by the directory pass before any
 * file lands, so it stands here as a directory at its working mode and fs_eaccess
 * simply passes. Prediction and mechanism, one rule.
 *
 * @param run Run context (must not be NULL)
 * @param ancestor Nearest present ancestor, NUL-terminated (must not be NULL)
 * @param occ What stands there
 * @param st Its lstat
 * @return Error or NULL on success
 */
static error_t open_landing_directory(
    deploy_run_t *run,
    const char *ancestor,
    fs_occupant_t occ,
    const struct stat *st
) {
    if (occ != FS_OCCUPANT_DIRECTORY || fs_eaccess(ancestor, W_OK | X_OK)) {
        return NULL;
    }

    const manifest_row_t *dir = holdable_directory(run->ws, ancestor, st);
    if (!dir) {
        return NULL;  /* not ours: the write meets the refusal */
    }

    mode_t current = st->st_mode & 0777;
    error_t err = fs_create_dir_with_ownership(
        dir->filesystem_path, working_mode(current), (uid_t) -1, (gid_t) -1
    );
    if (err) {
        return error_wrap(
            err, "Failed to open directory '%s' for the run",
            ancestor
        );
    }
    hold_directory(run, dir->filesystem_path, current);

    return NULL;
}

/**
 * Create the missing parents of a planned path, top-down from its nearest present
 * ancestor — opening that ancestor for the run first when it is ours and refuses.
 *
 * Mutation, not decision. Whether the path can land was preflight's question,
 * and the directory pass has already replaced any planned squatter above it; a
 * non-directory ancestor met here (a prompt sat in between) is a named error
 * rather than a mkdir errno. A dangling symlink is one: mkdir would report EEXIST
 * for a path that leads nowhere.
 *
 * @param run Run context (must not be NULL)
 * @param path Planned path whose parents must exist (must not be NULL)
 * @return Error or NULL on success
 */
static error_t ensure_parents(deploy_run_t *run, const char *path) {
    char *scratch = heap_strdup(path);

    error_t err = NULL;
    size_t ancestor_slash;
    fs_occupant_t occ;
    bool is_dir;
    struct stat st;
    if (!nearest_ancestor(scratch, &ancestor_slash, &occ, &is_dir, &st)) {
        goto cleanup;                            /* let the write surface the errno */
    }

    size_t len = ancestor_len(ancestor_slash);
    char saved = scratch[len];
    scratch[len] = '\0';                         /* the ancestor, on its own */

    if (!is_dir) {
        err = ERROR(
            ERR_FS, "Cannot create parents of '%s': '%s' is not a directory",
            path, scratch
        );
        goto cleanup;
    }
    err = open_landing_directory(run, scratch, occ, &st);
    scratch[len] = saved;
    if (err) goto cleanup;

    /* Every slash past the ancestor ends one missing parent; the final component
     * is the planned path itself. */
    char *tail = scratch + ancestor_slash + 1;
    for (char *slash = strchr(tail, '/'); slash; slash = strchr(slash + 1, '/')) {
        *slash = '\0';
        err = create_ancestor(run, scratch);
        *slash = '/';
        if (err) {
            err = error_wrap(
                err, "Failed to create parent directory for '%s'",
                path
            );
            goto cleanup;
        }
    }

cleanup:
    free(scratch);
    return err;
}

/**
 * Deploy a single view row to its filesystem path.
 *
 * Mechanism only: the verdict says what stands at the path and what the write
 * applies, and this lands it — missing parents first, then the one arm the row's
 * type calls for. Nothing here looks at the disk to decide anything; a path the
 * world has moved under since preflight meets the mechanism's refusal (rename
 * over a directory is EISDIR, symlink over anything is EEXIST, rmdir of a directory
 * that filled up is ENOTEMPTY) and the refusal is the row's outcome.
 *
 * The row:
 * - file->type: which arm — a symlink is re-linked from its blob, anything else
 *   is written from the content cache
 * - file->encrypted: handled transparently by the content cache
 * - file->blob_oid: the tree entry's, by construction — a blob row never carries
 *   a zero OID
 *
 * @param run Run context (must not be NULL)
 * @param v Verdict for the row (must not be NULL; the row is borrowed from the
 *          workspace's view, read-only for deploy)
 * @param out_stat The stat the write authored, in the record's vocabulary (must
 *          not be NULL): the regular arm distills the written descriptor's fstat
 *          (state_stat_from_write — taken before the rename that publishes it,
 *          so it describes exactly the bytes this run wrote); the symlink arm
 *          leaves the entry default standing. UNSET on every error return
 * @return Error or NULL on success
 */
static error_t deploy_file(
    deploy_run_t *run, const deploy_verdict_t *v, state_stat_t *out_stat
) {
    /* The stat's resting state: UNSET unless the regular arm's write lands and
     * binds its own fstat below. The symlink arm never does — a link is made by
     * path (symlink(2) opens no descriptor to describe), and readlink is its
     * whole re-verification. */
    *out_stat = STATE_STAT_UNSET;

    const manifest_row_t *file = v->item->row;

    error_t err = NULL;
    const buffer_t *content_buffer = NULL;  /* Borrowed from cache */
    char *target_str = NULL;

    /* Land the path: parents first, whichever arm writes it */
    err = ensure_parents(run, file->filesystem_path);
    if (err) return err;

    /* Handle symlinks - these are never encrypted, so handle separately */
    if (file->type == PATH_TYPE_SYMLINK) {
        /* A link's blob is its target, never sealed (infra/content.h), so it is
         * read raw and handed to symlink(2) as it stands. */
        size_t target_len = 0;
        err = gitops_read_blob_content(
            run->repo, &file->blob_oid, (void **) &target_str, &target_len
        );
        if (err) goto cleanup;

        /* symlink(2) refuses an occupied path outright, so whatever stands there
         * goes first — mechanism, not policy: an occupant of the link's own kind
         * too, which is no conflict and needed no --force. The one the verdict
         * named, never one found by a fresh look from down here. */
        if (deploy_occupant_present(v->occupant)) {
            err = clear_occupant(file->filesystem_path, v->occupant);
            if (err) goto cleanup;
        }

        /* Create the link with the ownership the verdict resolved: the one node
         * without a descriptor, so the primitive applies the pair itself. */
        err = fs_create_symlink(
            target_str, file->filesystem_path, v->uid, v->gid
        );
        if (err) {
            err = error_wrap(
                err, "Failed to deploy symlink '%s'",
                file->filesystem_path
            );
            goto cleanup;
        }

        goto cleanup;
    }

    /* Regular files: content from the cache with transparent decryption */
    err = content_cache_get_from_blob_oid(
        run->cache,
        &file->blob_oid,
        path_type_to_git_filemode(file->type),
        file->storage_path,
        file->profile,
        &content_buffer
    );

    if (err) {
        err = error_wrap(
            err, "Failed to get content for '%s'",
            file->storage_path
        );
        goto cleanup;
    }

    const unsigned char *content = (const unsigned char *) content_buffer->data;
    size_t size = content_buffer->size;

    /* fs_write_file_raw lands the content by rename(2) of a temp file over the
     * target, which replaces a regular file, a symlink (the link itself, not
     * what it points to) or a device in place — but never a directory (EISDIR).
     * Only that one case needs clearing first. */
    if (v->occupant == FS_OCCUPANT_DIRECTORY) {
        err = clear_occupant(file->filesystem_path, v->occupant);
        if (err) goto cleanup;
    }

    /* Write directly from git blob to filesystem with atomic ownership and
     * permissions.
     * SECURITY: fs_write_file_raw atomically sets BOTH ownership and permissions
     * via fchown() and fchmod() on the file descriptor, eliminating any security
     * window. This is the ONLY place where ownership is applied - the verdict
     * only resolves. */
    struct stat written;
    err = fs_write_file_raw(
        file->filesystem_path, content, size, file->mode, v->uid, v->gid, &written
    );

    if (err) {
        err = error_wrap(
            err, "Failed to deploy file '%s'",
            file->filesystem_path
        );
        goto cleanup;
    }

    /* The write's own stat, distilled where the write authority is in scope:
     * authorship, not a read, vouches for the triple, so its own open second
     * needs no smudge (state_stat_from_write). */
    *out_stat = state_stat_from_write(&written);

cleanup:
    free(target_str);
    return err;
}

/**
 * Materialize one planned tracked directory to its expected state.
 *
 * Mechanism only, by the verdict's occupant: a squatter is cleared (one node,
 * the one the verdict named), an absent path gets its missing parents, and then
 * the create-or-fix, which is idempotent — a planned directory whose reality
 * healed meanwhile is simply confirmed, and one a prompt-window race turned into
 * a symlink is refused by O_NOFOLLOW rather than chmod'd through.
 *
 * The directory lands at its working mode and is released to its exact recorded
 * mode once the run is over (working_mode, release_directories), so a recorded
 * mode without owner-write never refuses the tracked children written after it.
 *
 * @param run Run context (must not be NULL)
 * @param v Verdict for the row (must not be NULL; the row is borrowed, read-only)
 * @return Error or NULL on success
 */
static error_t deploy_directory(deploy_run_t *run, const deploy_verdict_t *v) {
    const char *path = v->item->filesystem_path;

    switch (v->occupant) {
        case FS_OCCUPANT_DIRECTORY:
            /* Converged in place below */
            break;

        case FS_OCCUPANT_NONE:
            /* Absent — or beneath a non-directory, which preflight blocked when
             * unplanned and the directory pass replaces when planned (prefix
             * order); one still there is ensure_parents' named error. */
            RETURN_IF_ERROR(ensure_parents(run, path));
            break;

        case FS_OCCUPANT_UNKNOWN:
            /* Not a verdict: preflight turned it into a skip, and a skip never
             * enters the verdict arrays. Said here rather than unlinked. */
            CHECK_ARG(false, "a look that failed never enters the verdicts");

        case FS_OCCUPANT_REGULAR:
        case FS_OCCUPANT_SYMLINK:
        case FS_OCCUPANT_OTHER:
            /* A single node in the way, cleared before the mkdir — the node the
             * verdict named. It can never be a directory (that is the first arm),
             * and --force was preflight's question. */
            RETURN_IF_ERROR(clear_occupant(path, v->occupant));
            break;
    }

    /* Create-or-fix with atomic ownership and permissions (fchown/fchmod on the
     * directory fd — no window with wrong metadata). Idempotent. */
    error_t err = materialize_directory(run, v);
    if (err) {
        return error_wrap(err, "Failed to create directory: %s", path);
    }

    return NULL;
}

/**
 * The failed directory whose absence poisons this path, or NULL
 *
 * Deploy's order is parents-first and its mechanism creates on the way down, so
 * per-row failure needs the preflight invariant's execution mirror: a failed
 * directory verdict whose convergence was not a fix left no directory standing
 * at its path — the create never happened, or the squatter survived its replace
 * — and a write beneath it would land through whatever stands there (ensure_parents
 * would fabricate the failed directory as an unclaimed 0755, or write through
 * the surviving squatter: the hazard the ancestry rung refuses at preflight,
 * met again at execution time). A failed converge-in-place poisons nothing: the
 * directory stands, and children land in it or fail on their own merits. Scanned
 * in verdict order, so the first match is the outermost failed ancestor — the
 * offender every deeper row is named against. The failed bucket is empty on every
 * healthy run, which is what makes the scan free.
 */
static const char *poisoned_above(const deploy_receipt_t *receipt, const char *path) {
    for (size_t i = 0; i < receipt->failed.count; i++) {
        const deploy_verdict_t *v = receipt->failed.entries[i].verdict;
        const char *dir = v->item->filesystem_path;

        if (v->item->item_kind != PATH_KIND_DIRECTORY ||
            deploy_convergence(v->occupant) == DEPLOY_CONVERGE_FIX) {
            continue;
        }
        if (str_path_beneath(path, dir, strlen(dir))) {
            return dir;
        }
    }

    return NULL;
}

/**
 * Carry the verdicts out
 *
 * Every exit passes through release_directories: a held directory takes its exact
 * recorded mode however the rows fared, so the tree a failure leaves behind is
 * incomplete but never wider than recorded. Row failures land in the receipt
 * (deploy_receipt_t's contract); the receipt travels in *out beside a release
 * error too, complete.
 */
error_t deploy_execute(
    git_repository *repo,
    const workspace_t *ws,
    const deploy_preflight_t *verdicts,
    content_cache_t *cache,
    arena_t *arena,
    deploy_receipt_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ws);
    CHECK_NULL(verdicts);
    CHECK_NULL(cache);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The receipt is sized to the verdicts up front, in the arena the run is
     * handed — one slot per verdict, zeroed, filled in verdict order as each
     * act lands (a zeroed slot's stat IS the UNSET triple), the failed bucket
     * to both kinds together — every promised row could fail. count gates what
     * a consumer reads, so an untaken slot is invisible and the receipt holds
     * exactly what happened — for a landed file, with its own write's stat. */
    deploy_receipt_t *receipt = arena_calloc(arena, 1, sizeof(*receipt));
    receipt->deployed.entries = arena_calloc(
        arena, verdicts->files.count, sizeof(*receipt->deployed.entries)
    );
    receipt->converged.entries = arena_calloc(
        arena, verdicts->directories.count, sizeof(*receipt->converged.entries)
    );
    receipt->ancestors.entries = arena_calloc(
        arena, verdicts->ancestors.count, sizeof(*receipt->ancestors.entries)
    );
    receipt->failed.entries = arena_calloc(
        arena, verdicts->directories.count + verdicts->files.count,
        sizeof(*receipt->failed.entries)
    );

    deploy_run_t run = {
        .repo     = repo,
        .cache    = cache,
        .ws       = ws,
        .verdicts = verdicts,
        .receipt  = receipt,
        .arena    = arena,
    };
    ptr_array_init(&run.held, arena);

    /* Directories first: parents before the files beneath them, and under --force
     * a squatting symlink is gone before anything is written through it. Verdict
     * order is the plan's prefix order = parents before children, which is also
     * what lets a replace settle everything beneath it: a planned path under a
     * replaced directory carries an absent occupant, and by the time it is reached
     * the replace has made that true. */
    for (size_t i = 0; i < verdicts->directories.count; i++) {
        const deploy_verdict_t *v = &verdicts->directories.entries[i];
        const char *above = poisoned_above(receipt, v->item->filesystem_path);

        error_t err = above ? ERROR(ERR_FS, "'%s' was not converged", above)
                            : deploy_directory(&run, v);
        if (err) {
            /* The row's own outcome; the cause already names its subject */
            deploy_outcome_t *o = &receipt->failed.entries[receipt->failed.count++];

            o->verdict = v;
            o->error = err;
            continue;
        }

        /* Record success; the verb is the verdict's occupant */
        receipt->converged.entries[receipt->converged.count++].verdict = v;
    }

    /* Every verdict is work the plan chose, by construction: the planner routed
     * the row through deploy_needs_work and past every reason to skip it, so
     * this loop applies no filter of its own. Clean in-scope rows with deployed_at
     * == 0 are apply's adoption step, which stamps the path owned without
     * deploy_file. */
    for (size_t i = 0; i < verdicts->files.count; i++) {
        const deploy_verdict_t *v = &verdicts->files.entries[i];
        deploy_outcome_t *o = &receipt->deployed.entries[receipt->deployed.count];
        const char *above = poisoned_above(receipt, v->item->filesystem_path);

        error_t err = above ? ERROR(ERR_FS, "'%s' was not converged", above)
                            : deploy_file(&run, v, &o->stat);
        if (err) {
            /* The row's own outcome, as above. The deployed slot stays untaken:
             * count never covers it, and its stat is UNSET on every deploy_file
             * error return. */
            deploy_outcome_t *f = &receipt->failed.entries[receipt->failed.count++];

            f->verdict = v;
            f->error = err;
            continue;
        }

        /* Record success */
        o->verdict = v;
        receipt->deployed.count++;
    }

    /* The subtree is as complete as it is going to get: exact modes now. The
     * rows' failures are in the receipt; what the release returns is the run's
     * one non-row error, and the receipt travels beside it either way. */
    *out = receipt;
    return release_directories(&run);
}
