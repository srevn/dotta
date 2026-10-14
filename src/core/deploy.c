/**
 * deploy.c - File and directory deployment engine implementation
 */

#include "core/deploy.h"

#include <errno.h>
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
 * Kind-agnostic: directory analysis tags only MODE / OWNERSHIP / CLAIM_MOVED /
 * TYPE / STALE / UNVERIFIED, so the DEPLOYED arm's test already covers every
 * directory verdict — no kind-specific arm. A file row can carry ENCRYPTION beside
 * any of those; the arm masks it either way.
 *
 * The planner walks the active items, so the five states an orphan or a scan
 * item takes never reach this: their arms name the owner that does handle them,
 * keep -Wswitch quiet, and die with the tail — answered false, the item would
 * fall to the clean bucket, which adoption reads.
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
        case WORKSPACE_STATE_UNSCANNED:
        /* A place the scan could not look: nobody's work, and never among the
         * active items either. */
        case WORKSPACE_STATE_OVERRIDDEN:
        /* A record whose profile still claims its path, standing nowhere: the
         * copy is left for the row standing over it, which is deploy's — never
         * the copy. */
        case WORKSPACE_STATE_RELEASED:
            /* The path left its profile in Git (an external commit, a pulled
             * removal, a vanished branch), or dotta never deployed it, and it
             * was released from management. Never needs deployment — cleanup
             * reports it and apply's record phase retires its record. */
            break;
    }

    /* An item the planner cannot hand in: one of the five above, or a value no
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
 * (cleanup_skip_reason_t). In this module "hold" means only a deploy_hold_t — a
 * directory carried at a working mode until the release lets it go
 * (deploy_release).
 */
typedef enum {
    SKIP_NONE,       /* nothing stands in the way of the row's work */
    SKIP_EXCLUDED,   /* an -e pattern matched the row's mount-relative path */
    SKIP_EXISTING    /* --skip-existing and something occupies the path */
} skip_reason_t;

/**
 * Add one active item in scope to its partition's bucket, or to none
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
 * The plan's one writer: the bucket an item goes to is named here and nowhere
 * else, and the plan's buckets are filled once the walk is done
 * (deploy_plan_build).
 *
 * @param buckets The plan's buckets (must not be NULL)
 * @param part Partition for the item's kind (must not be NULL)
 * @param item An active item in scope, borrowed (must not be NULL)
 * @param skip Why the item's work is skipped, if it is
 */
static void deploy_classify(
    workspace_buckets_t *buckets, deploy_partition_t *part, const workspace_item_t *item,
    skip_reason_t skip
) {
    if (!deploy_needs_work(item)) {
        /* Excluded: neither work nor apply's to own */
        if (skip != SKIP_EXCLUDED) workspace_buckets_add(buckets, item, &part->clean);
        return;
    }

    switch (skip) {
        case SKIP_NONE:
            workspace_buckets_add(buckets, item, &part->pending);
            return;
        case SKIP_EXCLUDED:
            workspace_buckets_add(buckets, item, &part->excluded);
            return;
        case SKIP_EXISTING:
            workspace_buckets_add(buckets, item, &part->skipped_existing);
            return;
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

    /* The plan and its eight buckets are the arena's, beside the items they borrow,
     * and nothing frees a plan. Each item is added to its bucket as the walk
     * decides it, and the eight are filled once the walk is done. */
    deploy_plan_t *plan = arena_calloc(arena, 1, sizeof(*plan));
    workspace_buckets_t *buckets = workspace_buckets_create(arena);

    /* Directories then files — the order the run acts in, each kind in path order,
     * which preflight merges into one (deploy_preflight). Convention alone: each
     * row's classification reads the workspace and the scope, never the buckets,
     * so neither loop depends on the other having run. */
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
         * must not take ownership of a parent it found already there). Save a
         * claim dotta's own copy squats, the view having moved past it — Git,
         * or the layer requiring the directory at a blob's place the claims beneath
         * it took (core/manifest.c manifest_layer) — STALE, the workspace's proof
         * (core/workspace.c workspace_analyze_directory), alone where the copy
         * is untouched and beside TYPE where it was edited: that squatter is
         * the view's pending move, the run's to converge as a tracked row's
         * squatter is — cleared at its own rung in the directory pass, parents
         * first, so nothing beneath it is written through what stood there, and
         * created in its place, the type rung deciding whether unasked or under
         * --force (deploy_preflight). Its convergence is always a replace: STALE
         * stands on a directory row only where another kind does. Prior to scope,
         * because scope decides reach and this decides whether there is anything
         * to reach for. */
        if (!item->row->tracked && !(item->divergence & DIVERGENCE_STALE)) continue;

        if (!scope_accepts_profile(scope, item->profile) ||
            !scope_accepts_path(
            scope, item->filesystem_path, item->storage_path, PATH_KIND_DIRECTORY
            )) {
            continue;                        /* out of scope: invisible */
        }

        /* No SKIP_EXISTING arm: --skip-existing does not reach tracked directories
         * (see deploy_partition_t). */
        deploy_classify(
            buckets, &plan->directories, item,
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

        deploy_classify(buckets, &plan->files, item, skip);
    }

    workspace_buckets_fill(buckets);
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
 * the user's stands there: an occupant the workspace proved is the very copy
 * dotta confirmed, Git having moved the kind past it, is replaced unasked under
 * a file row and a directory row alike, as a STALE row's bytes are overwritten
 * (the ladder's type rung, which hands the proof in).
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
 * @param consent Whether replacing it is consented: --force, or the workspace's
 *        proof that the occupant is dotta's own copy, untouched
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
 * before the ladder reaches a probe; this probe's answer stands for the ones no
 * claim names, the user's own arrangement. Exactly so: an enabled claim at an
 * ancestor of a planned row leaves a directory row standing there, the rung's
 * to guard, or no row would stand beneath it (core/manifest.c manifest_layer).
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
 * May the run hold this directory where it stands?
 *
 * A hold sets a standing directory's mode through the directory's own descriptor,
 * opened for reading (sys/filesystem.h fs_set_dir_mode), and a fix converges
 * one through the same open (fs_create_dir_with_ownership). So the run may hold
 * it only where it may change the node — its owner, or a run that holds root
 * (identity_may_chmod) — and the node's bits grant it the read (fs_denied): a
 * directory the run owns and may not read is no more its to hold than another's.
 * A run that holds root passes both, save where the bits deny root as well.
 *
 * Asked wherever the run would hold a directory: a landing whose bits deny the
 * run (holdable_directory) and a planned directory converged in place
 * (deploy_preflight's fix arm, FOREIGN where it may not).
 *
 * @param path The directory (must not be NULL)
 * @param st The look that found it there (must not be NULL): the climb's lstat
 *        at a landing, the load's at a fix
 */
static bool holdable(const char *path, const struct stat *st) {
    return identity_may_chmod(identity(), st->st_uid) && !fs_denied(path, R_OK);
}

/**
 * The item of a present directory this run may hold, or NULL
 *
 * A directory the view names — any enabled profile, in scope or not, either class,
 * the same reach create_ancestor has — that the run may hold where it stands
 * (holdable). The run may carry it at a working mode while the paths beneath it
 * land, until the caller's release (deploy_release), so its current mode can
 * never refuse a path beneath it. The class does not enter: a claim's mode is
 * captured with the very children it would refuse, and that argument is the
 * ancestor claim's as much as the tracked one's — the alternative would make
 * the reach depend on whether the user typed the directory or a file inside it.
 * Nothing else is ours to touch: a directory no row names whose bits deny the
 * run is a permission error, and so is a claimed one the run may not hold —
 * another's, or one whose bits refuse it the read.
 *
 * Asked by the landing check and the landing's open (check_landing,
 * open_landing_directory): the prediction and the mechanism, one question.
 *
 * @param st lstat of the directory (must not be NULL)
 */
static const workspace_item_t *holdable_directory(
    const workspace_t *ws, const char *path, const struct stat *st
) {
    const workspace_item_t *item = workspace_find(ws, path);

    /* The view's claim, which an active item carries and an orphan's does not:
     * a directory only a record remembers is no claim to hold */
    if (item && item->row &&
        item->item_kind == PATH_KIND_DIRECTORY && holdable(path, st)) {
        return item;
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
 * carries a working mode until the caller's release (deploy_release), so nothing
 * planned beneath it is refused on its account. Asked of the verdicts rather
 * than the plan: a skipped directory row does none of that, and vouches for nothing
 * beneath it.
 *
 * Asked by the ladder of an ancestor of the row in hand — the squatted directory
 * above it, the one its landing stands in — whose fate the walk, in path order,
 * has taken already; by the ancestors pass, of the walk's whole.
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
 * The fate an ancestor imposes on a planned row
 *
 * What the ladder asks before any probe of its own, of the directories on the
 * row's way whose fate the run has already decided. A pending directory row the
 * walk skipped for its pair with nothing standing there leaves the row nothing
 * to land in: no directory will stand there, whatever converges above it. A
 * squatted directory row above the path invalidates every probe beneath it —
 * the landing check's included: a symlink squatting a claimed directory points
 * somewhere real and writable, so the landing probe would wave the write through
 * and the run would deploy INTO the link's target, over whatever the user keeps
 * there. The walk notes the first beside its fates (deploy_preflight_t's
 * skipped_absent); the workspace lends the second whole
 * (workspace_squatted_ancestor — the outermost, fate-blind, with the claim the
 * load noted beside it), and this splits the answer by what the run itself decided
 * about that ancestor, the premise the plan carried by scope now asked of the
 * verdicts, so it is exactly true. One arm per fate, in the order asked, each
 * writing what it decides:
 *
 *   absent        the walk skipped a directory row on the way for its pair, and
 *                 nothing stands there as the run will find it: no directory
 *                 will stand there, so the row cannot land. OWNERSHIP, that row
 *                 named — a sentence about the row's own way, never the named
 *                 row's claim, which its own line says
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
 *                 and a rung dotta's own copy squats, the view having moved past
 *                 it (promoted, deploy_plan_build); the named re-derivation drops
 *                 an ancestor claim the user's own squatter holds
 *
 * The claimant is written in the no-fate arm alone — a row beneath a skipped
 * squatter leaves the ancestry NONE, its remedy being that squatter's own line's
 * (deploy_ancestry_t). Called before check_landing by the ladder, and once more
 * per ancestor candidate; the ladder decides in path order, so an ancestor's
 * own fate is always already taken when a row beneath it is reached — and noted,
 * where it was skipped for its pair with nothing standing there. The skip and
 * *out_absent are written only when an ancestor decides — the caller's zero skip
 * and false stand otherwise, and the row judges itself.
 *
 * @param ws Workspace, for the squatted-ancestor answer (must not be NULL)
 * @param verdicts The fates decided so far (must not be NULL)
 * @param path Planned path (must not be NULL)
 * @param skip The row's skip in the making (must not be NULL): the reason — TYPE,
 *        ANCESTOR or OWNERSHIP — the named ancestor's prefix length, and where
 *        the run gave a squatter no fate the claim at it
 * @param out_absent Whether the run empties the path before writing it (must
 *        not be NULL)
 */
static void check_ancestry(
    const workspace_t *ws, const deploy_preflight_t *verdicts, const char *path,
    deploy_skip_t *skip, bool *out_absent
) {
    /* Absent: a directory row on the way that this run skipped for its pair, so
     * no directory will stand there and nothing lands beneath it. Asked before
     * the squatter: a squatter that stays skips every row beneath it in its own
     * class, so a noted row stands beneath none but one the run replaces — whose
     * arm would plan this path absent, leaving the climb to meet the pair at
     * execute. The notes are in path order, a prefix before every path it opens,
     * so the first that holds is the outermost, the one skipped for its own pair */
    for (size_t i = 0; i < verdicts->skipped_absent.count; i++) {
        const workspace_item_t *dir = verdicts->skipped_absent.entries[i];
        const size_t len = strlen(dir->filesystem_path);

        if (str_path_beneath(path, dir->filesystem_path, len)) {
            skip->reason = DEPLOY_SKIP_OWNERSHIP;
            skip->ancestor = len;
            return;
        }
    }

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
     * view's face lends a view claim alone. A wider scope plans every squatter
     * but one: the user's own at a rung (DERIVED), which no plan holds and the
     * named re-derivation answers for */
    skip->reason = DEPLOY_SKIP_ANCESTOR;
    skip->ancestry = above->claim == WORKSPACE_DISPLACED_DERIVED
        ? DEPLOY_ANCESTRY_DERIVED : DEPLOY_ANCESTRY_TRACKED;
}

/**
 * Can this planned path's write land?
 *
 * One question per planned row, present or absent alike, and never about the
 * path itself: nothing deploy writes needs permission on the path. A file's or
 * a link's node is created beside it and renamed over it (sys/filesystem.h
 * fs_temp_t), what stands in its way is removed from its directory, and
 * deploy_directory mkdirs it — every one of those is an operation on the *parent*.
 * A read-only file, or a symlink pointing into a read-only store, is no obstacle
 * at all.
 *
 * So the question goes to the nearest present ancestor, and to it alone. Every
 * component between it and the planned path is absent, and ensure_parents creates
 * those with the owner triad on until the release (deploy_working_mode) — an
 * absent component can refuse nothing. What stands at the ancestor decides:
 *
 *   a deployable directory    the directory pass converges it first —
 *   row                       created, fixed or replaced — and carries it at a
 *                             working mode; fine, whatever squats it now (a
 *                             squatter there means --force, and the pass replaces
 *                             it before anything lands beneath). A *skipped*
 *                             directory row converges nothing and vouches for
 *                             nothing — it answers below like any stranger's path
 *   a directory the view      ours to hold, either class, where the run may
 *   names                     change it and read it (holdable_directory): if its
 *                             bits deny the run, ensure_parents holds it open
 *                             until the release (deploy_release); fine. Where
 *                             it may not, it answers as any other directory
 *   any other directory       its bits must not deny the run a new entry —
 *                             fs_denied, which unlike a mode test knows about
 *                             ownership, groups, ACLs and root, and asks for
 *                             the user the write will be made as — or the row
 *                             is skipped (PERMISSION); a symlink to a directory
 *                             is asked through the link. What refuses every
 *                             identity there — a read-only filesystem, an immutable
 *                             flag — denies the run nothing, and is the write's
 *                             to meet and report
 *   anything else             a non-directory no row names squats the
 *                             ancestry, and this run will not replace it (Coherent
 *                             Scope) — skipped (ANCESTOR), by hand. The rung
 *                             ran first, so nothing the load saw claims the
 *                             squatter: the skip's ancestry is UNCLAIMED, the
 *                             one ancestry this producer can find — and nothing
 *                             enabled claims it at all, a claim of it leaving a
 *                             directory row there or no row beneath it
 *                             (core/manifest.c manifest_layer)
 *   unreachable               EACCES is a denial too (PERMISSION, with no
 *                             ancestor to name); any other errno is left for
 *                             the write to report
 *
 * The mechanism asks the very same questions of the very same ancestor
 * (ensure_parents), so this is a prediction of the run, not a model of it.
 *
 * The skip is written only on a refusal — the caller's zero skip stands when
 * the landing is clear — and its ancestry only on the ANCESTOR one. The named
 * ancestor is a prefix of the planned path itself, so it travels as a byte length
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
    const workspace_t *ws, const deploy_preflight_t *verdicts, const char *path,
    deploy_skip_t *skip
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
    if (is_dir && !fs_denied(scratch, W_OK | X_OK)) {
        goto cleanup;
    }
    if (occ == FS_OCCUPANT_DIRECTORY && holdable_directory(ws, scratch, &st)) {
        goto cleanup;
    }

    skip->reason = is_dir ? DEPLOY_SKIP_PERMISSION : DEPLOY_SKIP_ANCESTOR;
    skip->ancestor = ancestor_len(slash);
    if (!is_dir) {
        skip->ancestry = DEPLOY_ANCESTRY_UNCLAIMED;
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
     * user asked to be stopped by: one fact, the row, the key and the name, as
     * the warning below says it */
    if (strict_ownership) {
        return error_create(
            ERR_NOT_FOUND, "Cannot deploy '%s' under strict_ownership: %s '%s' does not "
            "exist on this system", row->storage_path, half, name
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
 * bucket holds; the filesystem-level questions are the landing, the read a fix
 * opens its directory with (holdable), and, for a directory standing where a
 * file belongs, the readdir under path_clearance.
 *
 * Every pending row gets exactly one fate — a verdict or a skip, the totality
 * equation — so the verdict arrays hold deployable rows alone and the executors
 * read them without a gate. A row planned beneath a squatter this run replaces
 * gets its verdict too — absent, nothing asked — so the executors read one shape
 * for every row; beneath a squatter this run skips, it takes that skip's class
 * instead, TYPE or ANCESTOR, beneath one the run never reaches it is skipped
 * ANCESTOR, and beneath a pending directory row skipped for its pair with nothing
 * standing there it is skipped OWNERSHIP, naming that row — the ancestry rung
 * (check_ancestry), asked before any probe of the row's own.
 */
error_t deploy_preflight(
    const workspace_t *ws, const deploy_plan_t *plan, const deploy_options_t *opts,
    arena_t *arena, deploy_preflight_t **out
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
    ptr_array_init(&verdicts->skipped_absent, arena, 0);
    string_array_init(&verdicts->warnings, arena, 0);

    /* One slot per pending item — verdict or skip, so the skip array's bound is
     * both kinds together — and one per directory item for the ancestors (an
     * upper bound; the count says how many were decided). */
    workspace_items_t files = plan->files.pending;
    workspace_items_t dirs = plan->directories.pending;
    workspace_items_t all_dirs = workspace_directories(ws);

    verdicts->directories.entries = arena_calloc(
        arena, dirs.count, sizeof(*verdicts->directories.entries)
    );
    verdicts->files.entries = arena_calloc(
        arena, files.count, sizeof(*verdicts->files.entries)
    );
    verdicts->ancestors.entries = arena_calloc(
        arena, all_dirs.count, sizeof(*verdicts->ancestors.entries)
    );
    verdicts->skipped.entries = arena_calloc(
        arena, files.count + dirs.count, sizeof(*verdicts->skipped.entries)
    );

    /* Every planned row, in path order, either kind; then the ancestors. A fate
     * is a prediction of what the run will find at the row's path and on the
     * way to it, so it is decided after the fate of every one of the row's
     * ancestors, of either kind — which is all the rungs ask of the fates decided
     * so far: the absent directory skipped for its pair and the squatted directory
     * above the row (check_ancestry), and the deployable directory its landing
     * stands in (check_landing), are ancestors of it. The plan's two pending
     * slices are each in path order (workspace_kind_order), so the walk merges
     * them, and an ancestor, a prefix of every path beneath it, comes first.
     * core/cleanup's preflight decides in the order its fates read each other
     * too — there children before parents, so a directory reads the fates of
     * everything it holds. The verdicts fill per kind, each in path order, the
     * order deploy_execute acts in within a kind; the skips and the warnings
     * come out in path order, so a skipped squatter precedes the rows beneath it.
     *
     * The ancestors come last though the run creates them first: which directory
     * rows it may create on the way is derived from the planned rows as a whole,
     * not decided row by row. */
    for (size_t d = 0, f = 0; d < dirs.count || f < files.count;) {
        /* The row next in path order: a directory row while one is left and the
         * file rows are spent or it sorts first. The two slices never hold one
         * path: the view holds one row per path. */
        const workspace_item_t *item = d < dirs.count && (f == files.count ||
            strcmp(dirs.entries[d]->filesystem_path, files.entries[f]->filesystem_path) < 0)
            ? dirs.entries[d++] : files.entries[f++];

        const char *path = item->filesystem_path;

        /* Its ancestry first, before any probe: a directory on the way that the
         * walk skipped for its pair, absent, leaves the row nothing to land in,
         * and a squatted directory row above this path invalidates every look
         * taken beneath it, the landing check's included. The walk is in path
         * order, so such an ancestor's own fate is already taken. The row is
         * decided into its skip: each rung that refuses writes it — the reason,
         * and the ancestor it names with the claim there — and the row is skipped
         * iff one did. */
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

            /* The rungs, first match wins — the enum's own order. Every write
             * lands a new entry through the parent — a temp file or a link renamed
             * over the path, a directory created or put where a squatter stood
             * — whether or not something is already at the path, so one question
             * covers them all, and it is never about the path itself (the landing).
             * A directory already standing at a directory row is converged in
             * place instead, through its own descriptor: the run's to do only
             * where it may hold the directory (holdable — the owner the load's
             * look found, and the read the open needs), FOREIGN where it may
             * not. A row the workspace could not settle is asked too, and skipped
             * on its own account only when the landing had nothing to say (the
             * leftover, below). */
            if (item->item_kind != PATH_KIND_DIRECTORY ||
                deploy_convergence(occupant) != DEPLOY_CONVERGE_FIX) {
                check_landing(ws, verdicts, path, &skip);
            } else if (!holdable(path, &item->st)) {
                skip.reason = DEPLOY_SKIP_FOREIGN;
            }

            if (skip.reason == DEPLOY_SKIP_NONE) {
                if (occupant_conflicts(occupant, item->row->type)) {
                    /* Type: what stands at the path decides the remedy, and whose
                     * it is decides the consent. STALE on a kind the row does
                     * not have is the workspace's proof that Git retyped the
                     * path past the copy dotta confirmed, and TYPE that disk
                     * left that copy — the user's edit of the kind — beside it
                     * or alone (the frame across kinds, either row kind:
                     * core/workspace.c workspace_analyze_file,
                     * workspace_analyze_directory). So the consent is the content
                     * rung's own question: Git's move with no edit of the user's
                     * beside it loses nothing, and needs no --force, as a STALE
                     * row's bytes never do; an edit asks for --force, both sides
                     * moved or the user's alone (deploy_content_conflicts). The
                     * proof is the bit and never an absence of conflict: the
                     * analyses read every kind mismatch they can see off the
                     * look, before any read and whatever the key, so a mismatch
                     * without STALE carries TYPE and asks for --force.
                     *
                     * A directory row's squatter is a non-directory (the link
                     * itself, so a symlink to a directory counts), replaced one
                     * node at a time, and never a directory — that is the row
                     * converging in place — so it never meets REFUSED: TYPE is
                     * its one refusal, and "use --force" always the true remedy. */
                    switch (path_clearance(
                        path, occupant, opts->force || ((item->divergence & DIVERGENCE_STALE)
                        && !deploy_content_conflicts(item))
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
                     * that rung's consent and at the preview's other read. A
                     * directory row never carries CONTENT: a directory claims
                     * no content at all. */
                    skip.reason = DEPLOY_SKIP_CONTENT;
                }
            }

            /* A row the workspace could not settle is no verdict — the UNVERIFIED
             * bit, not its unstattable symptom. The bit has two producers: the
             * path could not be lstat'd (occupant UNKNOWN, which no rung above
             * judges — UNKNOWN is not present), or the look at a file row's content
             * failed with the row's own kind standing — a blob that could not
             * be loaded, decrypted or compared, an open the file refused — which
             * the content rung cannot catch either: a failed look accumulates
             * no content verdict. (A kind mismatch makes no content look to fail:
             * it is judged off the lstat before any read, and TYPE takes it above.)
             * A directory row's one producer is the unstattable path, but the
             * rung reads the fact, not its encoding. Nothing can say what the
             * run will find there, or that the write's own read will fare better,
             * and nothing is written on a guess. The ancestry that refused an
             * lstat is what refuses the write, and the landing has just named
             * it when it could (EACCES on the way up); the row is skipped on
             * its own account only when the landing had nothing to say — a failure
             * the run would otherwise have met mid-run, after siblings already
             * wrote. */
            if (skip.reason == DEPLOY_SKIP_NONE && (item->divergence & DIVERGENCE_UNVERIFIED)) {
                skip.reason = DEPLOY_SKIP_UNREADABLE;
            }
        }

        /* The row's rung, last: the ownership the write applies, and whether
         * this run may set it (check_ownership). */
        uid_t uid;
        gid_t gid;

        if (skip.reason == DEPLOY_SKIP_NONE) {
            error_t err = check_ownership(
                opts, &verdicts->warnings, item->row, &uid, &gid, &skip.reason
            );
            if (err) return err;
        }

        if (skip.reason != DEPLOY_SKIP_NONE) {
            /* A directory row skipped for a pair, nothing standing there as the
             * run will find it, is noted: no row beneath it can land
             * (check_ancestry). Its absence is the walk's occupant, never the
             * item's look, which beneath a squatter the run replaces says only
             * that nothing was looked at */
            if (skip.reason == DEPLOY_SKIP_OWNERSHIP && item->item_kind == PATH_KIND_DIRECTORY &&
                occupant == FS_OCCUPANT_NONE) {
                ptr_array_push(&verdicts->skipped_absent, item);
            }
            verdicts->skipped.entries[verdicts->skipped.count++] = skip;
            continue;
        }

        /* The verdict, onto its kind's array */
        deploy_verdicts_t *kind = item->item_kind == PATH_KIND_DIRECTORY
            ? &verdicts->directories : &verdicts->files;

        kind->entries[kind->count++] = (deploy_verdict_t){
            .item = item, .occupant = occupant, .uid = uid, .gid = gid,
        };
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
     * one skipped beneath a squatted ancestor that stays, or beneath an absent
     * one skipped for its pair, is not a parent this run can create (the rung's
     * reason), a TYPE-, FOREIGN- or UNREADABLE-skipped row is not absent (present,
     * as its item read), and a landing-skipped one, like one absent and skipped
     * for its pair, has no deployable row beneath it (the invariant,
     * deploy_preflight's doc). */
    for (size_t i = 0; i < all_dirs.count; i++) {
        const workspace_item_t *item = all_dirs.entries[i];
        const char *path = item->filesystem_path;

        if (directory_is_deployable(verdicts, path)) {
            continue;
        }

        /* Its ancestry, as the ladder asks it. An ancestor takes no skip (below),
         * so this one is the rung's answer alone: its reason is read and it is
         * never pushed. */
        deploy_skip_t skip = { .item = item };
        bool absent = false;

        check_ancestry(ws, verdicts, path, &skip, &absent);
        if (skip.reason != DEPLOY_SKIP_NONE) {
            continue;   /* beneath a squatter that stays, or an absent row skipped for its pair */
        }

        if (!(absent || item->occupant == FS_OCCUPANT_NONE) ||
            !above_deployable_row(verdicts, path)) {
            continue;
        }

        /* The pair, without the ownership rung: an ancestor is outside the plan
         * and has no skip to take, and the rows beneath it are decided by now.
         * A pair this run cannot set meets the refusal at the create, leaving
         * nothing behind (fs_create_dir_exclusive): the first act beneath carries
         * it as its outcome, and every later one fails naming the ancestor
         * (deploy_execute) — the under-approximation this pass accepts for a
         * foreign-owned claim the plan does not hold, derived or tracked outside
         * the run, above a landing the invoker can write. A pending row the walk
         * skipped for its pair is never here: no deployable row stands beneath
         * it. */
        uid_t uid;
        gid_t gid;

        error_t err = resolve_deployment_ownership(
            item->row, opts->strict_ownership, &verdicts->warnings, &uid, &gid
        );
        if (err) return err;

        verdicts->ancestors.entries[verdicts->ancestors.count++] = (deploy_verdict_t){
            .item = item, .occupant = FS_OCCUPANT_NONE, .uid = uid, .gid = gid,
        };
    }

    *out = verdicts;
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Execute
 * ══════════════════════════════════════════════════════════════════ */

/**
 * A place the run needed a directory at and created none, and the sentence every
 * act beneath it fails with
 *
 * A directory row not converged, or a parent the way could not create, noted by
 * the act that met the failure (note_uncreated) and read before every act after
 * it (poisoned_above). The path is the run's own copy, since a parent's spelling
 * lives only in the climb that met it (ensure_parents). The sentence is minted
 * once, when the place is noted, and borrowed by each act it fails.
 */
typedef struct {
    const char *filesystem_path;  /* The place, the run's arena copy */
    size_t len;                   /* strlen(filesystem_path): the prefix of every path beneath it */
    error_t error;                /* "'<path>' was not <verb>", minted once (base/error.h "Lifetime") */
} deploy_uncreated_t;

/**
 * One execution of the verdicts: what deploy_execute was handed, plus the state
 * the run accumulates. Lives exactly as long as deploy_execute; the parents it
 * created and the holds it took outlive it, handed to the receipt as it returns
 * — the holds for the caller's release.
 */
typedef struct {
    content_cache_t *cache;             /* every row's bytes, either kind (deploy_file) */
    const workspace_t *ws;              /* a landing directory's item (holdable_directory) */
    const deploy_preflight_t *verdicts; /* the ancestors' metadata (create_ancestor) */
    arena_t *arena;                     /* every list below grows here */
    deploy_outcome_t *ancestors;        /* every claimed parent created: the receipt's ancestors */
    size_t ancestor_count;
    size_t ancestor_capacity;
    deploy_hold_t *holds;               /* every hold taken, in the order taken: the receipt's taken */
    size_t hold_count;
    size_t hold_capacity;
    deploy_uncreated_t *uncreated;      /* every place not created, in the order noted (poisoned_above) */
    size_t uncreated_count;
    size_t uncreated_capacity;
} deploy_run_t;

/**
 * Remember a directory for the release (deploy_release)
 *
 * Only a directory whose owed mode is narrower than its working mode needs holding
 * — for the rest (0755, 0700, …) the working mode IS the owed one, so nothing
 * is held and nothing is done twice. The item is the workspace's, outliving the
 * run and its receipt (deploy_hold_t).
 *
 * Each directory is held once, by its caller's own shape: a planned row converges
 * once (deploy_execute's loop), a claimed parent is held at its first create
 * alone (create_ancestor), and a landing, once held, no longer denies the writes
 * beneath it (open_landing_directory).
 */
static void hold_directory(deploy_run_t *run, const workspace_item_t *item, mode_t mode) {
    if (deploy_working_mode(mode) == mode) return;

    run->holds = arena_grow(
        run->arena, run->holds, &run->hold_capacity, run->hold_count + 1,
        sizeof(*run->holds)
    );

    run->holds[run->hold_count++] = (deploy_hold_t){ .item = item, .mode = mode };
}

/**
 * Note a place the run needed a directory at and created none
 *
 * Called by the act that met the failure, with the verb that act failed at: a
 * directory row's create or replace ("converged", deploy_directory) and a parent
 * on the way, either arm of create_ancestor ("created", ensure_parents). That
 * act keeps its own cause; the sentence is the place's, true of every act beneath
 * it, so it is minted here once and each of them borrows it (base/error.h
 * "Lifetime").
 */
static void note_uncreated(deploy_run_t *run, const char *path, const char *verb) {
    run->uncreated = arena_grow(
        run->arena, run->uncreated, &run->uncreated_capacity, run->uncreated_count + 1,
        sizeof(*run->uncreated)
    );

    run->uncreated[run->uncreated_count++] = (deploy_uncreated_t){
        .filesystem_path = arena_strdup(run->arena, path),
        .len = strlen(path),
        .error = error_create(ERR_FS, "'%s' was not %s", path, verb),
    };
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

    error_t err = fs_create_dir_with_ownership(
        dir->filesystem_path, deploy_working_mode(dir->mode), v->uid, v->gid
    );
    if (err) return err;
    hold_directory(run, v->item, dir->mode);

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
 * has no metadata decided for it, is created like an unclaimed parent, and is
 * left for the next load to read — which sees its record and its row, and, where
 * the row is tracked, says [mode] if the two disagree.
 *
 * Creation only, either class (fs_create_dir_exclusive): every path it creates
 * was absent when the run probed it, and one the world made present in between
 * meets ERR_EXISTS as the outcome of the act that met it, and of every later
 * act beneath it by name (ensure_parents notes it) — not this run's to converge,
 * the way a planned row would be (materialize_directory). The header's stance
 * on every mid-run surprise, applied to the create itself.
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

        error_t err = fs_create_dir_exclusive(
            dir->filesystem_path, deploy_working_mode(dir->mode), v->uid, v->gid
        );
        if (err) return err;

        /* Listed and held once: a parent this run created for an earlier row's
         * write, and the world took away since, is created again here and is
         * the run's already — its first hold releases it */
        for (size_t j = 0; j < run->ancestor_count; j++) {
            if (run->ancestors[j].verdict == v) {
                return NULL;
            }
        }

        hold_directory(run, v->item, dir->mode);

        run->ancestors = arena_grow(
            run->arena, run->ancestors, &run->ancestor_capacity, run->ancestor_count + 1,
            sizeof(*run->ancestors)
        );
        run->ancestors[run->ancestor_count++] = (deploy_outcome_t){ .verdict = v };
        return NULL;
    }

    /* A parent no row claims: the word no claim makes, asked of its one producer
     * rather than spelled here a second time — two absences name nothing to miss,
     * so the pair always resolves. Left root's, the next climb through this
     * directory would claim it root's (core/profiles.h profile_capture_ancestors),
     * and dotta's own artefact would enter the sheet as intent. */
    uid_t uid;
    gid_t gid;
    (void) metadata_ownership(NULL, NULL, &uid, &gid);

    return fs_create_dir_exclusive(path, DIR_MODE_DEFAULT, uid, gid);
}

/**
 * Open a planned path's landing directory for the run
 *
 * The nearest present ancestor is where the write lands, and its bits must not
 * deny a new entry. An absent chain below it is created at working modes and
 * cannot refuse; the ancestor itself can — a claimed 0555 directory that is already
 * exactly as recorded denies the very child it was captured with. When the run
 * may hold it (holdable_directory) it does, at a working mode built from its
 * current mode so that the release restores exactly what was there, recorded or
 * not (an excluded or out-of-scope row is not the plan's to converge) — set on
 * the directory that stands and never created (fs_set_dir_mode): one the world
 * took away since the climb leaves nothing to set, and the write beneath meets
 * the absence as its row's outcome. Anything else is left alone and the write
 * reports the refusal — so is what refuses every identity (a read-only filesystem,
 * an immutable flag), which denies the run nothing: the hold's chmod lifts the
 * bits and no more, and would meet the refusal as flatly as the write.
 *
 * The questions check_landing asked of the same ancestor, less the one time has
 * answered: a pending row has been converged by the directory pass before any
 * file lands, so it stands here as a directory at its working mode and is denied
 * nothing. Prediction and mechanism, one rule.
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
    if (occ != FS_OCCUPANT_DIRECTORY || !fs_denied(ancestor, W_OK | X_OK)) {
        return NULL;
    }

    const workspace_item_t *item = holdable_directory(run->ws, ancestor, st);
    if (!item) {
        return NULL;  /* not the run's to hold: the write meets the refusal */
    }

    mode_t current = st->st_mode & 0777;
    error_t err = fs_set_dir_mode(item->filesystem_path, deploy_working_mode(current));
    if (err) return err;
    hold_directory(run, item, current);

    return NULL;
}

/**
 * Create the missing parents of a planned path, top-down from its nearest present
 * ancestor — opening that ancestor for the run first when it refuses and the
 * run may hold it.
 *
 * Mutation, not decision. Whether the path can land was preflight's question,
 * and the directory pass has already replaced any planned squatter above it; a
 * non-directory ancestor met here (a prompt sat in between) is a named error
 * rather than a mkdir errno. A dangling symlink is one: mkdir would report EEXIST
 * for a path that leads nowhere.
 *
 * A parent it cannot create, either arm of create_ancestor, is noted
 * (note_uncreated): the act that met the refusal carries its cause, and every
 * later act beneath the parent fails naming it, unattempted (poisoned_above).
 * Its two other refusals meet a place the run was not to create, and note nothing
 * — every act beneath meets them again: an ancestor that is not a directory,
 * and a landing that stands and refuses its open, a world that moved after the
 * landing check asked, since a landing the run may not hold is PERMISSION at
 * preflight (holdable_directory).
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
        err = error_create(
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
        if (err) {
            /* Not created: this act fails with the cause, and every later act
             * beneath the parent fails naming it rather than trying the create
             * again — after ERR_EXISTS too, since what the world created there
             * may be a link, and nothing lands through one */
            note_uncreated(run, scratch, "created");
            goto cleanup;
        }
        *slash = '/';
    }

cleanup:
    free(scratch);
    return err;
}

/**
 * Deploy a single view row to its filesystem path.
 *
 * Mechanism only: the verdict says what stands at the path and what the write
 * applies, and this lands it — its content first, then the way to it (the missing
 * parents created, the landing held where it refuses), then its node created
 * whole beside the path, then the directory in its way cleared, then the node
 * published over the path (sys/filesystem.h fs_temp_t). Nothing here looks at
 * the disk to decide anything; a path the world has moved under since preflight
 * meets the mechanism's refusal (rename over a directory is EISDIR, rmdir of a
 * directory that filled up is ENOTEMPTY) and the refusal is the row's outcome.
 *
 * A sealed row at a terminal, its key cold, is asked for the key before the way
 * to it is created, so a parent the run then cannot create costs a prompt answered
 * for nothing.
 *
 * The row:
 * - file->type: the entry its content is read as, and the node that lands it —
 *   a link to its target, anything else a file of its bytes
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
     * binds its own fstat below. The symlink arm never does — a link is created
     * by path (symlink(2) opens no descriptor to describe), and readlink is its
     * whole re-verification. */
    *out_stat = STATE_STAT_UNSET;

    const manifest_row_t *file = v->item->row;

    /* Its content first, whichever kind it is: a row whose content cannot be
     * read creates nothing on its way and removes nothing in it. Read as the
     * entry the row's type says it is (infra/content.h): a link's bytes are its
     * target, never a seal, and come back the C string symlink(2) is handed,
     * empty or not; a file's are decrypted where sealed */
    const buffer_t *content = NULL;
    error_t err = content_cache_get_from_blob_oid(
        run->cache, &file->blob_oid, gitops_type_filemode(file->type),
        file->storage_path, file->profile, &content
    );
    if (err) return err;

    /* Then the way to it: parents created, the landing held where it refuses */
    err = ensure_parents(run, file->filesystem_path);
    if (err) return err;

    /* Then its node, whole, beside the path, while what stands at the path stands:
     * a write the world refuses — a full disk, a file-size limit, a name the
     * kernel will not take — is refused before anything in its way moves.
     * SECURITY: the ownership the verdict resolved lands as the node is created,
     * and a file's mode with it, through the temporary's descriptor before its
     * first byte, so no moment has the wrong pair — a link, the one node without
     * a descriptor, takes it by lchown on the temporary. This is the ONLY place
     * where ownership is applied; the verdict only resolves. */
    fs_temp_t temp = FS_TEMP_INIT;
    struct stat written;
    if (file->type == PATH_TYPE_SYMLINK) {
        err = fs_temp_symlink(&temp, content->data, file->filesystem_path, v->uid, v->gid);
    } else {
        err = fs_temp_file(
            &temp, file->filesystem_path, (const unsigned char *) content->data,
            content->size, file->mode, v->uid, v->gid, &written
        );
    }
    if (err) goto cleanup;

    /* Then what the publish cannot replace, a directory (EISDIR): the one the
     * verdict named, never one found by a fresh look from down here. Refused,
     * it stands, and the write is taken back */
    err = v->occupant == FS_OCCUPANT_DIRECTORY
        ? clear_occupant(file->filesystem_path, v->occupant) : NULL;
    if (err) goto cleanup;

    /* Then the publish, the one step between a removal and the path standing
     * again: rename(2) replaces a regular file, a link (the link itself, not
     * what it points to — at a link row, no conflict and no --force) or a device
     * in place, and creates the path where nothing stands */
    err = fs_temp_publish(&temp);
    if (err) goto cleanup;

    /* The write's own stat, distilled where the write authority is in scope:
     * authorship, not a read, vouches for the triple, so its own open second
     * needs no smudge (state_stat_from_write). */
    if (file->type != PATH_TYPE_SYMLINK) *out_stat = state_stat_from_write(&written);

cleanup:
    /* However the row ended, no temporary outlives it: one created and not
     * published is taken back */
    fs_temp_deinit(&temp);
    return err;
}

/**
 * Materialize one planned tracked directory to its expected state.
 *
 * Mechanism only, by the verdict's convergence (deploy_convergence): a fix
 * converges the directory standing there in place; a create or a replace lands
 * a new entry — its landing opened, a replace's squatter cleared (one node, the
 * one the verdict named) — and then the create-or-fix, which is idempotent: a
 * planned directory whose reality healed meanwhile is simply confirmed, and one
 * a prompt-window race turned into a symlink is refused by O_NOFOLLOW rather
 * than chmod'd through.
 *
 * The directory lands at its working mode and is released to its exact recorded
 * mode by the caller's release (deploy_working_mode, deploy_release), so a recorded
 * mode without owner-write never refuses the tracked children written after it.
 *
 * A create or a replace that fails leaves no directory of the run's at the path,
 * so the path is noted (note_uncreated) and every act beneath it fails unattempted;
 * a fix that fails leaves the directory standing, and notes nothing.
 *
 * @param run Run context (must not be NULL)
 * @param v Verdict for the row (must not be NULL; the row is borrowed, read-only)
 * @return Error or NULL on success
 */
static error_t deploy_directory(deploy_run_t *run, const deploy_verdict_t *v) {
    const char *path = v->item->filesystem_path;
    const deploy_convergence_t convergence = deploy_convergence(v->occupant);

    /* A fix converges in place, through the directory's own descriptor: no new
     * entry lands, so there is no landing to open — and refused, the directory
     * still stands, so the acts beneath it land in it or fail on their own */
    if (convergence == DEPLOY_CONVERGE_FIX) return materialize_directory(run, v);

    /* A create or a replace lands a new entry through the parent — the replace's
     * after its clear — so the landing is opened first, the one check_landing
     * predicted, as deploy_file opens its own (ensure_parents): the missing parents
     * created, the nearest present one held where it refuses and the run may
     * hold it. A squatter's parent stands, the squatter being in it, and nothing
     * is created — the final component is the path itself. An absent path beneath
     * a non-directory is one preflight blocked when unplanned and the directory
     * pass replaces when planned (prefix order); one still there is ensure_parents'
     * named error. */
    error_t err = ensure_parents(run, path);

    /* A replace's squatter, cleared before the mkdir through the landing just
     * opened — the single node the verdict named. It is never a directory (that
     * is a fix), and --force was preflight's question. */
    if (!err && convergence == DEPLOY_CONVERGE_REPLACE) {
        err = clear_occupant(path, v->occupant);
    }

    /* Create-or-fix with atomic ownership and permissions (fchown/fchmod on the
     * directory fd — no window with wrong metadata). Idempotent. */
    if (!err) err = materialize_directory(run, v);

    /* No directory of the run's came to stand — the create never happened, or
     * the squatter survived its replace — so nothing beneath may land through
     * what stands there: every later act beneath the path fails naming it */
    if (err) note_uncreated(run, path, "converged");

    return err;
}

/**
 * The failure a planned path's act meets before it starts, or NULL
 *
 * Deploy's order is parents first and its mechanism creates on the way down, so
 * per-act failure needs the preflight invariant's execution mirror: a place the
 * run needed a directory at and created none (deploy_uncreated_t) — a create
 * that never happened, a squatter that survived its replace, a parent the way
 * could not create; never a fix refused, whose directory stands. An act beneath
 * it would create the place again — a row's as a parent no claim names, a parent's
 * against the same refusal — or land through whatever stands there, the hazard
 * the ancestry rung refuses at preflight met again at execution time. So it is
 * not attempted, and fails with the place's own sentence.
 *
 * The first match is the outermost: an act's way is created from the top down,
 * a place that fails there is noted before the act's own, and no act runs beneath
 * a noted place, so along any one path the outer place is noted first. Only the
 * world, taking a directory away mid-run, can note an outer place after an inner
 * one; the act fails as surely, naming the inner. The list is empty on every
 * healthy run, which is what makes the scan free.
 */
static error_t poisoned_above(const deploy_run_t *run, const char *path) {
    for (size_t i = 0; i < run->uncreated_count; i++) {
        const deploy_uncreated_t *uncreated = &run->uncreated[i];

        if (str_path_beneath(path, uncreated->filesystem_path, uncreated->len)) {
            return uncreated->error;
        }
    }

    return NULL;
}

/**
 * Carry the verdicts out
 *
 * Every run hands its holds to the receipt, and the caller's release asks each
 * back to its exact mode however the rows fared (deploy_release), so the tree a
 * failure leaves behind is incomplete but never wider than recorded — save a
 * hold the directory refuses, which the receipt names. Row failures land in the
 * receipt (deploy_receipt_t's contract); nothing is returned beside it.
 */
deploy_receipt_t *deploy_execute(
    arena_t *arena,
    const workspace_t *ws,
    const deploy_preflight_t *verdicts,
    content_cache_t *cache
) {
    CHECK_NULL(arena);
    CHECK_NULL(ws);
    CHECK_NULL(verdicts);
    CHECK_NULL(cache);

    /* The receipt is sized to the verdicts up front, in the arena the run is
     * handed — one slot per verdict, filled in verdict order as each act lands,
     * each outcome whole (a member it leaves out is zero, and a zeroed stat IS
     * the UNSET triple), the failed bucket to both kinds together — every promised
     * row could fail. count gates what a consumer reads, so an untaken slot is
     * invisible and the receipt holds exactly what happened — for a landed file,
     * with its own write's stat. */
    deploy_receipt_t *receipt = arena_calloc(arena, 1, sizeof(*receipt));
    receipt->deployed.entries = arena_calloc(
        arena, verdicts->files.count, sizeof(*receipt->deployed.entries)
    );
    receipt->converged.entries = arena_calloc(
        arena, verdicts->directories.count, sizeof(*receipt->converged.entries)
    );
    receipt->failed.entries = arena_calloc(
        arena, verdicts->directories.count + verdicts->files.count,
        sizeof(*receipt->failed.entries)
    );

    deploy_run_t run = {
        .cache    = cache,
        .ws       = ws,
        .verdicts = verdicts,
        .arena    = arena,
    };

    /* Directories first: parents before the files beneath them, and under --force
     * a squatting symlink is gone before anything is written through it. Verdict
     * order is the plan's prefix order = parents before children, which is also
     * what lets a replace settle everything beneath it: a planned path under a
     * replaced directory carries an absent occupant, and by the time it is reached
     * the replace has made that true. */
    for (size_t i = 0; i < verdicts->directories.count; i++) {
        const deploy_verdict_t *v = &verdicts->directories.entries[i];

        error_t err = poisoned_above(&run, v->item->filesystem_path);
        if (!err) err = deploy_directory(&run, v);
        if (err) {
            /* The row's own outcome; the cause already names its subject */
            receipt->failed.entries[receipt->failed.count++] = (deploy_outcome_t){
                .verdict = v, .error = err,
            };
            continue;
        }

        /* Record success; the verb is the verdict's occupant */
        receipt->converged.entries[receipt->converged.count++] = (deploy_outcome_t){
            .verdict = v,
        };
    }

    /* Every verdict is work the plan chose, by construction: the planner routed
     * the row through deploy_needs_work and past every reason to skip it, so
     * this loop applies no filter of its own. Clean in-scope rows with deployed_at
     * == 0 are apply's adoption step, which stamps the path owned without
     * deploy_file. */
    for (size_t i = 0; i < verdicts->files.count; i++) {
        const deploy_verdict_t *v = &verdicts->files.entries[i];
        state_stat_t stat;

        error_t err = poisoned_above(&run, v->item->filesystem_path);
        if (!err) err = deploy_file(&run, v, &stat);
        if (err) {
            /* The row's own outcome, as above */
            receipt->failed.entries[receipt->failed.count++] = (deploy_outcome_t){
                .verdict = v, .error = err,
            };
            continue;
        }

        /* Record success, with the write's own stat */
        receipt->deployed.entries[receipt->deployed.count++] = (deploy_outcome_t){
            .verdict = v, .stat = stat,
        };
    }

    /* The run's own lists, the receipt's to carry: the parents its acts created,
     * and the holds they took, which the caller lets go once every act beneath
     * them is done, the run's and any it runs next (deploy_release) */
    receipt->ancestors = (deploy_outcomes_t){
        .entries = run.ancestors, .count = run.ancestor_count,
    };
    receipt->taken = (deploy_holds_t){
        .entries = run.holds, .count = run.hold_count,
    };
    return receipt;
}

/* ══════════════════════════════════════════════════════════════════
 * Release
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Let the run's holds go
 *
 * Holds are taken top-down along each path — the directory pass runs in prefix
 * order and ensure_parents creates from the nearest present ancestor downward —
 * so reverse order releases a child before its parent, and a parent released to
 * a mode without owner-search never stands between us and a child still to be
 * released. A landing opened later may stand above a hold taken earlier on another
 * path, and is released first; but the mode it is released to is the one it had,
 * and the run reached beneath it at that mode, so it keeps every search the
 * releases beneath it need. A run that holds root opens no landing at all: root
 * is denied nothing the bits refuse (fs_denied). The caller's acts in between
 * take no hold, and remove no held directory — each is a view row's, never an
 * orphan's — nor a directory above one, which the active row beneath keeps
 * released; so the order stands across them.
 *
 * However the acts fared, every held directory is asked back to its exact mode,
 * and the next run holds what it needs afresh. Through the directory's own
 * descriptor (fs_set_dir_mode), never a chmod(2) on a path that may have become
 * a symlink meanwhile, and never a directory created anew: one the world took
 * away has nothing left to release. Every hold is attempted; one the directory
 * refuses stays held and is the receipt's, each in the order released, with its
 * cause (deploy_receipt_t's held).
 */
void deploy_release(arena_t *arena, deploy_receipt_t *receipt) {
    CHECK_NULL(arena);
    CHECK_NULL(receipt);

    /* Sized to the holds: every one could be refused */
    deploy_holds_t held = {
        .entries = arena_calloc(arena, receipt->taken.count, sizeof(*held.entries)),
    };

    for (size_t i = receipt->taken.count; i-- > 0;) {
        const deploy_hold_t *hold = &receipt->taken.entries[i];
        error_t err = fs_set_dir_mode(hold->item->filesystem_path, hold->mode);
        if (!err) continue;

        /* Left wide, or out of reach: the hold, with the refusal in the primitive's
         * own words — the receipt carries the path and both modes beside it */
        held.entries[held.count++] = (deploy_hold_t){
            .item = hold->item, .mode = hold->mode, .error = err,
        };
    }

    receipt->held = held;
}
