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

#include "base/array.h"
#include "base/error.h"
#include "base/string.h"
#include "core/metadata.h"
#include "core/scope.h"
#include "core/workspace.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/privilege.h"

/* ══════════════════════════════════════════════════════════════════
 * Plan
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Deploy's work predicate over a workspace verdict
 *
 * Two dimensions, in order: state (where does the path exist — Git, state database,
 * filesystem?) sets the baseline, divergence (what is wrong with it?) refines
 * it. A missing path is always work, and the only bit it can carry is the
 * blob-family ENCRYPTION verdict (types.h) — no path bit survives absence, so
 * the two missing states answer from state alone.
 *
 * Kind-agnostic: directory analysis tags only MODE / OWNERSHIP / TYPE / UNVERIFIED,
 * so the DEPLOYED arm's test already covers every directory verdict — no
 * kind-specific arm. A file row can carry ENCRYPTION beside any of those; the
 * arm masks it either way.
 *
 * The planner iterates the active slices, so the three non-active states never
 * reach this; their arms name the owner that does handle them and keep -Wswitch
 * quiet.
 *
 * @param item Workspace divergence verdict (NULL = not in the index = clean)
 * @return true when deploy must act on the path
 */
static bool deploy_needs_work(const workspace_item_t *item) {
    if (item == NULL) {
        /* Not in workspace divergence index -> file is clean */
        return false;
    }

    /* Decision tree: state (existence) determines baseline, then check divergence (quality) */
    switch (item->state) {
        case WORKSPACE_STATE_UNDEPLOYED:
            /* File exists in Git but has never been deployed to filesystem. Needs
             * initial deployment.
             *
             * No path bit survives absence (properties of non-existent files
             * cannot be compared); the blob-family ENCRYPTION bit can ride on a
             * missing row — [undeployed] [unencrypted] — and changes nothing
             * here: the row is work by state alone. */
            return true;

        case WORKSPACE_STATE_DELETED:
            /* File exists in Git and was previously deployed (deployed_at > 0),
             * but has been removed from filesystem. Needs restoration. Absence
             * and the blob-family bit read as in the UNDEPLOYED arm: work by
             * state alone. */
            return true;

        case WORKSPACE_STATE_DEPLOYED:
            /* File exists on filesystem and is tracked in Git. Needs deployment
             * only if properties diverged (content, mode, ownership, etc.).
             *
             * DIVERGENCE_STALE is a deploy reason like any other: Git moved past
             * the blob dotta deployed and disk did not follow.
             *
             * DIVERGENCE_ENCRYPTION is the one bit that is never deploy's work:
             * it says the blob is stored plaintext in Git where the auto-encrypt
             * policy claims the path — a fact about the profile's tree, not about
             * what stands at the path. No write deploy makes can change how a
             * blob is stored; update is the verb that re-stores it, and
             * deploy_content_conflicts states the same rule for overwrites. A
             * deny-mask rather than an allow-list, so a bit added later inherits
             * the arm's default: any divergence of the path is work. */
            return (item->divergence & ~DIVERGENCE_ENCRYPTION) != DIVERGENCE_NONE;

        case WORKSPACE_STATE_ORPHANED:
            /* A record whose path the view lacks.
             *
             * Not reachable from the planner: both active slices are partitioned
             * to enabled profiles, and orphan rows are exactly the ones that
             * partition rejected.
             *
             * Never deployment — cleanup owns orphan removal. */
            return false;

        case WORKSPACE_STATE_UNTRACKED:
            /* File exists on filesystem in a tracked directory but not in Git.
             *
             * Architectural invariant: Untracked files should NOT appear in the
             * active slice (which is built from view rows, not filesystem scans).
             * If we reach here, it's a programming error.
             *
             * Defensive: Return false (don't deploy untracked files, user must
             * 'add' them). */
            return false;

        case WORKSPACE_STATE_RELEASED:
            /* The path left its profile in Git (an external commit, a pulled
             * removal, a vanished branch), or dotta never deployed it, and it
             * was released from management. Never needs deployment — cleanup
             * reports it and apply's record step retires its record. */
            return false;
    }

    /* Unreachable once every enum value is handled — defensive against a value
     * from outside the enum. */
    return false;
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
 * Route one in-scope row into its partition bucket, or drop it
 *
 * A row with no work is adoptable unless -e named it: --exclude means "leave
 * this path alone entirely", while --skip-existing only means "do not overwrite",
 * and adoption overwrites nothing. So SKIP_EXISTING on a clean row (one the index
 * holds only for a profile reassignment, say) is not a skip at all.
 *
 * @param part Partition for the row's kind (must not be NULL)
 * @param row Borrowed view row (must not be NULL)
 * @param work Deploy's work predicate for the row
 * @param skip Why the row's work is skipped, if it is
 * @return Error or NULL on success
 */
static error_t *partition_push(
    deploy_partition_t *part,
    const void *row,
    bool work,
    skip_reason_t skip
) {
    if (!work) {
        if (skip == SKIP_EXCLUDED) return NULL;   /* neither work nor adoptable */
        return ptr_array_push(&part->clean, row);
    }

    switch (skip) {
        case SKIP_NONE:     return ptr_array_push(&part->pending, row);
        case SKIP_EXCLUDED: return ptr_array_push(&part->excluded, row);
        case SKIP_EXISTING: return ptr_array_push(&part->skipped_existing, row);
    }

    /* Unreachable once every enum value is handled */
    return ERROR(ERR_INTERNAL, "Unknown skip reason %d", (int) skip);
}

/**
 * Is `path` beneath a displaced directory this scope converges?
 *
 * A non-directory at a directory row's path is what every probe of the paths
 * beneath it went through — the workspace's lstat, and so its verdicts and the
 * occupant preflight reads off the item; preflight's landing probes. With a symlink
 * to a directory squatting, those probes reach the link's target and come back
 * with answers about *its* tree: a child reads clean, a parent reads present.
 * The directory pass replaces the squatter before anything beneath it is touched
 * (prefix order), so the observations describe a tree the run itself dismantles:
 * after the replace, nothing stands at any path beneath it. Such a path is planned
 * and predicted as absent — work, not occupied, nothing to ask of it — whatever
 * the index says. A file or dangling-link squatter changes nothing: beneath it
 * every probe already failed (ENOTDIR), and absent was the verdict anyway.
 *
 * Displaced is the workspace's fact (workspace_displaced_ancestor — the outermost
 * decides: a deeper displaced directory was itself observed through it, and
 * replacing the outer one empties every path beneath; the view's claims alone,
 * so the answer always has a row), and only a squatter this scope converges counts:
 * a squatted tracked row in scope always has work (the TYPE divergence), so
 * "converged this run" is exactly "a tracked view row this scope accepts and
 * does not exclude" (scope_accepts_entry) — one -e skips is not replaced this
 * run, and a squatted ancestor claim is never planned at all (deploy_plan_build).
 * The plan approximates with scope; preflight exacts the same premise against
 * the fates (check_ancestry) and writes the answer into the verdict's occupant,
 * which is where the executors read it. What the plan declines to call absent
 * is not thereby called safe: a row beneath a squatter this run leaves standing
 * is judged by the ancestry rung, which refuses it whatever bucket it sat in.
 *
 * @param ws Workspace, for the displaced-ancestor answer (must not be NULL)
 * @param scope Operation scope, for the ancestor's reach (must not be NULL)
 * @param path Planned path (must not be NULL)
 */
static bool beneath_squatted_directory(
    const workspace_t *ws, const scope_t *scope, const char *path
) {
    const char *dir = workspace_displaced_ancestor(ws, path);

    if (!dir) {
        return false;
    }

    const manifest_row_t *row = workspace_lookup(ws, dir);

    return row->tracked && scope_accepts_entry(
        scope, row->profile, row->storage_path, PATH_KIND_DIRECTORY
    );
}

/**
 * Build the deployment plan
 */
error_t *deploy_plan_build(
    const workspace_t *ws, const scope_t *scope, bool skip_existing,
    deploy_plan_t **out
) {
    CHECK_NULL(ws);
    CHECK_NULL(scope);
    CHECK_NULL(out);

    /* calloc zeroes the eight ptr_array_t buckets — that IS their empty state */
    deploy_plan_t *plan = calloc(1, sizeof(*plan));
    if (!plan) {
        return ERROR(ERR_MEMORY, "Failed to allocate deploy plan");
    }

    error_t *err = NULL;

    /* Directories then files — the order preflight decides and the run acts in.
     * Convention alone: each row's classification reads the workspace and the
     * scope, never the buckets, so neither loop depends on the other having run. */
    manifest_rows_t dirs = workspace_directories(ws);
    for (size_t i = 0; i < dirs.count; i++) {
        const manifest_row_t *row = dirs.entries[i];

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
        if (!row->tracked) continue;

        if (!scope_accepts_profile(scope, row->profile) ||
            !scope_accepts_path(scope, row->storage_path, PATH_KIND_DIRECTORY)) {
            continue;                        /* out of scope: invisible */
        }

        bool absent = beneath_squatted_directory(ws, scope, row->filesystem_path);

        /* No SKIP_EXISTING arm: --skip-existing does not reach tracked directories
         * (see deploy_partition_t). */
        err = partition_push(
            &plan->directories, row,
            absent || deploy_needs_work(workspace_get_item(ws, row->filesystem_path)),
            scope_is_excluded(scope, row->storage_path, PATH_KIND_DIRECTORY)
                ? SKIP_EXCLUDED : SKIP_NONE
        );
        if (err) goto cleanup;
    }

    manifest_rows_t files = workspace_files(ws);
    for (size_t i = 0; i < files.count; i++) {
        const manifest_row_t *row = files.entries[i];

        if (!scope_accepts_profile(scope, row->profile) ||
            !scope_accepts_path(scope, row->storage_path, PATH_KIND_FILE)) {
            continue;
        }

        const workspace_item_t *item = workspace_get_item(ws, row->filesystem_path);
        bool absent = beneath_squatted_directory(ws, scope, row->filesystem_path);

        /* Occupancy is the workspace's own lstat, not a fresh probe: a row with
         * work always has an item (deploy_needs_work(NULL) is false), and lstat
         * truth counts a broken symlink as occupying the path — which is what
         * the flag says, and what a stat that follows links could not tell us.
         * A path planned as absent is the one exception: its lstat reached the
         * squatter's target, and nothing will occupy the path once the squatter
         * goes — so the flag has nothing to preserve there. -e still holds: a
         * named path is intent, not an observation. */
        skip_reason_t skip = SKIP_NONE;
        if (scope_is_excluded(scope, row->storage_path, PATH_KIND_FILE)) {
            skip = SKIP_EXCLUDED;
        } else if (skip_existing && !absent && item && item->occupant != FS_OCCUPANT_NONE) {
            skip = SKIP_EXISTING;
        }

        err = partition_push(&plan->files, row, absent || deploy_needs_work(item), skip);
        if (err) goto cleanup;
    }

    *out = plan;
    return NULL;

cleanup:
    deploy_plan_free(plan);
    return error_wrap(err, "Failed to build deploy plan");
}

/**
 * Free a plan — bucket buffers only; the rows belong to the workspace
 */
void deploy_plan_free(deploy_plan_t *plan) {
    if (!plan) {
        return;
    }

    ptr_array_deinit(&plan->files.pending);
    ptr_array_deinit(&plan->files.clean);
    ptr_array_deinit(&plan->files.excluded);
    ptr_array_deinit(&plan->files.skipped_existing);
    ptr_array_deinit(&plan->directories.pending);
    ptr_array_deinit(&plan->directories.clean);
    ptr_array_deinit(&plan->directories.excluded);
    ptr_array_deinit(&plan->directories.skipped_existing);

    free(plan);
}

/* ══════════════════════════════════════════════════════════════════
 * Occupancy
 * ══════════════════════════════════════════════════════════════════ */

/**
 * What a file row materializes at its path
 *
 * The occupant vocabulary is sys/filesystem's (fs_occupant_t): the link itself,
 * never its target. Deploy unlinks the link and never follows it, so the target's
 * type and permissions are none of its business.
 */
static fs_occupant_t file_row_occupant(const manifest_row_t *file) {
    return file->type == PATH_TYPE_SYMLINK ? FS_OCCUPANT_SYMLINK
                                           : FS_OCCUPANT_REGULAR;
}

/**
 * Does what stands at the path disagree with what the row materializes?
 */
static bool occupant_conflicts(fs_occupant_t occ, fs_occupant_t want) {
    return deploy_occupant_present(occ) && occ != want;
}

/**
 * May deploy remove what occupies a planned path?
 */
typedef enum {
    CLEARANCE_OK,           /* --force is set, and the occupant is one node */
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
 * --force is the first half. Clearing an occupant is the destructive reading of
 * "overwrite modified files", and preflight already gates a type divergence on
 * that flag.
 *
 * The second half is a limit --force does not lift. What deploy replaces is the
 * tracked path the user named: one node, whose disappearance is exactly what
 * the preview and the prompt describe. A directory holding anything else holds
 * *other* paths — untracked, unnamed, uncounted, and not restorable from Git —
 * so nothing on the apply command line authorizes removing them. core/cleanup
 * never removes an orphaned directory holding anything of the user's, --force
 * included (cleanup_preflight's directory verdicts release it); this is the same
 * posture on deploy's side of the house.
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
 * @param occ Its occupant, as the workspace observed it
 * @param force Whether --force was given
 */
static clearance_t path_clearance(const char *path, fs_occupant_t occ, bool force) {
    if (occ == FS_OCCUPANT_DIRECTORY && !fs_is_directory_empty(path)) {
        return CLEARANCE_REFUSED;
    }

    return force ? CLEARANCE_OK : CLEARANCE_NEEDS_FORCE;
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
static error_t *clear_occupant(const char *path, fs_occupant_t occ) {
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
        *out_is_dir = (stat(scratch, &target) == 0) && S_ISDIR(target.st_mode);
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
            if (i == 0) {
                errno = EINVAL;                 /* not absolute — cannot happen */
                return false;
            }
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
 * not own cannot be fchmod'd at all. Root owns everything for this purpose.
 *
 * @param st lstat of the directory (must not be NULL)
 */
static const manifest_row_t *holdable_directory(
    const workspace_t *ws, const char *path, const struct stat *st
) {
    const manifest_row_t *dir = workspace_lookup(ws, path);

    if (dir && dir->type == PATH_TYPE_DIRECTORY
        && (st->st_uid == geteuid() || privilege_is_elevated())) {
        return dir;
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
    const deploy_preflight_result_t *verdicts, const char *path
) {
    for (size_t i = 0; i < verdicts->directories.count; i++) {
        if (strcmp(verdicts->directories.entries[i].row->filesystem_path, path) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * The fate a displaced ancestor imposes on a planned row
 *
 * The one question the ladders ask before any probe of their own, because a
 * displaced directory row above the path invalidates every probe beneath it —
 * the landing check's included: a symlink squatting a claimed directory points
 * somewhere real and writable, so access(2) would wave the write through and
 * the run would deploy INTO the link's target, over whatever the user keeps there.
 * The workspace names the offender (workspace_displaced_ancestor — the outermost,
 * fate-blind); this splits the answer by what the run itself decided about that
 * ancestor, the premise the plan carried by scope now asked of the verdicts, so
 * it is exactly true. In decision order:
 *
 *   deployable    the directory pass converges the ancestor before this row is
 *                 reached — created, fixed or replaced — so from here down the
 *                 path is empty at write time. *out_absent; the row is asked
 *                 nothing else
 *   skipped       the squatter stays: nothing beneath it can land, and no
 *                 probe of the path can be trusted about it. The row inherits
 *                 the ancestor's own reason, ancestor named — the fate is the
 *                 ancestor's, so the class (--force or not) and the exit code
 *                 must be the ancestor's too: TYPE keeps the consent class and
 *                 --force lifts parent and child together, PERMISSION keeps the
 *                 incapacity no flag lifts
 *   no fate       this run never reaches the ancestor (out of scope, -p'd
 *                 away, -e'd, or an ancestor claim the plan never holds): ANCESTOR
 *                 — the same fate a squatter no row names earns at check_landing,
 *                 an incapacity. The skip carries which claim holds the squatter
 *                 (*out_class), because the remedies part ways there: a wider
 *                 scope plans a tracked row, the named re-derivation drops an
 *                 ancestor claim
 *
 * Written default-then-override: ANCESTOR is what an unreached ancestor earns,
 * and the skip scan replaces it with the ancestor's own reason when this run
 * took one. The claimant is written only where the fate stays ANCESTOR — an
 * inherited reason is the ancestor's own story, and the class stays NONE. Called
 * before check_landing in both ladders and once more per ancestor candidate;
 * directories are decided parents-first, so a displaced ancestor's own fate is
 * always already taken when a row beneath it is reached. The outs are written
 * only when an ancestor decides — the caller's initialization (NONE, 0, NONE,
 * false) stands otherwise, and the row judges itself.
 *
 * @param ws Workspace, for the displaced-ancestor answer (must not be NULL)
 * @param verdicts The fates decided so far (must not be NULL)
 * @param path Planned path (must not be NULL)
 * @param out_reason NONE / ANCESTOR / the ancestor's own (must not be NULL)
 * @param out_ancestor Prefix length of the named ancestor, or 0 (must not be NULL)
 * @param out_class The claim at the named ancestor, ANCESTOR fates only (must
 *        not be NULL)
 * @param out_absent Whether the run empties the path before writing it (must
 *        not be NULL)
 */
static void check_ancestry(
    const workspace_t *ws, const deploy_preflight_result_t *verdicts, const char *path,
    deploy_skip_reason_t *out_reason, size_t *out_ancestor,
    deploy_ancestor_class_t *out_class, bool *out_absent
) {
    const char *dir = workspace_displaced_ancestor(ws, path);

    if (!dir) {
        return;
    }

    if (directory_is_deployable(verdicts, dir)) {
        *out_absent = true;
        return;
    }

    *out_reason = DEPLOY_SKIP_ANCESTOR;
    *out_ancestor = strlen(dir);

    for (size_t i = 0; i < verdicts->skipped.count; i++) {
        const deploy_skip_t *s = &verdicts->skipped.entries[i];

        if (strcmp(s->row->filesystem_path, dir) == 0) {
            *out_reason = s->reason;
            break;
        }
    }

    /* The lookup cannot meet a file row: the displaced set holds directory claims
     * alone. And it cannot miss a row: the probe answers view-side (the reach
     * rule, workspace.h), so a record that alone remembers a directory never
     * names the ancestor here. */
    if (*out_reason == DEPLOY_SKIP_ANCESTOR) {
        const manifest_row_t *row = workspace_lookup(ws, dir);

        *out_class = row->tracked
            ? DEPLOY_ANCESTOR_TRACKED : DEPLOY_ANCESTOR_DERIVED;
    }
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
 *   any other directory       must accept a new entry now — access(2),
 *                             which unlike a mode test knows about ownership,
 *                             groups, ACLs and root — or the row is skipped
 *                             (PERMISSION); a symlink to a directory is asked
 *                             through the link
 *   anything else             a non-directory no row names squats the
 *                             ancestry, and this run will not replace it (Coherent
 *                             Scope) — skipped (ANCESTOR), by hand. The rung
 *                             ran first, so nothing the load saw claims the
 *                             squatter: *out_class is UNCLAIMED, the one class
 *                             this producer can find
 *   unreachable               EACCES is a refusal too (PERMISSION, with no
 *                             ancestor to name); any other errno is left for
 *                             the write to report
 *
 * The mechanism asks the very same questions of the very same ancestor
 * (ensure_parents), so this is a prediction of the run, not a model of it.
 *
 * The outs are written only on a refusal — the caller's initialization (NONE,
 * 0, NONE) stands when the landing is clear — and the class only on the ANCESTOR
 * one. The named ancestor is a prefix of the planned path itself, so it travels
 * as a byte length (deploy_skip_t). A PERMISSION with an ancestor reads "<ancestor>
 * is not writable"; without one, "ancestry cannot be reached" — the zero length
 * is itself the honest fact (the offender could not be named).
 *
 * @param ws Workspace, for the claimed-ancestor lookup (must not be NULL)
 * @param verdicts The fates decided so far, for the deployable-directory test
 *        (must not be NULL)
 * @param path Planned path (must not be NULL)
 * @param out_reason NONE / PERMISSION / ANCESTOR (must not be NULL)
 * @param out_ancestor Prefix length of the refusing ancestor, or 0 (must not be
 *        NULL)
 * @param out_class UNCLAIMED on the ANCESTOR refusal alone (must not be NULL)
 * @return Error or NULL on success (a skip is not an error)
 */
static error_t *check_landing(
    const workspace_t *ws, const deploy_preflight_result_t *verdicts,
    const char *path, deploy_skip_reason_t *out_reason, size_t *out_ancestor,
    deploy_ancestor_class_t *out_class
) {
    char *scratch = strdup(path);
    if (!scratch) {
        return ERROR(ERR_MEMORY, "Failed to copy path for landing check");
    }

    size_t slash;
    fs_occupant_t occ;
    bool is_dir;
    struct stat st;

    if (!nearest_ancestor(scratch, &slash, &occ, &is_dir, &st)) {
        if (errno == EACCES) {
            *out_reason = DEPLOY_SKIP_PERMISSION; /* no ancestor to name */
        }
        goto cleanup;                             /* anything else: the write reports it */
    }

    scratch[ancestor_len(slash)] = '\0';  /* the ancestor, on its own */

    if (directory_is_deployable(verdicts, scratch)) {
        goto cleanup;
    }
    if (is_dir && access(scratch, W_OK | X_OK) == 0) {
        goto cleanup;
    }
    if (occ == FS_OCCUPANT_DIRECTORY && holdable_directory(ws, scratch, &st)) {
        goto cleanup;
    }

    *out_reason = is_dir ? DEPLOY_SKIP_PERMISSION : DEPLOY_SKIP_ANCESTOR;
    *out_ancestor = ancestor_len(slash);
    if (!is_dir) {
        *out_class = DEPLOY_ANCESTOR_UNCLAIMED;
    }

cleanup:
    free(scratch);
    return NULL;
}

/**
 * Resolve deployment ownership for a path
 *
 * Unified ownership resolution logic for both files and directories. Handles
 * home/ vs root/custom/ prefix logic and sudo detection.
 *
 * Resolution rules:
 * - Files deploying to user's home under sudo: Use actual user's UID/GID
 * - root/ or custom/ prefix with owner/group metadata: Resolve names to UID/GID
 * - All other cases: Return -1 (no ownership change)
 *
 * Home detection for sudo de-escalation:
 * - Primary: storage_path starts with "home/" (always deploys to $HOME)
 * - Fallback: filesystem_path is under actual user's home (catches custom/ prefix
 *   files reclassified by --target that still land under $HOME)
 *
 * Strict ownership mode (strict_ownership=true): an unknown user/group is a fatal
 * error, aborting deployment. An unelevated run never asks the resolver: it cannot
 * chown, so the claim stays unresolved (-1/-1) — reachable only in a dry run, a
 * real run's privilege check having re-exec'd under sudo before preflight.
 *
 * Pure decision, taken at preflight — no filesystem mutation — so the strict-mode
 * abort is met before the prompt and never mid-run. A warning is an anomaly report
 * and travels in the preflight result for the caller to print; nothing here reads
 * a verbosity flag, because the warning's visibility is not this module's output
 * policy to set.
 *
 * @param storage_path Path in profile (e.g., "home/.bashrc", "root/etc/hosts")
 * @param filesystem_path Resolved deployment path for home detection
 * @param owner Owner username from metadata (can be NULL)
 * @param group Group name from metadata (can be NULL)
 * @param out_uid Resolved UID or -1 for no change (must not be NULL)
 * @param out_gid Resolved GID or -1 for no change (must not be NULL)
 * @param strict_ownership Fail deployment if ownership cannot be resolved
 * @param warnings Preflight warnings, for a non-fatal failure (must not be NULL)
 * @return Error on fatal failures, NULL on success (non-fatal errors recorded
 *         as warnings and suppressed)
 */
static error_t *resolve_deployment_ownership(
    const char *storage_path,
    const char *filesystem_path,
    const char *owner, const char *group,
    uid_t *out_uid, gid_t *out_gid,
    bool strict_ownership,
    string_array_t *warnings
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out_uid);
    CHECK_NULL(out_gid);

    /* Initialize to "no change" */
    *out_uid = (uid_t) -1;
    *out_gid = (gid_t) -1;

    const mount_spec_t *spec = mount_spec_for_path(storage_path);
    bool requires_root_privileges = spec && spec->tracks_ownership;

    /* Case 1: file lands in the invoking user's HOME when running as root.
     *
     * fs_get_home is the single source of truth for "the user's home" (sudo-aware
     * via SUDO_UID's pw_dir); privilege_path_is_user_home trusts it. No label
     * dispatch needed:
     *   home/X    → resolves under HOME → de-escalate
     *   root/X    → /X, never under HOME → fall through
     *   custom/X with --target $HOME/jail → under HOME → de-escalate
     *   custom/X with --target /jail      → outside HOME → fall through
     *
     * The fs path tells us directly. The kind dispatch this replaces was a
     * workaround for HOME-truth divergence between fs_get_home and the inlined
     * SUDO_UID lookup; once both share fs_get_home, the dispatch collapses. */
    if (privilege_is_elevated()
        && filesystem_path && privilege_path_is_user_home(filesystem_path)) {
        error_t *err = privilege_get_actual_user(out_uid, out_gid);
        if (err) {
            return error_wrap(
                err, "Failed to determine actual user for home path: %s",
                storage_path
            );
        }
        return NULL;
    }

    /* Case 2: root/ or custom/ prefix with ownership metadata -> resolve to UID/GID */
    if (requires_root_privileges && (owner || group)) {
        if (!privilege_is_elevated()) {
            /* An unelevated run cannot chown; reachable only in a dry one — a
             * real run's privilege check re-exec'd under sudo before preflight.
             * The claim stays unresolved (-1/-1, set above). */
            return NULL;
        }

        error_t *err = metadata_resolve_ownership(owner, group, out_uid, out_gid);
        if (err) {
            /* ERR_NOT_FOUND only: the user/group does not exist on this system.
             * Fatal under strict_ownership (configuration/environment mismatch);
             * otherwise a warning, and the deployment continues with default
             * ownership. */
            if (strict_ownership) {
                return error_wrap(
                    err, "Ownership resolution failed for '%s' (strict_mode enabled)\n"
                    "Hint: Create the user/group on this system, or disable strict_mode",
                    storage_path
                );
            }

            char *warning = str_format(
                "Could not resolve ownership for %s: %s",
                storage_path, error_message(err)
            );
            error_free(err);    /* its message just moved into the warning */

            if (!warning) {
                return ERROR(ERR_MEMORY, "Failed to format ownership warning");
            }

            err = string_array_push_owned(warnings, warning);
            if (err) {
                free(warning);
                return err;
            }

            /* Reset to "no change": a resolved owner must not survive its group's
             * failure. */
            *out_uid = (uid_t) -1;
            *out_gid = (gid_t) -1;
        }
        return NULL;
    }

    /* Case 3: All other cases -> no ownership change */
    return NULL;
}

/**
 * The metadata a row's write applies
 *
 * The mode is the row's, verbatim — total for every kind that carries one (the
 * claim, or the floor manifest_build resolved absence into); a symlink row is
 * never asked (symlink(2) takes no mode). The write reads it off the row, and
 * the verdict does not carry it: the decided facts are exactly the ones not on
 * the row. Ownership is one, resolved ahead of the write so the write applies
 * it atomically through the descriptor (fchown on the file or directory fd, lchown
 * on a link): there is never a moment when the path exists with the wrong owner.
 *
 * @param opts Deployment options (must not be NULL)
 * @param warnings Preflight warnings (must not be NULL)
 * @param v Verdict whose uid and gid are decided, its row assigned (must not be
 *        NULL)
 * @return Error or NULL on success (a strict-mode ownership failure is one)
 */
static error_t *resolve_metadata(
    const deploy_options_t *opts,
    string_array_t *warnings,
    deploy_verdict_t *v
) {
    const manifest_row_t *row = v->row;

    error_t *err = resolve_deployment_ownership(
        row->storage_path,
        row->filesystem_path,
        row->owner, row->group,
        &v->uid, &v->gid,
        opts->strict_ownership,
        warnings
    );
    if (err) {
        return error_wrap(
            err, "Failed to resolve ownership for '%s'",
            row->filesystem_path
        );
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
 * warn nor fail strict mode (see deploy_preflight's invariant).
 *
 * @param verdicts Both verdict kinds decided (must not be NULL)
 * @param dir Directory path (must not be NULL)
 */
static bool above_deployable_row(
    const deploy_preflight_result_t *verdicts, const char *dir
) {
    const deploy_verdicts_t *kinds[] = { &verdicts->directories, &verdicts->files };
    size_t len = strlen(dir);

    for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
        for (size_t i = 0; i < kinds[k]->count; i++) {
            if (str_path_beneath(kinds[k]->entries[i].row->filesystem_path, dir, len)) {
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
 * layer. Divergence verdicts and occupants are O(1) index probes; the one
 * filesystem-level question is the landing (and, for a directory standing where
 * a file belongs, the readdir under path_clearance).
 *
 * Every pending row gets exactly one fate — a verdict or a skip, the totality
 * equation — so the verdict arrays hold deployable rows alone and the executors
 * read them without a gate. A row planned beneath a squatter this run replaces
 * gets its verdict too — absent, nothing asked — so the executors read one shape
 * for every row; beneath a squatter this run skips, it inherits that skip instead,
 * and beneath one the run never reaches it is skipped ANCESTOR — the ancestry
 * rung (check_ancestry), asked before any probe of the row's own.
 */
error_t *deploy_preflight(
    const workspace_t *ws,
    const deploy_plan_t *plan,
    const deploy_options_t *opts,
    deploy_preflight_result_t **out
) {
    CHECK_NULL(ws);
    CHECK_NULL(plan);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    deploy_preflight_result_t *result = calloc(1, sizeof(deploy_preflight_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate preflight result");
    }

    result->warnings = string_array_new(0);

    if (!result->warnings) {
        deploy_preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate result arrays");
    }

    /* One slot per pending row — verdict or skip, so the skip array's bound is
     * both kinds together — and one per directory row of the view for the ancestors
     * (an upper bound; the count says how many were decided). A zero count
     * allocates one slot rather than nothing, so every array is an array. */
    manifest_rows_t files = manifest_rows_view(&plan->files.pending);
    manifest_rows_t dirs = manifest_rows_view(&plan->directories.pending);
    manifest_rows_t all_dirs = workspace_directories(ws);

    result->directories.entries = calloc(dirs.count + 1, sizeof(deploy_verdict_t));
    result->files.entries = calloc(files.count + 1, sizeof(deploy_verdict_t));
    result->ancestors.entries = calloc(all_dirs.count + 1, sizeof(deploy_verdict_t));
    result->skipped.entries = calloc(files.count + dirs.count + 1, sizeof(deploy_skip_t));

    if (!result->directories.entries || !result->files.entries ||
        !result->ancestors.entries || !result->skipped.entries) {
        deploy_preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate verdict arrays");
    }

    error_t *err = NULL;

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
        const manifest_row_t *row = dirs.entries[i];
        const char *path = row->filesystem_path;

        /* Its ancestry first, before any probe: a displaced directory row above
         * this path invalidates every look taken beneath it, the landing check's
         * included. Directories decide parents-first, so such an ancestor's own
         * fate is already taken. */
        deploy_skip_reason_t reason = DEPLOY_SKIP_NONE;
        size_t ancestor = 0;
        deploy_ancestor_class_t ancestor_class = DEPLOY_ANCESTOR_NONE;
        bool absent = false;

        check_ancestry(ws, result, path, &reason, &ancestor, &ancestor_class, &absent);

        if (reason != DEPLOY_SKIP_NONE) {
            deploy_skip_t *s = &result->skipped.entries[result->skipped.count++];

            s->row = row;
            s->item = NULL;   /* judged by its ancestry — its own item reads through the squatter */
            s->reason = reason;
            s->ancestor = ancestor;
            s->ancestor_class = ancestor_class;
            continue;
        }

        /* Planned as absent: the path is empty once the directory pass has
         * converged the ancestor — no type, no content, nothing in the way, and
         * the landing is that ancestor's. */
        if (absent) {
            deploy_verdict_t *v = &result->directories.entries[result->directories.count++];

            v->row = row;
            v->item = workspace_get_item(ws, path);   /* verbatim; the occupant below overrides it */
            v->occupant = FS_OCCUPANT_NONE;
            err = resolve_metadata(opts, result->warnings, v);
            if (err) goto cleanup;
            continue;
        }

        const workspace_item_t *item = workspace_get_item(ws, path);
        fs_occupant_t occupant = item->occupant;

        /* The rungs, first match wins — the enum's own order. A directory already
         * there is converged in place: fchmod and fchown ask for ownership, not
         * for a writable parent. Only a create or a replace lands a new entry.
         * A row the workspace could not settle is asked too, and skipped on its
         * own account only when the landing had nothing to say — as for a file. */
        if (deploy_convergence(occupant) != DEPLOY_CONVERGE_FIX) {
            err = check_landing(ws, result, path, &reason, &ancestor, &ancestor_class);
            if (err) goto cleanup;
        }

        /* A planned directory squatted by a non-directory (the link itself, so
         * a symlink to a directory counts) is replaced under --force, one node
         * at a time. The squatter can never be a directory — that is the row
         * converging in place — so path_clearance cannot refuse here, TYPE is
         * the only reachable arm, and "use --force" is always the true remedy. */
        if (reason == DEPLOY_SKIP_NONE &&
            occupant_conflicts(occupant, FS_OCCUPANT_DIRECTORY) &&
            path_clearance(path, occupant, opts->force) != CLEARANCE_OK) {
            reason = DEPLOY_SKIP_TYPE;
        }

        /* The leftover, as for a file (the file ladder carries the rationale):
         * the fact is the UNVERIFIED bit; for an active directory row its one
         * producer today is the unstattable path (occupant UNKNOWN), but the
         * rung reads the fact, not its one current encoding, so the two ladders
         * keep one rule. */
        if (reason == DEPLOY_SKIP_NONE && (item->divergence & DIVERGENCE_UNVERIFIED)) {
            reason = DEPLOY_SKIP_UNREADABLE;
        }

        if (reason != DEPLOY_SKIP_NONE) {
            deploy_skip_t *s = &result->skipped.entries[result->skipped.count++];

            s->row = row;
            s->item = item;
            s->reason = reason;
            s->ancestor = ancestor;
            s->ancestor_class = ancestor_class;
            continue;
        }

        deploy_verdict_t *v = &result->directories.entries[result->directories.count++];

        v->row = row;
        v->item = item;
        v->occupant = occupant;
        err = resolve_metadata(opts, result->warnings, v);
        if (err) goto cleanup;
    }

    for (size_t i = 0; i < files.count; i++) {
        const manifest_row_t *row = files.entries[i];
        const char *path = row->filesystem_path;

        /* Its ancestry first (see the directory loop): the directory pass is
         * decided in full, so a displaced ancestor is converged, skipped, or
         * out of this run's reach by now. */
        deploy_skip_reason_t reason = DEPLOY_SKIP_NONE;
        size_t ancestor = 0;
        deploy_ancestor_class_t ancestor_class = DEPLOY_ANCESTOR_NONE;
        bool absent = false;

        check_ancestry(ws, result, path, &reason, &ancestor, &ancestor_class, &absent);

        if (reason != DEPLOY_SKIP_NONE) {
            deploy_skip_t *s = &result->skipped.entries[result->skipped.count++];

            s->row = row;
            s->item = NULL;   /* judged by its ancestry — its own item reads through the squatter */
            s->reason = reason;
            s->ancestor = ancestor;
            s->ancestor_class = ancestor_class;
            continue;
        }

        /* Planned as absent (see the directory loop): written beneath a directory
         * this run converges first, so neither a conflict nor a landing question
         * is its own. */
        if (absent) {
            deploy_verdict_t *v = &result->files.entries[result->files.count++];

            v->row = row;
            v->item = workspace_get_item(ws, path);   /* verbatim; the occupant below overrides it */
            v->occupant = FS_OCCUPANT_NONE;
            err = resolve_metadata(opts, result->warnings, v);
            if (err) goto cleanup;
            continue;
        }

        /* Self-judged: no displaced ancestor stands above the path, so the row
         * is pending only because deploy_needs_work said so — and
         * deploy_needs_work(NULL) is false, so the item is there. */
        const workspace_item_t *item = workspace_get_item(ws, path);
        fs_occupant_t occupant = item->occupant;

        /* The rungs, first match wins — the enum's own order. Every file row
         * lands through its parent, whichever arm writes it and whether or not
         * something is already at the path — so one question covers both, and
         * it is never about the path itself. */
        err = check_landing(ws, result, path, &reason, &ancestor, &ancestor_class);
        if (err) goto cleanup;

        if (reason == DEPLOY_SKIP_NONE) {
            if (occupant_conflicts(occupant, file_row_occupant(row))) {
                /* Type: what stands at the path decides the remedy. */
                switch (path_clearance(path, occupant, opts->force)) {
                    case CLEARANCE_OK:
                        break;

                    case CLEARANCE_NEEDS_FORCE:
                        reason = DEPLOY_SKIP_TYPE;
                        break;

                    case CLEARANCE_REFUSED:
                        reason = DEPLOY_SKIP_OCCUPIED;
                        break;
                }
            } else if (!opts->force && deploy_content_conflicts(item)) {
                /* Content, asked only when the occupant is the row's own type:
                 * a path holding something else has no content to compare — the
                 * mask's TYPE arm cannot fire here, a conflicting occupant took
                 * the TYPE rung above; it is load-bearing at the preview's other
                 * read. */
                reason = DEPLOY_SKIP_CONTENT;
            }
        }

        /* A row the workspace could not settle is no verdict — the UNVERIFIED
         * bit, not its unstattable symptom. The bit has two producers: the path
         * could not be lstat'd (occupant UNKNOWN, which no rung above judges —
         * UNKNOWN is not present), or the look at its content failed with the
         * occupant known — a blob that could not be loaded, decrypted or compared,
         * an open the file refused — which the content rung cannot catch either:
         * a failed look accumulates no content verdict. (A kind mismatch lstat
         * did settle still skips TYPE first, rightly — that fact depends on no
         * failed look.) Nothing can say what the run will find there, or that
         * the write's own read will fare better, and nothing is written on a
         * guess. The ancestry that refused an lstat is what refuses the write,
         * and the landing has just named it when it could (EACCES on the way
         * up); the row is skipped on its own account only when the landing had
         * nothing to say — a failure the run would otherwise have met mid-run,
         * after siblings already wrote. */
        if (reason == DEPLOY_SKIP_NONE && (item->divergence & DIVERGENCE_UNVERIFIED)) {
            reason = DEPLOY_SKIP_UNREADABLE;
        }

        if (reason != DEPLOY_SKIP_NONE) {
            deploy_skip_t *s = &result->skipped.entries[result->skipped.count++];

            s->row = row;
            s->item = item;
            s->reason = reason;
            s->ancestor = ancestor;
            s->ancestor_class = ancestor_class;
            continue;
        }

        deploy_verdict_t *v = &result->files.entries[result->files.count++];

        v->row = row;
        v->item = item;
        v->occupant = occupant;
        err = resolve_metadata(opts, result->warnings, v);
        if (err) goto cleanup;
    }

    /* The ancestors: every directory row the run does not act on, absent as the
     * run will find it, that stands above a deployable row. Absent has two
     * readings, both fate-aware now: the rung's — beneath a displaced ancestor
     * the run converges first — or the workspace's own occupant (a row without
     * an item is present and converged). ensure_parents creates exactly these
     * on the way down to a deployed path, with the metadata decided here; a
     * candidate the world makes present before then is simply not created and
     * costs nothing, and one made present past the probe meets the create's
     * refusal, never a convergence (fs_create_dir_exclusive).
     *
     * Every gate reads the verdicts, not the plan: a skipped directory row flows
     * past the first into the candidate pool, and the later gates keep it out —
     * one held beneath a displaced ancestor that stays is not a parent this run
     * can make (the rung's reason), a TYPE- or UNREADABLE-skipped row is not
     * absent (present, as its item read), and a landing-skipped one has no
     * deployable row beneath it (the invariant, deploy_preflight's doc). */
    for (size_t i = 0; i < all_dirs.count; i++) {
        const manifest_row_t *row = all_dirs.entries[i];
        const char *path = row->filesystem_path;

        if (directory_is_deployable(result, path)) {
            continue;
        }

        deploy_skip_reason_t reason = DEPLOY_SKIP_NONE;
        size_t ancestor = 0;
        deploy_ancestor_class_t ancestor_class = DEPLOY_ANCESTOR_NONE;
        bool absent = false;

        check_ancestry(ws, result, path, &reason, &ancestor, &ancestor_class, &absent);
        if (reason != DEPLOY_SKIP_NONE) {
            continue;   /* held beneath a displaced ancestor that stays */
        }

        const workspace_item_t *item = workspace_get_item(ws, path);

        if (!(absent || (item && item->occupant == FS_OCCUPANT_NONE)) ||
            !above_deployable_row(result, path)) {
            continue;
        }

        deploy_verdict_t *v = &result->ancestors.entries[result->ancestors.count++];

        v->row = row;
        v->item = item;
        v->occupant = FS_OCCUPANT_NONE;
        err = resolve_metadata(opts, result->warnings, v);
        if (err) goto cleanup;
    }

    *out = result;
    return NULL;

cleanup:
    deploy_preflight_result_free(result);
    return err;
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
    const workspace_t *ws;                     /* a landing directory's row (holdable_directory) */
    const deploy_preflight_result_t *verdicts; /* the ancestors' metadata (create_ancestor) */
    deploy_result_t *result;                   /* the receipt so far (the ancestors bucket) */
    ptr_array_t held;                          /* held_directory_t * (owned), in the order taken */
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
static error_t *hold_directory(deploy_run_t *run, const char *path, mode_t mode) {
    if (working_mode(mode) == mode) {
        return NULL;
    }

    held_directory_t *held = malloc(sizeof(*held));
    if (!held) {
        return ERROR(ERR_MEMORY, "Failed to record held directory '%s'", path);
    }
    held->path = path;
    held->mode = mode;

    error_t *err = ptr_array_push(&run->held, held);
    if (err) {
        free(held);
        return err;
    }
    return NULL;
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
 * Frees the holds either way.
 */
static error_t *release_directories(deploy_run_t *run) {
    error_t *err = NULL;

    for (size_t i = run->held.count; i-- > 0;) {
        held_directory_t *held = run->held.items[i];
        error_t *release_err = fs_create_dir_with_ownership(
            held->path, held->mode, (uid_t) -1, (gid_t) -1
        );

        if (release_err) {
            if (err) {
                error_free(release_err);
            } else {
                err = error_wrap(
                    release_err, "Failed to release directory '%s' to mode %04o",
                    held->path, held->mode
                );
            }
        }
        free(held);
    }

    ptr_array_deinit(&run->held);
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
static error_t *materialize_directory(
    deploy_run_t *run, const deploy_verdict_t *v
) {
    const manifest_row_t *dir = v->row;

    error_t *err = fs_create_dir_with_ownership(
        dir->filesystem_path, working_mode(dir->mode), v->uid, v->gid
    );
    if (err) {
        return err;
    }

    return hold_directory(run, dir->filesystem_path, dir->mode);
}

/**
 * Materialize one absent ancestor whose own parent exists: a directory the view
 * claims (any profile, in scope or not, either class) with the metadata its
 * ancestor verdict carries, anything else DIR_MODE_DEFAULT as the running identity.
 * A claim is the only voice a directory's attributes have: a parent no row claims
 * is never chowned — an owner borrowed from the leaf beneath it would hand a
 * service user the system directories above its files — and an identity that
 * cannot create it meets the refusal an invention would have papered over. The
 * default is exact (fchmod), not umask-masked — dotta reproduces modes, it does
 * not negotiate them — and already carries the owner triad, so a parent no row
 * claims is never held.
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
static error_t *create_ancestor(deploy_run_t *run, const char *path) {
    const deploy_verdicts_t *ancestors = &run->verdicts->ancestors;

    for (size_t i = 0; i < ancestors->count; i++) {
        const deploy_verdict_t *v = &ancestors->entries[i];

        if (strcmp(v->row->filesystem_path, path) != 0) {
            continue;
        }

        const manifest_row_t *dir = v->row;

        error_t *err = fs_create_dir_exclusive(
            dir->filesystem_path, working_mode(dir->mode), v->uid, v->gid
        );
        if (err) {
            return err;
        }
        RETURN_IF_ERROR(hold_directory(run, dir->filesystem_path, dir->mode));

        /* On the receipt once — and bounds the sized array: a parent present at
         * an earlier row's write and removed since is re-made here, and without
         * this scan the second re-make would write past entries[count]. */
        deploy_outcomes_t *receipt = &run->result->ancestors;
        for (size_t j = 0; j < receipt->count; j++) {
            if (receipt->entries[j].verdict == v) {
                return NULL;
            }
        }
        receipt->entries[receipt->count++].verdict = v;
        return NULL;
    }

    return fs_create_dir_exclusive(path, DIR_MODE_DEFAULT, (uid_t) -1, (gid_t) -1);
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
 * file lands, so it stands here as a directory at its working mode and access(2)
 * simply passes. Prediction and mechanism, one rule.
 *
 * @param run Run context (must not be NULL)
 * @param ancestor Nearest present ancestor, NUL-terminated (must not be NULL)
 * @param occ What stands there
 * @param st Its lstat
 * @return Error or NULL on success
 */
static error_t *open_landing_directory(
    deploy_run_t *run,
    const char *ancestor,
    fs_occupant_t occ,
    const struct stat *st
) {
    if (occ != FS_OCCUPANT_DIRECTORY || access(ancestor, W_OK | X_OK) == 0) {
        return NULL;
    }

    const manifest_row_t *dir = holdable_directory(run->ws, ancestor, st);
    if (!dir) {
        return NULL;  /* not ours: the write meets the refusal */
    }

    mode_t current = st->st_mode & 0777;
    error_t *err = fs_create_dir_with_ownership(
        dir->filesystem_path, working_mode(current), (uid_t) -1, (gid_t) -1
    );
    if (err) {
        return error_wrap(
            err, "Failed to open directory '%s' for the run",
            ancestor
        );
    }

    return hold_directory(run, dir->filesystem_path, current);
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
static error_t *ensure_parents(deploy_run_t *run, const char *path) {
    char *scratch = strdup(path);
    if (!scratch) {
        return ERROR(ERR_MEMORY, "Failed to copy path for parent creation");
    }

    error_t *err = NULL;
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
    if (err) {
        goto cleanup;
    }

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
 * Deploy a single view row to its target filesystem location.
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
 * @param out_stat The proof the write authored, in the record's vocabulary (must
 *          not be NULL): the regular arm distills the written descriptor's fstat
 *          (stat_cache_from_write — taken before the rename that publishes it,
 *          so it describes exactly the bytes this run wrote); the symlink arm
 *          leaves the entry default standing. UNSET on every error return
 * @return Error or NULL on success
 */
static error_t *deploy_file(
    deploy_run_t *run, const deploy_verdict_t *v, stat_cache_t *out_stat
) {
    /* The proof's resting state: UNSET unless the regular arm's write lands and
     * binds its own fstat below. The symlink arm never does — a link is made by
     * path (symlink(2) opens no descriptor to describe), and readlink is its
     * whole re-verification. */
    *out_stat = STAT_CACHE_UNSET;

    const manifest_row_t *file = v->row;

    error_t *err = NULL;
    const buffer_t *content_buffer = NULL;  /* Borrowed from cache */
    char *target_str = NULL;

    /* Whether the occupant must go before the write, which is mechanism rather
     * than policy: rename(2) replaces any non-directory in place, so the regular
     * arm clears only a directory; symlink(2) is EEXIST-strict, so the symlink
     * arm clears whatever is there — including an occupant of its own type, which
     * is no conflict and needed no --force. */
    fs_occupant_t want = file_row_occupant(file);
    bool must_clear = (want == FS_OCCUPANT_SYMLINK) ? deploy_occupant_present(v->occupant)
                                                    : (v->occupant == FS_OCCUPANT_DIRECTORY);

    /* Land the path: parents first, whichever arm writes it */
    err = ensure_parents(run, file->filesystem_path);
    if (err) {
        return err;
    }

    /* Handle symlinks - these are never encrypted, so handle separately */
    if (file->type == PATH_TYPE_SYMLINK) {
        /* For symlinks, we load the blob directly since the content layer is
         * designed for regular files with potential encryption. */
        size_t target_len = 0;
        err = gitops_read_blob_content(
            run->repo, &file->blob_oid, (void **) &target_str, &target_len
        );
        if (err) goto cleanup;

        /* symlink(2) refuses an occupied path outright, so the link's own
         * predecessor goes too — the one the verdict named, never one found by
         * a fresh look from down here. */
        if (must_clear) {
            err = clear_occupant(file->filesystem_path, v->occupant);
            if (err) goto cleanup;
        }

        /* Create symlink */
        err = fs_create_symlink(target_str, file->filesystem_path);
        if (err) {
            err = error_wrap(
                err, "Failed to deploy symlink '%s'",
                file->filesystem_path
            );
            goto cleanup;
        }

        /* Symlink permissions are ignored by most filesystems, but symlink
         * OWNERSHIP matters for auditing and consistency. lchown() changes the
         * link itself, not its target. */
        if (v->uid != (uid_t) -1 || v->gid != (gid_t) -1) {
            if (lchown(file->filesystem_path, v->uid, v->gid) != 0) {
                err = ERROR(
                    ERR_FS, "Failed to set ownership on symlink '%s': %s",
                    file->filesystem_path, strerror(errno)
                );
                goto cleanup;
            }
        }

        goto cleanup;
    }

    /* Regular files: content from the cache with transparent decryption */
    err = content_cache_get_from_blob_oid(
        run->cache,
        &file->blob_oid,
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
    if (must_clear) {
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

    /* The write's own proof, distilled where the write authority is in scope:
     * authorship, not a read, vouches for the triple, so its own open second
     * needs no smudge (stat_cache_from_write). */
    *out_stat = stat_cache_from_write(&written);

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
static error_t *deploy_directory(deploy_run_t *run, const deploy_verdict_t *v) {
    const char *path = v->row->filesystem_path;

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
            return ERROR(ERR_INTERNAL, "No verdict for '%s' (occupant unknown)", path);

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
    error_t *err = materialize_directory(run, v);
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
static const char *poisoned_above(const deploy_result_t *result, const char *path) {
    for (size_t i = 0; i < result->failed.count; i++) {
        const deploy_verdict_t *v = result->failed.entries[i].verdict;
        const char *dir = v->row->filesystem_path;

        if (v->row->type != PATH_TYPE_DIRECTORY ||
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
 * (deploy_result_t's contract); the receipt travels in *out beside a release
 * error too, complete.
 */
error_t *deploy_execute(
    git_repository *repo,
    const workspace_t *ws,
    const deploy_preflight_result_t *verdicts,
    content_cache_t *cache,
    deploy_result_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ws);
    CHECK_NULL(verdicts);
    CHECK_NULL(cache);
    CHECK_NULL(out);

    error_t *err = NULL;

    deploy_result_t *result = calloc(1, sizeof(deploy_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate deploy result");
    }

    /* The receipt is sized to the verdicts up front — one slot per verdict, zeroed,
     * filled in verdict order as each act lands (a zero count allocates one slot
     * rather than nothing, so every array is an array; a zeroed slot's stat IS
     * the UNSET triple), the failed bucket to both kinds together — every promised
     * row could fail. count gates what a consumer reads, so an untaken slot is
     * invisible and the receipt holds exactly what happened — for a landed file,
     * with its own write's proof. */
    result->deployed.entries = calloc(
        verdicts->files.count + 1, sizeof(*result->deployed.entries)
    );
    result->converged.entries = calloc(
        verdicts->directories.count + 1, sizeof(*result->converged.entries)
    );
    result->ancestors.entries = calloc(
        verdicts->ancestors.count + 1, sizeof(*result->ancestors.entries)
    );
    result->failed.entries = calloc(
        verdicts->directories.count + verdicts->files.count + 1,
        sizeof(*result->failed.entries)
    );

    if (!result->deployed.entries || !result->converged.entries ||
        !result->ancestors.entries || !result->failed.entries) {
        deploy_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate deployment receipt");
    }

    deploy_run_t run = {
        .repo     = repo,
        .cache    = cache,
        .ws       = ws,
        .verdicts = verdicts,
        .result   = result,
        .held     = { 0 },
    };

    /* Directories first: parents before the files beneath them, and under --force
     * a squatting symlink is gone before anything is written through it. Verdict
     * order is the plan's prefix order = parents before children, which is also
     * what lets a replace settle everything beneath it: a planned path under a
     * replaced directory carries an absent occupant, and by the time it is reached
     * the replace has made that true. */
    for (size_t i = 0; i < verdicts->directories.count; i++) {
        const deploy_verdict_t *v = &verdicts->directories.entries[i];
        const char *above = poisoned_above(result, v->row->filesystem_path);

        err = above ? ERROR(ERR_FS, "'%s' was not converged", above)
                    : deploy_directory(&run, v);
        if (err) {
            /* The row's own outcome; the cause already names its subject */
            deploy_outcome_t *o = &result->failed.entries[result->failed.count++];

            o->verdict = v;
            o->error = err;
            err = NULL;
            continue;
        }

        /* Record success; the verb is the verdict's occupant */
        result->converged.entries[result->converged.count++].verdict = v;
    }

    /* Every verdict is work the plan chose, by construction: the planner routed
     * the row through deploy_needs_work and past every reason to skip it, so
     * this loop applies no filter of its own. Clean in-scope rows with deployed_at
     * == 0 are apply's adoption step, which stamps the anchor without
     * deploy_file. */
    for (size_t i = 0; i < verdicts->files.count; i++) {
        const deploy_verdict_t *v = &verdicts->files.entries[i];
        deploy_outcome_t *o = &result->deployed.entries[result->deployed.count];
        const char *above = poisoned_above(result, v->row->filesystem_path);

        err = above ? ERROR(ERR_FS, "'%s' was not converged", above)
                    : deploy_file(&run, v, &o->stat);
        if (err) {
            /* The row's own outcome, as above. The deployed slot stays untaken:
             * count never covers it, and its stat is UNSET on every deploy_file
             * error return. */
            deploy_outcome_t *f = &result->failed.entries[result->failed.count++];

            f->verdict = v;
            f->error = err;
            err = NULL;
            continue;
        }

        /* Record success */
        o->verdict = v;
        result->deployed.count++;
    }

    /* The subtree is as complete as it is going to get: exact modes now. The
     * rows' failures are in the receipt; what the release returns is the run's
     * one non-row error, and the receipt travels beside it either way. */
    err = release_directories(&run);

    *out = result;
    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Teardown
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Free preflight result — the warnings, the skip array and the verdict arrays.
 * The rows they all point at belong to the workspace.
 */
void deploy_preflight_result_free(deploy_preflight_result_t *verdicts) {
    if (!verdicts) {
        return;
    }

    string_array_free(verdicts->warnings);
    free(verdicts->directories.entries);
    free(verdicts->files.entries);
    free(verdicts->ancestors.entries);
    free(verdicts->skipped.entries);
    free(verdicts);
}

/**
 * Free a deployment receipt — the four outcome arrays, and the failed bucket's
 * owned causes. The verdicts they all point at belong to the preflight result.
 */
void deploy_result_free(deploy_result_t *result) {
    if (!result) {
        return;
    }

    for (size_t i = 0; i < result->failed.count; i++) {
        error_free(result->failed.entries[i].error);
    }

    free(result->deployed.entries);
    free(result->converged.entries);
    free(result->ancestors.entries);
    free(result->failed.entries);
    free(result);
}
