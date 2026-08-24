/**
 * deploy.c - File and tracked-directory deployment engine implementation
 */

#include "core/deploy.h"

#include <errno.h>
#include <git2.h>
#include <stdio.h>
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

/**
 * The mode create_ancestor gives an untracked missing parent, and the fallback
 * resolve_metadata substitutes for a tracked directory row state never gave a
 * mode to. One constant, two readers.
 */
#define DEPLOY_DIR_MODE_DEFAULT 0755

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
             * content_conflicts below states the same rule for overwrites. A
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
 * Is `path` beneath a pending directory row observed squatted?
 *
 * A non-directory at a tracked directory's path is what every probe of the paths
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
 * Squatted is the workspace's TYPE verdict on the row, and only a *pending* row
 * counts: one -e skips is not replaced this run, so what was observed through
 * it stands. Walks directories.pending, which is in prefix order, so the planner
 * can ask this of a directory row while the bucket is still filling and find
 * the row's ancestors already there. Preflight asks it once more per row and
 * writes the answer into the verdict's occupant, which is where the executors
 * read it.
 *
 * @param ws Workspace, for the ancestor's verdict (must not be NULL)
 * @param plan Plan whose pending directories are the candidates (must not be NULL)
 * @param path Planned path (must not be NULL)
 */
static bool beneath_squatted_directory(
    const workspace_t *ws, const deploy_plan_t *plan, const char *path
) {
    manifest_rows_t dirs = manifest_rows_view(&plan->directories.pending);

    for (size_t i = 0; i < dirs.count; i++) {
        const char *dir = dirs.entries[i]->filesystem_path;
        size_t len = strlen(dir);

        /* Strictly beneath: a prefix and then a separator, the same test cleanup's
         * managed_beneath makes (strncmp == 0 guarantees path has at least len
         * bytes, so path[len] is in bounds). */
        if (strncmp(path, dir, len) != 0 || path[len] != '/') {
            continue;
        }

        const workspace_item_t *item = workspace_get_item(ws, dir);
        if (item && (item->divergence & DIVERGENCE_TYPE)) {
            return true;
        }
    }

    return false;
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

    /* Directories before files: a pending directory row observed squatted plans
     * every path beneath it as absent (beneath_squatted_directory), and those
     * paths are of either kind — so the pending directory bucket must be complete,
     * in prefix order, before a file is classified, and each directory row must
     * find its own ancestors already classified. */
    manifest_rows_t dirs = workspace_directories(ws);
    for (size_t i = 0; i < dirs.count; i++) {
        const manifest_row_t *row = dirs.entries[i];

        if (!scope_accepts_profile(scope, row->profile) ||
            !scope_accepts_path(scope, row->storage_path, PATH_KIND_DIRECTORY)) {
            continue;                        /* out of scope: invisible */
        }

        bool absent = beneath_squatted_directory(ws, plan, row->filesystem_path);

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
        bool absent = beneath_squatted_directory(ws, plan, row->filesystem_path);

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

    return file->type == PATH_TYPE_SYMLINK ? FS_OCCUPANT_SYMLINK : FS_OCCUPANT_REGULAR;
}

/**
 * Is something known to be standing at the path?
 *
 * FS_OCCUPANT_UNKNOWN deliberately answers no. Deploy judges nothing it could
 * not see: the mutation goes ahead and surfaces the real errno, rather than acting
 * on a guess about what it failed to stat.
 */
static bool occupant_present(fs_occupant_t occ) {
    return occ != FS_OCCUPANT_NONE && occ != FS_OCCUPANT_UNKNOWN;
}

/**
 * Does what stands at the path disagree with what the row materializes?
 */
static bool occupant_conflicts(fs_occupant_t occ, fs_occupant_t want) {
    return occupant_present(occ) && occ != want;
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
 * The tracked row of a present directory this run may hold, or NULL
 *
 * A tracked directory — any enabled profile, in scope or not, the same reach
 * create_ancestor has — that we own. The run may carry it at a working mode while
 * the paths beneath it land and release it afterwards (deploy_run_t), so its
 * current mode can never refuse a tracked path. Nothing else is ours to touch:
 * an untracked directory that refuses is a permission error, and a tracked one
 * we do not own cannot be fchmod'd at all. Root owns everything for this purpose.
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
 * Is `path` a pending directory row?
 *
 * A pending row is one the directory pass acts on before any file is written:
 * it creates the path, replaces whatever squats it, or converges what is already
 * there — and whichever it does, the directory carries a working mode until the
 * run is over, so nothing planned beneath it is refused on its account.
 */
static bool directory_is_pending(const deploy_plan_t *plan, const char *path) {
    manifest_rows_t dirs = manifest_rows_view(&plan->directories.pending);

    for (size_t i = 0; i < dirs.count; i++) {
        if (strcmp(dirs.entries[i]->filesystem_path, path) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Is this row's content not dotta's to overwrite unasked?
 *
 * The counterpart of occupant_conflicts, answered from the workspace's divergence
 * verdict: content is compared against a blob that is not on disk, so the load-time
 * verdict is the only authority there is — no lstat can improve on it.
 *
 * A TYPE verdict counts, because it means the compare never produced a content
 * verdict at all: whatever stood at the path was never measured against the row.
 * DIVERGENCE_STALE without CONTENT never conflicts: the bytes on disk are the
 * ones dotta itself deployed, so the overwrite loses nothing. Mode, ownership
 * and encryption divergence never block.
 *
 * @param item Workspace verdict for the row (NULL = not in the index)
 */
static bool content_conflicts(const workspace_item_t *item) {
    return item != NULL &&
           (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE));
}

/**
 * Record a formatted entry in one of the preflight arrays — a finding that carries
 * its own reason (a blocked path, a landing directory that refuses us), or a
 * warning. Takes ownership of `entry`; NULL means the formatting itself failed.
 */
static error_t *push_entry(string_array_t *entries, char *entry) {
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to format preflight entry");
    }

    error_t *err = string_array_push_owned(entries, entry);
    if (err) {
        free(entry);
    }
    return err;
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
 *   a pending directory row   the directory pass converges it first —
 *                             created, fixed or replaced — and carries it at a
 *                             working mode; fine, whatever squats it now (a
 *                             squatter is the row's own conflict)
 *   a tracked directory       ours to hold (holdable_directory): if it
 *                             refuses, ensure_parents opens it for the run and
 *                             releases it afterwards; fine
 *   any other directory       must accept a new entry now — access(2),
 *                             which unlike a mode test knows about ownership,
 *                             groups, ACLs and root — or it is a permission error;
 *                             a symlink to a directory is asked through the link
 *   anything else             an untracked non-directory squats the
 *                             ancestry, and this run will not replace it (Coherent
 *                             Scope) — blocked, by hand
 *   unreachable               EACCES is a refusal too (permission error);
 *                             any other errno is left for the write to report
 *
 * The mechanism asks the very same questions of the very same ancestor
 * (ensure_parents), so this is a prediction of the run, not a model of it.
 *
 * @param ws Workspace, for the tracked-ancestor lookup (must not be NULL)
 * @param plan Deployment plan, for the pending-directory test (must not be NULL)
 * @param path Planned path (must not be NULL)
 * @param result Preflight result to record a finding in (must not be NULL)
 * @return Error or NULL on success (a finding is not an error)
 */
static error_t *check_landing(
    const workspace_t *ws, const deploy_plan_t *plan,
    const char *path, deploy_preflight_result_t *result
) {
    char *scratch = strdup(path);
    if (!scratch) {
        return ERROR(ERR_MEMORY, "Failed to copy path for landing check");
    }

    error_t *err = NULL;
    size_t slash;
    fs_occupant_t occ;
    bool is_dir;
    struct stat st;

    if (!nearest_ancestor(scratch, &slash, &occ, &is_dir, &st)) {
        if (errno == EACCES) {
            err = push_entry(
                result->permission_errors,
                str_format("%s (ancestry cannot be reached)", path)
            );
        }
        goto cleanup;  /* anything else: the write reports it */
    }

    scratch[ancestor_len(slash)] = '\0';  /* the ancestor, on its own */

    if (directory_is_pending(plan, scratch)) {
        goto cleanup;
    }
    if (is_dir && access(scratch, W_OK | X_OK) == 0) {
        goto cleanup;
    }
    if (occ == FS_OCCUPANT_DIRECTORY && holdable_directory(ws, scratch, &st)) {
        goto cleanup;
    }

    if (is_dir) {
        err = push_entry(
            result->permission_errors,
            str_format("%s (%s is not writable)", path, scratch)
        );
    } else {
        err = push_entry(
            result->blocked,
            str_format("%s (%s is not a directory)", path, scratch)
        );
    }

cleanup:
    free(scratch);
    return err;
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
 * Strict ownership mode (strict_ownership=true):
 * - ERR_NOT_FOUND (user/group missing): Fatal error, abort deployment
 * - ERR_PERMISSION (not root): Silent (can't chown anyway; see below)
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
        error_t *err = metadata_resolve_ownership(owner, group, out_uid, out_gid);
        if (err) {
            /* Determine error type and whether it should be fatal
             *
             * ERR_NOT_FOUND: User/group doesn't exist on this system
             *   - strict_ownership=true: Fatal (configuration/environment mismatch)
             *   - strict_ownership=false: Warning, continue with default ownership
             *
             * ERR_PERMISSION: Not running as root (can't chown anyway)
             *   - Silent. Not an anomaly but the expected shape of an unelevated
             *     run, and reachable only in a dry one: a real run's privilege
             *     check has re-exec'd under sudo or failed hard before preflight.
             */
            bool is_resolution_failure = (err->code == ERR_NOT_FOUND);
            bool should_fail = is_resolution_failure && strict_ownership;

            if (should_fail) {
                /* Fatal: Return error to abort deployment */
                return error_wrap(
                    err, "Ownership resolution failed for '%s' (strict_mode enabled)\n"
                    "Hint: Create the user/group on this system, or disable strict_mode",
                    storage_path
                );
            }

            /* Non-fatal: record the anomaly and continue */
            if (err->code != ERR_PERMISSION) {
                error_t *push_err = push_entry(
                    warnings,
                    str_format(
                    "Could not resolve ownership for %s: %s",
                    storage_path, error_message(err)
                    )
                );
                if (push_err) {
                    error_free(err);
                    return push_err;
                }
            }

            error_free(err);
            /* Reset to "no change" */
            *out_uid = (uid_t) -1;
            *out_gid = (gid_t) -1;
        }
        return NULL;
    }

    /* Case 3: All other cases -> no ownership change */
    return NULL;
}

/**
 * The metadata a row's write applies: the mode, then the ownership — in that
 * order, so a corrupt row is named even when a strict-mode ownership failure
 * ends preflight there.
 *
 * A row's mode is its metadata item's — a blob row's the filemode default (0644
 * / 0755) unless the profile's metadata claims otherwise, a directory row's the
 * claim alone — and 0 is the one value the item can carry that is no claim at
 * all: a "0000" in the profile's metadata.json. The workspace reads that zero
 * as "no claim" (check_item_metadata_divergence skips the mode check), so preflight
 * reads it the same way — the default keyed on the row's type — and says so,
 * because the recorded value is the user's and they may want to know it is not
 * being honoured. One decision for both kinds; the default is the only thing
 * the kind changes.
 *
 * A symlink row is the one honest zero: the view carries mode 0 for
 * GIT_FILEMODE_LINK and metadata keeps it there, symlink(2) takes no mode and
 * the symlink arm never reads it. Its zero is the recorded value, not a hole —
 * so the question is asked only of the kinds that carry a mode.
 *
 * Ownership is resolved ahead of the write so the write applies it atomically
 * through the descriptor (fchown on the file or directory fd, lchown on a link):
 * there is never a moment when the path exists with the wrong owner.
 *
 * @param row View row (must not be NULL; borrowed, read-only)
 * @param opts Deployment options (must not be NULL)
 * @param warnings Preflight warnings (must not be NULL)
 * @param v Verdict whose mode, uid and gid are decided (must not be NULL)
 * @return Error or NULL on success (a strict-mode ownership failure is one)
 */
static error_t *resolve_metadata(
    const manifest_row_t *row,
    const deploy_options_t *opts,
    string_array_t *warnings,
    deploy_verdict_t *v
) {
    mode_t mode = row->mode;

    if (row->type != PATH_TYPE_SYMLINK && mode == 0) {
        mode = (row->type == PATH_TYPE_DIRECTORY) ? DEPLOY_DIR_MODE_DEFAULT
             : (row->type == PATH_TYPE_EXECUTABLE) ? 0755 : 0644;

        error_t *err = push_entry(
            warnings,
            str_format(
            "Mode 0000 recorded for '%s' in profile '%s' "
            "(.dotta/metadata.json), using default %04o",
            row->filesystem_path, row->profile, mode
            )
        );
        if (err) {
            return err;
        }
    }
    v->mode = mode;

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
 * Does a pending row of either kind lie beneath `dir`?
 *
 * The question that makes a tracked directory outside the plan an ancestor the
 * run may create: ensure_parents climbs from each planned path to its nearest
 * present ancestor and creates every component in between, so a directory row
 * above no pending row is never reached. Strictly beneath — the same test
 * beneath_squatted_directory makes.
 *
 * @param plan Deployment plan (must not be NULL)
 * @param dir Directory path (must not be NULL)
 */
static bool above_pending_row(const deploy_plan_t *plan, const char *dir) {
    const ptr_array_t *buckets[] = { &plan->directories.pending, &plan->files.pending };
    size_t len = strlen(dir);

    for (size_t b = 0; b < sizeof(buckets) / sizeof(buckets[0]); b++) {
        manifest_rows_t rows = manifest_rows_view(buckets[b]);

        for (size_t i = 0; i < rows.count; i++) {
            const char *path = rows.entries[i]->filesystem_path;

            if (strncmp(path, dir, len) == 0 && path[len] == '/') {
                return true;
            }
        }
    }

    return false;
}

/**
 * Decide the verdicts, and the findings that block the run
 *
 * Workspace = analysis layer, preflight = decision layer, execute = execution
 * layer. Divergence verdicts and occupants are O(1) index probes; the one
 * filesystem-level question is the landing (and, for a directory standing where
 * a file belongs, the readdir under path_clearance).
 *
 * Every pending row gets a verdict, findings or not: the arrays are the plan's
 * pending buckets in order, and a caller that meets a finding reads the counts
 * and never the verdicts. A row planned beneath a squatter this run replaces
 * gets its verdict too — absent, nothing asked — so the executors read one shape
 * for every row.
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

    result->conflicts = string_array_new(0);
    result->blocked = string_array_new(0);
    result->permission_errors = string_array_new(0);
    result->warnings = string_array_new(0);

    if (!result->conflicts || !result->blocked || !result->permission_errors ||
        !result->warnings) {
        deploy_preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate result arrays");
    }

    /* One slot per pending row, and one per directory row of the view for the
     * ancestors (an upper bound; the count says how many were decided). A zero
     * count allocates one slot rather than nothing, so every array is an array. */
    manifest_rows_t files = manifest_rows_view(&plan->files.pending);
    manifest_rows_t dirs = manifest_rows_view(&plan->directories.pending);
    manifest_rows_t all_dirs = workspace_directories(ws);

    result->directories.entries = calloc(dirs.count + 1, sizeof(deploy_verdict_t));
    result->files.entries = calloc(files.count + 1, sizeof(deploy_verdict_t));
    result->ancestors.entries = calloc(all_dirs.count + 1, sizeof(deploy_verdict_t));

    if (!result->directories.entries || !result->files.entries ||
        !result->ancestors.entries) {
        deploy_preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate verdict arrays");
    }

    error_t *err = NULL;

    for (size_t i = 0; i < files.count; i++) {
        const manifest_row_t *row = files.entries[i];
        const char *path = row->filesystem_path;
        deploy_verdict_t *v = &result->files.entries[result->files.count++];

        v->row = row;

        /* Planned as absent: every probe of this path would reach the squatter's
         * target and answer for the wrong tree, and the path is empty once the
         * directory pass has replaced the squatter — no type, no content, nothing
         * in the way. Its landing is the pending ancestor's, whose own row is
         * asked below. */
        if (beneath_squatted_directory(ws, plan, path)) {
            v->occupant = FS_OCCUPANT_NONE;
            err = resolve_metadata(row, opts, result->warnings, v);
            if (err) goto cleanup;
            continue;
        }

        /* A pending row not beneath a squatter has an item: the planner routed
         * it through deploy_needs_work, and deploy_needs_work(NULL) is false. */
        const workspace_item_t *item = workspace_get_item(ws, path);
        v->occupant = item->occupant;

        if (occupant_conflicts(v->occupant, file_row_occupant(row))) {
            /* Type: what stands at the path decides the remedy. */
            switch (path_clearance(path, v->occupant, opts->force)) {
                case CLEARANCE_OK:
                    break;

                case CLEARANCE_NEEDS_FORCE:
                    err = string_array_push(result->conflicts, path);
                    if (err) goto cleanup;
                    break;

                case CLEARANCE_REFUSED:
                    err = push_entry(
                        result->blocked,
                        str_format("%s (a non-empty directory is in the way)", path)
                    );
                    if (err) goto cleanup;
                    break;
            }
        } else if (!opts->force && content_conflicts(item)) {
            /* Content, asked only when the occupant is the row's own type: a
             * path holding something else has no content to compare. */
            err = string_array_push(result->conflicts, path);
            if (err) goto cleanup;
        }

        /* Every file row lands through its parent, whichever arm writes it and
         * whether or not something is already at the path — so one question covers
         * both, and it is never about the path itself. */
        size_t findings = result->permission_errors->count + result->blocked->count;

        err = check_landing(ws, plan, path, result);
        if (err) goto cleanup;

        /* An occupant the workspace could not examine is no verdict: nothing
         * can say what the run will find there, and nothing is written on a guess
         * (neither question above is asked of it — UNKNOWN is not present). The
         * ancestry that refused the lstat is what refuses the write, and the
         * landing has just named it when it could (EACCES on the way up); the
         * path is named on its own only when the landing had nothing to say —
         * an errno the write would otherwise have surfaced mid-run. */
        if (v->occupant == FS_OCCUPANT_UNKNOWN &&
            result->permission_errors->count + result->blocked->count == findings) {
            err = push_entry(
                result->permission_errors,
                str_format("%s (cannot be verified)", path)
            );
            if (err) goto cleanup;
        }

        err = resolve_metadata(row, opts, result->warnings, v);
        if (err) goto cleanup;
    }

    for (size_t i = 0; i < dirs.count; i++) {
        const manifest_row_t *row = dirs.entries[i];
        const char *path = row->filesystem_path;
        deploy_verdict_t *v = &result->directories.entries[result->directories.count++];

        v->row = row;

        /* Planned as absent (see the file loop): created beneath a directory
         * this run replaces first, so neither a conflict nor a landing question
         * is its own. */
        if (beneath_squatted_directory(ws, plan, path)) {
            v->occupant = FS_OCCUPANT_NONE;
            err = resolve_metadata(row, opts, result->warnings, v);
            if (err) goto cleanup;
            continue;
        }

        const workspace_item_t *item = workspace_get_item(ws, path);
        v->occupant = item->occupant;

        /* A planned directory squatted by a non-directory (the link itself, so
         * a symlink to a directory counts) is replaced under --force, one node
         * at a time. The squatter can never be a directory — that is the row
         * converging in place — so path_clearance cannot refuse here and "use
         * --force" is always the true remedy. */
        if (occupant_conflicts(v->occupant, FS_OCCUPANT_DIRECTORY) &&
            path_clearance(path, v->occupant, opts->force) != CLEARANCE_OK) {
            err = string_array_push(result->conflicts, path);
            if (err) goto cleanup;
        }

        /* A directory already there is converged in place: fchmod and fchown
         * ask for ownership, not for a writable parent. Only a create or a replace
         * lands a new entry. An unexaminable occupant is asked too, and named
         * on its own when the landing had nothing to say — as for a file. */
        size_t findings = result->permission_errors->count + result->blocked->count;

        if (v->occupant != FS_OCCUPANT_DIRECTORY) {
            err = check_landing(ws, plan, path, result);
            if (err) goto cleanup;
        }

        if (v->occupant == FS_OCCUPANT_UNKNOWN &&
            result->permission_errors->count + result->blocked->count == findings) {
            err = push_entry(
                result->permission_errors,
                str_format("%s (cannot be verified)", path)
            );
            if (err) goto cleanup;
        }

        err = resolve_metadata(row, opts, result->warnings, v);
        if (err) goto cleanup;
    }

    /* The ancestors: every directory row the plan does not act on, absent as
     * the plan reads it, that stands above a pending row. Absent as the plan
     * reads it is the planner's own reading — beneath a squatter this run replaces,
     * or the workspace's occupant (a row without an item is present and converged).
     * ensure_parents creates exactly these on the way down to a planned path,
     * with the metadata decided here; a candidate the world makes present before
     * then is simply not created, and costs nothing. */
    for (size_t i = 0; i < all_dirs.count; i++) {
        const manifest_row_t *row = all_dirs.entries[i];
        const char *path = row->filesystem_path;

        if (directory_is_pending(plan, path)) {
            continue;
        }

        const workspace_item_t *item = workspace_get_item(ws, path);
        bool absent = beneath_squatted_directory(ws, plan, path) ||
            (item && item->occupant == FS_OCCUPANT_NONE);

        if (!absent || !above_pending_row(plan, path)) {
            continue;
        }

        deploy_verdict_t *v = &result->ancestors.entries[result->ancestors.count++];

        v->row = row;
        v->occupant = FS_OCCUPANT_NONE;
        err = resolve_metadata(row, opts, result->warnings, v);
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
    const char *path;    /* borrowed from the tracked row (workspace-arena lifetime) */
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
 * pass the tracked row's own filesystem_path.
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
 * Runs on every exit from deploy_execute, fail-stop included: after a failure
 * the tree is incomplete, but every directory carries its recorded mode, and
 * the next run holds what it needs again. Applied through
 * fs_create_dir_with_ownership — the same fd-based fchmod the converge arm uses,
 * never a chmod(2) on a path that may have become a symlink meanwhile. Every
 * entry is attempted; the first failure is the one reported. Frees the holds
 * either way.
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
 * Create or converge a tracked directory at its working mode
 *
 * Ownership applies atomically through the descriptor
 * (fs_create_dir_with_ownership); idempotent, so a directory already there is
 * converged in place. The row is held for release when its recorded mode is
 * narrower than the working mode (hold_directory).
 *
 * @param run Run context (must not be NULL)
 * @param dir Tracked row (must not be NULL; borrowed, read-only)
 * @param mode Resolved target mode (the verdict's)
 * @param uid Resolved UID or -1 for no change
 * @param gid Resolved GID or -1 for no change
 * @return Error or NULL on success
 */
static error_t *materialize_tracked_directory(
    deploy_run_t *run,
    const manifest_row_t *dir,
    mode_t mode, uid_t uid, gid_t gid
) {
    error_t *err = fs_create_dir_with_ownership(
        dir->filesystem_path, working_mode(mode), uid, gid
    );
    if (err) {
        return err;
    }

    return hold_directory(run, dir->filesystem_path, mode);
}

/**
 * Materialize one absent ancestor whose own parent exists: a tracked directory
 * (any profile, in scope or not) with the metadata its ancestor verdict carries,
 * anything else 0755 owned like the planned path beneath it. The 0755 is exact
 * (fchmod), not umask-masked — dotta reproduces modes, it does not negotiate
 * them — and already carries the owner triad, so an untracked parent is never held.
 *
 * The verdicts are the authority for what is tracked here, not the view: a tracked
 * directory preflight did not foresee as absent (present then, gone since) has
 * no metadata decided for it, is made like an untracked parent, and is left for
 * the next load to read — which sees its record and its row, and says [mode] if
 * the two disagree.
 *
 * @param run Run context (must not be NULL)
 * @param path Absent ancestor to create (must not be NULL)
 * @param uid UID of the planned path beneath it (-1 for no change)
 * @param gid GID of the planned path beneath it (-1 for no change)
 * @return Error or NULL on success
 */
static error_t *create_ancestor(
    deploy_run_t *run,
    const char *path,
    uid_t uid, gid_t gid
) {
    const deploy_verdicts_t *ancestors = &run->verdicts->ancestors;

    for (size_t i = 0; i < ancestors->count; i++) {
        const deploy_verdict_t *v = &ancestors->entries[i];

        if (strcmp(v->row->filesystem_path, path) != 0) {
            continue;
        }

        RETURN_IF_ERROR(
            materialize_tracked_directory(run, v->row, v->mode, v->uid, v->gid)
        );
        return ptr_array_push(&run->result->ancestors, v->row);
    }

    return fs_create_dir_with_ownership(path, DEPLOY_DIR_MODE_DEFAULT, uid, gid);
}

/**
 * Open a planned path's landing directory for the run
 *
 * The nearest present ancestor is where the write lands, and it must accept a
 * new entry. An absent chain below it is created at working modes and cannot
 * refuse; the ancestor itself can — a tracked 0555 directory that is already
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
            err, "Failed to open tracked directory '%s' for the run",
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
 * @param uid Resolved UID of the planned path (-1 for no change)
 * @param gid Resolved GID of the planned path (-1 for no change)
 * @return Error or NULL on success
 */
static error_t *ensure_parents(
    deploy_run_t *run,
    const char *path,
    uid_t uid, gid_t gid
) {
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
        err = create_ancestor(run, scratch, uid, gid);
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
 * that filled up is ENOTEMPTY) and the run fail-stops there.
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
 * @return Error or NULL on success
 */
static error_t *deploy_file(deploy_run_t *run, const deploy_verdict_t *v) {
    CHECK_NULL(run);
    CHECK_NULL(v);

    const manifest_row_t *file = v->row;

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    const buffer_t *content_buffer = NULL;  /* Borrowed from cache (const) */
    char *target_str = NULL;

    /* Whether the occupant must go before the write, which is mechanism rather
     * than policy: rename(2) replaces any non-directory in place, so the regular
     * arm clears only a directory; symlink(2) is EEXIST-strict, so the symlink
     * arm clears whatever is there — including an occupant of its own type, which
     * is no conflict and needed no --force. */
    fs_occupant_t want = file_row_occupant(file);
    bool must_clear = (want == FS_OCCUPANT_SYMLINK) ? occupant_present(v->occupant)
                                                    : (v->occupant == FS_OCCUPANT_DIRECTORY);

    /* Land the path: parents first, whichever arm writes it */
    err = ensure_parents(run, file->filesystem_path, v->uid, v->gid);
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

        /* Success for symlink - goto cleanup will handle freeing */
        err = NULL;
        goto cleanup;
    }

    /* Regular files: content from the cache with transparent decryption */
    err = content_cache_get_from_blob_oid(
        run->cache,
        &file->blob_oid,
        file->storage_path,
        file->profile ? file->profile : "unknown",
        &content_buffer
    );

    if (err) {
        err = error_wrap(
            err, "Failed to get content for '%s'",
            file->storage_path
        );
        goto cleanup;
    }

    /* Get content pointer and size from buffer */
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
    err = fs_write_file_raw(
        file->filesystem_path, content, size, v->mode, v->uid, v->gid
    );

    if (err) {
        err = error_wrap(
            err, "Failed to deploy file '%s'",
            file->filesystem_path
        );
        goto cleanup;
    }

    /* Success */
    err = NULL;

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
    CHECK_NULL(run);
    CHECK_NULL(v);

    const manifest_row_t *dir = v->row;
    const char *path = dir->filesystem_path;
    error_t *err = NULL;

    switch (v->occupant) {
        case FS_OCCUPANT_DIRECTORY:
            /* Converged in place below */
            break;

        case FS_OCCUPANT_NONE:
            /* Absent — or beneath a non-directory, which preflight blocked when
             * unplanned and the directory pass replaces when planned (prefix
             * order); one still there is ensure_parents' named error. */
            err = ensure_parents(run, path, v->uid, v->gid);
            if (err) {
                return err;
            }
            break;

        case FS_OCCUPANT_UNKNOWN:
            /* Not a verdict: preflight turned it into a finding, and a caller
             * with a finding does not execute. Said here rather than unlinked. */
            return ERROR(ERR_INTERNAL, "No verdict for '%s' (occupant unknown)", path);

        default:
            /* A single node in the way, cleared before the mkdir — the node the
             * verdict named. It can never be a directory (that is the first arm),
             * and --force was preflight's question. */
            RETURN_IF_ERROR(clear_occupant(path, v->occupant));
            break;
    }

    /* Create-or-fix with atomic ownership and permissions (fchown/fchmod on the
     * directory fd — no window with wrong metadata). Idempotent. */
    err = materialize_tracked_directory(run, dir, v->mode, v->uid, v->gid);
    if (err) {
        return error_wrap(err, "Failed to create tracked directory: %s", path);
    }

    return NULL;
}

/**
 * Carry the verdicts out
 *
 * Every exit passes through release_directories: a held directory takes its exact
 * recorded mode whether the run completed or fail-stopped, so the tree a failure
 * leaves behind is incomplete but never wider than recorded. The partial result
 * travels with the error either way.
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

    /* calloc zeroes the ptr_array_t buckets — that IS their empty state */
    deploy_result_t *result = calloc(1, sizeof(deploy_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate deploy result");
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

        err = deploy_directory(&run, v);
        if (err) {
            /* Fail-stop with the partial result; the error names the path */
            err = error_wrap(
                err, "Failed to converge directory '%s'",
                v->row->filesystem_path
            );
            goto done;
        }

        /* Record success in the bucket for what the verdict said stood there */
        switch (v->occupant) {
            case FS_OCCUPANT_NONE:
                err = ptr_array_push(&result->created, v->row);
                break;

            case FS_OCCUPANT_DIRECTORY:
                err = ptr_array_push(&result->fixed, v->row);
                break;

            default:
                err = ptr_array_push(&result->replaced, v->row);
                break;
        }
        if (err) {
            err = error_wrap(err, "Failed to record converged directory");
            goto done;
        }
    }

    /* Every verdict is work the plan chose, by construction: the planner routed
     * the row through deploy_needs_work and past every reason to skip it, so
     * this loop applies no filter of its own. Clean in-scope rows with deployed_at
     * == 0 are apply's adoption step, which stamps the anchor without
     * deploy_file. */
    for (size_t i = 0; i < verdicts->files.count; i++) {
        const deploy_verdict_t *v = &verdicts->files.entries[i];

        err = deploy_file(&run, v);
        if (err) {
            /* Fail-stop with the partial result; the error names the path */
            err = error_wrap(
                err, "Deployment failed at '%s'",
                v->row->filesystem_path
            );
            goto done;
        }

        /* Record success */
        err = ptr_array_push(&result->deployed, v->row);
        if (err) {
            err = error_wrap(err, "Failed to record deployed file");
            goto done;
        }
    }

done:
    /* The subtree is as complete as it is going to get: exact modes now. A release
     * failure after a run that otherwise succeeded is the run's error; after a
     * fail-stop it is secondary to the cause and is only reported, so the cause
     * is what the caller sees. */
    {
        error_t *release_err = release_directories(&run);
        if (release_err) {
            if (err) {
                fprintf(stderr, "Warning: %s\n", error_message(release_err));
                error_free(release_err);
            } else {
                err = release_err;
            }
        }
    }

    *out = result;
    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Teardown
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Free preflight result — the findings, the warnings, and the verdict arrays.
 * The rows the verdicts point at belong to the workspace.
 */
void deploy_preflight_result_free(deploy_preflight_result_t *result) {
    if (!result) {
        return;
    }

    string_array_free(result->conflicts);
    string_array_free(result->blocked);
    string_array_free(result->permission_errors);
    string_array_free(result->warnings);
    free(result->directories.entries);
    free(result->files.entries);
    free(result->ancestors.entries);
    free(result);
}

/**
 * Free deployment result
 *
 * Each ptr_array_t holds borrowed row pointers (workspace-arena lifetime), so
 * deinit only releases the bucket buffers — the rows themselves outlive us.
 */
void deploy_result_free(deploy_result_t *result) {
    if (!result) {
        return;
    }

    ptr_array_deinit(&result->deployed);
    ptr_array_deinit(&result->created);
    ptr_array_deinit(&result->fixed);
    ptr_array_deinit(&result->replaced);
    ptr_array_deinit(&result->ancestors);
    free(result);
}
