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
#include "core/state.h"
#include "core/workspace.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/privilege.h"

/* ══════════════════════════════════════════════════════════════════
 * Rows
 * ══════════════════════════════════════════════════════════════════ */

/**
 * The mode create_ancestor gives an untracked missing parent, and the
 * fallback for a tracked directory row state never gave a mode to. One
 * constant, three readers.
 */
#define DEPLOY_DIR_MODE_DEFAULT 0755

/**
 * The mode a tracked-directory row means
 *
 * A row whose mode is zero is a state-database defect, not a request for
 * mode 0 — resolve_directory_metadata says so out loud on the executor's
 * path. This is the value alone, so preflight can predict the same mode
 * without emitting that warning a second time.
 */
static mode_t directory_row_mode(const state_directory_entry_t *dir) {
    return dir->mode ? dir->mode : DEPLOY_DIR_MODE_DEFAULT;
}

/* ══════════════════════════════════════════════════════════════════
 * Plan
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Deploy's work predicate over a workspace verdict
 *
 * Two dimensions, in order: state (where does the path exist — Git, state
 * database, filesystem?) sets the baseline, divergence (what is wrong with
 * it?) refines it. A missing path is always work and always carries
 * DIVERGENCE_NONE — properties of something that is not there cannot be
 * compared, so the two missing states answer from state alone.
 *
 * Kind-agnostic: directory analysis tags only MODE / OWNERSHIP / TYPE /
 * UNVERIFIED (never content, encryption or stale), so the DEPLOYED arm's
 * mask already covers every directory verdict — no kind-specific arm.
 *
 * The planner iterates the active slices, so the three non-active states
 * never reach this; their arms name the owner that does handle them and
 * keep -Wswitch quiet.
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
            /* File exists in Git but has never been deployed to filesystem.
             * Needs initial deployment.
             *
             * Note: divergence is always NONE for missing files (can't compare
             * properties of non-existent files). */
            return true;

        case WORKSPACE_STATE_DELETED:
            /* File exists in Git and was previously deployed (deployed_at > 0),
             * but has been removed from filesystem. Needs restoration.
             *
             * Note: divergence is always NONE for missing files. */
            return true;

        case WORKSPACE_STATE_DEPLOYED:
            /* File exists on filesystem and is tracked in Git.
             * Needs deployment only if properties diverged (content, mode, ownership, etc.).
             *
             * If divergence == NONE: file is clean, matches Git perfectly.
             * If divergence != NONE: file has property mismatches, needs redeployment.
             *
             * DIVERGENCE_STALE is informational (VWD cache was patched in-memory from
             * fresh Git state). It does NOT indicate a filesystem mismatch — the patched
             * values are the new expected state. Mask it out to avoid spurious deployment
             * when the file content already matches the new Git state. */
            return (item->divergence & ~DIVERGENCE_STALE) != DIVERGENCE_NONE;

        case WORKSPACE_STATE_ORPHANED:
            /* Path exists in deployment state but not in any enabled profile.
             *
             * Not reachable from the planner: both active slices are
             * partitioned to enabled profiles, and orphan rows are exactly
             * the ones that partition rejected.
             *
             * Never deployment — cleanup owns orphan removal. */
            return false;

        case WORKSPACE_STATE_UNTRACKED:
            /* File exists on filesystem in a tracked directory but not in Git.
             *
             * Architectural invariant: Untracked files should NOT appear in the active
             * slice (which is built from state rows, not filesystem scans). If we
             * reach here, it's a programming error.
             *
             * Defensive: Return false (don't deploy untracked files, user must 'add' them). */
            return false;

        case WORKSPACE_STATE_RELEASED:
            /* File removed from Git externally, released from management.
             * Never needs deployment — cleanup handles state entry removal. */
            return false;
    }

    /* Unreachable once every enum value is handled — defensive against a
     * value from outside the enum. */
    return false;
}

/**
 * Route one in-scope row into its partition bucket, or drop it
 * (clean + excluded is neither work nor adoptable).
 *
 * @param part Partition for the row's kind (must not be NULL)
 * @param row Borrowed state row (must not be NULL)
 * @param work Deploy's work predicate for the row
 * @param excluded Held back by an -e pattern
 * @return Error or NULL on success
 */
static error_t *partition_push(
    deploy_partition_t *part,
    const void *row,
    bool work,
    bool excluded
) {
    ptr_array_t *bucket;

    if (excluded) {
        if (!work) return NULL;
        bucket = &part->excluded;
    } else {
        bucket = work ? &part->pending : &part->clean;
    }

    return ptr_array_push(bucket, row);
}

/**
 * Build the deployment plan
 */
error_t *deploy_plan_build(
    const workspace_t *ws, const scope_t *scope, deploy_plan_t **out
) {
    CHECK_NULL(ws);
    CHECK_NULL(scope);
    CHECK_NULL(out);

    /* calloc zeroes the six ptr_array_t buckets — that IS their empty state */
    deploy_plan_t *plan = calloc(1, sizeof(*plan));
    if (!plan) {
        return ERROR(ERR_MEMORY, "Failed to allocate deploy plan");
    }

    error_t *err = NULL;

    state_files_t files = workspace_files(ws);
    for (size_t i = 0; i < files.count; i++) {
        const state_file_entry_t *row = files.entries[i];

        if (!scope_accepts_profile(scope, row->profile) ||
            !scope_accepts_path(scope, row->storage_path, PATH_KIND_FILE)) {
            continue;                        /* out of scope: invisible */
        }

        err = partition_push(
            &plan->files,
            row,
            deploy_needs_work(workspace_get_item(ws, row->filesystem_path)),
            scope_is_excluded(scope, row->storage_path, PATH_KIND_FILE)
        );
        if (err) goto cleanup;
    }

    state_directories_t dirs = workspace_directories(ws);
    for (size_t i = 0; i < dirs.count; i++) {
        const state_directory_entry_t *row = dirs.entries[i];

        if (!scope_accepts_profile(scope, row->profile) ||
            !scope_accepts_path(scope, row->storage_path, PATH_KIND_DIRECTORY)) {
            continue;
        }

        err = partition_push(
            &plan->directories,
            row,
            deploy_needs_work(workspace_get_item(ws, row->filesystem_path)),
            scope_is_excluded(scope, row->storage_path, PATH_KIND_DIRECTORY)
        );
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
    ptr_array_deinit(&plan->directories.pending);
    ptr_array_deinit(&plan->directories.clean);
    ptr_array_deinit(&plan->directories.excluded);

    free(plan);
}

/* ══════════════════════════════════════════════════════════════════
 * Ancestors
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Byte length of the ancestor ending at the slash at index `slash`. The
 * root is the one ancestor that IS its slash: index 0 means "/", one byte.
 */
static size_t ancestor_len(size_t slash) {
    return slash ? slash : 1;
}

/**
 * stat the ancestor of `scratch` ending at the slash at index `slash`,
 * NUL-terminating it in place for the call and restoring the byte
 * afterwards. errno is stat's.
 */
static int stat_ancestor(char *scratch, size_t slash, struct stat *st) {
    size_t len = ancestor_len(slash);
    char saved = scratch[len];
    scratch[len] = '\0';
    int rc = stat(scratch, st);
    int saved_errno = errno;
    scratch[len] = saved;
    errno = saved_errno;
    return rc;
}

/**
 * Nearest existing ancestor of an absolute path (parent, grandparent, …)
 *
 * Follows symlinks — a symlinked configuration directory is a directory
 * for the purpose of writing beneath it. `scratch` is a writable copy of
 * the path, intact on return; *out_slash receives the index of the slash
 * that ends the ancestor (0 for "/"), *st its stat. False only when stat
 * fails for a reason other than absence — the write will surface the
 * real errno.
 */
static bool nearest_ancestor(char *scratch, size_t *out_slash, struct stat *st) {
    size_t i = strlen(scratch);
    for (;;) {
        do {
            if (i == 0) return false;           /* not absolute — cannot happen */
        } while (scratch[--i] != '/');

        if (stat_ancestor(scratch, i, st) == 0) {
            *out_slash = i;
            return true;
        }
        if (errno != ENOENT && errno != ENOTDIR) {
            return false;
        }
        if (i == 0) {
            return false;                       /* "/" itself unstattable */
        }
        /* ENOENT: keep climbing. ENOTDIR: a higher ancestor is a
         * non-directory — keep climbing until stat lands on it. */
    }
}

/* ══════════════════════════════════════════════════════════════════
 * Preflight
 * ══════════════════════════════════════════════════════════════════ */

/**
 * The pending directory row at `path`, or NULL
 *
 * A pending row is one the directory pass acts on before any file is
 * written: it creates the path, replaces whatever squats it, or fchmods
 * what is already there. All three end with the row's own mode on disk,
 * so a pending row — not the current stat — is what the file pass will
 * meet.
 */
static const state_directory_entry_t *pending_directory(
    const deploy_plan_t *plan, const char *path
) {
    state_directories_t dirs = state_directories_view(&plan->directories.pending);

    for (size_t i = 0; i < dirs.count; i++) {
        if (strcmp(dirs.entries[i]->filesystem_path, path) == 0) {
            return dirs.entries[i];
        }
    }

    return NULL;
}

/**
 * Will a directory this run gives `mode` to let the write through?
 *
 * The owner triad is the kernel's own rule here, not an approximation of
 * it. POSIX consults exactly one class and stops, and the identity that
 * writes is the identity that will own this directory — creating it makes
 * us the owner, handing it to anyone else needs root. Group and other bits
 * are unreachable, so a mode like 0570 refuses its own owner and this says
 * so.
 *
 * Root is exempt: mode bits are advisory to the superuser, and a root run
 * is exactly how a root/ profile's read-only directories reach disk today.
 * Refusing them would block a run that works.
 */
static bool mode_permits(mode_t mode, bool is_parent) {
    if (privilege_is_elevated()) {
        return true;
    }

    /* The parent receives a new entry, so it must be writable as well as
     * searchable; everything above it is only walked through. */
    mode_t need = is_parent ? (S_IWUSR | S_IXUSR) : S_IXUSR;
    return (mode & need) == need;
}

/**
 * One component's answer on the way up from a planned path
 */
typedef enum {
    LANDING_CLIMB,            /* permits; its own ancestors still matter */
    LANDING_SETTLED,          /* permits, and nothing above it is left to ask */
    LANDING_UNWRITABLE,       /* a directory this run leaves alone refuses us */
    LANDING_MODE_BLOCKED,     /* a tracked directory's own mode refuses */
    LANDING_NOT_A_DIRECTORY,  /* an untracked non-directory squats a parent */
    LANDING_ABSTAIN           /* unstattable for a reason other than absence */
} landing_verdict_t;

/**
 * Judge one component of a planned path against the state this run will
 * have left it in by the time the write arrives.
 *
 * Three producers can decide a component's mode, and each is asked only
 * where it is the authority:
 *
 *   this run converges it   the directory pass runs first, and it both
 *                           creates and fchmods — so a pending row's mode
 *                           is the mode the write meets, whether the path
 *                           is there now or not
 *   this run creates it     an absent component is ensure_parents' to
 *                           materialize, by create_ancestor's rule: a
 *                           tracked row's mode from any profile, in scope
 *                           or not, otherwise DEPLOY_DIR_MODE_DEFAULT
 *   this run leaves it      access(2) decides, and unlike a mode test it
 *                           knows about ownership, groups, ACLs and root.
 *                           Path resolution has already checked the search
 *                           bit of every component above it, so that one
 *                           call settles the rest of the walk
 *
 * @param out_mode Receives the predicted mode on LANDING_MODE_BLOCKED
 */
static landing_verdict_t judge_component(
    const workspace_t *ws, const deploy_plan_t *plan,
    const char *component, bool is_parent, mode_t *out_mode
) {
    struct stat st;

    /* stat, not lstat: a symlinked configuration directory is a directory
     * for the purpose of writing beneath it. */
    if (stat(component, &st) != 0) {
        if (errno != ENOENT && errno != ENOTDIR) {
            return LANDING_ABSTAIN;      /* let the write surface the real errno */
        }

        /* Absent — ENOTDIR meaning a component above it is a non-directory,
         * which the walk meets on its own way up. */
        const state_directory_entry_t *dir = workspace_lookup_directory(ws, component);
        *out_mode = dir ? directory_row_mode(dir) : DEPLOY_DIR_MODE_DEFAULT;

        return mode_permits(*out_mode, is_parent) ? LANDING_CLIMB : LANDING_MODE_BLOCKED;
    }

    const state_directory_entry_t *pending = pending_directory(plan, component);

    if (!S_ISDIR(st.st_mode)) {
        if (!pending) {
            return LANDING_NOT_A_DIRECTORY;
        }

        /* The directory pass replaces the squatter with a directory of the
         * row's own mode. Landing that replacement is the row's question,
         * asked by its own walk — so this one stops rather than report the
         * same ancestor twice. */
        *out_mode = directory_row_mode(pending);
        return mode_permits(*out_mode, is_parent) ? LANDING_SETTLED : LANDING_MODE_BLOCKED;
    }

    if (pending) {
        *out_mode = directory_row_mode(pending);
        return mode_permits(*out_mode, is_parent) ? LANDING_CLIMB : LANDING_MODE_BLOCKED;
    }

    return access(component, is_parent ? (W_OK | X_OK) : X_OK) == 0
             ? LANDING_SETTLED
             : LANDING_UNWRITABLE;
}

/**
 * Record a blocked finding — a planned path that neither --force nor
 * privileges can land, so the entry carries its own reason. Takes
 * ownership of `entry`; NULL means the formatting itself failed.
 */
static error_t *push_blocked(preflight_result_t *result, char *entry) {
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to format blocked entry");
    }

    error_t *err = string_array_push_owned(result->blocked, entry);
    if (err) {
        free(entry);
        return err;
    }

    result->has_errors = true;
    return NULL;
}

/**
 * Can this planned path's write land?
 *
 * One question per planned row, present or absent alike. The split this
 * replaces asked two, and answered the existing case against the wrong
 * object: nothing deploy writes needs permission on the path itself.
 * fs_write_file_raw renames a temp file over it, fs_create_symlink unlinks
 * and re-links it, deploy_directory mkdirs it — every one of those is an
 * operation on the *parent*. A read-only file, or a symlink pointing into
 * a read-only store, is no obstacle at all.
 *
 * So the walk goes up, not down. The parent must accept a new entry, every
 * component above it must be traversable, and each is judged against the
 * state this run will have left it in rather than the state it is in now
 * (judge_component). It stops at the first component this run does not
 * touch, because access(2) there has already answered for everything
 * above.
 *
 * That leaves exactly one shape outside its reach: a tracked directory
 * that loses its search bit somewhere *above* an untouched existing
 * directory, where the walk has already stopped. A directory recorded
 * without owner-execute could not have been walked to add anything beneath
 * it, so no sequence of dotta commands produces that state.
 *
 * @param ws Workspace, for the tracked-ancestor lookup (must not be NULL)
 * @param plan Deployment plan, for the pending-directory test (must not be NULL)
 * @param path Planned path (must not be NULL)
 * @param result Preflight result to record a finding in (must not be NULL)
 * @return Error or NULL on success (a finding is not an error)
 */
static error_t *check_landing(
    const workspace_t *ws, const deploy_plan_t *plan,
    const char *path, preflight_result_t *result
) {
    char *scratch = strdup(path);
    if (!scratch) {
        return ERROR(ERR_MEMORY, "Failed to copy path for landing check");
    }

    error_t *err = NULL;
    size_t i = strlen(scratch);
    bool is_parent = true;

    for (;;) {
        /* Step left to the slash ending the next component up */
        do {
            if (i == 0) {
                goto cleanup;                 /* not absolute — cannot happen */
            }
        } while (scratch[--i] != '/');

        size_t len = ancestor_len(i);
        char saved = scratch[len];
        scratch[len] = '\0';                  /* the component, on its own */

        mode_t mode = 0;
        char *why = NULL;
        landing_verdict_t verdict =
            judge_component(ws, plan, scratch, is_parent, &mode);

        switch (verdict) {
            case LANDING_NOT_A_DIRECTORY:
                why = str_format("%s (%s is not a directory)", path, scratch);
                err = push_blocked(result, why);
                break;

            case LANDING_MODE_BLOCKED:
                why = str_format(
                    "%s (tracked directory %s is mode %04o)", path, scratch, mode
                );
                err = push_blocked(result, why);
                break;

            case LANDING_UNWRITABLE:
                err = string_array_push(result->permission_errors, path);
                if (!err) {
                    result->has_errors = true;
                }
                break;

            case LANDING_CLIMB:
            case LANDING_SETTLED:
            case LANDING_ABSTAIN:
                break;
        }

        scratch[len] = saved;

        if (err || verdict != LANDING_CLIMB) {
            goto cleanup;
        }
        is_parent = false;
    }

cleanup:
    free(scratch);
    return err;
}

/**
 * Run pre-flight checks over the plan
 *
 * Workspace = analysis layer, preflight = decision layer, execute =
 * execution layer. Divergence verdicts are O(1) index probes; the
 * landing and writability checks are filesystem-level.
 */
error_t *deploy_preflight(
    const workspace_t *ws,
    const deploy_plan_t *plan,
    const deploy_options_t *opts,
    preflight_result_t **out
) {
    CHECK_NULL(ws);
    CHECK_NULL(plan);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    preflight_result_t *result = calloc(1, sizeof(preflight_result_t));
    if (!result) {
        return ERROR(
            ERR_MEMORY, "Failed to allocate preflight result"
        );
    }

    result->conflicts = string_array_new(0);
    result->blocked = string_array_new(0);
    result->permission_errors = string_array_new(0);

    if (!result->conflicts || !result->blocked || !result->permission_errors) {
        preflight_result_free(result);
        return ERROR(
            ERR_MEMORY, "Failed to allocate result arrays"
        );
    }

    error_t *err = NULL;

    state_files_t files = state_files_view(&plan->files.pending);
    for (size_t i = 0; i < files.count; i++) {
        const char *path = files.entries[i]->filesystem_path;
        const workspace_item_t *item = workspace_get_item(ws, path);

        if (item && !opts->force) {
            /* File has divergence - check if it's a blocking conflict.
             * Only block on content conflicts (CONTENT, TYPE).
             * Metadata divergence (mode, ownership) and encryption policy are informational.
             *
             * DIVERGENCE_STALE exception: When content diverges because the expected
             * state changed (stale repair), and the file on disk matches what dotta
             * deployed (old blob), it's safe to overwrite. DIVERGENCE_STALE is only
             * set after this verification, so we can trust it here.
             */
            if ((item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE)) &&
                !(item->divergence & DIVERGENCE_STALE)) {
                /* Content or type conflict - block deployment */
                err = string_array_push(result->conflicts, path);
                if (err) goto cleanup;
                result->has_errors = true;
            }
            /* Mode/ownership/encryption divergence is not blocking */
        }

        /* Every file row lands through its parent, whichever arm writes it
         * and whether or not something is already at the path — so one
         * question covers both, and it is never about the path itself. */
        err = check_landing(ws, plan, path, result);
        if (err) goto cleanup;
    }

    state_directories_t dirs = state_directories_view(&plan->directories.pending);
    for (size_t i = 0; i < dirs.count; i++) {
        const char *path = dirs.entries[i]->filesystem_path;
        const workspace_item_t *item = workspace_get_item(ws, path);

        /* A planned directory squatted by a non-directory (workspace probes
         * with lstat, so a symlink to a directory counts) blocks unless
         * --force lets deploy_directory replace it. */
        if (item && !opts->force && (item->divergence & DIVERGENCE_TYPE)) {
            err = string_array_push(result->conflicts, path);
            if (err) goto cleanup;
            result->has_errors = true;
        }

        /* A directory already there is fixed in place: fchmod and fchown
         * ask for ownership, not for a writable parent. Only a create or a
         * replace lands a new entry — and lstat decides which, exactly as
         * deploy_directory does, so a symlink to a directory counts as the
         * squatter it is rather than as the tracked directory. */
        struct stat st;
        if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
            err = check_landing(ws, plan, path, result);
            if (err) goto cleanup;
        }
    }

    *out = result;
    return NULL;

cleanup:
    preflight_result_free(result);
    return error_wrap(err, "Failed to record preflight finding");
}

/* ══════════════════════════════════════════════════════════════════
 * Execute
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Resolve deployment ownership for a path
 *
 * Unified ownership resolution logic for both files and directories.
 * Handles home/ vs root/custom/ prefix logic and sudo detection.
 *
 * Resolution rules:
 * - Files deploying to user's home under sudo: Use actual user's UID/GID
 * - root/ or custom/ prefix with owner/group metadata: Resolve names to UID/GID
 * - All other cases: Return -1 (no ownership change)
 *
 * Home detection for sudo de-escalation:
 * - Primary: storage_path starts with "home/" (always deploys to $HOME)
 * - Fallback: filesystem_path is under actual user's home (catches custom/
 *   prefix files reclassified by --target that still land under $HOME)
 *
 * Strict ownership mode (strict_ownership=true):
 * - ERR_NOT_FOUND (user/group missing): Fatal error, abort deployment
 * - ERR_PERMISSION (not root): Warning only (can't chown anyway)
 *
 * Pure decision — no filesystem mutation — so executors call it ahead of
 * their dry-run gate; in dry-run a strict-mode failure prints "Would fail"
 * instead of aborting.
 *
 * @param storage_path Path in profile (e.g., "home/.bashrc", "root/etc/hosts")
 * @param filesystem_path Resolved deployment path for home detection
 * @param owner Owner username from metadata (can be NULL)
 * @param group Group name from metadata (can be NULL)
 * @param out_uid Resolved UID or -1 for no change (must not be NULL)
 * @param out_gid Resolved GID or -1 for no change (must not be NULL)
 * @param strict_ownership Fail deployment if ownership cannot be resolved
 * @param dry_run Dry-run mode (show "would fail" instead of failing)
 * @param verbose Enable verbose warning messages
 * @return Error on fatal failures, NULL on success (non-fatal errors logged and suppressed)
 */
static error_t *resolve_deployment_ownership(
    const char *storage_path,
    const char *filesystem_path,
    const char *owner, const char *group,
    uid_t *out_uid, gid_t *out_gid,
    bool strict_ownership,
    bool dry_run, bool verbose
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out_uid);
    CHECK_NULL(out_gid);

    /* Initialize to "no change" */
    *out_uid = (uid_t) -1;
    *out_gid = (gid_t) -1;

    const mount_spec_t *spec = mount_spec_for_path(storage_path);
    bool requires_root_privileges = spec && spec->tracks_ownership;

    /* Case 1: file lands in the invoking user's HOME when running as
     * root.
     *
     * fs_get_home is the single source of truth for "the user's home"
     * (sudo-aware via SUDO_UID's pw_dir); privilege_path_is_user_home
     * trusts it. No label dispatch needed:
     *   home/X    → resolves under HOME → de-escalate
     *   root/X    → /X, never under HOME → fall through
     *   custom/X with --target $HOME/jail → under HOME → de-escalate
     *   custom/X with --target /jail      → outside HOME → fall through
     *
     * The fs path tells us directly. The kind dispatch this replaces
     * was a workaround for HOME-truth divergence between fs_get_home
     * and the inlined SUDO_UID lookup; once both share fs_get_home,
     * the dispatch collapses. */
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
             *   - Always warning (user already warned about privileges)
             */
            bool is_resolution_failure = (err->code == ERR_NOT_FOUND);
            bool should_fail = is_resolution_failure && strict_ownership && !dry_run;

            if (should_fail) {
                /* Fatal: Return error to abort deployment */
                return error_wrap(
                    err, "Ownership resolution failed for '%s' (strict_mode enabled)\n"
                    "Hint: Create the user/group on this system, or disable strict_mode",
                    storage_path
                );
            }

            /* Non-fatal: Log appropriate message and continue */
            if (dry_run && is_resolution_failure && strict_ownership) {
                /* Dry-run with strict mode: Show what would fail */
                fprintf(
                    stderr, "Would fail: %s - %s (strict_mode enabled)\n",
                    storage_path, error_message(err)
                );
            } else if (verbose || err->code != ERR_PERMISSION) {
                /* Standard warning (suppress ERR_PERMISSION unless verbose) */
                fprintf(
                    stderr, "Warning: Could not resolve ownership for %s: %s\n",
                    storage_path, error_message(err)
                );
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
 * A tracked directory row's target metadata: mode (with the missing-mode
 * fallback and its warning) and resolved ownership. Pure decision — no
 * filesystem mutation, so it runs ahead of the dry-run gate.
 *
 * @param dir State row (must not be NULL; borrowed, read-only)
 * @param opts Deployment options (must not be NULL)
 * @param out_mode Resolved permission mode (must not be NULL)
 * @param out_uid Resolved UID or -1 for no change (must not be NULL)
 * @param out_gid Resolved GID or -1 for no change (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *resolve_directory_metadata(
    const state_directory_entry_t *dir,
    const deploy_options_t *opts,
    mode_t *out_mode,
    uid_t *out_uid, gid_t *out_gid
) {
    /* Validate directory mode from state (before skip/dry-run checks)
     *
     * In VWD operations, state should always have mode populated by the
     * manifest layer at write time. If mode==0, this indicates state
     * corruption or manifest sync failure. directory_row_mode supplies the
     * safe default; the warning is this path's alone, so preflight can
     * predict the same value without printing it twice.
     */
    mode_t mode = directory_row_mode(dir);
    if (dir->mode == 0) {
        /* Defensive fallback - indicates unexpected state corruption */
        fprintf(
            stderr,
            "Warning: Missing mode in state for directory '%s', using default %04o\n"
            "         This may indicate state database corruption. Consider running:\n"
            "         dotta profile disable %s && dotta profile enable %s\n",
            dir->filesystem_path, mode,
            dir->profile ? dir->profile : "<profile>",
            dir->profile ? dir->profile : "<profile>"
        );
    }
    *out_mode = mode;

    error_t *err = resolve_deployment_ownership(
        dir->storage_path,
        dir->filesystem_path,
        dir->owner, dir->group,
        out_uid, out_gid,
        opts->strict_ownership,
        opts->dry_run, opts->verbose
    );
    if (err) {
        return error_wrap(
            err, "Failed to resolve ownership for directory: %s",
            dir->storage_path
        );
    }

    return NULL;
}

/**
 * Materialize one absent ancestor whose own parent exists: a tracked
 * directory (any profile, in scope or not) with its tracked metadata,
 * anything else 0755 owned like the planned path beneath it. The 0755 is
 * exact (fchmod), not umask-masked — dotta reproduces modes, it does not
 * negotiate them.
 *
 * @param ws Workspace, for the tracked-directory lookup (must not be NULL)
 * @param path Absent ancestor to create (must not be NULL)
 * @param uid UID of the planned path beneath it (-1 for no change)
 * @param gid GID of the planned path beneath it (-1 for no change)
 * @param opts Deployment options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *create_ancestor(
    const workspace_t *ws,
    const char *path,
    uid_t uid, gid_t gid,
    const deploy_options_t *opts
) {
    const state_directory_entry_t *dir = workspace_lookup_directory(ws, path);

    if (dir) {
        mode_t mode;
        uid_t dir_uid;
        gid_t dir_gid;

        RETURN_IF_ERROR(
            resolve_directory_metadata(dir, opts, &mode, &dir_uid, &dir_gid)
        );

        return fs_create_dir_with_ownership(
            path, mode, dir_uid, dir_gid
        );
    }

    return fs_create_dir_with_ownership(path, DEPLOY_DIR_MODE_DEFAULT, uid, gid);
}

/**
 * Create the missing parents of a planned path, top-down from its nearest
 * existing ancestor.
 *
 * Mutation, not decision — called behind the dry-run gate. Whether the
 * path can land was preflight's question, and the directory pass has
 * already replaced any planned squatter above it; a non-directory
 * ancestor met here (a prompt sat in between) is a named error rather
 * than a mkdir errno.
 *
 * @param ws Workspace, for tracked-ancestor metadata (must not be NULL)
 * @param path Planned path whose parents must exist (must not be NULL)
 * @param uid Resolved UID of the planned path (-1 for no change)
 * @param gid Resolved GID of the planned path (-1 for no change)
 * @param opts Deployment options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *ensure_parents(
    const workspace_t *ws,
    const char *path,
    uid_t uid, gid_t gid,
    const deploy_options_t *opts
) {
    char *scratch = strdup(path);
    if (!scratch) {
        return ERROR(ERR_MEMORY, "Failed to copy path for parent creation");
    }

    error_t *err = NULL;
    struct stat st;
    size_t ancestor_slash;
    if (!nearest_ancestor(scratch, &ancestor_slash, &st)) {
        goto cleanup;                            /* let the write surface the errno */
    }
    if (!S_ISDIR(st.st_mode)) {
        scratch[ancestor_len(ancestor_slash)] = '\0';
        err = ERROR(
            ERR_FS, "Cannot create parents of '%s': '%s' is not a directory",
            path, scratch
        );
        goto cleanup;
    }

    /* Every slash past the ancestor ends one missing parent; the final
     * component is the planned path itself. */
    char *tail = scratch + ancestor_slash + 1;
    for (char *slash = strchr(tail, '/'); slash; slash = strchr(slash + 1, '/')) {
        *slash = '\0';
        err = create_ancestor(ws, scratch, uid, gid, opts);
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
 * Deploy a single state row to its target filesystem location.
 *
 * Decide, then gate, then mutate: the blob sanity check and ownership
 * resolution are decisions and run ahead of the dry-run gate (so a
 * dry-run previews strict-mode ownership failures too); every mutation
 * sits behind it, missing parents first.
 *
 * VWD Model:
 * - file->mode: Permission mode from state (0 = use safe fallback by type)
 * - file->owner/group: Ownership strings for root/ prefix files (NULL for home/)
 * - file->encrypted: handled transparently by the content cache
 *
 * @param repo Repository (must not be NULL)
 * @param cache Content cache for batch operations (must not be NULL)
 * @param ws Workspace, for tracked-ancestor metadata (must not be NULL)
 * @param file State row to deploy (must not be NULL; borrowed from the
 *             workspace's arena snapshot, read-only for deploy).
 * @param opts Deployment options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *deploy_file(
    git_repository *repo,
    content_cache_t *cache,
    const workspace_t *ws,
    const state_file_entry_t *file,
    const deploy_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(cache);
    CHECK_NULL(ws);
    CHECK_NULL(file);
    CHECK_NULL(opts);

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    const buffer_t *content_buffer = NULL;  /* Borrowed from cache (const) */
    char *target_str = NULL;

    /* Validate blob_oid from VWD cache. A zero OID means the row was never
     * populated from state — should be impossible for entries reaching the
     * deploy path, but we keep the defensive check. */
    if (git_oid_is_zero(&file->blob_oid)) {
        return ERROR(
            ERR_INTERNAL, "Missing blob_oid for '%s' (state corruption?)",
            file->filesystem_path
        );
    }

    /* Resolve ownership for the file based on prefix - RESOLVED BEFORE WRITING
     *
     * SECURITY: Ownership resolution happens BEFORE file creation to enable
     * atomic ownership via fchown() on the file descriptor. This eliminates
     * the security window where files exist with incorrect ownership.
     *
     * VWD Authority: uses file->owner and file->group from the state cache.
     * - root/ prefix files: owner/group are username/groupname strings from state
     * - home/ prefix files: owner/group are NULL (current user ownership)
     *
     * Unified helper handles:
     * - home/ files when running as root: Use actual user's UID/GID (sudo handling)
     * - root/ files with owner/group: Resolve username/groupname -> UID/GID
     * - All other cases: Return -1 (preserve current user/root ownership)
     */
    uid_t target_uid, target_gid;
    err = resolve_deployment_ownership(
        file->storage_path,
        file->filesystem_path,
        file->owner, file->group,
        &target_uid, &target_gid,
        opts->strict_ownership,
        opts->dry_run, opts->verbose
    );
    if (err) {
        return error_wrap(
            err, "Failed to resolve ownership for '%s'", file->filesystem_path
        );
    }

    /* The one mutation gate */
    if (opts->dry_run) {
        /* Dry-run mode - just print */
        if (opts->verbose) {
            printf("  Would deploy: %s\n", file->filesystem_path);
        }
        return NULL;
    }

    /* Land the path: parents first, whichever arm writes it */
    err = ensure_parents(ws, file->filesystem_path, target_uid, target_gid, opts);
    if (err) {
        return err;
    }

    /* Handle symlinks - these are never encrypted, so handle separately */
    if (file->type == STATE_FILE_SYMLINK) {
        /* For symlinks, we load the blob directly since the content layer
         * is designed for regular files with potential encryption. */
        size_t target_len = 0;
        err = gitops_read_blob_content(
            repo, &file->blob_oid, (void **) &target_str, &target_len
        );
        if (err) goto cleanup;

        /* Clear path for symlink deployment (handles files, symlinks, and directories)
         *
         * Uses fs_clear_path() instead of fs_remove_file() because:
         * 1. fs_remove_file() fails with EISDIR if target is a directory
         * 2. fs_clear_path() uses lstat() so broken symlinks are properly detected
         * 3. Idempotent - succeeds if path doesn't exist
         *
         * Safety: Only reached with --force (preflight blocks DIVERGENCE_TYPE)
         */
        err = fs_clear_path(file->filesystem_path);
        if (err) {
            err = error_wrap(
                err, "Failed to prepare path for symlink deployment"
            );
            goto cleanup;
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
         * OWNERSHIP matters for auditing and consistency. lchown() changes
         * the link itself, not its target. */
        if (target_uid != (uid_t) -1 || target_gid != (gid_t) -1) {
            if (lchown(file->filesystem_path, target_uid, target_gid) != 0) {
                err = ERROR(
                    ERR_FS, "Failed to set ownership on symlink '%s': %s",
                    file->filesystem_path, strerror(errno)
                );
                goto cleanup;
            }
        }

        if (opts->verbose) {
            printf("Deployed symlink: %s\n", file->filesystem_path);
        }

        /* Success for symlink - goto cleanup will handle freeing */
        err = NULL;
        goto cleanup;
    }

    /* Regular files: content from the cache with transparent decryption */
    err = content_cache_get_from_blob_oid(
        cache,
        &file->blob_oid,
        file->storage_path,
        file->profile ? file->profile : "unknown",
        &content_buffer
    );

    if (err) {
        err = error_wrap(err, "Failed to get content for '%s'", file->storage_path);
        goto cleanup;
    }

    /* Get content pointer and size from buffer */
    const unsigned char *content = (const unsigned char *) content_buffer->data;
    size_t size = content_buffer->size;

    /* Determine permissions from state row
     *
     * In VWD operations, the state row should always have mode populated
     * by the manifest layer at write time. If mode==0, this indicates state
     * corruption or manifest sync failure. Fall back to a safe default keyed
     * on file type. */
    mode_t file_mode = file->mode;
    if (file_mode == 0) {
        /* Defensive fallback - indicates unexpected state corruption */
        file_mode = (file->type == STATE_FILE_EXECUTABLE) ? 0755 : 0644;

        fprintf(
            stderr,
            "Warning: Missing mode in state for '%s', using default %04o\n"
            "         This may indicate state database corruption. Consider running:\n"
            "         dotta profile disable %s && dotta profile enable %s\n",
            file->filesystem_path, file_mode,
            file->profile ? file->profile : "<profile>",
            file->profile ? file->profile : "<profile>"
        );
    }

    /* Clear directory at target path if present
     *
     * fs_write_file_raw() lands the content by rename() of a temp file over
     * the target. rename() replaces a regular file or a symlink (the link
     * itself, not what it points to) but not a directory (EISDIR).
     * Directories must be cleared explicitly before writing.
     *
     * Uses lstat() to avoid following symlinks:
     * - Symlink to directory: lstat returns S_IFLNK -> rename replaces the link
     * - Actual directory: lstat returns S_IFDIR -> must clear before writing
     *
     * Safety: Only reached with --force (preflight blocks DIVERGENCE_TYPE)
     */
    struct stat target_stat;
    if (lstat(file->filesystem_path, &target_stat) == 0 && S_ISDIR(target_stat.st_mode)) {
        err = fs_remove_dir(file->filesystem_path, true);
        if (err) {
            err = error_wrap(
                err, "Failed to clear directory at '%s'", file->filesystem_path
            );
            goto cleanup;
        }
    }

    /* Write directly from git blob to filesystem with atomic ownership and permissions
     * SECURITY: fs_write_file_raw atomically sets BOTH ownership and permissions via
     * fchown() and fchmod() on the file descriptor, eliminating any security window.
     * This is the ONLY place where ownership is applied - metadata layer only resolves. */
    err = fs_write_file_raw(
        file->filesystem_path, content, size, file_mode,
        target_uid, target_gid
    );

    if (err) {
        err = error_wrap(
            err, "Failed to deploy file '%s'",
            file->filesystem_path
        );
        goto cleanup;
    }

    /* Verbose output */
    if (opts->verbose) {
        bool has_ownership = (file->owner || file->group) && target_uid != (uid_t) -1;

        if (has_ownership) {
            printf(
                "Deployed: %s (mode: %04o, owner: %s:%s)\n",
                file->filesystem_path, file_mode,
                file->owner ? file->owner : "?", file->group ? file->group : "?"
            );
        } else {
            printf(
                "Deployed: %s (mode: %04o)\n", file->filesystem_path, file_mode
            );
        }
    }

    /* Success */
    err = NULL;

cleanup:
    free(target_str);
    return err;
}

/**
 * How deploy_directory will materialize a planned row — decided from a
 * fresh lstat, never from the load-time observation.
 */
typedef enum {
    DIR_ACTION_CREATE,     /* absent */
    DIR_ACTION_FIX,        /* a directory is there — ensure mode/ownership */
    DIR_ACTION_REPLACE     /* a non-directory squats the path — clear it (--force) */
} directory_action_t;

/**
 * Verbose trace for deploy_directory, shared by the dry-run preview and
 * the real run — the verb is the only difference.
 */
static void print_directory_trace(
    const char *verb,
    const state_directory_entry_t *dir,
    mode_t mode,
    bool has_ownership,
    const char *detail
) {
    if (has_ownership) {
        printf(
            "  %s: %s (mode: %04o, owner: %s:%s)%s\n",
            verb, dir->filesystem_path, mode,
            dir->owner ? dir->owner : "?", dir->group ? dir->group : "?", detail
        );
    } else {
        printf(
            "  %s: %s (mode: %04o)%s\n",
            verb, dir->filesystem_path, mode, detail
        );
    }
}

/**
 * Materialize one planned tracked directory to its expected state.
 *
 * The plan settled *that* the row is acted on; this decides *how* from a
 * fresh lstat — reality between plan and execution (a prompt sat in
 * between) is not the plan's to know. Same decide → gate → mutate order
 * as deploy_file: the type check, the divergence detail and metadata
 * resolution are decisions; the dry-run gate follows; then the clear
 * (REPLACE) or the missing parents (CREATE), and the create/fix, which
 * is idempotent — a planned directory whose reality healed meanwhile is
 * simply confirmed.
 *
 * VWD Model:
 * - dir->filesystem_path: already resolved against the mount target
 * - dir->storage_path: portable path, drives ownership resolution
 * - dir->mode / owner / group: target metadata (mode 0 = fallback 0755)
 *
 * @param ws Workspace, for tracked-ancestor metadata (must not be NULL)
 * @param dir State row (must not be NULL; borrowed, read-only)
 * @param opts Deployment options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *deploy_directory(
    const workspace_t *ws,
    const state_directory_entry_t *dir,
    const deploy_options_t *opts
) {
    CHECK_NULL(ws);
    CHECK_NULL(dir);
    CHECK_NULL(opts);

    const char *path = dir->filesystem_path;

    /* Decide how, from disk truth now. lstat: a symlink to a directory is
     * not the directory being tracked. */
    directory_action_t action;
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            action = DIR_ACTION_FIX;
        } else if (opts->force) {
            action = DIR_ACTION_REPLACE;
        } else {
            return ERROR(
                ERR_CONFLICT, "'%s' is not a directory (use --force to replace it)",
                path
            );
        }
    } else if (errno == ENOENT || errno == ENOTDIR) {
        /* Absent — or beneath a non-directory, which preflight blocked
         * when unplanned and the directory pass replaces when planned
         * (prefix order); one still there is ensure_parents' named error. */
        action = DIR_ACTION_CREATE;
    } else {
        return ERROR(ERR_FS, "Failed to stat '%s': %s", path, strerror(errno));
    }

    /* Divergence detail for the trace — from the fresh stat, FIX only */
    char detail[32] = "";
    if (action == DIR_ACTION_FIX && opts->verbose) {
        bool mode_differs = false;
        bool ownership_differs = false;

        error_t *err = check_item_metadata_divergence(
            dir->mode, dir->owner, dir->group, &st, &mode_differs, &ownership_differs
        );
        if (err) return err;

        if (mode_differs || ownership_differs) {
            snprintf(
                detail, sizeof(detail), " [%s%s%s]", mode_differs ? "mode" : "",
                (mode_differs && ownership_differs) ? ", " : "",
                ownership_differs ? "ownership" : ""
            );
        }
    }

    /* Metadata is resolved BEFORE creation so fs_create_dir_with_ownership
     * applies it atomically via fchown()/fchmod() on the descriptor. */
    mode_t mode;
    uid_t target_uid;
    gid_t target_gid;
    error_t *err = resolve_directory_metadata(
        dir, opts, &mode, &target_uid, &target_gid
    );
    if (err) {
        return err;
    }

    bool has_ownership = (dir->owner || dir->group) && target_uid != (uid_t) -1;
    static const char *const verbs[][2] = {   /* [action][0] preview, [1] outcome */
        [DIR_ACTION_CREATE] =  { "Would create",  "Created"  },
        [DIR_ACTION_FIX] =     { "Would fix",     "Fixed"    },
        [DIR_ACTION_REPLACE] = { "Would replace", "Replaced" },
    };
    const char *verb = verbs[action][opts->dry_run ? 0 : 1];

    /* The one mutation gate */
    if (opts->dry_run) {
        if (opts->verbose) {
            print_directory_trace(verb, dir, mode, has_ownership, detail);
        }
        return NULL;
    }

    if (action == DIR_ACTION_REPLACE) {
        /* fs_clear_path: lstat-based, removes a file, symlink or directory
         * uniformly, so whatever squats the path goes before the mkdir */
        err = fs_clear_path(path);
        if (err) {
            return error_wrap(err, "Failed to clear type conflict at '%s'", path);
        }
    } else if (action == DIR_ACTION_CREATE) {
        err = ensure_parents(ws, path, target_uid, target_gid, opts);
        if (err) {
            return err;
        }
    }

    /* Create-or-fix with atomic ownership and permissions (fchown/fchmod on
     * the directory fd — no window with wrong metadata). Idempotent. */
    err = fs_create_dir_with_ownership(path, mode, target_uid, target_gid);
    if (err) {
        return error_wrap(err, "Failed to create tracked directory: %s", path);
    }

    if (opts->verbose) {
        print_directory_trace(verb, dir, mode, has_ownership, detail);
    }

    return NULL;
}

/**
 * Execute the plan
 */
error_t *deploy_execute(
    git_repository *repo,
    const workspace_t *ws,
    const deploy_plan_t *plan,
    const deploy_options_t *opts,
    content_cache_t *cache,
    deploy_result_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ws);
    CHECK_NULL(plan);
    CHECK_NULL(opts);
    CHECK_NULL(cache);
    CHECK_NULL(out);

    error_t *err = NULL;

    /* calloc zeroes the ptr_array_t buckets — that IS their empty state */
    deploy_result_t *result = calloc(1, sizeof(deploy_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate deploy result");
    }

    /* Directories first: parents before the files beneath them, and under
     * --force a squatting symlink is gone before anything is written
     * through it. Prefix order within the bucket = parents before children. */
    state_directories_t dirs = state_directories_view(&plan->directories.pending);
    if (opts->verbose && dirs.count > 0) {
        printf(
            "Processing %zu tracked director%s...\n",
            dirs.count, dirs.count == 1 ? "y" : "ies"
        );
    }

    for (size_t i = 0; i < dirs.count; i++) {
        const state_directory_entry_t *dir = dirs.entries[i];

        /* Deploy tracked directories (workspace owns the active slice) */
        err = deploy_directory(ws, dir, opts);
        if (err) {
            /* Fail-stop with the partial result; the error names the path */
            *out = result;
            return error_wrap(
                err, "Failed to converge directory '%s'",
                dir->filesystem_path
            );
        }

        err = ptr_array_push(&result->converged, dir);
        if (err) {
            deploy_result_free(result);
            return error_wrap(err, "Failed to record converged directory");
        }
    }

    state_files_t files = state_files_view(&plan->files.pending);
    if (opts->verbose && files.count > 0) {
        printf(
            "Processing %zu file%s for deployment...\n",
            files.count, files.count == 1 ? "" : "s"
        );
    }

    /* Every pending row is work by construction (the planner routed it
     * through deploy_needs_work), so there is no clean-skip here. Clean
     * in-scope rows with deployed_at == 0 are apply's adoption step, which
     * stamps the anchor without deploy_file. */
    for (size_t i = 0; i < files.count; i++) {
        const state_file_entry_t *file = files.entries[i];

        /* --skip-existing: the user explicitly chose not to overwrite */
        if (opts->skip_existing && fs_exists(file->filesystem_path) && !opts->force) {
            err = ptr_array_push(&result->skipped_existing, file);
            if (err) {
                deploy_result_free(result);
                return error_wrap(err, "Failed to record skipped file");
            }
            continue;
        }

        /* Deploy the file */
        err = deploy_file(repo, cache, ws, file, opts);
        if (err) {
            /* Fail-stop with the partial result.
             * ptr_array_push failure is non-fatal here (already error-pathing). */
            ptr_array_push(&result->failed, file);
            result->error_message = strdup(error_message(err));
            *out = result;
            return error_wrap(
                err, "Deployment failed at '%s'",
                file->filesystem_path
            );
        }

        /* Record success */
        err = ptr_array_push(&result->deployed, file);
        if (err) {
            deploy_result_free(result);
            return error_wrap(err, "Failed to record deployed file");
        }
    }

    /* Success - return results */
    *out = result;
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Teardown
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Free preflight result
 */
void preflight_result_free(preflight_result_t *result) {
    if (!result) {
        return;
    }

    string_array_free(result->conflicts);
    string_array_free(result->blocked);
    string_array_free(result->permission_errors);
    free(result);
}

/**
 * Free deployment result
 *
 * Each ptr_array_t holds borrowed row pointers (workspace-arena lifetime),
 * so deinit only releases the bucket buffers — the rows themselves outlive us.
 */
void deploy_result_free(deploy_result_t *result) {
    if (!result) {
        return;
    }

    ptr_array_deinit(&result->deployed);
    ptr_array_deinit(&result->converged);
    ptr_array_deinit(&result->skipped_existing);
    ptr_array_deinit(&result->failed);
    free(result->error_message);
    free(result);
}
