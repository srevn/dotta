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
 * Plan
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Deploy's work predicate over a workspace verdict
 *
 * State (existence) sets the baseline, divergence (quality) refines it.
 * Kind-agnostic: directories are tagged only MODE / OWNERSHIP / TYPE /
 * UNVERIFIED, so the DEPLOYED arm's mask covers every directory verdict.
 * The planner iterates the active slices, so orphan-state items never
 * reach this; those arms exist for -Wswitch completeness.
 */
static bool deploy_needs_work(const workspace_item_t *item) {
    if (item == NULL) {
        return false;                        /* not in the divergence index: clean */
    }

    switch (item->state) {
        case WORKSPACE_STATE_UNDEPLOYED:     /* in Git, never on disk */
        case WORKSPACE_STATE_DELETED:        /* was on disk, removed since */
            return true;

        case WORKSPACE_STATE_DEPLOYED:
            /* STALE is informational — the VWD row was re-pointed at the
             * new blob in memory; only a real property mismatch is work. */
            return (item->divergence & ~DIVERGENCE_STALE) != DIVERGENCE_NONE;

        case WORKSPACE_STATE_ORPHANED:       /* cleanup's, never deploy's */
        case WORKSPACE_STATE_UNTRACKED:      /* not managed; the user must add it */
        case WORKSPACE_STATE_RELEASED:       /* Git dropped it; cleanup retires the row */
            return false;
    }

    return false;
}

/**
 * Route one in-scope row into its partition bucket, or drop it
 * (clean + excluded is neither work nor adoptable).
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
    const workspace_t *ws,
    const scope_t *scope,
    deploy_plan_t **out
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
            &plan->files, row,
            deploy_needs_work(workspace_get_item(ws, row->filesystem_path)),
            scope_is_excluded(scope, row->storage_path, PATH_KIND_FILE)
        );
        if (err) goto fail;
    }

    state_directories_t dirs = workspace_directories(ws);
    for (size_t i = 0; i < dirs.count; i++) {
        const state_directory_entry_t *row = dirs.entries[i];

        if (!scope_accepts_profile(scope, row->profile) ||
            !scope_accepts_path(scope, row->storage_path, PATH_KIND_DIRECTORY)) {
            continue;
        }

        err = partition_push(
            &plan->directories, row,
            deploy_needs_work(workspace_get_item(ws, row->filesystem_path)),
            scope_is_excluded(scope, row->storage_path, PATH_KIND_DIRECTORY)
        );
        if (err) goto fail;
    }

    *out = plan;
    return NULL;

fail:
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
 * stat the prefix of `scratch` ending at the slash at index k — "/"
 * itself when k == 0 — NUL-terminating it in place for the call and
 * restoring the byte afterwards. errno is stat's.
 */
static int stat_prefix(char *scratch, size_t k, struct stat *st) {
    size_t cut = k ? k : 1;
    char saved = scratch[cut];
    scratch[cut] = '\0';
    int rc = stat(scratch, st);
    int saved_errno = errno;
    scratch[cut] = saved;
    errno = saved_errno;
    return rc;
}

/**
 * Nearest existing ancestor of an absolute path (parent, grandparent, …)
 *
 * Follows symlinks — a symlinked configuration directory is a directory
 * for the purpose of writing beneath it. `scratch` is a writable copy of
 * the path, intact on return; *k receives the index of the slash that
 * ends the ancestor (0 for "/"), *st its stat. False only when stat
 * fails for a reason other than absence — the write will surface the
 * real errno.
 */
static bool nearest_ancestor(char *scratch, size_t *k, struct stat *st) {
    size_t i = strlen(scratch);
    for (;;) {
        do {
            if (i == 0) return false;           /* not absolute — cannot happen */
        } while (scratch[--i] != '/');

        if (stat_prefix(scratch, i, st) == 0) {
            *k = i;
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
 * True when `path` is a planned directory (the directory pass acts on it
 * before any file is written, and preflight already judges it on its own).
 */
static bool directory_is_pending(const deploy_plan_t *plan, const char *path) {
    state_directories_t dirs = state_directories_view(&plan->directories.pending);
    for (size_t i = 0; i < dirs.count; i++) {
        if (strcmp(dirs.entries[i]->filesystem_path, path) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Run pre-flight checks over the plan
 *
 * Workspace = analysis layer, preflight = decision layer, execute =
 * execution layer. Divergence verdicts are O(1) index probes; the
 * ancestor and writability checks are filesystem-level.
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
        return ERROR(ERR_MEMORY, "Failed to allocate preflight result");
    }

    result->conflicts = string_array_new(0);
    result->blocked = string_array_new(0);
    result->permission_errors = string_array_new(0);
    if (!result->conflicts || !result->blocked || !result->permission_errors) {
        preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate result arrays");
    }

    error_t *err = NULL;
    char *scratch = NULL;

    state_files_t files = state_files_view(&plan->files.pending);
    for (size_t i = 0; i < files.count; i++) {
        const char *path = files.entries[i]->filesystem_path;
        const workspace_item_t *item = workspace_get_item(ws, path);

        /* Content or type divergence blocks unless --force. Metadata and
         * encryption divergence are informational. STALE content is the
         * old blob dotta itself deployed — safe to overwrite. */
        if (item && !opts->force &&
            (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE)) &&
            !(item->divergence & DIVERGENCE_STALE)) {
            err = string_array_push(result->conflicts, path);
            if (err) goto fail;
            result->has_errors = true;
        }

        /* Where will the write land? An existing path (any type; stat
         * follows symlinks, so a broken link counts as absent) must itself
         * be writable. An absent path is written beneath its nearest
         * existing ancestor: a non-directory there blocks the write —
         * unless that ancestor is a planned directory, whose own conflict
         * entry already describes the situation (and which --force replaces
         * before any file is written). An out-of-scope squatter is never
         * touched (Coherent Scope), so the file cannot land: say so now, not
         * at write time. A directory ancestor must be writable. */
        struct stat st;
        const char *landing = path;
        if (stat(path, &st) != 0) {
            free(scratch);
            scratch = strdup(path);
            if (!scratch) {
                err = ERROR(ERR_MEMORY, "Failed to copy path for ancestor check");
                goto fail;
            }
            size_t k;
            if (!nearest_ancestor(scratch, &k, &st)) {
                continue;                       /* let the write surface the errno */
            }
            scratch[k ? k : 1] = '\0';          /* the ancestor, on its own */
            landing = scratch;
            if (!S_ISDIR(st.st_mode)) {
                if (!directory_is_pending(plan, landing)) {
                    char *entry = str_format("%s (%s is not a directory)", path, landing);
                    if (!entry) {
                        err = ERROR(ERR_MEMORY, "Failed to format blocked entry");
                        goto fail;
                    }
                    err = string_array_push_owned(result->blocked, entry);
                    if (err) {
                        free(entry);
                        goto fail;
                    }
                    result->has_errors = true;
                }
                continue;
            }
        }

        if (access(landing, W_OK) != 0) {
            err = string_array_push(result->permission_errors, path);
            if (err) goto fail;
            result->has_errors = true;
        }
    }

    /* A planned directory squatted by a non-directory (workspace probes
     * with lstat, so a symlink to a directory counts) blocks unless --force
     * lets deploy_directory replace it. Only planned directories are asked. */
    state_directories_t dirs = state_directories_view(&plan->directories.pending);
    for (size_t i = 0; i < dirs.count; i++) {
        const char *path = dirs.entries[i]->filesystem_path;
        const workspace_item_t *item = workspace_get_item(ws, path);

        if (item && !opts->force && (item->divergence & DIVERGENCE_TYPE)) {
            err = string_array_push(result->conflicts, path);
            if (err) goto fail;
            result->has_errors = true;
        }
    }

    free(scratch);
    *out = result;
    return NULL;

fail:
    free(scratch);
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
 * @param storage_path Path in profile (e.g., "home/.bashrc", "root/etc/hosts", "custom/etc/nginx.conf")
 * @param filesystem_path Resolved deployment path (e.g., "/home/user/.bashrc") for home detection
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
    const char *owner,
    const char *group,
    uid_t *out_uid,
    gid_t *out_gid,
    bool strict_ownership,
    bool dry_run,
    bool verbose
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
 * fallback and its warning) and resolved ownership. Pure decision.
 */
static error_t *resolve_directory_metadata(
    const state_directory_entry_t *dir,
    const deploy_options_t *opts,
    mode_t *out_mode,
    uid_t *out_uid,
    gid_t *out_gid
) {
    /* The manifest layer populates mode at write time; mode==0 indicates
     * state corruption or a manifest sync failure. Warn and fall back. */
    mode_t mode = dir->mode;
    if (mode == 0) {
        mode = 0755;

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
        dir->owner,
        dir->group,
        out_uid,
        out_gid,
        opts->strict_ownership,
        opts->dry_run,
        opts->verbose
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
 * anything else 0755 owned like the planned path beneath it.
 */
static error_t *create_ancestor(
    const workspace_t *ws,
    const char *path,
    uid_t uid,
    gid_t gid,
    const deploy_options_t *opts
) {
    const state_directory_entry_t *dir = workspace_lookup_directory(ws, path);
    if (dir) {
        mode_t mode;
        uid_t dir_uid;
        gid_t dir_gid;
        RETURN_IF_ERROR(resolve_directory_metadata(dir, opts, &mode, &dir_uid, &dir_gid));
        return fs_create_dir_with_ownership(path, mode, dir_uid, dir_gid);
    }

    return fs_create_dir_with_ownership(path, 0755, uid, gid);
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
 */
static error_t *ensure_parents(
    const workspace_t *ws,
    const char *path,
    uid_t uid,
    gid_t gid,
    const deploy_options_t *opts
) {
    char *scratch = strdup(path);
    if (!scratch) {
        return ERROR(ERR_MEMORY, "Failed to copy path for parent creation");
    }

    error_t *err = NULL;
    struct stat st;
    size_t k;
    if (!nearest_ancestor(scratch, &k, &st)) {
        goto cleanup;                            /* let the write surface the errno */
    }
    if (!S_ISDIR(st.st_mode)) {
        scratch[k ? k : 1] = '\0';
        err = ERROR(
            ERR_FS, "Cannot create parents of '%s': '%s' is not a directory",
            path, scratch
        );
        goto cleanup;
    }

    /* Every slash past the ancestor ends one missing parent; the final
     * component is the planned path itself. */
    for (char *slash = strchr(scratch + k + 1, '/'); slash; slash = strchr(slash + 1, '/')) {
        *slash = '\0';
        err = create_ancestor(ws, scratch, uid, gid, opts);
        *slash = '/';
        if (err) {
            err = error_wrap(err, "Failed to create parent directory for '%s'", path);
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

    error_t *err = NULL;
    const buffer_t *content_buffer = NULL;  /* Borrowed from cache (const) */
    char *target_str = NULL;

    /* A zero OID means the row was never populated from state — impossible
     * for a row reaching the deploy path, kept as a sanity check. */
    if (git_oid_is_zero(&file->blob_oid)) {
        return ERROR(
            ERR_INTERNAL, "Missing blob_oid for '%s' (state corruption?)",
            file->filesystem_path
        );
    }

    /* Ownership is resolved BEFORE any write so fs_write_file_raw /
     * lchown apply it atomically — no window with wrong ownership. */
    uid_t target_uid, target_gid;
    err = resolve_deployment_ownership(
        file->storage_path,
        file->filesystem_path,
        file->owner,
        file->group,
        &target_uid,
        &target_gid,
        opts->strict_ownership,
        opts->dry_run,
        opts->verbose
    );
    if (err) {
        return error_wrap(
            err, "Failed to resolve ownership for '%s'",
            file->filesystem_path
        );
    }

    /* The one mutation gate */
    if (opts->dry_run) {
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

    /* Symlinks are never encrypted: read the blob directly, bypassing the
     * content layer (designed for regular files with potential encryption). */
    if (file->type == STATE_FILE_SYMLINK) {
        size_t target_len = 0;
        err = gitops_read_blob_content(
            repo, &file->blob_oid, (void **) &target_str, &target_len
        );
        if (err) goto cleanup;

        /* fs_clear_path: lstat-based (broken symlinks detected), handles
         * files, symlinks and directories, idempotent when absent.
         * Safety: only reached with --force (preflight blocks DIVERGENCE_TYPE) */
        err = fs_clear_path(file->filesystem_path);
        if (err) {
            err = error_wrap(err, "Failed to prepare path for symlink deployment");
            goto cleanup;
        }

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

    const unsigned char *content = (const unsigned char *) content_buffer->data;
    size_t size = content_buffer->size;

    /* The manifest layer populates mode at write time; mode==0 indicates
     * state corruption or a manifest sync failure. Fall back by type. */
    mode_t file_mode = file->mode;
    if (file_mode == 0) {
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

    /* fs_write_file_raw overwrites files via O_TRUNC but cannot replace a
     * directory (EISDIR): clear one explicitly. lstat so a symlink to a
     * directory is left to O_CREAT (it is not S_IFDIR).
     * Safety: only reached with --force (preflight blocks DIVERGENCE_TYPE) */
    struct stat target_stat;
    if (lstat(file->filesystem_path, &target_stat) == 0 && S_ISDIR(target_stat.st_mode)) {
        err = fs_remove_dir(file->filesystem_path, true);
        if (err) {
            err = error_wrap(
                err, "Failed to clear directory at '%s'",
                file->filesystem_path
            );
            goto cleanup;
        }
    }

    /* fs_write_file_raw atomically sets ownership and permissions via
     * fchown()/fchmod() on the descriptor — the ONLY place ownership is
     * applied; the metadata layer only resolves. */
    err = fs_write_file_raw(
        file->filesystem_path,
        content,
        size,
        file_mode,
        target_uid,
        target_gid
    );
    if (err) {
        err = error_wrap(
            err, "Failed to deploy file '%s'",
            file->filesystem_path
        );
        goto cleanup;
    }

    if (opts->verbose) {
        bool has_ownership = (file->owner || file->group) && target_uid != (uid_t) -1;

        if (has_ownership) {
            printf(
                "Deployed: %s (mode: %04o, owner: %s:%s)\n",
                file->filesystem_path, file_mode,
                file->owner ? file->owner : "?",
                file->group ? file->group : "?"
            );
        } else {
            printf(
                "Deployed: %s (mode: %04o)\n",
                file->filesystem_path, file_mode
            );
        }
    }

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
    DIR_CREATE,     /* absent */
    DIR_FIX,        /* a directory is there — ensure mode/ownership */
    DIR_REPLACE     /* a non-directory squats the path — clear it (--force) */
} dir_action_t;

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
            dir->owner ? dir->owner : "?",
            dir->group ? dir->group : "?", detail
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
    dir_action_t how;
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            how = DIR_FIX;
        } else if (opts->force) {
            how = DIR_REPLACE;
        } else {
            return ERROR(
                ERR_CONFLICT, "'%s' is not a directory (use --force to replace it)",
                path
            );
        }
    } else if (errno == ENOENT) {
        how = DIR_CREATE;
    } else {
        return ERROR(ERR_FS, "Failed to stat '%s': %s", path, strerror(errno));
    }

    /* Divergence detail for the trace — from the fresh stat, FIX only */
    char detail[32] = "";
    if (how == DIR_FIX && opts->verbose) {
        bool mode_differs = false;
        bool ownership_differs = false;
        error_t *err = check_item_metadata_divergence(
            dir->mode, dir->owner, dir->group, &st, &mode_differs, &ownership_differs
        );
        if (err) return err;

        if (mode_differs || ownership_differs) {
            snprintf(
                detail, sizeof(detail), " [%s%s%s]",
                mode_differs ? "mode" : "",
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
    error_t *err = resolve_directory_metadata(dir, opts, &mode, &target_uid, &target_gid);
    if (err) {
        return err;
    }

    bool has_ownership = (dir->owner || dir->group) && target_uid != (uid_t) -1;
    static const char *const verbs[][2] = {
        [DIR_CREATE]  = { "Would create",  "Created"  },
        [DIR_FIX]     = { "Would fix",     "Fixed"    },
        [DIR_REPLACE] = { "Would replace", "Replaced" },
    };

    /* The one mutation gate */
    if (opts->dry_run) {
        if (opts->verbose) {
            print_directory_trace(verbs[how][0], dir, mode, has_ownership, detail);
        }
        return NULL;
    }

    if (how == DIR_REPLACE) {
        err = fs_clear_path(path);
        if (err) {
            return error_wrap(err, "Failed to clear type conflict at '%s'", path);
        }
    } else if (how == DIR_CREATE) {
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
        print_directory_trace(verbs[how][1], dir, mode, has_ownership, detail);
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

        err = ptr_array_push(&result->deployed, file);
        if (err) {
            deploy_result_free(result);
            return error_wrap(err, "Failed to record deployed file");
        }
    }

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
