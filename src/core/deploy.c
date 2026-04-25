/**
 * deploy.c - File deployment engine implementation
 */

#include "core/deploy.h"

#include <errno.h>
#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/metadata.h"
#include "core/scope.h"
#include "core/workspace.h"
#include "infra/content.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/privilege.h"

/**
 * Run pre-flight checks using workspace divergence analysis
 *
 * This is the optimized preflight implementation that eliminates redundant
 * file comparisons by querying pre-computed workspace divergence data.
 *
 * Architecture:
 * - Workspace (single source of truth) = Analysis Layer
 * - Preflight (this function) = Decision Layer
 * - Deploy = Execution Layer
 */
error_t *deploy_workspace_preflight(
    const workspace_t *ws,
    const manifest_t *manifest,
    const deploy_options_t *opts,
    preflight_result_t **out
) {
    CHECK_NULL(ws);
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Allocate result structure */
    preflight_result_t *result = calloc(1, sizeof(preflight_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate preflight result");
    }

    result->has_errors = false;
    result->conflicts = string_array_new(0);
    result->permission_errors = string_array_new(0);
    result->reassignments = NULL;
    result->reassignment_count = 0;

    if (!result->conflicts || !result->permission_errors) {
        preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate result arrays");
    }

    /* Conflict Detection + Profile Reassignments + Writability
     * Query workspace for divergence (O(1) per file), map to preflight decisions.
     */

    /* Pre-allocate reassignments array (resize as needed) */
    size_t reassignment_capacity = 16;
    result->reassignments = calloc(reassignment_capacity, sizeof(reassignment_t));
    if (!result->reassignments) {
        preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate reassignments array");
    }

    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];
        const char *path = entry->filesystem_path;

        /* Query workspace for divergence (O(1) hashmap lookup) */
        const workspace_item_t *ws_item = workspace_get_item(ws, path);

        if (ws_item && !opts->force) {
            /*
             * File has divergence - check if it's a blocking conflict.
             * Only block on content conflicts (CONTENT, TYPE).
             * Metadata divergence (mode, ownership) and encryption policy are informational.
             *
             * DIVERGENCE_STALE exception: When content diverges because the expected
             * state changed (stale repair), and the file on disk matches what dotta
             * deployed (old blob), it's safe to overwrite. DIVERGENCE_STALE is only
             * set after this verification, so we can trust it here.
             */
            if ((ws_item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE)) &&
                !(ws_item->divergence & DIVERGENCE_STALE)) {
                /* Content or type conflict - block deployment */
                error_t *err = string_array_push(result->conflicts, path);
                if (err) {
                    preflight_result_free(result);
                    return error_wrap(err, "Failed to record conflict");
                }
                result->has_errors = true;
            }
            /* Mode/ownership/encryption divergence is not blocking */
        }

        /* Check for profile reassignment */
        if (ws_item && ws_item->profile_changed) {
            /* Grow reassignments array if needed */
            if (result->reassignment_count >= reassignment_capacity) {
                reassignment_capacity *= 2;
                reassignment_t *new_array = realloc(
                    result->reassignments,
                    reassignment_capacity * sizeof(reassignment_t)
                );
                if (!new_array) {
                    preflight_result_free(result);
                    return ERROR(ERR_MEMORY, "Failed to grow reassignments array");
                }
                result->reassignments = new_array;
            }

            /* Add reassignment */
            reassignment_t *change = &result->reassignments[result->reassignment_count];
            change->filesystem_path = strdup(path);
            change->old_profile = strdup(ws_item->old_profile);
            change->new_profile = strdup(ws_item->profile);

            if (!change->filesystem_path || !change->old_profile || !change->new_profile) {
                /* Cleanup partial allocation */
                free(change->filesystem_path);
                free(change->old_profile);
                free(change->new_profile);
                preflight_result_free(result);
                return ERROR(ERR_MEMORY, "Failed to allocate reassignment strings");
            }

            result->reassignment_count++;
        }

        /* Writability check (filesystem-level, not in workspace) */
        if (!fs_is_writable(path)) {
            error_t *err = string_array_push(result->permission_errors, path);
            if (err) {
                preflight_result_free(result);
                return error_wrap(err, "Failed to record permission error");
            }
            result->has_errors = true;
        }
    }

    /* Check directories for type conflicts
     *
     * File preflight checks manifest entries, but directories are tracked
     * separately in state database. Directory type divergence (dir replaced
     * by file/symlink) must also block deployment unless --force.
     *
     * Architecture: Workspace uses lstat() for type detection, so symlinks
     * are correctly identified as type changes even if they point to directories.
     */
    size_t diverged_count = 0;
    const workspace_item_t *diverged = workspace_get_all_diverged(ws, &diverged_count);

    for (size_t i = 0; i < diverged_count; i++) {
        const workspace_item_t *item = &diverged[i];

        /* Only check directories with TYPE divergence */
        if (item->item_kind != WORKSPACE_ITEM_DIRECTORY) {
            continue;
        }
        if (!(item->divergence & DIVERGENCE_TYPE)) {
            continue;
        }

        /* With --force, let deploy handle it */
        if (opts->force) {
            continue;
        }

        /* Record as blocking conflict */
        error_t *err = string_array_push(result->conflicts, item->filesystem_path);
        if (err) {
            preflight_result_free(result);
            return error_wrap(err, "Failed to record directory type conflict");
        }
        result->has_errors = true;
    }

    *out = result;
    return NULL;
}

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
 *   prefix files reclassified by --prefix that still land under $HOME)
 *
 * Strict ownership mode (strict_ownership=true):
 * - ERR_NOT_FOUND (user/group missing): Fatal error, abort deployment
 * - ERR_PERMISSION (not root): Warning only (can't chown anyway)
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

    /* Determine prefix type */
    bool is_home_prefix = str_starts_with(storage_path, "home/");
    bool requires_root_privileges = privilege_path_requires_root(storage_path);

    /* Case 1: File deploys to user's home when running as root (sudo handling)
     *
     * Primary: storage_path starts with "home/" (always deploys to $HOME)
     * Fallback: filesystem_path is under actual user's home (catches custom/
     * prefix files reclassified by --prefix that still land under $HOME) */
    if (privilege_is_elevated()) {
        bool deploys_to_home = is_home_prefix;

        if (!deploys_to_home && filesystem_path) {
            deploys_to_home = privilege_path_is_under_home(filesystem_path);
        }

        if (deploys_to_home) {
            error_t *err = privilege_get_actual_user(out_uid, out_gid);
            if (err) {
                return error_wrap(
                    err, "Failed to determine actual user for home path: %s",
                    storage_path
                );
            }
            return NULL;
        }
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
 * Deploy single file
 */
error_t *deploy_file(
    git_repository *repo,
    content_cache_t *cache,
    file_entry_t *entry,
    const deploy_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(cache);
    CHECK_NULL(entry);
    CHECK_NULL(opts);

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    const buffer_t *content_buffer = NULL;  /* Borrowed from cache (const) */
    char *target_str = NULL;

    if (opts->dry_run) {
        /* Dry-run mode - just print */
        if (opts->verbose) {
            printf("  Would deploy: %s\n", entry->filesystem_path);
        }
        return NULL;
    }

    /* Validate blob_oid from VWD cache. A zero OID means the entry was never
     * populated from state — should be impossible for entries reaching the
     * deploy path, but we keep the defensive check. */
    if (git_oid_is_zero(&entry->blob_oid)) {
        return ERROR(
            ERR_INTERNAL, "Missing blob_oid for '%s' (state corruption?)",
            entry->filesystem_path
        );
    }

    /* Handle symlinks - these are never encrypted, so handle separately */
    if (entry->type == STATE_FILE_SYMLINK) {
        /* For symlinks, we load the blob directly since the content layer
         * is designed for regular files with potential encryption. */
        size_t target_len = 0;
        err = gitops_read_blob_content(
            repo, &entry->blob_oid, (void **) &target_str, &target_len
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
        err = fs_clear_path(entry->filesystem_path);
        if (err) {
            err = error_wrap(
                err, "Failed to prepare path for symlink deployment"
            );
            goto cleanup;
        }

        /* Create symlink */
        err = fs_create_symlink(target_str, entry->filesystem_path);
        if (err) {
            err = error_wrap(
                err, "Failed to deploy symlink '%s'",
                entry->filesystem_path
            );
            goto cleanup;
        }

        /* Apply ownership to symlink if needed (root/ prefix paths)
         *
         * Symlink permissions are ignored by most filesystems, but symlink
         * OWNERSHIP matters for security auditing and consistency.
         * lchown() changes the link itself, not its target.
         */
        uid_t link_uid;
        gid_t link_gid;
        err = resolve_deployment_ownership(
            entry->storage_path,
            entry->filesystem_path,
            entry->owner,
            entry->group,
            &link_uid,
            &link_gid,
            opts->strict_ownership,
            opts->dry_run,
            opts->verbose
        );
        if (err) {
            err = error_wrap(
                err, "Failed to resolve ownership for symlink '%s'",
                entry->filesystem_path
            );
            goto cleanup;
        }

        if (link_uid != (uid_t) -1 || link_gid != (gid_t) -1) {
            if (lchown(entry->filesystem_path, link_uid, link_gid) != 0) {
                err = ERROR(
                    ERR_FS, "Failed to set ownership on symlink '%s': %s",
                    entry->filesystem_path, strerror(errno)
                );
                goto cleanup;
            }
        }

        if (opts->verbose) {
            printf(
                "Deployed symlink: %s\n",
                entry->filesystem_path
            );
        }

        /* Success for symlink - goto cleanup will handle freeing */
        err = NULL;
        goto cleanup;
    }

    /* Handle regular files - get content from cache with transparent decryption */
    err = content_cache_get_from_blob_oid(
        cache,
        &entry->blob_oid,
        entry->storage_path,
        entry->profile ? entry->profile : "unknown",
        entry->encrypted,
        &content_buffer
    );

    if (err) {
        err = error_wrap(err, "Failed to get content for '%s'", entry->storage_path);
        goto cleanup;
    }

    /* Get content pointer and size from buffer */
    const unsigned char *content = (const unsigned char *) content_buffer->data;
    size_t size = content_buffer->size;

    /* Determine permissions from manifest cache
     *
     * In VWD operations, state database should always have mode populated
     * by manifest layer. If mode==0, this indicates state corruption or
     * manifest sync failure. Fall back to git mode defensively.
     */
    mode_t file_mode = entry->mode;
    if (file_mode == 0) {
        /* Defensive fallback - indicates unexpected state corruption */
        file_mode = (entry->type == STATE_FILE_EXECUTABLE) ? 0755 : 0644;

        if (opts->verbose) {
            fprintf(
                stderr,
                "Warning: Missing mode in state for '%s', using git mode %04o\n"
                "         This may indicate state database corruption. Consider running:\n"
                "         dotta profile disable %s && dotta profile enable %s\n",
                entry->filesystem_path, file_mode,
                entry->profile ? entry->profile : "<profile>",
                entry->profile ? entry->profile : "<profile>"
            );
        }
    }

    /* Resolve ownership for the file based on prefix - RESOLVED BEFORE WRITING
     *
     * SECURITY: Ownership resolution happens BEFORE file creation to enable
     * atomic ownership via fchown() on the file descriptor. This eliminates
     * the security window where files exist with incorrect ownership.
     *
     * VWD Authority: Uses entry->owner and entry->group from state cache.
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
        entry->storage_path,
        entry->filesystem_path,
        entry->owner,  /* From manifest cache */
        entry->group,  /* From manifest cache */
        &target_uid,
        &target_gid,
        opts->strict_ownership,
        opts->dry_run,
        opts->verbose
    );
    if (err) {
        err = error_wrap(
            err, "Failed to resolve ownership for '%s'",
            entry->filesystem_path
        );
        goto cleanup;
    }

    /* Clear directory at target path if present
     *
     * fs_write_file_raw() can overwrite existing files via O_TRUNC but cannot
     * replace directories (open() fails with EISDIR). Directories must be
     * cleared explicitly before writing.
     *
     * Uses lstat() to avoid following symlinks:
     * - Symlink to directory: lstat returns S_IFLNK -> O_CREAT handles correctly
     * - Actual directory: lstat returns S_IFDIR -> must clear before writing
     *
     * Safety: Only reached with --force (preflight blocks DIVERGENCE_TYPE)
     */
    struct stat target_stat;
    if (lstat(entry->filesystem_path, &target_stat) == 0 && S_ISDIR(target_stat.st_mode)) {
        err = fs_remove_dir(entry->filesystem_path, true);
        if (err) {
            err = error_wrap(
                err, "Failed to clear directory at '%s'",
                entry->filesystem_path
            );
            goto cleanup;
        }
    }

    /* Write directly from git blob to filesystem with atomic ownership and permissions
     * SECURITY: fs_write_file_raw atomically sets BOTH ownership and permissions via
     * fchown() and fchmod() on the file descriptor, eliminating any security window.
     * This is the ONLY place where ownership is applied - metadata layer only resolves. */
    err = fs_write_file_raw(
        entry->filesystem_path,
        content,
        size,
        file_mode,
        target_uid,
        target_gid
    );

    if (err) {
        err = error_wrap(
            err, "Failed to deploy file '%s'",
            entry->filesystem_path
        );
        goto cleanup;
    }

    /* Verbose output */
    if (opts->verbose) {
        bool has_ownership = (entry->owner || entry->group) && target_uid != (uid_t) -1;

        if (has_ownership) {
            printf(
                "Deployed: %s (mode: %04o, owner: %s:%s)\n",
                entry->filesystem_path, file_mode,
                entry->owner ? entry->owner : "?", entry->group ? entry->group : "?"
            );
        } else {
            printf(
                "Deployed: %s (mode: %04o)\n",
                entry->filesystem_path, file_mode
            );
        }
    }

    /* Success */
    err = NULL;

cleanup:
    /* Free resources in reverse order */
    if (target_str) free(target_str);

    return err;
}

/**
 * Calculate directories required for deploying manifest files
 *
 * When the caller passes a path-scoped operation (scope_has_paths), only
 * directories that are ancestors of files in the manifest should be
 * processed. This function builds a hashmap of tracked directory paths
 * that are ancestors of any file being deployed.
 *
 * Performance: O(F * D) where F = files in manifest, D = average path depth
 * Memory: Caller owns returned hashmap and must free with hashmap_free(h, NULL)
 *
 * @param manifest Files being deployed (must not be NULL)
 * @param state State database for tracked directory lookup (must not be NULL)
 * @param out Hashmap of required directory filesystem_paths (caller frees)
 * @return Error or NULL on success
 */
static error_t *calculate_required_directories(
    const manifest_t *manifest,
    const state_t *state,
    arena_t *arena,
    hashmap_t **out
) {
    CHECK_NULL(manifest);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    error_t *err = NULL;
    hashmap_t *tracked = NULL;
    hashmap_t *required = NULL;
    char *parent = NULL;

    /* Get all tracked directories for O(1) membership check */
    state_directory_entry_t *directories = NULL;
    size_t dir_count = 0;
    err = state_get_all_directories(state, arena, &directories, &dir_count);
    if (err) goto cleanup;

    if (dir_count == 0) {
        goto cleanup;  /* No tracked directories - nothing to filter */
    }

    /* Build lookup hashmap of tracked directory paths */
    tracked = hashmap_create(dir_count);
    if (!tracked) {
        err = ERROR(ERR_MEMORY, "Failed to create tracked directory hashmap");
        goto cleanup;
    }

    for (size_t i = 0; i < dir_count; i++) {
        err = hashmap_set(tracked, directories[i].filesystem_path, (void *) 1);
        if (err) {
            err = error_wrap(err, "Failed to populate tracked directory set");
            goto cleanup;
        }
    }

    /* Build set of required directories from manifest file ancestors */
    required = hashmap_create(0);
    if (!required) {
        err = ERROR(ERR_MEMORY, "Failed to create required directory hashmap");
        goto cleanup;
    }

    for (size_t i = 0; i < manifest->count; i++) {
        const char *filepath = manifest->entries[i].filesystem_path;

        /* Walk up directory tree, adding tracked ancestors */
        size_t len = strlen(filepath);
        parent = malloc(len + 1);
        if (!parent) {
            err = ERROR(ERR_MEMORY, "Failed to allocate path buffer");
            goto cleanup;
        }
        memcpy(parent, filepath, len + 1);

        while (true) {
            char *slash = strrchr(parent, '/');
            if (!slash || slash == parent) {
                break;     /* Reached root */
            }
            *slash = '\0'; /* Truncate to parent */

            /* If this parent is tracked, add to required set */
            if (hashmap_has(tracked, parent)) {
                err = hashmap_set(required, parent, (void *) 1);
                if (err) {
                    err = error_wrap(err, "Failed to add required directory");
                    goto cleanup;
                }
            }
        }
        free(parent);
        parent = NULL;
    }

    *out = required;
    required = NULL;  /* Ownership transferred to caller */

cleanup:
    free(parent);
    if (tracked) hashmap_free(tracked, NULL);
    if (required) hashmap_free(required, NULL);
    return err;
}

/**
 * Deploy tracked directories from state
 *
 * Creates or updates tracked directories with proper permissions and ownership
 * before deploying files. Uses workspace divergence analysis to determine which
 * directories need updates, enabling convergence of directory metadata.
 *
 * ARCHITECTURE: Uses state (VWD) instead of metadata (Git) for directory resolution.
 * State contains filesystem_path already resolved with custom_prefix during manifest
 * building, eliminating path conversion errors and enabling custom prefix support.
 *
 * Convergence model (matches file deployment pattern):
 * - Query workspace for divergence (O(1) hashmap lookup)
 * - Skip CLEAN directories (no divergence, already correct)
 * - Create missing directories
 * - Fix divergent directories (mode/ownership changes)
 *
 * Targeted mode (when required_dirs is non-NULL):
 * - Only processes directories that are ancestors of files being deployed
 * - Implements coherent scope: file filter scopes all side effects
 *
 * @param ws Workspace with divergence analysis (must not be NULL)
 * @param state State database (can be NULL - returns immediately if NULL)
 * @param opts Deployment options (must not be NULL)
 * @param required_dirs Directories to process (NULL = all, non-NULL = filter)
 * @return Error or NULL on success
 */
static error_t *deploy_tracked_directories(
    const workspace_t *ws,
    const state_t *state,
    arena_t *arena,
    const deploy_options_t *opts,
    const hashmap_t *required_dirs
) {
    CHECK_NULL(ws);
    CHECK_NULL(arena);
    CHECK_NULL(opts);

    /* Gracefully handle NULL state (no database = no tracked directories) */
    if (!state) {
        return NULL;
    }

    /* Get all tracked directories from state database */
    state_directory_entry_t *directories = NULL;
    size_t dir_count = 0;
    error_t *err = state_get_all_directories(state, arena, &directories, &dir_count);
    if (err) {
        err = error_wrap(err, "Failed to load tracked directories from state");
        goto cleanup;
    }

    if (dir_count == 0) {
        goto cleanup;  /* No tracked directories */
    }

    /* Verbose output: differentiate scoped vs full sync mode.
     *
     * Path-scope (scope_has_paths) is strictly ancestor-only and trumps
     * profile-scope (scope_has_filter), which is inclusive. */
    if (opts->verbose) {
        if (opts->scope && scope_has_paths(opts->scope)) {
            /* File filter: strictly ancestors only */
            size_t required_count = required_dirs ? hashmap_size(required_dirs) : 0;
            if (required_count > 0) {
                printf(
                    "Processing %zu tracked director%s (scoped to deployment)...\n",
                    required_count, required_count == 1 ? "y" : "ies"
                );
            }
            /* If required_count == 0, no directories to process - skip message */
        } else if (opts->scope && scope_has_filter(opts->scope)) {
            /* Profile filter: ancestors + profile-owned directories */
            printf(
                "Processing tracked directories (scoped to profile)...\n"
            );
        } else {
            /* Full sync: all directories */
            printf(
                "Processing %zu tracked director%s...\n",
                dir_count, dir_count == 1 ? "y" : "ies"
            );
        }
    }

    /* Deploy each tracked directory */
    for (size_t i = 0; i < dir_count; i++) {
        const state_directory_entry_t *dir_entry = &directories[i];

        /* Scope filtering: path-scoped (strict) and/or profile-scoped (inclusive)
         *
         * Composition rules (Inclusive Ancestry principle):
         *
         * 1. path-scoped (scope_has_paths): STRICT — only required ancestors.
         *    Skip ALL directories not in required_dirs.
         *
         * 2. profile-scoped (scope_has_filter): INCLUSIVE — process if in
         *    required_dirs (ancestor of in-scope file) OR owned by a
         *    profile matching the CLI -p filter.
         *
         * 3. Both active: path-scoped wins (more restrictive) — only
         *    ancestors of specific files, regardless of profile ownership.
         */
        bool in_required = required_dirs &&
            hashmap_has(required_dirs, dir_entry->filesystem_path);

        if (opts->scope && scope_has_paths(opts->scope)) {
            /* Strict ancestor-only mode (file filter active) */
            if (!in_required) {
                if (opts->verbose) {
                    printf(
                        "  Skipped: %s (not ancestor of targeted files)\n",
                        dir_entry->filesystem_path
                    );
                }
                continue;
            }
        } else if (opts->scope && scope_has_filter(opts->scope)) {
            /* Profile scope: ancestors OR profile-owned directories.
             *
             * Inclusive Ancestry: ancestor directories are always processed
             * to ensure file deployment succeeds, even if owned by a
             * different profile than the one the user filtered to. */
            if (!in_required &&
                !scope_accepts_profile(opts->scope, dir_entry->profile)) {
                if (opts->verbose) {
                    printf(
                        "  Skipped: %s (outside profile scope)\n",
                        dir_entry->filesystem_path
                    );
                }
                continue;
            }
        }
        /* else: no filter, process all (full sync mode) */

        /* Skip removal-pending directories (STATE_INACTIVE or STATE_DELETED)
         *
         * ARCHITECTURE: These directories are staged for removal (by profile disable
         * or confirmed deletion). They should NOT be deployed.
         */
        if (dir_entry->state && (strcmp(dir_entry->state, STATE_INACTIVE) == 0 ||
            strcmp(dir_entry->state, STATE_DELETED) == 0)) {
            if (opts->verbose) {
                printf(
                    "  Skipped: %s (staged for removal)\n",
                    dir_entry->filesystem_path
                );
            }
            continue;
        }

        /* State directory entries contain:
         * - filesystem_path: Already resolved with custom_prefix (VWD principle)
         * - storage_path: Portable path (for ownership resolution)
         * - mode, owner, group: Metadata for deployment
         */

        /* Use filesystem path directly from state (already resolved) */
        const char *filesystem_path = dir_entry->filesystem_path;

        /* Validate directory mode from state (before skip/dry-run checks)
         *
         * In VWD operations, state database should always have mode populated
         * by manifest layer. If mode==0, this indicates state corruption or
         * manifest sync failure. Warn and use safe default (0755 for directories).
         */
        mode_t dir_mode = dir_entry->mode;
        if (dir_mode == 0) {
            /* Defensive fallback - indicates unexpected state corruption */
            dir_mode = 0755;  /* Safe default for directories */

            if (opts->verbose) {
                fprintf(
                    stderr,
                    "Warning: Missing mode in state for directory '%s', using default %04o\n"
                    "         This may indicate state database corruption. Consider running:\n"
                    "         dotta profile disable %s && dotta profile enable %s\n",
                    filesystem_path, dir_mode,
                    dir_entry->profile ? dir_entry->profile : "<profile>",
                    dir_entry->profile ? dir_entry->profile : "<profile>"
                );
            }
        }

        /* Query workspace for divergence (O(1) hashmap lookup)
         *
         * Convergence model (matches file deployment pattern):
         * - ws_item == NULL && exists -> SKIP (directory CLEAN)
         * - ws_item != NULL -> FIX (has divergence: mode/ownership/type)
         * - !exists -> CREATE (missing or deleted)
         */
        const workspace_item_t *ws_item = workspace_get_item(ws, filesystem_path);

        /* Track existence for output messaging and missing-directory creation
         *
         * Uses fs_is_directory (stat-based) rather than deriving from ws_item because:
         * - When ws_item is NULL, directory SHOULD exist (workspace found no divergence),
         *   but this provides a safety net for edge cases (e.g., analyze_directories=false)
         * - Type divergence detection uses workspace (lstat-based) — the distinction matters
         *   for symlink-to-directory detection
         * Mutable: type conflict branch below may clear the path and update this. */
        bool directory_existed = fs_is_directory(filesystem_path);

        /* Type conflict: workspace detected directory replaced by file/symlink
         *
         * Uses ws_item->divergence instead of filesystem checks because:
         * - Workspace uses lstat() for type detection (doesn't follow symlinks)
         * - fs_is_directory() uses stat() (follows symlinks)
         * - Symlink-to-directory would appear as "directory" to fs_is_directory()
         * - Single source of truth: workspace already did the analysis
         */
        if (ws_item && (ws_item->divergence & DIVERGENCE_TYPE)) {
            if (!opts->force) {
                /* Without --force, skip (preflight should have blocked) */
                fprintf(
                    stderr, "  Conflict: %s is not a directory (skipping)\n",
                    filesystem_path
                );
                fprintf(
                    stderr, "  Use --force to clear and recreate as directory\n"
                );
                continue;
            }

            /* With --force: clear the conflicting path
             *
             * fs_clear_path uses lstat() and handles files, symlinks, and
             * directories uniformly. After clearing, normal directory creation
             * proceeds below.
             */
            if (opts->verbose) {
                printf(
                    "  Clearing type conflict at %s (recreating as directory)\n",
                    filesystem_path
                );
            }

            error_t *clear_err = fs_clear_path(filesystem_path);
            if (clear_err) {
                err = error_wrap(
                    clear_err, "Failed to clear type conflict at '%s'",
                    filesystem_path
                );
                goto cleanup;
            }

            /* Path cleared - update tracking flag for verbose output */
            directory_existed = false;
        }

        /* Skip if directory is CLEAN (no divergence and exists on filesystem)
         *
         * Workspace divergence analysis is authoritative - if ws_item is NULL,
         * mode and ownership already match expected state. Continue. */
        if (!ws_item && directory_existed) {
            if (opts->verbose) {
                printf("  Skipped: %s (unchanged)\n", filesystem_path);
            }
            continue;
        }

        /* Dry-run: print what would happen with divergence detail */
        if (opts->dry_run) {
            if (opts->verbose) {
                const char *verb = directory_existed ? "Would fix" : "Would create";

                /* Build divergence detail from workspace analysis */
                char action[32] = "";
                if (ws_item && directory_existed) {
                    bool has_mode = ws_item->divergence & DIVERGENCE_MODE;
                    bool has_own = ws_item->divergence & DIVERGENCE_OWNERSHIP;
                    snprintf(
                        action, sizeof(action), " [%s%s%s]", has_mode ? "mode" : "",
                        (has_mode && has_own) ? ", " : "", has_own ? "ownership" : ""
                    );
                }

                if (dir_entry->owner || dir_entry->group) {
                    printf(
                        "  %s: %s (mode: %04o, owner: %s:%s)%s\n",
                        verb, filesystem_path, dir_mode,
                        dir_entry->owner ? dir_entry->owner : "?",
                        dir_entry->group ? dir_entry->group : "?", action
                    );
                } else {
                    printf(
                        "  %s: %s (mode: %04o)%s\n",
                        verb, filesystem_path, dir_mode, action
                    );
                }
            }
            continue;
        }

        /* Resolve ownership BEFORE creating directory - SECURITY: enables atomic ownership
         *
         * ARCHITECTURE: Ownership resolution happens upfront so fs_create_dir_with_ownership
         * can atomically apply ownership via fchown() on the directory file descriptor.
         * This eliminates the security window where directories exist with incorrect ownership.
         *
         * Uses unified helper that handles home/, root/, and custom/ cases.
         */
        uid_t target_uid, target_gid;
        err = resolve_deployment_ownership(
            dir_entry->storage_path,  /* Determines home/ vs root/ vs custom/ */
            dir_entry->filesystem_path,
            dir_entry->owner,
            dir_entry->group,
            &target_uid,
            &target_gid,
            opts->strict_ownership,
            opts->dry_run,
            opts->verbose
        );
        if (err) {
            err = error_wrap(
                err, "Failed to resolve ownership for directory: %s",
                dir_entry->storage_path
            );
            goto cleanup;
        }

        /* Create directory with ATOMIC ownership and permissions
         * SECURITY: fs_create_dir_with_ownership uses fchown() and fchmod() on the
         * directory fd, ensuring no security window exists */
        err = fs_create_dir_with_ownership(
            filesystem_path,
            dir_mode,
            target_uid,
            target_gid,
            true  /* create parents */
        );

        if (err) {
            err = error_wrap(
                err, "Failed to create tracked directory: %s",
                filesystem_path
            );
            goto cleanup;
        }

        /* Verbose output - distinguish creation from metadata fix */
        if (opts->verbose) {
            const char *verb = directory_existed ? "Fixed" : "Created";
            bool has_ownership =
                (dir_entry->owner || dir_entry->group) && target_uid != (uid_t) -1;

            /* Build divergence detail from workspace analysis */
            char action[32] = "";
            if (ws_item && directory_existed) {
                bool has_mode = ws_item->divergence & DIVERGENCE_MODE;
                bool has_own = ws_item->divergence & DIVERGENCE_OWNERSHIP;
                snprintf(
                    action, sizeof(action), " [%s%s%s]", has_mode ? "mode" : "",
                    (has_mode && has_own) ? ", " : "", has_own ? "ownership" : ""
                );
            }

            if (has_ownership) {
                printf(
                    "  %s: %s (mode: %04o, owner: %s:%s)%s\n",
                    verb, filesystem_path, dir_mode,
                    dir_entry->owner ? dir_entry->owner : "?",
                    dir_entry->group ? dir_entry->group : "?", action
                );
            } else {
                printf(
                    "  %s: %s (mode: %04o)%s\n",
                    verb, filesystem_path, dir_mode, action
                );
            }
        }
    }

cleanup:
    /* directories array lives in the borrowed arena; the caller's arena
     * (typically ctx->arena) reclaims it at command end. */
    return err;
}

/**
 * Execute deployment
 */
error_t *deploy_execute(
    git_repository *repo,
    const workspace_t *ws,
    const manifest_t *manifest,
    const state_t *state,
    arena_t *arena,
    const deploy_options_t *opts,
    content_cache_t *cache,
    deploy_result_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ws);
    CHECK_NULL(manifest);
    CHECK_NULL(arena);
    CHECK_NULL(opts);
    CHECK_NULL(cache);
    CHECK_NULL(out);

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    deploy_result_t *result = NULL;

    /* Allocate result */
    result = calloc(1, sizeof(deploy_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate deploy result");
    }

    result->deployed = string_array_new(0);
    result->skipped_existing = string_array_new(0);
    result->failed = string_array_new(0);

    if (!result->deployed || !result->skipped_existing || !result->failed) {
        deploy_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate result arrays");
    }

    /* Calculate required directories when ANY scope filter is active
     *
     * Required directories are ancestors of files in the manifest. They must
     * be processed regardless of profile ownership to ensure file deployment.
     *
     * Scope filters:
     * - scope_has_paths (file filter): Strictly process only ancestors
     * - scope_has_filter (profile filter): Process ancestors AND profile-owned dirs
     *
     * When either dimension is active we build the required_dirs hashmap so
     * the per-directory loop can tell "ancestor of a targeted file" apart
     * from "owned by a filtered-out profile". A scope with neither dimension
     * active (i.e. the user passed nothing) behaves like full sync.
     */
    hashmap_t *required_dirs = NULL;
    bool scope_narrows = opts->scope &&
        (scope_has_paths(opts->scope) || scope_has_filter(opts->scope));
    if (scope_narrows && manifest->count > 0 && state) {
        err = calculate_required_directories(manifest, state, arena, &required_dirs);
        if (err) {
            deploy_result_free(result);
            return error_wrap(err, "Failed to calculate required directories");
        }
    }

    /* Deploy tracked directories from state database first */
    err = deploy_tracked_directories(ws, state, arena, opts, required_dirs);
    if (required_dirs) {
        hashmap_free(required_dirs, NULL);
    }
    if (err) {
        deploy_result_free(result);
        return error_wrap(err, "Failed to deploy tracked directories");
    }

    /* Deploy each file */
    if (opts->verbose && manifest->count > 0) {
        printf(
            "Processing %zu file%s for deployment...\n",
            manifest->count, manifest->count == 1 ? "" : "s"
        );
    }

    for (size_t i = 0; i < manifest->count; i++) {
        /* Non-const: deploy_file may lazy-load git tree entry */
        file_entry_t *entry = &manifest->entries[i];

        /* Check --skip-existing first (user explicitly chose not to overwrite) */
        if (opts->skip_existing && fs_exists(entry->filesystem_path) && !opts->force) {
            err = string_array_push(result->skipped_existing, entry->filesystem_path);
            if (err) {
                deploy_result_free(result);
                return error_wrap(err, "Failed to record skipped file");
            }
            continue;
        }

        /* Every entry reaching this loop is divergent by construction:
         * cmd_apply's needs_deployment() filter drops clean entries before
         * building deploy_manifest, so deploy_execute never sees a
         * ws_item == NULL case. Clean in-scope entries with deployed_at == 0
         * are handled by cmd_apply's adoption step, which stamps the
         * lifecycle anchor without invoking deploy_file. */

        /* Deploy the file */
        err = deploy_file(repo, cache, entry, opts);
        if (err) {
            /* Record failure and return partial results.
             * string_array_push failure is non-fatal here (already error-pathing). */
            string_array_push(result->failed, entry->filesystem_path);
            result->error_message = strdup(error_message(err));
            *out = result;
            return error_wrap(
                err, "Deployment failed at '%s'",
                entry->filesystem_path
            );
        }

        /* Record success */
        err = string_array_push(result->deployed, entry->filesystem_path);
        if (err) {
            deploy_result_free(result);
            return error_wrap(err, "Failed to record deployed file");
        }
    }

    /* Success - return results */
    *out = result;
    return NULL;
}

/**
 * Free preflight result
 */
void preflight_result_free(preflight_result_t *result) {
    if (!result) {
        return;
    }

    string_array_free(result->conflicts);
    string_array_free(result->permission_errors);

    /* Free reassignments */
    if (result->reassignments) {
        for (size_t i = 0; i < result->reassignment_count; i++) {
            free(result->reassignments[i].filesystem_path);
            free(result->reassignments[i].old_profile);
            free(result->reassignments[i].new_profile);
        }
        free(result->reassignments);
    }

    free(result);
}

/**
 * Free deployment result
 */
void deploy_result_free(deploy_result_t *result) {
    if (!result) {
        return;
    }

    string_array_free(result->deployed);
    string_array_free(result->skipped_existing);
    string_array_free(result->failed);
    free(result->error_message);
    free(result);
}
