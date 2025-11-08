/**
 * deploy.c - File deployment engine implementation
 */

#include "deploy.h"

#include <errno.h>
#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "core/metadata.h"
#include "core/workspace.h"
#include "infra/content.h"
#include "infra/path.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"
#include "utils/string.h"

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
error_t *deploy_preflight_check_from_workspace(
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
    result->conflicts = string_array_create();
    result->permission_errors = string_array_create();
    result->overlaps = string_array_create();
    result->ownership_changes = NULL;
    result->ownership_change_count = 0;

    if (!result->conflicts || !result->permission_errors || !result->overlaps) {
        preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate result arrays");
    }

    /* CHECK 1: Overlap Detection (Manifest-level)
     * Detect files appearing in multiple profiles. This is a manifest concern,
     * not a divergence concern, so it stays in preflight.
     */
    hashmap_t *seen_paths = hashmap_create(manifest->count);
    if (!seen_paths) {
        preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to create overlap detection map");
    }

    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];
        void *state_val = hashmap_get(seen_paths, entry->filesystem_path);

        if (state_val == NULL) {
            /* First occurrence - mark as seen */
            hashmap_set(seen_paths, entry->filesystem_path, (void *)1);
        } else if (state_val == (void *)1) {
            /* Second occurrence - record as overlap */
            error_t *err = string_array_push(result->overlaps, entry->filesystem_path);
            if (err) {
                hashmap_free(seen_paths, NULL);
                preflight_result_free(result);
                return error_wrap(err, "Failed to record overlap");
            }
            /* Mark as already recorded to avoid duplicates */
            hashmap_set(seen_paths, entry->filesystem_path, (void *)2);
        }
        /* (void *)2 means already recorded - skip */
    }

    hashmap_free(seen_paths, NULL);

    /* CHECK 2: Conflict Detection + Ownership Changes + Writability
     * Query workspace for divergence (O(1) per file), map to preflight decisions.
     */

    /* Pre-allocate ownership_changes array (resize as needed) */
    size_t ownership_capacity = 16;
    result->ownership_changes = calloc(ownership_capacity, sizeof(ownership_change_t));
    if (!result->ownership_changes) {
        preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate ownership changes array");
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
             */
            if (ws_item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE)) {
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

        /* Check for profile ownership changes */
        if (ws_item && ws_item->profile_changed) {
            /* Grow ownership_changes array if needed */
            if (result->ownership_change_count >= ownership_capacity) {
                ownership_capacity *= 2;
                ownership_change_t *new_array = realloc(
                    result->ownership_changes,
                    ownership_capacity * sizeof(ownership_change_t)
                );
                if (!new_array) {
                    preflight_result_free(result);
                    return ERROR(ERR_MEMORY, "Failed to grow ownership changes array");
                }
                result->ownership_changes = new_array;
            }

            /* Add ownership change */
            ownership_change_t *change = &result->ownership_changes[result->ownership_change_count];
            change->filesystem_path = strdup(path);
            change->old_profile = strdup(ws_item->old_profile);
            change->new_profile = strdup(ws_item->profile);

            if (!change->filesystem_path || !change->old_profile || !change->new_profile) {
                /* Cleanup partial allocation */
                free(change->filesystem_path);
                free(change->old_profile);
                free(change->new_profile);
                preflight_result_free(result);
                return ERROR(ERR_MEMORY, "Failed to allocate ownership change strings");
            }

            result->ownership_change_count++;
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

    *out = result;
    return NULL;
}

/**
 * Resolve deployment ownership for a path
 *
 * Unified ownership resolution logic for both files and directories.
 * Handles home/ vs root/ prefix logic and sudo detection.
 *
 * Resolution rules:
 * - home/ prefix when running as root (sudo): Use actual user's UID/GID
 * - root/ prefix with owner/group metadata: Resolve names to UID/GID
 * - All other cases: Return -1 (no ownership change)
 *
 * @param storage_path Path in profile (e.g., "home/.bashrc", "root/etc/nginx.conf")
 * @param owner Owner username from metadata (can be NULL)
 * @param group Group name from metadata (can be NULL)
 * @param out_uid Resolved UID or -1 for no change (must not be NULL)
 * @param out_gid Resolved GID or -1 for no change (must not be NULL)
 * @param verbose Enable verbose warning messages
 * @return Error on fatal failures, NULL on success (non-fatal errors logged and suppressed)
 */
static error_t *resolve_deployment_ownership(
    const char *storage_path,
    const char *owner,
    const char *group,
    uid_t *out_uid,
    gid_t *out_gid,
    bool verbose
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out_uid);
    CHECK_NULL(out_gid);

    /* Initialize to "no change" */
    *out_uid = (uid_t)-1;
    *out_gid = (gid_t)-1;

    /* Determine prefix type */
    bool is_home_prefix = str_starts_with(storage_path, "home/");
    bool is_root_prefix = str_starts_with(storage_path, "root/");

    /* Case 1: home/ prefix when running as root → use actual user (sudo handling) */
    if (is_home_prefix && fs_is_running_as_root()) {
        error_t *err = fs_get_actual_user(out_uid, out_gid);
        if (err) {
            return error_wrap(err,
                "Failed to determine actual user for home/ path: %s", storage_path);
        }
        return NULL;
    }

    /* Case 2: root/ prefix with ownership metadata → resolve to UID/GID */
    if (is_root_prefix && (owner || group)) {
        error_t *err = metadata_resolve_ownership(owner, group, out_uid, out_gid);
        if (err) {
            /* Non-fatal: Log warning and continue with default ownership
             * This allows deployment to proceed even if the user/group doesn't
             * exist on this machine (e.g., deploying admin files as non-root) */
            if (verbose || err->code != ERR_PERMISSION) {
                fprintf(stderr, "Warning: Could not resolve ownership for %s: %s\n",
                        storage_path, error_message(err));
            }
            error_free(err);
            /* Reset to "no change" */
            *out_uid = (uid_t)-1;
            *out_gid = (gid_t)-1;
        }
        return NULL;
    }

    /* Case 3: All other cases → no ownership change */
    return NULL;
}

/**
 * Deploy single file
 */
error_t *deploy_file(
    git_repository *repo,
    content_cache_t *cache,
    const file_entry_t *entry,
    const metadata_t *metadata,
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
    const metadata_item_t *meta_entry = NULL;

    if (opts->dry_run) {
        /* Dry-run mode - just print */
        if (opts->verbose) {
            printf("Would deploy: %s\n", entry->filesystem_path);
        }
        return NULL;
    }

    /* Get file mode from tree entry */
    git_filemode_t mode = git_tree_entry_filemode(entry->entry);
    git_object_t type = git_tree_entry_type(entry->entry);

    if (type != GIT_OBJECT_BLOB) {
        err = ERROR(ERR_INTERNAL,
                    "Unsupported object type for '%s'", entry->storage_path);
        goto cleanup;
    }

    /* Handle symlinks - these are never encrypted, so handle separately */
    if (mode == GIT_FILEMODE_LINK) {
        /* For symlinks, we need to load the blob directly since content layer
         * is designed for regular files with potential encryption */

        /* Parse cached blob_oid */
        git_oid oid;
        if (!entry->blob_oid) {
            err = ERROR(ERR_INTERNAL, "Missing blob_oid for symlink '%s'", entry->storage_path);
            goto cleanup;
        }

        if (git_oid_fromstr(&oid, entry->blob_oid) != 0) {
            err = ERROR(ERR_INTERNAL, "Invalid blob_oid for symlink '%s'", entry->storage_path);
            goto cleanup;
        }

        git_blob *blob = NULL;
        int git_err = git_blob_lookup(&blob, repo, &oid);
        if (git_err < 0) {
            err = error_from_git(git_err);
            goto cleanup;
        }

        const char *target = (const char *)git_blob_rawcontent(blob);
        size_t target_len = git_blob_rawsize(blob);

        /* Null-terminate target */
        target_str = malloc(target_len + 1);
        if (!target_str) {
            git_blob_free(blob);
            err = ERROR(ERR_MEMORY, "Failed to allocate symlink target");
            goto cleanup;
        }
        memcpy(target_str, target, target_len);
        target_str[target_len] = '\0';

        git_blob_free(blob);

        /* Remove existing file/symlink */
        if (fs_exists(entry->filesystem_path)) {
            err = fs_remove_file(entry->filesystem_path);
            if (err) {
                goto cleanup;
            }
        }

        /* Create symlink */
        err = fs_create_symlink(target_str, entry->filesystem_path);
        if (err) {
            err = error_wrap(err, "Failed to deploy symlink '%s'", entry->filesystem_path);
            goto cleanup;
        }

        if (opts->verbose) {
            printf("Deployed symlink: %s\n", entry->filesystem_path);
        }

        /* Success for symlink - goto cleanup will handle freeing */
        err = NULL;
        goto cleanup;
    }

    /* Handle regular files - get content from cache with transparent decryption */
    err = content_cache_get_from_tree_entry(
        cache,
        entry->entry,
        entry->storage_path,
        entry->source_profile ? entry->source_profile->name : "unknown",
        metadata,
        &content_buffer
    );

    if (err) {
        err = error_wrap(err, "Failed to get content for '%s'", entry->storage_path);
        goto cleanup;
    }

    /* Get content pointer and size from buffer */
    const unsigned char *content = buffer_data(content_buffer);
    size_t size = buffer_size(content_buffer);

    /* Determine permissions - use metadata if available, otherwise fallback to git mode */
    mode_t file_mode;
    bool used_metadata = false;

    if (metadata) {
        error_t *meta_err = metadata_get_item(metadata, entry->storage_path, &meta_entry);

        if (meta_err == NULL && meta_entry != NULL) {
            /* Validate this is a file entry (storage_path should only map to files) */
            if (meta_entry->kind != METADATA_ITEM_FILE) {
                /* Metadata corruption - storage_path mapped to directory
                 * Fallback to git mode for safety */
                if (opts->verbose) {
                    fprintf(stderr, "Warning: Metadata corruption for '%s' (expected file, got directory)\n",
                            entry->storage_path);
                }
                meta_entry = NULL;
                file_mode = (mode == GIT_FILEMODE_BLOB_EXECUTABLE) ? 0755 : 0644;
            } else {
                /* Use mode from metadata (common field) */
                file_mode = meta_entry->mode;
                used_metadata = true;
            }
        } else {
            /* Fallback to git mode */
            if (meta_err) {
                error_free(meta_err);
            }
            meta_entry = NULL;  /* Ensure it's NULL if not found */
            file_mode = (mode == GIT_FILEMODE_BLOB_EXECUTABLE) ? 0755 : 0644;
        }
    } else {
        /* No metadata available - use git mode */
        file_mode = (mode == GIT_FILEMODE_BLOB_EXECUTABLE) ? 0755 : 0644;
    }

    /* Resolve ownership for the file based on prefix - RESOLVED BEFORE WRITING
     *
     * SECURITY: Ownership resolution happens BEFORE file creation to enable
     * atomic ownership via fchown() on the file descriptor. This eliminates
     * the security window where files exist with incorrect ownership.
     *
     * Uses unified helper that handles:
     * - home/ files when running as root: Use actual user's UID/GID (sudo handling)
     * - root/ files with metadata: Resolve owner/group → UID/GID
     * - All other cases: Return -1 (preserve current user/root ownership)
     */
    uid_t target_uid, target_gid;
    err = resolve_deployment_ownership(
        entry->storage_path,
        meta_entry ? meta_entry->owner : NULL,
        meta_entry ? meta_entry->group : NULL,
        &target_uid,
        &target_gid,
        opts->verbose
    );
    if (err) {
        err = error_wrap(err, "Failed to resolve ownership for '%s'", entry->filesystem_path);
        goto cleanup;
    }

    /* Write directly from git blob to filesystem with atomic ownership and permissions
     * SECURITY: fs_write_file_raw atomically sets BOTH ownership and permissions via
     * fchown() and fchmod() on the file descriptor, eliminating any security window.
     * This is the ONLY place where ownership is applied - metadata layer only resolves. */
    err = fs_write_file_raw(
        entry->filesystem_path,
        (const unsigned char *)content,
        (size_t)size,
        file_mode,
        target_uid,
        target_gid
    );

    if (err) {
        err = error_wrap(err, "Failed to deploy file '%s'", entry->filesystem_path);
        goto cleanup;
    }

    /* Verbose output */
    if (opts->verbose) {
        bool has_ownership = (meta_entry && (meta_entry->owner || meta_entry->group) &&
                             target_uid != (uid_t)-1);  /* Check if we actually resolved ownership */

        if (used_metadata && has_ownership) {
            printf("Deployed: %s (mode: %04o, owner: %s:%s)\n",
                   entry->filesystem_path, file_mode,
                   meta_entry->owner ? meta_entry->owner : "?",
                   meta_entry->group ? meta_entry->group : "?");
        } else if (used_metadata) {
            printf("Deployed: %s (mode: %04o from metadata)\n", entry->filesystem_path, file_mode);
        } else {
            printf("Deployed: %s (mode: %04o default)\n", entry->filesystem_path, file_mode);
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
 * Deploy tracked directories with metadata
 *
 * Creates all tracked directories with proper permissions and ownership before
 * deploying files. This ensures that directories are created with correct metadata
 * from the start, preventing security issues like world-readable sensitive dirs.
 *
 * @param metadata Merged metadata containing tracked directories (can be NULL)
 * @param opts Deployment options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *deploy_tracked_directories(
    const metadata_t *metadata,
    const deploy_options_t *opts
) {
    if (!metadata) {
        return NULL;  /* No metadata, nothing to do */
    }

    /* Get all tracked directories (filtered by kind) */
    size_t dir_count = 0;
    const metadata_item_t **directories =
        metadata_get_items_by_kind(metadata, METADATA_ITEM_DIRECTORY, &dir_count);

    if (dir_count == 0) {
        return NULL;  /* No tracked directories */
    }

    if (opts->verbose) {
        printf("Creating %zu tracked director%s with metadata...\n",
               dir_count, dir_count == 1 ? "y" : "ies");
    }

    /* Deploy each tracked directory */
    for (size_t i = 0; i < dir_count; i++) {
        const metadata_item_t *dir_entry = directories[i];

        /* For directory items:
         * - key field contains storage_path (e.g., "home/.config/fish")
         * - mode, owner, group are common fields
         * - Filesystem path is derived from storage_path using path_from_storage()
         */

        /* Derive filesystem path from storage path */
        char *filesystem_path = NULL;
        error_t *err = path_from_storage(dir_entry->key, &filesystem_path);
        if (err) {
            return error_wrap(err,
                "Failed to derive filesystem path for directory: %s", dir_entry->key);
        }

        /* Skip if directory already exists and we're not forcing */
        if (fs_is_directory(filesystem_path) && !opts->force) {
            if (opts->verbose) {
                printf("  Skipped: %s (already exists)\n", filesystem_path);
            }
            free(filesystem_path);
            continue;
        }

        /* Dry-run: just print what would happen */
        if (opts->dry_run) {
            if (opts->verbose) {
                if (dir_entry->owner || dir_entry->group) {
                    printf("  Would create: %s (mode: %04o, owner: %s:%s)\n",
                          filesystem_path, dir_entry->mode,
                          dir_entry->owner ? dir_entry->owner : "?",
                          dir_entry->group ? dir_entry->group : "?");
                } else {
                    printf("  Would create: %s (mode: %04o)\n",
                          filesystem_path, dir_entry->mode);
                }
            }
            free(filesystem_path);
            continue;
        }

        /* Resolve ownership BEFORE creating directory - SECURITY: enables atomic ownership
         *
         * ARCHITECTURE: Ownership resolution happens upfront so fs_create_dir_with_ownership
         * can atomically apply ownership via fchown() on the directory file descriptor.
         * This eliminates the security window where directories exist with incorrect ownership.
         *
         * Uses unified helper that handles home/, root/, and default cases.
         */
        uid_t target_uid, target_gid;
        err = resolve_deployment_ownership(
            dir_entry->key,  /* storage_path - determines home/ vs root/ */
            dir_entry->owner,
            dir_entry->group,
            &target_uid,
            &target_gid,
            opts->verbose
        );
        if (err) {
            free(filesystem_path);
            return error_wrap(err,
                "Failed to resolve ownership for directory: %s", dir_entry->key);
        }

        /* Create directory with ATOMIC ownership and permissions
         * SECURITY: fs_create_dir_with_ownership uses fchown() and fchmod() on the
         * directory fd, ensuring no security window exists */
        err = fs_create_dir_with_ownership(
            filesystem_path,
            dir_entry->mode,
            target_uid,
            target_gid,
            true  /* create parents */
        );

        if (err) {
            free(filesystem_path);
            return error_wrap(err, "Failed to create tracked directory: %s",
                            filesystem_path);
        }

        /* Verbose output */
        if (opts->verbose) {
            bool has_ownership = (target_uid != (uid_t)-1 || target_gid != (gid_t)-1);

            if (has_ownership && dir_entry->owner) {
                printf("  Created: %s (mode: %04o, owner: %s:%s)\n",
                      filesystem_path, dir_entry->mode,
                      dir_entry->owner ? dir_entry->owner : "?",
                      dir_entry->group ? dir_entry->group : "?");
            } else if (has_ownership) {
                printf("  Created: %s (mode: %04o, owner: actual user)\n",
                      filesystem_path, dir_entry->mode);
            } else {
                printf("  Created: %s (mode: %04o)\n",
                      filesystem_path, dir_entry->mode);
            }
        }

        free(filesystem_path);
    }

    /* Free the pointer array (items themselves remain in metadata) */
    free(directories);

    return NULL;
}

/**
 * Execute deployment
 */
error_t *deploy_execute(
    git_repository *repo,
    const workspace_t *ws,
    const manifest_t *manifest,
    const metadata_t *metadata,
    const deploy_options_t *opts,
    keymanager_t *km,
    content_cache_t *cache,
    deploy_result_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(ws);
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(cache);
    CHECK_NULL(out);

    /* Note: km parameter provided for API consistency with other core operations.
     * Encryption/decryption is handled via cache->km (set during cache creation).
     * This design keeps the cache as the abstraction boundary while maintaining
     * uniform function signatures across deploy, safety, and cleanup modules. */
    (void)km;  /* Explicitly mark as intentionally unused */

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    deploy_result_t *result = NULL;

    /* Allocate result */
    result = calloc(1, sizeof(deploy_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate deploy result");
    }

    result->deployed = string_array_create();
    result->skipped = string_array_create();
    result->skipped_reasons = string_array_create();
    result->failed = string_array_create();
    result->deployed_count = 0;
    result->skipped_count = 0;
    result->error_message = NULL;

    if (!result->deployed || !result->skipped || !result->skipped_reasons || !result->failed) {
        deploy_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate result arrays");
    }

    /* Deploy tracked directories with metadata first */
    err = deploy_tracked_directories(metadata, opts);
    if (err) {
        deploy_result_free(result);
        return error_wrap(err, "Failed to deploy tracked directories");
    }

    /* Deploy each file */
    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];

        /* Check skip conditions before deploying */
        bool should_skip = false;
        const char *skip_reason = NULL;

        /* Use Case 2: Skip existing files if requested */
        if (opts->skip_existing && fs_exists(entry->filesystem_path) && !opts->force) {
            should_skip = true;
            skip_reason = "exists";
        }

        /* Use Case 1: Smart skip - file already up-to-date
         *
         * Architecture: Query workspace for pre-computed divergence instead of
         * re-analyzing. The workspace already performed full content comparison
         * during workspace_load(), eliminating redundant:
         * - content_cache_get_from_tree_entry() calls (decryption)
         * - compare_buffer_to_disk() operations (filesystem I/O)
         * - Git OID comparisons (workspace already knows)
         *
         * Skip conditions:
         * 1. File is CLEAN (no divergence) → ws_item == NULL
         * 2. File is UNDEPLOYED but exists with matching content → optimization
         *
         * All other divergence types (MODIFIED, MODE_DIFF, OWNERSHIP, DELETED)
         * naturally fall through to deployment, ensuring metadata is always fixed.
         */
        if (!should_skip && opts->skip_unchanged && !opts->force) {
            /* Query workspace for pre-computed divergence (O(1) hashmap lookup) */
            const workspace_item_t *ws_item = workspace_get_item(ws, entry->filesystem_path);

            /* Case 1: The workspace found NO divergence. The file is CLEAN.
             * CLEAN items are not stored in the divergence index, so ws_item is NULL. */
            if (ws_item == NULL) {
                should_skip = true;
                skip_reason = "unchanged";
            }
            /* Case 2 (Optimization): The file is UNDEPLOYED but already exists on disk
             * with the correct content. We can safely skip the initial deployment. */
            else if (ws_item->state == WORKSPACE_STATE_UNDEPLOYED &&
                     ws_item->on_filesystem &&
                     !(ws_item->divergence & DIVERGENCE_CONTENT)) {
                should_skip = true;
                skip_reason = "unchanged";
            }
            /* All other cases (DEPLOYED with divergence, DELETED, etc.) will
             * result in ws_item being non-NULL and the conditions above being false,
             * correctly leading to a deployment. This ensures metadata divergence
             * (mode, ownership) is always fixed by redeploying with correct
             * permissions/ownership atomically. */
        }

        if (should_skip) {
            /* Record skip with reason (parallel arrays) */
            string_array_push(result->skipped, entry->filesystem_path);
            string_array_push(result->skipped_reasons, skip_reason);
            result->skipped_count++;
            if (opts->verbose) {
                printf("Skipped: %s (%s)\n", entry->filesystem_path, skip_reason);
            }
            continue;
        }

        /* Deploy the file */
        err = deploy_file(repo, cache, entry, metadata, opts);
        if (err) {
            /* Record failure and return partial results */
            string_array_push(result->failed, entry->filesystem_path);
            result->error_message = strdup(error_message(err));
            *out = result;
            return ERROR(ERR_INTERNAL, "Deployment failed at '%s'", entry->filesystem_path);
        }

        /* Record success */
        string_array_push(result->deployed, entry->filesystem_path);
        result->deployed_count++;
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
    string_array_free(result->overlaps);

    /* Free ownership changes */
    if (result->ownership_changes) {
        for (size_t i = 0; i < result->ownership_change_count; i++) {
            free(result->ownership_changes[i].filesystem_path);
            free(result->ownership_changes[i].old_profile);
            free(result->ownership_changes[i].new_profile);
        }
        free(result->ownership_changes);
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
    string_array_free(result->skipped);
    string_array_free(result->skipped_reasons);
    string_array_free(result->failed);
    free(result->error_message);
    free(result);
}
