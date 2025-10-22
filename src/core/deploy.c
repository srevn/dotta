/**
 * deploy.c - File deployment engine implementation
 */

#include "deploy.h"

#include <errno.h>
#include <git2.h>
#include <hydrogen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/encryption.h"
#include "base/error.h"
#include "base/filesystem.h"
#include "core/metadata.h"
#include "infra/compare.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"
#include "utils/keymanager.h"
#include "utils/string.h"

/**
 * Run pre-flight checks
 */
error_t *deploy_preflight_check(
    git_repository *repo,
    const manifest_t *manifest,
    const state_t *state,
    const deploy_options_t *opts,
    preflight_result_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    preflight_result_t *result = NULL;
    hashmap_t *seen_paths = NULL;
    state_file_entry_t *state_entries = NULL;
    size_t state_count = 0;
    hashmap_t *state_map = NULL;

    /* Allocate result */
    result = calloc(1, sizeof(preflight_result_t));
    if (!result) {
        err = ERROR(ERR_MEMORY, "Failed to allocate preflight result");
        goto cleanup;
    }

    result->conflicts = string_array_create();
    result->permission_errors = string_array_create();
    result->overlaps = string_array_create();
    result->ownership_changes = NULL;
    result->ownership_change_count = 0;
    result->has_errors = false;

    if (!result->conflicts || !result->permission_errors || !result->overlaps) {
        err = ERROR(ERR_MEMORY, "Failed to allocate result arrays");
        goto cleanup;
    }

    /* Detect overlaps: files that appear in multiple profiles */
    /* Use single hashmap with state tracking: (void*)1 = seen once, (void*)2 = overlap recorded */
    seen_paths = hashmap_create(manifest->count);
    if (!seen_paths) {
        err = ERROR(ERR_MEMORY, "Failed to create hashmap for overlap detection");
        goto cleanup;
    }

    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];

        /* Check occurrence state */
        void *state_val = hashmap_get(seen_paths, entry->filesystem_path);

        if (state_val == NULL) {
            /* First occurrence - mark as seen */
            err = hashmap_set(seen_paths, entry->filesystem_path, (void *)1);
            if (err) {
                err = error_wrap(err, "Failed to track path in overlap detection");
                goto cleanup;
            }
        } else if (state_val == (void *)1) {
            /* Second occurrence - this is an overlap, record it */
            string_array_push(result->overlaps, entry->filesystem_path);
            err = hashmap_set(seen_paths, entry->filesystem_path, (void *)2);
            if (err) {
                err = error_wrap(err, "Failed to record overlap");
                goto cleanup;
            }
        }
        /* else: state_val == (void*)2, already recorded as overlap, skip */
    }

    /* Done with seen_paths, free it now */
    hashmap_free(seen_paths, NULL);
    seen_paths = NULL;

    /* Detect ownership changes: files deployed from one profile, now being deployed from another */
    if (state) {
        /* Load all state entries once for O(1) lookups instead of O(N) database queries */
        err = state_get_all_files(state, &state_entries, &state_count);
        if (err) {
            err = error_wrap(err, "Failed to load state for ownership detection");
            goto cleanup;
        }

        /* Build hashmap for O(1) lookups */
        state_map = hashmap_create(state_count > 0 ? state_count : 16);
        if (!state_map) {
            err = ERROR(ERR_MEMORY, "Failed to create state lookup map");
            goto cleanup;
        }

        for (size_t i = 0; i < state_count; i++) {
            err = hashmap_set(state_map, state_entries[i].filesystem_path, &state_entries[i]);
            if (err) {
                err = error_wrap(err, "Failed to populate state lookup map");
                goto cleanup;
            }
        }

        /* Allocate ownership changes array */
        size_t ownership_change_capacity = 16;
        result->ownership_changes = calloc(ownership_change_capacity, sizeof(ownership_change_t));
        if (!result->ownership_changes) {
            err = ERROR(ERR_MEMORY, "Failed to allocate ownership changes array");
            goto cleanup;
        }

        /* Detect ownership changes using hashmap lookups (O(1) per file) */
        for (size_t i = 0; i < manifest->count; i++) {
            const file_entry_t *entry = &manifest->entries[i];

            /* Check if file exists in state (O(1) lookup) */
            state_file_entry_t *state_entry = hashmap_get(state_map, entry->filesystem_path);

            if (state_entry) {
                /* Check if profile is changing */
                if (strcmp(state_entry->profile, entry->source_profile->name) != 0) {
                    /* Ownership is changing - add to list */
                    if (result->ownership_change_count >= ownership_change_capacity) {
                        ownership_change_capacity *= 2;
                        ownership_change_t *new_changes = realloc(result->ownership_changes,
                                                                  ownership_change_capacity * sizeof(ownership_change_t));
                        if (!new_changes) {
                            err = ERROR(ERR_MEMORY, "Failed to grow ownership changes array");
                            goto cleanup;
                        }
                        result->ownership_changes = new_changes;
                    }

                    ownership_change_t *change = &result->ownership_changes[result->ownership_change_count];

                    /* Allocate all strings first, so we can clean them up properly on error */
                    char *fs_path = strdup(entry->filesystem_path);
                    char *old_prof = strdup(state_entry->profile);
                    char *new_prof = strdup(entry->source_profile->name);

                    if (!fs_path || !old_prof || !new_prof) {
                        /* Clean up partial allocations before goto cleanup */
                        free(fs_path);
                        free(old_prof);
                        free(new_prof);
                        err = ERROR(ERR_MEMORY, "Failed to allocate ownership change entry");
                        goto cleanup;
                    }

                    /* All allocations succeeded - assign and increment count */
                    change->filesystem_path = fs_path;
                    change->old_profile = old_prof;
                    change->new_profile = new_prof;
                    result->ownership_change_count++;
                }
            }
        }

        /* Clean up state cache - done with it */
        hashmap_free(state_map, NULL);
        state_map = NULL;
        state_free_all_files(state_entries, state_count);
        state_entries = NULL;
    }

    /* Check each file */
    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];

        /* Check if file exists and is modified */
        if (fs_exists(entry->filesystem_path)) {
            /* Compare with git */
            compare_result_t cmp_result;
            err = compare_tree_entry_to_disk(
                repo,
                entry->entry,
                entry->filesystem_path,
                &cmp_result
            );

            if (err) {
                err = error_wrap(err, "Failed to compare '%s'", entry->filesystem_path);
                goto cleanup;
            }

            /* If different and not forcing, it's a conflict */
            if ((cmp_result == CMP_DIFFERENT || cmp_result == CMP_MODE_DIFF || cmp_result == CMP_TYPE_DIFF) && !opts->force) {
                string_array_push(result->conflicts, entry->filesystem_path);
                result->has_errors = true;
            }
        }

        /* Check if path is writable */
        if (!fs_is_writable(entry->filesystem_path)) {
            string_array_push(result->permission_errors, entry->filesystem_path);
            result->has_errors = true;
        }
    }

    /* Success - set output and prevent cleanup from freeing result */
    *out = result;
    result = NULL;
    err = NULL;

cleanup:
    /* Free resources in reverse order of allocation */
    if (state_map) hashmap_free(state_map, NULL);
    if (state_entries) state_free_all_files(state_entries, state_count);
    if (seen_paths) hashmap_free(seen_paths, NULL);
    if (result) preflight_result_free(result);

    return err;
}

/**
 * Deploy single file
 */
error_t *deploy_file(
    git_repository *repo,
    const file_entry_t *entry,
    const metadata_t *metadata,
    const deploy_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(entry);
    CHECK_NULL(opts);

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    git_blob *blob = NULL;
    char *target_str = NULL;
    buffer_t *decrypted_buffer = NULL;
    const metadata_entry_t *meta_entry = NULL;

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

    /* Get blob */
    const git_oid *oid = git_tree_entry_id(entry->entry);
    int git_err = git_blob_lookup(&blob, repo, oid);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Handle symlinks */
    if (mode == GIT_FILEMODE_LINK) {
        const char *target = (const char *)git_blob_rawcontent(blob);
        size_t target_len = git_blob_rawsize(blob);

        /* Null-terminate target */
        target_str = malloc(target_len + 1);
        if (!target_str) {
            err = ERROR(ERR_MEMORY, "Failed to allocate symlink target");
            goto cleanup;
        }
        memcpy(target_str, target, target_len);
        target_str[target_len] = '\0';

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

    /* Handle regular files */
    const void *content = git_blob_rawcontent(blob);
    git_object_size_t size = git_blob_rawsize(blob);

    /* Determine permissions - use metadata if available, otherwise fallback to git mode */
    mode_t file_mode;
    bool used_metadata = false;

    if (metadata) {
        error_t *meta_err = metadata_get_entry(metadata, entry->storage_path, &meta_entry);

        if (meta_err == NULL && meta_entry != NULL) {
            /* Use mode from metadata */
            file_mode = meta_entry->mode;
            used_metadata = true;
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

    /* =====================================================================
     * DECRYPTION: If file is encrypted in metadata, decrypt before deployment
     * ===================================================================== */
    if (meta_entry && meta_entry->encrypted) {
        /* Verify file is actually encrypted */
        if (!encryption_is_encrypted((const unsigned char *)content, (size_t)size)) {
            err = ERROR(ERR_STATE_INVALID,
                        "Metadata indicates file is encrypted, but content is not encrypted: %s",
                        entry->storage_path);
            goto cleanup;
        }

        /* Get global keymanager */
        keymanager_t *key_mgr = keymanager_get_global(NULL);
        if (!key_mgr) {
            err = ERROR(ERR_INTERNAL, "Failed to get global keymanager");
            goto cleanup;
        }

        /* Get master key (may prompt user for passphrase) */
        uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE];
        err = keymanager_get_key(key_mgr, master_key);
        if (err) {
            err = error_wrap(err, "Failed to get encryption key for: %s", entry->storage_path);
            goto cleanup;
        }

        /* Derive profile-specific key */
        uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];

        /* CRITICAL: source_profile must not be NULL for encrypted files
         * Using a fallback like "unknown" would violate per-profile key isolation
         * and cause decryption failures or incorrect key derivation */
        if (!entry->source_profile || !entry->source_profile->name) {
            err = ERROR(ERR_INTERNAL, "Cannot decrypt %s: source profile is NULL (this is a bug)",
                        entry->storage_path);
            goto cleanup;
        }

        const char *profile_name = entry->source_profile->name;
        err = encryption_derive_profile_key(master_key, profile_name, profile_key);

        /* Clear master key immediately after derivation */
        hydro_memzero(master_key, sizeof(master_key));

        if (err) {
            err = error_wrap(err, "Failed to derive profile key for: %s", entry->storage_path);
            goto cleanup;
        }

        /* Decrypt content */
        err = encryption_decrypt(
            (const unsigned char *)content,
            (size_t)size,
            profile_key,
            &decrypted_buffer
        );

        /* Clear sensitive key material immediately */
        hydro_memzero(profile_key, sizeof(profile_key));

        if (err) {
            err = error_wrap(err, "Failed to decrypt %s (wrong passphrase or corrupted file?)",
                            entry->storage_path);
            goto cleanup;
        }

        /* Update content pointer and size to use decrypted data */
        content = buffer_data(decrypted_buffer);
        size = buffer_size(decrypted_buffer);

        if (opts->verbose) {
            printf("Decrypted: %s\n", entry->storage_path);
        }
    }

    /* Determine ownership for the file based on prefix
     *
     * For home/ files when running as root: Use actual user's UID/GID
     * For root/ files: Use -1 (preserve root ownership)
     * When not running as root: Use -1 (preserve current user)
     */
    uid_t target_uid = -1;
    gid_t target_gid = -1;

    bool is_home_prefix = str_starts_with(entry->storage_path, "home/");

    if (is_home_prefix && fs_is_running_as_root()) {
        /* Running as root, deploying home/ file - use actual user's credentials */
        err = fs_get_actual_user(&target_uid, &target_gid);
        if (err) {
            err = error_wrap(err,
                            "Failed to determine actual user for home/ file: %s",
                            entry->filesystem_path);
            goto cleanup;
        }
    }
    /* For root/ files or when not running as root: leave uid/gid as -1 (no change) */

    /* Write directly from git blob to filesystem with atomic permission setting
     * SECURITY: fs_write_file_raw now sets permissions atomically via fchmod(),
     * eliminating the window where the file has incorrect permissions */
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

    /* Apply ownership ONLY for root/ prefix files */
    bool is_root_prefix = str_starts_with(entry->storage_path, "root/");
    bool has_ownership = false;

    if (is_root_prefix && metadata && meta_entry && (meta_entry->owner || meta_entry->group)) {
        error_t *ownership_err = metadata_apply_ownership(meta_entry, entry->filesystem_path);
        if (ownership_err) {
            /* Non-fatal: warn and continue */
            if (opts->verbose || ownership_err->code != ERR_PERMISSION) {
                fprintf(stderr, "Warning: Could not set ownership on %s: %s\n",
                        entry->filesystem_path, error_message(ownership_err));
            }
            error_free(ownership_err);
        } else {
            has_ownership = true;
        }
    }

    if (opts->verbose) {
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
    if (decrypted_buffer) buffer_free(decrypted_buffer);
    if (target_str) free(target_str);
    if (blob) git_blob_free(blob);

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

    /* Get all tracked directories */
    size_t dir_count = 0;
    const metadata_directory_entry_t *directories =
        metadata_get_all_tracked_directories(metadata, &dir_count);

    if (dir_count == 0) {
        return NULL;  /* No tracked directories */
    }

    if (opts->verbose) {
        printf("Creating %zu tracked director%s with metadata...\n",
               dir_count, dir_count == 1 ? "y" : "ies");
    }

    /* Deploy each tracked directory */
    for (size_t i = 0; i < dir_count; i++) {
        const metadata_directory_entry_t *dir_entry = &directories[i];

        /* Skip if directory already exists and we're not forcing */
        if (fs_is_directory(dir_entry->filesystem_path) && !opts->force) {
            if (opts->verbose) {
                printf("  Skipped: %s (already exists)\n", dir_entry->filesystem_path);
            }
            continue;
        }

        /* Dry-run: just print what would happen */
        if (opts->dry_run) {
            if (opts->verbose) {
                if (dir_entry->owner || dir_entry->group) {
                    printf("  Would create: %s (mode: %04o, owner: %s:%s)\n",
                          dir_entry->filesystem_path, dir_entry->mode,
                          dir_entry->owner ? dir_entry->owner : "?",
                          dir_entry->group ? dir_entry->group : "?");
                } else {
                    printf("  Would create: %s (mode: %04o)\n",
                          dir_entry->filesystem_path, dir_entry->mode);
                }
            }
            continue;
        }

        /* Create directory with proper mode */
        error_t *err = fs_create_dir_with_mode(
            dir_entry->filesystem_path,
            dir_entry->mode,
            true  /* create parents */
        );

        if (err) {
            return error_wrap(err, "Failed to create tracked directory: %s",
                            dir_entry->filesystem_path);
        }

        /* Apply ownership based on prefix and sudo status */
        bool is_root_prefix = str_starts_with(dir_entry->storage_prefix, "root/");
        bool is_home_prefix = str_starts_with(dir_entry->storage_prefix, "home/");

        if (is_root_prefix && dir_entry->owner && dir_entry->group) {
            /* For root/ prefix: apply ownership from metadata */
            err = metadata_apply_directory_ownership(dir_entry, dir_entry->filesystem_path);
            if (err) {
                /* Non-fatal: warn and continue */
                if (opts->verbose || err->code != ERR_PERMISSION) {
                    fprintf(stderr, "Warning: Could not set directory ownership on %s: %s\n",
                            dir_entry->filesystem_path, error_message(err));
                }
                error_free(err);
            }
        } else if (is_home_prefix && fs_is_running_as_root()) {
            /* For home/ prefix when running as root: use actual user (sudo handling) */
            uid_t target_uid;
            gid_t target_gid;

            err = fs_get_actual_user(&target_uid, &target_gid);
            if (err) {
                return error_wrap(err,
                                "Failed to determine actual user for home/ directory: %s",
                                dir_entry->filesystem_path);
            }

            /* Apply ownership */
            if (chown(dir_entry->filesystem_path, target_uid, target_gid) != 0) {
                return ERROR(ERR_FS,
                            "Failed to set directory ownership on %s: %s",
                            dir_entry->filesystem_path, strerror(errno));
            }

            if (opts->verbose) {
                printf("  Created: %s (mode: %04o, owner: actual user)\n",
                      dir_entry->filesystem_path, dir_entry->mode);
            }
        } else {
            /* Normal case: directory created with current user ownership */
            if (opts->verbose) {
                printf("  Created: %s (mode: %04o)\n",
                      dir_entry->filesystem_path, dir_entry->mode);
            }
        }
    }

    return NULL;
}

/**
 * Execute deployment
 */
error_t *deploy_execute(
    git_repository *repo,
    const manifest_t *manifest,
    const state_t *state,
    const metadata_t *metadata,
    const deploy_options_t *opts,
    deploy_result_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    deploy_result_t *result = NULL;
    hashmap_t *state_map = NULL;
    state_file_entry_t *state_entries = NULL;
    size_t state_count = 0;

    /* Allocate result */
    result = calloc(1, sizeof(deploy_result_t));
    if (!result) {
        err = ERROR(ERR_MEMORY, "Failed to allocate deploy result");
        goto cleanup;
    }

    result->deployed = string_array_create();
    result->skipped = string_array_create();
    result->failed = string_array_create();
    result->deployed_count = 0;
    result->skipped_count = 0;
    result->error_message = NULL;

    if (!result->deployed || !result->skipped || !result->failed) {
        err = ERROR(ERR_MEMORY, "Failed to allocate result arrays");
        goto cleanup;
    }

    /* Deploy tracked directories with metadata first */
    err = deploy_tracked_directories(metadata, opts);
    if (err) {
        err = error_wrap(err, "Failed to deploy tracked directories");
        goto cleanup;
    }

    /* Load state entries once for O(1) lookups during smart skip (avoid O(N) database queries) */
    if (state && opts->skip_unchanged) {
        err = state_get_all_files(state, &state_entries, &state_count);
        if (err) {
            err = error_wrap(err, "Failed to load state for smart skip");
            goto cleanup;
        }

        /* Build hashmap for O(1) lookups */
        state_map = hashmap_create(state_count > 0 ? state_count : 16);
        if (!state_map) {
            err = ERROR(ERR_MEMORY, "Failed to create state lookup map");
            goto cleanup;
        }

        for (size_t i = 0; i < state_count; i++) {
            err = hashmap_set(state_map, state_entries[i].filesystem_path, &state_entries[i]);
            if (err) {
                err = error_wrap(err, "Failed to populate state lookup map");
                goto cleanup;
            }
        }
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

        /* Use Case 1: Smart skip - file already up-to-date AND tracked in state */
        if (!should_skip && opts->skip_unchanged && fs_exists(entry->filesystem_path)) {
            /* Check if file is tracked in state - only skip if it is (O(1) lookup) */
            state_file_entry_t *state_entry = NULL;
            if (state_map) {
                state_entry = hashmap_get(state_map, entry->filesystem_path);
            }

            if (state_entry) {
                /* File is tracked in state - check if we can skip deployment
                 *
                 * Optimization: Use git blob OID hash comparison to avoid expensive
                 * filesystem comparisons when the profile version changed.
                 *
                 * Two cases:
                 * 1. Profile changed (git OID differs from state)
                 *    → Must deploy, skip filesystem comparison
                 * 2. Profile unchanged (git OID matches state)
                 *    → Still need to verify user didn't modify file (safe comparison)
                 */

                /* Get git blob OID from manifest entry */
                const git_oid *manifest_oid = git_tree_entry_id(entry->entry);
                char manifest_oid_str[GIT_OID_SHA1_HEXSIZE + 1];
                git_oid_tostr(manifest_oid_str, sizeof(manifest_oid_str), manifest_oid);

                /* Compare with state hash to detect profile changes */
                bool profile_version_changed = true;
                if (state_entry->hash) {
                    profile_version_changed = (strcmp(state_entry->hash, manifest_oid_str) != 0);
                }

                if (profile_version_changed) {
                    /* Profile version changed since last deployment
                     * → File MUST be deployed, no need for expensive filesystem comparison
                     * This is the fast path that avoids syscalls when profiles are updated */
                    should_skip = false;
                } else {
                    /* Profile version unchanged - but user might have modified the file locally
                     * → Do full content comparison to verify (safe, reliable)
                     * This catches user modifications while maintaining correctness */
                    compare_result_t cmp_result;
                    error_t *cmp_err = compare_tree_entry_to_disk(
                        repo,
                        entry->entry,
                        entry->filesystem_path,
                        &cmp_result
                    );

                    if (!cmp_err && cmp_result == CMP_EQUAL) {
                        should_skip = true;
                        skip_reason = "unchanged";
                    }
                    error_free(cmp_err); /* Ignore comparison errors, proceed with deployment */
                }
            }
        }

        if (should_skip) {
            /* Record skip */
            string_array_push(result->skipped, entry->filesystem_path);
            result->skipped_count++;
            if (opts->verbose) {
                printf("Skipped: %s (%s)\n", entry->filesystem_path, skip_reason);
            }
            continue;
        }

        /* Deploy the file */
        err = deploy_file(repo, entry, metadata, opts);
        if (err) {
            /* Record failure */
            string_array_push(result->failed, entry->filesystem_path);
            result->error_message = strdup(error_message(err));

            /* Fail-stop: set output and goto cleanup */
            *out = result;
            result = NULL;  /* Prevent cleanup from freeing result */

            err = ERROR(ERR_INTERNAL, "Deployment failed at '%s'", entry->filesystem_path);
            goto cleanup;
        }

        /* Record success */
        string_array_push(result->deployed, entry->filesystem_path);
        result->deployed_count++;
    }

    /* Success - set output and prevent cleanup from freeing result */
    *out = result;
    result = NULL;
    err = NULL;

cleanup:
    /* Free resources in reverse order of allocation */
    if (state_map) hashmap_free(state_map, NULL);
    if (state_entries) state_free_all_files(state_entries, state_count);
    if (result) deploy_result_free(result);

    return err;
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
    string_array_free(result->failed);
    free(result->error_message);
    free(result);
}
