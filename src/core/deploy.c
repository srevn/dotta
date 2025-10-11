/**
 * deploy.c - File deployment engine implementation
 */

#include "deploy.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "infra/compare.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"

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

    /* Suppress unused parameter warning (state used for future conflict detection) */
    (void)state;

    /* Allocate result */
    preflight_result_t *result = calloc(1, sizeof(preflight_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate preflight result");
    }

    result->conflicts = string_array_create();
    result->permission_errors = string_array_create();
    result->overlaps = string_array_create();
    result->has_errors = false;

    if (!result->conflicts || !result->permission_errors || !result->overlaps) {
        preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate result arrays");
    }

    /* Detect overlaps: files that appear in multiple profiles */
    /* Use two hashmaps for O(N) complexity instead of O(N*M) */
    hashmap_t *seen_paths = hashmap_create(manifest->count);
    hashmap_t *recorded_overlaps = hashmap_create(manifest->count);
    if (!seen_paths || !recorded_overlaps) {
        hashmap_free(seen_paths, NULL);
        hashmap_free(recorded_overlaps, NULL);
        preflight_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to create hashmap for overlap detection");
    }

    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];

        /* Check if we've seen this path before */
        if (hashmap_has(seen_paths, entry->filesystem_path)) {
            /* This path appears in multiple profiles */
            /* Check if we've already recorded it in overlaps array (O(1) lookup) */
            if (!hashmap_has(recorded_overlaps, entry->filesystem_path)) {
                string_array_push(result->overlaps, entry->filesystem_path);
                error_t *err = hashmap_set(recorded_overlaps, entry->filesystem_path, (void *)1);
                if (err) {
                    hashmap_free(seen_paths, NULL);
                    hashmap_free(recorded_overlaps, NULL);
                    preflight_result_free(result);
                    return error_wrap(err, "Failed to track recorded overlap");
                }
            }
        } else {
            /* First time seeing this path - record it */
            error_t *err = hashmap_set(seen_paths, entry->filesystem_path, (void *)1);
            if (err) {
                hashmap_free(seen_paths, NULL);
                hashmap_free(recorded_overlaps, NULL);
                preflight_result_free(result);
                return error_wrap(err, "Failed to track path in overlap detection");
            }
        }
    }

    hashmap_free(seen_paths, NULL);
    hashmap_free(recorded_overlaps, NULL);

    /* Check each file */
    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];

        /* Check if file exists and is modified */
        if (fs_exists(entry->filesystem_path)) {
            /* Compare with git */
            compare_result_t cmp_result;
            error_t *err = compare_tree_entry_to_disk(
                repo,
                entry->entry,
                entry->filesystem_path,
                &cmp_result
            );

            if (err) {
                preflight_result_free(result);
                return error_wrap(err, "Failed to compare '%s'", entry->filesystem_path);
            }

            /* If different and not forcing, it's a conflict */
            if ((cmp_result == CMP_DIFFERENT || cmp_result == CMP_MODE_DIFF) && !opts->force) {
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

    *out = result;
    return NULL;
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
        return ERROR(ERR_INTERNAL,
                    "Unsupported object type for '%s'", entry->storage_path);
    }

    /* Get blob */
    const git_oid *oid = git_tree_entry_id(entry->entry);
    git_blob *blob = NULL;
    int err = git_blob_lookup(&blob, repo, oid);
    if (err < 0) {
        return error_from_git(err);
    }

    /* Handle symlinks */
    if (mode == GIT_FILEMODE_LINK) {
        const char *target = (const char *)git_blob_rawcontent(blob);
        size_t target_len = git_blob_rawsize(blob);

        /* Null-terminate target */
        char *target_str = malloc(target_len + 1);
        if (!target_str) {
            git_blob_free(blob);
            return ERROR(ERR_MEMORY, "Failed to allocate symlink target");
        }
        memcpy(target_str, target, target_len);
        target_str[target_len] = '\0';

        /* Remove existing file/symlink */
        if (fs_exists(entry->filesystem_path)) {
            error_t *derr = fs_remove_file(entry->filesystem_path);
            if (derr) {
                free(target_str);
                git_blob_free(blob);
                return derr;
            }
        }

        /* Create symlink */
        error_t *derr = fs_create_symlink(target_str, entry->filesystem_path);
        free(target_str);
        git_blob_free(blob);

        if (derr) {
            return error_wrap(derr, "Failed to deploy symlink '%s'", entry->filesystem_path);
        }

        if (opts->verbose) {
            printf("Deployed symlink: %s\n", entry->filesystem_path);
        }
        return NULL;
    }

    /* Handle regular files */
    const void *content = git_blob_rawcontent(blob);
    git_object_size_t size = git_blob_rawsize(blob);

    /* Create buffer */
    buffer_t *buf = buffer_create_from_data((const unsigned char *)content, size);
    if (!buf) {
        git_blob_free(blob);
        return ERROR(ERR_MEMORY, "Failed to create buffer for '%s'", entry->filesystem_path);
    }

    /* Write file */
    error_t *derr = fs_write_file(entry->filesystem_path, buf);
    buffer_free(buf);
    git_blob_free(blob);

    if (derr) {
        return error_wrap(derr, "Failed to deploy file '%s'", entry->filesystem_path);
    }

    /* Set permissions - use metadata if available, otherwise fallback to git mode */
    mode_t file_mode;
    bool used_metadata = false;

    if (metadata) {
        const metadata_entry_t *meta_entry = NULL;
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
            file_mode = (mode == GIT_FILEMODE_BLOB_EXECUTABLE) ? 0755 : 0644;
        }
    } else {
        /* No metadata available - use git mode */
        file_mode = (mode == GIT_FILEMODE_BLOB_EXECUTABLE) ? 0755 : 0644;
    }

    derr = fs_set_permissions(entry->filesystem_path, file_mode);
    if (derr) {
        return error_wrap(derr, "Failed to set permissions on '%s'", entry->filesystem_path);
    }

    if (opts->verbose) {
        if (used_metadata) {
            printf("Deployed: %s (mode: %04o from metadata)\n", entry->filesystem_path, file_mode);
        } else {
            printf("Deployed: %s (mode: %04o default)\n", entry->filesystem_path, file_mode);
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
    const metadata_t *metadata,
    const deploy_options_t *opts,
    deploy_result_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Allocate result */
    deploy_result_t *result = calloc(1, sizeof(deploy_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate deploy result");
    }

    result->deployed = string_array_create();
    result->skipped = string_array_create();
    result->failed = string_array_create();
    result->deployed_count = 0;
    result->skipped_count = 0;
    result->error_message = NULL;

    if (!result->deployed || !result->skipped || !result->failed) {
        deploy_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate result arrays");
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

        /* Use Case 1: Smart skip - file already up-to-date */
        if (!should_skip && opts->skip_unchanged && fs_exists(entry->filesystem_path)) {
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
        error_t *err = deploy_file(repo, entry, metadata, opts);
        if (err) {
            /* Record failure */
            string_array_push(result->failed, entry->filesystem_path);
            result->error_message = strdup(error_message(err));
            error_free(err);

            /* Fail-stop: don't continue deployment */
            *out = result;
            return ERROR(ERR_INTERNAL,
                        "Deployment failed at '%s'", entry->filesystem_path);
        }

        /* Record success */
        string_array_push(result->deployed, entry->filesystem_path);
        result->deployed_count++;
    }

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
