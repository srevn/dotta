/**
 * add.c - Add files to profiles
 */

#include "add.h"

#include <dirent.h>
#include <errno.h>
#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/state.h"
#include "crypto/keymanager.h"
#include "crypto/policy.h"
#include "infra/content.h"
#include "infra/path.h"
#include "infra/worktree.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/hooks.h"
#include "utils/output.h"
#include "utils/privilege.h"
#include "utils/string.h"

/**
 * Validate command options
 */
static error_t *validate_options(const cmd_add_options_t *opts) {
    CHECK_NULL(opts);

    if (!opts->profile || opts->profile[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name is required");
    }

    if (!opts->files || opts->file_count == 0) {
        return ERROR(ERR_INVALID_ARG, "At least one file is required");
    }

    return NULL;
}

/**
 * Check if path should be ignored using the ignore context
 *
 * Uses the multi-layered ignore system with full precedence logic.
 */
static bool is_excluded(
    const char *path,
    bool is_directory,
    ignore_context_t *ignore_ctx,
    const cmd_add_options_t *opts,
    output_ctx_t *out
) {
    if (!path) {
        return false;
    }

    /* If we have an ignore context, use it */
    if (ignore_ctx) {
        bool ignored = false;
        error_t *err = ignore_should_ignore(ignore_ctx, path, is_directory, &ignored);
        if (err) {
            /* On error, log and continue without ignoring */
            if (opts->verbose && out) {
                output_warning(out,
                    "Ignore check failed for %s: %s", path, error_message(err));
            }
            error_free(err);
            return false;
        }
        return ignored;
    }

    return false;
}

/**
 * Recursively collect files from directory
 *
 * Walks directory tree and collects all file paths, respecting ignore patterns.
 * All files including hidden files (dotfiles) are included by default.
 * Use ignore patterns to exclude specific files.
 */
static error_t *collect_files_from_dir(
    const char *dir_path,
    const cmd_add_options_t *opts,
    ignore_context_t *ignore_ctx,
    output_ctx_t *out,
    string_array_t **out_files
) {
    CHECK_NULL(dir_path);
    CHECK_NULL(opts);
    CHECK_NULL(out_files);

    DIR *dir = opendir(dir_path);
    if (!dir) {
        return ERROR(ERR_FS, "Failed to open directory: %s", dir_path);
    }

    string_array_t *files = string_array_create();
    if (!files) {
        closedir(dir);
        return ERROR(ERR_MEMORY, "Failed to allocate file list");
    }

    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            errno = 0;  /* Clear before next readdir() — see post-loop check */
            continue;
        }

        /* Build full path */
        char *full_path = str_format("%s/%s", dir_path, entry->d_name);
        if (!full_path) {
            string_array_free(files);
            closedir(dir);
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }

        /* Determine entry type */
        bool is_symlink = fs_is_symlink(full_path);
        bool is_dir = !is_symlink && fs_is_directory(full_path);

        /* Check exclude patterns */
        if (is_excluded(full_path, is_dir, ignore_ctx, opts, out)) {
            if (opts->verbose && out) {
                output_info(out, "Excluded: %s", full_path);
            }
            free(full_path);
            errno = 0;
            continue;
        }

        /* Handle directories vs files */
        if (is_dir) {
            /* Recurse into subdirectory */
            string_array_t *subdir_files = NULL;
            error_t *err = collect_files_from_dir(full_path, opts, ignore_ctx, out, &subdir_files);
            free(full_path);

            if (err) {
                string_array_free(files);
                closedir(dir);
                return err;
            }

            /* Merge subdirectory files */
            for (size_t i = 0; i < string_array_size(subdir_files); i++) {
                err = string_array_push(files, string_array_get(subdir_files, i));
                if (err) {
                    string_array_free(subdir_files);
                    string_array_free(files);
                    closedir(dir);
                    return err;
                }
            }
            string_array_free(subdir_files);
        } else {
            /* Add file to list */
            error_t *push_err = string_array_push(files, full_path);
            free(full_path);
            if (push_err) {
                string_array_free(files);
                closedir(dir);
                return push_err;
            }
        }
        errno = 0;
    }

    /* readdir() returns NULL on both end-of-directory and error.
     * With errno cleared before each call, non-zero errno means I/O error. */
    if (errno != 0) {
        int saved_errno = errno;
        closedir(dir);
        string_array_free(files);
        return ERROR(ERR_FS,
            "Error reading directory '%s': %s", dir_path, strerror(saved_errno));
    }

    closedir(dir);
    *out_files = files;
    return NULL;
}

/**
 * Add single file to worktree and capture metadata
 *
 * Handles file storage, encryption, and metadata capture in a single operation.
 * Uses stat data from content layer to eliminate race conditions.
 *
 * @param wt Worktree handle
 * @param filesystem_path Source path on filesystem
 * @param storage_path Pre-computed storage path (e.g., "home/.bashrc")
 * @param opts Command options
 * @param km Key manager (for encryption, can be NULL if encryption disabled)
 * @param config Configuration (for auto-encrypt patterns only, can be NULL)
 * @param metadata Metadata collection (captured entry will be added here)
 * @param out Output context
 * @return Error or NULL on success
 */
static error_t *add_file_to_worktree(
    worktree_handle_t *wt,
    const char *filesystem_path,
    const char *storage_path,
    const cmd_add_options_t *opts,
    keymanager_t *km,
    const dotta_config_t *config,
    metadata_t *metadata,
    output_ctx_t *out
) {
    CHECK_NULL(wt);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(opts);
    CHECK_NULL(metadata);

    error_t *err = NULL;
    metadata_item_t *item = NULL;  /* Will be created from captured metadata */
    struct stat file_stat;         /* Captured from content layer */

    /* Build destination path in worktree */
    const char *wt_path = worktree_get_path(wt);
    char *dest_path = str_format("%s/%s", wt_path, storage_path);
    if (!dest_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate destination path");
    }

    /* Handle existing files */
    if (fs_lexists(dest_path)) {
        if (!opts->force) {
            error_t *exists_err = ERROR(ERR_EXISTS,
                "File '%s' (as '%s') already exists in profile '%s'. "
                "Use --force to overwrite.", filesystem_path, storage_path, opts->profile);
            free(dest_path);
            return exists_err;
        }
        err = fs_remove_file(dest_path);
        if (err) {
            error_t *wrapped = error_wrap(err,
                "Failed to remove existing file '%s' in worktree", dest_path);
            free(dest_path);
            return wrapped;
        }
    }

    /* Create parent directory */
    char *parent = NULL;
    err = fs_get_parent_dir(dest_path, &parent);
    if (err) {
        free(dest_path);
        return err;
    }

    err = fs_create_dir(parent, true);
    free(parent);
    if (err) {
        free(dest_path);
        return error_wrap(err, "Failed to create parent directory");
    }

    /* Copy file to worktree */
    if (fs_is_symlink(filesystem_path)) {
        /* Handle symlink */
        char *target = NULL;
        err = fs_read_symlink(filesystem_path, &target);
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to read symlink '%s'", filesystem_path);
        }

        err = fs_create_symlink(target, dest_path);
        free(target);
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to create symlink in worktree");
        }

        /* Capture symlink ownership metadata (root/ prefix + root user only).
         * Uses lstat to get the symlink's own uid/gid, not the target's.
         * Returns NULL item for home/ prefix or non-root (no metadata needed). */
        struct stat link_stat;
        if (lstat(filesystem_path, &link_stat) == 0) {
            err = metadata_capture_from_symlink(storage_path, &link_stat, &item);
            if (err) {
                free(dest_path);
                return error_wrap(err,
                    "Failed to capture symlink metadata for '%s'", filesystem_path);
            }
        }

        if (opts->verbose && out) {
            output_info(out, "Added symlink: %s -> %s", filesystem_path, storage_path);
        }
    } else {
        /* Regular file - determine encryption policy using centralized logic */
        bool should_encrypt = false;
        err = encryption_policy_should_encrypt(
            config,
            storage_path,
            opts->encrypt,
            opts->no_encrypt,
            metadata,  /* Existing metadata (preserves encryption state on --force re-add) */
            &should_encrypt
        );
        if (err) {
            free(dest_path);
            return error_wrap(err,
                "Failed to determine encryption policy for '%s'", storage_path);
        }

        /* Store file to worktree with optional encryption (handles read → encrypt → write)
         * IMPORTANT: This captures stat data to share with metadata layer (eliminates race condition) */
        err = content_store_file_to_worktree(
            filesystem_path,
            dest_path,
            storage_path,
            opts->profile,
            km,
            should_encrypt,
            &file_stat  /* Capture stat data */
        );
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to store file to worktree");
        }

        /* Capture metadata from file using stat data from content layer
         * SECURITY: Single stat() call eliminates race condition between content and metadata */
        err = metadata_capture_from_file(filesystem_path, storage_path, &file_stat, &item);
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to capture metadata for '%s'", filesystem_path);
        }

        /* Update metadata item with encryption status */
        if (item) {
            item->file.encrypted = should_encrypt;
        }

        /* Verbose output */
        if (opts->verbose && out) {
            if (should_encrypt) {
                output_info(out, "Encrypted: %s -> %s", filesystem_path, storage_path);
            }
            output_info(out, "Added: %s -> %s", filesystem_path, storage_path);
        }
    }

    /* Stage file */
    git_index *index = NULL;
    err = worktree_get_index(wt, &index);
    if (err) {
        free(dest_path);
        return error_wrap(err, "Failed to get worktree index");
    }

    int git_err = git_index_add_bypath(index, storage_path);
    if (git_err < 0) {
        git_index_free(index);
        free(dest_path);
        return error_from_git(git_err);
    }

    git_err = git_index_write(index);
    git_index_free(index);
    if (git_err < 0) {
        free(dest_path);
        if (item) {
            metadata_item_free(item);
        }
        return error_from_git(git_err);
    }

    free(dest_path);

    /* Add metadata item to collection (NULL for home/ prefix symlinks — no metadata needed) */
    if (item) {
        /* Verbose output for metadata capture */
        if (opts->verbose && out) {
            if (item->owner || item->group) {
                output_info(out, "Captured metadata: %s (mode: %04o, owner: %s:%s)",
                            filesystem_path, item->mode,
                            item->owner ? item->owner : "?",
                            item->group ? item->group : "?");
            } else {
                output_info(out, "Captured metadata: %s (mode: %04o)",
                            filesystem_path, item->mode);
            }
        }

        err = metadata_add_item(metadata, item);
        metadata_item_free(item);

        if (err) {
            return error_wrap(err, "Failed to add metadata item for '%s'", filesystem_path);
        }
    }

    return NULL;
}

/**
 * Initialize profile .dottaignore in a new profile
 *
 * Creates a minimal .dottaignore file with clear documentation about
 * the layering system. This gives users a clean starting point and
 * documents baseline inheritance.
 */
static error_t *init_profile_dottaignore(
    worktree_handle_t *wt,
    const cmd_add_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(wt);
    CHECK_NULL(opts);

    const char *wt_path = worktree_get_path(wt);
    if (!wt_path) {
        return ERROR(ERR_INTERNAL, "Worktree path is NULL");
    }

    /* Build path to .dottaignore */
    char *dottaignore_path = str_format("%s/.dottaignore", wt_path);
    if (!dottaignore_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate .dottaignore path");
    }

    /* Get profile template content */
    const char *template_content = ignore_profile_dottaignore_template();

    /* Create buffer with template content */
    buffer_t *content = buffer_create();
    if (!content) {
        free(dottaignore_path);
        return ERROR(ERR_MEMORY, "Failed to create buffer");
    }

    error_t *err = buffer_append(
        content, (const uint8_t *)template_content, strlen(template_content)
    );

    if (err) {
        buffer_free(content);
        free(dottaignore_path);
        return error_wrap(err, "Failed to populate buffer");
    }

    /* Write to file */
    err = fs_write_file(dottaignore_path, content);
    buffer_free(content);
    if (err) {
        free(dottaignore_path);
        return error_wrap(err, "Failed to write .dottaignore");
    }

    /* Stage the file */
    git_index *index = NULL;
    err = worktree_get_index(wt, &index);
    if (err) {
        free(dottaignore_path);
        return error_wrap(err, "Failed to get worktree index");
    }

    int git_err = git_index_add_bypath(index, ".dottaignore");
    if (git_err < 0) {
        git_index_free(index);
        free(dottaignore_path);
        return error_from_git(git_err);
    }

    git_err = git_index_write(index);
    git_index_free(index);
    if (git_err < 0) {
        free(dottaignore_path);
        return error_from_git(git_err);
    }

    if (opts->verbose && out) {
        output_info(out, "Created .dottaignore for profile '%s'", opts->profile);
    }

    free(dottaignore_path);
    return NULL;
}

/**
 * Directory tracking entry for passing to metadata
 */
typedef struct {
    char *filesystem_path;
    char *storage_path;
} tracked_dir_t;

/**
 * Create commit in worktree
 *
 * @param repo Repository
 * @param wt Worktree handle
 * @param opts Command options
 * @param added_files Files that were added
 * @param config Configuration
 * @param out_commit_oid Output for commit OID (optional, can be NULL)
 * @return Error or NULL on success
 */
static error_t *create_commit(
    git_repository *repo,
    worktree_handle_t *wt,
    const cmd_add_options_t *opts,
    string_array_t *added_files,
    const dotta_config_t *config,
    git_oid *out_commit_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(wt);
    CHECK_NULL(opts);
    CHECK_NULL(added_files);

    git_repository *wt_repo = worktree_get_repo(wt);
    if (!wt_repo) {
        return ERROR(ERR_INTERNAL, "Worktree repository is NULL");
    }

    /* Get index tree */
    git_index *index = NULL;
    error_t *derr = worktree_get_index(wt, &index);
    if (derr) {
        return error_wrap(derr, "Failed to get worktree index");
    }

    git_oid tree_oid;
    int git_err = git_index_write_tree(&tree_oid, index);
    git_index_free(index);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_tree *tree = NULL;
    git_err = git_tree_lookup(&tree, wt_repo, &tree_oid);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Build commit message using storage paths */
    string_array_t *storage_paths = string_array_create();
    if (!storage_paths) {
        git_tree_free(tree);
        return ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
    }

    /* Convert filesystem paths to storage paths for commit message */
    for (size_t i = 0; i < string_array_size(added_files); i++) {
        const char *file_path = string_array_get(added_files, i);
        char *storage_path = NULL;
        path_prefix_t prefix;

        derr = path_to_storage(file_path, opts->custom_prefix, &storage_path, &prefix);
        if (derr) {
            /* Skip if conversion fails (shouldn't happen at this point) */
            error_free(derr);
            continue;
        }

        derr = string_array_push(storage_paths, storage_path);
        free(storage_path);
        if (derr) {
            error_free(derr);
            break;
        }
    }

    /* Build commit message context */
    commit_message_context_t ctx = {
        .action = COMMIT_ACTION_ADD,
        .profile = opts->profile,
        .files = storage_paths->items,
        .file_count = storage_paths->count,
        .custom_msg = opts->message,
        .target_commit = NULL
    };

    char *message = build_commit_message(config, &ctx);
    string_array_free(storage_paths);

    if (!message) {
        git_tree_free(tree);
        return ERROR(ERR_MEMORY, "Failed to build commit message");
    }

    /* Create commit */
    git_oid commit_oid;
    derr = gitops_create_commit(
        wt_repo,
        opts->profile,
        tree,
        message,
        &commit_oid
    );

    free(message);
    git_tree_free(tree);

    if (derr) {
        return error_wrap(derr, "Failed to create commit");
    }

    /* Copy commit OID to output if requested */
    if (out_commit_oid) {
        git_oid_cpy(out_commit_oid, &commit_oid);
    }

    return NULL;
}

/**
 * Auto-enable newly created profile and sync files to manifest
 *
 * Called when `dotta add -p <profile>` creates a NEW profile branch for the first
 * time. Combines profile enabling with manifest sync in a single atomic transaction.
 *
 * WHY manifest_add_files (not manifest_enable_profile):
 * - Files captured FROM filesystem (already deployed) → deployed_at = time(NULL)
 * - manifest_enable_profile uses lstat() check which may set deployed_at = 0 for missing files
 * - Matches VWD architecture specification
 *
 * Algorithm:
 *   1. Load current enabled profiles (or create empty list if no state)
 *   2. Check if already enabled (defensive, shouldn't happen)
 *   3. Add new profile to enabled list (in-memory only)
 *   4. Open transaction
 *   5. Enable profile in state with custom prefix (makes prefix available)
 *   6. Sync files to manifest with DEPLOYED status (uses custom_prefix)
 *   7. Record stat cache for added files
 *   8. Commit transaction atomically
 *
 * CRITICAL ORDER: Step 5 must precede step 6. The custom_prefix stored in step 5
 * is required by state_get_prefix_map() during manifest_add_files() in step 6 to
 * resolve custom/ storage paths. Transaction atomicity ensures: enable + sync
 * succeed together or fail together (automatic rollback on error).
 *
 * @param repo Git repository (must not be NULL)
 * @param profile_name Profile to auto-enable (must not be NULL, must exist in Git)
 * @param custom_prefix Custom prefix for custom/ files (can be NULL)
 * @param added_files Filesystem paths that were added (must not be NULL)
 * @param out_updated Output flag: true if successful (must not be NULL)
 * @param out_synced Output: count of files synced (can be NULL)
 * @return Error or NULL on success (non-fatal - caller treats as warning)
 */
static error_t *auto_enable_and_sync_profile(
    git_repository *repo,
    const char *profile_name,
    const char *custom_prefix,
    const string_array_t *added_files,
    bool *out_updated,
    size_t *out_synced
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(added_files);
    CHECK_NULL(out_updated);

    error_t *err = NULL;
    state_t *state = NULL;
    string_array_t *enabled_profiles = NULL;
    size_t synced_count = 0;

    *out_updated = false;
    if (out_synced) {
        *out_synced = 0;
    }

    /* STEP 1: Load current enabled profiles (read-only, no transaction) */
    err = state_load(repo, &state);
    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            /* No state file yet - create empty enabled list */
            error_free(err);
            err = NULL;
            enabled_profiles = string_array_create();
            if (!enabled_profiles) {
                return ERROR(ERR_MEMORY, "Failed to create enabled profiles list");
            }
        } else {
            return error_wrap(err, "Failed to load state");
        }
    } else {
        /* State exists - get enabled profiles */
        err = state_get_profiles(state, &enabled_profiles);
        if (err) {
            state_free(state);
            return error_wrap(err, "Failed to get enabled profiles");
        }
        state_free(state);
        state = NULL;
    }

    /* STEP 2: Check if already enabled (defensive) */
    for (size_t i = 0; i < string_array_size(enabled_profiles); i++) {
        if (strcmp(string_array_get(enabled_profiles, i), profile_name) == 0) {
            /* Already enabled - idempotent success */
            string_array_free(enabled_profiles);
            *out_updated = true;
            return NULL;
        }
    }

    /* STEP 3: Add new profile to enabled list (in-memory) */
    err = string_array_push(enabled_profiles, profile_name);
    if (err) {
        string_array_free(enabled_profiles);
        return error_wrap(err, "Failed to add profile to enabled list");
    }

    /* STEP 4: Open write transaction */
    err = state_load_for_update(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to open transaction");
        goto cleanup;
    }

    /* STEP 5: Enable profile in state with custom prefix (if provided)
     *
     * CRITICAL ORDER: Must enable BEFORE manifest sync so custom_prefix
     * is available in state for path resolution during manifest_add_files().
     * The custom prefix is stored in the enabled_profiles table and used
     * by state_get_prefix_map() to resolve custom/ storage paths.
     *
     * Transaction Safety: If manifest sync (STEP 6) fails, state_free()
     * automatically rolls back this change (see cleanup handler). */
    err = state_enable_profile(state, profile_name, custom_prefix);
    if (err) {
        err = error_wrap(err, "Failed to enable profile in state");
        goto cleanup;
    }

    /* STEP 6: Sync files to manifest with DEPLOYED status
     *
     * manifest_add_files() calls state_get_prefix_map() internally to build
     * the manifest. The custom_prefix stored in STEP 5 is now available for
     * resolving custom/ storage paths via path_from_storage().
     *
     * Precedence: If this profile has lower precedence than existing enabled
     * profiles, some files may be skipped (synced_count < added_files). */
    err = manifest_add_files(
        repo,
        state,
        profile_name,
        added_files,
        enabled_profiles,
        NULL,  /* metadata_cache - pass NULL for fresh load */
        &synced_count
    );
    if (err) {
        err = error_wrap(err, "Failed to sync files to manifest");
        goto cleanup;
    }

    /* STEP 7: Record stat cache for added files
     *
     * Files were just captured from filesystem — content matches blob_oid.
     * lstat() is cheap (kernel cache hot from recent content_store_file_to_worktree).
     * state_update_stat_cache returns success on not-found (file may have been
     * filtered by precedence, so not all added_files end up in manifest). */
    for (size_t i = 0; i < string_array_size(added_files); i++) {
        const char *path = string_array_get(added_files, i);
        struct stat st;
        if (lstat(path, &st) == 0) {
            stat_cache_t sc = stat_cache_from_stat(&st);
            state_update_stat_cache(state, path, &sc);
            /* Non-fatal: ignore errors (optimization only) */
        }
    }

    /* STEP 8: Commit transaction atomically */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to commit transaction");
        goto cleanup;
    }

    /* Success */
    *out_updated = true;
    if (out_synced) {
        *out_synced = synced_count;
    }

cleanup:
    if (enabled_profiles) {
        string_array_free(enabled_profiles);
    }
    if (state) {
        state_free(state);  /* Auto-rolls back if err != NULL */
    }

    return err;
}

/**
 * Update manifest after successful add operation
 *
 * Called after Git commit succeeds. Updates manifest for all added files
 * if the profile is enabled. This is part of the Virtual Working Directory
 * integration - maintaining the manifest as an expected state cache.
 *
 * OPTIMIZED: Uses bulk manifest sync (manifest_add_files) with O(M+N) complexity.
 * manifest_add_files builds its own fresh manifest from Git (post-commit state),
 * ensuring all newly-added files are found during precedence checks.
 *
 * Algorithm:
 *   1. Check if profile is enabled (read-only check)
 *   2. If not enabled: return NULL (skip manifest update)
 *   3. If enabled:
 *      a. Open transaction (state_load_for_update)
 *      b. If custom_prefix provided: update prefix in state (UPSERT)
 *      c. Call manifest_add_files() (builds fresh manifest internally)
 *      d. Record stat cache for added files
 *      e. Commit transaction (state_save)
 *
 * Custom Prefix Update:
 *   When adding custom/ files to an already-enabled profile, the custom_prefix
 *   must be stored in state BEFORE manifest_add_files(). This is the same
 *   ordering constraint as auto_enable_and_sync_profile() (STEP 5 → STEP 6).
 *   Only called when custom_prefix is non-NULL to avoid clearing an existing
 *   prefix when adding home/ or root/ files.
 *
 * Lifecycle Tracking:
 *   Files get deployed_at = time(NULL) because ADD captures files FROM the
 *   filesystem. They're already at their target locations, so deployed_at
 *   is set to indicate dotta knows about them.
 *
 * Error Handling:
 *   - State doesn't exist → treat as "not enabled" (return NULL)
 *   - Profile not enabled → return NULL (success, no update)
 *   - Manifest sync fails → rollback, return error
 *
 * Non-Fatal Integration:
 *   Caller should treat manifest update failure as non-fatal warning.
 *   Git commit already succeeded; user can repair with `profile enable`.
 *
 * Performance: O(M + N) where M = total files in all profiles, N = files added
 *
 * @param repo Git repository
 * @param profile_name Profile that files were added to
 * @param custom_prefix Custom prefix for custom/ files (can be NULL)
 * @param added_files Filesystem paths that were added
 * @param out_updated Output flag: true if manifest was updated (must not be NULL)
 * @param out_synced Output: count of files synced (can be NULL)
 * @return Error or NULL on success
 */
static error_t *update_manifest_after_add(
    git_repository *repo,
    const char *profile_name,
    const char *custom_prefix,
    const string_array_t *added_files,
    bool *out_updated,
    size_t *out_synced
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(added_files);
    CHECK_NULL(out_updated);

    error_t *err = NULL;
    state_t *state = NULL;
    string_array_t *enabled_profiles = NULL;

    /* Initialize output */
    *out_updated = false;

    /* STEP 1: Check if profile is enabled (read-only check) */
    err = state_load(repo, &state);
    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            /* State file doesn't exist yet - profile can't be enabled */
            error_free(err);
            return NULL;
        }
        return error_wrap(err, "Failed to load state for manifest check");
    }

    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        state_free(state);
        return error_wrap(err, "Failed to get enabled profiles");
    }

    /* Check if this profile is enabled */
    bool is_enabled = false;
    for (size_t i = 0; i < string_array_size(enabled_profiles); i++) {
        if (strcmp(string_array_get(enabled_profiles, i), profile_name) == 0) {
            is_enabled = true;
            break;
        }
    }

    /* Free read-only state */
    state_free(state);
    state = NULL;

    if (!is_enabled) {
        /* Profile not enabled - skip manifest update (this is success) */
        string_array_free(enabled_profiles);
        return NULL;
    }

    /* STEP 2: Open transaction */
    err = state_load_for_update(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to open state transaction for manifest update");
        goto cleanup;
    }

    /* STEP 3: Update custom prefix in state if adding custom/ files
     *
     * CRITICAL ORDER: Must store prefix BEFORE manifest_add_files() so
     * state_get_prefix_map() can resolve custom/ storage paths during
     * manifest building. Same ordering constraint as
     * auto_enable_and_sync_profile() (STEP 5 → STEP 6).
     *
     * Only called when custom_prefix is non-NULL to avoid clearing an
     * existing prefix when adding home/ or root/ files.
     * state_enable_profile() uses UPSERT - safe on already-enabled profiles. */
    if (custom_prefix) {
        err = state_enable_profile(state, profile_name, custom_prefix);
        if (err) {
            err = error_wrap(err, "Failed to update custom prefix for profile");
            goto cleanup;
        }
    }

    /* STEP 4: Bulk sync operation (O(M+N)) */
    size_t synced_count = 0;
    err = manifest_add_files(
        repo,
        state,
        profile_name,
        added_files,
        enabled_profiles,
        NULL,  /* metadata_cache - pass NULL for fresh load */
        &synced_count
    );

    if (err) {
        err = error_wrap(err, "Failed to sync files to manifest");
        goto cleanup;
    }

    /* STEP 5: Record stat cache for added files */
    for (size_t i = 0; i < string_array_size(added_files); i++) {
        const char *path = string_array_get(added_files, i);
        struct stat st;
        if (lstat(path, &st) == 0) {
            stat_cache_t sc = stat_cache_from_stat(&st);
            state_update_stat_cache(state, path, &sc);
        }
    }

    /* STEP 6: Commit transaction */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to save manifest updates");
        goto cleanup;
    }

    /* Success */
    *out_updated = true;
    if (out_synced) {
        *out_synced = synced_count;
    }

cleanup:
    if (enabled_profiles) {
        string_array_free(enabled_profiles);
    }
    if (state) {
        state_free(state);  /* Rolls back if err != NULL */
    }

    return err;
}

/**
 * Add command implementation
 */
error_t *cmd_add(git_repository *repo, const cmd_add_options_t *opts) {
    CHECK_NULL(repo);

    error_t *err = validate_options(opts);
    if (err) {
        return err;
    }

    /* Initialize all resources to NULL for safe cleanup */
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;
    ignore_context_t *ignore_ctx = NULL;
    char *repo_dir = NULL;
    hook_context_t *hook_ctx = NULL;
    worktree_handle_t *wt = NULL;
    string_array_t *all_files = NULL;
    tracked_dir_t *tracked_dirs = NULL;
    size_t tracked_dir_count = 0;
    size_t tracked_dir_capacity = 0;
    size_t added_count = 0;
    bool profile_was_new = false;
    metadata_t *metadata = NULL;
    keymanager_t *key_mgr = NULL;

    /* Pre-flight privilege check arrays (cleaned up in main cleanup block) */
    const char **preflight_storage_paths = NULL;
    char **preflight_allocated_paths = NULL;
    size_t preflight_storage_count = 0;

    /* Load configuration for hooks and ignore patterns */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with default config */
        error_free(err);
        err = NULL;
        config = config_create_default();
        if (!config) {
            err = ERROR(ERR_MEMORY, "Failed to create default config");
            goto cleanup;
        }
    }

    /* Create output context from config */
    out = output_create_from_config(config);
    if (!out) {
        err = ERROR(ERR_MEMORY, "Failed to create output context");
        goto cleanup;
    }

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Validate custom prefix if provided */
    if (opts->custom_prefix) {
        err = path_validate_custom_prefix(opts->custom_prefix);
        if (err) {
            goto cleanup;
        }
    }

    /* PRE-FLIGHT PRIVILEGE CHECK
     *
     * This check happens BEFORE any operations begin to ensure we have required
     * privileges. If elevation is needed, the process will re-exec with sudo,
     * and all operations will restart cleanly from main().
     *
     * CRITICAL: Must happen before:
     * - Hook execution (avoids double execution on re-exec)
     * - Worktree creation (avoids resource leaks)
     * - Any filesystem modifications (ensures clean restart)
     *
     * If re-exec succeeds, this function DOES NOT RETURN.
     */

    /* Build array of storage paths by pre-resolving all file paths */
    preflight_storage_paths = calloc(opts->file_count, sizeof(char *));
    preflight_allocated_paths = calloc(opts->file_count, sizeof(char *));

    if (!preflight_storage_paths || !preflight_allocated_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
        goto cleanup;
    }

    /* Pre-compute whether custom prefix needs elevation.
     * All paths in this add invocation share the same prefix. */
    bool custom_needs_elevation = opts->custom_prefix
        ? privilege_custom_prefix_needs_elevation(opts->custom_prefix)
        : false;  /* No prefix → no custom/ paths → irrelevant */

    /* Resolve all paths to storage format (pre-flight for privilege check).
     * Only paths that actually need elevation are included — home/ never does,
     * and custom/ only does when the prefix is outside $HOME. */
    for (size_t i = 0; i < opts->file_count; i++) {
        const char *file_path = opts->files[i];
        char *absolute = NULL;
        char *storage_path = NULL;
        path_prefix_t prefix;

        /* Storage-path inputs (home/..., root/..., custom/...) — only include
         * paths that actually need elevation in the privilege check. */
        if (str_starts_with(file_path, "home/") ||
            str_starts_with(file_path, "root/") ||
            str_starts_with(file_path, "custom/")) {
            bool needs_elevation = str_starts_with(file_path, "root/") ||
                                  (str_starts_with(file_path, "custom/") && custom_needs_elevation);
            if (!needs_elevation) {
                continue;
            }
            storage_path = strdup(file_path);
            if (!storage_path) {
                err = ERROR(ERR_MEMORY, "Failed to duplicate storage path");
                goto cleanup;
            }
            preflight_allocated_paths[preflight_storage_count] = storage_path;
            preflight_storage_paths[preflight_storage_count] = storage_path;
            preflight_storage_count++;
            continue;
        }

        /* Filesystem path — normalize raw user input to absolute path first */
        err = path_normalize_input(file_path, opts->custom_prefix, &absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve path '%s'", file_path);
            goto cleanup;
        }

        err = path_to_storage(absolute, opts->custom_prefix, &storage_path, &prefix);
        free(absolute);
        if (err) {
            /* Directory inputs that equal the custom prefix can't be converted
             * to a storage path (the prefix root has no storage representation).
             * The main processing loop will expand the directory into files.
             *
             * If the custom prefix needs elevation, add a representative entry
             * so the privilege check fires for expanded custom/ files. Without
             * this, directory inputs bypass the pre-flight entirely. */
            if (!fs_is_symlink(file_path) && fs_is_directory(file_path)) {
                error_free(err);
                err = NULL;
                if (custom_needs_elevation) {
                    storage_path = strdup("custom/");
                    if (!storage_path) {
                        err = ERROR(ERR_MEMORY, "Failed to allocate representative path");
                        goto cleanup;
                    }
                    preflight_allocated_paths[preflight_storage_count] = storage_path;
                    preflight_storage_paths[preflight_storage_count] = storage_path;
                    preflight_storage_count++;
                }
                continue;
            }
            /* Actual error for regular files */
            err = error_wrap(err, "Failed to resolve path '%s'", file_path);
            goto cleanup;
        }

        /* Only include paths that need elevation in the privilege check */
        if (prefix == PREFIX_ROOT || (prefix == PREFIX_CUSTOM && custom_needs_elevation)) {
            preflight_allocated_paths[preflight_storage_count] = storage_path;
            preflight_storage_paths[preflight_storage_count] = storage_path;
            preflight_storage_count++;
        } else {
            free(storage_path);
        }
    }

    /* Check privilege requirements
     *
     * If root/ files detected without root privileges:
     * - Interactive: Prompts user, re-execs with sudo if approved
     * - Non-interactive: Returns error with clear message
     *
     * If re-exec succeeds, this function DOES NOT RETURN.
     * If re-exec fails or user declines, returns error.
     */
    err = privilege_ensure_for_operation(
        preflight_storage_paths, preflight_storage_count, "add", true, opts->argc, opts->argv, out
    );

    if (err) {
        /* User declined elevation or non-interactive mode blocked it */
        goto cleanup;
    }

    /* If we reach here, privileges are OK - proceed with operation */

    /* Create ignore context */
    err = ignore_context_create(
        repo, config, opts->profile, opts->exclude_patterns, opts->exclude_count, &ignore_ctx
    );
    if (err) {
        /* Non-fatal: continue without ignore context */
        if (opts->verbose && out) {
            output_warning(out, "Failed to create ignore context: %s", error_message(err));
        }
        error_free(err);
        err = NULL;
    }

    /* Get repository directory */
    err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        goto cleanup;
    }

    /* Execute pre-add hook */
    hook_ctx = hook_context_create(repo_dir, "add", opts->profile);
    if (hook_ctx) {
        err = hook_context_add_files(hook_ctx, opts->files, opts->file_count);
        if (err) goto cleanup;

        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_PRE_ADD, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - abort operation */
            if (hook_result && hook_result->output && hook_result->output[0] && out) {
                output_print(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
            }
            hook_result_free(hook_result);
            err = error_wrap(err, "Pre-add hook failed");
            goto cleanup;
        }
        hook_result_free(hook_result);
    }

    /* Create temporary worktree */
    err = worktree_create_temp(repo, &wt);
    if (err) {
        err = error_wrap(err, "Failed to create temporary worktree");
        goto cleanup;
    }

    /* Checkout or create profile branch */
    bool profile_exists = false;
    err = gitops_branch_exists(repo, opts->profile, &profile_exists);
    if (err) {
        goto cleanup;
    }

    if (profile_exists) {
        err = worktree_checkout_branch(wt, opts->profile);
    } else {
        err = worktree_create_orphan(wt, opts->profile);
        profile_was_new = true;  /* Profile is newly created */
    }

    if (err) {
        err = error_wrap(err, "Failed to prepare profile branch '%s'", opts->profile);
        goto cleanup;
    }

    /* Initialize .dottaignore for new profiles */
    if (!profile_exists) {
        err = init_profile_dottaignore(wt, opts, out);
        if (err) {
            err = error_wrap(err,
                "Failed to initialize .dottaignore for profile '%s'", opts->profile);
            goto cleanup;
        }
    }

    /* Collect all files to add (expanding directories) */
    all_files = string_array_create();
    if (!all_files) {
        err = ERROR(ERR_MEMORY, "Failed to allocate file list");
        goto cleanup;
    }

    /* Process each input path */
    for (size_t i = 0; i < opts->file_count; i++) {
        const char *file = opts->files[i];
        char *absolute = NULL;

        /* Check if input is a storage path */
        if (str_starts_with(file, "home/") ||
            str_starts_with(file, "root/") ||
            str_starts_with(file, "custom/")) {

            /* Determine if we need custom prefix for this storage path */
            const char *prefix_for_conversion = NULL;

            if (str_starts_with(file, "custom/")) {
                /* custom/ paths require --prefix flag */
                prefix_for_conversion = opts->custom_prefix;

                if (!prefix_for_conversion || prefix_for_conversion[0] == '\0') {
                    err = ERROR(ERR_INVALID_ARG, "Storage path '%s' requires --prefix flag\n"
                                "Usage: dotta add -p %s --prefix /path/to/target %s",
                                file, opts->profile, file);
                    goto cleanup;
                }
            }
            /* home/ and root/ don't need custom prefix (pass NULL) */

            /* Convert storage path to filesystem path */
            char *fs_path = NULL;
            err = path_from_storage(file, prefix_for_conversion, &fs_path);
            if (err) {
                err = error_wrap(err, "Failed to convert storage path '%s'", file);
                goto cleanup;
            }

            /* Make absolute without following symlinks */
            err = fs_make_absolute(fs_path, &absolute);
            free(fs_path);
            if (err) {
                err = error_wrap(err, "Failed to resolve path '%s'", file);
                goto cleanup;
            }
        } else {
            /* Regular filesystem path - normalize it */
            err = path_normalize_input(file, opts->custom_prefix, &absolute);
            if (err) {
                err = error_wrap(err, "Failed to resolve path '%s'", file);
                goto cleanup;
            }
        }

        /* Check path exists (use lexists to allow broken symlinks) */
        if (!fs_lexists(absolute)) {
            err = ERROR(ERR_NOT_FOUND, "Path not found: %s", absolute);
            free(absolute);
            goto cleanup;
        }

        /* Handle symlinks, directories, and files */
        if (!fs_is_symlink(absolute) && fs_is_directory(absolute)) {
            /* Recursively collect files from directory */
            string_array_t *dir_files = NULL;
            err = collect_files_from_dir(absolute, opts, ignore_ctx, out, &dir_files);

            if (err) {
                free(absolute);
                err = error_wrap(err, "Failed to collect files from '%s'", file);
                goto cleanup;
            }

            /* If all files were excluded, skip this directory entirely */
            if (string_array_size(dir_files) == 0) {
                string_array_free(dir_files);
                if (opts->verbose && out) {
                    output_info(out, "Skipped directory (all files excluded): %s", absolute);
                }
                free(absolute);
                continue;
            }

            /* Merge directory files into all_files (dedup against explicit file args) */
            for (size_t j = 0; j < string_array_size(dir_files); j++) {
                const char *dir_file = string_array_get(dir_files, j);
                if (string_array_contains(all_files, dir_file)) {
                    continue;
                }
                err = string_array_push(all_files, dir_file);
                if (err) {
                    string_array_free(dir_files);
                    free(absolute);
                    goto cleanup;
                }
            }
            string_array_free(dir_files);

            if (opts->verbose && out) {
                output_info(out, "Added directory: %s", absolute);
            }

            /* Track this directory for metadata capture */
            char *storage_prefix = NULL;
            path_prefix_t prefix;
            err = path_to_storage(absolute, opts->custom_prefix, &storage_prefix, &prefix);
            if (err) {
                /* Non-fatal: directory that equals the custom prefix root has no
                 * storage path representation. Individual files are still added. */
                error_free(err);
                err = NULL;
                free(absolute);
                continue;
            }

            /* Add to tracked directories list */
            if (tracked_dir_count >= tracked_dir_capacity) {
                size_t new_capacity = tracked_dir_capacity == 0 ? 8 : tracked_dir_capacity * 2;
                tracked_dir_t *new_dirs = realloc(tracked_dirs, new_capacity * sizeof(tracked_dir_t));
                if (!new_dirs) {
                    free(storage_prefix);
                    free(absolute);
                    err = ERROR(ERR_MEMORY, "Failed to allocate tracked directories");
                    goto cleanup;
                }
                tracked_dirs = new_dirs;
                tracked_dir_capacity = new_capacity;
            }

            tracked_dirs[tracked_dir_count].filesystem_path = strdup(absolute);
            if (!tracked_dirs[tracked_dir_count].filesystem_path) {
                free(storage_prefix);
                free(absolute);
                err = ERROR(ERR_MEMORY, "Failed to duplicate directory path");
                goto cleanup;
            }
            tracked_dirs[tracked_dir_count].storage_path = storage_prefix;
            tracked_dir_count++;
        } else {
            /* Single file or symlink - check if excluded */
            if (is_excluded(absolute, false, ignore_ctx, opts, out)) {
                if (opts->verbose && out) {
                    output_info(out, "Excluded: %s", absolute);
                }
                free(absolute);
                continue;
            }

            /* Add to list (dedup: skip if already collected via directory expansion) */
            if (!string_array_contains(all_files, absolute)) {
                err = string_array_push(all_files, absolute);
                if (err) {
                    free(absolute);
                    goto cleanup;
                }
            }
        }

        free(absolute);
    }

    /* Check if we have anything to add (files or directories) */
    if (string_array_size(all_files) == 0 && tracked_dir_count == 0) {
        if (opts->exclude_count > 0) {
            err = ERROR(ERR_INVALID_ARG,
                "No files or directories to add (all excluded by patterns)");
        } else {
            err = ERROR(ERR_INVALID_ARG, "No files or directories to add");
        }
        goto cleanup;
    }

    /* Load or create metadata collection before processing files */
    const char *worktree_path = worktree_get_path(wt);
    char *metadata_file_path = str_format("%s/%s", worktree_path, METADATA_FILE_PATH);
    if (!metadata_file_path) {
        err = ERROR(ERR_MEMORY, "Failed to allocate metadata file path");
        goto cleanup;
    }

    err = metadata_load_from_file(metadata_file_path, &metadata);
    free(metadata_file_path);

    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            /* No existing metadata - create new */
            error_free(err);
            err = metadata_create_empty(&metadata);
            if (err) {
                goto cleanup;
            }
        } else {
            /* Real error - propagate */
            err = error_wrap(err, "Failed to load existing metadata");
            goto cleanup;
        }
    }

    /* Get keymanager if encryption may be needed
     *
     * Keymanager handles profile key caching internally, so files will reuse
     * the same derived key without redundant derivations (O(1) after first derivation).
     *
     * Get keymanager if EITHER:
     *   1. Explicit encryption requested (--encrypt flag)
     *   2. Auto-encrypt patterns configured (files may match patterns)
     */
    bool needs_encryption = opts->encrypt || (config && config->encryption_enabled &&
                            config->auto_encrypt_patterns && config->auto_encrypt_pattern_count > 0);

    if (needs_encryption) {
        if (!config || !config->encryption_enabled) {
            err = ERROR(ERR_INVALID_ARG,
                "Encryption requested (--encrypt) but encryption is not enabled in config.\n"
                "Add to config.toml:\n\n  [encryption]\n  enabled = true");
            goto cleanup;
        }
        key_mgr = keymanager_get_global(config);
        if (!key_mgr) {
            err = ERROR(ERR_INTERNAL, "Failed to get encryption key manager");
            goto cleanup;
        }
    }

    /* Single-pass: add files and capture metadata inline */
    for (size_t i = 0; i < string_array_size(all_files); i++) {
        const char *file_path = string_array_get(all_files, i);

        /* Compute storage path once */
        char *storage_path = NULL;
        path_prefix_t prefix;
        err = path_to_storage(file_path, opts->custom_prefix, &storage_path, &prefix);
        if (err) {
            err = error_wrap(err, "Failed to convert path '%s'", file_path);
            goto cleanup;
        }

        /* Validate storage path */
        err = path_validate_storage(storage_path);
        if (err) {
            free(storage_path);
            goto cleanup;
        }

        /* Add file to worktree and capture metadata
         * ARCHITECTURE: add_file_to_worktree now handles both operations atomically,
         * sharing stat() data between content and metadata layers to eliminate race conditions */
        err = add_file_to_worktree(
            wt, file_path, storage_path, opts, key_mgr, config, metadata, out
        );
        if (err) {
            free(storage_path);
            err = error_wrap(err, "Failed to add file '%s'", file_path);
            goto cleanup;
        }

        free(storage_path);
        added_count++;
    }

    /* Handle tracked directories metadata */
    size_t dir_tracked_count = 0;
    for (size_t i = 0; i < tracked_dir_count; i++) {
        const tracked_dir_t *dir = &tracked_dirs[i];

        /* Stat directory first to capture metadata */
        struct stat dir_stat;
        if (stat(dir->filesystem_path, &dir_stat) != 0) {
            /* Non-fatal: log warning and continue */
            if (opts->verbose && out) {
                output_warning(out, "Failed to stat directory '%s': %s",
                               dir->filesystem_path, strerror(errno));
            }
            continue;
        }

        /* Capture directory metadata using stat data */
        metadata_item_t *dir_item = NULL;
        err = metadata_capture_from_directory(dir->storage_path, &dir_stat, &dir_item);

        if (err) {
            /* Non-fatal: log warning and continue */
            if (opts->verbose && out) {
                output_warning(out, "Failed to capture metadata for directory '%s': %s",
                               dir->filesystem_path, error_message(err));
            }
            error_free(err);
            err = NULL;
            continue;
        }

        /* Verbose output before consuming the item */
        if (opts->verbose && out) {
            if (dir_item->owner || dir_item->group) {
                output_info(out, "Captured directory metadata: %s (mode: %04o, owner: %s:%s)",
                            dir->filesystem_path, dir_item->mode,
                            dir_item->owner ? dir_item->owner : "?",
                            dir_item->group ? dir_item->group : "?");
            } else {
                output_info(out, "Captured directory metadata: %s (mode: %04o)",
                            dir->filesystem_path, dir_item->mode);
            }
        }

        /* Add directory to metadata */
        err = metadata_add_item(metadata, dir_item);

        metadata_item_free(dir_item);

        if (err) {
            /* Non-fatal: log warning and continue */
            if (opts->verbose && out) {
                output_warning(out, "Failed to track directory '%s': %s",
                               dir->filesystem_path, error_message(err));
            }
            error_free(err);
            err = NULL;
        } else {
            dir_tracked_count++;
            if (opts->verbose && out) {
                output_info(out, "Tracked directory: %s -> %s",
                            dir->filesystem_path, dir->storage_path);
            }
        }
    }

    /* Save metadata to worktree */
    err = metadata_save_to_worktree(worktree_path, metadata);
    if (err) {
        err = error_wrap(err, "Failed to save metadata");
        goto cleanup;
    }

    /* Stage metadata.json file */
    git_index *index = NULL;
    err = worktree_get_index(wt, &index);
    if (err) {
        err = error_wrap(err, "Failed to get worktree index");
        goto cleanup;
    }

    int git_err = git_index_add_bypath(index, METADATA_FILE_PATH);
    if (git_err < 0) {
        git_index_free(index);
        err = error_from_git(git_err);
        goto cleanup;
    }

    git_err = git_index_write(index);
    git_index_free(index);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Verbose summary */
    if (opts->verbose && out && dir_tracked_count > 0) {
        output_info(out, "Tracked %zu director%s for change detection",
                    dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies");
    }

    /* Create commit */
    err = create_commit(repo, wt, opts, all_files, config, NULL);
    if (err) {
        goto cleanup;
    }

    /* Update manifest - auto-enable new profiles, sync existing enabled profiles
     *
     * VWD Architecture: When files are committed to an enabled profile, the manifest
     * (virtual working directory) must be updated immediately to maintain consistency.
     *
     * For NEW profiles: Auto-enable provides intuitive UX (creating via 'add' enables it).
     * For EXISTING profiles: Standard behavior (sync only if already enabled).
     *
     * Non-fatal: If manifest update fails, Git commit still succeeded.
     * User can repair manifest by running 'dotta profile enable <profile>'.
     */
    bool manifest_updated = false;
    size_t manifest_synced_count = 0;

    if (profile_was_new) {
        /* AUTO-ENABLE NEW PROFILE
         *
         * UX Decision: Creating a profile via 'add' should enable it automatically.
         * This matches user expectations: "I just added a file, it should be active."
         *
         * Uses manifest_add_files (not manifest_enable_profile) because:
         * - Files captured FROM filesystem (already deployed)
         * - Should have deployed_at = time(NULL), not deployed_at = 0
         * - Matches VWD architecture specification
         */
        error_t *enable_err = auto_enable_and_sync_profile(
            repo, opts->profile, opts->custom_prefix, all_files,
            &manifest_updated, &manifest_synced_count
        );

        if (enable_err) {
            /* Non-fatal: Git commit succeeded, user can manually enable later */
            if (out) {
                output_warning(out, "Failed to auto-enable profile: %s", error_message(enable_err));
                output_hint(out, "Run 'dotta profile enable %s' to enable manually", opts->profile);
            }
            error_free(enable_err);
            manifest_updated = false;
            manifest_synced_count = 0;
        }
    } else {
        /* EXISTING PROFILE - Standard manifest update
         *
         * Checks if profile is enabled and syncs if so.
         * If not enabled, skips manifest update (user must explicitly enable).
         */
        error_t *manifest_err = update_manifest_after_add(
            repo, opts->profile, opts->custom_prefix, all_files,
            &manifest_updated, &manifest_synced_count
        );

        if (manifest_err) {
            /* Non-fatal: Git commit succeeded */
            if (out) {
                output_warning(out, "Failed to update manifest: %s", error_message(manifest_err));
                output_info(out, "Files committed to Git successfully");
                output_hint(out, "Run 'dotta profile enable %s' to sync manifest", opts->profile);
            }
            error_free(manifest_err);
            manifest_updated = false;
            manifest_synced_count = 0;
        }
    }

    /* Cleanup worktree before post-processing */
    worktree_cleanup(&wt);

    /* Execute post-add hook */
    if (hook_ctx) {
        hook_result_t *hook_result = NULL;
        error_t *hook_err = hook_execute(config, HOOK_POST_ADD, hook_ctx, &hook_result);

        if (hook_err) {
            /* Hook failed - warn but don't abort (files already added) */
            if (out) {
                output_warning(out, "Post-add hook failed: %s", error_message(hook_err));
                if (hook_result && hook_result->output && hook_result->output[0]) {
                    output_print(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
                }
            }
            error_free(hook_err);
        }
        hook_result_free(hook_result);
    }

    /* Show summary on success */
    if ((added_count > 0 || dir_tracked_count > 0) && out) {
        /* Primary success message */
        if (added_count > 0) {
            output_success(out, "Added %zu file%s to profile '%s'",
                           added_count, added_count == 1 ? "" : "s", opts->profile);
        } else {
            /* Directory-only add */
            output_success(out, "Tracking %zu director%s in profile '%s'", dir_tracked_count,
                           dir_tracked_count == 1 ? "y" : "ies", opts->profile);
        }
    
        if (profile_was_new) {
            output_success(out, "Profile '%s' created and enabled", opts->profile);
        }
    
        /* Show directory tracking info only when files were also added */
        if (added_count > 0 && dir_tracked_count > 0) {
            output_info(out, "Tracking %zu director%s for change detection",
                        dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies");
        }
    
        output_newline(out);
    
        /* Manifest status feedback */
        if (manifest_updated) {
            if (added_count > 0) {
                /* Files were added */
                if (profile_was_new) {
                    /* New profile - show sync results with precedence awareness */
                    if (manifest_synced_count == added_count) {
                        output_info(out, "Manifest updated (%zu file%s marked as deployed)",
                                    manifest_synced_count, manifest_synced_count == 1 ? "" : "s");
                    } else {
                        output_info(out, "Manifest updated (%zu/%zu file%s marked as deployed)",
                                    manifest_synced_count, added_count, added_count == 1 ? "" : "s");
    
                        if (manifest_synced_count < added_count) {
                            size_t skipped = added_count - manifest_synced_count;
                            output_info(out, "Note: %zu file%s overridden by higher-precedence profiles",
                                        skipped, skipped == 1 ? "" : "s");
                        }
                    }
                } else {
                    /* Existing enabled profile */
                    if (manifest_synced_count == added_count) {
                        output_info(out, "Manifest updated (%zu file%s marked as deployed)",
                                    manifest_synced_count, manifest_synced_count == 1 ? "" : "s");
                    } else {
                        output_info(out, "Manifest updated (%zu/%zu file%s marked as deployed)",
                                    manifest_synced_count, added_count, added_count == 1 ? "" : "s");
                        if (manifest_synced_count < added_count) {
                            size_t skipped = added_count - manifest_synced_count;
                            output_info(out, "Note: %zu file%s overridden by higher-precedence profiles",
                                        skipped, skipped == 1 ? "" : "s");
                        }
                    }
                    output_hint(out, "Files captured from filesystem (already deployed)");
                }
            } else {
                /* Directory-only add */
                output_info(out, "Manifest updated (%zu director%s synced)",
                            dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies");
            }
            output_hint(out, "Run 'dotta status' to verify");
        } else {
            /* Existing disabled profile - original behavior */
            output_info(out, "Profile not enabled - manifest not updated");
            output_hint(out, "Run 'dotta profile enable %s' to activate", opts->profile);
            output_hint(out, "Run 'dotta apply -p %s' to deploy files", opts->profile);
        }
    }

cleanup:
    /* Free tracked directories */
    if (tracked_dirs) {
        for (size_t i = 0; i < tracked_dir_count; i++) {
            free(tracked_dirs[i].filesystem_path);
            free(tracked_dirs[i].storage_path);
        }
        free(tracked_dirs);
    }

    /* Free resources in reverse order of allocation */
    if (metadata) metadata_free(metadata);
    if (all_files) string_array_free(all_files);
    if (wt) worktree_cleanup(&wt);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (repo_dir) free(repo_dir);
    if (ignore_ctx) ignore_context_free(ignore_ctx);
    if (preflight_allocated_paths) {
        for (size_t i = 0; i < preflight_storage_count; i++) {
            free(preflight_allocated_paths[i]);
        }
        free(preflight_allocated_paths);
    }
    free(preflight_storage_paths);
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}
