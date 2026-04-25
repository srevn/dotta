/**
 * add.c - Add files to profiles
 */

#include "cmds/add.h"

#include <config.h>
#include <dirent.h>
#include <errno.h>
#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/output.h"
#include "base/string.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/state.h"
#include "crypto/policy.h"
#include "infra/content.h"
#include "infra/path.h"
#include "infra/worktree.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/source.h"
#include "utils/commit.h"
#include "utils/hooks.h"
#include "utils/privilege.h"

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
 * Check if path should be ignored.
 *
 * Consults two independent mechanisms in order:
 *   1. `rules` — the user's `.dottaignore` layers (baseline, profile,
 *      config, CLI) compiled into a single gitignore ruleset.
 *   2. `source_filter` — the source tree's own `.gitignore`, if the
 *      caller opted in by building a filter (typically gated on
 *      `config.respect_gitignore`).
 *
 * Either input may be NULL to skip that mechanism. Source-filter
 * errors degrade to a verbose warning and a "not excluded" verdict
 * so an odd source repo never blocks the user from adding a file
 * they explicitly named. The gitignore evaluator never fails — its
 * verdict is applied directly.
 */
static bool is_excluded(
    const char *path,
    bool is_directory,
    const gitignore_ruleset_t *rules,
    source_filter_t *source_filter,
    output_t *out
) {
    if (!path) return false;

    if (rules && gitignore_is_ignored(rules, path, is_directory)) {
        return true;
    }

    if (source_filter) {
        bool excluded = false;
        error_t *err = source_filter_is_excluded(
            source_filter, path, is_directory, &excluded
        );
        if (err) {
            output_warning(
                out, OUTPUT_VERBOSE,
                "Source .gitignore check failed for %s: %s",
                path, error_message(err)
            );
            error_free(err);
            return false;
        }
        return excluded;
    }

    return false;
}

/**
 * Recursively collect a directory tree into the caller's accumulators.
 *
 * Appends one entry to `directories` on every successful entry (the walker
 * is the sole source of truth for directory tracking), and one entry to
 * `files` for every non-excluded non-directory child. Dedups against
 * already-collected entries so overlapping CLI args (~/.config and
 * ~/.config/fish) don't double-record — within a single walk, tree
 * recursion visits each directory exactly once, so only cross-walk
 * duplicates are possible.
 *
 * Symlinks are never recursed into: symlink-to-dir is treated as an
 * atomic entry by the outer loop and never reaches this function.
 *
 * All pushed strings are owned by the arrays (string_array_push copies).
 * On error, partial results remain in the caller's arrays; the caller's
 * cleanup path frees them.
 */
static error_t *collect_tree(
    const char *dir_path,
    const gitignore_ruleset_t *rules,
    source_filter_t *source_filter,
    output_t *out,
    string_array_t *files,
    string_array_t *directories
) {
    CHECK_NULL(dir_path);
    CHECK_NULL(files);
    CHECK_NULL(directories);

    DIR *dir = opendir(dir_path);
    if (!dir) {
        return ERROR(ERR_FS, "Failed to open directory: %s", dir_path);
    }

    /* Record this directory. Classification-root skip happens later in
     * the metadata-capture phase; at collection time every walked
     * directory is a tracking candidate. */
    if (!string_array_contains(directories, dir_path)) {
        error_t *push_err = string_array_push(directories, dir_path);
        if (push_err) {
            closedir(dir);
            return push_err;
        }
    }

    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            errno = 0;  /* Clear before next readdir() */
            continue;
        }

        /* Build full path */
        char *full_path = str_format("%s/%s", dir_path, entry->d_name);
        if (!full_path) {
            closedir(dir);
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }

        /* Determine entry type */
        bool is_symlink = fs_is_symlink(full_path);
        bool is_dir = !is_symlink && fs_is_directory(full_path);

        /* Check exclude patterns */
        if (is_excluded(full_path, is_dir, rules, source_filter, out)) {
            output_info(out, OUTPUT_VERBOSE, "Excluded: %s", full_path);
            free(full_path);
            errno = 0;
            continue;
        }

        error_t *err = NULL;
        if (is_dir) {
            /* Recurse: child pushes itself on entry. */
            err = collect_tree(
                full_path, rules, source_filter, out, files, directories
            );
        } else if (!string_array_contains(files, full_path)) {
            err = string_array_push(files, full_path);
        }
        free(full_path);
        if (err) {
            closedir(dir);
            return err;
        }
        errno = 0;
    }

    /* readdir() returns NULL on both end-of-directory and error.
     * With errno cleared before each call, non-zero errno means I/O error. */
    if (errno != 0) {
        int saved_errno = errno;
        closedir(dir);
        return ERROR(
            ERR_FS, "Error reading directory '%s': %s",
            dir_path, strerror(saved_errno)
        );
    }

    closedir(dir);
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
 * @param keymgr Key manager (for encryption, can be NULL if encryption disabled)
 * @param config Configuration (for encryption policy; can be NULL)
 * @param metadata Metadata collection (captured entry will be added here)
 * @param out Output context
 * @return Error or NULL on success
 */
static error_t *add_file_to_worktree(
    worktree_handle_t *wt,
    const char *filesystem_path,
    const char *storage_path,
    const cmd_add_options_t *opts,
    keymgr *keymgr,
    const config_t *config,
    metadata_t *metadata,
    output_t *out
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
            error_t *exists_err = ERROR(
                ERR_EXISTS, "File '%s' (as '%s') already exists in profile '%s'. "
                "Use --force to overwrite.", filesystem_path, storage_path,
                opts->profile
            );
            free(dest_path);
            return exists_err;
        }
        err = fs_remove_file(dest_path);
        if (err) {
            error_t *wrapped = error_wrap(
                err, "Failed to remove existing file '%s' in worktree",
                dest_path
            );
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
            return error_wrap(
                err, "Failed to read symlink '%s'",
                filesystem_path
            );
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
                return error_wrap(
                    err, "Failed to capture symlink metadata for '%s'",
                    filesystem_path
                );
            }
        }

        output_info(
            out, OUTPUT_VERBOSE, "Added symlink: %s -> %s",
            filesystem_path, storage_path
        );
    } else {
        /* Regular file - determine encryption policy using centralized logic */
        bool should_encrypt = false;
        err = encryption_policy_should_encrypt(
            config,
            storage_path,
            opts->encrypt_mode == ADD_ENCRYPT_FORCE_ON,
            opts->encrypt_mode == ADD_ENCRYPT_FORCE_OFF,
            metadata,  /* Existing metadata (preserves encryption state on --force re-add) */
            &should_encrypt
        );
        if (err) {
            free(dest_path);
            return error_wrap(
                err, "Failed to determine encryption policy for '%s'",
                storage_path
            );
        }

        /* Store file to worktree with optional encryption (handles read → encrypt → write)
         * IMPORTANT: This captures stat data to share with metadata layer */
        err = content_store_file_to_worktree(
            filesystem_path,
            dest_path,
            storage_path,
            opts->profile,
            keymgr,
            should_encrypt,
            &file_stat  /* Capture stat data */
        );
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to store file to worktree");
        }

        /* Capture metadata from file using stat data from content layer
         * SECURITY: Single stat() call eliminates race condition */
        err = metadata_capture_from_file(
            filesystem_path, storage_path, &file_stat, &item
        );
        if (err) {
            free(dest_path);
            return error_wrap(
                err, "Failed to capture metadata for '%s'",
                filesystem_path
            );
        }

        /* Update metadata item with encryption status */
        if (item) {
            item->file.encrypted = should_encrypt;
        }

        /* Verbose output */
        if (should_encrypt) {
            output_info(
                out, OUTPUT_VERBOSE, "Encrypted: %s -> %s",
                filesystem_path, storage_path
            );
        }
        output_info(
            out, OUTPUT_VERBOSE, "Added: %s -> %s",
            filesystem_path, storage_path
        );
    }

    /* Stage file */
    err = worktree_stage_file(wt, storage_path);
    if (err) {
        free(dest_path);
        if (item) metadata_item_free(item);
        return error_wrap(err, "Failed to stage file");
    }

    free(dest_path);

    /* Add metadata item to collection (NULL for home/ prefix symlinks) */
    if (item) {
        /* Verbose output for metadata capture */
        if (item->owner || item->group) {
            output_info(
                out, OUTPUT_VERBOSE,
                "Captured metadata: %s (mode: %04o, owner: %s:%s)",
                filesystem_path, item->mode, item->owner ? item->owner : "?",
                item->group ? item->group : "?"
            );
        } else {
            output_info(
                out, OUTPUT_VERBOSE,
                "Captured metadata: %s (mode: %04o)",
                filesystem_path, item->mode
            );
        }

        err = metadata_add_item(metadata, item);
        metadata_item_free(item);

        if (err) {
            return error_wrap(
                err, "Failed to add metadata item for '%s'",
                filesystem_path
            );
        }
    }

    return NULL;
}

/**
 * Create commit in worktree
 *
 * @param wt Worktree handle
 * @param opts Command options
 * @param added_files Files that were added
 * @param config Configuration
 * @param out_commit_oid Output for commit OID (optional, can be NULL)
 * @return Error or NULL on success
 */
static error_t *create_commit(
    worktree_handle_t *wt,
    const cmd_add_options_t *opts,
    string_array_t *added_files,
    const config_t *config,
    git_oid *out_commit_oid
) {
    CHECK_NULL(wt);
    CHECK_NULL(opts);
    CHECK_NULL(added_files);

    /* Build commit message using storage paths */
    string_array_t *storage_paths = string_array_new(0);
    if (!storage_paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
    }

    /* Convert filesystem paths to storage paths for commit message */
    error_t *err = NULL;
    for (size_t i = 0; i < added_files->count; i++) {
        const char *file_path = added_files->items[i];
        char *storage_path = NULL;
        path_prefix_t prefix;

        err = path_to_storage(
            file_path, opts->custom_prefix, &storage_path, &prefix
        );
        if (err) {
            /* Skip if conversion fails (shouldn't happen at this point) */
            error_free(err);
            continue;
        }

        err = string_array_push(storage_paths, storage_path);
        free(storage_path);
        if (err) {
            error_free(err);
            break;
        }
    }

    /* Build commit message context */
    commit_message_context_t ctx = {
        .action        = COMMIT_ACTION_ADD,
        .profile       = opts->profile,
        .files         = storage_paths->items,
        .file_count    = storage_paths->count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };

    char *message = build_commit_message(config, &ctx);
    string_array_free(storage_paths);

    if (!message) {
        return ERROR(ERR_MEMORY, "Failed to build commit message");
    }

    /* Create commit */
    err = worktree_commit(wt, opts->profile, message, out_commit_oid);
    free(message);

    if (err) {
        return error_wrap(err, "Failed to create commit");
    }

    return NULL;
}

/**
 * Auto-enable newly created profile and sync files to manifest
 *
 * Called when `dotta add -p <profile>` creates a NEW profile branch for the first
 * time. Combines profile enabling with manifest sync in a single atomic transaction.
 *
 * WHY manifest_add_files (not manifest_apply_scope):
 * - These files were just captured FROM disk; the deployment anchor
 *   (deployed_blob_oid, stat_*, deployed_at) should be stamped from that
 *   witness so the next status hits the fast path.
 * - manifest_apply_scope is a pure VWD-cache writer; it never advances the
 *   anchor, which is correct for scope reconciliation but wrong here — we
 *   want fully deployed rows, not staged-for-deployment rows.
 *
 * Algorithm:
 *   1. Open write transaction (creates DB if missing)
 *   2. Read enabled profiles under the transaction snapshot
 *   3. If already enabled: commit (no-op) and return
 *   4. Enable profile in state with custom prefix (makes prefix available)
 *   5. Sync files to manifest with DEPLOYED status (uses custom_prefix;
 *      advances deployment anchor for synced entries)
 *   6. Commit transaction atomically
 *
 * CRITICAL ORDER: Step 4 must precede step 5. The custom_prefix stored in step 4
 * is required by manifest_add_files() in step 5 (which loads the prefix map
 * internally) to resolve custom/ storage paths. Transaction atomicity ensures:
 * enable + sync succeed together or fail together (automatic rollback on error).
 *
 * @param repo Git repository (must not be NULL)
 * @param profile Profile to auto-enable (must not be NULL, must exist in Git)
 * @param custom_prefix Custom prefix for custom/ files (can be NULL)
 * @param added_files Filesystem paths that were added (must not be NULL)
 * @param out_updated Output flag: true if successful (must not be NULL)
 * @param out_synced Output: count of files synced (can be NULL)
 * @return Error or NULL on success (non-fatal - caller treats as warning)
 */
static error_t *auto_enable_and_sync_profile(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const char *profile,
    const char *custom_prefix,
    const string_array_t *added_files,
    bool *out_updated,
    size_t *out_synced
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(profile);
    CHECK_NULL(added_files);
    CHECK_NULL(out_updated);

    error_t *err = NULL;
    string_array_t *enabled_profiles = NULL;
    size_t synced_count = 0;

    *out_updated = false;
    if (out_synced) {
        *out_synced = 0;
    }

    /* STEP 1: Read enabled profiles from the state dispatcher (WRITE) */
    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* STEP 2: Check if already enabled (defensive) */
    for (size_t i = 0; i < enabled_profiles->count; i++) {
        if (strcmp(enabled_profiles->items[i], profile) == 0) {
            /* Already enabled - idempotent success. The dispatcher's
             * state_free rolls back the untouched transaction. */
            *out_updated = true;
            goto cleanup;
        }
    }

    /* Append new profile to enabled list for manifest_add_files precedence */
    err = string_array_push(enabled_profiles, profile);
    if (err) {
        err = error_wrap(err, "Failed to add profile to enabled list");
        goto cleanup;
    }

    /* STEP 3: Enable profile in state with custom prefix (if provided).
     *
     * CRITICAL ORDER: Must enable BEFORE manifest sync so custom_prefix
     * is available in state for path resolution during manifest_add_files().
     * The custom prefix is stored in the enabled_profiles table and loaded
     * internally by the manifest layer to resolve custom/ storage paths.
     *
     * Transaction Safety: If manifest sync below fails, the dispatcher's
     * state_free automatically rolls back this change. */
    err = state_enable_profile(state, profile, custom_prefix);
    if (err) {
        err = error_wrap(err, "Failed to enable profile in state");
        goto cleanup;
    }

    /* STEP 4: Sync files to manifest with DEPLOYED status
     *
     * manifest_add_files() loads the prefix map internally to build the
     * manifest. The custom_prefix stored in STEP 3 is now available for
     * resolving custom/ storage paths via path_from_storage().
     *
     * manifest_add_files advances the deployment anchor internally for
     * synced entries, so the next status can short-circuit on the fast
     * path without an extra pass here.
     *
     * Precedence: If this profile has lower precedence than existing enabled
     * profiles, some files may be skipped (synced_count < added_files). Those
     * skipped entries correctly receive no anchor advance — any disk stat
     * captured at this site would misattribute to the winner's blob_oid. */
    err = manifest_add_files(
        repo,
        state,
        arena,
        profile,
        added_files,
        enabled_profiles,
        &synced_count
    );
    if (err) {
        err = error_wrap(err, "Failed to sync files to manifest");
        goto cleanup;
    }

    /* STEP 5: Commit transaction atomically */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to commit transaction");
        goto cleanup;
    }

    /* Success */
    *out_updated = true;
    if (out_synced) *out_synced = synced_count;

cleanup:
    if (enabled_profiles) {
        string_array_free(enabled_profiles);
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
 *   1. Read enabled profiles under the borrowed write transaction
 *   2. If profile not enabled: return (dispatcher's state_free rolls back)
 *   3. If custom_prefix provided: update prefix in state (UPSERT)
 *   4. Call manifest_add_files() (builds fresh manifest internally;
 *      advances deployment anchor for synced entries)
 *   5. Commit transaction (state_save)
 *
 * Custom Prefix Update:
 *   When adding custom/ files to an already-enabled profile, the custom_prefix
 *   must be stored in state BEFORE manifest_add_files(). This is the same
 *   prefix-before-sync ordering enforced by auto_enable_and_sync_profile().
 *   Only called when custom_prefix is non-NULL to avoid clearing an existing
 *   prefix when adding home/ or root/ files.
 *
 * Lifecycle Tracking:
 *   Files get deployed_at = time(NULL) because ADD captures files FROM the
 *   filesystem. They're already at their target locations, so deployed_at
 *   is set to indicate dotta knows about them.
 *
 * Error Handling:
 *   - Profile not enabled → rollback transaction, return NULL (success, no update)
 *   - Manifest sync fails → rollback, return error
 *
 * Non-Fatal Integration:
 *   Caller should treat manifest update failure as non-fatal warning.
 *   Git commit already succeeded; user can repair with `profile enable`.
 *
 * Performance: O(M + N) where M = total files in all profiles, N = files added
 *
 * @param repo Git repository
 * @param profile Profile that files were added to
 * @param custom_prefix Custom prefix for custom/ files (can be NULL)
 * @param added_files Filesystem paths that were added
 * @param out_updated Output flag: true if manifest was updated (must not be NULL)
 * @param out_synced Output: count of files synced (can be NULL)
 * @return Error or NULL on success
 */
static error_t *update_manifest_after_add(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const char *profile,
    const char *custom_prefix,
    const string_array_t *added_files,
    bool *out_updated,
    size_t *out_synced
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(profile);
    CHECK_NULL(added_files);
    CHECK_NULL(out_updated);

    error_t *err = NULL;
    string_array_t *enabled_profiles = NULL;

    /* Initialize output */
    *out_updated = false;

    /* STEP 1: Read enabled profiles from the state dispatcher (WRITE) */
    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* STEP 2: Check if this profile is enabled */
    bool is_enabled = false;
    for (size_t i = 0; i < enabled_profiles->count; i++) {
        if (strcmp(enabled_profiles->items[i], profile) == 0) {
            is_enabled = true;
            break;
        }
    }

    if (!is_enabled) {
        /* Profile not enabled - skip manifest update (this is success).
         * The dispatcher's state_free rolls back the untouched
         * transaction. */
        goto cleanup;
    }

    /* STEP 3: Update custom prefix in state if adding custom/ files
     *
     * CRITICAL ORDER: Must store prefix BEFORE manifest_add_files() so
     * the prefix map (loaded internally) can resolve custom/ storage paths
     * during manifest building. Same prefix-before-sync ordering as
     * auto_enable_and_sync_profile().
     *
     * Only called when custom_prefix is non-NULL to avoid clearing an
     * existing prefix when adding home/ or root/ files.
     * state_enable_profile() uses UPSERT - safe on already-enabled profiles. */
    if (custom_prefix) {
        err = state_enable_profile(state, profile, custom_prefix);
        if (err) {
            err = error_wrap(err, "Failed to update custom prefix for profile");
            goto cleanup;
        }
    }

    /* STEP 4: Bulk sync operation (O(M+N))
     *
     * manifest_add_files advances the deployment anchor internally for
     * synced entries. Entries skipped by precedence correctly receive
     * no anchor advance, so the winning profile's anchor stays
     * untouched. */
    size_t synced_count = 0;
    err = manifest_add_files(
        repo,
        state,
        arena,
        profile,
        added_files,
        enabled_profiles,
        &synced_count
    );

    if (err) {
        err = error_wrap(err, "Failed to sync files to manifest");
        goto cleanup;
    }

    /* STEP 5: Commit transaction */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to save manifest updates");
        goto cleanup;
    }

    /* Success */
    *out_updated = true;
    if (out_synced) *out_synced = synced_count;

cleanup:
    if (enabled_profiles) {
        string_array_free(enabled_profiles);
    }
    /* state is borrowed from the dispatcher. If state_save above
     * succeeded the transaction is committed; otherwise the
     * dispatcher's state_free rolls it back. */

    return err;
}

/**
 * Add command implementation
 */
error_t *cmd_add(const dotta_ctx_t *ctx, const cmd_add_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->state);

    git_repository *repo = ctx->repo;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    error_t *err = validate_options(opts);
    if (err) return err;

    /* Initialize all resources to NULL for safe cleanup */
    ignore_rules_t *ignore_rules = NULL;
    const gitignore_ruleset_t *profile_rules = NULL;
    source_filter_t *source_filter = NULL;
    worktree_handle_t *wt = NULL;
    string_array_t *all_files = NULL;
    string_array_t *all_directories = NULL;
    size_t added_count = 0;
    bool profile_was_new = false;
    metadata_t *metadata = NULL;

    /* Pre-flight privilege check arrays */
    char **preflight_storage_paths = NULL;
    char **preflight_allocated_paths = NULL;
    size_t preflight_storage_count = 0;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Validate custom prefix if provided */
    if (opts->custom_prefix) {
        err = path_validate_custom_prefix(opts->custom_prefix);
        if (err) goto cleanup;
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
            str_starts_with(file_path, "root/") || str_starts_with(file_path, "custom/")) {
            bool needs_elevation = str_starts_with(file_path, "root/") ||
                (str_starts_with(file_path, "custom/") && custom_needs_elevation);

            if (!needs_elevation) continue;

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
            /* A directory input equal to a classification root ($HOME, "/",
             * or --prefix) has no storage representation; path_to_storage
             * returns ERR_INVALID_ARG. The main loop's walker will still
             * expand its descendants — the metadata path handles that fine.
             *
             * What DOES need handling here: the pre-flight's only question
             * is "will this op touch a path that needs elevation?" If the
             * custom prefix needs elevation, the expanded descendants will
             * land under custom/, so we stub ONE representative "custom/"
             * entry as a proxy. Without this, a directory-typed input would
             * bypass the privilege check entirely.
             *
             * Known pre-existing gap: `dotta add /` as non-root with no
             * --prefix takes this branch for the root/ classification root;
             * the sentinel only fires for custom/, so root/ elevation is
             * missed in that edge case. Very unusual input, not addressed. */
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
        preflight_storage_paths, preflight_storage_count, "add",
        true, ctx->argc, ctx->argv, out
    );

    if (err) {
        /* User declined elevation or non-interactive mode blocked it */
        goto cleanup;
    }

    /* If we reach here, privileges are OK - proceed with operation */

    /* Build ignore rules once per command.
     *
     * Fatal on failure: if we cannot build the ignore rules, proceeding
     * would risk tracking files the user explicitly told us to ignore
     * (via baseline, profile, config, or CLI). Surface the error.
     *
     * The profile-specific ruleset (which layers the profile's own
     * `.dottaignore` on top of the common layers) is resolved below,
     * after the branch exists — for a brand-new profile the builder
     * would otherwise try to load a non-existent branch (a non-error,
     * but no point walking that code path). */
    err = ignore_rules_create(
        repo, config,
        opts->exclude_patterns, opts->exclude_count,
        ctx->arena, &ignore_rules
    );
    if (err) {
        err = error_wrap(err, "Failed to build ignore rules");
        goto cleanup;
    }

    /* Source-tree .gitignore filter (opt-in via config).
     *
     * Built once per command and shared across the whole collection
     * walk so the discovered source-repo handle is reused for every
     * file under the same source tree. A non-fatal build failure leaves
     * source_filter NULL, which is_excluded() treats as "layer skipped". */
    if (config && config->respect_gitignore) {
        err = source_filter_create(&source_filter);
        if (err) {
            err = error_wrap(err, "Failed to build source .gitignore filter");
            goto cleanup;
        }
    }

    /* Build hook invocation */
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_ADD,
        .profile    = opts->profile,
        .files      = opts->files,
        .file_count = opts->file_count,
        .dry_run    = false,
    };

    /* Execute pre-add hook */
    err = hook_fire_pre(config, out, ctx->repo_path, &hook_inv);
    if (err) goto cleanup;

    /* Create temporary worktree */
    err = worktree_create_temp(repo, &wt);
    if (err) {
        err = error_wrap(err, "Failed to create temporary worktree");
        goto cleanup;
    }

    /* Checkout or create profile branch */
    bool profile_exists = false;
    err = gitops_branch_exists(repo, opts->profile, &profile_exists);
    if (err) goto cleanup;

    if (profile_exists) {
        err = worktree_checkout_branch(wt, opts->profile);
    } else {
        err = worktree_create_orphan(wt, opts->profile);
        profile_was_new = true;  /* Profile is newly created */
    }

    if (err) {
        err = error_wrap(
            err, "Failed to prepare profile branch '%s'",
            opts->profile
        );
        goto cleanup;
    }

    /* Initialize .dottaignore for new profiles */
    if (!profile_exists) {
        err = ignore_seed_profile(wt);
        if (err) {
            err = error_wrap(
                err, "Failed to initialize .dottaignore for profile '%s'",
                opts->profile
            );
            goto cleanup;
        }
        output_info(
            out, OUTPUT_VERBOSE, "Created .dottaignore for profile '%s'",
            opts->profile
        );
    }

    /* Resolve the profile-specific ruleset. Safe for both paths:
     * existing profile → loads the profile's `.dottaignore`; new
     * profile → branch doesn't exist yet, builder treats that as
     * "no profile layer" and the common layers still apply. */
    err = ignore_rules_for_profile(ignore_rules, opts->profile, &profile_rules);
    if (err) {
        err = error_wrap(
            err, "Failed to load ignore rules for profile '%s'", opts->profile
        );
        goto cleanup;
    }

    /* Collect all files to add (expanding directories).
     * The walker appends to both arrays; the caller owns both. */
    all_files = string_array_new(0);
    all_directories = string_array_new(0);
    if (!all_files || !all_directories) {
        err = ERROR(ERR_MEMORY, "Failed to allocate collection arrays");
        goto cleanup;
    }

    /* Process each input path */
    for (size_t i = 0; i < opts->file_count; i++) {
        const char *file = opts->files[i];
        char *absolute = NULL;

        /* Check if input is a storage path */
        if (str_starts_with(file, "home/") ||
            str_starts_with(file, "root/") || str_starts_with(file, "custom/")) {

            /* Determine if we need custom prefix for this storage path */
            const char *prefix_for_conversion = NULL;
            if (str_starts_with(file, "custom/")) {
                /* custom/ paths require --prefix flag */
                prefix_for_conversion = opts->custom_prefix;

                if (!prefix_for_conversion || prefix_for_conversion[0] == '\0') {
                    err = ERROR(
                        ERR_INVALID_ARG, "Storage path '%s' requires --prefix flag\n"
                        "Usage: dotta add -p %s --prefix /path/to/target %s",
                        file, opts->profile, file
                    );
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
            /* Remember counts so we can describe what the walk produced. */
            size_t files_before = all_files->count;
            size_t dirs_before = all_directories->count;

            err = collect_tree(
                absolute, profile_rules, source_filter, out,
                all_files, all_directories
            );
            if (err) {
                free(absolute);
                err = error_wrap(err, "Failed to collect from '%s'", file);
                goto cleanup;
            }

            /* Diagnostic: the walker always pushes the CLI-arg directory
             * itself, so all_directories grows by at least one. The file
             * count reflects whether anything trackable was inside. */
            if (all_files->count == files_before &&
                all_directories->count == dirs_before + 1) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Directory has no trackable contents (tracking dir only): %s",
                    absolute
                );
            } else if (all_files->count == files_before) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "All files excluded (tracking directory tree only): %s",
                    absolute
                );
            } else {
                output_info(out, OUTPUT_VERBOSE, "Added directory: %s", absolute);
            }
        } else {
            /* Single file or symlink - check if excluded */
            if (is_excluded(absolute, false, profile_rules, source_filter, out)) {
                output_info(out, OUTPUT_VERBOSE, "Excluded: %s", absolute);
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

    /* Check if we have anything to add (files or directories).
     * all_directories may contain classification-root entries that Phase 3
     * skips, but it also captures descendants — so a non-empty array is
     * sufficient evidence that the walk produced something worth committing. */
    if (all_files->count == 0 && all_directories->count == 0) {
        if (opts->exclude_count > 0) {
            err = ERROR(
                ERR_INVALID_ARG,
                "No files or directories to add (all excluded by patterns)"
            );
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
            if (err) goto cleanup;
        } else {
            /* Real error - propagate */
            err = error_wrap(err, "Failed to load existing metadata");
            goto cleanup;
        }
    }

    /* Single-pass: add files and capture metadata inline */
    for (size_t i = 0; i < all_files->count; i++) {
        const char *file_path = all_files->items[i];

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
         * ARCHITECTURE: add_file_to_worktree handles both operations atomically,
         * sharing stat() data between content and metadata layers to eliminate TOCTOU */
        err = add_file_to_worktree(
            wt, file_path, storage_path, opts, ctx->keymgr, config, metadata, out
        );
        if (err) {
            free(storage_path);
            err = error_wrap(err, "Failed to add file '%s'", file_path);
            goto cleanup;
        }

        free(storage_path);
        added_count++;
    }

    /* Capture directory metadata for every walked directory.
     *
     * Iterates `all_directories` (filesystem paths produced by the walker)
     * and converts each to a storage path here. The walker records every
     * directory it walks into — including the CLI-arg top-level — so this
     * loop captures the full tree, not just the CLI-named entry points.
     *
     * Classification roots ($HOME, "/", --prefix) have no storage-path
     * representation: path_to_storage returns ERR_INVALID_ARG and we skip
     * them by design. Their descendants are captured normally.
     */
    size_t dir_tracked_count = 0;
    for (size_t i = 0; i < all_directories->count; i++) {
        const char *filesystem_path = all_directories->items[i];

        char *storage_path = NULL;
        path_prefix_t prefix;
        err = path_to_storage(filesystem_path, opts->custom_prefix, &storage_path, &prefix);
        if (err) {
            /* Classification root (filesystem_path equals $HOME, "/", or --prefix):
             * no storage encoding exists. Skip the root itself; its descendants
             * appear as separate entries and are captured normally. The error
             * message in path.c:path_classify makes this semantic explicit. */
            if (err->code == ERR_INVALID_ARG) {
                error_free(err);
                err = NULL;
                continue;
            }
            err = error_wrap(
                err, "Failed to convert directory path '%s'", filesystem_path
            );
            goto cleanup;
        }

        /* Stat directory to capture mode (and ownership if root/custom). */
        struct stat dir_stat;
        if (stat(filesystem_path, &dir_stat) != 0) {
            output_warning(
                out, OUTPUT_VERBOSE, "Failed to stat directory '%s': %s",
                filesystem_path, strerror(errno)
            );
            free(storage_path);
            continue;
        }

        /* Capture directory metadata using stat data */
        metadata_item_t *dir_item = NULL;
        err = metadata_capture_from_directory(storage_path, &dir_stat, &dir_item);
        if (err) {
            /* Non-fatal: log warning and continue */
            output_warning(
                out, OUTPUT_VERBOSE,
                "Failed to capture metadata for directory '%s': %s",
                filesystem_path, error_message(err)
            );
            error_free(err);
            err = NULL;
            free(storage_path);
            continue;
        }

        /* Verbose output before consuming the item */
        if (dir_item->owner || dir_item->group) {
            output_info(
                out, OUTPUT_VERBOSE,
                "Captured directory metadata: %s (mode: %04o, owner: %s:%s)",
                filesystem_path, dir_item->mode,
                dir_item->owner ? dir_item->owner : "?",
                dir_item->group ? dir_item->group : "?"
            );
        } else {
            output_info(
                out, OUTPUT_VERBOSE,
                "Captured directory metadata: %s (mode: %04o)",
                filesystem_path, dir_item->mode
            );
        }

        /* Add directory to metadata */
        err = metadata_add_item(metadata, dir_item);
        metadata_item_free(dir_item);

        if (err) {
            /* Non-fatal: log warning and continue */
            output_warning(
                out, OUTPUT_VERBOSE, "Failed to track directory '%s': %s",
                filesystem_path, error_message(err)
            );
            error_free(err);
            err = NULL;
        } else {
            dir_tracked_count++;
            output_info(
                out, OUTPUT_VERBOSE, "Tracked directory: %s -> %s",
                filesystem_path, storage_path
            );
        }
        free(storage_path);
    }

    /* Save metadata to worktree */
    err = metadata_save_to_worktree(worktree_path, metadata);
    if (err) {
        err = error_wrap(err, "Failed to save metadata");
        goto cleanup;
    }

    /* Stage metadata.json file */
    err = worktree_stage_file(wt, METADATA_FILE_PATH);
    if (err) {
        err = error_wrap(err, "Failed to stage metadata");
        goto cleanup;
    }

    /* Verbose summary */
    if (dir_tracked_count > 0) {
        output_info(
            out, OUTPUT_VERBOSE,
            "Tracked %zu director%s for change detection",
            dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies"
        );
    }

    /* Create commit */
    err = create_commit(wt, opts, all_files, config, NULL);
    if (err) goto cleanup;

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
         * Uses manifest_add_files (not manifest_apply_scope) because the files
         * were just captured from disk: we want the deployment anchor stamped
         * from that witness, not left unset for a later status to fill in.
         * apply_scope is the scope reconciler; add is the disk-capture path.
         */
        error_t *enable_err = auto_enable_and_sync_profile(
            repo, ctx->state, ctx->arena, opts->profile, opts->custom_prefix,
            all_files, &manifest_updated, &manifest_synced_count
        );

        if (enable_err) {
            /* Non-fatal: Git commit succeeded, user can manually enable later */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to auto-enable profile: %s",
                error_message(enable_err)
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile enable %s' to enable manually",
                opts->profile
            );
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
            repo, ctx->state, ctx->arena, opts->profile, opts->custom_prefix,
            all_files, &manifest_updated, &manifest_synced_count
        );

        if (manifest_err) {
            /* Non-fatal: Git commit succeeded */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to update manifest: %s",
                error_message(manifest_err)
            );
            output_info(
                out, OUTPUT_NORMAL, "Files committed to Git successfully"
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile enable %s' to sync manifest",
                opts->profile
            );
            error_free(manifest_err);
            manifest_updated = false;
            manifest_synced_count = 0;
        }
    }

    /* Cleanup worktree before post-processing */
    worktree_cleanup(&wt);

    /* Execute post-add hook */
    hook_fire_post(config, out, ctx->repo_path, &hook_inv);

    /* Show summary on success */
    if ((added_count > 0 || dir_tracked_count > 0)) {
        /* Primary success message */
        if (added_count > 0) {
            output_success(
                out, OUTPUT_NORMAL, "Added %zu file%s to profile '%s'",
                added_count, added_count == 1 ? "" : "s",
                opts->profile
            );
        } else {
            /* Directory-only add */
            output_success(
                out, OUTPUT_NORMAL, "Tracking %zu director%s in profile '%s'",
                dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies",
                opts->profile
            );
        }

        if (profile_was_new) {
            output_success(
                out, OUTPUT_NORMAL, "Profile '%s' created and enabled",
                opts->profile
            );
        }

        /* Show directory tracking info only when files were also added */
        if (added_count > 0 && dir_tracked_count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Tracking %zu director%s for change detection",
                dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies"
            );
        }

        output_newline(out, OUTPUT_NORMAL);

        /* Manifest status feedback */
        if (manifest_updated) {
            if (added_count > 0) {
                /* Files were added */
                if (profile_was_new) {
                    /* New profile - show sync results with precedence awareness */
                    if (manifest_synced_count == added_count) {
                        output_info(
                            out, OUTPUT_NORMAL,
                            "Manifest updated (%zu file%s marked as deployed)",
                            manifest_synced_count, manifest_synced_count == 1 ? "" : "s"
                        );
                    } else {
                        output_info(
                            out, OUTPUT_NORMAL,
                            "Manifest updated (%zu/%zu file%s marked as deployed)",
                            manifest_synced_count, added_count, added_count == 1 ? "" : "s"
                        );

                        if (manifest_synced_count < added_count) {
                            size_t skipped = added_count - manifest_synced_count;
                            output_info(
                                out, OUTPUT_NORMAL,
                                "Note: %zu file%s overridden by higher-precedence profiles",
                                skipped, skipped == 1 ? "" : "s"
                            );
                        }
                    }
                } else {
                    /* Existing enabled profile */
                    if (manifest_synced_count == added_count) {
                        output_info(
                            out, OUTPUT_NORMAL,
                            "Manifest updated (%zu file%s marked as deployed)",
                            manifest_synced_count, manifest_synced_count == 1 ? "" : "s"
                        );
                    } else {
                        output_info(
                            out, OUTPUT_NORMAL,
                            "Manifest updated (%zu/%zu file%s marked as deployed)",
                            manifest_synced_count, added_count, added_count == 1 ? "" : "s"
                        );
                        if (manifest_synced_count < added_count) {
                            size_t skipped = added_count - manifest_synced_count;
                            output_info(
                                out, OUTPUT_NORMAL,
                                "Note: %zu file%s overridden by higher-precedence profiles",
                                skipped, skipped == 1 ? "" : "s"
                            );
                        }
                    }
                    output_hint(
                        out, OUTPUT_NORMAL,
                        "Files captured from filesystem (already deployed)"
                    );
                }
            } else {
                /* Directory-only add */
                output_info(
                    out, OUTPUT_NORMAL, "Manifest updated (%zu director%s synced)",
                    dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies"
                );
            }
            output_hint(out, OUTPUT_NORMAL, "Run 'dotta status' to verify");
        } else {
            /* Existing disabled profile - original behavior */
            output_info(
                out, OUTPUT_NORMAL, "Profile not enabled - manifest not updated"
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile enable %s' to activate and deploy",
                opts->profile
            );
        }
    }

cleanup:
    /* Free resources in reverse order of allocation */
    if (metadata) metadata_free(metadata);
    if (all_directories) string_array_free(all_directories);
    if (all_files) string_array_free(all_files);
    if (wt) worktree_cleanup(&wt);
    source_filter_free(source_filter);
    ignore_rules_free(ignore_rules);
    if (preflight_allocated_paths) {
        for (size_t i = 0; i < preflight_storage_count; i++) {
            free(preflight_allocated_paths[i]);
        }
        free(preflight_allocated_paths);
    }
    if (preflight_storage_paths) free(preflight_storage_paths);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `profile` and `files[]`.
 *
 * Two legacy-compatible cases:
 *   1. -p/--profile was given: every positional is a file path.
 *   2. -p not given: first positional is the profile, rest are files.
 *
 * All validation lives here (not in a separate `validate` hook) so
 * the error message can reference the effective invariant rather
 * than a raw count.
 */
static error_t *add_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_add_options_t *o = opts_v;

    if (o->profile != NULL) {
        o->files = o->positional_args;
        o->file_count = o->positional_count;
    } else {
        if (o->positional_count == 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "profile name is required (as first positional or via -p)"
            );
        }
        o->profile = o->positional_args[0];
        o->files = o->positional_args + 1;
        o->file_count = o->positional_count - 1;
    }

    if (o->file_count == 0) {
        return ERROR(
            ERR_INVALID_ARG, "at least one file is required"
        );
    }
    return NULL;
}

static error_t *add_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_add(ctx, (const cmd_add_options_t *) opts_v);
}

static const args_opt_t add_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",          "<name>",
        cmd_add_options_t,    profile,
        "Profile name (alternative to positional)"
    ),
    ARGS_STRING(
        "prefix",             "<path>",
        cmd_add_options_t,    custom_prefix,
        "Declare a relocatable storage root"
    ),
    ARGS_STRING(
        "m message",          "<msg>",
        cmd_add_options_t,    message,
        "Commit message"
    ),
    ARGS_APPEND(
        "e exclude",          "<pattern>",
        cmd_add_options_t,    exclude_patterns, exclude_count,
        "Skip matching files (glob, repeatable)"
    ),
    ARGS_FLAG(
        "f force",
        cmd_add_options_t,    force,
        "Overwrite existing entries in the profile"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_add_options_t,    verbose,
        "Verbose output"
    ),
    ARGS_FLAG_SET(
        "encrypt",
        cmd_add_options_t,    encrypt_mode,
        ADD_ENCRYPT_FORCE_ON,
        "Force encryption for the given files"
    ),
    ARGS_FLAG_SET(
        "no-encrypt",
        cmd_add_options_t,    encrypt_mode,
        ADD_ENCRYPT_FORCE_OFF,
        "Bypass auto-encryption patterns"
    ),
    /* <profile> <file|dir>... — order-dependent, first is profile.
     * Mirrors clone's raw-bucket-plus-post_parse approach. */
    ARGS_POSITIONAL_RAW(
        cmd_add_options_t,    positional_args,  positional_count,
        0,                    0
    ),
    ARGS_END,
};

const args_command_t spec_add = {
    .name        = "add",
    .summary     = "Add files or directories to a profile",
    .usage       =
        "%s add [options] <profile> <file|dir>...\n"
        "   or: %s add [options] --profile <name> <file|dir>...",
    .description =
        "Import files or directories into a profile branch. The storage\n"
        "prefix derives from the source path — home/ under $HOME, root/\n"
        "otherwise — unless --prefix declares a relocatable root, in\n"
        "which case files are stored as custom/<path-relative-to-root>.\n"
        "Metadata (mode, owner) is captured outside HOME.\n",
    .notes       =
        "Exclude Patterns:\n"
        "  Glob syntax with *, ?, [abc]. Flag is repeatable.\n"
        "    --exclude '*.log'                    # Skip .log files\n"
        "    --exclude '.git/*'                   # Skip .git directory\n"
        "    --exclude '*.log' --exclude '*.tmp'  # Multiple patterns\n",
    .examples    =
        "  %s add global ~/.bashrc                   # Basic add\n"
        "  %s add darwin ~/.config/nvim              # Directory\n"
        "  %s add global ~/.ssh/config -e '*.pub'    # With exclude\n"
        "  %s add global ~/.ssh/id_rsa --encrypt     # Force encryption\n"
        "  %s add web /mnt/jails/web/nginx.conf --prefix /mnt/jails/web\n",
    .epilogue    =
        "See also:\n"
        "  %s key set                 # Set encryption passphrase\n"
        "  %s apply                   # Deploy the new entries\n",
    .opts_size   = sizeof(cmd_add_options_t),
    .opts        = add_opts,
    .post_parse  = add_post_parse,
    .payload     = &dotta_ext_write_key,
    .dispatch    = add_dispatch,
};
