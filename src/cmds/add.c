/**
 * add.c - Add files to profiles
 */

#include "add.h"

#include <dirent.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/ignore.h"
#include "core/metadata.h"
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
                output_warning(out, "Ignore check failed for %s: %s",
                              path, error_message(err));
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
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Build full path */
        char *full_path = str_format("%s/%s", dir_path, entry->d_name);
        if (!full_path) {
            string_array_free(files);
            closedir(dir);
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }

        /* Check if directory or file (needed for ignore check) */
        bool is_dir = fs_is_directory(full_path);

        /* Check exclude patterns */
        if (is_excluded(full_path, is_dir, ignore_ctx, opts, out)) {
            if (opts->verbose && out) {
                output_info(out, "Excluded: %s", full_path);
            }
            free(full_path);
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
                string_array_push(files, string_array_get(subdir_files, i));
            }
            string_array_free(subdir_files);
        } else {
            /* Add file to list */
            string_array_push(files, full_path);
            free(full_path);
        }
    }

    closedir(dir);
    *out_files = files;
    return NULL;
}

/**
 * Add single file to worktree
 *
 * @param wt Worktree handle
 * @param filesystem_path Source path on filesystem
 * @param storage_path Pre-computed storage path (e.g., "home/.bashrc")
 * @param opts Command options
 * @param km Key manager (for encryption, can be NULL if encryption disabled)
 * @param config Configuration (for auto-encrypt patterns only, can be NULL)
 * @param entry Metadata entry (updated with encryption status, can be NULL for symlinks)
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
    metadata_entry_t *entry,
    output_ctx_t *out
) {
    CHECK_NULL(wt);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(opts);

    error_t *err = NULL;

    /* Build destination path in worktree */
    const char *wt_path = worktree_get_path(wt);
    char *dest_path = str_format("%s/%s", wt_path, storage_path);
    if (!dest_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate destination path");
    }

    /* Handle existing files */
    if (fs_lexists(dest_path)) {
        if (!opts->force) {
            error_t *err = ERROR(ERR_EXISTS,
                        "File '%s' (as '%s') already exists in profile '%s'. Use --force to overwrite.",
                        filesystem_path, storage_path, opts->profile);
            free(dest_path);
            return err;
        }
        err = fs_remove_file(dest_path);
        if (err) {
            error_t *wrapped_err = error_wrap(err, "Failed to remove existing file '%s' in worktree", dest_path);
            free(dest_path);
            return wrapped_err;
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
    } else {
        /* Regular file - determine encryption policy using centralized logic */
        bool should_encrypt = false;
        err = encryption_policy_should_encrypt(
            config,
            storage_path,
            opts->encrypt,
            opts->no_encrypt,
            NULL,  /* No metadata for add command (new files) */
            &should_encrypt
        );
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to determine encryption policy for '%s'", storage_path);
        }

        /* Store file to worktree with optional encryption (handles read → encrypt → write) */
        err = content_store_file_to_worktree(
            filesystem_path,
            dest_path,
            storage_path,
            opts->profile,
            km,
            should_encrypt
        );
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to store file to worktree");
        }

        /* Update metadata entry with encryption status */
        if (entry) {
            entry->encrypted = should_encrypt;
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
        return error_from_git(git_err);
    }

    free(dest_path);
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

    error_t *err = buffer_append(content, (const uint8_t *)template_content, strlen(template_content));

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
    char *storage_prefix;
} tracked_dir_t;

/**
 * Create commit in worktree
 */
static error_t *create_commit(
    git_repository *repo,
    worktree_handle_t *wt,
    const cmd_add_options_t *opts,
    string_array_t *added_files,
    const dotta_config_t *config
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

        derr = path_to_storage(file_path, &storage_path, &prefix);
        if (derr) {
            /* Skip if conversion fails (shouldn't happen at this point) */
            error_free(derr);
            continue;
        }

        string_array_push(storage_paths, storage_path);
        free(storage_path);
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

    return NULL;
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
    size_t metadata_count = 0;
    bool profile_was_new = false;
    metadata_t *metadata = NULL;
    keymanager_t *key_mgr = NULL;

    /* Load configuration for hooks and ignore patterns */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue without config */
        error_free(err);
        err = NULL;
        config = config_create_default();
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

    /* Create ignore context */
    err = ignore_context_create(
        repo,
        config,
        opts->profile,
        opts->exclude_patterns,
        opts->exclude_count,
        &ignore_ctx
    );
    if (err) {
        /* Non-fatal: continue without ignore context */
        if (opts->verbose && out) {
            output_warning(out, "Failed to create ignore context: %s",
                          error_message(err));
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
        hook_context_add_files(hook_ctx, opts->files, opts->file_count);

        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_PRE_ADD, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - abort operation */
            if (hook_result && hook_result->output && hook_result->output[0] && out) {
                output_printf(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
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
            err = error_wrap(err, "Failed to initialize .dottaignore for profile '%s'", opts->profile);
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
        char *canonical = NULL;

        /* Check if input is a storage path */
        if (str_starts_with(file, "home/") || str_starts_with(file, "root/")) {
            /* Convert storage path to filesystem path */
            char *fs_path = NULL;
            err = path_from_storage(file, &fs_path);
            if (err) {
                err = error_wrap(err, "Failed to convert storage path '%s'", file);
                goto cleanup;
            }

            /* Canonicalize the filesystem path */
            err = fs_canonicalize_path(fs_path, &canonical);
            free(fs_path);
            if (err) {
                err = error_wrap(err, "Failed to resolve path '%s'", file);
                goto cleanup;
            }
        } else {
            /* Regular filesystem path - canonicalize directly */
            err = fs_canonicalize_path(file, &canonical);
            if (err) {
                err = error_wrap(err, "Failed to resolve path '%s'", file);
                goto cleanup;
            }
        }

        /* Check path exists */
        if (!fs_exists(canonical)) {
            free(canonical);
            err = ERROR(ERR_NOT_FOUND, "Path not found: %s", file);
            goto cleanup;
        }

        /* Handle directories vs files */
        if (fs_is_directory(canonical)) {
            /* Recursively collect files from directory */
            string_array_t *dir_files = NULL;
            err = collect_files_from_dir(canonical, opts, ignore_ctx, out, &dir_files);

            if (err) {
                free(canonical);
                err = error_wrap(err, "Failed to collect files from '%s'", file);
                goto cleanup;
            }

            /* Merge directory files into all_files */
            for (size_t j = 0; j < string_array_size(dir_files); j++) {
                string_array_push(all_files, string_array_get(dir_files, j));
            }
            string_array_free(dir_files);

            /* Track this directory for new file detection */
            char *storage_prefix = NULL;
            path_prefix_t prefix;
            err = path_to_storage(canonical, &storage_prefix, &prefix);
            if (err) {
                /* Non-fatal: just log warning */
                if (opts->verbose && out) {
                    output_warning(out, "Failed to compute storage prefix for directory '%s': %s",
                                  canonical, error_message(err));
                }
                error_free(err);
                err = NULL;
                free(canonical);
                continue;
            }

            /* Add to tracked directories list */
            if (tracked_dir_count >= tracked_dir_capacity) {
                size_t new_capacity = tracked_dir_capacity == 0 ? 8 : tracked_dir_capacity * 2;
                tracked_dir_t *new_dirs = realloc(tracked_dirs, new_capacity * sizeof(tracked_dir_t));
                if (!new_dirs) {
                    free(storage_prefix);
                    free(canonical);
                    err = ERROR(ERR_MEMORY, "Failed to allocate tracked directories");
                    goto cleanup;
                }
                tracked_dirs = new_dirs;
                tracked_dir_capacity = new_capacity;
            }

            tracked_dirs[tracked_dir_count].filesystem_path = strdup(canonical);
            tracked_dirs[tracked_dir_count].storage_prefix = storage_prefix;
            tracked_dir_count++;

            if (opts->verbose && out) {
                output_info(out, "Added directory: %s", canonical);
            }
        } else {
            /* Single file - check if excluded */
            if (is_excluded(canonical, false, ignore_ctx, opts, out)) {
                if (opts->verbose && out) {
                    output_info(out, "Excluded: %s", canonical);
                }
                free(canonical);
                continue;
            }

            /* Add to list */
            string_array_push(all_files, canonical);
        }

        free(canonical);
    }

    /* Check if we have any files to add */
    if (string_array_size(all_files) == 0) {
        if (opts->exclude_count > 0) {
            err = ERROR(ERR_INVALID_ARG, "No files to add (all files excluded by patterns)");
        } else {
            err = ERROR(ERR_INVALID_ARG, "No files to add");
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
    bool needs_encryption = opts->encrypt ||
                           (config && config->encryption_enabled &&
                            config->auto_encrypt_patterns &&
                            config->auto_encrypt_pattern_count > 0);

    if (needs_encryption && config && config->encryption_enabled) {
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
        err = path_to_storage(file_path, &storage_path, &prefix);
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

        /* Capture metadata FIRST (fail early before copying file) */
        metadata_entry_t *entry = NULL;
        err = metadata_capture_from_file(file_path, storage_path, &entry);
        if (err) {
            free(storage_path);
            err = error_wrap(err, "Failed to capture metadata for: %s", file_path);
            goto cleanup;
        }

        /* Add file to worktree (encryption handled transparently by content layer) */
        err = add_file_to_worktree(wt, file_path, storage_path, opts, key_mgr, config, entry, out);
        if (err) {
            if (entry) {
                metadata_entry_free(entry);
            }
            free(storage_path);
            err = error_wrap(err, "Failed to add file '%s'", file_path);
            goto cleanup;
        }

        /* Add metadata entry to collection (entry will be NULL for symlinks - that's ok) */
        if (entry) {
            /* Verbose output for metadata capture */
            if (opts->verbose && out) {
                if (entry->owner || entry->group) {
                    output_info(out, "Captured metadata: %s (mode: %04o, owner: %s:%s)",
                               file_path, entry->mode,
                               entry->owner ? entry->owner : "?",
                               entry->group ? entry->group : "?");
                } else {
                    output_info(out, "Captured metadata: %s (mode: %04o)",
                               file_path, entry->mode);
                }
            }

            err = metadata_add_entry(metadata, entry);
            metadata_entry_free(entry);

            if (err) {
                free(storage_path);
                err = error_wrap(err, "Failed to add metadata entry");
                goto cleanup;
            }

            metadata_count++;
        }

        free(storage_path);
        added_count++;
    }

    /* Handle tracked directories metadata */
    size_t dir_tracked_count = 0;
    for (size_t i = 0; i < tracked_dir_count; i++) {
        const tracked_dir_t *dir = &tracked_dirs[i];

        /* Capture directory metadata */
        metadata_directory_entry_t *dir_entry = NULL;
        err = metadata_capture_from_directory(
            dir->filesystem_path,
            dir->storage_prefix,
            &dir_entry
        );

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

        /* Verbose output before consuming the entry */
        if (opts->verbose && out) {
            if (dir_entry->owner || dir_entry->group) {
                output_info(out, "Captured directory metadata: %s (mode: %04o, owner: %s:%s)",
                           dir->filesystem_path, dir_entry->mode,
                           dir_entry->owner ? dir_entry->owner : "?",
                           dir_entry->group ? dir_entry->group : "?");
            } else {
                output_info(out, "Captured directory metadata: %s (mode: %04o)",
                           dir->filesystem_path, dir_entry->mode);
            }
        }

        /* Add directory to metadata */
        err = metadata_add_tracked_directory(
            metadata,
            dir_entry->filesystem_path,
            dir_entry->storage_prefix,
            dir_entry->added_at,
            dir_entry->mode,
            dir_entry->owner,
            dir_entry->group
        );

        metadata_directory_entry_free(dir_entry);

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
                           dir->filesystem_path, dir->storage_prefix);
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
    if (opts->verbose && out) {
        if (metadata_count > 0) {
            output_info(out, "Updated metadata for %zu file(s)", metadata_count);
        }
        if (dir_tracked_count > 0) {
            output_info(out, "Tracked %zu director%s for change detection",
                       dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies");
        }
    }

    /* Create commit */
    err = create_commit(repo, wt, opts, all_files, config);
    if (err) {
        goto cleanup;
    }

    /* Cleanup worktree before post-processing */
    worktree_cleanup(wt);
    wt = NULL;

    /* Execute post-add hook */
    if (hook_ctx) {
        hook_result_t *hook_result = NULL;
        error_t *hook_err = hook_execute(config, HOOK_POST_ADD, hook_ctx, &hook_result);

        if (hook_err) {
            /* Hook failed - warn but don't abort (files already added) */
            if (out) {
                output_warning(out, "Post-add hook failed: %s", error_message(hook_err));
                if (hook_result && hook_result->output && hook_result->output[0]) {
                    output_printf(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
                }
            }
            error_free(hook_err);
        }
        hook_result_free(hook_result);
    }

    /* Show summary on success */
    if (added_count > 0 && out) {
        output_success(out, "Added %zu file%s to profile '%s'",
                      added_count, added_count == 1 ? "" : "s", opts->profile);

        if (profile_was_new) {
            output_success(out, "Profile '%s' created", opts->profile);
        }

        if (tracked_dir_count > 0) {
            output_info(out, "Tracking %zu director%s for change detection",
                       tracked_dir_count, tracked_dir_count == 1 ? "y" : "ies");
        }

        output_newline(out);
        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "%sHint: Run 'dotta apply -p %s' to deploy files to filesystem%s\n",
                         output_color_code(out, OUTPUT_COLOR_DIM),
                         opts->profile,
                         output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_info(out, "Hint: Run 'dotta apply -p %s' to deploy files to filesystem", opts->profile);
        }
    }

cleanup:
    /* Free tracked directories */
    if (tracked_dirs) {
        for (size_t i = 0; i < tracked_dir_count; i++) {
            free(tracked_dirs[i].filesystem_path);
            free(tracked_dirs[i].storage_prefix);
        }
        free(tracked_dirs);
    }

    /* Free resources in reverse order of allocation */
    if (metadata) metadata_free(metadata);
    if (all_files) string_array_free(all_files);
    if (wt) worktree_cleanup(wt);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (repo_dir) free(repo_dir);
    if (ignore_ctx) ignore_context_free(ignore_ctx);
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}
