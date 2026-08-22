/**
 * remove.c - Remove files from profiles or delete profiles
 */

#include "cmds/remove.h"

#include <config.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "base/string.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "infra/worktree.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/commit.h"
#include "utils/hooks.h"

/**
 * Validate command options
 */
static error_t *validate_options(const cmd_remove_options_t *opts) {
    CHECK_NULL(opts);

    if (!opts->profile || opts->profile[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name is required");
    }

    /* If deleting profile, paths are optional */
    if (opts->delete_profile) {
        if (opts->paths && opts->path_count > 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "Cannot specify paths when using --delete-profile"
            );
        }
        return NULL;
    }

    /* If not deleting profile, paths are required */
    if (!opts->paths || opts->path_count == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "At least one path is required (or use --delete-profile)"
        );
    }

    return NULL;
}

/**
 * Resolve input paths to storage paths
 *
 * Accepts both filesystem paths and storage paths as input. Uses hashmap for
 * O(M+N) performance instead of O(N×M) nested loops.
 *
 * Complexity: O(M) to build index + O(N) to process inputs = O(M+N) Old
 * implementation: O(N×M) with nested loops
 *
 * @param mounts Per-machine mount table (must not be NULL). Caller passes
 *               ctx->mounts; the table covers HOME, ROOT, and every enabled
 *               profile's binding. Unenabled-profile lookups (custom/X) surface
 *               MOUNT_RESOLVE_UNBOUND, which the caller handles as "no filesystem
 *               path on this machine".
 */
static error_t *resolve_paths_to_remove(
    git_repository *repo,
    const char *profile,
    char **input_paths,
    size_t path_count,
    string_array_t **storage_paths_out,
    string_array_t **filesystem_paths_out,
    const cmd_remove_options_t *opts,
    output_t *out,
    const mount_table_t *mounts,
    arena_t *arena
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(input_paths);
    CHECK_NULL(storage_paths_out);
    CHECK_NULL(filesystem_paths_out);
    CHECK_NULL(opts);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    string_array_t *storage_paths = NULL;
    string_array_t *filesystem_paths = NULL;
    string_array_t *profile_files = NULL;
    hashmap_t *profile_files_map = NULL;

    /* Allocate arrays */
    storage_paths = string_array_new(0);
    filesystem_paths = string_array_new(0);
    if (!storage_paths || !filesystem_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate path arrays");
        goto cleanup;
    }

    /* Get list of files in profile */
    err = profile_list_files(repo, profile, &profile_files);
    if (err) {
        err = error_wrap(err, "Failed to list files in profile");
        goto cleanup;
    }

    /* Build hashmap index for O(1) lookups */
    profile_files_map = hashmap_borrow(profile_files->count);
    if (!profile_files_map) {
        err = ERROR(ERR_MEMORY, "Failed to create profile files index");
        goto cleanup;
    }

    for (size_t i = 0; i < profile_files->count; i++) {
        const char *file = profile_files->items[i];
        err = hashmap_set(profile_files_map, file, (void *) 1);  /* Dummy value */
        if (err) {
            err = error_wrap(err, "Failed to index profile files");
            goto cleanup;
        }
    }

    /* Process each input path */
    for (size_t i = 0; i < path_count; i++) {
        const char *input_path = input_paths[i];
        const char *storage_path = NULL;

        /* Resolve input path to storage format (file need not exist) */
        err = path_input_resolve(mounts, input_path, arena, &storage_path);
        if (err) {
            if (!opts->force) {
                goto cleanup;
            }
            /* With --force, skip this path */
            output_warning(
                out, OUTPUT_VERBOSE, "Skipping invalid path '%s': %s",
                input_path, error_message(err)
            );
            error_free(err);
            err = NULL;
            continue;
        }

        /* Try to get filesystem path for output. UNBOUND fires when the profile
         * has no --target on this machine; the storage path serves as fallback.
         * Genuine resolve errors (malformed input, OOM) are also non-fatal here
         * — same fallback. */
        mount_resolve_outcome_t canonical_outcome;
        const char *canonical = NULL;
        error_t *convert_err = mount_resolve(
            mounts, profile, storage_path, arena, &canonical_outcome, &canonical
        );
        if (convert_err) {
            error_free(convert_err);
            canonical = NULL;
        } else if (canonical_outcome == MOUNT_RESOLVE_UNBOUND) {
            canonical = NULL;
        }

        /* Find all files that match this path (exact match or directory prefix) */
        size_t matches_found = 0;
        size_t storage_path_len = strlen(storage_path);

        /* Check exact match first - O(1) with hashmap */
        if (hashmap_has(profile_files_map, storage_path)) {
            err = string_array_push(storage_paths, storage_path);
            if (!err) {
                /* If filesystem path unavailable (custom/ without prefix context),
                 * fall back to storage path. Downstream consumers handle
                 * gracefully: state lookups return "not found", display shows
                 * storage format. */
                err = string_array_push(filesystem_paths, canonical ? canonical : storage_path);
            }

            if (err) {
                err = error_wrap(err, "Failed to track path for removal");
                goto cleanup;
            }

            matches_found++;
        }

        /* Check for directory prefix matches - requires iteration */
        for (size_t j = 0; j < profile_files->count; j++) {
            const char *profile_file = profile_files->items[j];

            /* Skip if already matched as exact */
            if (strcmp(profile_file, storage_path) == 0) {
                continue;
            }

            /* Directory prefix match */
            if (str_starts_with(profile_file, storage_path)) {
                /* Ensure it's a directory boundary */
                if (profile_file[storage_path_len] == '/') {
                    /* Reconstruct filesystem path for this file. UNBOUND fires
                     * when the profile has no --target on this machine — fall
                     * back to the storage path so the hook context still names
                     * the file. */
                    mount_resolve_outcome_t file_outcome;
                    const char *file_fs_path = NULL;
                    err = mount_resolve(
                        mounts, profile, profile_file, arena,
                        &file_outcome, &file_fs_path
                    );
                    if (err) {
                        if (opts->verbose || !opts->force) {
                            output_warning(
                                out, OUTPUT_NORMAL,
                                "Failed to resolve filesystem path for '%s': %s",
                                profile_file, error_message(err)
                            );
                        }
                        error_free(err);
                        err = NULL;
                        continue;
                    }
                    bool bound = (file_outcome == MOUNT_RESOLVE_BOUND);

                    err = string_array_push(storage_paths, profile_file);
                    if (!err) {
                        err = string_array_push(
                            filesystem_paths,
                            bound ? file_fs_path : profile_file
                        );
                    }

                    if (err) {
                        err = error_wrap(err, "Failed to track path for removal");
                        goto cleanup;
                    }
                    matches_found++;
                }
            }
        }

        if (matches_found == 0) {
            if (!opts->force) {
                err = ERROR(
                    ERR_NOT_FOUND, "File '%s' not found in profile '%s'\n"
                    "Hint: Use 'dotta list --profile %s' to see tracked files",
                    storage_path, profile, profile
                );
                goto cleanup;
            }
            /* With --force, warn and skip */
            output_warning(
                out, OUTPUT_VERBOSE, "File '%s' not found in profile, skipping",
                storage_path
            );
        }
    }

    /* Check if we found any files */
    if (storage_paths->count == 0) {
        err = ERROR(
            ERR_NOT_FOUND, "No files found to remove from profile '%s'",
            profile
        );
        goto cleanup;
    }

    /* Success - transfer ownership to caller */
    *storage_paths_out = storage_paths;
    *filesystem_paths_out = filesystem_paths;
    storage_paths = NULL;      /* Prevent cleanup */
    filesystem_paths = NULL;   /* Prevent cleanup */

cleanup:
    /* Free all resources */
    if (profile_files_map) hashmap_free(profile_files_map, NULL);
    if (profile_files) string_array_free(profile_files);
    if (storage_paths) string_array_free(storage_paths);
    if (filesystem_paths) string_array_free(filesystem_paths);

    return err;
}

/**
 * Remove file from worktree
 */
static error_t *remove_file_from_worktree(
    worktree_handle_t *wt,
    const char *storage_path,
    const cmd_remove_options_t *opts,
    output_t *out
) {
    CHECK_NULL(wt);
    CHECK_NULL(storage_path);
    CHECK_NULL(opts);

    const char *wt_path = worktree_get_path(wt);
    char *file_path = str_format("%s/%s", wt_path, storage_path);
    if (!file_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate file path");
    }

    /* Check if file exists */
    if (!fs_exists(file_path)) {
        free(file_path);
        if (!opts->force) {
            return ERROR(
                ERR_NOT_FOUND, "File '%s' not found in worktree",
                storage_path
            );
        }
        /* With --force, skip silently */
        return NULL;
    }

    /* Remove from filesystem */
    error_t *err = fs_remove_file(file_path);
    free(file_path);
    if (err) {
        return error_wrap(
            err, "Failed to remove file '%s' from worktree",
            storage_path
        );
    }

    /* Stage deletion */
    err = worktree_unstage_file(wt, storage_path);
    if (err) {
        return error_wrap(err, "Failed to unstage file");
    }

    output_info(out, OUTPUT_VERBOSE, "Removed: %s", storage_path);

    return NULL;
}

/**
 * Analyze multi-profile conflicts for files to be removed
 *
 * Checks each file against all other profiles and determines:
 * - Which other profiles contain the file
 * - Whether the file is owned by another profile in the view — the enabled set's
 *   precedence gives the path to a profile other than the one the user is removing
 *   from, so the removal changes nothing on disk
 *
 * Performance: O(M×P + N) where M=profiles, P=avg files/profile, N=files checked
 * Uses centralized profile_build_file_index() for optimal performance.
 *
 * Returns arrays of other profiles per file (caller must free).
 */
static error_t *analyze_multi_profile_conflicts(
    git_repository *repo,
    const string_array_t *storage_paths,
    const string_array_t *filesystem_paths,
    const char *current_profile,
    const manifest_t *view,
    string_array_t ***other_profiles_out,
    size_t *multi_profile_count_out,
    bool *has_deployed_from_other_out
) {
    CHECK_NULL(repo);
    CHECK_NULL(storage_paths);
    CHECK_NULL(filesystem_paths);
    CHECK_NULL(current_profile);
    CHECK_NULL(other_profiles_out);
    CHECK_NULL(multi_profile_count_out);
    CHECK_NULL(has_deployed_from_other_out);

    error_t *err = NULL;
    size_t file_count = storage_paths->count;

    /* Allocate array to hold other_profiles for each file */
    string_array_t **other_profiles = calloc(file_count, sizeof(string_array_t *));
    if (!other_profiles) {
        return ERROR(ERR_MEMORY, "Failed to allocate multi-profile tracking");
    }

    /* Build profile file index once (O(M×P) - loads all profiles) Uses centralized
     * function from core/profiles.c */
    hashmap_t *profile_index = NULL;
    err = profile_build_file_index(repo, current_profile, &profile_index);
    if (err) {
        free(other_profiles);
        return error_wrap(err, "Failed to build profile index");
    }

    size_t multi_profile_count = 0;
    bool has_deployed_from_other = false;

    /* Check each file using O(1) index lookups */
    for (size_t i = 0; i < file_count; i++) {
        const char *storage_path = storage_paths->items[i];
        const char *filesystem_path = filesystem_paths->items[i];

        /* Lookup profiles containing this file - O(1) */
        string_array_t *indexed_profiles = hashmap_get(profile_index, storage_path);

        if (indexed_profiles && indexed_profiles->count > 0) {
            /* Create a copy for the output (index owns the original) */
            other_profiles[i] = string_array_new(0);
            if (other_profiles[i]) {
                for (size_t j = 0; j < indexed_profiles->count; j++) {
                    string_array_push(other_profiles[i], indexed_profiles->items[j]);
                }
                multi_profile_count++;

                /* Check if another profile owns the path in the view. Only valid
                 * with actual filesystem paths (absolute), not storage path
                 * fallbacks (relative, e.g., "home/.bashrc"). */
                if (filesystem_path[0] == '/') {
                    const manifest_row_t *row = manifest_lookup(view, filesystem_path);
                    if (row && strcmp(row->profile, current_profile) != 0) {
                        has_deployed_from_other = true;
                    }
                }
            }
        }
    }

    /* Free the index (and all its string arrays) */
    hashmap_free(profile_index, string_array_free_cb);

    *other_profiles_out = other_profiles;
    *multi_profile_count_out = multi_profile_count;
    *has_deployed_from_other_out = has_deployed_from_other;

    return NULL;
}

/**
 * Display multi-profile warnings to the user
 *
 * Shows which files exist in multiple profiles and explains the implications.
 */
static void display_multi_profile_warnings(
    output_t *out,
    const string_array_t *filesystem_paths,
    string_array_t **other_profiles,
    size_t file_count,
    size_t multi_profile_count,
    bool has_deployed_from_other,
    const char *current_profile
) {
    if (!out || multi_profile_count == 0) return;

    output_section(out, OUTPUT_NORMAL, "Multi-profile file warning");
    output_warning(
        out, OUTPUT_NORMAL, "Found %zu file%s in multiple profiles:",
        multi_profile_count, multi_profile_count == 1 ? "" : "s"
    );

    /* Display each multi-profile file */
    for (size_t i = 0; i < file_count; i++) {
        if (!other_profiles[i] || other_profiles[i]->count == 0) {
            continue;
        }

        const char *fs_path = filesystem_paths->items[i];
        output_styled(
            out, OUTPUT_NORMAL, "  {yellow}%s{reset} also in:",
            fs_path
        );

        for (size_t j = 0; j < other_profiles[i]->count; j++) {
            output_styled(
                out, OUTPUT_NORMAL, " {cyan}%s{reset}",
                other_profiles[i]->items[j]
            );
        }
        output_newline(out, OUTPUT_NORMAL);
    }

    /* Explain implications */
    output_newline(out, OUTPUT_NORMAL);
    output_info(
        out, OUTPUT_NORMAL, "These files will be removed only from profile '%s'.",
        current_profile
    );

    if (has_deployed_from_other) {
        output_warning(
            out, OUTPUT_NORMAL, "Some files are currently deployed from other profiles."
        );
        output_info(
            out, OUTPUT_NORMAL, "Those files will remain on the filesystem."
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL, "Files deployed from '%s' will remain until 'dotta apply'.",
            current_profile
        );
    }
    output_newline(out, OUTPUT_NORMAL);
}

/**
 * Free multi-profile tracking arrays
 */
static void free_multi_profile_tracking(string_array_t **other_profiles, size_t count) {
    if (!other_profiles) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        string_array_free(other_profiles[i]);
    }
    free(other_profiles);
}

/**
 * Confirm removal operation
 */
static bool confirm_removal(
    const string_array_t *storage_paths,
    const cmd_remove_options_t *opts,
    const config_t *config,
    output_t *out
) {
    if (!storage_paths || !opts || !out) {
        return false;
    }

    /* Skip confirmation if --force */
    if (opts->force) {
        return true;
    }

    /* Skip confirmation for dry run */
    if (opts->dry_run) {
        return true;
    }

    size_t count = storage_paths->count;

    /* Check config threshold */
    size_t threshold = 5; /* Default threshold */
    if (config->confirm_destructive) {
        threshold = 1;    /* Always confirm in strict mode */
    }

    /* No confirmation needed for small operations below threshold */
    if (count < threshold) {
        return true;
    }

    /* Prompt user */
    char prompt[512];
    if (opts->delete_files) {
        snprintf(
            prompt, sizeof(prompt), "Remove %zu file%s from profile '%s'?\n"
            "(Deployed files will be pruned on 'dotta apply')",
            count, count == 1 ? "" : "s", opts->profile
        );
    } else {
        snprintf(
            prompt, sizeof(prompt), "Remove %zu file%s from profile '%s'?\n"
            "(Deployed files will be released from management)",
            count, count == 1 ? "" : "s", opts->profile
        );
    }

    return output_confirm(out, prompt, false);
}

/**
 * Confirm profile deletion
 */
static bool confirm_profile_deletion(
    const char *profile,
    size_t file_count,
    const cmd_remove_options_t *opts,
    const config_t *config,
    output_t *out
) {
    if (!profile || !out) {
        return false;
    }

    /* Skip confirmation if --force */
    if (opts->force) {
        return true;
    }

    output_newline(out, OUTPUT_NORMAL);
    output_warning(
        out, OUTPUT_NORMAL, "This will delete profile '%s' (%zu file%s)",
        profile, file_count, file_count == 1 ? "" : "s"
    );
    if (opts->delete_files) {
        output_info(
            out, OUTPUT_NORMAL,
            "         Deployed files will be pruned when you run 'dotta apply'."
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL,
            "         Deployed files will be released from management."
        );
    }
    output_newline(out, OUTPUT_NORMAL);

    bool confirmed = output_confirm_destructive(
        out, config ? config->confirm_destructive : true, "Continue?", opts->force
    );

    return confirmed;
}

/**
 * Create commit for removal
 */
static error_t *create_removal_commit(
    worktree_handle_t *wt,
    const cmd_remove_options_t *opts,
    const string_array_t *removed_paths,
    const config_t *config
) {
    CHECK_NULL(wt);
    CHECK_NULL(opts);
    CHECK_NULL(removed_paths);

    /* Build commit message context */
    commit_message_context_t ctx = {
        .action        = COMMIT_ACTION_REMOVE,
        .profile       = opts->profile,
        .files         = removed_paths->items,
        .file_count    = removed_paths->count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };

    char *message = build_commit_message(config, &ctx);
    if (!message) {
        return ERROR(ERR_MEMORY, "Failed to build commit message");
    }

    /* Create commit */
    error_t *err = worktree_commit(wt, opts->profile, message, NULL);
    free(message);

    if (err) {
        return error_wrap(err, "Failed to create commit");
    }

    return NULL;
}

/**
 * Remove metadata entries for removed files
 *
 * Loads existing metadata from worktree, removes entries for deleted files, and
 * saves the updated metadata back. The metadata.json file is then staged. The
 * directory entries pruned as redundant on the way are appended to `pruned`
 * (storage paths): they leave the view by this commit too, and the record loop
 * after it retires them beside the removed files.
 */
static error_t *cleanup_metadata(
    worktree_handle_t *wt,
    const string_array_t *removed_paths,
    string_array_t *pruned,
    output_t *out
) {
    CHECK_NULL(wt);
    CHECK_NULL(removed_paths);
    CHECK_NULL(pruned);

    const char *worktree_path = worktree_get_path(wt);
    if (!worktree_path) {
        return ERROR(ERR_INTERNAL, "Worktree path is NULL");
    }

    /* Load existing metadata from worktree (if it exists) */
    metadata_t *metadata = NULL;
    char *metadata_file_path = str_format("%s/%s", worktree_path, METADATA_FILE_PATH);
    if (!metadata_file_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata file path");
    }

    error_t *err = metadata_load_from_file(metadata_file_path, &metadata);
    free(metadata_file_path);

    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            /* No existing metadata - nothing to clean up */
            error_free(err);
            return NULL;
        } else {
            /* Real error - propagate */
            return error_wrap(err, "Failed to load existing metadata");
        }
    }

    /* Remove metadata entries for each removed file */
    size_t removed_count = 0;
    for (size_t i = 0; i < removed_paths->count; i++) {
        const char *storage_path = removed_paths->items[i];

        /* Check if metadata item exists */
        if (metadata_has_item(metadata, storage_path)) {
            err = metadata_remove_item(metadata, storage_path);
            if (err) {
                metadata_free(metadata);
                return error_wrap(
                    err, "Failed to remove metadata item: %s",
                    storage_path
                );
            }

            removed_count++;

            output_info(out, OUTPUT_VERBOSE, "Removed metadata: %s", storage_path);
        }
    }

    /* Prune redundant directory entries.
     *
     * Removing a file may leave its parent directory metadata entry with no
     * anchoring descendants. Anchoring is judged against the post-edit worktree
     * index (removals already unstaged by the caller) — never against metadata
     * items, which omit unelevated symlinks. Only entries that carry no actionable
     * information are
     * dropped (default mode, no ownership, no tracked descendants);
     * custom-attribute entries are preserved as potential empty-dir intent. */
    git_index *index = NULL;
    err = worktree_get_index(wt, &index);
    if (err) {
        metadata_free(metadata);
        return error_wrap(err, "Failed to get worktree index");
    }

    err = metadata_prune_directories(metadata, index, pruned);
    git_index_free(index);
    if (err) {
        metadata_free(metadata);
        return error_wrap(err, "Failed to prune redundant directories");
    }

    if (pruned->count > 0) {
        removed_count += pruned->count;
        output_info(
            out, OUTPUT_VERBOSE, "Pruned %zu redundant directory entr%s",
            pruned->count, pruned->count == 1 ? "y" : "ies"
        );
    }

    /* Skip rewrite if nothing was actually removed from metadata */
    if (removed_count == 0) {
        metadata_free(metadata);
        return NULL;
    }

    /* Save updated metadata to worktree */
    err = metadata_save_to_worktree(worktree_path, metadata);
    metadata_free(metadata);

    if (err) {
        return error_wrap(err, "Failed to save metadata");
    }

    /* Stage metadata.json file */
    err = worktree_stage_file(wt, METADATA_FILE_PATH);
    if (err) {
        return error_wrap(err, "Failed to stage metadata");
    }

    if (removed_count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "Cleaned up %zu metadata entr%s",
            removed_count, removed_count == 1 ? "y" : "ies"
        );
    }

    return NULL;
}

/**
 * Remove files from profile
 */
static error_t *remove_files_from_profile(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const config_t *config,
    output_t *out,
    const char *repo_path,
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);
    CHECK_NULL(opts);

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    string_array_t *storage_paths = NULL;
    string_array_t *filesystem_paths = NULL;
    string_array_t **other_profiles = NULL;
    size_t multi_profile_count = 0;
    worktree_handle_t *wt = NULL;
    string_array_t *removed_paths = NULL;
    string_array_t pruned_dirs = { 0 };    /* Directory entries the metadata step pruned (storage paths) */
    string_array_t *enabled = NULL;
    manifest_t *before = NULL;
    manifest_t *after = NULL;
    hashmap_t *anchor_index = NULL;
    bool profile_enabled = false;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    } else if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Resolve paths */
    err = resolve_paths_to_remove(
        repo, opts->profile, opts->paths, opts->path_count, &storage_paths,
        &filesystem_paths, opts, out, mounts, arena
    );
    if (err) {
        goto cleanup;
    }

    /* The view before the commit. Who owns a path a moment before this command
     * removes it is a fact neither the post-commit view nor the record can state
     * — a path never seen here has no record, and a record can be a higher
     * profile's — so it is read here, once, and serves both the conflict analysis
     * and the record update below. */
    err = state_get_profiles(state, &enabled);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }
    err = manifest_build(repo, enabled, mounts, arena, &before);
    if (err) {
        err = error_wrap(err, "Failed to build manifest");
        goto cleanup;
    }

    /* Analyze multi-profile conflicts (critical safety check) */
    bool has_deployed_from_other = false;
    err = analyze_multi_profile_conflicts(
        repo,
        storage_paths,
        filesystem_paths,
        opts->profile,
        before,
        &other_profiles,
        &multi_profile_count,
        &has_deployed_from_other
    );

    if (err) {
        goto cleanup;
    }

    /* Capture profile-enabled status. The record-update phase below promotes
     * the borrowed read handle to a write transaction via state_begin; no reopen
     * needed. */
    profile_enabled = state_has_profile(state, opts->profile);

    /* Display multi-profile warnings BEFORE any operation */
    display_multi_profile_warnings(
        out,
        filesystem_paths,
        other_profiles,
        storage_paths->count,
        multi_profile_count,
        has_deployed_from_other,
        opts->profile
    );

    /* Dry run - just show what would be removed */
    if (opts->dry_run) {
        output_print(
            out, OUTPUT_NORMAL, "Would remove from profile '%s':\n",
            opts->profile
        );
        for (size_t i = 0; i < storage_paths->count; i++) {
            output_print(
                out, OUTPUT_NORMAL, "  - %s\n",
                storage_paths->items[i]
            );
        }
        output_print(
            out, OUTPUT_NORMAL, "\nTotal: %zu file%s would be removed from profile\n",
            storage_paths->count,
            storage_paths->count == 1 ? "" : "s"
        );
        if (opts->delete_files) {
            output_print(
                out, OUTPUT_NORMAL, "(Deployed files would be removed on 'dotta apply')\n"
            );
        } else {
            output_print(
                out, OUTPUT_NORMAL, "(Deployed files would be released from management)\n"
            );
        }

        goto cleanup;  /* err is NULL, will return success */
    }

    /* Confirm operation */
    if (!confirm_removal(storage_paths, opts, config, out)) {
        output_print(out, OUTPUT_NORMAL, "Cancelled\n");
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Cleanup multi-profile tracking - done with it */
    free_multi_profile_tracking(other_profiles, storage_paths->count);
    other_profiles = NULL;

    /* Build hook invocation with filesystem paths (resolved by
     * resolve_paths_to_remove). Reached only on non-dry-run: the dry-run branch
     * above early-cleanups before this point, so dry_run is always false here
     * in practice — still passed for honesty. */
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .files      = filesystem_paths->items,
        .file_count = filesystem_paths->count,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-remove hook */
    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /* Create temporary worktree */
    err = worktree_create_temp(repo, &wt);
    if (err) {
        err = error_wrap(err, "Failed to create temporary worktree");
        goto cleanup;
    }

    /* Checkout profile branch */
    err = worktree_checkout_branch(wt, opts->profile);
    if (err) {
        err = error_wrap(
            err, "Failed to checkout profile '%s'",
            opts->profile
        );
        goto cleanup;
    }

    /* Interactive mode requires a terminal for user prompts */
    if (opts->interactive && !isatty(STDIN_FILENO)) {
        err = ERROR(
            ERR_INVALID_ARG,
            "Interactive mode requires a terminal (stdin is not a TTY)"
        );
        goto cleanup;
    }

    /* Remove each file from worktree, tracking which files are actually removed */
    size_t removed_count = 0;
    removed_paths = string_array_new(0);
    if (!removed_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate removed paths array");
        goto cleanup;
    }

    for (size_t i = 0; i < storage_paths->count; i++) {
        const char *storage_path = storage_paths->items[i];

        /* Interactive mode: prompt for each file */
        if (opts->interactive) {
            char prompt[PATH_MAX + 16];
            snprintf(prompt, sizeof(prompt), "Remove %s?", storage_path);
            if (!output_confirm(out, prompt, false)) {
                output_info(out, OUTPUT_VERBOSE, "Skipped: %s", storage_path);
                continue;
            }
        }

        err = remove_file_from_worktree(wt, storage_path, opts, out);
        if (err) {
            /* If interactive or force, continue on error */
            if (opts->interactive || opts->force) {
                output_warning(out, OUTPUT_NORMAL, "%s", error_message(err));
                error_free(err);
                err = NULL;
                continue;
            }
            /* Otherwise, abort */
            goto cleanup;
        }

        err = string_array_push(removed_paths, storage_path);
        if (err) {
            err = error_wrap(err, "Failed to track removed path");
            goto cleanup;
        }
        removed_count++;
    }

    /* Nothing was removed (e.g., all declined in interactive mode) */
    if (removed_count == 0) {
        output_info(out, OUTPUT_NORMAL, "No files removed");
        goto cleanup;
    }

    /* Clean up metadata for actually-removed files only */
    err = cleanup_metadata(wt, removed_paths, &pruned_dirs, out);
    if (err) {
        err = error_wrap(err, "Failed to clean up metadata");
        goto cleanup;
    }

    /* Create commit */
    err = create_removal_commit(wt, opts, removed_paths, config);
    if (err) {
        goto cleanup;
    }

    /* Cleanup worktree */
    worktree_cleanup(&wt);

    /*
     * Architectural note: We do NOT delete files from the filesystem here. This
     * maintains separation of concerns:
     * - `remove` modifies the Git repository (profile branches)
     * - `apply` synchronizes the filesystem (prunes orphaned files by default)
     *
     * This ensures `apply` has global context from all enabled profiles to
     * correctly determine if a file should be removed (avoiding premature deletion
     * of files still needed by higher-priority profiles).
     */

    /* Write the record if the profile is enabled.
     *
     * profile_enabled==true implies state was successfully loaded with a live
     * DB (state_has_profile returns false for NULL/empty state), so state_begin
     * is safe without an additional guard. The handle is reused — no second
     * state_open that would re-prepare statements and re-query enabled_profiles
     * from scratch.
     *
     * Which paths this commit let go is read off the two views: `before` says
     * which were this profile's a moment ago; `after` (the enabled set at its
     * post-commit HEADs) says which a lower profile provides now — a fallback,
     * whose record stays and reads [reassigned] until apply deploys it. A path
     * that was ours and that nothing provides now gets the fate the user chose,
     * if dotta has a record of it at all (never seen here: nothing to release
     * or prune): --delete-files orders the deployed copy pruned at the next apply;
     * the default retires the record — released from management now. The directory
     * entries the metadata step pruned as redundant left the view by the same
     * commit and take the same route: an owned directory is pruned under cleanup's
     * emptiness rule, or released.
     *
     * Non-fatal throughout: Git succeeded and stands. A record this block fails
     * to write is an orphan the next apply reads, asks Git about, finds let go,
     * and releases — the default outcome, minus the prune order under
     * --delete-files. */
    size_t manifest_removed_count = 0, manifest_fallback_count = 0;

    if (profile_enabled) {
        /* Open transaction for the record update */
        error_t *manifest_err = state_begin(state);
        if (manifest_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to open transaction for record update: %s",
                error_message(manifest_err)
            );
            error_free(manifest_err);
        } else {
            anchor_t *anchors = NULL;
            size_t anchor_count = 0;

            manifest_err = manifest_build(repo, enabled, mounts, arena, &after);
            if (!manifest_err) {
                manifest_err = state_get_all_anchors(state, arena, &anchors, &anchor_count);
            }
            if (!manifest_err) {
                anchor_index = hashmap_borrow(anchor_count > 0 ? anchor_count : 16);
                if (!anchor_index) {
                    manifest_err = ERROR(ERR_MEMORY, "Failed to create anchors index");
                }
            }
            for (size_t i = 0; !manifest_err && i < anchor_count; i++) {
                manifest_err = hashmap_set(
                    anchor_index, anchors[i].filesystem_path, &anchors[i]
                );
            }

            const string_array_t *let_go[] = { removed_paths, &pruned_dirs };
            for (size_t b = 0; !manifest_err && b < sizeof(let_go) / sizeof(let_go[0]); b++) {
                for (size_t i = 0; !manifest_err && i < let_go[b]->count; i++) {
                    const char *storage_path = let_go[b]->items[i];

                    /* The path as this profile deploys it. UNBOUND (custom/ under
                     * a profile with no target here) names nothing on this machine:
                     * nothing to release. */
                    mount_resolve_outcome_t outcome;
                    const char *fs_path = NULL;
                    manifest_err = mount_resolve(
                        mounts, opts->profile, storage_path, arena, &outcome, &fs_path
                    );
                    if (manifest_err || outcome == MOUNT_RESOLVE_UNBOUND) continue;

                    const manifest_row_t *was = manifest_lookup(before, fs_path);
                    if (!was || strcmp(was->profile, opts->profile) != 0) continue;

                    if (manifest_lookup(after, fs_path)) {
                        manifest_fallback_count++;
                        continue;
                    }

                    if (!hashmap_has(anchor_index, fs_path)) continue;

                    manifest_err = opts->delete_files
                        ? state_order_prune(state, fs_path)
                        : state_retire_anchor(state, fs_path);
                    if (!manifest_err) manifest_removed_count++;
                }
            }

            if (manifest_err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Record update failed: %s",
                    error_message(manifest_err)
                );
                error_free(manifest_err);
                state_rollback(state);
            } else {
                /* Commit transaction */
                error_t *commit_err = state_commit(state);
                if (commit_err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to save record updates: %s",
                        error_message(commit_err)
                    );
                    error_free(commit_err);
                    state_rollback(state);
                } else if (manifest_removed_count > 0 || manifest_fallback_count > 0) {
                    if (opts->delete_files) {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "Manifest: %zu staged for removal, %zu fallback%s",
                            manifest_removed_count, manifest_fallback_count,
                            manifest_fallback_count == 1 ? "" : "s"
                        );
                    } else {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "Manifest: %zu released, %zu fallback%s",
                            manifest_removed_count, manifest_fallback_count,
                            manifest_fallback_count == 1 ? "" : "s"
                        );
                    }
                }
            }
        }
    } else {
        output_info(out, OUTPUT_VERBOSE, "Profile not enabled, Git updated only");
    }

    /* Execute post-remove hook */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* Success */
    if (!opts->quiet) {
        output_success(
            out, OUTPUT_NORMAL, "Removed %zu file%s from profile '%s'",
            removed_count, removed_count == 1 ? "" : "s", opts->profile
        );
        if (opts->delete_files) {
            output_info(
                out, OUTPUT_NORMAL, "Run 'dotta apply' to remove files from filesystem"
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL, "Files released from management (no apply needed)"
            );
        }
        output_newline(out, OUTPUT_NORMAL);
    }

cleanup:
    /* Free all resources in reverse order of allocation. state is borrowed from
     * the dispatcher — do not free it. state_rollback is a no-op if no transaction
     * is active (state.c:2898-2906), so it safely closes any partially-begun
     * record-update transaction on error paths. */
    state_rollback(state);
    if (anchor_index) hashmap_free(anchor_index, NULL);
    manifest_free(after);
    manifest_free(before);
    if (enabled) string_array_free(enabled);
    string_array_deinit(&pruned_dirs);
    if (removed_paths) string_array_free(removed_paths);
    if (wt) worktree_cleanup(&wt);
    if (other_profiles) free_multi_profile_tracking(
        other_profiles, storage_paths->count
    );
    if (filesystem_paths) string_array_free(filesystem_paths);
    if (storage_paths) string_array_free(storage_paths);

    return err;
}

/**
 * Delete entire profile branch
 */
static error_t *delete_profile_branch(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const config_t *config,
    output_t *out,
    const char *repo_path,
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);
    CHECK_NULL(opts);

    /* Initialize all resources to NULL */
    error_t *err = NULL;
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    string_array_t *all_profiles = NULL;
    string_array_t *files = NULL;
    string_array_t *hook_fs_paths = NULL;
    bool performed = false;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    } else if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Check if profile exists */
    if (!profile_exists(repo, opts->profile)) {
        if (!opts->force) {
            err = ERROR(
                ERR_NOT_FOUND, "Profile '%s' does not exist\n"
                "Hint: Use 'dotta list' to see available profiles",
                opts->profile
            );
            goto cleanup;
        }
        /* With --force, just warn and exit */
        output_warning(
            out, OUTPUT_VERBOSE, "Profile '%s' does not exist",
            opts->profile
        );
        goto cleanup;  /* err is NULL, will return success */
    }

    /* SAFETY: Prevent deletion of last remaining profile */
    err = profile_list_all_local(repo, &all_profiles);
    if (err) {
        err = error_wrap(err, "Failed to list profiles");
        goto cleanup;
    }

    if (all_profiles->count <= 1) {
        err = ERROR(
            ERR_INVALID_ARG, "Cannot delete last remaining profile '%s'\n"
            "Hint: A repository must have at least one profile", opts->profile
        );
        goto cleanup;
    }
    string_array_free(all_profiles);
    all_profiles = NULL;

    /* Load profile to count files */
    err = profile_list_files(repo, opts->profile, &files);
    if (err) {
        err = error_wrap(err, "Failed to list files in profile '%s'", opts->profile);
        goto cleanup;
    }

    size_t file_count = files->count;

    /* Dry run */
    if (opts->dry_run) {
        output_print(
            out, OUTPUT_NORMAL, "Would delete profile '%s' (%zu file%s)\n",
            opts->profile, file_count, file_count == 1 ? "" : "s"
        );
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Check for unpushed changes and detect remote Keep remote_name for later
     * use when pushing deletion
     */
    bool has_unpushed = false;
    bool is_local_only = false;

    /* Resolve remote name + URL up-front: the URL feeds the credential helper
     * for the deletion-push xfer further down (see line where
     * transfer_context_create is called). One resolve, two consumers. */
    err = gitops_resolve_default_remote(
        repo, arena, &remote_name, &remote_url
    );
    if (!err && remote_name) {
        /* Remote exists - check upstream state */
        upstream_info_t upstream_info;
        err = upstream_analyze_profile(
            repo, remote_name, opts->profile, &upstream_info
        );
        if (!err) {
            /* Determine if profile has actual remote tracking */
            if (upstream_info.state == UPSTREAM_NO_REMOTE) {
                /* Profile exists locally but was never pushed to remote */
                is_local_only = true;
            } else if (upstream_info.state == UPSTREAM_LOCAL_AHEAD ||
                upstream_info.state == UPSTREAM_DIVERGED){
                /* Profile has remote tracking and has unpushed changes */
                has_unpushed = true;
            }
        } else {
            /* Non-fatal: can't determine upstream state */
            error_free(err);
            err = NULL;
        }
    } else if (err) {
        /* No remote configured - treat as local-only */
        is_local_only = true;
        error_free(err);
        err = NULL;
    }

    /* Warn about unpushed changes (only if profile has remote tracking) */
    if (has_unpushed && !opts->force) {
        output_newline(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "Profile '%s' has unpushed changes!", opts->profile);
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta sync' first to avoid data loss");
        output_newline(out, OUTPUT_NORMAL);
    } else if (is_local_only) {
        /* Inform about local-only status in verbose mode (not a warning) */
        output_info(
            out, OUTPUT_VERBOSE, "Note: Profile '%s' is local-only (not pushed to remote)",
            opts->profile
        );
    }

    /* Informational queries and enabled check on the borrowed state. Under
     * spec-driven READ the handle is always non-NULL here (CHECK_NULL at entry),
     * and state_load for a missing DB still returns a usable handle (DB-less,
     * reads degrade to empty) — no defensive fallback needed. */
    bool profile_was_enabled = state_has_profile(state, opts->profile);
    size_t deployed_count = 0;

    /* Count the records dotta owns under the profile for informational display.
     * Failure is non-fatal: the count is purely cosmetic, so swallow any error
     * and display 0. Read outside the transaction the record update below takes;
     * that update reads the record again, inside it. */
    {
        anchor_t *anchors = NULL;
        size_t anchor_count = 0;
        error_t *count_err = state_get_all_anchors(state, arena, &anchors, &anchor_count);
        if (count_err) {
            error_free(count_err);
        } else {
            for (size_t i = 0; i < anchor_count; i++) {
                if (anchors[i].deployed_at > 0 &&
                    strcmp(anchors[i].profile, opts->profile) == 0) {
                    deployed_count++;
                }
            }
        }
    }

    /* Inform about deployed paths (informational, not a warning) */
    if (deployed_count > 0) {
        output_newline(out, OUTPUT_VERBOSE);

        output_info(
            out, OUTPUT_VERBOSE, "Note: Profile '%s' has %zu deployed entr%s",
            opts->profile, deployed_count, deployed_count == 1 ? "y" : "ies"
        );

        if (opts->delete_files) {
            output_info(
                out, OUTPUT_VERBOSE,
                "      These will be pruned when you run 'dotta apply'."
            );
        } else {
            output_info(
                out, OUTPUT_VERBOSE,
                "      These files will be released from management."
            );
        }
        output_newline(out, OUTPUT_VERBOSE);
    }

    /* Confirm deletion */
    if (!confirm_profile_deletion(
        opts->profile, file_count, opts, config, out
        )) {
        output_print(out, OUTPUT_NORMAL, "Cancelled\n");
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Convert storage paths to filesystem paths for hook consistency. The file
     * removal path passes filesystem paths to hooks; do the same here.
     *
     * Borrows the caller-supplied mount table. HOME and ROOT are always present,
     * so home/ and root/ paths resolve unconditionally. CUSTOM paths resolve
     * only when the profile is enabled with a binding; otherwise
     * MOUNT_RESOLVE_UNBOUND fires and the loop substitutes the storage path as
     * the user-visible fallback. */
    if (files) {
        hook_fs_paths = string_array_new(0);
        if (hook_fs_paths) {
            for (size_t i = 0; i < files->count; i++) {
                mount_resolve_outcome_t outcome;
                const char *fs_path = NULL;
                error_t *conv_err = mount_resolve(
                    mounts, opts->profile, files->items[i], arena,
                    &outcome, &fs_path
                );
                if (conv_err) {
                    error_free(conv_err);
                    /* Fall back to storage path (allocation failure or malformed
                     * input — non-fatal here). */
                    string_array_push(hook_fs_paths, files->items[i]);
                } else if (outcome == MOUNT_RESOLVE_BOUND) {
                    string_array_push(hook_fs_paths, fs_path);
                } else {
                    /* UNBOUND: custom/ profile without binding on this host.
                     * Fall back to storage path so the hook sees a meaningful
                     * name. */
                    string_array_push(hook_fs_paths, files->items[i]);
                }
            }
        }
    }

    /* Build hook invocation. Prefer filesystem paths (consistent with the
     * file-removal subcommand); fall back to storage paths if synthesis was
     * skipped. Both arrays live until cleanup. */
    const string_array_t *hook_files = hook_fs_paths ? hook_fs_paths : files;
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .files      = hook_files ? hook_files->items : NULL,
        .file_count = hook_files ? hook_files->count : 0,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-remove hook */
    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /*
     * Architectural note: We do NOT delete files from the filesystem here. This
     * maintains separation of concerns - `apply` handles filesystem cleanup.
     * This ensures proper global context when determining file removal.
     */

    /* Delete local branch */
    err = gitops_delete_branch(repo, opts->profile);
    if (err) {
        err = error_wrap(err, "Failed to delete profile '%s'", opts->profile);
        goto cleanup;
    }

    performed = true;

    /* Post-deletion: the enabled set and the record, in one transaction.
     *
     * The order of the branch deletion and this block does not matter: the view
     * is computed, and prune_ordered is the one fact the workspace reads for
     * these records — written once, here, after the branch is gone. The profile
     * leaves the enabled set (if it was in it), and every record under it is
     * decided against the view that remains: a path the view still has is a
     * fallback — its record is kept and reads [reassigned] P → Q until apply
     * deploys Q's; a path the view lacks gets the fate the user chose —
     * --delete-files orders the deployed copy pruned at the next apply, the default
     * retires the record (released from management now). One rule whether P was
     * enabled or not, and whether P's tree still claimed the path or had let it
     * go: the user is deleting P and P's files.
     *
     * Non-fatal: the branch is gone and stands. A record this block fails to
     * write is an orphan the next apply reads, asks Git about, finds the branch
     * gone, and releases. */
    error_t *delete_err = state_begin(state);
    if (!delete_err) {
        string_array_t *enabled_after = NULL;
        mount_table_t *post_delete_mounts = NULL;
        manifest_t *after = NULL;
        anchor_t *anchors = NULL;
        size_t anchor_count = 0;
        size_t removed = 0, fallbacks = 0;

        if (profile_was_enabled) {
            delete_err = state_disable_profile(state, opts->profile);
        }

        /* Build a fresh mount table from the post-disable row cache: the borrowed
         * `mounts` parameter still references the deleted profile, which would
         * let custom/ paths under its target keep classifying after it has left
         * scope. */
        if (!delete_err) {
            delete_err = profile_build_mount_table(state, arena, &post_delete_mounts);
        }
        if (!delete_err) delete_err = state_get_profiles(state, &enabled_after);
        if (!delete_err) {
            delete_err = manifest_build(repo, enabled_after, post_delete_mounts, arena, &after);
        }
        if (!delete_err) {
            delete_err = state_get_all_anchors(state, arena, &anchors, &anchor_count);
        }

        for (size_t i = 0; !delete_err && i < anchor_count; i++) {
            const anchor_t *anchor = &anchors[i];
            if (strcmp(anchor->profile, opts->profile) != 0) continue;

            if (manifest_lookup(after, anchor->filesystem_path)) {
                fallbacks++;
                continue;
            }

            delete_err = opts->delete_files
                ? state_order_prune(state, anchor->filesystem_path)
                : state_retire_anchor(state, anchor->filesystem_path);
            if (!delete_err) removed++;
        }

        /* Commit transaction */
        if (!delete_err) delete_err = state_commit(state);

        if (delete_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to update state after branch deletion: %s",
                error_message(delete_err)
            );
            error_free(delete_err);
            state_rollback(state);
        } else if (removed > 0 || fallbacks > 0) {
            if (opts->delete_files) {
                output_info(
                    out, OUTPUT_VERBOSE, "%zu entr%s staged for removal, %zu fallback%s",
                    removed, removed == 1 ? "y" : "ies",
                    fallbacks, fallbacks == 1 ? "" : "s"
                );
            } else {
                output_info(
                    out, OUTPUT_VERBOSE, "%zu entr%s released from management, %zu fallback%s",
                    removed, removed == 1 ? "y" : "ies",
                    fallbacks, fallbacks == 1 ? "" : "s"
                );
            }
        }

        manifest_free(after);
        if (enabled_after) string_array_free(enabled_after);
    } else {
        /* Non-fatal: the next workspace load observes the branch gone and releases
         * these records conservatively */
        output_warning(
            out, OUTPUT_NORMAL, "Failed to begin transaction for post-deletion update: %s",
            error_message(delete_err)
        );
        error_free(delete_err);
    }

    /* Push deletion to remote if remote exists This is critical for sync to work -
     * other repos need to know the branch was deleted
     */
    if (remote_name && !is_local_only) {
        output_info(
            out, OUTPUT_NORMAL, "Pushing profile deletion to remote '%s'...",
            remote_name
        );

        /* remote_url was resolved alongside remote_name above. NULL is legal —
         * unauthenticated paths still work, helper approve/reject become no-ops. */
        transfer_context_t *del_xfer = NULL;
        transfer_options_t del_opts = { .output = out, .url = remote_url };
        error_t *del_xfer_err = transfer_context_create(&del_opts, &del_xfer);

        if (del_xfer_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to create transfer context: %s",
                error_message(del_xfer_err)
            );
            error_free(del_xfer_err);
            err = NULL;
        } else {
            err = gitops_delete_remote_branch(
                repo, remote_name, opts->profile, del_xfer
            );
            transfer_context_free(del_xfer);
        }
        if (err) {
            /* Non-fatal: warn but don't fail the whole operation The local branch
             * is already deleted, so this is just about syncing
             */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to push deletion to remote: %s",
                error_message(err)
            );
            output_info(
                out, OUTPUT_NORMAL,
                "         The profile was deleted locally, but sync could fail."
            );
            output_info(
                out, OUTPUT_NORMAL,
                "         You can manually push the deletion with: git push %s :%s",
                remote_name, opts->profile
            );
            error_free(err);
            err = NULL;
        } else {
            output_info(out, OUTPUT_NORMAL, "Profile deletion pushed to remote");
        }
    }

    /*
     * Architectural note: the profile's records were prune-ordered (with
     * --delete-files) or retired in the post-deletion block above. The prune
     * itself happens on `apply`.
     */

    /* Execute post-remove hook */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* Success message (only on actual deletion, not dry-run/cancel/error) */
    if (performed && !opts->quiet) {
        output_success(out, OUTPUT_NORMAL, "Profile '%s' deleted", opts->profile);

        if (opts->delete_files) {
            output_info(
                out, OUTPUT_NORMAL,
                "Run 'dotta apply' to remove deployed files from filesystem"
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL,
                "Files released from management (no apply needed)"
            );
        }
        output_newline(out, OUTPUT_NORMAL);
    }

cleanup:
    /* Free all resources in reverse order of allocation. state is borrowed from
     * the dispatcher — do not free it. state_rollback is a no-op if no transaction
     * is active; this safely closes any partially-begun record-update or
     * post-deletion transaction on an error path. */
    state_rollback(state);

    if (hook_fs_paths) string_array_free(hook_fs_paths);
    if (files) string_array_free(files);
    if (all_profiles) string_array_free(all_profiles);

    return err;
}

/**
 * Remove command implementation
 */
error_t *cmd_remove(const dotta_ctx_t *ctx, const cmd_remove_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->state);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    state_t *state = ctx->state;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Validate options */
    error_t *err = validate_options(opts);
    if (err) {
        return err;
    }

    /* Branch: Delete profile or remove files */
    if (opts->delete_profile) {
        return delete_profile_branch(
            repo, state, ctx->arena, ctx->mounts, config, out,
            ctx->repo_path, opts
        );
    }

    return remove_files_from_profile(
        repo, state, ctx->arena, ctx->mounts, config, out,
        ctx->repo_path, opts
    );
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `profile` and `paths[]`.
 *
 * Legacy-compatible rules:
 *   1. -p/--profile was given: every positional is a path.
 *   2. -p not given: first positional is the profile, rest are paths.
 *   3. --delete-profile: paths must be empty (mutually exclusive).
 *   4. Without --delete-profile: at least one path is required.
 */
static error_t *remove_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_remove_options_t *o = opts_v;

    if (o->profile != NULL) {
        o->paths = o->positional_args;
        o->path_count = o->positional_count;
    } else {
        if (o->positional_count == 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "profile name is required (as first positional or via -p)"
            );
        }
        o->profile = o->positional_args[0];
        o->paths = o->positional_args + 1;
        o->path_count = o->positional_count - 1;
    }

    if (o->delete_profile && o->path_count > 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "cannot specify paths when using --delete-profile"
        );
    }
    if (!o->delete_profile && o->path_count == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "at least one path is required (or use --delete-profile)"
        );
    }
    return NULL;
}

static error_t *remove_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_remove(ctx, (const cmd_remove_options_t *) opts_v);
}

static const args_opt_t remove_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",         "<name>",
        cmd_remove_options_t,profile,
        "Profile name (alternative to positional)"
    ),
    ARGS_STRING(
        "m message",         "<msg>",
        cmd_remove_options_t,message,
        "Commit message"
    ),
    ARGS_FLAG(
        "delete-profile",
        cmd_remove_options_t,delete_profile,
        "Delete the entire profile branch"
    ),
    ARGS_FLAG(
        "delete-files",
        cmd_remove_options_t,delete_files,
        "Stage deployed items for removal on next apply"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_remove_options_t,dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG(
        "f force",
        cmd_remove_options_t,force,
        "Skip confirmation prompts"
    ),
    ARGS_FLAG(
        "i interactive",
        cmd_remove_options_t,interactive,
        "Prompt for each file"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_remove_options_t,verbose,
        "Verbose output"
    ),
    ARGS_FLAG(
        "q quiet",
        cmd_remove_options_t,quiet,
        "Minimal output"
    ),
    /* <profile> [<path>...]. -p promotes positionals to all-paths. */
    ARGS_POSITIONAL_RAW(
        cmd_remove_options_t,positional_args, positional_count,
        0,                   0
    ),
    ARGS_END,
};

const args_command_t spec_remove = {
    .name        = "remove",
    .summary     = "Remove files from a profile or delete profile",
    .usage       =
        "%s remove [options] <profile> <path>...\n"
        "   or: %s remove [options] <profile> --delete-profile\n"
        "   or: %s remove [options] --profile <name> <path>...",
    .description =
        "Untrack files from a profile, optionally scheduling removal of\n"
        "the deployed copies, or delete the profile branch outright.\n",
    .notes       =
        "Operation Modes:\n"
        "  (default)           Remove files from the profile branch. Deployed\n"
        "                      items are released from management and stay\n"
        "                      on the filesystem untouched.\n"
        "  --delete-files      Same as default, plus stage the deployed\n"
        "                      items for removal on the next '%s apply'.\n"
        "  --delete-profile    Delete the entire profile branch. No paths\n"
        "                      may be given; cannot be combined with\n"
        "                      --delete-files.\n",
    .examples    =
        "  %s remove global ~/.bashrc                  # Untrack, keep on disk\n"
        "  %s remove darwin ~/.config/nvim -n          # Preview removal\n"
        "  %s remove darwin ~/.config/nvim --delete-files  # Remove on apply\n"
        "  %s remove staging --delete-profile          # Delete whole profile\n",
    .epilogue    =
        "See also:\n"
        "  %s profile disable <name>  # Stop deploying without deleting\n"
        "  %s apply                   # Carry out staged file removals\n",
    .opts_size   = sizeof(cmd_remove_options_t),
    .opts        = remove_opts,
    .post_parse  = remove_post_parse,
    .payload     = &dotta_ext_read,
    .dispatch    = remove_dispatch,
};
