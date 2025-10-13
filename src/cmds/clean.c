/**
 * clean.c - Remove untracked managed files
 */

#include "clean.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "core/profiles.h"
#include "core/state.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/hooks.h"
#include "utils/output.h"

/**
 * Find orphaned files (files in state but not in manifest)
 *
 * Uses hashmap for O(1) lookups instead of O(n*m) linear search.
 *
 * @param state_files Array of state file entries
 * @param state_file_count Number of entries in state
 * @param manifest Current manifest (may be NULL)
 * @param orphaned Output array to populate with orphaned file paths
 * @return Error or NULL on success
 */
static error_t *find_orphaned_files_internal(
    const state_file_entry_t *state_files,
    size_t state_file_count,
    const manifest_t *manifest,
    string_array_t *orphaned)
{
    error_t *err = NULL;
    hashmap_t *manifest_paths = NULL;

    /* Build hashmap of manifest paths for O(1) lookups */
    if (manifest && manifest->count > 0) {
        manifest_paths = hashmap_create(manifest->count);
        if (!manifest_paths) {
            return ERROR(ERR_MEMORY, "Failed to create hashmap");
        }

        /* Populate hashmap with manifest paths */
        for (size_t i = 0; i < manifest->count; i++) {
            err = hashmap_set(manifest_paths, manifest->entries[i].filesystem_path,
                            (void *)1); /* dummy value */
            if (err) {
                hashmap_free(manifest_paths, NULL);
                return error_wrap(err, "Failed to populate hashmap");
            }
        }
    }

    /* Check each state file using O(1) hashmap lookup */
    for (size_t i = 0; i < state_file_count; i++) {
        const state_file_entry_t *entry = &state_files[i];

        /* O(1) lookup instead of O(m) linear search */
        if (!manifest_paths || !hashmap_has(manifest_paths, entry->filesystem_path)) {
            err = string_array_push(orphaned, entry->filesystem_path);
            if (err) {
                if (manifest_paths) {
                    hashmap_free(manifest_paths, NULL);
                }
                return err;
            }
        }
    }

    /* Cleanup hashmap */
    if (manifest_paths) {
        hashmap_free(manifest_paths, NULL);
    }

    return NULL;
}

/**
 * Remove orphaned files and update state
 *
 * @param orphaned Array of orphaned file paths to remove
 * @param state State to update
 * @param opts Command options (for verbose/colors)
 * @param out Output context
 * @param removed_count Output: number of files successfully removed
 * @param failed_count Output: number of files that failed to remove
 * @param state_cleaned_count Output: number of already-removed files cleaned from state
 * @return Error or NULL on success
 */
static error_t *remove_orphaned_files_internal(
    const string_array_t *orphaned,
    state_t *state,
    const cmd_clean_options_t *opts,
    output_ctx_t *out,
    size_t *removed_count,
    size_t *failed_count,
    size_t *state_cleaned_count)
{
    error_t *err = NULL;
    *removed_count = 0;
    *failed_count = 0;
    *state_cleaned_count = 0;

    for (size_t i = 0; i < string_array_size(orphaned); i++) {
        const char *path = string_array_get(orphaned, i);

        if (!fs_exists(path)) {
            /* File already removed - clean it from state */
            err = state_remove_file(state, path);
            if (err) {
                if (opts->verbose) {
                    fprintf(stderr, "  [warn] Failed to remove '%s' from state: %s\n",
                           path, error_message(err));
                }
                error_free(err);
                err = NULL;
            } else {
                (*state_cleaned_count)++;
                if (opts->verbose) {
                    fprintf(out->stream, "  [skip] %s (already removed, cleaned from state)\n", path);
                }
            }
            continue;
        }

        err = fs_remove_file(path);
        if (err) {
            if (output_colors_enabled(out)) {
                fprintf(stderr, "  %s[fail]%s %s: %s\n",
                        output_color_code(out, OUTPUT_COLOR_RED),
                        output_color_code(out, OUTPUT_COLOR_RESET),
                        path, error_message(err));
            } else {
                fprintf(stderr, "  [fail] %s: %s\n", path, error_message(err));
            }
            error_free(err);
            err = NULL;
            (*failed_count)++;
        } else {
            /* File removed successfully - also remove from state */
            err = state_remove_file(state, path);
            if (err) {
                if (opts->verbose) {
                    fprintf(stderr, "  [warn] Failed to remove '%s' from state: %s\n",
                           path, error_message(err));
                }
                error_free(err);
                err = NULL;
            }
            (*removed_count)++;
            if (opts->verbose) {
                if (output_colors_enabled(out)) {
                    fprintf(out->stream, "  %s[ok]%s   %s\n",
                            output_color_code(out, OUTPUT_COLOR_GREEN),
                            output_color_code(out, OUTPUT_COLOR_RESET),
                            path);
                } else {
                    fprintf(out->stream, "  [ok]   %s\n", path);
                }
            }
        }
    }

    return NULL;
}

/**
 * Clean command implementation
 */
error_t *cmd_clean(git_repository *repo, const cmd_clean_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Declare all resources at top and initialize to NULL */
    error_t *err = NULL;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;
    state_t *state = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *manifest = NULL;
    string_array_t *orphaned = NULL;
    char *repo_dir = NULL;
    hook_context_t *hook_ctx = NULL;
    profile_mode_t original_mode = PROFILE_MODE_LOCAL;
    bool mode_overridden = false;

    /* Local variables for file removal tracking */
    size_t removed_count = 0;
    size_t failed_count = 0;
    size_t state_cleaned_count = 0;

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
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
    if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Load state */
    err = state_load(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to load state");
        goto cleanup;
    }

    /* Get files from state */
    size_t state_file_count = 0;
    const state_file_entry_t *state_files = state_get_all_files(state, &state_file_count);

    if (state_file_count == 0) {
        output_info(out, "No files in state - nothing to clean");
        goto cleanup;
    }

    /* Apply mode override if provided */
    if (opts->mode) {
        original_mode = config->mode;
        config->mode = config_parse_mode(opts->mode, config->mode);
        mode_overridden = true;
    }

    /* Load profiles with config fallback */
    err = profile_resolve(repo, opts->profiles, opts->profile_count,
                         config, config->strict_mode, &profiles);

    /* Restore original mode */
    if (mode_overridden) {
        config->mode = original_mode;
    }

    if (err) {
        err = error_wrap(err, "Failed to load profiles");
        goto cleanup;
    }

    /* Show active profiles in verbose mode */
    if (opts->verbose && profiles->count > 0) {
        output_section(out, "Active profiles");
        for (size_t i = 0; i < profiles->count; i++) {
            if (output_colors_enabled(out)) {
                fprintf(out->stream, "  %s%s%s%s\n",
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       profiles->profiles[i].name,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       profiles->profiles[i].auto_detected ? " (auto)" : "");
            } else {
                fprintf(out->stream, "  %s%s\n",
                       profiles->profiles[i].name,
                       profiles->profiles[i].auto_detected ? " (auto)" : "");
            }
        }
        fprintf(out->stream, "\n");
    }

    /* Build manifest from current profiles */
    if (profiles->count > 0) {
        err = profile_build_manifest(repo, profiles, &manifest);
        if (err) {
            err = error_wrap(err, "Failed to build manifest");
            goto cleanup;
        }
    }

    /* Find orphaned files (in state but not in manifest) */
    orphaned = string_array_create();
    if (!orphaned) {
        err = ERROR(ERR_MEMORY, "Failed to allocate orphaned files array");
        goto cleanup;
    }

    err = find_orphaned_files_internal(state_files, state_file_count, manifest, orphaned);
    if (err) {
        goto cleanup;
    }

    /* Check if anything to clean */
    if (string_array_size(orphaned) == 0) {
        output_info(out, "No orphaned files to clean");
        goto cleanup;
    }

    /* Get repository directory for hooks */
    err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        goto cleanup;
    }

    /* Execute pre-clean hook */
    hook_ctx = hook_context_create(repo_dir, "clean", NULL);
    if (hook_ctx) {
        /* Add orphaned files to hook context */
        hook_context_add_files(hook_ctx,
                              (const char **)orphaned->items,
                              orphaned->count);

        hook_result_t *hook_result = NULL;
        err = hook_execute(config, HOOK_PRE_CLEAN, hook_ctx, &hook_result);

        if (err) {
            /* Hook failed - abort operation */
            if (hook_result && hook_result->output && hook_result->output[0]) {
                fprintf(stderr, "Hook output:\n%s\n", hook_result->output);
            }
            hook_result_free(hook_result);
            err = error_wrap(err, "Pre-clean hook failed");
            goto cleanup;
        }
        hook_result_free(hook_result);
        /* Keep hook_ctx for post-clean hook */
    }

    /* Show what will be removed */
    char header[128];
    snprintf(header, sizeof(header), "Files to remove (%zu)", string_array_size(orphaned));
    output_section(out, header);
    fprintf(out->stream, "\n");

    for (size_t i = 0; i < string_array_size(orphaned); i++) {
        if (output_colors_enabled(out)) {
            fprintf(out->stream, "  %s%s%s\n",
                    output_color_code(out, OUTPUT_COLOR_YELLOW),
                    string_array_get(orphaned, i),
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            fprintf(out->stream, "  %s\n", string_array_get(orphaned, i));
        }
    }
    fprintf(out->stream, "\n");

    if (opts->dry_run) {
        output_info(out, "Dry-run mode - no files removed");
        goto cleanup;
    }

    /* Confirm unless --force (only if confirm_destructive is enabled) */
    if (!output_confirm_destructive(out, config, "Proceed?", opts->force)) {
        output_info(out, "Cancelled");
        goto cleanup;
    }

    /* Remove orphaned files */
    err = remove_orphaned_files_internal(orphaned, state, opts, out,
                                        &removed_count, &failed_count, &state_cleaned_count);
    if (err) {
        goto cleanup;
    }

    /* Save state if any changes were made */
    if (removed_count > 0 || state_cleaned_count > 0) {
        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to save state after cleaning");
            goto cleanup;
        }
    }

    /* Execute post-clean hook */
    if (hook_ctx) {
        hook_result_t *hook_result = NULL;
        error_t *hook_err = hook_execute(config, HOOK_POST_CLEAN, hook_ctx, &hook_result);

        if (hook_err) {
            /* Hook failed - warn but don't abort (files already cleaned) */
            fprintf(stderr, "Warning: Post-clean hook failed: %s\n", error_message(hook_err));
            if (hook_result && hook_result->output && hook_result->output[0]) {
                fprintf(stderr, "Hook output:\n%s\n", hook_result->output);
            }
            error_free(hook_err);
        }
        hook_result_free(hook_result);
    }

    /* Summary */
    fprintf(out->stream, "\n");
    if (removed_count > 0) {
        if (output_colors_enabled(out)) {
            fprintf(out->stream, "Removed %s%zu%s file%s\n",
                    output_color_code(out, OUTPUT_COLOR_GREEN),
                    removed_count,
                    output_color_code(out, OUTPUT_COLOR_RESET),
                    removed_count == 1 ? "" : "s");
        } else {
            fprintf(out->stream, "Removed %zu file%s\n",
                    removed_count, removed_count == 1 ? "" : "s");
        }
    }
    if (failed_count > 0) {
        if (output_colors_enabled(out)) {
            fprintf(stderr, "Failed to remove %s%zu%s file%s\n",
                    output_color_code(out, OUTPUT_COLOR_RED),
                    failed_count,
                    output_color_code(out, OUTPUT_COLOR_RESET),
                    failed_count == 1 ? "" : "s");
        } else {
            fprintf(stderr, "Failed to remove %zu file%s\n",
                    failed_count, failed_count == 1 ? "" : "s");
        }
    }

    /* Add trailing newline for UX consistency */
    if (out && out->stream) {
        fprintf(out->stream, "\n");
    }

cleanup:
    /* Free resources in reverse order of allocation */
    if (hook_ctx) hook_context_free(hook_ctx);
    if (repo_dir) free(repo_dir);
    if (orphaned) string_array_free(orphaned);
    if (manifest) manifest_free(manifest);
    if (profiles) profile_list_free(profiles);
    if (state) state_free(state);
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}
