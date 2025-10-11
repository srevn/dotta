/**
 * apply.c - Apply profiles to filesystem
 */

#include "apply.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "core/deploy.h"
#include "core/profiles.h"
#include "core/state.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/hooks.h"
#include "utils/output.h"

/**
 * Confirm action with user
 */
static bool confirm_action(const char *prompt) {
    fprintf(stderr, "%s [y/N] ", prompt ? prompt : "Proceed?");
    fflush(stderr);

    char response[10];
    if (fgets(response, sizeof(response), stdin) == NULL) {
        return false;
    }

    return (response[0] == 'y' || response[0] == 'Y');
}

/**
 * Print pre-flight results
 */
static void print_preflight_results(const output_ctx_t *out, const preflight_result_t *result, bool strict_mode) {
    if (!result) return;

    /* Print overlaps (warnings or errors depending on strict_mode) */
    if (result->overlaps && string_array_size(result->overlaps) > 0) {
        if (strict_mode) {
            output_section(out, "Errors (strict mode)");
        } else {
            output_section(out, "Warnings");
        }
        for (size_t i = 0; i < string_array_size(result->overlaps); i++) {
            FILE *stream = strict_mode ? stderr : out->stream;
            output_color_t color = strict_mode ? OUTPUT_COLOR_RED : OUTPUT_COLOR_YELLOW;
            const char *symbol = strict_mode ? "✗" : "•";

            if (output_colors_enabled(out)) {
                fprintf(stream, "  %s%s%s %s appears in multiple profiles\n",
                       output_color_code(out, color),
                       symbol,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->overlaps, i));
            } else {
                fprintf(stream, "  %s %s appears in multiple profiles\n",
                       symbol,
                       string_array_get(result->overlaps, i));
            }
        }
        if (strict_mode) {
            fprintf(stderr, "\n");
            output_error(out, "Strict mode enabled: overlapping files not allowed");
        }
    }

    /* Print conflicts */
    if (result->conflicts && string_array_size(result->conflicts) > 0) {
        output_section(out, "Conflicts (files modified locally)");
        for (size_t i = 0; i < string_array_size(result->conflicts); i++) {
            if (output_colors_enabled(out)) {
                fprintf(stderr, "  %s✗%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_RED),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->conflicts, i));
            } else {
                fprintf(stderr, "  ✗ %s\n", string_array_get(result->conflicts, i));
            }
        }
        fprintf(stderr, "\n");
        output_info(out, "Use --force to overwrite local changes");
    }

    /* Print permission errors */
    if (result->permission_errors && string_array_size(result->permission_errors) > 0) {
        output_section(out, "Permission errors");
        for (size_t i = 0; i < string_array_size(result->permission_errors); i++) {
            if (output_colors_enabled(out)) {
                fprintf(stderr, "  %s✗%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_RED),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->permission_errors, i));
            } else {
                fprintf(stderr, "  ✗ %s\n", string_array_get(result->permission_errors, i));
            }
        }
    }
}

/**
 * Print deployment results
 */
static void print_deploy_results(const output_ctx_t *out, const deploy_result_t *result, bool verbose) {
    if (!result) return;

    if (verbose && result->deployed) {
        output_section(out, "Deployed files");
        for (size_t i = 0; i < string_array_size(result->deployed); i++) {
            if (output_colors_enabled(out)) {
                fprintf(out->stream, "  %s✓%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_GREEN),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->deployed, i));
            } else {
                fprintf(out->stream, "  ✓ %s\n", string_array_get(result->deployed, i));
            }
        }
    }

    if (verbose && result->skipped && string_array_size(result->skipped) > 0) {
        output_section(out, "Skipped files");
        for (size_t i = 0; i < string_array_size(result->skipped); i++) {
            if (output_colors_enabled(out)) {
                fprintf(out->stream, "  %s⊘%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->skipped, i));
            } else {
                fprintf(out->stream, "  ⊘ %s\n", string_array_get(result->skipped, i));
            }
        }
    }

    if (result->failed && string_array_size(result->failed) > 0) {
        output_section(out, "Failed to deploy");
        for (size_t i = 0; i < string_array_size(result->failed); i++) {
            if (output_colors_enabled(out)) {
                fprintf(stderr, "  %s✗%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_RED),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->failed, i));
            } else {
                fprintf(stderr, "  ✗ %s\n", string_array_get(result->failed, i));
            }
        }
        if (result->error_message) {
            fprintf(stderr, "\n");
            output_error(out, "%s", result->error_message);
        }
    }

    if (!verbose) {
        /* Print summary */
        if (result->deployed_count > 0) {
            if (output_colors_enabled(out)) {
                fprintf(out->stream, "Deployed %s%zu%s file%s\n",
                       output_color_code(out, OUTPUT_COLOR_GREEN),
                       result->deployed_count,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       result->deployed_count == 1 ? "" : "s");
            } else {
                fprintf(out->stream, "Deployed %zu file%s\n",
                       result->deployed_count,
                       result->deployed_count == 1 ? "" : "s");
            }
        }

        if (result->skipped_count > 0) {
            if (output_colors_enabled(out)) {
                fprintf(out->stream, "Skipped %s%zu%s file%s (up-to-date)\n",
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       result->skipped_count,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       result->skipped_count == 1 ? "" : "s");
            } else {
                fprintf(out->stream, "Skipped %zu file%s (up-to-date)\n",
                       result->skipped_count,
                       result->skipped_count == 1 ? "" : "s");
            }
        }
    }
}

/**
 * Prune orphaned files from filesystem
 *
 * Removes files that are tracked in state but not in the current manifest.
 * This happens when files are removed from profiles.
 *
 * @param repo Repository (must not be NULL)
 * @param state State (must not be NULL)
 * @param manifest Current manifest (must not be NULL)
 * @param out Output context (must not be NULL)
 * @param verbose Print detailed output
 * @return Error or NULL on success
 */
static error_t *apply_prune_orphaned_files(
    git_repository *repo,
    state_t *state,
    const manifest_t *manifest,
    output_ctx_t *out,
    bool verbose
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(manifest);
    CHECK_NULL(out);

    error_t *err = NULL;
    string_array_t *to_remove = NULL;
    hashmap_t *manifest_paths = NULL;

    /* Get all files tracked in state */
    size_t state_file_count = 0;
    const state_file_entry_t *state_files = state_get_all_files(state, &state_file_count);

    to_remove = string_array_create();
    if (!to_remove) {
        return ERROR(ERR_MEMORY, "Failed to allocate removal list");
    }

    /*
     * Build hashmap of manifest paths for O(1) lookups
     * This changes complexity from O(n*m) to O(n)
     */
    manifest_paths = hashmap_create(manifest->count);
    if (!manifest_paths) {
        string_array_free(to_remove);
        return ERROR(ERR_MEMORY, "Failed to create hashmap for pruning");
    }

    /* Populate hashmap with manifest paths */
    for (size_t j = 0; j < manifest->count; j++) {
        err = hashmap_set(manifest_paths, manifest->entries[j].filesystem_path,
                        (void *)1); /* dummy value, we only care about key existence */
        if (err) {
            err = error_wrap(err, "Failed to populate hashmap for pruning");
            goto cleanup;
        }
    }

    /* Check each state file using O(1) hashmap lookup */
    for (size_t i = 0; i < state_file_count; i++) {
        const state_file_entry_t *state_entry = &state_files[i];

        /* O(1) lookup instead of O(m) linear search */
        if (!hashmap_has(manifest_paths, state_entry->filesystem_path)) {
            string_array_push(to_remove, state_entry->filesystem_path);
        }
    }

    /* Remove orphaned files */
    if (string_array_size(to_remove) > 0) {
        if (verbose) {
            char header[128];
            snprintf(header, sizeof(header), "Pruning %zu orphaned file%s",
                    string_array_size(to_remove),
                    string_array_size(to_remove) == 1 ? "" : "s");
            output_section(out, header);
        }

        size_t removed_count = 0;

        for (size_t i = 0; i < string_array_size(to_remove); i++) {
            const char *path = string_array_get(to_remove, i);

            if (fs_exists(path)) {
                error_t *removal_err = fs_remove_file(path);
                if (removal_err) {
                    if (verbose) {
                        if (output_colors_enabled(out)) {
                            fprintf(stderr, "  %s[fail]%s %s: %s\n",
                                   output_color_code(out, OUTPUT_COLOR_RED),
                                   output_color_code(out, OUTPUT_COLOR_RESET),
                                   path, error_message(removal_err));
                        } else {
                            fprintf(stderr, "  [fail] %s: %s\n", path, error_message(removal_err));
                        }
                    }
                    error_free(removal_err);
                } else {
                    /* File removed successfully - remove from state */
                    error_t *state_err = state_remove_file(state, path);
                    if (state_err) {
                        if (verbose) {
                            if (output_colors_enabled(out)) {
                                fprintf(stderr, "  %s[warning]%s Failed to remove '%s' from state: %s\n",
                                       output_color_code(out, OUTPUT_COLOR_YELLOW),
                                       output_color_code(out, OUTPUT_COLOR_RESET),
                                       path, error_message(state_err));
                            } else {
                                fprintf(stderr, "  [warning] Failed to remove '%s' from state: %s\n",
                                       path, error_message(state_err));
                            }
                        }
                        error_free(state_err);
                    } else {
                        removed_count++;
                        if (verbose) {
                            if (output_colors_enabled(out)) {
                                fprintf(out->stream, "  %s[removed]%s %s\n",
                                       output_color_code(out, OUTPUT_COLOR_GREEN),
                                       output_color_code(out, OUTPUT_COLOR_RESET),
                                       path);
                            } else {
                                fprintf(out->stream, "  [removed] %s\n", path);
                            }
                        }
                    }
                }
            }
        }

        /* Save updated state after pruning */
        if (removed_count > 0) {
            err = state_save(repo, state);
            if (err) {
                err = error_wrap(err, "Failed to save state after pruning");
                goto cleanup;
            }

            output_print(out, OUTPUT_VERBOSE, "\nState updated after pruning\n");
        }

        if (!verbose && removed_count > 0) {
            if (output_colors_enabled(out)) {
                fprintf(out->stream, "Pruned %s%zu%s orphaned file%s\n",
                       output_color_code(out, OUTPUT_COLOR_YELLOW),
                       removed_count,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       removed_count == 1 ? "" : "s");
            } else {
                fprintf(out->stream, "Pruned %zu orphaned file%s\n",
                       removed_count,
                       removed_count == 1 ? "" : "s");
            }
        }
    }

cleanup:
    if (manifest_paths) hashmap_free(manifest_paths, NULL);
    if (to_remove) string_array_free(to_remove);
    return err;
}

/**
 * Update state with deployed files and save to disk
 *
 * Updates the state with:
 * - Active profile names
 * - Files from manifest (with computed hashes)
 *
 * @param repo Repository (must not be NULL)
 * @param state State to update (must not be NULL)
 * @param profiles Profiles being applied (must not be NULL)
 * @param manifest Manifest of deployed files (must not be NULL)
 * @param out Output context for messages (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *apply_update_and_save_state(
    git_repository *repo,
    state_t *state,
    const profile_list_t *profiles,
    const manifest_t *manifest,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profiles);
    CHECK_NULL(manifest);
    CHECK_NULL(out);

    error_t *err = NULL;
    const char **profile_names = NULL;

    /* Update state with active profiles */
    profile_names = malloc(profiles->count * sizeof(char *));
    if (!profile_names) {
        return ERROR(ERR_MEMORY, "Failed to allocate profile names");
    }

    for (size_t i = 0; i < profiles->count; i++) {
        profile_names[i] = profiles->profiles[i].name;
    }

    err = state_set_profiles(state, profile_names, profiles->count);
    free(profile_names);

    if (err) {
        return error_wrap(err, "Failed to update state profiles");
    }

    /* Clear old files and add new manifest */
    state_clear_files(state);

    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];

        /* Defensive check: ensure entry is valid */
        if (!entry->entry) {
            return ERROR(ERR_INTERNAL, "Invalid manifest entry at index %zu", i);
        }

        /* Determine file type */
        git_filemode_t mode = git_tree_entry_filemode(entry->entry);
        state_file_type_t type = STATE_FILE_REGULAR;
        if (mode == GIT_FILEMODE_LINK) {
            type = STATE_FILE_SYMLINK;
        } else if (mode == GIT_FILEMODE_BLOB_EXECUTABLE) {
            type = STATE_FILE_EXECUTABLE;
        }

        /* Compute hash from git blob OID */
        const git_oid *oid = git_tree_entry_id(entry->entry);
        if (!oid) {
            return ERROR(ERR_INTERNAL, "Failed to get OID for entry at index %zu", i);
        }

        char hash_str[GIT_OID_HEXSZ + 1];
        git_oid_tostr(hash_str, sizeof(hash_str), oid);

        /* Create state entry */
        state_file_entry_t *state_entry = NULL;
        err = state_create_entry(
            entry->storage_path,
            entry->filesystem_path,
            entry->source_profile->name,
            type,
            hash_str,  /* hash computed from blob OID */
            NULL,      /* mode */
            &state_entry
        );

        if (err) {
            return error_wrap(err, "Failed to create state entry");
        }

        err = state_add_file(state, state_entry);
        state_free_entry(state_entry);

        if (err) {
            return error_wrap(err, "Failed to add file to state");
        }
    }

    /* Save updated state */
    err = state_save(repo, state);
    if (err) {
        return error_wrap(err, "Failed to save state");
    }

    output_print(out, OUTPUT_VERBOSE, "\nState saved\n");

    return NULL;
}

/**
 * Apply command implementation
 */
error_t *cmd_apply(git_repository *repo, const cmd_apply_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Declare all resources at the top, initialized to NULL */
    error_t *err = NULL;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;
    char *repo_dir = NULL;
    state_t *state = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *manifest = NULL;
    preflight_result_t *preflight = NULL;
    hook_context_t *hook_ctx = NULL;
    char *profiles_str = NULL;
    deploy_result_t *deploy_res = NULL;

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        error_free(err);
        err = NULL;
        config = config_create_default();
        if (!config) {
            return ERROR(ERR_MEMORY, "Failed to create default configuration");
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

    /* Get repository directory for hooks */
    if (config) {
        err = config_get_repo_dir(config, &repo_dir);
        if (err) {
            goto cleanup;
        }
    }

    /* Load state */
    err = state_load(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to load state");
        goto cleanup;
    }

    /* Load profiles */
    output_print(out, OUTPUT_VERBOSE, "Loading profiles...\n");

    err = profile_load_with_fallback(repo, opts->profiles, opts->profile_count,
                                      (const char **)config->profile_order, config->profile_order_count,
                                      config->auto_detect, config->strict_mode, &profiles);
    if (err) {
        err = error_wrap(err, "Failed to load profiles");
        goto cleanup;
    }

    if (profiles->count == 0) {
        err = ERROR(ERR_NOT_FOUND, "No profiles found");
        goto cleanup;
    }

    if (opts->verbose) {
        output_print(out, OUTPUT_VERBOSE, "Using %zu profile%s:\n",
                    profiles->count, profiles->count == 1 ? "" : "s");
        for (size_t i = 0; i < profiles->count; i++) {
            if (output_colors_enabled(out)) {
                fprintf(out->stream, "  %s•%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       profiles->profiles[i].name);
            } else {
                fprintf(out->stream, "  • %s\n", profiles->profiles[i].name);
            }
        }
    }

    /* Build manifest */
    output_print(out, OUTPUT_VERBOSE, "\nBuilding manifest...\n");

    err = profile_build_manifest(repo, profiles, &manifest);
    if (err) {
        err = error_wrap(err, "Failed to build manifest");
        goto cleanup;
    }

    if (opts->verbose) {
        output_print(out, OUTPUT_VERBOSE, "Manifest contains %zu file%s\n",
                    manifest->count, manifest->count == 1 ? "" : "s");
    }

    /* Run pre-flight checks */
    output_print(out, OUTPUT_VERBOSE, "\nRunning pre-flight checks...\n");

    deploy_options_t deploy_opts = {
        .force = opts->force,
        .dry_run = opts->dry_run,
        .verbose = opts->verbose,
        .skip_existing = opts->skip_existing,
        .skip_unchanged = opts->skip_unchanged
    };

    err = deploy_preflight_check(repo, manifest, state, &deploy_opts, &preflight);
    if (err) {
        err = error_wrap(err, "Pre-flight checks failed");
        goto cleanup;
    }

    print_preflight_results(out, preflight, config->strict_mode);

    /* Check for errors (conflicts, permissions) */
    if (preflight->has_errors) {
        err = ERROR(ERR_CONFLICT, "Pre-flight checks failed");
        goto cleanup;
    }

    /* In strict mode, overlaps are treated as errors */
    if (config->strict_mode && preflight->overlaps && string_array_size(preflight->overlaps) > 0) {
        err = ERROR(ERR_CONFLICT, "Overlapping files detected in strict mode");
        goto cleanup;
    }

    /* Preflight checks passed - free the results as we don't need them anymore */
    preflight_result_free(preflight);
    preflight = NULL;

    /* Execute pre-apply hook */
    if (config && repo_dir) {
        /* Join all profile names into a space-separated string */
        size_t total_len = 0;
        for (size_t i = 0; i < profiles->count; i++) {
            total_len += strlen(profiles->profiles[i].name);
            if (i < profiles->count - 1) {
                total_len++; /* For space separator */
            }
        }

        profiles_str = malloc(total_len + 1);
        if (profiles_str) {
            char *p = profiles_str;
            for (size_t i = 0; i < profiles->count; i++) {
                const char *name = profiles->profiles[i].name;
                strcpy(p, name);
                p += strlen(name);
                if (i < profiles->count - 1) {
                    *p++ = ' ';
                }
            }
            *p = '\0';

            /* Create hook context with all profiles */
            hook_ctx = hook_context_create(repo_dir, "apply", profiles_str);
            if (hook_ctx) {
                hook_ctx->dry_run = opts->dry_run;

                hook_result_t *hook_result = NULL;
                err = hook_execute(config, HOOK_PRE_APPLY, hook_ctx, &hook_result);

                if (err) {
                    /* Hook failed - abort operation */
                    if (hook_result && hook_result->output && hook_result->output[0]) {
                        fprintf(stderr, "Hook output:\n%s\n", hook_result->output);
                    }
                    hook_result_free(hook_result);
                    err = error_wrap(err, "Pre-apply hook failed");
                    goto cleanup;
                }
                hook_result_free(hook_result);
            }
        }
    }

    /* Confirm before deployment if configured (unless --force or --dry-run) */
    if (config->confirm_destructive && !opts->force && !opts->dry_run) {
        char prompt[256];
        snprintf(prompt, sizeof(prompt), "\nDeploy %zu file%s to filesystem?",
                manifest->count, manifest->count == 1 ? "" : "s");

        if (!confirm_action(prompt)) {
            output_info(out, "Cancelled");
            err = NULL;  /* Not an error - user cancelled */
            goto cleanup;
        }
    }

    /* Execute deployment */
    if (opts->dry_run) {
        output_print(out, OUTPUT_VERBOSE, "\nDry-run mode - no files will be modified\n");
    } else {
        output_print(out, OUTPUT_VERBOSE, "\nDeploying files...\n");
    }

    err = deploy_execute(repo, manifest, &deploy_opts, &deploy_res);
    if (err) {
        if (deploy_res) {
            print_deploy_results(out, deploy_res, opts->verbose);
        }
        err = error_wrap(err, "Deployment failed");
        goto cleanup;
    }

    print_deploy_results(out, deploy_res, opts->verbose);
    deploy_result_free(deploy_res);
    deploy_res = NULL;

    /* Save state (only if not dry-run) */
    if (!opts->dry_run) {
        /* Prune orphaned files BEFORE updating state (if requested)
         * This is critical: pruning needs to compare the OLD state (what was previously deployed)
         * against the NEW manifest (what should be deployed now).
         * If we update state first, we lose track of previously deployed files.
         */
        if (opts->prune) {
            err = apply_prune_orphaned_files(repo, state, manifest, out, opts->verbose);
            if (err) {
                goto cleanup;
            }
        }

        /* Now update state with the new manifest */
        err = apply_update_and_save_state(repo, state, profiles, manifest, out);
        if (err) {
            goto cleanup;
        }
    }

    /* Execute post-apply hook */
    if (config && hook_ctx && !opts->dry_run) {
        hook_result_t *hook_result = NULL;
        error_t *hook_err = hook_execute(config, HOOK_POST_APPLY, hook_ctx, &hook_result);

        if (hook_err) {
            /* Hook failed - warn but don't abort (already deployed) */
            output_warning(out, "Post-apply hook failed: %s", error_message(hook_err));
            if (hook_result && hook_result->output && hook_result->output[0]) {
                fprintf(stderr, "Hook output:\n%s\n", hook_result->output);
            }
            error_free(hook_err);
        }
        hook_result_free(hook_result);
    }

    /* Success - fall through to cleanup */
    err = NULL;

    /* Add trailing newline for UX consistency */
    if (out && out->stream) {
        fprintf(out->stream, "\n");
    }

cleanup:
    /* Free resources in reverse order of allocation */
    if (deploy_res) deploy_result_free(deploy_res);
    if (preflight) preflight_result_free(preflight);
    if (profiles_str) free(profiles_str);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (manifest) manifest_free(manifest);
    if (profiles) profile_list_free(profiles);
    if (state) state_free(state);
    if (repo_dir) free(repo_dir);
    if (config) config_free(config);
    if (out) output_free(out);

    return err;
}
