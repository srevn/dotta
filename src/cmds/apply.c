/**
 * apply.c - Apply profiles to filesystem
 */

#include "apply.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "core/cleanup.h"
#include "core/deploy.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/safety.h"
#include "core/state.h"
#include "crypto/keymanager.h"
#include "infra/content.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/hooks.h"
#include "utils/output.h"

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

    /* Print ownership changes */
    if (result->ownership_changes && result->ownership_change_count > 0) {
        output_section(out, "Ownership changes");
        output_info(out, "  The following files will change ownership:");
        for (size_t i = 0; i < result->ownership_change_count; i++) {
            const ownership_change_t *change = &result->ownership_changes[i];
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s→%s %s: %s%s%s → %s%s%s\n",
                       output_color_code(out, OUTPUT_COLOR_YELLOW),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       change->filesystem_path,
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       change->old_profile,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       change->new_profile,
                       output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  → %s: %s → %s\n",
                       change->filesystem_path,
                       change->old_profile,
                       change->new_profile);
            }
        }
        output_info(out, "  This means these files will now be managed by a different profile.");
        output_newline(out);
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
                output_printf(out, OUTPUT_NORMAL, "  %s✓%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_GREEN),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->deployed, i));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  ✓ %s\n", string_array_get(result->deployed, i));
            }
        }
    }

    if (verbose && result->skipped && string_array_size(result->skipped) > 0) {
        output_section(out, "Skipped files");
        for (size_t i = 0; i < string_array_size(result->skipped); i++) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s⊘%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->skipped, i));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  ⊘ %s\n", string_array_get(result->skipped, i));
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
                output_printf(out, OUTPUT_NORMAL, "Deployed %s%zu%s file%s\n",
                       output_color_code(out, OUTPUT_COLOR_GREEN),
                       result->deployed_count,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       result->deployed_count == 1 ? "" : "s");
            } else {
                output_printf(out, OUTPUT_NORMAL, "Deployed %zu file%s\n",
                       result->deployed_count,
                       result->deployed_count == 1 ? "" : "s");
            }
        }

        if (result->skipped_count > 0) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "Skipped %s%zu%s file%s (up-to-date)\n",
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       result->skipped_count,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       result->skipped_count == 1 ? "" : "s");
            } else {
                output_printf(out, OUTPUT_NORMAL, "Skipped %zu file%s (up-to-date)\n",
                       result->skipped_count,
                       result->skipped_count == 1 ? "" : "s");
            }
        }
    }
}

/**
 * Print safety violations
 */
static void print_safety_violations(
    const output_ctx_t *out,
    const safety_result_t *safety_result
) {
    if (!safety_result || safety_result->count == 0) {
        return;
    }

    output_section(out, "Modified orphaned files detected");
    output_newline(out);

    output_warning(out, "The following files cannot be safely removed:");

    for (size_t i = 0; i < safety_result->count; i++) {
        const safety_violation_t *v = &safety_result->violations[i];

        /* Format reason for display */
        const char *reason_display = NULL;
        const char *icon = "•";

        if (strcmp(v->reason, SAFETY_REASON_MODIFIED) == 0) {
            reason_display = "modified";
            icon = "✗";
        } else if (strcmp(v->reason, SAFETY_REASON_MODE_CHANGED) == 0) {
            reason_display = "permissions changed";
            icon = "⚠";
        } else if (strcmp(v->reason, SAFETY_REASON_TYPE_CHANGED) == 0) {
            reason_display = "type changed";
            icon = "⚠";
        } else if (strcmp(v->reason, SAFETY_REASON_PROFILE_DELETED) == 0) {
            reason_display = "profile branch deleted";
            icon = "!";
        } else if (strcmp(v->reason, SAFETY_REASON_FILE_REMOVED) == 0) {
            reason_display = "removed from profile";
            icon = "!";
        } else if (strcmp(v->reason, SAFETY_REASON_CANNOT_VERIFY) == 0) {
            reason_display = "cannot verify";
            icon = "?";
        } else {
            reason_display = v->reason;
        }

        if (output_colors_enabled(out)) {
            const char *reason_color = v->content_modified ?
                output_color_code(out, OUTPUT_COLOR_RED) :
                output_color_code(out, OUTPUT_COLOR_YELLOW);

            output_printf(out, OUTPUT_NORMAL, "  %s%s%s %s %s(%s",
                   reason_color,
                   icon,
                   output_color_code(out, OUTPUT_COLOR_RESET),
                   v->filesystem_path,
                   reason_color,
                   reason_display);

            if (v->source_profile) {
                output_printf(out, OUTPUT_NORMAL, " from %s%s%s",
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       v->source_profile,
                       reason_color);
            }

            output_printf(out, OUTPUT_NORMAL, ")%s\n",
                   output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %s %s (%s",
                   icon, v->filesystem_path, reason_display);

            if (v->source_profile) {
                output_printf(out, OUTPUT_NORMAL, " from %s", v->source_profile);
            }

            output_printf(out, OUTPUT_NORMAL, ")\n");
        }
    }
    output_newline(out);

    output_info(out, "These files are from disabled profiles but have uncommitted changes.");
    output_info(out, "To prevent data loss, commit changes before removing:");
    output_newline(out);
    output_info(out, "Options:");
    output_info(out, "  1. Commit changes to the profile:");

    /* Get first violation's profile for example commands */
    const char *example_profile = NULL;
    if (safety_result->count > 0 && safety_result->violations[0].source_profile) {
        example_profile = safety_result->violations[0].source_profile;
    }

    if (example_profile) {
        output_info(out, "     dotta update -p %s <files>", example_profile);
        output_info(out, "     dotta apply");
    } else {
        output_info(out, "     dotta update <files>");
        output_info(out, "     dotta apply");
    }

    output_info(out, "  2. Force removal (discards changes):");
    output_info(out, "     dotta apply --force");
    output_info(out, "  3. Keep the profile enabled:");

    if (example_profile) {
        output_info(out, "     dotta profile enable %s", example_profile);
    }
}

/**
 * Print cleanup results
 */
static void print_cleanup_results(
    const output_ctx_t *out,
    const cleanup_result_t *result,
    bool verbose
) {
    if (!result) {
        return;
    }

    /* Display safety violations first (most important) */
    if (result->safety_violations) {
        print_safety_violations(out, result->safety_violations);
    }

    /* Display orphaned files */
    if (verbose && result->removed_files && string_array_size(result->removed_files) > 0) {
        output_section(out, "Pruned orphaned files");
        for (size_t i = 0; i < string_array_size(result->removed_files); i++) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s[removed]%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_GREEN),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->removed_files, i));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  [removed] %s\n",
                       string_array_get(result->removed_files, i));
            }
        }
    }

    if (verbose && result->skipped_files && string_array_size(result->skipped_files) > 0) {
        output_section(out, "Skipped orphaned files");
        for (size_t i = 0; i < string_array_size(result->skipped_files); i++) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s[skipped]%s %s (safety violation)\n",
                       output_color_code(out, OUTPUT_COLOR_YELLOW),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->skipped_files, i));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  [skipped] %s (safety violation)\n",
                       string_array_get(result->skipped_files, i));
            }
        }
    }

    if (verbose && result->failed_files && string_array_size(result->failed_files) > 0) {
        output_section(out, "Failed to remove orphaned files");
        for (size_t i = 0; i < string_array_size(result->failed_files); i++) {
            if (output_colors_enabled(out)) {
                fprintf(stderr, "  %s[fail]%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_RED),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->failed_files, i));
            } else {
                fprintf(stderr, "  [fail] %s\n",
                       string_array_get(result->failed_files, i));
            }
        }
    }

    /* Display empty directories */
    if (verbose && result->removed_dirs && string_array_size(result->removed_dirs) > 0) {
        output_section(out, "Pruned empty tracked directories");
        for (size_t i = 0; i < string_array_size(result->removed_dirs); i++) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s[removed]%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_GREEN),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->removed_dirs, i));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  [removed] %s\n",
                       string_array_get(result->removed_dirs, i));
            }
        }
    }

    if (verbose && result->failed_dirs && string_array_size(result->failed_dirs) > 0) {
        output_section(out, "Failed to remove empty directories");
        for (size_t i = 0; i < string_array_size(result->failed_dirs); i++) {
            if (output_colors_enabled(out)) {
                fprintf(stderr, "  %s[fail]%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_RED),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       string_array_get(result->failed_dirs, i));
            } else {
                fprintf(stderr, "  [fail] %s\n",
                       string_array_get(result->failed_dirs, i));
            }
        }
    }

    /* Print summaries if not verbose */
    if (!verbose) {
        if (result->orphaned_files_removed > 0) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "Pruned %s%zu%s orphaned file%s\n",
                       output_color_code(out, OUTPUT_COLOR_YELLOW),
                       result->orphaned_files_removed,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       result->orphaned_files_removed == 1 ? "" : "s");
            } else {
                output_printf(out, OUTPUT_NORMAL, "Pruned %zu orphaned file%s\n",
                       result->orphaned_files_removed,
                       result->orphaned_files_removed == 1 ? "" : "s");
            }
        }

        if (result->directories_removed > 0) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "Pruned %s%zu%s empty director%s\n",
                       output_color_code(out, OUTPUT_COLOR_YELLOW),
                       result->directories_removed,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       result->directories_removed == 1 ? "y" : "ies");
            } else {
                output_printf(out, OUTPUT_NORMAL, "Pruned %zu empty director%s\n",
                       result->directories_removed,
                       result->directories_removed == 1 ? "y" : "ies");
            }
        }

        if (result->orphaned_files_failed > 0 || result->directories_failed > 0) {
            size_t total_failed = result->orphaned_files_failed + result->directories_failed;
            output_warning(out, "Failed to prune %zu item%s",
                   total_failed,
                   total_failed == 1 ? "" : "s");
        }
    }
}

/**
 * Update state with deployed files and save to disk
 *
 * This function does NOT modify the enabled profile list in state.
 * Enabled profiles are managed exclusively by 'dotta profile enable/disable'
 * commands. Apply only deploys files and updates the file tracking list.
 *
 * The state file tracks:
 * - Enabled profiles - Modified ONLY by 'dotta profile' commands
 * - Deployed files - Modified by 'dotta apply' and 'dotta revert'
 *
 * This separation ensures:
 * - User's explicit profile management is never overwritten
 * - Temporary CLI overrides (-p flag) don't persist to state
 * - Profile management is predictable and intentional
 *
 * @param repo Repository (must not be NULL)
 * @param state State to update (must not be NULL)
 * @param profiles Profiles being applied (used for file tracking only)
 * @param manifest Manifest of deployed files (must not be NULL)
 * @param metadata Merged metadata for mode extraction (can be NULL)
 * @param out Output context for messages (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *apply_update_and_save_state(
    git_repository *repo,
    state_t *state,
    const profile_list_t *profiles,
    const manifest_t *manifest,
    const metadata_t *metadata,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(profiles);
    CHECK_NULL(manifest);
    CHECK_NULL(out);

    error_t *err = NULL;

    /* Clear old files and add new manifest */
    err = state_clear_files(state);
    if (err) {
        return error_wrap(err, "Failed to clear deployment state");
    }

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

        /* Look up mode from metadata (if available) */
        const char *mode_str = NULL;
        char mode_buf[5];  /* Stack buffer for "0777\0" (max 5 bytes) */

        if (metadata) {
            const metadata_entry_t *meta_entry = NULL;
            error_t *meta_err = metadata_get_entry(metadata, entry->storage_path, &meta_entry);

            if (!meta_err && meta_entry) {
                /* Format mode directly into stack buffer (no heap allocation) */
                snprintf(mode_buf, sizeof(mode_buf), "%04o", (unsigned int)(meta_entry->mode & 0777));
                mode_str = mode_buf;
            } else if (meta_err) {
                /* Not found is expected for symlinks and other cases - not an error */
                error_free(meta_err);
            }
        }

        /* Create state entry */
        state_file_entry_t *state_entry = NULL;
        err = state_create_entry(
            entry->storage_path,
            entry->filesystem_path,
            entry->source_profile->name,
            type,
            hash_str,  /* hash computed from blob OID */
            mode_str,  /* mode from metadata (may be NULL) */
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
    metadata_t *merged_metadata = NULL;
    content_cache_t *cache = NULL;
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

    /* Load state (with locking for write transaction) */
    err = state_load_for_update(repo, &state);
    if (err) {
        err = error_wrap(err, "Failed to load state");
        goto cleanup;
    }

    /* Load profiles */
    output_print(out, OUTPUT_VERBOSE, "Loading profiles...\n");

    /*
     * Resolve profiles using priority hierarchy:
     * 1. CLI -p flag (temporary override)
     * 2. State enabled_profiles (persistent management via 'dotta profile enable')
     */
    profile_source_t profile_source;  /* For informational purposes only */
    err = profile_resolve(repo, opts->profiles, opts->profile_count,
                         config->strict_mode, &profiles, &profile_source);

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
                output_printf(out, OUTPUT_NORMAL, "  %s•%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       profiles->profiles[i].name);
            } else {
                output_printf(out, OUTPUT_NORMAL, "  • %s\n", profiles->profiles[i].name);
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

    /* Load and merge metadata from profiles */
    output_print(out, OUTPUT_VERBOSE, "\nLoading metadata...\n");

    {
        /* Allocate array to hold metadata from each profile */
        metadata_t **profile_metadata = calloc(profiles->count, sizeof(metadata_t *));
        if (!profile_metadata) {
            err = ERROR(ERR_MEMORY, "Failed to allocate profile metadata array");
            goto cleanup;
        }

        size_t loaded_count = 0;

        /* Load metadata from each profile (in order for proper layering) */
        for (size_t i = 0; i < profiles->count; i++) {
            const char *profile_name = profiles->profiles[i].name;
            metadata_t *meta = NULL;

            error_t *meta_err = metadata_load_from_branch(repo, profile_name, &meta);
            if (meta_err) {
                if (meta_err->code == ERR_NOT_FOUND) {
                    /* No metadata in this profile - not an error */
                    if (opts->verbose) {
                        output_print(out, OUTPUT_VERBOSE,
                                    "  No metadata in profile '%s'\n", profile_name);
                    }
                    error_free(meta_err);
                } else {
                    /* Real error - clean up and propagate */
                    for (size_t j = 0; j < loaded_count; j++) {
                        metadata_free(profile_metadata[j]);
                    }
                    free(profile_metadata);
                    err = error_wrap(meta_err, "Failed to load metadata from profile '%s'",
                                   profile_name);
                    goto cleanup;
                }
            } else {
                /* Successfully loaded */
                profile_metadata[i] = meta;
                loaded_count++;
                if (opts->verbose) {
                    output_print(out, OUTPUT_VERBOSE,
                                "  Loaded %zu metadata entr%s from profile '%s'\n",
                                meta->count, meta->count == 1 ? "y" : "ies", profile_name);
                }
            }
        }

        /* Merge metadata according to profile precedence */
        if (loaded_count > 0) {
            err = metadata_merge((const metadata_t **)profile_metadata, profiles->count, &merged_metadata);

            /* Free individual profile metadata */
            for (size_t i = 0; i < profiles->count; i++) {
                if (profile_metadata[i]) {
                    metadata_free(profile_metadata[i]);
                }
            }

            if (err) {
                free(profile_metadata);
                err = error_wrap(err, "Failed to merge metadata");
                goto cleanup;
            }

            if (opts->verbose) {
                output_print(out, OUTPUT_VERBOSE,
                            "  Merged metadata: %zu entr%s total\n",
                            merged_metadata->count,
                            merged_metadata->count == 1 ? "y" : "ies");
            }
        } else {
            if (opts->verbose) {
                output_print(out, OUTPUT_VERBOSE, "  No metadata found in any profile\n");
            }
        }

        free(profile_metadata);
    }

    /* Create content cache for batch operations (reused across preflight and deployment)
     *
     * Architecture: The cache is created once and shared between preflight and deploy phases.
     * This provides significant performance benefits:
     * - Preflight decrypts files for comparison (cache miss - populates cache)
     * - Smart skip reuses cached content (cache hit - O(1) lookup)
     * - Deploy reuses cached content (cache hit - O(1) lookup)
     *
     * Result: Each blob is decrypted at most once, saving 2-3x redundant decryptions.
     */
    keymanager_t *km = keymanager_get_global(NULL);
    cache = content_cache_create(repo, km);
    if (!cache) {
        err = ERROR(ERR_MEMORY, "Failed to create content cache for deployment");
        goto cleanup;
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

    err = deploy_preflight_check(repo, manifest, state, &deploy_opts, km, cache, merged_metadata, &preflight);
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
        if (!profiles_str) {
            err = ERROR(ERR_MEMORY, "Failed to allocate profile names string");
            goto cleanup;
        }

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
                    output_printf(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
                }
                hook_result_free(hook_result);
                err = error_wrap(err, "Pre-apply hook failed");
                goto cleanup;
            }
            hook_result_free(hook_result);
        }
    }

    /* Confirm before deployment if configured (unless --force or --dry-run) */
    if (config->confirm_destructive && !opts->force && !opts->dry_run) {
        char prompt[256];
        snprintf(prompt, sizeof(prompt), "Deploy %zu file%s to filesystem?",
                manifest->count, manifest->count == 1 ? "" : "s");

        if (!output_confirm(out, prompt, false)) {
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

    err = deploy_execute(repo, manifest, state, merged_metadata, &deploy_opts, km, cache, &deploy_res);
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
        /* Prune orphaned files BEFORE updating state (unless --keep-orphans)
         *
         * Architecture:
         * 1. Pruning identifies orphaned files by comparing OLD state against NEW manifest
         * 2. Pruning removes orphaned files from filesystem ONLY (no state modification)
         * 3. State is rebuilt atomically from manifest (orphaned files naturally absent)
         *
         * This separation ensures:
         * - Single source of truth: state updated once, atomically
         * - Clear responsibility: filesystem ops separate from state tracking
         * - Better atomicity: all-or-nothing state update
         *
         * Apply is a synchronization operation - it ensures the filesystem matches
         * the declared state by both deploying new/updated files AND removing orphaned ones.
         *
         * The --keep-orphans flag allows opting out of automatic cleanup for advanced workflows.
         */
        if (!opts->keep_orphans) {
            /* Execute cleanup: remove orphaned files and prune empty directories */
            cleanup_result_t *cleanup_res = NULL;
            cleanup_options_t cleanup_opts = {
                .enabled_metadata = merged_metadata,
                .enabled_profiles = profiles,
                .cache = cache,    /* Pass cache for performance (avoids re-decryption) */
                .verbose = opts->verbose,
                .dry_run = false,  /* Dry-run handled at deployment level */
                .force = opts->force
            };

            err = cleanup_execute(repo, state, manifest, &cleanup_opts, &cleanup_res);
            if (err) {
                /* Display partial results before propagating error */
                if (cleanup_res) {
                    print_cleanup_results(out, cleanup_res, opts->verbose);
                }
                cleanup_result_free(cleanup_res);
                goto cleanup;
            }

            /* Display cleanup results */
            print_cleanup_results(out, cleanup_res, opts->verbose);

            /* Check if cleanup was blocked by safety violations */
            if (cleanup_res && cleanup_res->safety_violations &&
                cleanup_res->safety_violations->count > 0 && !opts->force) {
                /* Safety violations detected and displayed by print_cleanup_results() */
                size_t violation_count = cleanup_res->safety_violations->count;
                cleanup_result_free(cleanup_res);
                err = ERROR(ERR_CONFLICT,
                           "Cannot remove %zu orphaned file%s with uncommitted changes",
                           violation_count,
                           violation_count == 1 ? "" : "s");
                goto cleanup;
            }

            cleanup_result_free(cleanup_res);
        }

        /* Now update state with the new manifest */
        err = apply_update_and_save_state(repo, state, profiles, manifest, merged_metadata, out);
        if (err) {
            goto cleanup;
        }
    }

    /* Execute post-apply hook */
    if (hook_ctx && !opts->dry_run) {
        hook_result_t *hook_result = NULL;
        error_t *hook_err = hook_execute(config, HOOK_POST_APPLY, hook_ctx, &hook_result);

        if (hook_err) {
            /* Hook failed - warn but don't abort (already deployed) */
            output_warning(out, "Post-apply hook failed: %s", error_message(hook_err));
            if (hook_result && hook_result->output && hook_result->output[0]) {
                output_printf(out, OUTPUT_NORMAL, "Hook output:\n%s\n", hook_result->output);
            }
            error_free(hook_err);
        }
        hook_result_free(hook_result);
    }

    /* Success - fall through to cleanup */
    err = NULL;

cleanup:
    /* Free resources in reverse order of allocation */
    if (deploy_res) deploy_result_free(deploy_res);
    if (preflight) preflight_result_free(preflight);
    if (profiles_str) free(profiles_str);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (cache) content_cache_free(cache);
    if (merged_metadata) metadata_free(merged_metadata);
    if (manifest) manifest_free(manifest);
    if (profiles) profile_list_free(profiles);
    if (state) state_free(state);
    if (repo_dir) free(repo_dir);
    if (config) config_free(config);
    if (out) output_free(out);

    return err;
}
