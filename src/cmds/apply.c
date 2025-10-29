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
#include "core/workspace.h"
#include "crypto/keymanager.h"
#include "infra/content.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/hooks.h"
#include "utils/output.h"
#include "utils/privilege.h"

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

    /* Get first violation's profile for example commands */
    const char *example_profile = NULL;
    if (safety_result->count > 0 && safety_result->violations[0].source_profile) {
        example_profile = safety_result->violations[0].source_profile;
    }

    output_hint(out, "Options:");
    output_hint_line(out, "  1. Commit changes to the profile:");

    if (example_profile) {
        output_hint_line(out, "     dotta update -p %s <files>", example_profile);
        output_hint_line(out, "     dotta apply");
    } else {
        output_hint_line(out, "     dotta update <files>");
        output_hint_line(out, "     dotta apply");
    }

    output_hint_line(out, "  2. Force removal (discards changes):");
    output_hint_line(out, "     dotta apply --force");
    output_hint_line(out, "  3. Keep the profile enabled:");

    if (example_profile) {
        output_hint_line(out, "     dotta profile enable %s", example_profile);
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

        if (result->orphaned_directories_removed > 0) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "Pruned %s%zu%s orphaned director%s\n",
                       output_color_code(out, OUTPUT_COLOR_YELLOW),
                       result->orphaned_directories_removed,
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       result->orphaned_directories_removed == 1 ? "y" : "ies");
            } else {
                output_printf(out, OUTPUT_NORMAL, "Pruned %zu orphaned director%s\n",
                       result->orphaned_directories_removed,
                       result->orphaned_directories_removed == 1 ? "y" : "ies");
            }
        }

        if (result->orphaned_files_failed > 0 || result->orphaned_directories_failed > 0) {
            size_t total_failed = result->orphaned_files_failed + result->orphaned_directories_failed;
            output_warning(out, "Failed to prune %zu item%s",
                   total_failed,
                   total_failed == 1 ? "" : "s");
        }
    }
}

/**
 * Print cleanup preflight results
 *
 * Shows what cleanup will do BEFORE user confirmation.
 * This enables informed consent by revealing the full impact of orphan cleanup.
 */
static void print_cleanup_preflight_results(
    const output_ctx_t *out,
    const cleanup_preflight_result_t *result,
    bool verbose
) {
    if (!result) {
        return;
    }

    /* Case 1: No orphans and no directories - nothing to display */
    if (!result->will_prune_orphans && !result->will_prune_directories) {
        if (verbose) {
            output_print(out, OUTPUT_VERBOSE, "No orphaned files or directories to prune\n");
        }
        return;
    }

    /* Case 2: Orphaned files found - always show summary */
    if (result->will_prune_orphans) {
        output_section(out, "Orphaned files");

        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "  %s%zu%s file%s will be removed (no longer in any profile)\n",
                   output_color_code(out, OUTPUT_COLOR_YELLOW),
                   result->orphaned_files_count,
                   output_color_code(out, OUTPUT_COLOR_RESET),
                   result->orphaned_files_count == 1 ? "" : "s");
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %zu file%s will be removed (no longer in any profile)\n",
                   result->orphaned_files_count,
                   result->orphaned_files_count == 1 ? "" : "s");
        }

        /* Show individual paths in verbose mode */
        if (verbose && result->orphaned_files && result->orphaned_files_count > 0) {
            size_t display_limit = 20;  /* Don't flood the terminal */
            size_t display_count = result->orphaned_files_count < display_limit ?
                                  result->orphaned_files_count : display_limit;

            for (size_t i = 0; i < display_count; i++) {
                if (output_colors_enabled(out)) {
                    output_printf(out, OUTPUT_NORMAL, "    %s•%s %s\n",
                           output_color_code(out, OUTPUT_COLOR_CYAN),
                           output_color_code(out, OUTPUT_COLOR_RESET),
                           string_array_get(result->orphaned_files, i));
                } else {
                    output_printf(out, OUTPUT_NORMAL, "    • %s\n",
                           string_array_get(result->orphaned_files, i));
                }
            }

            if (result->orphaned_files_count > display_limit) {
                size_t remaining = result->orphaned_files_count - display_limit;
                output_printf(out, OUTPUT_NORMAL, "    ... and %zu more\n", remaining);
            }
        }
    }

    /* Case 3: Safety violations - ALWAYS show (blocking) */
    if (result->has_blocking_violations) {
        output_newline(out);  /* Add spacing before safety violations */
        print_safety_violations(out, result->safety_violations);
    }

    /* Case 4: Empty directories - only in verbose mode */
    if (verbose && result->will_prune_directories) {
        output_section(out, "Empty directories");

        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "  %s%zu%s orphaned director%s will be pruned\n",
                   output_color_code(out, OUTPUT_COLOR_CYAN),
                   result->orphaned_directories_count,
                   output_color_code(out, OUTPUT_COLOR_RESET),
                   result->orphaned_directories_count == 1 ? "y" : "ies");
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %zu orphaned director%s will be pruned\n",
                   result->orphaned_directories_count,
                   result->orphaned_directories_count == 1 ? "y" : "ies");
        }

        /* Show directory paths if not too many */
        if (result->orphaned_directories && result->orphaned_directories_count <= 10) {
            for (size_t i = 0; i < result->orphaned_directories_count; i++) {
                output_printf(out, OUTPUT_NORMAL, "    • %s\n",
                       string_array_get(result->orphaned_directories, i));
            }
        }
    }

    output_newline(out);
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
 * @param ws Workspace containing repo, profiles, manifest, and metadata cache (must not be NULL)
 * @param state State to update (must not be NULL)
 * @param metadata Merged metadata for mode extraction (can be NULL)
 * @param out Output context for messages (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *apply_update_and_save_state(
    workspace_t *ws,
    state_t *state,
    const metadata_t *metadata,
    output_ctx_t *out
) {
    CHECK_NULL(ws);
    CHECK_NULL(state);
    CHECK_NULL(out);

    /* Extract data from workspace using accessor functions */
    git_repository *repo = workspace_get_repo(ws);
    const profile_list_t *profiles = workspace_get_profiles(ws);
    const manifest_t *manifest = workspace_get_manifest(ws);

    /* Defensive checks: workspace should always have these initialized */
    if (!repo || !profiles || !manifest) {
        return ERROR(ERR_INTERNAL,
                    "Workspace missing required data (repo=%p, profiles=%p, manifest=%p)",
                    (void*)repo, (void*)profiles, (void*)manifest);
    }

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
            const metadata_item_t *item = NULL;
            error_t *meta_err = metadata_get_item(metadata, entry->storage_path, &item);

            if (!meta_err && item) {
                /* Defensive: Check kind (files should have file entries, symlinks may not exist) */
                if (item->kind == METADATA_ITEM_FILE) {
                    /* Format mode directly into stack buffer (no heap allocation) */
                    snprintf(mode_buf, sizeof(mode_buf), "%04o", (unsigned int)(item->mode & 0777));
                    mode_str = mode_buf;
                }
                /* If it's a directory entry, skip (shouldn't happen for files in manifest) */
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

    /* Sync tracked directories to state */
    output_print(out, OUTPUT_VERBOSE, "\nSyncing tracked directories to state...\n");

    err = state_clear_directories(state);
    if (err) {
        return error_wrap(err, "Failed to clear tracked directories from state");
    }

    /* Load per-profile metadata to preserve profile attribution
     *
     * Architecture: We cannot use merged_metadata here because it loses
     * profile attribution (all directories merged into one list without
     * source profile information). Instead, we retrieve each profile's metadata
     * from the workspace cache to correctly associate directories with their source profile.
     */
    for (size_t p = 0; p < profiles->count; p++) {
        const char *profile_name = profiles->profiles[p].name;

        /* Get cached metadata for this profile (O(1) hashmap lookup) */
        const metadata_t *profile_meta = workspace_get_metadata(ws, profile_name);

        /* Defensive check: workspace should always have metadata for enabled profiles.
         * During workspace_load(), empty metadata is created for profiles without
         * metadata.json, so NULL here indicates an invariant violation. */
        if (!profile_meta) {
            output_print(out, OUTPUT_VERBOSE,
                        "  No metadata in profile '%s' (skipping directories)\n",
                        profile_name);
            continue;
        }

        /* Get tracked directories from this profile's metadata */
        size_t dir_count = 0;
        const metadata_item_t **directories =
            metadata_get_items_by_kind(profile_meta, METADATA_ITEM_DIRECTORY, &dir_count);

        if (dir_count > 0) {
            output_print(out, OUTPUT_VERBOSE, "  Syncing %zu director%s from profile '%s'\n",
                        dir_count, dir_count == 1 ? "y" : "ies", profile_name);
        }

        /* Convert each directory to state entry and add to state */
        for (size_t i = 0; i < dir_count; i++) {
            state_directory_entry_t *state_dir = NULL;

            err = state_directory_entry_create_from_metadata(
                directories[i],
                profile_name,
                &state_dir
            );

            if (err) {
                free(directories);
                return error_wrap(err, "Failed to create state directory entry for '%s'",
                                directories[i]->key);
            }

            err = state_add_directory(state, state_dir);
            state_free_directory_entry(state_dir);

            if (err) {
                free(directories);
                return error_wrap(err, "Failed to add directory '%s' to state",
                                directories[i]->key);
            }
        }

        /* Free the pointer array (items themselves are owned by metadata) */
        free(directories);

        /* Note: profile_meta is borrowed from workspace cache - no free needed */
    }

    output_print(out, OUTPUT_VERBOSE, "Directory sync complete\n");
    /* End tracked directories sync */

    /* Save updated state */
    err = state_save(repo, state);
    if (err) {
        return error_wrap(err, "Failed to save state");
    }

    output_print(out, OUTPUT_VERBOSE, "\nState saved\n");

    return NULL;
}

/**
 * Check privileges for complete apply operation
 *
 * Examines BOTH manifest (files being deployed) and orphans (files being removed)
 * for root/ paths. This ensures we have required privileges BEFORE attempting
 * any filesystem modifications.
 *
 * The privilege gap this fixes:
 * - Before: Only checked manifest → missed orphaned root/ files → cleanup failed silently
 * - After: Checks both manifest + orphans → prompts for elevation → cleanup succeeds
 *
 * @param manifest Files being deployed (must not be NULL)
 * @param orphans Files being removed (can be NULL if --keep-orphans)
 * @param opts Apply command options (must not be NULL)
 * @param out Output context for messages (must not be NULL)
 * @return NULL if OK to proceed, error otherwise (or does not return if re-exec with sudo)
 */
static error_t *ensure_complete_apply_privileges(
    const manifest_t *manifest,
    const orphan_list_t *orphans,
    const cmd_apply_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    if (opts->dry_run) {
        return NULL;  /* Read-only operation, no privileges needed */
    }

    string_array_t *root_paths = string_array_create();
    if (!root_paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate root paths list");
    }

    /* 1. Collect root/ paths from manifest (files being deployed) */
    for (size_t i = 0; i < manifest->count; i++) {
        if (privilege_path_requires_root(manifest->entries[i].storage_path)) {
            error_t *err = string_array_push(root_paths, manifest->entries[i].storage_path);
            if (err) {
                string_array_free(root_paths);
                return error_wrap(err, "Failed to add manifest root path");
            }
        }
    }

    /* 2. Collect root/ paths from orphans (files being removed) */
    if (orphans) {
        for (size_t i = 0; i < orphans->count; i++) {
            if (privilege_path_requires_root(orphans->entries[i].storage_path)) {
                error_t *err = string_array_push(root_paths, orphans->entries[i].storage_path);
                if (err) {
                    string_array_free(root_paths);
                    return error_wrap(err, "Failed to add orphan root path");
                }
            }
        }
    }

    /* 3. Check privileges if any root/ paths found */
    error_t *err = NULL;
    if (string_array_size(root_paths) > 0) {
        err = privilege_ensure_for_operation(
            (const char**)root_paths->items,
            root_paths->count,
            "apply",
            true,  /* interactive: prompt user if elevation needed */
            opts->argc,
            opts->argv,
            out
        );
    }

    string_array_free(root_paths);
    return err;
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
    const manifest_t *manifest = NULL;
    workspace_t *ws = NULL;
    orphan_list_t *orphans = NULL;
    orphan_directory_list_t *dir_orphans = NULL;
    metadata_t *merged_metadata = NULL;
    content_cache_t *cache = NULL;
    preflight_result_t *preflight = NULL;
    cleanup_preflight_result_t *cleanup_preflight = NULL;
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

    /* Load workspace (includes manifest building and metadata loading)
     *
     * The workspace builds the manifest internally during initialization,
     * eliminating redundant manifest building. We extract the manifest
     * immediately after loading for use throughout the command.
     */
    output_print(out, OUTPUT_VERBOSE, "\nLoading workspace...\n");

    /* Apply needs file divergence + orphan detection for deployment and cleanup */
    workspace_load_t ws_opts = {
        .analyze_files = true,
        .analyze_orphans = true,
        .analyze_untracked = false,    /* Skip expensive directory scan */
        .analyze_directories = false,  /* Not needed for deployment */
        .analyze_encryption = false    /* Not needed for deployment */
    };
    err = workspace_load(repo, profiles, config, &ws_opts, &ws);
    if (err) {
        err = error_wrap(err, "Failed to load workspace");
        goto cleanup;
    }

    /* Extract manifest from workspace (borrowed reference, owned by workspace) */
    manifest = workspace_get_manifest(ws);
    if (!manifest) {
        err = ERROR(ERR_INTERNAL, "Workspace manifest is NULL");
        goto cleanup;
    }

    if (opts->verbose) {
        output_print(out, OUTPUT_VERBOSE, "Workspace loaded: %zu file%s in manifest\n",
                    manifest->count, manifest->count == 1 ? "" : "s");
    }

    /* Identify orphaned files (unless --keep-orphans)
     *
     * Architecture: Orphan identification is expensive O(N+M). We compute once here,
     * then reuse the result for:
     * 1. Privilege checking (filter root/ paths) - line ~948
     * 2. Preflight display (show user what will be removed) - line ~1048
     * 3. Actual removal (pass to cleanup) - line ~1193
     *
     * This eliminates 2×-3× redundant computation and fixes the privilege gap
     * (before: only checked manifest, missed orphaned root/ files).
     */
    if (!opts->keep_orphans) {
        output_print(out, OUTPUT_VERBOSE, "\nIdentifying orphaned files...\n");

        err = cleanup_identify_orphans(state, manifest, &orphans);
        if (err) {
            err = error_wrap(err, "Failed to identify orphaned files");
            goto cleanup;
        }

        if (opts->verbose && orphans && orphans->count > 0) {
            output_print(out, OUTPUT_VERBOSE,
                        "Found %zu orphaned file%s\n",
                        orphans->count,
                        orphans->count == 1 ? "" : "s");
        }
    }

    /* Extract merged metadata from workspace
     *
     * workspace_get_merged_metadata() merges metadata across all profiles
     * in precedence order (global → OS → host). The workspace was already
     * loaded earlier, so we just extract the merged metadata here.
     */
    output_print(out, OUTPUT_VERBOSE, "\nExtracting merged metadata...\n");

    err = workspace_get_merged_metadata(ws, &merged_metadata);
    if (err) {
        err = error_wrap(err, "Failed to get merged metadata from workspace");
        goto cleanup;
    }

    if (opts->verbose) {
        if (merged_metadata && merged_metadata->count > 0) {
            output_print(out, OUTPUT_VERBOSE,
                        "  Merged metadata: %zu entr%s total\n",
                        merged_metadata->count,
                        merged_metadata->count == 1 ? "y" : "ies");
        } else {
            output_print(out, OUTPUT_VERBOSE, "  No metadata found in any profile\n");
        }
    }

    /* Identify orphaned directories (state vs metadata)
     *
     * Similar to file orphan identification above, this computes the list of
     * directories that are tracked in state but no longer in any enabled profile's
     * metadata. Must happen AFTER metadata loading.
     *
     * Used for:
     * 1. Preflight display (show user what will be removed)
     * 2. Actual removal (pass to cleanup)
     */
    if (!opts->keep_orphans) {
        output_print(out, OUTPUT_VERBOSE, "\nIdentifying orphaned directories...\n");

        err = cleanup_identify_orphaned_directories(state, merged_metadata, &dir_orphans);
        if (err) {
            err = error_wrap(err, "Failed to identify orphaned directories");
            goto cleanup;
        }

        if (opts->verbose && dir_orphans && dir_orphans->count > 0) {
            output_print(out, OUTPUT_VERBOSE,
                        "Found %zu orphaned director%s\n",
                        dir_orphans->count,
                        dir_orphans->count == 1 ? "y" : "ies");
        }
    }

    /* Check privileges for root/ files BEFORE deployment begins
     *
     * This ensures we have required privileges upfront, preventing partial
     * deployments and cryptic mid-operation failures. Checks occur AFTER
     * manifest building AND orphan identification (know all files) but BEFORE
     * any filesystem modifications.
     *
     * Skip check if dry-run (read-only operation, no privileges needed).
     *
     * If re-exec with sudo occurs, the entire process restarts from main(),
     * and state lock is safely released before execvp() replaces the process.
     */
    if (!opts->dry_run) {
        output_print(out, OUTPUT_VERBOSE, "\nChecking privilege requirements...\n");

        err = ensure_complete_apply_privileges(manifest, orphans, opts, out);
        if (err) {
            err = error_wrap(err, "Insufficient privileges for operation");
            goto cleanup;
        }
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

    /* Run cleanup preflight checks (unless --keep-orphans) */
    if (!opts->keep_orphans) {
        output_print(out, OUTPUT_VERBOSE, "\nChecking orphaned files...\n");

        cleanup_options_t cleanup_opts = {
            .enabled_metadata = merged_metadata,
            .enabled_profiles = profiles,
            .cache = cache,
            .orphaned_files = orphans,              /* Pass pre-computed file orphans */
            .orphaned_directories = dir_orphans,    /* Pass pre-computed directory orphans */
            .verbose = opts->verbose,
            .dry_run = false,  /* Preflight is always read-only */
            .force = opts->force,
            .skip_safety_check = false  /* Run safety check in preflight */
        };

        err = cleanup_preflight_check(repo, state, manifest, &cleanup_opts, &cleanup_preflight);
        if (err) {
            err = error_wrap(err, "Cleanup preflight checks failed");
            goto cleanup;
        }

        /* Display cleanup preflight results (will be added in Phase 5) */
        print_cleanup_preflight_results(out, cleanup_preflight, opts->verbose);

        /* Block if safety violations (unless --force) */
        if (cleanup_preflight->has_blocking_violations && !opts->force) {
            err = ERROR(ERR_CONFLICT,
                       "Cannot remove %zu orphaned file%s with uncommitted changes",
                       cleanup_preflight->safety_violations->count,
                       cleanup_preflight->safety_violations->count == 1 ? "" : "s");
            goto cleanup;
        }
    }

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
        char prompt[512];  /* Larger buffer for enhanced prompt */

        /* Build comprehensive prompt that includes cleanup information */
        if (cleanup_preflight && cleanup_preflight->will_prune_orphans) {
            /* Enhanced prompt: mentions both deployment and orphan removal */
            snprintf(prompt, sizeof(prompt),
                    "Deploy %zu file%s and remove %zu orphaned file%s?",
                    manifest->count, manifest->count == 1 ? "" : "s",
                    cleanup_preflight->orphaned_files_count,
                    cleanup_preflight->orphaned_files_count == 1 ? "" : "s");
        } else {
            /* Standard prompt: only deployment */
            snprintf(prompt, sizeof(prompt), "Deploy %zu file%s to filesystem?",
                    manifest->count, manifest->count == 1 ? "" : "s");
        }

        if (!output_confirm(out, prompt, false)) {
            output_info(out, "Cancelled");
            err = NULL;  /* Not an error - user cancelled */
            goto cleanup;
        }
    }

    /* Execute deployment */
    if (opts->dry_run) {
        output_print(out, OUTPUT_VERBOSE, "Dry-run mode - no files will be modified\n");
    } else {
        output_print(out, OUTPUT_VERBOSE, "Deploying files...\n");
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
                .cache = cache,                      /* Pass cache for performance (avoids re-decryption) */
                .orphaned_files = orphans,           /* Pass pre-computed file orphans */
                .orphaned_directories = dir_orphans, /* Pass pre-computed directory orphans */
                .verbose = opts->verbose,
                .dry_run = false,  /* Dry-run handled at deployment level */
                .force = opts->force,
                .skip_safety_check = (cleanup_preflight != NULL)  /* Skip if preflight already checked */
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
        err = apply_update_and_save_state(ws, state, merged_metadata, out);
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
    if (cleanup_preflight) cleanup_preflight_result_free(cleanup_preflight);
    if (preflight) preflight_result_free(preflight);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (profiles_str) free(profiles_str);
    if (cache) content_cache_free(cache);
    if (merged_metadata) metadata_free(merged_metadata);
    if (dir_orphans) orphan_directory_list_free(dir_orphans);
    if (orphans) orphan_list_free(orphans);
    if (ws) workspace_free(ws);
    if (profiles) profile_list_free(profiles);
    if (state) state_free(state);
    if (repo_dir) free(repo_dir);
    if (config) config_free(config);
    if (out) output_free(out);

    return err;
}
