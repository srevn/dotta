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
#include "utils/match.h"
#include "utils/output.h"
#include "utils/privilege.h"

/**
 * Print pre-flight results
 */
static void print_preflight_results(const output_ctx_t *out, const preflight_result_t *result) {
    if (!result) return;

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

        if (result->orphaned_files_skipped > 0) {
            output_warning(out, "Skipped %zu orphaned file%s (uncommitted changes)",
                          result->orphaned_files_skipped,
                          result->orphaned_files_skipped == 1 ? "" : "s");
            output_print(out, OUTPUT_NORMAL, "Use --verbose to see which files were skipped.\n");
            output_print(out, OUTPUT_NORMAL, "To remove: commit/stash changes, or use --force.\n");
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
 * Check privileges for complete apply operation
 *
 * Examines manifest (files being deployed), file orphans (files being removed),
 * AND directory orphans (directories being removed) for root/ paths. This ensures
 * we have required privileges BEFORE attempting any filesystem modifications.
 *
 * @param manifest Files being deployed (must not be NULL)
 * @param file_orphans Files being removed (can be NULL if --keep-orphans)
 * @param file_orphan_count Number of file orphans
 * @param dir_orphans Directories being removed (can be NULL if --keep-orphans)
 * @param dir_orphan_count Number of directory orphans
 * @param opts Apply command options (must not be NULL)
 * @param out Output context for messages (must not be NULL)
 * @return NULL if OK to proceed, error otherwise (or does not return if re-exec with sudo)
 */
static error_t *ensure_complete_apply_privileges(
    const manifest_t *manifest,
    const workspace_item_t **file_orphans,
    size_t file_orphan_count,
    const workspace_item_t **dir_orphans,
    size_t dir_orphan_count,
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

    /* 2. Collect root/ paths from file orphans (files being removed) */
    if (file_orphans && file_orphan_count > 0) {
        for (size_t i = 0; i < file_orphan_count; i++) {
            /* workspace_item_t has storage_path field */
            if (privilege_path_requires_root(file_orphans[i]->storage_path)) {
                error_t *err = string_array_push(root_paths, file_orphans[i]->storage_path);
                if (err) {
                    string_array_free(root_paths);
                    return error_wrap(err, "Failed to add file orphan root path");
                }
            }
        }
    }

    /* 3. Collect root/ paths from directory orphans (directories being removed) */
    if (dir_orphans && dir_orphan_count > 0) {
        for (size_t i = 0; i < dir_orphan_count; i++) {
            /* workspace_item_t has storage_path field */
            if (privilege_path_requires_root(dir_orphans[i]->storage_path)) {
                error_t *err = string_array_push(root_paths, dir_orphans[i]->storage_path);
                if (err) {
                    string_array_free(root_paths);
                    return error_wrap(err, "Failed to add directory orphan root path");
                }
            }
        }
    }

    /* 4. Check privileges if any root/ paths found */
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
 * Check if filesystem path should be excluded by CLI patterns
 *
 * Helper function for manifest filtering during convergence analysis
 * and orphan removal. Uses gitignore-style pattern matching.
 *
 * @param path Filesystem path (VWD format: "home/.bashrc", "root/etc/hosts")
 * @param opts Command options containing exclusion patterns
 * @return true if path matches any exclusion pattern, false otherwise
 */
static bool matches_exclude_pattern(
    const char *path,
    const cmd_apply_options_t *opts
) {
    if (!path || !opts->exclude_patterns || opts->exclude_count == 0) {
        return false;
    }

    /* Use match module for gitignore-style pattern matching
     *
     * MATCH_DOUBLESTAR enables doublestar recursive wildcards:
     *   home/.config/doublestar         → matches all descendants
     *   *.conf                          → matches any .conf file
     *   home/.*                         → matches dotfiles in home/
     */
    return match_any(
        opts->exclude_patterns,
        opts->exclude_count,
        path,
        MATCH_DOUBLESTAR  /* Enable doublestar support */
    );
}

/**
 * Check if file needs deployment
 *
 * Determines whether a file requires deployment based on workspace analysis.
 * Uses two-dimensional model: state (existence) + divergence (quality).
 *
 * Architecture:
 * - State dimension (primary): Where does the file exist? (Git/DB/filesystem)
 * - Divergence dimension (secondary): For files on filesystem, what's wrong?
 *
 * @param ws_item Workspace item from divergence analysis (can be NULL)
 * @return true if file needs deployment, false if clean
 */
static bool needs_deployment(const workspace_item_t *ws_item) {
    if (ws_item == NULL) {
        /* Not in workspace divergence index → file is clean */
        return false;
    }

    /* Decision tree: state (existence) determines baseline, then check divergence (quality) */
    switch (ws_item->state) {
        case WORKSPACE_STATE_UNDEPLOYED:
            /* File exists in Git but has never been deployed to filesystem.
             * Needs initial deployment.
             *
             * Note: divergence is always NONE for missing files (can't compare
             * properties of non-existent files). */
            return true;

        case WORKSPACE_STATE_DELETED:
            /* File exists in Git and was previously deployed (deployed_at > 0),
             * but has been removed from filesystem. Needs restoration.
             *
             * Note: divergence is always NONE for missing files. */
            return true;

        case WORKSPACE_STATE_DEPLOYED:
            /* File exists on filesystem and is tracked in Git.
             * Needs deployment only if properties diverged (content, mode, ownership, etc.).
             *
             * If divergence == NONE: file is clean, matches Git perfectly.
             * If divergence != NONE: file has property mismatches, needs redeployment. */
            return (ws_item->divergence != DIVERGENCE_NONE);

        case WORKSPACE_STATE_ORPHANED:
            /* File exists in deployment state but not in any enabled profile.
             *
             * Architectural invariant: Orphaned files should NOT appear in the manifest
             * (manifest only contains files from enabled profiles). If we reach here,
             * it's a programming error in workspace or manifest building.
             *
             * Defensive: Return false (don't deploy orphans, cleanup handles removal). */
            return false;

        case WORKSPACE_STATE_UNTRACKED:
            /* File exists on filesystem in a tracked directory but not in Git.
             *
             * Architectural invariant: Untracked files should NOT appear in the manifest
             * (manifest is built from Git, not filesystem). If we reach here, it's a
             * programming error.
             *
             * Defensive: Return false (don't deploy untracked files, user must 'add' them). */
            return false;
    }

    /* Unreachable if all enum values handled.
     * Defensive fallback for unknown states (forward compatibility). */
    return false;
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
    profile_list_t *workspace_profiles = NULL;
    profile_list_t *operation_profiles = NULL;
    const manifest_t *manifest = NULL;
    manifest_t *deploy_manifest = NULL;
    workspace_t *ws = NULL;
    const workspace_item_t **file_orphans = NULL;
    size_t file_orphan_count = 0;
    const workspace_item_t **dir_orphans = NULL;
    size_t dir_orphan_count = 0;
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

    /* Load profiles
     *
     * Separate workspace scope (persistent) from operation filter (temporary).
     *   - workspace_profiles: ALWAYS persistent enabled profiles (for VWD scope)
     *   - operation_profiles: CLI filter or shared pointer (for filtering operations)
     *
     * This ensures accurate orphan detection while supporting CLI filtering.
     */
    output_print(out, OUTPUT_VERBOSE, "Loading profiles...\n");

    /* Phase 1: Load workspace profiles (ALWAYS persistent, ignore CLI overrides) */
    err = profile_resolve_for_workspace(repo, config->strict_mode, &workspace_profiles);
    if (err) {
        err = error_wrap(err, "Failed to resolve enabled profiles");
        goto cleanup;
    }

    if (workspace_profiles->count == 0) {
        err = ERROR(ERR_NOT_FOUND,
                   "No enabled profiles found\n"
                   "Hint: Run 'dotta profile enable <name>' to enable profiles");
        goto cleanup;
    }

    /* Phase 2: Load operation profiles */
    if (opts->profiles && opts->profile_count > 0) {
        /* User specified CLI filter - load filter profiles */
        err = profile_resolve_for_operations(repo, opts->profiles, opts->profile_count,
                                            config->strict_mode, &operation_profiles);
        if (err) {
            err = error_wrap(err, "Failed to resolve operation profiles");
            goto cleanup;
        }

        /* Validate: filter profiles must be enabled in workspace */
        err = profile_validate_filter(workspace_profiles, operation_profiles);
        if (err) {
            goto cleanup;
        }
    } else {
        /* No CLI filter - share workspace profiles */
        operation_profiles = workspace_profiles;
    }

    if (opts->verbose) {
        output_print(out, OUTPUT_VERBOSE, "Using %zu profile%s:\n",
                    operation_profiles->count, operation_profiles->count == 1 ? "" : "s");
        for (size_t i = 0; i < operation_profiles->count; i++) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s•%s %s\n",
                       output_color_code(out, OUTPUT_COLOR_CYAN),
                       output_color_code(out, OUTPUT_COLOR_RESET),
                       operation_profiles->profiles[i].name);
            } else {
                output_printf(out, OUTPUT_NORMAL, "  • %s\n", operation_profiles->profiles[i].name);
            }
        }
    }

    /* Load workspace (includes manifest building and metadata loading)
     *
     * The workspace builds the manifest internally during initialization,
     * eliminating redundant manifest building. We extract the manifest
     * immediately after loading for use throughout the command.
     *
     * Pass state handle to workspace so it analyzes within our write transaction.
     * This ensures consistency and eliminates redundant database connections.
     */
    output_print(out, OUTPUT_VERBOSE, "\nLoading workspace...\n");

    /* Apply needs file divergence + orphan detection for deployment and cleanup
     *
     * Use workspace_profiles (persistent) for VWD scope, NOT operation_profiles.
     * This ensures manifest scope matches state scope for accurate orphan detection.
     */
    workspace_load_t ws_opts = {
        .analyze_files = true,
        .analyze_orphans = true,
        .analyze_untracked = false,    /* Skip expensive directory scan */
        .analyze_directories = false,  /* Not needed for deployment */
        .analyze_encryption = false    /* Not needed for deployment */
    };
    err = workspace_load(repo, state, workspace_profiles, config, &ws_opts, &ws);
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

    /* CONVERGENCE MODEL: Analyze files for divergence and build deployment list
     *
     * Two-pass algorithm for exact memory allocation:
     *   Pass 1: Count divergent files (O(N) with O(1) divergence lookups)
     *   Pass 2: Allocate exact size and populate (O(D) where D = divergent count)
     *
     * Architecture:
     * - workspace_load() already computed fresh divergence for ALL files
     * - workspace_get_item() returns NULL for clean files (no divergence)
     * - workspace_get_item() returns workspace_item_t* for divergent files
     * - We deploy only files where divergence != DIVERGENCE_NONE
     */
    output_print(out, OUTPUT_VERBOSE, "\nAnalyzing files for convergence...\n");

    /* Pass 1: Count divergent and clean files (with filters) */
    size_t divergent_count = 0;
    size_t clean_count = 0;
    size_t excluded_deploy_count = 0;  /* Track deployment exclusions */
    size_t excluded_orphan_count = 0;  /* Track orphan exclusions */

    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];

        /* Filter by operation profiles (skip files not in filter) */
        if (entry->source_profile &&
            !profile_filter_matches(entry->source_profile->name, operation_profiles)) {
            continue;
        }

        /* Filter by exclusion pattern (skip excluded files) */
        if (matches_exclude_pattern(entry->filesystem_path, opts)) {
            excluded_deploy_count++;
            continue;
        }

        /* Query fresh divergence analysis (O(1) hashmap lookup) */
        const workspace_item_t *ws_item = workspace_get_item(ws, entry->filesystem_path);

        if (needs_deployment(ws_item)) {
            /* File needs deployment (missing or divergent from Git) */
            divergent_count++;
        } else {
            /* Clean file - matches Git perfectly */
            clean_count++;
        }
    }

    /* Allocate deployment manifest structure (always, for consistency) */
    deploy_manifest = calloc(1, sizeof(manifest_t));
    if (!deploy_manifest) {
        err = ERROR(ERR_MEMORY, "Failed to allocate deployment manifest");
        goto cleanup;
    }
    deploy_manifest->count = 0;

    /* Pass 2: Allocate entries array and populate (only if divergent files exist)
     *
     * If no divergent files, entries remains NULL. This saves memory when
     * workspace is clean (common case after initial apply).
     */
    if (divergent_count > 0) {
        deploy_manifest->entries = calloc(divergent_count, sizeof(file_entry_t));
        if (!deploy_manifest->entries) {
            free(deploy_manifest);
            deploy_manifest = NULL;
            err = ERROR(ERR_MEMORY, "Failed to allocate deployment entries");
            goto cleanup;
        }

        /* Populate with files that need deployment (with filters) */
        for (size_t i = 0; i < manifest->count; i++) {
            const file_entry_t *entry = &manifest->entries[i];

            /* Filter by operation profiles (skip files not in filter) */
            if (entry->source_profile &&
                !profile_filter_matches(entry->source_profile->name, operation_profiles)) {
                continue;
            }

            /* Filter by exclusion pattern (skip excluded files) */
            if (matches_exclude_pattern(entry->filesystem_path, opts)) {
                /* Already counted in Pass 1, just skip */
                if (opts->verbose) {
                    output_print(out, OUTPUT_VERBOSE,
                                "  Skipping (excluded): %s\n",
                                entry->filesystem_path);
                }
                continue;
            }

            /* Query fresh divergence analysis (O(1) hashmap lookup)
             *
             * workspace_get_item() returns:
             *   - NULL if file is clean (no divergence, not in index)
             *   - workspace_item_t* if file has state/divergence issues
             */
            const workspace_item_t *ws_item = workspace_get_item(ws, entry->filesystem_path);

            if (needs_deployment(ws_item)) {
                /* File needs deployment - either missing or has property divergence
                 *
                 * Missing files (state-based):
                 *   - UNDEPLOYED: File in Git, never deployed to filesystem
                 *   - DELETED: File in Git, was deployed, removed from filesystem
                 *
                 * Divergent files (property-based, bit flags can be combined):
                 *   - DIVERGENCE_CONTENT: File content differs from Git
                 *   - DIVERGENCE_MODE: Permissions changed
                 *   - DIVERGENCE_OWNERSHIP: Owner/group changed (root/ files)
                 *   - DIVERGENCE_TYPE: Type changed (file→symlink, etc.)
                 *   - DIVERGENCE_ENCRYPTION: Encryption policy violation
                 *
                 * Shallow copy: All pointers (tree entries, profile pointers) are
                 * borrowed from workspace manifest. Memory owned by workspace.
                 */
                deploy_manifest->entries[deploy_manifest->count++] = *entry;
            }
        }
    } else {
        /* No divergent files - entries array remains NULL (saves memory) */
        deploy_manifest->entries = NULL;
    }

    if (opts->verbose) {
        output_print(out, OUTPUT_VERBOSE,
                    "  %zu file%s need deployment (missing or divergent)\n",
                    deploy_manifest->count,
                    deploy_manifest->count == 1 ? "" : "s");
        output_print(out, OUTPUT_VERBOSE,
                    "  %zu file%s already up-to-date (skipped)\n",
                    clean_count,
                    clean_count == 1 ? "" : "s");
    }

    /* Extract orphans from workspace (unless --keep-orphans)
     *
     * Architecture: workspace_load() already detected ALL orphans (enabled + disabled
     * profiles) during analyze_orphaned_state(). We extract them here for cleanup.
     *
     * CRITICAL: Orphan removal is UNCONDITIONAL and does NOT respect operation filter.
     * - Operation filter applies to deployment (which files to deploy)
     * - Orphan removal is housekeeping (removing files outside VWD scope)
     * - The manifest layer already decided orphan status based on enabled profiles
     * - Apply must respect that authority regardless of CLI filter
     *
     * Why unconditional?
     * - Disabled profile orphans: User disabled profile → files must be removed
     * - Enabled profile orphans: File deleted from Git → filesystem must converge
     * - VWD invariant: manifest is authoritative source for scope decisions
     *
     * Extracted orphans are used for:
     * 1. Privilege checking (filter root/ paths)
     * 2. Preflight display (show user what will be removed)
     * 3. Actual removal (pass to cleanup_execute)
     *
     * This eliminates redundant orphan detection in cleanup module (performance gain).
     */
    if (!opts->keep_orphans) {
        output_print(out, OUTPUT_VERBOSE, "\nExtracting orphans from workspace...\n");

        /* Get ALL diverged items and extract orphans
         *
         * Orphan removal is UNCONDITIONAL (does not respect operation filter):
         * - Operation filter applies to deployment (which managed files to deploy)
         * - Orphan removal is housekeeping (removing files outside VWD scope)
         * - Manifest (VWD) already determined orphan status via enabled profiles
         * - Apply must respect that authority regardless of CLI filter
         *
         * Note: Files from enabled profiles cannot be orphans (they're in manifest).
         * Only files from disabled profiles or deleted from Git become orphans.
         */
        size_t all_diverged_count = 0;
        const workspace_item_t *all_diverged = workspace_get_all_diverged(ws, &all_diverged_count);

        /* First pass: count orphaned files vs directories (with exclusion filter) */
        for (size_t i = 0; i < all_diverged_count; i++) {
            const workspace_item_t *item = &all_diverged[i];

            if (item->state == WORKSPACE_STATE_ORPHANED) {
                /* Check exclusion pattern before counting */
                if (matches_exclude_pattern(item->filesystem_path, opts)) {
                    excluded_orphan_count++;
                    if (opts->verbose) {
                        output_print(out, OUTPUT_VERBOSE,
                                    "  Preserving orphan (excluded): %s\n",
                                    item->filesystem_path);
                    }
                    continue;
                }

                /* Count non-excluded orphans */
                if (item->item_kind == WORKSPACE_ITEM_FILE) {
                    file_orphan_count++;
                } else {
                    dir_orphan_count++;
                }
            }
        }

        /* Allocate separate arrays for files and directories */
        if (file_orphan_count > 0) {
            file_orphans = malloc(file_orphan_count * sizeof(workspace_item_t *));
            if (!file_orphans) {
                err = ERROR(ERR_MEMORY, "Failed to allocate file orphan array");
                goto cleanup;
            }

            /* Second pass: populate file orphans array (with exclusion filter) */
            size_t f_idx = 0;
            for (size_t i = 0; i < all_diverged_count; i++) {
                const workspace_item_t *item = &all_diverged[i];

                if (item->state == WORKSPACE_STATE_ORPHANED &&
                    item->item_kind == WORKSPACE_ITEM_FILE) {
                    /* Apply same exclusion filter as Pass 1 */
                    if (matches_exclude_pattern(item->filesystem_path, opts)) {
                        continue;  /* Skip excluded orphans (preserve) */
                    }

                    file_orphans[f_idx++] = item;
                }
            }
        }

        if (dir_orphan_count > 0) {
            dir_orphans = malloc(dir_orphan_count * sizeof(workspace_item_t *));
            if (!dir_orphans) {
                free(file_orphans);
                file_orphans = NULL;
                err = ERROR(ERR_MEMORY, "Failed to allocate directory orphan array");
                goto cleanup;
            }

            /* Second pass: populate directory orphans array (with exclusion filter) */
            size_t d_idx = 0;
            for (size_t i = 0; i < all_diverged_count; i++) {
                const workspace_item_t *item = &all_diverged[i];

                if (item->state == WORKSPACE_STATE_ORPHANED &&
                    item->item_kind == WORKSPACE_ITEM_DIRECTORY) {
                    /* Apply same exclusion filter as Pass 1 */
                    if (matches_exclude_pattern(item->filesystem_path, opts)) {
                        continue;  /* Skip excluded orphans (preserve) */
                    }

                    dir_orphans[d_idx++] = item;
                }
            }
        }

        if (opts->verbose) {
            if (file_orphan_count > 0) {
                output_print(out, OUTPUT_VERBOSE,
                            "Found %zu orphaned file%s\n",
                            file_orphan_count,
                            file_orphan_count == 1 ? "" : "s");
            }
            if (dir_orphan_count > 0) {
                output_print(out, OUTPUT_VERBOSE,
                            "Found %zu orphaned director%s\n",
                            dir_orphan_count,
                            dir_orphan_count == 1 ? "y" : "ies");
            }

            /* Show breakdown by profile status */
            if (file_orphan_count > 0 || dir_orphan_count > 0) {
                size_t disabled_count = 0;
                size_t enabled_count = 0;

                /* Count using already-extracted orphan arrays */
                for (size_t i = 0; i < file_orphan_count; i++) {
                    if (file_orphans[i]->profile_enabled) {
                        enabled_count++;
                    } else {
                        disabled_count++;
                    }
                }
                for (size_t i = 0; i < dir_orphan_count; i++) {
                    if (dir_orphans[i]->profile_enabled) {
                        enabled_count++;
                    } else {
                        disabled_count++;
                    }
                }

                if (disabled_count > 0) {
                    output_print(out, OUTPUT_VERBOSE,
                                "  %zu from disabled profile%s\n",
                                disabled_count,
                                disabled_count == 1 ? "" : "s");
                }
                if (enabled_count > 0) {
                    output_print(out, OUTPUT_VERBOSE,
                                "  %zu from enabled profiles (deleted from Git)\n",
                                enabled_count);
                }
            }
        }
    }

    /* Check if there's anything to do */
    if (deploy_manifest->count == 0 &&
        (opts->keep_orphans || (file_orphan_count == 0 && dir_orphan_count == 0))) {
        /* No divergent files and (keeping orphans OR no orphans to clean) */
        output_info(out, "Nothing to deploy (workspace is clean)");
        err = NULL;
        goto cleanup;
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

    /* Check privileges for root/ files AND directories BEFORE deployment begins
     *
     * This ensures we have required privileges upfront, preventing partial
     * deployments and cryptic mid-operation failures. Checks occur AFTER
     * manifest building AND orphan identification (know all files/dirs) but BEFORE
     * any filesystem modifications.
     *
     * Skip check if dry-run (read-only operation, no privileges needed).
     *
     * If re-exec with sudo occurs, the entire process restarts from main(),
     * and state lock is safely released before execvp() replaces the process.
     */
    if (!opts->dry_run) {
        output_print(out, OUTPUT_VERBOSE, "\nChecking privilege requirements...\n");

        err = ensure_complete_apply_privileges(
            deploy_manifest,
            file_orphans,
            file_orphan_count,
            dir_orphans,
            dir_orphan_count,
            opts,
            out
        );
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

    /* Run pre-flight checks (using workspace divergence analysis)
     *
     * Workspace already compared all files during workspace_load(), so preflight
     * just queries the results via O(1) hashmap lookups.
     */
    output_print(out, OUTPUT_VERBOSE, "\nRunning pre-flight checks...\n");

    deploy_options_t deploy_opts = {
        .force = opts->force,
        .dry_run = opts->dry_run,
        .verbose = opts->verbose,
        .skip_existing = opts->skip_existing,
        .skip_unchanged = opts->skip_unchanged,
        .strict_ownership = config->strict_mode
    };

    err = deploy_preflight_check_from_workspace(ws, deploy_manifest, &deploy_opts, &preflight);
    if (err) {
        err = error_wrap(err, "Pre-flight checks failed");
        goto cleanup;
    }

    print_preflight_results(out, preflight);

    /* Check for errors (conflicts, permissions) */
    if (preflight->has_errors) {
        err = ERROR(ERR_CONFLICT, "Pre-flight checks failed");
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
            .enabled_profiles = operation_profiles,   /* Use filtered profiles for preflight */
            .cache = cache,
            .orphaned_files = file_orphans,           /* Workspace item array */
            .orphaned_files_count = file_orphan_count,
            .orphaned_directories = dir_orphans,      /* Workspace item array */
            .orphaned_directories_count = dir_orphan_count,
            .preflight_violations = NULL,             /* No preflight violations yet */
            .verbose = opts->verbose,
            .dry_run = false,                         /* Preflight is always read-only */
            .force = opts->force,
            .skip_safety_check = false                /* Run safety check in preflight */
        };

        err = cleanup_preflight_check(repo, state, manifest, &cleanup_opts, &cleanup_preflight);
        if (err) {
            err = error_wrap(err, "Cleanup preflight checks failed");
            goto cleanup;
        }

        /* Display cleanup preflight results */
        print_cleanup_preflight_results(out, cleanup_preflight, opts->verbose);

        /* Warn about safety violations but allow partial cleanup
         *
         * Changed from blocking abort to warning + continue. This enables granular
         * cleanup where safe files are removed and unsafe files are skipped.
         *
         * The cleanup_execute function will use preflight_violations to build a
         * skip list, ensuring files with uncommitted changes are preserved.
         *
         * User benefits:
         * - Partial cleanup better than no cleanup
         * - Clear feedback about what was removed vs skipped
         * - Instructions on how to resolve remaining orphans
         */
        if (cleanup_preflight->has_blocking_violations && !opts->force) {
            output_print(out, OUTPUT_NORMAL, "\n");

            output_warning(out, "%zu orphaned file%s %s uncommitted changes.",
                          cleanup_preflight->safety_violations->count,
                          cleanup_preflight->safety_violations->count == 1 ? "" : "s",
                          cleanup_preflight->safety_violations->count == 1 ? "has" : "have");

            output_print(out, OUTPUT_NORMAL,
                        "These files will be skipped during cleanup to prevent data loss.\n");
            output_print(out, OUTPUT_NORMAL,
                        "To remove them: commit/stash changes first, or use --force.\n\n");

            /* Continue with operation - cleanup_execute will skip unsafe files */
        }
    }

    /* Execute pre-apply hook */
    if (config && repo_dir) {
        /* Join all profile names into a space-separated string */
        size_t total_len = 0;
        for (size_t i = 0; i < operation_profiles->count; i++) {
            total_len += strlen(operation_profiles->profiles[i].name);
            if (i < operation_profiles->count - 1) {
                total_len++; /* For space separator */
            }
        }

        profiles_str = malloc(total_len + 1);
        if (!profiles_str) {
            err = ERROR(ERR_MEMORY, "Failed to allocate profile names string");
            goto cleanup;
        }

        char *p = profiles_str;
        for (size_t i = 0; i < operation_profiles->count; i++) {
            const char *name = operation_profiles->profiles[i].name;
            strcpy(p, name);
            p += strlen(name);
            if (i < operation_profiles->count - 1) {
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
                    deploy_manifest->count, deploy_manifest->count == 1 ? "" : "s",
                    cleanup_preflight->orphaned_files_count,
                    cleanup_preflight->orphaned_files_count == 1 ? "" : "s");
        } else {
            /* Standard prompt: only deployment */
            snprintf(prompt, sizeof(prompt), "Deploy %zu file%s to filesystem?",
                    deploy_manifest->count, deploy_manifest->count == 1 ? "" : "s");
        }

        if (!output_confirm(out, prompt, false)) {
            output_info(out, "Cancelled");
            err = NULL;  /* Not an error - user cancelled */
            goto cleanup;
        }
    }

    /* Execute deployment (only if there are divergent files) */
    if (deploy_manifest->count > 0) {
        if (opts->dry_run) {
            output_print(out, OUTPUT_VERBOSE, "\nDry-run mode - no files will be modified\n");
        } else {
            output_print(out, OUTPUT_VERBOSE, "\nDeploying %zu divergent file%s...\n",
                        deploy_manifest->count,
                        deploy_manifest->count == 1 ? "" : "s");
        }

        err = deploy_execute(repo, ws, deploy_manifest, state, &deploy_opts, cache, &deploy_res);
        if (err) {
            if (deploy_res) {
                print_deploy_results(out, deploy_res, opts->verbose);
            }
            /* Free deploy_manifest before error exit */
            free(deploy_manifest->entries);
            free(deploy_manifest);
            deploy_manifest = NULL;
            err = error_wrap(err, "Deployment failed");
            goto cleanup;
        }

        print_deploy_results(out, deploy_res, opts->verbose);

        /* Report exclusion statistics */
        size_t total_excluded = excluded_deploy_count + excluded_orphan_count;
        if (total_excluded > 0) {
            if (opts->verbose) {
                /* Detailed breakdown */
                output_printf(out, OUTPUT_NORMAL,
                             "Skipped %zu file%s (--exclude patterns):\n",
                             total_excluded,
                             total_excluded == 1 ? "" : "s");
                if (excluded_deploy_count > 0) {
                    output_printf(out, OUTPUT_NORMAL,
                                 "  • %zu divergent file%s not deployed\n",
                                 excluded_deploy_count,
                                 excluded_deploy_count == 1 ? "" : "s");
                }
                if (excluded_orphan_count > 0) {
                    output_printf(out, OUTPUT_NORMAL,
                                 "  • %zu orphaned file%s not removed\n",
                                 excluded_orphan_count,
                                 excluded_orphan_count == 1 ? "" : "s");
                }
            } else {
                /* Simple summary */
                if (output_colors_enabled(out)) {
                    output_printf(out, OUTPUT_NORMAL,
                                 "Skipped %s%zu%s file%s (--exclude patterns)\n",
                                 output_color_code(out, OUTPUT_COLOR_CYAN),
                                 total_excluded,
                                 output_color_code(out, OUTPUT_COLOR_RESET),
                                 total_excluded == 1 ? "" : "s");
                } else {
                    output_printf(out, OUTPUT_NORMAL,
                                 "Skipped %zu file%s (--exclude patterns)\n",
                                 total_excluded,
                                 total_excluded == 1 ? "" : "s");
                }
            }
        }

        /* Free deploy_manifest after successful deployment */
        free(deploy_manifest->entries);
        free(deploy_manifest);
        deploy_manifest = NULL;

    } else {
        /* No divergent files - workspace is clean */
        output_print(out, OUTPUT_VERBOSE, "\nNo files need deployment (workspace is clean)\n");

        /* Create empty deploy result for consistency */
        deploy_res = calloc(1, sizeof(deploy_result_t));
        if (!deploy_res) {
            err = ERROR(ERR_MEMORY, "Failed to allocate deploy result");
            goto cleanup;
        }
        deploy_res->deployed_count = 0;
        deploy_res->skipped_count = 0;
    }

    /* Save state (only if not dry-run) */
    if (!opts->dry_run) {
        /* Prune orphaned files and remove from state (unless --keep-orphans)
         *
         * Architecture:
         * 1. cleanup_execute() removes orphaned files from filesystem
         * 2. For each successfully removed file, state_remove_file() deletes entry from state
         * 3. State updates are surgical (DELETE operations), not full rebuilds
         *
         * This separation ensures:
         * - Clear responsibility: filesystem ops separate from state tracking
         * - Transactional safety: filesystem changes committed before state changes
         * - Incremental updates: only modified entries updated in state
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
                .enabled_profiles = operation_profiles,   /* Use filtered profiles for cleanup */
                .cache = cache,                           /* Pass cache for performance */
                .orphaned_files = file_orphans,           /* Workspace item array */
                .orphaned_files_count = file_orphan_count,
                .orphaned_directories = dir_orphans,      /* Workspace item array */
                .orphaned_directories_count = dir_orphan_count,
                .preflight_violations = cleanup_preflight ? cleanup_preflight->safety_violations : NULL,
                .verbose = opts->verbose,
                .dry_run = false,                         /* Dry-run handled at deployment level */
                .force = opts->force,
                .skip_safety_check = true                 /* Trust preflight data */
            };

            /* Execute cleanup (non-fatal - deployment already succeeded)
             *
             * Rationale:
             * - Deployment already succeeded (files physically on filesystem)
             * - Deployment state is orthogonal to cleanup state (independent concerns)
             * - Partial success is valuable (preserve what worked, retry what failed)
             * - Next 'dotta apply' will retry cleanup naturally (idempotent convergence)
             *
             * Error scenarios handled gracefully:
             * - Permission denied on orphan removal → warn user, continue
             * - Filesystem errors during cleanup → warn user, continue
             * - Safety violations (uncommitted changes) → already warned in preflight
             * - Partial cleanup (some succeed, some fail) → record successful removals
             *
             * State consistency guarantee:
             * - Deployment state ALWAYS saved (deployment succeeded)
             * - Cleanup state conditionally saved (only successful removals recorded)
             * - Database remains consistent (VWD matches successful filesystem operations)
             */
            error_t *cleanup_err = cleanup_execute(repo, state, manifest, &cleanup_opts, &cleanup_res);
            if (cleanup_err) {
                /* Cleanup failed - warn but continue to save deployment state
                 *
                 * The deployment succeeded, so we MUST save deployment state regardless
                 * of cleanup failure. Otherwise we create state desynchronization where:
                 * - Filesystem has correct deployed files
                 * - Database shows files as undeployed (deployed_at = 0)
                 * - User sees confusing [undeployed] status on working files
                 */
                output_warning(out, "Deployment successful, but orphan cleanup failed: %s",
                               error_message(cleanup_err));

                /* Display partial results if available (cleanup_res may be partial or NULL) */
                if (cleanup_res) {
                    print_cleanup_results(out, cleanup_res, opts->verbose);
                }

                error_free(cleanup_err);
                /* Continue to save deployment state (critical for consistency) */
            } else {
                /* Cleanup succeeded - display results */
                if (cleanup_res) {
                    print_cleanup_results(out, cleanup_res, opts->verbose);
                }
            }

            /* CRITICAL: Remove orphaned entries from state database
             *
             * This completes the orphan cleanup process. Without this step,
             * orphaned entries accumulate forever in virtual_manifest.
             *
             * The flow for orphaned files:
             *   1. Profile disabled → entry stays in state (manifest_disable_profile)
             *   2. Workspace detects orphan → entry in state, profile not enabled
             *   3. cleanup_execute() → file removed from filesystem (just happened)
             *   4. THIS CODE → entry removed from state (completing the cycle)
             *
             * DEFENSIVE: Only process if cleanup succeeded and returned results.
             * - If cleanup_err occurred above, cleanup_res may be NULL or incomplete
             * - Only record state updates for successfully removed files (partial success)
             * - If cleanup failed completely, this section is safely skipped
             * - Next 'apply' will retry full cleanup with fresh workspace analysis
             */
            if (cleanup_res && cleanup_res->removed_files &&
                string_array_size(cleanup_res->removed_files) > 0) {

                output_print(out, OUTPUT_VERBOSE, "\nRemoving orphaned entries from state...\n");

                for (size_t i = 0; i < string_array_size(cleanup_res->removed_files); i++) {
                    const char *path = string_array_get(cleanup_res->removed_files, i);

                    /* Delete entry from virtual_manifest table
                     *
                     * The file was already removed from filesystem by cleanup_execute().
                     * Now we remove the database record to complete the cleanup.
                     */
                    err = state_remove_file(state, path);
                    if (err) {
                        /* Non-fatal - file already removed from filesystem
                         *
                         * The important operation (filesystem removal) already succeeded.
                         * State cleanup failure is a warning, not a fatal error.
                         */
                        output_warning(out, "Failed to remove state entry for %s: %s",
                                      path, error_message(err));
                        error_free(err);
                        err = NULL;  /* Don't propagate - continue operation */
                    }
                }

                output_print(out, OUTPUT_VERBOSE,
                            "  Removed %zu orphaned entr%s from state\n",
                            string_array_size(cleanup_res->removed_files),
                            string_array_size(cleanup_res->removed_files) == 1 ? "y" : "ies");
            }

            /* Remove orphaned directory entries from state
             *
             * After cleanup_execute() removes directories from filesystem,
             * we need to remove their entries from state to prevent accumulation.
             *
             * The flow for orphaned directories:
             *   1. Profile disabled → entry stays in state (manifest_disable_profile)
             *   2. Workspace detects orphan → entry in state, profile not enabled
             *   3. cleanup_execute() → directory removed from filesystem (just happened)
             *   4. THIS CODE → entry removed from state (completing the cycle)
             *
             * This mirrors file orphan cleanup (lines 1664-1712) and prevents
             * orphaned entries from accumulating forever in tracked_directories.
             *
             * DEFENSIVE: Only process if cleanup succeeded and returned results.
             * - If cleanup_err occurred above, cleanup_res may be NULL or incomplete
             * - Only record state updates for successfully removed directories (partial success)
             * - If cleanup failed completely, this section is safely skipped
             * - Next 'apply' will retry full cleanup with fresh workspace analysis
             */
            if (cleanup_res && cleanup_res->removed_dirs &&
                string_array_size(cleanup_res->removed_dirs) > 0) {

                output_print(out, OUTPUT_VERBOSE, "\nRemoving orphaned directory entries from state...\n");

                for (size_t i = 0; i < string_array_size(cleanup_res->removed_dirs); i++) {
                    const char *path = string_array_get(cleanup_res->removed_dirs, i);

                    /* Delete entry from tracked_directories table
                     *
                     * The directory was already removed from filesystem by cleanup_execute().
                     * Now we remove the database record to complete the cleanup.
                     */
                    err = state_remove_directory(state, path);
                    if (err) {
                        /* Non-fatal - directory already removed from filesystem
                         *
                         * The important operation (filesystem removal) already succeeded.
                         * State cleanup failure is a warning, not a fatal error.
                         */
                        output_warning(out, "Failed to remove directory state entry for %s: %s",
                                      path, error_message(err));
                        error_free(err);
                        err = NULL;  /* Don't propagate - continue operation */
                    }
                }

                output_print(out, OUTPUT_VERBOSE,
                            "  Removed %zu orphaned directory entr%s from state\n",
                            string_array_size(cleanup_res->removed_dirs),
                            string_array_size(cleanup_res->removed_dirs) == 1 ? "y" : "ies");
            }

            cleanup_result_free(cleanup_res);
        }

        /* Update deployed_at timestamp for successfully deployed files
         *
         * CRITICAL: This marks files as "known to dotta" and records deployment time.
         * The deployed_at field is used for lifecycle tracking (see state.h:85):
         *   - 0 = file never deployed by dotta
         *   - > 0 = file known to dotta (deployed or pre-existing)
         *
         * IMPORTANT: This operation runs REGARDLESS of cleanup success/failure.
         * - Deployment succeeded (files are physically on filesystem)
         * - State must reflect deployment success
         * - Cleanup failure does NOT invalidate deployment success
         * - This prevents state desynchronization (deployed files marked as undeployed)
         *
         * Non-critical operation: deployment already succeeded physically, so
         * timestamp update failures are non-fatal warnings (preserve consistency).
         */
        if (deploy_res && deploy_res->deployed && string_array_size(deploy_res->deployed) > 0) {
            time_t now = time(NULL);

            output_print(out, OUTPUT_VERBOSE, "\nUpdating deployment timestamps...\n");

            for (size_t i = 0; i < string_array_size(deploy_res->deployed); i++) {
                const char *path = string_array_get(deploy_res->deployed, i);

                /* Update deployed_at to mark file as deployed */
                err = state_update_deployed_at(state, path, now);
                if (err) {
                    /* Non-fatal warning - deployment succeeded, just timestamp update failed
                     *
                     * The file is already on the filesystem with correct content.
                     * The timestamp is metadata for display and lifecycle tracking.
                     * Failure here should not abort the entire operation.
                     */
                    output_warning(out, "Failed to update timestamp for %s: %s",
                                  path, error_message(err));
                    error_free(err);
                    err = NULL;  /* Don't propagate - continue operation */
                }

                /* Clear old_profile if ownership changed (acknowledge change after deployment) */
                const workspace_item_t *ws_item = workspace_get_item(ws, path);
                if (ws_item && ws_item->profile_changed) {
                    error_t *clear_err = state_clear_old_profile(state, path);
                    if (clear_err) {
                        /* Non-fatal warning - deployment succeeded, just clearing flag failed */
                        output_warning(out, "Failed to clear ownership change flag for %s: %s",
                                      path, error_message(clear_err));
                        error_free(clear_err);
                    }
                }
            }

            output_print(out, OUTPUT_VERBOSE, "  Updated %zu timestamp%s\n",
                        string_array_size(deploy_res->deployed),
                        string_array_size(deploy_res->deployed) == 1 ? "" : "s");
        }

        /* Update deployed_at for adopted files (skipped but need acknowledgment)
         *
         * Adopted files are those that:
         * - Exist in VWD with deployed_at = 0 (never tracked by dotta)
         * - Exist on filesystem with correct content (CLEAN, no divergence)
         * - Were skipped by deploy (no physical changes needed)
         * - Need state update to record dotta's acknowledgment
         *
         * This completes the adoption flow started in deploy.c where files
         * with deployed_at = 0 are skipped with reason "adopted".
         */
        if (deploy_res && deploy_res->skipped && deploy_res->skipped_reasons) {
            /* Defensive: Validate parallel arrays are consistent */
            size_t skipped_size = string_array_size(deploy_res->skipped);
            size_t reasons_size = string_array_size(deploy_res->skipped_reasons);

            if (skipped_size != reasons_size) {
                /* Programming error - these arrays should always be parallel
                 *
                 * This indicates a bug in deploy.c where skipped and skipped_reasons
                 * arrays weren't kept in sync. Log warning and use minimum size to
                 * prevent crashes, but this should never happen in correct code.
                 */
                output_warning(out,
                    "Internal error: skipped arrays size mismatch (%zu != %zu). "
                    "This indicates a bug in deployment logic.",
                    skipped_size, reasons_size);

                /* Use minimum size to avoid out-of-bounds access */
                skipped_size = (skipped_size < reasons_size) ? skipped_size : reasons_size;
            }

            if (skipped_size > 0) {
                time_t now = time(NULL);
                size_t adopted_count = 0;

                /* Process each skipped file, updating state only for "adopted" reason */
                for (size_t i = 0; i < skipped_size; i++) {
                    const char *path = string_array_get(deploy_res->skipped, i);
                    const char *reason = string_array_get(deploy_res->skipped_reasons, i);

                    /* Filter: Only process "adopted" files (skip "unchanged" and "exists") */
                    if (strcmp(reason, "adopted") == 0) {
                        /* Adoption case - update deployed_at to acknowledge file
                         *
                         * The file is already correct on the filesystem (that's why
                         * it was skipped). We just need to update the database to
                         * record that dotta now knows about this file.
                         */
                        err = state_update_deployed_at(state, path, now);
                        if (err) {
                            /* Non-fatal warning - file is already correct on filesystem
                             *
                             * The important operation (verifying file is correct) already
                             * succeeded. The timestamp is metadata for lifecycle tracking.
                             * Failure here should not abort the entire operation.
                             */
                            output_warning(out, "Failed to update timestamp for adopted file %s: %s",
                                          path, error_message(err));
                            error_free(err);
                            err = NULL;
                        } else {
                            adopted_count++;
                        }
                    }
                    /* Skip reasons "unchanged" and "exists" don't need state updates:
                     * - "unchanged": deployed_at already set (file previously tracked)
                     * - "exists": User explicitly skipped with --skip-existing (no adoption)
                     */
                }

                /* Report adoption statistics in verbose mode */
                if (adopted_count > 0) {
                    output_print(out, OUTPUT_VERBOSE,
                                "  Adopted %zu file%s (already correct on filesystem)\n",
                                adopted_count, adopted_count == 1 ? "" : "s");
                }
            }
        }

        /* Commit state transaction (saves both deployment and cleanup state)
         *
         * This atomically commits all state changes made during apply:
         * - Deployment state: deployed_at timestamps for newly deployed files
         * - Cleanup state: removed orphan entries (if cleanup succeeded)
         * - Ownership changes: cleared old_profile flags for transferred files
         *
         * If cleanup failed, only deployment state is saved (partial success model).
         * If cleanup succeeded, both deployment and cleanup state are saved (full success).
         *
         * This ensures state database stays synchronized with filesystem reality.
         */
        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to commit state changes");
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
    if (deploy_manifest) {
        /* Free deploy_manifest structure */
        free(deploy_manifest->entries);
        free(deploy_manifest);
    }
    if (cleanup_preflight) cleanup_preflight_result_free(cleanup_preflight);
    if (preflight) preflight_result_free(preflight);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (profiles_str) free(profiles_str);
    if (cache) content_cache_free(cache);
    if (merged_metadata) metadata_free(merged_metadata);
    if (dir_orphans) free(dir_orphans);
    if (file_orphans) free(file_orphans);
    if (ws) workspace_free(ws);
    if (operation_profiles && operation_profiles != workspace_profiles) {
        profile_list_free(operation_profiles);
    }
    if (workspace_profiles) profile_list_free(workspace_profiles);
    if (state) state_free(state);
    if (repo_dir) free(repo_dir);
    if (config) config_free(config);
    if (out) output_free(out);

    return err;
}
