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
#include "utils/hashmap.h"
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
 * Build manifest containing only PENDING_DEPLOYMENT files
 *
 * Filters the workspace manifest to include only files staged for deployment.
 * Uses single database query for optimal performance (O(P) + O(M) where
 * P = pending count, M = manifest size).
 *
 * Algorithm:
 *   1. Query all PENDING_DEPLOYMENT entries (single indexed DB query)
 *   2. Build hashmap for O(1) lookups
 *   3. Filter workspace manifest (shallow copy, preserves all metadata)
 *
 * The filtered manifest contains shallow copies of file_entry_t structures
 * from the workspace manifest, preserving all metadata (tree entries, profile
 * pointers, overlap tracking). Memory is owned by workspace, so filtered
 * manifest must be freed with simple structure cleanup only.
 *
 * @param ws Workspace (must not be NULL)
 * @param out Filtered manifest (must not be NULL, caller must free structure only)
 * @return Error or NULL on success
 */
static error_t *build_pending_manifest(
    const workspace_t *ws,
    manifest_t **out
) {
    CHECK_NULL(ws);
    CHECK_NULL(out);

    const manifest_t *full_manifest = workspace_get_manifest(ws);
    const state_t *state = workspace_get_state(ws);

    if (!full_manifest || !state) {
        return ERROR(ERR_INTERNAL, "Workspace missing manifest or state");
    }

    error_t *err = NULL;
    state_file_entry_t *pending_entries = NULL;
    size_t pending_count = 0;
    hashmap_t *pending_map = NULL;
    manifest_t *filtered = NULL;

    /* Query all PENDING_DEPLOYMENT entries (single indexed query - fast!) */
    err = state_get_entries_by_status(
        state,
        MANIFEST_STATUS_PENDING_DEPLOYMENT,
        &pending_entries,
        &pending_count
    );
    if (err) {
        return error_wrap(err, "Failed to query pending entries");
    }

    /* Allocate filtered manifest structure */
    filtered = malloc(sizeof(manifest_t));
    if (!filtered) {
        state_free_all_files(pending_entries, pending_count);
        return ERROR(ERR_MEMORY, "Failed to allocate filtered manifest");
    }

    filtered->entries = NULL;
    filtered->count = 0;

    /* Quick exit if no pending files */
    if (pending_count == 0) {
        state_free_all_files(pending_entries, pending_count);
        *out = filtered;
        return NULL;
    }

    /* Allocate entries array */
    filtered->entries = calloc(pending_count, sizeof(file_entry_t));
    if (!filtered->entries) {
        free(filtered);
        state_free_all_files(pending_entries, pending_count);
        return ERROR(ERR_MEMORY, "Failed to allocate filtered entries");
    }

    /* Build hashmap for O(1) pending lookups */
    pending_map = hashmap_create(0);  /* Default capacity */
    if (!pending_map) {
        free(filtered->entries);
        free(filtered);
        state_free_all_files(pending_entries, pending_count);
        return ERROR(ERR_MEMORY, "Failed to create pending hashmap");
    }

    for (size_t i = 0; i < pending_count; i++) {
        err = hashmap_set(pending_map, pending_entries[i].filesystem_path, (void*)1);
        if (err) {
            hashmap_free(pending_map, NULL);
            free(filtered->entries);
            free(filtered);
            state_free_all_files(pending_entries, pending_count);
            return error_wrap(err, "Failed to populate pending hashmap");
        }
    }

    /* Filter manifest: copy only pending entries (shallow copy - pointers borrowed) */
    for (size_t i = 0; i < full_manifest->count; i++) {
        const file_entry_t *entry = &full_manifest->entries[i];

        if (hashmap_has(pending_map, entry->filesystem_path)) {
            /* Shallow copy: all pointers borrowed from workspace manifest */
            filtered->entries[filtered->count++] = *entry;
        }
    }

    /* Cleanup temporary structures */
    hashmap_free(pending_map, NULL);
    state_free_all_files(pending_entries, pending_count);

    *out = filtered;
    return NULL;
}

/**
 * Free filtered manifest structure
 *
 * Only frees the manifest structure and entries array, not the borrowed
 * pointers inside (those are owned by workspace).
 *
 * @param manifest Filtered manifest (can be NULL)
 */
static void manifest_free_filtered(manifest_t *manifest) {
    if (!manifest) return;

    /* Don't free entry contents - they're borrowed from workspace */
    free(manifest->entries);
    free(manifest);
}

/**
 * Update manifest status after deployment
 *
 * Incrementally updates status for successfully deployed files instead of
 * rebuilding entire state. This preserves lifecycle tracking.
 *
 * Algorithm:
 *   1. For each successfully deployed file:
 *      - Transition status: PENDING_DEPLOYMENT → DEPLOYED
 *      - Update deployed_at timestamp
 *   2. Failed files remain PENDING_DEPLOYMENT (user can retry)
 *   3. Files with status=DEPLOYED remain unchanged (not deployed this run)
 *
 * All updates are batched in the active transaction for atomicity.
 *
 * @param state State with active transaction (must not be NULL)
 * @param deploy_result Deployment results (must not be NULL)
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *apply_update_deployment_status(
    state_t *state,
    const deploy_result_t *deploy_result,
    output_ctx_t *out
) {
    CHECK_NULL(state);
    CHECK_NULL(deploy_result);
    CHECK_NULL(out);

    error_t *err = NULL;
    time_t now = time(NULL);

    output_print(out, OUTPUT_VERBOSE, "\nUpdating manifest status...\n");

    /* Update status for successfully deployed files */
    if (deploy_result->deployed && deploy_result->deployed_count > 0) {
        for (size_t i = 0; i < string_array_size(deploy_result->deployed); i++) {
            const char *path = string_array_get(deploy_result->deployed, i);

            /* Transition: PENDING_DEPLOYMENT → DEPLOYED */
            err = state_update_entry_status(state, path, MANIFEST_STATUS_DEPLOYED);
            if (err) {
                return error_wrap(err, "Failed to update status for '%s'", path);
            }

            /* Update deployed_at timestamp */
            state_file_entry_t *entry = NULL;
            err = state_get_file(state, path, &entry);
            if (err) {
                return error_wrap(err, "Failed to get entry for '%s'", path);
            }

            entry->deployed_at = now;
            err = state_update_entry(state, entry);
            state_free_entry(entry);

            if (err) {
                return error_wrap(err, "Failed to update timestamp for '%s'", path);
            }
        }

        output_print(out, OUTPUT_VERBOSE,
                    "  Updated %zu file%s to DEPLOYED status\n",
                    deploy_result->deployed_count,
                    deploy_result->deployed_count == 1 ? "" : "s");
    }

    /* Update status for skipped files based on skip reason
     *
     * Files skipped with reason "unchanged" were verified by workspace to match
     * Git content (full comparison including decryption). These are semantically
     * deployed and should transition to DEPLOYED status.
     *
     * Files skipped with reason "exists" were NOT verified (--skip-existing flag),
     * so their status remains PENDING_DEPLOYMENT until actually deployed or verified.
     */
    if (deploy_result->skipped && deploy_result->skipped_count > 0) {
        /* Defensive check: ensure parallel arrays are synchronized */
        if (string_array_size(deploy_result->skipped) !=
            string_array_size(deploy_result->skipped_reasons)) {
            return ERROR(ERR_INTERNAL,
                        "Deploy result corruption: skipped arrays misaligned (%zu paths vs %zu reasons)",
                        string_array_size(deploy_result->skipped),
                        string_array_size(deploy_result->skipped_reasons));
        }

        size_t unchanged_count = 0;

        for (size_t i = 0; i < string_array_size(deploy_result->skipped); i++) {
            const char *path = string_array_get(deploy_result->skipped, i);
            const char *reason = string_array_get(deploy_result->skipped_reasons, i);

            if (strcmp(reason, "unchanged") == 0) {
                /* File is already on filesystem with correct content.
                 * Workspace verified content matches Git (full comparison including decryption).
                 * Transition: PENDING_DEPLOYMENT → DEPLOYED */
                err = state_update_entry_status(state, path, MANIFEST_STATUS_DEPLOYED);
                if (err) {
                    return error_wrap(err, "Failed to update status for '%s'", path);
                }

                /* Update deployed_at timestamp to reflect verification */
                state_file_entry_t *entry = NULL;
                err = state_get_file(state, path, &entry);
                if (err) {
                    return error_wrap(err, "Failed to get entry for '%s'", path);
                }

                entry->deployed_at = now;
                err = state_update_entry(state, entry);
                state_free_entry(entry);

                if (err) {
                    return error_wrap(err, "Failed to update timestamp for '%s'", path);
                }

                unchanged_count++;
            }
            /* Skip reason "exists": Leave as PENDING_DEPLOYMENT (not verified, status unknown) */
        }

        if (unchanged_count > 0) {
            output_print(out, OUTPUT_VERBOSE,
                        "  Updated %zu skipped file%s to DEPLOYED status (unchanged)\n",
                        unchanged_count,
                        unchanged_count == 1 ? "" : "s");
        }
    }

    /* Files in deploy_result->failed remain PENDING_DEPLOYMENT (retry later) */
    if (deploy_result->failed && string_array_size(deploy_result->failed) > 0) {
        size_t failed_count = string_array_size(deploy_result->failed);
        output_print(out, OUTPUT_VERBOSE,
                    "  %zu file%s remain PENDING_DEPLOYMENT (failed)\n",
                    failed_count,
                    failed_count == 1 ? "" : "s");
    }

    /* Files with status=DEPLOYED remain unchanged (not in pending_manifest) */

    return NULL;
}

/**
 * Remove PENDING_REMOVAL entries from manifest
 *
 * Called after cleanup_execute() removes files from filesystem.
 * Completes the VWD state machine: PENDING_REMOVAL → [deleted from manifest].
 *
 * This is the final step of the removal process:
 *   1. profile disable / remove marks files PENDING_REMOVAL
 *   2. cleanup_execute() removes from filesystem
 *   3. This function deletes entries from manifest table
 *
 * @param state State with active transaction (must not be NULL)
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *apply_cleanup_pending_removals(
    state_t *state,
    output_ctx_t *out
) {
    CHECK_NULL(state);
    CHECK_NULL(out);

    error_t *err = NULL;
    state_file_entry_t *removal_entries = NULL;
    size_t removal_count = 0;

    /* Get all PENDING_REMOVAL entries */
    err = state_get_entries_by_status(
        state,
        MANIFEST_STATUS_PENDING_REMOVAL,
        &removal_entries,
        &removal_count
    );
    if (err) {
        return error_wrap(err, "Failed to query PENDING_REMOVAL entries");
    }

    if (removal_count > 0) {
        output_print(out, OUTPUT_VERBOSE,
                    "\nRemoving %zu file%s from manifest...\n",
                    removal_count,
                    removal_count == 1 ? "" : "s");

        /* Delete each entry from manifest table */
        for (size_t i = 0; i < removal_count; i++) {
            err = state_remove_file(state, removal_entries[i].filesystem_path);
            if (err) {
                state_free_all_files(removal_entries, removal_count);
                return error_wrap(err,
                                "Failed to remove '%s' from manifest",
                                removal_entries[i].filesystem_path);
            }
        }

        output_print(out, OUTPUT_VERBOSE, "  Manifest cleanup complete\n");
    }

    state_free_all_files(removal_entries, removal_count);
    return NULL;
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
    manifest_t *pending_manifest = NULL;
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
     *
     * Pass state handle to workspace so it analyzes within our write transaction.
     * This ensures consistency and eliminates redundant database connections.
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
    err = workspace_load(repo, state, profiles, config, &ws_opts, &ws);
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

    /* Filter manifest to only PENDING_DEPLOYMENT files
     *
     * The workspace manifest contains all files (PENDING + DEPLOYED).
     * Apply should only deploy pending changes (VWD principle: respect staging).
     *
     * This filtering step transforms apply from "re-deploy everything" to
     * "deploy staged changes only", matching Git's commit behavior.
     */
    err = build_pending_manifest(ws, &pending_manifest);
    if (err) {
        err = error_wrap(err, "Failed to filter manifest for pending files");
        goto cleanup;
    }

    /* Report pending file count */
    if (opts->verbose) {
        if (pending_manifest->count == 0) {
            output_print(out, OUTPUT_VERBOSE, "  No files pending deployment\n");
        } else {
            output_print(out, OUTPUT_VERBOSE, "  %zu file%s pending deployment\n",
                        pending_manifest->count,
                        pending_manifest->count == 1 ? "" : "s");
        }
    }

    /* Extract orphans from workspace (unless --keep-orphans)
     *
     * Architecture: workspace_load() already detected ALL orphans (enabled + disabled
     * profiles) during analyze_orphaned_state(). We extract them here using
     * enabled_only=false to get complete picture for cleanup.
     *
     * Why enabled_only=false?
     * - When a profile is disabled, its files become orphans that MUST be cleaned up
     * - apply is responsible for removing files from disabled profiles
     * - status uses enabled_only=true to show only relevant divergence
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

        /* Get ALL diverged items and filter for orphans */
        size_t all_diverged_count = 0;
        const workspace_item_t *all_diverged = workspace_get_all_diverged(ws, &all_diverged_count);

        /* First pass: count orphaned files vs directories */
        for (size_t i = 0; i < all_diverged_count; i++) {
            if (all_diverged[i].state == WORKSPACE_STATE_ORPHANED) {
                if (all_diverged[i].item_kind == WORKSPACE_ITEM_FILE) {
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

            /* Second pass: populate file orphans array */
            size_t f_idx = 0;
            for (size_t i = 0; i < all_diverged_count; i++) {
                if (all_diverged[i].state == WORKSPACE_STATE_ORPHANED &&
                    all_diverged[i].item_kind == WORKSPACE_ITEM_FILE) {
                    file_orphans[f_idx++] = &all_diverged[i];
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

            /* Second pass: populate directory orphans array */
            size_t d_idx = 0;
            for (size_t i = 0; i < all_diverged_count; i++) {
                if (all_diverged[i].state == WORKSPACE_STATE_ORPHANED &&
                    all_diverged[i].item_kind == WORKSPACE_ITEM_DIRECTORY) {
                    dir_orphans[d_idx++] = &all_diverged[i];
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
        }
    }

    /* Check if there's anything to do
     *
     * After filtering to pending files and extracting orphans, check if
     * there's any work to do. If not, exit early with clean message.
     */
    if (pending_manifest->count == 0 &&
        (opts->keep_orphans || (file_orphan_count == 0 && dir_orphan_count == 0))) {
        /* No pending files and (keeping orphans OR no orphans to clean) */
        output_info(out, "Nothing to deploy (no pending changes)");
        output_info(out, "Workspace is clean");
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
            pending_manifest,
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
        .skip_unchanged = opts->skip_unchanged
    };

    err = deploy_preflight_check_from_workspace(ws, manifest, &deploy_opts, &preflight);
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
            .orphaned_files = file_orphans,           /* Workspace item array */
            .orphaned_files_count = file_orphan_count,
            .orphaned_directories = dir_orphans,      /* Workspace item array */
            .orphaned_directories_count = dir_orphan_count,
            .preflight_violations = NULL,             /* No preflight violations yet (this IS the preflight) */
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

    /* Execute deployment (only if there are pending files)
     *
     * Deploy only PENDING_DEPLOYMENT files (filtered manifest).
     * If pending_manifest is empty, skip deployment phase entirely.
     */
    if (pending_manifest->count > 0) {
        if (opts->dry_run) {
            output_print(out, OUTPUT_VERBOSE, "Dry-run mode - no files will be modified\n");
        } else {
            output_print(out, OUTPUT_VERBOSE, "Deploying %zu pending file%s...\n",
                        pending_manifest->count,
                        pending_manifest->count == 1 ? "" : "s");
        }

        err = deploy_execute(repo, ws, pending_manifest, merged_metadata, &deploy_opts, km, cache, &deploy_res);
        if (err) {
            if (deploy_res) {
                print_deploy_results(out, deploy_res, opts->verbose);
            }
            err = error_wrap(err, "Deployment failed");
            goto cleanup;
        }

        print_deploy_results(out, deploy_res, opts->verbose);
    } else {
        /* No files to deploy, but continue to cleanup phase */
        output_print(out, OUTPUT_VERBOSE, "Skipping deployment (no pending files)\n");

        /* Create empty deploy result for status update logic */
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
                .cache = cache,                           /* Pass cache for performance (avoids re-decryption) */
                .orphaned_files = file_orphans,           /* Workspace item array */
                .orphaned_files_count = file_orphan_count,
                .orphaned_directories = dir_orphans,      /* Workspace item array */
                .orphaned_directories_count = dir_orphan_count,
                .preflight_violations = cleanup_preflight ? cleanup_preflight->safety_violations : NULL,
                .verbose = opts->verbose,
                .dry_run = false,  /* Dry-run handled at deployment level */
                .force = opts->force,
                .skip_safety_check = true  /* Trust preflight data (performance optimization) */
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

        /* Update manifest status for deployed files (incremental, not rebuild) */
        output_print(out, OUTPUT_VERBOSE, "\nUpdating deployment state...\n");

        err = apply_update_deployment_status(state, deploy_res, out);
        if (err) {
            goto cleanup;
        }

        /* Delete PENDING_REMOVAL entries from manifest table */
        err = apply_cleanup_pending_removals(state, out);
        if (err) {
            goto cleanup;
        }

        /* Sync tracked directories to state (defensive refresh)
         *
         * Note: The manifest layer (manifest_enable_profile, manifest_disable_profile,
         * etc.) is the primary authority for directory syncing and should keep tracked
         * directories synchronized with enabled profiles. This refresh serves as a
         * defensive measure to ensure consistency in case manifest operations were
         * incomplete or state was manually modified.
         *
         * The operation is idempotent (state_add_directory uses INSERT OR REPLACE),
         * so redundant syncing is safe. Performance impact is negligible since there
         * are typically fewer than 50 tracked directories even in large configurations. */
        output_print(out, OUTPUT_VERBOSE, "\nSyncing tracked directories to state...\n");

        err = state_clear_directories(state);
        if (err) {
            err = error_wrap(err, "Failed to clear tracked directories");
            goto cleanup;
        }

        /* Extract workspace data for directory sync */
        const profile_list_t *profiles_ws = workspace_get_profiles(ws);

        /* Load per-profile metadata to preserve profile attribution */
        for (size_t p = 0; p < profiles_ws->count; p++) {
            const char *profile_name = profiles_ws->profiles[p].name;

            /* Get cached metadata for this profile (O(1) hashmap lookup) */
            const metadata_t *profile_meta = workspace_get_metadata(ws, profile_name);

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
                output_print(out, OUTPUT_VERBOSE,
                            "  Syncing %zu director%s from profile '%s'\n",
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
                    err = error_wrap(err, "Failed to create state directory entry for '%s'",
                                    directories[i]->key);
                    goto cleanup;
                }

                err = state_add_directory(state, state_dir);
                state_free_directory_entry(state_dir);

                if (err) {
                    free(directories);
                    err = error_wrap(err, "Failed to add directory '%s' to state",
                                    directories[i]->key);
                    goto cleanup;
                }
            }

            /* Free the pointer array (items themselves are owned by metadata) */
            free(directories);
        }

        output_print(out, OUTPUT_VERBOSE, "Directory sync complete\n");

        /* Save updated state */
        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to save state");
            goto cleanup;
        }

        output_print(out, OUTPUT_VERBOSE, "\nState saved\n");
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
    if (pending_manifest) manifest_free_filtered(pending_manifest);
    if (cleanup_preflight) cleanup_preflight_result_free(cleanup_preflight);
    if (preflight) preflight_result_free(preflight);
    if (hook_ctx) hook_context_free(hook_ctx);
    if (profiles_str) free(profiles_str);
    if (cache) content_cache_free(cache);
    if (merged_metadata) metadata_free(merged_metadata);
    if (dir_orphans) free(dir_orphans);
    if (file_orphans) free(file_orphans);
    if (ws) workspace_free(ws);
    if (profiles) profile_list_free(profiles);
    if (state) state_free(state);
    if (repo_dir) free(repo_dir);
    if (config) config_free(config);
    if (out) output_free(out);

    return err;
}
