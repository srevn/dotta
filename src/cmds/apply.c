/**
 * apply.c - Apply profiles to filesystem
 */

#include "cmds/apply.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "base/string.h"
#include "core/cleanup.h"
#include "core/deploy.h"
#include "core/manifest.h"
#include "core/safety.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "infra/content.h"
#include "utils/hooks.h"
#include "utils/privilege.h"

/**
 * Print pre-flight results
 */
static void print_preflight_results(
    const output_ctx_t *out,
    const preflight_result_t *result
) {
    if (!result) return;

    /* Print conflicts */
    if (result->conflicts && result->conflicts->count > 0) {
        output_section(out, OUTPUT_NORMAL, "Conflicts (files modified locally)");
        for (size_t i = 0; i < result->conflicts->count; i++) {
            output_styled(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s\n",
                result->conflicts->items[i]
            );
        }
        output_newline(out, OUTPUT_NORMAL);
        output_info(out, OUTPUT_NORMAL, "Use --force to overwrite local changes");
    }

    /* Print permission errors */
    if (result->permission_errors && result->permission_errors->count > 0) {
        output_section(out, OUTPUT_NORMAL, "Permission errors");
        for (size_t i = 0; i < result->permission_errors->count; i++) {
            output_styled(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s\n",
                result->permission_errors->items[i]
            );
        }
    }

    /* Print profile reassignments */
    if (result->reassignments && result->reassignment_count > 0) {
        output_section(out, OUTPUT_NORMAL, "Profile reassignments");
        for (size_t i = 0; i < result->reassignment_count; i++) {
            const reassignment_t *change = &result->reassignments[i];
            output_styled(
                out, OUTPUT_NORMAL, "  {yellow}→{reset} %s: {cyan}%s{reset} → {cyan}%s{reset}\n",
                change->filesystem_path, change->old_profile, change->new_profile
            );
        }
        output_info(
            out, OUTPUT_NORMAL,
            "  These files will now be managed by a different profile."
        );
    }
}

/**
 * Print deployment results
 *
 * Handles all output for deployment results. The deploy layer only collects
 * results; this function handles all presentation.
 *
 * Categories (each semantically distinct):
 * - deployed: Files written to disk (green)
 * - adopted: Existing files now managed by dotta (yellow - draws attention)
 * - unchanged: Already tracked, no changes needed (cyan)
 * - skipped_existing: --skip-existing flag applied (cyan)
 * - failed: Deployment failures (red, always shown)
 */
static void print_deploy_results(
    const output_ctx_t *out,
    const deploy_result_t *result,
    bool dry_run
) {
    if (!result) return;

    /* Verbose mode: show individual files per category */
    if (result->deployed && result->deployed->count > 0) {
        output_section(out, OUTPUT_VERBOSE, dry_run ? "Would deploy" : "Deployed files");
        for (size_t i = 0; i < result->deployed->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %s\n",
                result->deployed->items[i]
            );
        }
    }

    /* Adopted files - existing files now managed by dotta */
    if (result->adopted && result->adopted->count > 0) {
        output_section(out, OUTPUT_VERBOSE, dry_run ? "Would adopt" : "Adopted files");
        for (size_t i = 0; i < result->adopted->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}⊕{reset} %s\n",
                result->adopted->items[i]
            );
        }
    }

    /* Unchanged files - already tracked, still correct */
    if (result->unchanged && result->unchanged->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Unchanged files");
        for (size_t i = 0; i < result->unchanged->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}⊘{reset} %s\n",
                result->unchanged->items[i]
            );
        }
    }

    /* Skipped files (--skip-existing) */
    if (result->skipped_existing && result->skipped_existing->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Skipped files (--skip-existing)");
        for (size_t i = 0; i < result->skipped_existing->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}⊘{reset} %s\n",
                result->skipped_existing->items[i]
            );
        }
    }

    /* Failed files (always shown, regardless of verbose) */
    if (result->failed && result->failed->count > 0) {
        output_section(out, OUTPUT_NORMAL, "Failed to deploy");
        for (size_t i = 0; i < result->failed->count; i++) {
            output_styled(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s\n",
                result->failed->items[i]
            );
        }
        if (result->error_message) {
            output_newline(out, OUTPUT_NORMAL);
            output_error(out, "%s", result->error_message);
        }
    }

    /* Non-verbose: summary counts only.
     *
     * Arrays may be NULL on the empty-result calloc path in apply (no deployment
     * needed), so guard each read. arr->count is the authoritative source. */
    if (!output_is_verbose(out)) {
        /* Deployed count */
        if (result->deployed && result->deployed->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, dry_run ? "Would deploy {green}%zu{reset} file%s\n"
                                            : "Deployed {green}%zu{reset} file%s\n",
                result->deployed->count,
                result->deployed->count == 1 ? "" : "s"
            );
        }

        /* Adopted count */
        if (result->adopted && result->adopted->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, dry_run ? "Would adopt {yellow}%zu{reset} file%s\n"
                                            : "Adopted {yellow}%zu{reset} file%s (now tracked)\n",
                result->adopted->count,
                result->adopted->count == 1 ? "" : "s"
            );
        }

        /* Unchanged count */
        if (result->unchanged && result->unchanged->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Skipped {cyan}%zu{reset} file%s (unchanged)\n",
                result->unchanged->count,
                result->unchanged->count == 1 ? "" : "s"
            );
        }

        /* Skipped existing count (only shown if --skip-existing was used) */
        if (result->skipped_existing && result->skipped_existing->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Skipped {cyan}%zu{reset} file%s (--skip-existing)\n",
                result->skipped_existing->count,
                result->skipped_existing->count == 1 ? "" : "s"
            );
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

    /* Separate blocking violations from informational released entries.
     *
     * RELEASED violations are non-blocking (files left on filesystem, state cleaned).
     * All other violations are blocking (files skipped to prevent data loss).
     * Display them in separate sections with appropriate messaging. */
    size_t blocking_count = 0;
    size_t released_count = 0;

    for (size_t i = 0; i < safety_result->count; i++) {
        if (strcmp(safety_result->violations[i].reason, SAFETY_REASON_RELEASED) == 0) {
            released_count++;
        } else {
            blocking_count++;
        }
    }

    /* Display blocking violations (modified, type changed, etc.) */
    if (blocking_count > 0) {
        output_section(out, OUTPUT_NORMAL, "Modified orphaned files detected");
        output_newline(out, OUTPUT_NORMAL);

        output_warning(
            out, OUTPUT_NORMAL, "The following files cannot be safely removed:"
        );

        /* Get first blocking violation's profile for example commands */
        const char *example_profile = NULL;

        for (size_t i = 0; i < safety_result->count; i++) {
            const safety_violation_t *v = &safety_result->violations[i];

            if (strcmp(v->reason, SAFETY_REASON_RELEASED) == 0) {
                continue;  /* Show released files separately */
            }

            if (!example_profile && v->source_profile) {
                example_profile = v->source_profile;
            }

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
            } else if (strcmp(v->reason, SAFETY_REASON_CANNOT_VERIFY) == 0) {
                reason_display = "cannot verify";
                icon = "?";
            } else {
                reason_display = v->reason;
            }

            output_color_t reason = v->content_modified ? OUTPUT_COLOR_RED
                                                        : OUTPUT_COLOR_YELLOW;

            output_colored(out, OUTPUT_NORMAL, reason, "  %s", icon);
            output_print(out, OUTPUT_NORMAL, " %s ", v->filesystem_path);

            if (v->source_profile) {
                output_colored(out, OUTPUT_NORMAL, reason, "(%s from ", reason_display);
                output_styled(out, OUTPUT_NORMAL, "{cyan}%s{reset}", v->source_profile);
                output_colored(out, OUTPUT_NORMAL, reason, ")\n");
            } else {
                output_colored(out, OUTPUT_NORMAL, reason, "(%s)\n", reason_display);
            }
        }

        output_newline(out, OUTPUT_NORMAL);
        output_info(out, OUTPUT_NORMAL, "Uncommitted changes would be lost.");
        output_newline(out, OUTPUT_NORMAL);

        output_hintline(out, OUTPUT_NORMAL, "Options:");
        output_hintline(out, OUTPUT_NORMAL, "  1. Commit changes to the profile:");
        if (example_profile) {
            output_hintline(out, OUTPUT_NORMAL, "     dotta update -p %s <files>", example_profile);
            output_hintline(out, OUTPUT_NORMAL, "     dotta apply");
        } else {
            output_hintline(out, OUTPUT_NORMAL, "     dotta update <files>");
            output_hintline(out, OUTPUT_NORMAL, "     dotta apply");
        }
        output_hintline(out, OUTPUT_NORMAL, "  2. Force removal (discards changes):");
        output_hintline(out, OUTPUT_NORMAL, "         dotta apply --force");
        output_hintline(out, OUTPUT_NORMAL, "  3. Keep the profile enabled:");
        if (example_profile) {
            output_hintline(out, OUTPUT_NORMAL, "     dotta profile enable %s", example_profile);
        } else {
            output_hintline(out, OUTPUT_NORMAL, "     dotta profile enable <profile>");
        }
    }

    /* Display released files (informational, non-blocking) */
    if (released_count > 0) {
        output_section(out, OUTPUT_NORMAL, "Released files");
        output_info(out, OUTPUT_NORMAL, "The following files were removed from Git externally:");

        for (size_t i = 0; i < safety_result->count; i++) {
            const safety_violation_t *v = &safety_result->violations[i];

            if (strcmp(v->reason, SAFETY_REASON_RELEASED) != 0) {
                continue;
            }

            output_styled(out, OUTPUT_NORMAL, "  {cyan}→{reset} %s", v->filesystem_path);
            if (v->source_profile) {
                output_styled(out, OUTPUT_NORMAL, " {dim}(from %s){reset}", v->source_profile);
            }
            output_newline(out, OUTPUT_NORMAL);
        }

        output_info(
            out, OUTPUT_NORMAL,
            "These files will be left on the filesystem and released from management."
        );
    }
}

/**
 * Print cleanup results
 */
static void print_cleanup_results(
    const output_ctx_t *out,
    const cleanup_result_t *result
) {
    if (!result) return;

    /* Display safety violations first (most important) */
    if (result->safety_violations) {
        print_safety_violations(out, result->safety_violations);
    }

    /* Display orphaned files */
    if (result->removed_files && result->removed_files->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Pruned orphaned files");
        for (size_t i = 0; i < result->removed_files->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}[removed]{reset} %s\n",
                result->removed_files->items[i]
            );
        }
    }

    if (result->skipped_files && result->skipped_files->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Skipped orphaned files");
        for (size_t i = 0; i < result->skipped_files->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}[skipped]{reset} %s (safety violation)\n",
                result->skipped_files->items[i]
            );
        }
    }

    if (result->released_files && result->released_files->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Released files (removed from Git externally)");
        for (size_t i = 0; i < result->released_files->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[released]{reset} %s\n",
                result->released_files->items[i]
            );
        }
    }

    if (result->failed_files && result->failed_files->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Failed to remove orphaned files");
        for (size_t i = 0; i < result->failed_files->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {red}[fail]{reset} %s\n",
                result->failed_files->items[i]
            );
        }
    }

    /* Display empty directories */
    if (result->removed_dirs && result->removed_dirs->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Pruned empty tracked directories");
        for (size_t i = 0; i < result->removed_dirs->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}[removed]{reset} %s\n",
                result->removed_dirs->items[i]
            );
        }
    }

    if (result->skipped_dirs && result->skipped_dirs->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Skipped directories (not empty)");
        for (size_t i = 0; i < result->skipped_dirs->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}[skipped]{reset} %s\n",
                result->skipped_dirs->items[i]
            );
        }
    }

    if (result->failed_dirs && result->failed_dirs->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Failed to remove empty directories");
        for (size_t i = 0; i < result->failed_dirs->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {red}[fail]{reset} %s\n",
                result->failed_dirs->items[i]
            );
        }
    }

    /* Print summaries if not verbose.
     *
     * Arrays may be NULL when cleanup_result allocation partially failed; guard
     * each read. arr->count is the authoritative source. */
    if (!output_is_verbose(out)) {
        if (result->removed_files && result->removed_files->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Pruned {yellow}%zu{reset} orphaned file%s\n",
                result->removed_files->count,
                result->removed_files->count == 1 ? "" : "s"
            );
        }

        if (result->removed_dirs && result->removed_dirs->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Pruned {yellow}%zu{reset} orphaned director%s\n",
                result->removed_dirs->count,
                result->removed_dirs->count == 1 ? "y" : "ies"
            );
        }

        if (result->released_files && result->released_files->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Released {cyan}%zu{reset} file%s from management\n",
                result->released_files->count,
                result->released_files->count == 1 ? "" : "s"
            );
        }

        if (result->skipped_files && result->skipped_files->count > 0) {
            output_warning(
                out, OUTPUT_NORMAL, "Skipped %zu orphaned file%s (uncommitted changes)",
                result->skipped_files->count,
                result->skipped_files->count == 1 ? "" : "s"
            );
            output_info(
                out, OUTPUT_NORMAL, "Use --verbose to see which files were skipped."
            );
            output_info(
                out, OUTPUT_NORMAL, "To remove: commit/stash changes, or use --force."
            );
        }

        if (result->skipped_dirs && result->skipped_dirs->count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Skipped %zu orphaned director%s (not empty)",
                result->skipped_dirs->count,
                result->skipped_dirs->count == 1 ? "y" : "ies"
            );
            output_info(
                out, OUTPUT_NORMAL, "Use --verbose to see which directories were skipped."
            );
        }

        size_t files_failed = result->failed_files ? result->failed_files->count : 0;
        size_t dirs_failed = result->failed_dirs ? result->failed_dirs->count : 0;

        if (files_failed > 0 || dirs_failed > 0) {
            size_t total_failed = files_failed + dirs_failed;
            output_warning(
                out, OUTPUT_NORMAL, "Failed to prune %zu item%s",
                total_failed, total_failed == 1 ? "" : "s"
            );
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
    const cleanup_preflight_result_t *result
) {
    if (!result) return;

    /* Case 1: No orphans and no directories - nothing to display */
    if (!result->will_prune_orphans && !result->will_prune_directories) {
        output_print(
            out, OUTPUT_VERBOSE, "No orphaned files or directories to prune\n"
        );
        return;
    }

    /* Case 2: Orphaned files found - always show summary
     *
     * Count released files from safety violations to provide accurate breakdown.
     * Released files are left on filesystem (not removed), so the "will be removed"
     * count must exclude them to avoid misleading the user.
     */
    /* will_prune_orphans implies orphaned_files is non-NULL (see cleanup_preflight_check) */
    if (result->will_prune_orphans) {
        output_section(out, OUTPUT_NORMAL, "Orphaned files");

        /* Count released files from safety violations */
        size_t released_count = 0;
        if (result->safety_violations) {
            for (size_t i = 0; i < result->safety_violations->count; i++) {
                if (strcmp(
                    result->safety_violations->violations[i].reason, SAFETY_REASON_RELEASED
                    ) == 0) {
                    released_count++;
                }
            }
        }

        size_t removal_count = (result->orphaned_files->count > released_count)
                             ? result->orphaned_files->count - released_count : 0;

        if (removal_count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {yellow}%zu{reset} file%s will be removed (no longer active)\n",
                removal_count, removal_count == 1 ? "" : "s"
            );
        }

        if (released_count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {cyan}%zu{reset} file%s will be released from management\n",
                released_count, released_count == 1 ? "" : "s"
            );
        }

        /* Show individual paths in verbose mode */
        if (result->orphaned_files->count > 0) {
            size_t display_limit = 20;  /* Don't flood the terminal */
            size_t display_count = result->orphaned_files->count < display_limit
                                 ? result->orphaned_files->count : display_limit;

            for (size_t i = 0; i < display_count; i++) {
                output_styled(
                    out, OUTPUT_VERBOSE, "    {cyan}•{reset} %s\n",
                    result->orphaned_files->items[i]
                );
            }

            if (result->orphaned_files->count > display_limit) {
                size_t remaining = result->orphaned_files->count - display_limit;
                output_print(
                    out, OUTPUT_VERBOSE, "    ... and %zu more\n",
                    remaining
                );
            }
        }
    }

    /* Case 3: Safety violations - ALWAYS show (blocking) */
    if (result->has_blocking_violations) {
        print_safety_violations(out, result->safety_violations);
    }

    /* Case 4: Empty directories - only in verbose mode
     * will_prune_directories implies orphaned_directories is non-NULL */
    if (result->will_prune_directories) {
        output_section(out, OUTPUT_VERBOSE, "Empty directories");

        output_styled(
            out, OUTPUT_VERBOSE, "  {cyan}%zu{reset} orphaned director%s will be pruned\n",
            result->orphaned_directories->count,
            result->orphaned_directories->count == 1 ? "y" : "ies"
        );

        /* Show directory paths if not too many */
        if (result->orphaned_directories->count <= 10) {
            for (size_t i = 0; i < result->orphaned_directories->count; i++) {
                output_print(
                    out, OUTPUT_VERBOSE, "    • %s\n",
                    result->orphaned_directories->items[i]
                );
            }
        }
    }

    output_newline(out, OUTPUT_NORMAL);
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
    const dotta_ctx_t *ctx,
    const manifest_t *manifest,
    const workspace_item_t **file_orphans,
    size_t file_orphan_count,
    const workspace_item_t **dir_orphans,
    size_t dir_orphan_count,
    const cmd_apply_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    if (opts->dry_run) {
        return NULL;  /* Read-only operation, no privileges needed */
    }

    string_array_t *root_paths = string_array_new(0);
    if (!root_paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate root paths list");
    }

    /* 1. Collect paths needing elevation from manifest (files being deployed).
     * Uses privilege_needs_elevation() which considers whether the resolved
     * filesystem path is under $HOME — custom/ paths under $HOME don't need sudo. */
    for (size_t i = 0; i < manifest->count; i++) {
        if (privilege_needs_elevation(
            manifest->entries[i].storage_path, manifest->entries[i].filesystem_path
            )) {
            error_t *err = string_array_push(root_paths, manifest->entries[i].storage_path);
            if (err) {
                string_array_free(root_paths);
                return error_wrap(err, "Failed to add manifest root path");
            }
        }
    }

    /* 2. Collect paths needing elevation from file orphans (files being removed) */
    if (file_orphans && file_orphan_count > 0) {
        for (size_t i = 0; i < file_orphan_count; i++) {
            if (privilege_needs_elevation(
                file_orphans[i]->storage_path, file_orphans[i]->filesystem_path
                )) {
                error_t *err = string_array_push(root_paths, file_orphans[i]->storage_path);
                if (err) {
                    string_array_free(root_paths);
                    return error_wrap(err, "Failed to add file orphan root path");
                }
            }
        }
    }

    /* 3. Collect paths needing elevation from directory orphans (directories being removed) */
    if (dir_orphans && dir_orphan_count > 0) {
        for (size_t i = 0; i < dir_orphan_count; i++) {
            if (privilege_needs_elevation(
                dir_orphans[i]->storage_path, dir_orphans[i]->filesystem_path
                )) {
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
    if (root_paths->count > 0) {
        err = privilege_ensure_for_operation(
            root_paths->items,
            root_paths->count,
            "apply",
            true,  /* interactive: prompt user if elevation needed */
            ctx->argc,
            ctx->argv,
            out
        );
    }

    string_array_free(root_paths);

    return err;
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
        /* Not in workspace divergence index -> file is clean */
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
             * If divergence != NONE: file has property mismatches, needs redeployment.
             *
             * DIVERGENCE_STALE is informational (VWD cache was patched in-memory from
             * fresh Git state). It does NOT indicate a filesystem mismatch — the patched
             * values are the new expected state. Mask it out to avoid spurious deployment
             * when the file content already matches the new Git state. */
            return (ws_item->divergence & ~DIVERGENCE_STALE) != DIVERGENCE_NONE;

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

        case WORKSPACE_STATE_RELEASED:
            /* File removed from Git externally, released from management.
             * Never needs deployment — cleanup handles state entry removal. */
            return false;
    }

    /* Unreachable if all enum values handled.
     * Defensive fallback for unknown states (forward compatibility). */
    return false;
}

/**
 * Apply command implementation
 */
error_t *cmd_apply(const dotta_ctx_t *ctx, const cmd_apply_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->state);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    const config_t *config = ctx->config;
    output_ctx_t *out = ctx->out;

    /* Declare all resources at the top, initialized to NULL */
    error_t *err = NULL;
    state_t *state = ctx->state;  /* Borrowed from dispatcher (WRITE) */
    scope_t *scope = NULL;
    const manifest_t *manifest = NULL;
    manifest_t *deploy_manifest = NULL;
    ptr_array_t divergent = { 0 };
    workspace_t *ws = NULL;
    const workspace_item_t **file_orphans = NULL;
    size_t file_orphan_count = 0;
    const workspace_item_t **dir_orphans = NULL;
    size_t dir_orphan_count = 0;
    const workspace_item_t **excluded_orphans = NULL;
    content_cache_t *cache = NULL;
    preflight_result_t *preflight = NULL;
    cleanup_preflight_result_t *cleanup_preflight = NULL;
    char *profiles_str = NULL;
    deploy_result_t *deploy_res = NULL;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Build operation scope
     *
     *   scope_enabled — persistent VWD scope (passed to workspace_load).
     *                   Empty is a valid convergence target: all state
     *                   entries become orphans and apply cleans them up.
     *                   Enables the "disable last profile, then apply"
     *                   workflow.
     *   scope_active  — operation face (hook context).
     *   scope_paths / scope_is_excluded / scope_accepts_profile —
     *     per-iteration filter gates below.
     *
     * Scope_build resolves enabled (lenient on empty), resolves and
     * validates the CLI filter, harvests custom prefixes from the active
     * set, builds the path filter, and deep-copies excludes. */
    output_print(out, OUTPUT_VERBOSE, "Loading profiles...\n");

    scope_inputs_t scope_inputs = {
        .profiles         = opts->profiles,
        .profile_count    = opts->profile_count,
        .files            = opts->files,
        .file_count       = opts->file_count,
        .exclude_patterns = opts->exclude_patterns,
        .exclude_count    = opts->exclude_count,
        .strict_mode      = config->strict_mode,
    };
    err = scope_build(repo, state, &scope_inputs, &scope);
    if (err) goto cleanup;

    output_print(
        out, OUTPUT_VERBOSE, "Using %zu profile%s:\n",
        scope_active(scope)->count,
        scope_active(scope)->count == 1 ? "" : "s"
    );
    for (size_t i = 0; i < scope_active(scope)->count; i++) {
        output_styled(
            out, OUTPUT_VERBOSE, "  {cyan}•{reset} %s\n",
            scope_active(scope)->items[i]
        );
    }

    if (scope_has_paths(scope)) {
        output_print(
            out, OUTPUT_VERBOSE, "\nFile filter: %zu file%s specified\n",
            scope_paths(scope)->count,
            scope_paths(scope)->count == 1 ? "" : "s"
        );
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

    /* Apply needs file divergence + orphan detection for deployment and cleanup. */
    workspace_load_t ws_opts = {
        .analyze_files       = true,
        .analyze_orphans     = true,
        .analyze_untracked   = false,            /* Skip expensive directory scan */
        .analyze_directories = true,             /* Directory metadata convergence */
        .analyze_encryption  = false             /* Not needed for deployment */
    };
    err = workspace_load(repo, state, scope_enabled(scope), config, &ws_opts, &ws);
    if (err) {
        err = error_wrap(err, "Failed to load workspace");
        goto cleanup;
    }

    /* Flush stat caches for files verified clean during workspace analysis.
     * Within apply's transaction — committed atomically with deployment changes. */
    err = workspace_flush_stat_caches(ws);
    if (err) {
        err = error_wrap(err, "Failed to flush stat caches");
        goto cleanup;
    }

    /* Extract manifest from workspace (borrowed reference, owned by workspace) */
    manifest = workspace_get_manifest(ws);
    if (!manifest) {
        err = ERROR(ERR_INTERNAL, "Workspace manifest is NULL");
        goto cleanup;
    }

    output_print(
        out, OUTPUT_VERBOSE, "Workspace loaded: %zu file%s in manifest\n",
        manifest->count, manifest->count == 1 ? "" : "s"
    );

    /* CONVERGENCE MODEL: Analyze files for divergence and build deployment list
     *
     * Single-pass algorithm:
     *   - Walk the manifest once, applying filters and divergence analysis
     *   - Borrow divergent entries into a scratch ptr_array_t
     *   - Materialize the deployment manifest by exact-size copy
     *
     * Architecture:
     * - workspace_load() already computed fresh divergence for ALL files
     * - workspace_get_item() returns NULL for clean files (no divergence)
     * - workspace_get_item() returns workspace_item_t* for divergent files
     * - We deploy only files where divergence != DIVERGENCE_NONE
     */
    output_print(out, OUTPUT_VERBOSE, "\nAnalyzing files for convergence...\n");

    size_t clean_count = 0;
    size_t excluded_deploy_count = 0;  /* Track deployment exclusions */
    size_t excluded_orphan_count = 0;  /* Track orphan exclusions */

    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];

        /* Filter by operation profiles (skip files not in filter) */
        if (entry->profile && !scope_accepts_profile(scope, entry->profile)) {
            continue;
        }

        /* Filter by file filter (skip files not in CLI file list) */
        if (!scope_accepts_path(scope, entry->storage_path)) {
            continue;
        }

        /* Filter by exclusion pattern (skip excluded files; count by reason) */
        if (scope_is_excluded(scope, entry->storage_path)) {
            excluded_deploy_count++;
            output_print(
                out, OUTPUT_VERBOSE, "  Skipping (excluded): %s\n",
                entry->filesystem_path
            );
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
             *   - DIVERGENCE_TYPE: Type changed (file->symlink, etc.)
             *   - DIVERGENCE_ENCRYPTION: Encryption policy violation
             */
            err = ptr_array_push(&divergent, entry);
            if (err) {
                err = error_wrap(err, "Failed to record divergent entry");
                goto cleanup;
            }
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

    /* Materialize entries by exact-size copy. When zero divergent files exist,
     * entries remains NULL — saves memory in the common (clean) case and
     * preserves the consumer-facing contract that count==0 implies entries==NULL.
     *
     * Shallow copy: all pointers inside file_entry_t (tree entries, profile
     * pointers) are borrowed from workspace manifest; memory stays workspace-owned.
     */
    if (divergent.count > 0) {
        deploy_manifest->entries = calloc(divergent.count, sizeof(file_entry_t));
        if (!deploy_manifest->entries) {
            free(deploy_manifest);
            deploy_manifest = NULL;
            err = ERROR(ERR_MEMORY, "Failed to allocate deployment entries");
            goto cleanup;
        }

        for (size_t i = 0; i < divergent.count; i++) {
            deploy_manifest->entries[i] = *(const file_entry_t *) divergent.items[i];
        }
        deploy_manifest->count = divergent.count;
    } else {
        /* No divergent files - entries array remains NULL (saves memory) */
        deploy_manifest->entries = NULL;
    }

    output_print(
        out, OUTPUT_VERBOSE, "  %zu file%s need deployment (missing or divergent)\n",
        deploy_manifest->count, deploy_manifest->count == 1 ? "" : "s"
    );
    output_print(
        out, OUTPUT_VERBOSE, "  %zu file%s already up-to-date (skipped)\n",
        clean_count, clean_count == 1 ? "" : "s"
    );

    /* Warn if file filter was specified but no files matched */
    if (scope_has_paths(scope) && deploy_manifest->count == 0 && clean_count == 0) {
        output_warning(out, OUTPUT_NORMAL, "No matching files found in enabled profiles");
        output_hint(out, OUTPUT_NORMAL, "Check if the file path is correct and profile is enabled");
    }

    /* Extract orphans from workspace (unless --keep-orphans or file filter active)
     *
     * Architecture: workspace_load() already detected ALL orphans (enabled + disabled
     * profiles) during analyze_orphaned_state(). We extract them here for cleanup.
     *
     * Three semantic modes determine orphan cleanup behavior (Coherent Scope):
     *
     * 1. FULL SYNC MODE (no file filter, no profile filter):
     *    Process ALL orphans - complete workspace convergence.
     *    - Disabled profile orphans: User disabled profile -> files removed
     *    - Enabled profile orphans: File deleted from Git -> filesystem converges
     *    - VWD invariant: manifest is authoritative source for scope
     *
     * 2. PROFILE SCOPED MODE (profile filter active, no file filter):
     *    Process only orphans from filtered profiles.
     *    - `dotta apply -p work` removes only work's orphans
     *    - Orphans from other profiles are preserved
     *    - User can run `dotta apply` (no filter) for full sync when ready
     *    - Implements Coherent Scope: all side effects respect CLI filter
     *
     * 3. TARGETED MODE (file filter active):
     *    Orphan cleanup is SKIPPED entirely.
     *    - When user specifies files to apply, they expect a TARGETED operation
     *    - Orphan cleanup is a side effect that would violate least surprise
     *    - An orphan cannot "match" a specific file path by definition
     *
     * Extracted orphans are used for:
     * 1. Privilege checking (filter root/ paths)
     * 2. Preflight display (show user what will be removed)
     * 3. Actual removal (pass to cleanup_execute)
     *
     * This eliminates redundant orphan detection in cleanup module (performance gain).
     */
    if (!opts->keep_orphans && !scope_has_paths(scope)) {
        output_print(out, OUTPUT_VERBOSE, "\nExtracting orphans from workspace...\n");

        /* Extract orphans via workspace API (single pass internally).
         *
         * Coherent Scope principle: the workspace applies the full
         * operation-scope triplet — orphans outside the profile/path
         * dimensions are silently skipped, and orphans matched by an
         * --exclude pattern are counted via excluded_orphan_count so the
         * post-run summary can report them by reason. */
        err = workspace_extract_orphans(
            ws, scope, &file_orphans, &file_orphan_count, &dir_orphans, &dir_orphan_count,
            &excluded_orphans, &excluded_orphan_count
        );
        if (err) {
            err = error_wrap(err, "Failed to extract orphans from workspace");
            goto cleanup;
        }

        /* Mirror the deployment-loop trace: for each orphan held back by
         * --exclude, emit a per-file line. output_print gates on the
         * verbosity level, so non-verbose runs pay only the loop cost. */
        for (size_t i = 0; i < excluded_orphan_count; i++) {
            output_print(
                out, OUTPUT_VERBOSE, "  Preserving orphan (excluded): %s\n",
                excluded_orphans[i]->filesystem_path
            );
        }

        if (file_orphan_count > 0) {
            output_print(
                out, OUTPUT_VERBOSE, "Found %zu orphaned file%s\n",
                file_orphan_count, file_orphan_count == 1 ? "" : "s"
            );
        }
        if (dir_orphan_count > 0) {
            output_print(
                out, OUTPUT_VERBOSE, "Found %zu orphaned director%s\n",
                dir_orphan_count, dir_orphan_count == 1 ? "y" : "ies"
            );
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
                output_print(
                    out, OUTPUT_VERBOSE, "  %zu from disabled profile%s\n",
                    disabled_count, disabled_count == 1 ? "" : "s"
                );
            }
            if (enabled_count > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  %zu from enabled profiles (deleted from Git)\n",
                    enabled_count
                );
            }
        }
    } else if (scope_has_paths(scope) && !opts->keep_orphans) {
        /* File filter active: skip orphan cleanup (targeted operation) */
        output_print(out, OUTPUT_VERBOSE, "\nSkipping orphan cleanup (file filter active)\n");
    }

    /* Count pending profile reassignments within operation scope
     *
     * Profile reassignment (old_profile set in state) is state bookkeeping,
     * not deployment: no bytes need to move to disk since content may be
     * identical. needs_deployment() correctly returns false for these, so
     * they never enter deploy_manifest. But the old_profile flag must still
     * be cleared to prevent the workspace from reporting stale divergence.
     *
     * Counted before the early-exit check to prevent the infinite dirty-status
     * loop: status reports DIRTY (profile_changed), but needs_deployment()
     * correctly returns false (no content divergence), so deploy_manifest is
     * empty. Without this check, the acknowledgment code is never reached.
     *
     * Applies the same three filters as deploy_manifest construction:
     *   1. Profile filter (-p): Coherent Scope — only acknowledge within scope
     *   2. Path filter (file args): Only acknowledge targeted files
     *   3. Exclusion filter (--exclude): Respect explicit exclusions
     */
    size_t acknowledged_count = 0;
    size_t all_count = 0;
    const workspace_item_t *all_items = workspace_get_all_diverged(ws, &all_count);

    for (size_t i = 0; i < all_count; i++) {
        if (!all_items[i].profile_changed) {
            continue;
        }

        /* Coherent Scope: same filters as deployment pipeline */
        if (!scope_accepts_entry(scope, all_items[i].profile, all_items[i].storage_path)) {
            continue;
        }
        acknowledged_count++;
    }

    /* Check if there's anything to do */
    bool no_orphans = opts->keep_orphans || (file_orphan_count == 0 && dir_orphan_count == 0);

    if (deploy_manifest->count == 0 && acknowledged_count == 0 && no_orphans) {
        /* Nothing to deploy, acknowledge, or clean */
        size_t total_excluded = excluded_deploy_count + excluded_orphan_count;
        if (total_excluded > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Nothing to deploy (%zu file%s excluded by --exclude)",
                total_excluded, total_excluded == 1 ? "" : "s"
            );
        } else {
            output_info(out, OUTPUT_NORMAL, "Nothing to deploy (workspace is clean)");
        }

        /* Commit transaction to persist stat cache updates from workspace flush */
        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to commit stat cache updates");
            goto cleanup;
        }

        err = NULL;
        goto cleanup;
    }

    /* Acknowledgement-only fast path: profile reassignments with no filesystem changes
     *
     * When only profile bookkeeping is pending (no deployment, no orphans),
     * skip privilege checks, preflight, hooks, and confirmation — none apply
     * to pure state bookkeeping that doesn't touch the filesystem. */
    if (deploy_manifest->count == 0 && no_orphans) {
        if (!opts->dry_run) {
            size_t cleared = 0;

            for (size_t i = 0; i < all_count; i++) {
                if (!all_items[i].profile_changed) {
                    continue;
                }

                if (!scope_accepts_entry(scope, all_items[i].profile, all_items[i].storage_path)) {
                    continue;
                }

                error_t *clear_err = state_clear_old_profile(state, all_items[i].filesystem_path);
                if (clear_err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to clear profile reassignment flag for %s: %s",
                        all_items[i].filesystem_path, error_message(clear_err)
                    );
                    error_free(clear_err);
                    continue;
                }
                cleared++;
            }

            if (cleared > 0) {
                output_info(
                    out, OUTPUT_NORMAL, "Acknowledged %zu profile reassignment%s",
                    cleared, cleared == 1 ? "" : "s"
                );
            }

            err = state_save(repo, state);
            if (err) {
                err = error_wrap(err, "Failed to commit state changes");
                goto cleanup;
            }
        } else {
            output_info(
                out, OUTPUT_NORMAL, "Would acknowledge %zu profile reassignment%s (dry-run)",
                acknowledged_count, acknowledged_count == 1 ? "" : "s"
            );
        }

        err = NULL;
        goto cleanup;
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
            ctx, deploy_manifest, file_orphans, file_orphan_count, dir_orphans,
            dir_orphan_count, opts, out
        );
        if (err) {
            err = error_wrap(err, "Insufficient privileges for operation");
            goto cleanup;
        }
    }

    /* Reuse workspace's content cache for batch operations
     *
     * Architecture: Workspace creates and owns the content cache during workspace_load().
     * The cache is already populated with decrypted content from divergence analysis:
     * - Encrypted deployed files: decrypted for content comparison
     * - Encrypted orphaned files: decrypted for orphan divergence check
     *
     * By reusing the workspace cache, subsequent operations get cache hits:
     * - Safety check for orphan removal: cache hit (already decrypted)
     * - Deploy file content: cache hit (already decrypted)
     */
    cache = workspace_get_content_cache(ws);
    if (!cache) {
        err = ERROR(ERR_INTERNAL, "Workspace content cache unavailable");
        goto cleanup;
    }

    /* Run pre-flight checks (using workspace divergence analysis)
     *
     * Workspace already compared all files during workspace_load(), so preflight
     * just queries the results via O(1) hashmap lookups.
     */
    output_print(out, OUTPUT_VERBOSE, "\nRunning pre-flight checks...\n");

    deploy_options_t deploy_opts = {
        .force            = opts->force,
        .dry_run          = opts->dry_run,
        .verbose          = opts->verbose,
        .skip_existing    = opts->skip_existing,
        .skip_unchanged   = opts->skip_unchanged,
        .strict_ownership = config->strict_mode,
        .scope            = scope
    };

    err = deploy_workspace_preflight(ws, deploy_manifest, &deploy_opts, &preflight);
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
            .orphaned_files             = file_orphans, /* Workspace item array */
            .orphaned_files_count       = file_orphan_count,
            .orphaned_directories       = dir_orphans,  /* Workspace item array */
            .orphaned_directories_count = dir_orphan_count,
            .preflight_violations       = NULL,         /* No preflight violations yet */
            .dry_run                    = false,        /* Preflight is always read-only */
            .force                      = opts->force,
            .skip_safety_check          = false         /* Run safety check in preflight */
        };

        err = cleanup_preflight_check(repo, state, &cleanup_opts, &cleanup_preflight);
        if (err) {
            err = error_wrap(err, "Cleanup preflight checks failed");
            goto cleanup;
        }

        /* Display cleanup preflight results */
        print_cleanup_preflight_results(out, cleanup_preflight);

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

            /* Count only blocking violations (exclude RELEASED which are informational) */
            size_t blocking_violation_count = 0;
            for (size_t i = 0; i < cleanup_preflight->safety_violations->count; i++) {
                if (strcmp(
                    cleanup_preflight->safety_violations->violations[i].reason,
                    SAFETY_REASON_RELEASED
                    ) != 0) {
                    blocking_violation_count++;
                }
            }

            output_warning(
                out, OUTPUT_NORMAL, "%zu orphaned file%s %s uncommitted changes.",
                blocking_violation_count,
                blocking_violation_count == 1 ? "" : "s",
                blocking_violation_count == 1 ? "has" : "have"
            );

            output_print(
                out, OUTPUT_NORMAL,
                "These files will be skipped during cleanup to prevent data loss.\n"
            );
            output_print(
                out, OUTPUT_NORMAL,
                "To remove them: commit/stash changes first, or use --force.\n\n"
            );

            /* Continue with operation - cleanup_execute will skip unsafe files */
        }
    }

    /* Build hook invocation with all active profiles */
    profiles_str = string_array_join(scope_active(scope), " ");
    if (!profiles_str) {
        err = ERROR(ERR_MEMORY, "Failed to join profile names for hook");
        goto cleanup;
    }
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_APPLY,
        .profile    = profiles_str,
        .files      = NULL,
        .file_count = 0,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-apply hook */
    err = hook_fire_pre(config, out, ctx->repo_path, &hook_inv);
    if (err) goto cleanup;

    /* Confirm before deployment if configured (unless --force or --dry-run) */
    if (config->confirm_destructive && !opts->force && !opts->dry_run) {
        char prompt[512];  /* Larger buffer for enhanced prompt */

        /* Calculate orphan removal count (exclude safety violations)
         *
         * Violation files are either left on filesystem (released) or
         * skipped by safety (modified, mode_changed, etc.), so they
         * won't actually be deleted. Exclude them from the count.
         */
        size_t removal_count = 0;
        if (cleanup_preflight && cleanup_preflight->will_prune_orphans) {
            /* will_prune_orphans implies orphaned_files is non-NULL */
            size_t preflight_excluded = cleanup_preflight->safety_violations
                                      ? cleanup_preflight->safety_violations->count : 0;

            removal_count = (cleanup_preflight->orphaned_files->count > preflight_excluded)
                          ? cleanup_preflight->orphaned_files->count - preflight_excluded : 0;
        }

        /* Build prompt based on pending actions */
        if (deploy_manifest->count > 0 && removal_count > 0) {
            snprintf(
                prompt, sizeof(prompt), "Deploy %zu file%s and remove %zu orphaned file%s?",
                deploy_manifest->count, deploy_manifest->count == 1 ? "" : "s",
                removal_count, removal_count == 1 ? "" : "s"
            );
        } else if (deploy_manifest->count > 0) {
            snprintf(
                prompt, sizeof(prompt), "Deploy %zu file%s to filesystem?",
                deploy_manifest->count, deploy_manifest->count == 1 ? "" : "s"
            );
        } else if (removal_count > 0) {
            snprintf(
                prompt, sizeof(prompt), "Remove %zu orphaned file%s?",
                removal_count, removal_count == 1 ? "" : "s"
            );
        } else {
            snprintf(prompt, sizeof(prompt), "Proceed with cleanup?");
        }

        if (!output_confirm(out, prompt, false)) {
            output_info(out, OUTPUT_NORMAL, "Cancelled");
            err = NULL;  /* Not an error - user cancelled */
            goto cleanup;
        }
    }

    /* Execute deployment (only if there are divergent files) */
    if (deploy_manifest->count > 0) {
        if (opts->dry_run) {
            output_print(
                out, OUTPUT_VERBOSE, "\nDry-run mode - no files will be modified\n"
            );
        } else {
            output_print(
                out, OUTPUT_VERBOSE, "\nDeploying %zu divergent file%s...\n",
                deploy_manifest->count, deploy_manifest->count == 1 ? "" : "s"
            );
        }

        err = deploy_execute(
            repo, ws, deploy_manifest, state, &deploy_opts, cache, &deploy_res
        );
        if (err) {
            if (deploy_res) {
                print_deploy_results(out, deploy_res, opts->dry_run);
            }
            /* Free deploy_manifest before error exit */
            free(deploy_manifest->entries);
            free(deploy_manifest);
            deploy_manifest = NULL;
            err = error_wrap(err, "Deployment failed");
            goto cleanup;
        }

        print_deploy_results(out, deploy_res, opts->dry_run);

        /* Free deploy_manifest after successful deployment */
        free(deploy_manifest->entries);
        free(deploy_manifest);
        deploy_manifest = NULL;

    } else {
        /* No divergent files - workspace is clean */
        output_print(
            out, OUTPUT_VERBOSE,
            "\nNo files need deployment (workspace is clean)\n"
        );

        /* Create empty deploy result for consistency */
        deploy_res = calloc(1, sizeof(deploy_result_t));
        if (!deploy_res) {
            err = ERROR(ERR_MEMORY, "Failed to allocate deploy result");
            goto cleanup;
        }
    }

    /* Report exclusion statistics (shown regardless of deployment activity) */
    size_t total_excluded = excluded_deploy_count + excluded_orphan_count;
    if (total_excluded > 0) {
        if (output_is_verbose(out)) {
            /* Detailed breakdown */
            output_print(
                out, OUTPUT_VERBOSE, "Skipped %zu file%s (--exclude patterns):\n",
                total_excluded, total_excluded == 1 ? "" : "s"
            );
            if (excluded_deploy_count > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  • %zu divergent file%s not deployed\n",
                    excluded_deploy_count, excluded_deploy_count == 1 ? "" : "s"
                );
            }
            if (excluded_orphan_count > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  • %zu orphaned file%s not removed\n",
                    excluded_orphan_count, excluded_orphan_count == 1 ? "" : "s"
                );
            }
        } else {
            /* Simple summary */
            output_styled(
                out, OUTPUT_NORMAL, "Skipped {cyan}%zu{reset} file%s (--exclude)\n",
                total_excluded, total_excluded == 1 ? "" : "s"
            );
        }
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
            /* TOCTOU Safety: Determine if preflight results can be trusted
             *
             * Preflight runs BEFORE user confirmation. When confirm_destructive is
             * enabled and --force is not set, arbitrary time passes while user decides.
             * During this window, a "safe" orphan could be modified by the user.
             *
             * Risk scenario:
             *   1. Preflight: file X marked safe (no uncommitted changes)
             *   2. User prompt: "Deploy N files and remove M orphans? [y/N]"
             *   3. User edits file X (saves important work to it)
             *   4. User confirms "y"
             *   5. cleanup_execute trusts stale preflight -> deletes file X -> DATA LOSS
             *
             * Solution: Pass NULL to force fresh safety check when interactive delay
             * occurred. Non-interactive paths (--force, confirm_destructive=false)
             * still benefit from preflight optimization.
             */
            bool interactive_delay = config->confirm_destructive && !opts->force;
            cleanup_options_t cleanup_opts = {
                .orphaned_files             = file_orphans, /* Workspace item array */
                .orphaned_files_count       = file_orphan_count,
                .orphaned_directories       = dir_orphans,  /* Workspace item array */
                .orphaned_directories_count = dir_orphan_count,
                .preflight_violations       = interactive_delay
                    ? NULL                                  /* Stale - force fresh safety check */
                    : (cleanup_preflight ? cleanup_preflight->safety_violations : NULL),
                .dry_run                    = false,        /* Dry-run handled at deployment level */
                .force                      = opts->force,
                .skip_safety_check          = false         /* Run safety when preflight_violations is NULL */
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
             * - Permission denied on orphan removal -> warn user, continue
             * - Filesystem errors during cleanup -> warn user, continue
             * - Safety violations (uncommitted changes) -> already warned in preflight
             * - Partial cleanup (some succeed, some fail) -> record successful removals
             *
             * State consistency guarantee:
             * - Deployment state ALWAYS saved (deployment succeeded)
             * - Cleanup state conditionally saved (only successful removals recorded)
             * - Database remains consistent (VWD matches successful filesystem operations)
             */
            error_t *cleanup_err = cleanup_execute(repo, state, &cleanup_opts, &cleanup_res);
            if (cleanup_err) {
                /* Cleanup failed - warn but continue to save deployment state
                 *
                 * The deployment succeeded, so we MUST save deployment state regardless
                 * of cleanup failure. Otherwise we create state desynchronization where:
                 * - Filesystem has correct deployed files
                 * - Database shows files as undeployed (deployed_at = 0)
                 * - User sees confusing [undeployed] status on working files
                 */
                output_warning(
                    out, OUTPUT_NORMAL, "Deployment successful, but orphan cleanup failed: %s",
                    error_message(cleanup_err)
                );

                /* Display partial results if available (cleanup_res may be partial or NULL) */
                if (cleanup_res) {
                    print_cleanup_results(out, cleanup_res);
                }

                error_free(cleanup_err);
                /* Continue to save deployment state (critical for consistency) */
            } else {
                /* Cleanup succeeded - display results */
                if (cleanup_res) {
                    print_cleanup_results(out, cleanup_res);
                }
            }

            /* CRITICAL: Remove orphaned entries from state database
             *
             * This completes the orphan cleanup process. Without this step,
             * orphaned entries accumulate forever in virtual_manifest.
             *
             * The flow for orphaned files:
             *   1. Profile disabled -> entry stays in state (manifest_disable_profile)
             *   2. Workspace detects orphan -> entry in state, profile not enabled
             *   3. cleanup_execute() -> file removed from filesystem (just happened)
             *   4. THIS CODE -> entry removed from state (completing the cycle)
             *
             * DEFENSIVE: Only process if cleanup succeeded and returned results.
             * - If cleanup_err occurred above, cleanup_res may be NULL or incomplete
             * - Only record state updates for successfully removed files (partial success)
             * - If cleanup failed completely, this section is safely skipped
             * - Next 'apply' will retry full cleanup with fresh workspace analysis
             */
            if (cleanup_res && cleanup_res->removed_files &&
                cleanup_res->removed_files->count > 0) {

                output_print(out, OUTPUT_VERBOSE, "\nRemoving orphaned entries from state...\n");

                for (size_t i = 0; i < cleanup_res->removed_files->count; i++) {
                    const char *path = cleanup_res->removed_files->items[i];

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
                        output_warning(
                            out, OUTPUT_NORMAL, "Failed to remove state entry for %s: %s",
                            path, error_message(err)
                        );
                        error_free(err);
                        err = NULL;  /* Don't propagate - continue operation */
                    }
                }

                output_print(
                    out, OUTPUT_VERBOSE, "  Removed %zu orphaned entr%s from state\n",
                    cleanup_res->removed_files->count,
                    cleanup_res->removed_files->count == 1 ? "y" : "ies"
                );
            }

            /* Remove released file entries from state
             *
             * Released files: removed from Git externally (git rm, rebase, branch -D).
             * - File left on filesystem (Git cannot back it, protect user data)
             * - State entry removed (can't manage without Git backing)
             *
             * The user is informed via RELEASED display, but operation is
             * non-blocking. These files are effectively "let go" — dotta stops
             * tracking them and they become normal unmanaged files.
             */
            if (cleanup_res && cleanup_res->released_files &&
                cleanup_res->released_files->count > 0) {

                output_print(out, OUTPUT_VERBOSE, "\nReleasing files from management...\n");

                for (size_t i = 0; i < cleanup_res->released_files->count; i++) {
                    const char *path = cleanup_res->released_files->items[i];

                    /* Delete entry from virtual_manifest table
                     *
                     * The file is LEFT on filesystem (we can't verify it's safe to remove).
                     * We remove only the database record since we can't manage this file
                     * anymore (no profile branch to verify against).
                     */
                    err = state_remove_file(state, path);
                    if (err) {
                        /* Non-fatal - file is safe on filesystem */
                        output_warning(
                            out, OUTPUT_NORMAL, "Failed to release state entry for %s: %s",
                            path, error_message(err)
                        );
                        error_free(err);
                        err = NULL;
                    }
                }

                output_print(
                    out, OUTPUT_VERBOSE, "  Released %zu file%s from management\n",
                    cleanup_res->released_files->count,
                    cleanup_res->released_files->count == 1 ? "" : "s"
                );
            }

            /* Remove orphaned directory entries from state
             *
             * After cleanup_execute() removes directories from filesystem,
             * we need to remove their entries from state to prevent accumulation.
             *
             * The flow for orphaned directories:
             *   1. Profile disabled -> entry stays in state (manifest_disable_profile)
             *   2. Workspace detects orphan -> entry in state, profile not enabled
             *   3. cleanup_execute() -> directory removed from filesystem (just happened)
             *   4. THIS CODE -> entry removed from state (completing the cycle)
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
                cleanup_res->removed_dirs->count > 0) {

                output_print(
                    out, OUTPUT_VERBOSE,
                    "\nRemoving orphaned directory entries from state...\n"
                );

                for (size_t i = 0; i < cleanup_res->removed_dirs->count; i++) {
                    const char *path = cleanup_res->removed_dirs->items[i];

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
                        output_warning(
                            out, OUTPUT_NORMAL, "Failed to remove directory state entry for %s: %s",
                            path, error_message(err)
                        );
                        error_free(err);
                        err = NULL;  /* Don't propagate - continue operation */
                    }
                }

                output_print(
                    out, OUTPUT_VERBOSE, "  Removed %zu orphaned directory entr%s from state\n",
                    cleanup_res->removed_dirs->count,
                    cleanup_res->removed_dirs->count == 1 ? "y" : "ies"
                );
            }

            cleanup_result_free(cleanup_res);
        }

        /* Update deployed_at timestamp for successfully deployed files
         *
         * CRITICAL: This marks files as "known to dotta" and records deployment time.
         * The deployed_at field is used for lifecycle tracking:
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
        if (deploy_res && deploy_res->deployed && deploy_res->deployed->count > 0) {
            time_t now = time(NULL);

            output_print(out, OUTPUT_VERBOSE, "\nUpdating deployment timestamps...\n");

            for (size_t i = 0; i < deploy_res->deployed->count; i++) {
                const char *path = deploy_res->deployed->items[i];

                /* Capture stat from just-deployed file for fast-path cache.
                 *
                 * The file was just written and fsynced by deploy_file() — lstat()
                 * is a cheap inode lookup from kernel cache. If lstat fails (rare:
                 * file removed between deploy and here), pass NULL to clear cache. */
                struct stat post_stat;
                const stat_cache_t sc = (lstat(path, &post_stat) == 0)
                    ? stat_cache_from_stat(&post_stat) : STAT_CACHE_UNSET;

                /* Update deployed_at and stat cache */
                err = state_update_post_deploy(state, path, now, &sc);
                if (err) {
                    /* Non-fatal warning - deployment succeeded, just timestamp update failed
                     *
                     * The file is already on the filesystem with correct content.
                     * The timestamp is metadata for display and lifecycle tracking.
                     * Failure here should not abort the entire operation.
                     */
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to update timestamp for %s: %s",
                        path, error_message(err)
                    );
                    error_free(err);
                    err = NULL;  /* Don't propagate - continue operation */
                }
            }

            output_print(
                out, OUTPUT_VERBOSE, "  Updated %zu timestamp%s\n",
                deploy_res->deployed->count,
                deploy_res->deployed->count == 1 ? "" : "s"
            );
        }

        /* Update deployed_at for adopted files
         *
         * Adopted files are those that:
         * - Existed on filesystem with correct content
         * - Were never tracked by dotta (deployed_at == 0)
         * - Were added to deploy_res->adopted by deploy_execute
         */
        if (deploy_res->adopted && deploy_res->adopted->count > 0) {
            time_t now = time(NULL);

            output_print(out, OUTPUT_VERBOSE, "\nRecording adopted files in state...\n");

            for (size_t i = 0; i < deploy_res->adopted->count; i++) {
                const char *path = deploy_res->adopted->items[i];

                /* Capture stat from adopted file for fast-path cache.
                 *
                 * Adopted files already existed with correct content — lstat()
                 * is guaranteed to succeed (deploy_execute verified existence). */
                struct stat adopted_stat;
                const stat_cache_t sc = (lstat(path, &adopted_stat) == 0)
                    ? stat_cache_from_stat(&adopted_stat) : STAT_CACHE_UNSET;

                err = state_update_post_deploy(state, path, now, &sc);
                if (err) {
                    /* Non-fatal: file is already correct on filesystem.
                     * Log warning and continue - the important fact (file exists
                     * with correct content) is true regardless of database state.
                     */
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to record adoption for %s: %s",
                        path, error_message(err)
                    );
                    error_free(err);
                    err = NULL;
                }
            }

            output_print(
                out, OUTPUT_VERBOSE, "  Recorded %zu adopted file%s\n",
                deploy_res->adopted->count,
                deploy_res->adopted->count == 1 ? "" : "s"
            );
        }

        /* Acknowledge profile reassignments (clear old_profile in state)
         *
         * Profile reassignment may or may not coincide with content divergence.
         * When content also diverged, the file was redeployed above. Either way,
         * clear the old_profile flag for in-scope items so the transition doesn't
         * persist as stale state across future runs. */
        size_t cleared = 0;
        size_t all_count = 0;
        const workspace_item_t *all_items = workspace_get_all_diverged(ws, &all_count);

        for (size_t i = 0; i < all_count; i++) {
            if (!all_items[i].profile_changed) {
                continue;
            }

            if (!scope_accepts_entry(scope, all_items[i].profile, all_items[i].storage_path)) {
                continue;
            }

            error_t *clear_err = state_clear_old_profile(state, all_items[i].filesystem_path);
            if (clear_err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to clear profile reassignment flag for %s: %s",
                    all_items[i].filesystem_path, error_message(clear_err)
                );
                error_free(clear_err);
                continue;
            }
            cleared++;
        }

        if (cleared > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Acknowledged {cyan}%zu{reset} profile reassignment%s\n",
                cleared, cleared == 1 ? "" : "s"
            );
        }

        /* Commit state transaction (saves both deployment and cleanup state)
         *
         * This atomically commits all state changes made during apply:
         * - Deployment state: deployed_at timestamps for newly deployed files
         * - Cleanup state: removed orphan entries (if cleanup succeeded)
         * - Reassignments: cleared old_profile flags for reassigned files
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
    hook_fire_post(config, out, ctx->repo_path, &hook_inv);

    /* Success - fall through to cleanup */
    err = NULL;

cleanup:
    if (deploy_res) deploy_result_free(deploy_res);
    if (deploy_manifest) {
        /* Free deploy_manifest structure */
        free(deploy_manifest->entries);
        free(deploy_manifest);
    }
    ptr_array_deinit(&divergent);
    if (cleanup_preflight) cleanup_preflight_result_free(cleanup_preflight);
    if (preflight) preflight_result_free(preflight);
    if (profiles_str) free(profiles_str);
    if (excluded_orphans) free(excluded_orphans);
    if (dir_orphans) free(dir_orphans);
    if (file_orphans) free(file_orphans);
    if (ws) workspace_free(ws);
    if (scope) scope_free(scope);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/* Command-local positional classes. Start at 1 to reserve 0 for the
 * engine's "unclassified" sentinel (see args.h:args_class_t). */
enum apply_class { APPLY_CLASS_FILE = 1, APPLY_CLASS_PROFILE, };

/**
 * Positional classifier: file-like tokens go to files[]; everything
 * else is treated as a profile name.
 */
static args_class_t apply_classify(const char *tok) {
    return str_looks_like_file_path(tok) ? APPLY_CLASS_FILE
                                         : APPLY_CLASS_PROFILE;
}

/**
 * Seed non-zero defaults. `skip_unchanged` is true by default — the
 * user opts out with `--no-skip-unchanged`, which writes 0 via
 * ARGS_FLAG_SET.
 */
static void apply_defaults(void *opts_v) {
    cmd_apply_options_t *o = opts_v;
    o->skip_unchanged = 1;
}

static error_t *apply_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_apply(ctx, (const cmd_apply_options_t *) opts_v);
}

static const args_opt_t apply_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_APPEND(
        "p profile",        "<name>",
        cmd_apply_options_t,profiles,         profile_count,
        "Filter deployment to profile(s) (repeatable)"
    ),
    ARGS_APPEND(
        "e exclude",        "<pattern>",
        cmd_apply_options_t,exclude_patterns, exclude_count,
        "Skip matching files (no deploy, no removal)"
    ),
    ARGS_FLAG(
        "f force",
        cmd_apply_options_t,force,
        "Overwrite modified files"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_apply_options_t,dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG(
        "keep-orphans",
        cmd_apply_options_t,keep_orphans,
        "Leave orphaned files in place (advanced)"
    ),
    ARGS_FLAG(
        "skip-existing",
        cmd_apply_options_t,skip_existing,
        "Skip files that already exist"
    ),
    ARGS_FLAG_SET(
        "no-skip-unchanged",
        cmd_apply_options_t,skip_unchanged,   0,
        "Redeploy every file, even if unchanged"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_apply_options_t,verbose,
        "Verbose output"
    ),
    /* Positionals: bare `<file>` tokens append to files[]; bare
     * `<profile>` tokens append to profiles[]. The -p/--profile flag
     * above targets the same profiles[] array, so `-p darwin foo`
     * and `darwin foo` produce the same list in argv order. */
    ARGS_POSITIONAL(
        APPLY_CLASS_FILE,
        cmd_apply_options_t,files,            file_count
    ),
    ARGS_POSITIONAL(
        APPLY_CLASS_PROFILE,
        cmd_apply_options_t,profiles,         profile_count
    ),
    ARGS_END,
};

const args_command_t spec_apply = {
    .name          = "apply",
    .summary       = "Deploy enabled profiles to the filesystem",
    .usage         = "%s apply [options] [profile|file]...",
    .description   =
        "Converge the filesystem with enabled profiles: deploy new and\n"
        "updated files, remove files orphaned by disabled profiles, and\n"
        "update the deployment state.\n",
    .notes         =
        "Smart Skipping:\n"
        "  Files whose content already matches the profile are skipped\n"
        "  by default. Pass --no-skip-unchanged to force redeployment.\n"
        "\n"
        "Exclusion Patterns:\n"
        "  Excluded files are protected from both deployment and removal.\n"
        "  Patterns follow gitignore glob syntax. Flag is repeatable.\n",
    .examples      =
        "  %s apply                              # Deploy all enabled profiles\n"
        "  %s apply -p work                      # Filter to 'work' profile\n"
        "  %s apply -p work ~/.bashrc            # Profile + file filter\n"
        "  %s apply ~/.bashrc ~/.zshrc           # Deploy specific files only\n"
        "  %s apply -n                           # Preview without writing\n"
        "  %s apply --exclude 'home/.ssh/*'      # Protect matched files\n"
        "  %s apply --no-skip-unchanged          # Force-deploy every file\n",
    .epilogue      =
        "See also:\n"
        "  %s status          # Preview pending deployment\n"
        "  %s update          # Commit filesystem changes back\n"
        "  %s profile enable  # Stage a profile for deployment\n",
    .opts_size     = sizeof(cmd_apply_options_t),
    .opts          = apply_opts,
    .classify      = apply_classify,
    .init_defaults = apply_defaults,
    .payload       = &dotta_ext_write,
    .dispatch      = apply_dispatch,
};
