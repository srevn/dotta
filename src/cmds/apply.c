/**
 * apply.c - Apply profiles to filesystem
 */

#include "cmds/apply.h"

#include <config.h>
#include <ctype.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "core/cleanup.h"
#include "core/deploy.h"
#include "core/safety.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "infra/content.h"
#include "sys/filesystem.h"
#include "utils/hooks.h"
#include "utils/privilege.h"

/**
 * Print pre-flight results
 */
static void print_preflight_results(
    const output_t *out,
    const preflight_result_t *result
) {
    if (!result) return;

    /* Print conflicts */
    if (result->conflicts && result->conflicts->count > 0) {
        output_section(out, OUTPUT_NORMAL, "Conflicts (modified locally or wrong type)");
        for (size_t i = 0; i < result->conflicts->count; i++) {
            output_styled(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s\n",
                result->conflicts->items[i]
            );
        }
        output_newline(out, OUTPUT_NORMAL);
        output_info(out, OUTPUT_NORMAL, "Use --force to overwrite or replace them");
    }

    /* Print blocked paths (an ancestry that refuses the planned path) */
    if (result->blocked && result->blocked->count > 0) {
        output_section(out, OUTPUT_NORMAL, "Blocked (resolve these by hand)");
        for (size_t i = 0; i < result->blocked->count; i++) {
            output_styled(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s\n",
                result->blocked->items[i]
            );
        }
        output_newline(out, OUTPUT_NORMAL);
        output_info(
            out, OUTPUT_NORMAL,
            "Fix the path by hand, or widen the scope so a tracked ancestor is planned"
        );
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
}

/**
 * Print pending profile reassignments
 *
 * `reassigned` holds the in-scope diverged items whose owning profile
 * changed (workspace_item_t *, borrowed) — the exact set the run will
 * acknowledge, content-clean reassignments included.
 */
static void print_reassignments(const output_t *out, const ptr_array_t *reassigned) {
    if (reassigned->count == 0) return;

    output_section(out, OUTPUT_NORMAL, "Profile reassignments");
    for (size_t i = 0; i < reassigned->count; i++) {
        const workspace_item_t *item = reassigned->items[i];
        output_styled(
            out, OUTPUT_NORMAL, "  {yellow}→{reset} %s: {cyan}%s{reset} → {cyan}%s{reset}\n",
            item->filesystem_path, item->old_profile, item->profile
        );
    }
    output_info(
        out, OUTPUT_NORMAL,
        "  These files will now be managed by a different profile."
    );
}

/**
 * Acknowledge profile reassignments — clear old_profile in state
 *
 * Reassignment is state bookkeeping, not deployment: content may be
 * identical, so the row never enters the plan, but the flag must be
 * cleared or the workspace keeps reporting the transition. Failures are
 * per-item warnings (the next apply retries). Dry-run prints the count.
 */
static void acknowledge_reassignments(
    state_t *state,
    const ptr_array_t *reassigned,
    bool dry_run,
    output_t *out
) {
    if (reassigned->count == 0) return;

    if (dry_run) {
        output_info(
            out, OUTPUT_NORMAL, "Would acknowledge %zu profile reassignment%s",
            reassigned->count, reassigned->count == 1 ? "" : "s"
        );
        return;
    }

    size_t cleared = 0;
    for (size_t i = 0; i < reassigned->count; i++) {
        const workspace_item_t *item = reassigned->items[i];

        error_t *err = state_clear_old_profile(state, item->filesystem_path);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to clear profile reassignment flag for %s: %s",
                item->filesystem_path, error_message(err)
            );
            error_free(err);
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
}

/**
 * Report the work the plan withheld, by reason — and answer how much
 *
 * -e (files, tracked directories, orphans) and --skip-existing (files)
 * both mean "in scope, needed work, deliberately not done". This report
 * needs the two counts split for its two lines, so it is the only place
 * either is derived; the sum goes back to the caller, whose nothing-to-do
 * line must not call a workspace clean when its only work was held back.
 *
 * Printed once, above the nothing-to-do exit — so a run that does nothing
 * else still says what it held back — and therefore also above the
 * confirmation prompt, where a user weighing the rest of the run should
 * already know what is missing from it. Per-item traces stay at plan time,
 * beside the decision that produced them.
 *
 * @param excluded_orphans Orphans an -e pattern held back (borrowed)
 * @return Paths withheld, both reasons together
 */
static size_t print_withheld(
    const output_t *out,
    const deploy_plan_t *plan,
    workspace_items_t excluded_orphans
) {
    /* -e reaches all three kinds, so its summary counts "paths"; the
     * verbose breakdown names each kind and what it was spared. */
    size_t excluded_orphan_files = 0;
    size_t excluded_orphan_dirs = 0;
    for (size_t i = 0; i < excluded_orphans.count; i++) {
        if (excluded_orphans.entries[i]->item_kind == PATH_KIND_DIRECTORY) {
            excluded_orphan_dirs++;
        } else {
            excluded_orphan_files++;
        }
    }

    size_t excluded = plan->files.excluded.count +
        plan->directories.excluded.count + excluded_orphans.count;

    if (excluded > 0) {
        if (output_is_verbose(out)) {
            output_print(
                out, OUTPUT_VERBOSE, "Skipped %zu path%s (--exclude):\n",
                excluded, excluded == 1 ? "" : "s"
            );
            if (plan->files.excluded.count > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  • %zu divergent file%s not deployed\n",
                    plan->files.excluded.count, plan->files.excluded.count == 1 ? "" : "s"
                );
            }
            if (plan->directories.excluded.count > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  • %zu tracked director%s not converged\n",
                    plan->directories.excluded.count,
                    plan->directories.excluded.count == 1 ? "y" : "ies"
                );
            }
            if (excluded_orphan_files > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  • %zu orphaned file%s not pruned\n",
                    excluded_orphan_files, excluded_orphan_files == 1 ? "" : "s"
                );
            }
            if (excluded_orphan_dirs > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  • %zu orphaned director%s not pruned\n",
                    excluded_orphan_dirs, excluded_orphan_dirs == 1 ? "y" : "ies"
                );
            }
        } else {
            output_styled(
                out, OUTPUT_NORMAL, "Skipped {cyan}%zu{reset} path%s (--exclude)\n",
                excluded, excluded == 1 ? "" : "s"
            );
        }
    }

    /* --skip-existing reaches files only (see deploy_partition_t), so one
     * line says it at every verbosity. */
    size_t existing = plan->files.skipped_existing.count;
    if (existing > 0) {
        output_styled(
            out, OUTPUT_NORMAL,
            "Skipped {cyan}%zu{reset} existing file%s (--skip-existing)\n",
            existing, existing == 1 ? "" : "s"
        );
    }

    return excluded + existing;
}

/**
 * Print deployment results
 *
 * Handles all output for deployment results. The deploy layer only collects
 * results; this function handles all presentation.
 *
 * Categories (each semantically distinct):
 * - deployed: Files written to disk (green)
 * - converged: Tracked directories created / fixed / replaced (green)
 * - failed: Deployment failures (red, always shown)
 *
 * Work the run held back is not here: the plan decided it, print_withheld
 * reports it, and it must be said even on runs that never execute.
 *
 * Adoption (ownership stamping for pre-existing matching files) is an
 * apply-level concern and its summary is printed by cmd_apply directly.
 */
static void print_deploy_results(
    const output_t *out,
    const deploy_result_t *result,
    bool dry_run
) {
    if (!result) return;

    state_files_t deployed = state_files_view(&result->deployed);
    state_directories_t converged = state_directories_view(&result->converged);
    state_files_t failed = state_files_view(&result->failed);

    /* Verbose mode: show individual items per category */
    if (deployed.count > 0) {
        output_section(
            out, OUTPUT_VERBOSE, dry_run ? "Would deploy files"
                                         : "Deployed files"
        );
        for (size_t i = 0; i < deployed.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %s\n",
                deployed.entries[i]->filesystem_path
            );
        }
    }

    if (converged.count > 0) {
        output_section(
            out, OUTPUT_VERBOSE, dry_run ? "Would converge tracked directories"
                                         : "Converged tracked directories"
        );
        for (size_t i = 0; i < converged.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %s\n",
                converged.entries[i]->filesystem_path
            );
        }
    }

    /* Failed files (always shown, regardless of verbose) */
    if (failed.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Failed to deploy");
        for (size_t i = 0; i < failed.count; i++) {
            output_styled(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s\n",
                failed.entries[i]->filesystem_path
            );
        }
        if (result->error_message) {
            output_newline(out, OUTPUT_NORMAL);
            output_error(out, "%s", result->error_message);
        }
    }

    /* Non-verbose: summary counts only. */
    if (!output_is_verbose(out)) {
        if (deployed.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                dry_run ? "Would deploy {green}%zu{reset} file%s\n"
                        : "Deployed {green}%zu{reset} file%s\n",
                deployed.count, deployed.count == 1 ? "" : "s"
            );
        }

        if (converged.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                dry_run ? "Would converge {green}%zu{reset} tracked director%s\n"
                        : "Converged {green}%zu{reset} tracked director%s\n",
                converged.count, converged.count == 1 ? "y" : "ies"
            );
        }
    }
}

/**
 * Print safety violations
 */
static void print_safety_violations(
    const output_t *out,
    const safety_result_t *safety_result
) {
    if (!safety_result || safety_result->count == 0) {
        return;
    }

    /* Blocking violations (modified, type changed, etc.) and informational
     * released entries get separate sections with different messaging.
     * Safety took that split when it assigned each reason; this is display,
     * so it counts nothing and only routes per item. */
    if (safety_result->blocking > 0) {
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
    if (safety_result->released > 0) {
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
    const output_t *out,
    const cleanup_result_t *result
) {
    if (!result) return;

    /* Display safety violations first (most important) */
    if (result->safety_violations) {
        print_safety_violations(out, result->safety_violations);
    }

    /* Display orphaned files */
    if (result->pruned_files && result->pruned_files->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Pruned orphaned files");
        for (size_t i = 0; i < result->pruned_files->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}[pruned]{reset} %s\n",
                result->pruned_files->items[i]
            );
        }
    }

    if (result->reclaimed_files && result->reclaimed_files->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Reclaimed orphaned files (already absent)");
        for (size_t i = 0; i < result->reclaimed_files->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[reclaimed]{reset} %s\n",
                result->reclaimed_files->items[i]
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
        output_section(out, OUTPUT_VERBOSE, "Failed to prune orphaned files");
        for (size_t i = 0; i < result->failed_files->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {red}[failed]{reset} %s\n",
                result->failed_files->items[i]
            );
        }
    }

    /* Display empty directories */
    if (result->pruned_dirs && result->pruned_dirs->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Pruned orphaned directories");
        for (size_t i = 0; i < result->pruned_dirs->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}[pruned]{reset} %s\n",
                result->pruned_dirs->items[i]
            );
        }
    }

    if (result->reclaimed_dirs && result->reclaimed_dirs->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Reclaimed orphaned directories (already absent)");
        for (size_t i = 0; i < result->reclaimed_dirs->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[reclaimed]{reset} %s\n",
                result->reclaimed_dirs->items[i]
            );
        }
    }

    if (result->skipped_dirs && result->skipped_dirs->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Skipped orphaned directories (not empty)");
        for (size_t i = 0; i < result->skipped_dirs->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}[skipped]{reset} %s\n",
                result->skipped_dirs->items[i]
            );
        }
    }

    if (result->failed_dirs && result->failed_dirs->count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Failed to prune orphaned directories");
        for (size_t i = 0; i < result->failed_dirs->count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {red}[failed]{reset} %s\n",
                result->failed_dirs->items[i]
            );
        }
    }

    /* Print summaries if not verbose.
     *
     * Arrays may be NULL when cleanup_result allocation partially failed; guard
     * each read. arr->count is the authoritative source. */
    if (!output_is_verbose(out)) {
        if (result->pruned_files && result->pruned_files->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Pruned {yellow}%zu{reset} orphaned file%s\n",
                result->pruned_files->count,
                result->pruned_files->count == 1 ? "" : "s"
            );
        }

        if (result->pruned_dirs && result->pruned_dirs->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Pruned {yellow}%zu{reset} orphaned director%s\n",
                result->pruned_dirs->count,
                result->pruned_dirs->count == 1 ? "y" : "ies"
            );
        }

        /* State-only outcomes: rows retired for paths already absent from
         * the filesystem. Reported separately from "Pruned" — no removal
         * happened or was needed. */
        size_t files_reclaimed = result->reclaimed_files ? result->reclaimed_files->count : 0;
        size_t dirs_reclaimed = result->reclaimed_dirs ? result->reclaimed_dirs->count : 0;

        if (files_reclaimed + dirs_reclaimed > 0) {
            size_t total_reclaimed = files_reclaimed + dirs_reclaimed;
            output_styled(
                out, OUTPUT_NORMAL,
                "Reclaimed {cyan}%zu{reset} stale state entr%s (absent from filesystem)\n",
                total_reclaimed, total_reclaimed == 1 ? "y" : "ies"
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
 * List the paths behind a preview count, capped
 *
 * One shape for every preview list, so a long directory list is trimmed
 * and counted the way a long file list is rather than vanishing whole. The
 * glyph says which count the path belongs to: a cyan bullet for what the
 * run acts on, a yellow slash for what it deliberately leaves.
 */
static void print_path_list(
    const output_t *out,
    const string_array_t *paths,
    output_color_t color,
    const char *glyph
) {
    const size_t limit = 20;   /* Don't flood the terminal */
    size_t shown = paths->count < limit ? paths->count : limit;

    for (size_t i = 0; i < shown; i++) {
        output_colored(out, OUTPUT_VERBOSE, color, "    %s", glyph);
        output_print(out, OUTPUT_VERBOSE, " %s\n", paths->items[i]);
    }

    if (paths->count > limit) {
        output_print(
            out, OUTPUT_VERBOSE, "    ... and %zu more\n", paths->count - limit
        );
    }
}

/**
 * Print cleanup preflight results
 *
 * Shows what cleanup will do BEFORE user confirmation. Every number here
 * is one cleanup decided; this function reads them and adds nothing of its
 * own, so the preview, the prompt below it and the outcome after it are
 * three sentences about the same work — in the same words, because a
 * preview line and its outcome line name one verdict with one verb
 * ("will be pruned" / "Pruned"), differing only in tense.
 */
static void print_cleanup_preflight_results(
    const output_t *out,
    const cleanup_preflight_result_t *result
) {
    if (!result) return;

    const safety_result_t *violations = result->safety_violations;

    /* Every present orphan lands in exactly one bucket, so these two sums
     * are the present-orphan counts. */
    size_t present_files = result->prunable_files->count + violations->count;
    size_t present_dirs = result->prunable_dirs->count + result->skipped_dirs->count;

    if (present_files == 0 && present_dirs == 0) {
        output_print(
            out, OUTPUT_VERBOSE, "No orphaned files or directories to prune\n"
        );
        return;
    }

    if (present_files > 0) {
        output_section(out, OUTPUT_NORMAL, "Orphaned files");

        if (result->prunable_files->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {yellow}%zu{reset} file%s will be pruned (no longer active)\n",
                result->prunable_files->count,
                result->prunable_files->count == 1 ? "" : "s"
            );
        }

        if (violations->released > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {cyan}%zu{reset} file%s will be released from management\n",
                violations->released, violations->released == 1 ? "" : "s"
            );
        }

        if (violations->blocking > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {yellow}%zu{reset} file%s will be skipped (uncommitted changes)\n",
                violations->blocking, violations->blocking == 1 ? "" : "s"
            );
        }

        /* Only the files the count above promises — the held-back ones are
         * named with their reasons by print_safety_violations. */
        print_path_list(out, result->prunable_files, OUTPUT_COLOR_CYAN, "•");
    }

    if (present_dirs > 0) {
        output_section(out, OUTPUT_NORMAL, "Orphaned directories");

        if (result->prunable_dirs->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "  {cyan}%zu{reset} director%s will be pruned\n",
                result->prunable_dirs->count,
                result->prunable_dirs->count == 1 ? "y" : "ies"
            );
        }

        if (result->skipped_dirs->count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "  {yellow}%zu{reset} director%s will be skipped (not empty)\n",
                result->skipped_dirs->count,
                result->skipped_dirs->count == 1 ? "y" : "ies"
            );
        }

        print_path_list(out, result->prunable_dirs, OUTPUT_COLOR_CYAN, "•");
        print_path_list(out, result->skipped_dirs, OUTPUT_COLOR_YELLOW, "⊘");
    }

    /* Both violation kinds name their files here, with the reason for each
     * and the remedies for the blocking ones — which is why the summaries
     * above only count them. Last, so that guidance is what the user is
     * looking at when the confirmation prompt arrives. */
    print_safety_violations(out, violations);

    output_newline(out, OUTPUT_NORMAL);
}

/**
 * Check privileges for complete apply operation
 *
 * Examines the plan's pending files and directories (deployed / converged)
 * plus the file and directory orphans being removed, for root/ paths. This
 * ensures we have required privileges BEFORE attempting any filesystem
 * modifications — and, reading the plan, it is exact by construction:
 * parents deploy creates on the way are prefixes of planned paths, so a
 * planned path's own label already covers them.
 *
 * @param ctx Command context (must not be NULL)
 * @param plan Deployment plan (must not be NULL)
 * @param file_orphans Files being removed (zeroed if --keep-orphans)
 * @param dir_orphans Directories being removed (zeroed if --keep-orphans)
 * @param opts Apply command options (must not be NULL)
 * @param out Output context for messages (must not be NULL)
 * @return NULL if OK to proceed, error otherwise (or does not return if re-exec with sudo)
 */
static error_t *ensure_complete_apply_privileges(
    const dotta_ctx_t *ctx,
    const deploy_plan_t *plan,
    workspace_items_t file_orphans,
    workspace_items_t dir_orphans,
    const cmd_apply_options_t *opts,
    output_t *out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(plan);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    if (opts->dry_run) {
        return NULL;  /* Read-only operation, no privileges needed */
    }

    state_files_t files = state_files_view(&plan->files.pending);
    state_directories_t dirs = state_directories_view(&plan->directories.pending);

    /* Strict upper bound — every entry across the four sources may need
     * elevation. Reserve once to keep growth out of the hot loop. */
    size_t cap = files.count + dirs.count + file_orphans.count + dir_orphans.count;
    if (cap == 0) return NULL;

    string_array_t labels STRING_ARRAY_AUTO = { 0 };
    error_t *err = string_array_init_cap(&labels, cap);
    if (err) return error_wrap(err, "Failed to reserve privilege label array");

    /* Collect labels for entries needing elevation. The collect helper
     * runs the predicate and pushes the storage_path in one step — the
     * filter is enforced by the privilege module, not the call site. */
    for (size_t i = 0; i < files.count; i++) {
        err = privilege_collect_label(
            &labels,
            files.entries[i]->storage_path,
            files.entries[i]->filesystem_path
        );
        if (err) return err;
    }

    for (size_t i = 0; i < dirs.count; i++) {
        err = privilege_collect_label(
            &labels,
            dirs.entries[i]->storage_path,
            dirs.entries[i]->filesystem_path
        );
        if (err) return err;
    }

    for (size_t i = 0; i < file_orphans.count; i++) {
        err = privilege_collect_label(
            &labels,
            file_orphans.entries[i]->storage_path,
            file_orphans.entries[i]->filesystem_path
        );
        if (err) return err;
    }

    for (size_t i = 0; i < dir_orphans.count; i++) {
        err = privilege_collect_label(
            &labels,
            dir_orphans.entries[i]->storage_path,
            dir_orphans.entries[i]->filesystem_path
        );
        if (err) return err;
    }

    return privilege_ensure_for_operation(
        (const char *const *) labels.items, labels.count, "apply",
        true,  /* interactive: prompt user if elevation needed */
        ctx->argc, ctx->argv, out
    );
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
    output_t *out = ctx->out;

    /* Declare all resources at the top, initialized to NULL/zero */
    error_t *err = NULL;
    state_t *state = ctx->state;                /* Borrowed from dispatcher (WRITE) */
    scope_t *scope = NULL;
    workspace_t *ws = NULL;
    deploy_plan_t *plan = NULL;                 /* Rows borrow from ws; free before ws */
    ptr_array_t reassigned = { 0 };             /* In-scope items with profile_changed (borrowed) */
    workspace_items_t file_orphans = { 0 };     /* heap-allocated entries (must free) */
    workspace_items_t dir_orphans = { 0 };      /* heap-allocated entries (must free) */
    workspace_items_t excluded_orphans = { 0 }; /* heap-allocated entries (must free) */
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
     * validates the CLI filter, harvests custom targets from the active
     * set, builds the path filter, and deep-copies excludes. */
    output_print(out, OUTPUT_VERBOSE, "Loading profiles...\n");

    scope_inputs_t scope_inputs = {
        .profiles         = opts->profiles,
        .profile_count    = opts->profile_count,
        .files            = opts->files,
        .file_count       = opts->file_count,
        .exclude_patterns = opts->exclude_patterns,
        .exclude_count    = opts->exclude_count,
    };
    err = scope_build(
        repo, state, &scope_inputs, config, ctx->mounts, ctx->arena, &scope
    );
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
        size_t filter_count = pathspec_count(scope_paths(scope));
        output_print(
            out, OUTPUT_VERBOSE, "\nFile filter: %zu file%s specified\n",
            filter_count, filter_count == 1 ? "" : "s"
        );
    }

    /* Load workspace (partitions active state rows and runs divergence analysis)
     *
     * After workspace_load returns, workspace_files(ws) yields the in-scope
     * active slice; we use that view throughout the command instead of
     * building a separate manifest.
     *
     * Pass state handle to workspace so it analyzes within our write transaction.
     * This ensures consistency and eliminates redundant database connections.
     */
    output_print(out, OUTPUT_VERBOSE, "\nLoading workspace...\n");

    /* Apply needs file AND directory divergence (deploy_plan_build derives
     * both kinds from the divergence index — an unanalyzed kind plans as
     * clean) plus orphan detection for cleanup. */
    workspace_load_t ws_opts = {
        .analyze_files       = true,
        .analyze_orphans     = true,
        .analyze_untracked   = false,            /* Skip expensive directory scan */
        .analyze_directories = true,             /* Directory metadata convergence */
        .analyze_encryption  = false             /* Not needed for deployment */
    };
    err = workspace_load(
        repo, state, scope, config, ctx->content_cache, ctx->mounts,
        &ws_opts, ctx->arena, &ws
    );
    if (err) {
        err = error_wrap(err, "Failed to load workspace");
        goto cleanup;
    }

    /* Persist deployment-anchor advances for files verified clean via the
     * slow path. Within apply's transaction — committed atomically with
     * deployment changes. Routed through workspace_advance_anchor, so each
     * persisted update also patches the workspace's snapshot row in place —
     * downstream readers in this run see DB and memory agreeing. */
    err = workspace_flush_updates(ws);
    if (err) {
        err = error_wrap(err, "Failed to flush anchor updates");
        goto cleanup;
    }

    output_print(
        out, OUTPUT_VERBOSE, "Workspace loaded: %zu active file%s in scope\n",
        workspace_files(ws).count, workspace_files(ws).count == 1 ? "" : "s"
    );

    /* PLAN: decide once what deploy will do, from (workspace, scope).
     *
     * Every later consumer — preview, adoption, privileges, preflight, the
     * prompt, execution and the withheld report — reads this one object.
     * The workspace already computed fresh divergence for every active row;
     * the planner gates each row on scope and classifies it by deploy's
     * work predicate into pending / clean, or into one of the two
     * held-back buckets (-e, --skip-existing). */
    output_print(out, OUTPUT_VERBOSE, "\nPlanning deployment...\n");

    err = deploy_plan_build(ws, scope, opts->skip_existing, &plan);
    if (err) {
        err = error_wrap(err, "Failed to plan deployment");
        goto cleanup;
    }

    /* Per-item trace of the work the planner held back, by reason: -e for
     * both kinds, --skip-existing for files. output_print gates on the
     * verbosity level, so normal runs pay only the loop cost. */
    {
        state_files_t excluded_files = state_files_view(&plan->files.excluded);
        state_directories_t excluded_dirs = state_directories_view(&plan->directories.excluded);
        state_files_t existing_files = state_files_view(&plan->files.skipped_existing);

        for (size_t i = 0; i < excluded_files.count; i++) {
            output_print(
                out, OUTPUT_VERBOSE, "  Skipping (excluded): %s\n",
                excluded_files.entries[i]->filesystem_path
            );
        }
        for (size_t i = 0; i < excluded_dirs.count; i++) {
            output_print(
                out, OUTPUT_VERBOSE, "  Skipping (excluded): %s\n",
                excluded_dirs.entries[i]->filesystem_path
            );
        }
        for (size_t i = 0; i < existing_files.count; i++) {
            output_print(
                out, OUTPUT_VERBOSE, "  Skipping (exists): %s\n",
                existing_files.entries[i]->filesystem_path
            );
        }
    }

    output_print(
        out, OUTPUT_VERBOSE, "  %zu %s deployment (missing or divergent)\n",
        plan->files.pending.count, plan->files.pending.count == 1 ? "file needs"
                                                                  : "files need"
    );
    output_print(
        out, OUTPUT_VERBOSE, "  %zu file%s already up-to-date (skipped)\n",
        plan->files.clean.count, plan->files.clean.count == 1 ? "" : "s"
    );
    output_print(
        out, OUTPUT_VERBOSE, "  %zu %s convergence\n",
        plan->directories.pending.count,
        plan->directories.pending.count == 1 ? "tracked directory needs"
                                             : "tracked directories need"
    );
    output_print(
        out, OUTPUT_VERBOSE, "  %zu tracked director%s already converged\n",
        plan->directories.clean.count, plan->directories.clean.count == 1 ? "y" : "ies"
    );

    /* Warn if a file filter was given but matched no managed path at all
     * (held-back rows count as matched — the filter found them). */
    if (scope_has_paths(scope) && deploy_plan_row_count(plan) == 0) {
        output_warning(
            out, OUTPUT_NORMAL, "No matching files found in enabled profiles"
        );
        output_hint(
            out, OUTPUT_NORMAL, "Check if the file path is correct and profile is enabled"
        );
    }

    /* Apply-level adoption: stamp ownership for in-scope clean files that
     * dotta has never claimed.
     *
     * A clean in-scope entry with anchor.deployed_at == 0 represents a file
     * the user declared scope over (via profile enable or add/update) AND
     * that analyze_file_divergence just classified as clean — i.e.,
     * workspace_get_item returns NULL because neither the Phase 1 fast-path
     * nor the Phase 3 slow-path produced a divergence verdict. Apply is the
     * ownership moment: running it is how the user claims the in-scope set.
     * Stamping here collapses the "enable → apply on a pre-existing matching
     * file" flow to a coherent (blob, now, stat), so a later `rm file` is
     * classified as [deleted] and `update` commits the deletion.
     *
     * Independence from the earlier flush: workspace_flush_updates
     * above persists slow-path anchors for the *next* run's fast path.
     * It is not what proves this run's match — that proof comes from
     * analyze_file_divergence leaving the entry out of ws->diverged. The
     * flush preserves deployed_at by contract, so entry->anchor.deployed_at
     * here remains a valid ownership probe; DB and in-memory views are
     * kept coherent by workspace_advance_anchor.
     *
     * Placement rationale: MUST run before the nothing-to-do early exit
     * below, otherwise the canonical case (clean manifest, no orphans)
     * never reaches any anchor-writer. Adoption writes land in the open
     * transaction; the early exit's state_save and the main path's both
     * commit them.
     *
     * Write gated by !dry_run: stamping deployed_at is a write-effect that
     * contradicts dry-run's read-only ownership contract, so the
     * state_update_anchor call is skipped. Classification runs regardless,
     * so --dry-run previews "Would adopt N file(s)".
     *
     * plan->files.clean IS "in scope ∧ no work" — no gates re-derived here. */
    size_t adopted_count = 0;
    time_t adopt_now = time(NULL);
    state_files_t adoptable = state_files_view(&plan->files.clean);

    for (size_t i = 0; i < adoptable.count; i++) {
        const state_file_entry_t *file = adoptable.entries[i];

        if (file->anchor.deployed_at > 0) continue;

        if (!opts->dry_run) {
            deployment_anchor_t anchor = capture_anchor_from_disk(
                file->filesystem_path, &file->blob_oid, adopt_now
            );
            error_t *adopt_err = workspace_advance_anchor(ws, file, &anchor);
            if (adopt_err) {
                /* Non-fatal: file is correct on disk; next status's slow-path
                 * CMP_EQUAL re-seeds the witness, and the row will be
                 * re-adopted on the next apply. */
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to record adoption anchor for %s: %s",
                    file->filesystem_path, error_message(adopt_err)
                );
                error_free(adopt_err);
                continue;  /* Failed writes don't count — preview still accurate */
            }
        }
        adopted_count++;
    }
    if (adopted_count > 0) {
        output_styled(
            out, OUTPUT_NORMAL,
            opts->dry_run ? "Would adopt {yellow}%zu{reset} file%s\n"
                          : "Adopted {yellow}%zu{reset} file%s (now tracked)\n",
            adopted_count, adopted_count == 1 ? "" : "s"
        );
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
     * 2. Preflight display (show user what the run will do)
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
         * --exclude pattern land in excluded_orphans so the post-run
         * summary can report them by reason. */
        err = workspace_extract_orphans(
            ws, scope, &file_orphans, &dir_orphans, &excluded_orphans, NULL
        );
        if (err) {
            err = error_wrap(err, "Failed to extract orphans from workspace");
            goto cleanup;
        }

        /* Mirror the deployment-loop trace: for each orphan held back by
         * --exclude, emit a per-file line. output_print gates on the
         * verbosity level, so non-verbose runs pay only the loop cost. */
        for (size_t i = 0; i < excluded_orphans.count; i++) {
            output_print(
                out, OUTPUT_VERBOSE, "  Preserving orphan (excluded): %s\n",
                excluded_orphans.entries[i]->filesystem_path
            );
        }

        if (file_orphans.count > 0) {
            output_print(
                out, OUTPUT_VERBOSE, "Found %zu orphaned file%s\n",
                file_orphans.count, file_orphans.count == 1 ? "" : "s"
            );
        }
        if (dir_orphans.count > 0) {
            output_print(
                out, OUTPUT_VERBOSE, "Found %zu orphaned director%s\n",
                dir_orphans.count, dir_orphans.count == 1 ? "y" : "ies"
            );
        }

        /* Show breakdown by profile status */
        if (file_orphans.count > 0 || dir_orphans.count > 0) {
            size_t disabled_count = 0;
            size_t enabled_count = 0;

            /* Count using already-extracted orphan arrays */
            for (size_t i = 0; i < file_orphans.count; i++) {
                if (file_orphans.entries[i]->profile_enabled) {
                    enabled_count++;
                } else {
                    disabled_count++;
                }
            }
            for (size_t i = 0; i < dir_orphans.count; i++) {
                if (dir_orphans.entries[i]->profile_enabled) {
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

    /* Collect pending profile reassignments and count external-drift
     * repairs within operation scope.
     *
     * Profile reassignment (old_profile set in state) is state bookkeeping,
     * not deployment: content may be identical, so the row never enters
     * the plan — but the flag must be cleared or the workspace keeps
     * reporting the transition. Collected before the early exit so a
     * reassignment-only workspace does not loop DIRTY forever.
     *
     * DIVERGENCE_STALE is tagged inside analyze_file_divergence from the
     * persistent anchor.blob_oid vs row.blob_oid comparison — a
     * cross-invocation signal that survives status→apply sequences and
     * reports correctly even when reconcile had nothing new to repair.
     *
     * Coherent Scope: the same triplet the planner applies. */
    size_t stale_count = 0;
    size_t all_count = 0;
    const workspace_item_t *all_items = workspace_get_all_diverged(ws, &all_count);

    for (size_t i = 0; i < all_count; i++) {
        if (!scope_accepts_entry(
            scope, all_items[i].profile, all_items[i].storage_path, all_items[i].item_kind
            )) {
            continue;
        }
        if (all_items[i].divergence & DIVERGENCE_STALE) stale_count++;
        if (all_items[i].profile_changed) {
            err = ptr_array_push(&reassigned, &all_items[i]);
            if (err) {
                err = error_wrap(err, "Failed to record profile reassignment");
                goto cleanup;
            }
        }
    }

    /* Drift signal: external Git changes repaired by workspace_load's
     * reconcile, still visible in the persistent anchor/manifest.blob_oid
     * comparison. Released files are covered by the orphan-prune summary below. */
    if (stale_count > 0) {
        output_info(
            out, OUTPUT_NORMAL, "Synchronized %zu file%s from external Git changes",
            stale_count, stale_count == 1 ? "" : "s"
        );
    }

    /* Everything the plan held back, said once — above the exit below, so a
     * run whose only work was withheld still reports it, and above the
     * prompt, so consent is given with the full picture. */
    size_t withheld = print_withheld(out, plan, excluded_orphans);

    /* Nothing pends on the filesystem: acknowledge bookkeeping (if any) and
     * leave. Privilege checks, preflight, hooks and the prompt are for runs
     * that touch disk — pure state bookkeeping skips them. The save also
     * persists the reconcile + flush observations, dry-run included, as
     * status does. */
    bool no_orphans = opts->keep_orphans || (file_orphans.count == 0 && dir_orphans.count == 0);

    if (deploy_plan_is_empty(plan) && no_orphans) {
        if (reassigned.count > 0) {
            print_reassignments(out, &reassigned);
            acknowledge_reassignments(state, &reassigned, opts->dry_run, out);
        } else if (withheld > 0) {
            /* The report above named what and why; this only has to avoid
             * claiming the work was never there. */
            output_info(out, OUTPUT_NORMAL, "Nothing left to deploy");
        } else if (scope_has_filter(scope) || scope_has_paths(scope)) {
            output_info(out, OUTPUT_NORMAL, "Nothing to deploy (no pending work in scope)");
        } else {
            output_info(out, OUTPUT_NORMAL, "Nothing to deploy (workspace is clean)");
        }

        /* Commit transaction to persist stat cache updates from workspace flush */
        err = state_save(repo, state);
        if (err) {
            err = error_wrap(err, "Failed to commit state changes");
            goto cleanup;
        }

        err = NULL;
        goto cleanup;
    }

    /* Check privileges for root/ files AND directories BEFORE deployment begins
     *
     * This ensures we have required privileges upfront, preventing partial
     * deployments and cryptic mid-operation failures. Checks occur AFTER the
     * plan and the orphan slices (every path the run will touch is known) but
     * BEFORE any filesystem modification.
     *
     * Skip check if dry-run (read-only operation, no privileges needed).
     *
     * If re-exec with sudo occurs, the entire process restarts from main(),
     * and state lock is safely released before execvp() replaces the process.
     */
    if (!opts->dry_run) {
        output_print(out, OUTPUT_VERBOSE, "\nChecking privilege requirements...\n");

        err = ensure_complete_apply_privileges(
            ctx, plan, file_orphans, dir_orphans, opts, out
        );
        if (err) {
            err = error_wrap(err, "Insufficient privileges for operation");
            goto cleanup;
        }
    }

    /* Reuse the dispatcher-owned content cache for batch operations.
     *
     * The cache was populated with decrypted content during workspace
     * divergence analysis (workspace_load borrowed it from the same
     * ctx->content_cache). Subsequent operations get cache hits:
     * - Safety check for orphan removal: cache hit (already decrypted)
     * - Deploy file content:             cache hit (already decrypted)
     */
    cache = ctx->content_cache;

    /* Run pre-flight checks over the plan
     *
     * Divergence verdicts come from workspace_load's analysis (O(1) index
     * probes); the landing and writability checks are filesystem-level.
     */
    output_print(out, OUTPUT_VERBOSE, "\nRunning pre-flight checks...\n");

    deploy_options_t deploy_opts = {
        .force            = opts->force,
        .dry_run          = opts->dry_run,
        .verbose          = opts->verbose,
        .strict_ownership = config->strict_mode,
    };

    err = deploy_preflight(ws, plan, &deploy_opts, &preflight);
    if (err) {
        err = error_wrap(err, "Pre-flight checks failed");
        goto cleanup;
    }

    print_preflight_results(out, preflight);
    print_reassignments(out, &reassigned);

    /* Check for blocking findings (conflicts, blocked paths, permissions) */
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
            .orphaned_files        = file_orphans,
            .orphaned_directories  = dir_orphans,
            /* Deployment runs first, so an orphaned directory that will
             * receive one of these is not prunable — even though nothing
             * of it is on disk yet for the preview to see. */
            .deploying_files       = state_files_view(&plan->files.pending),
            .deploying_directories = state_directories_view(&plan->directories.pending),
            .preflight_violations  = NULL,        /* No preflight violations yet */
            .dry_run               = false,       /* Preflight is always read-only */
            .force                 = opts->force,
            .skip_safety_check     = false        /* Run safety check in preflight */
        };

        err = cleanup_preflight_check(&cleanup_opts, &cleanup_preflight);
        if (err) {
            err = error_wrap(err, "Cleanup preflight checks failed");
            goto cleanup;
        }

        /* Display cleanup preflight results */
        print_cleanup_preflight_results(out, cleanup_preflight);

        /* Blocking violations do not abort: safe orphans are still pruned
         * and unsafe ones skipped, which is better than doing nothing. The
         * preview above already counted the skipped files and printed the
         * remedies for them, and cleanup_execute builds its skip list from
         * the same violations — so there is nothing to add here. */
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
        char prompt[512];   /* Larger buffer for enhanced prompt */

        /* Both numbers are cleanup's, and the preview printed exactly these
         * two — so what the user consents to is what runs. NULL only under
         * --keep-orphans, where no orphan work happens at all. Directory
         * pruning can be the only pending action (no files move). */
        size_t prune_file_count = cleanup_preflight
                                ? cleanup_preflight->prunable_files->count : 0;
        size_t prune_dir_count = cleanup_preflight
                               ? cleanup_preflight->prunable_dirs->count : 0;

        /* Compose the prompt from the non-zero parts — "Deploy 2 files,
         * converge 1 tracked directory and prune 3 orphaned files?". No
         * part means every pending action is state-only reclamation (e.g.
         * an all-absent orphan set) — non-destructive, no consent needed. */
        size_t deploy_count = plan->files.pending.count;
        size_t converge_count = plan->directories.pending.count;

        char parts[4][64];
        size_t part_count = 0;
        if (deploy_count > 0) {
            snprintf(
                parts[part_count++], sizeof(parts[0]), "deploy %zu file%s",
                deploy_count, deploy_count == 1 ? "" : "s"
            );
        }
        if (converge_count > 0) {
            snprintf(
                parts[part_count++], sizeof(parts[0]), "converge %zu tracked director%s",
                converge_count, converge_count == 1 ? "y" : "ies"
            );
        }
        if (prune_file_count > 0) {
            snprintf(
                parts[part_count++], sizeof(parts[0]), "prune %zu orphaned file%s",
                prune_file_count, prune_file_count == 1 ? "" : "s"
            );
        }
        if (prune_dir_count > 0) {
            /* One verdict, said once: with a file part above, the verb
             * carries across the conjunction — "prune 2 orphaned files and
             * 2 orphaned directories" — rather than naming it twice. The
             * directory part is always last, so nothing follows to strand
             * the elided verb. */
            snprintf(
                parts[part_count++], sizeof(parts[0]), "%s%zu orphaned director%s",
                prune_file_count > 0 ? "" : "prune ",
                prune_dir_count, prune_dir_count == 1 ? "y" : "ies"
            );
        }

        if (part_count > 0) {
            /* ", " between parts, " and " before the last; four parts of
             * at most 63 bytes fit the buffer with room to spare */
            size_t off = 0;
            for (size_t i = 0; i < part_count; i++) {
                const char *sep = (i == 0) ? "" : (i + 1 == part_count) ? " and " : ", ";
                off += (size_t) snprintf(
                    prompt + off, sizeof(prompt) - off, "%s%s", sep, parts[i]
                );
            }
            snprintf(prompt + off, sizeof(prompt) - off, "?");
            prompt[0] = (char) toupper((unsigned char) prompt[0]);

            if (!output_confirm(out, prompt, false)) {
                output_info(out, OUTPUT_NORMAL, "Cancelled");
                err = NULL;  /* Not an error - user cancelled */
                goto cleanup;
            }
        }
    }

    /* Execute the plan (files-only, directories-only, or mixed — one call).
     * Reporting reads the result: outcomes, never plan counts. */
    if (!deploy_plan_is_empty(plan)) {
        if (opts->dry_run) {
            output_print(
                out, OUTPUT_VERBOSE, "\nDry-run mode - no files will be modified\n"
            );
        } else {
            output_print(out, OUTPUT_VERBOSE, "\nExecuting deployment plan...\n");
        }

        err = deploy_execute(repo, ws, plan, &deploy_opts, cache, &deploy_res);
        if (err) {
            if (deploy_res) {
                print_deploy_results(out, deploy_res, opts->dry_run);
            }
            err = error_wrap(err, "Deployment failed");
            goto cleanup;
        }

        print_deploy_results(out, deploy_res, opts->dry_run);
    } else {
        output_print(out, OUTPUT_VERBOSE, "\nNo deployment work in scope\n");
    }

    /* Record what happened (only if not dry-run): cleanup, anchors,
     * witnesses. Acknowledgements and the commit follow for both modes. */
    if (!opts->dry_run) {
        /* Prune orphaned files and remove from state (unless --keep-orphans)
         *
         * Architecture:
         * 1. cleanup_execute() prunes orphaned files from the filesystem
         * 2. For each pruned file, state_remove_file() deletes its entry from state
         * 3. State updates are surgical (DELETE operations), not full rebuilds
         *
         * This separation ensures:
         * - Clear responsibility: filesystem ops separate from state tracking
         * - Transactional safety: filesystem changes committed before state changes
         * - Incremental updates: only modified entries updated in state
         *
         * Apply is a synchronization operation - it ensures the filesystem matches
         * the declared state by both deploying new/updated files AND pruning orphaned ones.
         *
         * The --keep-orphans flag allows opting out of automatic cleanup for advanced workflows.
         */
        if (!opts->keep_orphans) {
            /* Execute cleanup: prune the orphaned files and the directories they empty */
            cleanup_result_t *cleanup_res = NULL;
            /* Preflight runs BEFORE user confirmation, so when
             * confirm_destructive is on and --force is not set, arbitrary
             * time passes while the user decides and an orphan called safe
             * could be edited in that window.
             *
             * Passing NULL here asks cleanup to decide again at deletion
             * time — which does not help: safety decides from the workspace
             * items, observed at load, so the second pass returns the first
             * pass's answers and the edited orphan is deleted either way
             * (cleanup.h). Kept only until the contract goes; closing the
             * window needs a post-consent look at the filesystem, for
             * deploy and cleanup alike. */
            bool interactive_delay = config->confirm_destructive && !opts->force;
            cleanup_options_t cleanup_opts = {
                .orphaned_files       = file_orphans,
                .orphaned_directories = dir_orphans,
                .preflight_violations = interactive_delay
                    ? NULL                            /* Stale - force fresh safety check */
                    : (cleanup_preflight ? cleanup_preflight->safety_violations : NULL),
                .dry_run              = false,        /* Dry-run handled at deployment level */
                .force                = opts->force,
                .skip_safety_check    = false         /* Run safety when preflight_violations is NULL */
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
            error_t *cleanup_err = cleanup_execute(&cleanup_opts, &cleanup_res);
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
             *   1. Profile disabled -> entry stays in state (manifest_apply_scope
             *      flipped ACTIVE -> INACTIVE during scope reconciliation)
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
            if (cleanup_res && cleanup_res->pruned_files &&
                cleanup_res->pruned_files->count > 0) {

                output_print(out, OUTPUT_VERBOSE, "\nRemoving orphaned entries from state...\n");

                for (size_t i = 0; i < cleanup_res->pruned_files->count; i++) {
                    const char *path = cleanup_res->pruned_files->items[i];

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
                    cleanup_res->pruned_files->count,
                    cleanup_res->pruned_files->count == 1 ? "y" : "ies"
                );
            }

            /* Retire reclaimed file entries (already absent from filesystem
             * — state-only outcome, same DELETE as above but no removal
             * happened or was needed) */
            if (cleanup_res && cleanup_res->reclaimed_files &&
                cleanup_res->reclaimed_files->count > 0) {

                for (size_t i = 0; i < cleanup_res->reclaimed_files->count; i++) {
                    const char *path = cleanup_res->reclaimed_files->items[i];

                    err = state_remove_file(state, path);
                    if (err) {
                        output_warning(
                            out, OUTPUT_NORMAL, "Failed to reclaim state entry for %s: %s",
                            path, error_message(err)
                        );
                        error_free(err);
                        err = NULL;  /* Don't propagate - continue operation */
                    }
                }

                output_print(
                    out, OUTPUT_VERBOSE, "  Reclaimed %zu stale state entr%s\n",
                    cleanup_res->reclaimed_files->count,
                    cleanup_res->reclaimed_files->count == 1 ? "y" : "ies"
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
             *   1. Profile disabled -> entry stays in state (manifest_sync_directories
             *      left the row LIFECYCLE_INACTIVE during scope reconciliation)
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
            if (cleanup_res && cleanup_res->pruned_dirs &&
                cleanup_res->pruned_dirs->count > 0) {

                output_print(
                    out, OUTPUT_VERBOSE, "\nRemoving orphaned directory entries from state...\n"
                );

                for (size_t i = 0; i < cleanup_res->pruned_dirs->count; i++) {
                    const char *path = cleanup_res->pruned_dirs->items[i];

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
                    cleanup_res->pruned_dirs->count,
                    cleanup_res->pruned_dirs->count == 1 ? "y" : "ies"
                );
            }

            /* Retire reclaimed directory entries (already absent — state-only) */
            if (cleanup_res && cleanup_res->reclaimed_dirs &&
                cleanup_res->reclaimed_dirs->count > 0) {

                for (size_t i = 0; i < cleanup_res->reclaimed_dirs->count; i++) {
                    const char *path = cleanup_res->reclaimed_dirs->items[i];

                    err = state_remove_directory(state, path);
                    if (err) {
                        output_warning(
                            out, OUTPUT_NORMAL,
                            "Failed to reclaim directory state entry for %s: %s",
                            path, error_message(err)
                        );
                        error_free(err);
                        err = NULL;  /* Don't propagate - continue operation */
                    }
                }

                output_print(
                    out, OUTPUT_VERBOSE, "  Reclaimed %zu stale directory entr%s\n",
                    cleanup_res->reclaimed_dirs->count,
                    cleanup_res->reclaimed_dirs->count == 1 ? "y" : "ies"
                );
            }

            cleanup_result_free(cleanup_res);
        }

        /* Advance the deployment anchor for successfully deployed files
         *
         * CRITICAL: This records disk-confirmation for each deployed file — the
         * blob dotta just wrote, the lifecycle timestamp, and the stat triple
         * used by the fast path on subsequent runs. The anchor is the
         * authoritative "dotta confirmed disk == this blob" record.
         *
         * IMPORTANT: This operation runs REGARDLESS of cleanup success/failure.
         * - Deployment succeeded (files are physically on filesystem)
         * - State must reflect deployment success
         * - Cleanup failure does NOT invalidate deployment success
         * - This prevents state desynchronization (deployed files marked as undeployed)
         *
         * Non-critical operation: deployment already succeeded physically, so
         * anchor advance failures are non-fatal warnings (preserve consistency).
         */
        state_files_t deployed = deploy_res ? state_files_view(&deploy_res->deployed)
                                            : (state_files_t){ 0 };
        if (deployed.count > 0) {
            time_t now = time(NULL);

            output_print(out, OUTPUT_VERBOSE, "\nUpdating deployment anchors...\n");

            for (size_t i = 0; i < deployed.count; i++) {
                const state_file_entry_t *file = deployed.entries[i];

                /* Snapshot disk state (mtime/size/ino) for the fast path.
                 * The file was just written and fsynced by deploy_file(); lstat()
                 * is a cheap inode-cache read. If lstat fails, the anchor is still
                 * advanced with a zero stat (slow-path fallback on next run). */
                deployment_anchor_t anchor = capture_anchor_from_disk(
                    file->filesystem_path, &file->blob_oid, now
                );

                err = workspace_advance_anchor(ws, file, &anchor);
                if (err) {
                    /* Non-fatal warning - deployment succeeded, just anchor update failed.
                     * The file is already on the filesystem with correct content.
                     * Failure here should not abort the entire operation. */
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to update anchor for %s: %s",
                        file->filesystem_path, error_message(err)
                    );
                    error_free(err);
                    err = NULL;  /* Don't propagate - continue operation */
                }
            }

            output_print(
                out, OUTPUT_VERBOSE, "  Updated %zu anchor%s\n",
                deployed.count, deployed.count == 1 ? "" : "s"
            );
        }

        /* Advance the witness for directories this apply materialized
         *
         * Sibling of the file anchor loop above. deploy_execute just
         * created/confirmed the planned directories (and, as parents of
         * written files, possibly others); the load-time flush only
         * covered directories present at load. Presence is the witness,
         * so this walks the active slice rather than the result; SQL
         * enforces monotonicity, so it is idempotent and never regresses
         * a stamp. Non-fatal on failure, mirroring anchor-advance failures. */
        {
            state_directories_t dirs = workspace_directories(ws);
            time_t dir_now = time(NULL);

            for (size_t i = 0; i < dirs.count; i++) {
                const state_directory_entry_t *dir = dirs.entries[i];

                if (dir->observed_at > 0) continue;

                /* lstat semantics, matching the analyzer's probe: a path of
                 * any type counts as observed (a squatting file is still
                 * "something was here"; type divergence is a separate
                 * signal). fs_exists would follow a final symlink and
                 * witness a path that is not the one being tracked. */
                if (!fs_lexists(dir->filesystem_path)) continue;

                error_t *werr = workspace_advance_witness(ws, dir, dir_now);
                if (werr) {
                    output_warning(
                        out, OUTPUT_NORMAL,
                        "Failed to advance witness for %s: %s",
                        dir->filesystem_path, error_message(werr)
                    );
                    error_free(werr);
                }
            }
        }
    }

    /* Acknowledge profile reassignments (clear old_profile in state).
     * When content also diverged the file was redeployed above; either
     * way the transition must not persist across runs. Dry-run previews. */
    acknowledge_reassignments(state, &reassigned, opts->dry_run, out);

    /* Commit the state transaction: anchors, witnesses, removed orphan
     * entries, cleared reassignments (partial success model — a cleanup
     * failure leaves deployment state to commit). Dry-run included: the
     * transaction then holds only the load-time reconcile + flush
     * observations, which status and the nothing-to-do exit persist too. */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to commit state changes");
        goto cleanup;
    }

    /* Execute post-apply hook */
    hook_fire_post(config, out, ctx->repo_path, &hook_inv);

    /* Success - fall through to cleanup */
    err = NULL;

cleanup:
    /* Result and plan buckets borrow rows from the workspace arena — free
     * them before workspace_free. reassigned borrows into the diverged array. */
    if (deploy_res) deploy_result_free(deploy_res);
    if (plan) deploy_plan_free(plan);
    ptr_array_deinit(&reassigned);
    if (cleanup_preflight) cleanup_preflight_result_free(cleanup_preflight);
    if (preflight) preflight_result_free(preflight);
    if (profiles_str) free(profiles_str);
    /* workspace_extract_orphans hands us heap-allocated buffers (per
     * ptr_array_steal). Items inside borrow into the workspace's diverged
     * array — only the entries buffer is ours to free. */
    free((void *) excluded_orphans.entries);
    free((void *) dir_orphans.entries);
    free((void *) file_orphans.entries);
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
        "Skip matching paths (no deploy)"
    ),
    ARGS_FLAG(
        "f force",
        cmd_apply_options_t,force,
        "Overwrite modified files and replace type conflicts"
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
        "Skip files whose path is already occupied"
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
    .name        = "apply",
    .summary     = "Deploy enabled profiles to the filesystem",
    .usage       = "%s apply [options] [profile|file]...",
    .description =
        "Converge the filesystem with enabled profiles: deploy new and\n"
        "updated files, prune files orphaned by disabled profiles, and\n"
        "update the deployment state.\n",
    .notes       =
        "Exclusion Patterns:\n"
        "  Excluded paths are protected from deployment, directory\n"
        "  convergence and pruning. Patterns follow gitignore glob syntax;\n"
        "  a trailing slash restricts a pattern to directories. Repeatable.\n",
    .examples    =
        "  %s apply                            # Deploy all enabled profiles\n"
        "  %s apply --force                    # Force overwrite of modifications\n"
        "  %s apply -p work                    # Filter to 'work' profile\n"
        "  %s apply -p work ~/.bashrc          # Profile + file filter\n"
        "  %s apply ~/.bashrc ~/.zshrc         # Deploy specific files only\n"
        "  %s apply -n                         # Preview without writing\n"
        "  %s apply --exclude 'home/.ssh/*'    # Protect matched files\n",
    .epilogue    =
        "See also:\n"
        "  %s status          # Preview pending deployment\n"
        "  %s update          # Commit filesystem changes back\n"
        "  %s profile enable  # Stage a profile for deployment\n",
    .opts_size   = sizeof(cmd_apply_options_t),
    .opts        = apply_opts,
    .classify    = apply_classify,
    .payload     = &dotta_ext_write_crypto,
    .dispatch    = apply_dispatch,
};
