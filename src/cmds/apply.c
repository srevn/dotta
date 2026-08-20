/**
 * apply.c - Apply profiles to filesystem
 */

#include "cmds/apply.h"

#include <config.h>
#include <ctype.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "core/cleanup.h"
#include "core/deploy.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "sys/filesystem.h"
#include "utils/hooks.h"
#include "utils/privilege.h"

/**
 * Print deploy pre-flight results
 */
static void print_deploy_preflight_results(
    const output_t *out,
    const deploy_preflight_result_t *result
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
 * @param deploy_plan Deployment plan (must not be NULL)
 * @param cleanup_plan Cleanup plan, whose `excluded` bucket carries the
 *        orphans an -e pattern spared (must not be NULL)
 * @return Paths withheld, both reasons together
 */
static size_t print_withheld(
    const output_t *out,
    const deploy_plan_t *deploy_plan,
    const cleanup_plan_t *cleanup_plan
) {
    /* -e reaches all three kinds, so its summary counts "paths"; the
     * verbose breakdown names each kind and what it was spared. */
    workspace_items_t excluded_orphans = workspace_items_view(&cleanup_plan->excluded);
    size_t excluded_orphan_files = 0;
    size_t excluded_orphan_dirs = 0;

    for (size_t i = 0; i < excluded_orphans.count; i++) {
        if (excluded_orphans.entries[i]->item_kind == PATH_KIND_DIRECTORY) {
            excluded_orphan_dirs++;
        } else {
            excluded_orphan_files++;
        }
    }

    size_t excluded = deploy_plan->files.excluded.count +
        deploy_plan->directories.excluded.count + excluded_orphans.count;

    if (excluded > 0) {
        if (output_is_verbose(out)) {
            output_print(
                out, OUTPUT_VERBOSE, "Skipped %zu path%s (--exclude):\n",
                excluded, excluded == 1 ? "" : "s"
            );
            if (deploy_plan->files.excluded.count > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  • %zu divergent file%s not deployed\n",
                    deploy_plan->files.excluded.count,
                    deploy_plan->files.excluded.count == 1 ? "" : "s"
                );
            }
            if (deploy_plan->directories.excluded.count > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  • %zu tracked director%s not converged\n",
                    deploy_plan->directories.excluded.count,
                    deploy_plan->directories.excluded.count == 1 ? "y" : "ies"
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
    size_t existing = deploy_plan->files.skipped_existing.count;
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
 * results; this function handles all presentation — the run's receipt,
 * per-item sections at verbose and summary counts at normal. Every number
 * is a bucket size: deploy bucketed the plan by outcome and this reads
 * that partition, adding nothing of its own.
 *
 * Categories (each semantically distinct):
 * - deployed: Files written to disk (green)
 * - created / fixed / replaced: Tracked directories, by what the executor
 *   found at the path — one line each, so the squatter --force displaced
 *   is named at every verbosity (green; the replaced count yellow, as
 *   cleanup colours a removal)
 *
 * The verb is execution truth; the tags are plan truth. A fixed row is
 * tagged [mode] / [ownership] from the workspace's divergence index —
 * why the planner chose it — never from a fresh stat: the run has just
 * converged the directory, so disk would say nothing. A pending row the
 * planner chose on its own verdict has an indexed item
 * (deploy_needs_work(NULL) is false); one planned as absent beneath a
 * squatted directory may have none, and is created rather than fixed.
 * A fixed row whose item carries neither bit, or no item, prints no tag,
 * and the other two buckets never carry one, since the verb already says
 * what the path held.
 *
 * Mode and ownership print as recorded on the row, corruption included:
 * a mode-0 row shows (mode: 0000) under the stderr warning that named
 * the substitution. The receipt reports the row, the warning reports the
 * repair. A symlink row records no mode by design and says so instead.
 *
 * Work the run held back is not here: the plan decided it, print_withheld
 * reports it, and it must be said even on runs that never execute. Nor
 * is a failure: fail-stop returns the error naming the path, and
 * cmd_apply prints the partial receipt ahead of it.
 *
 * Adoption (ownership stamping for pre-existing matching files) is an
 * apply-level concern and its summary is printed by cmd_apply directly.
 */
static void print_deploy_results(
    const output_t *out,
    const workspace_t *ws,
    const deploy_result_t *result,
    bool dry_run
) {
    if (!result) return;

    state_files_t deployed = state_files_view(&result->deployed);
    state_directories_t created = state_directories_view(&result->created);
    state_directories_t fixed = state_directories_view(&result->fixed);
    state_directories_t replaced = state_directories_view(&result->replaced);

    /* Verbose mode: show individual items per outcome */
    if (deployed.count > 0) {
        output_section(
            out, OUTPUT_VERBOSE, dry_run ? "Would deploy files"
                                         : "Deployed files"
        );
        for (size_t i = 0; i < deployed.count; i++) {
            const state_file_entry_t *file = deployed.entries[i];

            if (file->type == STATE_FILE_SYMLINK) {
                output_styled(
                    out, OUTPUT_VERBOSE, "  {green}✓{reset} %s (symlink)\n",
                    file->filesystem_path
                );
                continue;
            }

            output_styled(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %s (mode: %04o",
                file->filesystem_path, file->mode
            );
            if (file->owner || file->group) {
                output_print(
                    out, OUTPUT_VERBOSE, ", owner: %s:%s",
                    file->owner ? file->owner : "?", file->group ? file->group : "?"
                );
            }
            output_print(out, OUTPUT_VERBOSE, ")\n");
        }
    }

    if (created.count > 0) {
        output_section(
            out, OUTPUT_VERBOSE, dry_run ? "Would create tracked directories"
                                         : "Created tracked directories"
        );
        for (size_t i = 0; i < created.count; i++) {
            const state_directory_entry_t *dir = created.entries[i];

            output_styled(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %s (mode: %04o",
                dir->filesystem_path, dir->mode
            );
            if (dir->owner || dir->group) {
                output_print(
                    out, OUTPUT_VERBOSE, ", owner: %s:%s",
                    dir->owner ? dir->owner : "?", dir->group ? dir->group : "?"
                );
            }
            output_print(out, OUTPUT_VERBOSE, ")\n");
        }
    }

    if (fixed.count > 0) {
        output_section(
            out, OUTPUT_VERBOSE, dry_run ? "Would fix tracked directories"
                                         : "Fixed tracked directories"
        );
        for (size_t i = 0; i < fixed.count; i++) {
            const state_directory_entry_t *dir = fixed.entries[i];

            output_styled(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %s (mode: %04o",
                dir->filesystem_path, dir->mode
            );
            if (dir->owner || dir->group) {
                output_print(
                    out, OUTPUT_VERBOSE, ", owner: %s:%s",
                    dir->owner ? dir->owner : "?", dir->group ? dir->group : "?"
                );
            }
            output_print(out, OUTPUT_VERBOSE, ")");

            /* What was fixed: the divergence the planner saw */
            const workspace_item_t *item = workspace_get_item(ws, dir->filesystem_path);
            bool mode_differs = item && (item->divergence & DIVERGENCE_MODE);
            bool ownership_differs = item && (item->divergence & DIVERGENCE_OWNERSHIP);

            if (mode_differs || ownership_differs) {
                output_print(
                    out, OUTPUT_VERBOSE, " [%s%s%s]", mode_differs ? "mode" : "",
                    (mode_differs && ownership_differs) ? ", " : "",
                    ownership_differs ? "ownership" : ""
                );
            }
            output_print(out, OUTPUT_VERBOSE, "\n");
        }
    }

    if (replaced.count > 0) {
        output_section(
            out, OUTPUT_VERBOSE, dry_run ? "Would replace tracked directories"
                                         : "Replaced tracked directories"
        );
        for (size_t i = 0; i < replaced.count; i++) {
            const state_directory_entry_t *dir = replaced.entries[i];

            output_styled(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %s (mode: %04o",
                dir->filesystem_path, dir->mode
            );
            if (dir->owner || dir->group) {
                output_print(
                    out, OUTPUT_VERBOSE, ", owner: %s:%s",
                    dir->owner ? dir->owner : "?", dir->group ? dir->group : "?"
                );
            }
            output_print(out, OUTPUT_VERBOSE, ")\n");
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

        if (created.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                dry_run ? "Would create {green}%zu{reset} tracked director%s\n"
                        : "Created {green}%zu{reset} tracked director%s\n",
                created.count, created.count == 1 ? "y" : "ies"
            );
        }

        if (fixed.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                dry_run ? "Would fix {green}%zu{reset} tracked director%s\n"
                        : "Fixed {green}%zu{reset} tracked director%s\n",
                fixed.count, fixed.count == 1 ? "y" : "ies"
            );
        }

        if (replaced.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                dry_run ? "Would replace {yellow}%zu{reset} tracked director%s\n"
                        : "Replaced {yellow}%zu{reset} tracked director%s\n",
                replaced.count, replaced.count == 1 ? "y" : "ies"
            );
        }
    }
}

/**
 * Print cleanup results
 *
 * The run's receipt: per-item sections at verbose, summary counts at
 * normal. Every number is a bucket size — cleanup partitioned the plan and
 * this reads that partition, adding nothing of its own.
 */
static void print_cleanup_results(
    const output_t *out,
    const cleanup_result_t *result
) {
    if (!result) return;

    workspace_items_t pruned_files = workspace_items_view(&result->pruned_files);
    workspace_items_t reclaimed_files = workspace_items_view(&result->reclaimed_files);
    workspace_items_t released_files = workspace_items_view(&result->released_files);
    workspace_items_t skipped_files = workspace_items_view(&result->skipped_files);
    workspace_items_t failed_files = workspace_items_view(&result->failed_files);
    workspace_items_t pruned_dirs = workspace_items_view(&result->pruned_dirs);
    workspace_items_t reclaimed_dirs = workspace_items_view(&result->reclaimed_dirs);
    workspace_items_t skipped_dirs = workspace_items_view(&result->skipped_dirs);
    workspace_items_t failed_dirs = workspace_items_view(&result->failed_dirs);

    /* Verbose mode: show individual items per outcome */
    if (pruned_files.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Pruned orphaned files");
        for (size_t i = 0; i < pruned_files.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}[pruned]{reset} %s\n",
                pruned_files.entries[i]->filesystem_path
            );
        }
    }

    if (reclaimed_files.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Reclaimed orphaned files (already absent)");
        for (size_t i = 0; i < reclaimed_files.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[reclaimed]{reset} %s\n",
                reclaimed_files.entries[i]->filesystem_path
            );
        }
    }

    /* Each skipped file's reason was named by the preview's skipped-files
     * block, which always prints; the receipt only confirms the skip. */
    if (skipped_files.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Skipped orphaned files (uncommitted changes)");
        for (size_t i = 0; i < skipped_files.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}[skipped]{reset} %s\n",
                skipped_files.entries[i]->filesystem_path
            );
        }
    }

    if (released_files.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Released files (no longer in Git)");
        for (size_t i = 0; i < released_files.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[released]{reset} %s\n",
                released_files.entries[i]->filesystem_path
            );
        }
    }

    if (failed_files.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Failed to prune orphaned files");
        for (size_t i = 0; i < failed_files.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {red}[failed]{reset} %s\n",
                failed_files.entries[i]->filesystem_path
            );
        }
    }

    if (pruned_dirs.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Pruned orphaned directories");
        for (size_t i = 0; i < pruned_dirs.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}[pruned]{reset} %s\n",
                pruned_dirs.entries[i]->filesystem_path
            );
        }
    }

    if (reclaimed_dirs.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Reclaimed orphaned directories (already absent)");
        for (size_t i = 0; i < reclaimed_dirs.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[reclaimed]{reset} %s\n",
                reclaimed_dirs.entries[i]->filesystem_path
            );
        }
    }

    if (skipped_dirs.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Skipped orphaned directories (not empty)");
        for (size_t i = 0; i < skipped_dirs.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}[skipped]{reset} %s\n",
                skipped_dirs.entries[i]->filesystem_path
            );
        }
    }

    if (failed_dirs.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Failed to prune orphaned directories");
        for (size_t i = 0; i < failed_dirs.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {red}[failed]{reset} %s\n",
                failed_dirs.entries[i]->filesystem_path
            );
        }
    }

    /* Non-verbose: summary counts only. */
    if (!output_is_verbose(out)) {
        if (pruned_files.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Pruned {yellow}%zu{reset} orphaned file%s\n",
                pruned_files.count, pruned_files.count == 1 ? "" : "s"
            );
        }

        if (pruned_dirs.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Pruned {yellow}%zu{reset} orphaned director%s\n",
                pruned_dirs.count, pruned_dirs.count == 1 ? "y" : "ies"
            );
        }

        /* State-only outcomes: rows retired for paths already absent from
         * the filesystem. Reported separately from "Pruned" — no removal
         * happened or was needed. */
        size_t reclaimed = reclaimed_files.count + reclaimed_dirs.count;

        if (reclaimed > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "Reclaimed {cyan}%zu{reset} stale state entr%s (absent from filesystem)\n",
                reclaimed, reclaimed == 1 ? "y" : "ies"
            );
        }

        if (released_files.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Released {cyan}%zu{reset} file%s from management\n",
                released_files.count, released_files.count == 1 ? "" : "s"
            );
        }

        /* No remedy hints here: the preview's skipped-files block named
         * these files, their reasons and the three ways out, and it always
         * prints — including on the run that reports this line. */
        if (skipped_files.count > 0) {
            output_warning(
                out, OUTPUT_NORMAL, "Skipped %zu orphaned file%s (uncommitted changes)",
                skipped_files.count, skipped_files.count == 1 ? "" : "s"
            );
        }

        if (skipped_dirs.count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Skipped %zu orphaned director%s (not empty)",
                skipped_dirs.count, skipped_dirs.count == 1 ? "y" : "ies"
            );
            output_info(
                out, OUTPUT_NORMAL, "Use --verbose to see which directories were skipped."
            );
        }

        size_t failed = failed_files.count + failed_dirs.count;

        if (failed > 0) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to prune %zu item%s",
                failed, failed == 1 ? "" : "s"
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
    const ptr_array_t *bucket,
    output_color_t color,
    const char *glyph
) {
    const size_t limit = 20;   /* Don't flood the terminal */
    workspace_items_t items = workspace_items_view(bucket);
    size_t shown = items.count < limit ? items.count : limit;

    for (size_t i = 0; i < shown; i++) {
        output_colored(out, OUTPUT_VERBOSE, color, "    %s", glyph);
        output_print(out, OUTPUT_VERBOSE, " %s\n", items.entries[i]->filesystem_path);
    }

    if (items.count > limit) {
        output_print(
            out, OUTPUT_VERBOSE, "    ... and %zu more\n", items.count - limit
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
 *
 * The summaries only count the files the run will not prune; the two
 * blocks at the end name them, with different messaging: the skipped ones
 * with their reason and the remedies, where the user has to act, and the
 * released ones, where nothing is asked. Cleanup took that split when it
 * bucketed each file; this is display, so it counts nothing and only
 * routes per item. They come last, so that guidance is what the user is
 * looking at when the confirmation prompt arrives.
 */
static void print_cleanup_preflight_results(
    const output_t *out,
    const cleanup_preflight_result_t *verdicts
) {
    if (!verdicts) return;

    workspace_items_t skipped = workspace_items_view(&verdicts->skipped_files);
    workspace_items_t released = workspace_items_view(&verdicts->released_files);

    /* Every planned item lands in exactly one bucket, so these are the
     * present-orphan counts and the state-only count. */
    size_t present_files = verdicts->prunable_files.count + skipped.count + released.count;
    size_t present_dirs = verdicts->prunable_dirs.count + verdicts->skipped_dirs.count;

    size_t absent = verdicts->absent_files.count + verdicts->absent_dirs.count;

    /* An empty plan — no orphans in scope, --keep-orphans — has nothing
     * to say, and says nothing. */
    if (present_files + present_dirs + absent == 0) {
        return;
    }

    if (present_files > 0) {
        output_section(out, OUTPUT_NORMAL, "Orphaned files");

        if (verdicts->prunable_files.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {yellow}%zu{reset} file%s will be pruned (no longer active)\n",
                verdicts->prunable_files.count,
                verdicts->prunable_files.count == 1 ? "" : "s"
            );
        }

        if (released.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {cyan}%zu{reset} file%s will be released from management\n",
                released.count,
                released.count == 1 ? "" : "s"
            );
        }

        if (skipped.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {yellow}%zu{reset} file%s will be skipped (uncommitted changes)\n",
                skipped.count,
                skipped.count == 1 ? "" : "s"
            );
        }

        /* Only the files the count above promises — the skipped and
         * released ones are named, with their reasons, below. */
        print_path_list(out, &verdicts->prunable_files, OUTPUT_COLOR_CYAN, "•");
    }

    if (present_dirs > 0) {
        output_section(out, OUTPUT_NORMAL, "Orphaned directories");

        if (verdicts->prunable_dirs.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "  {cyan}%zu{reset} director%s will be pruned\n",
                verdicts->prunable_dirs.count,
                verdicts->prunable_dirs.count == 1 ? "y" : "ies"
            );
        }

        if (verdicts->skipped_dirs.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "  {yellow}%zu{reset} director%s will be skipped (not empty)\n",
                verdicts->skipped_dirs.count,
                verdicts->skipped_dirs.count == 1 ? "y" : "ies"
            );
        }

        print_path_list(out, &verdicts->prunable_dirs, OUTPUT_COLOR_CYAN, "•");
        print_path_list(out, &verdicts->skipped_dirs, OUTPUT_COLOR_YELLOW, "⊘");
    }

    if (absent > 0) {
        /* A state effect with no filesystem effect, said here so the dry run and the
         * real run agree — the receipt reports it as "Reclaimed N stale state entries".
         * Not indented under a section: it may be the only thing cleanup has to say. */
        if (present_files + present_dirs > 0) {
            output_newline(out, OUTPUT_NORMAL);
        }
        output_styled(
            out, OUTPUT_NORMAL, "{cyan}%zu{reset} stale state entr%s will be reclaimed\n",
            absent, absent == 1 ? "y" : "ies"
        );
    }

    /* Skipped files: the user has to act, so each is named with its reason
     * and the three ways out follow. */
    if (skipped.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Modified orphaned files detected");
        output_newline(out, OUTPUT_NORMAL);

        output_warning(
            out, OUTPUT_NORMAL, "The following files cannot be safely removed:"
        );

        /* First skipped file's profile drives the example commands */
        const char *example_profile = NULL;

        for (size_t i = 0; i < skipped.count; i++) {
            const workspace_item_t *item = skipped.entries[i];

            if (!example_profile && item->profile) {
                example_profile = item->profile;
            }

            /* How the reason reads on screen. The reason itself is
             * cleanup's (cleanup_skip_reason); this only names it — red
             * where the file's own content or type has moved away from what
             * dotta deployed, yellow where dotta simply cannot vouch for it. */
            const char *glyph = "•";
            const char *label = "skipped";
            output_color_t color = OUTPUT_COLOR_YELLOW;

            switch (cleanup_skip_reason(item)) {
                case CLEANUP_SKIP_MODIFIED:
                    glyph = "✗";
                    label = "modified";
                    color = OUTPUT_COLOR_RED;
                    break;
                case CLEANUP_SKIP_TYPE_CHANGED:
                    glyph = "⚠";
                    label = "type changed";
                    color = OUTPUT_COLOR_RED;
                    break;
                case CLEANUP_SKIP_MODE_CHANGED:
                    glyph = "⚠";
                    label = "permissions changed";
                    break;
                case CLEANUP_SKIP_UNVERIFIED:
                    glyph = "?";
                    label = "cannot verify";
                    break;
                case CLEANUP_SKIP_NONE:
                    /* Unreachable: a file is in skipped_files because a reason names it */
                    break;
            }

            output_colored(out, OUTPUT_NORMAL, color, "  %s", glyph);
            output_print(out, OUTPUT_NORMAL, " %s ", item->filesystem_path);

            if (item->profile) {
                output_colored(out, OUTPUT_NORMAL, color, "(%s from ", label);
                output_styled(out, OUTPUT_NORMAL, "{cyan}%s{reset}", item->profile);
                output_colored(out, OUTPUT_NORMAL, color, ")\n");
            } else {
                output_colored(out, OUTPUT_NORMAL, color, "(%s)\n", label);
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
        output_hintline(out, OUTPUT_NORMAL, "     dotta apply --force <files>");
        output_hintline(out, OUTPUT_NORMAL, "  3. Keep the profile enabled:");
        if (example_profile) {
            output_hintline(out, OUTPUT_NORMAL, "     dotta profile enable %s", example_profile);
        } else {
            output_hintline(out, OUTPUT_NORMAL, "     dotta profile enable <profile>");
        }
    }

    /* Released files are informational: nothing is asked of the user, and
     * --force does not change their fate (see cleanup.h). */
    if (released.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Released files");
        output_info(
            out, OUTPUT_NORMAL,
            "The following files are no longer in their profile's Git branch:"
        );

        for (size_t i = 0; i < released.count; i++) {
            const workspace_item_t *item = released.entries[i];

            output_styled(out, OUTPUT_NORMAL, "  {cyan}→{reset} %s", item->filesystem_path);
            if (item->profile) {
                output_styled(out, OUTPUT_NORMAL, " {dim}(from %s){reset}", item->profile);
            }
            output_newline(out, OUTPUT_NORMAL);
        }

        output_info(
            out, OUTPUT_NORMAL,
            "These files will be left on the filesystem and released from management."
        );
    }

    output_newline(out, OUTPUT_NORMAL);
}

/**
 * Check privileges for complete apply operation
 *
 * Examines the deployment plan's pending files and directories (deployed /
 * converged) plus the file and directory orphans being removed, for root/
 * paths. This ensures we have required privileges BEFORE attempting any
 * filesystem modifications — and, reading the plans, it is exact by
 * construction: parents deploy creates on the way are prefixes of planned
 * paths, so a planned path's own label already covers them.
 *
 * @param ctx Command context (must not be NULL)
 * @param deploy_plan Deployment plan (must not be NULL)
 * @param cleanup_plan Orphans the run may remove; the present ones are
 *        checked (must not be NULL — empty under --keep-orphans)
 * @param opts Apply command options (must not be NULL)
 * @param out Output context for messages (must not be NULL)
 * @return NULL if OK to proceed, error otherwise (or does not return if re-exec with sudo)
 */
static error_t *ensure_complete_apply_privileges(
    const dotta_ctx_t *ctx,
    const deploy_plan_t *deploy_plan,
    const cleanup_plan_t *cleanup_plan,
    const cmd_apply_options_t *opts,
    output_t *out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(deploy_plan);
    CHECK_NULL(cleanup_plan);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    if (opts->dry_run) {
        return NULL;  /* Read-only operation, no privileges needed */
    }

    state_files_t files = state_files_view(&deploy_plan->files.pending);
    state_directories_t dirs = state_directories_view(&deploy_plan->directories.pending);

    workspace_items_t file_orphans = workspace_items_view(&cleanup_plan->files);
    workspace_items_t dir_orphans = workspace_items_view(&cleanup_plan->directories);

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

    /* An orphan already gone from disk is a state-only reclaim: no
     * filesystem effect, so no elevation. The released and skipped ones
     * are an accepted over-approximation — their verdicts are taken after
     * this check runs, and being ready to touch a path the run then leaves
     * alone costs nothing. */
    for (size_t i = 0; i < file_orphans.count; i++) {
        const workspace_item_t *item = file_orphans.entries[i];

        if (!item->on_filesystem) continue;

        err = privilege_collect_label(&labels, item->storage_path, item->filesystem_path);
        if (err) return err;
    }

    for (size_t i = 0; i < dir_orphans.count; i++) {
        const workspace_item_t *item = dir_orphans.entries[i];

        if (!item->on_filesystem) continue;

        err = privilege_collect_label(&labels, item->storage_path, item->filesystem_path);
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
    deploy_plan_t *deploy_plan = NULL;          /* Rows borrow from ws; free before ws */
    cleanup_plan_t *cleanup_plan = NULL;        /* Items borrow from ws; free before ws */
    ptr_array_t reassigned = { 0 };             /* In-scope items with profile_changed (borrowed) */
    deploy_preflight_result_t *deploy_findings = NULL;
    cleanup_preflight_result_t *cleanup_verdicts = NULL;
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

    err = deploy_plan_build(ws, scope, opts->skip_existing, &deploy_plan);
    if (err) {
        err = error_wrap(err, "Failed to plan deployment");
        goto cleanup;
    }

    /* Per-item trace of the work the planner held back, by reason: -e for
     * both kinds, --skip-existing for files. output_print gates on the
     * verbosity level, so normal runs pay only the loop cost. */
    {
        state_files_t excluded_files = state_files_view(
            &deploy_plan->files.excluded
        );
        state_directories_t excluded_dirs = state_directories_view(
            &deploy_plan->directories.excluded
        );
        state_files_t existing_files = state_files_view(
            &deploy_plan->files.skipped_existing
        );

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
        deploy_plan->files.pending.count,
        deploy_plan->files.pending.count == 1 ? "file needs" : "files need"
    );
    output_print(
        out, OUTPUT_VERBOSE, "  %zu file%s already up-to-date (skipped)\n",
        deploy_plan->files.clean.count,
        deploy_plan->files.clean.count == 1 ? "" : "s"
    );
    output_print(
        out, OUTPUT_VERBOSE, "  %zu %s convergence\n",
        deploy_plan->directories.pending.count,
        deploy_plan->directories.pending.count == 1 ? "tracked directory needs"
                                                    : "tracked directories need"
    );
    output_print(
        out, OUTPUT_VERBOSE, "  %zu tracked director%s already converged\n",
        deploy_plan->directories.clean.count,
        deploy_plan->directories.clean.count == 1 ? "y" : "ies"
    );

    /* PLAN: decide once which orphans cleanup may touch, from (workspace,
     * scope).
     *
     * Coherent Scope — the same operation-scope triplet the deployment
     * planner applies: orphans outside the profile / path dimensions are
     * invisible; orphans an -e pattern names are held back and reported.
     * The filter shapes that reach the planner:
     *
     *   full sync (no filter)   every orphan converges — a disabled
     *                           profile's files, and files deleted from
     *                           Git under a profile that is still enabled
     *   profile scoped (-p)     only that profile's orphans; the rest wait
     *                           for an unfiltered apply
     *   path scoped             only the orphans the filter names — the
     *                           orphan at a file path, the orphans beneath
     *                           a directory path — so one orphan can be
     *                           retired without a whole-scope run. The
     *                           filter changes reach, never verdicts: a
     *                           modified orphan named by path is still
     *                           skipped, a released one still let go.
     *
     * --keep-orphans plans nothing. The empty plan is what every later
     * stage reads, so no stage re-encodes the flag. */
    output_print(out, OUTPUT_VERBOSE, "\nPlanning cleanup...\n");

    err = cleanup_plan_build(ws, scope, opts->keep_orphans, &cleanup_plan);
    if (err) {
        err = error_wrap(err, "Failed to plan cleanup");
        goto cleanup;
    }

    if (opts->keep_orphans) {
        output_print(out, OUTPUT_VERBOSE, "  Orphans kept (--keep-orphans)\n");
    }

    /* Mirror the deployment-loop trace: for each orphan held back by
     * --exclude, emit a per-file line. output_print gates on the
     * verbosity level, so non-verbose runs pay only the loop cost. */
    {
        workspace_items_t excluded_orphans = workspace_items_view(&cleanup_plan->excluded);

        for (size_t i = 0; i < excluded_orphans.count; i++) {
            output_print(
                out, OUTPUT_VERBOSE, "  Preserving orphan (excluded): %s\n",
                excluded_orphans.entries[i]->filesystem_path
            );
        }
    }

    if (cleanup_plan->files.count > 0) {
        output_print(
            out, OUTPUT_VERBOSE, "Found %zu orphaned file%s\n",
            cleanup_plan->files.count, cleanup_plan->files.count == 1 ? "" : "s"
        );
    }
    if (cleanup_plan->directories.count > 0) {
        output_print(
            out, OUTPUT_VERBOSE, "Found %zu orphaned director%s\n",
            cleanup_plan->directories.count,
            cleanup_plan->directories.count == 1 ? "y" : "ies"
        );
    }

    /* Breakdown by profile status — profile_enabled's only consumer. */
    if (!cleanup_plan_is_empty(cleanup_plan)) {
        workspace_items_t orphan_files = workspace_items_view(&cleanup_plan->files);
        workspace_items_t orphan_dirs = workspace_items_view(&cleanup_plan->directories);
        size_t disabled_count = 0;
        size_t enabled_count = 0;

        for (size_t i = 0; i < orphan_files.count; i++) {
            if (orphan_files.entries[i]->profile_enabled) {
                enabled_count++;
            } else {
                disabled_count++;
            }
        }
        for (size_t i = 0; i < orphan_dirs.count; i++) {
            if (orphan_dirs.entries[i]->profile_enabled) {
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

    /* Warn if a file filter was given but matched no managed path at all
     * (held-back rows count as matched — the filter found them). Asked
     * after both planners: a path can name an orphan as well as an active
     * row, and finding either is a match. */
    if (scope_has_paths(scope) && deploy_plan_row_count(deploy_plan) == 0 &&
        cleanup_plan_item_count(cleanup_plan) == 0) {
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
     * deploy_plan->files.clean IS "in scope ∧ no work" — no gates re-derived here. */
    size_t adopted_count = 0;
    time_t adopt_now = time(NULL);
    state_files_t adoptable = state_files_view(&deploy_plan->files.clean);

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

    /* Collect pending profile reassignments and count stale files within
     * operation scope.
     *
     * Profile reassignment (old_profile set in state) is state bookkeeping,
     * not deployment: content may be identical, so the row never enters
     * the plan — but the flag must be cleared or the workspace keeps
     * reporting the transition. Collected before the early exit so a
     * reassignment-only workspace does not loop DIRTY forever.
     *
     * DIVERGENCE_STALE is the workspace's verdict that Git moved past the
     * blob dotta last deployed (anchor.blob_oid ≠ row.blob_oid) — a
     * persistent signal that survives status→apply sequences and counts
     * the same however the branch moved.
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

    /* How many in-scope files Git has moved since dotta deployed them.
     * [stale] alone the plan deploys like any other divergence; beside
     * [modified] it is a conflict preflight reports. Released files are
     * covered by the orphan-prune summary below. */
    if (stale_count > 0) {
        output_info(
            out, OUTPUT_NORMAL, "Found %zu stale file%s (changed in Git since deployment)",
            stale_count, stale_count == 1 ? "" : "s"
        );
    }

    /* Everything the plans held back, said once — above the exit below, so a
     * run whose only work was withheld still reports it, and above the
     * prompt, so consent is given with the full picture. */
    size_t withheld = print_withheld(out, deploy_plan, cleanup_plan);

    /* Nothing pends on the filesystem: acknowledge bookkeeping (if any) and
     * leave. Privilege checks, preflight, hooks and the prompt are for runs
     * that touch disk — pure state bookkeeping skips them. The save also
     * persists the reconcile + flush observations, dry-run included, as
     * status does. */
    if (deploy_plan_is_empty(deploy_plan) && cleanup_plan_is_empty(cleanup_plan)) {
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
     * deployments and cryptic mid-operation failures. Checks occur AFTER
     * both plans (every path the run will touch is known) but BEFORE any
     * filesystem modification.
     *
     * Skip check if dry-run (read-only operation, no privileges needed).
     *
     * If re-exec with sudo occurs, the entire process restarts from main(),
     * and state lock is safely released before execvp() replaces the process.
     */
    if (!opts->dry_run) {
        output_print(out, OUTPUT_VERBOSE, "\nChecking privilege requirements...\n");

        err = ensure_complete_apply_privileges(
            ctx, deploy_plan, cleanup_plan, opts, out
        );
        if (err) {
            err = error_wrap(err, "Insufficient privileges for operation");
            goto cleanup;
        }
    }

    /* Run pre-flight checks over the plan
     *
     * Divergence verdicts come from workspace_load's analysis (O(1) index
     * probes); the landing and writability checks are filesystem-level.
     */
    output_print(out, OUTPUT_VERBOSE, "\nRunning pre-flight checks...\n");

    deploy_options_t deploy_opts = {
        .force            = opts->force,
        .dry_run          = opts->dry_run,
        .strict_ownership = config->strict_mode,
    };

    err = deploy_preflight(ws, deploy_plan, &deploy_opts, &deploy_findings);
    if (err) {
        err = error_wrap(err, "Pre-flight checks failed");
        goto cleanup;
    }

    print_deploy_preflight_results(out, deploy_findings);
    print_reassignments(out, &reassigned);

    /* Check for blocking findings (conflicts, blocked paths, permissions) */
    if (deploy_findings->has_errors) {
        err = ERROR(ERR_CONFLICT, "Pre-flight checks failed");
        goto cleanup;
    }

    /* Preflight checks passed - free the results as we don't need them anymore */
    deploy_preflight_result_free(deploy_findings);
    deploy_findings = NULL;

    /* Decide cleanup's verdicts from the plan. An empty plan
     * (--keep-orphans, no orphans in scope) yields empty verdicts and a
     * silent preview — no gate needed anywhere. */
    cleanup_options_t cleanup_opts = {
        .force                 = opts->force,
        .deploying_files       = state_files_view(&deploy_plan->files.pending),
        .deploying_directories = state_directories_view(&deploy_plan->directories.pending),
    };

    err = cleanup_preflight(cleanup_plan, &cleanup_opts, &cleanup_verdicts);
    if (err) {
        err = error_wrap(err, "Cleanup preflight checks failed");
        goto cleanup;
    }

    print_cleanup_preflight_results(out, cleanup_verdicts);

    /* Skipped orphans do not abort: prunable ones are still pruned and
     * skipped ones left alone, which is better than doing nothing. The
     * preview above counted the skipped files and printed the remedies for
     * them, and cleanup_execute acts on these same verdicts — so there is
     * nothing to add here. */

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
         * two — so what the user consents to is what runs. Directory
         * pruning can be the only pending action (no files move). */
        size_t prune_file_count = cleanup_verdicts->prunable_files.count;
        size_t prune_dir_count = cleanup_verdicts->prunable_dirs.count;

        /* Compose the prompt from the non-zero parts — "Deploy 2 files,
         * converge 1 tracked directory and prune 3 orphaned files?". No
         * part means every pending action is state-only reclamation (e.g.
         * an all-absent orphan set) — non-destructive, no consent needed. */
        size_t deploy_count = deploy_plan->files.pending.count;
        size_t converge_count = deploy_plan->directories.pending.count;

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
    if (!deploy_plan_is_empty(deploy_plan)) {
        if (opts->dry_run) {
            output_print(
                out, OUTPUT_VERBOSE, "\nDry-run mode - no files will be modified\n"
            );
        } else {
            output_print(
                out, OUTPUT_VERBOSE, "\nExecuting deployment plan...\n"
            );
        }

        /* ctx->content_cache was populated with decrypted content during
         * workspace divergence analysis; deploy's fetches hit it. */
        err = deploy_execute(
            repo, ws, deploy_plan, &deploy_opts, ctx->content_cache, &deploy_res
        );
        if (err) {
            if (deploy_res) {
                print_deploy_results(out, ws, deploy_res, opts->dry_run);
            }
            err = error_wrap(err, "Deployment failed");
            goto cleanup;
        }

        print_deploy_results(out, ws, deploy_res, opts->dry_run);
    } else {
        output_print(out, OUTPUT_VERBOSE, "\nNo deployment work in scope\n");
    }

    /* Record what happened (only if not dry-run): cleanup, anchors,
     * witnesses. Acknowledgements and the commit follow for both modes. */
    if (!opts->dry_run) {
        /* Prune the orphans the verdicts cleared and retire their rows.
         *
         * cleanup_execute changes the filesystem only; apply, as the
         * transaction owner, retires the rows behind what went and what
         * was let go. The flow for an orphan: profile disabled → row
         * INACTIVE (manifest_apply_scope for a file, manifest_sync_directories
         * for a directory) → workspace observes the orphan → the verdict →
         * this block → row retired, completing the cycle. Without it,
         * orphaned entries accumulate forever in the state tables.
         *
         * Non-fatal: deployment already succeeded and its state must be
         * saved regardless, or the database would show deployed files as
         * undeployed and the user would see [undeployed] on working files.
         * Partial success is recorded — the partial result names what did
         * happen — and the next apply re-observes the rest. */
        cleanup_result_t *cleanup_res = NULL;
        error_t *cleanup_err = cleanup_execute(cleanup_verdicts, &cleanup_res);
        if (cleanup_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Deployment successful, but orphan cleanup failed: %s",
                error_message(cleanup_err)
            );
            error_free(cleanup_err);
        }

        if (cleanup_res) {
            print_cleanup_results(out, cleanup_res);

            /* The rows behind a gone or let-go path retire; a skipped or
             * failed one stays. Which outcomes retire is cleanup's rule,
             * read off its result (cleanup.h); the act is apply's. Every
             * bucket is one kind and the kind travels on the item, so it
             * picks the table. Non-fatal per row: the filesystem effect,
             * if any, already happened, and a row that fails to retire is
             * reported and observed again by the next apply. */
            const ptr_array_t *retiring[] = {
                &cleanup_res->pruned_files,
                &cleanup_res->reclaimed_files,
                &cleanup_res->released_files,
                &cleanup_res->pruned_dirs,
                &cleanup_res->reclaimed_dirs,
            };
            size_t retired = 0;

            for (size_t b = 0; b < sizeof(retiring) / sizeof(retiring[0]); b++) {
                workspace_items_t items = workspace_items_view(retiring[b]);

                for (size_t i = 0; i < items.count; i++) {
                    const workspace_item_t *item = items.entries[i];

                    err = (item->item_kind == PATH_KIND_DIRECTORY)
                        ? state_remove_directory(state, item->filesystem_path)
                        : state_remove_file(state, item->filesystem_path);
                    if (err) {
                        output_warning(
                            out, OUTPUT_NORMAL, "Failed to retire state entry for %s: %s",
                            item->filesystem_path, error_message(err)
                        );
                        error_free(err);
                        err = NULL;  /* Don't propagate - continue operation */
                        continue;
                    }
                    retired++;
                }
            }

            if (retired > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  Retired %zu state entr%s\n",
                    retired, retired == 1 ? "y" : "ies"
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
    if (deploy_plan) deploy_plan_free(deploy_plan);
    ptr_array_deinit(&reassigned);
    if (cleanup_verdicts) cleanup_preflight_result_free(cleanup_verdicts);
    if (cleanup_plan) cleanup_plan_free(cleanup_plan);
    if (deploy_findings) deploy_preflight_result_free(deploy_findings);
    if (profiles_str) free(profiles_str);
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
        "Override conflicts and prune modified orphans"
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
        "Path Arguments:\n"
        "  A path narrows the run to what lies at or beneath it, in both\n"
        "  directions: tracked files there are deployed and orphaned ones\n"
        "  pruned, so 'apply ~/.zshrc' retires one orphan on its own.\n"
        "  --keep-orphans leaves the orphans. Filesystem (~/.bashrc) and\n"
        "  storage (home/.bashrc) forms are both accepted.\n"
        "\n"
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
