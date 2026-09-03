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

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/cleanup.h"
#include "core/deploy.h"
#include "core/manifest.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "sys/filesystem.h"
#include "sys/identity.h"
#include "utils/hooks.h"

#define LIST_LIMIT 20  /* Every capped list in this file trims here. */

/**
 * Print the deploy skips: what the run will not do, and why
 *
 * The skips are reported and the run goes on: the verdicts already exclude them,
 * so nothing downstream re-checks. One section for every skip, both kinds, in
 * decision order — a skipped squatter precedes the rows it holds back, which is
 * the reading order — capped like every preview list (one squatter can hold a
 * subtree, so this one has a multiplier cleanup's uncapped block does not). The
 * header is the block's only prose, as it is in every block on both sides: no
 * one sentence covers both families here — the consent holds --force lifts and
 * the hard blocks it does not — and "not deployed" would say the header again.
 * Each row names its own reason, and the remedies close.
 *
 * Two line families. The landing and occupancy reasons keep their exact
 * parentheticals — facts about the path's surroundings, no profile. The row-fact
 * reasons read the way cleanup's skip block three lines away reads: a short label,
 * then the profile whose claim goes undelivered — red where content or type moved
 * away from the row, yellow where dotta cannot vouch for what stands there. A
 * CONTENT label reads the row's route (workspace_item_route — one producer for
 * the characterization; deploy keeps its decision): modified locally where only
 * disk moved, changed in Git and on disk where both sides did. A CONTENT skip
 * carries its item by construction — content_conflicts(NULL) is false — and it
 * is DEPLOYED (no path bit survives absence), so the route read is total here.
 *
 * The remedies close the block, indented under the rows the way every block closes,
 * each gated by what is actually present — the reasons, and for a named squatter
 * the claim that holds it (the fate-borne ancestor_class): a conflict-only run
 * is not told to fix paths by hand, a squatted ancestor claim is not told to
 * widen a scope that can never plan it, a run that holds root is not told to
 * hold it, and an unreadable-only run is offered neither a flag that will not
 * lift it nor a by-hand fix for a path dotta could not even read: it closes with
 * its own line, because dotta never writes on a guess. The two refusals root
 * lifts — a landing the invoker cannot write, a pair it cannot set — close with
 * the one command that would, spelled whole (identity_sudo_hint), and only by a
 * run that holds none: the caller hands the line or NULL, so the printer renders
 * and never asks who it is. The consent remedy teaches both directions and names
 * its cost the way cleanup's does: --force keeps Git's and discards what stands
 * there, and a CONTENT skip adds the disk-wins verb, 'dotta update' — gated on
 * CONTENT and not on the class, because update refuses a retyped row (update.c's
 * retyped_skipped). It stops there: the 'dotta add --force' a Git-moved row needs
 * is what update's own refusal says at the moment the user meets it, and '-e'
 * is how to ignore a skip, not how to remedy one. The block sits between the
 * deploy preview and cleanup's, so each engine tells its story the same way —
 * what it will do, then what it will not and why. No total-count line: the exit
 * error's message is the count's one home.
 */
static void print_deploy_skips(
    const output_t *out, const deploy_preflight_result_t *verdicts,
    const char *sudo_hint
) {
    if (verdicts->skipped.count == 0) {
        return;
    }

    output_section(out, OUTPUT_NORMAL, "Skipped paths");

    for (size_t i = 0; i < verdicts->skipped.count && i < LIST_LIMIT; i++) {
        const deploy_skip_t *s = &verdicts->skipped.entries[i];
        const char *path = s->row->filesystem_path;

        switch (s->reason) {
            case DEPLOY_SKIP_PERMISSION: {
                if (s->ancestor) {
                    output_styled(
                        out, OUTPUT_NORMAL, "  {red}✗{reset} %s (%.*s is not writable)\n",
                        path, (int) s->ancestor, path
                    );
                } else {
                    output_styled(
                        out, OUTPUT_NORMAL, "  {red}✗{reset} %s (ancestry cannot be reached)\n",
                        path
                    );
                }
                break;
            }

            case DEPLOY_SKIP_ANCESTOR: {
                output_styled(
                    out, OUTPUT_NORMAL, "  {red}✗{reset} %s (%.*s is not a directory)\n",
                    path, (int) s->ancestor, path
                );
                break;
            }

            case DEPLOY_SKIP_OCCUPIED: {
                output_styled(
                    out, OUTPUT_NORMAL, "  {red}✗{reset} %s (non-empty directory in the way)\n",
                    path
                );
                break;
            }

            case DEPLOY_SKIP_TYPE: {
                output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_RED, "  ⚠");
                output_print(out, OUTPUT_NORMAL, " %s ", path);
                if (s->ancestor) {
                    output_colored(
                        out, OUTPUT_NORMAL, OUTPUT_COLOR_RED, "(wrong type at %.*s from ",
                        (int) s->ancestor, path
                    );
                } else {
                    output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_RED, "(wrong type from ");
                }
                output_styled(out, OUTPUT_NORMAL, "{cyan}%s{reset}", s->row->profile);
                output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_RED, ")\n");
                break;
            }

            case DEPLOY_SKIP_CONTENT: {
                bool conflict = workspace_item_route(s->item) == WORKSPACE_ROUTE_CONFLICT;

                output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_RED, "  ✗");
                output_print(out, OUTPUT_NORMAL, " %s ", path);
                output_colored(
                    out, OUTPUT_NORMAL, OUTPUT_COLOR_RED, "(%s from ",
                    conflict ? "changed in Git and on disk" : "modified locally"
                );
                output_styled(out, OUTPUT_NORMAL, "{cyan}%s{reset}", s->row->profile);
                output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_RED, ")\n");
                break;
            }

            case DEPLOY_SKIP_UNREADABLE: {
                output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_YELLOW, "  ?");
                output_print(out, OUTPUT_NORMAL, " %s ", path);
                output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_YELLOW, "(cannot verify from ");
                output_styled(out, OUTPUT_NORMAL, "{cyan}%s{reset}", s->row->profile);
                output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_YELLOW, ")\n");
                break;
            }

            case DEPLOY_SKIP_OWNERSHIP: {
                /* The claim as chown(1) spells it: owner, owner:group, or :group */
                const char *owner = s->row->owner ? s->row->owner : "";
                const char *group = s->row->group ? s->row->group : "";

                output_styled(
                    out, OUTPUT_NORMAL, "  {red}✗{reset} %s (%s%s%s needs root to set)\n",
                    path, owner, *group ? ":" : "", group
                );
                break;
            }

            case DEPLOY_SKIP_NONE: {
                /* Unreachable: a row is in skipped because a reason names it */
                break;
            }
        }
    }

    if (verdicts->skipped.count > LIST_LIMIT) {
        output_print(
            out, OUTPUT_NORMAL, "  ... and %zu more\n", verdicts->skipped.count - LIST_LIMIT
        );
    }

    /* The remedies, one line per family, each printed once: the consent line
     * when any skip is --force's to lift (the class the exit contract reads,
     * deploy_skip_needs_force), naming its cost; the disk-wins direction only
     * when a CONTENT skip is present — 'dotta update' refuses a retyped row
     * (update.c's retyped_skipped), so a TYPE-only block must not be told to
     * use it; the incapacities a hand can fix split by the claim the skip carries
     * (ancestor_class) — widening the scope plans a tracked ancestor, and
     * PERMISSION, OCCUPIED and a squatter nothing claims read the same line; a
     * derived claim is never planned, so its second way out is the named
     * re-derivation, whose own preview names what the re-capture would commit.
     * Last, UNREADABLE's closing — an unreadable path is not "in the way", and
     * a fix-or-widen instruction would misname a refusal to judge what could
     * not be seen. */
    for (size_t i = 0; i < verdicts->skipped.count; i++) {
        if (deploy_skip_needs_force(verdicts->skipped.entries[i].reason)) {
            output_info(
                out, OUTPUT_NORMAL,
                "  Use --force to overwrite or replace them (discards what stands there)"
            );
            break;
        }
    }
    for (size_t i = 0; i < verdicts->skipped.count; i++) {
        if (verdicts->skipped.entries[i].reason == DEPLOY_SKIP_CONTENT) {
            output_info(
                out, OUTPUT_NORMAL,
                "  To keep what is on disk instead: 'dotta update <path>'"
            );
            break;
        }
    }
    for (size_t i = 0; i < verdicts->skipped.count; i++) {
        const deploy_skip_t *s = &verdicts->skipped.entries[i];

        if (s->reason == DEPLOY_SKIP_PERMISSION || s->reason == DEPLOY_SKIP_OCCUPIED ||
            (s->reason == DEPLOY_SKIP_ANCESTOR &&
            (s->ancestor_class == DEPLOY_ANCESTOR_TRACKED ||
            s->ancestor_class == DEPLOY_ANCESTOR_UNCLAIMED))) {
            output_info(
                out, OUTPUT_NORMAL,
                "  Fix the path by hand, or widen the scope so a tracked ancestor is planned"
            );
            break;
        }
    }
    for (size_t i = 0; i < verdicts->skipped.count; i++) {
        if (verdicts->skipped.entries[i].ancestor_class == DEPLOY_ANCESTOR_DERIVED) {
            output_info(
                out, OUTPUT_NORMAL,
                "  Fix the path by hand, or 'dotta update <dir>' to re-derive the way there"
            );
            break;
        }
    }
    for (size_t i = 0; sudo_hint && i < verdicts->skipped.count; i++) {
        deploy_skip_reason_t reason = verdicts->skipped.entries[i].reason;

        if (reason == DEPLOY_SKIP_PERMISSION || reason == DEPLOY_SKIP_OWNERSHIP) {
            output_info(out, OUTPUT_NORMAL, "  Run under sudo to deploy them: %s", sudo_hint);
            break;
        }
    }
    for (size_t i = 0; i < verdicts->skipped.count; i++) {
        if (verdicts->skipped.entries[i].reason == DEPLOY_SKIP_UNREADABLE) {
            output_info(
                out, OUTPUT_NORMAL,
                "  These paths could not be read; dotta never writes on a guess"
            );
            break;
        }
    }
}

/**
 * Print the deployment preview
 *
 * What deploy will do BEFORE user confirmation, read off the verdicts: every
 * number is a verdict count, and the preview, the prompt below it and the receipt
 * after it are three sentences about the same work — "will be deployed" / "Deploy
 * N files?" / "Deployed" — differing only in tense. In a dry run this is the
 * whole of deploy's output: the verdicts are the run's decisions, and nothing
 * else is asked or done.
 *
 * A directory's verb is its verdict's occupant (deploy_convergence): created
 * where nothing stood, fixed where a directory did, replaced where a squatter
 * did — the replace is the one destructive deploy verb, counted on its own line
 * and coloured the way cleanup colours a removal. The files' destructive half
 * is counted the same way: a file verdict overwrites local content iff something
 * stands at its path (deploy_occupant_present — a row planned absent beneath a
 * replaced squatter is a write into an empty tree, whatever its item read through
 * the link) and its item carries the conflict bits (deploy_content_conflicts,
 * CONTENT | TYPE) — reachable in a verdict only under --force, so the yellow
 * line is the forced run's counterweight to the confirmation prompt --force skips.
 * At verbose the paths are listed under their count, capped the way every preview
 * list is — one list, the glyph carrying the overwrite split: a yellow bullet
 * on exactly the rows the yellow line counted, cyan on the rest (print_path_list's
 * idiom — the glyph says which count the path belongs to). The ancestors the
 * run may make on the way are not here: they are the mechanics of landing a planned
 * path, and the receipt names the ones it made.
 *
 * The warnings close the preview. A warning is an anomaly preflight met while
 * deciding — an ownership it could not resolve — on a row the run will deploy:
 * a caveat on the promise, not a hold, so it prints under the promise and ahead
 * of the skips. Only a row the run touches contributes one (deploy.h's warnings),
 * and an ancestor is decided only above a deployable row, so the loop sits past
 * the early return and an empty preview never has a warning to lose.
 *
 * Empty verdicts have nothing to say, and say nothing.
 */
static void print_deploy_preview(
    const output_t *out,
    const deploy_preflight_result_t *verdicts
) {
    const deploy_verdicts_t *files = &verdicts->files;
    const deploy_verdicts_t *dirs = &verdicts->directories;

    size_t created = 0; size_t fixed = 0; size_t replaced = 0;

    for (size_t i = 0; i < dirs->count; i++) {
        switch (deploy_convergence(dirs->entries[i].occupant)) {
            case DEPLOY_CONVERGE_CREATE:  created++; break;
            case DEPLOY_CONVERGE_FIX:     fixed++; break;
            case DEPLOY_CONVERGE_REPLACE: replaced++; break;
        }
    }

    if (files->count + dirs->count == 0) {
        return;
    }

    output_section(out, OUTPUT_NORMAL, "Deployment");

    if (files->count > 0) {
        output_styled(
            out, OUTPUT_NORMAL, "  {green}%zu{reset} file%s will be deployed\n",
            files->count, files->count == 1 ? "" : "s"
        );

        size_t overwrites = 0;
        for (size_t i = 0; i < files->count; i++) {
            const deploy_verdict_t *v = &files->entries[i];

            if (deploy_occupant_present(v->occupant) && deploy_content_conflicts(v->item)) {
                overwrites++;
            }
        }
        if (overwrites > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "  {yellow}%zu{reset} of them overwrite%s local changes\n",
                overwrites, overwrites == 1 ? "s" : ""
            );
        }

        for (size_t i = 0; i < files->count && i < LIST_LIMIT; i++) {
            /* The glyph carries the overwrite split: yellow on exactly the rows
             * the yellow line counted, cyan on the rest. */
            bool overwrite =
                deploy_occupant_present(files->entries[i].occupant) &&
                deploy_content_conflicts(files->entries[i].item);

            output_styled(
                out, OUTPUT_VERBOSE,
                overwrite ? "    {yellow}•{reset} %s\n" : "    {cyan}•{reset} %s\n",
                files->entries[i].row->filesystem_path
            );
        }
        if (files->count > LIST_LIMIT) {
            output_print(
                out, OUTPUT_VERBOSE, "    ... and %zu more\n", files->count - LIST_LIMIT
            );
        }
    }

    if (created > 0) {
        output_styled(
            out, OUTPUT_NORMAL, "  {green}%zu{reset} tracked director%s will be created\n",
            created, created == 1 ? "y" : "ies"
        );

        size_t shown = 0;
        for (size_t i = 0; i < dirs->count && shown < LIST_LIMIT; i++) {

            if (deploy_convergence(dirs->entries[i].occupant) != DEPLOY_CONVERGE_CREATE) {
                continue;
            }

            shown++;
            output_styled(
                out, OUTPUT_VERBOSE, "    {cyan}•{reset} %s\n",
                dirs->entries[i].row->filesystem_path
            );
        }
        if (created > LIST_LIMIT) {
            output_print(out, OUTPUT_VERBOSE, "    ... and %zu more\n", created - LIST_LIMIT);
        }
    }

    if (fixed > 0) {
        output_styled(
            out, OUTPUT_NORMAL, "  {green}%zu{reset} tracked director%s will be fixed\n",
            fixed, fixed == 1 ? "y" : "ies"
        );

        size_t shown = 0;
        for (size_t i = 0; i < dirs->count && shown < LIST_LIMIT; i++) {

            if (deploy_convergence(dirs->entries[i].occupant) != DEPLOY_CONVERGE_FIX) {
                continue;
            }

            shown++;
            output_styled(
                out, OUTPUT_VERBOSE, "    {cyan}•{reset} %s\n",
                dirs->entries[i].row->filesystem_path
            );
        }
        if (fixed > LIST_LIMIT) {
            output_print(out, OUTPUT_VERBOSE, "    ... and %zu more\n", fixed - LIST_LIMIT);
        }
    }

    if (replaced > 0) {
        output_styled(
            out, OUTPUT_NORMAL, "  {yellow}%zu{reset} tracked director%s will be replaced\n",
            replaced, replaced == 1 ? "y" : "ies"
        );

        size_t shown = 0;
        for (size_t i = 0; i < dirs->count && shown < LIST_LIMIT; i++) {

            if (deploy_convergence(dirs->entries[i].occupant) != DEPLOY_CONVERGE_REPLACE) {
                continue;
            }

            shown++;
            output_styled(
                out, OUTPUT_VERBOSE, "    {yellow}•{reset} %s\n",
                dirs->entries[i].row->filesystem_path
            );
        }
        if (replaced > LIST_LIMIT) {
            output_print(out, OUTPUT_VERBOSE, "    ... and %zu more\n", replaced - LIST_LIMIT);
        }
    }

    /* The caveats on the promise. Past the early return by the invariant above:
     * only a row the run touches contributes one, and an ancestor is decided
     * only above a deployable row. */
    for (size_t i = 0; i < verdicts->warnings->count; i++) {
        output_warning(out, OUTPUT_NORMAL, "%s", verdicts->warnings->items[i]);
    }
}

/**
 * A pending profile reassignment, materialized at collect time
 *
 * Exactly what the preview prints: the path (with its kind, for the directory
 * marker) and the two profiles of the handover, captured off the item before
 * the run's ownership events (the adoption and acknowledgement loops' re-stamp,
 * the deployment's anchor) rewrite the record the fact derives from. Strings
 * are borrowed from the workspace arena (command lifetime).
 */
typedef struct {
    const char *path;      /* Filesystem path */
    const char *from;      /* The record's profile at load */
    const char *to;        /* The row's profile — the new owner */
    path_kind_t kind;      /* The item's kind — the slash after a directory path */
} reassignment_t;

/**
 * Print pending profile reassignments
 *
 * `reassigned` holds the planned rows whose owning profile changed (collected
 * off the plan's clean buckets, both kinds, and then off the verdicts) — the
 * exact set the run will acknowledge: a clean one by its re-stamp, a deployable
 * one by the record step behind its deployment, creation, replacement or
 * convergence.
 */
static void print_reassignments(
    const output_t *out, const reassignment_t *reassigned, size_t count
) {
    if (count == 0) return;

    output_section(out, OUTPUT_NORMAL, "Profile reassignments");
    for (size_t i = 0; i < count; i++) {
        output_styled(
            out, OUTPUT_NORMAL,
            "  {yellow}→{reset} %s%s: {cyan}%s{reset} → {cyan}%s{reset}\n",
            reassigned[i].path, path_kind_suffix(reassigned[i].kind),
            reassigned[i].from, reassigned[i].to
        );
    }
    output_info(
        out, OUTPUT_NORMAL,
        "  These paths will now be managed by a different profile."
    );
}

/**
 * Report the work the plans withheld, by flag
 *
 * -e (files, tracked directories, orphans) and --skip-existing (files) both mean
 * "in scope, needed work, deliberately not done" — the user's own flags, decided
 * at plan time, which is what "withheld" names against preflight's "skipped".
 * The two flags take two lines, and -e's line splits its count by kind at verbose.
 *
 * Printed once, above the nothing-to-do exit — so a run that does nothing else
 * still says what it withheld — and therefore also above the confirmation prompt,
 * where a user weighing the rest of the run should already know what is missing
 * from it. Per-item traces stay at plan time, beside the decision that produced
 * them.
 *
 * @param deploy_plan Deployment plan (must not be NULL)
 * @param cleanup_plan Cleanup plan, whose `excluded` bucket carries the orphans
 *        an -e pattern spared (must not be NULL)
 */
static void print_withheld(
    const output_t *out,
    const deploy_plan_t *deploy_plan,
    const cleanup_plan_t *cleanup_plan
) {
    /* -e reaches all three kinds, so its summary counts "paths"; the verbose
     * breakdown names each kind and what it was spared. */
    workspace_items_t excluded_orphans = workspace_items_view(&cleanup_plan->excluded);
    size_t excluded_orphan_files = 0; size_t excluded_orphan_dirs = 0;

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
                    excluded_orphan_files,
                    excluded_orphan_files == 1 ? "" : "s"
                );
            }
            if (excluded_orphan_dirs > 0) {
                output_print(
                    out, OUTPUT_VERBOSE, "  • %zu orphaned director%s not pruned\n",
                    excluded_orphan_dirs,
                    excluded_orphan_dirs == 1 ? "y" : "ies"
                );
            }
        } else {
            output_styled(
                out, OUTPUT_NORMAL, "Skipped {cyan}%zu{reset} path%s (--exclude)\n",
                excluded, excluded == 1 ? "" : "s"
            );
        }
    }

    /* --skip-existing reaches files only (see deploy_partition_t), so one line
     * says it at every verbosity. */
    size_t existing = deploy_plan->files.skipped_existing.count;
    if (existing > 0) {
        output_styled(
            out, OUTPUT_NORMAL,
            "Skipped {cyan}%zu{reset} existing file%s (--skip-existing)\n",
            existing, existing == 1 ? "" : "s"
        );
    }
}

/**
 * Print deployment results
 *
 * Handles all output for deployment results. The deploy layer only collects
 * outcomes; this function handles all presentation — the run's receipt, per-item
 * sections at verbose and summary counts at normal. Every number is the same
 * fold the preview takes over the verdicts (print_deploy_preview), taken here
 * over the verdicts the run carried out — so the receipt restates the preview
 * by construction, adding nothing of its own.
 *
 * Categories (each semantically distinct):
 * - deployed: Files written to disk (green)
 * - created / fixed / replaced: Tracked directories, by what the verdict said
 *   stood at the path — one line each, so the squatter --force displaced is named
 *   at every verbosity (green; the replaced count yellow, as cleanup colours a
 *   removal)
 * - ancestors: Directories the run made on the way to a planned path, outside
 *   the plan — either class, since a claimed rung is created at its claim whether
 *   the profile manages it or only passes through it. Verbose only — the preview
 *   never counted them, and the summary says what the preview said; the verbose
 *   listing accounts for every owned record the run wrote
 *
 * The verb is the verdict's; the tags are plan truth. A fixed row is tagged [mode]
 * / [ownership] from its fate's item — why the planner chose it — never from a
 * fresh stat: the run has just converged the directory, so disk would say nothing.
 * A pending row the planner chose on its own verdict has an indexed item
 * (deploy_needs_work(NULL) is false); one planned as absent beneath a squatted
 * directory may have none, and is created rather than fixed. A fixed row whose
 * item carries neither bit, or no item, prints no tag, and the other sections
 * never carry one, since the verb already says what the path held.
 *
 * Mode and ownership print as the row carries them — total by build, a 0000 claim
 * included: the receipt reports the row, and (mode: 0000) is the claim honoured,
 * not an anomaly. A symlink row records no mode by design and says so instead,
 * carrying its ownership when the row holds one — a link's entry exists to carry
 * exactly that, so the receipt is where the claim becomes visible.
 *
 * Work the run skipped is not here: the plan decided it, print_withheld reports
 * it, and it must be said even on runs that never execute. A failure IS here —
 * one line per row that did not land, its cause beside it (the receipt's failed
 * bucket), at every verbosity and last, after what did land: a receipt that omits
 * what went wrong is not a receipt, and no run-level error will name it (cleanup's
 * receipt ends on its failures the same way). No total-count line: the exit error's
 * message is the count's one home, as for the skip block.
 *
 * Adoption (ownership stamping for pre-existing matching files) is an apply-level
 * concern and its summary is printed by cmd_apply directly.
 */
static void print_deploy_results(
    const output_t *out,
    const deploy_result_t *result
) {
    deploy_outcomes_t deployed = result->deployed;
    deploy_outcomes_t converged = result->converged;
    deploy_outcomes_t ancestors = result->ancestors;

    /* The verbs, folded off the carried-out fates exactly as the preview folds
     * them off the verdicts (print_deploy_preview) — the receipt restates the
     * preview by construction: one producer, so they cannot drift. */
    size_t created = 0; size_t fixed = 0; size_t replaced = 0;

    for (size_t i = 0; i < converged.count; i++) {
        switch (deploy_convergence(converged.entries[i].verdict->occupant)) {
            case DEPLOY_CONVERGE_CREATE:  created++; break;
            case DEPLOY_CONVERGE_FIX:     fixed++; break;
            case DEPLOY_CONVERGE_REPLACE: replaced++; break;
        }
    }

    /* Verbose mode: show individual items per outcome */
    if (deployed.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Deployed files");
        for (size_t i = 0; i < deployed.count; i++) {
            const manifest_row_t *file = deployed.entries[i].verdict->row;

            if (file->type == PATH_TYPE_SYMLINK) {
                output_styled(
                    out, OUTPUT_VERBOSE, "  {green}✓{reset} %s (symlink",
                    file->filesystem_path
                );
                if (file->owner || file->group) {
                    output_print(
                        out, OUTPUT_VERBOSE, ", owner: %s:%s",
                        file->owner ? file->owner : "?", file->group ? file->group : "?"
                    );
                }
                output_print(out, OUTPUT_VERBOSE, ")\n");
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

    if (created > 0) {
        output_section(out, OUTPUT_VERBOSE, "Created tracked directories");
        for (size_t i = 0; i < converged.count; i++) {
            const deploy_verdict_t *v = converged.entries[i].verdict;

            if (deploy_convergence(v->occupant) != DEPLOY_CONVERGE_CREATE) continue;
            const manifest_row_t *dir = v->row;

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

    if (fixed > 0) {
        output_section(out, OUTPUT_VERBOSE, "Fixed tracked directories");
        for (size_t i = 0; i < converged.count; i++) {
            const deploy_verdict_t *v = converged.entries[i].verdict;

            if (deploy_convergence(v->occupant) != DEPLOY_CONVERGE_FIX) continue;
            const manifest_row_t *dir = v->row;

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
            const workspace_item_t *item = v->item;
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

    if (replaced > 0) {
        output_section(out, OUTPUT_VERBOSE, "Replaced tracked directories");
        for (size_t i = 0; i < converged.count; i++) {
            const deploy_verdict_t *v = converged.entries[i].verdict;

            if (deploy_convergence(v->occupant) != DEPLOY_CONVERGE_REPLACE) continue;
            const manifest_row_t *dir = v->row;

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

    if (ancestors.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Created ancestors (outside the plan)");
        for (size_t i = 0; i < ancestors.count; i++) {
            const manifest_row_t *dir = ancestors.entries[i].verdict->row;

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
                out, OUTPUT_NORMAL, "Deployed {green}%zu{reset} file%s\n",
                deployed.count, deployed.count == 1 ? "" : "s"
            );
        }

        if (created > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Created {green}%zu{reset} tracked director%s\n",
                created, created == 1 ? "y" : "ies"
            );
        }

        if (fixed > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Fixed {green}%zu{reset} tracked director%s\n",
                fixed, fixed == 1 ? "y" : "ies"
            );
        }

        if (replaced > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Replaced {yellow}%zu{reset} tracked director%s\n",
                replaced, replaced == 1 ? "y" : "ies"
            );
        }
    }

    /* The rows that did not land — both kinds, verdict order, each with its cause.
     * At every verbosity, and after what landed (the header carries the rationale);
     * capped the way the skip block is. The cause is the chain's root, where
     * the refusal speaks verbatim — EISDIR, ENOSPC, a blob that would not load;
     * the wraps above it restate the row the line already names. */
    if (result->failed.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Failed deployments");
        for (size_t i = 0; i < result->failed.count && i < LIST_LIMIT; i++) {
            const deploy_outcome_t *o = &result->failed.entries[i];

            output_styled(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s (%s)\n",
                o->verdict->row->filesystem_path,
                error_message(error_root(o->error))
            );
        }
        if (result->failed.count > LIST_LIMIT) {
            output_print(
                out, OUTPUT_NORMAL, "  ... and %zu more\n", result->failed.count - LIST_LIMIT
            );
        }
    }
}

/**
 * Print cleanup results
 *
 * The run's receipt: per-item sections at verbose, summary counts at normal,
 * the failures at both. Every number is a bucket size, read off two objects because
 * the run's story is held by two: the verdicts hold what cleanup decided and
 * never acted on — released, skipped or refused at preflight, gone at load —
 * and the receipt what execute found and did — pruned, gone by the time it looked,
 * refused, failed (cleanup_result_t). Each read names its source; this adds nothing
 * of its own.
 *
 * A receipt reports effects. That is why this one re-tells a fate deploy's does
 * not: a deploy skip has no effect at all — nothing written, no record moved —
 * and the preview is its one home, where a cleanup release is an effect (the
 * record retires) and belongs here too. A second telling says the same thing in
 * the same order as the first, so the sections (kind-major) and the summary
 * (fate-major) both take the preview's order — pruned, released, skipped, then
 * what was already gone — and close on the failures: one section at every
 * verbosity, both kinds in act order, each row with its cause, the shape of
 * deploy's "Failed deployments". Where a section has more than one source — the
 * skipped files and directories (held or refused at preflight, and a directory
 * refused at removal), the reclaimed paths (gone at load, gone by the time the
 * run looked) — the verdicts' rows print first, so a run that had both names
 * each once.
 */
static void print_cleanup_results(
    const output_t *out,
    const cleanup_preflight_result_t *verdicts,
    const cleanup_result_t *result
) {
    /* Verbose mode: show individual items per outcome */
    if (result->pruned_files.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Pruned orphaned files");
        for (size_t i = 0; i < result->pruned_files.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}[pruned]{reset} %s\n",
                result->pruned_files.entries[i].item->filesystem_path
            );
        }
    }

    if (verdicts->released_files.count > 0) {
        workspace_items_t items = workspace_items_view(&verdicts->released_files);

        output_section(out, OUTPUT_VERBOSE, "Released files");
        for (size_t i = 0; i < items.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[released]{reset} %s\n",
                items.entries[i]->filesystem_path
            );
        }
    }

    /* Each skipped file's reason was named by the preview — the skipped-files
     * block for the item's own, the needing-root block for the run's — and both
     * always print; the receipt only confirms the skip. */
    if (verdicts->skipped_files.count + verdicts->refused_files.count > 0) {
        workspace_items_t held = workspace_items_view(&verdicts->skipped_files);
        workspace_items_t refused = workspace_items_view(&verdicts->refused_files);

        output_section(out, OUTPUT_VERBOSE, "Skipped orphaned files");
        for (size_t i = 0; i < held.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}[skipped]{reset} %s\n",
                held.entries[i]->filesystem_path
            );
        }
        for (size_t i = 0; i < refused.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}[skipped]{reset} %s\n",
                refused.entries[i]->filesystem_path
            );
        }
    }

    if (verdicts->absent_files.count + result->reclaimed_files.count > 0) {
        workspace_items_t absent = workspace_items_view(&verdicts->absent_files);

        output_section(out, OUTPUT_VERBOSE, "Reclaimed orphaned files");
        for (size_t i = 0; i < absent.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[reclaimed]{reset} %s\n",
                absent.entries[i]->filesystem_path
            );
        }
        for (size_t i = 0; i < result->reclaimed_files.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[reclaimed]{reset} %s\n",
                result->reclaimed_files.entries[i].item->filesystem_path
            );
        }
    }

    if (result->pruned_dirs.count > 0) {
        output_section(out, OUTPUT_VERBOSE, "Pruned orphaned directories");
        for (size_t i = 0; i < result->pruned_dirs.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {green}[pruned]{reset} %s\n",
                result->pruned_dirs.entries[i].item->filesystem_path
            );
        }
    }

    if (verdicts->released_dirs.count > 0) {
        workspace_items_t items = workspace_items_view(&verdicts->released_dirs);

        output_section(out, OUTPUT_VERBOSE, "Released directories");
        for (size_t i = 0; i < items.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[released]{reset} %s\n",
                items.entries[i]->filesystem_path
            );
        }
    }

    if (verdicts->skipped_dirs.count + verdicts->refused_dirs.count +
        result->skipped_dirs.count > 0) {
        workspace_items_t held = workspace_items_view(&verdicts->skipped_dirs);
        workspace_items_t refused = workspace_items_view(&verdicts->refused_dirs);

        output_section(out, OUTPUT_VERBOSE, "Skipped orphaned directories");
        for (size_t i = 0; i < held.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}[skipped]{reset} %s\n",
                held.entries[i]->filesystem_path
            );
        }
        for (size_t i = 0; i < refused.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}[skipped]{reset} %s\n",
                refused.entries[i]->filesystem_path
            );
        }
        for (size_t i = 0; i < result->skipped_dirs.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {yellow}[skipped]{reset} %s\n",
                result->skipped_dirs.entries[i].item->filesystem_path
            );
        }
    }

    if (verdicts->absent_dirs.count + result->reclaimed_dirs.count > 0) {
        workspace_items_t absent = workspace_items_view(&verdicts->absent_dirs);

        output_section(out, OUTPUT_VERBOSE, "Reclaimed orphaned directories");
        for (size_t i = 0; i < absent.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[reclaimed]{reset} %s\n",
                absent.entries[i]->filesystem_path
            );
        }
        for (size_t i = 0; i < result->reclaimed_dirs.count; i++) {
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}[reclaimed]{reset} %s\n",
                result->reclaimed_dirs.entries[i].item->filesystem_path
            );
        }
    }

    /* Non-verbose: summary counts only. */
    if (!output_is_verbose(out)) {
        if (result->pruned_files.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Pruned {yellow}%zu{reset} orphaned file%s\n",
                result->pruned_files.count,
                result->pruned_files.count == 1 ? "" : "s"
            );
        }

        if (result->pruned_dirs.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Pruned {yellow}%zu{reset} orphaned director%s\n",
                result->pruned_dirs.count,
                result->pruned_dirs.count == 1 ? "y" : "ies"
            );
        }

        if (verdicts->released_files.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Released {cyan}%zu{reset} file%s from management\n",
                verdicts->released_files.count,
                verdicts->released_files.count == 1 ? "" : "s"
            );
        }

        if (verdicts->released_dirs.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "Released {cyan}%zu{reset} director%s from management\n",
                verdicts->released_dirs.count,
                verdicts->released_dirs.count == 1 ? "y" : "ies"
            );
        }

        /* No reason here: the preview's skipped-files block named these files,
         * their reasons and the --force override, its needing-root block the
         * ones the parent refuses and the sudo line, and both always print —
         * including on the run that reports this line. */
        size_t skipped_files = verdicts->skipped_files.count + verdicts->refused_files.count;

        if (skipped_files > 0) {
            output_warning(
                out, OUTPUT_NORMAL, "Skipped %zu orphaned file%s",
                skipped_files, skipped_files == 1 ? "" : "s"
            );
        }

        /* Nor here: a directory is skipped because something the run holds back
         * is still in it, because the workspace could not verify it, because
         * its parent refuses the run, or because the removal refused — the verbose
         * listing names which. */
        size_t skipped_dirs = verdicts->skipped_dirs.count + verdicts->refused_dirs.count +
            result->skipped_dirs.count;

        if (skipped_dirs > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Skipped %zu orphaned director%s",
                skipped_dirs, skipped_dirs == 1 ? "y" : "ies"
            );
            output_info(
                out, OUTPUT_NORMAL, "Use --verbose to see which directories were skipped."
            );
        }

        /* Orphans already gone from the filesystem when the run loaded, and the
         * ones gone by the time the run looked. Reported separately from "Pruned"
         * — no removal happened or was needed — and named for the paths, not
         * for the record rows that retire behind them: what the user has here
         * is a path that is already gone. */
        size_t reclaimed = verdicts->absent_files.count + verdicts->absent_dirs.count +
            result->reclaimed_files.count + result->reclaimed_dirs.count;

        if (reclaimed > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "Reclaimed {cyan}%zu{reset} orphaned path%s (already gone)\n",
                reclaimed, reclaimed == 1 ? "" : "s"
            );
        }
    }

    /* The items the run could not remove — both kinds, act order, each with its
     * cause. At every verbosity, and after what went (the header carries the
     * rationale); capped the way deploy's failed section is. The cause is the
     * chain's root, where the refusal speaks verbatim — EACCES on the parent,
     * EROFS, EBUSY; the wraps above it restate the path the line already names. */
    if (result->failed.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Failed prunes");
        for (size_t i = 0; i < result->failed.count && i < LIST_LIMIT; i++) {
            const cleanup_outcome_t *o = &result->failed.entries[i];

            output_styled(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s (%s)\n",
                o->item->filesystem_path,
                error_message(error_root(o->error))
            );
        }
        if (result->failed.count > LIST_LIMIT) {
            output_print(
                out, OUTPUT_NORMAL, "  ... and %zu more\n", result->failed.count - LIST_LIMIT
            );
        }
    }
}

/**
 * List the paths behind a preview count, capped
 *
 * One shape for every preview list, so a long directory list is trimmed and counted
 * the way a long file list is rather than vanishing whole. The glyph says which
 * count the path belongs to: a cyan bullet for what the run acts on, a yellow
 * slash for what it deliberately leaves.
 */
static void print_path_list(
    const output_t *out,
    const ptr_array_t *bucket,
    output_color_t color,
    const char *glyph
) {
    workspace_items_t items = workspace_items_view(bucket);

    for (size_t i = 0; i < items.count && i < LIST_LIMIT; i++) {
        output_colored(out, OUTPUT_VERBOSE, color, "    %s", glyph);
        output_print(out, OUTPUT_VERBOSE, " %s\n", items.entries[i]->filesystem_path);
    }

    if (items.count > LIST_LIMIT) {
        output_print(
            out, OUTPUT_VERBOSE, "    ... and %zu more\n", items.count - LIST_LIMIT
        );
    }
}

/**
 * Print the cleanup preview
 *
 * Shows what cleanup will do BEFORE user confirmation. Every number here is one
 * cleanup decided; this function reads them and adds nothing of its own, so the
 * preview, the prompt below it and the outcome after it are three sentences about
 * the same work — in the same words, because a preview line and its outcome line
 * name one verdict with one verb ("will be pruned" / "Pruned"), differing only
 * in tense. Equal counts for a run the world did not move under: a path gone,
 * or a directory refilled, between the prompt and the removal moves one item
 * from the promise here to the receipt's own buckets (reclaimed, skipped), and
 * the receipt says so from its side (print_cleanup_results).
 *
 * The summaries only count the files the run will not prune; three blocks name
 * them, with different messaging. The released ones close this preview: a release
 * is a promise of an effect — the record retires — and nothing is asked about
 * it, so the block is the preview's to make. The skipped ones are two buckets
 * under one count — the skip is the fate, and the record stays either way — named
 * apart by what holds them: the item's own reason and the one lever that overrides
 * it (print_cleanup_skips), or the parent that refuses the run and the command
 * that holds root (print_cleanup_refused). Cleanup took that split when it bucketed
 * each file; this is display, so it counts nothing and only routes per item.
 */
static void print_cleanup_preview(
    const output_t *out,
    const cleanup_preflight_result_t *verdicts
) {
    workspace_items_t released = workspace_items_view(&verdicts->released_files);
    size_t skipped_files = verdicts->skipped_files.count + verdicts->refused_files.count;
    size_t skipped_dirs = verdicts->skipped_dirs.count + verdicts->refused_dirs.count;

    /* Every planned item lands in exactly one bucket, so these are the
     * present-orphan counts and the state-only count. */
    size_t present_files = verdicts->prunable_files.count + skipped_files + released.count;
    size_t present_dirs = verdicts->prunable_dirs.count + skipped_dirs +
        verdicts->released_dirs.count;

    /* An empty plan — no orphans in scope, --keep-orphans — has nothing to say,
     * and says nothing. The sum is the plan's size, by the partition above
     * (cleanup_preflight_result_t's two equations), so only an empty plan returns
     * here — the closer in cmd_apply counts on it. */
    if (present_files + present_dirs + verdicts->absent_files.count +
        verdicts->absent_dirs.count == 0) {
        return;
    }

    if (present_files + verdicts->absent_files.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Orphaned files");

        /* The prunable summary splits by the relocation the item carries
         * (item->row) — a naming, not a verdict: both halves are cleanup's one
         * prunable bucket, named together in the list below, and the split only
         * keeps each parenthetical true. A relocated prunable copy is not inactive
         * — its claim deploys at a new filesystem path — so "(no longer active)"
         * would lie about it. */
        workspace_items_t prunable = workspace_items_view(&verdicts->prunable_files);
        size_t moved = 0;
        for (size_t i = 0; i < prunable.count; i++) {
            if (prunable.entries[i]->row) moved++;
        }

        if (prunable.count - moved > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {yellow}%zu{reset} file%s will be pruned (no longer active)\n",
                prunable.count - moved,
                prunable.count - moved == 1 ? "" : "s"
            );
        }

        if (moved > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {yellow}%zu{reset} file%s will be pruned "
                "(relocated: the claim deploys at its new location)\n",
                moved, moved == 1 ? "" : "s"
            );
        }

        /* Every list follows the count that promises it, so a name is never read
         * against the wrong fate. One list here, under the two prune lines it
         * spans: the released and skipped files are named in blocks of their
         * own below — the released ones closing this preview, the skipped ones
         * with their reasons in the block after it — so their counts stand
         * alone. */
        print_path_list(out, &verdicts->prunable_files, OUTPUT_COLOR_CYAN, "•");

        if (released.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {cyan}%zu{reset} file%s will be released from management\n",
                released.count,
                released.count == 1 ? "" : "s"
            );
        }

        if (skipped_files > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {yellow}%zu{reset} file%s will be skipped\n",
                skipped_files,
                skipped_files == 1 ? "" : "s"
            );
        }

        /* A state effect with no filesystem effect: the path was already gone
         * when the run loaded, so only the record retires. Said in the block's
         * own noun and gated into it, because a run whose orphans are all absent
         * still has this to say. It breaks the block's future tense on purpose
         * — every other line promises an action, this one reports there is none. */
        if (verdicts->absent_files.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {cyan}%zu{reset} file%s already gone (nothing to remove)\n",
                verdicts->absent_files.count,
                verdicts->absent_files.count == 1 ? " is" : "s are"
            );
        }
    }

    if (present_dirs + verdicts->absent_dirs.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Orphaned directories");

        if (verdicts->prunable_dirs.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "  {cyan}%zu{reset} director%s will be pruned\n",
                verdicts->prunable_dirs.count,
                verdicts->prunable_dirs.count == 1 ? "y" : "ies"
            );
        }

        print_path_list(out, &verdicts->prunable_dirs, OUTPUT_COLOR_CYAN, "•");

        /* All three fates are named here, each list under its own count, because
         * a directory gets no block of its own: nothing is asked of the user
         * about a released one (the arrow says "left alone"), and a directory
         * left behind is not the event a file left behind is — whether the
         * workspace released it or it holds something this run will never remove
         * (cleanup.h's classes). A skipped directory holds something the run
         * holds back, could not be verified (status tags it [unverified]), sits
         * under a moved home ([relocated] — the hold --force lifts), or sits
         * under a parent that refuses the run (the needing-root block names it);
         * the slash says "left alone this run" for each. */
        if (verdicts->released_dirs.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {cyan}%zu{reset} director%s will be released from management\n",
                verdicts->released_dirs.count,
                verdicts->released_dirs.count == 1 ? "y" : "ies"
            );
        }

        print_path_list(out, &verdicts->released_dirs, OUTPUT_COLOR_CYAN, "→");

        if (skipped_dirs > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "  {yellow}%zu{reset} director%s will be skipped\n",
                skipped_dirs, skipped_dirs == 1 ? "y" : "ies"
            );
        }

        print_path_list(out, &verdicts->skipped_dirs, OUTPUT_COLOR_YELLOW, "⊘");
        print_path_list(out, &verdicts->refused_dirs, OUTPUT_COLOR_YELLOW, "⊘");

        if (verdicts->absent_dirs.count > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {cyan}%zu{reset} director%s already gone (nothing to remove)\n",
                verdicts->absent_dirs.count,
                verdicts->absent_dirs.count == 1 ? "y is" : "ies are"
            );
        }
    }

    /* Released files are informational: nothing is asked of the user, and --force
     * does not change their fate (see cleanup.h). So the block closes with the
     * consequence, indented under the rows the way "Profile reassignments" closes
     * — not a remedy, which stands off — and that closing line carries the half
     * the header cannot: pruned removes and released keeps, and only the line
     * under the rows says which. The causes are not listed: a release is the
     * workspace's verdict (state RELEASED), and cleanup has no per-row reason
     * for it the way cleanup_skip_reason answers for a skip, so the only honest
     * form would be a disjunction naming all three at every row. */
    if (released.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Released files");

        for (size_t i = 0; i < released.count; i++) {
            const workspace_item_t *item = released.entries[i];

            output_styled(out, OUTPUT_NORMAL, "  {cyan}→{reset} %s", item->filesystem_path);
            output_styled(out, OUTPUT_NORMAL, " {dim}(from %s){reset}\n", item->profile);
        }

        output_info(
            out, OUTPUT_NORMAL,
            "  These paths are left on disk, no longer managed by dotta."
        );
    }
}

/**
 * Print the cleanup skips: the orphaned files the run will not prune, and why
 *
 * Each is named with its reason, then the one line the deploy-side conflict block
 * also ends with — --force overrides the hold. The header names the fate in the
 * receipt's own words for this bucket — the two blocks that map one-to-one onto
 * a receipt section, this and "Released files", name it identically there and
 * here — which also keeps it clear of the deploy block's "Skipped paths" above,
 * whose rows carry the same shape. The labels name the reasons, because no one
 * reason covers the block — a held relocation is byte-clean and an unverifiable
 * copy may be — and the closing line names the cost the same way: what stands
 * there, whatever its state. The ways to keep a held file are the inverse of
 * the command that orphaned it (profile enable, add) or a move aside, and every
 * line names the profile; they are not spelled out.
 *
 * It comes last of the previews, so that guidance is what the user is looking
 * at when the confirmation prompt arrives.
 */
static void print_cleanup_skips(
    const output_t *out,
    const cleanup_preflight_result_t *verdicts
) {
    workspace_items_t skipped = workspace_items_view(&verdicts->skipped_files);

    if (skipped.count == 0) {
        return;
    }

    output_section(out, OUTPUT_NORMAL, "Skipped orphaned files");

    for (size_t i = 0; i < skipped.count; i++) {
        const workspace_item_t *item = skipped.entries[i];

        /* How the reason reads on screen. The reason itself is cleanup's
         * (cleanup_skip_reason); this only names it — red where the file's own
         * content or type has moved away from what dotta deployed, yellow where
         * dotta simply cannot vouch for it or deliberately holds it. */
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
            case CLEANUP_SKIP_RELOCATED:
                glyph = "⚠";
                label = "home changed";
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
        output_colored(out, OUTPUT_NORMAL, color, "(%s from ", label);
        output_styled(out, OUTPUT_NORMAL, "{cyan}%s{reset}", item->profile);
        output_colored(out, OUTPUT_NORMAL, color, ")\n");
    }

    output_info(
        out, OUTPUT_NORMAL,
        "  Use --force to prune them anyway (discards what stands there)"
    );
}

/**
 * Print the cleanup refusals: what the run cannot prune, and what could
 *
 * Both kinds in one section — files, then the directories in prune order — each
 * row naming the parent that refuses, verbatim, in the words deploy's PERMISSION
 * row uses for the same fact ("… is not writable"; "ancestry cannot be reached"
 * where the workspace's own lstat was refused on the way — the occupant says
 * so, and the parent the probe asked is then not the rung that refused), and
 * the one closer: the command line that holds root, handed in by the caller as
 * print_deploy_skips's is, so the printer renders and never asks who it is. Capped
 * like deploy's block — one root-owned parent can hold a subtree — where cleanup's
 * skipped-files block is not (every row there carries a reason of its own). Neither
 * a --force line nor a by-hand one: root is not a flag, and the row already names
 * the directory a hand would have to open.
 *
 * Last of the previews, after the skips it is the sibling of: a refusal is a
 * skip by fate — the count lines above say "skipped", the record stays, the receipt
 * confirms it under that word — and this block is where its reason lives, the
 * run's rather than the item's (cleanup_preflight_result_t). Empty under a run
 * that holds root, by construction, and prints nothing.
 */
static void print_cleanup_refused(
    const output_t *out,
    const cleanup_preflight_result_t *verdicts,
    const char *sudo_hint
) {
    const workspace_items_t kinds[] = {
        workspace_items_view(&verdicts->refused_files),
        workspace_items_view(&verdicts->refused_dirs),
    };
    size_t total = kinds[0].count + kinds[1].count;

    if (total == 0) {
        return;
    }

    output_section(out, OUTPUT_NORMAL, "Orphaned paths needing root");

    size_t shown = 0;
    for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
        for (size_t i = 0; i < kinds[k].count && shown < LIST_LIMIT; i++, shown++) {
            const workspace_item_t *item = kinds[k].entries[i];
            const char *path = item->filesystem_path;

            if (item->occupant == FS_OCCUPANT_UNKNOWN) {
                output_styled(
                    out, OUTPUT_NORMAL, "  {red}✗{reset} %s (ancestry cannot be reached)\n",
                    path
                );
            } else {
                output_styled(
                    out, OUTPUT_NORMAL, "  {red}✗{reset} %s (%.*s is not writable)\n",
                    path, (int) str_path_parent_len(path), path
                );
            }
        }
    }
    if (total > LIST_LIMIT) {
        output_print(out, OUTPUT_NORMAL, "  ... and %zu more\n", total - LIST_LIMIT);
    }

    if (sudo_hint) {
        output_info(out, OUTPUT_NORMAL, "  Run under sudo to prune them: %s", sudo_hint);
    }
}

/**
 * Apply command implementation
 */
error_t *cmd_apply(const dotta_ctx_t *ctx, const cmd_apply_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const char *repo_path = ctx->run.repo_path;
    state_t *state = ctx->run.state;                /* Borrowed from dispatcher (WRITE) */
    const mount_table_t *mounts = ctx->run.mounts;
    content_cache_t *content_cache = ctx->run.content_cache;
    const manifest_t *manifest = ctx->run.manifest; /* The view at dispatch */
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Declare all resources at the top, initialized to NULL/zero */
    error_t *err = NULL;
    scope_t *scope = NULL;
    workspace_t *ws = NULL;
    deploy_plan_t *deploy_plan = NULL;                 /* Rows borrow from ws; free before ws */
    cleanup_plan_t *cleanup_plan = NULL;               /* Items borrow from ws; free before ws */
    deploy_preflight_result_t *deploy_verdicts = NULL; /* Fates borrow rows from ws; free after deploy_result */
    cleanup_preflight_result_t *cleanup_verdicts = NULL;
    char *profiles_str = NULL;
    char *sudo_hint = NULL;                  /* Root's remedy for the skips; NULL when the run holds root */
    deploy_result_t *deploy_result = NULL;   /* Outcomes borrow the fates; free first */
    cleanup_result_t *cleanup_result = NULL; /* Outcomes borrow the verdicts; free first */

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Build operation scope
     *
     *   scope_enabled — the persistent enabled set, the CLI filter's bound. Empty
     *                   is a valid convergence target: every record becomes an
     *                   orphan and apply cleans them up. Enables the "disable
     *                   last profile, then apply" workflow.
     *   scope_active  — operation face (the verbose listing, hook context).
     *   scope_has_filter / scope_has_paths / scope_paths — the build's shape,
     *                   for the wording of the no-match warning and the
     *                   nothing-to-do exit.
     *
     * The per-iteration predicates are the two planners' (deploy_plan_build,
     * cleanup_plan_build): apply reads the scope through the plans and applies
     * no gate of its own.
     *
     * Scope_build resolves enabled (lenient on empty), resolves and validates
     * the CLI filter, harvests custom targets from the active set, builds the
     * path filter, and deep-copies excludes. */
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
        repo, state, &scope_inputs, config, mounts, ctx->arena, &scope
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
            out, OUTPUT_VERBOSE, "\nPath filter: %zu path%s specified\n",
            filter_count, filter_count == 1 ? "" : "s"
        );
    }

    /* The hooks' profile list, joined beside the scope it reads: the one allocation
     * on the way to the hooks fails here, before the previews are on screen,
     * rather than under a consent text the run then abandons. */
    profiles_str = string_array_join(scope_active(scope), " ");
    if (!profiles_str) {
        err = ERROR(ERR_MEMORY, "Failed to join profile names for hook");
        goto cleanup;
    }

    /* The command line that re-runs this invocation under sudo, for the two closing
     * lines that name it (print_deploy_skips, print_cleanup_refused). Built here
     * beside the other run-wide string, and only by a run that holds no root:
     * one that does is never refused where the invoker is, and would only name
     * a remedy already taken. */
    if (!identity()->privileged) {
        sudo_hint = identity_sudo_hint(ctx->argc, ctx->argv);
        if (!sudo_hint) {
            err = ERROR(ERR_MEMORY, "Failed to build the sudo hint");
            goto cleanup;
        }
    }

    /* Load workspace (partitions the view's rows and runs divergence analysis)
     *
     * After workspace_load returns, workspace_files(ws) yields the in-scope active
     * slice; we use that view throughout the command instead of building a separate
     * manifest.
     *
     * Pass state handle to workspace so it analyzes within our write transaction.
     * This ensures consistency and eliminates redundant database connections.
     */
    output_print(out, OUTPUT_VERBOSE, "\nLoading workspace...\n");

    /* Apply needs file AND directory divergence (deploy_plan_build derives both
     * kinds from the divergence index — an unanalyzed kind plans as clean) plus
     * orphan detection for cleanup. */
    workspace_load_t ws_opts = {
        .analyze_files       = true,
        .analyze_orphans     = true,
        .analyze_untracked   = false,            /* Skip expensive directory scan */
        .analyze_directories = true              /* Directory metadata convergence */
    };
    err = workspace_load(
        repo, state, config, content_cache, manifest, &ws_opts, ctx->arena, &ws
    );
    if (err) {
        err = error_wrap(err, "Failed to load workspace");
        goto cleanup;
    }

    /* Persist deployment-anchor advances for files verified clean via the slow
     * path, and observations of paths seen with no record. Within apply's
     * transaction — committed atomically with deployment changes. Routed through
     * workspace_anchor / workspace_observe, so each persisted update also lands
     * in the workspace's anchors snapshot — downstream readers in this run see
     * DB and memory agreeing. */
    err = workspace_flush_updates(ws);
    if (err) {
        err = error_wrap(err, "Failed to flush anchor updates");
        goto cleanup;
    }

    /* Both kinds: a scope of tracked directories alone is a workspace, not an
     * empty one. */
    char loaded[64];
    output_format_counts(
        workspace_files(ws).count, workspace_directories(ws).count,
        loaded, sizeof(loaded)
    );
    output_print(out, OUTPUT_VERBOSE, "Workspace loaded: %s\n", loaded);

    /* The claims the view could not place speak before the plan: they are in no
     * bucket below, and silence at the deploy moment is exactly what the old
     * hard error existed to prevent. One line per affected profile — the slice
     * arrives grouped, so a linear walk counts each run. */
    {
        manifest_unbound_t unbound = manifest_unbound(manifest);
        for (size_t i = 0; i < unbound.count;) {
            const char *profile = unbound.entries[i].profile;
            size_t n = 0;
            while (i + n < unbound.count &&
                strcmp(unbound.entries[i + n].profile, profile) == 0) n++;
            output_warning(
                out, OUTPUT_NORMAL,
                "Skipping %zu custom/ path%s of profile '%s' (no deployment target)",
                n, n == 1 ? "" : "s", profile
            );
            i += n;
        }
    }

    /* PLAN: decide once what deploy will do, from (workspace, scope).
     *
     * Every later consumer — preview, adoption, preflight, the prompt, execution
     * and the skipped report — reads this one object. The workspace already
     * computed fresh divergence for every active row; the planner gates each
     * row on scope and classifies it by deploy's work predicate into pending /
     * clean, or into one of the two skipped buckets (-e, --skip-existing). */
    output_print(out, OUTPUT_VERBOSE, "\nPlanning deployment...\n");

    err = deploy_plan_build(ws, scope, opts->skip_existing, &deploy_plan);
    if (err) {
        err = error_wrap(err, "Failed to plan deployment");
        goto cleanup;
    }

    /* Per-item trace of the work the planner skipped, by reason: -e for both
     * kinds, --skip-existing for files. output_print gates on the verbosity level,
     * so normal runs pay only the loop cost. */
    {
        manifest_rows_t excluded_files = manifest_rows_view(
            &deploy_plan->files.excluded
        );
        manifest_rows_t excluded_dirs = manifest_rows_view(
            &deploy_plan->directories.excluded
        );
        manifest_rows_t existing_files = manifest_rows_view(
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

    /* The plan's four counts, each only when it is non-zero — gated the way
     * cleanup's two lines below are, and by the preview's own rule: an empty
     * bucket has nothing to say, and says nothing (print_deploy_preview). */
    if (deploy_plan->files.pending.count > 0) {
        output_print(
            out, OUTPUT_VERBOSE, "  %zu %s deployment (missing or divergent)\n",
            deploy_plan->files.pending.count,
            deploy_plan->files.pending.count == 1 ? "file needs" : "files need"
        );
    }
    if (deploy_plan->files.clean.count > 0) {
        output_print(
            out, OUTPUT_VERBOSE, "  %zu file%s already up-to-date (skipped)\n",
            deploy_plan->files.clean.count,
            deploy_plan->files.clean.count == 1 ? "" : "s"
        );
    }
    if (deploy_plan->directories.pending.count > 0) {
        output_print(
            out, OUTPUT_VERBOSE, "  %zu %s convergence\n",
            deploy_plan->directories.pending.count,
            deploy_plan->directories.pending.count == 1 ? "tracked directory needs"
                                                        : "tracked directories need"
        );
    }
    if (deploy_plan->directories.clean.count > 0) {
        output_print(
            out, OUTPUT_VERBOSE, "  %zu tracked director%s already converged\n",
            deploy_plan->directories.clean.count,
            deploy_plan->directories.clean.count == 1 ? "y" : "ies"
        );
    }

    /* PLAN: decide once which orphans cleanup may touch, from (workspace, scope).
     *
     * Coherent Scope — the same operation-scope triplet the deployment planner
     * applies: orphans outside the profile / path dimensions are invisible; orphans
     * an -e pattern names are skipped and reported. The filter shapes that reach
     * the planner:
     *
     *   full sync (no filter)   every orphan converges — a disabled
     *                           profile's files, and files deleted from Git under
     *                           a profile that is still enabled
     *   profile scoped (-p)     only that profile's orphans; the rest wait
     *                           for an unfiltered apply
     *   path scoped             only the orphans the filter names — the
     *                           orphan at a file path, the orphans beneath a
     *                           directory path — so one orphan can be retired
     *                           without a whole-scope run. The filter changes
     *                           reach, never verdicts: a modified orphan named
     *                           by path is still skipped, a released one still
     *                           let go.
     *
     * --keep-orphans plans nothing. The empty plan is what every later stage
     * reads, so no stage re-encodes the flag. */
    output_print(out, OUTPUT_VERBOSE, "\nPlanning cleanup...\n");

    err = cleanup_plan_build(ws, scope, opts->keep_orphans, &cleanup_plan);
    if (err) {
        err = error_wrap(err, "Failed to plan cleanup");
        goto cleanup;
    }

    if (opts->keep_orphans) {
        output_print(out, OUTPUT_VERBOSE, "  Orphans kept (--keep-orphans)\n");
    }

    /* Mirror the deployment-loop trace: for each orphan skipped by --exclude,
     * emit a per-file line. output_print gates on the verbosity level, so
     * non-verbose runs pay only the loop cost. */
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

    /* Warn if a file filter was given but matched no managed path at all (skipped
     * rows count as matched — the filter found them). Asked after both planners:
     * a path can name an orphan as well as an active row, and finding either is
     * a match. */
    if (scope_has_paths(scope) && deploy_plan_row_count(deploy_plan) == 0 &&
        cleanup_plan_item_count(cleanup_plan) == 0) {
        output_warning(
            out, OUTPUT_NORMAL, "No matching paths found in enabled profiles"
        );
        output_hint(
            out, OUTPUT_NORMAL, "Check if the path is correct and profile is enabled"
        );
    }

    /* Collect the pending profile reassignments and count the stale files, off
     * the plan.
     *
     * Both are facts the planner read from the item and did not carry — the plan
     * says what the run does, the item says why — so the planned rows are walked
     * once more, each paired with its item. The four buckets, both kinds, are
     * exactly the rows whose record this run's ownership events rewrite: the
     * clean ones by the adoption and acknowledgement loops below, the pending
     * ones by the record step behind the deployment. The collection takes two
     * moments, one per writer: the clean half here, before the loops rewrite
     * the record the fact is read against, materialized so no print moment re-reads
     * it; the pending half off the verdicts after preflight, whose fates already
     * exclude the skips and whose item is this same analysis object — nothing
     * rewrites a pending row's record before the record step, so nothing is lost
     * by reading it late, and what the preview names is what the receipt counts.
     * One array, sized to the four buckets (the verdicts are a subset of the
     * pending rows), two fills, one print. A row the plan skips (-e,
     * --skip-existing) is in no bucket and is neither previewed nor counted:
     * the run will not acknowledge it. The scope is not re-derived — the planner
     * applied it once, and the buckets are its answer. Collected before the early
     * exit so a reassignment-only workspace is reported and acknowledged there
     * too — an empty plan has no pending rows, so the clean half is the whole
     * of it there.
     *
     * A reassignment is the workspace's reading of the record against the row —
     * the record dotta owns names one profile, the row another — and one of the
     * two reasons a deploy-clean row has an item at all (the other is the
     * blob-family ENCRYPTION bit, which neither loop here reads). DIVERGENCE_STALE
     * is the workspace's verdict that Git moved past the blob dotta last deployed
     * (anchor.blob_oid ≠ row.blob_oid) — a persistent signal that survives
     * status→apply sequences and counts the same however the branch moved; work
     * by definition, so only a pending row carries it, and only a file: a directory
     * has no blob for Git to move, so the kind-blind read below never counts
     * one. */
    size_t stale_count = 0;
    size_t reassigned_count = 0;
    reassignment_t *reassigned = NULL;
    const struct { manifest_rows_t rows; bool clean; } claimed[] = {
        { manifest_rows_view(&deploy_plan->files.clean),         true  },
        { manifest_rows_view(&deploy_plan->files.pending),       false },
        { manifest_rows_view(&deploy_plan->directories.clean),   true  },
        { manifest_rows_view(&deploy_plan->directories.pending), false },
    };

    size_t claimed_total = 0;
    for (size_t b = 0; b < sizeof(claimed) / sizeof(claimed[0]); b++) {
        claimed_total += claimed[b].rows.count;
    }
    if (claimed_total > 0) {
        reassigned = arena_alloc(ctx->arena, claimed_total * sizeof(*reassigned));
        if (!reassigned) {
            err = ERROR(ERR_MEMORY, "Failed to allocate reassignment collection");
            goto cleanup;
        }
    }

    for (size_t b = 0; b < sizeof(claimed) / sizeof(claimed[0]); b++) {
        for (size_t i = 0; i < claimed[b].rows.count; i++) {
            const workspace_item_t *item = workspace_get_item(
                ws, claimed[b].rows.entries[i]->filesystem_path
            );
            if (!item) continue;   /* no item: nothing stale, no reassignment */

            if (item->divergence & DIVERGENCE_STALE) stale_count++;

            /* The pending half reads the verdicts, after preflight. The stale
             * count above stands for every planned row, a row preflight will
             * skip included — STALE is the record against Git, no observation
             * involved, and preflight's answer does not change it. */
            if (!claimed[b].clean) continue;

            /* A clean row observed through a displaced managed directory is not
             * acknowledged this run (the adoption and acknowledgement loops take
             * the same gate, row-keyed; the field on this item is that gate's
             * answer at its path), so the preview must not promise it. */
            if (item->displaced != WORKSPACE_DISPLACED_NONE) continue;

            if (workspace_item_reassigned(item)) {
                reassigned[reassigned_count++] = (reassignment_t){
                    .path = item->filesystem_path,
                    .from = item->anchor->profile,
                    .to = item->profile,
                    .kind = item->item_kind,
                };
            }
        }
    }

    /* One moment for everything this run records — the adoption loop below and
     * the post-deploy record after the plan — so a run's ownership events carry
     * one timestamp. */
    time_t now = time(NULL);

    /* Apply-level adoption and acknowledgement: the ownership events for in-scope
     * clean files.
     *
     * A clean in-scope row whose record has deployed_at == 0 — or no record at
     * all — represents a file the user declared scope over (via profile enable
     * or add/update) AND that analyze_file_divergence just classified as clean
     * for deploy's purposes: no item, or one carrying only the blob-family
     * ENCRYPTION bit deploy_needs_work masks out. Apply is the ownership moment:
     * running it is how the user claims the in-scope set. Stamping here collapses
     * the "enable → apply on a pre-existing matching file" flow to a coherent
     * (blob, now, stat), so a later `rm file` is classified as [deleted] and
     * `update` commits the deletion. The stat is the analysis's own — the snapshot
     * pair, when it vouches for this row's blob — never a fresh lstat, which
     * would bind whatever stands at the path now to a verdict from two phases
     * earlier.
     *
     * A clean row whose record dotta owns under another profile is a reassignment:
     * disk holds what A deployed, B owns the path now, and the content is the
     * same. It sits in files.clean by construction (nothing to deploy), so this
     * loop is the one place its record is re-stamped under B — the acknowledgement.
     * Same write, same stat, one more counter; a stale reassignment is acknowledged
     * by its deployment and counted after the record step below.
     *
     * Division of labor with the earlier flush: the proof of this run's match
     * comes from analyze_file_divergence leaving the entry out of ws->diverged,
     * and workspace_flush_updates above put the pair that proof rests on where
     * this loop can read it — a slow-path CMP_EQUAL patched onto the snapshot
     * record, a recordless clean row's record created by the observation and
     * confirmed in the same flush. A confirmation rewrites neither deployed_at
     * nor the record's profile, so both remain valid probes here; DB and in-memory
     * views are kept coherent by workspace_anchor.
     *
     * Placement rationale: MUST run before the nothing-to-do early exit below,
     * otherwise the canonical case (clean manifest, no orphans) never reaches
     * any anchor-writer. The writes land in the dispatch transaction, which the
     * checkpoint below commits — on every path, the early exit included.
     *
     * Write gated by !dry_run: stamping deployed_at is a write-effect that
     * contradicts dry-run's read-only ownership contract, so the workspace_anchor
     * call is skipped. Classification runs regardless, so --dry-run previews
     * "Would adopt N file(s)".
     *
     * deploy_plan->files.clean IS "in scope ∧ no work" — no gates re-derived
     * here. */
    size_t adopted_count = 0;
    size_t acknowledged_count = 0;
    manifest_rows_t adoptable = manifest_rows_view(&deploy_plan->files.clean);

    for (size_t i = 0; i < adoptable.count; i++) {
        const manifest_row_t *file = adoptable.entries[i];

        /* Observed through a displaced managed directory: what read clean was
         * the squatter's target, not this path. Adopting it would set deployed_at
         * on a path dotta never put there and hand a stranger's file to the prune
         * at the next scope exit; an acknowledgement would re-stamp an owned
         * record with a proof the observation cannot give. The handover stays
         * pending until a run converges the ancestor. Row-keyed: a clean row
         * has no item to carry the fact, and the probe answers view-side, which
         * is what the field on an item would say (workspace_displaced_t). */
        if (workspace_displaced_ancestor(ws, file->filesystem_path)) continue;

        const anchor_t *anchor = workspace_get_anchor(ws, file->filesystem_path);
        bool adopt = !anchor || anchor->deployed_at == 0;
        bool acknowledge = !adopt && strcmp(anchor->profile, file->profile) != 0;
        if (!adopt && !acknowledge) continue;

        if (!opts->dry_run) {
            /* The snapshot pair vouches for this row's blob on every route a
             * clean row can arrive by — fast-path hit, slow-path confirmation,
             * record created and confirmed by the flush — except a confirmation
             * dropped under memory pressure, whose anchor still carries an older
             * pair. The gate asks the snapshot itself; NULL advances the record
             * blob-only, and the next load's slow path confirms. */
            const stat_cache_t *stat =
                (anchor && git_oid_equal(&anchor->blob_oid, &file->blob_oid))
                ? &anchor->stat : NULL;

            error_t *anchor_err = workspace_anchor(ws, file, stat, now);
            if (anchor_err) {
                /* Non-fatal: file is correct on disk; next status's slow-path
                 * CMP_EQUAL re-confirms the record, and the row will be re-adopted
                 * (or the reassignment re-acknowledged) on the next apply. */
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to anchor %s: %s",
                    file->filesystem_path, error_message(anchor_err)
                );
                error_free(anchor_err);
                continue;  /* Failed writes don't count — preview still accurate */
            }
        }
        if (adopt) adopted_count++;
        else acknowledged_count++;
    }
    if (adopted_count > 0) {
        output_styled(
            out, OUTPUT_NORMAL,
            opts->dry_run ? "Would adopt {yellow}%zu{reset} file%s\n"
                          : "Adopted {yellow}%zu{reset} file%s (now tracked)\n",
            adopted_count, adopted_count == 1 ? "" : "s"
        );
    }

    /* The directory half of the acknowledgement — and only that half. A clean
     * in-scope directory row whose owned record names another profile is the
     * same pending handover a file row is, and this loop is the one place its
     * record is re-stamped under the row's profile (same derivation as the file
     * loop's, its inputs in hand; NULL stat — a directory has none). The adopt
     * half is deliberately not taken: capture (add, update) is the ownership
     * event for a directory, apply's observation is not — an apply that adopted
     * every pre-existing clean parent would own it and prune it at scope exit.
     * A recordless clean directory stays the flush's observation, exactly as
     * before. */
    manifest_rows_t ackable = manifest_rows_view(&deploy_plan->directories.clean);

    for (size_t i = 0; i < ackable.count; i++) {
        const manifest_row_t *dir = ackable.entries[i];

        /* The file loop's displaced gate, same rationale — and row-keyed for
         * the same reason. */
        if (workspace_displaced_ancestor(ws, dir->filesystem_path)) continue;

        const anchor_t *anchor = workspace_get_anchor(ws, dir->filesystem_path);
        bool acknowledge = anchor && anchor->deployed_at > 0 &&
            strcmp(anchor->profile, dir->profile) != 0;
        if (!acknowledge) continue;

        if (!opts->dry_run) {
            error_t *anchor_err = workspace_anchor(ws, dir, NULL, now);
            if (anchor_err) {
                /* Non-fatal, the file loop's stance: the reassignment is
                 * re-acknowledged on the next apply. */
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to anchor %s: %s",
                    dir->filesystem_path, error_message(anchor_err)
                );
                error_free(anchor_err);
                continue;  /* Failed writes don't count — preview still accurate */
            }
        }
        acknowledged_count++;
    }

    /* How many in-scope files Git has moved since dotta deployed them. [stale]
     * alone the plan deploys like any other divergence; beside [modified] it is
     * a conflict preflight reports. Released files are covered by the orphan-prune
     * summary below. */
    if (stale_count > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Found %zu stale file%s (changed in Git since deployment)",
            stale_count, stale_count == 1 ? "" : "s"
        );
    }

    /* Everything the plans withheld, said once — above the exit below, so a run
     * whose only work was withheld still reports it, and above the prompt, so
     * consent is given with the full picture. The count below is the same four
     * buckets: the nothing-to-do line must not call a workspace clean when its
     * only work was withheld. ("Withheld" is the plan-time word — the user's
     * own flags, -e and --skip-existing; "skipped" is preflight's, a fate the
     * run decided.) */
    print_withheld(out, deploy_plan, cleanup_plan);
    size_t withheld = deploy_plan->files.excluded.count +
        deploy_plan->directories.excluded.count + cleanup_plan->excluded.count +
        deploy_plan->files.skipped_existing.count;

    /* Checkpoint: the run's reading of the present is complete, and recorded
     *
     * Everything written so far is a fact about the load — the flush's observations
     * and confirmations, and the ownership events above, which claim rows the
     * analysis found clean — and it stays a fact whatever the rest of the run
     * does. What follows can end without writing anything else: the nothing-to-do
     * exit below, a strict_ownership error, a hook that refuses, a declined prompt.
     * The dispatch transaction is committed here so that none of those exits
     * rolls the present back — "Adopted N files" has already been said, and the
     * record must say it too, or the next run adopts them again and the next
     * status reads a path the load observed as never seen. Dry run included:
     * its flush is as true as a real run's, and status persists the same writes.
     *
     * The record of the run's own effects — the anchors the deployment writes,
     * the records cleanup retires — is the run's second transaction, begun past
     * the early exit and committed at the end. */
    err = state_save(state);
    if (err) {
        err = error_wrap(err, "Failed to commit state changes");
        goto cleanup;
    }

    /* Nothing pends on the filesystem: report the bookkeeping (if any) and leave.
     * Privilege checks, preflight, hooks and the prompt are for runs that touch
     * disk — pure state bookkeeping skips them. Nothing is written past the
     * checkpoint, so there is nothing left to save. */
    if (deploy_plan_is_empty(deploy_plan) && cleanup_plan_is_empty(cleanup_plan)) {
        if (reassigned_count > 0) {
            print_reassignments(out, reassigned, reassigned_count);
            if (opts->dry_run) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Would acknowledge %zu profile reassignment%s",
                    reassigned_count, reassigned_count == 1 ? "" : "s"
                );
            } else if (acknowledged_count > 0) {
                output_styled(
                    out, OUTPUT_NORMAL,
                    "Acknowledged {cyan}%zu{reset} profile reassignment%s\n",
                    acknowledged_count, acknowledged_count == 1 ? "" : "s"
                );
            }
        } else if (withheld > 0) {
            /* The report above named what and why; this only has to avoid claiming
             * the work was never there. */
            output_info(out, OUTPUT_NORMAL, "Nothing left to deploy");
        } else if (scope_has_filter(scope) || scope_has_paths(scope)) {
            output_info(out, OUTPUT_NORMAL, "Nothing to deploy (no pending work in scope)");
        } else {
            output_info(out, OUTPUT_NORMAL, "Nothing to deploy (workspace is clean)");
        }

        err = NULL;
        goto cleanup;
    }

    /* The run's transaction: the record of what the two engines do, committed
     * at the end. Begun here rather than at the first write so the lock the
     * dispatcher took is this process's again across the preview, the prompt
     * and the execution — two applies must not interleave, and a status must
     * not record paths this run is rewriting. */
    err = state_begin(state);
    if (err) {
        err = error_wrap(err, "Failed to begin the run's state transaction");
        goto cleanup;
    }

    /* Decide deploy's verdicts from the plan, and the skips the run reports
     *
     * Divergence verdicts and occupants come from workspace_load's analysis (O(1)
     * index probes); the landing check is filesystem-level. The mode and ownership
     * every write applies are decided here too — deployable rows alone — so a
     * strict_ownership failure ends the run before the prompt (the wrap below
     * is for such real errors; a skip is not one), and the anomalies met on the
     * way — an owner this system does not know — print as warnings closing the
     * preview.
     */
    /* The trailing blank is this heading's own: the first preview section after
     * it is the run's first section, so output_section has no separator to emit
     * (has_content is still false). "Executing deployment plan..." needs none —
     * by then the preview has printed and the separator comes for free. */
    output_print(out, OUTPUT_VERBOSE, "\nRunning pre-flight checks...\n\n");

    deploy_options_t deploy_opts = {
        .force            = opts->force,
        .strict_ownership = config->strict_ownership,
    };

    err = deploy_preflight(ws, deploy_plan, &deploy_opts, &deploy_verdicts);
    if (err) {
        err = error_wrap(err, "Pre-flight checks failed");
        goto cleanup;
    }

    /* Decide cleanup's verdicts from the plan. An empty plan (--keep-orphans,
     * no orphans in scope) yields empty verdicts and a silent preview — no gate
     * needed anywhere. */
    err = cleanup_preflight(ws, cleanup_plan, opts->force, &cleanup_verdicts);
    if (err) {
        err = error_wrap(err, "Cleanup preflight checks failed");
        goto cleanup;
    }

    /* The pending half of the collection, off the verdicts: a row preflight skipped
     * is not here — its handover rides a deployment that will not happen — and
     * a deployable row's record is rewritten only by the record step, after this
     * is printed. The item is the verdict's, verbatim (deploy_verdict_t): NULL
     * where the index holds nothing, and its join facts sound wherever it is
     * not. The ancestors are outside the plan and stay uncounted, as the record
     * step leaves them. */
    const deploy_verdicts_t *kinds[] = {
        &deploy_verdicts->files,
        &deploy_verdicts->directories,
    };

    for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
        for (size_t i = 0; i < kinds[k]->count; i++) {
            const workspace_item_t *item = kinds[k]->entries[i].item;

            if (item && workspace_item_reassigned(item)) {
                reassigned[reassigned_count++] = (reassignment_t){
                    .path = item->filesystem_path,
                    .from = item->anchor->profile,
                    .to = item->profile,
                    .kind = item->item_kind,
                };
            }
        }
    }

    /* The previews: the reassignments the run acknowledges, then each engine's
     * story told the same way — what it will do (the preview, every caveat on
     * the promise with it), then what it will not and why (the skips, closing
     * with their remedies) — read the same way in a real run and a dry run. */
    print_reassignments(out, reassigned, reassigned_count);
    print_deploy_preview(out, deploy_verdicts);
    print_deploy_skips(out, deploy_verdicts, sudo_hint);
    print_cleanup_preview(out, cleanup_verdicts);
    print_cleanup_skips(out, cleanup_verdicts);
    print_cleanup_refused(out, cleanup_verdicts, sudo_hint);

    /* The previews are over: one blank before whatever follows — the prompt, a
     * dry run's tail, the run's trace. Unconditional, because past the
     * nothing-to-do exit some plan is non-empty, a non-empty plan yields a
     * non-empty fate set on its side (the two totality equations), and a non-empty
     * fate set prints a section. */
    output_newline(out, OUTPUT_NORMAL);

    /* Neither engine's skips abort: what can be deployed is deployed, what can
     * be pruned is pruned, and what cannot is named with its remedy — better
     * than doing nothing. Both previews above counted the skips and printed their
     * remedies, and both executors act on these same verdicts, so there is nothing
     * to add here. What the run planned and could not deliver reaches the exit
     * code at the run's tail. */

    /* Build hook invocation with all active profiles */
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_APPLY,
        .profile    = profiles_str,
        .files      = NULL,
        .file_count = 0,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-apply hook */
    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /* Confirm before deployment if configured (unless --force or --dry-run) */
    if (config->confirm_destructive && !opts->force && !opts->dry_run) {
        char prompt[512];   /* Larger buffer for enhanced prompt */

        /* Every number is a verdict count, and the two previews printed exactly
         * these — so what the user consents to is what runs. Directory pruning
         * can be the only pending action (no files move). */
        size_t prune_file_count = cleanup_verdicts->prunable_files.count;
        size_t prune_dir_count = cleanup_verdicts->prunable_dirs.count;

        /* Compose the prompt from the non-zero parts — "Deploy 2 files, converge
         * 1 tracked directory and prune 3 orphaned files?". No part means every
         * pending action is state-only reclamation (e.g. an all-absent orphan
         * set) — non-destructive, no consent needed. The one destructive deploy
         * verb, a replace, never reaches this prompt: it needs --force, and --force
         * is the consent. */
        size_t deploy_count = deploy_verdicts->files.count;
        size_t converge_count = deploy_verdicts->directories.count;

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
            /* One verdict, said once: with a file part above, the verb carries
             * across the conjunction — "prune 2 orphaned files and 2 orphaned
             * directories" — rather than naming it twice. The directory part is
             * always last, so nothing follows to strand the elided verb. */
            snprintf(
                parts[part_count++], sizeof(parts[0]), "%s%zu orphaned director%s",
                prune_file_count > 0 ? "" : "prune ",
                prune_dir_count, prune_dir_count == 1 ? "y" : "ies"
            );
        }

        if (part_count > 0) {
            /* ", " between parts, " and " before the last; four parts of at most
             * 63 bytes fit the buffer with room to spare */
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

    /* A dry run ends here. Both previews have printed, and neither engine is
     * called: the verdicts are the run's decisions, and executing would teach a
     * dry run nothing it does not already know. Everything below is for the run
     * that writes — the two engines, then the record of what they did. */
    if (opts->dry_run) {
        output_print(out, OUTPUT_VERBOSE, "Dry-run mode - no paths will be modified\n");
    } else {
        /* Carry the verdicts out (files-only, directories-only, or mixed — one
         * call). Reporting reads the result: outcomes, never plan counts. The
         * gate is verdict truth, not plan truth — a plan whose every row was
         * skipped carries no work — and a run the skips emptied stays silent:
         * the skip block was its whole story, and "no work in scope" would misname
         * it. */
        if (deploy_verdicts->files.count + deploy_verdicts->directories.count > 0) {
            output_print(out, OUTPUT_VERBOSE, "Executing deployment plan...\n");

            /* The content cache was populated with decrypted content during
             * workspace divergence analysis; deploy's fetches hit it. */
            err = deploy_execute(repo, ws, deploy_verdicts, content_cache, &deploy_result);

            if (deploy_result) {
                print_deploy_results(out, deploy_result);
            }
            if (err) {
                /* Infrastructure, never a row — a row's own failure is in the
                 * receipt's failed bucket, and the run goes on to record what
                 * landed. Which infrastructure, the receipt's presence tells:
                 * without one its allocation failed and nothing ran — nothing
                 * to record, the run ends. With one every row ran and only the
                 * release of held modes failed: the directory stands at its working
                 * mode, wider by the owner's own bits alone, and the next load
                 * reads the mode divergence and converges it — while the writes
                 * that landed must still be recorded, or the record loses them
                 * and a later scope exit releases what it should prune. Warned
                 * like the cleanup failure below: the exit fold reads receipts,
                 * never errors. */
                if (!deploy_result) {
                    err = error_wrap(err, "Deployment failed");
                    goto cleanup;
                }
                output_warning(
                    out, OUTPUT_NORMAL, "%s; the next apply converges it",
                    error_message(err)
                );
                error_free(err);
                err = NULL;
            }
        } else if (deploy_verdicts->skipped.count == 0) {
            output_print(out, OUTPUT_VERBOSE, "No deployment work in scope\n");
        }

        /* Prune the orphans the verdicts cleared, then settle the records: what
         * the run found gone (the receipt), what was gone before it began and
         * what it let go (the verdicts).
         *
         * cleanup_execute changes the filesystem only; apply, as the transaction
         * owner, settles the records behind what went and what was let go. The
         * flow for an orphan: the path leaves the view (profile disabled, branch
         * moved, target changed) → the workspace reads its record as an orphan
         * and asks Git why → the verdict → this block → record retired, completing
         * the cycle. Without it, orphaned records accumulate forever in the
         * path_anchors table.
         *
         * Non-fatal: the deployment's landed writes must be recorded and saved
         * regardless, or the database would show deployed files as undeployed
         * and the user would see [undeployed] on working files. The engine's
         * one error is its receipt's allocation — nothing ran, nothing to record
         * — and the next apply re-reads the prunable orphans. */
        error_t *prune_err = cleanup_execute(cleanup_verdicts, &cleanup_result);
        if (prune_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Orphan cleanup failed: %s",
                error_message(prune_err)
            );
            error_free(prune_err);
        }

        /* Which outcomes settle is cleanup's rule, read off its receipt and its
         * verdicts (cleanup.h); the act is apply's. Kind decides nothing here —
         * reason decides the verb: a gone copy (pruned, reclaimed, absent) plainly
         * retires, there is no fact to keep; a let-go copy (released) still stands
         * on disk, so its record's content-proof is kept through state_release
         * — except where the copy provably is not, or may not be, dotta's: a
         * TYPE-displaced item's path holds another kind of node, and a path beneath
         * a displaced managed directory was only ever observed through the
         * squatter, so what stands there is the link target's, whatever the bytes
         * said. Either way the released fact would be false at birth, and the
         * item takes the plain retire (a released directory needs no carve-out
         * — the release verb's blob guard makes it a plain retire on its own).
         * Non-fatal per row: the filesystem effect, if any, already happened,
         * and a record that fails to settle is reported and read as an orphan
         * again by the next apply. */
        if (cleanup_result) {
            print_cleanup_results(out, cleanup_verdicts, cleanup_result);

            /* What the run found gone: pruned, or gone by the time it looked */
            const cleanup_outcomes_t *gone[] = {
                &cleanup_result->pruned_files,
                &cleanup_result->reclaimed_files,
                &cleanup_result->pruned_dirs,
                &cleanup_result->reclaimed_dirs,
            };
            for (size_t b = 0; b < sizeof(gone) / sizeof(gone[0]); b++) {
                for (size_t i = 0; i < gone[b]->count; i++) {
                    const workspace_item_t *item = gone[b]->entries[i].item;

                    error_t *retire_err = state_retire_anchor(state, item->filesystem_path);
                    if (retire_err) {
                        output_warning(
                            out, OUTPUT_NORMAL, "Failed to retire state entry for %s: %s",
                            item->filesystem_path, error_message(retire_err)
                        );
                        error_free(retire_err);
                    }
                }
            }
        }

        /* The verdicts' own, settled whether or not the prune engine could start:
         * neither needed an effect. The receipt's printer told them above when
         * it did; on the one run whose warning said nothing ran, they settle
         * unreported. First what was gone before the run began. */
        const workspace_items_t absent[] = {
            workspace_items_view(&cleanup_verdicts->absent_files),
            workspace_items_view(&cleanup_verdicts->absent_dirs),
        };
        for (size_t b = 0; b < sizeof(absent) / sizeof(absent[0]); b++) {
            for (size_t i = 0; i < absent[b].count; i++) {
                const workspace_item_t *item = absent[b].entries[i];

                error_t *retire_err = state_retire_anchor(state, item->filesystem_path);
                if (retire_err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to retire state entry for %s: %s",
                        item->filesystem_path, error_message(retire_err)
                    );
                    error_free(retire_err);
                }
            }
        }

        /* Then what the run let go. */
        const workspace_items_t let_go[] = {
            workspace_items_view(&cleanup_verdicts->released_files),
            workspace_items_view(&cleanup_verdicts->released_dirs),
        };
        for (size_t b = 0; b < sizeof(let_go) / sizeof(let_go[0]); b++) {
            for (size_t i = 0; i < let_go[b].count; i++) {
                const workspace_item_t *item = let_go[b].entries[i];

                error_t *settle_err = ((item->divergence & DIVERGENCE_TYPE) ||
                    item->displaced != WORKSPACE_DISPLACED_NONE)
                    ? state_retire_anchor(state, item->filesystem_path)
                    : state_release(state, item->filesystem_path);
                if (settle_err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to settle state entry for %s: %s",
                        item->filesystem_path, error_message(settle_err)
                    );
                    error_free(settle_err);
                }
            }
        }

        /* Record what the run did, path by path
         *
         * CRITICAL: This writes the record for each path deploy touched — for a
         * file, the blob dotta just wrote, the ownership timestamp, and the stat
         * triple used by the fast path on subsequent runs. The record is the
         * authoritative "dotta confirmed disk == this blob" / "dotta made this"
         * account.
         *
         * IMPORTANT: This operation runs REGARDLESS of cleanup success/failure.
         * - The landed writes are physically on the filesystem
         * - State must reflect what landed
         * - Cleanup failure does NOT invalidate what landed
         * - This prevents state desynchronization (deployed files marked as
         *   undeployed)
         *
         * Non-critical operation: the landed writes already happened physically,
         * so record-write failures are non-fatal warnings (preserve consistency).
         *
         * The receipt is the whole of it, and the ownership rule is read off
         * each carried-out fate, never off a bucket topology:
         *   deployed                  files written or linked — an owned anchor
         *                             carrying the write's own proof: the receipt's
         *                             triple, distilled by the executor from
         *                             the fstat of the bytes it put there
         *                             (stat_cache_from_write — authorship needs
         *                             no closed second). A symlink's is UNSET,
         *                             the same statement as NULL to state_anchor:
         *                             a link is made by path, no descriptor exists
         *                             to describe it, and readlink is its whole
         *                             re-verification
         *   converged, made           a directory whose convergence is not a fix
         *   (a create or a replace)   (deploy_convergence) — dotta made it, where
         *                             nothing stood or in a squatter's place —
         *                             an owned anchor; a directory has no blob
         *                             and no stat
         *   converged in place        dotta did not make it, and it was present at
         *   (a fix)                   load, so the flush has already observed any
         *                             that had no record: nothing to write, with
         *                             one exception — a pending handover must
         *                             not outlive the run that converged the
         *                             directory, so a reassigned row takes the
         *                             one anchor that acknowledges it. Anchoring
         *                             it as owned would set deployed_at on a
         *                             directory the user made and hand it to
         *                             the prune on the next scope exit
         *   ancestors                 claimed parents made on the way, either
         *                             class — dotta made them too, an owned anchor
         * Every other active directory present on disk was present at load too,
         * and has its record from the flush by the same argument; the load
         * established presence at the boundary, and nothing here walks the disk
         * to establish it again.
         *
         * A deployed file — or a converged directory — whose item read [reassigned]
         * had its record rewritten under the row's profile by the write just
         * made; each is derived before its anchor (the write rewrites the record
         * the fact is read against) and counted with the clean ones the adoption
         * and acknowledgement loops re-stamped. Ancestors' anchors stay uncounted:
         * they are outside the plan, so the collection never previewed them,
         * and an acknowledgement that rides one heals the record silently.
         */
        if (deploy_result) {
            deploy_outcomes_t deployed = deploy_result->deployed;

            for (size_t i = 0; i < deployed.count; i++) {
                const deploy_outcome_t *o = &deployed.entries[i];
                const manifest_row_t *file = o->verdict->row;

                /* Derived before anchoring: the write below rewrites the record
                 * the reassignment fact is read against. */
                const workspace_item_t *item = o->verdict->item;
                bool acknowledges = item && workspace_item_reassigned(item);

                error_t *anchor_err = workspace_anchor(ws, file, &o->stat, now);
                if (anchor_err) {
                    /* Non-fatal warning - the write landed, just anchor update
                     * failed. The file is already on the filesystem with correct
                     * content. Failure here should not abort the entire
                     * operation. */
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to update anchor for %s: %s",
                        file->filesystem_path, error_message(anchor_err)
                    );
                    error_free(anchor_err);
                    continue;
                }

                if (acknowledges) acknowledged_count++;
            }

            deploy_outcomes_t converged = deploy_result->converged;
            for (size_t i = 0; i < converged.count; i++) {
                const deploy_outcome_t *o = &converged.entries[i];
                const manifest_row_t *dir = o->verdict->row;
                bool made = deploy_convergence(o->verdict->occupant) != DEPLOY_CONVERGE_FIX;

                const workspace_item_t *item = o->verdict->item;
                bool acknowledges = item && workspace_item_reassigned(item);

                if (!made && !acknowledges) continue;

                error_t *anchor_err = workspace_anchor(ws, dir, NULL, now);
                if (anchor_err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to update anchor for %s: %s",
                        dir->filesystem_path, error_message(anchor_err)
                    );
                    error_free(anchor_err);
                    continue;
                }

                if (acknowledges) acknowledged_count++;
            }

            deploy_outcomes_t ancestors = deploy_result->ancestors;
            for (size_t i = 0; i < ancestors.count; i++) {
                const manifest_row_t *dir = ancestors.entries[i].verdict->row;

                error_t *anchor_err = workspace_anchor(ws, dir, NULL, now);
                if (anchor_err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to update anchor for %s: %s",
                        dir->filesystem_path, error_message(anchor_err)
                    );
                    error_free(anchor_err);
                }
            }
        }

        /* The released-copies sweep: disk-side retirement of the facts whose
         * condition provably ended. A fresh read — the run's own release writes
         * included — then one lstat per row, each forget clause a truth statement:
         * an absent path took the fact's copy with it; a live size that differs
         * from the recorded triple's proves the bytes are not the blob's (a deploy
         * this run wrote over a released-base stale path lands here). Everything
         * else keeps — a same-size drift or an UNSET triple (mtime == 0: no usable
         * size to test) is possibly still true and the read verifies before
         * trusting, and a failed look (EACCES, ...) never retires a fact.
         * Bookkeeping only, never a filesystem effect, so it is apply's own —
         * not a cleanup.c concern — and non-fatal like the record step around
         * it. */
        {
            released_copy_t *copies = NULL;
            size_t copy_count = 0;
            error_t *sweep_err = state_get_released_copies(
                state, ctx->arena, &copies, &copy_count
            );
            if (sweep_err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Released-copies sweep skipped: %s",
                    error_message(sweep_err)
                );
                error_free(sweep_err);
            }

            for (size_t i = 0; i < copy_count; i++) {
                const released_copy_t *copy = &copies[i];

                struct stat live;
                fs_occupant_t occupant = fs_lstat_occupant(copy->filesystem_path, &live);

                bool dead = occupant == FS_OCCUPANT_NONE ||
                    (occupant != FS_OCCUPANT_UNKNOWN && copy->stat.mtime != 0 &&
                    (int64_t) live.st_size != copy->stat.size);
                if (!dead) continue;

                sweep_err = state_forget_released(state, copy->filesystem_path);
                if (sweep_err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to forget released copy for %s: %s",
                        copy->filesystem_path, error_message(sweep_err)
                    );
                    error_free(sweep_err);
                    continue;
                }
            }
        }
    }

    /* The reassignments this run acknowledged, both kinds: the clean ones the
     * adoption and acknowledgement loops re-stamped, the pending ones the record
     * step rewrote behind the run's own writes (deployed files; converged
     * directories). Dry-run previews the in-scope set the preview named. */
    if (opts->dry_run) {
        if (reassigned_count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Would acknowledge %zu profile reassignment%s",
                reassigned_count, reassigned_count == 1 ? "" : "s"
            );
        }
    } else if (acknowledged_count > 0) {
        output_styled(
            out, OUTPUT_NORMAL, "Acknowledged {cyan}%zu{reset} profile reassignment%s\n",
            acknowledged_count, acknowledged_count == 1 ? "" : "s"
        );
    }

    /* Commit the run's transaction: the anchors the deployment wrote and the
     * records cleanup retired (partial success model — a cleanup failure leaves
     * the record's writes to commit). The present was committed at the checkpoint;
     * a dry run's transaction is empty and the save only closes it. */
    err = state_save(state);
    if (err) {
        err = error_wrap(err, "Failed to commit state changes");
        goto cleanup;
    }

    /* Execute post-apply hook */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* The receipt is printed; what remains is the return value. The plan is the
     * run's promise: a row the user's own flags withheld (-e, --skip-existing)
     * or that dotta held for want of consent (--force) was never promised, and
     * the receipt is the whole of its report; a row the run planned and could
     * not deliver was promised, and the exit code says so — the incapacity skips,
     * and the rows the run could not land (the receipt's failed bucket) — as
     * does an orphan the run tried to prune and could not (failed_prunes, off
     * cleanup's receipt). The execution halves are facts a dry run does not have,
     * so `apply -n` predicts the preflight half alone. Every skip and failure
     * was already rendered where it happened, so the error carries the one fact
     * the receipt does not — that the run did not keep its promise. ERR_FS, not
     * ERR_CONFLICT: the class is filesystem incapacity, and a conflict no longer
     * ends the run. */
    size_t undelivered = 0;

    for (size_t i = 0; i < deploy_verdicts->skipped.count; i++) {
        if (!deploy_skip_needs_force(deploy_verdicts->skipped.entries[i].reason)) {
            undelivered++;
        }
    }
    if (deploy_result) {
        undelivered += deploy_result->failed.count;
    }

    /* Attempted and refused only — the skipped orphans stay out: cleanup's plan
     * is permission, not obligation (cleanup_result_t's exit contract, the table
     * both engines draw). */
    size_t failed_prunes = 0;

    if (cleanup_result) {
        failed_prunes = cleanup_result->failed.count;
    }

    if (undelivered > 0 && failed_prunes > 0) {
        err = ERROR(
            ERR_FS, "%zu path%s could not be deployed, %zu orphan%s could not be pruned",
            undelivered, undelivered == 1 ? "" : "s",
            failed_prunes, failed_prunes == 1 ? "" : "s"
        );
    } else if (undelivered > 0) {
        err = ERROR(
            ERR_FS, "%zu path%s could not be deployed",
            undelivered, undelivered == 1 ? "" : "s"
        );
    } else if (failed_prunes > 0) {
        err = ERROR(
            ERR_FS, "%zu orphan%s could not be pruned",
            failed_prunes, failed_prunes == 1 ? "" : "s"
        );
    }

cleanup:
    /* Each engine's objects in reverse construction order: the receipt borrows
     * the fates, and the fates and the plan borrow the workspace's rows and items
     * — everything before workspace_free. */
    if (deploy_result) deploy_result_free(deploy_result);
    if (deploy_verdicts) deploy_preflight_result_free(deploy_verdicts);
    if (deploy_plan) deploy_plan_free(deploy_plan);
    if (cleanup_result) cleanup_result_free(cleanup_result);
    if (cleanup_verdicts) cleanup_preflight_result_free(cleanup_verdicts);
    if (cleanup_plan) cleanup_plan_free(cleanup_plan);
    if (profiles_str) free(profiles_str);
    free(sudo_hint);
    if (ws) workspace_free(ws);
    if (scope) scope_free(scope);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/* Command-local positional classes. Start at 1 to reserve 0 for the engine's
 * "unclassified" sentinel (see args.h:args_class_t). */
enum apply_class { APPLY_CLASS_FILE = 1, APPLY_CLASS_PROFILE, };

/**
 * Positional classifier: file-like tokens go to files[]; everything else is treated
 * as a profile name.
 */
static args_class_t apply_classify(const char *tok) {
    return str_looks_like_file_path(tok) ? APPLY_CLASS_FILE
                                         : APPLY_CLASS_PROFILE;
}

/**
 * What can stand at the cursor: an enabled profile or a path of the view (files,
 * and directory claims as subtree filters), in any order, as apply_classify routes
 * them — the view narrowed to what the profiles named so far win, by -p or bare,
 * which is the filter the run will apply — or a filesystem path.
 */
static args_want_t apply_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_apply_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_apply_options_t, profiles)) {
        completion_profiles(ctx, out, COMPLETION_ENABLED);
        return ARGS_WANT_NONE;
    }
    if (at->value_of != NULL) {
        return ARGS_WANT_NONE;   /* -e: a pattern */
    }

    completion_profiles(ctx, out, COMPLETION_ENABLED);
    completion_files(ctx, out, o->profiles, o->profile_count, true);
    return ARGS_WANT_FILES;
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
        "Skip paths matching a .dottaignore-style pattern (repeatable)"
    ),
    ARGS_FLAG(
        "f force",
        cmd_apply_options_t,force,
        "Overwrite local changes, prune modified orphans, skip confirmation"
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
    /* Positionals: bare `<file>` tokens append to files[]; bare `<profile>` tokens
     * append to profiles[]. The -p/--profile flag above targets the same profiles[]
     * array, so `-p darwin foo` and `darwin foo` produce the same list in argv
     * order. */
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
    .name         = "apply",
    .summary      = "Deploy enabled profiles to the filesystem",
    .usage        = "%s apply [options] [profile|file]...",
    .description  =
        "Converge the filesystem with enabled profiles: deploy new and\n"
        "updated files, prune files orphaned by disabled profiles, and\n"
        "update the deployment state.\n",
    .notes        =
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
    .examples     =
        "  %s apply                            # Deploy all enabled profiles\n"
        "  %s apply --force                    # Lift the consent skips (overwrite, prune)\n"
        "  %s apply -p work                    # Filter to 'work' profile\n"
        "  %s apply -p work ~/.bashrc          # Profile + file filter\n"
        "  %s apply ~/.bashrc ~/.zshrc         # Deploy specific files only\n"
        "  %s apply -n                         # Preview without writing\n"
        "  %s apply --exclude 'home/.ssh/*'    # Protect matched files\n",
    .epilogue     =
        "See also:\n"
        "  %s status          # Preview pending deployment\n"
        "  %s update          # Commit filesystem changes back\n"
        "  %s profile enable  # Stage a profile for deployment\n",
    .opts_size    = sizeof(cmd_apply_options_t),
    .opts         = apply_opts,
    .classify     = apply_classify,
    .complete     = apply_complete,
    .payload      = &(const dotta_needs_t){
        .repo     = DOTTA_REPO_OPEN,
        .state    = DOTTA_STATE_WRITE,
        .mounts   = true,
        .crypto   = DOTTA_CRYPTO_OBTAIN,
        .manifest = true,
    },
    .dispatch     = apply_dispatch,
};
