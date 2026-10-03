/**
 * status.c - Show status of managed files
 */

#include "cmds/status.h"

#include <config.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/error.h"
#include "base/output.h"
#include "base/timeutil.h"
#include "cmds/completion.h"
#include "core/cleanup.h"
#include "core/manifest.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "sys/gitops.h"
#include "sys/identity.h"
#include "sys/transfer.h"
#include "sys/upstream.h"

/**
 * Print the enabled profiles and the last deployment of each
 *
 * @param out Output context (must not be NULL)
 * @param state The enabled rows: the binding printed beside a bound profile's
 *              name, the thing never printed without the where
 * @param scope The profiles the block lists — the filter's under -p, else the
 *              enabled set's (must not be NULL)
 * @param ws Workspace the view and the record come from: the per-profile
 *           last-deployed timestamp and the verbose per-profile counts are folded
 *           from its items (NULL when no workspace was loaded — it lends none
 *           then, and the header is names alone)
 * @param view The view whose health the block annotates (must not be NULL)
 */
static void status_print_profiles(
    output_t *out,
    const state_t *state,
    const scope_t *scope,
    const workspace_t *ws,
    const manifest_t *view
) {
    const string_array_t *profiles = scope_profiles(scope);

    /* The view's health, annotated onto the block. The claims the build could
     * not place, onto their profile's line (a count, the paths under -v), the
     * repair a legend line under the block; and its sibling, the names a profile
     * holds for a path it also names otherwise, annotated and listed the same
     * way — both say a profile carries more than it projects, for two different
     * reasons. And the enabled profiles the build found no branch for, a line
     * each beneath the rest: a profile the state enables is not left out of the
     * block that lists the enabled. */
    manifest_unbound_t unbound = manifest_unbound(view);
    manifest_unkept_t unkept = manifest_unkept(view);
    manifest_missing_t missing = manifest_missing(view);

    /* Show enabled profiles */
    output_section(out, OUTPUT_NORMAL, "Enabled profiles");

    /* What a profile contributes to this machine is its active paths of both
     * kinds — each item's own kind says which, and its record when it deployed */
    workspace_items_t active = workspace_active(ws);

    /* Whether each repair has a line to stand under. The question is about the
     * profiles this run *displays*, not the slices: -p filters the scope's profiles
     * while the view is always the whole enabled one, so a legend keyed off a
     * slice's own count would explain an annotation no line above it carries. */
    bool unbound_shown = false;
    bool unused_shown = false;
    bool missing_shown = false;

    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->entries[i];

        /* Format profile name, and the binding when the row has one */
        output_print(out, OUTPUT_NORMAL, "  {cyan}%s{reset}", profile);
        const char *target = state_target(state, profile);
        if (target) {
            char shown[PATH_MAX];
            output_format_path(target, identity()->home, shown, sizeof(shown));
            output_print(out, OUTPUT_NORMAL, " {dim}→ %s{reset}", shown);
        }

        /* One walk of the view per profile: the latest of its own ownership events
         * among the rows it owns now — the honest set for an enabled-profiles
         * header — and the verbose per-kind counts. A record another profile's
         * deployment left at one of those rows is that profile's event, a
         * reassignment apply has yet to acknowledge (core/workspace.h
         * workspace_reassigned), and dates this one nothing. */
        time_t profile_deploy_time = 0;
        size_t file_count = 0;
        size_t dir_count = 0;
        for (size_t j = 0; j < active.count; j++) {
            const workspace_item_t *item = active.entries[j];
            if (strcmp(item->profile, profile) != 0) continue;

            if (item->item_kind == PATH_KIND_DIRECTORY) dir_count++;
            else file_count++;

            if (item->record && strcmp(item->record->profile, profile) == 0 &&
                item->record->deployed_at > profile_deploy_time) {
                profile_deploy_time = item->record->deployed_at;
            }
        }

        /* Unbound claims are not rows — the counts above never see them; the
         * annotation is what says the profile carries more than it projects. */
        size_t unplaced = 0;
        for (size_t j = 0; j < unbound.count; j++) {
            if (strcmp(unbound.entries[j].profile, profile) == 0) unplaced++;
        }
        if (unplaced > 0) unbound_shown = true;

        /* Nor are the paths the view does not use. One count and not two: the
         * repair is per path, and the file each of them reaches is on its own
         * -v line, which is worth more than a tally of the files. */
        size_t unused = 0;
        for (size_t j = 0; j < unkept.count; j++) {
            if (strcmp(unkept.entries[j].profile, profile) == 0) unused++;
        }
        if (unused > 0) unused_shown = true;

        /* Show per-profile last deployed timestamp */
        if (profile_deploy_time > 0) {
            char relative_buf[64];
            timeutil_relative(
                profile_deploy_time, relative_buf, sizeof(relative_buf)
            );

            /* Display dimmed timestamp */
            output_print(
                out, OUTPUT_NORMAL, "  {dim}(deployed %s){reset}",
                relative_buf
            );
        }

        if (unplaced > 0) {
            output_print(
                out, OUTPUT_NORMAL,
                "  {yellow}(%zu custom/ path%s need%s a deployment target){reset}",
                unplaced, unplaced == 1 ? "" : "s", unplaced == 1 ? "s" : ""
            );
        }

        if (unused > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  {yellow}(%zu unused path%s){reset}",
                unused, unused == 1 ? "" : "s"
            );
        }

        /* In verbose mode, name what this profile contributes */
        if (output_is_verbose(out)) {
            char counts[64];
            output_format_counts(file_count, dir_count, counts, sizeof(counts));
            output_print(out, OUTPUT_NORMAL, "\n    %s", counts);

            for (size_t j = 0; j < unbound.count; j++) {
                if (strcmp(unbound.entries[j].profile, profile) != 0) continue;
                output_print(
                    out, OUTPUT_NORMAL, "\n    no target: %s%s",
                    unbound.entries[j].storage_path,
                    path_kind_suffix(unbound.entries[j].kind)
                );
            }

            /* The file is what makes the pair legible: two storage paths side
             * by side say nothing about being one thing, and this is the only
             * screen that says either is unused — `list -p` serves both, unmarked.
             * Named, not used: the kept name is what this profile calls the path,
             * while the window onto the view may show a higher profile there.
             * The path is the shared term of three paths on one line and takes
             * the target's own spelling a few lines above, not the window's
             * absolute one: `~/jail/etc/x` beside two storage paths reads, where
             * the absolute form is the longest thing on the line and is mostly
             * the storage path with its label spelled out. */
            char shown[PATH_MAX];
            for (size_t j = 0; j < unkept.count; j++) {
                if (strcmp(unkept.entries[j].profile, profile) != 0) continue;
                output_format_path(
                    unkept.entries[j].filesystem_path, identity()->home, shown,
                    sizeof(shown)
                );
                output_print(
                    out, OUTPUT_NORMAL, "\n    unused: %s%s — %s (named %s)",
                    unkept.entries[j].storage_path,
                    path_kind_suffix(unkept.entries[j].kind), shown,
                    unkept.entries[j].kept
                );
            }
        }

        output_endline(out, OUTPUT_NORMAL);
    }

    /* The enabled profiles the build found no branch for, beneath the ones the
     * view read, each one this run displays: -p names only a profile whose branch
     * is here (core/scope.h scope_build), so a filtered block lists none */
    for (size_t i = 0; i < missing.count; i++) {
        const char *profile = missing.entries[i];
        if (!scope_accepts_profile(scope, profile)) continue;

        output_print(out, OUTPUT_NORMAL, "  {cyan}%s{reset}", profile);
        const char *target = state_target(state, profile);
        if (target) {
            char shown[PATH_MAX];
            output_format_path(target, identity()->home, shown, sizeof(shown));
            output_print(out, OUTPUT_NORMAL, " {dim}→ %s{reset}", shown);
        }
        output_print(out, OUTPUT_NORMAL, "  {yellow}(no branch){reset}\n");
        missing_shown = true;
    }

    /* The repairs, in the shape this screen spells a repair: a dimmed key and a
     * sentence under the block it belongs to, keys aligned — what the Issues
     * and Unverifiable lists do for their tags, with the yellow annotation above
     * playing the tag's part. `Hint:` is apply's voice and sync's, and this channel
     * was the only thing in status that spoke it.
     *
     * Generic in both the profile and the path. The annotations say which profiles
     * carry them, so one filled name would read as the only one wherever two
     * do; and the path is the -v listing's to spell, where a name holding a space
     * is read rather than pasted into a command it would break. `--dry-run` is
     * the whole of the unused-path safety: dropping a directory name takes every
     * claim beneath it, and the preview shows that rather than asserting it.
     * The claims' two are worth a line at all because nothing else offers them
     * — neither claim has a row, so no completion source reaches one — and the
     * missing profile's because nothing else on this screen names it. */
    if (unbound_shown || unused_shown || missing_shown) {
        output_gap(out, OUTPUT_NORMAL);
        if (unbound_shown) {
            output_hintline(
                out, OUTPUT_NORMAL,
                "  custom/ paths - 'dotta profile enable <profile> --target /path' "
                "sets the target; 'dotta remove <profile> <path>' untracks"
            );
        }
        if (unused_shown) {
            /* The trailing space is the alignment: one key short of the other. */
            output_hintline(
                out, OUTPUT_NORMAL,
                "  unused paths  - 'dotta remove --dry-run <profile> <path>' shows "
                "what dropping one takes"
            );
        }
        if (missing_shown) {
            output_hintline(
                out, OUTPUT_NORMAL,
                "  no branch     - 'dotta profile disable <profile>' drops it; "
                "'dotta profile fetch <profile>' brings its branch back"
            );
        }
    }
}

/**
 * Print the manifest — every active path, with its state
 *
 * The window onto the view (--full): one line per active path, both kinds merged
 * in path order, tagged as its item says — [clean] or [ancestor] where nothing
 * diverged (workspace_item_tags) — with the owning profile ("from P", or "P →
 * Q" for a pending reassignment). The one listing that shows the whole view rather
 * than what diverged from it; printed whatever the workspace's cleanliness. Orphans
 * are records, not rows — they stay in the Issues section. Scoped by the CLI
 * filter like every other section.
 *
 * @param ws Workspace (must not be NULL, borrowed from caller)
 * @param scope Operation scope (must not be NULL; its filter dimension drives
 *              display)
 * @param out Output context (must not be NULL)
 */
static void status_print_manifest(
    const workspace_t *ws,
    const scope_t *scope,
    output_t *out
) {
    if (!ws || !out) return;

    output_list_t *list = output_list_create(
        out, "Manifest",
        "every active path; [clean] where nothing diverged, [ancestor] where "
        "dotta only passes through"
    );

    /* Each kind's items are in filesystem_path order and share no path (one row
     * per path, one kind), so a two-finger merge walks the view as one path-ordered
     * sequence. */
    workspace_items_t files = workspace_files(ws);
    workspace_items_t dirs = workspace_directories(ws);
    size_t f = 0;
    size_t d = 0;
    while (f < files.count || d < dirs.count) {
        const workspace_item_t *item;
        if (d == dirs.count) {
            item = files.entries[f++];
        } else if (f == files.count) {
            item = dirs.entries[d++];
        } else {
            const char *file_path = files.entries[f]->filesystem_path;
            const char *dir_path = dirs.entries[d]->filesystem_path;
            item = strcmp(file_path, dir_path) < 0 ? files.entries[f++]
                                                   : dirs.entries[d++];
        }

        if (!scope_accepts_profile(scope, item->profile)) continue;

        const char *tags[WORKSPACE_ITEM_MAX_TAGS];
        size_t tag_count;
        output_color_t color;
        char metadata[256];

        /* Every item through the one renderer, a clean one too: what agreement
         * reads as is the class's to say, and one that DID diverge keeps its
         * own tags — absence and a squatter are read of both classes, and they
         * already say the actionable thing. */
        if (!workspace_item_tags(
            item, tags, &tag_count, &color, metadata, sizeof(metadata)
            )) {
            continue;
        }

        char path[PATH_MAX + 2];
        snprintf(
            path, sizeof(path), "%s%s", item->filesystem_path,
            path_kind_suffix(item->item_kind)
        );

        output_list_add(list, tags, tag_count, color, path, metadata);
    }

    output_list_render(list);
    output_list_free(list);
}

/**
 * Print the workspace status
 *
 * Shows the consistency between the view, the record and the filesystem: the
 * status line, then the diverged items in actionable sections (git-like structure).
 *
 * The status line is one fold of the diverged items over the scope, decided and
 * worded the same whatever the filter: under -p it speaks for the filtered profiles
 * alone, so a clean one never reads Dirty for another's divergence, and what
 * the filter hides is counted beneath the sections.
 *
 * @param ws Workspace (must not be NULL, borrowed from caller)
 * @param scope Operation scope (must not be NULL; its filter dimension drives
 *              display)
 * @param config Configuration (must not be NULL; its switch words the key's remedy)
 * @param out Output context (must not be NULL)
 */
static void status_print_workspace(
    const workspace_t *ws,
    const scope_t *scope,
    const config_t *config,
    output_t *out
) {
    if (!ws || !out) return;

    /* The diverged items, read by the status line's fold and by the sections */
    workspace_items_t diverged = workspace_diverged(ws);

    /* A load holding none is clean (workspace_diverged), and says so only when
     * asked. One holding any opens the section whatever the filter reaches: a
     * filtered profile that reads Clean still counts the divergence it hides. */
    if (diverged.count == 0 && !output_is_verbose(out)) return;

    /* The status line, one fold whatever the filter: the diverged items shown,
     * those of them dotta could not verify, and those the filter hides. A scope
     * is Clean iff none is shown. Invalid is reserved for what the analysis could
     * not establish: an item carrying DIVERGENCE_UNVERIFIED (an unreadable path,
     * a comparison that could not run, a Git probe that did not answer) is one
     * no verb resolves by default — apply skips it and the user must look. Anything
     * else shown is Dirty: work some verb takes, an orphan included — pending
     * work, not an invalid workspace. With no filter every item is shown and
     * none is hidden. */
    size_t shown = 0;
    size_t unverified = 0;
    size_t hidden = 0;

    /* The sections, in the order they print: each item shown is added to its
     * section's bucket as the walk decides it, and the nine are filled once the
     * walk is done (core/workspace.h workspace_buckets_t). They are the printer's
     * own, in a frame it frees once they are printed — nothing here outlives
     * the call (include/runtime.h "Memory"). */
    arena_t *frame = arena_create(0);
    workspace_buckets_t *buckets = workspace_buckets_create(frame);

    workspace_items_t conflicts = { 0 };
    workspace_items_t squatted = { 0 };
    workspace_items_t displaced = { 0 };
    workspace_items_t unverifiable = { 0 };
    workspace_items_t uncommitted = { 0 };
    workspace_items_t reassigned = { 0 };
    workspace_items_t undeployed = { 0 };
    workspace_items_t new_files = { 0 };
    workspace_items_t orphaned = { 0 };

    for (size_t i = 0; i < diverged.count; i++) {
        const workspace_item_t *item = diverged.entries[i];

        /* Coherent Scope: under a profile filter only its profiles' items are
         * shown, so status matches what apply would do; the rest are hidden,
         * and counted beneath the sections */
        if (!scope_accepts_profile(scope, item->profile)) {
            hidden++;
            continue;
        }

        /* The fold counts every item shown, never a section's size: an unverified
         * orphan lists under Issues and still makes the line Invalid */
        shown++;
        if (item->divergence & DIVERGENCE_UNVERIFIED) {
            unverified++;
        }

        switch (item->state) {
            case WORKSPACE_STATE_DEPLOYED:
                /* One bucket per route — the same table update's filter and skip
                 * counter read (workspace_item_route), so no section promises a
                 * verb the verb refuses */
                switch (workspace_item_route(item)) {
                    case WORKSPACE_ROUTE_DISPLACED_TRACKED:
                    case WORKSPACE_ROUTE_DISPLACED_DERIVED:
                        /* Not looked at, so no path bit of its own — the squatter's
                         * section names the way out */
                        workspace_buckets_add(buckets, item, &displaced);
                        break;

                    case WORKSPACE_ROUTE_CONFLICT:
                    case WORKSPACE_ROUTE_KIND:
                        /* Neither verb's by default — its own header names the
                         * way out */
                        workspace_buckets_add(buckets, item, &conflicts);
                        break;

                    case WORKSPACE_ROUTE_KIND_DERIVED:
                        /* One verb and no decision — its own header names the
                         * verb */
                        workspace_buckets_add(buckets, item, &squatted);
                        break;

                    case WORKSPACE_ROUTE_UNVERIFIABLE:
                        workspace_buckets_add(buckets, item, &unverifiable);
                        break;

                    case WORKSPACE_ROUTE_STALE:
                        /* Apply's work, the same bucket as a path never deployed;
                         * the [stale] tag says which */
                        workspace_buckets_add(buckets, item, &undeployed);
                        break;

                    case WORKSPACE_ROUTE_CAPTURE:
                        /* Real divergence → uncommitted changes */
                        workspace_buckets_add(buckets, item, &uncommitted);
                        break;

                    case WORKSPACE_ROUTE_REASSIGNED:
                        /* Pure profile reassignment (no filesystem divergence) */
                        workspace_buckets_add(buckets, item, &reassigned);
                        break;

                    case WORKSPACE_ROUTE_CLEAN:
                        /* None: a diverged item has something to say
                         * (workspace_diverged), and the fold above counted each
                         * one */
                        break;
                }
                break;

            case WORKSPACE_STATE_DELETED:
                /* Deleted paths, either kind → uncommitted changes */
                workspace_buckets_add(buckets, item, &uncommitted);
                break;

            case WORKSPACE_STATE_UNDEPLOYED:
                workspace_buckets_add(buckets, item, &undeployed);
                break;

            case WORKSPACE_STATE_UNTRACKED:
                workspace_buckets_add(buckets, item, &new_files);
                break;

            case WORKSPACE_STATE_UNSCANNED:
                /* Where the scan could not look: no verb is promised, and New
                 * files' closer would send it to an update that never takes it */
                workspace_buckets_add(buckets, item, &unverifiable);
                break;

            case WORKSPACE_STATE_ORPHANED:
            case WORKSPACE_STATE_RELEASED:
                workspace_buckets_add(buckets, item, &orphaned);
                break;
        }
    }

    workspace_buckets_fill(buckets);

    output_section(out, OUTPUT_NORMAL, "Workspace status");

    /* The line: the fold's decision, in the same words filtered or not */
    if (shown == 0) {
        /* Active paths the filter reaches, both kinds — what stands aligned at
         * a path is not a question about which kind stands there. With no filter
         * every item is accepted, so this is the whole view. Counted here, the
         * one arm that prints it. */
        workspace_items_t active = workspace_active(ws);
        size_t scoped_paths = 0;
        for (size_t i = 0; i < active.count; i++) {
            if (scope_accepts_profile(scope, active.entries[i]->profile)) {
                scoped_paths++;
            }
        }

        /* Where the scope reaches no path, the sentence names its subject: the
         * filter's profiles, or the whole workspace */
        if (scoped_paths > 0) {
            output_colored(
                out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN,
                "  Clean - %zu path%s aligned\n",
                scoped_paths, scoped_paths == 1 ? "" : "s"
            );
        } else if (scope_filters_profiles(scope)) {
            output_colored(
                out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN,
                "  Clean - no paths in profile\n"
            );
        } else {
            output_colored(
                out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN,
                "  Clean - all states aligned\n"
            );
        }
    } else if (unverified > 0) {
        output_colored(
            out, OUTPUT_NORMAL, OUTPUT_COLOR_RED,
            "  Invalid - %zu item%s dotta could not verify\n",
            unverified, unverified == 1 ? "" : "s"
        );
    } else {
        output_colored(
            out, OUTPUT_NORMAL, OUTPUT_COLOR_YELLOW,
            "  Dirty - %zu item%s diverged\n",
            shown, shown == 1 ? "" : "s"
        );
    }

    /* Section 1: Conflicts — the buckets no default verb resolves lead; this
     * one's header carries the remedy, true of every row beneath it (content
     * moved on both sides, or a kind the copy cannot commit on a row a plan can
     * hold — a squatted rung dotta only passes through has the next section,
     * since no flag lifts it). `add --force` is qualified because it takes one
     * of the two and not the other: a kind change is a re-shaping of the tree
     * and add refuses it by the claim standing at the path, naming `dotta remove`
     * (cmds/add.c) */
    if (conflicts.count > 0) {
        output_list_t *list = output_list_create(
            out, "Conflicts",
            "changed on both sides or a different kind on disk; "
            "\"dotta diff\" to compare, \"dotta apply --force\" to "
            "keep Git's, \"dotta add --force\" to keep disk's bytes "
            "when the kind matches, \"dotta remove\" to untrack"
        );

        for (size_t i = 0; i < conflicts.count; i++) {
            const workspace_item_t *item = conflicts.entries[i];
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];
            char path[PATH_MAX + 2];

            if (workspace_item_tags(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                snprintf(
                    path, sizeof(path), "%s%s", item->filesystem_path,
                    path_kind_suffix(item->item_kind)
                );
                output_list_add(
                    list, tags, tag_count, color, path, metadata
                );
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 2: Squatted ancestors — a different kind stands at a directory
     * dotta only passes through (the route's KIND_DERIVED): never planned, so
     * no flag lifts it and no decision pends. One verb, the named re-derivation,
     * in the words update's counted line already uses. */
    if (squatted.count > 0) {
        output_list_t *list = output_list_create(
            out, "Squatted ancestors",
            "a different kind stands at a directory dotta only passes "
            "through; \"dotta update <dir>\" re-derives it"
        );

        for (size_t i = 0; i < squatted.count; i++) {
            const workspace_item_t *item = squatted.entries[i];
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];
            char path[PATH_MAX + 2];

            if (workspace_item_tags(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                snprintf(
                    path, sizeof(path), "%s%s", item->filesystem_path,
                    path_kind_suffix(item->item_kind)
                );
                output_list_add(
                    list, tags, tag_count, color, path, metadata
                );
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 3: Displaced paths — beneath a squatter one of the two sections
     * above holds (the route's DISPLACED_* arms, the claimant's): nothing there
     * was looked at, so the line shows [displaced] and only what no look decides
     * or disproves beside it (the blob's verdict, a reassignment), and the header
     * sends the user to the squatter, whose own section names its verb. The header
     * opens with the predicate, as every sentence about such a path does, and
     * spells the squatter out where the other four name it with the word — this
     * is where the word is grounded (core/workspace.h workspace_displaced_t).
     * Named by section rather than "above": under -p the squatter's row may be
     * filtered while a child is not, and the bare status lists both. */
    if (displaced.count > 0) {
        output_list_t *list = output_list_create(
            out, "Displaced paths",
            "not looked at: a different kind stands at a directory above "
            "them; resolve that directory first (\"dotta status\" lists "
            "it under Conflicts or Squatted ancestors)"
        );

        for (size_t i = 0; i < displaced.count; i++) {
            const workspace_item_t *item = displaced.entries[i];
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];
            char path[PATH_MAX + 2];

            if (workspace_item_tags(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                snprintf(
                    path, sizeof(path), "%s%s", item->filesystem_path,
                    path_kind_suffix(item->item_kind)
                );
                output_list_add(
                    list, tags, tag_count, color, path, metadata
                );
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 4: Unverifiable paths — the other no-verb bucket: dotta could not
     * look, so no verb is promised. The header says only that, and a key beneath
     * names each failed look and its way out, one line per tag string the block
     * shows — the Issues key's shape, for the reason that block has one: the
     * tag is a word the reader has to be taught, and one sentence over three
     * refusals is how a locked path came to be told to fix its permissions. A
     * key rather than a closer because a closer speaks only for a class that
     * has a remedy, and [unverified] has none — it would stand on the screen
     * unexplained. */
    if (unverifiable.count > 0) {
        output_list_t *list = output_list_create(
            out, "Unverifiable paths",
            "dotta could not verify these paths"
        );

        /* Keyed by the exact tags the line shows, the way Issues is keyed, so
         * the column below reads back against the one above. Three classes
         * (workspace_fault_t), and the policy bit before the class and a pending
         * reassignment after it can each ride on the line ([unencrypted]
         * [unreadable] [reassigned]), so twelve keys bound the domain. */
        struct { char tags[64]; const char *hint; } legend[12];
        size_t legend_count = 0;
        size_t legend_width = 0;

        for (size_t i = 0; i < unverifiable.count; i++) {
            const workspace_item_t *item = unverifiable.entries[i];
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];
            char path[PATH_MAX + 2];

            if (!workspace_item_tags(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                continue;
            }
            snprintf(
                path, sizeof(path), "%s%s", item->filesystem_path,
                path_kind_suffix(item->item_kind)
            );
            output_list_add(
                list, tags, tag_count, color, path, metadata
            );

            /* What the failed look was, then the way out of it: a key for the
             * locked rows, and the switch before it where encryption is off, a
             * run that holds no key at all; root for the unreadable ones and
             * only where the run holds none — offered, never promised, since a
             * policy may deny root the read as well. The residual class has no
             * remedy to name — there is no one remedy for a foreign epoch, a
             * cipher this build does not read and an I/O error — so its line
             * names the verb that will print the cause instead. */
            const char *hint = NULL;

            switch (item->fault) {
                case WORKSPACE_FAULT_LOCKED:
                    hint = config->encryption_enabled
                        ? "encrypted, and no key opened it; 'dotta key set' unlocks it"
                        : "encrypted, and encryption is disabled; 'dotta key set' "
                        "unlocks it once encryption.enabled = true";
                    break;
                case WORKSPACE_FAULT_UNREADABLE:
                    hint = identity()->privileged
                        ? "permissions refused the read"
                        : "permissions refused the read; "
                        "sudo may lift it";
                    break;
                case WORKSPACE_FAULT_NONE:
                case WORKSPACE_FAULT_UNVERIFIED:
                    hint = "no remedy dotta can name; the verb that "
                        "meets it prints why";
                    break;
            }

            /* Same bracketing and spacing the list gives the item line, so the
             * column below matches the one above */
            char key[64] = "";
            for (size_t t = 0; t < tag_count; t++) {
                size_t used = strlen(key);
                snprintf(
                    key + used, sizeof(key) - used, "%s[%s]",
                    t > 0 ? " " : "", tags[t]
                );
            }

            size_t slot = 0;
            while (slot < legend_count && strcmp(legend[slot].tags, key) != 0) {
                slot++;
            }
            if (slot == legend_count &&
                legend_count < sizeof(legend) / sizeof(legend[0])) {
                size_t len = strlen(key);
                memcpy(legend[legend_count].tags, key, len + 1);
                legend[legend_count].hint = hint;
                legend_count++;
                if (len > legend_width) legend_width = len;
            }
        }

        output_list_render(list);
        output_list_free(list);

        if (legend_count > 0) {
            output_gap(out, OUTPUT_NORMAL);
            for (size_t i = 0; i < legend_count; i++) {
                output_hintline(
                    out, OUTPUT_NORMAL, "  %-*s - %s",
                    (int) legend_width, legend[i].tags, legend[i].hint
                );
            }
        }
    }

    /* Section 5: Uncommitted Changes */
    if (uncommitted.count > 0) {
        output_list_t *list = output_list_create(
            out, "Uncommitted changes",
            "use \"dotta update\" to commit these changes"
        );

        for (size_t i = 0; i < uncommitted.count; i++) {
            const workspace_item_t *item = uncommitted.entries[i];
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];
            char path[PATH_MAX + 2];

            if (workspace_item_tags(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                snprintf(
                    path, sizeof(path), "%s%s", item->filesystem_path,
                    path_kind_suffix(item->item_kind)
                );
                output_list_add(
                    list, tags, tag_count, color, path, metadata
                );
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 6: Profile Reassignments */
    if (reassigned.count > 0) {
        output_list_t *list = output_list_create(
            out, "Profile reassignments",
            "run \"dotta apply\" to acknowledge"
        );

        for (size_t i = 0; i < reassigned.count; i++) {
            const workspace_item_t *item = reassigned.entries[i];
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];
            char path[PATH_MAX + 2];

            if (workspace_item_tags(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                snprintf(
                    path, sizeof(path), "%s%s", item->filesystem_path,
                    path_kind_suffix(item->item_kind)
                );
                output_list_add(
                    list, tags, tag_count, color, path, metadata
                );
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 7: Undeployed changes — apply's work, both kinds: what Git has
     * and disk does not, a path apply is to create or a move of Git's disk has
     * not followed ([stale]). Named as its twin, Uncommitted changes, is. */
    if (undeployed.count > 0) {
        output_list_t *list = output_list_create(
            out, "Undeployed changes",
            "use \"dotta apply\" to deploy these changes"
        );

        for (size_t i = 0; i < undeployed.count; i++) {
            const workspace_item_t *item = undeployed.entries[i];
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];
            char path[PATH_MAX + 2];

            if (workspace_item_tags(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                snprintf(
                    path, sizeof(path), "%s%s", item->filesystem_path,
                    path_kind_suffix(item->item_kind)
                );
                output_list_add(
                    list, tags, tag_count, color, path, metadata
                );
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 8: New Files */
    if (new_files.count > 0) {
        output_list_t *list = output_list_create(
            out, "New files",
            "use \"dotta update --include-new\" to track these files"
        );

        for (size_t i = 0; i < new_files.count; i++) {
            const workspace_item_t *item = new_files.entries[i];
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];
            char path[PATH_MAX + 2];

            if (workspace_item_tags(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                snprintf(
                    path, sizeof(path), "%s%s", item->filesystem_path,
                    path_kind_suffix(item->item_kind)
                );
                output_list_add(
                    list, tags, tag_count, color, path, metadata
                );
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 9: Issues (orphaned) */
    if (orphaned.count > 0) {
        output_list_t *list = output_list_create(
            out, "Issues",
            "run \"dotta apply\" to prune orphaned paths"
        );

        /* The header promises a prune; a clean orphaned file gets one and needs
         * no more words. Every other hint is keyed below by the exact tags its
         * line shows, once per distinct tag string, so the key reads back against
         * the list it follows. The verdict is cleanup's (cleanup_verdict, the
         * one producer the preview reads too) — this only names it. PRUNABLE is
         * the one verdict status cannot finish — the remainder and the run's
         * reach are preflight's, from the disk — and the directory hint says
         * so; it shares the bare [orphaned] key with the files, so the sentence
         * is written to be true of both. */
        struct { char tags[64]; const char *hint; } legend[16];
        size_t legend_count = 0;
        size_t legend_width = 0;

        /* One sentence for every [relocated] key, wherever the verdict put the
         * item — a pruned custom/ re-target and a skipped home move share the
         * tag string across kinds and fates, so the sentence is written to be
         * true of all of them, the way the bare [orphaned] key's is. */
        static const char relocated_hint[] =
            "the claim deploys elsewhere now (target or home moved); "
            "apply prunes the old copy — a moved home holds it "
            "behind --force";

        for (size_t i = 0; i < orphaned.count; i++) {
            const workspace_item_t *item = orphaned.entries[i];
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];
            char path[PATH_MAX + 2];

            if (!workspace_item_tags(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                continue;
            }
            snprintf(
                path, sizeof(path), "%s%s", item->filesystem_path,
                path_kind_suffix(item->item_kind)
            );
            output_list_add(
                list, tags, tag_count, color, path, metadata
            );

            const char *hint = NULL;

            switch (cleanup_verdict(item, false)) {
                case CLEANUP_ABSENT:
                    hint = "already gone from disk; apply reclaims its entry";
                    break;

                case CLEANUP_RELEASED:
                    /* The displaced read comes first: such an item was never
                     * looked at, so neither sibling sentence is true of it —
                     * the same precedence the verdict's own arms take. The last
                     * sentence is the bare [released] key's, which a file and a
                     * directory share — the legend keeps the first hint a key
                     * meets — so, like the bare [orphaned] key's, it is written
                     * to be true of both and names no kind. */
                    hint = item->displaced != WORKSPACE_DISPLACED_NONE
                        ? "not looked at, beneath a squatted directory; "
                        "apply releases its entry, the path stays"
                        : (item->divergence & DIVERGENCE_TYPE)
                        ? "what dotta put there is gone, another kind of "
                        "path stands in its place; apply releases its "
                        "entry, the path stays"
                        : "its claim is no longer in Git, dotta never "
                        "deployed it, or its record names it under another "
                        "spelling of its path; apply releases its "
                        "entry, the path stays";
                    break;

                case CLEANUP_SKIPPED:
                    if (item->item_kind == PATH_KIND_DIRECTORY) {
                        /* The two ways a directory reaches SKIPPED here
                         * (force=false): the workspace could not verify it, or
                         * the relocation skip — so the tail is the relocation,
                         * no third way existing. Unverified is read first, which
                         * is the file table's order and the inverse of
                         * cleanup_verdict's arms, deliberately: --force lifts
                         * the relocation skip and never the unverified bit, so
                         * on a directory carrying both the failed look's wording
                         * is the one that stays true. Worded by whose remedy it
                         * is; a directory seals no content, so its failed look
                         * is never the key's. */
                        hint = (item->divergence & DIVERGENCE_UNVERIFIED)
                            ? (item->fault == WORKSPACE_FAULT_UNREADABLE
                               ? "cannot be read; apply skips it"
                               : "could not be verified; apply skips it")
                            : relocated_hint;
                        break;
                    }
                    switch (cleanup_skip_reason(item)) {
                        case CLEANUP_SKIP_UNVERIFIED:
                            /* Worded by whose remedy the failed look is, so the
                             * hint and the tag it is keyed by say the same thing
                             * (workspace_fault_t) — the key's naming the switch
                             * first where encryption is off. */
                            switch (item->fault) {
                                case WORKSPACE_FAULT_LOCKED:
                                    hint = config->encryption_enabled
                                        ? "encrypted, and no key opened it "
                                        "('dotta key set'); apply skips it, "
                                        "--force prunes it"
                                        : "encrypted, and encryption is disabled "
                                        "(encryption.enabled = true, then 'dotta key "
                                        "set'); apply skips it, --force prunes it";
                                    break;
                                case WORKSPACE_FAULT_UNREADABLE:
                                    hint = "cannot be read; "
                                        "apply skips it, --force prunes it";
                                    break;
                                case WORKSPACE_FAULT_NONE:
                                case WORKSPACE_FAULT_UNVERIFIED:
                                    hint = "could not be verified; "
                                        "apply skips it, --force prunes it";
                                    break;
                            }
                            break;
                        case CLEANUP_SKIP_RELOCATED:
                            hint = relocated_hint;
                            break;
                        /* The key names what changed — [modified], [type], [mode],
                         * [ownership] — so the hint says only that it did. */
                        case CLEANUP_SKIP_MODIFIED:
                        case CLEANUP_SKIP_TYPE_CHANGED:
                        case CLEANUP_SKIP_CLAIM_CHANGED:
                            hint = "changed since deployment; "
                                "apply skips it, --force prunes it";
                            break;
                        case CLEANUP_SKIP_NONE:
                            break;
                    }
                    break;

                case CLEANUP_PRUNABLE:
                    if (item->relocation != WORKSPACE_RELOCATION_NONE) {
                        hint = relocated_hint;
                    } else if (item->item_kind == PATH_KIND_DIRECTORY) {
                        hint = "apply prunes it; a directory still holding "
                            "something not dotta's to remove is released "
                            "instead";
                    }
                    break;
            }
            if (!hint) continue;

            /* Same bracketing and spacing the list gives the item line, so the
             * column below matches the one above */
            char key[64] = "";
            for (size_t t = 0; t < tag_count; t++) {
                size_t used = strlen(key);
                snprintf(
                    key + used, sizeof(key) - used, "%s[%s]",
                    t > 0 ? " " : "", tags[t]
                );
            }

            size_t slot = 0;
            while (slot < legend_count && strcmp(legend[slot].tags, key) != 0) {
                slot++;
            }
            if (slot == legend_count && legend_count < 16) {
                size_t len = strlen(key);
                memcpy(legend[legend_count].tags, key, len + 1);
                legend[legend_count].hint = hint;
                legend_count++;
                if (len > legend_width) legend_width = len;
            }
        }

        output_list_render(list);
        output_list_free(list);

        if (legend_count > 0) {
            output_gap(out, OUTPUT_NORMAL);
            for (size_t i = 0; i < legend_count; i++) {
                output_hintline(
                    out, OUTPUT_NORMAL, "  %-*s - %s",
                    (int) legend_width, legend[i].tags, legend[i].hint
                );
            }
        }
    }

    /* The sections are printed, and their frame goes with them */
    arena_free(frame);

    /* The diverged items the filter hides, counted */
    if (hidden > 0) {
        output_print(
            out, OUTPUT_NORMAL, "  {dim}(%zu item%s hidden){reset}\n",
            hidden, hidden == 1 ? "" : "s"
        );
    }
}

/**
 * Print the remote sync status for profiles
 *
 * By default shows only enabled profiles for consistency with workspace status.
 * Use show_all_profiles to report on every branch in the repository. Its failures
 * are lines of its own section, as its siblings' are: no remote configured is
 * no section, and every other failure is a warning in its place.
 */
static void status_print_remote(
    const dotta_ctx_t *ctx,
    const string_array_t *profiles,
    bool show_all_profiles,
    bool no_fetch
) {
    CHECK_NULL(ctx);
    CHECK_NULL(profiles);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    bool verbose = output_is_verbose(out);

    /* Detect remote (name + URL — URL feeds the credential helper when we fetch
     * below). Both outputs are arena-borrowed for the call's lifetime. */
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    error_t err = gitops_resolve_default_remote(
        repo, ctx->arena, &remote_name, no_fetch ? NULL : &remote_url
    );
    if (error_code(err) == ERR_NOT_FOUND) {
        /* No remote configured — no section to print (sys/gitops.h names this
         * read) */
        return;
    }
    if (err) {
        /* A remote the resolver could not choose, or one it could not read: the
         * section's question has no answer, and says so where it would stand */
        output_warning(
            out, OUTPUT_NORMAL, "Cannot tell remote sync status: %s", error_line(err)
        );
        return;
    }

    /* Build profile array to check */
    string_array_t all_local;
    const string_array_t *check = profiles;

    if (show_all_profiles) {
        /* Explicit request: show ALL local profiles (lightweight, no ref resolution) */
        err = gitops_list_branches(repo, ctx->arena, &all_local);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Cannot list every profile for remote sync status: %s",
                error_line(err)
            );
            return;
        }
        check = &all_local;
    }

    if (check->count == 0) return;

    /* Fetch if requested */
    if (!no_fetch) {
        /* xfer is required by gitops network ops (credential state machine +
         * approve/reject are needed even without verbose progress). Status's
         * fetch is a background refresh: progress is always ephemeral so it never
         * persists between status sections. */
        transfer_options_t xfer_opts = {
            .output             = out,
            .url                = remote_url,
            .ephemeral_progress = true,
        };
        transfer_context_t *xfer = transfer_context_create(&xfer_opts);

        if (verbose) {
            /* Ephemeral fetch message (no newline — resolved after fetch). On
             * TTY: progress overwrites via \r, then line is cleared. On pipe:
             * falls back to inline " done.\n" resolution. */
            output_print(
                out, OUTPUT_VERBOSE, "Fetching from '%s'...", remote_name
            );
            fflush(out->stream);
        }

        /* Perform batched fetch — single network op for all branches */
        err = gitops_fetch_branches(repo, remote_name, check, xfer);

        /* Resolve the "Fetching from ..." preamble line (verbose only) */
        if (verbose) {
            if (output_is_tty(out)) {
                /* TTY: clear the preamble. Progress drawn over it ended with
                 * its op (sys/transfer.h transfer_op_end), so the preamble is
                 * all that can stand. */
                output_clear_line(out);
            } else if (err) {
                /* Non-TTY + error: finish the line before the warning */
                output_endline(out, OUTPUT_VERBOSE);
            } else {
                /* Non-TTY + success: inline resolution */
                output_print(out, OUTPUT_VERBOSE, " done.\n");
            }
        }

        if (err) {
            /* Non-fatal: warn and continue with status display */
            output_warning(
                out, OUTPUT_VERBOSE, "Failed to fetch branches: %s",
                error_line(err)
            );
        }

        transfer_context_free(xfer);
    }

    /* Display remote sync status section */
    output_section(out, OUTPUT_NORMAL, "Remote sync status ({cyan}%s{reset})", remote_name);

    /* Analyze and display each profile's sync state */
    size_t up_to_date = 0;
    size_t ahead = 0;
    size_t behind = 0;
    size_t diverged = 0;
    size_t no_remote = 0;
    size_t no_local = 0;
    size_t failed = 0;

    for (size_t i = 0; i < check->count; i++) {
        const char *profile = check->entries[i];

        /* Analyze upstream state. A profile whose state could not be read is a
         * row of the section like any other, on the report's stream, its cause
         * the error's own line and the outcome glyph sync gives a failed analysis;
         * the summary counts it, and the report goes on past it. At both levels:
         * a failure has no commit for -v to show. The error is dropped, one per
         * such profile. */
        upstream_info_t info;
        err = upstream_analyze_profile(repo, remote_name, profile, &info);
        if (err) {
            output_print(
                out, OUTPUT_NORMAL, "  {cyan}%s{reset}  {red}(✗ %s){reset}\n",
                profile, error_line(err)
            );
            failed++;
            continue;
        }

        /* Format display based on state. Color comes from the shared map; only
         * the descriptive text and the per-state counter are caller-specific. */
        const char *symbol = upstream_state_symbol(info.state);
        output_color_t color = upstream_state_color(info.state);
        char status_str[128];

        switch (info.state) {
            case UPSTREAM_UP_TO_DATE:
                snprintf(
                    status_str, sizeof(status_str), "%s up-to-date",
                    symbol
                );
                up_to_date++;
                break;
            case UPSTREAM_LOCAL_AHEAD:
                snprintf(
                    status_str, sizeof(status_str), "%s %zu ahead",
                    symbol, info.ahead
                );
                ahead++;
                break;
            case UPSTREAM_REMOTE_AHEAD:
                snprintf(
                    status_str, sizeof(status_str), "%s %zu behind",
                    symbol, info.behind
                );
                behind++;
                break;
            case UPSTREAM_DIVERGED:
                snprintf(
                    status_str, sizeof(status_str), "%s diverged (%zu ahead, %zu behind)",
                    symbol, info.ahead, info.behind
                );
                diverged++;
                break;
            case UPSTREAM_NO_REMOTE:
                snprintf(
                    status_str, sizeof(status_str), "%s no remote",
                    symbol
                );
                no_remote++;
                break;
            case UPSTREAM_NO_LOCAL:
                snprintf(
                    status_str, sizeof(status_str), "%s no local branch",
                    symbol
                );
                no_local++;
                break;
        }

        /* Display with colors */
        if (verbose && info.state != UPSTREAM_NO_REMOTE && info.state != UPSTREAM_NO_LOCAL) {
            /* Verbose mode: show detailed commit info. The enclosing branch has
             * already filtered out NO_REMOTE/NO_LOCAL, so both local and remote
             * refs are guaranteed to exist on every state reaching this block. */
            output_gap(out, OUTPUT_VERBOSE);
            output_print(out, OUTPUT_VERBOSE, "Profile: %s\n", profile);

            /* Get local commit info. A commit lookup here that fails prints no
             * line, its error dropped — at most two per profile, the local and
             * the remote. */
            git_commit *local_commit = NULL;
            err = gitops_load_branch_commit(repo, profile, &local_commit);

            /* Status line — always shown regardless of commit loading */
            output_print(out, OUTPUT_VERBOSE, "  Status:         ");
            output_colored(out, OUTPUT_VERBOSE, color, "%s\n", status_str);

            if (!err) {
                const git_oid *local_oid = git_commit_id(local_commit);
                char local_oid_str[8];
                git_oid_tostr(local_oid_str, sizeof(local_oid_str), local_oid);

                const char *local_summary = git_commit_summary(local_commit);
                git_time_t local_time = git_commit_time(local_commit);

                char time_str[64];
                timeutil_relative(local_time, time_str, sizeof(time_str));

                output_print(
                    out, OUTPUT_VERBOSE, "  Local commit:   %s %s (%s)\n",
                    local_oid_str, local_summary, time_str
                );

                git_commit_free(local_commit);
            }

            /* Remote commit info — guaranteed reachable per the enclosing filter
             * above. */
            char remote_ref[DOTTA_REFNAME_MAX];
            err = gitops_build_refname(
                remote_ref, sizeof(remote_ref), "refs/remotes/%s/%s",
                remote_name, profile
            );
            git_commit *remote_commit = NULL;
            if (!err) err = gitops_load_reference_commit(repo, remote_ref, &remote_commit);

            if (!err) {
                const git_oid *remote_oid = git_commit_id(remote_commit);
                char remote_oid_str[8];
                git_oid_tostr(remote_oid_str, sizeof(remote_oid_str), remote_oid);

                const char *remote_summary = git_commit_summary(remote_commit);
                git_time_t remote_time = git_commit_time(remote_commit);

                char time_str[64];
                timeutil_relative(remote_time, time_str, sizeof(time_str));

                output_print(
                    out, OUTPUT_VERBOSE, "  Remote commit:  %s %s (%s)\n",
                    remote_oid_str, remote_summary, time_str
                );

                git_commit_free(remote_commit);
            }
        } else {
            /* Compact mode: single line matching enabled profiles format */
            output_print(out, OUTPUT_NORMAL, "  {cyan}%s{reset}", profile);
            output_print(out, OUTPUT_NORMAL, "  {dim}(%s){reset}\n", status_str);
        }
    }

    /* Display summary section */
    output_section(out, OUTPUT_NORMAL, "Sync summary");

    if (up_to_date > 0) {
        output_print(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} up-to-date\n", up_to_date);
    }
    if (ahead > 0) {
        output_print(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} ahead\n", ahead);
    }
    if (behind > 0) {
        output_print(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} behind\n", behind);
    }
    if (diverged > 0) {
        output_print(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} diverged\n", diverged);
    }
    if (no_remote > 0) {
        output_print(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} no remote\n", no_remote);
    }
    if (no_local > 0) {
        output_print(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} no local branch\n", no_local);
    }
    if (failed > 0) {
        output_print(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} failed\n", failed);
    }
}

/**
 * Status command implementation
 */
error_t cmd_status(const dotta_ctx_t *ctx, const cmd_status_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;                /* Borrowed from dispatcher; do not free */
    content_cache_t *content_cache = ctx->run.content_cache;
    const manifest_t *manifest = ctx->run.manifest; /* The view at dispatch */
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Build operation scope
     *
     *   scope_enabled  — the persistent enabled set, the CLI filter's bound.
     *   scope_profiles — display face (enabled profile list, remote status).
     *
     * Zero enabled profiles is a valid state: workspace classifies all state
     * entries as orphaned. This enables the "disable last profile, then status"
     * workflow. scope_build returns success with an empty enabled set — no special
     * handling needed here. */
    scope_inputs_t scope_inputs = {
        .profiles      = opts->profiles,
        .profile_count = opts->profile_count,
    };
    scope_t *scope = NULL;
    error_t err = scope_build(repo, manifest, &scope_inputs, ctx->arena, &scope);
    if (err) return err;

    /* Load workspace for divergence analysis (only needed for local status)
     *
     * The workspace's profile set is the view's — the persistent enabled set —
     * so orphan detection is exact whatever -p narrowed.
     */
    workspace_t *ws = NULL;
    if (opts->show_local) {
        workspace_options_t ws_opts = {
            .analyze_orphans   = true,
            .analyze_untracked = config->auto_detect_new_files
        };
        err = workspace_load(
            repo, state, config, content_cache, manifest, &ws_opts, ctx->arena, &ws
        );
        if (err) return error_wrap(err, "Failed to load workspace");

        /* What the load owes the record — its observations, its confirmations,
         * the voids of orders the view took back (core/workspace.h workspace_flush)
         * — the confirmations seeding the fast path for subsequent status calls.
         * The flush keeps the failure of the transaction it takes, so status
         * renders what the load read whatever the flush met. */
        err = workspace_flush(ws);
        if (err) return err;
    }

    /* The enabled profiles and the last deployment of each */
    status_print_profiles(out, state, scope, ws, manifest);

    /* The whole view, on request — before the status line and the sections that
     * name only what diverged from it */
    if (opts->show_local && opts->full) {
        status_print_manifest(ws, scope, out);
    }

    /* The workspace status (with profile filtering for Coherent Scope)
     *
     * The workspace was loaded over the persistent enabled set (the view's) for
     * accurate divergence analysis. status_print_workspace then applies the CLI
     * filter dimension via scope_accepts_profile so `dotta status -p work` matches
     * `dotta apply -p work` behavior.
     */
    if (opts->show_local) {
        status_print_workspace(ws, scope, config, out);
    }

    /* Show remote sync status (if requested): no remote configured is no section,
     * and every failure of its own is a line of it */
    if (opts->show_remote) {
        status_print_remote(ctx, scope_profiles(scope), opts->all_profiles, opts->no_fetch);
    }

    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Resolve the --local / --remote intent pair into show_local / show_remote. Legacy
 * default: both true when neither flag given. Explicit flags reduce to their
 * own scope; giving both is identical to the default.
 */
static error_t status_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_status_options_t *o = opts_v;

    if (!o->want_local && !o->want_remote) {
        o->show_local = true;
        o->show_remote = true;
    } else {
        o->show_local = o->want_local != 0;
        o->show_remote = o->want_remote != 0;
    }
    return NULL;
}

/**
 * What can stand at the cursor: an enabled profile, by -p or bare.
 */
static args_want_t status_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) opts_v;
    (void) at;
    const dotta_ctx_t *ctx = ctx_v;

    completion_profiles(ctx, out, COMPLETION_ENABLED);
    return ARGS_WANT_NONE;
}

static error_t status_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_status(ctx, (const cmd_status_options_t *) opts_v);
}

static const args_opt_t status_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_APPEND(
        "p profile",         "<name>",
        cmd_status_options_t,profiles,     profile_count,
        "Filter status to profile(s) (repeatable)"
    ),
    ARGS_FLAG(
        "local",
        cmd_status_options_t,want_local,
        "Restrict to filesystem status"
    ),
    ARGS_FLAG(
        "remote",
        cmd_status_options_t,want_remote,
        "Restrict to remote sync status"
    ),
    ARGS_FLAG(
        "no-fetch",
        cmd_status_options_t,no_fetch,
        "Skip remote fetch; use cached refs"
    ),
    ARGS_FLAG(
        "all",
        cmd_status_options_t,all_profiles,
        "Include non-enabled profiles"
    ),
    ARGS_FLAG(
        "full",
        cmd_status_options_t,full,
        "List every active path with its state"
    ),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_status_options_t,verbosity,    DOTTA_VERBOSITY_VERBOSE,
        "Verbose output"
    ),
    /* Positional profile filters share the `profiles` APPEND field. */
    ARGS_POSITIONAL_ANY(
        cmd_status_options_t,profiles,     profile_count
    ),
    ARGS_END,
};

const args_command_t spec_status = {
    .name         = "status",
    .summary      = "Show workspace status and remote sync state",
    .usage        = "%s status [options] [profile]...",
    .description  =
        "Report divergence between enabled profiles and the filesystem,\n"
        "plus each profile's push/pull state against its remote. Default\n"
        "scope covers both; --local and --remote restrict it.\n",
    .notes        =
        "Ownership:\n"
        "  Ownership is compared like mode, without privileges. A path whose\n"
        "  permissions refuse the read is reported as [unreadable]; run the\n"
        "  command under sudo to verify it.\n"
        "\n"
        "Remote State Indicators:\n"
        "  =    up-to-date with remote\n"
        "  ↑ n  n commits ahead of remote (ready to push)\n"
        "  ↓ n  n commits behind remote (run '%s sync' to pull)\n"
        "  ↕    diverged from remote (needs resolution)\n"
        "  •    no remote tracking branch\n"
        "  ?    no local branch\n",
    .examples     =
        "  %s status                         # Local + remote\n"
        "  %s status --local                 # Filesystem only\n"
        "  %s status --remote                # Remote only\n"
        "  %s status --no-fetch              # Skip fetch (cached refs)\n"
        "  %s status -p work -p home         # Named profiles only\n"
        "  %s status --all                   # Include non-enabled profiles\n"
        "  %s status --full                  # Every active path, clean ones too\n",
    .epilogue     =
        "See also:\n"
        "  %s apply           # Deploy the pending filesystem changes\n"
        "  %s update          # Commit local filesystem changes\n"
        "  %s sync            # Reconcile with remote\n",
    .opts_size    = sizeof(cmd_status_options_t),
    .opts         = status_opts,
    .post_parse   = status_post_parse,
    .complete     = status_complete,
    .payload      = &(const dotta_needs_t){
        .repo     = DOTTA_REPO_OPEN,
        .state    = DOTTA_STATE_READ,
        .crypto   = DOTTA_CRYPTO_CACHED,
        .manifest = true,
    },
    .dispatch     = status_dispatch,
};
