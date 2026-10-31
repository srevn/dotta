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
#include "base/array.h"
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
#include "sys/remote.h"
#include "sys/stats.h"

/**
 * Print the enabled profiles and the last deployment of each — or, where no profile
 * is enabled, the sentence that says so in the section's place
 *
 * @param out Output context (must not be NULL)
 * @param state The enabled rows: whether the section stands, and the binding
 *              printed beside a bound profile's name, the thing never printed
 *              without the where
 * @param scope The profiles the block lists — the filter's under -p, else the
 *              enabled set's (must not be NULL)
 * @param ws Workspace the record comes from: the per-profile last-deployed
 *           timestamp is folded from its items (NULL when no workspace was loaded
 *           — it lends none then)
 * @param view The view the block reads in every run: the verbose per-profile
 *             counts are its rows, and its health the annotations (must not be
 *             NULL)
 */
static void status_print_profiles(
    output_t *out,
    const state_t *state,
    const scope_t *scope,
    const workspace_t *ws,
    const manifest_t *view
) {
    /* No profile enabled: the sentence profile list says over the same rows, in
     * the section's place (cmds/profile.c profile_list). Asked of the state's
     * rows, never the scope's: the scope holds the enabled profiles whose branch
     * is here (core/scope.h scope_enabled), and one whose branch is gone is a
     * row of the section all the same, "(no branch)" */
    if (state_profiles(state).count == 0) {
        output_info(out, OUTPUT_NORMAL, "No enabled profiles");
        return;
    }

    const string_array_t *profiles = scope_profiles(scope);

    /* The view's health, annotated onto the block. The claims the build could
     * not place, onto their profile's line (a count, the paths under -v), the
     * repair a legend line under the block; its sibling, the names a profile
     * holds for a path it also names otherwise, annotated and listed the same
     * way; and the claims a profile's own claims contradict, the same way again,
     * each beside what leaves it no room — the three say a profile carries more
     * than it projects, for three different reasons. And the enabled profiles
     * the build found no branch for, a line each beneath the rest: a profile
     * the state enables is not left out of the block that lists the enabled. */
    manifest_unbound_t unbound = manifest_unbound(view);
    manifest_unkept_t unkept = manifest_unkept(view);
    manifest_contradicted_t contradicted = manifest_contradicted(view);
    manifest_missing_t missing = manifest_missing(view);

    /* Show enabled profiles */
    output_section(out, OUTPUT_NORMAL, "Enabled profiles");

    /* What a profile contributes to this machine is its rows of both kinds —
     * the view's, which every run holds, each row's own type saying which — and
     * when it last deployed them is its record's, which a loaded workspace lends */
    manifest_rows_t rows = manifest_rows(view);
    workspace_items_t active = workspace_active(ws);

    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->entries[i];

        /* Format profile name, and the binding when the row has one: each part
         * of the row a space after the last, as a list row's metadata follows
         * its path (base/output.h output_list_render) */
        output_print(out, OUTPUT_NORMAL, "  {cyan}%s{reset}", profile);
        const char *target = state_target(state, profile);
        if (target) {
            char shown[PATH_MAX];
            output_format_path(target, identity()->home, shown, sizeof(shown));
            output_print(out, OUTPUT_NORMAL, " {dim}→ %s{reset}", shown);
        }

        /* One walk of the active items per profile: the latest of its own ownership
         * events among the rows it owns now — the honest set for an
         * enabled-profiles header. A record another profile's deployment left
         * at one of those rows is that profile's event, a reassignment apply
         * has yet to acknowledge (core/workspace.h workspace_reassigned), and
         * dates this one nothing. */
        time_t profile_deploy_time = 0;
        for (size_t j = 0; j < active.count; j++) {
            const workspace_item_t *item = active.entries[j];
            if (strcmp(item->profile, profile) != 0) continue;

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

        /* Nor are the paths the view does not use. One count and not two: the
         * repair is per path, and the file each of them reaches is on its own
         * -v line, which is worth more than a tally of the files. */
        size_t unused = 0;
        for (size_t j = 0; j < unkept.count; j++) {
            if (strcmp(unkept.entries[j].profile, profile) == 0) unused++;
        }

        /* Nor are the claims its own claims contradict: a file of the profile
         * stands at or above each, or claims of its own beneath it take its place,
         * so the view has no row for them. */
        size_t voided = 0;
        for (size_t j = 0; j < contradicted.count; j++) {
            if (strcmp(contradicted.entries[j].profile, profile) == 0) voided++;
        }

        /* Show per-profile last deployed timestamp */
        if (profile_deploy_time > 0) {
            char relative_buf[64];
            timeutil_relative(
                profile_deploy_time, relative_buf, sizeof(relative_buf)
            );

            /* Display dimmed timestamp */
            output_print(
                out, OUTPUT_NORMAL, " {dim}(deployed %s){reset}",
                relative_buf
            );
        }

        if (unplaced > 0) {
            output_print(
                out, OUTPUT_NORMAL,
                " {yellow}(%zu custom/ path%s need%s a deployment target){reset}",
                unplaced, unplaced == 1 ? "" : "s", unplaced == 1 ? "s" : ""
            );
        }

        if (unused > 0) {
            output_print(
                out, OUTPUT_NORMAL, " {yellow}(%zu unused path%s){reset}",
                unused, unused == 1 ? "" : "s"
            );
        }

        if (voided > 0) {
            output_print(
                out, OUTPUT_NORMAL, " {yellow}(%zu contradicted path%s){reset}",
                voided, voided == 1 ? "" : "s"
            );
        }

        /* In verbose mode, name what this profile contributes: one walk of the
         * view, each kind counted as what the profile holds is (core/profiles.h
         * profile_counts_t) — a derived row is the way to a tracked path, never
         * a directory of the profile's own */
        if (output_is_verbose(out)) {
            size_t file_count = 0;
            size_t dir_count = 0;
            for (size_t j = 0; j < rows.count; j++) {
                const manifest_row_t *row = rows.entries[j];
                if (strcmp(row->profile, profile) != 0) continue;

                if (path_type_kind(row->type) == PATH_KIND_FILE) file_count++;
                else if (!manifest_is_derived(row)) dir_count++;
            }

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

            /* What leaves the claim no room is what a repair chooses against,
             * and where it stands decides which verb keeps which (the legend
             * below): a directory taking the claim's place, or a file at the
             * claim's own path or above it. By storage path: the shape is a
             * relation of the two names, and the remedies take names. */
            for (size_t j = 0; j < contradicted.count; j++) {
                const manifest_contradicted_claim_t *claim = &contradicted.entries[j];
                if (strcmp(claim->profile, profile) != 0) continue;

                if (claim->place) {
                    output_print(
                        out, OUTPUT_NORMAL,
                        "\n    contradicted: %s%s (the directory %s takes its place)",
                        claim->storage_path, path_kind_suffix(claim->kind), claim->place
                    );
                } else {
                    output_print(
                        out, OUTPUT_NORMAL, "\n    contradicted: %s%s (%s the file %s)",
                        claim->storage_path, path_kind_suffix(claim->kind),
                        strcmp(claim->storage_path, claim->blob_above) == 0
                        ? "at" : "beneath", claim->blob_above
                    );
                }
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
        output_print(out, OUTPUT_NORMAL, " {yellow}(no branch){reset}\n");
    }

    /* The repairs, in the shape this screen spells a repair: a legend under the
     * block it belongs to, each line a dimmed annotation and its sentence, the
     * annotations aligned — what a list's legend does for its tags (base/output.h
     * output_list_legend), with the yellow annotation above playing the tag's
     * part. `Hint:` is apply's voice and sync's, and this channel was the only
     * thing in status that spoke it.
     *
     * Generic in both the profile and the path. The annotations say which profiles
     * carry them, so one filled name would read as the only one wherever two
     * do; and the path is the -v listing's to spell, where a name holding a space
     * is read rather than pasted into a command it would break. `--dry-run` is
     * the whole of the unused-path safety: dropping a directory name takes every
     * claim beneath it, and the preview shows that rather than asserting it.
     * The first two claims' lines are worth having at all because nothing else
     * offers them — neither claim has a row, so no completion source reaches
     * one; the contradicted claim's because which verb keeps which turns on a
     * shape only the -v line shows; and the missing profile's because nothing
     * else on this screen names it. */
    output_gap(out, OUTPUT_NORMAL);

    /* Each repair stands where a row this run displays carries its annotation:
     * the question is about the profiles shown, not the slices — -p filters the
     * scope's profiles while the view is always the whole enabled one, so a line
     * asked of a slice's own count would explain an annotation no row above it
     * carries. A block with none leaves its boundary owed to the next. */
    for (size_t i = 0; i < unbound.count; i++) {
        if (scope_accepts_profile(scope, unbound.entries[i].profile)) {
            /* Placing them is the repair; stopping tracking one is every claim's
             * way out (dotta remove), never this annotation's */
            output_hintline(
                out, OUTPUT_NORMAL,
                "  custom/ paths - run 'dotta profile enable <profile> --target /path' "
                "to place them"
            );
            break;
        }
    }

    for (size_t i = 0; i < unkept.count; i++) {
        if (scope_accepts_profile(scope, unkept.entries[i].profile)) {
            /* The trailing space is the alignment: one annotation a column short
             * of the other. */
            output_hintline(
                out, OUTPUT_NORMAL,
                "  unused paths  - run 'dotta remove --dry-run <profile> <path>' to "
                "preview it"
            );
            break;
        }
    }

    for (size_t i = 0; i < contradicted.count; i++) {
        if (scope_accepts_profile(scope, contradicted.entries[i].profile)) {
            /* A line a shape the -v line names, one remedy a line. The directory
             * is kept by taking the file, which names a blob and takes it alone
             * (cmds/remove.c remove_resolve); on a machine whose disk holds the
             * file, its record stays under the directory's row as dotta's own
             * copy, which apply replaces with the directory — unasked where the
             * copy is untouched, under --force where it was edited (the frame
             * across kinds, core/workspace.h workspace_displaced_t). The file
             * is kept by taking what leaves it no room: a claim beneath it by
             * its own path, which names that claim and never the file above it;
             * the directory taking its place by its name, which takes every claim
             * of the profile beneath that name; and, where the two are one path,
             * which would name the file, by capturing the file over it. */
            output_hintline(
                out, OUTPUT_NORMAL,
                "  contradicted  - run 'dotta remove <profile> <file>' to keep the "
                "directory, which apply then creates in the file's place"
            );
            output_hintline(
                out, OUTPUT_NORMAL,
                "                  run 'dotta remove <profile> <path>' to keep "
                "the file the path is beneath, or whose place it takes"
            );
            output_hintline(
                out, OUTPUT_NORMAL,
                "                  run 'dotta add --force <profile> <file>' to keep the "
                "file the directory is at"
            );
            break;
        }
    }

    for (size_t i = 0; i < missing.count; i++) {
        if (scope_accepts_profile(scope, missing.entries[i])) {
            /* Enable's two ways for the same fact, in its order (cmds/profile.c
             * profile_enable): the profile let go, or its branch brought back
             * from the remote, which sync says it cannot where the remote holds
             * none */
            output_hintline(
                out, OUTPUT_NORMAL,
                "  no branch     - run 'dotta profile disable <profile>' to drop it"
            );
            output_hintline(
                out, OUTPUT_NORMAL,
                "                  or run 'dotta sync <profile>' "
                "to bring its branch back"
            );
            break;
        }
    }
}

/**
 * Print the manifest — every active path, with its state
 *
 * The window onto the view (--full): one line per active path, both kinds merged
 * in path order, tagged as its item says — [clean] or [ancestor] where nothing
 * diverged (workspace_item_line) — with the owning profile ("from P", or "P →
 * Q" for a pending reassignment). The one listing that shows the whole view rather
 * than what diverged from it; printed whatever the workspace's cleanliness. Orphans
 * are records, not rows — the workspace's sections list them
 * (status_print_workspace). Scoped by the CLI filter like every other section.
 *
 * @param out Output context (must not be NULL)
 * @param ws Workspace (must not be NULL, borrowed from caller)
 * @param scope Operation scope (must not be NULL; its filter dimension drives
 *              display)
 */
static void status_print_manifest(
    output_t *out,
    const workspace_t *ws,
    const scope_t *scope
) {
    /* The one listing that asks nothing of the user, so its header says what it
     * lists rather than a command — and what its two tags of agreement mean,
     * since every row carries one — where every other header names one */
    output_list_t *list = output_list_create(
        out, "Manifest",
        "every active path; [clean] where nothing diverged, [ancestor] where dotta "
        "only passes through"
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

        /* Every item its one line, a clean one too: what agreement reads as is
         * the class's to say, and one that DID diverge keeps its own tags — absence
         * and a squatter are read of both classes, and they already say the
         * actionable thing. */
        const workspace_line_t line = workspace_item_line(item);

        output_list_add(list, line.tags, line.color, line.path, line.metadata);
    }

    output_list_render(list);
    output_list_free(list);
}

/**
 * What status made of the diverged items, in scope: each filed once, in the section
 * that settles it — and how many the filter hid
 *
 * One walk files every in-scope item into one slice (status_partition), read by
 * the workspace line's fold (status_print_summary) and by the sections that list
 * them (status_print_workspace), in the order they print. The slices are one
 * classification's buckets (core/workspace.h workspace_buckets_t), each in the
 * diverged items' order, in the arena the partition was made in — the items
 * borrowed, the workspace's.
 */
typedef struct {
    workspace_items_t conflicts;     /* CONFLICT and KIND: neither verb's by default */
    workspace_items_t unconfirmed;   /* UNCONFIRMED: no base proves who moved */
    workspace_items_t squatted;      /* KIND_DERIVED: one verb, and no decision */
    workspace_items_t displaced;     /* DISPLACED_*: beneath a squatter, not looked at */
    workspace_items_t unverifiable;  /* UNVERIFIABLE, and UNSCANNED: the looks that failed */
    workspace_items_t uncommitted;   /* CAPTURE, and DELETED: update's */
    workspace_items_t reassigned;    /* REASSIGNED: apply's, in the record alone */
    workspace_items_t undeployed;    /* STALE, and UNDEPLOYED: apply's */
    workspace_items_t new_files;     /* UNTRACKED: update's, where it is asked */
    workspace_items_t overridden;    /* OVERRIDDEN: the landing's above each */
    workspace_items_t orphaned;      /* PRUNABLE and SKIPPED, and OBSTRUCTING: apply's */
    workspace_items_t released;      /* ABSENT and RELEASED: the record's alone */
    size_t hidden;                   /* The diverged items the filter hides */
} status_partition_t;

/**
 * File the workspace's diverged items for status: each in scope in the section
 * that settles it, the rest counted as hidden
 *
 * @param ws Workspace (must not be NULL)
 * @param scope Operation scope (must not be NULL; its filter dimension decides
 *              what is filed)
 * @param arena Arena the partition's slices live in: the command's (must not be
 *              NULL)
 * @param partition Output, zeroed then filled (must not be NULL)
 */
static void status_partition(
    const workspace_t *ws,
    const scope_t *scope,
    arena_t *arena,
    status_partition_t *partition
) {
    CHECK_NULL(ws);
    CHECK_NULL(scope);
    CHECK_NULL(arena);
    CHECK_NULL(partition);

    *partition = (status_partition_t){ 0 };

    /* The sections' slices: each item in scope is added to its section's as the
     * walk decides it, and the twelve are filled once the walk is done
     * (core/workspace.h workspace_buckets_t) — in the arena the partition was
     * made in, so they outlive the printers that read them (include/runtime.h
     * "Memory") */
    workspace_items_t diverged = workspace_diverged(ws);
    workspace_buckets_t *buckets = workspace_buckets_create(arena);

    for (size_t i = 0; i < diverged.count; i++) {
        const workspace_item_t *item = diverged.entries[i];

        /* Coherent Scope: under a profile filter only its profiles' items are
         * shown, so status matches what apply would do; the rest are hidden,
         * and counted beneath the sections. A landing's orphan is filtered by
         * its record's profile and a derived rung by its own, where apply -p
         * reaches each from another row: under -p a status can list one apply
         * leaves, or hide one it acts on (stated) */
        if (!scope_accepts_profile(scope, item->profile)) {
            partition->hidden++;
            continue;
        }

        switch (item->state) {
            case WORKSPACE_STATE_DEPLOYED:
                /* One bucket per route — the same table update's filter and skip
                 * counter read (workspace_item_route), so no section promises a
                 * verb the verb refuses */
                switch (workspace_item_route(item)) {
                    case WORKSPACE_ROUTE_DISPLACED_TRACKED:
                    case WORKSPACE_ROUTE_DISPLACED_DERIVED:
                    case WORKSPACE_ROUTE_DISPLACED_STALE:
                    case WORKSPACE_ROUTE_DISPLACED_CONFLICT:
                        /* Not looked at, so no path bit of its own — the squatter's
                         * section names the way out */
                        workspace_buckets_add(buckets, item, &partition->displaced);
                        break;

                    case WORKSPACE_ROUTE_CONFLICT:
                    case WORKSPACE_ROUTE_KIND:
                        /* Neither verb's by default — its own header names the
                         * way out */
                        workspace_buckets_add(buckets, item, &partition->conflicts);
                        break;

                    case WORKSPACE_ROUTE_UNCONFIRMED:
                        /* Neither verb's by default either, and for another reason:
                         * no base proves who moved — its own header names both
                         * ways out */
                        workspace_buckets_add(buckets, item, &partition->unconfirmed);
                        break;

                    case WORKSPACE_ROUTE_KIND_DERIVED:
                        /* One verb and no decision — its own header names the
                         * verb */
                        workspace_buckets_add(buckets, item, &partition->squatted);
                        break;

                    case WORKSPACE_ROUTE_UNVERIFIABLE:
                        workspace_buckets_add(buckets, item, &partition->unverifiable);
                        break;

                    case WORKSPACE_ROUTE_STALE:
                        /* Apply's work, the same bucket as a path never deployed;
                         * the [stale] tag says which */
                        workspace_buckets_add(buckets, item, &partition->undeployed);
                        break;

                    case WORKSPACE_ROUTE_CAPTURE:
                        /* Real divergence → uncommitted changes */
                        workspace_buckets_add(buckets, item, &partition->uncommitted);
                        break;

                    case WORKSPACE_ROUTE_REASSIGNED:
                        /* Pure profile reassignment (no filesystem divergence) */
                        workspace_buckets_add(buckets, item, &partition->reassigned);
                        break;

                    case WORKSPACE_ROUTE_CLEAN:
                        /* None: a diverged item has something to say
                         * (workspace_diverged); the workspace's line reads the
                         * sections, so one filed nowhere would not count */
                        break;
                }
                break;

            case WORKSPACE_STATE_DELETED:
                /* Deleted paths, either kind → uncommitted changes */
                workspace_buckets_add(buckets, item, &partition->uncommitted);
                break;

            case WORKSPACE_STATE_UNDEPLOYED:
                workspace_buckets_add(buckets, item, &partition->undeployed);
                break;

            case WORKSPACE_STATE_UNTRACKED:
                workspace_buckets_add(buckets, item, &partition->new_files);
                break;

            case WORKSPACE_STATE_UNSCANNED:
                /* Where the scan could not look: no verb is promised, and New
                 * files' closer would send it to an update that never takes it */
                workspace_buckets_add(buckets, item, &partition->unverifiable);
                break;

            case WORKSPACE_STATE_ORPHANED:
            case WORKSPACE_STATE_RELEASED:
                /* A scope exit's, filed by what apply does with it, read off
                 * the item alone (core/cleanup.h cleanup_verdict) — unforced,
                 * though --force only turns a skip into a prune, and never moves
                 * an orphan between the two sections: a reclaim and a release
                 * touch nothing on disk and are listed apart; a prune and a skip
                 * are Orphaned paths, apply's word for both (cmds/apply.c
                 * apply_print_cleanup_receipt), a directory's prune skipped all
                 * the same while an orphan in it stays */
                switch (cleanup_verdict(item, false)) {
                    case CLEANUP_ABSENT:
                    case CLEANUP_RELEASED:
                        workspace_buckets_add(buckets, item, &partition->released);
                        break;

                    case CLEANUP_SKIPPED:
                    case CLEANUP_PRUNABLE:
                        workspace_buckets_add(buckets, item, &partition->orphaned);
                        break;
                }
                break;

            case WORKSPACE_STATE_OBSTRUCTING:
                /* The landing's, of the rows beneath dotta's node: an orphan of
                 * its own kind, among the Orphaned paths, its legend lines its
                 * own */
                workspace_buckets_add(buckets, item, &partition->orphaned);
                break;

            case WORKSPACE_STATE_OVERRIDDEN:
                /* The landing's too, of the blob standing over it — listed apart,
                 * each line naming that blob (section 10) */
                workspace_buckets_add(buckets, item, &partition->overridden);
                break;
        }
    }

    workspace_buckets_fill(buckets);
}

/**
 * Print where the view, the record and the filesystem disagree: the diverged
 * items in actionable sections (git-like structure), each under the verb that
 * settles it — nothing where none is in scope
 *
 * A header says what its rows are where the title's word needs it, then, as `run
 * '<command>' to <act> them`, the verb that settles them by default — or, where
 * no command does, what dotta does with them — and never catalogues. A legend
 * line beneath the rows (base/output.h output_list_legend) speaks for one tag
 * string, reading what those tags say and nothing else, so it is true of every
 * row carrying them: what those rows take instead of the header's verb (`run
 * …`), beside it (`or run …`), or, where no command applies, why (a clause). No
 * legend line repeats its header, and none stands for a string whose rows the
 * header answers.
 *
 * @param out Output context (must not be NULL)
 * @param partition The diverged items, filed (must not be NULL)
 * @param manifest The view the workspace was loaded over (must not be NULL; an
 *                 overridden copy's line names what stands over it, off the view)
 * @param config Configuration (must not be NULL; its switch words a [locked]
 *               legend line's remedy)
 */
static void status_print_workspace(
    output_t *out,
    const status_partition_t *partition,
    const manifest_t *manifest,
    const config_t *config
) {
    /* Section 1: Conflicts — the buckets no default verb resolves lead, each a
     * choice between disk's side and Git's, in the words the frame and the route
     * bind (core/workspace.h divergence_type_t, workspace_route_t): content or
     * a kind moved on both sides, or a kind no capture commits on a row a plan
     * can hold — a rung dotta only passes through, which the user squats, has
     * its own section below, since no flag lifts it. The header names the side
     * that loses nothing, as git's own conflict names "git add": `add --force`
     * commits disk's bytes, and Git keeps the other side in its history, where
     * `apply --force` would overwrite bytes nothing else holds. It is spelled
     * whole, the profile before the path: add reads its first word as the profile,
     * so a path typed alone leaves it none (cmds/add.c add_post_parse). The legend
     * names Git's side beside it, by the tag a row leads with. `add --force`
     * keeps disk's bytes and not its kind: a change across file and directory
     * is a re-shaping of the tree, which add refuses by the claim standing at
     * the path, naming `dotta remove` (cmds/add.c), which stops tracking the
     * path on every machine and keeps the node — so a [type] row's line names
     * that instead, its reach said with it, since a row on this machine reads
     * as this machine's to settle (update's census says it the same way), and
     * never `apply --force`, which replaces a directory in a blob row's way only
     * with all it holds, its walk stopping at what no landing removes, --force
     * included (core/deploy.c check_clearance), which status, reading no clearance,
     * cannot tell apart. A link standing at a file row is a file to add's kind
     * test, so the [type] line says more than its row needs there (stated: the
     * tag cannot tell the link from the directory). Every other row is a file
     * row with a file or a link standing, whose bytes `apply --force` replaces,
     * named with the path it lifts the skip at, since a bare one lifts every
     * consent skip of the run, the edited copies other machines' deletions left
     * among them. */
    if (partition->conflicts.count > 0) {
        output_list_t *list = output_list_create(
            out, "Conflicts", "run 'dotta add --force <profile> <path>' to keep disk's"
        );

        for (size_t i = 0; i < partition->conflicts.count; i++) {
            const workspace_item_t *item = partition->conflicts.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);

            /* [type] where the line leads with it: no conflict is displaced (the
             * DISPLACED_* routes file it below), so the tag is the bit */
            const char *legend = (item->divergence & DIVERGENCE_TYPE)
                ? "run 'dotta remove <profile> <path>' to stop tracking it "
                "on every machine"
                : "or run 'dotta apply --force <path>' to keep Git's";
            output_list_legend(list, line.tags, legend);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 2: Unconfirmed paths — bytes no base proves (the route's
     * UNCONFIRMED): disk is not the row's, and the record holds no confirmation
     * of what stands there, nor, where it could be asked, did the row's own branch
     * hold disk's bytes at the name (core/workspace.c workspace_ask_bases), so
     * nothing says whose move that is — the second bucket no default verb resolves,
     * beside the conflicts. Its header opens with what its rows are, in the route's
     * words (core/workspace.h workspace_route_t), as update's census and diff's
     * status line say it. Its header and its legend name the two sides as theirs
     * do, each unqualified: every row is a file row with a regular file or a
     * link standing — a directory row and every other kind answer at KIND, above
     * — which `add --force` captures, a link being a file to add's kind test
     * (cmds/add.c), and `apply --force` replaces. The header names disk's, the
     * side that loses nothing, as the Conflicts header does; the legend names
     * Git's, true of every row. */
    if (partition->unconfirmed.count > 0) {
        output_list_t *list = output_list_create(
            out, "Unconfirmed paths",
            "not confirmed by dotta; "
            "run 'dotta add --force <profile> <path>' to keep disk's"
        );

        for (size_t i = 0; i < partition->unconfirmed.count; i++) {
            const workspace_item_t *item = partition->unconfirmed.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
            output_list_legend(
                list, line.tags, "or run 'dotta apply --force <path>' to keep Git's"
            );
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 3: Squatted ancestors — a different kind stands at a directory
     * dotta only passes through (the route's KIND_DERIVED): never planned, so
     * no flag lifts it and no decision pends. The header opens with the route's
     * words, as update's census and diff's status line say it, then its one verb,
     * the named re-derivation, the word update's counted line already uses. */
    if (partition->squatted.count > 0) {
        output_list_t *list = output_list_create(
            out, "Squatted ancestors",
            "a different kind stands at a directory dotta only passes through; "
            "run 'dotta update <dir>' to re-derive them"
        );

        for (size_t i = 0; i < partition->squatted.count; i++) {
            const workspace_item_t *item = partition->squatted.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 4: Displaced paths — beneath a squatter Conflicts or Squatted
     * ancestors above holds, or Undeployed changes below where it is dotta's
     * own copy Git moved past, untouched, or Orphaned paths where it is dotta's
     * own node at no row, the landing's of the paths beneath it (the route's
     * DISPLACED_* arms, the squatter's own route inherited): nothing there was
     * looked at, so the line shows [displaced] and only what no look decides or
     * disproves beside it (the blob's verdict, a reassignment), and the header
     * sends the user to the squatter, whose own section names its verb — the
     * one header with no command of its own, since the command is the squatter's.
     * The header opens with the predicate, as every sentence about such a path
     * does, and spells the squatter out where the other four name it with the
     * word — this is where the word is grounded (core/workspace.h
     * workspace_displaced_t). Under -p the squatter's row may be filtered while
     * a child is not, and the bare status lists both. */
    if (partition->displaced.count > 0) {
        output_list_t *list = output_list_create(
            out, "Displaced paths",
            "not looked at: a different kind stands at a directory above them; "
            "resolve that directory first"
        );

        for (size_t i = 0; i < partition->displaced.count; i++) {
            const workspace_item_t *item = partition->displaced.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 5: Unverifiable paths — the bucket no verb resolves: dotta could
     * not look, so no verb acts on them. The header opens with what its rows
     * are, as the headers that name a route's meaning do, then says what the
     * verbs do with them, since no one command settles three failed looks. A
     * legend beneath names each failed look's way out where it has one, one line
     * per tag string the block shows: one sentence over three refusals is how a
     * locked path came to be told to fix its permissions. */
    if (partition->unverifiable.count > 0) {
        output_list_t *list = output_list_create(
            out, "Unverifiable paths",
            "dotta could not verify them; apply and update skip them"
        );

        for (size_t i = 0; i < partition->unverifiable.count; i++) {
            const workspace_item_t *item = partition->unverifiable.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);

            /* The failed look's way out: the key for the locked rows, and the
             * switch before it where encryption is off, a run that holds no key
             * at all; root for the unreadable ones and only where the run holds
             * none — offered, never promised, since a policy may deny root the
             * read as well. The residual class has no way out to name — there
             * is no one remedy for a foreign epoch, a cipher this build does
             * not read and an I/O error — and no verb that lists the path prints
             * its cause, the class being all the item carries (workspace_fault_t),
             * so its rows are the header's. */
            const char *legend = NULL;

            switch (item->fault) {
                case WORKSPACE_FAULT_LOCKED:
                    legend = config->encryption_enabled
                        ? "run 'dotta key set' to unlock it"
                        : "set encryption.enabled = true, then run 'dotta key set'";
                    break;
                case WORKSPACE_FAULT_UNREADABLE:
                    legend = identity()->privileged ? NULL : "run under sudo to read it";
                    break;
                case WORKSPACE_FAULT_NONE:
                case WORKSPACE_FAULT_UNVERIFIED:
                    break;
            }
            output_list_legend(list, line.tags, legend);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 6: Uncommitted changes — the user's moves, every row update's to
     * commit, as the header says. A legend beneath names apply where it settles
     * a row the other way unasked, by the tags each row shows: it puts a deletion
     * back, and restores a claim alone, a claim being no edit (core/deploy.h
     * deploy_content_conflicts). An edit, a kind a capture commits, and the blob's
     * policy take no legend line: apply skips the first two, and the third is
     * update's alone. A deletion's line names what update's commit reaches —
     * every machine's unchanged copy — as update's preview header words it
     * (cmds/update.c update_print_preview), since a user reading only status
     * could not guess it; another enabled profile's claim taking the place where
     * one claims the path is said per path by that preview. */
    if (partition->uncommitted.count > 0) {
        output_list_t *list = output_list_create(
            out, "Uncommitted changes", "run 'dotta update' to commit them"
        );

        for (size_t i = 0; i < partition->uncommitted.count; i++) {
            const workspace_item_t *item = partition->uncommitted.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);

            const char *legend = NULL;

            /* By the state, exhaustive as the partition's switch is, so a state
             * added to this bucket asks for an arm of its own here */
            switch (item->state) {
                case WORKSPACE_STATE_DEPLOYED:
                    /* The capture route, whose every bit is a tag of its own
                     * (workspace_item_route, workspace_item_line): the claim
                     * axes alone are [mode] and [ownership], a reassignment riding
                     * beside them or not, which apply restores beside the header's
                     * update — an owner a run under sudo left behind is what
                     * the user usually means to undo, never to commit for every
                     * machine */
                    if ((item->divergence & ~(DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) ==
                        DIVERGENCE_NONE) {
                        legend = "or run 'dotta apply' to restore it";
                    }
                    break;

                case WORKSPACE_STATE_DELETED:
                    legend = "or run 'dotta apply' to put it back; update deletes "
                        "every machine's unchanged copy";
                    break;

                case WORKSPACE_STATE_UNDEPLOYED:
                case WORKSPACE_STATE_ORPHANED:
                case WORKSPACE_STATE_UNTRACKED:
                case WORKSPACE_STATE_UNSCANNED:
                case WORKSPACE_STATE_RELEASED:
                case WORKSPACE_STATE_OVERRIDDEN:
                case WORKSPACE_STATE_OBSTRUCTING:
                    /* The partition's switch files no other state here */
                    CHECK_ARG(
                        false, "the uncommitted bucket holds DEPLOYED and DELETED alone"
                    );
            }
            output_list_legend(list, line.tags, legend);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 7: Profile reassignments — a clean row whose record names another
     * profile, which apply acknowledges at its checkpoint in the record alone:
     * listed, and the workspace's line leaves it as it finds it */
    if (partition->reassigned.count > 0) {
        output_list_t *list = output_list_create(
            out, "Profile reassignments", "run 'dotta apply' to acknowledge them"
        );

        for (size_t i = 0; i < partition->reassigned.count; i++) {
            const workspace_item_t *item = partition->reassigned.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 8: Undeployed changes — apply's work, both kinds: what Git has
     * and disk does not, a path apply is to create or a move of Git's disk has
     * not followed ([stale]). Named as its twin, Uncommitted changes, is. A legend
     * beneath names the one row a user meets after an act of their own: a copy
     * removed where Git moved past what dotta last saw there, whose absence deletes
     * nothing the view holds (core/workspace.c classify_absent), so it is here
     * and not among the deletions above, the [stale] its record gives it beside
     * [undeployed] saying why (workspace_item_line). It says that why alone,
     * the act being the header's. Every other row is the header's. */
    if (partition->undeployed.count > 0) {
        output_list_t *list = output_list_create(
            out, "Undeployed changes", "run 'dotta apply' to deploy them"
        );

        for (size_t i = 0; i < partition->undeployed.count; i++) {
            const workspace_item_t *item = partition->undeployed.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);

            const char *legend = NULL;

            /* By the state, exhaustive as the partition's switch is, so a state
             * added to this bucket asks for an arm of its own here */
            switch (item->state) {
                case WORKSPACE_STATE_UNDEPLOYED:
                    /* The [stale] its record gives it, read as the item's line
                     * reads it (core/workspace.h workspace_stale); every other
                     * absence here, a reassignment or a violation beside it, is
                     * the header's */
                    if (item->record && workspace_stale(item->row, item->record)) {
                        legend = "gone locally, and changed in Git since dotta saw it";
                    }
                    break;

                case WORKSPACE_STATE_DEPLOYED:
                    /* The STALE route, Git's move disk has not followed: the
                     * header's, whatever claims ride it */
                    break;

                case WORKSPACE_STATE_DELETED:
                case WORKSPACE_STATE_ORPHANED:
                case WORKSPACE_STATE_UNTRACKED:
                case WORKSPACE_STATE_UNSCANNED:
                case WORKSPACE_STATE_RELEASED:
                case WORKSPACE_STATE_OVERRIDDEN:
                case WORKSPACE_STATE_OBSTRUCTING:
                    /* The partition's switch files no other state here */
                    CHECK_ARG(
                        false, "the undeployed bucket holds DEPLOYED and UNDEPLOYED alone"
                    );
            }
            output_list_legend(list, line.tags, legend);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 9: New files — what the scan found beneath a directory a profile
     * tracks, every row update's to track, as the header says. The legend names
     * the other way out, true of every row: a pattern in the profile's
     * .dottaignore, which travels with it, keeps a file out on every machine —
     * the one way out for a file a removal took from inside a directory its profile
     * still tracks, which every scan offers back otherwise. A form, never a
     * command: a path holding a space or a glob character is the user's to quote
     * and escape, and ignore's help says what a pattern is matched against. */
    if (partition->new_files.count > 0) {
        output_list_t *list = output_list_create(
            out, "New files", "run 'dotta update --include-new' to track them"
        );

        for (size_t i = 0; i < partition->new_files.count; i++) {
            const workspace_item_t *item = partition->new_files.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
            output_list_legend(
                list, line.tags,
                "or run 'dotta ignore <profile> --add <pattern>' to keep it out"
            );
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 10: Overridden copies — orphans beneath a standing blob, each the
     * landing's of the row standing over it, which clears it (core/deploy.h
     * deploy_clearance). The header promises no flag and no tag has a legend
     * line, since a row's tags name what moved and not which cell it is: a bare
     * tag is a copy dotta confirmed — unasked — or one it never did — --force's
     * — and an [unreadable] one a read that failed — --force's — or a look — no
     * flag's. So it says what holds of every row: the landing clears the copy
     * where it can, and apply's skip names what keeps one. The workspace's line
     * counts none, a copy's work being its row's, which the line counts where
     * it shows that row (stated: a filter that hides it reads aligned over the
     * copy). Its blob is the one each row names, found by the call the orphan
     * analysis made the copy's state by (core/manifest.h manifest_blob_above),
     * the profile's own or another's, read off the view, since the item's line
     * reads the item alone, and composed onto its metadata in a buffer sized
     * for the path. */
    if (partition->overridden.count > 0) {
        output_list_t *list = output_list_create(
            out, "Overridden copies", "run 'dotta apply' to clear them where it can"
        );

        for (size_t i = 0; i < partition->overridden.count; i++) {
            const workspace_item_t *item = partition->overridden.entries[i];
            const workspace_line_t line = workspace_item_line(item);
            const manifest_row_t *above = manifest_blob_above(manifest, item->filesystem_path);
            char metadata[256 + PATH_MAX];

            if (strcmp(above->profile, item->profile) == 0) {
                snprintf(
                    metadata, sizeof(metadata), "%s, beneath its own %s", line.metadata,
                    above->filesystem_path
                );
            } else {
                snprintf(
                    metadata, sizeof(metadata), "%s, beneath %s's %s", line.metadata,
                    above->profile, above->filesystem_path
                );
            }
            output_list_add(list, line.tags, line.color, line.path, metadata);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 11: Orphaned paths — the scope exit's orphans apply prunes or skips
     * (core/cleanup.h cleanup_verdict: PRUNABLE, SKIPPED), apply's word for both
     * (cmds/apply.c apply_print_cleanup_receipt), and dotta's nodes the landing
     * of the rows beneath them replaces */
    if (partition->orphaned.count > 0) {
        output_list_t *list = output_list_create(
            out, "Orphaned paths", "run 'dotta apply' to prune them"
        );

        /* Every legend line reads the exact tags its row shows, said once per
         * tag string beneath the list, and reads what those tags say and nothing
         * else — never the kind, the relocation's class or what a directory holds,
         * which no tag carries — so it is true of every row it stands under.
         * The bare [orphaned] string has none: it is the header's, a file's and
         * a directory's: apply prunes a directory once the orphans in it go,
         * and skips it while one of them stays — that orphan's own row says why,
         * and apply's preview names the skip. A legend line says what becomes
         * of the item and not whether its parent admits the run: a parent that
         * refuses it is apply's skip line to name (stated). */
        for (size_t i = 0; i < partition->orphaned.count; i++) {
            const workspace_item_t *item = partition->orphaned.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);

            const char *legend = NULL;

            /* By the state, exhaustive as the partition's switch is, so a state
             * added to this bucket asks for an arm of its own here */
            switch (item->state) {
                case WORKSPACE_STATE_ORPHANED:
                    /* The line's ladder past absence and a squatter, which the
                     * partition's switch lists apart (section 12): the failed
                     * look or the bits, and the relocation beside them */
                    if (item->fault != WORKSPACE_FAULT_NONE) {
                        /* The way past the skip the failed look makes, by whose
                         * remedy it is (workspace_fault_t), so the line and its
                         * tag say the same thing: the key, or root where the
                         * run holds none, lets the next apply look, and prune
                         * what it finds unchanged. A directory shares [unreadable]
                         * and [unverified], and no flag lifts its skip, so neither
                         * names --force; [locked] is a file's alone, and names
                         * the key rather than --force, which would discard the
                         * copy unread — apply's skip block names that where it
                         * meets the row (cmds/apply.c apply_print_cleanup_skips).
                         * Read before the relocation, as the item's line ranks
                         * them. */
                        switch (item->fault) {
                            case WORKSPACE_FAULT_LOCKED:
                                legend = config->encryption_enabled
                                    ? "run 'dotta key set' to let apply prune it"
                                    : "set encryption.enabled = true, then run "
                                    "'dotta key set'";
                                break;
                            case WORKSPACE_FAULT_UNREADABLE:
                                legend = identity()->privileged
                                    ? "apply skips it"
                                    : "run under sudo to let apply prune it";
                                break;
                            case WORKSPACE_FAULT_NONE:
                            case WORKSPACE_FAULT_UNVERIFIED:
                                legend = "apply skips it";
                                break;
                        }
                    } else if (item->divergence &
                        (DIVERGENCE_CONTENT | DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
                        /* The tags name what changed — [modified], [mode],
                         * [ownership], a file's alone — so the line says only
                         * the way past the skip: --force lifts it whatever
                         * [relocated] beside them says, named with the path it
                         * lifts the skip at, here as on every screen naming it
                         * (the Conflicts section above says why) */
                        legend = "run 'dotta apply --force <path>' to prune it";
                    } else if (item->relocation != WORKSPACE_RELOCATION_NONE) {
                        /* One line for every [relocated] string: a re-target
                         * apply prunes and a moved home it skips share the tag
                         * string, and a claim that moved stands at its new path
                         * or nowhere, so it names the one case the header's verb
                         * does not settle, never where the claim stands */
                        legend = "if home moved, run 'dotta apply --force <path>'";
                    }
                    break;

                case WORKSPACE_STATE_OBSTRUCTING:
                    /* The landing's consent (core/deploy.h deploy_clearance),
                     * by the tags in the order they rank: what moved, and the
                     * replace --force gives where cleanup's would be a prune —
                     * save a claim, which is never an edit, and the bare
                     * [obstructing], whose line says what the landing does with
                     * the node. The failed look's lines are the orphan's above,
                     * the replace in the prune's place: a node whose look failed
                     * is replaced only under --force (deploy_clearance), the
                     * key the safe way for a locked one, which lets the landing
                     * look first */
                    if (item->fault != WORKSPACE_FAULT_NONE) {
                        switch (item->fault) {
                            case WORKSPACE_FAULT_LOCKED:
                                legend = config->encryption_enabled
                                    ? "run 'dotta key set' to let apply replace it"
                                    : "set encryption.enabled = true, then run "
                                    "'dotta key set'";
                                break;
                            case WORKSPACE_FAULT_UNREADABLE:
                            case WORKSPACE_FAULT_NONE:
                            case WORKSPACE_FAULT_UNVERIFIED:
                                legend = "run 'dotta apply --force <path>' "
                                    "to replace it";
                                break;
                        }
                    } else if (item->divergence & DIVERGENCE_CONTENT) {
                        legend = "run 'dotta apply --force <path>' to replace it";
                    } else {
                        legend = "run 'dotta apply' to replace it with a directory";
                    }
                    break;

                case WORKSPACE_STATE_DEPLOYED:
                case WORKSPACE_STATE_UNDEPLOYED:
                case WORKSPACE_STATE_DELETED:
                case WORKSPACE_STATE_UNTRACKED:
                case WORKSPACE_STATE_UNSCANNED:
                case WORKSPACE_STATE_RELEASED:
                case WORKSPACE_STATE_OVERRIDDEN:
                    /* The partition's switch files no other state here */
                    CHECK_ARG(
                        false, "the orphaned bucket holds ORPHANED and OBSTRUCTING alone"
                    );
            }
            output_list_legend(list, line.tags, legend);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Section 12: Released paths — the scope exit's orphans apply settles in
     * the record alone (core/cleanup.h cleanup_verdict: ABSENT, RELEASED): it
     * retires each record and touches nothing on disk, which is what the header
     * says of every row; a row says why where the item can, and the legend the
     * rest, by the tags each row shows. Last, since nothing here asks the user
     * anything, and the workspace's line leaves it as it finds it. */
    if (partition->released.count > 0) {
        output_list_t *list = output_list_create(
            out, "Released paths", "run 'dotta apply' to release them; disk stays as is"
        );

        for (size_t i = 0; i < partition->released.count; i++) {
            const workspace_item_t *item = partition->released.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);

            const char *legend = NULL;

            /* By the state, exhaustive as the partition's switch is, so a state
             * added to this bucket asks for an arm of its own here */
            switch (item->state) {
                case WORKSPACE_STATE_ORPHANED:
                    /* The line's ladder: absence, then a squatter above — the
                     * two an orphan is let go for here (cleanup_verdict) */
                    if (item->occupant == FS_OCCUPANT_NONE) {
                        legend = "already gone from disk";
                    } else if (item->displaced != WORKSPACE_DISPLACED_NONE) {
                        legend = "not looked at, beneath a squatted directory";
                    }
                    break;

                case WORKSPACE_STATE_RELEASED:
                    /* A row names what let it go wherever the item can say —
                     * what its profile's history kept it for, or that dotta never
                     * deployed it (core/workspace.c workspace_item_line) — and
                     * the rest are the header's: a row standing on the record's
                     * entry under another spelling, and what no apply removes,
                     * in a directory — an active path beneath it, an orphan the
                     * load released, a node no record names — which the bare
                     * [released] cannot tell apart and a line could only explain
                     * by dotta's model. [type] names its own cause: the node
                     * the record describes, one dotta deployed or only saw,
                     * gone. */
                    if (item->divergence & DIVERGENCE_TYPE) {
                        legend = "another kind of path stands in its place";
                    }
                    break;

                case WORKSPACE_STATE_DEPLOYED:
                case WORKSPACE_STATE_UNDEPLOYED:
                case WORKSPACE_STATE_DELETED:
                case WORKSPACE_STATE_UNTRACKED:
                case WORKSPACE_STATE_UNSCANNED:
                case WORKSPACE_STATE_OVERRIDDEN:
                case WORKSPACE_STATE_OBSTRUCTING:
                    /* The partition's switch files no other state here */
                    CHECK_ARG(
                        false, "the released bucket holds ORPHANED and RELEASED alone"
                    );
            }
            output_list_legend(list, line.tags, legend);
        }

        output_list_render(list);
        output_list_free(list);
    }
}

/**
 * A profile of the remote section: its branch against the remote, or why it could
 * not be read
 */
typedef struct {
    const char *profile;          /* The set's own name, borrowed */
    remote_relation_t relation;   /* Its branch against the remote; unread where an error stands */
    error_t error;                /* The read's failure, borrowed; NULL where it read */
} status_remote_row_t;

/**
 * What the remote section prints: the remote, and a row a profile it reports on
 *
 * The transport's answer (status_remote), a value of the command arena: the name
 * the resolver gave, and a row for each profile of the set the transport chose
 * — the scope's, or under --all every local branch — read against the remote
 * while its session stood, or with no contact as last seen. The zero value is
 * no section.
 */
typedef struct {
    const char *name;                 /* The default remote; NULL where no section stands */
    bool last_seen;                   /* Read with no contact: each row against its tracking ref */
    const status_remote_row_t *rows;  /* A row a profile of the set, in its order */
    size_t row_count;
} status_remote_t;

/**
 * The remote half's transport: the remote resolved, the set chosen, the set fetched
 * and read against it — each step saying its own lines where it runs
 *
 * By default the set is the scope's profiles, for consistency with workspace
 * status; --all reports on every branch in the repository. Its failures are lines
 * of its own section, as its siblings' are: no remote configured is no section
 * — said in its place where --remote asked for it — a remote the resolver could
 * not choose or read, and a listing --all could not make, are a warning in its
 * place and no section, and an empty set is no section, unsaid. The contact,
 * unless --no-fetch, is the half's one write, each profile's remote-tracking
 * ref (sys/remote.h remote_fetch): a progress line at -v while it runs, on a
 * terminal; its failure a warning at -v. Then each profile is read against the
 * remote while the session stands (sys/remote.h remote_relation), the session
 * left after it; or, with no contact — --no-fetch, or one that failed — against
 * its tracking ref, the remote as last seen (remote_last_relation), which the
 * answer says: the section prints values.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options: --remote, --all and --no-fetch (must not be NULL)
 * @param scope The operation scope, whose profiles are the default set (must
 *              not be NULL)
 * @return The remote and the rows the section prints; the zero value where no
 *         section stands
 */
static status_remote_t status_remote(
    const dotta_ctx_t *ctx,
    const cmd_status_options_t *opts,
    const scope_t *scope
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(scope);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    /* Which remote: its name the command arena's, so it outlives this call in
     * the value it returns */
    const char *remote_name = NULL;
    error_t err = remote_default(repo, ctx->arena, &remote_name);
    if (error_code(err) == ERR_NOT_FOUND) {
        /* No remote configured (sys/remote.h names this read): no section to
         * print, and where --remote asked for one, the resolver's words in its
         * place, as remote's listing says them (cmds/remote.c) — the half's
         * summary, said here where the half ends — and the default scope has no
         * remote half to report */
        if (opts->want_remote) {
            output_summary(out, OUTPUT_NORMAL, "%s", error_line(err));
        }
        return (status_remote_t){ 0 };
    }
    if (err) {
        /* A remote the resolver could not choose, or one it could not read: the
         * section's question has no answer, and says so where it would stand, a
         * block as the section is */
        output_gap(out, OUTPUT_NORMAL);
        output_warning(
            out, OUTPUT_NORMAL, "Cannot tell remote sync status: %s", error_line(err)
        );
        return (status_remote_t){ 0 };
    }

    /* The set: the scope's profiles, or on explicit request every local branch
     * (lightweight, no ref resolution), listed in the command arena, where the
     * value keeps it */
    const string_array_t *profiles = scope_profiles(scope);

    if (opts->all_profiles) {
        string_array_t *all_local = arena_calloc(ctx->arena, 1, sizeof(*all_local));
        err = gitops_list_branches(repo, ctx->arena, all_local);
        if (err) {
            output_gap(out, OUTPUT_NORMAL);
            output_warning(
                out, OUTPUT_NORMAL, "Cannot list every profile for remote sync status: %s",
                error_line(err)
            );
            return (status_remote_t){ 0 };
        }
        profiles = all_local;
    }

    if (profiles->count == 0) return (status_remote_t){ 0 };

    /* A row a profile of the set, in its order. A row that will not read keeps
     * its failure, which the section says in its place. */
    status_remote_row_t *rows = arena_calloc(ctx->arena, profiles->count, sizeof(*rows));

    /* The contact, unless --no-fetch: the remote met once and the set fetched
     * from it (sys/remote.h), its listing what the rows read the remote's heads
     * off. While it runs, a progress line at -v: a terminal's alone, drawn over
     * by transfer's frames while objects move (sys/transfer.h transfer_op_end),
     * never a line of the report (base/output.h output_progress), and taken down
     * once the fetch is done, whichever way it went */
    if (!opts->no_fetch) {
        output_progress(out, OUTPUT_VERBOSE, "Fetching from '%s'...", remote_name);
        remote_t *remote = NULL;
        err = remote_open(repo, remote_name, "status", out, &remote);
        if (!err) err = remote_fetch(remote, profiles, NULL, NULL);
        output_clear_line(out);

        /* Each profile against the session's heads, then the session left, its
         * credential's verdict told (sys/remote.h remote_free) */
        if (!err) {
            for (size_t i = 0; i < profiles->count; i++) {
                status_remote_row_t *row = &rows[i];

                row->profile = profiles->entries[i];
                row->error = remote_relation(remote, row->profile, &row->relation);
            }
            remote_free(remote);

            return (status_remote_t){
                .name = remote_name, .rows = rows, .row_count = profiles->count
            };
        }

        /* Non-fatal: warn and continue with status display. Either's failure
         * names its act and the remote, or the tracking ref the fetch read, took
         * out of a name's way or wrote (sys/remote.h remote_fetch), a block of
         * its own. A session whose fetch failed brought no objects for its
         * listing's heads: the rows read the tracking refs. */
        output_gap(out, OUTPUT_VERBOSE);
        output_warning(out, OUTPUT_VERBOSE, "%s", error_line(err));
        remote_free(remote);
    }

    /* With no contact, each profile against its tracking ref: the remote as last
     * seen (sys/remote.h remote_last_relation), which the section's title says */
    for (size_t i = 0; i < profiles->count; i++) {
        status_remote_row_t *row = &rows[i];

        row->profile = profiles->entries[i];
        row->error = remote_last_relation(repo, remote_name, row->profile, &row->relation);
    }

    return (status_remote_t){
        .name = remote_name, .last_seen = true, .rows = rows, .row_count = profiles->count
    };
}

/**
 * Print the remote sync status: a row per profile of the set the transport chose,
 * each its reading against the remote — nothing where no section stands; the
 * summary counts them (status_print_summary)
 *
 * Reads what it prints and writes nothing: each row as the transport read it,
 * and at -v, beneath it, each head its relation names.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param remote The transport's answer (status_remote; must not be NULL)
 */
static void status_print_remote(const dotta_ctx_t *ctx, const status_remote_t *remote) {
    CHECK_NULL(ctx);
    CHECK_NULL(remote);

    if (!remote->name) return;

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    bool verbose = output_is_verbose(out);

    /* The remote sync status section, under the title list's remote listing takes
     * too (cmds/list.c list_profiles): marked as last seen where its rows were
     * read with no contact, as list's always are */
    if (remote->last_seen) {
        output_section(
            out, OUTPUT_NORMAL, "Remote sync status ({cyan}%s{reset}, as last seen)",
            remote->name
        );
    } else {
        output_section(
            out, OUTPUT_NORMAL, "Remote sync status ({cyan}%s{reset})", remote->name
        );
    }

    for (size_t i = 0; i < remote->row_count; i++) {
        const status_remote_row_t *row = &remote->rows[i];
        const remote_relation_t *relation = &row->relation;

        /* A profile whose reading could not be read is a row of the section like
         * any other, on the report's stream, its cause the error's own line and
         * the outcome glyph sync gives a failed analysis; the summary counts it
         * (status_print_summary), and the report goes on past it. At both levels
         * its one line: a failure read no head for -v to show beneath it. */
        if (row->error) {
            output_print(
                out, OUTPUT_NORMAL, "  {cyan}%s{reset} {red}(✗ %s){reset}\n",
                row->profile, error_line(row->error)
            );
            continue;
        }

        /* The reading's face comes from the relation's map — its glyph and its
         * phrase, read as list's and profile fetch's rows read it (sys/remote.h);
         * only the frame is status's. The frame is one line at every level, the
         * enabled profiles' format: the reading a space after the name, as a
         * list row's metadata follows its path (base/output.h
         * output_list_render) */
        char phrase[REMOTE_PHRASE_MAX];
        remote_state_phrase(relation, phrase, sizeof(phrase));
        output_print(
            out, OUTPUT_NORMAL, "  {cyan}%s{reset} {dim}(%s %s){reset}\n",
            row->profile, remote_state_symbol(relation->state), phrase
        );

        /* At -v, beneath the row, each head its reading holds: the branch here,
         * and the remote's — the open's listing, or with no contact its tracking
         * ref. Each commit is read and printed as a list row's last commit is
         * (sys/stats.h stats_commit_info, cmds/list.c list_profiles); one that
         * will not read, an object a hand removed, prints no line. */
        git_commit *commit = NULL;
        if (verbose && !git_oid_is_zero(&relation->local) &&
            git_commit_lookup(&commit, repo, &relation->local) == 0) {
            const commit_info_t head = stats_commit_info(ctx->arena, commit);
            git_commit_free(commit);

            char oid_str[8];
            git_oid_tostr(oid_str, sizeof(oid_str), &head.oid);

            char time_str[64];
            timeutil_relative(head.time, time_str, sizeof(time_str));

            output_print(
                out, OUTPUT_VERBOSE, "    local:  {yellow}%s{reset} %s {dim}(%s){reset}\n",
                oid_str, head.summary, time_str
            );
        }
        if (verbose && !git_oid_is_zero(&relation->remote) &&
            git_commit_lookup(&commit, repo, &relation->remote) == 0) {
            const commit_info_t head = stats_commit_info(ctx->arena, commit);
            git_commit_free(commit);

            char oid_str[8];
            git_oid_tostr(oid_str, sizeof(oid_str), &head.oid);

            char time_str[64];
            timeutil_relative(head.time, time_str, sizeof(time_str));

            output_print(
                out, OUTPUT_VERBOSE, "    remote: {yellow}%s{reset} %s {dim}(%s){reset}\n",
                oid_str, head.summary, time_str
            );
        }
    }
}

/**
 * Print the run's summary: the workspace's verdict, with what the filter hid,
 * then where the set stands against the remote — a line each half, one block,
 * beneath everything the report listed, and nothing of a half that did not run
 *
 * The workspace's line is said on every run of its half, one with nothing diverged
 * included: it is the run's answer, and where nothing diverged it says what it
 * compared — the paths aligned — as an empty apply or diff says its own. It is
 * one fold of the items that ask the disk or the user something, over the scope,
 * decided and worded the same whatever the filter: under -p it speaks for the
 * filtered profiles alone, so it never counts another's divergence, and what
 * the filter hides is its last clause. The remote's line counts the rows the
 * transport read, each under its reading's first clause; where no remote is
 * configured the transport said the resolver's line in its place (status_remote).
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param ws Workspace (NULL where the local half did not run: no line of it)
 * @param scope Operation scope (must not be NULL; its filter dimension drives
 *              the count)
 * @param partition The diverged items, filed (must not be NULL; read where the
 *                  workspace is)
 * @param remote The transport's answer (must not be NULL; its zero value no line)
 */
static void status_print_summary(
    const dotta_ctx_t *ctx,
    const workspace_t *ws,
    const scope_t *scope,
    const status_partition_t *partition,
    const status_remote_t *remote
) {
    CHECK_NULL(ctx);
    CHECK_NULL(scope);
    CHECK_NULL(partition);
    CHECK_NULL(remote);

    output_t *out = ctx->out;

    if (ws) {
        /* The workspace's line, one fold whatever the filter: the items of the
         * sections that ask the disk or the user something, and those of them
         * dotta could not verify. Three sections are listed and leave the line
         * as they find it: an overridden copy, whose work is the landing of the
         * row standing over it, which the line counts where it shows that row
         * (stated: a filter that hides the row reads aligned over the copy);
         * and what apply settles in the record alone, nothing on disk changing
         * — a pure reassignment, a release, a reclaim. A scope's paths are aligned
         * iff the line counts none. What the analysis could not establish is
         * named beside the count: an item carrying a fault (an unreadable path,
         * a comparison that could not run, a history that would not read) is
         * one no verb resolves by default — apply skips it and the user must
         * look. Every other item counted is work that touches the disk or waits
         * on the user. With no filter every item is in scope and none is hidden. */
        const workspace_items_t *counted[] = {
            &partition->conflicts,  &partition->unconfirmed,  &partition->squatted,
            &partition->displaced,  &partition->unverifiable, &partition->uncommitted,
            &partition->undeployed, &partition->new_files,    &partition->orphaned,
        };
        size_t shown = 0;
        size_t unverified = 0;
        for (size_t b = 0; b < sizeof(counted) / sizeof(counted[0]); b++) {
            shown += counted[b]->count;
            for (size_t i = 0; i < counted[b]->count; i++) {
                if (counted[b]->entries[i]->fault != WORKSPACE_FAULT_NONE) {
                    unverified++;
                }
            }
        }

        /* The line: the fold's decision, in the same words filtered or not, a
         * clause a fact, joined and said once under the half's name, as the
         * remote's line says its counts */
        string_array_t clauses;
        string_array_init(&clauses, ctx->arena, 0);

        if (shown == 0) {
            /* Active paths the filter reaches, both kinds — what stands aligned
             * at a path is not a question about which kind stands there. With
             * no filter every item is accepted, so this is the whole view. Counted
             * here, the one arm that prints it. */
            workspace_items_t active = workspace_active(ws);
            size_t scoped_paths = 0;
            for (size_t i = 0; i < active.count; i++) {
                if (scope_accepts_profile(scope, active.entries[i]->profile)) {
                    scoped_paths++;
                }
            }

            /* Where the scope reaches no path, the sentence names its subject:
             * the filter's profiles, or the view, which holds none — whether or
             * not the record still lists what apply lets go */
            if (scoped_paths > 0) {
                string_array_pushf(
                    &clauses, "%zu path%s aligned",
                    scoped_paths, scoped_paths == 1 ? "" : "s"
                );
            } else if (scope_filters_profiles(scope)) {
                string_array_push(&clauses, "no paths in profile");
            } else {
                string_array_push(&clauses, "no active paths");
            }
        } else {
            string_array_pushf(&clauses, "%zu item%s diverged", shown, shown == 1 ? "" : "s");

            /* What the run found, and how much of it dotta could not verify */
            if (unverified > 0) {
                string_array_pushf(&clauses, "%zu dotta could not verify", unverified);
            }
        }

        /* The diverged items the filter hides, the line's last clause: what it
         * speaks for, then what it leaves out */
        if (partition->hidden > 0) {
            string_array_pushf(
                &clauses, "%zu item%s hidden by the profile filter",
                partition->hidden, partition->hidden == 1 ? "" : "s"
            );
        }

        const char *phrase = string_array_join(ctx->arena, &clauses, ", ");
        output_summary(out, OUTPUT_NORMAL, "Workspace: %s", phrase);
    }

    if (remote->name) {
        /* Each row counted under its reading's first clause (sys/remote.h
         * remote_state_phrase), a row that would not read under its failure */
        size_t up_to_date = 0; size_t ahead = 0; size_t behind = 0;
        size_t diverged = 0; size_t recreated = 0; size_t no_remote = 0;
        size_t deleted = 0; size_t no_local = 0; size_t failed = 0;

        for (size_t i = 0; i < remote->row_count; i++) {
            const status_remote_row_t *row = &remote->rows[i];

            if (row->error) {
                failed++;
                continue;
            }

            switch (row->relation.state) {
                case REMOTE_STATE_UP_TO_DATE:         up_to_date++; break;
                case REMOTE_STATE_AHEAD:              ahead++; break;
                case REMOTE_STATE_BEHIND:             behind++; break;
                case REMOTE_STATE_DIVERGED:           diverged++; break;
                case REMOTE_STATE_RECREATED:
                case REMOTE_STATE_RECREATED_AHEAD:    recreated++; break;
                case REMOTE_STATE_NO_REMOTE:          no_remote++; break;
                case REMOTE_STATE_DELETED:
                case REMOTE_STATE_DELETED_AHEAD:      deleted++; break;
                case REMOTE_STATE_NO_LOCAL:
                case REMOTE_STATE_NO_LOCAL_AHEAD:
                case REMOTE_STATE_NO_LOCAL_DELETED:
                case REMOTE_STATE_NO_LOCAL_NO_REMOTE: no_local++; break;
            }
        }

        /* One line, its non-zero counts in the readings' order, as sync's Manifest
         * rows say theirs (cmds/sync.c sync_print_manifest) — composed first,
         * since a summary's line is said whole and a count joined into a phrase
         * is a datum, uncoloured (base/output.h "Layout and data") */
        const struct {
            size_t count;
            const char *word;
        } parts[] = {
            { up_to_date, "up-to-date"              },
            { ahead,      "ahead"                   },
            { behind,     "behind"                  },
            { diverged,   "diverged"                },
            { recreated,  "recreated on the remote" },
            { no_remote,  "no remote branch"        },
            { deleted,    "deleted on the remote"   },
            { no_local,   "no local branch"         },
            { failed,     "failed"                  },
        };

        string_array_t clauses;
        string_array_init(&clauses, ctx->arena, 0);
        for (size_t k = 0; k < sizeof(parts) / sizeof(parts[0]); k++) {
            if (parts[k].count == 0) continue;

            string_array_pushf(&clauses, "%zu %s", parts[k].count, parts[k].word);
        }
        const char *phrase = string_array_join(ctx->arena, &clauses, ", ");

        /* The remote by its name alone: whether its rows were read with no contact
         * is their section's title's to say (status_print_remote) */
        output_summary(
            out, OUTPUT_NORMAL, "Remote '{cyan}%s{reset}': %s", remote->name, phrase
        );
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
        if (err) return err;
    }

    /* The enabled profiles and the last deployment of each */
    status_print_profiles(out, state, scope, ws, manifest);

    /* The whole view, on request — before the sections that name only what diverged
     * from it */
    if (opts->show_local && opts->full) {
        status_print_manifest(out, ws, scope);
    }

    /* The workspace's half (with profile filtering for Coherent Scope)
     *
     * The workspace was loaded over the persistent enabled set (the view's) for
     * accurate divergence analysis. status_partition then applies the CLI filter
     * dimension via scope_accepts_profile so `dotta status -p work` matches `dotta
     * apply -p work` behavior, and the sections and the summary read what it filed.
     */
    status_partition_t partition = { 0 };
    if (opts->show_local) {
        status_partition(ws, scope, ctx->arena, &partition);
        status_print_workspace(out, &partition, manifest, config);
    }

    /* The remote half (if requested): its transport, then its section — no remote
     * configured is no section, said where --remote asked for one, and every
     * failure of its own is a line of it */
    status_remote_t remote = { 0 };
    if (opts->show_remote) {
        remote = status_remote(ctx, opts, scope);
        status_print_remote(ctx, &remote);
    }

    /* The summary, last: what each half found, a line each, in one block */
    status_print_summary(ctx, ws, scope, &partition, &remote);

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
        "Show the remote as last seen, without contacting it"
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
        "  permissions refuse the read is reported as [unreadable]; sudo may\n"
        "  lift it.\n",
    .examples     =
        "  %s status                         # Local + remote\n"
        "  %s status --local                 # Filesystem only\n"
        "  %s status --remote                # Remote only\n"
        "  %s status --no-fetch              # Local + remote as last seen\n"
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
