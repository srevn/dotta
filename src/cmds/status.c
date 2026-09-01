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

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/timeutil.h"
#include "cmds/completion.h"
#include "core/cleanup.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "sys/gitops.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/privilege.h"

/**
 * Display enabled profiles and last deployment info
 *
 * @param out Output context (must not be NULL)
 * @param profiles Enabled profile names (must not be NULL)
 * @param ws Workspace the view and the record come from: the per-profile
 *           last-deployed timestamp and the verbose per-profile counts are folded
 *           from its rows (NULL when no workspace was loaded — the slices are
 *           empty then, and the header is names alone)
 * @param unbound The view's health slice: the claims the build could not place,
 *                annotated onto their profile's line (a count, the paths under
 *                -v) with one hint naming the repairs after the section
 */
static void display_enabled_profiles(
    output_t *out,
    const string_array_t *profiles,
    const workspace_t *ws,
    manifest_unbound_t unbound
) {
    if (!out || !profiles) return;

    /* Show enabled profiles */
    output_section(out, OUTPUT_NORMAL, "Enabled profiles");

    /* What a profile contributes to this machine is its rows of both kinds; the
     * slices are only how the view is reached, and each row's own type is what
     * says which kind it is. */
    const manifest_rows_t slices[] = {
        workspace_files(ws), workspace_directories(ws)
    };

    /* The first profile with unbound claims names the hint's example. */
    const char *unbound_profile = NULL;

    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->items[i];

        /* Format profile name */
        output_styled(out, OUTPUT_NORMAL, "  {cyan}%s{reset}", profile);

        /* One walk of the view per profile: the latest ownership event among
         * the rows the profile owns now — the honest set for an enabled-profiles
         * header — and the verbose per-kind counts. */
        time_t profile_deploy_time = 0;
        size_t file_count = 0;
        size_t dir_count = 0;
        for (size_t s = 0; s < sizeof(slices) / sizeof(slices[0]); s++) {
            for (size_t j = 0; j < slices[s].count; j++) {
                const manifest_row_t *row = slices[s].entries[j];
                if (strcmp(row->profile, profile) != 0) continue;

                if (row->type == PATH_TYPE_DIRECTORY) dir_count++;
                else file_count++;

                const anchor_t *anchor =
                    workspace_get_anchor(ws, row->filesystem_path);
                if (anchor && anchor->deployed_at > profile_deploy_time) {
                    profile_deploy_time = anchor->deployed_at;
                }
            }
        }

        /* Unbound claims are not rows — the counts above never see them; the
         * annotation is what says the profile carries more than it projects. */
        size_t unplaced = 0;
        for (size_t j = 0; j < unbound.count; j++) {
            if (strcmp(unbound.entries[j].profile, profile) == 0) unplaced++;
        }
        if (unplaced > 0 && !unbound_profile) unbound_profile = profile;

        /* Show per-profile last deployed timestamp */
        if (profile_deploy_time > 0) {
            char relative_buf[64];
            format_relative_time(
                profile_deploy_time, relative_buf, sizeof(relative_buf)
            );

            /* Display dimmed timestamp */
            output_styled(
                out, OUTPUT_NORMAL, "  {dim}(deployed %s){reset}",
                relative_buf
            );
        }

        if (unplaced > 0) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {yellow}(%zu custom/ path%s need%s a deployment target){reset}",
                unplaced, unplaced == 1 ? "" : "s", unplaced == 1 ? "s" : ""
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
        }

        output_newline(out, OUTPUT_NORMAL);
    }

    if (unbound_profile) {
        output_hint(
            out, OUTPUT_NORMAL,
            "Run 'dotta profile enable %s --target /path' to set the target, "
            "or 'dotta remove %s <path>' to untrack",
            unbound_profile, unbound_profile
        );
    }
}

/**
 * Display the manifest — every active row, with its state
 *
 * The window onto the view (--full): one line per managed path, both kinds merged
 * in path order, tagged as the diverged item at the path says or [clean] when
 * there is none, with the owning profile ("from P", or "P → Q" for a pending
 * reassignment). The one listing that shows the whole view rather than what
 * diverged from it; printed whatever the workspace's cleanliness. Orphans are
 * records, not rows — they stay in the Issues section. Scoped by the CLI filter
 * like every other section.
 *
 * @param ws Workspace (must not be NULL, borrowed from caller)
 * @param scope Operation scope (must not be NULL; its filter dimension drives
 *              display)
 * @param out Output context (must not be NULL)
 */
static void display_manifest(
    const workspace_t *ws,
    const scope_t *scope,
    output_t *out
) {
    if (!ws || !out) return;

    output_list_t *list = output_list_create(
        out, "Manifest", "every managed path; [clean] where nothing diverged"
    );
    if (!list) return;

    /* Both slices are in filesystem_path order and share no path (one row per
     * path, one kind), so a two-finger merge walks the view as one path-ordered
     * sequence. */
    manifest_rows_t files = workspace_files(ws);
    manifest_rows_t dirs = workspace_directories(ws);
    size_t f = 0;
    size_t d = 0;
    while (f < files.count || d < dirs.count) {
        const manifest_row_t *row;
        if (d == dirs.count) {
            row = files.entries[f++];
        } else if (f == files.count) {
            row = dirs.entries[d++];
        } else {
            const char *file_path = files.entries[f]->filesystem_path;
            const char *dir_path = dirs.entries[d]->filesystem_path;
            row = strcmp(file_path, dir_path) < 0 ? files.entries[f++]
                                                  : dirs.entries[d++];
        }

        if (!scope_accepts_profile(scope, row->profile)) continue;

        const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
        size_t tag_count;
        output_color_t color;
        char metadata[256];

        /* Only diverged paths have an item; a row without one is clean */
        const workspace_item_t *item = workspace_get_item(ws, row->filesystem_path);
        if (item) {
            if (!workspace_item_extract_display_info(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                continue;
            }
        } else {
            tags[0] = "clean";
            tag_count = 1;
            color = OUTPUT_COLOR_GREEN;
            snprintf(metadata, sizeof(metadata), "from %s", row->profile);
        }

        /* The window is onto rows, so the row's type is what says the kind —
         * the item at a path, when there is one, was analyzed from that row and
         * carries the same */
        char path[PATH_MAX + 2];
        snprintf(
            path, sizeof(path), "%s%s", row->filesystem_path,
            path_kind_suffix(path_type_kind(row->type))
        );

        output_list_add(list, tags, tag_count, color, path, metadata);
    }

    output_list_render(list);
    output_list_free(list);
}

/**
 * Display workspace status
 *
 * Shows the consistency between the view, the record and the filesystem. Organized
 * into actionable sections (git-like structure).
 *
 * When a profile filter is active, the status line is scoped to the filtered
 * profile(s), showing path counts and per-profile divergence instead of global
 * workspace status. This prevents misleading "Dirty" messages when the filtered
 * profile is clean but other enabled profiles have divergence.
 *
 * @param ws Workspace (must not be NULL, borrowed from caller)
 * @param scope Operation scope (must not be NULL; its filter dimension drives
 *              display)
 * @param out Output context (must not be NULL)
 */
static void display_workspace_status(
    workspace_t *ws,
    const scope_t *scope,
    output_t *out
) {
    if (!ws || !out) return;

    /* Get workspace status from provided workspace */
    workspace_status_t ws_status = workspace_get_status(ws);

    /* Get all diverged items (shared between pre-scan and categorization) */
    workspace_items_t all_items = workspace_get_all_diverged(ws);

    /* Managed paths the filter reaches, both kinds — what stands aligned at a
     * path is not a question about which kind stands there. With no filter every
     * row is accepted, so this is the whole view and the same count serves the
     * global line. */
    const manifest_rows_t slices[] = {
        workspace_files(ws), workspace_directories(ws)
    };
    size_t scoped_paths = 0;
    for (size_t s = 0; s < sizeof(slices) / sizeof(slices[0]); s++) {
        for (size_t i = 0; i < slices[s].count; i++) {
            if (scope_accepts_profile(scope, slices[s].entries[i]->profile)) {
                scoped_paths++;
            }
        }
    }

    /* Pre-scan: partition the diverged items by the filter. Needed before the
     * status line to determine filtered workspace state. */
    size_t filtered_diverged = 0;
    size_t filtered_unverified = 0;
    size_t hidden_count = 0;

    if (scope_has_filter(scope)) {
        /* Partition diverged items into filtered vs hidden. The unverified count
         * gives the filtered line its Invalid arm — the same bit the global verdict
         * reads (compute_workspace_status), so one workspace cannot read Invalid
         * globally and merely Dirty under -p while the unverifiable item is in
         * the filtered set. */
        for (size_t i = 0; i < all_items.count; i++) {
            if (scope_accepts_profile(scope, all_items.entries[i]->profile)) {
                filtered_diverged++;
                if (all_items.entries[i]->divergence & DIVERGENCE_UNVERIFIED) {
                    filtered_unverified++;
                }
            } else {
                hidden_count++;
            }
        }
    }

    /* Section visibility:
     * - Divergence present (filtered or global): always show
     * - Clean with hidden divergence from other profiles: always show
     * - Clean with no divergence anywhere: show only with verbose
     */
    bool has_divergence = scope_has_filter(scope) ? (filtered_diverged > 0)
                                                  : (ws_status != WORKSPACE_CLEAN);

    if (!has_divergence && hidden_count == 0 && !output_is_verbose(out)) {
        return;
    }

    output_section(out, OUTPUT_NORMAL, "Workspace status");

    /* Display status line */
    if (scope_has_filter(scope)) {
        /* Profile-scoped status: reflects the filtered profile */
        if (filtered_diverged == 0) {
            if (scoped_paths > 0) {
                output_colored(
                    out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN,
                    "  Clean - %zu path%s aligned\n",
                    scoped_paths, scoped_paths == 1 ? "" : "s"
                );
            } else {
                output_colored(
                    out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN,
                    "  Clean - no paths in profile\n"
                );
            }
        } else if (filtered_unverified > 0) {
            output_colored(
                out, OUTPUT_NORMAL, OUTPUT_COLOR_RED,
                "  Invalid - %zu item%s dotta could not verify\n",
                filtered_unverified, filtered_unverified == 1 ? "" : "s"
            );
        } else {
            output_colored(
                out, OUTPUT_NORMAL, OUTPUT_COLOR_YELLOW,
                "  Dirty - %zu item%s diverged\n",
                filtered_diverged, filtered_diverged == 1 ? "" : "s"
            );
        }
    } else {
        /* Global status */
        switch (ws_status) {
            case WORKSPACE_CLEAN:
                if (scoped_paths > 0) {
                    output_colored(
                        out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN,
                        "  Clean - %zu path%s aligned\n",
                        scoped_paths, scoped_paths == 1 ? "" : "s"
                    );
                } else {
                    output_colored(
                        out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN,
                        "  Clean - all states aligned\n"
                    );
                }
                break;

            case WORKSPACE_DIRTY:
                output_colored(
                    out, OUTPUT_NORMAL, OUTPUT_COLOR_YELLOW,
                    "  Dirty - workspace has divergence\n"
                );
                break;

            case WORKSPACE_INVALID:
                output_colored(
                    out, OUTPUT_NORMAL, OUTPUT_COLOR_RED,
                    "  Invalid - workspace has paths dotta could not verify\n"
                );
                break;
        }
    }

    /* Show sectioned output for dirty/invalid workspace */
    if (ws_status != WORKSPACE_CLEAN) {
        /* When filter active and filtered profile is clean, skip detailed sections */
        if ((!scope_has_filter(scope) || filtered_diverged > 0) && all_items.count > 0) {

            /* Single allocation for all category pointers (7 categories ×
             * all_items.count slots) Memory layout:
             * [conflicts][unverifiable][uncommitted][undeployed][new_files]
             * [orphaned][reassigned] This provides cache-friendly contiguous
             * memory with single malloc/free. */
            const workspace_item_t **categorized =
                malloc(all_items.count * 7 * sizeof(workspace_item_t *));
            if (!categorized) {
                output_error(
                    out, "Failed to allocate memory for status display (%zu items)",
                    all_items.count
                );
                return;
            }

            /* Category arrays (pointer arithmetic into single allocation) */
            const workspace_item_t **conflicts = categorized;
            const workspace_item_t **unverifiable = categorized + all_items.count;
            const workspace_item_t **uncommitted = categorized + all_items.count * 2;
            const workspace_item_t **undeployed = categorized + all_items.count * 3;
            const workspace_item_t **new_files = categorized + all_items.count * 4;
            const workspace_item_t **orphaned = categorized + all_items.count * 5;
            const workspace_item_t **reassigned = categorized + all_items.count * 6;

            size_t conflict_count = 0;
            size_t unverifiable_count = 0;
            size_t uncommitted_count = 0;
            size_t undeployed_count = 0;
            size_t new_count = 0;
            size_t orphaned_count = 0;
            size_t reassigned_count = 0;
            for (size_t i = 0; i < all_items.count; i++) {
                const workspace_item_t *item = all_items.entries[i];

                /* Apply profile filter if specified (Coherent Scope)
                 *
                 * When profile filter is active, only show items from matching
                 * profiles. This ensures status output matches what apply would do.
                 */
                if (!scope_accepts_profile(scope, item->profile)) {
                    continue;  /* Skip items from other profiles */
                }

                switch (item->state) {
                    case WORKSPACE_STATE_DEPLOYED:
                        /* One bucket per route — the same table update's filter
                         * and skip counter read (workspace_item_route), so no
                         * section promises a verb the verb refuses */
                        switch (workspace_item_route(item)) {
                            case WORKSPACE_ROUTE_CONFLICT:
                            case WORKSPACE_ROUTE_KIND:
                                /* Neither verb's by default — its own header
                                 * names the way out */
                                conflicts[conflict_count++] = item;
                                break;

                            case WORKSPACE_ROUTE_UNVERIFIABLE:
                                unverifiable[unverifiable_count++] = item;
                                break;

                            case WORKSPACE_ROUTE_STALE:
                                /* Apply's work, the same bucket as a file never
                                 * deployed; the [stale] tag says which */
                                undeployed[undeployed_count++] = item;
                                break;

                            case WORKSPACE_ROUTE_CAPTURE:
                                /* Real divergence → uncommitted changes */
                                uncommitted[uncommitted_count++] = item;
                                break;

                            case WORKSPACE_ROUTE_REASSIGNED:
                                /* Pure profile reassignment (no filesystem
                                 * divergence) */
                                reassigned[reassigned_count++] = item;
                                break;

                            case WORKSPACE_ROUTE_CLEAN:
                                break;
                        }
                        break;

                    case WORKSPACE_STATE_DELETED:
                        /* Deleted files → uncommitted changes */
                        uncommitted[uncommitted_count++] = item;
                        break;

                    case WORKSPACE_STATE_UNDEPLOYED:
                        undeployed[undeployed_count++] = item;
                        break;

                    case WORKSPACE_STATE_UNTRACKED:
                        new_files[new_count++] = item;
                        break;

                    case WORKSPACE_STATE_ORPHANED:
                    case WORKSPACE_STATE_RELEASED:
                        orphaned[orphaned_count++] = item;
                        break;
                }
            }

            /* Section 1: Conflicts — the buckets no default verb resolves lead;
             * this one's header carries the remedy, true of both its members
             * (content moved on both sides, or a kind the copy cannot commit) */
            if (conflict_count > 0) {
                output_list_t *list = output_list_create(
                    out, "Conflicts",
                    "changed on both sides or a different kind on disk; "
                    "\"dotta diff\" to compare, \"dotta apply --force\" to "
                    "keep Git's, \"dotta add --force\" to keep disk's, "
                    "\"dotta remove\" to untrack"
                );

                if (list) {
                    for (size_t i = 0; i < conflict_count; i++) {
                        const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                        size_t tag_count;
                        output_color_t color;
                        char metadata[256];
                        char path[PATH_MAX + 2];

                        if (workspace_item_extract_display_info(
                            conflicts[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            snprintf(
                                path, sizeof(path), "%s%s", conflicts[i]->filesystem_path,
                                path_kind_suffix(conflicts[i]->item_kind)
                            );
                            output_list_add(
                                list, tags, tag_count, color, path, metadata
                            );
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);
                }
            }

            /* Section 2: Unverifiable paths — the other no-verb bucket: dotta
             * could not look, so no verb is promised; the way out is the user's,
             * in the words update's counted line already uses */
            if (unverifiable_count > 0) {
                output_list_t *list = output_list_create(
                    out, "Unverifiable paths",
                    "dotta cannot read these paths; fix permissions, or "
                    "exclude with -e"
                );

                if (list) {
                    for (size_t i = 0; i < unverifiable_count; i++) {
                        const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                        size_t tag_count;
                        output_color_t color;
                        char metadata[256];
                        char path[PATH_MAX + 2];

                        if (workspace_item_extract_display_info(
                            unverifiable[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            snprintf(
                                path, sizeof(path), "%s%s", unverifiable[i]->filesystem_path,
                                path_kind_suffix(unverifiable[i]->item_kind)
                            );
                            output_list_add(
                                list, tags, tag_count, color, path, metadata
                            );
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);
                }
            }

            /* Section 3: Uncommitted Changes */
            if (uncommitted_count > 0) {
                output_list_t *list = output_list_create(
                    out, "Uncommitted changes",
                    "use \"dotta update\" to commit these changes"
                );

                if (list) {
                    for (size_t i = 0; i < uncommitted_count; i++) {
                        const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                        size_t tag_count;
                        output_color_t color;
                        char metadata[256];
                        char path[PATH_MAX + 2];

                        if (workspace_item_extract_display_info(
                            uncommitted[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            snprintf(
                                path, sizeof(path), "%s%s", uncommitted[i]->filesystem_path,
                                path_kind_suffix(uncommitted[i]->item_kind)
                            );
                            output_list_add(
                                list, tags, tag_count, color, path, metadata
                            );
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);
                }
            }

            /* Section 4: Profile Reassignments */
            if (reassigned_count > 0) {
                output_list_t *list = output_list_create(
                    out, "Profile reassignments",
                    "run \"dotta apply\" to acknowledge"
                );

                if (list) {
                    for (size_t i = 0; i < reassigned_count; i++) {
                        const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                        size_t tag_count;
                        output_color_t color;
                        char metadata[256];
                        char path[PATH_MAX + 2];

                        if (workspace_item_extract_display_info(
                            reassigned[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            snprintf(
                                path, sizeof(path), "%s%s", reassigned[i]->filesystem_path,
                                path_kind_suffix(reassigned[i]->item_kind)
                            );
                            output_list_add(
                                list, tags, tag_count, color, path, metadata
                            );
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);
                }
            }

            /* Section 5: Undeployed Files */
            if (undeployed_count > 0) {
                output_list_t *list = output_list_create(
                    out, "Undeployed files",
                    "use \"dotta apply\" to deploy these files"
                );

                if (list) {
                    for (size_t i = 0; i < undeployed_count; i++) {
                        const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                        size_t tag_count;
                        output_color_t color;
                        char metadata[256];
                        char path[PATH_MAX + 2];

                        if (workspace_item_extract_display_info(
                            undeployed[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            snprintf(
                                path, sizeof(path), "%s%s", undeployed[i]->filesystem_path,
                                path_kind_suffix(undeployed[i]->item_kind)
                            );
                            output_list_add(
                                list, tags, tag_count, color, path, metadata
                            );
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);
                }
            }

            /* Section 6: New Files */
            if (new_count > 0) {
                output_list_t *list = output_list_create(
                    out, "New files",
                    "use \"dotta update --include-new\" to track these files"
                );

                if (list) {
                    for (size_t i = 0; i < new_count; i++) {
                        const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                        size_t tag_count;
                        output_color_t color;
                        char metadata[256];
                        char path[PATH_MAX + 2];

                        if (workspace_item_extract_display_info(
                            new_files[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            snprintf(
                                path, sizeof(path), "%s%s", new_files[i]->filesystem_path,
                                path_kind_suffix(new_files[i]->item_kind)
                            );
                            output_list_add(
                                list, tags, tag_count, color, path, metadata
                            );
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);
                }
            }

            /* Section 7: Issues (orphaned) */
            if (orphaned_count > 0) {
                output_list_t *list = output_list_create(
                    out, "Issues",
                    "run \"dotta apply\" to prune orphaned paths"
                );

                if (list) {
                    /* The header promises a prune; a clean orphaned file gets
                     * one and needs no more words. Every other hint is keyed
                     * below by the exact tags its line shows, once per distinct
                     * tag string, so the key reads back against the list it
                     * follows. The verdict is cleanup's (cleanup_verdict, the
                     * one producer the preview reads too) — this only names it.
                     * A directory's PRUNABLE is the one verdict status cannot
                     * finish, and its hint says so; it shares the bare [orphaned]
                     * key with the files, so the sentence is written to be true
                     * of both. */
                    struct { char tags[64]; const char *hint; } legend[16];
                    size_t legend_count = 0;
                    size_t legend_width = 0;

                    /* One sentence for every [relocated] key, wherever the verdict
                     * put the item — a pruned custom/ re-target and a held home
                     * move share the tag string across kinds and fates, so the
                     * sentence is written to be true of all of them, the way
                     * the bare [orphaned] key's is. */
                    static const char relocated_hint[] =
                        "the claim deploys elsewhere now (target or home moved); "
                        "apply prunes the old copy — a moved home holds it "
                        "behind --force";

                    for (size_t i = 0; i < orphaned_count; i++) {
                        const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                        size_t tag_count;
                        output_color_t color;
                        char metadata[256];
                        char path[PATH_MAX + 2];

                        if (!workspace_item_extract_display_info(
                            orphaned[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            continue;
                        }
                        snprintf(
                            path, sizeof(path), "%s%s", orphaned[i]->filesystem_path,
                            path_kind_suffix(orphaned[i]->item_kind)
                        );
                        output_list_add(
                            list, tags, tag_count, color, path, metadata
                        );

                        const char *hint = NULL;
                        bool is_dir = (orphaned[i]->item_kind == PATH_KIND_DIRECTORY);

                        switch (cleanup_verdict(ws, orphaned[i], false)) {
                            case CLEANUP_ABSENT:
                                hint = "already gone from disk; apply reclaims its entry";
                                break;

                            case CLEANUP_RELEASED:
                                /* The displaced-ancestor read comes first: such
                                 * an item's own bits were computed through the
                                 * squatter, so neither sibling sentence is true
                                 * of it — the same precedence the verdict's own
                                 * arms take. */
                                hint = workspace_displaced_ancestor(
                                    ws, orphaned[i]->filesystem_path
                                )
                                    ? "observed through a displaced tracked "
                                    "directory; apply releases its entry, the "
                                    "path stays"
                                    : (orphaned[i]->divergence & DIVERGENCE_TYPE)
                                    ? "what dotta put there is gone, another kind of "
                                    "path stands in its place; apply releases its "
                                    "entry, the path stays"
                                    : "no longer in Git, or dotta never deployed it; "
                                    "apply releases its entry, the path stays";
                                break;

                            case CLEANUP_SKIPPED:
                                if (is_dir) {
                                    /* The two ways a directory reaches SKIPPED
                                     * here (force=false): the workspace could
                                     * not verify it — which outranks the hold,
                                     * as it does in the file table — or the
                                     * relocation hold. */
                                    hint = (orphaned[i]->divergence & DIVERGENCE_UNVERIFIED)
                                        ? "cannot be verified; apply skips it"
                                        : relocated_hint;
                                    break;
                                }
                                switch (cleanup_skip_reason(orphaned[i])) {
                                    case CLEANUP_SKIP_UNVERIFIED:
                                        hint = "cannot be verified; "
                                            "apply skips it, --force prunes it";
                                        break;
                                    case CLEANUP_SKIP_RELOCATED:
                                        hint = relocated_hint;
                                        break;
                                    case CLEANUP_SKIP_MODIFIED:
                                    case CLEANUP_SKIP_TYPE_CHANGED:
                                        hint = "changed since deployment; "
                                            "apply skips it, --force prunes it";
                                        break;
                                    case CLEANUP_SKIP_MODE_CHANGED:
                                        hint = "permissions changed; "
                                            "apply skips it, --force prunes it";
                                        break;
                                    case CLEANUP_SKIP_NONE:
                                        break;
                                }
                                break;

                            case CLEANUP_PRUNABLE:
                                if (orphaned[i]->row) {
                                    hint = relocated_hint;
                                } else if (is_dir) {
                                    hint = "apply prunes it; a directory still holding "
                                        "something not dotta's to remove is released "
                                        "instead";
                                }
                                break;
                        }
                        if (!hint) continue;

                        /* Same bracketing and spacing the list gives the item
                         * line, so the column below matches the one above */
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
                        output_newline(out, OUTPUT_NORMAL);
                        for (size_t i = 0; i < legend_count; i++) {
                            output_hintline(
                                out, OUTPUT_NORMAL, "  %-*s - %s",
                                (int) legend_width, legend[i].tags, legend[i].hint
                            );
                        }
                    }
                }
            }

            /* Cleanup (single free for all category arrays) */
            free(categorized);
        }

        /* Show hidden items note when profile filter is active */
        if (scope_has_filter(scope) && hidden_count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "  {dim}(%zu item%s hidden){reset}\n",
                hidden_count, hidden_count == 1 ? "" : "s"
            );
        }
    }
}

/**
 * Display remote sync status for profiles
 *
 * By default shows only enabled profiles for consistency with workspace status.
 * Use show_all_profiles to report on every branch in the repository.
 */
static error_t *display_remote_status(
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
    error_t *err = gitops_resolve_default_remote(
        repo, ctx->arena, &remote_name, no_fetch ? NULL : &remote_url
    );
    if (err) {
        /* No remote configured - not an error, just skip this section */
        error_free(err);
        return NULL;
    }

    /* Build profile array to check */
    string_array_t *all_local = NULL;
    const string_array_t *check = profiles;

    if (show_all_profiles) {
        /* Explicit request: show ALL local profiles (lightweight, no ref resolution) */
        err = profile_list_all_local(repo, &all_local);
        if (err) {
            return error_wrap(err, "Failed to list all profiles");
        }
        check = all_local;
    }

    if (check->count == 0) {
        string_array_free(all_local);
        return NULL;
    }

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
        transfer_context_t *xfer = NULL;
        error_t *xfer_err = transfer_context_create(&xfer_opts, &xfer);

        if (xfer_err) {
            /* Non-fatal: skip the fetch and fall through to cached status display.
             * Matches the "skip section on failure" pattern used earlier for
             * remote detection. */
            output_warning(
                out, OUTPUT_NORMAL, "Skipping remote fetch: %s",
                error_message(xfer_err)
            );
            error_free(xfer_err);
        } else {
            if (verbose) {
                /* Ephemeral fetch message (no newline — resolved after fetch).
                 * On TTY: progress overwrites via \r, then line is cleared. On
                 * pipe: falls back to inline " done.\n" resolution. */
                output_print(
                    out, OUTPUT_VERBOSE, "Fetching from '%s'...", remote_name
                );
                fflush(out->stream);
            }

            /* Perform batched fetch — single network op for all branches */
            error_t *fetch_err = gitops_fetch_branches(
                repo, remote_name, check, xfer
            );

            /* Resolve the "Fetching from ..." preamble line (verbose only) */
            if (verbose) {
                if (output_is_tty(out)) {
                    /* TTY: clear any remaining text. Handles all cases uniformly
                     * (callback-finalized, mid-progress error, up-to-date). */
                    transfer_progress_resolved(xfer);
                    output_clear_line(out);
                } else if (fetch_err) {
                    /* Non-TTY + error: finish the line before the warning */
                    output_newline(out, OUTPUT_VERBOSE);
                } else {
                    /* Non-TTY + success: inline resolution */
                    output_print(out, OUTPUT_VERBOSE, " done.\n");
                }
            }

            if (fetch_err) {
                /* Non-fatal: warn and continue with status display */
                output_warning(
                    out, OUTPUT_VERBOSE, "Failed to fetch branches: %s",
                    error_message(fetch_err)
                );
                error_free(fetch_err);
            }

            transfer_context_free(xfer);
        }
    }

    /* Display remote sync status section */
    output_section(out, OUTPUT_NORMAL, "Remote sync status ({cyan}%s{reset})", remote_name);

    /* Analyze and display each profile's sync state */
    size_t up_to_date = 0;
    size_t ahead = 0;
    size_t behind = 0;
    size_t diverged = 0;
    size_t no_remote = 0;

    for (size_t i = 0; i < check->count; i++) {
        const char *profile = check->items[i];

        /* Analyze upstream state */
        upstream_info_t info;
        err = upstream_analyze_profile(repo, remote_name, profile, &info);
        if (err) {
            /* Show error for this profile but continue */
            output_error(out, "  %s: %s", profile, error_message(err));
            error_free(err);
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
            case UPSTREAM_UNKNOWN:
            default:
                snprintf(
                    status_str, sizeof(status_str), "%s unknown",
                    symbol
                );
                break;
        }

        /* Display with colors */
        if (verbose && info.state != UPSTREAM_NO_REMOTE && info.state != UPSTREAM_UNKNOWN) {
            /* Verbose mode: show detailed commit info. The enclosing branch has
             * already filtered out NO_REMOTE/UNKNOWN, so both local and remote
             * refs are guaranteed to exist on every state reaching this block. */
            output_newline(out, OUTPUT_VERBOSE);
            output_print(out, OUTPUT_VERBOSE, "Profile: %s\n", profile);

            /* Get local commit info */
            char local_ref[DOTTA_REFNAME_MAX];
            error_t *local_ref_err = gitops_build_refname(
                local_ref, sizeof(local_ref), "refs/heads/%s", profile
            );
            git_commit *local_commit = NULL;
            error_t *commit_err = local_ref_err ? local_ref_err
                                : gitops_get_commit(repo, local_ref, &local_commit);

            /* Status line — always shown regardless of commit loading */
            output_print(out, OUTPUT_VERBOSE, "  Status:         ");
            output_colored(out, OUTPUT_VERBOSE, color, "%s\n", status_str);

            if (!commit_err && local_commit) {
                const git_oid *local_oid = git_commit_id(local_commit);
                char local_oid_str[8];
                git_oid_tostr(local_oid_str, sizeof(local_oid_str), local_oid);

                const char *local_summary = git_commit_summary(local_commit);
                git_time_t local_time = git_commit_time(local_commit);

                char time_str[64];
                format_relative_time(local_time, time_str, sizeof(time_str));

                output_print(
                    out, OUTPUT_VERBOSE, "  Local commit:   %s %s (%s)\n",
                    local_oid_str, local_summary, time_str
                );

                git_commit_free(local_commit);
            }
            error_free(commit_err);

            /* Remote commit info — guaranteed reachable per the enclosing filter
             * above. */
            char remote_ref[DOTTA_REFNAME_MAX];
            error_t *remote_ref_err = gitops_build_refname(
                remote_ref, sizeof(remote_ref), "refs/remotes/%s/%s",
                remote_name, profile
            );
            git_commit *remote_commit = NULL;
            commit_err = remote_ref_err ? remote_ref_err
                                        : gitops_get_commit(repo, remote_ref, &remote_commit);

            if (!commit_err && remote_commit) {
                const git_oid *remote_oid = git_commit_id(remote_commit);
                char remote_oid_str[8];
                git_oid_tostr(remote_oid_str, sizeof(remote_oid_str), remote_oid);

                const char *remote_summary = git_commit_summary(remote_commit);
                git_time_t remote_time = git_commit_time(remote_commit);

                char time_str[64];
                format_relative_time(remote_time, time_str, sizeof(time_str));

                output_print(
                    out, OUTPUT_VERBOSE, "  Remote commit:  %s %s (%s)\n",
                    remote_oid_str, remote_summary, time_str
                );

                git_commit_free(remote_commit);
            }
            error_free(commit_err);
        } else {
            /* Compact mode: single line matching enabled profiles format */
            output_styled(out, OUTPUT_NORMAL, "  {cyan}%s{reset}", profile);
            output_styled(out, OUTPUT_NORMAL, "  {dim}(%s){reset}\n", status_str);
        }
    }

    /* Display summary section */
    output_section(out, OUTPUT_NORMAL, "Sync summary");

    if (up_to_date > 0) {
        output_styled(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} up-to-date\n", up_to_date);
    }
    if (ahead > 0) {
        output_styled(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} ahead\n", ahead);
    }
    if (behind > 0) {
        output_styled(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} behind\n", behind);
    }
    if (diverged > 0) {
        output_styled(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} diverged\n", diverged);
    }
    if (no_remote > 0) {
        output_styled(out, OUTPUT_NORMAL, "  {cyan}%zu{reset} no remote\n", no_remote);
    }

    /* remote_name is arena-borrowed; no free here. */
    string_array_free(all_local);

    return NULL;
}

/**
 * Status command implementation
 */
error_t *cmd_status(const dotta_ctx_t *ctx, const cmd_status_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    const mount_table_t *mounts = ctx->run.mounts;
    content_cache_t *content_cache = ctx->run.content_cache;
    const manifest_t *manifest = ctx->run.manifest;  /* The view at dispatch */
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Declare all resources at top and initialize to NULL/zero */
    error_t *err = NULL;
    workspace_t *ws = NULL;
    scope_t *scope = NULL;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Build operation scope
     *
     *   scope_enabled — the persistent enabled set, the CLI filter's bound.
     *   scope_active  — display face (enabled profile list, remote status).
     *
     * Zero enabled profiles is a valid state: workspace classifies all state
     * entries as orphaned. This enables the "disable last profile, then status"
     * workflow. scope_build returns success with an empty enabled set — no special
     * handling needed here. */
    scope_inputs_t scope_inputs = {
        .profiles      = opts->profiles,
        .profile_count = opts->profile_count,
    };
    err = scope_build(
        repo, state, &scope_inputs, config, mounts, ctx->arena, &scope
    );
    if (err) goto cleanup;

    /* Load workspace for divergence analysis (only needed for local status)
     *
     * The workspace's profile set is the view's — the persistent enabled set —
     * so orphan detection is exact whatever -p narrowed.
     */
    if (opts->show_local) {
        workspace_load_t ws_opts = {
            .analyze_files       = true,
            .analyze_orphans     = true,
            .analyze_untracked   = config->auto_detect_new_files,
            .analyze_directories = true
        };
        err = workspace_load(
            repo, state, config, content_cache, manifest, &ws_opts, ctx->arena, &ws
        );
        if (err) {
            err = error_wrap(err, "Failed to load workspace");
            goto cleanup;
        }

        /* Persist deployment-anchor advances from slow-path CMP_EQUAL checks
         * (self-healing optimization). Seeds the fast path for subsequent status
         * calls. Non-fatal on failure — status still renders correctly, just
         * won't benefit from the fast path. */
        error_t *flush_err = workspace_flush_updates(ws);
        if (flush_err) {
            error_free(flush_err);
        }

        /* Check privileges for complete status (may re-exec with sudo)
         *
         * Both kinds: a root/ directory carries owner and group exactly as a
         * root/ file does, so reading what stands there needs the same elevation.
         * The label predicate is the privilege module's — the loops only hand
         * it every managed path. */
        if (!opts->no_sudo) {
            manifest_rows_t files = workspace_files(ws);
            manifest_rows_t dirs = workspace_directories(ws);

            string_array_t labels STRING_ARRAY_AUTO = { 0 };
            error_t *extract_err = NULL;
            for (size_t i = 0; i < files.count && !extract_err; i++) {
                extract_err = privilege_collect_label(
                    &labels,
                    files.entries[i]->storage_path,
                    files.entries[i]->filesystem_path
                );
            }
            for (size_t i = 0; i < dirs.count && !extract_err; i++) {
                extract_err = privilege_collect_label(
                    &labels,
                    dirs.entries[i]->storage_path,
                    dirs.entries[i]->filesystem_path
                );
            }

            if (!extract_err && labels.count > 0) {
                /* Check if privileges needed (may re-exec) */
                error_t *priv_err = privilege_ensure_for_operation(
                    (const char *const *) labels.items,
                    labels.count,
                    "status",
                    true,  /* interactive mode (prompt allowed) */
                    ctx->argc,
                    ctx->argv,
                    out
                );

                if (priv_err) {
                    /* User declined elevation or non-interactive mode */
                    output_newline(out, OUTPUT_NORMAL);
                    output_warning(out, OUTPUT_NORMAL, "Status check will be incomplete:\n");
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  {green}✓{reset} Content changes will be detected\n"
                    );
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  {green}✓{reset} Permission mode changes will be detected\n"
                    );
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  {red}✗{reset} Ownership changes will not be detected\n"
                    );
                    output_newline(out, OUTPUT_NORMAL);

                    error_free(priv_err);
                    /* Continue with partial status */
                }
            } else if (extract_err) {
                /* Extraction failed - non-fatal, continue without privilege check */
                error_free(extract_err);
            }
        }
    }

    /* Display enabled profiles and last deployment info */
    display_enabled_profiles(out, scope_active(scope), ws, manifest_unbound(manifest));

    /* The whole view, on request — before the verdict and the sections that name
     * only what diverged from it */
    if (opts->show_local && opts->full) {
        display_manifest(ws, scope, out);
    }

    /* Display workspace status (with profile filtering for Coherent Scope)
     *
     * The workspace was loaded over the persistent enabled set (the view's) for
     * accurate divergence analysis. display_workspace_status then applies the
     * CLI filter dimension via scope_accepts_profile so `dotta status -p work`
     * matches `dotta apply -p work` behavior.
     */
    if (opts->show_local) {
        display_workspace_status(ws, scope, out);
    }

    /* Show remote sync status (if requested) */
    if (opts->show_remote) {
        err = display_remote_status(
            ctx, scope_active(scope), opts->all_profiles, opts->no_fetch
        );
        if (err) {
            /* Non-fatal: might not have remote configured */
            error_free(err);
            err = NULL;
        }
    }

cleanup:
    if (ws) workspace_free(ws);
    if (scope) scope_free(scope);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Resolve the --local / --remote intent pair into show_local / show_remote. Legacy
 * default: both true when neither flag given. Explicit flags reduce to their
 * own scope; giving both is identical to the default.
 */
static error_t *status_post_parse(
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

static error_t *status_dispatch(const void *ctx_v, void *opts_v) {
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
        "no-sudo",
        cmd_status_options_t,no_sudo,
        "Skip sudo; disables ownership checks"
    ),
    ARGS_FLAG(
        "full",
        cmd_status_options_t,full,
        "List every managed path with its state"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_status_options_t,verbose,
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
        "Privilege Requirements:\n"
        "  Ownership checks on root/ files require root privileges. When\n"
        "  invoked without root, dotta prompts for sudo. --no-sudo skips\n"
        "  the prompt; ownership divergence will not be detected.\n"
        "\n"
        "Remote State Indicators:\n"
        "  =    up-to-date with remote\n"
        "  ^n   n commits ahead of remote (ready to push)\n"
        "  vn   n commits behind remote (run '%s sync' to pull)\n"
        "  <>   diverged from remote (needs resolution)\n"
        "  .    no remote tracking branch\n",
    .examples     =
        "  %s status                         # Local + remote\n"
        "  %s status --local                 # Filesystem only\n"
        "  %s status --remote                # Remote only\n"
        "  %s status --no-fetch              # Skip fetch (cached refs)\n"
        "  %s status -p work -p home         # Named profiles only\n"
        "  %s status --all                   # Include non-enabled profiles\n"
        "  %s status --full                  # Every managed path, clean ones too\n",
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
        .mounts   = true,
        .crypto   = true,
        .manifest = true,
    },
    .dispatch     = status_dispatch,
};
