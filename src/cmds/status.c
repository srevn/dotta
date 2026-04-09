/**
 * status.c - Show status of managed files
 */

#include "cmds/status.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/timeutil.h"
#include "core/profiles.h"
#include "core/state.h"
#include "sys/upstream.h"
#include "core/workspace.h"
#include "sys/gitops.h"
#include "sys/transfer.h"
#include "utils/privilege.h"

/**
 * Display enabled profiles and last deployment info
 */
static void display_enabled_profiles(
    output_ctx_t *out,
    const string_array_t *names,
    const manifest_t *manifest,
    const state_t *state
) {
    if (!out || !names) return;

    /* Show enabled profiles */
    output_section(out, OUTPUT_NORMAL, "Enabled profiles");

    for (size_t i = 0; i < names->count; i++) {
        const char *name = names->items[i];

        /* Format profile name */
        output_styled(out, OUTPUT_NORMAL, "  {cyan}%s{reset}", name);

        /* Show per-profile last deployed timestamp */
        if (state) {
            time_t profile_deploy_time = state_get_profile_timestamp(state, name);
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
        }

        /* In verbose mode, show file count for this profile */
        if (output_is_verbose(out) && manifest) {
            size_t profile_file_count = 0;
            for (size_t j = 0; j < manifest->count; j++) {
                if (manifest->entries[j].profile_name &&
                    strcmp(manifest->entries[j].profile_name, name) == 0) {
                    profile_file_count++;
                }
            }
            output_print(
                out, OUTPUT_NORMAL, "\n    %zu file%s",
                profile_file_count, profile_file_count == 1 ? "" : "s"
            );
        }

        output_newline(out, OUTPUT_NORMAL);
    }
}

/**
 * Display workspace status
 *
 * Shows the consistency between profile state, deployment state, and filesystem.
 * Organized into actionable sections (Git-like structure).
 *
 * When a profile filter is active, the status line is scoped to the filtered
 * profile(s), showing file counts and per-profile divergence instead of global
 * workspace status. This prevents misleading "Dirty" messages when the filtered
 * profile is clean but other enabled profiles have divergence.
 *
 * @param ws Workspace (must not be NULL, borrowed from caller)
 * @param profile_filter Optional profile filter (NULL = show all items)
 * @param manifest Manifest for file counting (can be NULL, used with profile filter)
 * @param out Output context (must not be NULL)
 * @param verbose Verbose output flag
 */
static void display_workspace_status(
    workspace_t *ws,
    const string_array_t *filter,
    const manifest_t *manifest,
    output_ctx_t *out
) {
    if (!ws || !out) return;

    /* Get workspace status from provided workspace */
    workspace_status_t ws_status = workspace_get_status(ws);

    /* Get all diverged items (shared between pre-scan and categorization) */
    size_t all_count = 0;
    const workspace_item_t *all_items = workspace_get_all_diverged(ws, &all_count);

    /* Pre-scan: count files and diverged items scoped to profile filter.
     * Needed before the status line to determine filtered workspace state. */
    size_t profile_file_count = 0;
    size_t filtered_diverged = 0;
    size_t hidden_count = 0;

    if (filter) {
        /* Count total managed files from manifest for filtered profile(s) */
        if (manifest) {
            for (size_t i = 0; i < manifest->count; i++) {
                if (manifest->entries[i].profile_name &&
                    profile_filter_matches(
                    manifest->entries[i].profile_name, filter
                    )) {
                    profile_file_count++;
                }
            }
        }

        /* Partition diverged items into filtered vs hidden */
        for (size_t i = 0; i < all_count; i++) {
            if (profile_filter_matches(all_items[i].profile, filter)) {
                filtered_diverged++;
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
    bool has_divergence = filter ? (filtered_diverged > 0)
                                       : (ws_status != WORKSPACE_CLEAN);
    if (!has_divergence && hidden_count == 0 && !output_is_verbose(out)) {
        return;
    }

    output_section(out, OUTPUT_NORMAL, "Workspace status");

    /* Display status line */
    if (filter) {
        /* Profile-scoped status: reflects the filtered profile */
        if (filtered_diverged == 0) {
            if (profile_file_count > 0) {
                output_colored(
                    out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN,
                    "  Clean - %zu file%s aligned\n",
                    profile_file_count, profile_file_count == 1 ? "" : "s"
                );
            } else {
                output_colored(
                    out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN,
                    "  Clean - no files in profile\n"
                );
            }
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
                if (manifest && manifest->count > 0) {
                    output_colored(
                        out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN,
                        "  Clean - %zu file%s aligned\n",
                        manifest->count, manifest->count == 1 ? "" : "s"
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
                    "  Invalid - workspace has orphaned state entries\n"
                );
                break;
        }
    }

    /* Staleness warning — external Git changes detected */
    if (workspace_is_stale(ws)) {
        output_warning(
            out, OUTPUT_NORMAL, "External Git changes detected — manifest is stale\n"
            "  Hint: Run 'dotta apply' to synchronize state"
        );
    }

    /* Show sectioned output for dirty/invalid workspace */
    if (ws_status != WORKSPACE_CLEAN) {
        /* When filter active and filtered profile is clean, skip detailed sections */
        if (!filter || filtered_diverged > 0) {

            /* Single allocation for all category pointers (5 categories × all_count slots)
             * Memory layout: [uncommitted][undeployed][new_files][orphaned][reassigned]
             * This provides cache-friendly contiguous memory with single malloc/free. */
            const workspace_item_t **categorized =
                malloc(all_count * 5 * sizeof(workspace_item_t *));
            if (!categorized) {
                output_error(
                    out, "Failed to allocate memory for status display (%zu items)",
                    all_count
                );
                return;
            }

            /* Category arrays (pointer arithmetic into single allocation) */
            const workspace_item_t **uncommitted = categorized;
            const workspace_item_t **undeployed = categorized + all_count;
            const workspace_item_t **new_files = categorized + all_count * 2;
            const workspace_item_t **orphaned = categorized + all_count * 3;
            const workspace_item_t **reassigned = categorized + all_count * 4;

            size_t uncommitted_count = 0;
            size_t undeployed_count = 0;
            size_t new_count = 0;
            size_t orphaned_count = 0;
            size_t reassigned_count = 0;
            for (size_t i = 0; i < all_count; i++) {
                const workspace_item_t *item = &all_items[i];

                /* Apply profile filter if specified (Coherent Scope)
                 *
                 * When profile filter is active, only show items from matching
                 * profiles. This ensures status output matches what apply would do.
                 */
                if (filter &&
                    !profile_filter_matches(item->profile, filter)) {
                    continue;  /* Skip items from other profiles */
                }

                switch (item->state) {
                    case WORKSPACE_STATE_DEPLOYED:
                        if (item->divergence != DIVERGENCE_NONE) {
                            /* Real divergence → uncommitted changes */
                            uncommitted[uncommitted_count++] = item;
                        } else if (item->profile_changed) {
                            /* Pure profile reassignment (no filesystem divergence) */
                            reassigned[reassigned_count++] = item;
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

            /* Section 1: Uncommitted Changes */
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

                        if (workspace_item_extract_display_info(
                            uncommitted[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            output_list_add(
                                list, tags, tag_count, color,
                                uncommitted[i]->filesystem_path, metadata
                            );
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);
                }
            }

            /* Section 2: Profile Reassignments */
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

                        if (workspace_item_extract_display_info(
                            reassigned[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            output_list_add(
                                list, tags, tag_count, color,
                                reassigned[i]->filesystem_path, metadata
                            );
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);
                }
            }

            /* Section 3: Undeployed Files */
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

                        if (workspace_item_extract_display_info(
                            undeployed[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            output_list_add(
                                list, tags, tag_count, color,
                                undeployed[i]->filesystem_path, metadata
                            );
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);
                }
            }

            /* Section 4: New Files */
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

                        if (workspace_item_extract_display_info(
                            new_files[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            output_list_add(
                                list, tags, tag_count, color,
                                new_files[i]->filesystem_path, metadata
                            );
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);
                }
            }

            /* Section 5: Issues (orphaned) */
            if (orphaned_count > 0) {
                output_list_t *list = output_list_create(
                    out, "Issues",
                    "run \"dotta apply\" to remove orphaned files"
                );

                if (list) {
                    /* Check if any orphans have divergence
                     * Clean orphans (DIVERGENCE_NONE) are straightforward - they'll be removed.
                     * Only show guidance hints for diverged orphans (modified, mode, unverified)
                     * since those are the confusing cases where apply won't remove the file.
                     */
                    bool has_diverged_orphans = false;

                    for (size_t i = 0; i < orphaned_count; i++) {
                        const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                        size_t tag_count;
                        output_color_t color;
                        char metadata[256];

                        if (workspace_item_extract_display_info(
                            orphaned[i], tags, &tag_count,
                            &color, metadata, sizeof(metadata)
                            )) {
                            output_list_add(
                                list, tags, tag_count, color,
                                orphaned[i]->filesystem_path, metadata
                            );
                        }

                        /* Track if this orphan has divergence (not clean) */
                        if (orphaned[i]->divergence != DIVERGENCE_NONE) {
                            has_diverged_orphans = true;
                        }
                    }

                    output_list_render(list);
                    output_list_free(list);

                    /* Show detailed guidance only for diverged orphans */
                    if (has_diverged_orphans) {
                        output_hint(
                            out, OUTPUT_NORMAL,
                            "Diverged orphans blocking safe removal."
                        );
                        output_hintline(
                            out, OUTPUT_NORMAL, "  [orphaned]              "
                            "- Clean, will be removed by 'dotta apply'"
                        );
                        output_hintline(
                            out, OUTPUT_NORMAL, "  [orphaned] [modified]   "
                            "- Has uncommitted changes, skipped by 'dotta apply'"
                        );
                        output_hintline(
                            out, OUTPUT_NORMAL, "  [orphaned] [mode]       "
                            "- Permissions changed, skipped by 'dotta apply'"
                        );
                    }
                }
            }

            /* Cleanup (single free for all category arrays) */
            free(categorized);
        }

        /* Show hidden items note when profile filter is active */
        if (filter && hidden_count > 0) {
            output_styled(
                out, OUTPUT_NORMAL, "  {dim}(%zu item%s from other profiles hidden){reset}\n",
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
    git_repository *repo,
    const string_array_t *names,
    output_ctx_t *out,
    bool show_all_profiles,
    bool no_fetch
) {
    CHECK_NULL(repo);
    CHECK_NULL(names);
    CHECK_NULL(out);

    bool verbose = output_is_verbose(out);

    /* Detect remote */
    char *remote_name = NULL;
    error_t *err = upstream_detect_remote(repo, &remote_name);
    if (err) {
        /* No remote configured - not an error, just skip this section */
        error_free(err);
        return NULL;
    }

    /* Build name array for profiles to check */
    string_array_t *all_local = NULL;
    const string_array_t *check = names;

    if (show_all_profiles) {
        /* Explicit request: show ALL local profiles (lightweight, no ref resolution) */
        err = profile_list_all_local_names(repo, &all_local);
        if (err) {
            free(remote_name);
            return error_wrap(err, "Failed to list all profiles");
        }
        check = all_local;
    }

    if (check->count == 0) {
        string_array_free(all_local);
        free(remote_name);
        return NULL;
    }

    /* Fetch if requested */
    if (!no_fetch) {
        transfer_context_t *xfer = NULL;
        bool ephemeral = false;

        if (verbose) {
            /* Ephemeral fetch message (no newline — resolved after fetch).
             * On TTY: progress overwrites via \r, then line is cleared entirely.
             * On pipe: falls back to inline text resolution. */
            output_print(
                out, OUTPUT_VERBOSE, "Fetching from '%s'...",
                remote_name
            );
            fflush(out->stream);

            /* Create transfer context for progress reporting */
            char *remote_url = NULL;
            error_t *url_err = gitops_get_remote_url(repo, remote_name, &remote_url);
            error_free(url_err);
            xfer = transfer_context_create(out, remote_url);
            free(remote_url);

            if (xfer) {
                xfer->ephemeral = true;
            }
            ephemeral = output_is_tty(out);  /* ANSI clear only works on TTY */
        }

        /* Perform batched fetch - single network operation for all branches */
        error_t *fetch_err = gitops_fetch_branches(
            repo, remote_name, check, xfer
        );

        /* Resolve the ephemeral fetch/progress line */
        if (verbose) {
            if (ephemeral) {
                /* Clear any remaining text on the line. Handles all cases:
                 *   - Callback completed: already cleared, harmless no-op
                 *   - Mid-progress error: clears partial progress
                 *   - Up-to-date: clears "Fetching..." text */
                if (xfer && xfer->progress_active) {
                    xfer->progress_active = false;
                }
                output_clear_line(out);
            } else if (fetch_err) {
                /* Non-TTY: finish the line before warning */
                output_newline(out, OUTPUT_VERBOSE);
            } else if (!xfer || xfer->total_objects == 0) {
                /* Non-TTY, up-to-date: resolve inline */
                output_print(out, OUTPUT_VERBOSE, " done.\n");
            }
            /* Non-TTY with objects: callback wrote ", done.\n" */
        }

        if (fetch_err) {
            /* Non-fatal: just warn and continue with status display */
            output_warning(
                out, OUTPUT_VERBOSE, "Failed to fetch branches: %s",
                error_message(fetch_err)
            );
            error_free(fetch_err);
        }

        transfer_context_free(xfer);
    }

    /* Display remote sync status section */
    output_section(out, OUTPUT_NORMAL, "Remote sync status (%s)", remote_name);

    /* Analyze and display each profile's sync state */
    size_t up_to_date = 0;
    size_t ahead = 0;
    size_t behind = 0;
    size_t diverged = 0;
    size_t no_remote = 0;

    for (size_t i = 0; i < check->count; i++) {
        const char *profile_name = check->items[i];

        /* Analyze upstream state */
        upstream_info_t *info = NULL;
        err = upstream_analyze_profile(repo, remote_name, profile_name, &info);
        if (err) {
            /* Show error for this profile but continue */
            output_error(out, "  %s: %s", profile_name, error_message(err));
            error_free(err);
            continue;
        }

        /* Format display based on state */
        const char *symbol = upstream_state_symbol(info->state);
        output_color_t color;
        char status_str[128];

        switch (info->state) {
            case UPSTREAM_UP_TO_DATE:
                color = OUTPUT_COLOR_GREEN;
                snprintf(
                    status_str, sizeof(status_str), "%s up-to-date",
                    symbol
                );
                up_to_date++;
                break;
            case UPSTREAM_LOCAL_AHEAD:
                color = OUTPUT_COLOR_YELLOW;
                snprintf(
                    status_str, sizeof(status_str), "%s %zu ahead",
                    symbol, info->ahead
                );
                ahead++;
                break;
            case UPSTREAM_REMOTE_AHEAD:
                color = OUTPUT_COLOR_YELLOW;
                snprintf(
                    status_str, sizeof(status_str), "%s %zu behind",
                    symbol, info->behind
                );
                behind++;
                break;
            case UPSTREAM_DIVERGED:
                color = OUTPUT_COLOR_RED;
                snprintf(
                    status_str, sizeof(status_str), "%s diverged (%zu ahead, %zu behind)",
                    symbol, info->ahead, info->behind
                );
                diverged++;
                break;
            case UPSTREAM_NO_REMOTE:
                color = OUTPUT_COLOR_CYAN;
                snprintf(
                    status_str, sizeof(status_str), "%s no remote",
                    symbol
                );
                no_remote++;
                break;
            case UPSTREAM_UNKNOWN:
            default:
                color = OUTPUT_COLOR_DIM;
                snprintf(
                    status_str, sizeof(status_str), "? unknown"
                );
                break;
        }

        /* Display with colors */
        if (verbose && info->state != UPSTREAM_NO_REMOTE && info->state != UPSTREAM_UNKNOWN) {
            /* Verbose mode: show detailed commit info */
            output_newline(out, OUTPUT_VERBOSE);
            output_print(out, OUTPUT_VERBOSE, "Profile: %s\n", profile_name);

            /* Get local commit info */
            char local_ref[DOTTA_REFNAME_MAX];
            error_t *local_ref_err = gitops_build_refname(
                local_ref, sizeof(local_ref), "refs/heads/%s", profile_name
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

            /* Get remote commit info if it exists */
            if (info->exists_remotely) {
                char remote_ref[DOTTA_REFNAME_MAX];
                error_t *remote_ref_err = gitops_build_refname(
                    remote_ref, sizeof(remote_ref), "refs/remotes/%s/%s",
                    remote_name, profile_name
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
            }
        } else {
            /* Compact mode: single line matching enabled profiles format */
            output_styled(out, OUTPUT_NORMAL, "  {cyan}%s{reset}", profile_name);
            output_styled(out, OUTPUT_NORMAL, "  {dim}(%s){reset}\n", status_str);
        }

        upstream_info_free(info);
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

    /* Free name resources */
    string_array_free(all_local);
    free(remote_name);

    return NULL;
}

/**
 * Extract paths needing elevation from manifest for privilege checking
 *
 * Uses privilege_needs_elevation() to filter paths, considering whether
 * each entry's custom prefix is under $HOME. Allocates array of storage
 * path pointers. Caller must free the array (but not the strings, which
 * are borrowed from manifest).
 *
 * @param manifest Manifest (must not be NULL)
 * @param paths_out Output array of paths needing elevation (must not be NULL)
 * @param count_out Output count (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *extract_elevation_paths_from_manifest(
    const manifest_t *manifest,
    const char ***paths_out,
    size_t *count_out
) {
    CHECK_NULL(manifest);
    CHECK_NULL(paths_out);
    CHECK_NULL(count_out);

    if (manifest->count == 0) {
        *paths_out = NULL;
        *count_out = 0;
        return NULL;
    }

    const char **paths = calloc(manifest->count, sizeof(char *));
    if (!paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
    }

    size_t count = 0;
    for (size_t i = 0; i < manifest->count; i++) {
        if (privilege_needs_elevation(manifest->entries[i].storage_path,
                                     manifest->entries[i].custom_prefix)) {
            paths[count++] = manifest->entries[i].storage_path;
        }
    }

    *paths_out = paths;
    *count_out = count;

    return NULL;
}

/**
 * Status command implementation
 */
error_t *cmd_status(
    git_repository *repo,
    const config_t *config,
    output_ctx_t *out,
    const cmd_status_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Declare all resources at top and initialize to NULL */
    error_t *err = NULL;
    workspace_t *ws = NULL;
    const state_t *state = NULL;
    const manifest_t *manifest = NULL;
    string_array_t *workspace_names = NULL;
    string_array_t *cli_names = NULL;
    const string_array_t *op_names = NULL;
    const string_array_t *filter = NULL;
    bool has_profile_filter = (opts->profiles != NULL && opts->profile_count > 0);

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Load profiles
     *
     * Separate workspace scope (persistent) from display filter (temporary):
     *   - workspace_names: Persistent enabled profile names (VWD scope)
     *   - cli_names / op_names: CLI filter names or workspace names (for display)
     *
     * Workspace always loads with persistent profiles to maintain accurate
     * orphan detection. Display operations filter by CLI profiles if specified.
     */
    err = profile_resolve_state_names(repo, &workspace_names);
    if (err) {
        err = error_wrap(err, "Failed to resolve enabled profiles");
        goto cleanup;
    }

    if (workspace_names->count == 0) {
        output_info(out, OUTPUT_NORMAL, "No enabled profiles found");
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta profile enable <name>'");
        goto cleanup;
    }

    /* Resolve display profile names */
    if (has_profile_filter) {
        err = profile_resolve_cli_names(
            repo, opts->profiles, opts->profile_count, config->strict_mode, &cli_names
        );
        if (err) {
            err = error_wrap(err, "Failed to resolve display profiles");
            goto cleanup;
        }

        err = profile_validate_filter(workspace_names, cli_names);
        if (err) goto cleanup;

        filter = cli_names;
        op_names = cli_names;
    } else {
        op_names = workspace_names;
    }

    /* Load workspace for divergence analysis (only needed for local status)
     *
     * Uses persistent enabled profiles to ensure accurate orphan detection.
     * Manifest scope matches state scope, preventing false orphan reports.
     */
    if (opts->show_local) {
        workspace_load_t ws_opts = {
            .analyze_files       = true,
            .analyze_orphans     = true,
            .analyze_untracked   = (config && config->auto_detect_new_files),
            .analyze_directories = true,
            .analyze_encryption  = true
        };
        err = workspace_load(repo, NULL, workspace_names, config, &ws_opts, &ws);
        if (err) {
            err = error_wrap(err, "Failed to load workspace");
            goto cleanup;
        }

        /* Flush verified stat caches to database (self-healing optimization).
         * Seeds the fast path for subsequent status calls. Non-fatal on failure
         * — status still renders correctly, just won't benefit from fast path. */
        error_t *flush_err = workspace_flush_stat_caches(ws);
        if (flush_err) {
            error_free(flush_err);
        }

        /* Extract manifest from workspace (borrowed reference, owned by workspace) */
        manifest = workspace_get_manifest(ws);
        if (!manifest) {
            err = ERROR(ERR_INTERNAL, "Workspace manifest is NULL");
            goto cleanup;
        }

        /* Extract state from workspace (borrowed reference, owned by workspace) */
        state = workspace_get_state(ws);
        if (!state) {
            err = ERROR(ERR_INTERNAL, "Workspace state is NULL");
            goto cleanup;
        }

        /* Check privileges for complete status (may re-exec with sudo) */
        if (!opts->no_sudo && manifest->count > 0) {
            /* Extract paths that need elevation from manifest */
            const char **storage_paths = NULL;
            size_t path_count = 0;

            error_t *extract_err = extract_elevation_paths_from_manifest(
                manifest, &storage_paths, &path_count
            );

            if (!extract_err && path_count > 0) {
                /* Check if privileges needed (may re-exec) */
                error_t *priv_err = privilege_ensure_for_operation(
                    storage_paths,
                    path_count,
                    "status",
                    true,  /* interactive mode (prompt allowed) */
                    opts->argc,
                    opts->argv,
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
            } else {
                /* Extraction failed - non-fatal, continue without privilege check */
                error_free(extract_err);
            }

            free((void *) storage_paths);
        }
    }

    /* Display enabled profiles and last deployment info */
    display_enabled_profiles(out, op_names, manifest, state);

    /* Display workspace status (with profile filtering for Coherent Scope)
     *
     * The workspace was loaded with persistent profiles (workspace_names)
     * for accurate divergence analysis. When CLI filter is specified,
     * we pass the filter to display_workspace_status to show only items
     * from those profiles. This ensures `dotta status -p work` matches
     * `dotta apply -p work` behavior.
     */
    if (opts->show_local) {
        display_workspace_status(ws, filter, manifest, out);
    }

    /* Show remote sync status (if requested) */
    if (opts->show_remote) {
        err = display_remote_status(
            repo, op_names, out, opts->all_profiles, opts->no_fetch
        );
        if (err) {
            /* Non-fatal: might not have remote configured */
            error_free(err);
            err = NULL;
        }
    }

cleanup:
    /* Free all resources (safe with NULL pointers) */
    if (ws) workspace_free(ws);
    if (cli_names) string_array_free(cli_names);
    if (workspace_names) string_array_free(workspace_names);

    return err;
}
