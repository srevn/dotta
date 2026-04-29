/**
 * status.c - Show status of managed files
 */

#include "cmds/status.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/timeutil.h"
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
 */
static void display_enabled_profiles(
    output_t *out,
    const string_array_t *profiles,
    const manifest_t *manifest,
    const state_t *state
) {
    if (!out || !profiles) return;

    /* Show enabled profiles */
    output_section(out, OUTPUT_NORMAL, "Enabled profiles");

    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->items[i];

        /* Format profile name */
        output_styled(out, OUTPUT_NORMAL, "  {cyan}%s{reset}", profile);

        /* Show per-profile last deployed timestamp */
        if (state) {
            time_t profile_deploy_time = state_get_profile_timestamp(state, profile);
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
                if (manifest->entries[j].profile &&
                    strcmp(manifest->entries[j].profile, profile) == 0) {
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
 * @param scope Operation scope (must not be NULL; its filter dimension drives display)
 * @param manifest Manifest for file counting (can be NULL, used with profile filter)
 * @param out Output context (must not be NULL)
 */
static void display_workspace_status(
    workspace_t *ws,
    const scope_t *scope,
    const manifest_t *manifest,
    output_t *out
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

    if (scope_has_filter(scope)) {
        /* Count total managed files from manifest for filtered profile(s) */
        if (manifest) {
            for (size_t i = 0; i < manifest->count; i++) {
                if (scope_accepts_profile(scope, manifest->entries[i].profile)) {
                    profile_file_count++;
                }
            }
        }

        /* Partition diverged items into filtered vs hidden */
        for (size_t i = 0; i < all_count; i++) {
            if (scope_accepts_profile(scope, all_items[i].profile)) {
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

    /* Tracks whether the Issues section contained orphans with divergence */
    bool has_diverged_orphans = false;

    /* Show sectioned output for dirty/invalid workspace */
    if (ws_status != WORKSPACE_CLEAN) {
        /* When filter active and filtered profile is clean, skip detailed sections */
        if ((!scope_has_filter(scope) || filtered_diverged > 0) && all_count > 0) {

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
                if (!scope_accepts_profile(scope, item->profile)) {
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
                    /* Render orphans and track whether any are diverged.
                     * Clean orphans (DIVERGENCE_NONE) are straightforward; they'll
                     * be removed. Diverged orphans (modified, mode, unverified) are
                     * confusing cases where apply won't remove the file.
                     */
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

        /* Section-level hint: show detailed guidance only for
         * diverged orphans. Placed outside the Issues section */
        if (has_diverged_orphans) {
            output_newline(out, OUTPUT_NORMAL);
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
            output_hintline(
                out, OUTPUT_NORMAL, "  [orphaned] [unverified] "
                "- Missing key, skipped by 'dotta apply'"
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
    arena_t *arena,
    const string_array_t *profiles,
    output_t *out,
    bool show_all_profiles,
    bool no_fetch
) {
    CHECK_NULL(repo);
    CHECK_NULL(arena);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    bool verbose = output_is_verbose(out);

    /* Detect remote (name + URL — URL feeds the credential helper when we
     * fetch below). Both outputs are arena-borrowed for the call's lifetime. */
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    error_t *err = gitops_resolve_default_remote(
        repo, arena, &remote_name, no_fetch ? NULL : &remote_url
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
        /* xfer is required by gitops network ops (credential state machine
         * + approve/reject are needed even without verbose progress).
         * Status's fetch is a background refresh: progress is always
         * ephemeral so it never persists between status sections. */
        transfer_options_t xfer_opts = {
            .output             = out,
            .url                = remote_url,
            .ephemeral_progress = true,
        };
        transfer_context_t *xfer = NULL;
        error_t *xfer_err = transfer_context_create(&xfer_opts, &xfer);

        if (xfer_err) {
            /* Non-fatal: skip the fetch and fall through to cached status
             * display. Matches the "skip section on failure" pattern used
             * earlier for remote detection. */
            output_warning(
                out, OUTPUT_NORMAL, "Skipping remote fetch: %s",
                error_message(xfer_err)
            );
            error_free(xfer_err);
        } else {
            if (verbose) {
                /* Ephemeral fetch message (no newline — resolved after fetch).
                 * On TTY: progress overwrites via \r, then line is cleared.
                 * On pipe: falls back to inline " done.\n" resolution. */
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
                    /* TTY: clear any remaining text. Handles all cases
                     * uniformly (callback-finalized, mid-progress error,
                     * up-to-date). */
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
    output_section(out, OUTPUT_NORMAL, "Remote sync status (%s)", remote_name);

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

        /* Format display based on state. Color comes from the shared
         * map; only the descriptive text and the per-state counter are
         * caller-specific. */
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
            /* Verbose mode: show detailed commit info. The enclosing branch
             * has already filtered out NO_REMOTE/UNKNOWN, so both local and
             * remote refs are guaranteed to exist on every state reaching
             * this block. */
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

            /* Remote commit info — guaranteed reachable per the enclosing
             * filter above. */
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
 * Extract paths needing elevation from manifest for privilege checking
 *
 * Uses privilege_needs_elevation() to filter paths, considering whether
 * each entry's custom target is under $HOME. Allocates array of storage
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
    char ***paths_out,
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

    char **paths = calloc(manifest->count, sizeof(char *));
    if (!paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
    }

    size_t count = 0;
    for (size_t i = 0; i < manifest->count; i++) {
        if (privilege_needs_elevation(
            manifest->entries[i].storage_path, manifest->entries[i].filesystem_path
            )) {
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
error_t *cmd_status(const dotta_ctx_t *ctx, const cmd_status_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Declare all resources at top and initialize to NULL */
    error_t *err = NULL;
    workspace_t *ws = NULL;
    state_t *state = ctx->state;  /* Borrowed from dispatcher; do not free */
    const manifest_t *manifest = NULL;
    scope_t *scope = NULL;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Build operation scope
     *
     *   scope_enabled — persistent VWD scope (passed to workspace_load for
     *                   accurate orphan detection).
     *   scope_active  — display face (enabled profile list, remote status).
     *
     * Zero enabled profiles is a valid state: workspace classifies all
     * state entries as orphaned. This enables the "disable last profile,
     * then status" workflow. scope_build returns success with an empty
     * enabled set — no special handling needed here. */
    scope_inputs_t scope_inputs = {
        .profiles      = opts->profiles,
        .profile_count = opts->profile_count,
    };
    err = scope_build(repo, state, &scope_inputs, config, ctx->arena, &scope);
    if (err) goto cleanup;

    /* Load workspace for divergence analysis (only needed for local status)
     *
     * Uses persistent enabled profiles to ensure accurate orphan detection.
     * Manifest scope matches state scope, preventing false orphan reports.
     */
    if (opts->show_local) {
        workspace_load_t ws_opts = {
            .analyze_files       = true,
            .analyze_orphans     = true,
            .analyze_untracked   = config->auto_detect_new_files,
            .analyze_directories = true,
            .analyze_encryption  = true
        };
        err = workspace_load(
            repo, state, scope, config, ctx->content_cache, &ws_opts,
            ctx->arena, &ws
        );
        if (err) {
            err = error_wrap(err, "Failed to load workspace");
            goto cleanup;
        }

        /* Persist deployment-anchor advances from slow-path CMP_EQUAL checks
         * (self-healing optimization). Seeds the fast path for subsequent
         * status calls. Non-fatal on failure — status still renders correctly,
         * just won't benefit from the fast path. */
        error_t *flush_err = workspace_flush_anchor_updates(ws);
        if (flush_err) {
            error_free(flush_err);
        }

        /* Extract manifest from workspace (borrowed reference, owned by workspace) */
        manifest = workspace_get_manifest(ws);
        if (!manifest) {
            err = ERROR(ERR_INTERNAL, "Workspace manifest is NULL");
            goto cleanup;
        }

        /* Check privileges for complete status (may re-exec with sudo) */
        if (!opts->no_sudo && manifest->count > 0) {
            /* Extract paths that need elevation from manifest */
            char **storage_paths = NULL;
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
            } else {
                /* Extraction failed - non-fatal, continue without privilege check */
                error_free(extract_err);
            }

            free(storage_paths);
        }
    }

    /* Display enabled profiles and last deployment info */
    display_enabled_profiles(out, scope_active(scope), manifest, state);

    /* Display workspace status (with profile filtering for Coherent Scope)
     *
     * The workspace was loaded with the persistent enabled set
     * (scope_enabled) for accurate divergence analysis. display_workspace_status
     * then applies the CLI filter dimension via scope_accepts_profile so
     * `dotta status -p work` matches `dotta apply -p work` behavior.
     */
    if (opts->show_local) {
        display_workspace_status(ws, scope, manifest, out);
    }

    /* Show remote sync status (if requested) */
    if (opts->show_remote) {
        err = display_remote_status(
            repo, ctx->arena, scope_active(scope), out,
            opts->all_profiles, opts->no_fetch
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
 * Resolve the --local / --remote intent pair into show_local /
 * show_remote. Legacy default: both true when neither flag given.
 * Explicit flags reduce to their own scope; giving both is identical
 * to the default.
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
    .name        = "status",
    .summary     = "Show workspace status and remote sync state",
    .usage       = "%s status [options] [profile]...",
    .description =
        "Report divergence between enabled profiles and the filesystem,\n"
        "plus each profile's push/pull state against its remote. Default\n"
        "scope covers both; --local and --remote restrict it.\n",
    .notes       =
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
    .examples    =
        "  %s status                         # Local + remote\n"
        "  %s status --local                 # Filesystem only\n"
        "  %s status --remote                # Remote only\n"
        "  %s status --no-fetch              # Skip fetch (cached refs)\n"
        "  %s status -p work -p home         # Named profiles only\n"
        "  %s status --all                   # Include non-enabled profiles\n",
    .epilogue    =
        "See also:\n"
        "  %s apply           # Deploy the pending filesystem changes\n"
        "  %s update          # Commit local filesystem changes\n"
        "  %s sync            # Reconcile with remote\n",
    .opts_size   = sizeof(cmd_status_options_t),
    .opts        = status_opts,
    .post_parse  = status_post_parse,
    .payload     = &dotta_ext_read_crypto,
    .dispatch    = status_dispatch,
};
