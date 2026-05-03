/**
 * diff.c - Show differences between profiles and filesystem
 */

#include "cmds/diff.h"

#include <assert.h>
#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/args.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "base/string.h"
#include "base/timeutil.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "infra/pathspec.h"
#include "infra/mount.h"
#include "sys/gitops.h"

/**
 * Determine if workspace item should be shown for the given direction
 *
 * Direction semantics:
 * - UPSTREAM: Show items where repository would change filesystem
 *   (undeployed files, files where Git differs from filesystem,
 *    profile reassignments that apply would acknowledge)
 * - DOWNSTREAM: Show items where filesystem would change repository
 *   (modified files, deleted files that exist in Git)
 *
 * @param item Workspace item (must not be NULL)
 * @param direction Diff direction
 * @return true if item should be shown
 */
static bool should_show_item_for_direction(
    const workspace_item_t *item,
    diff_direction_t direction
) {
    if (direction == DIFF_UPSTREAM) {
        /* Upstream: What would apply do? */
        /* Show: undeployed, deleted (apply would restore), content/mode differs,
         * or profile reassignment (apply acknowledges reassignment) */
        return (item->state == WORKSPACE_STATE_UNDEPLOYED) ||
               (item->state == WORKSPACE_STATE_DELETED) ||
               (item->state == WORKSPACE_STATE_DEPLOYED &&
               ((item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_MODE |
               DIVERGENCE_OWNERSHIP)) ||
               item->profile_changed));
    }

    if (direction == DIFF_DOWNSTREAM) {
        /* Downstream: What would update do? */
        /* Show: deleted, content/mode differs (filesystem → Git) */
        return (item->state == WORKSPACE_STATE_DELETED) ||
               (item->state == WORKSPACE_STATE_DEPLOYED &&
               (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_MODE |
               DIVERGENCE_OWNERSHIP)));
    }

    /* DIFF_BOTH is always decomposed into two explicit calls by the caller
     * before reaching this function — it should never arrive here. */
    return false;
}

/**
 * Get status message from workspace item and direction
 *
 * Determines the appropriate status message based on item's state,
 * divergence flags, and diff direction. This replaces the comparison-based
 * get_status_message() for workspace-aware diffs.
 *
 * @param item Workspace item (must not be NULL)
 * @param direction Diff direction
 * @return Status message string
 */
static const char *get_status_message_from_item(
    const workspace_item_t *item,
    diff_direction_t direction
) {
    /* Handle state-based messages first */
    if (item->state == WORKSPACE_STATE_UNDEPLOYED) {
        return direction == DIFF_UPSTREAM
                ? "not deployed (would be created by apply)"
                : "new in repository (not deployed yet)";
    }

    if (item->state == WORKSPACE_STATE_DELETED) {
        return direction == DIFF_UPSTREAM
                ? "deleted locally (file missing)"
                : "deleted locally (would be removed by update)";
    }

    /* Handle divergence-based messages for deployed items */
    if (item->divergence & DIVERGENCE_TYPE) {
        return direction == DIFF_UPSTREAM
                ? "type would change on apply"
                : "type changed locally";
    }

    if (item->divergence & DIVERGENCE_CONTENT) {
        return direction == DIFF_UPSTREAM
                ? "would be overwritten by apply"
                : "modified locally (would be committed by update)";
    }

    if (item->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
        return direction == DIFF_UPSTREAM
                ? "mode would change on apply"
                : "mode changed locally";
    }

    /* Profile reassignment with no content/metadata divergence.
     * Only reachable via UPSTREAM (DOWNSTREAM filtered by should_show_item). */
    if (item->profile_changed) {
        return "profile reassigned (acknowledged by apply)";
    }

    return "unknown";
}

/**
 * Show diff for a single file using workspace data
 *
 * Simplified version of show_file_diff() that uses pre-computed divergence
 * from workspace analysis. Doesn't re-analyze - just formats and displays.
 *
 * @param item Workspace item with divergence info (must not be NULL)
 * @param entry Manifest entry with VWD cache fields (must not be NULL)
 * @param cache Content cache (must not be NULL)
 * @param repo Repository (must not be NULL)
 * @param direction Diff direction
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *show_file_diff_from_workspace(
    const workspace_item_t *item,
    const state_file_entry_t *file,
    content_cache_t *cache,
    git_repository *repo,
    diff_direction_t direction,
    const cmd_diff_options_t *opts,
    output_t *out
) {
    CHECK_NULL(item);
    CHECK_NULL(file);
    CHECK_NULL(cache);
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Name-only output */
    if (opts->name_only) {
        output_print(out, OUTPUT_NORMAL, "%s\n", item->filesystem_path);
        return NULL;
    }

    /* Show file header */
    output_styled(
        out, OUTPUT_NORMAL, "{dim}# Profile:{reset} %s\n",
        file->profile
    );
    output_styled(
        out, OUTPUT_NORMAL, "{dim}# Path:{reset}    %s\n",
        file->storage_path
    );

    /* Get status message from workspace item (no re-analysis needed) */
    const char *status_msg = get_status_message_from_item(item, direction);

    /* Determine status color */
    output_color_t status_color = OUTPUT_COLOR_YELLOW;
    if (item->state == WORKSPACE_STATE_DELETED ||
        item->state == WORKSPACE_STATE_UNDEPLOYED) {
        status_color = OUTPUT_COLOR_RED;
    } else if (item->divergence & DIVERGENCE_TYPE) {
        status_color = OUTPUT_COLOR_RED;
    } else if (item->profile_changed && item->divergence == DIVERGENCE_NONE) {
        status_color = OUTPUT_COLOR_CYAN;
    }

    /* Show status */
    output_styled(out, OUTPUT_NORMAL, "{dim}# Status:{reset}  ");
    output_colored(out, OUTPUT_NORMAL, status_color, "%s\n", status_msg);

    /* For missing files or type changes, no content diff to show */
    if (item->state == WORKSPACE_STATE_DELETED ||
        item->state == WORKSPACE_STATE_UNDEPLOYED ||
        (item->divergence & DIVERGENCE_TYPE)) {
        return NULL;
    }

    /* For mode-only changes (content matches), no content diff */
    if ((item->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) &&
        !(item->divergence & DIVERGENCE_CONTENT)) {
        return NULL;
    }

    /* For profile reassignment only (content matches), no content diff */
    if (item->profile_changed && item->divergence == DIVERGENCE_NONE) {
        return NULL;
    }

    /* Get content from cache via VWD-cached blob_oid (borrowed reference - don't free) */
    const buffer_t *content = NULL;
    error_t *err = content_cache_get_from_blob_oid(
        cache, &file->blob_oid, file->storage_path, file->profile, &content
    );
    if (err) {
        return error_wrap(
            err, "Failed to get content for '%s'",
            item->filesystem_path
        );
    }

    /* Generate diff */
    git_filemode_t mode = state_type_to_git_filemode(file->type);
    compare_direction_t cmp_dir = (direction == DIFF_UPSTREAM)
                                ? CMP_DIR_UPSTREAM : CMP_DIR_DOWNSTREAM;

    file_diff_t *diff = NULL;
    err = compare_generate_diff(
        content, item->filesystem_path, file->storage_path, mode, NULL,
        cmp_dir, &diff
    );

    if (err) {
        return error_wrap(
            err, "Failed to generate diff for '%s'",
            item->filesystem_path
        );
    }

    if (diff) {
        output_styled(out, OUTPUT_NORMAL, "{dim}---{reset}\n");
        output_print_diff(out, diff->diff_text);
    }

    compare_free_diff(diff);

    return NULL;
}

/**
 * Present diffs for a specific direction using workspace analysis
 *
 * Filters pre-analyzed divergence and generates diffs for display.
 * Uses cached metadata and content from workspace/caches.
 *
 * @param ws Workspace handle for active-row lookup (must not be NULL)
 * @param diverged Array of diverged items from workspace (must not be NULL)
 * @param diverged_count Number of diverged items
 * @param content_cache Content cache for blob access (must not be NULL)
 * @param repo Repository (must not be NULL)
 * @param direction Diff direction (UPSTREAM or DOWNSTREAM)
 * @param scope Operation scope (profile + path dimensions; diff has no excludes)
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @param diff_count Output: number of diffs shown (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *present_diffs_for_direction(
    const workspace_t *ws,
    const workspace_item_t *diverged,
    size_t diverged_count,
    content_cache_t *content_cache,
    git_repository *repo,
    diff_direction_t direction,
    const scope_t *scope,
    const cmd_diff_options_t *opts,
    output_t *out,
    size_t *diff_count
) {
    CHECK_NULL(ws);
    CHECK_NULL(content_cache);
    CHECK_NULL(repo);
    CHECK_NULL(scope);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(diff_count);

    *diff_count = 0;
    error_t *err = NULL;

    /* Early return if no diverged items */
    if (diverged_count == 0 || !diverged) {
        return NULL;
    }

    for (size_t i = 0; i < diverged_count; i++) {
        const workspace_item_t *item = &diverged[i];

        /* Filter 1: Only process FILES (skip directories) */
        if (item->item_kind != WORKSPACE_ITEM_FILE) {
            continue;
        }

        /* Filter 2: Check file filter (user-specified files) */
        if (!scope_accepts_path(scope, item->storage_path)) {
            continue;
        }

        /* Filter 3: Direction-based filtering */
        if (!should_show_item_for_direction(item, direction)) {
            continue;
        }

        /* Filter 4: Profile filter (CLI filtering) */
        if (!scope_accepts_profile(scope, item->profile)) {
            continue;
        }

        /* Resolve to active state row via workspace's active index (O(1)).
         * Untracked or orphaned items have no active row — skip them. */
        const state_file_entry_t *file =
            workspace_lookup_active(ws, item->filesystem_path);
        if (!file) {
            continue;
        }

        /* Blank line between entries for readability */
        if (*diff_count > 0 && !opts->name_only) {
            output_newline(out, OUTPUT_NORMAL);
        }

        /* Show the diff (content already analyzed by workspace) */
        err = show_file_diff_from_workspace(
            item, file, content_cache, repo, direction, opts, out
        );
        if (err) {
            return err;
        }

        (*diff_count)++;
    }

    return NULL;
}

/**
 * Resolve commit reference across enabled profiles
 *
 * Searches for the commit in enabled profiles in order.
 * Returns the first match found.
 *
 * @param repo Repository (must not be NULL)
 * @param profiles Selected profiles to search (must not be NULL)
 * @param commit_ref Commit reference (must not be NULL)
 * @param out_oid Resolved commit OID (must not be NULL)
 * @param out_commit Resolved commit object (can be NULL, caller must free)
 * @param out_profile Found profile name (can be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *resolve_commit_in_profiles(
    git_repository *repo,
    const string_array_t *profiles,
    const char *commit_ref,
    git_oid *out_oid,
    git_commit **out_commit,
    char **out_profile
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(commit_ref);
    CHECK_NULL(out_oid);

    error_t *last_err = NULL;

    /* Search profiles in order */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->items[i];

        error_t *err = gitops_resolve_commit_in_branch(
            repo, profile, commit_ref, out_oid, out_commit
        );

        if (!err) {
            /* Found it! */
            if (out_profile) {
                *out_profile = strdup(profile);

                if (!*out_profile) {
                    if (out_commit && *out_commit) {
                        git_commit_free(*out_commit);
                        *out_commit = NULL;
                    }
                    return ERROR(
                        ERR_MEMORY, "Failed to allocate profile name"
                    );
                }
            }
            if (last_err) {
                error_free(last_err);
            }
            return NULL;
        }

        /* Save last error for reporting if we don't find anything */
        if (last_err) {
            error_free(last_err);
        }
        last_err = err;
    }

    /* Not found in any profile */
    if (last_err) {
        error_t *wrapped = error_wrap(
            last_err, "Commit '%s' not found in any enabled profile",
            commit_ref
        );
        return wrapped;
    }

    return ERROR(
        ERR_NOT_FOUND, "Commit '%s' not found in any enabled profile",
        commit_ref
    );
}

/**
 * Print commit header with metadata
 */
static void print_commit_header(
    output_t *out,
    const git_commit *commit,
    const git_oid *commit_oid,
    const char *profile
) {
    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), commit_oid);

    const git_signature *author = git_commit_author(commit);
    time_t commit_time = (time_t) author->when.time;

    /* Format absolute time */
    struct tm tm_info;
    localtime_r(&commit_time, &tm_info);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%a %b %d %H:%M:%S %Y", &tm_info);

    /* Format relative time */
    char relative_buf[64];
    format_relative_time(commit_time, relative_buf, sizeof(relative_buf));

    /* Print header with colors */
    output_styled(
        out, OUTPUT_NORMAL, "{yellow}commit %s{reset}",
        oid_str
    );
    if (profile) {
        output_styled(
            out, OUTPUT_NORMAL, " {cyan}(%s){reset}",
            profile
        );
    }
    output_newline(out, OUTPUT_NORMAL);

    output_styled(
        out, OUTPUT_NORMAL, "{bold}Author:{reset} %s <%s>\n",
        author->name, author->email
    );
    output_styled(
        out, OUTPUT_NORMAL, "{bold}Date:{reset}   %s (%s)\n",
        time_buf, relative_buf
    );
    output_newline(out, OUTPUT_NORMAL);

    /* Print commit message with indentation */
    const char *message = git_commit_message(commit);
    char *msg_copy = strdup(message);
    if (!msg_copy) {
        output_print(out, OUTPUT_NORMAL, "    (message unavailable)\n");
    } else {
        char *saveptr = NULL;
        char *line = strtok_r(msg_copy, "\n", &saveptr);
        while (line) {
            output_print(out, OUTPUT_NORMAL, "    %s\n", line);
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(msg_copy);
    }
    output_newline(out, OUTPUT_NORMAL);
}

/**
 * Print diff statistics
 */
static error_t *print_diff_stats(
    output_t *out,
    git_diff *diff
) {
    CHECK_NULL(out);
    CHECK_NULL(diff);

    git_diff_stats *stats = NULL;
    error_t *err = gitops_diff_get_stats(diff, &stats);
    if (err) {
        return err;
    }

    size_t files_changed = git_diff_stats_files_changed(stats);
    size_t insertions = git_diff_stats_insertions(stats);
    size_t deletions = git_diff_stats_deletions(stats);

    /* Print stats with color */
    output_print(
        out, OUTPUT_NORMAL, " %zu file%s changed",
        files_changed, files_changed == 1 ? "" : "s"
    );

    if (insertions > 0) {
        output_styled(
            out, OUTPUT_NORMAL, ", {green}%zu insertion%s(+){reset}",
            insertions, insertions == 1 ? "" : "s"
        );
    }

    if (deletions > 0) {
        output_styled(
            out, OUTPUT_NORMAL, ", {red}%zu deletion%s(-){reset}",
            deletions, deletions == 1 ? "" : "s"
        );
    }

    output_newline(out, OUTPUT_NORMAL);

    git_diff_stats_free(stats);

    return NULL;
}

/**
 * Print diff content (actual changes)
 */
static int print_diff_line_cb(
    const git_diff_delta *delta,
    const git_diff_hunk *hunk,
    const git_diff_line *line,
    void *payload
) {
    output_t *out = (output_t *) payload;
    (void) delta;
    (void) hunk;

    output_color_t line_color = OUTPUT_COLOR_RESET;

    switch (line->origin) {
        case GIT_DIFF_LINE_ADDITION:
            line_color = OUTPUT_COLOR_GREEN;
            break;
        case GIT_DIFF_LINE_DELETION:
            line_color = OUTPUT_COLOR_RED;
            break;
        case GIT_DIFF_LINE_FILE_HDR:
        case GIT_DIFF_LINE_HUNK_HDR:
            line_color = OUTPUT_COLOR_CYAN;
            break;
        default:
            break;
    }

    /* Print line origin character for change lines */
    if (line->origin == GIT_DIFF_LINE_ADDITION ||
        line->origin == GIT_DIFF_LINE_DELETION ||
        line->origin == GIT_DIFF_LINE_CONTEXT) {
        output_colored(
            out, OUTPUT_NORMAL, line_color, "%c%.*s",
            line->origin, (int) line->content_len, line->content
        );
    } else {
        /* File/hunk headers - print as-is */
        output_colored(
            out, OUTPUT_NORMAL, line_color, "%.*s",
            (int) line->content_len, line->content
        );
    }

    /* Add newline if not present */
    if (line->content_len == 0 || line->content[line->content_len - 1] != '\n') {
        output_newline(out, OUTPUT_NORMAL);
    }

    return 0;
}

/**
 * Compare a tree-built file slice against the current filesystem
 *
 * Generic comparison function for commit-to-workspace diffs. Takes a
 * state_files_t slice projected from a historical tree (via
 * manifest_load_tree_files) and compares each file against the current
 * filesystem state.
 *
 * @param repo Repository (must not be NULL)
 * @param files Tree-built file slice (passed by value; rows borrowed from
 *              the caller's arena and live until command end)
 * @param profile Profile name (must not be NULL)
 * @param file_filter File filter for CLI (can be NULL for no filter)
 * @param opts Command options (must not be NULL)
 * @param cache Shared content cache (borrowed from ctx, must not be NULL)
 * @param out Output context (must not be NULL)
 * @param diff_count Output: number of diffs shown (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *compare_tree_files_to_filesystem(
    git_repository *repo,
    state_files_t files,
    const char *profile,
    const pathspec_t *file_filter,
    const cmd_diff_options_t *opts,
    content_cache_t *cache,
    output_t *out,
    size_t *diff_count
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(opts);
    CHECK_NULL(cache);
    CHECK_NULL(out);
    CHECK_NULL(diff_count);

    *diff_count = 0;
    error_t *err = NULL;
    file_diff_t *diff = NULL;

    /* Iterate through all files in the historical slice */
    for (size_t i = 0; i < files.count; i++) {
        const state_file_entry_t *entry = files.entries[i];
        const char *fs_path = entry->filesystem_path;
        const char *storage_path = entry->storage_path;

        /* Check file filter */
        if (!pathspec_matches(file_filter, storage_path)) {
            continue;
        }

        git_filemode_t mode = state_type_to_git_filemode(entry->type);

        /* Name-only output */
        if (opts->name_only) {
            /* Use lstat to detect the path itself (broken symlinks are present,
             * not missing — only the target is absent). */
            struct stat st;
            bool exists = (lstat(fs_path, &st) == 0);

            if (!exists) {
                output_print(out, OUTPUT_NORMAL, "%s\n", fs_path);
                (*diff_count)++;
                continue;
            }

            /* Get content from historical commit (cached) */
            const buffer_t *hist_content = NULL;
            err = content_cache_get_from_blob_oid(
                cache, &entry->blob_oid, storage_path, profile, &hist_content
            );
            if (err) {
                err = error_wrap(
                    err, "Failed to get historical content for '%s'", fs_path
                );
                goto cleanup;
            }

            /* Compare with filesystem */
            compare_result_t result;
            err = compare_buffer_to_disk(
                hist_content, fs_path, mode, NULL, &result, NULL
            );
            if (err) {
                err = error_wrap(err, "Failed to compare '%s'", fs_path);
                goto cleanup;
            }

            if (result != CMP_EQUAL) {
                output_print(out, OUTPUT_NORMAL, "%s\n", fs_path);
                (*diff_count)++;
            }
            continue;
        }

        /* Full diff output */
        const buffer_t *hist_content = NULL;
        err = content_cache_get_from_blob_oid(
            cache, &entry->blob_oid, storage_path, profile, &hist_content
        );
        if (err) {
            err = error_wrap(
                err, "Failed to get historical content for '%s'",
                fs_path
            );
            goto cleanup;
        }

        /* Compare with filesystem */
        compare_result_t result;
        err = compare_buffer_to_disk(
            hist_content, fs_path, mode, NULL, &result, NULL
        );
        if (err) {
            err = error_wrap(
                err, "Failed to compare '%s'",
                fs_path
            );
            goto cleanup;
        }

        /* Skip if identical */
        if (result == CMP_EQUAL) {
            continue;
        }

        /* Blank line between entries for readability */
        if (*diff_count > 0) {
            output_newline(out, OUTPUT_NORMAL);
        }

        /* Show file header */
        output_styled(
            out, OUTPUT_NORMAL, "{dim}# Profile:{reset} %s\n",
            profile
        );
        output_styled(
            out, OUTPUT_NORMAL, "{dim}# Path:{reset}    %s\n",
            storage_path
        );

        /* Show status message */
        const char *status_msg = NULL;
        output_color_t status_color = OUTPUT_COLOR_YELLOW;

        switch (result) {
            case CMP_MISSING:
                status_msg = "deleted locally (file missing)";
                status_color = OUTPUT_COLOR_RED;
                break;
            case CMP_DIFFERENT:
                status_msg = "modified locally since commit";
                status_color = OUTPUT_COLOR_YELLOW;
                break;
            case CMP_TYPE_DIFF:
                status_msg = "type changed locally";
                status_color = OUTPUT_COLOR_RED;
                break;
            default:
                status_msg = "unknown";
                break;
        }

        output_styled(out, OUTPUT_NORMAL, "{dim}# Status:{reset}  ");
        output_colored(out, OUTPUT_NORMAL, status_color, "%s\n", status_msg);

        /* For missing files or type changes, no content diff */
        if (result == CMP_MISSING || result == CMP_TYPE_DIFF) {
            (*diff_count)++;
            continue;
        }

        err = compare_generate_diff(
            hist_content, fs_path, storage_path, mode, NULL,
            CMP_DIR_DOWNSTREAM, &diff
        );
        if (err) {
            err = error_wrap(err, "Failed to generate diff for '%s'", fs_path);
            goto cleanup;
        }

        if (diff) {
            output_styled(out, OUTPUT_NORMAL, "{dim}---{reset}\n");
            output_print_diff(out, diff->diff_text);
        }

        compare_free_diff(diff);
        diff = NULL;
        (*diff_count)++;
    }

cleanup:
    compare_free_diff(diff);
    return err;
}

/**
 * Validate file filter entries against a state file slice
 *
 * Checks each filter entry (exact paths and glob patterns) against the
 * slice's storage paths. Outputs a warning for each unmatched entry,
 * which likely indicates a typo.
 *
 * Per-pattern isolation matters here: a combined-ruleset evaluation
 * folds one pattern's negation into another's verdict and would under-
 * count coverage on overlap. The pathspec_glob_matches_at primitive
 * gives each glob independent attribution.
 *
 * One implementation serves both diff paths — the historical-diff path
 * (commit-to-workspace) feeds a tree-built slice via
 * manifest_load_tree_files; the workspace-diff path feeds the
 * workspace's active slice via workspace_active. Both flow through the
 * same state_files_t carrier.
 *
 * @param file_filter File filter to validate (NULL = no validation, returns 0)
 * @param files File slice to check against (passed by value)
 * @param out Output context for warnings
 * @return Number of filter entries that matched no managed file (0 = all matched)
 */
static size_t validate_filter_paths(
    const pathspec_t *file_filter,
    state_files_t files,
    output_t *out
) {
    if (!file_filter) return 0;

    size_t unmatched = 0;

    /* Exact paths: literal equality, then directory-prefix walk-up. */
    size_t exact_count = pathspec_exact_count(file_filter);
    for (size_t e = 0; e < exact_count; e++) {
        const char *filter_path = pathspec_exact_at(file_filter, e);
        size_t filter_len = strlen(filter_path);

        bool found = false;
        for (size_t i = 0; i < files.count; i++) {
            const char *sp = files.entries[i]->storage_path;
            if (strcmp(sp, filter_path) == 0) {
                found = true;
                break;
            }
            /* Directory prefix: filter path is ancestor of storage path */
            if (strncmp(sp, filter_path, filter_len) == 0 &&
                sp[filter_len] == '/') {
                found = true;
                break;
            }
        }

        if (!found) {
            output_warning(
                out, OUTPUT_NORMAL, "No managed file matches '%s'",
                filter_path
            );
            unmatched++;
        }
    }

    /* Glob patterns: per-pattern isolated coverage check. */
    size_t glob_count = pathspec_glob_count(file_filter);
    for (size_t g = 0; g < glob_count; g++) {
        bool found = false;
        for (size_t i = 0; i < files.count; i++) {
            if (pathspec_glob_matches_at(
                file_filter, g, files.entries[i]->storage_path
                )) {
                found = true;
                break;
            }
        }
        if (!found) {
            output_warning(
                out, OUTPUT_NORMAL, "No managed file matches pattern '%s'",
                pathspec_glob_at(file_filter, g)
            );
            unmatched++;
        }
    }

    return unmatched;
}

/**
 * Diff commit to workspace - Compare historical commit with filesystem
 *
 * CURRENT LIMITATION: Single-profile comparison only.
 * When multiple profiles are enabled, this function compares only the
 * profile that contains the specified commit (first match in precedence order)
 *
 * Type-enforced VWD invariant: historical commit search walks the persistent
 * enabled set via scope_enabled — the CLI filter must not hide commits
 * belonging to other enabled profiles. The path filter is derived from
 * scope_paths (raw CLI positional args, never narrowed).
 *
 * @param repo Repository (must not be NULL)
 * @param state State handle (must not be NULL)
 * @param commit_ref Commit reference to compare (must not be NULL)
 * @param scope Operation scope (must not be NULL)
 * @param arena Borrowed command arena (backs the tree-built file slice)
 * @param opts Command options (must not be NULL)
 * @param cache Shared content cache (borrowed from ctx, must not be NULL)
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *diff_commit_to_workspace(
    git_repository *repo,
    const char *commit_ref,
    const scope_t *scope,
    const mount_table_t *mounts,
    arena_t *arena,
    const cmd_diff_options_t *opts,
    content_cache_t *cache,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(commit_ref);
    CHECK_NULL(scope);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    const string_array_t *profiles = scope_enabled(scope);
    const pathspec_t *file_filter = scope_paths(scope);

    error_t *err = NULL;
    git_oid commit_oid;
    git_commit *commit = NULL;
    char *profile = NULL;
    git_tree *tree = NULL;
    metadata_t *metadata = NULL;
    state_files_t tree_files = { 0 };

    /* Step 1: Resolve commit to find which profile contains it */
    err = resolve_commit_in_profiles(
        repo, profiles, commit_ref, &commit_oid, &commit, &profile
    );
    if (err) {
        goto cleanup;
    }

    /* Step 2: Print commit header */
    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), &commit_oid);

    /* Warn when multiple profiles are enabled: only the profile containing
     * the commit is compared against the filesystem. */
    if (profiles->count > 1) {
        output_info(
            out, OUTPUT_NORMAL, "Note: comparing commit against profile '%s' only "
            "(commit-to-workspace compares one profile at a time)\n", profile
        );
        output_newline(out, OUTPUT_NORMAL);
    }

    output_styled(
        out, OUTPUT_NORMAL, "{bold}diff --dotta %s..workspace{reset}\n\n",
        oid_str
    );

    print_commit_header(out, commit, &commit_oid, profile);

    /* Step 3: Get tree from THE HISTORICAL COMMIT (not HEAD!) */
    int git_err = git_commit_tree(&tree, commit);
    if (git_err < 0) {
        err = error_from_git(git_err);
        err = error_wrap(err, "Failed to get tree from commit");
        goto cleanup;
    }

    /* Step 4: Load metadata from that historical tree */
    err = metadata_load_from_tree(repo, tree, profile, &metadata);
    if (err) {
        /* Graceful: if no metadata in commit, use empty metadata */
        error_free(err);
        err = metadata_create_empty(&metadata);
        if (err) goto cleanup;
    }

    /* Step 5: Project the historical tree into a state_files_t slice.
     *
     * Rows, per-row strings, and the pointer array are allocated into
     * the borrowed command arena; they outlive both this call and the
     * subsequent compare_tree_files_to_filesystem call, then live until
     * command end. No targeted free required. */
    err = manifest_load_tree_files(
        tree, profile, mounts, metadata, arena, &tree_files
    );
    if (err) {
        err = error_wrap(err, "Failed to load tree files from commit");
        goto cleanup;
    }

    /* Step 6: Compare historical slice against current filesystem */
    size_t diff_count = 0;
    err = compare_tree_files_to_filesystem(
        repo, tree_files, profile, file_filter, opts, cache, out, &diff_count
    );
    if (err) {
        goto cleanup;
    }

    if (diff_count == 0 && !opts->name_only) {
        size_t unmatched = validate_filter_paths(file_filter, tree_files, out);

        if (unmatched > 0) {
            output_hint(
                out, OUTPUT_NORMAL, "Use 'dotta list <profile>' to see managed files"
            );
        }
        if (unmatched == 0 || unmatched < pathspec_count(file_filter)) {
            output_info(
                out, OUTPUT_NORMAL, "No differences between commit and workspace\n"
            );
        }
    }

cleanup:
    /* tree_files is arena-backed (borrowed from `arena`); the caller owns
     * the arena's lifetime and reclaims every row, string, and the pointer
     * array at command end. No targeted free here. */
    metadata_free(metadata);
    git_tree_free(tree);
    git_commit_free(commit);
    free(profile);

    return err;
}

/**
 * Build a git_strarray pathspec from a path filter
 *
 * Flattens the pathspec's exact paths and glob patterns into a single
 * borrowed-pointer array suitable for libgit2's diff pathspec field.
 *
 * Memory ownership:
 *   - The returned strings array is heap-allocated; the caller frees
 *     opts->pathspec.strings after the diff operation completes.
 *   - Individual string pointers borrow from the filter and remain
 *     valid for the filter's lifetime; the filter MUST outlive the
 *     diff operation.
 *
 * Behaviour:
 *   - NULL filter or empty filter: no-op (libgit2 treats unset
 *     pathspec as "match all").
 *   - Allocation failure: returns ERR_MEMORY; opts->pathspec is left
 *     untouched.
 *
 * @param filter Path filter (can be NULL)
 * @param opts   Diff options to populate (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *build_diff_pathspec(
    const pathspec_t *filter,
    git_diff_options *opts
) {
    if (!opts) return NULL;

    size_t total = pathspec_count(filter);
    if (total == 0) return NULL;

    char **strings = calloc(total, sizeof(*strings));
    if (!strings) {
        return ERROR(
            ERR_MEMORY, "Failed to allocate memory for diff pathspec"
        );
    }

    size_t index = 0;

    size_t exact_count = pathspec_exact_count(filter);
    for (size_t i = 0; i < exact_count; i++) {
        strings[index++] = (char *) pathspec_exact_at(filter, i);
    }

    size_t glob_count = pathspec_glob_count(filter);
    for (size_t i = 0; i < glob_count; i++) {
        strings[index++] = (char *) pathspec_glob_at(filter, i);
    }

    /* Structural invariant: pathspec_count == exact_count + glob_count.
     * Held by pathspec_create; the pathspec is immutable thereafter. */
    assert(index == total);

    opts->pathspec.strings = strings;
    opts->pathspec.count = total;
    return NULL;
}

/**
 * Diff two commits
 *
 * Type-enforced VWD invariant: historical commit search walks the persistent
 * enabled set via scope_enabled — hiding commits behind the CLI filter would
 * make legitimately-referenceable commits unreachable. The path filter is
 * derived from scope_paths (raw CLI positional args, never narrowed).
 */
static error_t *diff_commits(
    git_repository *repo,
    const char *commit1_ref,
    const char *commit2_ref,
    const scope_t *scope,
    const cmd_diff_options_t *opts,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(commit1_ref);
    CHECK_NULL(commit2_ref);
    CHECK_NULL(scope);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    const string_array_t *profiles = scope_enabled(scope);
    const pathspec_t *file_filter = scope_paths(scope);

    error_t *err = NULL;
    git_oid commit1_oid, commit2_oid;
    git_commit *commit1 = NULL;
    git_commit *commit2 = NULL;
    char *profile1_name = NULL;
    char *profile2_name = NULL;
    git_tree *tree1 = NULL;
    git_tree *tree2 = NULL;
    git_diff *diff = NULL;

    /* Resolve first commit */
    err = resolve_commit_in_profiles(
        repo, profiles, commit1_ref, &commit1_oid, &commit1, &profile1_name
    );
    if (err) {
        goto cleanup;
    }

    /* Resolve second commit */
    err = resolve_commit_in_profiles(
        repo, profiles, commit2_ref, &commit2_oid, &commit2, &profile2_name
    );
    if (err) {
        goto cleanup;
    }

    /* Validate both commits are from the same profile.
     * Dotta profiles are orphan branches — comparing commits across profiles
     * would diff two completely unrelated trees, producing meaningless output. */
    if (strcmp(profile1_name, profile2_name) != 0) {
        err = ERROR(
            ERR_VALIDATION,
            "Commits belong to different profiles ('%s' and '%s'); "
            "cross-profile commit comparison is not supported",
            profile1_name, profile2_name
        );
        goto cleanup;
    }

    /* Print diff range header */
    char oid1_str[8], oid2_str[8];
    git_oid_tostr(oid1_str, sizeof(oid1_str), &commit1_oid);
    git_oid_tostr(oid2_str, sizeof(oid2_str), &commit2_oid);

    output_styled(
        out, OUTPUT_NORMAL, "{bold}diff --dotta %s..%s{reset}\n\n",
        oid1_str, oid2_str
    );

    /* Print second commit header (the "new" one) */
    print_commit_header(out, commit2, &commit2_oid, profile2_name);

    /* Get trees from commits */
    err = gitops_get_tree_from_commit(repo, &commit1_oid, &tree1);
    if (err) {
        err = error_wrap(
            err, "Failed to get tree from commit %s",
            oid1_str
        );
        goto cleanup;
    }

    err = gitops_get_tree_from_commit(repo, &commit2_oid, &tree2);
    if (err) {
        err = error_wrap(
            err, "Failed to get tree from commit %s",
            oid2_str
        );
        goto cleanup;
    }

    /* Generate diff with file filtering options */
    git_diff_options diff_opts;
    git_diff_options_init(&diff_opts, GIT_DIFF_OPTIONS_VERSION);
    err = build_diff_pathspec(file_filter, &diff_opts);
    if (err) {
        goto cleanup;
    }

    err = gitops_diff_trees(repo, tree1, tree2, &diff_opts, &diff);

    /* Free pathspec strings if they were allocated */
    if (diff_opts.pathspec.strings) {
        free(diff_opts.pathspec.strings);
    }

    if (err) {
        err = error_wrap(err, "Failed to generate diff");
        goto cleanup;
    }

    if (opts->name_only) {
        /* Name-only: list changed file paths without diff content or stats */
        int ret = git_diff_print(
            diff, GIT_DIFF_FORMAT_NAME_ONLY, print_diff_line_cb, out
        );
        if (ret < 0) {
            err = error_from_git(ret);
            goto cleanup;
        }
    } else {
        /* Full diff: statistics followed by patch */
        err = print_diff_stats(out, diff);
        if (err) goto cleanup;

        output_newline(out, OUTPUT_NORMAL);

        int ret = git_diff_print(
            diff, GIT_DIFF_FORMAT_PATCH, print_diff_line_cb, out
        );
        if (ret < 0) {
            err = error_from_git(ret);
            goto cleanup;
        }
    }

cleanup:
    if (diff) git_diff_free(diff);
    if (tree2) git_tree_free(tree2);
    if (tree1) git_tree_free(tree1);
    if (commit2) git_commit_free(commit2);
    if (commit1) git_commit_free(commit1);
    if (profile2_name) free(profile2_name);
    if (profile1_name) free(profile1_name);

    return err;
}

/**
 * Workspace diff - Compare current profiles with filesystem using workspace module
 *
 * Optimized implementation using workspace_load() for efficient, pre-analyzed
 * divergence detection. Eliminates N+1 metadata loading and redundant comparisons.
 *
 * Performance: O(P) metadata loads + O(F) file analysis (where P=profiles, F=files)
 *
 * @param repo Repository (must not be NULL)
 * @param profiles Profile list (must not be NULL)
 * @param filter_profiles Profile filter for CLI (can be NULL for no filter)
 * @param file_filter File filter (can be NULL)
 * @param config Configuration (can be NULL)
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *diff_workspace(
    git_repository *repo,
    state_t *state,
    const scope_t *scope,
    const config_t *config,
    content_cache_t *cache,
    const mount_table_t *mounts,
    const cmd_diff_options_t *opts,
    arena_t *arena,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(scope);
    CHECK_NULL(cache);
    CHECK_NULL(mounts);
    CHECK_NULL(opts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    error_t *err = NULL;
    workspace_t *ws = NULL;

    /* Step 1: Load workspace with full file analysis */
    workspace_load_t ws_opts = {
        .analyze_files       = true,  /* File content divergence detection */
        .analyze_orphans     = true,  /* Orphaned state entries */
        .analyze_untracked   = false, /* Not needed for diff (expensive) */
        .analyze_directories = false, /* Not needed for diff */
        .analyze_encryption  = false  /* Not needed for diff */
    };

    err = workspace_load(
        repo, state, scope, config, cache, mounts, &ws_opts, arena, &ws
    );
    if (err) {
        return error_wrap(err, "Failed to load workspace");
    }

    /* Persist deployment-anchor advances from slow-path CMP_EQUAL checks
     * (self-healing optimization). Seeds the fast path for subsequent
     * status/apply calls. Non-fatal on failure — diff still renders correctly,
     * just won't seed the fast path. */
    error_t *flush_err = workspace_flush_anchor_updates(ws);
    if (flush_err) {
        error_free(flush_err);
    }

    /* Step 2: Get pre-analyzed divergence from workspace */
    size_t diverged_count = 0;
    const workspace_item_t *diverged = workspace_get_all_diverged(ws, &diverged_count);

    /* Step 3: Borrow the active state slice for filter validation */
    state_files_t active = workspace_active(ws);

    /* Step 4: Validate file filter paths against the active slice */
    const pathspec_t *file_filter = scope_paths(scope);
    if (file_filter) {
        size_t unmatched = validate_filter_paths(file_filter, active, out);
        if (unmatched > 0) {
            output_hint(out, OUTPUT_NORMAL, "Use 'dotta list <profile>' to see managed files");
            if (unmatched == pathspec_count(file_filter)) {
                /* All filter paths are invalid — nothing to diff */
                goto cleanup;
            }
        }
    }

    /* Step 5: Filter and present diffs based on direction */
    size_t total_diff_count = 0;

    if (opts->direction == DIFF_BOTH) {
        /* Show both directions with headers */
        size_t upstream_count = 0, downstream_count = 0;

        /* Upstream section */
        output_section(out, OUTPUT_NORMAL, "Upstream (repository → filesystem)");
        output_info(out, OUTPUT_NORMAL, "Shows what 'dotta apply' would change\n");

        err = present_diffs_for_direction(
            ws, diverged, diverged_count, cache, repo, DIFF_UPSTREAM,
            scope, opts, out, &upstream_count
        );
        if (err) goto cleanup;

        if (upstream_count == 0 && !opts->name_only) {
            output_info(out, OUTPUT_NORMAL, "No upstream differences\n");
        }

        /* Downstream section */
        output_section(out, OUTPUT_NORMAL, "Downstream (filesystem → repository)");
        output_info(out, OUTPUT_NORMAL, "Shows what 'dotta update' would commit\n");

        err = present_diffs_for_direction(
            ws, diverged, diverged_count, cache, repo, DIFF_DOWNSTREAM,
            scope, opts, out, &downstream_count
        );
        if (err) goto cleanup;

        if (downstream_count == 0 && !opts->name_only) {
            output_info(out, OUTPUT_NORMAL, "No downstream differences\n");
        }

        total_diff_count = upstream_count + downstream_count;

    } else {
        /* Single direction */
        err = present_diffs_for_direction(
            ws, diverged, diverged_count, cache, repo, opts->direction,
            scope, opts, out, &total_diff_count
        );
        if (err) goto cleanup;

        if (total_diff_count == 0 && !opts->name_only) {
            if (opts->direction == DIFF_UPSTREAM) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "No differences (repository and filesystem in sync)"
                );
            } else {
                output_info(out, OUTPUT_NORMAL, "No local changes to commit");
            }
        }
    }

cleanup:
    workspace_free(ws);
    return err;
}

/**
 * Diff command implementation
 */
error_t *cmd_diff(const dotta_ctx_t *ctx, const cmd_diff_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    error_t *err = NULL;
    state_t *state = ctx->state;  /* Borrowed from dispatcher; do not free */
    scope_t *scope = NULL;

    /* Build operation scope
     *
     *   scope_enabled — persistent VWD scope (workspace_load, historical-
     *                   mode branch resolution search).
     *   scope_active  — diff display face.
     *   scope_paths   — CLI positional file filter (threaded into
     *                   historical modes and diff_workspace).
     */
    scope_inputs_t scope_inputs = {
        .profiles      = opts->profiles,
        .profile_count = opts->profile_count,
        .files         = opts->files,
        .file_count    = opts->file_count,
    };
    err = scope_build(
        repo, state, &scope_inputs, config, ctx->mounts, ctx->arena, &scope
    );
    if (err) goto cleanup;

    if (scope_enabled(scope)->count == 0) {
        output_info(out, OUTPUT_NORMAL, "No enabled profiles found");
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta profile enable <name>'");
        goto cleanup;
    }

    /* Route to diff implementation based on mode. All historical and
     * workspace paths share ctx->content_cache so that unchanged OIDs
     * get cache hits regardless of which path decodes them first. */
    switch (opts->mode) {
        case DIFF_COMMIT_TO_COMMIT:
            /* Diff two commits — historical mode, path filter only */
            err = diff_commits(
                repo, opts->commit1, opts->commit2, scope, opts, out
            );
            goto cleanup;

        case DIFF_COMMIT_TO_WORKSPACE:
            /* Commit-to-workspace — historical mode, path filter only */
            err = diff_commit_to_workspace(
                repo, opts->commit1, scope, ctx->mounts, ctx->arena,
                opts, ctx->content_cache, out
            );
            goto cleanup;

        case DIFF_WORKSPACE:
            /* Workspace diff — full scope (profile + path dimensions) */
            err = diff_workspace(
                repo, state, scope, config, ctx->content_cache, ctx->mounts,
                opts, ctx->arena, out
            );
            goto cleanup;
    }

cleanup:
    if (scope) scope_free(scope);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/* Command-local positional classes. Start at 1 to reserve 0 for the
 * engine's "unclassified" sentinel (see args.h:args_class_t). */
enum diff_class { DIFF_CLASS_FILE = 1, DIFF_CLASS_GIT_REF, DIFF_CLASS_PROFILE, };

/**
 * Positional classifier for diff.
 *
 * Three-way split:
 *   - File paths → files[] bucket (workspace file filter).
 *   - Git refs   → git_refs[] bucket (diff mode selector).
 *   - Else       → profiles[] bucket (profile filter).
 *
 * Mode (workspace vs commit-to-workspace vs commit-to-commit) is
 * inferred from the number of git refs in diff_post_parse.
 */
static args_class_t diff_classify(const char *tok) {
    if (str_looks_like_file_path(tok)) return DIFF_CLASS_FILE;
    if (str_looks_like_git_ref(tok))   return DIFF_CLASS_GIT_REF;
    return DIFF_CLASS_PROFILE;
}

/**
 * Infer mode from git_refs count, validate direction flag only fires
 * in workspace mode. Zero-default on `direction` (DIFF_DIR_UNSET) is
 * the signal that no direction flag was seen; it resolves to
 * DIFF_UPSTREAM as the legacy default.
 */
static error_t *diff_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_diff_options_t *o = opts_v;

    switch (o->git_ref_count) {
        case 0:
            o->mode = DIFF_WORKSPACE;
            break;
        case 1:
            o->mode = DIFF_COMMIT_TO_WORKSPACE;
            o->commit1 = o->git_refs[0];
            break;
        case 2:
            o->mode = DIFF_COMMIT_TO_COMMIT;
            o->commit1 = o->git_refs[0];
            o->commit2 = o->git_refs[1];
            break;
        default:
            return ERROR(
                ERR_INVALID_ARG,
                "too many commit references (max 2, got %zu)",
                o->git_ref_count
            );
    }

    bool direction_explicit = (o->direction != DIFF_DIR_UNSET);
    if (direction_explicit && o->mode != DIFF_WORKSPACE) {
        return ERROR(
            ERR_INVALID_ARG,
            "direction flags (--upstream, --downstream, --all) "
            "only apply to workspace diffs"
        );
    }
    if (!direction_explicit) {
        o->direction = DIFF_UPSTREAM;  /* Legacy default. */
    }
    return NULL;
}

static error_t *diff_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_diff(ctx, (const cmd_diff_options_t *) opts_v);
}

static const args_opt_t diff_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_APPEND(
        "p profile",       "<name>",
        cmd_diff_options_t,profiles,           profile_count,
        "Filter diff to profile(s) (repeatable)"
    ),
    /* Three direction flags, each writing its enum into the same
     * int. Default (no flag): direction stays at DIFF_DIR_UNSET (0)
     * which diff_post_parse resolves to DIFF_UPSTREAM. */
    ARGS_FLAG_SET(
        "upstream",
        cmd_diff_options_t,direction,          DIFF_UPSTREAM,
        "Preview apply: -/+ is filesystem/repo (default)"
    ),
    ARGS_FLAG_SET(
        "downstream",
        cmd_diff_options_t,direction,          DIFF_DOWNSTREAM,
        "Preview update: -/+ is repo/filesystem"
    ),
    ARGS_FLAG_SET(
        "a all",
        cmd_diff_options_t,direction,          DIFF_BOTH,
        "Show both directions in labelled sections"
    ),
    ARGS_FLAG(
        "name-only",
        cmd_diff_options_t,name_only,
        "Print changed file names only"
    ),
    /* Classified positionals: files go to files[], git refs to
     * git_refs[], everything else to profiles[]. The classify()
     * function above decides. */
    ARGS_POSITIONAL(
        DIFF_CLASS_FILE,   cmd_diff_options_t, files, file_count
    ),
    ARGS_POSITIONAL(
        DIFF_CLASS_GIT_REF,cmd_diff_options_t, git_refs, git_ref_count
    ),
    ARGS_POSITIONAL(
        DIFF_CLASS_PROFILE,cmd_diff_options_t, profiles, profile_count
    ),
    ARGS_END,
};

const args_command_t spec_diff = {
    .name        = "diff",
    .summary     = "Show differences between profiles and filesystem",
    .usage       = "%s diff [options] [<commit>] [<commit>] [<file>...]",
    .description =
        "Modes:\n"
        "  (no args)             Workspace diff (profile <-> filesystem).\n"
        "  <commit>              Commit -> workspace.\n"
        "  <commit> <commit>     Commit -> commit (must share a profile).\n"
        "  [<file>...]           Restrict any mode to the named files.\n",
    .examples    =
        "  %s diff                          # Preview apply (default)\n"
        "  %s diff --name-only              # Only changed file names\n"
        "  %s diff --downstream             # Preview update\n"
        "  %s diff --all                    # Both directions\n"
        "  %s diff home/.bashrc             # Workspace, single file\n"
        "  %s diff b3e1f9a                  # Commit -> workspace\n"
        "  %s diff HEAD~2 HEAD              # Commit -> commit\n"
        "  %s diff HEAD~1 home/.bashrc      # File at commit vs workspace\n",
    .epilogue    =
        "See also:\n"
        "  %s list <profile> <file>   # Find commit hashes for a file\n"
        "  %s show <commit>           # View commit with diff\n",
    .opts_size   = sizeof(cmd_diff_options_t),
    .opts        = diff_opts,
    .classify    = diff_classify,
    .post_parse  = diff_post_parse,
    .payload     = &dotta_ext_read_crypto,
    .dispatch    = diff_dispatch,
};
