/**
 * diff.c - Show differences between profiles and filesystem
 */

#include "diff.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/workspace.h"
#include "crypto/keymanager.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"
#include "utils/timeutil.h"

/**
 * Get basename from path
 */
static const char *get_basename(const char *path) {
    const char *last_slash = strrchr(path, '/');
    return last_slash ? last_slash + 1 : path;
}

/**
 * Check if file should be diffed based on file filter
 */
static bool matches_file_filter(const char *path, const cmd_diff_options_t *opts) {
    /* If no files specified, match all files */
    if (!opts->files || opts->file_count == 0) {
        return true;
    }

    const char *basename = get_basename(path);

    for (size_t i = 0; i < opts->file_count; i++) {
        /* Try exact path match first */
        if (strcmp(path, opts->files[i]) == 0) {
            return true;
        }

        /* Try basename match */
        const char *search_basename = get_basename(opts->files[i]);
        if (strcmp(basename, search_basename) == 0) {
            return true;
        }

        /* Try substring match in full path */
        if (strstr(path, opts->files[i]) != NULL) {
            return true;
        }
    }

    return false;
}

/**
 * Determine if workspace item should be shown for the given direction
 *
 * Direction semantics:
 * - UPSTREAM: Show items where repository would change filesystem
 *   (undeployed files, files where Git differs from filesystem)
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
        /* Show: undeployed, deleted (apply would restore), content/mode differs (Git → filesystem) */
        return (item->state == WORKSPACE_STATE_UNDEPLOYED) ||
               (item->state == WORKSPACE_STATE_DELETED) ||
               (item->state == WORKSPACE_STATE_DEPLOYED &&
                (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)));
    } else {
        /* Downstream: What would update do? */
        /* Show: deleted, content/mode differs (filesystem → Git) */
        return (item->state == WORKSPACE_STATE_DELETED) ||
               (item->state == WORKSPACE_STATE_DEPLOYED &&
                (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)));
    }
}

/**
 * Check if workspace item has divergence that can be diffed
 *
 * Some divergence types don't produce content diffs:
 * - Untracked files (not in Git yet)
 * - Orphaned state entries (removed from Git)
 *
 * @param item Workspace item (must not be NULL)
 * @return true if item can be diffed
 */
static bool has_diffable_divergence(const workspace_item_t *item) {
    /* Can't diff untracked or orphaned items (no Git side to compare) */
    if (item->state == WORKSPACE_STATE_UNTRACKED ||
        item->state == WORKSPACE_STATE_ORPHANED) {
        return false;
    }

    /* Must have actual divergence or be in transition state */
    return item->divergence != DIVERGENCE_NONE ||
           item->state == WORKSPACE_STATE_UNDEPLOYED ||
           item->state == WORKSPACE_STATE_DELETED;
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
        return direction == DIFF_UPSTREAM ?
            "not deployed (would be created by apply)" :
            "new in repository (not deployed yet)";
    }

    if (item->state == WORKSPACE_STATE_DELETED) {
        return direction == DIFF_UPSTREAM ?
            "deleted locally (file missing)" :
            "deleted locally (would be removed by update)";
    }

    /* Handle divergence-based messages for deployed items */
    if (item->divergence & DIVERGENCE_TYPE) {
        return direction == DIFF_UPSTREAM ?
            "type would change on apply" :
            "type changed locally";
    }

    if (item->divergence & DIVERGENCE_CONTENT) {
        return direction == DIFF_UPSTREAM ?
            "would be overwritten by apply" :
            "modified locally (would be committed by update)";
    }

    if (item->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
        return direction == DIFF_UPSTREAM ?
            "mode would change on apply" :
            "mode changed locally";
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
 * @param direction Diff direction
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *show_file_diff_from_workspace(
    const workspace_item_t *item,
    const file_entry_t *entry,
    content_cache_t *cache,
    diff_direction_t direction,
    const cmd_diff_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(item);
    CHECK_NULL(entry);
    CHECK_NULL(cache);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Name-only output */
    if (opts->name_only) {
        output_printf(out, OUTPUT_NORMAL, "%s\n", item->filesystem_path);
        return NULL;
    }

    /* Show file header with colors */
    if (output_colors_enabled(out)) {
        char *cyan_path = output_colorize(out, OUTPUT_COLOR_CYAN, entry->storage_path);
        output_printf(out, OUTPUT_NORMAL, "%sdiff --dotta a/%s b/%s%s\n",
                output_color_code(out, OUTPUT_COLOR_BOLD),
                entry->storage_path, entry->storage_path,
                output_color_code(out, OUTPUT_COLOR_RESET));

        /* Show profile with multi-profile indicator if applicable */
        output_printf(out, OUTPUT_NORMAL, "profile: %s%s%s",
                output_color_code(out, OUTPUT_COLOR_CYAN),
                entry->source_profile->name,
                output_color_code(out, OUTPUT_COLOR_RESET));

        /* Show if file exists in other profiles */
        if (entry->all_profiles && string_array_size(entry->all_profiles) > 0) {
            output_printf(out, OUTPUT_NORMAL, " %s(also in:",
                    output_color_code(out, OUTPUT_COLOR_DIM));
            for (size_t i = 0; i < string_array_size(entry->all_profiles); i++) {
                const char *profile_name = string_array_get(entry->all_profiles, i);
                /* Don't repeat the source profile */
                if (strcmp(profile_name, entry->source_profile->name) != 0) {
                    output_printf(out, OUTPUT_NORMAL, " %s", profile_name);
                }
            }
            output_printf(out, OUTPUT_NORMAL, ")%s",
                    output_color_code(out, OUTPUT_COLOR_RESET));
        }
        output_newline(out);
        free(cyan_path);
    } else {
        output_printf(out, OUTPUT_NORMAL, "diff --dotta a/%s b/%s\n", entry->storage_path, entry->storage_path);
        output_printf(out, OUTPUT_NORMAL, "profile: %s", entry->source_profile->name);

        /* Show if file exists in other profiles */
        if (entry->all_profiles && string_array_size(entry->all_profiles) > 0) {
            output_printf(out, OUTPUT_NORMAL, " (also in:");
            for (size_t i = 0; i < string_array_size(entry->all_profiles); i++) {
                const char *profile_name = string_array_get(entry->all_profiles, i);
                if (strcmp(profile_name, entry->source_profile->name) != 0) {
                    output_printf(out, OUTPUT_NORMAL, " %s", profile_name);
                }
            }
            output_printf(out, OUTPUT_NORMAL, ")");
        }
        output_newline(out);
    }

    /* Get status message from workspace item (no re-analysis needed) */
    const char *status_msg = get_status_message_from_item(item, direction);

    /* Determine status color */
    output_color_t status_color = OUTPUT_COLOR_YELLOW;
    if (item->state == WORKSPACE_STATE_DELETED || item->state == WORKSPACE_STATE_UNDEPLOYED) {
        status_color = OUTPUT_COLOR_RED;
    } else if (item->divergence & DIVERGENCE_TYPE) {
        status_color = OUTPUT_COLOR_RED;
    }

    /* Show status */
    if (output_colors_enabled(out)) {
        output_printf(out, OUTPUT_NORMAL, "status: %s%s%s\n",
                output_color_code(out, status_color),
                status_msg,
                output_color_code(out, OUTPUT_COLOR_RESET));
    } else {
        output_printf(out, OUTPUT_NORMAL, "status: %s\n", status_msg);
    }

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

    /* Get content from cache (borrowed reference - don't free) */
    const buffer_t *content = NULL;
    error_t *err = content_cache_get_from_tree_entry(
        cache, entry->entry, entry->storage_path,
        entry->source_profile->name, entry->encrypted,
        &content
    );
    if (err) {
        return error_wrap(err, "Failed to get content for '%s'", item->filesystem_path);
    }

    /* Generate diff */
    git_filemode_t mode = git_tree_entry_filemode(entry->entry);
    compare_direction_t cmp_dir = (direction == DIFF_UPSTREAM) ?
                                   CMP_DIR_UPSTREAM : CMP_DIR_DOWNSTREAM;

    file_diff_t *diff = NULL;
    err = compare_generate_diff(
        content, item->filesystem_path, entry->storage_path,
        mode, NULL, cmp_dir, &diff
    );

    if (err) {
        return error_wrap(err, "Failed to generate diff for '%s'", item->filesystem_path);
    }

    /* Print diff with colors if enabled */
    if (diff && diff->diff_text) {
        if (output_colors_enabled(out)) {
            /* Colorize diff output line by line */
            char *line = diff->diff_text;
            char *next_line;

            while (line && *line) {
                next_line = strchr(line, '\n');
                size_t line_len = next_line ? (size_t)(next_line - line) : strlen(line);

                /* Determine color based on first character */
                const char *color = NULL;
                if (line_len > 0 && line[0] == '+' && (line_len == 1 || line[1] != '+')) {
                    color = output_color_code(out, OUTPUT_COLOR_GREEN);
                } else if (line_len > 0 && line[0] == '-' && (line_len == 1 || line[1] != '-')) {
                    color = output_color_code(out, OUTPUT_COLOR_RED);
                } else if (line_len > 1 && line[0] == '@' && line[1] == '@') {
                    color = output_color_code(out, OUTPUT_COLOR_CYAN);
                }

                if (color) {
                    output_printf(out, OUTPUT_NORMAL, "%s%.*s%s\n",
                            color, (int)line_len, line,
                            output_color_code(out, OUTPUT_COLOR_RESET));
                } else {
                    output_printf(out, OUTPUT_NORMAL, "%.*s\n", (int)line_len, line);
                }

                line = next_line ? next_line + 1 : NULL;
            }
        } else {
            output_printf(out, OUTPUT_NORMAL, "%s\n", diff->diff_text);
        }
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
 * Key improvement over old show_diffs_for_direction():
 * - No metadata loading (uses cache parameter)
 * - No redundant comparisons (uses workspace divergence)
 * - Single comparison per file
 *
 * @param diverged Array of diverged items from workspace (must not be NULL)
 * @param diverged_count Number of diverged items
 * @param manifest Manifest for tree entry lookup (must not be NULL)
 * @param content_cache Content cache for blob access (must not be NULL)
 * @param direction Diff direction (UPSTREAM or DOWNSTREAM)
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @param diff_count Output: number of diffs shown (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *present_diffs_for_direction(
    const workspace_item_t *diverged,
    size_t diverged_count,
    const manifest_t *manifest,
    content_cache_t *content_cache,
    diff_direction_t direction,
    const cmd_diff_options_t *opts,
    output_ctx_t *out,
    size_t *diff_count
) {
    CHECK_NULL(diverged);
    CHECK_NULL(manifest);
    CHECK_NULL(content_cache);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(diff_count);

    *diff_count = 0;
    error_t *err = NULL;

    for (size_t i = 0; i < diverged_count; i++) {
        const workspace_item_t *item = &diverged[i];

        /* Filter 1: Only process FILES (skip directories) */
        if (item->item_kind != WORKSPACE_ITEM_FILE) {
            continue;
        }

        /* Filter 2: Check file filter (user-specified files) */
        if (!matches_file_filter(item->filesystem_path, opts)) {
            continue;
        }

        /* Filter 3: Direction-based filtering */
        if (!should_show_item_for_direction(item, direction)) {
            continue;
        }

        /* Filter 4: Check if item has diffable divergence */
        if (!has_diffable_divergence(item)) {
            continue;
        }

        /* Lookup manifest entry using O(1) index */
        if (!manifest->index) {
            /* Manifest must have index for O(1) lookup */
            return ERROR(ERR_INTERNAL, "Manifest missing index");
        }

        void *idx_ptr = hashmap_get(manifest->index, item->filesystem_path);
        if (!idx_ptr) {
            /* Item in diverged but not in manifest
             * This can happen for untracked/orphaned items - skip */
            continue;
        }

        size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
        if (idx >= manifest->count) {
            /* Index out of bounds - shouldn't happen */
            continue;
        }

        const file_entry_t *entry = &manifest->entries[idx];

        /* Show the diff (content already analyzed by workspace) */
        err = show_file_diff_from_workspace(
            item, entry, content_cache, direction, opts, out
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
 * @param out_profile_name Found profile name (can be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *resolve_commit_in_profiles(
    git_repository *repo,
    profile_list_t *profiles,
    const char *commit_ref,
    git_oid *out_oid,
    git_commit **out_commit,
    char **out_profile_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(commit_ref);
    CHECK_NULL(out_oid);

    error_t *last_err = NULL;

    /* Search profiles in order */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile_name = profiles->profiles[i].name;

        error_t *err = gitops_resolve_commit_in_branch(
            repo,
            profile_name,
            commit_ref,
            out_oid,
            out_commit
        );

        if (!err) {
            /* Found it! */
            if (out_profile_name) {
                *out_profile_name = strdup(profile_name);
                if (!*out_profile_name) {
                    if (out_commit && *out_commit) {
                        git_commit_free(*out_commit);
                        *out_commit = NULL;
                    }
                    return ERROR(ERR_MEMORY, "Failed to allocate profile name");
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
        error_t *wrapped = error_wrap(last_err,
            "Commit '%s' not found in any enabled profile", commit_ref);
        return wrapped;
    }

    return ERROR(ERR_NOT_FOUND, "Commit '%s' not found in any enabled profile", commit_ref);
}

/**
 * Print commit header with metadata
 */
static void print_commit_header(
    output_ctx_t *out,
    const git_commit *commit,
    const git_oid *commit_oid,
    const char *profile_name
) {
    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), commit_oid);

    const git_signature *author = git_commit_author(commit);
    time_t commit_time = (time_t)author->when.time;

    /* Format absolute time */
    struct tm tm_info;
    localtime_r(&commit_time, &tm_info);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%a %b %d %H:%M:%S %Y", &tm_info);

    /* Format relative time */
    char relative_buf[64];
    format_relative_time(commit_time, relative_buf, sizeof(relative_buf));

    /* Print header with colors */
    if (output_colors_enabled(out)) {
        output_printf(out, OUTPUT_NORMAL, "%scommit %s%s",
                output_color_code(out, OUTPUT_COLOR_YELLOW),
                oid_str,
                output_color_code(out, OUTPUT_COLOR_RESET));

        if (profile_name) {
            output_printf(out, OUTPUT_NORMAL, " %s(%s)%s",
                    output_color_code(out, OUTPUT_COLOR_CYAN),
                    profile_name,
                    output_color_code(out, OUTPUT_COLOR_RESET));
        }
        output_newline(out);

        output_printf(out, OUTPUT_NORMAL, "%sAuthor:%s %s <%s>\n",
                output_color_code(out, OUTPUT_COLOR_BOLD),
                output_color_code(out, OUTPUT_COLOR_RESET),
                author->name, author->email);

        output_printf(out, OUTPUT_NORMAL, "%sDate:%s   %s (%s)\n",
                output_color_code(out, OUTPUT_COLOR_BOLD),
                output_color_code(out, OUTPUT_COLOR_RESET),
                time_buf, relative_buf);
    } else {
        output_printf(out, OUTPUT_NORMAL, "commit %s", oid_str);
        if (profile_name) {
            output_printf(out, OUTPUT_NORMAL, " (%s)", profile_name);
        }
        output_newline(out);

        output_printf(out, OUTPUT_NORMAL, "Author: %s <%s>\n", author->name, author->email);
        output_printf(out, OUTPUT_NORMAL, "Date:   %s (%s)\n", time_buf, relative_buf);
    }

    output_newline(out);

    /* Print commit message with indentation */
    const char *message = git_commit_message(commit);
    char *msg_copy = strdup(message);
    if (msg_copy) {
        char *line = strtok(msg_copy, "\n");
        while (line) {
            output_printf(out, OUTPUT_NORMAL, "    %s\n", line);
            line = strtok(NULL, "\n");
        }
        free(msg_copy);
    }

    output_newline(out);
}

/**
 * Print diff statistics
 */
static error_t *print_diff_stats(
    output_ctx_t *out,
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
    if (output_colors_enabled(out)) {
        output_printf(out, OUTPUT_NORMAL, " %zu file%s changed",
                files_changed, files_changed == 1 ? "" : "s");

        if (insertions > 0) {
            output_printf(out, OUTPUT_NORMAL, ", %s%zu insertion%s(+)%s",
                    output_color_code(out, OUTPUT_COLOR_GREEN),
                    insertions, insertions == 1 ? "" : "s",
                    output_color_code(out, OUTPUT_COLOR_RESET));
        }

        if (deletions > 0) {
            output_printf(out, OUTPUT_NORMAL, ", %s%zu deletion%s(-)%s",
                    output_color_code(out, OUTPUT_COLOR_RED),
                    deletions, deletions == 1 ? "" : "s",
                    output_color_code(out, OUTPUT_COLOR_RESET));
        }
    } else {
        output_printf(out, OUTPUT_NORMAL, " %zu file%s changed",
                files_changed, files_changed == 1 ? "" : "s");

        if (insertions > 0) {
            output_printf(out, OUTPUT_NORMAL, ", %zu insertion%s(+)",
                    insertions, insertions == 1 ? "" : "s");
        }

        if (deletions > 0) {
            output_printf(out, OUTPUT_NORMAL, ", %zu deletion%s(-)",
                    deletions, deletions == 1 ? "" : "s");
        }
    }

    output_newline(out);

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
    output_ctx_t *out = (output_ctx_t *)payload;
    (void)delta;
    (void)hunk;

    const char *color = NULL;

    if (output_colors_enabled(out)) {
        switch (line->origin) {
            case GIT_DIFF_LINE_ADDITION:
                color = output_color_code(out, OUTPUT_COLOR_GREEN);
                break;
            case GIT_DIFF_LINE_DELETION:
                color = output_color_code(out, OUTPUT_COLOR_RED);
                break;
            case GIT_DIFF_LINE_CONTEXT:
                color = NULL;
                break;
            case GIT_DIFF_LINE_FILE_HDR:
            case GIT_DIFF_LINE_HUNK_HDR:
                color = output_color_code(out, OUTPUT_COLOR_CYAN);
                break;
            default:
                color = NULL;
                break;
        }
    }

    /* Print line origin if it's a change line */
    if (line->origin == GIT_DIFF_LINE_ADDITION ||
        line->origin == GIT_DIFF_LINE_DELETION ||
        line->origin == GIT_DIFF_LINE_CONTEXT) {
        if (color) {
            output_printf(out, OUTPUT_NORMAL, "%s%c%.*s%s",
                    color,
                    line->origin,
                    (int)line->content_len, line->content,
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_printf(out, OUTPUT_NORMAL, "%c%.*s",
                    line->origin,
                    (int)line->content_len, line->content);
        }
    } else {
        /* File/hunk headers - print as-is */
        if (color) {
            output_printf(out, OUTPUT_NORMAL, "%s%.*s%s",
                    color,
                    (int)line->content_len, line->content,
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_printf(out, OUTPUT_NORMAL, "%.*s",
                    (int)line->content_len, line->content);
        }
    }

    /* Add newline if not present */
    if (line->content_len == 0 || line->content[line->content_len - 1] != '\n') {
        output_newline(out);
    }

    return 0;
}

/**
 * Compare historical manifest to filesystem and show diffs
 *
 * Generic comparison function for commit-to-workspace diffs.
 * Takes a historical manifest (from a specific commit) and compares
 * each file against the current filesystem state.
 *
 * @param repo Repository (must not be NULL)
 * @param manifest Historical manifest to compare (must not be NULL)
 * @param metadata Metadata from historical commit (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @param diff_count Output: number of diffs shown (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *compare_manifest_to_filesystem(
    git_repository *repo,
    const manifest_t *manifest,
    const metadata_t *metadata,
    const char *profile_name,
    const cmd_diff_options_t *opts,
    output_ctx_t *out,
    size_t *diff_count
) {
    CHECK_NULL(repo);
    CHECK_NULL(manifest);
    CHECK_NULL(metadata);
    CHECK_NULL(profile_name);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(diff_count);

    *diff_count = 0;
    error_t *err = NULL;

    /* Create content cache for efficient blob access */
    keymanager_t *km = keymanager_get_global(NULL);
    content_cache_t *cache = content_cache_create(repo, km);
    if (!cache) {
        return ERROR(ERR_MEMORY, "Failed to create content cache");
    }

    /* Iterate through all files in the historical manifest */
    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];
        const char *fs_path = entry->filesystem_path;
        const char *storage_path = entry->storage_path;

        /* Check file filter */
        if (!matches_file_filter(fs_path, opts)) {
            continue;
        }

        /* Name-only output */
        if (opts->name_only) {
            /* Check if file exists and differs */
            struct stat st;
            bool exists = (stat(fs_path, &st) == 0);

            if (!exists) {
                output_printf(out, OUTPUT_NORMAL, "%s\n", fs_path);
                (*diff_count)++;
                continue;
            }

            /* Get content from historical commit (cached) */
            bool encrypted = metadata_get_file_encrypted(metadata, storage_path);
            const buffer_t *hist_content = NULL;
            err = content_cache_get_from_tree_entry(
                cache, entry->entry, storage_path,
                profile_name, encrypted, &hist_content
            );
            if (err) {
                content_cache_free(cache);
                return error_wrap(err, "Failed to get historical content for '%s'", fs_path);
            }

            /* Compare with filesystem */
            compare_result_t result;
            git_filemode_t mode = git_tree_entry_filemode(entry->entry);
            err = compare_buffer_to_disk(hist_content, fs_path, mode, NULL, &result, NULL);
            if (err) {
                content_cache_free(cache);
                return error_wrap(err, "Failed to compare '%s'", fs_path);
            }

            if (result != CMP_EQUAL) {
                output_printf(out, OUTPUT_NORMAL, "%s\n", fs_path);
                (*diff_count)++;
            }
            continue;
        }

        /* Full diff output */
        /* Get content from historical commit (cached) */
        bool encrypted = metadata_get_file_encrypted(metadata, storage_path);
        const buffer_t *hist_content = NULL;
        err = content_cache_get_from_tree_entry(
            cache, entry->entry, storage_path,
            profile_name, encrypted, &hist_content
        );
        if (err) {
            content_cache_free(cache);
            return error_wrap(err, "Failed to get historical content for '%s'", fs_path);
        }

        /* Compare with filesystem */
        compare_result_t result;
        git_filemode_t mode = git_tree_entry_filemode(entry->entry);
        err = compare_buffer_to_disk(hist_content, fs_path, mode, NULL, &result, NULL);
        if (err) {
            content_cache_free(cache);
            return error_wrap(err, "Failed to compare '%s'", fs_path);
        }

        /* Skip if identical */
        if (result == CMP_EQUAL) {
            continue;
        }

        /* Show file header */
        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "%sdiff --dotta a/%s b/%s%s\n",
                    output_color_code(out, OUTPUT_COLOR_BOLD),
                    storage_path, storage_path,
                    output_color_code(out, OUTPUT_COLOR_RESET));

            output_printf(out, OUTPUT_NORMAL, "profile: %s%s%s\n",
                    output_color_code(out, OUTPUT_COLOR_CYAN),
                    profile_name,
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_printf(out, OUTPUT_NORMAL, "diff --dotta a/%s b/%s\n", storage_path, storage_path);
            output_printf(out, OUTPUT_NORMAL, "profile: %s\n", profile_name);
        }

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

        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "status: %s%s%s\n",
                    output_color_code(out, status_color),
                    status_msg,
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_printf(out, OUTPUT_NORMAL, "status: %s\n", status_msg);
        }

        /* For missing files or type changes, no content diff */
        if (result == CMP_MISSING || result == CMP_TYPE_DIFF) {
            (*diff_count)++;
            continue;
        }

        /* Generate and show content diff (mode already declared above) */
        file_diff_t *diff = NULL;

        err = compare_generate_diff(
            hist_content, fs_path, storage_path,
            mode, NULL, CMP_DIR_DOWNSTREAM, &diff
        );
        if (err) {
            content_cache_free(cache);
            return error_wrap(err, "Failed to generate diff for '%s'", fs_path);
        }

        /* Print diff with colors */
        if (diff && diff->diff_text) {
            if (output_colors_enabled(out)) {
                /* Colorize diff output line by line */
                char *line = diff->diff_text;
                char *next_line;

                while (line && *line) {
                    next_line = strchr(line, '\n');
                    size_t line_len = next_line ? (size_t)(next_line - line) : strlen(line);

                    const char *color = NULL;
                    if (line_len > 0 && line[0] == '+' && (line_len == 1 || line[1] != '+')) {
                        color = output_color_code(out, OUTPUT_COLOR_GREEN);
                    } else if (line_len > 0 && line[0] == '-' && (line_len == 1 || line[1] != '-')) {
                        color = output_color_code(out, OUTPUT_COLOR_RED);
                    } else if (line_len > 1 && line[0] == '@' && line[1] == '@') {
                        color = output_color_code(out, OUTPUT_COLOR_CYAN);
                    }

                    if (color) {
                        output_printf(out, OUTPUT_NORMAL, "%s%.*s%s\n",
                                color, (int)line_len, line,
                                output_color_code(out, OUTPUT_COLOR_RESET));
                    } else {
                        output_printf(out, OUTPUT_NORMAL, "%.*s\n", (int)line_len, line);
                    }

                    line = next_line ? next_line + 1 : NULL;
                }
            } else {
                output_printf(out, OUTPUT_NORMAL, "%s\n", diff->diff_text);
            }
        }

        compare_free_diff(diff);
        (*diff_count)++;
    }

    content_cache_free(cache);
    return NULL;
}

/**
 * Diff commit to workspace - Compare historical commit with filesystem
 *
 * This is the NEW, CORRECT implementation that actually compares the
 * specified commit (not HEAD!) against the current filesystem.
 *
 * Fixes critical bug: Old implementation compared HEAD instead of the
 * user-specified commit, making the feature completely broken.
 *
 * CURRENT LIMITATION: Single-profile comparison only.
 * When multiple profiles are enabled, this function compares only the
 * profile that contains the specified commit (first match in precedence order)
 *
 * @param repo Repository (must not be NULL)
 * @param commit_ref Commit reference to compare (must not be NULL)
 * @param profiles Profile list (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *diff_commit_to_workspace_new(
    git_repository *repo,
    const char *commit_ref,
    profile_list_t *profiles,
    const cmd_diff_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(commit_ref);
    CHECK_NULL(profiles);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    error_t *err = NULL;
    git_oid commit_oid;
    git_commit *commit = NULL;
    char *profile_name = NULL;
    git_tree *tree = NULL;
    manifest_t *manifest = NULL;
    metadata_t *metadata = NULL;

    /* Step 1: Resolve commit to find which profile contains it */
    err = resolve_commit_in_profiles(repo, profiles, commit_ref,
                                     &commit_oid, &commit, &profile_name);
    if (err) {
        goto cleanup;
    }

    /* Step 2: Print commit header */
    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), &commit_oid);

    if (output_colors_enabled(out)) {
        output_printf(out, OUTPUT_NORMAL, "%sdiff --dotta %s..workspace%s\n\n",
                output_color_code(out, OUTPUT_COLOR_BOLD),
                oid_str,
                output_color_code(out, OUTPUT_COLOR_RESET));
    } else {
        output_printf(out, OUTPUT_NORMAL, "diff --dotta %s..workspace\n\n", oid_str);
    }

    print_commit_header(out, commit, &commit_oid, profile_name);

    /* Step 3: Get tree from THE HISTORICAL COMMIT (not HEAD!) */
    int git_err = git_commit_tree(&tree, commit);
    if (git_err < 0) {
        err = error_from_git(git_err);
        err = error_wrap(err, "Failed to get tree from commit");
        goto cleanup;
    }

    /* Step 4: Load metadata from that historical tree */
    err = metadata_load_from_tree(repo, tree, profile_name, &metadata);
    if (err) {
        /* Graceful: if no metadata in commit, use empty metadata */
        error_free(err);
        err = metadata_create_empty(&metadata);
        if (err) {
            goto cleanup;
        }
    }

    /* Step 5: Build manifest from historical tree
     * We need to traverse the tree and create file entries */
    err = profile_build_manifest_from_tree(repo, tree, profile_name, &manifest);
    if (err) {
        err = error_wrap(err, "Failed to build manifest from commit");
        goto cleanup;
    }

    /* Step 6: Compare historical manifest against current filesystem */
    size_t diff_count = 0;
    err = compare_manifest_to_filesystem(
        repo, manifest, metadata, profile_name,
        opts, out, &diff_count
    );
    if (err) {
        goto cleanup;
    }

    if (diff_count == 0 && !opts->name_only) {
        output_info(out, "No differences between commit and workspace\n");
    }

cleanup:
    metadata_free(metadata);
    manifest_free(manifest);
    git_tree_free(tree);
    git_commit_free(commit);
    free(profile_name);

    return err;
}

/**
 * Diff two commits
 */
static error_t *diff_commits(
    git_repository *repo,
    const char *commit1_ref,
    const char *commit2_ref,
    profile_list_t *profiles,
    const cmd_diff_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(commit1_ref);
    CHECK_NULL(commit2_ref);
    CHECK_NULL(profiles);
    CHECK_NULL(opts);
    CHECK_NULL(out);

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
    err = resolve_commit_in_profiles(repo, profiles, commit1_ref,
                                     &commit1_oid, &commit1, &profile1_name);
    if (err) {
        goto cleanup;
    }

    /* Resolve second commit */
    err = resolve_commit_in_profiles(repo, profiles, commit2_ref,
                                     &commit2_oid, &commit2, &profile2_name);
    if (err) {
        goto cleanup;
    }

    /* Print diff range header */
    char oid1_str[8], oid2_str[8];
    git_oid_tostr(oid1_str, sizeof(oid1_str), &commit1_oid);
    git_oid_tostr(oid2_str, sizeof(oid2_str), &commit2_oid);

    if (output_colors_enabled(out)) {
        output_printf(out, OUTPUT_NORMAL, "%sdiff --dotta %s..%s%s\n\n",
                output_color_code(out, OUTPUT_COLOR_BOLD),
                oid1_str, oid2_str,
                output_color_code(out, OUTPUT_COLOR_RESET));
    } else {
        output_printf(out, OUTPUT_NORMAL, "diff --dotta %s..%s\n\n", oid1_str, oid2_str);
    }

    /* Print second commit header (the "new" one) */
    print_commit_header(out, commit2, &commit2_oid, profile2_name);

    /* Get trees from commits */
    err = gitops_get_tree_from_commit(repo, &commit1_oid, &tree1);
    if (err) {
        err = error_wrap(err, "Failed to get tree from commit %s", oid1_str);
        goto cleanup;
    }

    err = gitops_get_tree_from_commit(repo, &commit2_oid, &tree2);
    if (err) {
        err = error_wrap(err, "Failed to get tree from commit %s", oid2_str);
        goto cleanup;
    }

    /* Generate diff */
    err = gitops_diff_trees(repo, tree1, tree2, &diff);
    if (err) {
        err = error_wrap(err, "Failed to generate diff");
        goto cleanup;
    }

    /* Print statistics */
    err = print_diff_stats(out, diff);
    if (err) {
        goto cleanup;
    }

    output_newline(out);

    /* Print diff content if not name-only */
    if (!opts->name_only) {
        int ret = git_diff_print(diff, GIT_DIFF_FORMAT_PATCH, print_diff_line_cb, out);
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
    free(profile2_name);
    free(profile1_name);

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
 * @param config Configuration (can be NULL)
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *diff_workspace(
    git_repository *repo,
    profile_list_t *profiles,
    const dotta_config_t *config,
    const cmd_diff_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    error_t *err = NULL;
    workspace_t *ws = NULL;
    content_cache_t *cache = NULL;

    /* Step 1: Load workspace with full file analysis */
    workspace_load_t ws_opts = {
        .analyze_files = true,        /* File content divergence detection */
        .analyze_orphans = true,      /* Orphaned state entries */
        .analyze_untracked = false,   /* Not needed for diff (expensive) */
        .analyze_directories = false, /* Not needed for diff */
        .analyze_encryption = false   /* Not needed for diff */
    };

    /* Pass NULL for state - diff is read-only, workspace allocates its own state */
    err = workspace_load(repo, NULL, profiles, config, &ws_opts, &ws);
    if (err) {
        return error_wrap(err, "Failed to load workspace");
    }

    /* Step 2: Get pre-analyzed divergence from workspace */
    size_t diverged_count = 0;
    const workspace_item_t *diverged = workspace_get_all_diverged(ws, &diverged_count);

    /* Step 3: Get cached resources from workspace */
    const manifest_t *manifest = workspace_get_manifest(ws);
    keymanager_t *km = workspace_get_keymanager(ws);

    /* Step 4: Create content cache for diff generation
     * Note: Could use workspace_get_content_cache(ws) if we want to reuse
     * the workspace's cache, but creating a fresh one is also fine */
    cache = content_cache_create(repo, km);
    if (!cache) {
        err = ERROR(ERR_MEMORY, "Failed to create content cache");
        goto cleanup;
    }

    /* Step 5: Filter and present diffs based on direction */
    size_t total_diff_count = 0;

    if (opts->direction == DIFF_BOTH) {
        /* Show both directions with headers */
        size_t upstream_count = 0, downstream_count = 0;

        /* Upstream section */
        output_section(out, "Upstream (repository → filesystem)");
        output_info(out, "Shows what 'dotta apply' would change\n");

        err = present_diffs_for_direction(
            diverged, diverged_count,
            manifest, cache,
            DIFF_UPSTREAM, opts, out,
            &upstream_count
        );
        if (err) goto cleanup;

        if (upstream_count == 0 && !opts->name_only) {
            output_info(out, "No upstream differences\n");
        }

        /* Downstream section */
        output_newline(out);
        output_section(out, "Downstream (filesystem → repository)");
        output_info(out, "Shows what 'dotta update' would commit\n");

        err = present_diffs_for_direction(
            diverged, diverged_count,
            manifest, cache,
            DIFF_DOWNSTREAM, opts, out,
            &downstream_count
        );
        if (err) goto cleanup;

        if (downstream_count == 0 && !opts->name_only) {
            output_info(out, "No downstream differences\n");
        }

        total_diff_count = upstream_count + downstream_count;

    } else {
        /* Single direction */
        err = present_diffs_for_direction(
            diverged, diverged_count,
            manifest, cache,
            opts->direction, opts, out,
            &total_diff_count
        );
        if (err) goto cleanup;

        if (total_diff_count == 0 && !opts->name_only) {
            if (opts->direction == DIFF_UPSTREAM) {
                output_info(out, "No differences (repository and filesystem in sync)");
            } else {
                output_info(out, "No local changes to commit");
            }
        }
    }

cleanup:
    content_cache_free(cache);
    workspace_free(ws);
    return err;
}

/**
 * Diff command implementation
 */
error_t *cmd_diff(git_repository *repo, const cmd_diff_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    error_t *err = NULL;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;
    profile_list_t *workspace_profiles = NULL;
    profile_list_t *diff_profiles = NULL;

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        error_free(err);
        err = NULL;
        config = config_create_default();
    }

    /* Create output context from config */
    out = output_create_from_config(config);
    if (!out) {
        err = ERROR(ERR_MEMORY, "Failed to create output context");
        goto cleanup;
    }

    /* Load profiles
     *
     * Separate workspace scope (persistent) from diff filter (temporary):
     *   - workspace_profiles: Persistent enabled profiles (VWD scope)
     *   - diff_profiles: CLI filter or shared pointer
     *
     * Workspace operations use persistent profiles. Diff operations filter
     * by CLI profiles when specified.
     */
    err = profile_resolve_for_workspace(repo, config->strict_mode, &workspace_profiles);
    if (err) {
        err = error_wrap(err, "Failed to resolve enabled profiles");
        goto cleanup;
    }

    if (workspace_profiles->count == 0) {
        output_info(out, "No enabled profiles found");
        output_hint(out, "Run 'dotta profile enable <name>' to enable profiles");
        goto cleanup;
    }

    /* Load diff profiles (CLI filter or shared pointer) */
    if (opts->profiles && opts->profile_count > 0) {
        err = profile_resolve_for_operations(repo, opts->profiles, opts->profile_count,
                                            config->strict_mode, &diff_profiles);
        if (err) {
            err = error_wrap(err, "Failed to resolve diff profiles");
            goto cleanup;
        }

        err = profile_validate_filter(workspace_profiles, diff_profiles);
        if (err) {
            goto cleanup;
        }
    } else {
        diff_profiles = workspace_profiles;
    }

    /* Route to diff implementation based on mode */
    switch (opts->mode) {
        case DIFF_COMMIT_TO_COMMIT:
            /* Diff two commits */
            err = diff_commits(repo, opts->commit1, opts->commit2, diff_profiles, opts, out);
            goto cleanup;

        case DIFF_COMMIT_TO_WORKSPACE:
            /* Use commit-to-workspace diff */
            err = diff_commit_to_workspace_new(repo, opts->commit1, diff_profiles, opts, out);
            goto cleanup;

        case DIFF_WORKSPACE:
            /* Workspace diff uses workspace_profiles for accurate analysis,
             * diff_profiles for filtering output */
            err = diff_workspace(repo, workspace_profiles, config, opts, out);
            goto cleanup;
    }

cleanup:
    if (diff_profiles && diff_profiles != workspace_profiles) {
        profile_list_free(diff_profiles);
    }
    if (workspace_profiles) profile_list_free(workspace_profiles);
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}
