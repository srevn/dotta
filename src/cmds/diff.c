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
#include "core/profiles.h"
#include "infra/compare.h"
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
 * Check if comparison result represents a difference
 *
 * All non-equal results are shown to the user. Direction affects HOW we
 * describe the difference (via get_status_message()), not WHETHER we show it.
 */
static bool is_result_different(compare_result_t result) {
    return result != CMP_EQUAL;
}

/**
 * Check if file should be diffed
 */
static bool should_diff_file(
    const char *path,
    compare_result_t result,
    const cmd_diff_options_t *opts
) {
    /* Check file filter first */
    if (!matches_file_filter(path, opts)) {
        return false;
    }

    /* Check if result represents a difference */
    return is_result_different(result);
}

/**
 * Get status message based on comparison result and direction
 */
static const char *get_status_message(compare_result_t result, diff_direction_t direction) {
    if (direction == DIFF_UPSTREAM) {
        /* Upstream: repo → filesystem (what apply would do) */
        switch (result) {
            case CMP_MISSING:    return "not deployed (would be created by apply)";
            case CMP_DIFFERENT:  return "would be overwritten by apply";
            case CMP_MODE_DIFF:  return "mode would change on apply";
            case CMP_TYPE_DIFF:  return "type would change on apply";
            default:             return "unknown";
        }
    } else {
        /* Downstream: filesystem → repo (what update would do) */
        switch (result) {
            case CMP_MISSING:    return "deleted locally (would be removed by update)";
            case CMP_DIFFERENT:  return "modified locally (would be committed by update)";
            case CMP_MODE_DIFF:  return "mode changed locally";
            case CMP_TYPE_DIFF:  return "type changed locally";
            default:             return "unknown";
        }
    }
}

/**
 * Show diff for a file with color support
 */
static error_t *show_file_diff(
    git_repository *repo,
    const file_entry_t *entry,
    diff_direction_t direction,
    const cmd_diff_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(entry);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Compare with disk */
    compare_result_t cmp_result;
    error_t *err = compare_tree_entry_to_disk(
        repo,
        entry->entry,
        entry->filesystem_path,
        &cmp_result
    );

    if (err) {
        return error_wrap(err, "Failed to compare '%s'", entry->filesystem_path);
    }

    /* Only show if different */
    if (cmp_result == CMP_EQUAL) {
        return NULL;
    }

    if (opts->name_only) {
        output_printf(out, OUTPUT_NORMAL, "%s\n", entry->filesystem_path);
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

    /* Show status with appropriate color and message based on direction */
    const char *status_msg = get_status_message(cmp_result, direction);
    output_color_t status_color = OUTPUT_COLOR_YELLOW;

    if (cmp_result == CMP_MISSING || cmp_result == CMP_TYPE_DIFF) {
        status_color = OUTPUT_COLOR_RED;
    }

    if (output_colors_enabled(out)) {
        output_printf(out, OUTPUT_NORMAL, "status: %s%s%s\n",
                output_color_code(out, status_color),
                status_msg,
                output_color_code(out, OUTPUT_COLOR_RESET));
    } else {
        output_printf(out, OUTPUT_NORMAL, "status: %s\n", status_msg);
    }

    /* For missing files, no diff to show */
    if (cmp_result == CMP_MISSING || cmp_result == CMP_TYPE_DIFF) {
        return NULL;
    }

    /* For mode-only changes, no content diff */
    if (cmp_result == CMP_MODE_DIFF) {
        return NULL;
    }

    /* Generate actual diff */
    file_diff_t *diff = NULL;
    /* Convert diff direction to compare direction */
    compare_direction_t cmp_dir = (direction == DIFF_UPSTREAM) ?
                                   CMP_DIR_UPSTREAM : CMP_DIR_DOWNSTREAM;
    err = compare_generate_diff(repo, entry->entry, entry->filesystem_path, cmp_dir, &diff);
    if (err) {
        return error_wrap(err, "Failed to generate diff for '%s'", entry->filesystem_path);
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
 * Show diffs for a specific direction
 */
static error_t *show_diffs_for_direction(
    git_repository *repo,
    manifest_t *manifest,
    diff_direction_t direction,
    const cmd_diff_options_t *opts,
    output_ctx_t *out,
    size_t *diff_count
) {
    CHECK_NULL(repo);
    CHECK_NULL(manifest);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(diff_count);

    error_t *err = NULL;
    *diff_count = 0;

    for (size_t i = 0; i < manifest->count; i++) {
        const file_entry_t *entry = &manifest->entries[i];

        /* First compare to get result */
        compare_result_t cmp_result;
        err = compare_tree_entry_to_disk(
            repo,
            entry->entry,
            entry->filesystem_path,
            &cmp_result
        );

        if (err) {
            return error_wrap(err, "Failed to compare '%s'", entry->filesystem_path);
        }

        /* Check if we should diff this file */
        if (!should_diff_file(entry->filesystem_path, cmp_result, opts)) {
            continue;
        }

        err = show_file_diff(repo, entry, direction, opts, out);
        if (err) {
            return err;
        }

        (*diff_count)++;
    }

    return NULL;
}

/**
 * Resolve commit reference across selected profiles
 *
 * Searches for the commit in selected profiles in order.
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
            "Commit '%s' not found in any selected profile", commit_ref);
        return wrapped;
    }

    return ERROR(ERR_NOT_FOUND, "Commit '%s' not found in any selected profile", commit_ref);
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
 * Diff commit to workspace
 */
static error_t *diff_commit_to_workspace(
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
    manifest_t *manifest = NULL;

    /* Resolve commit */
    err = resolve_commit_in_profiles(repo, profiles, commit_ref,
                                     &commit_oid, &commit, &profile_name);
    if (err) {
        goto cleanup;
    }

    /* Print commit header */
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

    /* Build manifest from current profiles */
    err = profile_build_manifest(repo, profiles, &manifest);
    if (err) {
        err = error_wrap(err, "Failed to build manifest");
        goto cleanup;
    }

    /* Show workspace diffs */
    size_t diff_count = 0;
    err = show_diffs_for_direction(repo, manifest, DIFF_BOTH, opts, out, &diff_count);
    if (err) {
        goto cleanup;
    }

    if (diff_count == 0 && !opts->name_only) {
        output_info(out, "No differences between commit and workspace\n");
    }

cleanup:
    if (manifest) manifest_free(manifest);
    if (commit) git_commit_free(commit);
    free(profile_name);

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
    profile_list_t *profiles = NULL;
    manifest_t *manifest = NULL;

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

    /* Load profiles */
    err = profile_resolve(repo, opts->profiles, opts->profile_count,
                         config->strict_mode, &profiles, NULL);
    if (err) {
        err = error_wrap(err, "Failed to load profiles");
        goto cleanup;
    }

    if (profiles->count == 0) {
        output_info(out, "No profiles found");
        goto cleanup;
    }

    /* Route based on mode */
    switch (opts->mode) {
        case DIFF_COMMIT_TO_COMMIT:
            /* Diff two commits */
            err = diff_commits(repo, opts->commit1, opts->commit2, profiles, opts, out);
            goto cleanup;

        case DIFF_COMMIT_TO_WORKSPACE:
            /* Diff commit to workspace */
            err = diff_commit_to_workspace(repo, opts->commit1, profiles, opts, out);
            goto cleanup;

        case DIFF_WORKSPACE:
            /* Fall through to workspace diff below */
            break;
    }

    /* Workspace diff */
    /* Build manifest */
    err = profile_build_manifest(repo, profiles, &manifest);
    if (err) {
        err = error_wrap(err, "Failed to build manifest");
        goto cleanup;
    }

    /* Show diffs based on direction */
    size_t total_diff_count = 0;

    if (opts->direction == DIFF_BOTH) {
        /* Show both directions with headers */
        size_t upstream_count = 0, downstream_count = 0;

        /* Upstream section */
        output_section(out, "Upstream (repository \u2192 filesystem)");
        output_info(out, "Shows what 'dotta apply' would change\n");

        err = show_diffs_for_direction(repo, manifest, DIFF_UPSTREAM, opts, out, &upstream_count);
        if (err) {
            goto cleanup;
        }

        if (upstream_count == 0 && !opts->name_only) {
            output_info(out, "No upstream differences\n");
        }

        /* Downstream section */
        output_newline(out);
        output_section(out, "Downstream (filesystem \u2192 repository)");
        output_info(out, "Shows what 'dotta update' would commit\n");

        err = show_diffs_for_direction(repo, manifest, DIFF_DOWNSTREAM, opts, out, &downstream_count);
        if (err) {
            goto cleanup;
        }

        if (downstream_count == 0 && !opts->name_only) {
            output_info(out, "No downstream differences\n");
        }

        total_diff_count = upstream_count + downstream_count;

    } else {
        /* Show single direction */
        err = show_diffs_for_direction(repo, manifest, opts->direction, opts, out, &total_diff_count);
        if (err) {
            goto cleanup;
        }

        if (total_diff_count == 0 && !opts->name_only) {
            if (opts->direction == DIFF_UPSTREAM) {
                output_info(out, "No differences (repository and filesystem in sync)");
            } else {
                output_info(out, "No local changes to commit");
            }
        }
    }

cleanup:
    if (manifest) manifest_free(manifest);
    if (profiles) profile_list_free(profiles);
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}
