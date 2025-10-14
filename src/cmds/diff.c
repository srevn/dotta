/**
 * diff.c - Show differences between profiles and filesystem
 */

#include "diff.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "core/profiles.h"
#include "infra/compare.h"
#include "utils/config.h"
#include "utils/output.h"

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
 * Check if comparison result should be shown in given direction
 *
 * Upstream (repo → filesystem): Show what apply would change
 * Downstream (filesystem → repo): Show what update would commit
 */
static bool should_show_in_direction(compare_result_t result, diff_direction_t direction) {
    /* Suppress unused parameter warning - direction used for future filtering */
    (void)direction;

    /* All non-equal results are relevant in both directions */
    if (result == CMP_EQUAL) {
        return false;
    }

    /* Both directions show all difference types */
    return true;
}

/**
 * Check if file should be diffed
 */
static bool should_diff_file(
    const char *path,
    compare_result_t result,
    diff_direction_t direction,
    const cmd_diff_options_t *opts
) {
    /* Check file filter first */
    if (!matches_file_filter(path, opts)) {
        return false;
    }

    /* Check if result is relevant for this direction */
    return should_show_in_direction(result, direction);
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
        fprintf(out->stream, "%s\n", entry->filesystem_path);
        return NULL;
    }

    /* Show file header with colors */
    if (output_colors_enabled(out)) {
        char *cyan_path = output_colorize(out, OUTPUT_COLOR_CYAN, entry->storage_path);
        fprintf(out->stream, "%sdiff --dotta a/%s b/%s%s\n",
                output_color_code(out, OUTPUT_COLOR_BOLD),
                entry->storage_path, entry->storage_path,
                output_color_code(out, OUTPUT_COLOR_RESET));
        fprintf(out->stream, "profile: %s%s%s\n",
                output_color_code(out, OUTPUT_COLOR_CYAN),
                entry->source_profile->name,
                output_color_code(out, OUTPUT_COLOR_RESET));
        free(cyan_path);
    } else {
        fprintf(out->stream, "diff --dotta a/%s b/%s\n", entry->storage_path, entry->storage_path);
        fprintf(out->stream, "profile: %s\n", entry->source_profile->name);
    }

    /* Show status with appropriate color and message based on direction */
    const char *status_msg = get_status_message(cmp_result, direction);
    output_color_t status_color = OUTPUT_COLOR_YELLOW;

    if (cmp_result == CMP_MISSING || cmp_result == CMP_TYPE_DIFF) {
        status_color = OUTPUT_COLOR_RED;
    }

    if (output_colors_enabled(out)) {
        fprintf(out->stream, "status: %s%s%s\n",
                output_color_code(out, status_color),
                status_msg,
                output_color_code(out, OUTPUT_COLOR_RESET));
    } else {
        fprintf(out->stream, "status: %s\n", status_msg);
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
    err = compare_generate_diff(repo, entry->entry, entry->filesystem_path, &diff);
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
                if (line[0] == '+' && line_len > 0 && line[1] != '+') {
                    color = output_color_code(out, OUTPUT_COLOR_GREEN);
                } else if (line[0] == '-' && line_len > 0 && line[1] != '-') {
                    color = output_color_code(out, OUTPUT_COLOR_RED);
                } else if (line[0] == '@' && line[1] == '@') {
                    color = output_color_code(out, OUTPUT_COLOR_CYAN);
                }

                if (color) {
                    fprintf(out->stream, "%s%.*s%s\n",
                            color, (int)line_len, line,
                            output_color_code(out, OUTPUT_COLOR_RESET));
                } else {
                    fprintf(out->stream, "%.*s\n", (int)line_len, line);
                }

                line = next_line ? next_line + 1 : NULL;
            }
        } else {
            fprintf(out->stream, "%s\n", diff->diff_text);
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
        if (!should_diff_file(entry->filesystem_path, cmp_result, direction, opts)) {
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
 * Diff command implementation
 */
error_t *cmd_diff(git_repository *repo, const cmd_diff_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    error_t *err = NULL;
    dotta_config_t *config = NULL;
    profile_list_t *profiles = NULL;
    manifest_t *manifest = NULL;

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        config = config_create_default();
    }

    /* Create output context from config */
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* Load profiles with config fallback */
    err = profile_resolve(repo, opts->profiles, opts->profile_count,
                         config, config->strict_mode, &profiles, NULL);

    if (err) {
        config_free(config);
        output_free(out);
        return error_wrap(err, "Failed to load profiles");
    }

    if (profiles->count == 0) {
        profile_list_free(profiles);
        config_free(config);
        output_info(out, "No profiles found");
        output_free(out);
        return NULL;
    }

    /* Build manifest */
    err = profile_build_manifest(repo, profiles, &manifest);
    if (err) {
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return error_wrap(err, "Failed to build manifest");
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
            manifest_free(manifest);
            profile_list_free(profiles);
            config_free(config);
            output_free(out);
            return err;
        }

        if (upstream_count == 0 && !opts->name_only) {
            output_info(out, "No upstream differences\n");
        }

        /* Downstream section */
        fprintf(out->stream, "\n");
        output_section(out, "Downstream (filesystem \u2192 repository)");
        output_info(out, "Shows what 'dotta update' would commit\n");

        err = show_diffs_for_direction(repo, manifest, DIFF_DOWNSTREAM, opts, out, &downstream_count);
        if (err) {
            manifest_free(manifest);
            profile_list_free(profiles);
            config_free(config);
            output_free(out);
            return err;
        }

        if (downstream_count == 0 && !opts->name_only) {
            output_info(out, "No downstream differences\n");
        }

        total_diff_count = upstream_count + downstream_count;

    } else {
        /* Show single direction */
        err = show_diffs_for_direction(repo, manifest, opts->direction, opts, out, &total_diff_count);
        if (err) {
            manifest_free(manifest);
            profile_list_free(profiles);
            config_free(config);
            output_free(out);
            return err;
        }

        if (total_diff_count == 0 && !opts->name_only) {
            if (opts->direction == DIFF_UPSTREAM) {
                output_info(out, "No differences (repository and filesystem in sync)");
            } else {
                output_info(out, "No local changes to commit");
            }
        }
    }

    /* Add trailing newline for UX consistency */
    if (out && out->stream) {
        fprintf(out->stream, "\n");
    }

    /* Cleanup */
    manifest_free(manifest);
    profile_list_free(profiles);
    config_free(config);
    output_free(out);

    return NULL;
}
