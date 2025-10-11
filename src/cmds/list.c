/**
 * list.c - List profiles, files, and commit history
 */

#include "list.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/profiles.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"
#include "utils/repo.h"
#include "utils/timeutil.h"
#include "utils/upstream.h"

/**
 * Format upstream state for display
 */
static void format_upstream_state(
    output_ctx_t *out,
    const upstream_info_t *info,
    char *buffer,
    size_t buffer_size
) {
    if (!info || !buffer) {
        return;
    }

    const char *symbol = upstream_state_symbol(info->state);
    output_color_t color;

    switch (info->state) {
        case UPSTREAM_UP_TO_DATE:
            color = OUTPUT_COLOR_GREEN;
            snprintf(buffer, buffer_size, "[%s]", symbol);
            break;
        case UPSTREAM_LOCAL_AHEAD:
            color = OUTPUT_COLOR_YELLOW;
            snprintf(buffer, buffer_size, "[%s%zu]", symbol, info->ahead);
            break;
        case UPSTREAM_REMOTE_AHEAD:
            color = OUTPUT_COLOR_YELLOW;
            snprintf(buffer, buffer_size, "[%s%zu]", symbol, info->behind);
            break;
        case UPSTREAM_DIVERGED:
            color = OUTPUT_COLOR_RED;
            snprintf(buffer, buffer_size, "[%s]", symbol);
            break;
        case UPSTREAM_NO_REMOTE:
            color = OUTPUT_COLOR_CYAN;
            snprintf(buffer, buffer_size, "[%s]", symbol);
            break;
        case UPSTREAM_UNKNOWN:
        default:
            color = OUTPUT_COLOR_DIM;
            snprintf(buffer, buffer_size, "[%s]", symbol);
            break;
    }

    if (output_colors_enabled(out)) {
        char temp[256];
        snprintf(temp, sizeof(temp), "%s%s%s",
                output_color_code(out, color),
                buffer,
                output_color_code(out, OUTPUT_COLOR_RESET));
        snprintf(buffer, buffer_size, "%s", temp);
    }
}

/**
 * List all profiles with color support
 */
static dotta_error_t *list_profiles(
    git_repository *repo,
    const cmd_list_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Get all branches */
    string_array_t *branches = NULL;
    dotta_error_t *err = gitops_list_branches(repo, &branches);
    if (err) {
        return error_wrap(err, "Failed to list branches");
    }

    if (string_array_size(branches) == 0) {
        string_array_free(branches);
        output_info(out, "No profiles found");
        return NULL;
    }

    /* Auto-detect profiles */
    profile_list_t *auto_profiles = NULL;
    err = profile_detect_auto(repo, &auto_profiles);
    bool has_auto = (err == NULL && auto_profiles && auto_profiles->count > 0);

    /* Detect remote if --remote flag is set */
    char *remote_name = NULL;
    bool show_remote = false;
    if (opts->remote) {
        err = upstream_detect_remote(repo, &remote_name);
        if (err) {
            /* Non-fatal: just warn and continue without remote info */
            output_warning(out, "Could not detect remote: %s", error_message(err));
            error_free(err);
            err = NULL;
        } else {
            show_remote = true;
        }
    }

    /* Print profiles */
    output_section(out, "Available profiles");

    for (size_t i = 0; i < string_array_size(branches); i++) {
        const char *name = string_array_get(branches, i);

        /* Skip dotta-worktree branch */
        if (strcmp(name, "dotta-worktree") == 0) {
            continue;
        }

        bool is_auto = false;
        if (has_auto) {
            for (size_t j = 0; j < auto_profiles->count; j++) {
                if (strcmp(auto_profiles->profiles[j].name, name) == 0) {
                    is_auto = true;
                    break;
                }
            }
        }

        /* Get upstream state if requested */
        char upstream_str[64] = "";
        if (show_remote) {
            upstream_info_t *info = NULL;
            dotta_error_t *upstream_err = upstream_analyze_profile(repo, remote_name, name, &info);
            if (!upstream_err && info) {
                format_upstream_state(out, info, upstream_str, sizeof(upstream_str));
                upstream_info_free(info);
            } else {
                error_free(upstream_err);
            }
        }

        if (is_auto) {
            if (output_colors_enabled(out)) {
                fprintf(out->stream, "  %s*%s %s%s%s %s\n",
                        output_color_code(out, OUTPUT_COLOR_GREEN),
                        output_color_code(out, OUTPUT_COLOR_RESET),
                        output_color_code(out, OUTPUT_COLOR_CYAN),
                        name,
                        output_color_code(out, OUTPUT_COLOR_RESET),
                        upstream_str);
            } else {
                fprintf(out->stream, "  * %s %s\n", name, upstream_str);
            }
        } else {
            if (output_colors_enabled(out)) {
                fprintf(out->stream, "    %s%s%s %s\n",
                        output_color_code(out, OUTPUT_COLOR_CYAN),
                        name,
                        output_color_code(out, OUTPUT_COLOR_RESET),
                        upstream_str);
            } else {
                fprintf(out->stream, "    %s %s\n", name, upstream_str);
            }
        }

        /* Show file count and last commit if verbose */
        if (opts->verbose) {
            profile_t *profile = NULL;
            err = profile_load(repo, name, &profile);
            if (err) {
                error_free(err);
                continue;
            }

            string_array_t *files = NULL;
            err = profile_list_files(repo, profile, &files);
            if (err) {
                profile_free(profile);
                error_free(err);
                continue;
            }

            fprintf(out->stream, "      %zu file%s",
                   string_array_size(files),
                   string_array_size(files) == 1 ? "" : "s");

            /* Get last commit info */
            char refname[256];
            snprintf(refname, sizeof(refname), "refs/heads/%s", name);
            git_commit *last_commit = NULL;
            dotta_error_t *commit_err = gitops_get_commit(repo, refname, &last_commit);

            if (!commit_err && last_commit) {
                const git_oid *oid = git_commit_id(last_commit);
                char oid_str[8];
                git_oid_tostr(oid_str, sizeof(oid_str), oid);

                const git_signature *author = git_commit_author(last_commit);
                char time_str[64];
                format_relative_time(author->when.time, time_str, sizeof(time_str));

                if (output_colors_enabled(out)) {
                    fprintf(out->stream, ", last: %s%s%s %s%s%s\n",
                            output_color_code(out, OUTPUT_COLOR_YELLOW),
                            oid_str,
                            output_color_code(out, OUTPUT_COLOR_RESET),
                            output_color_code(out, OUTPUT_COLOR_DIM),
                            time_str,
                            output_color_code(out, OUTPUT_COLOR_RESET));
                } else {
                    fprintf(out->stream, ", last: %s %s\n", oid_str, time_str);
                }

                git_commit_free(last_commit);
            } else {
                fprintf(out->stream, "\n");
            }
            error_free(commit_err);

            string_array_free(files);
            profile_free(profile);
        }
    }

    /* Print legend */
    if (has_auto || show_remote) {
        fprintf(out->stream, "\n");
    }

    if (has_auto) {
        if (output_colors_enabled(out)) {
            fprintf(out->stream, "%s*%s = auto-detected for this system\n",
                    output_color_code(out, OUTPUT_COLOR_GREEN),
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            fprintf(out->stream, "* = auto-detected for this system\n");
        }
    }

    if (show_remote) {
        fprintf(out->stream, "\nRemote tracking (from %s):\n", remote_name);
        if (output_colors_enabled(out)) {
            fprintf(out->stream, "  %s[=]%s  up-to-date    ",
                    output_color_code(out, OUTPUT_COLOR_GREEN),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            fprintf(out->stream, "%s[↑n]%s ahead    ",
                    output_color_code(out, OUTPUT_COLOR_YELLOW),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            fprintf(out->stream, "%s[↓n]%s behind\n",
                    output_color_code(out, OUTPUT_COLOR_YELLOW),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            fprintf(out->stream, "  %s[↕]%s  diverged      ",
                    output_color_code(out, OUTPUT_COLOR_RED),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            fprintf(out->stream, "%s[•]%s  no remote\n",
                    output_color_code(out, OUTPUT_COLOR_CYAN),
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            fprintf(out->stream, "  [=] up-to-date    [↑n] ahead     [↓n] behind\n");
            fprintf(out->stream, "  [↕] diverged      [•]  no remote\n");
        }
    }

    /* Cleanup */
    free(remote_name);
    string_array_free(branches);
    if (auto_profiles) {
        profile_list_free(auto_profiles);
    }

    return NULL;
}

/**
 * List files in a profile with color support
 */
static dotta_error_t *list_files(
    git_repository *repo,
    const cmd_list_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(opts->profile);
    CHECK_NULL(out);

    /* Load profile */
    profile_t *profile = NULL;
    dotta_error_t *err = profile_load(repo, opts->profile, &profile);
    if (err) {
        return error_wrap(err, "Failed to load profile '%s'", opts->profile);
    }

    /* List files */
    string_array_t *files = NULL;
    err = profile_list_files(repo, profile, &files);
    if (err) {
        profile_free(profile);
        return error_wrap(err, "Failed to list files in profile '%s'", opts->profile);
    }

    if (string_array_size(files) == 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "No files in profile '%s'", opts->profile);
        output_info(out, "%s", msg);
    } else {
        char header[256];
        snprintf(header, sizeof(header), "Files in profile '%s'", opts->profile);
        output_section(out, header);

        /* Sort for consistent output */
        string_array_sort(files);

        for (size_t i = 0; i < string_array_size(files); i++) {
            if (output_colors_enabled(out)) {
                fprintf(out->stream, "  %s%s%s\n",
                        output_color_code(out, OUTPUT_COLOR_CYAN),
                        string_array_get(files, i),
                        output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                fprintf(out->stream, "  %s\n", string_array_get(files, i));
            }
        }

        fprintf(out->stream, "\nTotal: %zu file%s\n",
               string_array_size(files),
               string_array_size(files) == 1 ? "" : "s");
    }

    string_array_free(files);
    profile_free(profile);

    return NULL;
}

/**
 * Format timestamp as human-readable date
 */
static char *format_time(git_time_t timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);

    char *buf = malloc(64);
    if (!buf) {
        return NULL;
    }

    strftime(buf, 64, "%a %b %d %H:%M:%S %Y", tm_info);
    return buf;
}

/**
 * Format commit in one-line format
 */
static void print_commit_oneline(
    const output_ctx_t *out,
    const git_commit *commit,
    const char *profile_name
) {
    const git_oid *oid = git_commit_id(commit);
    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), oid);

    const char *message = git_commit_message(commit);
    /* Get first line of message */
    const char *newline = strchr(message, '\n');
    size_t msg_len = newline ? (size_t)(newline - message) : strlen(message);

    char *msg_short = strndup(message, msg_len);
    if (!msg_short) {
        return;
    }

    /* Get relative time */
    const git_signature *author = git_commit_author(commit);
    char time_str[64];
    format_relative_time(author->when.time, time_str, sizeof(time_str));

    if (output_colors_enabled(out)) {
        fprintf(out->stream, "  %s%s%s %s(%s)%s %s %s(%s)%s\n",
                output_color_code(out, OUTPUT_COLOR_YELLOW),
                oid_str,
                output_color_code(out, OUTPUT_COLOR_RESET),
                output_color_code(out, OUTPUT_COLOR_CYAN),
                profile_name,
                output_color_code(out, OUTPUT_COLOR_RESET),
                msg_short,
                output_color_code(out, OUTPUT_COLOR_DIM),
                time_str,
                output_color_code(out, OUTPUT_COLOR_RESET));
    } else {
        fprintf(out->stream, "  %s (%s) %s (%s)\n", oid_str, profile_name, msg_short, time_str);
    }

    free(msg_short);
}

/**
 * Print commit in detailed format
 */
static void print_commit_detailed(
    const output_ctx_t *out,
    const git_commit *commit
) {
    const git_oid *oid = git_commit_id(commit);
    char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), oid);

    const git_signature *author = git_commit_author(commit);
    const char *message = git_commit_message(commit);

    char *date_str = format_time(author->when.time);
    char relative_str[64];
    format_relative_time(author->when.time, relative_str, sizeof(relative_str));

    if (output_colors_enabled(out)) {
        fprintf(out->stream, "%scommit %s%s%s\n",
                output_color_code(out, OUTPUT_COLOR_BOLD),
                output_color_code(out, OUTPUT_COLOR_YELLOW),
                oid_str,
                output_color_code(out, OUTPUT_COLOR_RESET));
    } else {
        fprintf(out->stream, "commit %s\n", oid_str);
    }

    fprintf(out->stream, "Author: %s <%s>\n", author->name, author->email);
    if (date_str) {
        if (output_colors_enabled(out)) {
            fprintf(out->stream, "Date:   %s %s(%s)%s\n",
                    date_str,
                    output_color_code(out, OUTPUT_COLOR_DIM),
                    relative_str,
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            fprintf(out->stream, "Date:   %s (%s)\n", date_str, relative_str);
        }
        free(date_str);
    }
    fprintf(out->stream, "\n    %s\n", message);
}

/**
 * List commit log for profile(s)
 */
static dotta_error_t *list_log(
    git_repository *repo,
    const cmd_list_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    dotta_error_t *err = NULL;
    profile_list_t *profiles = NULL;

    /* Load configuration */
    dotta_config_t *config = NULL;
    err = config_load(NULL, &config);
    if (err) {
        config = config_create_default();
    }

    /* Load profiles */
    if (opts->profile) {
        /* Use specified single profile */
        const char *names[] = { opts->profile };
        err = profile_list_load(repo, names, 1, true, &profiles);
        if (err) {
            config_free(config);
            return error_wrap(err, "Failed to load profile '%s'", opts->profile);
        }
    } else {
        /* Use all configured profiles (config order or auto-detect) */
        err = profile_load_with_fallback(
            repo,
            NULL, 0,  /* No CLI profiles */
            (const char **)config->profile_order,
            config->profile_order_count,
            config->auto_detect,
            config->strict_mode,
            &profiles
        );
        if (err) {
            config_free(config);
            return error_wrap(err, "Failed to load profiles");
        }
    }

    if (profiles->count == 0) {
        config_free(config);
        profile_list_free(profiles);
        output_info(out, "No profiles found");
        return NULL;
    }

    /* Print overall header for --log mode */
    if (profiles->count == 1) {
        char header[256];
        snprintf(header, sizeof(header), "Commit history for profile '%s'",
                 profiles->profiles[0].name);
        output_section(out, header);
    } else if (opts->oneline) {
        output_section(out, "Commit history (all profiles)");
    }

    /* Walk commits for each profile */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile_name = profiles->profiles[i].name;

        /* Build reference name */
        char refname[256];
        snprintf(refname, sizeof(refname), "refs/heads/%s", profile_name);

        /* Show profile header for multiple profiles in detailed mode */
        if (profiles->count > 1 && !opts->oneline) {
            if (i > 0) {
                fprintf(out->stream, "\n");  /* Separator between profiles */
            }
            char section_header[256];
            snprintf(section_header, sizeof(section_header), "Profile: %s", profile_name);
            output_section(out, section_header);
        }

        /* Get reference */
        git_reference *ref = NULL;
        err = gitops_lookup_reference(repo, refname, &ref);
        if (err) {
            profile_list_free(profiles);
            config_free(config);
            return error_wrap(err, "Failed to lookup reference '%s'", refname);
        }

        const git_oid *target_oid = git_reference_target(ref);
        if (!target_oid) {
            git_reference_free(ref);
            output_warning(out, "Profile '%s' has no commits", profile_name);
            continue;
        }

        /* Create revwalk */
        git_revwalk *walker = NULL;
        int git_err = git_revwalk_new(&walker, repo);
        if (git_err < 0) {
            git_reference_free(ref);
            profile_list_free(profiles);
            config_free(config);
            return error_from_git(git_err);
        }

        git_err = git_revwalk_push(walker, target_oid);
        git_reference_free(ref);

        if (git_err < 0) {
            git_revwalk_free(walker);
            profile_list_free(profiles);
            config_free(config);
            return error_from_git(git_err);
        }

        /* Set to topological order */
        git_revwalk_sorting(walker, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);

        /* Walk commits */
        size_t count = 0;
        git_oid oid;
        while (git_revwalk_next(&oid, walker) == 0) {
            if (opts->max_count > 0 && count >= opts->max_count) {
                break;
            }

            git_commit *commit = NULL;
            git_err = git_commit_lookup(&commit, repo, &oid);
            if (git_err < 0) {
                git_revwalk_free(walker);
                profile_list_free(profiles);
                config_free(config);
                return error_from_git(git_err);
            }

            /* Print commit */
            if (opts->oneline) {
                print_commit_oneline(out, commit, profile_name);
            } else {
                print_commit_detailed(out, commit);
            }

            git_commit_free(commit);
            count++;
        }

        git_revwalk_free(walker);

        if (count == 0) {
            output_info(out, "No commits in '%s'", profile_name);
        }
    }

    profile_list_free(profiles);
    config_free(config);

    return NULL;
}

/**
 * List command implementation
 */
dotta_error_t *cmd_list(git_repository *repo, const cmd_list_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Load configuration */
    dotta_config_t *config = NULL;
    dotta_error_t *err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        config = config_create_default();
    }

    /* Create output context from config */
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create output context");
    }

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Dispatch to appropriate list function */
    if (opts->mode == LIST_PROFILES) {
        err = list_profiles(repo, opts, out);
    } else if (opts->mode == LIST_FILES) {
        err = list_files(repo, opts, out);
    } else if (opts->mode == LIST_LOG) {
        err = list_log(repo, opts, out);
    } else {
        err = ERROR(DOTTA_ERR_INVALID_ARG, "Invalid list mode");
    }

    /* Add trailing newline for UX consistency */
    if (out && out->stream) {
        fprintf(out->stream, "\n");
    }

    /* Cleanup */
    config_free(config);
    output_free(out);
    return err;
}
