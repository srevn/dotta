/**
 * list.c - List profiles, files, and commit history
 *
 * Hierarchical listing interface with three levels:
 * 1. Profiles (default) - Show available profiles
 * 2. Files (with -p) - Show files in a profile
 * 3. File History (with -p <file>) - Show commits affecting a file
 */

#include "list.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/stats.h"
#include "core/upstream.h"
#include "crypto/encryption.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"
#include "utils/timeutil.h"

/* Display configuration constants */
#define LIST_SHORT_OID_SIZE 8
#define LIST_TIMESTAMP_BUFFER_SIZE 64
#define LIST_REFNAME_BUFFER_SIZE 256
#define LIST_MESSAGE_BUFFER_SIZE 256
#define LIST_HEADER_BUFFER_SIZE 512

/**
 * Format file size for display
 */
static void format_size(size_t bytes, char *buffer, size_t buffer_size) {
    if (bytes < 1024) {
        snprintf(buffer, buffer_size, "%zu B", bytes);
    } else if (bytes < 1024 * 1024) {
        snprintf(buffer, buffer_size, "%.1f KB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        snprintf(buffer, buffer_size, "%.1f MB", bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buffer, buffer_size, "%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

/**
 * Check if file is encrypted
 *
 * Strategy:
 * 1. Check metadata first (fast O(1) lookup if available)
 * 2. Fall back to blob magic header check if metadata unavailable
 *
 * @param metadata Metadata (can be NULL)
 * @param repo Repository (must not be NULL)
 * @param entry Tree entry (must not be NULL)
 * @param storage_path Storage path (must not be NULL)
 * @return true if file is encrypted, false otherwise
 */
static bool is_file_encrypted(
    const metadata_t *metadata,
    git_repository *repo,
    const git_tree_entry *entry,
    const char *storage_path
) {
    /* Fast path: Check metadata if available */
    if (metadata) {
        const metadata_entry_t *meta_entry = NULL;
        error_t *err = metadata_get_entry(metadata, storage_path, &meta_entry);
        if (!err && meta_entry) {
            return meta_entry->encrypted;
        }
        error_free(err);  /* Not found or error - fall through to blob check */
    }

    /* Fallback: Check blob magic header */
    const git_oid *blob_oid = git_tree_entry_id(entry);
    if (!blob_oid) {
        return false;
    }

    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, repo, blob_oid);
    if (git_err != 0) {
        return false;  /* Can't load blob - assume not encrypted */
    }

    const unsigned char *data = (const unsigned char *)git_blob_rawcontent(blob);
    size_t size = git_blob_rawsize(blob);
    bool encrypted = encryption_is_encrypted(data, size);

    git_blob_free(blob);
    return encrypted;
}

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
 * List profiles - Level 1
 *
 * Default: Just profile names
 * Verbose: Add stats (file count, size, last commit)
 * Remote:  Add tracking indicators
 */
static error_t *list_profiles(
    git_repository *repo,
    const cmd_list_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    /* Get all branches */
    string_array_t *branches = NULL;
    error_t *err = gitops_list_branches(repo, &branches);
    if (err) {
        return error_wrap(err, "Failed to list branches");
    }

    if (string_array_size(branches) == 0) {
        string_array_free(branches);
        output_info(out, "No profiles found");
        return NULL;
    }

    /* Detect remote if --remote flag is set */
    char *remote_name = NULL;
    bool show_remote = false;
    if (opts->remote) {
        err = upstream_detect_remote(repo, &remote_name);
        if (err) {
            output_warning(out, "Could not detect remote: %s", error_message(err));
            error_free(err);
            err = NULL;
        } else {
            show_remote = true;
        }
    }

    /* Print header */
    output_section(out, "Available profiles");

    /* List profiles */
    for (size_t i = 0; i < string_array_size(branches); i++) {
        const char *name = string_array_get(branches, i);

        /* Skip dotta-worktree branch */
        if (strcmp(name, "dotta-worktree") == 0) {
            continue;
        }

        /* Simple mode: Just name */
        if (!opts->verbose && !show_remote) {
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s%s%s\n",
                        output_color_code(out, OUTPUT_COLOR_CYAN),
                        name,
                        output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  %s\n", name);
            }
            continue;
        }

        /* Verbose or remote mode: Get additional info */
        profile_t *profile = NULL;
        err = profile_load(repo, name, &profile);
        if (err) {
            error_free(err);
            continue;
        }

        /* Start line with name */
        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "  %s%-20s%s",
                    output_color_code(out, OUTPUT_COLOR_CYAN),
                    name,
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_printf(out, OUTPUT_NORMAL, "  %-20s", name);
        }

        /* Verbose: Add stats */
        if (opts->verbose) {
            profile_stats_t stats = {0};
            err = stats_get_profile_stats(repo, profile->tree, &stats);
            if (!err) {
                char size_str[32];
                format_size(stats.total_size, size_str, sizeof(size_str));
                output_printf(out, OUTPUT_NORMAL, " %2zu file%s, %8s",
                       stats.file_count,
                       stats.file_count == 1 ? " " : "s",
                       size_str);
            }

            /* Get last commit info */
            char refname[LIST_REFNAME_BUFFER_SIZE];
            snprintf(refname, sizeof(refname), "refs/heads/%s", name);
            git_commit *last_commit = NULL;
            error_t *commit_err = gitops_get_commit(repo, refname, &last_commit);

            if (!commit_err && last_commit) {
                const git_oid *oid = git_commit_id(last_commit);
                char oid_str[LIST_SHORT_OID_SIZE];
                git_oid_tostr(oid_str, sizeof(oid_str), oid);

                const char *message = git_commit_message(last_commit);
                const char *newline = strchr(message, '\n');
                size_t msg_len = newline ? (size_t)(newline - message) : strlen(message);
                if (msg_len > 40) {
                    msg_len = 40;
                }

                const git_signature *author = git_commit_author(last_commit);
                char time_str[64];
                format_relative_time(author->when.time, time_str, sizeof(time_str));

                if (output_colors_enabled(out)) {
                    output_printf(out, OUTPUT_NORMAL, "  %s%s%s %.*s %s(%s)%s",
                            output_color_code(out, OUTPUT_COLOR_YELLOW),
                            oid_str,
                            output_color_code(out, OUTPUT_COLOR_RESET),
                            (int)msg_len, message,
                            output_color_code(out, OUTPUT_COLOR_DIM),
                            time_str,
                            output_color_code(out, OUTPUT_COLOR_RESET));
                } else {
                    output_printf(out, OUTPUT_NORMAL, "  %s %.*s (%s)",
                            oid_str, (int)msg_len, message, time_str);
                }

                git_commit_free(last_commit);
            }
            error_free(commit_err);
        }

        /* Remote: Add tracking state */
        if (show_remote) {
            upstream_info_t *info = NULL;
            error_t *upstream_err = upstream_analyze_profile(repo, remote_name, name, &info);
            if (!upstream_err && info) {
                char upstream_str[64];
                format_upstream_state(out, info, upstream_str, sizeof(upstream_str));
                output_printf(out, OUTPUT_NORMAL, "  %s", upstream_str);
                upstream_info_free(info);
            } else {
                error_free(upstream_err);
            }
        }

        output_newline(out);
        profile_free(profile);
    }

    /* Print remote legend if shown */
    if (show_remote) {
        output_newline(out);
        output_printf(out, OUTPUT_NORMAL, "Remote tracking (from %s):\n", remote_name);
        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "  %s[=]%s  up-to-date    ",
                    output_color_code(out, OUTPUT_COLOR_GREEN),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "%s[↑n]%s ahead    ",
                    output_color_code(out, OUTPUT_COLOR_YELLOW),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "%s[↓n]%s behind\n",
                    output_color_code(out, OUTPUT_COLOR_YELLOW),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "  %s[↕]%s  diverged      ",
                    output_color_code(out, OUTPUT_COLOR_RED),
                    output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "%s[•]%s  no remote\n",
                    output_color_code(out, OUTPUT_COLOR_CYAN),
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_printf(out, OUTPUT_NORMAL, "  [=] up-to-date    [↑n] ahead     [↓n] behind\n");
            output_printf(out, OUTPUT_NORMAL, "  [↕] diverged      [•]  no remote\n");
        }
    }

    /* Cleanup */
    free(remote_name);
    string_array_free(branches);

    return NULL;
}

/**
 * List files - Level 2
 *
 * Default: Just file paths
 * Verbose: Add sizes and per-file last commit
 */
static error_t *list_files(
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
    error_t *err = profile_load(repo, opts->profile, &profile);
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
        char msg[LIST_MESSAGE_BUFFER_SIZE];
        snprintf(msg, sizeof(msg), "No files in profile '%s'", opts->profile);
        output_info(out, "%s", msg);
        string_array_free(files);
        profile_free(profile);
        return NULL;
    }

    /* Print header */
    char header[LIST_MESSAGE_BUFFER_SIZE];
    snprintf(header, sizeof(header), "Files in profile '%s'", opts->profile);
    output_section(out, header);

    /* Sort for consistent output */
    string_array_sort(files);

    /* Build file→commit map if verbose */
    file_commit_map_t *commit_map = NULL;
    if (opts->verbose) {
        err = stats_build_file_commit_map(repo, opts->profile, profile->tree, &commit_map);
        if (err) {
            /* Non-fatal: continue without commit info */
            output_warning(out, "Failed to load commit history: %s", error_message(err));
            error_free(err);
            err = NULL;
        }
    }

    /* Load metadata for encryption status (verbose mode only) */
    metadata_t *metadata = NULL;
    if (opts->verbose) {
        err = metadata_load_from_branch(repo, opts->profile, &metadata);
        if (err) {
            /* Non-fatal: continue without encryption indicators */
            /* Don't warn - metadata may not exist yet (perfectly normal) */
            error_free(err);
            err = NULL;
        }
    }

    /* Calculate max path length for alignment (verbose mode only) */
    size_t max_path_len = 0;
    if (opts->verbose) {
        for (size_t i = 0; i < string_array_size(files); i++) {
            size_t len = strlen(string_array_get(files, i));
            if (len > max_path_len) {
                max_path_len = len;
            }
        }
        /* Cap at reasonable width to prevent excessive spacing */
        if (max_path_len > 80) {
            max_path_len = 80;
        }
    }

    /* List files */
    size_t total_size = 0;
    for (size_t i = 0; i < string_array_size(files); i++) {
        const char *file_path = string_array_get(files, i);

        /* Print file path (with alignment in verbose mode) */
        if (opts->verbose) {
            /* Verbose: Left-align with padding for column alignment */
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s%-*s%s",
                        output_color_code(out, OUTPUT_COLOR_CYAN),
                        (int)max_path_len,
                        file_path,
                        output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  %-*s", (int)max_path_len, file_path);
            }
        } else {
            /* Simple: No alignment needed */
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s%s%s",
                        output_color_code(out, OUTPUT_COLOR_CYAN),
                        file_path,
                        output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  %s", file_path);
            }
        }

        /* Verbose: Add size and last commit */
        if (opts->verbose) {
            /* Get file stats */
            git_tree_entry *entry = NULL;
            int git_err = git_tree_entry_bypath(&entry, profile->tree, file_path);
            if (git_err == 0) {
                /* Check encryption status and display indicator */
                bool encrypted = is_file_encrypted(metadata, repo, entry, file_path);
                if (encrypted) {
                    if (output_colors_enabled(out)) {
                        output_printf(out, OUTPUT_NORMAL, "  %s[E]%s ",
                                output_color_code(out, OUTPUT_COLOR_YELLOW),
                                output_color_code(out, OUTPUT_COLOR_RESET));
                    } else {
                        output_printf(out, OUTPUT_NORMAL, "  [E] ");
                    }
                } else {
                    /* Space padding to maintain alignment */
                    output_printf(out, OUTPUT_NORMAL, "      ");
                }

                /* Get blob size efficiently */
                size_t size;
                error_t *stats_err = stats_get_blob_size(repo, git_tree_entry_id(entry), &size);
                if (!stats_err) {
                    char size_str[32];
                    format_size(size, size_str, sizeof(size_str));
                    output_printf(out, OUTPUT_NORMAL, " %8s", size_str);
                    total_size += size;
                }
                error_free(stats_err);

                /* Get last commit for this file */
                if (commit_map) {
                    const commit_info_t *commit_info = stats_file_commit_map_get(commit_map, file_path);
                    if (commit_info) {
                        char oid_str[LIST_SHORT_OID_SIZE];
                        git_oid_tostr(oid_str, sizeof(oid_str), &commit_info->oid);

                        char time_str[64];
                        format_relative_time(commit_info->time, time_str, sizeof(time_str));

                        if (output_colors_enabled(out)) {
                            output_printf(out, OUTPUT_NORMAL, "  %s%s%s %s %s(%s)%s",
                                    output_color_code(out, OUTPUT_COLOR_YELLOW),
                                    oid_str,
                                    output_color_code(out, OUTPUT_COLOR_RESET),
                                    commit_info->summary,
                                    output_color_code(out, OUTPUT_COLOR_DIM),
                                    time_str,
                                    output_color_code(out, OUTPUT_COLOR_RESET));
                        } else {
                            output_printf(out, OUTPUT_NORMAL, "  %s %s (%s)",
                                    oid_str, commit_info->summary, time_str);
                        }
                    }
                }

                git_tree_entry_free(entry);
            }
        }

        output_newline(out);
    }

    /* Print summary */
    output_newline(out);
    if (opts->verbose) {
        char size_str[32];
        format_size(total_size, size_str, sizeof(size_str));
        output_printf(out, OUTPUT_NORMAL, "Total: %zu file%s, %s\n",
               string_array_size(files),
               string_array_size(files) == 1 ? "" : "s",
               size_str);
    } else {
        output_printf(out, OUTPUT_NORMAL, "Total: %zu file%s\n",
               string_array_size(files),
               string_array_size(files) == 1 ? "" : "s");
    }

    /* Cleanup */
    if (commit_map) {
        stats_free_file_commit_map(commit_map);
    }
    if (metadata) {
        metadata_free(metadata);
    }
    string_array_free(files);
    profile_free(profile);

    return NULL;
}

/**
 * Format timestamp as human-readable date (for verbose commit display)
 */
static char *format_time(git_time_t timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);

    /* localtime can return NULL for invalid timestamps */
    if (!tm_info) {
        return NULL;
    }

    char *buf = malloc(LIST_TIMESTAMP_BUFFER_SIZE);
    if (!buf) {
        return NULL;
    }

    strftime(buf, LIST_TIMESTAMP_BUFFER_SIZE, "%a %b %d %H:%M:%S %Y", tm_info);
    return buf;
}

/**
 * List file history - Level 3
 *
 * Default: Oneline format (hash, summary, time)
 * Verbose: Full commit format
 */
static error_t *list_file_history(
    git_repository *repo,
    const cmd_list_options_t *opts,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(opts->profile);
    CHECK_NULL(opts->file_path);
    CHECK_NULL(out);

    /* Get file history */
    file_history_t *history = NULL;
    error_t *err = stats_get_file_history(repo, opts->profile, opts->file_path, &history);
    if (err) {
        return error_wrap(err, "Failed to get history for '%s' in profile '%s'",
                         opts->file_path, opts->profile);
    }

    /* Print header */
    char header[LIST_HEADER_BUFFER_SIZE];
    snprintf(header, sizeof(header), "History of '%s' in profile '%s'",
             opts->file_path, opts->profile);
    output_section(out, header);

    /* Calculate max message length for alignment (oneline mode only) */
    size_t max_msg_len = 0;
    if (!opts->verbose) {
        for (size_t i = 0; i < history->count; i++) {
            size_t len = strlen(history->commits[i].summary);
            if (len > max_msg_len) {
                max_msg_len = len;
            }
        }
    }

    /* Print commits */
    for (size_t i = 0; i < history->count; i++) {
        commit_info_t *commit = &history->commits[i];

        if (opts->verbose) {
            /* Verbose: Full commit format */
            char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
            git_oid_tostr(oid_str, sizeof(oid_str), &commit->oid);

            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "%scommit %s%s%s\n",
                        output_color_code(out, OUTPUT_COLOR_BOLD),
                        output_color_code(out, OUTPUT_COLOR_YELLOW),
                        oid_str,
                        output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                output_printf(out, OUTPUT_NORMAL, "commit %s\n", oid_str);
            }

            /* Display timestamp if valid */
            char *date_str = format_time(commit->time);
            if (date_str) {
                char relative_str[64];
                format_relative_time(commit->time, relative_str, sizeof(relative_str));

                if (output_colors_enabled(out)) {
                    output_printf(out, OUTPUT_NORMAL, "Date:   %s %s(%s)%s\n",
                            date_str,
                            output_color_code(out, OUTPUT_COLOR_DIM),
                            relative_str,
                            output_color_code(out, OUTPUT_COLOR_RESET));
                } else {
                    output_printf(out, OUTPUT_NORMAL, "Date:   %s (%s)\n", date_str, relative_str);
                }
                free(date_str);
            }

            output_printf(out, OUTPUT_NORMAL, "\n    %s\n", commit->summary);

            if (i < history->count - 1) {
                output_newline(out);
            }
        } else {
            /* Default: Oneline format */
            char oid_str[LIST_SHORT_OID_SIZE];
            git_oid_tostr(oid_str, sizeof(oid_str), &commit->oid);

            char time_str[64];
            format_relative_time(commit->time, time_str, sizeof(time_str));

            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "  %s%s%s  %-*s %s(%s)%s\n",
                        output_color_code(out, OUTPUT_COLOR_YELLOW),
                        oid_str,
                        output_color_code(out, OUTPUT_COLOR_RESET),
                        (int)max_msg_len,
                        commit->summary,
                        output_color_code(out, OUTPUT_COLOR_DIM),
                        time_str,
                        output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                output_printf(out, OUTPUT_NORMAL, "  %s  %-*s (%s)\n",
                        oid_str, (int)max_msg_len, commit->summary, time_str);
            }
        }
    }

    /* Cleanup */
    stats_free_file_history(history);

    return NULL;
}

/**
 * List command implementation
 */
error_t *cmd_list(git_repository *repo, const cmd_list_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Load configuration */
    dotta_config_t *config = NULL;
    error_t *err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        error_free(err);
        err = NULL;
        config = config_create_default();
    }

    /* Create output context from config */
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Dispatch to appropriate list function based on mode */
    if (opts->mode == LIST_PROFILES) {
        err = list_profiles(repo, opts, out);
    } else if (opts->mode == LIST_FILES) {
        err = list_files(repo, opts, out);
    } else if (opts->mode == LIST_FILE_HISTORY) {
        err = list_file_history(repo, opts, out);
    } else {
        err = ERROR(ERR_INVALID_ARG, "Invalid list mode");
    }

    /* Cleanup */
    config_free(config);
    output_free(out);
    return err;
}
