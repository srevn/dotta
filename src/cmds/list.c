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
#include "core/state.h"
#include "core/stats.h"
#include "core/upstream.h"
#include "crypto/encryption.h"
#include "infra/path.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"
#include "utils/timeutil.h"

/* Display configuration constants */
#define LIST_SHORT_OID_BUF_SIZE 8
#define LIST_TIMESTAMP_BUFFER_SIZE 64
#define LIST_MAX_MSG_ALIGN 60
#define LIST_MAX_NAME_ALIGN 40
#define LIST_MIN_NAME_ALIGN 12

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
        const metadata_item_t *item = NULL;
        error_t *err = metadata_get_item(metadata, storage_path, &item);
        if (!err && item) {
            /* Defensive: Ensure it's a file (directories shouldn't appear here) */
            if (item->kind == METADATA_ITEM_FILE) {
                return item->file.encrypted;
            }
            /* If it's a directory, fall through to blob check (shouldn't happen) */
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

    const unsigned char *data = (const unsigned char *) git_blob_rawcontent(blob);
    size_t size = git_blob_rawsize(blob);
    bool encrypted = encryption_is_encrypted(data, size);

    git_blob_free(blob);
    return encrypted;
}

/**
 * Print upstream state indicator
 *
 * Prints a colored upstream tracking indicator (e.g., [=], [↑3], [↕2+1])
 * directly to the output stream via the output_colored API.
 */
static void print_upstream_state(
    output_ctx_t *out,
    const upstream_info_t *info
) {
    if (!info) {
        return;
    }

    const char *symbol = upstream_state_symbol(info->state);
    output_color_t color;
    char label[64];

    switch (info->state) {
        case UPSTREAM_UP_TO_DATE:
            color = OUTPUT_COLOR_GREEN;
            snprintf(
                label, sizeof(label),
                "[%s]", symbol
            );
            break;
        case UPSTREAM_LOCAL_AHEAD:
            color = OUTPUT_COLOR_YELLOW;
            snprintf(
                label, sizeof(label),
                "[%s%zu]", symbol, info->ahead
            );
            break;
        case UPSTREAM_REMOTE_AHEAD:
            color = OUTPUT_COLOR_YELLOW;
            snprintf(
                label, sizeof(label),
                "[%s%zu]", symbol, info->behind
            );
            break;
        case UPSTREAM_DIVERGED:
            color = OUTPUT_COLOR_RED;
            snprintf(
                label, sizeof(label),
                "[%s%zu+%zu]", symbol, info->ahead, info->behind
            );
            break;
        case UPSTREAM_NO_REMOTE:
            color = OUTPUT_COLOR_CYAN;
            snprintf(
                label, sizeof(label),
                "[%s]", symbol
            );
            break;
        case UPSTREAM_UNKNOWN:
        default:
            color = OUTPUT_COLOR_DIM;
            snprintf(
                label, sizeof(label),
                "[%s]", symbol
            );
            break;
    }

    output_colored(out, OUTPUT_NORMAL, color, "  %s", label);
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
            output_warning(
                out, "Could not detect remote: %s",
                error_message(err)
            );
            error_free(err);
            err = NULL;
        } else {
            show_remote = true;
        }
    }

    /* Load state for enabled profile indicators (non-fatal) */
    state_t *state = NULL;
    err = state_load(repo, &state);
    if (err) {
        error_free(err);
        err = NULL;
    }

    /* Calculate max branch name length for column alignment */
    size_t max_name_len = 0;
    if (opts->verbose || show_remote) {
        for (size_t i = 0; i < string_array_size(branches); i++) {
            const char *bname = string_array_get(branches, i);
            if (strcmp(bname, "dotta-worktree") == 0) {
                continue;
            }
            size_t len = strlen(bname);
            if (len > max_name_len) {
                max_name_len = len;
            }
        }
        if (max_name_len < LIST_MIN_NAME_ALIGN) {
            max_name_len = LIST_MIN_NAME_ALIGN;
        }
        if (max_name_len > LIST_MAX_NAME_ALIGN) {
            max_name_len = LIST_MAX_NAME_ALIGN;
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

        bool is_enabled = state && state_has_profile(state, name);
        const char *indicator = is_enabled ? "* " : "  ";

        /* Simple mode: Just name with enabled indicator */
        if (!opts->verbose && !show_remote) {
            output_styled(
                out, OUTPUT_NORMAL, "  %s{cyan}%s{reset}\n",
                indicator, name
            );
            continue;
        }

        /* Verbose/remote: Load profile for stats */
        profile_t *profile = NULL;
        if (opts->verbose) {
            err = profile_load(repo, name, &profile);
            if (err) {
                output_warning(
                    out, "Failed to load profile '%s': %s",
                    name, error_message(err)
                );
                error_free(err);
                err = NULL;
                /* profile stays NULL - stats skipped, name still shown */
            }
        }

        /* Start line with indicator and name */
        output_styled(
            out, OUTPUT_NORMAL, "  %s{cyan}%-*s{reset}",
            indicator, (int) max_name_len, name
        );

        /* Verbose: Add stats (requires successfully loaded profile) */
        if (opts->verbose && profile) {
            profile_stats_t stats = { 0 };
            error_t *stats_err = stats_get_profile_stats(repo, profile->tree, &stats);
            if (!stats_err) {
                char size_str[32];
                output_format_size(stats.total_size, size_str, sizeof(size_str));
                output_print(
                    out, OUTPUT_NORMAL, " %2zu file%s, %8s",
                    stats.file_count,
                    stats.file_count == 1 ? " " : "s", size_str
                );
            }
            error_free(stats_err);
        }

        /* Verbose: Add last commit info (uses branch name, not profile tree) */
        if (opts->verbose) {
            char refname[DOTTA_REFNAME_MAX];
            error_t *ref_err = gitops_build_refname(
                refname, sizeof(refname), "refs/heads/%s", name
            );
            if (!ref_err) {
                git_commit *last_commit = NULL;
                error_t *commit_err = gitops_get_commit(repo, refname, &last_commit);

                if (!commit_err && last_commit) {
                    const git_oid *oid = git_commit_id(last_commit);
                    char oid_str[LIST_SHORT_OID_BUF_SIZE];
                    git_oid_tostr(oid_str, sizeof(oid_str), oid);

                    const char *message = git_commit_message(last_commit);
                    const char *newline = strchr(message, '\n');
                    size_t msg_len = newline ? (size_t) (newline - message) : strlen(message);
                    if (msg_len > 40) {
                        msg_len = 40;
                    }

                    const git_signature *author = git_commit_author(last_commit);
                    char time_str[64];
                    format_relative_time(author->when.time, time_str, sizeof(time_str));

                    output_styled(
                        out, OUTPUT_NORMAL, "  {yellow}%s{reset} %.*s {dim}(%s){reset}",
                        oid_str, (int) msg_len, message, time_str
                    );

                    git_commit_free(last_commit);
                }
                error_free(commit_err);
            } else {
                error_free(ref_err);
            }
        }

        /* Remote: Add tracking state */
        if (show_remote) {
            upstream_info_t *info = NULL;
            error_t *upstream_err = upstream_analyze_profile(repo, remote_name, name, &info);
            if (!upstream_err && info) {
                print_upstream_state(out, info);
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
        output_print(
            out, OUTPUT_NORMAL,
            "Remote tracking (from %s):\n",
            remote_name
        );
        output_styled(
            out, OUTPUT_NORMAL,
            "  {green}[=]{reset} up-to-date  "
            "  {yellow}[↑n]{reset} ahead  "
            "  {yellow}[↓n]{reset} behind\n"
        );
        output_styled(
            out, OUTPUT_NORMAL,
            "  {red}[↕n+m]{reset} diverged  "
            " {cyan}[•]{reset}  no remote\n"
        );
    }

    /* Cleanup */
    state_free(state);
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
        output_info(out, "No files in profile '%s'", opts->profile);
        string_array_free(files);
        profile_free(profile);
        return NULL;
    }

    /* Print header */
    output_section(out, "Files in profile '%s'", opts->profile);
    output_newline(out);

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
            output_styled(
                out, OUTPUT_NORMAL, "  {cyan}%-*s{reset}",
                (int) max_path_len, file_path
            );
        } else {
            /* Simple: No alignment needed */
            output_styled(
                out, OUTPUT_NORMAL, "  {cyan}%s{reset}",
                file_path
            );
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
                    output_styled(
                        out, OUTPUT_NORMAL, "  {yellow}[E]{reset} "
                    );
                } else {
                    /* Space padding to maintain alignment */
                    output_print(
                        out, OUTPUT_NORMAL, "      "
                    );
                }

                /* Get blob size efficiently */
                size_t size;
                error_t *stats_err = stats_get_blob_size(
                    repo, git_tree_entry_id(entry), &size
                );
                if (!stats_err) {
                    /* For encrypted files, show content size (subtract fixed overhead) */
                    size_t display_size = encrypted && size > ENCRYPTION_OVERHEAD
                                        ? size - ENCRYPTION_OVERHEAD : size;

                    char size_str[32];
                    output_format_size(display_size, size_str, sizeof(size_str));
                    output_print(out, OUTPUT_NORMAL, " %8s", size_str);
                    total_size += display_size;
                }
                error_free(stats_err);

                /* Get last commit for this file */
                if (commit_map) {
                    const commit_info_t *commit_info = stats_file_commit_map_get(
                        commit_map, file_path
                    );
                    if (commit_info) {
                        char oid_str[LIST_SHORT_OID_BUF_SIZE];
                        git_oid_tostr(oid_str, sizeof(oid_str), &commit_info->oid);

                        char time_str[64];
                        format_relative_time(commit_info->time, time_str, sizeof(time_str));

                        size_t summary_len = strlen(commit_info->summary);
                        if (summary_len > 40) {
                            summary_len = 40;
                        }

                        output_styled(
                            out, OUTPUT_NORMAL, "  {yellow}%s{reset} %.*s {dim}(%s){reset}",
                            oid_str, (int) summary_len, commit_info->summary, time_str
                        );
                    }
                }

                git_tree_entry_free(entry);
            } else {
                /* Tree entry lookup failed unexpectedly */
                output_styled(out, OUTPUT_NORMAL, "  {dim}[?]{reset}");
            }
        }

        output_newline(out);
    }

    /* Print summary */
    output_newline(out);
    if (opts->verbose) {
        char size_str[32];
        output_format_size(total_size, size_str, sizeof(size_str));
        output_print(
            out, OUTPUT_NORMAL, "Total: %zu file%s, %s\n",
            string_array_size(files), string_array_size(files) == 1 ? "" : "s", size_str
        );
    } else {
        output_print(
            out, OUTPUT_NORMAL, "Total: %zu file%s\n",
            string_array_size(files), string_array_size(files) == 1 ? "" : "s"
        );
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
 *
 * @param timestamp Git timestamp to format
 * @param buf Caller-provided buffer (stack allocated)
 * @param buf_size Buffer size in bytes
 * @return true on success, false if timestamp is invalid
 */
static bool format_time(git_time_t timestamp, char *buf, size_t buf_size) {
    time_t t = (time_t) timestamp;

    struct tm tm_info;
    if (!localtime_r(&t, &tm_info)) {
        return false;
    }
    strftime(buf, buf_size, "%a %b %d %H:%M:%S %Y", &tm_info);
    return true;
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
    CHECK_NULL(opts->file_path);
    CHECK_NULL(out);

    char *discovered_profile = NULL;

    /* Resolve input path to storage format (handles absolute, tilde, relative,
     * and storage paths). Flexible mode - file need not exist on disk.
     *
     * Note: No custom prefix context available for list command - users must use
     * storage format (custom/etc/nginx.conf) for custom/ paths */
    char *storage_path = NULL;
    error_t *err = path_resolve_input(opts->file_path, false, NULL, 0, &storage_path);
    if (err) {
        return error_wrap(err, "Failed to resolve path '%s'", opts->file_path);
    }

    /* Resolve owning profile: explicit from user or implicit via manifest */
    const char *profile_name = opts->profile;

    if (!profile_name) {
        string_array_t *matches = NULL;
        err = profile_discover_file(repo, storage_path, true, &matches);
        if (err) {
            if (error_code(err) == ERR_NOT_FOUND) {
                error_free(err);
                err = ERROR(
                    ERR_NOT_FOUND,
                    "File '%s' not found in enabled profiles\n"
                    "Hint: Use 'dotta list -p <profile> %s' to specify a profile",
                    storage_path, opts->file_path
                );
            }
            free(storage_path);
            return err;
        }

        discovered_profile = strdup(string_array_get(matches, 0));
        string_array_free(matches);
        if (!discovered_profile) {
            free(storage_path);
            return ERROR(ERR_MEMORY, "Failed to allocate profile name");
        }
        profile_name = discovered_profile;
    }

    /* Verify profile exists and check if file is in current tree (fast pre-check).
     * This validates the profile early and gives a clear hint for typos/deleted files
     * before the expensive O(total_commits) history walk. */
    profile_t *profile = NULL;
    err = profile_load(repo, profile_name, &profile);
    if (err) {
        error_t *wrapped = error_wrap(err, "Profile '%s' not found", profile_name);
        free(discovered_profile);
        free(storage_path);
        return wrapped;
    }

    err = profile_load_tree(repo, profile);
    if (!err) {
        git_tree_entry *check = NULL;
        if (git_tree_entry_bypath(&check, profile->tree, storage_path) != 0) {
            output_info(out, "File not in current tree, searching history...");
        } else {
            git_tree_entry_free(check);
        }
    } else {
        error_free(err);
        err = NULL;
    }
    profile_free(profile);

    /* Get file history */
    file_history_t *history = NULL;
    err = stats_get_file_history(repo, profile_name, storage_path, &history);
    if (err) {
        error_t *wrapped = error_wrap(
            err, "Failed to get history for '%s' in profile '%s'",
            storage_path, profile_name
        );
        free(discovered_profile);
        free(storage_path);
        return wrapped;
    }

    /* Print header */
    output_section(
        out, "History of '%s' in profile '%s'",
        storage_path, profile_name
    );
    output_newline(out);

    /* Calculate max message length for alignment (oneline mode only) */
    size_t max_msg_len = 0;
    if (!opts->verbose) {
        for (size_t i = 0; i < history->count; i++) {
            size_t len = strlen(history->commits[i].summary);
            if (len > max_msg_len) {
                max_msg_len = len;
            }
        }

        /* Cap to prevent excessive padding from long commit messages */
        if (max_msg_len > LIST_MAX_MSG_ALIGN) {
            max_msg_len = LIST_MAX_MSG_ALIGN;
        }
    }

    /* Print commits */
    for (size_t i = 0; i < history->count; i++) {
        commit_info_t *commit = &history->commits[i];

        if (opts->verbose) {
            /* Verbose: Full commit format */
            char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
            git_oid_tostr(oid_str, sizeof(oid_str), &commit->oid);

            output_styled(
                out, OUTPUT_NORMAL, "{bold}commit {yellow}%s{reset}\n",
                oid_str
            );

            /* Display timestamp if valid */
            char date_buf[LIST_TIMESTAMP_BUFFER_SIZE];
            if (format_time(commit->time, date_buf, sizeof(date_buf))) {
                char relative_str[64];
                format_relative_time(commit->time, relative_str, sizeof(relative_str));

                output_styled(
                    out, OUTPUT_NORMAL, "Date:   %s {dim}(%s){reset}\n",
                    date_buf, relative_str
                );
            }

            output_print(out, OUTPUT_NORMAL, "\n    %s\n", commit->summary);

            if (i < history->count - 1) {
                output_newline(out);
            }
        } else {
            /* Default: Oneline format */
            char oid_str[LIST_SHORT_OID_BUF_SIZE];
            git_oid_tostr(oid_str, sizeof(oid_str), &commit->oid);

            char time_str[64];
            format_relative_time(commit->time, time_str, sizeof(time_str));

            output_styled(
                out, OUTPUT_NORMAL, "  {yellow}%s{reset}  %-*s {dim}(%s){reset}\n",
                oid_str, (int) max_msg_len, commit->summary, time_str
            );
        }
    }

    /* Cleanup */
    stats_free_file_history(history);
    free(discovered_profile);
    free(storage_path);

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

    /* Warn about flags that don't apply to the current mode */
    if (opts->remote && opts->mode != LIST_PROFILES) {
        output_warning(out, "--remote only applies when listing profiles");
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
