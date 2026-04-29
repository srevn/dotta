/**
 * list.c - List profiles, files, and commit history
 *
 * Hierarchical listing interface with three levels:
 * 1. Profiles (default) - Show available profiles
 * 2. Files (with -p) - Show files in a profile
 * 3. File History (with -p <file>) - Show commits affecting a file
 */

#include "cmds/list.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "base/timeutil.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "sys/gitops.h"
#include "sys/stats.h"
#include "sys/upstream.h"

/* Display configuration constants */
#define LIST_SHORT_OID_BUF_SIZE 8
#define LIST_TIMESTAMP_BUFFER_SIZE 64
#define LIST_MAX_MSG_ALIGN 60
#define LIST_MAX_NAME_ALIGN 40
#define LIST_MIN_NAME_ALIGN 12

/**
 * Print upstream state indicator
 *
 * Prints a colored upstream tracking indicator (e.g., [=], [↑3], [↕2+1])
 * directly to the output stream via the output_colored API.
 */
static void print_upstream_state(
    output_t *out,
    const upstream_info_t *info
) {
    if (!info) {
        return;
    }

    const char *symbol = upstream_state_symbol(info->state);
    output_color_t color = upstream_state_color(info->state);
    char label[32];

    switch (info->state) {
        case UPSTREAM_LOCAL_AHEAD:
            snprintf(
                label, sizeof(label), "[%s%zu]",
                symbol, info->ahead
            );
            break;
        case UPSTREAM_REMOTE_AHEAD:
            snprintf(
                label, sizeof(label), "[%s%zu]",
                symbol, info->behind
            );
            break;
        case UPSTREAM_DIVERGED:
            snprintf(
                label, sizeof(label), "[%s%zu+%zu]",
                symbol, info->ahead, info->behind
            );
            break;
        case UPSTREAM_UP_TO_DATE:
        case UPSTREAM_NO_REMOTE:
        case UPSTREAM_UNKNOWN:
        default:
            snprintf(
                label, sizeof(label), "[%s]",
                symbol
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
    state_t *state,
    arena_t *arena,
    const cmd_list_options_t *opts,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    bool verbose = output_is_verbose(out);

    /* Get all branches */
    string_array_t *branches = NULL;
    error_t *err = gitops_list_branches(repo, &branches);
    if (err) {
        return error_wrap(err, "Failed to list branches");
    }

    if (branches->count == 0) {
        string_array_free(branches);
        output_info(out, OUTPUT_NORMAL, "No profiles found");
        return NULL;
    }

    /* Detect remote if --remote flag is set */
    const char *remote_name = NULL;
    bool show_remote = false;
    if (opts->remote) {
        err = gitops_resolve_default_remote(repo, arena, &remote_name, NULL);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Could not detect remote: %s",
                error_message(err)
            );
            error_free(err);
            err = NULL;
        } else {
            show_remote = true;
        }
    }

    /* Calculate max branch name length for column alignment */
    size_t max_name_len = 0;
    if (verbose || show_remote) {
        for (size_t i = 0; i < branches->count; i++) {
            const char *bname = branches->items[i];
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
    output_section(out, OUTPUT_NORMAL, "Available profiles");

    /* List profiles */
    for (size_t i = 0; i < branches->count; i++) {
        const char *profile = branches->items[i];

        /* Skip dotta-worktree branch */
        if (strcmp(profile, "dotta-worktree") == 0) {
            continue;
        }

        bool is_enabled = state && state_has_profile(state, profile);
        const char *indicator = is_enabled ? "* " : "  ";

        /* Simple mode: Just name with enabled indicator */
        if (!verbose && !show_remote) {
            output_styled(
                out, OUTPUT_NORMAL, "  %s{cyan}%s{reset}\n",
                indicator, profile
            );
            continue;
        }

        /* Verbose: Load tree for stats */
        git_tree *tree = NULL;
        if (verbose) {
            err = gitops_load_branch_tree(repo, profile, &tree, NULL);
            if (err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to load profile '%s': %s",
                    profile, error_message(err)
                );
                error_free(err);
                err = NULL;
                /* tree stays NULL - stats skipped, name still shown */
            }
        }

        /* Start line with indicator and name */
        output_styled(
            out, OUTPUT_NORMAL, "  %s{cyan}%-*s{reset}",
            indicator, (int) max_name_len, profile
        );

        /* Verbose: Add stats (requires successfully loaded tree) */
        if (verbose && tree) {
            profile_stats_t stats = { 0 };
            error_t *stats_err = stats_get_profile_stats(repo, tree, &stats);
            if (!stats_err) {
                char size_str[32];
                output_format_size(stats.total_size, size_str, sizeof(size_str));
                output_print(
                    out, OUTPUT_VERBOSE, " %2zu file%s, %8s",
                    stats.file_count,
                    stats.file_count == 1 ? " " : "s", size_str
                );
            }
            error_free(stats_err);
        }

        /* Verbose: Add last commit info (uses branch name, not profile tree) */
        if (verbose) {
            char refname[DOTTA_REFNAME_MAX];
            error_t *ref_err = gitops_build_refname(
                refname, sizeof(refname), "refs/heads/%s", profile
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
                        out, OUTPUT_VERBOSE, "  {yellow}%s{reset} %.*s {dim}(%s){reset}",
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
            upstream_info_t info;
            error_t *upstream_err = upstream_analyze_profile(repo, remote_name, profile, &info);
            if (!upstream_err) {
                print_upstream_state(out, &info);
            } else {
                error_free(upstream_err);
            }
        }

        output_newline(out, OUTPUT_NORMAL);
        git_tree_free(tree);
    }

    /* Print remote legend if shown */
    if (show_remote) {
        output_newline(out, OUTPUT_NORMAL);
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
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(opts->profile);
    CHECK_NULL(out);

    bool verbose = output_is_verbose(out);

    /* List files */
    string_array_t *files = NULL;
    error_t *err = profile_list_files(repo, opts->profile, &files);
    if (err) {
        return error_wrap(
            err, "Failed to list files in profile '%s'",
            opts->profile
        );
    }

    if (files->count == 0) {
        output_info(out, OUTPUT_NORMAL, "No files in profile '%s'", opts->profile);
        string_array_free(files);
        return NULL;
    }

    /* Print header */
    output_section(out, OUTPUT_NORMAL, "Files in profile '%s'", opts->profile);
    output_newline(out, OUTPUT_NORMAL);

    /* Sort for consistent output */
    string_array_sort(files);

    /* Load tree and build file→commit map if verbose */
    git_tree *tree = NULL;
    file_commit_map_t *commit_map = NULL;
    if (verbose) {
        err = gitops_load_branch_tree(repo, opts->profile, &tree, NULL);
        if (!err) {
            err = stats_build_file_commit_map(repo, opts->profile, tree, &commit_map);
        }
        if (err) {
            /* Non-fatal: continue without commit info */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to load commit history: %s",
                error_message(err)
            );
            error_free(err);
            err = NULL;
        }
    }

    /* Load metadata for encryption status (verbose mode only) */
    metadata_t *metadata = NULL;
    if (verbose) {
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
    if (verbose) {
        for (size_t i = 0; i < files->count; i++) {
            size_t len = strlen(files->items[i]);
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
    for (size_t i = 0; i < files->count; i++) {
        const char *file_path = files->items[i];

        /* Print file path (with alignment in verbose mode) */
        if (verbose) {
            /* Verbose: Left-align with padding for column alignment */
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}%-*s{reset}",
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
        if (verbose) {
            /* Get file stats */
            git_tree_entry *entry = NULL;
            int git_err = tree ? git_tree_entry_bypath(&entry, tree, file_path) : -1;
            if (git_err == 0) {
                /* Check encryption status and display indicator */
                bool encrypted = metadata_get_file_encrypted(metadata, file_path);
                if (encrypted) {
                    output_styled(
                        out, OUTPUT_VERBOSE, "  {yellow}[E]{reset} "
                    );
                } else {
                    /* Space padding to maintain alignment */
                    output_print(
                        out, OUTPUT_VERBOSE, "      "
                    );
                }

                /* Get blob size efficiently */
                size_t size;
                error_t *stats_err = stats_get_blob_size(
                    repo, git_tree_entry_id(entry), &size
                );
                if (!stats_err) {
                    /* Show plaintext content size for encrypted blobs by
                     * subtracting the cipher's framing overhead. The
                     * helper keeps crypto/cipher.h imports out of the
                     * command layer (only infra/content and the crypto
                     * layer itself import cipher.h). */
                    content_kind_t kind = encrypted
                                        ? CONTENT_ENCRYPTED
                                        : CONTENT_PLAINTEXT;
                    size_t display_size =
                        content_estimated_plaintext_size(kind, size);

                    char size_str[32];
                    output_format_size(display_size, size_str, sizeof(size_str));
                    output_print(out, OUTPUT_VERBOSE, " %8s", size_str);
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
                        if (summary_len > 40) summary_len = 40;

                        output_styled(
                            out, OUTPUT_VERBOSE, "  {yellow}%s{reset} %.*s {dim}(%s){reset}",
                            oid_str, (int) summary_len, commit_info->summary, time_str
                        );
                    }
                }

                git_tree_entry_free(entry);
            } else {
                /* Tree entry lookup failed unexpectedly */
                output_styled(out, OUTPUT_VERBOSE, "  {dim}[?]{reset}");
            }
        }

        output_newline(out, OUTPUT_NORMAL);
    }

    /* Print summary */
    output_newline(out, OUTPUT_NORMAL);
    if (verbose) {
        char size_str[32];
        output_format_size(total_size, size_str, sizeof(size_str));
        output_print(
            out, OUTPUT_VERBOSE, "Total: %zu file%s, %s\n",
            files->count,
            files->count == 1 ? "" : "s", size_str
        );
    } else {
        output_print(
            out, OUTPUT_NORMAL, "Total: %zu file%s\n",
            files->count,
            files->count == 1 ? "" : "s"
        );
    }

    /* Cleanup */
    if (commit_map) {
        stats_free_file_commit_map(commit_map);
    }
    if (metadata) {
        metadata_free(metadata);
    }
    if (tree) {
        git_tree_free(tree);
    }
    string_array_free(files);

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
    const state_t *state,
    arena_t *arena,
    const cmd_list_options_t *opts,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(opts);
    CHECK_NULL(opts->file_path);
    CHECK_NULL(out);

    bool verbose = output_is_verbose(out);
    char *discovered_profile = NULL;

    /* Build mount table over all enabled profiles for path resolution. */
    mount_table_t *mounts = NULL;
    error_t *mounts_err = profile_build_mount_table(state, NULL, arena, &mounts);
    if (mounts_err) {
        return error_wrap(mounts_err, "Failed to build mount table");
    }

    /* Resolve input path to storage format (handles absolute, tilde, relative,
     * and storage paths). File need not exist on disk. */
    char *storage_path = NULL;
    error_t *err = mount_resolve_input(opts->file_path, mounts, &storage_path);
    if (err) {
        return error_wrap(err, "Failed to resolve path '%s'", opts->file_path);
    }

    /* Resolve owning profile: explicit from user or implicit via manifest */
    const char *profile = opts->profile;

    if (!profile) {
        string_array_t *matches = NULL;
        err = profile_discover_file(repo, state, storage_path, true, &matches);
        if (err) {
            if (error_code(err) == ERR_NOT_FOUND) {
                error_free(err);
                err = ERROR(
                    ERR_NOT_FOUND, "File '%s' not found in enabled profiles\n"
                    "Hint: Use 'dotta list -p <profile> %s' to specify a profile",
                    storage_path, opts->file_path
                );
            }
            free(storage_path);
            return err;
        }

        discovered_profile = strdup(matches->items[0]);
        string_array_free(matches);
        if (!discovered_profile) {
            free(storage_path);
            return ERROR(ERR_MEMORY, "Failed to allocate profile name");
        }
        profile = discovered_profile;
    }

    /* Verify profile exists and check if file is in current tree (fast pre-check).
     * This validates the profile early and gives a clear hint for typos/deleted files
     * before the expensive O(total_commits) history walk. */
    git_tree *tree = NULL;
    err = gitops_load_branch_tree(repo, profile, &tree, NULL);
    if (err) {
        error_t *wrapped = error_wrap(err, "Profile '%s' not found", profile);
        free(discovered_profile);
        free(storage_path);
        return wrapped;
    }

    git_tree_entry *check = NULL;
    if (git_tree_entry_bypath(&check, tree, storage_path) != 0) {
        output_info(out, OUTPUT_NORMAL, "File not in current tree, searching history...");
    } else {
        git_tree_entry_free(check);
    }
    git_tree_free(tree);

    /* Get file history */
    file_history_t *history = NULL;
    err = stats_get_file_history(repo, profile, storage_path, &history);
    if (err) {
        error_t *wrapped = error_wrap(
            err, "Failed to get history for '%s' in profile '%s'",
            storage_path, profile
        );
        free(discovered_profile);
        free(storage_path);
        return wrapped;
    }

    /* Print header */
    output_section(
        out, OUTPUT_NORMAL, "History of '%s' in profile '%s'",
        storage_path, profile
    );
    output_newline(out, OUTPUT_NORMAL);

    /* Calculate max message length for alignment (oneline mode only) */
    size_t max_msg_len = 0;
    if (!verbose) {
        for (size_t i = 0; i < history->count; i++) {
            size_t len = strlen(history->commits[i].summary);
            if (len > max_msg_len) max_msg_len = len;
        }

        /* Cap to prevent excessive padding from long commit messages */
        if (max_msg_len > LIST_MAX_MSG_ALIGN) {
            max_msg_len = LIST_MAX_MSG_ALIGN;
        }
    }

    /* Print commits */
    for (size_t i = 0; i < history->count; i++) {
        commit_info_t *commit = &history->commits[i];

        if (verbose) {
            /* Verbose: Full commit format */
            char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
            git_oid_tostr(oid_str, sizeof(oid_str), &commit->oid);

            output_styled(
                out, OUTPUT_VERBOSE, "{bold}commit {yellow}%s{reset}\n",
                oid_str
            );

            /* Display timestamp if valid */
            char date_buf[LIST_TIMESTAMP_BUFFER_SIZE];
            if (format_time(commit->time, date_buf, sizeof(date_buf))) {
                char relative_str[64];
                format_relative_time(commit->time, relative_str, sizeof(relative_str));

                output_styled(
                    out, OUTPUT_VERBOSE, "Date:   %s {dim}(%s){reset}\n",
                    date_buf, relative_str
                );
            }

            output_print(out, OUTPUT_VERBOSE, "\n    %s\n", commit->summary);

            if (i < history->count - 1) {
                output_newline(out, OUTPUT_NORMAL);
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
error_t *cmd_list(const dotta_ctx_t *ctx, const cmd_list_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    output_t *out = ctx->out;

    error_t *err = NULL;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Warn about flags that don't apply to the current mode */
    if (opts->remote && opts->mode != LIST_PROFILES) {
        output_warning(out, OUTPUT_NORMAL, "--remote only applies when listing profiles");
    }

    /* Dispatch to appropriate list function based on mode */
    if (opts->mode == LIST_PROFILES) {
        err = list_profiles(repo, ctx->state, ctx->arena, opts, out);
    } else if (opts->mode == LIST_FILES) {
        err = list_files(repo, opts, out);
    } else if (opts->mode == LIST_FILE_HISTORY) {
        err = list_file_history(repo, ctx->state, ctx->arena, opts, out);
    } else {
        err = ERROR(ERR_INVALID_ARG, "Invalid list mode");
    }

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Infer list mode from positionals and derive `profile` / `file_path`.
 *
 * Legacy form:
 *   - No positional:           mode = LIST_PROFILES
 *   - 1 positional (file path): mode = LIST_FILE_HISTORY (profile inferred)
 *   - 1 positional (profile):   mode = LIST_FILES
 *   - 2 positionals:            mode = LIST_FILE_HISTORY (profile, file)
 *
 * Classification uses str_looks_like_file_path to distinguish a bare
 * profile name from a file path.
 */
static error_t *list_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_list_options_t *o = opts_v;

    if (o->positional_count == 0) {
        o->mode = LIST_PROFILES;
        return NULL;
    }

    if (o->positional_count == 1) {
        const char *arg = o->positional_args[0];
        if (str_looks_like_file_path(arg)) {
            o->mode = LIST_FILE_HISTORY;
            o->file_path = arg;
        } else {
            o->mode = LIST_FILES;
            o->profile = arg;
        }
        return NULL;
    }

    if (o->positional_count == 2) {
        o->mode = LIST_FILE_HISTORY;
        o->profile = o->positional_args[0];
        o->file_path = o->positional_args[1];
        return NULL;
    }

    /* Max=2 enforced by POSITIONAL_RAW — unreachable. */
    return ERROR(ERR_INTERNAL, "list: too many positionals");
}

static error_t *list_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_list(ctx, (const cmd_list_options_t *) opts_v);
}

static const args_opt_t list_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",       "<name>",
        cmd_list_options_t,profile,
        "Profile name (alternative to positional)"
    ),
    ARGS_FLAG(
        "remote",
        cmd_list_options_t,remote,
        "Show remote tracking state (Level 1 only)"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_list_options_t,verbose,
        "Show detailed output"
    ),
    ARGS_POSITIONAL_RAW(
        cmd_list_options_t,positional_args, positional_count,
        0,                 2
    ),
    ARGS_END,
};

const args_command_t spec_list = {
    .name        = "list",
    .summary     = "List profiles, files, and commit history",
    .usage       =
        "%s list [options]\n"
        "   or: %s list [options] <profile>\n"
        "   or: %s list [options] <file>\n"
        "   or: %s list [options] <profile> <file>",
    .description =
        "Mode Inference:\n"
        "  No positional              Level 1: all profiles.\n"
        "  1 arg, looks like a path   Level 3: file history, profile inferred.\n"
        "  1 arg, looks like a name   Level 2: files in that profile.\n"
        "  2 args                     Level 3: file history in profile.\n",
    .notes       =
        "Verbose Mode Details:\n"
        "  Level 1    File count, total size, and last commit per profile.\n"
        "  Level 2    File sizes and per-file last commits.\n"
        "  Level 3    Full commit messages instead of oneline format.\n"
        "\n"
        "Remote State Indicators (with --remote):\n"
        "  [=]    up-to-date with remote\n"
        "  [^n]   n commits ahead of remote (run '%s sync' to push)\n"
        "  [vn]   n commits behind remote (run '%s sync' to pull)\n"
        "  [<>]   diverged from remote (manual resolution needed)\n"
        "  [.]    no remote tracking branch (created on first sync)\n",
    .examples    =
        "  %s list                           # L1 profiles: names only\n"
        "  %s list -v                        # L1 profiles: stats + last commit\n"
        "  %s list --remote                  # L1 profiles: remote tracking state\n"
        "  %s list -v --remote               # L1 profiles: full details + remote\n"
        "  %s list global                    # L2 files: paths only\n"
        "  %s list global -v                 # L2 files: sizes + commits\n"
        "  %s list home/.bashrc              # L3 history: oneline commits\n"
        "  %s list global home/.bashrc -v    # L3 history: full commit messages\n",
    .epilogue    =
        "See also:\n"
        "  %s show <commit>             # Show commit with diff\n"
        "  %s diff <commit> <commit>    # Compare two commits\n",
    .opts_size   = sizeof(cmd_list_options_t),
    .opts        = list_opts,
    .post_parse  = list_post_parse,
    .payload     = &dotta_ext_read,
    .dispatch    = list_dispatch,
};
