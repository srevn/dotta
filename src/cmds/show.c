/**
 * show.c - Show file content or commit details
 */

#include "cmds/show.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/args.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/output.h"
#include "base/refspec.h"
#include "base/string.h"
#include "base/timeutil.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "crypto/keymgr.h"
#include "infra/content.h"
#include "infra/path.h"
#include "sys/gitops.h"

/**
 * Check if content appears to be binary
 *
 * Scans for NUL bytes in the first 8000 bytes, matching Git's heuristic.
 * Must be called on plaintext content (after decryption).
 */
static bool content_is_binary(const unsigned char *data, size_t size) {
    size_t check_len = size < 8000 ? size : 8000;
    return memchr(data, '\0', check_len) != NULL;
}

/**
 * Get human-readable file type from git filemode
 */
static const char *filemode_type_str(git_filemode_t mode) {
    switch (mode) {
        case GIT_FILEMODE_BLOB_EXECUTABLE: return "executable";
        case GIT_FILEMODE_LINK:            return "symlink";
        case GIT_FILEMODE_BLOB:            return "regular file";
        default:                           return "file";
    }
}

/**
 * Print blob content with metadata header
 *
 * Uses content layer for transparent decryption. Password prompt only
 * happens if file is encrypted and key is not cached.
 *
 * Handles symlinks (shows target), binary files (shows size without
 * dumping content), and encrypted files (indicates decryption occurred).
 */
static error_t *print_blob_content(
    git_repository *repo,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile,
    const metadata_t *metadata,
    keymgr *keymgr,
    git_filemode_t filemode,
    bool raw,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(metadata);
    CHECK_NULL(out);

    /* Get plaintext content (handles encryption transparently) */
    bool encrypted = metadata_get_file_encrypted(metadata, storage_path);

    buffer_t content = BUFFER_INIT;
    error_t *err = content_get_from_blob_oid(
        repo, blob_oid, storage_path, profile, encrypted, keymgr, &content
    );
    if (err) {
        return error_wrap(err, "Failed to get file content");
    }

    /* Symlinks: content is the target path */
    if (filemode == GIT_FILEMODE_LINK) {
        if (!raw) {
            output_styled(
                out, OUTPUT_NORMAL, "{dim}# Type:{reset}    symlink\n"
            );
            output_styled(
                out, OUTPUT_NORMAL, "{dim}# Target:{reset}  %.*s\n",
                (int) content.size, (const char *) content.data
            );
        } else {
            fwrite(content.data, 1, content.size, stdout);
            const char *data = (const char *) content.data;
            if (content.size > 0 &&
                data[content.size - 1] != '\n') {
                fputc('\n', stdout);
            }
        }
        buffer_free(&content);
        return NULL;
    }

    /* Binary detection (on plaintext, after decryption) */
    if (content.size > 0 &&
        content_is_binary((const unsigned char *) content.data, content.size)) {
        if (!raw) {
            char size_buf[32];
            output_format_size(content.size, size_buf, sizeof(size_buf));

            output_styled(
                out, OUTPUT_NORMAL, "{dim}# Type:{reset}    binary file"
            );
            if (encrypted) {
                output_print(
                    out, OUTPUT_NORMAL, " (encrypted)"
                );
            }
            output_newline(out, OUTPUT_NORMAL);
            output_styled(
                out, OUTPUT_NORMAL, "{dim}# Size:{reset}    %s\n",
                size_buf
            );
        }
        /* Don't dump binary content to terminal */
        buffer_free(&content);
        return NULL;
    }

    if (!raw) {
        /* File type */
        output_styled(
            out, OUTPUT_NORMAL, "{dim}# Type:{reset}    %s",
            filemode_type_str(filemode)
        );
        if (encrypted) {
            output_print(out, OUTPUT_NORMAL, " (encrypted)");
        }
        output_newline(out, OUTPUT_NORMAL);

        /* Mode and ownership from metadata */
        const metadata_item_t *item = NULL;
        error_t *meta_err = metadata_get_item(metadata, storage_path, &item);
        if (meta_err) {
            error_free(meta_err);
            item = NULL;
        }
        if (item) {
            output_styled(
                out, OUTPUT_NORMAL, "{dim}# Mode:{reset}    %04o\n",
                (unsigned) item->mode
            );
            if (item->owner) {
                output_styled(
                    out, OUTPUT_NORMAL, "{dim}# Owner:{reset}   %s:%s\n",
                    item->owner, item->group ? item->group : ""
                );
            }
        }

        /* Size */
        char size_buf[32];
        output_format_size(content.size, size_buf, sizeof(size_buf));
        output_styled(
            out, OUTPUT_NORMAL, "{dim}# Size:{reset}    %s\n",
            size_buf
        );

        output_styled(
            out, OUTPUT_NORMAL, "{dim}---{reset}\n"
        );
    }

    /* Write content to stdout */
    if (content.size > 0) {
        fwrite(content.data, 1, content.size, stdout);

        /* Ensure trailing newline */
        const char *data = (const char *) content.data;
        if (data[content.size - 1] != '\n') {
            fputc('\n', stdout);
        }
    }

    buffer_free(&content);

    return NULL;
}

/**
 * Show file from a specific profile (optionally at specific commit)
 */
static error_t *show_file(
    git_repository *repo,
    const char *profile,
    const char *file_path,
    const char *commit_ref,
    bool raw,
    const config_t *config,
    output_ctx_t *out
) {
    error_t *err = NULL;
    git_tree *tree = NULL;
    git_tree_entry *entry = NULL;
    git_commit *commit = NULL;
    git_oid commit_oid;
    metadata_t *metadata = NULL;

    /*
     * Get global keymgr for decryption (if needed)
     *
     * This does NOT prompt for password yet. Password prompt only happens
     * if file is encrypted and key is not cached, when content layer calls
     * keymgr_get_key().
     */
    keymgr *keymgr = keymgr_get_global(config);

    /* Load metadata for encryption state validation */
    err = metadata_load_from_branch(repo, profile, &metadata);
    if (err) {
        /* Non-fatal: metadata file might not exist yet (new profile) */
        /* Create empty metadata for validation (won't have file entries) */
        error_t *create_err = metadata_create_empty(&metadata);
        if (create_err) {
            error_free(create_err);
            err = ERROR(ERR_MEMORY, "Failed to create metadata");
            goto cleanup;
        }
        error_free(err);
        err = NULL;
    }

    /* Load tree from profile */
    if (commit_ref) {
        /* Resolve commit and load its tree */
        err = gitops_resolve_commit_in_branch(
            repo, profile, commit_ref, &commit_oid, &commit
        );
        if (err) goto cleanup;

        err = gitops_get_tree_from_commit(repo, &commit_oid, &tree);
        if (err) {
            err = error_wrap(err, "Failed to load tree from commit '%s'", commit_ref);
            goto cleanup;
        }

        /* Print commit context if not raw */
        if (!raw && commit) {
            char oid_str[8];
            git_oid_tostr(oid_str, sizeof(oid_str), &commit_oid);

            const git_signature *author = git_commit_author(commit);
            time_t commit_time = (time_t) author->when.time;
            char time_str[64];
            format_relative_time(commit_time, time_str, sizeof(time_str));

            output_styled(
                out, OUTPUT_NORMAL, "{dim}# Commit:{reset}  {yellow}%s{reset}\n",
                oid_str
            );
            output_styled(
                out, OUTPUT_NORMAL, "{dim}# Date:{reset}    %s\n",
                time_str
            );
            output_styled(
                out, OUTPUT_NORMAL, "{dim}# Author:{reset}  %s <%s>\n",
                author->name, author->email
            );

            /* Show first line of commit message */
            const char *msg = git_commit_message(commit);
            if (msg) {
                const char *newline = strchr(msg, '\n');
                if (newline) {
                    output_styled(
                        out, OUTPUT_NORMAL, "{dim}# Message:{reset} %.*s\n",
                        (int) (newline - msg), msg
                    );
                } else {
                    output_styled(
                        out, OUTPUT_NORMAL, "{dim}# Message:{reset} %s\n",
                        msg
                    );
                }
            }
        }
    } else {
        /* Load from branch HEAD */
        err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            err = error_wrap(err, "Failed to load tree for profile '%s'", profile);
            goto cleanup;
        }
    }

    /* Find file in tree */
    err = gitops_find_file_in_tree(tree, file_path, &entry);
    if (err) {
        goto cleanup;
    }

    /* Get entry type, OID, and filemode */
    git_object_t entry_type = git_tree_entry_type(entry);
    const git_oid *entry_oid = git_tree_entry_id(entry);
    git_filemode_t filemode = git_tree_entry_filemode(entry);

    if (entry_type == GIT_OBJECT_BLOB) {
        /*
         * Print file content with transparent decryption
         *
         * file_path is the storage_path (e.g., "home/.bashrc")
         * profile is used for key derivation
         * metadata is used for encryption state validation
         * keymgr will prompt for password only if file is encrypted
         */
        err = print_blob_content(
            repo, entry_oid, file_path, profile, metadata, keymgr, filemode, raw, out
        );
    } else if (entry_type == GIT_OBJECT_TREE) {
        err = ERROR(ERR_INVALID_ARG, "'%s' is a directory", file_path);
    } else {
        err = ERROR(ERR_INTERNAL, "Unexpected object type for '%s'", file_path);
    }

cleanup:
    if (metadata) metadata_free(metadata);
    if (entry) git_tree_entry_free(entry);
    if (tree) git_tree_free(tree);
    if (commit) git_commit_free(commit);

    return err;
}

/**
 * Callback for printing diff lines with color
 *
 * Colorizes additions (green), deletions (red), and headers (cyan).
 * Matches the diff command's output style.
 */
static int print_diff_line_cb(
    const git_diff_delta *delta,
    const git_diff_hunk *hunk,
    const git_diff_line *line,
    void *payload
) {
    output_ctx_t *out = (output_ctx_t *) payload;
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
    if (line->content_len == 0 ||
        line->content[line->content_len - 1] != '\n') {
        output_print(out, OUTPUT_NORMAL, "\n");
    }

    return 0;
}

/**
 * Show commit with diff
 */
static error_t *show_commit(
    git_repository *repo,
    const char *commit_ref,
    const char *profile,
    bool raw,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(commit_ref);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    error_t *err = NULL;
    git_oid commit_oid;
    git_commit *commit = NULL;
    git_tree *commit_tree = NULL;
    git_tree *parent_tree = NULL;
    git_diff *diff = NULL;
    git_diff_stats *stats = NULL;

    /* Resolve commit in profile */
    err = gitops_resolve_commit_in_branch(
        repo, profile, commit_ref, &commit_oid, &commit
    );
    if (err) {
        err = error_wrap(
            err, "Commit '%s' not found in profile '%s'",
            commit_ref, profile
        );
        goto cleanup;
    }

    /* Get commit tree */
    err = gitops_get_tree_from_commit(repo, &commit_oid, &commit_tree);
    if (err) {
        goto cleanup;
    }

    /* Get parent tree (NULL if first commit) */
    unsigned int parent_count = git_commit_parentcount(commit);
    if (parent_count > 0) {
        const git_oid *parent_oid = git_commit_parent_id(commit, 0);
        err = gitops_get_tree_from_commit(repo, parent_oid, &parent_tree);
        if (err) goto cleanup;
    }

    /* Generate diff between parent and commit */
    err = gitops_diff_trees(repo, parent_tree, commit_tree, NULL, &diff);
    if (err) {
        goto cleanup;
    }

    if (!raw) {
        /* Commit header with color (matching diff command style) */
        char oid_str[8];
        git_oid_tostr(oid_str, sizeof(oid_str), &commit_oid);

        const git_signature *author = git_commit_author(commit);
        time_t commit_time = (time_t) author->when.time;

        struct tm tm_info;
        localtime_r(&commit_time, &tm_info);
        char time_buf[64];
        strftime(
            time_buf, sizeof(time_buf), "%a %b %d %H:%M:%S %Y",
            &tm_info
        );

        char relative_buf[64];
        format_relative_time(commit_time, relative_buf, sizeof(relative_buf));

        output_styled(
            out, OUTPUT_NORMAL, "{yellow}commit %s{reset} {cyan}(%s){reset}\n",
            oid_str, profile
        );

        output_styled(
            out, OUTPUT_NORMAL, "{bold}Author:{reset} %s <%s>\n",
            author->name, author->email
        );

        output_styled(
            out, OUTPUT_NORMAL, "{bold}Date:{reset}   %s (%s)\n",
            time_buf, relative_buf
        );

        output_newline(out, OUTPUT_NORMAL);

        /* Commit message (indented) */
        const char *msg = git_commit_message(commit);
        if (msg) {
            const char *line = msg;
            while (line && *line) {
                const char *next = strchr(line, '\n');
                if (next) {
                    output_print(
                        out, OUTPUT_NORMAL, "    %.*s\n", (int) (next - line), line
                    );
                    line = next + 1;
                } else {
                    output_print(
                        out, OUTPUT_NORMAL, "    %s\n", line
                    );
                    break;
                }
            }
        }

        output_newline(out, OUTPUT_NORMAL);

        /* Diff stats with color */
        err = gitops_diff_get_stats(diff, &stats);
        if (err) goto cleanup;

        size_t files_changed = git_diff_stats_files_changed(stats);
        size_t insertions = git_diff_stats_insertions(stats);
        size_t deletions = git_diff_stats_deletions(stats);

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

        output_print(out, OUTPUT_NORMAL, "\n\n");
    }

    /* Print the diff with color */
    int ret = git_diff_print(
        diff, GIT_DIFF_FORMAT_PATCH, print_diff_line_cb, out
    );
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

cleanup:
    if (stats) git_diff_stats_free(stats);
    if (diff) git_diff_free(diff);
    if (parent_tree) git_tree_free(parent_tree);
    if (commit_tree) git_tree_free(commit_tree);
    if (commit) git_commit_free(commit);

    return err;
}

/**
 * Show command implementation
 */
error_t *cmd_show(const args_ctx_t *ctx, const cmd_show_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    const config_t *config = ctx->config;
    output_ctx_t *out = ctx->out;

    error_t *err = NULL;
    string_array_t *profiles = NULL;
    string_array_t *matches = NULL;
    string_array_t *prefixes = NULL;
    char *converted = NULL;
    const char *found_profile = NULL;

    /* Handle SHOW_COMMIT mode */
    if (opts->mode == SHOW_COMMIT) {
        CHECK_NULL(opts->commit);

        /* Determine which profile to search */
        const char *profile = opts->profile;

        if (!profile) {
            /* No profile specified - use enabled profiles */
            err = profile_resolve_enabled(repo, NULL, &profiles);
            if (err) {
                if (error_code(err) == ERR_NOT_FOUND) {
                    error_free(err);
                    err = ERROR(
                        ERR_NOT_FOUND,
                        "No enabled profiles found\n\n"
                        "To search a specific profile:\n"
                        "  dotta show -p <profile> %s\n\n"
                        "To enable profiles:\n"
                        "  dotta profile enable <name>",
                        opts->commit
                    );
                } else {
                    err = error_wrap(err, "Failed to load profiles");
                }
                goto cleanup;
            }

            /* Try to find commit in enabled profiles (in order) */
            for (size_t i = 0; i < profiles->count; i++) {
                profile = profiles->items[i];
                error_t *try_err = show_commit(
                    repo, opts->commit, profile, opts->raw, out
                );

                /* If found, we're done */
                if (!try_err) {
                    goto cleanup;
                }

                /* If error is not "commit not found", save and bail out */
                if (try_err->code != ERR_NOT_FOUND) {
                    err = try_err;
                    goto cleanup;
                }

                error_free(try_err);
            }

            err = ERROR(
                ERR_NOT_FOUND, "Commit '%s' not found in enabled profiles",
                opts->commit
            );
            goto cleanup;
        }

        /* Profile specified - show commit from that profile */
        bool exists = false;
        err = gitops_branch_exists(repo, profile, &exists);
        if (err) goto cleanup;
        if (!exists) {
            err = ERROR(ERR_NOT_FOUND, "Profile '%s' not found", profile);
            goto cleanup;
        }

        err = show_commit(repo, opts->commit, profile, opts->raw, out);
        goto cleanup;
    }

    /* Handle SHOW_FILE mode */
    CHECK_NULL(opts->file_path);

    /* Load custom prefixes for path resolution (non-fatal) */
    error_t *prefix_err = profile_load_custom_prefixes(repo, &prefixes);
    if (prefix_err) error_free(prefix_err);

    /* Resolve file path to storage format (common to both explicit and implicit paths) */
    const char *search_path = opts->file_path;
    error_t *convert_err = path_resolve_input(
        opts->file_path, prefixes ? (const char *const *) prefixes->items : NULL,
        prefixes ? prefixes->count : 0, &converted
    );
    if (convert_err) {
        error_free(convert_err);
        /* Fall back to original path (may be a partial match pattern) */
        search_path = opts->file_path;
    } else {
        search_path = converted;
    }

    if (opts->profile) {
        /* Profile specified - show from that profile */
        bool exists = false;
        err = gitops_branch_exists(repo, opts->profile, &exists);
        if (err) goto cleanup;
        if (!exists) {
            err = ERROR(ERR_NOT_FOUND, "Profile '%s' not found", opts->profile);
            goto cleanup;
        }

        err = show_file(
            repo, opts->profile, search_path, opts->commit, opts->raw, config, out
        );
        goto cleanup;
    }

    /* No profile specified - resolve owning profile via manifest */

    /* File at specific commit requires explicit profile for unambiguous resolution */
    if (opts->commit) {
        err = ERROR(
            ERR_INVALID_ARG,
            "Showing a file at a specific commit requires a profile\n"
            "Hint: Use 'dotta show -p <profile> <file> <commit>'"
        );
        goto cleanup;
    }

    /* Discover owning profile via manifest (O(1) indexed lookup) */
    err = profile_discover_file(repo, NULL, search_path, true, &matches);
    if (err) {
        if (error_code(err) == ERR_NOT_FOUND) {
            error_free(err);
            err = ERROR(
                ERR_NOT_FOUND, "File '%s' not found in enabled profiles",
                opts->file_path
            );
        }
        goto cleanup;
    }

    found_profile = matches->items[0];

    /* Show the file */
    if (!opts->raw) {
        output_styled(
            out, OUTPUT_NORMAL, "{dim}# Profile:{reset} %s\n",
            found_profile
        );
        output_styled(
            out, OUTPUT_NORMAL, "{dim}# Path:{reset}    %s\n",
            search_path
        );
    }
    err = show_file(
        repo, found_profile, search_path, NULL, opts->raw, config, out
    );

cleanup:
    string_array_free(profiles);
    string_array_free(prefixes);
    if (matches) string_array_free(matches);
    if (converted) free(converted);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Interpret the 0-3 raw positionals into `profile`, `file_path`,
 * `commit`, and `mode`.
 *
 * Allocation model: all refspec strings are allocated in `arena`.
 * Pure positional pointers borrow argv. cmd_show does not free any of
 * these pointers — the engine's arena owns their lifetime.
 */
static error_t *show_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) cmd;
    cmd_show_options_t *o = opts_v;

    if (o->positional_count == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "target argument is required (profile, file, or commit)"
        );
    }

    char **args = o->positional_args;

    if (o->positional_count == 1) {
        const char *arg = args[0];

        /* Pure commit ref: git ref without path separators. */
        if (str_looks_like_git_ref(arg) && !strchr(arg, '/') &&
            !strchr(arg, '.')) {
            o->mode = SHOW_COMMIT;
            o->commit = arg;
            return NULL;
        }

        /* File mode: parse [profile:]file[@commit] into arena. */
        o->mode = SHOW_FILE;
        char *profile = NULL;
        char *file = NULL;
        char *commit = NULL;
        error_t *err = parse_refspec(arena, arg, &profile, &file, &commit);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse file specification");
        }
        /* A refspec-supplied profile overrides any -p/--profile flag. */
        if (profile != NULL) o->profile = profile;
        o->file_path = file;
        if (commit != NULL) o->commit = commit;
        return NULL;
    }

    if (o->positional_count == 2) {
        o->mode = SHOW_FILE;

        if (str_looks_like_git_ref(args[1])) {
            /* <file> <commit> */
            o->file_path = args[0];
            o->commit = args[1];
            return NULL;
        }

        /* <profile> <file[@commit]> — refspec profile wins if present. */
        o->profile = args[0];
        char *profile = NULL;
        char *file = NULL;
        char *commit = NULL;
        error_t *err = parse_refspec(arena, args[1], &profile, &file, &commit);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse file specification");
        }
        if (profile != NULL) o->profile = profile;
        o->file_path = file;
        if (commit != NULL) o->commit = commit;
        return NULL;
    }

    if (o->positional_count == 3) {
        o->mode = SHOW_FILE;
        o->profile = args[0];
        o->file_path = args[1];
        o->commit = args[2];
        return NULL;
    }

    /* Max=3 is enforced by POSITIONAL_RAW; this branch is unreachable. */
    return ERROR(ERR_INTERNAL, "show: too many positionals");
}

static error_t *show_dispatch(const args_ctx_t *ctx, void *opts_v) {
    return cmd_show(ctx, (const cmd_show_options_t *) opts_v);
}

static const args_opt_t show_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",       "<name>",
        cmd_show_options_t,profile,
        "Override profile for file or commit lookup"
    ),
    ARGS_FLAG(
        "raw",
        cmd_show_options_t,raw,
        "Print raw file content without formatting"
    ),
    ARGS_POSITIONAL_RAW(
        cmd_show_options_t,positional_args, positional_count,
        0,                 3
    ),
    ARGS_END,
};

const args_command_t spec_show = {
    .name        = "show",
    .summary     = "Show file content or commit details",
    .usage       =
        "%s show [options] <target>\n"
        "   or: %s show [options] <commit>\n"
        "   or: %s show [options] <file> <commit>\n"
        "   or: %s show [options] <profile>:<file>@<commit>\n"
        "   or: %s show [options] <profile> <file> <commit>",
    .description =
        "Inspect a single profile object: a commit, a file at HEAD, or a\n"
        "file at a specific commit. Mode is inferred from the positional\n"
        "shape; refspec forms pack the same selection into one token.\n",
    .notes       =
        "Commit Mode:\n"
        "  Triggered when the first positional parses as a Git ref (SHA,\n"
        "  HEAD, HEAD~N). Prints commit metadata, file change statistics,\n"
        "  and the full unified diff (equivalent to 'git show').\n"
        "\n"
        "File Mode:\n"
        "  Prints file content from the profile branch. Without -p, the\n"
        "  search runs across enabled profiles for an exact path match.\n"
        "  Paths accept either form: filesystem (~/.bashrc, /etc/hosts)\n"
        "  or storage (home/.bashrc, root/etc/hosts).\n",
    .examples    =
        "  %s show a4f2c8e                          # Commit from enabled profiles\n"
        "  %s show -p global a4f2c8e                # Commit from a specific profile\n"
        "  %s show home/.bashrc                     # File at HEAD, search profiles\n"
        "  %s show -p global home/.bashrc           # File at HEAD, specific profile\n"
        "  %s show global:home/.bashrc              # File at HEAD via refspec\n"
        "  %s show darwin home/.bashrc a4f2c8e      # File at commit, positional\n"
        "  %s show home/.bashrc@a4f2c8e             # File at commit via refspec\n"
        "  %s show global:home/.bashrc@a4f2c8e      # File at commit, full refspec\n",
    .epilogue    =
        "See also:\n"
        "  %s list <profile> <file>   # Commit history for a file\n"
        "  %s diff <commit> <commit>  # Compare two commits\n",
    .opts_size   = sizeof(cmd_show_options_t),
    .opts        = show_opts,
    .post_parse  = show_post_parse,
    .repo_mode   = ARGS_REPO_REQUIRED,
    .dispatch    = show_dispatch,
};
