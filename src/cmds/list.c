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
#include "base/timeutil.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "infra/path.h"
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
 * Prints a colored upstream tracking indicator (e.g., [=], [↑3], [↕2+1]) directly
 * to the output stream via the output_colored API.
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
 * One verbose profile line's measured facts
 *
 * Read from the branch before anything prints, because both fields set columns
 * measured across every branch, the way the name column already is. An empty
 * phrase is a branch whose statistics could not be read — its line still prints,
 * without them.
 *
 * Buffer sizes are the minimums output_format_counts and output_format_size state.
 */
typedef struct {
    char counts[64];
    char size[32];
} profile_line_t;

/**
 * List profiles - Level 1
 *
 * Default: Just profile names Verbose: Add stats (file count, size, last commit)
 * Remote:  Add tracking indicators
 */
static error_t *list_profiles(
    const dotta_ctx_t *ctx,
    const cmd_list_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    output_t *out = ctx->out;

    bool verbose = output_is_verbose(out);

    /* Every profile here */
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
        err = gitops_resolve_default_remote(repo, ctx->arena, &remote_name, NULL);
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

    /* Read what each branch holds, and measure the columns it needs. Both are
     * as wide as the branches make them — the counts phrase names only the kinds
     * a branch actually has, and a size runs from "0 B" to four digits and a
     * unit — so neither is guessed. One profile_get_stats per branch, the expensive
     * part of a verbose line, runs here rather than again at render time; a branch
     * that cannot be read is warned about and left with an empty phrase, in the
     * words the other screen of this file uses for the same producer's refusal:
     * what failed is the count, however far down the read it failed. */
    profile_line_t *lines = NULL;
    size_t max_counts_len = 0;
    size_t max_size_len = 0;
    if (verbose) {
        lines = calloc(branches->count, sizeof(*lines));
        if (!lines) {
            string_array_free(branches);
            return ERROR(ERR_MEMORY, "Failed to allocate profile lines");
        }

        for (size_t i = 0; i < branches->count; i++) {
            const char *bname = branches->items[i];

            profile_stats_t stats = { 0 };
            err = profile_get_stats(repo, bname, &stats);
            if (err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to count what profile '%s' holds: %s",
                    bname, error_message(error_root(err))
                );
                error_free(err);
                err = NULL;
                continue;
            }

            output_format_counts(
                stats.file_count, stats.directory_count,
                lines[i].counts, sizeof(lines[i].counts)
            );
            output_format_size(
                stats.total_size, lines[i].size, sizeof(lines[i].size)
            );

            size_t len = strlen(lines[i].counts);
            if (len > max_counts_len) {
                max_counts_len = len;
            }
            len = strlen(lines[i].size);
            if (len > max_size_len) {
                max_size_len = len;
            }
        }
    }

    /* Print header */
    output_section(out, OUTPUT_NORMAL, "Available profiles");

    /* List profiles */
    for (size_t i = 0; i < branches->count; i++) {
        const char *profile = branches->items[i];

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

        /* Start line with indicator and name */
        output_styled(
            out, OUTPUT_NORMAL, "  %s{cyan}%-*s{reset}",
            indicator, (int) max_name_len, profile
        );

        /* Verbose: what the branch holds, in the column measured for it */
        if (lines && lines[i].counts[0] != '\0') {
            output_print(
                out, OUTPUT_VERBOSE, " %-*s %*s",
                (int) max_counts_len, lines[i].counts,
                (int) max_size_len, lines[i].size
            );
        }

        /* Verbose: Add last commit info (uses branch name, not profile tree) */
        if (verbose) {
            char refname[DOTTA_REFNAME_MAX];
            error_t *ref_err = gitops_branch_refname(
                refname, sizeof(refname), profile
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

        output_endline(out, OUTPUT_NORMAL);
    }

    /* Print remote legend if shown */
    if (show_remote) {
        output_gap(out, OUTPUT_NORMAL);
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

    free(lines);
    string_array_free(branches);

    return NULL;
}

/**
 * List files - Level 2
 *
 * Default: Just file paths Verbose: Add sizes and per-file last commit
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

    /* One branch read serves the whole listing: the file walk, the verbose
     * per-entry lookups and commit map, and the statistics (what else the branch
     * holds, when the file list is empty). */
    error_t *err = profile_require(repo, opts->profile);
    if (err) return err;

    git_tree *tree = NULL;
    err = gitops_load_branch_tree(repo, opts->profile, &tree, NULL);
    if (err) {
        return error_wrap(
            err, "Failed to list files in profile '%s'", opts->profile
        );
    }

    string_array_t *files = NULL;
    err = profile_list_tree_files(tree, &files);
    if (err) {
        git_tree_free(tree);
        return error_wrap(
            err, "Failed to list files in profile '%s'", opts->profile
        );
    }

    if (files->count == 0) {
        /* Directory claims are not listed — no size, no history — but the count
         * of them keeps "nothing" honest for a branch whose whole content is
         * its claims. It is what the branch holds less the files, so it comes
         * from the one producer of that number (core/profiles.h
         * profile_get_tree_stats), over the tree already open: an ancestor claim
         * excluded there, the tree-versus-blob rule asked there, and no second
         * reading of the sheet to drift from it.
         *
         * A branch that will not read says so. Silence would spell an unreadable
         * sheet exactly as it spells an empty branch, and the count exists to
         * tell those apart. The sheet is the whole of what can refuse here: the
         * walk above and the count's own read one gate (core/profiles.c
         * tree_entry_content_path), so a file list that came back empty is an
         * empty one there too and no blob header is read. Which is why the refusal
         * is rendered from its root — between it and here the chain names the
         * profile twice more and nothing else, and this line names it a third
         * time (base/error.h error_root). */
        profile_stats_t stats = { 0 };
        error_t *stats_err = profile_get_tree_stats(repo, tree, opts->profile, &stats);
        if (stats_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to count what profile '%s' holds: %s",
                opts->profile, error_message(error_root(stats_err))
            );
            error_free(stats_err);
        }

        /* Either the count stands or the statistics wrote nothing at all (their
         * all-or-nothing `out`), so a sheet that would not read counts as no
         * claim and the warning above is what says which of the two this is. */
        if (stats.directory_count > 0) {
            char counts[64];
            output_format_counts(0, stats.directory_count, counts, sizeof(counts));
            output_info(
                out, OUTPUT_NORMAL, "No files in profile '%s' (%s)",
                opts->profile, counts
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL, "No files in profile '%s'", opts->profile
            );
        }
        string_array_free(files);
        git_tree_free(tree);
        return NULL;
    }

    /* Print header */
    output_section(out, OUTPUT_NORMAL, "Files in profile '{cyan}%s{reset}'", opts->profile);
    output_gap(out, OUTPUT_NORMAL);

    /* Sort for consistent output */
    string_array_sort(files);

    /* What a verbose row reads beyond the name: the branch's claims, the history
     * behind each name, and the width the names need. All three are the whole
     * listing's, read once before any row prints, the way the profile listing
     * above reads and measures before its own.
     *
     * A sheet that will not read costs the rows their marks and leaves their
     * sizes the stored blobs' own — the listing itself is the tree's and stands
     * either way — so it is warned about and folded, and rendered from the root,
     * where this document's refusals say what is wrong with it. The count's
     * sentence (list_profiles, and the empty-branch arm above) names what it
     * failed to do; this one names what it failed to read, which is the other
     * question about the same document. */
    metadata_t *metadata = NULL;
    file_commit_map_t *commit_map = NULL;
    size_t max_path_len = 0;
    if (verbose) {
        err = metadata_load_from_tree(repo, tree, opts->profile, &metadata);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to read what profile '%s' claims: %s",
                opts->profile, error_message(error_root(err))
            );
            error_free(err);
            err = NULL;
        }

        err = stats_build_file_commit_map(repo, opts->profile, tree, &commit_map);
        if (err) {
            /* Non-fatal: continue without commit info */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to load commit history: %s",
                error_message(err)
            );
            error_free(err);
            err = NULL;
        }

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
        const char *storage_path = files->items[i];

        /* Print file path (with alignment in verbose mode) */
        if (verbose) {
            /* Verbose: Left-align with padding for column alignment */
            output_styled(
                out, OUTPUT_VERBOSE, "  {cyan}%-*s{reset}",
                (int) max_path_len, storage_path
            );
        } else {
            /* Simple: No alignment needed */
            output_styled(
                out, OUTPUT_NORMAL, "  {cyan}%s{reset}",
                storage_path
            );
        }

        /* Verbose: Add size and last commit */
        if (verbose) {
            /* Get file stats */
            git_tree_entry *entry = NULL;
            int git_err = git_tree_entry_bypath(&entry, tree, storage_path);
            if (git_err == 0) {
                /* The stamp the branch's own claim makes of this entry, read as
                 * the view projects it: never onto a link, whose bytes are its
                 * target and never a seal (core/manifest.c manifest_apply_claim).
                 * A mark and a number are a screen, so the claim answers and no
                 * content blob is opened — the store made the stamp true for
                 * every file it sealed (infra/content.h content_capture_file),
                 * and a hand-written one is the sheet's word, honoured here as
                 * its mode and its owner are on every other screen (core/metadata.h
                 * metadata_item_t). */
                const metadata_item_t *item = metadata_lookup(metadata, storage_path);
                bool encrypted = git_tree_entry_filemode(entry) != GIT_FILEMODE_LINK
                    && item && item->encrypted;

                if (encrypted) {
                    output_styled(out, OUTPUT_VERBOSE, "  {yellow}[E]{reset} ");
                } else {
                    /* Space padding to maintain alignment */
                    output_print(out, OUTPUT_VERBOSE, "      ");
                }

                /* The size is the stored blob's own header, the cipher's framing
                 * taken off a stamped one through the helper that keeps
                 * crypto/cipher.h out of the command layer. The mark above needed
                 * no read at all, so a header that will not read costs this row
                 * its number and nothing else — and says so where the number
                 * would have stood, in the word the row above uses for an entry
                 * it could not read at all. A total short by a row is then short
                 * where the reader can see it, which is the whole of what this
                 * screen can honestly say: the object is missing or corrupt,
                 * and the count of what the branch holds refuses outright over
                 * the same failure (core/profiles.h profile_get_tree_stats). */
                size_t size = 0;
                error_t *size_err = stats_get_blob_size(
                    repo, git_tree_entry_id(entry), &size
                );
                if (!size_err) {
                    size_t display_size = content_estimated_plaintext_size(size, encrypted);

                    char size_str[32];
                    output_format_size(display_size, size_str, sizeof(size_str));
                    output_print(out, OUTPUT_VERBOSE, " %8s", size_str);
                    total_size += display_size;
                } else {
                    output_styled(out, OUTPUT_VERBOSE, " {dim}%8s{reset}", "[?]");
                }
                error_free(size_err);

                /* Get last commit for this file */
                if (commit_map) {
                    const commit_info_t *commit_info = stats_file_commit_map_get(
                        commit_map, storage_path
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

        output_endline(out, OUTPUT_NORMAL);
    }

    /* Print summary */
    output_gap(out, OUTPUT_NORMAL);
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
    metadata_free(metadata);
    git_tree_free(tree);
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
 * Default: Oneline format (hash, summary, time) Verbose: Full commit format
 */
static error_t *list_file_history(
    const dotta_ctx_t *ctx,
    const cmd_list_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->file_path);

    git_repository *repo = ctx->run.repo;
    const state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    const mount_table_t *mounts = ctx->run.mounts;
    output_t *out = ctx->out;

    bool verbose = output_is_verbose(out);

    /* The claim to list: the profile and the storage path, from the argument.
     * The file need not exist on disk. */
    const char *profile = opts->profile;
    const char *storage_path = NULL;
    git_tree *tree = NULL;
    error_t *err = NULL;

    /* The argument first, above the profile question and above anything read
     * under either: reading one asks no topology (infra/path.h), so every refusal
     * it earns is said before a branch is opened or a view built. Read once for
     * both arms, which differ in where each key's answer comes from and not in
     * which keys they take. */
    path_input_t arg;
    RETURN_IF_ERROR(path_input_resolve(opts->file_path, ctx->arena, &arg));

    if (profile) {
        /* The profile named must be here before anything is read under it; then
         * its tip, which is both where the claim is looked for and what the
         * pre-check below reads (core/profiles.h profile_claim_name). */
        RETURN_IF_ERROR(profile_require(repo, profile));

        err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            return error_wrap(err, "Failed to load tree for profile '%s'", profile);
        }

        /* The two keys, and each names its own read. A name the user typed is
         * Git's key already, so the pre-check below is what decides whether the
         * profile holds it; a path is the branch's to name. */
        if (arg.key == PATH_KEY_STORAGE) {
            storage_path = arg.storage_path;
        } else {
            err = profile_claim_name(
                repo, tree, mounts, profile, arg.filesystem_path, ctx->arena, &storage_path
            );
            if (err) {
                git_tree_free(tree);
                return err;
            }
        }
    } else {
        /* The owner is the view's: the enabled set at HEAD, precedence resolved,
         * asked in the key the argument names. A path is one row, the winner
         * standing there whatever its name. A name keys within one profile, so
         * the view may hold it once (home/, root/, or one binding), or once per
         * binding under custom/ — and then no profile is the answer, and each
         * holder is named with the path that tells them apart. The rows are the
         * arena's; only the index is released here. */
        manifest_t *manifest = NULL;
        err = manifest_build(repo, state, ctx->arena, &manifest);
        if (err) return err;

        const manifest_row_t *row = NULL;
        if (arg.key == PATH_KEY_FILESYSTEM) {
            row = manifest_lookup(manifest, arg.filesystem_path);
        } else {
            size_t holders = manifest_holders(manifest, arg.storage_path, &row);
            if (holders > 1) {
                output_print(
                    out, OUTPUT_NORMAL, "'%s' is held by %zu profiles:\n",
                    arg.storage_path, holders
                );
                manifest_rows_t rows = manifest_rows(manifest);
                for (size_t i = 0; i < rows.count; i++) {
                    const manifest_row_t *held = rows.entries[i];
                    if (strcmp(held->storage_path, arg.storage_path) != 0) continue;
                    output_print(
                        out, OUTPUT_NORMAL, "  • %s  (%s)\n", held->profile,
                        held->filesystem_path
                    );
                }
                output_hint(out, OUTPUT_NORMAL, "Specify -p <profile> to disambiguate:");
                output_hintline(
                    out, OUTPUT_NORMAL, "  dotta list -p <profile> %s", arg.storage_path
                );
                manifest_free(manifest);
                return ERROR(ERR_INVALID_ARG, "Ambiguous path '%s'", arg.storage_path);
            }
        }
        if (!row) {
            manifest_free(manifest);
            return ERROR(
                ERR_NOT_FOUND, "File '%s' not found in enabled profiles\n"
                "Hint: Use 'dotta list -p <profile> %s' to specify a profile",
                opts->file_path, opts->file_path
            );
        }
        /* The winner names both halves: whose claim stands there, and what it
         * is called — the row is that profile's own, so there is nothing to look
         * up again in its branch. */
        profile = row->profile;
        storage_path = row->storage_path;
        manifest_free(manifest);

        err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            return error_wrap(err, "Failed to load tree for profile '%s'", profile);
        }
    }

    /* What the tip holds at the name, asked of both documents at once
     * (core/profiles.h profile_holds), and only a file has a history to list: a
     * directory is refused as one whichever document holds it, a submodule as
     * one, and a name neither holds is a deleted file — given its word before
     * the O(total_commits) walk, which is the search's own. No sheet is handed
     * in: this verb holds none and reads one only where the tip is silent. The
     * history is one name's — a path's former names under another contract are
     * the user's to type, a prospective name proving nothing about what the profile
     * once held there. */
    profile_held_t held;
    err = profile_holds(repo, tree, NULL, profile, storage_path, &held);
    git_tree_free(tree);
    if (err) return err;

    switch (held.kind) {
        case PROFILE_HELD_FILE:
            break;

        case PROFILE_HELD_DIRECTORY:
        case PROFILE_HELD_SUBMODULE:
            return ERROR(
                ERR_INVALID_ARG, "'%s' is %s; list shows one file's history",
                storage_path,
                held.kind == PROFILE_HELD_DIRECTORY ? "a directory" : "a submodule"
            );

        case PROFILE_HELD_NOTHING:
            output_info(out, OUTPUT_NORMAL, "File not in current tree, searching history...");
            break;
    }

    /* Get file history */
    file_history_t *history = NULL;
    err = stats_get_file_history(repo, profile, storage_path, &history);
    if (err) {
        return error_wrap(
            err, "Failed to get history for '%s' in profile '%s'",
            storage_path, profile
        );
    }

    /* Print header */
    output_section(
        out, OUTPUT_NORMAL, "History of '{cyan}%s{reset}' in profile '{cyan}%s{reset}'",
        storage_path, profile
    );
    output_gap(out, OUTPUT_NORMAL);

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

            output_gap(out, OUTPUT_VERBOSE);
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

            output_gap(out, OUTPUT_VERBOSE);
            output_print(out, OUTPUT_VERBOSE, "    %s\n", commit->summary);
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

    return NULL;
}

/**
 * List command implementation
 */
error_t *cmd_list(const dotta_ctx_t *ctx, const cmd_list_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
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
        err = list_profiles(ctx, opts);
    } else if (opts->mode == LIST_FILES) {
        err = list_files(repo, opts, out);
    } else if (opts->mode == LIST_FILE_HISTORY) {
        err = list_file_history(ctx, opts);
    } else {
        err = ERROR(ERR_INVALID_ARG, "Invalid list mode");
    }

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Derive `mode`, `profile`, and `file_path` from the -p flag and the raw positional
 * bucket.
 *
 * -p <profile> is the leading positional forced to a profile: it names the profile
 * unambiguously, so every positional is then a file. It is the escape hatch for
 * profiles whose names would trip the path heuristic, and it mirrors add/remove's
 * flag-vs-first-positional split.
 *
 *   Flag form (-p given):
 *     0 positionals -> LIST_FILES        (profile = flag)
 *     1 positional  -> LIST_FILE_HISTORY (profile = flag, file = pos[0])
 *     2 positionals -> error: only one file may accompany -p
 *
 *   Inference form (no -p): the leading positional is a profile or a file,
 *   disambiguated by whether it announces a path (infra/path.h
 *   path_input_announces_path).
 *     0 positionals -> LIST_PROFILES
 *     1 positional  -> path? LIST_FILE_HISTORY (profile inferred)
 *                      name? LIST_FILES
 *     2 positionals -> LIST_FILE_HISTORY (profile = pos[0], file = pos[1])
 */
static error_t *list_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_list_options_t *o = opts_v;

    if (o->profile != NULL) {
        if (o->positional_count == 0) {
            o->mode = LIST_FILES;
        } else if (o->positional_count == 1) {
            o->mode = LIST_FILE_HISTORY;
            o->file_path = o->positional_args[0];
        } else {
            return ERROR(
                ERR_INVALID_ARG,
                "only one file may accompany -p/--profile"
            );
        }
        return NULL;
    }

    if (o->positional_count == 0) {
        o->mode = LIST_PROFILES;
        return NULL;
    }

    if (o->positional_count == 1) {
        const char *arg = o->positional_args[0];
        if (path_input_announces_path(arg)) {
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

/**
 * What can stand at the cursor, by the rule list_post_parse routes with: under
 * -p, a file of that profile's branch as the one positional; without, a local
 * profile or a file of the view first, then — under a profile — a file of its
 * branch, shadowed ones included. A path in the first slot was the file: nothing
 * follows it.
 */
static args_want_t list_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_list_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_list_options_t, profile)) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }

    if (o->profile != NULL) {
        if (o->positional_count == 0) {
            completion_refspecs(ctx, out, o->profile);
        }
        return ARGS_WANT_NONE;
    }
    if (o->positional_count == 0) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        completion_files(ctx, out, NULL, 0, false);
    } else if (o->positional_count == 1 &&
        !path_input_announces_path(o->positional_args[0])) {
        completion_refspecs(ctx, out, o->positional_args[0]);
    }
    return ARGS_WANT_NONE;
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
        "  [=]      up-to-date with remote\n"
        "  [↑n]     n commits ahead of remote (run '%s sync' to push)\n"
        "  [↓n]     n commits behind remote (run '%s sync' to pull)\n"
        "  [↕n+m]   diverged from remote (manual resolution needed)\n"
        "  [•]      no remote tracking branch (created on first sync)\n",
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
    .complete    = list_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_READ,
        .mounts  = true,
    },
    .dispatch    = list_dispatch,
};
