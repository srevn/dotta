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
#include <string.h>
#include <time.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/timeutil.h"
#include "cmds/completion.h"
#include "core/branch.h"
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
        case UPSTREAM_NO_LOCAL:
            snprintf(
                label, sizeof(label), "[%s]",
                symbol
            );
            break;
    }

    output_colored(out, OUTPUT_NORMAL, color, "  %s", label);
}

/**
 * One verbose profile line's facts
 *
 * Read off the branch's tip before anything prints: what it holds and what that
 * weighs, whose two phrases set columns measured across every branch, the way
 * the name column already is, and its last commit. One tip, read once, so the
 * line is one snapshot's. Empty phrases are a branch whose count or size could
 * not be read, a commit with no summary one whose tip could not — its line still
 * prints, without them.
 *
 * Buffer sizes are the minimums output_format_counts and output_format_size state.
 */
typedef struct {
    char counts[64];
    char size[32];
    commit_info_t commit;    /* the tip's; no summary where it did not read */
} list_profile_line_t;

/**
 * What a branch's files weigh, folded over its walk: the handle the headers are
 * read through, and the sum so far
 *
 * The size a profile line prints, and the fold of exactly the rows the file listing
 * prints one by one (list_files): the same blobs, each the bytes its file stands
 * for. The file listing's `Total:` is then not a second answer but the same one
 * by the other route — the rows it prints, summed as it prints them, which is
 * what a total under a table has to be. What makes the two routes meet is that
 * both take the framing off the same claim; nothing structural does, and a raw
 * sum disagreed with those rows by it on every profile holding a sealed file
 * until 228 C2c, so the agreement is pinned by a scenario (tests/test-encrypt.sh).
 */
typedef struct {
    git_odb *odb;    /* Held for the walk: one handle, a header read per file */
    size_t total;    /* The bytes the files stand for, the seal's framing off */
} list_size_t;

/**
 * Walk visitor: one file claim's bytes, added to the fold
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The fold (list_size_t)
 * @return NULL, or the failure that ends the walk: a header that will not read,
 *         or a total past what a size_t holds
 */
static error_t list_size_claim(const branch_claim_t *claim, void *payload) {
    list_size_t *size = payload;

    /* A directory claim holds no bytes of its own */
    if (claim->type == PATH_TYPE_DIRECTORY) return NULL;

    /* The size from the object's header: nothing inflated */
    size_t bytes = 0;
    error_t err = stats_blob_size_with_odb(size->odb, &claim->blob_oid, &bytes);
    if (err) return err;

    /* The bytes the file stands for, not the bytes the store holds: a sealed
     * blob carries the cipher's framing and its file does not, and the file is
     * what a screen names (197 R5). The stamp is the branch's own claim as it
     * decodes it, never on a link, whose bytes are its target and never a seal
     * (core/branch.c branch_decode_blob) — the same subtraction, off the same
     * claim, the file listing's rows make (list_files) */
    bytes = content_estimated_plaintext_size(bytes, claim->encrypted);

    if (size->total > SIZE_MAX - bytes) {
        return error_create(
            ERR_INTERNAL, "Profile size exceeds maximum representable value"
        );
    }
    size->total += bytes;

    return NULL;
}

/**
 * List profiles - Level 1
 *
 * Default: Just profile names Verbose: Add stats (file count, size, last commit)
 * Remote:  Add tracking indicators
 */
static error_t list_profiles(
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
    string_array_t branches;
    error_t err = gitops_list_branches(repo, ctx->arena, &branches);
    if (err) return err;

    if (branches.count == 0) {
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
                error_line(err)
            );
        } else {
            show_remote = true;
        }
    }

    /* Calculate max branch name length for column alignment */
    size_t max_name_len = 0;
    if (verbose || show_remote) {
        for (size_t i = 0; i < branches.count; i++) {
            const char *bname = branches.entries[i];
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

    /* Read what each branch holds and what that weighs, and measure the columns
     * they need. Both are as wide as the branches make them — the counts phrase
     * names only the kinds a branch actually has, and a size runs from "0 B" to
     * four digits and a unit — so neither is guessed. The size, a header read
     * per file, is the expensive part of a verbose line, and runs here rather
     * than again at render time; a branch that cannot be read is warned about
     * and left with empty phrases, in the words the other screen of this file
     * uses for the count's refusal: what failed is the line's account of what
     * the branch holds, however far down the read it failed. */
    list_profile_line_t *lines = NULL;
    size_t max_counts_len = 0;
    size_t max_size_len = 0;
    if (verbose) {
        lines = arena_calloc(ctx->arena, branches.count, sizeof(*lines));

        for (size_t i = 0; i < branches.count; i++) {
            const char *bname = branches.entries[i];

            /* The branch read once, at its tip: what it holds and its last commit
             * are that one commit's. A tip that will not read leaves the line
             * neither, its error warned and dropped, one per such branch. */
            git_commit *tip = NULL;
            err = gitops_load_branch_commit(repo, bname, &tip);
            if (err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to count what profile '%s' holds: %s",
                    bname, error_message(error_root(err))
                );
                continue;
            }

            /* Its last commit, kept for the line's tail */
            lines[i].commit = stats_commit_info(ctx->arena, tip);

            /* What it holds, counted over the same commit's tree (core/branch.h
             * branch_count); a tree or a count that will not read leaves the
             * line its commit, its error warned and dropped */
            git_tree *tree = NULL;
            int rc = git_commit_tree(&tree, tip);
            git_commit_free(tip);
            branch_t *branch = rc < 0 ? NULL : branch_open(repo, bname, tree);
            branch_count_t count = { 0 };
            err = rc < 0 ? error_git(rc, "Cannot read the tip's tree")
                         : branch_count(branch, &count);

            /* And what that weighs, folded over the same branch through one handle
             * on the object database (list_size_claim): the line's two phrases
             * are one snapshot's, so a size that will not read leaves it neither */
            list_size_t size = { 0 };
            if (!err) {
                rc = git_repository_odb(&size.odb, repo);
                err = rc < 0 ? error_git(rc, "Cannot open the object database")
                             : branch_walk(branch, BRANCH_READ_STRICT, list_size_claim, &size);
            }
            git_odb_free(size.odb);
            branch_free(branch);
            git_tree_free(tree);
            if (err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to count what profile '%s' holds: %s",
                    bname, error_message(error_root(err))
                );
                continue;
            }

            output_format_counts(
                count.file_count, count.directory_count,
                lines[i].counts, sizeof(lines[i].counts)
            );
            output_format_size(size.total, lines[i].size, sizeof(lines[i].size));

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
    for (size_t i = 0; i < branches.count; i++) {
        const char *profile = branches.entries[i];

        bool is_enabled = state_enabled(state, profile);
        const char *indicator = is_enabled ? "* " : "  ";

        /* Simple mode: Just name with enabled indicator */
        if (!verbose && !show_remote) {
            output_print(
                out, OUTPUT_NORMAL, "  %s{cyan}%s{reset}\n",
                indicator, profile
            );
            continue;
        }

        /* Start line with indicator and name */
        output_print(
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

        /* Verbose: its last commit, read off the tip its counts were, printed
         * as a file row prints its own */
        if (lines && lines[i].commit.summary) {
            const commit_info_t *last = &lines[i].commit;
            char oid_str[LIST_SHORT_OID_BUF_SIZE];
            git_oid_tostr(oid_str, sizeof(oid_str), &last->oid);

            char time_str[64];
            timeutil_relative(last->time, time_str, sizeof(time_str));

            size_t summary_len = strlen(last->summary);
            if (summary_len > 40) summary_len = 40;

            output_print(
                out, OUTPUT_VERBOSE, "  {yellow}%s{reset} %.*s {dim}(%s){reset}",
                oid_str, (int) summary_len, last->summary, time_str
            );
        }

        /* Remote: Add tracking state — none where the analysis fails, its error
         * dropped, one per such branch */
        if (show_remote) {
            upstream_info_t info;
            err = upstream_analyze_profile(repo, remote_name, profile, &info);
            if (!err) {
                print_upstream_state(out, &info);
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
        output_print(
            out, OUTPUT_NORMAL,
            "  {green}[=]{reset} up-to-date  "
            "  {yellow}[↑n]{reset} ahead  "
            "  {yellow}[↓n]{reset} behind\n"
        );
        output_print(
            out, OUTPUT_NORMAL,
            "  {red}[↕n+m]{reset} diverged  "
            " {cyan}[•]{reset}  no remote\n"
        );
    }

    return NULL;
}

/**
 * List files - Level 2
 *
 * Default: Just file paths Verbose: Add sizes and per-file last commit
 */
static error_t list_files(
    const dotta_ctx_t *ctx,
    const cmd_list_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->profile);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    bool verbose = output_is_verbose(out);

    /* One branch read serves the whole listing: its tip, read once, and every
     * fact the listing prints taken off that commit — the file walk, the verbose
     * per-entry lookups and the count (what else the branch holds, when the file
     * list is empty) from its tree, the history behind each row from its id —
     * so a branch another writer moves under the listing lends no row another
     * snapshot's history. The id is kept and the commit let go: the tree and
     * the id are all the listing reads of it. */
    error_t err = profile_require(repo, opts->profile);
    if (err) return err;

    git_commit *tip = NULL;
    err = gitops_load_branch_commit(repo, opts->profile, &tip);
    if (err) return err;

    git_oid tip_oid;
    git_oid_cpy(&tip_oid, git_commit_id(tip));
    git_tree *tree = NULL;
    int rc = git_commit_tree(&tree, tip);
    git_commit_free(tip);
    if (rc < 0) {
        return error_git(rc, "Failed to list files in profile '%s'", opts->profile);
    }

    string_array_t files;
    err = profile_list_tree_files(tree, opts->profile, ctx->arena, &files);
    if (err) {
        git_tree_free(tree);
        return err;
    }

    if (files.count == 0) {
        /* Directory claims are not listed — no size, no history — but the count
         * of them keeps "nothing" honest for a branch whose whole content is
         * its claims. It is what the branch holds less the files, so it comes
         * from the one producer of that number (core/branch.h branch_count),
         * over a branch opened on the tree already open, for the count alone:
         * an ancestor claim excluded there, the tree-versus-blob rule asked there,
         * and no second reading of the sheet to drift from it.
         *
         * A branch that will not read says so. Silence would spell an unreadable
         * sheet exactly as it spells an empty branch, and the count exists to
         * tell those apart. The sheet is the whole of what can refuse here: the
         * walk above and the count's own read one gate and one shape check, spelled
         * alike in each (core/profiles.c profile_list_entry, core/branch.c
         * branch_step), so a tree the walk above read whole the count reads whole
         * too. Which is why the refusal is rendered from its root — between it
         * and here the loader names the profile once more and nothing else, and
         * this line names it already (base/error.h error_root). */
        branch_t *branch = branch_open(repo, opts->profile, tree);
        branch_count_t count = { 0 };
        err = branch_count(branch, &count);
        branch_free(branch);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to count what profile '%s' holds: %s",
                opts->profile, error_message(error_root(err))
            );
        }

        /* Either the count stands or it wrote nothing at all (its all-or-nothing
         * `out`), so a sheet that would not read counts as no claim and the warning
         * above is what says which of the two this is. */
        if (count.directory_count > 0) {
            char counts[64];
            output_format_counts(0, count.directory_count, counts, sizeof(counts));
            output_info(
                out, OUTPUT_NORMAL, "No files in profile '%s' (%s)",
                opts->profile, counts
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL, "No files in profile '%s'", opts->profile
            );
        }
        git_tree_free(tree);
        return NULL;
    }

    /* Print header */
    output_section(out, OUTPUT_NORMAL, "Files in profile '{cyan}%s{reset}'", opts->profile);
    output_gap(out, OUTPUT_NORMAL);

    /* Sort for consistent output */
    string_array_sort(&files);

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
        }

        /* The history behind each row, sought for the rows alone, from the tip
         * they were listed at */
        err = stats_build_file_commit_map(
            repo, &tip_oid, &files, ctx->arena, &commit_map
        );
        if (err) {
            /* Non-fatal: continue without commit info */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to load commit history: %s",
                error_line(err)
            );
        }

        for (size_t i = 0; i < files.count; i++) {
            size_t len = strlen(files.entries[i]);
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
    for (size_t i = 0; i < files.count; i++) {
        const char *storage_path = files.entries[i];

        /* Print file path (with alignment in verbose mode) */
        if (verbose) {
            /* Verbose: Left-align with padding for column alignment */
            output_print(
                out, OUTPUT_VERBOSE, "  {cyan}%-*s{reset}",
                (int) max_path_len, storage_path
            );
        } else {
            /* Simple: No alignment needed */
            output_print(
                out, OUTPUT_NORMAL, "  {cyan}%s{reset}",
                storage_path
            );
        }

        /* Verbose: Add size and last commit */
        if (verbose) {
            /* Get file stats */
            git_tree_entry *entry = NULL;
            rc = git_tree_entry_bypath(&entry, tree, storage_path);
            if (rc == 0) {
                /* The stamp the branch's own claim makes of this entry, read as
                 * the branch decodes it: never onto a link, whose bytes are its
                 * target and never a seal (core/branch.c branch_decode_blob's
                 * link rule). A mark and a number are a screen, so the claim
                 * answers and no content blob is opened — the store made the
                 * stamp true for every file it sealed (infra/content.h
                 * content_capture_file), and a hand-written one is the sheet's
                 * word, honoured here as its mode and its owner are on every
                 * other screen (core/metadata.h metadata_item_t). */
                const metadata_item_t *item = metadata_lookup(metadata, storage_path);
                bool encrypted = git_tree_entry_filemode(entry) != GIT_FILEMODE_LINK
                    && item && item->encrypted;

                if (encrypted) {
                    output_print(out, OUTPUT_VERBOSE, "  {yellow}[E]{reset} ");
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
                 * and the profile's line at level 1, which weighs what it counts,
                 * refuses outright over the same failure (list_size_claim). The
                 * header's error is dropped, one per unreadable blob. */
                size_t size = 0;
                err = stats_blob_size(
                    repo, git_tree_entry_id(entry), &size
                );
                if (!err) {
                    size_t display_size = content_estimated_plaintext_size(size, encrypted);

                    char size_str[32];
                    output_format_size(display_size, size_str, sizeof(size_str));
                    output_print(out, OUTPUT_VERBOSE, " %8s", size_str);
                    total_size += display_size;
                } else {
                    output_print(out, OUTPUT_VERBOSE, " {dim}%8s{reset}", "[?]");
                }

                /* Get last commit for this file */
                if (commit_map) {
                    const commit_info_t *commit_info = stats_file_commit_map_get(
                        commit_map, storage_path
                    );
                    if (commit_info) {
                        char oid_str[LIST_SHORT_OID_BUF_SIZE];
                        git_oid_tostr(oid_str, sizeof(oid_str), &commit_info->oid);

                        char time_str[64];
                        timeutil_relative(commit_info->time, time_str, sizeof(time_str));

                        size_t summary_len = strlen(commit_info->summary);
                        if (summary_len > 40) summary_len = 40;

                        output_print(
                            out, OUTPUT_VERBOSE, "  {yellow}%s{reset} %.*s {dim}(%s){reset}",
                            oid_str, (int) summary_len, commit_info->summary, time_str
                        );
                    }
                }
                git_tree_entry_free(entry);
            } else {
                /* Tree entry lookup failed unexpectedly */
                output_print(out, OUTPUT_VERBOSE, "  {dim}[?]{reset}");
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
            files.count,
            files.count == 1 ? "" : "s", size_str
        );
    } else {
        output_print(
            out, OUTPUT_NORMAL, "Total: %zu file%s\n",
            files.count,
            files.count == 1 ? "" : "s"
        );
    }

    /* Cleanup */
    metadata_free(metadata);
    git_tree_free(tree);

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
    if (!localtime_r(&t, &tm_info)) return false;
    strftime(buf, buf_size, "%a %b %d %H:%M:%S %Y", &tm_info);

    return true;
}

/**
 * List file history - Level 3
 *
 * Default: Oneline format (hash, summary, time) Verbose: Full commit format
 */
static error_t list_file_history(
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
    error_t err = NULL;

    /* The argument first, above the profile question and above anything read
     * under either: reading one asks no topology (infra/path.h), so every refusal
     * it earns is said before a branch is opened or a view built. Read once for
     * both arms, which differ in where each key's answer comes from and not in
     * which keys they take. */
    path_input_t arg;
    err = path_input_resolve(opts->file_path, ctx->arena, &arg);
    if (err) return err;

    if (profile) {
        /* The profile named must be here before anything is read under it. Of
         * the two keys, a name the user typed is Git's key already, so the
         * pre-check below is what decides whether the profile holds it; a path
         * is the branch's to name, at its tip (below). */
        err = profile_require(repo, profile);
        if (err) return err;

        if (arg.key == PATH_KEY_STORAGE) {
            storage_path = arg.storage_path;
        }
    } else {
        /* The owner is the view's: the enabled set at HEAD, precedence resolved,
         * asked in the key the argument names. A path is one row, the winner
         * standing there whatever its name. A name keys within one profile, so
         * the view may hold it once (home/, root/, or one binding), or once per
         * binding under custom/ — and then no profile is the answer, and the
         * view's refusal names each holder with the path that tells them apart
         * (core/manifest.h manifest_holder). The view is the arena's. */
        manifest_t *manifest = NULL;
        err = manifest_build(repo, state, ctx->arena, &manifest);
        if (err) return err;

        const manifest_row_t *row = NULL;
        if (arg.key == PATH_KEY_FILESYSTEM) {
            row = manifest_lookup(manifest, arg.filesystem_path);
        } else {
            err = manifest_holder(ctx->arena, manifest, arg.storage_path, &row);
            if (err) return err;
        }
        if (!row) {
            return error_create(
                ERR_NOT_FOUND, "File '%s' not found in enabled profiles", opts->file_path
            );
        }
        /* The winner names both halves: whose claim stands there, and what it
         * is called — the row is that profile's own, so there is nothing to look
         * up again in its branch. */
        profile = row->profile;
        storage_path = row->storage_path;
    }

    /* The branch read once, at its tip: where a path is named, what the pre-check
     * below reads and where the history behind the name starts are all that one
     * commit's, so a branch another writer moves meanwhile lends the history no
     * other snapshot. The id is kept and the commit let go. */
    git_commit *tip = NULL;
    err = gitops_load_branch_commit(repo, profile, &tip);
    if (err) return err;

    git_oid tip_oid;
    git_oid_cpy(&tip_oid, git_commit_id(tip));
    git_tree *tree = NULL;
    int rc = git_commit_tree(&tree, tip);
    git_commit_free(tip);
    if (rc < 0) {
        return error_git(rc, "Failed to load tree for profile '%s'", profile);
    }

    /* The profile's branch over the tip's tree, held beside it */
    branch_t *branch = branch_open(repo, profile, tree);

    /* A path under a named profile, named by the branch at that tip
     * (core/profiles.h profile_claim_name) */
    if (opts->profile && arg.key == PATH_KEY_FILESYSTEM) {
        err = profile_claim_name(
            branch, mounts, arg.filesystem_path, ctx->arena, &storage_path
        );
        if (err) {
            branch_free(branch);
            git_tree_free(tree);
            return err;
        }
    }

    /* What the tip holds at the name, asked of the branch's two documents at
     * once (core/branch.h branch_holds), and only a file has a history to list:
     * a directory is refused as one whichever document holds it, a submodule as
     * one, and a name neither holds is a deleted file — given its word before
     * the O(total_commits) walk, which is the search's own. The branch reads
     * its sheet only where the tip is silent, strictly, and a path's view above
     * has already read it. The history is one name's — a path's former names
     * under another contract are the user's to type, a prospective name proving
     * nothing about what the profile once held there. */
    branch_held_t held;
    err = branch_holds(branch, storage_path, &held);
    branch_free(branch);
    git_tree_free(tree);
    if (err) return err;

    switch (held.kind) {
        case BRANCH_HELD_FILE:
            break;

        case BRANCH_HELD_DIRECTORY:
        case BRANCH_HELD_SUBMODULE:
            return error_create(
                ERR_INVALID_ARG, "'%s' is %s; list shows one file's history",
                storage_path,
                held.kind == BRANCH_HELD_DIRECTORY ? "a directory" : "a submodule"
            );

        case BRANCH_HELD_NOTHING:
            output_info(out, OUTPUT_NORMAL, "File not in current tree, searching history...");
            break;
    }

    /* The history, from the tip the name was asked of. None is a name the tip
     * does not hold that no commit touched either — the search announced above,
     * which found nothing. */
    file_history_t history;
    err = stats_file_history(repo, &tip_oid, storage_path, ctx->arena, &history);
    if (err) {
        return error_wrap(
            err, "Failed to get history for '%s' in profile '%s'",
            storage_path, profile
        );
    }
    if (history.count == 0) {
        return error_create(
            ERR_NOT_FOUND, "No history found for '%s' in profile '%s'", storage_path,
            profile
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
        for (size_t i = 0; i < history.count; i++) {
            size_t len = strlen(history.commits[i].summary);
            if (len > max_msg_len) max_msg_len = len;
        }

        /* Cap to prevent excessive padding from long commit messages */
        if (max_msg_len > LIST_MAX_MSG_ALIGN) {
            max_msg_len = LIST_MAX_MSG_ALIGN;
        }
    }

    /* Print commits */
    for (size_t i = 0; i < history.count; i++) {
        const commit_info_t *commit = &history.commits[i];

        if (verbose) {
            /* Verbose: Full commit format */
            char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
            git_oid_tostr(oid_str, sizeof(oid_str), &commit->oid);

            output_gap(out, OUTPUT_VERBOSE);
            output_print(
                out, OUTPUT_VERBOSE, "{bold}commit {yellow}%s{reset}\n",
                oid_str
            );

            /* Display timestamp if valid */
            char date_buf[LIST_TIMESTAMP_BUFFER_SIZE];
            if (format_time(commit->time, date_buf, sizeof(date_buf))) {
                char relative_str[64];
                timeutil_relative(commit->time, relative_str, sizeof(relative_str));

                output_print(
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
            timeutil_relative(commit->time, time_str, sizeof(time_str));

            output_print(
                out, OUTPUT_NORMAL, "  {yellow}%s{reset}  %-*s {dim}(%s){reset}\n",
                oid_str, (int) max_msg_len, commit->summary, time_str
            );
        }
    }

    return NULL;
}

/**
 * List command implementation
 */
error_t cmd_list(const dotta_ctx_t *ctx, const cmd_list_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    output_t *out = ctx->out;

    /* Warn about flags that don't apply to the current mode */
    if (opts->remote && opts->mode != LIST_PROFILES) {
        output_warning(out, OUTPUT_NORMAL, "--remote only applies when listing profiles");
    }

    /* Dispatch to appropriate list function based on mode — every mode
     * list_post_parse sets */
    switch (opts->mode) {
        case LIST_PROFILES:     return list_profiles(ctx, opts);
        case LIST_FILES:        return list_files(ctx, opts);
        case LIST_FILE_HISTORY: return list_file_history(ctx, opts);
    }

    CHECK_ARG(false, "a list mode no enumerator names");
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
static error_t list_post_parse(
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
            return error_create(ERR_INVALID_ARG, "Only one file may accompany -p/--profile");
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
    CHECK_ARG(false, "POSITIONAL_RAW bounds list's positionals at two");
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

static error_t list_dispatch(const void *ctx_v, void *opts_v) {
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
    ARGS_FLAG_SET(
        "v verbose",
        cmd_list_options_t,verbosity,       DOTTA_VERBOSITY_VERBOSE,
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
