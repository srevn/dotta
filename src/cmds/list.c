/**
 * list.c - List profiles, files, and commit history
 *
 * Hierarchical listing interface with three levels:
 * 1. Profiles (default) - Show every profile here, and every enabled one
 * 2. Files (with -p) - Show files in a profile
 * 3. A path's history (with -p <path>) - Show the commits that changed a file,
 *    or anything beneath a directory
 */

#include "cmds/list.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "base/timeutil.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/scope.h"
#include "core/state.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "infra/input.h"
#include "sys/gitops.h"
#include "sys/remote.h"
#include "sys/stats.h"

/* Display configuration constants */
#define LIST_SHORT_OID_BUF_SIZE 8
#define LIST_TIMESTAMP_BUFFER_SIZE 64
#define LIST_MAX_MSG_ALIGN 60
#define LIST_MAX_NAME_ALIGN 40
#define LIST_MIN_NAME_ALIGN 12
#define LIST_SUMMARY_MAX 40

/**
 * One verbose profile line's facts
 *
 * Read off the branch's head before anything prints: what it holds and what that
 * weighs, whose two phrases set columns measured across every profile, the way
 * the name column already is, and its last commit. One head, read once, so the
 * line is one snapshot's. Empty phrases are a profile whose count or size could
 * not be read, a commit with no summary one whose head could not — its line still
 * prints, without them.
 *
 * Buffer sizes are the minimums output_format_counts and output_format_size state.
 */
typedef struct {
    char counts[64];
    char size[32];
    commit_info_t commit;    /* the head's; no summary where it did not read */
} list_line_t;

/**
 * What a profile's files weigh, folded over its walk: the object database the
 * headers are read through, and the sum so far
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
static error_t list_size_claim(const profile_claim_t *claim, void *payload) {
    list_size_t *size = payload;

    /* A directory claim holds no bytes of its own */
    if (claim->type == PATH_TYPE_DIRECTORY) return NULL;

    /* The size from the object's header: nothing inflated */
    size_t bytes = 0;
    error_t err = stats_blob_size_with_odb(size->odb, &claim->blob_oid, &bytes);
    if (err) return err;

    /* The bytes the file stands for, not the bytes the store holds: a sealed
     * blob carries the cipher's framing and its file does not, and the file is
     * what a screen names (197 R5). The stamp is the profile's own claim as it
     * decodes it, never on a link, whose bytes are its target and never a seal
     * (core/profiles.c profile_decode_blob) — the same subtraction, off the same
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
 * Default: the names, the enabled ones starred. Verbose: what each holds, what
 * that weighs, and its last commit. Remote: each one's remote sync status, in
 * the row's words and under the title status's remote section prints (cmds/status.c
 * status_print_remote) — the glyph beside its phrase, so no legend keys it —
 * the names padded to one column, where status's rows follow a name by one space.
 * And beneath them in every mode, each enabled row Git lists no branch for, starred
 * and marked (no branch) where a branch's facts would stand, as profile list
 * marks its row (cmds/profile.c profile_list): the fact the view says as
 * core/manifest.h manifest_missing, read off the rows and the listing, since
 * list declares no view. Every mode closes on the total: the profiles listed,
 * the enabled among them, and at verbose what they weigh.
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
    string_array_t profiles;
    error_t err = gitops_list_branches(repo, ctx->arena, &profiles);
    if (err) return err;

    /* And every enabled row the listing holds no branch for, in the rows' order.
     * The rows and the listing are joined by name, the star below asking the
     * same join from the branch's side (state_enabled), so each row is listed
     * once: starred on its branch's line, or beneath the rest. The rows are the
     * handle's, and nothing here moves them (core/state.h state_profiles). */
    state_profiles_t enabled_profiles = state_profiles(state);
    string_array_t missing;
    string_array_init(&missing, ctx->arena, 0);
    for (size_t i = 0; i < enabled_profiles.count; i++) {
        const char *name = enabled_profiles.entries[i].name;
        if (!string_array_contains(&profiles, name)) string_array_push(&missing, name);
    }

    if (profiles.count == 0 && missing.count == 0) {
        output_summary(out, OUTPUT_NORMAL, "No profiles found");
        return NULL;
    }

    /* Detect remote if --remote flag is set */
    const char *remote_name = NULL;
    bool show_remote = false;
    if (opts->remote) {
        err = remote_default(repo, ctx->arena, &remote_name);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Could not detect remote: %s",
                error_line(err)
            );
        } else {
            show_remote = true;
        }
    }

    /* Calculate max profile name length for column alignment, over the enabled
     * rows with no branch too: their mark stands where a branch's columns start */
    size_t max_name_len = 0;
    if (verbose || show_remote) {
        for (size_t i = 0; i < profiles.count; i++) {
            const char *name = profiles.entries[i];
            size_t len = strlen(name);
            if (len > max_name_len) {
                max_name_len = len;
            }
        }
        for (size_t i = 0; i < missing.count; i++) {
            const char *name = missing.entries[i];
            size_t len = strlen(name);
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

    /* Read what each profile holds and what that weighs, and measure the columns
     * they need. Both are as wide as the profiles make them — the counts phrase
     * names only the kinds a profile actually has, and a size runs from "0 B"
     * to four digits and a unit — so neither is guessed. The size, a header read
     * per file, is the expensive part of a verbose line, and runs here rather
     * than again at render time; a profile that cannot be read is warned about
     * and left with empty phrases, in the words the other screen of this file
     * uses for the count's refusal: what failed is the line's account of what
     * the profile holds, however far down the read it failed. The sizes that
     * read are summed for the total, short by a profile that did not, as the
     * file listing's total is short by a row it could not size (list_files). */
    list_line_t *lines = NULL;
    size_t max_counts_len = 0;
    size_t max_size_len = 0;
    size_t total_size = 0;
    if (verbose) {
        lines = arena_calloc(ctx->arena, profiles.count, sizeof(*lines));

        for (size_t i = 0; i < profiles.count; i++) {
            const char *name = profiles.entries[i];

            /* The branch read once, at its head: what it holds and its last commit
             * are that one commit's. A head that will not read leaves the line
             * neither, its error warned and dropped, one per such branch. */
            git_commit *head = NULL;
            err = gitops_load_branch_commit(repo, name, &head);
            if (err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to count what profile '%s' holds: %s",
                    name, error_message(error_root(err))
                );
                continue;
            }

            /* Its last commit, kept for the line's tail */
            lines[i].commit = stats_commit_info(ctx->arena, head);

            /* What it holds, counted over the profile at the same commit
             * (core/profiles.h profile_counts); a tree or a count that will not
             * read leaves the line its commit, its error warned and dropped */
            profile_t *profile = NULL;
            err = profile_open(name, head, &profile);
            git_commit_free(head);
            profile_counts_t count = { 0 };
            if (!err) err = profile_counts(profile, &count);

            /* And what that weighs, folded over the same profile through one
             * handle on the object database (list_size_claim): the line's two
             * phrases are one snapshot's, so a size that will not read leaves
             * it neither */
            list_size_t size = { 0 };
            if (!err) {
                int rc = git_repository_odb(&size.odb, repo);
                err = rc < 0 ? error_git(rc, "Cannot open the object database")
                             : profile_walk(profile, PROFILE_READ_STRICT, list_size_claim, &size);
            }
            git_odb_free(size.odb);
            profile_free(profile);
            if (err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to count what profile '%s' holds: %s",
                    name, error_message(error_root(err))
                );
                continue;
            }

            output_format_counts(
                count.file_count, count.directory_count,
                lines[i].counts, sizeof(lines[i].counts)
            );
            output_format_size(size.total, lines[i].size, sizeof(lines[i].size));
            total_size += size.total;

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

    /* The header: where the rows say each state, the title status's remote section
     * gives the same rows read with no contact, naming the remote and marked as
     * last seen (cmds/status.c status_print_remote) — list makes none */
    if (show_remote) {
        output_section(
            out, OUTPUT_NORMAL, "Remote sync status ({cyan}%s{reset}, as last seen)",
            remote_name
        );
    } else {
        output_section(out, OUTPUT_NORMAL, "Profiles");
    }

    /* List profiles, the enabled ones starred */
    for (size_t i = 0; i < profiles.count; i++) {
        const char *profile = profiles.entries[i];
        const char *indicator = state_enabled(state, profile) ? "* " : "  ";

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

        /* Verbose: what the profile holds, in the column measured for it */
        if (lines && lines[i].counts[0] != '\0') {
            output_print(
                out, OUTPUT_VERBOSE, "  %-*s  %*s",
                (int) max_counts_len, lines[i].counts,
                (int) max_size_len, lines[i].size
            );
        }

        /* Verbose: its last commit, read off the head its counts were, printed
         * as a file row prints its own */
        if (lines && lines[i].commit.summary) {
            const commit_info_t *last = &lines[i].commit;
            char oid_str[LIST_SHORT_OID_BUF_SIZE];
            git_oid_tostr(oid_str, sizeof(oid_str), &last->oid);

            char time_str[64];
            timeutil_relative(last->time, time_str, sizeof(time_str));

            /* Cut on a whole character (base/string.h str_display), which the
             * print's own spelling of a datum leaves as it is */
            char summary[LIST_SUMMARY_MAX + 1];
            str_display(summary, sizeof(summary), last->summary, strlen(last->summary));

            output_print(
                out, OUTPUT_VERBOSE, "  {yellow}%s{reset} %s {dim}(%s){reset}",
                oid_str, summary, time_str
            );
        }

        /* Remote: where the profile stands against its tracking ref, the remote
         * as last seen — list makes no contact (sys/remote.h remote_last_relation)
         * — as status's row says it: the glyph beside its phrase, or the read's
         * failure in its place, its error dropped once said, one per such branch */
        if (show_remote) {
            remote_relation_t relation;
            err = remote_last_relation(repo, remote_name, profile, &relation);
            if (err) {
                output_print(
                    out, OUTPUT_NORMAL, "  {red}(✗ %s){reset}", error_line(err)
                );
            } else {
                char phrase[REMOTE_PHRASE_MAX];
                remote_state_phrase(&relation, phrase, sizeof(phrase));
                output_print(
                    out, OUTPUT_NORMAL, "  {dim}(%s %s){reset}",
                    remote_state_symbol(relation.state), phrase
                );
            }
        }

        output_endline(out, OUTPUT_NORMAL);
    }

    /* Beneath them, each enabled row with no branch, as status lists them beneath
     * the rest (cmds/status.c status_print_profiles). What a branch's line says
     * beside its name — what it holds, what that weighs, its last commit, where
     * it stands against the remote — is read off the branch, so the mark takes
     * its place, in every mode */
    for (size_t i = 0; i < missing.count; i++) {
        output_print(
            out, OUTPUT_NORMAL, "  * {cyan}%-*s{reset}  {yellow}(no branch){reset}\n",
            (int) max_name_len, missing.entries[i]
        );
    }

    /* Print summary: the file listing's shape (list_files), the profiles listed
     * and the enabled among them — every enabled row, each listed once above —
     * and at verbose what they weigh */
    size_t total = profiles.count + missing.count;
    if (verbose) {
        char size_str[32];
        output_format_size(total_size, size_str, sizeof(size_str));
        output_summary(
            out, OUTPUT_VERBOSE, "Total: %zu profile%s, %zu enabled, %s",
            total, total == 1 ? "" : "s", enabled_profiles.count, size_str
        );
    } else {
        output_summary(
            out, OUTPUT_NORMAL, "Total: %zu profile%s, %zu enabled",
            total, total == 1 ? "" : "s", enabled_profiles.count
        );
    }

    return NULL;
}

/**
 * A file the file listing prints: its name, and what a verbose row reads off
 * its claim
 *
 * Copied out of the claim the walk lends (core/profiles.h profile_visit_fn): a
 * row outlives the visit that showed it, and the walk joins each blob's name in
 * a buffer the next entry takes. The blob and the stamp are the claim's, as the
 * profile decodes them, so no row asks the tree again.
 */
typedef struct {
    const char *storage_path;   /* The name, in the listing's arena */
    git_oid blob_oid;           /* The blob whose header sizes the row */
    bool encrypted;             /* The claim's stamp: the mark, and the framing off the size */
} list_file_t;

/**
 * The file listing's walk: every file claim the profile shows, collected
 */
typedef struct {
    arena_t *arena;             /* The listing's: the rows, and each row's name */
    list_file_t *files;
    size_t file_count;
    size_t file_capacity;
} list_walk_t;

/**
 * Walk visitor: one claim, onto the listing where it is a file's
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The walk (list_walk_t)
 * @return NULL: a collection fails nowhere
 */
static error_t list_collect_file(const profile_claim_t *claim, void *payload) {
    list_walk_t *walk = payload;

    /* A directory claim is no row: it has no size of its own, and what else the
     * profile holds is the count's to say (the no-files arm, and level 1's line) */
    if (claim->type == PATH_TYPE_DIRECTORY) return NULL;

    /* The row: the name copied out of the walk's loan, the blob and the stamp
     * taken by value */
    walk->files = arena_grow(
        walk->arena, walk->files, &walk->file_capacity, walk->file_count + 1,
        sizeof(*walk->files)
    );
    walk->files[walk->file_count++] = (list_file_t){
        .storage_path = arena_strdup(walk->arena, claim->storage_path),
        .blob_oid = claim->blob_oid,
        .encrypted = claim->encrypted,
    };

    return NULL;
}

/* qsort's: two rows by their storage paths (strcmp), the order base/array.h
 * string_array_sort gives names */
static int list_path_order(const void *a, const void *b) {
    const list_file_t *fa = a;
    const list_file_t *fb = b;

    return strcmp(fa->storage_path, fb->storage_path);
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

    /* One branch read serves the whole listing: its head, read once, and every
     * fact the listing prints taken off that commit — the rows and the count
     * (what else the profile holds, when it holds no file) from the profile at
     * that commit, the history behind each row from its id — so a branch another
     * writer moves under the listing lends no row another snapshot's history.
     * The id is kept and the commit let go once the profile is opened at it:
     * the profile and the id are all the listing reads of it. */
    error_t err = profile_require(repo, opts->profile);
    if (err) return err;

    git_commit *head = NULL;
    err = gitops_load_branch_commit(repo, opts->profile, &head);
    if (err) return err;

    git_oid head_oid;
    git_oid_cpy(&head_oid, git_commit_id(head));
    profile_t *profile = NULL;
    err = profile_open(opts->profile, head, &profile);
    git_commit_free(head);
    if (err) return err;

    /* Every file the profile claims, collected in one walk: each row's name,
     * blob and stamp as the profile decodes them, so no row asks the tree again
     * (list_collect_file). Read tolerantly — the listing is the tree's and stands,
     * the marks are the sheet's and do not — so a sheet that will not load costs
     * the rows their marks alone, said where the marks would print. What the
     * walk cannot read of the tree is its failure, in the profile's words. */
    list_walk_t walk = { .arena = ctx->arena };
    err = profile_walk(profile, PROFILE_READ_TOLERANT, list_collect_file, &walk);
    if (err) goto cleanup;

    if (walk.file_count == 0) {
        /* Directory claims are not listed — no size of their own — but the count
         * of them keeps "nothing" honest for a profile whose whole content is
         * its claims. It is what the profile holds less the files, so it comes
         * from the one producer of that number (core/profiles.h profile_counts),
         * over the profile the rows were walked from: an ancestor claim excluded
         * there, the tree-versus-blob rule asked there, and the sheet the walk
         * read, parsed once for both.
         *
         * A profile that will not read says so. Silence would spell an unreadable
         * sheet exactly as it spells an empty profile, and the count exists to
         * tell those apart. The sheet is the whole of what can refuse here: the
         * count walks the tree the walk above read whole, through the same visitor
         * (core/profiles.c profile_step), and reads strictly the sheet the walk
         * above read tolerantly, its failure the one the handle kept
         * (core/profiles.h profile_load_sheet). Which is why the refusal is
         * rendered from its root — between it and here the loader names the profile
         * once more and the head's commit, and this line names the profile already,
         * its head being the listing's own (base/error.h error_root). */
        profile_counts_t count = { 0 };
        err = profile_counts(profile, &count);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to count what profile '%s' holds: %s",
                opts->profile, error_message(error_root(err))
            );
            err = NULL;
        }

        /* Either the count stands or it wrote nothing at all (its all-or-nothing
         * `out`), so a sheet that would not read counts as no claim and the warning
         * above is what says which of the two this is. */
        if (count.directory_count > 0) {
            char counts[64];
            output_format_counts(0, count.directory_count, counts, sizeof(counts));
            output_summary(
                out, OUTPUT_NORMAL, "No files in profile '%s' (%s)",
                opts->profile, counts
            );
        } else {
            output_summary(
                out, OUTPUT_NORMAL, "No files in profile '%s'", opts->profile
            );
        }
        goto cleanup;
    }

    /* Print header */
    output_section(out, OUTPUT_NORMAL, "Files in profile '{cyan}%s{reset}'", opts->profile);
    output_gap(out, OUTPUT_NORMAL);

    /* Sort for consistent output: the rows by name. A tree Git wrote walks in
     * that order already, but libgit2 keeps a tree's entries as they are stored
     * (lib/libgit2/src/libgit2/tree.c git_tree__parse_raw), and a hand can store
     * them in another */
    qsort(walk.files, walk.file_count, sizeof(*walk.files), list_path_order);

    /* What a verbose row reads beyond its claim: the last change behind each
     * name, and the width the names need. Both are the whole listing's, read
     * once before any row prints, the way the profile listing above reads and
     * measures before its own.
     *
     * A sheet the walk could not read costs the rows their marks and leaves their
     * sizes the stored blobs' own — the listing itself is the tree's and stands
     * either way — so it is warned about once, before the rows that print the
     * marks, and rendered from the root, where this document's refusals say what
     * is wrong with it. The count's sentence (list_profiles, and the empty-profile
     * arm above) names what it failed to do; this one names what it failed to
     * read, which is the other question about the same document. */
    commit_info_t *changes = NULL;
    size_t max_path_len = 0;
    if (verbose) {
        err = profile_load_sheet(profile);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to read what profile '%s' claims: %s",
                opts->profile, error_message(error_root(err))
            );
            err = NULL;
        }

        /* The last change behind each row, sought for the rows alone, from the
         * head they were listed at. The walk asks names (sys/stats.h), so the
         * rows lend it theirs, in their order, and its answers stand in that
         * order */
        const char **names = arena_calloc(ctx->arena, walk.file_count, sizeof(*names));
        for (size_t i = 0; i < walk.file_count; i++) {
            names[i] = walk.files[i].storage_path;
        }
        err = stats_last_changes(
            repo, &head_oid, names, walk.file_count, ctx->arena, &changes
        );
        if (err) {
            /* Non-fatal: continue without commit info */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to load commit history: %s",
                error_line(err)
            );
            err = NULL;
        }

        for (size_t i = 0; i < walk.file_count; i++) {
            size_t len = strlen(walk.files[i].storage_path);
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
    for (size_t i = 0; i < walk.file_count; i++) {
        const list_file_t *file = &walk.files[i];

        /* Print file path (with alignment in verbose mode) */
        if (verbose) {
            /* Verbose: Left-align with padding for column alignment */
            output_print(
                out, OUTPUT_VERBOSE, "  {cyan}%-*s{reset}",
                (int) max_path_len, file->storage_path
            );
        } else {
            /* Simple: No alignment needed */
            output_print(
                out, OUTPUT_NORMAL, "  {cyan}%s{reset}",
                file->storage_path
            );
        }

        /* Verbose: Add size and last commit */
        if (verbose) {
            /* The stamp the profile's own claim makes of this file, as the profile
             * decodes it: never onto a link, whose bytes are its target and never
             * a seal (core/profiles.c profile_decode_blob's link rule). A mark
             * and a number are a screen, so the claim answers and no content
             * blob is opened — the store made the stamp true for every file it
             * sealed (infra/content.h content_capture_file), and a hand-written
             * one is the sheet's word, honoured here as its mode and its owner
             * are on every other screen (core/metadata.h metadata_item_t). */
            if (file->encrypted) {
                output_print(out, OUTPUT_VERBOSE, "  {yellow}[E]{reset} ");
            } else {
                /* Space padding to maintain alignment */
                output_print(out, OUTPUT_VERBOSE, "      ");
            }

            /* The size is the stored blob's own header, the cipher's framing
             * taken off a stamped one through the helper that keeps crypto/cipher.h
             * out of the command layer. The mark above needed no read at all,
             * so a header that will not read costs this row its number and nothing
             * else — and says so where the number would have stood. A total short
             * by a row is then short where the reader can see it, which is the
             * whole of what this screen can honestly say: the object is missing
             * or corrupt, and the profile's line at level 1, which weighs what
             * it counts, refuses outright over the same failure (list_size_claim).
             * The header's error is dropped where the row says so, one per
             * unreadable blob. */
            size_t size = 0;
            err = stats_blob_size(repo, &file->blob_oid, &size);
            if (!err) {
                size_t display_size = content_estimated_plaintext_size(size, file->encrypted);

                char size_str[32];
                output_format_size(display_size, size_str, sizeof(size_str));
                output_print(out, OUTPUT_VERBOSE, " %8s", size_str);
                total_size += display_size;
            } else {
                output_print(out, OUTPUT_VERBOSE, " {dim}%8s{reset}", "[?]");
                err = NULL;
            }

            /* Its last change, printed as a profile row prints its last commit
             * (list_profiles): a row is a file the head holds, so its line ends
             * at the commit that made its entry, and every row has one */
            if (changes) {
                const commit_info_t *last = &changes[i];
                char oid_str[LIST_SHORT_OID_BUF_SIZE];
                git_oid_tostr(oid_str, sizeof(oid_str), &last->oid);

                char time_str[64];
                timeutil_relative(last->time, time_str, sizeof(time_str));

                /* Cut on a whole character (base/string.h str_display), which
                 * the print's own spelling of a datum leaves as it is */
                char summary[LIST_SUMMARY_MAX + 1];
                str_display(summary, sizeof(summary), last->summary, strlen(last->summary));

                output_print(
                    out, OUTPUT_VERBOSE, "  {yellow}%s{reset} %s {dim}(%s){reset}",
                    oid_str, summary, time_str
                );
            }
        }

        output_endline(out, OUTPUT_NORMAL);
    }

    /* Print summary */
    if (verbose) {
        char size_str[32];
        output_format_size(total_size, size_str, sizeof(size_str));
        output_summary(
            out, OUTPUT_VERBOSE, "Total: %zu file%s, %s",
            walk.file_count,
            walk.file_count == 1 ? "" : "s", size_str
        );
    } else {
        output_summary(
            out, OUTPUT_NORMAL, "Total: %zu file%s",
            walk.file_count,
            walk.file_count == 1 ? "" : "s"
        );
    }

cleanup:
    profile_free(profile);

    return err;
}

/**
 * List a path's history - Level 3
 *
 * Default: Oneline format (hash, summary, time) Verbose: Full commit format.
 * Both close on the total: the commits listed.
 */
static error_t list_path_history(
    const dotta_ctx_t *ctx,
    const cmd_list_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->path);

    git_repository *repo = ctx->run.repo;
    const state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    const mount_table_t *mounts = ctx->run.mounts;
    output_t *out = ctx->out;

    bool verbose = output_is_verbose(out);

    /* The claim to list: the profile and the storage path, from the argument.
     * The path need not exist on disk. */
    const char *name = opts->profile;
    const char *storage_path = NULL;
    error_t err = NULL;

    /* The argument first, above the profile question and above anything read
     * under either: reading one asks no topology (infra/input.h), so every refusal
     * it earns is said before a profile is opened or a view built. Read once
     * for both arms, which differ in where each key's answer comes from and not
     * in which keys they take. */
    input_path_t arg;
    err = input_resolve(opts->path, ctx->arena, &arg);
    if (err) return err;

    if (opts->profile) {
        /* The profile named must be here before anything is read under it; what
         * it calls the argument is read at its head (below) */
        err = profile_require(repo, name);
        if (err) return err;
    } else {
        /* The owner is the view's: the enabled set at HEAD, precedence resolved,
         * which holds the set it was built from. The view is the arena's. */
        manifest_t *manifest = NULL;
        err = manifest_build(repo, state, NULL, ctx->arena, &manifest);
        if (err) return err;

        /* Nowhere to search: refused as show refuses it — the fact the set's
         * own words, the way through this command's — over the set the view was
         * built from, the one searched below */
        err = scope_require_enabled(state, manifest_profiles(manifest), ctx->arena);
        if (err) {
            return error_wrap(
                err, "Cannot search for '%s'; -p searches a profile by name",
                arg.key == INPUT_KEY_FILESYSTEM ? arg.filesystem_path : arg.storage_path
            );
        }

        /* The claim the argument names there, in its key: the row standing at a
         * path, a name's one holder (core/scope.h scope_resolve_claim) */
        const manifest_row_t *row = NULL;
        err = scope_resolve_claim(manifest, &arg, ctx->arena, &row);
        if (err) return err;

        /* The winner names both halves: whose claim stands there, and what it
         * is called — the row is that profile's own, so there is nothing to look
         * up again in the profile. Its head is read below a second time, moments
         * after the view read it: a writer landing between the two lends the
         * history the later head's, a window stated and not closed. */
        name = row->profile;
        storage_path = row->storage_path;
    }

    /* The branch read once, at its head: where a path is named, what the pre-check
     * below reads and where the history behind the name starts are all that one
     * commit's, so a branch another writer moves meanwhile lends the history no
     * other snapshot. The id is kept and the commit let go once the profile is
     * opened at it. */
    git_commit *head = NULL;
    err = gitops_load_branch_commit(repo, name, &head);
    if (err) return err;

    git_oid head_oid;
    git_oid_cpy(&head_oid, git_commit_id(head));
    profile_t *profile = NULL;
    err = profile_open(name, head, &profile);
    git_commit_free(head);
    if (err) return err;

    /* A profile named: the name it gives the argument at that head (core/scope.h
     * scope_resolve_name) — a name as typed, which the pre-check below decides
     * the profile holds, and a path its own view's */
    if (opts->profile) {
        err = scope_resolve_name(profile, mounts, &arg, ctx->arena, &storage_path);
    }

    /* What the head holds at the name, asked of the profile's two documents at
     * once (core/profiles.h profile_holds): a file and a directory have a history
     * to list, whichever document holds the directory — one the sheet alone holds
     * walks to what its subtree once held, or to none (sys/stats.h
     * stats_path_history); a submodule is refused as one, a gitlink being no
     * claim; and a name neither holds is a path the head lacks — given its word
     * before the walk of its lines, which is the search's own. The profile reads
     * its sheet only where the head is silent, strictly, and a path's view above
     * has already read it. The history is one name's — a path's former names
     * under another contract are the user's to type, a prospective name proving
     * nothing about what the profile once held there. */
    profile_held_t held;
    if (!err) err = profile_holds(profile, storage_path, &held);
    profile_free(profile);
    if (err) return err;

    switch (held.kind) {
        case PROFILE_HELD_FILE:
        case PROFILE_HELD_DIRECTORY:
            break;

        case PROFILE_HELD_SUBMODULE:
            return error_create(
                ERR_INVALID_ARG,
                "'%s' is a submodule; list shows a file's or a directory's history",
                storage_path
            );

        case PROFILE_HELD_NOTHING:
            output_info(
                out, OUTPUT_NORMAL,
                "'%s' is not in the current tree; searching its history...",
                storage_path
            );
            break;
    }

    /* The history, from the head the name was asked of. None is a name the head
     * does not hold that no commit on its lines held either — the search announced
     * above, which found nothing — or a directory the sheet alone holds, whose
     * subtree no commit held. */
    path_history_t history;
    err = stats_path_history(repo, &head_oid, storage_path, ctx->arena, &history);
    if (err) {
        return error_wrap(
            err, "Failed to get history for '%s' in profile '%s'",
            storage_path, name
        );
    }
    if (history.count == 0) {
        return error_create(
            ERR_NOT_FOUND, "No history found for '%s' in profile '%s'", storage_path,
            name
        );
    }

    /* Print header */
    output_section(
        out, OUTPUT_NORMAL, "History of '{cyan}%s{reset}' in profile '{cyan}%s{reset}'",
        storage_path, name
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

            /* The date, where a local time places the commit's (base/timeutil.h
             * timeutil_absolute) */
            char date_buf[LIST_TIMESTAMP_BUFFER_SIZE];
            if (timeutil_absolute(commit->time, date_buf, sizeof(date_buf))) {
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

    /* Print summary: the commits listed, at every level, as the file listing
     * counts its rows (list_files) */
    output_summary(
        out, OUTPUT_NORMAL, "Total: %zu commit%s",
        history.count, history.count == 1 ? "" : "s"
    );

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
        case LIST_PATH_HISTORY: return list_path_history(ctx, opts);
    }

    CHECK_ARG(false, "a list mode no enumerator names");
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Derive `mode`, `profile`, and `path` from the -p flag and the raw positional
 * bucket.
 *
 * -p <profile> is the leading positional forced to a profile: it names the profile
 * unambiguously, so every positional is then a path. It is the escape hatch for
 * profiles whose names would trip the path heuristic, and it mirrors add/remove's
 * flag-vs-first-positional split.
 *
 *   Flag form (-p given):
 *     0 positionals -> LIST_FILES        (profile = flag)
 *     1 positional  -> LIST_PATH_HISTORY (profile = flag, path = pos[0])
 *     2 positionals -> error: only one path may accompany -p
 *
 *   Inference form (no -p): the leading positional is a profile or a path,
 *   disambiguated by whether it announces a path (infra/input.h
 *   input_announces_path).
 *     0 positionals -> LIST_PROFILES
 *     1 positional  -> path? LIST_PATH_HISTORY (profile inferred)
 *                      name? LIST_FILES
 *     2 positionals -> LIST_PATH_HISTORY (profile = pos[0], path = pos[1])
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
            o->mode = LIST_PATH_HISTORY;
            o->path = o->positional_args[0];
        } else {
            return error_create(ERR_INVALID_ARG, "Only one path may accompany -p/--profile");
        }
        return NULL;
    }

    if (o->positional_count == 0) {
        o->mode = LIST_PROFILES;
        return NULL;
    }

    if (o->positional_count == 1) {
        const char *arg = o->positional_args[0];
        if (input_announces_path(arg)) {
            o->mode = LIST_PATH_HISTORY;
            o->path = arg;
        } else {
            o->mode = LIST_FILES;
            o->profile = arg;
        }
        return NULL;
    }

    if (o->positional_count == 2) {
        o->mode = LIST_PATH_HISTORY;
        o->profile = o->positional_args[0];
        o->path = o->positional_args[1];
        return NULL;
    }

    /* Max=2 enforced by POSITIONAL_RAW — unreachable. */
    CHECK_ARG(false, "POSITIONAL_RAW bounds list's positionals at two");
}

/**
 * What can stand at the cursor, by the rule list_post_parse routes with: under
 * -p, a path of that profile as the one positional — a file, or a directory it
 * claims; without, a local profile or a path of the view first, then — under a
 * profile — a path of its own, standing or not. A path in the first slot was
 * the path: nothing follows it.
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
            completion_directories(ctx, out, o->profile);
        }
        return ARGS_WANT_NONE;
    }
    if (o->positional_count == 0) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        completion_files(ctx, out, NULL, 0);
    } else if (o->positional_count == 1 &&
        !input_announces_path(o->positional_args[0])) {
        completion_refspecs(ctx, out, o->positional_args[0]);
        completion_directories(ctx, out, o->positional_args[0]);
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
        "Show remote sync status as last seen (Level 1 only)"
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
        "   or: %s list [options] <path>\n"
        "   or: %s list [options] <profile> <path>",
    .description =
        "Mode Inference:\n"
        "  No positional              Level 1: all profiles.\n"
        "  1 arg, looks like a path   Level 3: a path's history, profile inferred.\n"
        "  1 arg, looks like a name   Level 2: files in that profile.\n"
        "  2 args                     Level 3: a path's history in profile.\n"
        "\n"
        "A path's history is the commits that changed it: a file, or anything\n"
        "beneath a directory.\n",
    .notes       =
        "Verbose Mode Details:\n"
        "  Level 1    File count, total size, and last commit per profile.\n"
        "  Level 2    File sizes and per-file last commits.\n"
        "  Level 3    Full commit messages instead of oneline format.\n",
    .examples    =
        "  %s list                           # L1 profiles: names only\n"
        "  %s list -v                        # L1 profiles: stats + last commit\n"
        "  %s list --remote                  # L1 profiles: remote sync status\n"
        "  %s list -v --remote               # L1 profiles: full details + remote\n"
        "  %s list global                    # L2 files: paths only\n"
        "  %s list global -v                 # L2 files: sizes + commits\n"
        "  %s list home/.bashrc              # L3 history: oneline commits\n"
        "  %s list global ~/.config/nvim     # L3 history: a directory's commits\n"
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
