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

/**
 * Check if content appears to be binary
 *
 * Scans for NUL bytes in the first 8000 bytes, matching Git's heuristic. Must
 * be called on plaintext content (after decryption).
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
 * Write blob bytes to stdout with a trailing newline ensured
 *
 * Terminal display normalization — byte-faithful extraction lives in `dotta
 * export`, not here. Flushes before returning so buffered IO failures (ENOSPC,
 * closed pipe with SIGPIPE ignored) surface as a non-zero exit instead of vanishing
 * at process teardown.
 */
static error_t *write_stdout(const buffer_t *content) {
    if (content->size > 0 &&
        fwrite(content->data, 1, content->size, stdout) != content->size) {
        return ERROR(ERR_FS, "Failed to write content to stdout");
    }

    if (content->size > 0) {
        const char *data = (const char *) content->data;
        if (data[content->size - 1] != '\n' &&
            fputc('\n', stdout) == EOF) {
            return ERROR(ERR_FS, "Failed to write content to stdout");
        }
    }

    if (fflush(stdout) != 0) {
        return ERROR(ERR_FS, "Failed to write content to stdout");
    }

    return NULL;
}

/**
 * Print blob content with metadata header
 *
 * Uses content layer for transparent decryption. Password prompt only happens
 * if file is encrypted and key is not cached.
 *
 * The header is the path's claims read the way the view projects them: the type
 * is the tree's word, the mode prints only where the type can carry one and the
 * entry claims one, and ownership prints for every kind that holds it — a link's
 * entry exists to carry exactly that. Symlinks show their target, binary files
 * their size without dumping content, encrypted files that decryption occurred.
 */
static error_t *print_blob_content(
    const dotta_ctx_t *ctx,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile,
    const metadata_t *metadata,
    git_filemode_t filemode
) {
    CHECK_NULL(ctx);
    CHECK_NULL(blob_oid);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(metadata);

    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr;
    output_t *out = ctx->out;

    /* Get plaintext content (handles encryption transparently — the content layer
     * classifies by bytes, no caller-supplied flag needed, and by the filemode,
     * which says a link's bytes are its target: they are read as they stand).
     *
     * The metadata-derived `encrypted` bool below is read for display only (the
     * "(encrypted)" annotation): it is byte-truth via the write-time invariant
     * in `content_stage_file`, but does not influence routing inside the content
     * layer. */
    bool encrypted = metadata_file_encrypted(metadata, storage_path);

    buffer_t content = BUFFER_INIT;
    error_t *err = content_get_from_blob_oid(
        repo, blob_oid, filemode, storage_path, profile, keymgr, &content
    );
    if (err) {
        return error_wrap(err, "Failed to get file content");
    }

    bool is_link = (filemode == GIT_FILEMODE_LINK);

    /* Binary detection (on plaintext, after decryption; a link's content is its
     * target path, text by nature) */
    bool is_binary = !is_link && content.size > 0 &&
        content_is_binary((const unsigned char *) content.data, content.size);

    /* Type — the tree's word — and, for a link, the target it stores */
    if (is_link) {
        output_styled(
            out, OUTPUT_NORMAL, "{dim}# Type:{reset}    symlink\n"
        );
        output_styled(
            out, OUTPUT_NORMAL, "{dim}# Target:{reset}  %.*s\n",
            (int) content.size, (const char *) content.data
        );
    } else {
        output_styled(
            out, OUTPUT_NORMAL, "{dim}# Type:{reset}    %s",
            is_binary ? "binary file" : filemode_type_str(filemode)
        );
        if (encrypted) {
            output_print(out, OUTPUT_NORMAL, " (encrypted)");
        }
        output_newline(out, OUTPUT_NORMAL);
    }

    /* The entry's claims, by the projection's own rule: mode only where the type
     * can carry one and the entry claims one; ownership for every kind that holds
     * it. */
    const metadata_item_t *item = metadata_lookup(metadata, storage_path);
    if (item) {
        if (!is_link && item->mode != MODE_UNCLAIMED) {
            output_styled(
                out, OUTPUT_NORMAL, "{dim}# Mode:{reset}    %04o\n",
                (unsigned) item->mode
            );
        }
        if (item->owner || item->group) {
            output_styled(
                out, OUTPUT_NORMAL, "{dim}# Owner:{reset}   %s:%s\n",
                item->owner ? item->owner : "?",
                item->group ? item->group : "?"
            );
        }
    }

    /* Size — for the kinds whose content is bytes, not a target */
    if (!is_link) {
        char size_buf[32];
        output_format_size(content.size, size_buf, sizeof(size_buf));
        output_styled(
            out, OUTPUT_NORMAL, "{dim}# Size:{reset}    %s\n",
            size_buf
        );
    }

    /* The target line said everything a link has to say; binary content is not
     * dumped to the terminal. */
    if (is_link || is_binary) {
        buffer_free(&content);
        return NULL;
    }

    output_styled(
        out, OUTPUT_NORMAL, "{dim}---{reset}\n"
    );

    /* Write content to stdout (trailing newline normalized) */
    err = write_stdout(&content);
    buffer_free(&content);

    return err;
}

/**
 * The tree `show` reads, and the commit it came from
 *
 * The branch's tip, or the tree of the commit the user named — resolved in the
 * branch, so a ref that means something elsewhere means nothing here. A resolved
 * commit is always in hand (sys/gitops.h), and the handle is the tree's source
 * and the header's alike: it comes back beside the tree rather than being spent
 * here, because what it captions is printed once the argument has an answer
 * (show_provenance). `*out_commit` is NULL where the tip was read — a tip is
 * what the profile holds now and has no provenance to announce. Both are the
 * caller's to free.
 */
static error_t *show_source(
    const dotta_ctx_t *ctx,
    const char *profile,
    const char *commit_ref,
    git_tree **out_tree,
    git_commit **out_commit
) {
    CHECK_NULL(ctx);
    CHECK_NULL(profile);
    CHECK_NULL(out_tree);
    CHECK_NULL(out_commit);

    git_repository *repo = ctx->run.repo;

    *out_tree = NULL;
    *out_commit = NULL;

    if (!commit_ref) {
        error_t *err = gitops_load_branch_tree(repo, profile, out_tree, NULL);
        if (err) {
            return error_wrap(err, "Failed to load tree for profile '%s'", profile);
        }
        return NULL;
    }

    git_oid commit_oid;
    git_commit *commit = NULL;
    error_t *err = gitops_resolve_commit_in_branch(
        repo, profile, commit_ref, &commit_oid, &commit
    );
    if (err) return err;

    /* The commit is in hand, so its tree is one dereference and not a second
     * lookup by oid. */
    int ret = git_commit_tree(out_tree, commit);
    if (ret < 0) {
        git_commit_free(commit);
        return error_wrap(
            error_from_git(ret), "Failed to load tree from commit '%s'", commit_ref
        );
    }

    *out_commit = commit;

    return NULL;
}

/**
 * The provenance of what is about to be shown
 *
 * The commit's own header lines, from the handle show_source kept. A caption
 * stands over what it captions, so this is said only once the verb has an answer:
 * an argument the branch refuses by its own noun — a label, a root with no claim
 * on it — leaves nothing of the commit on screen, and the hint under a refusal
 * that asks for a profile cannot be followed into a second refusal under a header.
 * Past that point the header is what says which tree the bytes, or the absence
 * of them, were read from.
 */
static void show_provenance(output_t *out, const git_commit *commit) {
    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), git_commit_id(commit));

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
                out, OUTPUT_NORMAL, "{dim}# Message:{reset} %s\n", msg
            );
        }
    }
}

/**
 * Print one claim of a profile, from the tree the caller opened
 *
 * The tree is the authority on what stands at the name; the sheet beside it is
 * read for the encryption state the content layer validates against, tolerantly
 * — a tree without one holds an empty sheet, and one that will not load is folded
 * into an empty sheet too, which then says nothing about anything.
 *
 * The name is asked of both documents at once, the sheet as this verb read it
 * (core/profiles.h profile_holds), and answered four ways. A blob is printed. A
 * subtree and a gitlink are each refused by their own noun. A directory claim
 * the sheet alone holds — a tracked directory the branch holds no blob beneath
 * — is refused as the directory it is, because the profile does hold it and "not
 * found" would be the wrong word. Only a name neither document holds is not found.
 */
static error_t *show_file(
    const dotta_ctx_t *ctx,
    const char *profile,
    const char *storage_path,
    const git_tree *tree
) {
    git_repository *repo = ctx->run.repo;

    metadata_t *metadata = NULL;

    /* The sheet of the same tree, for the encryption state print_blob_content
     * validates against. A tree without one loads as an empty sheet; one that
     * would not load is folded into an empty sheet too, and then says nothing —
     * about the encryption state, and about a directory claim below. Handed to
     * the read below, so the name is answered from the sheet as this verb read
     * it, and the sheet is read once. */
    error_t *err = metadata_load_from_tree(repo, tree, profile, &metadata);
    if (err) {
        error_free(err);
        err = metadata_create_empty(&metadata);
        if (err) {
            return error_wrap(err, "Failed to create metadata");
        }
    }

    profile_held_t held;
    err = profile_holds(repo, tree, metadata, profile, storage_path, &held);
    if (err) goto cleanup;

    switch (held.kind) {
        case PROFILE_HELD_FILE:
            /* The bytes, decrypted where they are ciphertext: the name is the
             * one the blob was sealed under (the AAD, infra/content.h), the profile
             * derives the key, and the sheet says what state to expect. */
            err = print_blob_content(
                ctx, &held.oid, storage_path, profile, metadata, held.filemode
            );
            break;

        case PROFILE_HELD_DIRECTORY:
        case PROFILE_HELD_SUBMODULE:
            err = ERROR(
                ERR_INVALID_ARG, "'%s' is %s; show prints one file's bytes",
                storage_path,
                held.kind == PROFILE_HELD_DIRECTORY ? "a directory" : "a submodule"
            );
            break;

        case PROFILE_HELD_NOTHING:
            err = ERROR(ERR_NOT_FOUND, "File '%s' not found", storage_path);
            break;
    }

cleanup:
    metadata_free(metadata);

    return err;
}

/**
 * Callback for printing diff lines with color
 *
 * Colorizes additions (green), deletions (red), and headers (cyan). Matches the
 * diff command's output style.
 */
static int print_diff_line_cb(
    const git_diff_delta *delta,
    const git_diff_hunk *hunk,
    const git_diff_line *line,
    void *payload
) {
    output_t *out = (output_t *) payload;
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
    output_t *out
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

    /* Resolve commit in profile. The resolution names both the commit and the
     * branch in every fate it has (sys/gitops.h), so there is nothing to restate
     * here — and the sentence that used to stand over it said "not found" of an
     * ancestry the walk could not read. */
    err = gitops_resolve_commit_in_branch(
        repo, profile, commit_ref, &commit_oid, &commit
    );
    if (err) goto cleanup;

    /* Get commit tree — from the commit in hand, not by a second lookup */
    int ret = git_commit_tree(&commit_tree, commit);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Get parent tree (NULL if first commit) — only its oid is in hand */
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

    /* Print the diff with color */
    ret = git_diff_print(
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
error_t *cmd_show(const dotta_ctx_t *ctx, const cmd_show_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    /* Borrow the dispatcher's mount table over all enabled profiles. */
    const mount_table_t *mounts = ctx->run.mounts;
    output_t *out = ctx->out;

    error_t *err = NULL;
    string_array_t *profiles = NULL;
    manifest_t *manifest = NULL;
    git_tree *tree = NULL;
    git_commit *source = NULL;
    const char *profile = opts->profile;
    const char *storage_path = NULL;

    /* Handle SHOW_COMMIT mode */
    if (opts->mode == SHOW_COMMIT) {
        CHECK_NULL(opts->commit);

        if (!profile) {
            /* No profile specified - use enabled profiles */
            err = profile_resolve_enabled(repo, state, &profiles);
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
                error_t *try_err = show_commit(repo, opts->commit, profile, out);

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
        err = profile_require(repo, profile);
        if (err) goto cleanup;

        err = show_commit(repo, opts->commit, profile, out);
        goto cleanup;
    }

    /* Handle SHOW_FILE mode */
    CHECK_NULL(opts->file_path);

    /* The argument first, above the profile question and above anything opened
     * or announced under either: reading one asks no topology (infra/path.h),
     * so a key show cannot act on is refused in its own words with nothing of
     * the repository standing on screen above it. Read once for both arms, which
     * differ in where each key's answer comes from and not in which keys they
     * take. */
    path_input_t arg;
    err = path_input_resolve(opts->file_path, ctx->arena, &arg);
    if (err) goto cleanup;

    switch (arg.key) {
        case PATH_KEY_LOCATION:
        case PATH_KEY_STORAGE:
            break;

        case PATH_KEY_LABEL:
            /* A label names the namespace above every path of its kind, and show
             * prints one file's bytes. Said without the flag's profile, bound
             * or not: what a label names is the same on every machine and for
             * every asker, so there is nothing here for a profile to change. */
            err = path_input_refuse_label(arg.label);
            goto cleanup;
    }

    if (profile) {
        /* The profile named must be here before its tree is opened. Then the
         * tree the profile selected — its tip, or the commit's — which is both
         * where the claim is looked for and what its bytes come from, so a name
         * that changed since the commit is found as of then (core/profiles.h
         * profile_claim_name). */
        err = profile_require(repo, profile);
        if (err) goto cleanup;

        err = show_source(ctx, profile, opts->commit, &tree, &source);
        if (err) goto cleanup;

        /* The two keys the door left. A name the user typed is Git's key already,
         * so show_file's own read of the branch's two documents is what decides
         * whether the profile holds it; a location is the branch's to name. */
        if (arg.key == PATH_KEY_STORAGE) {
            storage_path = arg.storage_path;
        } else {
            err = profile_claim_name(
                repo, tree, mounts, profile, arg.location, ctx->arena, &storage_path
            );
            if (err) goto cleanup;
        }

        /* The argument is answered, so the commit it was read from can caption
         * the answer. A tip named none and captions nothing. */
        if (source) {
            show_provenance(out, source);
        }

        err = show_file(ctx, profile, storage_path, tree);
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

    /* The owning profile is the view's: the enabled set at HEAD with precedence
     * resolved, asked in the key the argument names. A location is one row, the
     * winner standing there whatever its name. A name keys within one profile,
     * so the view may hold it once (home/, root/, or one binding), or once per
     * binding under custom/ — and then no profile is the answer, and each holder
     * is named with the location that tells them apart. */
    err = manifest_build(repo, state, ctx->arena, &manifest);
    if (err) goto cleanup;

    const manifest_row_t *row = NULL;
    if (arg.key == PATH_KEY_LOCATION) {
        row = manifest_lookup(manifest, arg.location);
        if (!row) {
            /* No row is not the same as no thing: a location standing at a root
             * of the view is a place, and is refused in the root's own words as
             * it is under -p (core/manifest.h manifest_root_at). A name is never
             * a root, so only this arm asks. */
            const mount_root_t *root = manifest_root_at(manifest, arg.location);
            if (root) {
                err = mount_root_refuse(root);
                goto cleanup;
            }
        }
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
                out, OUTPUT_NORMAL, "  dotta show -p <profile> %s", arg.storage_path
            );
            err = ERROR(ERR_INVALID_ARG, "Ambiguous path '%s'", arg.storage_path);
            goto cleanup;
        }
    }
    if (!row) {
        err = ERROR(
            ERR_NOT_FOUND, "File '%s' not found in enabled profiles",
            opts->file_path
        );
        goto cleanup;
    }

    /* The winner names both halves: whose claim stands there, and what it is
     * called — the row is that profile's own, so there is nothing to look up
     * again in its branch. */
    profile = row->profile;
    storage_path = row->storage_path;

    output_styled(
        out, OUTPUT_NORMAL, "{dim}# Profile:{reset} %s\n",
        profile
    );
    output_styled(
        out, OUTPUT_NORMAL, "{dim}# Path:{reset}    %s\n",
        storage_path
    );

    /* The tip, which this arm is always about: the view is HEAD's, so the row
     * that answered names no commit and there is no provenance to announce. */
    err = show_source(ctx, profile, NULL, &tree, &source);
    if (err) goto cleanup;

    err = show_file(ctx, profile, storage_path, tree);

cleanup:
    git_commit_free(source);
    git_tree_free(tree);
    manifest_free(manifest);
    string_array_free(profiles);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Interpret the 0-3 raw positionals into `profile`, `file_path`, `commit`, and
 * `mode`.
 *
 * Allocation model: all refspec strings are allocated in `arena`. Pure positional
 * pointers borrow argv. cmd_show does not free any of these pointers — the engine's
 * arena owns their lifetime.
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
        if (refspec_looks_like_commit(arg) && !strchr(arg, '/') &&
            !strchr(arg, '.')) {
            o->mode = SHOW_COMMIT;
            o->commit = arg;
            return NULL;
        }

        /* File mode: parse [profile:]file[@commit] into arena. */
        o->mode = SHOW_FILE;
        refspec_t rs = { 0 };
        error_t *err = parse_refspec(arena, arg, &rs);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse file specification");
        }
        /* A refspec-supplied profile overrides any -p/--profile flag. */
        if (rs.profile != NULL) o->profile = rs.profile;
        o->file_path = rs.file;
        if (rs.commit != NULL) o->commit = rs.commit;
        return NULL;
    }

    if (o->positional_count == 2) {
        o->mode = SHOW_FILE;

        if (refspec_looks_like_commit(args[1])) {
            /* <file> <commit> */
            o->file_path = args[0];
            o->commit = args[1];
            return NULL;
        }

        /* <profile> <file[@commit]> — refspec profile wins if present. */
        o->profile = args[0];
        refspec_t rs = { 0 };
        error_t *err = parse_refspec(arena, args[1], &rs);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse file specification");
        }
        if (rs.profile != NULL) o->profile = rs.profile;
        o->file_path = rs.file;
        if (rs.commit != NULL) o->commit = rs.commit;
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

/**
 * What can stand at the cursor, by the shapes show_post_parse reads. First: a
 * file of any branch as `profile:path` — bare once -p pins one — or a commit.
 * After one positional, the grammar decides by the next token whether it was a
 * profile (`<profile> <file>`) or a file (`<file> <commit>`), so both are offered
 * — the files of the profile it pins, and that profile's history. After two:
 * the commit. An `@` in the token being typed completes its commit part from
 * the refspec's history.
 */
static args_want_t show_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_show_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_show_options_t, profile)) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    if (completion_commits_at(ctx, out, at->current, o->profile)) {
        return ARGS_WANT_NONE;
    }

    const char *pinned = o->profile;
    if (pinned == NULL && o->positional_count >= 1) {
        pinned = completion_profile_of(ctx, o->positional_args[0]);
    }

    if (o->positional_count == 0) {
        completion_refspecs(ctx, out, pinned);
        completion_history(ctx, out, pinned);
    } else if (o->positional_count == 1) {
        if (o->profile == NULL) {
            completion_refspecs(ctx, out, pinned);
        }
        completion_history(ctx, out, pinned);
    } else if (o->positional_count == 2) {
        completion_history(ctx, out, pinned);
    }
    return ARGS_WANT_NONE;
}

static error_t *show_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_show(ctx, (const cmd_show_options_t *) opts_v);
}

static const args_opt_t show_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",       "<name>",
        cmd_show_options_t,profile,
        "Override profile for file or commit lookup"
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
        "  or storage (home/.bashrc, root/etc/hosts).\n"
        "\n"
        "  Output is a terminal display: a metadata header precedes the\n"
        "  content, and binary content is summarized, never dumped. For\n"
        "  the exact bytes, use 'export <profile>:<file> -'.\n",
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
        "  %s diff <commit> <commit>  # Compare two commits\n"
        "  %s export <target> -o <dest>  # Copy content to the filesystem\n",
    .opts_size   = sizeof(cmd_show_options_t),
    .opts        = show_opts,
    .post_parse  = show_post_parse,
    .complete    = show_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_READ,
        .mounts  = true,
        .crypto  = DOTTA_CRYPTO_OBTAIN,
    },
    .dispatch    = show_dispatch,
};
