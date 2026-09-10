/**
 * revert.c - Revert file to previous commit state
 */

#include "cmds/revert.h"

#include <config.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/args.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/output.h"
#include "base/refspec.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/identity.h"
#include "sys/stage.h"
#include "utils/commit.h"

/**
 * Which profile the revert acts on
 *
 * The profile question, and only that. What that profile calls the argument is
 * read afterwards, and twice: from the commit's tree for the bytes to restore
 * and from the tree the revert edits for the name to write them under (cmd_revert
 * steps 8 and 10). A branch's tip is its stage's tree, so the search below and
 * the naming there read one source and cannot disagree about a name.
 *
 * With `opts->profile`: the user's word, required to be here. Whether the branch
 * holds the argument at its tip is not asked — a revert restores what the *commit*
 * holds, and a path the profile deleted is the case a revert exists for.
 *
 * Without: every local branch is asked what it stands at the argument
 * (profile_discover_claims — enabled or not, revert's question), and an argument
 * two profiles hold is ambiguous, listed with each branch's own name for it and
 * refused.
 */
static error_t *select_profile(
    const dotta_ctx_t *ctx,
    const cmd_revert_options_t *opts,
    const path_input_t *arg,
    const char **out_profile
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(arg);
    CHECK_NULL(out_profile);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    *out_profile = NULL;

    if (opts->profile) {
        RETURN_IF_ERROR(profile_require(repo, opts->profile));
        *out_profile = opts->profile;
        return NULL;
    }

    /* The argument in the key it named — what every statement below is about.
     * The hints spell the command with what the user typed, so they paste back,
     * and they spell it in the three-positional form: that is the one arm of
     * revert_post_parse that assigns without asking str_looks_like_git_ref whether
     * the second word is a commit, so a tag or a branch name pastes back as readily
     * as an oid does. */
    const char *subject = arg->key == PATH_KEY_LOCATION ? arg->location
                                                        : arg->storage_path;

    profile_claims_t claims = { 0 };
    error_t *err = profile_discover_claims(
        repo, ctx->run.mounts, arg, ctx->arena, &claims
    );
    if (err) {
        if (error_code(err) != ERR_NOT_FOUND) return err;
        error_free(err);
        return ERROR(
            ERR_NOT_FOUND, "'%s' is not held by any profile\n\n"
            "If you are trying to revert a deleted file, specify the profile:\n"
            "  dotta revert <profile> %s %s\n\n"
            "Use 'dotta list' to see all profiles.",
            subject, opts->file_path, opts->commit
        );
    }

    if (claims.count == 1) {
        *out_profile = claims.entries[0].profile;
        return NULL;
    }

    output_print(
        out, OUTPUT_NORMAL, "'%s' is held by %zu profiles:\n", subject,
        claims.count
    );
    for (size_t i = 0; i < claims.count; i++) {
        output_print(
            out, OUTPUT_NORMAL, "  • %s  (%s)\n", claims.entries[i].profile,
            claims.entries[i].storage_path
        );
    }
    output_hint(out, OUTPUT_NORMAL, "Name the profile to disambiguate:");
    output_hintline(
        out, OUTPUT_NORMAL, "  dotta revert <profile> %s %s",
        opts->file_path, opts->commit
    );

    return ERROR(ERR_INVALID_ARG, "Ambiguous path '%s'", subject);
}

/**
 * The claim `profile` stands at `location` in `tree`, or NULL when it stands none
 *
 * One contribution of the tree, asked for the row at the location and freed
 * (core/manifest.h manifest_build_tree, manifest_lookup_claim). The row is the
 * arena's and outlives the view — manifest_free releases the heap indexes and
 * nothing else — so the answer survives this call.
 *
 * The row and not its name, because this file asks it two ways: the read takes
 * any claim, and the write's name takes the claim standing there whatever it is
 * called. A verb answering a string would have to pick one of them for both,
 * which is also why revert no longer asks core/profiles.h profile_claim_name:
 * over a past tree a name today's roots would compose is one that tree never
 * held, and for a verb that writes, composing a name would choose a deployment
 * contract. The third question — may this name be authored at all — is the
 * admission's, and it reads more of one view than a row (refuse_second_name).
 *
 * Strict, like every view: a tree whose sheet will not load refuses the question
 * rather than answering from the tree alone. cmd_revert loads both sheets strictly
 * already, so no policy is added here.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param tree The tree the claim is looked for in (must not be NULL)
 * @param profile Whose claims these are (must not be NULL)
 * @param location Where to ask (must not be NULL)
 * @param out_row The claim, or NULL where none stands (must not be NULL; the
 *                command arena's, borrowed)
 * @return Error or NULL on success
 */
static error_t *claim_standing(
    const dotta_ctx_t *ctx,
    const git_tree *tree,
    const char *profile,
    const char *location,
    const manifest_row_t **out_row
) {
    CHECK_NULL(ctx);
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(location);
    CHECK_NULL(out_row);

    *out_row = NULL;

    manifest_t *view = NULL;
    error_t *err = manifest_build_tree(
        ctx->run.repo, tree, profile, ctx->run.mounts, ctx->arena, &view
    );
    if (err) return err;

    *out_row = manifest_lookup_claim(view, profile, location);  /* the arena's */
    manifest_free(view);

    return NULL;
}

/**
 * Refuse a typed name that would give the profile a second name for one location
 *
 * The tip's own contribution, asked two questions while it is alive: the claim
 * standing where the name resolves, and whether the profile holds the typed name
 * at all (core/manifest.h manifest_holds_name). Both readings are the
 * contribution's, so they are asked of one build rather than of a row that outlived
 * it — the second reads the names the settle recorded against the standing one,
 * which no row carries.
 *
 * A name the profile already holds is a re-capture and authors nothing, whether
 * it is the name standing at the location or one the settle did not keep. Only
 * a name new to the profile at a location it already names is a second name,
 * and that is what this refuses — naming the first, and not skippable by --force:
 * a refusal is not a confirmation.
 *
 * A derived claim names nothing (manifest_is_derived), so it is not a first name
 * and does not block one — explicit outranks derived within a profile as across
 * them.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param tip The tip's tree, whose claims the name would join (must not be NULL)
 * @param profile Whose claims these are (must not be NULL)
 * @param location Where the typed name resolves (must not be NULL)
 * @param name The typed name (must not be NULL)
 * @param commit Abbreviated target commit oid, for the remedy (must not be NULL)
 * @return The refusal, or NULL when the name may be authored
 */
static error_t *refuse_second_name(
    const dotta_ctx_t *ctx,
    const git_tree *tip,
    const char *profile,
    const char *location,
    const char *name,
    const char *commit
) {
    CHECK_NULL(ctx);
    CHECK_NULL(tip);
    CHECK_NULL(profile);
    CHECK_NULL(location);
    CHECK_NULL(name);
    CHECK_NULL(commit);

    manifest_t *view = NULL;
    error_t *err = manifest_build_tree(
        ctx->run.repo, tip, profile, ctx->run.mounts, ctx->arena, &view
    );
    if (err) return err;

    const manifest_row_t *row = manifest_lookup_claim(view, profile, location);
    if (row && !manifest_is_derived(row) &&
        !manifest_holds_name(view, profile, location, name)) {
        /* The location is the shared term of three paths in one sentence, and
         * the one path here the user never typed — so it is spelled the way the
         * shell spells it, as the screen that reports the pair this refuses already
         * spells it (cmds/status.c's unused-path listing, base/output.h
         * output_format_path). The remedy stays runnable: a tilde is what the
         * shell expands back. */
        char shown[PATH_MAX];
        output_format_path(location, identity()->home, shown, sizeof(shown));

        /* Both remedies are spelled to run: the revert in the three-positional
         * form, which assigns its words by position and never asks
         * str_looks_like_git_ref whether the second one is a commit — the
         * two-positional form reads a tag or a branch name as a profile and refuses
         * the command it was offered as. */
        err = ERROR(
            ERR_INVALID_ARG,
            "Profile '%s' names '%s' as '%s'\n\n"
            "'%s' would be a second name for it, and a profile names a "
            "location once.\n"
            "  dotta revert %s %s %s   restores those bytes into it\n"
            "  dotta remove %s %s   gives that name up first",
            profile, shown, row->storage_path, name,
            profile, shown, commit, profile, row->storage_path
        );
    }

    manifest_free(view);

    return err;
}

/**
 * The entry the target commit holds for this file, and the name it stands under
 *
 * Asked in the key the user named (cmds/revert.h, the two names), and it never
 * sees the tip: the read's name is the commit's alone.
 *
 *   a LOCATION  — the claim standing at the location, whatever it is called; the
 *                 tree then says whether that claim is one file.
 *   a STORAGE   — the name as typed, because a name is Git's key and does not
 *                 move. Only a name the commit holds neither in its tree nor in
 *                 its sheet is a contract change to find, and then the location
 *                 is the key.
 *
 * The sheet before the fallback, and that is not an optimisation: a DIRECTORY
 * claim can stand at exactly the typed name with no tree entry — a tracked
 * directory with nothing inside it, or an ancestor chain the tree no longer has
 * — and reading its absence as permission to search the location would answer
 * with a *different* claim's blob under the name the user typed.
 *
 * A name kept without an entry is the whole of one case, and that is why the
 * fallback is guarded by the name and not by the entry: a claim stands at the
 * name and the tree holds nothing there, which is the one kind of claim that
 * lives in the sheet alone. Every other absence leaves no name at all, and the
 * two are told apart once, below.
 *
 * Refuses rather than answering nothing, so the caller holds a blob or an error
 * and no third state: a directory or a submodule by its own noun, and an absence
 * worded from the key the user named — a location that is a root of the profile
 * saying so instead, after both rungs have answered rather than before, because
 * a root the commit held a file at is one file.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param target_tree The target commit's tree (must not be NULL)
 * @param target_sheet The target commit's claim sheet (must not be NULL)
 * @param profile Whose claims these are (must not be NULL)
 * @param arg The argument, in the key it named (must not be NULL)
 * @param location Where both trees may be asked about, or NULL for a custom/
 *                 name this machine cannot place
 * @param commit Abbreviated target commit oid, for the refusals (must not be NULL)
 * @param out_name The name the entry stands under (must not be NULL; borrowed)
 * @param out_entry The entry (must not be NULL; caller frees with
 *                  git_tree_entry_free)
 * @return Error or NULL on success
 */
static error_t *entry_to_restore(
    const dotta_ctx_t *ctx,
    const git_tree *target_tree,
    const metadata_t *target_sheet,
    const char *profile,
    const path_input_t *arg,
    const char *location,
    const char *commit,
    const char **out_name,
    git_tree_entry **out_entry
) {
    CHECK_NULL(ctx);
    CHECK_NULL(target_tree);
    CHECK_NULL(target_sheet);
    CHECK_NULL(profile);
    CHECK_NULL(arg);
    CHECK_NULL(commit);
    CHECK_NULL(out_name);
    CHECK_NULL(out_entry);

    *out_name = NULL;
    *out_entry = NULL;

    const char *name = NULL;
    git_tree_entry *entry = NULL;

    if (arg->key == PATH_KEY_STORAGE) {
        name = arg->storage_path;

        /* git_tree_entry_bypath answers three ways and is read as three: an
         * intermediate object that will not load is a failure to read, never an
         * absence. */
        int rc = git_tree_entry_bypath(&entry, target_tree, name);
        if (rc < 0 && rc != GIT_ENOTFOUND) {
            return error_from_git(rc);
        }

        if (!entry) {
            /* A DIRECTORY claim standing at exactly this name is a claim and
             * not an absence, both classes of it. A FILE item without a blob
             * claims nothing — the tree is the content authority (core/manifest.h)
             * — and only that one frees the location to answer. */
            const metadata_item_t *item = metadata_lookup(target_sheet, name);
            if (!item || item->kind != PATH_KIND_DIRECTORY) {
                name = NULL;
            }
        }
    }

    /* The name is the guard, and it also makes the write below safe: the arm
     * above drops the name only where it found no entry, so no entry can be
     * standing here to overwrite. */
    if (!name && location) {
        const manifest_row_t *row = NULL;
        RETURN_IF_ERROR(
            claim_standing(ctx, target_tree, profile, location, &row)
        );

        if (row) {
            name = row->storage_path;
            int rc = git_tree_entry_bypath(&entry, target_tree, name);
            if (rc < 0 && rc != GIT_ENOTFOUND) {
                return error_from_git(rc);
            }
        }
    }

    if (!entry) {
        if (name) {
            /* The sheet claims what the tree does not hold. Where the fallback
             * found it, this name is not the one the user typed, and that
             * difference is the information. */
            return ERROR(
                ERR_INVALID_ARG,
                "'%s' is a directory at commit %s; revert restores one file",
                name, commit
            );
        }

        if (arg->key == PATH_KEY_LOCATION) {
            const mount_spec_t *root = mount_root(ctx->run.mounts, profile, arg->location);
            if (root) {
                char buf[MOUNT_NOUN_MAX];
                const char *noun = mount_root_describe(root, profile, buf, sizeof(buf));
                return ERROR(
                    ERR_INVALID_ARG, "'%s' is %s: name what is inside it",
                    arg->location, noun
                );
            }
            return ERROR(
                ERR_NOT_FOUND, "Profile '%s' held nothing at '%s' at commit %s",
                profile, arg->location, commit
            );
        }

        return ERROR(
            ERR_NOT_FOUND, "File '%s' not found at commit %s in profile '%s'",
            arg->storage_path, commit, profile
        );
    }

    git_object_t type = git_tree_entry_type(entry);
    if (type != GIT_OBJECT_BLOB) {
        git_tree_entry_free(entry);
        return ERROR(
            ERR_INVALID_ARG, "'%s' is %s at commit %s; revert restores one file",
            name, type == GIT_OBJECT_TREE ? "a directory" : "a submodule", commit
        );
    }

    *out_name = name;
    *out_entry = entry;

    return NULL;
}

/**
 * Show diff preview between two blobs
 *
 * Uses content layer to transparently decrypt encrypted files before diffing,
 * so users see readable plaintext diffs instead of encrypted gibberish. The content
 * layer classifies each blob by its own bytes, so blobs with different encryption
 * states across commits are routed correctly without any caller-supplied flag.
 *
 * Each blob is read under its own name, because a name is what an encrypted blob
 * is sealed under (crypto/cipher.h "Path binding") and the two names differ
 * wherever the profile renamed the claim. One label, though: the revert is not
 * a rename — the commit's name stays in history and nothing moves it — and a
 * patch header naming two paths would say it was. The preview's own "Named at
 * the commit" line is where the other name is said.
 *
 * `target_oid` is the object the commit holds and never the id a reseal would
 * take: that one names no object yet, and nothing here would open under it.
 *
 * The two blobs differ: the caller reaches this only from the preview arm that
 * says so, and the arm beside it is what a copy with the same bytes and a different
 * mode gets.
 *
 * That arm is also why the caller hands its `restored_name` in here: the tip's
 * entry is looked up at the name the revert writes, so wherever there is an entry
 * to diff against, the write's name is the tip's binding and the two words name
 * one string.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param profile Profile name, for key derivation (must not be NULL)
 * @param standing_name The tip's binding, and the label on both sides (must not
 *                     be NULL)
 * @param standing_oid The blob standing at the tip (must not be NULL)
 * @param target_name The commit's binding: how its bytes open (must not be NULL)
 * @param target_oid The committed object (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *show_diff_preview(
    const dotta_ctx_t *ctx,
    const char *profile,
    const char *standing_name,
    const git_oid *standing_oid,
    const char *target_name,
    const git_oid *target_oid
) {
    CHECK_NULL(ctx);
    CHECK_NULL(profile);
    CHECK_NULL(standing_name);
    CHECK_NULL(standing_oid);
    CHECK_NULL(target_name);
    CHECK_NULL(target_oid);

    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr; /* NULL if encryption disabled */
    output_t *out = ctx->out;

    /* Get decrypted plaintext content from both blobs.
     *
     * Each call classifies its own blob's bytes — the routing decision lives
     * with the blob, so encryption-state changes between commits are handled by
     * the content layer with no caller participation. */
    buffer_t standing_plaintext = BUFFER_INIT;
    error_t *err = content_get_from_blob_oid(
        repo,
        standing_oid,
        standing_name,
        profile,
        keymgr,
        &standing_plaintext
    );
    if (err) {
        return error_wrap(err, "Failed to get current file content");
    }

    buffer_t target_plaintext = BUFFER_INIT;
    err = content_get_from_blob_oid(
        repo,
        target_oid,
        target_name,
        profile,
        keymgr,
        &target_plaintext
    );
    if (err) {
        buffer_free(&standing_plaintext);
        return error_wrap(err, "Failed to get target file content");
    }

    /* Create patch directly from plaintext buffers using in-memory API
     *
     * This uses libgit2's buffer-based patch API to avoid creating temporary
     * blobs in the Git ODB that would persist until gc.
     */
    git_patch *patch = NULL;
    int ret = git_patch_from_buffers(
        &patch,
        standing_plaintext.data, standing_plaintext.size, standing_name,
        target_plaintext.data, target_plaintext.size, standing_name,
        NULL  /* options */
    );

    if (ret < 0) {
        buffer_free(&standing_plaintext);
        buffer_free(&target_plaintext);
        return error_from_git(ret);
    }

    /* Get patch stats */
    size_t additions = 0;
    size_t deletions = 0;
    git_patch_line_stats(NULL, &additions, &deletions, patch);

    /* Show header */
    output_section(out, OUTPUT_NORMAL, "Changes preview");

    /* Show stats */
    output_styled(
        out, OUTPUT_NORMAL, "  File: {cyan}%s{reset}\n",
        standing_name
    );
    output_styled(
        out, OUTPUT_NORMAL, "  Changes: {green}+%zu{reset} / {red}-%zu{reset}\n",
        additions, deletions
    );
    output_newline(out, OUTPUT_NORMAL);

    /* Print patch */
    git_buf buf = { 0 };
    ret = git_patch_to_buf(&buf, patch);
    if (ret < 0) {
        output_warning(out, OUTPUT_NORMAL, "Could not format diff output");
    } else if (buf.ptr) {
        output_print_diff(out, buf.ptr);
    }

    git_buf_dispose(&buf);
    git_patch_free(patch);

    /* Free plaintext buffers */
    buffer_free(&standing_plaintext);
    buffer_free(&target_plaintext);

    return NULL;
}

/**
 * Build commit message for revert operation
 *
 * Uses custom message if provided, otherwise generates from template system.
 * This centralizes message generation logic for reuse across revert operations.
 *
 * @param config Configuration (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param file_path File path (must not be NULL)
 * @param target_commit_oid Target commit OID (must not be NULL)
 * @param custom_message Custom message (can be NULL for template generation)
 * @return Allocated message string (caller must free), or NULL on allocation
 *         failure
 */
static char *build_revert_commit_message(
    const config_t *config,
    const char *profile,
    const char *file_path,
    const git_oid *target_commit_oid,
    const char *custom_message
) {
    if (custom_message && custom_message[0]) {
        return strdup(custom_message);
    }

    /* Generate message using template system */
    char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), target_commit_oid);

    /* Build context for commit message */
    char *files[] = { (char *) file_path };
    commit_message_context_t ctx = {
        .action        = COMMIT_ACTION_REVERT,
        .profile       = profile,
        .files         = files,
        .file_count    = 1,
        .custom_msg    = NULL,
        .target_commit = oid_str
    };

    return build_commit_message(config, &ctx);
}

/**
 * The claim to restore: the one the target commit records, or one reconstructed
 * from the entry it holds
 *
 * A symlink's claim is the entry as recorded — revert restores history, it does
 * not reinterpret it — and its absence is an answer (NULL): the target records
 * no claim for the link, so the standing one is retired by the write. For every
 * other blob the encrypted bit is stamped from the restored blob's own bytes
 * (the write-boundary invariant — see policy.h), over an item cloned from the
 * sheet or, where the target commit has none, over a mode read from the entry's
 * own filemode and no ownership at all.
 *
 * The claim is built and not announced: a reconstruction is a fact about a write,
 * and the write may still be answered "nothing to do" by the gate that reads
 * this claim. The caller says it at the preview, where every other fact about
 * the write is said and where the user can still decline it.
 *
 * The name is the one the revert writes, because a claim outlives the name it
 * was recorded under: the target commit records it at one, and the revert writes
 * it at the name the branch holds now (cmd_revert, the two names). Every
 * construction takes the second — the sheet's own key is what metadata_same_claim
 * compares, so a claim built under the commit's name would answer "different"
 * against every standing one.
 *
 * Every input is a fact the caller has already established, and none of them is
 * a Git object: the claim the commit records, the name to write it under, the
 * entry's filemode and the restored blob's kind. Nothing here reads the repository
 * or writes to a screen, so nothing here can fail, and nothing here can be said
 * about a write that does not happen.
 *
 * @param recorded The FILE claim the target commit records, or NULL where it
 *                 records none (borrowed)
 * @param restored_name Storage path the claim is written under (must not be NULL)
 * @param restored_mode The admitted entry's filemode
 * @param target_kind The restored blob's own bytes (cmd_revert step 9)
 * @param out_claim The claim, or NULL where the target records none (must not
 *                  be NULL; caller frees with metadata_item_free)
 * @return Error or NULL on success
 */
static error_t *claim_to_restore(
    const metadata_item_t *recorded,
    const char *restored_name,
    git_filemode_t restored_mode,
    content_kind_t target_kind,
    metadata_item_t **out_claim
) {
    CHECK_NULL(restored_name);
    CHECK_NULL(out_claim);

    *out_claim = NULL;

    if (restored_mode == GIT_FILEMODE_LINK) {
        /* A link's entry is a FILE item without a mode. Restore it as recorded
         * — revert restores history, it does not reinterpret it; whatever the
         * entry carries, the view adjudicates against the tree. No entry → the
         * write's retire arm takes the standing item. */
        if (!recorded) {
            return NULL;
        }
        return metadata_item_clone(recorded, restored_name, out_claim);
    }

    /* The encrypted bit revert writes must be true of the blob it restores: it
     * is stamped from the target blob's own bytes — the single authority — the
     * way the capture paths stamp from the bytes they store, never trusted from
     * (or, absent an entry, invented beside) a historical stamp.
     * UNSUPPORTED_VERSION carries encryption intent and collapses onto true,
     * the same collapse the capture paths make. */
    const bool encrypted = (target_kind != CONTENT_PLAINTEXT);

    if (recorded) {
        /* Found metadata entry - clone it. Mode and ownership have no byte source,
         * so the entry is their authority; the encrypted bit is the blob's
         * (above). */
        RETURN_IF_ERROR(metadata_item_clone(recorded, restored_name, out_claim));
        (*out_claim)->encrypted = encrypted;
        return NULL;
    }

    /* No metadata entry at target commit - mode falls back to the tree's filemode;
     * ownership is not recoverable. The caller announces it (cmd_revert step
     * 17). */
    return metadata_item_create_file(
        restored_name, restored_mode & 0777, encrypted, out_claim
    );
}

/**
 * Is the revert's whole write already standing at the name?
 *
 * The entry it would put — both halves of it, the blob and the mode Git records
 * — and the claim it would write beside it. A revert restores bytes, the entry's
 * mode, and the sheet's mode and ownership; comparing blob oids alone read a
 * restored exec bit, a 0644 over a 0600 and an ownership claim as "no changes"
 * and did nothing about any of them. A tree's filemode carries only the
 * owner-execute bit (infra/content), so the sheet cannot be read off the entry
 * and is asked for itself.
 *
 * `standing` is NULL where the branch's tip has no entry at the name — a path
 * the profile deleted, which is never already at the target. The restored side
 * is an id and a mode rather than an entry, because it may belong to no tree
 * entry at all: bytes resealed under a new name are an object the repository
 * does not hold yet (cmd_revert, the rebind), and it is that object the write
 * would store.
 *
 * The proof this gate needs is one-way, and it is the only one it makes: if the
 * selected blob, its filemode, or the reconstructed claim differs, this write
 * moves an entry or the sheet's bytes. It holds because metadata_same_claim and
 * metadata_to_json read the same seven fields — kind, key, mode, owner, group,
 * encrypted, tracked. The converse does not, for a hand-written sheet the parser
 * accepts and the serializer normalizes, and nothing here uses it: the true arm
 * exits before anything is staged.
 *
 * @param standing The entry at the branch tip, or NULL for none
 * @param standing_claim The sheet's claim at the name there, or NULL for none
 * @param restored_blob The blob the write would store (must not be NULL)
 * @param restored_mode The filemode it would carry
 * @param restored_claim The claim the revert would write, or NULL where the target
 *                       records none
 * @return true when nothing about the write would change the branch
 */
static bool already_at_target(
    const git_tree_entry *standing,
    const metadata_item_t *standing_claim,
    const git_oid *restored_blob,
    git_filemode_t restored_mode,
    const metadata_item_t *restored_claim
) {
    return standing &&
           git_oid_equal(git_tree_entry_id(standing), restored_blob) &&
           git_tree_entry_filemode(standing) == restored_mode &&
           metadata_same_claim(standing_claim, restored_claim);
}

/**
 * Revert command implementation
 */
error_t *cmd_revert(const dotta_ctx_t *ctx, const cmd_revert_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->file_path);
    CHECK_NULL(opts->commit);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    const mount_table_t *mounts = ctx->run.mounts;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Three prefixes, one per column, and no local needs a comment to say which
     * it is in: `target_` is the commit — what is read — `standing_` is the branch
     * tip, and `restored_` is the write, which is neither of them. A restore
     * lands on the claim standing at the location, so the standing side has no
     * name of its own here: wherever the tip holds anything, its name is the
     * write's, and where it holds nothing there is no name to have. */
    error_t *err = NULL;
    const char *profile = NULL;
    const char *target_name = NULL;
    const char *restored_name = NULL;
    git_oid target_commit_oid = { { 0 } };
    git_commit *target_commit = NULL;
    stage_t *stage = NULL;
    git_tree *target_tree = NULL;
    git_tree_entry *standing_entry = NULL;
    git_tree_entry *target_entry = NULL;
    metadata_t *standing_sheet = NULL;
    metadata_t *target_sheet = NULL;
    metadata_item_t *restored_claim = NULL;
    buffer_t rebound = BUFFER_INIT;
    char *msg = NULL;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Step 2: the argument in the key the user named — a location or a storage
     * path, neither manufactured from the other (infra/path.h) — and the profile
     * the revert acts on. */
    path_input_t arg;
    err = path_input_resolve(mounts, opts->file_path, ctx->arena, &arg);
    if (err) goto cleanup;

    err = select_profile(ctx, opts, &arg, &profile);
    if (err) goto cleanup;

    /* Step 3: Resolve target commit */
    output_print(
        out, OUTPUT_VERBOSE, "Resolving target commit '%s'...\n",
        opts->commit
    );

    err = gitops_resolve_commit_in_branch(
        repo, profile, opts->commit, &target_commit_oid, &target_commit
    );
    if (err) goto cleanup;

    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), &target_commit_oid);

    /* Step 4: The branch's stage — its tip is the current state the preview
     * compares against and the parent the revert's commit will have, so a branch
     * that moves between the preview and the commit is refused at the commit,
     * --force or not: what the user confirmed is what is reverted. It is also
     * the tree the profile's own name for the place is read from (steps 10 and
     * 12): the tree the revert edits is the tree the claim is looked for in, so
     * the name and the write cannot disagree. */
    char refname[DOTTA_REFNAME_MAX];
    err = gitops_branch_refname(refname, sizeof(refname), profile);
    if (err) goto cleanup;

    err = stage_open(repo, refname, &stage);
    if (err) {
        err = error_wrap(err, "Failed to open profile '%s'", profile);
        goto cleanup;
    }

    /* Step 5: the target commit's tree, opened once and lent to everything below
     * that reads the commit. */
    int ret = git_commit_tree(&target_tree, target_commit);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Step 6: the two sheets — the one the write merges into, read from the tree
     * the stage opened at, and the target commit's, whose claim at the name is
     * what the revert restores. Both are read here so that everything the revert
     * will do is known before it is shown: the reconstruction a claimless target
     * earns is announced by the preview, not by the write, and the commit's sheet
     * is one of the two places the read's name is looked for (step 8). Both are
     * read strictly, as every reader of a sheet is unless it argues otherwise
     * (core/metadata.h): a corrupt destination sheet would discard claims for
     * unrelated paths when the write saved its replacement, and a corrupt source
     * sheet would invent attributes while claiming to restore them. A commit
     * without a sheet loads as an empty one (the tree loader's contract), so a
     * revert to a state before any claim was written retires what stands. */
    err = metadata_load_from_tree(
        repo, stage_tree(stage), profile, &standing_sheet
    );
    if (err) {
        err = error_wrap(err, "Failed to load current metadata");
        goto cleanup;
    }

    err = metadata_load_from_tree(repo, target_tree, profile, &target_sheet);
    if (err) {
        err = error_wrap(err, "Failed to load metadata from target commit");
        goto cleanup;
    }

    /* Step 7: the place both trees may be asked about. A location argument is
     * one already; a typed name resolves to one through the profile's own binding.
     *
     * The location argument's own spelling is used rather than resolving a name
     * back through the table: the two agree everywhere but the stated edge
     * (infra/mount.h mount_resolve — a claim of the very link a binding is declared
     * through stands at the link, where locate reads the link through to the
     * target), and where they part it is the argument that is right.
     *
     * NULL is a custom/ name this machine cannot place. Then the name is the
     * only key there is: the commit is asked for it alone, nothing can be shown
     * to collide with it, and two such names are both manifest_unbound — the
     * namespace's own hole, and not a revert-shaped one. */
    const char *location = NULL;
    if (arg.key == PATH_KEY_LOCATION) {
        location = arg.location;
    } else {
        err = mount_resolve(
            mounts, profile, arg.storage_path, ctx->arena, &location
        );
        if (err) goto cleanup;
    }

    /* Step 8: the entry the commit holds, and the name it stands under — asked
     * in the key the user named, of the commit alone. It is the whole authority
     * on whether there is a revert to make: a claim with bytes at the commit
     * the user typed is one, and everything else is refused there by its own
     * noun. (A walk of the branch's history used to stand in for this question
     * and answered a weaker one — a name held at some *other* commit passed it
     * — while a commit object anywhere in the branch could refuse a revert that
     * needed none of it.) */
    err = entry_to_restore(
        ctx, target_tree, target_sheet, profile, &arg, location, oid_str,
        &target_name, &target_entry
    );
    if (err) goto cleanup;

    /* The blob the commit holds and the mode Git records for it. `restored_blob`
     * is a value and not the entry's own pointer, because a reseal under another
     * name (step 13) names an object no tree holds yet — and it is that object
     * the preview describes, the gate compares and the write stores. */
    const git_oid *target_blob = git_tree_entry_id(target_entry);
    git_filemode_t restored_mode = git_tree_entry_filemode(target_entry);
    git_oid restored_blob = *target_blob;

    /* Step 9: and the bytes behind it, read once. The kind is what the claim's
     * encrypted bit is stamped from (step 14) and what decides whether the bytes
     * can travel to another name (step 13), and the read itself is the proof
     * the repository holds the object — which every filemode needs and only the
     * regular-file arm used to make: a link whose blob was gone passed the dry
     * run and failed at the tree write, after the preview had promised the restore.
     * A link's bytes are its target path and no claim reads their kind (cmds/add.c
     * stages them raw) — classification is a fact about bytes, and whether it
     * applies is the filemode's question. */
    content_kind_t target_kind = CONTENT_PLAINTEXT;
    err = content_classify(repo, target_blob, &target_kind, NULL);
    if (err) {
        err = error_wrap(
            err, "Cannot read '%s' at commit %s", target_name, oid_str
        );
        goto cleanup;
    }

    /* Step 10: the name the revert writes. A typed name is the user's own choice
     * of contract and is written as typed (cmds/add.c's storage arm is the other
     * place that choice is made). A location is answered by the claim standing
     * there, whatever its name and whatever its kind — home/jail/etc/x under a
     * binding at ~/jail is found by ~/jail/etc/x, and a chain the profile names
     * nothing by is answered as the claim it is, so the tip's own tree refuses
     * a file where it holds a subtree (step 11). Where none stands, the commit's
     * own name is what comes back: a revert restores, and a name composed from
     * today's roots would choose a deployment contract the user did not. */
    if (arg.key == PATH_KEY_LOCATION) {
        const manifest_row_t *row = NULL;
        err = claim_standing(ctx, stage_tree(stage), profile, location, &row);
        if (err) goto cleanup;

        restored_name = row ? row->storage_path : target_name;
    } else {
        restored_name = arg.storage_path;
    }

    output_print(
        out, OUTPUT_VERBOSE, "Resolved to '%s' in profile '%s'\n", restored_name,
        profile
    );

    /* Step 11: what stands at that name in the tip. It may be absent — a path
     * the profile deleted is exactly what a revert brings back — and wherever
     * it stands it is a blob, because a revert restores one file's bytes. */
    ret = git_tree_entry_bypath(&standing_entry, stage_tree(stage), restored_name);
    if (ret < 0 && ret != GIT_ENOTFOUND) {
        err = error_from_git(ret);
        goto cleanup;
    }

    if (standing_entry) {
        git_object_t standing_type = git_tree_entry_type(standing_entry);
        if (standing_type != GIT_OBJECT_BLOB) {
            err = ERROR(
                ERR_INVALID_ARG, "'%s' is %s in profile '%s'; revert restores one file",
                restored_name,
                standing_type == GIT_OBJECT_TREE ? "a directory" : "a submodule",
                profile
            );
            goto cleanup;
        }
    }

    /* Step 12: the admission. A typed name the tip's tree does not hold is a
     * name this command would author, and a profile names a location once
     * (infra/mount.h, core/manifest.h): if the profile already names where this
     * name resolves and does not hold this name for it, authoring it would give
     * the profile a second name for one place — the pair the health channel calls
     * an unused path, and only `remove` can undo (refuse_second_name).
     *
     * The entry test is the authoring question and not a cost guard: a name the
     * tree already holds is not authored, and whether one it lacks is a second
     * name is the contribution's to answer. A location argument is answered *by*
     * the claim standing there and can never be a second name, so this arm is
     * the typed one's alone. */
    if (arg.key == PATH_KEY_STORAGE && !standing_entry && location) {
        err = refuse_second_name(
            ctx, stage_tree(stage), profile, location, restored_name, opts->commit
        );
        if (err) goto cleanup;
    }

    /* Step 13: the object the commit would store under the name the write uses.
     * Encrypted bytes are sealed under the storage path they were written at
     * (crypto/cipher.h "Path binding"), so bytes that carry a binding cannot
     * travel by id to another name — no read under the new name could open them.
     * Plaintext carries none, and a link's bytes are its target path rather than
     * content, so Git's filemode decides that one as it does at capture
     * (infra/content.h content_stage_file): both re-enter the tree as the id
     * the repository already holds.
     *
     * The bytes are hashed, not written: what the gate compares and what the
     * preview describes must be the object the commit would store, and a dry
     * run must leave the object database as it found it — the preview's own
     * in-memory patch is there for the same reason. The cost of that order is
     * that a cross-name restore of an encrypted file needs the key even where
     * the whole write turns out to already stand: there is no id to compare until
     * the reseal has made one. */
    if (restored_mode != GIT_FILEMODE_LINK &&
        target_kind != CONTENT_PLAINTEXT &&
        strcmp(target_name, restored_name) != 0) {
        err = content_rebind(
            repo, target_blob, target_name, restored_name, profile,
            ctx->run.keymgr, &rebound
        );
        if (err) {
            err = error_wrap(
                err, "Cannot restore '%s' as '%s'", target_name, restored_name
            );
            goto cleanup;
        }

        ret = git_odb_hash(
            &restored_blob, rebound.data, rebound.size, GIT_OBJECT_BLOB
        );
        if (ret < 0) {
            err = error_wrap(
                error_from_git(ret), "Cannot identify the resealed '%s'",
                restored_name
            );
            goto cleanup;
        }
    }

    /* Step 14: the claim. What the target records at the name it records it under,
     * as the claim builder reads one: a FILE item, or nothing. A DIRECTORY item
     * at a key the tree holds a blob at claims nothing about this file — the
     * tree is the content authority, and it has already answered (step 8). */
    const metadata_item_t *recorded = metadata_lookup(target_sheet, target_name);
    if (recorded && recorded->kind != PATH_KIND_FILE) {
        recorded = NULL;
    }

    /* A link's claim is the entry as recorded and its absence is an answer, so
     * a reconstruction is what a non-link without one earns. Named here, beside
     * the lookup that decides it, and said at the preview: the gate below may
     * yet answer "nothing to do", and a reconstruction that does not happen must
     * not be announced. */
    const bool reconstructed = !recorded && restored_mode != GIT_FILEMODE_LINK;

    err = claim_to_restore(
        recorded, restored_name, restored_mode, target_kind, &restored_claim
    );
    if (err) goto cleanup;

    /* Step 15: nothing to do — the whole write, entry and claim, already stands */
    const metadata_item_t *standing_claim = metadata_lookup(
        standing_sheet, restored_name
    );
    if (already_at_target(
        standing_entry, standing_claim, &restored_blob, restored_mode,
        restored_claim
        )) {
        output_info(
            out, OUTPUT_NORMAL, "File '%s' is already at target state (no changes)",
            restored_name
        );
        goto cleanup;  /* Not an error, just nothing to do */
    }

    /* Step 16: the entry the write puts, admitted now — the last thing about
     * this revert that can be refused, and refused before the preview promises
     * it. stage_put_blob is the producer of that refusal and it reads the private
     * index alone: the mode, the path's shape, a proper prefix that names an
     * entry, any entry beneath the path. A destination beneath a blob the tip
     * holds used to pass the dry run and fail after the prompt, with what the
     * dry run should have said.
     *
     * It writes no object — the id is one the commit already holds, or one the
     * reseal computed and step 20 will store — so a dry run or a declined prompt
     * frees the stage and leaves the object database as it found it. stage_tree()
     * is still the tree the stage opened at, so every read below is the tip's. */
    err = stage_put_blob(stage, restored_name, &restored_blob, restored_mode);
    if (err) goto cleanup;

    /* Step 17: Show preview (always, including dry-run) */
    output_section(out, OUTPUT_NORMAL, "Revert preview");

    const git_signature *author = git_commit_author(target_commit);
    time_t commit_time = (time_t) author->when.time;
    struct tm *tm_info = localtime(&commit_time);

    char time_buf[64];
    if (tm_info) {
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(time_buf, sizeof(time_buf), "<invalid time>");
    }

    /* A name is cyan and everything else is not — the profile's, the file's and,
     * where there are two, the commit's — which is how a name is marked wherever
     * one is printed beside other words (cmds/list.c's history header prints
     * two in one line). The commit line is an oid and a time and carries none. */
    output_styled(
        out, OUTPUT_NORMAL, "  Profile: {cyan}%s{reset}\n",
        profile
    );
    output_styled(
        out, OUTPUT_NORMAL, "  File: {cyan}%s{reset}\n",
        restored_name
    );
    output_print(
        out, OUTPUT_NORMAL, "  Target commit: %s (%s)\n",
        oid_str, time_buf
    );

    /* The other name, said once and only where there is one: the write lands on
     * the claim the branch holds now, and this is where the bytes come from. */
    if (strcmp(target_name, restored_name) != 0) {
        output_styled(
            out, OUTPUT_NORMAL, "  Named at the commit: {cyan}%s{reset}\n",
            target_name
        );
    }

    /* Mode and ownership have no byte source, so a commit that records no claim
     * for the path leaves the revert reconstructing one from the entry's own
     * filemode. It is said here, with the rest of what the write will do, and
     * only once the write is going to happen. */
    if (reconstructed) {
        output_newline(out, OUTPUT_NORMAL);
        /* What is missing is a *file* claim, which is not the same as a missing
         * sheet: a DIRECTORY item can stand at this very key and claim nothing
         * about this file, the tree being the content authority. Both reach here,
         * and the sentence names the one thing both mean. */
        output_warning(
            out, OUTPUT_NORMAL, "No file claim recorded for '%s' at commit %s",
            target_name, oid_str
        );
        output_hintline(
            out, OUTPUT_NORMAL,
            "Reconstructed from the commit (mode=%04o, encrypted=%s); "
            "ownership is not recoverable",
            (unsigned int) (restored_mode & 0777),
            target_kind != CONTENT_PLAINTEXT ? "true" : "false"
        );
    }

    /* The three ways the write differs from what stands: the file comes back,
     * everything but its bytes moves — the one thing no diff can show — or its
     * bytes do. The middle arm is *the blob is the same and the gate said something
     * differs*, and what is left to differ is the entry's filemode and the four
     * fields of the claim beside it, so the sentence names those rather than
     * two of them. */
    if (!standing_entry) {
        output_newline(out, OUTPUT_NORMAL);
        output_styled(
            out, OUTPUT_NORMAL, "{green}Restoring a deleted file{reset}\n"
        );
    } else if (git_oid_equal(git_tree_entry_id(standing_entry), &restored_blob)) {
        output_newline(out, OUTPUT_NORMAL);
        output_styled(
            out, OUTPUT_NORMAL,
            "{green}Contents unchanged; restoring the recorded mode, ownership "
            "and stamp{reset}\n"
        );
    } else {
        /* Detailed diff preview with decryption support. The content layer
         * classifies each blob by its own bytes, so the "current vs target may
         * differ in encryption state" case is handled inside show_diff_preview
         * without caller-side metadata gymnastics. */
        err = show_diff_preview(
            ctx, profile, restored_name, git_tree_entry_id(standing_entry),
            target_name, target_blob
        );
        if (err) {
            /* Non-fatal: the revert itself doesn't need decryption (copies blobs).
             * Show warning and continue to confirmation — user decides. */
            output_warning(
                out, OUTPUT_NORMAL, "Could not show diff preview: %s",
                error_message(err)
            );
            error_free(err);
            err = NULL;
        }
    }

    /* Step 18: Early exit for dry-run (preview shown, no changes to make) */
    if (opts->dry_run) {
        output_info(out, OUTPUT_NORMAL, "\nDry-run mode: No changes made");
        goto cleanup;
    }

    /* Step 19: Prompt for confirmation (unless --force or config disables) */
    if (!output_confirm_destructive(
        out, config ? config->confirm_destructive : true, "Revert file?", opts->force
        )) {
        output_info(out, OUTPUT_NORMAL, "Aborted.");
        goto cleanup;  /* err is NULL here: an abort is not a failure */
    }

    output_print(out, OUTPUT_VERBOSE, "\nReverting file...\n");

    /* Step 20: the write, on the stage opened at the preview's tip — the entry
     * put at step 16 and the merged sheet beside it, in one commit, all of it
     * decided above. A branch another writer moved since is refused by the commit
     * itself rather than by a second look at the tip.
     *
     * The resealed bytes only now: the entry was admitted at its id before the
     * preview, and this is the object that id names. Materialising it earlier
     * would leave a loose object behind every dry run. */
    if (rebound.data) {
        err = stage_put(
            stage, restored_name, rebound.data, rebound.size, restored_mode
        );
        if (err) goto cleanup;
    }

    /* The claim to restore upserts over the standing one; where the target records
     * none for a link, the standing item is the reverted-away state's — retire
     * it. */
    if (restored_claim) {
        err = metadata_add_item(standing_sheet, &restored_claim);
        if (err) {
            err = error_wrap(err, "Failed to update metadata");
            goto cleanup;
        }
    } else {
        metadata_remove_item(standing_sheet, restored_name);
    }

    err = metadata_save_to_stage(stage, standing_sheet);
    if (err) {
        err = error_wrap(err, "Failed to save metadata");
        goto cleanup;
    }

    msg = build_revert_commit_message(
        config, profile, restored_name, &target_commit_oid, opts->message
    );
    if (!msg) {
        err = ERROR(ERR_MEMORY, "Failed to allocate commit message");
        goto cleanup;
    }

    err = stage_commit(stage, msg, NULL);
    if (err) goto cleanup;

    /* Step 21: Report. Nothing to write: the revert moved the branch HEAD, and
     * the next load's view carries the reverted blob — the record stays where
     * apply last confirmed it, so the workspace reads the result as [stale] until
     * apply deploys it. A disabled profile's revert reaches no view at all. */
    output_success(
        out, OUTPUT_NORMAL, "Reverted %s in profile '%s'", restored_name, profile
    );

    /* The one line after it differs: a profile this machine has not enabled has
     * nothing to apply the revert to. */
    if (!state_has_profile(state, profile)) {
        output_info(
            out, OUTPUT_NORMAL, "\nNote: Profile '%s' is not enabled on this machine",
            profile
        );
        goto cleanup;
    }

    output_info(
        out, OUTPUT_NORMAL, "\nRun 'dotta apply' to deploy changes to filesystem"
    );

cleanup:
    if (msg) free(msg);
    buffer_free(&rebound);
    if (restored_claim) metadata_item_free(restored_claim);
    if (standing_sheet) metadata_free(standing_sheet);
    if (target_sheet) metadata_free(target_sheet);
    if (standing_entry) git_tree_entry_free(standing_entry);
    if (target_entry) git_tree_entry_free(target_entry);
    if (target_tree) git_tree_free(target_tree);
    stage_free(stage);
    if (target_commit) git_commit_free(target_commit);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Interpret the 1-3 raw positionals into `profile`, `file_path`, and `commit`.
 *
 * Forms (POSITIONAL_RAW min=0, max=3; commit is always required):
 *   0 args        → error "file specification is required"
 *   1 arg         → parse [profile:]<file>[@commit] via parse_refspec
 *   2 args        → <file> <commit>         when arg[1] is a git ref;
 *                   <profile> <file[@commit]> otherwise (refspec on 2nd)
 *   3 args        → <profile> <file> <commit>
 *
 * Allocation model: refspec substrings are arena-allocated; pure positional
 * pointers borrow argv. cmd_revert does not free any of these pointers — the
 * engine's arena owns their lifetime.
 *
 * A refspec that yields an explicit profile always overrides a previously-set
 * one (from -p or a positional).
 */
static error_t *revert_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) cmd;
    cmd_revert_options_t *o = opts_v;
    char **args = o->positional_args;

    if (o->positional_count == 0) {
        return ERROR(
            ERR_INVALID_ARG, "file specification is required"
        );
    }

    if (o->positional_count == 1) {
        /* [profile:]<file>[@commit] */
        refspec_t rs = { 0 };
        error_t *err = parse_refspec(arena, args[0], &rs);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse file specification");
        }
        if (rs.profile != NULL) o->profile = rs.profile;
        o->file_path = rs.file;
        if (rs.commit != NULL) o->commit = rs.commit;
    } else if (o->positional_count == 2) {
        if (str_looks_like_git_ref(args[1])) {
            /* <file> <commit> */
            o->file_path = args[0];
            o->commit = args[1];
        } else {
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
        }
    } else if (o->positional_count == 3) {
        o->profile = args[0];
        o->file_path = args[1];
        o->commit = args[2];
    } else {
        /* Max=3 is enforced by POSITIONAL_RAW; this branch is unreachable. */
        return ERROR(ERR_INTERNAL, "revert: too many positionals");
    }

    /* A commit is required by the command; file_path is guaranteed set by
     * successful refspec parsing or explicit positional assignment. */
    if (o->commit == NULL) {
        return ERROR(
            ERR_INVALID_ARG, "commit reference is required"
        );
    }
    return NULL;
}

/**
 * What can stand at the cursor, by the shapes revert_post_parse reads — as show,
 * without the bare-commit form: first a file of any branch as `profile:path`,
 * bare once -p pins one; after one positional the files of the profile it pins
 * or that profile's history, the grammar deciding by the next token; after two,
 * the commit. An `@` in the token being typed completes its commit part from
 * the refspec's history.
 */
static args_want_t revert_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_revert_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_revert_options_t, profile)) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    if (at->value_of != NULL) {
        return ARGS_WANT_NONE;   /* -m: free text */
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

static error_t *revert_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_revert(ctx, (const cmd_revert_options_t *) opts_v);
}

static const args_opt_t revert_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",         "<name>",
        cmd_revert_options_t,profile,
        "Disambiguate profile when file is ambiguous"
    ),
    ARGS_STRING(
        "m message",         "<msg>",
        cmd_revert_options_t,message,
        "Commit message"
    ),
    ARGS_FLAG(
        "f force",
        cmd_revert_options_t,force,
        "Skip confirmation prompt"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_revert_options_t,dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_revert_options_t,verbose,
        "Verbose output"
    ),
    ARGS_POSITIONAL_RAW(
        cmd_revert_options_t,positional_args, positional_count,
        0,                   3
    ),
    ARGS_END,
};

const args_command_t spec_revert = {
    .name        = "revert",
    .summary     = "Revert a file to a previous version",
    .usage       =
        "%s revert [options] <file@commit>\n"
        "   or: %s revert [options] <file> <commit>\n"
        "   or: %s revert [options] <profile>:<file@commit>\n"
        "   or: %s revert [options] <profile> <file> <commit>",
    .description =
        "Restore a file's content and metadata to its state at a past\n"
        "commit. Only the Git repository is modified; run '%s apply'\n"
        "afterward to propagate to the filesystem.\n",
    .notes       =
        "Execution Order:\n"
        "  1. Find the profile that holds the argument (--profile if ambiguous).\n"
        "  2. Resolve the commit in that profile's history.\n"
        "  3. Read what the commit holds and what stands at the branch tip. A\n"
        "     file the profile has renamed since is found either way, and comes\n"
        "     back under the name the profile uses now.\n"
        "  4. Refuse a storage path that would be the profile's second name\n"
        "     for one place, naming the first and both ways out. A profile\n"
        "     names a place once, and --force does not skip a refusal.\n"
        "  5. Answer 'nothing to do' when that whole state already stands.\n"
        "  6. Show the preview: the restored file, a diff, or a metadata-only\n"
        "     change. A dry run stops here, having refused whatever the real\n"
        "     run would have refused.\n"
        "  7. Prompt for confirmation (bypassed by --force).\n"
        "  8. Create one commit with the restored blob and the merged metadata.\n",
    .examples    =
        "  %s revert home/.bashrc HEAD~3              # Profile inferred\n"
        "  %s revert darwin home/.bashrc a4f2c8e      # Explicit profile\n"
        "  %s revert darwin:home/.bashrc@a4f2c8e      # Compact refspec\n"
        "  %s revert -m \"Fix config\" home/.bashrc HEAD~1   # Custom message\n"
        "  %s revert -n darwin home/.config/nvim/init.lua HEAD~2  # Preview\n",
    .epilogue    =
        "See also:\n"
        "  %s list <profile> <file>   # Find commit refs for a file\n"
        "  %s apply                   # Deploy the restored content\n",
    .opts_size   = sizeof(cmd_revert_options_t),
    .opts        = revert_opts,
    .post_parse  = revert_post_parse,
    .complete    = revert_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_READ,
        .mounts  = true,
        .crypto  = DOTTA_CRYPTO_OBTAIN,
    },
    .dispatch    = revert_dispatch,
};
