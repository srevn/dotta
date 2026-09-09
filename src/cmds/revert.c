/**
 * revert.c - Revert file to previous commit state
 */

#include "cmds/revert.h"

#include <config.h>
#include <git2.h>
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
#include "sys/stage.h"
#include "utils/commit.h"

/**
 * Which profile the revert acts on
 *
 * The profile question, and only that. What that profile calls the argument is
 * read afterwards, from the tree the revert edits (cmd_revert step 4) — a branch's
 * tip is its stage's tree, so the search below and the naming there read one
 * source and cannot disagree about a name.
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
     * The hints spell the command with what the user typed, so they paste back. */
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
            "  dotta revert --profile <name> %s %s\n\n"
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
    output_hint(out, OUTPUT_NORMAL, "Specify --profile to disambiguate:");
    output_hintline(
        out, OUTPUT_NORMAL, "  dotta revert --profile <name> %s %s",
        opts->file_path, opts->commit
    );

    return ERROR(ERR_INVALID_ARG, "Ambiguous path '%s'", subject);
}

/**
 * Show diff preview between two blobs
 *
 * Uses content layer to transparently decrypt encrypted files before diffing,
 * so users see readable plaintext diffs instead of encrypted gibberish. The content
 * layer classifies each blob by its own bytes, so blobs with different encryption
 * states across commits are routed correctly without any caller-supplied flag.
 *
 * The two blobs differ: the caller reaches this only from the preview arm that
 * says so, and the arm beside it is what a copy with the same bytes and a different
 * mode gets.
 */
static error_t *show_diff_preview(
    const dotta_ctx_t *ctx,
    const char *file_path,
    const char *profile,
    const git_oid *current_oid,
    const git_oid *target_oid
) {
    CHECK_NULL(ctx);
    CHECK_NULL(file_path);
    CHECK_NULL(profile);
    CHECK_NULL(current_oid);
    CHECK_NULL(target_oid);

    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr; /* NULL if encryption disabled */
    output_t *out = ctx->out;

    /* Get decrypted plaintext content from both blobs.
     *
     * Each call classifies its own blob's bytes — the routing decision lives
     * with the blob, so encryption-state changes between commits are handled by
     * the content layer with no caller participation. */
    buffer_t current_plaintext = BUFFER_INIT;
    error_t *err = content_get_from_blob_oid(
        repo,
        current_oid,
        file_path,
        profile,
        keymgr,
        &current_plaintext
    );
    if (err) {
        return error_wrap(err, "Failed to get current file content");
    }

    buffer_t target_plaintext = BUFFER_INIT;
    err = content_get_from_blob_oid(
        repo,
        target_oid,
        file_path,
        profile,
        keymgr,
        &target_plaintext
    );
    if (err) {
        buffer_free(&current_plaintext);
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
        current_plaintext.data, current_plaintext.size, file_path,
        target_plaintext.data, target_plaintext.size, file_path,
        NULL  /* options */
    );

    if (ret < 0) {
        buffer_free(&current_plaintext);
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
        file_path
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
    buffer_free(&current_plaintext);
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
 * The reconstruction is announced here — at the preview, before the prompt, where
 * the user can still decline it. It used to be announced during the write, so a
 * dry run never mentioned it at all.
 *
 * Every input is a fact the caller has already established, and none of them is
 * a Git object: the claim the commit records, the name to write it under, the
 * entry's filemode and the restored blob's kind. Nothing here reads the repository,
 * so nothing here can fail for a reason the preview could not have shown.
 *
 * @param out Output handle (must not be NULL)
 * @param recorded The FILE claim the target commit records at the name, or NULL
 *                 where it records none (borrowed)
 * @param file_path Storage path the claim is written under (must not be NULL)
 * @param target_mode The admitted entry's filemode
 * @param target_kind The restored blob's own bytes (cmd_revert step 5)
 * @param commit Abbreviated target commit oid, for the warning (must not be NULL)
 * @param out_claim The claim, or NULL where the target records none (must not
 *                  be NULL; caller frees with metadata_item_free)
 * @return Error or NULL on success
 */
static error_t *claim_to_restore(
    output_t *out,
    const metadata_item_t *recorded,
    const char *file_path,
    git_filemode_t target_mode,
    content_kind_t target_kind,
    const char *commit,
    metadata_item_t **out_claim
) {
    CHECK_NULL(out);
    CHECK_NULL(file_path);
    CHECK_NULL(commit);
    CHECK_NULL(out_claim);

    *out_claim = NULL;

    if (target_mode == GIT_FILEMODE_LINK) {
        /* A link's entry is a FILE item without a mode. Restore it as recorded
         * — revert restores history, it does not reinterpret it; whatever the
         * entry carries, the view adjudicates against the tree. No entry → the
         * write's retire arm takes the standing item. */
        if (!recorded) {
            return NULL;
        }
        return metadata_item_clone(recorded, out_claim);
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
        RETURN_IF_ERROR(metadata_item_clone(recorded, out_claim));
        (*out_claim)->encrypted = encrypted;
        return NULL;
    }

    /* No metadata entry at target commit - mode falls back to the tree's filemode;
     * ownership is not recoverable */
    output_warning(
        out, OUTPUT_NORMAL, "No metadata found for '%s' at commit %s",
        file_path, commit
    );
    output_hintline(
        out, OUTPUT_NORMAL,
        "Reconstructed from the commit (mode=%04o, encrypted=%s); "
        "ownership is not recoverable",
        (unsigned int) (target_mode & 0777),
        encrypted ? "true" : "false"
    );

    return metadata_item_create_file(
        file_path, target_mode & 0777, encrypted, out_claim
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
 * the profile deleted, which is never already at the target.
 *
 * @param standing The entry at the branch tip, or NULL for none
 * @param standing_claim The sheet's claim at the name there, or NULL for none
 * @param restored The entry at the target commit (must not be NULL)
 * @param restored_claim The claim the revert would write, or NULL where the target
 *                       records none
 * @return true when nothing about the write would change the branch
 */
static bool already_at_target(
    const git_tree_entry *standing,
    const metadata_item_t *standing_claim,
    const git_tree_entry *restored,
    const metadata_item_t *restored_claim
) {
    return standing &&
           git_oid_equal(git_tree_entry_id(standing), git_tree_entry_id(restored)) &&
           git_tree_entry_filemode(standing) == git_tree_entry_filemode(restored) &&
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

    error_t *err = NULL;
    const char *profile = NULL;
    const char *resolved_path = NULL;
    git_oid target_oid = { { 0 } };
    git_commit *target_commit = NULL;
    stage_t *stage = NULL;
    git_tree *target_tree = NULL;
    git_tree_entry *current_entry = NULL;
    git_tree_entry *target_entry = NULL;
    metadata_t *current_metadata = NULL;
    metadata_t *target_metadata = NULL;
    metadata_item_t *restore_metadata = NULL;
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
        repo, profile, opts->commit, &target_oid, &target_commit
    );
    if (err) goto cleanup;

    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), &target_oid);

    /* Step 4: The branch's stage — its tip is the current state the preview
     * compares against and the parent the revert's commit will have, so a branch
     * that moves between the preview and the commit is refused at the commit,
     * --force or not: what the user confirmed is what is reverted. It is also
     * where the profile's name for the argument is read: the tree the revert
     * edits is the tree the claim is looked for in, so the name and the write
     * cannot disagree. */
    char refname[DOTTA_REFNAME_MAX];
    err = gitops_branch_refname(refname, sizeof(refname), profile);
    if (err) goto cleanup;

    err = stage_open(repo, refname, &stage);
    if (err) {
        err = error_wrap(err, "Failed to open profile '%s'", profile);
        goto cleanup;
    }

    err = profile_claim_name(
        repo, stage_tree(stage), mounts, profile, &arg, ctx->arena, &resolved_path
    );
    if (err) goto cleanup;

    output_print(
        out, OUTPUT_VERBOSE, "Resolved to '%s' in profile '%s'\n", resolved_path,
        profile
    );

    /* Step 5: the two entries the revert reads, both admitted here — before
     * anything is shown and before the prompt.
     *
     * The commit's side is required, and it is the whole authority on whether
     * there is a revert to make: a name with bytes at the commit the user typed
     * is one, a name without is the argument's error. (A walk of the branch's
     * history used to stand in for this question and answered a weaker one — a
     * name held at some *other* commit passed it — while a commit object anywhere
     * in the branch could refuse a revert that needed none of it.)
     *
     * The tip's side may be absent: a path the profile deleted is exactly what
     * a revert brings back. Wherever either side stands it is a blob — a regular
     * file or a symlink — because a revert restores one file's bytes; a directory
     * and a submodule are refused here by their own noun, not at the stage after
     * the prompt where stage_put_blob refuses the mode and content_classify the
     * oid, and not after a dry run that promised the revert would happen.
     *
     * git_tree_entry_bypath answers three ways and is read as three: an
     * intermediate object that will not load is a failure to read, never an
     * absence. */
    int ret = git_commit_tree(&target_tree, target_commit);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    ret = git_tree_entry_bypath(&target_entry, target_tree, resolved_path);
    if (ret == GIT_ENOTFOUND) {
        err = ERROR(
            ERR_NOT_FOUND, "File '%s' not found at commit %s in profile '%s'",
            resolved_path, oid_str, profile
        );
        goto cleanup;
    }
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    git_object_t target_type = git_tree_entry_type(target_entry);
    if (target_type != GIT_OBJECT_BLOB) {
        err = ERROR(
            ERR_INVALID_ARG, "'%s' is %s at commit %s; revert restores one file",
            resolved_path,
            target_type == GIT_OBJECT_TREE ? "a directory" : "a submodule",
            oid_str
        );
        goto cleanup;
    }

    /* The blob the revert restores and the mode Git records for it: the admitted
     * entry's own identity, which the preview, the claim and the write all read. */
    const git_oid *restored_blob = git_tree_entry_id(target_entry);
    git_filemode_t restored_mode = git_tree_entry_filemode(target_entry);

    /* And the bytes behind it, read once. The kind is what the claim's encrypted
     * bit is stamped from (step 6), and the read itself is the proof the repository
     * holds the object — which every filemode needs and only the regular-file
     * arm used to make: a link whose blob was gone passed the dry run and failed
     * at the tree write, after the preview had promised the restore. A link's
     * bytes are its target path and no claim reads their kind (cmds/add.c stages
     * them raw) — classification is a fact about bytes, and whether it applies
     * is the filemode's question. */
    content_kind_t target_kind = CONTENT_PLAINTEXT;
    err = content_classify(repo, restored_blob, &target_kind, NULL);
    if (err) {
        err = error_wrap(
            err, "Cannot read '%s' at commit %s", resolved_path, oid_str
        );
        goto cleanup;
    }

    ret = git_tree_entry_bypath(&current_entry, stage_tree(stage), resolved_path);
    if (ret < 0 && ret != GIT_ENOTFOUND) {
        err = error_from_git(ret);
        goto cleanup;
    }

    if (current_entry) {
        git_object_t current_type = git_tree_entry_type(current_entry);
        if (current_type != GIT_OBJECT_BLOB) {
            err = ERROR(
                ERR_INVALID_ARG, "'%s' is %s in profile '%s'; revert restores one file",
                resolved_path,
                current_type == GIT_OBJECT_TREE ? "a directory" : "a submodule",
                profile
            );
            goto cleanup;
        }
    }

    /* Step 6: the two sheets — the one the write merges into, read from the tree
     * the stage opened at, and the target commit's, whose claim at the name is
     * what the revert restores. Both are read here so that everything the revert
     * will do is known before it is shown: the reconstruction a claimless target
     * earns is announced by the preview, not by the write. Both are read strictly,
     * as every reader of a sheet is unless it argues otherwise (core/metadata.h):
     * a corrupt destination sheet would discard claims for unrelated paths when
     * the write saved its replacement, and a corrupt source sheet would invent
     * attributes while claiming to restore them. A commit without a sheet loads
     * as an empty one (the tree loader's contract), so a revert to a state before
     * any claim was written retires what stands. */
    err = metadata_load_from_tree(
        repo, stage_tree(stage), profile, &current_metadata
    );
    if (err) {
        err = error_wrap(err, "Failed to load current metadata");
        goto cleanup;
    }

    err = metadata_load_from_tree(
        repo, target_tree, profile, &target_metadata
    );
    if (err) {
        err = error_wrap(err, "Failed to load metadata from target commit");
        goto cleanup;
    }

    /* What the target records at the name, as the claim builder reads one: a
     * FILE item, or nothing. A DIRECTORY item at a key the tree holds a blob at
     * claims nothing about this file — the tree is the content authority, and
     * it has already answered (step 5). */
    const metadata_item_t *recorded = metadata_lookup(
        target_metadata, resolved_path
    );
    if (recorded && recorded->kind != PATH_KIND_FILE) {
        recorded = NULL;
    }

    err = claim_to_restore(
        out, recorded, resolved_path, restored_mode, target_kind, oid_str,
        &restore_metadata
    );
    if (err) goto cleanup;

    /* Step 7: nothing to do — the whole write, entry and claim, already stands */
    const metadata_item_t *standing_claim = metadata_lookup(
        current_metadata, resolved_path
    );
    if (already_at_target(
        current_entry, standing_claim, target_entry, restore_metadata
        )) {
        output_info(
            out, OUTPUT_NORMAL, "File '%s' is already at target state (no changes)",
            resolved_path
        );
        goto cleanup;  /* Not an error, just nothing to do */
    }

    /* Step 8: the entry the write puts, admitted now — the last thing about this
     * revert that can be refused, and refused before the preview promises it.
     * stage_put_blob is the producer of that refusal and it reads the private
     * index alone: the mode, the path's shape, a proper prefix that names an
     * entry, any entry beneath the path. A destination beneath a blob the tip
     * holds used to pass the dry run and fail after the prompt, with what the
     * dry run should have said.
     *
     * It writes no object — the blob is one the commit already holds — so a dry
     * run or a declined prompt frees the stage and leaves the object database
     * as it found it. stage_tree() is still the tree the stage opened at, so
     * every read below is the tip's. */
    err = stage_put_blob(stage, resolved_path, restored_blob, restored_mode);
    if (err) goto cleanup;

    /* Step 9: Show preview (always, including dry-run) */
    output_section(out, OUTPUT_NORMAL, "Revert preview:");

    const git_signature *author = git_commit_author(target_commit);
    time_t commit_time = (time_t) author->when.time;
    struct tm *tm_info = localtime(&commit_time);

    char time_buf[64];
    if (tm_info) {
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(time_buf, sizeof(time_buf), "<invalid time>");
    }

    output_styled(
        out, OUTPUT_NORMAL, "  Profile: {cyan}%s{reset}\n",
        profile
    );
    output_print(
        out, OUTPUT_NORMAL, "  File: %s\n",
        resolved_path
    );
    output_print(
        out, OUTPUT_NORMAL, "  Target commit: %s (%s)\n",
        oid_str, time_buf
    );

    /* The three ways the write differs from what stands: the file comes back,
     * only its mode and ownership move — the one thing no diff can show — or
     * its bytes do. */
    if (!current_entry) {
        output_newline(out, OUTPUT_NORMAL);
        output_styled(
            out, OUTPUT_NORMAL, "{green}Restoring a deleted file{reset}\n"
        );
    } else if (git_oid_equal(git_tree_entry_id(current_entry), restored_blob)) {
        output_newline(out, OUTPUT_NORMAL);
        output_styled(
            out, OUTPUT_NORMAL,
            "{green}Contents unchanged; restoring the recorded mode and "
            "ownership{reset}\n"
        );
    } else {
        /* Detailed diff preview with decryption support. The content layer
         * classifies each blob by its own bytes, so the "current vs target may
         * differ in encryption state" case is handled inside show_diff_preview
         * without caller-side metadata gymnastics. */
        err = show_diff_preview(
            ctx, resolved_path, profile, git_tree_entry_id(current_entry),
            restored_blob
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

    /* Step 10: Early exit for dry-run (preview shown, no changes to make) */
    if (opts->dry_run) {
        output_info(out, OUTPUT_NORMAL, "\nDry-run mode: No changes made");
        goto cleanup;
    }

    /* Step 11: Prompt for confirmation (unless --force or config disables) */
    if (!output_confirm_destructive(
        out, config ? config->confirm_destructive : true, "Revert file?", opts->force
        )) {
        output_info(out, OUTPUT_NORMAL, "Aborted.");
        goto cleanup;  /* err is NULL here: an abort is not a failure */
    }

    output_print(out, OUTPUT_VERBOSE, "\nReverting file...\n");

    /* Step 12: the write, on the stage opened at the preview's tip — the entry
     * put at step 8 and the merged sheet beside it, in one commit, all of it
     * decided above. A branch another writer moved since is refused by the commit
     * itself rather than by a second look at the tip.
     *
     * The claim to restore upserts over the standing one; where the target records
     * none for a link, the standing item is the reverted-away state's — retire
     * it. */
    if (restore_metadata) {
        err = metadata_add_item(current_metadata, &restore_metadata);
        if (err) {
            err = error_wrap(err, "Failed to update metadata");
            goto cleanup;
        }
    } else {
        metadata_remove_item(current_metadata, resolved_path);
    }

    err = metadata_save_to_stage(stage, current_metadata);
    if (err) {
        err = error_wrap(err, "Failed to save metadata");
        goto cleanup;
    }

    msg = build_revert_commit_message(
        config, profile, resolved_path, &target_oid, opts->message
    );
    if (!msg) {
        err = ERROR(ERR_MEMORY, "Failed to allocate commit message");
        goto cleanup;
    }

    err = stage_commit(stage, msg, NULL);
    if (err) goto cleanup;

    /* Step 13: Report. Nothing to write: the revert moved the branch HEAD, and
     * the next load's view carries the reverted blob — the record stays where
     * apply last confirmed it, so the workspace reads the result as [stale] until
     * apply deploys it. A disabled profile's revert reaches no view at all. */
    if (!state_has_profile(state, profile)) {
        output_success(
            out, OUTPUT_NORMAL, "Reverted %s in profile '%s'",
            resolved_path, profile
        );
        output_info(
            out, OUTPUT_NORMAL, "\nNote: Profile '%s' is not enabled on this machine",
            profile
        );
        goto cleanup;
    }

    output_success(
        out, OUTPUT_NORMAL, "Reverted %s in profile '%s'", resolved_path, profile
    );

    /* Guide user to deploy changes */
    output_info(
        out, OUTPUT_NORMAL, "\nRun 'dotta apply' to deploy changes to filesystem"
    );

cleanup:
    if (msg) free(msg);
    if (restore_metadata) metadata_item_free(restore_metadata);
    if (current_metadata) metadata_free(current_metadata);
    if (target_metadata) metadata_free(target_metadata);
    if (current_entry) git_tree_entry_free(current_entry);
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
        "  3. Read what the commit holds and what stands at the branch tip.\n"
        "  4. Answer 'nothing to do' when that whole state already stands.\n"
        "  5. Show the preview: the restored file, a diff, or a metadata-only\n"
        "     change. A dry run stops here, having refused whatever the real\n"
        "     run would have refused.\n"
        "  6. Prompt for confirmation (bypassed by --force).\n"
        "  7. Create one commit with the restored blob and the merged metadata.\n",
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
