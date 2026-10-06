/**
 * revert.c - Revert file to previous commit state
 */

#include "cmds/revert.h"

#include <config.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/output.h"
#include "base/refspec.h"
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
#include "sys/revision.h"
#include "utils/commit.h"

/**
 * The claim `profile` stands at `filesystem_path`, or NULL when it stands none
 *
 * One contribution of the profile, asked for the row at the path (core/manifest.h
 * manifest_build_profile, manifest_lookup_claim). The row is the arena's, as
 * the view is, so the answer survives this call.
 *
 * The row and not its name, because this file asks it three ways: the search
 * takes any claim, for whether a profile holds the path at all; the read takes
 * any claim; and the write's name takes the claim standing there whatever it is
 * called. A verb answering a string would have to pick one of them for all three,
 * which is also why revert no longer asks core/manifest.h manifest_claim_name:
 * over a past tree a name today's roots would compose is one that tree never
 * held, and for a verb that writes, composing a name would choose a deployment
 * contract. A fourth question — may this name be authored at all — is the
 * admission's, and it reads more of one view than a row
 * (revert_refuse_second_name).
 *
 * Strict, like every view: a profile whose sheet will not load refuses the question
 * rather than answering from the tree alone. cmd_revert reads both sheets strictly
 * before it asks — the head's at its stage's open, the commit's at its step 6 —
 * and the search is complete or an error (revert_select_profile), so no policy
 * is added here.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param profile The profile the claim is looked for in — at the head's tree or
 *                the target commit's (must not be NULL)
 * @param filesystem_path Where to ask (must not be NULL)
 * @param out_row The claim, or NULL where none stands and after an error (must
 *                not be NULL; the command arena's, borrowed)
 * @return Error or NULL on success
 */
static error_t revert_claim_standing(
    const dotta_ctx_t *ctx,
    profile_t *profile,
    const char *filesystem_path,
    const manifest_row_t **out_row
) {
    CHECK_NULL(ctx);
    CHECK_NULL(profile);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(out_row);

    *out_row = NULL;

    manifest_t *view = NULL;
    error_t err = manifest_build_profile(profile, ctx->run.mounts, ctx->arena, &view);
    if (err) return err;

    /* The profile's own contribution: the row is the arena's */
    *out_row = manifest_lookup_claim(view, profile_name(profile), filesystem_path);

    return NULL;
}

/**
 * Which profile the revert acts on
 *
 * The profile question, and only that. What that profile calls the argument is
 * read afterwards, and twice: from the commit's tree for the bytes to restore
 * and from the tree the revert edits for the name to write them under (cmd_revert
 * steps 8 and 10). A branch's head is its stage's tree, so the search below and
 * the naming there read one source and cannot disagree about a name.
 *
 * With `opts->profile`: the user's word, required to be here. Whether the profile
 * holds the argument at its head is not asked — a revert restores what the *commit*
 * holds, and a path the profile deleted is the case a revert exists for.
 *
 * Without: the search. Every local profile, enabled or not, is asked what it
 * holds at the argument, in the key the argument named, and the one that holds
 * it is the answer. None is refused as an absence, whose way through is -p;
 * several, as ambiguous, each listed beside its own name for the argument. Complete
 * or an error: a profile the search cannot read stops it whichever profile it
 * is, since a list short by one is a falsely unique answer, and the refusal's
 * clause names the flag that reads one profile instead of all of them.
 */
static error_t revert_select_profile(
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

    *out_profile = NULL;

    if (opts->profile) {
        error_t err = profile_require(repo, opts->profile);
        if (err) return err;
        *out_profile = opts->profile;
        return NULL;
    }

    /* The argument in the key it named — one of two — which every refusal below
     * names it by. */
    const char *subject = arg->key == PATH_KEY_FILESYSTEM ? arg->filesystem_path
                                                          : arg->storage_path;

    /* Every local branch, listed into the command's arena: the one holder is
     * answered as the listing's own string, which outlives this call there. One
     * enumeration, not a snapshot: a ref born between it and the loads is not
     * consulted. */
    string_array_t profiles;
    error_t err = gitops_list_branches(repo, ctx->arena, &profiles);

    /* Each profile loaded once and asked in the key the argument named. The
     * question is every local profile's, not the enabled set's, whose holder
     * the view answers (core/manifest.h manifest_holder: show, list). A profile
     * names a path once and holds a name once, so each answers once at most:
     * the first holder is kept as itself — the answer, where it is the only one
     * — and every holder is spelled as found, beside its own name for the argument,
     * which is all the refusal for several reads. */
    const char *holder = NULL;
    string_array_t holders;
    string_array_init(&holders, ctx->arena);
    for (size_t i = 0; !err && i < profiles.count; i++) {
        profile_t *profile = NULL;
        err = profile_load(repo, profiles.entries[i], &profile);
        if (err) break;

        const char *storage_path = NULL;
        if (arg->key == PATH_KEY_FILESYSTEM) {
            /* A path: the claim standing there in the profile's view, a derived
             * one included, under the name the profile holds it by — a binding's,
             * or one kept from before the binding, never one this machine composes.
             * The view is placed by this machine's table, which is the enabled
             * set's (core/manifest.h manifest_mount_table): a profile nothing
             * has enabled is bound nowhere, so no path reaches its custom/ claims,
             * and their names find them as always. */
            const manifest_row_t *row = NULL;
            err = revert_claim_standing(ctx, profile, arg->filesystem_path, &row);
            if (row) storage_path = row->storage_path;
        } else {
            /* A name, as typed: held by either of the profile's two documents
             * (core/profiles.h profile_holds) — the tree first, a subtree counting
             * as a name has always counted, so a name the tree holds is answered
             * without the sheet; the sheet where the tree is silent, for a
             * directory claim with nothing beneath it. */
            profile_held_t held;
            err = profile_holds(profile, arg->storage_path, &held);
            if (!err && held.kind != PROFILE_HELD_NOTHING) storage_path = arg->storage_path;
        }
        profile_free(profile);

        if (storage_path) {
            if (!holder) holder = profiles.entries[i];
            string_array_pushf(&holders, "%s (%s)", profiles.entries[i], storage_path);
        }
    }
    if (err) {
        /* The search crosses every local profile, so one this command has nothing
         * to do with can stop it — a sheet no loader will parse, an object the
         * store lost, a branch a delete took mid-search, which its load refuses
         * as not found and never reads as holding nothing. Whatever the cause,
         * the way through is the same one: name the profile and one is read instead
         * of all of them. Said once, over whichever profile failed, each failure
         * naming its own. */
        return error_wrap(
            err, "Cannot search every profile for '%s'; -p reads one instead", subject
        );
    }

    if (holders.count == 0) {
        /* Held at no head, every profile having answered: a file deleted from
         * its profile is the case a revert exists for, and naming the profile
         * is what reaches it — a profile named is not asked what its head holds
         * (the -p arm above). */
        return error_create(
            ERR_NOT_FOUND, "'%s' is not held by any profile; -p restores it into a "
            "profile that deleted it", subject
        );
    }

    /* One holder: the profile the revert acts on */
    if (holders.count == 1) {
        *out_profile = holder;
        return NULL;
    }

    /* Several: the way through is the clause, because no key tells them apart
     * here — a path asks every profile again, and each answers as before. */
    return error_create(
        ERR_INVALID_ARG,
        "'%s' is held by %zu profiles: %s; -p names one", subject,
        holders.count, string_array_join(ctx->arena, &holders, ", ")
    );
}

/**
 * Refuse a typed name that would give the profile a second name for one path
 *
 * The head's own contribution, asked two questions: the claim standing where
 * the name resolves, and whether the profile holds the typed name at all
 * (core/manifest.h manifest_holds_name). Both readings are the contribution's,
 * so they are asked of one build rather than of a row alone — the second reads
 * the names the settle recorded against the standing one, which no row carries.
 *
 * A name the profile already holds is a re-capture and authors nothing, whether
 * it is the name standing at the path or one the settle did not keep. Only a
 * name new to the profile at a path it already names is a second name, and that
 * is what this refuses — naming the first, and not skippable by --force: a refusal
 * is not a confirmation.
 *
 * A derived claim names nothing (manifest_is_derived), so it is not a first name
 * and does not block one — explicit outranks derived within a profile as across
 * them.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param profile The profile at its head, whose claims the name would join (must
 *                not be NULL)
 * @param filesystem_path Where the typed name resolves (must not be NULL)
 * @param name The typed name (must not be NULL)
 * @return The refusal, or NULL when the name may be authored
 */
static error_t revert_refuse_second_name(
    const dotta_ctx_t *ctx,
    profile_t *profile,
    const char *filesystem_path,
    const char *name
) {
    CHECK_NULL(ctx);
    CHECK_NULL(profile);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(name);

    manifest_t *view = NULL;
    error_t err = manifest_build_profile(profile, ctx->run.mounts, ctx->arena, &view);
    if (err) return err;

    const manifest_row_t *row = manifest_lookup_claim(view, profile_name(profile), filesystem_path);
    if (row && !manifest_is_derived(row) &&
        !manifest_holds_name(view, profile_name(profile), filesystem_path, name)) {
        /* The path is the shared term of three paths in one sentence, and the
         * one path here the user never typed — so it is spelled the way the shell
         * spells it, as the screen that reports the pair this refuses already
         * spells it (cmds/status.c's unused-path listing, base/output.h
         * output_format_path). */
        char shown[PATH_MAX];
        output_format_path(filesystem_path, identity()->home, shown, sizeof(shown));

        /* No clause: the way through is in the fact. The name the profile has
         * reverts the file as its path does — a name the commit did not hold
         * falls through to the path (revert_target_claim) — and giving that name
         * up is remove's, the verb the fact implies. */
        return error_create(
            ERR_INVALID_ARG, "Profile '%s' names '%s' as '%s', and '%s' would be a "
            "second name for it", profile_name(profile), shown, row->storage_path, name
        );
    }

    return NULL;
}

/**
 * The file claim the target commit holds for this argument, decoded
 *
 * Its name is the commit's, its blob and type the commit's entry, and its
 * attributes the commit's FILE item over it, read as the walk reads one
 * (core/profiles.h profile_find): the claim a restore writes, renamed and restamped
 * by its caller. Asked in the key the user named (cmds/revert.h, the two names),
 * and it never sees the head: the read's name is the commit's alone.
 *
 *   a FILESYSTEM — the claim standing at the path, whatever it is called; the
 *                  commit's two documents then say whether that claim is one file.
 *   a STORAGE    — the name as typed, because a name is Git's key and does not
 *                  move. Only a name the commit holds neither in its tree nor
 *                  in its sheet is a contract change to find, and then the path
 *                  is the key.
 *
 * A name is answered by both documents at once (core/profiles.h profile_holds),
 * and that is what keeps the fallback honest: a DIRECTORY claim standing at the
 * typed name with no tree entry — a tracked directory with nothing inside it,
 * an ancestor chain the tree no longer has — answers as the directory it is,
 * where reading the tree's silence as permission to search the path would answer
 * with a *different* claim's blob under the name the user typed.
 *
 * Refuses rather than answering nothing, so the caller holds a claim or an error
 * and no third state: a directory or a submodule by its own noun — under the
 * fallback's name where the fallback found it, that name not being the one the
 * user typed, and the difference being the information — and an absence worded
 * from the key the user named, a path the commit held nothing at included, whether
 * or not a root of the profile stands there: a root is a directory the profile
 * may hold a claim at like any other, so what the commit held is the whole question
 * and where the place stands is none of it.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param target_profile The profile at the target commit's tree, which reads
 *                       the commit's sheet strictly where its tree is silent
 *                       (must not be NULL)
 * @param arg The argument, in the key it named (must not be NULL)
 * @param filesystem_path Where both trees may be asked about, or NULL for a custom/
 *        name this machine cannot place
 * @param commit Abbreviated target commit oid, for the refusals (must not be NULL)
 * @param out The claim, lent by the target's profile for its life (must not be
 *            NULL; NULL after an error)
 * @return Error or NULL on success
 */
static error_t revert_target_claim(
    const dotta_ctx_t *ctx,
    profile_t *target_profile,
    const path_input_t *arg,
    const char *filesystem_path,
    const char *commit,
    const profile_claim_t **out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(target_profile);
    CHECK_NULL(arg);
    CHECK_NULL(commit);
    CHECK_NULL(out);

    *out = NULL;

    /* A typed name is asked first, as typed; a path has no name until the claim
     * standing there gives it one. The commit's two documents answer a name through
     * the profile at its tree (core/profiles.h profile_holds), which reads the
     * commit's sheet where the tree is silent. */
    const char *name = arg->key == PATH_KEY_STORAGE ? arg->storage_path : NULL;
    profile_held_t held = { .kind = PROFILE_HELD_NOTHING };

    error_t err = name ? profile_holds(target_profile, name, &held) : NULL;
    if (err) return err;

    /* Only a name the commit holds in neither document falls back to the claim
     * standing at the path, and a path argument starts here. The claim is asked
     * by its own name, which the commit holds in one document or the other by
     * construction: the row came from them. */
    if (held.kind == PROFILE_HELD_NOTHING && filesystem_path) {
        const manifest_row_t *row = NULL;
        err = revert_claim_standing(ctx, target_profile, filesystem_path, &row);
        if (err) return err;

        if (row) {
            name = row->storage_path;
            err = profile_holds(target_profile, name, &held);
            if (err) return err;
        }
    }

    switch (held.kind) {
        case PROFILE_HELD_FILE:
            /* The file claim the commit makes there, decoded as its walk shows
             * it: a blob stands at the name, so the claim is there to find */
            return profile_find(target_profile, PROFILE_READ_STRICT, PATH_KIND_FILE, name, out);

        case PROFILE_HELD_DIRECTORY:
        case PROFILE_HELD_SUBMODULE:
            return error_create(
                ERR_INVALID_ARG, "'%s' is %s at commit %s; revert restores one file",
                name,
                held.kind == PROFILE_HELD_DIRECTORY ? "a directory" : "a submodule",
                commit
            );

        case PROFILE_HELD_NOTHING:
            break;
    }

    /* Nothing, in the key the user named. A row found above is held in one document
     * or the other and cannot reach here; if it ever did, this block is honest
     * for it too. */
    if (arg->key == PATH_KEY_FILESYSTEM) {
        return error_create(
            ERR_NOT_FOUND, "Profile '%s' held nothing at '%s' at commit %s",
            profile_name(target_profile), arg->filesystem_path, commit
        );
    }

    return error_create(
        ERR_NOT_FOUND, "File '%s' not found at commit %s in profile '%s'",
        arg->storage_path, commit, profile_name(target_profile)
    );
}

/**
 * Print the diff preview between two blobs
 *
 * Uses content layer to transparently decrypt encrypted files before diffing,
 * so users see readable plaintext diffs instead of encrypted gibberish. The content
 * layer classifies each blob by its own bytes, so blobs with different encryption
 * states across commits are routed correctly without any caller-supplied flag —
 * as the entry each stands in, which is why both filemodes come in: a link's
 * bytes are its target, never a seal (infra/content.h).
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
 * That arm is also why the caller hands the restored claim's name in here: the
 * head's entry is looked up at the name the revert writes, so wherever there is
 * an entry to diff against, the write's name is the head's binding and the two
 * words name one string.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param profile Profile name, for key derivation (must not be NULL)
 * @param standing_name The head's binding, and the label on both sides (must
 *                     not be NULL)
 * @param standing_oid The blob standing at the head (must not be NULL)
 * @param standing_mode Its filemode at the head
 * @param target_name The commit's binding: how its bytes open (must not be NULL)
 * @param target_oid The committed object (must not be NULL)
 * @param target_mode Its filemode at the commit
 * @return Error or NULL on success
 */
static error_t revert_print_diff(
    const dotta_ctx_t *ctx,
    const char *profile,
    const char *standing_name,
    const git_oid *standing_oid,
    git_filemode_t standing_mode,
    const char *target_name,
    const git_oid *target_oid,
    git_filemode_t target_mode
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
     * Each call classifies its own blob's bytes, as the entry it stands in —
     * the routing decision lives with the blob, so encryption-state changes between
     * commits are handled by the content layer with no caller participation. */
    buffer_t standing_plaintext = BUFFER_INIT;
    error_t err = content_get_from_blob_oid(
        repo,
        standing_oid,
        standing_mode,
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
        target_mode,
        target_name,
        profile,
        keymgr,
        &target_plaintext
    );
    if (err) {
        buffer_deinit(&standing_plaintext);
        return error_wrap(err, "Failed to get target file content");
    }

    /* Create patch directly from plaintext buffers using in-memory API
     *
     * This uses libgit2's buffer-based patch API to avoid creating temporary
     * blobs in the Git ODB that would persist until gc.
     */
    git_patch *patch = NULL;
    int rc = git_patch_from_buffers(
        &patch,
        standing_plaintext.data, standing_plaintext.size, standing_name,
        target_plaintext.data, target_plaintext.size, standing_name,
        NULL  /* options */
    );

    if (rc < 0) {
        buffer_deinit(&standing_plaintext);
        buffer_deinit(&target_plaintext);
        return error_git(rc, "Cannot compare the two versions of '%s'", standing_name);
    }

    /* Get patch stats */
    size_t additions = 0;
    size_t deletions = 0;
    git_patch_line_stats(NULL, &additions, &deletions, patch);

    /* Show header */
    output_section(out, OUTPUT_NORMAL, "Changes preview");

    /* Show stats */
    output_print(
        out, OUTPUT_NORMAL, "  File: {cyan}%s{reset}\n",
        standing_name
    );
    output_print(
        out, OUTPUT_NORMAL, "  Changes: {green}+%zu{reset} / {red}-%zu{reset}\n",
        additions, deletions
    );
    output_gap(out, OUTPUT_NORMAL);

    /* Print patch */
    git_buf buf = { 0 };
    rc = git_patch_to_buf(&buf, patch);
    if (rc < 0) {
        output_warning(out, OUTPUT_NORMAL, "Could not format diff output");
    } else if (buf.ptr) {
        output_print_diff(out, OUTPUT_NORMAL, buf.ptr);
    }

    git_buf_dispose(&buf);
    git_patch_free(patch);

    /* Free plaintext buffers */
    buffer_deinit(&standing_plaintext);
    buffer_deinit(&target_plaintext);

    return NULL;
}

/**
 * The revert's commit message
 *
 * Uses custom message if provided, otherwise generates from template system.
 * This centralizes message generation logic for reuse across revert operations.
 *
 * @param arena Arena the message lives in (must not be NULL)
 * @param config Configuration (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param file_path File path (must not be NULL)
 * @param target_commit_oid Target commit OID (must not be NULL)
 * @param custom_message Custom message (can be NULL for template generation)
 * @return The message, the arena's
 */
static const char *revert_commit_message(
    arena_t *arena,
    const config_t *config,
    const char *profile,
    const char *file_path,
    const git_oid *target_commit_oid,
    const char *custom_message
) {
    if (custom_message && custom_message[0]) {
        return arena_strdup(arena, custom_message);
    }

    /* Generate message using template system */
    char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), target_commit_oid);

    /* Build context for commit message. One path, the name the restore wrote,
     * borrowed for the call as every caller's list is (utils/commit.h). */
    const char *paths[] = { file_path };
    commit_message_context_t msg_ctx = {
        .action        = COMMIT_ACTION_REVERT,
        .profile       = profile,
        .paths         = paths,
        .path_count    = 1,
        .custom_msg    = NULL,
        .target_commit = oid_str
    };

    return commit_message(arena, config, &msg_ctx);
}

/**
 * Revert command implementation
 */
error_t cmd_revert(const dotta_ctx_t *ctx, const cmd_revert_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->file_path);
    CHECK_NULL(opts->commit);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    const mount_table_t *mounts = ctx->run.mounts;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Three columns, each one value, and no local needs a comment to say which
     * it is in: `target` is the claim the commit holds — what is read — `standing`
     * what the head's tree holds where the write lands, and `restored` the claim
     * the write restores, which is neither of them. The handles keep the column
     * as a prefix — the commit, its tree and the profile at it; the head's profile,
     * the stage's base. A restore lands on the claim standing at the path, so
     * the standing side has no name of its own here: wherever the head holds
     * anything, its name is the write's, and where it holds nothing there is no
     * name to have. */
    error_t err = NULL;
    const char *profile = NULL;
    git_commit *target_commit = NULL;
    profile_stage_t *stage = NULL;
    git_tree *target_tree = NULL;
    profile_t *target_profile = NULL;
    buffer_t rebound = BUFFER_INIT;

    /* Step 2: the argument in the key the user named — a path or a storage path,
     * neither manufactured from the other (infra/path.h) — and the profile the
     * revert acts on. */
    path_input_t arg;
    err = path_input_resolve(opts->file_path, ctx->arena, &arg);
    if (err) goto cleanup;

    err = revert_select_profile(ctx, opts, &arg, &profile);
    if (err) goto cleanup;

    /* Step 3: Resolve target commit */
    output_print(
        out, OUTPUT_VERBOSE, "Resolving target commit '%s'...\n",
        opts->commit
    );

    err = revision_load(repo, profile, opts->commit, &target_commit);
    if (err) goto cleanup;

    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), git_commit_id(target_commit));

    /* Step 4: the profile's next commit, opened at its head (core/profiles.h
     * profile_stage_t). The head is the current state the preview compares against
     * and the parent the revert's commit will have, so a branch that moves between
     * the preview and the commit is refused at the commit, --force or not: what
     * the user confirmed is what is reverted. Its base is the profile as the
     * head holds it, the tree the profile's own name for the place is read from
     * (steps 10 to 12) and the one the restore edits, so the name and the write
     * cannot disagree. Its sheet is read now, strictly: a corrupt destination
     * sheet would discard claims for unrelated paths when the write saved its
     * replacement, so one that will not load is refused before the preview, in
     * the loader's words, as every writer refuses it. */
    err = profile_stage_open(repo, profile, &stage);
    if (err) goto cleanup;
    profile_t *standing_profile = profile_stage_base(stage);

    /* Step 5: the target commit's tree, opened once and lent to everything below
     * that reads the commit, and the profile at it. */
    int rc = git_commit_tree(&target_tree, target_commit);
    if (rc < 0) {
        err = error_git(rc, "Cannot read the tree of commit '%s'", opts->commit);
        goto cleanup;
    }
    target_profile = profile_open(profile, target_tree);

    /* Step 6: the commit's sheet, read once and said as the commit's. Every later
     * read of the commit — the claim at a path, the claim at a name, the way
     * the restore brings back — reads it through the profile at the commit's
     * tree, so a sheet that will not load is refused here, naming the commit,
     * whichever read the argument would have made first. Read strictly, as every
     * reader of a sheet is unless it argues otherwise (core/metadata.h): a corrupt
     * source sheet would invent attributes while claiming to restore them. A
     * commit without a sheet loads as an empty one (the tree loader's contract),
     * so a revert to a state before any claim was written retires what stands. */
    err = profile_load_sheet(target_profile);
    if (err) {
        err = error_wrap(err, "Failed to load metadata from target commit %s", oid_str);
        goto cleanup;
    }

    /* Step 7: the place both trees may be asked about. A path argument is one
     * already; a typed name resolves to one through the profile's own binding.
     *
     * NULL is a custom/ name this machine cannot place. Then the name is the
     * only key there is: the commit is asked for it alone, nothing can be shown
     * to collide with it, and two such names are both manifest_unbound — the
     * namespace's own hole, and not a revert-shaped one. */
    const char *filesystem_path = arg.key == PATH_KEY_FILESYSTEM
        ? arg.filesystem_path
        : mount_resolve(ctx->arena, mounts, profile, arg.storage_path);

    /* Step 8: the claim the commit holds, decoded — asked in the key the user
     * named, of the commit alone. It is the whole authority on whether there is
     * a revert to make: a claim with bytes at the commit the user typed is one,
     * and everything else is refused there by its own noun. (A walk of the branch's
     * history used to stand in for this question and answered a weaker one — a
     * name held at some *other* commit passed it — while a commit object anywhere
     * in the branch could refuse a revert that needed none of it.) */
    const profile_claim_t *target = NULL;
    err = revert_target_claim(ctx, target_profile, &arg, filesystem_path, oid_str, &target);
    if (err) goto cleanup;

    /* Step 9: and the bytes behind it, read once, as the entry its filemode says
     * it is. The kind is what the restored claim's encrypted bit is stamped from
     * (step 14) and what decides whether the bytes can travel to another name
     * (step 13), and the read itself is the proof the repository holds the object
     * — which every filemode needs and only the regular-file arm used to make:
     * a link whose blob was gone passed the dry run and failed at the tree write,
     * after the preview had promised the restore. A link's bytes are its target
     * path, never a seal, and the classify is told the filemode, so a link's
     * kind is PLAINTEXT whatever its target begins with (infra/content.h). */
    content_kind_t target_kind = CONTENT_PLAINTEXT;
    err = content_classify(
        repo, &target->blob_oid, gitops_type_filemode(target->type), &target_kind, NULL
    );
    if (err) {
        err = error_wrap(
            err, "Cannot read '%s' at commit %s", target->storage_path, oid_str
        );
        goto cleanup;
    }

    /* Step 10: the name the revert writes, which the restored claim takes — the
     * commit's claim, renamed here and restamped below. A typed name is the user's
     * own choice of contract and is written as typed (cmds/add.c's storage arm
     * is the other place that choice is made). A path is answered by the claim
     * standing there, whatever its name and whatever its kind — home/jail/etc/x
     * under a binding at ~/jail is found by ~/jail/etc/x, and a chain the profile
     * names nothing by is answered as the claim it is, so the head's own tree
     * refuses a file where it holds a subtree (step 11). Where none stands, the
     * commit's own name is what comes back: a revert restores, and a name composed
     * from today's roots would choose a deployment contract the user did not. */
    profile_claim_t restored = *target;
    if (arg.key == PATH_KEY_FILESYSTEM) {
        const manifest_row_t *row = NULL;
        err = revert_claim_standing(ctx, standing_profile, filesystem_path, &row);
        if (err) goto cleanup;

        if (row) restored.storage_path = row->storage_path;
    } else {
        restored.storage_path = arg.storage_path;
    }

    output_print(
        out, OUTPUT_VERBOSE, "Resolved to '%s' in profile '%s'\n",
        restored.storage_path, profile
    );

    /* Step 11: what stands at that name in the head. It may be nothing — a path
     * the profile deleted is exactly what a revert brings back — and wherever
     * it stands it is a blob, because a revert restores one file's bytes.
     *
     * The tree alone, on purpose: Git's one-entry rule about the name the write
     * uses (core/profiles.h profile_entry), by value, and a directory claim the
     * sheet holds there never stands in its way — the restore takes its place
     * where it stands, and carries it where this entry's blob contradicts it
     * (step 15). So the sheet must not answer here. */
    profile_held_t standing;
    err = profile_entry(standing_profile, restored.storage_path, &standing);
    if (err) goto cleanup;

    if (standing.kind == PROFILE_HELD_DIRECTORY ||
        standing.kind == PROFILE_HELD_SUBMODULE) {
        err = error_create(
            ERR_INVALID_ARG, "'%s' is %s in profile '%s'; revert restores one file",
            restored.storage_path,
            standing.kind == PROFILE_HELD_DIRECTORY ? "a directory" : "a submodule",
            profile
        );
        goto cleanup;
    }

    /* Step 12: the admission. A typed name the head's tree does not hold is a
     * name this command would author, and a profile names a path once
     * (infra/mount.h, core/manifest.h): if the profile already names where this
     * name resolves and does not hold this name for it, authoring it would give
     * the profile a second name for one place — the pair the health channel calls
     * an unused path, and only `remove` can undo (revert_refuse_second_name).
     *
     * The entry test is the authoring question and not a cost guard: a name the
     * tree already holds is not authored, and whether one it lacks is a second
     * name is the contribution's to answer. A path argument is answered *by*
     * the claim standing there and can never be a second name, so this arm is
     * the typed one's alone. */
    if (arg.key == PATH_KEY_STORAGE &&
        standing.kind == PROFILE_HELD_NOTHING && filesystem_path) {
        err = revert_refuse_second_name(
            ctx, standing_profile, filesystem_path, restored.storage_path
        );
        if (err) goto cleanup;
    }

    /* Step 13: the object the commit would store under the name the write uses.
     * Encrypted bytes are sealed under the storage path they were written at
     * (crypto/cipher.h "Path binding"), so bytes that carry a binding cannot
     * travel by id to another name — no read under the new name could open them.
     * Plaintext carries none, and a link's bytes are its target path rather than
     * content — step 9's kind is PLAINTEXT for one, the filemode having decided
     * it (infra/content.h) — so both re-enter the tree as the id the repository
     * already holds.
     *
     * The bytes are hashed, not written: what the change test compares and what
     * the preview describes must be the object the commit would store, and a
     * dry run must leave the object database as it found it — the preview's own
     * in-memory patch is there for the same reason. The cost of that order is
     * that a cross-name restore of an encrypted file needs the key even where
     * the whole write turns out to already stand: there is no id to compare until
     * the reseal has made one. */
    if (target_kind != CONTENT_PLAINTEXT &&
        strcmp(target->storage_path, restored.storage_path) != 0) {
        err = content_rebind(
            repo, &target->blob_oid, target->storage_path, restored.storage_path,
            profile, ctx->run.keymgr, &rebound
        );
        if (err) {
            err = error_wrap(
                err, "Cannot restore '%s' as '%s'", target->storage_path,
                restored.storage_path
            );
            goto cleanup;
        }

        rc = git_odb_hash(
            &restored.blob_oid, rebound.data, rebound.size, GIT_OBJECT_BLOB
        );
        if (rc < 0) {
            err = error_git(
                rc, "Cannot identify the resealed '%s'", restored.storage_path
            );
            goto cleanup;
        }
    }

    /* Step 14: what the bytes and the commit's silence decide about a file's
     * claim. A link's is the commit's as the decode reads it, its owner and group
     * alone: its bytes are a target and never a seal, and symlink(2) takes no
     * mode. A file's stamp is the restored blob's own bytes — the write-boundary
     * invariant (core/policy.h), never trusted from a historical stamp, and
     * UNSUPPORTED_VERSION collapsing onto true as the captures collapse it —
     * and where the commit claims nothing about the file, no mode, no owner and
     * no group, its mode is reconstructed at its type's floor (core/profiles.h
     * profile_claim_mode), ownership not being recoverable. Decided here, and
     * said at the preview, where the user can still decline it. */
    if (target->type != PATH_TYPE_SYMLINK) {
        restored.encrypted = target_kind != CONTENT_PLAINTEXT;
        if (target->mode == MODE_UNCLAIMED && !target->owner && !target->group) {
            restored.mode = profile_claim_mode(&restored);
        }
    }

    /* Step 15: the restore, onto the profile's next commit (core/profiles.h
     * profile_stage_restore_file) — the admission's two halves, the entry at
     * its id, the put rule at the name, the way the commit stood the file on,
     * and the claim — the last thing about this revert that can be refused, and
     * refused before the preview promises it. The sheet's half finds what the
     * tree cannot, a directory the profile claims beneath the name; the tree's,
     * a destination beneath a blob the head holds, which used to pass the dry
     * run and fail after the prompt, with what the dry run should have said.
     *
     * Nothing is written to the repository: the id is one the commit already
     * holds, or one the reseal hashed and step 20 stores, so a dry run or a
     * declined prompt frees the stage and leaves the object database as it found
     * it. The stage's base is still the head, so every read below is the head's. */
    err = profile_stage_restore_file(stage, &restored, target_profile, target->storage_path);
    if (err) goto cleanup;

    /* Step 16: nothing to do — the restore moved neither document. A revert
     * restores bytes, the entry's mode, the sheet's mode and ownership, and the
     * way, so the whole write is weighed and never the blob alone: the stage
     * holds each document against the one it opened (core/profiles.h
     * profile_stage_changed). A directory claim at the name the standing blob
     * contradicts rides the write whatever it is, and moves nothing. */
    bool changed = false;
    err = profile_stage_changed(stage, &changed);
    if (err) goto cleanup;
    if (!changed) {
        output_info(
            out, OUTPUT_NORMAL, "File '%s' is already at target state (no changes)",
            restored.storage_path
        );
        goto cleanup;  /* Not an error, just nothing to do */
    }

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
    output_print(
        out, OUTPUT_NORMAL, "  Profile: {cyan}%s{reset}\n",
        profile
    );
    output_print(
        out, OUTPUT_NORMAL, "  File: {cyan}%s{reset}\n",
        restored.storage_path
    );
    output_print(
        out, OUTPUT_NORMAL, "  Target commit: %s (%s)\n",
        oid_str, time_buf
    );

    /* The other name, said once and only where there is one: the write lands on
     * the claim the profile holds now, and this is where the bytes come from. */
    if (strcmp(target->storage_path, restored.storage_path) != 0) {
        output_print(
            out, OUTPUT_NORMAL, "  Named at the commit: {cyan}%s{reset}\n",
            target->storage_path
        );
    }

    /* Mode and ownership have no byte source, so a commit that claims nothing
     * about the file leaves the revert reconstructing its mode (step 14): the
     * one way the restored claim names a mode the commit's does not. It is said
     * here, with the rest of what the write will do, and only once the write is
     * going to happen. */
    if (restored.mode != target->mode) {
        output_gap(out, OUTPUT_NORMAL);
        /* What is missing is a *file* claim, which is not the same as a missing
         * sheet: a DIRECTORY item can stand at this very key and claim nothing
         * about this file, the tree being the content authority, and a FILE item
         * that names nothing claims nothing either. Each reaches here, and the
         * sentence names the one thing all of them mean. */
        output_warning(
            out, OUTPUT_NORMAL, "No file claim recorded for '%s' at commit %s",
            target->storage_path, oid_str
        );
        output_hintline(
            out, OUTPUT_NORMAL,
            "Reconstructed from the commit (mode=%04o, encrypted=%s); "
            "ownership is not recoverable",
            (unsigned int) restored.mode, restored.encrypted ? "true" : "false"
        );
    }

    /* The three ways the write differs from what stands: the file comes back,
     * everything but its bytes moves — the one thing no diff can show — or its
     * bytes do. The middle arm is *the blob is the same and the change test said
     * something differs*, and what is left to differ is the entry's filemode
     * and the four fields of the claim beside it, so the sentence names those
     * rather than two of them. */
    if (standing.kind == PROFILE_HELD_NOTHING) {
        output_gap(out, OUTPUT_NORMAL);
        output_print(
            out, OUTPUT_NORMAL, "{green}Restoring a deleted file{reset}\n"
        );
    } else if (git_oid_equal(&standing.oid, &restored.blob_oid)) {
        output_gap(out, OUTPUT_NORMAL);
        output_print(
            out, OUTPUT_NORMAL,
            "{green}Contents unchanged; restoring the recorded mode, ownership "
            "and stamp{reset}\n"
        );
    } else {
        /* Detailed diff preview with decryption support. The content layer
         * classifies each blob by its own bytes, as the entry its filemode says
         * it is, so the "current vs target may differ in encryption state" case
         * is handled inside revert_print_diff without caller-side metadata
         * gymnastics. */
        err = revert_print_diff(
            ctx, profile, restored.storage_path, &standing.oid, standing.filemode,
            target->storage_path, &target->blob_oid, gitops_type_filemode(target->type)
        );
        if (err) {
            /* Non-fatal: the revert itself doesn't need decryption (copies blobs).
             * Show warning and continue to confirmation — user decides. */
            output_warning(
                out, OUTPUT_NORMAL, "Could not show diff preview: %s",
                error_line(err)
            );
            err = NULL;
        }
    }

    /* Step 18: Early exit for dry-run (preview shown, no changes to make) */
    if (opts->dry_run) {
        output_gap(out, OUTPUT_NORMAL);
        output_info(out, OUTPUT_NORMAL, "Dry-run mode: No changes made");
        goto cleanup;
    }

    /* Step 19: the confirmation, unless --force or the configuration gives it.
     * Declined is the user's word, and no failure; unanswered — off a terminal,
     * where a destructive question is never asked — nobody declined, and the
     * run did not do what it was asked: its refusal, naming the flag that answers
     * in advance. */
    if (!opts->force && config->confirm_destructive) {
        switch (output_ask_destructive(out, "Revert file?")) {
            case OUTPUT_ANSWER_YES:
                break;
            case OUTPUT_ANSWER_NO:
                output_info(out, OUTPUT_NORMAL, "Aborted.");
                goto cleanup;  /* err is NULL here: an abort is not a failure */
            case OUTPUT_ANSWER_NONE:
                err = error_create(
                    ERR_VALIDATION, "Cannot revert '%s' without a confirmation, which "
                    "only a terminal gives; --force reverts without asking",
                    restored.storage_path
                );
                goto cleanup;
        }
    }

    output_gap(out, OUTPUT_VERBOSE);
    output_print(out, OUTPUT_VERBOSE, "Reverting file...\n");

    /* Step 20: the write — the restore step 15 staged, in one commit on the head
     * the preview showed. A branch another writer moved since is refused by the
     * commit itself rather than by a second look at the head.
     *
     * The resealed bytes only now: the entry was put at their id before the
     * preview, and this is the object that id names — the same bytes step 13
     * hashed, so the same id. Materialising it earlier would leave a loose object
     * behind every dry run. */
    if (rebound.data) {
        rc = git_blob_create_from_buffer(
            &restored.blob_oid, repo, rebound.data, rebound.size
        );
        if (rc < 0) {
            err = error_git(rc, "Cannot store the resealed '%s'", restored.storage_path);
            goto cleanup;
        }
    }

    /* The commit prunes a derived claim nothing stands beneath any longer —
     * imported redundancy alone, since a restore makes no claim redundant — and
     * keeps no keys: a revert writes no record, and the next load releases one
     * a pruned rung stood on (core/profiles.h profile_stage_t). */
    const char *msg = revert_commit_message(
        ctx->arena, config, profile, restored.storage_path, git_commit_id(target_commit),
        opts->message
    );

    err = profile_stage_commit(stage, msg, NULL);
    if (err) goto cleanup;

    /* Step 21: Report. Nothing to write: the revert moved the branch HEAD, and
     * the next load's view carries the reverted blob — the record stays where
     * apply last confirmed it, so the workspace reads the result as [stale] until
     * apply deploys it. A disabled profile's revert reaches no view at all. */
    output_success(
        out, OUTPUT_NORMAL, "Reverted %s in profile '%s'", restored.storage_path,
        profile
    );

    /* The one line after it differs: a profile this machine has not enabled has
     * nothing to apply the revert to. */
    if (!state_enabled(state, profile)) {
        output_gap(out, OUTPUT_NORMAL);
        output_info(
            out, OUTPUT_NORMAL, "Note: Profile '%s' is not enabled on this machine",
            profile
        );
        goto cleanup;
    }

    output_gap(out, OUTPUT_NORMAL);
    output_info(
        out, OUTPUT_NORMAL, "Run 'dotta apply' to deploy changes to filesystem"
    );

cleanup:
    buffer_deinit(&rebound);
    profile_free(target_profile);
    if (target_tree) git_tree_free(target_tree);
    profile_stage_free(stage);
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
 *   0 args        → error "File specification is required"
 *   1 arg         → parse [profile:]<file>[@commit] via refspec_parse
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
static error_t revert_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) cmd;
    cmd_revert_options_t *o = opts_v;
    char **args = o->positional_args;

    if (o->positional_count == 0) {
        return error_create(
            ERR_INVALID_ARG, "File specification is required"
        );
    }

    if (o->positional_count == 1) {
        /* [profile:]<file>[@commit] */
        refspec_t rs = { 0 };
        error_t err = refspec_parse(arena, args[0], &rs);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse file specification");
        }
        if (rs.profile != NULL) o->profile = rs.profile;
        o->file_path = rs.file;
        if (rs.commit != NULL) o->commit = rs.commit;
    } else if (o->positional_count == 2) {
        if (refspec_looks_like_commit(args[1])) {
            /* [profile:]<file> <commit> — the file token read as the lone one
             * is, its profile winning over -p; the commit is the second's, so
             * one inside the token too is a commit given twice. */
            refspec_t rs = { 0 };
            error_t err = refspec_parse(arena, args[0], &rs);
            if (err != NULL) {
                return error_wrap(err, "Failed to parse file specification");
            }
            if (rs.commit != NULL) {
                return error_create(
                    ERR_INVALID_ARG, "Commit given twice: '%s' and '%s'", rs.commit,
                    args[1]
                );
            }
            if (rs.profile != NULL) o->profile = rs.profile;
            o->file_path = rs.file;
            o->commit = args[1];
        } else {
            /* <profile> <file[@commit]> — refspec profile wins if present. */
            o->profile = args[0];
            refspec_t rs = { 0 };
            error_t err = refspec_parse(arena, args[1], &rs);
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
        CHECK_ARG(false, "POSITIONAL_RAW bounds revert's positionals at three");
    }

    /* A commit is required by the command; file_path is guaranteed set by
     * successful refspec parsing or explicit positional assignment. */
    if (o->commit == NULL) {
        return error_create(
            ERR_INVALID_ARG, "Commit reference is required"
        );
    }
    return NULL;
}

/**
 * What can stand at the cursor, by the shapes revert_post_parse reads — as show,
 * without the bare-commit form: first a file of any profile as `profile:path`,
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

static error_t revert_dispatch(const void *ctx_v, void *opts_v) {
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
    ARGS_FLAG_SET(
        "v verbose",
        cmd_revert_options_t,verbosity,       DOTTA_VERBOSITY_VERBOSE,
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
        "  3. Read what the commit holds and what stands at the branch head. A\n"
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
        "  8. Create one commit with the restored file and its metadata, and the\n"
        "     directories it stood in, claimed as the commit claimed them where\n"
        "     the profile no longer does.\n",
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
