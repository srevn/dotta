/**
 * revert.c - A path or a whole profile made as a past commit held it
 */

#include "cmds/revert.h"

#include <config.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "base/refspec.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/restore.h"
#include "core/state.h"
#include "infra/commit.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/identity.h"
#include "sys/revision.h"
#include "utils/hooks.h"

/**
 * The one local profile holding the path, where no profile is named
 *
 * Every local profile, enabled or not, is asked at its head what it holds at
 * the argument, in the key the argument named. A path: the rows its one-profile
 * view stands at or beneath it — a file's, or a directory's whole — as export
 * selects them (cmds/export.c export_collect_filesystem), named by the profile's
 * own name for the path (core/manifest.h manifest_claim_name: the claim held
 * there, else the name one would take). The view is placed by this machine's
 * table, which is the enabled set's (core/manifest.h manifest_mount_table): a
 * profile nothing has enabled is bound nowhere, so no path reaches its custom/
 * claims, and their names find them. A name: a file or a directory either of
 * the profile's two documents holds at it (core/profiles.h profile_holds) — the
 * tree first, so a name the tree holds is answered without the sheet — named as
 * typed.
 *
 * Every holder counts. The one is the answer; several are refused, each listed
 * beside its own name for the argument, the way through the clause; none is refused
 * as an absence, whose way through is -p: a profile that deleted the path is
 * the case a revert exists for, and a profile named is not asked what its head
 * holds. A profile holding the path only by a name its view did not keep, or by
 * a claim its own claims contradict, stands no row there and is not found by
 * path; -p reaches it (stated).
 *
 * Complete or an error: a profile the search cannot read stops it whichever profile
 * it is, since a list short by one is a falsely unique answer, and the refusal's
 * clause names the flag that reads one profile instead of all of them. Each view
 * is built in a frame of its own, a view built to read one answer
 * (include/runtime.h "Memory"), the holder's name copied out: the search visits
 * every local profile, at a one-profile view each.
 *
 * Readers: cmd_revert, the profile the revert acts on where none is named; and
 * revert_holder, the profile a path's commit slot offers the changes of.
 *
 * @param ctx Dispatch context: the repository, the table and the arena the answer
 *            lives in (must not be NULL)
 * @param arg The argument, in the key it named (must not be NULL)
 * @param out_profile The one holder, as the listing spells it in ctx->arena (must
 *                    not be NULL; NULL after an error)
 * @return Error or NULL on success
 */
static error_t revert_select_profile(
    const dotta_ctx_t *ctx, const path_input_t *arg, const char **out_profile
) {
    CHECK_NULL(ctx);
    CHECK_NULL(arg);
    CHECK_NULL(out_profile);

    git_repository *repo = ctx->run.repo;

    *out_profile = NULL;

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

    /* Each profile loaded once and asked in the key the argument named: a profile
     * names a path once and holds a name once, so each answers once at most.
     * The first holder is kept as itself, and every holder is spelled as found
     * beside its own name for the argument, which is all the refusal for several
     * reads. */
    const char *holder = NULL;
    string_array_t holders;
    string_array_init(&holders, ctx->arena, 0);
    for (size_t i = 0; !err && i < profiles.count; i++) {
        profile_t *profile = NULL;
        err = profile_load(repo, profiles.entries[i], &profile);
        if (err) break;

        const char *name = NULL;
        if (arg->key == PATH_KEY_FILESYSTEM) {
            /* A path: any row at or beneath it, the profile's name for the path
             * itself said, in the command's arena, of the view the frame holds */
            arena_t *frame = arena_create(0);
            manifest_t *view = NULL;
            err = manifest_build_profile(profile, ctx->run.mounts, frame, &view);

            const manifest_rows_t rows = manifest_rows(view);
            const size_t len = strlen(arg->filesystem_path);
            for (size_t r = 0; !err && r < rows.count; r++) {
                if (str_path_under(rows.entries[r]->filesystem_path, arg->filesystem_path, len)) {
                    name = manifest_claim_name(
                        ctx->arena, view, profile_name(profile), arg->filesystem_path
                    );
                    break;
                }
            }
            arena_free(frame);
        } else {
            /* A name: a file or a directory at it, as typed — a gitlink there
             * is no claim, as the view holds none */
            profile_held_t held;
            err = profile_holds(profile, arg->storage_path, &held);
            if (!err && (held.kind == PROFILE_HELD_FILE || held.kind == PROFILE_HELD_DIRECTORY)) {
                name = arg->storage_path;
            }
        }
        profile_free(profile);
        if (err || !name) continue;

        if (!holder) holder = profiles.entries[i];
        string_array_pushf(&holders, "%s (%s)", profiles.entries[i], name);
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

    /* Held at no head, every profile having answered: naming the profile is what
     * reaches a path it deleted — a profile named is not asked what its head
     * holds */
    if (holders.count == 0) {
        return error_create(
            ERR_NOT_FOUND, "'%s' is not held by any profile; -p restores it into a "
            "profile that deleted it", subject
        );
    }

    /* Several: the way through is the clause, because no key tells them apart
     * here — a path asks every profile again, and each answers as before */
    if (holders.count > 1) {
        return error_create(
            ERR_INVALID_ARG, "'%s' is held by %zu profiles: %s; -p names one", subject,
            holders.count, string_array_join(ctx->arena, &holders, ", ")
        );
    }

    *out_profile = holder;
    return NULL;
}

/**
 * Print one line of a patch as libgit2 hands it, coloured by its origin
 *
 * Nothing is added: a change line that ends without a newline is followed by
 * libgit2's end-of-file line, which opens with the newline that line lacks
 * (lib/libgit2/src/libgit2/diff_xdiff.c git_xdiff_cb), so the lines printed as
 * handed are git's patch. The twin of cmds/diff.c diff_print_line_cb and
 * cmds/show.c show_print_line_cb, so a preview's patch reads as show's.
 */
static int revert_print_line_cb(
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

    /* A patch line is a payload, its bytes the file's own and libgit2's quoted
     * headers, written as they are: a change line's origin first, each in the
     * line's colour */
    if (line->origin == GIT_DIFF_LINE_ADDITION ||
        line->origin == GIT_DIFF_LINE_DELETION ||
        line->origin == GIT_DIFF_LINE_CONTEXT) {
        output_write(out, OUTPUT_NORMAL, line_color, &line->origin, 1);
    }
    output_write(out, OUTPUT_NORMAL, line_color, line->content, line->content_len);

    return 0;
}

/**
 * Print the changes between two blobs — a row of the preview, then the patch —
 * or that their contents are one
 *
 * The lines added and removed, or that a binary change moved, are a row of the
 * revert's preview, which the caller opened and which names the file already;
 * the patch is a block of its own beneath it.
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
 * The two blobs' ids differ: the caller reaches this only from the preview arm
 * that says so, and the arm beside it is what a copy with the same blob and a
 * different mode gets. Two ids can still hold one plaintext — a seal made or
 * opened in place, or made again under the name the head holds — and the patch,
 * made from the plaintexts, says so where the ids cannot: its delta unmodified,
 * the preview says the sentence that arm says.
 *
 * That arm is also why the caller hands the head's name in as the label: the
 * head's claim is read at the file's place, and its name is the one the revert
 * writes there (core/restore.h), so wherever there is a blob to diff against,
 * the write's name is the head's binding and the two words name one string.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param profile Profile name, for key derivation (must not be NULL)
 * @param head_name The head's binding, and the label on both sides (must not be
 *                  NULL)
 * @param head_oid The blob at the head (must not be NULL)
 * @param head_mode Its filemode at the head
 * @param target_name The commit's binding: how its bytes open (must not be NULL)
 * @param target_oid The committed object (must not be NULL)
 * @param target_mode Its filemode at the commit
 * @return Error or NULL on success
 */
static error_t revert_print_diff(
    const dotta_ctx_t *ctx,
    const char *profile,
    const char *head_name,
    const git_oid *head_oid,
    git_filemode_t head_mode,
    const char *target_name,
    const git_oid *target_oid,
    git_filemode_t target_mode
) {
    CHECK_NULL(ctx);
    CHECK_NULL(profile);
    CHECK_NULL(head_name);
    CHECK_NULL(head_oid);
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
    buffer_t head_plaintext = BUFFER_INIT;
    error_t err = content_get_from_blob_oid(
        repo,
        head_oid,
        head_mode,
        head_name,
        profile,
        keymgr,
        &head_plaintext
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
        buffer_deinit(&head_plaintext);
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
        head_plaintext.data, head_plaintext.size, head_name,
        target_plaintext.data, target_plaintext.size, head_name,
        NULL  /* options */
    );

    if (rc < 0) {
        buffer_deinit(&head_plaintext);
        buffer_deinit(&target_plaintext);
        return error_git(rc, "Cannot compare the two versions of '%s'", head_name);
    }

    /* What the patch found, off libgit2's own tests, set as it was built: two
     * plaintexts that are one — a seal made or opened in place, or made again
     * under another name, the bytes kept under another id — move nothing a patch
     * shows, and the revert restores the claim alone, said in the words the
     * caller's arm on equal ids says it */
    const git_diff_delta *delta = git_patch_get_delta(patch);
    if (delta->status == GIT_DELTA_UNMODIFIED) {
        output_gap(out, OUTPUT_NORMAL);
        output_print(
            out, OUTPUT_NORMAL,
            "{green}Contents unchanged; restoring the commit's mode, ownership "
            "and stamp{reset}\n"
        );
    } else {
        /* The changes, a row of the preview's block: a binary change has no line
         * to count, and says so */
        if (delta->flags & GIT_DIFF_FLAG_BINARY) {
            output_print(out, OUTPUT_NORMAL, "  Changes: binary\n");
        } else {
            size_t additions = 0;
            size_t deletions = 0;
            git_patch_line_stats(NULL, &additions, &deletions, patch);

            output_print(
                out, OUTPUT_NORMAL, "  Changes: {green}+%zu{reset} / {red}-%zu{reset}\n",
                additions, deletions
            );
        }
        output_gap(out, OUTPUT_NORMAL);

        /* The patch it holds, each line as libgit2 hands it */
        if (git_patch_print(patch, revert_print_line_cb, out) < 0) {
            output_warning(out, OUTPUT_NORMAL, "Could not format diff output");
        }
    }

    git_patch_free(patch);

    /* Free plaintext buffers */
    buffer_deinit(&head_plaintext);
    buffer_deinit(&target_plaintext);

    return NULL;
}

/**
 * Print what a revert changes of the profile: a section a change, in the words
 * its commit will carry
 *
 * The names the commit adds, updates, removes and changes of dotta's own files
 * (core/profiles.h profile_changes), each list a section titled in the message's
 * headings (infra/commit.c commit_paths) and every name listed, where the message
 * names five a heading. The preview spells its titles and never reads the removal
 * rule (infra/commit.h commit_action_t): the Deleted section's hint is the one
 * effect another machine feels, every machine's unchanged copy deleted at its
 * next apply, in update's words for its own (cmds/update.c update_print_preview).
 * A revert whose lists name nothing moves only the way to the claims — a derived
 * directory's attributes, or a sheet saying the head's claims in other bytes —
 * and says so in the message's own line, tensed for a preview.
 *
 * Reader: cmd_revert, every revert but one file's restore.
 *
 * @param out Output context (must not be NULL)
 * @param changes What the commit changes (must not be NULL)
 */
static void revert_print_changes(output_t *out, const commit_changes_t *changes) {
    CHECK_NULL(out);
    CHECK_NULL(changes);

    /* No list names anything: the way to the claims moved alone */
    if (changes->added.count + changes->updated.count + changes->removed.count +
        changes->internal.count == 0) {
        output_gap(out, OUTPUT_NORMAL);
        output_print(out, OUTPUT_NORMAL, "Only ancestor claims will change\n");
        return;
    }

    /* The names the profile claims nothing at now, and the commit does */
    if (changes->added.count > 0) {
        output_list_t *list = output_list_create(out, "Added", NULL);
        for (size_t i = 0; i < changes->added.count; i++) {
            output_list_add(list, NULL, OUTPUT_COLOR_RESET, changes->added.entries[i], NULL);
        }
        output_list_render(list);
        output_list_free(list);
    }

    /* The names claimed on both sides, saying another thing */
    if (changes->updated.count > 0) {
        output_list_t *list = output_list_create(out, "Updated", NULL);
        for (size_t i = 0; i < changes->updated.count; i++) {
            output_list_add(list, NULL, OUTPUT_COLOR_RESET, changes->updated.entries[i], NULL);
        }
        output_list_render(list);
        output_list_free(list);
    }

    /* The names the profile claims and the commit nothing at: a file's removal
     * deletes every machine's unchanged copy at its next apply, the one effect
     * the revert has past the profile */
    if (changes->removed.count > 0) {
        output_list_t *list = output_list_create(
            out, "Deleted",
            "will be deleted from the profile, with every machine's unchanged copy"
        );
        for (size_t i = 0; i < changes->removed.count; i++) {
            output_list_add(list, NULL, OUTPUT_COLOR_RESET, changes->removed.entries[i], NULL);
        }
        output_list_render(list);
        output_list_free(list);
    }

    /* Dotta's own files the commit changes, a whole profile's alone */
    if (changes->internal.count > 0) {
        output_list_t *list = output_list_create(out, "Internal", NULL);
        for (size_t i = 0; i < changes->internal.count; i++) {
            output_list_add(list, NULL, OUTPUT_COLOR_RESET, changes->internal.entries[i], NULL);
        }
        output_list_render(list);
        output_list_free(list);
    }
}

/**
 * What a revert hands its hooks: the path each claim its commit changes stands
 * at, once
 *
 * The claims the commit adds, updates and removes (core/profiles.h
 * profile_changes), each at the path this machine puts it; one placed nowhere
 * hands its name, the shape remove hands a hook its claims in (cmds/remove.c
 * remove_hook_paths). A path two names stand at — the head's unused name a revert
 * takes beside the one it writes — is one entry: a hook is told the paths the
 * revert reaches. An internal file stands nowhere and hands nothing, and is never
 * placed: the table places a name under a label alone (infra/mount.h
 * mount_resolve).
 *
 * Reader: cmd_revert, both hooks.
 *
 * @param arena The list's arena, its seen-set's and the places' (must not be NULL)
 * @param changes What the commit changes (must not be NULL)
 * @param mounts This machine's table (must not be NULL)
 * @param profile The reverted profile, whose binding places its custom/ names
 *                (must not be NULL)
 * @return The paths, copies in `arena`
 */
static string_array_t revert_hook_paths(
    arena_t *arena, const commit_changes_t *changes, const mount_table_t *mounts,
    const char *profile
) {
    string_array_t paths;
    string_array_init(&paths, arena, 0);

    /* Each path once, by a seen-set's one probe (base/hashmap.h hashmap_add);
     * the list keeps copies, the shape the hook contract's char *const * takes
     * as it stands */
    const string_array_t *const lists[] = {
        &changes->added, &changes->updated, &changes->removed,
    };
    hashmap_t *handed = hashmap_borrow(arena, 0);
    for (size_t l = 0; l < sizeof(lists) / sizeof(lists[0]); l++) {
        for (size_t i = 0; i < lists[l]->count; i++) {
            const char *name = lists[l]->entries[i];
            const char *place = mount_resolve(arena, mounts, profile, name);
            const char *path = place ? place : name;
            if (hashmap_add(handed, path, NULL)) string_array_push(&paths, path);
        }
    }

    return paths;
}

/**
 * Whether the record at a place the commit changed a claim at is this profile's
 * — the one a revert's reclaim retires
 *
 * Asked of the read before the lock, whether to take it (revert_owes), and of
 * the one under it, which decides (revert_write_record). The storage name is
 * not asked: another of the profile's names at the place is the same profile's
 * node.
 *
 * @param records The record, as a read gave it (NULL when record_count is 0)
 * @param record_count Records in it
 * @param profile The reverted profile (must not be NULL)
 * @param filesystem_path The place (must not be NULL)
 * @return Whether the record there names the profile
 */
static bool revert_reclaims(
    const state_record_t *records, size_t record_count, const char *profile,
    const char *filesystem_path
) {
    const state_record_t *record = state_find_record(
        records, record_count, filesystem_path
    );

    return record && strcmp(record->profile, profile) == 0;
}

/**
 * Whether the record phase owes a write, as the record stands before the lock:
 * this profile's record at one of the places, each a place the commit changed a
 * claim at whose node is gone (revert_write_record)
 *
 * No place owes nothing, and reads no record. Else the record is read on the
 * READ handle, empty where the database does not exist, which grows none. A read
 * that fails owes the lock: the read here decides only whether to take it, and
 * the read under the lock says why where it fails again, so this one's error is
 * dropped — as remove's (cmds/remove.c remove_owes).
 *
 * @param ctx Dispatch context: the store, and the arena the read lands in
 * @param profile The reverted profile (must not be NULL)
 * @param restored The places the commit restored a claim at
 * @param removed The places only its removals reached
 * @return Whether to take the lock
 */
static bool revert_owes(
    const dotta_ctx_t *ctx, const char *profile, const string_array_t *restored,
    const string_array_t *removed
) {
    if (restored->count + removed->count == 0) return false;

    state_record_t *records = NULL;
    size_t record_count = 0;
    if (state_records(ctx->run.state, ctx->arena, &records, &record_count)) return true;

    for (size_t i = 0; i < restored->count; i++) {
        if (revert_reclaims(records, record_count, profile, restored->entries[i])) {
            return true;
        }
    }
    for (size_t i = 0; i < removed->count; i++) {
        if (revert_reclaims(records, record_count, profile, removed->entries[i])) {
            return true;
        }
    }

    return false;
}

/**
 * Write the record a revert owes: the reclaim of each place its commit changed
 * a claim at, where the node is gone
 *
 * A revert changes Git and nothing on disk, and the next load reads each claim
 * it restored against the record at its place: [stale] over a copy that stands,
 * apply's to bring. Over a node already gone that record is the history of a
 * node the user removed — under an earlier removal of the claim, or Git's — and
 * where it confirmed the bytes the revert restores, as a revert undoing that
 * removal finds it, would read the restored claim's absence as the user's deletion
 * again (core/workspace.c classify_absent), every screen sending the user to
 * undo the revert. So this profile's record there retires, the commit having
 * reconciled the claim with the node's absence, and the claim starts from its
 * first look, apply's to land (core/state.h state_retire) — by one of two rules
 * (cmds/revert.h):
 *   - a place the commit restored a claim at, whatever row stands there now:
 *     the record is the restored claim's own history, which would misread its
 *     absence wherever that claim comes to stand — beneath a higher profile's
 *     row, once that row leaves before an apply;
 *   - a place only its removals reached, where no row stands there after the
 *     commit, as remove's (cmds/remove.c remove_write_record): a record kept
 *     under another profile's row is that row's reassignment (core/workspace.h
 *     workspace_reassigned), which the screens say.
 * This profile's record alone, whatever its kind, the enabled set or no. A name
 * this machine places nowhere is no place, and an internal file none.
 *
 * The look first: a node standing at every place — every revert of deployed files
 * — reads no record and takes no lock. Then whether this profile's record stands
 * at one of the places whose node is gone, before the lock, so a revert that
 * owes nothing takes none and a store with no database grows none (revert_owes),
 * and again under it, which decides (core/state.h state_begin); the enabled view
 * the commit leaves is built there only where a place only removals reached owes.
 *
 * Refused, the records stand, and the reclaim is what no later load re-derives:
 * a restored claim's absence reads as its record says — [undeployed] [stale],
 * apply's, where it confirmed other bytes than the restored ones, and the user's
 * deletion, which an update would commit, where it confirmed the very bytes
 * restored (stated, cmd_revert) — and in a disabled profile the record is an
 * orphan, which the next apply reclaims.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param profile The reverted profile (must not be NULL)
 * @param changes What the commit changed (must not be NULL)
 * @return Error or NULL on success; the transaction is ended either way
 */
static error_t revert_write_record(
    const dotta_ctx_t *ctx, const char *profile, const commit_changes_t *changes
) {
    CHECK_NULL(ctx);
    CHECK_NULL(profile);
    CHECK_NULL(changes);

    const mount_table_t *mounts = ctx->run.mounts;
    state_t *state = ctx->run.state;

    /* The places whose node is gone, each once, by the rule its record goes by:
     * a place a claim was restored at, added or updated, then one only removals
     * reached — read after, so a place both reached is the restored claim's. A
     * node standing there is the copy the record describes, apply's to bring */
    hashmap_t *places = hashmap_borrow(ctx->arena, 0);
    string_array_t restored;
    string_array_t removed;
    string_array_init(&restored, ctx->arena, 0);
    string_array_init(&removed, ctx->arena, 0);

    const string_array_t *const lists[] = { &changes->added, &changes->updated };
    for (size_t l = 0; l < sizeof(lists) / sizeof(lists[0]); l++) {
        for (size_t i = 0; i < lists[l]->count; i++) {
            const char *name = lists[l]->entries[i];
            const char *place = mount_resolve(ctx->arena, mounts, profile, name);
            if (place && hashmap_add(places, place, NULL) &&
                fs_lstat_occupant(place, NULL) == FS_OCCUPANT_NONE) {
                string_array_push(&restored, place);
            }
        }
    }
    for (size_t i = 0; i < changes->removed.count; i++) {
        const char *name = changes->removed.entries[i];
        const char *place = mount_resolve(ctx->arena, mounts, profile, name);
        if (place && hashmap_add(places, place, NULL) &&
            fs_lstat_occupant(place, NULL) == FS_OCCUPANT_NONE) {
            string_array_push(&removed, place);
        }
    }

    if (!revert_owes(ctx, profile, &restored, &removed)) return NULL;

    /* The lock, and every decision below made under it */
    error_t err = state_begin(state);
    if (err) return err;

    state_record_t *records = NULL;
    size_t record_count = 0;
    err = state_records(state, ctx->arena, &records, &record_count);
    if (err) goto cleanup;

    /* A place a claim was restored at: this profile's record retires, whatever
     * row stands there */
    for (size_t i = 0; i < restored.count; i++) {
        if (!revert_reclaims(records, record_count, profile, restored.entries[i])) continue;

        err = state_retire(state, restored.entries[i]);
        if (err) goto cleanup;
    }

    /* A place only removals reached: this profile's record retires where no row
     * stands there after the commit, the view it leaves built at the first such
     * record and read for each */
    manifest_t *after = NULL;
    for (size_t i = 0; i < removed.count; i++) {
        if (!revert_reclaims(records, record_count, profile, removed.entries[i])) continue;

        if (!after) {
            err = manifest_build(ctx->run.repo, state, ctx->arena, &after);
            if (err) goto cleanup;
        }
        if (manifest_lookup(after, removed.entries[i])) continue;

        err = state_retire(state, removed.entries[i]);
        if (err) goto cleanup;
    }

    err = state_commit(state);

cleanup:
    /* The transaction ends here either way: a refused one is rolled back, and a
     * committed one has already ended (state_rollback finds none to end) */
    state_rollback(state);

    return err;
}

/**
 * Revert command implementation
 */
error_t cmd_revert(const dotta_ctx_t *ctx, const cmd_revert_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->commit);
    CHECK_ARG(opts->path || opts->profile, "a whole profile is named by its own word");

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    const mount_table_t *mounts = ctx->run.mounts;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* The handles keep their column as a prefix — the commit reverted to, its
     * tree and the profile at it — beside the profile's draft at its head */
    error_t err = NULL;
    git_commit *target_commit = NULL;
    profile_draft_t *draft = NULL;
    git_tree *target_tree = NULL;
    profile_t *target_profile = NULL;

    /* The path, where one is given, in the key the user named — a path or a storage
     * path, neither manufactured from the other (infra/path.h) — and the profile
     * the revert acts on: the one named — a refspec's, -p's, a whole profile's
     * own word — required to be here, and never asked what its head holds, a
     * path it deleted being the case a revert exists for; else the one local
     * profile holding the path (revert_select_profile). */
    path_input_t arg = { 0 };
    if (opts->path) {
        err = path_input_resolve(opts->path, ctx->arena, &arg);
        if (err) goto cleanup;
    }

    const char *profile = opts->profile;
    err = profile ? profile_require(repo, profile) : revert_select_profile(ctx, &arg, &profile);
    if (err) goto cleanup;

    /* The commit, in the profile's history */
    output_print(out, OUTPUT_VERBOSE, "Resolving target commit '%s'...\n", opts->commit);
    err = revision_load(repo, profile, opts->commit, &target_commit);
    if (err) goto cleanup;

    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), git_commit_id(target_commit));

    /* The profile's draft, opened at its head (core/profiles.h profile_draft_t).
     * The head is what the preview compares against and the parent the revert's
     * commit will have, so a branch that moves between the preview and the commit
     * is refused at the commit, --force or not: what the user confirmed is what
     * is reverted. Its sheet is read now, strictly: a corrupt destination sheet
     * would discard claims for unrelated paths when the commit saved its
     * replacement, so one that will not load is refused before the preview, in
     * the loader's words, as every writer refuses it. */
    err = profile_draft_open(repo, profile, &draft);
    if (err) goto cleanup;

    /* The commit's tree, opened once and lent to everything below that reads
     * the commit, and the profile at it, whose sheet is read once, strictly,
     * and said as the commit's: every later read of the commit — its claims at
     * a path, the way a restore brings back, the whole tree — reads it through
     * the profile at the commit's tree, so a sheet that will not load is refused
     * here, naming the commit, whichever read would have met it first. A corrupt
     * source sheet would invent attributes while claiming to restore them. A
     * commit without a sheet loads as an empty one (the tree loader's contract). */
    int rc = git_commit_tree(&target_tree, target_commit);
    if (rc < 0) {
        err = error_git(rc, "Cannot read the tree of commit '%s'", opts->commit);
        goto cleanup;
    }
    target_profile = profile_open(profile, target_tree);

    err = profile_load_sheet(target_profile);
    if (err) {
        err = error_wrap(err, "Failed to load metadata from target commit %s", oid_str);
        goto cleanup;
    }

    /* The revert, onto the draft, and nothing written to the repository: the
     * path's claims made the commit's — every claim the commit's view stands at
     * and beneath it, under the name the head holds its place by, and every claim
     * the head holds there that the commit did not, removed (core/restore.h
     * restore_path) — or the commit's whole tree (core/profiles.h
     * profile_restore_tree). Every refusal comes here, before the preview promises
     * anything: a stage collision, a lost blob, a seal that moves to another
     * name with no key. A reseal's bytes wait in the stage until its commit, so
     * a dry run, a refusing hook or a declined question leaves the object database
     * as it found it (sys/stage.h stage_put_unwritten).
     *
     * The restore answers how many claims the path reaches at the head and at
     * the commit together. None is no revert to make — usually a typo — and refused
     * as an absence on both sides, in the key the user named: "nothing to revert"
     * is the change test's, for a path a side holds. */
    size_t found = 0;
    if (opts->path) {
        err = restore_path(draft, mounts, &arg, target_profile, ctx->run.keymgr, &found);
        if (!err && found == 0) {
            err = error_create(
                ERR_NOT_FOUND,
                "'%s' not found in profile '%s', at its head or at commit %s",
                arg.key == PATH_KEY_FILESYSTEM ? arg.filesystem_path : arg.storage_path,
                profile, oid_str
            );
        }
    } else {
        err = profile_restore_tree(draft, target_profile);
    }
    if (err) goto cleanup;

    /* What the revert is said of, at a path: what it leaves at the argument's
     * own place — its path, or where the table puts the name it typed; a name
     * placed nowhere has none — each side read as the restore reads it
     * (core/restore.c restore_path), in two one-profile views of the same trees
     * built here again (stated): the commit's claim its view stands there, the
     * layer's rung being no claim of the profile's, and the head's claim there,
     * explicit else derived. The command's arena holds them: the subject is said
     * past the commit.
     *
     * A file is said by its name — the claim the revert leaves there, or, where
     * the commit held none, the head's it takes — and its name the head's for
     * the place, else the claim's own (as core/restore.c restore_select names
     * each write). Anything else is said by the argument as the shell spells it
     * (base/output.h output_format_path), a name as typed. A whole profile is
     * said by its own word. */
    const manifest_row_t *target = NULL;    /* the commit's claim at the place */
    const manifest_row_t *held = NULL;      /* the head's claim there */
    const char *file = NULL;                /* the file it is said of, where it is one */
    const char *subject = NULL;             /* what it is said of; NULL: the whole profile */
    char spelled[PATH_MAX];
    if (opts->path) {
        const char *place = arg.key == PATH_KEY_FILESYSTEM
            ? arg.filesystem_path
            : mount_resolve(ctx->arena, mounts, profile, arg.storage_path);

        if (place) {
            manifest_t *head = NULL;
            manifest_t *historical = NULL;
            err = manifest_build_profile(profile_draft_base(draft), mounts, ctx->arena, &head);
            if (!err) {
                err = manifest_build_profile(target_profile, mounts, ctx->arena, &historical);
            }
            if (err) goto cleanup;

            const manifest_row_t *row = manifest_lookup(historical, place);
            if (manifest_holds_row(historical, row)) target = row;
            held = manifest_lookup_claim(head, profile, place);
        }

        const manifest_row_t *claim = target ? target : held;
        if (claim && claim->type != PATH_TYPE_DIRECTORY) {
            file = held ? held->storage_path : claim->storage_path;
            subject = file;
        } else if (arg.key == PATH_KEY_FILESYSTEM) {
            output_format_path(arg.filesystem_path, identity()->home, spelled, sizeof(spelled));
            subject = spelled;
        } else {
            subject = arg.storage_path;
        }
    }

    /* Nothing to do: the revert moved neither the tree nor the sheet, each held
     * against the one the draft opened (core/profiles.h profile_changed) — every
     * claim the path reaches held alike, the way to them too, or the commit's
     * tree the head's own. Said as every command says it has nothing to do, naming
     * what the revert is said of, its profile and the commit. */
    bool changed = false;
    err = profile_changed(draft, &changed);
    if (err) goto cleanup;
    if (!changed) {
        if (subject) {
            output_summary(
                out, OUTPUT_NORMAL, "Nothing to revert: %s in profile '%s' is already "
                "as at commit %s", subject, profile, oid_str
            );
        } else {
            output_summary(
                out, OUTPUT_NORMAL, "Nothing to revert: profile '%s' is already as at "
                "commit %s", profile, oid_str
            );
        }
        goto cleanup;  /* Not an error, just nothing to do */
    }

    /* The consent the revert owes — none under --force, where the configuration
     * asks none, or in a dry run — is a person's at a terminal (base/output.h
     * output_ask_destructive): off one it is refused here, at the decision, before
     * the preview and the hook. A revert with nothing to do owes none, ended
     * above. */
    const bool asks = !opts->force && config->confirm_destructive && !opts->dry_run;
    if (asks && !isatty(STDIN_FILENO)) {
        if (subject) {
            err = error_create(
                ERR_VALIDATION, "Cannot revert '%s' without a confirmation, which only "
                "a terminal gives; --force reverts without asking", subject
            );
        } else {
            err = error_create(
                ERR_VALIDATION, "Cannot revert profile '%s' without a confirmation, "
                "which only a terminal gives; --force reverts without asking", profile
            );
        }
        goto cleanup;
    }

    /* What the commit changes of the profile, name by name (core/profiles.h
     * profile_changes): the preview's sections, the paths the hooks are handed,
     * the places the record phase reads — the commit's own answer, asked before
     * it, its prune and its save moving no name the lists hold. */
    commit_changes_t changes;
    err = profile_changes(draft, ctx->arena, &changes);
    if (err) goto cleanup;

    /* The preview (always, a dry run's too): the header — the profile, the file
     * or the path the revert is said of, the commit and, where the file's name
     * moved since, the name the commit held its bytes under — then the body */
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
    output_print(out, OUTPUT_NORMAL, "  Profile: {cyan}%s{reset}\n", profile);
    if (subject) {
        output_print(
            out, OUTPUT_NORMAL, "  %s: {cyan}%s{reset}\n", file ? "File" : "Path", subject
        );
    }
    output_print(out, OUTPUT_NORMAL, "  Target commit: %s (%s)\n", oid_str, time_buf);
    if (file && target && strcmp(target->storage_path, file) != 0) {
        output_print(
            out, OUTPUT_NORMAL, "  Named at the commit: {cyan}%s{reset}\n",
            target->storage_path
        );
    }

    /* The body. One file's restore is said whole — the path reaches one claim,
     * the commit's file at the argument's own place, and the revert moves it —
     * by the three ways a file differs from what the head holds: it comes back,
     * everything but its bytes moves — the one thing no diff can show — or its
     * bytes do. The middle arm is *the blob is the same and the change test said
     * something differs*, and what is left to differ is the entry's filemode
     * and the claim beside it, so the sentence names those. Its proof is the
     * ids, which needs no byte read, so a cold key keeps the preview; two ids
     * that hold one plaintext are its twin, which only a read can prove, and
     * revert_print_diff says the same sentence off the two plaintexts — among
     * them a seal the restore made again under the name the head holds it by,
     * since the id compared is the commit's own blob, never the one a reseal's
     * bytes will be written as.
     *
     * Every other revert — a directory, a file it removes, a file beside another
     * claim the path reaches, a claim the head holds at the file's own name among
     * them, a whole profile, a name placed nowhere — lists what its commit changes,
     * in the commit's words (revert_print_changes). */
    if (found == 1 && target && target->type != PATH_TYPE_DIRECTORY &&
        changes.added.count + changes.updated.count == 1) {
        if (!held || held->type == PATH_TYPE_DIRECTORY) {
            output_gap(out, OUTPUT_NORMAL);
            output_print(out, OUTPUT_NORMAL, "{green}Restoring a deleted file{reset}\n");
        } else if (git_oid_equal(&held->blob_oid, &target->blob_oid)) {
            output_gap(out, OUTPUT_NORMAL);
            output_print(
                out, OUTPUT_NORMAL,
                "{green}Contents unchanged; restoring the commit's mode, ownership "
                "and stamp{reset}\n"
            );
        } else {
            /* The diff, both blobs decrypted where sealed — each classified by
             * its own bytes, as the entry its filemode says it is. Non-fatal:
             * the revert itself needs no decryption, a restore putting an id or
             * a reseal's bytes, so a warning stands in for the changes, a block
             * of its own, and the user decides at the question. */
            err = revert_print_diff(
                ctx, profile, held->storage_path, &held->blob_oid,
                gitops_type_filemode(held->type), target->storage_path,
                &target->blob_oid, gitops_type_filemode(target->type)
            );
            if (err) {
                output_gap(out, OUTPUT_NORMAL);
                output_warning(
                    out, OUTPUT_NORMAL, "Could not show diff preview: %s",
                    error_line(err)
                );
                err = NULL;
            }
        }
    } else {
        revert_print_changes(out, &changes);
    }

    /* The pre-revert hook, over the decided revert — a dry run's too, told so
     * (DOTTA_DRY_RUN=1) — handed every path a claim the commit changes stands
     * at (revert_hook_paths). The draft opened before it, so a commit the hook
     * makes to the branch refuses this revert's, and a branch it deletes comes
     * back with it (sys/stage.h). */
    const string_array_t hook_paths = revert_hook_paths(ctx->arena, &changes, mounts, profile);
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REVERT,
        .profile    = profile,
        .paths      = hook_paths.entries,
        .path_count = hook_paths.count,
        .dry_run    = opts->dry_run,
    };

    err = hook_fire_pre(config, out, &hook_inv);
    if (err) goto cleanup;

    /* A dry run ends here, its preview shown and nothing committed */
    if (opts->dry_run) {
        output_summary(out, OUTPUT_NORMAL, "Dry run: nothing was committed");
        goto cleanup;
    }

    /* The confirmation, after the hook, where one is owed. Declined is the user's
     * word, and no failure; unanswered — the terminal's input ended — nobody
     * declined, and the run did not do what it was asked: its refusal, naming
     * the flag that answers in advance. */
    if (asks) {
        switch (output_ask_destructive(out, "Continue?")) {
            case OUTPUT_ANSWER_YES:
                break;
            case OUTPUT_ANSWER_NO:
                output_summary(out, OUTPUT_NORMAL, "Cancelled");
                goto cleanup;  /* err is NULL here: a cancel is not a failure */
            case OUTPUT_ANSWER_NONE:
                if (subject) {
                    err = error_create(
                        ERR_VALIDATION, "Cannot revert '%s' without a confirmation, and "
                        "none was read; --force reverts without asking", subject
                    );
                } else {
                    err = error_create(
                        ERR_VALIDATION, "Cannot revert profile '%s' without a "
                        "confirmation, and none was read; --force reverts "
                        "without asking", profile
                    );
                }
                goto cleanup;
        }
    }

    output_gap(out, OUTPUT_VERBOSE);
    output_print(out, OUTPUT_VERBOSE, "Reverting...\n");

    /* The write — what the revert staged, in one commit on the head the preview
     * showed. A branch another writer moved since is refused by the commit itself
     * rather than by a second look at the head. A reseal's bytes are written
     * only now, by the stage, with the commit's tree (sys/stage.h
     * stage_put_unwritten).
     *
     * The commit, its message the draft's as every writer's is (core/profiles.h
     * profile_commit): the user's own where one was given, else the template's
     * over what the commit changes of the profile's claims and its internal files,
     * and the commit restored from, whole. Its prune takes a derivation nothing
     * stands beneath any longer, and the record of a rung it pruned is the next
     * load's to decide, as of every claim a commit lets go. Where the prune takes
     * back the only edit — a derivation the commit held with nothing beneath
     * it, all else held alike — the tree is the head's and no commit lands: nothing
     * to revert after all, and no receipt, record or post-revert hook follows,
     * as none follows a cancel. */
    char target_hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(target_hex, sizeof(target_hex), git_commit_id(target_commit));
    const commit_words_t words = {
        .action        = COMMIT_ACTION_REVERT,
        .title         = config->commit_title,
        .body          = config->commit_body,
        .custom_msg    = opts->message,
        .target_commit = target_hex,
    };
    git_oid commit = GIT_OID_SHA1_ZERO;
    err = profile_commit(draft, &words, &commit, NULL);
    if (err) goto cleanup;

    if (git_oid_is_zero(&commit)) {
        if (subject) {
            output_summary(
                out, OUTPUT_NORMAL, "Nothing to revert: %s in profile '%s' is already "
                "as at commit %s", subject, profile, oid_str
            );
        } else {
            output_summary(
                out, OUTPUT_NORMAL, "Nothing to revert: profile '%s' is already as at "
                "commit %s", profile, oid_str
            );
        }
        goto cleanup;
    }

    /* The receipt, once the commit lands and before the record phase, which may
     * wait on the store's lock (core/state.h state_begin). A block of its own,
     * beneath the preview, the question or the trace. A profile this machine
     * has not enabled is said on its line: the commit restored content no apply
     * here deploys, as add says of a capture into one (cmds/add.c cmd_add). */
    if (subject) {
        output_success(
            out, OUTPUT_NORMAL, "Reverted %s in profile '%s'%s", subject, profile,
            state_enabled(state, profile) ? "" : " (not enabled here)"
        );
    } else {
        output_success(
            out, OUTPUT_NORMAL, "Reverted profile '%s' to commit %s%s", profile,
            oid_str, state_enabled(state, profile) ? "" : " (not enabled here)"
        );
    }

    /* The record phase: the reclaim at each place the commit changed a claim at
     * whose node is gone (revert_write_record). Non-fatal: the commit stands,
     * so the store's refusal is warned in its own words, a block beneath the
     * receipt. What it loses, no later load re-derives: the reclaim, so a gone
     * node's record stays, and a restored claim's absence reads as that record
     * says (core/workspace.c classify_absent) — apply's to land, [stale] beside
     * it, where it confirmed other bytes than the restored ones; and the user's
     * deletion where it confirmed the very bytes restored, a revert undoing a
     * removal whose copy the user then removed, which an update would commit,
     * undoing the revert (stated): status lists it as deleted, and a plain apply
     * lands it. In a disabled profile the record is an orphan the next apply
     * reclaims, and nothing reads it wrong unless an enable comes first
     * (stated). */
    error_t record_err = revert_write_record(ctx, profile, &changes);
    if (record_err) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(record_err));
    }

    /* The post-revert hook, last (utils/hooks.h hook_fire_post): the commit landed
     * and the record phase's transaction ended, so the hook meets the store this
     * run leaves */
    hook_fire_post(config, out, &hook_inv);

cleanup:
    profile_free(target_profile);
    if (target_tree) git_tree_free(target_tree);
    profile_draft_free(draft);
    if (target_commit) git_commit_free(target_commit);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * The 1-3 raw positionals read by the forms into `profile`, `path` and `commit`
 *
 * By position, each slot's word read as a refspec where it can carry a profile
 * or a commit of its own (base/refspec.h refspec_parse), and the shape rule where
 * a slot could hold a profile or a path — a word that announces a path is one
 * (infra/path.h path_input_announces_path), any other is a profile, as list reads
 * its first word:
 *
 *   typed               profile                path                  commit
 *   p@C, p C            p                      none: the whole one   C
 *   p:X@C, p:X C        p                      X                     C
 *   X@C, X C            found, or -p's         X                     C
 *   p X, p X@C          p, X's own over it     X                     C
 *   p X C               p                      X                     C
 *
 * where X announces a path and p does not. The first word is read alone, or beside
 * a second that has a commit's shape (refspec_looks_like_commit); under -p it
 * is the path's whatever its shape (cmds/list.c list_post_parse), so `-p q w@C`
 * reads the path w, which the resolver refuses as a bare word. Two words whose
 * second has no commit's shape are a profile and a path, the first word's profile
 * over -p's — by position. The three-word form takes its commit by position, so
 * a tag or a branch reaches revert there alone, and a whole profile never at
 * one (stated): `p C` reads its commit by its shape, and `p@v1.0` is one word,
 * the profile p@v1.0 that no branch is. A profile whose own name announces a
 * path — one named under a label's word — has no whole-profile form (stated). A
 * commit inside the first word beside a commit-shaped second is a commit given
 * twice; none at all is refused, and so is `p:@C`, a refspec that names no path.
 *
 * Allocation model: refspec substrings are arena-allocated; pure positional
 * pointers borrow argv. cmd_revert does not free any of these pointers — the
 * engine's arena owns their lifetime.
 */
static error_t revert_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) cmd;
    cmd_revert_options_t *o = opts_v;
    char **args = o->positional_args;

    if (o->positional_count == 0) {
        return error_create(ERR_INVALID_ARG, "A path or a profile is required");
    }

    if (o->positional_count == 3) {
        /* <profile> <path> <commit>, each by position */
        o->profile = args[0];
        o->path = args[1];
        o->commit = args[2];
    } else if (o->positional_count == 2 && !refspec_looks_like_commit(args[1])) {
        /* <profile> <path>[@commit]: the first word the profile, over -p, and
         * the second's own over it */
        refspec_t rs = { 0 };
        error_t err = refspec_parse(arena, args[1], &rs);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse file specification");
        }
        o->profile = rs.profile ? rs.profile : args[0];
        o->path = rs.file;
        if (rs.commit != NULL) o->commit = rs.commit;
    } else {
        /* The first word, alone or beside its commit: its own profile, over -p;
         * else, under -p, the path; else a path where it announces one and the
         * whole profile it names where it does not */
        refspec_t rs = { 0 };
        error_t err = refspec_parse(arena, args[0], &rs);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse file specification");
        }

        if (o->positional_count == 2 && rs.commit != NULL) {
            return error_create(
                ERR_INVALID_ARG, "Commit given twice: '%s' and '%s'", rs.commit, args[1]
            );
        }
        o->commit = o->positional_count == 2 ? args[1] : rs.commit;

        if (rs.profile != NULL) {
            o->profile = rs.profile;
            o->path = rs.file;
        } else if (o->profile != NULL || path_input_announces_path(rs.file)) {
            o->path = rs.file;
        } else {
            o->profile = rs.file;
        }
    }

    if (o->commit == NULL) {
        return error_create(ERR_INVALID_ARG, "Commit reference is required");
    }
    return NULL;
}

/**
 * The one profile revert's own search finds holding the path a word names, for
 * the commit slot after it, where the line names no profile for it
 *
 * The word read as the forms read it: a refspec naming no profile of its own,
 * whose path announces itself (revert_post_parse), then resolved and searched
 * as the command searches it (revert_select_profile, its refusal dropped). NULL
 * for a word that names its own profile or no path, or that will not read; for
 * a path several profiles hold, or none; and for a search that fails — the
 * completion's caller then keeps its rules for a profile it does not know.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param word The word naming the path (must not be NULL)
 * @return The holder, or NULL
 */
static const char *revert_holder(const dotta_ctx_t *ctx, const char *word) {
    if (ctx->run.repo == NULL || ctx->run.mounts == NULL) return NULL;

    refspec_t rs = { 0 };
    if (refspec_parse(ctx->arena, word, &rs) != NULL || rs.profile != NULL ||
        !path_input_announces_path(rs.file)) {
        return NULL;
    }

    path_input_t arg;
    const char *holder = NULL;
    if (path_input_resolve(rs.file, ctx->arena, &arg) != NULL ||
        revert_select_profile(ctx, &arg, &holder) != NULL) {
        return NULL;
    }
    return holder;
}

/**
 * What can stand at the cursor, by the shapes revert_post_parse reads — as show,
 * without the bare-commit form: first a file of any profile as `profile:path`,
 * bare once -p pins one. After one positional, a word naming a profile and a
 * path — `profile:path`, or a path once -p pins one, or a path the one profile
 * holding it pins (revert_holder) — is followed by its commit, the path's own
 * changes (completion_path_history); any other word by the files of the profile
 * it may name or that profile's history, the grammar deciding by the next token,
 * a path several profiles hold or none by the enabled histories. After two, the
 * commit: the second word's own changes in the profile the first names. An `@`
 * in the token being typed completes its commit part, its profile the token's
 * own, the line's, or the one holding the path its part before the `@` names
 * (completion_commits_at).
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

    /* The profile the line names before the cursor: -p's, else the first word's;
     * else, for an `@` in the token being typed, the one holding the path its
     * part before the `@` names (revert_holder) */
    const char *pinned = o->profile;
    if (pinned == NULL && o->positional_count >= 1) {
        pinned = completion_profile_of(ctx, o->positional_args[0]);
    }
    const char *commit_at = strrchr(at->current, '@');
    if (pinned == NULL && commit_at != NULL) {
        pinned = revert_holder(
            ctx, arena_strndup(ctx->arena, at->current, (size_t) (commit_at - at->current))
        );
    }
    if (completion_commits_at(ctx, out, at->current, pinned)) {
        return ARGS_WANT_NONE;
    }

    if (o->positional_count == 0) {
        completion_refspecs(ctx, out, pinned);
    } else if (o->positional_count == 1) {
        /* The path's own profile: -p's, else the one holding it, where it names
         * none of its own (completion_path_history reads a word's own first) */
        const char *word = o->positional_args[0];
        const char *holder = o->profile ? o->profile : revert_holder(ctx, word);
        if (!completion_path_history(ctx, out, holder, word)) {
            completion_refspecs(ctx, out, pinned);
            completion_history(ctx, out, pinned);
        }
    } else if (o->positional_count == 2) {
        completion_path_history(ctx, out, pinned, o->positional_args[1]);
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
        "The profile to revert in (default: the one holding the path)"
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
        "Preview without committing"
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
    .summary     = "Revert a path or a profile to a past commit",
    .usage       =
        "%s revert [options] <path>@<commit>\n"
        "   or: %s revert [options] <path> <commit>\n"
        "   or: %s revert [options] <profile>:<path>@<commit>\n"
        "   or: %s revert [options] <profile> <path> <commit>\n"
        "   or: %s revert [options] <profile>@<commit>\n"
        "   or: %s revert [options] <profile> <commit>",
    .description =
        "Restore a file, a directory or a whole profile to its state at a past\n"
        "commit, in one commit on its profile: what the commit held comes back,\n"
        "and what it did not hold is removed. Every machine's next '%s apply'\n"
        "brings its files in line, deleting the unchanged copies of removed files.\n",
    .notes       =
        "Execution Order:\n"
        "  1. Find the profile holding the path, where none is named.\n"
        "  2. Show the preview: a file's diff, or what the revert adds, updates\n"
        "     and deletes. Off a terminal, a revert that owes a confirmation is\n"
        "     refused before it (--force owes none).\n"
        "  3. Run the pre-revert hook. A dry run stops here.\n"
        "  4. Prompt for confirmation (bypassed by --force).\n"
        "  5. Create one commit, then run the post-revert hook.\n",
    .examples    =
        "  %s revert ~/.bashrc@HEAD~3                # A file, its profile found\n"
        "  %s revert ./src/config@a4f2c8e            # A path beneath this directory\n"
        "  %s revert darwin:~/.config/nvim@HEAD~1    # A directory, in profile darwin\n"
        "  %s revert darwin ~/.config/nvim v1.0      # The commit by tag\n"
        "  %s revert -n darwin a4f2c8e               # Preview a whole profile's revert\n"
        "  %s revert darwin@a4f2c8e                  # The whole profile\n",
    .epilogue    =
        "See also:\n"
        "  %s list <profile> <path>   # Find a path's commits\n"
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
