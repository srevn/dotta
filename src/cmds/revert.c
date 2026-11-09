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
#include "base/secure.h"
#include "base/string.h"
#include "base/timeutil.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/commit.h"
#include "infra/content.h"
#include "infra/input.h"
#include "infra/mount.h"
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
    const dotta_ctx_t *ctx, const input_path_t *arg, const char **out_profile
) {
    CHECK_NULL(ctx);
    CHECK_NULL(arg);
    CHECK_NULL(out_profile);

    git_repository *repo = ctx->run.repo;

    *out_profile = NULL;

    /* The argument as the shell spells it, a name as typed (base/output.h
     * output_format_path), as the revert says it: every refusal below names it
     * so */
    char spelled[PATH_MAX];
    const char *subject = NULL;
    if (arg->key == INPUT_KEY_FILESYSTEM) {
        output_format_path(arg->filesystem_path, identity()->home, spelled, sizeof(spelled));
        subject = spelled;
    } else {
        subject = arg->storage_path;
    }

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
        if (arg->key == INPUT_KEY_FILESYSTEM) {
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
 * One write of a restore: a claim the commit's view stands where the argument
 * reaches, and the name the draft writes it at
 */
typedef struct {
    const char *storage_path;       /* The name written: the head's at its place, else its own */
    const profile_claim_t *claim;   /* The commit's claim, whole: lent by the commit's profile */
} revert_write_t;

/**
 * A restore as it selects (revert_restore_path): the draft it edits, the two
 * sides it reads, the path both are selected by, and the writes chosen so far
 *
 * Readers: revert_restore_path, which makes it, and the statics it calls —
 * revert_reaches, revert_select_claim and revert_take_claim.
 */
typedef struct {
    profile_draft_t *draft;          /* The profile's next commit: every removal's */
    profile_t *from;                 /* The profile at the commit: every claim written */
    manifest_t *head;                /* The head's view: the name each write takes */
    const mount_table_t *mounts;     /* This machine's table: where each claim stands */
    const char *profile;             /* The profile's name: the views' asker, each claim's placer */
    input_key_t key;                 /* What a claim is selected by: where it stands, or its name */
    const char *path;                /* The place the argument reaches, or a name placed nowhere */
    size_t path_len;                 /* strlen(path), asked once */
    ptr_array_t writes;              /* Each write chosen (revert_write_t), in the view's order */
    hashmap_t *written;              /* The name each write takes → the write */
    size_t found;                    /* The claims selected on either side, each once */
    arena_t *frame;                  /* The call's own: the views, the places, the writes */
} revert_restore_t;

/**
 * Whether the argument reaches a claim, asked in the key of the path it reaches:
 * where the claim stands — nowhere, where this machine places it nowhere — or
 * its name
 *
 * The one selection both sides are asked (revert_select_claim, revert_take_claim),
 * so the commit's claims and the head's cannot part over what the argument reaches.
 * Both views are one profile's under one table, so the two keys never cross: no
 * claim this machine places has a name beneath a name it places nowhere.
 *
 * @param r The restore
 * @param filesystem_path Where the claim stands, or NULL where it stands nowhere
 * @param storage_path Its name
 * @return Whether the claim lies at or beneath the path the argument reaches
 */
static bool revert_reaches(
    const revert_restore_t *r, const char *filesystem_path, const char *storage_path
) {
    const char *key = r->key == INPUT_KEY_FILESYSTEM ? filesystem_path : storage_path;

    return key && str_path_under(key, r->path, r->path_len);
}

/**
 * One of the commit's claims, chosen where the argument reaches it: the claim
 * whole, and the name the draft writes it at
 *
 * The claim as the commit's walk decodes it (core/profiles.h profile_find): the
 * view's row is the claim placed, its mode a floor where the commit claimed none
 * (core/manifest.h manifest_row_t, "Totality"), and a restore writes what the
 * commit claimed. Its name the one the head gives its place — the head's claim
 * there, explicit else derived (core/manifest.h manifest_lookup_claim) — else
 * its own; a claim placed nowhere has no place to ask, and keeps its own. No
 * two writes take one name: a name places at one path, and one row stands at a
 * path.
 *
 * @param r The restore
 * @param filesystem_path Where the commit's view stands the claim, or NULL where
 *        it stands nowhere
 * @param storage_path The commit's name for it
 * @param kind Its kind
 * @return Error or NULL on success: the claim's, in the profile's words
 */
static error_t revert_select_claim(
    revert_restore_t *r,
    const char *filesystem_path,
    const char *storage_path,
    path_kind_t kind
) {
    if (!revert_reaches(r, filesystem_path, storage_path)) return NULL;

    const profile_claim_t *claim = NULL;
    error_t err = profile_find(r->from, PROFILE_READ_STRICT, kind, storage_path, &claim);
    if (err) return err;

    const manifest_row_t *held = filesystem_path
        ? manifest_lookup_claim(r->head, r->profile, filesystem_path)
        : NULL;

    /* Each write allocated alone, so the index holds it where the list's spine
     * moves (core/manifest.c's rows, the same idiom); counted where its claim
     * is one, a derivation being the way to the claims */
    revert_write_t *w = arena_alloc(r->frame, sizeof(*w));
    *w = (revert_write_t){
        .storage_path = held ? held->storage_path : claim->storage_path,
        .claim = claim,
    };
    ptr_array_push(&r->writes, w);
    hashmap_add(r->written, w->storage_path, w);
    if (claim->type != PATH_TYPE_DIRECTORY || claim->tracked) r->found++;

    return NULL;
}

/**
 * One of the head's claims, taken from the draft where the argument reaches it
 * and no write takes its name in its kind
 *
 * The visitor of the walk over the draft's base and of its contradicted claims:
 * between the two, every claim the head holds, standing or not, once
 * (core/profiles.h profile_walk, profile_contradicted), each placed where this
 * machine puts it, as the head's view placed it. The walk reads the base and
 * the removal edits the draft — its stage, and the sheet its commit carries,
 * neither of which the base holds or reads (core/profiles.h profile_draft_t) —
 * so a claim taken moves nothing the walk has yet to show.
 *
 * @param claim One of the head's claims, decoded (borrowed for the call)
 * @param payload The restore (revert_restore_t)
 * @return Error or NULL on success: the removal's, in the draft's words
 */
static error_t revert_take_claim(const profile_claim_t *claim, void *payload) {
    revert_restore_t *r = payload;

    /* A derivation is the way to the claims beneath it, and no writer's to take:
     * the commit's prune takes one nothing stands beneath any longer */
    if (claim->type == PATH_TYPE_DIRECTORY && !claim->tracked) return NULL;

    /* Where the argument reaches it, and no write takes its name in its kind: a
     * write of the other kind at its name takes the place this removal leaves */
    const char *filesystem_path = mount_resolve(
        r->frame, r->mounts, r->profile, claim->storage_path
    );
    if (!revert_reaches(r, filesystem_path, claim->storage_path)) return NULL;

    const path_kind_t kind = path_type_kind(claim->type);
    const revert_write_t *w = hashmap_get(r->written, claim->storage_path);
    if (w && path_type_kind(w->claim->type) == kind) return NULL;

    r->found++;
    return profile_remove(r->draft, kind, claim->storage_path);
}

/**
 * The profile's claims at and beneath `arg`, made the commit's on its draft
 *
 * One rule for a file, a directory and every place the table puts claims beneath:
 * what the commit's view stands there comes back, and what the head holds there
 * that no restore writes goes. Read through two views of the one profile — at
 * the draft's base, and at the commit — placed by this machine's table, so one
 * path keys both; written through the draft's verbs (core/profiles.h), so every
 * rule of a restored claim is the draft's, and every rule of an entry the stage's.
 * A whole profile is no path: its commit is the commit's own tree, no claim
 * selected, its sheet the save's (core/profiles.h profile_restore_tree).
 *
 * The argument reaches a place, or a name. A path, and a name this machine places,
 * reach every claim either side places at or beneath that place, whichever label
 * names it; a name this machine places nowhere — a custom/ name with no target
 * here — reaches every claim either side holds at or beneath that name. Of those:
 *   - the commit's, as its view stands them (core/manifest.h
 *     manifest_build_profile), one a place, the view standing one row a path,
 *     each restored whole by the draft's verb of its kind (core/profiles.h
 *     profile_restore_file, profile_restore_directory) — a derived one with its
 *     attributes, as the commit had them — under the name the head gives its
 *     place, its claim there, explicit else derived (manifest_lookup_claim),
 *     else under its own: a name is where a claim lands on every machine, and
 *     the profile's stays. A claim the commit held that stood nowhere in its
 *     view — a second name for one path, a claim its own claims contradict — is
 *     not restored; one placed nowhere keeps its own name;
 *   - the head's, every claim it holds, standing or not (core/profiles.h
 *     profile_walk, profile_contradicted), each taken from the draft
 *     (profile_remove) where no restore writes its name in its kind. A derived
 *     one is the way to the claims beneath it, and no writer's to take: the
 *     commit's prune takes one nothing stands beneath any longer.
 * Every removal before any restore, so a restore of the other kind at a name
 * meets nothing in its way. All or nothing: any refusal — the draft's, the stage's,
 * a seal's that moves with no key — leaves a draft its writer abandons.
 *
 * A claim the head holds as the commit held it is written over and moves nothing
 * (sys/stage.h, an entry put as the index holds it; core/metadata.h
 * metadata_write_item), and still pays its restore's reads: its blob, for the
 * stamp, and a tree lookup a rung of its way. The head's claims are placed again,
 * as its view placed them (infra/mount.h mount_resolve): a second walk of the
 * profile, beside the two views' builds.
 *
 * What moved is the draft's to say (profile_changed, profile_changes); the one
 * thing no draft holds is how many claims the argument reaches.
 *
 * Reader: cmd_revert, a revert at a path: it refuses an argument that reaches
 * no claim, and says one file's restore whole where the argument reaches one,
 * the commit's file at its own place.
 *
 * @param ctx Dispatch context: this machine's table, which places both sides,
 *            and the key manager, for a sealed claim restored under another name
 *            (must not be NULL; with no key manager such a restore is refused,
 *            ERR_LOCKED)
 * @param draft The profile's next commit, opened at its head (must not be NULL)
 * @param arg The argument, in the key it named (must not be NULL)
 * @param place Where the argument stands on this machine: the path itself, or
 *              the place this machine puts the name at; NULL for a name placed
 *              nowhere, which reaches by name (cmd_revert)
 * @param from The profile at the commit's tree (must not be NULL; its sheet read
 *             strictly)
 * @param out_found The claims the argument reaches, the commit's and the head's,
 *                  a claim both hold counted once and a derivation, a way, none
 *                  (must not be NULL; 0 after an error)
 * @return Error or NULL on success
 */
static error_t revert_restore_path(
    const dotta_ctx_t *ctx, profile_draft_t *draft, const input_path_t *arg,
    const char *place, profile_t *from, size_t *out_found
) {
    CHECK_NULL(ctx);
    CHECK_NULL(draft);
    CHECK_NULL(arg);
    CHECK_NULL(from);
    CHECK_NULL(out_found);

    *out_found = 0;

    /* Everything the selection spells — the two views, each claim's place, the
     * writes and their index — in a frame of the call's own, its answer no memory:
     * the draft copies what it keeps of a name (include/runtime.h, "Memory") */
    profile_t *base = profile_draft_base(draft);
    arena_t *frame = arena_create(0);

    /* The path every claim is asked to lie at or beneath: the place the argument
     * reaches, so every claim standing there is reached whichever label names
     * it — else, a name placed nowhere, the name itself, its claims standing
     * nowhere for a place to reach */
    const char *path = place ? place : arg->storage_path;

    revert_restore_t r = {
        .draft    = draft,
        .from     = from,
        .mounts   = ctx->run.mounts,
        .profile  = profile_name(base),
        .key      = place ? INPUT_KEY_FILESYSTEM : INPUT_KEY_STORAGE,
        .path     = path,
        .path_len = strlen(path),
        .frame    = frame,
    };
    ptr_array_init(&r.writes, frame, 0);
    r.written = hashmap_borrow(frame, 0);

    /* The two views, each one profile's under this machine's table: the head's,
     * which names each write, and the historical, the profile at the commit's
     * tree, which stands the claims written */
    manifest_t *historical = NULL;
    error_t err = manifest_build_profile(base, ctx->run.mounts, frame, &r.head);
    if (!err) err = manifest_build_profile(from, ctx->run.mounts, frame, &historical);

    /* The commit's claims the argument reaches, as its view stands them, in its
     * view's order: each this machine places — the layer's rung being no claim
     * of the profile's — then each it places nowhere (revert_select_claim) */
    const manifest_rows_t rows = manifest_rows(historical);
    for (size_t i = 0; !err && i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];
        if (!manifest_holds_row(historical, row)) continue;

        err = revert_select_claim(
            &r, row->filesystem_path, row->storage_path, path_type_kind(row->type)
        );
    }
    const manifest_unbound_t unbound = manifest_unbound(historical);
    for (size_t i = 0; !err && i < unbound.count; i++) {
        err = revert_select_claim(
            &r, NULL, unbound.entries[i].storage_path, unbound.entries[i].kind
        );
    }

    /* The head's claims the argument reaches that no write takes — every claim
     * it holds, standing or not: the walk's, then those its own tree contradicts
     * — taken before any write, so a write of the other kind at a name meets
     * nothing in its way (revert_take_claim) */
    if (!err) err = profile_walk(base, PROFILE_READ_STRICT, revert_take_claim, &r);
    if (!err) err = profile_contradicted(base, PROFILE_READ_STRICT, revert_take_claim, &r);

    /* Then each write, by the draft's verb of its claim's kind: the claim whole
     * at its name, and the way the commit stood it on */
    for (size_t i = 0; !err && i < r.writes.count; i++) {
        const revert_write_t *w = r.writes.entries[i];
        err = w->claim->type == PATH_TYPE_DIRECTORY
            ? profile_restore_directory(draft, w->storage_path, w->claim, from)
            : profile_restore_file(draft, w->storage_path, w->claim, from, ctx->run.keymgr);
    }

    if (!err) *out_found = r.found;
    arena_free(frame);

    return err;
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
 * The commit's side is its row's blob, the object the commit holds and never
 * the id a reseal would take: that one names no object yet, and nothing here
 * would open under it.
 *
 * The two blobs' ids differ: the caller reaches this only from the preview arm
 * that says so, and the arm beside it is what a copy with the same blob and a
 * different mode gets. Two ids can still hold one plaintext — a seal made or
 * opened in place, or made again under the name the head holds — and the patch,
 * made from the plaintexts, says so where the ids cannot: its delta unmodified,
 * the preview says the sentence that arm says.
 *
 * The name is the one the revert writes the file at, and the head's entry is
 * read there (cmd_revert): wherever there is a blob to diff against, the head
 * held that name, the one the restore writes over (revert_restore_path), so the
 * write's name is the head's binding and one string labels both sides.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param profile Profile name, for key derivation (must not be NULL)
 * @param storage_path The name the revert writes the file at: the head's binding,
 *                     and the label on both sides (must not be NULL)
 * @param held The head's entry there, a blob (must not be NULL)
 * @param target The commit's row at the file's place: its binding, how its bytes
 *               open, and its blob (must not be NULL)
 * @return Error or NULL on success
 */
static error_t revert_print_diff(
    const dotta_ctx_t *ctx,
    const char *profile,
    const char *storage_path,
    const profile_held_t *held,
    const manifest_row_t *target
) {
    CHECK_NULL(ctx);
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(held);
    CHECK_NULL(target);

    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr; /* NULL if encryption disabled */
    output_t *out = ctx->out;

    /* Get decrypted plaintext content from both blobs.
     *
     * Each call classifies its own blob's bytes, as the entry it stands in —
     * the routing decision lives with the blob, so encryption-state changes between
     * commits are handled by the content layer with no caller participation. */
    buffer_t head_plaintext = BUFFER_INIT;
    buffer_t target_plaintext = BUFFER_INIT;
    git_patch *patch = NULL;
    error_t err = content_get_from_blob_oid(
        repo, &held->oid, held->filemode, storage_path, profile, keymgr,
        &head_plaintext
    );
    if (err) {
        err = error_wrap(err, "Failed to get current file content");
        goto cleanup;
    }

    err = content_get_from_blob_oid(
        repo, &target->blob_oid, gitops_type_filemode(target->type),
        target->storage_path, profile, keymgr, &target_plaintext
    );
    if (err) {
        err = error_wrap(err, "Failed to get target file content");
        goto cleanup;
    }

    /* Create patch directly from plaintext buffers using in-memory API
     *
     * This uses libgit2's buffer-based patch API to avoid creating temporary
     * blobs in the Git ODB that would persist until gc.
     */
    int rc = git_patch_from_buffers(
        &patch,
        head_plaintext.data, head_plaintext.size, storage_path,
        target_plaintext.data, target_plaintext.size, storage_path,
        NULL  /* options */
    );
    if (rc < 0) {
        err = error_git(
            rc, "Cannot compare the two versions of '%s'",
            storage_path
        );
        goto cleanup;
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

cleanup:
    git_patch_free(patch);

    /* The two plaintexts — a sealed file's decrypted bytes — wiped before they
     * are freed, on every exit and whatever the reads left (base/buffer.h: on a
     * failure the caller owns what the callee left), as the comparison wipes
     * its copy (infra/compare.c); secure_wipe answers a NULL pointer and a zero
     * length itself, so the tail is total without a guard */
    secure_wipe(head_plaintext.data, head_plaintext.size);
    buffer_deinit(&head_plaintext);
    secure_wipe(target_plaintext.data, target_plaintext.size);
    buffer_deinit(&target_plaintext);

    return err;
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
 * directory's attributes — and says so in the message's own line, tensed for a
 * preview.
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
        if (!revert_reclaims(records, record_count, profile, restored.entries[i])) {
            continue;
        }

        err = state_retire(state, restored.entries[i]);
        if (err) goto cleanup;
    }

    /* A place only removals reached: this profile's record retires where no row
     * stands there after the commit, the view it leaves built at the first such
     * record and read for each */
    manifest_t *after = NULL;
    for (size_t i = 0; i < removed.count; i++) {
        if (!revert_reclaims(records, record_count, profile, removed.entries[i])) {
            continue;
        }

        if (!after) {
            err = manifest_build(ctx->run.repo, state, NULL, ctx->arena, &after);
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

    /* The handles keep their column as a prefix — the commit reverted to and
     * the profile at it — beside the profile's draft at its head */
    error_t err = NULL;
    git_commit *target_commit = NULL;
    profile_draft_t *draft = NULL;
    profile_t *target_profile = NULL;

    /* The path, where one is given, in the key the user named — a path or a storage
     * path, neither manufactured from the other (infra/input.h) — and what the
     * revert is said of: what was typed, the argument as the shell spells it, a
     * name as typed (base/output.h output_format_path), every sentence below
     * naming it so; with no path, the profile whole. */
    input_path_t arg = { 0 };
    char spelled[PATH_MAX];
    const char *subject = NULL;
    if (opts->path) {
        err = input_resolve(opts->path, ctx->arena, &arg);
        if (err) goto cleanup;

        if (arg.key == INPUT_KEY_FILESYSTEM) {
            output_format_path(arg.filesystem_path, identity()->home, spelled, sizeof(spelled));
            subject = spelled;
        } else {
            subject = arg.storage_path;
        }
    }

    /* The profile the revert acts on: the one named — a refspec's, -p's, a whole
     * profile's own word — required to be here, and never asked what its head
     * holds, a path it deleted being the case a revert exists for; else the one
     * local profile holding the path (revert_select_profile). A summary says
     * the revert is of the argument in it, or of it whole, in one phrase; a refusal
     * quotes the argument alone, a datum (base/error.h). */
    const char *profile = opts->profile;
    err = profile ? profile_require(repo, profile) : revert_select_profile(ctx, &arg, &profile);
    if (err) goto cleanup;

    const char *phrase = subject
        ? arena_str_format(ctx->arena, "%s in profile '%s'", subject, profile)
        : arena_str_format(ctx->arena, "profile '%s'", profile);

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
     * the loader's words naming the head, as every writer refuses it. */
    err = profile_draft_open(repo, profile, &draft);
    if (err) goto cleanup;

    /* The profile at the commit, opened once and lent to everything below that
     * reads the commit — its claims at a path, the way a restore brings back,
     * the whole tree — so every failure of it names the commit, whichever read
     * meets it first (core/profiles.h profile_open): a tree that will not read
     * refused here, and a sheet that will not load by the first read of it,
     * strictly, before the preview. A corrupt source sheet would invent attributes
     * while claiming to restore them. A commit without a sheet loads as an empty
     * one (the tree loader's contract). */
    err = profile_open(profile, target_commit, &target_profile);
    if (err) goto cleanup;

    /* The revert, onto the draft, and nothing written to the repository: the
     * path's claims made the commit's — every claim the commit's view stands at
     * and beneath it, under the name the head holds its place by, and every claim
     * the head holds there that the commit did not, removed (revert_restore_path)
     * — or the commit's whole tree (core/profiles.h profile_restore_tree). Every
     * refusal comes here, before the preview promises anything: a stage collision,
     * a lost blob, a seal that moves to another name with no key. A reseal's
     * bytes wait in the stage until its commit, so a dry run, a refusing hook
     * or a declined question leaves the object database as it found it (sys/stage.h
     * stage_put_unwritten).
     *
     * The restore answers how many claims the path reaches at the head and at
     * the commit together. None is no revert to make — usually a typo — and refused
     * as an absence on both sides, naming what was typed: "nothing to revert"
     * is the change test's, for a path a side holds. */
    const char *place = NULL;
    size_t found = 0;
    if (opts->path) {
        /* Where the path stands on this machine, said once for the restore and
         * for the one-file preview below: a path is its own place, and a name
         * the place this machine puts it at — none for a name it places nowhere,
         * which the restore reaches by name */
        place = arg.key == INPUT_KEY_FILESYSTEM
            ? arg.filesystem_path
            : mount_resolve(ctx->arena, mounts, profile, arg.storage_path);

        err = revert_restore_path(ctx, draft, &arg, place, target_profile, &found);
        if (!err && found == 0) {
            err = error_create(
                ERR_NOT_FOUND, "'%s' not found in profile '%s', at its head or at commit %s",
                subject, profile, oid_str
            );
        }
    } else {
        err = profile_restore_tree(draft, target_profile);
    }
    if (err) goto cleanup;

    /* Nothing to do: the revert moved neither the tree nor the sheet, each held
     * against the one the draft opened (core/profiles.h profile_changed) — every
     * claim the path reaches held alike, the way to them too, or the commit's
     * tree the head's own, its sheet held by its claims. Said as every command
     * says it has nothing to do, naming what the revert is said of, its profile
     * and the commit. */
    bool changed = false;
    err = profile_changed(draft, &changed);
    if (err) goto cleanup;
    if (!changed) {
        output_summary(
            out, OUTPUT_NORMAL, "Nothing to revert: %s is already as at commit %s",
            phrase, oid_str
        );
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
     * profile_changes): the preview's sections and the name it shows one file
     * at, the paths the hooks are handed, the places the record phase reads —
     * the commit's own answer, asked before it, its prune and its save moving
     * no name the lists hold. */
    commit_changes_t changes;
    err = profile_changes(draft, ctx->arena, &changes);
    if (err) goto cleanup;

    /* One file's restore is said whole where the path reaches one claim — the
     * commit's file, standing at the argument's own place — and the commit's
     * one change is that file's restore: a name it adds or updates that the table
     * places at the argument's own place, as the record phase reads a place a
     * claim was restored at (revert_write_record). The restore writes one claim
     * a place, under the head's name for it or else its own (revert_restore_path),
     * and a name places at one path (infra/mount.h mount_resolve), so the name
     * moved there is that write, read off the commit and never named again here;
     * a change the table places anywhere else lists the changes. The commit's
     * claim is read off its one-profile view, built again (stated), the layer's
     * rung being no claim of the profile's, and the head's entry off its tree
     * at the name (core/profiles.h profile_entry). A name this machine places
     * nowhere has no place, and lists its changes. */
    const manifest_row_t *target = NULL;
    profile_held_t held = { .kind = PROFILE_HELD_NOTHING };
    const char *file = NULL;
    if (found == 1 && changes.added.count + changes.updated.count == 1) {
        const char *name = changes.added.count > 0
            ? changes.added.entries[0]
            : changes.updated.entries[0];

        manifest_t *historical = NULL;
        if (place && str_equal(place, mount_resolve(ctx->arena, mounts, profile, name))) {
            err = manifest_build_profile(target_profile, mounts, ctx->arena, &historical);
            if (err) goto cleanup;
        }

        const manifest_row_t *row = manifest_lookup(historical, place);
        if (manifest_holds_row(historical, row) && row->type != PATH_TYPE_DIRECTORY) {
            target = row;
            file = name;

            err = profile_entry(profile_draft_base(draft), file, &held);
            if (err) goto cleanup;
        }
    }

    /* The preview (always, a dry run's too): the header — the profile, the file
     * the body shows whole or else what was typed, the commit and, where the
     * file's name moved since, the name the commit held its bytes under — then
     * the body */
    output_section(out, OUTPUT_NORMAL, "Revert preview");

    /* A name is cyan and everything else is not — the profile's, the file's and,
     * where there are two, the commit's — which is how a name is marked wherever
     * one is printed beside other words (cmds/list.c's history header prints
     * two in one line). The commit line is an oid and a time and carries none. */
    output_print(out, OUTPUT_NORMAL, "  Profile: {cyan}%s{reset}\n", profile);
    if (file) {
        output_print(out, OUTPUT_NORMAL, "  File: {cyan}%s{reset}\n", file);
    } else if (subject) {
        output_print(out, OUTPUT_NORMAL, "  Path: {cyan}%s{reset}\n", subject);
    }

    /* The commit, and its date as Git prints it where a local time places the
     * author's (base/timeutil.h timeutil_absolute) */
    const git_signature *author = git_commit_author(target_commit);
    time_t commit_time = (time_t) author->when.time;

    char time_buf[64];
    if (timeutil_absolute(commit_time, time_buf, sizeof(time_buf))) {
        output_print(out, OUTPUT_NORMAL, "  Target commit: %s (%s)\n", oid_str, time_buf);
    } else {
        output_print(out, OUTPUT_NORMAL, "  Target commit: %s\n", oid_str);
    }

    if (file && strcmp(target->storage_path, file) != 0) {
        output_print(
            out, OUTPUT_NORMAL, "  Named at the commit: {cyan}%s{reset}\n",
            target->storage_path
        );
    }

    /* The body. One file's restore is said whole by the three ways a file differs
     * from what the head holds at its name: it comes back, everything but its
     * bytes moves — the one thing no diff can show — or its bytes do. The middle
     * arm is *the blob is the same and the change test said something differs*,
     * and what is left to differ is the entry's filemode and the claim beside
     * it, so the sentence names those. Its proof is the ids, which needs no byte
     * read, so a cold key keeps the preview; two ids that hold one plaintext
     * are its twin, which only a read can prove, and revert_print_diff says the
     * same sentence off the two plaintexts — among them a seal the restore made
     * again under the name the head holds it by, since the id compared is the
     * commit's own blob, never the one a reseal's bytes will be written as.
     *
     * Every other revert — a directory, a file it removes, a file beside another
     * claim the path reaches, a claim the head holds at the file's own name among
     * them, a whole profile, a name placed nowhere — lists what its commit changes,
     * in the commit's words (revert_print_changes). */
    if (file) {
        if (held.kind != PROFILE_HELD_FILE) {
            output_gap(out, OUTPUT_NORMAL);
            output_print(out, OUTPUT_NORMAL, "{green}Restoring a deleted file{reset}\n");
        } else if (git_oid_equal(&held.oid, &target->blob_oid)) {
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
            err = revert_print_diff(ctx, profile, file, &held, target);
            if (err) {
                output_gap(out, OUTPUT_NORMAL);
                output_warning(
                    out, OUTPUT_NORMAL, "Could not show diff preview: %s", error_line(err)
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
        output_summary(
            out, OUTPUT_NORMAL, "Nothing to revert: %s is already as at commit %s",
            phrase, oid_str
        );
        goto cleanup;
    }

    /* The receipt, once the commit lands and before the record phase, which may
     * wait on the store's lock (core/state.h state_begin). A block of its own,
     * beneath the preview, the question or the trace. A profile this machine
     * has not enabled is said on its line: the commit restored content no apply
     * here deploys, as add says of a capture into one (cmds/add.c cmd_add). */
    output_success(
        out, OUTPUT_NORMAL, "Reverted %s to commit %s%s", phrase, oid_str,
        state_enabled(state, profile) ? "" : " (not enabled here)"
    );

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
 * One reading, left to right, each word that can carry a profile or a commit of
 * its own read as a refspec (infra/input.h input_refspec). The first word is
 * the path's where it names its own profile, under -p whatever its shape, or
 * where it announces a path (infra/input.h input_announces_path), and the profile's
 * otherwise — the shape rule, as list reads its first word, and -p making it
 * the path's slot (cmds/list.c list_post_parse), so `-p q w@C` reads the path
 * w, which the resolver refuses as a bare word. A profile's word names the profile
 * whole where it holds its commit, stands alone, or stands beside a second and
 * last word with a commit's shape (refspec_looks_like_commit); else the next
 * word is the path's, its own profile over the first. Every word left is the
 * commit, by position — a tag or a branch among them — and one past a commit
 * already read is a commit given twice:
 *
 *   typed               profile                path                  commit
 *   p@C, p C            p                      none: the whole one   C
 *   p:X@C, p:X C        p                      X                     C
 *   X@C, X C            found, or -p's         X                     C
 *   p X@C, p X C        p, X's own over it     X                     C
 *
 * where X announces a path, or follows -p, and p does not. A whole profile is
 * never at a tag (stated): `p C` reads its second word's shape to tell a commit
 * from a path, and `p@v1.0` is one word, the profile p@v1.0 that no branch is.
 * A profile whose own name announces a path — one named under a label's word —
 * has no whole-profile form and no profile:path form, -p naming it (stated). No
 * commit at all is refused, and so is `p:@C`, a refspec that names no path.
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
    const size_t count = o->positional_count;

    if (count == 0) {
        return error_create(ERR_INVALID_ARG, "A path or a profile is required");
    }

    size_t next = 0;
    input_refspec_t rs;
    error_t err = input_refspec(args[next++], arena, &rs);
    if (err != NULL) {
        return error_wrap(err, "Failed to parse file specification");
    }

    if (rs.profile != NULL || o->profile != NULL || input_announces_path(rs.path)) {
        /* The path's word: its own profile, over -p's */
        if (rs.profile != NULL) o->profile = rs.profile;
        o->path = rs.path;
        o->commit = rs.commit;
    } else if (rs.commit != NULL || next == count ||
        (count == 2 && refspec_looks_like_commit(args[next]))) {
        /* The profile's word, naming it whole: its commit inside it, no word
         * beside it, or the one beside it with a commit's shape */
        o->profile = rs.path;
        o->commit = rs.commit;
    } else {
        /* The profile's word, then the path's: its own profile over the first */
        o->profile = rs.path;
        err = input_refspec(args[next++], arena, &rs);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse file specification");
        }
        if (rs.profile != NULL) o->profile = rs.profile;
        o->path = rs.path;
        o->commit = rs.commit;
    }

    /* Every word left is the commit, by position */
    for (; next < count; next++) {
        if (o->commit != NULL) {
            return error_create(
                ERR_INVALID_ARG, "Commit given twice: '%s' and '%s'", o->commit, args[next]
            );
        }
        o->commit = args[next];
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

    input_refspec_t rs;
    if (input_refspec(word, ctx->arena, &rs) != NULL || rs.profile != NULL ||
        !input_announces_path(rs.path)) {
        return NULL;
    }

    input_path_t arg;
    const char *holder = NULL;
    if (input_resolve(rs.path, ctx->arena, &arg) != NULL ||
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
