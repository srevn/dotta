/**
 * restore.c - A commit's claims at a path, restored onto a profile's draft
 */

#include "core/restore.h"

#include <string.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "infra/mount.h"

/**
 * One write of a restore: a claim the commit's view stands where the argument
 * reaches, and the name the draft writes it at
 */
typedef struct {
    const char *storage_path;       /* The name written: the head's at its place, else its own */
    const profile_claim_t *claim;   /* The commit's claim, whole: lent by the commit's profile */
} restore_write_t;

/**
 * A restore as it selects (restore_path): the draft it edits, the two sides it
 * reads, the subject both are selected by, and the writes chosen so far
 *
 * Readers: restore_path, which makes it, and the statics it calls —
 * restore_reaches, restore_select and restore_take.
 */
typedef struct {
    profile_draft_t *draft;          /* The profile's next commit: every removal's */
    profile_t *from;                 /* The profile at the commit: every claim written */
    manifest_t *head;                /* The head's view: the name each write takes */
    const mount_table_t *mounts;     /* This machine's table: where each claim stands */
    const char *profile;             /* The profile's name: the views' asker, each claim's placer */
    path_key_t key;                  /* What a claim is selected by: where it stands, or its name */
    const char *subject;             /* The place the argument reaches, or a name placed nowhere */
    size_t subject_len;              /* strlen(subject), asked once */
    ptr_array_t writes;              /* Each write chosen (restore_write_t), in the view's order */
    hashmap_t *written;              /* The name each write takes → the write */
    size_t found;                    /* The claims selected on either side, each once */
    arena_t *frame;                  /* The call's own: the views, the places, the writes */
} restore_t;

/**
 * Whether the argument reaches a claim, asked in the subject's key: where the
 * claim stands — nowhere, where this machine places it nowhere — or its name
 *
 * The one selection both sides are asked (restore_select, restore_take), so the
 * commit's claims and the head's cannot part over what the argument reaches.
 * Both views are one profile's under one table, so the two keys never cross: no
 * claim this machine places has a name beneath a name it places nowhere.
 *
 * @param r The restore
 * @param filesystem_path Where the claim stands, or NULL where it stands nowhere
 * @param storage_path Its name
 * @return Whether the claim lies at or beneath the subject
 */
static bool restore_reaches(
    const restore_t *r, const char *filesystem_path, const char *storage_path
) {
    const char *key = r->key == PATH_KEY_FILESYSTEM ? filesystem_path : storage_path;

    return key && str_path_under(key, r->subject, r->subject_len);
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
static error_t restore_select(
    restore_t *r, const char *filesystem_path, const char *storage_path, path_kind_t kind
) {
    if (!restore_reaches(r, filesystem_path, storage_path)) return NULL;

    const profile_claim_t *claim = NULL;
    error_t err = profile_find(r->from, PROFILE_READ_STRICT, kind, storage_path, &claim);
    if (err) return err;

    const manifest_row_t *held = filesystem_path
        ? manifest_lookup_claim(r->head, r->profile, filesystem_path)
        : NULL;

    /* Each write allocated alone, so the index holds it where the list's spine
     * moves (core/manifest.c's rows, the same idiom); counted where its claim
     * is one, a derivation being the way to the claims */
    restore_write_t *w = arena_alloc(r->frame, sizeof(*w));
    *w = (restore_write_t){
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
 * @param payload The restore (restore_t)
 * @return Error or NULL on success: the removal's, in the draft's words
 */
static error_t restore_take(const profile_claim_t *claim, void *payload) {
    restore_t *r = payload;

    /* A derivation is the way to the claims beneath it, and no writer's to take:
     * the commit's prune takes one nothing stands beneath any longer */
    if (claim->type == PATH_TYPE_DIRECTORY && !claim->tracked) return NULL;

    /* Where the argument reaches it, and no write takes its name in its kind: a
     * write of the other kind at its name takes the place this removal leaves */
    const char *filesystem_path = mount_resolve(
        r->frame, r->mounts, r->profile, claim->storage_path
    );
    if (!restore_reaches(r, filesystem_path, claim->storage_path)) return NULL;

    const path_kind_t kind = path_type_kind(claim->type);
    const restore_write_t *w = hashmap_get(r->written, claim->storage_path);
    if (w && path_type_kind(w->claim->type) == kind) return NULL;

    r->found++;
    return profile_remove(r->draft, kind, claim->storage_path);
}

error_t restore_path(
    profile_draft_t *draft,
    const mount_table_t *mounts,
    const path_input_t *arg,
    profile_t *from,
    keymgr *keymgr,
    size_t *out_found
) {
    CHECK_NULL(draft);
    CHECK_NULL(mounts);
    CHECK_NULL(arg);
    CHECK_NULL(from);
    CHECK_NULL(out_found);

    *out_found = 0;

    /* Everything the selection spells — the two views, each claim's place, the
     * writes and their index — in a frame of the call's own, its answer no memory:
     * the draft copies what it keeps of a name (include/runtime.h, "Memory") */
    profile_t *base = profile_draft_base(draft);
    const char *profile = profile_name(base);
    arena_t *frame = arena_create(0);

    /* The subject: the place the argument reaches — a path is one, and a name
     * the place this machine puts it at, so every claim standing there is reached
     * whichever label names it — else, a name placed nowhere, the name itself,
     * its claims standing nowhere for a place to reach */
    const char *place = arg->key == PATH_KEY_FILESYSTEM
        ? arg->filesystem_path
        : mount_resolve(frame, mounts, profile, arg->storage_path);
    const char *subject = place ? place : arg->storage_path;

    restore_t r = {
        .draft       = draft,
        .from        = from,
        .mounts      = mounts,
        .profile     = profile,
        .key         = place ? PATH_KEY_FILESYSTEM : PATH_KEY_STORAGE,
        .subject     = subject,
        .subject_len = strlen(subject),
        .frame       = frame,
    };
    ptr_array_init(&r.writes, frame, 0);
    r.written = hashmap_borrow(frame, 0);

    /* The two views, each one profile's under this machine's table: the head's,
     * which names each write, and the historical, the profile at the commit's
     * tree, which stands the claims written */
    manifest_t *historical = NULL;
    error_t err = manifest_build_profile(base, mounts, frame, &r.head);
    if (!err) err = manifest_build_profile(from, mounts, frame, &historical);

    /* The commit's claims the argument reaches, as its view stands them, in its
     * view's order: each this machine places — the layer's rung being no claim
     * of the profile's — then each it places nowhere (restore_select) */
    const manifest_rows_t rows = manifest_rows(historical);
    for (size_t i = 0; !err && i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];
        if (!manifest_holds_row(historical, row)) continue;

        err = restore_select(
            &r, row->filesystem_path, row->storage_path, path_type_kind(row->type)
        );
    }
    const manifest_unbound_t unbound = manifest_unbound(historical);
    for (size_t i = 0; !err && i < unbound.count; i++) {
        err = restore_select(&r, NULL, unbound.entries[i].storage_path, unbound.entries[i].kind);
    }

    /* The head's claims the argument reaches that no write takes — every claim
     * it holds, standing or not: the walk's, then those its own tree contradicts
     * — taken before any write, so a write of the other kind at a name meets
     * nothing in its way (restore_take) */
    if (!err) err = profile_walk(base, PROFILE_READ_STRICT, restore_take, &r);
    if (!err) err = profile_contradicted(base, PROFILE_READ_STRICT, restore_take, &r);

    /* Then each write, by the draft's verb of its claim's kind: the claim whole
     * at its name, and the way the commit stood it on */
    for (size_t i = 0; !err && i < r.writes.count; i++) {
        const restore_write_t *w = r.writes.entries[i];
        err = w->claim->type == PATH_TYPE_DIRECTORY
            ? profile_restore_directory(draft, w->storage_path, w->claim, from)
            : profile_restore_file(draft, w->storage_path, w->claim, from, keymgr);
    }

    if (!err) *out_found = r.found;
    arena_free(frame);

    return err;
}
