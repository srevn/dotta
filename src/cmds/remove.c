/**
 * remove.c - Remove paths from profiles or delete profiles
 */

#include "cmds/remove.h"

#include <config.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/commit.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/hooks.h"

/**
 * One claim of the profile: a path it tracks, in storage terms, either kind — a
 * blob (FILE) or a directory claim it tracks (DIRECTORY), never one it only passes
 * through.
 *
 * The profile's claims are the argument universe of a removal — never the view:
 * a disabled profile's paths must stay removable (the view holds only enabled
 * profiles), an unbound custom claim too (the view refuses it), and a claim that
 * stands nowhere is still the profile's to remove (the view is
 * precedence-resolved).
 */
typedef struct {
    const char *storage_path;      /* arena */
    const char *filesystem_path;   /* arena; NULL when this machine places the
                                    * claim nowhere — an unbound custom/ one */
    path_kind_t kind;
} remove_claim_t;

/**
 * A walk of a profile's claims: each one collected, placed where this machine
 * puts it
 */
typedef struct {
    arena_t *arena;                /* The command's: the claims, their names and paths */
    const mount_table_t *mounts;   /* This machine's table, every claim placed under it */
    const char *profile;           /* Whose claims: a custom/ claim's binding is its */
    remove_claim_t *claims;
    size_t claim_count;
    size_t claim_capacity;
} remove_walk_t;

/**
 * Walk visitor: one claim of the profile, whatever its kind, collected and placed
 * — a derived claim passed by
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The walk (remove_walk_t)
 * @return NULL: a collection fails nowhere
 */
static error_t remove_collect_claim(const profile_claim_t *claim, void *payload) {
    remove_walk_t *walk = payload;

    /* A derived claim is the way to the profile's claims and never one of them
     * (core/profiles.h profile_counts): no argument takes it, and the commit's
     * prune lets it go once nothing tracked stands beneath — a rung, whose record
     * the next apply decides */
    if (claim->type == PATH_TYPE_DIRECTORY && !claim->tracked) return NULL;

    /* The name copied out of the walk's loan, and the kind off the type the decode
     * gave: a blob is a file claim whatever its filemode */
    const char *storage_path = arena_strdup(walk->arena, claim->storage_path);
    path_kind_t kind = path_type_kind(claim->type);

    /* Where it stands on this machine, placed as it is collected: NULL for a
     * custom/ claim under a profile with no target here, which stands nowhere
     * and which its name still names. The name is one the walk validated — the
     * tree's shape check, the sheet's parse — so the resolve has no failure to
     * answer. */
    const char *filesystem_path = mount_resolve(
        walk->arena, walk->mounts, walk->profile, storage_path
    );

    walk->claims = arena_grow(
        walk->arena, walk->claims, &walk->claim_capacity, walk->claim_count + 1,
        sizeof(*walk->claims)
    );
    walk->claims[walk->claim_count++] = (remove_claim_t){
        .storage_path = storage_path, .filesystem_path = filesystem_path, .kind = kind,
    };

    return NULL;
}

/**
 * Every claim the profile makes, each placed where this machine puts it
 *
 * The claims the walk shows, then those its own tree contradicts (core/profiles.h
 * profile_walk, profile_contradicted), collected by one visitor, under the reader's
 * policy: a removal reads strictly, refusing a sheet that will not load before
 * its preview as every writer does; a deletion tolerantly, so a profile whose
 * sheet will not load stays deletable. The profile's own claims alone: the blobs
 * and the directories it tracks, never the way to them (remove_collect_claim).
 * In order: the blobs in the tree's pre-order, the directory claims that stand
 * in the sheet's, the contradicted ones in the sheet's.
 *
 * Readers: remove_resolve, the universe a removal's arguments are matched against,
 * and remove_profile, every claim a deletion takes — one producer, so the two
 * routes cannot read two universes.
 *
 * @param ctx Dispatch context: the arena the claims live in, this machine's table
 * @param profile The profile (must not be NULL); its sheet is read through it
 * @param read The sheet's policy for this reader
 * @param out The claims, in ctx->arena (must not be NULL; NULL after an error)
 * @param out_count How many (must not be NULL)
 * @return Error or NULL on success: the walk's, which names the profile
 */
static error_t remove_list_claims(
    const dotta_ctx_t *ctx,
    profile_t *profile,
    profile_read_t read,
    remove_claim_t **out,
    size_t *out_count
) {
    *out = NULL;
    *out_count = 0;

    /* What stands, then what the tree contradicts, through the one visitor. The
     * walk's failures name the profile already — the loader's words for the sheet,
     * "Cannot read profile" over the tree's — so nothing is said over them. */
    remove_walk_t walk = {
        .arena = ctx->arena, .mounts = ctx->run.mounts, .profile = profile_name(profile),
    };
    error_t err = profile_walk(profile, read, remove_collect_claim, &walk);
    if (!err) err = profile_contradicted(profile, read, remove_collect_claim, &walk);
    if (err) return err;

    *out = walk.claims;
    *out_count = walk.claim_count;
    return NULL;
}

/**
 * What a removal hands its hooks: the path each claim stands at, once
 *
 * A path two claims stand at — a blob and the directory claim at its own name,
 * or two names one binding places together — is one entry: a hook is told the
 * paths the removal reaches, never how many claims stood at each. The first claim
 * at a path places it, so the list keeps the claims' order. A claim this machine
 * places nowhere hands its name instead, the shape a hook comparing DOTTA_PATH_N
 * against $HOME has always received here.
 *
 * Readers: remove_paths (the claims its arguments took) and remove_profile (every
 * claim the profile makes) — one producer, so the two routes cannot hand a hook
 * two shapes of one list.
 *
 * @param arena The list's arena, and its seen-set's (must not be NULL)
 * @param claims The claims (borrowed; their strings outlive the list's set)
 * @param claim_count How many
 * @return The paths, copies in `arena`
 */
static string_array_t remove_hook_paths(
    arena_t *arena, const remove_claim_t *claims, size_t claim_count
) {
    string_array_t paths;
    string_array_init(&paths, arena, 0);

    /* Each path once, by a seen-set's one probe over the claims' own strings
     * (base/hashmap.h hashmap_add); the list keeps copies, the shape the hook
     * contract's char *const * takes as it stands */
    hashmap_t *handed = hashmap_borrow(arena, claim_count);
    for (size_t i = 0; i < claim_count; i++) {
        const char *path = claims[i].filesystem_path
            ? claims[i].filesystem_path : claims[i].storage_path;
        if (hashmap_add(handed, path, NULL)) string_array_push(&paths, path);
    }

    return paths;
}

/**
 * Whether the removal reaches a record: this profile's, at a place this machine
 * puts a claim the removal took
 *
 * The place, the rule update's and revert's reclaims read (cmds/update.c
 * update_write_record, cmds/revert.c revert_reclaims): the record at it, whichever
 * of the profile's names it was bound under — another of its names at the place
 * is the same profile's node. A claim placed nowhere here (an unbound custom/
 * one) reaches none, and neither does a record at another place — an earlier
 * binding's, another HOME's, another spelling of this one: its node gone, each
 * is an absent orphan the next apply reclaims.
 *
 * Asked of the record before the lock and under it (remove_owes,
 * remove_write_record).
 *
 * @param profile The removing profile (must not be NULL)
 * @param places Where this machine puts the claims the removal took
 * @param record A record (must not be NULL)
 * @return Whether the removal reaches the record
 */
static bool remove_reaches(
    const char *profile, const hashmap_t *places, const state_record_t *record
) {
    return strcmp(record->profile, profile) == 0 &&
           hashmap_has(places, record->filesystem_path);
}

/**
 * Whether the record phase owes a write, as the record stands before the lock
 *
 * A deletion's row, wherever the profile is enabled. Else a reached record owes
 * one where its node is gone: read on the READ handle, empty where the database
 * does not exist, which grows none. The view is not asked, so a path a row still
 * stands at owes the lock and nothing under it. A read that fails owes the lock:
 * the read here decides only whether to take it, and the read under the lock
 * says why where it fails again, so this one's error is dropped.
 *
 * @param ctx Dispatch context: the store, and the arena the read lands in
 * @param opts The options: the profile and the route (must not be NULL)
 * @param places Where this machine puts the claims the removal took
 * @return Whether to take the lock
 */
static bool remove_owes(
    const dotta_ctx_t *ctx, const cmd_remove_options_t *opts, const hashmap_t *places
) {
    state_t *state = ctx->run.state;

    if (opts->delete_profile && state_enabled(state, opts->profile)) {
        return true;
    }

    state_record_t *records = NULL;
    size_t record_count = 0;
    if (state_records(state, ctx->arena, &records, &record_count)) return true;

    for (size_t i = 0; i < record_count; i++) {
        const state_record_t *record = &records[i];

        if (remove_reaches(opts->profile, places, record) &&
            fs_lstat_occupant(record->filesystem_path, NULL) == FS_OCCUPANT_NONE) {
            return true;
        }
    }

    return false;
}

/**
 * Write the record a removal owes
 *
 * A removal moves the view and nothing on disk: the copies its commit let go
 * are the next apply's, decided with the landings they may stand in the way of
 * (core/workspace.c workspace_analyze_orphans). This writes the fact no load
 * can derive, over each record it reaches (remove_reaches) at a path where no
 * row stands after it: a node already gone, whose record retires — Git now agreeing
 * with the disk, so a claim that returns there starts from its first look
 * (core/state.h state_retire) — the reclaim; and a deletion's enabled row, dropped.
 * A row standing at a reached record's path keeps it as that row's history, whose
 * landing acknowledges or replaces it — another profile's, or another of this
 * profile's names. A copy whose node stands keeps its record for the next apply:
 * should the user remove the node and a pull re-add the claim before that apply,
 * a re-add of the bytes the record confirmed reads as the user's deletion
 * (core/workspace.c classify_absent, stated).
 *
 * Decided under the lock from the record read there (core/state.h state_begin);
 * the lock taken only where a write may be owed (remove_owes).
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts The options: the profile and the route (must not be NULL)
 * @param claims The claims the removal took — a deletion's, every claim the profile
 *        held (must not be NULL where claim_count > 0)
 * @param claim_count How many
 * @return Error or NULL on success; the transaction is ended either way
 */
static error_t remove_write_record(
    const dotta_ctx_t *ctx,
    const cmd_remove_options_t *opts,
    const remove_claim_t *claims,
    size_t claim_count
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    state_t *state = ctx->run.state;

    /* Where this machine puts the claims the removal took: two at one place — a
     * blob and the directory claim at its own name, or two names one binding
     * places together — are one key, and a claim placed nowhere here is none */
    hashmap_t *places = hashmap_borrow(ctx->arena, claim_count);
    for (size_t i = 0; i < claim_count; i++) {
        if (claims[i].filesystem_path) {
            hashmap_add(places, claims[i].filesystem_path, NULL);
        }
    }

    if (!remove_owes(ctx, opts, places)) return NULL;

    /* The lock, and everything below decided under it: the enabled row a deletion
     * drops, then the record and the view the removal leaves, as the lock holds
     * them */
    error_t err = state_begin(state);
    if (err) return err;

    if (opts->delete_profile && state_enabled(state, opts->profile)) {
        err = state_disable_profile(state, opts->profile);
        if (err) goto cleanup;
    }

    state_record_t *records = NULL;
    size_t record_count = 0;
    err = state_records(state, ctx->arena, &records, &record_count);
    if (err) goto cleanup;

    manifest_t *after = NULL;
    err = manifest_build(ctx->run.repo, state, ctx->arena, &after);
    if (err) goto cleanup;

    for (size_t i = 0; i < record_count; i++) {
        const state_record_t *record = &records[i];
        const char *path = record->filesystem_path;

        if (!remove_reaches(opts->profile, places, record) || manifest_lookup(after, path)) {
            continue;
        }

        if (fs_lstat_occupant(path, NULL) == FS_OCCUPANT_NONE) {
            err = state_retire(state, path);
            if (err) goto cleanup;
        }
    }

    err = state_commit(state);

cleanup:
    /* The transaction ends here either way: a refused one is rolled back, and a
     * committed one has already ended (state_rollback finds none to end) */
    state_rollback(state);

    return err;
}

/**
 * Whether a blob an argument names contradicts the claim at `storage_path`: the
 * name stands at or beneath the blob's own, where a blob leaves no room
 * (remove_resolve)
 *
 * @param storage_path A directory claim's name
 * @param named The names of the blobs the argument names
 * @param named_count How many
 * @return true iff the claim stands at or beneath one of them
 */
static bool remove_contradicted(
    const char *storage_path, const char *const *named, size_t named_count
) {
    for (size_t i = 0; i < named_count; i++) {
        if (str_path_under(storage_path, named[i], strlen(named[i]))) {
            return true;
        }
    }

    return false;
}

/**
 * Resolve the arguments to the claims they take
 *
 * The claims array starts as every claim the profile makes, placed
 * (remove_list_claims, read strictly) — the base of the caller's draft
 * (core/profiles.h profile_draft_base), so the claims and the commit describe
 * one head; the arguments mark what they take, and the array compacts to just that.
 *
 * Where each claim stands is established before the match, not after it, because
 * the match is by the key the argument named (infra/path.h) and neither key is
 * manufactured from the other. A storage argument matches over the claims' names;
 * a path argument matches over the paths they were placed at — so `remove web
 * ~/jail/etc/x` takes the claim standing there under whatever name, and a root
 * takes everything beneath it. Either way an argument takes every claim at it
 * and — at a '/' boundary, never a false prefix like home/dir2 for home/dir —
 * every claim beneath it: naming a directory means untracking it whole, and one
 * the profile only passes through means what it tracks beneath, the way itself
 * the commit's prune's. A claim is removed once, however many arguments match it.
 *
 * But a blob the argument names leaves no room: a file has nothing beneath it,
 * so the directory claims at or beneath the named blob's own name — the claims
 * it contradicts — are none of the argument's, and naming a blob takes it alone.
 * By path every blob placed at the argument is named, and a claim placed beneath
 * it under another name — another label, another binding — contradicts none of
 * them and is the argument's. The rule reads names alone, never the classification
 * (core/profiles.h), so where the classification draws its line moves none of
 * its answers; and over a tree a hand stored unsorted, where the classification
 * can miss a blob, the names do not.
 *
 * A claim this machine places nowhere — an unbound custom/ one — keeps a NULL
 * path and no path argument reaches it; its name still does, which is how such
 * a claim is untracked at all. Nothing stands in for the path: the screens print
 * the name outright, the hooks are handed it where there is no path to hand over,
 * and the overlap analysis and the record read the NULL as the fact it is.
 *
 * Every argument takes a claim or refuses the removal, naming itself — in the
 * reader's words where it is no spelling of a path, else as not found — whatever
 * --force says: the flag answers the questions a removal asks, never an absence.
 * So the claims taken are never none, the arguments never being none
 * (remove_post_parse).
 *
 * @param ctx Dispatch context (must not be NULL). ctx->run.mounts covers HOME,
 *            ROOT, and every enabled profile's binding.
 * @param profile The base of the caller's draft: the profile at the head the
 *                commit will have as its parent (must not be NULL)
 * @param opts The options: the profile's name and the arguments (must not be NULL)
 * @param out The claims the arguments took, in ctx->arena (must not be NULL)
 * @param out_count How many (must not be NULL)
 * @return Error or NULL on success
 */
static error_t remove_resolve(
    const dotta_ctx_t *ctx,
    profile_t *profile,
    const cmd_remove_options_t *opts,
    remove_claim_t **out,
    size_t *out_count
) {
    CHECK_NULL(ctx);
    CHECK_NULL(profile);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(out_count);

    *out = NULL;
    *out_count = 0;

    /* Every claim the profile makes, each placed where this machine puts it —
     * the key a path argument matches against, established before the match.
     * Read strictly: a sheet that will not load refuses the removal before its
     * preview, as every writer's does. */
    remove_claim_t *claims = NULL;
    size_t claim_count = 0;
    error_t err = remove_list_claims(ctx, profile, PROFILE_READ_STRICT, &claims, &claim_count);
    if (err) return err;

    /* Beside each claim, whether an argument took it; and the names of the blobs
     * one argument names, refilled by each */
    bool *taken = arena_calloc(ctx->arena, claim_count, sizeof(*taken));
    const char **named = arena_calloc(ctx->arena, claim_count, sizeof(*named));

    /* Match each argument, marking the claims it takes */
    for (size_t i = 0; i < opts->path_count; i++) {
        path_input_t arg;
        err = path_input_resolve(opts->paths[i], ctx->arena, &arg);
        if (err) return err;

        /* The sum type, read at the use site and read once: a storage argument
         * keys against the claims' names and a path against where they stand,
         * the word alone among the names — every claim of its namespace being
         * beneath it — and the form that reaches a profile with no binding here,
         * whose custom/ claims stand nowhere for a path to match. */
        const char *subject = NULL;
        bool by_name = false;

        switch (arg.key) {
            case PATH_KEY_FILESYSTEM:
                subject = arg.filesystem_path;
                break;

            case PATH_KEY_STORAGE:
                subject = arg.storage_path;
                by_name = true;
                break;
        }

        /* The subject's length, asked once for every claim below — "/" a directory
         * like any other: what stands at it is at it, and every other absolute
         * path lies beneath it (base/string.h str_path_under) */
        const size_t subject_len = strlen(subject);

        /* The blobs the argument names: a file claim at the subject itself — by
         * its name, or each name this machine places there */
        size_t named_count = 0;
        for (size_t j = 0; j < claim_count; j++) {
            const char *key = by_name ? claims[j].storage_path : claims[j].filesystem_path;
            if (claims[j].kind == PATH_KIND_FILE && key && strcmp(key, subject) == 0) {
                named[named_count++] = claims[j].storage_path;
            }
        }

        size_t matches_found = 0;
        for (size_t j = 0; j < claim_count; j++) {
            const char *key = by_name ? claims[j].storage_path : claims[j].filesystem_path;
            if (!key) continue;                       /* it stands nowhere */

            /* The claim at the subject, or one beneath it at a directory boundary */
            if (!str_path_under(key, subject, subject_len)) {
                continue;
            }

            /* But a blob the argument names leaves no room: a directory claim
             * at or beneath its name is the blob's contradiction, and none of
             * the argument's. A file claim there is the blob itself — a tree
             * holds no blob beneath a blob, nor two at one name — so only a
             * directory claim is asked. */
            if (claims[j].kind == PATH_KIND_DIRECTORY &&
                remove_contradicted(claims[j].storage_path, named, named_count)) {
                continue;
            }

            matches_found++;
            taken[j] = true;
        }

        if (matches_found == 0) {
            return error_create(
                ERR_NOT_FOUND, "Path '%s' not found in profile '%s'",
                opts->paths[i], opts->profile
            );
        }
    }

    /* Compact to the taken claims: one at least, every argument having taken one */
    size_t taken_count = 0;
    for (size_t j = 0; j < claim_count; j++) {
        if (taken[j]) claims[taken_count++] = claims[j];
    }

    /* The claims are the command arena's, as the universe they were cut from */
    *out = claims;
    *out_count = taken_count;
    return NULL;
}

/**
 * One path this removal shares with other profiles
 *
 * The claim removed there — the first, where the removal takes two at one place:
 * two of the profile's names, or a blob and the directory claim at its own name
 * — what each other profile claims there, in the order of their names, and whether
 * an enabled one is among them.
 */
typedef struct {
    const char *filesystem_path;
    const char *storage_path;   /* the claim the removal takes there */
    manifest_rows_t others;     /* each other profile's claim there */
    bool provided;              /* an enabled one among them: the path stays in the view */
} remove_overlap_t;

/**
 * The multi-profile section, as data: one entry per path this removal shares
 * with another profile
 */
typedef struct {
    const remove_overlap_t *entries;
    size_t count;
} remove_overlaps_t;

/**
 * Whether an enabled profile is among the claimants at a shared path: its claim
 * keeps the path in the view once the removal is done (remove_overlaps)
 *
 * @param state The store, whose enabled set is asked
 * @param others Each other profile's claim at the path
 * @param count How many
 * @return true iff one of them is an enabled profile's
 */
static bool remove_provided(
    const state_t *state, const manifest_row_t *const *others, size_t count
) {
    for (size_t i = 0; i < count; i++) {
        if (state_enabled(state, others[i]->profile)) {
            return true;
        }
    }

    return false;
}

/**
 * What this removal shares with the other profiles
 *
 * Read by path, not by name: what each other local profile claims where a removed
 * claim stands — its claim there, explicit or derived, whether or not it stands
 * (core/manifest.h manifest_lookup_claim). So two profiles bound at two targets
 * holding one name are two paths and share nothing, while a portable name and a
 * binding's name at one place do share and used to go unsaid; one profile's two
 * names for one place are its one claim there; a directory claim is met like
 * any other — the profile claims the directory, and a caller asking who else is
 * at a place is owed it; and a claim this machine places nowhere meets nothing.
 *
 * Complete or an error: a short section is an "also in" a user reads as complete.
 * What a failure means is remove_paths' to say, and it is advisory: it says what
 * it could not read and drops the section rather than refuse the untrack, since
 * a local profile nobody enabled must not stop the repair and must not hide a
 * claim in silence either.
 *
 * `provided` is asked of the claimants the section holds against the enabled
 * set, no view built for it (remove_provided): another enabled profile's claim
 * at the path keeps it in the view once the removal is done — the row standing
 * there now, or the one taking the place this profile's held — so the removal
 * neither prunes nor releases the copy there. Its one limit, stated: an enabled
 * claimant beneath a third profile's blob, whose place the removed claim held,
 * stands nowhere once that blob stands again, and the path goes with the blob's
 * landing.
 *
 * Cost: one view per other local profile — a tree walk and a sheet load each —
 * then one lookup per removed path per profile. Everything the section holds is
 * the command's arena's, the views its entries borrow from included.
 */
static error_t remove_overlaps(
    const dotta_ctx_t *ctx,
    const remove_claim_t *claims,
    size_t claim_count,
    const char *current_profile,
    remove_overlaps_t *out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(claims);
    CHECK_NULL(current_profile);
    CHECK_NULL(out);

    *out = (remove_overlaps_t){ 0 };

    /* The other local profiles, by name: the order a line lists them in, the
     * store listing them as its enumeration met them (sys/gitops.h
     * gitops_list_refs) */
    string_array_t profiles;
    error_t err = gitops_list_branches(ctx->run.repo, ctx->arena, &profiles);
    if (err) return err;
    string_array_remove_value(&profiles, current_profile);
    string_array_sort(&profiles);

    /* Each read once, through its own view of its head under this machine's table */
    manifest_t **views = arena_calloc(ctx->arena, profiles.count, sizeof(*views));
    for (size_t p = 0; p < profiles.count; p++) {
        profile_t *profile = NULL;
        err = profile_load(ctx->run.repo, profiles.entries[p], &profile);
        if (!err) err = manifest_build_profile(profile, ctx->run.mounts, ctx->arena, &views[p]);
        profile_free(profile);
        if (err) return err;
    }

    /* Each path asked once, so two claims the removal takes at one place — two
     * of the profile's names, or a blob and the directory claim at its own name
     * — are one line and one count: a seen-set's one probe over the claims' own
     * strings (base/hashmap.h hashmap_add) */
    remove_overlap_t *overlaps = arena_calloc(ctx->arena, claim_count, sizeof(*overlaps));
    hashmap_t *asked = hashmap_borrow(ctx->arena, claim_count);

    size_t count = 0;
    for (size_t i = 0; i < claim_count; i++) {
        const char *filesystem_path = claims[i].filesystem_path;
        if (!filesystem_path || !hashmap_add(asked, filesystem_path, NULL)) continue;

        /* Each other profile's claim at the path, in name order: the list made
         * at the first profile that holds one, with room for every profile */
        const manifest_row_t **others = NULL;
        size_t other_count = 0;
        for (size_t p = 0; p < profiles.count; p++) {
            const manifest_row_t *other = manifest_lookup_claim(
                views[p], profiles.entries[p], filesystem_path
            );
            if (!other) continue;

            if (!others) others = arena_calloc(ctx->arena, profiles.count, sizeof(*others));
            others[other_count++] = other;
        }
        if (other_count == 0) continue;

        overlaps[count++] = (remove_overlap_t){
            .filesystem_path = filesystem_path,
            .storage_path = claims[i].storage_path,
            .others = { others, other_count },
            .provided = remove_provided(ctx->run.state, others, other_count),
        };
    }

    *out = (remove_overlaps_t){ overlaps, count };

    return NULL;
}

/**
 * Print the overlap section
 *
 * One line per shared path: the path, then each other profile and — where its
 * name for the place differs from the removed claim's — the name it holds it
 * under, since under two bindings one path wears two names. The closing lines
 * say what is true of the shared paths: the removal takes them from this profile
 * alone, and where another enabled profile claims one, the path stays managed
 * under that claim — whether the removed claim stood there or another's stood
 * over it — said once, here, before the act, and after it by status, which reads
 * the copy's record as that profile's reassignment. What remove does to every
 * other copy is promised once before the act, by the question (remove_ask_paths)
 * or the dry run.
 */
static void remove_print_overlaps(
    output_t *out,
    const remove_overlaps_t *overlaps,
    const char *current_profile
) {
    if (overlaps->count == 0) return;

    output_section(out, OUTPUT_NORMAL, "Multi-profile path warning");
    output_warning(
        out, OUTPUT_NORMAL, "Found %zu path%s in multiple profiles:",
        overlaps->count, overlaps->count == 1 ? "" : "s"
    );

    for (size_t i = 0; i < overlaps->count; i++) {
        const remove_overlap_t *overlap = &overlaps->entries[i];

        output_print(
            out, OUTPUT_NORMAL, "  {yellow}%s{reset} also in:", overlap->filesystem_path
        );
        for (size_t j = 0; j < overlap->others.count; j++) {
            const manifest_row_t *other = overlap->others.entries[j];

            output_print(out, OUTPUT_NORMAL, " {cyan}%s{reset}", other->profile);
            if (strcmp(other->storage_path, overlap->storage_path) != 0) {
                output_print(
                    out, OUTPUT_NORMAL, " {dim}(as %s){reset}", other->storage_path
                );
            }
        }
        output_endline(out, OUTPUT_NORMAL);
    }

    /* Explain implications */
    output_gap(out, OUTPUT_NORMAL);
    output_info(
        out, OUTPUT_NORMAL,
        "These paths will be removed only from profile '%s'",
        current_profile
    );

    /* Said once, at the first path another enabled profile claims: the path stays
     * in the view, so its copy is that profile's to acknowledge or replace on
     * apply, never pruned or released — the record rule in one clause, and the
     * exception to the promise the question or the dry run makes */
    for (size_t i = 0; i < overlaps->count; i++) {
        if (overlaps->entries[i].provided) {
            output_warning(
                out, OUTPUT_NORMAL,
                "Another enabled profile also tracks some of them"
            );
            output_info(
                out, OUTPUT_NORMAL,
                "Those paths stay tracked, from that profile"
            );
            break;
        }
    }
}

/**
 * Format a claim count for display: "2 files", "1 directory", or "2 files and 1
 * directory". The directory half appears only when dirs is non-zero, so file-only
 * wordings stay exactly what they were. Three distant sites print the phrase
 * (the dry-run total, the confirmation prompt, the receipt) and tests pin the
 * wording — one spelling.
 */
static void remove_format_counts(
    char *buf, size_t size, size_t files, size_t dirs
) {
    if (dirs == 0) {
        snprintf(buf, size, "%zu file%s", files, files == 1 ? "" : "s");
    } else if (files == 0) {
        snprintf(buf, size, "%zu director%s", dirs, dirs == 1 ? "y" : "ies");
    } else {
        snprintf(
            buf, size, "%zu file%s and %zu director%s",
            files, files == 1 ? "" : "s", dirs, dirs == 1 ? "y" : "ies"
        );
    }
}

/**
 * Ask whether to remove the claims the arguments took — or answer yes where no
 * question is owed: --force, a removal below the threshold
 */
static output_answer_t remove_ask_paths(
    const remove_claim_t *claims,
    size_t claim_count,
    const cmd_remove_options_t *opts,
    const config_t *config,
    output_t *out
) {
    /* Skip confirmation if --force */
    if (opts->force) return OUTPUT_ANSWER_YES;

    /* Check config threshold */
    size_t threshold = 5; /* Default threshold */
    if (config->confirm_destructive) {
        threshold = 1;    /* confirm_destructive: every removal asks, however small */
    }

    /* No confirmation needed for small operations below threshold */
    if (claim_count < threshold) return OUTPUT_ANSWER_YES;

    size_t files = 0, dirs = 0;
    for (size_t i = 0; i < claim_count; i++) {
        if (claims[i].kind == PATH_KIND_DIRECTORY) dirs++;
        else files++;
    }
    char counts[64];
    remove_format_counts(counts, sizeof(counts), files, dirs);

    /* The question, and beneath it the one promise remove makes the copies before
     * the act: what every machine's next apply does to them where no other enabled
     * profile claims the path — the overlap section above names those — each
     * file's copy left on disk, its record retired. The files' alone: a directory
     * goes by what is left in it, whatever took its claim, one dotta created
     * pruned once empty (core/workspace.c workspace_analyze_orphans) */
    return output_ask(
        out, false, "Remove %s from profile '%s'?\n"
        "(No file is deleted from disk, on any machine)", counts, opts->profile
    );
}

/**
 * Print what a deletion takes, and the one promise remove makes the copies
 *
 * One fact in two tenses: a dry run's lines, or the warning a question is the
 * preamble of. `counts` is the profile-holdings phrase from the count family
 * (output_format_counts, or its "counts unavailable" stand-in), and the promise
 * is the one a removal of paths makes, the files' (remove_ask_paths), true here
 * on other grounds: this machine's next apply releases each file's copy, no history
 * answering for a branch that is gone, and no sync carries a branch's deletion,
 * so every other machine keeps managing its copies. Where no question is asked,
 * nothing previews the deletion: the receipt says what it took (remove_profile,
 * its one reader).
 */
static void remove_print_deletion(
    output_t *out, const cmd_remove_options_t *opts, const char *counts
) {
    /* A block of its own in either tense, beneath the warnings above it */
    output_gap(out, OUTPUT_NORMAL);

    if (opts->dry_run) {
        output_print(
            out, OUTPUT_NORMAL, "Would delete profile '%s' (%s)\n",
            opts->profile, counts
        );
        output_print(
            out, OUTPUT_NORMAL, "(No file would be deleted from disk, on any machine)\n"
        );
    } else {
        output_warning(
            out, OUTPUT_NORMAL, "This will delete profile '%s' (%s)",
            opts->profile, counts
        );
        output_info(
            out, OUTPUT_NORMAL, "         No file is deleted from disk, on any machine"
        );
    }
}

/**
 * Remove paths from a profile
 */
static error_t remove_paths(
    const dotta_ctx_t *ctx,
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Initialize all resources to NULL for safe cleanup */
    error_t err = NULL;
    profile_draft_t *draft = NULL;      /* the profile's next commit (owned) */
    remove_claim_t *claims = NULL;      /* arena — the resolver's */
    size_t claim_count = 0;
    remove_overlaps_t overlaps = { 0 }; /* arena — the analysis's */

    /* The profile's draft: the head everything below reads — the claims, the
     * sheet, the judge — and the parent the commit will have, its sheet read at
     * the open, strictly. The removal is pure tree surgery, so the draft is the
     * whole of its Git side. */
    err = profile_draft_open(repo, opts->profile, &draft);
    if (err) goto cleanup;

    /* The arguments resolved against the claims the profile makes at the tree
     * the draft opened at — the head the commit will have as its parent */
    err = remove_resolve(ctx, profile_draft_base(draft), opts, &claims, &claim_count);
    if (err) goto cleanup;

    /* What the removal shares with the other profiles (critical safety check).
     * Advisory: the untrack proceeds without the section and says why, since a
     * local profile nobody enabled must not stop the repair — and must not hide
     * a claim in silence either, an absent section reading as "no overlap". */
    err = remove_overlaps(ctx, claims, claim_count, opts->profile, &overlaps);
    if (err) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(
            out, OUTPUT_NORMAL, "Could not read the other profiles' claims: %s",
            error_line(err)
        );
        err = NULL;
    }

    /* The overlap section, BEFORE any operation */
    remove_print_overlaps(out, &overlaps, opts->profile);

    /* Selection: -i narrows the run, each claim asked beside its name, beneath
     * the overlap section and before anything fires — so the hooks and the plan
     * below see exactly what will happen, a declined claim out before the pre-hook
     * names the set. Each is a consent question, answered by a terminal or a
     * pipe, as a script answers it (base/output.h output_ask); a claim no answer
     * came for refuses the run: -i asked of each, and a selection with one
     * unanswered is no selection. The refusal names that claim and no way on,
     * since the asking is the flag the user typed. None binds a dry run, which
     * lists every claim; and a selection that keeps none ends the run, which
     * fires no hook. */
    if (opts->interactive && !opts->dry_run) {
        size_t kept = 0;
        for (size_t i = 0; i < claim_count; i++) {
            switch (output_ask(
                out, false, "Remove %s%s?",
                claims[i].storage_path, path_kind_suffix(claims[i].kind)
                )) {
                case OUTPUT_ANSWER_YES:
                    claims[kept++] = claims[i];
                    break;
                case OUTPUT_ANSWER_NO:
                    output_info(out, OUTPUT_VERBOSE, "Kept: %s", claims[i].storage_path);
                    break;
                case OUTPUT_ANSWER_NONE:
                    err = error_create(
                        ERR_VALIDATION, "Cannot remove '%s' from profile '%s' without a "
                        "confirmation, and none was read", claims[i].storage_path,
                        opts->profile
                    );
                    goto cleanup;
            }
        }
        claim_count = kept;

        if (claim_count == 0) {
            output_gap(out, OUTPUT_NORMAL);
            output_info(out, OUTPUT_NORMAL, "Nothing removed");
            goto cleanup;
        }
    }

    /* Dry run: what would be removed, and the one promise the copies are made,
     * as the question makes it (remove_ask_paths) */
    if (opts->dry_run) {
        size_t dry_files = 0, dry_dirs = 0;
        output_gap(out, OUTPUT_NORMAL);
        output_print(
            out, OUTPUT_NORMAL, "Would remove from profile '%s':\n",
            opts->profile
        );
        for (size_t i = 0; i < claim_count; i++) {
            output_print(
                out, OUTPUT_NORMAL, "  - %s%s\n",
                claims[i].storage_path, path_kind_suffix(claims[i].kind)
            );
            if (claims[i].kind == PATH_KIND_DIRECTORY) dry_dirs++;
            else dry_files++;
        }
        char counts[64];
        remove_format_counts(counts, sizeof(counts), dry_files, dry_dirs);
        output_gap(out, OUTPUT_NORMAL);
        output_print(
            out, OUTPUT_NORMAL,
            "Total: %s would be removed from profile\n",
            counts
        );
        output_print(
            out, OUTPUT_NORMAL, "(No file would be deleted from disk, on any machine)\n"
        );
    }

    /* The pre-remove hook, over the decided removal — a dry run's too, told so
     * (DOTTA_DRY_RUN=1) — handed the paths the accepted claims stand at, each
     * once (remove_hook_paths), as placed by the resolver. The draft opened before
     * it, so a commit it makes to the branch refuses this removal's, and a branch
     * it deletes comes back with it (sys/stage.h). */
    const string_array_t hook_paths = remove_hook_paths(ctx->arena, claims, claim_count);
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .paths      = hook_paths.entries,
        .path_count = hook_paths.count,
        .dry_run    = opts->dry_run,
    };

    err = hook_fire_pre(config, out, &hook_inv);
    if (err) goto cleanup;

    /* A dry run ends here, beneath its pre-hook, in the act it did not do */
    if (opts->dry_run) {
        output_gap(out, OUTPUT_NORMAL);
        output_info(out, OUTPUT_NORMAL, "Dry run: nothing was committed");
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Confirm operation: the consent, after the hook. Declined is the user's
     * word, and no failure; unanswered — the input ended before a line — nobody
     * declined, and the run did not do what it was asked: its refusal, naming
     * the flag that answers in advance. */
    switch (remove_ask_paths(claims, claim_count, opts, config, out)) {
        case OUTPUT_ANSWER_YES:
            break;
        case OUTPUT_ANSWER_NO:
            output_gap(out, OUTPUT_NORMAL);
            output_info(out, OUTPUT_NORMAL, "Cancelled");
            goto cleanup;  /* err is NULL, will return success */
        case OUTPUT_ANSWER_NONE:
            err = error_create(
                ERR_VALIDATION, "Cannot remove from profile '%s' without a confirmation, "
                "and none was read; --force removes without asking", opts->profile
            );
            goto cleanup;
    }

    /* The plan, on the draft: each claim leaves the commit by its own kind
     * (core/profiles.h profile_remove) — a FILE claim its tree entry and its
     * item, a DIRECTORY claim its tracking, the way staying where anything tracked
     * stands beneath it — so a directory claim at a removed file's name stays,
     * carried, and stands again once the blob is gone. Every claim is the base's
     * own, taken once, and every directory claim a tracked one (the resolver's
     * universe is the base's walk and the claims its tree contradicts, a derivation
     * never among them), so neither of the removal's refusals can fire. */
    size_t removed_files = 0, removed_dirs = 0;

    /* Each removal traced at verbose, the trace a block of its own */
    output_gap(out, OUTPUT_VERBOSE);
    for (size_t i = 0; i < claim_count; i++) {
        const remove_claim_t *claim = &claims[i];

        err = profile_remove(draft, claim->kind, claim->storage_path);
        if (err) goto cleanup;
        if (claim->kind == PATH_KIND_DIRECTORY) removed_dirs++;
        else removed_files++;

        output_info(
            out, OUTPUT_VERBOSE, "Removed: %s%s",
            claim->storage_path, path_kind_suffix(claim->kind)
        );
    }

    /* One atomic commit: the file claims leave the tree, and the sheet follows
     * in the same tree write where its claims moved — pruned first of the derived
     * claims the removals left nothing tracked beneath, counted in `pruned`
     * (core/profiles.h profile_commit). Its message names what the commit changes
     * of the profile's claims, never the claims taken: a blob and the directory
     * claim at its own name are two claims to the receipt and one name to the
     * message. All-or-nothing: any failure up to here leaves every ref where it
     * was. */
    const commit_words_t words = {
        .action     = COMMIT_ACTION_REMOVE,
        .title      = config->commit_title,
        .body       = config->commit_body,
        .custom_msg = opts->message,
    };
    size_t pruned = 0;
    err = profile_commit(draft, &words, NULL, &pruned);
    if (err) goto cleanup;
    if (pruned > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "Pruned %zu ancestor claim%s", pruned, pruned == 1 ? "" : "s"
        );
    }

    /*
     * Architectural note: no filesystem deletion here. Only apply writes to a
     * managed filesystem path — core/deploy and core/cleanup are the only mutators
     * — so remove's whole effect is the commit above and the record below. The
     * deployed copy's fate is decided at the next apply, against the view standing
     * then.
     */

    /* Success: what the commit took, said once it lands and before the record
     * phase, which may wait on the store's lock (core/state.h state_begin) */
    char counts[64];
    remove_format_counts(counts, sizeof(counts), removed_files, removed_dirs);
    output_gap(out, OUTPUT_NORMAL);
    output_success(
        out, OUTPUT_NORMAL, "Removed %s from profile '%s'",
        counts, opts->profile
    );

    /* The record phase (remove_write_record): the reclaim of a copy already gone.
     * One phase, one sentence, whichever step refused, as add's, update's and
     * apply's say it: the store's refusal in its own words, which name the step
     * — the read, the lock, the view, a retire or the commit. Non-fatal: the
     * commit to Git stands, so the refusal is warned in a block beneath the success
     * line, and the command goes on; what the phase did not write the next apply
     * decides, as every let-go — a gone copy's record it reclaims as every absent
     * orphan's. */
    error_t record_err = remove_write_record(ctx, opts, claims, claim_count);
    if (record_err) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(record_err));
    }

    /* The post-remove hook, last (utils/hooks.h hook_fire_post) */
    hook_fire_post(config, out, &hook_inv);

cleanup:
    /* The draft, whatever it held — a draft never committed changes nothing in
     * the repository. The record phase ended its own transaction. */
    profile_draft_free(draft);

    return err;
}

/**
 * Delete a profile
 */
static error_t remove_profile(
    const dotta_ctx_t *ctx,
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Initialize all resources to NULL */
    error_t err = NULL;
    profile_t *profile = NULL;
    const char *remote_name = NULL;
    const char *remote_url = NULL;

    /* Is the profile here? Git's answer or Git's error: an unreadable ref is
     * not an absence. One that is not here is refused whatever --force says:
     * the flag answers the questions a deletion asks — the warnings below and
     * the confirmation they preface — and an absence is none of them. */
    bool exists = false;
    err = gitops_branch_exists(repo, opts->profile, &exists);
    if (err) goto cleanup;
    if (!exists) {
        err = error_create(ERR_NOT_FOUND, "Profile '%s' does not exist", opts->profile);
        goto cleanup;
    }

    /* SAFETY: Prevent deletion of last remaining profile */
    string_array_t all_profiles;
    err = gitops_list_branches(repo, ctx->arena, &all_profiles);
    if (err) goto cleanup;

    if (all_profiles.count <= 1) {
        err = error_create(
            ERR_INVALID_ARG, "Cannot delete last remaining profile '%s'; a repository "
            "keeps at least one", opts->profile
        );
        goto cleanup;
    }

    /* The profile at its head, read once for all the deletion says before it
     * acts: every claim it takes, for its hooks, and what it holds, for the preview
     * and the confirmation, one commit for both. A head that will not load refuses
     * here, in gitops' words, which name the branch. */
    err = profile_load(repo, opts->profile, &profile);
    if (err) goto cleanup;

    /* Every claim the deletion takes, each placed where this machine puts it —
     * the claims the walk shows, and those the tree contradicts, by the producer
     * the resolver reads (remove_list_claims) — so the hooks are handed every
     * path the profile goes with. Read tolerantly: a deletion that refused over
     * a sheet it cannot read would leave the profile undeletable, so it goes on
     * and says below what its hooks lose. A tree it cannot walk is refused here,
     * before the preview: no tolerant read loses the tree's half. */
    remove_claim_t *claims = NULL;
    size_t claim_count = 0;
    err = remove_list_claims(ctx, profile, PROFILE_READ_TOLERANT, &claims, &claim_count);
    if (err) goto cleanup;

    /* What the tolerant read lost, said where it was read, so the dry run says
     * it too: the directory claims the hooks are not handed, and the count below,
     * in the loader's line, which names the profile. The record phase loses them
     * too, unsaid (stated): a record of one is never reclaimed, the next apply's
     * as every let-go — released where it holds what no apply removes, pruned
     * once empty where dotta created it */
    err = profile_load_sheet(profile);
    if (err) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(
            out, OUTPUT_NORMAL, "%s; its hooks are handed its files alone",
            error_line(err)
        );
        err = NULL;
    }

    /* The count, over the same profile, both kinds (core/profiles.h
     * profile_counts): one truth with `dotta list`. Its failure is display-only
     * — the deletion must not refuse over a count — so it becomes the phrase
     * the preview prints, its error dropped and err back to the NULL the phase
     * began with. The profile is read no further: the claims its hooks are handed
     * hold their own copies. */
    profile_counts_t count = { 0 };
    err = profile_counts(profile, &count);
    profile_free(profile);
    profile = NULL;

    char counts[64];
    if (err) {
        snprintf(counts, sizeof(counts), "counts unavailable");
        err = NULL;
    } else {
        output_format_counts(
            count.file_count, count.directory_count, counts, sizeof(counts)
        );
    }

    /* The remote, resolved up-front for two readers: where the profile stands
     * against it, said before the act — in the dry run too, which previews what
     * the deletion says before it acts — and the deletion's push below, whose
     * credential helper reads the URL (its transfer context). No remote configured
     * is an answer — the profile is this repository's alone, nothing pushed
     * (sys/gitops.h names this read) — and every other failure is the run's,
     * joined below with the upstream's own. */
    err = gitops_resolve_default_remote(
        repo, ctx->arena, &remote_name, &remote_url
    );
    if (error_code(err) == ERR_NOT_FOUND) {
        err = NULL;
    } else if (!err) {
        /* A remote: where the profile stands against it */
        upstream_info_t upstream_info;
        err = upstream_analyze_profile(
            repo, remote_name, opts->profile, &upstream_info
        );
        if (!err) {
            /* Commits no remote holds — ahead of what it pushed, or never pushed
             * at all: the deletion takes them with every other commit of the
             * profile's, so they are said before it, unless --force. No sync
             * first saves them: the deletion is pushed as well. */
            if (!opts->force &&
                (upstream_info.ahead > 0 || upstream_info.state == UPSTREAM_NO_REMOTE)) {
                output_gap(out, OUTPUT_NORMAL);
                output_warning(
                    out, OUTPUT_NORMAL, "Profile '%s' has unpushed changes", opts->profile
                );
            }

            /* Never pushed: no branch there for the deletion to delete */
            if (upstream_info.state == UPSTREAM_NO_REMOTE) remote_name = NULL;
        }
    }
    if (err) {
        /* Where the profile stands is unknown — a remote the resolver could not
         * choose, an upstream that would not read: said where unpushed changes
         * are said, before the same confirmation, and --force skips it as it
         * skips that warning. A refusal here would refuse past --force, where a
         * positive finding only warns. */
        if (!opts->force) {
            output_gap(out, OUTPUT_NORMAL);
            output_warning(
                out, OUTPUT_NORMAL, "Cannot tell whether profile '%s' has unpushed "
                "changes: %s", opts->profile, error_line(err)
            );
        }
        err = NULL;
    }

    /* The consent the deletion owes — none under --force, where the configuration
     * asks none, or in a dry run — is a person's at a terminal (base/output.h
     * output_ask_destructive): off one it is refused here, at the decision, before
     * the preview and the hook — and after the warnings above, which say what
     * --force, the refusal's way through, deletes unasked */
    const bool asks = !opts->force && config->confirm_destructive && !opts->dry_run;
    if (asks && !isatty(STDIN_FILENO)) {
        err = error_create(
            ERR_VALIDATION, "Cannot delete profile '%s' without a confirmation, "
            "which only a terminal gives; --force deletes it without asking",
            opts->profile
        );
        goto cleanup;
    }

    /* The preview: what the deletion takes, and the one promise the copies are
     * made — a dry run's lines, or the question's preamble where one is asked
     * (remove_print_deletion); an unasked deletion previews nothing it then does
     * at once */
    if (opts->dry_run || asks) remove_print_deletion(out, opts, counts);

    /* The pre-remove hook, over the decided deletion — a dry run's too, told so
     * (DOTTA_DRY_RUN=1) — handed the path of every claim the profile goes with,
     * each once, by the producer the path route's hooks read (remove_hook_paths):
     * HOME and ROOT place every home/ and root/ claim, and a custom/ claim with
     * no binding here hands its name. The list is the command arena's. The deletion
     * reads no draft: it deletes the branch whatever the hook committed. */
    const string_array_t hook_paths = remove_hook_paths(ctx->arena, claims, claim_count);
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .paths      = hook_paths.entries,
        .path_count = hook_paths.count,
        .dry_run    = opts->dry_run,
    };

    err = hook_fire_pre(config, out, &hook_inv);
    if (err) goto cleanup;

    /* A dry run ends here, beneath its pre-hook, in the act it did not do */
    if (opts->dry_run) {
        output_gap(out, OUTPUT_NORMAL);
        output_info(out, OUTPUT_NORMAL, "Dry run: nothing was deleted");
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Confirm the deletion: the consent, after the hook. Declined is the user's
     * word, and no failure; unanswered — the terminal's input ended — nobody
     * declined: the run's refusal, naming the flag that answers in advance. */
    if (asks) {
        switch (output_ask_destructive(out, "Continue?")) {
            case OUTPUT_ANSWER_YES:
                break;
            case OUTPUT_ANSWER_NO:
                output_gap(out, OUTPUT_NORMAL);
                output_info(out, OUTPUT_NORMAL, "Cancelled");
                goto cleanup;  /* err is NULL, will return success */
            case OUTPUT_ANSWER_NONE:
                err = error_create(
                    ERR_VALIDATION, "Cannot delete profile '%s' without a confirmation, "
                    "and none was read; --force deletes it without asking", opts->profile
                );
                goto cleanup;
        }
    }

    /* No filesystem deletion here either — see the Architectural note in
     * remove_paths: apply owns deferred filesystem cleanup. */

    /* Delete local branch */
    err = gitops_delete_branch(repo, opts->profile);
    if (err) goto cleanup;

    /* Success message: every exit before the deletion is behind us (dry run,
     * cancel, error) — with what it took, which a question asked before it said
     * too, and nothing else on an unasked run says — said once the branch is
     * gone and before the record phase, which may wait on the store's lock
     * (core/state.h state_begin). */
    output_gap(out, OUTPUT_NORMAL);
    output_success(
        out, OUTPUT_NORMAL, "Profile '%s' deleted (%s)", opts->profile, counts
    );

    /* The record phase (remove_write_record): the enabled row and the record,
     * in one transaction, after the branch is gone — the view the phase builds
     * is the one the deletion leaves — and before the push, the store settled
     * before the network is asked. Its claims are the tolerant read's, so a sheet
     * that would not load leaves its directory claims unreached, never reclaimed,
     * the next apply's as every let-go (stated beside the read's warning).
     * Non-fatal: the branch is gone and stands, so the store's refusal is warned
     * in its own words, a block beneath the success line, and the command goes
     * on; of what the phase owed, every later load re-derives its share — the
     * next apply reclaims a gone copy's record as every absent orphan's, and
     * every load names an enabled profile with no branch, with its remedy. */
    error_t record_err = remove_write_record(ctx, opts, claims, claim_count);
    if (record_err) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(record_err));
    }

    /* Push the deletion to the remote, unless the profile was never pushed there
     * (remote_name NULL, above): sync needs it, since other repositories learn
     * the branch is gone only from there. The push is a block of its own: its
     * announce, then its outcome. */
    if (remote_name) {
        output_gap(out, OUTPUT_NORMAL);
        output_info(
            out, OUTPUT_NORMAL, "Pushing profile deletion to remote '%s'...",
            remote_name
        );

        /* remote_url was resolved alongside remote_name above. NULL is legal —
         * unauthenticated paths still work, helper approve/reject become no-ops. */
        transfer_options_t del_opts = { .output = out, .url = remote_url };
        transfer_context_t *del_xfer = transfer_context_create(&del_opts);
        error_t push_err = gitops_delete_remote_branch(
            repo, remote_name, opts->profile, del_xfer
        );
        transfer_context_free(del_xfer);
        if (push_err) {
            /* Non-fatal: the branch is gone here, as the success line above says,
             * and what failed is the remote's half, which other machines learn
             * the deletion from. Warned in its own words, which name the profile
             * and the remote (sys/gitops.c gitops_delete_remote_branch), and
             * the push by hand its remedy — through dotta git, which runs git
             * on the store (cmds/git.h cmd_git), where a git typed in a shell
             * acts on whatever repository the shell stands in. */
            output_warning(out, OUTPUT_NORMAL, "%s", error_line(push_err));
            output_hint(
                out, OUTPUT_NORMAL,
                "Run 'dotta git push %s --delete %s' to push the deletion",
                remote_name, opts->profile
            );
        } else {
            output_info(out, OUTPUT_NORMAL, "Profile deletion pushed to remote");
        }
    }

    /* The prune itself happens on `apply` — see the Architectural note in
     * remove_paths. */

    /* The post-remove hook, last (utils/hooks.h hook_fire_post): the deletion's
     * push among what the run said */
    hook_fire_post(config, out, &hook_inv);

cleanup:
    /* The profile is freed once its count is read; here only a refusal before
     * that frees it. The record phase ended its own transaction. */
    profile_free(profile);

    return err;
}

/**
 * Remove command implementation
 */
error_t cmd_remove(const dotta_ctx_t *ctx, const cmd_remove_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    /* Branch: delete a profile, or remove paths from one */
    if (opts->delete_profile) {
        return remove_profile(ctx, opts);
    }

    return remove_paths(ctx, opts);
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `profile` and `paths[]` — the one place
 * the arguments' shape is judged, which cmd_remove trusts:
 *   1. -p/--profile was given: every positional is a path.
 *   2. -p not given: first positional is the profile, rest are paths.
 *   3. --delete-profile: paths must be empty (mutually exclusive).
 *   4. Without --delete-profile: at least one path is required.
 */
static error_t remove_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_remove_options_t *o = opts_v;

    if (o->profile != NULL) {
        o->paths = o->positional_args;
        o->path_count = o->positional_count;
    } else {
        if (o->positional_count == 0) {
            return error_create(ERR_INVALID_ARG, "Profile name is required");
        }
        o->profile = o->positional_args[0];
        o->paths = o->positional_args + 1;
        o->path_count = o->positional_count - 1;
    }

    if (o->delete_profile && o->path_count > 0) {
        return error_create(ERR_INVALID_ARG, "Cannot specify paths when using --delete-profile");
    }
    if (!o->delete_profile && o->path_count == 0) {
        return error_create(ERR_INVALID_ARG, "At least one path is required");
    }
    return NULL;
}

/**
 * A directory offer: where its candidates go, and whose claims it asks
 */
typedef struct {
    FILE *out;
    profile_t *profile;   /* Asked of each claim's name; its name each description */
} remove_offer_t;

/**
 * Walk visitor: a directory claim offered where its name takes what the profile
 * tracks at and beneath it — where no blob stands at that name, which an argument
 * would take alone (remove_resolve). A file claim is the refspecs' to offer
 * (cmds/completion.h completion_refspecs).
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The offer (remove_offer_t)
 * @return NULL, or the question's failure, which ends the offer
 */
static error_t remove_offer_directory(const profile_claim_t *claim, void *payload) {
    const remove_offer_t *offer = payload;

    if (claim->type != PATH_TYPE_DIRECTORY) return NULL;

    /* Whether a blob stands at the claim's own name, where an argument naming
     * it would name the blob and take the blob alone. Asked of the name, never
     * read off which walk showed the claim, so the offer holds wherever the
     * classification draws its line: a claim beneath a blob is reached by its
     * own name, one at a blob's name is not. A gitlink's name names no blob. */
    profile_held_t held;
    error_t err = profile_holds(offer->profile, claim->storage_path, &held);
    if (err) return err;
    if (held.kind != PROFILE_HELD_FILE) {
        fprintf(
            offer->out, "%s/\t%s\n",
            claim->storage_path, profile_name(offer->profile)
        );
    }

    return NULL;
}

/**
 * What can stand at the cursor, read off the buckets remove_post_parse routes:
 * a local profile in the profile slot — the first positional, unless -p took it
 * — then the claims of that profile, standing or not, enabled or not: its files,
 * and the directory claims whose names take what it tracks there, slash-marked;
 * nothing after --delete-profile, which takes no path.
 */
static args_want_t remove_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_remove_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_remove_options_t, profile)) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    if (at->value_of != NULL) {
        return ARGS_WANT_NONE;   /* -m: free text */
    }

    if (o->profile == NULL && o->positional_count == 0) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    if (o->delete_profile) {
        return ARGS_WANT_NONE;
    }
    const char *pinned = o->profile ? o->profile : o->positional_args[0];
    completion_refspecs(ctx, out, pinned);

    /* The directory claims, remove's own offer: every claim the profile makes
     * at its head — the walk's, then those its tree contradicts — asked whether
     * a blob stands at its name (remove_offer_directory), so the offer is the
     * rule's and not where the classification draws its line. Read strictly:
     * the claims are the sheet's, so a sheet that will not load offers none either
     * way. None outside a repository, and every failure dropped, as every
     * completion source drops its own (cmds/completion.h) */
    if (ctx->run.repo == NULL) return ARGS_WANT_NONE;
    remove_offer_t offer = { .out = out };
    error_t err = profile_load(ctx->run.repo, pinned, &offer.profile);
    if (!err) {
        err = profile_walk(
            offer.profile, PROFILE_READ_STRICT, remove_offer_directory, &offer
        );
    }
    if (!err) {
        (void) profile_contradicted(
            offer.profile, PROFILE_READ_STRICT, remove_offer_directory, &offer
        );
    }
    profile_free(offer.profile);

    return ARGS_WANT_NONE;
}

static error_t remove_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_remove(ctx, (const cmd_remove_options_t *) opts_v);
}

static const args_opt_t remove_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",         "<name>",
        cmd_remove_options_t,profile,
        "Profile name (alternative to positional)"
    ),
    ARGS_STRING(
        "m message",         "<msg>",
        cmd_remove_options_t,message,
        "Commit message"
    ),
    ARGS_FLAG(
        "delete-profile",
        cmd_remove_options_t,delete_profile,
        "Delete the entire profile branch"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_remove_options_t,dry_run,
        "Preview without committing or deleting"
    ),
    ARGS_FLAG(
        "f force",
        cmd_remove_options_t,force,
        "Skip confirmation prompts"
    ),
    ARGS_FLAG(
        "i interactive",
        cmd_remove_options_t,interactive,
        "Prompt for each path"
    ),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_remove_options_t,verbosity,       DOTTA_VERBOSITY_VERBOSE,
        "Verbose output"
    ),
    ARGS_FLAG_SET(
        "q quiet",
        cmd_remove_options_t,verbosity,       DOTTA_VERBOSITY_QUIET,
        "Minimal output"
    ),
    /* <profile> [<path>...]. -p promotes positionals to all-paths. */
    ARGS_POSITIONAL_RAW(
        cmd_remove_options_t,positional_args, positional_count,
        0,                   0
    ),
    ARGS_END,
};

const args_command_t spec_remove = {
    .name        = "remove",
    .summary     = "Remove paths from a profile or delete a profile",
    .usage       =
        "%s remove [options] <profile> <path>...\n"
        "   or: %s remove [options] <profile> --delete-profile\n"
        "   or: %s remove [options] --profile <name> <path>...",
    .description =
        "Stop tracking files and directories: they leave the profile, and no\n"
        "file is deleted from disk, on any machine. To delete every machine's\n"
        "unchanged copy instead, delete the file and run 'dotta update'.\n",
    .notes       =
        "Operation Modes:\n"
        "  (default)           Remove the paths from the profile. No file\n"
        "                      is deleted from disk.\n"
        "  --delete-profile    Delete the entire profile branch. No paths\n"
        "                      may be given.\n",
    .examples    =
        "  %s remove global ~/.bashrc                  # Stop tracking, keep the file\n"
        "  %s remove darwin ~/.config/nvim -n          # Preview removal\n"
        "  %s remove staging --delete-profile          # Delete whole profile\n",
    .epilogue    =
        "See also:\n"
        "  %s profile disable <name>  # Stop deploying a profile on this machine\n"
        "  %s update                  # Delete every unchanged copy, once deleted here\n",
    .opts_size   = sizeof(cmd_remove_options_t),
    .opts        = remove_opts,
    .post_parse  = remove_post_parse,
    .complete    = remove_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_READ,
        .mounts  = true,
    },
    .dispatch    = remove_dispatch,
};
