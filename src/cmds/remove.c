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
#include <time.h>
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
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/commit.h"
#include "utils/hooks.h"

/**
 * One claim of the profile: a tracked path in storage terms, either kind — a
 * tree blob (FILE) or a metadata directory item (DIRECTORY).
 *
 * The profile's claims are the argument universe of a removal — never the view:
 * a disabled profile's paths must stay removable (the view holds only enabled
 * profiles), an unbound custom claim too (the view refuses it), and a shadowed
 * claim is still the profile's to remove (the view is precedence-resolved).
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
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The walk (remove_walk_t)
 * @return NULL: a collection fails nowhere
 */
static error_t remove_collect_claim(const profile_claim_t *claim, void *payload) {
    remove_walk_t *walk = payload;

    /* The name copied out of the walk's loan, and the kind off the type the decode
     * gave: a blob is a file claim whatever its filemode */
    walk->claims = arena_grow(
        walk->arena, walk->claims, &walk->claim_capacity, walk->claim_count + 1,
        sizeof(*walk->claims)
    );
    remove_claim_t *collected = &walk->claims[walk->claim_count++];
    collected->storage_path = arena_strdup(walk->arena, claim->storage_path);
    collected->kind = path_type_kind(claim->type);

    /* Where it stands on this machine, placed as it is collected: NULL for a
     * custom/ claim under a profile with no target here, which stands nowhere
     * and which its name still names. The name is one the walk validated — the
     * tree's shape check, the sheet's parse — so the resolve has no failure to
     * answer. */
    collected->filesystem_path = mount_resolve(
        walk->arena, walk->mounts, walk->profile, collected->storage_path
    );

    return NULL;
}

/**
 * Every claim the profile makes, each placed where this machine puts it
 *
 * The claims the walk shows, then those its own tree contradicts (core/profiles.h
 * profile_walk, profile_contradicted), collected by one visitor, under the reader's
 * policy: a removal reads strictly, refusing a sheet that will not load before
 * its preview as every writer does; a deletion tolerantly, so a profile whose
 * sheet will not load stays deletable. In order: the blobs in the tree's pre-order,
 * the directory claims that stand in the sheet's, the contradicted ones in the
 * sheet's.
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
 * places nowhere hands its name instead, the shape a hook comparing DOTTA_FILE_N
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
    string_array_init(&paths, arena);

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
 * One path a removal let go, and whose word decides its fate
 *
 * A candidate is a path the removal's Git effect no longer claims, joined to
 * the record standing at it. The file route's commit lets go of the claims the
 * arguments named and the directory entries its prune took once nothing tracked
 * stood beneath them; the profile route lets go of every path whose record names
 * the deleted profile. Only paths bearing this profile's record become candidates
 * — a record naming another profile is not ours to settle, and a path with no
 * record was never observed: nothing to settle.
 *
 * The routes part on one question — whether the user was asked. Only a named
 * path hears --delete-files with its own voice; a pruned entry lost its reason
 * rather than being asked for, and a profile deletion names the profile, not
 * its paths, so both leave the flag to the record's ownership (remove_settle).
 *
 * The path is the filesystem one, as this profile deploys it; arena-backed, command
 * lifetime. The record borrows from the read its producer made
 * (remove_paths_candidates, remove_profile_candidates).
 */
typedef struct {
    const char *path;             /* Filesystem path, as this profile deploys it */
    const state_record_t *record; /* The record at that path; names the removed profile */
    bool named;                   /* An argument's reach took it, so the flag speaks to it */
} remove_candidate_t;

/**
 * What the settle loop did, counted by fate
 *
 * The fates are counted apart: under --delete-files several can occur in one
 * removal — the named paths staged for the next apply, a rung it only emptied
 * and dotta never made released here and now — and a receipt that folded them
 * would name work apply is not going to do.
 */
typedef struct {
    size_t ordered;    /* Prune ordered — staged for the next apply */
    size_t released;   /* Record retired, the copy left standing */
    size_t fallback;   /* Record kept — a lower profile still provides the path */
} remove_settlement_t;

/**
 * Settle the candidates a removal let go — the one spelling of the fate rule
 *
 * For each candidate the subject is its record: one whose path the view that
 * remains still provides is a fallback — kept, it reads [reassigned] until apply
 * acknowledges it; one the view no longer provides takes the fate the user chose
 * — --delete-files orders the copy pruned at the next apply, the default releases
 * (the record retires, and the copy stays on disk — core/state.h state_retire).
 *
 * Asked under the caller's lock, of candidates read under it: the fates are written
 * blind (state_order_prune, state_retire), so the record they are decided from
 * is the one the lock holds (core/state.h state_begin). The view is built here
 * under the same lock, over the rows and the Git the route's own effects left —
 * the commit, the branch deletion, the disable — and only where there is a
 * candidate to ask it of.
 *
 * The flag is the user's word about the paths the removal NAMED, and only those
 * — named by the resolver's reach, not the typed line: an argument takes the
 * exact claim and every claim beneath a named directory (naming a directory means
 * untracking it whole), a named blob alone (remove_resolve), and the flag speaks
 * for all of them. The flag alone cannot make dotta delete a path it never made:
 * cleanup reads the order ahead of the ownership gate, by design, since a named
 * path the user wants gone must go whether dotta deployed it or only ever found
 * it. For a path the user did not name there is nothing to read ahead of, so
 * the gate answers, and it is read here because the record that carries it is
 * about to retire: dotta takes back what it created on the way in and leaves
 * what it merely found. The flag stays a ceiling over both — a plain remove
 * promises release and deletes nothing, whoever made the path.
 *
 * One loop for both routes because the rule drifted while each spelled its own:
 * a let-go record's fate must not turn on which removal retired it. The gate
 * here is what makes the analysis's order-before-gate read sound — an order is
 * born only for a path the user named or a copy dotta deployed (state_order_prune's
 * birth rule, core/state.h).
 *
 * Fates are counted as they enter the transaction; on error the caller rolls
 * back and zeroes its settlement — the rollback takes the writes with it.
 */
static error_t remove_settle(
    const dotta_ctx_t *ctx,
    const remove_candidate_t *candidates,
    size_t count,
    bool delete_files,
    remove_settlement_t *settlement
) {
    /* Nothing let go is recorded: no view to ask, and nothing to write */
    if (count == 0) return NULL;

    /* The view that remains — what still provides each candidate now */
    manifest_t *after = NULL;
    error_t err = manifest_build(ctx->run.repo, ctx->run.state, ctx->arena, &after);
    if (err) return err;

    /* The settle's one moment: every order it places carries it (state_order_prune) */
    time_t now = time(NULL);

    for (size_t i = 0; i < count; i++) {
        const remove_candidate_t *candidate = &candidates[i];

        if (manifest_lookup(after, candidate->path)) {
            settlement->fallback++;
        } else if (delete_files && (candidate->named || candidate->record->deployed_at > 0)) {
            err = state_order_prune(ctx->run.state, candidate->path, now);
            if (err) return err;
            settlement->ordered++;
        } else {
            err = state_retire(ctx->run.state, candidate->path);
            if (err) return err;
            settlement->released++;
        }
    }

    return NULL;
}

/**
 * The candidates a removal of paths settles, as the record stands now
 *
 * The paths the commit let go, as this profile deploys them, each joined to the
 * record standing at it by a lookup in one read (state_find_record): the claims
 * the arguments took, and the directory entries the commit's prune took. A
 * candidate exists only where one of this profile's records stands; a claim that
 * stands nowhere on this machine (custom/ under a profile with no target here)
 * names nothing to settle, and is not one.
 *
 * The two buckets are placed differently because they were placed already, or
 * never: a removed claim carries the path the resolver established before the
 * match (remove_resolve), while a pruned directory entry was no claim of the
 * arguments and is placed here.
 *
 * One candidate a path: what the commit let go at one place — a blob and the
 * directory claim at its own name, two names one binding places together, or a
 * claim and a rung the prune let go there — joins one record, which is settled
 * once. The claims come first, so a path an argument took is named however else
 * the commit let it go.
 *
 * Asked twice by its one caller (remove_paths): before the lock, whether there
 * is anything to settle, and under it, what the settle acts on.
 */
static error_t remove_paths_candidates(
    const dotta_ctx_t *ctx,
    const char *profile,
    const remove_claim_t *claims,
    size_t claim_count,
    const string_array_t *pruned,
    remove_candidate_t **out,
    size_t *out_count
) {
    *out = NULL;
    *out_count = 0;

    /* The record, one read — empty where the database does not exist */
    state_record_t *records = NULL;
    size_t record_count = 0;
    error_t err = state_records(ctx->run.state, ctx->arena, &records, &record_count);
    if (err) return err;
    if (record_count == 0) return NULL;

    /* Room for every path, and the paths already joined, by a seen-set's one
     * probe over the candidates' own strings (base/hashmap.h hashmap_add) */
    remove_candidate_t *candidates = arena_calloc(
        ctx->arena, claim_count + pruned->count, sizeof(*candidates)
    );
    hashmap_t *joined = hashmap_borrow(ctx->arena, claim_count + pruned->count);
    size_t count = 0;

    /* The claims the arguments took: the user's word reaches all of them
     * (remove_settle). Each joined to its record by a lookup in the read
     * (state_find_record), once a path. */
    for (size_t i = 0; i < claim_count; i++) {
        const char *filesystem_path = claims[i].filesystem_path;
        if (!filesystem_path) continue;
        const state_record_t *record = state_find_record(records, record_count, filesystem_path);
        if (!record || strcmp(record->profile, profile) != 0) continue;
        if (!hashmap_add(joined, filesystem_path, NULL)) continue;
        candidates[count++] = (remove_candidate_t){
            .path = filesystem_path, .record = record, .named = true
        };
    }

    /* The entries the commit's prune took: nobody asked for them, so the flag
     * does not speak to them — but where a claim the arguments took stands at
     * one, it was joined above, named. One this machine cannot place stands
     * nowhere, and no record of this run's can be there. */
    for (size_t i = 0; i < pruned->count; i++) {
        const char *filesystem_path = mount_resolve(
            ctx->arena, ctx->run.mounts, profile, pruned->entries[i]
        );
        if (!filesystem_path) continue;
        const state_record_t *record = state_find_record(records, record_count, filesystem_path);
        if (!record || strcmp(record->profile, profile) != 0) continue;
        if (!hashmap_add(joined, filesystem_path, NULL)) continue;
        candidates[count++] = (remove_candidate_t){
            .path = filesystem_path, .record = record, .named = false
        };
    }

    *out = candidates;
    *out_count = count;
    return NULL;
}

/**
 * The candidates a profile's deletion settles, as the record stands now
 *
 * Every record naming the profile, whether it was enabled or not, and whether
 * its tree still claimed the path or had let it go — the user is deleting the
 * profile and its files. None is named: a deletion names the profile, not its
 * paths, so --delete-files speaks only through the ownership gate (remove_settle),
 * and an observed record — a path dotta found rather than made — releases rather
 * than prunes.
 *
 * Asked twice by its one caller (remove_profile): before the prompt, for the
 * preview and whether there is anything to settle, and under the lock, what the
 * settle acts on.
 */
static error_t remove_profile_candidates(
    const dotta_ctx_t *ctx,
    const char *profile,
    remove_candidate_t **out,
    size_t *out_count
) {
    *out = NULL;
    *out_count = 0;

    /* The record, one read — empty where the database does not exist */
    state_record_t *records = NULL;
    size_t record_count = 0;
    error_t err = state_records(ctx->run.state, ctx->arena, &records, &record_count);
    if (err) return err;
    if (record_count == 0) return NULL;

    remove_candidate_t *candidates = arena_calloc(ctx->arena, record_count, sizeof(*candidates));
    size_t count = 0;

    for (size_t i = 0; i < record_count; i++) {
        if (strcmp(records[i].profile, profile) != 0) continue;
        candidates[count++] = (remove_candidate_t){
            .path = records[i].filesystem_path, .record = &records[i], .named = false
        };
    }

    *out = candidates;
    *out_count = count;
    return NULL;
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
        if (strcmp(storage_path, named[i]) == 0 ||
            str_path_beneath(storage_path, named[i], strlen(named[i]))) {
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
 * every claim beneath it: naming a directory means untracking it whole. A claim
 * is removed once, however many arguments match it.
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
 * the name outright, the hook's file list renders it where there is no path to
 * hand over, and the overlap analysis and the record read the NULL as the fact
 * it is.
 *
 * @param ctx Dispatch context (must not be NULL). ctx->run.mounts covers HOME,
 *            ROOT, and every enabled profile's binding.
 * @param profile The base of the caller's draft: the profile at the head the
 *                commit will have as its parent (must not be NULL)
 * @param opts The options: the profile's name, the arguments, --force (must not
 *             be NULL)
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
        if (err) {
            if (!opts->force) return err;
            /* With --force, skip this path: its error is dropped, one per refused
             * argument */
            output_warning(
                ctx->out, OUTPUT_VERBOSE, "Skipping invalid path '%s': %s",
                opts->paths[i], error_line(err)
            );
            continue;
        }

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

        /* The prefix the claims beneath the subject join under: the subject itself,
         * but at the filesystem root, whose key is "/" and whose prefix is "" —
         * the mount table's two spellings of it (infra/mount.c join_prefix) —
         * so "/" is a root like any other: what stands at it is at it, and every
         * absolute path is beneath it */
        const char *prefix = strcmp(subject, "/") == 0 ? "" : subject;
        const size_t prefix_len = strlen(prefix);

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
            if (strcmp(key, subject) != 0 && !str_path_beneath(key, prefix, prefix_len)) {
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
            if (!opts->force) {
                return error_create(
                    ERR_NOT_FOUND, "Path '%s' not found in profile '%s'",
                    opts->paths[i], opts->profile
                );
            }
            /* With --force, warn and skip */
            output_warning(
                ctx->out, OUTPUT_VERBOSE, "Path '%s' not found in profile, skipping",
                opts->paths[i]
            );
        }
    }

    /* Compact to the taken claims. */
    size_t taken_count = 0;
    for (size_t j = 0; j < claim_count; j++) {
        if (taken[j]) claims[taken_count++] = claims[j];
    }

    /* Check if the arguments took any claims */
    if (taken_count == 0) {
        return error_create(
            ERR_NOT_FOUND, "No paths found to remove from profile '%s'", opts->profile
        );
    }

    /* The claims are the command arena's, as the universe they were cut from */
    *out = claims;
    *out_count = taken_count;
    return NULL;
}

/**
 * By filesystem path, then by profile
 *
 * Equal paths sort together, so the rows standing at one path form a contiguous
 * run; the profile breaks the tie, and the order is total because one profile
 * places one row per path. The name would not be: two profiles can hold one name
 * at one path.
 */
static int remove_filesystem_order(const void *a, const void *b) {
    const manifest_row_t *const *ra = a;
    const manifest_row_t *const *rb = b;

    int by_path = strcmp((*ra)->filesystem_path, (*rb)->filesystem_path);

    return by_path ? by_path : strcmp((*ra)->profile, (*rb)->profile);
}

/**
 * filesystem path → the rows every local profile but `exclude` places there
 *
 * Each profile read once through its own view of its head under this machine's
 * table, so a claim is keyed by where it stands and never by what it is called:
 * two profiles bound at two targets holding one name are two paths and meet no
 * key of each other's, and one profile's two names for one path are one row and
 * one entry. A claim this machine cannot place stands nowhere and is not indexed.
 * Directory claims are indexed like any row — the profile claims the directory,
 * and a caller asking who else is at a place is owed it.
 *
 * The map, its keys — each a row's own path string — and its values, each a run
 * of the rows themselves, are the command's arena's, as the rows are: nothing
 * frees the index.
 *
 * Complete or an error: a short index is an "also in" a user reads as complete.
 * What a failure means is remove_paths' to say, and it is advisory: it says what
 * it could not read and drops the section rather than refuse the untrack, since
 * a local profile nobody enabled must not stop the repair and must not hide a
 * claim in silence either.
 *
 * Cost: one view per profile — a tree walk and a sheet load each — then O(T log
 * T) over T placed rows for the runs.
 *
 * Reader: remove_overlaps.
 *
 * @param ctx Dispatch context (must not be NULL): the repository, this machine's
 *            mount table, and the arena the index, its keys and its runs live in
 * @param exclude A profile to leave out, or NULL for every one of them
 * @param out_index filesystem path (const char *) -> manifest_rows_t * (must not
 *                  be NULL; NULL on a failure)
 * @return Error or NULL on success
 */
static error_t remove_build_filesystem_index(
    const dotta_ctx_t *ctx,
    const char *exclude,
    hashmap_t **out_index
) {
    CHECK_NULL(ctx);
    CHECK_NULL(out_index);

    *out_index = NULL;

    /* The profiles, in the arena the index lives in */
    string_array_t profiles;
    error_t err = gitops_list_branches(ctx->run.repo, ctx->arena, &profiles);
    if (err) return err;

    /* Every placed row of every profile, gathered before any of it is keyed:
     * each view's rows as it lends them, a slot per listed profile — the excluded
     * one's left empty — and how many they are, so the list below is allocated
     * once and typed from its first slot. The rows are the arena's, as the views
     * they came from are. */
    manifest_rows_t *placed = arena_calloc(ctx->arena, profiles.count, sizeof(*placed));
    size_t total = 0;
    for (size_t i = 0; i < profiles.count; i++) {
        if (exclude && strcmp(profiles.entries[i], exclude) == 0) continue;

        profile_t *profile = NULL;
        manifest_t *view = NULL;
        err = profile_load(ctx->run.repo, profiles.entries[i], &profile);
        if (!err) err = manifest_build_profile(profile, ctx->run.mounts, ctx->arena, &view);
        profile_free(profile);
        if (err) return err;

        placed[i] = manifest_rows(view);
        total += placed[i].count;
    }

    /* The runs: every row in the one list, sorted so the rows standing at one
     * path are adjacent. A list of none is still a place of its own, never the
     * NULL qsort may not be handed even with nothing to sort (C11 7.22.5). */
    const manifest_row_t **rows = arena_calloc(ctx->arena, total, sizeof(*rows));
    size_t row_count = 0;
    for (size_t i = 0; i < profiles.count; i++) {
        for (size_t j = 0; j < placed[i].count; j++) rows[row_count++] = placed[i].entries[j];
    }
    qsort(rows, row_count, sizeof(*rows), remove_filesystem_order);

    hashmap_t *index = hashmap_borrow(ctx->arena, row_count);

    for (size_t i = 0; i < row_count;) {
        const char *filesystem_path = rows[i]->filesystem_path;

        size_t n = 0;
        while (i + n < row_count &&
            strcmp(rows[i + n]->filesystem_path, filesystem_path) == 0) n++;

        /* The value is the run itself: the rows standing at the path, every other
         * profile's own, lent in place */
        manifest_rows_t *run = arena_calloc(ctx->arena, 1, sizeof(*run));
        *run = (manifest_rows_t){ rows + i, n };

        /* The key is the row's own string — hashmap_borrow keeps the pointer
         * and compares by content, and the row lives as long as the map. */
        hashmap_set(index, filesystem_path, run);
        i += n;
    }

    *out_index = index;

    return NULL;
}

/**
 * One path this removal shares with other profiles
 *
 * The claim removed there — the first, where the removal takes two at one place:
 * two of the profile's names, or a blob and the directory claim at its own name
 * — and who else stands there under what name.
 */
typedef struct {
    const char *filesystem_path;
    const char *storage_path;
    const manifest_rows_t *others;
} remove_overlap_t;

/**
 * The multi-profile section, as data
 *
 * One entry per path this removal shares with another profile, and the one fact
 * its closing line reads: whether the view's winner at any of those paths is a
 * different enabled profile, which is what makes a removal change nothing on disk.
 */
typedef struct {
    const remove_overlap_t *entries;
    size_t count;
    bool provided_by_other;
} remove_overlaps_t;

/**
 * What this removal shares with the other profiles
 *
 * Keyed by path, not by name (remove_build_filesystem_index): two profiles bound
 * at two targets holding one name are two paths and share nothing, while a portable
 * name and a binding's name at one place do share and used to go unsaid. A claim
 * this machine places nowhere meets nothing and is skipped.
 *
 * The index is read once per path and taken out of the map, so two claims the
 * removal takes at one place — two of the profile's names, or a blob and the
 * directory claim at its own name — are one line and one count: the data is the
 * dedup, and no seen-set or second scan is needed.
 *
 * `provided_by_other` is the view's fact, not the record's: the winner at the
 * path is another enabled profile, so the path stays as it is. It is asked only
 * where the index answered, which is sound — a winner other than this profile
 * holds a row at the path and is therefore in the index, the excluded profile
 * being this profile itself.
 *
 * The view is built here, tolerantly: remove must run on an enabled set the builder
 * refuses (that is how an offending claim gets untracked), so a failed build
 * leaves the bit false and the closing lines keep their neutral wording. The
 * index is not tolerant — a short index is an "also in" a user reads as complete
 * — and its failure is the caller's to weigh.
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

    hashmap_t *index = NULL;
    error_t err = remove_build_filesystem_index(ctx, current_profile, &index);
    if (err) return err;

    /* Tolerant (the header): a view the builder refuses leaves `view` NULL and
     * the bit false, its error dropped */
    manifest_t *view = NULL;
    (void) manifest_build(ctx->run.repo, ctx->run.state, ctx->arena, &view);

    remove_overlap_t *overlaps = arena_calloc(
        ctx->arena, claim_count, sizeof(*overlaps)
    );

    size_t count = 0;
    bool provided_by_other = false;
    for (size_t i = 0; i < claim_count; i++) {
        const remove_claim_t *claim = &claims[i];
        if (!claim->filesystem_path) continue;

        void *others = NULL;
        if (!hashmap_remove(index, claim->filesystem_path, &others)) continue;

        overlaps[count++] = (remove_overlap_t){
            claim->filesystem_path, claim->storage_path, others
        };

        const manifest_row_t *row = manifest_lookup(view, claim->filesystem_path);
        if (row && strcmp(row->profile, current_profile) != 0) {
            provided_by_other = true;
        }
    }

    *out = (remove_overlaps_t){ overlaps, count, provided_by_other };

    return NULL;
}

/**
 * Print the overlap section
 *
 * One line per shared path: the path, then each other profile and — where its
 * name for the place differs from the removed claim's — the name it holds it
 * under, since under two bindings one path wears two names. The closing line
 * names the fate `delete_files` chose.
 */
static void remove_print_overlaps(
    output_t *out,
    const remove_overlaps_t *overlaps,
    const char *current_profile,
    bool delete_files
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
        for (size_t j = 0; j < overlap->others->count; j++) {
            const manifest_row_t *other = overlap->others->entries[j];

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
        "These paths will be removed only from profile '%s'.",
        current_profile
    );

    if (overlaps->provided_by_other) {
        output_warning(
            out, OUTPUT_NORMAL,
            "Some paths are provided by another enabled profile."
        );
        output_info(
            out, OUTPUT_NORMAL,
            "Those paths will remain on the filesystem."
        );
    } else if (delete_files) {
        /* The record rule in one clause: the fate applies only where nothing
         * still provides the path — a remaining claimant makes it a fallback,
         * reassigned on apply, not pruned. */
        output_info(
            out, OUTPUT_NORMAL,
            "Paths deployed from '%s' will be pruned on the next 'dotta apply' "
            "unless another enabled profile still provides them.",
            current_profile
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL,
            "Paths deployed from '%s' stay on the filesystem.",
            current_profile
        );
    }
    output_gap(out, OUTPUT_NORMAL);
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
 * question is owed: --force, a dry run, a removal below the threshold
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

    /* Skip confirmation for dry run */
    if (opts->dry_run) return OUTPUT_ANSWER_YES;

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

    /* Prompt user */
    return output_ask(
        out, false, opts->delete_files
        ? "Remove %s from profile '%s'?\n(Deployed files will be pruned on 'dotta apply')"
        : "Remove %s from profile '%s'?\n(Deployed files will be released from management)",
        counts, opts->profile
    );
}

/**
 * Ask whether to delete a profile — or answer yes where --force gave the answer
 *
 * `counts` is the profile-holdings phrase from the count family
 * (output_format_counts, or its "counts unavailable" stand-in). The warning says
 * what the deletion takes whether or not the configuration asks.
 */
static output_answer_t remove_ask_profile(
    const char *profile,
    const char *counts,
    const cmd_remove_options_t *opts,
    const config_t *config,
    output_t *out
) {
    /* Skip confirmation if --force */
    if (opts->force) return OUTPUT_ANSWER_YES;

    output_gap(out, OUTPUT_NORMAL);
    output_warning(
        out, OUTPUT_NORMAL, "This will delete profile '%s' (%s)",
        profile, counts
    );
    if (opts->delete_files) {
        output_info(
            out, OUTPUT_NORMAL,
            "         Deployed paths will be pruned when you run 'dotta apply'."
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL,
            "         Deployed paths will be released from management."
        );
    }
    if (!config->confirm_destructive) return OUTPUT_ANSWER_YES;
    return output_ask_destructive(out, "Continue?");
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
    state_t *state = ctx->run.state;
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
        output_warning(
            out, OUTPUT_NORMAL, "Could not read the other profiles' claims: %s",
            error_line(err)
        );
        err = NULL;
    }

    /* The overlap section, BEFORE any operation */
    remove_print_overlaps(out, &overlaps, opts->profile, opts->delete_files);

    /* Dry run - just show what would be removed */
    if (opts->dry_run) {
        size_t dry_files = 0, dry_dirs = 0;
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
        if (opts->delete_files) {
            output_print(
                out, OUTPUT_NORMAL,
                "(Deployed paths would be removed on 'dotta apply')\n"
            );
        } else {
            output_print(
                out, OUTPUT_NORMAL,
                "(Deployed paths would be released from management)\n"
            );
        }

        goto cleanup;  /* err is NULL, will return success */
    }

    /* Confirm operation. Declined is the user's word, and no failure; unanswered
     * — the input ended before a line — nobody declined, and the run did not do
     * what it was asked: its refusal, naming the flag that answers in advance. */
    switch (remove_ask_paths(claims, claim_count, opts, config, out)) {
        case OUTPUT_ANSWER_YES:
            break;
        case OUTPUT_ANSWER_NO:
            output_print(out, OUTPUT_NORMAL, "Cancelled\n");
            goto cleanup;  /* err is NULL, will return success */
        case OUTPUT_ANSWER_NONE:
            err = error_create(
                ERR_VALIDATION, "Cannot remove from profile '%s' without a confirmation, "
                "and none was read; --force removes without asking", opts->profile
            );
            goto cleanup;
    }

    /* Selection: the accepted claims, before anything fires. In interactive mode
     * each claim is confirmed here, so the hooks and the plan below see exactly
     * what will happen — a declined claim is out before the pre-hook names the
     * set, and a claim no answer came for refuses the run: -i asked of each,
     * and a selection with one unanswered is no selection. */
    if (opts->interactive) {
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
                    output_info(out, OUTPUT_VERBOSE, "Skipped: %s", claims[i].storage_path);
                    break;
                case OUTPUT_ANSWER_NONE:
                    err = error_create(
                        ERR_VALIDATION, "Cannot choose what to remove: -i asks of each "
                        "path, and no answer was read for '%s'", claims[i].storage_path
                    );
                    goto cleanup;
            }
        }
        claim_count = kept;
    }
    if (claim_count == 0) {
        output_info(out, OUTPUT_NORMAL, "Nothing removed");
        goto cleanup;
    }

    /* The hooks are handed the paths the accepted claims stand at, each once
     * (remove_hook_paths), as placed by the resolver. Reached only on non-dry-run:
     * the dry-run branch above early-cleanups before this point, so dry_run is
     * always false here in practice — still passed for honesty. */
    const string_array_t hook_paths = remove_hook_paths(ctx->arena, claims, claim_count);
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .files      = hook_paths.entries,
        .file_count = hook_paths.count,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-remove hook */
    err = hook_fire_pre(config, out, &hook_inv);
    if (err) goto cleanup;

    /* The plan, on the draft: each claim leaves the commit by its own kind
     * (core/profiles.h profile_remove) — a FILE claim its tree entry and its
     * item, a DIRECTORY claim its item, the whole of its Git footprint — so a
     * directory claim at a removed file's name stays, carried, and stands again
     * once the blob is gone. Every claim is the base's own, taken once (the
     * resolver's universe is the base's walk and the claims its tree contradicts),
     * so neither of the removal's refusals can fire. */
    size_t removed_files = 0, removed_dirs = 0;

    /* The names this commit lets go, borrowed from the claims (arena), each once:
     * both kinds, since the message's unit is the path and a directory claim is
     * a path the commit gives up as surely as a blob is (utils/commit.h) — so a
     * blob and the directory claim at its own name are one name, listed and counted
     * once. The message reads them once and the arena outlives the call, so nothing
     * is copied. */
    const char **removed_paths = arena_calloc(
        ctx->arena, claim_count, sizeof(*removed_paths)
    );
    size_t removed_path_count = 0;
    hashmap_t *listed = hashmap_borrow(ctx->arena, claim_count);

    for (size_t i = 0; i < claim_count; i++) {
        const remove_claim_t *claim = &claims[i];

        err = profile_remove(draft, claim->kind, claim->storage_path);
        if (err) goto cleanup;
        if (claim->kind == PATH_KIND_DIRECTORY) removed_dirs++;
        else removed_files++;

        if (hashmap_add(listed, claim->storage_path, NULL)) {
            removed_paths[removed_path_count++] = claim->storage_path;
        }
        output_info(
            out, OUTPUT_VERBOSE, "Removed: %s%s",
            claim->storage_path, path_kind_suffix(claim->kind)
        );
    }

    /* One atomic commit: the file claims leave the tree, and the sheet follows
     * in the same tree write where its claims moved — pruned first of the derived
     * directory entries the removals left nothing tracked beneath, whose keys
     * come back in `pruned` (core/profiles.h profile_commit). All-or-nothing:
     * any failure up to here leaves every ref where it was. */
    commit_message_context_t msg_ctx = {
        .action        = COMMIT_ACTION_REMOVE,
        .profile       = opts->profile,
        .paths         = removed_paths,
        .path_count    = removed_path_count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };
    string_array_t pruned;   /* Directory entries the commit's prune took (storage paths) */
    string_array_init(&pruned, ctx->arena);
    err = profile_commit(draft, commit_message(ctx->arena, config, &msg_ctx), NULL, &pruned);
    if (err) goto cleanup;
    if (pruned.count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "Pruned %zu redundant directory entr%s",
            pruned.count, pruned.count == 1 ? "y" : "ies"
        );
    }

    /*
     * Architectural note: no filesystem deletion here. Only apply writes to a
     * managed filesystem path — core/deploy and core/cleanup are the only mutators
     * — so remove's whole effect is the commit above and the record below. The
     * deployed copy's fate is decided at the next apply, against the view standing
     * then.
     */

    /* The record phase: the record answers to the record. The candidates are
     * the paths this commit let go — the removed claims, and the directory entries
     * its prune took as redundant (an ancestor claim above the named path is
     * the common case), which left the view by the same commit — each joined to
     * its record and settled by the one rule (remove_settle).
     *
     * Enablement decides no fate: a record dotta holds under a disabled profile
     * is still dotta's record — the rule remove_profile runs over every record
     * naming the profile, run here over the candidates.
     *
     * Non-fatal throughout: Git succeeded and stands. A record this block fails
     * to write is an orphan the next apply reads, asks Git about, finds let go,
     * and releases — the default outcome, minus the prune order under
     * --delete-files. */
    remove_settlement_t settlement = { 0 };

    /* Whether there is anything to settle: a candidate as the record stands before
     * the lock, read on the READ handle — none where the database does not exist
     * — or the profile enabled here, under which another process can make one
     * while this command works: an apply deploying a path this commit let go, a
     * status observing one. A remove with neither takes no lock, and grows a
     * never-enabled repository no database: state_begin publishes the store's
     * dotta.db at first write intent (its contract, core/state.h). The one write
     * this cannot see coming is a record another process makes under the profile
     * after enabling it since this command began, left to the next apply as a
     * settle this block fails to write is. The deletion begins on the same two
     * (remove_profile). */
    remove_candidate_t *candidates = NULL;
    size_t candidate_count = 0;
    err = remove_paths_candidates(
        ctx, opts->profile, claims, claim_count, &pruned, &candidates, &candidate_count
    );

    if (!err && (candidate_count > 0 || state_enabled(state, opts->profile))) {
        err = state_begin(state);

        /* What the settle acts on, read again under the lock: the read above
         * decided only whether to take it, and another process can write the
         * record between the two — or while this one waits for it. */
        if (!err) {
            err = remove_paths_candidates(
                ctx, opts->profile, claims, claim_count, &pruned,
                &candidates, &candidate_count
            );
        }
        if (!err) {
            err = remove_settle(
                ctx, candidates, candidate_count, opts->delete_files, &settlement
            );
        }

        /* Commit transaction */
        if (!err) err = state_commit(state);

        /* A step refused, the lock goes back with every write it held */
        if (err) {
            state_rollback(state);
            settlement = (remove_settlement_t){ 0 };   /* the rollback took the writes with it */
        }
    }

    /* One phase, one sentence, whichever step refused: the record phase's, as
     * add's, update's and apply's say it — each refusal beneath names its own
     * step, the read, the lock or the commit. Non-fatal: the commit to Git stands,
     * so the refusal is warned and the command goes on. */
    if (err) {
        output_warning(out, OUTPUT_NORMAL, "Failed to update the record: %s", error_line(err));
        err = NULL;
    } else if (settlement.ordered + settlement.released + settlement.fallback > 0) {
        if (opts->delete_files) {
            output_info(
                out, OUTPUT_VERBOSE,
                "Record: %zu staged for removal, %zu released, %zu fallback%s",
                settlement.ordered, settlement.released, settlement.fallback,
                settlement.fallback == 1 ? "" : "s"
            );
        } else {
            output_info(
                out, OUTPUT_VERBOSE,
                "Record: %zu released, %zu fallback%s",
                settlement.released, settlement.fallback,
                settlement.fallback == 1 ? "" : "s"
            );
        }
    }

    /* Execute post-remove hook */
    hook_fire_post(config, out, &hook_inv);

    /* Success */
    char counts[64];
    remove_format_counts(counts, sizeof(counts), removed_files, removed_dirs);
    output_success(
        out, OUTPUT_NORMAL, "Removed %s from profile '%s'",
        counts, opts->profile
    );
    /* The hint speaks only for records actually settled, and for the fate they
     * took rather than the flag that was typed: an order is work waiting for
     * apply, a release is already done. Nothing recorded — or a record phase
     * that failed with its warning — leaves the success line to stand alone. */
    if (settlement.ordered > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Run 'dotta apply' to remove paths from filesystem"
        );
    } else if (settlement.released > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Paths released from management (no apply needed)"
        );
    }

cleanup:
    /* Free all resources in reverse order of allocation. state is borrowed from
     * the dispatcher — do not free it. state_rollback is a no-op if no transaction
     * is active, so it safely closes any partially-begun record-update transaction
     * on error paths. */
    state_rollback(state);
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
    state_t *state = ctx->run.state;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Initialize all resources to NULL */
    error_t err = NULL;
    profile_t *profile = NULL;
    const char *remote_name = NULL;
    const char *remote_url = NULL;

    /* Is the profile here? Git's answer or Git's error: an unreadable ref is
     * not an absence, and --force must not read one as "already gone". */
    bool exists = false;
    err = gitops_branch_exists(repo, opts->profile, &exists);
    if (err) goto cleanup;
    if (!exists) {
        if (!opts->force) {
            err = error_create(ERR_NOT_FOUND, "Profile '%s' does not exist", opts->profile);
            goto cleanup;
        }
        /* With --force, just warn and exit */
        output_warning(
            out, OUTPUT_VERBOSE, "Profile '%s' does not exist",
            opts->profile
        );
        goto cleanup;  /* err is NULL, will return success */
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
     * in the loader's line, which names the profile */
    err = profile_load_sheet(profile);
    if (err) {
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

    /* Dry run */
    if (opts->dry_run) {
        output_print(
            out, OUTPUT_NORMAL, "Would delete profile '%s' (%s)\n",
            opts->profile, counts
        );
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Check for unpushed changes, and detect the remote: remote_name is kept
     * for pushing the deletion below. */
    bool has_unpushed = false;
    bool is_local_only = false;

    /* Resolve remote name + URL up-front: the URL feeds the credential helper
     * for the deletion's push further down (its transfer context). One resolve,
     * two consumers. No remote configured is an answer — the profile is this
     * repository's alone (sys/gitops.h names this read) — and every other failure
     * is the run's, joined below with the upstream's own. */
    err = gitops_resolve_default_remote(
        repo, ctx->arena, &remote_name, &remote_url
    );
    if (error_code(err) == ERR_NOT_FOUND) {
        is_local_only = true;
        err = NULL;
    } else if (!err) {
        /* A remote: where the profile stands against it */
        upstream_info_t upstream_info;
        err = upstream_analyze_profile(
            repo, remote_name, opts->profile, &upstream_info
        );
        if (!err) {
            /* Never pushed, or ahead of what it pushed — the one finding the
             * warning below is for */
            is_local_only = upstream_info.state == UPSTREAM_NO_REMOTE;
            has_unpushed = upstream_info.state == UPSTREAM_LOCAL_AHEAD ||
                upstream_info.state == UPSTREAM_DIVERGED;
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

    /* Warn about unpushed changes (only if profile has remote tracking) */
    if (has_unpushed && !opts->force) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "Profile '%s' has unpushed changes!", opts->profile);
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta sync' first to avoid data loss");
    } else if (is_local_only) {
        /* Inform about local-only status in verbose mode (not a warning) */
        output_info(
            out, OUTPUT_VERBOSE, "Note: Profile '%s' is local-only (not pushed to remote)",
            opts->profile
        );
    }

    /* The candidates as the record stands before the prompt, on the borrowed
     * state: the preview's, and whether there is anything to settle once the
     * branch is gone. Under spec-driven READ the handle is always non-NULL here
     * (the dispatcher's), and state_load for a missing DB still returns a usable
     * handle (DB-less, reads degrade to empty) — no defensive fallback needed.
     * The settle reads them again under its lock: the prompt and the pre-remove
     * hook stand between the two, and another process can write the record there
     * — an apply that adopts or deploys this profile's files, from another terminal
     * or from the hook. Failure is non-fatal — warn and decide over what was
     * read; what this run cannot settle, the next apply reads as orphans and
     * releases. */
    remove_candidate_t *candidates = NULL;
    size_t candidate_count = 0;
    size_t deployed_count = 0;
    remove_settlement_t settlement = { 0 };
    err = remove_profile_candidates(ctx, opts->profile, &candidates, &candidate_count);
    if (err) {
        /* The store's refusal says the read it refused */
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
        err = NULL;
    }
    for (size_t i = 0; i < candidate_count; i++) {
        if (candidates[i].record->deployed_at > 0) deployed_count++;
    }

    /* The fates ahead of the prompt, from the same gate the settle reads: with
     * --delete-files the deployed entries are ordered pruned and the observed
     * rest releases; without it everything releases (informational, not a warning).
     * The view that remains does not exist yet, so a fallback — a path a lower
     * profile still provides — is promised the fate it will not take; the receipt
     * corrects it, as it does a record another process moved before the lock.
     * With none, the two read the same gate over the same records and agree. */
    if (candidate_count > 0) {
        output_gap(out, OUTPUT_VERBOSE);
        if (opts->delete_files && deployed_count > 0) {
            if (deployed_count < candidate_count) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Note: Profile '%s' has %zu managed entr%s (%zu deployed)",
                    opts->profile, candidate_count,
                    candidate_count == 1 ? "y" : "ies", deployed_count
                );
                output_info(
                    out, OUTPUT_VERBOSE,
                    "      The deployed entries will be pruned when you run 'dotta apply';"
                );
                output_info(
                    out, OUTPUT_VERBOSE,
                    "      the rest will be released from management."
                );
            } else {
                output_info(
                    out, OUTPUT_VERBOSE, "Note: Profile '%s' has %zu deployed entr%s",
                    opts->profile, deployed_count, deployed_count == 1 ? "y" : "ies"
                );
                output_info(
                    out, OUTPUT_VERBOSE,
                    "      These will be pruned when you run 'dotta apply'."
                );
            }
        } else {
            output_info(
                out, OUTPUT_VERBOSE, "Note: Profile '%s' has %zu managed entr%s",
                opts->profile, candidate_count, candidate_count == 1 ? "y" : "ies"
            );
            output_info(
                out, OUTPUT_VERBOSE,
                "      These will be released from management."
            );
        }
    }

    /* Confirm deletion. Declined is the user's word, and no failure; unanswered
     * — off a terminal, where a destructive question is never asked — nobody
     * declined: the run's refusal, naming the flag that answers in advance. */
    switch (remove_ask_profile(opts->profile, counts, opts, config, out)) {
        case OUTPUT_ANSWER_YES:
            break;
        case OUTPUT_ANSWER_NO:
            output_gap(out, OUTPUT_NORMAL);
            output_print(out, OUTPUT_NORMAL, "Cancelled\n");
            goto cleanup;  /* err is NULL, will return success */
        case OUTPUT_ANSWER_NONE:
            err = error_create(
                ERR_VALIDATION, "Cannot delete profile '%s' without a confirmation, "
                "which only a terminal gives; --force deletes it without asking",
                opts->profile
            );
            goto cleanup;
    }

    /* The hooks are handed the path of every claim the profile goes with, each
     * once, by the producer the file route's hooks read (remove_hook_paths):
     * HOME and ROOT place every home/ and root/ claim, and a custom/ claim with
     * no binding here hands its name. The list is the command arena's. */
    const string_array_t hook_paths = remove_hook_paths(ctx->arena, claims, claim_count);
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .files      = hook_paths.entries,
        .file_count = hook_paths.count,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-remove hook */
    err = hook_fire_pre(config, out, &hook_inv);
    if (err) goto cleanup;

    /* No filesystem deletion here either — see the Architectural note in
     * remove_paths: apply owns deferred filesystem cleanup. */

    /* Delete local branch */
    err = gitops_delete_branch(repo, opts->profile);
    if (err) goto cleanup;

    /* Post-deletion: the enabled set and the record, in one transaction — opened
     * only where there is, or can come to be, something to write: a record naming
     * the profile (the candidates read before the prompt), or the profile enabled
     * here, whose row must drop and under which another process can make one
     * while this command works. A repository with no database — never enabled,
     * nothing recorded — is left without one: state_begin publishes the store's
     * dotta.db at first write intent, and a deletion with nothing to settle is
     * not that. The one write this cannot see coming is a record another process
     * makes under the profile after enabling it since this command began, left
     * to the next apply as a settle this block fails to write is.
     *
     * The order of the branch deletion and this block does not matter: the view
     * is computed, and the prune order is the one fact the workspace reads for
     * these records — written once, here, after the branch is gone. The profile
     * leaves the enabled set where a row holds it under the lock, and every
     * candidate the lock reads is settled against the view that remains by the
     * one rule (remove_settle); a fallback's record reads [reassigned] P → Q
     * until apply deploys Q's, and an ordered copy's blob still opens with the
     * branch gone — the next apply's orphan compare reads it under the record's
     * own binding, and subkey derivation needs only the profile name.
     *
     * Non-fatal: the branch is gone and stands. A record this block fails to
     * write is an orphan the next apply reads, asks Git about, finds the branch
     * gone, and releases. */
    if (candidate_count > 0 || state_enabled(state, opts->profile)) {
        err = state_begin(state);

        /* The row and the record as the lock holds them: state_begin read the
         * rows inside it, and the candidates are read here */
        if (!err && state_enabled(state, opts->profile)) {
            err = state_disable_profile(state, opts->profile);
        }
        if (!err) {
            err = remove_profile_candidates(ctx, opts->profile, &candidates, &candidate_count);
        }
        if (!err) {
            err = remove_settle(
                ctx, candidates, candidate_count, opts->delete_files, &settlement
            );
        }

        /* Commit transaction */
        if (!err) err = state_commit(state);

        /* One phase, one sentence, whichever step refused — the lock, the row,
         * the read, the settle or the commit, each naming its own — as every
         * record phase says it; the lock goes back with every write it held.
         * Non-fatal: the branch is gone and stands. */
        if (err) {
            output_warning(out, OUTPUT_NORMAL, "Failed to update the record: %s", error_line(err));
            state_rollback(state);
            settlement = (remove_settlement_t){ 0 };   /* the rollback took the writes with it */
            err = NULL;
        } else if (settlement.ordered + settlement.released + settlement.fallback > 0) {
            if (opts->delete_files) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "%zu entr%s staged for removal, %zu released, %zu fallback%s",
                    settlement.ordered, settlement.ordered == 1 ? "y" : "ies",
                    settlement.released,
                    settlement.fallback, settlement.fallback == 1 ? "" : "s"
                );
            } else {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "%zu entr%s released from management, %zu fallback%s",
                    settlement.released, settlement.released == 1 ? "y" : "ies",
                    settlement.fallback, settlement.fallback == 1 ? "" : "s"
                );
            }
        }
    }

    /* Push the deletion to the remote, where there is one: sync needs it, since
     * other repositories learn the branch is gone only from there. */
    if (remote_name && !is_local_only) {
        output_info(
            out, OUTPUT_NORMAL, "Pushing profile deletion to remote '%s'...",
            remote_name
        );

        /* remote_url was resolved alongside remote_name above. NULL is legal —
         * unauthenticated paths still work, helper approve/reject become no-ops. */
        transfer_options_t del_opts = { .output = out, .url = remote_url };
        transfer_context_t *del_xfer = transfer_context_create(&del_opts);
        err = gitops_delete_remote_branch(repo, remote_name, opts->profile, del_xfer);
        transfer_context_free(del_xfer);
        if (err) {
            /* Non-fatal: the local branch is already deleted, so what failed is
             * the sync's half alone — warned, and the operation stands. */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to push deletion to remote: %s",
                error_line(err)
            );
            output_info(
                out, OUTPUT_NORMAL,
                "         The profile was deleted locally, but sync could fail."
            );
            output_info(
                out, OUTPUT_NORMAL,
                "         You can manually push the deletion with: git push %s :%s",
                remote_name, opts->profile
            );
            err = NULL;
        } else {
            output_info(out, OUTPUT_NORMAL, "Profile deletion pushed to remote");
        }
    }

    /* The prune itself happens on `apply` — see the Architectural note in
     * remove_paths. */

    /* Execute post-remove hook */
    hook_fire_post(config, out, &hook_inv);

    /* Success message: every exit before the deletion is behind us (dry run,
     * cancel, error) */
    output_success(out, OUTPUT_NORMAL, "Profile '%s' deleted", opts->profile);

    /* The hint speaks only for records actually settled, and for the fate they
     * took rather than the flag that was typed: an order is work waiting for
     * apply, a release is already done. Nothing recorded — or a settle that failed
     * with its warning — leaves the success line to stand alone. */
    if (settlement.ordered > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Run 'dotta apply' to remove deployed paths from filesystem"
        );
    } else if (settlement.released > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Paths released from management (no apply needed)"
        );
    }

cleanup:
    /* state is borrowed from the dispatcher — do not free it. state_rollback is
     * a no-op if no transaction is active; this safely closes any partially-begun
     * record-update or post-deletion transaction on an error path. The profile
     * is freed once its count is read; here only a refusal before that frees it. */
    profile_free(profile);
    state_rollback(state);

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

    /* Interactive mode requires a terminal for user prompts — refused at entry,
     * before any hook fires or any work begins */
    if (opts->interactive && !isatty(STDIN_FILENO)) {
        return error_create(
            ERR_INVALID_ARG,
            "Interactive mode requires a terminal (stdin is not a TTY)"
        );
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
 * Walk visitor: a directory claim offered where its own name would take it —
 * where no blob stands at that name (remove_resolve). A file claim is the refspecs'
 * to offer (cmds/completion.h completion_refspecs).
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
     * classification draws its line: a claim beneath a blob is its own name's
     * to take, one at a blob's name is not. A gitlink's name names no blob. */
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
 * — then the claims of that profile, shadowed and disabled ones included: its
 * files, and the directory claims its own names would take, slash-marked; nothing
 * after --delete-profile, which takes no path.
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
     * its own name would take it (remove_offer_directory), so the offer is the
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
        "delete-files",
        cmd_remove_options_t,delete_files,
        "Stage deployed items for removal on next apply"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_remove_options_t,dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG(
        "f force",
        cmd_remove_options_t,force,
        "Skip confirmation prompts"
    ),
    ARGS_FLAG(
        "i interactive",
        cmd_remove_options_t,interactive,
        "Prompt for each file"
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
    .summary     = "Remove paths from a profile or delete profile",
    .usage       =
        "%s remove [options] <profile> <path>...\n"
        "   or: %s remove [options] <profile> --delete-profile\n"
        "   or: %s remove [options] --profile <name> <path>...",
    .description =
        "Untrack paths — files and tracked directories — from a profile,\n"
        "optionally scheduling removal of the deployed copies, or delete\n"
        "the profile branch outright.\n",
    .notes       =
        "Operation Modes:\n"
        "  (default)           Remove paths from the profile branch. Deployed\n"
        "                      items are released from management and stay\n"
        "                      on the filesystem untouched.\n"
        "  --delete-files      Same as default, plus stage the deployed\n"
        "                      items for removal on the next '%s apply'.\n"
        "  --delete-profile    Delete the entire profile branch. No paths\n"
        "                      may be given; with --delete-files the deployed\n"
        "                      items are staged for removal as well.\n",
    .examples    =
        "  %s remove global ~/.bashrc                  # Untrack, keep on disk\n"
        "  %s remove darwin ~/.config/nvim -n          # Preview removal\n"
        "  %s remove darwin ~/.config/nvim --delete-files  # Remove on apply\n"
        "  %s remove staging --delete-profile          # Delete whole profile\n"
        "  %s remove staging --delete-profile --delete-files  # ...and its copies\n",
    .epilogue    =
        "See also:\n"
        "  %s profile disable <name>  # Stop deploying without deleting\n"
        "  %s apply                   # Carry out staged file removals\n",
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
