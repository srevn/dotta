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
#include "core/branch.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/state.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/stage.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/commit.h"
#include "utils/hooks.h"

/**
 * One claim of the profile branch: a tracked path in storage terms, either kind
 * — a tree blob (FILE) or a metadata directory item (DIRECTORY).
 *
 * The branch's claims are the argument universe of a removal — never the view:
 * a disabled profile's paths must stay removable (the view holds only enabled
 * profiles), an unbound custom claim too (the view refuses it), and a shadowed
 * claim is still the branch's to remove (the view is precedence-resolved).
 */
typedef struct {
    const char *storage_path;      /* arena */
    const char *filesystem_path;   /* arena; NULL when this machine places the
                                    * claim nowhere — an unbound custom/ one */
    path_kind_t kind;
} claim_t;

/**
 * One path a removal let go, and whose word decides its fate
 *
 * A candidate is a path the removal's Git effect no longer claims, joined to
 * the record standing at it. The file route's commit lets go of the claims the
 * arguments named and the directory entries the metadata step reaped once nothing
 * tracked stood beneath them; the profile route lets go of every path whose record
 * names the deleted profile. Only paths bearing this profile's record become
 * candidates — a record naming another profile is not ours to settle, and a path
 * with no record was never observed: nothing to settle.
 *
 * The routes part on one question — whether the user was asked. Only a named
 * path hears --delete-files with its own voice; a reaped entry lost its reason
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
} candidate_t;

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
} settlement_t;

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
 * untracking it whole, remove_resolve), and the flag speaks for all of them.
 * The flag alone cannot make dotta delete a path it never made: cleanup reads
 * the order ahead of the ownership gate, by design, since a named path the user
 * wants gone must go whether dotta deployed it or only ever found it. For a path
 * the user did not name there is nothing to read ahead of, so the gate answers,
 * and it is read here because the record that carries it is about to retire:
 * dotta takes back what it created on the way in and leaves what it merely found.
 * The flag stays a ceiling over both — a plain remove promises release and deletes
 * nothing, whoever made the path.
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
    const candidate_t *candidates,
    size_t count,
    bool delete_files,
    settlement_t *settlement
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
        const candidate_t *candidate = &candidates[i];

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
 * the arguments took, and the directory entries the metadata step pruned. A
 * candidate exists only where one of this profile's records stands; a claim that
 * stands nowhere on this machine (custom/ under a profile with no target here)
 * names nothing to settle, and is not one.
 *
 * The two buckets are placed differently because they were placed already, or
 * never: a removed claim carries the path the resolver established before the
 * match (remove_resolve), while a pruned directory entry was no claim of the
 * arguments and is placed here.
 *
 * Asked twice by its one caller (remove_paths): before the lock, whether there
 * is anything to settle, and under it, what the settle acts on.
 */
static error_t remove_paths_candidates(
    const dotta_ctx_t *ctx,
    const char *profile,
    const claim_t *claims,
    size_t claim_count,
    const string_array_t *pruned_dirs,
    candidate_t **out,
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

    candidate_t *candidates = arena_calloc(
        ctx->arena, claim_count + pruned_dirs->count, sizeof(*candidates)
    );
    size_t count = 0;

    /* The claims the arguments took: the user's word reaches all of them
     * (remove_settle). Each joined to its record by a lookup in the read
     * (state_find_record). */
    for (size_t i = 0; i < claim_count; i++) {
        const char *filesystem_path = claims[i].filesystem_path;
        if (!filesystem_path) continue;
        const state_record_t *record = state_find_record(records, record_count, filesystem_path);
        if (!record || strcmp(record->profile, profile) != 0) continue;
        candidates[count++] = (candidate_t){
            .path = filesystem_path, .record = record, .named = true
        };
    }

    /* The entries the metadata step pruned: nobody asked for them, so the flag
     * does not speak to them. One this machine cannot place stands nowhere, and
     * no record of this run's can be there. */
    for (size_t i = 0; i < pruned_dirs->count; i++) {
        const char *filesystem_path = mount_resolve(
            ctx->arena, ctx->run.mounts, profile, pruned_dirs->entries[i]
        );
        if (!filesystem_path) continue;
        const state_record_t *record = state_find_record(records, record_count, filesystem_path);
        if (!record || strcmp(record->profile, profile) != 0) continue;
        candidates[count++] = (candidate_t){
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
    candidate_t **out,
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

    candidate_t *candidates = arena_calloc(ctx->arena, record_count, sizeof(*candidates));
    size_t count = 0;

    for (size_t i = 0; i < record_count; i++) {
        if (strcmp(records[i].profile, profile) != 0) continue;
        candidates[count++] = (candidate_t){
            .path = records[i].filesystem_path, .record = &records[i], .named = false
        };
    }

    *out = candidates;
    *out_count = count;
    return NULL;
}

/**
 * Walk visitor: one entry of a profile tree, onto the listing where it is content
 *
 * A content blob's storage path is pushed onto the listing, the payload; the
 * branch's machinery is pruned with its subtree, a tree beneath a label is entered
 * and a gitlink passed; a name the storage grammar refuses is the walk's failure.
 */
static error_t remove_list_entry(
    const char *path,
    const git_tree_entry *entry,
    void *payload,
    gitops_next_t *next
) {
    string_array_t *paths = payload;

    /* The content gate: a managed path is a name in the grammar — beneath a label,
     * or the label's word alone, the namespace's own directory — and everything
     * else the branch carries is machinery, which no walk of content sees
     * (infra/label.h label_prefixes). Asked of every entry's whole name, a tree's
     * included, so a tree of machinery goes with everything beneath it. */
    if (!label_prefixes(path)) {
        *next = GITOPS_NEXT_SKIP;
        return NULL;
    }

    /* Content is a blob: a tree beneath a label is walked into, and a gitlink
     * claims nothing. */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return NULL;
    }

    /* The entry name is Git's, not this machine's. A tree can name a subtree
     * "..", and every consumer of a path from here joins it onto a root's spelling
     * (infra/mount.h mount_resolve) on the strength of its having been validated
     * where it was written — which holds for a branch this machine authored and
     * not for one that arrived by clone, sync or foreign push. So the shape is
     * checked where the tree is read, exactly as the branch's walk checks its
     * own (core/branch.c branch_step). Malformed here is corruption, not an entry
     * to skip: a walk that dropped it silently would leave the caller a listing
     * it cannot place and call it complete. */
    error_t err = label_validate_storage(path);
    if (err) return err;

    string_array_push(paths, path);
    return NULL;
}

/**
 * List deployable files in a Git tree
 *
 * Walks the tree past the branch's machinery (infra/label.h label_prefixes, the
 * content gate), and returns the storage paths of its content blobs. It takes
 * the tree its caller holds, so one read of the branch serves the walk and whatever
 * else the caller does with it.
 *
 * Complete or an error: an entry whose name the storage grammar refuses is
 * corruption and fails the walk rather than being skipped, since a listing short
 * by a name would still read as complete. A branch this machine authored holds
 * no such entry; one that arrived by clone, sync or foreign push can. A name is
 * never refused for its length: Git's only bound on one is memory. Every failure
 * is said under the profile, since the walk's own name a path in the tree and
 * never the branch it is, and no reader names it again.
 *
 * Reader: remove_resolve.
 *
 * @param tree Git tree to walk (must not be NULL)
 * @param profile The profile whose branch the tree is (must not be NULL)
 * @param arena Arena the listing lives in (must not be NULL)
 * @param out The storage paths (must not be NULL; left as it was on a failure)
 * @return Error or NULL on success
 */
static error_t remove_list_tree_files(
    const git_tree *tree,
    const char *profile,
    arena_t *arena,
    string_array_t *out
) {
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The walk pushes straight onto the listing, handed out once it is whole.
     * Its failures name a path in the tree — a name the grammar refused, a subtree
     * that would not load — and the profile is the where they do not say. */
    string_array_t paths;
    string_array_init(&paths, arena);
    error_t err = gitops_tree_walk(tree, remove_list_entry, &paths);
    if (err) return error_wrap(err, "Failed to list files in profile '%s'", profile);

    *out = paths;
    return NULL;
}

/**
 * Resolve the arguments to the claims they remove
 *
 * The claims array starts as everything the branch holds, in branch order (the
 * tree's blobs, then the directory items) — read from `tree`, the one the caller's
 * stage opened at, so the claims, the sheet and the commit describe one tip;
 * the arguments mark what they take, and the array compacts to just that.
 *
 * Where each claim stands is established before the match, not after it, because
 * the match is by the key the argument named (infra/path.h) and neither key is
 * manufactured from the other. A storage argument matches over the claims' names;
 * a path argument matches over the paths they were placed at — so `remove web
 * ~/jail/etc/x` takes the claim standing there under whatever name, and a root
 * takes everything beneath it. Either way an argument matches the exact claim
 * and — at a '/' boundary, never a false prefix like home/dir2 for home/dir —
 * every claim beneath it: naming a directory means untracking it whole. A claim
 * is removed once, however many arguments match it.
 *
 * A claim this machine places nowhere — an unbound custom/ one — keeps a NULL
 * path and no path argument reaches it; its name still does, which is how such
 * a claim is untracked at all. Nothing stands in for the path: the screens print
 * the name outright, the hook's file list renders it where there is no path to
 * hand over, and the overlap analysis and the record read the NULL as the fact
 * it is.
 *
 * The branch's metadata rides out through `metadata_out` for the commit's edit
 * — loaded once, where the directory claims are enumerated; an empty sheet when
 * the branch carries none (the loader's contract). Caller frees.
 *
 * @param ctx Dispatch context (must not be NULL). ctx->run.mounts covers HOME,
 *            ROOT, and every enabled profile's binding.
 * @param tree The branch's tree as the stage opened it — the universe of claims
 *            (must not be NULL)
 * @param claims_out The claims the arguments took, borrowed from ctx->arena (do
 *            not free)
 */
static error_t remove_resolve(
    const dotta_ctx_t *ctx,
    const git_tree *tree,
    const char *profile,
    char **input_paths,
    size_t path_count,
    const cmd_remove_options_t *opts,
    claim_t **claims_out,
    size_t *count_out,
    metadata_t **metadata_out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(input_paths);
    CHECK_NULL(opts);
    CHECK_NULL(claims_out);
    CHECK_NULL(count_out);
    CHECK_NULL(metadata_out);

    git_repository *repo = ctx->run.repo;
    const mount_table_t *mounts = ctx->run.mounts;
    output_t *out = ctx->out;

    /* Initialize all resources to NULL for safe cleanup */
    error_t err = NULL;
    metadata_t *metadata = NULL;

    /* The branch's claims, off the tree: its blobs, then the metadata's directory
     * claims. */
    string_array_t profile_files;
    err = remove_list_tree_files(tree, profile, ctx->arena, &profile_files);
    if (err) return err;

    err = metadata_load_from_tree(repo, tree, profile, &metadata);
    if (err) goto cleanup;

    size_t item_count = 0;
    size_t dir_count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &item_count);
    for (size_t i = 0; i < item_count; i++) {
        if (items[i]->kind == PATH_KIND_DIRECTORY) dir_count++;
    }

    claim_t *claims = NULL;
    bool *taken = NULL;            /* beside claims[j]: an argument took it */
    size_t claim_count = 0;
    if (profile_files.count + dir_count > 0) {
        claims = arena_calloc(
            ctx->arena, profile_files.count + dir_count, sizeof(claim_t)
        );
        taken = arena_calloc(
            ctx->arena, profile_files.count + dir_count, sizeof(bool)
        );
    }

    for (size_t i = 0; i < profile_files.count; i++) {
        claims[claim_count++] = (claim_t) {
            .storage_path = profile_files.entries[i], .kind = PATH_KIND_FILE
        };
    }

    for (size_t i = 0; i < item_count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY) continue;
        const char *key = items[i]->key;

        /* Same-profile rule as the branch's walk (core/branch.c branch_walk): a
         * key the tree holds as a blob cannot also stand as a directory claim —
         * the tree's blob outranks the stale item. Keeps every claim path unique,
         * so one argument takes one claim. */
        if (string_array_contains(&profile_files, key)) continue;

        claims[claim_count++] = (claim_t) {
            .storage_path = arena_strdup(ctx->arena, key), .kind = PATH_KIND_DIRECTORY
        };
    }

    /* Where each claim stands on this machine, or nowhere: the key a filesystem
     * argument matches against, established before the match rather than after
     * it. A custom/ claim under a profile with no target here stands nowhere
     * and gets none — a miss the filesystem arm below reads as "not this claim".
     * Every path here is a validated storage path (the tree walk's own gate and
     * the sheet's parse both refuse anything else), so the resolve has no failure
     * left to answer. */
    for (size_t j = 0; j < claim_count; j++) {
        claims[j].filesystem_path = mount_resolve(
            ctx->arena, mounts, profile, claims[j].storage_path
        );
    }

    /* Match each argument, marking the claims it takes */
    for (size_t i = 0; i < path_count; i++) {
        path_input_t arg;
        err = path_input_resolve(input_paths[i], ctx->arena, &arg);
        if (err) {
            if (!opts->force) goto cleanup;
            /* With --force, skip this path: its error is dropped, one per refused
             * argument */
            output_warning(
                out, OUTPUT_VERBOSE, "Skipping invalid path '%s': %s",
                input_paths[i], error_line(err)
            );
            err = NULL;
            continue;
        }

        /* The sum type, read at the use site and read once: a storage argument
         * keys against the claims' names and a path against where they stand,
         * the word alone among the names — every claim of its namespace being
         * beneath it — and the form that reaches a profile with no binding here,
         * whose custom/ claims stand nowhere for a path to match. The filesystem
         * root is spelled "" — the one prefix every absolute path is beneath,
         * as the table spells it and the pathspec reads it. */
        const char *subject = NULL;
        bool by_name = false;

        switch (arg.key) {
            case PATH_KEY_FILESYSTEM:
                subject = strcmp(arg.filesystem_path, "/") == 0 ? "" : arg.filesystem_path;
                break;

            case PATH_KEY_STORAGE:
                subject = arg.storage_path;
                by_name = true;
                break;
        }

        size_t subject_len = strlen(subject);
        size_t matches_found = 0;

        for (size_t j = 0; j < claim_count; j++) {
            const char *key = by_name ? claims[j].storage_path
                                      : claims[j].filesystem_path;
            if (!key) continue;                       /* it stands nowhere */

            /* The exact claim, or one beneath it at a directory boundary */
            if (strcmp(key, subject) != 0 &&
                !str_path_beneath(key, subject, subject_len)) continue;

            matches_found++;
            taken[j] = true;
        }

        if (matches_found == 0) {
            if (!opts->force) {
                err = error_create(
                    ERR_NOT_FOUND, "Path '%s' not found in profile '%s'",
                    input_paths[i], profile
                );
                goto cleanup;
            }
            /* With --force, warn and skip */
            output_warning(
                out, OUTPUT_VERBOSE, "Path '%s' not found in profile, skipping",
                input_paths[i]
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
        err = error_create(
            ERR_NOT_FOUND, "No paths found to remove from profile '%s'",
            profile
        );
        goto cleanup;
    }

    /* Success — the claims are arena-backed; the metadata rides out for the
     * commit's edit */
    *claims_out = claims;
    *count_out = taken_count;
    *metadata_out = metadata;
    metadata = NULL;

cleanup:
    /* Free all resources */
    if (metadata) metadata_free(metadata);

    return err;
}

/**
 * By filesystem path, then by profile
 *
 * Equal paths sort together, so the rows standing at one path form a contiguous
 * run; the profile breaks the tie, and the order is total because one branch
 * places one row per path. The name would not be: two branches can hold one name
 * at one path.
 */
static int remove_filesystem_order(const void *a, const void *b) {
    const manifest_row_t *const *ra = a;
    const manifest_row_t *const *rb = b;

    int by_path = strcmp((*ra)->filesystem_path, (*rb)->filesystem_path);

    return by_path ? by_path : strcmp((*ra)->profile, (*rb)->profile);
}

/**
 * filesystem path → the rows every local branch but `exclude` places there
 *
 * Each branch read once through its own view of its tip under this machine's
 * table, so a claim is keyed by where it stands and never by what it is called:
 * two profiles bound at two targets holding one name are two paths and meet no
 * key of each other's, and one profile's two names for one path are one row and
 * one entry. A claim this machine cannot place stands nowhere and is not indexed.
 * Directory claims are indexed like any row — the branch claims the directory,
 * and a caller asking who else is at a place is owed it.
 *
 * The map, its keys — each a row's own path string — and its values, each a run
 * of the rows themselves, are the command's arena's, as the rows are: nothing
 * frees the index.
 *
 * Complete or an error: a short index is an "also in" a user reads as complete.
 * What a failure means is remove_paths' to say, and it is advisory: it says what
 * it could not read and drops the section rather than refuse the untrack, since
 * a local branch nobody enabled must not stop the repair and must not hide a
 * claim in silence either.
 *
 * Cost: one view per branch — a tree walk and a sheet load each — then O(T log
 * T) over T placed rows for the runs.
 *
 * Reader: remove_overlaps.
 *
 * @param ctx Dispatch context (must not be NULL): the repository, this machine's
 *            mount table, and the arena the index, its keys and its runs live in
 * @param exclude A branch to leave out, or NULL for every one of them
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

        branch_t *branch = NULL;
        manifest_t *view = NULL;
        err = branch_load(ctx->run.repo, profiles.entries[i], &branch);
        if (!err) err = manifest_build_branch(branch, ctx->run.mounts, ctx->arena, &view);
        branch_free(branch);
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
 * One path this removal shares with other branches
 *
 * The claim removed there — the first, where a pair of the profile's own names
 * is removed at one place — and who else stands there under what name.
 */
typedef struct {
    const char *filesystem_path;
    const char *storage_path;
    const manifest_rows_t *others;
} overlap_t;

/**
 * The multi-profile section, as data
 *
 * One entry per path this removal shares with another branch, and the one fact
 * its closing line reads: whether the view's winner at any of those paths is a
 * different enabled profile, which is what makes a removal change nothing on disk.
 */
typedef struct {
    const overlap_t *entries;
    size_t count;
    bool provided_by_other;
} overlaps_t;

/**
 * What this removal shares with the other profiles
 *
 * Keyed by path, not by name (remove_build_filesystem_index): two profiles bound
 * at two targets holding one name are two paths and share nothing, while a portable
 * name and a binding's name at one place do share and used to go unsaid. A claim
 * this machine places nowhere meets nothing and is skipped.
 *
 * The index is read once per path and taken out of the map, so a pair of the
 * profile's own names removed at one place is one line and one count — the data
 * is the dedup, and no seen-set or second scan is needed.
 *
 * `provided_by_other` is the view's fact, not the record's: the winner at the
 * path is another enabled profile, so the path stays as it is. It is asked only
 * where the index answered, which is sound — a winner other than this profile
 * holds a row at the path and is therefore in the index, the excluded branch
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
    const claim_t *claims,
    size_t claim_count,
    const char *current_profile,
    overlaps_t *out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(claims);
    CHECK_NULL(current_profile);
    CHECK_NULL(out);

    *out = (overlaps_t){ 0 };

    hashmap_t *index = NULL;
    error_t err = remove_build_filesystem_index(ctx, current_profile, &index);
    if (err) return err;

    /* Tolerant (the header): a view the builder refuses leaves `view` NULL and
     * the bit false, its error dropped */
    manifest_t *view = NULL;
    (void) manifest_build(ctx->run.repo, ctx->run.state, ctx->arena, &view);

    overlap_t *overlaps = arena_calloc(
        ctx->arena, claim_count, sizeof(*overlaps)
    );

    size_t count = 0;
    bool provided_by_other = false;
    for (size_t i = 0; i < claim_count; i++) {
        const claim_t *claim = &claims[i];
        if (!claim->filesystem_path) continue;

        void *others = NULL;
        if (!hashmap_remove(index, claim->filesystem_path, &others)) continue;

        overlaps[count++] = (overlap_t){
            claim->filesystem_path, claim->storage_path, others
        };

        const manifest_row_t *row = manifest_lookup(view, claim->filesystem_path);
        if (row && strcmp(row->profile, current_profile) != 0) {
            provided_by_other = true;
        }
    }

    *out = (overlaps_t){ overlaps, count, provided_by_other };

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
    const overlaps_t *overlaps,
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
        const overlap_t *overlap = &overlaps->entries[i];

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
    const claim_t *claims,
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
 * `counts` is the branch-holdings phrase from the count family
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
    stage_t *stage = NULL;              /* the branch's tip, tree and index; the commit's */
    claim_t *claims = NULL;             /* arena — the resolver's */
    size_t claim_count = 0;
    metadata_t *metadata = NULL;        /* the branch's, from the resolver (owned) */
    overlaps_t overlaps = { 0 };        /* arena — the analysis's */

    /* The branch's stage: the tip everything below reads — the claims, the sheet,
     * the judge — and the parent the commit will have. The removal is pure tree
     * surgery, so the stage is the whole of its Git side. */
    char refname[DOTTA_REFNAME_MAX];
    err = gitops_branch_refname(refname, sizeof(refname), opts->profile);
    if (err) goto cleanup;

    err = stage_open(repo, refname, &stage);
    if (err) goto cleanup;

    /* Resolve the arguments to the claims they remove */
    err = remove_resolve(
        ctx, stage_tree(stage), opts->profile, opts->paths, opts->path_count, opts,
        &claims, &claim_count, &metadata
    );
    if (err) goto cleanup;

    /* What the removal shares with the other branches (critical safety check).
     * Advisory: the untrack proceeds without the section and says why, since a
     * local branch nobody enabled must not stop the repair — and must not hide
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

    /* Build hook invocation with the claims' filesystem paths (resolved by
     * remove_resolve). Reached only on non-dry-run: the dry-run branch above
     * early-cleanups before this point, so dry_run is always false here in practice
     * — still passed for honesty. */
    char **hook_paths = arena_calloc(ctx->arena, claim_count, sizeof(char *));
    for (size_t i = 0; i < claim_count; i++) {
        /* Arena-backed and never written through; the cast bridges the hook
         * contract's char *const *. A claim this machine places nowhere has no
         * path to hand over, and its name goes in the field's stead — the shape
         * a hook comparing DOTTA_FILE_N against $HOME has always received here,
         * spelled at the site rather than substituted upstream. */
        hook_paths[i] = (char *) (claims[i].filesystem_path ? claims[i].filesystem_path
                                                            : claims[i].storage_path);
    }
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .files      = hook_paths,
        .file_count = claim_count,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-remove hook */
    err = hook_fire_pre(config, out, &hook_inv);
    if (err) goto cleanup;

    /* The plan, on the stage: which tree entries leave, and the metadata edit
     * riding the same commit. A FILE claim is a tree entry; a DIRECTORY claim
     * has no tree entry — its whole Git footprint is its metadata item. Every
     * FILE claim is in the stage's tree (the resolver's universe is that tree's
     * own listing), so the stage's missing-entry error cannot fire. */
    size_t removed_files = 0, removed_dirs = 0, meta_edits = 0;

    /* The names this commit lets go, borrowed from the claims (arena): one per
     * claim, both kinds, since the message's unit is the path and a directory
     * claim is a path the commit gives up as surely as a blob is (utils/commit.h).
     * The message reads them once and the arena outlives the call, so nothing
     * is copied. */
    const char **removed_paths = arena_calloc(
        ctx->arena, claim_count, sizeof(*removed_paths)
    );

    for (size_t i = 0; i < claim_count; i++) {
        const claim_t *claim = &claims[i];

        if (claim->kind == PATH_KIND_FILE) {
            err = stage_remove(stage, claim->storage_path);
            if (err) goto cleanup;
            removed_files++;
        } else {
            removed_dirs++;
        }

        if (metadata_remove_item(metadata, claim->storage_path)) {
            meta_edits++;
        }

        removed_paths[i] = claim->storage_path;
        output_info(out, OUTPUT_VERBOSE, "Removed: %s", claim->storage_path);
    }

    /* Prune redundant directory entries against the stage's index — the branch
     * tree minus the removed file claims, the tree the impending commit will
     * record (the judge's own contract, metadata.h). Removing a file may leave
     * its parent directory metadata entry with nothing tracked beneath it. The
     * index answers that for every path a tree can hold — never the metadata
     * items, which omit unelevated symlinks — and the sheet's own tracked claims
     * answer it for the one path it cannot, an empty directory. */
    string_array_t pruned_dirs;   /* Directory entries the metadata step pruned (storage paths) */
    string_array_init(&pruned_dirs, ctx->arena);
    err = metadata_prune_ancestors(metadata, stage_index(stage), &pruned_dirs);
    if (err) goto cleanup;
    if (pruned_dirs.count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "Pruned %zu redundant directory entr%s",
            pruned_dirs.count, pruned_dirs.count == 1 ? "y" : "ies"
        );
    }

    /* The sheet, only when the collection actually changed — a removal that touched
     * no items and pruned nothing keeps the branch's metadata.json byte-identical,
     * so no rewrite is staged. */
    if (meta_edits + pruned_dirs.count > 0) {
        err = metadata_save_to_stage(stage, metadata);
        if (err) goto cleanup;
    }

    /* One atomic commit: the file claims leave the tree, metadata.json follows
     * in the same tree write. All-or-nothing — any failure up to here leaves
     * the repository byte-identical. */
    commit_message_context_t msg_ctx = {
        .action        = COMMIT_ACTION_REMOVE,
        .profile       = opts->profile,
        .paths         = removed_paths,
        .path_count    = claim_count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };
    err = stage_commit(stage, commit_message(ctx->arena, config, &msg_ctx), NULL);
    if (err) goto cleanup;

    /*
     * Architectural note: no filesystem deletion here. Only apply writes to a
     * managed filesystem path — core/deploy and core/cleanup are the only mutators
     * — so remove's whole effect is the commit above and the record below. The
     * deployed copy's fate is decided at the next apply, against the view standing
     * then.
     */

    /* The record phase: the record answers to the record. The candidates are
     * the paths this commit let go — the removed claims, and the directory entries
     * the metadata step pruned as redundant (an ancestor claim above the named
     * path is the common case), which left the view by the same commit — each
     * joined to its record and settled by the one rule (remove_settle).
     *
     * Enablement decides no fate: a record dotta holds under a disabled profile
     * is still dotta's record — the rule remove_profile runs over every record
     * naming the profile, run here over the candidates.
     *
     * Non-fatal throughout: Git succeeded and stands. A record this block fails
     * to write is an orphan the next apply reads, asks Git about, finds let go,
     * and releases — the default outcome, minus the prune order under
     * --delete-files. */
    settlement_t settlement = { 0 };

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
    candidate_t *candidates = NULL;
    size_t candidate_count = 0;
    err = remove_paths_candidates(
        ctx, opts->profile, claims, claim_count, &pruned_dirs, &candidates, &candidate_count
    );

    if (!err && (candidate_count > 0 || state_enabled(state, opts->profile))) {
        err = state_begin(state);

        /* What the settle acts on, read again under the lock: the read above
         * decided only whether to take it, and another process can write the
         * record between the two — or while this one waits for it. */
        if (!err) {
            err = remove_paths_candidates(
                ctx, opts->profile, claims, claim_count, &pruned_dirs,
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
            settlement = (settlement_t){ 0 };   /* the rollback took the writes with it */
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
    if (metadata) metadata_free(metadata);
    stage_free(stage);

    return err;
}

/**
 * Walk visitor: one claim of a profile being deleted, its name onto its hooks' list
 *
 * Every claim, whatever its kind: a deletion takes them all, and its hooks are
 * handed each one, a directory's beside a file's (etc/hooks/README.md).
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The hooks' list of names (string_array_t, given its arena)
 * @return NULL: a collection fails nowhere
 */
static error_t remove_collect_claim(const branch_claim_t *claim, void *payload) {
    string_array_t *names = payload;

    /* The name copied out of the walk's loan, into the list's own arena */
    string_array_push(names, claim->storage_path);

    return NULL;
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
    const mount_table_t *mounts = ctx->run.mounts;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Initialize all resources to NULL */
    error_t err = NULL;
    branch_t *branch = NULL;
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

    /* The branch at its tip, read once for all the deletion says before it acts:
     * every claim it takes, for its hooks, and what it holds, for the preview
     * and the confirmation, one commit for both. A tip that will not load refuses
     * here, in gitops' words, which name the branch. */
    err = branch_load(repo, opts->profile, &branch);
    if (err) goto cleanup;

    /* Every claim the deletion takes, by name: the claims the walk shows — the
     * blobs, then the directory claims that stand — and then those the tree
     * contradicts (core/branch.h branch_contradicted), so the hooks are handed
     * every claim the profile goes with, one entry each, and a path two claims
     * stand at once for each. Read tolerantly: a deletion that refused over a
     * sheet it cannot read would leave the profile undeletable, so it goes on
     * and says below what its hooks lose. A tree it cannot walk is refused here,
     * before the preview: no tolerant read loses the tree's half. */
    string_array_t hook_storage;
    string_array_init(&hook_storage, ctx->arena);
    err = branch_walk(branch, BRANCH_READ_TOLERANT, remove_collect_claim, &hook_storage);
    if (err) goto cleanup;
    err = branch_contradicted(branch, BRANCH_READ_TOLERANT, remove_collect_claim, &hook_storage);
    if (err) goto cleanup;

    /* What the tolerant read lost, said where it was read, so the dry run says
     * it too: the directory claims the hooks are not handed, and the count below,
     * in the loader's line, which names the profile */
    err = branch_sheet_failure(branch);
    if (err) {
        output_warning(
            out, OUTPUT_NORMAL, "%s; its hooks are handed its files alone",
            error_line(err)
        );
        err = NULL;
    }

    /* The count, over the same branch, both kinds (core/branch.h branch_count):
     * one truth with `dotta list`. Its failure is display-only — the deletion
     * must not refuse over a count — so it becomes the phrase the preview prints,
     * its error dropped and err back to the NULL the phase began with. The branch
     * is read no further: the hooks' list holds its own copies. */
    branch_count_t count = { 0 };
    err = branch_count(branch, &count);
    branch_free(branch);
    branch = NULL;

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
    candidate_t *candidates = NULL;
    size_t candidate_count = 0;
    size_t deployed_count = 0;
    settlement_t settlement = { 0 };
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

    /* Convert storage paths to filesystem paths for hook consistency. The file
     * removal path passes filesystem paths to hooks; do the same here.
     *
     * Borrows the run's mount table. HOME and ROOT are always present, so home/
     * and root/ paths resolve unconditionally. CUSTOM paths resolve only when
     * the profile is enabled with a binding; otherwise the loop substitutes the
     * storage path so the hook sees a meaningful name. */
    string_array_t hook_filesystem;
    string_array_init(&hook_filesystem, ctx->arena);
    for (size_t i = 0; i < hook_storage.count; i++) {
        const char *filesystem_path = mount_resolve(
            ctx->arena, mounts, opts->profile, hook_storage.entries[i]
        );
        string_array_push(
            &hook_filesystem, filesystem_path ? filesystem_path : hook_storage.entries[i]
        );
    }

    /* Build hook invocation with the filesystem paths (consistent with the
     * file-removal subcommand). The arrays are the command arena's. */
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .files      = hook_filesystem.entries,
        .file_count = hook_filesystem.count,
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
            settlement = (settlement_t){ 0 };   /* the rollback took the writes with it */
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
     * record-update or post-deletion transaction on an error path. The branch
     * is freed once its count is read; here only a refusal before that frees it. */
    branch_free(branch);
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
 * What can stand at the cursor, read off the buckets remove_post_parse routes:
 * a local profile in the profile slot — the first positional, unless -p took it
 * — then the claims of that profile's branch, shadowed and disabled ones included:
 * its files, and its directory claims slash-marked; nothing after --delete-profile,
 * which takes no path.
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
    completion_refspecs(
        ctx, out, o->profile ? o->profile : o->positional_args[0]
    );
    completion_directories(
        ctx, out, o->profile ? o->profile : o->positional_args[0]
    );
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
