/**
 * update.c - Update profiles with modified files
 */

#include "cmds/update.h"

#include <config.h>
#include <errno.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/policy.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/identity.h"
#include "sys/stage.h"
#include "utils/commit.h"
#include "utils/hooks.h"

/**
 * Capture a path from the filesystem as the entry it becomes
 *
 * A regular file is sealed as the policy decides (core/policy.h), and the seal
 * it keeps — priority 3 — is read from the entry the stage holds at this name,
 * by its own bytes (infra/content.h content_classify), never from the sheet's
 * copy of that fact. The view projects the copy for its screens, and a sheet
 * that disagrees with its tree — a hand edit, another tool's commit, the
 * contradicted claim a branch decodes as no claim at all (core/branch.c
 * branch_step) — would otherwise have this capture store a secret in the clear.
 *
 * Routed by what the load observed at the path, as add routes by what its listing
 * found there (cmds/add.c add_capture) — every item on this route carries an
 * occupant, a diverged file's from the join's look and an offer's from the walk.
 * No look is taken here: each capture takes its own and refuses the other's
 * occupant (infra/content.h), so a path whose kind changed since the load is
 * refused rather than read as what it has become, which is the refusal a second
 * look here would only have moved one frame earlier.
 *
 * This routes, decides and captures; the entry the capture becomes is the caller's
 * to put, beside the claim and the record it also writes. So the stage is read
 * here and never written: the only question asked of it is the prior entry above.
 *
 * @param ctx Dispatch context (must not be NULL; supplies the repository, the
 *            key and the encryption policy)
 * @param stage The profile's stage (must not be NULL; the entry it holds at the
 *              item's name is the prior this capture's policy reads)
 * @param item The path to capture (must not be NULL; its occupant chooses the
 *             capture, its two keys name the source and the seal)
 * @param profile The profile, for the seal's key (must not be NULL)
 * @param out The capture (must not be NULL; cleared here before the policy can
 *            refuse, so freeing it is correct on every path)
 */
static error_t update_capture(
    const dotta_ctx_t *ctx,
    stage_t *stage,
    const workspace_item_t *item,
    const char *profile,
    content_capture_t *out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(stage);
    CHECK_NULL(item);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    /* The captures clear this too, but the policy below stands in front of them
     * and can refuse. */
    *out = (content_capture_t){ 0 };

    const char *filesystem_path = item->filesystem_path;
    const char *storage_path = item->storage_path;
    keymgr *keymgr = ctx->run.keymgr;

    if (item->occupant == FS_OCCUPANT_SYMLINK) {
        /* The entry is the link's target, never encrypted */
        return content_capture_link(filesystem_path, out);
    }

    /* Priority 3's source: the entry the stage holds at this name — the branch
     * as the stage opened it, an update capturing each name once — judged by
     * its bytes and its mode, and no entry at all for a file new to the profile.
     * A blob that cannot be read is an error, not "not encrypted": a sniff that
     * defaulted would flip the policy silently. */
    error_t err = NULL;
    const git_index_entry *prior = git_index_get_bypath(
        stage_index(stage), storage_path, 0
    );
    content_kind_t prior_kind = CONTENT_PLAINTEXT;
    if (prior) {
        err = content_classify(
            ctx->run.repo, &prior->id, prior->mode, &prior_kind, NULL
        );
        if (err) {
            return error_wrap(
                err, "Failed to classify the committed bytes of '%s'", storage_path
            );
        }
    }

    /* Handle regular file - determine encryption policy using centralized logic */
    bool should_encrypt = false;
    err = encryption_policy_should_encrypt(
        ctx->config,
        storage_path,
        ENCRYPTION_REQUEST_NONE,  /* update carries no encryption flags */
        prior_kind != CONTENT_PLAINTEXT,
        &should_encrypt
    );
    if (err) return err;

    /* The entry the file becomes: read → seal as decided → the bytes, the mode
     * and the fstat of the descriptor they came off, bytes and look one inode
     * by construction (infra/content.h content_capture_t). */
    return content_capture_file(
        filesystem_path, storage_path, profile, keymgr, should_encrypt, out
    );
}

/**
 * What one profile's update commit did, path by path
 *
 * Filled by the walk that does the work — one writer per item: the capture for
 * a file, the claim capture for a directory, the entry removal for a deletion,
 * the ancestry derivation for the chains it climbed, the prune for the directory
 * entries dropped as redundant — and read back by the commit message and by the
 * record loop (update_write_record), so both follow the commit and nothing else:
 * an item the walk skipped (a directory the race guard refused) lands in no list,
 * is not named, and gets no record write. Whether the commit landed at all is
 * the stage's own answer (sys/stage.h stage_commit) — a walk whose edits leave
 * the tree as the stage opened it lands none, whatever its lists hold — and the
 * executor hands on only the bookkeeping of a commit that landed (update_execute).
 *
 * A capture is kept as the record of what it committed — the node the capture
 * held to, the blob the stage wrote, the triple its bytes were read with (a file's,
 * the fstat of the descriptor it read; a link's, the lstat before its target;
 * none for a directory, which confirms no content), and the claim the sheet took
 * — so the record loop writes what this commit put there, never what a later
 * tip of the branch says should be. Its names are the item's (workspace lifetime)
 * and the arena's (the claim's, copied before the sheet that held them is freed).
 * Deleted items are borrowed; the pruned and retired keys are storage paths their
 * writers copy out, resolved through the mount table by the record loop — the
 * same route remove's record loop takes. The derivation's two outs are shaped
 * by what a reader can do with them (metadata.h): an authored claim has no
 * consequence beyond the sheet, so `claimed` is the count the commit gate and
 * the receipt read, while a dropped claim leaves the view by this commit and
 * only its key can settle the record it strands.
 *
 * Memory: every member is the command arena's, and nothing frees a commit.
 */
typedef struct {
    const char *profile;               /* Borrowed from the enabled set */
    bool committed;                    /* Whether the commit landed: the stage's own answer */
    state_record_t *captured;          /* What each capture committed, as the record keeps it */
    size_t captured_count;
    const workspace_item_t **deleted;  /* Items whose deletion the commit recorded */
    size_t deleted_count;
    string_array_t pruned;             /* Directory entries dropped as redundant (storage paths) */
    size_t claimed;                    /* Ancestor claims the derivation authored or refreshed */
    string_array_t retired;            /* Ancestor claims the derivation dropped (storage paths) */
} commit_t;

/**
 * What the filter made of the diverged items, in scope
 *
 * One walk partitions every in-scope item five ways. Excluded — an -e pattern's,
 * whatever the state rule would say of it: answered for the command's trace,
 * and never touched. Accepted — the run's work: a deployed item on the capture
 * route, a deleted path, a new file under a tracked directory when a flag or
 * the config asked for it. Refused — a deployed item on any other route
 * (workspace_item_route), counted under that route so the census names the table's
 * own reason; a multi-bit divergence counts under the route that refused it.
 * Unscanned — a place the scan could not look: never accepted, since what it
 * could not judge may be what Git excludes, and listed by path rather than counted
 * (cmd_update), since no route refused it and status lists it only where the
 * config scans. Or neither — a state that is another verb's, and, under --only-new,
 * every deployed and deleted item: the user asked about new files, nothing about
 * the others answers that, so none is accepted and none is counted (a refused
 * route would name a reason the user did not ask for) — but a directory the load
 * could not look at, beneath which the scan never looked either, which is counted
 * under its route.
 *
 * An accepted item is answered by its fate as well — the preview lists one section
 * per fate, and the new-files prompt counts new_files. The modified fate splits
 * by kind (a directory's modification is a claim recapture, not a content commit),
 * deleted deliberately does not (a deleted directory is a deletion), and the
 * deployed files split by what diverged (core/workspace.h divergence_type_t): a
 * path bit is a modification, the blob bit, ENCRYPTION, a policy violation. A
 * file with both kinds of bit is in both; a violator with nothing changed on
 * disk only among the violations — it is committed for the re-store, not for a
 * modification. So every accepted item has a fate, and a file may have two.
 *
 * The lists are slices one classification fills (core/workspace.h
 * workspace_buckets_t), each in the diverged items' order, in the arena the
 * partition was made in — the items borrowed, the workspace's. The discoveries
 * follow every other diverged item (workspace_diverged), so the new files are
 * accepted's suffix: what cmd_update's decline drops.
 *
 * The equation: in-scope deployed items no pattern spared = accepted deployed ∪
 * Σ refused[arm], by one switch that routes each item once — nothing is counted
 * twice, nothing falls through. The UNVERIFIABLE arm keeps a second index beside
 * it, for the same reason the first one exists: one route, three ways out
 * (workspace_fault_t), and the census prints a line per class. Σ faults[f] ==
 * refused[UNVERIFIABLE], and faults[NONE] is zero by the fold's invariant.
 * CAPTURE's slot stays zero (that arm is accepted) and CLEAN's (the diverged
 * items hold no clean row); REASSIGNED's counts a reassignment the census has
 * no line for — apply acknowledges it, the filter only declines it.
 */
typedef struct {
    workspace_items_t accepted;              /* The run's work */

    /* The accepted items by fate, in the preview's order */
    workspace_items_t modified_files;        /* DEPLOYED files with a path bit: divergent content or metadata */
    workspace_items_t new_files;             /* UNTRACKED files from tracked directories */
    workspace_items_t deleted;               /* DELETED paths, both kinds */
    workspace_items_t modified_dirs;         /* DEPLOYED directories: claim capture */
    workspace_items_t unencrypted;           /* DEPLOYED policy violators (a path bit beside it or alone) */

    workspace_items_t excluded;              /* In scope, spared by -e — traced, never touched */
    workspace_items_t unscanned;             /* In scope, where the scan could not look — listed, never taken */
    size_t refused[WORKSPACE_ROUTE_COUNT];   /* In scope, deployed, refused — by the route that refused it */
    size_t faults[WORKSPACE_FAULT_COUNT];    /* The UNVERIFIABLE arm again — by whose remedy the look is */
} partition_t;

/**
 * Partition the workspace's diverged items for update
 *
 * The scope first: the profiles and paths the user named, then the patterns they
 * excluded — the order every scope reader asks in (core/scope.h
 * scope_accepts_entry). Then the state rule under the flags, and for a deployed
 * item the route: the partition (partition_t). It decides in silence: what it
 * answers, the command says (cmd_update traces the excluded, as apply traces
 * its plans').
 *
 * @param ws Workspace (must not be NULL)
 * @param opts Update options (must not be NULL)
 * @param scope Operation scope (must not be NULL)
 * @param arena Arena the partition's lists live in: the command's (must not be
 *              NULL)
 * @param partition Output, zeroed then filled (must not be NULL)
 */
static void update_partition(
    const workspace_t *ws,
    const cmd_update_options_t *opts,
    const scope_t *scope,
    arena_t *arena,
    partition_t *partition
) {
    CHECK_NULL(ws);
    CHECK_NULL(opts);
    CHECK_NULL(scope);
    CHECK_NULL(arena);
    CHECK_NULL(partition);

    *partition = (partition_t){ 0 };

    /* Each item is added to its lists as the walk decides it, and every list is
     * filled once the walk is done — the arena's, beside the items they borrow */
    workspace_items_t diverged = workspace_diverged(ws);
    workspace_buckets_t *buckets = workspace_buckets_create(arena);

    for (size_t i = 0; i < diverged.count; i++) {
        const workspace_item_t *item = diverged.entries[i];

        /* Outside the profiles and the paths the user named: invisible, as to
         * every scope reader — the path filter reads both names */
        if (!scope_accepts_profile(scope, item->profile) ||
            !scope_accepts_path(
            scope, item->filesystem_path, item->storage_path, item->item_kind
            )) {
            continue;
        }

        /* A pattern's, by the mount-relative name: asked apart from the two above
         * because what it spares is answered — every item in scope the pattern
         * hits, whatever the state rule would then say of it — for the command's
         * trace */
        if (scope_is_excluded(scope, item->storage_path, item->item_kind)) {
            workspace_buckets_add(buckets, item, &partition->excluded);
            continue;
        }

        switch (item->state) {
            case WORKSPACE_STATE_DEPLOYED: {
                /* The route table partitions the deployed items — the same producer
                 * status's sections and sync's guard read (workspace_item_route;
                 * workspace.h carries each arm's why). CAPTURE is the one arm
                 * update commits; every other arm is refused and counted under
                 * its route, so the preview never promises an update the executor
                 * would refuse and the census says why in the table's words.
                 * Under --only-new the user asked about new files alone: neither
                 * accepted nor counted — but a directory the load could not look
                 * at, beneath which the scan did not look either (no root is
                 * registered where the join's look failed, and the walk adds no
                 * item where a rung's did), so the new files asked for may stand
                 * there. */
                const workspace_route_t route = workspace_item_route(item);
                if (opts->only_new && (route != WORKSPACE_ROUTE_UNVERIFIABLE ||
                    item->item_kind != PATH_KIND_DIRECTORY)) {
                    continue;
                }
                if (route != WORKSPACE_ROUTE_CAPTURE) {
                    partition->refused[route]++;
                    if (route == WORKSPACE_ROUTE_UNVERIFIABLE) {
                        partition->faults[item->fault]++;
                    }
                    continue;
                }

                /* The capture's fate: a directory's is its claim; a file's is
                 * what diverged — a path bit a modification, the ENCRYPTION bit
                 * a violation, so a file with both is both, and a violator nothing
                 * changed on disk only a violation */
                if (item->item_kind == PATH_KIND_DIRECTORY) {
                    workspace_buckets_add(buckets, item, &partition->modified_dirs);
                } else {
                    if ((item->divergence & ~DIVERGENCE_ENCRYPTION) != DIVERGENCE_NONE) {
                        workspace_buckets_add(buckets, item, &partition->modified_files);
                    }
                    if (item->divergence & DIVERGENCE_ENCRYPTION) {
                        workspace_buckets_add(buckets, item, &partition->unencrypted);
                    }
                }
                break;
            }

            case WORKSPACE_STATE_DELETED:
                /* Removed from disk since deployment: the deletion is update's
                 * to commit, unless the user asked about new files alone. One
                 * fate for both kinds, and a deleted violator is a deletion too:
                 * its commit resolves the violation by removing the plaintext. */
                if (opts->only_new) continue;
                workspace_buckets_add(buckets, item, &partition->deleted);
                break;

            case WORKSPACE_STATE_UNTRACKED:
                /* A new file under a tracked directory, the run's whenever the
                 * load found one: it scans only where the run asked for new files
                 * — by flag (--include-new, --only-new), or by config, for the
                 * consent prompt (cmd_update's analyze_untracked) */
                workspace_buckets_add(buckets, item, &partition->new_files);
                break;

            case WORKSPACE_STATE_UNSCANNED:
                /* Where the scan could not look: never accepted — what it could
                 * not judge may be what Git excludes — and listed by path, not
                 * counted (cmd_update): no route refused it, and status may not
                 * have it */
                workspace_buckets_add(buckets, item, &partition->unscanned);
                continue;

            case WORKSPACE_STATE_UNDEPLOYED:
            case WORKSPACE_STATE_ORPHANED:
            case WORKSPACE_STATE_RELEASED:
                /* Another verb's: not deployed yet (apply's), or a record the
                 * view lacks (cleanup prunes or releases it; never update's to
                 * commit) */
                continue;
        }

        workspace_buckets_add(buckets, item, &partition->accepted);
    }

    workspace_buckets_fill(buckets);
}

/**
 * Update a single profile with workspace items
 *
 * One walk, one writer per item, over one metadata load (the sheet in the tree
 * the stage opened at — the branch's own bytes). Each arm does its item's work
 * and fills the commit's bookkeeping beside it: the capture onto the stage for
 * a file, the claim capture for a directory, the entry removal for a deletion.
 * The chain rides the capture: after the walk, every captured leaf's ancestry
 * is re-derived into the same sheet — the content now comes from this machine,
 * and so does its way — and a named run hands in the profile's in-scope rows,
 * each a leaf whose chain is climbed whether or not anything about it diverged.
 * The walk ends with the redundancy prune, one metadata save, and the commit.
 *
 * Success means committed or untouched, and the bookkeeping says which
 * (commit->committed, the stage's answer): a walk that captured nothing and deleted
 * nothing saves nothing and commits nothing — the stage is freed by the caller
 * as it was opened — and a walk whose captures put back what the branch holds
 * commits nothing either. A mid-walk failure returns with the stage part-edited:
 * the executor stops the run there, and a stage that is never committed changes
 * nothing in the repository.
 *
 * @param ctx Dispatch context (must not be NULL; the capture reads the key and
 *            the encryption policy off it)
 * @param stage The profile's stage, opened by the caller (must not be NULL)
 * @param profile Profile to update (must not be NULL)
 * @param items The profile's share of the run's work, in filter order (empty
 *              where the profile has only chains to re-derive)
 * @param rows The named run's in-scope view rows for this profile, each the leaf
 *             of a chain to re-derive (empty on a bare run, which names no paths)
 * @param opts Update options (must not be NULL)
 * @param commit The commit's bookkeeping, zero-filled by the caller; the walk
 *               fills it (must not be NULL)
 * @return Error or NULL on success
 */
static error_t update_profile(
    const dotta_ctx_t *ctx,
    stage_t *stage,
    const char *profile,
    workspace_items_t items,
    manifest_rows_t rows,
    const cmd_update_options_t *opts,
    commit_t *commit
) {
    CHECK_NULL(ctx);
    CHECK_NULL(stage);
    CHECK_NULL(profile);
    CHECK_NULL(opts);
    CHECK_NULL(commit);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    commit->profile = profile;
    string_array_init(&commit->pruned, ctx->arena);
    string_array_init(&commit->retired, ctx->arena);

    /* Initialize all resources to NULL for goto cleanup */
    metadata_t *metadata = NULL;
    error_t err = NULL;

    /* The one metadata load: the sheet in the tree the stage opened at — the
     * branch's own bytes — mutated as the walk goes, saved once. */
    err = metadata_load_from_tree(repo, stage_tree(stage), profile, &metadata);
    if (err) return err;

    /* The capture and deletion lists can each hold every item; the walk fills
     * them with the ones that landed. A rows-only call has nothing to capture
     * or delete, and no list to size. */
    if (items.count > 0) {
        commit->captured = arena_calloc(
            ctx->arena, items.count, sizeof(*commit->captured)
        );
        commit->deleted = arena_calloc(
            ctx->arena, items.count, sizeof(*commit->deleted)
        );
    }

    size_t captured_file_count = 0;
    size_t updated_dir_count = 0;

    /* One walk, one writer per item: each arm does its item's work and fills
     * the commit's bookkeeping beside it. */
    for (size_t i = 0; i < items.count; i++) {
        const workspace_item_t *item = items.entries[i];

        switch (item->item_kind) {
            case PATH_KIND_FILE: {
                /* Handle deleted files */
                if (item->state == WORKSPACE_STATE_DELETED) {
                    output_info(
                        out, OUTPUT_VERBOSE, "  Removed: %s",
                        item->filesystem_path
                    );
                    /* The entry leaves the stage: the row says the tree holds
                     * it, so a path the stage lacks is the model's error, not a
                     * no-op. */
                    err = stage_remove(stage, item->storage_path);
                    if (err) goto cleanup;
                    /* Remove metadata entry if it exists */
                    metadata_remove_item(metadata, item->storage_path);
                    commit->deleted[commit->deleted_count++] = item;
                    continue;
                }

                output_info(out, OUTPUT_VERBOSE, "  %s", item->filesystem_path);

                /* The capture, and the entry it becomes on the stage, at the
                 * name the seal was made under (infra/content.h). One tail past
                 * the door: the bytes are released whichever step refused, and
                 * each refusal names the path itself — the capture's the file,
                 * the put's the name it lands at. */
                content_capture_t capture = { 0 };
                git_oid blob;
                err = update_capture(ctx, stage, item, profile, &capture);
                if (!err) {
                    err = stage_put(
                        stage, item->storage_path, capture.bytes.data,
                        capture.bytes.size, capture.mode, &blob
                    );
                }
                content_capture_free(&capture);
                if (err) goto cleanup;

                /* The claim from the capture's own stat, sealed as the capture
                 * sealed the bytes: its write-time invariant makes that verdict
                 * the byte truth, so the claim and every reader agree — and a
                 * link is never sealed. */
                metadata_item_t *meta_item = NULL;
                err = metadata_capture_file(
                    item->storage_path,
                    &capture.st,
                    capture.encrypted,
                    &meta_item
                );
                if (err) goto cleanup;

                /* What the capture committed, as the record keeps it: the node
                 * the load found and the capture held to, the blob the put wrote
                 * under the look its bytes came off, and the claim — taken before
                 * the sheet takes the item */
                state_record_t *record = &commit->captured[commit->captured_count];
                *record = (state_record_t){
                    .filesystem_path = item->filesystem_path,
                    .storage_path = item->storage_path,
                    .profile = profile,
                    .kind = item->occupant,
                    .blob_oid = blob,
                    .stat = state_stat_from_read(&capture.st),
                };
                metadata_item_claim(meta_item, ctx->arena, record);

                /* meta_item is NULL for a link that claims nothing — no mode to
                 * take, no ownership tracked. A capture that claims nothing retires
                 * the standing claim: an item at the key is the replaced
                 * state's. */
                if (meta_item) {
                    /* Say what the capture took before metadata_add_item takes
                     * it — the claim decides the shape. The fourth combination
                     * (no mode, no ownership) has no line: such an item does
                     * not exist. Ownership is both names or neither at the capture
                     * (core/metadata.c metadata_capture_ownership), so the owner
                     * alone is asked, as add asks it (cmds/add.c
                     * add_print_capture). The ownership-only shape carries no
                     * encrypted suffix by construction: it is a link's entry,
                     * and the capture never encrypts one. */
                    if (meta_item->mode != MODE_UNCLAIMED && meta_item->owner) {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "  Captured metadata: %s (mode: %04o, owner: %s:%s%s)",
                            item->filesystem_path, meta_item->mode, meta_item->owner,
                            meta_item->group, meta_item->encrypted ? ", encrypted" : ""
                        );
                    } else if (meta_item->mode != MODE_UNCLAIMED) {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "  Captured metadata: %s (mode: %04o%s)",
                            item->filesystem_path, meta_item->mode,
                            meta_item->encrypted ? ", encrypted" : ""
                        );
                    } else {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "  Captured metadata: %s (owner: %s:%s)",
                            item->filesystem_path, meta_item->owner, meta_item->group
                        );
                    }

                    /* Add to metadata collection */
                    metadata_add_item(metadata, &meta_item);

                    captured_file_count++;
                } else {
                    metadata_remove_item(metadata, item->storage_path);
                }

                commit->captured_count++;
                break;
            }

            case PATH_KIND_DIRECTORY: {
                /* Handle deleted directories (symmetric with the file branch
                 * above). Without this, the stat() below would fail with ENOENT
                 * and the metadata entry would survive, letting the view keep
                 * claiming a directory the user just deleted. A deleted directory
                 * is a deletion: the entry's removal goes on the commit's
                 * bookkeeping like a deleted file, so the commit gate counts
                 * it, the message names it, and the record loop retires it. */
                if (item->state == WORKSPACE_STATE_DELETED) {
                    if (metadata_remove_item(metadata, item->storage_path)) {
                        output_info(
                            out, OUTPUT_VERBOSE, "  Removed directory metadata: %s",
                            item->filesystem_path
                        );
                        commit->deleted[commit->deleted_count++] = item;
                    }
                    continue;
                }

                /* lstat + S_ISDIR: the race guard. The filter refused load-time
                 * [type] and [unverified]; this refuses a change since load — a
                 * path that vanished, or a tracked directory replaced by a symlink,
                 * which would stat() as its target and launder the target's
                 * attributes into metadata. Skip; the next load classifies what
                 * now stands there. */
                struct stat dir_stat;
                if (fs_lstat(item->filesystem_path, &dir_stat) != 0) {
                    output_warning(
                        out, OUTPUT_VERBOSE,
                        "Failed to stat directory '%s': %s",
                        item->filesystem_path, strerror(errno)
                    );
                    continue;
                }
                if (!S_ISDIR(dir_stat.st_mode)) {
                    output_warning(
                        out, OUTPUT_NORMAL,
                        "Skipping '%s': tracked as directory but type changed on disk",
                        item->filesystem_path
                    );
                    continue;
                }

                /* Capture directory metadata. A re-derivation replaces the
                 * attributes and never the class: whether the profile tracks
                 * this directory or only passes through it was decided by the
                 * walk that authored the claim, and an update is not that walk.
                 * The standing item is the authority for it — this is the profile's
                 * own sheet, not the resolved view, so precedence has nothing
                 * to say here — and a key it does not hold answers with the class
                 * dotta does less with. */
                const metadata_item_t *held = metadata_lookup(metadata, item->storage_path);
                metadata_item_t *meta_item = NULL;
                err = metadata_capture_directory(
                    item->storage_path, &dir_stat, held && held->tracked, &meta_item
                );

                if (err) {
                    /* Non-fatal, and said at the verbosity its sibling above is
                     * said at: the claim standing on the directory is left exactly
                     * as it is — absence of a capture is not knowledge that the
                     * claim is wrong — so the sheet quietly keeps saying something
                     * this run could not confirm. The error is dropped once said,
                     * one per directory whose owner or group this host cannot
                     * name (core/metadata.h). */
                    output_warning(
                        out, OUTPUT_NORMAL, "Skipping directory '%s': %s",
                        item->filesystem_path, error_line(err)
                    );
                    err = NULL;
                    continue;
                }

                /* What the capture committed, as the record keeps it: the directory
                 * the guard above just held it to, and its claim — no content,
                 * which a directory never confirms — taken before the sheet takes
                 * the item */
                state_record_t *record = &commit->captured[commit->captured_count];
                *record = (state_record_t){
                    .filesystem_path = item->filesystem_path,
                    .storage_path = item->storage_path,
                    .profile = profile,
                    .kind = FS_OCCUPANT_DIRECTORY,
                };
                metadata_item_claim(meta_item, ctx->arena, record);

                /* Say what the capture took before metadata_add_item takes it */
                if (meta_item->owner) {
                    output_info(
                        out, OUTPUT_VERBOSE,
                        "  Updated directory metadata: %s (mode: %04o, owner: %s:%s)",
                        item->filesystem_path, meta_item->mode, meta_item->owner,
                        meta_item->group
                    );
                } else {
                    output_info(
                        out, OUTPUT_VERBOSE,
                        "  Updated directory metadata: %s (mode: %04o)",
                        item->filesystem_path, meta_item->mode
                    );
                }

                /* Add to metadata collection (upsert - updates if exists) */
                metadata_add_item(metadata, &meta_item);

                updated_dir_count++;
                commit->captured_count++;
                break;
            }
        }
    }

    /* The chain rides the capture: every leaf the walk took has its ancestry
     * re-derived — the content now comes from this machine, and so does its way
     * (add's own rule, applied to the re-capture an update is). After the walk,
     * so a rung the walk itself claimed stands as the walk's word; over both
     * kinds, a captured tracked directory having a chain of its own; and never
     * over a deleted item — the absence of a leaf says nothing about the chain
     * that led to it. This trigger authors and refreshes but structurally never
     * retires: a leaf beneath a squatted rung was refused at the filter (the
     * route's displaced arms), whichever profile's claim the squatter displaced,
     * so a chain that reaches here holds directories at every claimed rung. */
    for (size_t i = 0; i < commit->captured_count; i++) {
        err = metadata_capture_ancestors(
            metadata, ctx->run.mounts, profile, commit->captured[i].storage_path,
            ctx->arena, &commit->claimed, &commit->retired
        );
        if (err) goto cleanup;
    }

    /* A named path re-derives its subtree's chains: the rows the caller gathered
     * are the leaves the run's paths named, each climbed whether or not anything
     * about it diverged — naming is consent, and this is the derivation's one
     * route to a retire (a captured leaf's chain cannot hold a squatted rung; a
     * named one can, and naming it is the remedy). A row the walk also captured
     * climbs twice for free: the derivation counts only differences. */
    for (size_t i = 0; i < rows.count; i++) {
        err = metadata_capture_ancestors(
            metadata, ctx->run.mounts, profile, rows.entries[i]->storage_path, ctx->arena,
            &commit->claimed, &commit->retired
        );
        if (err) goto cleanup;
    }

    if (commit->claimed > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "  Captured %zu ancestor director%s",
            commit->claimed, commit->claimed == 1 ? "y" : "ies"
        );
    }
    if (commit->retired.count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "  Dropped %zu ancestor claim%s",
            commit->retired.count, commit->retired.count == 1 ? "" : "s"
        );
    }

    /* A profile whose walk captured nothing and deleted nothing, and whose
     * derivation moved nothing, has nothing to commit, and a no-commit profile
     * leaves the stage as it was opened: nothing saved, nothing committed. The
     * prune is skipped with the save — imported redundancy rides whatever commit
     * triggers the metadata rewrite, never drives one. The derivation is not
     * redundancy: a chain re-derived under a captured leaf or a named path is
     * the user's own word about the disk, and it drives the commit it needs —
     * which is how the remedy for a rung the world moved under works at all. */
    size_t path_count = commit->captured_count + commit->deleted_count +
        commit->claimed + commit->retired.count;
    if (path_count == 0) goto cleanup;

    /* Prune redundant directory entries.
     *
     * Catches the implicit-orphaning case (the DELETED branch above handles
     * explicit removals): file removals can leave a parent directory's metadata
     * entry with nothing tracked beneath it. That set is judged against the stage's
     * index (deletions removed, captures put by the walk) for every path a tree
     * can hold — never against metadata items, which omit unelevated symlinks —
     * and against the sheet's own tracked claims for the one path it cannot, an
     * empty directory. Without this, the view would keep claiming the orphaned
     * entry indefinitely. The keys go on the commit's bookkeeping: the entry
     * leaves the view by this commit, so its record is this verb's to retire. */
    err = metadata_prune_ancestors(metadata, stage_index(stage), &commit->pruned);
    if (err) goto cleanup;

    if (commit->pruned.count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "  Pruned %zu redundant directory entr%s",
            commit->pruned.count, commit->pruned.count == 1 ? "y" : "ies"
        );
    }

    /* The sheet onto the stage (single save for both files and directories) */
    err = metadata_save_to_stage(stage, metadata);
    if (err) goto cleanup;

    if (captured_file_count > 0 || updated_dir_count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "Updated metadata for %zu file%s and %zu director%s",
            captured_file_count, captured_file_count == 1 ? "" : "s",
            updated_dir_count, updated_dir_count == 1 ? "y" : "ies"
        );
    }

    /* Build array of storage paths for commit message: what the commit captured
     * and what it let go — the bookkeeping, so an item the walk skipped is not
     * named. Both kinds, a captured directory claim being a path the commit took
     * as surely as a blob is (utils/commit.h). A retired claim is named with
     * them (it leaves the view by this commit); an authored one only rides, the
     * pruned-keys precedent, so a derivation that only refreshed names nothing
     * and the message's path list says so. */
    size_t named_count = commit->captured_count + commit->deleted_count +
        commit->retired.count;
    const char **storage_paths = NULL;
    if (named_count > 0) {
        storage_paths = arena_calloc(ctx->arena, named_count, sizeof(*storage_paths));

        size_t named = 0;
        for (size_t i = 0; i < commit->captured_count; i++) {
            storage_paths[named++] = commit->captured[i].storage_path;
        }
        for (size_t i = 0; i < commit->deleted_count; i++) {
            storage_paths[named++] = commit->deleted[i]->storage_path;
        }
        for (size_t i = 0; i < commit->retired.count; i++) {
            storage_paths[named++] = commit->retired.entries[i];
        }
    }

    /* Build commit message context */
    commit_message_context_t msg_ctx = {
        .action        = COMMIT_ACTION_UPDATE,
        .profile       = profile,
        .paths         = storage_paths,
        .path_count    = named_count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };

    /* The commit, and whether it landed: the stage's own answer, false for a
     * tree the walk left as the stage opened it — captures that put back what
     * the branch holds, which a hook rewriting a file between the decision and
     * the capture makes */
    err = stage_commit(
        stage, commit_message(ctx->arena, ctx->config, &msg_ctx), &commit->committed
    );

cleanup:
    /* Free resources in reverse order */
    if (metadata) metadata_free(metadata);

    return err;
}

/**
 * Write the record for the commits that landed
 *
 * Called over the commits that landed — error or no: a later profile's failure
 * invalidates nothing about an earlier profile's landed commit, so the record
 * follows each one. The view is computed, so nothing projects; what update writes
 * is the one thing only it knows about the paths it committed — read off each
 * commit's own bookkeeping (commit_t), so a path the walk skipped gets no record
 * write. A modified or new file was captured FROM disk, so where the capture's
 * own claim still stands at its path in the post-commit view the record is what
 * the capture committed — its node, its blob under the stat the capture took
 * (the next status takes the fast path), its claim — stamped as an ownership
 * event. The view says whose the path is and nothing else: a commit another writer
 * landed since moves what Git holds past the capture, which the next load reads
 * as Git's move ([stale]), never as a capture of it. A path the commit let go —
 * a deleted item, a directory entry the walk's prune dropped as redundant, or
 * an ancestor claim the derivation dropped — left Git by this commit: with no
 * row left at the path its record retires (nothing backs it now); with a lower
 * profile's row at the path it is a fallback — the record stays and reads
 * [reassigned] until apply deploys it. The rule "write only where the row IS
 * the captured claim" is the same one add applies (core/manifest.h's
 * manifest_is_claim): a row another profile won is its own, and so is one a second
 * claim of this very profile won. Both kinds: a directory's claim (mode, ownership)
 * is captured from disk exactly as add captures it, so the capture owns the
 * directory the same way — the ownership the orphan gate asks for on scope exit
 * — with no stat triple, a directory having no content to confirm.
 *
 * Algorithm:
 *   1. No commit landed: nothing to write, and no lock taken to write it
 *   2. Begin write transaction on caller's handle
 *   3. Build the post-commit view once, under the lock; one lookup per committed
 *      path
 *   4. Commit transaction
 *
 * Preconditions:
 *   - Every entry in commits is a landed Git commit
 *   - the run's state is a live handle (DB open), borrowed from the dispatcher
 *   - commits is what update_execute returned
 *
 * Postconditions:
 *   - The record written for the committed paths as above
 *   - Transaction committed or rolled back atomically; state handle left clean
 *
 * Error Handling:
 *   - Non-fatal: Git commits succeeded and stand
 *   - The store's refusals — the begin's, a write's, the commit's — are returned
 *     in their own words (core/state.h), the one message the caller's warning
 *     prints
 *   - On any error after the begin, the rollback keeps state clean so the caller
 *     can continue to post-update hook and cleanup deterministically
 *   - Caller should warn user
 *
 * Performance: one view build + O(N) point lookups, N = committed paths
 *
 * @param ctx Dispatch context (must not be NULL; the repository, the state handle
 *            and the mount table come off the run, the view is built into
 *            ctx->arena)
 * @param commits One commit's bookkeeping per landed commit (may be NULL when
 *                count is 0)
 * @param commit_count Number of commits
 * @return Error or NULL on success
 */
static error_t update_write_record(
    const dotta_ctx_t *ctx,
    const commit_t *commits,
    size_t commit_count
) {
    CHECK_NULL(ctx);

    /* Nothing landed: nothing to write, and no lock to take for it */
    if (commit_count == 0) return NULL;

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    const mount_table_t *mounts = ctx->run.mounts;
    output_t *out = ctx->out;

    size_t synced = 0, removed = 0, fallbacks = 0;   /* The split, said once the commit lands */

    /* The lock, and every decision below made under it (state_begin) */
    error_t err = state_begin(state);
    if (err) return err;

    /* The post-commit view, once */
    manifest_t *manifest = NULL;
    err = manifest_build(repo, state, ctx->arena, &manifest);
    if (err) goto cleanup;

    /* One lookup per committed path, both kinds; the arms of the header doc. A
     * path let go and a fallback receive no ownership event: there is no disk
     * confirmation for a deleted path, and a fallback's disk content is what
     * this profile's blob was, not the fallback blob. */
    time_t now = time(NULL);

    for (size_t c = 0; c < commit_count; c++) {
        const commit_t *commit = &commits[c];

        for (size_t i = 0; i < commit->captured_count; i++) {
            /* What the capture committed, where its claim still stands, and the
             * phase's stamp: the ownership event */
            state_record_t record = commit->captured[i];
            const manifest_row_t *row = manifest_lookup(manifest, record.filesystem_path);
            if (!manifest_is_claim(row, commit->profile, record.storage_path)) {
                continue;
            }
            record.deployed_at = now;

            err = state_write(state, &record);
            if (err) goto cleanup;
            synced++;
        }

        /* What the commit let go: the deleted items by their own path, the keys
         * — the pruned entries and the dropped ancestor claims — by the path
         * this profile deploys them at (UNBOUND names nothing on this machine:
         * nothing to release). */
        for (size_t i = 0; i < commit->deleted_count; i++) {
            const workspace_item_t *item = commit->deleted[i];
            const manifest_row_t *row = manifest_lookup(manifest, item->filesystem_path);

            if (!row) {
                err = state_retire(state, item->filesystem_path);
                if (err) goto cleanup;
                removed++;
            } else if (strcmp(row->profile, commit->profile) != 0) {
                fallbacks++;
            }
            /* else: still this profile's row — the commit did not remove it;
             * not ours to count. */
        }

        const string_array_t *let_go[] = { &commit->pruned, &commit->retired };
        for (size_t b = 0; b < sizeof(let_go) / sizeof(let_go[0]); b++) {
            for (size_t i = 0; i < let_go[b]->count; i++) {
                const char *filesystem_path = mount_resolve(
                    ctx->arena, mounts, commit->profile, let_go[b]->entries[i]
                );
                /* An unbound claim resolves nowhere on this machine: no filesystem
                 * path, so nothing to look up and no record of this run's to
                 * retire. Whatever record a once-bound era may have left is an
                 * orphan the next load's analysis settles. */
                if (!filesystem_path) continue;

                const manifest_row_t *row = manifest_lookup(manifest, filesystem_path);
                if (!row) {
                    err = state_retire(state, filesystem_path);
                    if (err) goto cleanup;
                    removed++;
                } else if (strcmp(row->profile, commit->profile) != 0) {
                    fallbacks++;
                }
            }
        }
    }

    err = state_commit(state);
    if (err) goto cleanup;

    /* The split of the "Record updated" line cmd_update says, said once the commit
     * landed: a count said before it would stand above a COMMIT the store refused
     * (core/state.h state_commit) */
    if (synced > 0 || removed > 0 || fallbacks > 0) {
        output_info(
            out, OUTPUT_VERBOSE,
            "Record synced: %zu staged, %zu removed, %zu fallback%s",
            synced, removed, fallbacks, fallbacks == 1 ? "" : "s"
        );
    }

cleanup:
    /* The transaction ends here either way: a refused one is rolled back, and a
     * committed one has already ended (state_rollback finds none to end) */
    state_rollback(state);

    return err;
}

/**
 * Execute profile updates, in enabled-set order
 *
 * One stage per profile visited: opened at the branch's tip, edited by the walk,
 * committed once, freed — nothing is checked out anywhere.
 *
 * Profiles are walked in enabled-set order — the model's one canonical profile
 * order — so multi-profile runs commit, report, and (on a stop) strand in one
 * predictable sequence; within a profile, items keep filter order. Every item's
 * and every row's profile is in the enabled set by construction (the view is
 * built from it), so the per-profile gathers drop nothing. A profile is visited
 * when it has items to commit or chains to re-derive: a named run's row slice
 * reaches profiles whose items all held still, which is what makes the derivation's
 * consent trigger — and the remedy it carries — work on a quiet tree at all. A
 * bare run hands no rows and visits exactly the profiles it always did.
 *
 * The commits that landed cross the error boundary: out_commits receives one
 * bookkeeping entry per landed commit, written as the commit lands, so the caller
 * holds it even when a later profile fails and the record write follows what
 * Git shows. A profile whose commit did not land — a walk that touched nothing,
 * one whose captures put back what the branch holds, or a failure before its
 * commit — contributes no entry, and its items are neither counted nor said.
 *
 * @param ctx Dispatch context (must not be NULL; the stages are opened on the
 *            run's repository, the capture reads the key and the encryption policy)
 * @param enabled The enabled set, in order (must not be NULL)
 * @param work The run's work: the accepted items, less the new files where the
 *             user declined them (empty where a named run has only chains to
 *             re-derive)
 * @param derive_rows The named run's in-scope view rows, the chains to re-derive
 *                    (empty on a bare run)
 * @param opts Update options (must not be NULL)
 * @param total_updated Output: total items committed across all profiles (must
 *                      not be NULL)
 * @param out_commits Output: one commit's bookkeeping per landed commit, in the
 *                    command arena; set on every return (must not be NULL)
 * @param out_commit_count Output: number of entries in out_commits (must not be
 *                         NULL)
 * @return Error or NULL on success
 */
static error_t update_execute(
    const dotta_ctx_t *ctx,
    const string_array_t *enabled,
    workspace_items_t work,
    manifest_rows_t derive_rows,
    const cmd_update_options_t *opts,
    size_t *total_updated,
    commit_t **out_commits,
    size_t *out_commit_count
) {
    CHECK_NULL(ctx);
    CHECK_NULL(enabled);
    CHECK_NULL(opts);
    CHECK_NULL(total_updated);
    CHECK_NULL(out_commits);
    CHECK_NULL(out_commit_count);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    *total_updated = 0;
    *out_commit_count = 0;

    /* One bookkeeping slot per enabled profile — an upper bound; only landed
     * commits fill one, each as it lands, so the caller holds every commit that
     * landed whichever profile stops the run. */
    commit_t *commits = arena_calloc(ctx->arena, enabled->count, sizeof(*commits));
    *out_commits = commits;

    /* One profile's items and chains, gathered afresh for each profile into two
     * arrays sized once to the whole run's: update_profile keeps no pointer into
     * either — the bookkeeping holds each item it deleted, and each capture its
     * record — so a landed commit keeps its own when the next profile refills
     * them */
    const workspace_item_t **items = arena_calloc(ctx->arena, work.count, sizeof(*items));
    const manifest_row_t **rows = arena_calloc(ctx->arena, derive_rows.count, sizeof(*rows));

    for (size_t p = 0; p < enabled->count; p++) {
        const char *profile = enabled->entries[p];

        /* This profile's items, in filter order */
        size_t item_count = 0;
        for (size_t i = 0; i < work.count; i++) {
            if (strcmp(work.entries[i]->profile, profile) == 0) {
                items[item_count++] = work.entries[i];
            }
        }

        /* This profile's chains to re-derive, when the run named paths */
        size_t row_count = 0;
        for (size_t i = 0; i < derive_rows.count; i++) {
            if (strcmp(derive_rows.entries[i]->profile, profile) == 0) {
                rows[row_count++] = derive_rows.entries[i];
            }
        }

        if (item_count == 0 && row_count == 0) {
            continue;
        }

        /* Display profile header */
        output_section(
            out, OUTPUT_NORMAL, "Updating profile '{cyan}%s{reset}':",
            profile
        );

        /* The profile's stage: the branch as it stands now, the parent of the
         * commit the walk makes. Its life is this iteration's. */
        char refname[DOTTA_REFNAME_MAX];
        error_t err = gitops_branch_refname(refname, sizeof(refname), profile);
        if (err) return err;

        stage_t *stage = NULL;
        err = stage_open(repo, refname, &stage);
        if (err) return err;

        /* Update this profile on its stage */
        commit_t bookkeeping = { 0 };
        err = update_profile(
            ctx, stage, profile,
            (workspace_items_t){ .entries = items, .count = item_count },
            (manifest_rows_t){ .entries = rows, .count = row_count },
            opts, &bookkeeping
        );
        stage_free(stage);

        /* Any error is a failure before the commit: no commit landed, whatever
         * the bookkeeping holds */
        if (err) return err;

        /* Whether the commit landed is the stage's answer, read off the
         * bookkeeping: the walk's lists say what it did to the tree, and a tree
         * it left as the stage opened it is no commit — nothing to report, nothing
         * to record */
        if (!bookkeeping.committed) continue;

        /* The commit landed: its bookkeeping is the record write's now, the
         * caller's whatever a later profile meets. Its user items are what it
         * captured and deleted; a derivation-only commit carries none. */
        commits[(*out_commit_count)++] = bookkeeping;
        size_t processed = bookkeeping.captured_count + bookkeeping.deleted_count;
        *total_updated += processed;

        if (!output_is_verbose(out)) {
            if (processed > 0) {
                output_print(
                    out, OUTPUT_NORMAL, "  {green}✓{reset} Updated %zu item%s\n",
                    processed, processed == 1 ? "" : "s"
                );
            } else {
                /* A derivation-only commit: no user item moved, the chains did */
                output_print(
                    out, OUTPUT_NORMAL, "  {green}✓{reset} Re-derived the ancestry\n"
                );
            }
        }
    }

    return NULL;
}

/**
 * Render the preview: the run's work, grouped by fate
 *
 * One section per fate the partition answered — modified, new, deleted (both
 * kinds), directory claims, encryption violations — each listing its fate's items
 * and none when it holds none, every hint speaking update's own voice: what this
 * run will do. A dry run renders identically; whether anything was written is
 * the summary's one line at the end of the run, not the preview's.
 *
 * @param out Output context (must not be NULL)
 * @param partition The partition, whose fates are read (must not be NULL; a named
 *                  run whose rows all held still has none to preview — its filter
 *                  context printed ahead of the census)
 */
static void update_print_preview(output_t *out, const partition_t *partition) {
    CHECK_NULL(out);
    CHECK_NULL(partition);

    /* Display modified files section */
    if (partition->modified_files.count > 0) {
        output_list_t *list = output_list_create(
            out, "Modified files",
            "will be committed to their profiles"
        );

        for (size_t i = 0; i < partition->modified_files.count; i++) {
            const workspace_item_t *item = partition->modified_files.entries[i];

            /* Extract tags using shared helper */
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char base_metadata[256];

            if (!workspace_item_tags(
                item, tags, &tag_count, &color,
                base_metadata, sizeof(base_metadata)
                )) {
                continue;
            }

            output_list_add(
                list, tags, tag_count, color,
                item->filesystem_path, base_metadata
            );
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Display new files section */
    if (partition->new_files.count > 0) {
        output_list_t *list = output_list_create(
            out, "New files",
            "will be added to their profiles"
        );

        for (size_t i = 0; i < partition->new_files.count; i++) {
            const workspace_item_t *item = partition->new_files.entries[i];

            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];

            if (workspace_item_tags(
                item, tags, &tag_count, &color,
                metadata, sizeof(metadata)
                )) {
                output_list_add(
                    list, tags, tag_count, color,
                    item->filesystem_path, metadata
                );
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Display deleted paths section — one fate, both kinds: a deleted directory
     * is a deletion, so it lists beside the deleted files rather than under a
     * section that promises a metadata update */
    if (partition->deleted.count > 0) {
        output_list_t *list = output_list_create(
            out, "Deleted paths",
            "will be removed from their profiles"
        );

        for (size_t i = 0; i < partition->deleted.count; i++) {
            const workspace_item_t *item = partition->deleted.entries[i];

            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char base_metadata[256];

            if (!workspace_item_tags(
                item, tags, &tag_count, &color,
                base_metadata, sizeof(base_metadata)
                )) {
                continue;
            }

            /* Directory rows read as directories: trailing slash, kind named —
             * the same shape the claims section uses */
            char path[PATH_MAX + 2];
            snprintf(
                path, sizeof(path), "%s%s", item->filesystem_path,
                path_kind_suffix(item->item_kind)
            );

            if (item->item_kind == PATH_KIND_DIRECTORY) {
                char metadata[256];
                snprintf(
                    metadata, sizeof(metadata), "directory %s",
                    base_metadata
                );

                output_list_add(
                    list, tags, tag_count, color,
                    path, metadata
                );
            } else {
                output_list_add(
                    list, tags, tag_count, color,
                    path, base_metadata
                );
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Display modified directories section */
    if (partition->modified_dirs.count > 0) {
        output_list_t *list = output_list_create(
            out, "Modified directories",
            "directory metadata will be updated"
        );

        for (size_t i = 0; i < partition->modified_dirs.count; i++) {
            const workspace_item_t *item = partition->modified_dirs.entries[i];

            /* Extract tags and metadata using helper */
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char base_metadata[256];

            if (workspace_item_tags(
                item, tags, &tag_count, &color,
                base_metadata, sizeof(base_metadata)
                )) {
                /* Build custom content with trailing slash for directories */
                char path[PATH_MAX + 2];
                snprintf(
                    path, sizeof(path), "%s%s", item->filesystem_path,
                    path_kind_suffix(item->item_kind)
                );

                /* Build custom metadata with explicit "directory" indicator */
                char metadata[256];
                snprintf(
                    metadata, sizeof(metadata), "directory %s",
                    base_metadata
                );

                output_list_add(
                    list, tags, tag_count, color,
                    path, metadata
                );
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Display encryption policy violations section */
    if (partition->unencrypted.count > 0) {
        output_list_t *list = output_list_create(
            out, "Encryption policy violations",
            "match auto-encrypt patterns but are stored as plaintext"
        );

        for (size_t i = 0; i < partition->unencrypted.count; i++) {
            const workspace_item_t *item = partition->unencrypted.entries[i];

            char metadata[512];
            snprintf(
                metadata, sizeof(metadata), "from %s, will be encrypted",
                item->profile
            );

            /* Single tag for policy violation */
            const char *tags[] = { "plaintext" };
            output_list_add(
                list, tags, 1, OUTPUT_COLOR_RED,
                item->filesystem_path, metadata
            );
        }

        output_list_render(list);
        output_list_free(list);

        output_gap(out, OUTPUT_NORMAL);
        output_info(
            out, OUTPUT_NORMAL, "These files will be encrypted on the next commit, "
            "per auto_encrypt in your config's [encryption] section."
        );
        output_info(
            out, OUTPUT_NORMAL, "To keep a file as plaintext, "
            "narrow the pattern that matches it before this commit."
        );
    }
}

/**
 * Update command implementation
 */
error_t cmd_update(const dotta_ctx_t *ctx, const cmd_update_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    content_cache_t *content_cache = ctx->run.content_cache;
    const manifest_t *manifest = ctx->run.manifest;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Build operation scope
     *
     *   scope_enabled  — the persistent enabled set, the CLI filter's bound.
     *   scope_profiles — update operation face (hook context string).
     *
     *   scope_accepts_profile / scope_accepts_path, then scope_is_excluded —
     *   the per-item gates: update_partition's, and the named run's rows'
     *   (scope_accepts_entry)
     */
    scope_inputs_t scope_inputs = {
        .profiles         = opts->profiles,
        .profile_count    = opts->profile_count,
        .files            = opts->files,
        .file_count       = opts->file_count,
        .exclude_patterns = opts->exclude_patterns,
        .exclude_count    = opts->exclude_count,
    };
    scope_t *scope = NULL;
    error_t err = scope_build(repo, manifest, &scope_inputs, ctx->arena, &scope);
    if (err) return err;

    /* Nothing to capture into: refused, in the words that say whether nothing
     * is enabled or no enabled profile has its branch */
    err = scope_require_enabled(state, scope_enabled(scope), ctx->arena);
    if (err) return err;

    /* Load workspace for update analysis
     *
     * Update processes files from the filesystem (either modified tracked files
     * or new files) and commits them to Git profiles.
     *
     * Orphan detection is unnecessary because update operates on view rows (files
     * from enabled profiles) and new files. Orphans (recorded but not in any
     * enabled profile) are out of scope for update operations, and the scan keeps
     * them so without it: a leaf the record holds is no discovery, asked of the
     * orphan items the load makes whether or not the orphan analysis ran
     * (core/workspace.h workspace_load). Running that analysis here would not
     * change one item.
     *
     * The scan is the run's one answer to whether new files are in scope at all:
     * a flag asks for them, or the config does, for the consent prompt — and
     * every discovery it makes is the run's (update_partition).
     *
     * State is borrowed from the dispatcher (ctx->run.state). Read-only analysis.
     * The transaction for the record write opens later in update_write_record().
     */
    workspace_options_t ws_opts = {
        .analyze_orphans   = false,     /* Update doesn't process orphaned files */
        .analyze_untracked = (opts->include_new || opts->only_new ||
            config->auto_detect_new_files) /* Explicit flags or config auto-detect */
    };
    workspace_t *ws = NULL;
    err = workspace_load(
        repo, state, config, content_cache, manifest, &ws_opts, ctx->arena, &ws
    );
    if (err) return err;

    /* What the load owes the record — its observations, its confirmations, the
     * voids of orders the view took back (core/workspace.h workspace_flush) —
     * the confirmations seeding the fast path for subsequent status/apply/update
     * calls. The flush keeps the failure of the transaction it takes, so update
     * proceeds on what the load read whatever the flush met.
     *
     * Files actually updated by this command get their record written separately
     * inside update_write_record(); this flush covers the clean files the analysis
     * verified but didn't modify. */
    err = workspace_flush(ws);
    if (err) return err;

    /* The run's filter context, ahead of everything the filter says against it:
     * the verbose "Excluded" log, the census, the nothing-exit and the preview */
    if (opts->only_new) {
        output_info(
            out, OUTPUT_NORMAL,
            "Filter: Showing only new files (--only-new)"
        );
    } else if (opts->include_new) {
        output_info(
            out, OUTPUT_NORMAL,
            "Filter: Including new files from tracked directories (--include-new)"
        );
    }
    if (opts->file_count > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Filter: Limiting to %zu specified path%s",
            opts->file_count, opts->file_count == 1 ? "" : "s"
        );
    }
    if (opts->exclude_count > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Filter: Excluding %zu pattern%s",
            opts->exclude_count, opts->exclude_count == 1 ? "" : "s"
        );
    }

    /* Partition the diverged items: the scope, the flags, and for a deployed
     * item the route table. */
    partition_t partition;
    update_partition(ws, opts, scope, ctx->arena, &partition);

    /* What the patterns spared, one verbose line each — as apply traces what
     * its plans spared (output_info gates on the verbosity, so a normal run pays
     * only the loop) */
    for (size_t i = 0; i < partition.excluded.count; i++) {
        output_info(
            out, OUTPUT_VERBOSE, "Excluded: %s",
            partition.excluded.entries[i]->filesystem_path
        );
    }

    /* What the filter refused, said once — above the exit below, so a workspace
     * whose only divergence is stale explains itself, and above the prompt. One
     * line per refusing arm, read off the partition's counts in the table's order
     * (workspace_item_route), each naming its route's way out. Two pairs arrive
     * split from the route by the claim that holds the offender — the same split
     * apply prints from the fate-borne ancestor_class: the displaced pair
     * (DISPLACED_TRACKED beneath a planned squatter --force replaces,
     * DISPLACED_DERIVED beneath a rung the named re-derivation drops) and the
     * retyped pair (KIND on a row a plan can hold, KIND_DERIVED on a rung dotta
     * only passes through). */
    const size_t *refused = partition.refused;

    if (refused[WORKSPACE_ROUTE_DISPLACED_TRACKED] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: not looked at, beneath a squatted directory — "
            "'dotta apply --force' replaces the squatter first",
            refused[WORKSPACE_ROUTE_DISPLACED_TRACKED],
            refused[WORKSPACE_ROUTE_DISPLACED_TRACKED] == 1 ? "" : "s"
        );
    }
    if (refused[WORKSPACE_ROUTE_DISPLACED_DERIVED] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: not looked at, beneath a squatted directory — "
            "'dotta update <dir>' re-derives the way there",
            refused[WORKSPACE_ROUTE_DISPLACED_DERIVED],
            refused[WORKSPACE_ROUTE_DISPLACED_DERIVED] == 1 ? "" : "s"
        );
    }
    if (refused[WORKSPACE_ROUTE_UNVERIFIABLE] > 0) {
        /* One arm, up to three lines — by whose remedy the failed look is
         * (workspace_fault_t), because one sentence over the three is how a locked
         * path came to be told to fix its permissions. The key's rows name the
         * verb that unlocks them, and the switch first where encryption is off;
         * the unreadable ones name permissions, and root where the run holds
         * none; the rest have no remedy to name and point at the listing that
         * names each path. */
        const size_t *faults = partition.faults;

        if (faults[WORKSPACE_FAULT_LOCKED] > 0) {
            output_info(
                out, OUTPUT_NORMAL, config->encryption_enabled
                    ? "%zu path%s skipped: locked — run 'dotta key set'"
                    : "%zu path%s skipped: locked, and encryption is disabled — set "
                "encryption.enabled = true, then run 'dotta key set'",
                faults[WORKSPACE_FAULT_LOCKED],
                faults[WORKSPACE_FAULT_LOCKED] == 1 ? "" : "s"
            );
        }
        if (faults[WORKSPACE_FAULT_UNREADABLE] > 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "%zu path%s skipped: cannot be read — fix permissions, or exclude with -e",
                faults[WORKSPACE_FAULT_UNREADABLE],
                faults[WORKSPACE_FAULT_UNREADABLE] == 1 ? "" : "s"
            );
            if (!identity()->privileged) {
                output_info(out, OUTPUT_NORMAL, "  Run under sudo to read them");
            }
        }
        if (faults[WORKSPACE_FAULT_UNVERIFIED] > 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "%zu path%s skipped: could not be verified — 'dotta status' lists %s",
                faults[WORKSPACE_FAULT_UNVERIFIED],
                faults[WORKSPACE_FAULT_UNVERIFIED] == 1 ? "" : "s",
                faults[WORKSPACE_FAULT_UNVERIFIED] == 1 ? "it" : "them"
            );
        }
    }
    if (refused[WORKSPACE_ROUTE_CONFLICT] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu file%s skipped: changed in Git and on disk — 'dotta diff' shows "
            "Git's version against disk, 'dotta apply --force' keeps Git's, "
            "'dotta add --force' keeps disk's",
            refused[WORKSPACE_ROUTE_CONFLICT],
            refused[WORKSPACE_ROUTE_CONFLICT] == 1 ? "" : "s"
        );
    }
    if (refused[WORKSPACE_ROUTE_STALE] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: changed in Git — run 'dotta apply' first",
            refused[WORKSPACE_ROUTE_STALE],
            refused[WORKSPACE_ROUTE_STALE] == 1 ? "" : "s"
        );
    }
    if (refused[WORKSPACE_ROUTE_KIND] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: a different kind stands on disk — "
            "'dotta apply --force' replaces %s, 'dotta remove' untracks %s",
            refused[WORKSPACE_ROUTE_KIND],
            refused[WORKSPACE_ROUTE_KIND] == 1 ? "" : "s",
            refused[WORKSPACE_ROUTE_KIND] == 1 ? "it" : "them",
            refused[WORKSPACE_ROUTE_KIND] == 1 ? "it" : "them"
        );
    }
    if (refused[WORKSPACE_ROUTE_KIND_DERIVED] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: a different kind stands at a directory dotta "
            "only passes through — 'dotta update <dir>' re-derives %s",
            refused[WORKSPACE_ROUTE_KIND_DERIVED],
            refused[WORKSPACE_ROUTE_KIND_DERIVED] == 1 ? "" : "s",
            refused[WORKSPACE_ROUTE_KIND_DERIVED] == 1 ? "it" : "them"
        );
    }

    /* Where the scan could not look, by path and above the exit below, so a run
     * that found nothing to add still says where it could not look: this may be
     * the one screen that has them — status scans only where the config asks,
     * and this run may have scanned on its own flag. Each line is the item's
     * tags and path, as status lists it; add meets each cause again and prints
     * it. */
    if (partition.unscanned.count > 0) {
        output_list_t *list = output_list_create(
            out, "Not scanned for new files",
            "nothing at or beneath these is offered; 'dotta add -n' says why"
        );

        for (size_t i = 0; i < partition.unscanned.count; i++) {
            const workspace_item_t *item = partition.unscanned.entries[i];
            const char *tags[WORKSPACE_ITEM_MAX_TAGS];
            size_t tag_count;
            output_color_t color;
            char metadata[256];
            char path[PATH_MAX + 2];

            if (workspace_item_tags(
                item, tags, &tag_count, &color, metadata, sizeof(metadata)
                )) {
                snprintf(
                    path, sizeof(path), "%s%s", item->filesystem_path,
                    path_kind_suffix(item->item_kind)
                );
                output_list_add(list, tags, tag_count, color, path, metadata);
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* A named path re-derives its subtree's chains. Naming is consent, so a run
     * given paths climbs the chain of every in-scope row under them, captured
     * or not — the explicit backfill, and the remedy for a rung the world moved
     * under. The slice is the leaves: blob rows and tracked directory rows, each
     * the root of its own chain; an ancestor claim is never a leaf — its own
     * re-derivation is carried by the leaves beneath it, which the residue rule
     * guarantees exist. The exclude gate binds here (the user excluded the path
     * from this operation), where the chain riding a captured leaf stays
     * scope-blind like add's — an exclusion names a path, never the way to it.
     * A bare run names nothing and derives nothing. The leaves grow as the walk
     * finds them rather than into room for the whole view: a named path picks a
     * few rows out of all of them. */
    manifest_rows_t derive_rows = { 0 };
    if (opts->file_count > 0) {
        manifest_rows_t rows = manifest_rows(manifest);
        const manifest_row_t **leaves = NULL;
        size_t leaf_count = 0;
        size_t leaf_capacity = 0;

        for (size_t i = 0; i < rows.count; i++) {
            const manifest_row_t *row = rows.entries[i];

            if (manifest_is_derived(row)) {
                continue;
            }
            if (!scope_accepts_entry(
                scope, row->profile,
                row->filesystem_path, row->storage_path, path_type_kind(row->type)
                )) {
                continue;
            }
            leaves = arena_grow(
                ctx->arena, leaves, &leaf_capacity, leaf_count + 1, sizeof(*leaves)
            );
            leaves[leaf_count++] = row;
        }

        derive_rows = (manifest_rows_t){ .entries = leaves, .count = leaf_count };
    }

    /* Check if we have anything to update — or, on a named run, any chains to
     * re-derive: whether a chain moved is the walk's to discover, so the named
     * run proceeds on the slice alone and the summary says what came of it */
    if (partition.accepted.count == 0 && derive_rows.count == 0) {
        if (opts->only_new) {
            output_info(out, OUTPUT_NORMAL, "No new files to add");
        } else if (opts->include_new) {
            output_info(out, OUTPUT_NORMAL, "No modified or new files/directories to update");
        } else {
            output_info(out, OUTPUT_NORMAL, "No modified files or directories to update");
        }
        return NULL;
    }

    /* Preview: what this run will do, grouped by the fates the partition
     * answered */
    update_print_preview(out, &partition);

    /* The hooks fire around the work — after the nothing-exit (a no-op run fires
     * nothing), before the prompt: apply's order. The preview's verdicts predate
     * the pre-hook, but the capture stores execute-time bytes — a pre-hook that
     * edits a candidate still commits what it wrote. */
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_UPDATE,
        .profile    = string_array_join(ctx->arena,scope_profiles(scope),  " "),
        .files      = opts->files,
        .file_count = opts->file_count,
        .dry_run    = opts->dry_run,
    };

    err = hook_fire_pre(config, out, &hook_inv);
    if (err) return err;

    /* The run's work: the accepted items — less the new files, where the user
     * declines them below. A value the command holds; the partition's list is
     * never edited. */
    workspace_items_t work = partition.accepted;

    /* The prompts — none bind a dry run: it executes nothing, so there is nothing
     * to consent to */
    if (!opts->dry_run) {
        if (opts->interactive) {
            /* -i asked to be asked: declined is the user's word, and no answer
             * refuses the run, since nobody declined */
            switch (output_ask(out, false, "Update these items?")) {
                case OUTPUT_ANSWER_YES:
                    break;
                case OUTPUT_ANSWER_NO:
                    output_info(out, OUTPUT_NORMAL, "Cancelled");
                    return NULL;
                case OUTPUT_ANSWER_NONE:
                    return error_create(
                        ERR_VALIDATION,
                        "Cannot update: -i asks before updating, and no answer was read"
                    );
            }
        }

        /* New files no flag asked for — the config's scan found them — are added
         * only with consent. Declining keeps the rest of the run — the preview
         * named the new files separately, and the receipt reports what actually
         * happens. What is left is asked the nothing-exit's own question, so a
         * named run whose only accepted items were new files still re-derives
         * the chains it named. */
        if (partition.new_files.count > 0 && config->confirm_new_files &&
            !opts->include_new && !opts->only_new) {

            /* The new files are an extra the run stands without: declined, or
             * unanswered and said so with the flag that adds them, they leave
             * the work alike. They are the accepted items' suffix: the discoveries
             * follow every other diverged item (core/workspace.h
             * workspace_diverged), and the partition keeps the order it walks
             * in — so the rest of the run is the prefix before them. */
            switch (output_ask(
                out, false, "Found %zu new file%s. Add %s to profiles?",
                partition.new_files.count, partition.new_files.count == 1 ? "" : "s",
                partition.new_files.count == 1 ? "it" : "them"
                )) {
                case OUTPUT_ANSWER_YES:
                    break;
                case OUTPUT_ANSWER_NO:
                    work.count -= partition.new_files.count;
                    break;
                case OUTPUT_ANSWER_NONE:
                    output_info(
                        out, OUTPUT_NORMAL, "%zu new file%s not added: no answer was "
                        "read; --include-new adds %s", partition.new_files.count,
                        partition.new_files.count == 1 ? "" : "s",
                        partition.new_files.count == 1 ? "it" : "them"
                    );
                    work.count -= partition.new_files.count;
                    break;
            }

            /* Nothing left: the new files were the run's whole work, and they
             * were left out */
            if (work.count == 0 && derive_rows.count == 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "No modified files remaining after skipping new files"
                );
                return NULL;
            }
        }
    }

    /* Execute profile updates, in enabled-set order. Filtered to operation scope.
     * ctx->run.keymgr is borrowed by the capture inside per-profile iteration.
     * A dry run executes nothing: the sections above are its preview, and the
     * summary below is its one sentence. */
    commit_t *commits = NULL;
    size_t commit_count = 0;
    size_t total_updated = 0;
    error_t record_err = NULL;   /* The record phase's fate: non-fatal, read by the stop and the summary */
    if (!opts->dry_run) {
        err = update_execute(
            ctx, scope_enabled(scope), work, derive_rows, opts, &total_updated,
            &commits, &commit_count
        );

        /* Write the record — for the commits that landed, error or no
         *
         * Captured files get their record written because UPDATE captures them
         * FROM the filesystem (already at their target paths): what each capture
         * committed, stamped as dotta's. The view itself is computed at every
         * load and needs no update. A mid-sequence stop above changes nothing
         * here: the landed commits are Git truth and the record follows them;
         * the profiles that never committed have nothing to write.
         *
         * Non-fatal, and said in landed terms: its fate is the error, which is
         * carried to the screens that read it — the stop's, and the summary's. */
        record_err = update_write_record(ctx, commits, commit_count);

        if (record_err) {
            /* The landed commits are Git truth and the record's write failed
             * behind them, rolled back whole: the record is what it was. The
             * next load confirms what it finds disk agrees with; a file new to
             * the record is apply's to adopt, and the paths the commits let go
             * are apply's to settle. A directory the commits re-captured keeps
             * the ownership its record already held — apply earns none for a
             * directory (cmds/add.c add_write_record) — which is the conservative
             * side: an unowned directory is released at scope exit, never pruned.
             * Said in landed terms — after a mid-sequence stop only some profiles
             * committed, and this line must not claim more. */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to update the record: %s",
                error_line(record_err)
            );
            output_info(
                out, OUTPUT_NORMAL,
                "The commits that landed are in Git; the record was not written - "
                "what it already held stands"
            );
            output_hint(
                out, OUTPUT_NORMAL,
                "Run 'dotta apply' to adopt the files they added and settle the paths "
                "they let go"
            );
        } else if (err && commit_count > 0) {
            /* The executor stopped mid-sequence, and the commits that landed
             * are recorded (just above): said before the stop is reported, so
             * the ✓ lines above are accounted for */
            output_info(out, OUTPUT_NORMAL, "Record updated");
        }

        if (err) return err;
    }

    /* Execute post-update hook (the hooks layer suppresses it on a dry run) */
    hook_fire_post(config, out, &hook_inv);

    /* Summary — one truthful line */
    output_gap(out, OUTPUT_NORMAL);
    if (opts->dry_run) {
        output_info(out, OUTPUT_NORMAL, "Dry run: nothing was committed");
    } else if (commit_count == 0) {
        /* Every profile committed nothing (the walk's race guard refused what
         * the plan admitted, or the captures put back what the branch holds):
         * say so instead of counting zero */
        output_info(out, OUTPUT_NORMAL, "Nothing was committed");
    } else {
        if (total_updated > 0) {
            output_success(
                out, OUTPUT_NORMAL, "Updated %zu item%s across %zu profile%s",
                total_updated, total_updated == 1 ? "" : "s",
                commit_count, commit_count == 1 ? "" : "s"
            );
        } else {
            /* Every landed commit was derivation-only: say what moved instead
             * of counting zero items */
            output_success(
                out, OUTPUT_NORMAL, "Re-derived the ancestry across %zu profile%s",
                commit_count, commit_count == 1 ? "" : "s"
            );
        }

        /* Record feedback, plain: the per-path split is the verbose "Record synced"
         * line, and the failure case already said what happened (warning above) */
        if (!record_err) {
            output_info(out, OUTPUT_NORMAL, "Record updated");
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta status' to verify state"
            );
        }
    }

    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `files[]` and `profiles[]`.
 *
 * Positional rule (differs from add — position-dependent):
 *   - First positional: a file path or a profile name, by whether it announces a
 *     path (infra/path.h path_input_announces_path). A file path lands in `files`;
 *     a name lands in `profiles`.
 *   - Remaining positionals: always file paths.
 *
 * Profiles from `-p` are already populated in `profiles` by the APPEND row; a
 * positional profile appends onto that list. Files go into a fresh arena-backed
 * array.
 */
static error_t update_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) cmd;
    cmd_update_options_t *o = opts_v;

    if (o->positional_count == 0) {
        return NULL;
    }

    /* Worst case: every positional becomes a file. */
    char **files = arena_calloc(arena, o->positional_count, sizeof(char *));
    size_t file_count = 0;

    for (size_t i = 0; i < o->positional_count; i++) {
        char *arg = o->positional_args[i];

        /* Only the first positional is ambiguous (profile or file). It becomes
         * a profile only if -p was not given AND it announces no path. */
        if (i == 0 && o->profile_count == 0 &&
            !path_input_announces_path(arg)) {
            /* Arena-backed 1-slot profile array for the positional. */
            char **profiles = arena_calloc(arena, 1, sizeof(char *));
            profiles[0] = arg;
            o->profiles = profiles;
            o->profile_count = 1;
            continue;
        }

        files[file_count++] = arg;
    }

    if (file_count > 0) {
        o->files = files;
        o->file_count = file_count;
    }

    return NULL;
}

/**
 * What can stand at the cursor, by the rule update_post_parse routes with: an
 * enabled profile while the first positional is still open and -p has not taken
 * it; at every position a path of the view (files, and directory claims as subtree
 * filters) — narrowed to what the profiles named so far win — or a filesystem path.
 */
static args_want_t update_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_update_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_update_options_t, profiles)) {
        completion_profiles(ctx, out, COMPLETION_ENABLED);
        return ARGS_WANT_NONE;
    }
    if (at->value_of != NULL) {
        return ARGS_WANT_NONE;   /* -m, -e: free text */
    }

    char *const *winners = o->profiles;
    size_t winner_count = o->profile_count;
    if (o->profile_count == 0) {
        if (o->positional_count == 0) {
            completion_profiles(ctx, out, COMPLETION_ENABLED);
        } else if (!path_input_announces_path(o->positional_args[0])) {
            winners = o->positional_args;   /* the profile slot was taken */
            winner_count = 1;
        }
    }
    completion_files(ctx, out, winners, winner_count, true);
    return ARGS_WANT_FILES;
}

static error_t update_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_update(ctx, (const cmd_update_options_t *) opts_v);
}

static const args_opt_t update_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "m message",         "<msg>",
        cmd_update_options_t,message,
        "Commit message"
    ),
    ARGS_APPEND(
        "p profile",         "<name>",
        cmd_update_options_t,profiles,         profile_count,
        "Filter update to profile(s) (repeatable)"
    ),
    ARGS_APPEND(
        "e exclude",         "<pattern>",
        cmd_update_options_t,exclude_patterns, exclude_count,
        "Skip paths matching a .dottaignore-style pattern (repeatable)"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_update_options_t,dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG(
        "i interactive",
        cmd_update_options_t,interactive,
        "Prompt for confirmation before committing"
    ),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_update_options_t,verbosity,        DOTTA_VERBOSITY_VERBOSE,
        "Verbose output"
    ),
    ARGS_FLAG(
        "include-new",
        cmd_update_options_t,include_new,
        "Also stage new files inside tracked directories"
    ),
    ARGS_FLAG(
        "only-new",
        cmd_update_options_t,only_new,
        "Stage only new files; skip modifications"
    ),
    ARGS_POSITIONAL_RAW(
        cmd_update_options_t,positional_args,  positional_count,
        0,                   0
    ),
    ARGS_END,
};

const args_command_t spec_update = {
    .name         = "update",
    .summary      = "Commit filesystem changes back to profiles",
    .usage        = "%s update [options] [profile|file]...",
    .description  =
        "Commit filesystem modifications to the matching profile branches\n"
        "(the reverse direction of 'apply'). Mode is captured alongside\n"
        "content, and ownership for root/ and custom/ paths that are not\n"
        "yours.\n",
    .notes        =
        "File Detection:\n"
        "  New files inside tracked directories are included based on\n"
        "  config: core.auto_detect_new_files toggles detection,\n"
        "  security.confirm_new_files toggles the prompt. --include-new\n"
        "  and --only-new override both for this invocation.\n",
    .examples     =
        "  %s update                             # All modified files\n"
        "  %s update ~/.bashrc                   # Specific file\n"
        "  %s update -p global                   # Filter to 'global'\n"
        "  %s update --include-new               # Modified + new files\n"
        "  %s update --only-new                  # New files only\n"
        "  %s update -n                          # Preview without writing\n"
        "  %s update --exclude '*.log'           # Skip log files\n"
        "  %s update -m \"Update shell config\"    # Custom commit message\n",
    .epilogue     =
        "See also:\n"
        "  %s status          # See what will be committed\n"
        "  %s sync            # Publish committed changes to remote\n",
    .opts_size    = sizeof(cmd_update_options_t),
    .opts         = update_opts,
    .post_parse   = update_post_parse,
    .complete     = update_complete,
    .payload      = &(const dotta_needs_t){
        .repo     = DOTTA_REPO_OPEN,
        .state    = DOTTA_STATE_READ,
        .mounts   = true,
        .crypto   = DOTTA_CRYPTO_OBTAIN,
        .manifest = true,
    },
    .dispatch     = update_dispatch,
};
