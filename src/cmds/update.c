/**
 * update.c - Commit filesystem changes back to profiles
 */

#include "cmds/update.h"

#include <config.h>
#include <git2.h>
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
#include "core/policy.h"
#include "core/profiles.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "infra/commit.h"
#include "infra/content.h"
#include "infra/path.h"
#include "infra/pathspec.h"
#include "sys/filesystem.h"
#include "utils/hooks.h"

/**
 * Capture a path from the filesystem as the entry it becomes
 *
 * A regular file is sealed as the policy decides (core/policy.h), and the seal
 * it keeps — priority 3 — is the one the profile holds at this name in the tree
 * its draft opened at, its stamp or its blob's own bytes (core/profiles.h
 * profile_sealed). Either sealing is the answer, so a sheet that disagrees with
 * its tree — a hand edit, another tool's commit, the contradicted claim a profile
 * decodes as no claim at all (core/profiles.c profile_step) — never has this
 * capture store in the clear what either calls a secret.
 *
 * Routed by what the load observed at the path, as add routes by what its listing
 * found there (cmds/add.c add_capture) — every item on this route carries an
 * occupant, a diverged file's from the join's look and an offer's from the walk.
 * No look is taken here: each capture takes its own and refuses the other's
 * occupant (infra/content.h), so a path whose kind changed since the load is
 * refused rather than read as what it has become, which is the refusal a second
 * look here would only have moved one frame earlier — the walk looks once the
 * refusal is in, to tell a change since the preview from any other
 * (update_profile).
 *
 * This routes, decides and captures; the entry and the claim the capture becomes
 * are the draft's to make (core/profiles.h profile_capture_file), and the record
 * the caller's. So the profile is asked here and never edited: the one question
 * asked of it is the prior above.
 *
 * @param ctx Dispatch context (must not be NULL; supplies the key and the
 *            encryption policy)
 * @param base The profile as its draft opened it (must not be NULL): the seal
 *             it holds at the item's name is the prior this capture's policy
 *             reads, and its name the seal's key
 * @param item The path to capture (must not be NULL; its occupant chooses the
 *             capture, its two keys name the source and the seal)
 * @param out The capture (must not be NULL; cleared here before the policy can
 *            refuse, so freeing it is correct on every path)
 */
static error_t update_capture(
    const dotta_ctx_t *ctx,
    profile_t *base,
    const workspace_item_t *item,
    content_capture_t *out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(base);
    CHECK_NULL(item);
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

    /* Priority 3's source: the seal the profile holds at this name in the tree
     * its draft opened at — the head, which no edit moves; no blob at all, a
     * name new to the profile or a gitlink a hand left, which places nothing,
     * holds none. A seal that cannot be read is the capture's failure, never
     * "not encrypted". */
    bool sealed = false;
    error_t err = profile_sealed(base, storage_path, &sealed);
    if (err) return err;

    /* Handle regular file - determine encryption policy using centralized logic */
    bool should_encrypt = false;
    err = encryption_policy_should_encrypt(
        ctx->config,
        storage_path,
        ENCRYPTION_REQUEST_NONE,  /* update carries no encryption flags */
        sealed,
        &should_encrypt
    );
    if (err) return err;

    /* The entry the file becomes: read → seal as decided → the bytes, the mode
     * and the fstat of the descriptor they came off, bytes and look one inode
     * by construction (infra/content.h content_capture_t). */
    return content_capture_file(
        filesystem_path, storage_path, profile_name(base), keymgr, should_encrypt, out
    );
}

/**
 * One capture a commit took: the item, what it committed, and its seal
 *
 * The record is the record phase's (update_write_record) — the node the capture
 * held to, the blob the commit holds at the name, the triple its bytes were read
 * with (a file's, the fstat of the descriptor it read; a link's, the lstat before
 * its target; none for a directory, which confirms no content), and the claim
 * the capture answered — so the phase writes what this commit put there, never
 * what a later head of the branch says should be. The item and the seal are the
 * receipt's (update_print_receipt): the path as the walk met it, its kind's slash
 * read as a deletion's row reads its item, and whether the bytes landed sealed,
 * which no column of the record holds (core/state.h state_record_t).
 */
typedef struct {
    const workspace_item_t *item;      /* The item captured, the workspace's */
    state_record_t record;             /* What the capture committed, as the record keeps it */
    bool encrypted;                    /* The claim's seal: the bytes landed sealed */
} update_captured_t;

/**
 * What one profile's update commit did, path by path
 *
 * Filled by the walk that does the work — one edit per item on the profile's
 * draft: the capture for a file, the claim capture for a directory, the removal
 * for a deletion — and by the climbs and the commit after it, and read back by
 * the receipt (update_print_receipt), the run's line and the record phase
 * (update_write_record), so each follows the commit and nothing else: an item
 * the walk skipped (a path the race guard refused) lands in no list, and gets
 * no row and no record write. The message is the draft's, never these lists,
 * and whether the commit landed at all is the commit's own answer (core/profiles.h
 * profile_commit) — a walk whose edits leave both documents as the draft opened
 * them lands none, whatever its lists hold — and the executor hands on only the
 * bookkeeping of a commit that landed (update_execute).
 *
 * A capture is kept whole (update_captured_t), its names the item's (workspace
 * lifetime) and the command arena's (the claim's, which the capture answers there).
 * A deletion is kept as the item it took, the workspace's, which the command
 * arena holds past the record phase: its path is where the phase reclaims the
 * record of the node already gone. What the climbs claim and retire and what
 * the prune takes are counts — a derived claim is the way to the claims, never
 * one (core/profiles.h profile_capture_ancestors) — which the receipt says; the
 * record of each is the next apply's to decide.
 *
 * Memory: every member is the command arena's, and nothing frees a commit.
 */
typedef struct {
    const char *profile;               /* Borrowed from the enabled set */
    git_oid oid;                       /* The commit, Git's null id where none landed: its own answer */
    update_captured_t *captured;       /* What each capture committed */
    size_t captured_count;
    const workspace_item_t **deleted;  /* The DELETED items the deletions took (the workspace's) */
    size_t deleted_count;
    size_t ancestors_captured;         /* Rungs the climbs claimed from the disk */
    size_t ancestors_retired;          /* Derived claims the climbs retired */
    size_t ancestors_pruned;           /* Derived claims the commit's prune took */
} update_commit_t;

/**
 * What the filter made of the diverged items, in scope
 *
 * One walk partitions every in-scope item five ways. Excluded — an -e pattern's,
 * whatever the state rule would say of it: answered for the command's trace,
 * and never touched. Accepted — the run's work: a deployed item on the capture
 * route, and under --force one on either route no default takes, a conflict or
 * bytes no base proves, where the capture commits the node standing
 * (core/workspace.h workspace_capturable); a deleted path; a new file under a
 * tracked directory when a flag or the config asked for it. Skipped — a deployed
 * item on any other route (workspace_item_route), and a row no copy stands at
 * yet, each counted under the section status lists it in (cmds/status.c
 * status_partition_t), so the summary names what the run left in status's words
 * (update_print_skipped) and a count is status's where the scopes agree; a
 * multi-bit divergence counts once, in the section of the route that skipped
 * it. Unscanned — a place the scan could not look: never accepted, since what
 * it could not judge may be what Git excludes, and listed by path rather than
 * counted (cmd_update), since this run may have scanned on its own flag where
 * status, which scans only where the config asks, has no row of it — where it
 * has one, its Unverifiable paths lists it beside the failed looks the count of
 * that name holds. Or neither — a reassignment apply settles in the record alone,
 * an orphan's state, which this load never makes, and, under --only-new, every
 * deployed, deleted and undeployed item: the user asked about new files, nothing
 * about the others answers that, so none is accepted and none is counted (a skip
 * would name a section the user did not ask about) — but a directory the load
 * could not look at, beneath which the scan never looked either, which is counted
 * among the skipped.
 *
 * An accepted item is answered by its fate as well — the preview lists one section
 * per fate, and the new-files prompt counts new_files. The modified fate splits
 * by kind (a directory's modification is a claim recapture, not a content commit),
 * deleted deliberately does not (a deleted directory is a deletion), and the
 * deployed files split by what diverged (core/workspace.h divergence_type_t): a
 * path bit is a modification — a conflict --force took among them, its line's
 * [stale] saying Git moved too — save over bytes no base proves, which --force
 * takes into a fate of their own, their line reading as a modification's
 * (workspace_item_line); the blob bit, ENCRYPTION, a policy violation the commit
 * seals. A file with both kinds of bit is in both; a violator with nothing changed
 * on disk only among the violations — it is committed for the re-store, not for
 * a modification; and one a link stands over only in its path bit's fate — its
 * capture commits the link's target, never sealed (update_capture), which resolves
 * the violation by removing the plaintext, as a deletion's commit does. So every
 * accepted item has a fate, and a file may have two.
 *
 * The lists are slices one classification fills (core/workspace.h
 * workspace_buckets_t), each in the diverged items' order, in the arena the
 * partition was made in — the items borrowed, the workspace's. The discoveries
 * follow every other diverged item (workspace_diverged), so the new files are
 * accepted's suffix: what cmd_update's question drops, and what the summary counts
 * beside the skipped (update_print_skipped).
 *
 * The skipped counts are status's sections, folded off the route table here as
 * status_partition folds them there — two folds the compiler holds to the table
 * and not to each other, so a section moved there moves its count here. The one
 * section of this load they leave out is the reassignments, which ask nothing
 * of the disk or the user — apply acknowledges them in the record alone — as
 * status's workspace line leaves them uncounted (cmds/status.c
 * status_print_summary).
 *
 * The equation: in-scope deployed items no pattern spared = accepted deployed ∪
 * skipped deployed ∪ the reassignments, by one switch that routes each item once
 * — nothing is counted twice, nothing falls through, and the diverged items hold
 * no clean row. Under --force the unconfirmed count is zero — every such row is
 * one a capture commits, KIND answering first — and the conflicts count every
 * KIND and the conflicts across file and directory alone.
 */
typedef struct {
    workspace_items_t accepted;              /* The run's work */

    /* The accepted items by fate, in the preview's order */
    workspace_items_t modified_files;        /* DEPLOYED files with a path bit: content or metadata, conflict */
    workspace_items_t unconfirmed;           /* DEPLOYED files --force took whose bytes no base proves */
    workspace_items_t new_files;             /* UNTRACKED files from tracked directories */
    workspace_items_t deleted;               /* DELETED paths, both kinds */
    workspace_items_t modified_dirs;         /* DEPLOYED directories: claim capture */
    workspace_items_t unencrypted;           /* DEPLOYED violators the commit seals (a path bit beside it or alone) */

    workspace_items_t excluded;              /* In scope, spared by -e — traced, never touched */
    workspace_items_t unscanned;             /* In scope, where the scan could not look — listed, never taken */

    /* In scope, skipped — by the section status lists each in */
    struct {
        size_t conflicts;                    /* CONFLICT --force did not take, and KIND */
        size_t unconfirmed;                  /* UNCONFIRMED --force did not take */
        size_t squatted;                     /* KIND_DERIVED */
        size_t displaced;                    /* DISPLACED_*: beneath a squatter, not looked at */
        size_t unverifiable;                 /* UNVERIFIABLE: a look at a row that failed */
        size_t undeployed;                   /* STALE, and UNDEPLOYED: apply's */
    } skipped;
} update_partition_t;

/**
 * Partition the workspace's diverged items for update
 *
 * The scope first: the profiles and paths the user named — a place the scan could
 * not look reached by a path the filter may select beneath it — then the patterns
 * they excluded, the order every scope reader asks in (core/scope.h
 * scope_accepts_entry). Then the state rule under the flags, and for a deployed
 * item the route, the two no default takes under --force's consent: the partition
 * (update_partition_t). It decides in silence: what it answers, the command says
 * (cmd_update traces the excluded, as apply traces its plans').
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
    update_partition_t *partition
) {
    CHECK_NULL(ws);
    CHECK_NULL(opts);
    CHECK_NULL(scope);
    CHECK_NULL(arena);
    CHECK_NULL(partition);

    *partition = (update_partition_t){ 0 };

    /* Each item is added to its lists as the walk decides it, and every list is
     * filled once the walk is done — the arena's, beside the items they borrow */
    workspace_items_t diverged = workspace_diverged(ws);
    workspace_buckets_t *buckets = workspace_buckets_create(arena);

    for (size_t i = 0; i < diverged.count; i++) {
        const workspace_item_t *item = diverged.entries[i];

        /* Outside the profiles and the paths the user named: invisible, as to
         * every scope reader — the path filter reads both names. A place the
         * scan could not look answers for every path beneath it, so a path the
         * filter may select there reaches it too (infra/pathspec.h
         * pathspec_matches_beneath): nothing beneath it was looked at, a named
         * one included */
        if (!scope_accepts_profile(scope, item->profile)) continue;
        if (!scope_accepts_path(
            scope, item->filesystem_path, item->storage_path, item->item_kind
            ) &&
            !(item->state == WORKSPACE_STATE_UNSCANNED && pathspec_matches_beneath(
                scope_paths(scope), item->filesystem_path, item->storage_path
            ))) {
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
                 * status's sections read (workspace_item_route; workspace.h carries
                 * each arm's why), one arm a section as status files them, so
                 * the compiler holds this filter to the table. CAPTURE is update's
                 * own, and the two arms no default takes, CONFLICT and UNCONFIRMED,
                 * are its under --force; every other arm is skipped, counted
                 * under its section, so the preview never promises an update
                 * the executor would refuse and the summary names what the run
                 * left in status's words. Under --only-new the user asked about
                 * new files alone: neither accepted nor counted — but a directory
                 * the load could not look at, beneath which the scan did not
                 * look either (no root is registered where the join's look failed,
                 * and the walk adds no item where a rung's did), so the new files
                 * asked for may stand there. */
                const workspace_route_t route = workspace_item_route(item);
                if (opts->only_new && (route != WORKSPACE_ROUTE_UNVERIFIABLE ||
                    item->item_kind != PATH_KIND_DIRECTORY)) {
                    continue;
                }

                switch (route) {
                    case WORKSPACE_ROUTE_CAPTURE:
                        /* The user's own, over a base: a directory's fate is
                         * its claim; a file's, a path bit standing, a modification
                         * — a violator nothing changed on disk has the blob bit's
                         * fate alone, below */
                        if (item->item_kind == PATH_KIND_DIRECTORY) {
                            workspace_buckets_add(buckets, item, &partition->modified_dirs);
                        } else if ((item->divergence & ~DIVERGENCE_ENCRYPTION) != DIVERGENCE_NONE) {
                            workspace_buckets_add(buckets, item, &partition->modified_files);
                        }
                        break;

                    case WORKSPACE_ROUTE_CONFLICT:
                    /* Both sides moved: under --force disk's, where the capture
                     * commits the node standing (workspace_capturable) — never
                     * a change across file and directory, which STALE answers
                     * before KIND. Its fate is an edit's, its line's [stale]
                     * saying the commit goes over a move of Git's */
                    case WORKSPACE_ROUTE_KIND:
                        /* A kind no capture commits, Git having moved nothing
                         * past it: the ladder reads KIND only where
                         * workspace_capturable answers no, so no --force takes
                         * one, and it is counted beside the conflicts, as status
                         * files it */
                        if (opts->force && workspace_capturable(item)) {
                            workspace_buckets_add(buckets, item, &partition->modified_files);
                            break;
                        }
                        partition->skipped.conflicts++;
                        continue;

                    case WORKSPACE_ROUTE_UNCONFIRMED:
                        /* No base proves who moved: under --force disk's, where
                         * the capture commits the node standing — every such
                         * row, KIND answering first, asked as its twin above
                         * asks it. Listed apart, its line reading as a
                         * modification's (workspace_item_line) */
                        if (opts->force && workspace_capturable(item)) {
                            workspace_buckets_add(buckets, item, &partition->unconfirmed);
                            break;
                        }
                        partition->skipped.unconfirmed++;
                        continue;

                    case WORKSPACE_ROUTE_KIND_DERIVED:
                        /* A kind at a rung dotta only passes through, which no
                         * flag lifts: the squatted ancestors */
                        partition->skipped.squatted++;
                        continue;

                    case WORKSPACE_ROUTE_DISPLACED_TRACKED:
                    case WORKSPACE_ROUTE_DISPLACED_DERIVED:
                    case WORKSPACE_ROUTE_DISPLACED_STALE:
                    case WORKSPACE_ROUTE_DISPLACED_CONFLICT:
                        /* Beneath a squatter, not looked at: one section whoever
                         * the squatter is, its own section naming the way out */
                        partition->skipped.displaced++;
                        continue;

                    case WORKSPACE_ROUTE_UNVERIFIABLE:
                        /* A look that failed, whatever its class */
                        partition->skipped.unverifiable++;
                        continue;

                    case WORKSPACE_ROUTE_STALE:
                        /* Git moved and disk did not follow: apply's, beside
                         * the rows no copy stands at yet */
                        partition->skipped.undeployed++;
                        continue;

                    case WORKSPACE_ROUTE_REASSIGNED:
                    /* Apply's, in the record alone: neither taken nor counted
                     * (update_partition_t) */
                    case WORKSPACE_ROUTE_CLEAN:
                        /* None: a diverged item has something to say
                         * (workspace_diverged) */
                        continue;
                }

                /* The blob bit's fate, beside the path bit's: the ENCRYPTION
                 * bit a violation the commit seals, so a file with both is in
                 * both, and a directory, which holds no blob, never here. A link
                 * standing over a violator is captured as its target, never sealed
                 * (update_capture): its path bit's fate alone, whose commit removes
                 * the plaintext as a deletion's does */
                if ((item->divergence & DIVERGENCE_ENCRYPTION) &&
                    item->occupant != FS_OCCUPANT_SYMLINK) {
                    workspace_buckets_add(buckets, item, &partition->unencrypted);
                }
                break;
            }

            case WORKSPACE_STATE_DELETED:
                /* Removed from disk since dotta confirmed there the content the
                 * claim still holds (core/workspace.c classify_absent): the
                 * deletion is update's to commit, unless the user asked about
                 * new files alone. One fate for both kinds, and a deleted violator
                 * is a deletion too: its commit resolves the violation by removing
                 * the plaintext. */
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
                 * counted (cmd_update): this run may have scanned on its own
                 * flag, and status may have no row of it */
                workspace_buckets_add(buckets, item, &partition->unscanned);
                continue;

            case WORKSPACE_STATE_UNDEPLOYED:
                /* A row no copy stands at yet: apply's to deploy, counted where
                 * status lists it, beside a move of Git's disk has not followed
                 * — unless the user asked about new files alone */
                if (opts->only_new) continue;
                partition->skipped.undeployed++;
                continue;

            case WORKSPACE_STATE_ORPHANED:
            case WORKSPACE_STATE_RELEASED:
            case WORKSPACE_STATE_OVERRIDDEN:
            case WORKSPACE_STATE_OBSTRUCTING:
                /* Another verb's: a record the view lacks (cleanup prunes or
                 * releases it), a copy beneath a blob, which that blob's landing
                 * clears, or dotta's node above a row, which the landing beneath
                 * it replaces — never update's to commit, and never met here:
                 * this load declines the orphans' analysis */
                continue;
        }

        workspace_buckets_add(buckets, item, &partition->accepted);
    }

    workspace_buckets_fill(buckets);
}

/**
 * Update a single profile with workspace items
 *
 * One walk, one edit per item on the profile's draft, each made where the walk
 * finds what the load found and each filling the commit's bookkeeping beside
 * it: a deletion takes its claim by its kind, a file's capture becomes its entry
 * and its claim, a directory's its claim; a path changed since the preview is
 * skipped and said. The chain rides the capture: after the walk, every captured
 * leaf's chain is climbed on the same commit — the content now comes from this
 * machine; the way to it is claimed where the profile does not pass through it
 * yet, and re-derived where the run's paths reach it — and a named run hands in
 * the profile's in-scope rows the load could look along, each a leaf whose chain
 * is climbed whether or not anything about it diverged. The walk ends with the
 * commit, which prunes what nothing stands on any longer and saves the sheet
 * where a claim moved.
 *
 * Success means committed or untouched, and the bookkeeping says which
 * (commit->oid, the commit's own answer): a walk whose edits moved nothing —
 * none at all, or captures that put back what the profile holds — commits nothing.
 * A mid-walk failure returns with the draft part-edited: the executor stops the
 * run there, and a draft that is never committed changes nothing in the repository.
 *
 * @param ctx Dispatch context (must not be NULL; the capture reads the key and
 *            the encryption policy off it, the climb the mount table)
 * @param draft The profile's draft, opened by the caller (must not be NULL)
 * @param profile Profile to update — the enabled set's name, which the bookkeeping
 *                keeps past the draft (must not be NULL)
 * @param items The profile's share of the run's work, in filter order (empty
 *              where the profile has only chains to re-derive)
 * @param rows The named run's in-scope view rows for this profile, each the leaf
 *             of a chain re-derived where `path_filter` selects it, none beneath
 *             a squatter the view keeps (empty on a bare run, which names no
 *             paths, and under --only-new, which asks about new files alone)
 * @param path_filter The run's path filter (core/scope.h scope_paths), read with
 *                    the rows alone; NULL on a bare run
 * @param opts Update options (must not be NULL)
 * @param commit The commit's bookkeeping, zero-filled by the caller; the walk
 *               fills it (must not be NULL)
 * @return Error or NULL on success
 */
static error_t update_profile(
    const dotta_ctx_t *ctx,
    profile_draft_t *draft,
    const char *profile,
    workspace_items_t items,
    manifest_rows_t rows,
    const pathspec_t *path_filter,
    const cmd_update_options_t *opts,
    update_commit_t *commit
) {
    CHECK_NULL(ctx);
    CHECK_NULL(draft);
    CHECK_NULL(profile);
    CHECK_NULL(opts);
    CHECK_NULL(commit);

    output_t *out = ctx->out;

    commit->profile = profile;

    /* The capture and deletion lists can each hold every item; the walk fills
     * them with the ones that landed, a rows-only call's at none */
    commit->captured = arena_calloc(ctx->arena, items.count, sizeof(*commit->captured));
    commit->deleted = arena_calloc(ctx->arena, items.count, sizeof(*commit->deleted));

    /* One walk, one edit per item on the profile's draft, each filling the
     * bookkeeping beside it */
    for (size_t i = 0; i < items.count; i++) {
        const workspace_item_t *item = items.entries[i];

        /* The race guard. A deletion and a directory's claim are edits of the
         * load's look — nothing stood there, a directory stood there — where a
         * file's capture reads the path itself and refuses another kind
         * (update_capture). So the walk looks again at those two and edits only
         * where it finds what the load found: anything else — a node standing
         * again, a directory gone or of another kind, a look that now fails —
         * is a change since the preview (a hook, the new files' question, an
         * editor racing the run), skipped and said, and the next load reads what
         * stands there. An lstat, never a stat: a link in a directory's place
         * is another kind, so no target's attributes reach the claim, which is
         * captured off this look. What changes after it, the commit cannot see
         * (stated): one edit's window, where the load's look alone would leave
         * the run's. A file's refusal meets the same question once it is in (the
         * file arm below), so a change since the preview is a skip whatever the
         * edit. */
        struct stat st;
        if ((item->state == WORKSPACE_STATE_DELETED || item->item_kind == PATH_KIND_DIRECTORY) &&
            fs_lstat_occupant(item->filesystem_path, &st) != item->occupant) {
            output_warning(
                out, OUTPUT_NORMAL, "Skipping '%s%s': changed on disk since the preview",
                item->filesystem_path, path_kind_suffix(item->item_kind)
            );
            continue;
        }

        /* A deletion, of either kind, ahead of both arms: it takes the claim of
         * the item's kind, a file's blob and FILE item or a directory's tracking
         * — a deleted row is a tracked one (core/workspace.c classify_absent) —
         * never the other kind's at the name, so a directory claim the blob
         * contradicted stands again once the blob is gone (core/profiles.h
         * profile_remove). The row said the profile holds it, so one the commit
         * lacks — another writer's commit since the load — is the model's error
         * and stops the run, never a no-op. Then the bookkeeping, so the record
         * phase reclaims it */
        if (item->state == WORKSPACE_STATE_DELETED) {
            error_t err = profile_remove(draft, item->item_kind, item->storage_path);
            if (err) return err;

            commit->deleted[commit->deleted_count++] = item;
            continue;
        }

        switch (item->item_kind) {
            case PATH_KIND_FILE: {
                /* The capture, and the entry and the claim it becomes on the
                 * profile's draft, at the name the seal was made under
                 * (infra/content.h). One tail past both: the bytes are released
                 * whichever refused, the look staying readable for the record,
                 * and each refusal names the path itself — the capture's the
                 * file, the commit's the name it lands at. Either stops the run
                 * at this profile (update_execute) but over a path changed since
                 * the preview, an owner or a group this host cannot name among
                 * them (core/profiles.h profile_capture_file), which the directory
                 * arm below skips: the preview listed the file among what the
                 * run commits, no item carrying what its owner's lookup answers
                 * (stated) */
                content_capture_t capture = { 0 };
                profile_claim_t claim;
                error_t err = update_capture(ctx, profile_draft_base(draft), item, &capture);
                if (!err) {
                    err = profile_capture_file(
                        draft, item->storage_path, &capture, ctx->arena, &claim
                    );
                }
                content_capture_free(&capture);
                if (err) {
                    /* The race guard's question, asked once the refusal is in,
                     * never before the read (update_capture): a path that no
                     * longer stands as the load found it — another kind, gone,
                     * or a look that now fails, a parent made unreadable among
                     * them — is a change since the preview, skipped and said in
                     * the guard's words, the error dropped once said as the
                     * directory arm drops its own. Over the node the load found,
                     * the refusal is the run's (above) */
                    if (fs_lstat_occupant(item->filesystem_path, &st) == item->occupant) {
                        return err;
                    }

                    output_warning(
                        out, OUTPUT_NORMAL, "Skipping '%s': changed on disk since the preview",
                        item->filesystem_path
                    );
                    continue;
                }

                /* What the capture committed, as the record keeps it: the node
                 * the load found and the capture held to, the blob the commit
                 * holds at the name under the look its bytes came off, and the
                 * claim the capture answered — its mode the type's floor where
                 * it claims none, a link's, the record's don't-care under its
                 * kind — and the seal the claim carries, for the receipt */
                commit->captured[commit->captured_count++] = (update_captured_t){
                    .item = item,
                    .record = {
                        .filesystem_path = item->filesystem_path,
                        .storage_path    = item->storage_path,
                        .profile         = profile,
                        .kind            = item->occupant,
                        .blob_oid        = claim.blob_oid,
                        .stat            = state_stat_from_read(&capture.st),
                        .mode            = profile_claim_mode(&claim),
                        .owner           = claim.owner,
                        .group           = claim.group,
                    },
                    .encrypted = claim.encrypted,
                };
                break;
            }

            case PATH_KIND_DIRECTORY: {
                /* The claim, refreshed off the race guard's look and written
                 * tracked: a derived claim is asked nothing of a look
                 * (core/workspace.c workspace_analyze_directory), so every
                 * directory this arm meets is one the profile tracks. Its one
                 * refusal — an owner or a group this host cannot name — is
                 * non-fatal, and said at the verbosity the guard's skip is said
                 * at: the claim standing on the directory is left exactly as it
                 * is, and the commit as it was — absence of a capture is not
                 * knowledge that the claim is wrong — so the sheet quietly keeps
                 * saying something this run could not confirm. The error is dropped
                 * once said, one per such directory */
                profile_claim_t claim;
                error_t err = profile_capture_directory(
                    draft, item->storage_path, &st, ctx->arena, &claim
                );
                if (err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Skipping directory '%s': %s",
                        item->filesystem_path, error_line(err)
                    );
                    continue;
                }

                /* What the capture committed, as the record keeps it: the directory
                 * the guard above just held it to, and the claim the capture
                 * answered — no content, which a directory never confirms, and
                 * no seal */
                commit->captured[commit->captured_count++] = (update_captured_t){
                    .item = item,
                    .record = {
                        .filesystem_path = item->filesystem_path,
                        .storage_path    = item->storage_path,
                        .profile         = profile,
                        .kind            = FS_OCCUPANT_DIRECTORY,
                        .mode            = profile_claim_mode(&claim),
                        .owner           = claim.owner,
                        .group           = claim.group,
                    },
                };
                break;
            }
        }
    }

    /* The chain rides the capture: every leaf the walk took has its chain climbed
     * — the content now comes from this machine, and so does its way where the
     * profile does not pass through it yet, the first capture (add's own rule,
     * applied to the re-capture an update is), a rung it passes through keeping
     * its word whatever this disk holds there. After the walk, so a rung the
     * walk itself claimed stands as the walk's word; over both kinds, a captured
     * tracked directory having a chain of its own; and never over a deleted item
     * — the absence of a leaf says nothing about the chain that led to it. This
     * trigger authors but structurally never retires: a leaf beneath a squatted
     * rung was skipped at the filter (the route's displaced arms), whichever
     * profile's claim the squatter displaced, so a chain that reaches here holds
     * directories at every claimed rung. Its two outs count the claims it authored
     * and the ones it retired, into the bookkeeping for the receipt, the record
     * of each the next apply's to decide. */
    for (size_t i = 0; i < commit->captured_count; i++) {
        error_t err = profile_capture_ancestors(
            draft, ctx->run.mounts, commit->captured[i].record.storage_path,
            &commit->ancestors_captured, &commit->ancestors_retired
        );
        if (err) return err;
    }

    /* A named path re-derives its subtree's chains: the rows the caller gathered
     * are the leaves at and beneath the run's paths, each climbed whether or
     * not anything about it diverged and re-derived at each rung the paths select
     * — at and beneath a named path, never above one, so a named file re-derives
     * nothing of its chain (core/profiles.h profile_derive_ancestors). Naming
     * is consent, and this is the derivation's one route to a retire (a captured
     * leaf's chain cannot hold a squatted rung; a named one can where the squatter
     * is the user's at a rung, selected or not, and naming a path beneath it is
     * the remedy — no leaf beneath any other squatter is handed in, nor beneath
     * one at a lost blob's place, cmd_update). A row the walk also captured climbs
     * twice for free: the derivation counts only differences. */
    for (size_t i = 0; i < rows.count; i++) {
        error_t err = profile_derive_ancestors(
            draft, ctx->run.mounts, rows.entries[i]->storage_path, path_filter,
            &commit->ancestors_captured, &commit->ancestors_retired
        );
        if (err) return err;
    }

    /* The commit, where an edit moved either document: a capture, a deletion,
     * or a chain re-derived — which is not redundancy but the user's own word
     * about the disk, and drives the commit it needs, how the remedy for a rung
     * the world moved under works at all — while imported redundancy rides a
     * commit and never drives one. Its message names what the commit changes of
     * the profile's claims, as the walk and both climbs left the draft, never
     * the bookkeeping, which is the receipt's, the record's and the run line's.
     * Its prune takes what nothing stands on any longer, counted into the
     * bookkeeping for the receipt: the claim leaves the view by this commit,
     * and its record is the next apply's to decide. And the commit it made, the
     * commit's own answer, Git's null id for captures that put back what the
     * profile holds, which a hook rewriting a file between the decision and the
     * capture makes */
    const commit_words_t words = {
        .action     = COMMIT_ACTION_UPDATE,
        .title      = ctx->config->commit_title,
        .body       = ctx->config->commit_body,
        .custom_msg = opts->message,
    };
    return profile_commit(draft, &words, &commit->oid, &commit->ancestors_pruned);
}

/**
 * Write the record for the commits that landed
 *
 * Called over the commits that landed — error or no: a later profile's failure
 * invalidates nothing about an earlier profile's landed commit, so the record
 * follows each one. The view is computed, so nothing projects; what update writes
 * is the one thing only it knows about the paths it committed — read off each
 * commit's own bookkeeping (update_commit_t), so a path the walk skipped gets
 * no record write. A modified or new file was captured FROM disk, so where the
 * capture's own claim still stands at its path in the post-commit view the record
 * is what the capture committed — its node, its blob under the stat the capture
 * took (the next status takes the fast path), its claim — stamped as an ownership
 * event. The view says whose the path is and nothing else: a commit another writer
 * landed since moves what Git holds past the capture, which the next load reads
 * as Git's move ([stale]), never as a capture of it. The rule "write only where
 * the row IS the captured claim" is the same one add applies (core/manifest.h's
 * manifest_is_claim): a row another profile won is its own, and so is one a second
 * claim of this very profile won. Both kinds: a directory's claim (mode, ownership)
 * is captured from disk exactly as add captures it, so the capture owns the
 * directory the same way — the ownership the orphan gate asks for on scope exit
 * — with no stat triple, a directory having no content to confirm.
 *
 * A deletion the commit took reconciled Git to the absence its walk found again,
 * so the record of the gone node — this profile's, as the lock holds it — retires
 * where no row stands at its path after the commit, the reclaim: a claim that
 * returns there starts from its first look, where with the bytes the record
 * confirmed the record would read its absence as the user's deletion again
 * (core/workspace.c classify_absent). A row standing there keeps it, as that
 * row's history: a lower profile's surfacing, whose landing acknowledges it, or
 * another of this profile's names. Everything else the commit let go — the rungs
 * its prune and its climb took — is the next apply's, decided with the landings
 * it may stand in the way of (core/workspace.c workspace_analyze_orphans).
 *
 * Algorithm:
 *   1. No landed commit captured or deleted — none landed, or each re-derived
 *      the way alone, whose rungs are the next apply's (above): nothing to write,
 *      and no lock taken to write it
 *   2. Begin write transaction on caller's handle
 *   3. Build the post-commit view once, under the lock; one lookup per committed
 *      path, and the record read under the same lock, once per commit that deleted
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
 * Performance: one view build + O(N) point lookups, N = committed paths, and
 * one read of the record per commit that deleted
 *
 * @param ctx Dispatch context (must not be NULL; the repository and the state
 *            handle come off the run, the view is built into ctx->arena)
 * @param commits One commit's bookkeeping per landed commit (may be NULL when
 *                count is 0)
 * @param commit_count Number of commits
 * @return Error or NULL on success
 */
static error_t update_write_record(
    const dotta_ctx_t *ctx, const update_commit_t *commits, size_t commit_count
) {
    CHECK_NULL(ctx);

    /* No landed commit captured or deleted — none landed, or each re-derived
     * the way alone: nothing to write, and no lock to take for it */
    size_t owed = 0;
    for (size_t c = 0; c < commit_count; c++) {
        owed += commits[c].captured_count + commits[c].deleted_count;
    }
    if (owed == 0) return NULL;

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;

    /* The lock, and every decision below made under it (state_begin) */
    error_t err = state_begin(state);
    if (err) return err;

    /* The post-commit view, once */
    manifest_t *manifest = NULL;
    err = manifest_build(repo, state, ctx->arena, &manifest);
    if (err) goto cleanup;

    /* One lookup per committed path, both kinds; the arms of the header doc. A
     * deleted path receives no ownership event: there is no disk confirmation
     * for a node that is gone. */
    time_t now = time(NULL);

    for (size_t c = 0; c < commit_count; c++) {
        const update_commit_t *commit = &commits[c];

        for (size_t i = 0; i < commit->captured_count; i++) {
            /* What the capture committed, where its claim still stands, and the
             * phase's stamp: the ownership event */
            state_record_t record = commit->captured[i].record;
            const manifest_row_t *row = manifest_lookup(manifest, record.filesystem_path);
            if (!manifest_is_claim(row, commit->profile, record.storage_path)) {
                continue;
            }
            record.deployed_at = now;

            err = state_write(state, &record);
            if (err) goto cleanup;
        }

        /* What the commit reconciled to the absence its walk found again: each
         * deletion's record — a gone node's — retires where no row stands at
         * its path after the commit (the header doc). The record is read here,
         * under the phase's lock, and only for a commit that deleted: an update
         * that only captured reads none. */
        if (commit->deleted_count == 0) continue;

        state_record_t *records = NULL;
        size_t record_count = 0;
        err = state_records(state, ctx->arena, &records, &record_count);
        if (err) goto cleanup;

        for (size_t i = 0; i < commit->deleted_count; i++) {
            const char *filesystem_path = commit->deleted[i]->filesystem_path;
            const state_record_t *record = state_find_record(
                records, record_count, filesystem_path
            );

            /* This profile's record alone, as the lock holds it — another process
             * can have written the path since the load — and only where no row
             * stands there after the commit */
            if (!record || strcmp(record->profile, commit->profile) != 0 ||
                manifest_lookup(manifest, filesystem_path)) {
                continue;
            }

            err = state_retire(state, filesystem_path);
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
 * Execute profile updates, in enabled-set order
 *
 * One draft per profile visited: opened at its head, edited by the walk, committed
 * once, freed — nothing is checked out anywhere.
 *
 * Profiles are walked in enabled-set order — the model's one canonical profile
 * order — so multi-profile runs commit, report at verbose, and (on a stop) strand
 * in one predictable sequence; within a profile, items keep filter order. Every
 * item's and every row's profile is in the enabled set by construction (the view
 * is built from it), so the per-profile gathers drop nothing. A profile is visited
 * when it has items to commit or chains to re-derive: a named run's row slice
 * reaches profiles whose items all held still, which is what makes the derivation's
 * consent trigger — and the remedy it carries — work on a quiet tree at all. A
 * bare run hands no rows, nor does a run under --only-new, and each visits exactly
 * the profiles its items name.
 *
 * The commits that landed cross the error boundary: out_commits receives one
 * bookkeeping entry per landed commit, written as the commit lands, so the caller
 * holds it even when a later profile fails, and the receipt and the record write
 * follow what Git shows. A profile whose commit did not land — a walk that touched
 * nothing, one whose captures put back what the profile holds, or a failure before
 * its commit — contributes no entry, and its items are not counted. A failure
 * stops the run at its profile, and its error says so over the cause: the profiles
 * before it committed, the ones after it are never visited.
 *
 * @param ctx Dispatch context (must not be NULL; the drafts are opened on the
 *            run's repository, the capture reads the key and the encryption policy)
 * @param enabled The enabled set, in order (must not be NULL)
 * @param work The run's work: the accepted items, less the new files where the
 *             question left them out (empty where a named run has only chains
 *             to re-derive)
 * @param derive_rows The named run's in-scope view rows, the chains to re-derive,
 *                    none beneath a squatter the view keeps (empty on a bare
 *                    run and under --only-new)
 * @param path_filter The run's path filter, which selects the rungs of each row's
 *                    chain the run re-derives (core/scope.h scope_paths; NULL
 *                    on a bare run)
 * @param opts Update options (must not be NULL)
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
    const pathspec_t *path_filter,
    const cmd_update_options_t *opts,
    update_commit_t **out_commits,
    size_t *out_commit_count
) {
    CHECK_NULL(ctx);
    CHECK_NULL(enabled);
    CHECK_NULL(opts);
    CHECK_NULL(out_commits);
    CHECK_NULL(out_commit_count);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    *out_commit_count = 0;

    /* One bookkeeping slot per enabled profile — an upper bound; only landed
     * commits fill one, each as it lands, so the caller holds every commit that
     * landed whichever profile stops the run. */
    update_commit_t *commits = arena_calloc(ctx->arena, enabled->count, sizeof(*commits));
    *out_commits = commits;

    /* One profile's items and chains, gathered afresh for each profile into two
     * arrays sized once to the whole run's: update_profile keeps no pointer into
     * either — the bookkeeping holds each deletion's item in an array of its
     * own, and each capture its record — so a landed commit keeps its own when
     * the next profile refills them */
    const workspace_item_t **items = arena_calloc(ctx->arena, work.count, sizeof(*items));
    const manifest_row_t **rows = arena_calloc(ctx->arena, derive_rows.count, sizeof(*rows));

    /* What the walks say — a skip a change since the load forced, at every
     * verbosity — is one block beneath the preview: one boundary above every
     * profile's walk, paid by whichever of their lines is the first to print.
     * What each landed commit took is said once the walks are done, by the
     * receipt's own sections (update_print_receipt). */
    output_gap(out, OUTPUT_NORMAL);
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

        /* The profile's draft, opened at its head: the parent of the commit the
         * walk makes, and the profile every question of the walk is asked of,
         * its sheet read now — one that will not load stops the run, the loader's
         * words its cause. Its life is this iteration's. */
        profile_draft_t *draft = NULL;
        update_commit_t bookkeeping = { 0 };
        error_t err = profile_draft_open(repo, profile, &draft);
        if (!err) {
            err = update_profile(
                ctx, draft, profile,
                (workspace_items_t){ .entries = items, .count = item_count },
                (manifest_rows_t){ .entries = rows, .count = row_count },
                path_filter, opts, &bookkeeping
            );
        }
        profile_draft_free(draft);

        /* Any error is a failure before the commit — no commit landed, whatever
         * the bookkeeping holds — and stops the run here: the error says where,
         * over its cause */
        if (err) return error_wrap(err, "Update stopped at profile '%s'", profile);

        /* Whether the commit landed is the commit's own answer, read off the
         * bookkeeping: the walk's lists say what it edited, and edits that left
         * both documents as the draft opened them are no commit — nothing to
         * report, nothing to record */
        if (git_oid_is_zero(&bookkeeping.oid)) continue;

        /* The commit landed: its bookkeeping is the record write's now, the
         * caller's whatever a later profile meets */
        commits[(*out_commit_count)++] = bookkeeping;
    }

    return NULL;
}

/**
 * Render the preview: the run's work, grouped by fate
 *
 * One section per fate the partition answered — modified, unconfirmed (what --force
 * takes over no base), new, deleted (both kinds), directory claims, encryption
 * violations — each listing its fate's items and none when it holds none, every
 * hint speaking update's own voice: what this run will do, and of a deletion
 * how far it reaches. A dry run renders identically; whether anything was written
 * is the summary's one line at the end of the run, not the preview's.
 *
 * @param out Output context (must not be NULL)
 * @param manifest The view the run was loaded over (must not be NULL; a deleted
 *                 path's line names the claim that stands in its place once its
 *                 own leaves, off the view)
 * @param partition The partition, whose fates are read (must not be NULL; one
 *                  that accepted nothing has nothing to preview, every fate being
 *                  an accepted item's)
 */
static void update_print_preview(
    output_t *out, const manifest_t *manifest, const update_partition_t *partition
) {
    CHECK_NULL(out);
    CHECK_NULL(manifest);
    CHECK_NULL(partition);

    /* Display modified files section — the deployed files with a path bit:
     * divergent content or metadata, a conflict --force took among them, its
     * line's [stale] saying Git moved too */
    if (partition->modified_files.count > 0) {
        output_list_t *list = output_list_create(
            out, "Modified files",
            "will be committed to their profiles"
        );

        for (size_t i = 0; i < partition->modified_files.count; i++) {
            const workspace_item_t *item = partition->modified_files.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Display unconfirmed paths section — the deployed files --force took whose
     * bytes no base proves, under status's title: their line reads as a
     * modification's (workspace_item_line), so the title says what they are,
     * and the hint the fate the modifications' says */
    if (partition->unconfirmed.count > 0) {
        output_list_t *list = output_list_create(
            out, "Unconfirmed paths",
            "will be committed to their profiles"
        );

        for (size_t i = 0; i < partition->unconfirmed.count; i++) {
            const workspace_item_t *item = partition->unconfirmed.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Display new files section — the untracked files from tracked directories */
    if (partition->new_files.count > 0) {
        output_list_t *list = output_list_create(
            out, "New files",
            "will be added to their profiles"
        );

        for (size_t i = 0; i < partition->new_files.count; i++) {
            const workspace_item_t *item = partition->new_files.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Display deleted paths section — one fate, both kinds: a deleted directory
     * is a deletion, so it lists beside the deleted files rather than under a
     * section that promises a metadata update. The header says how far the commit
     * reaches: a copy its profile's history says update deleted is pruned by
     * every machine's next apply, where dotta deployed it and it is unchanged
     * (core/workspace.c workspace_analyze_orphans), its content and its claim
     * (core/cleanup.h cleanup_skip_reason). Where another profile claims the
     * path, its claim takes the place instead, and the line names it — the header
     * true of it all the same, since the copy goes — the reach in the words
     * status's Uncommitted changes legend gives it (cmds/status.c
     * status_print_workspace). A copy dotta only observed, which no apply on
     * its machine has adopted, is released however unchanged: the one the header
     * leaves out (stated). */
    if (partition->deleted.count > 0) {
        output_list_t *list = output_list_create(
            out, "Deleted paths",
            "will be deleted from their profiles, with every machine's unchanged copy"
        );

        /* The view's profiles, lowest precedence first, each asked below for
         * its claim at a deleted path */
        const string_array_t *profiles = manifest_profiles(manifest);

        for (size_t i = 0; i < partition->deleted.count; i++) {
            const workspace_item_t *item = partition->deleted.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            /* The claim that stands in the path's place once this one leaves:
             * the highest other profile's there, explicit or derived, standing
             * or not (core/manifest.h manifest_lookup_claim). What stands above
             * the path or beneath it is not read, so a claim a blob above it
             * stands over again, or one whose place the claims beneath it take,
             * is named all the same (stated, as cmds/remove.c remove_overlaps
             * states it of its claimants). */
            const manifest_row_t *other = NULL;
            for (size_t p = profiles->count; p-- > 0 && !other;) {
                if (strcmp(profiles->entries[p], item->profile) == 0) continue;
                other = manifest_lookup_claim(
                    manifest, profiles->entries[p], item->filesystem_path
                );
            }

            /* The other claim composed onto the line's metadata where there is
             * one, as status's Overridden section composes the blob above a copy */
            if (other) {
                char metadata[512];
                snprintf(
                    metadata, sizeof(metadata), "%s, %s's takes its place", line.metadata,
                    other->profile
                );
                output_list_add(list, line.tags, line.color, line.path, metadata);
            } else {
                output_list_add(list, line.tags, line.color, line.path, line.metadata);
            }
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Display modified directories section — the deployed directories, whose
     * capture is their claim: committed as a file's is, in the act the other
     * sections say */
    if (partition->modified_dirs.count > 0) {
        output_list_t *list = output_list_create(
            out, "Modified directories",
            "will be committed to their profiles"
        );

        for (size_t i = 0; i < partition->modified_dirs.count; i++) {
            const workspace_item_t *item = partition->modified_dirs.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* Display encryption policy violations section — the deployed violators the
     * commit seals, a path bit beside each or not: the one place a reader sees
     * every file the commit seals, an edited violator among the modifications
     * too (update_partition_t). Its header says the act and the way out, as a
     * status header does: the policy decides the seal (core/policy.h), so a file
     * meant to stay plaintext leaves the patterns before the commit */
    if (partition->unencrypted.count > 0) {
        output_list_t *list = output_list_create(
            out, "Encryption policy violations",
            "will be encrypted; narrow auto_encrypt to keep one plaintext"
        );

        for (size_t i = 0; i < partition->unencrypted.count; i++) {
            const workspace_item_t *item = partition->unencrypted.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
        }

        output_list_render(list);
        output_list_free(list);
    }
}

/**
 * Print the receipt: what each landed commit took, once it landed
 *
 * At verbose, a section a landed commit, in the enabled set's order: each item
 * the commit took, a row each — a capture with the claim it committed, then a
 * deletion as one — and beneath them the directories on their way the commit
 * moved, counted. Read off the bookkeeping alone (update_commit_t), so a commit
 * that did not land says nothing, however far its walk went, and an item the
 * walk skipped has no row: the walk said that skip as it met it. The rows take
 * apply's receipt's form (cmds/apply.c apply_print_deploy_receipt), where the
 * sections are by outcome; these are by commit, update's act being one commit a
 * profile, which its line counts across.
 *
 * @param out Output context (must not be NULL)
 * @param commits One commit's bookkeeping per landed commit (may be NULL when
 *                commit_count is 0)
 * @param commit_count Number of landed commits
 */
static void update_print_receipt(
    output_t *out, const update_commit_t *commits, size_t commit_count
) {
    CHECK_NULL(out);

    for (size_t c = 0; c < commit_count; c++) {
        const update_commit_t *commit = &commits[c];

        output_section(
            out, OUTPUT_VERBOSE, "Updated profile '{cyan}%s{reset}'", commit->profile
        );

        /* Each capture with the claim it committed, as the record keeps it: a
         * link's claims no mode, so the row names the link instead, as apply's
         * does; ownership is both names or neither at the capture (core/metadata.c
         * metadata_capture_ownership), so the owner alone is asked; and the seal,
         * which the record lacks, where the bytes landed sealed */
        for (size_t i = 0; i < commit->captured_count; i++) {
            const update_captured_t *captured = &commit->captured[i];
            const state_record_t *record = &captured->record;

            if (record->kind == FS_OCCUPANT_SYMLINK) {
                output_print(
                    out, OUTPUT_VERBOSE, "  {green}✓{reset} %s (symlink",
                    captured->item->filesystem_path
                );
            } else {
                output_print(
                    out, OUTPUT_VERBOSE, "  {green}✓{reset} %s%s (mode: %04o",
                    captured->item->filesystem_path,
                    path_kind_suffix(captured->item->item_kind), record->mode
                );
            }
            if (record->owner) {
                output_print(
                    out, OUTPUT_VERBOSE, ", owner: %s:%s", record->owner, record->group
                );
            }
            if (captured->encrypted) {
                output_print(out, OUTPUT_VERBOSE, ", encrypted");
            }
            output_print(out, OUTPUT_VERBOSE, ")\n");
        }

        /* Each deletion, either kind, by its slash */
        for (size_t i = 0; i < commit->deleted_count; i++) {
            const workspace_item_t *item = commit->deleted[i];

            output_print(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %s%s (deleted)\n",
                item->filesystem_path, path_kind_suffix(item->item_kind)
            );
        }

        /* The directories on the way to the profile's files the commit moved,
         * counted: a derived claim is the way to the claims, never one, so a
         * count is the whole of what is said of it (core/profiles.h
         * profile_capture_ancestors) — recorded off the disk where the profile
         * did not pass through them yet or the run named them, let go where another
         * kind stands at one, and pruned where no file stands beneath one any
         * longer */
        if (commit->ancestors_captured > 0) {
            output_print(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %zu director%s above its files "
                "recorded\n", commit->ancestors_captured,
                commit->ancestors_captured == 1 ? "y" : "ies"
            );
        }
        if (commit->ancestors_retired > 0) {
            output_print(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %zu director%s another kind "
                "stands at let go\n", commit->ancestors_retired,
                commit->ancestors_retired == 1 ? "y" : "ies"
            );
        }
        if (commit->ancestors_pruned > 0) {
            output_print(
                out, OUTPUT_VERBOSE, "  {green}✓{reset} %zu director%s no file stands "
                "beneath let go\n", commit->ancestors_pruned,
                commit->ancestors_pruned == 1 ? "y" : "ies"
            );
        }
    }
}

/**
 * Say what the run skipped: the summary's line before its arm's own
 *
 * One clause a section the run left something in, in status's titles and in its
 * order (cmds/status.c status_print_workspace), so each count reads as the section
 * that lists those paths with their way out — the skipped counts
 * (update_partition_t), then the new files the question left out, status's New
 * files. Nothing where the run skipped nothing. Said at each of the run's three
 * ends (cmd_update: the nothing-exit, the dry run, the run's line), the line
 * before its arm's, so every arm's verdict is the last word of the summary.
 *
 * @param ctx Dispatch context (must not be NULL; the clauses are joined in its
 *            arena)
 * @param partition The partition, whose skipped counts are read (must not be NULL)
 * @param work The run's work: the accepted items, less the new files where the
 *             question left them out
 */
static void update_print_skipped(
    const dotta_ctx_t *ctx, const update_partition_t *partition, workspace_items_t work
) {
    CHECK_NULL(ctx);
    CHECK_NULL(partition);

    /* Status's section titles in its order, the new files the question left out
     * last: the discoveries are accepted's suffix (update_partition_t), so the
     * work lacks exactly them — none where nothing was asked */
    const struct {
        size_t count;
        const char *word;
    } parts[] = {
        { partition->skipped.conflicts,           "conflict"          },
        { partition->skipped.unconfirmed,         "unconfirmed path"  },
        { partition->skipped.squatted,            "squatted ancestor" },
        { partition->skipped.displaced,           "displaced path"    },
        { partition->skipped.unverifiable,        "unverifiable path" },
        { partition->skipped.undeployed,          "undeployed change" },
        { partition->accepted.count - work.count, "new file"          },
    };

    string_array_t clauses;
    string_array_init(&clauses, ctx->arena, 0);
    for (size_t k = 0; k < sizeof(parts) / sizeof(parts[0]); k++) {
        if (parts[k].count == 0) continue;

        string_array_pushf(
            &clauses, "%zu %s%s", parts[k].count, parts[k].word,
            parts[k].count == 1 ? "" : "s"
        );
    }
    if (clauses.count == 0) return;

    /* One line, composed first, since a summary's line is said whole and a count
     * joined into a phrase is a datum, uncoloured (base/output.h "Layout and
     * data") */
    const char *phrase = string_array_join(ctx->arena, &clauses, ", ");
    output_summary(ctx->out, OUTPUT_NORMAL, "Skipped: %s", phrase);
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
        .paths            = opts->paths,
        .path_count       = opts->path_count,
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
     * State is borrowed from the dispatcher (ctx->run.state), which holds no
     * transaction: the load writes what it owes the record in one of its own,
     * the files it verified but this command does not modify among them
     * (core/workspace.h workspace_load), and the files the command captures get
     * their record in its record phase, whose transaction opens there
     * (update_write_record).
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

    /* The run's filter context, ahead of everything the filter says against it:
     * the verbose "Excluded" log, the places the scan could not look, the preview
     * and the summary. Verbose, as the log it heads is: at NORMAL it would say
     * back the flags the user typed, the nothing-exit naming the two modes in
     * its own words */
    if (opts->only_new) {
        output_info(
            out, OUTPUT_VERBOSE,
            "Filter: Showing only new files (--only-new)"
        );
    } else if (opts->include_new) {
        output_info(
            out, OUTPUT_VERBOSE,
            "Filter: Including new files from tracked directories (--include-new)"
        );
    }
    if (opts->path_count > 0) {
        output_info(
            out, OUTPUT_VERBOSE,
            "Filter: Limiting to %zu specified path%s",
            opts->path_count, opts->path_count == 1 ? "" : "s"
        );
    }
    if (opts->exclude_count > 0) {
        output_info(
            out, OUTPUT_VERBOSE,
            "Filter: Excluding %zu pattern%s",
            opts->exclude_count, opts->exclude_count == 1 ? "" : "s"
        );
    }

    /* Partition the diverged items: the scope, the flags, and for a deployed
     * item the route table. */
    update_partition_t partition;
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

    /* Where the scan could not look, by path and above the exit below, so a run
     * that found nothing to add still says where it could not look: this may be
     * the one screen that has them — status scans only where the config asks,
     * and this run may have scanned on its own flag. Each line is the item's
     * own (core/workspace.h workspace_item_line), as status lists it; add meets
     * each cause again and prints it. */
    if (partition.unscanned.count > 0) {
        output_list_t *list = output_list_create(
            out, "Not scanned for new files",
            "nothing at or beneath these is offered; 'dotta add -n' says why"
        );

        for (size_t i = 0; i < partition.unscanned.count; i++) {
            const workspace_item_t *item = partition.unscanned.entries[i];
            const workspace_line_t line = workspace_item_line(item);

            output_list_add(list, line.tags, line.color, line.path, line.metadata);
        }

        output_list_render(list);
        output_list_free(list);
    }

    /* A named path re-derives its subtree's chains. Naming is consent, so a run
     * given paths climbs the chain of every in-scope row under them, captured
     * or not, and re-derives each rung at and beneath a path it named
     * (update_profile) — the explicit backfill, and the remedy for a rung the
     * world moved under. The slice is the leaves: blob rows and tracked directory
     * rows, each the root of its own chain; an ancestor claim is never a leaf —
     * its own re-derivation is carried by the leaves beneath it, which the residue
     * rule guarantees exist. The exclude gate binds here (the user excluded the
     * path from this operation), where the chain riding a captured leaf stays
     * scope-blind like add's — an exclusion names a path, never the way to it.
     * A bare run names nothing and derives nothing; nor does a run under
     * --only-new, where the user asked about new files alone and a re-derivation
     * is a move of the way, never a new file — a new file's own capture still
     * climbs its way, the first capture's rule (update_profile). The rows are
     * walked as the active items, one a row, each carrying the look the load
     * took at it; the leaves grow as the walk finds them rather than into room
     * for the whole view: a named path picks a few rows out of all of them. */
    manifest_rows_t derive_rows = { 0 };
    if (opts->path_count > 0 && !opts->only_new) {
        workspace_items_t active = workspace_active(ws);
        const manifest_row_t **leaves = NULL;
        size_t leaf_count = 0;
        size_t leaf_capacity = 0;

        for (size_t i = 0; i < active.count; i++) {
            const workspace_item_t *item = active.entries[i];

            if (manifest_is_derived(item->row)) {
                continue;
            }
            if (!scope_accepts_entry(
                scope, item->profile, item->filesystem_path, item->storage_path,
                item->item_kind
                )) {
                continue;
            }

            /* The climb reads the disk rung by rung (core/profiles.h
             * profile_derive_ancestors), so a leaf the load looked at nothing
             * along — beneath a squatter, whose look answers for the occupant
             * (core/workspace.h workspace_displaced_t) — is climbed only beneath
             * the user's squatter at a rung: the climb's own retire there — under
             * every name its profile derives the place by — is the remedy, and
             * past it the arrangement is the user's. Beneath any other the view
             * keeps its claim at the squatter — a row the profile tracks, or
             * dotta's own copy Git moved past — and a climb would commit what
             * the occupant answers as the user's word about the chain: a rung
             * retired, or a link target's attributes, on every machine. */
            if (item->displaced != WORKSPACE_DISPLACED_NONE &&
                item->displaced != WORKSPACE_DISPLACED_DERIVED) {
                continue;
            }

            /* Nor beneath the user's squatter at a lost blob's place
             * (core/manifest.c manifest_layer): the rung standing there makes
             * the squatter DERIVED, but the blob's explicit claim names the path,
             * so the view requires the directory whatever any sheet holds and
             * no retire is the remedy — a climb would commit one for every machine
             * and free nothing. Every enabled profile is asked for an explicit
             * claim there, whatever the run's -p. The leaf is counted among the
             * displaced (update_partition), and the way out is status's to give,
             * which at that place names the re-derivation this test refuses: a
             * named run there re-derives nothing, and no screen names moving
             * the node aside (stated) */
            if (item->displaced == WORKSPACE_DISPLACED_DERIVED) {
                const workspace_squatted_t *above = workspace_squatted_ancestor(
                    ws, item->filesystem_path
                );
                const string_array_t *profiles = manifest_profiles(manifest);

                size_t p = 0;
                for (; p < profiles->count; p++) {
                    const manifest_row_t *held = manifest_lookup_claim(
                        manifest, profiles->entries[p], above->filesystem_path
                    );
                    if (held && !manifest_is_derived(held)) break;
                }
                if (p < profiles->count) continue;
            }

            leaves = arena_grow(
                ctx->arena, leaves, &leaf_capacity, leaf_count + 1, sizeof(*leaves)
            );
            leaves[leaf_count++] = item->row;
        }

        derive_rows = (manifest_rows_t){ .entries = leaves, .count = leaf_count };
    }

    /* Preview: what this run will do, grouped by the fates the partition answered,
     * and nothing where it accepted nothing */
    update_print_preview(out, manifest, &partition);

    /* The run's work: the accepted items — less the new files, where the question
     * below leaves them out. A value the command holds; the partition's list is
     * never edited. */
    workspace_items_t work = partition.accepted;

    /* New files no flag asked for — the config's scan found them — are added
     * only with consent: a question that narrows the run, so the decision's,
     * asked beneath the preview that lists what it narrows and before the hook,
     * and binding no dry run, which executes nothing. Declining keeps the rest
     * of the run — the preview named the new files separately, and the summary
     * counts what the question left out (update_print_skipped) — and the
     * nothing-exit below asks what is left, so a named run whose only accepted
     * items were new files still re-derives the chains it named. */
    if (!opts->dry_run && partition.new_files.count > 0 && config->confirm_new_files &&
        !opts->include_new && !opts->only_new) {

        /* The new files are an extra the run stands without, each offered to
         * the profile whose tracked directory holds it. They are the accepted
         * items' suffix: the discoveries follow every other diverged item
         * (core/workspace.h workspace_diverged), and the partition keeps the
         * order it walks in — so the rest of the run is the prefix before them. */
        switch (output_ask(
            out, false, "Found %zu new file%s. Add %s to %s?",
            partition.new_files.count, partition.new_files.count == 1 ? "" : "s",
            partition.new_files.count == 1 ? "it" : "them",
            partition.new_files.count == 1 ? "its profile" : "their profiles"
            )) {
            case OUTPUT_ANSWER_YES:
                break;
            case OUTPUT_ANSWER_NO:
            /* Declined: the user's word */
            case OUTPUT_ANSWER_NONE:
                /* Unanswered: nobody declined, and the run stands without the
                 * extra all the same — the summary counts what it left out */
                work.count -= partition.new_files.count;
                break;
        }
    }

    /* Anything to update — or, on a named run, any chains to re-derive: whether
     * a chain moved is the walk's to discover, so the named run proceeds on the
     * slice alone and the summary says what came of it. Asked once the work is
     * decided, so a run the question emptied — its new files the whole of it,
     * left out — ends in the same verdict as one that accepted nothing, in the
     * words of the mode it ran in (the question is asked under neither flag),
     * beneath what the run skipped, and fires no hook */
    if (work.count == 0 && derive_rows.count == 0) {
        update_print_skipped(ctx, &partition, work);
        if (opts->only_new) {
            output_summary(out, OUTPUT_NORMAL, "No new files to add");
        } else if (opts->include_new) {
            output_summary(out, OUTPUT_NORMAL, "No modified or new files to update");
        } else {
            output_summary(out, OUTPUT_NORMAL, "No modified files or directories to update");
        }
        return NULL;
    }

    /* The pre-update hook, over the decided run — the nothing-exit and the
     * narrowing above it, a run left with nothing to do firing none; a dry run's
     * too, told so (DOTTA_DRY_RUN=1). The preview's verdicts predate it, but
     * the drafts open after it (update_execute) and the capture stores execute-time
     * bytes: a commit it makes to a profile is the update's parent, a candidate
     * it edits is committed as it wrote it, and one it removes or retypes is
     * skipped and said (update_profile). */
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_UPDATE,
        .profile    = string_array_join(ctx->arena,scope_profiles(scope),  " "),
        .paths      = opts->paths,
        .path_count = opts->path_count,
        .dry_run    = opts->dry_run,
    };

    err = hook_fire_pre(config, out, &hook_inv);
    if (err) return err;

    /* A dry run ends here, beneath its pre-hook, in the act it did not do: the
     * sections above are its preview, and what it would skip is said before its
     * verdict. A named run's re-derivation is the walk's to discover — its climbs
     * read the disk rung by rung against a draft that opens beneath the pre-hook
     * (update_execute) — so a dry run says nothing of it (stated). It reaches
     * only a directory dotta only passes through: a tracked directory's moved
     * mode is an item, listed under Modified directories above. */
    if (opts->dry_run) {
        update_print_skipped(ctx, &partition, work);
        output_summary(out, OUTPUT_NORMAL, "Dry run: nothing was committed");
        return NULL;
    }

    /* Execute profile updates, in enabled-set order. Filtered to operation scope.
     * ctx->run.keymgr is borrowed by the capture inside per-profile iteration. */
    update_commit_t *commits = NULL;
    size_t commit_count = 0;
    err = update_execute(
        ctx, scope_enabled(scope), work, derive_rows, scope_paths(scope), opts, &commits,
        &commit_count
    );

    /* What each landed commit took, at verbose, whatever stopped the run: the
     * bookkeeping holds every commit that landed */
    update_print_receipt(out, commits, commit_count);

    /* The run's summary, once the act is done and before the record phase, which
     * may wait on the store's lock (core/state.h state_begin): what it skipped,
     * then its one line — what it committed, whole or before the stop the error
     * below names, or that it committed nothing. The walk's own skips, a race's,
     * are said as the walk meets them and counted nowhere here */
    update_print_skipped(ctx, &partition, work);
    if (commit_count == 0) {
        /* Every profile committed nothing (the walk's race guard skipped what
         * the plan admitted, the captures put back what the profile holds, or
         * the first profile stopped the run): say so instead of counting zero */
        output_summary(out, OUTPUT_NORMAL, "Nothing was committed");
    } else {
        /* A landed commit's user items are what it captured and deleted; a
         * derivation-only commit carries none */
        size_t total_updated = 0;
        for (size_t i = 0; i < commit_count; i++) {
            total_updated += commits[i].captured_count + commits[i].deleted_count;
        }

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
                out, OUTPUT_NORMAL, "Re-derived directories across %zu profile%s",
                commit_count, commit_count == 1 ? "" : "s"
            );
        }
    }

    /* Write the record — for the commits that landed, error or no
     *
     * Captured files get their record written because UPDATE captures them FROM
     * the filesystem (already at their target paths): what each capture committed,
     * stamped as dotta's. The view itself is computed at every load and needs
     * no update. A mid-sequence stop above changes nothing here: the landed commits
     * are Git truth and the record follows them; the profiles that never committed
     * have nothing to write.
     *
     * Non-fatal, and said in a block of its own beneath the run's line, which
     * names what landed. */
    error_t record_err = update_write_record(ctx, commits, commit_count);
    if (record_err) {
        /* The landed commits are Git truth and the record's write failed behind
         * them, rolled back whole: the record is what it was. A refused phase
         * owed a write — a commit of the way alone owes none (update_write_record)
         * — and each capture or deletion it did not record leaves the record
         * behind the commit: a modified or re-stored file a stale record, which
         * the next load confirms where disk agrees; a new one a row no owned
         * record vouches for, which apply adopts; a re-captured directory a claim
         * the record did not reconcile; a deletion an absent orphan, which the
         * next apply reclaims. A directory the commits re-captured keeps the
         * ownership its record already held — apply earns none for a directory
         * (cmds/add.c add_write_record) — which is the conservative side: an
         * unowned directory is released at scope exit, never pruned. The store's
         * refusal is said in its own words and names no step, each arm above
         * settling as it says — after a mid-sequence stop only some profiles
         * committed, and the run's line above names what did. */
        output_gap(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(record_err));
    }

    /* The post-update hook, last (utils/hooks.h hook_fire_post), over a run whose
     * every commit landed: a stop fires none, the error below naming it */
    if (!err) hook_fire_post(config, out, &hook_inv);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `paths[]` and `profiles[]`.
 *
 * Positional rule (differs from add — position-dependent):
 *   - First positional: a path or a profile name, by whether it announces a path
 *     (infra/path.h path_input_announces_path). A path lands in `paths`; a name
 *     lands in `profiles`.
 *   - Remaining positionals: always paths.
 *
 * Profiles from `-p` are already populated in `profiles` by the APPEND row; a
 * positional profile appends onto that list. Paths go into a fresh arena-backed
 * array.
 *
 * One pair is refused ahead of the routing: --force beside --only-new, which
 * leaves every deployed row before its route is asked (update_partition), so
 * the first would take nothing.
 */
static error_t update_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) cmd;
    cmd_update_options_t *o = opts_v;

    if (o->force && o->only_new) {
        return error_create(ERR_INVALID_ARG, "--force and --only-new are mutually exclusive");
    }

    if (o->positional_count == 0) {
        return NULL;
    }

    /* Worst case: every positional becomes a path. */
    char **paths = arena_calloc(arena, o->positional_count, sizeof(*paths));
    size_t path_count = 0;

    for (size_t i = 0; i < o->positional_count; i++) {
        char *arg = o->positional_args[i];

        /* Only the first positional is ambiguous (profile or path). It becomes
         * a profile only if -p was not given AND it announces no path. */
        if (i == 0 && o->profile_count == 0 &&
            !path_input_announces_path(arg)) {
            /* Arena-backed 1-slot profile array for the positional. */
            char **profiles = arena_calloc(arena, 1, sizeof(*profiles));
            profiles[0] = arg;
            o->profiles = profiles;
            o->profile_count = 1;
            continue;
        }

        paths[path_count++] = arg;
    }

    if (path_count > 0) {
        o->paths = paths;
        o->path_count = path_count;
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
        "f force",
        cmd_update_options_t,force,
        "Also commit conflicts and unconfirmed paths, as they are on disk"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_update_options_t,dry_run,
        "Preview without committing"
    ),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_update_options_t,verbosity,        DOTTA_VERBOSITY_VERBOSE,
        "Verbose output"
    ),
    ARGS_FLAG(
        "include-new",
        cmd_update_options_t,include_new,
        "Also commit new files inside tracked directories"
    ),
    ARGS_FLAG(
        "only-new",
        cmd_update_options_t,only_new,
        "Commit only new files; skip modifications"
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
    .usage        = "%s update [options] [profile|path]...",
    .description  =
        "Commit filesystem modifications to the matching profile branches\n"
        "(the reverse direction of 'apply'). Mode is captured alongside\n"
        "content, and ownership for any path owned by someone other than\n"
        "the user running dotta, and under a root login for the paths\n"
        "outside home/. A file gone from disk that dotta last saw at the\n"
        "profile's version is deleted from its profile, and every\n"
        "machine's next apply deletes its unchanged copy. To stop tracking\n"
        "a file but keep it, use 'dotta remove'.\n",
    .notes        =
        "File Detection:\n"
        "  New files inside tracked directories are included based on\n"
        "  config: core.auto_detect_new_files toggles detection,\n"
        "  security.confirm_new_files toggles the prompt. --include-new\n"
        "  and --only-new override both for this invocation.\n"
        "\n"
        "Directories:\n"
        "  Updating a file never changes the permissions recorded for the\n"
        "  directories above it. To record a directory's current\n"
        "  permissions, name it: 'dotta update ~/.config' records those of\n"
        "  ~/.config and of the directories in it that hold your files.\n"
        "\n"
        "Conflicts and Unconfirmed Paths:\n"
        "  A plain update skips the files 'dotta status' lists under these\n"
        "  headings. --force commits them as they are on disk, the way\n"
        "  'apply --force' takes the profile's version instead. With no path\n"
        "  it takes all of them, so name the files you mean.\n",
    .examples     =
        "  %s update                             # Every modified path\n"
        "  %s update ~/.bashrc                   # Specific file\n"
        "  %s update ~/.config                   # A directory, permissions included\n"
        "  %s update -p global                   # Filter to 'global'\n"
        "  %s update --include-new               # Modified + new files\n"
        "  %s update --only-new                  # New files only\n"
        "  %s update --force ~/.bashrc           # Keep your version over the profile's\n"
        "  %s update -n                          # Preview without committing\n"
        "  %s update --exclude '*.log'           # Skip log files\n"
        "  %s update -m \"Update shell config\"    # Custom commit message\n",
    .epilogue     =
        "See also:\n"
        "  %s status          # See what will be committed\n"
        "  %s remove          # Stop tracking a path, keep it on disk\n"
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
