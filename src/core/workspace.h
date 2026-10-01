/**
 * workspace.h - The join of the view, the record and the filesystem
 *
 * The workspace pairs three things per managed path:
 * 1. The view (core/manifest.h, built from Git at load): what *should* stand at
 *    each active path, from which profile
 * 2. The record (the store's dotta.db, core/state.h): what dotta *did* there —
 *    deployed, confirmed, observed
 * 3. The filesystem: what *actually* stands there
 *
 * Detects and categorizes the divergence between them to prevent data loss and
 * provide clear visibility into workspace consistency.
 *
 * Snapshot ownership:
 *   The workspace is the authority for the join within its lifetime: the view
 *   (core/manifest.h — every enabled profile at HEAD, built by the dispatcher
 *   at the start of the command and borrowed here, `ctx->run.manifest`) and the
 *   record (read once, state_records, and held by the items). Downstream consumers
 *   (deploy, cleanup, command-internal analyses) read both through workspace
 *   accessors — the active items, each carrying its row and the record at its
 *   path (workspace_active, workspace_directories, workspace_files), and the
 *   item at a path (workspace_find) — rather than building a view or calling
 *   state_records themselves. The view has no writer: it is current by construction
 *   and nothing invalidates it. The record has four writers while a workspace
 *   is live — the flush (workspace_flush), workspace_anchor, workspace_learn
 *   and workspace_learn_mode — and each writes a record whole, built before its
 *   statement (core/state.h state_write), and points the path's item at it once
 *   the store holds it: the flush after its own commit, or at its end in the
 *   caller's transaction; the other three at once, in the run's. The record an
 *   item held before is never written, so a reader that took it earlier reads
 *   what the load read, whenever it reads. Retirements (state_retire, from apply's
 *   record phase and the verbs) go to the database directly — no later reader
 *   in the run consults a retired path.
 *
 *   Exception: the verbs — add, remove, and update after its commit — write the
 *   record through state.h directly, against the post-commit view they build
 *   with manifest_build: add and update what their captures committed, where
 *   that view says the claim stands, and each the retirements — remove's orders
 *   too — of what its commit let go. add and remove load no workspace, and nothing
 *   reads update's after its record write, so there is no snapshot for the write
 *   to desync. profile enable / disable write only the enabled set, sync writes
 *   nothing, and completion reads the dispatcher's view alone.
 *
 *   The workspace's products (rows, records, verdicts) are read through the
 *   workspace; the run's resources (the repository, the content cache) are read
 *   through the dispatch context, at every layer — the workspace borrows them
 *   for its own reads and lends none of them (include/runtime.h, "Members not
 *   welcome" #3). A core step that acts on the workspace's plan and reads Git
 *   or content takes those handles by name beside the workspace (deploy_execute).
 *
 * Identity:
 *   The join is by spelling, and so is every fact the workspace holds about a
 *   path but one: where each row and each orphan record stands, indexed by the
 *   (dev, ino) the load's own look at that path found, for the two verbs that
 *   act on an entry through a string and could otherwise act on a spelling the
 *   load knows the entry by another name of — cleanup's unlink (an owned, backed
 *   orphan whose entry a row stands on is a stale key: released, never pruned)
 *   and the scan's offer (a child whose entry a row or a record stands on is no
 *   discovery). An entry is a name in a directory; a key is one spelling of it,
 *   and a filesystem can reach one entry through as many spellings as there are
 *   links above it, folds it performs on the name, and roots the table spells
 *   two ways (infra/mount.h).
 *
 *   The scan's roots read identity for a third reason of their own — one walk
 *   per directory (workspace_analyze_untracked) — and read it off that same look.
 *   Only the untracked walk asks the disk which entry a string names, at a child
 *   no claim settles; a filter, a namer or a join that wanted to is asking a
 *   question the model does not answer.
 */

#ifndef DOTTA_WORKSPACE_H
#define DOTTA_WORKSPACE_H

#include <git2.h>
#include <string.h>
#include <types.h>

#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "core/manifest.h"
#include "core/state.h"
#include "infra/compare.h"
#include "infra/content.h"

/* The most tags one item's line carries — six, on a deployed item: [modified],
 * [stale], [mode], [ownership], [unencrypted] and [reassigned]. A kind that
 * changed, a look that failed and a look not taken end the measure, so [type],
 * the fault's tag and [displaced] ride beside the last two alone, and agreement's
 * one tag — [clean], or [ancestor] on a derived rung — stands alone
 * (workspace_item_tags, whose Tag Priority this counts; a tag added there is
 * counted here). */
#define WORKSPACE_ITEM_MAX_TAGS 6

/**
 * Workspace state - where an item exists
 *
 * Represents the deployment status of a file or directory across the view (Git),
 * the record (the store's dotta.db) and the filesystem.
 *
 * This enum captures WHERE an item exists, separate from WHAT is wrong with it
 * (see divergence_type_t). States are mutually exclusive.
 */
typedef enum {
    WORKSPACE_STATE_DEPLOYED,      /* The view claims the path and something stands there */
    WORKSPACE_STATE_UNDEPLOYED,    /* The view claims the path and nothing does: apply's to create */
    WORKSPACE_STATE_DELETED,       /* The view claims the path, dotta saw its node there, and nothing does */
    WORKSPACE_STATE_ORPHANED,      /* A record whose path the view lacks */
    WORKSPACE_STATE_UNTRACKED,     /* Beneath a tracked directory, in neither the view nor the record */
    WORKSPACE_STATE_RELEASED       /* An orphan dotta lets go: the path stays, the record retires */
} workspace_state_t;

/**
 * Divergence type - what is wrong with an item
 *
 * Bit flags; multiple can be set simultaneously (e.g., content changed AND mode
 * changed). This enum captures WHAT is wrong, separate from WHERE the item exists
 * (see workspace_state_t).
 *
 * The bits divide in two, by what their operands are:
 *
 * The path bits — CONTENT, MODE, OWNERSHIP, TYPE, STALE, CLAIM_MOVED, UNVERIFIED
 * — measure the active path against the view: what stands on disk versus the
 * row (STALE and CLAIM_MOVED through the record: the pair and the claim dotta
 * last reconciled, versus the row's), UNVERIFIED when the measurement itself
 * could not run. No path bit survives absence — properties of what is not there
 * cannot be compared.
 *
 * The blob bit — ENCRYPTION, alone — measures the blob Git holds against the
 * config's auto-encrypt policy (core/policy.h). The filesystem is not a party,
 * so it is the one bit a row in any state can carry, absence included; and because
 * no write to the path can change how a blob is stored, it is never deploy's
 * work — update re-stores the blob, status reports it.
 *
 * Who moved. On the content axis two bits split a difference by its mover: CONTENT
 * that disk left what dotta last confirmed there (any difference, where nothing
 * was), STALE that Git moved past it — both, a conflict. On a claim axis the
 * axis bit says what differs, and CLAIM_MOVED beside it that the claim is Git's
 * to bring: the record last reconciled another (workspace_claims_moved) — Git
 * moved it since, or a run left the path short of it, the record saying the mode
 * the run left (workspace_learn_mode) — or it names an owner this host cannot
 * resolve, which no move of disk's can satisfy (core/workspace.c
 * workspace_compare_ownership); without it the difference is the user's. Only
 * Git's side is asked of a claim: apply converges every claim whoever moved it
 * (core/deploy.h deploy_content_conflicts), so the user's side would name a state
 * no verb treats apart. One bit for both claim axes, since no reader tells them
 * apart, and set only beside an axis bit it attributes — by
 * workspace_analyze_claim, and by workspace_compare_ownership in the one return
 * it makes of both — so no screen shows it alone. Its readers: workspace_item_route
 * (the CONFLICT and STALE arms), workspace_item_tags ([stale]), cmds/apply.c
 * cmd_apply (the count of what Git
 * moved) and core/cleanup.c cleanup_skip_reason (a known flag no orphan carries);
 * every other surface reads the route. A reader not on this list is a bug.
 *
 * The words on screen: MODE is the mode and OWNERSHIP the ownership wherever a
 * screen names a claim axis that differs — the tags (workspace_item_tags), which
 * apply's fixed directories print too (cmds/apply.c apply_print_deploy_receipt),
 * diff's status line (cmds/diff.c get_status_message_from_item), and a skipped
 * orphan's label and legend (cmds/apply.c apply_print_cleanup_skips, cmds/status.c
 * status_print_workspace) — and a sentence that names both says "mode and
 * ownership", never "permissions", which is one word for two axes. STALE and
 * CLAIM_MOVED are one word: [stale] on a tag, and "changed in Git" in a sentence
 * — update's census, apply's count, diff's status line — "changed in Git and on
 * disk" where CONTENT stands beside them (the route's CONFLICT). The words are
 * the three-way frame's, true whatever moved the base: the record is what dotta
 * last left at the path, and Git's side is the side that differs from it — a
 * claim a run could not land among it.
 *
 * A path bit names its axis — CONTENT the bytes, MODE the mode, OWNERSHIP the
 * owner and group — so a mask of them can name axes where no difference is meant:
 * the ones a look or a fix established, which the record learns (workspace_flush,
 * workspace_learn), and the claims Git moved past the record
 * (workspace_claims_moved).
 */
typedef enum {
    DIVERGENCE_NONE        = 0,       /* No divergence detected */
    DIVERGENCE_CONTENT     = 1 << 0,  /* Disk left what dotta last confirmed (the row, where nothing was) */
    DIVERGENCE_MODE        = 1 << 1,  /* The mode is not the claim's */
    DIVERGENCE_OWNERSHIP   = 1 << 2,  /* Owner or group is not the claim's */
    DIVERGENCE_ENCRYPTION  = 1 << 3,  /* Blob stored plaintext where the auto-encrypt policy claims the path */
    DIVERGENCE_TYPE        = 1 << 4,  /* Type changed (file/symlink/dir) */
    DIVERGENCE_UNVERIFIED  = 1 << 5,  /* The look failed; (workspace_fault_t) */
    DIVERGENCE_STALE       = 1 << 6,  /* Git moved past the pair dotta last confirmed */
    DIVERGENCE_CLAIM_MOVED = 1 << 7   /* A claim Git's to bring: not the record's, or unresolvable here */
} divergence_type_t;

/**
 * Whose claim holds the squatter standing above a path — the displaced fact,
 * with its reach
 *
 * A directory is squatted when a claim says a directory belongs at the path and
 * the load's look found something else standing there — or, where the view claims
 * no directory there, when a link stands there that a record beneath it would
 * be looked at through. **Nothing beneath a squatter is looked at.** A look there
 * would answer for the occupant — a symlink to a directory answers for the link's
 * target, so a child would read clean, present, modified or new about a tree
 * that is not this path's; a file answers ENOTDIR, and a link to nothing ENOENT,
 * so a child would read absence caused by the squatter as the user's own deletion
 * to propagate. No such answer is the path's, and one act would be read as an
 * intent per path beneath it. So the ask comes before every look the load takes
 * (workspace_squatter_above): beneath a squatter the row or the record is an
 * item as the partition made it, DEPLOYED- or ORPHANED-shaped, occupant UNKNOWN,
 * with no path bit and nothing owed the record. Every displaced active item is
 * therefore DEPLOYED with no path bit — a file row's blob bit rides, Git's and
 * no look's — which is what lets a consumer that forgets this field do nothing
 * rather than something wrong: the absence arms are never reached beneath a
 * squatter, so none of them needs a clause.
 *
 * Two authorities can make the claim, and they reach differently — the reach rule:
 *
 *   TRACKED / DERIVED   the view claims the path — a directory row of either
 *                       class (core/manifest.h): nothing beneath it is looked
 *                       at, a row's or a record's. A view claim displaces
 *                       everything beneath it.
 *   RECORD              only a record remembers a directory there — the view
 *                       claims none — and none stands there: a record of a
 *                       directory with another kind of node in its place, or a
 *                       link at a path the load looks at, a record's or a row's
 *                       of another kind, with a record beneath it, the link being
 *                       the one node a key beneath resolves through. The orphans
 *                       beneath it, the ORPHANED and RELEASED items, are not
 *                       looked at, and nothing else is. A view row beneath such
 *                       a path is a deliberate through-capture: its profile's
 *                       derivation met the non-directory and claimed no rung
 *                       there (core/metadata.h), so the arrangement predates
 *                       the row and the look is the row's own. A record's memory
 *                       displaces only the orphans beneath it — never a view
 *                       row, so RECORD stands on no DEPLOYED item.
 *
 * NONE on every item looked at at its own path, the squatter's own included:
 * the ask is of proper ancestors, so a squatter is never its own answer and carries
 * its own TYPE verdict instead.
 *
 * Noted by the look that found the squatter, and written by every look it withholds
 * (workspace.c workspace_look), which asks the same scan before it takes one
 * (workspace_squatter_above) — so the class is total, and both halves of the
 * fact are one function: an item that carries one is an item with nothing measured.
 *
 * The words on screen, so the sentences cannot drift apart again: the directory
 * another kind stands at is *squatted*, the path beneath it is *displaced* —
 * the tag, status's section, this class — and every sentence about such a path
 * opens "not looked at", the predicate its neighbours spell "locked", "cannot
 * be read" and "could not be verified". The four that name the squatter say
 * "beneath a squatted directory" (cmds/update.c cmd_update's two census lines,
 * cmds/diff.c get_status_message_from_item, cmds/sync.c cmd_sync's note,
 * cmds/status.c status_print_workspace's Issues hint); the Displaced paths header,
 * where the word is grounded, spells the squatter out instead.
 *
 * Readers: workspace_item_route, core/cleanup.c cleanup_verdict, core/deploy.c
 * deploy_needs_work and deploy_plan_build (the --skip-existing test), workspace.c
 * workspace_item_tags (the DEPLOYED arm's [displaced], beside which only what
 * no look decides or disproves rides, and the ORPHANED arm's rider), cmds/status.c
 * status_print_workspace's Issues hint, and cmds/diff.c
 * get_status_message_from_item and show_file_diff_from_workspace (the colour
 * ladder and the content gate), should_show_item_for_direction beside them; and
 * core/deploy.c check_ancestry, off the squatted directory itself — a caller
 * that needs the squatter, which no item carries, is lent it whole, the claim
 * this class is copied from (workspace_squatted_ancestor), so apply's remedy
 * and status's section cannot name two claimants for one squatter.
 */
typedef enum {
    WORKSPACE_DISPLACED_NONE = 0,  /* Looked at, at its own path */
    WORKSPACE_DISPLACED_TRACKED,   /* Beneath a squatter a tracked row claims */
    WORKSPACE_DISPLACED_DERIVED,   /* Beneath a squatter an ancestor claim holds */
    WORKSPACE_DISPLACED_RECORD     /* Beneath a squatter only a record remembers — orphans alone */
} workspace_displaced_t;

/**
 * The rule of the namespace a relocated claim lands in — the class of a relocation
 *
 * A relocation is an orphan whose own claim is still in the view, standing at
 * another path: the record's (profile, storage path) pair found a row that projects
 * elsewhere (workspace_analyze_orphans). What becomes of the copy left behind
 * turns on one question — did the user move the claim, or did the ground move
 * under it — and the answer is the mounting rule of the namespace the claim is
 * named in (infra/label.h), not the place either side stands at:
 *
 *   SHARED    home/ and root/ mount where the machine says — the invoker's HOME
 *             and `/`. Neither is anyone's to re-target, so a claim that moved
 *             under one moved because the machine's own HOME did. root/'s
 *             projection is a constant and never relocates at all; it is named
 *             here because the rule is the namespace's and the switch is
 *             exhaustive.
 *   BOUND     custom/ mounts at the target this machine binds for the profile —
 *             the user's word, and re-bound by the user's word alone.
 *
 * A fact of the placement, not an assertion about who moved the file: the program
 * read the record and the view, never the actor. NONE on every item that is not
 * a relocation — any item with no row, and every state but ORPHANED (a RELEASED
 * record carries no row, and on a DEPLOYED item the row is the ordinary claim).
 *
 * Assigned once, by the orphan analysis where it reads the relocation (workspace.c
 * workspace_analyze_orphans), off the label; the row it finds there is not kept,
 * so an orphan item carries no row. Trusted downstream, as the displaced class
 * is. Readers: cleanup's two verdicts, which skip a SHARED relocation unless
 * --force and prune a BOUND one — the reason is cleanup's and lives there
 * (core/cleanup.h) — and the three screens that ask only whether there is a
 * relocation at all: the [relocated] tag (workspace_item_tags), apply's prune
 * split, status's prunable hint. The presence question is this field against
 * NONE at every one of them.
 */
typedef enum {
    WORKSPACE_RELOCATION_NONE = 0,  /* Not a relocation */
    WORKSPACE_RELOCATION_SHARED,    /* home/, root/ — the machine places the root */
    WORKSPACE_RELOCATION_BOUND      /* custom/ — the profile's binding places it */
} workspace_relocation_t;

/**
 * Why a look failed — the class of DIVERGENCE_UNVERIFIED, by whose remedy it is
 *
 * The bit answers the verb question: no verb resolves this item — apply skips
 * it, update refuses it, cleanup skips the orphan — and every engine reads it.
 * It does not answer the user's question, what do I do, and the things that can
 * make it have three different answers to that: a missing key, a permission,
 * and a list of one-offs no key or privilege settles. One remedy over all three
 * is how a locked path came to be told to fix its permissions.
 *
 * The fault is that partition, read off the root error's code at the one moment
 * an analysis holds it — crypto/keymgr.h's "The codes" is the producer's half
 * of the contract, and sys/filesystem's errno the other:
 *
 *   LOCKED       ERR_LOCKED: the run holds no usable master — none in reach,
 *                none read, none that opens this repository — or the feature is
 *                off over a sealed blob. One key settles every such row at once.
 *   UNREADABLE   ERR_PERMISSION: the invoker cannot read the path. Permissions,
 *                or a run that holds root.
 *   UNVERIFIED   anything else: a foreign epoch, a cipher version this build does
 *                not read, a Git object that would not load, an I/O error, a
 *                probe that could not answer. Dotta names no remedy for these,
 *                because there is no one remedy to name — the verb that meets
 *                the refusal prints its cause, and a block that lists such a
 *                path points at the verb.
 *
 * The class is the whole of what the item carries. The mechanism's own sentence
 * stays in the error the analysis dropped, where the verb that raises it prints
 * it ("dotta show", "dotta export", add's and update's wraps): a report is a
 * list of paths and their state, and every block in cmds/ closes by naming a
 * remedy in its own fixed words, never by quoting a line another layer wrote.
 *
 * One invariant, established at every fold and trusted downstream: `fault !=
 * NONE` iff the item carries DIVERGENCE_UNVERIFIED. Only DEPLOYED (both kinds)
 * and ORPHANED items can carry one — RELEASED is born of answers, never of a
 * failed look (three that are not looks, and the relocation read's inode compare,
 * whose failure leaves the orphan where it stood), and UNDEPLOYED, DELETED and
 * UNTRACKED of looks that answered. And only a file row can be LOCKED: a directory
 * seals no content, so every fault it can carry comes from an errno.
 *
 * Readers: workspace_item_tags (the tag — [locked] / [unreadable] / [unverified],
 * the same word on both arms), status's two keys — Unverifiable's and Issues' —
 * update's census, apply's preflight rows and the closers under them, diff's
 * status line. The engines read the bit and never the fault: one verb, three words.
 */
typedef enum {
    WORKSPACE_FAULT_NONE = 0,     /* The look succeeded */
    WORKSPACE_FAULT_LOCKED,       /* No usable key this run — one key settles them all */
    WORKSPACE_FAULT_UNREADABLE,   /* Refused by permissions — root would read it */
    WORKSPACE_FAULT_UNVERIFIED    /* Anything else — no remedy dotta can name */
} workspace_fault_t;

/* The classes' arity, for an array with one slot per class. A macro, not an
 * enumerator, for the reason WORKSPACE_ROUTE_COUNT is one. */
#define WORKSPACE_FAULT_COUNT (WORKSPACE_FAULT_UNVERIFIED + 1)

/**
 * One path the workspace knows — a row of the view, a record the view lacks, or
 * a discovery of the scan — with the load's look at it, the verdict over that
 * look, and the confirmation the record is owed
 *
 * One per active path and one per orphan record, made at the partition before
 * anything is looked at, with the record at its path paired onto it there; a
 * discovery is one more, made at the scan's door with neither source. Items can
 * be files (PATH_KIND_FILE: content, claimed by a profile's tree) or directories
 * (PATH_KIND_DIRECTORY: metadata only, claimed by a profile's metadata.json,
 * planned and converged by core/deploy on apply's behalf). Arena-allocated and
 * never moved, so an item's address is stable for the workspace's lifetime —
 * the diverged items, deploy's and cleanup's buckets, the fates and apply's
 * collections hold items across phases by construction.
 *
 * The fields are grouped by their writer:
 *   the sources, the identity   the partition, once; the writers point `record`
 *                               at each record they write (workspace_flush,
 *                               workspace_anchor, workspace_learn,
 *                               workspace_learn_mode)
 *   the look                    workspace.c workspace_look, once per item a looker
 *                               reaches — and one retraction: the file analysis
 *                               sets the occupant to absence when its read met
 *                               ENOENT against a look that said a file stood
 *                               there, so the item and the index say one thing
 *   the verdict                 its kind's analysis, at the arm that decides it
 *   the confirmation            its kind's analysis, beside the verdict; the
 *                               flush clears it once the store holds it
 *
 * The occupant is the load's one look at the disk, carried as the sys layer names
 * it rather than folded to a presence bit: what the lstat found at the path —
 * the link itself, never its target. FS_OCCUPANT_NONE is absence;
 * FS_OCCUPANT_UNKNOWN is a path the load could not stat, or by the displaced
 * rule did not, or has not yet — the partition makes every item so, a look nobody
 * took — and assumes present either way (absence is never inferred from a failure
 * to look, and never from a look not taken). What it means is said beside it:
 * DIVERGENCE_UNVERIFIED where a look failed, a displaced class where none was
 * taken, and on a released record neither — letting a copy go needs no measurement.
 * An orphan on a load that took no look at the orphans keeps UNKNOWN, and no
 * reader is lent it — nor, whatever its look, one the load did not analyze: the
 * diverged items (workspace_diverged) and workspace_find lend an orphan only
 * where the load analyzed the orphans. Presence is
 * therefore `occupant != FS_OCCUPANT_NONE` — the workspace's rule, and cleanup's;
 * deploy judges by the stricter one (deploy_occupant_present: UNKNOWN is not
 * present, since deploy judges nothing it could not see), and a new consumer
 * picks one of the two and says which. The divergence bits are the verdict over
 * that look (DIVERGENCE_TYPE: the occupant is not the row's or the record's kind);
 * every consumer that once re-probed the path to learn its type reads this field
 * instead, so status, deploy and cleanup cannot see three different occupants
 * at one path. And where a look failed outright, whose remedy that is: the fault
 * (workspace_fault_t), NONE on every item the analysis could verify.
 *
 * `st` is the look's stat, meaningful for a present occupant alone, and
 * `lstat_errno` lstat's errno on an UNKNOWN from a look that failed. The whole
 * struct stat, because state_stat_matches, content_compare_blob_to_disk and
 * workspace_compare_ownership, which the analyses hand it to, each take one,
 * the entries index and the scan's roots read its identity, and deploy reads
 * its owner where it would converge a directory in place (core/deploy.c
 * deploy_preflight's FIX arm, DEPLOY_SKIP_FOREIGN) — where a narrowed look would
 * have to synthesize one back for each. A discovery's is the scan's own lstat.
 *
 * The identity is the source's strings, lent read-only: the row's for an active
 * item, the record's for an orphan, a discovery's own copies (profile: the view's
 * profile list's). A discovery's kind is FILE: the scan offers regular files
 * and symlinks alone (workspace.c workspace_analyze_untracked), which status's
 * New files label reads.
 *
 * `stat` is what stands behind the content verdict where it found disk to be
 * the row's pair (workspace.c workspace_analyze_file): the base's own stat where
 * the fast path stood on it, the look's triple distilled from `st` where the
 * slow path read. The row's content is on disk whatever the record says, so it
 * is set whatever the record, and UNSET on every other item. Two writers carry
 * it into the record: the flush's learning of the content, and apply's ownership
 * events over the clean rows (cmds/apply.c cmd_apply), which also reach a record
 * the load could confirm nothing onto — one bound to another row.
 *
 * The confirmation is what the analyses established that the record lacks, by
 * axis, for the flush to write (workspace_flush) and nothing else to read: the
 * content (DIVERGENCE_CONTENT) where the look found disk to be the row's pair
 * and the record can take it, written with `stat` — no record, or one of another
 * kind, whose place the row's first observation takes (workspace_flush), or one
 * of the row's kind bound to the row (workspace.c workspace_analyze_file); and
 * each claim Git moved that the look found disk already standing on
 * (DIVERGENCE_MODE, DIVERGENCE_OWNERSHIP). The flush clears it once the store
 * holds what the item learned, so it is NONE on every item that owes the record
 * nothing — orphans and discoveries always.
 *
 * `record` is the record at the path as the load read it, then as each writer
 * wrote it — published, and never edited: a writer builds the record its write
 * makes before the statement, and points the item at it once the store holds it
 * (the header's writers). It is const so a reader holding the item cannot write
 * the record, and no writer casts one: the item alone is cast, where a writer
 * lent it const moves its pointer (workspace_anchor, workspace_learn,
 * workspace_learn_mode), which is defined because no item is an object defined
 * const — every item is the arena's. So a pointer a reader took before a write
 * keeps the load's values, and a record's strings are never freed before the
 * arena (apply's reassignment_t, its from).
 */
typedef struct {
    /* The join's sources — borrowed for the workspace's lifetime */
    const manifest_row_t *row;           /* The view's claim; NULL on an orphan and a discovery */
    const state_record_t *record;        /* The record at the path, or NULL; the writers' alone */

    /* The identity — the source's strings, read-only */
    const char *filesystem_path;         /* Target path on filesystem */
    const char *storage_path;            /* Path in profile, e.g., home/.bashrc */
    const char *profile;                 /* The profile it is from (a discovery: the one it is in) */
    path_kind_t item_kind;               /* The identity source's kind (a discovery: FILE) */

    /* The look, taken once (workspace_look) */
    fs_occupant_t occupant;              /* What the lstat found; UNKNOWN where none was taken or it failed */
    workspace_displaced_t displaced;     /* Whose squatter withheld the look, or NONE */
    int lstat_errno;                     /* lstat's, on an UNKNOWN from a look that failed */
    struct stat st;                      /* The look's stat, meaningful for a present occupant alone */

    /* The verdict — its kind's analysis's */
    workspace_state_t state;             /* Where the item exists (deployed/undeployed/etc.) */
    divergence_type_t divergence;        /* What's wrong with it (bit flags, can combine) */
    workspace_fault_t fault;             /* Whose remedy the failed look is; NONE unless UNVERIFIED */
    workspace_relocation_t relocation;   /* The rule of a relocated claim's namespace, or NONE */
    state_stat_t stat;                   /* What stands behind disk being the row's content; UNSET elsewhere */

    /* The confirmation — its kind's analysis's; the flush clears it once the store holds it */
    divergence_type_t confirmation;      /* The axes the look established that the record lacks */
} workspace_item_t;

/**
 * The node a type stands as — the kind, in the ladder's division
 *
 * A regular file for either blob mode, a link, a directory: as finely as
 * infra/compare.h's ladder tells one from another — compare.c tests S_ISLNK for
 * a link and S_ISREG for either blob mode, and never the executable bit — so
 * FILE and EXECUTABLE are one kind, their difference the mode axis's. A directory
 * is the third kind. Named in the look's words because a kind is what a look
 * can tell apart: two types are one kind iff they stand as one occupant, and a
 * look finds a type's node iff it found this occupant. No type stands as an
 * absence, as a look failed or not taken, or as a FIFO, a socket or a device
 * (FS_OCCUPANT_NONE, FS_OCCUPANT_UNKNOWN, FS_OCCUPANT_OTHER).
 *
 * The record keeps the node it describes in the same words (core/state.h
 * state_record_t's kind), so a row and the record at its path are of one kind
 * iff this answers the record's — the ladder's first rung, asked of a record,
 * which no reader asks any other way. A record of another kind than its row
 * describes another node, so it is none of the row's: no pair the row's content
 * is measured from (workspace_compare_confirmed below), no base for its claim
 * (workspace_claims_moved below), no record a learning is written onto
 * (core/workspace.c workspace_flush), and no witness to its deletion
 * (classify_absent). Whether that node still stands is a look's to say. While
 * it does, the row's deployment replaces dotta's own node there, which is a
 * reassignment (workspace_reassigned below); where the look found the row's own
 * kind in its place, that node is gone, and the load's flush writes the row's
 * first observation over the record wherever no verdict reads it — a directory
 * row's always, a file row's where the record holds no confirmed pair or the
 * load learned the row's content (workspace_flush) — which apply adopts, a file's,
 * as it adopts a path with no record (cmds/apply.c cmd_apply's adoption).
 *
 * The same division one layer down, over a stat: infra/compare.c mode_stands,
 * under a git filemode, and core/state.h state_stat_matches, under the record's
 * kind. core/workspace.c claim_stands asks a coarser question of its own: a
 * directory or not.
 *
 * Readers: the rung's, named above; workspace_observation (the kind a row's record
 * is born with); workspace_flush (the observation, owed only where the row's
 * own kind stands, either kind of row, over no record or one of another kind);
 * core/workspace.c workspace_analyze_file (the ladder's first rung, off the look
 * before any read, and the content's note, which a record of another kind takes
 * through the observation written in its place); core/deploy.c occupant_conflicts
 * (what stands at a planned path, against the node its row lands). A reader not
 * on this list is a bug.
 */
static inline fs_occupant_t workspace_type_occupant(path_type_t type) {
    switch (type) {
        case PATH_TYPE_FILE:
        case PATH_TYPE_EXECUTABLE: return FS_OCCUPANT_REGULAR;
        case PATH_TYPE_SYMLINK:    return FS_OCCUPANT_SYMLINK;
        case PATH_TYPE_DIRECTORY:  return FS_OCCUPANT_DIRECTORY;
    }

    CHECK_ARG(false, "a path type no enumerator names");
}

/**
 * The row's content against the pair the record confirmed — a verdict from no look
 *
 * infra/compare.h's ladder asked of the record's confirmation instead of a disk
 * copy: the kind, then the bytes. It answers in that module's words, minus the
 * one only a read can reach — nothing is opened here, so no absence can be met.
 *
 * The kind rung is what keeps one object from standing for two contents: Git
 * hashes a link's target exactly as it hashes a file's bytes, so a single id
 * sits behind both and means a different thing under each. A row and a record
 * are one kind iff the row's type stands as the record's node
 * (workspace_type_occupant above, which says what another kind means); a directory
 * claims no content at all, so a blob row and a directory record are never one
 * another's, whatever their (zero) blobs say.
 *
 * Readers: core/workspace.c workspace_analyze_file's base fast path, which reaches
 * its row-against-disk verdict through this one — a live look standing behind
 * the pair's stat means disk IS the pair, so what the row is to the pair is what
 * it is to disk — and workspace_stale below, the boolean reading of it. A reader
 * not on this list is a bug.
 *
 * Not this: core/workspace.c workspace_compare_base's stat — the second question's
 * and an orphan's — whose reference IS the record's pair. Nothing stands on the
 * other side there, so a stat that matches is CMP_EQUAL by identity and no
 * comparison is owed.
 */
static inline compare_result_t workspace_compare_confirmed(
    const manifest_row_t *row, const state_record_t *record
) {
    if (record->kind != workspace_type_occupant(row->type)) {
        return CMP_TYPE_DIFF;
    }

    return git_oid_equal(&record->blob_oid, &row->blob_oid) ? CMP_EQUAL : CMP_DIFFERENT;
}

/**
 * A pending reassignment: the record dotta owns names a profile the row does
 * not, and describes the node the row's deployment takes over
 *
 * The join over its two subjects — a view row and the record at its path — and
 * the look at that path, since a record describes a node and only a look says
 * whether one stands; an item-shaped caller passes item->row, item->record and
 * item->occupant. NULL on either side is no reassignment: an orphan item carries
 * no row, and a path dotta has no record of has no owner to reassign it from.
 *
 * The record's kind decides what the look is asked (the ladder's first rung,
 * workspace_type_occupant above). Of the row's kind, the record is the row's
 * own node's history, and the reassignment stands whatever the look found: a
 * copy the user edited, replaced or deleted is still the one the record names,
 * and the write that answers the row re-stamps the record under it. Of another
 * kind, it is another node's — a link where the row claims a file, a file where
 * it claims a directory — reassigned only while that node stands: the row's
 * deployment then replaces dotta's own node, and the replacement is the
 * acknowledgement, the line a same-kind reassignment reads. A look that found
 * anything else found that node gone — the row's own kind in its place, another
 * node, or nothing — and there is nothing to reassign: the path reads as one
 * the record does not name, and where the row's own kind stands the load's flush
 * observes it in the record's place (workspace_flush), a clean file then adopted
 * (cmds/apply.c cmd_apply). No look — withheld beneath a squatter, failed, or
 * not in the caller's hands (FS_OCCUPANT_UNKNOWN) — disproves nothing, and the
 * reassignment stands: absence is never inferred from a failure to look.
 *
 * Reads the LIVE record when handed the item's — after apply acknowledges
 * (workspace_anchor points the item at a record under the row's profile) the
 * same read of the item honestly answers false, so a consumer that wants the
 * load-time fact reads before the run's ownership events, or off the record the
 * load read, which they replace and never write (each of apply's writers reads
 * before its own).
 *
 * Only an owned record qualifies: an observed or confirmed record dotta never
 * deployed names the row the path was first seen under, not a deployer, and apply
 * adopts such a path rather than acknowledging it.
 *
 * Both kinds — and of a directory's two classes, the tracked one alone. A
 * reassignment is a question about tracking the path, which core/manifest.h asks
 * of tracked claims alone: a derived ancestor claim carries no intent to
 * acknowledge, deploy's plan drops such a row before scope and the directory
 * analysis stops at the same line, so nothing would ever discharge one. The clause
 * lives in the rule and not at the callers because most callers stand inside a
 * loop that has already settled the row's kind and class, and the ones that do
 * not cannot see that they need it. manifest_is_derived is that clause entire:
 * a file row's `tracked` is a don't-care, and the kind gates the read inside
 * the predicate.
 *
 * Orphans: false by construction — an orphan item carries no row, so no reader
 * needs an orphan guard.
 *
 * Readers: the route table, with the item's — the diverged items list a clean
 * row that carries this through it (core/workspace.c workspace_list) — and the
 * tags (workspace_item_tags), with the item's; diff's filter, its "acknowledged
 * by apply" line and its status colour (cmds/diff.c), with the item's; apply's
 * two acknowledgement loops — the writers that move the record onto the row's
 * profile — its pending reassignments off the verdicts, and its record phase,
 * each with the item's (cmds/apply.c cmd_apply, apply_write_record); and sync's
 * apply hint, with none, which asks it of the record against the view with no
 * workspace at all, workspace_stale answering first across kinds (cmds/sync.c).
 * A record's WRITER asks the whole binding — profile and storage path both —
 * which is manifest_is_claim; this is the half the screens name and the receipts
 * count. Not manifest_diff_stats_t's `reassigned`, which counts one transition's
 * own delta between two views; this is the record against the view, standing
 * from whenever it began.
 *
 * The record against the view has three words, and this is the binding's — the
 * one of the three that reads the look; workspace_stale below is the content's,
 * workspace_claims_moved the claim's.
 */
static inline bool workspace_reassigned(
    const manifest_row_t *row, const state_record_t *record, fs_occupant_t occupant
) {
    /* A record dotta owns, a claim the row makes, and another profile named */
    if (!row || !record || record->deployed_at == 0 || manifest_is_derived(row) ||
        strcmp(record->profile, row->profile) == 0) {
        return false;
    }

    /* Of the row's kind: the row's own node's history, whatever the look found */
    if (record->kind == workspace_type_occupant(row->type)) {
        return true;
    }

    /* Of another kind: its own node's, while a look finds it standing — and no
     * look disproves nothing */
    return occupant == FS_OCCUPANT_UNKNOWN || occupant == record->kind;
}

/**
 * Stale: Git advanced past what dotta confirmed — the join's content word
 *
 * The row's content is not the confirmed pair's: another blob, or the same blob
 * under another kind. The rule is workspace_compare_confirmed's above; this is
 * the word the screens and the record's own contract keep for it, beside
 * workspace_reassigned over the same two subjects and a look.
 *
 * A zero blob is stale against any file row: nothing was confirmed, so nothing
 * vouches. Two zero blobs under one kind are not — a directory record under a
 * directory row has nothing to confirm and nothing has moved.
 *
 * Readers: core/workspace.c workspace_analyze_file (git_moved — the three-way
 * frame's first question, and the gate on its second), cmds/sync.c cmd_sync's
 * apply hint (the record still disagrees with the view). A reader not on this
 * list is a bug.
 */
static inline bool workspace_stale(const manifest_row_t *row, const state_record_t *record) {
    return workspace_compare_confirmed(row, record) != CMP_EQUAL;
}

/**
 * The claims Git moved past the ones dotta last reconciled — the join's claim word
 *
 * The row's claim against the record's, axis by axis, in the divergence's words:
 * DIVERGENCE_MODE where the modes differ, DIVERGENCE_OWNERSHIP where the owner
 * or the group does. The record's claim is the one dotta last reconciled the
 * path against (core/state.h state_record_t), so an axis answered here is one
 * Git moved since, or one a run left the path short of; whether disk followed
 * is the look's to say. The words, never their reading on this host: a claim is
 * what Git holds, and two spellings of one owner are two claims.
 *
 * A link claims no mode, and is never asked for one: a link row's 0 is a
 * don't-care, and so is a link record's (its column NULL, core/state.h
 * state_record_t).
 *
 * NONE where the record is no base for the row's claim: no record; a record of
 * another kind (the kind rung, workspace_type_occupant above — another node's,
 * whose claim says nothing of the row's, whether or not that node still stands);
 * a derived row, whose claim says what to create the path as and nothing the
 * analysis measures (the clause workspace_reassigned keeps).
 *
 * Readers: core/workspace.c workspace_analyze_claim, which both analyses of an
 * active item call (DIVERGENCE_CLAIM_MOVED where disk has not followed a moved
 * claim, the record's learning where it has), cmds/apply.c apply_write_record
 * (the claims a fix set that the record still lacks), cmds/sync.c cmd_sync's
 * apply hint (the record still disagrees with the view). A reader not on this
 * list is a bug.
 */
static inline divergence_type_t workspace_claims_moved(
    const manifest_row_t *row, const state_record_t *record
) {
    if (!record || manifest_is_derived(row) ||
        record->kind != workspace_type_occupant(row->type)) {
        return DIVERGENCE_NONE;
    }

    divergence_type_t moved = DIVERGENCE_NONE;
    if (row->type != PATH_TYPE_SYMLINK && record->mode != row->mode) {
        moved |= DIVERGENCE_MODE;
    }
    if (!str_equal(record->owner, row->owner) || !str_equal(record->group, row->group)) {
        moved |= DIVERGENCE_OWNERSHIP;
    }
    return moved;
}

/**
 * Bound carrier for a borrowed slice of workspace items
 *
 * Structural type — parallels manifest_rows_t. Callers receive a typed handle
 * instead of triple-star out-params.
 *
 * Pass by value. Lifetime is the producer's:
 * - the workspace's own — the active items, both kinds or one (workspace_active,
 *   workspace_directories, workspace_files), and the diverged items
 *   (workspace_diverged) — borrow for the workspace's life;
 * - a classification's buckets (workspace_buckets_t: deploy's plan, core/deploy.h
 *   deploy_partition_t; cleanup's plan and verdicts, core/cleanup.h; status's
 *   sections, cmds/status.c status_print_workspace; update's partition,
 *   cmds/update.c update_partition) point into arrays in the arena its buckets
 *   were made in;
 * - update's per-profile share of its work (cmds/update.c update_execute) points
 *   into an array the next profile refills: valid for one update_profile call.
 * The items are the workspace's however long a slice lives. Nothing frees a slice.
 */
typedef struct {
    const workspace_item_t *const *entries;
    size_t count;
} workspace_items_t;

/**
 * Which verb resolves a deployed item — the one route table
 *
 * The partition of WORKSPACE_STATE_DEPLOYED items that every surface routing a
 * deployed item reads, so no two surfaces can route one item two ways — the shape
 * cleanup_verdict gives the orphan side. One producer (workspace_item_route)
 * and eight readers, each named with the arm it reads; a reader not on this list
 * is a bug:
 *
 *   the diverged items' derivation CLEAN, the one arm a DEPLOYED item is left
 *                                  out on (workspace.c workspace_list)
 *   the tags' clean arm            CLEAN, the one arm rendered as agreement —
 *                                  [clean], or [ancestor] on a derived rung
 *                                  (workspace.c workspace_item_tags)
 *   status's section partition     every arm, one bucket each
 *   update's filter                CAPTURE accepted; every other arm refused
 *                                  and counted under its route, one slot per
 *                                  arm (WORKSPACE_ROUTE_COUNT), which the census
 *                                  reads back as one line per refusing arm —
 *                                  the one reader the compiler does not hold to
 *                                  the table: a new arm needs its line there
 *   sync's guard                   CAPTURE blocks (update's work); CONFLICT ∪
 *                                  KIND block (the conflicts update refuses);
 *                                  UNVERIFIABLE, DISPLACED_* and KIND_DERIVED
 *                                  are advisory
 *   apply's CONTENT skip label     CONFLICT
 *   diff's status line             CONFLICT
 *   diff's downstream direction    CAPTURE
 *
 * Values are listed in precedence order: the route is the first that applies,
 * so a multi-bit divergence routes under the reason that outranks the rest.
 *
 * Deployed items only. Every other state routes trivially by the state itself
 * (DELETED → update's, UNDEPLOYED → apply's, UNTRACKED → update --include-new's,
 * ORPHANED / RELEASED → cleanup_verdict's) and is not drift-prone. DELETED earns
 * that triviality upstream, three times: classify_absent reads absence as a
 * deletion only for a claim that asserts its path, so an ancestor claim never
 * arrives here; only over a record of the claim's own kind, so a path where dotta
 * only ever saw another kind of node never does either; and only where a look
 * was taken, so a path whose absence the squatter above it caused is a displaced
 * DEPLOYED item instead (workspace_displaced_t). Every DELETED item can therefore
 * bear update's verb. Callers keep their state switch and read this table for
 * the DEPLOYED arm alone.
 */
typedef enum {
    WORKSPACE_ROUTE_CLEAN,             /* No divergence, no reassignment */
    WORKSPACE_ROUTE_DISPLACED_TRACKED, /* Through a squatter a tracked row claims (apply --force) */
    WORKSPACE_ROUTE_DISPLACED_DERIVED, /* … an ancestor claim holds ('dotta update <dir>') */
    WORKSPACE_ROUTE_UNVERIFIABLE,      /* DIVERGENCE_UNVERIFIED — dotta could not look */
    WORKSPACE_ROUTE_CONFLICT,          /* (STALE ∨ CLAIM_MOVED) ∧ CONTENT — both sides moved */
    WORKSPACE_ROUTE_STALE,             /* STALE ∨ CLAIM_MOVED alone — Git moved, disk did not */
    WORKSPACE_ROUTE_KIND,              /* TYPE the copy cannot commit, on a row a plan can hold */
    WORKSPACE_ROUTE_KIND_DERIVED,      /* … on a rung dotta only passes through — never planned */
    WORKSPACE_ROUTE_CAPTURE,           /* Any other divergence — update's to commit */
    WORKSPACE_ROUTE_REASSIGNED         /* No divergence; the record names another profile */
} workspace_route_t;

/* The table's arity, for an array with one slot per arm. A macro, not an
 * enumerator: the switches over the table are exhaustive and must not have to
 * name a sentinel. */
#define WORKSPACE_ROUTE_COUNT (WORKSPACE_ROUTE_REASSIGNED + 1)

/**
 * Decide which verb's work a deployed item is, from the item alone
 *
 * Pure in the fields the load wrote once — the displaced class, divergence, kind,
 * occupant, reassignment. No syscall, no options; first match wins:
 *
 *   displaced, TRACKED       DISPLACED_TRACKED — a squatter a tracked row
 *                            claims stands above the path, so nothing there was
 *                            looked at and the item carries no bit for the arms
 *                            below to rank: no verdict can outrank the fact that
 *                            voided every look (deploy's ANCESTOR rung and
 *                            cleanup_verdict's displaced arm rank it the same
 *                            way). apply --force replaces the squatter and writes
 *                            the row fresh beneath it.
 *   displaced, DERIVED       DISPLACED_DERIVED — the same, beneath a rung
 *                            dotta only passes through, which no plan holds:
 *                            'dotta update <dir>' re-derives the way there. RECORD
 *                            stands on no deployed item (the reach rule,
 *                            workspace_displaced_t), so the two view classes
 *                            are the whole test.
 *   DIVERGENCE_UNVERIFIED    UNVERIFIABLE — a bit the analysis could not
 *                            settle outranks the ones it could (the precedence
 *                            cleanup_skip_reason gives orphans): the path could
 *                            not be read (EACCES, ELOOP, EIO — both kinds), or
 *                            its content could not be loaded, decrypted, or
 *                            compared. update's copy would fail on the same errno;
 *                            apply plans the row and skips it rather than write
 *                            what it cannot read, and says so through the exit
 *                            code — and an ENCRYPTION bit beside it changes nothing
 *                            the user can act on while the path cannot be read.
 *                            Which of the three refusals it was, and what settles
 *                            it, is the item's fault (workspace_fault_t); the
 *                            route does not read it — one verb, three words.
 *   (STALE ∨ CLAIM_MOVED)    CONFLICT — both sides moved since dotta last
 *     ∧ CONTENT              reconciled: the edit is real, but update will not
 *                            commit over a move Git made — its capture takes
 *                            the item whole, bytes and claims — and apply skips
 *                            the row rather than overwrite the edit without
 *                            --force. Neither verb's by default; the user decides.
 *   STALE ∨ CLAIM_MOVED      STALE — Git moved past what dotta last reconciled,
 *     alone                  the bytes or a claim, and disk did not follow:
 *                            overwriting loses nothing, so it is apply's to bring,
 *                            whatever claims of the user's ride beside it — a
 *                            claim is never an edit (deploy_content_conflicts),
 *                            and apply converges every claim whoever moved it.
 *                            A claim naming an owner this host cannot resolve
 *                            reads here too: no run here brings it, and apply
 *                            is the verb that says why every time it is run.
 *   TYPE, non-capturable     KIND — a kind mismatch the copy cannot commit, on
 *                            a row a plan can hold: a tracked directory row's
 *                            type change (the walk's race guard refuses it — a
 *                            symlink would stat as its target and launder the
 *                            target's attributes into metadata), or a file row
 *                            occupied by a directory, FIFO, socket, or device.
 *                            Resolution is explicit and the user's: apply --force
 *                            replaces what the run converges, remove untracks it.
 *   TYPE on a derived rung   KIND_DERIVED — the same mismatch on a directory
 *                            dotta only passes through: neither planned nor named,
 *                            so no flag lifts it and no decision pends. One verb
 *                            — the named re-derivation whose chain meets the
 *                            squatter drops the claim ('dotta update <dir>',
 *                            metadata_capture_ancestors). The two arms partition
 *                            what was one by the row's class: a deployed item
 *                            is a view row's (the join), so the row is the subject
 *                            and manifest_is_derived is the whole test — the
 *                            kind gating the read inside it, a file row's tracked
 *                            field being a don't-care.
 *   any other divergence     CAPTURE — the user's own, bytes or a claim Git did
 *                            not move: update's to commit. A file row's file ↔
 *                            symlink stays here: the copy commits it as the new
 *                            kind.
 *   none, record disagrees   REASSIGNED — a pending reassignment apply
 *                            acknowledges.
 *   none                     CLEAN.
 *
 * @param item Deployed workspace item (must not be NULL)
 * @return The first route that applies
 */
workspace_route_t workspace_item_route(const workspace_item_t *item);

/**
 * Workspace structure (opaque)
 *
 * Holds the view, the record and the divergence analysis over both.
 */
typedef struct workspace workspace_t;

/**
 * Workspace load options — the two analyses a caller may decline
 *
 * What every load does is workspace_load's own contract, stated there. These
 * two are optional because each walks a set the join does not, at a cost, for a
 * reader that may not exist:
 *
 * - analyze_orphans — every record whose path the view lacks, either kind:
 *   presence, ownership, divergence and Git authority, at one ref lookup and a
 *   lazy tree load per profile with present, owned orphans, the sheet beside it
 *   where a directory orphan needs one, and one tree lookup per such orphan.
 *   Read by core/cleanup.c cleanup_plan_build (the settle, apply's cleanup) and
 *   cmds/status.c status_print_workspace (Issues).
 * - analyze_untracked — every regular file and symlink beneath a tracked directory
 *   that no enabled profile claims and dotta has no record of, at a readdir walk
 *   per tracked directory. Read by cmds/update.c update_partition, cmds/status.c
 *   status_print_workspace (New files) and cmds/sync.c cmd_sync (the
 *   clean-workspace guard). Declined for a second reason the orphan analysis
 *   has no equivalent of: auto_detect_new_files and --include-new are the user
 *   saying whether to look at all, so this one is a config read where the other
 *   is a per-command constant.
 *
 * A reader not named above is a bug. Declining an analysis declines its items;
 * it never asserts there are none — a load with the orphan analysis off reads
 * an empty orphan set because nobody looked, not because the machine is clean.
 *
 * Lifetime: read-only during workspace_load(), safe to stack-allocate.
 */
typedef struct {
    bool analyze_orphans;      /* The records the view lacks (a Git probe per profile) */
    bool analyze_untracked;    /* New files under tracked directories (a readdir each) */
} workspace_options_t;

/**
 * Load workspace from repository
 *
 * Slices the view, loads the record and performs divergence analysis against
 * the filesystem:
 * - The view: every enabled profile's tree and metadata at HEAD
 * - The record: the path_records in the store's dotta.db
 * - The filesystem: one look per row, either kind, and one per record the view
 *   lacks where a reader asks for it — and none beneath a squatter that reaches
 *   the asker (workspace_displaced_t)
 *
 * The join is every load's and no caller's to decline: the view's directory rows,
 * then its file rows. Both kinds, because a kind nobody analyzed keeps the verdict
 * the partition made its items with — DEPLOYED, nothing wrong — which every reader
 * of an item takes for a path looked at and found clean: for apply that is
 * adoption, taking ownership of paths it never looked at (core/deploy.c
 * deploy_plan_build, which files a clean item among the adoptable). Directories
 * first, because their looks are the only producer of the view's squatters
 * (workspace.c workspace_look) and every look the load takes after them asks
 * that fact before taking one: run the file rows without it and a row beneath a
 * squatter is looked at *through* the squatter — workspace_displaced_t names
 * what such a look answers — carrying no displaced field to say so, so its bits
 * come back as the user's own work (workspace_item_route).
 *
 * Additionally, where `analyze_untracked` asks for it: every regular file and
 * symlink beneath a tracked directory that no enabled profile claims and dotta
 * has no record of, offered to the profile whose tracked directory it lies in —
 * the nearest by the directory's own identity, the later-enabled where two stand
 * at one directory — under the name that profile's own claims give it and minus
 * what its ignore layers exclude — and nothing beneath a path the view holds a
 * blob at, where no apply could ever place it. A best-effort look that says what
 * it could not list or look at, and what Git's ignore rules could not judge,
 * which it withholds, each cause once — never a path the view settles, which
 * the join has already named — and goes on with the siblings
 * (workspace_analyze_untracked). The record's half is a load fact, not an
 * analysis's: a path dotta remembers is no discovery on any surface, whichever
 * of the two the caller asked for — and so is the entry each row and each record
 * stands on, so a path the view claims or the record remembers under another
 * spelling is no discovery either (see Identity above).
 *
 * The workspace is scoped to the persistent enabled profile set — the view is
 * built over exactly those profiles, and a record under any other profile is an
 * orphan. This enforces the invariant that workspace loading uses the persistent
 * enabled set rather than any CLI filter (operations like `dotta status -p global`
 * still load the full workspace and apply the filter at display time via
 * scope_accepts_profile).
 *
 * The workspace keeps no copy of the profile set: the view itself is the
 * dispatcher's, built over the enabled set at the start of the command and borrowed
 * here — one tree walk per enabled profile, once per command — and what needs
 * the set's order reads it from the view (manifest_profiles: the untracked scan's
 * registration of its roots), so the workspace borrows nothing a caller must
 * keep alive beside it.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (must not be NULL, borrowed from caller, who keeps
 *              it open for as long as it reads the workspace)
 * @param config Configuration (for ignore patterns, can be NULL)
 * @param content_cache Shared blob-content cache (must not be NULL;
 *              borrowed — it must outlive the workspace. Obtain from
 *              `ctx->run.content_cache` under a spec that declares crypto)
 * @param manifest The view over the enabled set (must not be NULL; borrowed —
 *                 it must outlive the workspace. `ctx->run.manifest`, which the
 *                 command's spec declares with `.manifest`; no command mutates
 *                 Git or the enabled set between dispatch and workspace_load,
 *                 so it is current)
 * @param opts The two analyses this load may decline (must not be NULL)
 * @param arena The arena the workspace lives in, and everything it holds (the
 *              items, the record, the diverged items, the partition's arrays),
 *              beside the view's rows: nothing frees a workspace, which goes
 *              with it. In practice `ctx->arena` (must not be NULL).
 * @param out Workspace (must not be NULL)
 * @return Error or NULL on success
 */
error_t workspace_load(
    git_repository *repo,
    state_t *state,
    const struct config *config,
    content_cache_t *content_cache,
    const manifest_t *manifest,
    const workspace_options_t *opts,
    arena_t *arena,
    workspace_t **out
);

/**
 * The diverged items
 *
 * Every item the load's analyses left with something to say, derived once every
 * verdict is in (workspace.c workspace_list), then the scan's discoveries — as
 * a borrowed slice. Pure value return — no allocation, no error path. Items are
 * arena-allocated, so the slice and the item addresses it carries are valid for
 * the workspace's lifetime.
 *
 * The discoveries follow every other item, an order a reader may keep:
 * cmds/update.c cmd_update declines the new files as its accepted items' suffix.
 *
 * Every item it holds has something to say: a state but DEPLOYED, or a DEPLOYED
 * item the route does not call clean (workspace_item_route) — a squatter above
 * it, a divergence bit, or a pending reassignment, which a clean row's sources
 * and look derive where its owned record, of the row's own kind, names another
 * profile (workspace_reassigned: a record of another kind is a node the clean
 * row's look found gone). An active path with none of these is not among them,
 * and is lent among the active items all the same (workspace_active, and its
 * kind's: workspace_directories, workspace_files). So a load is clean iff this
 * is empty, and clean over a scope iff it holds none of the scope's items:
 * cmds/status.c status_print_workspace reads its status line that way, filtered
 * or not.
 *
 * @param ws Workspace (NULL returns an empty slice)
 * @return Borrowed slice over the diverged items
 */
workspace_items_t workspace_diverged(const workspace_t *ws);

/**
 * The active items: every row of the view, each as its item
 *
 * Every path an enabled profile claims, the winning profile's claim applied, as
 * the item the load made of it — the row, the record at its path, the look and
 * the verdict over it — the clean ones too: the directory items, then the file
 * items (workspace_directories, workspace_files), for a reader whose question
 * is about an active path whatever its kind. Pure value return — no allocation,
 * no error path.
 *
 * The whole enabled set, never a command's own filter: the workspace is loaded
 * over the persistent set for every command, and a -p or a pathspec narrows what
 * the caller does with these items, afterwards and on its own (core/scope.h).
 *
 * The items are the workspace's, made in its arena at workspace_load and never
 * moved, so the slice and every item in it are valid for the workspace's lifetime.
 *
 * @param ws Workspace (NULL returns an empty slice)
 * @return Borrowed slice over the active items
 */
workspace_items_t workspace_active(const workspace_t *ws);

/**
 * The file items: the active items the view's file rows make
 *
 * workspace_active's set and lifetime, one kind of it, in filesystem_path order.
 * Pure value return — no allocation, no error path.
 *
 * Iterate via:
 *   workspace_items_t files = workspace_files(ws);
 *   for (size_t i = 0; i < files.count; i++) {
 *       const workspace_item_t *item = files.entries[i];
 *       ...
 *   }
 *
 * @param ws Workspace (NULL returns an empty slice)
 * @return Borrowed slice over the file items
 */
workspace_items_t workspace_files(const workspace_t *ws);

/**
 * The directory items: the active items the view's directory rows make
 *
 * Mirror of workspace_files(ws) for directories, in filesystem_path order — both
 * classes, since both name a path that must exist. A consumer whose question is
 * about tracking the directory rather than about it existing tests the row's
 * class (item->row->tracked, core/manifest.h). Pure value return — no allocation,
 * no error path.
 *
 * @param ws Workspace (NULL returns an empty slice)
 * @return Borrowed slice over the directory items
 */
workspace_items_t workspace_directories(const workspace_t *ws);

/**
 * The buckets a classification of the workspace's items fills
 *
 * A producer that classifies items — each into the buckets of its answer that
 * hold it: one, several (update's partition lists an item as the run's work and
 * again by its fate), or none — adds each item to its buckets as it decides it,
 * a bucket named by the slice it will be: a field of the result the producer
 * returns, or a local. Once the last is added, the fill sets every bucket's slice
 * over its items, in the order they were added — a stable grouping, with no
 * comparator and no path order. So a classification spells its buckets once, as
 * its answer's own slices: no container per bucket, no cast, and the slice every
 * reader holds (workspace_items_t).
 *
 * What the producer owes the construction:
 *   - a slice is empty ({ 0 }) when first added to, and belongs to these buckets
 *     alone until the fill: no two share one
 *   - it stays at one address, and is neither changed nor read as an answer until
 *     the fill — a copy of the struct holding it, taken before, is not the one
 *     the fill writes
 *   - the fill comes once, after the last addition, and ends the construction
 *   - totality and uniqueness are the producer's: every addition is kept, and
 *     nothing checks that each item was classified, or classified once
 * The one misuse the buckets can see dies at a slice's first addition: a slice
 * that already holds items, which the fill would overwrite.
 *
 * Three lifetimes meet here: the slice, a value wherever its holder keeps it;
 * each bucket's array, the arena's the buckets were made in, grown as items are
 * added and never moved once filled; and the items, the workspace's — an arena
 * that outlives the workspace does not extend them.
 *
 * A pass that must read what it decided while it decides keeps an index of its
 * own beside the buckets (core/cleanup.c cleanup_preflight's fate set); a producer
 * that builds a new element per decision keeps typed arrays of it instead
 * (core/deploy.h deploy_preflight_t, the receipts).
 *
 * Readers: core/deploy.c deploy_plan_build (through deploy_classify),
 * core/cleanup.c cleanup_plan_build and cleanup_preflight, cmds/status.c
 * status_print_workspace, cmds/update.c update_partition. A reader not on this
 * list is a bug.
 */
typedef struct workspace_buckets workspace_buckets_t;

/**
 * Make the buckets of one classification
 *
 * Nothing is reserved: a bucket's array is made at its first addition and grows
 * as every array in an arena grows (base/arena.h arena_grow), each outgrown array
 * left to the arena.
 *
 * @param arena Arena the buckets and every bucket's array live in: the answer's
 *              own (must not be NULL)
 * @return The buckets; never NULL
 */
workspace_buckets_t *workspace_buckets_create(arena_t *arena);

/**
 * Add an item to a bucket, after every item added to it before
 *
 * @param buckets The classification's buckets (must not be NULL)
 * @param item    The item, borrowed (must not be NULL)
 * @param slice   The bucket, as the slice the fill sets (must not be NULL; empty
 *                the first time it is added to)
 */
void workspace_buckets_add(
    workspace_buckets_t *buckets, const workspace_item_t *item, workspace_items_t *slice
);

/**
 * Fill every bucket added to: its slice, over its items in the order added
 *
 * Once, after the last addition. A slice nothing was added to is none of the
 * buckets', and keeps its { 0 }: the empty slice.
 *
 * @param buckets The classification's buckets (must not be NULL)
 */
void workspace_buckets_fill(workspace_buckets_t *buckets);

/**
 * The managed item at a path, or NULL
 *
 * An active path's item, the clean ones too — the row, the record at its path,
 * the look and the verdict — else an orphan's, where the load analyzed the orphans:
 * declining an analysis declines its items (workspace_options_t), and an orphan
 * no analysis reached carries the verdict the partition made it with, which a
 * reader would take for a copy to prune. Found by the path's spelling, the join's
 * own key (see Identity above). NULL where the load lends no item at the path:
 * no row and no record is spelled so, the orphans went unanalyzed, or the path
 * is a discovery of the scan, which the diverged items alone lend
 * (workspace_diverged). Pure value return — no allocation, no error path; the
 * item is valid for the workspace's lifetime.
 *
 * For a reader walking the disk, which meets a path cold: core/cleanup.c
 * vouch_entry, whose emptiness walk meets an entry outside the plan and asks
 * whether it is an orphan; core/deploy.c holdable_directory, whose landing climb
 * meets a present ancestor and asks whether the view names a directory there.
 * Each asks its own question of the item: an orphan carries no row, and an active
 * item is never ORPHANED. A reader holding an item — the active items, the diverged
 * items, an engine's bucket, a fate — asks nothing by path. A reader not on this
 * list is a bug.
 *
 * @param ws Workspace (NULL returns NULL)
 * @param filesystem_path Path to look up (NULL returns NULL)
 * @return The item, borrowed for the workspace's lifetime, or NULL
 */
const workspace_item_t *workspace_find(
    const workspace_t *ws,
    const char *filesystem_path
);

/**
 * A squatted directory, and whose claim holds it
 *
 * A claim says a directory belongs at the path and the load's look found another
 * kind standing there (workspace_displaced_t: the words, and the reach the claim's
 * class decides). One producer for both authorities of the reach rule: the look
 * that found the squatter (workspace.c workspace_look), over a view directory
 * row whose class names the claim, over a directory record no row stands at that
 * another kind of node stands in the place of, or over any path it looks at — a
 * record's or a row's — where a link stands with an orphan beneath it, noted
 * where it was found, so the claim is the producer's and is never re-derived:
 * an item the squatted directory reaches carries it as its displaced class —
 * the outermost's, where two reach the item — and a caller holding a path is
 * lent the element itself (workspace_squatted_ancestor).
 *
 * The workspace's own list element, lent: the list is one arena block, sized by
 * the partition for every item that could note one and never grown, so a pointer
 * to an element is valid for the workspace's lifetime. The path is the row's or
 * the record's (borrowed); `len` is its strlen, hoisted for the scan — and, the
 * squatted directory being a proper ancestor of every path it reaches, the byte
 * length of the prefix each of those paths opens with.
 */
typedef struct {
    const char *filesystem_path;  /* The row's or the record's (borrowed) */
    size_t len;                   /* strlen(filesystem_path): the prefix of every path beneath it */
    workspace_displaced_t claim;  /* TRACKED / DERIVED (a view row's), RECORD (a record's) */
} workspace_squatted_t;

/**
 * The squatted directory above `path`, or NULL — the view's claims
 *
 * A directory is *squatted* when a claim says a directory belongs at the path
 * and something else stands there. A look taken beneath such a path would resolve
 * through the occupant — a symlink to a directory answers for the link's target
 * — so nothing it said would be that path's, and the load takes none
 * (workspace_displaced_t).
 *
 * Both classes of directory row qualify: what matters is that some claim says a
 * directory belongs at the path, not whether the profile tracks the directory
 * itself (core/manifest.h). A path no claim names at all stays invisible here
 * by design — a symlinked configuration directory of the user's own arrangement
 * is the user's, and deploy writes through it, cleanup prunes through it, and
 * update captures through it, all correctly. That case survives the ancestry
 * being claimed because the capture rule authors nothing for a component that
 * is not a real directory when the chain is walked: a directory the user had
 * already symlinked never becomes a claim in the first place.
 *
 * A record's memory does not qualify here: a path only a record remembers displaces
 * the orphans beneath it alone (the reach rule, workspace_displaced_t), and every
 * orphan carries the fact on itself. This probe is for a caller that needs the
 * squatter itself, which no item carries: the fate of a planned row (core/deploy.c
 * check_ancestry). A view row beneath a record-remembered squatter is the
 * through-capture the rule leaves to its own occupant. So the answer is the view's
 * claims alone, and its claim is exactly the displaced class a view row's item
 * beneath it carries.
 *
 * The answer is noted by the look that found each squatter (workspace.c
 * workspace_look), and every directory row is looked at before any file row or
 * orphan record (workspace_load), so it is complete before anything asks — a
 * scan root is chosen off the look the directory analysis took, later still.
 * The outermost such ancestor is returned: the true offender, whose presence
 * voids every path beneath it. Fate-blind by construction — whether *this run*
 * converges the squatted directory is deploy's question, asked of its own fates
 * against this answer (check_ancestry).
 *
 * Lent whole, as the load noted it (workspace_squatted_t): the one search, handed
 * out, with nothing re-derived from it. Reader: core/deploy.c check_ancestry,
 * which reads all three — the path, to find the fate this run gave the squatted
 * directory's row; the length, to name it on the skip of a row it holds
 * (core/deploy.h deploy_skip_t); the claim, for the remedy where the run gave
 * that row no fate (deploy_ancestor_class_t).
 *
 * @param ws Workspace (NULL returns NULL)
 * @param path Path to test (NULL returns NULL); proper ancestors only, so a
 *        squatted directory is never its own answer — its own path is its item's
 *        to answer, whose TYPE says so
 * @return The squatted directory, lent (workspace lifetime), or NULL
 */
const workspace_squatted_t *workspace_squatted_ancestor(
    const workspace_t *ws,
    const char *path
);

/**
 * An item's tags: the words its line carries, their colour, and whose it is
 *
 * Translates workspace item state and divergence flags into presentation tags,
 * colors, and metadata strings for use with output_list builder. Provides
 * consistent item visualization across all commands.
 *
 * Clean (DEPLOYED, and the route CLEAN — workspace_item_route): one tag, the
 * only one that renders agreement, and only status's full listing hands such an
 * item over (cmds/status.c status_print_manifest; every other caller renders
 * diverged items). "clean" (GREEN) on a row compared and found agreeing; "ancestor"
 * (DIM) on a derived rung, which was compared with nothing (core/manifest.h
 * manifest_is_derived).
 *
 * Tag Priority (for DEPLOYED state with divergence):
 *   0. "displaced" (YELLOW) - The path's one tag when a squatter stands above
 *      it (workspace_displaced_t): nothing there was looked at, so the item carries
 *      no path bit, and no tag read off a look — 1 to 3, the claim axes, 5 —
 *      can be its. What no look decides still rides: "unencrypted", the blob
 *      against the policy, and "reassigned", the record against the row. The
 *      ORPHANED arm carries "displaced" as a rider, ranked where cleanup_verdict
 *      ranks it — after [absent], before the bits — because a displaced orphan
 *      carries no bits at all and the bare arm would colour it as a prune
 *   1. "type" (RED) - File type changed (symlink ↔ regular), most severe
 *   2. "modified" (YELLOW) - Disk content moved away from what dotta confirmed
 *   3. "stale" (CYAN when alone: apply-side work, like "undeployed") - Git moved
 *      past what dotta last reconciled, the bytes or a claim; next to "modified"
 *      it names a conflict and the primary tag's colour stands
 *   4. Secondary: "mode", "ownership" - the claim axes that differ, whoever moved
 *      them; "unencrypted" - the blob against the policy, beside "displaced" too
 *   5. "locked" / "unreadable" / "unverified" (MAGENTA when still the default) -
 *      The look that failed, worded by the item's fault (workspace_fault_t)
 *      so one path reads the same word wherever it is listed. What settles it
 *      is the block's to say, in its own words, not the row's
 *   6. "reassigned" (CYAN when alone) - A pending reassignment
 *      (workspace_reassigned), last and beside any of the above: the record against
 *      the row, and the look only where the record is of another kind
 *
 * The function handles special cases:
 *   - TYPE divergence suppresses MODE tag (type change makes mode irrelevant)
 *   - ENCRYPTION divergence upgrades color to MAGENTA if still the default
 *   - ENCRYPTION is the one divergence a row carries where nothing was measured
 *     at its path: an UNDEPLOYED row — the copy is not on disk to have diverged
 *     from, but the blob apply is about to write violates the policy, and that
 *     is worth saying before it lands — and a displaced one, whose path no look
 *     reached and whose blob is Git's all the same
 *
 * Metadata Format:
 *   - "from {profile}" - Standard source profile
 *   - "{old} → {new}" - Profile reassignment transition
 *   - "in {profile}" - For untracked items
 *
 * Thread Safety: Uses only stack variables and string literals. Safe for concurrent
 * calls with different items.
 *
 * @param item Workspace item (must not be NULL)
 * @param tags_out Array to receive tag string pointers (WORKSPACE_ITEM_MAX_TAGS
 *                 slots)
 * @param tag_count_out Receives number of tags extracted (must not be NULL)
 * @param color_out Receives color for tags (must not be NULL)
 * @param metadata_buf Buffer for formatted metadata (must not be NULL)
 * @param metadata_size Size of metadata buffer (minimum 32 bytes, 256 recommended
 *                      for safety with long profile names)
 * @return true on success, false on error (invalid parameters)
 */
bool workspace_item_tags(
    const workspace_item_t *item,
    const char **tags_out,
    size_t *tag_count_out,
    output_color_t *color_out,
    char *metadata_buf,
    size_t metadata_size
);

/**
 * The record of a row's first observation: its key, binding, kind and claim —
 * no content, never owned, no order
 *
 * What dotta writes of a path it has seen standing as its row's own kind and
 * holds nothing of — no record, or one of a node the look found gone: the row
 * it reconciled the path against, and nothing it did there. An ownership event
 * is this record with the row's content — its blob, under the stat the event
 * stands on — and the event's stamp; a learning of the content adds the content
 * alone (workspace_flush). The strings are the row's, the view's own, borrowed
 * for as long as the view lives.
 *
 * Readers: core/workspace.c workspace_flush (a first observation, over no record
 * or one of another kind) and workspace_anchor (an ownership event's record). A
 * reader not on this list is a bug.
 */
static inline state_record_t workspace_observation(const manifest_row_t *row) {
    return (state_record_t){
        .filesystem_path = row->filesystem_path,
        .storage_path = row->storage_path,
        .profile = row->profile,
        .kind = workspace_type_occupant(row->type),
        .mode = row->mode,
        .owner = row->owner,
        .group = row->group,
    };
}

/**
 * Anchor an active path: its ownership event, written as a fresh record the item
 * holds once the statement lands
 *
 * The event's record is the row's whole — its observation (workspace_observation),
 * the row's blob under the stat the event stands on, and the event's stamp —
 * built before the statement, written over whatever stood (core/state.h
 * state_write), and pointed at by the item once the statement landed, so
 * item->record reads the post-write record. The record the item held before the
 * event is never written: a reader that took it earlier — apply's reassignment
 * names — reads what the load read, whenever it reads.
 *
 * The workspace-scope writer for ownership events — add and update build theirs
 * from their captures, what each committed, and write it through state_write
 * directly (the header's exception: add loads no workspace, and nothing reads
 * update's after its record write). Its callers, in cmds/apply.c, each holding
 * the item:
 *   - cmd_apply's adoption and acknowledgement loops, over the clean items (an
 *     ownership event on a file's first claim, and the acknowledgement of a clean
 *     row the record has yet to follow, a file's or a tracked directory's — the
 *     record's binding becomes the row's, whichever half of it moved: another
 *     profile's row, or another name of the same profile that the view gave the
 *     path to)
 *   - apply_write_record, the record phase (an ownership event after a write: a
 *     file deployed, a directory made — where nothing stood, in a squatter's
 *     place, or as the parent of a planned path — and a directory fixed in place
 *     whose owned record names another row, which follows the row as a clean
 *     one's does)
 * Learnings are not ownership events and do not come through here: they are the
 * flush's, workspace_learn's for a directory apply fixed, and
 * workspace_learn_mode's for one a run left at its working mode.
 *
 * @param ws Workspace (must not be NULL, state must be open)
 * @param item The active item whose path is anchored (must not be NULL; a row's,
 *             with a non-zero blob for a file row), as the workspace lent it:
 *             the record is this item's from the write on, its strings borrowed
 *             from the item's row, the view's own, for the workspace's lifetime
 * @param stat The stat of the moment the row's content was established on disk,
 *             taken by the code that established it: the analysis's own for an
 *             adoption or acknowledgement, the one its comparison stood on
 *             (workspace_item_t's stat); the deploy receipt's triple for a file
 *             deployment — the executor's fstat of the bytes it wrote, distilled
 *             at the write (state_stat_from_write: authorship vouches for it,
 *             no closed second needed), UNSET for a symlink (made by path, no
 *             descriptor exists to describe it); UNSET for a directory, which
 *             confirms no content. Never a fresh lstat: a look taken here binds
 *             whatever stands at the path now to a verdict from earlier.
 * @param now Timestamp of the event (must be > 0: a record stamped 0 is one dotta
 *            never owned)
 * @return The write's failure, naming the path, or NULL on success
 */
error_t workspace_anchor(
    workspace_t *ws,
    const workspace_item_t *item,
    state_stat_t stat,
    time_t now
);

/**
 * Learn the claims a fix set: the path's record written as a fresh one the item
 * holds once the statement lands
 *
 * The record the item holds, with the row's claim on each axis named — the mode
 * (DIVERGENCE_MODE), the owner and group (DIVERGENCE_OWNERSHIP) — and its own
 * on the rest: what the flush learns of a claim a look found disk standing on,
 * made here by a fix. Built before the statement, written whole over the record
 * it replaces (core/state.h state_write), and pointed at by the item once the
 * statement landed; the record the item held before is never written. The axes
 * are the caller's, established where it stood: this writes what it is handed
 * and asks nothing again.
 *
 * Never an ownership event: the binding and the stamp are the record's own, so
 * a pending reassignment keeps reading as one, and a directory the user made is
 * never handed to the prune.
 *
 * One caller, holding the item: cmds/apply.c apply_write_record, apply's record
 * phase, for the claims a fix set on a tracked directory it converged in place
 * — never the content, which only a load's comparison proves.
 *
 * @param ws Workspace (must not be NULL, state must be open)
 * @param item The active item the fix converged (must not be NULL; a row's, whose
 *             record stands wherever axes is not NONE)
 * @param axes The claim axes the fix established, by their divergence bits (NONE
 *             writes nothing, and the item keeps its record)
 * @return The write's failure, naming the path, or NULL on success
 */
error_t workspace_learn(
    workspace_t *ws,
    const workspace_item_t *item,
    divergence_type_t axes
);

/**
 * Learn the mode a run left standing where it could not land the one it owed:
 * the path's record written as a fresh one the item holds once the statement lands
 *
 * The record the item holds, with `mode` on the mode axis and its own on every
 * other — the binding, the content, the rest of the claim, the stamp: what the
 * record learns where a run widened a directory to its working mode and could
 * not narrow it back (core/deploy.h deploy_hold_t). The record is the base a
 * difference is read from (core/state.h state_record_t), so the next load reads
 * the row's mode as Git's still to bring (workspace_claims_moved) — apply's —
 * and never as the user's, for update to commit. Built before the statement,
 * written whole over the record it replaces (core/state.h state_write), and pointed
 * at by the item once the statement landed; the record the item held before is
 * never written.
 *
 * Never an ownership event: the binding and the stamp are the record's own, as
 * a learning's are.
 *
 * One caller, holding the item: cmds/apply.c apply_write_record, apply's record
 * phase, for each hold its release could not let go whose record says the mode
 * the hold owed.
 *
 * @param ws Workspace (must not be NULL, state must be open)
 * @param item The active item the run left at `mode` (must not be NULL; a row's,
 *             whose record stands)
 * @param mode The mode the run left standing, at most 0777
 * @return The write's failure, naming the path, or NULL on success
 */
error_t workspace_learn_mode(
    workspace_t *ws,
    const workspace_item_t *item,
    mode_t mode
);

/**
 * Write what the load owes the record
 *
 * One write per owed active item — its record whole, as the load learned it
 * (core/state.h state_write) — made of three things the load established:
 *
 *   The observation — a path whose look found its row's own kind standing, either
 *   kind of row, where dotta holds no record of that node: presence of that kind,
 *   the node's first record (workspace_observation). Where no record stands it
 *   is the path's first write; where one of another kind stands — a node the
 *   look found gone — it is written whole over that record wherever no verdict
 *   reads it: under a directory row always, the directory analysis reading no
 *   base; under a file row where the record holds no confirmed pair, or where
 *   the load learned the row's content, which leaves the pair nothing to decide.
 *   A gone node's pair the load measured a difference from, or could not read
 *   past, stays: it is the base both sides of a conflict moved from, or the next
 *   readable load's (core/workspace.c workspace_analyze_file), and the path is
 *   observed once a load finds disk the row's, or apply writes it. Never owned:
 *   a gone node's stamp vouches for a node dotta never wrote there, and apply
 *   adopts a file as it adopts one with no record. A node of another kind than
 *   the row's is no observation: the record would name the row's kind, and the
 *   absence rung reads that as the node dotta saw. The record's one observation,
 *   the load's, because the analysis is where presence is established: every
 *   active path whose look found its row's own kind holds a record of that kind
 *   once the flush has run, but where a gone node's pair is the verdict's base,
 *   and a path the run makes afterwards is an ownership event (workspace_anchor),
 *   not an observation.
 *
 *   The learning — what the analyses established that the record lacks, by axis
 *   (workspace_item_t's confirmation), onto the record the load read or the
 *   observation. The content of a file found equal to its row (the slow path's
 *   CMP_EQUAL), with the look's triple as its stat: persisting it beside the
 *   row's blob lets subsequent runs short-circuit via the fast-path stat AND —
 *   if Git advances blob_oid in the meantime — classify the file as stale directly
 *   from the fast path instead of re-hashing. A learning keeps the binding it
 *   read, so a record of the row's kind is noted a content confirmation only
 *   where the row is its binding's (core/workspace.c workspace_analyze_file),
 *   and the one noted over no record or one of another kind lands on the
 *   observation, the row's own binding: the blob a record carries was committed
 *   under its binding (core/state.h state_record_t), and a path whose record is
 *   bound to another row takes the slow path on every load until an ownership
 *   event moves the record onto the standing one. And a claim Git moved that a
 *   look of either kind found disk already standing on, whichever row's it is,
 *   since a claim opens nothing: the record follows every agreement, so the user's
 *   next move on that axis reads as the user's.
 *
 *   The void — every order a record the load read carries, where the view has
 *   the path again: the order's view end (core/state.h's lifetime rule), here
 *   because the view is. No record written whole carries an order, so an owed
 *   item's write voids its order whatever else it learned, and a record whose
 *   order is all the load owes is written for the void alone.
 *
 * Nothing is owed from beneath a squatter, because nothing there is looked at
 * (workspace_displaced_t): a confirmation taken through one would advance the
 * record's blob to the row's on the strength of the squatter's target, and the
 * three-way frame would then read the bytes dotta actually deployed as the user's
 * own edit once the squatter went — apply-side work turned into update-side work
 * by one squat. Through a symlinked ancestor the view does not claim, the
 * arrangement is the user's own, and so is the stat taken through it.
 *
 * No learning writes the binding, an ownership event's to change, so a clean
 * reassignment keeps reading as one until apply acknowledges it: the one write
 * here that changes a record's binding is the observation over a gone node's,
 * whose binding named a node no longer standing — never a reassignment, which
 * is of the row's own node or of another still standing (workspace_reassigned).
 * Nor does any stamp deployed_at — this flush records what the load saw, not
 * deployments, and apply and the capturing verbs remain its writers; the
 * observation takes a gone node's stamp away with its record.
 *
 * Every write is decided from the load, so each lands only on the store the load
 * read. A run of apply passes its dispatch transaction, taken before the load
 * read anything, and the writes land in it. Where the caller holds none — status,
 * diff, sync, update and a preview of apply — the flush takes the store's lock
 * only where the store still stands as the handle's admission left it (core/state.h
 * state_resume): the view was built from what the admission read, and the record
 * read after it, so the writes land on the store the load decided from, or not
 * at all — a commit since, a learning's as much as a move, refuses the flush
 * whole. So each write is blind and none can undo another writer's: an order
 * placed after the view was built, which the view never answered, or a record
 * moved after it was read. A load that owes nothing, the common one, takes no
 * lock and writes nothing. The lock is a boundary of the row cache that reads
 * the enabled rows again (core/state.h state_begin), so a reader after the flush
 * — cmds/status.c status_print_profiles, cmds/sync.c cmd_sync's view after the
 * pull — reads the rows that lock read.
 *
 * Each owed item's record is built before any statement, and published — the
 * item holds it, and owes nothing more — once the store holds it: after the flush's
 * own commit, or at its end where the writes are the caller's, whose failure
 * ends the run. A flush that fails publishes nothing: every item holds what the
 * load read, and owes what it owed.
 *
 * The failure goes with the transaction. A failure of the writes into the caller's
 * transaction is the caller's: the flush returns it, and the run it poisons ends
 * (cmds/apply.c cmd_apply). A flush that writes for itself keeps every failure
 * of its own — another process's commit since the load or its lock held past
 * the busy timeout, a write or a commit the store refuses — rolls back what it
 * wrote, and what the load owed, the next load owes again, reading the record
 * anew. So a read command renders what its load read whatever the flush met,
 * and every caller takes what the flush returns as its own failure.
 *
 * Self-healing: the first status/apply after profile enable verifies all files
 * via the slow path and seeds the record. The second call hits the fast path
 * for unchanged files and tags STALE directly for externally-modified profiles.
 *
 * @param ws Workspace (must not be NULL); written through the state handle its
 *           load borrowed
 * @return The failure of a write into the caller's transaction, the caller's to
 *         end; NULL otherwise, a flush that writes for itself keeping its own
 */
error_t workspace_flush(workspace_t *ws);

#endif /* DOTTA_WORKSPACE_H */
