/**
 * deploy.h - File and directory deployment engine
 *
 * Plan / preflight / execute, in that order, and the release:
 *
 *   deploy_plan_build   — decide *what* from (workspace, scope), once
 *   deploy_preflight    — decide the fate of every planned row, from the
 *                         workspace's look and the row: a verdict (how it is
 *                         materialized) or a skip (why it is not)
 *   deploy_execute      — carry the verdicts out; decides nothing
 *   deploy_release      — let the holds go, once the caller's other acts are
 *                         done
 *
 * Preview, prompt, reporting and apply's record phase all read the one plan and
 * the one set of verdicts; execution applies no filter and takes no decision of
 * its own. Same shape as core/cleanup, save the release, which the caller times.
 *
 * Design principles:
 * - Every decision is taken at preflight, before anything changes, from the
 *   occupant the workspace's look found (workspace_item_t.occupant) and the row
 *   — and, for a directory in a blob row's way, the entries a readdir finds beneath
 *   it (the clearance) — one fate per planned row, a verdict or an explicit skip,
 *   and one per node of the plan, replaced or kept. A confirmation prompt may
 *   sit between preflight and execute; nothing looks again across it, and nothing
 *   pretends to: the mechanisms refuse what a verdict no longer describes
 *   (O_NOFOLLOW, EISDIR, EEXIST, ENOTEMPTY) and the refusal is that row's outcome,
 *   not the run's end. The one unlink of dotta's node is the mechanism that cannot
 *   tell: whatever non-directory the world put in the node's place by then —
 *   across the prompt, a hook — goes as the node did, one node all the same,
 *   and a directory there refuses it. The same stance as core/cleanup
 * - One element type per phase: the plan buckets borrowed items and authors
 *   nothing; preflight authors the fates — a verdict or a skip, carrying everything
 *   decided about the row; execute authors the outcomes — one per verdict, landed
 *   or failed, the one split execute itself takes. A verb inside a landed bucket
 *   is derived from the fate, never stored twice
 * - A dry run is the preview: the caller reads the verdicts and calls no executor,
 *   so there is no dry-run flag beneath the plan
 * - Removals are single-node, each one node and never a tree, and only to land
 *   a row: what stands at a planned path, the row's own node landing there; a
 *   copy of dotta's beneath a blob row's path, which the row's landing removes
 *   with what stands at its path or not at all — every entry beneath judged first
 *   (deploy_clearance), and each copy removed deepest first, before the directory
 *   it stood in (deploy_preflight_t's clears); or dotta's own node above a planned
 *   path, a file or a link where the rows beneath need a directory, replaced by
 *   one as part of the first act beneath it (deploy_preflight_t's replaces). A
 *   file or link row's node is created whole beside its path before anything in
 *   its way is removed (sys/filesystem.h fs_temp_t), so a write the world refuses
 *   — a full disk, a file-size limit, a name the kernel will not take — removes
 *   nothing; a directory row's squatter goes first, rename(2) putting no directory
 *   over a non-directory. Either arm's window is the one step after its removal,
 *   the rename or the mkdir: refused there, or killed, the run leaves the path
 *   empty over the record that stood, which reads [deleted] wherever a claim of
 *   that record's kind and profile asserts the path — at once where it is the
 *   row's own — and [undeployed] under any other, until a plain apply creates
 *   it (core/workspace.c classify_absent). A copy whose removal is refused fails
 *   its row with that removal's cause, every removal before it standing and its
 *   record retired (cmds/apply.c apply_write_record): no row stands beneath a
 *   standing blob, so no later act's way runs through what is left. The clearance
 *   is preflight's look, and the removals meet what the prompt's window left: a
 *   directory copy a link replaced in that window turns the removals beneath it
 *   into removals inside the link's target, as cleanup's prune does (stated);
 *   and, unlike git, the clearance does not refuse the process's working directory
 *   (stated). Dotta's node goes on the way to the first act beneath it, after
 *   that act's content read and before its node is created, since the temporary
 *   is created in the directory that takes the node's place or beneath it: a
 *   write refused there leaves that directory standing empty and the node gone,
 *   its bytes Git's where dotta confirmed them, and a create refused after its
 *   unlink leaves the path empty with the node's record kept, which the next
 *   load reads absent and reclaims. The node goes alone, never through it, so a
 *   link's target keeps whatever was written through it — an edit of a row beneath
 *   included, which no screen names, nothing beneath the node being looked at
 *   (core/workspace.h workspace_displaced_t) — and the row lands Git's bytes
 *   (stated)
 * - Directories are materialized in two phases: held at a working mode (the mode
 *   owed, owner rwx on: deploy_working_mode) while the run writes beneath them,
 *   then released to the exact mode owed, deepest first, by the caller once every
 *   act beneath them is done — the run's, and whatever the caller runs next
 *   (deploy_release) — the way cmd_export materializes a profile in its own two
 *   phases. A directory the view claims therefore never refuses a path beneath
 *   it where the run may hold it — its owner's or root's to change, and its read
 *   granted, since a hold reaches the directory through a descriptor opened for
 *   reading — and preflight predicts no modes
 * - Metadata is reproduced, not negotiated: every write applies the row's mode
 *   and resolved ownership atomically through its own descriptor, so there is
 *   never a moment when a path stands with the wrong owner
 * - Silent: outcomes travel in the receipt — a row's failure among them, its
 *   cause on the outcome; the nodes and copies the run removed; the holds the
 *   run took, and each the release could not let go — verdicts and skips in the
 *   preflight, with the anomalies met while deciding (an identity that could
 *   not be resolved), which are the caller's to print; the one error this module
 *   returns is preflight's strict_ownership refusal, met before anything changes.
 *   This module emits no prose of its own; verbosity and tense are the caller's,
 *   the same convention as every other core module
 */

#ifndef DOTTA_DEPLOY_H
#define DOTTA_DEPLOY_H

#include <types.h>

#include "base/error.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"

/* Forward declaration — the content cache is deploy_execute's input alone
 * (infra/content.h); everything else this header names is workspace vocabulary,
 * included above. */
typedef struct content_cache content_cache_t;

/**
 * Deployment options — read by deploy_preflight alone, as cleanup's are
 */
typedef struct {
    bool force;               /* Overwrite modified files; replace a type conflict */
    bool strict_ownership;    /* Fail if ownership cannot be resolved */
} deploy_options_t;

/**
 * How one planned row is materialized — decided once, at preflight
 *
 * Everything a consumer needs of the row's own path and nothing it has to go
 * and get: the row's item — the row, with its analysis — what stands at its path,
 * and the metadata the write applies. The occupant is the workspace's lstat,
 * never a fresh one — or FS_OCCUPANT_NONE for a row preflight planned absent
 * beneath a squatter this run replaces first (check_ancestry), whose own path
 * the workspace never looked at and which the run empties before anything lands
 * there. The occupant is also the receipt's verb for a directory: NONE → created,
 * DIRECTORY → fixed, anything else → replaced (deploy_convergence).
 *
 * The item is the one the fate is taken for, filled verbatim on every arm — the
 * planned-absent arms and the skip's included (deploy_skip_t). Its row is the
 * fate's: the view holds one row per path, and an active path's item is that
 * row's own, so the row is read off the item (item->row) and never carried beside
 * it. An item's join facts (row, record, profile) are sound on every fate; a
 * row beneath a squatter carries no look at all (core/workspace.h
 * workspace_displaced_t), which is why the fate's own occupant says what the
 * run will find. What a fate declines to consult it declines at the reader, never
 * by blanking the pointer.
 *
 * Never NULL, so a reader dereferences it without a test. A fate is taken for a
 * pending row, a verdict or a skip, or for an ancestor, a verdict alone, and
 * each holds an item by construction, since every active path has one
 * (core/workspace.h workspace_active): a pending row's is the item its bucket
 * holds, an ancestor's the directory item the pass walks (workspace_directories).
 *
 * The decided facts are exactly the ones not on the row: the occupant, and the
 * ownership the write applies (resolve_deployment_ownership: the claim resolved
 * on this host, half by half — the invoker where it names no owner, no change
 * where it names no group — on every run; (uid_t) -1 is no change, and an owner
 * is left unchanged only where the claim named one this host cannot resolve).
 * The mode the write applies is the row's, read there — total for every kind
 * that carries one (check_ownership carries the rationale). What the row's way
 * needs beyond its path is the run's, never a verdict's (deploy_preflight_t):
 * the ancestors it may create, dotta's node above it, the copies beneath it —
 * each found again by the act whose way meets it.
 */
typedef struct {
    const workspace_item_t *item;    /* Borrowed (workspace lifetime), never NULL; the row is item->row */
    fs_occupant_t occupant;          /* What the run will find at the path */
    uid_t uid;                       /* Ownership the write applies; -1 = no change */
    gid_t gid;
} deploy_verdict_t;

/**
 * A verdict array with its count — the shape manifest_rows_t gives rows
 */
typedef struct {
    deploy_verdict_t *entries;
    size_t count;
} deploy_verdicts_t;

/**
 * Is something known to be standing at the path?
 *
 * FS_OCCUPANT_UNKNOWN deliberately answers no. Deploy judges nothing it could
 * not see: an occupant it failed to stat conflicts with nothing, and the row is
 * skipped as unreadable rather than judged on a guess (the ladder's leftover
 * rung). The workspace's own presence rule (occupant != FS_OCCUPANT_NONE,
 * workspace.h) assumes an unstattable path present; this is deploy's stricter
 * reading, for judgments — one producer, read by occupant_conflicts (the ladder's
 * type rung) in deploy.c, and by cmds/apply.c apply_print_deploy_preview (the
 * overwrite count).
 */
static inline bool deploy_occupant_present(fs_occupant_t occ) {
    return occ != FS_OCCUPANT_NONE && occ != FS_OCCUPANT_UNKNOWN;
}

/**
 * How a directory verdict converges its row — and the receipt's word for it
 *
 * The verdict's occupant decides the whole of it: nothing stood → created; a
 * directory did → fixed, converged in place, no new entry lands; anything else
 * → replaced, one node cleared and then created. One producer for the mapping
 * deploy_verdict_t documents and deploy_receipt_t's verbs derive from, so the
 * preview, the receipt, apply's record phase and the executor read one answer
 * and cannot drift. Two facts ride on it and are read as it: a new entry lands
 * iff the convergence is not a fix (preflight's landing question, and the
 * executor's in deploy_directory: the landing it opens, and the path it notes
 * where no directory came to stand), and dotta created the directory iff the
 * convergence is not a fix (the record phase's ownership gate).
 *
 * Total over fs_occupant_t, so a new occupant is a build error here and not a
 * silent REPLACE. UNKNOWN is answered — preflight asks before it skips such a
 * row (UNREADABLE) — and never reaches a verdict, so no receipt folds it and no
 * executor meets it.
 */
typedef enum {
    DEPLOY_CONVERGE_CREATE,   /* Nothing stood at the path */
    DEPLOY_CONVERGE_FIX,      /* A directory stood there — converged in place */
    DEPLOY_CONVERGE_REPLACE   /* A squatter stood there — cleared, then created */
} deploy_convergence_t;

static inline deploy_convergence_t deploy_convergence(fs_occupant_t occ) {
    switch (occ) {
        case FS_OCCUPANT_NONE:      return DEPLOY_CONVERGE_CREATE;
        case FS_OCCUPANT_DIRECTORY: return DEPLOY_CONVERGE_FIX;
        case FS_OCCUPANT_REGULAR:
        case FS_OCCUPANT_SYMLINK:
        case FS_OCCUPANT_OTHER:
        case FS_OCCUPANT_UNKNOWN:   return DEPLOY_CONVERGE_REPLACE;
    }

    CHECK_ARG(false, "an occupant no enumerator names");
}

/**
 * Is this row's content not dotta's to overwrite unasked?
 *
 * The counterpart of occupant_conflicts (deploy.c), answered from the workspace's
 * divergence verdict: content is compared against a blob that is not on disk,
 * so the load-time verdict is the only authority there is — no lstat can improve
 * on it.
 *
 * A TYPE verdict counts: another kind than the row's stands, and it is not the
 * node dotta last saw there — disk left that node on the kind, the content's
 * axis across kinds (core/workspace.h divergence_type_t) — so whatever stands
 * there is the user's, never measured against the row. A Git move without an
 * edit — STALE, the bytes or the kind, or CLAIM_MOVED, a claim — never conflicts:
 * what stands on disk is what dotta last saw there — its confirmed copy, or its
 * own directory — so the overwrite loses nothing. Mode, ownership and encryption
 * divergence never conflict, whoever moved them: a claim is never an edit
 * (core/workspace.h workspace_item_route, whose STALE arm rests on this).
 *
 * Three readers, two files: the ladder's content rung and its type rung's consent
 * (deploy_preflight) — an occupant of another kind is replaced unasked where
 * Git moved past dotta's own node (STALE) and this answers no — and the forced
 * preview's counterweight (cmds/apply.c apply_print_deploy_preview) — a verdict
 * overwrites local content iff something stands at its path AND this answers
 * yes, so the preview reads it beside deploy_occupant_present. Each hands it
 * the row's item, which every fate carries (deploy_verdict_t).
 *
 * @param item The row's workspace verdict (must not be NULL)
 */
static inline bool deploy_content_conflicts(const workspace_item_t *item) {
    return item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE);
}

/**
 * May a landing remove this node, and on whose word? — the landing's consent
 *
 * The one table for every node of dotta's a landing removes beside its row's
 * own occupant: its node above a row, which the first act beneath it replaces,
 * and a copy beneath a blob row, which that row's landing clears (core/workspace.h
 * workspace_state_t: OBSTRUCTING, OVERRIDDEN). Pure in the item the load made,
 * so --force is each reader's to apply. Its rule is two facts about every path:
 * a landing removes a node dotta keeps any record of, and bytes Git may lack
 * only under --force.
 *
 *   no item — a stranger's — or one no landing   REFUSED      no flag lifts it
 *   removes: a scope exit's orphan, another node where dotta's stood, a stale
 *   key, a row
 *   a landing's, its look failed                 UNREADABLE   no flag lifts it:
 *                                                             nothing says what
 *                                                             an unlink would meet
 *   a landing's directory                        OK           it holds no bytes;
 *                                                             what it holds is
 *                                                             judged entry by entry
 *   a landing's file or link as dotta            OK           its bytes are Git's
 *   confirmed it (core/workspace.h workspace_untouched)
 *   a landing's file or link otherwise           NEEDS_FORCE  edited, never
 *                                                             confirmed, or a
 *                                                             read that failed:
 *                                                             bytes Git may lack
 *
 * A node meets the last two cells alone — it stands as its record's kind, a file
 * or a link (core/workspace.c workspace_obstructs) — a copy any of the last four,
 * and an entry a clearance's walk meets any of the five. A scope exit's orphan
 * is read by another table, cleanup's (core/cleanup.h cleanup_skip_reason), whose
 * reasons are the copy's where these are the user's order to land: the two stay
 * two, and the state says which reads an orphan.
 *
 * Readers: core/deploy.c vouch_clearance (each entry a clearance's walk meets)
 * and deploy_preflight (dotta's node above a row, its consent), cmds/apply.c
 * apply_print_deploy_preview (the nodes' and the copies' discards). A reader
 * not on this list is a bug.
 */
typedef enum {
    DEPLOY_CLEARANCE_OK,            /* Unasked: dotta's copy as it confirmed it, or a directory */
    DEPLOY_CLEARANCE_NEEDS_FORCE,   /* --force's: dotta's file or link, edited, never confirmed, or unread */
    DEPLOY_CLEARANCE_UNREADABLE,    /* No flag's: dotta's, but its look failed */
    DEPLOY_CLEARANCE_REFUSED        /* No flag's: nothing of dotta's a landing removes */
} deploy_clearance_t;

static inline deploy_clearance_t deploy_clearance(const workspace_item_t *item) {
    if (!item) return DEPLOY_CLEARANCE_REFUSED;

    switch (item->state) {
        case WORKSPACE_STATE_OBSTRUCTING:
        case WORKSPACE_STATE_OVERRIDDEN:
            /* A landing's: by its look, then its kind, then its bytes */
            if (item->occupant == FS_OCCUPANT_UNKNOWN) return DEPLOY_CLEARANCE_UNREADABLE;
            if (item->occupant == FS_OCCUPANT_DIRECTORY) return DEPLOY_CLEARANCE_OK;
            return workspace_untouched(item) ? DEPLOY_CLEARANCE_OK : DEPLOY_CLEARANCE_NEEDS_FORCE;

        case WORKSPACE_STATE_DEPLOYED:
        case WORKSPACE_STATE_UNDEPLOYED:
        case WORKSPACE_STATE_DELETED:
        case WORKSPACE_STATE_ORPHANED:
        case WORKSPACE_STATE_UNTRACKED:
        case WORKSPACE_STATE_UNSCANNED:
        case WORKSPACE_STATE_RELEASED:
            /* An active row, a scan's item, a scope exit's orphan — another node
             * where dotta's stood, a stale key among them: no landing's */
            return DEPLOY_CLEARANCE_REFUSED;
    }

    CHECK_ARG(false, "a state no enumerator names");
}

/**
 * Why a planned row is not deployed this run
 *
 * The counterpart of cleanup_skip_reason_t, and the same contract: values are
 * listed in precedence order, and the reason is the first that applies, so a
 * row several reasons claim is reported under the one that outranks the rest.
 *
 * Two classes, and the class is the whole of what a consumer needs beyond the
 * label (deploy_skip_needs_force):
 *
 *   consent      dotta could act and did not, because nothing said to —
 *                TYPE, CONTENT. --force lifts them; the run kept its promise,
 *                so they do not reach the exit code.
 *   incapacity   dotta could not act — PERMISSION, FOREIGN, ANCESTOR,
 *                OCCUPIED, UNREADABLE, OWNERSHIP. No flag lifts them (the posture
 *                cleanup takes towards a released file and a directory's
 *                UNVERIFIED); the run planned the row and did not deliver it,
 *                so the exit code says so. Three of them are the invoker's refusals
 *                and root's to lift — PERMISSION, FOREIGN, OWNERSHIP — and a
 *                run that holds none closes its skips by naming it (apply's sudo
 *                line); one that holds root meets none of them, save a PERMISSION
 *                where the bits deny root as well (a MAC policy, an NFS export
 *                that squashes root). What refuses every identity — a read-only
 *                filesystem, an immutable flag — is no skip: the write meets it.
 *
 * The split is deploy's exit contract, and workspace_item_route's UNVERIFIABLE
 * arm (workspace.h) restates its incapacity half from the route side — a change
 * here keeps that description true. cleanup_receipt_t draws the same table from
 * its side, with a third column between these two — attempted, and the world
 * moved — where the engines part: deploy's execute-time refusal (EEXIST, EISDIR,
 * ENOTEMPTY) is a failed row, cleanup's a skipped directory, and both headers
 * say why.
 *
 * Precedence. ANCESTOR ranks first: a look taken through a squatted claimed
 * ancestor is void, so no judgment made through it can outrank the fact — the
 * ancestry rung (check_ancestry) asks it before any probe of the row's own, the
 * landing check included, whose access(2) resolves through a squatting symlink
 * and answers for the target's tree. The reason spans both producers: a squatter
 * at a path no row claims is the landing check's find, one at a directory row's
 * is the rung's — and, since the rung's reach is the view's directory rows rather
 * than the walk's, whether it is the rung that answers no longer depends on how
 * the user spelled the add. The two producers stay one reason and one exit
 * contribution; what a consumer may tell apart is the claim that holds the
 * squatter, which the skip carries (deploy_ancestry_t) — the remedy differs by
 * claimant where the refusal does not. And why UNREADABLE ranks after every path
 * rung where its siblings (cleanup_skip_reason, workspace_item_route) rank the
 * same fact first: the landing check, when it has something to say, names the
 * ancestry that refused the look — the actionable half of the very same fact.
 * UNREADABLE is what is left when the landing had nothing to say. FOREIGN is
 * the landing's twin for a directory already there: a create or a replace lands
 * a new entry through its parent, which PERMISSION asks, where a fix converges
 * the node in place through a descriptor opened for reading, which only a run
 * that may hold it can do — the node's owner, or root, its read granted
 * (core/deploy.c holdable) — so a row takes one question or the other, never
 * both, and FOREIGN stands beside PERMISSION. OWNERSHIP ranks last of all, an
 * incapacity behind the consent reasons, because it is the row's rung and not
 * the path's: the ownership is resolved for a row every other rung passed (a
 * skipped row can neither warn nor fail strict_ownership — deploy_preflight's
 * invariant), so the question is never asked of a row another reason already
 * holds, and its place in the order is the place the decision takes. Save where
 * it names an ancestor: a pending directory row on the way that this run skipped
 * for its pair, nothing standing there as the run will find it, is the ancestry
 * rung's to answer, before any probe of the row's own (check_ancestry) — no
 * directory will stand there, so no rung beneath it can say more, and the remedy
 * is that pair's.
 *
 * The clearance answers at the type rung, for a blob row whose occupant is a
 * directory (core/deploy.c check_clearance), and three reasons are its stops:
 * OCCUPIED where an entry is no landing's to remove, UNREADABLE where an entry
 * could not be looked at or a directory it walks could not be read, PERMISSION
 * where a directory it would empty denies the run the removals in it. And TYPE
 * is its edit, a copy only --force removes. The walk goes on past an edit and
 * ends at a stop, so a stop outranks every edit wherever readdir met each, whatever
 * their order here — one cause a skip, and the next run names the next
 * (deploy_blocker_t).
 *
 * Each reason is a sentence about the row that carries it, read off that skip's
 * own fields (cmds/apply.c apply_print_deploy_skips): the ancestor it names
 * (PERMISSION, ANCESTOR, a TYPE or an OWNERSHIP that names one), the path a
 * clearance names at the row's path or beneath it (OCCUPIED, a clearance's
 * PERMISSION and UNREADABLE, and a TYPE its edit holds back), its own occupant
 * (TYPE), its own item (CONTENT, UNREADABLE, and FOREIGN, the owner its look
 * found — another, or the run itself, its read refused — and a PERMISSION that
 * names its landing, the bit that refused: the search where the row's own look
 * was refused beneath it, else the write), its own claim (an OWNERSHIP that names
 * none). So a row beneath a skipped squatter takes the squatter's class and never
 * its reason (check_ancestry): the squatter's sentence is about the squatter,
 * whatever reason a later rung adds. A row beneath an absent directory skipped
 * for its pair takes OWNERSHIP all the same, read as a sentence about its own
 * way — that directory named, which needs root to create — and never about the
 * directory's claim, which the directory's own line says.
 *
 * Dotta's node above rows of the run takes a skip of its own where the run keeps
 * it, with no row: two of the reasons, in their order — PERMISSION where its
 * parent denies the run the unlink and the create in its place (the landing check,
 * asked of the node's own path), TYPE where nothing but --force consents to
 * replacing it (deploy_clearance) — each a sentence about the node, its own item
 * read for the second. A row beneath it takes its class, as beneath any skipped
 * squatter.
 *
 * Symlink rows need no arm of their own: a foreign kind at a link row's path is
 * TYPE (deploy.c occupant_conflicts), a retargeted link is CONTENT (the target
 * compare), and the undecryptable arm of UNREADABLE cannot fire for one (a link's
 * bytes are its target, never a seal: infra/content.h).
 */
typedef enum {
    DEPLOY_SKIP_NONE = 0,     /* Not skipped — the row has a verdict */
    DEPLOY_SKIP_ANCESTOR,     /* A non-directory squats an ancestor this run does not converge */
    DEPLOY_SKIP_PERMISSION,   /* The landing's bits deny the run: an ancestor not ours, or none reachable */
    DEPLOY_SKIP_FOREIGN,      /* The directory at the path is another's, or its bits deny the run the read */
    DEPLOY_SKIP_OCCUPIED,     /* A directory holding what no landing may remove stands at the path */
    DEPLOY_SKIP_TYPE,         /* A different kind of path stands where the row lands (--force) */
    DEPLOY_SKIP_CONTENT,      /* Disk holds content dotta did not put there (--force) */
    DEPLOY_SKIP_UNREADABLE,   /* The path could not be read: no verdict, no guess */
    DEPLOY_SKIP_OWNERSHIP     /* A pair this run cannot set, the row's or its way's (no root held) */
} deploy_skip_reason_t;

/**
 * Is --force the remedy for this skip?
 *
 * The consent/incapacity split, as a value. "Needs force" is the module's own
 * word (DEPLOY_CLEARANCE_NEEDS_FORCE) and the screen's ("Use --force to overwrite
 * or replace them"). Total over the reasons, so a new one is classed here or
 * the build fails.
 *
 * Readers: cmds/apply.c apply_print_deploy_skips (the block's level and each
 * row's, and the --force line) and cmd_apply (the exit, which counts the
 * incapacities), and core/deploy.c check_ancestry (the class a row beneath a
 * skipped squatter takes). A reader not on this list is a bug.
 */
static inline bool deploy_skip_needs_force(deploy_skip_reason_t reason) {
    switch (reason) {
        case DEPLOY_SKIP_TYPE:
        case DEPLOY_SKIP_CONTENT:    return true;
        case DEPLOY_SKIP_ANCESTOR:
        case DEPLOY_SKIP_PERMISSION:
        case DEPLOY_SKIP_FOREIGN:
        case DEPLOY_SKIP_OCCUPIED:
        case DEPLOY_SKIP_UNREADABLE:
        case DEPLOY_SKIP_OWNERSHIP:  return false;
        case DEPLOY_SKIP_NONE:       break;
    }

    CHECK_ARG(false, "a skip is classed by its reason");
}

/**
 * The claim standing at the squatted ancestor an ANCESTOR skip names
 *
 * One reason, one exit — but the remedy is the claimant's. A row a plan holds,
 * out of the run's reach, is planned by a wider scope, which then replaces the
 * squatter: a tracked row's under --force, and dotta's own copy at a rung, Git
 * having moved past it (promoted, deploy_plan_build), unasked where the copy is
 * untouched. An ancestor claim the user's own squatter holds is never planned,
 * so no scope and no flag helps: the consent-preserving cure is the named
 * re-derivation ('dotta update <dir>'), which drops a claim the disk contradicts
 * and leaves the arrangement the user's. A squatter nothing claims is the landing
 * check's find past the rung: by hand is all there is. A record that alone
 * remembers a directory there is no claim on a planned row at all (the reach
 * rule, core/workspace.h): the rung never names it, the landing check meets what
 * stands there on its own terms, and apply's own cleanup releases the record in
 * the same run. And dotta's own file or link above a row is the landing's, never
 * a squatter the run has no fate for: the plan holds it wherever a row of the
 * run lies beneath it (deploy_plan_t's nodes), and preflight replaces it, the
 * row then planned absent, or keeps it with a skip of its own, whose class the
 * row takes — so there is no fourth ancestry.
 *
 * Written where the reason is decided. TRACKED and DERIVED by the ancestry rung
 * (check_ancestry), off the claim the load noted beside the squatter
 * (core/workspace.h workspace_squatted_t) — the claim every path beneath it carries
 * as its displaced class, so the remedy here and status's Displaced paths section
 * cannot name two claimants for one squatter: DERIVED where the user's own squatter
 * holds an ancestor claim, TRACKED for every other view claim; UNCLAIMED by the
 * landing check (check_landing), the one ancestry it can find. Read by cmds/apply.c
 * apply_print_deploy_skips, whose remedies part on it.
 *
 * The ancestry answers for ANCESTOR, where the reason is one and the cure is
 * not — and only where the skip is the squatter's only report: a squatter this
 * run never reached, or one nothing claims. NONE everywhere else: on every skip
 * whose reason is another, and on a row beneath a squatter this run planned and
 * skipped, which reads ANCESTOR and names it but whose remedy is that squatter's
 * own skip, listed above the row — TRACKED's line, a wider scope, is false of a
 * squatter already in it.
 */
typedef enum {
    DEPLOY_ANCESTRY_NONE = 0,  /* Another reason, or a squatter with a skip of its own */
    DEPLOY_ANCESTRY_TRACKED,   /* A row a plan holds stands there: tracked, or promoted */
    DEPLOY_ANCESTRY_DERIVED,   /* An ancestor claim the user's own squatter holds */
    DEPLOY_ANCESTRY_UNCLAIMED  /* Nothing claims it — the landing check's find */
} deploy_ancestry_t;

/**
 * Where a clearance stopped, or its first edit — the path a skip names at its
 * row's path or beneath it
 *
 * A blob row's clearance walks everything beneath its path (core/deploy.c
 * check_clearance) and stops at what its landing may not remove, --force included:
 * an entry no landing's (OCCUPIED), one it could not look at or a directory it
 * could not read (UNREADABLE), a directory whose bits deny the run the removals
 * in it (PERMISSION) — the occupant at the row's own path among them. Or it goes
 * on past a copy only --force removes, the first of which is its edit (TYPE).
 * The path is a stop's, the walk's copy of it, or the edit's own; the item the
 * edit's alone, whose bits say why only --force removes it; the fault an UNREADABLE
 * stop's, classed off the bits at the path when the walk stopped (sys/filesystem.h
 * fs_denied: UNREADABLE where they refused this identity, UNVERIFIED for any
 * other failure), so no engine reads a load's fault. A stop outranks every edit
 * (deploy_skip_reason_t), and one cause rides a skip: the first stop in readdir's
 * order, else the first edit — the next run names the next (stated).
 *
 * Read by cmds/apply.c apply_print_deploy_skips: the path on the row's line,
 * the item for the edit's word and the closer its failed read takes, the fault
 * for the sudo closer. A reader not on this list is a bug.
 */
typedef struct {
    const char *path;                /* A stop's (the walk's copy) or the edit's; NULL: none */
    const workspace_item_t *item;    /* The edit's (TYPE); NULL on a stop */
    workspace_fault_t fault;         /* An UNREADABLE stop's, off the bits at the path; NONE elsewhere */
} deploy_blocker_t;

/**
 * One planned row the run does not deploy — or dotta's node above rows of the
 * run that the run keeps
 *
 * The shape deploy_verdict_t gives a row the run does deploy: the row's item,
 * and the facts decided about it — a node's item, an orphan's, carrying no row
 * (deploy_skip_reason_t: its two reasons). `ancestor` is the path the reason
 * names — the ancestor that refused, the non-directory in the way, the squatted
 * directory above the row, the absent directory on its way only root can create
 * as claimed. Every such path is an ancestor of the row's own, and so a prefix
 * of the item's filesystem_path by construction (check_landing truncates the
 * planned path; a squatted directory stands strictly above every row that names
 * it, and the load lends its length with it — core/workspace.h
 * workspace_squatted_t; an absent directory is a row the walk decided above the
 * path) — carried as the byte length of that prefix, not a copy. 0 where the
 * reason has no ancestor to name: it is about the planned path itself (OWNERSHIP
 * is, save beneath an absent directory skipped for its pair), or (PERMISSION
 * alone) the ancestry could not even be reached to name its refusing node.
 * `ancestry` says which claim holds the named path where the skip is the squatter's
 * only report — ANCESTOR's alone, and NONE on a row beneath a skipped squatter
 * (deploy_ancestry_t). `blocker` is the path a clearance names at the row's path
 * or beneath it — where its walk stopped, or the first copy only --force removes
 * (deploy_blocker_t) — and none on every skip the walk did not write.
 *
 * The item is the verdict's: the one the row's bucket holds, or the node the
 * plan holds, and never NULL (deploy_verdict_t). Whether it holds a look is the
 * row's ancestry's to say — a node's is always its own — and the item says so
 * itself: a row its ancestry answered for — beneath a squatter that stays, or
 * planned absent and then refused by the row's rung — carries an item nothing
 * looked at, occupant UNKNOWN and no path bit (the displaced class every reader
 * of an item reads, core/workspace.h workspace_displaced_t), never a blanked
 * pointer. So a reader consults the look only where the reason is a sentence
 * about it — a CONTENT skip's route, an UNREADABLE skip's fault, a FOREIGN skip's
 * owner, the bit a landing's PERMISSION names: path rungs, asked only where the
 * ancestry did not answer. OWNERSHIP reads its claim off the row and never the
 * item's look, which a row planned absent does not have — or, where it names an
 * ancestor, the ancestry rung's answer, nothing of the row but its path.
 *
 * Nothing here is owned: the item is borrowed (workspace lifetime), as every
 * item and row in this module is.
 */
typedef struct {
    const workspace_item_t *item;    /* Borrowed (workspace lifetime), as the verdict's — never NULL */
    deploy_skip_reason_t reason;
    size_t ancestor;                 /* Prefix length of the named ancestor; 0 = none */
    deploy_ancestry_t ancestry;      /* ANCESTOR only: the claim at a squatter with no skip of its own */
    deploy_blocker_t blocker;        /* A clearance's stop or first edit, at or beneath the path; none elsewhere */
} deploy_skip_t;

/**
 * A skip array with its count — the shape deploy_verdicts_t gives verdicts
 */
typedef struct {
    deploy_skip_t *entries;
    size_t count;
} deploy_skips_t;

/**
 * Preflight: the skips, the anomalies, and the verdicts
 *
 * The verdicts are the *how*, one per row the run WILL deploy, each kind in path
 * order — the order deploy_execute acts in within a kind, the directories first,
 * parents before the paths beneath them — and then the ancestors: the directory
 * rows outside the plan that the run may create on the way to a planned path —
 * either class, since the plan holds the tracked ones and the ancestors pass is
 * where a derived claim is acted on, save one the plan promoted (see
 * deploy_plan_build, deploy_preflight).
 *
 * Beside them, what of dotta's own the landings remove on their way — the run's,
 * never a verdict's (deploy_verdict_t): its nodes above rows (replaces), each
 * replaced by the first act beneath it that lands; and its copies beneath blob
 * rows (clears), each cleared by the file row above it — a directory row's squatter
 * is never a directory, so no clearance walks one — every row's together and
 * deepest first, so a directory goes once everything in it has. The act whose
 * way meets each finds it by position (core/deploy.c replace_node above its path,
 * clear_copies beneath it), and the preview and the prompt count each kind off
 * its own list.
 *
 * A consumer reads every array by its count, so none needs a NULL guard: an empty
 * one may hold no spine at all. A value of the arena it was decided in, as every
 * array it holds is: nothing frees one.
 */
typedef struct {
    /* The rows the run does not deploy, both kinds, in path order, the order
     * they are decided in: a squatted directory therefore precedes the rows beneath
     * it — and dotta's nodes the run keeps, each before the rows beneath it.
     * With the verdicts and the nodes replaced below this is a partition of the
     * plan's pending rows and of its nodes:
     *
     *   files.pending ∪ directories.pending = verdicts(files ∪ directories) ∪
     *       skipped's rows
     *   nodes = replaces ∪ skipped's nodes ∪ the nodes every row beneath which
     *       was skipped, which stand as they are
     *
     * — deploy's own totality equations, the counterpart of cleanup.h's. */
    deploy_skips_t skipped;

    /* The directory rows among them that nothing will stand at as the run finds
     * them: skipped for a pair, absent at the load or planned absent beneath a
     * squatter the run replaces — each a skip's item, in path order. No directory
     * will stand at one, so every row decided beneath it is skipped naming it.
     * Read by the ancestry rung alone (core/deploy.c check_ancestry); empty on
     * every healthy run. */
    ptr_array_t skipped_absent;

    /* Anomalies met while deciding — the run goes on; the caller prints them.
     * Only rows the run will touch contribute: a skipped row's ownership is not
     * resolved, so it can neither warn nor fail strict_ownership. */
    string_array_t warnings;

    /* The how — one per row the run WILL deploy */
    deploy_verdicts_t directories;       /* Pending directory rows, parents first */
    deploy_verdicts_t files;             /* Pending file rows */
    deploy_verdicts_t ancestors;         /* Directory rows the run may create on the way */
    workspace_items_t replaces;          /* Dotta's nodes the run replaces, path order, on their rows' way */
    workspace_items_t clears;            /* Dotta's copies the run clears, each row's deepest first */
} deploy_preflight_t;

/**
 * One kind's partition of the active items in scope
 *
 * Every file item and every tracked directory item that passes the scope's profile
 * and path dimensions lands in exactly one bucket, or nowhere: one that is both
 * clean and excluded enters none (neither work nor apply's to own). Out-of-scope
 * items are invisible, and so is an ancestor claim, which is no convergence of
 * the run's — the plan drops it before scope (deploy_plan_build) — save one dotta's
 * own copy squats, the view having moved past it, which the plan holds as it
 * holds a tracked row: promoted, and always work.
 *
 * Three buckets carry work the run deliberately does not do. They differ by reason,
 * and the reason is the only thing a consumer needs from them — so the bucket
 * an item sits in *is* its reason tag, and a path -e names is reported as excluded
 * even when another reason would also skip it — --skip-existing, or a landing's
 * orphan in its way a flag keeps (a named path is the more explicit intent).
 *
 * Each bucket is a slice of the items it holds, filled once the plan has decided
 * every item (core/workspace.h workspace_buckets_t): deploy.c deploy_classify
 * names the bucket for each, and nothing else adds to one. The items are borrowed
 * (workspace lifetime — arena-allocated, their addresses stable by construction),
 * each bucket's array the plan's arena's.
 */
typedef struct {
    workspace_items_t pending;    /* Need work — deploy_preflight decides how, deploy_execute acts */
    workspace_items_t clean;      /* In scope, no work — apply's to adopt or acknowledge */
    workspace_items_t excluded;   /* Need work, skipped by -e — reported, never touched */

    /* Need work, skipped by --skip-existing: something already occupies the path.
     * Files only. A tracked directory row writes no data — it creates a container
     * and converges its metadata in place — so skipping one would preserve nothing
     * and would instead strand the tracked children the flag exists to deploy.
     * Its one destructive act, replacing a squatter, is force-gated at preflight
     * already, save over dotta's own untouched copy, which loses nothing. */
    workspace_items_t skipped_existing;

    /* Need work, skipped because a landing's orphan in the row's way stays —
     * dotta's node above it, or a copy beneath it where the row is a blob: -e
     * names it, or --keep-orphans keeps it (deploy_ceded_t), and the row lands
     * only with every removal its way needs. Never existing too where a node
     * stands above: a row beneath a node was never looked at, so nothing occupies
     * its path for --skip-existing to keep. */
    workspace_items_t skipped_kept;
} deploy_partition_t;

/**
 * The landing's orphans in scope that no landing of this run removes, by why
 *
 * Dotta's nodes above rows and the copies beneath blob rows alike. Counted for
 * a path filter's match (deploy_plan_item_count), reported where a flag of the
 * user's spared one (cmds/apply.c apply_print_withheld), never touched. One a
 * flag spares keeps the row in its way from landing (deploy_partition_t's
 * skipped_kept), and the rest of that row's way waits with it; one no row of
 * the run reaches waits for a run that lands one.
 */
typedef struct {
    workspace_items_t excluded;    /* -e names it */
    workspace_items_t kept;        /* --keep-orphans keeps it */
    workspace_items_t unreached;   /* In scope, no row of the run in its way: it waits for a run with one */
} deploy_ceded_t;

/**
 * Deployment plan — deploy's classification of the active items in scope, one
 * partition per kind, and of the landing's orphans: dotta's own nodes above rows
 * of the view (core/workspace.h WORKSPACE_STATE_OBSTRUCTING), each replaced by
 * the first act beneath it, and the copies beneath blob rows (OVERRIDDEN), each
 * cleared by its row's landing — no bucket's where a row of the run reaches it,
 * that row's clearance deciding it at preflight (deploy_preflight_t's clears),
 * or the row's own skip keeping it. A value of the arena it was built in: nothing
 * frees one.
 *
 * Both kinds' items arrive ordered by filesystem_path (workspace_directories,
 * workspace_files), so within each kind's pending a row precedes every path beneath
 * it. Two consumers lean on that: preflight merges the two into one path order
 * and decides every row after its ancestors' fates, of either kind (the ancestry
 * rung and the landing read them), and the execute loop converges a parent before
 * the paths beneath it — which is what lets a replaced directory settle its subtree
 * for the rows that follow (see deploy_preflight, deploy_execute).
 *
 * The nodes are what preflight's walk trusts, in its order: path order, the
 * outermost alone — a node beneath another was never looked at, so is none —
 * each with a pending row beneath it, and never at a row's path, a record being
 * an orphan exactly where no row stands. So the walk decides each node before
 * the first row that sorts after it, and none is left when the rows are.
 */
typedef struct {
    deploy_partition_t files;         /* The file items */
    deploy_partition_t directories;   /* The tracked directory items, and promoted rungs */
    workspace_items_t nodes;          /* Dotta's nodes above rows of the run, to replace */
    deploy_ceded_t ceded;             /* The landing's orphans in scope this run leaves standing, by why */
} deploy_plan_t;

/**
 * One verdict's outcome — the act's stat where it landed, the cause where it
 * did not
 *
 * The stat is the record's own triple (state_stat_from_write), distilled by the
 * executor from the fstat of the descriptor it wrote — taken after the last byte
 * and before the rename that publishes it, so it describes exactly what this
 * run wrote, never what a later look at the path would find. It is what lets
 * apply's record phase anchor a deployment with the write's own stat instead of
 * leaving the record blob-only.
 *
 * UNSET where the act authored no stat — the executor's fact, not a consumer's
 * re-derivation: a symlink is created by path (symlink(2) opens no descriptor
 * to describe, and readlink is its whole re-verification), and a directory's
 * write is fchmod/fchown through its own descriptor, whose record carries no
 * triple at all. The record phase passes the triple blind: an ownership event
 * writes UNSET as no stat (core/workspace.h workspace_anchor).
 *
 * The error is the failed bucket's tail — the row's own cause, verbatim (ENOSPC,
 * a blob that would not load, an ancestor this run did not converge or create)
 * — and NULL in every landed bucket: the bucket is the tag, as UNSET already is
 * for the stat. A failure has a dozen causes and the remedy differs by cause,
 * so the receipt keeps each for the caller to render, as cleanup's does
 * (cleanup_outcome_t). Borrowed, as every error is (base/error.h).
 *
 * The verdict is borrowed from the preflight, whose arrays are sized once and
 * never reallocated, so every address is stable for the receipt's life — which
 * is no longer than the preflight's (deploy_receipt_t).
 */
typedef struct {
    const deploy_verdict_t *verdict;   /* Borrowed (the preflight's lifetime) */
    state_stat_t stat;                 /* The write's stat; UNSET where it authored none */
    error_t error;                     /* The failed bucket's cause; NULL elsewhere (borrowed) */
} deploy_outcome_t;

/**
 * An outcome array with its count — the shape deploy_verdicts_t gives verdicts
 */
typedef struct {
    deploy_outcome_t *entries;
    size_t count;
} deploy_outcomes_t;

/**
 * The mode a held directory carries while the run writes beneath it
 *
 * The mode the release owes it with the owner triad forced on. Everything the
 * run lands beneath a directory lands through the owner's own write and search
 * bits — mkdir for a child directory, a temporary created and renamed over its
 * path for a file or a link — so a recorded mode that lacks them (0555, 0500, a
 * 0600 captured on a directory the walker could not enter) would refuse the very
 * children it was captured with. Two phases instead: materialize at the working
 * mode, write the subtree, then release each held directory to its exact mode,
 * deepest-first (deploy_hold_t). Group and other bits are never widened — a 0700
 * directory is 0700 throughout — and the window is the owner's own, from the
 * act that takes the hold to the caller's release (deploy_release), which follows
 * every act beneath it, another engine's included; a run killed inside the window
 * leaves the directory at its working mode. cmd_export materializes a profile
 * the same way (export.c, materialize_entries); this is the same rule on the
 * other materializer.
 *
 * One producer, read in two files: core/deploy.c — each hold's mode
 * (materialize_directory, create_ancestor, open_landing_directory), and whether
 * a directory needs a hold at all (hold_directory) — and cmds/apply.c, for a
 * hold the release could not let go: the mode it was left at
 * (apply_print_deploy_receipt) and the mode its record learns (apply_write_record).
 * A reader not on this list is a bug.
 */
static inline mode_t deploy_working_mode(mode_t mode) {
    return mode | S_IRWXU;
}

/**
 * One directory the run holds at its working mode — on the receipt, one the run
 * took, or one the release could not let go
 *
 * A hold carries a directory at deploy_working_mode while the acts land beneath
 * it, and the release narrows it back to `mode` once they are done, the caller's
 * other acts included, deepest first (deploy_release). The run takes one for a
 * directory it creates or converges — a planned row, or a claimed ancestor created
 * on the way — owing its row's mode, and one for a claimed directory a write
 * must land in whose bits deny the run, owing the mode it had; and only where
 * the working mode would widen what is owed. Each is a directory row of the view,
 * either class, so each has its item. In this module "hold" means only this.
 *
 * On the receipt a hold sits in one of two arrays, the array its tag, as the
 * failed bucket is deploy_outcome_t's: `taken`, every hold the run took, `error`
 * NULL — the directory at its working mode until the release; `held`, one the
 * release could not let go — the directory stands at deploy_working_mode(mode),
 * or the release could not reach it — `error` the release's refusal, verbatim.
 */
typedef struct {
    const workspace_item_t *item;   /* Borrowed (workspace lifetime): the directory's, never NULL */
    mode_t mode;                    /* The exact mode the release owes it */
    error_t error;                  /* On held, the release's refusal; NULL on taken (borrowed) */
} deploy_hold_t;

/**
 * A hold array with its count — the shape deploy_outcomes_t gives outcomes
 */
typedef struct {
    deploy_hold_t *entries;
    size_t count;
} deploy_holds_t;

/**
 * Deployment receipt — the run's: one outcome per verdict, in act order, the
 * nodes and the copies of dotta's its landings removed, and the holds: every
 * one the run took, and each the release could not let go
 *
 * Four outcome arrays: three mirroring the preflight's split for the rows that
 * landed, and `failed` for the rows that did not — landed or failed is the one
 * split execute itself takes, so execute buckets it; everything else the receipt
 * restates rather than re-decides. The verb inside a landed array is derived,
 * never stored twice — a directory's is its verdict's occupant (the mapping is
 * deploy_convergence's), so the caller can still say "replaced" where a squatter
 * went and "fixed" where nothing was created. Work the run deliberately did not
 * do is the plan's to report, never the receipt's — the plan decided it, so only
 * the plan can report it before a run that ends up executing nothing. A failure
 * is a row's own outcome: it lands in `failed` with its cause, the run goes on,
 * and the caller's exit contract reads the count; nothing is returned beside
 * the receipt (deploy_execute).
 *
 * With `failed` the receipt partitions the promise — execute's totality equation,
 * the mirror of preflight's:
 *
 *   verdicts(directories ∪ files) = converged ∪ deployed ∪ failed
 *
 * — every promised row accounted for, however the rows fared. The ancestors stay
 * outside it, as they stand outside the plan.
 *
 * The promise's arrays are sized to their verdicts at entry (calloc), `failed`
 * to both kinds together (every promised row could fail), and all three fill in
 * verdict order; count gates every read, so an untaken slot is invisible and
 * the receipt holds exactly what happened, by construction.
 *
 * The derived verb is also the ownership gate apply's record phase reads: a
 * converged directory whose convergence is not a fix was created by dotta and
 * anchors as owned; one converged in place was not — anchoring it would set
 * deployed_at on a directory the user created, and hand it to the prune on the
 * next scope exit.
 *
 * `ancestors` is outside the plan: the claimed directories the run created as
 * parents of a planned path (create_ancestor), each once, either class, in the
 * order created — the run's own list, handed to the receipt whole as execute
 * returns, as `taken` is. They carry their recorded mode and ownership like any
 * other directory row, and dotta created them — so the record phase anchors them
 * as owned, the same event as a created directory — but the plan never named
 * them and the preview never counted them, so the caller's summary keeps them
 * apart from the created count. A parent no row claims has no receipt and no
 * record.
 *
 * `replaced` and `cleared` are outside the plan too: what of dotta's own the
 * landings removed, each by its own act, in act order — the run's own lists,
 * handed to the receipt whole as execute returns, as `ancestors` is, the outcomes
 * of the preflight's two (deploy_preflight_t's replaces, clears). `replaced`
 * holds dotta's nodes the way replaced, each unlinked with a directory standing
 * in its place; `cleared` the copies the clearances took, each removed on its
 * row's way. The record phase retires each one's record, and a node's takes with
 * it the record of every row beneath it, which a capture through the node wrote
 * and no look did (cmds/apply.c apply_write_record) — no row stands beneath a
 * copy. A replace stopped short — its way refused, its unlink, or the create in
 * its place — is on neither: the act that met it carries its cause, and every
 * later act beneath it fails naming the node (deploy_execute); and a copy is on
 * `cleared` once its own removal has landed, whatever its row does after.
 *
 * `taken` and `held` are the holds' (deploy_hold_t). `taken` is execute's: every
 * hold the run took, in the order taken, each directory still at its working
 * mode when execute returns — the release's to let go, and read by it alone
 * (deploy_release). `held` is the release's: the holds it could not let go, in
 * the order released — deepest first — each with its cause. Every hold taken is
 * released to its exact mode or is held, the release's own totality beside
 * execute's above:
 *
 *   taken = released ∪ held
 *
 * A held directory's act stands where it landed — on converged, on ancestors,
 * or on no array for a landing opened for a write beneath it — and only its exact
 * mode did not. Outside the promise, as the ancestors are; the exit contract
 * counts each with the rows the run could not land (cmds/apply.c cmd_apply), a
 * path the run leaves off its claim, and the screen names it a directory left
 * wide (cmds/apply.c apply_print_deploy_receipt). Each is handed to the receipt
 * whole by the pass that builds it, as that pass's last act: taken by execute,
 * the run's own list; held by the release, sized to taken — every hold could be
 * refused — and filled in the order released.
 *
 * A value of the arena its run was handed, as its arrays are: nothing frees one.
 * Its outcomes borrow the verdicts, so a receipt lives in the arena they were
 * decided in, or in one they outlive.
 */
typedef struct {
    deploy_outcomes_t deployed;      /* Files written or linked, each with its write's stat */
    deploy_outcomes_t converged;     /* Planned directories — the verb is the verdict's occupant */
    deploy_outcomes_t ancestors;     /* Claimed directories created on the way, each once */
    workspace_items_t replaced;      /* Dotta's nodes the way replaced — their records retire */
    workspace_items_t cleared;       /* Dotta's copies the clearances took — their records retire */
    deploy_outcomes_t failed;        /* Rows that did not land — both kinds, each with its cause */
    deploy_holds_t taken;            /* Every hold the run took, in the order taken — the release's to let go */
    deploy_holds_t held;             /* Holds the release could not let go, each with its cause */
} deploy_receipt_t;

/**
 * Build the deployment plan
 *
 * Walks the workspace's orphans for the landing's (workspace_orphans, by the
 * switch every engine reads them with: OBSTRUCTING, OVERRIDDEN), then its directory
 * items and file items once — a directory where its profile tracks it, an ancestor
 * claim being no convergence of the run's save where dotta's own copy squats
 * it, Git having moved past that copy (STALE: the squatter is Git's pending move,
 * which the run converges — promoted, a replace) — gating each on
 * scope_accepts_profile ∧ scope_accepts_path(kind), then classifying it by deploy's
 * work predicate (missing, or diverged in content / mode / ownership / type /
 * stale) and by the reasons its work is skipped: scope_is_excluded(kind), then
 * a landing's orphan in its way a flag spares, then skip_existing. Every item
 * was analyzed — neither kind is a load's to decline (workspace_load) — so a
 * clean one is a path the load looked at and found agreeing.
 *
 * A path beneath a squatted directory needs no rule of the plan's own: the
 * workspace looked at nothing there, so the row's item carries the displaced
 * class and no path bit (core/workspace.h workspace_displaced_t), and the work
 * predicate reads that class first (deploy_needs_work). Such a row is work, and
 * not occupied for --skip-existing's purpose; -e still excludes it. What becomes
 * of it is preflight's alone, asked of this run's own fates rather than guessed
 * from scope: the directory pass converges the ancestor and the row is written
 * fresh beneath it, or the pass does not and the row is skipped with it, in the
 * ancestor's class (check_ancestry, deploy_preflight). Scope still bounds the
 * plan in the ordinary way — a row scope rejects (-p, a path filter) is not planned
 * on its ancestor's account, Coherent Scope, and converges on the next apply
 * that covers it.
 *
 * A landing's orphan is the plan's where a row of the run needs its place — in
 * scope, -e naming the row not — whatever the orphan's own scope: dotta's node
 * above rows is the landing's of every row beneath it, so a -p naming their profile
 * reaches another profile's node (the landing's reach above), and a copy beneath
 * a blob row is that row's landing's, whoever's copy it is. A node a row reaches
 * is the plan's to replace (nodes); a copy a row reaches is no bucket's, that
 * row's clearance deciding it at preflight, or the row's own skip keeping it.
 * One in scope that no row reaches waits for a run that lands one (unreached),
 * counted for a path filter's match. The user's word spares one, and with it
 * the row in its way that would otherwise be work (SKIP_KEPT): -e naming the
 * orphan, the named path first, else --keep-orphans. A spared one is reported,
 * never touched (deploy_ceded_t).
 *
 * @param arena Arena the plan and its buckets live in (must not be NULL)
 * @param ws Workspace with divergence analysis (must not be NULL)
 * @param scope Operation scope (must not be NULL; read at plan time alone —
 *        everything else a fate carries is workspace vocabulary)
 * @param skip_existing --skip-existing: a file row whose path is already occupied
 *        is not work. A plan fact, not an execution one — the occupancy comes
 *        from the workspace's own lstat, so preflight, the prompt and the executor
 *        all see one answer. Not overridden by --force: --force also overrides
 *        cleanup's skip reasons and the confirmation prompt, so the combination
 *        is meaningful and the narrower flag keeps its promise.
 * @param keep_orphans --keep-orphans: the landing's orphans are kept, dotta's
 *        node above rows and a copy beneath a blob row, and the rows in their
 *        way skipped with them — the flag cleanup's plan reads for the scope
 *        exit's orphans (core/cleanup.h cleanup_plan_build), read here for the
 *        landing's. The bucket is the answer every later stage reads.
 * @return The plan
 */
deploy_plan_t *deploy_plan_build(
    arena_t *arena,
    const workspace_t *ws,
    const scope_t *scope,
    bool skip_existing,
    bool keep_orphans
);

/**
 * True when the plan carries no work of either kind. A node is never work on
 * its own: every one the plan holds has a pending row beneath it.
 */
static inline bool deploy_plan_is_empty(const deploy_plan_t *plan) {
    return plan->files.pending.count == 0 && plan->directories.pending.count == 0;
}

/**
 * How many items the plan classified — both kinds and the landing's orphans,
 * every bucket
 *
 * Distinct from deploy_plan_is_empty, which counts only *work*: a plan of nothing
 * but clean items is empty there and non-zero here. Apply reads this to tell a
 * path filter that named nothing dotta manages from one whose paths are all
 * converged or skipped already — or name a landing's orphan, which waits for a
 * run that lands the row in its way.
 *
 * The bucket set lives here so a consumer never has to enumerate it. An item
 * that is both clean and excluded lands in no bucket at all, nor does an ancestor
 * claim (see deploy_partition_t), so a scope of only such items counts zero;
 * nor does a copy a row of the run reaches, the row counted in its own bucket.
 */
static inline size_t deploy_plan_item_count(const deploy_plan_t *plan) {
    const deploy_partition_t *kinds[] = { &plan->files, &plan->directories };
    size_t total = plan->nodes.count + plan->ceded.excluded.count +
        plan->ceded.kept.count + plan->ceded.unreached.count;

    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        const deploy_partition_t *part = kinds[i];

        total += part->pending.count;
        total += part->clean.count;
        total += part->excluded.count;
        total += part->skipped_existing.count;
        total += part->skipped_kept.count;
    }
    return total;
}

/**
 * Decide the fate of every planned row: a verdict, or a skip
 *
 * Decided in path order, both kinds in one walk, and then the ancestors — so
 * every row's fate is decided after the fate of every one of its ancestors, of
 * either kind, which is all the rungs read of the fates decided so far. The skips
 * and the warnings come out in that order too. The run acts in another — the
 * directories, then the files (deploy_execute) — each kind's verdicts in path
 * order within it.
 *
 * One fate per pending row (the totality equation, deploy_preflight_t), each
 * question asked of its one authority, the first skip reason that applies winning
 * (deploy_skip_reason_t):
 * - Ancestry — the look must bind, and the way must be one the run can create,
 *   so this rung runs first and answers from the run's own fates (check_ancestry).
 *   A pending directory row on the way that this run skipped for its pair, nothing
 *   standing there as the run will find it, is asked first: no directory will
 *   stand there whatever converges above it, so the row takes OWNERSHIP naming
 *   it. Then a squatter above the path where the view requires a directory — a
 *   directory row's, or dotta's node above the row (workspace_squatted_ancestor)
 *   — which voids every probe taken beneath it, the landing check's included —
 *   the workspace took none there at all, so the row arrives with nothing measured:
 *   an ancestor the directory pass converges first, or a node the way replaces,
 *   means the row is planned absent and asked nothing else; one the run skips
 *   means the row takes that skip's class, ancestor named; one the run never
 *   acts on (scope, -p, -e, an ancestor claim the plan does not hold) is ANCESTOR
 *   — an incapacity, and the remedy is a run that reaches it, or, for a claim
 *   the run cannot reach at all because nothing plans it, a re-derivation of
 *   the chain.
 * - Landing — the write must be able to land. Every arm of the executor writes
 *   through the *parent* — a temp file or a link renamed over the target, a mkdir
 *   — so the path's own permissions are never the question; a directory converged
 *   in place lands no new entry and asks no landing, only whether the run may
 *   hold it where it stands (FOREIGN, the landing's twin). The question goes to
 *   the nearest present ancestor alone: everything absent beneath it is created
 *   by this run at a working mode and cannot refuse. A deployable directory row
 *   there is dotta's and never refuses, and neither does a claimed directory
 *   the run may hold — its owner's or root's to change, its read granted
 *   (holdable_directory); any other directory's bits must not deny the run a
 *   new entry (fs_denied) or the row is skipped (PERMISSION) — what refuses every
 *   identity there denies the run nothing, and is the write's to meet; a
 *   non-directory squatter at a path no row claims skips it too (ANCESTOR — the
 *   claimed ones were the ancestry rung's). Ancestors are not items, so the landing
 *   is probed fresh: what stands there, the bits it grants a new entry and, where
 *   the run would hold it, the read the hold opens it with; the mechanism
 *   (ensure_parents) asks the same questions of the same ancestor, so this predicts
 *   the run rather than modelling it.
 * - Type — the occupant the workspace's look found at the planned path, both
 *   kinds (workspace_item_t.occupant; a row planned beneath a squatter this run
 *   replaces is absent, and asked nothing). A different kind at the path — a
 *   non-directory where a directory belongs, the reverse, or a file row's other
 *   kind — is skipped unless --force (TYPE), save an occupant, under either kind
 *   of row, the workspace proved is dotta's own node — a copy it confirmed, or
 *   a directory its record names — with its kind moved by Git alone (STALE, and
 *   no edit of the user's beside it: deploy_content_conflicts): that one is
 *   replaced unasked, as a STALE row's bytes are overwritten. A directory in a
 *   blob row's way goes with everything beneath it or not at all: the clearance
 *   (check_clearance) judges every entry beneath it first, by the landing's table
 *   (deploy_clearance) — dotta's copy as it confirmed it goes unasked, any other
 *   copy of dotta's under --force alone (TYPE, its edit named), and what no landing
 *   may remove — a stranger's, one it could not look at, a directory it could
 *   not read or empty — skips the row whatever --force says (OCCUPIED, UNREADABLE,
 *   PERMISSION), the stop named and nothing removed. A row the workspace could
 *   not settle (DIVERGENCE_UNVERIFIED — an unexaminable occupant, or a look at
 *   its content that failed) is skipped as UNREADABLE when the landing had nothing
 *   to say: no verdict can say what the run will find there.
 * - Content — the workspace's divergence verdict, the only authority for a fact
 *   no lstat can settle. Skipped unless --force (CONTENT; STALE without CONTENT
 *   never skips: disk still holds the blob dotta deployed, so the overwrite loses
 *   nothing); mode, ownership and encryption divergence never skip.
 * - Ownership — the row's rung, last, asked of a row every path rung passed and
 *   the one rung a row planned absent takes: the pair the write applies
 *   (resolve_deployment_ownership: the row's claim resolved on this host, half
 *   by half — the invoker's own owner where it names none, no group where it
 *   names none, on every run, core/metadata.h metadata_ownership), and whether
 *   this run may set it (identity_may_chown) — a pair that is not the invoker's
 *   to set is skipped (OWNERSHIP), the incapacity sudo lifts. The mode the write
 *   applies is the row's, total by build, and is not decided here. Under
 *   strict_ownership an owner or group this system does not know is an error,
 *   returned here — before the prompt, never mid-run; otherwise it is a warning
 *   and no change. A skipped row is not consulted, so it can neither warn nor
 *   fail strict_ownership.
 *
 * And one fate per node of the plan, decided in the same walk before the first
 * row that sorts after it — after its parent's fate, a prefix of its own path,
 * and before every row beneath it: replaced (replaces), or kept with a skip of
 * its own. Its ancestry is settled by construction — it was looked at, so no
 * squatter stands above it, and it stands, so its parent does — and two questions
 * are left, in the order the reasons rank: its reach, the landing rule asked of
 * its own path, since the unlink and the directory created in its place both
 * land through its parent (PERMISSION); then its consent — dotta's own copy as
 * it confirmed it goes unasked, any other only under --force (TYPE,
 * core/workspace.h workspace_untouched). At the walk's end a node with no
 * deployable row beneath it — every row there skipped on its own account — is
 * dropped from replaces, by the ancestors pass's own question: no act's way meets
 * it, so it stands, its record with it, and no replace is promised.
 *
 * Then the ancestors: every directory row the plan does not act on — an ancestor
 * claim it does not hold, a tracked or promoted row out of scope or skipped —
 * absent as the plan reads it (the workspace's occupant, or beneath a squatter
 * this run replaces) and standing above a *deployable* row. ensure_parents creates
 * exactly these on the way to a planned path (the parents beside them that no
 * row claims carry no metadata to decide), so their metadata is decided here
 * like any other row's, and a warning or a strict_ownership error about one is
 * met before the prompt like any other. This pass is why the plan has no ancestors
 * partition of its own: whether such a row is created turns on facts only preflight
 * holds — that the path is absent, and that something deployable stands beneath it.
 *
 * The deployable gate rests on an invariant the ladder establishes rather than
 * checks: beneath a directory this run leaves without a directory of its own —
 * a squatter it does not converge, an absent pending row it skips — every planned
 * row is skipped. Where a squatter stands at a skipped pending row, in that skip's
 * class, whatever its reason — the rung reads the ancestor's own fate; where it
 * stands at an ancestor outside the run's reach, by ANCESTOR; where the skipped
 * row is absent instead, by the rung too where the row was skipped for its pair
 * (OWNERSHIP, naming it), and otherwise by the row's own landing check — presence
 * is monotone up a path, so every planned row beneath meets the same refusing
 * ancestor (an unreadable one leaves its descendants' probes to fail the same
 * way). So the ancestors loop can never plan a parent for a subtree the run skips.
 *
 * Only rows the run will touch are consulted — the deployable ones, and the
 * ancestors it will create; a directory the run leaves alone cannot skip anything.
 * A planned row beneath a squatted ancestor this run converges (deploy_plan_build
 * routed it; the rung confirms it against the fates) is asked nothing: the path
 * is empty once the directory pass has replaced the squatter, and its landing
 * is that ancestor's — whose own row carries the conflict --force resolves, and
 * the landing question. Its verdict carries that absence; when the ancestor's
 * row is skipped instead, the row takes that skip's class, ancestor named (the
 * plan's premise — "the squatter is gone first" — holds row by row, never on
 * average).
 *
 * Runs as the invoker, the identity every write is made as (sys/identity), and
 * asks for no other: a landing whose bits deny the invoker is PERMISSION; a
 * directory it may not hold where it stands, another's or one whose bits deny
 * it the read, is FOREIGN; a pair it cannot set is OWNERSHIP — a row is
 * OWNERSHIP-skipped iff its resolved pair, or that of a pending directory row
 * on its way that nothing stands at, is not the invoker's to set and the run
 * holds no root. A run that holds root meets none of the three, since the executors
 * land the row through the syscall's second try (sys/filesystem) and root holds
 * any directory and sets any pair, save where the bits deny root as well (fs_denied
 * asks as root already). The ancestors are not asked the ownership rung: a pending
 * row the walk skipped for its pair is never one, every row beneath it skipped
 * naming it, and a claim the plan does not hold — derived, or tracked outside
 * the run — that the invoker cannot set, above a landing the invoker can write,
 * meets the refusal at the create: the first act whose way meets it carries it,
 * and every later act beneath fails naming the ancestor, unattempted
 * (deploy_execute).
 *
 * READ-ONLY: modifies neither the filesystem, the state database nor Git.
 *
 * @param ws Workspace with pre-loaded divergence analysis (must not be NULL)
 * @param plan Deployment plan (must not be NULL)
 * @param opts Deployment options (must not be NULL)
 * @param arena Arena the preflight and every array it holds live in (must not
 *        be NULL)
 * @param out The preflight (must not be NULL; left as it was on a failure)
 * @return Error or NULL on success (a skip is not an error; a strict_ownership
 *         failure is)
 */
error_t deploy_preflight(
    const workspace_t *ws,
    const deploy_plan_t *plan,
    const deploy_options_t *opts,
    arena_t *arena,
    deploy_preflight_t **out
);

/**
 * Carry the verdicts out
 *
 * Directories first (a planned directory may be the parent of a planned file,
 * and under --force a squatting symlink must be gone before a file is written
 * beneath it), then files, each in verdict order. Every verdict is acted on;
 * nothing outside them is *fixed*, and nothing is re-decided: what the verdict
 * says stands at the path is what the executor clears or converges, and a path
 * the world has moved under since preflight meets the mechanism's refusal rather
 * than a fresh judgment. Whatever a planned path's occupant was, clearing it
 * removes exactly one node, and so does clearing each copy its clearance vouched
 * for.
 *
 * A file or link row's act runs in the order a failure must stop it: its content
 * read, the way to it created — dotta's node on it replaced first — its node
 * created whole beside its path, what stands in its way cleared — the copies
 * its clearance vouched for, deepest first, then the directory they stood in —
 * the node published — so a row whose content cannot be read creates nothing on
 * its way and replaces no node there, and one whose node cannot be created removes
 * nothing at its path.
 *
 * Missing parents are the mechanics of landing a planned path, created top-down
 * as part of its write: a directory the view claims (any profile, in scope or
 * not, either class) with the mode and ownership its ancestor verdict carries,
 * anything else with the word no claim makes, DIR_MODE_DEFAULT and the invoker's
 * own owner — what a claimless row gets, so a directory a raised mkdir created
 * is handed back like the leaf beneath it, and no owner is borrowed from below.
 * Creation is all this pass may do: a parent the world made present after the
 * probe meets ERR_EXISTS rather than a convergence (fs_create_dir_exclusive),
 * since whatever now stands there is not this run's to fix, nor to land through
 * (the failure rule below). The claimed ones land in the receipt's ancestors;
 * the ones no row names are never reported. A claimed parent the verdicts did
 * not foresee — present at preflight, gone by the time the run reaches it — is
 * created like an unclaimed one, and the next load reads whatever it has to say
 * about its mode.
 *
 * Dotta's node on the way — one preflight replaces (deploy_preflight_t's replaces)
 * — goes before the parents beneath it, as part of the first act whose way meets
 * it: its own way first, its parent held open where it refuses the run and the
 * run may hold it; then the node, one unlink, never followed; then a directory
 * in its place, created as a parent no row claims is, since no row stands at an
 * orphan's path. A run whose acts beneath it all fail before their way leaves
 * it standing. The receipt lists each one replaced (replaced).
 *
 * Dotta's copies beneath a blob row — the ones its clearance vouched for
 * (deploy_preflight_t's clears) — go as part of that row's act alone, found beneath
 * its path: each one node, never through a link, deepest first, then the directory
 * they stood in. A removal refused among them fails the row, every copy before
 * it gone. The receipt lists each one cleared (cleared).
 *
 * Directories are materialized in two phases. Every directory the run creates
 * or converges carries its recorded mode with the owner triad forced on while
 * the run writes beneath it; a claimed directory the run may hold (core/deploy.c
 * holdable_directory: its owner's or root's to change, its read granted) that
 * already stands where a planned path must land and refuses it is opened the
 * same way, whichever class it is — a claim's mode was captured with the very
 * children it would refuse. None is let go here: the receipt carries every hold
 * (taken), and the caller lets them go once every act beneath them is done —
 * this run's, and whatever it runs next (deploy_release) — however the rows fared,
 * each to its exact mode, deepest first: recorded for the ones the plan
 * materialized, the mode it had for the ones merely opened. Group and other bits
 * are never widened. This is the one transient the run leaves, standing until
 * the caller's release and none after it; it is what lets a 0555 directory captured
 * with children be redeployed with them, and what makes the landing check a
 * question about the directories the run may not hold. A hold the release cannot
 * let go is the release's outcome (deploy_receipt_t's held).
 *
 * Individual row failures are non-fatal: the row lands in the receipt's failed
 * bucket with its cause and the run goes on — save the one failure that crosses
 * rows, a place the run needed a directory at and created none: a directory row
 * whose create or replace failed, a parent the way could not create, claimed or
 * not, or dotta's node the way could not replace. The act that met it carries
 * its cause; every later act beneath it fails unattempted, naming the outermost
 * such place in a sentence minted once — "'<path>' was not converged" for a row,
 * "'<path>' was not created" for a parent, "'<path>' was not replaced" for a
 * node — since a write there would land through whatever stands at the place,
 * or meet the same refusal again (poisoned_above, the preflight invariant's
 * execution mirror). A parent the world made present after the probe is such a
 * place too: what stands there may be a link, and nothing lands through one. A
 * failed converge-in-place poisons nothing — the directory stands, and children
 * land in it or fail on their own merits — nor does a refusal at a place the
 * run did not try to create: an ancestor that is not a directory, a landing that
 * stands and refuses its open (ensure_parents).
 *
 * Every failure is an outcome on the receipt — a row's in `failed`, the run going
 * on, and a hold the release could not let go in `held`, the release's own — so
 * nothing is returned beside it, as cleanup_execute returns its own: the caller
 * lets the holds go, prints the receipt, records what landed and reads the counts
 * for its exit.
 *
 * View rows are self-contained (blob_oid, type, storage path), and the content
 * cache reads every one — a link's bytes as its target, a file's decrypted where
 * sealed (infra/content.h). The record (path_records, observations) is the caller's
 * to write, after deployment succeeds.
 *
 * @param arena Arena the receipt, its arrays and the run's holds live in (must
 *        not be NULL; the verdicts' own, or one they outlive)
 * @param ws Workspace the plan was built from (must not be NULL; the
 *        claimed-ancestor lookup for a landing directory the run may hold)
 * @param verdicts The verdicts to carry out — deployable rows only, by
 *        construction: the skips never enter these arrays (must not be NULL)
 * @param cache Content cache, every row's bytes read through it (must not be NULL)
 * @return The receipt, the arena's, its holds still taken — the caller's to let
 *         go (deploy_release); never NULL
 */
deploy_receipt_t *deploy_execute(
    arena_t *arena,
    const workspace_t *ws,
    const deploy_preflight_t *verdicts,
    content_cache_t *cache
);

/**
 * Let the run's holds go — every directory it carried at a working mode, back
 * to its exact mode, deepest first
 *
 * A phase of its own, after deploy_execute, so the caller runs every other act
 * of its run in between and none meets a directory the release has narrowed: a
 * removal inside a directory a fix narrows needs it writable still. Called after
 * the caller's last act, however any act fared; a receipt with no holds — the
 * empty one a run that executed nothing reads — is let go at no cost. Through
 * each directory's own descriptor (fs_set_dir_mode). Hands `held` to the receipt
 * whole, as its last act: the holds it could not let go, each with its refusal,
 * an outcome on the receipt, so nothing is returned.
 *
 * Readers of what it fills: cmds/apply.c apply_print_deploy_receipt,
 * apply_write_record and cmd_apply's exit (held). A reader of held before the
 * release is a bug.
 *
 * @param arena Arena `held` lives in (must not be NULL; the one deploy_execute
 *        was handed, as every array of the receipt does)
 * @param receipt The receipt deploy_execute answered, or the empty one (must
 *        not be NULL)
 */
void deploy_release(arena_t *arena, deploy_receipt_t *receipt);

#endif /* DOTTA_DEPLOY_H */
