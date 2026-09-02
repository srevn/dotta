/**
 * workspace.h - The join of the view, the record and the filesystem
 *
 * The workspace pairs three things per managed path:
 * 1. The view (core/manifest.h, built from Git at load): what *should* stand at
 *    each managed path, from which profile
 * 2. The record (.git/dotta.db, core/state.h): what dotta *did* there — deployed,
 *    confirmed, observed
 * 3. The filesystem: what *actually* stands there
 *
 * Detects and categorizes the divergence between them to prevent data loss and
 * provide clear visibility into workspace consistency.
 *
 * Snapshot ownership:
 *   The workspace is the authority for the join within its lifetime: the view
 *   (core/manifest.h — every enabled profile at HEAD, built by the dispatcher
 *   at the start of the command and borrowed here, `ctx->run.manifest`) and the
 *   record (the anchors snapshot, state_get_all_anchors). Downstream consumers
 *   (deploy, cleanup, command-internal analyses) read both through workspace
 *   accessors (workspace_files, workspace_directories, workspace_lookup,
 *   workspace_get_anchor) rather than building a view or calling
 *   state_get_all_anchors themselves. The view has no writer: it is current by
 *   construction and nothing invalidates it. The record has two writers while a
 *   workspace is live, workspace_observe and workspace_anchor, each of which
 *   patches the snapshot it persists through (the flush's confirmations patch
 *   inline, in this file); retirements (state_retire_anchor, from apply's record
 *   step and the verbs) go to the database directly — no later reader in the
 *   run consults a retired path.
 *
 *   Exception: the verbs — add, remove, and update after its commit — write the
 *   record through state.h directly, against the post-commit view they build
 *   with manifest_build. add and remove load no workspace, and nothing reads
 *   update's after its record write, so there is no snapshot for the write to
 *   desync. profile enable / disable write only the enabled set, sync writes
 *   nothing, and completion reads the dispatcher's view alone.
 *
 *   The workspace's products (rows, records, verdicts) are read through the
 *   workspace; the run's resources (the repository, the content cache) are read
 *   through the dispatch context, at every layer — the workspace borrows them
 *   for its own reads and lends none of them (include/runtime.h, "Members not
 *   welcome" #3). A core step that acts on the workspace's plan and reads Git
 *   or content takes those handles by name beside the workspace (deploy_execute).
 */

#ifndef DOTTA_WORKSPACE_H
#define DOTTA_WORKSPACE_H

#include <git2.h>
#include <string.h>
#include <types.h>

#include "base/output.h"
#include "core/manifest.h"
#include "core/state.h"
#include "infra/content.h"
#include "sys/filesystem.h"

/* Maximum number of display tags that can be extracted from a workspace item */
#define WORKSPACE_ITEM_MAX_DISPLAY_TAGS 5

/**
 * Whose claim holds the squatted directory an observation resolved through —
 * the displaced fact, with its reach
 *
 * A directory is squatted when a claim says a directory belongs at the path and
 * the load observed something else standing there. Every lstat taken beneath it
 * resolved through the occupant: a symlink to a directory answers for the link's
 * target, so a child reads clean, present, modified or new about a tree that is
 * not this path's; a file answers ENOTDIR — absence. Two authorities can make
 * the claim, and they reach differently — the reach rule:
 *
 *   TRACKED / DERIVED   the view claims the path — a directory row of either
 *                       class (core/manifest.h): every present item beneath it,
 *                       whatever its state, was observed through the squatter.
 *                       A view claim displaces everything beneath it.
 *   RECORD              only a record remembers a directory there — the view
 *                       lacks the path: the record's own family beneath it, the
 *                       ORPHANED and RELEASED items, was observed through the
 *                       squatter, and nothing else was. A view row beneath such
 *                       a path is a deliberate through-capture: its profile's
 *                       derivation met the non-directory and claimed no rung
 *                       there (core/metadata.h), so the arrangement predates
 *                       the row and the observation is the row's own. A record's
 *                       memory displaces only what the record family remembers
 *                       beneath it — never a view row, so RECORD stands on no
 *                       DEPLOYED item.
 *
 * NONE on every item observed at its own path, and on every absent one: an absent
 * reading beneath a squatter is true — the lstat reached nothing, and there is
 * no directory for the path to exist in — so a DELETED item stays update's to
 * commit and an absent orphan a reclaim. Presence is the whole of the condition.
 * A clean row beneath a squatter has no item and so no field: the squatter's
 * own row is the work, and the two loops that touch clean rows (apply's adoption
 * and acknowledgement) ask the row-keyed probe (workspace_displaced_ancestor),
 * which answers view-side and so agrees with the field on a DEPLOYED item by
 * construction.
 *
 * Established once at load, after every analysis has observed its slice
 * (collect_displaced), and trusted downstream: the route reads it first
 * (workspace_item_route), cleanup_verdict's displaced arm reads it, and the
 * displays name it ([displaced]).
 */
typedef enum {
    WORKSPACE_DISPLACED_NONE = 0,  /* Observed at its own path, or absent */
    WORKSPACE_DISPLACED_TRACKED,   /* Through a squatter a tracked row claims */
    WORKSPACE_DISPLACED_DERIVED,   /* Through a squatter an ancestor claim holds */
    WORKSPACE_DISPLACED_RECORD     /* Through a squatter only a record remembers — orphans alone */
} workspace_displaced_t;

/**
 * Diverged item entry
 *
 * Represents a single item (file or directory) with divergence between states.
 *
 * Items can be:
 * - Files (PATH_KIND_FILE): Have content, claimed by a profile's tree, deployed
 *   to filesystem
 * - Directories (PATH_KIND_DIRECTORY): Metadata-only (mode/ownership, no content),
 *   claimed by a profile's metadata.json; planned and converged by core/deploy
 *   on apply's behalf
 * - Use item_kind to distinguish between files and directories.
 *
 * The occupant is the analysis's one observation of the disk, carried as the
 * sys layer names it rather than folded to a presence bit: what the analyzer's
 * lstat found at the path — the link itself, never its target. FS_OCCUPANT_NONE
 * is absence; FS_OCCUPANT_UNKNOWN is a path the analyzer could not stat and assumes
 * present (absence is never inferred from a failure to look; the item carries
 * DIVERGENCE_UNVERIFIED beside it). Presence is therefore `occupant !=
 * FS_OCCUPANT_NONE` — the workspace's rule, and cleanup's; deploy judges by the
 * stricter one (deploy_occupant_present: UNKNOWN is not present, since deploy
 * judges nothing it could not see), and a new consumer picks one of the two and
 * says which. The divergence bits are the verdict over that observation
 * (DIVERGENCE_TYPE: the occupant is not the row's or the record's kind); every
 * consumer that once re-probed the path to learn its type reads this field instead,
 * so status, deploy and cleanup cannot see three different occupants at one path.
 * Beside it, whether the lstat reached this path at all: the displaced class
 * (workspace_displaced_t) names the claim whose squatter the look resolved through,
 * and every bit the divergence carries was read off that squatter's target when
 * it is not NONE.
 *
 * Lifetime — every borrowed pointer on the item is arena-backed and valid for
 * the workspace's lifetime (the arena outlives it): the view's rows, the anchors
 * snapshot, the untracked scan's copies. Item addresses are stable too, which
 * is what lets cleanup's buckets and apply's collections hold them across phases
 * by construction.
 */
typedef struct {
    /* The join's sources — borrowed for the workspace's lifetime; at least one
     * is set except for UNTRACKED items.
     *   row     the view's claim. NULL for an orphan (the view lacks the path)
     *           and for UNTRACKED — except a relocated orphan, where it is the
     *           record's own claim's row at its new filesystem path (the orphan
     *           analysis carried it: non-NULL on an ORPHANED item IS the
     *           relocation, and the new location is printable from it).
     *   anchor  the record — always the live snapshot record, the same pointer
     *           workspace_get_anchor returns: the writers patch it in place
     *           (workspace_anchor) or create it and backfill this field
     *           (workspace_observe, workspace_anchor), so a read here is never
     *           stale. NULL only while the path truly has no record (UNTRACKED,
     *           and active rows dotta has never observed, until the flush observes
     *           them). */
    const manifest_row_t *row;
    const anchor_t *anchor;

    /* Identity — the join key and the claim's coordinates, one uniform read for
     * every state. Aliases of the identity source's strings — the row's for active
     * items, the record's for orphans (the state names the source:
     * ORPHANED/RELEASED are record-defined), the scan's arena copies for untracked
     * (profile: the view's profile list's) — assigned once by the producer, never
     * a second copy. */
    char *filesystem_path;      /* Target path on filesystem */
    char *storage_path;         /* Path in profile, e.g., home/.bashrc */
    char *profile;              /* Winning profile name */

    /* The analysis's verdicts */
    workspace_state_t state;      /* Where the item exists (deployed/undeployed/etc.) */
    divergence_type_t divergence; /* What's wrong with it (bit flags, can combine) */
    path_kind_t item_kind;        /* The identity source's kind (scan: FILE) */

    /* The observation */
    fs_occupant_t occupant;           /* What the analysis's lstat found at the path (see above) */
    workspace_displaced_t displaced;  /* Whose squatter the lstat resolved through, or NONE */
} workspace_item_t;

/**
 * A pending handover: the record dotta owns names a different profile than the
 * row's
 *
 * Reads the LIVE record — after apply acknowledges (workspace_anchor rewrites
 * the record under the row's profile) the same read honestly answers false, so
 * a consumer that wants the load-time fact reads before the run's ownership events
 * rewrite it (apply's collection does). Kind-blind: one rule for both kinds.
 * Orphans: false by construction — a relocated orphan's row is carried only when
 * its profile equals the record's (the strict same-profile rule of the relocation
 * read), so no reader needs an orphan guard. Only an owned record qualifies: an
 * observed or confirmed record dotta never deployed names the row the path was
 * first seen under, not a deployer, and apply adopts such a path rather than
 * acknowledging it.
 */
static inline bool workspace_item_reassigned(const workspace_item_t *item) {
    return item->row && item->anchor && item->anchor->deployed_at > 0 &&
           strcmp(item->anchor->profile, item->row->profile) != 0;
}

/**
 * Bound carrier for a borrowed slice of workspace items
 *
 * Structural type — parallels manifest_rows_t. Callers receive a typed handle
 * instead of triple-star out-params.
 *
 * Pass by value. Lifetime is the producer's: cleanup's plan / verdict / result
 * buckets project through workspace_items_view and borrow for the bucket's life;
 * the workspace's own spine returns through workspace_get_all_diverged and borrows
 * for the workspace's life; update's filters hand over heap buffers the caller
 * frees.
 */
typedef struct {
    const workspace_item_t *const *entries;
    size_t count;
} workspace_items_t;

/**
 * Project a ptr_array_t bucket of borrowed items as a typed slice
 *
 * Mirrors manifest_rows_view: buckets filled by ptr_array_push(&bucket, item)
 * hold `void *`, and the cast layers const onto both pointer levels. The view
 * aliases the bucket's storage and is valid for the bucket's lifetime.
 */
static inline workspace_items_t workspace_items_view(const ptr_array_t *bucket) {
    return (workspace_items_t){
        .entries = (const workspace_item_t *const *) bucket->items,
        .count = bucket->count,
    };
}

/**
 * Which verb resolves a deployed item — the one route table
 *
 * The partition of WORKSPACE_STATE_DEPLOYED items that every surface routing a
 * deployed item reads, so no two surfaces can route one item two ways — the shape
 * cleanup_verdict gives the orphan side. One producer (workspace_item_route)
 * and five readers, each named with the arm it reads; a reader not on this list
 * is a bug:
 *
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
 *   diff's downstream direction    CAPTURE
 *
 * Values are listed in precedence order: the route is the first that applies,
 * so a multi-bit divergence routes under the reason that outranks the rest.
 *
 * Deployed items only. Every other state routes trivially by the state itself
 * (DELETED → update's, UNDEPLOYED → apply's, UNTRACKED → update --include-new's,
 * ORPHANED / RELEASED → cleanup_verdict's) and is not drift-prone. DELETED earns
 * that triviality upstream: classify_absent reads absence as a deletion only
 * for a claim that asserts its path, so an ancestor claim never arrives here
 * and every DELETED item can bear update's verb. Callers keep their state switch
 * and read this table for the DEPLOYED arm alone.
 */
typedef enum {
    WORKSPACE_ROUTE_CLEAN,             /* No divergence, no reassignment */
    WORKSPACE_ROUTE_DISPLACED_TRACKED, /* Through a squatter a tracked row claims (apply --force) */
    WORKSPACE_ROUTE_DISPLACED_DERIVED, /* … an ancestor claim holds ('dotta update <dir>') */
    WORKSPACE_ROUTE_UNVERIFIABLE,      /* DIVERGENCE_UNVERIFIED — dotta could not look */
    WORKSPACE_ROUTE_CONFLICT,          /* STALE ∧ CONTENT — both sides moved  */
    WORKSPACE_ROUTE_STALE,             /* STALE alone — Git moved, disk did not */
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
 * Pure in the fields the analysis observed once at load — the displaced class,
 * divergence, kind, occupant, reassignment. No syscall, no options; first match
 * wins:
 *
 *   displaced, TRACKED       DISPLACED_TRACKED — the observation resolved
 *                            through a squatter a tracked row claims, so every
 *                            bit below was read off the squatter's target and
 *                            not this path: no judgment made through it can outrank
 *                            the fact (deploy's ANCESTOR rung and cleanup_verdict's
 *                            displaced arm rank it the same way). apply --force
 *                            replaces the squatter and writes the row fresh beneath
 *                            it.
 *   displaced, DERIVED       DISPLACED_DERIVED — the same, through a rung
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
 *   STALE ∧ CONTENT          CONFLICT — both sides moved since dotta last
 *                            deployed: the edit is real, but update will not
 *                            commit bytes Git has moved past, and apply skips
 *                            the row rather than overwrite the edit without
 *                            --force. Neither verb's by default; the user decides.
 *   STALE alone              STALE — Git advanced past the deployed blob and
 *                            disk did not move: overwriting loses nothing, so
 *                            the bytes are apply's to bring whether or not a
 *                            mode bit rides along (update stores bytes; the bytes
 *                            on disk are old either way).
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
 *                            what was one by the row's tracked field: a deployed
 *                            item is a view row's (the join), so the row holds,
 *                            and a file row's tracked field is a don't-care, so
 *                            the kind gates the read.
 *   any other divergence     CAPTURE — update's work. file ↔ symlink on a
 *                            file row stays here: the copy commits it as the
 *                            new kind.
 *   none, record disagrees   REASSIGNED — a pending handover apply
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
 * Workspace cleanliness status
 */
typedef enum {
    WORKSPACE_CLEAN,        /* No divergence */
    WORKSPACE_DIRTY,        /* Has divergence (warnings) */
    WORKSPACE_INVALID       /* Serious issues (errors) */
} workspace_status_t;

/**
 * Workspace load options
 *
 * Controls which analyses workspace_load() performs. All flags default to false
 * when zero-initialized. Build custom options by setting specific flags. The
 * analyses are independent: the partition that every load runs is what decides
 * which rows are active and which records are orphans, and each analysis walks
 * its own slice.
 *
 * Two of them are the join, and every command's load sets both: the file and
 * the directory analyses observe the view's rows, and the displaced fact
 * (collect_displaced) is complete only when every directory row has been observed
 * — a load that routes items (workspace_item_route) must never read NULL over a
 * squatter. The other two are optional because each has a cost and a reader that
 * may not exist: the orphan analysis (a Git probe per profile; read by the settle
 * — apply's cleanup — and status's Issues) and the untracked scan (a readdir
 * walk per tracked directory; read by update --include-new and status's New files).
 *
 * Lifetime: Options are read-only during workspace_load(), safe to stack-allocate.
 */
typedef struct {
    bool analyze_files;        /* File divergence detection */
    /* Orphan analysis — presence, ownership, divergence and Git authority of
     * every record whose path the view lacks, either kind (one ref lookup and a
     * lazy tree or metadata load per profile with present, owned orphans) */
    bool analyze_orphans;
    bool analyze_untracked;    /* Directory scanning for new files (EXPENSIVE!) */
    bool analyze_directories;  /* Directory metadata checks */
} workspace_load_t;

/**
 * Load workspace from repository
 *
 * Slices the view, loads the record and performs divergence analysis against
 * the filesystem:
 * - The view: every enabled profile's tree and metadata at HEAD
 * - The record: the path_anchors in .git/dotta.db
 * - The filesystem: actual files on disk
 *
 * Additionally scans tracked directories for untracked files (new files that
 * appeared in directories previously added via 'dotta add').
 *
 * The workspace is scoped to the persistent enabled profile set — the view is
 * built over exactly those profiles, and a record under any other profile is an
 * orphan. This enforces the invariant that workspace loading uses the persistent
 * enabled set rather than any CLI filter (operations like `dotta status -p global`
 * still load the full workspace and apply the filter at display time via
 * scope_accepts_profile).
 *
 * Profile set: the view's (manifest_profiles — the enabled profiles whose branch
 * existed at build, in precedence order), read for the orphan label's membership
 * set and the untracked scan's order. The view itself is the dispatcher's, built
 * over the enabled set at the start of the command and borrowed here — one tree
 * walk per enabled profile, once per command — so the workspace borrows nothing
 * a caller must keep alive beside it.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (must not be NULL, borrowed from caller;
 *              caller retains ownership and must free it after workspace_free)
 * @param config Configuration (for ignore patterns, can be NULL)
 * @param content_cache Shared blob-content cache (must not be NULL;
 *              borrowed — lifetime must extend past workspace_free. Obtain from
 *              `ctx->run.content_cache` under a spec that declares crypto)
 * @param manifest The view over the enabled set (must not be NULL; borrowed —
 *                 lifetime must extend past workspace_free. `ctx->run.manifest`,
 *                 which the command's spec declares with `.manifest`; no command
 *                 mutates Git or the enabled set between dispatch and
 *                 workspace_load, so it is current)
 * @param options Analysis options (must not be NULL)
 * @param arena Borrowed allocator backing every workspace-lifetime string (the
 *              view's rows, the record, diverged items, partition pointer arrays).
 *              Must outlive workspace_free; in practice `ctx->arena` (must not
 *              be NULL).
 * @param out Workspace (must not be NULL, caller must free with workspace_free)
 * @return Error or NULL on success
 */
error_t *workspace_load(
    git_repository *repo,
    state_t *state,
    const struct config *config,
    content_cache_t *content_cache,
    const manifest_t *manifest,
    const workspace_load_t *options,
    arena_t *arena,
    workspace_t **out
);

/**
 * Get workspace status
 *
 * Returns overall cleanliness assessment:
 * - WORKSPACE_CLEAN: No divergence detected
 * - WORKSPACE_DIRTY: Has work for a verb (undeployed, modified, deleted, stale,
 *   reassigned, orphaned, released, untracked or policy-violating items)
 * - WORKSPACE_INVALID: Has an item the analysis could not verify
 *   (DIVERGENCE_UNVERIFIED) — no verb resolves it; the user must look
 *
 * @param ws Workspace (must not be NULL)
 * @return Status enum
 */
workspace_status_t workspace_get_status(const workspace_t *ws);

/**
 * Get all diverged items
 *
 * Returns the workspace's diverged spine — every item (file and directory) the
 * analysis produced — as a borrowed slice. Pure value return — no allocation,
 * no error path. Items are arena-allocated, so the slice and the item addresses
 * it carries are valid for the workspace's lifetime.
 *
 * Iterate via:
 *   workspace_items_t items = workspace_get_all_diverged(ws);
 *   for (size_t i = 0; i < items.count; i++) {
 *       const workspace_item_t *item = items.entries[i];
 *       ...
 *   }
 *
 * @param ws Workspace (NULL returns an empty slice)
 * @return Borrowed slice over the diverged items
 */
workspace_items_t workspace_get_all_diverged(const workspace_t *ws);

/**
 * Get workspace item by filesystem path
 *
 * Returns the divergence information for a specific file or directory via O(1)
 * hashmap lookup. Every item the analysis produced is indexed — a row with a
 * state other than DEPLOYED, a divergence bit, or a reassignment (a clean row
 * whose owned record names another profile has an item whose sources derive it
 * — workspace_item_reassigned); a row with none of the three has no item, and
 * this returns NULL — a clean row beneath a squatter included, since what read
 * clean was the squatter's target and the squatter's own row is the work
 * (workspace_displaced_t).
 *
 * This function enables preflight to efficiently query workspace data instead
 * of re-analyzing files, eliminating redundant comparisons.
 *
 * @param ws Workspace (must not be NULL)
 * @param filesystem_path Path to query (must not be NULL)
 * @return Workspace item or NULL if not found/clean (borrowed reference)
 */
const workspace_item_t *workspace_get_item(
    const workspace_t *ws,
    const char *filesystem_path
);

/**
 * Get the active file slice
 *
 * Returns a borrowed view over the view's file rows — every path an enabled profile
 * claims as a file, the winning profile's claim applied — in filesystem_path
 * order. Pure value return — no allocation, no error path.
 *
 * The pointers reference the view's rows, built into the arena at workspace_load
 * time; the arena outlives the workspace so the slice is valid for the workspace's
 * lifetime.
 *
 * Iterate via:
 *   manifest_rows_t files = workspace_files(ws);
 *   for (size_t i = 0; i < files.count; i++) {
 *       const manifest_row_t *file = files.entries[i];
 *       ...
 *   }
 *
 * @param ws Workspace (NULL returns an empty slice)
 * @return Borrowed slice over the active file rows
 */
manifest_rows_t workspace_files(const workspace_t *ws);

/**
 * Get the active directory slice
 *
 * Mirror of workspace_files(ws) for directories: a borrowed view over the view's
 * directory rows, in filesystem_path order — both classes, since both name a
 * path that must exist. A consumer whose question is about managing the directory
 * rather than about it existing tests row->tracked (core/manifest.h). Pure value
 * return — no allocation, no error path. Same lifetime as workspace_files.
 *
 * @param ws Workspace (NULL returns an empty slice)
 * @return Borrowed slice over the active directory rows
 */
manifest_rows_t workspace_directories(const workspace_t *ws);

/**
 * Look up an active row by filesystem path
 *
 * O(1) random access over the view — a path is one managed thing, whatever its
 * kind; callers that want one kind test row->type. Returns NULL if no enabled
 * profile claims the path — the single chokepoint for "is this path managed?"
 * probes.
 *
 * @param ws Workspace (NULL returns NULL)
 * @param filesystem_path Path to look up (NULL returns NULL)
 * @return Borrowed row pointer, or NULL if not managed
 */
const manifest_row_t *workspace_lookup(
    const workspace_t *ws,
    const char *filesystem_path
);

/**
 * The displaced managed directory above `path`, or NULL — the view's claims
 *
 * A directory is *displaced* when a claim says a directory belongs at the path
 * and something else stands there. Every lstat taken beneath such a path resolved
 * through the occupant — a symlink to a directory answers for the link's target
 * — so a child read clean, present, modified or new about a tree that is not
 * this path's. An observation taken there is not an observation of that path at
 * all.
 *
 * Both classes of directory row qualify: what matters is that some claim says a
 * directory belongs at the path, not whether the profile manages the directory
 * itself (core/manifest.h). A path no claim names at all stays invisible here
 * by design — a symlinked configuration directory of the user's own arrangement
 * is the user's, and deploy writes through it, cleanup prunes through it, and
 * update captures through it, all correctly. That case survives the ancestry
 * being claimed because the capture rule authors nothing for a component that
 * is not a real directory when the chain is walked: a directory the user had
 * already symlinked never becomes a claim in the first place.
 *
 * The record's claims do not qualify here: a directory only a record remembers
 * displaces the record's own family alone (the reach rule, workspace_displaced_t),
 * and every item of that family carries the fact on itself. This probe is for a
 * row or a path that may have no item — a clean row apply adopts or acknowledges,
 * a planned row deploy judges, a scan root — and a view row beneath a
 * record-remembered squatter is the through-capture the rule leaves to its own
 * occupant. So the answer is the view's claims alone, and on a DEPLOYED item it
 * is exactly the item's own displaced field.
 *
 * The answer is derived from the load's own observations (collect_displaced),
 * and every command's load observes every directory row (workspace_load_t: a
 * load that routes items must never read NULL over a squatter), so it is complete
 * on every load. The outermost such ancestor is returned: the true offender,
 * whose occupant every deeper observation went through. Fate-blind by construction
 * — whether *this run* converges the displacement is deploy's question, asked
 * of its own fates against this answer (check_ancestry).
 *
 * @param ws Workspace (NULL returns NULL)
 * @param path Path to test (NULL returns NULL); proper ancestors only, so a
 *        displaced directory is never its own answer
 * @return Borrowed path (workspace lifetime), or NULL
 */
const char *workspace_displaced_ancestor(const workspace_t *ws, const char *path);

/**
 * Look up the record dotta keeps of a path
 *
 * O(1) probe over the anchors snapshot, active and orphan paths alike. Returns
 * NULL when dotta has never observed the path on disk while it was managed. Within
 * a run the answer follows the writers: a record workspace_observe or
 * workspace_anchor created or patched reads back here with its post-write value.
 *
 * @param ws Workspace (NULL returns NULL)
 * @param filesystem_path Path to look up (NULL returns NULL)
 * @return Borrowed record pointer, or NULL if the path has none
 */
const anchor_t *workspace_get_anchor(
    const workspace_t *ws,
    const char *filesystem_path
);

/**
 * Extract display tags and metadata from workspace item
 *
 * Translates workspace item state and divergence flags into presentation tags,
 * colors, and metadata strings for use with output_list builder. Provides
 * consistent item visualization across all commands.
 *
 * Tag Priority (for DEPLOYED state with divergence):
 *   0. "displaced" (YELLOW) - The one tag when the observation resolved through
 *      a squatter (workspace_displaced_t): every divergence bit was read off
 *      the squatter's target, so none of the tags below is shown beside it —
 *      "modified" on a stranger's bytes would name work no verb takes. The
 *      reassignment tag still rides: it is the record against the row, no
 *      observation involved
 *   1. "type" (RED) - File type changed (symlink ↔ regular), most severe
 *   2. "modified" (YELLOW) - Disk content moved away from what dotta deployed
 *   3. "stale" (CYAN when alone: apply-side work, like "undeployed") - Git moved
 *      past the deployed blob; next to "modified" it names a conflict and the
 *      primary tag's colour stands
 *   4. Secondary: "mode", "ownership", "unencrypted" - Metadata divergence
 *
 * The function handles special cases:
 *   - TYPE divergence suppresses MODE tag (type change makes mode irrelevant)
 *   - ENCRYPTION divergence upgrades color to MAGENTA if still the default
 *   - ENCRYPTION is the one divergence an UNDEPLOYED row also carries: the copy
 *     is not on disk to have diverged from, but the blob apply is about to write
 *     violates the policy, and that is worth saying before it lands
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
 * @param tags_out Array to receive tag string pointers
 * @param tag_count_out Receives number of tags extracted (must not be NULL)
 * @param color_out Receives color for tags (must not be NULL)
 * @param metadata_buf Buffer for formatted metadata (must not be NULL)
 * @param metadata_size Size of metadata buffer (minimum 32 bytes, 256 recommended
 *                      for safety with long profile names)
 * @return true on success, false on error (invalid parameters)
 */
bool workspace_item_extract_display_info(
    const workspace_item_t *item,
    const char **tags_out,
    size_t *tag_count_out,
    output_color_t *color_out,
    char *metadata_buf,
    size_t metadata_size
);

/**
 * Observe a managed path with in-memory consistency
 *
 * Workspace-scope side of state_observe (see state.h): records the path's first
 * sighting on disk — presence only, no blob, no stat — and creates the matching
 * record in the workspace's anchors snapshot so every later reader in the run
 * (workspace_get_anchor, the adoption loop's ownership test) sees it, backfilling
 * the path's item, if analysis produced one, so item->anchor is the live record
 * from the record's creation on. A path that already has a record, in the snapshot
 * or created earlier in this run, is left exactly as it is and no statement runs:
 * observation is idempotent on both sides.
 *
 * Single entry point for every workspace-scope observation: the flush
 * (workspace_flush_updates — rows found on disk with no record during analysis,
 * either kind). That is the one producer of observations, because the analysis
 * is where presence is established: every active path present at load has a record
 * once the flush has run, and a path the run makes afterwards is an ownership
 * event (workspace_anchor), not an observation.
 *
 * The row pointer is borrowed from the workspace's active partition; the record
 * created here borrows its strings from that row for the workspace's lifetime.
 *
 * @param ws Workspace (must not be NULL, state must be open)
 * @param row Active row whose path was seen on disk (must not be NULL, borrowed
 *            from workspace's active partition)
 * @param now Observation timestamp (must be > 0)
 * @return Error from state_observe, or NULL on success
 */
error_t *workspace_observe(
    workspace_t *ws,
    const manifest_row_t *row,
    time_t now
);

/**
 * Anchor a managed path with in-memory consistency
 *
 * Workspace-scope side of the routing invariant defined on state_anchor (see
 * state.h): persists via state_anchor and assigns the canonical post-write record
 * (the inputs plus the one column SQL RETURNING decided) into the workspace's
 * anchors snapshot — patching the path's record in place, or creating it when
 * the path had none at load and backfilling the path's item, so item->anchor
 * reads the post-write record either way. The SQL UPSERT is the single
 * specification of the observed_at INSERT-arm rule; this function holds none of
 * that logic.
 *
 * Single entry point for every workspace-scope ownership event:
 *   - apply's adoption loop (ownership event on first claim, and the
 *     acknowledgement of a clean reassignment — the record's profile becomes
 *     the row's)
 *   - apply's record step (ownership event after a write: a file deployed, a
 *     directory made — where nothing stood, in a squatter's place, or as the
 *     parent of a planned path)
 * Confirmations are not ownership events and do not come through here: the flush
 * persists them with state_confirm and patches the record's confirmed columns
 * itself.
 *
 * The row pointer is borrowed from the workspace's active partition; the record
 * borrows its strings from that row for the workspace's lifetime.
 *
 * @param ws Workspace (must not be NULL, state must be open)
 * @param row Active row the path is anchored to (must not be NULL, borrowed from
 *            workspace's active partition; non-zero blob for a file row)
 * @param stat The stat of the moment this row's content was established on disk,
 *             taken by the code that established it: the analysis's own triple
 *             for an adoption or acknowledgement (the snapshot pair, when its
 *             blob is this row's); the deploy receipt's triple for a file
 *             deployment — the executor's fstat of the bytes it wrote, distilled
 *             at the write (stat_cache_from_write: proof by authorship, no closed
 *             second needed), UNSET for a symlink (made by path, no descriptor
 *             exists to describe it), and UNSET and NULL say the same thing to
 *             state_anchor; NULL for a directory. Never a fresh lstat: a look
 *             taken here binds whatever stands at the path now to a verdict from
 *             earlier.
 * @param now Timestamp of the write (must be > 0)
 * @return Error from state_anchor, or NULL on success
 */
error_t *workspace_anchor(
    workspace_t *ws,
    const manifest_row_t *row,
    const stat_cache_t *stat,
    time_t now
);

/**
 * Flush the updates accumulated during workspace_load to the state database
 *
 * Both channels drain here, in one transaction, observations first:
 *
 *   Observations — rows of either kind whose path was lstat-observed during
 *   analysis while it had no record. Through workspace_observe, so the snapshot
 *   gains the record the INSERT creates.
 *
 *   Confirmations — files verified CMP_EQUAL via the slow path (content hash
 *   comparison) accumulate the stat they were verified with. Persisting it beside
 *   the row's blob (state_confirm) lets subsequent runs short-circuit via the
 *   fast-path stat AND — if Git advances blob_oid in the meantime — classify
 *   the file as stale directly from the fast path instead of re-hashing. A
 *   confirmation rewrites only what it confirmed (type, blob, stat); the record's
 *   claim — profile, storage path, mode, owner, group — is an ownership event's
 *   to change, so a clean reassignment keeps reading as one until apply
 *   acknowledges it. The snapshot's record is patched on the same columns. One
 *   taken through a symlinked ancestor binds the target file's triple — harmless
 *   whether the ancestor is the user's own arrangement or a displaced managed
 *   directory: the engines judge the latter by the item's displaced class, and
 *   by the row-keyed probe (workspace_displaced_ancestor) where a row has no
 *   item, never by the confirmation, and the fast path simply misses until the
 *   path heals and the slow path re-confirms.
 *
 * The order is load-bearing: a confirmation is an UPDATE that creates nothing,
 * so a path that had no record at analysis (it is in both lists) must take the
 * observation's INSERT first. DB and memory stay consistent for downstream readers
 * in the same run.
 *
 * The joins run last — each fact's lifetime rule (state.h), enforced here because
 * the flush is where the view, the record and both loaded fact sets are in hand:
 * every prune order whose path the view has is void, and every released copy
 * whose path's record again carries a confirmed blob is forgotten.
 *
 * Self-healing: the first status/apply after profile enable verifies all files
 * via the slow path and seeds the record. The second call hits the fast path
 * for unchanged files and tags STALE directly for externally-modified profiles.
 *
 * The deployed_at timestamp is intentionally not advanced here — this flush
 * confirms observations, not deployments. Apply and the capturing verbs remain
 * the writers of anchor.deployed_at.
 *
 * Safe to call on any workspace — returns immediately if no updates pending.
 * Uses the workspace's internal state handle for database writes.
 *
 * @param ws Workspace (must not be NULL)
 * @return Error or NULL on success
 */
error_t *workspace_flush_updates(workspace_t *ws);

/**
 * Free workspace
 *
 * Frees all internal state and divergence analysis results.
 *
 * @param ws Workspace to free (can be NULL)
 */
void workspace_free(workspace_t *ws);

#endif /* DOTTA_WORKSPACE_H */
