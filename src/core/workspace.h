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
 *   construction and nothing invalidates it. The record has two writers while
 *   a workspace is live, workspace_observe and workspace_anchor, each of which
 *   patches the snapshot it persists through (the flush's confirmations patch
 *   inline, in this file); retirements (state_retire_anchor, from apply's
 *   record step and the verbs) go to the database directly — no later reader
 *   in the run consults a retired path.
 *
 *   Exception: paths that load no workspace (the verbs — add, update, remove —
 *   profile enable / disable, sync's --force arm, completion) read the
 *   dispatcher's view or build their own with manifest_build, and write the
 *   record through state.h directly; no snapshot exists for them to desync.
 *
 *   The workspace's products (rows, records, verdicts) are read through the
 *   workspace; the run's resources (the repository, the content cache) are
 *   read through the dispatch context, at every layer — the workspace borrows
 *   them for its own reads and lends none of them (include/runtime.h, "Members
 *   not welcome" #3). A core step that acts on the workspace's plan and reads
 *   Git or content takes those handles by name beside the workspace
 *   (deploy_execute).
 */

#ifndef DOTTA_WORKSPACE_H
#define DOTTA_WORKSPACE_H

#include <git2.h>
#include <types.h>

#include "base/output.h"
#include "core/manifest.h"
#include "core/state.h"
#include "infra/content.h"

/* Maximum number of display tags that can be extracted from a workspace item */
#define WORKSPACE_ITEM_MAX_DISPLAY_TAGS 5

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
 * Lifetime notes — every string is borrowed for the workspace's lifetime:
 * - filesystem_path, storage_path: a view row's or a record's (arena), or the
 *   untracked scan's arena copies
 * - profile: a view row's or a record's (arena), or — an untracked item's — the
 *   view's profile list's (arena)
 * - old_profile: the record's profile (arena; can be NULL)
 */
typedef struct {
    char *filesystem_path;      /* Target path on filesystem (borrowed) */
    char *storage_path;         /* Path in profile, e.g., home/.bashrc (borrowed) */
    char *profile;              /* Winning profile name (borrowed) */
    char *old_profile;          /* Profile that deployed the disk content when it differs from profile, else NULL (borrowed) */

    /* Item classification */
    workspace_state_t state;      /* Where the item exists (deployed/undeployed/etc.) */
    divergence_type_t divergence; /* What's wrong with it (bit flags, can combine) */
    path_kind_t item_kind;        /* PATH_KIND_FILE or PATH_KIND_DIRECTORY */

    /* State flags */
    bool on_filesystem;         /* Exists on actual filesystem */
    bool profile_enabled;       /* Is source profile in workspace's enabled list? */
    bool profile_changed;       /* Profile differs from the record's (reassigned) */
} workspace_item_t;

/**
 * Bound carrier for a borrowed slice of workspace items
 *
 * Structural type — parallels manifest_rows_t. Callers receive a typed handle
 * instead of triple-star out-params.
 *
 * Pass by value. Lifetime is the producer's: cleanup's plan / verdict / result
 * buckets project through workspace_items_view and borrow for the bucket's life;
 * update's filters hand over heap buffers the caller frees.
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
    bool analyze_encryption;   /* Encryption policy validation */
} workspace_load_t;

/**
 * Load workspace from repository
 *
 * Slices the view, loads the record and performs divergence analysis against
 * the filesystem:
 * - The view: every enabled profile's tree and metadata at HEAD
 * - The record: the anchors in .git/dotta.db
 * - The filesystem: actual files on disk
 *
 * Additionally scans tracked directories for untracked files (new files that
 * appeared in directories previously added via 'dotta add').
 *
 * The workspace is scoped to the persistent enabled profile set — the view is
 * built over exactly those profiles, and a record under any other profile is
 * an orphan. This enforces the invariant that workspace loading uses the
 * persistent enabled set rather than any CLI filter (operations like `dotta
 * status -p global` still load the full workspace and apply the filter at
 * display time via scope_accepts_profile).
 *
 * Profile set: the view's (manifest_profiles — the enabled profiles whose
 * branch existed at build, in precedence order), read for the orphan label's
 * membership set and the untracked scan's order. The view itself is the
 * dispatcher's, built over the enabled set at the start of the command and
 * borrowed here — one tree walk per enabled profile, once per command — so
 * the workspace borrows nothing a caller must keep alive beside it.
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
 *                 which the command's spec declares with `.manifest`; no
 *                 command mutates Git or the enabled set between dispatch and
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
 * - WORKSPACE_DIRTY: Has work for apply (undeployed, modified, deleted, stale,
 *   reassigned, orphaned, released, untracked items)
 * - WORKSPACE_INVALID: Has an item the analysis could not verify
 *   (DIVERGENCE_UNVERIFIED) — apply skips it; the user must look
 *
 * @param ws Workspace (must not be NULL)
 * @return Status enum
 */
workspace_status_t workspace_get_status(const workspace_t *ws);

/**
 * Get all diverged items
 *
 * Returns array of all items (files and directories) with any divergence.
 *
 * @param ws Workspace (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Array of items (borrowed reference, do not free)
 */
const workspace_item_t *workspace_get_all_diverged(
    const workspace_t *ws,
    size_t *count
);

/**
 * Get workspace item by filesystem path
 *
 * Returns the divergence information for a specific file or directory via O(1)
 * hashmap lookup. If the item exists in the workspace but has no divergence
 * (CLEAN), this returns NULL. Only items with divergence are indexed.
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
 * Check for metadata (mode and ownership) divergence (data-centric design)
 *
 * Compares filesystem metadata with expected values to detect changes in
 * permissions (mode) and ownership (user/group). Checks both independently.
 *
 * Data-centric approach: Accepts values directly instead of structs, enabling
 * use with both manifest rows (manifest_row_t) and metadata (metadata_item_t)
 * without conversion.
 *
 * Stat propagation: Caller must provide pre-captured stat to avoid redundant
 * syscalls. This function performs zero filesystem operations.
 *
 * @param expected_mode Expected permission mode (0 = skip mode check, no metadata
 *                      tracked)
 * @param expected_owner Expected owner username (NULL = skip owner check)
 * @param expected_group Expected group name (NULL = skip group check)
 * @param st File stat data (must not be NULL, pre-captured by caller)
 * @param out_mode_differs Output flag for mode divergence (must not be NULL)
 * @param out_ownership_differs Output flag for ownership divergence (must not
 *                              be NULL)
 * @return Error or NULL on success
 */
error_t *check_item_metadata_divergence(
    mode_t expected_mode,
    const char *expected_owner,
    const char *expected_group,
    const struct stat *st,
    bool *out_mode_differs,
    bool *out_ownership_differs
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
 * Mirror of workspace_files(ws) for tracked directories: a borrowed view over
 * the view's directory rows, in filesystem_path order. Pure value return — no
 * allocation, no error path. Same lifetime as workspace_files.
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
 * (workspace_get_anchor, the adoption loop's ownership test) sees it. A path
 * that already has a record, in the snapshot or created earlier in this run, is
 * left exactly as it is and no statement runs: observation is idempotent on both
 * sides.
 *
 * Single entry point for every workspace-scope observation:
 *   - workspace_flush_updates (rows found on disk with no record during analysis,
 *     either kind)
 *   - apply's post-deploy loop (directories apply fixed rather than made, and
 *     active directories present on disk without a record)
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
 * the path had none at load. The SQL UPSERT is the single specification of the
 * observed_at INSERT-arm rule; this function holds none of that logic.
 *
 * Single entry point for every workspace-scope ownership event:
 *   - apply's adoption loop (ownership event on first claim, and the
 *     acknowledgement of a clean reassignment — the record's profile becomes
 *     the row's)
 *   - apply's post-deploy loop (ownership event after a write, file or directory)
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
 * @param stat Stat triple captured after the confirmation (may be NULL:
 *             a directory, or lstat failed after the write)
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
 *   acknowledges it. The snapshot's record is patched on the same columns.
 *
 * The order is load-bearing: a confirmation is an UPDATE that creates nothing,
 * so a path that had no record at analysis (it is in both lists) must take the
 * observation's INSERT first. DB and memory stay consistent for downstream readers
 * in the same run.
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
