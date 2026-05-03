/**
 * workspace.h - Workspace abstraction for state consistency management
 *
 * The workspace provides a unified view of three parallel states:
 * 1. Profile State (Git branches): Authoritative source - what files *should* be tracked
 * 2. Deployment State (.git/dotta.db): Tracking layer - what files *have been* deployed
 * 3. Filesystem State (actual files): Physical reality - what files *actually* exist
 *
 * Detects and categorizes divergence between states to prevent data loss and provide
 * clear visibility into workspace consistency.
 *
 * Design principles:
 * - Holistic state analysis
 * - Divergence detection and categorization
 * - Validation gates for destructive operations
 * - Foundation for future features (auto-apply, conflict resolution)
 */

#ifndef DOTTA_WORKSPACE_H
#define DOTTA_WORKSPACE_H

#include <git2.h>
#include <types.h>

#include "base/output.h"
#include "core/state.h"
#include "infra/content.h"
#include "infra/mount.h"

/* Maximum number of display tags that can be extracted from a workspace item */
#define WORKSPACE_ITEM_MAX_DISPLAY_TAGS 5

/**
 * Diverged item entry
 *
 * Represents a single item (file or directory) with divergence between states.
 *
 * Items can be:
 * - Files (WORKSPACE_ITEM_FILE): Have content, tracked in profile and state,
 *   deployed to filesystem
 * - Directories (WORKSPACE_ITEM_DIRECTORY): Metadata-only, tracked in profile,
 *   never in deployment state (created implicitly when files are deployed)
 * - Use item_kind to distinguish between files and directories.
 *
 * Lifetime notes:
 * - filesystem_path, storage_path: borrowed from arena-backed manifest/state entries
 * - profile: arena_strdup'd (arena-owned, freed via arena_destroy)
 * - old_profile: borrowed from arena-backed manifest entry (can be NULL)
 */
typedef struct {
    char *filesystem_path;      /* Target path on filesystem (arena-borrowed) */
    char *storage_path;         /* Path in profile, e.g., home/.bashrc (arena-borrowed) */
    char *profile;              /* Winning profile name (arena-owned) */
    char *old_profile;          /* Previous profile from state, NULL if unchanged (arena-borrowed) */

    /* Item classification */
    workspace_state_t state;          /* Where the item exists (deployed/undeployed/etc.) */
    divergence_type_t divergence;     /* What's wrong with it (bit flags, can combine) */
    workspace_item_kind_t item_kind;  /* FILE or DIRECTORY (explicit type) */

    /* State flags */
    bool on_filesystem;         /* Exists on actual filesystem */
    bool profile_enabled;       /* Is source profile in workspace's enabled list? */
    bool profile_changed;       /* Profile differs from state (reassigned) */
} workspace_item_t;

/**
 * Bound carrier for a borrowed slice of workspace items
 *
 * Structural type — parallels state_files_t. Used at the
 * workspace_extract_orphans boundary so callers receive a typed handle
 * instead of triple-star out-params.
 *
 * Pass by value. Lifetime is dictated by the producer's documented
 * contract — workspace_extract_orphans returns heap-allocated buffers
 * (caller frees `entries`), other producers may borrow.
 */
typedef struct {
    const workspace_item_t *const *entries;
    size_t count;
} workspace_items_t;

/**
 * Workspace structure (opaque)
 *
 * Contains all three states and divergence analysis results.
 */
typedef struct workspace workspace_t;

/**
 * Forward declarations
 */
typedef struct scope scope_t;

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
 * Controls which analyses workspace_load() performs. All flags default to
 * false when zero-initialized. Build custom options by setting specific flags.
 *
 * Analysis dependencies are automatically resolved:
 * - analyze_orphans requires analyze_files (auto-enabled if needed)
 *
 * Lifetime: Options are read-only during workspace_load(), safe to stack-allocate.
 */
typedef struct {
    bool analyze_files;        /* File divergence detection */
    bool analyze_orphans;      /* Orphaned state validation (depends on analyze_files) */
    bool analyze_untracked;    /* Directory scanning for new files (EXPENSIVE!) */
    bool analyze_directories;  /* Directory metadata checks */
    bool analyze_encryption;   /* Encryption policy validation */
} workspace_load_t;

/**
 * Load workspace from repository
 *
 * Loads all three states and performs divergence analysis:
 * - Profile state: Files in profile branches
 * - Deployment state: Files tracked in .git/dotta.db
 * - Filesystem state: Actual files on disk
 *
 * Additionally scans tracked directories for untracked files (new files
 * that appeared in directories previously added via 'dotta add').
 *
 * The workspace is scoped to the caller's operation scope — specifically,
 * `scope_enabled(scope)`, the persistent VWD profile set. State entries
 * and tracked directories from profiles NOT in the enabled set are
 * ignored. This enforces the VWD invariant that workspace loading uses
 * the persistent enabled set rather than any CLI filter (operations like
 * `dotta status -p global` still load the full workspace and apply the
 * filter at display time via scope_accepts_profile).
 *
 * Profile loading: The workspace borrows the enabled name array from
 * the scope (caller must keep the scope alive until workspace_free).
 * Git tree loading is deferred to the rare stale repair path. In the
 * common (non-stale) case, workspace_load performs zero Git tree
 * operations for profile loading.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (must not be NULL, borrowed from caller;
 *              caller retains ownership and must free it after workspace_free)
 * @param scope Operation scope (must not be NULL; workspace reads
 *              scope_enabled(scope) as its profile set)
 * @param config Configuration (for ignore patterns, can be NULL)
 * @param content_cache Shared blob-content cache (must not be NULL;
 *              borrowed — lifetime must extend past workspace_free.
 *              Obtain from `ctx->content_cache` under crypto_mode == KEY_CACHE)
 * @param mounts Per-machine mount table covering scope_enabled(scope).
 *               Must not be NULL. Threaded through to manifest_reconcile
 *               in the load prelude. Callers pass `ctx->mounts` — read-
 *               only commands hold no binding-mutation between dispatch
 *               and workspace_load, so ctx->mounts is current.
 * @param options Analysis options (must not be NULL)
 * @param arena Borrowed allocator backing every workspace-lifetime
 *              string (manifest entries, diverged items, partition
 *              pointer arrays). Must outlive workspace_free; in practice
 *              `ctx->arena` (must not be NULL).
 * @param out Workspace (must not be NULL, caller must free with workspace_free)
 * @return Error or NULL on success
 */
error_t *workspace_load(
    git_repository *repo,
    state_t *state,
    const scope_t *scope,
    const struct config *config,
    content_cache_t *content_cache,
    const mount_table_t *mounts,
    const workspace_load_t *options,
    arena_t *arena,
    workspace_t **out
);

/**
 * Get workspace status
 *
 * Returns overall cleanliness assessment:
 * - WORKSPACE_CLEAN: No divergence detected
 * - WORKSPACE_DIRTY: Has warnings (undeployed, modified, deleted items)
 * - WORKSPACE_INVALID: Has errors (orphaned state entries)
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
 * Extract orphaned files and directories from workspace
 *
 * On-demand extraction that produces separated file and directory slices.
 * Encapsulates orphan filtering logic within the workspace module.
 *
 * Algorithm: Single pass over diverged items, pushing orphans into
 * per-kind ptr_array_t accumulators, then stealing the buffers into
 * the workspace_items_t outputs.
 *
 * Performance: O(N) where N = diverged count (single pass).
 *
 * Memory: Each output's `entries` field is heap-allocated (per
 * ptr_array_steal). Caller frees with `free(out_files->entries)` etc.
 * Items in the slice are borrowed (point into workspace's diverged array).
 *
 * Selective extraction: Pass NULL for any of out_files / out_dirs /
 * out_excluded to skip that extraction.
 *
 * Scope filtering: When `scope` is non-NULL, the full operation-scope
 * triplet (profile filter ∧ path filter ∧ ¬exclude) is applied. Orphans
 * rejected by the profile/path dimensions are dropped silently; orphans
 * rejected by the exclude dimension are counted via `out_excluded_count`
 * and optionally collected into `out_excluded` so the caller can emit a
 * per-item verbose trace and the "N orphaned files not removed" summary
 * without re-walking the workspace. A NULL scope is treated as match-all.
 *
 * Edge cases:
 * - No orphans: Returns success with all outputs zero-initialized.
 * - analyze_orphans=false during load: Returns success with zeros.
 * - Memory failure: Returns error, no partial allocation.
 * - scope filter with no matches: Returns success with zeros.
 *
 * @param ws Workspace (must not be NULL)
 * @param scope Optional operation scope (NULL = all orphans). When
 *              non-NULL, applies scope_accepts_profile ∧ scope_accepts_path
 *              ∧ ¬scope_is_excluded.
 * @param out_files Output file slice (caller frees entries, NULL to skip)
 * @param out_dirs Output directory slice (caller frees entries, NULL to skip)
 * @param out_excluded Output excluded-orphan slice (caller frees entries,
 *                     NULL to skip collection)
 * @param out_excluded_count Optional: count of orphans preserved because the
 *                           exclude dimension matched (NULL to skip).
 *                           Populated whether or not out_excluded is asked for.
 * @return Error or NULL on success
 */
error_t *workspace_extract_orphans(
    const workspace_t *ws,
    const scope_t *scope,
    workspace_items_t *out_files,
    workspace_items_t *out_dirs,
    workspace_items_t *out_excluded,
    size_t *out_excluded_count
);

/**
 * Get workspace item by filesystem path
 *
 * Returns the divergence information for a specific file or directory via
 * O(1) hashmap lookup. If the item exists in the workspace but has no
 * divergence (CLEAN), this returns NULL. Only items with divergence are
 * indexed.
 *
 * This function enables preflight to efficiently query workspace data
 * instead of re-analyzing files, eliminating redundant comparisons.
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
 * Data-centric approach: Accepts values directly instead of structs, enabling use with
 * both state rows (state_file_entry_t) and metadata (metadata_item_t) without conversion.
 *
 * Stat propagation: Caller must provide pre-captured stat to avoid redundant
 * syscalls. This function performs zero filesystem operations.
 *
 * @param expected_mode Expected permission mode (0 = skip mode check, no metadata tracked)
 * @param expected_owner Expected owner username (NULL = skip owner check)
 * @param expected_group Expected group name (NULL = skip group check)
 * @param st File stat data (must not be NULL, pre-captured by caller)
 * @param out_mode_differs Output flag for mode divergence (must not be NULL)
 * @param out_ownership_differs Output flag for ownership divergence (must not be NULL)
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
 * Get the active in-scope state file slice
 *
 * Returns a borrowed view over the state rows that the workspace
 * partitioned as in-scope and active (i.e., profile is in the enabled
 * set and lifecycle state is ACTIVE). Pure value return — no allocation,
 * no error path.
 *
 * The pointers reference rows in the arena snapshot returned by
 * state_get_all_files at workspace_load time; the arena outlives the
 * workspace so the slice is valid for the workspace's lifetime.
 *
 * Iterate via:
 *   state_files_t active = workspace_active(ws);
 *   for (size_t i = 0; i < active.count; i++) {
 *       const state_file_entry_t *file = active.entries[i];
 *       ...
 *   }
 *
 * @param ws Workspace (NULL returns an empty slice)
 * @return Borrowed slice over the active rows
 */
state_files_t workspace_active(const workspace_t *ws);

/**
 * Look up an active row by filesystem path
 *
 * O(1) random access over the active slice. Returns NULL if the path is
 * not in scope or its row is in a terminal lifecycle state — the
 * single chokepoint for "is this path managed and active?" probes.
 *
 * @param ws Workspace (NULL returns NULL)
 * @param filesystem_path Path to look up (NULL returns NULL)
 * @return Borrowed row pointer, or NULL if not active
 */
const state_file_entry_t *workspace_lookup_active(
    const workspace_t *ws,
    const char *filesystem_path
);

/**
 * Extract display tags and metadata from workspace item
 *
 * Translates workspace item state and divergence flags into presentation
 * tags, colors, and metadata strings for use with output_list builder.
 * Provides consistent item visualization across all commands.
 *
 * Tag Priority (for DEPLOYED state with divergence):
 *   1. "type" (RED) - File type changed (symlink ↔ regular), most severe
 *   2. "modified" (YELLOW) - Content divergence from profile
 *   3. Secondary: "mode", "ownership", "unencrypted" - Metadata divergence
 *
 * The function handles special cases:
 *   - TYPE divergence suppresses MODE tag (type change makes mode irrelevant)
 *   - ENCRYPTION divergence upgrades color to MAGENTA if not already RED
 *
 * Metadata Format:
 *   - "from {profile}" - Standard source profile
 *   - "{old} → {new}" - Profile reassignment transition
 *   - "in {profile}" - For untracked items
 *
 * Thread Safety: Uses only stack variables and string literals. Safe for
 * concurrent calls with different items.
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
 * Advance the deployment anchor with in-memory consistency
 *
 * Workspace-scope side of the routing invariant defined on
 * state_update_anchor (see state.h): persists via state_update_anchor and
 * assigns the canonical post-write anchor (returned by SQL RETURNING)
 * directly into the caller's row. The SQL UPDATE is the single specification
 * of preserve-on-zero / monotonic-once-set rules; this function holds none
 * of that logic.
 *
 * Single entry point for every workspace-scope anchor writer:
 *   - apply's adoption loop (ownership advance on first claim)
 *   - apply's post-deploy loop (ownership advance after write)
 *   - workspace_flush_anchor_updates (witness advance from slow-path)
 *
 * The row pointer is borrowed from the workspace's active partition (where
 * the workspace owns the storage as mutable; see workspace_active(),
 * workspace_lookup_active(), and ws->active in workspace.c). The const
 * decoration is a public-API guard against mutation by non-anchor callers;
 * this function casts internally to assign anchor in place.
 *
 * @param ws Workspace (must not be NULL, state must be open)
 * @param row Active row whose anchor should advance (must not be NULL,
 *            borrowed from workspace's active partition)
 * @param anchor New anchor (must not be NULL; blob_oid must be non-zero)
 * @return Error from state_update_anchor, or NULL on success
 */
error_t *workspace_advance_anchor(
    workspace_t *ws,
    const state_file_entry_t *row,
    const deployment_anchor_t *anchor
);

/**
 * Flush accumulated deployment-anchor advances to the state database
 *
 * During workspace_load(), files verified CMP_EQUAL via the slow path
 * (content hash comparison) accumulate (blob_oid, stat) pairs. This function
 * persists them as deployment-anchor advances so subsequent runs can both
 * short-circuit via the fast-path stat witness AND — if Git advances
 * blob_oid in the meantime — classify the file as stale directly from the
 * fast path instead of re-hashing.
 *
 * Routes through workspace_advance_anchor, so each persisted update also
 * assigns the canonical post-write anchor into its row — DB and memory
 * stay consistent for downstream readers in the same run.
 *
 * Self-healing: the first status/apply after profile enable verifies all
 * files via the slow path and seeds the anchor. The second call hits the
 * fast path for unchanged files and tags STALE directly for externally-
 * modified profiles.
 *
 * The deployed_at timestamp is intentionally not advanced here — this
 * flush is a witness advance, not a deployment event. Apply remains the
 * sole writer of anchor.deployed_at.
 *
 * Safe to call on any workspace — returns immediately if no updates pending.
 * Uses the workspace's internal state handle for database writes.
 *
 * @param ws Workspace (must not be NULL)
 * @return Error or NULL on success
 */
error_t *workspace_flush_anchor_updates(workspace_t *ws);

/**
 * Free workspace
 *
 * Frees all internal state and divergence analysis results.
 *
 * @param ws Workspace to free (can be NULL)
 */
void workspace_free(workspace_t *ws);

#endif /* DOTTA_WORKSPACE_H */
