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
 * Workspace structure (opaque)
 *
 * Contains all three states and divergence analysis results.
 */
typedef struct workspace workspace_t;

/**
 * Forward declarations
 */
typedef struct manifest manifest_t;
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
 * @param options Analysis options (must not be NULL)
 * @param out Workspace (must not be NULL, caller must free with workspace_free)
 * @return Error or NULL on success
 */
error_t *workspace_load(
    git_repository *repo,
    state_t *state,
    const scope_t *scope,
    const struct config *config,
    const workspace_load_t *options,
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
 * On-demand extraction that produces separated file and directory arrays.
 * Encapsulates orphan filtering logic within the workspace module.
 *
 * Algorithm: Single pass over diverged items, pushing orphans into
 * per-kind ptr_array_t accumulators, then stealing the buffers into
 * the output arrays.
 *
 * Performance: O(N) where N = diverged count (single pass).
 * Memory: Caller owns returned arrays and must free them.
 *         Items in arrays are borrowed (point into workspace's diverged array).
 *
 * Selective extraction: Pass NULL for out_file_orphans or out_dir_orphans
 * to skip that extraction. The corresponding count will be set to 0.
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
 * - No orphans: Returns success with counts=0, arrays=NULL
 * - analyze_orphans=false during load: Returns success with counts=0
 * - Memory failure: Returns error, no partial allocation
 * - scope filter with no matches: Returns success with counts=0
 *
 * @param ws Workspace (must not be NULL)
 * @param scope Optional operation scope (NULL = all orphans). When
 *              non-NULL, applies scope_accepts_profile ∧ scope_accepts_path
 *              ∧ ¬scope_is_excluded.
 * @param out_file_orphans Output file array (caller frees, NULL to skip)
 * @param out_file_count Output file count (set to 0 if out_file_orphans is NULL)
 * @param out_dir_orphans Output directory array (caller frees, NULL to skip)
 * @param out_dir_count Output directory count (set to 0 if out_dir_orphans is NULL)
 * @param out_excluded Optional: array of orphans dropped by the exclude
 *                     dimension (caller frees the array; items are
 *                     borrowed from workspace). NULL to skip collection.
 * @param out_excluded_count Optional: count of orphans preserved because the
 *                           exclude dimension matched (NULL to skip).
 *                           Populated whether or not out_excluded is asked for.
 * @return Error or NULL on success
 */
error_t *workspace_extract_orphans(
    const workspace_t *ws,
    const scope_t *scope,
    const workspace_item_t ***out_file_orphans,
    size_t *out_file_count,
    const workspace_item_t ***out_dir_orphans,
    size_t *out_dir_count,
    const workspace_item_t ***out_excluded,
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
 * both VWD cache (file_entry_t) and metadata (metadata_item_t) without conversion.
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
 * Get the manifest of files managed by the workspace
 *
 * Returns borrowed reference to the manifest built during workspace_load().
 * The manifest represents all files across all profiles in the workspace scope.
 * The manifest is owned by the workspace and remains valid until workspace_free()
 * is called.
 *
 * @param ws Workspace (must not be NULL)
 * @return Manifest (borrowed reference, never NULL for valid workspace)
 */
const manifest_t *workspace_get_manifest(const workspace_t *ws);

/**
 * Get content cache from workspace
 *
 * Returns the content cache used by the workspace for transparent
 * encryption/decryption. The cache is pre-populated during workspace
 * analysis and can be reused by commands to avoid redundant decryption.
 *
 * Typical usage: Pass to diff/show commands to reuse decrypted content
 * without redundant blob reads and decryption operations.
 *
 * @param ws Workspace (must not be NULL)
 * @return Content cache (borrowed reference, do not free, can be NULL)
 */
content_cache_t *workspace_get_content_cache(const workspace_t *ws);

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
 * Flush accumulated stat cache updates to the state database
 *
 * During workspace_load(), files verified clean via the slow path (content
 * comparison) accumulate stat cache updates. This function persists those
 * updates so subsequent runs benefit from the fast path.
 *
 * This makes the stat cache self-healing: the first status/apply after
 * profile enable verifies all files via the slow path and seeds the cache.
 * The second call hits the fast path for unchanged files.
 *
 * Safe to call on any workspace — returns immediately if no updates pending.
 * Uses the workspace's internal state handle for database writes.
 *
 * @param ws Workspace (must not be NULL)
 * @return Error or NULL on success
 */
error_t *workspace_flush_stat_caches(workspace_t *ws);

/**
 * Free workspace
 *
 * Frees all internal state and divergence analysis results.
 *
 * @param ws Workspace to free (can be NULL)
 */
void workspace_free(workspace_t *ws);

#endif /* DOTTA_WORKSPACE_H */
