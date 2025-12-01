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

#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "crypto/keymanager.h"
#include "infra/content.h"
#include "utils/output.h"

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
 * Memory layout optimized for cache locality: pointers grouped together to
 * fit in first cache line (64 bytes), followed by scalars.
 *
 * Lifetime notes:
 * - filesystem_path, storage_path, profile, metadata_profile, old_profile: owned strings (must free)
 * - source_profile: borrowed pointer, valid while workspace lives
 *   (workspace borrows profiles list from caller, so pointer is safe)
 */
typedef struct {
    char *filesystem_path;      /* Target path on filesystem (owned) */
    char *storage_path;         /* Path in profile, e.g., home/.bashrc (owned) */
    char *profile;              /* Winning profile name (owned) */
    char *metadata_profile;     /* Which profile's metadata won, can differ from profile (owned) */
    char *old_profile;          /* Previous profile from state, NULL if unchanged (owned) */

    /* Direct pointer to profile structure for convenience (borrowed, can be NULL if not enabled) */
    profile_t *source_profile;

    /* Item classification */
    workspace_state_t state;          /* Where the item exists (deployed/undeployed/etc.) */
    divergence_type_t divergence;     /* What's wrong with it (bit flags, can combine) */
    workspace_item_kind_t item_kind;  /* FILE or DIRECTORY (explicit type) */

    /* State flags */
    bool on_filesystem;         /* Exists on actual filesystem */
    bool profile_enabled;       /* Is source profile in workspace's enabled list? */
    bool profile_changed;       /* Profile differs from state (ownership changed) */
} workspace_item_t;

/**
 * Workspace structure (opaque)
 *
 * Contains all three states and divergence analysis results.
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
 * The workspace is scoped to the provided profiles. State entries
 * and tracked directories from profiles NOT in the list are ignored. This ensures
 * that operations like `dotta status -p global` only report divergence for the
 * specified profile, not the entire repository.
 *
 * State Ownership:
 * - If state is NULL: Workspace allocates its own state via state_load() and
 *   owns it (will free it in workspace_free). Use this for read-only operations
 *   like status and diff.
 * - If state is non-NULL: Workspace borrows the provided state and does NOT
 *   free it (caller remains responsible). Use this for transactional operations
 *   where the command has already opened a write transaction via
 *   state_load_for_update(). This ensures the workspace analyzes the state
 *   within the active transaction, not a stale committed snapshot.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (can be NULL)
 *              - NULL: Allocate read-only state internally (workspace owns it)
 *              - non-NULL: Borrow existing state (caller owns it, typically from
 *                state_load_for_update for transactional operations)
 * @param profiles Profile list to analyze (must not be NULL)
 * @param config Configuration (for ignore patterns, can be NULL)
 * @param options Analysis options (must not be NULL)
 * @param out Workspace (must not be NULL, caller must free with workspace_free)
 * @return Error or NULL on success
 */
error_t *workspace_load(
    git_repository *repo,
    state_t *state,
    profile_list_t *profiles,
    const struct dotta_config *config,
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
 * Get cached metadata for profile
 *
 * Returns pre-loaded metadata from the workspace cache (O(1) lookup).
 * The metadata cache is populated during workspace_load() for all profiles
 * in the workspace scope.
 *
 * Use this instead of metadata_load_from_branch() when you have a workspace
 * to avoid redundant Git operations. The returned metadata is owned by the
 * workspace and remains valid until workspace_free() is called.
 *
 * This is a performance optimization - operations that need metadata for
 * multiple profiles can reuse the cache instead of loading from Git repeatedly.
 *
 * @param ws Workspace (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @return Metadata or NULL if profile has no metadata (borrowed reference)
 */
const metadata_t *workspace_get_metadata(
    const workspace_t *ws,
    const char *profile_name
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
 * Get the deployment state from workspace
 *
 * Returns borrowed reference to the state_t that was loaded during
 * workspace_load(). The state is owned by the workspace and remains
 * valid until workspace_free() is called.
 *
 * This allows commands to access deployment state without redundant
 * loads, improving performance and reducing database connections.
 *
 * @param ws Workspace (must not be NULL)
 * @return State (borrowed reference, never NULL for valid workspace)
 */
const state_t *workspace_get_state(const workspace_t *ws);

/**
 * Get keymanager from workspace
 *
 * Returns the keymanager borrowed from global configuration. This is used
 * for content hashing and encryption operations. Can be NULL if encryption
 * is not configured.
 *
 * @param ws Workspace (must not be NULL)
 * @return Keymanager (borrowed reference, do not free, can be NULL)
 */
keymanager_t *workspace_get_keymanager(const workspace_t *ws);

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
 * Get metadata cache from workspace
 *
 * Returns the pre-loaded metadata cache (hashmap: profile_name → metadata_t*)
 * populated during workspace_load(). This cache remains valid for the
 * workspace's lifetime and can be passed to bulk operations that need
 * per-profile metadata without redundant loads.
 *
 * Typical usage: Pass to manifest_sync_files_bulk() to avoid redundant
 * metadata loads during batch operations.
 *
 * @param ws Workspace (must not be NULL)
 * @return Metadata cache hashmap (borrowed reference, do not free, can be NULL)
 */
const hashmap_t *workspace_get_metadata_cache(const workspace_t *ws);

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
 *   - Metadata from different profile shows "metadata from X" instead of "from X"
 *
 * Metadata Format:
 *   - "from {profile}" - Standard source profile
 *   - "metadata from {profile}" - Metadata-specific profile (differs from content)
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
 * Free workspace
 *
 * Frees all internal state and divergence analysis results.
 *
 * @param ws Workspace to free (can be NULL)
 */
void workspace_free(workspace_t *ws);

#endif /* DOTTA_WORKSPACE_H */
