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

#include "types.h"
#include "core/state.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "utils/config.h"

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
 *
 * Use item_kind to distinguish between files and directories. Invariant:
 * directories always have in_state == false.
 *
 * Memory layout optimized for cache locality: pointers grouped together to
 * fit in first cache line (64 bytes), followed by scalars.
 *
 * Lifetime notes:
 * - filesystem_path, storage_path, profile, metadata_profile, old_profile: owned strings (must free)
 * - all_profiles: owned array, must free with string_array_free()
 * - source_profile: borrowed pointer, valid while workspace lives
 *   (workspace borrows profiles list from caller, so pointer is safe)
 */
typedef struct {
    char *filesystem_path;      /* Target path on filesystem (owned) */
    char *storage_path;         /* Path in profile, e.g., home/.bashrc (owned) */
    char *profile;              /* Winning profile name (owned) */
    char *metadata_profile;     /* Which profile's metadata won, can differ from profile (owned) */
    char *old_profile;          /* Previous profile from state, NULL if unchanged (owned) */

    /* All enabled profiles containing this file (multi-profile overlap tracking) */
    string_array_t *all_profiles;

    /* Direct pointer to profile structure for convenience (borrowed, can be NULL if not enabled) */
    profile_t *source_profile;

    /* Item classification */
    workspace_state_t state;             /* Where the item exists (deployed/undeployed/etc.) */
    divergence_type_t divergence;        /* What's wrong with it (bit flags, can combine) */
    workspace_item_kind_t item_kind;     /* FILE or DIRECTORY (explicit type) */
    manifest_status_t manifest_status;   /* Manifest status from VWD (pending/deployed/pending_removal) */

    /* State flags */
    bool in_profile;            /* Exists in profile branch */
    bool in_state;              /* Exists in deployment state (only for FILES) */
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
 * @param repo Git repository (must not be NULL)
 * @param profiles Profile list to analyze (must not be NULL)
 * @param config Configuration (for ignore patterns, can be NULL)
 * @param options Analysis options (must not be NULL)
 * @param out Workspace (must not be NULL, caller must free with workspace_free)
 * @return Error or NULL on success
 */
error_t *workspace_load(
    git_repository *repo,
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
 * Check for metadata (mode and ownership) divergence
 *
 * Compares filesystem metadata with stored metadata to detect changes in
 * permissions (mode) and ownership (user/group). Checks both independently.
 *
 * Works for both FILE and DIRECTORY metadata kinds.
 *
 * Stat propagation: Caller must provide pre-captured stat to avoid redundant
 * syscalls. This function performs zero filesystem operations.
 *
 * @param item Metadata item (FILE or DIRECTORY, must not be NULL)
 * @param fs_path Filesystem path (for error messages, must not be NULL)
 * @param st File stat data (must not be NULL, pre-captured by caller)
 * @param out_mode_differs Output flag for mode divergence (must not be NULL)
 * @param out_ownership_differs Output flag for ownership divergence (must not be NULL)
 * @return Error or NULL on success
 */
error_t *check_item_metadata_divergence(
    const metadata_item_t *item,
    const char *fs_path,
    const struct stat *st,
    bool *out_mode_differs,
    bool *out_ownership_differs
);

/**
 * Get the repository associated with the workspace
 *
 * Returns borrowed reference to the git_repository that the workspace
 * was loaded from. The repository is owned by the caller of workspace_load()
 * and remains valid until that caller closes it.
 *
 * @param ws Workspace (must not be NULL)
 * @return Repository (borrowed reference, never NULL for valid workspace)
 */
git_repository *workspace_get_repo(const workspace_t *ws);

/**
 * Get the list of profiles managed by the workspace
 *
 * Returns borrowed reference to the profile_list_t that defines the
 * workspace scope. The profile list is owned by the caller of workspace_load()
 * and remains valid until that caller frees it.
 *
 * @param ws Workspace (must not be NULL)
 * @return Profile list (borrowed reference, never NULL for valid workspace)
 */
const profile_list_t *workspace_get_profiles(const workspace_t *ws);

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
 * Get merged metadata from workspace
 *
 * Returns metadata merged across all profiles in precedence order (global → OS → host).
 * The workspace pre-computes merged metadata during workspace_load() by applying
 * profile precedence. This function efficiently builds a new metadata_t from that
 * pre-merged view, avoiding redundant merge operations.
 *
 * Convenience function for commands that need merged metadata (e.g., apply, deploy).
 * The returned metadata is a new allocation - caller receives ownership and must
 * free with metadata_free().
 *
 * Performance: O(N) where N = unique items across all profiles. This is significantly
 * more efficient than re-merging from scratch when profiles have overlapping items.
 * If you only need metadata for a specific profile, use workspace_get_metadata() instead.
 *
 * @param ws Workspace (must not be NULL)
 * @param out Merged metadata (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success
 */
error_t *workspace_get_merged_metadata(
    const workspace_t *ws,
    metadata_t **out
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
