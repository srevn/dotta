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
 * Lifetime notes:
 * - filesystem_path, storage_path, profile, metadata_profile: owned strings (must free)
 * - source_profile: borrowed pointer, valid while workspace lives
 *   (workspace borrows profiles list from caller, so pointer is safe)
 */
typedef struct {
    char *filesystem_path;      /* Target path on filesystem */
    char *storage_path;         /* Path in profile (e.g., home/.bashrc) */
    char *profile;              /* Source profile name (owned string) */
    char *metadata_profile;     /* Which profile's metadata won (can differ from profile) */

    /* Direct pointer to profile for convenience (borrowed, can be NULL if profile not in enabled set) */
    profile_t *source_profile;  /* Borrowed - valid while workspace lives */

    divergence_type_t type;     /* Divergence category */

    /* Item classification */
    workspace_item_kind_t item_kind;  /* FILE or DIRECTORY (explicit type) */

    /* State flags */
    bool in_profile;            /* Exists in profile branch */
    bool in_state;              /* Exists in deployment state (only meaningful for FILES) */
    bool on_filesystem;         /* Exists on actual filesystem */
    bool content_differs;       /* Content changed (only meaningful for FILES) */

    /* Secondary metadata divergences (can both be true simultaneously) */
    bool mode_differs;          /* Permissions/mode changed from metadata */
    bool ownership_differs;     /* Owner/group changed from metadata (requires root) */

    /* Scope tracking */
    bool profile_enabled;       /* Is source profile in workspace's enabled list? */

    /* Profile change tracking (ownership changes between profiles) */
    bool profile_changed;       /* Profile differs from state (ownership changed) */
    char *old_profile;          /* Profile from state (NULL if not changed, owned) */
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
 * false when zero-initialized. Use workspace_load_default() for all analyses
 * enabled, or build custom options by setting specific flags.
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
 * Get default workspace load options
 *
 * Returns options with ALL analyses enabled. This matches the current
 * behavior of workspace_load() and provides backward compatibility.
 *
 * @return Default options (all analyses enabled)
 */
workspace_load_t workspace_load_default(void);

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
 * @param options Analysis options (can be NULL for defaults)
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
 * Get diverged items by category
 *
 * Returns a dynamically allocated array of pointers to matching diverged items.
 * The array contains only items (files or directories) of the specified type.
 *
 * The returned pointers reference the workspace's internal data and remain
 * valid until the workspace is freed. However, the array itself must be freed
 * by the caller using free().
 *
 * @param ws Workspace (must not be NULL)
 * @param type Divergence type to query
 * @param count Output count of matching entries (must not be NULL)
 * @return Allocated array of pointers to matching items, or NULL if none match or on error.
 *         Caller must free() the array (but not the pointed-to entries).
 */
const workspace_item_t **workspace_get_diverged(
    const workspace_t *ws,
    divergence_type_t type,
    size_t *count
);

/**
 * Get diverged items by category with optional profile scope filtering
 *
 * Returns items matching the specified divergence type, optionally
 * filtered by profile_enabled flag.
 *
 * The returned pointers reference the workspace's internal data and remain
 * valid until the workspace is freed. However, the array itself must be freed
 * by the caller using free().
 *
 * Use cases:
 * - status: enabled_only=true (only show enabled profiles)
 * - apply: enabled_only=false (cleanup all orphans including disabled)
 *
 * @param ws Workspace (must not be NULL)
 * @param type Divergence type to query
 * @param enabled_only If true, only return items where profile_enabled=true
 * @param count Output count of matching entries (must not be NULL)
 * @return Allocated array of pointers, or NULL if none. Caller must free().
 */
const workspace_item_t **workspace_get_diverged_filtered(
    const workspace_t *ws,
    divergence_type_t type,
    bool enabled_only,
    size_t *count
);

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
 * Check if item has divergence
 *
 * Checks if a specific item (file or directory) has any divergence.
 *
 * @param ws Workspace (must not be NULL)
 * @param filesystem_path Item path to check (must not be NULL)
 * @param type Output divergence type (can be NULL)
 * @return true if diverged
 */
bool workspace_item_diverged(
    const workspace_t *ws,
    const char *filesystem_path,
    divergence_type_t *type
);

/**
 * Validate workspace for operation
 *
 * Checks if workspace is suitable for the given operation.
 * Returns error if workspace is in invalid state.
 *
 * Validation rules:
 * - WORKSPACE_INVALID always fails (orphaned state)
 * - WORKSPACE_DIRTY fails if allow_dirty=false
 * - WORKSPACE_CLEAN always succeeds
 *
 * @param ws Workspace (must not be NULL)
 * @param operation Operation name for error messages (must not be NULL)
 * @param allow_dirty Allow dirty workspace (warnings only)
 * @return Error or NULL if valid
 */
error_t *workspace_validate(
    const workspace_t *ws,
    const char *operation,
    bool allow_dirty
);

/**
 * Get divergence count by type
 *
 * Returns count of items (files and directories) with specified divergence.
 *
 * @param ws Workspace (must not be NULL)
 * @param type Divergence type
 * @return Count of items
 */
size_t workspace_count_divergence(
    const workspace_t *ws,
    divergence_type_t type
);

/**
 * Check if workspace is clean
 *
 * Convenience function - equivalent to workspace_get_status() == WORKSPACE_CLEAN
 *
 * @param ws Workspace (must not be NULL)
 * @return true if clean
 */
bool workspace_is_clean(const workspace_t *ws);

/**
 * Free workspace
 *
 * Frees all internal state and divergence analysis results.
 *
 * @param ws Workspace to free (can be NULL)
 */
void workspace_free(workspace_t *ws);

#endif /* DOTTA_WORKSPACE_H */
