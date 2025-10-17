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
#include "core/profiles.h"
#include "utils/config.h"

/**
 * Diverged file entry
 *
 * Represents a single file with divergence between the three states.
 */
typedef struct {
    char *filesystem_path;      /* Target path on filesystem */
    char *storage_path;         /* Path in profile (e.g., home/.bashrc) */
    char *profile;              /* Source profile name */
    divergence_type_t type;     /* Divergence category */

    /* State flags */
    bool in_profile;            /* Exists in profile branch */
    bool in_state;              /* Exists in deployment state */
    bool on_filesystem;         /* Exists on actual filesystem */
    bool content_differs;       /* Content changed (if on filesystem) */
} workspace_file_t;

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
 * @param repo Git repository (must not be NULL)
 * @param profiles Profile list to analyze (must not be NULL)
 * @param config Configuration (for ignore patterns, can be NULL)
 * @param out Workspace (must not be NULL, caller must free with workspace_free)
 * @return Error or NULL on success
 */
error_t *workspace_load(
    git_repository *repo,
    profile_list_t *profiles,
    const struct dotta_config *config,
    workspace_t **out
);

/**
 * Get workspace status
 *
 * Returns overall cleanliness assessment:
 * - WORKSPACE_CLEAN: No divergence detected
 * - WORKSPACE_DIRTY: Has warnings (undeployed, modified, deleted files)
 * - WORKSPACE_INVALID: Has errors (orphaned state entries)
 *
 * @param ws Workspace (must not be NULL)
 * @return Status enum
 */
workspace_status_t workspace_get_status(const workspace_t *ws);

/**
 * Get diverged files by category
 *
 * Returns a dynamically allocated array of pointers to matching diverged files.
 * The array contains only files of the specified type.
 *
 * The returned pointers reference the workspace's internal data and remain
 * valid until the workspace is freed. However, the array itself must be freed
 * by the caller using free().
 *
 * @param ws Workspace (must not be NULL)
 * @param type Divergence type to query
 * @param count Output count of matching entries (must not be NULL)
 * @return Allocated array of pointers to matching files, or NULL if none match or on error.
 *         Caller must free() the array (but not the pointed-to entries).
 *
 * Example:
 *   size_t count;
 *   const workspace_file_t **modified = workspace_get_diverged(ws, DIVERGENCE_MODIFIED, &count);
 *   if (modified) {
 *       for (size_t i = 0; i < count; i++) {
 *           printf("%s\n", modified[i]->filesystem_path);
 *       }
 *       free(modified);  // Free the pointer array only
 *   }
 */
const workspace_file_t **workspace_get_diverged(
    const workspace_t *ws,
    divergence_type_t type,
    size_t *count
);

/**
 * Get all diverged files
 *
 * Returns array of all files with any divergence.
 *
 * @param ws Workspace (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Array of files (borrowed reference, do not free)
 */
const workspace_file_t *workspace_get_all_diverged(
    const workspace_t *ws,
    size_t *count
);

/**
 * Check if file has divergence
 *
 * Checks if a specific file has any divergence.
 *
 * @param ws Workspace (must not be NULL)
 * @param filesystem_path File to check (must not be NULL)
 * @param type Output divergence type (can be NULL)
 * @return true if diverged
 */
bool workspace_file_diverged(
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
 * Returns count of files with specified divergence.
 *
 * @param ws Workspace (must not be NULL)
 * @param type Divergence type
 * @return Count of files
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
