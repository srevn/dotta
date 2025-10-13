/**
 * workspace.c - Workspace abstraction implementation
 *
 * Manages three-state consistency: Profile (Git), Deployment (state.json), Filesystem (disk).
 * Detects and categorizes divergence to prevent data loss and enable safe operations.
 */

#include "workspace.h"

#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/compare.h"
#include "utils/array.h"
#include "utils/hashmap.h"

/**
 * Workspace structure
 *
 * Contains indexed views of all three states plus divergence analysis.
 * Uses hashmaps for O(1) lookups during analysis.
 */
struct workspace {
    git_repository *repo;          /* Borrowed reference */

    /* State data */
    manifest_t *manifest;          /* Profile state (owned) */
    state_t *state;                /* Deployment state (owned) */
    hashmap_t *manifest_index;     /* Maps filesystem_path -> file_entry_t* */

    /* Divergence tracking */
    workspace_file_t *diverged;    /* Array of diverged files */
    size_t diverged_count;
    size_t diverged_capacity;

    /* Status cache */
    workspace_status_t status;
    bool status_computed;
};

/**
 * Create empty workspace
 */
static error_t *workspace_create_empty(git_repository *repo, workspace_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    workspace_t *ws = calloc(1, sizeof(workspace_t));
    if (!ws) {
        return ERROR(ERR_MEMORY, "Failed to allocate workspace");
    }

    ws->repo = repo;
    ws->manifest_index = hashmap_create(256);  /* Initial capacity */
    if (!ws->manifest_index) {
        free(ws);
        return ERROR(ERR_MEMORY, "Failed to create manifest index");
    }

    ws->diverged = NULL;
    ws->diverged_count = 0;
    ws->diverged_capacity = 0;
    ws->status = WORKSPACE_CLEAN;
    ws->status_computed = false;

    *out = ws;
    return NULL;
}

/**
 * Add diverged file to workspace
 */
static error_t *workspace_add_diverged(
    workspace_t *ws,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    divergence_type_t type,
    bool in_profile,
    bool in_state,
    bool on_filesystem,
    bool content_differs
) {
    CHECK_NULL(ws);
    CHECK_NULL(filesystem_path);

    /* Grow array if needed */
    if (ws->diverged_count >= ws->diverged_capacity) {
        size_t new_capacity = ws->diverged_capacity == 0 ? 32 : ws->diverged_capacity * 2;
        workspace_file_t *new_diverged = realloc(ws->diverged,
                                                  new_capacity * sizeof(workspace_file_t));
        if (!new_diverged) {
            return ERROR(ERR_MEMORY, "Failed to grow diverged array");
        }
        ws->diverged = new_diverged;
        ws->diverged_capacity = new_capacity;
    }

    /* Add entry */
    workspace_file_t *entry = &ws->diverged[ws->diverged_count];
    memset(entry, 0, sizeof(workspace_file_t));

    entry->filesystem_path = strdup(filesystem_path);
    entry->storage_path = storage_path ? strdup(storage_path) : NULL;
    entry->profile = profile ? strdup(profile) : NULL;
    entry->type = type;
    entry->in_profile = in_profile;
    entry->in_state = in_state;
    entry->on_filesystem = on_filesystem;
    entry->content_differs = content_differs;

    if (!entry->filesystem_path ||
        (storage_path && !entry->storage_path) ||
        (profile && !entry->profile)) {
        free(entry->filesystem_path);
        free(entry->storage_path);
        free(entry->profile);
        return ERROR(ERR_MEMORY, "Failed to allocate diverged entry");
    }

    ws->diverged_count++;
    return NULL;
}

/**
 * Build manifest index for O(1) lookups
 */
static error_t *workspace_build_manifest_index(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->manifest);

    for (size_t i = 0; i < ws->manifest->count; i++) {
        file_entry_t *entry = &ws->manifest->entries[i];
        error_t *err = hashmap_set(ws->manifest_index,
                                   entry->filesystem_path,
                                   entry);
        if (err) {
            return error_wrap(err, "Failed to index manifest entry");
        }
    }

    return NULL;
}

/**
 * Analyze single file for divergence
 */
static error_t *analyze_file_divergence(
    workspace_t *ws,
    const file_entry_t *manifest_entry,
    const state_file_entry_t *state_entry
) {
    CHECK_NULL(ws);
    CHECK_NULL(manifest_entry);

    const char *fs_path = manifest_entry->filesystem_path;
    const char *storage_path = manifest_entry->storage_path;
    const char *profile = manifest_entry->source_profile->name;

    bool in_profile = true;  /* By definition - we're iterating manifest */
    bool in_state = (state_entry != NULL);
    bool on_filesystem = fs_lexists(fs_path);
    bool content_differs = false;
    divergence_type_t div_type = DIVERGENCE_CLEAN;

    /* Case 1: File not deployed (in profile, not in state) */
    if (!in_state) {
        div_type = DIVERGENCE_UNDEPLOYED;
    }
    /* Case 2: File deployed but missing from filesystem */
    else if (in_state && !on_filesystem) {
        div_type = DIVERGENCE_DELETED;
    }
    /* Case 3: File deployed and exists - check for modifications */
    else if (in_state && on_filesystem) {
        compare_result_t cmp_result;
        error_t *err = compare_tree_entry_to_disk(
            ws->repo,
            manifest_entry->entry,
            fs_path,
            &cmp_result
        );

        if (err) {
            return error_wrap(err, "Failed to compare '%s'", fs_path);
        }

        switch (cmp_result) {
            case CMP_EQUAL:
                /* Clean - no divergence */
                return NULL;

            case CMP_DIFFERENT:
                div_type = DIVERGENCE_MODIFIED;
                content_differs = true;
                break;

            case CMP_MODE_DIFF:
                div_type = DIVERGENCE_MODE_DIFF;
                content_differs = false;
                break;

            case CMP_TYPE_DIFF:
                div_type = DIVERGENCE_TYPE_DIFF;
                content_differs = true;
                break;

            case CMP_MISSING:
                /* Shouldn't happen - we checked on_filesystem above */
                div_type = DIVERGENCE_DELETED;
                break;
        }
    }

    /* Add to diverged list if not clean */
    if (div_type != DIVERGENCE_CLEAN) {
        return workspace_add_diverged(ws, fs_path, storage_path, profile,
                                     div_type, in_profile, in_state,
                                     on_filesystem, content_differs);
    }

    return NULL;
}

/**
 * Analyze state for orphaned entries
 */
static error_t *analyze_orphaned_state(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);

    /* Get all files in state */
    size_t state_file_count = 0;
    const state_file_entry_t *state_files = state_get_all_files(ws->state, &state_file_count);

    /* Check each state entry */
    for (size_t i = 0; i < state_file_count; i++) {
        const state_file_entry_t *state_entry = &state_files[i];
        const char *fs_path = state_entry->filesystem_path;

        /* Check if this file exists in manifest (profile state) */
        file_entry_t *manifest_entry = hashmap_get(ws->manifest_index, fs_path);

        if (!manifest_entry) {
            /* Orphaned: In state but not in any profile */
            bool on_filesystem = fs_lexists(fs_path);

            error_t *err = workspace_add_diverged(
                ws,
                fs_path,
                state_entry->storage_path,
                state_entry->profile,
                DIVERGENCE_ORPHANED,
                false,     /* not in profile */
                true,      /* in state */
                on_filesystem,
                false      /* content_differs N/A */
            );

            if (err) {
                return err;
            }
        }
    }

    return NULL;
}

/**
 * Perform divergence analysis
 */
static error_t *workspace_analyze_divergence(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->manifest);
    CHECK_NULL(ws->state);

    error_t *err = NULL;

    /* Analyze each file in manifest */
    for (size_t i = 0; i < ws->manifest->count; i++) {
        const file_entry_t *manifest_entry = &ws->manifest->entries[i];

        /* Check if file is in deployment state */
        const state_file_entry_t *state_entry = NULL;
        error_t *lookup_err = state_get_file(ws->state,
                                             manifest_entry->filesystem_path,
                                             &state_entry);

        if (lookup_err && lookup_err->code != ERR_NOT_FOUND) {
            /* Real error */
            return lookup_err;
        }

        /* Not found is OK - means not deployed */
        if (lookup_err) {
            error_free(lookup_err);
            state_entry = NULL;
        }

        /* Analyze this file */
        err = analyze_file_divergence(ws, manifest_entry, state_entry);
        if (err) {
            return err;
        }
    }

    /* Analyze state for orphaned entries */
    err = analyze_orphaned_state(ws);
    if (err) {
        return err;
    }

    return NULL;
}

/**
 * Compute workspace status
 */
static workspace_status_t compute_workspace_status(const workspace_t *ws) {
    if (!ws) {
        return WORKSPACE_INVALID;
    }

    bool has_orphaned = false;
    bool has_warnings = false;

    for (size_t i = 0; i < ws->diverged_count; i++) {
        const workspace_file_t *file = &ws->diverged[i];

        switch (file->type) {
            case DIVERGENCE_ORPHANED:
                has_orphaned = true;
                break;

            case DIVERGENCE_UNDEPLOYED:
            case DIVERGENCE_MODIFIED:
            case DIVERGENCE_DELETED:
            case DIVERGENCE_MODE_DIFF:
            case DIVERGENCE_TYPE_DIFF:
                has_warnings = true;
                break;

            case DIVERGENCE_CLEAN:
                /* Should not be in diverged list */
                break;
        }
    }

    if (has_orphaned) {
        return WORKSPACE_INVALID;
    } else if (has_warnings) {
        return WORKSPACE_DIRTY;
    } else {
        return WORKSPACE_CLEAN;
    }
}

/**
 * Load workspace from repository
 */
error_t *workspace_load(
    git_repository *repo,
    profile_list_t *profiles,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    workspace_t *ws = NULL;
    error_t *err = NULL;

    /* Create empty workspace */
    err = workspace_create_empty(repo, &ws);
    if (err) {
        return err;
    }

    /* Load profile state (manifest) */
    err = profile_build_manifest(repo, profiles, &ws->manifest);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to build manifest");
    }

    /* Build manifest index for O(1) lookups */
    err = workspace_build_manifest_index(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to build manifest index");
    }

    /* Load deployment state */
    err = state_load(repo, &ws->state);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to load state");
    }

    /* Perform divergence analysis */
    err = workspace_analyze_divergence(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to analyze divergence");
    }

    /* Compute status */
    ws->status = compute_workspace_status(ws);
    ws->status_computed = true;

    *out = ws;
    return NULL;
}

/**
 * Get workspace status
 */
workspace_status_t workspace_get_status(const workspace_t *ws) {
    if (!ws) {
        return WORKSPACE_INVALID;
    }
    return ws->status;
}

/**
 * Get diverged files by category
 */
const workspace_file_t *workspace_get_diverged(
    const workspace_t *ws,
    divergence_type_t type,
    size_t *count
) {
    if (!ws || !count) {
        if (count) *count = 0;
        return NULL;
    }

    /* For CLEAN, return nothing */
    if (type == DIVERGENCE_CLEAN) {
        *count = 0;
        return NULL;
    }

    /* Count matching entries (we'll return a subset view) */
    *count = 0;
    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (ws->diverged[i].type == type) {
            (*count)++;
        }
    }

    /* If none found, return NULL */
    if (*count == 0) {
        return NULL;
    }

    /* Return pointer to first matching entry
     * NOTE: This is a simple implementation that returns the whole array.
     * Caller must check type field to find matching entries.
     * A more sophisticated implementation would build a filtered array.
     */
    *count = 0;  /* Reset and recount with proper return */
    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (ws->diverged[i].type == type) {
            if (*count == 0) {
                /* Return pointer to first match, but set count correctly */
                size_t match_count = 0;
                for (size_t j = i; j < ws->diverged_count; j++) {
                    if (ws->diverged[j].type == type) {
                        match_count++;
                    }
                }
                *count = match_count;
                /* Note: This simple implementation requires caller to filter.
                 * For Phase 1, we'll return all and let caller filter.
                 */
                break;
            }
        }
    }

    /* Simpler approach: just return whole array with type filtering by caller */
    *count = 0;
    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (ws->diverged[i].type == type) {
            (*count)++;
        }
    }

    return ws->diverged;  /* Caller must filter by type */
}

/**
 * Get all diverged files
 */
const workspace_file_t *workspace_get_all_diverged(
    const workspace_t *ws,
    size_t *count
) {
    if (!ws || !count) {
        if (count) *count = 0;
        return NULL;
    }

    *count = ws->diverged_count;
    return ws->diverged;
}

/**
 * Check if file has divergence
 */
bool workspace_file_diverged(
    const workspace_t *ws,
    const char *filesystem_path,
    divergence_type_t *type
) {
    if (!ws || !filesystem_path) {
        return false;
    }

    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (strcmp(ws->diverged[i].filesystem_path, filesystem_path) == 0) {
            if (type) {
                *type = ws->diverged[i].type;
            }
            return true;
        }
    }

    if (type) {
        *type = DIVERGENCE_CLEAN;
    }
    return false;
}

/**
 * Validate workspace for operation
 */
error_t *workspace_validate(
    const workspace_t *ws,
    const char *operation,
    bool allow_dirty
) {
    CHECK_NULL(ws);
    CHECK_NULL(operation);

    workspace_status_t status = workspace_get_status(ws);

    switch (status) {
        case WORKSPACE_CLEAN:
            return NULL;  /* All good */

        case WORKSPACE_DIRTY:
            if (allow_dirty) {
                return NULL;  /* Warnings only */
            }
            return ERROR(ERR_VALIDATION,
                        "Cannot %s: workspace has divergence (use --force or resolve first)",
                        operation);

        case WORKSPACE_INVALID:
            return ERROR(ERR_VALIDATION,
                        "Cannot %s: workspace has orphaned state entries (run 'dotta check --fix')",
                        operation);
    }

    return ERROR(ERR_INTERNAL, "Unknown workspace status");
}

/**
 * Get divergence count by type
 */
size_t workspace_count_divergence(
    const workspace_t *ws,
    divergence_type_t type
) {
    if (!ws) {
        return 0;
    }

    size_t count = 0;
    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (ws->diverged[i].type == type) {
            count++;
        }
    }

    return count;
}

/**
 * Check if workspace is clean
 */
bool workspace_is_clean(const workspace_t *ws) {
    return workspace_get_status(ws) == WORKSPACE_CLEAN;
}

/**
 * Free workspace
 */
void workspace_free(workspace_t *ws) {
    if (!ws) {
        return;
    }

    /* Free diverged entries */
    for (size_t i = 0; i < ws->diverged_count; i++) {
        free(ws->diverged[i].filesystem_path);
        free(ws->diverged[i].storage_path);
        free(ws->diverged[i].profile);
    }
    free(ws->diverged);

    /* Free manifest index (values are borrowed from manifest) */
    hashmap_free(ws->manifest_index, NULL);

    /* Free owned state */
    manifest_free(ws->manifest);
    state_free(ws->state);

    free(ws);
}
