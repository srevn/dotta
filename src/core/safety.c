/**
 * safety.c - Safety checks for destructive operations implementation
 */

#include "safety.h"

#include <git2.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "infra/compare.h"

/* Initial capacity for dynamic arrays */
#define INITIAL_CAPACITY 16

/* Initial capacity for profile tree cache (typically few profiles involved) */
#define PROFILE_TREE_CACHE_INITIAL_SIZE 8

/**
 * Profile tree cache entry
 */
typedef struct {
    char *profile_name;
    git_tree *tree;     /* NULL if profile doesn't exist */
    bool attempted;     /* True if we tried to load (to avoid repeated failures) */
} profile_tree_cache_t;

/**
 * Free profile tree cache entry callback (for hashmap)
 */
static void free_profile_tree_cache(void *entry) {
    if (!entry) {
        return;
    }
    profile_tree_cache_t *cache = (profile_tree_cache_t *)entry;
    free(cache->profile_name);
    if (cache->tree) {
        git_tree_free(cache->tree);
    }
    free(cache);
}

/**
 * Get or load profile tree from cache
 *
 * Returns NULL if profile doesn't exist (not an error).
 * Returns error only for fatal issues (memory allocation, etc.).
 */
static error_t *get_or_load_profile_tree(
    git_repository *repo,
    hashmap_t *tree_cache,
    const char *profile_name,
    git_tree **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree_cache);
    CHECK_NULL(profile_name);
    CHECK_NULL(out);

    /* Check cache first */
    profile_tree_cache_t *cached = hashmap_get(tree_cache, profile_name);
    if (cached) {
        *out = cached->tree;  /* May be NULL if profile doesn't exist */
        return NULL;
    }

    /* Not cached - try to load tree */
    git_tree *tree = NULL;
    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(refname, sizeof(refname),
                                        "refs/heads/%s", profile_name);
    if (!err) {
        err = gitops_load_tree(repo, refname, &tree);
    }

    /* Cache the result (even if NULL - profile doesn't exist) */
    profile_tree_cache_t *cache_entry = calloc(1, sizeof(profile_tree_cache_t));
    if (!cache_entry) {
        if (tree) git_tree_free(tree);
        return ERROR(ERR_MEMORY, "Failed to allocate cache entry");
    }

    cache_entry->profile_name = strdup(profile_name);
    if (!cache_entry->profile_name) {
        if (tree) git_tree_free(tree);
        free(cache_entry);
        return ERROR(ERR_MEMORY, "Failed to allocate profile name");
    }

    cache_entry->tree = tree;  /* May be NULL */
    cache_entry->attempted = true;

    /* Cache it */
    error_t *cache_err = hashmap_set(tree_cache, profile_name, cache_entry);
    if (cache_err) {
        free_profile_tree_cache(cache_entry);
        return cache_err;
    }

    /* Discard tree loading error (expected if profile deleted) */
    error_free(err);

    *out = tree;
    return NULL;
}

/**
 * Create violation and add to result
 */
static error_t *add_violation(
    safety_result_t *result,
    const char *filesystem_path,
    const char *reason,
    bool content_modified,
    const char *source_profile
) {
    CHECK_NULL(result);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(reason);

    /* Grow array if needed */
    if (result->count >= result->capacity) {
        size_t new_capacity = result->capacity == 0 ? INITIAL_CAPACITY : result->capacity * 2;

        /* Check for overflow */
        if (new_capacity > SIZE_MAX / sizeof(safety_violation_t)) {
            return ERROR(ERR_MEMORY, "Violations array too large");
        }

        safety_violation_t *new_violations = realloc(result->violations,
                                                       new_capacity * sizeof(safety_violation_t));
        if (!new_violations) {
            return ERROR(ERR_MEMORY, "Failed to grow violations array");
        }

        result->violations = new_violations;
        result->capacity = new_capacity;
    }

    /* Allocate strings */
    safety_violation_t *v = &result->violations[result->count];
    memset(v, 0, sizeof(safety_violation_t));

    v->filesystem_path = strdup(filesystem_path);
    v->reason = strdup(reason);
    v->content_modified = content_modified;
    v->source_profile = source_profile ? strdup(source_profile) : NULL;

    /* Check allocations */
    if (!v->filesystem_path || !v->reason ||
        (source_profile && !v->source_profile)) {
        free(v->filesystem_path);
        free(v->reason);
        free(v->source_profile);
        return ERROR(ERR_MEMORY, "Failed to allocate violation strings");
    }

    result->count++;
    return NULL;
}

/**
 * Try fast path: Check file using blob hash from state
 *
 * Returns true if fast path succeeded (file checked), false if fallback needed.
 * On success, updates result with violation if file is modified.
 */
static bool safety_fast_path_check(
    git_repository *repo,
    const char *fs_path,
    const char *state_hash,
    const char *source_profile,
    safety_result_t *result,
    error_t **out_err
) {
    *out_err = NULL;

    /* No hash - must use slow path */
    if (!state_hash) {
        return false;
    }

    /* Parse hash */
    git_oid blob_oid;
    if (git_oid_fromstr(&blob_oid, state_hash) != 0) {
        /* Invalid hash - use slow path */
        return false;
    }

    /* Try blob comparison */
    compare_result_t cmp_result;
    error_t *cmp_err = compare_blob_to_disk(repo, &blob_oid, fs_path, &cmp_result);

    if (!cmp_err) {
        /* Fast path succeeded! */
        if (cmp_result != CMP_EQUAL) {
            /* File is modified - add violation */
            const char *reason = NULL;
            bool content_mod = false;

            switch (cmp_result) {
                case CMP_DIFFERENT:
                    reason = "modified";
                    content_mod = true;
                    break;
                case CMP_MODE_DIFF:
                    reason = "mode_changed";
                    content_mod = false;
                    break;
                case CMP_TYPE_DIFF:
                    reason = "type_changed";
                    content_mod = true;
                    break;
                case CMP_MISSING:
                    reason = "deleted";
                    content_mod = false;
                    break;
                case CMP_EQUAL:
                    /* Unreachable */
                    break;
            }

            if (reason) {
                *out_err = add_violation(result, fs_path, reason, content_mod, source_profile);
            }
        }
        /* else: File matches Git - safe to remove */
        return true;
    }

    /* Fast path failed - check error type */
    if (cmp_err->code == ERR_NOT_FOUND || cmp_err->code == ERR_GIT) {
        /* Blob not found - likely profile deleted, use slow path */
        error_free(cmp_err);
        return false;
    }

    /* Other error (I/O, permission) - conservative: treat as unsafe */
    error_free(cmp_err);
    *out_err = add_violation(result, fs_path, "cannot_verify", false, source_profile);
    return true;  /* Don't try fallback */
}

/**
 * Check single orphaned file using tree-based comparison (fallback path)
 */
static error_t *check_file_with_tree(
    git_repository *repo,
    const char *filesystem_path,
    const char *storage_path,
    git_tree *profile_tree,
    const char *source_profile,
    safety_result_t *result
) {
    CHECK_NULL(repo);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(result);

    error_t *err = NULL;

    /* If profile tree is NULL, profile was deleted */
    if (!profile_tree) {
        return add_violation(result, filesystem_path, "profile_deleted",
                           false, source_profile);
    }

    /* Need storage_path to look up in tree */
    if (!storage_path) {
        return add_violation(result, filesystem_path, "cannot_verify",
                           false, source_profile);
    }

    /* Load tree entry from profile */
    git_tree_entry *tree_entry = NULL;
    int git_err = git_tree_entry_bypath(&tree_entry, profile_tree, storage_path);

    if (git_err < 0) {
        /* File not in profile tree - might have been removed from Git */
        return add_violation(result, filesystem_path, "file_removed",
                           false, source_profile);
    }

    /* Compare tree entry to disk */
    compare_result_t cmp_result;
    err = compare_tree_entry_to_disk(repo, tree_entry, filesystem_path, &cmp_result);

    git_tree_entry_free(tree_entry);

    if (err) {
        /* Cannot read file - permission issue or I/O error */
        error_free(err);
        return add_violation(result, filesystem_path, "cannot_verify",
                           false, source_profile);
    }

    /* Check comparison result */
    if (cmp_result != CMP_EQUAL) {
        const char *reason = NULL;
        bool content_mod = false;

        switch (cmp_result) {
            case CMP_DIFFERENT:
                reason = "modified";
                content_mod = true;
                break;
            case CMP_MODE_DIFF:
                reason = "mode_changed";
                content_mod = false;
                break;
            case CMP_TYPE_DIFF:
                reason = "type_changed";
                content_mod = true;
                break;
            case CMP_MISSING:
                /* Shouldn't happen - we checked fs_exists earlier */
                reason = "deleted";
                content_mod = false;
                break;
            case CMP_EQUAL:
                /* Shouldn't reach here */
                return NULL;
        }

        return add_violation(result, filesystem_path, reason, content_mod, source_profile);
    }

    return NULL;
}

/**
 * Find state entry by filesystem path
 *
 * Linear search through state entries. For typical use cases (small number of
 * orphaned files), this is more efficient than building a hashmap.
 */
static const state_file_entry_t *find_state_entry(
    const state_file_entry_t *state_entries,
    size_t state_count,
    const char *filesystem_path
) {
    for (size_t i = 0; i < state_count; i++) {
        if (strcmp(state_entries[i].filesystem_path, filesystem_path) == 0) {
            return &state_entries[i];
        }
    }
    return NULL;
}

/**
 * Check orphaned files for filesystem modifications
 */
error_t *safety_check_orphaned(
    git_repository *repo,
    const char **orphaned_paths,
    size_t orphaned_count,
    const state_file_entry_t *state_entries,
    size_t state_count,
    bool force,
    safety_result_t **out_result
) {
    CHECK_NULL(repo);
    CHECK_NULL(state_entries);
    CHECK_NULL(out_result);

    /* Allow NULL orphaned_paths if orphaned_count is 0 */
    if (orphaned_count > 0 && !orphaned_paths) {
        return ERROR(ERR_INVALID_ARG, "orphaned_paths cannot be NULL when orphaned_count > 0");
    }

    error_t *err = NULL;
    safety_result_t *result = NULL;
    hashmap_t *tree_cache = NULL;

    /* Allocate result */
    result = calloc(1, sizeof(safety_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate safety result");
    }

    /* If force is enabled or no orphaned files, return empty result */
    if (force || orphaned_count == 0) {
        *out_result = result;
        return NULL;
    }

    /* Create profile tree cache for fallback path */
    tree_cache = hashmap_create(PROFILE_TREE_CACHE_INITIAL_SIZE);
    if (!tree_cache) {
        safety_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to create tree cache");
    }

    /* Check each orphaned file for modifications */
    for (size_t i = 0; i < orphaned_count; i++) {
        const char *fs_path = orphaned_paths[i];

        /* Find corresponding state entry */
        const state_file_entry_t *state_entry = find_state_entry(state_entries, state_count, fs_path);
        if (!state_entry) {
            /* Shouldn't happen - orphaned paths should come from state */
            continue;
        }

        const char *source_profile = state_entry->profile;
        const char *storage_path = state_entry->storage_path;

        /* Check if file exists on filesystem */
        if (!fs_exists(fs_path)) {
            /* Already deleted from filesystem - safe to prune from state */
            continue;
        }

        /* File exists - need to verify it's unmodified before removal */
        /* Try fast path: compare using state hash */
        error_t *check_err = NULL;
        bool fast_path_succeeded = safety_fast_path_check(
            repo, fs_path, state_entry->hash, source_profile, result, &check_err
        );

        if (check_err) {
            /* Error during fast path check */
            hashmap_free(tree_cache, free_profile_tree_cache);
            safety_result_free(result);
            return error_wrap(check_err, "Failed to check file");
        }

        /* Fallback to slow path if fast path didn't succeed */
        if (!fast_path_succeeded) {
            git_tree *profile_tree = NULL;
            err = get_or_load_profile_tree(repo, tree_cache, source_profile, &profile_tree);
            if (err) {
                /* Fatal error (memory allocation, cache failure) */
                hashmap_free(tree_cache, free_profile_tree_cache);
                safety_result_free(result);
                return error_wrap(err, "Failed to load profile tree");
            }

            /* Check file using tree-based comparison */
            err = check_file_with_tree(repo, fs_path, storage_path, profile_tree,
                                      source_profile, result);
            if (err) {
                hashmap_free(tree_cache, free_profile_tree_cache);
                safety_result_free(result);
                return error_wrap(err, "Failed to check file");
            }
        }
    }

    /* Cleanup cache */
    hashmap_free(tree_cache, free_profile_tree_cache);

    /* Check if we found any violations */
    if (result->count > 0) {
        *out_result = result;
        return ERROR(ERR_CONFLICT,
                    "Cannot remove %zu orphaned file%s with uncommitted changes",
                    result->count,
                    result->count == 1 ? "" : "s");
    }

    /* No violations - safe to proceed */
    *out_result = result;
    return NULL;
}

/**
 * Free safety violation
 */
void safety_violation_free(safety_violation_t *violation) {
    if (!violation) {
        return;
    }

    free(violation->filesystem_path);
    free(violation->reason);
    free(violation->source_profile);
    free(violation);
}

/**
 * Free safety result
 */
void safety_result_free(safety_result_t *result) {
    if (!result) {
        return;
    }

    /* Free all violations */
    for (size_t i = 0; i < result->count; i++) {
        free(result->violations[i].filesystem_path);
        free(result->violations[i].reason);
        free(result->violations[i].source_profile);
    }

    free(result->violations);
    free(result);
}
