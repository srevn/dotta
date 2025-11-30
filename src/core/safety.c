/**
 * safety.c - Data loss prevention for file removal operations
 *
 * Validates that files scheduled for removal don't have uncommitted changes.
 * Used by the `apply` command when pruning orphaned files.
 *
 * Key optimizations:
 * - Fast path: Works for both encrypted and plaintext files
 * - Content cache reuse: Avoids re-decryption of files from preflight checks
 * - Metadata pass-through: Avoids repeated Git operations
 * - Adaptive lookup: Linear search for small batches, hashmap for large
 * - Profile tree caching: Loads each profile tree only once per batch
 */

#include "safety.h"

#include <errno.h>
#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/metadata.h"
#include "core/state.h"
#include "core/workspace.h"
#include "crypto/keymanager.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"

/* Initial capacity for dynamic arrays */
#define INITIAL_CAPACITY 16

/* Threshold for switching from linear search to hashmap (empirically tuned) */
#define HASHMAP_THRESHOLD 20

/* Initial size for profile tree cache (typically few profiles involved) */
#define PROFILE_TREE_CACHE_SIZE 8

/**
 * Profile tree cache entry
 *
 * Caches loaded trees to avoid repeated Git operations in batch checks.
 * The `attempted` flag prevents repeated failed lookups for deleted profiles.
 */
typedef struct {
    char *profile_name;
    git_tree *tree;      /* NULL if profile doesn't exist */
    bool attempted;      /* True if we tried to load (even if failed) */
} profile_tree_cache_t;

/**
 * Free profile tree cache entry (hashmap callback)
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
 * Returns NULL if profile doesn't exist (not an error - expected case).
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

    /* Insert into cache */
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
 * Add violation to result
 *
 * Grows the violations array if needed and adds a new entry.
 * Uses direct struct manipulation for efficiency.
 */
static error_t *add_violation(
    safety_result_t *result,
    const char *filesystem_path,
    const char *storage_path,
    const char *source_profile,
    const char *reason,
    bool content_modified
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

    /* Add violation directly to array (no extra allocation) */
    safety_violation_t *v = &result->violations[result->count];
    memset(v, 0, sizeof(safety_violation_t));

    v->filesystem_path = strdup(filesystem_path);
    v->storage_path = storage_path ? strdup(storage_path) : NULL;
    v->source_profile = source_profile ? strdup(source_profile) : NULL;
    v->reason = strdup(reason);
    v->content_modified = content_modified;

    /* Check allocations */
    if (!v->filesystem_path || !v->reason ||
        (storage_path && !v->storage_path) ||
        (source_profile && !v->source_profile)) {
        free(v->filesystem_path);
        free(v->storage_path);
        free(v->source_profile);
        free(v->reason);
        memset(v, 0, sizeof(safety_violation_t));
        return ERROR(ERR_MEMORY, "Failed to allocate violation strings");
    }

    result->count++;
    return NULL;
}

/**
 * Try fast path: Check file using state entry (VWD)
 *
 * Verifies file safety using the Virtual Working Directory (state entry) as the
 * authoritative source. The state entry contains all properties captured when
 * the file was deployed, including encryption flag and file type.
 *
 * Returns:
 *   true  - Verification completed (check out_err for violation)
 *   false - Verification couldn't complete (caller should try slow path)
 *
 * Trust Model:
 *   The state entry is authoritative because it represents what was actually
 *   deployed. It persists even after the profile is deleted, ensuring we can
 *   always verify orphaned files correctly.
 *
 * Defense-in-Depth:
 *   On content load failure, returns false to allow slow path verification.
 *   This handles edge cases where state might have incorrect encrypted flag
 *   (though rare, the slow path can recover by loading from Git tree).
 *
 * Architecture:
 * - Unified content layer: Both encrypted and plaintext files use same code path
 * - Cache optimization: Reuses cached content when available (avoids redundant I/O)
 * - Type from state: Uses state_entry->type for correct symlink/executable handling
 * - Encryption from state: Uses state_entry->encrypted (always correct)
 *
 * Fast path advantages:
 * - O(1) blob lookup vs O(log n) tree traversal
 * - Only requires hash string, no Git tree loading
 * - Cache benefits for ALL file types (not just encrypted)
 * - Succeeds in 99% of cases (profile not deleted, hash available)
 *
 * @param repo Git repository (must not be NULL)
 * @param state_entry State entry with file properties from VWD (must not be NULL)
 * @param keymanager Key manager for decryption (can be NULL, uses global)
 * @param cache Content cache for performance (can be NULL)
 * @param result Safety result to populate (must not be NULL)
 * @param out_err Error output for violations (must not be NULL)
 * @return true if verification completed, false if slow path should be tried
 */
static bool try_fast_path_check(
    git_repository *repo,
    const state_file_entry_t *state_entry,
    keymanager_t *keymanager,
    content_cache_t *cache,
    safety_result_t *result,
    error_t **out_err
) {
    *out_err = NULL;

    /* Step 1: Precondition validation (Fast path eligibility)
     *
     * If any required field is missing, fall to slow path which can load
     * the data from Git tree directly.
     */
    if (!state_entry->blob_oid || !state_entry->storage_path ||
        !state_entry->filesystem_path || !state_entry->profile) {
        return false;  /* Missing data - slow path can load from tree */
    }

    /* Parse blob OID from string */
    git_oid blob_oid;
    if (git_oid_fromstr(&blob_oid, state_entry->blob_oid) != 0) {
        return false;  /* Invalid OID format - slow path can load from tree */
    }

    /* Step 2: Derive file properties from state (VWD authority)
     *
     * State entry is authoritative - populated from Git when profile enabled.
     * - Encryption flag from state (always correct, even for deleted profiles)
     * - File type from state (handles symlinks correctly)
     */

    /* Map state file type to git filemode */
    git_filemode_t expected_mode = state_type_to_git_filemode(state_entry->type);

    /* Encryption flag from state - this is always correct because
     * state was populated from Git metadata when the profile was enabled */
    bool encrypted = state_entry->encrypted;

    /* Step 3: File existence check (I/O optimization)
     *
     * Check before loading content to avoid unnecessary blob lookup/decryption.
     */
    struct stat file_stat;
    memset(&file_stat, 0, sizeof(file_stat));

    if (lstat(state_entry->filesystem_path, &file_stat) != 0) {
        if (errno == ENOENT) {
            return true;  /* File already deleted - safe to prune state */
        }
        return false;  /* Stat failed for other reason - try slow path */
    }

    /* Step 4: Content verification (defense-in-depth)
     *
     * Load blob, decrypt if needed, compare to disk.
     * On content load failure, fall to slow path which loads from Git tree.
     * This handles the rare case where state has wrong encrypted flag.
     */
    const buffer_t *plaintext = NULL;
    bool owns_buffer = false;
    error_t *err = NULL;

    if (cache) {
        /* Optimal: Use cache (avoids re-decryption/re-load) */
        err = content_cache_get_from_blob_oid(
            cache, &blob_oid, state_entry->storage_path,
            state_entry->profile, encrypted, &plaintext
        );
    } else {
        /* Fallback: Load/decrypt directly */
        buffer_t *temp = NULL;
        keymanager_t *km = keymanager ? keymanager : keymanager_get_global(NULL);
        err = content_get_from_blob_oid(
            repo, &blob_oid, state_entry->storage_path, state_entry->profile,
            encrypted, km, &temp
        );
        plaintext = temp;
        owns_buffer = (err == NULL);
    }

    if (err) {
        /* Content loading failed - fall to slow path for independent verification
         * This provides defense-in-depth: if state has wrong blob_oid or wrong
         * encrypted flag, slow path loads fresh from Git and may succeed. */
        error_free(err);
        return false;  /* Fall to slow path instead of CANNOT_VERIFY */
    }

    /* Compare content to disk */
    compare_result_t cmp_result;
    err = compare_buffer_to_disk(plaintext, state_entry->filesystem_path,
                                 expected_mode, &file_stat, &cmp_result, &file_stat);

    if (owns_buffer) {
        buffer_free((buffer_t *)plaintext);
    }

    if (err) {
        error_free(err);
        /* Check if file was deleted during comparison (race condition) */
        if (!fs_exists(state_entry->filesystem_path)) {
            return true;  /* File gone - safe */
        }
        /* Comparison failed for other reason - report CANNOT_VERIFY */
        *out_err = add_violation(result, state_entry->filesystem_path,
                                 state_entry->storage_path, state_entry->profile,
                                 SAFETY_REASON_CANNOT_VERIFY, false);
        return true;
    }

    /* Step 5: Result evaluation (comparison outcome) */
    if (cmp_result == CMP_MISSING) {
        return true;  /* File deleted - safe */
    }

    if (cmp_result == CMP_DIFFERENT) {
        *out_err = add_violation(result, state_entry->filesystem_path,
                                 state_entry->storage_path, state_entry->profile,
                                 SAFETY_REASON_MODIFIED, true);
        return true;
    }

    if (cmp_result == CMP_TYPE_DIFF) {
        *out_err = add_violation(result, state_entry->filesystem_path,
                                 state_entry->storage_path, state_entry->profile,
                                 SAFETY_REASON_TYPE_CHANGED, true);
        return true;
    }

    /* Step 6: Permission verification (CMP_EQUAL case)
     *
     * Two-phase check:
     * - Phase A: Git filemode (executable bit) - skip for symlinks
     * - Phase B: Full metadata (mode + ownership) from state
     */
    bool mode_changed = false;

    /* PHASE A: Git filemode (executable bit) - skip for symlinks
     * Symlinks don't have deployable permissions (chmod on symlink changes target
     * or fails depending on OS). */
    if (expected_mode != GIT_FILEMODE_LINK) {
        bool expect_exec = (expected_mode == GIT_FILEMODE_BLOB_EXECUTABLE);
        bool is_exec = fs_stat_is_executable(&file_stat);
        if (expect_exec != is_exec) {
            mode_changed = true;
        }
    }

    /* PHASE B: Full metadata (mode + ownership) from state
     * Only check if state has mode set (0 means no metadata tracked). */
    if (!mode_changed && state_entry->mode != 0) {
        bool mode_differs = false;
        bool ownership_differs = false;
        error_t *check_err = check_item_metadata_divergence(
            state_entry->mode, state_entry->owner, state_entry->group,
            &file_stat, &mode_differs, &ownership_differs
        );

        if (check_err == NULL && (mode_differs || ownership_differs)) {
            mode_changed = true;
        }
        error_free(check_err);
    }

    if (mode_changed) {
        *out_err = add_violation(result, state_entry->filesystem_path,
                                 state_entry->storage_path, state_entry->profile,
                                 SAFETY_REASON_MODE_CHANGED, false);
    }

    return true;  /* Verification completed */
}

/**
 * Check file using tree-based comparison (fallback/slow path)
 *
 * Provides defense-in-depth by verifying files using Git tree directly,
 * completely independent of state database. This path is used when:
 * - Fast path cannot verify (missing blob_oid, content load failure)
 * - Profile tree needs to be consulted for definitive verification
 *
 * Trust Model:
 *   This path trusts Git only - all file properties are loaded from the
 *   Git tree and metadata file within that tree. This provides independent
 *   verification from the fast path (which trusts state/VWD).
 *
 * Data Sources (ALL from Git, NONE from state):
 * - encrypted    <- metadata_load_from_tree()
 * - file type    <- git_tree_entry_filemode()
 * - permissions  <- Git tree metadata
 * - blob content <- git_tree_entry_id()
 *
 * Terminal Results:
 * - Profile tree NULL    -> CANNOT_VERIFY (defense-in-depth, unreachable with precondition)
 * - File not in tree     -> FILE_REMOVED
 * - Any verification failure -> CANNOT_VERIFY (conservative)
 *
 * @param repo Git repository (must not be NULL)
 * @param filesystem_path Path on disk (must not be NULL)
 * @param storage_path Path in profile tree (can be NULL -> CANNOT_VERIFY)
 * @param source_profile Profile name (can be NULL)
 * @param profile_tree Git tree for profile (NULL -> CANNOT_VERIFY, defensive only)
 * @param tree_metadata_cache Cache of profile -> metadata_t* loaded from Git
 * @param keymanager Key manager for decryption (can be NULL, uses global)
 * @param result Safety result to populate (must not be NULL)
 * @return NULL on success, error on fatal failure
 */
static error_t *check_file_with_tree(
    git_repository *repo,
    const char *filesystem_path,
    const char *storage_path,
    const char *source_profile,
    git_tree *profile_tree,
    hashmap_t *tree_metadata_cache,
    keymanager_t *keymanager,
    safety_result_t *result
) {
    CHECK_NULL(repo);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(result);

    /* Profile tree not available - defensive check
     *
     * With the branch existence check in the main loop, this path should
     * be unreachable. Keep for defense-in-depth in case:
     * - Future code changes break the invariant
     * - Function called from different context
     */
    if (!profile_tree) {
        return add_violation(result, filesystem_path, storage_path,
                             source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
    }

    /* Need storage_path to look up in tree */
    if (!storage_path) {
        return add_violation(result, filesystem_path, storage_path,
                             source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
    }

    /* Step 1: Load tree entry from Git */
    git_tree_entry *tree_entry = NULL;
    int git_err = git_tree_entry_bypath(&tree_entry, profile_tree, storage_path);

    if (git_err < 0) {
        /* File not in profile tree - might have been removed from Git */
        return add_violation(result, filesystem_path, storage_path,
                             source_profile, SAFETY_REASON_FILE_REMOVED, false);
    }

    /* Step 2: Load metadata from Git tree (defense-in-depth)
     *
     * Key to independence: fast path uses state, slow path uses Git.
     * This provides two independent verification sources.
     */
    metadata_t *tree_metadata = NULL;
    bool owns_metadata = false;
    error_t *err = NULL;

    /* Check cache first (O(1) lookup) */
    if (tree_metadata_cache && source_profile) {
        tree_metadata = hashmap_get(tree_metadata_cache, source_profile);
    }

    if (!tree_metadata && source_profile) {
        /* Cache miss - load metadata from Git tree */
        err = metadata_load_from_tree(repo, profile_tree, source_profile, &tree_metadata);

        if (err) {
            if (err->code == ERR_NOT_FOUND) {
                /* No metadata file in tree - files are plaintext by default */
                error_free(err);
                error_t *create_err = metadata_create_empty(&tree_metadata);
                if (create_err) {
                    error_free(create_err);
                    git_tree_entry_free(tree_entry);
                    return add_violation(result, filesystem_path, storage_path,
                                         source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
                }
            } else {
                /* Real error loading metadata */
                error_free(err);
                git_tree_entry_free(tree_entry);
                return add_violation(result, filesystem_path, storage_path,
                                     source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
            }
        }

        /* Cache for subsequent files from same profile */
        if (tree_metadata_cache && tree_metadata) {
            error_t *cache_err = hashmap_set(tree_metadata_cache, source_profile, tree_metadata);
            if (cache_err) {
                /* Cache failed - we still own metadata, proceed without caching */
                error_free(cache_err);
                owns_metadata = true;
            }
            /* If cache succeeded, cache now owns tree_metadata */
        } else {
            owns_metadata = true;
        }
    }

    /* Step 3: Content verification (Git-based comparison)
     *
     * All properties come from Git tree - file mode, encryption flag, content.
     */
    buffer_t *content = NULL;
    git_filemode_t tree_mode = git_tree_entry_filemode(tree_entry);

    keymanager_t *km = keymanager ? keymanager : keymanager_get_global(NULL);

    /* Extract encrypted flag from Git metadata */
    bool encrypted = false;
    if (tree_metadata) {
        encrypted = metadata_get_file_encrypted(tree_metadata, storage_path);
    }

    err = content_get_from_tree_entry(
        repo,
        tree_entry,
        storage_path,
        source_profile,
        encrypted,
        km,
        &content
    );

    if (err) {
        /* Failed to get content - conservative: cannot verify */
        error_free(err);
        if (owns_metadata) metadata_free(tree_metadata);
        git_tree_entry_free(tree_entry);
        return add_violation(result, filesystem_path, storage_path,
                             source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
    }

    /* Compare content to disk */
    compare_result_t cmp_result;
    struct stat file_stat;
    err = compare_buffer_to_disk(content, filesystem_path, tree_mode, NULL,
                                 &cmp_result, &file_stat);

    buffer_free(content);
    git_tree_entry_free(tree_entry);

    if (err) {
        error_free(err);
        /* Check if file was deleted during comparison (race condition) */
        if (!fs_exists(filesystem_path)) {
            if (owns_metadata) metadata_free(tree_metadata);
            return NULL;  /* File gone - safe */
        }
        /* Comparison failed for other reason - report CANNOT_VERIFY */
        if (owns_metadata) metadata_free(tree_metadata);
        return add_violation(result, filesystem_path, storage_path,
                             source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
    }

    /* Step 4: Result evaluation (comparison outcome) */
    if (cmp_result == CMP_MISSING) {
        if (owns_metadata) metadata_free(tree_metadata);
        return NULL;  /* File deleted - safe */
    }

    if (cmp_result == CMP_DIFFERENT) {
        if (owns_metadata) metadata_free(tree_metadata);
        return add_violation(result, filesystem_path, storage_path,
                             source_profile, SAFETY_REASON_MODIFIED, true);
    }

    if (cmp_result == CMP_TYPE_DIFF) {
        if (owns_metadata) metadata_free(tree_metadata);
        return add_violation(result, filesystem_path, storage_path,
                             source_profile, SAFETY_REASON_TYPE_CHANGED, true);
    }

    /* Step 5: Permission verification (Git metadata source)
     *
     * Two-phase check:
     * - Phase A: Git filemode (executable bit) - skip for symlinks
     * - Phase B: Full metadata from Git tree
     */
    bool mode_changed = false;

    /* Phase A: Git filemode - skip for symlinks */
    if (tree_mode != GIT_FILEMODE_LINK) {
        bool expect_exec = (tree_mode == GIT_FILEMODE_BLOB_EXECUTABLE);
        bool is_exec = fs_stat_is_executable(&file_stat);
        if (expect_exec != is_exec) {
            mode_changed = true;
        }
    }

    /* Phase B: Full metadata from Git tree */
    if (!mode_changed && tree_metadata) {
        const metadata_item_t *meta_entry = NULL;
        error_t *meta_err = metadata_get_item(tree_metadata, storage_path, &meta_entry);

        if (meta_err == NULL && meta_entry && meta_entry->kind == METADATA_ITEM_FILE) {
            bool mode_differs = false;
            bool ownership_differs = false;
            error_t *check_err = check_item_metadata_divergence(
                meta_entry->mode, meta_entry->owner, meta_entry->group,
                &file_stat, &mode_differs, &ownership_differs
            );

            if (check_err == NULL && (mode_differs || ownership_differs)) {
                mode_changed = true;
            }
            error_free(check_err);
        }
        error_free(meta_err);
    }

    if (owns_metadata) metadata_free(tree_metadata);

    if (mode_changed) {
        return add_violation(result, filesystem_path, storage_path,
                             source_profile, SAFETY_REASON_MODE_CHANGED, false);
    }

    return NULL;  /* File verified safe */
}

/**
 * Find state entry by filesystem path (linear search)
 *
 * Used for small batches where hashmap overhead isn't justified.
 * For typical use cases (< 20 orphaned files), this is faster than building a hashmap.
 */
static const state_file_entry_t *find_state_entry_linear(
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
 * Check files for removal safety
 *
 * Verifies that files scheduled for removal haven't been modified locally.
 * Uses two-tier verification with independent data sources:
 *
 * - Fast path: Uses state entry (VWD) as authoritative source
 * - Slow path: Falls back to Git tree for defense-in-depth
 */
error_t *safety_check_removal(
    git_repository *repo,
    const state_t *state,
    char **filesystem_paths,
    size_t path_count,
    bool force,
    keymanager_t *keymanager,
    content_cache_t *cache,
    safety_result_t **out_result
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(out_result);

    /* Allow NULL filesystem_paths if path_count is 0 */
    if (path_count > 0 && !filesystem_paths) {
        return ERROR(ERR_INVALID_ARG, "filesystem_paths cannot be NULL when path_count > 0");
    }

    error_t *err = NULL;
    safety_result_t *result = NULL;
    state_file_entry_t *state_entries = NULL;
    size_t state_count = 0;
    hashmap_t *state_index = NULL;         /* Used only if path_count >= HASHMAP_THRESHOLD */
    hashmap_t *tree_cache = NULL;          /* Profile tree cache for slow path */
    hashmap_t *tree_metadata_cache = NULL; /* Metadata cache for slow path (loaded from Git) */

    /* Allocate result */
    result = calloc(1, sizeof(safety_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate safety result");
    }

    /* If force or no files, return empty result */
    if (force || path_count == 0) {
        *out_result = result;
        return NULL;
    }

    /* Load all state entries */
    err = state_get_all_files(state, &state_entries, &state_count);
    if (err) {
        safety_result_free(result);
        return error_wrap(err, "Failed to load state for safety check");
    }

    /* Adaptive lookup strategy: hashmap for large batches, linear for small
     *
     * Use hashmap when:
     * 1. Many paths to check (path_count >= HASHMAP_THRESHOLD), OR
     * 2. Linear search cost exceeds hashmap overhead (path_count * state_count >= threshold²)
     *
     * This prevents O(n*m) blowup when checking few paths against many state entries.
     */
    bool use_hashmap = (path_count >= HASHMAP_THRESHOLD) ||
                       (path_count * state_count >= HASHMAP_THRESHOLD * HASHMAP_THRESHOLD);

    if (use_hashmap) {
        /* Build hashmap for O(1) state lookups */
        state_index = hashmap_create(state_count > 0 ? state_count : INITIAL_CAPACITY);
        if (!state_index) {
            state_free_all_files(state_entries, state_count);
            safety_result_free(result);
            return ERROR(ERR_MEMORY, "Failed to create state index");
        }

        /* Populate state index */
        for (size_t i = 0; i < state_count; i++) {
            err = hashmap_set(state_index, state_entries[i].filesystem_path, &state_entries[i]);
            if (err) {
                hashmap_free(state_index, NULL);
                state_free_all_files(state_entries, state_count);
                safety_result_free(result);
                return error_wrap(err, "Failed to populate state index");
            }
        }
    }

    /* Create profile tree cache for slow path */
    tree_cache = hashmap_create(PROFILE_TREE_CACHE_SIZE);
    if (!tree_cache) {
        if (state_index) hashmap_free(state_index, NULL);
        state_free_all_files(state_entries, state_count);
        safety_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to create tree cache");
    }

    /* Create tree metadata cache for slow path (independent Git loading)
     *
     * This cache stores metadata loaded directly from Git trees, providing
     * true defense-in-depth. Each profile's metadata is loaded at most once.
     * Lifecycle: Created here, freed at ALL exit points after this line.
     */
    tree_metadata_cache = hashmap_create(PROFILE_TREE_CACHE_SIZE);
    if (!tree_metadata_cache) {
        hashmap_free(tree_cache, free_profile_tree_cache);
        if (state_index) hashmap_free(state_index, NULL);
        state_free_all_files(state_entries, state_count);
        safety_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to create tree metadata cache");
    }

    /* Main verification loop (Two-tier architecture)
     *
     * For each file:
     * - Look up state entry (VWD) - authoritative source
     * - Try fast path (trusts state)
     * - Fall to slow path if needed (trusts Git)
     */
    for (size_t i = 0; i < path_count; i++) {
        const char *fs_path = filesystem_paths[i];

        /* Find corresponding state entry (O(1) hashmap or O(n) linear) */
        const state_file_entry_t *state_entry = NULL;
        if (use_hashmap) {
            state_entry = hashmap_get(state_index, fs_path);
        } else {
            state_entry = find_state_entry_linear(state_entries, state_count, fs_path);
        }

        if (!state_entry) {
            /* File not in state - skip (shouldn't happen for orphaned files) */
            continue;
        }

        /* Check if file exists on filesystem (fast existence check) */
        if (!fs_exists(fs_path)) {
            /* Already deleted from filesystem - safe to prune from state */
            continue;
        }

        /* BRANCH EXISTENCE PRECONDITION CHECK
         *
         * Must check branch existence BEFORE any verification. This determines:
         * 1. Whether verification is meaningful (branch exists -> can verify)
         * 2. What to do when branch is deleted (controlled vs external deletion)
         *
         * Key insight: Checking FIRST provides consistent behavior regardless of
         * Git garbage collection timing. Without this, fast path might succeed
         * (blob exists) or fail (blob GC'd), producing different results for
         * the same semantic case — confusing and incoherent.
         *
         * Performance: Tree loading is cached per profile (hashmap lookup after
         * first file). Most orphans are from the same profile, so this adds
         * ~1 hashmap lookup per file, not a tree load per file.
         */
        git_tree *profile_tree = NULL;
        err = get_or_load_profile_tree(repo, tree_cache,
                                       state_entry->profile, &profile_tree);
        if (err) {
            /* Fatal error (memory allocation, etc.) */
            hashmap_free(tree_metadata_cache, (void(*)(void*))metadata_free);
            hashmap_free(tree_cache, free_profile_tree_cache);
            if (state_index) hashmap_free(state_index, NULL);
            state_free_all_files(state_entries, state_count);
            safety_result_free(result);
            return error_wrap(err, "Failed to load profile tree for '%s'", state_entry->profile);
        }

        if (!profile_tree) {
            /* Branch deleted - determine action based on lifecycle state */
            bool is_controlled_deletion = state_entry->state &&
                                          strcmp(state_entry->state, STATE_INACTIVE) == 0;

            if (is_controlled_deletion) {
                /* CONTROLLED DELETION
                 *
                 * Entry marked STATE_INACTIVE by manifest_disable_profile() while
                 * the branch still existed. The removal intent was recorded with
                 * full verification capability at that time.
                 *
                 * Trust the recorded intent UNCONDITIONALLY:
                 * - No verification needed (intent validated when recorded)
                 * - No violation (removal is pre-approved)
                 * - File will be removed by cleanup
                 *
                 * This provides consistent behavior regardless of Git GC timing.
                 * The alternative (try fast path first) creates confusing violations
                 * referencing deleted profiles when blob exists but content differs.
                 *
                 * Follows Git staging model:
                 *   profile disable = git rm (staging)
                 *   apply = git commit (execution)
                 */
                continue;  /* Safe to remove - no violation */
            } else {
                /* EXTERNAL DELETION
                 *
                 * Profile branch deleted outside dotta (e.g., git branch -D).
                 * State entry is still ACTIVE (never went through controlled flow).
                 *
                 * Cannot verify: No branch = no reference to compare against.
                 * Cannot trust intent: User didn't request deletion via dotta.
                 *
                 * Safe choice: "Release" the file from management
                 * - Leave file on filesystem (protect user data)
                 * - Track for state cleanup (can't manage without profile)
                 * - Non-blocking (inform user, don't prevent operation)
                 */
                err = add_violation(result, fs_path, state_entry->storage_path,
                                    state_entry->profile, SAFETY_REASON_RELEASED, false);
                if (err) {
                    hashmap_free(tree_metadata_cache, (void(*)(void*))metadata_free);
                    hashmap_free(tree_cache, free_profile_tree_cache);
                    if (state_index) hashmap_free(state_index, NULL);
                    state_free_all_files(state_entries, state_count);
                    safety_result_free(result);
                    return error_wrap(err, "Failed to add released violation for '%s'", fs_path);
                }
                continue;
            }
        }

        /* Fast path: Trust state entry
         *
         * State entry contains all properties from deployment - persists even
         * after profile deletion. Returns true if verification completed.
         */
        error_t *check_err = NULL;
        bool fast_path_succeeded = try_fast_path_check(
            repo, state_entry, keymanager, cache, result, &check_err
        );

        if (check_err) {
            /* Error during fast path check - FATAL (add_violation failed) */
            hashmap_free(tree_metadata_cache, (void(*)(void*))metadata_free);
            hashmap_free(tree_cache, free_profile_tree_cache);
            if (state_index) hashmap_free(state_index, NULL);
            state_free_all_files(state_entries, state_count);
            safety_result_free(result);
            return error_wrap(check_err, "Failed to check file '%s'", fs_path);
        }

        /* Slow path: Trust Git only (defense-in-depth)
         *
         * Used when fast path can't verify (missing blob_oid, content failure).
         * profile_tree already loaded above, guaranteed non-NULL here.
         */
        if (!fast_path_succeeded) {
            /* Check file using tree-based comparison (independent data source) */
            err = check_file_with_tree(
                repo, fs_path, state_entry->storage_path, state_entry->profile,
                profile_tree, tree_metadata_cache, keymanager, result
            );

            if (err) {
                hashmap_free(tree_metadata_cache, (void(*)(void*))metadata_free);
                hashmap_free(tree_cache, free_profile_tree_cache);
                if (state_index) hashmap_free(state_index, NULL);
                state_free_all_files(state_entries, state_count);
                safety_result_free(result);
                return error_wrap(err, "Failed to check file '%s'", fs_path);
            }
        }
    }

    /* Cleanup */
    hashmap_free(tree_metadata_cache, (void(*)(void*))metadata_free);
    hashmap_free(tree_cache, free_profile_tree_cache);
    if (state_index) hashmap_free(state_index, NULL);
    state_free_all_files(state_entries, state_count);

    /* Return result (caller checks result->count for violations) */
    *out_result = result;
    return NULL;
}

/**
 * Free safety result
 *
 * Frees all violations (inline in array) and the result structure itself.
 */
void safety_result_free(safety_result_t *result) {
    if (!result) {
        return;
    }

    /* Free all violations */
    for (size_t i = 0; i < result->count; i++) {
        free(result->violations[i].filesystem_path);
        free(result->violations[i].storage_path);
        free(result->violations[i].source_profile);
        free(result->violations[i].reason);
    }

    free(result->violations);
    free(result);
}
