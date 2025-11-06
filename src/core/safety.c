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

#include <git2.h>
#include <stdint.h>
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
 * Try fast path: Check file using blob hash from state
 *
 * Returns true if fast path succeeded (file checked), false if fallback needed.
 * On success, updates result with violation if file is modified.
 *
 * Architecture:
 * - Unified content layer: Both encrypted and plaintext files use same code path
 * - Cache optimization: Reuses cached content when available (avoids redundant I/O)
 * - Transparent handling: Content layer automatically detects and decrypts encrypted files
 * - Mode accuracy: Gets file mode from metadata for precise permission comparison
 *
 * Fast path advantages:
 * - O(1) blob lookup vs O(log n) tree traversal
 * - Only requires hash string, no Git tree loading
 * - Cache benefits for ALL file types (not just encrypted)
 * - Succeeds in 99% of cases (profile not deleted, hash available)
 */
static bool try_fast_path_check(
    git_repository *repo,
    const char *filesystem_path,
    const char *storage_path,
    const char *source_profile,
    const char *state_blob_oid,
    const metadata_t *metadata,
    keymanager_t *keymanager,
    content_cache_t *cache,
    safety_result_t *result,
    error_t **out_err
) {
    *out_err = NULL;

    /* No blob_oid - must use slow path */
    if (!state_blob_oid) {
        return false;
    }

    /* Parse blob OID from string */
    git_oid blob_oid;
    if (git_oid_fromstr(&blob_oid, state_blob_oid) != 0) {
        /* Invalid OID - use slow path */
        return false;
    }

    compare_result_t cmp_result;
    error_t *err = NULL;
    git_filemode_t expected_mode = GIT_FILEMODE_BLOB;  /* Default, may be updated from metadata */
    struct stat file_stat;  /* Captured during comparison, used for permission checking */
    memset(&file_stat, 0, sizeof(file_stat));

    if (metadata && storage_path) {
        /* Get mode from metadata for accurate comparison */
        const metadata_item_t *meta_entry = NULL;
        error_t *mode_err = metadata_get_item(metadata, storage_path, &meta_entry);
        if (!mode_err && meta_entry) {
            /* Validate this is a file entry (storage_path should only map to files)
             * If it's a directory, something is seriously wrong - fall back to slow path.
             */
            if (meta_entry->kind != METADATA_ITEM_FILE) {
                error_free(mode_err);
                return false;  /* Use slow path fallback for safety */
            }

            /* Mode is common field - check executable bit */
            if (meta_entry->mode & S_IXUSR) {
                expected_mode = GIT_FILEMODE_BLOB_EXECUTABLE;
            }
        }
        error_free(mode_err);  /* Non-fatal if not found */

        /* Get plaintext content via content layer (handles encryption transparently) */
        const buffer_t *plaintext = NULL;
        bool owns_buffer = false;

        if (cache) {
            /* Optimal: Use cache (avoids re-decryption for encrypted, avoids re-load for plaintext) */
            err = content_cache_get_from_blob_oid(
                cache, &blob_oid, storage_path, source_profile,
                metadata, &plaintext
            );
        } else {
            /* Fallback: Load/decrypt directly (content layer handles both types) */
            buffer_t *temp = NULL;
            keymanager_t *km = keymanager ? keymanager : keymanager_get_global(NULL);
            err = content_get_from_blob_oid(
                repo, &blob_oid, storage_path, source_profile,
                metadata, km, &temp
            );
            plaintext = temp;
            owns_buffer = (err == NULL);  /* Only own if successful */
        }

        if (err) {
            /* Loading/decryption failed - conservative: cannot verify */
            error_free(err);
            *out_err = add_violation(result, filesystem_path, storage_path,
                                    source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
            return true;  /* Handled (don't try slow path) */
        }

        /* Compare plaintext to disk (captures stat for reuse) */
        err = compare_buffer_to_disk(plaintext, filesystem_path, expected_mode, NULL,
                                    &cmp_result, &file_stat);

        /* Free owned buffer if we allocated it */
        if (owns_buffer) {
            buffer_free((buffer_t *)plaintext);
        }

        if (err) {
            /* Comparison failed - conservative */
            error_free(err);
            *out_err = add_violation(result, filesystem_path, storage_path,
                                    source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
            return true;
        }
    } else {
        /* No metadata or storage_path - cannot use fast path, fall back to slow path */
        return false;
    }

    if (cmp_result == CMP_MISSING) {
        /* File already deleted - safe to prune */
        return true;
    }

    /* Check for divergence: content/type from compare, permissions separately */
    bool has_divergence = false;
    const char *reason = NULL;
    bool content_mod = false;

    /* Content/type divergence from compare_buffer_to_disk */
    if (cmp_result == CMP_DIFFERENT) {
        has_divergence = true;
        reason = SAFETY_REASON_MODIFIED;
        content_mod = true;
    } else if (cmp_result == CMP_TYPE_DIFF) {
        has_divergence = true;
        reason = SAFETY_REASON_TYPE_CHANGED;
        content_mod = true;
    } else if (cmp_result == CMP_EQUAL) {
        /* Content matches - check permissions separately.
         * Two-phase permission checking (matches workspace.c logic):
         *
         * PHASE A: Git filemode (executable bit) - always check
         * PHASE B: Full metadata - only if metadata available
         */

        bool mode_changed = false;

        /* PHASE A: Check git filemode (executable bit) */
        bool expect_exec = (expected_mode == GIT_FILEMODE_BLOB_EXECUTABLE);
        bool is_exec = fs_stat_is_executable(&file_stat);
        if (expect_exec != is_exec) {
            mode_changed = true;
        }

        /* PHASE B: Check full metadata if available and exec bit matches */
        if (!mode_changed && metadata && storage_path) {
            const metadata_item_t *meta_entry = NULL;
            error_t *meta_err = metadata_get_item(metadata, storage_path, &meta_entry);

            if (meta_err == NULL && meta_entry && meta_entry->kind == METADATA_ITEM_FILE) {
                bool mode_differs = false;
                bool ownership_differs = false;
                error_t *check_err = check_item_metadata_divergence(
                    meta_entry->mode, meta_entry->owner, meta_entry->group,
                    filesystem_path, &file_stat,
                    &mode_differs, &ownership_differs);

                if (check_err == NULL && (mode_differs || ownership_differs)) {
                    mode_changed = true;
                }
                error_free(check_err);
            }
            error_free(meta_err);
        }

        if (mode_changed) {
            has_divergence = true;
            reason = SAFETY_REASON_MODE_CHANGED;
            content_mod = false;
        }
    }

    if (has_divergence && reason) {
        *out_err = add_violation(result, filesystem_path, storage_path,
                                source_profile, reason, content_mod);
    }

    /* Fast path succeeded! */
    return true;
}

/**
 * Check file using tree-based comparison (fallback path)
 *
 * Used when fast path fails (profile deleted, hash unavailable, blob not found).
 * Loads profile tree and compares tree entry to disk file.
 * Uses passed-in metadata/keymanager if available, loads as fallback if NULL.
 */
static error_t *check_file_with_tree(
    git_repository *repo,
    const char *filesystem_path,
    const char *storage_path,
    const char *source_profile,
    git_tree *profile_tree,
    const metadata_t *metadata,
    keymanager_t *keymanager,
    safety_result_t *result
) {
    CHECK_NULL(repo);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(result);

    /* Profile tree not available - profile might be deleted */
    if (!profile_tree) {
        return add_violation(result, filesystem_path, storage_path,
                           source_profile, SAFETY_REASON_PROFILE_DELETED, false);
    }

    /* Need storage_path to look up in tree */
    if (!storage_path) {
        return add_violation(result, filesystem_path, storage_path,
                           source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
    }

    /* Load tree entry from profile */
    git_tree_entry *tree_entry = NULL;
    int git_err = git_tree_entry_bypath(&tree_entry, profile_tree, storage_path);

    if (git_err < 0) {
        /* File not in profile tree - might have been removed from Git */
        return add_violation(result, filesystem_path, storage_path,
                           source_profile, SAFETY_REASON_FILE_REMOVED, false);
    }

    /* Get decrypted content from tree entry
     *
     * For encrypted files, this transparently decrypts the content so we can
     * correctly compare it to the plaintext file deployed on the filesystem.
     * For plaintext files, this simply returns the raw content.
     *
     * Error handling: Any failure (decryption, I/O) is treated as "cannot verify"
     * to err on the side of caution (prevents removal of potentially modified files).
     */

    /* Use passed-in metadata OR load as fallback */
    metadata_t *fallback_metadata = NULL;
    const metadata_t *resolved_metadata = metadata;  /* Prefer passed-in */

    if (!resolved_metadata) {
        /* Fallback: load metadata (for tests or standalone usage) */
        error_t *err = metadata_load_from_branch(repo, source_profile, &fallback_metadata);
        if (err) {
            /* Graceful fallback: create empty metadata if loading fails */
            error_t *create_err = metadata_create_empty(&fallback_metadata);
            if (create_err) {
                error_free(create_err);
                error_free(err);
                git_tree_entry_free(tree_entry);
                return add_violation(result, filesystem_path, storage_path,
                                   source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
            }
            error_free(err);
        }
        resolved_metadata = fallback_metadata;
    }

    /* Get content via content layer (transparent encryption handling) */
    buffer_t *content = NULL;
    git_filemode_t mode = git_tree_entry_filemode(tree_entry);

    /* Use passed-in keymanager OR global as fallback */
    keymanager_t *km_to_use = keymanager ? keymanager : keymanager_get_global(NULL);

    error_t *err = content_get_from_tree_entry(
        repo,
        tree_entry,
        storage_path,
        source_profile,
        resolved_metadata,
        km_to_use,
        &content
    );

    if (err) {
        /* Failed to get content - treat as "cannot verify"
         *
         * Possible causes:
         * - Encrypted file but no passphrase available
         * - Decryption failed (wrong passphrase, corrupted file)
         * - I/O error reading blob from git
         *
         * Conservative approach: Block removal to prevent potential data loss.
         */
        error_free(err);
        if (fallback_metadata) metadata_free(fallback_metadata);
        git_tree_entry_free(tree_entry);
        return add_violation(result, filesystem_path, storage_path,
                           source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
    }

    /* Compare decrypted content to disk file (capture stat for reuse) */
    compare_result_t cmp_result;
    struct stat file_stat;
    err = compare_buffer_to_disk(content, filesystem_path, mode, NULL, &cmp_result, &file_stat);

    /* Free resources immediately */
    buffer_free(content);
    git_tree_entry_free(tree_entry);

    if (err) {
        /* Cannot read file - permission issue or I/O error */
        error_free(err);
        if (fallback_metadata) metadata_free(fallback_metadata);
        return add_violation(result, filesystem_path, storage_path,
                           source_profile, SAFETY_REASON_CANNOT_VERIFY, false);
    }

    /* Check comparison result */
    if (cmp_result == CMP_MISSING) {
        /* File already deleted - safe to prune, don't add violation */
        if (fallback_metadata) metadata_free(fallback_metadata);
        return NULL;
    }

    /* Check for divergence: content/type from compare, permissions separately */
    const char *reason = NULL;
    bool content_mod = false;

    /* Content/type divergence from compare_buffer_to_disk */
    if (cmp_result == CMP_DIFFERENT) {
        reason = SAFETY_REASON_MODIFIED;
        content_mod = true;
    } else if (cmp_result == CMP_TYPE_DIFF) {
        reason = SAFETY_REASON_TYPE_CHANGED;
        content_mod = true;
    } else if (cmp_result == CMP_EQUAL) {
        /* Content matches - check permissions separately.
         * Two-phase permission checking (matches workspace.c logic):
         *
         * PHASE A: Git filemode (executable bit) - always check
         * PHASE B: Full metadata - only if metadata available
         */

        bool mode_changed = false;

        /* PHASE A: Check git filemode (executable bit) */
        bool expect_exec = (mode == GIT_FILEMODE_BLOB_EXECUTABLE);
        bool is_exec = fs_stat_is_executable(&file_stat);
        if (expect_exec != is_exec) {
            mode_changed = true;
        }

        /* PHASE B: Check full metadata if available and exec bit matches */
        if (!mode_changed && resolved_metadata && storage_path) {
            const metadata_item_t *meta_entry = NULL;
            error_t *meta_err = metadata_get_item(resolved_metadata, storage_path, &meta_entry);

            if (meta_err == NULL && meta_entry && meta_entry->kind == METADATA_ITEM_FILE) {
                bool mode_differs = false;
                bool ownership_differs = false;
                error_t *check_err = check_item_metadata_divergence(
                    meta_entry->mode, meta_entry->owner, meta_entry->group,
                    filesystem_path, &file_stat,
                    &mode_differs, &ownership_differs);

                if (check_err == NULL && (mode_differs || ownership_differs)) {
                    mode_changed = true;
                }
                error_free(check_err);
            }
            error_free(meta_err);
        }

        if (mode_changed) {
            reason = SAFETY_REASON_MODE_CHANGED;
            content_mod = false;
        }
    }

    if (reason) {
        if (fallback_metadata) metadata_free(fallback_metadata);
        return add_violation(result, filesystem_path, storage_path,
                           source_profile, reason, content_mod);
    }

    if (fallback_metadata) metadata_free(fallback_metadata);
    return NULL;
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
 * Check files for removal safety (main implementation)
 */
error_t *safety_check_removal(
    git_repository *repo,
    const state_t *state,
    char **filesystem_paths,
    size_t path_count,
    bool force,
    const metadata_t *metadata,
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
    hashmap_t *state_index = NULL;  /* Used only if path_count >= HASHMAP_THRESHOLD */
    hashmap_t *tree_cache = NULL;
    hashmap_t *orphan_metadata_cache = NULL;  /* For lazy loading metadata from disabled profiles */

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

    /* Create cache for on-demand metadata loading
     *
     * When verifying orphaned files from disabled profiles, we need their metadata
     * for encryption detection, mode verification, and content comparison. This cache
     * ensures we load each profile's metadata at most once, avoiding redundant Git
     * operations when multiple orphans share the same source profile.
     *
     * Lifecycle: Created here, freed at ALL exit points after this line.
     */
    orphan_metadata_cache = hashmap_create(16);
    if (!orphan_metadata_cache) {
        state_free_all_files(state_entries, state_count);
        safety_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to create orphan metadata cache");
    }

    /* Adaptive lookup strategy: hashmap for large batches, linear for small
     *
     * Use hashmap when:
     * 1. Many paths to check (path_count >= HASHMAP_THRESHOLD), OR
     * 2. Linear search cost exceeds hashmap overhead (path_count * state_count >= threshold²)
     *
     * This prevents O(n*m) blowup when checking few paths against many state entries.
     * Example: 19 paths × 10,000 state entries = 190,000 comparisons → use hashmap
     *
     * Note: Overflow is not a concern here since HASHMAP_THRESHOLD² = 400, and the
     * multiplication is short-circuited by condition 1 when path_count >= 20.
     */
    bool use_hashmap = (path_count >= HASHMAP_THRESHOLD) ||
                       (path_count * state_count >= HASHMAP_THRESHOLD * HASHMAP_THRESHOLD);

    if (use_hashmap) {
        /* Build hashmap for O(1) state lookups */
        state_index = hashmap_create(state_count > 0 ? state_count : INITIAL_CAPACITY);
        if (!state_index) {
            hashmap_free(orphan_metadata_cache, (void(*)(void*))metadata_free);
            state_free_all_files(state_entries, state_count);
            safety_result_free(result);
            return ERROR(ERR_MEMORY, "Failed to create state index");
        }

        /* Populate state index */
        for (size_t i = 0; i < state_count; i++) {
            err = hashmap_set(state_index, state_entries[i].filesystem_path, &state_entries[i]);
            if (err) {
                hashmap_free(orphan_metadata_cache, (void(*)(void*))metadata_free);
                hashmap_free(state_index, NULL);
                state_free_all_files(state_entries, state_count);
                safety_result_free(result);
                return error_wrap(err, "Failed to populate state index");
            }
        }
    }

    /* Create profile tree cache for fallback path */
    tree_cache = hashmap_create(PROFILE_TREE_CACHE_SIZE);
    if (!tree_cache) {
        hashmap_free(orphan_metadata_cache, (void(*)(void*))metadata_free);
        if (state_index) hashmap_free(state_index, NULL);
        state_free_all_files(state_entries, state_count);
        safety_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to create tree cache");
    }

    /* Check each file for modifications */
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
            /* File not in state - this indicates caller passed a path that isn't
             * tracked in the deployment state. This shouldn't happen for orphaned
             * files (which by definition are in state), but we handle it gracefully
             * by skipping. This could indicate a bug in the caller's logic.
             */
            continue;
        }

        const char *source_profile = state_entry->profile;
        const char *storage_path = state_entry->storage_path;

        /* Check if file exists on filesystem */
        if (!fs_exists(fs_path)) {
            /* Already deleted from filesystem - safe to prune from state */
            continue;
        }

        /* METADATA RESOLUTION: Enabled vs Disabled Profiles
         *
         * Problem: Orphaned files may come from disabled profiles, but the
         * passed-in metadata only covers enabled profiles.
         *
         * Solution: Three-tier resolution strategy:
         * 1. Try enabled metadata first (fast path for enabled profiles)
         * 2. Load from source profile on-demand if not found (lazy loading)
         * 3. Cache loaded metadata to avoid redundant Git operations
         *
         * This handles both cases correctly:
         * - Enabled profile orphans: Found in passed metadata (instant)
         * - Disabled profile orphans: Loaded once and cached (efficient)
         */
        const metadata_t *resolved_metadata = metadata;  /* Start with enabled metadata */
        bool need_source_metadata = false;

        /* Check if we need to load metadata from source profile */
        if (metadata && storage_path) {
            /* Try to find item in enabled metadata (fast path) */
            const metadata_item_t *meta_item = NULL;
            error_t *lookup_err = metadata_get_item(metadata, storage_path, &meta_item);

            if (lookup_err || !meta_item) {
                /* Item not found in enabled metadata - likely disabled profile */
                need_source_metadata = true;
            }

            error_free(lookup_err);  /* Non-fatal */
        } else if (!metadata && source_profile) {
            /* No enabled metadata at all - need source metadata for verification */
            need_source_metadata = true;
        }

        /* Load source profile metadata on-demand if needed */
        if (need_source_metadata && source_profile) {
            /* Check cache first (O(1) lookup) */
            metadata_t *profile_meta = hashmap_get(orphan_metadata_cache, source_profile);

            if (!profile_meta) {
                /* Cache miss - load from branch (O(git_read)) */
                error_t *load_err = metadata_load_from_branch(repo, source_profile, &profile_meta);

                if (!load_err && profile_meta) {
                    /* Successfully loaded - try to cache for reuse */
                    error_t *cache_err = hashmap_set(orphan_metadata_cache, source_profile, profile_meta);

                    if (cache_err) {
                        /* Caching failed (memory exhaustion?) - free metadata and fall back
                         *
                         * Ownership note: hashmap_set() failed, so cache did NOT take ownership.
                         * We must free profile_meta to avoid leak. Next file from same profile
                         * will reload metadata (inefficient but correct).
                         *
                         * Rationale: Cache insertion failure is extremely rare (memory exhaustion).
                         * Falling back to slow path is acceptable in this edge case.
                         */
                        error_free(cache_err);
                        metadata_free(profile_meta);
                        profile_meta = NULL;
                        /* resolved_metadata remains 'metadata' - will trigger slow path fallback */
                    }
                    /* If cache succeeded, cache now OWNS profile_meta (will free at function end) */
                } else if (load_err && load_err->code == ERR_NOT_FOUND) {
                    /* Profile branch has no metadata file - not an error */
                    error_free(load_err);
                } else if (load_err) {
                    /* FATAL: Real error loading metadata (I/O error, corrupt file, etc.) */
                    hashmap_free(orphan_metadata_cache, (void(*)(void*))metadata_free);
                    hashmap_free(tree_cache, free_profile_tree_cache);
                    if (state_index) hashmap_free(state_index, NULL);
                    state_free_all_files(state_entries, state_count);
                    safety_result_free(result);
                    return error_wrap(load_err, "Failed to load metadata from profile '%s'",
                                    source_profile);
                }
            }

            /* Use profile-specific metadata if available (borrowed from cache) */
            if (profile_meta) {
                resolved_metadata = profile_meta;
            }
        }

        /* File exists - verify it's unmodified before removal */
        /* Try fast path WITH resolved metadata (enabled OR disabled profile) */
        error_t *check_err = NULL;
        bool fast_path_succeeded = try_fast_path_check(
            repo, fs_path, storage_path, source_profile,
            state_entry->blob_oid,
            resolved_metadata,   /* ← Use resolved metadata (enabled OR loaded on-demand) */
            keymanager,          /* Pass keymanager for decryption */
            cache,               /* Pass cache for performance */
            result, &check_err
        );

        if (check_err) {
            /* Error during fast path check - FATAL */
            hashmap_free(orphan_metadata_cache, (void(*)(void*))metadata_free);
            hashmap_free(tree_cache, free_profile_tree_cache);
            if (state_index) hashmap_free(state_index, NULL);
            state_free_all_files(state_entries, state_count);
            safety_result_free(result);
            return error_wrap(check_err, "Failed to check file '%s'", fs_path);
        }

        /* Fallback to slow path if fast path didn't succeed */
        if (!fast_path_succeeded) {
            git_tree *profile_tree = NULL;
            err = get_or_load_profile_tree(repo, tree_cache, source_profile, &profile_tree);
            if (err) {
                /* Fatal error (memory allocation, cache failure) */
                hashmap_free(orphan_metadata_cache, (void(*)(void*))metadata_free);
                hashmap_free(tree_cache, free_profile_tree_cache);
                if (state_index) hashmap_free(state_index, NULL);
                state_free_all_files(state_entries, state_count);
                safety_result_free(result);
                return error_wrap(err, "Failed to load profile tree for '%s'", source_profile);
            }

            /* Check file using tree-based comparison WITH resolved metadata */
            err = check_file_with_tree(repo, fs_path, storage_path, source_profile,
                                      profile_tree,
                                      resolved_metadata,   /* ← Use resolved metadata */
                                      keymanager,          /* Pass keymanager */
                                      result);
            if (err) {
                hashmap_free(orphan_metadata_cache, (void(*)(void*))metadata_free);
                hashmap_free(tree_cache, free_profile_tree_cache);
                if (state_index) hashmap_free(state_index, NULL);
                state_free_all_files(state_entries, state_count);
                safety_result_free(result);
                return error_wrap(err, "Failed to check file '%s'", fs_path);
            }
        }
    }

    /* Cleanup */
    /* Free orphan metadata cache (OWNS all cached metadata) */
    hashmap_free(orphan_metadata_cache, (void(*)(void*))metadata_free);

    /* Free profile tree cache */
    hashmap_free(tree_cache, free_profile_tree_cache);

    /* Free state index if used */
    if (state_index) hashmap_free(state_index, NULL);

    /* Free state entries */
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
