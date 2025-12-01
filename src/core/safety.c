/**
 * safety.c - Data loss prevention for file removal operations
 *
 * Validates that orphaned files can be safely removed by checking edge cases
 * that workspace divergence analysis cannot detect. Used by the `apply` command
 * when pruning orphaned files.
 *
 * Architecture:
 * - Trusts workspace divergence for verified cases (no re-verification)
 * - Branch existence check: Detects external profile deletion
 * - Lifecycle state query: Distinguishes controlled vs external deletion
 * - Slow path recovery: Git-based verification for DIVERGENCE_UNVERIFIED
 *
 * Key optimizations:
 * - Targeted O(1) state queries (no bulk loading)
 * - Profile tree caching: Each profile tree loaded at most once
 * - Metadata caching: Each profile's metadata loaded at most once (slow path)
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

/* Initial size for profile tree cache */
#define PROFILE_TREE_CACHE_SIZE 8

/**
 * Check result for orphan processing pipeline
 *
 * Indicates what action the caller should take after a check completes.
 * Provides single-channel control flow encoding to replace dual-return patterns.
 *
 * Used by check_branch_existence() and map_divergence_to_violation() to
 * communicate processing outcomes without mixing return mechanisms.
 */
typedef enum {
    SAFETY_CHECK_CONTINUE,  /* Check passed - continue to next processing phase */
    SAFETY_CHECK_DONE,      /* Item fully processed (safe or violation added) - skip to next item */
    SAFETY_CHECK_ERROR      /* Fatal error occurred - check error parameter */
} check_result_t;

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
 * Map workspace divergence flags to safety violation
 *
 * Translates workspace's divergence_type_t to safety's violation structure.
 * This is the "trust workspace" path - no re-verification performed.
 *
 * Priority order (check in this order, return on first match):
 * 1. DIVERGENCE_UNVERIFIED - caller handles with slow path (CONTINUE)
 * 2. DIVERGENCE_CONTENT - content changed (MODIFIED violation, DONE or ERROR)
 * 3. DIVERGENCE_TYPE - file type changed (TYPE_CHANGED violation, DONE or ERROR)
 * 4. DIVERGENCE_MODE/OWNERSHIP - permissions changed (MODE_CHANGED violation, DONE or ERROR)
 * 5. DIVERGENCE_NONE - safe to remove (no violation, DONE)
 *
 * @param orphan Workspace item with pre-computed divergence
 * @param result Safety result to populate (if violation found)
 * @param out_err Error output for allocation failures (only set on ERROR)
 * @return SAFETY_CHECK_CONTINUE if slow path needed
 *         SAFETY_CHECK_DONE if handled (violation added or safe)
 *         SAFETY_CHECK_ERROR if violation allocation failed (check out_err)
 */
static check_result_t map_divergence_to_violation(
    const workspace_item_t *orphan,
    safety_result_t *result,
    error_t **out_err
) {
    *out_err = NULL;

    /* DIVERGENCE_UNVERIFIED: Caller must handle with slow path */
    if (orphan->divergence & DIVERGENCE_UNVERIFIED) {
        return SAFETY_CHECK_CONTINUE;  /* Signal caller to run slow path */
    }

    /* DIVERGENCE_NONE: Safe to remove (workspace verified clean) */
    if (orphan->divergence == DIVERGENCE_NONE) {
        return SAFETY_CHECK_DONE;  /* No violation - safe to remove */
    }

    /* DIVERGENCE_CONTENT: Content differs from Git */
    if (orphan->divergence & DIVERGENCE_CONTENT) {
        *out_err = add_violation(result, orphan->filesystem_path, orphan->storage_path,
                                 orphan->profile, SAFETY_REASON_MODIFIED, true);
        return *out_err ? SAFETY_CHECK_ERROR : SAFETY_CHECK_DONE;
    }

    /* DIVERGENCE_TYPE: File type changed (file <-> symlink) */
    if (orphan->divergence & DIVERGENCE_TYPE) {
        *out_err = add_violation(result, orphan->filesystem_path, orphan->storage_path,
                                 orphan->profile, SAFETY_REASON_TYPE_CHANGED, true);
        return *out_err ? SAFETY_CHECK_ERROR : SAFETY_CHECK_DONE;
    }

    /* DIVERGENCE_MODE or DIVERGENCE_OWNERSHIP: Permissions changed */
    if (orphan->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
        *out_err = add_violation(result, orphan->filesystem_path, orphan->storage_path,
                                 orphan->profile, SAFETY_REASON_MODE_CHANGED, false);
        return *out_err ? SAFETY_CHECK_ERROR : SAFETY_CHECK_DONE;
    }

    /* Unrecognized divergence flags (future-proofing) - treat as safe */
    return SAFETY_CHECK_DONE;
}

/**
 * Check lifecycle state and branch existence
 *
 * Two-phase check implementing precedence hierarchy:
 *
 * PHASE 1: Lifecycle State (highest precedence)
 * - STATE_INACTIVE: Controlled deletion (safe to remove, skip all verification)
 * - STATE_ACTIVE: Continue to phase 2
 *
 * PHASE 2: Branch Existence (only for STATE_ACTIVE orphans)
 * - Branch exists: Proceed to divergence routing
 * - Branch deleted: RELEASED violation (external deletion)
 *
 * Key Invariant: User intent (STATE_INACTIVE) overrides all other checks.
 * This ensures consistent behavior regardless of branch existence (Git GC timing).
 *
 * @param repo Git repository
 * @param state State database (for targeted lookup)
 * @param orphan Workspace item
 * @param tree_cache Profile tree cache
 * @param result Safety result to populate
 * @param out_err Error output for fatal failures (only set on ERROR)
 * @return SAFETY_CHECK_CONTINUE if branch exists (proceed to divergence routing)
 *         SAFETY_CHECK_DONE if handled (controlled deletion or violation added)
 *         SAFETY_CHECK_ERROR if fatal error occurred (check out_err)
 */
static check_result_t check_branch_existence(
    git_repository *repo,
    const state_t *state,
    const workspace_item_t *orphan,
    hashmap_t *tree_cache,
    safety_result_t *result,
    error_t **out_err
) {
    *out_err = NULL;

    /* PHASE 1: Check lifecycle state (highest precedence)
     *
     * User intent (STATE_INACTIVE) takes precedence over all other checks.
     * If user explicitly disabled profile via manifest_disable_profile(),
     * trust that intent unconditionally regardless of branch existence.
     */
    state_file_entry_t *state_entry = NULL;
    error_t *err = state_get_file(state, orphan->filesystem_path, &state_entry);

    if (err) {
        /* State lookup failed - cannot determine lifecycle */
        error_free(err);
        err = add_violation(result, orphan->filesystem_path, orphan->storage_path,
                            orphan->profile, SAFETY_REASON_CANNOT_VERIFY, false);
        if (err) {
            *out_err = err;
            return SAFETY_CHECK_ERROR;
        }

        return SAFETY_CHECK_DONE;
    }

    if (!state_entry) {
        /* Not in state - shouldn't happen for orphans, but handle gracefully */
        return SAFETY_CHECK_CONTINUE;  /* Proceed to divergence routing (defensive) */
    }

    bool is_controlled_deletion = state_entry->state &&
                                  strcmp(state_entry->state, STATE_INACTIVE) == 0;

    state_free_entry(state_entry);

    if (is_controlled_deletion) {
        /* CONTROLLED DELETION
         *
         * Entry marked STATE_INACTIVE by manifest_disable_profile() while
         * the branch still existed. The removal intent was recorded with
         * full verification capability at that time.
         *
         * Trust the recorded intent unconditionally:
         * - Bypass all safety checks (intent validated at disable time)
         * - Remove file regardless of branch existence
         * - Remove file regardless of modifications
         *
         * This provides consistent behavior whether branch exists or deleted.
         * Branch existence is an implementation detail; user intent is authoritative.
         *
         * Follows Git staging model:
         *   profile disable = git rm (staging)
         *   apply = git commit (execution)
         */
        return SAFETY_CHECK_DONE;  /* Safe to remove - skip verification */
    }

    /* PHASE 2: Check branch existence (only for STATE_ACTIVE orphans)
     *
     * At this point, lifecycle state is STATE_ACTIVE. Check if branch was
     * deleted externally (outside dotta).
     */
    git_tree *profile_tree = NULL;
    err = get_or_load_profile_tree(repo, tree_cache, orphan->profile, &profile_tree);
    if (err) {
        *out_err = error_wrap(err, "Failed to load profile tree for '%s'", orphan->profile);
        return SAFETY_CHECK_ERROR;
    }

    /* Branch exists - proceed with divergence routing */
    if (profile_tree) {
        return SAFETY_CHECK_CONTINUE;
    }

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
    err = add_violation(result, orphan->filesystem_path, orphan->storage_path,
                        orphan->profile, SAFETY_REASON_RELEASED, false);
    if (err) {
        *out_err = err;
        return SAFETY_CHECK_ERROR;
    }

    return SAFETY_CHECK_DONE;
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
 * - This path trusts Git only - all file properties are loaded from the
 * - Git tree and metadata file within that tree. This provides independent
 * - verification from the fast path (which trusts state/VWD).
 *
 * Data Sources (ALL from Git, NONE from state):
 * - encrypted    <- metadata_load_from_tree()
 * - file type    <- git_tree_entry_filemode()
 * - permissions  <- Git tree metadata
 * - blob content <- git_tree_entry_id()
 *
 * Terminal Results:
 * - Profile tree NULL        -> CANNOT_VERIFY (defense-in-depth)
 * - File not in tree         -> FILE_REMOVED
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
 * Check removal safety for orphaned workspace items
 *
 * Validates that orphaned files can be safely removed by checking:
 * 1. Branch existence (external deletion detection)
 * 2. Lifecycle state (controlled vs external deletion)
 * 3. Workspace divergence (trusted for verified cases)
 * 4. Slow path recovery (for DIVERGENCE_UNVERIFIED only)
 *
 * Trusts workspace divergence analysis for verified cases, eliminating
 * redundant verification while preserving all data loss protections.
 */
error_t *safety_check_orphans(
    git_repository *repo,
    const state_t *state,
    const workspace_item_t **orphans,
    size_t orphan_count,
    bool force,
    keymanager_t *keymanager,
    safety_result_t **out_result
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(out_result);

    /* Allow NULL orphans if orphan_count is 0 */
    if (orphan_count > 0 && !orphans) {
        return ERROR(ERR_INVALID_ARG, "orphans cannot be NULL when orphan_count > 0");
    }

    error_t *err = NULL;
    safety_result_t *result = NULL;
    hashmap_t *tree_cache = NULL;          /* Profile tree cache for slow path */
    hashmap_t *tree_metadata_cache = NULL; /* Metadata cache for slow path (loaded from Git) */

    /* Allocate result */
    result = calloc(1, sizeof(safety_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate safety result");
    }

    /* Force mode or empty input: return empty result */
    if (force || orphan_count == 0) {
        *out_result = result;
        return NULL;
    }

    /* Create profile tree cache for branch existence checks */
    tree_cache = hashmap_create(PROFILE_TREE_CACHE_SIZE);
    if (!tree_cache) {
        safety_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to create tree cache");
    }

    /* Create metadata cache for slow path (only used for UNVERIFIED) */
    tree_metadata_cache = hashmap_create(PROFILE_TREE_CACHE_SIZE);
    if (!tree_metadata_cache) {
        hashmap_free(tree_cache, free_profile_tree_cache);
        safety_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to create metadata cache");
    }

    /* Main processing loop */
    for (size_t i = 0; i < orphan_count; i++) {
        const workspace_item_t *orphan = orphans[i];

        /* Skip if file already gone (workspace may have stale info) */
        if (!orphan->on_filesystem) {
            continue;
        }

        /* PHASE 1: Branch Existence Precondition Check
         *
         * Must check branch existence before any verification. This determines:
         * 1. Whether verification is meaningful (branch exists -> can verify)
         * 2. What to do when branch is deleted (controlled vs external deletion)
         *
         * Key insight: Checking first provides consistent behavior regardless of
         * Git garbage collection timing. Without this, fast path might succeed
         * (blob exists) or fail (blob GC'd), producing different results for
         * the same semantic case — confusing and incoherent.
         */
        check_result_t check_result = check_branch_existence(repo, state, orphan,
                                                             tree_cache, result, &err);
        if (check_result == SAFETY_CHECK_ERROR) {
            goto cleanup;
        }

        if (check_result == SAFETY_CHECK_DONE) {
            continue;
        }

        /* PHASE 2: Divergence Routing
         *
         * Workspace already performed comprehensive verification.
         * Route based on divergence type:
         * - NONE: Safe to remove (no violation)
         * - CONTENT/TYPE/MODE/OWNERSHIP: Map to violation directly
         * - UNVERIFIED: Run slow path for recovery
         */
        check_result = map_divergence_to_violation(orphan, result, &err);
        if (check_result == SAFETY_CHECK_ERROR) {
            goto cleanup;
        }

        if (check_result == SAFETY_CHECK_DONE) {
            continue;
        }

        /* PHASE 3: Slow Path Recovery (DIVERGENCE_UNVERIFIED only)
         *
         * Workspace couldn't verify - try using Git tree directly.
         * Profile tree guaranteed to exist (checked in Phase 1).
         */
        git_tree *profile_tree = NULL;
        err = get_or_load_profile_tree(repo, tree_cache, orphan->profile, &profile_tree);
        if (err) {
            goto cleanup;
        }

        err = check_file_with_tree(repo, orphan->filesystem_path, orphan->storage_path,
                                   orphan->profile, profile_tree, tree_metadata_cache,
                                   keymanager, result);
        if (err) {
            goto cleanup;
        }
    }

    /* Success */
    hashmap_free(tree_metadata_cache, (void(*)(void*))metadata_free);
    hashmap_free(tree_cache, free_profile_tree_cache);
    *out_result = result;
    return NULL;

cleanup:
    hashmap_free(tree_metadata_cache, (void(*)(void*))metadata_free);
    hashmap_free(tree_cache, free_profile_tree_cache);
    safety_result_free(result);
    return err;
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
