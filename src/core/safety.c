/**
 * safety.c - Data loss prevention for file removal operations
 *
 * Validates that orphaned files can be safely removed by checking edge cases
 * that workspace divergence analysis cannot detect. Used by the `apply` command
 * when pruning orphaned files.
 *
 * Architecture:
 * - Trusts workspace divergence completely (no re-verification)
 * - Branch existence check: Detects external profile deletion
 * - Lifecycle state query: Distinguishes controlled vs external deletion
 * - UNVERIFIED treated conservatively: Don't delete what we can't verify
 *
 * Workspace provides accurate divergence for orphans:
 * - Non-encrypted: Streaming OID verification (git_odb_hashfile, any size)
 * - Encrypted ≤100MB: Content comparison
 * - Encrypted >100MB: UNVERIFIED (OOM protection, maps to CANNOT_VERIFY)
 *
 * Key optimizations:
 * - Targeted O(1) state queries (no bulk loading)
 * - Profile tree caching: Each profile tree loaded at most once
 */

#include "safety.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/gitops.h"
#include "core/state.h"
#include "core/workspace.h"
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
    SAFETY_CHECK_DONE,      /* Item fully processed (safe or violation added) */
    SAFETY_CHECK_ERROR      /* Fatal error occurred - check error parameter */
} check_result_t;

/**
 * Profile tree cache entry
 *
 * Caches loaded trees to avoid repeated Git operations in batch checks.
 * Stores NULL for deleted profiles to prevent repeated failed Git lookups.
 */
typedef struct {
    char *profile_name;  /* Owned copy of profile name (hashmap key) */
    git_tree *tree;      /* NULL if profile doesn't exist */
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
 * 1. DIVERGENCE_CONTENT - content changed (MODIFIED violation)
 * 2. DIVERGENCE_TYPE - file type changed (TYPE_CHANGED violation)
 * 3. DIVERGENCE_MODE/OWNERSHIP - permissions changed (MODE_CHANGED violation)
 * 4. DIVERGENCE_UNVERIFIED - verification failed (CANNOT_VERIFY violation)
 * 5. DIVERGENCE_NONE - safe to remove (no violation)
 *
 * Note: DIVERGENCE_UNVERIFIED now only occurs for:
 * - Encrypted files > 100MB (AEAD requires full ciphertext, OOM protection)
 * - Blob corruption (missing blob_oid, invalid OID format)
 * - I/O errors during verification
 *
 * Non-encrypted files can be verified at any size using streaming OID
 * verification (git_odb_hashfile), so they should not reach UNVERIFIED.
 *
 * @param orphan Workspace item with pre-computed divergence
 * @param result Safety result to populate (if violation found)
 * @param out_err Error output for allocation failures (only set on ERROR)
 * @return SAFETY_CHECK_DONE if handled (violation added or safe)
 *         SAFETY_CHECK_ERROR if violation allocation failed (check out_err)
 */
static check_result_t map_divergence_to_violation(
    const workspace_item_t *orphan,
    safety_result_t *result,
    error_t **out_err
) {
    *out_err = NULL;

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

    /* DIVERGENCE_UNVERIFIED: Verification failed */
    if (orphan->divergence & DIVERGENCE_UNVERIFIED) {
        *out_err = add_violation(result, orphan->filesystem_path, orphan->storage_path,
                                 orphan->profile, SAFETY_REASON_CANNOT_VERIFY, false);
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
 * - STATE_INACTIVE: Controlled deletion (proceed to content verification)
 * - STATE_ACTIVE: Continue to phase 2
 *
 * PHASE 2: Branch Existence (only for STATE_ACTIVE orphans)
 * - Branch exists: Proceed to divergence routing
 * - Branch deleted: RELEASED violation (external deletion)
 *
 * Key Invariant: User intent (STATE_INACTIVE) overrides branch existence check.
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
        /* CONTROLLED DELETION WITH VERIFICATION
         *
         * Entry marked STATE_INACTIVE by manifest_disable_profile() while
         * the branch still existed. User intent is to remove these files.
         *
         * Behavior:
         * - Clean files (DIVERGENCE_NONE): Safe to remove (no violation)
         * - Modified files (DIVERGENCE_CONTENT): Violation added (user warned)
         * - Force flag: Bypasses all checks (unchanged behavior)
         *
         * This provides defense-in-depth: user intent is respected for clean
         * files, but post-disable modifications are protected.
         */
        return SAFETY_CHECK_CONTINUE;  /* Proceed to divergence routing */
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
 * Check removal safety for orphaned workspace items
 *
 * Validates that orphaned files can be safely removed by checking:
 * 1. Branch existence (external deletion detection)
 * 2. Lifecycle state (controlled vs external deletion)
 * 3. Workspace divergence (trusted completely - no re-verification)
 *
 * Trusts workspace divergence analysis completely, eliminating redundant
 * verification while preserving all data loss protections. DIVERGENCE_UNVERIFIED
 * is treated conservatively as CANNOT_VERIFY (don't delete what we can't verify).
 */
error_t *safety_check_orphans(
    git_repository *repo,
    const state_t *state,
    const workspace_item_t **orphans,
    size_t orphan_count,
    bool force,
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
    hashmap_t *tree_cache = NULL;  /* Profile tree cache for branch existence checks */

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
         * Workspace already performed comprehensive verification:
         * - Non-encrypted: Streaming OID verification
         * - Encrypted ≤100MB: Content comparison
         * - Encrypted >100MB: UNVERIFIED (OOM protection)
         *
         * Route based on divergence type:
         * - NONE: Safe to remove (no violation)
         * - CONTENT/TYPE/MODE/OWNERSHIP: Map to violation directly
         * - UNVERIFIED: Map to CANNOT_VERIFY violation (conservative)
         */
        check_result = map_divergence_to_violation(orphan, result, &err);
        if (check_result == SAFETY_CHECK_ERROR) {
            goto cleanup;
        }
    }

    /* Success */
    hashmap_free(tree_cache, free_profile_tree_cache);
    *out_result = result;
    return NULL;

cleanup:
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
