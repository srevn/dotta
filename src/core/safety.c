/**
 * safety.c - Data loss prevention for file removal operations
 *
 * Validates that orphaned files can be safely removed by checking edge cases
 * that workspace divergence analysis cannot detect. Used by the `apply` command
 * when pruning orphaned files.
 *
 * Architecture:
 * - Trusts workspace divergence completely (no re-verification)
 * - Lifecycle state: STATE_DELETED bypasses branch check (controlled deletion)
 * - Branch existence check: Detects external profile deletion for STATE_INACTIVE/ACTIVE
 * - UNVERIFIED treated conservatively: Don't delete what we can't verify
 *
 * Workspace provides accurate divergence for orphans:
 * - Non-encrypted: Streaming OID verification (git_odb_hashfile, any size)
 * - Encrypted ≤100MB: Content comparison
 * - Encrypted >100MB: UNVERIFIED (OOM protection, maps to CANNOT_VERIFY)
 *
 * Key optimizations:
 * - Targeted O(1) state queries (no bulk loading)
 * - Profile existence caching: Each profile checked at most once
 */

#include "safety.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/state.h"
#include "core/workspace.h"
#include "utils/hashmap.h"

/* Initial capacity for dynamic arrays */
#define INITIAL_CAPACITY 16

/* Initial size for profile cache */
#define PROFILE_CACHE_SIZE 8

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
 * Profile cache entry
 *
 * Caches branch existence to avoid repeated Git lookups in batch checks.
 * Uses lightweight boolean instead of loading full git_tree objects.
 */
typedef struct {
    char *profile_name;  /* Owned copy of profile name (hashmap key) */
    bool exists;         /* true if profile branch exists */
} profile_cache_t;

/**
 * Free profile cache entry (hashmap callback)
 */
static void free_profile_cache(void *entry) {
    if (!entry) {
        return;
    }
    profile_cache_t *cache = (profile_cache_t *)entry;
    free(cache->profile_name);
    free(cache);
}

/**
 * Check if profile branch exists (cached)
 *
 * Uses gitops_branch_exists() for O(1) ref lookup instead of loading
 * full git_tree objects. Caches results to avoid repeated Git lookups.
 *
 * @param repo Git repository
 * @param cache Profile existence cache
 * @param profile_name Profile to check
 * @param out_exists Output: true if branch exists, false otherwise
 * @return Error on fatal failure (memory), NULL on success
 */
static error_t *check_profile_exists(
    git_repository *repo,
    hashmap_t *cache,
    const char *profile_name,
    bool *out_exists
) {
    CHECK_NULL(repo);
    CHECK_NULL(cache);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_exists);

    /* Check cache first */
    profile_cache_t *cached = hashmap_get(cache, profile_name);
    if (cached) {
        *out_exists = cached->exists;
        return NULL;
    }

    /* Not cached - check branch existence via ref lookup */
    bool exists = false;
    error_t *err = gitops_branch_exists(repo, profile_name, &exists);
    if (err) {
        /* Treat lookup errors as "doesn't exist" (conservative) */
        error_free(err);
        exists = false;
    }

    /* Cache the result */
    profile_cache_t *entry = calloc(1, sizeof(profile_cache_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate cache entry");
    }

    entry->profile_name = strdup(profile_name);
    if (!entry->profile_name) {
        free(entry);
        return ERROR(ERR_MEMORY, "Failed to allocate profile name");
    }
    entry->exists = exists;

    /* Insert into cache */
    err = hashmap_set(cache, profile_name, entry);
    if (err) {
        free_profile_cache(entry);
        return err;
    }

    *out_exists = exists;
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
 * Three-phase check implementing safety hierarchy:
 *
 * PHASE 1: Controlled Deletion (STATE_DELETED)
 * - Skip branch check entirely (user confirmed intent via remove command)
 * - Proceed to divergence routing
 *
 * PHASE 2: Branch Existence (STATE_INACTIVE and STATE_ACTIVE)
 * - Branch exists: Proceed to divergence routing
 * - Branch gone: RELEASED violation (irrecoverable, protect user data)
 *
 * Key Invariant: Only STATE_DELETED (explicit confirmed intent) bypasses the
 * branch check. Both STATE_INACTIVE and STATE_ACTIVE require branch existence
 * for safe removal. This prevents silent data loss when a branch is deleted
 * externally after a profile disable.
 *
 * @param repo Git repository
 * @param state State database (for targeted lookup)
 * @param orphan Workspace item
 * @param cache Profile existence cache
 * @param result Safety result to populate
 * @param out_err Error output for fatal failures (only set on ERROR)
 * @return SAFETY_CHECK_CONTINUE if safe to proceed (divergence routing)
 *         SAFETY_CHECK_DONE if handled (violation added or released)
 *         SAFETY_CHECK_ERROR if fatal error occurred (check out_err)
 */
static check_result_t check_branch_existence(
    git_repository *repo,
    const state_t *state,
    const workspace_item_t *orphan,
    hashmap_t *cache,
    safety_result_t *result,
    error_t **out_err
) {
    *out_err = NULL;

    /* Look up lifecycle state from state database */
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

    /* Extract lifecycle state before freeing entry */
    bool is_controlled_deletion = state_entry->state &&
                                  strcmp(state_entry->state, STATE_DELETED) == 0;

    state_free_entry(state_entry);

    if (is_controlled_deletion) {
        /* PHASE 1: CONTROLLED DELETION (STATE_DELETED)
         *
         * Entry marked STATE_DELETED by deliberate user action (remove command).
         * User intent is unambiguous - skip branch existence check entirely.
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

    /* PHASE 2: BRANCH EXISTENCE CHECK (STATE_INACTIVE and STATE_ACTIVE)
     *
     * For both staged removals (profile disable) and active entries,
     * verify the profile branch still exists. If the branch is gone,
     * Git content is irrecoverable — release files to prevent data loss.
     */
    bool profile_exists = false;
    err = check_profile_exists(repo, cache, orphan->profile, &profile_exists);
    if (err) {
        *out_err = error_wrap(err, "Failed to check profile existence for '%s'", orphan->profile);
        return SAFETY_CHECK_ERROR;
    }

    if (profile_exists) {
        return SAFETY_CHECK_CONTINUE;  /* Branch exists, proceed to divergence routing */
    }

    /* RELEASED: Branch deleted (externally or after profile disable).
     * Cannot recover content from Git. Release file from management.
     *
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
    hashmap_t *cache = NULL;  /* Profile existence cache for branch checks */

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

    /* Create profile cache for branch existence checks */
    cache = hashmap_create(PROFILE_CACHE_SIZE);
    if (!cache) {
        safety_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to create profile cache");
    }

    /* Main processing loop */
    for (size_t i = 0; i < orphan_count; i++) {
        const workspace_item_t *orphan = orphans[i];

        /* Skip if file already gone (workspace may have stale info) */
        if (!orphan->on_filesystem) {
            continue;
        }

        /* Lifecycle State and Branch Existence Check
         *
         * Determines safety based on lifecycle state and branch existence:
         * - STATE_DELETED: Skip branch check (controlled deletion)
         * - STATE_INACTIVE/ACTIVE + branch exists: Proceed to divergence routing
         * - STATE_INACTIVE/ACTIVE + branch gone: RELEASED violation
         */
        check_result_t check_result = check_branch_existence(repo, state, orphan,
                                                             cache, result, &err);

        if (check_result == SAFETY_CHECK_ERROR) {
            goto cleanup;
        }

        if (check_result == SAFETY_CHECK_DONE) {
            continue;
        }

        /* Divergence Routing
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
    hashmap_free(cache, free_profile_cache);
    *out_result = result;
    return NULL;

cleanup:
    hashmap_free(cache, free_profile_cache);
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
