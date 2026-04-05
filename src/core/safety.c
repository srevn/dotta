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
 * Caches branch existence and tree to avoid repeated Git lookups in batch checks.
 * Tree is loaded lazily on first file-in-tree check for each profile.
 */
typedef struct {
    bool exists;         /* true if profile branch exists */
    git_tree *tree;      /* Cached tree for file-in-tree checks (NULL until loaded, NULL if !exists) */
    bool tree_loaded;    /* true if tree load was attempted (avoids retrying on failure) */
} profile_cache_t;

/**
 * Free profile cache entry (hashmap callback)
 */
static void free_profile_cache(void *entry) {
    if (!entry) {
        return;
    }
    profile_cache_t *cache = (profile_cache_t *) entry;
    if (cache->tree) {
        git_tree_free(cache->tree);
    }
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
 * @return Error on failure (memory or Git lookup), NULL on success
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
        /* Propagate Git errors — caller emits CANNOT_VERIFY.
         * Don't cache failures (transient errors should be retryable). */
        return err;
    }

    /* Cache successful lookups only */
    profile_cache_t *entry = calloc(1, sizeof(profile_cache_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate cache entry");
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
 * Check if a file exists in a profile's current Git tree (cached)
 *
 * Loads the profile's tree lazily (once per profile) and checks if the
 * given storage_path exists in it. This detects files removed from Git
 * externally while the branch still exists.
 *
 * Error handling propagates all failures as errors so the caller
 * can emit CANNOT_VERIFY (blocks removal, preserves state entry).
 * Tree loading is only cached on success — transient failures
 * allow retries for subsequent files from the same profile.
 *
 * @param repo Git repository
 * @param cache Profile cache (tree loaded lazily and cached)
 * @param profile_name Profile to check
 * @param storage_path Storage path to look up (e.g., "home/.bashrc")
 * @param out_in_tree Output: true if file exists in tree
 * @return Error on failure (Git or memory), NULL on success
 */
static error_t *check_file_in_tree(
    git_repository *repo,
    hashmap_t *cache,
    const char *profile_name,
    const char *storage_path,
    bool *out_in_tree
) {
    CHECK_NULL(repo);
    CHECK_NULL(cache);
    CHECK_NULL(profile_name);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_in_tree);

    *out_in_tree = false;

    /* Get cached profile entry */
    profile_cache_t *cached = hashmap_get(cache, profile_name);
    if (!cached || !cached->exists) {
        /* Profile doesn't exist or not cached — file can't be in tree */
        return NULL;
    }

    /* Lazy-load tree on first file-in-tree check for this profile.
     * Only set tree_loaded on success — failures allow retries. */
    if (!cached->tree_loaded) {
        /* Resolve branch HEAD to tree */
        char refname[DOTTA_REFNAME_MAX];
        error_t *err = gitops_build_refname(
            refname, sizeof(refname), "refs/heads/%s", profile_name
        );
        if (err) {
            return err;
        }

        git_tree *tree = NULL;
        err = gitops_load_tree(repo, refname, &tree);
        if (err) {
            return err;
        }

        cached->tree = tree;          /* Transfer ownership to cache */
        cached->tree_loaded = true;   /* Cache success only */
    }

    /* Check if file exists in tree via path traversal
     *
     * Distinguish between "file not in tree" (GIT_ENOTFOUND) and actual
     * errors (GIT_ERROR, OOM). ENOTFOUND is the normal "removed from Git"
     * case. Actual errors should propagate so the caller can treat them
     * as CANNOT_VERIFY rather than RELEASED — preserving the state entry
     * is more conservative than removing it.
     */
    git_tree_entry *entry = NULL;
    int ret = git_tree_entry_bypath(&entry, cached->tree, storage_path);

    if (ret == 0) {
        *out_in_tree = true;
        git_tree_entry_free(entry);
    } else if (ret != GIT_ENOTFOUND) {
        /* Unexpected error (corrupt tree, OOM). Propagate so caller
         * can use CANNOT_VERIFY instead of RELEASED. */
        return ERROR(
            ERR_GIT, "Failed to check tree entry for '%s': %s",
            storage_path, git_error_last() ? git_error_last()->message : "unknown"
        );
    }
    /* GIT_ENOTFOUND: file not in tree — out_in_tree stays false */

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

        safety_violation_t *new_violations = realloc(
            result->violations,
            new_capacity * sizeof(safety_violation_t)
        );
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
 * 5. DIVERGENCE_ENCRYPTION/STALE - known-safe (no user modification)
 * 6. DIVERGENCE_NONE - safe to remove (no violation)
 * 7. Unknown flags - CANNOT_VERIFY (defensive default)
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
        *out_err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_MODIFIED, true
        );
        return *out_err ? SAFETY_CHECK_ERROR : SAFETY_CHECK_DONE;
    }

    /* DIVERGENCE_TYPE: File type changed (file <-> symlink) */
    if (orphan->divergence & DIVERGENCE_TYPE) {
        *out_err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_TYPE_CHANGED, true
        );
        return *out_err ? SAFETY_CHECK_ERROR : SAFETY_CHECK_DONE;
    }

    /* DIVERGENCE_MODE or DIVERGENCE_OWNERSHIP: Permissions changed */
    if (orphan->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
        *out_err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_MODE_CHANGED, false
        );
        return *out_err ? SAFETY_CHECK_ERROR : SAFETY_CHECK_DONE;
    }

    /* DIVERGENCE_UNVERIFIED: Verification failed */
    if (orphan->divergence & DIVERGENCE_UNVERIFIED) {
        *out_err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_CANNOT_VERIFY, false
        );
        return *out_err ? SAFETY_CHECK_ERROR : SAFETY_CHECK_DONE;
    }

    /* All priority flags handled above. Remaining flags:
     * - ENCRYPTION: Policy mismatch (not user modification) — safe
     * - STALE: VWD cache outdated (Git changed) — irrelevant for removal
     * Unknown flags: block removal until explicitly handled above. */
    static const divergence_type_t known_flags = DIVERGENCE_CONTENT |
        DIVERGENCE_TYPE | DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP |
        DIVERGENCE_UNVERIFIED | DIVERGENCE_ENCRYPTION | DIVERGENCE_STALE;

    if (orphan->divergence & ~known_flags) {
        /* Unknown divergence type — cannot assess safety, block removal */
        *out_err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_CANNOT_VERIFY, false
        );
        return *out_err ? SAFETY_CHECK_ERROR : SAFETY_CHECK_DONE;
    }

    return SAFETY_CHECK_DONE;  /* Only known-safe flags — safe to remove */
}

/**
 * Check lifecycle state, branch existence, and file-in-tree
 *
 * Four-phase check implementing safety hierarchy:
 *
 * PHASE 1: Controlled Deletion (STATE_DELETED)
 * - Skip branch check entirely (user confirmed intent via remove command)
 * - Proceed to divergence routing
 *
 * PHASE 2: Stale Entry (STATE_RELEASED)
 * - File already identified as removed from Git externally
 * - Auto-release: RELEASED violation, skip all further checks
 *
 * PHASE 3: Branch Existence (STATE_INACTIVE and STATE_ACTIVE)
 * - Branch gone: RELEASED violation (irrecoverable, protect user data)
 * - Branch exists: continue to Phase 4
 *
 * PHASE 4: File-in-Tree (defense in depth)
 * - Branch exists but file not in tree: RELEASED violation
 * - File in tree: proceed to divergence routing
 *
 * Key Invariant: Only STATE_DELETED (explicit confirmed intent) bypasses
 * safety checks. STATE_RELEASED auto-releases. All other states require both
 * branch existence AND file-in-tree verification for safe removal.
 *
 * @param repo Git repository
 * @param state State database (for targeted lookup)
 * @param orphan Workspace item
 * @param cache Profile cache (branch existence + tree, lazy-loaded)
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
        err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_CANNOT_VERIFY, false
        );
        if (err) {
            *out_err = err;
            return SAFETY_CHECK_ERROR;
        }

        return SAFETY_CHECK_DONE;
    }

    /* Extract lifecycle state and storage_path before freeing entry */
    bool is_controlled_deletion = state_entry->state &&
        strcmp(state_entry->state, STATE_DELETED) == 0;

    bool is_stale = state_entry->state &&
        strcmp(state_entry->state, STATE_RELEASED) == 0;

    char *storage_path = state_entry->storage_path
                       ? strdup(state_entry->storage_path) : NULL;

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
         */
        free(storage_path);
        return SAFETY_CHECK_CONTINUE;  /* Proceed to divergence routing */
    }

    if (is_stale) {
        /* PHASE 2: STALE ENTRY (STATE_RELEASED)
         *
         * File removed from Git externally. Manifest repair (or workspace
         * in-memory patching) already identified this as loss of authority.
         * Auto-release without further checks — the decision was already made.
         */
        free(storage_path);
        err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_RELEASED, false
        );
        if (err) {
            *out_err = err;
            return SAFETY_CHECK_ERROR;
        }
        return SAFETY_CHECK_DONE;
    }

    /* PHASE 3: BRANCH EXISTENCE CHECK (STATE_INACTIVE and STATE_ACTIVE)
     *
     * For both staged removals (profile disable) and active entries,
     * verify the profile branch still exists. If the branch is gone,
     * Git content is irrecoverable — release files to prevent data loss.
     */
    bool profile_exists = false;
    err = check_profile_exists(repo, cache, orphan->profile, &profile_exists);
    if (err) {
        if (error_code(err) == ERR_MEMORY) {
            /* Memory allocation failure — fatal */
            free(storage_path);
            *out_err = error_wrap(
                err, "Failed to check profile existence for '%s'",
                orphan->profile
            );
            return SAFETY_CHECK_ERROR;
        }
        /* Git lookup failed (transient I/O, locked packfile, etc.)
         * Cannot determine branch existence — block removal to preserve state.
         * Don't emit RELEASED (would permanently delete state entry). */
        error_free(err);
        free(storage_path);
        err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_CANNOT_VERIFY, false
        );
        if (err) {
            *out_err = err;
            return SAFETY_CHECK_ERROR;
        }
        return SAFETY_CHECK_DONE;
    }

    if (!profile_exists) {
        /* Branch deleted externally. Release file from management. */
        free(storage_path);
        err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_RELEASED, false
        );
        if (err) {
            *out_err = err;
            return SAFETY_CHECK_ERROR;
        }
        return SAFETY_CHECK_DONE;
    }

    /* PHASE 4: FILE-IN-TREE CHECK (defense in depth)
     *
     * Branch exists, but file may have been removed from it externally.
     * Verify the specific file still exists in the profile's current tree.
     * This catches: git rm <file> && git commit (branch alive, file gone).
     */
    const char *lookup_path = storage_path ? storage_path : orphan->storage_path;

    if (!lookup_path) {
        /* No storage path available — cannot verify file in Git tree.
         * Block removal rather than silently bypassing defense-in-depth check. */
        err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_CANNOT_VERIFY, false
        );
        if (err) {
            *out_err = err;
            return SAFETY_CHECK_ERROR;
        }
        return SAFETY_CHECK_DONE;
    }

    bool file_in_tree = false;
    err = check_file_in_tree(repo, cache, orphan->profile, lookup_path, &file_in_tree);
    if (err) {
        /* Tree entry lookup failed (corrupt tree, OOM).
         * Degrade to CANNOT_VERIFY — don't release (destructive to state),
         * don't allow removal (can't confirm Git backing). */
        error_free(err);
        free(storage_path);
        err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_CANNOT_VERIFY, false
        );
        if (err) {
            *out_err = err;
            return SAFETY_CHECK_ERROR;
        }
        return SAFETY_CHECK_DONE;
    }

    if (!file_in_tree) {
        /* Branch exists but file doesn't — loss of authority.
         * Git cannot back this file. Release from management. */
        free(storage_path);
        err = add_violation(
            result, orphan->filesystem_path, orphan->storage_path,
            orphan->profile, SAFETY_REASON_RELEASED, false
        );
        if (err) {
            *out_err = err;
            return SAFETY_CHECK_ERROR;
        }
        return SAFETY_CHECK_DONE;
    }

    free(storage_path);
    return SAFETY_CHECK_CONTINUE;  /* File backed by Git, proceed to divergence routing */
}

/**
 * Check removal safety for orphaned workspace items
 *
 * Validates that orphaned files can be safely removed by checking:
 * 1. Lifecycle state (STATE_DELETED bypasses, STATE_RELEASED auto-releases)
 * 2. Branch existence (external deletion detection)
 * 3. File-in-tree (defense in depth — branch exists but file removed)
 * 4. Workspace divergence (trusted completely - no re-verification)
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
        return ERROR(
            ERR_INVALID_ARG, "orphans cannot be NULL when orphan_count > 0"
        );
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
        check_result_t check_result = check_branch_existence(
            repo, state, orphan, cache, result, &err
        );

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
