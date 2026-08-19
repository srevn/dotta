/**
 * safety.c - Data loss prevention for orphan removal
 *
 * The verdict table described in safety.h. Every input is a field of the
 * workspace item: presence, Git authority (WORKSPACE_STATE_RELEASED) and
 * divergence were all observed once, at workspace load, so this module
 * re-verifies nothing and touches neither disk, Git nor state.
 */

#include "core/safety.h"

#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "core/workspace.h"

/* Initial capacity for dynamic arrays */
#define INITIAL_CAPACITY 16

/**
 * Add violation to result
 *
 * Grows the violations array if needed and adds a new entry.
 * Uses direct struct manipulation for efficiency.
 */
static error_t *add_violation(
    safety_result_t *result,
    const char *filesystem_path,
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
    v->source_profile = source_profile ? strdup(source_profile) : NULL;
    v->reason = strdup(reason);
    v->content_modified = content_modified;

    /* Check allocations */
    if (!v->filesystem_path || !v->reason ||
        (source_profile && !v->source_profile)) {
        free(v->filesystem_path);
        free(v->source_profile);
        free(v->reason);
        memset(v, 0, sizeof(safety_violation_t));
        return ERROR(ERR_MEMORY, "Failed to allocate violation strings");
    }

    result->count++;

    /* Split the verdict here, where the reason is chosen — every caller
     * that needs "how many of each" then reads one number instead of
     * folding the array on the reason again. */
    if (strcmp(reason, SAFETY_REASON_RELEASED) == 0) {
        result->released++;
    } else {
        result->blocking++;
    }

    return NULL;
}

/**
 * Map workspace divergence flags to a safety violation
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
 * Note: DIVERGENCE_UNVERIFIED occurs for:
 * - Encrypted files > 100MB (AEAD requires full ciphertext, OOM protection)
 * - Blob corruption (missing blob_oid, invalid OID format)
 * - I/O errors during verification
 * - A present file that could not be stat'd (EACCES, EIO, …)
 * - Git could not answer whether the profile still claims the path
 *
 * Non-encrypted files can be verified at any size using streaming OID
 * verification (git_odb_hashfile), so they should not reach UNVERIFIED.
 *
 * @param orphan Workspace item with pre-computed divergence
 * @param result Safety result to populate (if violation found)
 * @return Error on allocation failure, NULL otherwise (violation added or safe)
 */
static error_t *map_divergence_to_violation(
    const workspace_item_t *orphan,
    safety_result_t *result
) {
    divergence_type_t divergence = orphan->divergence;

    /* DIVERGENCE_NONE: Safe to remove (workspace verified clean) */
    if (divergence == DIVERGENCE_NONE) {
        return NULL;
    }

    /* DIVERGENCE_CONTENT: Content differs from Git */
    if (divergence & DIVERGENCE_CONTENT) {
        return add_violation(
            result, orphan->filesystem_path, orphan->profile,
            SAFETY_REASON_MODIFIED, true
        );
    }

    /* DIVERGENCE_TYPE: File type changed (file <-> symlink) */
    if (divergence & DIVERGENCE_TYPE) {
        return add_violation(
            result, orphan->filesystem_path, orphan->profile,
            SAFETY_REASON_TYPE_CHANGED, true
        );
    }

    /* DIVERGENCE_MODE or DIVERGENCE_OWNERSHIP: Permissions changed */
    if (divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
        return add_violation(
            result, orphan->filesystem_path, orphan->profile,
            SAFETY_REASON_MODE_CHANGED, false
        );
    }

    /* DIVERGENCE_UNVERIFIED: Verification failed */
    if (divergence & DIVERGENCE_UNVERIFIED) {
        return add_violation(
            result, orphan->filesystem_path, orphan->profile,
            SAFETY_REASON_CANNOT_VERIFY, false
        );
    }

    /* All priority flags handled above. Remaining flags:
     * - ENCRYPTION: Policy mismatch (not user modification) — safe
     * - STALE: VWD cache outdated (Git changed) — irrelevant for removal
     * Unknown flags: block removal until explicitly handled above. */
    static const divergence_type_t known_flags = DIVERGENCE_CONTENT |
        DIVERGENCE_TYPE | DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP |
        DIVERGENCE_UNVERIFIED | DIVERGENCE_ENCRYPTION | DIVERGENCE_STALE;

    if (divergence & ~known_flags) {
        /* Unknown divergence type — cannot assess safety, block removal */
        return add_violation(
            result, orphan->filesystem_path, orphan->profile,
            SAFETY_REASON_CANNOT_VERIFY, false
        );
    }

    return NULL;   /* Only known-safe flags — safe to remove */
}

/**
 * Decide removal safety for orphaned workspace items
 *
 * One pass over the items, one verdict each, in the order presence →
 * authority → divergence. The first two are the workspace's observations,
 * read straight off the item; the third is the table above.
 */
error_t *safety_check_orphans(
    workspace_items_t orphans,
    bool force,
    safety_result_t **out_result
) {
    CHECK_NULL(out_result);

    /* Empty slice with NULL entries is valid; non-empty slice with NULL is not. */
    if (orphans.count > 0 && !orphans.entries) {
        return ERROR(
            ERR_INVALID_ARG, "orphans.entries cannot be NULL when count > 0"
        );
    }

    safety_result_t *result = calloc(1, sizeof(safety_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate safety result");
    }

    /* Force mode or empty input: return empty result */
    if (force || orphans.count == 0) {
        *out_result = result;
        return NULL;
    }

    for (size_t i = 0; i < orphans.count; i++) {
        const workspace_item_t *orphan = orphans.entries[i];
        error_t *err = NULL;

        /* Already gone: nothing to protect. Cleanup reclaims the row. */
        if (!orphan->on_filesystem) {
            continue;
        }

        if (orphan->state == WORKSPACE_STATE_RELEASED) {
            /* Git no longer backs the file — the workspace observed it,
             * either from the lifecycle column (the consistency layer's
             * decision) or against Git at load. Left on disk; the row
             * retires because dotta cannot manage what Git cannot restore. */
            err = add_violation(
                result, orphan->filesystem_path, orphan->profile,
                SAFETY_REASON_RELEASED, false
            );
        } else {
            err = map_divergence_to_violation(orphan, result);
        }

        if (err) {
            safety_result_free(result);
            return err;
        }
    }

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
        free(result->violations[i].source_profile);
        free(result->violations[i].reason);
    }

    free(result->violations);
    free(result);
}
