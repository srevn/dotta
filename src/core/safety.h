/**
 * safety.h - Data loss prevention for orphan removal
 *
 * Answers one question per orphaned item: may `dotta apply` remove this
 * file, and if not, why not. The answer is a pure function of the
 * workspace item — this module reads no disk, no Git and no state.
 *
 * Every fact it needs was observed once, at workspace load:
 * - on_filesystem  is the file still there?
 * - state          does Git still back the path? (WORKSPACE_STATE_RELEASED
 *                  when it does not — set from the lifecycle column by the
 *                  consistency layer, or observed against Git by the
 *                  workspace's orphan analysis for the rows that layer
 *                  does not cover)
 * - divergence     did the user change it since dotta deployed it?
 *
 * Verdict table (first match wins):
 *   not on filesystem              no violation — cleanup reclaims the row
 *   state RELEASED                 RELEASED     — left on disk, row retires
 *   DIVERGENCE_CONTENT             MODIFIED
 *   DIVERGENCE_TYPE                TYPE_CHANGED
 *   DIVERGENCE_MODE / OWNERSHIP    MODE_CHANGED
 *   DIVERGENCE_UNVERIFIED          CANNOT_VERIFY
 *   an unnamed divergence bit      CANNOT_VERIFY (defensive default)
 *   ENCRYPTION / STALE only        no violation — not user changes
 *   DIVERGENCE_NONE                no violation — safe to remove
 *
 * Divergence-side edge cases, and where their bits come from:
 * - Large non-encrypted files: verified by streaming OID hash (any size)
 * - Large encrypted files (>100MB): UNVERIFIED (OOM protection)
 * - Blob corruption, decryption failure, I/O during verification: UNVERIFIED
 * - Stat failed but the file is present (EACCES): UNVERIFIED
 * - Git could not be consulted for authority: UNVERIFIED, so the orphan is
 *   held rather than released or pruned
 * - ENCRYPTION (policy mismatch) and STALE (VWD cache refreshed) are not
 *   user modifications: safe to remove
 * - File deleted between load and this check: no violation — the load-time
 *   observation still governs here; cleanup sees the absence when it acts
 *   and reclaims the row
 *
 * force yields an empty result: every present orphan becomes removable,
 * released files included.
 */

#ifndef DOTTA_SAFETY_H
#define DOTTA_SAFETY_H

#include <stdbool.h>
#include <stddef.h>

#include "core/workspace.h"

/**
 * Safety violation details
 *
 * Represents a single file that cannot be safely removed due to uncommitted
 * changes or verification failures.
 */
typedef struct {
    char *filesystem_path;      /* File path on disk */
    char *source_profile;       /* Profile that originally tracked this file */
    char *reason;               /* Machine-readable reason code (see SAFETY_REASON_* below) */
    bool content_modified;      /* True if content differs (not just metadata) */
} safety_violation_t;

/**
 * Reason codes for safety violations
 *
 * Used in safety_violation_t.reason field for programmatic handling and display.
 */
#define SAFETY_REASON_RELEASED         "released"          /* Git no longer backs the file */
#define SAFETY_REASON_MODIFIED         "modified"          /* Content changed */
#define SAFETY_REASON_MODE_CHANGED     "mode_changed"      /* Permissions changed */
#define SAFETY_REASON_TYPE_CHANGED     "type_changed"      /* File<->symlink conversion */
#define SAFETY_REASON_CANNOT_VERIFY    "cannot_verify"     /* Unable to verify (I/O, permissions) */

/**
 * Safety check result
 *
 * Contains list of files that are unsafe to remove.
 * Empty list (count == 0) means all files are safe to remove.
 */
typedef struct {
    safety_violation_t *violations;  /* Array of violations (owns memory) */
    size_t count;                    /* Number of violations */
    size_t capacity;                 /* Allocated capacity (internal use) */

    /* The reason split, counted where the reasons are assigned.
     *
     * Every violation is one or the other, so blocking + released ==
     * count. Both leave the file on disk; they differ in what happens to
     * the state row. RELEASED means Git no longer backs the file, so the
     * row retires and dotta lets go of it. Everything else means the file
     * diverged from what dotta last deployed, so the row stays and the
     * removal is refused until the user resolves it.
     *
     * Callers that need the split read these. Re-folding the array on the
     * reason makes a second producer of a fact this module already
     * decided. */
    size_t blocking;                 /* Removal refused, row kept */
    size_t released;                 /* Authority lost, row retires */
} safety_result_t;

/**
 * Decide removal safety for orphaned workspace items
 *
 * Maps each orphan to a verdict using the table in this header's overview.
 * Present orphans with nothing against them yield no violation and are the
 * caller's to prune; everything else is named here, once, with a reason
 * the caller displays and routes on.
 *
 * Performance: O(n) in the orphan count. No syscalls, no queries — the
 * observations were made at workspace load.
 *
 * @param orphans Workspace items marked as orphaned or released (empty slice valid)
 * @param force If true, skip all checks (emergency override — empty result)
 * @param out_result Output safety result (must not be NULL, caller must free)
 * @return Error on fatal failure (allocation), NULL on success
 */
error_t *safety_check_orphans(
    workspace_items_t orphans,
    bool force,
    safety_result_t **out_result
);

/**
 * Free safety result
 *
 * Frees all contained violations and the result structure itself.
 *
 * Note: Individual violations are stored inline in the result array and
 * cannot be freed separately. This function handles all cleanup.
 *
 * @param result Result to free (can be NULL)
 */
void safety_result_free(safety_result_t *result);

#endif /* DOTTA_SAFETY_H */
