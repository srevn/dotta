/**
 * transfer.h - Unified transfer context for network operations
 *
 * Provides a unified context for Git network operations (clone, fetch, push)
 * that encapsulates both credential handling and progress reporting.
 *
 * Design principles:
 * - Single context per operation (matches libgit2 design)
 * - Encapsulates credentials (callers don't manage them directly)
 * - Type-safe (no void* payloads)
 * - Delegates to existing credential and output systems
 * - Extensible for future enhancements (sideband, pack progress)
 */

#ifndef DOTTA_TRANSFER_H
#define DOTTA_TRANSFER_H

#include <git2.h>
#include <stdbool.h>

#include "base/output.h"
#include "sys/credentials.h"

/**
 * Outcome of the most recent op within a transfer session.
 *
 * Reported by transfer_last_outcome() to let callers classify errors
 * authoritatively instead of matching on libgit2's English error strings.
 */
typedef enum {
    TRANSFER_OUTCOME_NONE = 0,     /* No op has completed in this session. */
    TRANSFER_OUTCOME_OK,           /* Op succeeded. */
    TRANSFER_OUTCOME_AUTH_FAILED,  /* Op failed with an authentication error. */
    TRANSFER_OUTCOME_OTHER_FAILURE /* Op failed for a non-auth reason. */
} transfer_outcome_t;

/**
 * Transfer context for network operations
 *
 * Unified context that manages credential session state and progress
 * reporting for Git network operations (clone, fetch, push). A single
 * context spans multiple ops against one remote (e.g., a sync that
 * fetches then pushes several profiles); the credential session caches
 * creds across ops and commits an approve/reject decision to the
 * credential helper exactly once, at transfer_context_free().
 */
typedef struct transfer_context_s {
    credential_context_t *cred; /* Credential context (owned) */
    output_t *output;           /* Output context (borrowed) */

    /* Progress tracking state */
    bool progress_active;          /* Whether progress is currently being displayed */
    bool ephemeral;                /* Clear progress on completion instead of showing "done" */
    const char *operation;         /* Current operation ("Receiving", "Sending", etc.) */

    /* Transfer statistics */
    size_t total_objects;          /* Total objects to transfer */
    size_t indexed_objects;        /* Objects indexed so far */
    size_t received_objects;       /* Objects received so far */
    size_t received_bytes;         /* Bytes received so far */

    /* Credential session state (internal — use the transfer_* API below).
     * credential_state is stored as int so the enum stays file-local to
     * transfer.c and callers cannot depend on its values. */
    int credential_state;          /* credential_state_t in transfer.c */
    transfer_outcome_t last_outcome; /* Outcome of the most recent op. */
    int attempts;                  /* Per-op anti-loop counter. */
} transfer_context_t;

/**
 * Create transfer context
 *
 * Creates a transfer context for a network operation. The context owns
 * the credential context and will free it on destruction. The output
 * context is borrowed and must remain valid for the lifetime of the
 * transfer context.
 *
 * @param output Output context for progress reporting (may be NULL for silent)
 * @param url Remote URL for credential handling (may be NULL)
 * @return Transfer context or NULL on allocation failure
 */
transfer_context_t *transfer_context_create(output_t *output, const char *url);

/**
 * Free transfer context
 *
 * Frees the transfer context and its owned credential context.
 * Before freeing, commits the session's credential decision to the
 * helper exactly once: approve on VALIDATED, reject on REJECTED,
 * neither on NOT_ACQUIRED (SSH/anonymous) or unresolved ACQUIRED.
 *
 * Safe to call with NULL.
 *
 * @param ctx Transfer context (may be NULL)
 */
void transfer_context_free(transfer_context_t *ctx);

/**
 * Begin an op on this transfer session.
 *
 * Resets per-op counters (anti-loop attempts, last_outcome). Pair with
 * transfer_op_end() around each libgit2 network call (git_clone,
 * git_remote_fetch, git_remote_push, git_remote_connect).
 *
 * Safe to call with NULL.
 */
void transfer_op_begin(transfer_context_t *xfer);

/**
 * End an op on this transfer session.
 *
 * Classifies `git_err` into last_outcome and advances the credential
 * state machine:
 *
 *   NOT_ACQUIRED  + anything     → NOT_ACQUIRED   (no helper fill happened)
 *   ACQUIRED      + OK           → VALIDATED      (terminal)
 *   ACQUIRED      + AUTH_FAILED  → REJECTED       (terminal)
 *   ACQUIRED      + OTHER        → ACQUIRED       (network hiccup, etc.)
 *   VALIDATED     + anything     → VALIDATED      (terminal-absorbing)
 *   REJECTED      + anything     → REJECTED       (terminal-absorbing)
 *
 * Safe to call with NULL.
 *
 * @param xfer    Transfer context (may be NULL)
 * @param git_err libgit2 return code (0, GIT_EAUTH, or other negative)
 */
void transfer_op_end(transfer_context_t *xfer, int git_err);

/**
 * Return the outcome of the most recent op.
 *
 * Callers should inspect this immediately after the op completes,
 * before the next transfer_op_begin() overwrites it.
 *
 * @param xfer Transfer context (may be NULL)
 * @return transfer_outcome_t (NONE for NULL input)
 */
transfer_outcome_t transfer_last_outcome(const transfer_context_t *xfer);

/**
 * Wire transfer_context_t into a libgit2 remote_callbacks struct.
 *
 * Installs the credential callback (always) and the progress callback
 * matching `direction`. NULL xfer is safe: payload becomes NULL and
 * the credential callback falls through to SSH/anonymous paths without
 * session tracking.
 *
 * Ops with no byte transfer (e.g., git_remote_connect + git_remote_ls)
 * may pass GIT_DIRECTION_FETCH; the installed progress callback simply
 * never fires.
 *
 * @param cb        Callbacks struct (caller must have initialized it)
 * @param xfer      Transfer context (may be NULL)
 * @param direction GIT_DIRECTION_FETCH or GIT_DIRECTION_PUSH
 */
void transfer_configure_callbacks(
    git_remote_callbacks *cb,
    transfer_context_t *xfer,
    git_direction direction
);

/**
 * Credential callback for libgit2
 *
 * This callback is used for clone, fetch, and push operations.
 * Delegates to the credential system (credentials_callback).
 *
 * @param out Output credential object
 * @param url Remote URL being accessed
 * @param username_from_url Username from URL (may be NULL)
 * @param allowed_types Allowed credential types (bitfield)
 * @param payload Transfer context (transfer_context_t*)
 * @return 0 on success, negative error code on failure
 */
int transfer_credentials_callback(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    void *payload
);

/**
 * Transfer progress callback for fetch operations
 *
 * Called by libgit2 during fetch to report download progress.
 * Uses output_progress() to display progress to the user.
 *
 * @param stats Transfer statistics
 * @param payload Transfer context (transfer_context_t*)
 * @return 0 to continue, negative to abort
 */
int transfer_progress_callback(
    const git_indexer_progress *stats,
    void *payload
);

/**
 * Push transfer progress callback for push operations
 *
 * Called by libgit2 during push to report upload progress.
 * Uses output_progress() to display progress to the user.
 *
 * @param current Number of objects transferred
 * @param total Total number of objects
 * @param bytes Bytes transferred
 * @param payload Transfer context (transfer_context_t*)
 * @return 0 to continue, negative to abort
 */
int transfer_push_progress_callback(
    unsigned int current,
    unsigned int total,
    size_t bytes,
    void *payload
);

#endif /* DOTTA_TRANSFER_H */
