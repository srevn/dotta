/**
 * transfer.h - Unified transfer context for network operations
 *
 * Provides an opaque context for Git network operations (clone, fetch,
 * push, delete) that encapsulates credential session identity and
 * progress reporting.
 *
 * Design principles:
 * - Single context per command-level network session (one remote, N ops)
 * - Opaque: struct body is private to transfer.c
 * - Encapsulates credential session state and identity
 * - Type-safe payload for libgit2 callbacks
 * - Commits exactly one approve/reject decision to the credential helper
 *   at session teardown (based on classified op outcomes)
 */

#ifndef DOTTA_TRANSFER_H
#define DOTTA_TRANSFER_H

#include <git2.h>
#include <stdbool.h>
#include <types.h>

#include "base/output.h"

/* Opaque transfer context. Struct body lives in transfer.c. */
typedef struct transfer_context_s transfer_context_t;

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
 * Configuration for transfer_context_create.
 *
 * Designated-initializer friendly; unset fields default to zero/NULL/false.
 */
typedef struct {
    output_t *output;              /* Required. Borrowed for the session. */
    const char *url;               /* Remote URL. NULL is legal (SSH agent /
                                    * unauthenticated paths still work;
                                    * helper approve/reject become no-ops). */
    bool ephemeral_progress;       /* If true, clear the progress line on
                                    * completion instead of emitting "done". */
} transfer_options_t;

/**
 * Create a transfer context.
 *
 * @param opts Configuration (must not be NULL; opts->output required)
 * @param out  Receives the new context on success (caller frees via
 *             transfer_context_free)
 * @return Error or NULL on success. On failure, *out is unchanged.
 */
error_t *transfer_context_create(
    const transfer_options_t *opts,
    transfer_context_t **out
);

/**
 * Free a transfer context.
 *
 * Before freeing, commits the session's credential decision to the
 * helper exactly once: approve on VALIDATED, reject on REJECTED,
 * neither on NOT_ACQUIRED (SSH/anonymous) or unresolved ACQUIRED.
 * NULL-safe.
 */
void transfer_context_free(transfer_context_t *ctx);

/**
 * Begin an op on this transfer session.
 *
 * Resets per-op counters (anti-loop attempts, last_outcome). Pair with
 * transfer_op_end() around each libgit2 network call (git_clone,
 * git_remote_fetch, git_remote_push, git_remote_connect).
 *
 * NULL-safe.
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
 * NULL-safe.
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
 * NULL-safe (returns TRANSFER_OUTCOME_NONE).
 */
transfer_outcome_t transfer_last_outcome(const transfer_context_t *xfer);

/**
 * Wire transfer context into a libgit2 remote_callbacks struct.
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
 * Mark the progress line as no longer active.
 *
 * Callers that take manual ownership of the current output line (clearing
 * it or emitting their own content) invoke this to suppress the safety-net
 * newline that transfer_context_free would otherwise emit at teardown.
 *
 * NULL-safe.
 */
void transfer_clear_progress(transfer_context_t *xfer);

/**
 * Return true iff any objects were received by a fetch op on this session.
 *
 * Used to distinguish "up-to-date, nothing to fetch" from "fetched
 * something" when resolving the trailing progress line.
 *
 * NULL-safe (returns false).
 */
bool transfer_received_any(const transfer_context_t *xfer);

/**
 * libgit2 credential callback (payload = transfer_context_t *).
 *
 * Installed by transfer_configure_callbacks. Not intended for direct use.
 */
int transfer_credentials_callback(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    void *payload
);

/**
 * libgit2 fetch progress callback (payload = transfer_context_t *).
 *
 * Installed by transfer_configure_callbacks. Not intended for direct use.
 */
int transfer_progress_callback(
    const git_indexer_progress *stats,
    void *payload
);

/**
 * libgit2 push progress callback (payload = transfer_context_t *).
 *
 * Installed by transfer_configure_callbacks. Not intended for direct use.
 */
int transfer_push_progress_callback(
    unsigned int current,
    unsigned int total,
    size_t bytes,
    void *payload
);

#endif /* DOTTA_TRANSFER_H */
