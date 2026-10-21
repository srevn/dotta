/**
 * transfer.h - Unified transfer context for network operations
 *
 * Provides an opaque context for Git network operations (clone, fetch, push,
 * delete) that encapsulates credential session identity, progress reporting,
 * and what its ops moved on the wire.
 *
 * Design principles:
 * - Single context per command-level network session (one remote, N ops)
 * - Opaque: struct body is private to transfer.c
 * - Encapsulates credential session state and identity
 * - Type-safe payload for libgit2 callbacks
 * - Commits exactly one approve/reject decision to the credential helper at session
 *   teardown (based on classified op outcomes)
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
 * What moved on the wire, one way
 */
typedef struct {
    size_t objects;             /* Objects received or sent */
    size_t bytes;               /* Their bytes; 0 where the transport counts none (a local push) */
} transfer_wire_t;

/**
 * Cumulative transfer metrics for a session: what it received and what it sent.
 *
 * Every op that succeeded folds what it moved into its direction's at its end
 * (transfer_op_end): a fetch into received, a push into sent. A failed op folds
 * nothing, and an op that moved nothing — an up-to-date fetch, a connect that
 * lists the remote's heads — adds nothing: the intent is "what moved", not "how
 * many syscalls". The fold is the counters' one writer and only adds, so the
 * difference of two readings is what the ops between them moved.
 *
 * Fed by the libgit2 progress callbacks TTY-independently, so metrics are accurate
 * on pipes and logs, not just interactive terminals. Read by value
 * (transfer_stats), and over an interval (transfer_stats_since).
 */
typedef struct {
    transfer_wire_t received;   /* Every fetch's */
    transfer_wire_t sent;       /* Every push's */
} transfer_stats_t;

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
 * @return The context (caller frees via transfer_context_free)
 */
transfer_context_t *transfer_context_create(const transfer_options_t *opts);

/**
 * Free a transfer context.
 *
 * Before freeing, commits the session's credential decision to the helper exactly
 * once: approve on VALIDATED, reject on REJECTED, neither on NOT_ACQUIRED
 * (SSH/anonymous) or unresolved ACQUIRED. NULL-safe.
 */
void transfer_context_free(transfer_context_t *ctx);

/**
 * Begin an op on this transfer session.
 *
 * Resets per-op scratch (anti-loop attempts, last_outcome, the op's wire). Records
 * the direction so transfer_op_end() knows which side of transfer_stats_t to
 * fold into on success.
 *
 * Pair with transfer_op_end() around each libgit2 network call (git_clone,
 * git_remote_fetch, git_remote_push, git_remote_connect).
 *
 * NULL-safe.
 *
 * @param xfer      Transfer context (may be NULL)
 * @param direction GIT_DIRECTION_FETCH or GIT_DIRECTION_PUSH
 */
void transfer_op_begin(transfer_context_t *xfer, git_direction direction);

/**
 * End an op on this transfer session.
 *
 * Ends the progress line the op drew, the one place it ends: cleared where the
 * session's progress is ephemeral, else closed with ", done." for an op that
 * succeeded and a bare newline for one that failed. So no line outlives its op,
 * and a caller that announced the op on that line finds only its announce left.
 *
 * Classifies `rc` into last_outcome and advances the credential state machine:
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
 * @param rc libgit2 return code (0, GIT_EAUTH, or other negative)
 */
void transfer_op_end(transfer_context_t *xfer, int rc);

/**
 * What the session has moved so far: its stats, by value — the mark an interval
 * is measured from (transfer_stats_since)
 *
 * NULL-safe (zero for NULL).
 */
transfer_stats_t transfer_stats(const transfer_context_t *xfer);

/**
 * What the session moved since `mark`, a reading transfer_stats gave of it: the
 * ops that succeeded between the two readings, each direction's
 *
 * Readers: cmds/sync.c sync_execute (a row's act), sync_fetch, and
 * sync_reconcile_epoch (the epoch's establish and adopt).
 *
 * NULL-safe, as transfer_stats is.
 */
transfer_stats_t transfer_stats_since(
    const transfer_context_t *xfer,
    transfer_stats_t mark
);

#define TRANSFER_PHRASE_MAX 64 /* "%zu objects, " at a size_t's widest, a size output_format_size writes, and NUL */

/**
 * A wire's words: its objects, and their size where the transport counted one
 *
 * "1 object", "8 objects, 687 B": the phrase, not its frame — each reader sets
 * the frame its line gives a wire, and says nothing where nothing moved. Bytes
 * of zero leave the size unsaid rather than say a size of nothing: the transport
 * counted none (transfer_wire_t, a local push).
 *
 * Readers: sys/transfer.c transfer_print_wire, the summary's line a direction;
 * cmds/sync.c sync_print_wire, beside the line that says an op.
 *
 * @param wire What moved, one way
 * @param buffer Output buffer for the phrase (must not be NULL)
 * @param buffer_size Size of output buffer: TRANSFER_PHRASE_MAX
 */
void transfer_wire_phrase(
    transfer_wire_t wire,
    char *buffer,
    size_t buffer_size
);

/**
 * Emit a summary of the session's transfer activity, a line a direction.
 *
 * Writes "Fetched <phrase>" and/or "Pushed <phrase>" (transfer_wire_phrase) to
 * `out` at the given verbosity level. Silent when:
 *   - `xfer` or `out` is NULL,
 *   - the session's last op failed (the error message already carries the
 *     narrative; a summary would be misleading),
 *   - no direction saw any data (nothing interesting to report).
 *
 * Reader: cmds/profile.c profile_fetch, beneath its rows.
 */
void transfer_summarize(
    const transfer_context_t *xfer,
    output_t *out,
    output_verbosity_t level
);

/**
 * Wire transfer context into a libgit2 remote_callbacks struct.
 *
 * Installs the credential callback (always), the progress callback matching
 * `direction`, and for a push the per-ref status (transfer_push_status_callback),
 * without which a ref the remote refused reads as pushed. The transfer context
 * is required — every gitops_* network primitive enforces this with CHECK_NULL,
 * so a NULL payload here would be a dotta-internal contract violation, not a
 * user-recoverable case.
 *
 * Ops with no byte transfer (e.g., git_remote_connect + git_remote_ls) may pass
 * GIT_DIRECTION_FETCH; the installed progress callback simply never fires.
 *
 * @param cb        Callbacks struct (caller must have initialized it)
 * @param xfer      Transfer context (must not be NULL)
 * @param direction GIT_DIRECTION_FETCH or GIT_DIRECTION_PUSH
 */
void transfer_configure_callbacks(
    git_remote_callbacks *cb,
    transfer_context_t *xfer,
    git_direction direction
);

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

/**
 * libgit2 push status callback (payload = transfer_context_t *).
 *
 * A ref the remote refused is the push's failure, said in the remote's words: a
 * local remote's refusal (lib/libgit2/src/libgit2/transports/local.c local_push)
 * and a server's per-ref report alike. Installed by transfer_configure_callbacks
 * for a push. Not intended for direct use.
 *
 * @return 0 for a ref the remote updated; for one it refused, a failure whose
 *         sentence is the remote's reason
 */
int transfer_push_status_callback(
    const char *refname,
    const char *status,
    void *payload
);

#endif /* DOTTA_TRANSFER_H */
