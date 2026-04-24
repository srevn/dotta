/**
 * transfer.c - Unified transfer context for network operations
 */

#include "sys/transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <git2/errors.h>

#include "base/output.h"
#include "sys/credentials.h"

/**
 * Credential session states (file-local).
 *
 * Terminal states (VALIDATED, REJECTED) are absorbing: once reached,
 * further ops cannot change the decision that will be committed at
 * transfer_context_free(). NOT_ACQUIRED means no helper fill happened
 * (SSH agent, SSH key, anonymous, default) — nothing to approve or
 * reject.
 */
typedef enum {
    CRED_STATE_NOT_ACQUIRED = 0,  /* Initial; SSH/anonymous stay here. */
    CRED_STATE_ACQUIRED,          /* Helper filled creds; outcome pending. */
    CRED_STATE_VALIDATED,         /* At least one op succeeded. Terminal. */
    CRED_STATE_REJECTED           /* Auth failed with no prior success. Terminal. */
} credential_state_t;

/**
 * Map a libgit2 return code to a transfer outcome class.
 *
 * GIT_EAUTH is libgit2's canonical auth-failure signal — returned when
 * our credential callback bails with GIT_EAUTH, or when libgit2 exhausts
 * its own retry budget against server rejections. We treat it as
 * definitive.
 *
 * Rarely, auth failures may surface as generic errors (certain TLS/SSH
 * paths, HTTP 401 before the credential callback runs). Those classify
 * as OTHER_FAILURE here; the resulting wording is suboptimal but not
 * incorrect. If smoke tests surface a misclassified case, widen the
 * match (e.g., inspect giterr_last()->klass).
 */
static transfer_outcome_t classify_outcome(int git_err) {
    if (git_err == 0) return TRANSFER_OUTCOME_OK;
    if (git_err == GIT_EAUTH) return TRANSFER_OUTCOME_AUTH_FAILED;
    return TRANSFER_OUTCOME_OTHER_FAILURE;
}

/**
 * Advance credential_state on first helper fill. Idempotent: subsequent
 * calls (cached-cred replays, terminal states) do not regress the state.
 */
static void transfer_mark_cred_acquired(transfer_context_t *xfer) {
    if (!xfer) return;
    if (xfer->credential_state == CRED_STATE_NOT_ACQUIRED) {
        xfer->credential_state = CRED_STATE_ACQUIRED;
    }
}

/**
 * Finalize the current progress line
 *
 * In ephemeral mode on a TTY, clears the entire line (progress vanishes).
 * In persistent mode, appends the given completion text (e.g., ", done.\n").
 * Non-TTY ephemeral falls back to newline (ANSI clear requires terminal).
 */
static void finalize_progress(transfer_context_t *ctx, const char *completion) {
    if (ctx->ephemeral) {
        /* Ephemeral: clear the line — progress vanishes */
        output_clear_line(ctx->output);
    } else {
        /* Persistent: show completion text */
        fputs(completion, ctx->output->stream);
        fflush(ctx->output->stream);
    }
    ctx->progress_active = false;
}

/**
 * Create transfer context
 */
transfer_context_t *transfer_context_create(output_t *output, const char *url) {
    transfer_context_t *ctx = calloc(1, sizeof(transfer_context_t));
    if (!ctx) {
        return NULL;
    }

    /* Create credential context (owned by transfer context) */
    ctx->cred = credential_context_create(url);
    if (!ctx->cred && url) {
        /* If URL was provided but credential creation failed, treat as error */
        free(ctx);
        return NULL;
    }

    /* Borrow output context (not owned) */
    ctx->output = output;

    /* Initialize progress state */
    ctx->progress_active = false;
    ctx->operation = NULL;
    ctx->total_objects = 0;
    ctx->indexed_objects = 0;
    ctx->received_objects = 0;
    ctx->received_bytes = 0;

    return ctx;
}

/**
 * Free transfer context
 */
void transfer_context_free(transfer_context_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Commit the session's credential decision exactly once. Guarded on
     * terminal state: intermediate states (NOT_ACQUIRED, unresolved
     * ACQUIRED) produce no helper traffic. credential_context_approve /
     * reject additionally guard on credentials_provided, so SSH paths
     * are silent even if state somehow advanced. */
    if (ctx->cred) {
        if (ctx->credential_state == CRED_STATE_VALIDATED) {
            credential_context_approve(ctx->cred);
        } else if (ctx->credential_state == CRED_STATE_REJECTED) {
            credential_context_reject(ctx->cred);
        }
    }

    /* Free owned credential context */
    credential_context_free(ctx->cred);

    /* Clear progress if still active (safety net for interrupted transfers) */
    if (ctx->progress_active && ctx->output) {
        finalize_progress(ctx, "\n");
    }

    /* Free the context itself */
    free(ctx);
}

/**
 * Begin an op — reset per-op counters.
 */
void transfer_op_begin(transfer_context_t *xfer) {
    if (!xfer) return;
    xfer->attempts = 0;
    xfer->last_outcome = TRANSFER_OUTCOME_NONE;
}

/**
 * End an op — classify outcome and advance the credential state machine.
 */
void transfer_op_end(transfer_context_t *xfer, int git_err) {
    if (!xfer) return;

    xfer->last_outcome = classify_outcome(git_err);

    if (xfer->credential_state != CRED_STATE_ACQUIRED) {
        /* NOT_ACQUIRED (no helper fill) and terminal states (VALIDATED,
         * REJECTED) absorb any outcome without transitioning. */
        return;
    }

    switch (xfer->last_outcome) {
        case TRANSFER_OUTCOME_OK:
            xfer->credential_state = CRED_STATE_VALIDATED;
            break;
        case TRANSFER_OUTCOME_AUTH_FAILED:
            xfer->credential_state = CRED_STATE_REJECTED;
            break;
        case TRANSFER_OUTCOME_OTHER_FAILURE:
        case TRANSFER_OUTCOME_NONE:
            /* Non-auth failure: session identity is still pending;
             * a subsequent op may validate or invalidate it. */
            break;
    }
}

/**
 * Return the outcome of the most recent op.
 */
transfer_outcome_t transfer_last_outcome(const transfer_context_t *xfer) {
    return xfer ? xfer->last_outcome : TRANSFER_OUTCOME_NONE;
}

/**
 * Wire transfer_context_t into a remote_callbacks struct.
 */
void transfer_configure_callbacks(
    git_remote_callbacks *cb,
    transfer_context_t *xfer,
    git_direction direction
) {
    if (!cb) return;

    cb->credentials = transfer_credentials_callback;
    cb->payload = xfer;

    if (direction == GIT_DIRECTION_PUSH) {
        cb->push_transfer_progress = transfer_push_progress_callback;
    } else {
        cb->transfer_progress = transfer_progress_callback;
    }
}

/**
 * Credential callback for libgit2
 *
 * Runs two session-level gates before delegating to credentials_callback:
 *
 *   1. Fast-fail on REJECTED — once the server has rejected helper creds
 *      in this session, subsequent ops skip sending the same creds. Saves
 *      a wasted round-trip per op in a multi-profile sync after an auth
 *      failure.
 *
 *   2. Anti-loop — libgit2 re-invokes this callback when the server
 *      rejects creds within a single negotiation. transfer_op_begin
 *      resets the per-op counter, so across-op retries are allowed.
 *
 * On successful fill via the helper, advance the session state to
 * ACQUIRED so transfer_op_end() can then transition to VALIDATED or
 * REJECTED based on the op's outcome.
 */
int transfer_credentials_callback(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    void *payload
) {
    transfer_context_t *ctx = (transfer_context_t *) payload;

    if (ctx && ctx->credential_state == CRED_STATE_REJECTED) {
        return GIT_EAUTH;
    }

    if (ctx && ctx->attempts++ > 0) {
        return GIT_EAUTH;
    }

    int rc = credentials_callback(
        out,
        url,
        username_from_url,
        allowed_types,
        ctx ? ctx->cred : NULL
    );

    if (rc == 0 && ctx && ctx->cred && ctx->cred->credentials_provided) {
        transfer_mark_cred_acquired(ctx);
    }

    return rc;
}

/**
 * Transfer progress callback for fetch operations
 */
int transfer_progress_callback(
    const git_indexer_progress *stats,
    void *payload
) {
    if (!stats || !payload) {
        return 0;
    }

    transfer_context_t *ctx = (transfer_context_t *) payload;

    /* Skip progress if no output context or below NORMAL verbosity */
    if (!ctx->output || ctx->output->verbosity < OUTPUT_NORMAL) {
        return 0;
    }

    /* Inline progress uses \r — only works on TTY */
    if (!output_is_tty(ctx->output)) return 0;

    /* Update statistics */
    ctx->total_objects = stats->total_objects;
    ctx->indexed_objects = stats->indexed_objects;
    ctx->received_objects = stats->received_objects;
    ctx->received_bytes = stats->received_bytes;

    unsigned int total = stats->total_objects;
    unsigned int received = stats->received_objects;
    unsigned int indexed = stats->indexed_objects;

    /* Determine what to display based on state */
    if (total > 0) {
        /* Show receiving progress with percentage and bytes */
        int percent = (received * 100) / total;
        char bytes_str[32];
        output_format_size(stats->received_bytes, bytes_str, sizeof(bytes_str));

        /* Display: "Receiving objects: XX% (current/total), X.X MiB" */
        fprintf(
            ctx->output->stream, "\rReceiving objects: %3d%% (%u/%u), %s",
            percent, received, total, bytes_str
        );
        fflush(ctx->output->stream);
        ctx->progress_active = true;

        /* Check if indexing is complete (guard prevents double finalization) */
        if (indexed == total && received == total && ctx->progress_active) {
            finalize_progress(ctx, ", done.\n");
        }
    } else if (received > 0) {
        /* Don't know total yet, just show count */
        char bytes_str[32];
        output_format_size(stats->received_bytes, bytes_str, sizeof(bytes_str));

        fprintf(
            ctx->output->stream, "\rReceiving objects: %u, %s",
            received, bytes_str
        );
        fflush(ctx->output->stream);
        ctx->progress_active = true;
    }

    return 0;
}

/**
 * Push transfer progress callback for push operations
 */
int transfer_push_progress_callback(
    unsigned int current,
    unsigned int total,
    size_t bytes,
    void *payload
) {
    if (!payload) {
        return 0;
    }

    transfer_context_t *ctx = (transfer_context_t *) payload;

    /* Skip progress if no output context or below NORMAL verbosity */
    if (!ctx->output || ctx->output->verbosity < OUTPUT_NORMAL) {
        return 0;
    }

    /* Inline progress uses \r — only works on TTY */
    if (!output_is_tty(ctx->output)) return 0;

    /* Update statistics */
    ctx->total_objects = total;
    ctx->received_objects = current;
    ctx->received_bytes = bytes;

    /* Calculate progress percentage */
    if (total > 0) {
        int percent = (current * 100) / total;

        /* Display: "Sending objects: XX% (current/total)" */
        fprintf(
            ctx->output->stream, "\rSending objects: %3d%% (%u/%u)",
            percent, current, total
        );
        fflush(ctx->output->stream);
        ctx->progress_active = true;

        /* Check if complete (guard prevents double finalization) */
        if (current == total && ctx->progress_active) {
            finalize_progress(ctx, ", done.\n");
        }
    } else {
        /* No total known - just show current */
        fprintf(ctx->output->stream, "\rSending objects: %u", current);
        fflush(ctx->output->stream);
        ctx->progress_active = true;
    }

    return 0;
}
