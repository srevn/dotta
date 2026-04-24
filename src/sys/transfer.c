/**
 * transfer.c - Unified transfer context for network operations
 */

#include "sys/transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <git2/errors.h>

#include "base/buffer.h"
#include "base/error.h"
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
 * Transfer context.
 *
 * Owns the full lifecycle of a network session against one remote:
 *   - Progress reporting (line state, ephemeral flag)
 *   - Session stats (cumulative objects/bytes across all ops)
 *   - Credential identity (URL, cached username/password)
 *   - Credential state machine (acquisition → validation / rejection)
 *
 * Per-op counters (attempts, last_outcome, op scratch) are reset by
 * transfer_op_begin and classified/folded by transfer_op_end. The cached
 * credentials are filled at most once per session by the first successful
 * helper fill (cache-once identity pinning).
 */
struct transfer_context_s {
    output_t *output;               /* Borrowed. */

    /* Progress UI state */
    bool progress_active;           /* Line is mid-display. */
    bool ephemeral;                 /* Clear on completion. */

    /* Cumulative session stats (TTY-independent) */
    transfer_stats_t stats;

    /* Per-op scratch. Written by the progress callbacks on each update;
     * folded into `stats` by transfer_op_end on success. Reset by
     * transfer_op_begin. */
    struct {
        git_direction direction;    /* Op direction (fetch/push). */
        size_t last_count;          /* Last received_objects or current. */
        size_t last_bytes;          /* Last received_bytes or bytes. */
    } op;

    /* Credential session identity */
    char *url;                      /* Owned. Captured at create; drives
                                     * helper approve/reject at teardown. */
    char *username;                 /* Owned, heap, wiped on free. */
    char *password;                 /* Owned, heap, wiped on free. */

    /* Session state machine */
    credential_state_t credential_state;
    transfer_outcome_t last_outcome;
    int attempts;                   /* Per-op anti-loop counter. */
};

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
 * Securely replace a heap-allocated secret with a new heap-allocated value.
 *
 * Wipes and frees the old buffer (if any), then installs the new pointer.
 * `*slot` is a field slot (e.g., `&ctx->username`). Ownership of `incoming`
 * transfers to the slot; the caller must NOT free it after this call.
 */
static void secure_replace(char **slot, char *incoming) {
    if (*slot) {
        buffer_secure_free(*slot, strlen(*slot) + 1);
    }
    *slot = incoming;
}

/**
 * Finalize the current progress line.
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

error_t *transfer_context_create(
    const transfer_options_t *opts,
    transfer_context_t **out
) {
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(opts->output);

    transfer_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return ERROR(ERR_MEMORY, "Failed to allocate transfer context");
    }

    if (opts->url) {
        ctx->url = strdup(opts->url);
        if (!ctx->url) {
            free(ctx);
            return ERROR(ERR_MEMORY, "Failed to copy transfer URL");
        }
    }

    ctx->output = opts->output;
    ctx->ephemeral = opts->ephemeral_progress;
    /* All other fields zero-initialized by calloc. */

    *out = ctx;
    return NULL;
}

/**
 * Free transfer context
 */
void transfer_context_free(transfer_context_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Commit the session's credential decision exactly once. Helper calls
     * are guarded against empty inputs, so NOT_ACQUIRED / unresolved
     * ACQUIRED states produce no helper traffic (SSH paths never populate
     * username/password). */
    if (ctx->credential_state == CRED_STATE_VALIDATED) {
        credentials_helper_approve(ctx->url, ctx->username, ctx->password);
    } else if (ctx->credential_state == CRED_STATE_REJECTED) {
        credentials_helper_reject(ctx->url, ctx->username, ctx->password);
    }

    /* Clear progress if still active (safety net for interrupted transfers) */
    if (ctx->progress_active && ctx->output) {
        finalize_progress(ctx, "\n");
    }

    if (ctx->username) {
        buffer_secure_free(ctx->username, strlen(ctx->username) + 1);
    }
    if (ctx->password) {
        buffer_secure_free(ctx->password, strlen(ctx->password) + 1);
    }
    free(ctx->url);
    free(ctx);
}

/**
 * Begin an op — reset per-op scratch and record direction.
 */
void transfer_op_begin(transfer_context_t *xfer, git_direction direction) {
    if (!xfer) return;
    xfer->attempts = 0;
    xfer->last_outcome = TRANSFER_OUTCOME_NONE;
    xfer->op.direction = direction;
    xfer->op.last_count = 0;
    xfer->op.last_bytes = 0;
}

/**
 * End an op — fold stats, classify outcome, advance state machine.
 */
void transfer_op_end(transfer_context_t *xfer, int git_err) {
    if (!xfer) return;

    xfer->last_outcome = classify_outcome(git_err);

    /* Fold per-op values into cumulative stats. Only count ops that
     * actually transferred data — connect+ls (list_remote_branches) and
     * up-to-date fetches would otherwise pollute the summary. */
    if (git_err == 0 &&
        (xfer->op.last_count > 0 || xfer->op.last_bytes > 0)) {
        if (xfer->op.direction == GIT_DIRECTION_PUSH) {
            xfer->stats.push_ops++;
            xfer->stats.objects_sent += xfer->op.last_count;
            xfer->stats.bytes_sent += xfer->op.last_bytes;
        } else {
            xfer->stats.fetch_ops++;
            xfer->stats.objects_received += xfer->op.last_count;
            xfer->stats.bytes_received += xfer->op.last_bytes;
        }
    }

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
 * Return read-only view of cumulative session stats.
 */
const transfer_stats_t *transfer_stats(const transfer_context_t *xfer) {
    return xfer ? &xfer->stats : NULL;
}

/**
 * Emit a one-line summary of the session's transfer activity.
 *
 * Silent on failed sessions (errors already carry the narrative) and on
 * sessions with no data transferred (nothing to report).
 */
void transfer_summarize(
    const transfer_context_t *xfer,
    output_t *out,
    output_verbosity_t level
) {
    if (!xfer || !out) return;

    if (xfer->last_outcome == TRANSFER_OUTCOME_AUTH_FAILED ||
        xfer->last_outcome == TRANSFER_OUTCOME_OTHER_FAILURE) {
        return;
    }

    const transfer_stats_t *s = &xfer->stats;
    char bytes_str[32];

    if (s->objects_received > 0) {
        output_format_size(s->bytes_received, bytes_str, sizeof(bytes_str));
        output_info(
            out, level, "Fetched %zu object%s (%s)",
            s->objects_received,
            s->objects_received == 1 ? "" : "s",
            bytes_str
        );
    }

    if (s->objects_sent > 0) {
        output_format_size(s->bytes_sent, bytes_str, sizeof(bytes_str));
        output_info(
            out, level, "Pushed %zu object%s (%s)",
            s->objects_sent,
            s->objects_sent == 1 ? "" : "s",
            bytes_str
        );
    }
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

void transfer_progress_resolved(transfer_context_t *xfer) {
    if (!xfer) return;
    xfer->progress_active = false;
}

/**
 * libgit2 credential callback.
 *
 * Runs two session-level gates before delegating to credentials_dispatch:
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
 * On a fresh helper fill, cache-once the credentials into the session
 * and advance the state to ACQUIRED so transfer_op_end() can then
 * transition to VALIDATED or REJECTED based on the op's outcome.
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

    char *obtained_user = NULL;
    char *obtained_pass = NULL;

    int rc = credentials_dispatch(
        out, url, username_from_url, allowed_types,
        ctx ? ctx->username : NULL,
        ctx ? ctx->password : NULL,
        &obtained_user,
        &obtained_pass
    );

    if (rc == 0 && ctx && (obtained_user || obtained_pass)) {
        /* Fresh helper fill — cache-once into the session. secure_replace
         * wipes any stale value first (defensive: the REJECTED fast-fail
         * above makes re-entry impossible today, but a future code-path
         * change must not silently leak secrets through an overwrite). */
        secure_replace(&ctx->username, obtained_user);
        secure_replace(&ctx->password, obtained_pass);
        if (ctx->username && ctx->password) {
            transfer_mark_cred_acquired(ctx);
        }
    } else {
        /* No cache side-effect (SSH, cache-hit, anonymous, default, or
         * failure). Free anything dispatch may have handed back. */
        if (obtained_user) {
            buffer_secure_free(obtained_user, strlen(obtained_user) + 1);
        }
        if (obtained_pass) {
            buffer_secure_free(obtained_pass, strlen(obtained_pass) + 1);
        }
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

    /* Record latest values for the stats fold at op_end. TTY-independent:
     * running in a pipe or over a log must still produce correct totals. */
    ctx->op.last_count = stats->received_objects;
    ctx->op.last_bytes = stats->received_bytes;

    /* Skip progress if no output context or below NORMAL verbosity */
    if (!ctx->output || ctx->output->verbosity < OUTPUT_NORMAL) {
        return 0;
    }

    /* Inline progress uses \r — only works on TTY. */
    if (!output_is_tty(ctx->output)) return 0;

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

    /* Record latest values for the stats fold at op_end (TTY-independent). */
    ctx->op.last_count = current;
    ctx->op.last_bytes = bytes;

    /* Skip progress if no output context or below NORMAL verbosity */
    if (!ctx->output || ctx->output->verbosity < OUTPUT_NORMAL) {
        return 0;
    }

    /* Inline progress uses \r — only works on TTY */
    if (!output_is_tty(ctx->output)) return 0;

    char bytes_str[32];
    output_format_size(bytes, bytes_str, sizeof(bytes_str));

    if (total > 0) {
        int percent = (current * 100) / total;

        /* Display: "Sending objects: XX% (current/total), X.X MiB" */
        fprintf(
            ctx->output->stream, "\rSending objects: %3d%% (%u/%u), %s",
            percent, current, total, bytes_str
        );
        fflush(ctx->output->stream);
        ctx->progress_active = true;

        /* Check if complete (guard prevents double finalization) */
        if (current == total && ctx->progress_active) {
            finalize_progress(ctx, ", done.\n");
        }
    } else {
        /* Total unknown — show count and bytes */
        fprintf(
            ctx->output->stream, "\rSending objects: %u, %s",
            current, bytes_str
        );
        fflush(ctx->output->stream);
        ctx->progress_active = true;
    }

    return 0;
}
