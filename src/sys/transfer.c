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
 * Per-op counters (op_attempts, last_outcome, op scratch) are reset by
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
    int op_attempts;                /* Per-op anti-loop counter. */

    /* Transport classification (cached from `url` at create time).
     * True for file:// or plain filesystem paths. libgit2's local push
     * transport leaves the `bytes` parameter of push_transfer_progress
     * uninitialized (no wire bytes to count), so byte accounting must
     * be suppressed for these sessions. */
    bool local_transport;
};

/**
 * Classify a remote URL as local (file:// or plain filesystem path) or
 * remote (http(s)://, ssh://, git://, user@host:path).
 *
 * libgit2's local transport synthesizes push progress from packfile
 * creation and does not populate the `bytes` parameter reliably. We use
 * this classification to suppress byte accounting for local sessions so
 * the summary line does not report nonsense (observed: 131038.9 GiB for
 * an 8-object push against a file:// remote).
 *
 * Why this is not credential_url_parse:
 *   The credential parser deliberately rejects URLs that have no
 *   credential identity — file:// (empty host) and bare filesystem
 *   paths both fail the "valid host" rule. Those are exactly the
 *   shapes this function must classify as local. The two predicates
 *   partition URL space — credential_url_parse for "is this an
 *   authenticated transport?", url_is_local for "did libgit2 pick its
 *   local transport?" — and pulling them through one function would
 *   cost an allocate-and-free on every session create just to reuse
 *   a 4-line shape check. The duplication is the right trade.
 */
static bool url_is_local(const char *url) {
    if (!url || !*url) return false;

    /* Explicit local scheme. */
    if (strncmp(url, "file://", 7) == 0) return true;

    /* Any other `scheme://` is a remote network transport. */
    if (strstr(url, "://")) return false;

    /* SCP-style `user@host:path` → SSH. Detect by `@` preceding the
     * first `:`. Plain filesystem paths can contain `@` but not in
     * this position. */
    const char *at = strchr(url, '@');
    const char *colon = strchr(url, ':');
    if (at && colon && at < colon) return false;

    /* No scheme, no SCP-style marker → filesystem path. */
    return true;
}

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
    ctx->local_transport = url_is_local(ctx->url);
    /* All other fields zero-initialized by calloc. */

    *out = ctx;
    return NULL;
}

/**
 * Commit the session's credential decision to the helper.
 *
 * Approve on VALIDATED (a successful op confirmed the cred), reject
 * on REJECTED (an auth-failed op invalidated it). Other states never
 * acquired creds in the first place — nothing to commit.
 *
 * Helper IPC errors (exec failure, timeout) are surfaced as warnings
 * so users have a breadcrumb when the helper subprocess misbehaves;
 * "helper has nothing to say about approve/reject" (a non-zero exit
 * from a read-only helper) is intentionally not surfaced.
 */
static void transfer_commit_credential_decision(transfer_context_t *ctx) {
    if (ctx->credential_state != CRED_STATE_VALIDATED &&
        ctx->credential_state != CRED_STATE_REJECTED) {
        return;
    }
    if (!ctx->url || !ctx->username || !ctx->password) {
        return;
    }

    credential_url_t u = { 0 };
    error_t *parse_err = credential_url_parse(ctx->url, &u);
    if (parse_err) {
        /* URL came from gitops_get_remote_url, so a parse failure here
         * is an internal correctness issue rather than user-actionable.
         * Surface verbose-only. */
        output_print(
            ctx->output, OUTPUT_VERBOSE,
            "credential helper: skipping commit — %s\n",
            error_message(parse_err)
        );
        error_free(parse_err);
        return;
    }

    error_t *commit_err =
        (ctx->credential_state == CRED_STATE_VALIDATED)
        ? credential_helper_approve(&u, ctx->username, ctx->password)
        : credential_helper_reject(&u, ctx->username, ctx->password);

    if (commit_err) {
        output_warning(
            ctx->output, OUTPUT_NORMAL,
            "credential helper: %s",
            error_message(commit_err)
        );
        error_free(commit_err);
    }

    credential_url_dispose(&u);
}

/**
 * Free transfer context
 */
void transfer_context_free(transfer_context_t *ctx) {
    if (!ctx) {
        return;
    }

    transfer_commit_credential_decision(ctx);

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
    xfer->op_attempts = 0;
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
        if (s->bytes_received > 0) {
            output_format_size(s->bytes_received, bytes_str, sizeof(bytes_str));
            output_info(
                out, level, "Fetched %zu object%s (%s)",
                s->objects_received,
                s->objects_received == 1 ? "" : "s",
                bytes_str
            );
        } else {
            output_info(
                out, level, "Fetched %zu object%s",
                s->objects_received,
                s->objects_received == 1 ? "" : "s"
            );
        }
    }

    if (s->objects_sent > 0) {
        /* Local transports leave bytes_sent at zero (see push callback).
         * Suppress the "(SIZE)" suffix rather than reporting a bogus value. */
        if (s->bytes_sent > 0) {
            output_format_size(s->bytes_sent, bytes_str, sizeof(bytes_str));
            output_info(
                out, level, "Pushed %zu object%s (%s)",
                s->objects_sent,
                s->objects_sent == 1 ? "" : "s",
                bytes_str
            );
        } else {
            output_info(
                out, level, "Pushed %zu object%s",
                s->objects_sent,
                s->objects_sent == 1 ? "" : "s"
            );
        }
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
 * Drop credentials handed back by credential_helper_fill that we
 * couldn't install (libgit2 cred construction failed under memory
 * pressure). Both inputs are heap-owned and must be wiped before free.
 */
static void discard_obtained_credentials(char *user, char *pass) {
    if (user) buffer_secure_free(user, strlen(user) + 1);
    if (pass) buffer_secure_free(pass, strlen(pass) + 1);
}

/**
 * libgit2 credential callback.
 *
 * Composes the credential primitives directly so all session policy
 * — REJECTED fast-fail, anti-loop, cache-once, fill-then-cache,
 * anonymous fallback — lives next to the state it touches.
 *
 *   1. Fast-fail on REJECTED — once the server has rejected helper
 *      creds in this session, subsequent ops skip sending the same
 *      creds. Saves a wasted round-trip per op in a multi-profile
 *      sync after an auth failure.
 *
 *   2. Anti-loop — libgit2 re-invokes this callback when the server
 *      rejects creds within a single negotiation. transfer_op_begin
 *      resets the per-op counter, so across-op retries are allowed.
 *
 *   3. SSH path takes precedence when allowed; SSH never populates
 *      the cred cache, so the session stays in NOT_ACQUIRED.
 *
 *   4. HTTPS userpass path: replay the cache-once cred if pinned;
 *      otherwise parse the URL, fill the helper, install the cred,
 *      and cache it for subsequent ops in the same session. Helper
 *      / parse failures fall through to anonymous (public-repo path)
 *      and finally libgit2's default.
 */
int transfer_credentials_callback(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    void *payload
) {
    transfer_context_t *ctx = (transfer_context_t *) payload;

    if (ctx->credential_state == CRED_STATE_REJECTED) return GIT_EAUTH;
    if (ctx->op_attempts++ > 0) return GIT_EAUTH;
    if (!url) return GIT_PASSTHROUGH;

    /* SSH path — agent then on-disk key. */
    if (allowed_types & GIT_CREDENTIAL_SSH_KEY) {
        if (credential_try_ssh(out, url, username_from_url) == 0) {
            return 0;
        }
    }

    /* HTTPS userpass path. */
    if (allowed_types & GIT_CREDENTIAL_USERPASS_PLAINTEXT) {
        /* Cache-once replay. If construction fails (memory pressure
         * is the only realistic cause), fall through to the libgit2
         * default rather than re-prompting the helper — the user
         * already authed once, surprising them with a fresh prompt
         * mid-session is worse than a passthrough. */
        if (ctx->username && ctx->password) {
            if (credential_make_userpass(out, ctx->username, ctx->password) == 0) {
                return 0;
            }
            return credential_make_default(out) == 0 ? 0 : GIT_PASSTHROUGH;
        }

        /* Fresh fill from the helper. */
        credential_url_t u = { 0 };
        error_t *parse_err = credential_url_parse(url, &u);
        char *fresh_user = NULL;
        char *fresh_pass = NULL;

        if (parse_err) {
            output_print(
                ctx->output, OUTPUT_VERBOSE,
                "credential URL parse: %s\n", error_message(parse_err)
            );
            error_free(parse_err);
        } else {
            error_t *fill_err = credential_helper_fill(
                &u, username_from_url, &fresh_user, &fresh_pass
            );
            credential_url_dispose(&u);

            if (fill_err) {
                /* Exec failure / timeout / malformed response — surface
                 * to the user so they can diagnose helper issues. */
                output_warning(
                    ctx->output, OUTPUT_NORMAL,
                    "credential helper: %s", error_message(fill_err)
                );
                error_free(fill_err);
            }
        }

        if (fresh_user && fresh_pass) {
            if (credential_make_userpass(out, fresh_user, fresh_pass) == 0) {
                /* Cache-once: ownership of fresh_user/fresh_pass moves
                 * into the session. secure_replace wipes any stale
                 * value before installing the new one (defensive — the
                 * REJECTED fast-fail above makes re-entry impossible
                 * today, but a future code-path change must not
                 * silently leak secrets through an overwrite). */
                secure_replace(&ctx->username, fresh_user);
                secure_replace(&ctx->password, fresh_pass);
                transfer_mark_cred_acquired(ctx);
                return 0;
            }
            discard_obtained_credentials(fresh_user, fresh_pass);
        }

        /* Anonymous fallback for public repos (no cache side-effect). */
        if (credential_make_anonymous(out) == 0) {
            return 0;
        }
    }

    /* Last resort — libgit2's platform-integrated default. */
    return credential_make_default(out) == 0 ? 0 : GIT_PASSTHROUGH;
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

    /* Record latest values for the stats fold at op_end (TTY-independent).
     * For local transports libgit2 does not populate `bytes` meaningfully
     * (no wire to count) — treat it as absent rather than fold garbage
     * into the session total. */
    ctx->op.last_count = current;
    ctx->op.last_bytes = ctx->local_transport ? 0 : bytes;

    /* Skip progress if no output context or below NORMAL verbosity */
    if (!ctx->output || ctx->output->verbosity < OUTPUT_NORMAL) {
        return 0;
    }

    /* Inline progress uses \r — only works on TTY */
    if (!output_is_tty(ctx->output)) return 0;

    if (total > 0) {
        int percent = (current * 100) / total;

        if (ctx->local_transport) {
            /* Local push has no wire-byte count; show objects only. */
            fprintf(
                ctx->output->stream, "\rSending objects: %3d%% (%u/%u)",
                percent, current, total
            );
        } else {
            char bytes_str[32];
            output_format_size(bytes, bytes_str, sizeof(bytes_str));
            fprintf(
                ctx->output->stream, "\rSending objects: %3d%% (%u/%u), %s",
                percent, current, total, bytes_str
            );
        }
        fflush(ctx->output->stream);
        ctx->progress_active = true;

        /* Check if complete (guard prevents double finalization) */
        if (current == total && ctx->progress_active) {
            finalize_progress(ctx, ", done.\n");
        }
    } else {
        /* Total unknown — show count (and bytes when meaningful). */
        if (ctx->local_transport) {
            fprintf(ctx->output->stream, "\rSending objects: %u", current);
        } else {
            char bytes_str[32];
            output_format_size(bytes, bytes_str, sizeof(bytes_str));
            fprintf(
                ctx->output->stream, "\rSending objects: %u, %s",
                current, bytes_str
            );
        }
        fflush(ctx->output->stream);
        ctx->progress_active = true;
    }

    return 0;
}
