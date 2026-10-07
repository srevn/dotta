/**
 * transfer.c - Unified transfer context for network operations
 */

#include "sys/transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <git2/errors.h>
#include <git2/sys/errors.h>

#include "base/buffer.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/output.h"
#include "sys/credentials.h"

/**
 * Credential session states (file-local).
 *
 * Terminal states (VALIDATED, REJECTED) are absorbing: once reached, further
 * ops cannot change the decision that will be committed at transfer_context_free().
 * NOT_ACQUIRED means no helper fill happened (SSH agent, SSH key, anonymous,
 * default) — nothing to approve or reject.
 */
typedef enum {
    CRED_STATE_NOT_ACQUIRED = 0,  /* Initial; SSH/anonymous stay here. */
    CRED_STATE_ACQUIRED,          /* Helper filled creds; outcome pending. */
    CRED_STATE_VALIDATED,         /* At least one op succeeded. Terminal. */
    CRED_STATE_REJECTED           /* Auth failed with no prior success. Terminal. */
} credential_state_t;

/**
 * Outcome of the most recent op within a transfer session (file-local).
 *
 * What the credential state machine advances on (transfer_op_end) and what keeps
 * a failed session's summary silent (transfer_summarize). No caller reads it: a
 * failure says whose refusal it was in its own words, the credential callback's
 * among them (transfer_credentials_callback).
 */
typedef enum {
    TRANSFER_OUTCOME_NONE = 0,     /* No op has completed in this session. */
    TRANSFER_OUTCOME_OK,           /* Op succeeded. */
    TRANSFER_OUTCOME_AUTH_FAILED,  /* Op failed with an authentication error. */
    TRANSFER_OUTCOME_OTHER_FAILURE /* Op failed for a non-auth reason. */
} transfer_outcome_t;

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
 * credentials are filled at most once per session by the first successful helper
 * fill (cache-once identity pinning).
 */
struct transfer_context_s {
    output_t *output;               /* Borrowed. */

    /* Progress UI state */
    bool progress_active;           /* The op drew a line its end has not ended. */
    bool ephemeral;                 /* The op's end clears it, never says done. */

    /* Cumulative session stats (TTY-independent) */
    transfer_stats_t stats;

    /* Per-op scratch. Written by the progress callbacks on each update; folded
     * into `stats` by transfer_op_end on success. Reset by transfer_op_begin. */
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

    /* Transport classification (cached from `url` at create time). True for file://
     * or plain filesystem paths. libgit2's local push transport leaves the `bytes`
     * parameter of push_transfer_progress uninitialized (no wire bytes to count),
     * so byte accounting must be suppressed for these sessions. */
    bool local_transport;
};

/**
 * Classify a remote URL as local (file:// or plain filesystem path) or remote
 * (http(s)://, ssh://, git://, user@host:path).
 *
 * libgit2's local transport synthesizes push progress from packfile creation
 * and does not populate the `bytes` parameter reliably. We use this classification
 * to suppress byte accounting for local sessions so the summary line does not
 * report nonsense (observed: 131038.9 GiB for an 8-object push against a file://
 * remote).
 *
 * Why this is not credential_url_parse:
 *   The credential parser deliberately rejects URLs that have no credential
 *   identity — file:// (empty host) and bare filesystem paths both fail the "valid
 *   host" rule. Those are exactly the shapes this function must classify as local.
 *   The two predicates partition URL space — credential_url_parse for "is this
 *   an authenticated transport?", url_is_local for "did libgit2 pick its local
 *   transport?" — and pulling them through one function would cost an
 *   allocate-and-free on every session create just to reuse a 4-line shape check.
 *   The duplication is the right trade.
 */
static bool url_is_local(const char *url) {
    if (!url || !*url) return false;

    /* Explicit local scheme. */
    if (strncmp(url, "file://", 7) == 0) return true;

    /* Any other `scheme://` is a remote network transport. */
    if (strstr(url, "://")) return false;

    /* SCP-style `user@host:path` → SSH. Detect by `@` preceding the first `:`.
     * Plain filesystem paths can contain `@` but not in this position. */
    const char *at = strchr(url, '@');
    const char *colon = strchr(url, ':');
    if (at && colon && at < colon) return false;

    /* No scheme, no SCP-style marker → filesystem path. */
    return true;
}

/**
 * Map a libgit2 return code to a transfer outcome class.
 *
 * GIT_EAUTH is libgit2's auth-failure code: the credential callback returns it
 * when it gives up (transfer_credentials_callback), and libgit2 where a remote
 * asks for credentials no callback could give (transports/http.c handle_auth,
 * transports/ssh_libssh2.c request_creds). We treat it as definitive.
 *
 * A run that exhausts libgit2's own replay budget is GIT_ERROR — "the exact cause
 * is unclear", in its words (transports/http.c http_stream_read) — and classifies
 * as OTHER_FAILURE, as do the auth failures some TLS and SSH paths surface as
 * other errors: their credentials stay pending, neither approved nor rejected.
 */
static transfer_outcome_t classify_outcome(int rc) {
    if (rc == 0) return TRANSFER_OUTCOME_OK;
    if (rc == GIT_EAUTH) return TRANSFER_OUTCOME_AUTH_FAILED;
    return TRANSFER_OUTCOME_OTHER_FAILURE;
}

/**
 * Advance credential_state on first helper fill. Idempotent: subsequent calls
 * (cached-cred replays, terminal states) do not regress the state.
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
 * Wipes and frees the old buffer (if any), then installs the new pointer. `*slot`
 * is a field slot (e.g., `&ctx->username`). Ownership of `incoming` transfers
 * to the slot; the caller must NOT free it after this call.
 */
static void secure_replace(char **slot, char *incoming) {
    if (*slot) {
        buffer_secure_free(*slot, strlen(*slot) + 1);
    }
    *slot = incoming;
}

transfer_context_t *transfer_context_create(const transfer_options_t *opts) {
    CHECK_NULL(opts);
    CHECK_NULL(opts->output);

    transfer_context_t *ctx = heap_calloc(1, sizeof(*ctx));

    ctx->url = heap_strdup(opts->url);
    ctx->output = opts->output;
    ctx->ephemeral = opts->ephemeral_progress;
    ctx->local_transport = url_is_local(ctx->url);
    /* All other fields zero-initialized by heap_calloc. */

    return ctx;
}

/**
 * Commit the session's credential decision to the helper.
 *
 * Approve on VALIDATED (a successful op confirmed the cred), reject on REJECTED
 * (an auth-failed op invalidated it). Other states never acquired creds in the
 * first place — nothing to commit.
 *
 * Helper IPC errors (exec failure, timeout) are surfaced as warnings so users
 * have a breadcrumb when the helper subprocess misbehaves; "helper has nothing
 * to say about approve/reject" (a non-zero exit from a read-only helper) is
 * intentionally not surfaced.
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
    error_t err = credential_url_parse(ctx->url, &u);
    if (err) {
        /* URL came from gitops_get_remote_url, so a parse failure here is an
         * internal correctness issue rather than user-actionable. Surface
         * verbose-only. */
        output_print(
            ctx->output, OUTPUT_VERBOSE,
            "credential helper: skipping commit — %s\n",
            error_line(err)
        );
        return;
    }

    err = ctx->credential_state == CRED_STATE_VALIDATED
        ? credential_helper_approve(&u, ctx->username, ctx->password)
        : credential_helper_reject(&u, ctx->username, ctx->password);

    if (err) {
        output_warning(
            ctx->output, OUTPUT_NORMAL,
            "credential helper: %s",
            error_line(err)
        );
    }

    credential_url_deinit(&u);
}

/**
 * Free transfer context
 */
void transfer_context_free(transfer_context_t *ctx) {
    if (!ctx) return;

    transfer_commit_credential_decision(ctx);

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
 * End an op — end its progress line, fold stats, classify outcome, advance state
 * machine.
 */
void transfer_op_end(transfer_context_t *xfer, int rc) {
    if (!xfer) return;

    /* The line the op drew ends here, once. A callback cannot tell its last call
     * from one libgit2 makes after it — the smart protocol reports a fetch once
     * more past the indexer's last object (transports/smart_protocol.c
     * git_smart__download_pack), a local push's indexer once per delta it resolves
     * — so a line a callback ended by its counts was drawn and ended again. An
     * ephemeral line is cleared; a lasting one says done only for an op that
     * succeeded. */
    if (xfer->progress_active) {
        if (xfer->ephemeral) {
            output_clear_line(xfer->output);
        } else {
            fputs(rc == 0 ? ", done.\n" : "\n", xfer->output->stream);
            fflush(xfer->output->stream);
        }
        xfer->progress_active = false;
    }

    xfer->last_outcome = classify_outcome(rc);

    /* Fold per-op values into cumulative stats. Only count ops that actually
     * transferred data — connect+ls (list_remote_branches) and up-to-date fetches
     * would otherwise pollute the summary. */
    if (rc == 0 &&
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
        /* NOT_ACQUIRED (no helper fill) and terminal states (VALIDATED, REJECTED)
         * absorb any outcome without transitioning. */
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
            /* Non-auth failure: session identity is still pending; a subsequent
             * op may validate or invalidate it. */
            break;
    }
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
 * Silent on failed sessions (errors already carry the narrative) and on sessions
 * with no data transferred (nothing to report).
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
        /* Local transports leave bytes_sent at zero (see push callback). Suppress
         * the "(SIZE)" suffix rather than reporting a bogus value. */
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
        cb->push_update_reference = transfer_push_status_callback;
    } else {
        cb->transfer_progress = transfer_progress_callback;
    }
}

/**
 * Drop credentials handed back by credential_helper_fill that we couldn't install
 * (libgit2 cred construction failed under memory pressure). Both inputs are
 * heap-owned and must be wiped before free.
 */
static void discard_obtained_credentials(char *user, char *pass) {
    if (user) buffer_secure_free(user, strlen(user) + 1);
    if (pass) buffer_secure_free(pass, strlen(pass) + 1);
}

/**
 * libgit2 credential callback.
 *
 * Composes the credential primitives directly so all session policy — REJECTED
 * fast-fail, anti-loop, cache-once, fill-then-cache, anonymous fallback — lives
 * next to the state it touches.
 *
 *   1. Fast-fail on REJECTED — once the server has rejected helper creds in this
 *      session, subsequent ops skip sending the same creds. Saves a wasted
 *      round-trip per op in a multi-profile sync after an auth failure.
 *
 *   2. Anti-loop — libgit2 re-invokes this callback when the server rejects creds
 *      within a single negotiation. transfer_op_begin resets the per-op counter,
 *      so across-op retries are allowed.
 *
 *      Both refusals are worded here, in libgit2's own slot: the sentence a failed
 *      op ends on is the one this callback leaves.
 *
 *   3. SSH path takes precedence when allowed; SSH never populates the cred cache,
 *      so the session stays in NOT_ACQUIRED.
 *
 *   4. HTTPS userpass path: replay the cache-once cred if pinned; otherwise parse
 *      the URL, fill the helper, install the cred, and cache it for subsequent
 *      ops in the same session. Helper / parse failures fall through to anonymous
 *      (public-repo path) and finally libgit2's default.
 */
int transfer_credentials_callback(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    void *payload
) {
    transfer_context_t *ctx = (transfer_context_t *) payload;

    /* A refusal is worded where it is decided. libgit2 hands a callback's code
     * up with no sentence of its own (transports/http.c handle_auth,
     * transports/ssh_libssh2.c request_creds), and the sentence it last set may
     * be a lookup that succeeded (remote.c lookup_redirect_config's value "not
     * found"). The session is REJECTED only once the helper's pair was refused:
     * no other offer moves it out of NOT_ACQUIRED. */
    if (ctx->credential_state == CRED_STATE_REJECTED) {
        (void) git_error_set_str(
            GIT_ERROR_CALLBACK,
            "the remote refused the credentials the git credential helper gave"
        );
        return GIT_EAUTH;
    }

    /* Asked again within one op: what this op offered was refused. Where an SSH
     * key is allowed the offer was the agent's, refused in libssh2's words, set
     * before this call (transports/ssh_libssh2.c ssh_agent_auth), and those stand;
     * else it was the helper's pair, or with none the anonymous one, which the
     * remote answered by asking again. */
    if (ctx->op_attempts++ > 0) {
        if (!(allowed_types & GIT_CREDENTIAL_SSH_KEY)) {
            (void) git_error_set_str(
                GIT_ERROR_CALLBACK, ctx->username
                    ? "the remote refused the credentials the git credential helper gave"
                    : "the remote requires credentials, and no git credential helper gave any"
            );
        }
        return GIT_EAUTH;
    }
    if (!url) return GIT_PASSTHROUGH;

    /* SSH path — agent then on-disk key. */
    if (allowed_types & GIT_CREDENTIAL_SSH_KEY) {
        if (credential_try_ssh(out, url, username_from_url) == 0) {
            return 0;
        }
    }

    /* HTTPS userpass path. */
    if (allowed_types & GIT_CREDENTIAL_USERPASS_PLAINTEXT) {
        /* Cache-once replay. If construction fails (memory pressure is the only
         * realistic cause), fall through to the libgit2 default rather than
         * re-prompting the helper — the user already authed once, surprising
         * them with a fresh prompt mid-session is worse than a passthrough. */
        if (ctx->username && ctx->password) {
            if (credential_make_userpass(out, ctx->username, ctx->password) == 0) {
                return 0;
            }
            return credential_make_default(out) == 0 ? 0 : GIT_PASSTHROUGH;
        }

        /* Fresh fill from the helper. A parse or a fill that fails is printed
         * and dropped — at most one per operation, which the anti-loop above
         * asks once. */
        credential_url_t u = { 0 };
        error_t err = credential_url_parse(url, &u);
        char *fresh_user = NULL;
        char *fresh_pass = NULL;

        if (err) {
            output_print(
                ctx->output, OUTPUT_VERBOSE,
                "credential URL parse: %s\n", error_line(err)
            );
        } else {
            err = credential_helper_fill(
                &u, username_from_url, &fresh_user, &fresh_pass
            );
            credential_url_deinit(&u);

            if (err) {
                /* Exec failure / timeout / malformed response — surface to the
                 * user so they can diagnose helper issues. */
                output_warning(
                    ctx->output, OUTPUT_NORMAL,
                    "credential helper: %s", error_line(err)
                );
            }
        }

        if (fresh_user && fresh_pass) {
            if (credential_make_userpass(out, fresh_user, fresh_pass) == 0) {
                /* Cache-once: ownership of fresh_user/fresh_pass moves into the
                 * session. secure_replace wipes any stale value before installing
                 * the new one (defensive — the REJECTED fast-fail above makes
                 * re-entry impossible today, but a future code-path change must
                 * not silently leak secrets through an overwrite). */
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
    if (!stats || !payload) return 0;

    transfer_context_t *ctx = (transfer_context_t *) payload;

    /* Record latest values for the stats fold at op_end. TTY-independent: running
     * in a pipe or over a log must still produce correct totals. */
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
    if (!payload) return 0;

    transfer_context_t *ctx = (transfer_context_t *) payload;

    /* Record latest values for the stats fold at op_end (TTY-independent). For
     * local transports libgit2 does not populate `bytes` meaningfully (no wire
     * to count) — treat it as absent rather than fold garbage into the session
     * total. */
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

/**
 * libgit2 push status callback: a ref the remote refused is the push's failure
 */
int transfer_push_status_callback(
    const char *refname,
    const char *status,
    void *payload
) {
    (void) refname;
    (void) payload;

    /* A ref the remote updated answers NULL, and one it refused its reason; libgit2
     * counts the push done either way, reading the statuses through this callback
     * alone (remote.c git_remote_upload). So the refusal is the push's failure,
     * worded here in libgit2's own slot, which a non-zero return keeps (push.c
     * git_push_status_foreach, util/errors.h git_error_set_after_callback). The
     * reason is the remote's as it stands: every push dotta makes moves one ref,
     * which its caller's words name (sys/gitops.c gitops_push_branch). */
    if (!status) return 0;

    (void) git_error_set_str(GIT_ERROR_CALLBACK, status);
    return GIT_ERROR;
}
