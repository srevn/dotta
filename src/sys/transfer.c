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
 * Transfer context.
 *
 * Owns the full lifecycle of a network session against one remote:
 *   - Progress reporting (the op's frames, drawn once an object moved)
 *   - Session stats (cumulative objects/bytes across all ops)
 *   - The remote's words (a push's side band, an op's at a time)
 *   - Credential identity (URL, cached username/password)
 *   - Credential state machine (acquisition → validation / rejection)
 *
 * Per-op counters (op_attempts, op scratch) are reset by transfer_op_begin;
 * transfer_op_end folds the scratch, says the remote's words it kept, and advances
 * the credential state machine on the op's return code. The cached credentials
 * are filled at most once per session by the first successful helper fill
 * (cache-once identity pinning).
 */
struct transfer_context_s {
    output_t *output;               /* Borrowed. */

    /* Cumulative session stats (TTY-independent) */
    transfer_stats_t stats;

    /* Per-op scratch. Written by the callbacks as the op runs: the progress
     * callbacks' counts, folded into `stats` by transfer_op_end on success, and
     * the remote's words, said by the side band's callback or by transfer_op_end.
     * Reset by transfer_op_begin. */
    struct {
        git_direction direction;    /* Op direction (fetch/push). */
        transfer_wire_t wire;       /* What it moved: the callbacks' latest counts. */
        buffer_t sideband;          /* The remote's words not yet said: under -v the
                                     * line still open, else every byte, to
                                     * TRANSFER_SIDEBAND_MAX. */
        size_t sideband_dropped;    /* The bytes past the bound, never kept. */
    } op;

    /* Credential session identity */
    char *url;                      /* Owned. Captured at create; drives
                                     * helper approve/reject at teardown. */
    char *username;                 /* Owned, heap, wiped on free. */
    char *password;                 /* Owned, heap, wiped on free. */

    /* Session state machine */
    credential_state_t credential_state;
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
 * to suppress byte accounting for local sessions so a wire's phrase never says
 * a size the transport did not count (transfer_wire_phrase; observed: 131038.9
 * GiB for an 8-object push against a file:// remote).
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

transfer_context_t *transfer_context_create(output_t *output, const char *url) {
    CHECK_NULL(output);

    transfer_context_t *ctx = heap_calloc(1, sizeof(*ctx));

    ctx->url = heap_strdup(url);
    ctx->output = output;
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

    /* In the refusal's own words: they name the helper ('git credential approve',
     * or reject), so nothing leads them */
    if (err) {
        output_warning(ctx->output, OUTPUT_NORMAL, "%s", error_line(err));
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
    buffer_deinit(&ctx->op.sideband);
    free(ctx);
}

/**
 * Say the remote's words the op kept, and let them go: each line as a terminal
 * shows it, behind "remote: ", then what the bound dropped, counted — utils/hooks.c
 * hook_print_output's twin, each line a datum
 *
 * At `level`, in the block that stands: the caller's to open where it asks one
 * (transfer_op_end). What is said is taken off the op, so a line is said once,
 * whichever of the side band's callback and the op's end says it.
 */
static void transfer_print_sideband(transfer_context_t *xfer, output_verbosity_t level) {
    buffer_t *kept = &xfer->op.sideband;

    for (size_t at = 0; at < kept->size;) {
        /* A line ends at its newline, or where the words do: what the remote
         * left open, or what the bound cut */
        const char *line = kept->data + at;
        const char *newline = memchr(line, '\n', kept->size - at);
        size_t len = newline ? (size_t) (newline - line) : kept->size - at;
        at += len + 1;

        /* What a terminal shows of it: the CRs that end it dropped — a CRLF ends
         * a line as its newline does — and of the rest, what follows its last
         * CR, the last state of a line the remote redrew in place (receive-pack's
         * progress). A line that shows nothing is said as none. */
        const char *end = line + len;
        while (end > line && end[-1] == '\r') end--;
        const char *start = end;
        while (start > line && start[-1] != '\r') start--;

        /* A datum (base/output.h "Layout and data"): every control byte spelled,
         * never sent — a colour's too, which git passes on (lib/git/sideband.c
         * strbuf_add_sanitized) — and the line ended at a NUL, where git's
         * sanitizer ends it as well */
        if (start < end) {
            output_print(
                xfer->output, level, "remote: %.*s\n", (int) (end - start), start
            );
        }
    }

    /* What the bound dropped is counted, never shown, as a hook's output past
     * its capture's bound is (utils/hooks.c hook_print_output) */
    if (xfer->op.sideband_dropped > 0) {
        output_print(
            xfer->output, level, "remote: ... and %zu more bytes\n",
            xfer->op.sideband_dropped
        );
    }

    buffer_clear(kept);
    xfer->op.sideband_dropped = 0;
}

/**
 * Begin an op — reset per-op scratch and record direction.
 */
void transfer_op_begin(transfer_context_t *xfer, git_direction direction) {
    if (!xfer) return;
    xfer->op_attempts = 0;
    xfer->op.direction = direction;
    xfer->op.wire = (transfer_wire_t){ 0 };
    buffer_clear(&xfer->op.sideband);
    xfer->op.sideband_dropped = 0;
}

/**
 * End an op — take its progress line down, fold stats, advance the credential
 * state machine.
 */
void transfer_op_end(transfer_context_t *xfer, int rc) {
    if (!xfer) return;

    /* The row the op leaves is taken down here, once, whichever way it went. A
     * callback cannot tell its last call from one libgit2 makes after it — the
     * smart protocol reports a fetch once more past the indexer's last object
     * (transports/smart_protocol.c git_smart__download_pack) and a push once
     * more past the remote's report (git_smart__push), a local push's indexer
     * once per delta it resolves — so a line a callback took down by its counts
     * would be drawn again; a remote's line said while the op runs takes it down
     * as it lands, and the next report draws it again. The layer keeps whether
     * one stands (base/output.h output_clear_line): nothing is written where
     * none does. */
    output_clear_line(xfer->output);

    /* Then the remote's words, once the line has ended: under -v the line the
     * remote left open, said in the run's trace as the lines it ended were;
     * otherwise every line where the push failed — a block of its own, as a
     * refusing hook's output is (utils/hooks.c hook_fire_pre) — and none where
     * it landed */
    if (output_is_verbose(xfer->output)) {
        transfer_print_sideband(xfer, OUTPUT_VERBOSE);
    } else if (rc != 0 && xfer->op.sideband.size > 0) {
        output_gap(xfer->output, OUTPUT_NORMAL);
        transfer_print_sideband(xfer, OUTPUT_NORMAL);
    }

    /* Fold what the op moved into its direction's. An op that failed folds nothing,
     * and one that moved nothing — connect+ls (list_remote_branches), an up-to-date
     * fetch — adds nothing. */
    if (rc == 0) {
        if (xfer->op.direction == GIT_DIRECTION_PUSH) {
            xfer->stats.sent.objects += xfer->op.wire.objects;
            xfer->stats.sent.bytes += xfer->op.wire.bytes;
        } else {
            xfer->stats.received.objects += xfer->op.wire.objects;
            xfer->stats.received.bytes += xfer->op.wire.bytes;
        }
    }

    if (xfer->credential_state != CRED_STATE_ACQUIRED) {
        /* NOT_ACQUIRED (no helper fill) and terminal states (VALIDATED, REJECTED)
         * absorb any outcome without transitioning. */
        return;
    }

    /* The helper's pair, judged by the op it served. An op that succeeded validates
     * it. GIT_EAUTH, libgit2's auth-failure code, rejects it definitively: the
     * credential callback returns it when it gives up
     * (transfer_credentials_callback), and libgit2 where a remote asks for
     * credentials no callback could give (transports/http.c handle_auth,
     * transports/ssh_libssh2.c request_creds). Any other failure leaves the
     * identity pending, for a later op to validate or reject: a network hiccup,
     * a run that exhausts libgit2's own replay budget — GIT_ERROR, "the exact
     * cause is unclear" in its words (transports/http.c http_stream_read) — and
     * the auth failures some TLS and SSH paths surface as other errors. */
    if (rc == 0) {
        xfer->credential_state = CRED_STATE_VALIDATED;
    } else if (rc == GIT_EAUTH) {
        xfer->credential_state = CRED_STATE_REJECTED;
    }
}

/**
 * What the session has moved so far, by value
 */
transfer_stats_t transfer_stats(const transfer_context_t *xfer) {
    return xfer ? xfer->stats : (transfer_stats_t){ 0 };
}

/**
 * What the session moved since `mark`
 */
transfer_stats_t transfer_stats_since(const transfer_context_t *xfer, transfer_stats_t mark) {
    const transfer_stats_t now = transfer_stats(xfer);

    /* The fold only adds (transfer_op_end), so no reading of a session stands
     * below an earlier one: each difference is what the ops between them moved */
    return (transfer_stats_t){
        .received = {
            .objects = now.received.objects - mark.received.objects,
            .bytes   = now.received.bytes - mark.received.bytes,
        },
        .sent = {
            .objects = now.sent.objects - mark.sent.objects,
            .bytes   = now.sent.bytes - mark.sent.bytes,
        },
    };
}

/**
 * A wire's words: its objects, and their size where the transport counted one
 */
void transfer_wire_phrase(transfer_wire_t wire, char *buffer, size_t buffer_size) {
    CHECK_NULL(buffer);

    /* A transport that counted no bytes — a local push (see push callback) —
     * leaves the size unsaid, never a size of nothing */
    if (wire.bytes == 0) {
        snprintf(
            buffer, buffer_size, "%zu object%s",
            wire.objects, wire.objects == 1 ? "" : "s"
        );
        return;
    }

    char bytes_str[32];
    output_format_size(wire.bytes, bytes_str, sizeof(bytes_str));
    snprintf(
        buffer, buffer_size, "%zu object%s, %s",
        wire.objects, wire.objects == 1 ? "" : "s", bytes_str
    );
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
        cb->sideband_progress = transfer_push_sideband_callback;
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
            /* The fill may ask at the terminal itself — git prompts there where
             * no helper answers (lib/git/prompt.c git_prompt) — past the output
             * layer, which sees none of it: the progress line that stands, a
             * caller's around the op, is taken down first, so the prompt stands
             * on a row of its own */
            output_clear_line(ctx->output);
            err = credential_helper_fill(
                &u, username_from_url, &fresh_user, &fresh_pass
            );
            credential_url_deinit(&u);

            if (err) {
                /* Exec failure / timeout / malformed response — surface to the
                 * user so they can diagnose helper issues, in the refusal's own
                 * words: they name the helper ('git credential fill'). */
                output_warning(ctx->output, OUTPUT_NORMAL, "%s", error_line(err));
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
    ctx->op.wire = (transfer_wire_t){
        .objects = stats->received_objects,
        .bytes = stats->received_bytes,
    };

    /* Then a frame of the op's progress line, each drawn over the last, a
     * terminal's alone at OUTPUT_NORMAL (base/output.h output_progress) — and
     * none before an object moved: the report the pack's header brings, its total
     * and no object yet (indexer.c git_indexer_append), draws nothing */
    unsigned int total = stats->total_objects;
    unsigned int received = stats->received_objects;
    if (received == 0) return 0;

    if (total > 0) {
        /* Show receiving progress with percentage and bytes */
        int percent = (received * 100) / total;
        char bytes_str[32];
        output_format_size(stats->received_bytes, bytes_str, sizeof(bytes_str));

        /* Display: "Receiving objects: XX% (current/total), X.X MiB" */
        output_progress(
            ctx->output, OUTPUT_NORMAL, "Receiving objects: %3d%% (%u/%u), %s",
            percent, received, total, bytes_str
        );
    } else {
        /* Don't know total yet, just show count */
        char bytes_str[32];
        output_format_size(stats->received_bytes, bytes_str, sizeof(bytes_str));

        output_progress(
            ctx->output, OUTPUT_NORMAL, "Receiving objects: %u, %s", received, bytes_str
        );
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
    ctx->op.wire = (transfer_wire_t){
        .objects = current,
        .bytes = ctx->local_transport ? 0 : bytes,
    };

    /* Then a frame of the op's progress line, as a fetch's is, none before an
     * object is sent (transfer_progress_callback): a deletion sends none, and
     * its report, nothing sent of nothing to send (transports/smart_protocol.c
     * git_smart__push), draws nothing */
    if (current == 0) return 0;

    if (total > 0) {
        int percent = (current * 100) / total;

        if (ctx->local_transport) {
            /* Local push has no wire-byte count; show objects only. */
            output_progress(
                ctx->output, OUTPUT_NORMAL, "Sending objects: %3d%% (%u/%u)",
                percent, current, total
            );
        } else {
            char bytes_str[32];
            output_format_size(bytes, bytes_str, sizeof(bytes_str));
            output_progress(
                ctx->output, OUTPUT_NORMAL, "Sending objects: %3d%% (%u/%u), %s",
                percent, current, total, bytes_str
            );
        }
    } else {
        /* Total unknown — show count (and bytes when meaningful). */
        if (ctx->local_transport) {
            output_progress(ctx->output, OUTPUT_NORMAL, "Sending objects: %u", current);
        } else {
            char bytes_str[32];
            output_format_size(bytes, bytes_str, sizeof(bytes_str));
            output_progress(
                ctx->output, OUTPUT_NORMAL, "Sending objects: %u, %s", current, bytes_str
            );
        }
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

/**
 * libgit2 side band callback for a push: the remote's words, kept for the op's
 * end or said as they come
 */
int transfer_push_sideband_callback(const char *str, int len, void *payload) {
    if (!payload || len <= 0) return 0;

    transfer_context_t *ctx = (transfer_context_t *) payload;
    buffer_t *kept = &ctx->op.sideband;

    /* A packet is cut wherever the remote's writes were, so it is read up to
     * each newline in turn, and to its end, each part kept to the bound with
     * the rest counted, as a hook's capture is (sys/process.h PROCESS_CAPTURE_MAX):
     * a newline past the bound still ends its line */
    for (const char *at = str, *end = str + len; at < end;) {
        const char *newline = memchr(at, '\n', (size_t) (end - at));
        const char *next = newline ? newline + 1 : end;

        size_t n = (size_t) (next - at);
        size_t room = TRANSFER_SIDEBAND_MAX - kept->size;
        size_t keep = n < room ? n : room;
        buffer_append(kept, at, keep);
        ctx->op.sideband_dropped += n - keep;

        /* Under -v a line is said once the remote ends it, as a hook's output
         * is under -v (utils/hooks.c hook_fire, PROCESS_OUTPUT_INHERIT) — a slow
         * hook's words while it runs — on a row of its own: the op's progress
         * line is taken down as the line lands (base/output.h output_progress),
         * and libgit2's closing report draws it again beneath the remote's lines
         * (transports/smart_protocol.c git_smart__push), for the op's end to
         * take down */
        if (newline && output_is_verbose(ctx->output)) {
            transfer_print_sideband(ctx, OUTPUT_VERBOSE);
        }

        at = next;
    }

    /* A negative answer cancels the push (transports/smart_protocol.c
     * parse_report): the remote's words are never a reason to stop it */
    return 0;
}
