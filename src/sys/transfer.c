/**
 * transfer.c - What libgit2 calls back into while one network op runs:
 * implementation
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
 * A pair's states (file-local).
 *
 * A pair is born ACQUIRED, of the helper's fill, and judged by the ops it served.
 * Terminal states (VALIDATED, REJECTED) are absorbing: once reached, further
 * ops cannot change the verdict that will be told at transfer_context_free().
 */
typedef enum {
    CRED_STATE_ACQUIRED,          /* Helper filled it; outcome pending. */
    CRED_STATE_VALIDATED,         /* At least one op it served succeeded. Terminal. */
    CRED_STATE_REJECTED           /* Auth failed with no prior success. Terminal. */
} credential_state_t;

/**
 * A pair the helper filled (file-local): the answer to one key, kept for that
 * key's later asks in the session.
 *
 * Its key is git's own (lib/git/credential.c credential_match): the protocol
 * and host of the URL that asked, parsed once at the fill (sys/credentials.h
 * credential_url_parse) and the one its verdict is told against, and the user
 * the helper gave, which an ask naming a user must name. A session's pairs are
 * a list in the order filled.
 */
typedef struct transfer_pair {
    credential_url_t url;           /* Owned. The protocol and host it was filled for. */
    char *username;                 /* Owned, heap, wiped on free. */
    char *password;                 /* Owned, heap, wiped on free. */
    credential_state_t state;       /* Its verdict, once an op reaches one. */
    struct transfer_pair *next;     /* The pair filled after it. */
} transfer_pair_t;

/**
 * Transfer context.
 *
 * What libgit2 calls back into for the ops of one session against one remote:
 *   - Progress reporting (the op's frames, drawn once an object moved)
 *   - What the op moved (its wire, answered at its end)
 *   - The remote's words (a push's side band, an op's at a time)
 *   - The credentials: the pairs the helper filled, one a key the session met,
 *     each judged by the ops it served (acquisition → validation / rejection)
 *
 * Per-op scratch is reset by transfer_op_begin; transfer_op_end answers its wire,
 * says the remote's words it kept, and judges the pair it offered on the op's
 * return code. A key is filled at most once a session, by the first helper fill
 * that answers it, and its pair replayed to the key's later asks.
 */
struct transfer_context_s {
    output_t *output;               /* Borrowed. */

    /* Per-op scratch. Written by the callbacks as the op runs: the progress
     * callbacks' counts, answered by transfer_op_end where the op succeeded;
     * the remote's words, said by the side band's callback or by transfer_op_end;
     * and the credential callback's asks, and the pair it offered, judged by
     * transfer_op_end. Reset by transfer_op_begin. */
    struct {
        transfer_wire_t wire;       /* What it moved: the callbacks' latest counts. */
        buffer_t sideband;          /* The remote's words not yet said: under -v the
                                     * line still open, else every byte, to
                                     * TRANSFER_SIDEBAND_MAX. */
        size_t sideband_dropped;    /* The bytes past the bound, never kept. */
        int attempts;               /* The credential callback's asks: the anti-loop. */
        transfer_pair_t *offered;   /* The pair it offered; NULL where none. */
    } op;

    transfer_pair_t *pairs;         /* Owned. Every pair the helper filled, in the order filled. */
};

transfer_context_t *transfer_context_create(output_t *output) {
    CHECK_NULL(output);

    transfer_context_t *xfer = heap_calloc(1, sizeof(*xfer));

    xfer->output = output;
    /* All other fields zero-initialized by heap_calloc. */

    return xfer;
}

/**
 * Commit a pair's verdict to the helper.
 *
 * Approve on VALIDATED (a successful op confirmed it), reject on REJECTED (an
 * auth-failed op invalidated it), against the key it was filled for. A pair no
 * op judged — every op it served failed some other way — is told nothing.
 *
 * Helper IPC errors (exec failure, timeout) are surfaced as warnings so users
 * have a breadcrumb when the helper subprocess misbehaves; "helper has nothing
 * to say about approve/reject" (a non-zero exit from a read-only helper) is
 * intentionally not surfaced.
 */
static void transfer_commit_credential_decision(
    transfer_context_t *xfer, const transfer_pair_t *pair
) {
    if (pair->state == CRED_STATE_ACQUIRED) return;

    error_t err = pair->state == CRED_STATE_VALIDATED
        ? credential_helper_approve(&pair->url, pair->username, pair->password)
        : credential_helper_reject(&pair->url, pair->username, pair->password);

    /* In the refusal's own words: they name the helper ('git credential approve',
     * or reject), so nothing leads them */
    if (err) {
        output_warning(xfer->output, OUTPUT_NORMAL, "%s", error_line(err));
    }
}

/**
 * Free transfer context
 */
void transfer_context_free(transfer_context_t *xfer) {
    if (!xfer) return;

    /* Each pair told its verdict, in the order filled, then let go, its secrets
     * wiped */
    for (transfer_pair_t *pair = xfer->pairs, *next; pair; pair = next) {
        next = pair->next;
        transfer_commit_credential_decision(xfer, pair);

        buffer_secure_free(pair->username, strlen(pair->username) + 1);
        buffer_secure_free(pair->password, strlen(pair->password) + 1);
        credential_url_deinit(&pair->url);
        free(pair);
    }
    buffer_deinit(&xfer->op.sideband);
    free(xfer);
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
                xfer->output, level, "remote: %.*s\n",
                (int) (end - start), start
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
 * Begin an op — reset per-op scratch.
 */
void transfer_op_begin(transfer_context_t *xfer) {
    CHECK_NULL(xfer);

    xfer->op.wire = (transfer_wire_t){ 0 };
    buffer_clear(&xfer->op.sideband);
    xfer->op.sideband_dropped = 0;
    xfer->op.attempts = 0;
    xfer->op.offered = NULL;
}

/**
 * End an op — take its frame down, say the remote's words, advance the credential
 * state machine, and answer what it moved.
 */
transfer_wire_t transfer_op_end(transfer_context_t *xfer, int rc) {
    CHECK_NULL(xfer);

    /* The frame the op drew is taken down here, once, whichever way it went. A
     * callback cannot tell its last call from one libgit2 makes after it — the
     * smart protocol reports a fetch once more past the indexer's last object
     * (transports/smart_protocol.c git_smart__download_pack) and a push once
     * more past the remote's report (git_smart__push), a local push's indexer
     * once per delta it resolves — so a frame a callback took down by its counts
     * would be drawn again; a remote's line said while the op runs takes it down
     * as it lands, and the next report draws it again. A frame stands only where
     * an object moved (transfer_draw), so the op's wire says whether it drew
     * one: a line its caller drew around an op that moved none — a connect's,
     * an up-to-date fetch's — is not the op's, and stands for its caller to take
     * down. The layer keeps whether a row stands (base/output.h output_clear_line):
     * nothing is written where none does. */
    if (xfer->op.wire.objects > 0) output_clear_line(xfer->output);

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

    /* The helper's pair this op offered, judged by it — where no verdict was
     * reached yet: an op that offered none (an SSH key, the anonymous pair, no
     * ask at all) judges nothing, and the terminal states (VALIDATED, REJECTED)
     * absorb any outcome without transitioning. An op that succeeded validates
     * it. GIT_EAUTH, libgit2's auth-failure code, rejects it definitively: the
     * credential callback returns it when it gives up
     * (transfer_credentials_callback), and libgit2 where a remote asks for
     * credentials no callback could give (transports/http.c handle_auth,
     * transports/ssh_libssh2.c request_creds). Any other failure leaves the pair
     * pending, for a later op to validate or reject: a network hiccup, a run
     * that exhausts libgit2's own replay budget — GIT_ERROR, "the exact cause
     * is unclear" in its words (transports/http.c http_stream_read) — and the
     * auth failures some TLS and SSH paths surface as other errors. */
    transfer_pair_t *pair = xfer->op.offered;
    if (pair && pair->state == CRED_STATE_ACQUIRED) {
        if (rc == 0) {
            pair->state = CRED_STATE_VALIDATED;
        } else if (rc == GIT_EAUTH) {
            pair->state = CRED_STATE_REJECTED;
        }
    }

    /* What the op moved, where it succeeded: one that failed moved nothing a
     * caller may count, whatever its callbacks recorded on the way */
    return rc == 0 ? xfer->op.wire : (transfer_wire_t){ 0 };
}

/**
 * A wire's words: its objects, and their size where the transport counted one
 */
void transfer_wire_phrase(transfer_wire_t wire, char *buffer, size_t buffer_size) {
    CHECK_NULL(buffer);

    /* A transport that counted no bytes — a local push (pack-objects.c
     * git_packbuilder_write) — leaves the size unsaid, never a size of nothing,
     * as a frame does (transfer_draw) */
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
    git_remote_callbacks *cb, transfer_context_t *xfer, git_direction direction
) {
    CHECK_NULL(cb);
    CHECK_NULL(xfer);

    cb->credentials = transfer_credentials_callback;
    cb->payload = xfer;

    if (direction == GIT_DIRECTION_PUSH) {
        cb->push_transfer_progress = transfer_push_progress_callback;
        cb->push_update_reference = transfer_push_status_callback;
        cb->sideband_progress = transfer_push_sideband_callback;
    } else {
        cb->transfer_progress = transfer_fetch_progress_callback;
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
 * The pair the helper filled for an ask's key, or NULL: the same protocol and
 * host, and where the asking URL names a user, that user's — the first so filled,
 * as git matches a request against the pairs it holds, a field the request leaves
 * unset matching any (lib/git/credential.c credential_match)
 */
static transfer_pair_t *transfer_pair_find(
    const transfer_context_t *xfer, const credential_url_t *u, const char *username_from_url
) {
    for (transfer_pair_t *pair = xfer->pairs; pair; pair = pair->next) {
        if (strcmp(pair->url.protocol, u->protocol) == 0 &&
            strcmp(pair->url.host, u->host) == 0 &&
            (!username_from_url || !*username_from_url ||
            strcmp(pair->username, username_from_url) == 0)) {
            return pair;
        }
    }

    return NULL;
}

/**
 * libgit2 credential callback.
 *
 * Composes the credential primitives directly so all session policy — anti-loop,
 * a pair a key, its replay and its refusal, fill-then-keep, anonymous fallback
 * — lives next to the state it touches.
 *
 *   1. Anti-loop — libgit2 re-invokes this callback when the server rejects creds
 *      within a single negotiation. transfer_op_begin resets the per-op counter,
 *      so across-op retries are allowed.
 *
 *      Every refusal is worded here, in libgit2's own slot: the sentence a failed
 *      op ends on is the one this callback leaves.
 *
 *   2. SSH path takes precedence when allowed; SSH never fills a pair.
 *
 *   3. HTTPS userpass path: parse the asking URL into its key, and offer the
 *      pair the helper filled for it — refused at once where the remote rejected
 *      it, which saves a wasted round-trip per op in a multi-profile sync after
 *      an auth failure, and replayed otherwise; with none, fill the helper, install
 *      the cred, and keep it as the key's pair for the session's later ops. Helper
 *      / parse failures fall through to anonymous (public-repo path) and finally
 *      libgit2's default.
 */
int transfer_credentials_callback(
    git_credential **out, const char *url, const char *username_from_url,
    unsigned int allowed_types, void *payload
) {
    transfer_context_t *xfer = (transfer_context_t *) payload;

    /* Asked again within one op: what this op offered was refused. A refusal is
     * worded where it is decided: libgit2 hands a callback's code up with no
     * sentence of its own (transports/http.c handle_auth, transports/ssh_libssh2.c
     * request_creds), and the sentence it last set may be a lookup that succeeded
     * (remote.c lookup_redirect_config's value "not found"). Where an SSH key
     * is allowed the offer was the agent's, refused in libssh2's words, set before
     * this call (transports/ssh_libssh2.c ssh_agent_auth), and those stand; else
     * it was the helper's pair the op offered, or with none the anonymous one,
     * which the remote answered by asking again. */
    if (xfer->op.attempts++ > 0) {
        if (!(allowed_types & GIT_CREDENTIAL_SSH_KEY)) {
            (void) git_error_set_str(
                GIT_ERROR_CALLBACK, xfer->op.offered
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
        /* The asking URL's key, and the pair the helper filled for it. A parse
         * that fails names no key, and is printed and dropped, as a fill that
         * fails is — at most one per operation, which the anti-loop above asks
         * once. */
        credential_url_t u = { 0 };
        error_t err = credential_url_parse(url, &u);
        if (err) {
            output_print(
                xfer->output, OUTPUT_VERBOSE,
                "credential URL parse: %s\n", error_line(err)
            );
        }
        transfer_pair_t *pair = err ? NULL : transfer_pair_find(xfer, &u, username_from_url);

        /* The key's pair: refused at once where the remote rejected it — a pair
         * is rejected only where an op it offered failed authenticating, and no
         * other key's verdict reaches it — and replayed otherwise. If construction
         * fails (memory pressure is the only realistic cause), fall through to
         * the libgit2 default rather than re-prompting the helper — the user
         * already authed once, surprising them with a fresh prompt mid-session
         * is worse than a passthrough. */
        if (pair) {
            credential_url_deinit(&u);
            if (pair->state == CRED_STATE_REJECTED) {
                (void) git_error_set_str(
                    GIT_ERROR_CALLBACK,
                    "the remote refused the credentials the git credential helper gave"
                );
                return GIT_EAUTH;
            }
            if (credential_make_userpass(out, pair->username, pair->password) == 0) {
                xfer->op.offered = pair;
                return 0;
            }
            return credential_make_default(out) == 0 ? 0 : GIT_PASSTHROUGH;
        }

        /* None yet: a fresh fill from the helper. The fill may ask at the terminal
         * itself — git prompts there where no helper answers (lib/git/prompt.c
         * git_prompt) — past the output layer, which sees none of it: the progress
         * line that stands, a caller's around the op, is taken down first, so
         * the prompt stands on a row of its own */
        char *fresh_user = NULL;
        char *fresh_pass = NULL;
        if (!err) {
            output_clear_line(xfer->output);
            err = credential_helper_fill(
                &u, username_from_url, &fresh_user, &fresh_pass
            );

            if (err) {
                /* Exec failure / timeout / malformed response — surface to the
                 * user so they can diagnose helper issues, in the refusal's own
                 * words: they name the helper ('git credential fill'). */
                output_warning(xfer->output, OUTPUT_NORMAL, "%s", error_line(err));
            }
        }

        if (fresh_user && fresh_pass) {
            if (credential_make_userpass(out, fresh_user, fresh_pass) == 0) {
                /* The key's pair from here: ownership of the parsed URL and of
                 * fresh_user/fresh_pass moves into it, last in the order filled */
                pair = heap_calloc(1, sizeof(*pair));
                pair->url = u;
                pair->username = fresh_user;
                pair->password = fresh_pass;
                pair->state = CRED_STATE_ACQUIRED;

                transfer_pair_t **last = &xfer->pairs;
                while (*last) last = &(*last)->next;
                *last = pair;

                xfer->op.offered = pair;
                return 0;
            }
            discard_obtained_credentials(fresh_user, fresh_pass);
        }
        credential_url_deinit(&u);

        /* Anonymous fallback for public repos (no pair kept). */
        if (credential_make_anonymous(out) == 0) {
            return 0;
        }
    }

    /* Last resort — libgit2's platform-integrated default. */
    return credential_make_default(out) == 0 ? 0 : GIT_PASSTHROUGH;
}

/**
 * Draw a frame of the op's progress line: the objects its wire moved, of their
 * total where one is known, and their size where the transport counted one
 *
 * A fetch's and a push's alike, off the wire its callback has just recorded,
 * each frame drawn over the last, a terminal's alone at OUTPUT_NORMAL
 * (base/output.h output_progress). None is drawn before an object moved: neither
 * the report a fetch's pack header brings, its total and no object yet (indexer.c
 * git_indexer_append), nor a deletion's, nothing sent of nothing to send
 * (transports/smart_protocol.c git_smart__push). A size of nothing is left unsaid,
 * as a wire's phrase leaves it (transfer_wire_phrase): a local push counts no
 * bytes (pack-objects.c git_packbuilder_write).
 */
static void transfer_draw(
    const transfer_context_t *xfer, const char *title, unsigned int total
) {
    const transfer_wire_t *wire = &xfer->op.wire;
    if (wire->objects == 0) return;

    char size[32];
    output_format_size(wire->bytes, size, sizeof(size));

    if (total > 0 && wire->bytes > 0) {
        output_progress(
            xfer->output, OUTPUT_NORMAL, "%s: %3zu%% (%zu/%u), %s",
            title, wire->objects * 100 / total, wire->objects, total, size
        );
    } else if (total > 0) {
        output_progress(
            xfer->output, OUTPUT_NORMAL, "%s: %3zu%% (%zu/%u)",
            title, wire->objects * 100 / total, wire->objects, total
        );
    } else if (wire->bytes > 0) {
        output_progress(
            xfer->output, OUTPUT_NORMAL, "%s: %zu, %s",
            title, wire->objects, size
        );
    } else {
        output_progress(
            xfer->output, OUTPUT_NORMAL, "%s: %zu",
            title, wire->objects
        );
    }
}

/**
 * A fetch's progress: the op's wire, then a frame of its line
 */
int transfer_fetch_progress_callback(
    const git_indexer_progress *stats, void *payload
) {
    transfer_context_t *xfer = (transfer_context_t *) payload;

    /* The op's wire, its latest counts, answered at its end (transfer_op_end)
     * whatever the medium: a pipe or a log counts what a terminal draws */
    xfer->op.wire = (transfer_wire_t){
        .objects = stats->received_objects,
        .bytes = stats->received_bytes,
    };

    transfer_draw(xfer, "Receiving objects", stats->total_objects);
    return 0;
}

/**
 * A push's progress: the op's wire, then a frame of its line
 */
int transfer_push_progress_callback(
    unsigned int current, unsigned int total, size_t bytes, void *payload
) {
    transfer_context_t *xfer = (transfer_context_t *) payload;

    /* The op's wire, its latest counts, answered at its end (transfer_op_end)
     * whatever the medium: a pipe or a log counts what a terminal draws */
    xfer->op.wire = (transfer_wire_t){
        .objects = current,
        .bytes = bytes,
    };

    transfer_draw(xfer, "Sending objects", total);
    return 0;
}

/**
 * libgit2 push status callback: a ref the remote refused is the push's failure
 */
int transfer_push_status_callback(
    const char *refname, const char *status, void *payload
) {
    (void) refname;
    (void) payload;

    /* A ref the remote updated answers NULL, and one it refused its reason; libgit2
     * counts the push done either way, reading the statuses through this callback
     * alone (remote.c git_remote_upload). So the refusal is the push's failure,
     * worded here in libgit2's own slot, which a non-zero return keeps (push.c
     * git_push_status_foreach, util/errors.h git_error_set_after_callback). The
     * reason is the remote's as it stands: every push dotta makes moves one ref,
     * which its caller's words name (sys/remote.c remote_push). */
    if (!status) return 0;

    (void) git_error_set_str(GIT_ERROR_CALLBACK, status);
    return GIT_ERROR;
}

/**
 * libgit2 side band callback for a push: the remote's words, kept for the op's
 * end or said as they come
 */
int transfer_push_sideband_callback(const char *str, int len, void *payload) {
    if (len <= 0) return 0;

    transfer_context_t *xfer = (transfer_context_t *) payload;
    buffer_t *kept = &xfer->op.sideband;

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
        xfer->op.sideband_dropped += n - keep;

        /* Under -v a line is said once the remote ends it, as a hook's output
         * is under -v (utils/hooks.c hook_fire, PROCESS_OUTPUT_INHERIT) — a slow
         * hook's words while it runs — on a row of its own: the op's progress
         * line is taken down as the line lands (base/output.h output_progress),
         * and libgit2's closing report draws it again beneath the remote's lines
         * (transports/smart_protocol.c git_smart__push), for the op's end to
         * take down */
        if (newline && output_is_verbose(xfer->output)) {
            transfer_print_sideband(xfer, OUTPUT_VERBOSE);
        }

        at = next;
    }

    /* A negative answer cancels the push (transports/smart_protocol.c
     * parse_report): the remote's words are never a reason to stop it */
    return 0;
}
