/**
 * transfer.h - What libgit2 calls back into while one network op runs
 *
 * libgit2 hands every callback of an op one pointer (git_remote_callbacks'
 * payload), so what they share is one context, one a session: the credential
 * session — asked once, its answer cached for the session's later ops, refused
 * at the second ask within one op, judged by the ops it served and committed to
 * the helper once, at the free; the op's progress — its counts drawn as
 * base/output's progress line while objects move, a push that sends nothing drawing
 * none, the frame taken down at the op's end; what the op moved, answered there;
 * the remote's words a push's side band carries, said by the hooks' rule; and a
 * ref the remote refused, the push's failure in the remote's words.
 *
 * Created by the session alone (sys/remote.h remote_open), which wraps each libgit2
 * network call it makes in transfer_op_begin and transfer_op_end, and freed by
 * it. tests/test-transfer.c asks each callback as libgit2 asks it, on a context
 * made with no network.
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
 * Create a transfer context.
 *
 * @param output The run's output, borrowed for the session (must not be NULL)
 * @param url The remote's URL; NULL is legal — SSH agent and unauthenticated
 *        paths still work, and the helper's approve and reject become no-ops
 * @return The context (caller frees via transfer_context_free)
 */
transfer_context_t *transfer_context_create(output_t *output, const char *url);

/**
 * Free a transfer context.
 *
 * Before freeing, commits the session's credential decision to the helper exactly
 * once: approve on VALIDATED, reject on REJECTED, neither on NOT_ACQUIRED
 * (SSH/anonymous) or unresolved ACQUIRED. NULL-safe.
 */
void transfer_context_free(transfer_context_t *xfer);

/**
 * Begin an op on this transfer session.
 *
 * Resets per-op scratch (anti-loop attempts, the op's wire, the remote's words).
 *
 * Pair with transfer_op_end() around each libgit2 network call (git_remote_connect,
 * git_remote_download, git_remote_upload).
 *
 * @param xfer Transfer context (must not be NULL)
 */
void transfer_op_begin(transfer_context_t *xfer);

/**
 * End an op on this transfer session, and answer what it moved.
 *
 * Takes down the frame the op drew (base/output.h output_clear_line), whichever
 * way the op went — libgit2 reports past an op's last count, so its end alone
 * knows the frame is done. A remote's line said while the op runs takes the row
 * down as it lands, and libgit2's closing report draws the frame again
 * (transfer_push_sideband_callback), so no frame outlives its op. A frame stands
 * only where an object moved: a progress line its caller drew around an op that
 * moved none — a connect's, an up-to-date fetch's — is not the op's, and stands
 * for its caller to take down.
 *
 * Then the remote's words the op kept are said: under -v the line the remote
 * left open, the others said as they arrived; otherwise, where the op failed,
 * every line, a block of its own at OUTPUT_NORMAL — and where it succeeded, none.
 *
 * Advances the credential state machine on `rc`:
 *
 *   NOT_ACQUIRED  + anything     → NOT_ACQUIRED   (no helper fill happened)
 *   ACQUIRED      + 0            → VALIDATED      (terminal)
 *   ACQUIRED      + GIT_EAUTH    → REJECTED       (terminal)
 *   ACQUIRED      + any other    → ACQUIRED       (network hiccup, etc.)
 *   VALIDATED     + anything     → VALIDATED      (terminal-absorbing)
 *   REJECTED      + anything     → REJECTED       (terminal-absorbing)
 *
 * The op's wire is fed by the progress callbacks whatever the medium, so a pipe
 * and a log count what a terminal draws.
 *
 * @param xfer Transfer context (must not be NULL)
 * @param rc libgit2 return code (0, GIT_EAUTH, or other negative)
 * @return What the op moved: zero where it failed, and where it moved nothing —
 *         a connect, an up-to-date fetch, a deletion's push
 */
transfer_wire_t transfer_op_end(transfer_context_t *xfer, int rc);

#define TRANSFER_PHRASE_MAX 64 /* "%zu objects, " at a size_t's widest, a size output_format_size writes, and NUL */

/**
 * A wire's words: its objects, and their size where the transport counted one
 *
 * "1 object", "8 objects, 687 B": the phrase, not its frame — each reader sets
 * the frame its line gives a wire, and says nothing where nothing moved. Bytes
 * of zero leave the size unsaid rather than say a size of nothing: the transport
 * counted none (transfer_wire_t, a local push).
 *
 * Readers: cmds/sync.c sync_print_wire, beside the line that says an op;
 * cmds/profile.c profile_fetch, beside the line that says its fetch.
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
 * Wire transfer context into a libgit2 remote_callbacks struct.
 *
 * Installs the credential callback (always), the progress callback matching
 * `direction`, and for a push the per-ref status (transfer_push_status_callback),
 * without which a ref the remote refused reads as pushed, and the side band
 * (transfer_push_sideband_callback), the remote's words. A fetch's side band is
 * left uninstalled: it carries the server's packing progress alone.
 *
 * Readers: sys/remote.c remote_open (the connect), remote_fetch (the download)
 * and remote_push (the push's connect and its upload).
 *
 * An op with no byte transfer — the session's open, git_remote_connect and
 * git_remote_ls — passes GIT_DIRECTION_FETCH; the installed progress callback
 * simply never fires.
 *
 * @param cb        Callbacks struct (must not be NULL; initialized by its caller)
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
 * A helper's fill runs on a row of its own: git asks at the terminal where no
 * helper answers (lib/git/prompt.c git_prompt), past the output layer, so the
 * progress line that stands is taken down first, a caller's around the op among
 * it (base/output.h output_clear_line).
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
 * Each report recorded as the op's wire, then drawn as a frame of its progress
 * line once an object moved, its size where the transport counted one
 * (base/output.h output_progress): the report a pack's header brings, its total
 * and no object yet, draws nothing.
 *
 * Installed by transfer_configure_callbacks. Not intended for direct use.
 */
int transfer_fetch_progress_callback(
    const git_indexer_progress *stats,
    void *payload
);

/**
 * libgit2 push progress callback (payload = transfer_context_t *).
 *
 * Each report recorded as the op's wire, then drawn as a frame of its progress
 * line once an object moved, its size where the transport counted one
 * (base/output.h output_progress): a push that sends nothing — a deletion — draws
 * nothing, and a local push counts no bytes.
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

#define TRANSFER_SIDEBAND_MAX ((size_t) 64 * 1024) /* What a push keeps of the remote's words; the rest is counted */

/**
 * libgit2 side band callback for a push (payload = transfer_context_t *).
 *
 * The remote's words — a refusing hook's reason, a server's notice, receive-pack's
 * own progress — a packet at a time, cut anywhere, said by the hooks' rule
 * (utils/hooks.h hook_fire_pre): under -v each line as the remote ends it, on a
 * row of its own (base/output.h output_progress); otherwise every byte kept, to
 * TRANSFER_SIDEBAND_MAX and counted past it, for the op's end to say where the
 * push failed (transfer_op_end). A line is said as a terminal shows it, behind
 * "remote: ", and as a datum: no byte of it starts a line, moves the cursor or
 * sets a colour (base/output.h "Layout and data"). A path remote sends none,
 * its transport running no hook (lib/libgit2/src/libgit2/transports/local.c
 * local_push).
 *
 * Installed by transfer_configure_callbacks for a push. Not intended for direct
 * use.
 *
 * @return 0, always: a negative answer cancels the push
 *         (lib/libgit2/src/libgit2/transports/smart_protocol.c parse_report)
 */
int transfer_push_sideband_callback(
    const char *str,
    int len,
    void *payload
);

#endif /* DOTTA_TRANSFER_H */
