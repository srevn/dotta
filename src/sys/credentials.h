/**
 * credentials.h - Stateless credential primitives.
 *
 * Leaf-level building blocks for git credential resolution:
 *   - URL parsing (credential_url_t)
 *   - SSH credential acquisition (agent + on-disk key files)
 *   - HTTPS credential helper IPC (fill / approve / reject)
 *   - Thin libgit2 cred constructors
 *
 * Holds no session state. Cache-once policy, anti-loop counters, and
 * the approve/reject decision belong to the session owner
 * (sys/transfer.c) — a credential session has a lifetime that this
 * module deliberately does not model.
 */

#ifndef DOTTA_CREDENTIALS_H
#define DOTTA_CREDENTIALS_H

#include <git2.h>
#include <types.h>

/**
 * Parsed remote URL (protocol + host).
 *
 * Both fields are validated at parse time:
 *   - protocol is free of \r/\n (required for the line-based git
 *     credential protocol)
 *   - host matches one of the accepted host grammars (plain
 *     hostname[:port] or bracketed IPv6 [addr][:port]) and is
 *     therefore also free of \r/\n by construction.
 *
 * Brackets on IPv6 hosts are preserved so callers can forward the
 * value verbatim into a `host=` line — disambiguating address bytes
 * from a trailing port without further parsing downstream.
 */
typedef struct {
    char *protocol;   /* e.g. "https", "ssh" */
    char *host;       /* hostname[:port] or "[ipv6][:port]" */
} credential_url_t;

/**
 * Parse a remote URL into protocol + host components.
 *
 * Accepts:
 *   - <scheme>://[user[:pass]@]host[:port][/path]
 *   - <scheme>://[user[:pass]@][ipv6-addr][:port][/path]
 *   - user@host:path  (SCP-style → protocol "ssh")
 *
 * Strips userinfo and path; only protocol and host[:port] survive.
 * A URL whose protocol or host fails validation produces an error;
 * downstream consumers therefore do not need to re-validate parsed
 * components.
 *
 * @param url Remote URL (must be non-NULL and non-empty)
 * @param out Output struct (zero-initialize before calling; populated
 *            on success). Caller disposes via credential_url_dispose.
 * @return Error or NULL on success. On failure, *out is left
 *         zero-initialized.
 */
error_t *credential_url_parse(const char *url, credential_url_t *out);

/**
 * Release resources owned by a parsed URL.
 *
 * Idempotent; safe to call on a zero-initialized struct or twice in a
 * row. Resets the struct to its zero-initialized form.
 */
void credential_url_dispose(credential_url_t *u);

/**
 * Try SSH-based credential acquisition (agent first, then on-disk key).
 *
 * Stateless: each call attempts the SSH agent once and falls back to a
 * file-system key search. Encrypted on-disk keys without an agent are
 * not supported (see project notes on F6).
 *
 * @param out               libgit2 credential output (required)
 * @param url               Remote URL — used to default the SSH user to
 *                          "git" for common URL shapes
 * @param username_from_url Username encoded in URL (may be NULL)
 * @return 0 on success (cred installed), -1 if no SSH path succeeded
 */
int credential_try_ssh(
    git_credential **out,
    const char *url,
    const char *username_from_url
);

/**
 * Construct a libgit2 userpass plaintext credential.
 *
 * Thin wrapper over git_credential_userpass_plaintext_new — kept for
 * symmetry with credential_try_ssh and to confine libgit2 cred-API
 * details to a single module.
 *
 * @return 0 on success, libgit2 error code otherwise.
 */
int credential_make_userpass(
    git_credential **out, const char *user, const char *pass
);

/**
 * Construct an anonymous (empty userpass) credential — used as the
 * "public repo" fallback over HTTPS.
 *
 * @return 0 on success, libgit2 error code otherwise.
 */
int credential_make_anonymous(git_credential **out);

/**
 * Construct libgit2's default credential (platform-integrated paths,
 * e.g. NTLM/Negotiate). Last-resort fallback.
 *
 * @return 0 on success, libgit2 error code otherwise.
 */
int credential_make_default(git_credential **out);

/**
 * Query the git credential helper for a username + password.
 *
 * Atomic: on success, both `*out_user` and `*out_pass` are non-NULL,
 * heap-allocated, and free of \r/\n. On any other outcome both are
 * left NULL and the caller falls through to its anonymous / default
 * path. Error_t is returned only for unusual conditions worth
 * surfacing to the user — exec failure, timeout, OOM, malformed
 * helper response. The common "helper has no creds for this URL"
 * outcome is signalled by NULL out-params and a NULL return value.
 *
 * Caller frees `*out_user` / `*out_pass` with buffer_secure_free
 * (using `strlen(buf) + 1` as the length).
 *
 * @param u                 Parsed remote URL
 * @param username_from_url Username encoded in URL (may be NULL);
 *                          forwarded so multi-account configs
 *                          disambiguate per URL.
 * @param out_user          Output (initialized to NULL)
 * @param out_pass          Output (initialized to NULL)
 * @return Error or NULL.
 */
error_t *credential_helper_fill(
    const credential_url_t *u,
    const char *username_from_url,
    char **out_user,
    char **out_pass
);

/**
 * Commit accepted credentials to the helper (`git credential approve`).
 *
 * No-op if `user` or `pass` is NULL or empty. A non-zero exit from a
 * read-only helper that doesn't implement approve is NOT an error —
 * many helpers are query-only by design. Returns an error only for
 * exec failure or timeout.
 */
error_t *credential_helper_approve(
    const credential_url_t *u, const char *user, const char *pass
);

/**
 * Revoke credentials at the helper (`git credential reject`).
 *
 * Same semantics as credential_helper_approve.
 */
error_t *credential_helper_reject(
    const credential_url_t *u, const char *user, const char *pass
);

#endif /* DOTTA_CREDENTIALS_H */
