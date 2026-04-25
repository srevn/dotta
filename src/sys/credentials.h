/**
 * credentials.h - Git credential dispatch and helper IPC
 *
 * Stateless module: dispatches to SSH agent / SSH key files / HTTPS
 * credential helper to obtain a git_credential, and commits or revokes
 * credentials against the helper.
 *
 * Session identity (URL, cached credentials, approval state) lives on
 * transfer_context_t. This module holds no state between calls.
 */

#ifndef DOTTA_CREDENTIALS_H
#define DOTTA_CREDENTIALS_H

#include <git2.h>
#include <types.h>

/**
 * Parsed remote URL (protocol + host).
 *
 * Replaces ad-hoc duplicated walks of the URL. Both fields are
 * validated at parse time:
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
 * Dispatch credential acquisition for a libgit2 network op.
 *
 * Attempt order:
 *   - SSH agent (for SSH URLs, if GIT_CREDENTIAL_SSH_KEY allowed)
 *   - SSH private key from ~/.ssh/id_* (SSH URLs)
 *   - Cache-once reuse (if cached_username/cached_password non-NULL/non-empty)
 *   - git credential helper fill (HTTPS URLs, if USERPASS_PLAINTEXT allowed)
 *   - Anonymous (empty userpass) for public HTTPS repos
 *   - git_credential_default (libgit2 fallback)
 *
 * Cache-once semantics (HTTPS helper path):
 *   - If the caller provides cached credentials, dispatch wraps them and
 *     returns without invoking the helper — avoids re-prompts and pins
 *     the session identity to the first successful fill.
 *   - On a fresh helper fill (no cache), dispatch writes strdup'd copies
 *     of the obtained credentials into `*out_username` / `*out_password`
 *     when those out-params are non-NULL. The caller owns and must free
 *     these with buffer_secure_free.
 *   - On SSH, cached reuse, anonymous, or default paths, the out-params
 *     are left untouched (NULL on first call).
 *
 * @param out               libgit2 credential output (required)
 * @param url               Remote URL (required for credential resolution;
 *                          NULL returns GIT_PASSTHROUGH)
 * @param username_from_url Username encoded in URL (may be NULL)
 * @param allowed_types     libgit2 credential-type bitfield
 * @param cached_username   Cached username to reuse (may be NULL)
 * @param cached_password   Cached password to reuse (may be NULL)
 * @param out_username      On fresh helper fill, receives strdup'd copy
 *                          (may be NULL to opt out of caching)
 * @param out_password      On fresh helper fill, receives strdup'd copy
 *                          (may be NULL to opt out of caching)
 * @return 0 on success, GIT_PASSTHROUGH for unauthenticated fallback,
 *         negative git error on failure
 */
int credentials_dispatch(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    const char *cached_username,
    const char *cached_password,
    char **out_username,
    char **out_password
);

/**
 * Commit credentials to the helper via `git credential approve`.
 *
 * No-op if any argument is NULL or empty, or if hostname/protocol
 * extraction or validation fails. Safe to call with any input —
 * malformed inputs silently skip the helper invocation.
 */
void credentials_helper_approve(
    const char *url, const char *username, const char *password
);

/**
 * Revoke credentials via `git credential reject`.
 *
 * Same safety rules as credentials_helper_approve.
 */
void credentials_helper_reject(
    const char *url, const char *username, const char *password
);

#endif /* DOTTA_CREDENTIALS_H */
