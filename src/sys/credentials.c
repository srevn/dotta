/**
 * credentials.c - Git credential dispatch and helper IPC implementation
 */

#include "sys/credentials.h"

#include <hydrogen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"
#include "base/string.h"
#include "sys/process.h"

/* Credential helper subprocess timeout. Accommodates TouchID/Keychain
 * prompts and LDAP-backed corporate helpers on first use; a hung helper
 * is killed after this window so dotta does not wedge indefinitely. */
#define CRED_HELPER_TIMEOUT_SECONDS 30

/**
 * Validate a credential field for git credential protocol compliance.
 *
 * The git credential protocol is line-based (key=value\n format).
 * Field values MUST NOT contain newlines or carriage returns, as they
 * would break the protocol parser and could leak later fields.
 */
static bool is_valid_credential_field(const char *field) {
    /* Defensive check - caller should ensure non-NULL */
    if (!field) {
        return false;
    }

    /* Scan for protocol-breaking characters */
    for (const char *p = field; *p; p++) {
        /* Newline (LF) or carriage return (CR) breaks line-based protocol */
        if (*p == '\n' || *p == '\r') {
            return false;
        }
    }

    return true;
}

/**
 * Validate a host string.
 *
 * Accepts two forms:
 *   - Bracketed IPv6: "[<address>]" optionally followed by ":<port>".
 *     Inner address is hex digits, ':' separators, and '.' (for the
 *     IPv4-mapped form ::ffff:1.2.3.4).
 *   - Plain hostname[:port]: alphanumerics plus '.', '-', '_', then
 *     an optional ":<port>" of digits only.
 *
 * Brackets are preserved on IPv6 hosts so the value can travel
 * directly into a `host=` line — internal address colons are not
 * mistaken for a port separator by the helper.
 */
static bool is_valid_host(const char *host) {
    if (!host || !*host) {
        return false;
    }

    /* Bracketed IPv6 form */
    if (host[0] == '[') {
        const char *close = strchr(host, ']');
        if (!close || close == host + 1) {
            return false;
        }

        /* Inside brackets: hex digits, ':' separators, '.' (for IPv4-
         * mapped addresses like ::ffff:1.2.3.4). */
        for (const char *p = host + 1; p < close; p++) {
            char c = *p;
            bool is_hex = (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F');
            if (!(is_hex || c == ':' || c == '.')) {
                return false;
            }
        }

        /* After ']': end of string, or ":<digits>". */
        const char *after = close + 1;
        if (*after == '\0') {
            return true;
        }
        if (*after != ':' || !*(after + 1)) {
            return false;
        }
        for (const char *p = after + 1; *p; p++) {
            if (*p < '0' || *p > '9') {
                return false;
            }
        }
        return true;
    }

    /* Plain hostname[:port] */
    bool in_port = false;
    bool port_has_digit = false;
    for (const char *p = host; *p; p++) {
        char c = *p;
        if (in_port) {
            if (c < '0' || c > '9') {
                return false;
            }
            port_has_digit = true;
        } else if (c == ':') {
            in_port = true;
        } else if (!((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '.' || c == '-' || c == '_')) {
            return false;
        }
    }
    if (in_port && !port_has_digit) {
        return false;
    }
    return true;
}

error_t *credential_url_parse(const char *url, credential_url_t *out) {
    CHECK_NULL(out);

    /* Reset before any return so callers that forgot to zero-initialize
     * still see well-defined fields on the failure paths. The header
     * documents the zero-init contract; this guarantees it instead of
     * just expecting it. */
    out->protocol = NULL;
    out->host = NULL;

    if (!url || !*url) {
        return ERROR(ERR_INVALID_ARG, "URL is empty");
    }

    /* Resolve protocol and the start of the authority component. */
    const char *scheme_sep = strstr(url, "://");
    bool is_scp = false;
    char *protocol = NULL;
    const char *authority_start;

    if (scheme_sep) {
        size_t plen = (size_t) (scheme_sep - url);
        if (plen == 0) {
            return ERROR(ERR_INVALID_ARG, "URL has empty scheme: %s", url);
        }
        protocol = malloc(plen + 1);
        if (!protocol) {
            return ERROR(ERR_MEMORY, "Failed to allocate URL protocol");
        }
        memcpy(protocol, url, plen);
        protocol[plen] = '\0';
        authority_start = scheme_sep + 3;
    } else {
        /* No "://" — only SCP-style user@host:path is accepted. A bare
         * hostname is not a valid git remote URL; reject explicitly so
         * the caller can fall through to its no-credentials path. */
        const char *at = strchr(url, '@');
        const char *colon = strchr(url, ':');
        if (!(at && colon && at < colon)) {
            return ERROR(
                ERR_INVALID_ARG, "URL has no scheme or SCP-style form: %s", url
            );
        }
        protocol = strdup("ssh");
        if (!protocol) {
            return ERROR(ERR_MEMORY, "Failed to allocate URL protocol");
        }
        is_scp = true;
        authority_start = url;
    }

    /* Walk to the authority terminator. For standard URLs that's '/'.
     * For SCP it's the first unbracketed ':' (path separator). Bracketed
     * regions (IPv6 literals) are skipped wholesale so internal colons
     * are not confused for a port or path separator. */
    const char *authority_end = authority_start;
    while (*authority_end) {
        char c = *authority_end;
        if (c == '/') break;
        if (c == ':' && is_scp) break;
        if (c == '[') {
            const char *q = authority_end + 1;
            while (*q && *q != ']') q++;
            if (*q == ']') {
                authority_end = q + 1;
                continue;
            }
            /* Unmatched bracket — let host validation reject it. */
            break;
        }
        authority_end++;
    }

    /* Skip userinfo: take the LAST '@' before the authority terminator
     * so a password containing an unencoded '@' (uncommon but legal
     * pre-encoding) does not split the host away. */
    const char *host_start = authority_start;
    for (const char *p = authority_start; p < authority_end; p++) {
        if (*p == '@') {
            host_start = p + 1;
        }
    }

    size_t host_len = (size_t) (authority_end - host_start);
    char *host = malloc(host_len + 1);
    if (!host) {
        free(protocol);
        return ERROR(ERR_MEMORY, "Failed to allocate URL host");
    }
    memcpy(host, host_start, host_len);
    host[host_len] = '\0';

    if (!is_valid_credential_field(protocol) || !is_valid_host(host)) {
        free(host);
        free(protocol);
        return ERROR(ERR_INVALID_ARG, "URL is malformed: %s", url);
    }

    out->protocol = protocol;
    out->host = host;
    return NULL;
}

void credential_url_dispose(credential_url_t *u) {
    if (!u) {
        return;
    }
    free(u->protocol);
    free(u->host);
    u->protocol = NULL;
    u->host = NULL;
}

/**
 * Build a git credential protocol request into `out`.
 *
 *   protocol=<protocol>\n
 *   host=<hostname>\n
 *   [username=<username>\n]
 *   [password=<password>\n]
 *   \n  (blank line terminates request)
 *
 * `username` and `password` are optional — omitted when NULL or empty.
 * The fill path passes `username_from_url` (or NULL) and no password;
 * the approve/reject path passes both.
 *
 * Pre-sizes the buffer so no mid-fill realloc occurs. Buffers used to
 * carry passwords are scrubbed and freed by the caller; pre-sizing
 * means the scrub covers the complete lifetime of the password bytes
 * — no freed-and-reused intermediate heap pages escape zeroization.
 */
static error_t *build_credential_request(
    buffer_t *out,
    const char *protocol,
    const char *hostname,
    const char *username,
    const char *password
) {
    /* Upper bound: fixed keywords/newlines/terminator + field lengths. */
    size_t upper = 64
        + strlen(protocol)
        + strlen(hostname)
        + (username ? strlen(username) : 0)
        + (password ? strlen(password) : 0);

    error_t *err = buffer_grow(out, upper);
    if (err) return err;

    if ((err = buffer_appendf(out, "protocol=%s\n", protocol))) return err;
    if ((err = buffer_appendf(out, "host=%s\n", hostname))) return err;
    if (username && *username) {
        if ((err = buffer_appendf(out, "username=%s\n", username))) return err;
    }
    if (password && *password) {
        if ((err = buffer_appendf(out, "password=%s\n", password))) return err;
    }
    return buffer_append(out, "\n", 1);
}

/**
 * Run `git credential <subcommand>` with `request` piped to stdin.
 *
 * Shared by fill / approve / reject. Shell-free: the child is spawned
 * via `sys/process` using execve — no popen, no heredoc, no
 * interpolation of user data into any command string.
 *
 * `capture` controls whether the helper's response is captured into
 * `*result`. Approve/reject pass false (fire-and-forget, output
 * ignored); fill passes true.
 */
static error_t *run_credential_helper(
    const char *subcommand,
    const char *request,
    size_t request_len,
    bool capture,
    process_result_t *result
) {
    /* `env` locates `git` on PATH; process_run does no PATH lookup of
     * its own (argv[0] must be an absolute path). */
    char *const argv[] = {
        "/usr/bin/env",
        "git",
        "credential",
        (char *) subcommand,
        NULL
    };
    /* Helper inherits the user's environment — git needs $HOME for
     * ~/.gitconfig, $PATH to dispatch to `git-credential-<name>`
     * binaries, and possibly $DISPLAY / $SSH_AUTH_SOCK / $XDG_* for
     * GUI-backed helpers. Curating a narrower list risks missing a
     * var some helper silently depends on. */
    extern char **environ;
    process_spec_t spec = {
        .argv              = argv,
        .envp              = environ,
        .stdin_policy      = PROCESS_STDIN_BUFFER,
        .stdin_content     = request,
        .stdin_content_len = request_len,
        .capture           = capture,
        .secure_capture    = capture,
        .stream_fd         = -1,
        .timeout_seconds   = CRED_HELPER_TIMEOUT_SECONDS,
        .pgrp_policy       = PROCESS_PGRP_SHARED,
    };
    return process_run(&spec, result);
}

/**
 * Scrub and free the request buffer.
 *
 * Request buffers may hold a password (approve/reject). The pre-size
 * in build_credential_request prevents realloc, so scrubbing the
 * capacity before buffer_free wipes every byte that ever held
 * credential data.
 */
static void credential_request_secure_free(buffer_t *req) {
    if (req->data) {
        hydro_memzero(req->data, req->capacity);
    }
    buffer_free(req);
}

/**
 * Inspect a process_result_t for primitive-level helper failures
 * (exec failed / timed out) and synthesize an error_t describing the
 * cause. Returns NULL when the process completed normally — even when
 * the exit code is non-zero, since many helpers signal "no creds for
 * this URL" or "subcommand not implemented" via non-zero exit, which
 * the caller treats as a non-fatal outcome.
 *
 * `subcommand` is woven into the message so the caller doesn't need
 * to repeat the context.
 */
static error_t *helper_outcome_error(
    const char *subcommand, const process_result_t *result
) {
    if (result->exec_failed) {
        return ERROR(
            ERR_INTERNAL,
            "git credential %s failed to execute (errno=%d)",
            subcommand, result->exec_errno
        );
    }
    if (result->timed_out) {
        return ERROR(
            ERR_INTERNAL,
            "git credential %s timed out after %d seconds",
            subcommand, CRED_HELPER_TIMEOUT_SECONDS
        );
    }
    return NULL;
}

/**
 * Run the git credential helper subcommand (approve/reject) for a
 * single credential tuple. Shared body for
 * credential_helper_{approve,reject}.
 *
 * SECURITY: No user data is interpolated into any shell command —
 * there is no shell. argv is a fixed-literal vector; credential fields
 * flow through the subprocess stdin pipe assembled in
 * build_credential_request.
 *
 * A non-zero exit from the helper is NOT propagated as an error — many
 * helpers are read-only and don't implement approve/reject. Only exec
 * failure or timeout produce an error_t; the caller decides whether
 * to surface it.
 */
static error_t *credential_helper_commit(
    const char *subcommand,
    const credential_url_t *u,
    const char *username,
    const char *password
) {
    if (!username || !password || !*username || !*password) {
        return NULL;
    }
    if (!is_valid_credential_field(username) ||
        !is_valid_credential_field(password)) {
        return ERROR(
            ERR_INVALID_ARG,
            "credential field contains protocol-breaking characters"
        );
    }

    buffer_t req = BUFFER_INIT;
    error_t *err = build_credential_request(
        &req, u->protocol, u->host, username, password
    );
    if (err) {
        credential_request_secure_free(&req);
        return err;
    }

    process_result_t result = { 0 };
    err = run_credential_helper(
        subcommand, req.data, req.size, false, &result
    );
    credential_request_secure_free(&req);

    if (!err) {
        err = helper_outcome_error(subcommand, &result);
    }
    process_result_dispose(&result);
    return err;
}

error_t *credential_helper_approve(
    const credential_url_t *u, const char *user, const char *pass
) {
    CHECK_NULL(u);
    return credential_helper_commit("approve", u, user, pass);
}

error_t *credential_helper_reject(
    const credential_url_t *u, const char *user, const char *pass
) {
    CHECK_NULL(u);
    return credential_helper_commit("reject", u, user, pass);
}

error_t *credential_helper_fill(
    const credential_url_t *u,
    const char *username_from_url,
    char **out_user,
    char **out_pass
) {
    CHECK_NULL(u);
    CHECK_NULL(out_user);
    CHECK_NULL(out_pass);

    *out_user = NULL;
    *out_pass = NULL;

    bool forward_user = username_from_url && *username_from_url &&
        is_valid_credential_field(username_from_url);

    /* Build the fill request. No password in fill requests; the
     * username-from-URL is optional and disambiguates multi-account
     * configs (helper picks the matching entry instead of the default
     * for this host). */
    buffer_t req = BUFFER_INIT;
    error_t *err = build_credential_request(
        &req, u->protocol, u->host,
        forward_user ? username_from_url : NULL,
        NULL
    );
    if (err) {
        credential_request_secure_free(&req);
        return err;
    }

    process_result_t result = { 0 };
    err = run_credential_helper("fill", req.data, req.size, true, &result);

    /* Request bytes (protocol, host, optionally username-from-URL) are
     * low-sensitivity, but scrub on the same path as approve/reject so
     * the discipline is uniform and future changes do not silently
     * leak a newly added field. */
    credential_request_secure_free(&req);

    /* All process_result_dispose paths below scrub the capture buffer
     * automatically because run_credential_helper opted into
     * secure_capture — no separate per-exit scrub call needed. */
    if (err) {
        process_result_dispose(&result);
        return err;
    }

    err = helper_outcome_error("fill", &result);
    if (err) {
        process_result_dispose(&result);
        return err;
    }

    /* A non-zero exit means "helper has nothing for this URL" — common
     * (helper not configured, public repo). Not an error; the caller
     * falls through to its anonymous / default path. */
    if (result.exit_code != 0 || !result.output) {
        process_result_dispose(&result);
        return NULL;
    }

    /* Parse key=value\n lines from stdout. Helper stderr is merged
     * into the same capture stream; lines that don't match the
     * key=value shape are skipped (benign). The parse is destructive —
     * it rewrites the output buffer — which is fine because the
     * buffer is scrubbed and freed by process_result_dispose below.
     *
     * strdup'ing each value gives a right-sized heap allocation
     * (no fixed-buffer truncation) that the caller scrubs and
     * frees with buffer_secure_free. */
    char *user_buf = NULL;
    char *pass_buf = NULL;
    error_t *parse_err = NULL;

    for (char *p = result.output; p && *p && !parse_err;) {
        char *line_end = strchr(p, '\n');
        if (!line_end) break;
        *line_end = '\0';

        char *eq = strchr(p, '=');
        if (eq) {
            *eq = '\0';
            const char *key = p;
            const char *value = eq + 1;
            if (strcmp(key, "username") == 0 && !user_buf) {
                user_buf = strdup(value);
                if (!user_buf) {
                    parse_err = ERROR(
                        ERR_MEMORY, "Failed to copy helper username"
                    );
                }
            } else if (strcmp(key, "password") == 0 && !pass_buf) {
                pass_buf = strdup(value);
                if (!pass_buf) {
                    parse_err = ERROR(
                        ERR_MEMORY, "Failed to copy helper password"
                    );
                }
            }
        }
        p = line_end + 1;
    }

    process_result_dispose(&result);

    if (parse_err) {
        if (user_buf) buffer_secure_free(user_buf, strlen(user_buf) + 1);
        if (pass_buf) buffer_secure_free(pass_buf, strlen(pass_buf) + 1);
        return parse_err;
    }

    /* Atomic both-or-neither: a partial response is treated as "no
     * creds" so the caller falls through cleanly. The git credential
     * protocol contracts both fields on a successful fill. */
    if (!user_buf || !pass_buf) {
        if (user_buf) buffer_secure_free(user_buf, strlen(user_buf) + 1);
        if (pass_buf) buffer_secure_free(pass_buf, strlen(pass_buf) + 1);
        return NULL;
    }

    /* Defensive: a misbehaving helper can't inject additional protocol
     * lines (we rebuild the request from scratch each call), but it
     * could poison fields we forward elsewhere. Reject malformed values
     * outright. */
    if (!is_valid_credential_field(user_buf) ||
        !is_valid_credential_field(pass_buf)) {
        buffer_secure_free(user_buf, strlen(user_buf) + 1);
        buffer_secure_free(pass_buf, strlen(pass_buf) + 1);
        return ERROR(
            ERR_INTERNAL,
            "git credential helper returned malformed fields"
        );
    }

    *out_user = user_buf;
    *out_pass = pass_buf;
    return NULL;
}

/**
 * Check if a file exists and is readable.
 */
static bool file_exists(const char *path) {
    return access(path, R_OK) == 0;
}

/**
 * Find an SSH private key in standard locations.
 */
static char *find_ssh_key(void) {
    const char *home = getenv("HOME");
    if (!home) {
        return NULL;
    }

    /* List of common SSH key filenames (in order of preference) */
    const char *key_names[] = {
        ".ssh/id_ed25519",
        ".ssh/id_ecdsa",
        ".ssh/id_rsa",
        NULL
    };

    for (int i = 0; key_names[i] != NULL; i++) {
        /* Build full path */
        size_t path_len = strlen(home) + strlen(key_names[i]) + 2;
        char *key_path = malloc(path_len);
        if (!key_path) {
            continue;
        }

        snprintf(key_path, path_len, "%s/%s", home, key_names[i]);

        if (file_exists(key_path)) {
            return key_path;
        }

        free(key_path);
    }

    return NULL;
}

int credential_try_ssh(
    git_credential **out,
    const char *url,
    const char *username_from_url
) {
    const char *username = username_from_url;
    if (!username && url) {
        /* Default SSH username for the common URL shapes that don't
         * already encode one. libgit2 itself extracts userinfo for
         * standard ssh://user@host paths and SCP-style user@host:path,
         * so the only case we still need to cover is the bare `git@`
         * convention with no userinfo and the `ssh://host/path` form
         * — both default to "git" in practice. */
        if (str_starts_with(url, "git@") || strstr(url, "ssh://") != NULL) {
            username = "git";
        }
    }

    if (username) {
        if (git_credential_ssh_key_from_agent(out, username) == 0) {
            return 0;
        }
    }

    char *ssh_key_path = find_ssh_key();
    if (!ssh_key_path) {
        return -1;
    }

    size_t pub_key_len = strlen(ssh_key_path) + 5;
    char *pub_key_path = malloc(pub_key_len);
    int err = -1;
    if (pub_key_path) {
        snprintf(pub_key_path, pub_key_len, "%s.pub", ssh_key_path);
        err = git_credential_ssh_key_new(
            out,
            username ? username : "git",
            pub_key_path,
            ssh_key_path,
            NULL  /* empty passphrase — encrypted keys without an agent
                   * are not supported; users hit ssh-add or fall back
                   * to the helper path. */
        );
        free(pub_key_path);
    }
    free(ssh_key_path);

    return (err == 0) ? 0 : -1;
}

int credential_make_userpass(
    git_credential **out, const char *user, const char *pass
) {
    return git_credential_userpass_plaintext_new(out, user, pass);
}

int credential_make_anonymous(git_credential **out) {
    return git_credential_userpass_plaintext_new(out, "", "");
}

int credential_make_default(git_credential **out) {
    return git_credential_default_new(out);
}
