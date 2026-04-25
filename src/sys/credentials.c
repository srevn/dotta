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

/* Maximum length for username and password received from the helper. */
#define CRED_MAX_LEN 256

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
    if (!url || !*url) {
        return ERROR(ERR_INVALID_ARG, "URL is empty");
    }

    out->protocol = NULL;
    out->host = NULL;

    /* Resolve protocol and the start of the authority component. */
    const char *scheme_sep = strstr(url, "://");
    bool is_scp = false;
    char *protocol = NULL;
    const char *authority_start;

    if (scheme_sep) {
        size_t plen = (size_t)(scheme_sep - url);
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

    size_t host_len = (size_t)(authority_end - host_start);
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
 * Run the git credential helper subcommand (approve/reject) for a single
 * credential tuple. Shared body for credentials_helper_{approve,reject}.
 *
 * SECURITY: No user data is interpolated into any shell command — there
 * is no shell. argv is a fixed-literal vector; credential fields flow
 * through the subprocess stdin pipe assembled in build_credential_request.
 */
static void credentials_helper_commit(
    const char *subcommand,
    const char *url,
    const char *username,
    const char *password
) {
    if (!url || !username || !password || !*username || !*password) {
        return;
    }
    if (!is_valid_credential_field(username) ||
        !is_valid_credential_field(password)) {
        return;
    }

    credential_url_t u = {0};
    error_t *parse_err = credential_url_parse(url, &u);
    if (parse_err) {
        error_free(parse_err);
        return;
    }

    buffer_t req = BUFFER_INIT;
    error_t *err = build_credential_request(
        &req, u.protocol, u.host, username, password
    );
    if (!err) {
        process_result_t result = { 0 };
        error_t *run_err = run_credential_helper(
            subcommand, req.data, req.size, false, &result
        );
        if (run_err) error_free(run_err);
        process_result_dispose(&result);
        /* Approve / reject are best-effort: the caller's state
         * machine has already classified this session, and the
         * user observes any downstream failure at the next auth
         * attempt. Silent failure here is intentional. */
    } else {
        error_free(err);
    }
    credential_request_secure_free(&req);

    credential_url_dispose(&u);
}

void credentials_helper_approve(
    const char *url, const char *username, const char *password
) {
    credentials_helper_commit("approve", url, username, password);
}

void credentials_helper_reject(
    const char *url, const char *username, const char *password
) {
    credentials_helper_commit("reject", url, username, password);
}

/**
 * Check if a file exists and is readable.
 */
static bool file_exists(const char *path) {
    return access(path, R_OK) == 0;
}

/**
 * Query the git credential helper for credentials.
 *
 * Spawns `git credential fill` via sys/process — no shell, no heredoc.
 * The request is written over a pipe built by PROCESS_STDIN_BUFFER; the
 * response is captured into process_result_t.output and parsed in place.
 *
 * Protocol and host travel as a parsed credential_url_t — already
 * validated at parse time, so this function does not re-walk the URL.
 * A helper that emits a password containing a newline cannot inject
 * additional request lines into its own next invocation, because the
 * request is assembled fresh each time.
 *
 * @param u                 Parsed remote URL (protocol + host)
 * @param username_from_url Username encoded in URL (may be NULL/empty);
 *                          forwarded to the helper so multi-account
 *                          configs disambiguate per URL.
 * @param username          Output buffer for username
 * @param password          Output buffer for password
 * @param max_len           Size of output buffers
 * @return 0 on success, -1 on failure
 */
static int get_credentials_from_helper(
    const credential_url_t *u,
    const char *username_from_url,
    char *username,
    char *password,
    size_t max_len
) {
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
        error_free(err);
        credential_request_secure_free(&req);
        return -1;
    }

    process_result_t result = { 0 };
    err = run_credential_helper("fill", req.data, req.size, true, &result);

    /* Request bytes (protocol, host, optionally username-from-URL) are
     * low-sensitivity, but scrub on the same path as approve/reject so
     * the discipline is uniform and future changes do not silently
     * leak a newly added field. */
    credential_request_secure_free(&req);

    int rc = -1;
    username[0] = '\0';
    password[0] = '\0';

    if (!err && !result.exec_failed && !result.timed_out &&
        result.exit_code == 0 && result.output) {
        /* Parse key=value\n lines from stdout. Helper stderr is merged
         * into the same capture stream; lines that don't match the
         * key=value shape are skipped (benign). The parse is
         * destructive — it rewrites the output buffer — which is fine
         * because the buffer is scrubbed and freed immediately below. */
        char *p = result.output;
        while (p && *p) {
            char *line_end = strchr(p, '\n');
            if (!line_end) break;
            *line_end = '\0';
            char *eq = strchr(p, '=');
            if (eq) {
                *eq = '\0';
                const char *key = p;
                const char *value = eq + 1;
                if (strcmp(key, "username") == 0) {
                    strncpy(username, value, max_len - 1);
                    username[max_len - 1] = '\0';
                } else if (strcmp(key, "password") == 0) {
                    strncpy(password, value, max_len - 1);
                    password[max_len - 1] = '\0';
                }
            }
            p = line_end + 1;
        }
        if (username[0] != '\0' || password[0] != '\0') {
            rc = 0;
        }
    }

    if (err) error_free(err);

    /* Output buffer held the helper response, password included.
     * process_result_dispose free()s it unscrubbed; zero the bytes
     * first so they do not linger on the freelist. */
    if (result.output) {
        hydro_memzero(result.output, result.output_len);
    }
    process_result_dispose(&result);

    return rc;
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

/**
 * Try SSH-based credential acquisition (agent + key files).
 *
 * @return 0 on success (cred installed), -1 if no SSH path succeeded
 */
static int try_ssh_credentials(
    git_credential **out,
    const char *url,
    const char *username_from_url
) {
    const char *username = username_from_url;
    if (!username) {
        /* Default SSH username for common URL shapes */
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
            NULL  /* empty passphrase */
        );
        free(pub_key_path);
    }
    free(ssh_key_path);

    return (err == 0) ? 0 : -1;
}

/**
 * Try HTTPS userpass credential acquisition (cache → helper → anonymous).
 *
 * @param out_username  On fresh helper fill, receives strdup'd copy
 *                      (may be NULL to opt out)
 * @param out_password  On fresh helper fill, receives strdup'd copy
 *                      (may be NULL to opt out)
 * @return 0 on success (cred installed), -1 otherwise
 */
static int try_userpass_credentials(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    const char *cached_username,
    const char *cached_password,
    char **out_username,
    char **out_password
) {
    /* Cache-once: wrap cached creds without re-querying the helper. */
    if (cached_username && *cached_username &&
        cached_password && *cached_password) {
        if (git_credential_userpass_plaintext_new(
            out, cached_username, cached_password
            ) == 0) {
            return 0;
        }
    }

    credential_url_t u = {0};
    error_t *parse_err = credential_url_parse(url, &u);
    int result = -1;

    if (!parse_err) {
        char cred_username[CRED_MAX_LEN];
        char cred_password[CRED_MAX_LEN];

        if (get_credentials_from_helper(
            &u, username_from_url,
            cred_username, cred_password, CRED_MAX_LEN
            ) == 0) {
            if (git_credential_userpass_plaintext_new(
                out, cred_username, cred_password
                ) == 0) {
                /* Hand fresh creds back to the caller for session caching.
                 * Heap copies because the caller's lifetime outlives this
                 * function's stack. */
                if (out_username) {
                    *out_username = strdup(cred_username);
                }
                if (out_password) {
                    *out_password = strdup(cred_password);
                }
                result = 0;
            }
        } else {
            /* Anonymous access for public repos (no cache side-effect). */
            if (git_credential_userpass_plaintext_new(out, "", "") == 0) {
                result = 0;
            }
        }

        /* Wipe stack buffers that may still hold credential bytes. */
        hydro_memzero(cred_username, sizeof(cred_username));
        hydro_memzero(cred_password, sizeof(cred_password));
    } else {
        error_free(parse_err);
    }

    credential_url_dispose(&u);
    return result;
}

int credentials_dispatch(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    const char *cached_username,
    const char *cached_password,
    char **out_username,
    char **out_password
) {
    if (!url) {
        return GIT_PASSTHROUGH;
    }

    if ((allowed_types & GIT_CREDENTIAL_SSH_KEY) &&
        try_ssh_credentials(out, url, username_from_url) == 0) {
        return 0;
    }

    if ((allowed_types & GIT_CREDENTIAL_USERPASS_PLAINTEXT) &&
        try_userpass_credentials(
        out, url, username_from_url,
        cached_username, cached_password,
        out_username, out_password
        ) == 0) {
        return 0;
    }

    /* Try default credentials (uses git credential helpers) */
    if (git_credential_default_new(out) == 0) {
        return 0;
    }

    /* Pass through to let libgit2 try without credentials (for public repos) */
    return GIT_PASSTHROUGH;
}
