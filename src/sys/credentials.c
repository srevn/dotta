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

#include "base/string.h"

/* Maximum length for username and password received from the helper. */
#define CRED_MAX_LEN 256

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
 * Validate a host string (hostname or hostname:port).
 *
 * Hostnames: alphanumeric, dots, hyphens, underscores.
 * Port (optional): colon followed by digits only.
 */
static bool is_valid_hostname(const char *hostname) {
    if (!hostname || !*hostname) {
        return false;
    }

    bool in_port = false;
    for (const char *p = hostname; *p; p++) {
        if (in_port) {
            if (!(*p >= '0' && *p <= '9')) {
                return false;
            }
        } else if (*p == ':') {
            in_port = true;
        } else if (!((*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') ||
            *p == '.' || *p == '-' || *p == '_')) {
            return false;
        }
    }
    return true;
}

/**
 * Extract host (hostname[:port]) from URL.
 *
 * Handles standard URLs (https://host:port/path) and
 * SCP-style URLs (user@host:path) where ':' is a path separator.
 */
static char *extract_hostname(const char *url) {
    bool has_protocol = false;
    const char *start = strstr(url, "://");
    if (start) {
        has_protocol = true;
        start += 3;
    } else {
        start = url;
    }

    const char *authority_end = start;
    if (has_protocol) {
        while (*authority_end && *authority_end != '/') {
            authority_end++;
        }
    } else {
        /* SCP-style: ':' is a path separator, not port */
        while (*authority_end &&
               *authority_end != '/' &&
               *authority_end != ':') {
            authority_end++;
        }
    }

    /* Skip userinfo@ prefix within authority */
    for (const char *p = start; p < authority_end; p++) {
        if (*p == '@') {
            start = p + 1;
            break;
        }
    }

    size_t len = authority_end - start;
    char *host = malloc(len + 1);
    if (host) {
        memcpy(host, start, len);
        host[len] = '\0';
    }

    return host;
}

/**
 * Extract protocol from URL.
 */
static char *extract_protocol(const char *url) {
    const char *sep = strstr(url, "://");
    if (sep) {
        size_t len = sep - url;
        char *proto = malloc(len + 1);
        if (proto) {
            memcpy(proto, url, len);
            proto[len] = '\0';
            return proto;
        }
    }

    /* SCP-style user@host:path implies SSH */
    if (strchr(url, '@') && strchr(url, ':') && !strstr(url, "://")) {
        return strdup("ssh");
    }

    /* Default */
    return strdup("https");
}

/**
 * Write a credential request to the helper subprocess stdin.
 *
 * Implements the git credential protocol:
 *   protocol=https\n
 *   host=<hostname>\n
 *   [username=<username>\n]
 *   [password=<password>\n]
 *   \n  (blank line terminates request)
 *
 * SECURITY: No user data passes through shell command construction.
 * All credential fields are written directly to the subprocess stdin
 * pipe, not the shell command line.
 */
static int write_credential_request(
    FILE *fp,
    const char *protocol,
    const char *hostname,
    const char *username,
    const char *password
) {
    if (!fp || !hostname || !protocol) {
        return -1;
    }

    /* Check for write errors */
    if (fprintf(fp, "protocol=%s\n", protocol) < 0) return -1;
    if (fprintf(fp, "host=%s\n", hostname) < 0) return -1;

    /* Write optional fields only if present and non-empty */
    if (username && *username) {
        if (fprintf(fp, "username=%s\n", username) < 0) return -1;
    }
    if (password && *password) {
        if (fprintf(fp, "password=%s\n", password) < 0) return -1;
    }

    /* Blank line signals end of request (protocol requirement) */
    if (fprintf(fp, "\n") < 0) return -1;

    /* Ensure data is flushed */
    if (fflush(fp) != 0) return -1;

    return 0;
}

/**
 * Run the git credential helper subcommand (approve/reject) for a single
 * credential tuple. Shared body for credentials_helper_{approve,reject}.
 *
 * SECURITY: No user data is interpolated into the shell command — the
 * subcommand is a static string literal from the caller. Credential
 * fields flow through the subprocess stdin pipe via write_credential_request.
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

    char *hostname = extract_hostname(url);
    char *protocol = extract_protocol(url);

    if (hostname && protocol &&
        is_valid_hostname(hostname) &&
        is_valid_credential_field(username) &&
        is_valid_credential_field(password)) {
        /* Command is a compile-time literal + a hardcoded subcommand —
         * no injection surface. Buffer size is generous for the short
         * subcommands we pass ("approve" or "reject"). */
        char cmd[64];
        int n = snprintf(
            cmd, sizeof(cmd),
            "git credential %s 2>/dev/null", subcommand
        );
        if (n > 0 && (size_t) n < sizeof(cmd)) {
            FILE *fp = popen(cmd, "w");
            if (fp) {
                write_credential_request(
                    fp, protocol, hostname, username, password
                );
                pclose(fp);
            }
        }
    }

    free(hostname);
    free(protocol);
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
 * Get the user's home directory.
 */
static const char *get_home_dir(void) {
    const char *home = getenv("HOME");
    if (!home) {
        home = getenv("USERPROFILE"); /* Windows fallback */
    }
    return home;
}

/**
 * Query the git credential helper for credentials.
 *
 * SECURITY NOTE: Uses heredoc (unlike approve/reject which use pipe
 * writes) because we need bidirectional communication — write request,
 * read response. This is SAFE because:
 *   1. Only hostname, protocol, and username_from_url are in the shell
 *      command (not the resulting credentials).
 *   2. Hostname is strictly validated (alphanumeric + .-_ only).
 *   3. username_from_url is validated for CR/LF (heredoc-breaking chars).
 *   4. Credentials are READ from helper output (not written to shell).
 *
 * @param protocol          Validated protocol (e.g., "https")
 * @param hostname          Validated hostname (NOT full URL)
 * @param username_from_url Username encoded in URL (may be NULL/empty);
 *                          forwarded to the helper so multi-account
 *                          configs disambiguate per URL.
 * @param username          Output buffer for username
 * @param password          Output buffer for password
 * @param max_len           Size of output buffers
 * @return 0 on success, -1 on failure
 */
static int get_credentials_from_helper(
    const char *protocol,
    const char *hostname,
    const char *username_from_url,
    char *username,
    char *password,
    size_t max_len
) {
    /* SECURITY: Validate inputs before embedding in heredoc command.
     * hostname, protocol, and username_from_url are the only user-derived
     * inputs in the shell command. The single-quoted heredoc (<<'EOF')
     * prevents shell expansion, but newlines in any field could break
     * the heredoc structure. All credential fields come from the
     * helper's OUTPUT (we read them). */
    if (!is_valid_hostname(hostname) || !protocol ||
        !is_valid_credential_field(protocol)) {
        return -1;
    }

    bool forward_user = username_from_url && *username_from_url &&
        is_valid_credential_field(username_from_url);

    /* Build credential helper command using safe heredoc */
    char cmd[1024];
    int n;
    if (forward_user) {
        n = snprintf(
            cmd, sizeof(cmd),
            "git credential fill 2>/dev/null <<'EOF'\n"
            "protocol=%s\n"
            "host=%s\n"
            "username=%s\n"
            "EOF\n",
            protocol,
            hostname,
            username_from_url
        );
    } else {
        n = snprintf(
            cmd, sizeof(cmd),
            "git credential fill 2>/dev/null <<'EOF'\n"
            "protocol=%s\n"
            "host=%s\n"
            "EOF\n",
            protocol,
            hostname
        );
    }
    if (n < 0 || (size_t) n >= sizeof(cmd)) {
        /* Refuse to run a truncated heredoc — would send a malformed
         * request and possibly leak a partial username. */
        return -1;
    }

    /* Execute command and read output */
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return -1;
    }

    char line[512];
    username[0] = '\0';
    password[0] = '\0';

    while (fgets(line, sizeof(line), fp)) {
        /* Remove newline */
        line[strcspn(line, "\n")] = 0;

        /* Parse key=value */
        char *eq = strchr(line, '=');
        if (!eq) {
            continue;
        }

        *eq = '\0';
        const char *key = line;
        const char *value = eq + 1;

        if (strcmp(key, "username") == 0) {
            strncpy(username, value, max_len - 1);
            username[max_len - 1] = '\0';
        } else if (strcmp(key, "password") == 0) {
            strncpy(password, value, max_len - 1);
            password[max_len - 1] = '\0';
        }
    }

    /* Wipe the line buffer — may contain credential bytes. */
    hydro_memzero(line, sizeof(line));

    int status = pclose(fp);

    /* Check if we got credentials */
    if (status == 0 && (username[0] != '\0' || password[0] != '\0')) {
        return 0;
    }

    return -1;
}


/**
 * Find an SSH private key in standard locations.
 */
static char *find_ssh_key(void) {
    const char *home = get_home_dir();
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
                out, cached_username, cached_password) == 0) {
            return 0;
        }
    }

    char *hostname = extract_hostname(url);
    char *protocol = extract_protocol(url);
    int result = -1;

    if (hostname && protocol) {
        char cred_username[CRED_MAX_LEN];
        char cred_password[CRED_MAX_LEN];

        if (get_credentials_from_helper(
                protocol, hostname, username_from_url,
                cred_username, cred_password, CRED_MAX_LEN) == 0) {
            if (git_credential_userpass_plaintext_new(
                    out, cred_username, cred_password) == 0) {
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
    }

    free(hostname);
    free(protocol);
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
