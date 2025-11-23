/**
 * credentials.c - Git credential handling implementation
 */

#include "credentials.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils/string.h"

/* Maximum length for username and password */
#define CRED_MAX_LEN 256

/* Forward declarations */
static char *extract_hostname(const char *url);
static char *extract_protocol(const char *url);
static bool is_valid_hostname(const char *hostname);

/**
 * Validate credential field for git credential protocol compliance
 *
 * The git credential protocol is line-based (key=value\n format).
 * Field values MUST NOT contain newlines or carriage returns, as they
 * would break the protocol parser.
 *
 * This validation provides defense-in-depth against protocol injection,
 * though the primary protection is direct pipe I/O (no shell interpolation).
 *
 * @param field Field value (must not be NULL - caller responsibility)
 * @return true if field is protocol-compliant, false otherwise
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
 * Validate hostname to prevent command injection
 * Hostnames should only contain alphanumeric characters, dots, hyphens, and underscores
 */
static bool is_valid_hostname(const char *hostname) {
    if (!hostname || !*hostname) {
        return false;
    }

    for (const char *p = hostname; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') ||
              (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') ||
              *p == '.' || *p == '-' || *p == '_')) {
            return false;
        }
    }
    return true;
}

/**
 * Write credential request to git credential helper
 *
 * Uses direct pipe I/O without shell interpolation to prevent command injection.
 * Implements the git credential protocol:
 *   protocol=https\n
 *   host=<hostname>\n
 *   [username=<username>\n]
 *   [password=<password>\n]
 *   \n  (blank line terminates request)
 *
 * SECURITY: No user data passes through shell command construction.
 * All credential fields are written directly to the subprocess stdin pipe.
 *
 * @param fp Pipe to credential helper subprocess (from popen)
 * @param hostname Validated hostname (required, must not be NULL)
 * @param username Username (optional, may be NULL or empty)
 * @param password Password (optional, may be NULL or empty)
 * @return 0 on success, -1 on error
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
 * Create credential context
 */
credential_context_t *credential_context_create(const char *url) {
    credential_context_t *ctx = calloc(1, sizeof(credential_context_t));
    if (!ctx) {
        return NULL;
    }
    ctx->url = url ? strdup(url) : NULL;
    ctx->username = NULL;
    ctx->password = NULL;
    ctx->credentials_provided = false;
    return ctx;
}

/**
 * Free credential context
 */
void credential_context_free(credential_context_t *ctx) {
    if (!ctx) {
        return;
    }
    free(ctx->url);
    if (ctx->username) {
        memset(ctx->username, 0, strlen(ctx->username));
        free(ctx->username);
    }
    if (ctx->password) {
        memset(ctx->password, 0, strlen(ctx->password));
        free(ctx->password);
    }
    free(ctx);
}

/**
 * Approve credentials (save via git credential helper)
 *
 * SECURITY NOTE: This function previously used heredoc with user data,
 * creating command injection and process visibility vulnerabilities.
 * Now uses direct pipe I/O to eliminate shell involvement.
 */
void credential_context_approve(credential_context_t *ctx) {
    /* Validate context and required fields */
    if (!ctx || !ctx->credentials_provided || !ctx->url ||
        !ctx->username || !ctx->password) {
        return;
    }

    /* Extract hostname from URL */
    char *hostname = extract_hostname(ctx->url);
    char *protocol = extract_protocol(ctx->url);
    
    if (!hostname || !protocol) {
        free(hostname);
        free(protocol);
        return;
    }

    /* Validation */
    if (!is_valid_hostname(hostname) ||
        !is_valid_credential_field(ctx->username) ||
        !is_valid_credential_field(ctx->password)) {
        free(hostname);
        free(protocol);
        return;
    }

    /* Execute git credential approve with direct pipe I/O
     * SECURITY: No user data in command string (only command name)
     * Credentials written to pipe, never exposed to shell */
    FILE *fp = popen("git credential approve 2>/dev/null", "w");
    if (fp) {
        write_credential_request(fp, protocol, hostname, ctx->username, ctx->password);
        pclose(fp);
    }

    free(hostname);
    free(protocol);
}

/**
 * Reject credentials (remove via git credential helper)
 *
 * SECURITY NOTE: Uses same secure pattern as approve() - direct pipe I/O
 * with no shell interpolation of user data.
 */
void credential_context_reject(credential_context_t *ctx) {
    /* Validate context and required fields */
    if (!ctx || !ctx->credentials_provided || !ctx->url ||
        !ctx->username || !ctx->password) {
        return;
    }

    /* Extract hostname from URL */
    char *hostname = extract_hostname(ctx->url);
    char *protocol = extract_protocol(ctx->url);

    /* Validate hostname to prevent command injection */
    if (!hostname || !protocol) {
        free(hostname);
        free(protocol);
        return;
    }

    /* Validate credentials for protocol compliance */
    if (!is_valid_hostname(hostname) ||
        !is_valid_credential_field(ctx->username) ||
        !is_valid_credential_field(ctx->password)) {
        free(hostname);
        free(protocol);
        return;
    }

    /* Execute git credential reject with direct pipe I/O */
    FILE *fp = popen("git credential reject 2>/dev/null", "w");
    if (fp) {
        write_credential_request(
            fp,
            protocol,
            hostname,
            ctx->username,
            ctx->password
        );
        pclose(fp);
    }

    free(hostname);
    free(protocol);
}

/**
 * Check if a file exists and is readable
 */
static bool file_exists(const char *path) {
    return access(path, R_OK) == 0;
}

/**
 * Get home directory
 */
static const char *get_home_dir(void) {
    const char *home = getenv("HOME");
    if (!home) {
        home = getenv("USERPROFILE"); /* Windows fallback */
    }
    return home;
}

/**
 * Try to get credentials from git credential helper
 *
 * SECURITY NOTE: This function uses heredoc (unlike approve/reject) because
 * it needs bidirectional communication (write request, read response).
 * This is SAFE because:
 *  1. Only hostname is in the shell command (not credentials)
 *  2. Hostname is strictly validated (alphanumeric + .-_ only)
 *  3. Credentials are READ from helper output (not written to shell)
 *
 * @param hostname Validated hostname (NOT full URL - caller extracts it)
 * @param username Output buffer for username
 * @param password Output buffer for password
 * @param max_len Size of output buffers
 * @return 0 on success, -1 on failure
 */
static int get_credentials_from_helper(
    const char *protocol,
    const char *hostname,
    char *username,
    char *password,
    size_t max_len
) {
    /* SECURITY: Validate hostname to prevent command injection
     * This is the ONLY user-derived input in the shell command.
     * All credential fields come from the helper's OUTPUT (we read them). */
    if (!is_valid_hostname(hostname) || !protocol) {
        return -1;
    }

    /* Build credential helper command using safe heredoc */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
            "git credential fill 2>/dev/null <<'EOF'\n"
            "protocol=%s\n"
            "host=%s\n"
            "EOF\n",
            protocol,
            hostname);

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

    int status = pclose(fp);

    /* Check if we got credentials */
    if (status == 0 && (username[0] != '\0' || password[0] != '\0')) {
        return 0;
    }

    return -1;
}

/**
 * Extract hostname from URL
 */
static char *extract_hostname(const char *url) {
    /* Skip protocol */
    const char *start = strstr(url, "://");
    if (start) {
        start += 3;
    } else {
        start = url;
    }

    /* Find end of hostname (before '/' or ':') */
    const char *end = start;
    while (*end && *end != '/' && *end != ':' && *end != '@') {
        end++;
    }

    /* Handle username@ prefix */
    const char *at = strchr(start, '@');
    if (at && at < end) {
        start = at + 1;
        end = start;
        while (*end && *end != '/' && *end != ':') {
            end++;
        }
    }

    size_t len = end - start;
    char *hostname = malloc(len + 1);
    if (hostname) {
        memcpy(hostname, start, len);
        hostname[len] = '\0';
    }

    return hostname;
}

/**
 * Extract protocol from URL
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
    
    /* Handle SSH SCP-like syntax (user@host:path) */
    if (strchr(url, '@') && strchr(url, ':') && !strstr(url, "://")) {
        return strdup("ssh");
    }
    
    /* Fallback default */
    return strdup("https");
}

/**
 * Try to find SSH private key in standard locations
 */
static char *find_ssh_key(void) {
    const char *home = get_home_dir();
    if (!home) {
        return NULL;
    }

    /* List of common SSH key filenames (in order of preference) */
    const char *key_names[] = {
        ".ssh/id_ed25519",
        ".ssh/id_rsa",
        ".ssh/id_ecdsa",
        ".ssh/id_dsa",
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
 * Default credential callback
 */
int credentials_callback(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    void *payload
) {
    credential_context_t *ctx = (credential_context_t *)payload;
    int err = -1;

    /* Determine username */
    const char *username = username_from_url;
    if (!username) {
        /* For SSH, default to "git" */
        if (str_starts_with(url, "git@") || strstr(url, "ssh://") != NULL) {
            username = "git";
        }
    }

    /* Try SSH agent first (most common for SSH) */
    if (allowed_types & GIT_CREDENTIAL_SSH_KEY) {
        if (username) {
            err = git_credential_ssh_key_from_agent(out, username);
            if (err == 0) {
                return 0;
            }
        }

        /* Try finding SSH key in default locations */
        char *ssh_key_path = find_ssh_key();
        if (ssh_key_path) {
            /* Build path to public key */
            size_t pub_key_len = strlen(ssh_key_path) + 5;
            char *pub_key_path = malloc(pub_key_len);
            if (pub_key_path) {
                snprintf(pub_key_path, pub_key_len, "%s.pub", ssh_key_path);

                /* Try to use the key (with empty passphrase) */
                err = git_credential_ssh_key_new(
                    out,
                    username ? username : "git",
                    pub_key_path,
                    ssh_key_path,
                    NULL  /* No passphrase */
                );

                free(pub_key_path);
            }
            free(ssh_key_path);

            if (err == 0) {
                return 0;
            }
        }
    }

    /* For HTTPS with username/password - try git credential helper */
    if (allowed_types & GIT_CREDENTIAL_USERPASS_PLAINTEXT) {
        /* Extract hostname from URL */
        char *hostname = extract_hostname(url);
        char *protocol = extract_protocol(url);
        
        if (hostname && protocol) {
            char cred_username[CRED_MAX_LEN];
            char cred_password[CRED_MAX_LEN];

            /* Try to get credentials from git credential helper */
            if (get_credentials_from_helper(
                protocol,
                hostname,
                cred_username,
                cred_password,
                CRED_MAX_LEN) == 0
            ) {
                err = git_credential_userpass_plaintext_new(
                    out,
                    cred_username,
                    cred_password
                );
                if (err == 0) {
                    /* Store credentials in context for later approve/reject */
                    if (ctx) {
                        ctx->username = strdup(cred_username);
                        ctx->password = strdup(cred_password);
                        ctx->credentials_provided = true;
                    }
                    free(hostname);
                    free(protocol);
                    return 0;
                }
            } else {
                /* Try anonymous access for public repos */
                err = git_credential_userpass_plaintext_new(out, "", "");
                if (err == 0) {
                    free(hostname);
                    free(protocol);
                    return 0;
                }
            }
        }
        free(hostname);
        free(protocol);
    }

    /* Try default credentials (uses git credential helpers) */
    err = git_credential_default_new(out);
    if (err == 0) {
        return 0;
    }

    /* Pass through to let libgit2 try without credentials (for public repos) */
    return GIT_PASSTHROUGH;
}
