/**
 * credentials.c - Git credential handling implementation
 */

#define _POSIX_C_SOURCE 200809L  /* For popen/pclose */

#include "credentials.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Maximum length for username and password */
#define CRED_MAX_LEN 256

/* Forward declarations */
static char *extract_hostname(const char *url);

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
 */
void credential_context_approve(credential_context_t *ctx) {
    if (!ctx || !ctx->credentials_provided || !ctx->url || !ctx->username || !ctx->password) {
        return;
    }

    /* Extract hostname from URL */
    char *hostname = extract_hostname(ctx->url);
    if (!hostname) {
        return;
    }

    /* Build and execute git credential approve command */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
            "git credential approve 2>/dev/null <<EOF\n"
            "protocol=https\n"
            "host=%s\n"
            "username=%s\n"
            "password=%s\n"
            "EOF\n",
            hostname, ctx->username, ctx->password);

    FILE *fp = popen(cmd, "w");
    if (fp) {
        pclose(fp);
    }

    free(hostname);
}

/**
 * Reject credentials (remove via git credential helper)
 */
void credential_context_reject(credential_context_t *ctx) {
    if (!ctx || !ctx->credentials_provided || !ctx->url || !ctx->username || !ctx->password) {
        return;
    }

    /* Extract hostname from URL */
    char *hostname = extract_hostname(ctx->url);
    if (!hostname) {
        return;
    }

    /* Build and execute git credential reject command */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
            "git credential reject 2>/dev/null <<EOF\n"
            "protocol=https\n"
            "host=%s\n"
            "username=%s\n"
            "password=%s\n"
            "EOF\n",
            hostname, ctx->username, ctx->password);

    FILE *fp = popen(cmd, "w");
    if (fp) {
        pclose(fp);
    }

    free(hostname);
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
 * Returns 0 on success, -1 on failure
 */
static int get_credentials_from_helper(const char *url, char *username, char *password, size_t max_len) {
    /* Build credential helper command */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
            "echo 'protocol=https\nhost=%s\n' | git credential fill 2>/dev/null",
            url);

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
        if (strncmp(url, "git@", 4) == 0 || strstr(url, "ssh://") != NULL) {
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
            size_t pub_key_len = strlen(ssh_key_path) + 5; /* .pub\0 */
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
        if (hostname) {
            char cred_username[CRED_MAX_LEN];
            char cred_password[CRED_MAX_LEN];

            /* Try to get credentials from git credential helper */
            if (get_credentials_from_helper(hostname, cred_username, cred_password, CRED_MAX_LEN) == 0) {
                err = git_credential_userpass_plaintext_new(out, cred_username, cred_password);
                if (err == 0) {
                    /* Store credentials in context for later approve/reject */
                    if (ctx) {
                        ctx->username = strdup(cred_username);
                        ctx->password = strdup(cred_password);
                        ctx->credentials_provided = true;
                    }
                    free(hostname);
                    return 0;
                }
            } else {
                /* Try anonymous access for public repos */
                err = git_credential_userpass_plaintext_new(out, "", "");
                if (err == 0) {
                    free(hostname);
                    return 0;
                }
            }
            free(hostname);
        }
    }

    /* Try default credentials (uses git credential helpers) */
    err = git_credential_default_new(out);
    if (err == 0) {
        return 0;
    }

    /* Pass through to let libgit2 try without credentials (for public repos) */
    return GIT_PASSTHROUGH;
}
