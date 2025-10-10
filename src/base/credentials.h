/**
 * credentials.h - Git credential handling
 */

#ifndef DOTTA_CREDENTIALS_H
#define DOTTA_CREDENTIALS_H

#include <git2.h>
#include <stdbool.h>

/**
 * Credential context for tracking credentials across operations
 */
typedef struct {
    char *url;
    char *username;
    char *password;
    bool credentials_provided;
} credential_context_t;

/**
 * Create credential context
 */
credential_context_t *credential_context_create(const char *url);

/**
 * Free credential context
 */
void credential_context_free(credential_context_t *ctx);

/**
 * Approve credentials (save them via git credential helper)
 */
void credential_context_approve(credential_context_t *ctx);

/**
 * Reject credentials (remove them via git credential helper)
 */
void credential_context_reject(credential_context_t *ctx);

/**
 * Default credential callback for git operations
 *
 * This callback is used for clone, fetch, push, and pull operations.
 * It attempts authentication in the following order:
 *
 * For SSH URLs:
 *   1. SSH agent (git@github.com or ssh:// URLs)
 *   2. SSH keys from standard locations (~/.ssh/id_ed25519, ~/.ssh/id_rsa, etc.)
 *
 * For HTTPS URLs:
 *   1. Git credential helper (invokes `git credential fill`)
 *   2. Anonymous access (empty credentials for public repositories)
 *   3. libgit2 default credentials (fallback)
 *
 * The callback integrates with git's credential helper system, so it works
 * with configured credential helpers like osxkeychain, wincred, or custom helpers.
 *
 * @param out Output credential object
 * @param url Remote URL being accessed
 * @param username_from_url Username from URL (may be NULL)
 * @param allowed_types Allowed credential types (bitfield)
 * @param payload User payload (unused)
 * @return 0 on success, GIT_PASSTHROUGH to let libgit2 try without credentials,
 *         or negative error code on failure
 */
int credentials_callback(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    void *payload
);

#endif /* DOTTA_CREDENTIALS_H */
