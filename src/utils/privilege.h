/**
 * privilege.h - Privilege management for metadata preservation
 *
 * ARCHITECTURE:
 * Ensures complete metadata capture by enforcing privilege requirements
 * before operations begin. Provides explicit user interaction when elevation
 * is needed, with fail-fast behavior to prevent silent metadata loss.
 *
 * SECURITY:
 * - Uses execvp() directly (no shell interpretation)
 * - Preserves exact command-line arguments for re-execution
 * - Requires explicit user authentication via sudo
 * - No automatic elevation without user consent
 */

#ifndef DOTTA_PRIVILEGE_H
#define DOTTA_PRIVILEGE_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "base/error.h"
#include "utils/output.h"

/**
 * Check if running with elevated privileges (effective UID is 0)
 *
 * @return true if running as root, false otherwise
 */
bool privilege_is_elevated(void);

/**
 * Check if running under sudo (original user context preserved)
 *
 * Detects sudo by checking for SUDO_UID/SUDO_GID environment variables.
 * This allows code to distinguish between:
 * - Real root user (logged in as root)
 * - Sudo user (elevated via sudo, original user known)
 *
 * @return true if running under sudo, false otherwise
 */
bool privilege_is_sudo(void);

/**
 * Check if a storage path requires root privileges
 *
 * Paths with root/ or custom/ prefix require root privileges for complete
 * metadata capture (ownership information). Paths with home/ prefix do not.
 *
 * @param storage_path Storage path (e.g., "home/.bashrc", "root/etc/hosts", "custom/etc/nginx.conf")
 * @return true if path requires root privileges, false otherwise
 */
bool privilege_path_requires_root(const char *storage_path);

/**
 * Check if any paths in array require root privileges
 *
 * @param storage_paths Array of storage paths
 * @param count Number of paths in array
 * @return true if any path requires root, false otherwise
 */
bool privilege_paths_require_root(const char **storage_paths, size_t count);

/**
 * Get actual user UID/GID (handling sudo context)
 *
 * When running under sudo, returns the original user's UID/GID from SUDO_UID/SUDO_GID
 * environment variables. When not under sudo, returns effective UID/GID.
 *
 * Use Cases:
 * - Deployment: home/ prefix files under sudo should be owned by actual user, not root
 * - Repository: Fix repository ownership after sudo operations
 *
 * This is the single source of truth for "who is the real user" semantics.
 * All sudo context detection is centralized in the privilege module.
 *
 * @param uid Output for user ID (must not be NULL)
 * @param gid Output for group ID (must not be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_INVALID_ARG: Invalid SUDO_UID/SUDO_GID format
 * - ERR_NOT_FOUND: UID from SUDO_UID does not exist in system
 */
error_t *privilege_get_actual_user(uid_t *uid, gid_t *gid);

/**
 * Ensure proper privileges for an operation
 *
 * This is the main entry point for privilege management. Call this BEFORE
 * starting any operation that might need root privileges.
 *
 * BEHAVIOR:
 * 1. If no root/ paths: Returns NULL (proceed normally)
 * 2. If already elevated: Returns NULL (proceed with privileges)
 * 3. If interactive && user approves: Re-execs with sudo (DOES NOT RETURN)
 * 4. If interactive && user declines: Returns ERR_PERMISSION
 * 5. If non-interactive: Returns ERR_PERMISSION with helpful message
 *
 * CRITICAL: This function may re-execute the entire process with sudo.
 * If re-execution succeeds, this function DOES NOT RETURN.
 * Any state changes before calling this function will be lost.
 *
 * @param storage_paths Array of storage paths being operated on
 * @param count Number of paths
 * @param operation_name Operation name (for display, e.g., "add", "update")
 * @param interactive Whether interactive prompts are allowed
 * @param argc Original argc from main() (for re-exec)
 * @param argv Original argv from main() (for re-exec)
 * @param out Output context for messages (must not be NULL)
 * @return NULL if OK to proceed, error otherwise (or does not return if re-exec)
 */
error_t *privilege_ensure_for_operation(
    const char **storage_paths,
    size_t count,
    const char *operation_name,
    bool interactive,
    int argc,
    char **argv,
    output_ctx_t *out
);

#endif /* DOTTA_PRIVILEGE_H */
