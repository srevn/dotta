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
#include <types.h>

#include "base/output.h"

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
 * Check if a filesystem path is under the invoking user's home directory.
 *
 * Single boundary predicate replacing the prior pair
 * (privilege_target_needs_elevation, privilege_path_is_under_home):
 * one polarity, one implementation, one source of HOME truth via
 * fs_get_home (sudo-aware).
 *
 * Symlink-aware: cross-checks raw and realpath-canonical forms of
 * both sides, so /tmp -> /private/tmp on macOS and similar bind/loop
 * arrangements do not produce false negatives. Component-aware
 * boundary so /home/user does not falsely match /home/username.
 *
 * Returns false when:
 *   - filesystem_path is NULL
 *   - HOME cannot be resolved (no $HOME, no passwd entry)
 *   - filesystem_path is genuinely outside HOME
 *
 * The "false on lookup failure" bias keeps callers conservative: a
 * caller asking "should I de-escalate ownership?" gets "no" when in
 * doubt; a caller asking "no elevation needed?" gets "elevation
 * needed" when in doubt (via the natural negation).
 *
 * @param filesystem_path Absolute filesystem path to check (may be NULL)
 * @return true iff filesystem_path is under the user's HOME
 */
bool privilege_path_is_user_home(const char *filesystem_path);

/**
 * Check if a storage path requires elevation for pre-flight purposes
 *
 * Pre-flight decision function: "should we prompt for sudo?"
 *
 * Composes the label vocabulary (mount spec) with the resolved
 * filesystem path's home-membership:
 *
 * - home/ paths: never need elevation (no ownership metadata)
 * - root/ paths: always need elevation
 * - custom/ paths: need elevation only if filesystem_path is NOT under $HOME
 *
 * For metadata-capture/deploy layers' "could this path carry ownership
 * metadata?" question, read mount_spec_for_path(p)->tracks_ownership
 * directly — the label vocabulary lives in infra/mount.
 *
 * @param storage_path Storage path (e.g., "custom/etc/nginx.conf")
 * @param filesystem_path Resolved filesystem path (NULL if unknown → conservative true)
 * @return true if elevation needed, false otherwise
 */
bool privilege_needs_elevation(const char *storage_path, const char *filesystem_path);

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
 * Append `storage_path` to `labels` iff this entry needs elevation.
 *
 * Wraps the predicate-and-push idiom that the manifest- and workspace-
 * driven callers (apply, update, status) repeat for every entry: if the
 * (storage_path, filesystem_path) pair triggers privilege_needs_elevation,
 * push storage_path onto the label collection.
 *
 * Pulls the filter into the privilege module so callers cannot mistakenly
 * surface entries that don't actually need elevation — the predicate is
 * now self-enforcing at the collection boundary.
 *
 * Callers that have only a kind on hand (e.g., add.c's storage-path
 * inputs and classification-root case) compute the predicate locally
 * — they have no filesystem_path and use a precomputed
 * "target outside HOME" bool (one fs_get_home / is_under per command)
 * instead of consulting privilege_path_is_user_home per file.
 *
 * Lifetime: storage_path is copied into `labels` (string_array_push
 * strdups), so the array is independent of the entry's lifetime.
 *
 * @param labels Output collection (must not be NULL)
 * @param storage_path Storage path (must not be NULL)
 * @param filesystem_path Resolved filesystem path (NULL → conservative)
 * @return Error on allocation failure; NULL otherwise (including the
 *         "no elevation needed" no-op success)
 */
error_t *privilege_collect_label(
    string_array_t *labels,
    const char *storage_path,
    const char *filesystem_path
);

/**
 * Ensure proper privileges for an operation.
 *
 * Main entry point for privilege management. Call this BEFORE starting
 * any operation that might need root privileges.
 *
 * Behavior:
 *   1. count == 0:                          Returns NULL (proceed)
 *   2. Already elevated:                    Returns NULL (proceed)
 *   3. Interactive + user approves:         Re-execs with sudo (DOES NOT RETURN)
 *   4. Interactive + user declines:         Returns ERR_PERMISSION
 *   5. Non-interactive:                     Returns ERR_PERMISSION with hint
 *
 * CRITICAL: This function may re-execute the entire process with sudo.
 * If re-execution succeeds, this function DOES NOT RETURN.
 * Any state changes before calling this function will be lost.
 *
 * @param labels Storage paths for items needing elevation (must outlive
 *               the call; an empty array means "nothing needs root")
 * @param count Number of labels
 * @param operation_name Operation name (for display, e.g., "add", "update")
 * @param interactive Whether interactive prompts are allowed
 * @param argc Original argc from main() (for re-exec)
 * @param argv Original argv from main() (for re-exec)
 * @param out Output context for messages (must not be NULL)
 * @return NULL if OK to proceed, error otherwise (or does not return if re-exec)
 */
error_t *privilege_ensure_for_operation(
    const char *const *labels,
    size_t count,
    const char *operation_name,
    bool interactive,
    int argc,
    char **argv,
    output_t *out
);

#endif /* DOTTA_PRIVILEGE_H */
