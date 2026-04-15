/**
 * privilege.c - Privilege management implementation
 *
 * ARCHITECTURE:
 * This module ensures operations have required privileges BEFORE they begin,
 * preventing partial operations and silent metadata loss. Uses explicit user
 * interaction (prompts) rather than automatic elevation for transparency.
 *
 * SECURITY CONSIDERATIONS:
 * 1. Uses execvp() directly - no shell interpretation prevents injection
 * 2. Preserves exact argv - no manipulation or reconstruction
 * 3. User must authenticate via sudo - no passwordless elevation
 * 4. Clear messaging - user understands what and why
 * 5. Fail-fast - never proceeds with degraded functionality
 */

#include "utils/privilege.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/array.h"
#include "base/error.h"
#include "base/string.h"
#include "base/terminal.h"
#include "infra/path.h"
#include "sys/filesystem.h"

/**
 * Check if running with elevated privileges
 */
bool privilege_is_elevated(void) {
    /* Check effective UID (not real UID) to handle sudo correctly */
    return geteuid() == 0;
}

/**
 * Check if running under sudo
 */
bool privilege_is_sudo(void) {
    /* Sudo sets SUDO_UID and SUDO_GID to the original user's IDs
     * If both are present, we're running under sudo */
    const char *sudo_uid = getenv("SUDO_UID");
    const char *sudo_gid = getenv("SUDO_GID");

    return (sudo_uid != NULL && sudo_gid != NULL);
}

/**
 * Check if a storage path requires root privileges
 */
bool privilege_path_requires_root(const char *storage_path) {
    if (!storage_path) {
        return false;  /* Defensive: NULL path doesn't require root */
    }

    if (storage_path[0] == '\0') {
        return false;  /* Defensive: empty path doesn't require root */
    }

    /* Both root/ and custom/ prefix files may require root privileges for ownership capture
     * home/ prefix files always use current user (never need root) */
    return str_starts_with(storage_path, "root/") ||
           str_starts_with(storage_path, "custom/");
}

/**
 * Check if any paths in array require root privileges
 */
bool privilege_paths_require_root(const char **storage_paths, size_t count) {
    if (!storage_paths || count == 0) {
        return false;  /* Defensive: NULL or empty array doesn't require root */
    }

    /* Check each path - return true on first match */
    for (size_t i = 0; i < count; i++) {
        if (privilege_path_requires_root(storage_paths[i])) {
            return true;
        }
    }

    return false;  /* No paths require root */
}

/**
 * Check if a path is under a parent directory
 *
 * Verifies proper path boundary: /home/user matches /home/user/foo
 * but NOT /home/username/foo. The path can equal the parent (boundary
 * char is '\0').
 *
 * Handles trailing slashes on parent (e.g., "/home/user/" treated
 * identically to "/home/user").
 *
 * @param path Path to check (must not be NULL)
 * @param parent Candidate parent directory (must not be NULL)
 * @return true if path is under (or equal to) parent
 */
static bool is_path_under(const char *path, const char *parent) {
    size_t parent_len = strlen(parent);

    /* Strip trailing slashes from parent for consistent boundary checking */
    while (parent_len > 1 && parent[parent_len - 1] == '/') {
        parent_len--;
    }

    if (strncmp(path, parent, parent_len) != 0) {
        return false;
    }

    /* Verify boundary: next char after prefix must be '/' or end of string */
    char boundary = path[parent_len];
    return boundary == '/' || boundary == '\0';
}

/**
 * Check if a custom prefix requires elevated privileges
 *
 * Compares the custom prefix against $HOME using canonical paths to handle
 * symlinks (e.g., macOS /tmp → /private/tmp). Checks all combinations of
 * raw and canonical forms to catch symlinks on either side.
 */
bool privilege_custom_prefix_needs_elevation(const char *custom_prefix) {
    if (!custom_prefix || custom_prefix[0] == '\0') {
        return true;  /* No prefix → conservative default */
    }

    char *home = NULL;
    error_t *err = path_get_home(&home);
    if (err) {
        error_free(err);
        return true;  /* Can't determine HOME → conservative default */
    }

    /* Canonicalize both paths to resolve symlinks.
     * Either may fail (e.g., prefix doesn't exist on this system). */
    char *home_canonical = NULL;
    char *prefix_canonical = NULL;

    error_t *h_err = fs_canonicalize_path(home, &home_canonical);
    if (h_err) {
        error_free(h_err);
    }

    error_t *p_err = fs_canonicalize_path(custom_prefix, &prefix_canonical);
    if (p_err) {
        error_free(p_err);
    }

    /* Check all valid combinations of raw/canonical forms.
     * A single match is sufficient — symlinks may be on either side. */
    const char *homes[] = { home, home_canonical };
    const char *prefixes[] = { custom_prefix, prefix_canonical };

    bool under_home = false;
    for (int h = 0; h < 2 && !under_home; h++) {
        if (!homes[h]) continue;
        for (int p = 0; p < 2 && !under_home; p++) {
            if (!prefixes[p]) continue;
            under_home = is_path_under(prefixes[p], homes[h]);
        }
    }

    free(home);
    free(home_canonical);
    free(prefix_canonical);

    return !under_home;
}

/**
 * Check if filesystem path is under actual user's home (sudo-aware)
 *
 * Resolves symlinks on both sides to avoid false negatives on systems
 * where home or path components go through symlinks (e.g., macOS
 * /var → /private/var). Matches the canonicalization approach used
 * by privilege_custom_prefix_needs_elevation().
 */
bool privilege_path_is_under_home(const char *filesystem_path) {
    if (!filesystem_path || !privilege_is_sudo()) {
        return false;
    }

    const char *sudo_uid_str = getenv("SUDO_UID");
    if (!sudo_uid_str) {
        return false;
    }

    char *endptr;
    errno = 0;
    long parsed_uid = strtol(sudo_uid_str, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || parsed_uid < 0) {
        return false;
    }

    struct passwd *pw = getpwuid((uid_t) parsed_uid);
    if (!pw || !pw->pw_dir) {
        return false;
    }

    /* Canonicalize both paths to resolve symlinks, then check all
     * valid combinations of raw/canonical forms (same approach as
     * privilege_custom_prefix_needs_elevation). */
    char *home_canonical = NULL;
    char *path_canonical = NULL;

    error_t *h_err = fs_canonicalize_path(pw->pw_dir, &home_canonical);
    if (h_err) {
        error_free(h_err);
    }

    error_t *p_err = fs_canonicalize_path(filesystem_path, &path_canonical);
    if (p_err) {
        error_free(p_err);
    }

    const char *homes[] = { pw->pw_dir, home_canonical };
    const char *paths[] = { filesystem_path, path_canonical };

    bool under_home = false;
    for (int h = 0; h < 2 && !under_home; h++) {
        if (!homes[h]) continue;
        for (int p = 0; p < 2 && !under_home; p++) {
            if (!paths[p]) continue;
            under_home = is_path_under(paths[p], homes[h]);
        }
    }

    free(home_canonical);
    free(path_canonical);

    return under_home;
}

/**
 * Check if a storage path requires elevation for pre-flight purposes
 *
 * For custom/ paths, checks whether the resolved filesystem_path is under $HOME.
 * This works because filesystem_path = custom_prefix + /relative, and is_path_under()
 * on the full path gives the same result as on the prefix alone (no traversal allowed
 * in custom paths, enforced by path_validate_custom_prefix).
 */
bool privilege_needs_elevation(const char *storage_path, const char *filesystem_path) {
    if (!storage_path || storage_path[0] == '\0') {
        return false;
    }

    if (str_starts_with(storage_path, "root/")) {
        return true;
    }

    if (str_starts_with(storage_path, "custom/")) {
        return privilege_custom_prefix_needs_elevation(filesystem_path);
    }

    /* home/ and other prefixes don't need elevation */
    return false;
}

/**
 * Get actual user UID/GID (handling sudo context)
 *
 * When running under sudo, returns the original user's UID/GID from SUDO_UID/SUDO_GID
 * environment variables. When not under sudo, returns effective UID/GID.
 *
 * This is the single source of truth for sudo context detection and actual user resolution.
 */
error_t *privilege_get_actual_user(uid_t *uid, gid_t *gid) {
    CHECK_NULL(uid);
    CHECK_NULL(gid);

    /* Check if running under sudo by examining SUDO_UID environment variable */
    const char *sudo_uid_str = getenv("SUDO_UID");
    const char *sudo_gid_str = getenv("SUDO_GID");

    if (sudo_uid_str && sudo_gid_str) {
        /* Running under sudo - parse the environment variables */
        char *endptr;

        /* Parse UID */
        errno = 0;
        long parsed_uid = strtol(sudo_uid_str, &endptr, 10);
        if (errno != 0 || *endptr != '\0' || parsed_uid < 0) {
            return ERROR(
                ERR_INVALID_ARG, "Invalid SUDO_UID environment variable: %s",
                sudo_uid_str
            );
        }

        /* Parse GID */
        errno = 0;
        long parsed_gid = strtol(sudo_gid_str, &endptr, 10);
        if (errno != 0 || *endptr != '\0' || parsed_gid < 0) {
            return ERROR(
                ERR_INVALID_ARG, "Invalid SUDO_GID environment variable: %s",
                sudo_gid_str
            );
        }

        /* Validate that the UID actually exists in the system */
        struct passwd *pw = getpwuid((uid_t) parsed_uid);
        if (!pw) {
            return ERROR(
                ERR_NOT_FOUND, "User with UID %ld not found in system",
                parsed_uid
            );
        }

        *uid = (uid_t) parsed_uid;
        *gid = (gid_t) parsed_gid;
        return NULL;
    }

    /* Not running under sudo - return current effective UID/GID */
    *uid = geteuid();
    *gid = getegid();
    return NULL;
}

/**
 * Collect paths that require elevated privileges
 *
 * Filters input to paths with root/ or custom/ prefix (both may carry
 * ownership metadata requiring root). Allocates a new array of pointers;
 * does NOT duplicate the path strings themselves.
 *
 * @param all_paths Input array of all paths
 * @param count Number of paths in input array
 * @param priv_paths_out Output array of privileged paths (caller must free)
 * @param priv_count_out Number of privileged paths found
 * @return Error or NULL on success
 */
static error_t *collect_privileged_paths(
    char *const *all_paths,
    size_t count,
    char ***priv_paths_out,
    size_t *priv_count_out
) {
    CHECK_NULL(all_paths);
    CHECK_NULL(priv_paths_out);
    CHECK_NULL(priv_count_out);

    *priv_paths_out = NULL;
    *priv_count_out = 0;

    ptr_array_t matches PTR_ARRAY_AUTO = { 0 };
    for (size_t i = 0; i < count; i++) {
        if (privilege_path_requires_root(all_paths[i])) {
            RETURN_IF_ERROR(ptr_array_push(&matches, all_paths[i]));
        }
    }

    *priv_paths_out = (char **) ptr_array_steal(&matches, priv_count_out);
    return NULL;
}

/**
 * Display privilege requirement message to user
 *
 * Shows which files require root and explains why. Limits output to
 * first 10 files to avoid overwhelming the user.
 *
 * @param operation Operation name (e.g., "add", "update")
 * @param priv_paths Array of paths requiring root
 * @param priv_count Number of paths
 * @param out Output context
 */
static void display_privilege_requirement(
    const char *operation,
    char *const *priv_paths,
    size_t priv_count,
    output_ctx_t *out
) {
    /* Header */
    output_error(
        out, "\nRoot privileges required for this operation.\n"
    );

    /* Operation name */
    output_print(
        out, OUTPUT_NORMAL, "\nOperation: %s\n", operation
    );

    /* List files requiring root (limit to 10 for readability) */
    output_print(
        out, OUTPUT_NORMAL, "\nFiles requiring root privileges:\n"
    );

    size_t display_count = priv_count > 10 ? 10 : priv_count;
    for (size_t i = 0; i < display_count; i++) {
        output_print(
            out, OUTPUT_NORMAL, "  %s\n",
            priv_paths[i]
        );
    }

    if (priv_count > 10) {
        output_print(
            out, OUTPUT_NORMAL, "  ... and %zu more\n",
            priv_count - 10
        );
    }

    /* Explain why root is needed */
    output_print(
        out, OUTPUT_NORMAL,
        "\nReason: These files require ownership metadata capture,\n"
        "          which requires root privileges to access.\n"
    );
}

/**
 * Re-execute current process with sudo
 *
 * SECURITY CRITICAL:
 * - Uses execvp() directly (no shell, no injection risk)
 * - Preserves exact argv (no reconstruction or manipulation)
 * - Uses sudo -E to preserve environment (including DOTTA_*)
 * - Requires user authentication (system sudo policy)
 *
 * If successful, this function DOES NOT RETURN (process is replaced).
 * If exec() fails, returns an error.
 *
 * @param argc Original argc from main()
 * @param argv Original argv from main()
 * @return Error (only returned if exec fails)
 */
static error_t *reexec_with_sudo(int argc, char **argv) {
    CHECK_NULL(argv);

    if (argc < 1) {
        return ERROR(ERR_INVALID_ARG, "Invalid argc/argv for re-exec");
    }

    /* Build sudo command: sudo -E <original command> <original args>
     *
     * Example transformation:
     *   Original: dotta add -p test /etc/hosts
     *   New:      sudo -E dotta add -p test /etc/hosts
     *
     * Array layout:
     *   sudo_argv[0] = "sudo"
     *   sudo_argv[1] = "-E"
     *   sudo_argv[2] = argv[0] (original "dotta")
     *   sudo_argv[3] = argv[1] (original "add")
     *   ...
     *   sudo_argv[argc + 2] = NULL
     */

    /* Allocate new argv array: sudo, -E, original args, NULL */
    char **sudo_argv = calloc((size_t) argc + 3, sizeof(char *));
    if (!sudo_argv) {
        return ERROR(ERR_MEMORY, "Failed to allocate sudo argv array");
    }

    /* Build sudo command */
    sudo_argv[0] = "sudo";
    sudo_argv[1] = "-E";  /* Preserve environment variables */

    /* Copy all original arguments */
    for (int i = 0; i < argc; i++) {
        sudo_argv[i + 2] = argv[i];
    }

    sudo_argv[argc + 2] = NULL;  /* NULL terminator required by execvp */

    /* Execute sudo - replaces current process on success
     * execvp searches PATH for "sudo" and handles it properly */
    execvp("sudo", sudo_argv);

    /* If we reach here, exec failed */
    int saved_errno = errno;
    free(sudo_argv);

    /* Provide helpful error message based on errno */
    if (saved_errno == ENOENT) {
        return ERROR(
            ERR_PERMISSION, "Failed to execute sudo: command not found\n"
            "Ensure sudo is installed and in PATH"
        );
    } else {
        return ERROR(
            ERR_PERMISSION, "Failed to execute sudo: %s",
            strerror(saved_errno)
        );
    }
}

/**
 * Ensure proper privileges for an operation
 *
 * Main entry point for privilege management. Call this BEFORE starting
 * any operation that might need elevated privileges (root/ or custom/ prefix files).
 *
 * WORKFLOW:
 * 1. Filter paths to find privileged prefixes (root/, custom/)
 * 2. Check if already elevated - if yes, proceed
 * 3. Display requirement to user
 * 4. If interactive: prompt for confirmation
 * 5. If approved: re-exec with sudo (DOES NOT RETURN)
 * 6. If declined or non-interactive: return error
 *
 * CRITICAL: May re-execute entire process. Any state changes before
 * calling this function will be lost.
 */
error_t *privilege_ensure_for_operation(
    char *const *storage_paths,
    size_t count,
    const char *operation_name,
    bool interactive,
    int argc,
    char **argv,
    output_ctx_t *out
) {
    CHECK_NULL(storage_paths);
    CHECK_NULL(operation_name);
    CHECK_NULL(argv);
    CHECK_NULL(out);

    /* Early exit: no paths means no privilege check needed */
    if (count == 0) {
        return NULL;
    }

    /* Collect paths requiring elevated privileges */
    char **priv_paths = NULL;
    size_t priv_count = 0;

    error_t *err = collect_privileged_paths(
        storage_paths, count, &priv_paths, &priv_count
    );
    if (err) {
        return err;
    }

    /* Early exit: no privileged paths means no privilege check needed */
    if (priv_count == 0) {
        free(priv_paths);
        return NULL;
    }

    /* Early exit: already elevated means we have required privileges */
    if (privilege_is_elevated()) {
        free(priv_paths);
        return NULL;
    }

    /* We need elevation but don't have it - interact with user */

    /* Display requirement (always shown, even in non-interactive mode) */
    display_privilege_requirement(operation_name, priv_paths, priv_count, out);

    error_t *result = NULL;

    /* Check if we can prompt user interactively */
    if (interactive && terminal_is_tty()) {
        /* Interactive mode: prompt for confirmation */
        if (output_confirm(out, "\nAuthenticate with sudo?", true)) {
            /* User approved - re-exec with sudo */
            output_print(out, OUTPUT_NORMAL, "\nRe-executing with sudo...\n\n");

            /* This function does not return on success */
            result = reexec_with_sudo(argc, argv);

            /* If we reach here, re-exec failed */
            free(priv_paths);
            return result;
        } else {
            /* User declined elevation */
            result = ERROR(ERR_PERMISSION, "Elevation declined by user");
        }
    } else {
        /* Non-interactive mode: cannot prompt, must fail */
        output_print(out, OUTPUT_NORMAL, "\nTo proceed, run with sudo:\n");
        output_print(out, OUTPUT_NORMAL, "  sudo %s %s ...\n\n", argv[0], operation_name);

        result = ERROR(
            ERR_PERMISSION,
            "Root privileges required but cannot prompt (non-interactive mode)"
        );
    }

    free(priv_paths);
    return result;
}
