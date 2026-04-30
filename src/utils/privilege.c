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
#include "base/terminal.h"
#include "infra/mount.h"
#include "sys/filesystem.h"

/**
 * Boundary-aware ancestor check with symlink awareness.
 *
 * Returns true when `absolute_path` is under (or equal to) `reference_dir`,
 * comparing both raw and canonical (realpath-resolved) forms of each side.
 * A single match across the (raw, canonical) x (raw, canonical) cross
 * product is sufficient, catching symlinks on either side (e.g.,
 * macOS's /tmp -> /private/tmp, or a $HOME that traverses a bind mount).
 *
 * Boundary rule (component-aware):
 *   /home/user matches /home/user and /home/user/.bashrc
 *   /home/user does NOT match /home/username (false-prefix guard)
 *
 * Trailing slashes on `reference_dir` are normalised internally so that
 * "/home/user/" and "/home/user" behave identically.
 *
 * Privilege-internal: the only callers are the HOME-boundary checks below.
 * Generic-looking but specifically tuned for "is this filesystem path under
 * the user's home / the deployment target?" — moving it elsewhere when no
 * second consumer exists would be premature indirection.
 */
static bool is_under(
    const char *absolute_path,
    const char *reference_dir
) {
    if (!absolute_path || !reference_dir) return false;

    /* Best-effort canonicalize both sides; either may fail (e.g., the
     * path does not exist on this system, or symlink resolution hits
     * EACCES). On failure, the raw form is the only comparison
     * candidate for that side. */
    char *path_canonical = NULL;
    char *ref_canonical = NULL;

    error_t *p_err = fs_canonicalize_path(absolute_path, &path_canonical);
    if (p_err) error_free(p_err);

    error_t *r_err = fs_canonicalize_path(reference_dir, &ref_canonical);
    if (r_err) error_free(r_err);

    const char *paths[] = { absolute_path, path_canonical };
    const char *refs[] = { reference_dir, ref_canonical };

    bool under = false;
    for (int p = 0; p < 2 && !under; p++) {
        if (!paths[p]) continue;
        for (int r = 0; r < 2 && !under; r++) {
            if (!refs[r]) continue;

            /* Trim trailing slashes from the reference for boundary
             * parity. getenv("HOME"), pw_dir, and user-supplied targets
             * may carry a stray trailing slash; "/home/user/" and
             * "/home/user" must classify the same path identically. */
            size_t ref_len = strlen(refs[r]);
            while (ref_len > 1 && refs[r][ref_len - 1] == '/') {
                ref_len--;
            }
            if (strncmp(paths[p], refs[r], ref_len) != 0) continue;

            /* Component boundary: next char must be '/' or '\0'.
             * Rejects /home/username when reference is /home/user. */
            char boundary = paths[p][ref_len];
            if (boundary == '/' || boundary == '\0') under = true;
        }
    }

    free(path_canonical);
    free(ref_canonical);
    return under;
}

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
    const mount_spec_t *spec = mount_spec_for_label(storage_path);
    return spec && spec->tracks_ownership;
}

/**
 * Check if a deployment target requires elevated privileges
 *
 * Returns true when the target is NOT under $HOME — files under it carry
 * ownership metadata that requires root to read on capture. The
 * boundary-aware comparison (is_under) cross-checks raw and canonical
 * forms of both sides, so symlinks (e.g., macOS /tmp -> /private/tmp)
 * do not produce false negatives.
 */
bool privilege_target_needs_elevation(const char *target) {
    if (!target || target[0] == '\0') {
        return true;  /* No target → conservative default */
    }

    char *home = NULL;
    error_t *err = fs_get_home(&home);
    if (err) {
        error_free(err);
        return true;  /* Can't determine HOME → conservative default */
    }

    bool under_home = is_under(target, home);
    free(home);

    return !under_home;
}

/**
 * Check if filesystem path is under actual user's home (sudo-aware)
 *
 * Reads the sudo-invoking user's home from getpwuid(SUDO_UID)->pw_dir
 * (more reliable than $HOME under sudo, which may have been overridden
 * with `sudo -H`). The boundary-aware comparison cross-checks raw and
 * canonical forms to avoid symlink false negatives.
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

    return is_under(filesystem_path, pw->pw_dir);
}

/**
 * Check if a storage path requires elevation for pre-flight purposes
 *
 * For custom/ paths, checks whether the resolved filesystem_path is under $HOME.
 * This works because filesystem_path = target + /relative; the
 * boundary-aware ancestor check on the full path gives the same result as on
 * the target alone (no traversal allowed in custom paths, enforced by
 * mount_validate_target).
 */
bool privilege_needs_elevation(
    const char *storage_path,
    const char *filesystem_path
) {
    const mount_spec_t *spec = mount_spec_for_label(storage_path);
    if (!spec || !spec->tracks_ownership) return false;

    /* Two ownership-tracking kinds today:
     *   ROOT (!per_profile): always needs elevation.
     *   CUSTOM (per_profile): elevation depends on deployment target */
    if (!spec->per_profile) return true;
    return privilege_target_needs_elevation(filesystem_path);
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
 * Display privilege requirement message to user.
 *
 * Shows which items require root and explains why. Limits output to
 * first 10 items to avoid overwhelming the user. The header is a
 * warning, not an error: the operation will still proceed cleanly
 * after the user authenticates with sudo.
 *
 * @param operation Operation name (e.g., "add", "update")
 * @param labels Storage paths needing root (pre-filtered, must not be NULL when count > 0)
 * @param count Number of labels
 * @param out Output context
 */
static void display_privilege_requirement(
    const char *operation,
    const char *const *labels,
    size_t count,
    output_t *out
) {
    output_warning(
        out, OUTPUT_NORMAL, "\nRoot privileges required for this operation.\n"
    );

    output_print(out, OUTPUT_NORMAL, "\nOperation: %s\n", operation);
    output_print(out, OUTPUT_NORMAL, "\nFiles requiring root privileges:\n");

    size_t display_count = count > 10 ? 10 : count;
    for (size_t i = 0; i < display_count; i++) {
        output_print(out, OUTPUT_NORMAL, "  %s\n", labels[i]);
    }

    if (count > 10) {
        output_print(
            out, OUTPUT_NORMAL, "  ... and %zu more\n", count - 10
        );
    }

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
 * Append a label iff this entry needs elevation.
 *
 * Self-enforcing filter at the collection boundary: callers cannot
 * surface entries that don't actually need elevation. The privilege
 * decision and the push live in one call; there is no intermediate
 * state where a caller could forget the predicate.
 *
 * The label that goes into the array is always the storage_path —
 * stable, user-recognizable, already what every VWD-driven caller
 * wants displayed.
 */
error_t *privilege_collect_label(
    string_array_t *labels,
    const char *storage_path,
    const char *filesystem_path
) {
    CHECK_NULL(labels);
    CHECK_NULL(storage_path);

    if (!privilege_needs_elevation(storage_path, filesystem_path)) {
        return NULL;
    }
    return string_array_push(labels, storage_path);
}

/**
 * Ensure proper privileges for an operation.
 *
 * Main entry point for privilege management. Call this BEFORE starting
 * any operation that might need elevated privileges (kinds whose spec
 * marks tracks_ownership: root/ files always; custom/ files when the
 * deployment target is outside $HOME).
 *
 * WORKFLOW:
 * 1. count == 0 → already nothing to elevate for, proceed.
 * 2. Already elevated → we have what we need, proceed.
 * 3. Display requirement to user.
 * 4. Interactive: prompt for confirmation.
 *    - Approved  → re-exec with sudo (DOES NOT RETURN).
 *    - Declined  → return ERR_PERMISSION.
 * 5. Non-interactive → return ERR_PERMISSION with hint.
 *
 * CRITICAL: May re-execute entire process. Any state changes before
 * calling this function will be lost.
 */
error_t *privilege_ensure_for_operation(
    const char *const *labels,
    size_t count,
    const char *operation_name,
    bool interactive,
    int argc,
    char **argv,
    output_t *out
) {
    CHECK_NULL(operation_name);
    CHECK_NULL(argv);
    CHECK_NULL(out);

    if (count == 0) return NULL;
    CHECK_NULL(labels);

    /* Already elevated — we have what we need. */
    if (privilege_is_elevated()) return NULL;

    /* Display requirement (always shown, even in non-interactive mode) */
    display_privilege_requirement(operation_name, labels, count, out);

    if (interactive && terminal_is_tty()) {
        if (output_confirm(out, "\nAuthenticate with sudo?", true)) {
            output_print(out, OUTPUT_NORMAL, "\nRe-executing with sudo...\n\n");
            /* reexec_with_sudo does not return on success. */
            return reexec_with_sudo(argc, argv);
        }
        return ERROR(ERR_PERMISSION, "Elevation declined by user");
    }

    /* Non-interactive: cannot prompt, must fail. */
    output_print(out, OUTPUT_NORMAL, "\nTo proceed, run with sudo:\n");
    output_print(out, OUTPUT_NORMAL, "  sudo %s %s ...\n\n", argv[0], operation_name);
    return ERROR(
        ERR_PERMISSION,
        "Root privileges required but cannot prompt (non-interactive mode)"
    );
}
