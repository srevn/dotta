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

#include "privilege.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils/string.h"

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

    /* Only root/ prefix files require root privileges for ownership capture */
    return str_starts_with(storage_path, "root/");
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
 * Collect all paths that require root privileges
 *
 * Allocates a new array containing pointers to root/ paths from the input.
 * Does NOT duplicate the path strings themselves - just stores pointers.
 *
 * @param all_paths Input array of all paths
 * @param count Number of paths in input array
 * @param root_paths_out Output array of root/ paths (caller must free)
 * @param root_count_out Number of root/ paths found
 * @return Error or NULL on success
 */
static error_t *collect_root_paths(
    const char **all_paths,
    size_t count,
    const char ***root_paths_out,
    size_t *root_count_out
) {
    CHECK_NULL(all_paths);
    CHECK_NULL(root_paths_out);
    CHECK_NULL(root_count_out);

    /* Count root/ paths first (two-pass for cleaner code) */
    size_t root_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (privilege_path_requires_root(all_paths[i])) {
            root_count++;
        }
    }

    /* If no root paths, return empty result */
    if (root_count == 0) {
        *root_paths_out = NULL;
        *root_count_out = 0;
        return NULL;
    }

    /* Allocate array for root path pointers */
    const char **root_paths = calloc(root_count, sizeof(char *));
    if (!root_paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate root paths array");
    }

    /* Populate array with pointers to root/ paths */
    size_t idx = 0;
    for (size_t i = 0; i < count; i++) {
        if (privilege_path_requires_root(all_paths[i])) {
            root_paths[idx++] = all_paths[i];
        }
    }

    *root_paths_out = root_paths;
    *root_count_out = root_count;
    return NULL;
}

/**
 * Display privilege requirement message to user
 *
 * Shows which files require root and explains why. Limits output to
 * first 10 files to avoid overwhelming the user.
 *
 * @param operation Operation name (e.g., "add", "update")
 * @param root_paths Array of paths requiring root
 * @param root_count Number of paths
 * @param out Output context
 */
static void display_privilege_requirement(
    const char *operation,
    const char **root_paths,
    size_t root_count,
    output_ctx_t *out
) {
    /* Header */
    output_error(out, "\nRoot privileges required for this operation.\n");

    /* Operation name */
    output_print(out, OUTPUT_NORMAL, "\nOperation: %s\n", operation);

    /* List files requiring root (limit to 10 for readability) */
    output_print(out, OUTPUT_NORMAL, "\nFiles requiring root privileges:\n");

    size_t display_count = root_count > 10 ? 10 : root_count;
    for (size_t i = 0; i < display_count; i++) {
        output_print(out, OUTPUT_NORMAL, "  %s\n", root_paths[i]);
    }

    if (root_count > 10) {
        output_print(out, OUTPUT_NORMAL, "  ... and %zu more\n", root_count - 10);
    }

    /* Explain why root is needed */
    output_print(out, OUTPUT_NORMAL, "\nReason: Files with root/ prefix require ownership metadata capture,\n");
    output_print(out, OUTPUT_NORMAL, "        which requires root privileges to access.\n");
}

/**
 * Prompt user for sudo authentication
 *
 * Interactive prompt with sensible defaults (default = yes).
 * Handles EOF, signals, and various input formats gracefully.
 *
 * @param out Output context for displaying prompt
 * @return true if user approves, false otherwise
 */
static bool prompt_for_elevation(output_ctx_t *out) {
    /* Display prompt with default indicator [Y/n] */
    output_print(out, OUTPUT_NORMAL, "\nAuthenticate with sudo? [Y/n] ");

    /* Ensure prompt is visible before reading input */
    fflush(stdout);
    fflush(stderr);

    /* Read user response */
    char response[10];
    if (!fgets(response, sizeof(response), stdin)) {
        /* EOF or read error - treat as decline */
        return false;
    }

    /* Parse response:
     * - Empty line (just Enter): YES (default)
     * - 'Y' or 'y': YES
     * - Anything else: NO */
    if (response[0] == '\n') {
        return true;  /* Default to yes */
    }

    if (response[0] == 'Y' || response[0] == 'y') {
        return true;
    }

    return false;  /* Any other input is treated as no */
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
    char **sudo_argv = calloc((size_t)argc + 3, sizeof(char *));
    if (!sudo_argv) {
        return ERROR(ERR_MEMORY, "Failed to allocate sudo argv array");
    }

    /* Build sudo command */
    sudo_argv[0] = "sudo";
    sudo_argv[1] = "-E";  /* Preserve environment variables (DOTTA_CONFIG_FILE, etc.) */

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
        return ERROR(ERR_PERMISSION, "Failed to execute sudo: command not found\n"
                    "Ensure sudo is installed and in PATH");
    } else {
        return ERROR(ERR_PERMISSION, "Failed to execute sudo: %s", strerror(saved_errno));
    }
}

/**
 * Ensure proper privileges for an operation
 *
 * Main entry point for privilege management. Call this BEFORE starting
 * any operation that might modify root/ prefix files.
 *
 * WORKFLOW:
 * 1. Filter paths to find root/ prefixes
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
    const char **storage_paths,
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

    /* Collect paths requiring root privileges */
    const char **root_paths = NULL;
    size_t root_count = 0;

    error_t *err = collect_root_paths(storage_paths, count, &root_paths, &root_count);
    if (err) {
        return err;
    }

    /* Early exit: no root/ paths means no privilege check needed */
    if (root_count == 0) {
        free((void *)root_paths);  /* Free array even though it's NULL (defensive) */
        return NULL;
    }

    /* Early exit: already elevated means we have required privileges */
    if (privilege_is_elevated()) {
        free((void *)root_paths);
        return NULL;
    }

    /* We need elevation but don't have it - interact with user */

    /* Display requirement (always shown, even in non-interactive mode) */
    display_privilege_requirement(operation_name, root_paths, root_count, out);

    error_t *result = NULL;

    /* Check if we can prompt user interactively */
    if (interactive && isatty(STDIN_FILENO)) {
        /* Interactive mode: prompt for confirmation */
        if (prompt_for_elevation(out)) {
            /* User approved - re-exec with sudo */
            output_print(out, OUTPUT_NORMAL, "\nRe-executing with sudo...\n\n");

            /* This function does not return on success */
            result = reexec_with_sudo(argc, argv);

            /* If we reach here, re-exec failed */
            free((void *)root_paths);
            return result;
        } else {
            /* User declined elevation */
            result = ERROR(ERR_PERMISSION, "Elevation declined by user");
        }
    } else {
        /* Non-interactive mode: cannot prompt, must fail */
        output_print(out, OUTPUT_NORMAL, "\nTo proceed, run with sudo:\n");
        output_print(out, OUTPUT_NORMAL, "  sudo %s %s ...\n\n", argv[0], operation_name);

        result = ERROR(ERR_PERMISSION,
                      "Root privileges required but cannot prompt (non-interactive mode)");
    }

    free((void *)root_paths);
    return result;
}
