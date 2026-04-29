/**
 * path.h - Generic path arithmetic
 *
 * Pure path string utilities — no storage labels, no mount table, no
 * arena. The four functions exposed here are layer-agnostic primitives
 * shared by the mount module above and a handful of boundary consumers
 * (config, hooks, privilege) that need only generic path operations.
 *
 * SECURITY CRITICAL: All conversions validate against path traversal.
 *
 * Design principles:
 *   - Reject any path containing ".." in security-sensitive contexts
 *   - Canonicalize when needed
 *   - Clear error messages
 */

#ifndef DOTTA_PATH_H
#define DOTTA_PATH_H

#include <stdbool.h>
#include <types.h>

/**
 * Get $HOME directory.
 *
 * Tries $HOME from getenv(3) first, falls back to passwd database.
 *
 * @param out HOME directory path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_get_home(char **out);

/**
 * Expand ~ to $HOME.
 *
 * Examples:
 *   ~/.bashrc -> /home/user/.bashrc
 *   ~/foo/bar -> /home/user/foo/bar
 *
 * Note: ~user/foo (other-user expansion) is not supported.
 *
 * @param path Path with optional ~ prefix (must not be NULL)
 * @param out  Expanded path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_expand_home(const char *path, char **out);

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
 * "/home/user/" and "/home/user" behave identically. Either side may
 * fail to canonicalise (e.g., the path does not exist on this system);
 * the raw form is then the only comparison candidate on that side.
 *
 * Typical use: privilege checks that ask "is this filesystem path under
 * $HOME / the user's home / the deployment target?", where symlinks on
 * either side would otherwise cause false negatives.
 *
 * @param absolute_path Path to test (NULL returns false)
 * @param reference_dir Candidate parent directory (NULL returns false)
 * @return true if absolute_path is under reference_dir
 */
bool path_is_under(
    const char *absolute_path,
    const char *reference_dir
);

/**
 * Normalize user input path to absolute filesystem path.
 *
 * Transformation order:
 *   1. Tilde expansion (~/ -> $HOME)
 *   2. Virtual-root resolution:
 *      - Relative paths: join with virtual_root
 *      - Absolute paths already under virtual_root: pass through
 *      - Absolute paths not under virtual_root: prepend virtual_root
 *   3. CWD joining (relative, no virtual_root)
 *
 * The virtual_root defines a virtual filesystem root. All paths
 * (relative and absolute) are resolved within that context. An
 * absolute path like /etc/hosts with virtual_root /jail becomes
 * /jail/etc/hosts because the path is "absolute within the jail".
 *
 * Security: rejects path traversal (..) in relative paths when
 * virtual_root is set.
 *
 * Examples:
 *   ("~/file", NULL)              -> "$HOME/file"
 *   ("rel/file", "/jail")         -> "/jail/rel/file"
 *   ("/etc/hosts", "/jail")       -> "/jail/etc/hosts"
 *   ("/jail/etc/hosts", "/jail")  -> "/jail/etc/hosts" (already under root)
 *   ("rel/file", NULL)            -> "$CWD/rel/file"
 *   ("../escape", "/jail")        -> ERROR
 *
 * @param user_path    User-provided path (filesystem or tilde)
 * @param virtual_root Optional virtual filesystem root (can be NULL)
 * @param out          Normalized absolute path (caller must free)
 * @return Error or NULL on success
 */
error_t *path_normalize_at(
    const char *user_path,
    const char *virtual_root,
    char **out
);

#endif /* DOTTA_PATH_H */
