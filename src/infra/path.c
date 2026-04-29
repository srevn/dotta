/**
 * path.c - Generic path arithmetic
 *
 * Pure path string utilities — no storage labels, no mount table, no
 * arena. SECURITY: tilde expansion and ancestor checks are written to
 * resist path traversal under user-controlled input.
 */

#include "infra/path.h"

#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/error.h"
#include "base/string.h"
#include "sys/filesystem.h"

error_t *path_get_home(char **out) {
    CHECK_NULL(out);

    /* Try $HOME environment variable first */
    const char *home = getenv("HOME");
    if (home && home[0] != '\0') {
        *out = strdup(home);
        if (!*out) {
            return ERROR(ERR_MEMORY, "Failed to allocate HOME path");
        }
        return NULL;
    }

    /* Fall back to passwd database */
    struct passwd *pw = getpwuid(getuid());
    if (!pw || !pw->pw_dir) {
        return ERROR(ERR_FS, "Unable to determine HOME directory");
    }

    *out = strdup(pw->pw_dir);
    if (!*out) {
        return ERROR(ERR_MEMORY, "Failed to allocate HOME path");
    }
    return NULL;
}

error_t *path_expand_home(const char *path, char **out) {
    CHECK_NULL(path);
    CHECK_NULL(out);

    if (path[0] != '~') {
        *out = strdup(path);
        if (!*out) {
            return ERROR(ERR_MEMORY, "Failed to duplicate path");
        }
        return NULL;
    }

    char *home = NULL;
    error_t *err = path_get_home(&home);
    if (err) return err;

    const char *rest = path + 1;  /* skip ~ */
    if (rest[0] == '/' || rest[0] == '\0') {
        err = fs_path_join(home, rest[0] == '/' ? rest + 1 : "", out);
    } else {
        free(home);
        return ERROR(
            ERR_INVALID_ARG, "~user syntax not supported (got '%s')",
            path
        );
    }
    free(home);
    return err;
}

bool path_is_under(
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

error_t *path_normalize_at(
    const char *user_path,
    const char *virtual_root,
    char **out
) {
    CHECK_NULL(user_path);
    CHECK_NULL(out);

    error_t *err = NULL;
    char *expanded = NULL;
    char *joined = NULL;
    const char *path_to_make_absolute = user_path;

    /* Step 1: Expand tilde (canonical, bypasses virtual_root). */
    if (user_path[0] == '~') {
        err = path_expand_home(user_path, &expanded);
        if (err) return err;
        path_to_make_absolute = expanded;
    }
    /* Step 2: Resolve paths within virtual_root context. Tilde paths
     * skip this — ~/file always means $HOME/file regardless of root. */
    else if (virtual_root && virtual_root[0] != '\0') {
        const char *path = path_to_make_absolute;

        if (path[0] != '/') {
            /* SECURITY: Reject '..' as a path component (not as substring).
             * Prevents virtual_root escape: ../foo + /jail -> /jail/../foo -> /foo */
            for (const char *p = path; *p; p++) {
                if ((p == path || *(p - 1) == '/') && p[0] == '.' && p[1] == '.' &&
                    (p[2] == '/' || p[2] == '\0')) {
                    free(expanded);
                    return ERROR(
                        ERR_INVALID_ARG,
                        "Path traversal (..) not allowed in relative paths with --target.\n"
                        "Use absolute paths if you need to reference files outside the virtual root."
                    );
                }
            }

            err = fs_path_join(virtual_root, path, &joined);
            if (err) {
                free(expanded);
                return error_wrap(err, "Failed to join virtual root with relative path");
            }
            path_to_make_absolute = joined;
        } else {
            /* Absolute path: prepend virtual_root unless already under it. */
            size_t root_len = strlen(virtual_root);
            bool already_under =
                strncmp(path, virtual_root, root_len) == 0 &&
                (path[root_len] == '/' || path[root_len] == '\0');

            if (!already_under) {
                joined = str_format("%s%s", virtual_root, path);
                if (!joined) {
                    free(expanded);
                    return ERROR(ERR_MEMORY, "Failed to prepend virtual root to path");
                }
                path_to_make_absolute = joined;
            }
            /* Otherwise already under virtual_root, pass through unchanged. */
        }
    }

    /* Step 3: Make absolute (handles absolute pass-through and CWD joining). */
    char *absolute = NULL;
    err = fs_make_absolute(path_to_make_absolute, &absolute);
    if (!err) {
        /* Step 4: Normalize (resolve ., .., consecutive slashes). */
        err = fs_normalize_path(absolute, out);
        free(absolute);
    }

    free(expanded);
    free(joined);
    return err;
}
