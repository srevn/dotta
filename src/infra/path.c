/**
 * path.c - User-input path resolution
 *
 * Two views over flexible CLI path arguments:
 *
 *   path_input_resolve    - filesystem path -> canonical storage path
 *                           (commands that query Git data: show, revert, remove,
 *                           list, filter)
 *
 *   path_input_normalize  - filesystem path -> absolute filesystem path,
 *                           optionally re-rooted under a virtual root (commands
 *                           that walk the filesystem: add)
 *
 * One dispatch: the resolver reads the storage label itself and hands every
 * filesystem spelling (absolute, tilde, relative) to the normalizer with no root,
 * then classifies what comes back. Topology lookups (mount_classify) and filesystem
 * primitives (fs_expand_tilde, fs_make_absolute, fs_normalize_path) are delegated
 * to the layers below.
 */

#include "infra/path.h"

#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/string.h"
#include "infra/mount.h"
#include "sys/filesystem.h"

/**
 * Boundary-aware "is `path` under `dir`" predicate.
 *
 * Pure string check; no syscalls. Matches when `path` equals `dir` exactly, or
 * has a '/' at the dir-length offset — rejects false prefixes like `/home/userX`
 * against `/home/user`. NULL `dir` returns false, gating the cross-product
 * canonical check below when realpath() yielded no distinct second form.
 */
static bool path_under_dir(const char *path, const char *dir) {
    if (!path || !dir) return false;
    size_t dir_len = strlen(dir);
    if (strncmp(path, dir, dir_len) != 0) return false;
    char boundary = path[dir_len];
    return boundary == '/' || boundary == '\0';
}

/**
 * Test whether an input string looks like a relative path.
 *
 * Relative:    ./foo, ../bar, .hidden, paths with / not starting with a label
 * NOT relative: absolute (/...), tilde (~...), storage paths (home/...)
 */
static bool input_is_relative(const char *input) {
    if (!input || input[0] == '\0') return false;
    if (input[0] == '.') return true;
    if (input[0] == '/' || input[0] == '~') return false;
    if (mount_spec_for_path(input)) return false;
    /* Contains slash but not a storage label — treat as relative. */
    if (strchr(input, '/') != NULL) return true;
    /* Single component without slash — ambiguous, not relative. User should use
     * ./X for clarity. */
    return false;
}

error_t *path_input_resolve(
    const mount_table_t *table,
    const char *input,
    arena_t *arena,
    const char **out_storage
) {
    CHECK_NULL(table);
    CHECK_NULL(input);
    CHECK_NULL(arena);
    CHECK_NULL(out_storage);

    *out_storage = NULL;

    error_t *err = NULL;
    char *normalized = NULL;

    if (input[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* Case 1: Storage path — shed the directory spelling, validate, arena-copy.
     * A trailing '/' is the same path spelled as a directory — the UI's own
     * listings print directory claims slash-marked — and the filesystem case
     * below sheds its own inside fs_normalize_path; shedding here keeps the two
     * surface forms resolving alike. */
    if (mount_spec_for_path(input)) {
        size_t len = strlen(input);
        while (len > 0 && input[len - 1] == '/') len--;
        const char *copy = arena_strndup(arena, input, len);
        if (!copy) {
            return ERROR(ERR_MEMORY, "Failed to allocate storage path");
        }
        err = mount_validate_storage(copy);
        if (err) {
            return error_wrap(err, "Invalid storage path '%s'", input);
        }
        *out_storage = copy;
        return NULL;
    }

    /* Case 2: Filesystem path — absolute, tilde, or relative to the working
     * directory — through the normalizer with no root: one arm for the three
     * spellings, with `.`, `..` and the directory spelling folded there. Each
     * mount entry carries up to two surface forms (raw and realpath-canonical),
     * so a canonical input (find's output, a working directory spelled physically)
     * classifies against a raw-stored target without any canonicalization here. */
    if (input[0] == '/' || input[0] == '~' || input_is_relative(input)) {
        err = path_input_normalize(input, NULL, &normalized);
        if (err) return err;
    }
    /* Case 3: Ambiguous — single-component with no slash and no leading . */
    else {
        return ERROR(
            ERR_INVALID_ARG,
            "Path '%s' is neither a valid filesystem path nor storage path\n"
            "Hint: Use absolute (/path), tilde (~/.file), relative (./path), or\n"
            "      storage format (home/..., root/..., custom/...)", input
        );
    }

    /* mount_classify produces a well-formed storage path by construction: the
     * label is one of three compile-time constants ("home", "root", "custom"),
     * and the tail is the result of relative_after_target which strips a validated
     * mount target from a normalized absolute path. Re-validating the classifier's
     * own output is theater. */
    mount_classify_outcome_t outcome;
    err = mount_classify(table, normalized, arena, &outcome, out_storage, NULL);
    if (err) goto cleanup;

    if (outcome == MOUNT_CLASSIFY_ROOT) {
        /* User input matched a classification root exactly ($HOME, /, or a CUSTOM
         * target). No storage-path encoding exists for the root itself — surface
         * to the caller as an explicit error rather than the internal
         * MOUNT_CLASSIFY_ROOT signal. */
        err = ERROR(
            ERR_INVALID_ARG,
            "Path '%s' is a mount root and has no storage representation",
            input
        );
        *out_storage = NULL;
    }

cleanup:
    free(normalized);

    return err;
}

error_t *path_input_normalize(
    const char *input,
    const char *target_root,
    char **out
) {
    CHECK_NULL(input);
    CHECK_NULL(out);

    *out = NULL;

    if (input[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }

    error_t *err = NULL;
    char *expanded = NULL;
    char *composed = NULL;
    char *absolute = NULL;
    char *target_canonical = NULL;
    const char *to_absolute = input;

    bool has_target = target_root && target_root[0] != '\0';
    bool is_tilde = (input[0] == '~');

    /* Pre-resolve target's symlink-canonical form once when re-rooting applies.
     * Best-effort: realpath() failure leaves it NULL and the dual checks degrade
     * to raw-only (correct when the target has no symlinks on its path). When
     * canonical equals raw, drop it so path_under_dir's NULL gate skips the
     * redundant second comparison. */
    if (has_target && !is_tilde) {
        error_t *canon_err =
            fs_canonicalize_path(target_root, &target_canonical);
        if (canon_err) {
            error_free(canon_err);
            target_canonical = NULL;
        }
        if (target_canonical &&
            strcmp(target_canonical, target_root) == 0) {
            free(target_canonical);
            target_canonical = NULL;
        }
    }

    if (is_tilde) {
        /* Tilde always means $HOME — `~/file` is HOME's namespace by design,
         * not subject to target_root re-rooting. Mirrors how the shell resolves
         * tilde before any cd context applies. */
        err = fs_expand_tilde(input, &expanded);
        if (err) goto cleanup;
        to_absolute = expanded;
    } else if (has_target) {
        /* Re-root: prepend target_root unless the input is the shell's — spelled
         * from here (`./x`, `../x`, a dotfile's `.x`), the way the resolver reads
         * a leading '.' (input_is_relative): the file in front of the user,
         * wherever they stand — or already inside the target (raw or canonical
         * surface form). Uniform compose for a bare relative path ("etc/foo")
         * and a host-absolute one ("/etc/foo") — the leading '/' of an absolute
         * input doubles as the join separator, so absolute uses an empty separator
         * and relative an explicit "/".
         *
         *   etc/foo                   -> <target>/etc/foo
         *   /etc/foo                  -> <target>/etc/foo
         *   ./x, ../x, .x             -> the working directory's (not composed)
         *   /<target>/etc/foo         -> /<target>/etc/foo (already inside)
         *   /<target-canonical>/.../X -> /<target-canonical>/.../X
         *                                (canonical alias inside) */
        if (input[0] != '.' &&
            !path_under_dir(input, target_root) &&
            !path_under_dir(input, target_canonical)) {
            const char *separator = (input[0] == '/') ? "" : "/";
            composed = str_format(
                "%s%s%s", target_root, separator, input
            );
            if (!composed) {
                err = ERROR(
                    ERR_MEMORY,
                    "Failed to prepend target root to path"
                );
                goto cleanup;
            }
            to_absolute = composed;
        }
    }

    err = fs_make_absolute(to_absolute, &absolute);
    if (err) goto cleanup;

    err = fs_normalize_path(absolute, out);
    if (err) goto cleanup;

    /* Post-condition: when target_root applies, the normalized output must remain
     * inside it. Lexical `..` resolution can move an already-inside path back
     * outside (e.g., `/jail/../etc/secret` -> `/etc/secret`), and a path spelled
     * from here resolves wherever the user stands — `./x` typed outside the target,
     * or `../x` walked out of it. One uniform check catches every escape — no
     * per-shape pre-validation needed in the compose step. Tilde inputs are exempt:
     * HOME is its own namespace, never required to live inside target_root. */
    if (has_target && !is_tilde) {
        if (!path_under_dir(*out, target_root) &&
            !path_under_dir(*out, target_canonical)) {
            char *escaped = *out;
            *out = NULL;
            err = ERROR(
                ERR_INVALID_ARG,
                "Path '%s' resolves outside target root '%s'.\n"
                "Path traversal (..) cannot escape the target.",
                escaped, target_root
            );
            free(escaped);
        }
    }

cleanup:
    free(expanded);
    free(composed);
    free(absolute);
    free(target_canonical);

    return err;
}
