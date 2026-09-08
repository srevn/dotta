/**
 * path.c - User-input path resolution
 *
 * Two views over flexible CLI path arguments:
 *
 *   path_input_resolve    - filesystem path -> canonical storage path
 *                           (commands that query Git data: show, revert, remove,
 *                           list, filter)
 *
 *   path_input_normalize  - filesystem path -> absolute filesystem path
 *                           (the commands that walk, bind or test a spelling:
 *                            add, the binders' --target, ignore --test, the
 *                            completion)
 *
 * One dispatch: the resolver reads the storage label itself and hands every
 * filesystem spelling (absolute, tilde, relative) to the normalizer, then
 * classifies what comes back. Topology lookups (mount_classify) and filesystem
 * primitives (fs_expand_tilde, fs_make_absolute, fs_normalize_path) are delegated
 * to the layers below.
 */

#include "infra/path.h"

#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "infra/mount.h"
#include "sys/filesystem.h"

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
     * directory — through the normalizer: one arm for the three spellings, with
     * `.`, `..` and the directory spelling folded there. Each mount entry carries
     * up to two surface forms (raw and realpath-canonical), so a canonical input
     * (find's output, a working directory spelled physically) classifies against
     * a raw-stored target without any canonicalization here. */
    if (input[0] == '/' || input[0] == '~' || input_is_relative(input)) {
        err = path_input_normalize(input, &normalized);
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

error_t *path_input_normalize(const char *input, char **out) {
    CHECK_NULL(input);
    CHECK_NULL(out);

    *out = NULL;

    if (input[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* Three spellings, one pipeline: the tilde expands (a path without one is
     * duplicated verbatim, fs_expand_tilde's contract), the result joins the
     * working directory when it is still relative, and `.`, `..` and doubled
     * slashes fold out lexically. */
    char *expanded = NULL;
    error_t *err = fs_expand_tilde(input, &expanded);
    if (err) return err;

    char *absolute = NULL;
    err = fs_make_absolute(expanded, &absolute);
    free(expanded);
    if (err) return err;

    err = fs_normalize_path(absolute, out);
    free(absolute);

    return err;
}
