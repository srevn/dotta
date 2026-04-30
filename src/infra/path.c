/**
 * path.c - User-input path resolution
 *
 * Parses CLI path arguments (storage labels, absolute, tilde, relative)
 * into canonical storage paths. Single chokepoint for input-shape
 * dispatch; topology lookups (mount_classify) and filesystem primitives
 * (fs_expand_tilde, fs_make_absolute, fs_normalize_path) are delegated.
 */

#include "infra/path.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/error.h"
#include "infra/mount.h"
#include "sys/filesystem.h"

/**
 * Boolean predicate: does the input begin with a storage label
 * ("home/", "root/", "custom/")? Centralises the "discardable kind"
 * antipattern in one place — every consumer in this TU asks the same
 * boolean question via mount_kind_extract. After a future
 * base/storage_label vocabulary descent this collapses to
 * `storage_label_is(input)`.
 */
static bool input_looks_like_storage(const char *input) {
    mount_kind_t kind;
    return mount_kind_extract(input, &kind);
}

/**
 * Resolve a relative path to absolute using CWD.
 * Pure string operation — does not check file existence.
 *
 * Handles:
 *   ./foo         -> $CWD/foo (strips leading ./)
 *   ../bar        -> $CWD/../bar (keeps ..)
 *   relative/path -> $CWD/relative/path
 */
static error_t *resolve_relative(const char *relative_path, char **out) {
    CHECK_NULL(relative_path);
    CHECK_NULL(out);

    if (relative_path[0] == '/') {
        *out = strdup(relative_path);
        if (!*out) return ERROR(ERR_MEMORY, "Failed to duplicate path");
        return NULL;
    }

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        return ERROR(
            ERR_FS, "Failed to get current working directory: %s",
            strerror(errno)
        );
    }

    const char *clean = relative_path;
    while (clean[0] == '.' && clean[1] == '/') {
        clean += 2;
        while (*clean == '/') clean++;
    }

    /* Edge case: input was just "./" or "." */
    if (*clean == '\0' || (clean[0] == '.' && clean[1] == '\0')) {
        *out = strdup(cwd);
        if (!*out) return ERROR(ERR_MEMORY, "Failed to duplicate CWD");
        return NULL;
    }

    return fs_path_join(cwd, clean, out);
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
    if (input_looks_like_storage(input)) return false;
    /* Contains slash but not a storage label — treat as relative. */
    if (strchr(input, '/') != NULL) return true;
    /* Single component without slash — ambiguous, not relative.
     * User should use ./X for clarity. */
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
    char *expanded = NULL;
    char *absolute = NULL;
    char *normalized = NULL;

    if (input[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* Case 1: Storage path — validate and arena-copy. */
    if (input_looks_like_storage(input)) {
        err = mount_validate_storage(input);
        if (err) {
            return error_wrap(err, "Invalid storage path '%s'", input);
        }
        const char *copy = arena_strdup(arena, input);
        if (!copy) {
            return ERROR(ERR_MEMORY, "Failed to allocate storage path");
        }
        *out_storage = copy;
        return NULL;
    }

    /* Case 2: Filesystem path (absolute or tilde-prefixed) */
    if (input[0] == '/' || input[0] == '~') {
        if (input[0] == '~') {
            err = fs_expand_tilde(input, &expanded);
            if (err) {
                err = error_wrap(err, "Failed to expand path '%s'", input);
                goto cleanup;
            }
        } else {
            expanded = strdup(input);
            if (!expanded) {
                err = ERROR(ERR_MEMORY, "Failed to allocate path");
                goto cleanup;
            }
        }
        err = fs_make_absolute(expanded, &absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve path '%s'", input);
            goto cleanup;
        }
    }
    /* Case 3: Relative path (./foo, ../bar, or path with /) */
    else if (input_is_relative(input)) {
        err = resolve_relative(input, &absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve relative path '%s'", input);
            goto cleanup;
        }
    }
    /* Case 4: Ambiguous — single-component with no slash and no leading . */
    else {
        err = ERROR(
            ERR_INVALID_ARG,
            "Path '%s' is neither a valid filesystem path nor storage path\n"
            "Hint: Use absolute (/path), tilde (~/.file), relative (./path), or\n"
            "      storage format (home/..., root/..., custom/...)", input
        );
        goto cleanup;
    }

    /* Normalize ., .., and consecutive slashes before classification.
     * Each mount entry carries up to two surface forms (raw and
     * realpath-canonical), so canonical inputs (e.g., from getcwd
     * returning a symlink-resolved CWD on Case 3) classify correctly
     * against raw-stored targets without input canonicalization here. */
    err = fs_normalize_path(absolute, &normalized);
    if (err) {
        err = error_wrap(err, "Failed to normalize path '%s'", input);
        goto cleanup;
    }

    /* mount_classify produces a well-formed storage path by construction:
     * the label is one of three compile-time constants ("home", "root",
     * "custom"), and the tail is the result of relative_after_target
     * which strips a validated mount target from a normalized absolute
     * path. Re-validating the classifier's own output is theater (Rule 6
     * — establish at the boundary, trust downstream). */
    mount_classify_outcome_t outcome;
    err = mount_classify(table, normalized, arena, &outcome, out_storage, NULL);
    if (err) goto cleanup;

    if (outcome == MOUNT_CLASSIFY_ROOT) {
        /* User input matched a classification root exactly ($HOME, /, or
         * a CUSTOM target). No storage-path encoding exists for the root
         * itself — surface to the caller as an explicit error rather
         * than the internal MOUNT_CLASSIFY_ROOT signal. */
        err = ERROR(
            ERR_INVALID_ARG,
            "Path '%s' is a mount root and has no storage representation",
            input
        );
        *out_storage = NULL;
    }

cleanup:
    free(expanded);
    free(absolute);
    free(normalized);

    return err;
}
