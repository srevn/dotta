/**
 * path.c - The key a CLI path argument names
 *
 * Two readings of a flexible CLI path argument:
 *
 *   path_input_resolve    - the key the input names: a location (a filesystem
 *                           shape, normalized and located) or a storage path
 *                           (validated, as typed) — the pathspec, show and list
 *                           without a profile, path_input_classify
 *
 *   path_input_normalize  - filesystem path -> absolute filesystem path
 *                           (the commands that walk, bind or test a spelling:
 *                            add, the binders' --target, ignore --test, the
 *                            completion)
 *
 * and the former resolver, path_input_classify — a location named with no asker
 * — kept for the query verbs until a claim is found where it stands.
 *
 * One dispatch: the resolver reads the storage label itself and hands every
 * filesystem spelling (absolute, tilde, relative) to the normalizer, then asks
 * the table where the spelling stands. The topology (mount_spec_for_path,
 * mount_validate_storage, mount_locate, mount_classify) and the filesystem
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
 * Does the input spell a filesystem path?
 *
 * Absolute (`/x`), tilde (`~/x`), or relative to the working directory — `./x`,
 * `../x`, a dotfile's `.x`, `a/b`. A bare single component is neither shape and
 * is refused by the one caller: `./X` says which was meant, and the resolver's
 * callers may read a bare word as a profile.
 *
 * Asked once the storage label is ruled out (path_input_resolve's first arm has
 * returned for every `home/`, `root/` and `custom/` spelling), so no label test
 * is needed here.
 */
static bool input_is_filesystem_shape(const char *input) {
    if (input[0] == '/' || input[0] == '~' || input[0] == '.') return true;
    return strchr(input, '/') != NULL;
}

error_t *path_input_resolve(
    const mount_table_t *table, const char *input, arena_t *arena, path_input_t *out
) {
    CHECK_NULL(table);
    CHECK_NULL(input);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = (path_input_t){ 0 };

    if (input[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* A storage shape — shed the directory spelling, validate, arena-copy. A
     * trailing '/' is the same path spelled as a directory — the UI's own listings
     * print directory claims slash-marked — and the filesystem arm below sheds
     * its own inside fs_normalize_path; shedding here keeps the two surface forms
     * resolving alike. */
    if (mount_spec_for_path(input)) {
        size_t len = strlen(input);
        while (len > 0 && input[len - 1] == '/') len--;
        const char *storage = arena_strndup(arena, input, len);
        if (!storage) {
            return ERROR(ERR_MEMORY, "Failed to allocate storage path");
        }
        error_t *err = mount_validate_storage(storage);
        if (err) {
            return error_wrap(err, "Invalid storage path '%s'", input);
        }
        out->key = PATH_KEY_STORAGE;
        out->storage_path = storage;
        return NULL;
    }

    /* A bare name — a single component with no slash and no leading '.' — is
     * neither shape: the resolver's callers may read it as a profile. */
    if (!input_is_filesystem_shape(input)) {
        return ERROR(
            ERR_INVALID_ARG,
            "Path '%s' is neither a valid filesystem path nor storage path\n"
            "Hint: Use absolute (/path), tilde (~/.file), relative (./path), or\n"
            "      storage format (home/..., root/..., custom/...)", input
        );
    }

    /* A filesystem shape — absolute, tilde, or relative to the working directory
     * — through the normalizer (one arm for the three spellings, with `.`, `..`
     * and the directory spelling folded there), then located: where the spelling
     * stands, physical as far as the table knows its roots, so the answer keys
     * with the view's rows by strcmp whichever spelling was typed. */
    char *normalized = NULL;
    error_t *err = path_input_normalize(input, &normalized);
    if (err) return err;

    const char *location = NULL;
    err = mount_locate(table, normalized, arena, &location);
    free(normalized);
    if (err) return err;

    out->key = PATH_KEY_LOCATION;
    out->location = location;

    return NULL;
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

error_t *path_input_classify(
    const mount_table_t *table, const char *input, arena_t *arena,
    const char **out_storage
) {
    CHECK_NULL(table);
    CHECK_NULL(input);
    CHECK_NULL(arena);
    CHECK_NULL(out_storage);

    *out_storage = NULL;

    path_input_t arg;
    error_t *err = path_input_resolve(table, input, arena, &arg);
    if (err) return err;

    if (arg.key == PATH_KEY_STORAGE) {
        *out_storage = arg.storage_path;
        return NULL;
    }

    /* The machine-wide name: mount_classify produces a well-formed storage path
     * by construction — the label is one of three compile-time constants, and
     * the tail is a located path past a validated target — so its output is not
     * re-validated. A located input is its own location, so the classify's own
     * locate is a no-op over it. */
    mount_classify_outcome_t outcome;
    err = mount_classify(table, arg.location, arena, &outcome, out_storage, NULL);
    if (err) return err;

    if (outcome == MOUNT_CLASSIFY_ROOT) {
        /* The input is a classification root itself ($HOME, /, or a --target).
         * No storage-path encoding exists for the root; the verbs that ask this
         * function take a claim, and a root holds none. */
        return ERROR(
            ERR_INVALID_ARG,
            "Path '%s' is a mount root and has no storage representation", input
        );
    }

    return NULL;
}
