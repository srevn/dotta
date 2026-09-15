/**
 * path.c - The key a CLI path argument names
 *
 * Two readings of a flexible CLI path argument, and the one refusal a reading
 * earns:
 *
 *   path_input_resolve      - the key the input names: a location (a filesystem
 *                             shape, normalized), a storage path (validated, as
 *                             typed) or a label alone (the one address a root
 *                             has) — the pathspec, and every verb that takes a
 *                             path from the command line
 *
 *   path_input_normalize    - filesystem path -> absolute filesystem path, a
 *                             relative one's working directory spelled under
 *                             HOME (the commands that walk, bind or test a
 *                             spelling: add, the binders' --target, ignore --test,
 *                             the completion)
 *
 *   path_input_refuse_label - the sentence the verbs that act on one path give
 *                             a label, in the noun the vocabulary gives the root
 *                             it names
 *
 * One dispatch: the resolver reads the storage label itself and hands every
 * filesystem spelling (absolute, tilde, relative) to the normalizer, whose answer
 * is the key. The storage-label vocabulary (mount_spec_for_path,
 * mount_spec_for_label, mount_validate_storage, mount_root_describe over a spec
 * those answered), the filesystem primitives (fs_expand_tilde,
 * fs_working_directory, fs_path_join, fs_normalize_path) and HOME's two spellings
 * (sys/identity) are delegated to the layers below. The table of roots is not
 * among them: no root's spelling is read here (infra/path.h).
 */

#include "infra/path.h"

#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/string.h"
#include "infra/mount.h"
#include "sys/filesystem.h"
#include "sys/identity.h"

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
    const char *input, arena_t *arena, path_input_t *out
) {
    CHECK_NULL(input);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = (path_input_t){ 0 };

    if (input[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* A storage shape — shed the directory spelling, then read what is left of
     * it. A trailing '/' is the same path spelled as a directory — the UI's own
     * listings print directory claims slash-marked — and the filesystem arm below
     * sheds its own inside fs_normalize_path; shedding here keeps the two surface
     * forms resolving alike. */
    const mount_spec_t *spec = mount_spec_for_path(input);
    if (spec) {
        size_t len = strlen(input);
        while (len > 0 && input[len - 1] == '/') len--;

        /* The label and nothing after it: the root of a namespace, which is no
         * storage path — mount_validate_storage refuses one — and no location
         * either, since a label is the same word on every machine while a location
         * is this one's. The prefix already matched and no label ends in a
         * separator, so what survives the shed is the whole test; and the answer
         * is the spec's own static string, which outlives every arena and needs
         * no copy. */
        if (len == strlen(spec->label)) {
            out->key = PATH_KEY_LABEL;
            out->label = spec->label;
            return NULL;
        }

        /* A name beneath it. The two refusals a label alone would have earned
         * here are unreachable from this arm now: the prefix matched, so the
         * byte at the label's own length is the '/' the decode wants, and the
         * shed above took every trailing one. */
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
            "Hint: Use absolute (/path), tilde (~/.file), relative (./path),\n"
            "      storage format (home/..., root/..., custom/...), or a label\n"
            "      alone (home/, root/, custom/)", input
        );
    }

    /* A filesystem shape — absolute, tilde, or relative to the working directory
     * — through the normalizer (one arm for the three spellings, with `.`, `..`
     * and the directory spelling folded there), and its answer is the key. The
     * copy is the resolver's because the answer outlives the call and the
     * normalizer's is malloc's by contract (path.h). */
    char *normalized = NULL;
    error_t *err = path_input_normalize(input, &normalized);
    if (err) return err;

    const char *location = arena_strdup(arena, normalized);
    free(normalized);
    if (!location) {
        return ERROR(ERR_MEMORY, "Failed to allocate the location");
    }

    out->key = PATH_KEY_LOCATION;
    out->location = location;

    return NULL;
}

error_t *path_input_refuse_label(const char *label, const char *profile) {
    CHECK_NULL(label);

    char buf[MOUNT_NOUN_MAX];

    return ERROR(
        ERR_INVALID_ARG, "'%s/' is %s: name what is inside it", label,
        mount_root_describe(mount_spec_for_label(label), profile, buf, sizeof(buf))
    );
}

/**
 * The working directory a relative argument is read from: the shell's spelling
 * (fs_working_directory), spelled back under HOME where it lies beneath HOME's
 * directory under the kernel's spelling.
 *
 * The shell spells the working directory the way the user reached it and the
 * kernel spells it physically; a key under HOME is HOME's spelling as the identity
 * gives it (infra/mount.h), and a relative argument spelled no directory at all.
 * So the directory, never the argument's tail, is read back: getcwd's answer
 * where the shell set no $PWD (a sudo that dropped it, a cron, an env -i) or a
 * stale one, and a $PWD the shell wrote physically (`cd -P`), both lie beneath
 * HOME's physical and both become HOME's spelling plus the tail. One already
 * under HOME stands. No syscall: the identity read HOME's physical once. A
 * directory reached through a link no root names keeps the kernel's spelling of
 * that link's target, as a typed absolute path would.
 *
 * HOME has two spellings, or it has one: the kernel's is the rule's, or it is
 * the filesystem root (a HOME linking to `/` would spell the machine under it),
 * or it encloses the rule's — a HOME reached through a link to its own ancestor,
 * where the substitution would nest the tail beneath itself; the other direction
 * is a link to its own descendant, which the kernel refuses as a loop. In each,
 * the directory stands as the shell spelled it.
 */
static error_t *working_directory(char **out) {
    char *cwd = NULL;
    RETURN_IF_ERROR(fs_working_directory(&cwd));
    *out = cwd;

    const identity_t *id = identity();
    const char *home = id->home, *physical = id->home_physical;
    if (!physical) return NULL;

    size_t len = strlen(physical);
    if (strcmp(home, physical) == 0 || physical[1] == '\0' ||
        str_path_beneath(home, physical, len)) {
        return NULL;
    }
    if (strcmp(cwd, physical) != 0 && !str_path_beneath(cwd, physical, len)) {
        return NULL;
    }

    /* The tail carries its own separator, and HOME's own directory has none. */
    *out = str_format("%s%s", home, cwd + len);
    free(cwd);
    if (!*out) {
        return ERROR(
            ERR_MEMORY, "Failed to spell the working directory under home"
        );
    }

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
     * duplicated verbatim, fs_expand_tilde's contract), a path still relative
     * joins the working directory, and `.`, `..` and doubled slashes fold out
     * lexically. */
    char *expanded = NULL;
    error_t *err = fs_expand_tilde(input, &expanded);
    if (err) return err;

    /* An absolute spelling — typed, or the tilde's — is the user's own and stands.
     * A relative one joins the working directory, spelled for a key before the
     * join so that the tail stays the user's own too. */
    char *absolute = NULL;
    if (expanded[0] == '/') {
        absolute = expanded;
    } else {
        char *cwd = NULL;
        err = working_directory(&cwd);
        if (!err) err = fs_path_join(cwd, expanded, &absolute);
        free(cwd);
        free(expanded);
        if (err) return err;
    }

    err = fs_normalize_path(absolute, out);
    free(absolute);

    return err;
}
