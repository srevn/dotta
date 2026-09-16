/**
 * path.c - The key a CLI path argument names
 *
 * The readings of a flexible CLI path argument, and the one refusal a reading
 * earns:
 *
 *   path_input_resolve      - the key the input names: a location (a filesystem
 *                             shape, normalized), a storage path (validated, as
 *                             typed) or a label alone (the one address a root
 *                             has) — the pathspec, and every verb that takes a
 *                             path from the command line
 *
 *   path_input_locate       - the location alone, in the arena: the same reading,
 *                             for a caller whose grammar has no storage arm to
 *                             dispatch to (add, the binders' --target, ignore
 *                             --test, the completion, a glob's anchor)
 *
 *   path_input_normalize    - filesystem path -> absolute filesystem path, a
 *                             relative one's working directory spelled under
 *                             HOME; malloc's, for the one reader that replaces
 *                             and frees what it holds (the interactive save)
 *
 *   path_input_refuse_label - the sentence the verbs that act on one path give
 *                             a label, in the noun the vocabulary gives the root
 *                             it names
 *
 *   path_input_is_bare      - the one shape the resolver has no reading for, for
 *                             the caller whose own grammar has one
 *
 *   path_input_announces_path
 *                           - the grammars' question, asked of a positional whose
 *                             slot is still undecided: a path, or a name (list,
 *                             diff, apply, update)
 *
 * One dispatch: the resolver reads the storage label itself and hands every
 * filesystem spelling (absolute, tilde, relative) to the location door, whose
 * answer is the key. The grammar of a name (infra/label.h: label_split,
 * label_words, label_validate_storage), the noun a screen calls a root by over
 * a label the grammar answered (infra/mount.h mount_root_describe), the filesystem
 * primitives (fs_expand_tilde, fs_working_directory, fs_path_join,
 * fs_normalize_path) and HOME's two spellings (sys/identity) are delegated to
 * the layers below. The table of roots is not among them: no root's spelling is
 * read here (infra/path.h).
 */

#include "infra/path.h"

#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/string.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "sys/filesystem.h"
#include "sys/identity.h"

bool path_input_announces_path(const char *input) {
    if (!input || input[0] == '\0') return false;

    /* A place, in the first byte; a name, under a label; or a pattern that selects
     * either. A separator alone announces nothing — that is a profile's own shape,
     * and the reason this is not the resolver's reading of the same string
     * (infra/path.h). */
    return input[0] == '/' || input[0] == '~' || input[0] == '.' ||
           label_prefixes(input) || strpbrk(input, "*?[") != NULL;
}

bool path_input_is_bare(const char *input) {
    if (!input || input[0] == '\0') return false;

    /* A filesystem place announces itself in its first byte — absolute (`/x`),
     * tilde (`~/x`), relative to the working directory (`./x`, `../x`, a dotfile's
     * `.x`) — or in a separator anywhere (`a/b`, and every name under a label).
     * What announces neither stands alone. */
    if (input[0] == '/' || input[0] == '~' || input[0] == '.') return false;
    return strchr(input, '/') == NULL;
}

error_t *path_input_resolve(
    const char *input, arena_t *arena, path_input_t *out
) {
    CHECK_NULL(input);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = (path_input_t){ 0 };

    /* The same sentence the normalizer gives, said here because the storage arm
     * below never reaches the normalizer at all. */
    if (input[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* A storage shape — read at its label, then the directory spelling shed from
     * what is left. A trailing '/' is the same path spelled as a directory —
     * the UI's own listings print directory claims slash-marked — and the
     * filesystem arm below sheds its own inside fs_normalize_path; shedding here
     * keeps the two surface forms resolving alike. The grammar folds nothing,
     * so the shed is this function's, and it walks the tail alone: every trailing
     * separator is in it, the label's own bytes are not. */
    label_split_t split = label_split(input);
    if (split.tail) {
        size_t tail_len = strlen(split.tail);
        while (tail_len > 0 && split.tail[tail_len - 1] == '/') tail_len--;

        /* Nothing stands past the label once the shed is done: the root of a
         * namespace, which is no storage path — label_validate_storage refuses
         * one — and no location either, since a label is the same word on every
         * machine while a location is this one's. The answer is the label itself,
         * a value nothing has to hold or copy. */
        if (tail_len == 0) {
            out->key = PATH_KEY_LABEL;
            out->label = split.label;
            return NULL;
        }

        /* A name beneath it, the shed one the split already measured out. The
         * two refusals a label alone would have earned here are unreachable from
         * this arm now: the prefix matched, so the byte at the label's own length
         * is the '/' the split wants, and the shed above took every trailing
         * one. */
        const char *storage = arena_strndup(
            arena, input, (size_t) (split.tail - input) + tail_len
        );
        if (!storage) {
            return ERROR(ERR_MEMORY, "Failed to allocate storage path");
        }
        error_t *err = label_validate_storage(storage);
        if (err) {
            return error_wrap(err, "Invalid storage path '%s'", input);
        }
        out->key = PATH_KEY_STORAGE;
        out->storage_path = storage;
        return NULL;
    }

    /* A word standing alone is neither shape: a caller's path slot may hold a
     * profile and this function cannot see whose does, so `./X` is what says a
     * path was meant. The caller whose slot cannot asks the same question first
     * and puts its own reading here (infra/path.h path_input_is_bare). */
    if (path_input_is_bare(input)) {
        return ERROR(
            ERR_INVALID_ARG,
            "Path '%s' is neither a valid filesystem path nor storage path\n"
            "Hint: Use absolute (/path), tilde (~/.file), relative (./path),\n"
            "      storage format (home/..., root/..., custom/...), or a label\n"
            "      alone (home/, root/, custom/)", input
        );
    }

    /* A filesystem shape — absolute, tilde, or relative to the working directory
     * — read as the location it names: one arm for the three spellings, with
     * `.`, `..` and the directory spelling folded inside it. The key is written
     * before the answer because the zeroed key is already this one: a read that
     * fails leaves a NULL beneath it, which is what this function promises after
     * an error. */
    out->key = PATH_KEY_LOCATION;

    return path_input_locate(input, arena, &out->location);
}

error_t *path_input_locate(const char *input, arena_t *arena, const char **out) {
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    /* `input` is the normalizer's to refuse: a NULL one and an empty one earn
     * the same sentence a frame deeper, so a guard here would spell it twice. */
    char *normalized = NULL;
    RETURN_IF_ERROR(path_input_normalize(input, &normalized));

    *out = arena_strdup(arena, normalized);
    free(normalized);

    return *out ? NULL : ERROR(ERR_MEMORY, "Failed to allocate the location");
}

error_t *path_input_refuse_label(label_t root, const char *profile) {
    char buf[MOUNT_NOUN_MAX];

    return ERROR(
        ERR_INVALID_ARG, "'%s/' is %s: name what is inside it",
        label_words[root], mount_root_describe(root, profile, buf, sizeof(buf))
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
