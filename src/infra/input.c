/**
 * input.c - The readings of a CLI argument: the refspec it spells, the key it names
 *
 * The readings of a flexible CLI argument:
 *
 *   input_resolve           - the key the input names: a filesystem path (a
 *                             filesystem shape, normalized) or a storage path
 *                             (validated, as typed) — the pathspec, and every
 *                             verb that takes a path from the command line
 *
 *   input_filesystem_path   - that key alone, in the arena: filesystem path ->
 *                             absolute filesystem path, a relative one's working
 *                             directory spelled under HOME, for a caller whose
 *                             grammar has no storage arm to dispatch to (add, a
 *                             target, ignore --test, the completion, a filesystem
 *                             rule's anchor)
 *
 *   input_target            - that key, held to a target's rules (infra/mount.h
 *                             mount_validate_target), for the three binders:
 *                             the --target flags and the editor's save
 *
 *   input_refspec           - a positional of the refspec family, read once: its
 *                             commit, then its profile where the first ':' sets
 *                             one apart, then its path — every verb that reads
 *                             a refspec, and the scope's profile:path arguments
 *
 *   input_announces_path    - the grammars' question, asked of a positional whose
 *                             slot is still undecided: a path, or a name (list,
 *                             diff, apply, update)
 *
 *   input_announces_profile
 *                           - the refspec's, asked of the same positional: a
 *                             profile set apart at its first ':', or a path holding
 *                             one (the refspec's reading, apply's classifier)
 *
 *   input_announces_rule    - the filter's question: a rule, or a path named
 *                             exactly (the pathspec's gate, and the pattern a
 *                             positional announces above)
 *
 * One dispatch: the resolver reads the storage grammar itself and hands every
 * filesystem spelling (absolute, tilde, relative) to the argument's reading,
 * whose answer is the key. The grammar of a name (infra/label.h: label_prefixes,
 * label_validate_storage), the filesystem's two readings (fs_expand_tilde,
 * fs_working_directory), the grammar of a path's spelling (base/path.h: path_join,
 * path_fold), HOME's two spellings (sys/identity) and the commit a refspec carries
 * (base/refspec.h refspec_commit) are delegated to the layers below. The table
 * of roots is not among them: no root's spelling is read here and no root's noun,
 * so this file names no place (infra/input.h). A target's rules are mount's (the
 * place a binding means), asked of the argument's spelling and of nothing the
 * table holds.
 */

#include "infra/input.h"

#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/path.h"
#include "base/refspec.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "sys/filesystem.h"
#include "sys/identity.h"

#define PATH_WILDCARDS "*?["   /* a rule's alphabet: the filter's wildcards */

bool input_announces_path(const char *input) {
    if (!input || input[0] == '\0') return false;

    /* A place, in the first byte; a name, under a label; or a pattern that selects
     * either. A separator alone announces nothing — that is a profile's own shape,
     * and the reason this is not the resolver's reading of the same string
     * (infra/input.h). */
    return input[0] == '/' || input[0] == '~' || input[0] == '.' ||
           label_prefixes(input) || input_announces_rule(input);
}

bool input_announces_profile(const char *input) {
    const char *colon = input ? strchr(input, ':') : NULL;
    if (colon == NULL) return false;

    /* input_announces_path's tests, a rule's bounded at the ':' — a wildcard
     * after it is the profile's own pattern — and the label's asked of the whole
     * token, which a label's word alone before the ':' does not open. A ':' opening
     * the token passes every one: the separator, with no name before it */
    return !(input[0] == '/' || input[0] == '~' || input[0] == '.' || input[0] == '!' ||
           label_prefixes(input) || strcspn(input, PATH_WILDCARDS) < (size_t) (colon - input));
}

bool input_announces_rule(const char *input) {
    CHECK_NULL(input);

    return input[0] == '!' || strpbrk(input, PATH_WILDCARDS) != NULL;
}

error_t input_refspec(const char *input, arena_t *arena, input_refspec_t *out) {
    CHECK_NULL(input);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = (input_refspec_t){ 0 };

    /* The commit first, and the word it leaves: the arena's own copy, so the
     * ':' that sets a profile apart ends the profile in place */
    const char *commit = refspec_commit(input);
    char *word = arena_strndup(
        arena, input, commit ? (size_t) (commit - 1 - input) : strlen(input)
    );

    /* Then the profile, at the word's first ':' where no path is announced before
     * it — asked of the word and never the token, whose commit may hold a ':' —
     * and the path after it, or the word whole */
    char *colon = input_announces_profile(word) ? strchr(word, ':') : NULL;
    if (colon) *colon = '\0';
    const char *path = colon ? colon + 1 : word;

    /* A side the ':' or the commit sets apart and leaves empty, the path's first,
     * so a token that names neither — `:`, `:@HEAD` — names no file. A word with
     * no profile's ':' and no commit is its caller's, the empty one among them. */
    if (path[0] == '\0' && (colon || commit)) {
        return error_create(ERR_INVALID_ARG, "'%s' names no file", input);
    }
    if (colon == word) {
        return error_create(ERR_INVALID_ARG, "'%s' names no profile before its ':'", input);
    }

    *out = (input_refspec_t){
        .profile = colon ? word : NULL,
        .path = path,
        .commit = commit ? arena_strdup(arena, commit) : NULL,
    };
    return NULL;
}

error_t input_resolve(const char *input, arena_t *arena, input_path_t *out) {
    CHECK_NULL(input);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = (input_path_t){ 0 };

    /* The same sentence the argument's reading gives, said here because the storage
     * arm below never reaches it at all. */
    if (input[0] == '\0') {
        return error_create(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* A storage shape: the name as typed with its directory spelling shed — every
     * trailing separator, and the shed cannot reach past the word, which ends
     * in none. What is left is a name beneath the label or the word alone, the
     * namespace's own directory: one key for both, validated as every key is,
     * the rule taking the word and refusing the marker (infra/label.h
     * label_validate_storage). A trailing '/' is the same path spelled as a
     * directory — the UI's own listings print directory claims slash-marked —
     * and the filesystem arm below sheds its own inside the fold; shedding here
     * keeps the two surface forms resolving alike. */
    if (label_prefixes(input)) {
        size_t len = strlen(input);
        while (input[len - 1] == '/') len--;

        char *storage = arena_strndup(arena, input, len);
        error_t err = label_validate_storage(storage);
        if (err) return err;
        out->key = INPUT_KEY_STORAGE;
        out->storage_path = storage;
        return NULL;
    }

    /* A word standing alone — no separator, and no first byte announcing a place
     * (`/x`, `~/x`, `./x`, `../x`, a dotfile's `.x`) — is neither shape: a caller's
     * path slot may hold a profile and this function cannot see whose does, so
     * `./X` is what says a path was meant. One refusal for every verb, and the
     * only one a word standing alone earns anywhere — the three words are names
     * and the arm above reads them. A verb that reads a bare word as a path asks
     * the argument's reading instead (add, the binders, `ignore --test`, the
     * completion). */
    if (input[0] != '/' && input[0] != '~' && input[0] != '.' &&
        !strchr(input, '/')) {
        return error_create(
            ERR_INVALID_ARG, "Path '%s' is neither a filesystem path (/x, ~/x, ./x) nor "
            "a storage path (home/..., root/..., custom/...)", input
        );
    }

    /* A filesystem shape — absolute, tilde, or relative to the working directory
     * — read as the path it names: one arm for the three spellings, with `.`,
     * `..` and the directory spelling folded inside it. The key is written before
     * the answer because the zeroed key is already this one: a read that fails
     * leaves a NULL beneath it, which is what this function promises after an
     * error. */
    out->key = INPUT_KEY_FILESYSTEM;

    return input_filesystem_path(input, arena, &out->filesystem_path);
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
 * HOME has two spellings, or it has one: the kernel's is the rule's, or it encloses
 * the rule's — the filesystem root, where a HOME linking to `/` would spell the
 * machine under it, or a HOME reached through a link to its own ancestor, where
 * the substitution would nest the tail beneath itself; the other direction is a
 * link to its own descendant, which the kernel refuses as a loop. Both are one
 * test, the rule's spelling under the kernel's (base/path.h path_under). In each,
 * the directory stands as the shell spelled it.
 */
static error_t input_working_directory(arena_t *arena, const char **out) {
    const char *cwd = NULL;
    error_t err = fs_working_directory(arena, &cwd);
    if (err) return err;
    *out = cwd;

    const identity_t *id = identity();
    const char *home = id->home, *physical = id->home_physical;
    if (!physical) return NULL;

    size_t len = strlen(physical);
    if (path_under(home, physical, len)) {
        return NULL;
    }
    if (!path_under(cwd, physical, len)) {
        return NULL;
    }

    /* The tail carries its own separator, and HOME's own directory has none. */
    *out = arena_str_format(arena, "%s%s", home, cwd + len);

    return NULL;
}

error_t input_filesystem_path(const char *input, arena_t *arena, const char **out) {
    CHECK_NULL(input);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    if (input[0] == '\0') {
        return error_create(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* Three spellings, one pipeline, each step's answer the arena's: the tilde
     * expands (a path without one is copied verbatim, fs_expand_tilde's contract),
     * a path still relative joins the working directory, and `.`, `..` and doubled
     * slashes fold out lexically. */
    const char *path = NULL;
    error_t err = fs_expand_tilde(input, arena, &path);
    if (err) return err;

    /* An absolute spelling — typed, or the tilde's — is the user's own and stands.
     * A relative one joins the working directory, spelled for a key before the
     * join so that the tail stays the user's own too. */
    if (path[0] != '/') {
        const char *cwd = NULL;
        err = input_working_directory(arena, &cwd);
        if (err) return err;
        path = path_join(arena, cwd, path);
    }

    *out = path_fold(arena, path, NULL);

    return NULL;
}

error_t input_target(const char *input, arena_t *arena, const char **out) {
    CHECK_NULL(input);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    /* The spelling the row stores, then the place it names: each refusal is its
     * step's own, in its own words */
    const char *target = NULL;
    error_t err = input_filesystem_path(input, arena, &target);
    if (!err) err = mount_validate_target(target);
    if (err) return err;

    *out = target;
    return NULL;
}
