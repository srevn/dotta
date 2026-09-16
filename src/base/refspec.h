/**
 * refspec.h - The refspec syntax, and the shape of a commit in it
 *
 * Parsing for `[profile:]<path>[@commit]`, for the commands that name a file
 * with an optional profile and commit; and the lexical rule that decides where
 * the '@' splits — what a commit reference looks like, with no repository in
 * hand — which those same commands ask of a whole positional where a slot of
 * theirs could hold one. Git's revision spellings are read here and in no lower
 * module; resolving one against a store is sys/gitops's.
 */

#ifndef DOTTA_REFSPEC_H
#define DOTTA_REFSPEC_H

#include <types.h>

/**
 * Does the token look like a commit reference?
 *
 * The lexical half of the syntax below: what may stand after the last '@', and
 * — for the verbs whose positional slot could hold one — what a whole token may
 * be. It recognizes the spellings that name a commit with nothing looked up:
 * `HEAD` and its modifiers (`HEAD~1`, `HEAD^`, `HEAD~3^2`), `@` for the current
 * commit, a bare SHA of 7 to 40 hex digits, and a SHA carrying a modifier
 * (`a4f2c8e^`, `def4567~2`).
 *
 * A shape and never an existence: nothing is resolved and no store is read, so
 * a tag and a branch name are refused here whatever the repository holds. A verb
 * that means to accept either takes its commit by position instead of asking
 * (cmds/revert.c's three-positional form), and that is the whole reason the two
 * forms differ.
 *
 * Readers: the parse below, for its '@' gate; show's one- and two-positional
 * forms, export's second positional and revert's, each deciding whether a token
 * is its commit slot's; and diff's classifier, which asks this second — a token
 * that announces a path is never read as a commit (infra/path.h
 * path_input_announces_path).
 *
 * @param token The token to read (may be NULL, which looks like nothing)
 * @return true iff the token has a commit reference's shape
 */
bool refspec_looks_like_commit(const char *token);

/**
 * Parsed refspec components.
 *
 * String fields point into the arena supplied to parse_refspec, which owns their
 * storage — the caller MUST NOT free them individually. A field is NULL when
 * the corresponding component is absent from the input (except `file`, which is
 * always set on success).
 */
typedef struct {
    const char *profile;    /* Profile name, or NULL if not specified */
    const char *file;       /* File path (always set on success) */
    const char *commit;     /* Commit reference, or NULL if not specified */
} refspec_t;

/**
 * Parse refspec: [profile:]<path>[@commit]
 *
 * Splits the input into profile, file path, and commit components. The ':'
 * separator for profile is optional (profile defaults to NULL). The '@' separator
 * is only recognized when followed by a valid git reference.
 *
 * Output slices are bump-allocated in the provided arena and share its lifetime.
 * On error, *out is left unchanged; callers should only read *out after the
 * returned error is NULL.
 *
 * Examples:
 *   "home/.bashrc"                  -> {NULL,         "home/.bashrc", NULL}
 *   "global:home/.bashrc"           -> {"global",     "home/.bashrc", NULL}
 *   "home/.bashrc@a4f2c8e"          -> {NULL,         "home/.bashrc", "a4f2c8e"}
 *   "home/.bashrc@HEAD~1"           -> {NULL,         "home/.bashrc", "HEAD~1"}
 *   "global:home/.bashrc@a4f2c8e"   -> {"global",     "home/.bashrc", "a4f2c8e"}
 *   "darwin/work:home/.bashrc"      -> {"darwin/work","home/.bashrc", NULL}
 *   "foo@bar.txt"                   -> {NULL,         "foo@bar.txt",  NULL}  (not a git ref)
 *
 * @param arena Arena for output allocations (must not be NULL).
 * @param input Refspec string (must not be NULL).
 * @param out   Parsed components. Untouched on error.
 * @return Error or NULL on success.
 */
error_t *parse_refspec(arena_t *arena, const char *input, refspec_t *out);

#endif /* DOTTA_REFSPEC_H */
