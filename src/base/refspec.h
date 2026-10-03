/**
 * refspec.h - The refspec syntax, and the shape of a commit in it
 *
 * Parsing for `[profile:]<path>[@commit]`, for the commands that name a file
 * with an optional profile and commit; and the lexical rule that decides where
 * the '@' splits — what a commit reference looks like, with no repository in
 * hand — which those same commands ask of a whole positional where a slot of
 * theirs could hold one. Git's revision spellings are read here and in no lower
 * module — a commit reference's shape, and where HEAD's steps begin; resolving
 * one against a store is sys/revision's, HEAD's steps walked back from a branch's
 * tip.
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
 * HEAD's (refspec_head_steps — `HEAD` or `@` where the word ends there or a
 * modifier follows it: `HEAD~1`, `HEAD^`, `HEAD~3^2`, `HEAD@{1}`, `HEAD:x`, `@`,
 * `@~1`, `@^2`), a bare SHA of 7 to 40 hex digits, and a SHA carrying a modifier
 * (`a4f2c8e^`, `def4567~2`).
 *
 * A shape and never an existence: nothing is resolved and no store is read, so
 * a tag and a branch name are refused here whatever the repository holds — and
 * so is a word that merely begins with a commit's letters, `HEADER` being a profile
 * name like any other. A verb that means to accept a tag takes its commit by
 * position instead of asking (cmds/revert.c's three-positional form), and that
 * is the whole reason the two forms differ.
 *
 * Readers: the parse below, for its '@' gate; show's one- and two-positional
 * forms, export's second positional and revert's, each deciding by this alone
 * whether a token is its commit slot's; and diff's classifier, which asks this
 * first — a token shaped like a commit is never read as a path, and the two shapes
 * meet only in a revision whose pattern holds a glob's bytes (infra/path.h
 * path_input_announces_path).
 *
 * @param token The token to read (may be NULL, which looks like nothing)
 * @return true iff the token has a commit reference's shape
 */
bool refspec_looks_like_commit(const char *token);

/**
 * The steps a HEAD spelling takes from a branch's tip
 *
 * dotta's HEAD is a branch's tip, whichever branch a verb reads (sys/revision.h
 * revision_t), and `@` is HEAD wherever it stands for it, as git reads it. So
 * `HEAD` and `@` answer "", the tip itself, and either with a modifier right
 * after it answers the modifier on: `HEAD~3^2` is "~3^2", `@~1` is "~1", `HEAD@{1}`
 * is "@{1}", `@{1}` is "{1}" and `HEAD:x` is ":x". Every other spelling answers
 * NULL, a word that merely begins with the four letters among them — `HEADER`
 * is a profile name like any other — and an `@` followed by a name: `@foo` is a
 * path.
 *
 * The shape alone: which steps a branch can take is the resolver's to say, so a
 * modifier it refuses is still HEAD's here, and a spelling that opens on HEAD
 * never reaches git's own HEAD, the store's, which nothing reads. Readers:
 * refspec_looks_like_commit, whose HEAD and `@` spellings are exactly these,
 * and sys/revision.c revision_resolve, which reads the steps and walks them.
 *
 * @param spelling The spelling to read (may be NULL, which is nobody's HEAD)
 * @return The steps after HEAD, borrowed from `spelling` ("" for the tip), or
 *         NULL for a spelling that is not HEAD's
 */
const char *refspec_head_steps(const char *spelling);

/**
 * Parsed refspec components.
 *
 * String fields point into the arena supplied to refspec_parse, which owns their
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
 * Splits the input into profile, file path, and commit components. The commit
 * is found first: the shortest suffix after an '@' that has a commit's shape
 * (refspec_looks_like_commit), so an '@' that no commit follows is the name's
 * own, and a commit that carries an '@' of its own — `@` alone, `HEAD@{1}` — is
 * split before it. The profile is then what precedes the first ':' before the
 * commit, and is optional (NULL where no ':' stands there): a ':' the commit
 * carries — `HEAD^{/fix: typo}` — is the commit's, and no profile holds one
 * (git-check-ref-format). The names this order reads otherwise are a profile's
 * holding an '@' with a commit's shape after it — `x@HEAD@y:home/f`, or one ending
 * in `@HEAD` or `@@` — each read as a file at a commit the resolver then refuses.
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
 *   "home/.bashrc@@"                -> {NULL,         "home/.bashrc", "@"}
 *   "home/.bashrc@HEAD^{/a: b}"     -> {NULL,         "home/.bashrc", "HEAD^{/a: b}"}
 *   "global:home/.bashrc@a4f2c8e"   -> {"global",     "home/.bashrc", "a4f2c8e"}
 *   "darwin/work:home/.bashrc"      -> {"darwin/work","home/.bashrc", NULL}
 *   "foo@bar.txt"                   -> {NULL,         "foo@bar.txt",  NULL}  (not a git ref)
 *
 * @param arena Arena for output allocations (must not be NULL).
 * @param input Refspec string (must not be NULL).
 * @param out   Parsed components. Untouched on error.
 * @return Error or NULL on success.
 */
error_t refspec_parse(arena_t *arena, const char *input, refspec_t *out);

#endif /* DOTTA_REFSPEC_H */
