/**
 * refspec.h - The commit a refspec carries, and the shape of a commit
 *
 * The lexical rule that decides where the '@' of `[profile:]<path>[@commit]`
 * splits — the shape that announces a commit, with no repository in hand, and
 * the commit a token carries by it — which the refspec's reading asks of a
 * positional (infra/input.h input_refspec), and the commands whose slot could
 * hold a commit ask of a whole one. The profile and the path are read above,
 * where a path's shape is known. Git's revision spellings are read here and in
 * no lower module — a commit reference's shape, and where HEAD's steps begin;
 * resolving one against a store is sys/revision's, HEAD's steps walked back from
 * a branch's head.
 */

#ifndef DOTTA_REFSPEC_H
#define DOTTA_REFSPEC_H

#include <types.h>

/**
 * Does the token announce a commit?
 *
 * The shape of a refspec's commit: what may stand after an '@', and — for the
 * verbs whose positional slot could hold one — what a whole token may be. A commit
 * announces itself, with nothing looked up, in the spellings that name one: HEAD's
 * (refspec_head_steps — `HEAD` or `@` where the word ends there or a modifier
 * follows it: `HEAD~1`, `HEAD^`, `HEAD~3^2`, `HEAD@{1}`, `HEAD:x`, `@`, `@~1`,
 * `@^2`), a bare SHA of 7 to 40 hex digits, and a SHA carrying a modifier
 * (`a4f2c8e^`, `def4567~2`).
 *
 * A shape and never an existence: nothing is resolved and no store is read, so
 * a tag and a branch name announce nothing, whatever the repository holds — and
 * neither does a word that merely begins with a commit's letters, `HEADER` being
 * a profile name like any other. A verb that means to accept a tag takes its
 * commit by position instead of asking — revert, every word past its path's —
 * and asks only where a word could be a commit or something else: revert's second
 * word beside a profile's, the whole profile's commit or its path (cmds/revert.c
 * revert_post_parse).
 *
 * Readers: refspec_commit, for its '@' gate, and the refspec's reading through
 * it (infra/input.h input_refspec); show's one- and two-positional forms, export's
 * second positional, and revert's second word beside a profile's, each deciding
 * by this alone whether a token is its commit slot's; and diff's classifier,
 * which asks this first — a token that announces a commit is never read as a
 * path, and the two shapes meet only in a revision whose pattern holds a glob's
 * bytes (infra/input.h input_announces_path).
 *
 * @param token The token to read (may be NULL, which announces nothing)
 * @return true iff the token announces a commit
 */
bool refspec_announces_commit(const char *token);

/**
 * The steps a HEAD spelling takes from a branch's head
 *
 * dotta's HEAD is a branch's head, whichever branch a verb reads (sys/revision.h
 * revision_t), and `@` is HEAD wherever it stands for it, as git reads it. So
 * `HEAD` and `@` answer "", the head itself, and either with a modifier right
 * after it answers the modifier on: `HEAD~3^2` is "~3^2", `@~1` is "~1", `HEAD@{1}`
 * is "@{1}", `@{1}` is "{1}" and `HEAD:x` is ":x". Every other spelling answers
 * NULL, a word that merely begins with the four letters among them — `HEADER`
 * is a profile name like any other — and an `@` followed by a name: `@foo` is a
 * path.
 *
 * The shape alone: which steps a branch can take is the resolver's to say, so a
 * modifier it refuses is still HEAD's here, and a spelling that opens on HEAD
 * never reaches git's own HEAD, the store's, which nothing reads. Readers:
 * refspec_announces_commit, whose HEAD and `@` spellings are exactly these, and
 * sys/revision.c revision_resolve, which reads the steps and walks them.
 *
 * @param spelling The spelling to read (may be NULL, which is nobody's HEAD)
 * @return The steps after HEAD, borrowed from `spelling` ("" for the head), or
 *         NULL for a spelling that is not HEAD's
 */
const char *refspec_head_steps(const char *spelling);

/**
 * The commit a token carries
 *
 * The shortest suffix after an '@' that announces a commit
 * (refspec_announces_commit), so an '@' that no commit follows is the name's
 * own — `foo@bar.txt` carries none — and a commit holding an '@' of its own is
 * split before it: `x@@` carries `@`, and `x@HEAD@{1}` carries `HEAD@{1}`, which
 * the resolver refuses. A commit's shape inside the name before it stays the
 * name's: `p:~/a@deadbeef0@HEAD` carries HEAD. A shape, never an existence: nothing
 * is resolved, and a commit with no name before it (`@HEAD`) is carried all the
 * same — the refspec's reading is what refuses such a token, as naming no file.
 *
 * Readers: infra/input.c input_refspec, which ends the path at its '@'; and
 * cmds/apply.c apply_classify, which routes a token carrying one to that reading.
 *
 * @param token The token (may be NULL, which carries none)
 * @return The commit, borrowed from `token` past its '@'; NULL where none stands
 */
const char *refspec_commit(const char *token);

#endif /* DOTTA_REFSPEC_H */
