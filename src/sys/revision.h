/**
 * revision.h - A commit a user named: the spelling read, and asked of a branch
 *
 * The one reader of a revision against a store: the spelling read once, before
 * any branch is chosen (revision_resolve), then asked of a branch's tip
 * (revision_find), or of a named branch, where a branch that has no commit for
 * it is the refusal (revision_load). What a spelling looks like with no store
 * in hand is base/refspec.h's; what a reference holds is sys/gitops.h's.
 *
 * A spelling is a name and the steps after it, as git reads one
 * (lib/git/object-name.c get_oid_1). dotta has one name of its own, HEAD — `HEAD`
 * or `@` and everything after it (base/refspec.h refspec_head_steps) — a branch's
 * tip, so a commit only once the branch is chosen. Every other name is git's —
 * an id, a short id, a tag, a branch, `name@{…}`, `:/text`, `rev:path` — and
 * libgit2 resolves it once, peeled to its commit, which is the same whichever
 * branch is asked after.
 *
 * The steps are dotta's after either name, read by one evaluator: `~N` and `^N`
 * in any chain; `^{}`, `^{commit}` and `^{object}`, which a commit answers as
 * itself; `^{tree}`, `^{blob}` and `^{tag}`, which name no commit and are refused;
 * and `^{/pattern}`, the youngest commit reached, itself among them, whose message
 * the pattern matches. Anything else after a name is no step and is refused,
 * `HEAD@{1}`, `@{1}` and `HEAD:path` among it. Each is git's reading, and libgit2's
 * revparse departs from it on five (lib/libgit2/src/libgit2/revparse.c): it has
 * no `^{object}`, refuses `^{/}`, reads `^{/!-x}` as a pattern, refuses a count
 * past 2^31 as no spelling, and ends a group at its first '}'. Its answers are
 * the other reason the walk is dotta's: a history shorter than the steps reach,
 * a search that matches nothing and an object the store lost all come back
 * GIT_ENOTFOUND, the search's with no sentence at all (commit.c git_commit_parent;
 * revparse.c walk_and_search). Here every "none" is proven — by the parent count
 * each commit was read with, by the walk's end — and a look that could not read
 * is the failure, never a none.
 */

#ifndef DOTTA_REVISION_H
#define DOTTA_REVISION_H

#include <git2.h>
#include <types.h>

/**
 * A revision a user named, read before any branch is chosen
 *
 * HEAD's spelling names a commit of a branch, and only once the branch is chosen:
 * its tip, and its steps walked from there, so the steps are kept and walked at
 * each tip asked (revision_find). Every other spelling names one commit whichever
 * branch is asked after — a name and the steps from it, `<id>~N`, `release^{}`,
 * `<id>^{/fix}` — so it is resolved once, when the revision is read, and kept
 * as that commit's id.
 *
 * Nothing is held but the spelling and one commit's id, so the value needs no
 * release and is copied freely; it is valid while the spelling is.
 */
typedef struct {
    const char *spelling;   /* as typed, borrowed: what every refusal names */
    const char *steps;      /* HEAD's steps, borrowed ("" the tip); NULL: a commit */
    git_oid commit;         /* the commit the spelling names; unread where steps is */
} revision_t;

/**
 * Read a revision
 *
 * The steps are read whole, after HEAD as after any name, so one that is no step
 * — `HEAD@{1}`, `@{1}`, a peel to no commit among them — refuses here, before
 * any branch is, and so does a pattern that is no expression, compiled now. A
 * count too large for any history is read as it is: the walk answers that it
 * reaches past the root.
 *
 * Every other spelling is resolved now, and resolving it is required: a name
 * that names no commit is the failure, in Git's words, whatever kept it from
 * naming one — a typo, an ambiguous short id, a commit or a tag object the store
 * has lost — and a name that names a tree or a blob refuses as naming no commit.
 * Its steps are walked now too, from the name's commit, and steps that reach no
 * commit refuse as naming none: they reach none in any branch. No branch is ever
 * passed over for a spelling that does not resolve.
 *
 * @param repo Repository (must not be NULL)
 * @param spelling The revision as typed (must not be NULL; borrowed by `out`)
 * @param out The revision (must not be NULL; left as it was on a failure)
 * @return Error or NULL on success
 */
error_t revision_resolve(
    git_repository *repo,
    const char *spelling,
    revision_t *out
);

/**
 * The commit a revision names in a branch, or NULL where the branch has none
 *
 * A query, asked of a tip the caller read once (sys/gitops.h
 * gitops_load_branch_commit) so every revision asked of a branch is asked of
 * one tip. HEAD's steps are walked from it, and NULL is a history shorter than
 * they reach or one that holds no commit a search matches — proven by the parent
 * count each commit on the way was read with, and by the end of a walk that read
 * every commit it passed, never by a lookup that missed. A commit is the branch's
 * where the tip is that commit or reaches it through its parents, and NULL is a
 * history that does not hold it. A commit the walk could not load and a history
 * the query could not read are the failures, each naming the revision and the
 * branch — even where libgit2 answers GIT_ENOTFOUND, which here is an object
 * the store has lost and never an answer. The walk is stricter than its answer
 * needs in one place: libgit2 reads a commit's parents before it yields the commit
 * (revwalk.c get_revision), so a search whose match has lost a parent fails where
 * git would answer the match.
 *
 * @param repo Repository (must not be NULL)
 * @param rev The revision (must not be NULL)
 * @param branch The tip's branch, for what a failure names (must not be NULL)
 * @param tip The branch's tip (must not be NULL; borrowed)
 * @param out The commit (caller frees with git_commit_free), or NULL: none in
 *            the branch (must not be NULL)
 * @return Error or NULL on success
 */
error_t revision_find(
    git_repository *repo,
    const revision_t *rev,
    const char *branch,
    git_commit *tip,
    git_commit **out
);

/**
 * The commit a revision names in a named branch, or a refusal
 *
 * The revision read (revision_resolve), the branch's tip read once (sys/gitops.h
 * gitops_load_branch_commit), and the one asked of the other (revision_find); a
 * revision the branch has no commit for is the refusal that says so — HEAD's
 * steps reaching past the branch's history or matching nothing in it, a commit
 * its history does not hold. Every failure names what failed, the revision or
 * the branch, so a caller adds nothing by restating the subject. Readers, none
 * of which wraps: export.c cmd_export (the refspec's @commit), revert.c cmd_revert
 * (the commit reverted to), show.c show_source and cmd_show (a file's tree, and
 * a commit shown under a named profile).
 *
 * The commit is the whole answer, and its OID is read off it (git_commit_id):
 * nothing is handed back beside it, so no caller holds two views of one fact
 * and none looks the commit up a second time to reach its tree.
 *
 * @param repo Repository (must not be NULL)
 * @param branch Branch name (must not be NULL)
 * @param spelling The revision as typed (must not be NULL)
 * @param out The commit (must not be NULL, caller must free with git_commit_free)
 * @return Error or NULL on success
 */
error_t revision_load(
    git_repository *repo,
    const char *branch,
    const char *spelling,
    git_commit **out
);

#endif /* DOTTA_REVISION_H */
