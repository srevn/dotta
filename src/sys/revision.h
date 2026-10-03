/**
 * revision.h - A commit a user named: the spelling read, and asked of a branch
 *
 * The one reader of a revision against a store: the spelling read once, before
 * any branch is chosen (revision_resolve), then asked of a branch's tip
 * (revision_find), or of a named branch, where a branch that has no commit for
 * it is the refusal (revision_load). What a spelling looks like with no store
 * in hand is base/refspec.h's; what a reference holds is sys/gitops.h's.
 */

#ifndef DOTTA_REVISION_H
#define DOTTA_REVISION_H

#include <git2.h>
#include <types.h>

/**
 * A revision a user named, read before any branch is chosen
 *
 * Two kinds of spelling name a commit. HEAD's — `HEAD` or `@`, alone or with
 * its steps back, `~N` and `^N` in any chain (base/refspec.h refspec_head_steps)
 * — names a commit of a branch, and only once the branch is chosen: its tip,
 * and the steps back from it. Every other spelling is git's revision syntax and
 * names one commit whichever branch is asked after — an id, a short id, a tag
 * peeled to its commit, `<id>~N` — so it is resolved once, when the revision is
 * read.
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
 * HEAD's steps are read whole, so one dotta does not walk — anything after HEAD
 * but `~N` and `^N`, `HEAD@{1}`, `@{1}` and `HEAD^{commit}` among them — refuses
 * here, before any branch is. A count too large for any history is read as it
 * is: the walk answers that it reaches past the root.
 *
 * Every other spelling is resolved now, and resolving it is required: one that
 * names no commit is the failure, in Git's words, whatever kept it from naming
 * one — a typo, an ambiguous short id, a commit or a tag object the store has
 * lost — and a spelling that names a tree or a blob refuses as naming no commit.
 * No branch is ever passed over for a spelling that does not resolve.
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
 * one tip. HEAD's steps are walked back from it, and NULL is the history shorter
 * than they reach — proven by the parent count each commit on the way was read
 * with, never by a lookup that missed. A commit is the branch's where the tip
 * is that commit or reaches it through its parents, and NULL is a history that
 * does not hold it. A parent the walk could not load and a history the query
 * could not read are the failures, each naming the revision and the branch —
 * even where libgit2 answers GIT_ENOTFOUND, which here is an object the store
 * has lost and never an answer.
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
 * steps reaching past the branch's history, a commit its history does not hold.
 * Every failure names what failed, the revision or the branch, so a caller adds
 * nothing by restating the subject. Readers, none of which wraps: export.c
 * cmd_export (the refspec's @commit), revert.c cmd_revert (the commit reverted
 * to), show.c show_source and cmd_show (a file's tree, and a commit shown under
 * a named profile).
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
