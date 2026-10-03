/**
 * revision.c - A commit a user named: the spelling read, and asked of a branch
 */

#include "sys/revision.h"

#include <git2.h>
#include <stdint.h>

#include "base/error.h"
#include "base/refspec.h"
#include "sys/gitops.h"

/*
 * One of HEAD's steps, read at the cursor and the cursor moved past it: the step's
 * operator, `~` or `^`, with its count — 1 where none is written — or 0 where
 * the text at the cursor is no step. The count saturates rather than wraps: no
 * history is 2^64 commits deep, so a count past that reaches beyond the root
 * like any count longer than the history, git's own reading of one that overflows
 * (lib/git/object-name.c get_nth_ancestor). The digits are ASCII's ten, whatever
 * the locale's classes hold.
 */
static char revision_step(const char **cursor, size_t *count) {
    const char *p = *cursor;
    const char op = *p++;
    if (op != '~' && op != '^') return 0;

    size_t n = *p >= '0' && *p <= '9' ? 0 : 1;
    for (; *p >= '0' && *p <= '9'; p++) {
        const size_t digit = (size_t) (*p - '0');
        n = n > (SIZE_MAX - digit) / 10 ? SIZE_MAX : n * 10 + digit;
    }

    *cursor = p;
    *count = n;
    return op;
}

error_t revision_resolve(
    git_repository *repo, const char *spelling, revision_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(spelling);
    CHECK_NULL(out);

    /* HEAD's steps are read whole now, so one the walk would not take refuses
     * before any branch is read; revision_find walks them from each tip. */
    const char *steps = refspec_head_steps(spelling);
    if (steps) {
        for (const char *step = steps; *step;) {
            size_t count = 0;
            if (!revision_step(&step, &count)) {
                return error_create(
                    ERR_INVALID_ARG,
                    "Cannot resolve '%s': after HEAD, dotta reads ~N and ^N steps",
                    spelling
                );
            }
        }
        *out = (revision_t){ .spelling = spelling, .steps = steps };
        return NULL;
    }

    /* Every other spelling is git's, and names one commit whichever branch is
     * asked after, so it is resolved here, once. revparse answers a typo, a lost
     * commit and a tag whose object is gone alike (GIT_ENOTFOUND), and nothing
     * after it could tell them apart: a spelling that does not resolve is the
     * failure, and never a branch passed over. */
    git_object *named = NULL;
    int rc = git_revparse_single(&named, repo, spelling);
    if (rc < 0) {
        return error_wrap(error_from_git(rc), "Cannot resolve '%s'", spelling);
    }

    /* Peeled to a commit: an annotated tag's id is the tag's, and the commit is
     * the one it names, so the id the revision holds is always a commit's — the
     * reachability query reads commits. A tree or a blob names none, refused
     * here rather than as a failure later. A commit peels to a counted reference
     * to itself, which is why the named object is freed on its own. */
    git_object *commit = NULL;
    rc = git_object_peel(&commit, named, GIT_OBJECT_COMMIT);
    git_object_free(named);
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "'%s' does not point to a commit", spelling
        );
    }

    *out = (revision_t){ .spelling = spelling };
    git_oid_cpy(&out->commit, git_object_id(commit));
    git_object_free(commit);
    return NULL;
}

error_t revision_find(
    git_repository *repo, const revision_t *rev, const char *branch,
    git_commit *tip, git_commit **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(rev);
    CHECK_NULL(branch);
    CHECK_NULL(tip);
    CHECK_NULL(out);

    *out = NULL;

    if (!rev->steps) {
        /* A commit resolved repository-wide may be any branch's, and read as
         * this one's without asking it would be misattributed. It is the branch's
         * where the tip is that commit or reaches it through its parents — the
         * graph answers the tip itself as reachable, which descendant_of does
         * not (graph.c). A history it cannot read is the failure, as `git
         * merge-base --is-ancestor` fails it: an unread object below the commit
         * decides nothing. */
        int rc = git_graph_reachable_from_any(repo, &rev->commit, git_commit_id(tip), 1);
        if (rc < 0) {
            return error_wrap(
                error_from_git(rc),
                "Cannot tell whether commit '%s' is reachable from branch '%s'",
                rev->spelling, branch
            );
        }
        if (rc == 0) return NULL;

        rc = git_commit_lookup(out, repo, &rev->commit);
        if (rc < 0) {
            return error_wrap(
                error_from_git(rc), "Cannot read commit '%s'", rev->spelling
            );
        }
        return NULL;
    }

    /* HEAD's steps, walked back from the tip this branch was read at. The walk
     * holds its own reference from the start — the tip is the answer to HEAD
     * itself — and git_commit_dup's one answer is 0 (a count taken, nothing
     * made). */
    git_commit *commit = NULL;
    (void) git_commit_dup(&commit, tip);

    for (const char *step = rev->steps; *step;) {
        size_t count = 0;
        const char op = revision_step(&step, &count);
        CHECK_ARG(op != 0, "a revision's steps are the ones its resolve read");

        /* `~N` takes N first parents; `^N` takes one step, to the Nth parent,
         * and `^0` none — it is the commit itself. */
        size_t generations = count;
        size_t nth = 0;
        if (op == '^') {
            if (count == 0) continue;
            generations = 1;
            nth = count - 1;
        }

        for (; generations > 0; generations--) {
            /* The count read off the parsed commit is the evidence: a parent
             * past it is a history shorter than the steps reach — no commit, an
             * answer — while one it names is there to load, and a load that fails
             * is an object the store lost, though libgit2 answers GIT_ENOTFOUND. */
            if (nth >= git_commit_parentcount(commit)) {
                git_commit_free(commit);
                return NULL;
            }

            git_commit *parent = NULL;
            int rc = git_commit_parent(&parent, commit, (unsigned int) nth);
            git_commit_free(commit);
            if (rc < 0) {
                return error_wrap(
                    error_from_git(rc), "Cannot walk '%s' in branch '%s'",
                    rev->spelling, branch
                );
            }
            commit = parent;
        }
    }

    *out = commit;
    return NULL;
}

/**
 * The commit a revision names in a named branch
 */
error_t revision_load(
    git_repository *repo, const char *branch, const char *spelling, git_commit **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch);
    CHECK_NULL(spelling);
    CHECK_NULL(out);

    /* The revision first: a spelling that names nothing refuses before the branch
     * is read, whichever branch is named. */
    revision_t rev;
    error_t err = revision_resolve(repo, spelling, &rev);
    if (err) return err;

    /* The tip, read once, and the revision asked of it: HEAD's steps and the
     * membership of a commit are one tip's answers, never two reads of a ref
     * that may move between them. */
    git_commit *tip = NULL;
    err = gitops_load_branch_commit(repo, branch, &tip);
    if (err) return err;

    err = revision_find(repo, &rev, branch, tip, out);
    git_commit_free(tip);
    if (err || *out) return err;

    /* The branch has no commit for it: HEAD's steps reach past its history, or
     * its history does not hold the commit. */
    if (rev.steps) {
        return error_create(
            ERR_NOT_FOUND, "'%s' names no commit of branch '%s'", spelling, branch
        );
    }
    return error_create(
        ERR_NOT_FOUND, "Commit '%s' is not reachable from branch '%s'", spelling,
        branch
    );
}
