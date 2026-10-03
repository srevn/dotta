/**
 * revision.c - A commit a user named: the spelling read, and asked of a branch
 *
 * One evaluator reads the steps after a name, HEAD's and git's alike, and walks
 * them from a commit; with none in hand — HEAD's at the read, before any branch
 * is chosen, or past a history that ran out — it only reads them. Its loop and
 * its lexing are libgit2's revparse's (lib/libgit2/src/libgit2/revparse.c revparse,
 * extract_how_many); what each step means is git's (lib/git/object-name.c).
 */

#include "sys/revision.h"

#include <git2.h>
#include <regex.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/heap.h"
#include "base/refspec.h"
#include "sys/gitops.h"

/*
 * What a walk that could not load a commit says: the revision, and the branch
 * it was walked in where there is one — HEAD's steps are walked at a branch's
 * tip, a name's once, in none.
 */
static error_t revision_unwalked(int rc, const char *spelling, const char *branch) {
    return branch
        ? error_wrap(error_from_git(rc), "Cannot walk '%s' in branch '%s'", spelling, branch)
        : error_wrap(error_from_git(rc), "Cannot walk '%s'", spelling);
}

/*
 * `generations` steps from the commit in hand, each to its parent `nth` (0 the
 * first): what `~N` and `^N` take. NULL in hand is the history ending before
 * the steps do — an answer — and with none in hand there is nothing to take.
 */
static error_t revision_parents(
    const char *spelling, const char *branch, size_t nth, size_t generations,
    git_commit **commit
) {
    for (; *commit && generations > 0; generations--) {
        /* The count the commit was parsed with is the evidence: a parent past
         * it is a history shorter than the steps reach, while one it names is
         * there to load, and a load that fails is an object the store lost, though
         * libgit2 answers GIT_ENOTFOUND (lib/libgit2/src/libgit2/commit.c
         * git_commit_parent). */
        git_commit *parent = NULL;
        int rc = nth < git_commit_parentcount(*commit)
            ? git_commit_parent(&parent, *commit, (unsigned int) nth) : 0;
        git_commit_free(*commit);
        *commit = parent;
        if (rc < 0) return revision_unwalked(rc, spelling, branch);
    }

    return NULL;
}

/*
 * `^{/pattern}` from the commit in hand: the youngest commit it reaches, itself
 * among them, whose message the pattern matches, and NULL in hand where none
 * does — an answer. With none in hand the pattern is only compiled, so one that
 * is no expression refuses wherever the steps are read.
 */
static error_t revision_search(
    git_repository *repo, const char *spelling, const char *branch,
    const char *pattern, git_commit **commit
) {
    /* git's reading (lib/git/object-name.c peel_onion, get_oid_oneline): `^{/}`
     * is the commit itself, with no expression compiled — a regcomp may refuse
     * the empty one, as macOS's does — and `!-` leading the pattern matches where
     * the rest does not, `!!` is a literal `!`, any other `!` git's to reserve. */
    if (!*pattern) return NULL;

    const bool negated = pattern[0] == '!' && pattern[1] == '-';
    if (pattern[0] == '!') {
        if (!negated && pattern[1] != '!') {
            return error_create(
                ERR_INVALID_ARG, "Cannot resolve '%s': a pattern opening on '!' "
                "reads '!-' or '!!'", spelling
            );
        }
        pattern += negated ? 2 : 1;
    }

    /* An extended POSIX expression, as git compiles it, so what a pattern means
     * is never libgit2's build's (PCRE or regcomp, revparse.c build_regex) */
    regex_t regex;
    int rc = regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        char why[256];
        regerror(rc, &regex, why, sizeof(why));
        return error_create(ERR_INVALID_ARG, "Cannot resolve '%s': %s", spelling, why);
    }
    if (!*commit) {
        regfree(&regex);
        return NULL;
    }

    /* git's order, newest first, each commit's parents read as it is passed:
     * libgit2's unsorted walk inserts them by date (GIT_SORT_NONE: revwalk.c
     * get_revision), as git's pop_most_recent_commit does, where its own search
     * sorts by time and reads the whole history before the first message
     * (revparse.c handle_grep_syntax, revwalk.c limit_list). */
    git_revwalk *walk = NULL;
    rc = git_revwalk_new(&walk, repo);
    if (rc == 0) rc = git_revwalk_push(walk, git_commit_id(*commit));

    /* Each commit passed is looked up as the match, and let go where the pattern
     * does not take its raw message — what follows the header's blank line, as
     * git's search reads it. The walk's end is the answer that none matches; a
     * commit the walk or the lookup could not read is the failure, never that
     * answer — a commit-graph can name a commit whose object the store lost
     * (commit_list.c git_commit_list_parse). */
    git_commit *match = NULL;
    git_oid id;
    while (!match && rc == 0 && (rc = git_revwalk_next(&id, walk)) == 0) {
        rc = git_commit_lookup(&match, repo, &id);
        if (rc == 0 &&
            (regexec(&regex, git_commit_message_raw(match), 0, NULL, 0) == 0) == negated) {
            git_commit_free(match);
            match = NULL;
        }
    }

    /* The failure is read before anything is freed: the frees are libgit2's */
    error_t err = match || rc == GIT_ITEROVER
        ? NULL : revision_unwalked(rc, spelling, branch);
    git_revwalk_free(walk);
    regfree(&regex);
    git_commit_free(*commit);
    *commit = match;
    return err;
}

/*
 * One step, read at the cursor and taken from the commit in hand, the cursor
 * moved past it; with none in hand it is only read. What is no step refuses,
 * naming what one is.
 */
static error_t revision_step(
    git_repository *repo, const char *spelling, const char *branch,
    const char **cursor, git_commit **commit
) {
    const char *p = *cursor;

    /* `~N` and `^N`: the operator, then its count — 1 where none is written.
     * The count saturates rather than wraps: no history is 2^64 commits deep,
     * so a count past that reaches beyond the root like any count longer than
     * the history, git's own reading of one that overflows (lib/git/object-name.c
     * get_oid_1, get_nth_ancestor). The digits are ASCII's ten, whatever the
     * locale's classes hold. */
    if (p[0] == '~' || (p[0] == '^' && p[1] != '{')) {
        const char op = *p++;
        size_t count = *p >= '0' && *p <= '9' ? 0 : 1;
        for (; *p >= '0' && *p <= '9'; p++) {
            const size_t digit = (size_t) (*p - '0');
            count = count > (SIZE_MAX - digit) / 10 ? SIZE_MAX : count * 10 + digit;
        }
        *cursor = p;

        /* `~N` takes N first parents; `^N` one step, to the Nth parent, and `^0`
         * none — it is the commit itself */
        if (op == '~') return revision_parents(spelling, branch, 0, count, commit);
        return count > 0 ? revision_parents(spelling, branch, count - 1, 1, commit) : NULL;
    }

    /* `^{…}`: what the braces hold runs to the last '}' before the next `^{`
     * that only `~N` and `^N` follow — git's reading, which takes the steps from
     * the right (lib/git/object-name.c get_oid_1, peel_onion), so a pattern's
     * own braces are the pattern's: `^{/a{2}}`, `^{/[}]}`, `^{/a\}b}`. */
    if (p[0] == '^' && p[1] == '{') {
        const char *body = p + 2;
        const char *next = strstr(body, "^{");
        const char *end = next ? next : body + strlen(body);
        for (const char *q = end; q > body;) {
            while (q > body && q[-1] >= '0' && q[-1] <= '9') q--;
            if (q == body || (q[-1] != '~' && q[-1] != '^')) break;
            end = --q;
        }

        if (end > body && end[-1] == '}') {
            *cursor = end;

            /* What the braces hold, as one word — the whole of it, where git's
             * peel_onion reads `^{commit}x}` as `^{commit}` — a commit is its
             * own ^{}, ^{commit} and ^{object}, and peeled to a tree, a blob or
             * a tag it is no commit at all. */
            char *group = heap_strndup(body, (size_t) (end - 1 - body));
            error_t err = NULL;
            if (group[0] == '/') {
                err = revision_search(repo, spelling, branch, group + 1, commit);
            } else if (strcmp(group, "tree") == 0 || strcmp(group, "blob") == 0 ||
                strcmp(group, "tag") == 0) {
                err = error_create(
                    ERR_INVALID_ARG, "'%s' does not point to a commit", spelling
                );
            } else if (*group && strcmp(group, "commit") != 0 &&
                strcmp(group, "object") != 0) {
                err = error_create(
                    ERR_INVALID_ARG, "Cannot resolve '%s': a step is ~N, ^N, ^{type} "
                    "or ^{/pattern}", spelling
                );
            }
            free(group);
            return err;
        }
    }

    return error_create(
        ERR_INVALID_ARG, "Cannot resolve '%s': a step is ~N, ^N, ^{type} or "
        "^{/pattern}", spelling
    );
}

/*
 * A revision's steps, read in order and walked from the commit in hand, which
 * the walk owns from the call: what it holds after is the commit the steps reach,
 * or NULL where none was given or the history ran out before them — an answer,
 * and the steps after it are still read. A failure leaves NULL, the reference
 * released.
 */
static error_t revision_walk(
    git_repository *repo, const char *spelling, const char *branch, const char *steps,
    git_commit **commit
) {
    for (const char *cursor = steps; *cursor;) {
        error_t err = revision_step(repo, spelling, branch, &cursor, commit);
        if (err) {
            git_commit_free(*commit);
            *commit = NULL;
            return err;
        }
    }

    return NULL;
}

/*
 * Where a name's steps begin: at the first `~` or `^` standing outside a `@{…}`,
 * the reflog's and the upstream's selector, which is the name's own. No ref may
 * hold either byte (git-check-ref-format), so the first is always the name's
 * end. A spelling that reaches a `:` first is git's whole — the rest a path or
 * a search (lib/libgit2/src/libgit2/revparse.c revparse) — and so is one that
 * opens on a step, with no name to walk from: its steps are none, as where no
 * step stands at all.
 */
static const char *revision_name_steps(const char *spelling) {
    const char *p = spelling;
    while (*p && *p != ':' && *p != '~' && *p != '^') {
        const char *close = p[0] == '@' && p[1] == '{' ? strchr(p, '}') : NULL;
        p = close ? close + 1 : p + 1;
    }
    return *p == ':' || p == spelling ? p + strlen(p) : p;
}

error_t revision_resolve(
    git_repository *repo, const char *spelling, revision_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(spelling);
    CHECK_NULL(out);

    /* HEAD's steps are read whole now, so one that is no step refuses before
     * any branch is read: walked from no commit, each is only read — the tip
     * they are walked from is each branch's, at revision_find. */
    const char *steps = refspec_head_steps(spelling);
    if (steps) {
        git_commit *tip = NULL;
        error_t err = revision_walk(repo, spelling, NULL, steps, &tip);
        if (err) return err;

        *out = (revision_t){ .spelling = spelling, .steps = steps };
        return NULL;
    }

    /* Every other spelling is a name and its steps. The name is git's, and names
     * one object whichever branch is asked after. revparse answers a typo, a
     * lost commit and a tag whose object is gone alike (GIT_ENOTFOUND), and nothing
     * after it could tell them apart: a name that does not resolve is the failure,
     * and never a branch passed over. */
    steps = revision_name_steps(spelling);
    char *name = heap_strndup(spelling, (size_t) (steps - spelling));
    git_object *named = NULL;
    int rc = git_revparse_single(&named, repo, name);
    free(name);
    if (rc < 0) {
        return error_wrap(error_from_git(rc), "Cannot resolve '%s'", spelling);
    }

    /* Peeled to a commit before any step is walked: an annotated tag's id is
     * the tag's, and the commit is the one it names, so every step starts from
     * a commit, as every step dotta reads does — and the id the revision holds
     * is always a commit's, which the reachability query reads. A tree or a blob
     * names none, refused here rather than as a failure later. A commit peels
     * to a counted reference to itself, which is why the named object is freed
     * on its own. */
    git_object *peeled = NULL;
    rc = git_object_peel(&peeled, named, GIT_OBJECT_COMMIT);
    git_object_free(named);
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "'%s' does not point to a commit", spelling
        );
    }

    /* The steps, walked once: the name's commit is the same whichever branch is
     * asked after, and so is every commit its steps reach — so steps that reach
     * none name none in any branch. */
    git_commit *commit = (git_commit *) peeled;
    error_t err = revision_walk(repo, spelling, NULL, steps, &commit);
    if (err) return err;
    if (!commit) {
        return error_create(ERR_NOT_FOUND, "'%s' names no commit", spelling);
    }

    *out = (revision_t){ .spelling = spelling };
    git_oid_cpy(&out->commit, git_commit_id(commit));
    git_commit_free(commit);
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

    /* HEAD's steps, walked from the tip this branch was read at. The walk holds
     * its own reference from the start — the tip is the answer to HEAD itself —
     * and git_commit_dup's one answer is 0 (a count taken, nothing made). */
    (void) git_commit_dup(out, tip);
    return revision_walk(repo, rev->spelling, branch, rev->steps, out);
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

    /* The branch has no commit for it: HEAD's steps reach past its history or
     * match nothing in it, or its history does not hold the commit. */
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
