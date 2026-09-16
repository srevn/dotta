/**
 * source.h - Queries against a source tree's ignore rules
 *
 * When a user runs `dotta add` against a file that lives inside a git repository,
 * they usually want dotta to skip whatever that repo's `.gitignore` already
 * excludes (build artefacts, `node_modules/`, secrets in `.env`) without having
 * to restate every pattern in `.dottaignore`. This module is the single adapter
 * over libgit2's nested-gitignore + attr-stack machinery for that one question.
 *
 * The answer is libgit2's, and libgit2 differs from git(1) on nested negation:
 * it stops at the first rung that decides, so `build/` followed by `!build/keep`
 * leaves `build/keep` un-ignored where git excludes it. `base/gitignore` reads
 * the rung order git reads; this adapter cannot, and no libgit2 release carries
 * the fix (libgit2#7339, open upstream). A source tree whose `.gitignore` holds
 * a negation beneath a directory rule is therefore read more permissively than
 * the same rules in `.dottaignore` would be. Which repository's rules are read
 * is this module's own question and is answered below; the divergence is about
 * the order the rungs of one repository decide in, and is untouched by it.
 *
 * It is intentionally orthogonal to `core/ignore`, which compiles the user's
 * own `.dottaignore` + config + CLI layers inside the dotta repo. A consumer
 * that wants both behaviours calls both modules — no hidden cross-wiring.
 *
 * Lifetime: command-scoped. One handle per command, shared across any profile /
 * directory iterations the command runs. The handle remembers one directory's
 * answer — the repository that governs it, and where it stands inside — and asks
 * again at every directory it is given, because a repository is a boundary and
 * not a subtree: a nested repository's `.git/info/exclude` is visible through
 * no handle but its own.
 *
 * Threading: not thread-safe — mirrors libgit2's per-handle model. A handle must
 * not be used concurrently from multiple threads.
 */

#ifndef DOTTA_SYS_SOURCE_H
#define DOTTA_SYS_SOURCE_H

#include <stdbool.h>
#include <types.h>

typedef struct source_filter source_filter_t;

/**
 * Create a source filter.
 *
 * @param out Output handle (must not be NULL)
 * @return Error or NULL on success
 */
error_t *source_filter_create(source_filter_t **out);

/**
 * Free a source filter, the directory it last answered for and the repository
 * handle it was holding.
 *
 * @param f Filter (may be NULL)
 */
void source_filter_free(source_filter_t *f);

/**
 * Test whether `abs_path` is excluded by the gitignore rules of the repository
 * that contains it.
 *
 * The rules are those of the repository containing `abs_path`'s **directory**,
 * and the innermost one: a nested repository answers for its own contents and
 * no repository above it is consulted, and a repository's own root is judged by
 * whatever contains its parent. That is the rule git walks a tree by — the outer
 * never forms an opinion about a nested repository's files — and it is the rule
 * this handle answers by however many directories it has been asked about before:
 * a warm handle answers what a fresh one would.
 *
 * Semantics:
 *   - Returns `*out = false` (no error) for "not excluded" and for "no verdict"
 *     alike, and the two are deliberately one answer: no repository above the
 *     directory, a bare one, a workdir that does not contain the directory
 *     (`core.worktree` pointing away), and rules that simply do not match all
 *     read the same to a caller that layers this beneath its own.
 *   - Returns `*out = true` only when libgit2's `git_ignore_path_is_ignored`
 *     reports a positive match against that repository's rules, asked with the
 *     trailing `/` a directory needs for a directory-only pattern.
 *   - Uses `git_repository_discover` with `across_fs = 0`, so a source repo on
 *     a different filesystem than the directory is treated as "not in a repo" —
 *     matches git's own behaviour.
 *
 * Policy: this function answers the mechanical question "is this path ignored
 * by its source repo?". The policy "do we consult that answer at all?" belongs
 * with the caller (typically via `config.respect_gitignore`). A caller that wants
 * layer-5 off for a given operation simply does not build a filter — there is
 * no flag to wire through.
 *
 * Preconditions: `abs_path` must start with `/` and must name an entry — one
 * with nothing after its last `/` has no name for a rule to match and answers
 * `false`. Callers with possibly-relative input must resolve it first (in-tree
 * callers either ride path_input_locate, path_input_resolve, realpath, or feed
 * a pre-resolved state filesystem path), and every one of those sheds a trailing
 * `/` on the way.
 *
 * @param f        Filter (must not be NULL)
 * @param abs_path Absolute path (must start with `/`)
 * @param is_dir   True if the path refers to a directory
 * @param out      Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t *source_filter_is_excluded(
    source_filter_t *f,
    const char *abs_path,
    bool is_dir,
    bool *out
);

#endif /* DOTTA_SYS_SOURCE_H */
