/**
 * source.h - Queries against a source tree's ignore rules
 *
 * When a user runs `dotta add` against a file that lives inside a git
 * repository, they usually want dotta to skip whatever that repo's
 * `.gitignore` already excludes (build artefacts, `node_modules/`,
 * secrets in `.env`) without having to restate every pattern in
 * `.dottaignore`. This module is the single adapter over libgit2's
 * nested-gitignore + attr-stack machinery for that one question.
 *
 * It is intentionally orthogonal to `core/ignore`, which compiles the
 * user's own `.dottaignore` + config + CLI layers inside the dotta
 * repo. A consumer that wants both behaviours calls both modules — no
 * hidden cross-wiring.
 *
 * Lifetime: command-scoped. One handle per command, shared across any
 * profile / directory iterations the command runs. The handle caches
 * the last-discovered source repository so repeated queries against
 * the same subtree amortise the `git_repository_discover` walk.
 *
 * Threading: not thread-safe — mirrors libgit2's per-handle model. A
 * handle must not be used concurrently from multiple threads.
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
 * Free a source filter and any cached repository handle.
 *
 * @param f Filter (may be NULL)
 */
void source_filter_free(source_filter_t *f);

/**
 * Test whether `abs_path` is excluded by the gitignore rules of the
 * repository that contains it.
 *
 * Semantics:
 *   - Returns `*out = false` (no error) when `abs_path` is not inside
 *     any git repository, or the containing repository is bare.
 *   - Returns `*out = true` only when libgit2's
 *     `git_ignore_path_is_ignored` reports a positive match against
 *     the containing repo's rules.
 *   - Uses `git_repository_discover` with `across_fs = 0`, so a source
 *     repo on a different filesystem than `abs_path` is treated as
 *     "not in a repo" — matches git's own behaviour.
 *
 * Policy: this function answers the mechanical question "is this path
 * ignored by its source repo?". The policy "do we consult that answer
 * at all?" belongs with the caller (typically via
 * `config.respect_gitignore`). A caller that wants layer-5 off for a
 * given operation simply does not build a filter — there is no flag
 * to wire through.
 *
 * Preconditions: `abs_path` must start with `/`. Callers with possibly-
 * relative input must resolve it first (every in-tree caller already
 * does so via `path_normalize_input`, `realpath`, or a pre-resolved
 * state filesystem path).
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
