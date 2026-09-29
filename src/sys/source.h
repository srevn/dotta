/**
 * source.h - A source tree's ignore rules, as git reads them
 *
 * When a user runs `dotta add` against a file that lives inside a git repository,
 * they usually want dotta to skip whatever that repository already excludes (build
 * artefacts, `node_modules/`, secrets in `.env`) without having to restate every
 * pattern in `.dottaignore`. This module answers that one question, and answers
 * it as git(1) does: it finds the repository, reads its stack — each `.gitignore`
 * from the workdir down, `$GIT_COMMON_DIR/info/exclude`, and `core.excludesFile`
 * (git's default `$XDG_CONFIG_HOME/git/ignore`, else `~/.config/git/ignore`,
 * where none is set, or an optional one — `:(optional)` — names no file that is
 * there) — and matches it with base/gitignore in git's order. The specification
 * is git itself: tests/test-source-parity.c asks `git check-ignore` the same
 * questions, layout by layout.
 *
 * Which repository answers is git's discovery: the one whose `.git` a directory
 * holds, else the directory itself where it is a git directory (bare), else its
 * parent's — stopping where git's walk up stops, below a ceiling
 * (GIT_CEILING_DIRECTORIES: a directory that is one still asks its own `.git`)
 * and where it would cross into another filesystem (unless
 * GIT_DISCOVERY_ACROSS_FILESYSTEM). The environment that names one repository
 * for every path (GIT_DIR, GIT_WORK_TREE, GIT_COMMON_DIR) is not read: every
 * path here is asked of its own. A nested repository answers for its own contents,
 * and a repository's own root is an entry of whatever contains its parent. Its
 * workdir is where the `.git` was found, unless its format says otherwise:
 * `core.worktree` or `core.bare`, which git reads from the repository's own files
 * alone — a config that declares a format, and a linked worktree's own
 * config.worktree where the format reads one (else neither, for a linked worktree).
 * A directory that is not there reads as it will once it is — git's rules are
 * the path's, and `ignore --test` asks about a path before it is made. So does
 * one the invoker cannot look into: discovery walks past it, as libgit2 does,
 * where git itself cannot work there as the invoker at all. Under sudo that is
 * a hybrid on purpose — the walk enters such a directory with root's reach and
 * reads its rules so, while discovery sees what the invoker sees — and its residue
 * is stated: a repository nested inside one, which only root can see, is read
 * by the lists of the repository around it.
 *
 * It knows nothing of `core/ignore`, which compiles the user's own `.dottaignore`,
 * config and CLI layers inside the dotta repo: core/ignore asks this module as
 * the lowest of its layers (ignore_verdict), and no other module asks it.
 *
 * What it reads, and as whom. The repository — its discovery and its configuration
 * — is read as the invoker: libgit2 reads the configuration by path, as the
 * invoker, and a repository only root could find would be one whose configuration
 * dotta cannot read. The rule files are read through sys/filesystem's funnel,
 * whose reach a walk enters a directory with: a directory a sudo'd walk could
 * list is one whose rules it can read.
 *
 * What it does not read, stated. A conditional include (`includeIf`) is not
 * evaluated: libgit2 evaluates one only for a repository it has opened, and this
 * module opens none, since git's newer formats (reftable, sha256) keep libgit2
 * from opening one at all. Nor is git's environment configuration
 * (`GIT_CONFIG_GLOBAL` and the rest), which libgit2 reads none of, nor a
 * repository's owner (`safe.directory`), which guards what a repository could
 * make git run — hooks, a filter, a pager — where a rule file runs nothing. Nor
 * is a repository's format verified — its version and extensions — since the
 * rules are plain files whatever the format, and reading them where libgit2 cannot
 * open the repository is what this module is for; and its layout keys are read
 * with the includes libgit2 follows, where git's format pass reads the file alone.
 * `core.excludesFile` spelled from another user's home (`~user/`) is refused,
 * as every tilde dotta reads is (sys/filesystem.h fs_expand_tilde), and one spelled
 * from git's own install (`%(prefix)/`) names a place dotta cannot know: it is
 * read from the workdir, and is not there.
 *
 * What cannot be read is a failure, never an answer. What git reads as absent
 * by rule reads absent here: a rule file that is not there, and an in-tree
 * `.gitignore` that is a link (git opens one without following it). Anything
 * else is a failure of the layer — a rule file that cannot be opened or read,
 * is not a regular file, holds a NUL or does not compile; a configuration that
 * does not parse, or a file of the repository's own configuration that the invoker
 * cannot read; a `.git` file that names no repository, a `.git` that is neither
 * a file nor a directory, a git directory whose commondir names nothing; a
 * `core.worktree` that names nothing, or stands beside `core.bare` — each minted
 * once per cause and answered again for every entry that reaches it: a directory's,
 * a repository's, a file's. One of the machine's configuration files that the
 * invoker cannot read is absent, as git skips a global or XDG file; the system
 * file libgit2 finds is its own, which need not be git's, and is read as the
 * machine's.
 *
 * Lifetime: the arena's. A filter lives in the arena it was made in, every answer
 * it keeps with it, and nothing frees it; no libgit2 handle outlives a call. It
 * remembers every directory it was asked about, under every spelling, and every
 * file it read: one per command, shared across every profile and directory the
 * command asks about. A failure is an answer it remembers too, and the filter
 * is the retry boundary: a fresh one asks again.
 *
 * Threading: not thread-safe. A filter must not be used concurrently from multiple
 * threads.
 */

#ifndef DOTTA_SYS_SOURCE_H
#define DOTTA_SYS_SOURCE_H

#include <stdbool.h>
#include <types.h>

typedef struct gitignore_rule gitignore_rule_t;
typedef struct source_filter source_filter_t;

/**
 * The rule that decides one rung, and the file it was read from
 *
 * Both are the filter's own and live as long as its arena. `rule` is read through
 * base/gitignore's accessors (its pattern, its line in `file`, whether it negates).
 */
typedef struct {
    const gitignore_rule_t *rule;      /* NULL: no rule decides the rung */
    const char *file;                  /* The file it was read from, absolute; NULL with no rule */
} source_rule_t;

/**
 * Create a source filter.
 *
 * git's discovery environment is read here, once — GIT_CEILING_DIRECTORIES and
 * GIT_DISCOVERY_ACROSS_FILESYSTEM — so a filter asks under the environment it
 * was made in, and a value git refuses is the failure of every query it answers.
 *
 * @param arena Arena the filter and everything it reads live in (must not be NULL)
 * @return The filter, the arena's; never NULL
 */
source_filter_t *source_filter_create(arena_t *arena);

/**
 * The rule of the source repository's stack that decides `path` itself.
 *
 * git's last_matching_pattern_from_lists, asked of the repository that governs
 * `path`'s directory: each `.gitignore` from that directory up to the workdir,
 * the deepest first, each reading the path from its own directory; then
 * `info/exclude`, then the excludes file, reading it from the workdir. The first
 * list with a rule that matches decides, and within a list the last such rule
 * does — a negation as readily as any, for the caller to read. No ancestor of
 * `path` is asked: the climb over its rungs is the caller's.
 *
 * `out->rule` is NULL where no rule decides the rung, where no repository governs
 * the directory or its workdir does not contain it (a bare repository, a
 * `core.worktree` elsewhere), and where `path` names no entry — nothing after
 * its last `/` ("/"). A directory is asked with `is_dir`, which a directory-only
 * rule (`node_modules/`) needs.
 *
 * Readers: source_filter_excludes (below), until core/ignore's climb asks the
 * rungs itself; tests/test-source-parity.c climb, which climbs over it as git does.
 *
 * @param f      Filter (must not be NULL)
 * @param path   Absolute path (must start with `/`)
 * @param is_dir True if the path refers to a directory
 * @param out    The deciding rule and its file (must not be NULL)
 * @return Error (the failure the rule could not be read past) or NULL on success
 */
error_t source_filter_find(
    source_filter_t *f,
    const char *path,
    bool is_dir,
    source_rule_t *out
);

/**
 * Test whether `path` is excluded by the ignore rules of its directory's
 * repository.
 *
 * git's climb over the rungs of the path beneath that repository's workdir: every
 * directory on the way down, shallowest first, each asked as source_filter_find
 * asks one; then the path itself. The first rung a rule excludes is the verdict
 * — an excluded directory is final, and a rule beneath it cannot re-include
 * anything — and a rung a negation decides settles nothing beneath it. That is
 * `git check-ignore` from the repository, the tree's own rules at every rung
 * and no other repository's: a nested repository's root, which its parent's
 * repository judges, is not asked of it here.
 *
 * `*out` is false for "not excluded" and for "no verdict" alike — no repository
 * governs the directory, or its workdir does not contain it — and the two are
 * deliberately one answer to a caller that layers this beneath its own. A path
 * that names no entry answers false.
 *
 * Policy: whether to consult the answer at all belongs with the caller — the
 * builder of the ladder's layers reads `config.respect_gitignore`, and a caller
 * that wants the layer off does not build a filter. Reader: core/ignore.c
 * ignore_verdict, the ladder's one question; built by core/ignore.c
 * ignore_rules_create.
 *
 * Preconditions: `path` must start with `/`. Callers with possibly-relative input
 * resolve it first (path_input_filesystem_path, path_input_resolve, realpath,
 * or a state filesystem path), and every one of those sheds a trailing `/`.
 *
 * @param f      Filter (must not be NULL)
 * @param path   Absolute path (must start with `/`)
 * @param is_dir True if the path refers to a directory
 * @param out    Output boolean (must not be NULL)
 * @return Error (the failure the verdict could not be read past) or NULL on success
 */
error_t source_filter_excludes(
    source_filter_t *f,
    const char *path,
    bool is_dir,
    bool *out
);

#endif /* DOTTA_SYS_SOURCE_H */
