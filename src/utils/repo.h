/**
 * repo.h - Repository path resolution
 *
 * Determines which dotta repository to use based on:
 * 1. DOTTA_REPO_DIR environment variable (highest priority)
 * 2. Config file setting (~/.config/dotta/config.toml)
 * 3. Default location: ~/.local/share/dotta/repo
 *
 * This is different from git's behavior - dotta uses a centralized repository,
 * not discovery from current working directory.
 */

#ifndef DOTTA_REPO_H
#define DOTTA_REPO_H

#include <git2.h>
#include <types.h>

/**
 * Resolve repository path
 *
 * Determines the dotta repository location based on:
 * 1. DOTTA_REPO_DIR environment variable (always highest priority)
 * 2. Config file repo_dir setting
 * 3. Default: ~/.local/share/dotta/repo
 *
 * The path is always expanded (~ becomes absolute path). If the config file exists
 * but fails to parse/validate, a warning is emitted to stderr and the resolution
 * continues without config (env var and default are still respected).
 *
 * @param config Loaded configuration (must not be NULL)
 * @param out Resolved repository path (caller must free)
 * @return Error or NULL on success
 */
error_t *resolve_repo_path(const config_t *config, char **out);

/**
 * Where a create-style command puts the repository
 *
 * `resolve_repo_path` answers "where does this machine's repository live"; this
 * answers "where does a command that creates one put it". Two questions, two
 * tails: only the second has a positional to honour, parent directories to make,
 * and a caller to warn.
 *
 * `explicit_path` is the command's optional positional (`init [path]`, `clone
 * <url> [path]`); NULL means "wherever this machine's repository lives", which
 * is `resolve_repo_path` and nothing else. Both branches expand `~`, settle a
 * relative path against the current directory, and create the parent directories
 * — an explicit path is not a lesser path, and each of the two commands used to
 * drop a different one of those three steps: a quoted `dotta init "~/dotfiles"`
 * created a literal `./~/dotfiles`, and `dotta clone` re-derived the implicit
 * branch without $DOTTA_REPO_DIR in it.
 *
 * `*out_elsewhere` is where later commands will look, set only when that is not
 * `*out_path` — NULL when the two are the same place, so a non-NULL answer is
 * exactly "this repository is somewhere dotta will not find it". Both sides are
 * normalised here, by one function, which is what makes the comparison mean
 * anything. The caller says so on success, because nothing else will: every later
 * command resolves the configured location and stops there, so a `dotta status`
 * run straight afterwards answers "No dotta repository found... Run 'dotta init'"
 * about the repository just created.
 *
 * @param config        Loaded configuration (must not be NULL)
 * @param explicit_path The command's positional, or NULL for the configured
 *                      location
 * @param out_path      Resolved absolute path (must not be NULL, caller frees)
 * @param out_elsewhere Optional: the configured location when out_path is not
 *                      it, NULL otherwise (can be NULL; caller frees)
 * @return Error or NULL on success
 */
error_t *repo_create_target(
    const config_t *config,
    const char *explicit_path,
    char **out_path,
    char **out_elsewhere
);

/**
 * Open dotta repository
 *
 * Resolves the repository path and opens it, then holds dotta's own invariant:
 * HEAD on the `dotta-worktree` branch, recovered automatically when a manual
 * checkout moved it. This is the standard way to open a repository for dotta
 * commands — the pass-through (`dotta git`) is the one that deliberately does
 * not, taking only the path (`dotta_repo_mode_t` in include/runtime.h).
 *
 * RESOLUTION ORDER:
 * 1. DOTTA_REPO_DIR environment variable
 * 2. Config file repo_dir setting
 * 3. Default: ~/.local/share/dotta/repo
 *
 * THE OPEN IS THE PRESENCE TEST: there is no separate "is a repository here"
 * question — asking it means opening, and a predicate that opens and throws the
 * failure away reports "absent" for every reason an open can fail. So the open's
 * own failure is what gets classified, and only the one case that is genuinely
 * an absence is reworded:
 *
 * - ERR_NOT_FOUND — the path holds no git directory. Names the path, the hint
 *   to run 'dotta init', and DOTTA_REPO_DIR when the path came from it.
 * - ERR_GIT — a git directory is present but libgit2 could not read it (the same
 *   GIT_ENOTFOUND, told apart by the filesystem), or the open failed for its
 *   own reason — a config file that will not parse, a damaged object database —
 *   in which case libgit2's message is wrapped, not replaced.
 * - ERR_PERMISSION — the repository is owned by another user.
 *
 * OWNERSHIP:
 * - Caller must free repository with git_repository_free()
 * - Caller must free path_out (if requested) with free()
 * - On error, outputs are not modified
 *
 * @param config Loaded configuration (must not be NULL)
 * @param repo_out Repository handle (must not be NULL, caller must free)
 * @param path_out Optional resolved path (can be NULL, caller must free if set)
 * @return Error or NULL on success
 */
error_t *repo_open(const config_t *config, git_repository **repo_out, char **path_out);

#endif /* DOTTA_REPO_H */
