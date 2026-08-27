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

/**
 * Fix repository ownership if running under sudo
 *
 * Automatically restores normal user ownership of the repository directory and
 * .git/ contents when dotta commands are run via sudo. This prevents "Permission
 * denied" errors and libgit2 ownership validation failures (CVE-2022-24765) on
 * subsequent non-sudo runs.
 *
 * WHEN TO CALL:
 * - Call this at process exit, after all Git operations complete
 * - Only effective when running under sudo (detected automatically)
 * - Safe to call always - it's a no-op when not under sudo
 *
 * BEHAVIOR:
 * 1. Checks if running under sudo (via privilege_is_sudo())
 * 2. If not sudo: returns immediately (no-op)
 * 3. If sudo: gets original user's UID/GID from SUDO_UID/SUDO_GID
 * 4. Fixes ownership of the repository directory itself
 * 5. Recursively fixes ownership of .git/ directory
 * 6. Logs statistics (files fixed/failed) to stderr
 *
 * ERROR HANDLING:
 * - Individual file failures: Logged, operation continues
 * - Fatal errors (can't get user, .git missing): Returns error
 * - Non-fatal: Even if some files fail, most will be fixed
 *
 * @param repo_path Repository base path (e.g., ~/.local/share/dotta/repo) Must
 *                  not be NULL, must be a valid dotta repository
 * @return Error on fatal failures, NULL on success
 */
error_t *repo_fix_ownership_if_needed(const char *repo_path);

#endif /* DOTTA_REPO_H */
