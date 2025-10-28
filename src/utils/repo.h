/**
 * repo.h - Repository path resolution
 *
 * Determines which dotta repository to use based on:
 * 1. DOTTA_REPO_DIR environment variable (highest priority)
 * 2. Config file setting (~/.config/dotta/config.toml)
 * 3. Default location: ~/.local/share/dotta/repo
 *
 * This is different from git's behavior - dotta uses a centralized
 * repository, not discovery from current working directory.
 */

#ifndef DOTTA_REPO_H
#define DOTTA_REPO_H

#include <git2.h>
#include <stdbool.h>

#include "types.h"

/**
 * Resolve repository path
 *
 * Determines the dotta repository location based on:
 * 1. DOTTA_REPO_DIR environment variable
 * 2. Config file repo_dir setting
 * 3. Default: ~/.local/share/dotta/repo
 *
 * The path is always expanded (~ becomes absolute path).
 * If the config file exists but fails to parse/validate, falls back
 * to the default path to ensure the application remains usable.
 *
 * @param out Resolved repository path (caller must free)
 * @return Error or NULL on success
 */
error_t *resolve_repo_path(char **out);

/**
 * Get default repository path
 *
 * Returns: ~/.local/share/dotta/repo
 *
 * @param out Default repository path (caller must free)
 * @return Error or NULL on success
 */
error_t *get_default_repo_path(char **out);

/**
 * Open dotta repository
 *
 * Resolves the repository path, validates it exists and is a valid git
 * repository, then opens it. This is the standard way to open a repository
 * for dotta commands.
 *
 * RESOLUTION ORDER:
 * 1. DOTTA_REPO_DIR environment variable
 * 2. Config file repo_dir setting
 * 3. Default: ~/.local/share/dotta/repo
 *
 * VALIDATION:
 * - Checks path exists and is a valid git repository
 * - Returns detailed error with helpful hints if not found
 * - Includes DOTTA_REPO_DIR hint in error if set
 *
 * ERROR MESSAGES:
 * If repository not found, error includes:
 * - Path that was checked
 * - Hint to run 'dotta init'
 * - DOTTA_REPO_DIR value if set
 *
 * OWNERSHIP:
 * - Caller must free repository with git_repository_free()
 * - Caller must free path_out (if requested) with free()
 * - On error, outputs are not modified
 *
 * @param repo_out Repository handle (must not be NULL, caller must free)
 * @param path_out Optional resolved path (can be NULL, caller must free if set)
 * @return Error or NULL on success
 */
error_t *repo_open(git_repository **repo_out, char **path_out);

/**
 * Fix repository ownership if running under sudo
 *
 * Automatically restores normal user ownership of the .git directory when
 * dotta commands are run via sudo. This prevents "Permission denied" errors
 * on subsequent non-sudo runs.
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
 * 4. Recursively fixes ownership of .git/ directory
 * 5. Logs statistics (files fixed/failed) to stderr
 *
 * ERROR HANDLING:
 * - Individual file failures: Logged, operation continues
 * - Fatal errors (can't get user, .git missing): Returns error
 * - Non-fatal: Even if some files fail, most will be fixed
 *
 * @param repo_path Repository base path (e.g., ~/.local/share/dotta/repo)
 *                  Must not be NULL, must be a valid dotta repository
 * @return Error on fatal failures, NULL on success
 */
error_t *repo_fix_ownership_if_needed(const char *repo_path);

#endif /* DOTTA_REPO_H */
