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

#include <stdbool.h>

#include "dotta/types.h"

/* Forward declarations */
typedef struct git_repository git_repository;

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
dotta_error_t *resolve_repo_path(char **out);

/**
 * Get default repository path
 *
 * Returns: ~/.local/share/dotta/repo
 *
 * @param out Default repository path (caller must free)
 * @return Error or NULL on success
 */
dotta_error_t *get_default_repo_path(char **out);

/**
 * Check if path is a valid git repository
 *
 * @param path Path to check
 * @return true if path exists and is a valid git repository
 */
bool is_git_repository(const char *path);

/**
 * Ensure parent directories exist
 *
 * Creates all parent directories for the given path if they don't exist.
 * Similar to `mkdir -p $(dirname path)`.
 *
 * @param path Full path to file/directory
 * @return Error or NULL on success
 */
dotta_error_t *ensure_parent_dirs(const char *path);

#endif /* DOTTA_REPO_H */
