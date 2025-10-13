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

#endif /* DOTTA_REPO_H */
