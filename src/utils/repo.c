/**
 * repo.c - Repository path resolution implementation
 */

#include "repo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "infra/path.h"
#include "utils/config.h"

/**
 * Get default repository path
 */
error_t *get_default_repo_path(char **out) {
    CHECK_NULL(out);

    /* Get HOME directory */
    char *home = NULL;
    error_t *err = path_get_home(&home);
    if (err) {
        return error_wrap(err, "Failed to determine HOME directory");
    }

    /* Build path: ~/.local/share/dotta/repo */
    size_t len = strlen(home) + strlen("/.local/share/dotta/repo") + 1;
    char *path = malloc(len);
    if (!path) {
        free(home);
        return ERROR(ERR_MEMORY, "Failed to allocate default repo path");
    }

    snprintf(path, len, "%s/.local/share/dotta/repo", home);
    free(home);

    *out = path;
    return NULL;
}

/**
 * Resolve repository path
 */
error_t *resolve_repo_path(char **out) {
    CHECK_NULL(out);

    dotta_config_t *config = NULL;
    error_t *err = NULL;
    char *repo_dir = NULL;

    /* Load configuration
     * Note: config_load returns default config if file doesn't exist,
     * so this is safe and won't fail for missing config files.
     * If config parsing fails, we fall back to default path.
     */
    err = config_load(NULL, &config);
    if (err) {
        /* Config file exists but failed to parse/validate.
         * Log the issue but fall back to default path gracefully.
         * This ensures the application remains usable even with
         * a broken config file.
         */
        error_free(err);
        return get_default_repo_path(out);
    }

    /* Get repository directory using full priority chain:
     * 1. DOTTA_REPO_DIR environment variable
     * 2. Config file repo_dir setting
     * 3. Default: ~/.local/share/dotta/repo
     */
    err = config_get_repo_dir(config, &repo_dir);
    config_free(config);

    if (err) {
        /* Path expansion failed (e.g., invalid home directory).
         * This is a genuine error that should be propagated.
         */
        return error_wrap(err, "Failed to resolve repository path");
    }

    *out = repo_dir;
    return NULL;
}
