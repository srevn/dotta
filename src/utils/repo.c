/**
 * repo.c - Repository path resolution implementation
 */

#include "repo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "infra/path.h"
#include "utils/config.h"
#include "utils/privilege.h"

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

/**
 * Open dotta repository
 */
error_t *repo_open(git_repository **repo_out, char **path_out) {
    CHECK_NULL(repo_out);

    char *repo_path = NULL;
    git_repository *repo = NULL;
    error_t *err = NULL;

    /* Resolve repository path */
    err = resolve_repo_path(&repo_path);
    if (err) {
        return error_wrap(err, "Failed to resolve repository path");
    }

    /* Check if repository exists and is valid */
    if (!gitops_is_repository(repo_path)) {
        /* Build helpful error message with actionable hints */
        const char *env_repo = getenv("DOTTA_REPO_DIR");

        if (env_repo) {
            err = ERROR(ERR_NOT_FOUND,
                "No dotta repository found at: %s\n\n"
                "Run 'dotta init' to create a new repository\n"
                "Note: DOTTA_REPO_DIR is set to: %s",
                repo_path, env_repo);
        } else {
            err = ERROR(ERR_NOT_FOUND,
                "No dotta repository found at: %s\n\n"
                "Run 'dotta init' to create a new repository",
                repo_path);
        }

        free(repo_path);
        return err;
    }

    /* Open repository */
    err = gitops_open_repository(&repo, repo_path);
    if (err) {
        error_t *wrapped = error_wrap(err, "Failed to open repository at: %s",
                        repo_path);
        free(repo_path);
        return wrapped;
    }

    /* Success - set outputs */
    *repo_out = repo;
    if (path_out) {
        *path_out = repo_path;
    } else {
        free(repo_path);
    }

    return NULL;
}

/**
 * Fix repository ownership if running under sudo
 */
error_t *repo_fix_ownership_if_needed(const char *repo_path) {
    CHECK_NULL(repo_path);

    /* Early exit: only fix ownership when running under sudo
     * This is the common case - most operations don't need sudo */
    if (!privilege_is_sudo()) {
        return NULL;  /* No-op: not running under sudo */
    }

    /* We're running under sudo - need to fix ownership */

    /* Get the actual user's credentials (from SUDO_UID/SUDO_GID)
     * Delegates to privilege module for consistent sudo handling. */
    uid_t actual_uid = 0;
    gid_t actual_gid = 0;
    error_t *err = privilege_get_actual_user(&actual_uid, &actual_gid);
    if (err) {
        return error_wrap(err, "Failed to determine actual user for ownership fix");
    }

    /* Build path to .git directory */
    char *git_dir = NULL;
    err = fs_path_join(repo_path, ".git", &git_dir);
    if (err) {
        return error_wrap(err, "Failed to construct .git path");
    }

    /* Check if .git directory exists
     * If it doesn't exist, this is likely the init command creating a new repo.
     * In that case, there's nothing to fix - just return success. */
    if (!fs_is_directory(git_dir)) {
        free(git_dir);
        return NULL;  /* .git doesn't exist - nothing to fix */
    }

    /* Fix ownership recursively */
    size_t fixed_count = 0;
    size_t failed_count = 0;
    err = fs_fix_ownership_recursive(git_dir, actual_uid, actual_gid,
                                     &fixed_count, &failed_count);
    free(git_dir);

    if (err) {
        return error_wrap(err, "Failed to fix repository ownership");
    }

    /* Only warn if there were failures */
    if (failed_count > 0) {
        fprintf(stderr, "Warning: Failed to restore ownership for %zu files\n", failed_count);
    }

    return NULL;
}
