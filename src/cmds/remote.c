/**
 * remote.c - Manage remote repositories
 */

#include "remote.h"

#include <ctype.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"

/**
 * Validate remote name
 *
 * Remote names must be alphanumeric with hyphens and underscores only.
 */
static bool validate_remote_name(const char *name) {
    if (!name || name[0] == '\0') {
        return false;
    }

    for (const char *p = name; *p; p++) {
        if (!isalnum(*p) && *p != '-' && *p != '_') {
            return false;
        }
    }

    return true;
}

/**
 * Validate remote URL (basic validation)
 *
 * Accepts:
 * - SSH: git@github.com:user/repo.git
 * - HTTPS: https://github.com/user/repo.git
 * - File paths: /path/to/repo
 */
static bool validate_remote_url(const char *url) {
    if (!url || url[0] == '\0') {
        return false;
    }

    /* Basic validation - just check it's not empty */
    /* libgit2 will do the real validation */
    return strlen(url) > 0;
}

/**
 * List remotes
 */
static dotta_error_t *remote_list(git_repository *repo, bool verbose) {
    CHECK_NULL(repo);

    dotta_config_t *config = NULL;
    dotta_error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) config = config_create_default();
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create output context");
    }

    git_strarray remotes = {0};
    int git_err = git_remote_list(&remotes, repo);
    if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }

    if (remotes.count == 0) {
        output_info(out, "No remotes configured");
        git_strarray_dispose(&remotes);
        config_free(config);
        output_free(out);
        return NULL;
    }

    /* List each remote */
    for (size_t i = 0; i < remotes.count; i++) {
        const char *remote_name = remotes.strings[i];

        if (verbose) {
            /* Show URLs for fetch and push */
            git_remote *remote = NULL;
            git_err = git_remote_lookup(&remote, repo, remote_name);
            if (git_err < 0) {
                git_strarray_dispose(&remotes);
                config_free(config);
        output_free(out);
                return error_from_git(git_err);
            }

            const char *fetch_url = git_remote_url(remote);
            const char *push_url = git_remote_pushurl(remote);

            /* Use fetch URL for push if push URL not set */
            if (!push_url) {
                push_url = fetch_url;
            }

            char *colored_name = output_colorize(out, OUTPUT_COLOR_CYAN, remote_name);
            if (colored_name) {
                printf("%-15s %s (fetch)\n", colored_name, fetch_url);
                printf("%-15s %s (push)\n", colored_name, push_url);
                free(colored_name);
            } else {
                printf("%-15s %s (fetch)\n", remote_name, fetch_url);
                printf("%-15s %s (push)\n", remote_name, push_url);
            }

            git_remote_free(remote);
        } else {
            /* Just show names */
            char *colored_name = output_colorize(out, OUTPUT_COLOR_CYAN, remote_name);
            if (colored_name) {
                printf("%s\n", colored_name);
                free(colored_name);
            } else {
                printf("%s\n", remote_name);
            }
        }
    }

    printf("\n");

    git_strarray_dispose(&remotes);
    config_free(config);
        output_free(out);
    return NULL;
}

/**
 * Add remote
 */
static dotta_error_t *remote_add(
    git_repository *repo,
    const char *name,
    const char *url
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(url);

    dotta_config_t *config = NULL;
    dotta_error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) config = config_create_default();
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create output context");
    }

    /* Validate remote name */
    if (!validate_remote_name(name)) {
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_INVALID_ARG,
                    "Invalid remote name '%s'\n"
                    "Remote names must contain only letters, numbers, hyphens, and underscores",
                    name);
    }

    /* Validate URL */
    if (!validate_remote_url(url)) {
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid remote URL");
    }

    /* Check if remote already exists */
    git_remote *existing = NULL;
    int git_err = git_remote_lookup(&existing, repo, name);
    if (git_err == 0) {
        /* Remote exists */
        git_remote_free(existing);
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_EXISTS,
                    "Remote '%s' already exists\n"
                    "Hint: Use 'dotta remote set-url %s <url>' to change the URL",
                    name, name);
    } else if (git_err != GIT_ENOTFOUND) {
        /* Unexpected error */
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }

    /* Create remote */
    git_remote *remote = NULL;
    git_err = git_remote_create(&remote, repo, name, url);
    if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }

    git_remote_free(remote);

    /* Success message */
    char *colored_name = output_colorize(out, OUTPUT_COLOR_CYAN, name);
    if (colored_name) {
        output_success(out, "Remote '%s' added successfully", colored_name);
        free(colored_name);
    } else {
        output_success(out, "Remote '%s' added successfully", name);
    }

    config_free(config);
        output_free(out);
    return NULL;
}

/**
 * Remove remote
 */
static dotta_error_t *remote_remove(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    dotta_config_t *config = NULL;
    dotta_error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) config = config_create_default();
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create output context");
    }

    /* Check if remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, name);
    if (git_err == GIT_ENOTFOUND) {
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_NOT_FOUND, "Remote '%s' not found", name);
    } else if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }
    git_remote_free(remote);

    /* Delete remote */
    git_err = git_remote_delete(repo, name);
    if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }

    /* Success message */
    char *colored_name = output_colorize(out, OUTPUT_COLOR_CYAN, name);
    if (colored_name) {
        output_success(out, "Removed remote '%s'", colored_name);
        free(colored_name);
    } else {
        output_success(out, "Removed remote '%s'", name);
    }

    config_free(config);
        output_free(out);
    return NULL;
}

/**
 * Set remote URL
 */
static dotta_error_t *remote_set_url(
    git_repository *repo,
    const char *name,
    const char *new_url
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(new_url);

    dotta_config_t *config = NULL;
    dotta_error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) config = config_create_default();
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create output context");
    }

    /* Validate URL */
    if (!validate_remote_url(new_url)) {
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid remote URL");
    }

    /* Check if remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, name);
    if (git_err == GIT_ENOTFOUND) {
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_NOT_FOUND, "Remote '%s' not found", name);
    } else if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }
    git_remote_free(remote);

    /* Set new URL */
    git_err = git_remote_set_url(repo, name, new_url);
    if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }

    /* Success message */
    char *colored_name = output_colorize(out, OUTPUT_COLOR_CYAN, name);
    if (colored_name) {
        output_success(out, "Remote '%s' URL updated", colored_name);
        free(colored_name);
    } else {
        output_success(out, "Remote '%s' URL updated", name);
    }

    config_free(config);
        output_free(out);
    return NULL;
}

/**
 * Rename remote
 */
static dotta_error_t *remote_rename(
    git_repository *repo,
    const char *old_name,
    const char *new_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(old_name);
    CHECK_NULL(new_name);

    dotta_config_t *config = NULL;
    dotta_error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) config = config_create_default();
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create output context");
    }

    /* Validate new name */
    if (!validate_remote_name(new_name)) {
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_INVALID_ARG,
                    "Invalid remote name '%s'\n"
                    "Remote names must contain only letters, numbers, hyphens, and underscores",
                    new_name);
    }

    /* Check if old remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, old_name);
    if (git_err == GIT_ENOTFOUND) {
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_NOT_FOUND, "Remote '%s' not found", old_name);
    } else if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }
    git_remote_free(remote);

    /* Check if new name already exists */
    git_err = git_remote_lookup(&remote, repo, new_name);
    if (git_err == 0) {
        git_remote_free(remote);
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_EXISTS, "Remote '%s' already exists", new_name);
    } else if (git_err != GIT_ENOTFOUND) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }

    /* Rename remote */
    git_strarray problems = {0};
    git_err = git_remote_rename(&problems, repo, old_name, new_name);

    if (problems.count > 0) {
        /* Show warnings about problematic refspecs */
        output_warning(out, "The following refspecs could not be updated:");
        for (size_t i = 0; i < problems.count; i++) {
            fprintf(stderr, "  %s\n", problems.strings[i]);
        }
    }

    git_strarray_dispose(&problems);

    if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }

    /* Success message */
    char *old_colored = output_colorize(out, OUTPUT_COLOR_CYAN, old_name);
    char *new_colored = output_colorize(out, OUTPUT_COLOR_CYAN, new_name);
    if (old_colored && new_colored) {
        output_success(out, "Renamed remote '%s' to '%s'", old_colored, new_colored);
        free(old_colored);
        free(new_colored);
    } else {
        output_success(out, "Renamed remote '%s' to '%s'", old_name, new_name);
    }

    config_free(config);
        output_free(out);
    return NULL;
}

/**
 * Show remote details
 */
static dotta_error_t *remote_show(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    dotta_config_t *config = NULL;
    dotta_error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) config = config_create_default();
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create output context");
    }

    /* Lookup remote */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, name);
    if (git_err == GIT_ENOTFOUND) {
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_NOT_FOUND, "Remote '%s' not found", name);
    } else if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }

    /* Show remote information */
    char *colored_name = output_colorize(out, OUTPUT_COLOR_CYAN, name);
    if (colored_name) {
        output_section(out, NULL);
        printf("Remote: %s\n", colored_name);
        free(colored_name);
    } else {
        output_section(out, NULL);
        printf("Remote: %s\n", name);
    }

    const char *fetch_url = git_remote_url(remote);
    const char *push_url = git_remote_pushurl(remote);

    if (!push_url) {
        push_url = fetch_url;
    }

    printf("  Fetch URL: %s\n", fetch_url);
    printf("  Push URL:  %s\n", push_url);

    /* Show tracked branches */
    git_strarray refspecs;
    git_err = git_remote_get_fetch_refspecs(&refspecs, remote);
    if (git_err == 0 && refspecs.count > 0) {
        printf("  Fetch refspecs:\n");
        for (size_t i = 0; i < refspecs.count; i++) {
            printf("    %s\n", refspecs.strings[i]);
        }
        git_strarray_dispose(&refspecs);
    }

    git_remote_free(remote);
    config_free(config);
        output_free(out);
    return NULL;
}

/**
 * Remote command implementation
 */
dotta_error_t *cmd_remote(git_repository *repo, const cmd_remote_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    switch (opts->subcommand) {
        case REMOTE_LIST:
            return remote_list(repo, opts->verbose);

        case REMOTE_ADD:
            if (!opts->name || !opts->url) {
                return ERROR(DOTTA_ERR_INVALID_ARG,
                            "Remote name and URL are required");
            }
            return remote_add(repo, opts->name, opts->url);

        case REMOTE_REMOVE:
            if (!opts->name) {
                return ERROR(DOTTA_ERR_INVALID_ARG, "Remote name is required");
            }
            return remote_remove(repo, opts->name);

        case REMOTE_SET_URL:
            if (!opts->name || !opts->url) {
                return ERROR(DOTTA_ERR_INVALID_ARG,
                            "Remote name and new URL are required");
            }
            return remote_set_url(repo, opts->name, opts->url);

        case REMOTE_RENAME:
            if (!opts->name || !opts->new_name) {
                return ERROR(DOTTA_ERR_INVALID_ARG,
                            "Old and new remote names are required");
            }
            return remote_rename(repo, opts->name, opts->new_name);

        case REMOTE_SHOW:
            if (!opts->name) {
                return ERROR(DOTTA_ERR_INVALID_ARG, "Remote name is required");
            }
            return remote_show(repo, opts->name);

        default:
            return ERROR(DOTTA_ERR_INVALID_ARG, "Unknown remote subcommand");
    }
}
