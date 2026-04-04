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
 * Validate remote URL structure
 *
 * Accepts:
 * - URL-style: https://, http://, ssh://, git://, file:// schemes
 * - SSH SCP-style: user@host:path (e.g., git@github.com:user/repo.git)
 * - Local paths: absolute (/path) or relative (./path, ../path)
 */
static bool validate_remote_url(const char *url) {
    if (!url || !*url) {
        return false;
    }

    /* Reject whitespace */
    for (const char *p = url; *p; p++) {
        if (isspace((unsigned char)*p)) {
            return false;
        }
    }

    /* URL-style: scheme://... */
    const char *scheme_end = strstr(url, "://");
    if (scheme_end) {
        size_t scheme_len = (size_t)(scheme_end - url);
        if ((scheme_len == 5 && strncmp(url, "https", 5) == 0) ||
            (scheme_len == 4 && strncmp(url, "http", 4) == 0) ||
            (scheme_len == 3 && strncmp(url, "ssh", 3) == 0) ||
            (scheme_len == 3 && strncmp(url, "git", 3) == 0) ||
            (scheme_len == 4 && strncmp(url, "file", 4) == 0)) {
            /* Must have something after scheme:// */
            return *(scheme_end + 3) != '\0';
        }
        return false;
    }

    /* SSH SCP-style: user@host:path */
    const char *at = strchr(url, '@');
    if (at && at > url) {
        const char *colon = strchr(at + 1, ':');
        if (colon && colon > at + 1 && *(colon + 1) != '\0') {
            return true;
        }
    }

    /* Local path: absolute or explicitly relative */
    if (url[0] == '/') {
        return true;
    }
    if (url[0] == '.' && (url[1] == '/' ||
        (url[1] == '.' && url[2] == '/'))) {
        return true;
    }

    return false;
}

/**
 * List remotes
 */
static error_t *remote_list(
    git_repository *repo,
    bool verbose
) {
    CHECK_NULL(repo);

    dotta_config_t *config = NULL;
    error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) {
        error_free(cfg_err);
        config = config_create_default();
    }
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
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

            output_styled(out, OUTPUT_NORMAL,
                "{cyan}%-15s{reset} %s (fetch)\n", remote_name, fetch_url);
            output_styled(out, OUTPUT_NORMAL,
                "{cyan}%-15s{reset} %s (push)\n", remote_name, push_url);

            git_remote_free(remote);
        } else {
            /* Just show names */
            output_styled(out, OUTPUT_NORMAL, "{cyan}%s{reset}\n", remote_name);
        }
    }

    output_newline(out);

    git_strarray_dispose(&remotes);
    config_free(config);
    output_free(out);
    return NULL;
}

/**
 * Add remote
 */
static error_t *remote_add(
    git_repository *repo,
    const char *name,
    const char *url
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(url);

    dotta_config_t *config = NULL;
    error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) {
        error_free(cfg_err);
        config = config_create_default();
    }
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* Validate remote name */
    if (!validate_remote_name(name)) {
        config_free(config);
        output_free(out);
        return ERROR(ERR_INVALID_ARG, "Invalid remote name '%s'\n"
            "Only letters, numbers, hyphens, and underscores allowed", name);
    }

    /* Validate URL */
    if (!validate_remote_url(url)) {
        config_free(config);
        output_free(out);
        return ERROR(ERR_INVALID_ARG, "Invalid remote URL '%s'\n"
            "Expected: https://..., git@host:path, ssh://..., or /local/path",
            url);
    }

    /* Check if remote already exists */
    git_remote *existing = NULL;
    int git_err = git_remote_lookup(&existing, repo, name);
    if (git_err == 0) {
        /* Remote exists */
        git_remote_free(existing);
        config_free(config);
        output_free(out);
        return ERROR(ERR_EXISTS, "Remote '%s' already exists\n"
            "Hint: Use 'dotta remote set-url %s <url>' to change the URL", name, name);
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
    output_success(out, "Remote '{cyan}%s{reset}' added successfully", name);

    config_free(config);
    output_free(out);
    return NULL;
}

/**
 * Remove remote
 */
static error_t *remote_remove(
    git_repository *repo,
    const char *name
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    dotta_config_t *config = NULL;
    error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) {
        error_free(cfg_err);
        config = config_create_default();
    }
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* Check if remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, name);
    if (git_err == GIT_ENOTFOUND) {
        config_free(config);
        output_free(out);
        return ERROR(ERR_NOT_FOUND, "Remote '%s' not found", name);
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
    output_success(out, "Removed remote '{cyan}%s{reset}'", name);

    config_free(config);
    output_free(out);
    return NULL;
}

/**
 * Set remote URL
 */
static error_t *remote_set_url(
    git_repository *repo,
    const char *name,
    const char *new_url
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(new_url);

    dotta_config_t *config = NULL;
    error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) {
        error_free(cfg_err);
        config = config_create_default();
    }
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* Validate URL */
    if (!validate_remote_url(new_url)) {
        config_free(config);
        output_free(out);
        return ERROR(ERR_INVALID_ARG, "Invalid remote URL '%s'\n"
            "Expected: https://..., git@host:path, ssh://..., or /local/path",
            new_url);
    }

    /* Check if remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, name);
    if (git_err == GIT_ENOTFOUND) {
        config_free(config);
        output_free(out);
        return ERROR(ERR_NOT_FOUND, "Remote '%s' not found", name);
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
    output_success(out, "Remote '{cyan}%s{reset}' URL updated", name);

    config_free(config);
    output_free(out);
    return NULL;
}

/**
 * Rename remote
 */
static error_t *remote_rename(
    git_repository *repo,
    const char *old_name,
    const char *new_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(old_name);
    CHECK_NULL(new_name);

    dotta_config_t *config = NULL;
    error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) {
        error_free(cfg_err);
        config = config_create_default();
    }
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* Validate new name */
    if (!validate_remote_name(new_name)) {
        config_free(config);
        output_free(out);
        return ERROR(ERR_INVALID_ARG, "Invalid remote name '%s'\n"
            "Only letters, numbers, hyphens, and underscores allowed", new_name);
    }

    /* Check if old remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, old_name);
    if (git_err == GIT_ENOTFOUND) {
        config_free(config);
        output_free(out);
        return ERROR(ERR_NOT_FOUND, "Remote '%s' not found", old_name);
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
        return ERROR(ERR_EXISTS, "Remote '%s' already exists", new_name);
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
            output_print(out, OUTPUT_NORMAL, "  %s\n", problems.strings[i]);
        }
    }

    git_strarray_dispose(&problems);

    if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }

    /* Success message */
    output_success(out, "Renamed remote '{cyan}%s{reset}' to '{cyan}%s{reset}'",
        old_name, new_name);

    config_free(config);
    output_free(out);
    return NULL;
}

/**
 * Show remote details
 */
static error_t *remote_show(
    git_repository *repo,
    const char *name
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    dotta_config_t *config = NULL;
    error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) {
        error_free(cfg_err);
        config = config_create_default();
    }
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* Lookup remote */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, name);
    if (git_err == GIT_ENOTFOUND) {
        config_free(config);
        output_free(out);
        return ERROR(ERR_NOT_FOUND, "Remote '%s' not found", name);
    } else if (git_err < 0) {
        config_free(config);
        output_free(out);
        return error_from_git(git_err);
    }

    /* Show remote information */
    output_styled(out, OUTPUT_NORMAL, "Remote: {cyan}%s{reset}\n", name);

    const char *fetch_url = git_remote_url(remote);
    const char *push_url = git_remote_pushurl(remote);

    if (!push_url) {
        push_url = fetch_url;
    }

    output_print(out, OUTPUT_NORMAL, "  Fetch URL: %s\n", fetch_url);
    output_print(out, OUTPUT_NORMAL, "  Push URL:  %s\n", push_url);

    /* Show fetch refspecs */
    git_strarray refspecs = {0};
    git_err = git_remote_get_fetch_refspecs(&refspecs, remote);
    if (git_err == 0 && refspecs.count > 0) {
        output_print(out, OUTPUT_NORMAL, "  Fetch refspecs:\n");
        for (size_t i = 0; i < refspecs.count; i++) {
            output_print(out, OUTPUT_NORMAL, "    %s\n", refspecs.strings[i]);
        }
    }
    if (git_err == 0) {
        git_strarray_dispose(&refspecs);
    }

    /* Show push refspecs */
    memset(&refspecs, 0, sizeof(refspecs));
    git_err = git_remote_get_push_refspecs(&refspecs, remote);
    if (git_err == 0 && refspecs.count > 0) {
        output_print(out, OUTPUT_NORMAL, "  Push refspecs:\n");
        for (size_t i = 0; i < refspecs.count; i++) {
            output_print(out, OUTPUT_NORMAL, "    %s\n", refspecs.strings[i]);
        }
    }
    if (git_err == 0) {
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
error_t *cmd_remote(
    git_repository *repo,
    const cmd_remote_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    switch (opts->subcommand) {
        case REMOTE_LIST:
            return remote_list(repo, opts->verbose);

        case REMOTE_ADD:
            if (!opts->name || !opts->url) {
                return ERROR(ERR_INVALID_ARG,
                            "Remote name and URL are required");
            }
            return remote_add(repo, opts->name, opts->url);

        case REMOTE_REMOVE:
            if (!opts->name) {
                return ERROR(ERR_INVALID_ARG, "Remote name is required");
            }
            return remote_remove(repo, opts->name);

        case REMOTE_SET_URL:
            if (!opts->name || !opts->url) {
                return ERROR(ERR_INVALID_ARG,
                            "Remote name and new URL are required");
            }
            return remote_set_url(repo, opts->name, opts->url);

        case REMOTE_RENAME:
            if (!opts->name || !opts->new_name) {
                return ERROR(ERR_INVALID_ARG,
                            "Old and new remote names are required");
            }
            return remote_rename(repo, opts->name, opts->new_name);

        case REMOTE_SHOW:
            if (!opts->name) {
                return ERROR(ERR_INVALID_ARG, "Remote name is required");
            }
            return remote_show(repo, opts->name);

        default:
            return ERROR(ERR_INVALID_ARG, "Unknown remote subcommand");
    }
}
