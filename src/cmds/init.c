/**
 * init.c - Initialize dotta repository
 */

#include "init.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/ignore.h"
#include "core/state.h"
#include "utils/config.h"
#include "utils/output.h"
#include "utils/repo.h"

/**
 * Initialize repository
 *
 * @param path Repository path
 * @param out Repository handle
 * @param is_new Set to true if a new repo was created, false if existing
 */
static error_t *init_repository(const char *path, git_repository **out, bool *is_new) {
    CHECK_NULL(path);
    CHECK_NULL(out);
    CHECK_NULL(is_new);

    git_repository *repo = NULL;
    int err;

    /* Try to open existing repository first */
    err = git_repository_open(&repo, path);
    if (err == 0) {
        /* Repository already exists */
        *out = repo;
        *is_new = false;
        return NULL;
    }

    /* Create new repository */
    git_repository_init_options opts;
    git_repository_init_options_init(&opts, GIT_REPOSITORY_INIT_OPTIONS_VERSION);
    opts.flags = GIT_REPOSITORY_INIT_MKPATH;

    err = git_repository_init_ext(&repo, path, &opts);
    if (err < 0) {
        return error_from_git(err);
    }

    *out = repo;
    *is_new = true;

    return NULL;
}

/**
 * Check if dotta is already initialized
 */
static error_t *is_initialized(git_repository *repo, bool *out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    *out = false;
    error_t *err = gitops_branch_exists(repo, "dotta-worktree", out);
    if (err) {
        return error_wrap(err, "Failed to check initialization status");
    }

    return NULL;
}

/**
 * Initialize dotta branch structure
 */
static error_t *init_branches(git_repository *repo, bool is_new_repo) {
    CHECK_NULL(repo);

    /* Create dotta-worktree branch (empty orphan branch) */
    error_t *err = gitops_create_orphan_branch(repo, "dotta-worktree");
    if (err) {
        return error_wrap(err, "Failed to create dotta-worktree branch");
    }

    /* Set HEAD to dotta-worktree */
    int git_err = git_repository_set_head(repo, "refs/heads/dotta-worktree");
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /*
     * Sync working directory with the (empty) dotta-worktree branch.
     *
     * FORCE is only safe for freshly-created repos where no user data exists.
     * For existing repos, use SAFE to avoid wiping uncommitted work.
     */
    git_checkout_strategy_t strategy = is_new_repo
        ? GIT_CHECKOUT_FORCE
        : GIT_CHECKOUT_SAFE;

    err = gitops_sync_worktree(repo, strategy);
    if (err) {
        return error_wrap(err, "Failed to checkout dotta-worktree");
    }

    return NULL;
}

/**
 * Initialize state file
 */
static error_t *init_state(git_repository *repo) {
    CHECK_NULL(repo);

    state_t *state = NULL;
    error_t *err = state_create_empty(&state);
    if (err) {
        return err;
    }

    err = state_save(repo, state);
    state_free(state);

    if (err) {
        return error_wrap(err, "Failed to save initial state");
    }

    return NULL;
}

/**
 * Create default .dottaignore file in dotta-worktree branch
 */
static error_t *init_dottaignore(git_repository *repo) {
    CHECK_NULL(repo);

    const char *content = ignore_default_dottaignore_content();

    /* Commit .dottaignore directly to the branch (no index/workdir needed) */
    error_t *err = gitops_update_file(
        repo,
        "dotta-worktree",
        ".dottaignore",
        content,
        strlen(content),
        "Initialize .dottaignore with default patterns",
        GIT_FILEMODE_BLOB,
        NULL
    );
    if (err) {
        return error_wrap(err, "Failed to commit .dottaignore");
    }

    /* Sync working directory so the file appears on disk */
    err = gitops_sync_worktree(repo, GIT_CHECKOUT_FORCE);
    if (err) {
        return error_wrap(
            err, "Failed to sync .dottaignore to working directory"
        );
    }

    return NULL;
}

/**
 * Initialize command implementation
 */
error_t *cmd_init(const cmd_init_options_t *opts) {
    CHECK_NULL(opts);

    git_repository *repo = NULL;
    error_t *err = NULL;
    char *resolved_path = NULL;
    const char *path = NULL;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        error_free(err);
        err = NULL;
        config = config_create_default();
    }

    /* Create output context from config */
    out = output_create_from_config(config);
    if (!out) {
        err = ERROR(ERR_MEMORY, "Failed to create output context");
        goto cleanup;
    }

    /* Handle quiet flag */
    if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Determine repository path */
    if (opts->repo_path) {
        /* User provided explicit path */
        path = opts->repo_path;
    } else {
        /* Use resolved repository location */
        err = resolve_repo_path(&resolved_path);
        if (err) {
            err = error_wrap(err, "Failed to resolve repository path");
            goto cleanup;
        }
        path = resolved_path;

        /* Ensure parent directories exist */
        err = fs_ensure_parent_dirs(path);
        if (err) {
            err = error_wrap(err, "Failed to create parent directories");
            goto cleanup;
        }
    }

    /* Initialize or open repository */
    bool is_new_repo = false;
    err = init_repository(path, &repo, &is_new_repo);
    if (err) {
        err = error_wrap(err, "Failed to initialize repository");
        goto cleanup;
    }

    /* Check if already initialized */
    bool initialized = false;
    err = is_initialized(repo, &initialized);
    if (err) {
        goto cleanup;
    }
    if (initialized) {
        output_info(out, "Dotta already initialized in this repository");
        goto cleanup;
    }

    /* Create branch structure */
    err = init_branches(repo, is_new_repo);
    if (err) {
        goto cleanup;
    }

    /* Create initial state */
    err = init_state(repo);
    if (err) {
        goto cleanup;
    }

    /* Create default .dottaignore */
    err = init_dottaignore(repo);
    if (err) {
        goto cleanup;
    }

    /* Success */
    output_success(out, "Initialized dotta repository in %s", path);
    output_newline(out);

    output_hint(out, "Next steps:");
    output_hint_line(out, "  1. Create a profile: dotta add --profile global ~/.bashrc");
    output_hint_line(out, "  2. Apply profiles: dotta apply");

cleanup:
    if (repo) git_repository_free(repo);
    if (resolved_path) free(resolved_path);
    if (out) output_free(out);
    if (config) config_free(config);

    return err;
}
