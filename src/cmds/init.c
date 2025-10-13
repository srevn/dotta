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
#include "utils/buffer.h"
#include "utils/repo.h"
#include "utils/string.h"

/**
 * Initialize repository
 */
static error_t *init_repository(const char *path, git_repository **out) {
    CHECK_NULL(path);
    CHECK_NULL(out);

    git_repository *repo = NULL;
    int err;

    /* Try to open existing repository first */
    err = git_repository_open(&repo, path);
    if (err == 0) {
        /* Repository already exists */
        *out = repo;
        return NULL;
    }

    /* Create new repository */
    git_repository_init_options opts = GIT_REPOSITORY_INIT_OPTIONS_INIT;
    opts.flags = GIT_REPOSITORY_INIT_MKPATH;

    err = git_repository_init_ext(&repo, path, &opts);
    if (err < 0) {
        return error_from_git(err);
    }

    *out = repo;
    return NULL;
}

/**
 * Check if dotta is already initialized
 */
static bool is_initialized(git_repository *repo) {
    bool exists = false;
    error_t *err = gitops_branch_exists(repo, "dotta-worktree", &exists);
    if (err) {
        error_free(err);
        return false;
    }
    return exists;
}

/**
 * Initialize dotta branch structure
 */
static error_t *init_branches(git_repository *repo) {
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

    /* Get repository path */
    const char *repo_path = git_repository_workdir(repo);
    if (!repo_path) {
        return ERROR(ERR_INTERNAL, "Repository has no working directory");
    }

    /* Build path to .dottaignore */
    char *dottaignore_path = str_format("%s/.dottaignore", repo_path);
    if (!dottaignore_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate .dottaignore path");
    }

    /* Create buffer with default content */
    const char *default_content = ignore_default_dottaignore_content();
    buffer_t *content = buffer_create();
    if (!content) {
        free(dottaignore_path);
        return ERROR(ERR_MEMORY, "Failed to create buffer");
    }

    error_t *err = buffer_append(content, (const uint8_t *)default_content, strlen(default_content));
    if (err) {
        buffer_free(content);
        free(dottaignore_path);
        return error_wrap(err, "Failed to populate buffer");
    }

    /* Write to file */
    err = fs_write_file(dottaignore_path, content);
    buffer_free(content);
    if (err) {
        free(dottaignore_path);
        return error_wrap(err, "Failed to write .dottaignore");
    }

    /* Stage the file */
    git_index *index = NULL;
    err = gitops_get_index(repo, &index);
    if (err) {
        free(dottaignore_path);
        return error_wrap(err, "Failed to get index");
    }

    int git_err = git_index_add_bypath(index, ".dottaignore");
    if (git_err < 0) {
        git_index_free(index);
        free(dottaignore_path);
        return error_from_git(git_err);
    }

    git_err = git_index_write(index);
    if (git_err < 0) {
        git_index_free(index);
        free(dottaignore_path);
        return error_from_git(git_err);
    }

    /* Create tree from index */
    git_oid tree_oid;
    git_err = git_index_write_tree(&tree_oid, index);
    git_index_free(index);
    if (git_err < 0) {
        free(dottaignore_path);
        return error_from_git(git_err);
    }

    /* Load tree */
    git_tree *tree = NULL;
    git_err = git_tree_lookup(&tree, repo, &tree_oid);
    if (git_err < 0) {
        free(dottaignore_path);
        return error_from_git(git_err);
    }

    /* Create commit */
    err = gitops_create_commit(
        repo,
        "dotta-worktree",
        tree,
        "Initialize .dottaignore with default patterns",
        NULL
    );

    git_tree_free(tree);
    free(dottaignore_path);

    if (err) {
        return error_wrap(err, "Failed to commit .dottaignore");
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

    /* Determine repository path */
    if (opts->repo_path) {
        /* User provided explicit path */
        path = opts->repo_path;
    } else {
        /* Use resolved repository location */
        err = resolve_repo_path(&resolved_path);
        if (err) {
            return error_wrap(err, "Failed to resolve repository path");
        }
        path = resolved_path;

        /* Ensure parent directories exist */
        err = ensure_parent_dirs(path);
        if (err) {
            free(resolved_path);
            return error_wrap(err, "Failed to create parent directories");
        }
    }

    /* Initialize or open repository */
    err = init_repository(path, &repo);
    if (err) {
        if (resolved_path) free(resolved_path);
        return error_wrap(err, "Failed to initialize repository");
    }

    /* Check if already initialized */
    if (is_initialized(repo)) {
        git_repository_free(repo);
        if (resolved_path) free(resolved_path);
        if (!opts->quiet) {
            printf("Dotta already initialized in this repository\n");
        }
        return NULL;
    }

    /* Create branch structure */
    err = init_branches(repo);
    if (err) {
        git_repository_free(repo);
        if (resolved_path) free(resolved_path);
        return err;
    }

    /* Create initial state */
    err = init_state(repo);
    if (err) {
        git_repository_free(repo);
        if (resolved_path) free(resolved_path);
        return err;
    }

    /* Create default .dottaignore */
    err = init_dottaignore(repo);
    if (err) {
        git_repository_free(repo);
        if (resolved_path) free(resolved_path);
        return err;
    }

    /* Success */
    git_repository_free(repo);

    if (!opts->quiet) {
        printf("Initialized dotta repository in %s\n", path);
        printf("\nNext steps:\n");
        printf("  1. Create a profile: dotta add --profile global ~/.bashrc\n");
        printf("  2. Apply profiles: dotta apply\n");
        printf("\n");
    }

    if (resolved_path) free(resolved_path);
    return NULL;
}
