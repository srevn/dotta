/**
 * worktree.c - Temporary git worktree management implementation
 *
 * Critical resource management:
 * - Worktrees must always be cleaned up
 * - Cleanup order matters: index -> repo -> worktree -> directory
 * - Safe to call cleanup multiple times
 */

#include "worktree.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "utils/string.h"

/**
 * Worktree handle structure
 */
struct worktree_handle {
    char *name;                /* Worktree name (unique) */
    char *path;                /* Filesystem path */
    git_repository *repo;      /* Worktree repository */
    git_worktree *worktree;    /* libgit2 worktree object */
    git_repository *main_repo; /* Reference to main repo */
    bool cleaned_up;           /* Cleanup already called? */
};

/**
 * Generate unique worktree name
 */
static char *generate_worktree_name(void) {
    /* Use process ID and microsecond timestamp for uniqueness */
    struct timeval tv;
    gettimeofday(&tv, NULL);

    pid_t pid = getpid();
    long usec = tv.tv_sec * 1000000L + tv.tv_usec;

    char *name = malloc(64);
    if (!name) {
        return NULL;
    }

    snprintf(name, 64, "dotta-temp-%d-%ld", pid, usec);
    return name;
}

/**
 * Generate temporary directory path from name
 */
static dotta_error_t *generate_temp_path_from_name(const char *name, char **out) {
    CHECK_NULL(name);
    CHECK_NULL(out);

    /* Get temp directory */
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = getenv("TEMP");
    if (!tmpdir) tmpdir = getenv("TMP");
    if (!tmpdir) tmpdir = "/tmp";

    /* Join path */
    return fs_path_join(tmpdir, name, out);
}

dotta_error_t *worktree_create_temp(
    git_repository *repo,
    worktree_handle_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    /* Allocate handle */
    worktree_handle_t *wt = calloc(1, sizeof(worktree_handle_t));
    if (!wt) {
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate worktree handle");
    }

    wt->main_repo = repo;
    wt->cleaned_up = false;

    /* Generate unique name */
    wt->name = generate_worktree_name();
    if (!wt->name) {
        free(wt);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to generate worktree name");
    }

    /* Generate temp path from the same name */
    dotta_error_t *err = generate_temp_path_from_name(wt->name, &wt->path);
    if (err) {
        free(wt->name);
        free(wt);
        return err;
    }


    /* Check if directory already exists from failed previous run */
    if (fs_is_directory(wt->path)) {
        err = fs_remove_dir(wt->path, true);
        if (err) {
            free(wt->path);
            free(wt->name);
            free(wt);
            return error_wrap(err, "Failed to remove existing temp directory");
        }
    }

    /* Create worktree using libgit2 (it will create the directory) */
    git_worktree_add_options opts = GIT_WORKTREE_ADD_OPTIONS_INIT;

    int git_err = git_worktree_add(&wt->worktree, repo, wt->name, wt->path, &opts);
    if (git_err < 0) {
        fs_remove_dir(wt->path, true);  /* Cleanup directory */
        free(wt->path);
        free(wt->name);
        free(wt);
        return error_from_git(git_err);
    }

    /* Open repository from worktree */
    git_err = git_repository_open_from_worktree(&wt->repo, wt->worktree);
    if (git_err < 0) {
        git_worktree_prune_options prune_opts = {0};
        prune_opts.version = 1;
        prune_opts.flags = GIT_WORKTREE_PRUNE_VALID;
        git_worktree_prune(wt->worktree, &prune_opts);
        git_worktree_free(wt->worktree);
        fs_remove_dir(wt->path, true);
        free(wt->path);
        free(wt->name);
        free(wt);
        return error_from_git(git_err);
    }

    *out = wt;
    return NULL;
}

dotta_error_t *worktree_checkout_branch(
    worktree_handle_t *wt,
    const char *branch_name
) {
    CHECK_NULL(wt);
    CHECK_NULL(branch_name);

    if (wt->cleaned_up) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Worktree already cleaned up");
    }

    /* Build reference name dynamically to support long branch names */
    char *refname = str_format("refs/heads/%s", branch_name);
    if (!refname) {
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate reference name");
    }

    /* Find the commit for the branch */
    git_object *commit = NULL;
    int err = git_revparse_single(&commit, wt->repo, refname);
    if (err < 0) {
        free(refname);
        return error_from_git(err);
    }

    /* Checkout */
    git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
    checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;

    err = git_checkout_tree(wt->repo, commit, &checkout_opts);
    git_object_free(commit);
    if (err < 0) {
        free(refname);
        return error_from_git(err);
    }

    /* Update HEAD */
    err = git_repository_set_head(wt->repo, refname);
    free(refname);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

dotta_error_t *worktree_create_orphan(
    worktree_handle_t *wt,
    const char *branch_name
) {
    CHECK_NULL(wt);
    CHECK_NULL(branch_name);

    if (wt->cleaned_up) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Worktree already cleaned up");
    }

    /* Build reference name dynamically to support long branch names */
    char *refname = str_format("refs/heads/%s", branch_name);
    if (!refname) {
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate reference name");
    }

    /* Set HEAD to new orphan branch (doesn't exist yet) */
    int err = git_repository_set_head(wt->repo, refname);
    free(refname);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}

void worktree_cleanup(worktree_handle_t *wt) {
    if (!wt) {
        return;
    }

    if (wt->cleaned_up) {
        return;  /* Already cleaned up */
    }

    wt->cleaned_up = true;

    /* Step 1: Close repository handle FIRST (critical ordering) */
    if (wt->repo) {
        git_repository_free(wt->repo);
        wt->repo = NULL;
    }

    /* Step 2: Delete the temporary worktree branch from main repo */
    if (wt->name && wt->main_repo) {
        char *refname = str_format("refs/heads/%s", wt->name);
        if (refname) {
            git_reference *ref = NULL;
            if (git_reference_lookup(&ref, wt->main_repo, refname) == 0) {
                git_branch_delete(ref);
                git_reference_free(ref);
            }
            free(refname);
        }
    }

    /* Step 3: Prune worktree */
    if (wt->worktree) {
        git_worktree_prune_options opts = {0};
        opts.version = 1;
        opts.flags = GIT_WORKTREE_PRUNE_VALID;  /* Prune even if valid */

        git_worktree_prune(wt->worktree, &opts);
        git_worktree_free(wt->worktree);
        wt->worktree = NULL;
    }

    /* Step 4: Remove temporary directory */
    if (wt->path) {
        /* Ignore errors - best effort cleanup */
        fs_remove_dir(wt->path, true);
        free(wt->path);
        wt->path = NULL;
    }

    /* Step 5: Free name */
    if (wt->name) {
        free(wt->name);
        wt->name = NULL;
    }

    /* Step 6: Free handle */
    free(wt);
}

const char *worktree_get_path(const worktree_handle_t *wt) {
    if (!wt || wt->cleaned_up) {
        return NULL;
    }
    return wt->path;
}

git_repository *worktree_get_repo(const worktree_handle_t *wt) {
    if (!wt || wt->cleaned_up) {
        return NULL;
    }
    return wt->repo;
}

dotta_error_t *worktree_get_index(worktree_handle_t *wt, git_index **out) {
    CHECK_NULL(wt);
    CHECK_NULL(out);

    if (wt->cleaned_up) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Worktree already cleaned up");
    }

    int err = git_repository_index(out, wt->repo);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}
