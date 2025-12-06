/**
 * worktree.c - Temporary git worktree management implementation
 *
 * Critical resource management:
 * - Worktrees must always be cleaned up
 * - Cleanup order matters: index -> repo -> worktree -> directory
 * - Safe to call cleanup multiple times
 */

#include "worktree.h"

#include <errno.h>
#include <git2.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"

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
static error_t *generate_temp_path_from_name(
    const char *name,
    char **out
) {
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

/**
 * Cleanup orphaned worktrees from dead processes
 *
 * Scans .git/worktrees/ for dotta-temp-* entries from processes that
 * are no longer running and cleans up both Git metadata and filesystem
 * directories.
 *
 * This extends the existing self-healing pattern (worktree.c:103-112)
 * to handle cross-process orphans from interrupted operations (Ctrl-C),
 * crashes, and kill -9.
 *
 * Design principles:
 * - Silent operation (best-effort cleanup, ignores all errors)
 * - Uses Git worktree API as source of truth
 * - Checks process liveness via kill(pid, 0)
 * - Cleans Git metadata, branches, and filesystem directories
 * - Idempotent (safe to call multiple times)
 *
 * This is called automatically before creating new worktrees to ensure
 * no stale resources from previous interrupted operations block the
 * creation of new worktrees.
 *
 * @param repo Main repository (must not be NULL)
 */
static void cleanup_orphaned_worktrees(git_repository *repo) {
    if (!repo) {
        return;
    }

    /* Get worktree list from Git (source of truth for what exists) */
    git_strarray worktree_names = {0};
    if (git_worktree_list(&worktree_names, repo) < 0) {
        return; /* Non-fatal - continue with worktree creation */
    }

    /* Scan for orphaned dotta temp worktrees */
    for (size_t i = 0; i < worktree_names.count; i++) {
        const char *name = worktree_names.strings[i];

        /* Only process our temp worktrees */
        if (strncmp(name, "dotta-temp-", 11) != 0) {
            continue;
        }

        /* Extract PID from name: dotta-temp-{pid}-{timestamp} */
        pid_t pid = 0;
        if (sscanf(name, "dotta-temp-%d-", &pid) != 1) {
            continue; /* Invalid format - skip */
        }

        /* Skip PID 0 or negative (invalid) */
        if (pid <= 0) {
            continue;
        }

        /* Check if process is alive
         * kill(pid, 0) performs error checking without sending a signal */
        if (kill(pid, 0) == 0) {
            continue; /* Process still running - not an orphan */
        }

        if (errno != ESRCH) {
            continue; /* Permission denied or other error - skip to be safe */
        }

        /* Process is dead (ESRCH = No such process) - this is an orphaned worktree
         * Clean it up using the same steps as normal cleanup (see worktree_cleanup) */

        /* Step 1: Prune Git metadata (.git/worktrees/{name}/)
         * This is the critical step that unblocks subsequent operations */
        git_worktree *wt = NULL;
        if (git_worktree_lookup(&wt, repo, name) == 0) {
            git_worktree_prune_options opts = {0};
            opts.version = 1;
            opts.flags = GIT_WORKTREE_PRUNE_VALID; /* Prune even if valid */
            git_worktree_prune(wt, &opts);
            git_worktree_free(wt);
        }

        /* Step 2: Delete temporary branch (refs/heads/{name}) */
        char refname[DOTTA_REFNAME_MAX];
        error_t *err_build = gitops_build_refname(refname, sizeof(refname),
                                                   "refs/heads/%s", name);
        if (!err_build) {
            git_reference *ref = NULL;
            if (git_reference_lookup(&ref, repo, refname) == 0) {
                git_branch_delete(ref);
                git_reference_free(ref);
            }
        }
        /* Silently ignore refname build errors during cleanup */
        error_free(err_build);

        /* Step 3: Remove filesystem directory (/tmp/{name}/)
         * This is best-effort cleanup of the working tree directory */
        char *path = NULL;
        error_t *err_path = generate_temp_path_from_name(name, &path);
        if (!err_path) {
            /* Ignore errors - best effort cleanup */
            fs_remove_dir(path, true);
            free(path);
        }
        error_free(err_path);
    }

    git_strarray_dispose(&worktree_names);
}

error_t *worktree_create_temp(
    git_repository *repo,
    worktree_handle_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    /* Cleanup orphaned worktrees from dead processes (self-healing)
     * This is transparent, best-effort cleanup that ensures no stale
     * worktrees from interrupted operations block this creation. */
    cleanup_orphaned_worktrees(repo);

    /* Allocate handle */
    worktree_handle_t *wt = calloc(1, sizeof(worktree_handle_t));
    if (!wt) {
        return ERROR(ERR_MEMORY, "Failed to allocate worktree handle");
    }

    wt->main_repo = repo;
    wt->cleaned_up = false;

    /* Generate unique name */
    wt->name = generate_worktree_name();
    if (!wt->name) {
        free(wt);
        return ERROR(ERR_MEMORY, "Failed to generate worktree name");
    }

    /* Generate temp path from the same name */
    error_t *err = generate_temp_path_from_name(wt->name, &wt->path);
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

error_t *worktree_checkout_branch(
    worktree_handle_t *wt,
    const char *branch_name
) {
    CHECK_NULL(wt);
    CHECK_NULL(branch_name);

    if (wt->cleaned_up) {
        return ERROR(ERR_INVALID_ARG, "Worktree already cleaned up");
    }

    /* Build reference name */
    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(refname, sizeof(refname),
                                        "refs/heads/%s", branch_name);
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    /* Resolve branch to commit object */
    git_object *commit = NULL;
    int git_err = git_revparse_single(&commit, wt->repo, refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Checkout tree with SAFE strategy
     *
     * With GIT_CHECKOUT_SAFE:
     * - Clean working directory: transition allowed, files updated
     * - Modified files: checkout blocked with GIT_ECONFLICT
     */
    git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
    checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;

    git_err = git_checkout_tree(wt->repo, commit, &checkout_opts);
    git_object_free(commit);

    if (git_err < 0) {
        if (git_err == GIT_ECONFLICT) {
            return ERROR(ERR_CONFLICT,
                "Cannot checkout '%s': local modifications would be overwritten",
                branch_name);
        }
        return error_from_git(git_err);
    }

    /*
     * Move HEAD to target branch
     *
     * At this point, Index and Working Directory already match the target.
     * This is just updating the HEAD pointer to complete the transition.
     */
    git_err = git_repository_set_head(wt->repo, refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    return NULL;
}

error_t *worktree_create_orphan(
    worktree_handle_t *wt,
    const char *branch_name
) {
    CHECK_NULL(wt);
    CHECK_NULL(branch_name);

    if (wt->cleaned_up) {
        return ERROR(ERR_INVALID_ARG, "Worktree already cleaned up");
    }

    /* Build reference name */
    char refname[DOTTA_REFNAME_MAX];
    error_t *err_build = gitops_build_refname(refname, sizeof(refname),
                                              "refs/heads/%s", branch_name);
    if (err_build) {
        return error_wrap(err_build, "Invalid branch name '%s'", branch_name);
    }

    /* Set HEAD to new orphan branch (doesn't exist yet) */
    int err = git_repository_set_head(wt->repo, refname);
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

    /* Step 2: Prune worktree */
    if (wt->worktree) {
        git_worktree_prune_options opts = {0};
        opts.version = 1;
        opts.flags = GIT_WORKTREE_PRUNE_VALID;  /* Prune even if valid */

        git_worktree_prune(wt->worktree, &opts);
        git_worktree_free(wt->worktree);
        wt->worktree = NULL;
    }

    /* Step 3: Delete the temporary worktree branch from main repo */
    if (wt->name && wt->main_repo) {
        char refname[DOTTA_REFNAME_MAX];
        error_t *err_build = gitops_build_refname(refname, sizeof(refname),
                                                  "refs/heads/%s", wt->name);
        if (!err_build) {
            git_reference *ref = NULL;
            if (git_reference_lookup(&ref, wt->main_repo, refname) == 0) {
                git_branch_delete(ref);
                git_reference_free(ref);
            }
        }
        /* Silently ignore refname build errors during cleanup */
        error_free(err_build);
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

error_t *worktree_get_index(worktree_handle_t *wt, git_index **out) {
    CHECK_NULL(wt);
    CHECK_NULL(out);

    if (wt->cleaned_up) {
        return ERROR(ERR_INVALID_ARG, "Worktree already cleaned up");
    }

    int err = git_repository_index(out, wt->repo);
    if (err < 0) {
        return error_from_git(err);
    }

    return NULL;
}
