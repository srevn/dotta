/**
 * repo.c - Repository path resolution implementation
 */

#include "utils/repo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/error.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/config.h"
#include "utils/privilege.h"

/**
 * Resolve repository path
 */
error_t *resolve_repo_path(const config_t *config, char **out) {
    CHECK_NULL(config);
    CHECK_NULL(out);

    /* Resolve repository directory using full priority chain:
     * 1. DOTTA_REPO_DIR environment variable
     * 2. Config file repo_dir setting
     * 3. Default: ~/.local/share/dotta/repo */
    char *repo_dir = NULL;
    error_t *err = config_get_repo_dir(config, &repo_dir);
    if (err) {
        /* Path expansion failed (e.g., invalid home directory). This is a genuine
         * error that should be propagated.
         */
        return error_wrap(
            err, "Failed to resolve repository path"
        );
    }

    *out = repo_dir;
    return NULL;
}

/**
 * Where a create-style command puts the repository
 */
error_t *repo_create_target(
    const config_t *config,
    const char *explicit_path,
    char **out_path,
    char **out_elsewhere
) {
    CHECK_NULL(config);
    CHECK_NULL(out_path);

    /* Where this machine's repository lives, in the one shape the comparison at
     * the end can trust. Both sides are normalised by this function, which is
     * the whole reason the answer means anything: `resolve_repo_path` expands
     * `~`, and `fs_make_absolute` settles a relative repo_dir against the current
     * directory exactly as it settles a relative positional below. */
    char *resolved = NULL;
    RETURN_IF_ERROR(resolve_repo_path(config, &resolved));

    char *configured = NULL;
    error_t *err = fs_make_absolute(resolved, &configured);
    free(resolved);
    if (err) {
        return err;
    }

    char *path = NULL;
    if (explicit_path == NULL) {
        /* No positional: the configured location is the answer, already in hand
         * and already normalised. */
        path = configured;
        configured = NULL;
    } else {
        char *expanded = NULL;
        err = fs_expand_tilde(explicit_path, &expanded);
        if (!err) {
            err = fs_make_absolute(expanded, &path);
            free(expanded);
        }
        if (err) {
            free(configured);
            return err;
        }
    }

    /* The directory holding the repository, not the repository: `git_clone` refuses
     * a non-empty target and `git_repository_init_ext` makes its own, so neither
     * caller wants this to reach the leaf. */
    err = fs_ensure_parent_dirs(path);
    if (err) {
        free(configured);
        free(path);
        return err;
    }

    /* An explicit path may still name the configured location — `dotta clone
     * <url> "$DOTTA_REPO_DIR"` does — and that is not elsewhere. */
    if (configured != NULL && strcmp(path, configured) == 0) {
        free(configured);
        configured = NULL;
    }

    if (out_elsewhere != NULL) {
        *out_elsewhere = configured;
    } else {
        free(configured);
    }

    *out_path = path;
    return NULL;
}

/**
 * Ensure repository HEAD points to dotta-worktree
 *
 * Dotta requires the main worktree to always be on the dotta-worktree branch.
 * If HEAD is on a different branch (e.g., user manually ran git checkout), this
 * function automatically switches back using the correct checkout sequence.
 *
 * Behavior:
 * - Already on dotta-worktree: no-op (fast path)
 * - Clean working directory: switch succeeds, info message emitted
 * - Dirty working directory: fails with clear error and fix instructions
 * - Bare repository: no-op (no working directory)
 *
 * @param repo Repository handle (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *repo_ensure_dotta_worktree(git_repository *repo) {
    CHECK_NULL(repo);

    /* Bare repositories have no working directory */
    if (git_repository_is_bare(repo)) {
        return NULL;
    }

    error_t *err = NULL;

    /* Verify dotta-worktree branch exists */
    bool worktree_exists = false;
    err = gitops_branch_exists(repo, "dotta-worktree", &worktree_exists);
    if (err) {
        return error_wrap(err, "Failed to check for dotta-worktree branch");
    }

    if (!worktree_exists) {
        return ERROR(
            ERR_NOT_FOUND,
            "Repository is not initialized (dotta-worktree branch missing)\n"
            "Run 'dotta init' to initialize the repository"
        );
    }

    /* Fast path: check if already on dotta-worktree */
    bool is_current = false;
    err = gitops_is_current_branch(repo, "dotta-worktree", &is_current);
    if (err) {
        /*
         * Non-fatal: could be detached HEAD state. Continue with recovery attempt.
         */
        error_free(err);
        err = NULL;
    }

    if (is_current) {
        /* Already on dotta-worktree - nothing to do */
        return NULL;
    }

    /* Get current branch name for user messaging */
    char *old_branch = NULL;
    error_t *branch_err = gitops_current_branch(repo, &old_branch);
    if (branch_err) {
        /*
         * Non-fatal: detached HEAD or other unusual state. Continue with recovery,
         * use placeholder in message.
         */
        error_free(branch_err);
        old_branch = NULL;
    }

    /*
     * Checkout dotta-worktree using correct order of operations
     *
     * Order (checkout_tree -> set_head):
     * 1. checkout_tree compares target tree vs current state
     * 2. With SAFE mode, fails if local modifications exist
     * 3. Updates both Index and Working Directory atomically
     * 4. set_head just moves the pointer after state is updated
     */
    git_object *target_commit = NULL;
    int git_err = git_revparse_single(
        &target_commit, repo, "refs/heads/dotta-worktree"
    );
    if (git_err < 0) {
        free(old_branch);
        return error_from_git(git_err);
    }

    git_checkout_options checkout_opts;
    git_checkout_options_init(&checkout_opts, GIT_CHECKOUT_OPTIONS_VERSION);
    checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;

    git_err = git_checkout_tree(repo, target_commit, &checkout_opts);
    git_object_free(target_commit);

    if (git_err < 0) {
        const char *branch_desc = old_branch ? old_branch : "detached HEAD";

        if (git_err == GIT_ECONFLICT) {
            err = ERROR(
                ERR_CONFLICT,
                "Cannot auto-recover to 'dotta-worktree' (currently on '%s')\n\n"
                "Your working directory has modifications that prevent switching.\n"
                "To resolve manually:\n"
                "  dotta git stash          # Save your changes\n"
                "  dotta git checkout dotta-worktree\n"
                "  dotta git stash pop      # Restore changes (if needed)", branch_desc
            );
        } else {
            err = error_wrap(
                error_from_git(git_err),
                "Failed to checkout dotta-worktree (was on '%s')", branch_desc
            );
        }

        free(old_branch);
        return err;
    }

    /* Move HEAD to dotta-worktree (state already updated) */
    git_err = git_repository_set_head(repo, "refs/heads/dotta-worktree");
    if (git_err < 0) {
        free(old_branch);
        return error_from_git(git_err);
    }

    /*
     * Recovery may have deleted the process CWD (e.g., user was in a subdirectory
     * that only existed on the old branch). Move to the repo workdir so subsequent
     * operations (credential helpers, hooks) don't fail with invalid CWD.
     */
    const char *workdir = git_repository_workdir(repo);
    if (workdir) {
        (void) chdir(workdir);
    }

    /* Success - inform user about the automated recovery */
    const char *branch_desc = old_branch ? old_branch : "detached HEAD";
    fprintf(
        stderr, "info: Recovered to 'dotta-worktree' (was on '%s')\n",
        branch_desc
    );
    free(old_branch);

    return NULL;
}

/**
 * Open dotta repository
 */
error_t *repo_open(const config_t *config, git_repository **repo_out, char **path_out) {
    CHECK_NULL(config);
    CHECK_NULL(repo_out);

    char *repo_path = NULL;
    git_repository *repo = NULL;
    error_t *err = NULL;

    /* Resolve repository path — resolve_repo_path names its own failure. */
    err = resolve_repo_path(config, &repo_path);
    if (err) {
        return err;
    }

    /*
     * Open the repository, and let the open be the answer to whether one is there.
     * Only ERR_NOT_FOUND is dotta's to reword, and only after the filesystem
     * has been asked which of the two cases libgit2 folds into it: a path that
     * is not a repository, and a repository that could not be read. Every other
     * failure is already the truth — a config file that will not parse, an object
     * database that will not open — and is wrapped, not replaced. Telling a user
     * with a broken ~/.gitconfig to run 'dotta init' costs them the repository
     * they still have.
     */
    err = gitops_open_repository(&repo, repo_path);
    if (err) {
        error_t *answer;

        if (error_code(err) == ERR_NOT_FOUND) {
            /* Which of the two it is. libgit2 words them identically — "could
             * not find repository at X" for an empty directory, for a .git it
             * cannot read, and for a path that is not there — so the filesystem
             * is the one that can tell them apart, and the question to ask it
             * is about the git directory rather than the directory holding it:
             * an empty directory at the path is the absence of a repository,
             * not an unreadable one. A path dotta cannot look into at all answers
             * neither and reads as the absence; 'dotta init' then names the
             * permission itself. */
            char *git_dir = NULL;
            error_t *join_err = fs_path_join(repo_path, ".git", &git_dir);
            bool holds_repository = !join_err && fs_lexists(git_dir);
            free(git_dir);
            error_free(join_err);

            /* Where the path came from, when it did not come from the default.
             * The same test config_get_repo_dir's priority 1 makes, so the note
             * cannot name an origin the resolution did not use. */
            const char *env_repo = getenv("DOTTA_REPO_DIR");
            bool from_env = env_repo && env_repo[0] != '\0';
            const char *env_note = from_env ? "\nDOTTA_REPO_DIR is set to: " : "";
            const char *env_value = from_env ? env_repo : "";

            if (holds_repository) {
                answer = ERROR(
                    ERR_GIT, "Cannot read the repository at: %s\n\n"
                    "A git directory is present, so this is not a missing "
                    "repository.\n"
                    "Check its ownership and permissions — a dotta run under "
                    "sudo can leave root-owned files behind.%s%s",
                    repo_path, env_note, env_value
                );
            } else {
                answer = ERROR(
                    ERR_NOT_FOUND, "No dotta repository found at: %s\n\n"
                    "Run 'dotta init' to create a new repository%s%s",
                    repo_path, env_note, env_value
                );
            }
            error_free(err);
        } else {
            answer = error_wrap(err, "Failed to open repository at: %s", repo_path);
        }

        free(repo_path);
        return answer;
    }

    /*
     * Ensure HEAD points to dotta-worktree
     *
     * Dotta's invariant: HEAD must always be on dotta-worktree. If user manually
     * checked out another branch (e.g., git checkout global), recover automatically
     * before proceeding.
     */
    err = repo_ensure_dotta_worktree(repo);
    if (err) {
        git_repository_free(repo);
        free(repo_path);
        return err;
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

    /* Early exit: only fix ownership when running under sudo This is the common
     * case - most operations don't need sudo */
    if (!privilege_is_sudo()) {
        return NULL;  /* No-op: not running under sudo */
    }

    /* We're running under sudo - need to fix ownership */

    /* Get the actual user's credentials (from SUDO_UID/SUDO_GID) Delegates to
     * privilege module for consistent sudo handling. */
    uid_t actual_uid = 0;
    gid_t actual_gid = 0;
    error_t *err = privilege_get_actual_user(&actual_uid, &actual_gid);
    if (err) {
        return error_wrap(
            err, "Failed to determine actual user for ownership fix"
        );
    }

    /* Build path to .git directory */
    char *git_dir = NULL;
    err = fs_path_join(repo_path, ".git", &git_dir);
    if (err) {
        return error_wrap(err, "Failed to construct .git path");
    }

    /* Check if .git directory exists If it doesn't exist, this is likely the
     * init command creating a new repo. In that case, there's nothing to fix -
     * just return success. */
    if (!fs_is_directory(git_dir)) {
        free(git_dir);
        return NULL;  /* .git doesn't exist - nothing to fix */
    }

    /* Fix ownership of the repository directory itself. Without this, libgit2
     * ownership validation (CVE-2022-24765 mitigations) may reject the repository
     * on subsequent non-sudo runs. */
    (void) chown(repo_path, actual_uid, actual_gid);

    /* Fix .git/ ownership recursively */
    size_t fixed_count = 0;
    size_t failed_count = 0;
    err = fs_fix_ownership_recursive(
        git_dir, actual_uid, actual_gid, &fixed_count, &failed_count
    );
    free(git_dir);

    if (err) {
        return error_wrap(
            err, "Failed to fix repository ownership"
        );
    }

    /* Only warn if there were failures */
    if (failed_count > 0) {
        fprintf(
            stderr, "Warning: Failed to restore ownership for %zu files\n",
            failed_count
        );
    }

    return NULL;
}
