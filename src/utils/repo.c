/**
 * repo.c - The store: where it is, what makes it one, how it is opened
 */

#include "utils/repo.h"

#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/config.h"

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

    /* The directory holding the repository, not the repository: the clone refuses
     * a target that is not empty, and the init makes its own leaf
     * (gitops_init_repository), so neither caller wants this to reach it. */
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
 * Declare the repository dotta's store
 */
error_t *repo_declare_store(git_repository *repo) {
    CHECK_NULL(repo);

    /* The layered handle writes at its write level, the repository's own file. */
    git_config *config = NULL;
    int rc = git_repository_config(&config, repo);
    if (rc < 0) {
        return error_from_git(rc);
    }

    rc = git_config_set_bool(config, "dotta.store", 1);
    if (rc < 0) {
        git_config_free(config);
        return error_from_git(rc);
    }

    rc = git_config_set_bool(config, "core.logAllRefUpdates", 1);
    git_config_free(config);
    if (rc < 0) {
        return error_from_git(rc);
    }

    return NULL;
}

/**
 * Is this repository declared dotta's store?
 */
error_t *repo_is_store(git_repository *repo, bool *out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    git_config *config = NULL;
    int rc = git_repository_config(&config, repo);
    if (rc < 0) {
        return error_from_git(rc);
    }

    /* The repository's own level, cut out of the layered handle (the header). */
    git_config *local = NULL;
    rc = git_config_open_level(&local, config, GIT_CONFIG_LEVEL_LOCAL);
    git_config_free(config);
    if (rc == GIT_ENOTFOUND) {
        return ERROR(ERR_GIT, "Cannot read the repository's config file");
    }
    if (rc < 0) {
        return error_from_git(rc);
    }

    int declared = 0;
    rc = git_config_get_bool(&declared, local, "dotta.store");
    git_config_free(local);
    if (rc == GIT_ENOTFOUND) {
        *out = false;
        return NULL;
    }
    if (rc < 0) {
        return error_from_git(rc);
    }

    *out = declared != 0;
    return NULL;
}

/* The one-time remedy for a repository an older dotta left root-owned. It does
 * not happen again — the run drops to the invoker at main() (sys/identity) —
 * and what was left from before is the user's to take back once. Two arms below
 * name it, for the two faces a root-owned repository has. */
#define REPO_RECLAIM_HINT \
    "An older dotta run under sudo could leave it root-owned; take it back " \
    "once:\n  sudo chown -R \"$(id -u):$(id -g)\" %s"

/**
 * Open dotta's store
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

    /* Where the path came from, when it did not come from the default — for the
     * refusals below that send the user to 'dotta init' or to DOTTA_REPO_DIR.
     * The reader config_get_repo_dir's priority 1 has, so the note cannot name
     * an origin the resolution did not use. */
    const char *env_repo = config_repo_dir_from_env();
    const char *env_note = env_repo ? "\nDOTTA_REPO_DIR is set to: " : "";
    const char *env_value = env_repo ? env_repo : "";

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
             * not find repository at X" for an empty directory, for a store it
             * cannot read, and for a path that is not there — so the filesystem
             * is the one that can tell them apart. The store is the directory,
             * and HEAD is the file whose absence is what makes libgit2 say so:
             * gone, the directory holds no repository (nothing there, a directory
             * of other things, a store a hand stripped of its HEAD, which 'dotta
             * init' recreates with refs, epoch and record intact); present, or
             * unstattable because the directory cannot be looked into, there is
             * a repository here that could not be read, and the answer to an
             * absence is the one answer that must not be offered for it. */
            char *head = NULL;
            error_t *join_err = fs_path_join(repo_path, "HEAD", &head);
            bool absent = !join_err
                && fs_lstat_occupant(head, NULL) == FS_OCCUPANT_NONE;
            free(head);
            error_free(join_err);

            if (absent) {
                answer = ERROR(
                    ERR_NOT_FOUND, "No dotta repository found at: %s\n\n"
                    "Run 'dotta init' to create a new repository%s%s",
                    repo_path, env_note, env_value
                );
            } else {
                answer = ERROR(
                    ERR_GIT, "Cannot read the repository at: %s\n\n"
                    "Check its ownership and permissions. " REPO_RECLAIM_HINT
                    "%s%s", repo_path, repo_path, env_note, env_value
                );
            }
            error_free(err);
        } else if (error_code(err) == ERR_PERMISSION) {
            /* libgit2's owner check (CVE-2022-24765): the repository is another
             * user's — any other user's, which is why the hint says "could" —
             * and root is the one owner an older dotta could have made of it,
             * since the repository is per-user by design. After the drop, root's
             * own is one too. */
            answer = error_wrap(
                err, "Cannot open the repository at: %s\n" REPO_RECLAIM_HINT,
                repo_path, repo_path
            );
        } else {
            answer = error_wrap(err, "Failed to open repository at: %s", repo_path);
        }

        free(repo_path);
        return answer;
    }

    /*
     * Opened; is it dotta's? The store's own declaration (repo_is_store): a
     * repository without one is somebody's — a project, a mirror, the store an
     * older dotta kept checked out — and dotta writes into none of them. The
     * remedy named is 'dotta init', which is the verb that decides: it takes a
     * bare repository with no refs at all and refuses one with a working tree
     * or a history, naming the true thing.
     */
    bool declared = false;
    err = repo_is_store(repo, &declared);
    if (err) {
        err = error_wrap(err, "Cannot open the repository at: %s", repo_path);
        git_repository_free(repo);
        free(repo_path);
        return err;
    }
    if (!declared) {
        err = ERROR(
            ERR_NOT_FOUND, "The repository at %s is not a dotta store\n\n"
            "Run 'dotta init' to make it one, or point DOTTA_REPO_DIR at your "
            "store%s%s", repo_path, env_note, env_value
        );
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
