/**
 * repo.c - The store: where it is, what makes it one, how it is opened
 */

#include "utils/repo.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "base/error.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/config.h"

/**
 * Where a create-style command puts the repository
 */
error_t repo_create_target(
    const config_t *config,
    arena_t *arena,
    const char *explicit_path,
    const char **out_path,
    const char **out_elsewhere
) {
    CHECK_NULL(config);
    CHECK_NULL(arena);
    CHECK_NULL(out_path);

    /* Where this machine's repository lives, and where the positional puts one,
     * in the one shape the comparison at the end can trust: both are read by
     * fs_make_absolute — the configured one at load, the positional here — so
     * the two spellings of one directory are one string, all but one through a
     * link beside its target's, whose `..` only the kernel folds: that pair reads
     * as elsewhere, a note and never a second store. No positional: the configured
     * location is the answer. */
    const char *configured = config->repo_dir;
    const char *path = configured;
    error_t err = explicit_path ? fs_make_absolute(explicit_path, arena, &path) : NULL;
    if (err) return err;

    /* The directory holding the repository, not the repository: the clone refuses
     * a target that is not empty, and the init makes its own leaf
     * (gitops_init_repository), so neither caller wants this to reach it. */
    err = fs_ensure_parent_dirs(path);
    if (err) return err;

    /* An explicit path may still name the configured location — `dotta clone
     * <url> "$DOTTA_REPO_DIR"` does — and that is not elsewhere. */
    if (out_elsewhere != NULL) {
        *out_elsewhere = strcmp(path, configured) == 0 ? NULL : configured;
    }

    *out_path = path;
    return NULL;
}

/**
 * Declare the repository dotta's store
 */
error_t repo_declare_store(git_repository *repo) {
    CHECK_NULL(repo);

    /* The layered handle writes at its write level, the repository's own file. */
    git_config *config = NULL;
    int rc = git_repository_config(&config, repo);
    if (rc < 0) return error_from_git(rc);

    rc = git_config_set_bool(config, "dotta.store", 1);
    if (rc < 0) {
        git_config_free(config);
        return error_from_git(rc);
    }

    rc = git_config_set_bool(config, "core.logAllRefUpdates", 1);
    git_config_free(config);
    if (rc < 0) return error_from_git(rc);

    return NULL;
}

/**
 * Is this repository declared dotta's store?
 */
error_t repo_is_store(git_repository *repo, bool *out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    git_config *config = NULL;
    int rc = git_repository_config(&config, repo);
    if (rc < 0) return error_from_git(rc);

    /* The repository's own level, cut out of the layered handle (the header). */
    git_config *local = NULL;
    rc = git_config_open_level(&local, config, GIT_CONFIG_LEVEL_LOCAL);
    git_config_free(config);
    if (rc == GIT_ENOTFOUND) {
        return ERROR(ERR_GIT, "Cannot read the repository's config file");
    }
    if (rc < 0) return error_from_git(rc);

    int declared = 0;
    rc = git_config_get_bool(&declared, local, "dotta.store");
    git_config_free(local);
    if (rc == GIT_ENOTFOUND) {
        *out = false;
        return NULL;
    }
    if (rc < 0) return error_from_git(rc);

    *out = declared != 0;
    return NULL;
}

/**
 * Open dotta's store
 */
error_t repo_open(const config_t *config, git_repository **repo_out) {
    CHECK_NULL(config);
    CHECK_NULL(repo_out);

    /* The store's directory, settled at load (utils/config.h) */
    const char *repo_path = config->repo_dir;
    git_repository *repo = NULL;

    /* Where the path came from, when the environment named it: the one source
     * of the path its reader cannot see in the path. The reader config_load's
     * override has, so the clause cannot name an origin the load did not use. */
    const char *origin = config_repo_dir_from_env() ? " (DOTTA_REPO_DIR)" : "";

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
    error_t err = gitops_open_repository(&repo, repo_path);
    if (err) {
        if (error_code(err) == ERR_NOT_FOUND) {
            /* Which of the two it is. libgit2 words them identically — "could
             * not find repository at X" for an empty directory, for a store it
             * cannot read, and for a path that is not there — so the filesystem
             * is the one that can tell them apart. The store is the directory,
             * and HEAD is the file whose absence is what makes libgit2 say so:
             * gone, the directory holds no repository (nothing there, a directory
             * of other things, a store a hand stripped of its HEAD, which 'dotta
             * init' recreates with refs, epoch and record intact); present, or
             * unstattable because the directory cannot be looked into — or a
             * spelling past PATH_MAX, which no lstat could answer — there is a
             * repository here that could not be read, and the answer to an absence
             * is the one answer that must not be offered for it. */
            char head[PATH_MAX];
            int n = snprintf(head, sizeof(head), "%s/HEAD", repo_path);
            if (n >= 0 && (size_t) n < sizeof(head) &&
                fs_lstat_occupant(head, NULL) == FS_OCCUPANT_NONE) {
                return ERROR(
                    ERR_NOT_FOUND, "No dotta repository found at %s%s", repo_path,
                    origin
                );
            }
            return ERROR(
                ERR_GIT, "Cannot read the repository at %s%s", repo_path, origin
            );
        }
        /* Every other failure is its own words beneath the path — libgit2's owner
         * check (CVE-2022-24765) among them, another user's repository, which
         * its leaf names */
        return error_wrap(err, "Failed to open repository at: %s", repo_path);
    }

    /*
     * Opened; is it dotta's? The store's own declaration (repo_is_store): a
     * repository without one is somebody's — a project, a mirror, the store an
     * older dotta kept checked out — and dotta writes into none of them. Which
     * one it is, the refusal does not guess: 'dotta init' takes a bare repository
     * with no refs at all and refuses one with a working tree or a history, naming
     * the true thing.
     */
    bool declared = false;
    err = repo_is_store(repo, &declared);
    if (err) {
        git_repository_free(repo);
        return error_wrap(err, "Cannot open the repository at: %s", repo_path);
    }
    if (!declared) {
        git_repository_free(repo);
        return ERROR(
            ERR_NOT_FOUND, "The repository at %s is not a dotta store%s", repo_path,
            origin
        );
    }

    *repo_out = repo;
    return NULL;
}
