/**
 * repo.c - The store: where it is, what makes it one, how it is opened
 */

#include "utils/repo.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
        /* The level libgit2 dropped (config_file.c config_file_open), which says
         * why only for a directory, and nothing where access(2) refused the file:
         * the word is the kernel's, asked again as libgit2 asked it, and where
         * access(2) passes, the file is the directory libgit2 refused — the words
         * sys/source.c source_config gives the same fact. The store is never a
         * worktree, so the file is its commondir's. */
        char path[PATH_MAX + sizeof("config")];
        snprintf(path, sizeof(path), "%sconfig", git_repository_commondir(repo));
        return error_create(
            ERR_GIT, "Cannot read '%s': %s", path,
            strerror(access(path, R_OK) != 0 ? errno : EISDIR)
        );
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
     * Only ERR_NOT_FOUND is dotta's to reword: the open has looked at the path's
     * places itself before it says so (sys/gitops.h gitops_open_repository), so
     * it is the absence it reads as — nothing there, a directory of other things,
     * a store a hand stripped of its HEAD, which 'dotta init' recreates with
     * refs, epoch and record intact. Every other failure is already the truth —
     * a repository that would not open whose HEAD stands, a directory that cannot
     * be looked into, a config file that will not parse — and is wrapped, not
     * replaced. Telling a user with a broken ~/.gitconfig to run 'dotta init'
     * costs them the repository they still have.
     */
    error_t err = gitops_open_repository(&repo, repo_path);
    if (error_code(err) == ERR_NOT_FOUND) {
        return error_create(
            ERR_NOT_FOUND, "No dotta repository found at '%s'%s", repo_path, origin
        );
    }
    if (err) {
        /* Its own words beneath the path — libgit2's owner check (CVE-2022-24765)
         * among them, another user's repository, which its leaf names */
        return error_wrap(err, "Cannot open the repository at '%s'%s", repo_path, origin);
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
        return error_wrap(err, "Cannot open the repository at '%s'%s", repo_path, origin);
    }
    if (!declared) {
        git_repository_free(repo);
        return error_create(
            ERR_NOT_FOUND, "The repository at '%s' is not a dotta store%s", repo_path,
            origin
        );
    }

    *repo_out = repo;
    return NULL;
}
