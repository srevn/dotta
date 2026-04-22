/**
 * source.c - Source-tree gitignore queries via libgit2.
 *
 * Implementation notes:
 *
 *   - The cache stores at most one repo handle at a time. A query
 *     whose `abs_path` falls outside the cached workdir invalidates
 *     the cache before re-discovering. This matches the common
 *     `dotta add` pattern (walking a single source tree) without
 *     growing memory on pathological workloads.
 *
 *   - `git_repository_workdir` returns a string ending in `/`; the
 *     prefix-stripping helper is defensive either way and consumes
 *     any leading slashes on the resulting relative path so later
 *     comparisons start from a real component.
 *
 *   - Directory queries get a trailing `/` appended before the libgit2
 *     call so directory-only patterns (e.g. `node_modules/`) match.
 *     An allocation failure on that append surfaces as ERR_MEMORY
 *     rather than silently falling back to the non-suffixed query,
 *     which would change the verdict under OOM.
 *
 *   - The cache is populated only after a successful query. If the
 *     query errors, the freshly-opened repo is freed and the cache
 *     stays empty so the next query starts clean.
 */

#include "sys/source.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/string.h"

struct source_filter {
    git_repository *cached_repo;   /* Owned; NULL when cache is cold */
    char *cached_workdir;          /* Owned; libgit2 workdir ends in '/' */
};

error_t *source_filter_create(source_filter_t **out) {
    CHECK_NULL(out);

    source_filter_t *f = calloc(1, sizeof(*f));
    if (!f) {
        return ERROR(ERR_MEMORY, "Failed to allocate source filter");
    }

    *out = f;
    return NULL;
}

void source_filter_free(source_filter_t *f) {
    if (!f) return;

    if (f->cached_repo) {
        git_repository_free(f->cached_repo);
    }
    free(f->cached_workdir);
    free(f);
}

/**
 * Query an already-opened repo for `rel_path`'s ignore status.
 * Handles the is_dir→trailing-slash convention in one place.
 */
static error_t *query_repo(
    git_repository *repo, const char *rel_path, bool is_dir, bool *out
) {
    char *dir_path = NULL;
    const char *check_path = rel_path;
    if (is_dir && rel_path[0] != '\0' &&
        rel_path[strlen(rel_path) - 1] != '/') {
        dir_path = str_format("%s/", rel_path);
        if (!dir_path) {
            return ERROR(ERR_MEMORY, "Failed to allocate directory path");
        }
        check_path = dir_path;
    }

    int ignored = 0;
    int rc = git_ignore_path_is_ignored(&ignored, repo, check_path);
    free(dir_path);

    if (rc < 0) {
        return error_from_git(rc);
    }

    *out = (ignored == 1);
    return NULL;
}

/**
 * Compute the portion of `abs_path` that lies below `workdir`, or NULL
 * when `abs_path` is not under `workdir`. Consumes any leading slashes
 * on the result so empty input is reported as "the workdir itself".
 */
static const char *strip_workdir(const char *workdir, const char *abs_path) {
    if (!str_starts_with(abs_path, workdir)) return NULL;

    const char *rel = abs_path + strlen(workdir);
    while (*rel == '/') rel++;
    return rel;
}

error_t *source_filter_is_excluded(
    source_filter_t *f, const char *abs_path, bool is_dir, bool *out
) {
    CHECK_NULL(f);
    CHECK_NULL(abs_path);
    CHECK_NULL(out);
    CHECK_ARG(abs_path[0] == '/', "source_filter requires absolute paths");

    *out = false;

    /* Fast path: cached repo still covers this path. */
    if (f->cached_repo && f->cached_workdir) {
        const char *rel = strip_workdir(f->cached_workdir, abs_path);
        if (rel) {
            /* Path IS the workdir: no gitignore decision to make. */
            if (*rel == '\0') return NULL;
            return query_repo(f->cached_repo, rel, is_dir, out);
        }

        /* Outside cached workdir — drop the cache and re-discover. */
        git_repository_free(f->cached_repo);
        free(f->cached_workdir);
        f->cached_repo = NULL;
        f->cached_workdir = NULL;
    }

    /* Slow path: discover the containing repository. */
    git_buf discovered = GIT_BUF_INIT;
    int rc = git_repository_discover(
        &discovered, abs_path,
        /* across_fs */ 0,
        /* ceiling_dirs */ NULL
    );
    if (rc < 0) {
        /* Not in any git repo: a legitimate "no verdict", not an error. */
        if (rc == GIT_ENOTFOUND) return NULL;
        return error_from_git(rc);
    }

    git_repository *repo = NULL;
    rc = git_repository_open(&repo, discovered.ptr);
    git_buf_dispose(&discovered);
    if (rc < 0) {
        return error_from_git(rc);
    }

    const char *workdir = git_repository_workdir(repo);
    if (!workdir) {
        /* Bare repo — no workdir, no paths to resolve against. */
        git_repository_free(repo);
        return NULL;
    }

    const char *rel = strip_workdir(workdir, abs_path);
    if (!rel || *rel == '\0') {
        git_repository_free(repo);
        return NULL;
    }

    error_t *err = query_repo(repo, rel, is_dir, out);
    if (err) {
        git_repository_free(repo);
        return err;
    }

    /* Adopt into cache. Allocation failure drops the repo but keeps the
     * successful result — the next call will re-discover from scratch. */
    char *workdir_copy = strdup(workdir);
    if (!workdir_copy) {
        git_repository_free(repo);
        return NULL;
    }

    f->cached_repo = repo;
    f->cached_workdir = workdir_copy;
    return NULL;
}
