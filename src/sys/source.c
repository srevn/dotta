/**
 * source.c - Source-tree gitignore queries via libgit2.
 *
 * Implementation notes:
 *
 *   - The memo is one directory's answer, keyed by the directory the caller
 *     spelled. A repository is a boundary, not a subtree: a `.git` anywhere beneath
 *     a workdir starts a repository whose rules are its own and whose
 *     `.git/info/exclude` no other handle can see. So the question is put to
 *     `git_repository_discover` again at every directory, and only the handle
 *     survives a transition — kept when discovery answers with the gitdir the
 *     held handle already has, which is the common walk and the 170 µs an open
 *     costs. At most one handle is held, whatever the walk's shape.
 *
 *   - What a directory costs: one discovery (~36 µs) and one `realpath` (~14
 *     µs). What an entry in it costs: one `str_format` and the libgit2 query. A
 *     walk that recurses inline re-enters the parent after every subdirectory
 *     it leaves, so a tree pays about two transitions per directory — against a
 *     `realpath` per query that is a wash at seven entries per directory, a win
 *     above it, and a large win wherever no repository stands above at all: a
 *     failed discovery is an answer like any other and is remembered, where it
 *     used to be paid per entry.
 *
 *   - The relativisation is load-bearing, not defensive.
 *     `git_ignore_path_is_ignored` does not refuse a path outside the workdir;
 *     it matches the rules against whatever it is handed, so `/etc/x.log` against
 *     a repository holding `*.log` reports ignored, and a non-canonical absolute
 *     path is silently mis-answered. The prefix `place` computes is what keeps
 *     the question inside the repository that was asked.
 *
 *   - `git_repository_workdir` reports the workdir canonical (symlinks resolved)
 *     and ending in `/`, so the directory is canonicalised to compare
 *     with it: under a symlinked prefix (macOS's /tmp -> /private/tmp, a
 *     symlinked $HOME) the raw spelling never matched. Discovery prettifies its
 *     own start path, so a directory it found is one `realpath` can resolve and
 *     the entry itself need not exist (`ignore --test`); a symlink entry is judged
 *     where it stands, not where it points.
 *
 *   - Nothing is remembered after a failure: the memo is emptied, so a repository
 *     that cannot be opened says so for every entry rather than once and then
 *     quietly answering "no verdict" for the rest.
 */

#include "sys/source.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/string.h"
#include "sys/filesystem.h"

struct source_filter {
    char *directory;       /* Owned; the directory answered for, through its '/' */
    git_repository *repo;  /* Owned; what discovery found above it, or NULL */
    char *prefix;          /* Owned; where the directory stands inside the
                              workdir, or NULL when there is no verdict */
};

/**
 * Empty the memo: no directory, no handle, no answer.
 *
 * `prefix` is the answer and `repo` the handle that computes it, so a prefix
 * implies a repository and nothing has to maintain that — `place` is called only
 * with one and writes only on success. The reverse does not hold: a bare
 * repository, or one whose `core.worktree` points away, is held without answering
 * for the directory, because the next directory may well be its own.
 */
static void forget(source_filter_t *f) {
    git_repository_free(f->repo);
    free(f->directory);
    free(f->prefix);
    f->repo = NULL;
    f->directory = NULL;
    f->prefix = NULL;
}

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

    forget(f);
    free(f);
}

/**
 * The repository governing `directory` — `*held` on return, or NULL when none does
 *
 * `*held` on entry is the repository the last directory belonged to. Discovery
 * answers with a gitdir and a gitdir names one repository, so a held handle whose
 * own path is that gitdir is the same repository and is kept; that is exact for
 * a linked worktree and a submodule too, whose gitdirs are the `.git` file's
 * target and not the repository they were reached through. Anything else releases
 * the handle first, so the caller never has to, and `*held` is NULL whenever
 * this returns an error.
 *
 * `git_repository_discover` is the only authority here: it walks up from the
 * directory exactly as git does, stopping at a filesystem boundary (`across_fs`
 * 0, git's own default) and at the first rung that holds a repository. That is
 * what makes a nested repository answer for its own contents, and what keeps
 * the rules of every repository above it from reaching in.
 */
static error_t *adopt(git_repository **held, const char *directory) {
    git_buf discovered = GIT_BUF_INIT;
    int rc = git_repository_discover(&discovered, directory, 0, NULL);

    if (rc == 0 && *held &&
        strcmp(discovered.ptr, git_repository_path(*held)) == 0) {
        git_buf_dispose(&discovered);
        return NULL;
    }

    git_repository_free(*held);
    *held = NULL;

    if (rc == 0) {
        rc = git_repository_open(held, discovered.ptr);
    }
    git_buf_dispose(&discovered);

    /* No repository above the directory is an answer, not a failure — and so is
     * one that left between the discovery and the open. */
    return rc < 0 && rc != GIT_ENOTFOUND ? error_from_git(rc) : NULL;
}

/**
 * Where `directory` stands inside `repo` — git's own prefix, '/'-terminated and
 * "" at the workdir root — or nowhere
 *
 * `*out == NULL` is "this repository cannot answer for that directory", not a
 * failure: a bare repository has no workdir and no paths to resolve against,
 * and a `core.worktree` may name one that does not contain the directory. The
 * value is the same object `git rev-parse --show-prefix` prints, and it is what
 * every query in the directory is composed under.
 */
static error_t *place(git_repository *repo, const char *directory, char **out) {
    *out = NULL;

    const char *workdir = git_repository_workdir(repo);
    if (!workdir) return NULL;

    char *canonical = NULL;
    RETURN_IF_ERROR(fs_canonicalize_path(directory, &canonical));

    /* The workdir without the separator libgit2 ends it with: at that offset a
     * path beneath the workdir holds the separator, and the workdir's own spelling
     * holds the terminator. Comparing one byte short is what lets the root compare
     * equal rather than one byte short of itself. */
    size_t root = strlen(workdir) - 1;
    const char *tail = NULL;
    if (strncmp(workdir, canonical, root) == 0) {
        if (canonical[root] == '\0') {
            tail = canonical + root;
        } else if (canonical[root] == '/') {
            tail = canonical + root + 1;
        }
    }

    error_t *err = NULL;
    if (tail) {
        *out = str_format("%s%s", tail, *tail ? "/" : "");
        if (!*out) {
            err = ERROR(ERR_MEMORY, "Failed to allocate the source prefix");
        }
    }

    free(canonical);
    return err;
}

/**
 * The memo moved to the directory `path` begins with — the repository above it
 * and its place inside, or neither
 *
 * The key goes in before the answer is asked, so whatever comes back belongs to
 * this directory; a failure empties the memo rather than leaving a stale one,
 * which is what makes a repository that cannot be opened say so for every entry
 * instead of once.
 */
static error_t *enter(
    source_filter_t *f, const char *path, size_t directory_len
) {
    char *directory = strndup(path, directory_len);
    if (!directory) {
        return ERROR(ERR_MEMORY, "Failed to allocate the source directory");
    }

    free(f->directory);
    free(f->prefix);
    f->directory = directory;
    f->prefix = NULL;

    error_t *err = adopt(&f->repo, directory);
    if (!err && f->repo) {
        err = place(f->repo, directory, &f->prefix);
    }
    if (err) forget(f);

    return err;
}

error_t *source_filter_is_excluded(
    source_filter_t *f, const char *abs_path, bool is_dir, bool *out
) {
    CHECK_NULL(f);
    CHECK_NULL(abs_path);
    CHECK_NULL(out);
    CHECK_ARG(abs_path[0] == '/', "source_filter requires absolute paths");

    *out = false;

    /* The name the path ends in, and how much of the path is the directory that
     * name stands in — through the separator, so "/" is a key like any other
     * and the name is never empty and never holds one. A path that names no entry
     * has nothing for a rule to match, and asks no repository anything. */
    const char *name = strrchr(abs_path, '/') + 1;
    if (!*name) return NULL;

    size_t directory_len = (size_t) (name - abs_path);
    if (!f->directory ||
        strncmp(f->directory, abs_path, directory_len) != 0 ||
        f->directory[directory_len] != '\0') {
        RETURN_IF_ERROR(enter(f, abs_path, directory_len));
    }
    if (!f->prefix) return NULL;

    /* Where the name stands inside the workdir, spelled as libgit2 wants it: a
     * directory carries the trailing separator a directory-only pattern needs
     * (`node_modules/`), which the name can neither hold already nor be empty
     * of. An allocation failure surfaces as ERR_MEMORY rather than silently falling
     * back to an unsuffixed query, which would change the verdict. */
    char *query = str_format("%s%s%s", f->prefix, name, is_dir ? "/" : "");
    if (!query) {
        return ERROR(ERR_MEMORY, "Failed to allocate the source query");
    }

    int ignored = 0;
    int rc = git_ignore_path_is_ignored(&ignored, f->repo, query);
    free(query);

    if (rc < 0) {
        return error_from_git(rc);
    }

    *out = (ignored == 1);
    return NULL;
}
