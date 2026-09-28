/**
 * source.c - Source-tree gitignore queries via libgit2.
 *
 * Implementation notes:
 *
 *   - The memo holds two answers at two lifetimes. A repository is a boundary,
 *     not a subtree: a `.git` anywhere beneath a workdir starts a repository
 *     whose rules are its own and whose `.git/info/exclude` no other handle can
 *     see. So the question is put to `git_repository_discover` again at every
 *     directory, keyed by the directory the caller spelled, and only the repository
 *     survives a transition — kept while discovery answers with the gitdir it
 *     was opened from, which is the common walk and the 170 µs an open costs.
 *     At most one repository is held, whatever the walk's shape.
 *
 *   - What a directory costs: one discovery (~36 µs) and one `realpath` (~14
 *     µs). What an entry in it costs: one `heap_str_format` and the libgit2 query.
 *     A walk that recurses inline re-enters the parent after every subdirectory
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
 *     path is silently mis-answered. The prefix `source_place` computes is what
 *     keeps the question inside the repository that was asked.
 *
 *   - `git_repository_workdir` reports the workdir canonical (symlinks resolved)
 *     and ending in `/`, so the directory is canonicalised to compare
 *     with it: under a symlinked prefix (macOS's /tmp -> /private/tmp, a
 *     symlinked $HOME) the raw spelling never matched. Discovery prettifies its
 *     own start path, so a directory it found is one `realpath` can resolve and
 *     the entry itself need not exist (`ignore --test`); a symlink entry is judged
 *     where it stands, not where it points.
 *
 *   - A failure is remembered like any answer, never asked again: every entry
 *     reads it, so a repository that cannot be opened says so for every entry
 *     beneath it rather than once and then quietly answering "no verdict" for
 *     the rest — and says it with the one error its open made (base/error.h
 *     "Lifetime"). What the run keeps is counted by the causes: one error per
 *     repository that will not open, each time a walk enters it — one that leaves
 *     for a nested repository and comes back asks again — and one per directory
 *     whose own discovery, place or query fails.
 */

#include "sys/source.h"

#include <errno.h>
#include <git2.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/heap.h"
#include "sys/filesystem.h"

struct source_filter {
    /* The repository discovery last answered, and what opening it gave — kept
     * while discovery answers the same gitdir, so a walk inside one repository
     * opens it once, and one that will not open refuses once. */
    char *gitdir;          /* Owned; the gitdir discovery answered, or NULL: none */
    git_repository *repo;  /* Owned; that gitdir open, or NULL: none, or it would not open */
    error_t refusal;       /* Why it would not open; NULL when it did */

    /* The directory last asked about, and its answer. A prefix implies a repository
     * and nothing has to maintain that — source_place is asked only of one —
     * but a repository implies no prefix: a bare one, or one whose `core.worktree`
     * points away, is held without answering for the directory, because the next
     * directory may well be its own. */
    char *directory;       /* Owned; the directory answered for, through its '/' */
    char *prefix;          /* Owned; where it stands inside the workdir, or NULL: no verdict */
    error_t failure;       /* Why it has no answer; NULL when it has one */
};

source_filter_t *source_filter_create(void) {
    return heap_calloc(1, sizeof(source_filter_t));
}

void source_filter_free(source_filter_t *f) {
    if (!f) return;

    git_repository_free(f->repo);
    free(f->gitdir);
    free(f->directory);
    free(f->prefix);
    free(f);
}

/**
 * The repository governing `directory` — f->repo, or none — or the failure that
 * left the directory without one
 *
 * Discovery answers with a gitdir and a gitdir names one repository, so the
 * repository held already is kept wherever discovery answers its gitdir again:
 * its handle, and just as surely the refusal its open gave, which stands for
 * every directory the repository governs rather than being asked for once more.
 * That is exact for a linked worktree and a submodule too, whose gitdirs are
 * the `.git` file's target and not the repository they were reached through.
 * Anything else replaces it, so the caller never has to.
 *
 * `git_repository_discover` is the only authority here: it walks up from the
 * directory exactly as git does, stopping at a filesystem boundary (`across_fs`
 * 0, git's own default) and at the first rung that holds a repository. That is
 * what makes a nested repository answer for its own contents, and what keeps
 * the rules of every repository above it from reaching in.
 */
static error_t source_adopt(source_filter_t *f, const char *directory) {
    git_buf discovered = GIT_BUF_INIT;
    int rc = git_repository_discover(&discovered, directory, 0, NULL);

    /* The repository held already: its handle stands, or its refusal does. */
    if (rc == 0 && f->gitdir && strcmp(discovered.ptr, f->gitdir) == 0) {
        git_buf_dispose(&discovered);
        return f->refusal;
    }

    git_repository_free(f->repo);
    free(f->gitdir);
    f->repo = NULL;
    f->gitdir = NULL;
    f->refusal = NULL;

    /* No repository above the directory is an answer, not a failure. A discovery
     * that failed is this directory's own: it names no gitdir to be kept by. */
    if (rc < 0) {
        git_buf_dispose(&discovered);
        return rc == GIT_ENOTFOUND ? NULL : error_from_git(rc);
    }

    /* The gitdir it answers now, opened once and kept with whatever the open
     * gave: the handle, or the refusal. A repository that left between the
     * discovery and the open is no repository, an answer again. */
    f->gitdir = heap_strdup(discovered.ptr);
    git_buf_dispose(&discovered);

    rc = git_repository_open(&f->repo, f->gitdir);
    if (rc < 0 && rc != GIT_ENOTFOUND) f->refusal = error_from_git(rc);

    return f->refusal;
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
static error_t source_place(git_repository *repo, const char *directory, char **out) {
    *out = NULL;

    const char *workdir = git_repository_workdir(repo);
    if (!workdir) return NULL;

    /* The directory as the kernel spells it, through the funnel's reach: a
     * transient of this call, with no arena in reach. */
    char canonical[PATH_MAX];
    if (fs_realpath(directory, canonical) == NULL) {
        return error_from_errno(errno, "Failed to resolve path '%s'", directory);
    }

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

    if (tail) {
        *out = heap_str_format("%s%s", tail, *tail ? "/" : "");
    }

    return NULL;
}

/**
 * Move the memo to the directory `path` begins with: the key, then its answer —
 * where it stands inside its repository, no verdict, or the failure that left
 * it none
 *
 * The key goes in before the answer is asked, so whatever comes back belongs to
 * this directory, a failure included: it is the directory's answer until the
 * memo moves, and every entry of the directory reads that one error. Cannot fail
 * — its outcome is the memo.
 */
static void source_enter(source_filter_t *f, const char *path, size_t directory_len) {
    free(f->directory);
    free(f->prefix);
    f->directory = heap_strndup(path, directory_len);
    f->prefix = NULL;

    f->failure = source_adopt(f, f->directory);
    if (!f->failure && f->repo) {
        f->failure = source_place(f->repo, f->directory, &f->prefix);
    }
}

error_t source_filter_excludes(
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
        source_enter(f, abs_path, directory_len);
    }
    if (f->failure) return f->failure;
    if (!f->prefix) return NULL;

    /* Where the name stands inside the workdir, spelled as libgit2 wants it: a
     * directory carries the trailing separator a directory-only pattern needs
     * (`node_modules/`), which the name can neither hold already nor be empty
     * of. */
    char *query = heap_str_format("%s%s%s", f->prefix, name, is_dir ? "/" : "");

    int ignored = 0;
    int rc = git_ignore_path_is_ignored(&ignored, f->repo, query);
    free(query);

    /* A query's failure is the directory's too: libgit2 builds the rules it asks
     * from the directory's rungs and the repository's own files — one it cannot
     * read reads as absent — and takes of the entry its name and a look that
     * cannot fail, so the next entry would meet the same failure. */
    if (rc < 0) {
        f->failure = error_from_git(rc);
        return f->failure;
    }

    *out = (ignored == 1);
    return NULL;
}
